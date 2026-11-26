//! HTTP/2 response streams whose client stops granting flow-control window.
//!
//! On HTTP/1.1 a client that stops reading blocks the TCP socket and `WriteGuardedIo` cuts it.
//! On HTTP/2 a client can close the window of one stream (or of the whole connection) while it
//! keeps reading everything else: the socket never blocks, pings are answered, and the response
//! body, its file handle or its upstream connection would be held for as long as the client
//! likes. hyper does not poll a response body while it waits for stream capacity, so a timer
//! inside the body would never run. The deadline is therefore scheduled on the connection:
//!
//! - every HTTP/2 response body is wrapped in [`H2StallBody`], which records when it handed a
//!   piece of data to hyper and clears the mark when hyper asks for the next one;
//! - the connection task calls [`H2StallRegistry::expire_stalled`] on a timer; a stream that
//!   has been waiting
//!   for longer than `response-write-idle` while the socket itself was writable is expired:
//!   its body is dropped at once and the connection is then shut down gracefully, so streams
//!   that are still moving can finish within `graceful-drain`.
//!
//! hyper offers no way to reset a single stream that is waiting for capacity, which is why the
//! connection is closed rather than only the stream.
//!
//! Time during which the socket was blocked does not count: on a slow link every stream waits
//! for the link, the minimum rate is enforced on the connection by `WriteGuardedIo`, and a
//! stream that waits its turn there is not stalled. Blocked time is subtracted exactly
//! ([`TransportWriteState`]); writable time always adds up, however the two alternate.
//!
//! Bodies are cut into pieces ([`in_pieces`], sized by [`piece_bytes`]) before the accounting
//! wrappers see them, so that a slow but acceptable client completes a piece well inside the
//! deadline and a buffered body is not counted as delivered while most of it is still here.

use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt as _;
use tokio::sync::Notify;

use crate::{HttpBody, HttpError, PipeRespBody, monotonic_idle_ms};

/// How long writes to the connection's socket have been blocked in total, as seen above TLS.
///
/// The total only ever grows. A waiting stream remembers the total at the moment it handed its
/// piece over and later subtracts the increase, so time the socket was blocked is not counted
/// against it, while time the socket was writable is never forgotten, however often another
/// stream's write blocks in between.
#[derive(Debug, Default)]
pub(crate) struct TransportWriteState {
    /// Monotonic milliseconds at which the current blocked period began; `0` while writable.
    blocked_since: AtomicU64,
    /// Sum of all finished blocked periods, in milliseconds.
    blocked_total: AtomicU64,
    /// Monotonic flag set before any HTTP/2 stream or DATA frame updates `delivery`. While `false`
    /// (always on HTTP/1.1 connections), `delivery` holds its all-zero initial state and
    /// `is_delivering` / `last_data_ms` return without locking `delivery`.
    delivery_used: AtomicBool,
    /// What has been handed over and written. One lock for all of it: the correction after a
    /// cancelled stream reads and changes these together, and several tasks ask (the stall
    /// watchdog, the per-address connection table) while responses are handed over.
    delivery: Mutex<Delivery>,
}

/// The delivery counts of one connection (see [`TransportWriteState::is_delivering`]).
#[derive(Debug, Default)]
struct Delivery {
    /// Response body bytes handed to hyper (DATA payload to be sent).
    handed: u64,
    /// DATA frame payload bytes the socket has accepted, counted from the frames written
    /// ([`DataFrameCounter`]). Control frames (PING replies, `WINDOW_UPDATE`) are not counted.
    written: u64,
    /// Monotonic milliseconds when the socket last accepted DATA payload.
    last_data_at: u64,
    /// A stream was cancelled with body bytes handed to hyper that may never be written: the
    /// handed/written difference is no longer exact.
    discard_pending: bool,
    /// Responses that have not reached their end: what they handed over may still be waiting
    /// for the client, so nothing is discarded while there is one.
    unfinished: u64,
}

impl TransportWriteState {
    fn delivery(&self) -> std::sync::MutexGuard<'_, Delivery> {
        self.delivery.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A write or flush returned `Pending`.
    pub(crate) fn mark_blocked(&self) {
        let _ = self.blocked_since.compare_exchange(
            0,
            monotonic_idle_ms(),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    /// A write or flush completed.
    pub(crate) fn mark_writable(&self) {
        // Single-writer (`HeadDeadlineIo` on the connection task): skip the atomic swap when the
        // socket was not blocked.
        if self.blocked_since.load(Ordering::Relaxed) == 0 {
            return;
        }
        let since = self.blocked_since.swap(0, Ordering::AcqRel);
        if since != 0 {
            self.blocked_total
                .fetch_add(monotonic_idle_ms().saturating_sub(since), Ordering::AcqRel);
        }
    }

    /// Whether any HTTP/2 stream or DATA frame has ever used delivery accounting on this
    /// connection. Monotonic (`false` -> `true`), set with `Release` before locking `delivery`.
    fn has_delivery_accounting(&self) -> bool {
        self.delivery_used.load(Ordering::Acquire)
    }

    /// Body bytes handed to hyper for sending.
    fn add_handed(&self, bytes: u64) {
        self.delivery_used.store(true, Ordering::Release);
        let mut delivery = self.delivery();
        delivery.handed = delivery.handed.saturating_add(bytes);
    }

    /// DATA payload bytes the socket accepted.
    pub(crate) fn add_data_written(&self, bytes: u64) {
        if bytes > 0 {
            self.delivery_used.store(true, Ordering::Release);
            let mut delivery = self.delivery();
            delivery.written = delivery.written.saturating_add(bytes);
            delivery.last_data_at = monotonic_idle_ms();
        }
    }

    /// Whether response data is still on its way: a write is waiting, or hyper holds body
    /// bytes that have not reached the socket AND some DATA reached it within `progress_window`.
    /// Control frames (a client's keep-alive PINGs and their replies) do not count, so they
    /// cannot keep an idle connection open; and bytes of a stream the client cancelled, which
    /// will never be written, stop counting once no DATA has moved for `progress_window`.
    ///
    /// After a cancelled stream (whose discarded bytes hyper never writes and which cannot be
    /// attributed per stream from here), the difference is resynchronised once no response is
    /// unfinished and no DATA has moved for `progress_window`: until then the unsent bytes
    /// count, as they may be another stream's (hyper takes a response to its end while h2
    /// still holds part of it for the client's window). The decision and the correction are
    /// one step under the lock.
    pub(crate) fn is_delivering(&self, progress_window: Duration) -> bool {
        if self.is_blocked() {
            return true;
        }
        if !self.has_delivery_accounting() {
            return false;
        }
        let mut delivery = self.delivery();
        if delivery.written >= delivery.handed {
            return false;
        }
        let since_data = monotonic_idle_ms().saturating_sub(delivery.last_data_at);
        let window = u64::try_from(progress_window.as_millis()).unwrap_or(u64::MAX);
        if since_data >= window && delivery.discard_pending && delivery.unfinished == 0 {
            // Whatever is still counted as unsent belongs to the cancelled stream.
            delivery.handed = delivery.written;
            delivery.discard_pending = false;
            return false;
        }
        since_data < window
    }

    /// Monotonic milliseconds of the last DATA written, `0` if none.
    pub(crate) fn last_data_ms(&self) -> u64 {
        if !self.has_delivery_accounting() {
            return 0;
        }
        self.delivery().last_data_at
    }

    /// A response body was dropped before its end (the client cancelled the stream).
    fn note_cancelled(&self) {
        self.delivery_used.store(true, Ordering::Release);
        self.delivery().discard_pending = true;
    }

    /// A response starts: it is unfinished until [`Self::response_ended`].
    fn response_started(&self) {
        self.delivery_used.store(true, Ordering::Release);
        let mut delivery = self.delivery();
        delivery.unfinished = delivery.unfinished.saturating_add(1);
    }

    fn response_ended(&self) {
        let mut delivery = self.delivery();
        delivery.unfinished = delivery.unfinished.saturating_sub(1);
    }

    /// Whether a write is waiting on the socket right now.
    pub(crate) fn is_blocked(&self) -> bool {
        self.blocked_since.load(Ordering::Acquire) != 0
    }

    /// Total blocked time up to `now_ms`, including a period still in progress.
    fn blocked_total_at(&self, now_ms: u64) -> u64 {
        let finished = self.blocked_total.load(Ordering::Acquire);
        let since = self.blocked_since.load(Ordering::Acquire);
        if since == 0 {
            finished
        } else {
            finished.saturating_add(now_ms.saturating_sub(since))
        }
    }
}

/// Inner body stored inside [`StreamState`] so HTTP/2 connections avoid boxing `AccessLogBody`
/// while preserving `HttpBody` support for `redirect-only` and unit tests.
#[allow(clippy::large_enum_variant)]
enum StallInner {
    AccessLog(crate::AccessLogBody),
    Http(HttpBody),
}

impl std::fmt::Debug for StallInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AccessLog(_) => f.write_str("StallInner::AccessLog(..)"),
            Self::Http(body) => f.debug_tuple("StallInner::Http").field(body).finish(),
        }
    }
}

impl Body for StallInner {
    type Data = Bytes;
    type Error = HttpError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            Self::AccessLog(body) => Pin::new(body).poll_frame(cx),
            Self::Http(body) => Pin::new(body).poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::AccessLog(body) => body.is_end_stream(),
            Self::Http(body) => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::AccessLog(body) => body.size_hint(),
            Self::Http(body) => body.size_hint(),
        }
    }
}

#[derive(Debug)]
struct StreamState {
    /// Monotonic milliseconds at which a piece was handed to hyper that it has not followed up
    /// on yet; `0` while the stream is not waiting for the client.
    waiting_since_ms: AtomicU64,
    /// The transport's total blocked time when that piece was handed over.
    blocked_at_handoff_ms: AtomicU64,
    /// The body finished, failed, was dropped or was expired.
    done: AtomicBool,
    /// Set by the watchdog; the body fails if hyper ever polls it again.
    expired: AtomicBool,
    /// The wrapped body. Shared so the watchdog can release it while hyper still holds the
    /// wrapper.
    inner: Mutex<Option<StallInner>>,
}

impl StreamState {
    fn new(body: StallInner) -> Self {
        Self {
            waiting_since_ms: AtomicU64::new(0),
            blocked_at_handoff_ms: AtomicU64::new(0),
            done: AtomicBool::new(false),
            expired: AtomicBool::new(false),
            inner: Mutex::new(Some(body)),
        }
    }

    /// Resets a uniquely owned, completed `StreamState` in place for reuse by a new HTTP/2
    /// stream. Returns any previous `StallInner` (always `None` for released streams) so callers
    /// can drop it outside the registry mutex.
    fn reset(&mut self, body: StallInner) -> Option<StallInner> {
        *self.waiting_since_ms.get_mut() = 0;
        *self.blocked_at_handoff_ms.get_mut() = 0;
        *self.done.get_mut() = false;
        *self.expired.get_mut() = false;
        self.inner.clear_poison();
        match self.inner.get_mut() {
            Ok(slot) => slot.replace(body),
            Err(poisoned) => poisoned.into_inner().replace(body),
        }
    }

    fn release(&self) -> Option<StallInner> {
        self.done.store(true, Ordering::Release);
        self.waiting_since_ms.store(0, Ordering::Release);
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
}

/// The response streams of one HTTP/2 connection.
#[derive(Debug, Default)]
pub(crate) struct H2StallRegistry {
    /// Tracked streams in strict registration order. Uses `VecDeque` so finished, uniquely owned
    /// shells at either end (`front` for FIFO completion, `back` when an older stream stays open)
    /// can be recycled in O(1) without scanning or reordering any surviving streams.
    streams: Mutex<VecDeque<Arc<StreamState>>>,
    transport: Arc<TransportWriteState>,
    wake: Notify,
}

impl H2StallRegistry {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// The write state to feed from the connection's I/O wrapper.
    pub(crate) fn transport(&self) -> Arc<TransportWriteState> {
        Arc::clone(&self.transport)
    }

    /// Wakes [`Self::changed`]: the connection turned out to be HTTP/2 or has a new stream.
    pub(crate) fn notify(&self) {
        self.wake.notify_one();
    }

    /// Resolves after the next [`Self::notify`].
    pub(crate) async fn changed(&self) {
        self.wake.notified().await;
    }

    /// Wraps the body of an HTTP/2 response so its progress is tracked.
    #[cfg(test)]
    pub(crate) fn guard(&self, body: HttpBody) -> HttpBody {
        self.guard_counting(body, None)
    }

    /// Wraps an [`AccessLogBody`] directly without boxing either `AccessLogBody` or
    /// [`H2StallBody`].
    pub(crate) fn guard_access_log(&self, body: crate::AccessLogBody) -> H2StallBody {
        self.guard_inner(StallInner::AccessLog(body), None)
    }

    /// [`Self::guard`]; `on_cancel` runs if the body is dropped before its end (the client
    /// reset the stream).
    pub(crate) fn guard_counting(&self, body: HttpBody, on_cancel: Option<OnCancel>) -> HttpBody {
        self.guard_inner(StallInner::Http(body), on_cancel).boxed()
    }

    fn guard_inner(&self, body: StallInner, on_cancel: Option<OnCancel>) -> H2StallBody {
        let remaining_exact = body.size_hint().exact();
        // O(1) stable recycling: inspect only `front()` (oldest stream finished first, FIFO) and
        // `back()` (newest stream finished while an older stream remains open, LIFO). Both
        // `pop_front` and `pop_back` preserve the exact registration order of every surviving
        // stream with zero linear scan below 64 entries and zero shifting of live elements.
        //
        // Retention bound:
        // - When `streams.len() >= 64` (checked BEFORE popping so `len == 64` still prunes),
        //   `retain` compacts all other finished shells, leaving only open streams plus the new
        //   one.
        // - Below 64 entries, or after a concurrency burst above 64 that finishes before another
        //   admission or active `expire_stalled` sweep (same burst retention as `416f01f`),
        //   finished shells remain until reused at `front()`/`back()`, pruned at `len >= 64`,
        //   swept by an active `expire_stalled`, or dropped at connection teardown (`h2_watch`'s
        //   fully idle branch skips `expire_stalled`).
        let mut body = Some(body);
        let mut stale_inner = None;
        let recycled = {
            let mut streams = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
            let needs_prune = streams.len() >= 64;
            let popped = if streams
                .front()
                .is_some_and(|s| s.done.load(Ordering::Acquire) && Arc::strong_count(s) == 1)
            {
                streams.pop_front()
            } else if streams
                .back()
                .is_some_and(|s| s.done.load(Ordering::Acquire) && Arc::strong_count(s) == 1)
            {
                streams.pop_back()
            } else {
                None
            };
            if let Some(mut arc) = popped {
                if needs_prune {
                    streams.retain(|s| !s.done.load(Ordering::Acquire));
                }
                if let Some(st) = Arc::get_mut(&mut arc) {
                    if let Some(b) = body.take() {
                        stale_inner = st.reset(b);
                    }
                    streams.push_back(Arc::clone(&arc));
                    Some(arc)
                } else {
                    // Unreachable while `self.streams` held the only strong ref and no `Weak`
                    // refs exist; drop the already-done entry and allocate outside the lock.
                    None
                }
            } else {
                None
            }
        };
        let state = if let Some(state) = recycled {
            state
        } else {
            // Miss path: allocate strictly OUTSIDE `self.streams` mutex (matching `416f01f`),
            // then lock once to prune (if `>= 64`) and append in registration order.
            let state = Arc::new(StreamState::new(
                body.unwrap_or_else(|| StallInner::Http(crate::empty_http_body())),
            ));
            let mut streams = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
            if streams.len() >= 64 {
                streams.retain(|s| !s.done.load(Ordering::Acquire));
            }
            streams.push_back(Arc::clone(&state));
            state
        };
        // Defensively dropped outside `self.streams` (always `None` for released streams).
        drop(stale_inner);
        // Every new stream leaves one notification for the watchdog, as in v0.1.2, whether
        // or not it is waiting at this instant.
        self.notify();
        self.transport.response_started();
        H2StallBody {
            state,
            transport: Arc::clone(&self.transport),
            remaining_exact,
            finished: false,
            counted: true,
            on_cancel,
        }
    }

    /// Whether any tracked stream is still open: its body has not finished, failed or been
    /// dropped. A connection with an open stream is not idle, whatever the request accounting
    /// says (a buffered body counts as produced once its last piece is handed over).
    pub(crate) fn has_open_streams(&self) -> bool {
        self.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|s| !s.done.load(Ordering::Acquire))
    }

    /// Expires every stream that has waited for the client for at least `limit` of time in which
    /// the socket was writable, dropping its body, and returns the longest such wait.
    pub(crate) fn expire_stalled(&self, limit: Duration) -> Option<Duration> {
        let now = monotonic_idle_ms();
        let blocked_total = self.transport.blocked_total_at(now);
        let limit_ms = u64::try_from(limit.as_millis()).unwrap_or(u64::MAX);
        let mut longest: Option<u64> = None;
        let mut released = Vec::new();
        {
            let mut streams = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
            streams.retain(|s| !s.done.load(Ordering::Acquire));
            for stream in streams.iter() {
                let since = stream.waiting_since_ms.load(Ordering::Acquire);
                if since == 0 {
                    continue;
                }
                // Time since the hand-over, less the time the socket was blocked in between.
                let blocked_meanwhile = blocked_total
                    .saturating_sub(stream.blocked_at_handoff_ms.load(Ordering::Acquire));
                let waited = now.saturating_sub(since).saturating_sub(blocked_meanwhile);
                if waited >= limit_ms {
                    stream.expired.store(true, Ordering::Release);
                    released.push(stream.release());
                    longest = Some(longest.map_or(waited, |l| l.max(waited)));
                }
            }
        }
        // Dropped outside the lock: a body's drop can run access logging and cleanup.
        drop(released);
        longest.map(Duration::from_millis)
    }
}

/// Follows the HTTP/2 frames a server writes and counts the payload bytes of DATA frames.
///
/// Fed with exactly the bytes the socket accepted, in order. A connection that turns out not to
/// be HTTP/2 (its first bytes are an HTTP/1 status line) is ignored from then on. The server
/// never pads DATA frames, so the payload length is the frame length.
#[derive(Debug, Default)]
pub(crate) struct DataFrameCounter {
    /// Bytes of the current 9-byte frame header collected so far.
    header: [u8; 9],
    header_len: usize,
    /// Payload bytes of the current frame still to come.
    payload_left: u64,
    payload_is_data: bool,
    /// `Some(false)` once the connection is known not to be HTTP/2.
    is_h2: Option<bool>,
}

impl DataFrameCounter {
    /// Consumes `bytes` and returns how many of them were DATA payload.
    pub(crate) fn feed(&mut self, mut bytes: &[u8]) -> u64 {
        if self.is_h2.is_none() && !bytes.is_empty() {
            self.is_h2 = Some(!bytes.starts_with(b"HTTP/"));
        }
        if self.is_h2 != Some(true) {
            return 0;
        }
        let mut data = 0_u64;
        while !bytes.is_empty() {
            if self.payload_left > 0 {
                let take = usize::try_from(self.payload_left)
                    .unwrap_or(usize::MAX)
                    .min(bytes.len());
                if self.payload_is_data {
                    data = data.saturating_add(take as u64);
                }
                self.payload_left = self.payload_left.saturating_sub(take as u64);
                bytes = bytes.get(take..).unwrap_or(&[]);
                continue;
            }
            if self.header_len == 0
                && let Some(&[l0, l1, l2, kind, _, _, _, _, _]) = bytes.get(..9)
            {
                self.payload_left = u64::from(l0) << 16 | u64::from(l1) << 8 | u64::from(l2);
                self.payload_is_data = kind == 0;
                bytes = bytes.get(9..).unwrap_or(&[]);
                continue;
            }
            let take = (9 - self.header_len).min(bytes.len());
            if let (Some(dst), Some(src)) = (
                self.header.get_mut(self.header_len..self.header_len + take),
                bytes.get(..take),
            ) {
                dst.copy_from_slice(src);
            }
            self.header_len += take;
            bytes = bytes.get(take..).unwrap_or(&[]);
            if self.header_len == 9 {
                let [l0, l1, l2, kind, ..] = self.header;
                self.payload_left = u64::from(l0) << 16 | u64::from(l1) << 8 | u64::from(l2);
                self.payload_is_data = kind == 0;
                self.header_len = 0;
            }
        }
        data
    }
}

/// Follows the HTTP/2 frames a client sends and counts its `RST_STREAM` frames.
///
/// Fed with the bytes read from the socket, in order. hyper tells the server about a reset
/// only in some states of a stream (not, for one, when the answer's headers cannot be sent
/// any more), so the frames themselves are counted: that is what `max-h2-rst-stream-per-sec`
/// says. A connection that does not start with the HTTP/2 preface is ignored.
#[derive(Debug, Default)]
pub(crate) struct ResetFrameCounter {
    /// How much of the 24-byte preface has been seen.
    preface_seen: usize,
    /// `Some(false)` once the connection is known not to be HTTP/2.
    is_h2: Option<bool>,
    /// How much of the current 9-byte frame header has been seen, with its length and
    /// whether it is a `RST_STREAM` once known.
    header_seen: usize,
    length: u64,
    is_reset: bool,
    /// Payload bytes of the current frame still to come.
    payload_left: u64,
}

impl ResetFrameCounter {
    const PREFACE: &'static [u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    const RST_STREAM: u8 = 3;

    /// Consumes `bytes` and returns how many `RST_STREAM` frame headers were completed in them.
    pub(crate) fn feed(&mut self, mut bytes: &[u8]) -> u32 {
        if self.is_h2 == Some(false) {
            return 0;
        }
        if self.is_h2.is_none() {
            while let (Some(&byte), Some(&expected)) =
                (bytes.first(), Self::PREFACE.get(self.preface_seen))
            {
                if byte != expected {
                    self.is_h2 = Some(false);
                    return 0;
                }
                self.preface_seen += 1;
                bytes = bytes.get(1..).unwrap_or(&[]);
            }
            if self.preface_seen < Self::PREFACE.len() {
                return 0;
            }
            self.is_h2 = Some(true);
        }
        let mut resets = 0_u32;
        while !bytes.is_empty() {
            if self.payload_left > 0 {
                let take = usize::try_from(self.payload_left)
                    .unwrap_or(usize::MAX)
                    .min(bytes.len());
                self.payload_left = self.payload_left.saturating_sub(take as u64);
                bytes = bytes.get(take..).unwrap_or(&[]);
                continue;
            }
            if self.header_seen == 0
                && let Some(&[l0, l1, l2, kind, _, _, _, _, _]) = bytes.get(..9)
            {
                self.payload_left = u64::from(l0) << 16 | u64::from(l1) << 8 | u64::from(l2);
                if kind == Self::RST_STREAM {
                    resets = resets.saturating_add(1);
                }
                bytes = bytes.get(9..).unwrap_or(&[]);
                continue;
            }
            // The header: three bytes of length, the type, then flags and the stream.
            let Some((&byte, rest)) = bytes.split_first() else {
                break;
            };
            bytes = rest;
            match self.header_seen {
                0 => self.length = u64::from(byte),
                1 | 2 => self.length = self.length << 8 | u64::from(byte),
                3 => self.is_reset = byte == Self::RST_STREAM,
                _ => {}
            }
            self.header_seen += 1;
            // Counted when its header is complete, not on a header left unfinished.
            if self.header_seen == 9 {
                self.header_seen = 0;
                self.payload_left = self.length;
                if self.is_reset {
                    resets = resets.saturating_add(1);
                }
            }
        }
        resets
    }
}

/// Largest DATA payload handed over in one piece, for a connection with these limits.
///
/// "The next piece was asked for" is the only progress signal there is, so a piece must be
/// small enough for a slow but acceptable client to take within the deadline: at the minimum
/// rate a piece of this size takes half of `write_idle`. Never less than 1 KiB (tiny pieces
/// cost more than they prove) and never more than 64 KiB.
pub(crate) fn piece_bytes(min_rate_bps: u64, write_idle: Duration) -> usize {
    const MAX_PIECE: u64 = 64 * 1024;
    const MIN_PIECE: u64 = 1024;
    if min_rate_bps == 0 {
        return usize::try_from(MAX_PIECE).unwrap_or(usize::MAX);
    }
    let half_deadline = u128::from(min_rate_bps).saturating_mul(write_idle.as_millis()) / 2_000;
    let piece = u64::try_from(half_deadline)
        .unwrap_or(MAX_PIECE)
        .clamp(MIN_PIECE, MAX_PIECE);
    usize::try_from(piece).unwrap_or(usize::MAX)
}

/// Returns whether `body` needs [`PieceBody`] to split DATA frames into chunks of at most `piece`
/// bytes. Bodies whose exact remaining length is already at most `piece` cannot yield a DATA frame
/// larger than `piece`, so skipping the wrapper produces identical frames without boxing.
fn needs_piece_wrapper<B: Body>(body: &B, piece: usize) -> bool {
    let piece = piece.max(1) as u64;
    body.size_hint().exact().is_none_or(|exact| exact > piece)
}

/// Hands the DATA frames of `body` over in pieces of at most `piece` bytes.
///
/// This wrapper goes INSIDE the wrappers that account for a response (bytes sent, request in
/// flight): they then see each piece when it is handed over, not a whole buffered body at
/// once, and the unsent rest of a large buffer is part of the body the watchdog can release.
///
/// Bodies whose exact size is already at most one piece are returned unwrapped (identical frames).
pub(crate) fn in_pieces_pipe(body: PipeRespBody, piece: usize) -> PipeRespBody {
    let piece = piece.max(1);
    if !needs_piece_wrapper(&body, piece) {
        return body;
    }
    PipeRespBody::Boxed(
        PieceBody {
            inner: body.into_http_body(),
            pending: None,
            piece,
        }
        .boxed(),
    )
}

#[cfg(test)]
pub(crate) fn in_pieces(body: HttpBody, piece: usize) -> HttpBody {
    let piece = piece.max(1);
    if !needs_piece_wrapper(&body, piece) {
        return body;
    }
    PieceBody {
        inner: body,
        pending: None,
        piece,
    }
    .boxed()
}

struct PieceBody {
    inner: HttpBody,
    /// Rest of a DATA frame that was larger than one piece.
    pending: Option<Bytes>,
    piece: usize,
}

impl PieceBody {
    fn next_piece(&mut self, mut data: Bytes) -> Frame<Bytes> {
        if data.len() > self.piece {
            self.pending = Some(data.split_off(self.piece));
        }
        Frame::data(data)
    }
}

impl Body for PieceBody {
    type Data = Bytes;
    type Error = HttpError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(rest) = this.pending.take() {
            return Poll::Ready(Some(Ok(this.next_piece(rest))));
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => Poll::Ready(Some(Ok(this.next_piece(data)))),
                Err(other) => Poll::Ready(Some(Ok(other))),
            },
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.pending.is_none() && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        let pending = self.pending.as_ref().map_or(0, |p| p.len() as u64);
        let inner = self.inner.size_hint();
        let mut hint = SizeHint::new();
        hint.set_lower(inner.lower().saturating_add(pending));
        if let Some(upper) = inner.upper() {
            hint.set_upper(upper.saturating_add(pending));
        }
        hint
    }
}

/// What to do when a response body is dropped before its end.
pub(crate) type OnCancel = Box<dyn FnOnce() + Send + Sync>;

/// Response body wrapper for HTTP/2, see the module documentation.
pub(crate) struct H2StallBody {
    state: Arc<StreamState>,
    transport: Arc<TransportWriteState>,
    /// Exact remaining bytes cached from the wrapped body's `size_hint`, updated on each DATA
    /// frame so `size_hint()` avoids locking `state.inner` for known-length bodies.
    remaining_exact: Option<u64>,
    finished: bool,
    /// Still counted among the transport's unfinished responses.
    counted: bool,
    /// Runs when the body is dropped before its end.
    on_cancel: Option<OnCancel>,
}

impl H2StallBody {
    fn finish(&mut self) {
        self.finished = true;
        self.uncount();
        drop(self.state.release());
    }

    fn uncount(&mut self) {
        if std::mem::take(&mut self.counted) {
            self.transport.response_ended();
        }
    }

    fn mark_handed_over(&self, bytes: u64) {
        self.transport.add_handed(bytes);
        let now = monotonic_idle_ms();
        self.state
            .blocked_at_handoff_ms
            .store(self.transport.blocked_total_at(now), Ordering::Release);
        self.state.waiting_since_ms.store(now, Ordering::Release);
    }
}

impl Drop for H2StallBody {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if !self.state.expired.load(Ordering::Acquire) {
            self.transport.note_cancelled();
            if let Some(on_cancel) = self.on_cancel.take() {
                on_cancel();
            }
        }
        self.uncount();
        drop(self.state.release());
    }
}

impl Body for H2StallBody {
    type Data = Bytes;
    type Error = HttpError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(None);
        }
        if this.state.expired.load(Ordering::Acquire) {
            this.finish();
            return Poll::Ready(Some(Err(HttpError::Body(
                "HTTP/2 response stream made no progress (client flow-control window closed)"
                    .to_owned(),
            ))));
        }
        // hyper asks for more: the stream accepted what it was given.
        this.state.waiting_since_ms.store(0, Ordering::Release);
        let polled = {
            let mut slot = this
                .state
                .inner
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            match slot.as_mut() {
                Some(inner) => Pin::new(inner).poll_frame(cx),
                None => Poll::Ready(None),
            }
        };
        match polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let len = data.len() as u64;
                    if let Some(rem) = &mut this.remaining_exact {
                        *rem = rem.saturating_sub(len);
                    }
                    this.mark_handed_over(len);
                } else if frame.is_trailers() {
                    // Trailers end the stream: hyper does not poll again after them, so this
                    // is a finished response, not one cut short.
                    this.finish();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(err))) => {
                this.finish();
                Poll::Ready(Some(Err(err)))
            }
            Poll::Ready(None) => {
                this.finish();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// Only true once the end has been returned from `poll_frame`. The last DATA piece is
    /// deliberately not announced as the end: hyper then polls once more after the stream has
    /// accepted it, which is the only signal that it was not left waiting for capacity.
    fn is_end_stream(&self) -> bool {
        self.finished
    }

    fn size_hint(&self) -> SizeHint {
        if self.finished || self.state.expired.load(Ordering::Acquire) {
            return SizeHint::with_exact(0);
        }
        if let Some(remaining) = self.remaining_exact {
            return SizeHint::with_exact(remaining);
        }
        self.state
            .inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map_or_else(|| SizeHint::with_exact(0), Body::size_hint)
    }
}

#[cfg(test)]
mod tests {
    use super::{H2StallRegistry, in_pieces, piece_bytes};
    use crate::full_http_body;
    use bytes::Bytes;
    use http_body_util::BodyExt as _;
    use std::time::Duration;

    const PIECE: usize = 64 * 1024;
    /// A progress window short enough to wait for in a test.
    const SHORT_WINDOW: Duration = Duration::from_millis(300);

    #[tokio::test]
    async fn large_buffer_is_handed_over_in_pieces_and_the_end_is_a_separate_poll() {
        let registry = H2StallRegistry::new();
        let payload = Bytes::from(vec![7_u8; PIECE * 2 + 10]);
        let mut body = registry.guard(in_pieces(full_http_body(payload.clone()), PIECE));
        assert_eq!(
            http_body::Body::size_hint(&body).exact(),
            Some(payload.len() as u64)
        );

        let mut sizes = Vec::new();
        let mut total = Vec::new();
        while let Some(frame) = body.frame().await {
            let data = frame
                .ok()
                .and_then(|f| f.into_data().ok())
                .unwrap_or_default();
            assert!(
                !http_body::Body::is_end_stream(&body) || data.is_empty(),
                "the end is only reported after the last piece was followed up"
            );
            sizes.push(data.len());
            total.extend_from_slice(&data);
        }
        assert_eq!(sizes, vec![PIECE, PIECE, 10]);
        assert_eq!(total, payload);
        assert!(http_body::Body::is_end_stream(&body));
        assert!(!registry.has_open_streams());
    }

    #[test]
    fn data_frame_counter_counts_only_data_payload_across_split_writes() {
        use super::DataFrameCounter;
        // SETTINGS (6 bytes payload), DATA (5), PING ACK (8), DATA (3).
        let mut stream = Vec::new();
        stream.extend_from_slice(&[0, 0, 6, 4, 0, 0, 0, 0, 0]);
        stream.extend_from_slice(&[0; 6]);
        stream.extend_from_slice(&[0, 0, 5, 0, 0, 0, 0, 0, 1]);
        stream.extend_from_slice(b"hello");
        stream.extend_from_slice(&[0, 0, 8, 6, 1, 0, 0, 0, 0]);
        stream.extend_from_slice(&[9; 8]);
        stream.extend_from_slice(&[0, 0, 3, 0, 1, 0, 0, 0, 3]);
        stream.extend_from_slice(b"abc");
        for split in [1, 2, 4, 7, 13, stream.len()] {
            let mut counter = DataFrameCounter::default();
            let total: u64 = stream.chunks(split).map(|c| counter.feed(c)).sum();
            assert_eq!(total, 8, "split into chunks of {split}");
        }
        let mut http1 = DataFrameCounter::default();
        assert_eq!(http1.feed(b"HTTP/1.1 200 OK\r\n\r\nbody"), 0);
        assert_eq!(http1.feed(&[0, 0, 5, 0, 0, 0, 0, 0, 1]), 0);
    }

    #[test]
    fn piece_size_lets_a_reader_at_the_minimum_rate_finish_a_piece_in_half_the_deadline() {
        // Defaults: 1 KiB/s and 30 s give 15 KiB, not 64 KiB (which would take 64 s).
        assert_eq!(piece_bytes(1_024, Duration::from_secs(30)), 15_360);
        assert_eq!(piece_bytes(16_384, Duration::from_secs(30)), 64 * 1024);
        assert_eq!(piece_bytes(10, Duration::from_secs(1)), 1_024);
        assert_eq!(piece_bytes(0, Duration::from_secs(30)), 64 * 1024);
    }

    #[tokio::test]
    async fn stream_that_is_not_followed_up_expires_and_releases_its_body() {
        let registry = H2StallRegistry::new();
        // A buffered body larger than one piece: the unsent rest must be released too.
        let payload = Bytes::from(vec![1_u8; 4 * 1024]);
        let mut body = registry.guard(in_pieces(full_http_body(payload), 1_024));
        // hyper takes the piece and then waits for stream capacity: it never polls again.
        assert!(body.frame().await.is_some());
        assert!(registry.expire_stalled(Duration::from_secs(60)).is_none());
        assert!(registry.has_open_streams());

        tokio::time::sleep(Duration::from_millis(60)).await;
        let waited = registry.expire_stalled(Duration::from_millis(40));
        assert!(waited.is_some_and(|w| w >= Duration::from_millis(40)));
        assert!(
            !registry.has_open_streams(),
            "the expired body was released"
        );
        // If hyper does poll again, the stream fails instead of pretending to be complete.
        assert!(matches!(body.frame().await, Some(Err(_))));
    }

    #[tokio::test]
    async fn stream_that_keeps_moving_never_expires() {
        let registry = H2StallRegistry::new();
        let payload = Bytes::from(vec![1_u8; PIECE * 3]);
        let mut body = registry.guard(in_pieces(full_http_body(payload), PIECE));
        // The limit is far above the 30 ms gaps so a loaded machine (where a 30 ms sleep can
        // take much longer) cannot turn a moving stream into a stalled one.
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_millis(30)).await;
            assert!(registry.expire_stalled(Duration::from_secs(2)).is_none());
            assert!(body.frame().await.is_some());
        }
    }

    #[tokio::test]
    async fn time_with_a_blocked_socket_does_not_count() {
        let registry = H2StallRegistry::new();
        let transport = registry.transport();
        let mut body = registry.guard(full_http_body(Bytes::from_static(b"hello")));
        assert!(body.frame().await.is_some());

        transport.mark_blocked();
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(
            registry.expire_stalled(Duration::from_millis(40)).is_none(),
            "every stream waits while the link is the bottleneck"
        );
        transport.mark_writable();
        assert!(registry.expire_stalled(Duration::from_millis(40)).is_none());
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(registry.expire_stalled(Duration::from_millis(40)).is_some());
    }

    /// Review 13: writable time must add up across short blocked periods. The stream waits
    /// 5 x (30 ms writable + 10 ms blocked): 150 ms writable in total, past a 100 ms limit,
    /// although no single writable stretch reaches it.
    #[tokio::test]
    async fn writable_time_accumulates_across_short_blocked_periods() {
        let registry = H2StallRegistry::new();
        let transport = registry.transport();
        let mut body = registry.guard(full_http_body(Bytes::from_static(b"hello")));
        assert!(body.frame().await.is_some());

        // Sleeps are measured rather than assumed (a loaded machine stretches them): the stream
        // must expire only once the MEASURED writable time reaches the limit, and must expire.
        let limit = Duration::from_millis(100);
        let mut writable_total = Duration::ZERO;
        let mut longest_stretch = Duration::ZERO;
        let mut expired = false;
        for _ in 0..40_u32 {
            let started = std::time::Instant::now();
            tokio::time::sleep(Duration::from_millis(30)).await;
            transport.mark_blocked();
            let stretch = started.elapsed();
            writable_total += stretch;
            longest_stretch = longest_stretch.max(stretch);
            tokio::time::sleep(Duration::from_millis(10)).await;
            transport.mark_writable();
            if registry.expire_stalled(limit).is_some() {
                expired = true;
                break;
            }
        }
        assert!(
            expired,
            "writable time adds up across blocked periods and expires the stream"
        );
        assert!(
            writable_total + Duration::from_millis(5) >= limit,
            "expired after only {writable_total:?} of writable time (limit {limit:?})"
        );
        if longest_stretch >= limit {
            // The machine was so slow that one stretch alone reached the limit: the
            // accumulation itself was not exercised this time, but nothing was wrong.
            return;
        }
    }

    /// Review of section 4e: bytes a cancelled stream had handed over, which hyper discards,
    /// do not make a later, fully written response look undelivered.
    #[tokio::test]
    async fn cancelled_stream_does_not_leave_phantom_pending_data() {
        let registry = H2StallRegistry::new();
        let transport = registry.transport();
        let window = SHORT_WINDOW;

        // Stream 1: 1,000 bytes handed, 400 written, then the client cancels.
        let mut cancelled = registry.guard(full_http_body(Bytes::from(vec![0_u8; 1_000])));
        assert!(cancelled.frame().await.is_some());
        transport.add_data_written(400);
        drop(cancelled);

        // Stream 2: 500 bytes handed and fully written.
        let mut later = registry.guard(full_http_body(Bytes::from(vec![0_u8; 500])));
        while later.frame().await.is_some() {}
        transport.add_data_written(500);
        assert!(
            transport.is_delivering(window),
            "right after the last write the difference is not yet known to be discarded"
        );
        tokio::time::sleep(SHORT_WINDOW + Duration::from_millis(50)).await;
        assert!(
            !transport.is_delivering(window),
            "once DATA has been still, the cancelled stream's bytes no longer count"
        );
        // Exact again for the next response.
        let mut next = registry.guard(full_http_body(Bytes::from(vec![0_u8; 300])));
        while next.frame().await.is_some() {}
        let long = Duration::from_secs(30);
        assert!(transport.is_delivering(long));
        transport.add_data_written(300);
        assert!(!transport.is_delivering(long));
    }

    #[tokio::test]
    async fn finished_and_dropped_streams_are_forgotten() {
        let registry = H2StallRegistry::new();
        let body = registry.guard(full_http_body(Bytes::from_static(b"x")));
        assert!(registry.has_open_streams());
        drop(body);
        assert!(!registry.has_open_streams());
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(registry.expire_stalled(Duration::from_millis(10)).is_none());
    }

    /// The client's `RST_STREAM` frames are counted wherever a read ends, and nothing is
    /// counted on a connection that is not HTTP/2 (Codex 82, audit claim 6).
    #[test]
    fn reset_frames_are_counted_from_the_bytes_read() {
        let frame = |kind: u8, payload: &[u8]| {
            let len = u32::try_from(payload.len()).unwrap_or(0).to_be_bytes();
            let mut bytes = vec![len[1], len[2], len[3], kind, 0, 0, 0, 0, 1];
            bytes.extend_from_slice(payload);
            bytes
        };
        let mut stream = super::ResetFrameCounter::PREFACE.to_vec();
        stream.extend(frame(4, &[]));
        // A DATA frame whose payload looks like a RST_STREAM header.
        stream.extend(frame(0, &[0, 0, 4, 3, 0, 0, 0, 0, 1, 0, 0, 0, 8]));
        stream.extend(frame(3, &[0, 0, 0, 8]));
        stream.extend(frame(1, &[0x82]));
        stream.extend(frame(3, &[0, 0, 0, 8]));
        for step in [1, 2, 7, 9, 10, 64, stream.len()] {
            let mut counter = super::ResetFrameCounter::default();
            let total: u32 = stream.chunks(step).map(|part| counter.feed(part)).sum();
            assert_eq!(total, 2, "in reads of {step}");
        }
        let mut http1 = super::ResetFrameCounter::default();
        assert_eq!(http1.feed(b"POST / HTTP/1.1\r\n\r\n"), 0);
        assert_eq!(http1.feed(&frame(3, &[0, 0, 0, 8])), 0);
    }

    /// After a cancelled stream the count is corrected once, and by what is counted at that
    /// moment (Cloudflare-skills audit of v0.1.0, claim 18; Codex 73 to 75): the decision and
    /// the correction are one step under a lock, so two tasks asking cannot both subtract, and
    /// a response that starts in between keeps its bytes.
    #[test]
    fn a_cancelled_streams_bytes_are_discarded_once() {
        use std::sync::Arc;
        let transport = Arc::new(super::TransportWriteState::default());
        let state = |transport: &super::TransportWriteState| {
            let delivery = transport.delivery();
            (delivery.handed, delivery.written, delivery.discard_pending)
        };
        // The progress window has passed for a connection that never wrote DATA.
        let window = Duration::ZERO;
        transport.add_handed(1_000);
        transport.delivery().written = 400;
        transport.note_cancelled();
        // Many tasks ask at once, while responses are handed over and written in full.
        let start = Arc::new(std::sync::Barrier::new(8));
        let tasks: Vec<_> = (0..8)
            .map(|n| {
                let (transport, start) = (Arc::clone(&transport), Arc::clone(&start));
                std::thread::spawn(move || {
                    start.wait();
                    for _ in 0..2_000 {
                        if n % 2 == 0 {
                            let _ = transport.is_delivering(window);
                        } else {
                            transport.add_handed(7);
                            transport.add_data_written(7);
                        }
                    }
                })
            })
            .collect();
        for task in tasks {
            assert!(task.join().is_ok());
        }
        // The cancelled 600 are gone and nothing was subtracted twice: the count of handed
        // bytes never went below zero or wrapped (with a zero window, bytes handed over but
        // not yet written at the moment of the correction go with them, never more).
        let (handed, written, pending) = state(&transport);
        assert_eq!(written, 400 + 4 * 2_000 * 7);
        assert!(!pending);
        assert!(
            handed <= written && written - handed <= 4 * 7,
            "{handed} of {written}"
        );
    }

    /// A body of the given frames.
    struct Frames(std::collections::VecDeque<http_body::Frame<Bytes>>);

    impl http_body::Body for Frames {
        type Data = Bytes;
        type Error = crate::HttpError;
        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, crate::HttpError>>> {
            std::task::Poll::Ready(self.0.pop_front().map(Ok))
        }
    }

    /// A response that ends with trailers is finished, not cut short (Codex 70 finding 4):
    /// hyper does not poll again after them.
    #[tokio::test]
    async fn a_response_ending_with_trailers_is_not_a_reset() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        let registry = H2StallRegistry::new();
        for with_trailers in [true, false] {
            let cancelled = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&cancelled);
            let mut frames = std::collections::VecDeque::new();
            frames.push_back(http_body::Frame::data(Bytes::from_static(b"x")));
            if with_trailers {
                frames.push_back(http_body::Frame::trailers(http::HeaderMap::new()));
            }
            let mut body = registry.guard_counting(
                Frames(frames).boxed(),
                Some(Box::new(move || flag.store(true, Ordering::Release))),
            );
            let expected = if with_trailers { 2 } else { 1 };
            for _ in 0..expected {
                assert!(body.frame().await.is_some());
            }
            drop(body);
            // Without trailers the end was not reached: that is a response cut short.
            assert_eq!(cancelled.load(Ordering::Acquire), !with_trailers);
        }
    }

    /// Cancelling one stream does not make another stream's response look delivered while it
    /// still waits for the client (Codex 71 finding 5, 72 finding 2): hyper takes a response to
    /// its end while h2 holds part of it, so the unsent bytes count until no DATA has moved
    /// for the whole progress window.
    #[tokio::test]
    async fn a_cancelled_stream_does_not_hide_another_streams_delivery() {
        let registry = H2StallRegistry::new();
        let transport = registry.transport();
        let window = Duration::from_secs(30);
        let mut cancelled = registry.guard(full_http_body(Bytes::from(vec![0_u8; 1_000])));
        assert!(cancelled.frame().await.is_some());
        let mut other = registry.guard(full_http_body(Bytes::from(vec![0_u8; 500])));
        drop(cancelled);
        // The other response is taken to its end; none of it has been written yet.
        while other.frame().await.is_some() {}
        tokio::time::sleep(SHORT_WINDOW + Duration::from_millis(50)).await;
        assert!(transport.is_delivering(window));
        // Once nothing has moved for the progress window it is given up, and the count is
        // exact again.
        assert!(!transport.is_delivering(SHORT_WINDOW));
        assert!(!transport.is_delivering(window));
    }

    #[test]
    fn frame_counters_fast_path_matches_byte_by_byte_across_splits() {
        use super::{DataFrameCounter, ResetFrameCounter};

        // Construct a realistic sequence of HTTP/2 frames: SETTINGS (type 4, len 6),
        // HEADERS (type 1, len 12), DATA (type 0, len 20), RST_STREAM (type 3, len 4),
        // DATA (type 0, len 7), RST_STREAM (type 3, len 4).
        let mut wire = Vec::new();
        let push_frame = |buf: &mut Vec<u8>, kind: u8, payload_len: usize| {
            let len_u32 = u32::try_from(payload_len).unwrap_or(0);
            buf.push(u8::try_from((len_u32 >> 16) & 0xff).unwrap_or(0));
            buf.push(u8::try_from((len_u32 >> 8) & 0xff).unwrap_or(0));
            buf.push(u8::try_from(len_u32 & 0xff).unwrap_or(0));
            buf.push(kind);
            buf.extend_from_slice(&[0, 0, 0, 0, 1]);
            buf.extend(std::iter::repeat_n(0x41_u8, payload_len));
        };
        push_frame(&mut wire, 4, 6);
        push_frame(&mut wire, 1, 12);
        push_frame(&mut wire, 0, 20);
        push_frame(&mut wire, 3, 4);
        push_frame(&mut wire, 0, 7);
        push_frame(&mut wire, 3, 4);

        let mut client_wire = Vec::from(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".as_slice());
        client_wire.extend_from_slice(&wire);

        for step in [1_usize, 2, 3, 5, 8, 9, 13, 32, 256] {
            let mut dc = DataFrameCounter::default();
            let mut data_total = 0_u64;
            for chunk in wire.chunks(step) {
                data_total += dc.feed(chunk);
            }
            assert_eq!(data_total, 27, "data mismatch for chunk size {step}");

            let mut rc = ResetFrameCounter::default();
            let mut resets_total = 0_u32;
            for chunk in client_wire.chunks(step) {
                resets_total += rc.feed(chunk);
            }
            assert_eq!(resets_total, 2, "reset mismatch for chunk size {step}");
        }
    }

    #[test]
    fn data_frame_counter_counts_exact_data_payload_across_short_vectored_prefix_and_multiple_streams()
     {
        use super::DataFrameCounter;

        // Build an interleaved multi-stream HTTP/2 frame sequence matching batched small
        // DATA frames alongside control and HEADERS frames across streams 1, 3, 5, and 7.
        let mut wire = Vec::new();
        let push_frame = |buf: &mut Vec<u8>, kind: u8, stream_id: u32, payload_len: usize| {
            let len_u32 = u32::try_from(payload_len).unwrap_or(0);
            buf.push(u8::try_from((len_u32 >> 16) & 0xff).unwrap_or(0));
            buf.push(u8::try_from((len_u32 >> 8) & 0xff).unwrap_or(0));
            buf.push(u8::try_from(len_u32 & 0xff).unwrap_or(0));
            buf.push(kind);
            buf.push(0);
            buf.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
            buf.extend(std::iter::repeat_n(0x42_u8, payload_len));
        };
        push_frame(&mut wire, 1, 1, 24); // HEADERS stream 1
        push_frame(&mut wire, 0, 1, 300); // DATA stream 1
        push_frame(&mut wire, 1, 3, 18); // HEADERS stream 3
        push_frame(&mut wire, 0, 3, 1_024); // DATA stream 3
        push_frame(&mut wire, 4, 0, 6); // SETTINGS stream 0
        push_frame(&mut wire, 1, 5, 31); // HEADERS stream 5
        push_frame(&mut wire, 0, 5, 4_095); // DATA stream 5 (copied limit - 1)
        push_frame(&mut wire, 6, 0, 8); // PING ACK stream 0
        push_frame(&mut wire, 1, 7, 19); // HEADERS stream 7
        push_frame(&mut wire, 0, 7, 4_096); // DATA stream 7 (chained limit)

        let expected_data: u64 = 300 + 1_024 + 4_095 + 4_096;

        // Partition the wire bytes into uneven IoSlice-like segments (including empty slices)
        // and feed short vectored prefixes of varied lengths, mirroring
        // `HeadDeadlineIo::note_write_result` across `poll_write_vectored`.
        let split_points = [0, 5, 5, 19, 340, 340, 1_400, 1_409, 5_550, wire.len()];
        let mut slices: Vec<&[u8]> = Vec::new();
        for pair in split_points.windows(2) {
            if let [start, end] = *pair
                && let Some(seg) = wire.get(start..end)
            {
                slices.push(seg);
            }
        }

        for accept_cap in [1_usize, 4, 7, 9, 13, 37, 257, 1_000, 4_105] {
            let mut dc = DataFrameCounter::default();
            let mut total_data = 0_u64;
            let mut remaining_slices: Vec<&[u8]> = slices.clone();

            while !remaining_slices.is_empty() {
                let avail: usize = remaining_slices.iter().map(|s| s.len()).sum();
                if avail == 0 {
                    break;
                }
                let accepted = avail.min(accept_cap);
                let mut left = accepted;
                let mut next_slices: Vec<&[u8]> = Vec::new();
                for slice in &remaining_slices {
                    if left == 0 {
                        if !slice.is_empty() {
                            next_slices.push(slice);
                        }
                        continue;
                    }
                    let take = slice.len().min(left);
                    if let Some(prefix) = slice.get(..take) {
                        total_data = total_data.saturating_add(dc.feed(prefix));
                    }
                    if let Some(tail) = slice.get(take..)
                        && !tail.is_empty()
                    {
                        next_slices.push(tail);
                    }
                    left -= take;
                }
                remaining_slices = next_slices;
            }

            assert_eq!(
                total_data, expected_data,
                "short vectored prefix cap {accept_cap} miscounted DATA payload"
            );
        }
    }

    #[tokio::test]
    async fn cached_size_hint_tracks_remaining_bytes_and_a_new_stream_always_notifies() {
        use http_body::Body as _;

        let registry = H2StallRegistry::new();
        assert!(!registry.has_open_streams());

        let mut body = registry.guard(in_pieces(
            full_http_body(Bytes::from(vec![3_u8; 3000])),
            1024,
        ));
        // Nobody was waiting when the stream was registered; the notification is stored
        // for the watchdog's next wait all the same, as in v0.1.2.
        assert!(
            tokio::time::timeout(Duration::from_millis(200), registry.changed())
                .await
                .is_ok(),
            "a new stream must leave a notification even when the watchdog is not waiting"
        );
        assert!(registry.has_open_streams());

        assert_eq!(body.size_hint().exact(), Some(3000));
        assert!(body.frame().await.is_some());
        assert_eq!(body.size_hint().exact(), Some(1976));
        assert!(body.frame().await.is_some());
        assert_eq!(body.size_hint().exact(), Some(952));
        assert!(body.frame().await.is_some());
        assert_eq!(body.size_hint().exact(), Some(0));
        assert!(body.frame().await.is_none());
        assert_eq!(body.size_hint().exact(), Some(0));
        assert!(!registry.has_open_streams());
    }

    /// Regression test for Diet Audit 2 P1 #2: on terminal EOF, error, and trailers,
    /// `H2StallBody::poll_frame` must decrement `transport.delivery.unfinished` BEFORE marking
    /// the registry stream entry `done` (exact v0.1.2 order) so the idle watchdog cannot arm and
    /// begin graceful shutdown while the unfinished-response count is still nonzero.
    #[test]
    fn terminal_poll_decrements_unfinished_before_marking_stream_done()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::pin::Pin;
        use std::sync::mpsc;
        use std::task::{Context, Poll, Waker};

        #[derive(Clone, Copy, Debug)]
        enum TerminalKind {
            Eof,
            Error,
            Trailers,
        }

        struct SignalingTerminalBody {
            kind: TerminalKind,
            polled_tx: Option<mpsc::Sender<()>>,
        }

        impl http_body::Body for SignalingTerminalBody {
            type Data = Bytes;
            type Error = crate::HttpError;

            fn poll_frame(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
                if let Some(tx) = self.polled_tx.take() {
                    let _ = tx.send(());
                }
                match self.kind {
                    TerminalKind::Eof => Poll::Ready(None),
                    TerminalKind::Error => {
                        Poll::Ready(Some(Err(crate::HttpError::Body("boom".to_owned()))))
                    }
                    TerminalKind::Trailers => {
                        Poll::Ready(Some(Ok(http_body::Frame::trailers(http::HeaderMap::new()))))
                    }
                }
            }
        }

        for kind in [
            TerminalKind::Eof,
            TerminalKind::Error,
            TerminalKind::Trailers,
        ] {
            let registry = H2StallRegistry::new();
            let transport = registry.transport();
            let (polled_tx, polled_rx) = mpsc::channel();
            let (done_tx, done_rx) = mpsc::channel();

            let mut body = registry.guard_counting(
                SignalingTerminalBody {
                    kind,
                    polled_tx: Some(polled_tx),
                }
                .boxed(),
                None,
            );
            assert!(registry.has_open_streams());
            assert_eq!(transport.delivery().unfinished, 1);

            // Hold `transport.delivery` so `transport.response_ended()` blocks until we release
            // it. In v0.1.2 order, `state.done` must NOT become true while `unfinished == 1`.
            let delivery_guard = transport.delivery();
            assert_eq!(delivery_guard.unfinished, 1);

            let worker = std::thread::spawn(move || {
                let waker = Waker::noop();
                let mut cx = Context::from_waker(waker);
                let _ = http_body::Body::poll_frame(Pin::new(&mut body), &mut cx);
                let _ = done_tx.send(());
                drop(body);
            });

            polled_rx.recv_timeout(Duration::from_secs(2))?;
            // Give the worker thread ample time to advance past `inner.poll_frame` and block on
            // `transport.response_ended()`. If it flipped `state.done` beforehand, `has_open_streams`
            // becomes false while `unfinished == 1`.
            for _ in 0..20 {
                assert!(
                    registry.has_open_streams(),
                    "{kind:?}: registry marked stream done BEFORE transport.response_ended() decremented unfinished"
                );
                assert!(
                    done_rx.try_recv().is_err(),
                    "{kind:?}: poll_frame finished without acquiring transport.delivery"
                );
                std::thread::sleep(Duration::from_millis(1));
            }

            drop(delivery_guard);
            done_rx.recv_timeout(Duration::from_secs(2))?;
            worker.join().map_err(|_| "worker thread panicked")?;

            assert_eq!(transport.delivery().unfinished, 0);
            assert!(!registry.has_open_streams());
        }
        Ok(())
    }

    #[tokio::test]
    async fn idle_since_ms_skips_delivery_mutex_until_h2_delivery_starts()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::ConnectionIdleState;
        use std::sync::Arc;

        let registry = H2StallRegistry::new();
        let transport = registry.transport();
        let idle = Arc::new(ConnectionIdleState::new());
        idle.attach_transport(Arc::clone(&transport), Duration::from_secs(5));
        idle.enter_request();
        idle.exit_request();

        assert!(!transport.has_delivery_accounting());

        // 1. Hold `transport.delivery()` on this thread and verify another thread's
        //    `idle_since_ms()` returns immediately without touching the mutex — both while
        //    writable (`since > 0`) and while socket-blocked (`0`).
        let guard = transport.delivery();
        let idle_for_thread = Arc::clone(&idle);
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let _ = tx.send(idle_for_thread.idle_since_ms());
        });
        let unlocked_since = rx.recv_timeout(Duration::from_millis(500))?;
        reader.join().map_err(|_| "reader thread panicked")?;
        assert!(
            unlocked_since > 0,
            "idle H1 connection must report since > 0"
        );

        transport.mark_blocked();
        let idle_for_thread2 = Arc::clone(&idle);
        let (tx2, rx2) = std::sync::mpsc::channel();
        let reader2 = std::thread::spawn(move || {
            let _ = tx2.send(idle_for_thread2.idle_since_ms());
        });
        let blocked_val = rx2.recv_timeout(Duration::from_millis(500))?;
        reader2.join().map_err(|_| "reader2 thread panicked")?;
        assert_eq!(blocked_val, 0, "blocked socket must still report 0");
        transport.mark_writable();
        drop(guard);

        // 2. Once HTTP/2 delivery accounting is used, `idle_since_ms()` observes handed/written
        //    bytes and `last_data_ms` identically to before.
        let mut body = registry.guard(full_http_body(Bytes::from_static(b"hello")));
        assert!(transport.has_delivery_accounting());
        // First poll hands 5 bytes to hyper; not written yet, so connection is delivering -> 0.
        let frame = body.frame().await;
        assert!(frame.is_some());
        transport.add_data_written(2);
        assert_eq!(idle.idle_since_ms(), 0);
        // Once all 5 bytes are written, idle time advances to max(since, last_data_ms).
        tokio::time::sleep(Duration::from_millis(5)).await;
        transport.add_data_written(3);
        let last_data = transport.last_data_ms();
        assert!(last_data > 0);
        assert_eq!(idle.idle_since_ms(), unlocked_since.max(last_data));
        // Finish the body cleanly.
        assert!(body.frame().await.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn in_pieces_skips_wrapper_for_single_piece_exact_bodies_with_identical_frames() {
        use super::{PieceBody, needs_piece_wrapper};
        use crate::{HttpBody, HttpError, empty_http_body};
        use http_body::{Body, Frame, SizeHint};
        use std::pin::Pin;
        use std::task::{Context, Poll};

        struct UnsizedBody(Option<Bytes>);

        impl Body for UnsizedBody {
            type Data = Bytes;
            type Error = HttpError;

            fn poll_frame(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
                Poll::Ready(self.0.take().map(|b| Ok(Frame::data(b))))
            }

            fn size_hint(&self) -> SizeHint {
                SizeHint::new()
            }
        }

        async fn collect_frames(mut body: HttpBody) -> Vec<Bytes> {
            let mut frames = Vec::new();
            while let Some(res) = body.frame().await {
                if let Ok(frame) = res
                    && let Ok(data) = frame.into_data()
                {
                    frames.push(data);
                }
            }
            frames
        }

        let piece = 1_024_usize;
        assert!(!needs_piece_wrapper(&empty_http_body(), piece));
        for len in [0_usize, 1, piece - 1, piece] {
            let payload = Bytes::from(vec![b'x'; len]);
            let b1 = full_http_body(payload.clone());
            assert!(
                !needs_piece_wrapper(&b1, piece),
                "exact body of len {len} <= {piece} must skip PieceBody"
            );
            let wrapped = in_pieces(b1, piece);
            let forced = PieceBody {
                inner: full_http_body(payload),
                pending: None,
                piece,
            }
            .boxed();
            assert_eq!(wrapped.is_end_stream(), forced.is_end_stream());
            assert_eq!(wrapped.size_hint().exact(), forced.size_hint().exact());
            assert_eq!(collect_frames(wrapped).await, collect_frames(forced).await);
        }

        // One byte over `piece` still wraps and splits into two frames.
        let over = Bytes::from(vec![b'y'; piece + 1]);
        let b_over = full_http_body(over.clone());
        assert!(needs_piece_wrapper(&b_over, piece));
        let over_frames = collect_frames(in_pieces(b_over, piece)).await;
        assert_eq!(over_frames.len(), 2);
        assert_eq!(over_frames.first().map(Bytes::len), Some(piece));
        assert_eq!(over_frames.get(1).map(Bytes::len), Some(1));

        // Unknown-size bodies (`exact() == None`) MUST still wrap even if small or large.
        let small_unsized: HttpBody = UnsizedBody(Some(Bytes::from(vec![b'z'; 64]))).boxed();
        assert!(needs_piece_wrapper(&small_unsized, piece));
        let large_unsized: HttpBody =
            UnsizedBody(Some(Bytes::from(vec![b'z'; piece + 17]))).boxed();
        assert!(needs_piece_wrapper(&large_unsized, piece));
        let unsized_frames = collect_frames(in_pieces(large_unsized, piece)).await;
        assert_eq!(unsized_frames.len(), 2);
        assert_eq!(unsized_frames.first().map(Bytes::len), Some(piece));
        assert_eq!(unsized_frames.get(1).map(Bytes::len), Some(17));
    }

    #[tokio::test]
    async fn guard_inner_recycles_dropped_stream_state_and_idle_sweep_frees_it()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::{Arc, PoisonError};

        use super::StallInner;

        let registry = H2StallRegistry::new();

        // 1. Stream 1 completes and is dropped -> leaves 1 done entry with strong_count == 1.
        let mut s1 = registry.guard_inner(
            StallInner::Http(full_http_body(Bytes::from_static(b"one"))),
            None,
        );
        let ptr1 = Arc::as_ptr(&s1.state) as usize;
        while s1.frame().await.is_some() {}
        // While `s1` is still alive (`done == true`, `strong_count == 2`), Stream 2 MUST NOT reuse `ptr1`.
        let mut s2 = registry.guard_inner(
            StallInner::Http(full_http_body(Bytes::from_static(b"two"))),
            None,
        );
        let ptr2 = Arc::as_ptr(&s2.state) as usize;
        assert_ne!(
            ptr1, ptr2,
            "must not recycle StreamState while prior H2StallBody still holds an Arc"
        );
        drop(s1);

        // 2. Now `ptr1` has `done == true` and `strong_count == 1`; Stream 3 MUST recycle `ptr1`.
        let mut s3 = registry.guard_inner(
            StallInner::Http(full_http_body(Bytes::from_static(b"three"))),
            None,
        );
        let ptr3 = Arc::as_ptr(&s3.state) as usize;
        assert_eq!(ptr3, ptr1, "expected Stream 3 to recycle dropped Stream 1");
        assert!(registry.has_open_streams());
        while s2.frame().await.is_some() {}
        drop(s2);
        while s3.frame().await.is_some() {}
        drop(s3);
        assert!(!registry.has_open_streams());

        // 3. Poison a finished `StreamState`'s `inner` mutex and mark it expired, then verify
        //    recycling clears poison and expired flag cleanly.
        {
            let streams = registry
                .streams
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let target = Arc::clone(streams.back().ok_or("expected retained StreamState")?);
            target
                .expired
                .store(true, std::sync::atomic::Ordering::Release);
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = target.inner.lock();
                #[allow(clippy::panic)]
                {
                    panic!("intentional test poison");
                }
            }));
            assert!(target.inner.is_poisoned());
        }
        let mut s4 = registry.guard_inner(
            StallInner::Http(full_http_body(Bytes::from_static(b"recovered"))),
            None,
        );
        assert!(!s4.state.inner.is_poisoned());
        assert!(!s4.state.expired.load(std::sync::atomic::Ordering::Acquire));
        let mut out = Vec::new();
        while let Some(res) = s4.frame().await {
            if let Ok(data) = res?.into_data() {
                out.extend_from_slice(&data);
            }
        }
        assert_eq!(out, b"recovered");
        drop(s4);

        // 4. Watchdog sweep (`expire_stalled`) frees all idle finished entries so idle connections
        //    retain zero `Arc<StreamState>` allocations.
        assert!(registry.expire_stalled(SHORT_WINDOW).is_none());
        let retained = registry
            .streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len();
        assert_eq!(
            retained, 0,
            "active expire_stalled sweep must free all finished StreamStates"
        );
        Ok(())
    }

    /// Regression test for Codex Round-1 P1-2 (`e279303`): recycling a finished `StreamState` MUST
    /// preserve exact registration order of all surviving streams during `expire_stalled` sweeps
    /// (so interrupted response body drops and access-log emission stay in registration order),
    /// while still reusing the allocation and pruning other finished shells at `len == 64`.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn guard_inner_recycle_preserves_registration_release_order_and_reuses_allocation()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::pin::Pin;
        use std::sync::{Arc, Mutex, PoisonError};
        use std::task::{Context, Poll};

        use http_body::{Body, Frame};
        use http_body_util::BodyExt as _;

        use super::StallInner;
        use crate::HttpError;

        /// Test body that yields one DATA frame, then stays Pending until dropped, recording its
        /// label on drop to observe exact watchdog release order.
        struct DropOrderBody {
            label: &'static str,
            sent_first: bool,
            log: Arc<Mutex<Vec<&'static str>>>,
        }

        impl Body for DropOrderBody {
            type Data = Bytes;
            type Error = HttpError;

            fn poll_frame(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
                if self.sent_first {
                    Poll::Pending
                } else {
                    self.sent_first = true;
                    Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"chunk")))))
                }
            }
        }

        impl Drop for DropOrderBody {
            fn drop(&mut self) {
                self.log
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(self.label);
            }
        }

        // 1. Codex's exact counterexample: [A, B, C] -> A finishes & drops -> D registers and
        //    reuses A's allocation -> registry order MUST be [B, C, D] (NOT [C, B, D]), so when B
        //    and C both stall in the same sweep, B is released strictly BEFORE C.
        {
            let registry = H2StallRegistry::new();
            let drops = Arc::new(Mutex::new(Vec::<&'static str>::new()));

            let mut a = registry.guard_inner(
                StallInner::Http(full_http_body(Bytes::from_static(b"a"))),
                None,
            );
            let ptr_a = Arc::as_ptr(&a.state) as usize;
            let mut b = registry.guard_inner(
                StallInner::Http(
                    DropOrderBody {
                        label: "B",
                        sent_first: false,
                        log: Arc::clone(&drops),
                    }
                    .boxed(),
                ),
                None,
            );
            let mut c = registry.guard_inner(
                StallInner::Http(
                    DropOrderBody {
                        label: "C",
                        sent_first: false,
                        log: Arc::clone(&drops),
                    }
                    .boxed(),
                ),
                None,
            );

            // Hand over first piece of B and C so both enter waiting/stalled state.
            assert!(b.frame().await.is_some());
            assert!(c.frame().await.is_some());

            // A finishes and drops -> A is at front() with done == true, strong_count == 1.
            while a.frame().await.is_some() {}
            drop(a);

            // Register D -> MUST reuse A's allocation AND keep [B, C, D] order.
            let mut d = registry.guard_inner(
                StallInner::Http(
                    DropOrderBody {
                        label: "D",
                        sent_first: false,
                        log: Arc::clone(&drops),
                    }
                    .boxed(),
                ),
                None,
            );
            let ptr_d = Arc::as_ptr(&d.state) as usize;
            assert_eq!(ptr_d, ptr_a, "expected D to reuse finished A's StreamState");

            // Stall B and C past SHORT_WINDOW (D has not handed over a piece yet, so D stays open).
            tokio::time::sleep(SHORT_WINDOW + Duration::from_millis(20)).await;
            assert!(registry.expire_stalled(SHORT_WINDOW).is_some());

            let released_order = drops.lock().unwrap_or_else(PoisonError::into_inner).clone();
            assert_eq!(
                released_order,
                vec!["B", "C"],
                "watchdog sweep must release surviving streams in registration order [B, C]"
            );

            // Clean up D (now stalled after handing over a piece).
            assert!(d.frame().await.is_some());
            drop(b);
            drop(c);
            drop(d);
        }

        // 2. LIFO (`back()`) reuse when an older stream X remains open at `front()`:
        //    [X(open), Y(done)] -> Z reuses Y -> [X, Z] -> sweep releases X strictly before Z.
        {
            let registry = H2StallRegistry::new();
            let drops = Arc::new(Mutex::new(Vec::<&'static str>::new()));

            let mut x = registry.guard_inner(
                StallInner::Http(
                    DropOrderBody {
                        label: "X",
                        sent_first: false,
                        log: Arc::clone(&drops),
                    }
                    .boxed(),
                ),
                None,
            );
            let mut y = registry.guard_inner(
                StallInner::Http(full_http_body(Bytes::from_static(b"y"))),
                None,
            );
            let ptr_y = Arc::as_ptr(&y.state) as usize;
            while y.frame().await.is_some() {}
            drop(y);

            let mut z = registry.guard_inner(
                StallInner::Http(
                    DropOrderBody {
                        label: "Z",
                        sent_first: false,
                        log: Arc::clone(&drops),
                    }
                    .boxed(),
                ),
                None,
            );
            assert_eq!(
                Arc::as_ptr(&z.state) as usize,
                ptr_y,
                "expected Z to reuse back() shell Y while X stays open at front()"
            );
            assert!(x.frame().await.is_some());
            assert!(z.frame().await.is_some());
            tokio::time::sleep(SHORT_WINDOW + Duration::from_millis(20)).await;
            assert!(registry.expire_stalled(SHORT_WINDOW).is_some());
            let released_order = drops.lock().unwrap_or_else(PoisonError::into_inner).clone();
            assert_eq!(released_order, vec!["X", "Z"]);
            drop(x);
            drop(z);
        }

        // 3. At-exactly-64 threshold: when `streams.len() == 64` with 64 finished shells,
        //    registering stream #65 reuses one allocation AND prunes all other 63 finished shells.
        {
            let registry = H2StallRegistry::new();
            let mut open = Vec::with_capacity(64);
            let mut ptrs = std::collections::HashSet::with_capacity(64);
            for _ in 0..64 {
                let s = registry.guard_inner(
                    StallInner::Http(full_http_body(Bytes::from_static(b"burst"))),
                    None,
                );
                ptrs.insert(Arc::as_ptr(&s.state) as usize);
                open.push(s);
            }
            for mut s in open {
                while s.frame().await.is_some() {}
                drop(s);
            }
            assert_eq!(
                registry
                    .streams
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .len(),
                64
            );
            let s65 = registry.guard_inner(
                StallInner::Http(full_http_body(Bytes::from_static(b"next"))),
                None,
            );
            assert!(
                ptrs.contains(&(Arc::as_ptr(&s65.state) as usize)),
                "stream #65 should recycle one of the 64 finished shells"
            );
            assert_eq!(
                registry
                    .streams
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .len(),
                1,
                "at len == 64, recycling must still prune all other finished shells"
            );
            drop(s65);
        }

        Ok(())
    }
}

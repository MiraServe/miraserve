//! HTTP/2 & HTTP/3 flood defenses (CVE-2023-44487 Rapid Reset rate caps, bad-request
//! strike limits, and Slowloris minimum body transfer-rate enforcement).

use std::future::Future as _;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body::{Body, Frame};
use miraserve_config::{LimitsConfig, TimeoutsConfig};
use tokio::time::Sleep;

/// Maximum rejected/malformed requests tolerated per 60-second window on a single persistent
/// connection before terminating the connection (`R2-HTTP-2`).
const DEFAULT_MAX_BAD_REQUESTS: u32 = 20;

/// Sliding time window (in seconds) over which server-generated bad-request strikes accumulate.
const BAD_REQUEST_WINDOW_SECS: u64 = 60;

/// Grace period / sliding throughput window before Slowloris minimum rate checks engage.
const SLOWLORIS_GRACE_PERIOD: Duration = Duration::from_secs(10);

/// Per-connection flood guard tracking HTTP/2 `RST_STREAM` rates and bad-request strikes.
#[derive(Debug)]
pub struct ConnectionFloodGuard {
    epoch: Instant,
    max_rst_per_sec: u32,
    max_bad_requests: u32,
    window_sec: AtomicU64,
    bad_req_window: AtomicU64,
    bad_requests: AtomicU32,
}

impl ConnectionFloodGuard {
    /// Creates a new per-connection [`ConnectionFloodGuard`] from [`LimitsConfig`].
    #[must_use]
    pub fn from_limits(limits: &LimitsConfig) -> Self {
        Self {
            epoch: Instant::now(),
            max_rst_per_sec: limits.max_h2_rst_stream_per_sec.max(1),
            max_bad_requests: DEFAULT_MAX_BAD_REQUESTS,
            window_sec: AtomicU64::new(0),
            bad_req_window: AtomicU64::new(0),
            bad_requests: AtomicU32::new(0),
        }
    }

    /// Records a stream reset (`RST_STREAM` / H3 stream cancellation).
    ///
    /// Returns `false` if the connection exceeded `max_h2_rst_stream_per_sec` and must
    /// be closed immediately with `ENHANCE_YOUR_CALM` / connection drop.
    #[must_use]
    pub fn record_stream_reset(&self) -> bool {
        self.record_stream_reset_at(Instant::now())
    }

    /// Deterministic clock variant of [`Self::record_stream_reset`] for unit testing.
    #[must_use]
    pub fn record_stream_reset_at(&self, now: Instant) -> bool {
        // The second and its count change together (one word: the second above, the count
        // below), so a reset is never counted in a second that has just been replaced.
        let current_sec = now.saturating_duration_since(self.epoch).as_secs() & 0xFFFF_FFFF;
        let mut seen = self.window_sec.load(Ordering::Acquire);
        loop {
            let (sec, count) = (seen >> 32, seen & 0xFFFF_FFFF);
            let count = if current_sec > sec {
                1
            } else {
                count.saturating_add(1).min(0xFFFF_FFFF)
            };
            let next = (current_sec.max(sec) << 32) | count;
            match self.window_sec.compare_exchange_weak(
                seen,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return count <= u64::from(self.max_rst_per_sec),
                Err(now) => seen = now,
            }
        }
    }

    /// Records a server-generated malformed/smuggling-rejected request on this connection.
    ///
    /// Strikes decay across 60-second windows (`R2-HTTP-2`) so long-lived multiplexed CDN
    /// connections do not accumulate strikes indefinitely. Returns `false` if the bad-request
    /// budget in the current window is exhausted and the connection should drain and close.
    #[must_use]
    pub fn record_bad_request(&self) -> bool {
        self.record_bad_request_at(Instant::now())
    }

    /// Deterministic clock variant of [`Self::record_bad_request`] for unit testing.
    #[must_use]
    pub fn record_bad_request_at(&self, now: Instant) -> bool {
        let current_win =
            now.saturating_duration_since(self.epoch).as_secs() / BAD_REQUEST_WINDOW_SECS;
        let prev_win = self.bad_req_window.load(Ordering::Acquire);
        if current_win > prev_win
            && self
                .bad_req_window
                .compare_exchange(prev_win, current_win, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            self.bad_requests.store(1, Ordering::Release);
            return true;
        }
        let strikes = self
            .bad_requests
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        strikes <= self.max_bad_requests
    }
}

/// Error returned when a request body violates size or Slowloris minimum-rate limits.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BodyGuardError {
    /// Request body exceeded `server.limits.max_body_bytes`.
    #[error("request body exceeded maximum size of {max_bytes} bytes")]
    PayloadTooLarge {
        /// Configured ceiling in bytes.
        max_bytes: u64,
    },
    /// Request body transfer rate dropped below `server.timeouts.min_body_rate_bps`.
    #[error("request body read rate fell below minimum {min_rate_bps} bytes/sec (Slowloris guard)")]
    SlowBodyRate {
        /// Configured minimum bytes per second.
        min_rate_bps: u64,
    },
    /// Underlying transport error from the wrapped body.
    #[error("underlying body error: {0}")]
    Inner(String),
}

/// Wrapping [`http_body::Body`] adapter that enforces `max_body_bytes`, `body_idle_timeout`
/// (even when `min_body_rate_bps == 0`, `R4-HTTP-1`), AND `min_body_rate_bps` (Threat Model T4
/// Slowloris protection) on streaming request bodies.
///
/// Hardening (`R2-HTTP-1`, `R3-HTTP-1`, `R3-HTTP-2`, `R4-HTTP-1`, `R4-HTTP-2`, `R4-HTTP-3`):
/// - Always enforces `body_idle_timeout` (default 30s) on continuous stalls, including when
///   `min_body_rate_bps == 0` (`R4-HTTP-1`).
/// - Skips the throughput rate check while actively paused `< body_idle_timeout` so
///   `body_idle_timeout` governs pauses even for low-rate mobile clients (`R4-HTTP-2`).
/// - Measures elapsed time **strictly while the inner body returns `Poll::Pending`** so time spent
///   NOT being polled due to slow upstream back-pressure is NEVER charged to the client!
/// - Preserves structured inner transport errors (such as HTTP/3 `PayloadTooLarge`) via
///   [`Self::with_error_mapper`] (`R4-HTTP-3`).
/// - Embeds a lazy Tokio wakeup timer so completely stalled peers are actively woken and closed.
pub struct BoundedBody<B: Body> {
    inner: B,
    first_poll_at: Option<Instant>,
    pending_since: Option<Instant>,
    idle_wait: Duration,
    window_active_wait: Duration,
    window_bytes: u64,
    consecutive_pauses_without_quota: u32,
    total_free_pause_used: Duration,
    max_total_free_pause: Duration,
    bytes_read: u64,
    max_body_bytes: u64,
    min_body_rate_bps: u64,
    grace_period: Duration,
    idle_gap_timeout: Duration,
    max_body_duration: Duration,
    rate_timer: Option<Pin<Box<Sleep>>>,
    error_mapper: fn(B::Error) -> BodyGuardError,
}

impl<B> BoundedBody<B>
where
    B: Body,
    B::Error: std::fmt::Display,
{
    /// Wraps `inner` with limits from [`LimitsConfig`] and [`TimeoutsConfig`].
    #[must_use]
    pub fn new(inner: B, limits: &LimitsConfig, timeouts: &TimeoutsConfig) -> Self {
        Self {
            inner,
            first_poll_at: None,
            pending_since: None,
            idle_wait: Duration::ZERO,
            window_active_wait: Duration::ZERO,
            window_bytes: 0,
            consecutive_pauses_without_quota: 0,
            total_free_pause_used: Duration::ZERO,
            max_total_free_pause: timeouts.body_idle_timeout.saturating_mul(2),
            bytes_read: 0,
            max_body_bytes: limits.max_body_bytes.as_bytes(),
            min_body_rate_bps: timeouts.min_body_rate_bps,
            grace_period: SLOWLORIS_GRACE_PERIOD,
            idle_gap_timeout: timeouts.body_idle_timeout,
            max_body_duration: timeouts.max_body_duration,
            rate_timer: None,
            error_mapper: |err| BodyGuardError::Inner(err.to_string()),
        }
    }

    /// Overrides the mapper converting inner stream errors into [`BodyGuardError`] so structured
    /// variants (e.g. HTTP/3 `PayloadTooLarge` -> `413`) survive intact (`R4-HTTP-3`).
    #[must_use]
    pub fn with_error_mapper(mut self, mapper: fn(B::Error) -> BodyGuardError) -> Self {
        self.error_mapper = mapper;
        self
    }

    /// Overrides both the Slowloris rate grace window and idle-gap ceiling (primarily for
    /// deterministic testing).
    #[must_use]
    pub fn with_grace_period(mut self, grace: Duration) -> Self {
        self.grace_period = grace;
        self.idle_gap_timeout = grace;
        self.max_total_free_pause = grace.saturating_mul(2);
        self.rate_timer = None;
        self
    }

    /// Overrides the maximum idle gap permitted between request body frames (`R3-HTTP-1`),
    /// independently of the Slowloris rate calculation window.
    #[must_use]
    pub fn with_idle_gap(mut self, idle_gap: Duration) -> Self {
        self.idle_gap_timeout = idle_gap;
        self.max_total_free_pause = idle_gap.saturating_mul(2);
        self.rate_timer = None;
        self
    }

    /// Overrides the absolute maximum wall-clock duration permitted for the entire request body
    /// from first poll (`R5-HTTP-2`).
    #[must_use]
    pub fn with_max_body_duration(mut self, max_duration: Duration) -> Self {
        self.max_body_duration = max_duration;
        self.rate_timer = None;
        self
    }

    fn check_rate_waits(
        &self,
        total_idle: Duration,
        total_win_wait: Duration,
        total_elapsed: Duration,
    ) -> Result<(), BodyGuardError> {
        // 0. R5-HTTP-2: Absolute maximum wall-clock body duration ALWAYS applies (even when
        //    `min_body_rate_bps == 0` or a client trickles just under `body_idle_timeout`).
        if total_elapsed >= self.max_body_duration {
            return Err(BodyGuardError::SlowBodyRate {
                min_rate_bps: self.min_body_rate_bps,
            });
        }
        // 1. R4-HTTP-1: Per-idle-gap guard ALWAYS applies even when `min_body_rate_bps == 0` so
        //    a silent peer cannot hold tasks/upstream connections open forever.
        if total_idle >= self.idle_gap_timeout {
            return Err(BodyGuardError::SlowBodyRate {
                min_rate_bps: self.min_body_rate_bps,
            });
        }
        if self.min_body_rate_bps == 0 {
            return Ok(());
        }
        // 2. R4-HTTP-2: While actively paused below `body_idle_timeout`, let `body_idle_timeout`
        //    govern the pause rather than cutting off low-rate mobile clients early at 10s.
        if total_idle > Duration::ZERO && total_idle < self.idle_gap_timeout {
            return Ok(());
        }
        // 3. Sliding-window throughput check against `min_body_rate_bps` (evaluated on arriving
        //    frames once active streaming wait reaches `grace_period`, excluding legitimate
        //    single pauses `< body_idle_timeout` per `R5-HTTP-1`).
        if total_win_wait < self.grace_period {
            return Ok(());
        }
        let expected_u128 =
            (u128::from(self.min_body_rate_bps).saturating_mul(total_win_wait.as_millis())) / 1000;
        let min_expected = u64::try_from(expected_u128).unwrap_or(u64::MAX).max(1);
        if self.window_bytes < min_expected {
            return Err(BodyGuardError::SlowBodyRate {
                min_rate_bps: self.min_body_rate_bps,
            });
        }
        Ok(())
    }

    /// Computes the remaining active pending-wait budget before either `body_idle_timeout` or
    /// `max_body_duration` trips.
    fn remaining_wait_budget(&self, total_idle: Duration, total_elapsed: Duration) -> Duration {
        self.idle_gap_timeout
            .saturating_sub(total_idle)
            .min(self.max_body_duration.saturating_sub(total_elapsed))
    }

    /// Converts surplus bytes transferred above `min_body_rate_bps` over `active_wait` into
    /// earned pause-budget replenishment (`R7-HTTP-1`).
    fn surplus_pause_credit(&self, window_bytes: u64, active_wait: Duration) -> Duration {
        if self.min_body_rate_bps == 0 {
            return Duration::ZERO;
        }
        let required_u128 =
            (u128::from(self.min_body_rate_bps).saturating_mul(active_wait.as_millis())) / 1000;
        let required = u64::try_from(required_u128).unwrap_or(u64::MAX);
        let surplus = window_bytes.saturating_sub(required);
        if surplus == 0 {
            return Duration::ZERO;
        }
        let earned_ms_u128 =
            (u128::from(surplus).saturating_mul(1000)) / u128::from(self.min_body_rate_bps);
        let earned_ms = u64::try_from(earned_ms_u128).unwrap_or(u64::MAX);
        Duration::from_millis(earned_ms)
    }
}

/// Clock used by [`BoundedBody`]. It is tokio's clock, which is the system monotonic clock in
/// production and can be paused and advanced in tests, so the upload-rate rules can be tested
/// without depending on how fast the test machine is.
fn body_clock_now() -> Instant {
    tokio::time::Instant::now().into_std()
}

impl<B> Body for BoundedBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    type Data = Bytes;
    type Error = BodyGuardError;

    #[allow(clippy::too_many_lines)]
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let poll_started = *self.first_poll_at.get_or_insert_with(body_clock_now);
        // R3-HTTP-2: Poll inner body FIRST and charge time strictly while `inner` returns
        // `Poll::Pending`. Time spent NOT being polled (e.g., upstream consumer back-pressure)
        // leaves `pending_since == None` and is NEVER billed to the client!
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Pending => {
                let now = body_clock_now();
                let delta = if let Some(since) = self.pending_since {
                    now.saturating_duration_since(since)
                } else {
                    self.pending_since = Some(now);
                    Duration::ZERO
                };
                let total_idle = self.idle_wait.saturating_add(delta);
                let total_win_wait = self.window_active_wait.saturating_add(delta);
                let total_elapsed = now.saturating_duration_since(poll_started);
                if let Err(err) = self.check_rate_waits(total_idle, total_win_wait, total_elapsed) {
                    self.rate_timer = None;
                    return Poll::Ready(Some(Err(err)));
                }
                let remaining = self.remaining_wait_budget(total_idle, total_elapsed);
                if tokio::runtime::Handle::try_current().is_ok() {
                    let deadline = now + remaining + Duration::from_millis(10);
                    let tokio_deadline = tokio::time::Instant::from_std(deadline);
                    let timer = self
                        .rate_timer
                        .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(tokio_deadline)));
                    if timer.as_mut().poll(cx).is_ready() {
                        self.rate_timer = None;
                        let after = body_clock_now();
                        let d2 = self
                            .pending_since
                            .map_or(Duration::ZERO, |s| after.saturating_duration_since(s));
                        let idle2 = self.idle_wait.saturating_add(d2);
                        let win2 = self.window_active_wait.saturating_add(d2);
                        let elapsed2 = after.saturating_duration_since(poll_started);
                        if let Err(err) = self.check_rate_waits(idle2, win2, elapsed2) {
                            return Poll::Ready(Some(Err(err)));
                        }
                        let next_wake = tokio::time::Instant::now() + Duration::from_millis(25);
                        let mut retry = Box::pin(tokio::time::sleep_until(next_wake));
                        let _ = retry.as_mut().poll(cx);
                        self.rate_timer = Some(retry);
                    }
                }
                Poll::Pending
            }
            Poll::Ready(None) => {
                self.pending_since = None;
                self.rate_timer = None;
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(err))) => {
                self.pending_since = None;
                self.rate_timer = None;
                Poll::Ready(Some(Err((self.error_mapper)(err))))
            }
            Poll::Ready(Some(Ok(frame))) => {
                let frame_now = body_clock_now();
                self.rate_timer = None;
                let total_elapsed = frame_now.saturating_duration_since(poll_started);
                if total_elapsed >= self.max_body_duration {
                    return Poll::Ready(Some(Err(BodyGuardError::SlowBodyRate {
                        min_rate_bps: self.min_body_rate_bps,
                    })));
                }
                let frame_delta = self.pending_since.take().map_or(Duration::ZERO, |since| {
                    frame_now.saturating_duration_since(since)
                });
                self.idle_wait = self.idle_wait.saturating_add(frame_delta);

                if let Some(data) = frame.data_ref() {
                    let n = data.len() as u64;
                    self.bytes_read = self.bytes_read.saturating_add(n);
                    if self.bytes_read > self.max_body_bytes {
                        return Poll::Ready(Some(Err(BodyGuardError::PayloadTooLarge {
                            max_bytes: self.max_body_bytes,
                        })));
                    }
                    if n > 0 {
                        let gap = self.idle_wait;
                        self.idle_wait = Duration::ZERO;
                        let pause_threshold = self.grace_period.min(self.idle_gap_timeout) / 2;
                        let is_discrete_pause = !pause_threshold.is_zero()
                            && gap >= pause_threshold
                            && gap < self.idle_gap_timeout;
                        // R7-HTTP-1: Before judging a discrete pause against the lifetime pause
                        // budget, credit any surplus bytes transferred above `min_body_rate_bps`
                        // since the last window roll back into `total_free_pause_used` (clamped at
                        // 0 so an initial burst can never bank unbounded future pauses).
                        let earned_before_pause =
                            self.surplus_pause_credit(self.window_bytes, self.window_active_wait);
                        let credited_pause_used = if is_discrete_pause {
                            self.total_free_pause_used
                                .saturating_sub(earned_before_pause)
                        } else {
                            self.total_free_pause_used
                        };
                        let next_free_pause = credited_pause_used.saturating_add(gap);
                        let can_pause_again = self.consecutive_pauses_without_quota == 0
                            || earned_before_pause >= gap;
                        if is_discrete_pause
                            && can_pause_again
                            && next_free_pause <= self.max_total_free_pause
                        {
                            // R5-HTTP-1, R6-HTTP-1 & R7-HTTP-1: Do NOT bill a legitimate discrete
                            // pause shorter than `body_idle_timeout` into the active rate window.
                            // Legitimate uploads whose long-run throughput stays >= `min_body_rate_bps`
                            // replenish pause credit via surplus bytes and survive indefinitely;
                            // pause-and-trickle Slowloris peers earn insufficient surplus and still
                            // exhaust `max_total_free_pause` (`2 * body_idle_timeout`).
                            self.total_free_pause_used = next_free_pause;
                            self.consecutive_pauses_without_quota = 1;
                            self.window_active_wait = Duration::ZERO;
                            self.window_bytes = n;
                        } else {
                            self.window_active_wait = self.window_active_wait.saturating_add(gap);
                            self.window_bytes = self.window_bytes.saturating_add(n);
                            if self.min_body_rate_bps > 0
                                && self.window_active_wait >= self.grace_period
                            {
                                if let Err(err) = self.check_rate_waits(
                                    Duration::ZERO,
                                    self.window_active_wait,
                                    total_elapsed,
                                ) {
                                    return Poll::Ready(Some(Err(err)));
                                }
                                // R7-HTTP-1: Healthy active transfer window completed — replenish
                                // `total_free_pause_used` strictly from surplus bytes transferred
                                // above `min_body_rate_bps` during this window (clamped at 0),
                                // reset consecutive-pause counter, and roll the sliding window.
                                let earned = self.surplus_pause_credit(
                                    self.window_bytes,
                                    self.window_active_wait,
                                );
                                self.total_free_pause_used =
                                    self.total_free_pause_used.saturating_sub(earned);
                                self.consecutive_pauses_without_quota = 0;
                                self.window_active_wait = Duration::ZERO;
                                self.window_bytes = n;
                            }
                        }
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

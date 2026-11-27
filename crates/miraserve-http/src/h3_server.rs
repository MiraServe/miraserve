//! HTTP/3 over QUIC connection driver (`h3` + `h3-quinn`) feeding into [`HttpEngine`].
//!
//! Enforces:
//! - RFC 9114 header field-section size cap (`max_field_section_size`)
//! - Header-read timeout on `resolve_request()`
//! - Streaming, zero-pre-buffer request bodies wrapped in [`miraserve_security::BoundedBody`]
//!   (so Slowloris, size limits, anti-smuggling, and auth run BEFORE buffering request payloads)
//! - Strict `Content-Length` vs received body verification and stream error propagation
//! - QUIC SNI propagation for TLS SNI/Host binding (421 Misdirected Request)
//! - RFC 9114 §4.2 hop-by-hop response header stripping

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf as _, Bytes};
use http::header::{CONNECTION, CONTENT_LENGTH, HeaderName, TRANSFER_ENCODING, UPGRADE};
use http::{Request, StatusCode};
use http_body::{Body, Frame};
use http_body_util::BodyExt as _;
use miraserve_security::{BodyGuardError, BoundedBody, ConnectionFloodGuard};
use tokio::sync::{mpsc, watch};
use tokio::task::AbortHandle;
use tracing::{debug, warn};

use crate::{
    ConnectionControl, HttpBody, HttpEngine, HttpError, InFlightRequestGuard, RequestContext,
    TlsConnectionInfo,
};

/// RAII guard that aborts the H3 request-body pump ONLY when the full stream handler finishes
/// (after the response body completes), preventing premature upload truncation (`R2-H3-1`).
struct AbortOnDrop(AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Streaming [`Body`] adapter fed asynchronously from an `h3` receive stream.
/// Surfaces an explicit [`HttpError::Body`] if the producer pump terminates unexpectedly before
/// marking clean EOF (`R2-H3-1`).
struct H3ChannelBody {
    rx: mpsc::Receiver<Result<Bytes, HttpError>>,
    eof_clean: Arc<AtomicBool>,
    errored: bool,
}

impl Body for H3ChannelBody {
    type Data = Bytes;
    type Error = HttpError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.rx.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                if !self.errored && !self.eof_clean.load(Ordering::Acquire) {
                    self.errored = true;
                    Poll::Ready(Some(Err(HttpError::Body(
                        "HTTP/3 request body pump aborted before stream EOF".to_owned(),
                    ))))
                } else {
                    Poll::Ready(None)
                }
            }
            Poll::Ready(Some(Ok(chunk))) => Poll::Ready(Some(Ok(Frame::data(chunk)))),
            Poll::Ready(Some(Err(err))) => {
                self.errored = true;
                Poll::Ready(Some(Err(err)))
            }
        }
    }
}

/// Serves all HTTP/3 streams on an accepted `quinn::Connection` until closed or gracefully drained.
pub async fn serve_h3_connection(
    quinn_conn: quinn::Connection,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    engine: Arc<HttpEngine>,
    shutdown: watch::Receiver<bool>,
) {
    serve_h3_connection_with_control(
        quinn_conn,
        peer_addr,
        local_addr,
        engine,
        shutdown,
        ConnectionControl::default(),
    )
    .await;
}

/// Serves all HTTP/3 streams like [`serve_h3_connection`], wiring per-connection idle eviction
/// (`ConnectionControl`) so idle QUIC connections can be gracefully evicted via HTTP/3 GOAWAY
/// when a client IP hits `max-connections-per-ip`.
#[allow(clippy::too_many_lines)]
pub async fn serve_h3_connection_with_control(
    quinn_conn: quinn::Connection,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    engine: Arc<HttpEngine>,
    mut shutdown: watch::Receiver<bool>,
    control: ConnectionControl,
) {
    let (limits, timeouts) = engine.limits_and_timeouts();
    let max_header_bytes = limits.max_header_bytes.as_bytes();
    let flood_guard = Arc::new(ConnectionFloodGuard::from_limits(&limits));
    let idle_state = control.idle_state;
    let mut evict_rx = control.evict_rx;
    let effective_local_addr = SocketAddr::new(
        quinn_conn
            .local_ip()
            .map_or_else(|| local_addr.ip().to_canonical(), |ip| ip.to_canonical()),
        local_addr.port(),
    );

    // Extract negotiated QUIC TLS SNI and optional verified mTLS peer certificate DN.
    let tls_sni: Option<Arc<str>> = quinn_conn
        .handshake_data()
        .and_then(|any| any.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|hs| hs.server_name)
        .map(Arc::<str>::from);
    let peer_cert_chain_der =
        miraserve_tls::extract_peer_cert_chain_der_any(quinn_conn.peer_identity());
    let verified_client_cert_dn: Option<Arc<str>> = peer_cert_chain_der
        .as_deref()
        .and_then(miraserve_tls::extract_verified_client_cert_dn_from_der)
        .map(Arc::<str>::from);

    let tls_info = TlsConnectionInfo {
        sni: tls_sni,
        is_tls13: true, // QUIC mandates TLS 1.3 (RFC 9001).
        is_pqc: engine.pqc_hybrid_enabled(),
        verified_client_cert_dn,
        peer_cert_chain_der,
    };

    // A handle to the same connection, to see per request whether the client has moved to
    // another address since the handshake (QUIC connection migration).
    let address_view = quinn_conn.clone();
    let h3_conn = crate::h3_quic::Connection::new(quinn_conn);
    let quic = h3_conn.shared();
    // Setup opens the control streams and writes SETTINGS: a peer that grants no credit for
    // them must not hold the connection (and its place among all connections) for ever.
    let mut builder = h3::server::builder();
    builder.max_field_section_size(max_header_bytes);
    let setup = tokio::time::timeout(timeouts.header_read, builder.build(h3_conn));
    let mut conn: h3::server::Connection<crate::h3_quic::Connection, Bytes> = match setup.await {
        Ok(Ok(c)) => c,
        Ok(Err(err)) => {
            debug!(peer = %peer_addr, error = %err, "HTTP/3 handshake failed");
            return;
        }
        Err(_) => {
            debug!(peer = %peer_addr, "HTTP/3 setup timed out");
            address_view.close(H3_NO_ERROR, b"setup timeout");
            return;
        }
    };
    // Without a request in flight the connection lives until this time: the first request has
    // to come within the header deadline, later ones within the keep-alive time. QUIC's own
    // idle timer does not do this, as any packet (a PING) restarts it.
    let mut idle_deadline = tokio::time::Instant::now() + timeouts.header_read;
    let activity = Arc::new(ConnActivity::default());
    // A request counts as in flight until the peer has acknowledged all of its answer (the
    // stream's end waits for that, see `h3_quic`): a connection without one is idle, and
    // nothing of an answer is lost when it is closed.

    let mut active_streams = tokio::task::JoinSet::new();
    let (flood_close_tx, mut flood_close_rx) = watch::channel(false);
    // GOAWAY is sent and the connection ends when its requests have (see the join arm).
    let mut replacing = false;

    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    // RLD-3: Send HTTP/3 GOAWAY and gracefully drain in-flight streams before returning!
                    send_goaway(&mut conn).await;
                    let _ = tokio::time::timeout(timeouts.graceful_drain, async {
                        while active_streams.join_next().await.is_some() {}
                    })
                    .await;
                    break;
                }
            }
            () = async {
                if let Some(rx) = evict_rx.as_mut() {
                    while !*rx.borrow() {
                        if rx.changed().await.is_err() {
                            std::future::pending::<()>().await;
                        }
                    }
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                debug!(peer = %peer_addr, "closing evicted oldest idle HTTP/3 connection via GOAWAY");
                send_goaway(&mut conn).await;
                let _ = tokio::time::timeout(
                    timeouts.graceful_drain.min(Duration::from_millis(500)),
                    async {
                        while active_streams.join_next().await.is_some() {}
                    },
                )
                .await;
                break;
            }
            changed = flood_close_rx.changed() => {
                if changed.is_ok() && *flood_close_rx.borrow() {
                    warn!(peer = %peer_addr, "closing HTTP/3 connection after stream reset flood (R2-H3-2)");
                    send_goaway(&mut conn).await;
                    break;
                }
            }
            Some(_) = active_streams.join_next(), if !active_streams.is_empty() => {
                // See `h3_quic::Shared`: stop accepting further requests on this
                // connection while letting in-flight requests finish.
                if !replacing && quic.stale_notifications() >= MAX_STALE_STOP_NOTIFICATIONS {
                    debug!(peer = %peer_addr, "replacing an HTTP/3 connection with many reset streams");
                    let _ = tokio::time::timeout(GOAWAY_WRITE_TIMEOUT, conn.shutdown(1)).await;
                    replacing = true;
                }
                if replacing && active_streams.is_empty() {
                    break;
                }
            }
            // Armed also while streams are open that have not sent their request yet: they do
            // not hold the deadline off.
            () = tokio::time::sleep_until(idle_deadline) => {
                let now = tokio::time::Instant::now();
                if activity.in_flight.load(Ordering::Acquire) > 0 {
                    idle_deadline = now + timeouts.idle_keepalive;
                    continue;
                }
                // Read after the count: a request that came and went in between is seen here.
                let finished = activity.last_finished_ms.load(Ordering::Acquire);
                if finished != 0 {
                    let idle_for =
                        Duration::from_millis(crate::monotonic_idle_ms().saturating_sub(finished));
                    if let Some(left) = timeouts.idle_keepalive.checked_sub(idle_for)
                        && !left.is_zero()
                    {
                        idle_deadline = now + left;
                        continue;
                    }
                }
                debug!(peer = %peer_addr, "closing HTTP/3 connection without a request in time");
                send_goaway(&mut conn).await;
                break;
            }
            // Not while the connection is being replaced: the GOAWAY has named the next
            // request as the first one not taken, so none is taken (a client may send it
            // again on a new connection).
            next = conn.accept(), if !replacing => {
                match next {
                    Ok(Some(resolver)) => {
                        let eng = Arc::clone(&engine);
                        let fg = Arc::clone(&flood_guard);
                        let tls_c = tls_info.clone();
                        let close_tx = flood_close_tx.clone();
                        let activity_c = Arc::clone(&activity);
                        let idle_guard = InFlightRequestGuard::enter(idle_state.clone());
                        let connection = address_view.clone();
                        let quic_c = Arc::clone(&quic);
                        active_streams.spawn(async move {
                            let _idle_guard = idle_guard;
                            handle_h3_stream(
                                resolver,
                                peer_addr,
                                connection,
                                quic_c,
                                effective_local_addr,
                                eng,
                                fg,
                                tls_c,
                                close_tx,
                                activity_c,
                            )
                            .await;
                        });
                    }
                    Ok(None) => break,
                    Err(err) => {
                        debug!(peer = %peer_addr, error = %err, "HTTP/3 connection closed");
                        break;
                    }
                }
            }
        }
    }
    // Whatever ended it, the QUIC connection ends here too (a GOAWAY the peer does not let
    // through, or streams it keeps open, do not keep it).
    address_view.close(H3_NO_ERROR, b"");
}

/// How many streams of one connection may be reset by the server while Quinn holds a stop
/// notification for them (kept until the connection closes) before the server
/// stops accepting further requests on that connection.
const MAX_STALE_STOP_NOTIFICATIONS: u32 = 512;

/// How long the peer's acknowledgement of an answer is waited for once its end is queued: a
/// full QUIC send window at the lowest accepted rate, with a quarter to spare. `None` without
/// a lowest rate: then only the transport decides (as in v0.1.0, which did not wait at all).
fn ack_wait(min_rate_bps: u64, write_idle: Duration) -> Option<Duration> {
    const SEND_WINDOW: u64 = 4 * 1024 * 1024;
    let secs = SEND_WINDOW.checked_div(min_rate_bps)?;
    Some(Duration::from_secs(secs.saturating_add(secs / 4).max(1)).max(write_idle))
}

/// Whether the peer has stopped the stream, asked before the server resets it for a reason of
/// its own (a cancellation the server did not get to see on a write still counts as one). An
/// empty DATA frame is tried once; it is not waited for. Only for a stream whose answer's
/// headers have been sent: a DATA frame before them would be a protocol error.
async fn stopped_by_peer<S>(send_stream: &mut h3::server::RequestStream<S, Bytes>) -> bool
where
    S: h3::quic::SendStream<Bytes>,
{
    let tried = tokio::time::timeout(Duration::ZERO, send_stream.send_data(Bytes::new())).await;
    matches!(
        tried,
        Ok(Err(h3::error::StreamError::RemoteTerminate { .. }))
    )
}

/// Streams of one connection that never sent a request, in all (h3 keeps a record of each
/// until the connection ends): beyond this the connection is closed.
const MAX_UNRESOLVED_STREAMS: u32 = 1_024;

/// What the streams of a connection tell its idle timer.
#[derive(Debug, Default)]
struct ConnActivity {
    /// Requests whose headers arrived and whose answer is not delivered yet.
    in_flight: AtomicUsize,
    /// When a request last ended (monotonic milliseconds; 0: none yet).
    last_finished_ms: AtomicU64,
    /// Streams that ended without a request.
    unresolved: AtomicU32,
}

impl ConnActivity {
    fn request_arrived(self: &Arc<Self>) -> InFlight {
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        InFlight(Arc::clone(self))
    }

    fn too_many_unresolved(&self) -> bool {
        self.unresolved.fetch_add(1, Ordering::AcqRel) >= MAX_UNRESOLVED_STREAMS
    }
}

/// A request being handled; counted until dropped.
struct InFlight(Arc<ConnActivity>);

impl Drop for InFlight {
    fn drop(&mut self) {
        // The time first: who sees no request in flight sees when the last one ended.
        self.0
            .last_finished_ms
            .store(crate::monotonic_idle_ms().max(1), Ordering::Release);
        self.0.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// `H3_NO_ERROR` (RFC 9114 section 8.1).
const H3_NO_ERROR: quinn::VarInt = quinn::VarInt::from_u32(0x100);

/// How long a GOAWAY may take to be written: it needs credit on the control stream, which a
/// peer can withhold.
const GOAWAY_WRITE_TIMEOUT: Duration = Duration::from_millis(250);

/// Sends GOAWAY, waiting only briefly for the peer to take it.
async fn send_goaway(conn: &mut h3::server::Connection<crate::h3_quic::Connection, Bytes>) {
    let _ = tokio::time::timeout(GOAWAY_WRITE_TIMEOUT, conn.shutdown(0)).await;
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn handle_h3_stream(
    resolver: h3::server::RequestResolver<crate::h3_quic::Connection, Bytes>,
    peer_addr: SocketAddr,
    connection: quinn::Connection,
    quic: Arc<crate::h3_quic::Shared>,
    local_addr: SocketAddr,
    engine: Arc<HttpEngine>,
    flood_guard: Arc<ConnectionFloodGuard>,
    tls_info: TlsConnectionInfo,
    flood_close_tx: watch::Sender<bool>,
    activity: Arc<ConnActivity>,
) {
    let (limits, timeouts) = engine.limits_and_timeouts();

    // Enforce header_read timeout on H3 request header resolution.
    let (head_req, stream) =
        match tokio::time::timeout(timeouts.header_read, resolver.resolve_request()).await {
            Ok(Ok(pair)) => pair,
            Ok(Err(err)) => {
                if !flood_guard.record_stream_reset() || activity.too_many_unresolved() {
                    let _ = flood_close_tx.send(true);
                }
                debug!(peer = %peer_addr, error = %err, "HTTP/3 request resolution failed");
                return;
            }
            Err(_) => {
                if !flood_guard.record_stream_reset() || activity.too_many_unresolved() {
                    let _ = flood_close_tx.send(true);
                }
                warn!(peer = %peer_addr, "closing slow HTTP/3 request: header read timed out");
                return;
            }
        };

    let _in_flight = activity.request_arrived();
    let (mut send_stream, mut recv_stream) = stream.split();
    let (mut parts, ()) = head_req.into_parts();
    parts.version = http::Version::HTTP_3;

    let declared_cl = parts
        .headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());
    let max_body_bytes = limits.max_body_bytes.as_bytes();

    // Stream incoming H3 DATA frames on demand through BoundedBody (Slowloris + size guarded)
    // AFTER framing/header/auth validation instead of pre-buffering up front!
    let (tx, rx) = mpsc::channel::<Result<Bytes, HttpError>>(4);
    let eof_clean = Arc::new(AtomicBool::new(false));
    let eof_clean_pump = Arc::clone(&eof_clean);
    let pump_task = tokio::spawn(async move {
        let mut received: u64 = 0;
        loop {
            match recv_stream.recv_data().await {
                Ok(Some(mut chunk)) => {
                    let chunk_len = chunk.remaining() as u64;
                    received = received.saturating_add(chunk_len);
                    if received > max_body_bytes {
                        let _ = tx
                            .send(Err(HttpError::PayloadTooLarge(max_body_bytes)))
                            .await;
                        return;
                    }
                    if let Some(expected) = declared_cl
                        && received > expected
                    {
                        let _ = tx
                            .send(Err(HttpError::Body(
                                "HTTP/3 request body exceeded declared Content-Length".to_owned(),
                            )))
                            .await;
                        return;
                    }
                    let mut out = Vec::with_capacity(usize::try_from(chunk_len).unwrap_or(0));
                    while chunk.has_remaining() {
                        let slice = chunk.chunk();
                        out.extend_from_slice(slice);
                        let n = slice.len();
                        chunk.advance(n);
                    }
                    if tx.send(Ok(Bytes::from(out))).await.is_err() {
                        // Handler rejected or closed stream early; stop reading immediately.
                        return;
                    }
                }
                Ok(None) => {
                    if let Some(expected) = declared_cl
                        && received != expected
                    {
                        let _ = tx
                            .send(Err(HttpError::Body(
                                "HTTP/3 request body truncated before declared Content-Length"
                                    .to_owned(),
                            )))
                            .await;
                    } else {
                        eof_clean_pump.store(true, Ordering::Release);
                    }
                    return;
                }
                Err(err) => {
                    let _ = tx
                        .send(Err(HttpError::Body(format!(
                            "HTTP/3 recv_data error: {err}"
                        ))))
                        .await;
                    return;
                }
            }
        }
    });
    // R2-H3-1: Keep the upload pump alive until the entire response stream finishes (so duplex
    // streaming uploads to reverse-proxy upstreams that send early response headers are NEVER
    // truncated when the response head arrives).
    let _pump_guard = AbortOnDrop(pump_task.abort_handle());

    let streaming_body: HttpBody = BoundedBody::new(
        H3ChannelBody {
            rx,
            eof_clean,
            errored: false,
        },
        &limits,
        &timeouts,
    )
    // R4-HTTP-3: Preserve structured HTTP/3 body errors (`PayloadTooLarge` -> 413) through BoundedBody!
    .with_error_mapper(|err| match err {
        HttpError::PayloadTooLarge(max_bytes) => BodyGuardError::PayloadTooLarge { max_bytes },
        HttpError::SlowBodyRate(min_rate_bps) => BodyGuardError::SlowBodyRate { min_rate_bps },
        other => BodyGuardError::Inner(other.to_string()),
    })
    .map_err(crate::map_body_guard_error)
    .boxed();

    let mut full_req = Request::from_parts(parts, streaming_body);
    // Every request is attributed to the address the handshake validated (as before this
    // release). If the connection has moved since (checked after the headers arrived), the
    // request is marked: a site that decides by visitor address answers 421 so the client sends
    // it again on a fresh connection; other sites serve it as before.
    let current = connection.remote_address();
    // Compared by address and port only (an IPv6 scope id may be dropped on one side).
    if current.ip().to_canonical() != peer_addr.ip().to_canonical()
        || current.port() != peer_addr.port()
    {
        full_req.extensions_mut().insert(crate::PeerMigrated);
    }
    let ctx = RequestContext {
        client_ip: Some(peer_addr.ip().to_canonical()),
        remote_port: Some(peer_addr.port()),
        server_addr: Some(local_addr.ip().to_canonical()),
        server_port: local_addr.port(),
        is_https: true,
        tls: Some(tls_info),
    };
    let resp = engine.handle_request(full_req, &ctx).await;
    // Framing rejections count against the connection, as on TCP.
    if resp
        .extensions()
        .get::<crate::ServerFramingRejection>()
        .is_some()
        && matches!(
            resp.status(),
            StatusCode::BAD_REQUEST | StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        )
        && !flood_guard.record_bad_request()
    {
        let _ = flood_close_tx.send(true);
    }

    let (mut resp_parts, mut resp_body) = resp.into_parts();
    // RFC 9114 §4.2: Strip HTTP/1.1 connection-specific headers from HTTP/3 responses.
    strip_h3_forbidden_response_headers(&mut resp_parts.headers);
    if resp_parts.status.is_informational() {
        resp_parts.status = StatusCode::BAD_GATEWAY;
    }

    let (_, h3_timeouts) = engine.limits_and_timeouts();
    let write_idle = h3_timeouts.response_write_idle;
    let min_send_rate_bps = h3_timeouts.min_response_rate_bps;

    let transport_outcome = resp_parts
        .extensions
        .get::<crate::TransportOutcome>()
        .cloned();
    if let Some(o) = &transport_outcome {
        o.mark_awaiting_finish();
    }
    let head_resp = http::Response::from_parts(resp_parts, ());
    match tokio::time::timeout(write_idle, send_stream.send_response(head_resp)).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            if let Some(o) = &transport_outcome {
                o.mark_failed();
            }
            // The peer ending the stream after its request was handled is a reset. Other
            // failures are our own (headers larger than the peer accepts) and must not close
            // the connection's other streams; but the peer may have stopped the stream while
            // the request was handled, which such a failure hides.
            let mut by_peer = matches!(err, h3::error::StreamError::RemoteTerminate { .. });
            if !by_peer {
                // Nothing has been written. A plain 500 takes the answer's place (a DATA
                // frame before any headers would be a protocol error for the whole
                // connection): the client gets a proper answer, and a stream it has
                // stopped shows on this write.
                let mut plain = http::Response::new(());
                *plain.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                let sent = tokio::time::timeout(write_idle, send_stream.send_response(plain)).await;
                match sent {
                    Ok(Ok(())) => {
                        // The end waits for the peer (see `h3_quic`): a stop shows here too.
                        let ended = tokio::time::timeout(write_idle, send_stream.finish()).await;
                        by_peer = matches!(
                            ended,
                            Ok(Err(h3::error::StreamError::RemoteTerminate { .. }))
                        );
                    }
                    Ok(Err(h3::error::StreamError::RemoteTerminate { .. })) => by_peer = true,
                    // Not even a bare status fits what the peer accepts: it has made every
                    // answer impossible, so this is its doing as well (and whether it had
                    // stopped the stream cannot be seen without writing to it).
                    Ok(Err(h3::error::StreamError::HeaderTooBig { .. })) => {
                        by_peer = true;
                        send_stream.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
                    }
                    _ => send_stream.stop_stream(h3::error::Code::H3_INTERNAL_ERROR),
                }
            }
            if by_peer && !flood_guard.record_stream_reset() {
                let _ = flood_close_tx.send(true);
            }
            debug!(peer = %peer_addr, error = %err, "HTTP/3 send_response failed");
            return;
        }
        Err(_) => {
            if let Some(o) = &transport_outcome {
                o.mark_failed();
            }
            warn!(peer = %peer_addr, reason = "h3_send_response_idle", "closing slow-reader HTTP/3 stream");
            send_stream.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
            return;
        }
    }

    let mut rate_window = crate::stream_rate::StreamRateBudget::new(min_send_rate_bps, write_idle);
    let piece = crate::h2_stall::piece_bytes(min_send_rate_bps, write_idle);

    while let Some(frame_res) = resp_body.frame().await {
        match frame_res {
            Ok(frame) => {
                let Ok(mut unsent) = frame.into_data() else {
                    continue;
                };
                // One `send_data` call is one unit of progress for the idle timeout and the
                // rate budget, so a unit must be small enough for a slow but acceptable client
                // to take within the deadline (see `h2_stall::piece_bytes`).
                while !unsent.is_empty() {
                    let data = unsent.split_to(unsent.len().min(piece));
                    let n = data.len() as u64;
                    let send_started = std::time::Instant::now();
                    match tokio::time::timeout(write_idle, send_stream.send_data(data)).await {
                        Ok(Ok(())) => {
                            if rate_window.record(n, send_started.elapsed()) {
                                if let Some(o) = &transport_outcome {
                                    o.mark_failed();
                                }
                                warn!(
                                    peer = %peer_addr,
                                    reason = "h3_min_response_rate_bps",
                                    min_send_rate_bps,
                                    "closing slow-reader HTTP/3 stream"
                                );
                                send_stream.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
                                return;
                            }
                        }
                        Ok(Err(err)) => {
                            if let Some(o) = &transport_outcome {
                                o.mark_failed();
                            }
                            if !flood_guard.record_stream_reset() {
                                let _ = flood_close_tx.send(true);
                            }
                            debug!(peer = %peer_addr, error = %err, "HTTP/3 send_data failed");
                            return;
                        }
                        Err(_) => {
                            if let Some(o) = &transport_outcome {
                                o.mark_failed();
                            }
                            warn!(peer = %peer_addr, reason = "h3_send_data_idle", "closing slow-reader HTTP/3 stream");
                            send_stream.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
                            return;
                        }
                    }
                }
            }
            Err(err) => {
                if let Some(o) = &transport_outcome {
                    o.mark_failed();
                }
                warn!(peer = %peer_addr, error = %err, "HTTP/3 response body stream error; resetting stream with H3_INTERNAL_ERROR");
                // The peer may have cancelled while the body was waited for.
                if stopped_by_peer(&mut send_stream).await && !flood_guard.record_stream_reset() {
                    let _ = flood_close_tx.send(true);
                }
                // R5-PRX-2: Explicitly reset the QUIC send stream with H3_INTERNAL_ERROR instead
                // of dropping it silently (which can emit a clean FIN and make truncated responses
                // look complete to HTTP/3 clients).
                send_stream.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
                return;
            }
        }
    }

    // The end of the stream: done when the peer has acknowledged all of the answer, failed
    // when the peer stopped the stream instead (see `h3_quic`). Until the end is queued a
    // write may still wait for credit (the library's own closing frame): that has the write
    // deadline. Afterwards everything has the peer's credit already and the transport
    // delivers it, also across a loss; it is only given up when it takes longer than the
    // slowest accepted client would need.
    let stream_id = send_stream.send_id().into_inner();
    let ack_wait = ack_wait(min_send_rate_bps, write_idle);
    let ended = {
        let finish = send_stream.finish();
        tokio::pin!(finish);
        let started = tokio::time::Instant::now();
        let mut queued_at = None;
        let step = write_idle.min(Duration::from_secs(1));
        loop {
            tokio::select! {
                result = &mut finish => break Some(result),
                () = tokio::time::sleep(step) => {
                    let now = tokio::time::Instant::now();
                    if quic.fin_queued(stream_id) {
                        let at = *queued_at.get_or_insert(now);
                        if ack_wait.is_some_and(|limit| now.duration_since(at) >= limit) {
                            break None;
                        }
                    } else if now.duration_since(started) >= write_idle {
                        break None;
                    }
                }
            }
        }
    };
    match ended {
        Some(Ok(())) => {
            if let Some(o) = &transport_outcome {
                o.mark_completed();
            }
        }
        Some(Err(err)) if matches!(err, h3::error::StreamError::RemoteTerminate { .. }) => {
            if let Some(o) = &transport_outcome {
                o.mark_failed();
            }
            if !flood_guard.record_stream_reset() {
                let _ = flood_close_tx.send(true);
            }
            debug!(peer = %peer_addr, error = %err, "HTTP/3 stream was stopped before its end");
        }
        Some(Err(err)) => {
            // The connection ended first. A peer that closed it itself after the whole
            // answer was sent has what it wanted.
            let closed_by_peer = matches!(
                connection.close_reason(),
                Some(quinn::ConnectionError::ApplicationClosed(_))
            );
            if let Some(o) = &transport_outcome {
                if closed_by_peer {
                    o.mark_completed();
                } else {
                    o.mark_failed();
                }
            }
            debug!(peer = %peer_addr, error = %err, "HTTP/3 connection ended before the stream");
        }
        None => {
            if let Some(o) = &transport_outcome {
                o.mark_failed();
            }
            warn!(peer = %peer_addr, reason = "h3_finish_idle", "closing slow-reader HTTP/3 stream on finish");
            send_stream.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
        }
    }
}

fn strip_h3_forbidden_response_headers(headers: &mut http::HeaderMap) {
    headers.remove(CONNECTION);
    headers.remove(TRANSFER_ENCODING);
    headers.remove(UPGRADE);
    headers.remove(HeaderName::from_static("keep-alive"));
    headers.remove(HeaderName::from_static("proxy-connection"));
}

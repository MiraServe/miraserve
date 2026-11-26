#![forbid(unsafe_code)]
//! Streaming reverse proxy pool with weighted load balancing, concurrent active HTTP health
//! checks, zero-buffer SSE streaming (`streaming-flush "immediate"`), RFC 6455 HTTP/1.1
//! WebSocket upgrade tunneling, and upstream HTTPS / mTLS via `rustls` + `aws-lc-rs`.

pub mod pool;

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::header::{
    ALT_SVC, AUTHORIZATION, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST, HeaderName,
    HeaderValue, ORIGIN, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, REFERER, SET_COOKIE, TE, TRAILER,
    TRANSFER_ENCODING, UPGRADE,
};
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri, Version};
use http_body::{Body, Frame};
use http_body_util::{BodyExt as _, Empty, Full, Limited, combinators::BoxBody};
use hyper::body::Incoming;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
#[cfg(any(test, feature = "test-h2-hooks"))]
use hyper_util::client::legacy::connect::HttpInfo;
use hyper_util::rt::{TokioExecutor, TokioIo};
use miraserve_config::{HealthCheckConfig, IpCidr, ReverseProxyConfig, StreamingFlushMode};
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::{AbortHandle, JoinSet};
use tokio::time::Sleep;
use tracing::{debug, info, warn};

pub use pool::{Backend, BackendPool, InFlightGuard};

/// Default TCP + TLS connect timeout to upstream backends (`R2-PRX-2`, `R3-PRX-1`).
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default timeout awaiting upstream response headers AFTER request body upload finishes
/// (does not bound long uploads or long-lived SSE response streams, `R2-PRX-2`).
const DEFAULT_UPSTREAM_RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);

/// Default maximum idle gap between upstream response body chunks before aborting (`DOS-7`).
const DEFAULT_UPSTREAM_BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum idle/wall-clock timeout for upgraded WebSocket tunnel tasks.
const UPGRADE_TUNNEL_TIMEOUT: Duration = Duration::from_secs(3600);

/// Maximum response body bytes drained on an active health-check probe.
const MAX_HEALTH_BODY_DRAIN_BYTES: usize = 64 * 1024;

thread_local! {
    /// Index (`0..N`) of the dedicated single-threaded worker event loop running on the current OS
    /// thread (`server { workers ... }`). Always `None` on shared-runtime threads, blocking-pool
    /// threads, and background tasks such as active health checks.
    static WORKER_LOOP_INDEX: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

/// Returns the dedicated worker event-loop index (`0..N`) for the current OS thread, or `None` on
/// shared-runtime threads, blocking-pool threads, and background tasks.
#[must_use]
pub fn current_worker_loop_index() -> Option<usize> {
    WORKER_LOOP_INDEX.with(std::cell::Cell::get)
}

/// Guard returned by [`enter_worker_loop_index`] that restores the previous thread-local
/// worker-loop index on drop (including during stack unwinding). Marked `!Send` and `!Sync`
/// because it restores state on the OS thread where it was created.
///
/// # Ordering
///
/// Nested guards created on the same OS thread **must be dropped in reverse (LIFO) order** (the
/// order guaranteed automatically by lexical scoping, early returns, and stack unwinding).
/// Dropping an outer guard explicitly before an inner guard restores the outer guard's previous
/// value first and then overwrites it with the inner guard's captured value when the inner guard
/// drops, leaving the thread-local index stale.
#[derive(Debug)]
pub struct WorkerLoopIndexGuard {
    prev: Option<usize>,
    _not_send: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl Drop for WorkerLoopIndexGuard {
    fn drop(&mut self) {
        WORKER_LOOP_INDEX.with(|slot| slot.set(self.prev));
    }
}

/// Associates the current OS thread with dedicated worker event loop `index` (`0..N`) until the
/// returned guard drops. Blocking-pool threads started by this thread's runtime do not inherit
/// this index.
///
/// If multiple guards are entered on the same thread, they **must be dropped in reverse (LIFO)
/// order**; see [`WorkerLoopIndexGuard`].
#[must_use]
pub fn enter_worker_loop_index(index: usize) -> WorkerLoopIndexGuard {
    let prev = WORKER_LOOP_INDEX.with(|slot| slot.replace(Some(index)));
    WorkerLoopIndexGuard {
        prev,
        _not_send: std::marker::PhantomData,
    }
}

/// Which hyper connection pool slot a [`ReverseProxy`] request or health probe used.
#[cfg(any(test, feature = "test-h2-hooks"))]
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyClientSlot {
    /// The shared request client (default runtime, health probes, out-of-range worker index).
    Shared,
    /// The shared HTTP/1.1 upgrade / `preserve-host` client.
    SharedUpgrade,
    /// Per-worker request client for worker index `0..N`.
    Worker(usize),
    /// Per-worker HTTP/1.1 upgrade / `preserve-host` client for worker index `0..N`.
    WorkerUpgrade(usize),
}

/// Observation recorded by the test-only proxy pool observer hook.
#[cfg(any(test, feature = "test-h2-hooks"))]
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyPoolEvent {
    /// Pool slot selected for this upstream request.
    pub slot: ProxyClientSlot,
    /// Thread-local worker loop index observed on the executing thread (`None` outside workers).
    pub worker_index: Option<usize>,
    /// Number of per-worker client pairs configured on the [`ReverseProxy`] (`0` in shared mode).
    pub worker_pool_count: usize,
    /// Local TCP socket address of the upstream connection reported by `hyper-util` (`HttpInfo`).
    pub local_addr: Option<SocketAddr>,
    /// `true` when emitted by an active health-check probe rather than a forwarded request.
    pub is_health_probe: bool,
    /// Request path sent to the upstream.
    pub path: String,
    /// OS thread identifier where the request future executed.
    pub thread_id: std::thread::ThreadId,
}

#[cfg(any(test, feature = "test-h2-hooks"))]
type ProxyPoolObserverFn = Arc<dyn Fn(ProxyPoolEvent) + Send + Sync>;

#[cfg(any(test, feature = "test-h2-hooks"))]
static TEST_PROXY_POOL_OBSERVER: std::sync::Mutex<Option<ProxyPoolObserverFn>> =
    std::sync::Mutex::new(None);

/// Guard returned by [`test_proxy_pool_observer_guard`] that restores the previous observer on
/// drop.
#[cfg(any(test, feature = "test-h2-hooks"))]
#[doc(hidden)]
pub struct TestProxyPoolObserverGuard {
    prev: Option<ProxyPoolObserverFn>,
}

#[cfg(any(test, feature = "test-h2-hooks"))]
impl std::fmt::Debug for TestProxyPoolObserverGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestProxyPoolObserverGuard").finish()
    }
}

#[cfg(any(test, feature = "test-h2-hooks"))]
impl Drop for TestProxyPoolObserverGuard {
    fn drop(&mut self) {
        let mut slot = TEST_PROXY_POOL_OBSERVER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *slot = self.prev.take();
    }
}

/// Installs a test-only callback invoked when an upstream proxy request or active health probe
/// receives a response, restoring the previous observer on drop.
#[cfg(any(test, feature = "test-h2-hooks"))]
#[doc(hidden)]
#[must_use]
pub fn test_proxy_pool_observer_guard(
    observer: impl Fn(ProxyPoolEvent) + Send + Sync + 'static,
) -> TestProxyPoolObserverGuard {
    let mut slot = TEST_PROXY_POOL_OBSERVER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let prev = slot.replace(Arc::new(observer));
    TestProxyPoolObserverGuard { prev }
}

#[cfg(any(test, feature = "test-h2-hooks"))]
fn emit_proxy_pool_event(event: ProxyPoolEvent) {
    let observer = TEST_PROXY_POOL_OBSERVER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    if let Some(cb) = observer {
        cb(event);
    }
}

/// Response extension marker attached by [`ReverseProxy`] when the upstream advertised a
/// digest trailer (`Trailer: Content-Digest`, `Repr-Digest`, or `Digest`) before hop-by-hop
/// header stripping so downstream compression preserves the upstream representation bytes
/// untouched (RFC 9530 §2 / Codex G6).
#[derive(Debug, Clone, Copy)]
pub struct UpstreamHasDigestTrailer;

/// Boxed streaming body type accepted and returned by [`ReverseProxy`].
pub type ProxyBody = BoxBody<Bytes, ProxyError>;

/// Concrete request body accepted by [`ReverseProxy::forward_concrete`] without intermediate
/// box-in-box wrapping on empty or bounded `hyper::body::Incoming` bodies.
pub enum ProxyRequestBody {
    /// Empty request body (`GET`, `HEAD`, or zero-length body).
    Empty,
    /// Single-buffer request body.
    Full(Option<Bytes>),
    /// Incoming `hyper` body already guarded by [`miraserve_security::BoundedBody`].
    BoundedIncoming(Box<miraserve_security::BoundedBody<Incoming>>),
    /// Arbitrary boxed streaming body ([`ProxyBody`]).
    Boxed(ProxyBody),
}

impl std::fmt::Debug for ProxyRequestBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("ProxyRequestBody::Empty"),
            Self::Full(b) => f
                .debug_tuple("ProxyRequestBody::Full")
                .field(&b.as_ref().map(Bytes::len))
                .finish(),
            Self::BoundedIncoming(_) => f.write_str("ProxyRequestBody::BoundedIncoming(..)"),
            Self::Boxed(_) => f.write_str("ProxyRequestBody::Boxed(..)"),
        }
    }
}

impl From<ProxyBody> for ProxyRequestBody {
    fn from(body: ProxyBody) -> Self {
        // Always retain the caller-supplied `ProxyBody` intact so its exact `size_hint()` (which
        // may be unknown rather than exact zero even when `is_end_stream()` is true) and its drop
        // lifetime match `536486f`.
        Self::Boxed(body)
    }
}

fn map_body_guard_err_to_proxy(err: miraserve_security::BodyGuardError) -> ProxyError {
    match err {
        miraserve_security::BodyGuardError::PayloadTooLarge { max_bytes } => {
            ProxyError::PayloadTooLarge(max_bytes)
        }
        miraserve_security::BodyGuardError::SlowBodyRate { min_rate_bps } => ProxyError::Body(
            format!("request body read rate fell below minimum {min_rate_bps} bytes/sec"),
        ),
        miraserve_security::BodyGuardError::Inner(msg) => {
            ProxyError::Body(format!("HTTP body error: {msg}"))
        }
    }
}

impl Body for ProxyRequestBody {
    type Data = Bytes;
    type Error = ProxyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            Self::Empty => Poll::Ready(None),
            Self::Full(opt) => match opt.take() {
                Some(bytes) if !bytes.is_empty() => Poll::Ready(Some(Ok(Frame::data(bytes)))),
                _ => Poll::Ready(None),
            },
            Self::BoundedIncoming(inner) => Pin::new(inner.as_mut())
                .poll_frame(cx)
                .map(|opt| opt.map(|res| res.map_err(map_body_guard_err_to_proxy))),
            Self::Boxed(inner) => Pin::new(inner).poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Empty => true,
            Self::Full(opt) => opt.as_ref().is_none_or(Bytes::is_empty),
            Self::BoundedIncoming(inner) => inner.is_end_stream(),
            Self::Boxed(inner) => inner.is_end_stream(),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match self {
            Self::Empty => http_body::SizeHint::with_exact(0),
            Self::Full(opt) => {
                http_body::SizeHint::with_exact(opt.as_ref().map_or(0, |b| b.len() as u64))
            }
            Self::BoundedIncoming(inner) => inner.size_hint(),
            Self::Boxed(inner) => inner.size_hint(),
        }
    }
}

enum ProxyResponseBodyInner {
    Empty,
    Full(Option<Bytes>),
    Incoming(GuardedIncoming),
}

/// Concrete streaming response body returned by [`ReverseProxy::forward_concrete`], avoiding
/// per-request heap boxing of upstream response streams and single-chunk error bodies.
pub struct ProxyResponseBody {
    inner: ProxyResponseBodyInner,
}

impl std::fmt::Debug for ProxyResponseBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.inner {
            ProxyResponseBodyInner::Empty => f.write_str("ProxyResponseBody::Empty"),
            ProxyResponseBodyInner::Full(b) => f
                .debug_tuple("ProxyResponseBody::Full")
                .field(&b.as_ref().map(Bytes::len))
                .finish(),
            ProxyResponseBodyInner::Incoming(_) => f.write_str("ProxyResponseBody::Incoming(..)"),
        }
    }
}

impl ProxyResponseBody {
    /// Creates an empty [`ProxyResponseBody`].
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            inner: ProxyResponseBodyInner::Empty,
        }
    }

    /// Creates a single-chunk [`ProxyResponseBody`].
    #[must_use]
    pub fn full(bytes: impl Into<Bytes>) -> Self {
        let bytes = bytes.into();
        if bytes.is_empty() {
            Self::empty()
        } else {
            Self {
                inner: ProxyResponseBodyInner::Full(Some(bytes)),
            }
        }
    }

    const fn from_guarded(guarded: GuardedIncoming) -> Self {
        Self {
            inner: ProxyResponseBodyInner::Incoming(guarded),
        }
    }

    /// Converts this concrete body into a boxed [`ProxyBody`].
    #[must_use]
    pub fn into_boxed(self) -> ProxyBody {
        match self.inner {
            ProxyResponseBodyInner::Empty | ProxyResponseBodyInner::Full(None) => empty_body(),
            ProxyResponseBodyInner::Full(Some(bytes)) => full_body(bytes),
            ProxyResponseBodyInner::Incoming(guarded) => guarded.boxed(),
        }
    }
}

impl Body for ProxyResponseBody {
    type Data = Bytes;
    type Error = ProxyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match &mut self.get_mut().inner {
            ProxyResponseBodyInner::Empty => Poll::Ready(None),
            ProxyResponseBodyInner::Full(opt) => match opt.take() {
                Some(bytes) if !bytes.is_empty() => Poll::Ready(Some(Ok(Frame::data(bytes)))),
                _ => Poll::Ready(None),
            },
            ProxyResponseBodyInner::Incoming(guarded) => Pin::new(guarded).poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.inner {
            ProxyResponseBodyInner::Empty => true,
            ProxyResponseBodyInner::Full(opt) => opt.as_ref().is_none_or(Bytes::is_empty),
            ProxyResponseBodyInner::Incoming(guarded) => guarded.is_end_stream(),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match &self.inner {
            ProxyResponseBodyInner::Empty => http_body::SizeHint::with_exact(0),
            ProxyResponseBodyInner::Full(opt) => {
                http_body::SizeHint::with_exact(opt.as_ref().map_or(0, |b| b.len() as u64))
            }
            ProxyResponseBodyInner::Incoming(guarded) => guarded.size_hint(),
        }
    }
}

/// Lifecycle hooks attached to an upgraded tunnel (such as a WebSocket) so server graceful
/// shutdown counts and drains upgraded connections up to `graceful_drain` instead of cutting
/// them immediately, and closes remaining tunnels cleanly once the drain timeout elapses.
#[derive(Clone, Default)]
pub struct UpgradeLifecycle {
    /// Opaque RAII connection lease (active-connection drain guard, global/per-IP slots,
    /// telemetry active counter) kept alive until the upgraded tunnel closes.
    pub connection_lease: Option<Arc<dyn std::any::Any + Send + Sync>>,
    /// Signaled `true` ONLY after `graceful_drain` elapses to force remaining upgraded
    /// tunnels closed cleanly.
    pub force_close: Option<watch::Receiver<bool>>,
}

impl std::fmt::Debug for UpgradeLifecycle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpgradeLifecycle")
            .field("has_connection_lease", &self.connection_lease.is_some())
            .field("has_force_close", &self.force_close.is_some())
            .finish()
    }
}

/// Errors produced during reverse-proxy initialization or request forwarding.
#[derive(Debug, Error)]
pub enum ProxyError {
    /// Upstream URL configuration or request URI is invalid.
    #[error("invalid upstream configuration: {0}")]
    InvalidUpstream(String),
    /// Upstream TLS / mTLS client configuration failed.
    #[error("upstream TLS error: {0}")]
    Tls(#[from] miraserve_tls::TlsError),
    /// No healthy upstreams are available in the pool (`503`).
    #[error("no healthy upstream backends available")]
    NoHealthyUpstreams,
    /// Upstream connection or protocol failure (`502`).
    #[error("upstream transport error: {0}")]
    Upstream(String),
    /// Request body exceeded configured `max-body-bytes` (`413`, `R3-HTTP-2`).
    #[error("request body exceeded maximum size of {0} bytes")]
    PayloadTooLarge(u64),
    /// Streaming body error while forwarding frames.
    #[error("body stream error: {0}")]
    Body(String),
}

/// Level-triggered upload progress snapshot shared between [`UploadTrackingBody`] and
/// [`ReverseProxy::forward_concrete`] via `tokio::sync::watch` (eliminating lost-wakeup races and
/// bounding stalled upstream TLS handshakes / write stalls, `R3-PRX-1`).
///
/// Carries `client_error_status` inline so client-side upload errors (`413` vs `408`) require no
/// separate `Arc<AtomicU16>` allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UploadState {
    done: bool,
    ever_polled: bool,
    client_waiting: bool,
    last_activity_ms: u64,
    client_error_status: u16,
}

/// Completed zero-byte upload snapshot for body-less requests (`GET`, `HEAD`, or `is_end_stream()`
/// bodies), identical to the initial [`UploadState`] produced by [`UploadTrackingBody::new`] when
/// `inner.is_end_stream()` is `true`.
const DONE_UPLOAD_STATE: UploadState = UploadState {
    done: true,
    ever_polled: true,
    client_waiting: false,
    last_activity_ms: 0,
    client_error_status: 0,
};

/// Default passive cooldown duration after an upstream connect failure in a multi-backend pool.
const DEFAULT_PASSIVE_CONNECT_COOLDOWN: Duration = Duration::from_secs(10);

/// Maximum total upstream attempts per request on connect failure (initial + up to 3 failovers).
const MAX_CONNECT_FAILOVER_ATTEMPTS: usize = 4;

type ReclaimSlot = Arc<std::sync::Mutex<Option<ProxyRequestBody>>>;

/// Tracks client request-body upload progress and structured client-side body errors (`413` vs
/// `408`) so response-header timeouts do not prematurely abort legitimate slow uploads (`R2-PRX-2`),
/// stalled upstream TLS handshakes / write stalls ARE bounded and counted toward passive health
/// (`R3-PRX-1`), client body failures never mark healthy upstreams unhealthy (`R2-PRX-1`), and an
/// untouched request body can be reclaimed on connect error to fail over safely to the next backend.
struct UploadTrackingBody {
    inner: Option<ProxyRequestBody>,
    reclaim_slot: ReclaimSlot,
    polled_any_frame: bool,
    started_at: Instant,
    state_tx: watch::Sender<UploadState>,
}

impl UploadTrackingBody {
    fn new(
        inner: ProxyRequestBody,
        started_at: Instant,
        reclaim_slot: ReclaimSlot,
    ) -> (Self, watch::Receiver<UploadState>) {
        let already_done = inner.is_end_stream();
        let init = UploadState {
            done: already_done,
            ever_polled: already_done,
            client_waiting: false,
            last_activity_ms: 0,
            client_error_status: 0,
        };
        let (state_tx, state_rx) = watch::channel(init);
        let body = Self {
            inner: Some(inner),
            reclaim_slot,
            polled_any_frame: false,
            started_at,
            state_tx,
        };
        (body, state_rx)
    }

    fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn update_state(&self, client_waiting: bool, last_activity_ms: u64) {
        self.state_tx.send_if_modified(|cur| {
            let next = UploadState {
                done: false,
                ever_polled: true,
                client_waiting,
                last_activity_ms,
                client_error_status: cur.client_error_status,
            };
            if *cur == next {
                false
            } else {
                *cur = next;
                true
            }
        });
    }

    fn mark_error_and_finish(&self, status_code: u16, now_ms: u64) {
        self.state_tx.send_if_modified(|cur| {
            cur.client_error_status = status_code;
            cur.done = true;
            cur.ever_polled = true;
            cur.client_waiting = false;
            cur.last_activity_ms = now_ms;
            true
        });
    }

    fn mark_finished(&self) {
        let now_ms = self.elapsed_ms();
        self.state_tx.send_if_modified(|cur| {
            if cur.done {
                false
            } else {
                cur.done = true;
                cur.ever_polled = true;
                cur.client_waiting = false;
                cur.last_activity_ms = now_ms;
                true
            }
        });
    }
}

impl Drop for UploadTrackingBody {
    fn drop(&mut self) {
        if !self.polled_any_frame
            && let Some(untouched) = self.inner.take()
            && let Ok(mut slot) = self.reclaim_slot.lock()
        {
            *slot = Some(untouched);
        }
        self.mark_finished();
    }
}

impl Body for UploadTrackingBody {
    type Data = Bytes;
    type Error = ProxyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let now_ms = self.elapsed_ms();
        self.polled_any_frame = true;
        let Some(inner) = self.inner.as_mut() else {
            self.mark_finished();
            return Poll::Ready(None);
        };
        match Pin::new(inner).poll_frame(cx) {
            Poll::Pending => {
                self.update_state(true, now_ms);
                Poll::Pending
            }
            Poll::Ready(None) => {
                self.mark_finished();
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(err))) => {
                let status_code = if matches!(err, ProxyError::PayloadTooLarge(_)) {
                    StatusCode::PAYLOAD_TOO_LARGE.as_u16()
                } else {
                    StatusCode::REQUEST_TIMEOUT.as_u16()
                };
                self.mark_error_and_finish(status_code, now_ms);
                Poll::Ready(Some(Err(err)))
            }
            Poll::Ready(Some(Ok(frame))) => {
                self.update_state(false, now_ms);
                Poll::Ready(Some(Ok(frame)))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.as_ref().is_none_or(Body::is_end_stream)
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner
            .as_ref()
            .map_or_else(http_body::SizeHint::default, Body::size_hint)
    }
}

/// Concrete body type sent over `hyper_util::client::legacy::Client`: exact-zero empty requests
/// (`GET`, `HEAD`, health probes, exact-zero `Incoming`) bypass [`UploadTrackingBody`],
/// `watch::channel`, `Arc<Mutex>`, and `BoxBody`.
enum UpstreamBody {
    Empty,
    Tracked(UploadTrackingBody),
}

impl Body for UpstreamBody {
    type Data = Bytes;
    type Error = ProxyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            Self::Empty => Poll::Ready(None),
            Self::Tracked(tracked) => Pin::new(tracked).poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Empty => true,
            Self::Tracked(tracked) => tracked.is_end_stream(),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match self {
            Self::Empty => http_body::SizeHint::with_exact(0),
            Self::Tracked(tracked) => tracked.size_hint(),
        }
    }
}

/// Streaming response body wrapper that retains an [`InFlightGuard`] AND enforces a per-chunk
/// idle timeout (`DOS-7`, `R2-PRX-2`) until the entire upstream response stream finishes or drops.
struct GuardedIncoming {
    inner: Incoming,
    body_idle_timeout: Duration,
    idle_sleep: Option<Pin<Box<Sleep>>>,
    _guard: InFlightGuard,
}

impl Body for GuardedIncoming {
    type Data = Bytes;
    type Error = ProxyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                self.idle_sleep = None;
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => {
                self.idle_sleep = None;
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(err))) => {
                self.idle_sleep = None;
                Poll::Ready(Some(Err(ProxyError::Body(err.to_string()))))
            }
            Poll::Pending => {
                let timeout = self.body_idle_timeout;
                if tokio::runtime::Handle::try_current().is_ok() {
                    let sleep = self
                        .idle_sleep
                        .get_or_insert_with(|| Box::pin(tokio::time::sleep(timeout)));
                    if sleep.as_mut().poll(cx).is_ready() {
                        self.idle_sleep = None;
                        return Poll::Ready(Some(Err(ProxyError::Body(
                            "upstream response body idle timeout elapsed".to_owned(),
                        ))));
                    }
                }
                Poll::Pending
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

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Bounds BOTH TCP connect AND upstream TLS handshake by `timeout` for every HTTP method
/// (including `GET`/`HEAD` requests with empty bodies, `R3-PRX-1` / `R2-PRX-2`) and tracks
/// active connect/handshake attempts per [`Backend`] so `R5-PRX-1` distinguishes connect
/// stalls from requests queued on an established connection under load.
#[derive(Debug, Clone)]
struct TimeoutConnector<C> {
    inner: C,
    timeout_ms: Arc<AtomicU64>,
    pool: Arc<BackendPool>,
}

impl<C> tower_service::Service<Uri> for TimeoutConnector<C>
where
    C: tower_service::Service<Uri> + Clone + Send + 'static,
    C::Response: Send + 'static,
    C::Error: Into<BoxError> + Send + 'static,
    C::Future: Send + 'static,
{
    type Response = C::Response;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let connect_guard = dst
            .authority()
            .and_then(|auth| self.pool.find_by_authority(auth.as_str()))
            .map(|backend| backend.begin_connect());
        let fut = self.inner.call(dst);
        let timeout = Duration::from_millis(self.timeout_ms.load(Ordering::Acquire));
        Box::pin(async move {
            let _connect_guard = connect_guard;
            match tokio::time::timeout(timeout, fut).await {
                Ok(Ok(stream)) => Ok(stream),
                Ok(Err(err)) => Err(err.into()),
                Err(_) => Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "upstream TCP/TLS connect handshake timed out",
                )) as BoxError),
            }
        })
    }
}

/// Bounds per-request TCP/TLS connect timeout strictly below `response_timeout` so genuine
/// connect timeouts always surface through `TimeoutConnector` (`err.is_connect() == true`)
/// before the outer `response_deadline` fires.
fn compute_effective_connect_timeout(
    connect_timeout: Duration,
    response_timeout: Duration,
) -> Duration {
    let margin = Duration::from_millis(20);
    let capped_response = if response_timeout > margin {
        response_timeout.saturating_sub(margin)
    } else {
        response_timeout
    };
    connect_timeout.min(capped_response)
}
/// Cancels the background health-check task cleanly when the last `Arc<ReverseProxy>` drops.
#[derive(Debug)]
struct HealthTaskGuard {
    abort: AbortHandle,
}

impl Drop for HealthTaskGuard {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

type ProxyClient = Client<TimeoutConnector<HttpsConnector<HttpConnector>>, UpstreamBody>;

fn build_request_client(connector: TimeoutConnector<HttpsConnector<HttpConnector>>) -> ProxyClient {
    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(60))
        .http2_initial_stream_window_size(Some(256 * 1024))
        .http2_initial_connection_window_size(Some(4 * 1024 * 1024))
        .build(connector)
}

fn build_upgrade_client(connector: TimeoutConnector<HttpsConnector<HttpConnector>>) -> ProxyClient {
    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(30))
        .build(connector)
}

fn build_worker_clients(
    worker_pools: usize,
    connector: &TimeoutConnector<HttpsConnector<HttpConnector>>,
    upgrade_connector: &TimeoutConnector<HttpsConnector<HttpConnector>>,
) -> Vec<WorkerClients> {
    (0..worker_pools)
        .map(|_| WorkerClients {
            client: build_request_client(connector.clone()),
            upgrade_client: build_upgrade_client(upgrade_connector.clone()),
        })
        .collect()
}

/// Dedicated per-worker request and HTTP/1.1 upgrade clients so each worker event loop keeps its
/// upstream connections and their hyper connection tasks on its own single-thread runtime.
#[derive(Debug)]
struct WorkerClients {
    client: ProxyClient,
    upgrade_client: ProxyClient,
}

/// Configured reverse proxy pool with optional concurrent active health checking.
#[derive(Debug)]
pub struct ReverseProxy {
    pool: Arc<BackendPool>,
    client: ProxyClient,
    upgrade_client: ProxyClient,
    /// Per-worker client pairs indexed by worker loop index (`0..N`); empty in shared-runtime mode
    /// (zero allocation, identical to v0.1.4's single shared pool).
    worker_clients: Vec<WorkerClients>,
    streaming_flush: StreamingFlushMode,
    /// Forward the client's `Host` instead of the upstream authority (`preserve-host`).
    preserve_host: bool,
    allow_upgrades: bool,
    connect_timeout: Duration,
    effective_connect_timeout_ms: Arc<AtomicU64>,
    upstream_timeout: Duration,
    body_idle_timeout: Duration,
    passive_unhealthy_threshold: Option<u32>,
    passive_connect_cooldown: Duration,
    trusted_proxies: Vec<IpCidr>,
    _health_task: Option<HealthTaskGuard>,
}

impl ReverseProxy {
    /// Builds a [`ReverseProxy`] from a validated [`ReverseProxyConfig`] with default upstream
    /// connect (`10s`), response-header (`60s`), and response-body idle (`60s`) timeouts.
    ///
    /// # Errors
    /// Returns [`ProxyError`] if upstream URLs or upstream TLS configuration fail to load.
    pub fn new(config: &ReverseProxyConfig) -> Result<Self, ProxyError> {
        Self::new_with_timeouts(
            config,
            UPSTREAM_CONNECT_TIMEOUT,
            DEFAULT_UPSTREAM_RESPONSE_TIMEOUT,
            DEFAULT_UPSTREAM_BODY_IDLE_TIMEOUT,
        )
    }

    /// Builds a [`ReverseProxy`] with explicit dedicated upstream connect, response-header, and
    /// response-body idle timeouts (`R2-PRX-2`, `DOS-7`, `R3-PRX-1`), using the single shared
    /// connection pool (no per-worker pools).
    ///
    /// # Errors
    /// Returns [`ProxyError`] if upstream URLs or upstream TLS configuration fail to load.
    pub fn new_with_timeouts(
        config: &ReverseProxyConfig,
        connect_timeout: Duration,
        response_timeout: Duration,
        body_idle_timeout: Duration,
    ) -> Result<Self, ProxyError> {
        Self::new_with_timeouts_and_workers(
            config,
            connect_timeout,
            response_timeout,
            body_idle_timeout,
            0,
        )
    }

    /// Builds a [`ReverseProxy`] with explicit dedicated upstream timeouts and `worker_pools`
    /// dedicated per-worker connection pools (`0` in default shared-runtime mode allocates no
    /// per-worker pools and behaves identically to [`Self::new_with_timeouts`]).
    ///
    /// When `worker_pools > 0`, each worker index `0..worker_pools` receives its own request
    /// client and HTTP/1.1 upgrade/`preserve-host` client built from the same connector, TLS
    /// config, shared [`BackendPool`], and shared effective connect timeout. Requests outside a
    /// worker loop (shared runtime, blocking pool, active health probes, or a worker index out of
    /// range after a reload that lowers `server.workers`) fall back to the shared client.
    ///
    /// # Errors
    /// Returns [`ProxyError`] if upstream URLs or upstream TLS configuration fail to load.
    pub fn new_with_timeouts_and_workers(
        config: &ReverseProxyConfig,
        connect_timeout: Duration,
        response_timeout: Duration,
        body_idle_timeout: Duration,
        worker_pools: usize,
    ) -> Result<Self, ProxyError> {
        let pool = Arc::new(BackendPool::new(&config.upstreams, config.lb_policy)?);
        let tls_cfg = miraserve_tls::build_upstream_client_config(config.upstream_tls.as_ref())?;

        let mut http_conn = HttpConnector::new();
        http_conn.enforce_http(false);
        http_conn.set_nodelay(true);
        http_conn.set_connect_timeout(Some(connect_timeout));

        let https_connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls_cfg.clone())
            .https_or_http()
            .enable_all_versions()
            .wrap_connector(http_conn.clone());

        let upgrade_https = HttpsConnectorBuilder::new()
            .with_tls_config(tls_cfg)
            .https_or_http()
            .enable_http1()
            .wrap_connector(http_conn);

        let effective_connect_timeout =
            compute_effective_connect_timeout(connect_timeout, response_timeout);
        let effective_connect_timeout_ms = Arc::new(AtomicU64::new(
            u64::try_from(effective_connect_timeout.as_millis()).unwrap_or(u64::MAX),
        ));
        let connector = TimeoutConnector {
            inner: https_connector,
            timeout_ms: Arc::clone(&effective_connect_timeout_ms),
            pool: Arc::clone(&pool),
        };
        let upgrade_connector = TimeoutConnector {
            inner: upgrade_https,
            timeout_ms: Arc::clone(&effective_connect_timeout_ms),
            pool: Arc::clone(&pool),
        };

        let worker_clients = build_worker_clients(worker_pools, &connector, &upgrade_connector);

        let client = build_request_client(connector);
        let upgrade_client = build_upgrade_client(upgrade_connector);

        let passive_unhealthy_threshold = config
            .health_check
            .as_ref()
            .map(|hc| hc.unhealthy_threshold.max(1));
        let passive_connect_cooldown = config
            .health_check
            .as_ref()
            .map_or(DEFAULT_PASSIVE_CONNECT_COOLDOWN, |hc| {
                hc.interval.min(DEFAULT_PASSIVE_CONNECT_COOLDOWN)
            });

        let health_task = config.health_check.as_ref().map(|hc| {
            // Probes always use the shared client (never a worker loop's pool) and travel the way
            // real requests do: `preserve-host` uses the HTTP/1.1-only shared client and the
            // configured probe host.
            let probe_client = if config.preserve_host {
                upgrade_client.clone()
            } else {
                client.clone()
            };
            #[cfg(any(test, feature = "test-h2-hooks"))]
            let probe_slot = if config.preserve_host {
                ProxyClientSlot::SharedUpgrade
            } else {
                ProxyClientSlot::Shared
            };
            let probe_host = if config.preserve_host {
                hc.host
                    .as_deref()
                    .and_then(|h| HeaderValue::from_str(h).ok())
            } else {
                None
            };
            spawn_health_checker(
                Arc::clone(&pool),
                probe_client,
                hc.clone(),
                probe_host,
                #[cfg(any(test, feature = "test-h2-hooks"))]
                probe_slot,
                #[cfg(any(test, feature = "test-h2-hooks"))]
                worker_clients.len(),
            )
        });

        Ok(Self {
            pool,
            client,
            upgrade_client,
            worker_clients,
            streaming_flush: config.streaming_flush,
            preserve_host: config.preserve_host,
            allow_upgrades: config.allow_upgrades,
            connect_timeout,
            effective_connect_timeout_ms,
            upstream_timeout: response_timeout,
            body_idle_timeout,
            passive_unhealthy_threshold,
            passive_connect_cooldown,
            trusted_proxies: Vec::new(),
            _health_task: health_task,
        })
    }

    /// Selects the hyper connection pool for this request (the dedicated per-worker pool when
    /// running on a worker loop within range, otherwise the shared pool). One shared
    /// implementation is compiled for both production and hook-enabled builds so tests exercise
    /// the exact production client-selection code.
    fn select_client(&self, use_upgrade: bool) -> (&ProxyClient, Option<usize>) {
        if !self.worker_clients.is_empty()
            && let Some(idx) = current_worker_loop_index()
            && let Some(worker) = self.worker_clients.get(idx)
        {
            let client = if use_upgrade {
                &worker.upgrade_client
            } else {
                &worker.client
            };
            return (client, Some(idx));
        }
        let client = if use_upgrade {
            &self.upgrade_client
        } else {
            &self.client
        };
        (client, None)
    }

    /// Enables or disables HTTP/1.1 WebSocket upgrade tunneling (e.g. disabled for MCP gateways).
    #[must_use]
    pub const fn with_upgrades_enabled(mut self, enabled: bool) -> Self {
        self.allow_upgrades = enabled;
        self
    }

    /// Overrides the upstream response-header timeout.
    #[must_use]
    pub fn with_upstream_timeout(mut self, timeout: Duration) -> Self {
        self.upstream_timeout = timeout;
        let effective_ms = u64::try_from(
            compute_effective_connect_timeout(self.connect_timeout, timeout).as_millis(),
        )
        .unwrap_or(u64::MAX);
        self.effective_connect_timeout_ms
            .store(effective_ms, Ordering::Release);
        self
    }

    /// Overrides the upstream response-body per-chunk idle timeout (`DOS-7`).
    #[must_use]
    pub const fn with_body_idle_timeout(mut self, timeout: Duration) -> Self {
        self.body_idle_timeout = timeout;
        self
    }

    /// Overrides the passive connect-failure cooldown applied to failed backends in multi-backend pools.
    #[must_use]
    pub const fn with_passive_connect_cooldown(mut self, cooldown: Duration) -> Self {
        self.passive_connect_cooldown = cooldown;
        self
    }

    /// Configures trusted upstream reverse-proxy peer IPs whose `X-Forwarded-For` chain may
    /// be preserved; all other peers have untrusted forwarding headers stripped and overwritten.
    #[must_use]
    pub fn with_trusted_proxies(mut self, trusted: Vec<IpAddr>) -> Self {
        self.trusted_proxies = trusted.into_iter().map(IpCidr::from_ip).collect();
        self
    }

    /// Configures trusted upstream reverse-proxy peer CIDRs whose `X-Forwarded-For` chain may
    /// be preserved (`R5-RL-1` / `R5-DOS-1`).
    #[must_use]
    pub fn with_trusted_proxy_cidrs(mut self, trusted: Vec<IpCidr>) -> Self {
        self.trusted_proxies = trusted;
        self
    }

    /// Exposes the underlying [`BackendPool`] for telemetry or testing.
    #[must_use]
    pub fn pool(&self) -> &Arc<BackendPool> {
        &self.pool
    }

    /// Forwards an incoming HTTP request to a healthy upstream, preserving zero-buffer
    /// streaming for SSE / LLM responses, RFC 6455 HTTP/1.1 WebSocket upgrade tunneling,
    /// passive cooldown ejection, and automatic failover on connect errors when no request
    /// body bytes have been sent to the failed backend.
    ///
    /// On the final upstream attempt, the request's header map is moved directly into the
    /// upstream HTTP/1.1 request and may be cleared by `hyper` once encoded on the wire, so any
    /// custom backing storage owned by a header value (such as `bytes::Bytes::from_owner`) can
    /// be dropped before the upstream response arrives. Likewise, when the selected upstream URL
    /// has no base path prefix, the upstream request shares the incoming URI's `PathAndQuery`
    /// storage (`Bytes` reference count) rather than copying it into a new string, so a custom
    /// URI backing owner may remain referenced briefly by `hyper`'s connection task until the
    /// upstream request head is dropped. In addition, `X-Forwarded-Host` is cloned from the
    /// incoming `Host` header value (with sensitivity cleared) rather than copied into fresh
    /// storage, so on any HTTP/2 upstream attempt (including non-final attempts) the HPACK
    /// encoder's dynamic table may index that value and retain its backing owner until eviction
    /// or connection teardown—potentially past both the response and request-extension
    /// destructors.
    pub async fn forward(
        &self,
        req: Request<ProxyBody>,
        client_ip: Option<IpAddr>,
        client_scheme: &str,
    ) -> Response<ProxyBody> {
        self.forward_with_upgrade_lifecycle(req, client_ip, client_scheme, None)
            .await
    }

    /// Forwards an incoming HTTP request like [`Self::forward`], attaching an optional
    /// [`UpgradeLifecycle`] to any upgraded WebSocket tunnel so graceful shutdown drains
    /// active WebSockets up to `graceful_drain` instead of cutting them immediately.
    ///
    /// On the final upstream attempt, the request's header map is moved directly into the
    /// upstream HTTP/1.1 request and may be cleared by `hyper` once encoded on the wire, so any
    /// custom backing storage owned by a header value (such as `bytes::Bytes::from_owner`) can
    /// be dropped before the upstream response arrives. Likewise, when the selected upstream URL
    /// has no base path prefix, the upstream request shares the incoming URI's `PathAndQuery`
    /// storage (`Bytes` reference count) rather than copying it into a new string, so a custom
    /// URI backing owner may remain referenced briefly by `hyper`'s connection task until the
    /// upstream request head is dropped. In addition, `X-Forwarded-Host` is cloned from the
    /// incoming `Host` header value (with sensitivity cleared) rather than copied into fresh
    /// storage, so on any HTTP/2 upstream attempt (including non-final attempts) the HPACK
    /// encoder's dynamic table may index that value and retain its backing owner until eviction
    /// or connection teardown—potentially past both the response and request-extension
    /// destructors.
    pub async fn forward_with_upgrade_lifecycle(
        &self,
        req: Request<ProxyBody>,
        client_ip: Option<IpAddr>,
        client_scheme: &str,
        upgrade_lifecycle: Option<UpgradeLifecycle>,
    ) -> Response<ProxyBody> {
        let concrete_req = req.map(ProxyRequestBody::from);
        self.forward_concrete(concrete_req, client_ip, client_scheme, upgrade_lifecycle)
            .await
            .map(ProxyResponseBody::into_boxed)
    }

    /// Forwards a request with a concrete [`ProxyRequestBody`] and returns a concrete
    /// [`ProxyResponseBody`], avoiding intermediate box-in-box allocations on empty requests,
    /// bounded `hyper::body::Incoming` uploads, and `GuardedIncoming` upstream responses.
    ///
    /// On the final upstream attempt, the request's header map is moved directly into the
    /// upstream HTTP/1.1 request and may be cleared by `hyper` once encoded on the wire, so any
    /// custom backing storage owned by a header value (such as `bytes::Bytes::from_owner`) can
    /// be dropped before the upstream response arrives. Likewise, when the selected upstream URL
    /// has no base path prefix, the upstream request shares the incoming URI's `PathAndQuery`
    /// storage (`Bytes` reference count) rather than copying it into a new string, so a custom
    /// URI backing owner may remain referenced briefly by `hyper`'s connection task until the
    /// upstream request head is dropped. In addition, `X-Forwarded-Host` is cloned from the
    /// incoming `Host` header value (with sensitivity cleared) rather than copied into fresh
    /// storage, so on any HTTP/2 upstream attempt (including non-final attempts) the HPACK
    /// encoder's dynamic table may index that value and retain its backing owner until eviction
    /// or connection teardown—potentially past both the response and request-extension
    /// destructors.
    pub async fn forward_concrete(
        &self,
        req: Request<ProxyRequestBody>,
        client_ip: Option<IpAddr>,
        client_scheme: &str,
        upgrade_lifecycle: Option<UpgradeLifecycle>,
    ) -> Response<ProxyResponseBody> {
        let (parts, initial_body) = req.into_parts();
        self.forward_parts(
            parts,
            initial_body,
            client_ip,
            client_scheme,
            upgrade_lifecycle,
        )
        .await
    }

    /// Forwards already-decomposed request parts and a concrete [`ProxyRequestBody`], avoiding
    /// intermediate `Request::map` round-trips when callers convert the body type directly.
    ///
    /// On the final upstream attempt, the request's header map is moved directly into the
    /// upstream HTTP/1.1 request and may be cleared by `hyper` once encoded on the wire, so any
    /// custom backing storage owned by a header value (such as `bytes::Bytes::from_owner`) can
    /// be dropped before the upstream response arrives. Likewise, when the selected upstream URL
    /// has no base path prefix, the upstream request shares the incoming URI's `PathAndQuery`
    /// storage (`Bytes` reference count) rather than copying it into a new string, so a custom
    /// URI backing owner may remain referenced briefly by `hyper`'s connection task until the
    /// upstream request head is dropped. In addition, `X-Forwarded-Host` is cloned from the
    /// incoming `Host` header value (with sensitivity cleared) rather than copied into fresh
    /// storage, so on any HTTP/2 upstream attempt (including non-final attempts) the HPACK
    /// encoder's dynamic table may index that value and retain its backing owner until eviction
    /// or connection teardown—potentially past both the response and request-extension
    /// destructors.
    #[allow(clippy::too_many_lines)]
    pub async fn forward_parts(
        &self,
        mut base_parts: http::request::Parts,
        initial_body: ProxyRequestBody,
        client_ip: Option<IpAddr>,
        client_scheme: &str,
        upgrade_lifecycle: Option<UpgradeLifecycle>,
    ) -> Response<ProxyResponseBody> {
        // Strictly permit RFC 6455 WebSocket upgrade ONLY on HTTP/1.1 GET requests when enabled.
        let is_upgrade = self.allow_upgrades && is_valid_websocket_upgrade(&base_parts);
        let client_upgrade = if is_upgrade {
            let mut tmp = Request::from_parts(base_parts, ());
            let on_upgrade = hyper::upgrade::on(&mut tmp);
            base_parts = tmp.into_parts().0;
            Some(on_upgrade)
        } else {
            None
        };

        // Declare `_held_extensions` and `base_parts` BEFORE `orig_uri` so `orig_uri` always drops
        // before downstream request extensions on every exit path (matching `536486f`, where
        // `base_parts` preceded `orig_uri` and `Parts::uri` drops before `Parts::extensions`).
        let mut _held_extensions = http::Extensions::new();
        let mut base_parts = Some(base_parts);
        let (original_host, orig_uri) = if let Some(parts) = base_parts.as_mut() {
            let host = extract_original_host(&parts.headers, &parts.uri);
            let uri = parts.uri.clone();
            // Reset HTTP version so hyper negotiates cleanly with the upstream transport.
            parts.version = Version::HTTP_11;
            strip_hop_by_hop_headers(&mut parts.headers, is_upgrade, false);
            (host, uri)
        } else {
            (None, Uri::default())
        };
        let is_trusted_peer =
            client_ip.is_some_and(|ip| self.trusted_proxies.iter().any(|cidr| cidr.contains(ip)));
        // By default the upstream sees its own authority as `Host` (like Nginx `$proxy_host`).
        // With `preserve-host` it sees the host the client asked for, which the router has
        // already matched against this site's configured hosts.
        let (xf_host_val, mut preserved_host) = if self.preserve_host {
            (original_host.clone(), original_host)
        } else {
            (original_host, None)
        };
        if let Some(parts) = base_parts.as_mut() {
            // Reserve once for forwarded headers, the attempt `Host` header (when absent, e.g.
            // HTTP/2 `:authority`), plus 1 headroom slot so `hyper_util`'s `headers.entry(HOST)`
            // does not trigger a final `try_reserve_one()` regrow when `keys_len() == capacity()`.
            let extra_slots = usize::from(!parts.headers.contains_key(HOST)) + 1;
            apply_forwarded_headers(
                &mut parts.headers,
                client_ip,
                client_scheme,
                xf_host_val,
                is_trusted_peer,
                &self.trusted_proxies,
                extra_slots,
            );
        }

        let body_is_empty = initial_body.is_end_stream();
        let multi_backend = self.pool.backends().len() > 1;
        let max_attempts = self
            .pool
            .backends()
            .len()
            .clamp(1, MAX_CONNECT_FAILOVER_ATTEMPTS);
        // Allocate the retry exclusion list lazily (never allocated on single-backend routes or
        // when the first attempt succeeds).
        let mut tried: Vec<Arc<Backend>> = Vec::new();
        let mut pending_body = Some(initial_body);
        let mut last_error_response: Option<Response<ProxyResponseBody>> = None;

        let (guard, mut upstream_resp) = loop {
            let Some(guard) = self.pool.select_excluding(&tried) else {
                if let Some(err_resp) = last_error_response {
                    return err_resp;
                }
                return plain_error_response_concrete(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "503 Service Unavailable: no healthy upstreams\n",
                );
            };

            let upstream_uri = match build_upstream_uri(guard.backend(), &orig_uri) {
                Ok(uri) => uri,
                Err(err) => {
                    warn!(error = %err, "rejected unsafe or invalid upstream URI");
                    return plain_error_response_concrete(
                        StatusCode::BAD_REQUEST,
                        "400 Bad Request\n",
                    );
                }
            };

            // Prepare the attempt head (including final-attempt `Host` insertion and non-final
            // header/method cloning) BEFORE recording `started_at` and constructing the tracked
            // body, matching `536486f` so a worker pause during head preparation is never charged
            // against the upstream pre-poll deadline allowance.
            let is_final_attempt = tried.len() + 1 >= max_attempts;
            let attempt_parts = if is_final_attempt {
                let Some(mut parts) = base_parts.take() else {
                    return last_error_response.unwrap_or_else(|| {
                        plain_error_response_concrete(StatusCode::BAD_GATEWAY, "502 Bad Gateway\n")
                    });
                };
                parts.uri = upstream_uri;
                parts.version = Version::HTTP_11;
                // Move downstream extensions out instead of clearing them early so caller leases
                // live until `forward_parts` returns while the upstream request starts with empty
                // extensions (matching `Request::builder()`).
                _held_extensions = std::mem::take(&mut parts.extensions);
                if let Some(host_val) = preserved_host.take() {
                    parts.headers.insert(HOST, host_val);
                } else if let Some(auth_val) = guard.backend().host_header.as_ref() {
                    parts.headers.insert(HOST, auth_val.clone());
                }
                parts
            } else {
                let Some(bp) = base_parts.as_ref() else {
                    return last_error_response.unwrap_or_else(|| {
                        plain_error_response_concrete(StatusCode::BAD_GATEWAY, "502 Bad Gateway\n")
                    });
                };
                let mut attempt_headers = bp.headers.clone();
                if let Some(host_val) = &preserved_host {
                    attempt_headers.insert(HOST, host_val.clone());
                } else if let Some(auth_val) = guard.backend().host_header.as_ref() {
                    attempt_headers.insert(HOST, auth_val.clone());
                }
                let (mut parts, ()) = Request::new(()).into_parts();
                parts.method = bp.method.clone();
                parts.uri = upstream_uri;
                parts.version = Version::HTTP_11;
                parts.headers = attempt_headers;
                parts
            };

            #[cfg(test)]
            run_head_prepare_hook(guard.backend().authority.as_str());

            let Some(attempt_body) = pending_body.take() else {
                return last_error_response.unwrap_or_else(|| {
                    plain_error_response_concrete(StatusCode::BAD_GATEWAY, "502 Bad Gateway\n")
                });
            };

            let (upstream_body, started_at, reclaim_slot, mut upload_state_rx) = match attempt_body
            {
                ProxyRequestBody::Empty | ProxyRequestBody::Full(None) => {
                    (UpstreamBody::Empty, None, None, None)
                }
                ProxyRequestBody::Full(Some(ref bytes)) if bytes.is_empty() => {
                    (UpstreamBody::Empty, None, None, None)
                }
                other => {
                    let started = Instant::now();
                    // Allocate `reclaim_slot` unconditionally on every tracked attempt (including
                    // the final one) so an untouched request body (including `BoundedIncoming`
                    // with an unread HTTP/2 stream) stays alive through passive-health accounting,
                    // matching `536486f` and `v0.1.4` exactly.
                    let slot: ReclaimSlot = Arc::new(std::sync::Mutex::new(None));
                    let (tracked_body, rx) =
                        UploadTrackingBody::new(other, started, Arc::clone(&slot));
                    (
                        UpstreamBody::Tracked(tracked_body),
                        Some(started),
                        Some(slot),
                        Some(rx),
                    )
                }
            };

            let upstream_req = Request::from_parts(attempt_parts, upstream_body);

            // R2-PRX-2 & R3-PRX-1: Level-triggered `watch` deadline (zero lost-wakeup race!).
            let connect_timeout = self.connect_timeout;
            let upstream_timeout = self.upstream_timeout;
            let backend_ref = guard.backend();
            let pre_poll_limit = upstream_timeout
                .min(connect_timeout)
                .saturating_add(Duration::from_millis(50));

            let use_upgrade_client = is_upgrade || self.preserve_host;
            #[cfg_attr(not(any(test, feature = "test-h2-hooks")), allow(unused_variables))]
            let (selected_client, selected_worker_idx) = self.select_client(use_upgrade_client);
            #[cfg(any(test, feature = "test-h2-hooks"))]
            let selected_slot = match (selected_worker_idx, use_upgrade_client) {
                (Some(idx), true) => ProxyClientSlot::WorkerUpgrade(idx),
                (Some(idx), false) => ProxyClientSlot::Worker(idx),
                (None, true) => ProxyClientSlot::SharedUpgrade,
                (None, false) => ProxyClientSlot::Shared,
            };

            let response_res = {
                let req_fut = selected_client.request(upstream_req);
                let response_deadline = async {
                    if let (Some(rx), Some(started)) = (upload_state_rx.as_mut(), started_at)
                        && let Some(timed_out) = wait_for_upload_completion(
                            rx,
                            started,
                            pre_poll_limit,
                            upstream_timeout,
                            backend_ref,
                        )
                        .await
                    {
                        #[cfg(test)]
                        run_timeout_after_snapshot_hook(backend_ref.authority.as_str(), rx);
                        return timed_out;
                    }
                    tokio::time::sleep(upstream_timeout).await;
                    (
                        backend_ref.connecting_in_flight() > 0,
                        upload_state_rx
                            .as_ref()
                            .map_or(DONE_UPLOAD_STATE, |rx| *rx.borrow()),
                    )
                };

                tokio::select! {
                    res = req_fut => Ok(res),
                    timeout_snap = response_deadline => Err(timeout_snap),
                }
            };

            match response_res {
                Ok(Ok(resp)) => {
                    #[cfg(any(test, feature = "test-h2-hooks"))]
                    emit_proxy_pool_event(ProxyPoolEvent {
                        slot: selected_slot,
                        worker_index: current_worker_loop_index(),
                        worker_pool_count: self.worker_clients.len(),
                        local_addr: resp
                            .extensions()
                            .get::<HttpInfo>()
                            .map(HttpInfo::local_addr),
                        is_health_probe: false,
                        path: orig_uri.path().to_owned(),
                        thread_id: std::thread::current().id(),
                    });
                    // R3-PRX-2: Reset ONLY passive failure count and cooldown on non-5xx responses
                    // so failing active `/health` probes are never masked by traffic returning 5xx.
                    if !resp.status().is_server_error() {
                        guard.backend().reset_passive_failures();
                    }
                    break (guard, resp);
                }
                Err((was_connecting, latest)) => {
                    if should_charge_timeout_passive_health(
                        was_connecting,
                        latest,
                        upload_state_rx.as_ref(),
                        || guard.backend().in_flight(),
                    ) && let Some(threshold) = self.passive_unhealthy_threshold
                    {
                        guard.backend().record_passive_health_failure(threshold);
                    }
                    warn!(
                        upstream = %guard.backend().base_url,
                        timeout_ms = self.upstream_timeout.as_millis(),
                        was_connecting,
                        "reverse-proxy upstream connect/upload/response-header timeout"
                    );
                    // G1: Never retry from the outer `response_deadline` timeout branch.
                    // `was_connecting` is a backend-wide counter, so another request connecting to
                    // the same backend must never cause an already-transmitted request (such as a
                    // bodyless POST awaiting an application response) to be replayed on a sibling
                    // backend. Genuine per-request connect timeouts surface from `TimeoutConnector`
                    // via `Ok(Err(err))` with `err.is_connect() == true` before any bytes are sent.
                    return plain_error_response_concrete(
                        StatusCode::GATEWAY_TIMEOUT,
                        "504 Gateway Timeout\n",
                    );
                }
                Ok(Err(err)) => {
                    let client_status = upload_state_rx
                        .as_ref()
                        .map_or(0, |rx| rx.borrow().client_error_status);
                    if client_status != 0 {
                        if client_status == StatusCode::PAYLOAD_TOO_LARGE.as_u16() {
                            debug!(
                                upstream = %guard.backend().base_url,
                                error = %err,
                                client_status,
                                "client request body exceeded max_body_bytes during reverse-proxy upload (backend remains healthy)"
                            );
                            return plain_error_response_concrete(
                                StatusCode::PAYLOAD_TOO_LARGE,
                                "413 Payload Too Large\n",
                            );
                        }
                        warn!(
                            upstream = %guard.backend().base_url,
                            client_ip = %client_ip.map_or_else(|| "-".to_owned(), |ip| ip.to_string()),
                            error = %err,
                            "closing slow client request body upload on reverse-proxy route (408)"
                        );
                        return plain_error_response_concrete(
                            StatusCode::REQUEST_TIMEOUT,
                            "408 Request Timeout\n",
                        );
                    }
                    let is_hyper_user_err = std::error::Error::source(&err)
                        .and_then(|src| src.downcast_ref::<hyper::Error>())
                        .is_some_and(hyper::Error::is_user);
                    let is_connect_err = err.is_connect();
                    if is_connect_err && multi_backend {
                        if !guard.backend().is_in_passive_cooldown() {
                            info!(
                                upstream = %guard.backend().base_url,
                                cooldown_ms = u64::try_from(self.passive_connect_cooldown.as_millis())
                                    .unwrap_or(u64::MAX),
                                "upstream connect failed; skipping it for the cooldown period"
                            );
                        }
                        guard
                            .backend()
                            .record_passive_cooldown(self.passive_connect_cooldown);
                    }
                    if (is_connect_err || !is_hyper_user_err)
                        && let Some(threshold) = self.passive_unhealthy_threshold
                    {
                        guard.backend().record_passive_health_failure(threshold);
                        #[cfg(test)]
                        run_passive_health_failure_hook(
                            guard.backend().authority.as_str(),
                            reclaim_slot
                                .as_ref()
                                .and_then(|slot| slot.lock().ok())
                                .is_some_and(|s| s.is_some()),
                        );
                    }
                    let err_resp = if is_connect_err && is_timeout_error(&err) {
                        plain_error_response_concrete(
                            StatusCode::GATEWAY_TIMEOUT,
                            "504 Gateway Timeout\n",
                        )
                    } else {
                        plain_error_response_concrete(StatusCode::BAD_GATEWAY, "502 Bad Gateway\n")
                    };
                    if is_connect_err && tried.len() + 1 < max_attempts {
                        let reclaimed = if body_is_empty {
                            Some(ProxyRequestBody::Empty)
                        } else {
                            reclaim_slot
                                .as_ref()
                                .and_then(|slot| slot.lock().ok())
                                .and_then(|mut s| s.take())
                        };
                        if let Some(body_for_retry) = reclaimed {
                            warn!(
                                upstream = %guard.backend().base_url,
                                error = %err,
                                attempt = tried.len() + 1,
                                "upstream connect failed; failing over to next healthy backend"
                            );
                            tried.push(guard.backend_arc());
                            pending_body = Some(body_for_retry);
                            last_error_response = Some(err_resp);
                            continue;
                        }
                    }
                    warn!(
                        upstream = %guard.backend().base_url,
                        error = %err,
                        "reverse-proxy upstream request failed"
                    );
                    return err_resp;
                }
            }
        };

        // Handle HTTP 101 Switching Protocols ONLY for validated HTTP/1.1 WebSocket upgrades.
        if is_upgrade
            && upstream_resp.status() == StatusCode::SWITCHING_PROTOCOLS
            && let Some(on_client_upgrade) = client_upgrade
        {
            let on_upstream_upgrade = hyper::upgrade::on(&mut upstream_resp);
            let upgrade_lease = upgrade_lifecycle
                .as_ref()
                .and_then(|u| u.connection_lease.clone());
            let mut force_close_rx = upgrade_lifecycle.and_then(|u| u.force_close);
            tokio::spawn(async move {
                let _hold_guard = guard;
                let _hold_connection_lease = upgrade_lease;
                let wait_force_close = async {
                    if let Some(rx) = force_close_rx.as_mut() {
                        while !*rx.borrow() {
                            if rx.changed().await.is_err() {
                                break;
                            }
                        }
                    } else {
                        std::future::pending::<()>().await;
                    }
                };
                tokio::pin!(wait_force_close);

                let upgrade_pair = tokio::select! {
                    biased;
                    () = &mut wait_force_close => {
                        debug!("closing upgraded WebSocket handshake after graceful drain timeout");
                        return;
                    }
                    res = tokio::time::timeout(Duration::from_secs(10), async {
                        tokio::try_join!(on_client_upgrade, on_upstream_upgrade)
                    }) => res,
                };

                match upgrade_pair {
                    Ok(Ok((downstream, upstream_io))) => {
                        let mut c_io = TokioIo::new(downstream);
                        let mut u_io = TokioIo::new(upstream_io);
                        tokio::select! {
                            biased;
                            () = &mut wait_force_close => {
                                debug!("closing active upgraded WebSocket tunnel after graceful drain timeout");
                            }
                            _ = tokio::time::timeout(
                                UPGRADE_TUNNEL_TIMEOUT,
                                tokio::io::copy_bidirectional(&mut c_io, &mut u_io),
                            ) => {}
                        }
                    }
                    Ok(Err(err)) => {
                        warn!(error = %err, "HTTP upgrade handshake failed");
                    }
                    Err(_) => {
                        warn!("HTTP upgrade handshake timed out");
                    }
                }
            });

            let (mut resp_parts, _) = upstream_resp.into_parts();
            strip_hop_by_hop_headers(&mut resp_parts.headers, true, true);
            return Response::from_parts(resp_parts, ProxyResponseBody::empty());
        }

        // Refuse forwarding unsolicited 101 Switching Protocols on non-upgrade requests.
        if upstream_resp.status() == StatusCode::SWITCHING_PROTOCOLS {
            warn!(
                upstream = %guard.backend().base_url,
                "upstream returned unsolicited 101 Switching Protocols"
            );
            return plain_error_response_concrete(StatusCode::BAD_GATEWAY, "502 Bad Gateway\n");
        }

        let (mut resp_parts, incoming) = upstream_resp.into_parts();
        let has_digest_trailer = resp_parts.headers.get_all(TRAILER).iter().any(|v| {
            v.to_str().is_ok_and(|s| {
                s.split(',').any(|tok| {
                    let t = tok.trim();
                    t.eq_ignore_ascii_case("content-digest")
                        || t.eq_ignore_ascii_case("repr-digest")
                        || t.eq_ignore_ascii_case("digest")
                })
            })
        });
        if has_digest_trailer {
            resp_parts.extensions.insert(UpstreamHasDigestTrailer);
        }
        strip_hop_by_hop_headers(&mut resp_parts.headers, false, true);

        if self.streaming_flush == StreamingFlushMode::Immediate {
            resp_parts.headers.insert(
                HeaderName::from_static("x-accel-buffering"),
                HeaderValue::from_static("no"),
            );
        }

        let guarded_body = ProxyResponseBody::from_guarded(GuardedIncoming {
            inner: incoming,
            body_idle_timeout: self.body_idle_timeout,
            idle_sleep: None,
            _guard: guard,
        });

        Response::from_parts(resp_parts, guarded_body)
    }
}

/// Decides whether a `response_deadline` timeout should charge passive backend health.
///
/// Uses the deadline `snapshot` (and `was_connecting`) to classify whether the request was queued
/// on or awaiting a slow response from an established connection, while reading the CURRENT
/// `client_error_status` from `upload_state_rx` at the decision point (matching `536486f`'s
/// post-select atomic read) so a client-side `413`/`408` published between the deadline snapshot
/// and the health decision never penalises a healthy backend.
fn should_charge_timeout_passive_health(
    was_connecting: bool,
    snapshot: UploadState,
    upload_state_rx: Option<&watch::Receiver<UploadState>>,
    in_flight: impl FnOnce() -> usize,
) -> bool {
    let queued_on_established_conn =
        !was_connecting && !snapshot.ever_polled && !snapshot.done && in_flight() > 1;
    let slow_response_on_established_conn = !was_connecting && snapshot.done;
    let current_client_error_status =
        upload_state_rx.map_or(0, |rx| rx.borrow().client_error_status);
    current_client_error_status == 0
        && !queued_on_established_conn
        && !slow_response_on_established_conn
}

#[cfg(test)]
type PassiveHealthFailureHookFn = Arc<dyn Fn(bool) + Send + Sync>;

#[cfg(test)]
static PASSIVE_HEALTH_FAILURE_HOOKS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, PassiveHealthFailureHookFn>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

#[cfg(test)]
fn run_passive_health_failure_hook(authority: &str, body_retained: bool) {
    let hook = PASSIVE_HEALTH_FAILURE_HOOKS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(authority)
        .cloned();
    if let Some(cb) = hook {
        cb(body_retained);
    }
}

#[cfg(test)]
type HeadPrepareHookFn = Arc<dyn Fn() + Send + Sync>;

#[cfg(test)]
static HEAD_PREPARE_HOOKS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, HeadPrepareHookFn>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

#[cfg(test)]
fn run_head_prepare_hook(authority: &str) {
    let hook = HEAD_PREPARE_HOOKS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(authority)
        .cloned();
    if let Some(cb) = hook {
        cb();
    }
}

#[cfg(test)]
type TimeoutAfterSnapshotHookFn = Arc<dyn Fn(&str, &watch::Receiver<UploadState>) + Send + Sync>;

#[cfg(test)]
static TIMEOUT_AFTER_SNAPSHOT_HOOK: std::sync::Mutex<Option<TimeoutAfterSnapshotHookFn>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
fn run_timeout_after_snapshot_hook(authority: &str, rx: &watch::Receiver<UploadState>) {
    let hook = TIMEOUT_AFTER_SNAPSHOT_HOOK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    if let Some(cb) = hook {
        cb(authority, rx);
    }
}

async fn wait_for_upload_completion(
    upload_state_rx: &mut watch::Receiver<UploadState>,
    started_at: Instant,
    pre_poll_limit: Duration,
    upstream_timeout: Duration,
    backend_ref: &Backend,
) -> Option<(bool, UploadState)> {
    loop {
        let st = *upload_state_rx.borrow_and_update();
        if st.done {
            return None;
        }
        if st.client_waiting {
            if upload_state_rx.changed().await.is_err() {
                return None;
            }
            continue;
        }
        let limit = if st.ever_polled {
            upstream_timeout
        } else {
            pre_poll_limit
        };
        let now_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        let since_activity = Duration::from_millis(now_ms.saturating_sub(st.last_activity_ms));
        let Some(remaining) = limit.checked_sub(since_activity) else {
            return Some((
                backend_ref.connecting_in_flight() > 0,
                *upload_state_rx.borrow(),
            ));
        };
        tokio::select! {
            () = tokio::time::sleep(remaining) => {
                let latest = *upload_state_rx.borrow();
                if !latest.done && !latest.client_waiting {
                    let check_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
                    if Duration::from_millis(check_ms.saturating_sub(latest.last_activity_ms)) >= limit {
                        return Some((backend_ref.connecting_in_flight() > 0, latest));
                    }
                }
            }
            changed = upload_state_rx.changed() => {
                if changed.is_err() {
                    return None;
                }
            }
        }
    }
}

fn is_timeout_error(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = cur {
        if let Some(io_err) = e.downcast_ref::<std::io::Error>()
            && io_err.kind() == std::io::ErrorKind::TimedOut
        {
            return true;
        }
        cur = e.source();
    }
    false
}

fn spawn_health_checker(
    pool: Arc<BackendPool>,
    client: ProxyClient,
    hc: HealthCheckConfig,
    probe_host: Option<HeaderValue>,
    #[cfg(any(test, feature = "test-h2-hooks"))] probe_slot: ProxyClientSlot,
    #[cfg(any(test, feature = "test-h2-hooks"))] worker_pool_count: usize,
) -> HealthTaskGuard {
    let probe_timeout = hc
        .timeout
        .unwrap_or_else(|| (hc.interval / 2).max(Duration::from_millis(250)));

    let handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(hc.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;
            // Probe all backends concurrently so one blackholed/stalled backend never
            // head-of-line blocks health detection or recovery for sibling backends.
            let mut probes = JoinSet::new();
            for backend in pool.backends().iter().cloned() {
                let client_c = client.clone();
                let path_c = hc.path.clone();
                let threshold = hc.unhealthy_threshold;
                let host_c = probe_host.clone();
                probes.spawn(async move {
                    let Ok(probe_uri) = build_health_uri(&backend, &path_c) else {
                        return;
                    };
                    let Ok(mut req) = Request::builder()
                        .method(Method::GET)
                        .uri(probe_uri)
                        .body(UpstreamBody::Empty)
                    else {
                        return;
                    };
                    if let Some(host) = host_c {
                        req.headers_mut().insert(HOST, host);
                    }

                    let probe_ok = match tokio::time::timeout(probe_timeout, async {
                        let resp = client_c.request(req).await.ok()?;
                        #[cfg(any(test, feature = "test-h2-hooks"))]
                        emit_proxy_pool_event(ProxyPoolEvent {
                            slot: probe_slot,
                            worker_index: current_worker_loop_index(),
                            worker_pool_count,
                            local_addr: resp
                                .extensions()
                                .get::<HttpInfo>()
                                .map(HttpInfo::local_addr),
                            is_health_probe: true,
                            path: path_c.clone(),
                            thread_id: std::thread::current().id(),
                        });
                        let code = resp.status();
                        // Bounded body drain prevents OOM and still enables keep-alive reuse.
                        let _ = Limited::new(resp.into_body(), MAX_HEALTH_BODY_DRAIN_BYTES)
                            .collect()
                            .await;
                        Some(code.is_success() || code.is_redirection())
                    })
                    .await
                    {
                        Ok(Some(ok)) => ok,
                        _ => false,
                    };

                    let was_healthy = backend.is_healthy();
                    if probe_ok {
                        if !was_healthy {
                            info!(upstream = %backend.base_url, "upstream recovered; health check passed");
                        }
                        backend.record_health_success();
                    } else if backend.record_health_failure(threshold) && was_healthy {
                        // Logged on the state change only, not on every failed probe after it.
                        warn!(
                            upstream = %backend.base_url,
                            threshold,
                            "upstream marked unhealthy after failed health checks"
                        );
                    }
                });
            }

            while probes.join_next().await.is_some() {}
        }
    });

    HealthTaskGuard {
        abort: handle.abort_handle(),
    }
}

fn build_upstream_uri(backend: &Backend, req_uri: &Uri) -> Result<Uri, ProxyError> {
    let raw_path = req_uri.path();
    validate_safe_proxy_path(raw_path)?;

    let base_prefix = backend.base_url.path().trim_end_matches('/');
    let builder = Uri::builder()
        .scheme(backend.scheme.clone())
        .authority(backend.authority.clone());
    let uri_res = if base_prefix.is_empty() {
        // Clone the `Bytes`-backed `PathAndQuery` directly instead of formatting and re-parsing a
        // `String`.
        let pq = req_uri
            .path_and_query()
            .cloned()
            .unwrap_or_else(|| http::uri::PathAndQuery::from_static("/"));
        builder.path_and_query(pq).build()
    } else {
        let path_and_query = req_uri
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str);
        let mut combined = String::with_capacity(base_prefix.len() + path_and_query.len());
        combined.push_str(base_prefix);
        combined.push_str(path_and_query);
        builder.path_and_query(combined).build()
    };
    uri_res.map_err(|err| ProxyError::InvalidUpstream(err.to_string()))
}

fn validate_safe_proxy_path(raw_path: &str) -> Result<(), ProxyError> {
    if raw_path.contains('\\') || raw_path.contains('\0') {
        return Err(ProxyError::InvalidUpstream(
            "proxy request path contains forbidden backslash or NUL byte".to_owned(),
        ));
    }
    if raw_path
        .as_bytes()
        .split(|&b| b == b'/')
        .any(miraserve_security::is_dot_segment_bytes)
    {
        return Err(ProxyError::InvalidUpstream(
            "proxy request path contains dot-segment traversal".to_owned(),
        ));
    }
    // Fast path: without `%`, percent-decoding cannot produce any new bytes, and `raw_path: &str`
    // is already valid UTF-8 (so overlong UTF-8 and UTF-16 surrogates are impossible).
    if !raw_path.as_bytes().contains(&b'%') {
        return Ok(());
    }
    // Reject encoded backslashes, NULs, IIS `%uXXXX` Unicode escapes (`R4-PRX-1`), invalid /
    // overlong UTF-8 percent sequences (`%c0%ae`, `0xF5..=0xFF`, `R4-PRX-1`, `R6-HTTP-2`),
    // decoded dot segments including `;params` (`..;`, `R7-HTTP-2`), and double-encoded traversal
    // (`%252e%252e`, `%252e.`, `%255c`, `%2500`, `R7-HTTP-2`) while preserving legitimate encoded
    // slashes `%2F` within a segment for GitLab/npm/REST APIs (`R2-HTTP-3`).
    let decoded = percent_decode_proxy_once(raw_path.as_bytes())?;
    if miraserve_security::contains_overlong_or_surrogate_utf8(&decoded) {
        return Err(ProxyError::InvalidUpstream(
            "proxy request path contains forbidden overlong UTF-8 or UTF-16 surrogate sequence"
                .to_owned(),
        ));
    }
    if decoded
        .split(|&b| b == b'/')
        .any(miraserve_security::is_dot_segment_bytes)
    {
        return Err(ProxyError::InvalidUpstream(
            "decoded proxy request path contains dot-segment traversal".to_owned(),
        ));
    }
    // R7-HTTP-2: Run a second decode pass to block double-encoded traversal (`%252e%252e`,
    // `%252e.`, `%252e%252e%253b`, `%255c`, `%2500`, `%252f..`) before forwarding upstream.
    if decoded.contains(&b'%') {
        let decoded2 = percent_decode_proxy_once(&decoded)?;
        if miraserve_security::contains_overlong_or_surrogate_utf8(&decoded2) {
            return Err(ProxyError::InvalidUpstream(
                "double-decoded proxy request path contains forbidden overlong UTF-8 or surrogate sequence"
                    .to_owned(),
            ));
        }
        if decoded2.contains(&0x00)
            || decoded2.contains(&b'\\')
            || decoded2
                .split(|&b| b == b'/')
                .any(miraserve_security::is_dot_segment_bytes)
        {
            return Err(ProxyError::InvalidUpstream(
                "double-encoded proxy request path contains forbidden traversal (R7-HTTP-2)"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

fn percent_decode_proxy_once(bytes: &[u8]) -> Result<Vec<u8>, ProxyError> {
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0_usize;
    while let Some(&b) = bytes.get(i) {
        if b == b'%' {
            if matches!(bytes.get(i.saturating_add(1)), Some(b'u' | b'U'))
                && bytes
                    .get(i.saturating_add(2)..i.saturating_add(6))
                    .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
            {
                return Err(ProxyError::InvalidUpstream(
                    "proxy request path contains forbidden IIS %uXXXX Unicode escape".to_owned(),
                ));
            }
            if let (Some(&h1), Some(&h2)) = (
                bytes.get(i.saturating_add(1)),
                bytes.get(i.saturating_add(2)),
            ) && let (Some(n1), Some(n2)) = (hex_nibble(h1), hex_nibble(h2))
            {
                let ch = (n1 << 4) | n2;
                if matches!(ch, 0x00 | b'\\') {
                    return Err(ProxyError::InvalidUpstream(
                        "proxy request path contains encoded backslash or NUL".to_owned(),
                    ));
                }
                decoded.push(ch);
                i = i.saturating_add(3);
                continue;
            }
        }
        decoded.push(b);
        i = i.saturating_add(1);
    }
    Ok(decoded)
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn build_health_uri(backend: &Backend, health_path: &str) -> Result<Uri, http::Error> {
    Uri::builder()
        .scheme(backend.scheme.clone())
        .authority(backend.authority.clone())
        .path_and_query(health_path)
        .build()
}

/// Validates a strict RFC 6455 HTTP/1.1 WebSocket upgrade request (rejecting `h2c`,
/// arbitrary custom upgrade protocols, and non-HTTP/1.1 requests).
fn is_valid_websocket_upgrade(parts: &http::request::Parts) -> bool {
    if parts.version != Version::HTTP_11 || parts.method != Method::GET {
        return false;
    }
    let headers = &parts.headers;
    let has_conn_upgrade = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| {
            v.split(',')
                .any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"))
        });
    if !has_conn_upgrade {
        return false;
    }

    let mut upgrade_vals = headers.get_all(UPGRADE).iter();
    let Some(first_upgrade) = upgrade_vals.next() else {
        return false;
    };
    if upgrade_vals.next().is_some() {
        return false;
    }
    let Ok(upgrade_str) = first_upgrade.to_str() else {
        return false;
    };
    if !upgrade_str.trim().eq_ignore_ascii_case("websocket") {
        return false;
    }

    let has_ws_key = headers
        .get("sec-websocket-key")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| !v.trim().is_empty());
    let has_ws_version = headers
        .get("sec-websocket-version")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim() == "13");

    has_ws_key && has_ws_version
}

/// Returns `true` for security-critical end-to-end headers that an untrusted `Connection`
/// header MUST NEVER be allowed to strip in transit.
fn is_protected_end_to_end_header(name: &HeaderName) -> bool {
    if matches!(
        *name,
        HOST | AUTHORIZATION
            | COOKIE
            | SET_COOKIE
            | CONTENT_LENGTH
            | CONTENT_TYPE
            | ORIGIN
            | REFERER
    ) {
        return true;
    }
    let s = name.as_str();
    s.starts_with("x-forwarded-")
        || matches!(
            s,
            "x-real-ip"
                | "forwarded"
                | "signature"
                | "signature-input"
                | "signature-agent"
                | "mcp-session-id"
                | "strict-transport-security"
                | "content-security-policy"
                | "x-frame-options"
                | "x-content-type-options"
                | "referrer-policy"
                | "permissions-policy"
                | "cache-control"
                | "sec-websocket-key"
                | "sec-websocket-version"
                | "sec-websocket-accept"
                | "sec-websocket-protocol"
                | "sec-websocket-extensions"
        )
}

/// Removes RFC 9110 §7.6.1 hop-by-hop headers without allowing untrusted `Connection`
/// headers to strip protected end-to-end/forwarding/auth/security headers.
fn strip_hop_by_hop_headers(headers: &mut HeaderMap, preserve_upgrade: bool, is_response: bool) {
    let mut dynamic_hop_headers: Vec<HeaderName> = Vec::new();
    for val in headers.get_all(CONNECTION) {
        if let Ok(raw) = val.to_str() {
            for token in raw.split(',') {
                let name = token.trim();
                if name.is_empty() || (preserve_upgrade && name.eq_ignore_ascii_case("upgrade")) {
                    continue;
                }
                // `HeaderMap::contains_key(&str)` validates and probes on the stack without
                // allocating a `HeaderName`. Removing an absent key is a pure no-op on
                // `HeaderMap`, so skipping absent tokens preserves the exact `swap_remove`
                // removal sequence (and surviving iteration order) for every present key.
                if !headers.contains_key(name) {
                    continue;
                }
                if let Ok(header_name) = HeaderName::from_bytes(name.as_bytes())
                    && !is_protected_end_to_end_header(&header_name)
                {
                    dynamic_hop_headers.push(header_name);
                }
            }
        }
    }

    for name in dynamic_hop_headers {
        headers.remove(&name);
    }

    // PRX-1: Preserve `TE: trailers` (required by gRPC over HTTP/2) while stripping any other TE tokens.
    let preserve_te_trailers = !is_response
        && headers
            .get_all(TE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .any(|v| {
                v.split(',')
                    .any(|tok| tok.trim().eq_ignore_ascii_case("trailers"))
            });

    let static_hop_headers = [
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-connection"),
        HeaderName::from_static("http2-settings"),
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
    ];
    for name in static_hop_headers {
        headers.remove(&name);
    }

    if preserve_te_trailers {
        headers.insert(TE, HeaderValue::from_static("trailers"));
    }

    if is_response {
        // Never let an upstream spoof MiraServe's authoritative HTTP/3 Alt-Svc advertisement.
        headers.remove(ALT_SVC);
    }

    if preserve_upgrade {
        headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
    } else {
        headers.remove(CONNECTION);
        headers.remove(UPGRADE);
    }
}

/// Parses a single comma-delimited `X-Forwarded-For` token byte-wise (`R6-XFF-1`).
///
/// Accepts canonical IPv4/IPv6 literals, optional double quotes, bracketed IPv6 (`[2001:db8::1]`),
/// and `ip:port` / `[v6]:port` forms emitted by common reverse proxies. Non-UTF-8 bytes, `unknown`,
/// or malformed tokens return `None` strictly at their own position so a corrupt token earlier in
/// the chain never invalidates valid proxy-appended client IPs to its right.
#[must_use]
fn parse_xff_token(raw: &[u8]) -> Option<IpAddr> {
    let trimmed = trim_ascii_ows(raw);
    if trimmed.is_empty() {
        return None;
    }
    let text = std::str::from_utf8(trimmed).ok()?;
    // At most one balanced pair of quotes around the whole token; any other quote makes the
    // token malformed (it never names an established hop).
    let unquoted = match text.strip_prefix('"') {
        // Exactly the address inside the quotes: no whitespace of any kind.
        Some(inner) => inner.strip_suffix('"')?,
        None => text,
    };
    // A zone ID (`fe80::1%eth0`, numeric or named, also inside `[..]:port`) names a local
    // interface, not a client address: such a hop is malformed.
    if unquoted.is_empty() || unquoted.contains('"') || unquoted.contains('%') {
        return None;
    }
    if let Ok(ip) = IpAddr::from_str(unquoted) {
        return Some(ip.to_canonical());
    }
    if let Ok(sock) = SocketAddr::from_str(unquoted)
        && !matches!(sock, SocketAddr::V6(v6) if v6.scope_id() != 0)
    {
        return Some(sock.ip().to_canonical());
    }
    // Brackets are IPv6 syntax only: `[192.0.2.1]` is malformed, not an IPv4 address.
    if let Some(inner) = unquoted.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
        && let Ok(ip) = std::net::Ipv6Addr::from_str(inner)
    {
        return Some(IpAddr::V6(ip).to_canonical());
    }
    None
}

fn trim_ascii_ows(mut bytes: &[u8]) -> &[u8] {
    while let Some((&first, rest)) = bytes.split_first() {
        if first == b' ' || first == b'\t' {
            bytes = rest;
        } else {
            break;
        }
    }
    while let Some((&last, rest)) = bytes.split_last() {
        if last == b' ' || last == b'\t' {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

/// Derives the effective client IP from `X-Forwarded-For` using byte-wise right-to-left peeling of
/// `server.limits.trusted-proxies` (`R5-RL-1`, `R6-XFF-1`).
///
/// - Untrusted peers ALWAYS keep their canonical socket IP.
/// - Every `X-Forwarded-For` header line is split byte-wise on `,` so non-UTF-8 bytes earlier in a
///   merged header (e.g. `\xff, 203.0.113.5`) never discard valid hops to the right.
/// - Peeling stops immediately at the first malformed/`unknown`/non-UTF-8 token at its own
///   position, returning the last valid hop to its right (or `peer` if none).
#[must_use]
pub fn resolve_effective_client_ip(
    peer_ip: Option<IpAddr>,
    headers: &HeaderMap,
    trusted_proxies: &[IpCidr],
) -> Option<IpAddr> {
    let peer = peer_ip?.to_canonical();
    if trusted_proxies.is_empty() || !trusted_proxies.iter().any(|cidr| cidr.contains(peer)) {
        return Some(peer);
    }
    let mut tokens: Vec<&[u8]> = Vec::new();
    for val in headers.get_all("x-forwarded-for") {
        for part in val.as_bytes().split(|&b| b == b',') {
            let trimmed = trim_ascii_ows(part);
            if !trimmed.is_empty() {
                tokens.push(trimmed);
            }
        }
    }
    if tokens.is_empty() {
        return Some(peer);
    }
    let mut last_valid: Option<IpAddr> = None;
    for tok in tokens.into_iter().rev() {
        let Some(ip) = parse_xff_token(tok) else {
            // Stop peeling on malformed/`unknown`/non-UTF-8 token strictly at its own position so
            // attacker-controlled prefixes to its left can never be trusted.
            // R7-XFF-1: Log loudly (rate-limited) when a trusted proxy sends an unparseable
            // rightmost token (`unknown`, `_hidden`, zone-id, octal IP) because every client behind
            // that proxy collapses into the proxy's own rate-limit bucket!
            if last_valid.is_none() {
                warn_unparseable_trusted_xff(peer, tok);
            }
            return Some(last_valid.unwrap_or(peer));
        };
        last_valid = Some(ip);
        if !trusted_proxies.iter().any(|cidr| cidr.contains(ip)) {
            return Some(ip);
        }
    }
    Some(last_valid.unwrap_or(peer))
}

/// The visitor address for allow/deny decisions, with the same token grammar as
/// [`resolve_effective_client_ip`] but stricter about what counts as established: walking from
/// the nearest hop, the first address outside the trusted proxies is the client. An empty,
/// malformed or `unknown` element reached before it, or a chain made only of trusted proxies,
/// leaves the client unknown (`None`), never a proxy's own address or an address beyond an
/// unnamed hop. An untrusted socket peer is the client.
#[must_use]
pub fn resolve_established_client_ip(
    peer_ip: Option<IpAddr>,
    headers: &HeaderMap,
    trusted_proxies: &[IpCidr],
) -> Option<IpAddr> {
    let peer = peer_ip?.to_canonical();
    if !trusted_proxies.iter().any(|cidr| cidr.contains(peer)) {
        return Some(peer);
    }
    let mut parts: Vec<&[u8]> = Vec::new();
    for val in headers.get_all("x-forwarded-for") {
        parts.extend(val.as_bytes().split(|&b| b == b','));
    }
    for part in parts.into_iter().rev() {
        let ip = parse_xff_token(part)?;
        if !trusted_proxies.iter().any(|cidr| cidr.contains(ip)) {
            return Some(ip);
        }
    }
    None
}

fn warn_unparseable_trusted_xff(proxy_peer: IpAddr, raw_token: &[u8]) {
    use std::fmt::Write as _;
    use std::sync::atomic::AtomicU64;
    use std::time::{SystemTime, UNIX_EPOCH};

    static LAST_WARN_UNIX: AtomicU64 = AtomicU64::new(0);
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |d| d.as_secs().max(1));
    let prev = LAST_WARN_UNIX.load(Ordering::Relaxed);
    if now_secs.saturating_sub(prev) >= 30
        && LAST_WARN_UNIX
            .compare_exchange(prev, now_secs, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    {
        let mut safe_tok = String::with_capacity(raw_token.len().min(64));
        for &b in raw_token.iter().take(64) {
            if (0x20..=0x7E).contains(&b) {
                safe_tok.push(char::from(b));
            } else {
                let _ = write!(safe_tok, "\\x{b:02X}");
            }
        }
        warn!(
            trusted_proxy = %proxy_peer,
            xff_token = %safe_tok,
            "trusted proxy sent an unparseable rightmost X-Forwarded-For token (R7-XFF-1); falling back to proxy IP bucket — verify front proxy XFF formatting"
        );
    }
}

/// Formats an [`IpAddr`] directly into a 48-byte stack buffer (longest canonical IPv6 literal is
/// 45 bytes) and builds a [`HeaderValue`] without an intermediate heap `String`.
fn ip_header_value(ip: IpAddr) -> Option<HeaderValue> {
    use std::fmt::Write as _;

    struct IpStackBuf {
        buf: [u8; 48],
        len: usize,
    }

    impl std::fmt::Write for IpStackBuf {
        fn write_str(&mut self, s: &str) -> std::fmt::Result {
            let bytes = s.as_bytes();
            let end = self.len.checked_add(bytes.len()).ok_or(std::fmt::Error)?;
            let dst = self.buf.get_mut(self.len..end).ok_or(std::fmt::Error)?;
            dst.copy_from_slice(bytes);
            self.len = end;
            Ok(())
        }
    }

    let mut out = IpStackBuf {
        buf: [0; 48],
        len: 0,
    };
    write!(out, "{ip}").ok()?;
    HeaderValue::from_bytes(out.buf.get(..out.len)?).ok()
}

/// Extracts the client's original host from the `Host` header (when valid UTF-8) or falls back to
/// the request URI authority, clearing any caller-marked `sensitive` flag so `X-Forwarded-Host`
/// and `preserved_host` match `536486f`'s `HeaderValue::from_str` representation.
fn extract_original_host(headers: &HeaderMap, uri: &Uri) -> Option<HeaderValue> {
    headers
        .get(HOST)
        .filter(|v| v.to_str().is_ok())
        .map(|v| {
            let mut cloned = v.clone();
            cloned.set_sensitive(false);
            cloned
        })
        .or_else(|| {
            uri.authority()
                .and_then(|a| HeaderValue::from_str(a.as_str()).ok())
        })
}

fn apply_forwarded_headers(
    headers: &mut HeaderMap,
    client_ip: Option<IpAddr>,
    client_scheme: &str,
    original_host: Option<HeaderValue>,
    is_trusted_peer: bool,
    trusted_proxies: &[IpCidr],
    extra_slots: usize,
) {
    let xff = HeaderName::from_static("x-forwarded-for");
    let x_real_ip = HeaderName::from_static("x-real-ip");
    let forwarded = HeaderName::from_static("forwarded");
    let xf_proto = HeaderName::from_static("x-forwarded-proto");
    let xf_host = HeaderName::from_static("x-forwarded-host");
    let xf_port = HeaderName::from_static("x-forwarded-port");

    // Optional speculative capacity hint: always use `try_reserve` so an oversized or near-MAX_SIZE
    // map (e.g., while `Forwarded` still occupies a slot) can never panic on the hint itself.
    let reserve_once = |headers: &mut HeaderMap, additional: usize| {
        if additional > 0 && headers.capacity() < headers.keys_len().saturating_add(additional) {
            let _ = headers.try_reserve(additional);
        }
    };

    // Parse `X-Forwarded-Proto` upfront so the slot budget matches whether `headers.insert` will
    // actually run (an empty `client_scheme` parses as a valid empty `HeaderValue` and IS inserted,
    // whereas an invalid header value is skipped).
    let proto_val = match client_scheme {
        "https" => Some(HeaderValue::from_static("https")),
        "http" => Some(HeaderValue::from_static("http")),
        other => HeaderValue::from_str(other).ok(),
    };

    if !is_trusted_peer {
        // Untrusted client peer: strip spoofable forwarding headers before setting ours.
        headers.remove(&x_real_ip);
        headers.remove(&forwarded);
        headers.remove(&xf_port);
        headers.remove(&xf_proto);
        headers.remove(&xf_host);
        if client_ip.is_none() {
            headers.remove(&xff);
        }
        let needed = if client_ip.is_some() {
            1 + usize::from(!headers.contains_key(&xff))
        } else {
            0
        } + usize::from(proto_val.is_some())
            + usize::from(original_host.is_some())
            + extra_slots;
        reserve_once(headers, needed);
        if let Some(ip) = client_ip
            && let Some(val) = ip_header_value(ip)
        {
            // `X-Real-IP` is set as well as `X-Forwarded-For`. Only removing it left the
            // upstream with no `X-Real-IP` at all, and a backend that falls back to the
            // socket peer then sees the proxy's own (often allow-listed) address.
            headers.insert(x_real_ip, val.clone());
            headers.insert(xff, val);
        }
    } else if let Some(peer_ip) = client_ip {
        use std::fmt::Write as _;

        // R6-XFF-2: Compute the effective client IP across ALL incoming XFF lines BEFORE mutating
        // headers, join ALL XFF header lines in order (preserving non-ASCII positions as `unknown`
        // so valid hops on the right survive), strip client-supplied `Forwarded`, and overwrite
        // `X-Real-IP` with the resolved effective client IP!
        let effective_ip = resolve_effective_client_ip(Some(peer_ip), headers, trusted_proxies)
            .unwrap_or_else(|| peer_ip.to_canonical());
        let mut xff_buf = bytes::BytesMut::with_capacity(64);
        for val in headers.get_all(&xff) {
            for part in val.as_bytes().split(|&b| b == b',') {
                let trimmed = trim_ascii_ows(part);
                if trimmed.is_empty() {
                    continue;
                }
                if !xff_buf.is_empty() {
                    xff_buf.extend_from_slice(b", ");
                }
                if trimmed.iter().all(|&b| (0x20..0x7F).contains(&b))
                    && std::str::from_utf8(trimmed).is_ok()
                {
                    xff_buf.extend_from_slice(trimmed);
                } else {
                    xff_buf.extend_from_slice(b"unknown");
                }
            }
        }
        if !xff_buf.is_empty() {
            xff_buf.extend_from_slice(b", ");
        }
        let _ = write!(xff_buf, "{}", peer_ip.to_canonical());
        let needed = usize::from(!headers.contains_key(&xff))
            + usize::from(!headers.contains_key(&x_real_ip))
            + usize::from(proto_val.is_some() && !headers.contains_key(&xf_proto))
            + usize::from(original_host.is_some() && !headers.contains_key(&xf_host))
            + extra_slots;
        reserve_once(headers, needed);
        if let Ok(val) = HeaderValue::from_maybe_shared(xff_buf.freeze()) {
            headers.insert(xff, val);
        }
        headers.remove(&forwarded);
        if let Some(real_val) = ip_header_value(effective_ip) {
            headers.insert(x_real_ip, real_val);
        } else {
            headers.remove(&x_real_ip);
        }
    } else {
        let needed = usize::from(proto_val.is_some() && !headers.contains_key(&xf_proto))
            + usize::from(original_host.is_some() && !headers.contains_key(&xf_host))
            + extra_slots;
        reserve_once(headers, needed);
    }

    if let Some(proto_val) = proto_val {
        headers.insert(xf_proto, proto_val);
    }

    if let Some(host_val) = original_host {
        headers.insert(xf_host, host_val);
    }
}

/// Builds an empty [`ProxyBody`].
#[must_use]
pub fn empty_body() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

/// Builds a single-buffer [`ProxyBody`].
#[must_use]
pub fn full_body(bytes: impl Into<Bytes>) -> ProxyBody {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed()
}

/// Response extension marker attached ONLY when [`ReverseProxy`] itself synthesizes a
/// gateway error response (`502`, `503`, `504`, `413`, `408`) — never on responses returned
/// by an upstream backend — so `miraserve-http` can render MiraServe's built-in error pages
/// without overwriting application error bodies.
#[derive(Debug, Clone, Copy)]
pub struct ProxyGeneratedError;

fn plain_error_response_concrete(
    status: StatusCode,
    msg: &'static str,
) -> Response<ProxyResponseBody> {
    let mut resp = Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(ProxyResponseBody::full(Bytes::from_static(msg.as_bytes())))
        .unwrap_or_else(|_| {
            let mut r = Response::new(ProxyResponseBody::empty());
            *r.status_mut() = status;
            r
        });
    resp.extensions_mut().insert(ProxyGeneratedError);
    resp
}

#[cfg(test)]
mod worker_pool_tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn observer_lock() -> &'static Mutex<()> {
        static LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn base_rp_config(upstream_url: String) -> ReverseProxyConfig {
        ReverseProxyConfig {
            upstreams: vec![miraserve_config::UpstreamConfig {
                url: upstream_url,
                weight: 1,
            }],
            streaming_flush: StreamingFlushMode::Buffered,
            lb_policy: miraserve_config::LoadBalancePolicy::RoundRobin,
            health_check: None,
            upstream_tls: None,
            upstream_connect_timeout: None,
            upstream_response_timeout: None,
            upstream_body_idle_timeout: None,
            preserve_host: false,
            allow_upgrades: true,
            strip_prefix: false,
        }
    }

    async fn spawn_keepalive_upstream()
    -> Result<(SocketAddr, Arc<AtomicU64>, tokio::task::JoinHandle<()>), std::io::Error> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let accepted = Arc::new(AtomicU64::new(0));
        let accepted_c = Arc::clone(&accepted);
        let handle = tokio::spawn(async move {
            while let Ok((mut sock, peer)) = listener.accept().await {
                let conn_id = accepted_c.fetch_add(1, Ordering::SeqCst) + 1;
                tokio::spawn(async move {
                    let mut buf = [0_u8; 4096];
                    while let Ok(n) = sock.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Upstream-Conn: {conn_id}\r\nX-Upstream-Peer: {peer}\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok"
                        );
                        if sock.write_all(resp.as_bytes()).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        Ok((addr, accepted, handle))
    }

    #[test]
    fn worker_loop_index_guard_scopes_nests_unwinds_and_excludes_blocking_pool() -> TestResult {
        assert_eq!(current_worker_loop_index(), None);

        {
            let _g0 = enter_worker_loop_index(0);
            assert_eq!(current_worker_loop_index(), Some(0));
            {
                let _g1 = enter_worker_loop_index(3);
                assert_eq!(current_worker_loop_index(), Some(3));
            }
            assert_eq!(current_worker_loop_index(), Some(0));

            // Panic unwind restores the enclosing guard cleanly.
            let unwind = std::panic::catch_unwind(|| {
                let _g2 = enter_worker_loop_index(7);
                assert_eq!(current_worker_loop_index(), Some(7));
                std::panic::resume_unwind(Box::new("expected unwind"));
            });
            assert!(unwind.is_err());
            assert_eq!(current_worker_loop_index(), Some(0));

            // Neither a fresh OS thread nor a Tokio blocking-pool thread inherits the index.
            let child_seen = std::thread::spawn(current_worker_loop_index)
                .join()
                .map_err(|_| "child thread panicked")?;
            assert_eq!(child_seen, None);

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let blocking_seen = rt.block_on(async {
                assert_eq!(current_worker_loop_index(), Some(0));
                tokio::task::spawn_blocking(current_worker_loop_index).await
            })?;
            assert_eq!(blocking_seen, None);
        }

        assert_eq!(current_worker_loop_index(), None);
        Ok(())
    }

    /// Unit-level verification of per-worker pool selection, concurrent alternating isolation,
    /// out-of-range fallback to `Shared`, and `preserve_host` upgrade-client routing.
    ///
    /// Note: the full end-to-end proof through real `MiraServeServer` `SO_REUSEPORT` worker loops,
    /// TLS, and upstream keep-alive reuse lives in
    /// `crates/miraserve-core/tests/e2e_worker_proxy_pools.rs`.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn per_worker_pools_isolate_connections_and_fall_back_cleanly() -> TestResult {
        let _serial = observer_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let events: Arc<Mutex<Vec<ProxyPoolEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let events_cb = Arc::clone(&events);
        let _observer = test_proxy_pool_observer_guard(move |ev| {
            // Scope to this test's own request paths so parallel unit tests in `miraserve-proxy`
            // (such as active health probes in sibling tests) never pollute this test's counts.
            let is_ours = !ev.is_health_probe
                && (ev.path.starts_with("/shared-")
                    || ev.path.starts_with("/w0-")
                    || ev.path.starts_with("/w1-")
                    || ev.path == "/out-of-range"
                    || ev.path == "/preserve");
            if is_ours {
                events_cb
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(ev);
            }
        });

        let upstream_rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let (addr, accepted, upstream_task) = upstream_rt.block_on(spawn_keepalive_upstream())?;

        // 1. Default mode (`worker_pools == 0`): always uses Shared even if a thread carries an index.
        let shared_proxy = ReverseProxy::new_with_timeouts_and_workers(
            &base_rp_config(format!("http://{addr}")),
            UPSTREAM_CONNECT_TIMEOUT,
            DEFAULT_UPSTREAM_RESPONSE_TIMEOUT,
            DEFAULT_UPSTREAM_BODY_IDLE_TIMEOUT,
            0,
        )?;
        upstream_rt.block_on(async {
            for i in 0..3_usize {
                let req = Request::builder()
                    .uri(format!("/shared-{i}"))
                    .body(empty_body())?;
                let resp = shared_proxy.forward(req, None, "https").await;
                assert_eq!(resp.status(), StatusCode::OK);
                let _ = resp.into_body().collect().await?;
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        {
            let recorded = events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert_eq!(recorded.len(), 3);
            assert!(recorded.iter().all(|e| {
                e.slot == ProxyClientSlot::Shared
                    && e.worker_index.is_none()
                    && e.worker_pool_count == 0
            }));
        }
        drop(shared_proxy);

        // 2. Two per-worker pools kept alive concurrently on two dedicated current-thread runtimes,
        //    alternating completed requests round-by-round via barriers so a shared pool would
        //    reuse worker 0's idle socket on worker 1's turn and fail the disjointness/accept checks.
        events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        accepted.store(0, Ordering::SeqCst);

        let proxy = Arc::new(ReverseProxy::new_with_timeouts_and_workers(
            &base_rp_config(format!("http://{addr}")),
            UPSTREAM_CONNECT_TIMEOUT,
            DEFAULT_UPSTREAM_RESPONSE_TIMEOUT,
            DEFAULT_UPSTREAM_BODY_IDLE_TIMEOUT,
            2,
        )?);

        // Keep both current-thread runtimes actively polling while alternating turns via bounded
        // mpsc channels: if either worker exits early or panics, its sender drops and closes the
        // peer's receiver immediately (and every wait is additionally bounded by a timeout), so a
        // failure on either turn can never hang the test.
        let (w0_to_w1_tx, w0_to_w1_rx) = tokio::sync::mpsc::channel::<usize>(1);
        let (w1_to_w0_tx, w1_to_w0_rx) = tokio::sync::mpsc::channel::<usize>(1);
        let spawn_alternating_worker =
            |idx: usize,
             proxy: Arc<ReverseProxy>,
             peer_tx: tokio::sync::mpsc::Sender<usize>,
             mut peer_rx: tokio::sync::mpsc::Receiver<usize>| {
                std::thread::spawn(move || -> Result<Vec<String>, String> {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| e.to_string())?;
                    let _guard = enter_worker_loop_index(idx);
                    rt.block_on(async move {
                        let turn_timeout = Duration::from_secs(5);
                        let mut conn_ids = Vec::new();
                        for round in 0..4_usize {
                            if idx == 1 || round > 0 {
                                match tokio::time::timeout(turn_timeout, peer_rx.recv()).await {
                                    Ok(Some(_)) => {}
                                    Ok(None) => {
                                        return Err(format!(
                                            "worker {idx} aborted at round {round}: peer exited before hand-off"
                                        ));
                                    }
                                    Err(_) => {
                                        return Err(format!(
                                            "worker {idx} timed out waiting for peer hand-off at round {round}"
                                        ));
                                    }
                                }
                            }
                            let req = Request::builder()
                                .uri(format!("/w{idx}-{round}"))
                                .body(empty_body())
                                .map_err(|e| e.to_string())?;
                            let resp = proxy.forward(req, None, "https").await;
                            if resp.status() != StatusCode::OK {
                                return Err(format!(
                                    "worker {idx} round {round}: unexpected status {}",
                                    resp.status()
                                ));
                            }
                            let cid = resp
                                .headers()
                                .get("x-upstream-conn")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_owned();
                            let _ = resp.into_body().collect().await;
                            // Give hyper's H1 connection driver a turn to return the socket to idle.
                            tokio::time::sleep(Duration::from_millis(5)).await;
                            conn_ids.push(cid);
                            if peer_tx.send(round).await.is_err() {
                                return Err(format!(
                                    "worker {idx} round {round}: peer exited before accepting hand-off"
                                ));
                            }
                        }
                        // Worker 0 stays alive until worker 1 finishes its final round.
                        if idx == 0 {
                            match tokio::time::timeout(turn_timeout, peer_rx.recv()).await {
                                Ok(Some(_)) => {}
                                Ok(None) => {
                                    return Err(
                                        "worker 0 aborted: worker 1 exited before final hand-off"
                                            .to_owned(),
                                    );
                                }
                                Err(_) => {
                                    return Err(
                                        "worker 0 timed out waiting for worker 1 final hand-off"
                                            .to_owned(),
                                    );
                                }
                            }
                        }
                        Ok(conn_ids)
                    })
                })
            };

        let w0_handle = spawn_alternating_worker(0, Arc::clone(&proxy), w0_to_w1_tx, w1_to_w0_rx);
        let w1_handle = spawn_alternating_worker(1, Arc::clone(&proxy), w1_to_w0_tx, w0_to_w1_rx);
        let w0_res = w0_handle.join().map_err(|_| "worker 0 thread panicked")?;
        let w1_res = w1_handle.join().map_err(|_| "worker 1 thread panicked")?;
        let (w0_ids, w1_ids) = match (w0_res, w1_res) {
            (Ok(a), Ok(b)) => (a, b),
            (Err(e0), Err(e1)) => {
                return Err(format!("alternating workers failed: w0=({e0}); w1=({e1})").into());
            }
            (Err(e0), Ok(_)) => return Err(format!("worker 0 failed: {e0}").into()),
            (Ok(_), Err(e1)) => return Err(format!("worker 1 failed: {e1}").into()),
        };

        let w0_set: HashSet<&str> = w0_ids.iter().map(String::as_str).collect();
        let w1_set: HashSet<&str> = w1_ids.iter().map(String::as_str).collect();
        assert_eq!(
            w0_set.len(),
            1,
            "worker 0 must reuse one upstream conn: {w0_ids:?}"
        );
        assert_eq!(
            w1_set.len(),
            1,
            "worker 1 must reuse one upstream conn: {w1_ids:?}"
        );
        assert!(
            w0_set.is_disjoint(&w1_set),
            "worker 0 and worker 1 must not share upstream connections: {w0_set:?} vs {w1_set:?}"
        );
        assert_eq!(accepted.load(Ordering::SeqCst), 2);

        // 3. Out-of-range worker index (e.g. reload lowered `workers`) falls back to Shared.
        let oor_thread = {
            let proxy_c = Arc::clone(&proxy);
            std::thread::spawn(move || -> Result<String, String> {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?;
                let _guard = enter_worker_loop_index(5);
                rt.block_on(async move {
                    let req = Request::builder()
                        .uri("/out-of-range")
                        .body(empty_body())
                        .map_err(|e| e.to_string())?;
                    let resp = proxy_c.forward(req, None, "https").await;
                    if resp.status() != StatusCode::OK {
                        return Err(format!("unexpected status {}", resp.status()));
                    }
                    let cid = resp
                        .headers()
                        .get("x-upstream-conn")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_owned();
                    let _ = resp.into_body().collect().await;
                    Ok(cid)
                })
            })
        };
        let oor_cid = oor_thread
            .join()
            .map_err(|_| "out-of-range thread panicked")??;
        assert!(!w0_set.contains(oor_cid.as_str()));
        assert!(!w1_set.contains(oor_cid.as_str()));
        assert_eq!(accepted.load(Ordering::SeqCst), 3);

        let recorded = events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(recorded.len(), 9);
        assert_eq!(
            recorded
                .iter()
                .filter(|e| e.slot == ProxyClientSlot::Worker(0))
                .count(),
            4
        );
        assert_eq!(
            recorded
                .iter()
                .filter(|e| e.slot == ProxyClientSlot::Worker(1))
                .count(),
            4
        );
        let oor_ev = recorded
            .iter()
            .find(|e| e.path == "/out-of-range")
            .ok_or("missing out-of-range event")?;
        assert_eq!(oor_ev.slot, ProxyClientSlot::Shared);
        assert_eq!(oor_ev.worker_index, Some(5));
        assert_eq!(oor_ev.worker_pool_count, 2);

        // 4. `preserve_host` on a worker uses `WorkerUpgrade(idx)` and `with_upstream_timeout`
        //    updates the shared effective connect timeout across all pools.
        events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        let mut ph_cfg = base_rp_config(format!("http://{addr}"));
        ph_cfg.preserve_host = true;
        let ph_proxy = Arc::new(
            ReverseProxy::new_with_timeouts_and_workers(
                &ph_cfg,
                Duration::from_secs(5),
                Duration::from_secs(10),
                Duration::from_secs(10),
                2,
            )?
            .with_upstream_timeout(Duration::from_millis(500)),
        );
        assert_eq!(
            ph_proxy
                .effective_connect_timeout_ms
                .load(Ordering::Acquire),
            480
        );
        let ph_proxy_c = Arc::clone(&ph_proxy);
        std::thread::spawn(move || -> Result<(), String> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            let _guard = enter_worker_loop_index(1);
            rt.block_on(async move {
                let req = Request::builder()
                    .uri("/preserve")
                    .header(HOST, "tenant.example.test")
                    .body(empty_body())
                    .map_err(|e| e.to_string())?;
                let resp = ph_proxy_c.forward(req, None, "https").await;
                if resp.status() != StatusCode::OK {
                    return Err(format!("unexpected status {}", resp.status()));
                }
                let _ = resp.into_body().collect().await;
                Ok(())
            })
        })
        .join()
        .map_err(|_| "preserve-host worker thread panicked")??;
        let ph_events = events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(ph_events.len(), 1);
        assert_eq!(
            ph_events.first().map(|e| e.slot),
            Some(ProxyClientSlot::WorkerUpgrade(1))
        );

        drop(ph_proxy);
        drop(proxy);
        upstream_task.abort();
        Ok(())
    }
}

#[cfg(test)]
mod header_parity_oracle_tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // =========================================================================
    // VERBATIM COPY from commit `536486f` (`crates/miraserve-proxy/src/lib.rs`,
    // lines 1589–1692): `is_protected_end_to_end_header` and
    // `strip_hop_by_hop_headers` used as the exact behavioral oracle.
    // =========================================================================
    fn oracle_is_protected_end_to_end_header(name: &HeaderName) -> bool {
        if matches!(
            *name,
            HOST | AUTHORIZATION
                | COOKIE
                | SET_COOKIE
                | CONTENT_LENGTH
                | CONTENT_TYPE
                | ORIGIN
                | REFERER
        ) {
            return true;
        }
        let s = name.as_str();
        s.starts_with("x-forwarded-")
            || matches!(
                s,
                "x-real-ip"
                    | "forwarded"
                    | "signature"
                    | "signature-input"
                    | "signature-agent"
                    | "mcp-session-id"
                    | "strict-transport-security"
                    | "content-security-policy"
                    | "x-frame-options"
                    | "x-content-type-options"
                    | "referrer-policy"
                    | "permissions-policy"
                    | "cache-control"
                    | "sec-websocket-key"
                    | "sec-websocket-version"
                    | "sec-websocket-accept"
                    | "sec-websocket-protocol"
                    | "sec-websocket-extensions"
            )
    }

    fn oracle_strip_hop_by_hop_headers(
        headers: &mut HeaderMap,
        preserve_upgrade: bool,
        is_response: bool,
    ) {
        let mut dynamic_hop_headers: Vec<HeaderName> = Vec::new();
        for val in headers.get_all(CONNECTION) {
            if let Ok(raw) = val.to_str() {
                for token in raw.split(',') {
                    let name = token.trim();
                    if preserve_upgrade && name.eq_ignore_ascii_case("upgrade") {
                        continue;
                    }
                    if let Ok(header_name) = HeaderName::from_bytes(name.as_bytes())
                        && !oracle_is_protected_end_to_end_header(&header_name)
                    {
                        dynamic_hop_headers.push(header_name);
                    }
                }
            }
        }

        for name in dynamic_hop_headers {
            headers.remove(&name);
        }

        // PRX-1: Preserve `TE: trailers` (required by gRPC over HTTP/2) while stripping any other TE tokens.
        let preserve_te_trailers = !is_response
            && headers
                .get_all(TE)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .any(|v| {
                    v.split(',')
                        .any(|tok| tok.trim().eq_ignore_ascii_case("trailers"))
                });

        let static_hop_headers = [
            HeaderName::from_static("keep-alive"),
            HeaderName::from_static("proxy-connection"),
            HeaderName::from_static("http2-settings"),
            PROXY_AUTHENTICATE,
            PROXY_AUTHORIZATION,
            TE,
            TRAILER,
            TRANSFER_ENCODING,
        ];
        for name in static_hop_headers {
            headers.remove(&name);
        }

        if preserve_te_trailers {
            headers.insert(TE, HeaderValue::from_static("trailers"));
        }

        if is_response {
            // Never let an upstream spoof MiraServe's authoritative HTTP/3 Alt-Svc advertisement.
            headers.remove(ALT_SVC);
        }

        if preserve_upgrade {
            headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
            headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
        } else {
            headers.remove(CONNECTION);
            headers.remove(UPGRADE);
        }
    }

    // =========================================================================
    // VERBATIM COPY from commit `536486f` (`crates/miraserve-proxy/src/lib.rs`,
    // lines 1865–1943): `apply_forwarded_headers` used as the exact behavioral
    // oracle (including `HeaderMap` iteration order and `is_sensitive` flag).
    // =========================================================================
    fn oracle_apply_forwarded_headers(
        headers: &mut HeaderMap,
        client_ip: Option<IpAddr>,
        client_scheme: &str,
        original_host: Option<&str>,
        is_trusted_peer: bool,
        trusted_proxies: &[IpCidr],
    ) {
        let xff = HeaderName::from_static("x-forwarded-for");
        let x_real_ip = HeaderName::from_static("x-real-ip");
        let forwarded = HeaderName::from_static("forwarded");
        let xf_proto = HeaderName::from_static("x-forwarded-proto");
        let xf_host = HeaderName::from_static("x-forwarded-host");
        let xf_port = HeaderName::from_static("x-forwarded-port");

        if !is_trusted_peer {
            headers.remove(&x_real_ip);
            headers.remove(&forwarded);
            headers.remove(&xf_port);
            headers.remove(&xf_proto);
            headers.remove(&xf_host);
            if let Some(ip) = client_ip {
                if let Ok(val) = HeaderValue::from_str(&ip.to_string()) {
                    headers.insert(x_real_ip, val.clone());
                    headers.insert(xff, val);
                }
            } else {
                headers.remove(&xff);
            }
        } else if let Some(peer_ip) = client_ip {
            let effective_ip = resolve_effective_client_ip(Some(peer_ip), headers, trusted_proxies)
                .unwrap_or_else(|| peer_ip.to_canonical());
            let mut joined_parts: Vec<String> = Vec::new();
            for val in headers.get_all(&xff) {
                for part in val.as_bytes().split(|&b| b == b',') {
                    let trimmed = trim_ascii_ows(part);
                    if trimmed.is_empty() {
                        continue;
                    }
                    if trimmed.iter().all(|&b| (0x20..0x7F).contains(&b))
                        && let Ok(text) = std::str::from_utf8(trimmed)
                    {
                        joined_parts.push(text.to_owned());
                    } else {
                        joined_parts.push("unknown".to_owned());
                    }
                }
            }
            joined_parts.push(peer_ip.to_canonical().to_string());
            let updated = joined_parts.join(", ");
            if let Ok(val) = HeaderValue::from_str(&updated) {
                headers.insert(xff, val);
            }
            headers.remove(&forwarded);
            if let Ok(real_val) = HeaderValue::from_str(&effective_ip.to_string()) {
                headers.insert(x_real_ip, real_val);
            } else {
                headers.remove(&x_real_ip);
            }
        }

        if let Ok(proto_val) = HeaderValue::from_str(client_scheme) {
            headers.insert(xf_proto, proto_val);
        }

        if let Some(host) = original_host
            && let Ok(host_val) = HeaderValue::from_str(host)
        {
            headers.insert(xf_host, host_val);
        }
    }

    fn snapshot_headers(map: &HeaderMap) -> Vec<(String, Vec<u8>, bool)> {
        map.iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_owned(),
                    v.as_bytes().to_vec(),
                    v.is_sensitive(),
                )
            })
            .collect()
    }

    fn assert_strip_matches_oracle(base: &HeaderMap, case_desc: &str) {
        for preserve_upgrade in [false, true] {
            for is_response in [false, true] {
                let mut expected = base.clone();
                let mut actual = base.clone();
                oracle_strip_hop_by_hop_headers(&mut expected, preserve_upgrade, is_response);
                strip_hop_by_hop_headers(&mut actual, preserve_upgrade, is_response);
                let exp_snap = snapshot_headers(&expected);
                let act_snap = snapshot_headers(&actual);
                assert_eq!(
                    act_snap, exp_snap,
                    "strip_hop_by_hop_headers diverged from 536486f oracle on `{case_desc}` \
                     (preserve_upgrade={preserve_upgrade}, is_response={is_response})"
                );
            }
        }
    }

    /// Visits every k-permutation of indices `0..pool_len` without repetition.
    fn for_each_k_permutation(
        pool_len: usize,
        k: usize,
        used: &mut [bool],
        cur: &mut Vec<usize>,
        f: &mut impl FnMut(&[usize]),
    ) {
        if cur.len() == k {
            f(cur);
            return;
        }
        for i in 0..pool_len {
            if let Some(slot) = used.get_mut(i)
                && !*slot
            {
                *slot = true;
                cur.push(i);
                for_each_k_permutation(pool_len, k, used, cur, f);
                cur.pop();
                if let Some(slot_back) = used.get_mut(i) {
                    *slot_back = false;
                }
            }
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn strip_hop_by_hop_matches_536486f_oracle_exhaustively() {
        let long_custom = HeaderName::from_static(
            "x-very-long-custom-hop-header-exceeding-sixty-four-bytes-for-stack-buf",
        );
        let long_conn_val = HeaderValue::from_static(
            "Keep-Alive, X-VERY-LONG-CUSTOM-HOP-HEADER-EXCEEDING-SIXTY-FOUR-BYTES-FOR-STACK-BUF, x-hop",
        );

        // 1. Codex's exact counterexample plus self-nomination, TE, Upgrade, and >64-byte mixed-case
        //    nominations across all 1..=6 permutations of a 7-field core pool (8,659 * 4 = 34,636 cases).
        let core_pool: [(HeaderName, HeaderValue); 7] = [
            (HOST, HeaderValue::from_static("public.example.test")),
            (
                CONNECTION,
                HeaderValue::from_static("keep-alive, x-hop, , bad name!, TE, Connection"),
            ),
            (
                HeaderName::from_static("keep-alive"),
                HeaderValue::from_static("timeout=5"),
            ),
            (
                HeaderName::from_static("x-hop"),
                HeaderValue::from_static("discard"),
            ),
            (TE, HeaderValue::from_static("trailers")),
            (
                HeaderName::from_static("x-a"),
                HeaderValue::from_static("a"),
            ),
            (
                HeaderName::from_static("x-b"),
                HeaderValue::from_static("b"),
            ),
        ];

        let mut total_cases: usize = 0;
        let mut used = vec![false; core_pool.len()];
        let mut cur = Vec::with_capacity(6);
        for k in 1..=6 {
            for_each_k_permutation(core_pool.len(), k, &mut used, &mut cur, &mut |perm| {
                let mut map = HeaderMap::new();
                for &idx in perm {
                    if let Some((name, val)) = core_pool.get(idx) {
                        map.append(name.clone(), val.clone());
                    }
                }
                assert_strip_matches_oracle(&map, "core_pool_1_to_6");
                total_cases += 4;
            });
        }

        // 2. Full 10-field pool covering static hop names, custom nominated names, duplicates,
        //    protected headers, Upgrade, Alt-Svc, multiple Connection lines, and ordinary headers:
        //    all 1..=4 permutations (5,860 * 4 = 23,440 cases).
        let ten_pool: [(HeaderName, HeaderValue); 10] = [
            (HOST, HeaderValue::from_static("example.test")),
            (
                CONNECTION,
                HeaderValue::from_static("Keep-Alive, X-Hop, Upgrade, Host, , x-absent"),
            ),
            (
                CONNECTION,
                HeaderValue::from_static("x-dup, Proxy-Authorization, bad:hdr, transfer-encoding"),
            ),
            (
                HeaderName::from_static("keep-alive"),
                HeaderValue::from_static("timeout=5, max=100"),
            ),
            (
                HeaderName::from_static("x-hop"),
                HeaderValue::from_static("discard"),
            ),
            (
                HeaderName::from_static("x-dup"),
                HeaderValue::from_static("dup-1"),
            ),
            (
                HeaderName::from_static("x-dup"),
                HeaderValue::from_static("dup-2"),
            ),
            (UPGRADE, HeaderValue::from_static("websocket")),
            (ALT_SVC, HeaderValue::from_static("h3=\":443\"")),
            (
                HeaderName::from_static("x-a"),
                HeaderValue::from_static("a"),
            ),
        ];
        let mut used10 = vec![false; ten_pool.len()];
        let mut cur10 = Vec::with_capacity(4);
        for k in 1..=4 {
            for_each_k_permutation(ten_pool.len(), k, &mut used10, &mut cur10, &mut |perm| {
                let mut map = HeaderMap::new();
                for &idx in perm {
                    if let Some((name, val)) = ten_pool.get(idx) {
                        map.append(name.clone(), val.clone());
                    }
                }
                assert_strip_matches_oracle(&map, "ten_pool_1_to_4");
                total_cases += 4;
            });
        }

        // 3. All 6! = 720 permutations (x 4 flags = 2,880 cases each) of tricky 6-field sets:
        //    (a) >64-byte mixed-case nominated custom header + Keep-Alive + X-Hop + X-A + X-B
        //    (b) Duplicate nominated custom header + multiple Connection lines + static Transfer-Encoding
        let tricky_sets: [[(HeaderName, HeaderValue); 6]; 2] = [
            [
                (CONNECTION, long_conn_val),
                (
                    HeaderName::from_static("keep-alive"),
                    HeaderValue::from_static("timeout=5"),
                ),
                (long_custom, HeaderValue::from_static("long-val")),
                (
                    HeaderName::from_static("x-hop"),
                    HeaderValue::from_static("discard"),
                ),
                (
                    HeaderName::from_static("x-a"),
                    HeaderValue::from_static("a"),
                ),
                (
                    HeaderName::from_static("x-b"),
                    HeaderValue::from_static("b"),
                ),
            ],
            [
                (
                    CONNECTION,
                    HeaderValue::from_static("close, transfer-encoding, x-dup"),
                ),
                (
                    CONNECTION,
                    HeaderValue::from_static("proxy-connection, x-dup, authorization, x-missing"),
                ),
                (TRANSFER_ENCODING, HeaderValue::from_static("chunked")),
                (
                    HeaderName::from_static("x-dup"),
                    HeaderValue::from_static("v1"),
                ),
                (
                    HeaderName::from_static("x-dup"),
                    HeaderValue::from_static("v2"),
                ),
                (AUTHORIZATION, HeaderValue::from_static("Bearer secret")),
            ],
        ];
        for (set_idx, set) in tricky_sets.iter().enumerate() {
            let mut u = vec![false; 6];
            let mut c = Vec::with_capacity(6);
            for_each_k_permutation(6, 6, &mut u, &mut c, &mut |perm| {
                let mut map = HeaderMap::new();
                for &idx in perm {
                    if let Some((name, val)) = set.get(idx) {
                        map.append(name.clone(), val.clone());
                    }
                }
                assert_strip_matches_oracle(&map, &format!("tricky_set_{set_idx}"));
                total_cases += 4;
            });
        }

        assert!(
            total_cases >= 60_000,
            "unexpectedly low case count: {total_cases}"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn apply_forwarded_headers_matches_536486f_oracle_including_order_and_sensitivity() {
        let trusted = vec![IpCidr::from_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)))];
        let ips: [Option<IpAddr>; 4] = [
            None,
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
            Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
        ];
        let schemes = ["https", "http", "custom-proto"];
        let sensitive_host = {
            let mut h = HeaderValue::from_static("secret.example.test");
            h.set_sensitive(true);
            h
        };
        let non_utf8_host = HeaderValue::from_bytes(b"bad\xffhost")
            .unwrap_or_else(|_| HeaderValue::from_static("bad-host"));
        // (host_header, request_uri): exercises absent Host, URI-authority fallback, ordinary Host,
        // caller-marked sensitive Host (must clear sensitivity via `extract_original_host`), and
        // non-UTF-8 Host falling back to URI authority.
        let host_cases: [(Option<HeaderValue>, Uri); 5] = [
            (None, Uri::from_static("/path")),
            (None, Uri::from_static("http://authority.example.test/path")),
            (
                Some(HeaderValue::from_static("public.example.test")),
                Uri::from_static("/path"),
            ),
            (Some(sensitive_host), Uri::from_static("/path")),
            (
                Some(non_utf8_host),
                Uri::from_static("http://fallback.example.test/path"),
            ),
        ];

        // Permute a representative 5-header set (120 orders) including spoofed forwarding headers
        // and multi-line / non-ASCII XFF tokens.
        let non_ascii_xff = HeaderValue::from_bytes(b"203.0.113.1, \xffbad, 198.51.100.9")
            .unwrap_or_else(|_| HeaderValue::from_static("203.0.113.1"));
        let base_pool: [(HeaderName, HeaderValue); 5] = [
            (HeaderName::from_static("x-forwarded-for"), non_ascii_xff),
            (
                HeaderName::from_static("x-real-ip"),
                HeaderValue::from_static("1.2.3.4"),
            ),
            (
                HeaderName::from_static("forwarded"),
                HeaderValue::from_static("for=1.2.3.4"),
            ),
            (
                HeaderName::from_static("x-forwarded-port"),
                HeaderValue::from_static("9999"),
            ),
            (
                HeaderName::from_static("x-a"),
                HeaderValue::from_static("a"),
            ),
        ];

        let mut u = vec![false; base_pool.len()];
        let mut c = Vec::with_capacity(base_pool.len());
        for_each_k_permutation(base_pool.len(), 5, &mut u, &mut c, &mut |perm| {
            for (host_opt, uri) in &host_cases {
                let mut base = HeaderMap::new();
                if let Some(h) = host_opt {
                    base.insert(HOST, h.clone());
                }
                for &idx in perm {
                    if let Some((name, val)) = base_pool.get(idx) {
                        base.append(name.clone(), val.clone());
                    }
                }
                base.append(
                    HeaderName::from_static("x-forwarded-for"),
                    HeaderValue::from_static("203.0.113.99"),
                );
                base.insert(
                    HeaderName::from_static("x-b"),
                    HeaderValue::from_static("b"),
                );

                // Verbatim `536486f` host extraction (`crates/miraserve-proxy/src/lib.rs:890-895`).
                let oracle_host_owned = base
                    .get(HOST)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned)
                    .or_else(|| uri.authority().map(|a| a.as_str().to_owned()));
                let oracle_preserved = oracle_host_owned
                    .as_deref()
                    .and_then(|h| HeaderValue::from_str(h).ok());

                // Production extraction helper: removing `cloned.set_sensitive(false)` inside
                // `extract_original_host` immediately fails both assertions below.
                let actual_extracted = extract_original_host(&base, uri);
                assert_eq!(
                    actual_extracted
                        .as_ref()
                        .map(|v| (v.as_bytes(), v.is_sensitive())),
                    oracle_preserved
                        .as_ref()
                        .map(|v| (v.as_bytes(), v.is_sensitive())),
                    "extract_original_host diverged from 536486f (host={host_opt:?}, uri={uri})"
                );

                for &client_ip in &ips {
                    for &scheme in &schemes {
                        for is_trusted in [false, true] {
                            let mut expected = base.clone();
                            let mut actual = base.clone();

                            oracle_apply_forwarded_headers(
                                &mut expected,
                                client_ip,
                                scheme,
                                oracle_host_owned.as_deref(),
                                is_trusted,
                                &trusted,
                            );

                            let actual_host = extract_original_host(&actual, uri);
                            let extra_slots = usize::from(!actual.contains_key(HOST)) + 1;
                            apply_forwarded_headers(
                                &mut actual,
                                client_ip,
                                scheme,
                                actual_host,
                                is_trusted,
                                &trusted,
                                extra_slots,
                            );

                            assert_eq!(
                                snapshot_headers(&actual),
                                snapshot_headers(&expected),
                                "apply_forwarded_headers diverged from 536486f oracle \
                                 (ip={client_ip:?}, scheme={scheme}, trusted={is_trusted}, uri={uri})"
                            );
                        }
                    }
                }
            }
        });
    }

    #[test]
    fn apply_forwarded_headers_single_reserve_prevents_host_and_entry_regrows() {
        let trusted = vec![IpCidr::from_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)))];
        let uri = Uri::from_static("https://bench.test/api/item");
        for initial_count in [0_usize, 1, 2, 6, 12] {
            for is_trusted in [false, true] {
                for has_host in [false, true] {
                    for scheme in ["https", "http", ""] {
                        let mut expected = HeaderMap::with_capacity(initial_count);
                        if has_host {
                            expected.insert(HOST, HeaderValue::from_static("bench.test"));
                        }
                        for i in 0..initial_count {
                            if let Ok(name) = HeaderName::from_bytes(format!("x-h-{i}").as_bytes())
                            {
                                expected.insert(name, HeaderValue::from_static("v"));
                            }
                        }
                        let mut actual = expected.clone();
                        let ip = Some(IpAddr::V4(if is_trusted {
                            Ipv4Addr::new(10, 0, 0, 5)
                        } else {
                            Ipv4Addr::new(198, 51, 100, 9)
                        }));

                        oracle_apply_forwarded_headers(
                            &mut expected,
                            ip,
                            scheme,
                            Some("bench.test"),
                            is_trusted,
                            &trusted,
                        );
                        let extra_slots = usize::from(!actual.contains_key(HOST)) + 1;
                        let orig = extract_original_host(&actual, &uri);
                        apply_forwarded_headers(
                            &mut actual,
                            ip,
                            scheme,
                            orig,
                            is_trusted,
                            &trusted,
                            extra_slots,
                        );
                        assert_eq!(snapshot_headers(&actual), snapshot_headers(&expected));

                        let cap_after_forward = actual.capacity();
                        actual.insert(HOST, HeaderValue::from_static("127.0.0.1:8080"));
                        let _ = actual.entry(HOST);
                        assert_eq!(
                            actual.capacity(),
                            cap_after_forward,
                            "Host insert or hyper_util entry(HOST) regrew HeaderMap \
                             (initial={initial_count}, trusted={is_trusted}, has_host={has_host}, scheme={scheme:?})"
                        );
                    }
                }
            }
        }
    }

    /// Regression test for Codex Round-1 P2-3: speculative reserve in `apply_forwarded_headers`
    /// uses `try_reserve`, so a large trusted-peer map near `HeaderMap`'s `MAX_SIZE` ceiling (where
    /// `Forwarded` still occupies a slot before being removed) never panics on the optional hint.
    #[test]
    fn apply_forwarded_headers_speculative_reserve_near_max_size_never_panics() {
        let trusted = vec![IpCidr::from_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)))];
        let ip = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)));
        let mut expected = HeaderMap::with_capacity(24_575);
        expected.insert(
            HeaderName::from_static("forwarded"),
            HeaderValue::from_static("for=198.51.100.1"),
        );
        expected.insert(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("198.51.100.1"),
        );
        expected.insert(
            HeaderName::from_static("x-forwarded-proto"),
            HeaderValue::from_static("https"),
        );
        expected.insert(
            HeaderName::from_static("x-forwarded-host"),
            HeaderValue::from_static("bench.test"),
        );
        // Fill right up to 24,574 keys (usable capacity ceiling for MAX_SIZE=32,768 is 24,576),
        // leaving room after `Forwarded` is removed for `x-real-ip` while a speculative reserve of
        // `extra_slots = 10` exceeds `MAX_SIZE`.
        for i in 0..24_570_usize {
            if let Ok(name) = HeaderName::from_bytes(format!("x-f-{i}").as_bytes()) {
                expected.insert(name, HeaderValue::from_static("v"));
            }
        }
        let mut actual = expected.clone();

        oracle_apply_forwarded_headers(
            &mut expected,
            ip,
            "https",
            Some("bench.test"),
            true,
            &trusted,
        );
        apply_forwarded_headers(
            &mut actual,
            ip,
            "https",
            Some(HeaderValue::from_static("bench.test")),
            true,
            &trusted,
            10,
        );
        assert_eq!(snapshot_headers(&actual), snapshot_headers(&expected));
    }
}

#[cfg(test)]
mod timeout_passive_health_tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    struct TimeoutHookGuard {
        prev: Option<TimeoutAfterSnapshotHookFn>,
    }

    impl TimeoutHookGuard {
        fn install(hook: TimeoutAfterSnapshotHookFn) -> Self {
            let mut slot = TIMEOUT_AFTER_SNAPSHOT_HOOK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let prev = slot.replace(hook);
            Self { prev }
        }
    }

    impl Drop for TimeoutHookGuard {
        fn drop(&mut self) {
            let mut slot = TIMEOUT_AFTER_SNAPSHOT_HOOK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *slot = self.prev.take();
        }
    }

    struct StallThen413Body {
        should_error: Arc<std::sync::atomic::AtomicBool>,
        chunks_sent: usize,
    }

    impl Body for StallThen413Body {
        type Data = Bytes;
        type Error = ProxyError;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            static CHUNK: [u8; 64 * 1024] = [b'A'; 64 * 1024];
            if self.should_error.load(Ordering::Acquire) || self.chunks_sent >= 512 {
                return Poll::Ready(Some(Err(ProxyError::PayloadTooLarge(1024))));
            }
            self.chunks_sent += 1;
            Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(&CHUNK)))))
        }

        fn is_end_stream(&self) -> bool {
            false
        }
    }

    #[test]
    fn should_charge_timeout_passive_health_uses_live_watch_status() {
        let initial = UploadState {
            done: false,
            ever_polled: true,
            client_waiting: false,
            last_activity_ms: 0,
            client_error_status: 0,
        };
        let (tx, rx) = watch::channel(initial);
        let stale_snapshot = *rx.borrow();
        assert_eq!(stale_snapshot.client_error_status, 0);

        // Control: when status remains 0, an upload stall charges passive health.
        assert!(should_charge_timeout_passive_health(
            false,
            stale_snapshot,
            Some(&rx),
            || 1,
        ));

        // Client publishes 413 AFTER the deadline snapshot was captured.
        tx.send_modify(|s| {
            s.client_error_status = StatusCode::PAYLOAD_TOO_LARGE.as_u16();
            s.done = true;
        });
        assert!(
            !should_charge_timeout_passive_health(false, stale_snapshot, Some(&rx), || 1),
            "timeout branch must read live client_error_status (413), not stale snapshot (0)"
        );

        // Same for client-side 408 slow-body error published after the snapshot.
        tx.send_modify(|s| {
            s.client_error_status = StatusCode::REQUEST_TIMEOUT.as_u16();
        });
        assert!(
            !should_charge_timeout_passive_health(false, stale_snapshot, Some(&rx), || 1),
            "timeout branch must read live client_error_status (408), not stale snapshot (0)"
        );
    }

    #[test]
    fn should_charge_timeout_passive_health_short_circuits_in_flight_load() {
        let loads = std::sync::atomic::AtomicUsize::new(0);
        let load_fn = || {
            loads.fetch_add(1, Ordering::AcqRel);
            2
        };

        let unpolled = UploadState {
            done: false,
            ever_polled: false,
            client_waiting: false,
            last_activity_ms: 0,
            client_error_status: 0,
        };
        let polled = UploadState {
            ever_polled: true,
            ..unpolled
        };
        let done = UploadState {
            done: true,
            ever_polled: true,
            ..unpolled
        };

        // Short-circuited when connecting, already polled, or already done (matching `536486f`).
        assert!(should_charge_timeout_passive_health(
            true, unpolled, None, load_fn
        ));
        assert!(should_charge_timeout_passive_health(
            false, polled, None, load_fn
        ));
        assert!(!should_charge_timeout_passive_health(
            false, done, None, load_fn
        ));
        assert_eq!(
            loads.load(Ordering::Acquire),
            0,
            "in_flight() must be short-circuited unless !was_connecting && !ever_polled && !done"
        );

        // Loaded once for the queued-on-established-connection class.
        assert!(!should_charge_timeout_passive_health(
            false, unpolled, None, load_fn
        ));
        assert_eq!(loads.load(Ordering::Acquire), 1);
    }

    /// Reproduces Codex's exact P1-2 interleaving deterministically against live `ReverseProxy`:
    /// an upload stalls on an unread upstream TCP socket so the deadline snapshots `(done=false,
    /// ever_polled=true, client_waiting=false, client_error_status=0)`, then the upstream drains
    /// the socket so hyper's connection driver polls the next body frame and publishes a
    /// client-side `413` before the timeout branch makes its passive-health decision. On `a01f181`
    /// (stale snapshot), `unhealthy_threshold = 1` marks the backend unhealthy; with the live watch
    /// read, the backend remains healthy.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::too_many_lines)]
    async fn live_timeout_branch_does_not_mark_backend_unhealthy_after_late_client_413()
    -> TestResult {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let start_draining = Arc::new(tokio::sync::Notify::new());
        let start_draining_srv = Arc::clone(&start_draining);

        let upstream_task = tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let start_draining_conn = Arc::clone(&start_draining_srv);
                tokio::spawn(async move {
                    let mut head = [0_u8; 64];
                    let Ok(n) = sock.read(&mut head).await else {
                        return;
                    };
                    if head.get(..n).is_some_and(|b| b.starts_with(b"GET /health")) {
                        let _ = sock
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                            )
                            .await;
                        return;
                    }
                    // POST upload: stop reading so the TCP receive buffer fills and the upload
                    // write stalls until the deadline snapshots `(done=false, client_waiting=false,
                    // client_error_status=0)`.
                    start_draining_conn.notified().await;
                    let mut sink = vec![0_u8; 64 * 1024];
                    while let Ok(read_n) = sock.read(&mut sink).await {
                        if read_n == 0 {
                            break;
                        }
                    }
                });
            }
        });

        let proxy = ReverseProxy::new_with_timeouts(
            &ReverseProxyConfig {
                upstreams: vec![miraserve_config::UpstreamConfig {
                    url: format!("http://{addr}"),
                    weight: 1,
                }],
                streaming_flush: StreamingFlushMode::Buffered,
                lb_policy: miraserve_config::LoadBalancePolicy::RoundRobin,
                health_check: Some(HealthCheckConfig {
                    path: "/health".to_owned(),
                    interval: Duration::from_secs(60),
                    timeout: Some(Duration::from_secs(1)),
                    unhealthy_threshold: 1,
                    host: None,
                }),
                upstream_tls: None,
                upstream_connect_timeout: None,
                upstream_response_timeout: None,
                upstream_body_idle_timeout: None,
                preserve_host: false,
                allow_upgrades: true,
                strip_prefix: false,
            },
            Duration::from_secs(5),
            Duration::from_millis(80),
            Duration::from_secs(5),
        )?;

        let expected_authority = addr.to_string();
        let should_error = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let should_error_hook = Arc::clone(&should_error);
        let start_draining_hook = Arc::clone(&start_draining);
        let saw_413 = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let saw_413_hook = Arc::clone(&saw_413);
        let _hook = TimeoutHookGuard::install(Arc::new(move |authority, rx| {
            if authority != expected_authority {
                return;
            }
            // Snapshot has already been taken with status 0; now switch the body to return 413 and
            // drain the upstream socket so hyper's connection driver polls the next frame and
            // publishes client_error_status = 413 BEFORE `response_deadline` returns to select!.
            should_error_hook.store(true, Ordering::Release);
            start_draining_hook.notify_one();
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                if rx.borrow().client_error_status == StatusCode::PAYLOAD_TOO_LARGE.as_u16() {
                    saw_413_hook.store(true, Ordering::Release);
                    return;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }));

        let req = Request::builder()
            .method(Method::POST)
            .uri("/upload-late-413")
            .body(
                StallThen413Body {
                    should_error,
                    chunks_sent: 0,
                }
                .boxed(),
            )?;

        let resp = proxy.forward(req, None, "https").await;
        upstream_task.abort();

        assert!(
            saw_413.load(Ordering::Acquire),
            "test hook did not observe client 413 publication before timeout return"
        );
        assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
        let backend = proxy
            .pool()
            .backends()
            .first()
            .ok_or("missing backend in pool")?;
        assert!(
            backend.is_healthy(),
            "healthy backend was marked unhealthy on a timeout after late client-side 413"
        );
        Ok(())
    }

    struct HeadPrepareHookGuard {
        authority: String,
        prev: Option<HeadPrepareHookFn>,
    }

    impl HeadPrepareHookGuard {
        fn install(authority: String, hook: HeadPrepareHookFn) -> Self {
            let mut map = HEAD_PREPARE_HOOKS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let prev = map.insert(authority.clone(), hook);
            Self { authority, prev }
        }
    }

    impl Drop for HeadPrepareHookGuard {
        fn drop(&mut self) {
            let mut map = HEAD_PREPARE_HOOKS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(prev) = self.prev.take() {
                map.insert(self.authority.clone(), prev);
            } else {
                map.remove(&self.authority);
            }
        }
    }

    async fn spawn_post_and_health_upstream() -> Result<
        (
            SocketAddr,
            Arc<std::sync::atomic::AtomicUsize>,
            Arc<tokio::sync::Notify>,
            tokio::task::JoinHandle<()>,
        ),
        std::io::Error,
    > {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let received_posts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let received_posts_srv = Arc::clone(&received_posts);
        let first_health_done = Arc::new(tokio::sync::Notify::new());
        let first_health_srv = Arc::clone(&first_health_done);
        let handle = tokio::spawn(async move {
            let signaled_health = Arc::new(std::sync::atomic::AtomicBool::new(false));
            while let Ok((mut sock, _)) = listener.accept().await {
                let posts = Arc::clone(&received_posts_srv);
                let health_nfy = Arc::clone(&first_health_srv);
                let signaled = Arc::clone(&signaled_health);
                tokio::spawn(async move {
                    let mut buf = vec![0_u8; 4096];
                    let Ok(n) = sock.read(&mut buf).await else {
                        return;
                    };
                    if buf.get(..n).is_some_and(|b| b.starts_with(b"GET /health")) {
                        let _ = sock
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                            )
                            .await;
                        let _ = sock.shutdown().await;
                        if !signaled.swap(true, Ordering::AcqRel) {
                            health_nfy.notify_one();
                        }
                        return;
                    }
                    let mut acc = buf.get(..n).unwrap_or_default().to_vec();
                    // Read until full POST body arrives if headers and body split across packets.
                    let deadline = Instant::now() + Duration::from_secs(2);
                    while !acc.windows(b"hello-post".len()).any(|w| w == b"hello-post")
                        && Instant::now() < deadline
                    {
                        let mut more = [0_u8; 1024];
                        match tokio::time::timeout(Duration::from_millis(200), sock.read(&mut more))
                            .await
                        {
                            Ok(Ok(m)) if m > 0 => {
                                if let Some(slice) = more.get(..m) {
                                    acc.extend_from_slice(slice);
                                }
                            }
                            Ok(Ok(_) | Err(_)) | Err(_) => break,
                        }
                    }
                    if acc.starts_with(b"POST /submit")
                        && acc.windows(b"hello-post".len()).any(|w| w == b"hello-post")
                    {
                        posts.fetch_add(1, Ordering::AcqRel);
                    }
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                });
            }
        });
        Ok((addr, received_posts, first_health_done, handle))
    }

    async fn assert_post_survives_head_prepare_pause(include_second_backend: bool) -> TestResult {
        let (addr1, posts1, health1, srv1) = spawn_post_and_health_upstream().await?;
        let mut upstreams = vec![miraserve_config::UpstreamConfig {
            url: format!("http://{addr1}"),
            weight: 1,
        }];
        let second = if include_second_backend {
            let (addr2, _posts2, health2, srv2) = spawn_post_and_health_upstream().await?;
            upstreams.push(miraserve_config::UpstreamConfig {
                url: format!("http://{addr2}"),
                weight: 1,
            });
            Some((health2, srv2))
        } else {
            None
        };

        // `connect_timeout = 100 ms`, `response_timeout = 500 ms` -> `pre_poll_limit = 150 ms`.
        // The head-preparation hook sleeps 180 ms (> pre_poll_limit). Because head preparation
        // runs BEFORE `started_at = Instant::now()`, the POST must still be forwarded cleanly and
        // the backend must stay healthy (`unhealthy_threshold = 1`).
        let proxy = ReverseProxy::new_with_timeouts(
            &ReverseProxyConfig {
                upstreams,
                streaming_flush: StreamingFlushMode::Buffered,
                lb_policy: miraserve_config::LoadBalancePolicy::RoundRobin,
                health_check: Some(HealthCheckConfig {
                    path: "/health".to_owned(),
                    interval: Duration::from_secs(60),
                    timeout: Some(Duration::from_secs(1)),
                    unhealthy_threshold: 1,
                    host: None,
                }),
                upstream_tls: None,
                upstream_connect_timeout: None,
                upstream_response_timeout: None,
                upstream_body_idle_timeout: None,
                preserve_host: false,
                allow_upgrades: true,
                strip_prefix: false,
            },
            Duration::from_millis(100),
            Duration::from_millis(500),
            Duration::from_secs(5),
        )?;

        // Wait for the initial t=0 health probe(s) to finish so no background health success can
        // race with or mask passive-health checks after our POST completes.
        tokio::time::timeout(Duration::from_secs(2), health1.notified()).await?;
        if let Some((ref health2, _)) = second {
            tokio::time::timeout(Duration::from_secs(2), health2.notified()).await?;
        }

        let hook_ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hook_ran_c = Arc::clone(&hook_ran);
        let _hook = HeadPrepareHookGuard::install(
            addr1.to_string(),
            Arc::new(move || {
                hook_ran_c.store(true, Ordering::Release);
                std::thread::sleep(Duration::from_millis(180));
            }),
        );

        let req = Request::builder()
            .method(Method::POST)
            .uri("/submit")
            .body(full_body(Bytes::from_static(b"hello-post")))?;

        let resp = proxy.forward(req, None, "https").await;
        let status = resp.status();
        let body = resp.into_body().collect().await?.to_bytes();

        srv1.abort();
        if let Some((_, srv2)) = second {
            srv2.abort();
        }

        assert!(
            hook_ran.load(Ordering::Acquire),
            "head-preparation test hook did not execute (include_second_backend={include_second_backend})"
        );
        assert_eq!(
            status,
            StatusCode::OK,
            "pause during head preparation must not exhaust pre-poll deadline (include_second_backend={include_second_backend})"
        );
        assert_eq!(&body[..], b"ok");
        assert_eq!(
            posts1.load(Ordering::Acquire),
            1,
            "POST must be forwarded to upstream after head-preparation pause (include_second_backend={include_second_backend})"
        );
        let backend0 = proxy
            .pool()
            .backends()
            .first()
            .ok_or("missing primary backend")?;
        assert!(
            backend0.is_healthy(),
            "healthy backend must not be marked unhealthy after head-preparation pause (include_second_backend={include_second_backend})"
        );
        Ok(())
    }

    /// Reproduces Codex's Round 2 P1 deterministically on BOTH final-attempt (single-backend moved
    /// head) and non-final-attempt (multi-backend cloned headers) paths: delaying inside attempt
    /// head preparation for longer than `pre_poll_limit` (180 ms > 150 ms) must not expire the
    /// upstream deadline before hyper polls the request, must forward the POST, and must leave the
    /// backend healthy. On `006cbba` (where `started_at` preceded head preparation), both cases
    /// fail with `504 Gateway Timeout`, `0` upstream POSTs, and an unhealthy backend.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn head_preparation_delay_does_not_exhaust_pre_poll_deadline() -> TestResult {
        assert_post_survives_head_prepare_pause(false).await?;
        assert_post_survives_head_prepare_pause(true).await?;
        Ok(())
    }

    struct PassiveHealthHookGuard {
        authority: String,
        prev: Option<PassiveHealthFailureHookFn>,
    }

    impl PassiveHealthHookGuard {
        fn install(authority: String, hook: PassiveHealthFailureHookFn) -> Self {
            let mut map = PASSIVE_HEALTH_FAILURE_HOOKS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let prev = map.insert(authority.clone(), hook);
            Self { authority, prev }
        }
    }

    impl Drop for PassiveHealthHookGuard {
        fn drop(&mut self) {
            let mut map = PASSIVE_HEALTH_FAILURE_HOOKS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(prev) = self.prev.take() {
                map.insert(self.authority.clone(), prev);
            } else {
                map.remove(&self.authority);
            }
        }
    }

    struct SeqDropBytes {
        data: &'static [u8],
        label: &'static str,
        events: Arc<std::sync::Mutex<Vec<&'static str>>>,
    }

    impl AsRef<[u8]> for SeqDropBytes {
        fn as_ref(&self) -> &[u8] {
            self.data
        }
    }

    impl Drop for SeqDropBytes {
        fn drop(&mut self) {
            self.events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(self.label);
        }
    }

    #[derive(Clone)]
    struct SeqDropExtension {
        label: &'static str,
        events: Arc<std::sync::Mutex<Vec<&'static str>>>,
    }

    impl Drop for SeqDropExtension {
        fn drop(&mut self) {
            self.events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(self.label);
        }
    }

    /// Creates a single-backend proxy whose initial `t = 0` active health probe has completely
    /// finished (`record_health_success()` observed) and whose backend listener is then dropped so
    /// the next forwarded request gets an immediate connect refusal (`ECONNREFUSED`) on its final
    /// attempt (`is_final_attempt = true`) with zero race against the background probe task.
    async fn single_backend_proxy_with_closed_port()
    -> Result<(ReverseProxy, SocketAddr), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let allow_health_reply = Arc::new(tokio::sync::Notify::new());
        let allow_health_reply_srv = Arc::clone(&allow_health_reply);
        let one_shot_health = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0_u8; 256];
                let _ = sock.read(&mut buf).await;
                allow_health_reply_srv.notified().await;
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = sock.shutdown().await;
            }
            drop(listener);
        });

        let proxy = ReverseProxy::new_with_timeouts(
            &ReverseProxyConfig {
                upstreams: vec![miraserve_config::UpstreamConfig {
                    url: format!("http://{addr}"),
                    weight: 1,
                }],
                streaming_flush: StreamingFlushMode::Buffered,
                lb_policy: miraserve_config::LoadBalancePolicy::RoundRobin,
                health_check: Some(HealthCheckConfig {
                    path: "/health".to_owned(),
                    interval: Duration::from_secs(60),
                    timeout: Some(Duration::from_secs(2)),
                    unhealthy_threshold: 1,
                    host: None,
                }),
                upstream_tls: None,
                upstream_connect_timeout: None,
                upstream_response_timeout: None,
                upstream_body_idle_timeout: None,
                preserve_host: false,
                allow_upgrades: true,
                strip_prefix: false,
            },
            Duration::from_secs(2),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )?;

        // Flip the backend unhealthy before releasing the `t = 0` probe reply, then wait for the
        // probe task itself to flip it back to healthy via `record_health_success()`. That proves
        // the `t = 0` probe task has finished all health writes before our test request starts.
        let backend = proxy
            .pool()
            .backends()
            .first()
            .ok_or("missing primary backend")?;
        backend.record_passive_health_failure(1);
        assert!(!backend.is_healthy());
        allow_health_reply.notify_one();
        one_shot_health.await?;
        let deadline = Instant::now() + Duration::from_secs(5);
        while !backend.is_healthy() {
            if Instant::now() >= deadline {
                return Err(
                    "timed out waiting for t=0 health probe to record_health_success".into(),
                );
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        Ok((proxy, addr))
    }

    /// Reproduces Codex's Round 3 P1 deterministically via direct `Drop` ordering: on a final
    /// attempt (`is_final_attempt = true`), a failed upstream connect on a bodied request MUST
    /// keep the untouched request body alive until AFTER `record_passive_health_failure` runs
    /// (matching `536486f` and `v0.1.4`). On `670e246` (where `needs_slot` was false for non-Boxed
    /// final attempts), `SeqDropBytes::drop` ran before the passive-health write.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn final_attempt_connect_error_retains_full_body_through_passive_health_write()
    -> TestResult {
        let (proxy, addr) = single_backend_proxy_with_closed_port().await?;
        let events: Arc<std::sync::Mutex<Vec<&'static str>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let events_hook = Arc::clone(&events);
        let retained_at_hook = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let retained_c = Arc::clone(&retained_at_hook);

        let _hook = PassiveHealthHookGuard::install(
            addr.to_string(),
            Arc::new(move |retained| {
                retained_c.store(retained, Ordering::Release);
                events_hook
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push("passive_health_failure");
            }),
        );

        let payload = Bytes::from_owner(SeqDropBytes {
            data: b"bodied-upload-payload",
            label: "body_dropped",
            events: Arc::clone(&events),
        });
        let req = Request::builder()
            .method(Method::POST)
            .uri("/upload")
            .body(ProxyRequestBody::Full(Some(payload)))?;

        let resp = proxy.forward_concrete(req, None, "https", None).await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let backend = proxy
            .pool()
            .backends()
            .first()
            .ok_or("missing primary backend")?;
        assert!(!backend.is_healthy());
        let recorded = events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(
            recorded,
            vec!["passive_health_failure", "body_dropped"],
            "final-attempt bodied request must record passive failure BEFORE dropping the body"
        );
        assert!(
            retained_at_hook.load(Ordering::Acquire),
            "untouched body must still be retained in reclaim_slot at passive-health write"
        );
        Ok(())
    }

    /// Exercises the exact HTTP engine upload path from Codex's Round 3 P1 (`BoundedIncoming`
    /// wrapping a real HTTP/2 `hyper::body::Incoming` with unread DATA): after a failed
    /// final-attempt connect, the untouched `BoundedIncoming` MUST still be alive in
    /// `reclaim_slot` when `record_passive_health_failure` executes so `h2::RecvStream::drop`
    /// cannot contend on the downstream H2 stream lock before the passive failure is written.
    /// Fails deterministically on `670e246` where `reclaim_slot` was `None` for final-attempt
    /// `BoundedIncoming`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::too_many_lines)]
    async fn final_attempt_connect_error_retains_bounded_incoming_through_passive_health_write()
    -> TestResult {
        let (proxy, addr) = single_backend_proxy_with_closed_port().await?;
        let proxy = Arc::new(proxy);
        let hook_ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hook_ran_c = Arc::clone(&hook_ran);
        let retained_at_hook = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let retained_c = Arc::clone(&retained_at_hook);

        let _hook = PassiveHealthHookGuard::install(
            addr.to_string(),
            Arc::new(move |retained| {
                hook_ran_c.store(true, Ordering::Release);
                retained_c.store(retained, Ordering::Release);
            }),
        );

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let proxy_srv = Arc::clone(&proxy);
        let server_task = tokio::spawn(async move {
            let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                let proxy_req = Arc::clone(&proxy_srv);
                async move {
                    let (parts, incoming) = req.into_parts();
                    let bounded = miraserve_security::BoundedBody::new(
                        incoming,
                        &miraserve_config::LimitsConfig::default(),
                        &miraserve_config::TimeoutsConfig::default(),
                    );
                    let resp = proxy_req
                        .forward_parts(
                            parts,
                            ProxyRequestBody::BoundedIncoming(Box::new(bounded)),
                            None,
                            "https",
                            None,
                        )
                        .await;
                    Ok::<_, std::convert::Infallible>(resp)
                }
            });
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(server_io), service)
                .await;
        });

        let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .handshake(TokioIo::new(client_io))
            .await?;
        let client_conn_task = tokio::spawn(conn);

        let req = Request::builder()
            .method(Method::POST)
            .uri("http://127.0.0.1/upload-h2")
            .header(CONTENT_LENGTH, "4096")
            .body(Full::new(Bytes::from(vec![b'B'; 4096])))?;
        let resp = sender.send_request(req).await?;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let _ = resp.into_body().collect().await?;

        drop(sender);
        let _ = client_conn_task.await;
        let _ = server_task.await;

        assert!(
            hook_ran.load(Ordering::Acquire),
            "passive-health failure hook did not fire on failed final-attempt connect"
        );
        assert!(
            retained_at_hook.load(Ordering::Acquire),
            "untouched HTTP/2 BoundedIncoming must remain alive in reclaim_slot through passive-health write"
        );
        let backend = proxy
            .pool()
            .backends()
            .first()
            .ok_or("missing primary backend")?;
        assert!(!backend.is_healthy());
        Ok(())
    }

    /// Verifies Codex's Round 3 table correction (Rows 7 & 9): on an early URI rejection (`400`),
    /// `orig_uri` and `base_parts.uri` drop BEFORE `base_parts.extensions` (matching `536486f`),
    /// so an extension destructor observes the custom `Bytes::from_owner` URI owner already dropped.
    #[tokio::test]
    async fn early_uri_rejection_drops_uri_owner_before_request_extensions() -> TestResult {
        let proxy = ReverseProxy::new(&ReverseProxyConfig {
            upstreams: vec![miraserve_config::UpstreamConfig {
                url: "http://127.0.0.1:1".to_owned(),
                weight: 1,
            }],
            streaming_flush: StreamingFlushMode::Buffered,
            lb_policy: miraserve_config::LoadBalancePolicy::RoundRobin,
            health_check: None,
            upstream_tls: None,
            upstream_connect_timeout: None,
            upstream_response_timeout: None,
            upstream_body_idle_timeout: None,
            preserve_host: false,
            allow_upgrades: true,
            strip_prefix: false,
        })?;

        let events: Arc<std::sync::Mutex<Vec<&'static str>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let bad_uri = Uri::from_maybe_shared(Bytes::from_owner(SeqDropBytes {
            data: b"/safe/../escape",
            label: "uri_dropped",
            events: Arc::clone(&events),
        }))?;
        let mut req = Request::builder()
            .method(Method::GET)
            .uri(bad_uri)
            .body(ProxyRequestBody::Empty)?;
        req.extensions_mut().insert(SeqDropExtension {
            label: "ext_dropped",
            events: Arc::clone(&events),
        });

        let resp = proxy.forward_concrete(req, None, "https", None).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let recorded = events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(
            recorded,
            vec!["uri_dropped", "ext_dropped"],
            "early URI rejection must drop URI backing before request extensions (matching 536486f)"
        );
        Ok(())
    }
}

#[cfg(test)]
mod boxed_contract_and_error_tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    struct EndStreamUnknownHintBody {
        _drop_flag: DropFlag,
    }

    impl Body for EndStreamUnknownHintBody {
        type Data = Bytes;
        type Error = ProxyError;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(None)
        }

        fn is_end_stream(&self) -> bool {
            true
        }

        fn size_hint(&self) -> http_body::SizeHint {
            // Deliberately default/unknown (NOT `SizeHint::with_exact(0)`).
            http_body::SizeHint::default()
        }
    }

    #[test]
    fn map_body_guard_err_preserves_http_body_error_prefix() {
        assert!(matches!(
            map_body_guard_err_to_proxy(miraserve_security::BodyGuardError::PayloadTooLarge {
                max_bytes: 4096,
            }),
            ProxyError::PayloadTooLarge(4096)
        ));
        match map_body_guard_err_to_proxy(miraserve_security::BodyGuardError::SlowBodyRate {
            min_rate_bps: 128,
        }) {
            ProxyError::Body(msg) => {
                assert_eq!(
                    msg,
                    "request body read rate fell below minimum 128 bytes/sec"
                );
            }
            other => assert_eq!(format!("{other:?}"), "ProxyError::Body(..)"),
        }
        match map_body_guard_err_to_proxy(miraserve_security::BodyGuardError::Inner(
            "connection reset".to_owned(),
        )) {
            ProxyError::Body(msg) => {
                assert_eq!(msg, "HTTP body error: connection reset");
            }
            other => assert_eq!(format!("{other:?}"), "ProxyError::Body(..)"),
        }
    }

    #[derive(Default)]
    struct ObservedH2Request {
        version: Option<Version>,
        has_content_length: bool,
        body_dropped_during_upstream: bool,
        ext_dropped_during_upstream: bool,
        xf_host: Option<String>,
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn boxed_end_stream_unknown_hint_omits_content_length_on_h2_and_preserves_lifetimes()
    -> TestResult {
        let cert_pem = miraserve_tls::generate_dev_cert_pem(&["127.0.0.1".to_owned()])?;
        let ca_path = std::env::temp_dir().join(format!(
            "miraserve-proxy-h2-contract-{}.pem",
            std::process::id()
        ));
        std::fs::write(&ca_path, &cert_pem.cert_pem)?;

        let provider = miraserve_tls::build_crypto_provider(true);
        let certified = miraserve_tls::load_certified_key_from_pem(
            cert_pem.cert_pem.as_bytes(),
            cert_pem.key_pem.as_bytes(),
            &provider,
        )?;
        let resolver = Arc::new(miraserve_tls::DynamicCertResolver::new(Arc::new(
            miraserve_tls::AcmeChallengeStore::new(),
        )));
        resolver.set_default(certified);
        let mut server_tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        server_tls.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let body_dropped = Arc::new(AtomicBool::new(false));
        let ext_dropped = Arc::new(AtomicBool::new(false));
        let body_dropped_srv = Arc::clone(&body_dropped);
        let ext_dropped_srv = Arc::clone(&ext_dropped);

        let observed = Arc::new(std::sync::Mutex::new(ObservedH2Request::default()));
        let observed_srv = Arc::clone(&observed);

        let upstream_task = tokio::spawn(async move {
            if let Ok((tcp, _)) = listener.accept().await
                && let Ok(tls) = acceptor.accept(tcp).await
            {
                let io = TokioIo::new(tls);
                let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let obs = Arc::clone(&observed_srv);
                    let bd = Arc::clone(&body_dropped_srv);
                    let ed = Arc::clone(&ext_dropped_srv);
                    async move {
                        let mut g = obs
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        g.version = Some(req.version());
                        g.has_content_length = req.headers().contains_key(CONTENT_LENGTH);
                        g.body_dropped_during_upstream = bd.load(Ordering::Acquire);
                        g.ext_dropped_during_upstream = ed.load(Ordering::Acquire);
                        g.xf_host = req
                            .headers()
                            .get("x-forwarded-host")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned);
                        drop(g);
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                            Bytes::from_static(b"ok"),
                        )))
                    }
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await;
            }
        });

        let proxy = ReverseProxy::new(&ReverseProxyConfig {
            upstreams: vec![miraserve_config::UpstreamConfig {
                url: format!("https://{addr}"),
                weight: 1,
            }],
            streaming_flush: StreamingFlushMode::Buffered,
            lb_policy: miraserve_config::LoadBalancePolicy::RoundRobin,
            health_check: None,
            upstream_tls: Some(miraserve_config::UpstreamTlsConfig {
                ca_cert: Some(ca_path.display().to_string()),
                client_cert: None,
                client_key: None,
            }),
            upstream_connect_timeout: None,
            upstream_response_timeout: None,
            upstream_body_idle_timeout: None,
            preserve_host: false,
            allow_upgrades: true,
            strip_prefix: false,
        })?;

        let boxed: ProxyBody = EndStreamUnknownHintBody {
            _drop_flag: DropFlag(Arc::clone(&body_dropped)),
        }
        .boxed();
        // Converting a boxed body into `ProxyRequestBody` must not drop it early or alter its hint.
        let converted = ProxyRequestBody::from(boxed);
        assert!(converted.is_end_stream());
        assert_eq!(converted.size_hint().exact(), None);
        assert!(
            !body_dropped.load(Ordering::Acquire),
            "ProxyRequestBody::from dropped caller's empty boxed body prematurely"
        );

        let mut sensitive_host = HeaderValue::from_static("tenant.example.test");
        sensitive_host.set_sensitive(true);
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/h2-eos-unknown-hint")
            .header(HOST, sensitive_host)
            .body(converted)?;
        req.extensions_mut()
            .insert(Arc::new(DropFlag(Arc::clone(&ext_dropped))));

        let resp = proxy.forward_concrete(req, None, "https", None).await;
        upstream_task.abort();
        let _ = std::fs::remove_file(&ca_path);

        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await?.to_bytes();
        assert_eq!(&body[..], b"ok");

        let obs = observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(obs.version, Some(Version::HTTP_2));
        assert!(
            !obs.has_content_length,
            "POST with end-of-stream boxed body of unknown size_hint must not gain Content-Length: 0 on HTTP/2"
        );
        assert!(
            !obs.body_dropped_during_upstream,
            "caller's empty boxed body dropped before upstream handled the request"
        );
        assert!(
            !obs.ext_dropped_during_upstream,
            "caller's request extension lease dropped early before forward_parts completed"
        );
        assert_eq!(obs.xf_host.as_deref(), Some("tenant.example.test"));
        drop(obs);

        assert!(
            ext_dropped.load(Ordering::Acquire),
            "request extension lease should drop when forward_parts returns"
        );
        Ok(())
    }
}

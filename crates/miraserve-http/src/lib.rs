#![forbid(unsafe_code)]
//! HTTP/1.1, HTTP/2 (`hyper`), and HTTP/3 (`quinn`/`h3`) server engine, virtual-host router,
//! HTTPS redirector, and security headers middleware for MiraServe.

mod basic_auth;
mod buffered;
mod h2_intask;
mod h2_stall;
mod h3_quic;
pub mod h3_server;
mod headers;
mod offload_queue;
pub mod pages;
mod rewrite;
pub mod router;
mod stream_rate;

use std::borrow::Cow;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use bytes::Bytes;
use http::header::CONTENT_TYPE;
use http::{Method, Request, Response, StatusCode, Version};
use http_body_util::{BodyExt as _, Empty, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as AutoConnBuilder;
use miraserve_ai::AgentKeyRegistry;
use miraserve_config::{Config, LimitsConfig, TimeoutsConfig};
use miraserve_security::ConnectionFloodGuard;
use miraserve_telemetry::TelemetryRegistry;
use miraserve_telemetry::redact::{
    escape_log_controls_cow, redact_header_value_cow, redact_request_target_cow,
    redact_uri_query_cow,
};
use miraserve_tls::AcmeChallengeStore;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;
use tracing::{debug, info, warn};

pub use basic_auth::users_file_alias_problem;
pub use h2_intask::{H2ExecMode, H2ExecSelection, select_h2_exec_mode};
#[cfg(any(test, feature = "test-h2-hooks"))]
#[doc(hidden)]
pub use h2_intask::{
    TestH2ExecOverrideGuard, test_h2_exec_override_guard, test_h2_exec_stream_counts,
    test_h2_handoff_mismatch_count, test_h2_upgrade_tasks_spawned,
};
pub use h3_server::{serve_h3_connection, serve_h3_connection_with_control};
pub use miraserve_ai::AgentKeyRegistry as BotAuthKeyRegistry;
#[cfg(feature = "test-h2-hooks")]
#[doc(hidden)]
pub use miraserve_proxy::{
    ProxyClientSlot, ProxyPoolEvent, TestProxyPoolObserverGuard, test_proxy_pool_observer_guard,
};
pub use miraserve_proxy::{
    WorkerLoopIndexGuard, current_worker_loop_index, enter_worker_loop_index,
};
pub use miraserve_static::{
    CacheClock, ManualClock, NonblockingInlineContextGuard, NonblockingStaticSupport,
    WorkerLoopThreadGuard, credential_file_problem, credential_file_problem_for,
    enter_nonblocking_inline_context, enter_worker_loop_thread, find_symlink_component,
    handle_identities, in_nonblocking_inline_context, inline_work_must_not_block,
    is_worker_loop_thread, kernel_supports_h2_intask_static, kernel_supports_nowait_read,
    nonblocking_static_support, open_root_probe, probe_nonblocking_static_support,
    read_no_symlink_file, read_no_symlink_file_opened, reserved_acme_tokens,
    scan_precompressed_siblings_no_follow, warm_nowait_kernel_probe,
    with_nonblocking_inline_context,
};
pub use offload_queue::{
    DiagnosticLogSink, OffloadDrainOutcome, OffloadLogDrainReport,
    enqueue_offloaded_diagnostic_log, flush_offloaded_diagnostic_logs,
    flush_offloaded_diagnostic_logs_blocking, flush_offloaded_diagnostic_logs_until,
    flush_offloaded_diagnostic_logs_until_blocking, offloaded_diagnostic_log_dropped,
    write_or_offload_diagnostic_line,
};
pub use pages::{
    DeterministicRenderOptions, ErrorPageContext, PageFormat, WelcomePageContext,
    generate_csp_nonce, generate_request_id, negotiate_format, render_error_response,
    render_welcome_response,
};
pub use router::{
    CompiledRouter, CredentialSources, OfflineSite, configured_credential_paths,
    serve_https_redirect,
};
#[cfg(any(test, feature = "test-h2-hooks"))]
#[doc(hidden)]
pub use router::{
    TestCompressWaiterBudgetGuard, TestProxyCompressPoolHookGuard, TestWasmHoldGateGuard,
    TestWasmSlotsOverrideGuard, test_compress_waiter_budget_override_guard,
    test_compress_waiter_stats, test_proxy_compress_pool_hook_guard, test_proxy_compress_stats,
    test_wasm_available_slots, test_wasm_hold_path_guard, test_wasm_slots_override_guard,
    test_wasm_spawned_count,
};

/// Unified streaming HTTP body type used across HTTP/1.1, HTTP/2, and HTTP/3.
pub type HttpBody = BoxBody<Bytes, HttpError>;

/// Internal concrete request body flowing from `serve_hyper_connection_with_control` through the
/// router into handlers without heap-boxing empty bodies or double-boxing `BoundedBody<Incoming>`
/// on reverse-proxy uploads.
pub(crate) enum PipeReqBody {
    Empty,
    BoundedIncoming(Box<miraserve_security::BoundedBody<Incoming>>),
    Boxed(HttpBody),
}

impl PipeReqBody {
    pub(crate) fn from_http_body(body: HttpBody) -> Self {
        // Keep caller-supplied boxed bodies intact so their `size_hint()` and drop lifetime match
        // `536486f` on public boxed entry points (`HttpEngine::handle_request`,
        // `CompiledRouter::dispatch`).
        Self::Boxed(body)
    }

    pub(crate) fn into_http_body(self) -> HttpBody {
        match self {
            Self::Empty => empty_http_body(),
            Self::BoundedIncoming(inner) => (*inner).map_err(map_body_guard_error).boxed(),
            Self::Boxed(inner) => inner,
        }
    }

    pub(crate) fn into_proxy_body(self) -> miraserve_proxy::ProxyRequestBody {
        match self {
            Self::Empty => miraserve_proxy::ProxyRequestBody::Empty,
            Self::BoundedIncoming(inner) => {
                miraserve_proxy::ProxyRequestBody::BoundedIncoming(inner)
            }
            Self::Boxed(inner) => miraserve_proxy::ProxyRequestBody::Boxed(
                inner
                    .map_err(|err| match err {
                        HttpError::PayloadTooLarge(max) => {
                            miraserve_proxy::ProxyError::PayloadTooLarge(max)
                        }
                        other => miraserve_proxy::ProxyError::Body(other.to_string()),
                    })
                    .boxed(),
            ),
        }
    }
}

impl http_body::Body for PipeReqBody {
    type Data = Bytes;
    type Error = HttpError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            Self::Empty => Poll::Ready(None),
            Self::BoundedIncoming(inner) => Pin::new(inner.as_mut())
                .poll_frame(cx)
                .map(|opt| opt.map(|res| res.map_err(map_body_guard_error))),
            Self::Boxed(inner) => Pin::new(inner).poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Empty => true,
            Self::BoundedIncoming(inner) => inner.is_end_stream(),
            Self::Boxed(inner) => inner.is_end_stream(),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match self {
            Self::Empty => http_body::SizeHint::with_exact(0),
            Self::BoundedIncoming(inner) => inner.size_hint(),
            Self::Boxed(inner) => inner.size_hint(),
        }
    }
}

/// Internal concrete response body flowing from handlers (`ReverseProxy`, `StaticServer`, error
/// pages) into [`AccessLogBody`] and [`HyperResponseBody`] without boxing `Full(Bytes)` or
/// double-boxing `ProxyResponseBody`.
#[allow(clippy::large_enum_variant)]
pub(crate) enum PipeRespBody {
    Empty,
    Full(Option<Bytes>),
    Proxy(miraserve_proxy::ProxyResponseBody),
    Boxed(HttpBody),
}

impl PipeRespBody {
    pub(crate) const fn empty() -> Self {
        Self::Empty
    }

    pub(crate) fn full(bytes: impl Into<Bytes>) -> Self {
        let bytes = bytes.into();
        if bytes.is_empty() {
            Self::Empty
        } else {
            Self::Full(Some(bytes))
        }
    }

    pub(crate) fn into_http_body(self) -> HttpBody {
        match self {
            Self::Empty | Self::Full(None) => empty_http_body(),
            Self::Full(Some(bytes)) => full_http_body(bytes),
            Self::Proxy(body) => body.map_err(|err| HttpError::Body(err.to_string())).boxed(),
            Self::Boxed(body) => body,
        }
    }
}

impl http_body::Body for PipeRespBody {
    type Data = Bytes;
    type Error = HttpError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            Self::Empty => Poll::Ready(None),
            Self::Full(opt) => match opt.take() {
                Some(bytes) if !bytes.is_empty() => {
                    Poll::Ready(Some(Ok(http_body::Frame::data(bytes))))
                }
                _ => Poll::Ready(None),
            },
            Self::Proxy(body) => Pin::new(body)
                .poll_frame(cx)
                .map(|opt| opt.map(|res| res.map_err(|err| HttpError::Body(err.to_string())))),
            Self::Boxed(body) => Pin::new(body).poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Empty => true,
            Self::Full(opt) => opt.as_ref().is_none_or(Bytes::is_empty),
            Self::Proxy(body) => body.is_end_stream(),
            Self::Boxed(body) => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match self {
            Self::Empty => http_body::SizeHint::with_exact(0),
            Self::Full(opt) => {
                http_body::SizeHint::with_exact(opt.as_ref().map_or(0, |b| b.len() as u64))
            }
            Self::Proxy(body) => body.size_hint(),
            Self::Boxed(body) => body.size_hint(),
        }
    }
}

/// Errors produced by `miraserve-http`.
#[derive(Debug, Error)]
pub enum HttpError {
    /// Failed to initialize a `cap-std` static root.
    #[error("static handler error: {0}")]
    Static(#[from] miraserve_static::StaticError),
    /// Failed to initialize a reverse-proxy upstream pool.
    #[error("proxy handler error: {0}")]
    Proxy(#[from] miraserve_proxy::ProxyError),
    /// Failed to initialize an `ai-publish` release store.
    #[error("ai-publish store error: {0}")]
    Publish(#[from] miraserve_publish::PublishError),
    /// Failed to initialize a sandboxed WebAssembly plugin.
    #[error("WASM plugin error: {0}")]
    Wasm(#[from] miraserve_wasm::WasmError),
    /// Failed to load a site's TLS `client-ca` trust store.
    #[error("TLS trust store error: {0}")]
    Tls(#[from] miraserve_tls::TlsError),
    /// Router configuration error.
    #[error("router error: {0}")]
    Router(String),
    /// Request body exceeded `server.limits.max_body_bytes` (`413`, `R3-HTTP-2`).
    #[error("request body exceeded maximum size of {0} bytes")]
    PayloadTooLarge(u64),
    /// Request body transfer rate fell below `server.timeouts.min_body_rate_bps` (`408`).
    #[error("request body read rate fell below minimum {0} bytes/sec")]
    SlowBodyRate(u64),
    /// Request or response streaming body error.
    #[error("HTTP body error: {0}")]
    Body(String),
}

pub(crate) fn map_body_guard_error(err: miraserve_security::BodyGuardError) -> HttpError {
    match err {
        miraserve_security::BodyGuardError::PayloadTooLarge { max_bytes } => {
            HttpError::PayloadTooLarge(max_bytes)
        }
        miraserve_security::BodyGuardError::SlowBodyRate { min_rate_bps } => {
            HttpError::SlowBodyRate(min_rate_bps)
        }
        miraserve_security::BodyGuardError::Inner(msg) => HttpError::Body(msg),
    }
}

/// TLS connection attributes negotiated at the transport layer and bound to each HTTP request.
#[derive(Debug, Clone, Default)]
pub struct TlsConnectionInfo {
    /// TLS SNI hostname sent in `ClientHello`, if any.
    pub sni: Option<Arc<str>>,
    /// Whether the negotiated TLS version is TLS 1.3 (`false` for legacy TLS 1.2).
    pub is_tls13: bool,
    /// Whether hybrid post-quantum key exchange (`X25519MLKEM768`) was negotiated.
    pub is_pqc: bool,
    /// Out-of-band TLS-verified mTLS client certificate subject DN (never sourced from HTTP headers).
    pub verified_client_cert_dn: Option<Arc<str>>,
    /// Raw DER peer certificate chain (`[leaf, intermediates...]`) presented during TLS/QUIC
    /// handshake, re-verified strictly against the routed site's own `client-ca` trust roots.
    pub peer_cert_chain_der: Option<Arc<[Vec<u8>]>>,
}

/// Request extension: the HTTP/3 connection now uses a different client address than the one
/// its handshake established (QUIC connection migration). Sites that decide by visitor address
/// answer 421 so the client retries on a new connection.
#[derive(Debug, Clone, Copy)]
pub struct PeerMigrated;

/// Per-connection metadata passed into request dispatch.
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// Client peer IP address, if available.
    pub client_ip: Option<IpAddr>,
    /// Client peer TCP/UDP port (`REMOTE_PORT`), if available.
    pub remote_port: Option<u16>,
    /// Local listener IP address (`SERVER_ADDR`), if available.
    pub server_addr: Option<IpAddr>,
    /// Local listener port handling this connection.
    pub server_port: u16,
    /// Whether the request arrived over TLS (HTTPS / HTTP/3).
    pub is_https: bool,
    /// Negotiated TLS SNI / protocol version / mTLS identity (when `is_https == true`).
    pub tls: Option<TlsConnectionInfo>,
}

impl RequestContext {
    /// Returns `"https"` or `"http"` for `X-Forwarded-Proto`.
    #[must_use]
    pub const fn scheme(&self) -> &'static str {
        if self.is_https { "https" } else { "http" }
    }
}

/// Process-monotonic millisecond clock (`>= 1`) used to identify the oldest idle keep-alive
/// connection per IP when evicting idle slots at `max-connections-per-ip`.
fn monotonic_idle_ms() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let elapsed = EPOCH.get_or_init(Instant::now).elapsed().as_millis();
    u64::try_from(elapsed).unwrap_or(u64::MAX).max(1)
}

/// Shared lock-free idle/active tracker for a single accepted client connection.
///
/// Connections start active (not evictable during handshake or before their first request),
/// transition to idle (`idle_since_ms > 0`) only once every in-flight request and response
/// body has completed, and permanently leave the idle pool once upgraded (e.g. WebSocket).
#[derive(Debug, Default)]
pub struct ConnectionIdleState {
    in_flight: AtomicUsize,
    idle_since_ms: AtomicU64,
    upgraded: AtomicBool,
    /// The connection's writer, consulted live for response data still on its way (HTTP/2:
    /// produced but not yet written to the socket), and the progress window that applies.
    transport: OnceLock<(Arc<h2_stall::TransportWriteState>, Duration)>,
}

impl ConnectionIdleState {
    /// Creates a new active (non-idle) connection state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            in_flight: AtomicUsize::new(0),
            idle_since_ms: AtomicU64::new(0),
            upgraded: AtomicBool::new(false),
            transport: OnceLock::new(),
        }
    }

    /// Attaches the connection's writer. From then on the connection is not idle while response
    /// data is still on its way, and its idle time counts from the last DATA written. The answer
    /// is computed when asked, so per-IP eviction never acts on a stale view.
    pub(crate) fn attach_transport(
        &self,
        transport: Arc<h2_stall::TransportWriteState>,
        progress_window: Duration,
    ) {
        let _ = self.transport.set((transport, progress_window));
    }

    /// Marks the start of an active in-flight HTTP request or stream on this connection.
    pub fn enter_request(&self) {
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        self.idle_since_ms.store(0, Ordering::Release);
    }

    /// Marks the completion of an in-flight HTTP request or stream, recording the current
    /// monotonic timestamp when no other streams remain active on this connection.
    pub fn exit_request(&self) {
        if self.in_flight.fetch_sub(1, Ordering::AcqRel) == 1
            && !self.upgraded.load(Ordering::Acquire)
        {
            let now = monotonic_idle_ms();
            if self.in_flight.load(Ordering::Acquire) == 0 && !self.upgraded.load(Ordering::Acquire)
            {
                self.idle_since_ms.store(now, Ordering::Release);
            }
        }
    }

    /// Permanently marks this connection as upgraded (e.g. WebSocket tunnel) so idle eviction
    /// never closes it.
    pub fn mark_upgraded(&self) {
        self.upgraded.store(true, Ordering::Release);
        self.idle_since_ms.store(0, Ordering::Release);
    }

    /// Returns the monotonic millisecond timestamp at which this connection became an idle
    /// keep-alive, or `0` if it is currently active, handshaking, or upgraded.
    #[must_use]
    pub fn idle_since_ms(&self) -> u64 {
        if self.upgraded.load(Ordering::Acquire) || self.in_flight.load(Ordering::Acquire) > 0 {
            return 0;
        }
        let since = self.idle_since_ms.load(Ordering::Acquire);
        match self.transport.get() {
            Some((transport, window)) if since > 0 => {
                if transport.is_delivering(*window) {
                    0
                } else {
                    since.max(transport.last_data_ms())
                }
            }
            _ => since,
        }
    }
}

/// Optional per-connection lifecycle hooks passed from the listener supervisor into
/// [`HttpEngine::serve_hyper_connection_with_control`] and [`serve_h3_connection_with_control`].
#[derive(Clone, Default)]
pub struct ConnectionControl {
    /// Opaque RAII connection lease kept alive across upgraded WebSocket tunnels so graceful
    /// shutdown drains active WebSockets and connection-cap accounting remains exact.
    pub lease: Option<Arc<dyn std::any::Any + Send + Sync>>,
    /// Lock-free idle/active state enabling per-IP idle keep-alive eviction.
    pub idle_state: Option<Arc<ConnectionIdleState>>,
    /// Signaled `true` when the per-IP cap tracker evicts this idle keep-alive connection.
    pub evict_rx: Option<watch::Receiver<bool>>,
    /// Signaled `true` ONLY after `graceful_drain` elapses to force remaining upgraded
    /// tunnels closed cleanly.
    pub upgrade_force_close: Option<watch::Receiver<bool>>,
}

impl std::fmt::Debug for ConnectionControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionControl")
            .field("has_lease", &self.lease.is_some())
            .field("has_idle_state", &self.idle_state.is_some())
            .field("has_evict_rx", &self.evict_rx.is_some())
            .field(
                "has_upgrade_force_close",
                &self.upgrade_force_close.is_some(),
            )
            .finish()
    }
}

struct InFlightRequestGuard {
    idle_state: Option<Arc<ConnectionIdleState>>,
    active: bool,
}

impl InFlightRequestGuard {
    fn enter(idle_state: Option<Arc<ConnectionIdleState>>) -> Self {
        if let Some(st) = &idle_state {
            st.enter_request();
        }
        Self {
            idle_state,
            active: true,
        }
    }

    fn disarm_for_upgrade(mut self) {
        if let Some(st) = &self.idle_state {
            st.mark_upgraded();
        }
        self.active = false;
    }

    fn attach_to_access_log_body(mut self, body: &mut AccessLogBody) {
        if let Some(idle_state) = self.idle_state.take() {
            body.attach_idle_state(idle_state);
        }
        self.active = false;
    }

    fn attach_to_hyper_body(mut self, resp: Response<HttpBody>) -> Response<HyperResponseBody> {
        let Some(idle_state) = self.idle_state.take() else {
            self.active = false;
            return resp.map(HyperResponseBody::Plain);
        };
        self.active = false;
        let (parts, body) = resp.into_parts();
        let tracked = InFlightResponseBody {
            inner: body,
            idle_state: Some(idle_state),
        };
        Response::from_parts(parts, HyperResponseBody::InFlight(tracked))
    }
}

impl Drop for InFlightRequestGuard {
    fn drop(&mut self) {
        if self.active
            && let Some(st) = &self.idle_state
        {
            st.exit_request();
        }
    }
}

struct InFlightResponseBody {
    inner: HttpBody,
    idle_state: Option<Arc<ConnectionIdleState>>,
}

impl InFlightResponseBody {
    fn finish(&mut self) {
        if let Some(st) = self.idle_state.take() {
            st.exit_request();
        }
    }
}

impl Drop for InFlightResponseBody {
    fn drop(&mut self) {
        self.finish();
    }
}

impl http_body::Body for InFlightResponseBody {
    type Data = Bytes;
    type Error = HttpError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if self.inner.is_end_stream() {
                    self.finish();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => {
                self.finish();
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(err))) => {
                self.finish();
                Poll::Ready(Some(Err(err)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

/// Internal response-extension marker attached ONLY when MiraServe itself rejects a request for
/// framing/header/smuggling violations (`400`/`431`), so upstream/plugin `400` responses never
/// accrue HTTP/2 connection termination strikes (`R2-HTTP-2`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct ServerFramingRejection;

/// Runtime HTTP settings refreshed atomically on hot reload.
#[derive(Debug, Clone)]
pub(crate) struct RuntimeHttpSettings {
    pub(crate) limits: LimitsConfig,
    pub(crate) timeouts: TimeoutsConfig,
    pub(crate) alt_svc_header: Option<http::HeaderValue>,
    pub(crate) https_redirect_port: u16,
    pub(crate) redact_logs: bool,
    pub(crate) pqc_hybrid: bool,
    pub(crate) sandbox_state: Arc<str>,
}

/// Staged, validated HTTP router & settings ready for atomic commit during 2-phase reload.
#[derive(Debug)]
pub struct PreparedReload {
    router: Arc<CompiledRouter>,
    settings: Arc<RuntimeHttpSettings>,
}

/// Lock-free, hot-reloadable HTTP request engine shared across H1, H2, and H3 listeners.
#[derive(Debug)]
pub struct HttpEngine {
    router: ArcSwap<CompiledRouter>,
    settings: ArcSwap<RuntimeHttpSettings>,
    acme_challenges: Arc<AcmeChallengeStore>,
    agent_keys: Arc<AgentKeyRegistry>,
    telemetry: Arc<TelemetryRegistry>,
    /// Process-wide byte budget shared across all sites, worker loops, and reload generations.
    file_cache_budget: Arc<miraserve_static::FileCacheBudget>,
    /// Monotonic clock source for the opt-in file cache (`System` in production; `Manual` in tests).
    file_cache_clock: CacheClock,
    /// This server's credential files beyond its configuration (refused by static serving).
    credentials: CredentialSources,
    /// Whether this server's startup configuration includes any non-redirect HTTP/2 listener
    /// (also `true` for synthetic configs with an empty listener list).
    has_h2_listener: bool,
    /// Last logged HTTP/2 stream execution mode (`0` = unselected, `1` = `InTask`, `2` = `Spawned`),
    /// updated at startup and re-evaluated on every hot reload.
    h2_exec_mode: AtomicU8,
    /// Test-only hook: requests whose URI path matches this string intentionally panic inside
    /// `handle_request_with_snapshot` to verify HTTP/2 in-task stream panic isolation.
    #[cfg(test)]
    test_panic_path: Mutex<Option<String>>,
}

impl HttpEngine {
    /// Compiles initial routes and runtime limits from `config`.
    ///
    /// # Errors
    /// Returns [`HttpError`] if any static root, WASM plugin, or reverse-proxy backend fails to initialize.
    pub fn from_config(
        config: &Config,
        acme_challenges: Arc<AcmeChallengeStore>,
        alt_svc_h3_port: Option<u16>,
        https_redirect_port: u16,
    ) -> Result<Self, HttpError> {
        Self::from_config_with_credentials(
            config,
            acme_challenges,
            alt_svc_h3_port,
            https_redirect_port,
            CredentialSources::default(),
        )
    }

    /// [`Self::from_config`] for a server that also holds `credentials` outside its
    /// configuration (command-line secrets, ACME state); every configuration this engine
    /// compiles refuses them in static responses.
    ///
    /// # Errors
    /// As [`Self::from_config`].
    pub fn from_config_with_credentials(
        config: &Config,
        acme_challenges: Arc<AcmeChallengeStore>,
        alt_svc_h3_port: Option<u16>,
        https_redirect_port: u16,
        credentials: CredentialSources,
    ) -> Result<Self, HttpError> {
        Self::from_config_inner(
            config,
            acme_challenges,
            alt_svc_h3_port,
            https_redirect_port,
            credentials,
            CacheClock::System,
        )
    }

    /// [`Self::from_config_with_credentials`] using an explicit [`CacheClock`] for deterministic,
    /// sleep-free file-cache deadline testing.
    ///
    /// # Errors
    /// As [`Self::from_config`].
    pub fn from_config_with_file_cache_clock(
        config: &Config,
        acme_challenges: Arc<AcmeChallengeStore>,
        alt_svc_h3_port: Option<u16>,
        https_redirect_port: u16,
        credentials: CredentialSources,
        file_cache_clock: CacheClock,
    ) -> Result<Self, HttpError> {
        Self::from_config_inner(
            config,
            acme_challenges,
            alt_svc_h3_port,
            https_redirect_port,
            credentials,
            file_cache_clock,
        )
    }

    fn from_config_inner(
        config: &Config,
        acme_challenges: Arc<AcmeChallengeStore>,
        alt_svc_h3_port: Option<u16>,
        https_redirect_port: u16,
        credentials: CredentialSources,
        file_cache_clock: CacheClock,
    ) -> Result<Self, HttpError> {
        let agent_keys = Arc::new(AgentKeyRegistry::new());
        let telemetry = Arc::new(TelemetryRegistry::new());
        let budget_limit =
            usize::try_from(config.server.limits.file_cache_bytes.as_bytes()).unwrap_or(usize::MAX);
        let file_cache_budget = Arc::new(miraserve_static::FileCacheBudget::new(budget_limit));
        let counters =
            miraserve_static::FileCacheCounters::from_raw(telemetry.file_cache_counters_raw());
        let compiled = CompiledRouter::compile_with_file_cache(
            config,
            &agent_keys,
            false,
            &credentials,
            &file_cache_budget,
            counters,
            &file_cache_clock,
        )?;
        buffered::set_max_streamed(
            config.server.limits.max_streamed_answers_per_ip,
            config.server.limits.max_streamed_answers_per_backend,
        );
        let settings = RuntimeHttpSettings {
            limits: config.server.limits.clone(),
            timeouts: config.server.timeouts.clone(),
            alt_svc_header: alt_svc_h3_port.and_then(headers::alt_svc_header_value),
            https_redirect_port,
            redact_logs: config.server.telemetry.redact_logs,
            pqc_hybrid: config.server.tls.pqc_hybrid,
            sandbox_state: Arc::from("Not enabled"),
        };
        let has_h2_listener = config.server.listeners.is_empty()
            || config.server.listeners.iter().any(|l| {
                !l.redirect_https && l.protocols.contains(&miraserve_config::Protocol::H2)
            });
        Ok(Self {
            router: ArcSwap::from_pointee(compiled),
            settings: ArcSwap::from_pointee(settings),
            acme_challenges,
            agent_keys,
            telemetry,
            file_cache_budget,
            file_cache_clock,
            credentials,
            has_h2_listener,
            h2_exec_mode: AtomicU8::new(0),
            #[cfg(test)]
            test_panic_path: Mutex::new(None),
        })
    }

    /// Evaluates and records the HTTP/2 stream execution mode for the currently live configuration,
    /// conditionally probing `openat2(2)` ONLY when HTTP/2, Linux 5.12–6.11, and static file work
    /// are all active.
    #[must_use]
    pub fn select_h2_exec_mode(&self) -> H2ExecSelection {
        let selection = h2_intask::select_h2_exec_mode(
            self.has_h2_listener,
            self.router.load().has_static_work(),
            true,
        );
        self.h2_exec_mode
            .store(selection.mode.encode(), Ordering::Release);
        selection
    }

    /// Returns whether the currently live router has any static file work configured.
    #[must_use]
    pub fn has_static_work(&self) -> bool {
        self.router.load().has_static_work()
    }

    pub(crate) fn classify_h2_stream_exec<B>(&self, req: &Request<B>) -> h2_intask::StreamExec {
        self.router
            .load()
            .classify_h2_stream_exec(req, &self.acme_challenges)
    }

    #[cfg(test)]
    pub(crate) fn set_test_panic_path(&self, path: Option<&str>) {
        *self
            .test_panic_path
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = path.map(str::to_owned);
    }

    /// Returns live bytes currently charged to the process-wide static file-cache budget
    /// (including cached entries and any in-flight bodies still held by slow readers).
    #[must_use]
    pub fn file_cache_budget_used(&self) -> usize {
        self.file_cache_budget.used_bytes()
    }

    /// Sweeps expired entries from the active configuration generation's file cache and returns
    /// how many entries were removed.
    #[must_use]
    pub fn sweep_expired_file_cache(&self) -> usize {
        self.router.load().sweep_expired_file_cache()
    }

    /// The sites the live configuration serves as a 503 as a whole (isolated tenant sites).
    #[must_use]
    pub fn offline_sites(&self) -> Vec<router::OfflineSite> {
        self.router.load().offline_sites().to_vec()
    }

    /// Returns the shared RFC 9421 Web Bot Auth Ed25519 [`AgentKeyRegistry`].
    #[must_use]
    pub fn agent_keys(&self) -> &Arc<AgentKeyRegistry> {
        &self.agent_keys
    }

    /// Returns the shared lock-free Prometheus / OTLP [`TelemetryRegistry`].
    #[must_use]
    pub fn telemetry(&self) -> &Arc<TelemetryRegistry> {
        &self.telemetry
    }

    /// Compiles a replacement routing table WITHOUT mutating live state (Phase 1 of 2-phase reload).
    ///
    /// # Errors
    /// Returns [`HttpError`] if any handler in `next_config` fails to initialize.
    pub fn prepare_reload(&self, next_config: &Config) -> Result<PreparedReload, HttpError> {
        let counters =
            miraserve_static::FileCacheCounters::from_raw(self.telemetry.file_cache_counters_raw());
        // Each reload starts a fresh, empty FileCache generation linked to the same process-wide
        // budget and monotonic telemetry counters; the live budget limit is not mutated until
        // `commit_reload`.
        let mut next_router = CompiledRouter::compile_with_file_cache(
            next_config,
            &self.agent_keys,
            true,
            &self.credentials,
            &self.file_cache_budget,
            counters,
            &self.file_cache_clock,
        )?;
        next_router.inherit_limits(&self.router.load());
        let current_settings = self.settings.load();
        let next_settings = RuntimeHttpSettings {
            limits: next_config.server.limits.clone(),
            timeouts: next_config.server.timeouts.clone(),
            alt_svc_header: current_settings.alt_svc_header.clone(),
            https_redirect_port: current_settings.https_redirect_port,
            redact_logs: next_config.server.telemetry.redact_logs,
            pqc_hybrid: next_config.server.tls.pqc_hybrid,
            sandbox_state: Arc::clone(&current_settings.sandbox_state),
        };
        Ok(PreparedReload {
            router: Arc::new(next_router),
            settings: Arc::new(next_settings),
        })
    }

    /// Atomically commits a previously prepared reload into live traffic (Phase 2 — infallible).
    pub fn commit_reload(&self, prepared: PreparedReload) {
        // With the configuration that becomes live, not when it is prepared: a reload that is
        // refused later must leave the limits of the running configuration alone.
        buffered::set_max_streamed(
            prepared.settings.limits.max_streamed_answers_per_ip,
            prepared.settings.limits.max_streamed_answers_per_backend,
        );
        let next_cache_limit =
            usize::try_from(prepared.settings.limits.file_cache_bytes.as_bytes())
                .unwrap_or(usize::MAX);
        self.file_cache_budget.set_limit(next_cache_limit);
        let has_static_work = prepared.router.has_static_work();
        self.router.store(prepared.router);
        self.settings.store(prepared.settings);
        let selection = h2_intask::select_h2_exec_mode(self.has_h2_listener, has_static_work, true);
        let encoded = selection.mode.encode();
        let prev = self.h2_exec_mode.swap(encoded, Ordering::AcqRel);
        if prev != 0 && prev != encoded {
            info!(
                mode = %selection.mode.as_str(),
                reason = %selection.reason,
                "HTTP/2 stream execution mode updated after reload"
            );
        }
    }

    /// Atomically swaps in a freshly compiled routing table and updated limits/timeouts.
    ///
    /// If compilation fails, the currently active router remains untouched.
    ///
    /// # Errors
    /// Returns [`HttpError`] if the replacement config's routes fail to initialize.
    pub fn reload(&self, next_config: &Config) -> Result<(), HttpError> {
        let prepared = self.prepare_reload(next_config)?;
        self.commit_reload(prepared);
        Ok(())
    }

    /// Updates the advertised HTTP/3 `Alt-Svc` port (used when binding ephemeral ports in tests).
    pub fn set_alt_svc_h3_port(&self, port: Option<u16>) {
        let header = port.and_then(headers::alt_svc_header_value);
        self.settings.rcu(|current| {
            let mut next = (**current).clone();
            next.alt_svc_header.clone_from(&header);
            next
        });
    }

    /// Updates the target HTTPS port used by plaintext `redirect-https=true` listeners.
    pub fn set_https_redirect_port(&self, port: u16) {
        self.settings.rcu(|current| {
            let mut next = (**current).clone();
            next.https_redirect_port = port;
            next
        });
    }

    /// Updates the human-readable worker sandbox summary displayed on the built-in Welcome page
    /// (e.g. `"Enabled"`, `"Filesystem confined"`, or `"Not enabled"`). Never include OS names
    /// or version strings.
    pub fn set_sandbox_state(&self, state: impl Into<Arc<str>>) {
        let state = state.into();
        self.settings.rcu(|current| {
            let mut next = (**current).clone();
            next.sandbox_state = Arc::clone(&state);
            next
        });
    }

    /// Returns whether Post-Quantum Hybrid TLS (`X25519MLKEM768`) is enabled globally (`TEL-3`).
    #[must_use]
    pub fn pqc_hybrid_enabled(&self) -> bool {
        self.settings.load().pqc_hybrid
    }

    /// Returns the configured maximum request body size in bytes.
    #[must_use]
    pub fn max_body_bytes(&self) -> u64 {
        self.settings.load().limits.max_body_bytes.as_bytes()
    }

    /// Returns a snapshot of the active [`LimitsConfig`] and [`TimeoutsConfig`].
    #[must_use]
    pub fn limits_and_timeouts(&self) -> (LimitsConfig, TimeoutsConfig) {
        let s = self.settings.load();
        (s.limits.clone(), s.timeouts.clone())
    }

    /// Returns the configured HTTPS listener port.
    #[must_use]
    pub fn https_port(&self) -> u16 {
        self.settings.load().https_redirect_port
    }

    /// Dispatches a full HTTP request through the active compiled router and emits
    /// secret-redacted structured access logs (`TEL-1`).
    ///
    /// Emits a structured `miraserve::access` log entry once the response body finishes or errors
    /// (`TEL-1`).
    pub async fn handle_request(
        &self,
        req: Request<HttpBody>,
        ctx: &RequestContext,
    ) -> Response<HttpBody> {
        let resp = self
            .handle_request_tracked(req.map(PipeReqBody::from_http_body), ctx, None, true)
            .await;
        box_access_log_response(resp)
    }

    /// Internal request pipeline shared by [`Self::handle_request`] and hyper H1/H2 connections.
    ///
    /// Hyper connections pass `conn_writer` directly and receive a concrete `Response<AccessLogBody>`
    /// without allocating a `TransportOutcome`, a `Response::extensions` map, or a `BoxBody`.
    async fn handle_request_tracked(
        &self,
        req: Request<PipeReqBody>,
        ctx: &RequestContext,
        conn_writer: Option<Arc<ConnWriteTracker>>,
        with_transport_outcome: bool,
    ) -> Response<AccessLogBody> {
        let started = Instant::now();
        let router = self.router.load();
        let settings = self.settings.load();
        let mut req_slot = Some(req);
        self.handle_request_with_snapshot(
            &mut req_slot,
            ctx,
            &router,
            &settings,
            started,
            conn_writer,
            with_transport_outcome,
        )
        .await
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn handle_request_with_snapshot(
        &self,
        req_slot: &mut Option<Request<PipeReqBody>>,
        ctx: &RequestContext,
        router: &CompiledRouter,
        settings: &RuntimeHttpSettings,
        started: Instant,
        conn_writer: Option<Arc<ConnWriteTracker>>,
        with_transport_outcome: bool,
    ) -> Response<AccessLogBody> {
        let (proto, log_method, log_strings, effective_client_ip) = {
            let Some(req) = req_slot.as_ref() else {
                let record = AccessLogRecord {
                    started,
                    telemetry: conn_writer.is_none().then(|| Arc::clone(&self.telemetry)),
                    request_id: pages::generate_request_id_inline(),
                    proto: "h1",
                    scheme: ctx.scheme(),
                    method: Method::GET,
                    strings: AccessLogStrings::from_raw_parts(
                        None,
                        "/",
                        None,
                        None,
                        settings.redact_logs,
                    ),
                    status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    client_ip: IpText::from_opt(ctx.client_ip),
                    peer_ip: IpText::from_opt(ctx.client_ip),
                    redacted: settings.redact_logs,
                };
                let mut resp = Response::new(AccessLogBody {
                    inner: PipeRespBody::empty(),
                    bytes_sent: 0,
                    stream_eof: true,
                    body_errored: false,
                    conn_writer,
                    transport_outcome: with_transport_outcome.then(TransportOutcome::new),
                    idle_state: None,
                    record: Some(record),
                });
                *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                return resp;
            };
            let proto = match req.version() {
                Version::HTTP_3 => "h3",
                Version::HTTP_2 => "h2",
                _ => "h1",
            };
            #[cfg(test)]
            if self
                .test_panic_path
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_deref()
                == Some(req.uri().path())
            {
                #[allow(clippy::panic)]
                {
                    panic!("intentional test panic on {}", req.uri().path());
                }
            }

            // Capture independently owned, already redacted and escaped access-log metadata before
            // moving `req` into router dispatch (`TEL-1`), exactly as in v0.1.2: no `HeaderValue`,
            // `Uri`, or other handle into hyper's request-head buffer outlives `req`, and `latency_us`
            // covers the redaction work.
            let log_method = req.method().clone();
            let raw_target = req
                .uri()
                .path_and_query()
                .map_or_else(|| req.uri().path(), http::uri::PathAndQuery::as_str);
            // Hostname the client asked for (`Host` header, or the HTTP/2 `:authority`), so logs can
            // be split per site. Lower-cased, control characters escaped, length-capped.
            let raw_host = req
                .headers()
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .or_else(|| req.uri().authority().map(http::uri::Authority::as_str));
            let raw_referer = req
                .headers()
                .get(http::header::REFERER)
                .and_then(|v| v.to_str().ok());
            let raw_ua = req
                .headers()
                .get(http::header::USER_AGENT)
                .and_then(|v| v.to_str().ok());
            let log_strings = AccessLogStrings::from_raw_parts(
                raw_host,
                raw_target,
                raw_ua,
                raw_referer,
                settings.redact_logs,
            );

            let effective_client_ip = router::resolve_effective_client_ip(
                ctx.client_ip,
                req.headers(),
                &settings.limits.trusted_proxies,
            );
            (proto, log_method, log_strings, effective_client_ip)
        };
        let request_id = pages::generate_request_id_inline();
        let resp = router
            .dispatch_with_request_id(
                req_slot,
                ctx,
                &settings.limits,
                &self.acme_challenges,
                settings.alt_svc_header.as_ref(),
                &self.telemetry,
                request_id.as_str(),
                &settings.sandbox_state,
            )
            .await;
        // HTTP/2: hand the body over in pieces, inside the accounting wrappers added below and
        // by the connection (see `h2_stall`).
        let resp = if proto == "h2" && !http_body::Body::is_end_stream(resp.body()) {
            let piece = h2_stall::piece_bytes(
                settings.timeouts.min_response_rate_bps,
                settings.timeouts.response_write_idle,
            );
            resp.map(|body| h2_stall::in_pieces_pipe(body, piece))
        } else {
            resp
        };
        let status_u16 = resp.status().as_u16();
        let stream_eof = http_body::Body::is_end_stream(resp.body());
        let record_telemetry = conn_writer.is_none().then(|| Arc::clone(&self.telemetry));
        let peer_ip = IpText::from_opt(ctx.client_ip);
        let client_ip = if effective_client_ip == ctx.client_ip {
            peer_ip
        } else {
            IpText::from_opt(effective_client_ip)
        };
        let access_record = AccessLogRecord {
            started,
            telemetry: record_telemetry,
            request_id,
            proto,
            scheme: ctx.scheme(),
            method: log_method,
            strings: log_strings,
            status: status_u16,
            client_ip,
            peer_ip,
            redacted: settings.redact_logs,
        };
        // The outcome is allocated here, after dispatch and inside the measured interval, where
        // v0.1.2 allocated it (HTTP/3 and embedders; hyper connections pass `false`).
        let transport_outcome = with_transport_outcome.then(TransportOutcome::new);
        let (parts, body) = resp.into_parts();
        let tracked = AccessLogBody {
            inner: body,
            bytes_sent: 0,
            stream_eof,
            body_errored: false,
            conn_writer,
            transport_outcome,
            idle_state: None,
            record: Some(access_record),
        };
        Response::from_parts(parts, tracked)
    }

    /// Handles a request received on a plaintext `redirect-https=true` listener.
    #[must_use]
    pub fn handle_redirect(&self, req: &Request<HttpBody>) -> Response<HttpBody> {
        let router = self.router.load();
        let settings = self.settings.load();
        let request_id = pages::generate_request_id_inline();
        router::serve_https_redirect_with_request_id(
            req,
            settings.https_redirect_port,
            &settings.limits,
            &router,
            &self.acme_challenges,
            request_id.as_str(),
        )
    }

    /// Handles a request received on a plaintext `redirect-https=#true` listener:
    /// when no site in the active router uses `http "serve"`, runs the unmodified v0.1.2
    /// redirect responder directly; otherwise decides against a single router/settings snapshot
    /// whether an HTTP/1.x request belongs to an `http "serve"` site and dispatches it through
    /// the normal request pipeline with `ctx.is_https == false`.
    pub async fn handle_redirect_listener_request(
        &self,
        req: Request<HttpBody>,
        ctx: &RequestContext,
    ) -> Response<HttpBody> {
        match self
            .handle_redirect_listener_request_with_upgrade(
                req.map(PipeReqBody::Boxed),
                ctx,
                None,
                None,
                true,
            )
            .await
            .0
            .into_parts()
        {
            (parts, HyperResponseBody::Direct(tracked)) => {
                box_access_log_response(Response::from_parts(parts, tracked))
            }
            (parts, HyperResponseBody::Plain(body)) => Response::from_parts(parts, body),
            (parts, other) => Response::from_parts(parts, other.boxed()),
        }
    }

    async fn handle_redirect_listener_request_with_upgrade(
        &self,
        req: Request<PipeReqBody>,
        ctx: &RequestContext,
        upgrade_lc: Option<miraserve_proxy::UpgradeLifecycle>,
        conn_writer: Option<&Arc<ConnWriteTracker>>,
        with_transport_outcome: bool,
    ) -> (Response<HyperResponseBody>, Option<Request<PipeReqBody>>) {
        let router = self.router.load();
        let settings = self.settings.load();
        let mut req_slot = Some(req);
        if router.has_http_serve_site() {
            // The clock covers the attribution to a site, as it covers the site search of an
            // HTTPS request; configurations without a serve-mode site never get here.
            let started = Instant::now();
            if req_slot
                .as_ref()
                .is_some_and(|r| router::should_serve_plain_http(r, &router))
            {
                if let (Some(lc), Some(r)) = (upgrade_lc, req_slot.as_mut()) {
                    r.extensions_mut().insert(lc);
                }
                let resp = self
                    .handle_request_with_snapshot(
                        &mut req_slot,
                        ctx,
                        &router,
                        &settings,
                        started,
                        conn_writer.map(Arc::clone),
                        with_transport_outcome,
                    )
                    .await
                    .map(HyperResponseBody::Direct);
                return (resp, None);
            }
        }
        let request_id = pages::generate_request_id_inline();
        let resp = if let Some(req_ref) = req_slot.as_ref() {
            router::serve_https_redirect_with_request_id_async(
                req_ref,
                settings.https_redirect_port,
                &settings.limits,
                &router,
                &self.acme_challenges,
                request_id.as_str(),
            )
            .await
            .map(HyperResponseBody::Plain)
        } else {
            let mut r = Response::new(HyperResponseBody::Plain(empty_http_body()));
            *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            r
        };
        // The request goes back to the caller, which keeps it until its strike accounting is
        // done, as v0.1.2 did: dropping an HTTP/2 request body can wait on the connection.
        (resp, req_slot)
    }

    /// Serves HTTP/1.1 and HTTP/2 over an accepted TCP or TLS stream with protocol caps,
    /// initial idle/sniff timeout (`DOS-2`), header timeouts, bad-request flood protection,
    /// exact listener `local_addr` (`FCGI-5`), WebSocket upgrades, and graceful drain.
    #[allow(clippy::too_many_arguments)]
    pub async fn serve_hyper_connection<I>(
        self: Arc<Self>,
        io: I,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        is_https: bool,
        redirect_only: bool,
        tls_info: Option<TlsConnectionInfo>,
        shutdown: watch::Receiver<bool>,
    ) where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.serve_hyper_connection_with_control(
            io,
            peer_addr,
            local_addr,
            is_https,
            redirect_only,
            tls_info,
            shutdown,
            ConnectionControl::default(),
        )
        .await;
    }

    /// Serves HTTP/1.1 and HTTP/2 like [`Self::serve_hyper_connection`], wiring per-connection
    /// idle eviction (`ConnectionIdleState` + `evict_rx`) and upgraded WebSocket tunnel
    /// graceful-drain lease propagation (`ConnectionControl`).
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_lines)]
    pub async fn serve_hyper_connection_with_control<I>(
        self: Arc<Self>,
        io: I,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        is_https: bool,
        redirect_only: bool,
        tls_info: Option<TlsConnectionInfo>,
        mut shutdown: watch::Receiver<bool>,
        control: ConnectionControl,
    ) where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let settings = self.settings.load();
        let header_timeout = settings.timeouts.header_read;
        let drain_timeout = settings.timeouts.graceful_drain;
        let max_streams = settings.limits.max_concurrent_streams;
        let max_headers_bytes =
            usize::try_from(settings.limits.max_header_bytes.as_bytes()).unwrap_or(16_384);
        let idle_timeout = settings.timeouts.idle_keepalive;

        let (h2_exec, h2_handoff) = h2_intask::H2Exec::for_connection(
            !redirect_only && self.has_h2_listener,
            self.router.load().has_static_work(),
        );
        let mut builder = AutoConnBuilder::new(h2_exec.clone());
        builder
            .http1()
            .timer(TokioTimer::new())
            // hyper runs this one timer from the moment a connection starts waiting for a
            // request until the head is complete, so it cannot enforce the idle limit and the
            // header limit separately. `HeadDeadlineIo` enforces both phases (and
            // `first_req_deadline` covers the wait before the first request); hyper's timer is
            // only a backstop, set to the longest a correct client can take.
            .header_read_timeout(idle_timeout.saturating_add(header_timeout))
            .max_buf_size(max_headers_bytes.max(8_192));
        builder
            .http2()
            .timer(TokioTimer::new())
            .max_concurrent_streams(max_streams)
            .max_header_list_size(u32::try_from(max_headers_bytes).unwrap_or(16_384))
            // R5-HTTP-4: Size the H2 connection flow-control window at 16x the per-stream window
            // (4 MiB vs 256 KiB) so one stalled stream whose upstream stops reading cannot fill
            // the entire connection window and starve sibling uploads into false 408 timeouts.
            .initial_stream_window_size(Some(256 * 1024))
            .initial_connection_window_size(Some(4 * 1024 * 1024))
            .max_pending_accept_reset_streams(Some(
                usize::try_from(settings.limits.max_h2_rst_stream_per_sec).unwrap_or(50),
            ));
        // No HTTP/2 keep-alive PINGs. A PING queues behind the response data already sent, so
        // a client reading slowly answers it only after draining that data: with 20 s to answer,
        // a 3 KB/s download over HTTP/2 was closed after exactly 50 s although it was above the
        // minimum rate (AmiraPanel staging). The cases PINGs were meant for are covered without
        // them: an idle connection closes at `idle-keepalive` (`h2_watch`), a peer that stops
        // reading blocks the socket and is cut by the TCP write guard, and a stream whose window
        // stays closed is released by the stall watchdog.

        let limits_snap = settings.limits.clone();
        let timeouts_snap = settings.timeouts.clone();
        let flood_guard = Arc::new(ConnectionFloodGuard::from_limits(&limits_snap));
        let (bad_req_close_tx, mut bad_req_close_rx) = watch::channel(false);
        let first_req_seen = Arc::new(AtomicBool::new(false));
        let first_req_seen_svc = Arc::clone(&first_req_seen);
        // Always tracked (not only when a per-IP lease exists): the header deadline needs to
        // know when the connection is between requests.
        let idle_state = control
            .idle_state
            .unwrap_or_else(|| Arc::new(ConnectionIdleState::new()));
        let is_h2 = Arc::new(AtomicBool::new(false));
        let is_h2_svc = Arc::clone(&is_h2);
        let head_in_progress = Arc::new(AtomicBool::new(false));
        let mut evict_rx = control.evict_rx;
        let upgrade_template = if control.lease.is_some() || control.upgrade_force_close.is_some() {
            Some(miraserve_proxy::UpgradeLifecycle {
                connection_lease: control.lease,
                force_close: control.upgrade_force_close,
            })
        } else {
            None
        };

        let write_tracker = Arc::new(ConnWriteTracker::new(Arc::clone(&self.telemetry)));
        let write_idle = settings.timeouts.response_write_idle;
        let h2_streams = h2_stall::H2StallRegistry::new();
        idle_state.attach_transport(h2_streams.transport(), write_idle);
        let dispatched = Arc::new(AtomicU64::new(0));
        let dispatched_svc = Arc::clone(&dispatched);

        // The client's RST_STREAM frames are counted where they are read (see
        // `h2_stall::ResetFrameCounter`).
        let reset_count = (Arc::clone(&flood_guard), bad_req_close_tx.clone());

        let (shared_upgrade_template, redirect_upgrade_template) = if redirect_only {
            (None, upgrade_template)
        } else {
            (upgrade_template, None)
        };

        let conn_shared = Arc::new(ConnShared {
            engine: Arc::clone(&self),
            limits: limits_snap,
            timeouts: timeouts_snap,
            flood_guard,
            bad_req_close_tx,
            idle_state: Arc::clone(&idle_state),
            upgrade_template: shared_upgrade_template,
            write_tracker: Arc::clone(&write_tracker),
            h2_streams: Arc::clone(&h2_streams),
            ctx: RequestContext {
                client_ip: Some(peer_addr.ip().to_canonical()),
                remote_port: Some(peer_addr.port()),
                server_addr: Some(local_addr.ip().to_canonical()),
                server_port: local_addr.port(),
                is_https,
                tls: tls_info,
            },
            redirect_only,
        });

        let svc = service_fn(move |req: Request<Incoming>| {
            if !first_req_seen_svc.load(Ordering::Relaxed) {
                first_req_seen_svc.store(true, Ordering::Release);
            }
            let is_h2_request = req.version() == http::Version::HTTP_2;
            if is_h2_request {
                if let Some(handoff) = &h2_handoff {
                    let decision = if req.method() == http::Method::CONNECT {
                        h2_intask::StreamExec::Spawn
                    } else if conn_shared.redirect_only {
                        h2_intask::StreamExec::InTask
                    } else {
                        conn_shared.engine.classify_h2_stream_exec(&req)
                    };
                    handoff.set(decision);
                }
                if !is_h2_svc.load(Ordering::Acquire) && !is_h2_svc.swap(true, Ordering::AcqRel) {
                    // Start the HTTP/2 watchdog of this connection.
                    conn_shared.h2_streams.notify();
                }
            } else {
                dispatched_svc.fetch_add(1, Ordering::AcqRel);
            }
            let shared = Arc::clone(&conn_shared);
            let idle_guard = InFlightRequestGuard::enter(Some(Arc::clone(&shared.idle_state)));
            // On the redirect listener an HTTP/2 request is never served and never upgraded,
            // so keep the redirect listener's upgrade template outside `ConnShared` and clone it
            // only for HTTP/1.1 requests carrying an `Upgrade` header.
            let redirect_upgrade_lc = if redirect_only
                && req.version() == Version::HTTP_11
                && req.headers().contains_key(http::header::UPGRADE)
            {
                redirect_upgrade_template.clone()
            } else {
                None
            };
            let fut = async move {
                // On the redirect listener the request keeps its original body, as in v0.1.2:
                // the request is held until after the strike accounting below, and replacing
                // an HTTP/2 body here would end its receive stream (which takes the
                // connection's stream lock) before the strike is counted.
                let keep_original_body = shared.redirect_only;
                let mut mapped: Request<PipeReqBody> = req.map(|b| {
                    // Match `536486f`'s ingress predicate (`is_end_stream()` only) so an HTTP/2
                    // stream entering connection error shutdown as `ErrorAfterEndStream` with a
                    // non-zero stored `Content-Length` hint is released at ingress identically to
                    // baseline rather than retained as a tracked `BoundedIncoming` body.
                    if !keep_original_body && http_body::Body::is_end_stream(&b) {
                        PipeReqBody::Empty
                    } else {
                        PipeReqBody::BoundedIncoming(Box::new(
                            miraserve_security::BoundedBody::new(
                                b,
                                &shared.limits,
                                &shared.timeouts,
                            ),
                        ))
                    }
                });
                if !shared.redirect_only {
                    // WebSocket upgrades only occur on HTTP/1.1 requests carrying an `Upgrade` header.
                    if mapped.version() == Version::HTTP_11
                        && mapped.headers().contains_key(http::header::UPGRADE)
                        && let Some(lc) = &shared.upgrade_template
                    {
                        mapped.extensions_mut().insert(lc.clone());
                    }
                    // Boxed: see `SERVICE_FUTURE_MAX_BYTES`.
                    let (parts, mut body) = Box::pin(shared.engine.handle_request_tracked(
                        mapped,
                        &shared.ctx,
                        Some(Arc::clone(&shared.write_tracker)),
                        false,
                    ))
                    .await
                    .into_parts();
                    if parts.extensions.get::<ServerFramingRejection>().is_some()
                        && matches!(
                            parts.status,
                            StatusCode::BAD_REQUEST | StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
                        )
                        && !shared.flood_guard.record_bad_request()
                    {
                        let _ = shared.bad_req_close_tx.send(true);
                    }
                    if parts.status == StatusCode::SWITCHING_PROTOCOLS {
                        idle_guard.disarm_for_upgrade();
                        return Ok::<_, std::convert::Infallible>(Response::from_parts(
                            parts,
                            HyperResponseBody::Direct(body),
                        ));
                    }
                    idle_guard.attach_to_access_log_body(&mut body);
                    let resp = if is_h2_request && !http_body::Body::is_end_stream(&body) {
                        Response::from_parts(
                            parts,
                            HyperResponseBody::H2Stalled(shared.h2_streams.guard_access_log(body)),
                        )
                    } else {
                        Response::from_parts(parts, HyperResponseBody::Direct(body))
                    };
                    return Ok::<_, std::convert::Infallible>(resp);
                }
                // Redirect-only listener path: a request answered by the v0.1.2 redirect responder
                // is kept here until after the strike accounting below, as in v0.1.2.
                let (resp, kept_redirect_request) =
                    Box::pin(shared.engine.handle_redirect_listener_request_with_upgrade(
                        mapped,
                        &shared.ctx,
                        redirect_upgrade_lc,
                        Some(&shared.write_tracker),
                        false,
                    ))
                    .await;
                // R2-HTTP-2: Only server-generated framing/smuggling rejections accrue strikes,
                // never upstream reverse-proxy, FastCGI, MCP, or WASM 400 responses. Both normal
                // and redirect-only listeners pass through this common check (as in v0.1.2).
                if resp.extensions().get::<ServerFramingRejection>().is_some()
                    && matches!(
                        resp.status(),
                        StatusCode::BAD_REQUEST | StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
                    )
                    && !shared.flood_guard.record_bad_request()
                {
                    let _ = shared.bad_req_close_tx.send(true);
                }
                if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
                    idle_guard.disarm_for_upgrade();
                    return Ok::<_, std::convert::Infallible>(resp);
                }
                let resp = match resp.into_parts() {
                    (parts, HyperResponseBody::Direct(mut body)) => {
                        idle_guard.attach_to_access_log_body(&mut body);
                        if is_h2_request && !http_body::Body::is_end_stream(&body) {
                            Response::from_parts(
                                parts,
                                HyperResponseBody::H2Stalled(
                                    shared.h2_streams.guard_access_log(body),
                                ),
                            )
                        } else {
                            Response::from_parts(parts, HyperResponseBody::Direct(body))
                        }
                    }
                    (parts, HyperResponseBody::Plain(body)) => {
                        let resp =
                            idle_guard.attach_to_hyper_body(Response::from_parts(parts, body));
                        if is_h2_request && !http_body::Body::is_end_stream(resp.body()) {
                            resp.map(|body| {
                                HyperResponseBody::Plain(
                                    shared.h2_streams.guard_counting(body.boxed(), None),
                                )
                            })
                        } else {
                            resp
                        }
                    }
                    (parts, other) => Response::from_parts(parts, other),
                };
                drop(kept_redirect_request);
                Ok::<_, std::convert::Infallible>(resp)
            };
            debug_assert!(
                std::mem::size_of_val(&fut) <= SERVICE_FUTURE_MAX_BYTES,
                "the per-request service future grew to {} bytes",
                std::mem::size_of_val(&fut)
            );
            fut
        });

        // R8-HTTP-1: slow-reader protection is NOT applied here. It has to sit on the TCP socket,
        // below TLS, so the listener wraps the accepted stream with
        // `WriteGuardedIo::for_tcp_stream` before the handshake and passes the result in as `io`.
        // Codex G8: Wrap `io` in `WriteOutcomeIo` so transport write/flush failures on the final
        // response bytes are fed into `AccessLogRecord` even after `AccessLogBody` is dropped.
        let head_io = HeadDeadlineIo::new(
            io,
            Arc::clone(&idle_state),
            Arc::clone(&is_h2),
            Arc::clone(&head_in_progress),
            header_timeout,
            idle_timeout,
            h2_streams.transport(),
            Arc::clone(&dispatched),
        )
        .counting_resets(reset_count.0, reset_count.1);
        let tracked_io = WriteOutcomeIo::new(head_io, write_tracker);
        let conn = builder.serve_connection_with_upgrades(TokioIo::new(tracked_io), svc);
        let conn = pin!(conn);
        let mut conn = pin!(h2_intask::ConnDriver::new(
            conn,
            h2_exec,
            hyper_util::server::conn::auto::UpgradeableConnection::graceful_shutdown,
        ));

        // DOS-2: Bound protocol-sniff / pre-first-request silence by `header_read` timeout so
        // peers that connect and send zero bytes can never pin connection slots indefinitely.
        let mut first_req_deadline = pin!(tokio::time::sleep(header_timeout));
        let mut first_req_timer_active = true;

        loop {
            tokio::select! {
                res = conn.as_mut() => {
                    if let Err(err) = res {
                        // The message of the error and of everything it wraps: hyper reports
                        // the specific cause (a keep-alive timeout, an I/O timeout) as a source.
                        let mut text = err.to_string();
                        let mut source = std::error::Error::source(&*err);
                        while let Some(cause) = source {
                            text.push_str(": ");
                            text.push_str(&cause.to_string());
                            source = cause.source();
                        }
                        let timed_out = text.contains("timeout") || text.contains("TimedOut");
                        // An idle keep-alive connection reaching `idle-keepalive` with no
                        // request head in progress is normal and not worth a warning.
                        let idle_expiry = timed_out
                            && idle_state.idle_since_ms() > 0
                            && !head_in_progress.load(Ordering::Acquire);
                        if idle_expiry {
                            debug!(peer = %peer_addr, "closing idle keep-alive connection");
                        } else if timed_out {
                            warn!(peer = %peer_addr, error = %err, "closing slow client HTTP connection");
                        } else {
                            debug!(peer = %peer_addr, error = %err, "HTTP connection closed with error");
                        }
                    }
                    break;
                }
                () = first_req_deadline.as_mut(), if first_req_timer_active => {
                    first_req_timer_active = false;
                    if !first_req_seen.load(Ordering::Acquire) {
                        warn!(
                            peer = %peer_addr,
                            timeout_ms = u64::try_from(header_timeout.as_millis()).unwrap_or(u64::MAX),
                            "closing slow/idle client connection before initial request"
                        );
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
                    info!(
                        peer = %peer_addr,
                        "closing oldest idle keep-alive connection of this address to free a per-IP slot"
                    );
                    conn.as_mut().graceful_shutdown();
                    // Chosen while idle, but a request or queued response data may have arrived
                    // since: then it gets the full drain time to finish, not half a second.
                    let drain = if idle_state.idle_since_ms() > 0 {
                        drain_timeout.min(Duration::from_millis(500))
                    } else {
                        drain_timeout
                    };
                    let _ = tokio::time::timeout(drain, conn.as_mut()).await;
                    break;
                }
                verdict = h2_watch(&h2_streams, &idle_state, &is_h2, write_idle, idle_timeout) => {
                    match verdict {
                        H2Verdict::Stalled(waited) => {
                            warn!(
                                peer = %peer_addr,
                                reason = "h2_stream_stalled",
                                waited_ms = u64::try_from(waited.as_millis()).unwrap_or(u64::MAX),
                                "closing HTTP/2 connection: a response stream made no progress (client flow-control window closed)"
                            );
                            conn.as_mut().graceful_shutdown();
                            // Streams that are still moving may finish; the stalled one cannot,
                            // so the connection is dropped when the drain time is over.
                            let _ = tokio::time::timeout(drain_timeout, conn.as_mut()).await;
                        }
                        H2Verdict::Idle => {
                            debug!(peer = %peer_addr, "closing idle HTTP/2 connection");
                            conn.as_mut().graceful_shutdown();
                            let _ = tokio::time::timeout(
                                drain_timeout.min(Duration::from_millis(500)),
                                conn.as_mut(),
                            )
                            .await;
                        }
                    }
                    break;
                }
                changed = bad_req_close_rx.changed() => {
                    if changed.is_ok() && *bad_req_close_rx.borrow() {
                        warn!(peer = %peer_addr, "draining and closing connection after excessive framing rejections or stream resets");
                        conn.as_mut().graceful_shutdown();
                        // R2-HTTP-2: Honor configured `graceful-drain` timeout so innocent
                        // in-flight H2 streams finish cleanly instead of being aborted early.
                        let _ = tokio::time::timeout(drain_timeout, conn.as_mut()).await;
                        break;
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        conn.as_mut().graceful_shutdown();
                        if let Err(err) = conn.await {
                            debug!(peer = %peer_addr, error = %err, "HTTP connection error during drain");
                        }
                        break;
                    }
                }
            }
        }
    }
}

/// Why the HTTP/2 watchdog asks for a connection to be closed.
enum H2Verdict {
    /// A response stream waited this long for the client with a writable socket.
    Stalled(Duration),
    /// No request has been in flight for `idle-keepalive`.
    Idle,
}

/// Watches one connection once it is known to speak HTTP/2 (it never resolves for HTTP/1.1).
///
/// While requests are in flight it checks the response streams on a timer
/// ([`h2_stall::H2StallRegistry::expire_stalled`]); while none are, it bounds the idle time by
/// `idle-keepalive`. hyper's HTTP/2 keep-alive pings only detect a dead peer: a client that
/// answers pings would otherwise keep an idle connection, and whatever a finished stream left
/// buffered for it, for ever.
async fn h2_watch(
    streams: &h2_stall::H2StallRegistry,
    idle_state: &ConnectionIdleState,
    is_h2: &AtomicBool,
    write_idle: Duration,
    idle_timeout: Duration,
) -> H2Verdict {
    let tick = (write_idle / 4).clamp(Duration::from_millis(25), Duration::from_secs(5));
    loop {
        if !is_h2.load(Ordering::Acquire) {
            streams.changed().await;
            continue;
        }
        // A body counts as produced once its last piece is handed to hyper, but hyper and the
        // HTTP/2 layer can still hold a good part of it, waiting for the client's flow-control
        // window (AmiraPanel staging: 134 to 231 KB unsent when a 3 KB/s download was closed as
        // idle). While DATA is still on its way the connection is neither idle nor a candidate
        // for per-IP eviction; idle time counts from when the last of it was written. Control
        // frames (keep-alive PING replies) do not count as delivery.
        // `idle_since_ms` is 0 while DATA is still on its way and otherwise counts from the
        // later of the last request and the last DATA written (see `attach_transport`).
        let idle_since = idle_state.idle_since_ms();
        if idle_since > 0 && !streams.has_open_streams() {
            let idle_for = Duration::from_millis(monotonic_idle_ms().saturating_sub(idle_since));
            if idle_for >= idle_timeout {
                return H2Verdict::Idle;
            }
            tokio::select! {
                () = tokio::time::sleep(idle_timeout.saturating_sub(idle_for).min(tick)) => {}
                () = streams.changed() => {}
            }
            continue;
        }
        tokio::time::sleep(tick).await;
        if let Some(waited) = streams.expire_stalled(write_idle) {
            return H2Verdict::Stalled(waited);
        }
    }
}

/// Deferred access-log state flushed when a streaming response body finishes or drops so
/// `bytes_sent` and `latency_us` reflect the actual end-of-response transfer.
/// Where access-log lines go when they are written directly (see [`set_access_log_sink`]).
pub type AccessLogSink = Box<dyn Fn(&[u8]) + Send + Sync>;

static ACCESS_LOG_SINK: OnceLock<AccessLogSink> = OnceLock::new();

/// Integration-test access-log sink callback type.
#[cfg(any(test, feature = "test-h2-hooks"))]
#[doc(hidden)]
pub type TestAccessLogSink = Arc<dyn Fn(&[u8]) + Send + Sync>;

#[cfg(any(test, feature = "test-h2-hooks"))]
static TEST_ACCESS_LOG_SINK: Mutex<Option<TestAccessLogSink>> = Mutex::new(None);

/// Integration-test RAII guard overriding the direct access-log sink until drop.
#[cfg(any(test, feature = "test-h2-hooks"))]
#[doc(hidden)]
pub struct TestAccessLogSinkOverrideGuard {
    prev: Option<TestAccessLogSink>,
}

#[cfg(any(test, feature = "test-h2-hooks"))]
impl Drop for TestAccessLogSinkOverrideGuard {
    fn drop(&mut self) {
        *TEST_ACCESS_LOG_SINK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = self.prev.take();
    }
}

/// Integration-test helper installing a replaceable direct access-log sink until drop.
#[cfg(any(test, feature = "test-h2-hooks"))]
#[doc(hidden)]
#[must_use]
pub fn test_access_log_sink_override_guard(
    sink: TestAccessLogSink,
) -> TestAccessLogSinkOverrideGuard {
    let prev = TEST_ACCESS_LOG_SINK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .replace(sink);
    TestAccessLogSinkOverrideGuard { prev }
}

/// Returns how many offloaded in-task HTTP/2 interrupted access-log records were dropped because
/// the bounded off-connection-task queue (approximate 1 MiB / 4,096 records) overflowed while
/// the log sink was stalled.
#[must_use]
pub fn offloaded_access_log_dropped() -> u64 {
    OFFLOAD_ACCESS_LOG_QUEUE.dropped_total()
}

enum OffloadAccessLogItem {
    FormattedLine {
        bytes: Vec<u8>,
        #[cfg(any(test, feature = "test-h2-hooks"))]
        test_sink: Option<TestAccessLogSink>,
    },
    TracingRecord {
        record: Box<AccessLogRecord>,
        bytes_sent: u64,
        body_complete: bool,
        delivery: TransportDelivery,
        completed: bool,
        msg: &'static str,
        latency_us: u64,
    },
}

impl offload_queue::OffloadLogItem for OffloadAccessLogItem {
    fn approx_bytes(&self) -> usize {
        match self {
            Self::FormattedLine { bytes, .. } => bytes.len(),
            Self::TracingRecord { record, .. } => record.strings.len().saturating_add(256),
        }
    }

    fn emit_now(self) {
        match self {
            Self::FormattedLine {
                bytes,
                #[cfg(any(test, feature = "test-h2-hooks"))]
                test_sink,
            } => {
                #[cfg(any(test, feature = "test-h2-hooks"))]
                if let Some(sink) = test_sink {
                    sink(&bytes);
                    return;
                }
                if let Some(sink) = ACCESS_LOG_SINK.get() {
                    sink(&bytes);
                }
            }
            Self::TracingRecord {
                record,
                bytes_sent,
                body_complete,
                delivery,
                completed,
                msg,
                latency_us,
            } => {
                record.emit_tracing_event(
                    bytes_sent,
                    body_complete,
                    delivery,
                    completed,
                    msg,
                    latency_us,
                );
            }
        }
    }
}

static OFFLOAD_ACCESS_LOG_QUEUE: std::sync::LazyLock<
    Arc<offload_queue::OffloadLogQueue<OffloadAccessLogItem>>,
> = std::sync::LazyLock::new(|| {
    offload_queue::OffloadLogQueue::new(
        offload_queue::MAX_OFFLOADED_LOG_BYTES,
        offload_queue::MAX_OFFLOADED_LOG_RECORDS,
        offload_queue::OFFLOAD_DROP_REPORT_INTERVAL,
        report_offloaded_access_log_drops,
    )
});

fn enqueue_offloaded_access_log(item: OffloadAccessLogItem) {
    OFFLOAD_ACCESS_LOG_QUEUE.enqueue(item);
}

fn report_offloaded_access_log_drops(dropped: u64) {
    use std::io::Write as _;
    let mut stderr = io::stderr().lock();
    let _ = writeln!(
        stderr,
        "miraserve: dropped {dropped} interrupted HTTP/2 access-log record(s) while the access-log sink was stalled"
    );
}

/// Blocks up to `deadline` until all offloaded interrupted HTTP/2 access-log records have been
/// handed to the access-log sink.
#[must_use]
pub fn flush_offloaded_access_logs_until_blocking(deadline: Instant) -> OffloadDrainOutcome {
    OFFLOAD_ACCESS_LOG_QUEUE.flush_until_blocking(deadline)
}

/// Blocks up to `timeout` (measured from the caller) until all offloaded interrupted HTTP/2
/// access-log records have been handed to the access-log sink. Returns `true` when drained
/// cleanly.
#[must_use]
pub fn flush_offloaded_access_logs_blocking(timeout: Duration) -> bool {
    let outcome = flush_offloaded_access_logs_until_blocking(Instant::now() + timeout);
    outcome.drained && outcome.remaining == 0
}

/// Awaits up to `deadline` (measured from the caller) until all offloaded interrupted HTTP/2
/// access-log records have been handed to the access-log sink.
#[must_use]
pub async fn flush_offloaded_access_logs_until(deadline: Instant) -> OffloadDrainOutcome {
    OFFLOAD_ACCESS_LOG_QUEUE.flush_until_async(deadline).await
}

/// Awaits up to `timeout` (measured from the caller) until all offloaded interrupted HTTP/2
/// access-log records have been handed to the access-log sink (intended for graceful async
/// shutdown). Returns `true` when drained cleanly.
pub async fn flush_offloaded_access_logs(timeout: Duration) -> bool {
    let outcome = flush_offloaded_access_logs_until(Instant::now() + timeout).await;
    outcome.drained && outcome.remaining == 0
}

/// Drains both offloaded log queues (interrupted HTTP/2 access records and runtime diagnostics)
/// under ONE shared `deadline` measured from the caller.
#[must_use]
pub async fn flush_offloaded_logs_until(deadline: Instant) -> OffloadLogDrainReport {
    let (access, diagnostic) = tokio::join!(
        flush_offloaded_access_logs_until(deadline),
        flush_offloaded_diagnostic_logs_until(deadline),
    );
    OffloadLogDrainReport {
        access_remaining: access.remaining,
        access_drained: access.drained,
        diagnostic_remaining: diagnostic.remaining,
        diagnostic_drained: diagnostic.drained,
        connections_forced_closed: false,
        workers_join_timed_out: false,
    }
}

/// Drains both offloaded log queues (interrupted HTTP/2 access records and runtime diagnostics)
/// under ONE shared `timeout` measured from the caller before any blocking-pool job starts.
#[must_use]
pub async fn flush_offloaded_logs(timeout: Duration) -> OffloadLogDrainReport {
    flush_offloaded_logs_until(Instant::now() + timeout).await
}

/// Synchronous counterpart to [`flush_offloaded_logs_until`], draining both offloaded log queues
/// under ONE shared `deadline`.
#[must_use]
pub fn flush_offloaded_logs_until_blocking(deadline: Instant) -> OffloadLogDrainReport {
    let access = flush_offloaded_access_logs_until_blocking(deadline);
    let diagnostic = flush_offloaded_diagnostic_logs_until_blocking(deadline);
    OffloadLogDrainReport {
        access_remaining: access.remaining,
        access_drained: access.drained,
        diagnostic_remaining: diagnostic.remaining,
        diagnostic_drained: diagnostic.drained,
        connections_forced_closed: false,
        workers_join_timed_out: false,
    }
}

thread_local! {
    /// Reused buffer for one access-log line.
    static ACCESS_LINE: std::cell::RefCell<String> = std::cell::RefCell::new(String::with_capacity(512));
}

/// Sends access-log lines straight to `sink`, formatted by MiraServe itself, instead of through
/// the general `tracing` formatter: the same text, byte for byte, at a fraction of the cost (the
/// generic formatter was about a tenth of the CPU time of a small static request). Lines are
/// still written only when INFO is enabled for `miraserve::access`. Returns `false` if a sink
/// was already set.
pub fn set_access_log_sink(sink: AccessLogSink) -> bool {
    ACCESS_LOG_SINK.set(sink).is_ok()
}

/// The values of an access-log line that are not stored in [`AccessLogRecord`].
#[derive(Clone, Copy)]
struct AccessLineFields<'a> {
    bytes_sent: u64,
    body_complete: bool,
    delivery: &'a str,
    completed: bool,
    latency_us: u64,
}

/// Appends `value` as `tracing`'s formatter writes a string field: quoted and escaped like
/// `Debug`. Printable ASCII without `"` and `\\` (the usual case) is copied as it is.
fn push_quoted(out: &mut String, value: &str) {
    use std::fmt::Write as _;
    if value
        .bytes()
        .all(|b| (0x20..0x7f).contains(&b) && b != b'"' && b != b'\\')
    {
        out.push('"');
        out.push_str(value);
        out.push('"');
    } else {
        let _ = write!(out, "{value:?}");
    }
}

fn push_u64(out: &mut String, mut value: u64) {
    let mut digits = [0_u8; 20];
    let mut at = digits.len();
    loop {
        at -= 1;
        if let Some(slot) = digits.get_mut(at) {
            *slot = b'0' + u8::try_from(value % 10).unwrap_or(0);
        }
        value /= 10;
        if value == 0 {
            break;
        }
    }
    for &d in digits.get(at..).unwrap_or(&[]) {
        out.push(char::from(d));
    }
}

fn push_padded(out: &mut String, mut value: u64, width: usize) {
    let mut digits = [b'0'; 20];
    let mut at = digits.len();
    loop {
        at -= 1;
        if let Some(slot) = digits.get_mut(at) {
            *slot = b'0' + u8::try_from(value % 10).unwrap_or(0);
        }
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let len = digits.len().saturating_sub(at);
    for _ in len..width {
        out.push('0');
    }
    for &d in digits.get(at..).unwrap_or(&[]) {
        out.push(char::from(d));
    }
}

/// `2026-11-22T04:46:31.112840Z`, as `tracing-subscriber`'s default timer writes it.
fn push_rfc3339_micros(out: &mut String, now: std::time::SystemTime) {
    let since = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = since.as_secs();
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    // Civil date from days since 1970-01-01 (H. Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let as_u64 = |v: i64| u64::try_from(v).unwrap_or(0);
    push_padded(out, as_u64(year), 4);
    out.push('-');
    push_padded(out, as_u64(month), 2);
    out.push('-');
    push_padded(out, as_u64(day), 2);
    out.push('T');
    push_padded(out, rem / 3_600, 2);
    out.push(':');
    push_padded(out, rem % 3_600 / 60, 2);
    out.push(':');
    push_padded(out, rem % 60, 2);
    out.push('.');
    push_padded(out, u64::from(since.subsec_micros()), 6);
    out.push('Z');
}

/// Inline formatted IP address (`Ipv4Addr` <= 15 bytes, `Ipv6Addr` <= 45 bytes), avoiding
/// per-request heap `String` allocations for `client_ip` and `peer_ip`.
#[derive(Clone, Copy)]
struct IpText {
    buf: [u8; 46],
    len: u8,
}

impl IpText {
    const EMPTY: Self = Self {
        buf: [0; 46],
        len: 0,
    };

    fn from_opt(ip: Option<IpAddr>) -> Self {
        use std::fmt::Write as _;
        let Some(ip) = ip else {
            return Self::EMPTY;
        };
        let mut out = Self::EMPTY;
        let _ = write!(&mut out, "{ip}");
        out
    }

    fn as_str(&self) -> &str {
        let n = usize::from(self.len);
        self.buf
            .get(..n)
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .unwrap_or("")
    }
}

impl std::fmt::Write for IpText {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let start = usize::from(self.len);
        let end = start.saturating_add(s.len());
        let Some(dst) = self.buf.get_mut(start..end) else {
            return Err(std::fmt::Error);
        };
        dst.copy_from_slice(s.as_bytes());
        self.len = u8::try_from(end).map_err(|_| std::fmt::Error)?;
        Ok(())
    }
}

impl std::fmt::Display for IpText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Inline byte capacity for [`AccessLogStrings`] (fits minimal and 12-header browser requests
/// including a full User-Agent and Referer without heap allocation; longer lines spill to `Heap`).
const ACCESS_LOG_INLINE_CAP: usize = 192;

/// Independently owned, already redacted and escaped string fields of an [`AccessLogRecord`]
/// packed into a single inline buffer when `<= 192` bytes (zero heap allocations on the common
/// path) or a single contiguous `String` when longer.
enum AccessLogStrings {
    Inline {
        buf: [u8; ACCESS_LOG_INLINE_CAP],
        host_end: u8,
        target_end: u8,
        ua_end: u8,
        len: u8,
    },
    Heap {
        buf: String,
        host_end: usize,
        target_end: usize,
        ua_end: usize,
    },
}

impl AccessLogStrings {
    fn from_raw_parts(
        raw_host: Option<&str>,
        raw_target: &str,
        raw_ua: Option<&str>,
        raw_referer: Option<&str>,
        redact_logs: bool,
    ) -> Self {
        let target_cow = if redact_logs {
            redact_request_target_cow(raw_target)
        } else {
            escape_log_controls_cow(raw_target)
        };
        let host_cow = raw_host.map_or(Cow::Borrowed(""), |raw| {
            // Never the user and password of an authority (such a request is refused, but
            // it is logged).
            let raw = raw.rsplit_once('@').map_or(raw, |(_, host)| host);
            escape_log_controls_cow(raw)
        });
        let host_slice = if host_cow.len() > 255 {
            let mut cut = 255;
            while !host_cow.is_char_boundary(cut) {
                cut = cut.saturating_sub(1);
            }
            host_cow.get(..cut).unwrap_or("")
        } else {
            host_cow.as_ref()
        };
        let referer_cow = raw_referer.map_or(Cow::Borrowed(""), |raw| {
            if redact_logs {
                redact_uri_query_cow(raw)
            } else {
                escape_log_controls_cow(raw)
            }
        });
        let ua_cow = raw_ua.map_or(Cow::Borrowed(""), |raw| {
            if redact_logs {
                redact_header_value_cow(&http::header::USER_AGENT, raw)
            } else {
                escape_log_controls_cow(raw)
            }
        });

        let host_len = host_slice.len();
        let target_len = target_cow.len();
        let ua_len = ua_cow.len();
        let referer_len = referer_cow.len();
        let total_len = host_len
            .saturating_add(target_len)
            .saturating_add(ua_len)
            .saturating_add(referer_len);
        if total_len <= ACCESS_LOG_INLINE_CAP
            && let (Ok(host_end), Ok(target_end), Ok(ua_end), Ok(len)) = (
                u8::try_from(host_len),
                u8::try_from(host_len + target_len),
                u8::try_from(host_len + target_len + ua_len),
                u8::try_from(total_len),
            )
        {
            let mut buf = [0_u8; ACCESS_LOG_INLINE_CAP];
            let h_end = usize::from(host_end);
            let t_end = usize::from(target_end);
            let u_end = usize::from(ua_end);
            let total = usize::from(len);
            if let Some(dst) = buf.get_mut(..h_end) {
                dst.copy_from_slice(host_slice.as_bytes());
                // ASCII lowercasing preserves byte length and UTF-8 char boundaries.
                dst.make_ascii_lowercase();
            }
            if let Some(dst) = buf.get_mut(h_end..t_end) {
                dst.copy_from_slice(target_cow.as_bytes());
            }
            if let Some(dst) = buf.get_mut(t_end..u_end) {
                dst.copy_from_slice(ua_cow.as_bytes());
            }
            if let Some(dst) = buf.get_mut(u_end..total) {
                dst.copy_from_slice(referer_cow.as_bytes());
            }
            return Self::Inline {
                buf,
                host_end,
                target_end,
                ua_end,
                len,
            };
        }

        let mut buf = String::with_capacity(total_len);
        buf.push_str(host_slice);
        // ASCII lowercasing preserves byte length and UTF-8 char boundaries.
        buf.make_ascii_lowercase();
        let host_end = buf.len();
        buf.push_str(target_cow.as_ref());
        let target_end = buf.len();
        buf.push_str(ua_cow.as_ref());
        let ua_end = buf.len();
        buf.push_str(referer_cow.as_ref());
        Self::Heap {
            buf,
            host_end,
            target_end,
            ua_end,
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Inline { len, .. } => usize::from(*len),
            Self::Heap { buf, .. } => buf.len(),
        }
    }

    fn host(&self) -> &str {
        match self {
            Self::Inline { buf, host_end, .. } => buf
                .get(..usize::from(*host_end))
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .unwrap_or(""),
            Self::Heap { buf, host_end, .. } => buf.get(..*host_end).unwrap_or(""),
        }
    }

    fn target(&self) -> &str {
        match self {
            Self::Inline {
                buf,
                host_end,
                target_end,
                ..
            } => buf
                .get(usize::from(*host_end)..usize::from(*target_end))
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .unwrap_or(""),
            Self::Heap {
                buf,
                host_end,
                target_end,
                ..
            } => buf.get(*host_end..*target_end).unwrap_or(""),
        }
    }

    fn user_agent(&self) -> &str {
        match self {
            Self::Inline {
                buf,
                target_end,
                ua_end,
                ..
            } => buf
                .get(usize::from(*target_end)..usize::from(*ua_end))
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .unwrap_or(""),
            Self::Heap {
                buf,
                target_end,
                ua_end,
                ..
            } => buf.get(*target_end..*ua_end).unwrap_or(""),
        }
    }

    fn referer(&self) -> &str {
        match self {
            Self::Inline {
                buf, ua_end, len, ..
            } => buf
                .get(usize::from(*ua_end)..usize::from(*len))
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .unwrap_or(""),
            Self::Heap { buf, ua_end, .. } => buf.get(*ua_end..).unwrap_or(""),
        }
    }
}

struct AccessLogRecord {
    started: Instant,
    /// Owned handle used only when not attached to a per-connection `ConnWriteTracker`
    /// (direct `handle_request` / HTTP/3). Hyper H1/H2 connections reuse the single
    /// `Arc<TelemetryRegistry>` held by `ConnWriteTracker` without cloning per request.
    telemetry: Option<Arc<TelemetryRegistry>>,
    request_id: pages::RequestId,
    proto: &'static str,
    scheme: &'static str,
    method: Method,
    strings: AccessLogStrings,
    status: u16,
    client_ip: IpText,
    peer_ip: IpText,
    redacted: bool,
}

/// Per-stream transport delivery observation recorded in access logs (Codex G8 & Round-4 P2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportDelivery {
    /// Per-stream transport flush/finish was explicitly observed (`h1` flush, `h3` stream finish,
    /// or direct in-process `handle_request`).
    Confirmed,
    /// Body reached EOF and the multiplexed `h2` connection flushed, but per-stream `END_STREAM`
    /// delivery vs. post-EOF `RST_STREAM` is not exposed by `hyper`'s HTTP/2 transport.
    UnconfirmedMultiplexed,
    /// Body production errored/truncated, transport write/flush failed, or connection/stream was
    /// cancelled before transport confirmation.
    Failed,
}

impl TransportDelivery {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::UnconfirmedMultiplexed => "unconfirmed_multiplexed",
            Self::Failed => "failed",
        }
    }
}

impl AccessLogRecord {
    /// Formats one line exactly as `tracing-subscriber`'s `fmt` layer formats the equivalent
    /// `info!` event (target hidden, no colours). Checked byte for byte by a test.
    fn format_line(
        &self,
        out: &mut String,
        now: std::time::SystemTime,
        msg: &str,
        fields: AccessLineFields<'_>,
    ) {
        let flag = |b: bool| if b { "true" } else { "false" };
        push_rfc3339_micros(out, now);
        out.push_str("  INFO ");
        out.push_str(msg);
        out.push_str(" request_id=");
        out.push_str(self.request_id.as_str());
        out.push_str(" proto=");
        push_quoted(out, self.proto);
        out.push_str(" host=");
        push_quoted(out, self.strings.host());
        out.push_str(" method=");
        push_quoted(out, self.method.as_str());
        out.push_str(" target=");
        push_quoted(out, self.strings.target());
        out.push_str(" status=");
        push_u64(out, u64::from(self.status));
        out.push_str(" bytes_sent=");
        push_u64(out, fields.bytes_sent);
        out.push_str(" body_complete=");
        out.push_str(flag(fields.body_complete));
        out.push_str(" transport_delivery=");
        push_quoted(out, fields.delivery);
        out.push_str(" completed=");
        out.push_str(flag(fields.completed));
        out.push_str(" latency_us=");
        push_u64(out, fields.latency_us);
        out.push_str(" client_ip=");
        out.push_str(self.client_ip.as_str());
        out.push_str(" peer_ip=");
        out.push_str(self.peer_ip.as_str());
        out.push_str(" user_agent=");
        push_quoted(out, self.strings.user_agent());
        out.push_str(" referer=");
        push_quoted(out, self.strings.referer());
        out.push_str(" redacted=");
        out.push_str(flag(self.redacted));
        // Keep HTTPS lines byte-for-byte identical to v0.1.2; emit `scheme="http"` on plain HTTP.
        if self.scheme != "https" {
            out.push_str(" scheme=");
            push_quoted(out, self.scheme);
        }
        out.push('\n');
    }

    fn emit(
        self,
        fallback_telemetry: Option<&TelemetryRegistry>,
        bytes_sent: u64,
        body_complete: bool,
        delivery: TransportDelivery,
    ) {
        let elapsed = self.started.elapsed();
        if let Some(telemetry) = self.telemetry.as_deref().or(fallback_telemetry) {
            telemetry.record_http_request(self.proto, self.status, elapsed);
        }
        // `completed` means the whole response body was produced and handed to the transport
        // without a write error. On a multiplexed HTTP/2 connection the server cannot observe
        // delivery per stream; that uncertainty is carried by
        // `transport_delivery="unconfirmed_multiplexed"`, not by reporting every successful
        // HTTP/2 request as incomplete (which made `completed` useless for statistics).
        let completed = body_complete && delivery != TransportDelivery::Failed;
        let msg = if completed {
            "http request completed"
        } else {
            "http request interrupted"
        };
        let latency_us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        let now = std::time::SystemTime::now();
        let offload = miraserve_static::in_nonblocking_inline_context();
        #[cfg(any(test, feature = "test-h2-hooks"))]
        let test_sink = TEST_ACCESS_LOG_SINK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        #[cfg(any(test, feature = "test-h2-hooks"))]
        let has_direct_sink = test_sink.is_some() || ACCESS_LOG_SINK.get().is_some();
        #[cfg(not(any(test, feature = "test-h2-hooks")))]
        let has_direct_sink = ACCESS_LOG_SINK.get().is_some();

        // The direct writer produces exactly the tracing formatter's line when no span is
        // entered (the server enters none) and the clock is after 1970; otherwise the line
        // goes through tracing, which prints span context and signed pre-1970 dates.
        if has_direct_sink
            && tracing::enabled!(target: "miraserve::access", tracing::Level::INFO)
            && now >= std::time::UNIX_EPOCH
            && tracing::Span::current().is_none()
        {
            let offloaded_bytes = ACCESS_LINE.with(|cell| {
                let mut line = cell.borrow_mut();
                line.clear();
                self.format_line(
                    &mut line,
                    now,
                    msg,
                    AccessLineFields {
                        bytes_sent,
                        body_complete,
                        delivery: delivery.as_str(),
                        completed,
                        latency_us,
                    },
                );
                if offload {
                    return Some(line.as_bytes().to_vec());
                }
                #[cfg(any(test, feature = "test-h2-hooks"))]
                if let Some(sink) = test_sink.as_ref() {
                    sink(line.as_bytes());
                    return None;
                }
                if let Some(sink) = ACCESS_LOG_SINK.get() {
                    sink(line.as_bytes());
                }
                None
            });
            if let Some(bytes) = offloaded_bytes {
                enqueue_offloaded_access_log(OffloadAccessLogItem::FormattedLine {
                    bytes,
                    #[cfg(any(test, feature = "test-h2-hooks"))]
                    test_sink,
                });
            }
            return;
        }
        if offload {
            if !tracing::enabled!(target: "miraserve::access", tracing::Level::INFO) {
                return;
            }
            enqueue_offloaded_access_log(OffloadAccessLogItem::TracingRecord {
                record: Box::new(self),
                bytes_sent,
                body_complete,
                delivery,
                completed,
                msg,
                latency_us,
            });
            return;
        }
        self.emit_tracing_event(
            bytes_sent,
            body_complete,
            delivery,
            completed,
            msg,
            latency_us,
        );
    }

    fn emit_tracing_event(
        self,
        bytes_sent: u64,
        body_complete: bool,
        delivery: TransportDelivery,
        completed: bool,
        msg: &'static str,
        latency_us: u64,
    ) {
        if self.scheme == "https" {
            info!(
                target: "miraserve::access",
                request_id = %self.request_id,
                proto = self.proto,
                // Client-supplied text is recorded as string values, not `Display`: the log
                // formatter then quotes and escapes them, so a header such as
                // `User-Agent: x status=500 host=victim` cannot forge fields for a log parser.
                host = self.strings.host(),
                method = self.method.as_str(),
                target = self.strings.target(),
                status = self.status,
                bytes_sent,
                body_complete,
                transport_delivery = delivery.as_str(),
                completed,
                latency_us,
                client_ip = %self.client_ip,
                peer_ip = %self.peer_ip,
                user_agent = self.strings.user_agent(),
                referer = self.strings.referer(),
                redacted = self.redacted,
                "{msg}"
            );
        } else {
            info!(
                target: "miraserve::access",
                request_id = %self.request_id,
                proto = self.proto,
                host = self.strings.host(),
                method = self.method.as_str(),
                target = self.strings.target(),
                status = self.status,
                bytes_sent,
                body_complete,
                transport_delivery = delivery.as_str(),
                completed,
                latency_us,
                client_ip = %self.client_ip,
                peer_ip = %self.peer_ip,
                user_agent = self.strings.user_agent(),
                referer = self.strings.referer(),
                redacted = self.redacted,
                scheme = self.scheme,
                "{msg}"
            );
        }
    }
}

/// Upper bound on the size of the future hyper gets for one request.
///
/// On HTTP/2, hyper moves that future by value through `H2Stream::new` into `InTaskExec::execute`
/// before boxing it into `Driven`'s `FuturesUnordered` (and formerly into a spawned Tokio task).
/// With the request pipeline's state machine inline it was about 10 KiB, so every HTTP/2 request
/// copied tens of kilobytes on entry (measured with a probe on `memmove`: 23% of the server's CPU
/// time at 64 connections x 10 streams). The pipeline's future is therefore boxed inside the
/// service future: one allocation and one copy per request, and the moves copy only what is left.
const SERVICE_FUTURE_MAX_BYTES: usize = 2048;

const TRANSPORT_OUTCOME_PENDING: u8 = 0;
const TRANSPORT_OUTCOME_COMPLETED: u8 = 1;
const TRANSPORT_OUTCOME_FAILED: u8 = 2;
const TRANSPORT_OUTCOME_AWAITING_FINISH: u8 = 3;

struct PendingAccessLog {
    record: AccessLogRecord,
    bytes_sent: u64,
    body_complete: bool,
}

/// Shared transport-write state for a single H1/H2 connection (`WriteOutcomeIo`), deferring
/// final `completed=true` emission until the socket flush succeeds on HTTP/1.1, distinguishing
/// multiplexed HTTP/2 connection flushes (`transport_delivery="unconfirmed_multiplexed"`), and
/// turning any final write, flush error, or unconfirmed cancellation into `failed` (Codex G8).
struct ConnWriteTracker {
    telemetry: Arc<TelemetryRegistry>,
    write_failed: AtomicBool,
    pending_logs: Mutex<Vec<PendingAccessLog>>,
}

impl ConnWriteTracker {
    const fn new(telemetry: Arc<TelemetryRegistry>) -> Self {
        Self {
            telemetry,
            write_failed: AtomicBool::new(false),
            pending_logs: Mutex::new(Vec::new()),
        }
    }

    fn telemetry(&self) -> &TelemetryRegistry {
        &self.telemetry
    }

    fn is_failed(&self) -> bool {
        self.write_failed.load(Ordering::Acquire)
    }

    fn enqueue_or_emit_failed(
        &self,
        record: AccessLogRecord,
        bytes_sent: u64,
        body_complete: bool,
    ) {
        if self.is_failed() {
            record.emit(
                Some(&self.telemetry),
                bytes_sent,
                body_complete,
                TransportDelivery::Failed,
            );
            return;
        }
        if let Ok(mut pending) = self.pending_logs.lock() {
            if self.is_failed() {
                drop(pending);
                record.emit(
                    Some(&self.telemetry),
                    bytes_sent,
                    body_complete,
                    TransportDelivery::Failed,
                );
            } else {
                pending.push(PendingAccessLog {
                    record,
                    bytes_sent,
                    body_complete,
                });
            }
        } else {
            record.emit(
                Some(&self.telemetry),
                bytes_sent,
                body_complete,
                TransportDelivery::Failed,
            );
        }
    }

    fn mark_flushed(&self, scratch: &mut Vec<PendingAccessLog>) {
        let transport_ok = !self.is_failed();
        scratch.clear();
        if let Ok(mut pending) = self.pending_logs.lock()
            && !pending.is_empty()
        {
            std::mem::swap(&mut *pending, scratch);
        }
        for entry in scratch.drain(..) {
            let delivery = if !transport_ok || !entry.body_complete {
                TransportDelivery::Failed
            } else if entry.record.proto == "h2" {
                // Codex Round-4 P2 #3 (G8): On multiplexed HTTP/2, a connection-wide socket flush
                // does not confirm per-stream `END_STREAM` delivery or rule out a post-EOF reset.
                TransportDelivery::UnconfirmedMultiplexed
            } else {
                TransportDelivery::Confirmed
            };
            entry.record.emit(
                Some(&self.telemetry),
                entry.bytes_sent,
                entry.body_complete,
                delivery,
            );
        }
    }

    fn mark_failed(&self) {
        self.write_failed.store(true, Ordering::Release);
        let drained = self
            .pending_logs
            .lock()
            .map(|mut pending| std::mem::take(&mut *pending))
            .unwrap_or_default();
        for entry in drained {
            entry.record.emit(
                Some(&self.telemetry),
                entry.bytes_sent,
                entry.body_complete,
                TransportDelivery::Failed,
            );
        }
    }
}

/// Thin `AsyncRead`/`AsyncWrite` wrapper feeding transport write/flush outcomes into
/// [`ConnWriteTracker`] so failed final writes or cancelled pending writes never log
/// `completed=true` (Codex G8).
/// Enforces the two waiting phases of an HTTP/1.1 keep-alive connection separately:
///
/// - **idle** (`timeouts.idle-keepalive`): from the moment the connection is between requests
///   with nothing left to flush, until the first byte of the next request;
/// - **head** (`timeouts.header-read`): from the first byte of a request head until the
///   request reaches the service. A client that starts a head and stalls (Slowloris) is cut
///   after `header-read`, and a head that starts late in the idle phase still gets the whole
///   `header-read` budget.
///
/// hyper's own head timer cannot tell the phases apart (it runs from the start of the wait to
/// the end of the head), so it is set to `idle-keepalive + header-read`, the longest a correct
/// client can take, and only acts as a backstop.
///
/// Bytes of a pipelined request that arrive while the previous response is still being produced
/// are read "in flight" and do not start the head phase; such a connection is then held to the
/// idle limit, which is what a client sending nothing at all is allowed anyway.
///
/// Nothing here applies to HTTP/2 connections (their frames arrive while "idle"; the
/// connection loop bounds their idle time) or to upgraded connections.
struct HeadDeadlineIo<I> {
    inner: I,
    idle_state: Arc<ConnectionIdleState>,
    is_h2: Arc<AtomicBool>,
    head_in_progress: Arc<AtomicBool>,
    header_timeout: Duration,
    idle_timeout: Duration,
    phase: WaitPhase,
    /// Bytes were written since the last completed flush: the previous response is not out yet.
    unflushed: bool,
    /// Tells the HTTP/2 stream watchdog whether the socket is currently blocked.
    transport: Arc<h2_stall::TransportWriteState>,
    /// Counts requests handed to the service on this connection.
    dispatched: Arc<AtomicU64>,
    /// Value of `dispatched` when the current phase was armed.
    phase_generation: u64,
    /// Counts the DATA payload of the HTTP/2 frames written (see `h2_stall`).
    data_frames: h2_stall::DataFrameCounter,
    /// Counts the `RST_STREAM` frames read, against the connection's limit.
    reset_frames: h2_stall::ResetFrameCounter,
    reset_guard: Option<(Arc<ConnectionFloodGuard>, watch::Sender<bool>)>,
}

/// Which deadline a connection between requests is running against.
enum WaitPhase {
    /// A request is in flight, or nothing is armed yet.
    None,
    /// Waiting for the first byte of the next request.
    Idle(Pin<Box<tokio::time::Sleep>>),
    /// A request head has started.
    Head(Pin<Box<tokio::time::Sleep>>),
}

impl<I> HeadDeadlineIo<I> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        inner: I,
        idle_state: Arc<ConnectionIdleState>,
        is_h2: Arc<AtomicBool>,
        head_in_progress: Arc<AtomicBool>,
        header_timeout: Duration,
        idle_timeout: Duration,
        transport: Arc<h2_stall::TransportWriteState>,
        dispatched: Arc<AtomicU64>,
    ) -> Self {
        Self {
            inner,
            idle_state,
            is_h2,
            head_in_progress,
            header_timeout,
            idle_timeout,
            phase: WaitPhase::None,
            unflushed: false,
            transport,
            dispatched,
            phase_generation: 0,
            data_frames: h2_stall::DataFrameCounter::default(),
            reset_frames: h2_stall::ResetFrameCounter::default(),
            reset_guard: None,
        }
    }

    /// Counts the client's `RST_STREAM` frames against `guard`; `close` asks for the connection
    /// to be closed when there are too many.
    fn counting_resets(
        mut self,
        guard: Arc<ConnectionFloodGuard>,
        close: watch::Sender<bool>,
    ) -> Self {
        self.reset_guard = Some((guard, close));
        self
    }

    /// What was read into `buf` after its first `before` bytes.
    fn note_read(&mut self, buf: &tokio::io::ReadBuf<'_>, before: usize) {
        let Some((guard, close)) = &self.reset_guard else {
            return;
        };
        let resets = self
            .reset_frames
            .feed(buf.filled().get(before..).unwrap_or(&[]));
        for _ in 0..resets {
            if !guard.record_stream_reset() {
                let _ = close.send(true);
            }
        }
    }

    /// Drops a waiting phase that belongs to an earlier request.
    ///
    /// hyper can read a whole request plus the start of the next one in a single read and then
    /// not read again while it writes a slow response. The head deadline armed for the first
    /// request would still be standing when parsing resumes, possibly already expired, and
    /// would be charged to the next request. A request reaching the service ends its phase for
    /// good; the next phase is armed afresh after the response is flushed.
    fn drop_stale_phase(&mut self) {
        let generation = self.dispatched.load(Ordering::Acquire);
        if generation != self.phase_generation {
            self.phase_generation = generation;
            if !matches!(self.phase, WaitPhase::None) {
                self.phase = WaitPhase::None;
                self.head_in_progress.store(false, Ordering::Release);
            }
        }
    }

    /// Records a write's outcome; `written` are the bytes the socket accepted, in order.
    fn note_write_result<'b>(
        &mut self,
        res: &Poll<io::Result<usize>>,
        written: impl Iterator<Item = &'b [u8]>,
    ) {
        match res {
            Poll::Pending => self.transport.mark_blocked(),
            Poll::Ready(Ok(n)) => {
                self.transport.mark_writable();
                let mut left = *n;
                let mut data = 0_u64;
                for chunk in written {
                    if left == 0 {
                        break;
                    }
                    let take = chunk.len().min(left);
                    data = data
                        .saturating_add(self.data_frames.feed(chunk.get(..take).unwrap_or(&[])));
                    left -= take;
                }
                self.transport.add_data_written(data);
            }
            Poll::Ready(Err(_)) => {}
        }
    }

    fn note_flush_result(&self, res: &Poll<io::Result<()>>) {
        match res {
            Poll::Pending => self.transport.mark_blocked(),
            Poll::Ready(Ok(())) => self.transport.mark_writable(),
            Poll::Ready(Err(_)) => {}
        }
    }

    fn tracks_phases(&self) -> bool {
        !self.is_h2.load(Ordering::Acquire)
    }

    /// Starts the idle phase once the connection is between requests and fully flushed.
    fn arm_idle_if_waiting(&mut self, cx: &mut Context<'_>) {
        if matches!(self.phase, WaitPhase::None)
            && !self.unflushed
            && self.idle_state.idle_since_ms() > 0
        {
            let mut timer = Box::pin(tokio::time::sleep(self.idle_timeout));
            // Register the waker so the connection is polled again at the deadline.
            let _ = timer.as_mut().poll(cx);
            self.phase = WaitPhase::Idle(timer);
        }
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for HeadDeadlineIo<I> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.tracks_phases() {
            let before = buf.filled().len();
            let res = Pin::new(&mut this.inner).poll_read(cx, buf);
            this.note_read(buf, before);
            return res;
        }
        this.drop_stale_phase();
        let between_requests = this.idle_state.idle_since_ms() > 0;
        if between_requests {
            this.arm_idle_if_waiting(cx);
            let expired = match &mut this.phase {
                WaitPhase::Idle(timer) => timer
                    .as_mut()
                    .poll(cx)
                    .is_ready()
                    .then_some("idle keep-alive timeout elapsed (idle-keepalive)"),
                WaitPhase::Head(timer) => timer
                    .as_mut()
                    .poll(cx)
                    .is_ready()
                    .then_some("request header read timeout elapsed (header-read)"),
                WaitPhase::None => None,
            };
            if let Some(message) = expired {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, message)));
            }
        } else if !matches!(this.phase, WaitPhase::None) {
            // The request reached the service: neither waiting phase applies any more.
            this.phase = WaitPhase::None;
            this.head_in_progress.store(false, Ordering::Release);
        }
        let before = buf.filled().len();
        let res = Pin::new(&mut this.inner).poll_read(cx, buf);
        if between_requests
            && !matches!(this.phase, WaitPhase::Head(_))
            && matches!(res, Poll::Ready(Ok(())))
            && buf.filled().len() > before
        {
            let mut timer = Box::pin(tokio::time::sleep(this.header_timeout));
            let _ = timer.as_mut().poll(cx);
            this.phase = WaitPhase::Head(timer);
            this.head_in_progress.store(true, Ordering::Release);
        }
        // The preface and the first frames arrive before the connection is known to be HTTP/2.
        this.note_read(buf, before);
        res
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for HeadDeadlineIo<I> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let res = Pin::new(&mut this.inner).poll_write(cx, buf);
        this.note_write_result(&res, std::iter::once(buf));
        if matches!(res, Poll::Ready(Ok(n)) if n > 0) {
            this.unflushed = true;
        }
        res
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let res = Pin::new(&mut this.inner).poll_flush(cx);
        this.note_flush_result(&res);
        if matches!(res, Poll::Ready(Ok(()))) {
            this.unflushed = false;
            if this.tracks_phases() {
                this.drop_stale_phase();
                // The last response is out: the idle phase starts here, not while its tail was
                // still being delivered to a slow reader.
                this.arm_idle_if_waiting(cx);
            }
        }
        res
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let res = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        this.note_write_result(&res, bufs.iter().map(|b| &**b));
        if matches!(res, Poll::Ready(Ok(n)) if n > 0) {
            this.unflushed = true;
        }
        res
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

struct WriteOutcomeIo<I> {
    inner: I,
    tracker: Arc<ConnWriteTracker>,
    pending_scratch: Vec<PendingAccessLog>,
}

impl<I> WriteOutcomeIo<I> {
    fn new(inner: I, tracker: Arc<ConnWriteTracker>) -> Self {
        Self {
            inner,
            tracker,
            pending_scratch: Vec::new(),
        }
    }
}

impl<I> Drop for WriteOutcomeIo<I> {
    fn drop(&mut self) {
        // Codex Round-3 P2 #3 (G8): Any access-log record still pending when the transport IO
        // drops was NEVER confirmed flushed by `poll_flush`/`poll_shutdown` (for example, the
        // connection task was cancelled while `poll_write` was `Poll::Pending` or a drain timeout
        // aborted the connection). Fail closed and emit `completed=false` rather than falsely
        // logging `completed=true`.
        self.tracker.mark_failed();
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for WriteOutcomeIo<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for WriteOutcomeIo<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write(cx, buf);
        if matches!(res, Poll::Ready(Err(_))) {
            self.tracker.mark_failed();
        }
        res
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if matches!(res, Poll::Ready(Err(_))) {
            self.tracker.mark_failed();
        }
        res
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let res = Pin::new(&mut this.inner).poll_flush(cx);
        match &res {
            Poll::Ready(Ok(())) => this.tracker.mark_flushed(&mut this.pending_scratch),
            Poll::Ready(Err(_)) => this.tracker.mark_failed(),
            Poll::Pending => {}
        }
        res
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let res = Pin::new(&mut this.inner).poll_shutdown(cx);
        match &res {
            Poll::Ready(Ok(())) => this.tracker.mark_flushed(&mut this.pending_scratch),
            Poll::Ready(Err(_)) => this.tracker.mark_failed(),
            Poll::Pending => {}
        }
        res
    }
}

struct TransportOutcomeInner {
    state: AtomicU8,
    conn_writer: OnceLock<Arc<ConnWriteTracker>>,
}

/// Shared transport completion hook attached to response extensions so HTTP/3 and direct
/// [`HttpEngine::handle_request`] callers feed final write/flush/finish outcomes into
/// [`AccessLogBody`] (Codex G8).
#[derive(Clone)]
pub(crate) struct TransportOutcome {
    inner: Arc<TransportOutcomeInner>,
}

impl TransportOutcome {
    fn new() -> Self {
        Self {
            inner: Arc::new(TransportOutcomeInner {
                state: AtomicU8::new(TRANSPORT_OUTCOME_PENDING),
                conn_writer: OnceLock::new(),
            }),
        }
    }

    pub(crate) fn mark_awaiting_finish(&self) {
        let _ = self.inner.state.compare_exchange(
            TRANSPORT_OUTCOME_PENDING,
            TRANSPORT_OUTCOME_AWAITING_FINISH,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    pub(crate) fn mark_completed(&self) {
        let mut cur = self.inner.state.load(Ordering::Acquire);
        while matches!(
            cur,
            TRANSPORT_OUTCOME_PENDING | TRANSPORT_OUTCOME_AWAITING_FINISH
        ) {
            match self.inner.state.compare_exchange(
                cur,
                TRANSPORT_OUTCOME_COMPLETED,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(next) => cur = next,
            }
        }
    }

    pub(crate) fn mark_failed(&self) {
        self.inner
            .state
            .store(TRANSPORT_OUTCOME_FAILED, Ordering::Release);
    }

    fn conn_writer(&self) -> Option<&Arc<ConnWriteTracker>> {
        self.inner.conn_writer.get()
    }

    fn state(&self) -> u8 {
        self.inner.state.load(Ordering::Acquire)
    }

    fn is_explicitly_failed(&self) -> bool {
        self.inner.state.load(Ordering::Acquire) == TRANSPORT_OUTCOME_FAILED
            || self
                .inner
                .conn_writer
                .get()
                .is_some_and(|wt| wt.is_failed())
    }
}

/// Tracks response body bytes yielded to the HTTP transport (`hyper` / `h3`), tracks per-request
/// in-flight idle state on hyper connections, and defers access-log emission until the transport
/// finishes flushing or fails (Codex G8).
///
/// `bytes_sent` reports body bytes produced and handed to the transport before completion or
/// disconnect, `body_complete` reports per-stream body production completeness (exact even on
/// multiplexed HTTP/2 connections), and `completed` distinguishes clean transport delivery
/// (`true`) from body errors, premature drops, cancellation, or failed final transport writes
/// (`false`).
pub(crate) struct AccessLogBody {
    inner: PipeRespBody,
    bytes_sent: u64,
    stream_eof: bool,
    body_errored: bool,
    conn_writer: Option<Arc<ConnWriteTracker>>,
    transport_outcome: Option<TransportOutcome>,
    idle_state: Option<Arc<ConnectionIdleState>>,
    record: Option<AccessLogRecord>,
}

impl AccessLogBody {
    fn attach_idle_state(&mut self, idle_state: Arc<ConnectionIdleState>) {
        self.idle_state = Some(idle_state);
    }

    fn finish_idle(&mut self) {
        if let Some(st) = self.idle_state.take() {
            st.exit_request();
        }
    }

    fn finish_now(&mut self, body_complete: bool, delivery: TransportDelivery) {
        if let Some(rec) = self.record.take() {
            let conn_writer = self.conn_writer.as_ref().or_else(|| {
                self.transport_outcome
                    .as_ref()
                    .and_then(TransportOutcome::conn_writer)
            });
            rec.emit(
                conn_writer.map(|wt| wt.telemetry()),
                self.bytes_sent,
                body_complete,
                delivery,
            );
        }
    }
}

impl Drop for AccessLogBody {
    fn drop(&mut self) {
        // Release in-flight request count first, matching the drop order when
        // `InFlightResponseBody` wrapped `AccessLogBody`.
        self.finish_idle();
        let Some(rec) = self.record.take() else {
            return;
        };
        let body_exhausted =
            !self.body_errored && (self.stream_eof || http_body::Body::is_end_stream(&self.inner));
        let conn_writer = self.conn_writer.as_ref().or_else(|| {
            self.transport_outcome
                .as_ref()
                .and_then(TransportOutcome::conn_writer)
        });
        let explicitly_failed = conn_writer.is_some_and(|wt| wt.is_failed())
            || self
                .transport_outcome
                .as_ref()
                .is_some_and(TransportOutcome::is_explicitly_failed);
        if !body_exhausted || explicitly_failed {
            rec.emit(
                conn_writer.map(|wt| wt.telemetry()),
                self.bytes_sent,
                body_exhausted,
                TransportDelivery::Failed,
            );
            return;
        }
        // On H1/H2 connections wrapped by `WriteOutcomeIo`, defer emission until the socket
        // flushes the final buffered bytes (or fails writing them) so a broken pipe or
        // cancellation during the final write accurately records `completed=false`!
        if let Some(wt) = conn_writer {
            wt.enqueue_or_emit_failed(rec, self.bytes_sent, true);
            return;
        }
        let delivery = if matches!(
            self.transport_outcome
                .as_ref()
                .map_or(TRANSPORT_OUTCOME_PENDING, TransportOutcome::state),
            TRANSPORT_OUTCOME_COMPLETED | TRANSPORT_OUTCOME_PENDING
        ) {
            TransportDelivery::Confirmed
        } else {
            TransportDelivery::Failed
        };
        rec.emit(None, self.bytes_sent, true, delivery);
    }
}

impl http_body::Body for AccessLogBody {
    type Data = Bytes;
    type Error = HttpError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    self.bytes_sent = self.bytes_sent.saturating_add(data.len() as u64);
                }
                if self.inner.is_end_stream() {
                    self.finish_idle();
                }
                // Codex G8: Do NOT emit completion here; the transport has not written `frame` yet.
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => {
                // Codex G8: Mark body EOF, but wait for `Drop` / transport flush/finish before
                // emitting so a failed final write or `send_stream.finish()` records `completed=false`.
                self.stream_eof = true;
                self.finish_idle();
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(err))) => {
                self.body_errored = true;
                // Emit the failure record before releasing the in-flight count, matching v0.1.2
                // where `InFlightResponseBody` wrapped `AccessLogBody`.
                self.finish_now(false, TransportDelivery::Failed);
                self.finish_idle();
                Poll::Ready(Some(Err(err)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

fn box_access_log_response(resp: Response<AccessLogBody>) -> Response<HttpBody> {
    let (mut parts, tracked) = resp.into_parts();
    if let Some(outcome) = tracked.transport_outcome.clone() {
        parts.extensions.insert(outcome);
    }
    Response::from_parts(parts, tracked.boxed())
}

/// Immutable per-connection state shared across every request on a hyper connection under one
/// `Arc` instead of cloning individual handles and config structs per request.
struct ConnShared {
    engine: Arc<HttpEngine>,
    limits: LimitsConfig,
    timeouts: TimeoutsConfig,
    flood_guard: Arc<ConnectionFloodGuard>,
    bad_req_close_tx: watch::Sender<bool>,
    idle_state: Arc<ConnectionIdleState>,
    upgrade_template: Option<miraserve_proxy::UpgradeLifecycle>,
    write_tracker: Arc<ConnWriteTracker>,
    h2_streams: Arc<h2_stall::H2StallRegistry>,
    ctx: RequestContext,
    redirect_only: bool,
}

/// Concrete response body returned to hyper so H1 and empty H2 responses skip `BoxBody`
/// allocations for `AccessLogBody` and `InFlightResponseBody`.
///
/// `Direct` is the hot variant used by almost every request; keeping it unboxed avoids a heap
/// allocation per request.
#[allow(clippy::large_enum_variant)]
enum HyperResponseBody {
    Direct(AccessLogBody),
    H2Stalled(h2_stall::H2StallBody),
    InFlight(InFlightResponseBody),
    Plain(HttpBody),
}

impl http_body::Body for HyperResponseBody {
    type Data = Bytes;
    type Error = HttpError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            Self::Direct(body) => Pin::new(body).poll_frame(cx),
            Self::H2Stalled(body) => Pin::new(body).poll_frame(cx),
            Self::InFlight(body) => Pin::new(body).poll_frame(cx),
            Self::Plain(body) => Pin::new(body).poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Direct(body) => body.is_end_stream(),
            Self::H2Stalled(body) => body.is_end_stream(),
            Self::InFlight(body) => body.is_end_stream(),
            Self::Plain(body) => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match self {
            Self::Direct(body) => body.size_hint(),
            Self::H2Stalled(body) => body.size_hint(),
            Self::InFlight(body) => body.size_hint(),
            Self::Plain(body) => body.size_hint(),
        }
    }
}

/// Builds an empty [`HttpBody`].
#[must_use]
pub fn empty_http_body() -> HttpBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

/// Builds a single-chunk [`HttpBody`].
#[must_use]
pub fn full_http_body(bytes: impl Into<Bytes>) -> HttpBody {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed()
}

/// Builds a plain-text HTTP response.
#[must_use]
pub fn text_response(status: StatusCode, text: impl Into<String>) -> Response<HttpBody> {
    let body_bytes = Bytes::from(text.into().into_bytes());
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full_http_body(body_bytes))
        .unwrap_or_else(|_| {
            let mut resp = Response::new(empty_http_body());
            *resp.status_mut() = status;
            resp
        })
}

/// Reports the kernel send-buffer size of the wrapped socket, see [`WriteGuardedIo`].
pub type SendBufferProbe<I> = Box<dyn Fn(&I) -> Option<usize> + Send + Sync>;

/// Largest send-buffer allowance the guard grants where the kernel cannot bound its unsent
/// queue (`R8-HTTP-1`; not Linux, see [`NOTSENT_LOWAT_BYTES`]). There a client that stops
/// reading entirely can hold a connection for `response-write-idle` plus
/// `MAX_SEND_BUFFER_SLACK_BYTES / min-response-rate-bps` (about 17 minutes at the defaults).
const MAX_SEND_BUFFER_SLACK_BYTES: u64 = 1024 * 1024;

/// `TCP_NOTSENT_LOWAT` set on every accepted connection on Linux, and the guard's kernel
/// allowance there.
///
/// With it the kernel accepts a write only while roughly this much data is queued but not yet
/// sent (it can overshoot by one buffer), whatever size it has grown the send buffer to. So the
/// server's own side of the connection hides at most about this much progress, and a client
/// that stops reading is cut after `response-write-idle + NOTSENT_LOWAT_BYTES /
/// min-response-rate-bps` (62 s at the defaults) instead of an amount that depends on kernel
/// buffer autotuning. It limits only unsent data, not data in flight, so it does not cap
/// throughput.
///
/// It says nothing about the **client's** side: a receiver reopens its window in steps (one
/// segment, or a sixteenth of its receive buffer on Linux), so accepted writes arrive in lumps
/// with silence in between even from a steady reader. That silence is covered by the time
/// allowance in [`WriteGuardedIo`], not by this constant.
const NOTSENT_LOWAT_BYTES: u32 = 32 * 1024;

/// Largest lead over the minimum rate a client can bank in one backpressure episode, and so the
/// longest extra silence it can buy: `MAX_READER_LEAD_BYTES / min-response-rate` (about 8.5
/// minutes at 2048 bytes per second, 17 at the default 1024).
///
/// Staging over a `WireGuard` path with 60-70 ms round trips: curl reading at 3 KB/s over HTTP/2
/// had taken about 540 KB more than it had read when its window stayed shut for over 46 s, and
/// was cut while still reading. A lead of this size covers such paths; it also bounds how long a
/// client that downloads fast and then stops reading can hold a connection.
const MAX_READER_LEAD_BYTES: u64 = 1024 * 1024;

/// Outbound `AsyncWrite` wrapper defending connections against slow-reader DoS (`R7-DOS-1`,
/// `R8-HTTP-1`).
///
/// It MUST wrap the TCP socket itself, below TLS. Only there does `Poll::Pending` mean "the
/// kernel send buffer is full" and `Poll::Ready(n)` mean "the kernel accepted `n` bytes"; above
/// TLS both are distorted by rustls' own buffering.
///
/// The guard only acts during write backpressure, so idle keep-alive connections and quiet SSE
/// streams are never closed. During backpressure two rules apply:
///
/// - **Silence.** No write accepted for `write_idle_timeout` (plus the time the minimum rate
///   needs for the kernel allowance): the client has stopped reading.
/// - **Rate.** Over the blocked time of the episode the kernel must have accepted at least
///   `min_response_rate_bps`, less two allowances: the kernel allowance (one send buffer, or
///   `NOTSENT_LOWAT_BYTES` where the unsent queue is bounded), and `write_idle_timeout` worth
///   of data at the minimum rate.
///
/// The second allowance is what makes the rate rule safe for honest readers. Accepted writes
/// do not track the reader smoothly: the receiving kernel reopens its window in steps, so a
/// steady reader produces lumps of accepted data separated by silence, and the lump size is
/// the client's choice (it grows with its receive buffer). Any silence shorter than
/// `write_idle_timeout` is allowed by the first rule, so the rate rule must not punish it
/// either: a reader at or above the minimum rate whose silences stay below `write_idle_timeout`
/// is never behind by more than `min_response_rate_bps * write_idle_timeout`. A client that
/// reads too slowly still falls behind without limit and is cut; one that stops is cut by the
/// silence rule.
///
/// When `min_response_rate_bps` is `0` only `write_idle_timeout` applies, and it then measures
/// the gap between two kernel writes; set it generously for slow clients.
pub struct WriteGuardedIo<I> {
    inner: I,
    write_idle_timeout: Duration,
    min_response_rate_bps: u64,
    rate_grace: Duration,
    pending_since: Option<Instant>,
    write_timer: Option<Pin<Box<tokio::time::Sleep>>>,
    /// Time spent blocked (`Poll::Pending`) in the current backpressure episode.
    episode_blocked: Duration,
    /// Bytes the kernel accepted in the current backpressure episode. Surplus above the minimum
    /// rate is capped (see `clamp_surplus`), so a fast start cannot buy an endless trickle.
    episode_bytes: u64,
    in_backpressure: bool,
    last_ready_at: Option<Instant>,
    send_buffer_probe: Option<SendBufferProbe<I>>,
    peer_addr: Option<SocketAddr>,
    logged_close: bool,
    /// Bytes accepted at once, outside any backpressure episode, since `fresh_since`. A client
    /// that takes a burst into its buffers before the first write blocks is ahead of the
    /// minimum rate by that much, and the first blocked wait may spend it (see
    /// `check_pending_budget`). Forgotten after `write_idle_timeout` without writes, so an
    /// earlier response cannot finance a later one.
    fresh_bytes: u64,
    fresh_since: Option<Instant>,
    fresh_last: Option<Instant>,
}

/// Bounds the kernel's unsent queue for `stream` (see [`NOTSENT_LOWAT_BYTES`]). Returns whether
/// the bound is in force.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_notsent_lowat(stream: &tokio::net::TcpStream) -> bool {
    socket2::SockRef::from(stream)
        .set_tcp_notsent_lowat(NOTSENT_LOWAT_BYTES)
        .is_ok()
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
const fn set_notsent_lowat(_stream: &tokio::net::TcpStream) -> bool {
    let _ = NOTSENT_LOWAT_BYTES;
    false
}

impl WriteGuardedIo<tokio::net::TcpStream> {
    /// Wraps an accepted TCP socket, reading its live `SO_SNDBUF` size as the send-buffer
    /// allowance. This is the constructor the listener uses for every HTTP/1.1 and HTTP/2
    /// connection, before any TLS handshake.
    #[must_use]
    pub fn for_tcp_stream(
        stream: tokio::net::TcpStream,
        write_idle_timeout: Duration,
        min_response_rate_bps: u64,
    ) -> Self {
        let peer_addr = stream.peer_addr().ok();
        let bounded_unsent = set_notsent_lowat(&stream);
        let mut guarded = Self::new(stream, write_idle_timeout, min_response_rate_bps)
            .with_send_buffer_probe(Box::new(move |stream: &tokio::net::TcpStream| {
                if bounded_unsent {
                    usize::try_from(NOTSENT_LOWAT_BYTES).ok()
                } else {
                    socket2::SockRef::from(stream).send_buffer_size().ok()
                }
            }));
        guarded.peer_addr = peer_addr;
        guarded
    }
}

impl<I> WriteGuardedIo<I> {
    /// Wraps `inner` with slow-reader write-idle and minimum send-rate enforcement and no
    /// send-buffer allowance (see [`Self::with_send_buffer_probe`]).
    #[must_use]
    pub fn new(inner: I, write_idle_timeout: Duration, min_response_rate_bps: u64) -> Self {
        let rate_grace = Duration::from_secs(10)
            .min(write_idle_timeout)
            .max(Duration::from_millis(50));
        Self {
            inner,
            write_idle_timeout,
            min_response_rate_bps,
            rate_grace,
            pending_since: None,
            write_timer: None,
            episode_blocked: Duration::ZERO,
            episode_bytes: 0,
            in_backpressure: false,
            last_ready_at: None,
            send_buffer_probe: None,
            peer_addr: None,
            logged_close: false,
            fresh_bytes: 0,
            fresh_since: None,
            fresh_last: None,
        }
    }

    /// Attaches a peer socket address for slow-reader close diagnostics.
    #[must_use]
    pub const fn with_peer_addr(mut self, peer_addr: SocketAddr) -> Self {
        self.peer_addr = Some(peer_addr);
        self
    }

    /// Overrides the minimum-rate evaluation grace window (for deterministic unit tests).
    #[must_use]
    pub fn with_rate_grace(mut self, grace: Duration) -> Self {
        self.rate_grace = grace;
        self
    }

    /// Supplies the kernel send-buffer size used as the allowance described on the type.
    #[must_use]
    pub fn with_send_buffer_probe(mut self, probe: SendBufferProbe<I>) -> Self {
        self.send_buffer_probe = Some(probe);
        self
    }

    /// Returns the wrapped I/O object.
    pub const fn get_ref(&self) -> &I {
        &self.inner
    }

    fn slack_bytes(&self) -> u64 {
        self.send_buffer_probe
            .as_ref()
            .and_then(|probe| probe(&self.inner))
            .map_or(0, |b| {
                u64::try_from(b)
                    .unwrap_or(u64::MAX)
                    .min(MAX_SEND_BUFFER_SLACK_BYTES)
            })
    }

    /// Time the minimum rate needs to deliver `bytes`.
    fn time_to_send(&self, bytes: u64) -> Duration {
        if self.min_response_rate_bps == 0 {
            return Duration::ZERO;
        }
        let millis =
            u128::from(bytes).saturating_mul(1000) / u128::from(self.min_response_rate_bps);
        Duration::from_millis(u64::try_from(millis).unwrap_or(u64::MAX))
    }

    fn expected_bytes(&self, blocked: Duration) -> u64 {
        let expected =
            u128::from(self.min_response_rate_bps).saturating_mul(blocked.as_millis()) / 1000;
        u64::try_from(expected).unwrap_or(u64::MAX).max(1)
    }

    /// Longest tolerated gap with no accepted write.
    /// How far the client is ahead of the minimum rate in this backpressure episode: bytes it
    /// took beyond what the minimum rate required (capped, see [`MAX_READER_LEAD_BYTES`]).
    fn reader_lead(&self) -> u64 {
        if self.min_response_rate_bps == 0 {
            return 0;
        }
        self.episode_bytes
            .saturating_sub(self.expected_bytes(self.episode_blocked))
            .min(MAX_READER_LEAD_BYTES)
    }

    /// Longest tolerated gap with no accepted write.
    ///
    /// `response-write-idle`, plus the time the minimum rate needs for the kernel allowance and
    /// for the client's lead. A client that took data faster than the minimum rate may hold it
    /// in its own buffers and along the path (on a long path with a large receive window, half a
    /// megabyte), and a steady reader works through it before the window reopens: that silence
    /// is the lead being spent, not a stall.
    fn idle_limit(&self, slack: u64) -> Duration {
        self.write_idle_timeout
            .saturating_add(self.time_to_send(slack.saturating_add(self.reader_lead())))
    }

    /// Bytes the rate rule forgives: the kernel allowance plus `write_idle_timeout` worth of
    /// data at the minimum rate (see the type documentation). Granted once per episode.
    fn rate_allowance(&self, slack: u64) -> u64 {
        slack.saturating_add(self.expected_bytes(self.write_idle_timeout))
    }

    /// The single kill decision, shared by every code path.
    fn verdict(
        &mut self,
        idle: Duration,
        total_blocked: Duration,
        slack: u64,
    ) -> Option<io::Error> {
        let peer_display = self
            .peer_addr
            .map_or_else(|| "-".to_owned(), |p| p.to_string());
        if idle >= self.idle_limit(slack) {
            if !self.logged_close {
                self.logged_close = true;
                warn!(
                    peer = %peer_display,
                    reason = "response_write_idle",
                    idle_ms = u64::try_from(idle.as_millis()).unwrap_or(u64::MAX),
                    "closing slow-reader client connection"
                );
            }
            return Some(io::Error::new(
                io::ErrorKind::TimedOut,
                "client response write idle timeout elapsed (R7-DOS-1)",
            ));
        }
        if self.min_response_rate_bps > 0
            && total_blocked >= self.rate_grace
            && self
                .episode_bytes
                .saturating_add(self.rate_allowance(slack))
                < self.expected_bytes(total_blocked)
        {
            if !self.logged_close {
                self.logged_close = true;
                warn!(
                    peer = %peer_display,
                    reason = "min_response_rate_bps",
                    min_response_rate_bps = self.min_response_rate_bps,
                    blocked_ms = u64::try_from(total_blocked.as_millis()).unwrap_or(u64::MAX),
                    bytes_accepted = self.episode_bytes,
                    "closing slow-reader client connection"
                );
            }
            return Some(io::Error::new(
                io::ErrorKind::TimedOut,
                "client response send rate below min-response-rate-bps (R7-DOS-1)",
            ));
        }
        None
    }

    /// Caps how far ahead of the minimum rate a client can get. Without the cap a client could
    /// read quickly for a while and then trickle a byte at a time for as long as the surplus
    /// lasts. The cap is `write_idle_timeout` worth of minimum-rate data.
    fn clamp_surplus(&mut self) {
        if self.min_response_rate_bps == 0 {
            return;
        }
        let due = self.expected_bytes(self.episode_blocked);
        let max_surplus = self
            .expected_bytes(self.write_idle_timeout)
            .max(MAX_READER_LEAD_BYTES);
        self.episode_bytes = self.episode_bytes.min(due.saturating_add(max_surplus));
    }

    /// Starts a backpressure episode with the lead of the burst taken just before it: bytes
    /// accepted at once beyond what the minimum rate needed for that time, capped.
    fn seed_episode_from_burst(&mut self, now: Instant) {
        let fresh_recent = self
            .fresh_last
            .is_some_and(|last| now.saturating_duration_since(last) < self.write_idle_timeout);
        if self.min_response_rate_bps > 0
            && fresh_recent
            && let Some(since) = self.fresh_since
        {
            let due = u128::from(self.min_response_rate_bps)
                .saturating_mul(now.saturating_duration_since(since).as_millis())
                / 1000;
            let due = u64::try_from(due).unwrap_or(u64::MAX);
            self.episode_bytes = self
                .fresh_bytes
                .saturating_sub(due)
                .min(MAX_READER_LEAD_BYTES);
        }
        self.fresh_bytes = 0;
        self.fresh_since = None;
        self.fresh_last = None;
    }

    fn check_pending_budget(&mut self, cx: &mut Context<'_>) -> Result<(), io::Error> {
        let now = Instant::now();
        if self.pending_since.is_none() && !self.in_backpressure {
            self.seed_episode_from_burst(now);
        }
        let since = *self.pending_since.get_or_insert(now);
        let idle = now.saturating_duration_since(since);
        let total_blocked = self.episode_blocked.saturating_add(idle);
        let slack = self.slack_bytes();

        if let Some(err) = self.verdict(idle, total_blocked, slack) {
            self.write_timer = None;
            return Err(err);
        }

        if tokio::runtime::Handle::try_current().is_ok() {
            let mut remaining = self.idle_limit(slack).saturating_sub(idle);
            if self.min_response_rate_bps > 0 {
                // Wake when the rate rule could first trip: after the grace window, and once
                // the minimum rate would have sent more than was accepted plus the allowance.
                let trip_at = self
                    .time_to_send(
                        self.episode_bytes
                            .saturating_add(self.rate_allowance(slack)),
                    )
                    .max(self.rate_grace);
                let rate_wait = trip_at
                    .saturating_sub(total_blocked)
                    .max(Duration::from_millis(50));
                remaining = remaining.min(rate_wait);
            }
            let deadline =
                tokio::time::Instant::from_std(now + remaining + Duration::from_millis(10));
            let timer = self
                .write_timer
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(deadline)));
            if timer.as_mut().poll(cx).is_ready() {
                self.write_timer = None;
                let after = Instant::now();
                let idle2 = self
                    .pending_since
                    .map_or(Duration::ZERO, |s| after.saturating_duration_since(s));
                let blocked2 = self.episode_blocked.saturating_add(idle2);
                if let Some(err) = self.verdict(idle2, blocked2, slack) {
                    return Err(err);
                }
                let next_wake = tokio::time::Instant::now() + Duration::from_millis(25);
                let mut retry = Box::pin(tokio::time::sleep_until(next_wake));
                let _ = retry.as_mut().poll(cx);
                self.write_timer = Some(retry);
            }
        }
        Ok(())
    }

    /// Records bytes accepted at once outside a backpressure episode.
    fn note_fresh(&mut self, bytes: u64, now: Instant) {
        if bytes == 0 {
            return;
        }
        let stale = self
            .fresh_last
            .is_none_or(|last| now.saturating_duration_since(last) >= self.write_idle_timeout);
        if stale {
            self.fresh_bytes = 0;
            self.fresh_since = Some(now);
        }
        self.fresh_bytes = self.fresh_bytes.saturating_add(bytes);
        self.fresh_last = Some(now);
    }

    fn record_write_progress(&mut self, bytes_written: usize) -> Result<(), io::Error> {
        self.write_timer = None;
        let n = bytes_written as u64;
        if self.pending_since.is_none()
            && !self.in_backpressure
            && (n == 0 || self.min_response_rate_bps == 0)
        {
            return Ok(());
        }
        let now = Instant::now();
        if let Some(since) = self.pending_since.take() {
            let delta = now.saturating_duration_since(since);
            self.episode_blocked = self.episode_blocked.saturating_add(delta);
            self.episode_bytes = self.episode_bytes.saturating_add(n);
            self.in_backpressure = true;
            self.last_ready_at = Some(now);
            let slack = self.slack_bytes();
            if let Some(err) = self.verdict(Duration::ZERO, self.episode_blocked, slack) {
                return Err(err);
            }
            self.clamp_surplus();
        } else if self.in_backpressure {
            if self
                .last_ready_at
                .is_some_and(|t| now.saturating_duration_since(t) >= self.rate_grace)
            {
                // Writes have flowed without blocking for a full grace window: the episode is
                // over and the next one starts with a fresh allowance.
                self.in_backpressure = false;
                self.episode_blocked = Duration::ZERO;
                self.episode_bytes = 0;
                self.note_fresh(n, now);
            } else {
                self.episode_bytes = self.episode_bytes.saturating_add(n);
                self.last_ready_at = Some(now);
                self.clamp_surplus();
            }
        } else {
            self.note_fresh(n, now);
        }
        Ok(())
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for WriteGuardedIo<I> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for WriteGuardedIo<I> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Pending => match this.check_pending_budget(cx) {
                Ok(()) => Poll::Pending,
                Err(err) => Poll::Ready(Err(err)),
            },
            Poll::Ready(Ok(n)) => match this.record_write_progress(n) {
                Ok(()) => Poll::Ready(Ok(n)),
                Err(err) => Poll::Ready(Err(err)),
            },
            Poll::Ready(Err(err)) => {
                this.pending_since = None;
                this.write_timer = None;
                Poll::Ready(Err(err))
            }
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write_vectored(cx, bufs) {
            Poll::Pending => match this.check_pending_budget(cx) {
                Ok(()) => Poll::Pending,
                Err(err) => Poll::Ready(Err(err)),
            },
            Poll::Ready(Ok(n)) => match this.record_write_progress(n) {
                Ok(()) => Poll::Ready(Ok(n)),
                Err(err) => Poll::Ready(Err(err)),
            },
            Poll::Ready(Err(err)) => {
                this.pending_since = None;
                this.write_timer = None;
                Poll::Ready(Err(err))
            }
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Pending => match this.check_pending_budget(cx) {
                Ok(()) => Poll::Pending,
                Err(err) => Poll::Ready(Err(err)),
            },
            Poll::Ready(Ok(())) => match this.record_write_progress(0) {
                Ok(()) => Poll::Ready(Ok(())),
                Err(err) => Poll::Ready(Err(err)),
            },
            Poll::Ready(Err(err)) => {
                this.pending_since = None;
                this.write_timer = None;
                Poll::Ready(Err(err))
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Pending => match this.check_pending_budget(cx) {
                Ok(()) => Poll::Pending,
                Err(err) => Poll::Ready(Err(err)),
            },
            Poll::Ready(res) => {
                this.pending_since = None;
                this.write_timer = None;
                Poll::Ready(res)
            }
        }
    }
}

/// Serializes unit tests that install thread-local `tracing` subscribers (`with_default` /
/// `set_default`) or register callsites observed by those tests.
///
/// `tracing-core 0.1.36` keeps `DISPATCHERS.has_just_one == true` whenever at most one
/// thread-local subscriber is alive; if a concurrent test thread registers a callsite while
/// another thread is inside `with_default`, `Rebuilder::JustOne` queries the registering
/// thread's `NoSubscriber` without locking `LOCKED_DISPATCHERS` and caches `Interest::never()`
/// on that callsite, causing the subscriber thread to drop events. Keeping two live
/// `NoSubscriber` dispatches registered forces `has_just_one == false` (so callsite registration
/// takes `LOCKED_DISPATCHERS`'s `RwLock` across all active dispatchers), and the mutex
/// serializes subscriber and callsite-registration tests against each other.
#[cfg(test)]
pub(crate) fn test_tracing_lock() -> &'static tokio::sync::Mutex<()> {
    use std::sync::OnceLock;
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    static KEEP_MULTI_DISPATCH: OnceLock<[tracing::Dispatch; 2]> = OnceLock::new();
    let _ = KEEP_MULTI_DISPATCH.get_or_init(|| {
        [
            tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()),
            tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()),
        ]
    });
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

#[cfg(test)]
mod access_line_tests {
    use super::{
        ACCESS_LOG_INLINE_CAP, AccessLineFields, AccessLogRecord, AccessLogStrings, IpText,
        PipeReqBody, PipeRespBody, TransportDelivery, escape_log_controls_cow, push_rfc3339_micros,
    };
    use http::{HeaderValue, Method, Uri};
    use miraserve_telemetry::TelemetryRegistry;
    use miraserve_telemetry::redact::{
        escape_log_controls, redact_header_value, redact_request_target, redact_uri_query,
    };
    use std::io::Write as _;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant, UNIX_EPOCH};

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .map_err(|_| std::io::Error::other("poisoned"))?
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn record(user_agent: &str) -> AccessLogRecord {
        record_full(
            "localhost:18443",
            "/1k.txt?q=1",
            Some(user_agent),
            None,
            true,
            "https",
        )
    }

    fn record_full(
        host: &str,
        target: &str,
        user_agent: Option<&str>,
        referer: Option<&str>,
        redacted: bool,
        scheme: &'static str,
    ) -> AccessLogRecord {
        let strings =
            AccessLogStrings::from_raw_parts(Some(host), target, user_agent, referer, redacted);
        AccessLogRecord {
            started: Instant::now(),
            telemetry: Some(Arc::new(TelemetryRegistry::new())),
            request_id: crate::pages::RequestId::from_ascii_bytes(*b"01M80S7H68T38Y3SXC6EWWT8NA"),
            proto: "h1",
            scheme,
            method: Method::GET,
            strings,
            status: 200,
            client_ip: IpText::from_opt(Some(IpAddr::V4(Ipv4Addr::LOCALHOST))),
            peer_ip: IpText::from_opt(Some(IpAddr::V6(Ipv6Addr::LOCALHOST))),
            redacted,
        }
    }

    /// The direct formatter must write exactly what `tracing-subscriber` writes for the same
    /// event (log parsers rely on it), also for values that need escaping, redaction, and
    /// plain HTTP.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn direct_access_line_matches_the_tracing_formatter() {
        let _tracing_serial = crate::test_tracing_lock().blocking_lock();
        for (host, target, ua, referer, redacted, complete, scheme) in [
            (
                "localhost:18443",
                "/1k.txt?q=1",
                Some("curl/8.5.0"),
                None,
                true,
                true,
                "https",
            ),
            (
                "localhost:18443",
                "/1k.txt?q=1",
                Some("curl/8.5.0"),
                None,
                true,
                true,
                "http",
            ),
            (
                "EXAMPLE.COM:8443",
                "/cb?token=secret123&q=ok",
                Some("Bearer eyJabc.def"),
                Some("https://ann:pw@ref.example/p?code=999&ok=1"),
                true,
                true,
                "https",
            ),
            (
                "EXAMPLE.COM:8443",
                "/cb?token=secret123&q=ok",
                Some("Bearer eyJabc.def"),
                Some("https://ann:pw@ref.example/p?code=999&ok=1"),
                false,
                true,
                "https",
            ),
            (
                "user:pw@site.example",
                "/go",
                Some("x \"quoted\" \\ back"),
                None,
                true,
                false,
                "https",
            ),
            (
                "localhost:18443",
                "/1k.txt?q=1",
                Some("caf\u{e9}"),
                Some("https://app.example/docs"),
                true,
                true,
                "https",
            ),
            (
                "localhost:18443",
                "/1k.txt?q=1",
                Some("caf\u{e9} \u{7f}"),
                None,
                true,
                true,
                "http",
            ),
            ("localhost:18443", "/empty", None, None, true, true, "https"),
        ] {
            let capture = Capture::default();
            let writer = capture.clone();
            let subscriber = tracing_subscriber::fmt()
                .with_target(false)
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish();
            let delivery = if complete {
                TransportDelivery::Confirmed
            } else {
                TransportDelivery::Failed
            };
            tracing::subscriber::with_default(subscriber, || {
                record_full(host, target, ua, referer, redacted, scheme)
                    .emit(None, 1024, complete, delivery);
            });
            let traced = String::from_utf8(capture.0.lock().map(|b| b.clone()).unwrap_or_default())
                .unwrap_or_default();
            let latency = traced
                .split(" latency_us=")
                .nth(1)
                .and_then(|rest| rest.split(' ').next())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            let mut direct = String::new();
            let msg = if complete {
                "http request completed"
            } else {
                "http request interrupted"
            };
            let fields = AccessLineFields {
                bytes_sent: 1024,
                body_complete: complete,
                delivery: delivery.as_str(),
                completed: complete && delivery != TransportDelivery::Failed,
                latency_us: latency,
            };
            let now = std::time::SystemTime::now();
            record_full(host, target, ua, referer, redacted, scheme).format_line(
                &mut direct,
                now,
                msg,
                fields,
            );
            // Timestamps differ by the time between the two calls; everything after matches.
            let after = |line: &str| line.split_once("Z ").map(|(_, r)| r.to_owned());
            assert_eq!(
                after(&direct),
                after(&traced),
                "user agent {ua:?}, scheme {scheme}"
            );
            if scheme == "https" {
                assert!(
                    !traced.contains(" scheme="),
                    "HTTPS access log line must stay v0.1.2-compatible: {traced:?}"
                );
            } else {
                assert!(
                    traced.contains(" scheme=\"http\"\n"),
                    "plain-HTTP access log line must carry scheme=\"http\": {traced:?}"
                );
            }
            assert!(traced.len() > 100, "tracing produced {traced:?}");
        }
        // Keep the simple helper exercised for default record shape.
        let _ = record("curl/8.5.0");
    }

    #[test]
    fn timestamp_is_rfc3339_with_microseconds() {
        let mut out = String::new();
        push_rfc3339_micros(
            &mut out,
            UNIX_EPOCH + Duration::from_micros(1_795_322_791_112_840),
        );
        assert_eq!(out, "2026-11-22T04:46:31.112840Z");
        out.clear();
        push_rfc3339_micros(&mut out, UNIX_EPOCH + Duration::from_secs(951_782_400));
        assert_eq!(out, "2000-02-29T00:00:00.000000Z");
        let _ = std::io::sink().write(out.as_bytes());
    }

    #[test]
    fn push_quoted_matches_debug_for_non_ascii_and_del() {
        let mut out = String::new();
        super::push_quoted(&mut out, "caf\u{e9} \u{7f}");
        assert_eq!(out, format!("{:?}", "caf\u{e9} \u{7f}"));
    }

    #[derive(Clone, Default)]
    struct FieldFilteredCapture(Arc<Mutex<Vec<String>>>);

    struct FieldCollector<'a>(&'a mut String);

    impl tracing::field::Visit for FieldCollector<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write as _;
            let _ = write!(self.0, "{}={value:?} ", field.name());
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            use std::fmt::Write as _;
            let _ = write!(self.0, "{}={value:?} ", field.name());
        }
    }

    impl tracing::Subscriber for FieldFilteredCapture {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            metadata.target() == "miraserve::access" && metadata.fields().field("status").is_some()
        }

        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            let mut line = String::new();
            event.record(&mut FieldCollector(&mut line));
            if let Ok(mut lines) = self.0.lock() {
                lines.push(line);
            }
        }

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}
    }

    /// Regression test for reverted commit 7753877: deciding at request arrival whether logging is
    /// on would lose access-log lines when a subscriber is enabled while the request is in flight
    /// or filters on event fields (`status`, `method`, ...).
    #[tokio::test(flavor = "current_thread")]
    async fn access_log_decides_at_emit_not_arrival_and_honors_field_filtering_subscribers()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::{HttpEngine, RequestContext, empty_http_body};
        use http::Request;
        use http_body_util::BodyExt as _;
        use miraserve_config::parse_kdl;
        use miraserve_tls::AcmeChallengeStore;

        let _tracing_serial = crate::test_tracing_lock().lock().await;

        // 1. Arrive with a warn-only subscriber (miraserve::access INFO is disabled at arrival!).
        let warn_only = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_writer(std::io::sink)
            .finish();
        let kdl = r#"
server {
    listen ":8443"
    tls { cert "/c.pem"; key "/k.pem" }
}
site "late.example.test" {
    route "/go" { redirect "/dest" }
}
"#;
        let (cfg, _) = parse_kdl("late.kdl", kdl)?;
        let engine =
            HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
        let ctx = RequestContext {
            client_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42))),
            remote_port: Some(50_000),
            server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            server_port: 8443,
            is_https: true,
            tls: None,
        };
        let req = Request::builder()
            .method(Method::GET)
            .uri("/go?token=topsecret&q=ok")
            .header(http::header::HOST, "late.example.test")
            .header(http::header::USER_AGENT, "LateTest/1.0")
            .header(
                http::header::REFERER,
                "https://ref.example/p?code=1234&keep=yes",
            )
            .body(empty_http_body())?;
        let resp = {
            let _guard = tracing::subscriber::set_default(warn_only);
            engine.handle_request(req, &ctx).await
        };

        // 2. Now install a subscriber that ONLY enables callsites carrying the `status` field.
        let captured = FieldFilteredCapture::default();
        {
            let _guard = tracing::subscriber::set_default(captured.clone());
            let _ = resp.into_body().collect().await?;
        }
        let lines = captured.0.lock().map(|g| g.clone()).unwrap_or_default();
        assert_eq!(
            lines.len(),
            1,
            "expected 1 emitted access log line: {lines:?}"
        );
        let line = lines.first().map_or("", String::as_str);
        assert!(
            line.contains("target=\"/go?token=[REDACTED]&q=ok\""),
            "{line}"
        );
        assert!(line.contains("user_agent=\"LateTest/1.0\""), "{line}");
        assert!(
            line.contains("referer=\"https://ref.example/p?code=[REDACTED]&keep=yes\""),
            "{line}"
        );
        assert!(line.contains("client_ip=198.51.100.42"), "{line}");
        assert!(line.contains("status=301"), "{line}");
        Ok(())
    }

    /// Regression test for 600c0d9 P1 #1 (flush race): `ConnWriteTracker::mark_flushed` must
    /// synchronize on `pending_logs`'s mutex so a record pushed under the lock can never be
    /// missed by a concurrent flush and later logged as `transport_delivery="failed"`.
    #[test]
    fn conn_write_tracker_mark_flushed_synchronizes_on_pending_logs_lock()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::{ConnWriteTracker, PendingAccessLog};

        let _tracing_serial = crate::test_tracing_lock().blocking_lock();

        // 1. Single-threaded deterministic check: a record present in `pending_logs` must be
        //    drained on `mark_flushed`, regardless of any auxiliary flag.
        let tracker = Arc::new(ConnWriteTracker::new(Arc::new(TelemetryRegistry::new())));
        let mut rec = record("curl/8.5.0");
        rec.proto = "h2";
        {
            let mut guard = tracker
                .pending_logs
                .lock()
                .map_err(|_| "pending_logs lock poisoned")?;
            guard.push(PendingAccessLog {
                record: rec,
                bytes_sent: 128,
                body_complete: true,
            });
        }
        let capture = Capture::default();
        let writer = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_target(false)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let mut scratch = Vec::new();
        tracing::subscriber::with_default(subscriber, || {
            tracker.mark_flushed(&mut scratch);
            tracker.mark_failed();
        });
        let single_out = String::from_utf8(
            capture
                .0
                .lock()
                .map_err(|_| "capture lock poisoned")?
                .clone(),
        )?;
        assert!(
            single_out.contains("transport_delivery=\"unconfirmed_multiplexed\"")
                && single_out.contains("completed=true"),
            "flush missed record queued under pending_logs lock: {single_out:?}"
        );
        assert!(
            !single_out.contains("transport_delivery=\"failed\""),
            "subsequent mark_failed must not emit already-flushed record: {single_out:?}"
        );

        // 2. Two-thread lock-ordering check: while a producer holds `pending_logs.lock()`,
        //    `mark_flushed` must wait on the mutex and drain the record pushed before unlock.
        let tracker = Arc::new(ConnWriteTracker::new(Arc::new(TelemetryRegistry::new())));
        let guard = tracker
            .pending_logs
            .lock()
            .map_err(|_| "pending_logs lock poisoned")?;
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let capture = Capture::default();
        let writer = capture.clone();
        let tracker_flusher = Arc::clone(&tracker);
        let flusher = std::thread::spawn(move || {
            let subscriber = tracing_subscriber::fmt()
                .with_target(false)
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish();
            let mut scratch = Vec::new();
            let _ = entered_tx.send(());
            tracing::subscriber::with_default(subscriber, || {
                tracker_flusher.mark_flushed(&mut scratch);
            });
            let _ = done_tx.send(());
        });

        entered_rx.recv_timeout(Duration::from_secs(2))?;
        assert!(
            done_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "mark_flushed returned without acquiring pending_logs mutex while producer held it"
        );
        let mut rec = record("h2load");
        rec.proto = "h2";
        {
            let mut guard = guard;
            guard.push(PendingAccessLog {
                record: rec,
                bytes_sent: 512,
                body_complete: true,
            });
        }
        done_rx.recv_timeout(Duration::from_secs(2))?;
        flusher.join().map_err(|_| "flusher thread panicked")?;

        let out = String::from_utf8(
            capture
                .0
                .lock()
                .map_err(|_| "capture lock poisoned")?
                .clone(),
        )?;
        assert!(
            out.contains("transport_delivery=\"unconfirmed_multiplexed\"")
                && out.contains("completed=true"),
            "flusher must drain the record pushed before releasing the lock: {out:?}"
        );
        Ok(())
    }

    /// Regression test for bc9835b P1 #6: `HeadDeadlineIo` must defer to Tokio `Sleep`'s
    /// readiness (rounded millisecond tick) for both header-read and keep-alive idle deadlines,
    /// with no unrounded `Instant::now() >= deadline` check ahead of it.
    #[tokio::test(flavor = "current_thread")]
    #[allow(clippy::too_many_lines)]
    async fn head_deadline_io_defers_to_tokio_sleep_readiness_for_head_and_idle()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::{ConnectionIdleState, HeadDeadlineIo};
        use std::collections::VecDeque;
        use std::future::Future as _;
        use std::io;
        use std::pin::Pin;
        use std::sync::atomic::{AtomicBool, AtomicU64};
        use std::task::{Context, Poll, Waker};
        use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

        struct ScriptedIo {
            chunks: VecDeque<&'static [u8]>,
        }

        impl AsyncRead for ScriptedIo {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                if let Some(chunk) = self.chunks.pop_front() {
                    buf.put_slice(chunk);
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }
        }

        impl AsyncWrite for ScriptedIo {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Ok(buf.len()))
            }

            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let make_head_io = |chunks: &[&'static [u8]], header_tmo: Duration, idle_tmo: Duration| {
            let idle = Arc::new(ConnectionIdleState::new());
            idle.enter_request();
            idle.exit_request();
            HeadDeadlineIo::new(
                ScriptedIo {
                    chunks: chunks.iter().copied().collect(),
                },
                idle,
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicBool::new(false)),
                header_tmo,
                idle_tmo,
                crate::h2_stall::H2StallRegistry::new().transport(),
                Arc::new(AtomicU64::new(0)),
            )
        };

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        // 1. Header-read deadline boundary: between unrounded `deadline` and Tokio's rounded
        //    millisecond tick, a readable second header chunk must still be read (not TimedOut).
        let mut tested_head_boundary = false;
        for _ in 0..64 {
            let mut io = make_head_io(
                &[b"GET / ", b"HTTP/1.1\r\nHost: a\r\n\r\n"],
                Duration::from_nanos(1),
                Duration::from_secs(60),
            );
            // Armed strictly BEFORE `HeadDeadlineIo` arms its timer, so while `ref_sleep` is
            // still Pending, `HeadDeadlineIo`'s Tokio `Sleep` cannot be ready yet either.
            let mut ref_sleep = Box::pin(tokio::time::sleep(Duration::from_nanos(1)));
            let _ = ref_sleep.as_mut().poll(&mut cx);

            let mut first = [0_u8; 32];
            let mut first_buf = ReadBuf::new(&mut first);
            assert!(matches!(
                Pin::new(&mut io).poll_read(&mut cx, &mut first_buf),
                Poll::Ready(Ok(()))
            ));
            let past_unrounded = tokio::time::Instant::now() + Duration::from_nanos(1);
            while tokio::time::Instant::now() < past_unrounded {
                std::hint::spin_loop();
            }
            if ref_sleep.as_mut().poll(&mut cx).is_ready() {
                continue;
            }
            tested_head_boundary = true;

            let mut second = [0_u8; 64];
            let mut second_buf = ReadBuf::new(&mut second);
            let res = Pin::new(&mut io).poll_read(&mut cx, &mut second_buf);
            assert!(
                matches!(res, Poll::Ready(Ok(()))),
                "header-read rejected readable bytes before Tokio Sleep became ready: {res:?}"
            );
            assert_eq!(second_buf.filled(), b"HTTP/1.1\r\nHost: a\r\n\r\n");

            // Once Tokio's timer genuinely fires, subsequent reads must time out with header-read.
            tokio::time::sleep(Duration::from_millis(5)).await;
            let mut third = [0_u8; 16];
            let mut third_buf = ReadBuf::new(&mut third);
            let expired = Pin::new(&mut io).poll_read(&mut cx, &mut third_buf);
            match expired {
                Poll::Ready(Err(err)) => {
                    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
                    assert!(err.to_string().contains("header-read"), "{err}");
                }
                other => return Err(format!("expected header-read timeout, got {other:?}").into()),
            }
            break;
        }
        assert!(
            tested_head_boundary,
            "failed to observe sub-ms window before ref_sleep fired"
        );

        // 2. Keep-alive idle deadline boundary: same guarantee when `poll_flush` arms idle.
        let mut tested_idle_boundary = false;
        for _ in 0..64 {
            let mut io = make_head_io(
                &[b"GET /next HTTP/1.1\r\nHost: a\r\n\r\n"],
                Duration::from_secs(60),
                Duration::from_nanos(1),
            );
            let mut ref_sleep = Box::pin(tokio::time::sleep(Duration::from_nanos(1)));
            let _ = ref_sleep.as_mut().poll(&mut cx);

            assert!(matches!(
                Pin::new(&mut io).poll_flush(&mut cx),
                Poll::Ready(Ok(()))
            ));
            let past_unrounded = tokio::time::Instant::now() + Duration::from_nanos(1);
            while tokio::time::Instant::now() < past_unrounded {
                std::hint::spin_loop();
            }
            if ref_sleep.as_mut().poll(&mut cx).is_ready() {
                continue;
            }
            tested_idle_boundary = true;

            let mut req = [0_u8; 64];
            let mut req_buf = ReadBuf::new(&mut req);
            let res = Pin::new(&mut io).poll_read(&mut cx, &mut req_buf);
            assert!(
                matches!(res, Poll::Ready(Ok(()))),
                "idle keep-alive rejected readable bytes before Tokio Sleep became ready: {res:?}"
            );
            assert_eq!(req_buf.filled(), b"GET /next HTTP/1.1\r\nHost: a\r\n\r\n");
            break;
        }
        assert!(
            tested_idle_boundary,
            "failed to observe sub-ms window for idle phase"
        );

        // Verify genuine idle expiry after Tokio's Sleep fires.
        let mut idle_io = make_head_io(&[], Duration::from_secs(60), Duration::from_millis(1));
        assert!(matches!(
            Pin::new(&mut idle_io).poll_flush(&mut cx),
            Poll::Ready(Ok(()))
        ));
        tokio::time::sleep(Duration::from_millis(10)).await;
        let mut buf = [0_u8; 16];
        let mut read_buf = ReadBuf::new(&mut buf);
        match Pin::new(&mut idle_io).poll_read(&mut cx, &mut read_buf) {
            Poll::Ready(Err(err)) => {
                assert_eq!(err.kind(), io::ErrorKind::TimedOut);
                assert!(err.to_string().contains("idle-keepalive"), "{err}");
            }
            other => return Err(format!("expected idle-keepalive timeout, got {other:?}").into()),
        }
        Ok(())
    }

    /// Regression test for bc9835b P1 #7: on a response body `poll_frame(Err)`, `AccessLogBody`
    /// must emit the failed access record BEFORE releasing the in-flight connection count,
    /// matching v0.1.2 where `InFlightResponseBody` wrapped `AccessLogBody`.
    #[test]
    fn access_log_body_error_emits_record_before_releasing_in_flight_idle_state() {
        use super::{AccessLogBody, ConnectionIdleState, HttpError};
        use bytes::Bytes;
        use http_body::Body as _;
        use http_body_util::BodyExt as _;
        use std::pin::Pin;
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
        use std::task::{Context, Poll, Waker};

        struct FailingBody;
        impl http_body::Body for FailingBody {
            type Data = Bytes;
            type Error = HttpError;

            fn poll_frame(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
                Poll::Ready(Some(Err(HttpError::Body("stream failed".to_owned()))))
            }
        }

        #[derive(Clone)]
        struct IdleObserver {
            idle_state: Arc<ConnectionIdleState>,
            emitted: Arc<AtomicUsize>,
            idle_during_emit: Arc<AtomicU64>,
        }

        impl tracing::Subscriber for IdleObserver {
            fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
                metadata.target() == "miraserve::access"
            }

            fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                tracing::span::Id::from_u64(1)
            }

            fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

            fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {
            }

            fn event(&self, event: &tracing::Event<'_>) {
                if event.metadata().target() == "miraserve::access" {
                    self.idle_during_emit
                        .store(self.idle_state.idle_since_ms(), Ordering::Release);
                    self.emitted.fetch_add(1, Ordering::AcqRel);
                }
            }

            fn enter(&self, _span: &tracing::span::Id) {}

            fn exit(&self, _span: &tracing::span::Id) {}
        }

        let _tracing_serial = crate::test_tracing_lock().blocking_lock();
        let idle_state = Arc::new(ConnectionIdleState::new());
        idle_state.enter_request();
        assert_eq!(idle_state.idle_since_ms(), 0);

        let emitted = Arc::new(AtomicUsize::new(0));
        let idle_during_emit = Arc::new(AtomicU64::new(u64::MAX));
        let observer = IdleObserver {
            idle_state: Arc::clone(&idle_state),
            emitted: Arc::clone(&emitted),
            idle_during_emit: Arc::clone(&idle_during_emit),
        };

        let mut body = AccessLogBody {
            inner: PipeRespBody::Boxed(FailingBody.boxed()),
            bytes_sent: 0,
            stream_eof: false,
            body_errored: false,
            conn_writer: None,
            transport_outcome: None,
            idle_state: Some(Arc::clone(&idle_state)),
            record: Some(record("curl/8.5.0")),
        };

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let res =
            tracing::subscriber::with_default(observer, || Pin::new(&mut body).poll_frame(&mut cx));
        assert!(matches!(res, Poll::Ready(Some(Err(_)))));
        assert_eq!(emitted.load(Ordering::Acquire), 1);
        assert_eq!(
            idle_during_emit.load(Ordering::Acquire),
            0,
            "connection became idle/evictable BEFORE the body-error access record was emitted"
        );
        assert!(
            idle_state.idle_since_ms() > 0,
            "in-flight count must be released before poll_frame(Err) returns"
        );
    }

    /// Regression test for Diet Audit 2 P1 #1: when the response body is dropped and the access
    /// record sits in `ConnWriteTracker::pending_logs` waiting for a socket flush, the underlying
    /// request-head buffer (including unrelated headers such as `Authorization` and raw URI/Referer
    /// tokens) must ALREADY be freed before flush happens.
    #[tokio::test(flavor = "current_thread")]
    #[allow(clippy::too_many_lines)]
    async fn access_log_pending_flush_does_not_retain_request_head_buffer()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::{ConnWriteTracker, WriteOutcomeIo};
        use crate::{HttpEngine, RequestContext, empty_http_body};
        use bytes::Bytes;
        use http::Request;
        use http_body_util::BodyExt as _;
        use miraserve_config::parse_kdl;
        use miraserve_tls::AcmeChallengeStore;
        use std::io;
        use std::pin::Pin;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::task::{Context, Poll, Waker};
        use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

        struct TrackedHeadBuffer {
            data: Vec<u8>,
            dropped: Arc<AtomicBool>,
        }
        impl AsRef<[u8]> for TrackedHeadBuffer {
            fn as_ref(&self) -> &[u8] {
                &self.data
            }
        }
        impl Drop for TrackedHeadBuffer {
            fn drop(&mut self) {
                self.dropped.store(true, Ordering::Release);
            }
        }

        struct GatedFlushIo {
            allow_flush: bool,
        }
        impl AsyncRead for GatedFlushIo {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }
        }
        impl AsyncWrite for GatedFlushIo {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Ok(buf.len()))
            }

            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                if self.allow_flush {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }

            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let _tracing_serial = crate::test_tracing_lock().lock().await;
        let kdl = r#"
server {
    listen ":8443"
    tls { cert "/c.pem"; key "/k.pem" }
}
site "pending.example.test" {
    route "/go" { redirect "/dest" }
}
"#;
        let (cfg, _) = parse_kdl("pending.kdl", kdl)?;
        assert!(cfg.server.telemetry.redact_logs);
        let engine =
            HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
        let ctx = RequestContext {
            client_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99))),
            remote_port: Some(50_000),
            server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            server_port: 8443,
            is_https: true,
            tls: None,
        };

        let dropped = Arc::new(AtomicBool::new(false));
        let raw_head = b"/go?token=uripw&q=1|pending.example.test|Bearer supersecret-auth|curl/8.5.0|https://app.example/cb?token=refpw";
        let find_slice = |needle: &[u8]| -> Result<std::ops::Range<usize>, &'static str> {
            let start = raw_head
                .windows(needle.len())
                .position(|w| w == needle)
                .ok_or("missing fixture slice")?;
            Ok(start..start + needle.len())
        };
        let uri_range = find_slice(b"/go?token=uripw&q=1")?;
        let host_range = find_slice(b"pending.example.test")?;
        let auth_range = find_slice(b"Bearer supersecret-auth")?;
        let ua_range = find_slice(b"curl/8.5.0")?;
        let ref_range = find_slice(b"https://app.example/cb?token=refpw")?;

        let head_buf = Bytes::from_owner(TrackedHeadBuffer {
            data: raw_head.to_vec(),
            dropped: Arc::clone(&dropped),
        });
        let uri = Uri::from_maybe_shared(head_buf.slice(uri_range))?;
        let host_val = HeaderValue::from_maybe_shared(head_buf.slice(host_range))?;
        let auth_val = HeaderValue::from_maybe_shared(head_buf.slice(auth_range))?;
        let ua_val = HeaderValue::from_maybe_shared(head_buf.slice(ua_range))?;
        let ref_val = HeaderValue::from_maybe_shared(head_buf.slice(ref_range))?;
        drop(head_buf);

        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(http::header::HOST, host_val)
            .header(http::header::AUTHORIZATION, auth_val)
            .header(http::header::USER_AGENT, ua_val)
            .header(http::header::REFERER, ref_val)
            .body(empty_http_body())?;

        let tracker = Arc::new(ConnWriteTracker::new(Arc::new(TelemetryRegistry::new())));
        let mut io = WriteOutcomeIo::new(GatedFlushIo { allow_flush: false }, Arc::clone(&tracker));

        let resp = engine
            .handle_request_tracked(
                req.map(PipeReqBody::from_http_body),
                &ctx,
                Some(Arc::clone(&tracker)),
                false,
            )
            .await;
        // Finish and drop the response body so `AccessLogBody::drop` queues the record into
        // `tracker.pending_logs`, while the socket flush remains pending.
        let _ = resp.into_body().collect().await?;

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        assert!(matches!(
            Pin::new(&mut io).poll_flush(&mut cx),
            Poll::Pending
        ));
        assert_eq!(
            tracker
                .pending_logs
                .lock()
                .map_err(|_| "pending_logs poisoned")?
                .len(),
            1,
            "access record must be queued awaiting flush"
        );
        assert!(
            dropped.load(Ordering::Acquire),
            "tracked request-head allocation (carrying Authorization and raw tokens) must already be freed while flush is still pending"
        );

        // Now complete the flush and verify the emitted record preserved redacted metadata.
        let capture = Capture::default();
        let writer = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_target(false)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        io.inner.allow_flush = true;
        tracing::subscriber::with_default(subscriber, || {
            assert!(matches!(
                Pin::new(&mut io).poll_flush(&mut cx),
                Poll::Ready(Ok(()))
            ));
        });
        let out = String::from_utf8(
            capture
                .0
                .lock()
                .map_err(|_| "capture lock poisoned")?
                .clone(),
        )?;
        assert!(out.contains("target=\"/go?token=[REDACTED]&q=1\""), "{out}");
        assert!(
            out.contains("referer=\"https://app.example/cb?token=[REDACTED]\""),
            "{out}"
        );
        assert!(!out.contains("uripw"), "leaked URI secret: {out}");
        assert!(!out.contains("refpw"), "leaked Referer secret: {out}");
        assert!(!out.contains("supersecret-auth"), "leaked Auth: {out}");
        Ok(())
    }

    /// Regression test for Diet Audit 2 P2 (H1 timer ownership): transitioning from `Idle` to
    /// `Head` or clearing a stale phase must drop the superseded `Sleep` so it cannot fire a
    /// spurious wake later.
    #[tokio::test(flavor = "current_thread")]
    #[allow(clippy::too_many_lines)]
    async fn head_deadline_io_drops_phase_timer_on_replacement_and_clear() {
        use super::{ConnectionIdleState, HeadDeadlineIo};
        use std::collections::VecDeque;
        use std::io;
        use std::pin::Pin;
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        use std::task::{Context, Poll, Wake, Waker};
        use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

        struct FlagWaker(AtomicBool);
        impl Wake for FlagWaker {
            fn wake(self: Arc<Self>) {
                self.0.store(true, Ordering::Release);
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.store(true, Ordering::Release);
            }
        }

        struct ScriptedIo(VecDeque<&'static [u8]>);
        impl AsyncRead for ScriptedIo {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                if let Some(chunk) = self.0.pop_front() {
                    buf.put_slice(chunk);
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }
        }
        impl AsyncWrite for ScriptedIo {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Ok(buf.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        // 1. Replacing `Idle` with `Head` drops the short idle `Sleep` so its waker never fires.
        let idle = Arc::new(ConnectionIdleState::new());
        idle.enter_request();
        idle.exit_request();
        let dispatched = Arc::new(AtomicU64::new(0));
        let mut io = HeadDeadlineIo::new(
            ScriptedIo(VecDeque::from([b"GET / ".as_slice()])),
            Arc::clone(&idle),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
            Duration::from_secs(60),
            Duration::from_millis(15),
            crate::h2_stall::H2StallRegistry::new().transport(),
            Arc::clone(&dispatched),
        );
        let idle_flag = Arc::new(FlagWaker(AtomicBool::new(false)));
        let idle_waker = Waker::from(Arc::clone(&idle_flag));
        let mut idle_cx = Context::from_waker(&idle_waker);
        assert!(matches!(
            Pin::new(&mut io).poll_flush(&mut idle_cx),
            Poll::Ready(Ok(()))
        ));

        let noop = Waker::noop();
        let mut head_cx = Context::from_waker(noop);
        let mut buf = [0_u8; 32];
        let mut read_buf = ReadBuf::new(&mut buf);
        assert!(matches!(
            Pin::new(&mut io).poll_read(&mut head_cx, &mut read_buf),
            Poll::Ready(Ok(()))
        ));
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(
            !idle_flag.0.load(Ordering::Acquire),
            "replaced idle Sleep remained registered and fired a spurious wake during head phase"
        );

        // 2. Clearing a stale `Head` phase drops its short `Sleep` so its waker never fires.
        let mut io2 = HeadDeadlineIo::new(
            ScriptedIo(VecDeque::from([b"GET / ".as_slice()])),
            Arc::clone(&idle),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
            Duration::from_millis(15),
            Duration::from_secs(60),
            crate::h2_stall::H2StallRegistry::new().transport(),
            Arc::clone(&dispatched),
        );
        let head_flag = Arc::new(FlagWaker(AtomicBool::new(false)));
        let head_waker = Waker::from(Arc::clone(&head_flag));
        let mut head_cx2 = Context::from_waker(&head_waker);
        let mut buf2 = [0_u8; 32];
        let mut read_buf2 = ReadBuf::new(&mut buf2);
        assert!(matches!(
            Pin::new(&mut io2).poll_read(&mut head_cx2, &mut read_buf2),
            Poll::Ready(Ok(()))
        ));
        // Dispatching a request invalidates the phase; `poll_flush` drops the stale head timer.
        dispatched.fetch_add(1, Ordering::AcqRel);
        let mut noop_cx = Context::from_waker(noop);
        assert!(matches!(
            Pin::new(&mut io2).poll_flush(&mut noop_cx),
            Poll::Ready(Ok(()))
        ));
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(
            !head_flag.0.load(Ordering::Acquire),
            "cleared head Sleep remained registered and fired a spurious wake"
        );
    }

    /// Regression test for Diet Audit 2 P2 (`HttpBody` embedder API parity): `HttpBody::default()`
    /// and direct assignment from `.boxed()` must both compile and work as in v0.1.2.
    #[test]
    fn http_body_supports_default_and_direct_boxed_assignment() {
        use crate::HttpBody;
        use bytes::Bytes;
        use http_body::Body as _;
        use http_body_util::{BodyExt as _, Empty, Full};

        let empty_default: HttpBody = HttpBody::default();
        assert!(empty_default.is_end_stream());

        let boxed_empty: HttpBody = Empty::<Bytes>::new()
            .map_err(|never| match never {})
            .boxed();
        assert!(boxed_empty.is_end_stream());

        let boxed_full: HttpBody = Full::new(Bytes::from_static(b"ok"))
            .map_err(|never| match never {})
            .boxed();
        assert_eq!(boxed_full.size_hint().exact(), Some(2));
    }

    #[tokio::test]
    async fn tracked_request_reuses_connection_telemetry_without_cloning_arc()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::ConnWriteTracker;
        use crate::{HttpEngine, RequestContext, empty_http_body};
        use http::Request;
        use http_body_util::BodyExt as _;

        let kdl = r#"
            server {
                listen ":8443"
                tls { cert "/c.pem"; key "/k.pem" }
            }
            site "example.test" {
                route "/go" {
                    redirect "/dest"
                }
            }
        "#;
        let (cfg, _) = miraserve_config::parse_kdl("<test>", kdl)?;
        let engine = HttpEngine::from_config(
            &cfg,
            Arc::new(miraserve_tls::AcmeChallengeStore::new()),
            None,
            8443,
        )?;
        let tracker = Arc::new(ConnWriteTracker::new(Arc::clone(engine.telemetry())));
        let baseline_strong = Arc::strong_count(engine.telemetry());
        let ctx = RequestContext {
            client_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            remote_port: Some(41_000),
            server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            server_port: 443,
            is_https: true,
            tls: None,
        };

        // 1. Flushed path: telemetry Arc strong count stays constant while body is live and queued.
        let req1 = Request::builder()
            .method(Method::GET)
            .uri("/go")
            .header(http::header::HOST, "example.test")
            .body(empty_http_body())?;
        let resp1 = engine
            .handle_request_tracked(
                req1.map(PipeReqBody::from_http_body),
                &ctx,
                Some(Arc::clone(&tracker)),
                false,
            )
            .await;
        assert_eq!(
            Arc::strong_count(engine.telemetry()),
            baseline_strong,
            "tracked request must not clone Arc<TelemetryRegistry>"
        );
        let _ = resp1.into_body().collect().await?;
        assert_eq!(
            Arc::strong_count(engine.telemetry()),
            baseline_strong,
            "queued access record must reuse ConnWriteTracker's telemetry handle"
        );
        let mut scratch = Vec::new();
        tracker.mark_flushed(&mut scratch);
        assert_eq!(engine.telemetry().total_http_requests(), 1);

        // 2. Failed transport path also records the metric via ConnWriteTracker's telemetry handle.
        let req2 = Request::builder()
            .method(Method::GET)
            .uri("/go")
            .header(http::header::HOST, "example.test")
            .body(empty_http_body())?;
        let resp2 = engine
            .handle_request_tracked(
                req2.map(PipeReqBody::from_http_body),
                &ctx,
                Some(Arc::clone(&tracker)),
                false,
            )
            .await;
        assert_eq!(Arc::strong_count(engine.telemetry()), baseline_strong);
        let _ = resp2.into_body().collect().await?;
        tracker.mark_failed();
        assert_eq!(engine.telemetry().total_http_requests(), 2);
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn access_log_compact_fields_match_legacy_strings_and_ips_byte_for_byte() {
        let _tracing_serial = crate::test_tracing_lock().blocking_lock();
        // 1. Inline IpText matches IpAddr::to_string() across None, IPv4, and full/mapped IPv6.
        let ips: [Option<IpAddr>; 7] = [
            None,
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            Some(IpAddr::V4(Ipv4Addr::BROADCAST)),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            Some(IpAddr::V6(Ipv6Addr::new(
                0x2001, 0x0db8, 0x85a3, 0x1234, 0x5678, 0x8a2e, 0x0370, 0x7334,
            ))),
            Some(IpAddr::V6(Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            ))),
            Some(IpAddr::V6(Ipv4Addr::BROADCAST.to_ipv6_mapped())),
        ];
        for ip in ips {
            let expected = ip.map(|a| a.to_string()).unwrap_or_default();
            let actual = IpText::from_opt(ip);
            assert_eq!(actual.as_str(), expected.as_str(), "ip={ip:?}");
            assert_eq!(actual.to_string(), expected, "Display ip={ip:?}");
        }

        // 2. AccessLogStrings matches legacy separate-String preparation across clean, redacted,
        //    unredacted, empty, userinfo, control-escaped, inline-capacity boundaries (191/192/193
        //    bytes including multi-byte UTF-8), and >255-byte UTF-8 hosts.
        let long_ascii_host = format!("SUB.{}.EXAMPLE.COM", "A".repeat(260));
        let long_utf8_host = format!("{}EX", "é".repeat(130)); // 262 bytes, 2-byte UTF-8 chars
        let ctrl_host = format!("user:pw@HOST\x1b{}", "X".repeat(250));
        let browser_ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
        let ua_191_pad = "u".repeat(191 - ("example.test".len() + "/p".len() + "r".len()));
        let ua_192_pad = "u".repeat(192 - ("example.test".len() + "/p".len() + "r".len()));
        let ua_193_pad = "u".repeat(193 - ("example.test".len() + "/p".len() + "r".len()));
        // Multi-byte UTF-8 ('é' = 2 bytes) hitting exact 192-byte inline limit and 194-byte heap spill.
        let utf8_192_ua = "é".repeat(90); // 180 bytes + 12 bytes host/target = 192 bytes exact
        let utf8_194_ua = "é".repeat(91); // 182 bytes + 12 bytes host/target = 194 bytes -> Heap
        let cases = [
            (
                Some("example.test:8443"),
                "/1k.txt",
                Some("curl/8.5.0"),
                None,
                true,
            ),
            (
                Some("bench.local:12345"),
                "/1k.txt",
                Some(browser_ua),
                Some("https://bench.local/"),
                true,
            ),
            (
                Some("example.test"),
                "/p",
                Some(ua_191_pad.as_str()),
                Some("r"),
                true,
            ),
            (
                Some("example.test"),
                "/p",
                Some(ua_192_pad.as_str()),
                Some("r"),
                true,
            ),
            (
                Some("example.test"),
                "/p",
                Some(ua_193_pad.as_str()),
                Some("r"),
                true,
            ),
            (
                Some("EX.TEST"),
                "/café",
                Some(utf8_192_ua.as_str()),
                None,
                true,
            ),
            (
                Some("EX.TEST"),
                "/café",
                Some(utf8_194_ua.as_str()),
                None,
                true,
            ),
            (None, "/", None, None, true),
            (
                Some("EXAMPLE.COM:443"),
                "/cb?token=secret123&ok=1",
                Some("Bearer eyJabc.def"),
                Some("https://ann:pw@ref.example/p?code=999&ok=1"),
                true,
            ),
            (
                Some("EXAMPLE.COM:443"),
                "/cb?token=secret123&ok=1",
                Some("Bearer eyJabc.def"),
                Some("https://ann:pw@ref.example/p?code=999&ok=1"),
                false,
            ),
            (
                Some(&long_ascii_host),
                "/a",
                Some("ua"),
                Some("https://r"),
                true,
            ),
            (
                Some(&long_utf8_host),
                "/caf\u{e9}\n",
                Some("ua\t1"),
                Some("ref\r"),
                true,
            ),
            (
                Some(&ctrl_host),
                "/x",
                None,
                Some("https://ref.test/?a=1"),
                false,
            ),
            (Some(""), "/empty-host", Some(""), Some(""), true),
        ];

        for (raw_host, raw_target, raw_ua, raw_ref, redact) in cases {
            let expected_target = if redact {
                redact_request_target(raw_target)
            } else {
                escape_log_controls(raw_target)
            };
            let expected_host = raw_host
                .map(|raw| {
                    let raw = raw.rsplit_once('@').map_or(raw, |(_, h)| h);
                    let mut h = escape_log_controls_cow(raw).into_owned();
                    h.make_ascii_lowercase();
                    if h.len() > 255 {
                        let mut cut = 255;
                        while !h.is_char_boundary(cut) {
                            cut = cut.saturating_sub(1);
                        }
                        h.truncate(cut);
                    }
                    h
                })
                .unwrap_or_default();
            let expected_ref = raw_ref
                .map(|raw| {
                    if redact {
                        redact_uri_query(raw)
                    } else {
                        escape_log_controls(raw)
                    }
                })
                .unwrap_or_default();
            let expected_ua = raw_ua
                .map(|raw| {
                    if redact {
                        redact_header_value(&http::header::USER_AGENT, raw)
                    } else {
                        escape_log_controls(raw)
                    }
                })
                .unwrap_or_default();

            let expected_total = expected_host.len()
                + expected_target.len()
                + expected_ua.len()
                + expected_ref.len();
            let packed =
                AccessLogStrings::from_raw_parts(raw_host, raw_target, raw_ua, raw_ref, redact);
            assert_eq!(packed.len(), expected_total, "len {raw_host:?}");
            assert_eq!(
                matches!(packed, AccessLogStrings::Inline { .. }),
                expected_total <= ACCESS_LOG_INLINE_CAP,
                "inline vs heap storage mismatch for total={expected_total}"
            );
            assert_eq!(packed.host(), expected_host.as_str(), "host {raw_host:?}");
            assert_eq!(
                packed.target(),
                expected_target.as_str(),
                "target {raw_target:?}"
            );
            assert_eq!(packed.user_agent(), expected_ua.as_str(), "ua {raw_ua:?}");
            assert_eq!(packed.referer(), expected_ref.as_str(), "ref {raw_ref:?}");
        }

        // 3. Standard and custom extension Methods (both inline <=15 and heap-allocated >15)
        //    format identically between direct formatter and tracing-subscriber.
        for method_bytes in [b"GET".as_slice(), b"PROPFIND", b"CUSTOMLONGEXTMETHODNAME"] {
            let Ok(method) = Method::from_bytes(method_bytes) else {
                continue;
            };
            let capture = Capture::default();
            let writer = capture.clone();
            let subscriber = tracing_subscriber::fmt()
                .with_target(false)
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish();
            let mut rec = record("curl/8.5.0");
            rec.method = method.clone();
            tracing::subscriber::with_default(subscriber, || {
                rec.emit(None, 42, true, TransportDelivery::Confirmed);
            });
            let traced = String::from_utf8(capture.0.lock().map(|b| b.clone()).unwrap_or_default())
                .unwrap_or_default();
            let latency = traced
                .split(" latency_us=")
                .nth(1)
                .and_then(|rest| rest.split(' ').next())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            let mut direct = String::new();
            let mut rec2 = record("curl/8.5.0");
            rec2.method = method;
            rec2.format_line(
                &mut direct,
                std::time::SystemTime::now(),
                "http request completed",
                AccessLineFields {
                    bytes_sent: 42,
                    body_complete: true,
                    delivery: TransportDelivery::Confirmed.as_str(),
                    completed: true,
                    latency_us: latency,
                },
            );
            let after = |line: &str| line.split_once("Z ").map(|(_, r)| r.to_owned());
            assert_eq!(after(&direct), after(&traced));
        }
    }

    /// M015 Intersection 6: Verifies that `SERVICE_FUTURE_MAX_BYTES` (2048) still holds for the
    /// outer Hyper service future (matching `serve_hyper_connection`'s `fut` shape; cache adds 0
    /// bytes to the outer boxed future) and prints the exact sizes of the outer service future,
    /// the boxed `handle_request_tracked` pipeline future, and the boxed
    /// `handle_redirect_listener_request_with_upgrade` pipeline future.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn m015_intersection_6_boxed_service_future_and_pipeline_sizes()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::Arc;

        use http::{Request, Response, StatusCode, Version};
        use http_body_util::BodyExt as _;
        use miraserve_config::{LimitsConfig, TimeoutsConfig, parse_kdl};
        use miraserve_security::ConnectionFloodGuard;
        use miraserve_tls::AcmeChallengeStore;

        use crate::{
            ConnShared, ConnWriteTracker, ConnectionIdleState, HttpEngine, HyperResponseBody,
            InFlightRequestGuard, PipeReqBody, RequestContext, SERVICE_FUTURE_MAX_BYTES,
            ServerFramingRejection, h2_stall,
        };

        let (cfg, _) = parse_kdl(
            "future-size.kdl",
            r#"
server {
    listen "127.0.0.1:8443" protocols="h1"
}
site "future.example.test" {
    route "/" {
        respond 404
    }
}
"#,
        )?;
        let engine = Arc::new(HttpEngine::from_config(
            &cfg,
            Arc::new(AcmeChallengeStore::new()),
            None,
            8443,
        )?);
        let write_tracker = Arc::new(ConnWriteTracker::new(Arc::clone(engine.telemetry())));
        let (bad_req_close_tx, _rx) = tokio::sync::watch::channel(false);
        let limits = LimitsConfig::default();
        let flood_guard = Arc::new(ConnectionFloodGuard::from_limits(&limits));
        let shared = Arc::new(ConnShared {
            engine: Arc::clone(&engine),
            limits,
            timeouts: TimeoutsConfig::default(),
            flood_guard,
            bad_req_close_tx,
            idle_state: Arc::new(ConnectionIdleState::new()),
            upgrade_template: None,
            write_tracker: Arc::clone(&write_tracker),
            h2_streams: h2_stall::H2StallRegistry::new(),
            ctx: RequestContext {
                client_ip: None,
                remote_port: None,
                server_addr: None,
                server_port: 8443,
                is_https: true,
                tls: None,
            },
            redirect_only: false,
        });

        // 1. Exact outer service future shape from `serve_hyper_connection`.
        let outer_shared = Arc::clone(&shared);
        let idle_guard = InFlightRequestGuard::enter(Some(Arc::clone(&outer_shared.idle_state)));
        let redirect_upgrade_lc: Option<miraserve_proxy::UpgradeLifecycle> = None;
        let is_h2_request = false;
        let mapped: Request<PipeReqBody> = Request::builder().uri("/").body(PipeReqBody::Empty)?;
        let outer_fut = async move {
            let mut mapped = mapped;
            if !outer_shared.redirect_only {
                if mapped.version() == Version::HTTP_11
                    && mapped.headers().contains_key(http::header::UPGRADE)
                    && let Some(lc) = &outer_shared.upgrade_template
                {
                    mapped.extensions_mut().insert(lc.clone());
                }
                let (parts, mut body) = Box::pin(outer_shared.engine.handle_request_tracked(
                    mapped,
                    &outer_shared.ctx,
                    Some(Arc::clone(&outer_shared.write_tracker)),
                    false,
                ))
                .await
                .into_parts();
                if parts.extensions.get::<ServerFramingRejection>().is_some()
                    && matches!(
                        parts.status,
                        StatusCode::BAD_REQUEST | StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
                    )
                    && !outer_shared.flood_guard.record_bad_request()
                {
                    let _ = outer_shared.bad_req_close_tx.send(true);
                }
                if parts.status == StatusCode::SWITCHING_PROTOCOLS {
                    idle_guard.disarm_for_upgrade();
                    return Ok::<_, std::convert::Infallible>(Response::from_parts(
                        parts,
                        HyperResponseBody::Direct(body),
                    ));
                }
                idle_guard.attach_to_access_log_body(&mut body);
                let resp = if is_h2_request && !http_body::Body::is_end_stream(&body) {
                    Response::from_parts(
                        parts,
                        HyperResponseBody::H2Stalled(
                            outer_shared.h2_streams.guard_access_log(body),
                        ),
                    )
                } else {
                    Response::from_parts(parts, HyperResponseBody::Direct(body))
                };
                return Ok::<_, std::convert::Infallible>(resp);
            }
            let (resp, kept_redirect_request) = Box::pin(
                outer_shared
                    .engine
                    .handle_redirect_listener_request_with_upgrade(
                        mapped,
                        &outer_shared.ctx,
                        redirect_upgrade_lc,
                        Some(&outer_shared.write_tracker),
                        false,
                    ),
            )
            .await;
            if resp.extensions().get::<ServerFramingRejection>().is_some()
                && matches!(
                    resp.status(),
                    StatusCode::BAD_REQUEST | StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
                )
                && !outer_shared.flood_guard.record_bad_request()
            {
                let _ = outer_shared.bad_req_close_tx.send(true);
            }
            if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
                idle_guard.disarm_for_upgrade();
                return Ok::<_, std::convert::Infallible>(resp);
            }
            let resp = match resp.into_parts() {
                (parts, HyperResponseBody::Direct(mut body)) => {
                    idle_guard.attach_to_access_log_body(&mut body);
                    if is_h2_request && !http_body::Body::is_end_stream(&body) {
                        Response::from_parts(
                            parts,
                            HyperResponseBody::H2Stalled(
                                outer_shared.h2_streams.guard_access_log(body),
                            ),
                        )
                    } else {
                        Response::from_parts(parts, HyperResponseBody::Direct(body))
                    }
                }
                (parts, HyperResponseBody::Plain(body)) => {
                    let resp = idle_guard.attach_to_hyper_body(Response::from_parts(parts, body));
                    if is_h2_request && !http_body::Body::is_end_stream(resp.body()) {
                        resp.map(|body| {
                            HyperResponseBody::Plain(
                                outer_shared.h2_streams.guard_counting(body.boxed(), None),
                            )
                        })
                    } else {
                        resp
                    }
                }
                (parts, other) => Response::from_parts(parts, other),
            };
            drop(kept_redirect_request);
            Ok::<_, std::convert::Infallible>(resp)
        };
        let outer_size = std::mem::size_of_val(&outer_fut);
        drop(outer_fut);

        // 2. Inner boxed pipeline future (`handle_request_tracked`).
        let req2 = Request::builder().uri("/").body(PipeReqBody::Empty)?;
        let pipeline_fut = engine.handle_request_tracked(
            req2,
            &shared.ctx,
            Some(Arc::clone(&write_tracker)),
            false,
        );
        let pipeline_size = std::mem::size_of_val(&pipeline_fut);
        drop(pipeline_fut);

        // 3. Inner boxed redirect pipeline future (`handle_redirect_listener_request_with_upgrade`).
        let req3 = Request::builder().uri("/").body(PipeReqBody::Empty)?;
        let redirect_fut = engine.handle_redirect_listener_request_with_upgrade(
            req3,
            &shared.ctx,
            None,
            Some(&write_tracker),
            false,
        );
        let redirect_size = std::mem::size_of_val(&redirect_fut);
        drop(redirect_fut);

        println!(
            "M015_FUTURE_SIZES outer_service={outer_size} pipeline_tracked={pipeline_size} redirect_pipeline={redirect_size} limit={SERVICE_FUTURE_MAX_BYTES}"
        );
        assert!(
            outer_size <= SERVICE_FUTURE_MAX_BYTES,
            "outer service future ({outer_size} B) exceeds SERVICE_FUTURE_MAX_BYTES ({SERVICE_FUTURE_MAX_BYTES} B)"
        );
        Ok(())
    }

    /// Verifies `HeadDeadlineIo::poll_write_vectored` feeds only the accepted short prefix
    /// across multiple `IoSlice`s containing interleaved HTTP/2 frames of several streams,
    /// advancing `TransportWriteState` by the exact DATA payload bytes and nothing else.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn head_deadline_io_vectored_short_prefix_counts_exact_data_across_streams() {
        use super::{ConnectionIdleState, HeadDeadlineIo};
        use http_body_util::BodyExt as _;
        use std::io::{self, IoSlice};
        use std::pin::Pin;
        use std::sync::atomic::{AtomicBool, AtomicU64};
        use std::task::{Context, Poll, Waker};
        use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

        struct ShortVectoredIo {
            max_accept: usize,
            accepted_bytes: Vec<u8>,
        }

        impl AsyncRead for ShortVectoredIo {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }
        }

        impl AsyncWrite for ShortVectoredIo {
            fn poll_write(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                let take = buf.len().min(self.max_accept);
                if let Some(part) = buf.get(..take) {
                    self.accepted_bytes.extend_from_slice(part);
                }
                Poll::Ready(Ok(take))
            }

            fn poll_write_vectored(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                bufs: &[IoSlice<'_>],
            ) -> Poll<io::Result<usize>> {
                let mut left = self.max_accept;
                let mut total = 0_usize;
                for slice in bufs {
                    if left == 0 {
                        break;
                    }
                    let take = slice.len().min(left);
                    if let Some(part) = slice.get(..take) {
                        self.accepted_bytes.extend_from_slice(part);
                    }
                    total += take;
                    left -= take;
                }
                Poll::Ready(Ok(total))
            }

            fn is_write_vectored(&self) -> bool {
                true
            }

            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let make_frame = |kind: u8, stream_id: u32, payload_len: usize| -> Vec<u8> {
            let mut out = Vec::with_capacity(9 + payload_len);
            let len_u32 = u32::try_from(payload_len).unwrap_or(0);
            out.push(u8::try_from((len_u32 >> 16) & 0xff).unwrap_or(0));
            out.push(u8::try_from((len_u32 >> 8) & 0xff).unwrap_or(0));
            out.push(u8::try_from(len_u32 & 0xff).unwrap_or(0));
            out.push(kind);
            out.push(0);
            out.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
            out.extend(std::iter::repeat_n(0x55_u8, payload_len));
            out
        };

        let f1_hdr = make_frame(1, 1, 17);
        let f1_data = make_frame(0, 1, 500);
        let f3_data = make_frame(0, 3, 1_200);
        let f0_settings = make_frame(4, 0, 6);
        let f5_hdr = make_frame(1, 5, 29);
        let f5_data = make_frame(0, 5, 4_095);

        let mut full_wire = Vec::new();
        for part in [&f1_hdr, &f1_data, &f3_data, &f0_settings, &f5_hdr, &f5_data] {
            full_wire.extend_from_slice(part);
        }

        let registry = crate::h2_stall::H2StallRegistry::new();
        let transport = registry.transport();
        let expected_data = 500_usize + 1_200 + 4_095;
        let mut guarded_body = registry.guard(crate::full_http_body(bytes::Bytes::from(vec![
            0x55_u8;
            expected_data
        ])));
        while guarded_body.frame().await.is_some() {}
        drop(guarded_body);
        assert!(transport.is_delivering(Duration::from_secs(30)));

        let mut head_io = HeadDeadlineIo::new(
            ShortVectoredIo {
                max_accept: 313,
                accepted_bytes: Vec::new(),
            },
            Arc::new(ConnectionIdleState::new()),
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicBool::new(false)),
            Duration::from_secs(30),
            Duration::from_secs(60),
            Arc::clone(&transport),
            Arc::new(AtomicU64::new(0)),
        );
        assert!(head_io.is_write_vectored());

        let noop = Waker::noop();
        let mut cx = Context::from_waker(noop);
        let mut offset = 0_usize;
        while offset < full_wire.len() {
            // Split remaining bytes into 3 unequal slices to exercise cross-slice prefixes.
            let rem = full_wire.get(offset..).unwrap_or(&[]);
            let cut1 = rem.len().min(7);
            let cut2 = rem.len().min(cut1 + 211);
            let s1 = rem.get(..cut1).unwrap_or(&[]);
            let s2 = rem.get(cut1..cut2).unwrap_or(&[]);
            let s3 = rem.get(cut2..).unwrap_or(&[]);
            let bufs = [IoSlice::new(s1), IoSlice::new(s2), IoSlice::new(s3)];
            match Pin::new(&mut head_io).poll_write_vectored(&mut cx, &bufs) {
                Poll::Ready(Ok(n)) => {
                    assert!(n > 0);
                    offset += n;
                }
                other => assert!(
                    matches!(other, Poll::Ready(Ok(_))),
                    "unexpected write outcome: {other:?}"
                ),
            }
            if offset < full_wire.len() {
                // Before the final DATA frame is fully accepted, delivery is still in progress.
                assert!(transport.is_delivering(Duration::from_secs(30)));
            }
        }
        assert_eq!(head_io.inner.accepted_bytes, full_wire);
        // Once every DATA byte has been accepted, handed == written so delivery is complete.
        assert!(!transport.is_delivering(Duration::from_secs(30)));
    }

    fn h2_exec_test_lock() -> &'static tokio::sync::Mutex<()> {
        crate::h2_intask::h2_exec_test_lock()
    }

    /// Full `HttpEngine::serve_hyper_connection_with_control` panic isolation over real TCP on a
    /// single-thread runtime: a panicking route resets only its own HTTP/2 stream
    /// (`RST_STREAM(CANCEL)`), drops its `InFlightRequestGuard` (so `idle_state` returns to idle),
    /// restores the non-blocking inline context guard on the OS thread, leaves concurrent sibling
    /// streams intact, and keeps the connection alive for subsequent requests.
    #[tokio::test(flavor = "current_thread")]
    #[allow(clippy::too_many_lines)]
    async fn h2_intask_engine_panicking_handler_resets_only_that_stream_and_releases_inflight()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use bytes::Bytes;
        use http_body_util::{BodyExt as _, Empty};
        use hyper::client::conn::http2 as h2_client;
        use hyper_util::rt::{TokioExecutor, TokioIo};
        use miraserve_config::parse_kdl;
        use miraserve_tls::AcmeChallengeStore;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio::net::{TcpListener, TcpStream};
        use tokio::sync::{Notify, watch};

        use crate::{
            ConnectionControl, ConnectionIdleState, HttpEngine, test_h2_exec_override_guard,
            test_h2_exec_stream_counts, test_h2_handoff_mismatch_count,
        };

        static SEQ: AtomicUsize = AtomicUsize::new(1);

        let _serial = h2_exec_test_lock().lock().await;
        let _exec_guard = test_h2_exec_override_guard(Some(true));
        let (intask_before, spawned_before) = test_h2_exec_stream_counts();
        let mismatches_before = test_h2_handoff_mismatch_count();
        let root = std::env::temp_dir().join(format!(
            "miraserve-h2it-panic-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root)?;
        std::fs::write(root.join("ok.txt"), b"static-ok")?;

        // Controllable HTTP/1.1 upstream to hold a concurrent sibling stream in flight.
        let up_listener = TcpListener::bind("127.0.0.1:0").await?;
        let up_port = up_listener.local_addr()?.port();
        let up_entered = Arc::new(Notify::new());
        let up_release = Arc::new(Notify::new());
        let up_entered_srv = Arc::clone(&up_entered);
        let up_release_srv = Arc::clone(&up_release);
        let up_task = tokio::spawn(async move {
            if let Ok((mut sock, _)) = up_listener.accept().await {
                let mut buf = [0_u8; 2048];
                let _ = sock.read(&mut buf).await;
                up_entered_srv.notify_one();
                up_release_srv.notified().await;
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\nconnection: close\r\n\r\nsibling-ok",
                    )
                    .await;
            }
        });

        let kdl = format!(
            r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "h2it.example.test" {{
    root "{root}"
    route "/slow/*" {{
        reverse-proxy {{
            upstream "http://127.0.0.1:{up_port}"
        }}
    }}
}}
"#,
            root = root.to_string_lossy().replace('\\', "/")
        );
        let (cfg, _) = parse_kdl("h2it-panic.kdl", &kdl)?;
        let engine = Arc::new(HttpEngine::from_config(
            &cfg,
            Arc::new(AcmeChallengeStore::new()),
            None,
            8443,
        )?);
        engine.set_test_panic_path(Some("/panic"));

        let srv_listener = TcpListener::bind("127.0.0.1:0").await?;
        let srv_addr = srv_listener.local_addr()?;
        let idle_state = Arc::new(ConnectionIdleState::new());
        let idle_state_srv = Arc::clone(&idle_state);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let eng_srv = Arc::clone(&engine);
        let srv_task = tokio::spawn(async move {
            if let Ok((tcp, peer)) = srv_listener.accept().await {
                let _ = tcp.set_nodelay(true);
                let local = tcp.local_addr().unwrap_or(srv_addr);
                eng_srv
                    .serve_hyper_connection_with_control(
                        tcp,
                        peer,
                        local,
                        true,
                        false,
                        None,
                        shutdown_rx,
                        ConnectionControl {
                            idle_state: Some(idle_state_srv),
                            ..ConnectionControl::default()
                        },
                    )
                    .await;
            }
        });

        let client_tcp = TcpStream::connect(srv_addr).await?;
        let _ = client_tcp.set_nodelay(true);
        let (mut sender, conn) = h2_client::handshake::<_, _, Empty<Bytes>>(
            TokioExecutor::new(),
            TokioIo::new(client_tcp),
        )
        .await?;
        let conn_task = tokio::spawn(async move {
            let _ = conn.await;
        });

        // 1. Open slow sibling stream on the connection.
        sender.ready().await?;
        let slow_fut = sender.send_request(
            http::Request::builder()
                .uri("https://h2it.example.test/slow/item")
                .body(Empty::new())?,
        );
        tokio::time::timeout(Duration::from_secs(5), up_entered.notified()).await?;
        assert_eq!(
            idle_state.idle_since_ms(),
            0,
            "connection must not be idle while /slow is in flight"
        );

        // 2. Send panicking request concurrently.
        sender.ready().await?;
        let panic_res = sender
            .send_request(
                http::Request::builder()
                    .uri("https://h2it.example.test/panic")
                    .body(Empty::new())?,
            )
            .await;
        let Err(panic_err) = panic_res else {
            let _ = std::fs::remove_dir_all(&root);
            return Err("panicking /panic stream must fail with RST_STREAM".into());
        };
        let mut text = panic_err.to_string();
        let mut src = std::error::Error::source(&panic_err);
        while let Some(cause) = src {
            text.push_str(": ");
            text.push_str(&cause.to_string());
            src = cause.source();
        }
        assert!(
            text.contains("stream no longer needed"),
            "expected RST_STREAM(CANCEL) from panicking handler, got: {text}"
        );

        // 3. Release `/slow`: must complete cleanly with exact body.
        up_release.notify_one();
        let slow_resp = tokio::time::timeout(Duration::from_secs(5), slow_fut).await??;
        assert_eq!(slow_resp.status(), http::StatusCode::OK);
        assert_eq!(
            slow_resp.into_body().collect().await?.to_bytes().as_ref(),
            b"sibling-ok"
        );

        // 4. Verify in-flight counter returned to 0 (connection becomes idle).
        let idle_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while idle_state.idle_since_ms() == 0 && tokio::time::Instant::now() < idle_deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            idle_state.idle_since_ms() > 0,
            "idle_state must become idle once /panic was reset and /slow finished"
        );

        // 5. Also panic inside a SPAWNED stream (`/slow/panic`, reverse-proxy route) on the SAME
        //    connection: Tokio catches the unwind identically to v0.1.4, resets only that stream,
        //    and leaves the connection alive.
        engine.set_test_panic_path(Some("/slow/panic"));
        sender.ready().await?;
        let spawned_panic_res = sender
            .send_request(
                http::Request::builder()
                    .uri("https://h2it.example.test/slow/panic")
                    .body(Empty::new())?,
            )
            .await;
        let Err(spawned_panic_err) = spawned_panic_res else {
            let _ = std::fs::remove_dir_all(&root);
            return Err("panicking spawned /slow/panic stream must fail with RST_STREAM".into());
        };
        let mut sp_text = spawned_panic_err.to_string();
        let mut sp_src = std::error::Error::source(&spawned_panic_err);
        while let Some(cause) = sp_src {
            sp_text.push_str(": ");
            sp_text.push_str(&cause.to_string());
            sp_src = cause.source();
        }
        assert!(
            sp_text.contains("stream no longer needed"),
            "expected RST_STREAM(CANCEL) from panicking spawned stream, got: {sp_text}"
        );
        let idle_deadline2 = tokio::time::Instant::now() + Duration::from_secs(3);
        while idle_state.idle_since_ms() == 0 && tokio::time::Instant::now() < idle_deadline2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            idle_state.idle_since_ms() > 0,
            "idle_state must become idle once spawned /slow/panic was reset"
        );

        // 6. Follow-up static request on the same connection still succeeds.
        assert!(!conn_task.is_finished());
        sender.ready().await?;
        let ok_resp = sender
            .send_request(
                http::Request::builder()
                    .uri("https://h2it.example.test/ok.txt")
                    .body(Empty::new())?,
            )
            .await?;
        assert_eq!(ok_resp.status(), http::StatusCode::OK);
        assert_eq!(
            ok_resp.into_body().collect().await?.to_bytes().as_ref(),
            b"static-ok"
        );
        let (intask_after, spawned_after) = test_h2_exec_stream_counts();
        assert_eq!(
            (intask_after - intask_before, spawned_after - spawned_before),
            (2, 2),
            "expected 2 in-task streams (/panic, /ok.txt) and 2 spawned proxy streams (/slow/item, /slow/panic)"
        );
        assert_eq!(
            test_h2_handoff_mismatch_count(),
            mismatches_before,
            "expected zero hand-off mismatches"
        );
        assert!(
            !crate::inline_work_must_not_block(),
            "non-blocking context must remain false outside stream polls after panic"
        );

        drop(sender);
        up_task.abort();
        let _ = tokio::time::timeout(Duration::from_secs(5), conn_task).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), srv_task).await;
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    /// Client `RST_STREAM` while an HTTP/2 stream future is pending drops the stream future
    /// promptly (closing the upstream connection) and returns `ConnectionIdleState` to idle.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn h2_intask_client_reset_while_pending_drops_future_and_zeroes_inflight()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use bytes::Bytes;
        use http_body_util::{BodyExt as _, Empty};
        use hyper::client::conn::http2 as h2_client;
        use hyper_util::rt::{TokioExecutor, TokioIo};
        use miraserve_config::parse_kdl;
        use miraserve_tls::AcmeChallengeStore;
        use tokio::io::AsyncReadExt as _;
        use tokio::net::{TcpListener, TcpStream};
        use tokio::sync::{Notify, watch};

        use crate::{
            ConnectionControl, ConnectionIdleState, HttpEngine, test_h2_exec_override_guard,
            test_h2_exec_stream_counts, test_h2_handoff_mismatch_count,
        };

        static SEQ: AtomicUsize = AtomicUsize::new(1);

        let _serial = h2_exec_test_lock().lock().await;
        let _exec_guard = test_h2_exec_override_guard(Some(true));
        let (intask_before, spawned_before) = test_h2_exec_stream_counts();
        let mismatches_before = test_h2_handoff_mismatch_count();
        let root = std::env::temp_dir().join(format!(
            "miraserve-h2it-reset-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root)?;
        std::fs::write(root.join("ok.txt"), b"after-reset")?;

        let up_listener = TcpListener::bind("127.0.0.1:0").await?;
        let up_port = up_listener.local_addr()?.port();
        let up_entered = Arc::new(Notify::new());
        let up_saw_drop = Arc::new(Notify::new());
        let up_entered_srv = Arc::clone(&up_entered);
        let up_saw_drop_srv = Arc::clone(&up_saw_drop);
        let up_task = tokio::spawn(async move {
            if let Ok((mut sock, _)) = up_listener.accept().await {
                let mut buf = [0_u8; 2048];
                let _ = sock.read(&mut buf).await;
                up_entered_srv.notify_one();
                // Wait until the server drops the pending proxy future and closes the upstream
                // TCP connection (EOF on read).
                let mut probe = [0_u8; 64];
                loop {
                    match sock.read(&mut probe).await {
                        Ok(0) | Err(_) => {
                            up_saw_drop_srv.notify_one();
                            break;
                        }
                        Ok(_) => {}
                    }
                }
            }
        });

        let kdl = format!(
            r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "h2it-reset.example.test" {{
    root "{root}"
    route "/hang/*" {{
        reverse-proxy {{
            upstream "http://127.0.0.1:{up_port}"
        }}
    }}
}}
"#,
            root = root.to_string_lossy().replace('\\', "/")
        );
        let (cfg, _) = parse_kdl("h2it-reset.kdl", &kdl)?;
        let engine = Arc::new(HttpEngine::from_config(
            &cfg,
            Arc::new(AcmeChallengeStore::new()),
            None,
            8443,
        )?);

        let srv_listener = TcpListener::bind("127.0.0.1:0").await?;
        let srv_addr = srv_listener.local_addr()?;
        let idle_state = Arc::new(ConnectionIdleState::new());
        let idle_state_srv = Arc::clone(&idle_state);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let srv_task = tokio::spawn(async move {
            if let Ok((tcp, peer)) = srv_listener.accept().await {
                let _ = tcp.set_nodelay(true);
                let local = tcp.local_addr().unwrap_or(srv_addr);
                engine
                    .serve_hyper_connection_with_control(
                        tcp,
                        peer,
                        local,
                        true,
                        false,
                        None,
                        shutdown_rx,
                        ConnectionControl {
                            idle_state: Some(idle_state_srv),
                            ..ConnectionControl::default()
                        },
                    )
                    .await;
            }
        });

        let client_tcp = TcpStream::connect(srv_addr).await?;
        let _ = client_tcp.set_nodelay(true);
        let (mut sender, conn) = h2_client::handshake::<_, _, Empty<Bytes>>(
            TokioExecutor::new(),
            TokioIo::new(client_tcp),
        )
        .await?;
        let conn_task = tokio::spawn(async move {
            let _ = conn.await;
        });

        sender.ready().await?;
        let pending_fut = sender.send_request(
            http::Request::builder()
                .uri("https://h2it-reset.example.test/hang/1")
                .body(Empty::new())?,
        );
        // Drive the future until the upstream has received the request.
        let cancel_handle = tokio::spawn(async move {
            let _ = pending_fut.await;
        });
        tokio::time::timeout(Duration::from_secs(5), up_entered.notified()).await?;
        assert_eq!(
            idle_state.idle_since_ms(),
            0,
            "connection must not be idle while /hang/1 is pending"
        );

        // Cancel the client's response future -> hyper client sends `RST_STREAM(CANCEL)`.
        cancel_handle.abort();
        let _ = cancel_handle.await;

        // Server MUST drop the pending stream future (upstream observes socket close) AND
        // decrement the in-flight counter back to zero.
        tokio::time::timeout(Duration::from_secs(5), up_saw_drop.notified()).await?;
        let idle_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while idle_state.idle_since_ms() == 0 && tokio::time::Instant::now() < idle_deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            idle_state.idle_since_ms() > 0,
            "in-flight counter must return to 0 after client RST_STREAM"
        );

        // Connection stays alive for subsequent requests.
        sender.ready().await?;
        let ok_resp = sender
            .send_request(
                http::Request::builder()
                    .uri("https://h2it-reset.example.test/ok.txt")
                    .body(Empty::new())?,
            )
            .await?;
        assert_eq!(ok_resp.status(), http::StatusCode::OK);
        assert_eq!(
            ok_resp.into_body().collect().await?.to_bytes().as_ref(),
            b"after-reset"
        );
        let (intask_after, spawned_after) = test_h2_exec_stream_counts();
        assert_eq!(
            (intask_after - intask_before, spawned_after - spawned_before),
            (1, 1),
            "expected /ok.txt to run in-task and /hang/1 reverse-proxy to run spawned"
        );
        assert_eq!(
            test_h2_handoff_mismatch_count(),
            mismatches_before,
            "expected zero hand-off mismatches"
        );

        drop(sender);
        up_task.abort();
        let _ = tokio::time::timeout(Duration::from_secs(5), conn_task).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), srv_task).await;
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn p1_b_offloaded_access_log_queue_bounds_and_drops_oldest() {
        use super::OffloadAccessLogItem;
        use super::offload_queue::OffloadLogQueue;

        fn noop_report(_: u64) {}

        let q = OffloadLogQueue::<OffloadAccessLogItem>::new(
            64,
            3,
            Duration::from_secs(30),
            noop_report,
        );

        for i in 0_u8..5 {
            q.push_bounded_for_test(OffloadAccessLogItem::FormattedLine {
                bytes: vec![b'0' + i; 16],
                test_sink: None,
            });
        }
        q.inspect_queue_for_test(|queue, total_bytes| {
            assert_eq!(queue.len(), 3, "queue must cap at max_records=3");
            assert_eq!(total_bytes, 48);
            let retained: Vec<u8> = queue
                .iter()
                .filter_map(|item| match item {
                    OffloadAccessLogItem::FormattedLine { bytes, .. } => bytes.first().copied(),
                    OffloadAccessLogItem::TracingRecord { .. } => None,
                })
                .collect();
            assert_eq!(retained, vec![b'2', b'3', b'4']);
        });
        assert_eq!(q.dropped_total(), 2, "two oldest records must be dropped");

        // Byte-limit eviction: pushing a 40-byte line drops oldest until <= 64 bytes.
        q.push_bounded_for_test(OffloadAccessLogItem::FormattedLine {
            bytes: vec![b'X'; 40],
            test_sink: None,
        });
        q.inspect_queue_for_test(|queue, total_bytes| {
            assert!(total_bytes <= 64);
            assert_eq!(queue.len(), 2);
        });
        assert_eq!(q.dropped_total(), 4);
    }

    #[test]
    fn p1_c_select_h2_exec_mode_rules() {
        use super::{H2ExecMode, select_h2_exec_mode};

        let no_h2 = select_h2_exec_mode(false, false, false);
        assert_eq!(no_h2.mode, H2ExecMode::Spawned);
        let no_h2_static = select_h2_exec_mode(false, true, false);
        assert_eq!(no_h2_static.mode, H2ExecMode::Spawned);

        // Round 6: a configuration with no static work has nothing that would run in-task, so it
        // selects Spawned (`TokioExecutor`, zero overhead, exact v0.1.4) on every platform/kernel.
        let h2_proxy = select_h2_exec_mode(true, false, false);
        assert_eq!(h2_proxy.mode, H2ExecMode::Spawned);
        assert!(
            h2_proxy.reason.contains("no static file work"),
            "expected no-static-work reason, got: {}",
            h2_proxy.reason
        );
    }
}

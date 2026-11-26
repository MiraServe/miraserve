//! End-to-end reverse-proxy truncation tests over real TCP + TLS 1.3 (HTTP/2 and HTTP/1.1),
//! in default (`workers "shared"`) mode and with dedicated per-worker upstream pools (`workers`),
//! against a raw TCP upstream server we control.
//!
//! Cases covered for every `(protocol, runtime_mode)` combination:
//! - (a) Upstream answers `Content-Length: 100000`, sends `10000` bytes, and closes cleanly (FIN).
//! - (b) Upstream answers `Transfer-Encoding: chunked`, sends two chunks, and closes without the
//!   terminating `0\r\n\r\n` chunk.
//! - (c) Upstream sends the `200 OK` head and initial body bytes, waits for the client to observe
//!   the head and mid-body bytes, then resets the connection (`SO_LINGER 0`) mid-body.
//! - (d) Control: complete `100000`-byte bodies (`Content-Length` and chunked) arrive intact with
//!   clean end-of-stream.
//!
//! Assertions for (a)-(c):
//! - Client NEVER observes a complete response:
//!   - HTTP/2: the stream ends with an error (`RST_STREAM` / client body error), never a clean
//!     `END_STREAM` with fewer bytes than declared.
//!   - HTTP/1.1: the connection closes short of the declared length or without the terminating
//!     chunk, the client's body read reports an error, and the connection cannot be reused for
//!     another request.
//! - The server stays up and the next request on a new connection succeeds with the full control
//!   body intact.
//! - The truncated upstream connection is closed and NEVER returned to the upstream pool: the next
//!   request opens a new upstream connection (verified by counting `accept()` calls on the raw TCP
//!   upstream).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, HOST, TRANSFER_ENCODING};
use http::{Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper::client::conn::{http1 as h1_client, http2 as h2_client};
use hyper_util::rt::{TokioExecutor, TokioIo};
use miraserve_config::{ConfigStore, parse_kdl};
use miraserve_core::{ListenerKind, MiraServeServer, RunningServer, ServerOptions};
use miraserve_http::{
    ProxyClientSlot, ProxyPoolEvent, flush_offloaded_logs_until_blocking,
    test_access_log_sink_override_guard, test_proxy_pool_observer_guard,
};
use miraserve_tls::build_crypto_provider;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const FULL_LEN: usize = 100_000;
const PARTIAL_LEN: usize = 10_000;
const CHUNK1_LEN: usize = 5_000;
const CHUNK2_LEN: usize = 5_000;
const IO_TIMEOUT: Duration = Duration::from_secs(15);

/// Serializes tests in this binary because they install the process-wide proxy pool observer
/// and access-log sink override guards.
fn proxy_trunc_test_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

struct PostRuntimeFlushGuard;

impl Drop for PostRuntimeFlushGuard {
    fn drop(&mut self) {
        let _ = flush_offloaded_logs_until_blocking(Instant::now() + Duration::from_secs(5));
    }
}

fn run_serialized_async<F>(f: F) -> TestResult
where
    F: std::future::Future<Output = TestResult>,
{
    let _serial = proxy_trunc_test_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _post_flush = PostRuntimeFlushGuard;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let res = rt.block_on(f);
    drop(rt);
    let _ = flush_offloaded_logs_until_blocking(Instant::now() + Duration::from_secs(5));
    res
}

/// Deterministic non-zero printable byte at offset `idx` so every forwarded byte can be verified.
#[allow(clippy::cast_possible_truncation)]
const fn pattern_byte(idx: usize) -> u8 {
    (((idx.wrapping_mul(131) ^ (idx >> 8)) & 0x3f) as u8) + b'!'
}

fn make_pattern_bytes(start: usize, len: usize) -> Vec<u8> {
    (start..start + len).map(pattern_byte).collect()
}

fn assert_pattern_prefix(received: &[u8], context: &str) {
    for (idx, &got) in received.iter().enumerate() {
        let want = pattern_byte(idx);
        assert_eq!(
            got, want,
            "{context}: byte at offset {idx} mismatch (got 0x{got:02x}, want 0x{want:02x})"
        );
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

struct OpenConnGuard {
    open: Arc<AtomicUsize>,
    closed_notify: Arc<Notify>,
}

impl Drop for OpenConnGuard {
    fn drop(&mut self) {
        self.open.fetch_sub(1, Ordering::SeqCst);
        self.closed_notify.notify_waiters();
    }
}

/// Raw TCP upstream server we control directly on an ephemeral port (`127.0.0.1:0`, kept).
struct RawTruncUpstream {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
    open: Arc<AtomicUsize>,
    closed_notify: Arc<Notify>,
    rst_gate: Arc<Notify>,
    task: JoinHandle<()>,
}

impl RawTruncUpstream {
    #[allow(clippy::too_many_lines)]
    async fn start() -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let accepted = Arc::new(AtomicUsize::new(0));
        let open = Arc::new(AtomicUsize::new(0));
        let closed_notify = Arc::new(Notify::new());
        let rst_gate = Arc::new(Notify::new());

        let accepted_c = Arc::clone(&accepted);
        let open_c = Arc::clone(&open);
        let closed_c = Arc::clone(&closed_notify);
        let rst_gate_c = Arc::clone(&rst_gate);

        let task = tokio::spawn(async move {
            while let Ok((mut sock, _peer)) = listener.accept().await {
                let _ = sock.set_nodelay(true);
                accepted_c.fetch_add(1, Ordering::SeqCst);
                open_c.fetch_add(1, Ordering::SeqCst);
                let open_inner = Arc::clone(&open_c);
                let closed_inner = Arc::clone(&closed_c);
                let rst_inner = Arc::clone(&rst_gate_c);
                tokio::spawn(async move {
                    let _guard = OpenConnGuard {
                        open: open_inner,
                        closed_notify: closed_inner,
                    };
                    let mut buf = Vec::with_capacity(4096);
                    let mut chunk = [0_u8; 4096];
                    loop {
                        let header_end = loop {
                            if let Some(pos) = find_header_end(&buf) {
                                break Some(pos);
                            }
                            let Ok(n) = sock.read(&mut chunk).await else {
                                break None;
                            };
                            if n == 0 {
                                break None;
                            }
                            if let Some(slice) = chunk.get(..n) {
                                buf.extend_from_slice(slice);
                            }
                            if buf.len() > 64 * 1024 {
                                break None;
                            }
                        };
                        let Some(end_pos) = header_end else {
                            break;
                        };
                        let head_bytes: Vec<u8> = buf.drain(..end_pos).collect();
                        let req_line = String::from_utf8_lossy(&head_bytes)
                            .lines()
                            .next()
                            .unwrap_or("")
                            .to_owned();
                        let target = req_line.split_whitespace().nth(1).unwrap_or("/");

                        match target {
                            // (a) Content-Length: 100000, sends 10000 bytes, closes cleanly (FIN).
                            p if p.starts_with("/api/trunc-cl") => {
                                let head = format!(
                                    "HTTP/1.1 200 OK\r\n\
                                     Content-Type: application/octet-stream\r\n\
                                     Content-Length: {FULL_LEN}\r\n\
                                     Connection: keep-alive\r\n\r\n"
                                );
                                let partial = make_pattern_bytes(0, PARTIAL_LEN);
                                let _ = sock.write_all(head.as_bytes()).await;
                                let _ = sock.write_all(&partial).await;
                                let _ = sock.flush().await;
                                let _ = sock.shutdown().await;
                                break;
                            }
                            // (b) Transfer-Encoding: chunked, sends two chunks, closes without 0\r\n\r\n.
                            p if p.starts_with("/api/trunc-chunked") => {
                                let head = "HTTP/1.1 200 OK\r\n\
                                     Content-Type: application/octet-stream\r\n\
                                     Transfer-Encoding: chunked\r\n\
                                     Connection: keep-alive\r\n\r\n";
                                let c1_hdr = format!("{CHUNK1_LEN:x}\r\n");
                                let c1_body = make_pattern_bytes(0, CHUNK1_LEN);
                                let c2_hdr = format!("{CHUNK2_LEN:x}\r\n");
                                let c2_body = make_pattern_bytes(CHUNK1_LEN, CHUNK2_LEN);
                                let _ = sock.write_all(head.as_bytes()).await;
                                let _ = sock.write_all(c1_hdr.as_bytes()).await;
                                let _ = sock.write_all(&c1_body).await;
                                let _ = sock.write_all(b"\r\n").await;
                                let _ = sock.write_all(c2_hdr.as_bytes()).await;
                                let _ = sock.write_all(&c2_body).await;
                                let _ = sock.write_all(b"\r\n").await;
                                let _ = sock.flush().await;
                                let _ = sock.shutdown().await;
                                break;
                            }
                            // (c) Sends head + initial body bytes, waits for client gate, then resets
                            //     the connection (`SO_LINGER 0`) mid-body.
                            p if p.starts_with("/api/trunc-rst") => {
                                let head = format!(
                                    "HTTP/1.1 200 OK\r\n\
                                     Content-Type: application/octet-stream\r\n\
                                     Content-Length: {FULL_LEN}\r\n\
                                     Connection: keep-alive\r\n\r\n"
                                );
                                let partial = make_pattern_bytes(0, PARTIAL_LEN);
                                // Register the waiter BEFORE flushing so the client's notify can
                                // never be missed.
                                let notified = rst_inner.notified();
                                tokio::pin!(notified);
                                notified.as_mut().enable();
                                let _ = sock.write_all(head.as_bytes()).await;
                                let _ = sock.write_all(&partial).await;
                                let _ = sock.flush().await;
                                let _ = tokio::time::timeout(IO_TIMEOUT, notified).await;
                                let _ =
                                    socket2::SockRef::from(&sock).set_linger(Some(Duration::ZERO));
                                drop(sock);
                                break;
                            }
                            // (d1) Control: full 100000-byte Content-Length body, keep-alive.
                            p if p.starts_with("/api/ok-cl") => {
                                let head = format!(
                                    "HTTP/1.1 200 OK\r\n\
                                     Content-Type: application/octet-stream\r\n\
                                     Content-Length: {FULL_LEN}\r\n\
                                     Connection: keep-alive\r\n\r\n"
                                );
                                let full = make_pattern_bytes(0, FULL_LEN);
                                if sock.write_all(head.as_bytes()).await.is_err()
                                    || sock.write_all(&full).await.is_err()
                                    || sock.flush().await.is_err()
                                {
                                    break;
                                }
                            }
                            // (d2) Control: full 100000-byte chunked body with terminating chunk.
                            p if p.starts_with("/api/ok-chunked") => {
                                let head = "HTTP/1.1 200 OK\r\n\
                                     Content-Type: application/octet-stream\r\n\
                                     Transfer-Encoding: chunked\r\n\
                                     Connection: keep-alive\r\n\r\n";
                                if sock.write_all(head.as_bytes()).await.is_err() {
                                    break;
                                }
                                let mut offset = 0_usize;
                                let mut write_ok = true;
                                while offset < FULL_LEN {
                                    let len = (FULL_LEN - offset).min(16_384);
                                    let chdr = format!("{len:x}\r\n");
                                    let cbody = make_pattern_bytes(offset, len);
                                    if sock.write_all(chdr.as_bytes()).await.is_err()
                                        || sock.write_all(&cbody).await.is_err()
                                        || sock.write_all(b"\r\n").await.is_err()
                                    {
                                        write_ok = false;
                                        break;
                                    }
                                    offset += len;
                                }
                                if !write_ok
                                    || sock.write_all(b"0\r\n\r\n").await.is_err()
                                    || sock.flush().await.is_err()
                                {
                                    break;
                                }
                            }
                            _ => {
                                let resp =
                                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                                let _ = sock.write_all(resp).await;
                                break;
                            }
                        }
                    }
                });
            }
        });

        Ok(Self {
            addr,
            accepted,
            open,
            closed_notify,
            rst_gate,
            task,
        })
    }

    fn accepted_count(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    fn trigger_rst(&self) {
        self.rst_gate.notify_one();
    }

    async fn wait_open_conns(&self, expected: usize, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.open.load(Ordering::SeqCst) == expected {
                return true;
            }
            let notified = self.closed_notify.notified();
            if self.open.load(Ordering::SeqCst) == expected {
                return true;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return self.open.load(Ordering::SeqCst) == expected;
            }
        }
    }
}

impl Drop for RawTruncUpstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeMode {
    DefaultShared,
    WorkersTwo,
}

impl RuntimeMode {
    const fn label(self) -> &'static str {
        match self {
            Self::DefaultShared => "default-shared",
            Self::WorkersTwo => "workers-2",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DownstreamProto {
    Http1,
    Http2,
}

impl DownstreamProto {
    const fn label(self) -> &'static str {
        match self {
            Self::Http1 => "h1",
            Self::Http2 => "h2",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TruncCase {
    ContentLengthShort,
    ChunkedNoTerminator,
    MidBodyReset,
}

impl TruncCase {
    const fn label(self) -> &'static str {
        match self {
            Self::ContentLengthShort => "case-a-content-length-short",
            Self::ChunkedNoTerminator => "case-b-chunked-no-terminator",
            Self::MidBodyReset => "case-c-mid-body-rst",
        }
    }

    const fn path(self) -> &'static str {
        match self {
            Self::ContentLengthShort => "/api/trunc-cl",
            Self::ChunkedNoTerminator => "/api/trunc-chunked",
            Self::MidBodyReset => "/api/trunc-rst",
        }
    }
}

/// Starts `MiraServeServer` bound directly to ephemeral port `0` (kept; never reserve-and-release).
async fn start_proxy_server(
    up_addr: SocketAddr,
    mode: RuntimeMode,
) -> Result<(RunningServer, SocketAddr), Box<dyn std::error::Error>> {
    let workers_line = match mode {
        RuntimeMode::DefaultShared => "",
        RuntimeMode::WorkersTwo => "    workers 2\n",
    };
    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443" protocols="h2,h1"
{workers_line}    timeouts {{
        response-write-idle "10s"
        idle-keepalive "10s"
        graceful-drain "2s"
    }}
}}
site "trunc.proxy.test" {{
    route "/api/*" {{
        reverse-proxy {{
            upstream "http://{up_addr}"
        }}
    }}
}}
"#
    );
    let (mut cfg, _) = parse_kdl("proxy-trunc.kdl", &kdl)?;
    cfg.server
        .listeners
        .first_mut()
        .ok_or("expected listener in fixture")?
        .addr
        .port = 0;

    let server = MiraServeServer::start(
        Arc::new(ConfigStore::new(cfg)),
        ServerOptions {
            dev_tls: true,
            ..ServerOptions::default()
        },
    )
    .await?;
    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::HttpsTcp)
        .ok_or("missing HttpsTcp listener")?
        .local_addr;
    Ok((server, https_addr))
}

fn build_tls_client(
    server: &RunningServer,
    alpn: &[u8],
) -> Result<Arc<ClientConfig>, Box<dyn std::error::Error>> {
    let cert_pem = server.dev_cert_pem().ok_or("expected dev cert PEM")?;
    let mut roots = RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert_pem.as_bytes()).collect::<Result<_, _>>()?;
    let (added, _) = roots.add_parsable_certificates(certs);
    assert_eq!(added, 1);

    let mut cfg = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![alpn.to_vec()];
    Ok(Arc::new(cfg))
}

struct H1ClientConn {
    sender: h1_client::SendRequest<Empty<Bytes>>,
    conn_task: JoinHandle<Result<(), hyper::Error>>,
}

impl H1ClientConn {
    async fn connect(
        addr: SocketAddr,
        host: &str,
        tls_cfg: &Arc<ClientConfig>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let tcp = tokio::time::timeout(IO_TIMEOUT, TcpStream::connect(addr)).await??;
        let _ = tcp.set_nodelay(true);
        let tls = tokio::time::timeout(
            IO_TIMEOUT,
            TlsConnector::from(Arc::clone(tls_cfg))
                .connect(ServerName::try_from(host.to_owned())?, tcp),
        )
        .await??;
        assert_eq!(
            tls.get_ref().1.alpn_protocol(),
            Some(b"http/1.1".as_slice())
        );
        let (sender, conn) =
            tokio::time::timeout(IO_TIMEOUT, h1_client::handshake(TokioIo::new(tls))).await??;
        let conn_task = tokio::spawn(conn);
        Ok(Self { sender, conn_task })
    }

    async fn get_complete_body(
        &mut self,
        host: &str,
        path: &str,
        expected_cl: Option<usize>,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        tokio::time::timeout(IO_TIMEOUT, self.sender.ready()).await??;
        let req = Request::builder()
            .uri(path)
            .header(HOST, host)
            .body(Empty::<Bytes>::new())?;
        let resp = tokio::time::timeout(IO_TIMEOUT, self.sender.send_request(req)).await??;
        assert_eq!(resp.status(), StatusCode::OK, "H1 GET {path} status");
        if let Some(cl) = expected_cl {
            assert_eq!(
                resp.headers()
                    .get(CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok()),
                Some(cl.to_string().as_str()),
                "H1 GET {path} Content-Length"
            );
        }
        let body = tokio::time::timeout(IO_TIMEOUT, resp.into_body().collect())
            .await??
            .to_bytes();
        Ok(body.to_vec())
    }

    async fn close(self) {
        drop(self.sender);
        let _ = tokio::time::timeout(IO_TIMEOUT, self.conn_task).await;
    }
}

struct H2ClientConn {
    sender: h2_client::SendRequest<Empty<Bytes>>,
    conn_task: JoinHandle<Result<(), hyper::Error>>,
}

impl H2ClientConn {
    async fn connect(
        addr: SocketAddr,
        host: &str,
        tls_cfg: &Arc<ClientConfig>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let tcp = tokio::time::timeout(IO_TIMEOUT, TcpStream::connect(addr)).await??;
        let _ = tcp.set_nodelay(true);
        let tls = tokio::time::timeout(
            IO_TIMEOUT,
            TlsConnector::from(Arc::clone(tls_cfg))
                .connect(ServerName::try_from(host.to_owned())?, tcp),
        )
        .await??;
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        let (sender, conn) = tokio::time::timeout(
            IO_TIMEOUT,
            h2_client::handshake::<_, _, Empty<Bytes>>(TokioExecutor::new(), TokioIo::new(tls)),
        )
        .await??;
        let conn_task = tokio::spawn(conn);
        Ok(Self { sender, conn_task })
    }

    async fn get_complete_body(
        &mut self,
        host: &str,
        path: &str,
        expected_cl: Option<usize>,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        tokio::time::timeout(IO_TIMEOUT, self.sender.ready()).await??;
        let req = Request::builder()
            .uri(format!("https://{host}{path}"))
            .body(Empty::<Bytes>::new())?;
        let resp = tokio::time::timeout(IO_TIMEOUT, self.sender.send_request(req)).await??;
        assert_eq!(resp.status(), StatusCode::OK, "H2 GET {path} status");
        if let Some(cl) = expected_cl {
            assert_eq!(
                resp.headers()
                    .get(CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok()),
                Some(cl.to_string().as_str()),
                "H2 GET {path} Content-Length"
            );
        }
        let body = tokio::time::timeout(IO_TIMEOUT, resp.into_body().collect())
            .await??
            .to_bytes();
        Ok(body.to_vec())
    }

    async fn close(self) {
        drop(self.sender);
        let _ = tokio::time::timeout(IO_TIMEOUT, self.conn_task).await;
    }
}

fn assert_pool_events(recorded: &[ProxyPoolEvent], mode: RuntimeMode, tag: &str) {
    assert!(
        !recorded.is_empty(),
        "{tag}: expected proxy pool events to be recorded"
    );
    for ev in recorded {
        match mode {
            RuntimeMode::DefaultShared => {
                assert_eq!(ev.slot, ProxyClientSlot::Shared, "{tag}: expected Shared");
                assert_eq!(ev.worker_pool_count, 0, "{tag}: expected 0 worker pools");
            }
            RuntimeMode::WorkersTwo => {
                #[cfg(target_os = "linux")]
                {
                    assert!(
                        matches!(ev.slot, ProxyClientSlot::Worker(0 | 1)),
                        "{tag}: expected per-worker pool Worker(0|1) on Linux, got {:?}",
                        ev.slot
                    );
                    assert_eq!(
                        ev.worker_pool_count, 2,
                        "{tag}: expected 2 worker pools on Linux"
                    );
                }
                #[cfg(not(target_os = "linux"))]
                {
                    assert_eq!(
                        ev.slot,
                        ProxyClientSlot::Shared,
                        "{tag}: non-Linux falls back to Shared"
                    );
                }
            }
        }
    }
}

/// Runs case (d) control on a fresh upstream + server: both `Content-Length: 100000` and chunked
/// `100000`-byte responses arrive intact with a clean end of stream on a reusable connection.
async fn run_control_case(proto: DownstreamProto, mode: RuntimeMode) -> TestResult {
    let host = "trunc.proxy.test";
    let tag = format!("{}/{}/case-d-control", proto.label(), mode.label());

    let pool_events: Arc<Mutex<Vec<ProxyPoolEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let pool_events_cb = Arc::clone(&pool_events);
    let _observer = test_proxy_pool_observer_guard(move |ev| {
        pool_events_cb
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(ev);
    });

    let upstream = RawTruncUpstream::start().await?;
    let (server, https_addr) = start_proxy_server(upstream.addr, mode).await?;
    let alpn: &[u8] = match proto {
        DownstreamProto::Http1 => b"http/1.1",
        DownstreamProto::Http2 => b"h2",
    };
    let tls_cfg = build_tls_client(&server, alpn)?;

    match proto {
        DownstreamProto::Http1 => {
            let mut cli = H1ClientConn::connect(https_addr, host, &tls_cfg).await?;
            let fixed_body = cli
                .get_complete_body(host, "/api/ok-cl", Some(FULL_LEN))
                .await?;
            assert_eq!(fixed_body.len(), FULL_LEN, "{tag}: control CL length");
            assert_pattern_prefix(&fixed_body, &format!("{tag} CL"));

            let chunked_body = cli.get_complete_body(host, "/api/ok-chunked", None).await?;
            assert_eq!(
                chunked_body.len(),
                FULL_LEN,
                "{tag}: control chunked length"
            );
            assert_pattern_prefix(&chunked_body, &format!("{tag} chunked"));
            cli.close().await;
        }
        DownstreamProto::Http2 => {
            let mut cli = H2ClientConn::connect(https_addr, host, &tls_cfg).await?;
            let fixed_body = cli
                .get_complete_body(host, "/api/ok-cl", Some(FULL_LEN))
                .await?;
            assert_eq!(fixed_body.len(), FULL_LEN, "{tag}: control CL length");
            assert_pattern_prefix(&fixed_body, &format!("{tag} CL"));

            let chunked_body = cli.get_complete_body(host, "/api/ok-chunked", None).await?;
            assert_eq!(
                chunked_body.len(),
                FULL_LEN,
                "{tag}: control chunked length"
            );
            assert_pattern_prefix(&chunked_body, &format!("{tag} chunked"));
            cli.close().await;
        }
    }

    let recorded = pool_events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_pool_events(&recorded, mode, &tag);

    let report = server.shutdown_with_report().await;
    assert!(
        report.is_clean(),
        "{tag}: expected clean server shutdown, got {report:?}"
    );
    assert!(
        upstream.wait_open_conns(0, IO_TIMEOUT).await,
        "{tag}: upstream connections must close after server shutdown"
    );
    Ok(())
}

/// Runs one truncation case (`a`, `b`, or `c`) on an isolated upstream + server (starting at
/// `accepted == 0`, `open == 0`) so pool accounting has zero cross-case interference.
#[allow(clippy::too_many_lines)]
async fn run_truncation_case(
    proto: DownstreamProto,
    mode: RuntimeMode,
    case: TruncCase,
) -> TestResult {
    let host = "trunc.proxy.test";
    let case_tag = format!("{}/{}/{}", proto.label(), mode.label(), case.label());

    let pool_events: Arc<Mutex<Vec<ProxyPoolEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let pool_events_cb = Arc::clone(&pool_events);
    let _observer = test_proxy_pool_observer_guard(move |ev| {
        pool_events_cb
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(ev);
    });

    let upstream = RawTruncUpstream::start().await?;
    let (server, https_addr) = start_proxy_server(upstream.addr, mode).await?;
    let alpn: &[u8] = match proto {
        DownstreamProto::Http1 => b"http/1.1",
        DownstreamProto::Http2 => b"h2",
    };
    let tls_cfg = build_tls_client(&server, alpn)?;

    assert_eq!(upstream.accepted_count(), 0);

    match proto {
        DownstreamProto::Http1 => {
            let mut cli = H1ClientConn::connect(https_addr, host, &tls_cfg).await?;
            tokio::time::timeout(IO_TIMEOUT, cli.sender.ready())
                .await
                .map_err(|_| format!("{case_tag}: timed out waiting for H1 sender ready"))??;
            let req = Request::builder()
                .uri(case.path())
                .header(HOST, host)
                .body(Empty::<Bytes>::new())?;
            let resp_res = tokio::time::timeout(IO_TIMEOUT, cli.sender.send_request(req))
                .await
                .map_err(|_| format!("{case_tag}: timed out awaiting H1 response head"))?;

            match resp_res {
                Ok(resp) => {
                    assert_eq!(
                        resp.status(),
                        StatusCode::OK,
                        "{case_tag}: expected 200 OK head before mid-body truncation"
                    );
                    match case {
                        TruncCase::ContentLengthShort | TruncCase::MidBodyReset => {
                            assert_eq!(
                                resp.headers()
                                    .get(CONTENT_LENGTH)
                                    .and_then(|v| v.to_str().ok()),
                                Some(FULL_LEN.to_string().as_str()),
                                "{case_tag}: expected declared Content-Length: {FULL_LEN}"
                            );
                        }
                        TruncCase::ChunkedNoTerminator => {
                            assert!(
                                resp.headers().get(CONTENT_LENGTH).is_none(),
                                "{case_tag}: chunked response must not invent Content-Length"
                            );
                            assert_eq!(
                                resp.headers()
                                    .get(TRANSFER_ENCODING)
                                    .and_then(|v| v.to_str().ok()),
                                Some("chunked"),
                                "{case_tag}: expected Transfer-Encoding: chunked downstream over H1"
                            );
                        }
                    }

                    let mut body = resp.into_body();
                    let mut received = Vec::new();
                    let mut saw_body_error = false;
                    let mut rst_triggered = false;
                    let deadline = tokio::time::Instant::now() + IO_TIMEOUT;
                    loop {
                        let remaining =
                            deadline.saturating_duration_since(tokio::time::Instant::now());
                        assert!(
                            !remaining.is_zero(),
                            "{case_tag}: H1 client hung reading truncated body (received {} bytes)",
                            received.len()
                        );
                        match tokio::time::timeout(remaining, body.frame()).await {
                            Ok(Some(Ok(frame))) => {
                                if let Ok(data) = frame.into_data() {
                                    received.extend_from_slice(&data);
                                    if case == TruncCase::MidBodyReset
                                        && !rst_triggered
                                        && !received.is_empty()
                                    {
                                        upstream.trigger_rst();
                                        rst_triggered = true;
                                    }
                                }
                            }
                            Ok(Some(Err(_))) => {
                                saw_body_error = true;
                                break;
                            }
                            Ok(None) => break,
                            Err(_) => {
                                return Err(format!(
                                    "{case_tag}: H1 body read timed out after {} bytes",
                                    received.len()
                                )
                                .into());
                            }
                        }
                    }

                    assert!(
                        saw_body_error,
                        "{case_tag}: H1 client MUST observe a body error on truncation, never clean EOF (received {} bytes)",
                        received.len()
                    );
                    assert!(
                        received.len() < FULL_LEN,
                        "{case_tag}: H1 truncated body must be strictly shorter than {FULL_LEN} (got {})",
                        received.len()
                    );
                    if case == TruncCase::MidBodyReset {
                        assert!(
                            rst_triggered && !received.is_empty(),
                            "{case_tag}: RST must be triggered mid-body after client observed body bytes"
                        );
                    }
                    assert_pattern_prefix(&received, &case_tag);
                }
                Err(err) => {
                    // On fast loopback, hyper's H1 server can observe the upstream premature EOF
                    // while still buffering the head + initial body bytes and immediately abort
                    // the downstream TLS connection (UnexpectedEof / closed) before flushing the
                    // head. That is still a clean non-complete failure; case (c) holds the socket
                    // open until the client triggers RST so it must always reach the body loop.
                    assert_ne!(
                        case,
                        TruncCase::MidBodyReset,
                        "{case_tag}: case (c) must deliver head and body bytes before RST (got {err})"
                    );
                    assert!(
                        err.is_closed()
                            || err.is_incomplete_message()
                            || std::error::Error::source(&err).is_some(),
                        "{case_tag}: expected H1 transport/truncation error from server, got {err:?}"
                    );
                }
            }

            // The downstream HTTP/1.1 connection MUST NOT be reusable for another request.
            let reuse_res = tokio::time::timeout(IO_TIMEOUT, async {
                cli.sender.ready().await?;
                let probe = Request::builder()
                    .uri("/api/ok-cl")
                    .header(HOST, host)
                    .body(Empty::<Bytes>::new())
                    .map_err(std::io::Error::other)?;
                let r = cli.sender.send_request(probe).await?;
                let _ = r.into_body().collect().await?;
                Ok::<(), Box<dyn std::error::Error>>(())
            })
            .await;
            assert!(
                matches!(reuse_res, Ok(Err(_))),
                "{case_tag}: H1 connection must NOT be reusable after a truncated response (got {reuse_res:?})"
            );
            // Underlying H1 connection task must terminate promptly.
            let conn_done = tokio::time::timeout(IO_TIMEOUT, &mut cli.conn_task).await;
            assert!(
                conn_done.is_ok(),
                "{case_tag}: H1 connection task must close promptly after truncated response"
            );
        }
        DownstreamProto::Http2 => {
            let mut cli = H2ClientConn::connect(https_addr, host, &tls_cfg).await?;
            tokio::time::timeout(IO_TIMEOUT, cli.sender.ready()).await??;
            let req = Request::builder()
                .uri(format!("https://{host}{}", case.path()))
                .body(Empty::<Bytes>::new())?;
            let resp_res = tokio::time::timeout(IO_TIMEOUT, cli.sender.send_request(req))
                .await
                .map_err(|_| format!("{case_tag}: timed out awaiting H2 response head"))?;

            match resp_res {
                Ok(resp) => {
                    assert_eq!(
                        resp.status(),
                        StatusCode::OK,
                        "{case_tag}: expected 200 OK head before mid-body truncation"
                    );
                    match case {
                        TruncCase::ContentLengthShort | TruncCase::MidBodyReset => {
                            assert_eq!(
                                resp.headers()
                                    .get(CONTENT_LENGTH)
                                    .and_then(|v| v.to_str().ok()),
                                Some(FULL_LEN.to_string().as_str()),
                                "{case_tag}: expected declared Content-Length: {FULL_LEN}"
                            );
                        }
                        TruncCase::ChunkedNoTerminator => {
                            assert!(
                                resp.headers().get(CONTENT_LENGTH).is_none(),
                                "{case_tag}: chunked upstream must not synthesize Content-Length over H2"
                            );
                        }
                    }

                    let mut body = resp.into_body();
                    let mut received = Vec::new();
                    let mut saw_stream_error = false;
                    let mut rst_triggered = false;
                    let deadline = tokio::time::Instant::now() + IO_TIMEOUT;
                    loop {
                        let remaining =
                            deadline.saturating_duration_since(tokio::time::Instant::now());
                        assert!(
                            !remaining.is_zero(),
                            "{case_tag}: H2 client hung reading truncated stream (received {} bytes)",
                            received.len()
                        );
                        match tokio::time::timeout(remaining, body.frame()).await {
                            Ok(Some(Ok(frame))) => {
                                if let Ok(data) = frame.into_data() {
                                    received.extend_from_slice(&data);
                                    if case == TruncCase::MidBodyReset
                                        && !rst_triggered
                                        && !received.is_empty()
                                    {
                                        upstream.trigger_rst();
                                        rst_triggered = true;
                                    }
                                }
                            }
                            Ok(Some(Err(_))) => {
                                saw_stream_error = true;
                                break;
                            }
                            Ok(None) => break,
                            Err(_) => {
                                return Err(format!(
                                    "{case_tag}: H2 body read timed out after {} bytes",
                                    received.len()
                                )
                                .into());
                            }
                        }
                    }

                    assert!(
                        saw_stream_error,
                        "{case_tag}: H2 stream MUST end with RST_STREAM/body error, NEVER clean END_STREAM (received {} bytes)",
                        received.len()
                    );
                    assert!(
                        received.len() < FULL_LEN,
                        "{case_tag}: H2 truncated body must be strictly shorter than {FULL_LEN} (got {})",
                        received.len()
                    );
                    if case == TruncCase::MidBodyReset {
                        assert!(
                            rst_triggered && !received.is_empty(),
                            "{case_tag}: RST must be triggered mid-body after client observed body bytes"
                        );
                    }
                    assert_pattern_prefix(&received, &case_tag);
                }
                Err(err) => {
                    assert_ne!(
                        case,
                        TruncCase::MidBodyReset,
                        "{case_tag}: case (c) must deliver head and body bytes before RST (got {err})"
                    );
                    assert!(
                        err.is_closed()
                            || err.is_incomplete_message()
                            || std::error::Error::source(&err).is_some(),
                        "{case_tag}: expected HTTP/2 stream error/reset from server, got {err:?}"
                    );
                }
            }
            cli.close().await;
        }
    }

    // Event-driven wait (no sleep) until the truncated upstream connection is completely closed.
    assert!(
        upstream.wait_open_conns(0, IO_TIMEOUT).await,
        "{case_tag}: truncated upstream connection did not close cleanly"
    );
    assert_eq!(
        upstream.accepted_count(),
        1,
        "{case_tag}: truncated request must have opened exactly 1 upstream connection"
    );

    // Next request on a brand-new downstream connection MUST succeed AND open a brand-new
    // upstream connection (`accepted_count` goes 1 -> 2, proving the truncated upstream socket was
    // never returned to the pool).
    match proto {
        DownstreamProto::Http1 => {
            let mut next = H1ClientConn::connect(https_addr, host, &tls_cfg).await?;
            let body = next
                .get_complete_body(host, "/api/ok-cl", Some(FULL_LEN))
                .await?;
            assert_eq!(body.len(), FULL_LEN, "{case_tag}: follow-up H1 body length");
            assert_pattern_prefix(&body, &format!("{case_tag} follow-up H1"));
            next.close().await;
        }
        DownstreamProto::Http2 => {
            let mut next = H2ClientConn::connect(https_addr, host, &tls_cfg).await?;
            let body = next
                .get_complete_body(host, "/api/ok-cl", Some(FULL_LEN))
                .await?;
            assert_eq!(body.len(), FULL_LEN, "{case_tag}: follow-up H2 body length");
            assert_pattern_prefix(&body, &format!("{case_tag} follow-up H2"));
            next.close().await;
        }
    }

    assert_eq!(
        upstream.accepted_count(),
        2,
        "{case_tag}: follow-up request after truncated response MUST open a new upstream connection (count=2)"
    );

    // Under Linux `workers 2`, if the first follow-up landed on the sibling worker, keep opening
    // fresh downstream connections until the exact worker that suffered the truncated response
    // handles a follow-up request too, proving ITS per-worker pool opens a fresh upstream
    // connection rather than reusing the truncated socket.
    #[cfg(target_os = "linux")]
    if mode == RuntimeMode::WorkersTwo {
        let snap = pool_events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let trunc_worker = snap
            .iter()
            .find(|e| e.path == case.path())
            .and_then(|e| e.worker_index)
            .ok_or_else(|| format!("{case_tag}: missing pool event for truncated request"))?;
        let mut saw_same_worker_ok = snap
            .iter()
            .any(|e| e.path == "/api/ok-cl" && e.worker_index == Some(trunc_worker));
        for attempt in 0..64_usize {
            if saw_same_worker_ok {
                break;
            }
            let accepts_before_attempt = upstream.accepted_count();
            let path = format!("/api/ok-cl?recheck={attempt}");
            match proto {
                DownstreamProto::Http1 => {
                    let mut extra = H1ClientConn::connect(https_addr, host, &tls_cfg).await?;
                    let body = extra.get_complete_body(host, &path, Some(FULL_LEN)).await?;
                    assert_eq!(body.len(), FULL_LEN);
                    assert_pattern_prefix(&body, &format!("{case_tag} same-worker H1"));
                    extra.close().await;
                }
                DownstreamProto::Http2 => {
                    let mut extra = H2ClientConn::connect(https_addr, host, &tls_cfg).await?;
                    let body = extra.get_complete_body(host, &path, Some(FULL_LEN)).await?;
                    assert_eq!(body.len(), FULL_LEN);
                    assert_pattern_prefix(&body, &format!("{case_tag} same-worker H2"));
                    extra.close().await;
                }
            }
            let latest_worker = pool_events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .last()
                .and_then(|e| e.worker_index);
            if latest_worker == Some(trunc_worker) {
                saw_same_worker_ok = true;
                assert_eq!(
                    upstream.accepted_count(),
                    accepts_before_attempt + 1,
                    "{case_tag}: re-exercising trunc_worker {trunc_worker} must open a brand-new upstream connection"
                );
            }
        }
        assert!(
            saw_same_worker_ok,
            "{case_tag}: expected a follow-up request to land on worker {trunc_worker}"
        );
    }

    let recorded = pool_events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_pool_events(&recorded, mode, &case_tag);

    let report = server.shutdown_with_report().await;
    assert!(
        report.is_clean(),
        "{case_tag}: expected clean server shutdown, got {report:?}"
    );
    assert!(
        upstream.wait_open_conns(0, IO_TIMEOUT).await,
        "{case_tag}: all upstream connections must close after server shutdown"
    );
    Ok(())
}

async fn run_matrix_cell(proto: DownstreamProto, mode: RuntimeMode) -> TestResult {
    run_control_case(proto, mode).await?;
    for case in [
        TruncCase::ContentLengthShort,
        TruncCase::ChunkedNoTerminator,
        TruncCase::MidBodyReset,
    ] {
        run_truncation_case(proto, mode, case).await?;
    }
    Ok(())
}

#[test]
fn proxy_truncation_http2_default_mode() -> TestResult {
    run_serialized_async(run_matrix_cell(
        DownstreamProto::Http2,
        RuntimeMode::DefaultShared,
    ))
}

#[test]
fn proxy_truncation_http1_default_mode() -> TestResult {
    run_serialized_async(run_matrix_cell(
        DownstreamProto::Http1,
        RuntimeMode::DefaultShared,
    ))
}

#[test]
fn proxy_truncation_http2_workers_mode() -> TestResult {
    run_serialized_async(run_matrix_cell(
        DownstreamProto::Http2,
        RuntimeMode::WorkersTwo,
    ))
}

#[test]
fn proxy_truncation_http1_workers_mode() -> TestResult {
    run_serialized_async(run_matrix_cell(
        DownstreamProto::Http1,
        RuntimeMode::WorkersTwo,
    ))
}

struct EnableAccessLogSubscriber;

impl tracing::Subscriber for EnableAccessLogSubscriber {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target() == "miraserve::access"
    }
    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
    fn event(&self, _event: &tracing::Event<'_>) {}
    fn enter(&self, _span: &tracing::span::Id) {}
    fn exit(&self, _span: &tracing::span::Id) {}
}

/// Captures the exact access-log records emitted for truncated proxied responses (`a`, `b`, `c`)
/// and a control response (`d`) over HTTP/2 and HTTP/1.1, confirming the current status/bytes
/// recording without changing production behaviour.
#[test]
#[allow(clippy::too_many_lines)]
fn proxy_truncation_access_log_records_status_and_bytes() -> TestResult {
    static INIT_SUB: std::sync::Once = std::sync::Once::new();
    INIT_SUB.call_once(|| {
        let _ = tracing::subscriber::set_global_default(EnableAccessLogSubscriber);
    });

    run_serialized_async(async {
        let host = "trunc.proxy.test";
        let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let lines_cb = Arc::clone(&lines);
        let _sink = test_access_log_sink_override_guard(Arc::new(move |bytes: &[u8]| {
            lines_cb
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(String::from_utf8_lossy(bytes).into_owned());
        }));

        let upstream = RawTruncUpstream::start().await?;
        let (server, https_addr) =
            start_proxy_server(upstream.addr, RuntimeMode::DefaultShared).await?;

        let h2_tls = build_tls_client(&server, b"h2")?;
        {
            let mut cli = H2ClientConn::connect(https_addr, host, &h2_tls).await?;
            tokio::time::timeout(IO_TIMEOUT, cli.sender.ready()).await??;
            let resp_res = tokio::time::timeout(
                IO_TIMEOUT,
                cli.sender.send_request(
                    Request::builder()
                        .uri(format!("https://{host}/api/trunc-cl"))
                        .body(Empty::<Bytes>::new())?,
                ),
            )
            .await?;
            if let Ok(resp) = resp_res {
                let mut body = resp.into_body();
                while let Ok(Some(Ok(_))) = tokio::time::timeout(IO_TIMEOUT, body.frame()).await {}
            }
            cli.close().await;
        }
        {
            let mut cli = H2ClientConn::connect(https_addr, host, &h2_tls).await?;
            let ok = cli
                .get_complete_body(host, "/api/ok-cl", Some(FULL_LEN))
                .await?;
            assert_eq!(ok.len(), FULL_LEN);
            cli.close().await;
        }

        let h1_tls = build_tls_client(&server, b"http/1.1")?;
        {
            let mut cli = H1ClientConn::connect(https_addr, host, &h1_tls).await?;
            tokio::time::timeout(IO_TIMEOUT, cli.sender.ready()).await??;
            let resp_res = tokio::time::timeout(
                IO_TIMEOUT,
                cli.sender.send_request(
                    Request::builder()
                        .uri("/api/trunc-chunked")
                        .header(HOST, host)
                        .body(Empty::<Bytes>::new())?,
                ),
            )
            .await?;
            if let Ok(resp) = resp_res {
                let mut body = resp.into_body();
                while let Ok(Some(Ok(_))) = tokio::time::timeout(IO_TIMEOUT, body.frame()).await {}
            }
            cli.close().await;
        }
        {
            let mut cli = H2ClientConn::connect(https_addr, host, &h2_tls).await?;
            tokio::time::timeout(IO_TIMEOUT, cli.sender.ready()).await??;
            let resp = tokio::time::timeout(
                IO_TIMEOUT,
                cli.sender.send_request(
                    Request::builder()
                        .uri(format!("https://{host}/api/trunc-rst"))
                        .body(Empty::<Bytes>::new())?,
                ),
            )
            .await??;
            let mut body = resp.into_body();
            let mut rst_triggered = false;
            while let Ok(Some(Ok(frame))) = tokio::time::timeout(IO_TIMEOUT, body.frame()).await {
                if !rst_triggered && frame.into_data().is_ok_and(|d| !d.is_empty()) {
                    upstream.trigger_rst();
                    rst_triggered = true;
                }
            }
            assert!(rst_triggered, "expected RST trigger mid-body");
            cli.close().await;
        }

        let report = server.shutdown_with_report().await;
        assert!(report.is_clean(), "expected clean shutdown, got {report:?}");

        let logged = lines
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let trunc_cl_line = logged
            .iter()
            .find(|l| l.contains("target=\"/api/trunc-cl\""))
            .ok_or_else(|| format!("missing /api/trunc-cl access log line; got: {logged:?}"))?;
        assert!(
            trunc_cl_line.contains("http request interrupted")
                && trunc_cl_line.contains("proto=\"h2\"")
                && trunc_cl_line.contains("status=200")
                && trunc_cl_line.contains("bytes_sent=10000")
                && trunc_cl_line.contains("body_complete=false")
                && trunc_cl_line.contains("transport_delivery=\"failed\"")
                && trunc_cl_line.contains("completed=false"),
            "unexpected /api/trunc-cl access-log line: {trunc_cl_line}"
        );

        let trunc_chunked_line = logged
            .iter()
            .find(|l| l.contains("target=\"/api/trunc-chunked\""))
            .ok_or_else(|| {
                format!("missing /api/trunc-chunked access log line; got: {logged:?}")
            })?;
        assert!(
            trunc_chunked_line.contains("http request interrupted")
                && trunc_chunked_line.contains("proto=\"h1\"")
                && trunc_chunked_line.contains("status=200")
                && trunc_chunked_line.contains("bytes_sent=10000")
                && trunc_chunked_line.contains("body_complete=false")
                && trunc_chunked_line.contains("transport_delivery=\"failed\"")
                && trunc_chunked_line.contains("completed=false"),
            "unexpected /api/trunc-chunked access-log line: {trunc_chunked_line}"
        );

        let trunc_rst_line = logged
            .iter()
            .find(|l| l.contains("target=\"/api/trunc-rst\""))
            .ok_or_else(|| format!("missing /api/trunc-rst access log line; got: {logged:?}"))?;
        let rst_bytes: u64 = trunc_rst_line
            .split_whitespace()
            .find_map(|tok| tok.strip_prefix("bytes_sent="))
            .ok_or_else(|| format!("missing bytes_sent in {trunc_rst_line}"))?
            .parse()?;
        assert!(
            trunc_rst_line.contains("http request interrupted")
                && trunc_rst_line.contains("proto=\"h2\"")
                && trunc_rst_line.contains("status=200")
                && rst_bytes > 0
                && rst_bytes <= PARTIAL_LEN as u64
                && trunc_rst_line.contains("body_complete=false")
                && trunc_rst_line.contains("transport_delivery=\"failed\"")
                && trunc_rst_line.contains("completed=false"),
            "unexpected /api/trunc-rst access-log line: {trunc_rst_line}"
        );

        let ok_line = logged
            .iter()
            .find(|l| l.contains("target=\"/api/ok-cl\""))
            .ok_or_else(|| format!("missing /api/ok-cl access log line; got: {logged:?}"))?;
        assert!(
            ok_line.contains("http request completed")
                && ok_line.contains("status=200")
                && ok_line.contains("bytes_sent=100000")
                && ok_line.contains("body_complete=true")
                && ok_line.contains("completed=true"),
            "unexpected /api/ok-cl access-log line: {ok_line}"
        );
        Ok(())
    })
}

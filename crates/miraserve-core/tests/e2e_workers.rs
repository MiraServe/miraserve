//! End-to-end tests for per-worker event loops (`server { workers ... }`): reload
//! `restart_required`, split-daemon fallback, readiness, bounded shutdown, and loop isolation.

use std::fs;
use std::net::TcpListener as StdTcpListener;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::header::HOST;
use http::{Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper_util::rt::TokioIo;
use miraserve_config::{ConfigStore, parse_kdl};
use miraserve_core::{ListenerKind, MiraServeServer, ServerOptions};
use miraserve_tls::{
    KeydEndpoint, KeydKeyStore, KeydServer, build_crypto_provider, generate_dev_certificate,
};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Serializes tests in this file that spawn worker threads or inspect `/proc/self/task`.
fn worker_test_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

#[cfg(target_os = "linux")]
fn count_worker_loop_threads() -> Result<usize, std::io::Error> {
    Ok(fs::read_dir("/proc/self/task")?
        .filter_map(Result::ok)
        .filter_map(|task| fs::read_to_string(task.path().join("comm")).ok())
        .filter(|name| name.starts_with("miraserve-loop-"))
        .count())
}

/// Waits briefly for Linux `release_task()` to unlink already-joined `miraserve-loop-*` TIDs
/// from `/proc/self/task` (`pthread_join` wakes on `CLONE_CHILD_CLEARTID` during `exit_mm()`,
/// slightly before `/proc/self/task/<tid>` disappears on another CPU).
#[cfg(target_os = "linux")]
async fn wait_for_zero_worker_loop_threads() -> Result<usize, std::io::Error> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(250);
    loop {
        let count = count_worker_loop_threads()?;
        if count == 0 || std::time::Instant::now() >= deadline {
            return Ok(count);
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Result<Self, std::io::Error> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "miraserve-workers-e2e-{tag}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn reserve_free_port() -> Result<u16, std::io::Error> {
    let sock = StdTcpListener::bind("127.0.0.1:0")?;
    Ok(sock.local_addr()?.port())
}

/// Reloading a changed `server.workers` value reports `"server.workers"` in `restart_required`
/// on the first reload and on repeated reloads, and reverting to the startup value clears it.
#[tokio::test]
async fn workers_reload_reports_restart_required_on_change_repeat_and_revert() -> TestResult {
    let _serial = worker_test_lock().lock().await;
    let tmp_v1 = TempDir::new("rr-v1")?;
    let tmp_v2 = TempDir::new("rr-v2")?;
    fs::write(tmp_v1.path.join("index.html"), b"v1")?;
    fs::write(tmp_v2.path.join("index.html"), b"v2")?;
    let tls_port = reserve_free_port()?;
    let make_kdl = |workers: &str, root: &std::path::Path| {
        format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
    workers {workers}
}}
site "rr.example.test" {{
    root "{}"
}}
"#,
            root.to_string_lossy().replace('\\', "/")
        )
    };

    let (cfg, _) = parse_kdl("rr-startup.kdl", &make_kdl("2", &tmp_v1.path))?;
    let server = MiraServeServer::start(
        Arc::new(ConfigStore::new(cfg)),
        ServerOptions {
            dev_tls: true,
            ..ServerOptions::default()
        },
    )
    .await?;
    assert_eq!(server.restart_required(), Vec::<&str>::new());

    // Change workers 2 -> 4: reported in restart_required.
    server.reload_from_str("rr-change.kdl", &make_kdl("4", &tmp_v1.path))?;
    assert_eq!(server.restart_required(), vec!["server.workers"]);

    // Repeat reload with workers still 4 (and a site change): still reported.
    server.reload_from_str("rr-repeat.kdl", &make_kdl("4", &tmp_v2.path))?;
    assert_eq!(server.restart_required(), vec!["server.workers"]);

    // Revert back to startup value (workers 2): clears restart_required.
    server.reload_from_str("rr-revert.kdl", &make_kdl("2", &tmp_v2.path))?;
    assert_eq!(server.restart_required(), Vec::<&str>::new());

    server.shutdown().await;
    #[cfg(target_os = "linux")]
    assert_eq!(wait_for_zero_worker_loop_threads().await?, 0);
    Ok(())
}

/// When `key-isolation "split-daemon"` is configured, `workers` is ignored at startup and the
/// shared runtime serves HTTPS so keyd IPC never runs on a single-threaded worker event loop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn split_daemon_ignores_workers_and_serves_on_shared_runtime() -> TestResult {
    let _serial = worker_test_lock().lock().await;
    let tmp = TempDir::new("split-keyd")?;
    fs::write(tmp.path.join("index.html"), b"split-daemon-ok")?;

    let provider = build_crypto_provider(true);
    let (real_ck, cert_pem) =
        generate_dev_certificate(&["keyd.workers.test".to_owned()], &provider)?;
    let mut key_store = KeydKeyStore::new();
    key_store.insert_certified_key(
        "workers-keyd-default",
        vec!["keyd.workers.test".to_owned()],
        true,
        real_ck,
    )?;
    let keyd = KeydServer::start(
        KeydEndpoint::LoopbackTcp("127.0.0.1:0".parse()?),
        key_store,
        false,
    )
    .await?;
    let keyd_sock_str = keyd.endpoint().to_socket_string();
    let tls_port = reserve_free_port()?;
    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
    workers 3
    tls {{
        min-version "1.3"
        key-isolation "split-daemon"
        keyd-socket "{keyd_sock_str}"
    }}
}}
site "keyd.workers.test" {{
    root "{}"
}}
"#,
        tmp.path.to_string_lossy().replace('\\', "/")
    );

    let (cfg, _) = parse_kdl("split-workers.kdl", &kdl)?;
    let server = MiraServeServer::start(
        Arc::new(ConfigStore::new(cfg)),
        ServerOptions {
            dev_tls: false,
            keyd_auth_secret: keyd.auth_secret(),
            ..ServerOptions::default()
        },
    )
    .await?;

    #[cfg(target_os = "linux")]
    assert_eq!(
        count_worker_loop_threads()?,
        0,
        "split-daemon must ignore workers and run HTTPS on the shared runtime"
    );

    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::HttpsTcp)
        .ok_or("missing HttpsTcp listener")?
        .local_addr;

    let mut roots = RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert_pem.cert_pem.as_bytes()).collect::<Result<_, _>>()?;
    roots.add_parsable_certificates(certs);

    let mut cli_tls = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cli_tls.alpn_protocols = vec![b"http/1.1".to_vec()];

    let tcp = TcpStream::connect(https_addr).await?;
    let tls = TlsConnector::from(Arc::new(cli_tls))
        .connect(ServerName::try_from("keyd.workers.test")?, tcp)
        .await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
    let conn_task = tokio::spawn(conn);
    let resp = sender
        .send_request(
            Request::builder()
                .uri("/index.html")
                .header(HOST, "keyd.workers.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await?.to_bytes();
    assert_eq!(&body[..], b"split-daemon-ok");
    assert_eq!(keyd.signatures_served(), 1);

    drop(sender);
    let _ = conn_task.await;
    server.shutdown().await;
    keyd.shutdown().await;
    Ok(())
}

/// Minimal `tracing::Subscriber` that enables `INFO` for `miraserve::access` so the direct
/// access-log sink (`set_access_log_sink`) receives formatted access lines without needing
/// `tracing-subscriber` as a dev-dependency.
#[cfg(target_os = "linux")]
struct AccessLogEnableSubscriber;

#[cfg(target_os = "linux")]
impl tracing::Subscriber for AccessLogEnableSubscriber {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target() == "miraserve::access" && *metadata.level() <= tracing::Level::INFO
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

#[cfg(target_os = "linux")]
fn init_access_log_capture() -> &'static std::sync::Mutex<Vec<String>> {
    static LINES: OnceLock<std::sync::Mutex<Vec<String>>> = OnceLock::new();
    static INIT: OnceLock<()> = OnceLock::new();
    let lines = LINES.get_or_init(|| std::sync::Mutex::new(Vec::new()));
    INIT.get_or_init(|| {
        let _ = tracing::subscriber::set_global_default(AccessLogEnableSubscriber);
        let _ = miraserve_core::set_access_log_sink(Box::new(move |bytes| {
            let line = String::from_utf8_lossy(bytes).into_owned();
            lines
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(line);
        }));
    });
    lines
}

/// Shutdown with an open SSE response on a worker loop returns within `graceful_drain + 2s`,
/// joins the worker loop thread, and emits the SSE access-log record BEFORE `shutdown()` returns
/// (so it is always present before the CLI's final access-log flush).
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn worker_shutdown_with_open_sse_joins_within_bound_and_writes_access_line() -> TestResult {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let _serial = worker_test_lock().lock().await;
    let access_lines = init_access_log_capture();
    access_lines
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();

    // Upstream SSE server: replies immediately with headers + one SSE event, then holds open.
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let upstream_addr = upstream_listener.local_addr()?;
    let release_upstream = Arc::new(tokio::sync::Notify::new());
    let release_c = Arc::clone(&release_upstream);
    let upstream_task = tokio::spawn(async move {
        if let Ok((mut sock, _)) = upstream_listener.accept().await {
            let mut req_buf = [0_u8; 2048];
            let _ = sock.read(&mut req_buf).await;
            let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nTransfer-Encoding: chunked\r\n\r\n11\r\ndata: hello-sse\n\n\r\n";
            let _ = sock.write_all(head).await;
            let _ = sock.flush().await;
            release_c.notified().await;
        }
    });

    let tls_port = reserve_free_port()?;
    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
    workers 1
    timeouts {{
        graceful-drain "300ms"
    }}
}}
site "sse.workers.test" {{
    route "/events" {{
        reverse-proxy {{
            upstream "http://{upstream_addr}"
        }}
    }}
}}
"#
    );
    let (cfg, _) = parse_kdl("sse-shutdown.kdl", &kdl)?;
    let server = MiraServeServer::start(
        Arc::new(ConfigStore::new(cfg)),
        ServerOptions {
            dev_tls: true,
            ..ServerOptions::default()
        },
    )
    .await?;
    assert_eq!(count_worker_loop_threads()?, 1);

    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::HttpsTcp)
        .ok_or("missing HttpsTcp listener")?
        .local_addr;
    let cert_pem = server.dev_cert_pem().ok_or("expected dev cert PEM")?;
    let mut roots = RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert_pem.as_bytes()).collect::<Result<_, _>>()?;
    roots.add_parsable_certificates(certs);

    let mut cli_tls = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cli_tls.alpn_protocols = vec![b"http/1.1".to_vec()];

    let tcp = TcpStream::connect(https_addr).await?;
    let tls = TlsConnector::from(Arc::new(cli_tls))
        .connect(ServerName::try_from("sse.workers.test")?, tcp)
        .await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
    let conn_task = tokio::spawn(conn);

    let resp = sender
        .send_request(
            Request::builder()
                .uri("/events")
                .header(HOST, "sse.workers.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let mut body = resp.into_body();
    let first_frame = tokio::time::timeout(std::time::Duration::from_secs(3), body.frame())
        .await?
        .ok_or("expected initial SSE frame")??;
    assert_eq!(
        first_frame.into_data().ok().as_deref(),
        Some(&b"data: hello-sse\n\n"[..])
    );

    // The SSE response is still open, so its access line has NOT been written yet.
    assert!(
        !access_lines
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .any(|line| line.contains("/events")),
        "SSE access line must not be emitted while response is still open"
    );

    // Initiate shutdown while keeping the SSE response and connection open.
    let started = std::time::Instant::now();
    server.shutdown().await;
    let elapsed = started.elapsed();

    // Must wait through the 300ms drain and finish well within `graceful_drain + 2s` (2300ms).
    assert!(
        elapsed >= std::time::Duration::from_millis(250),
        "shutdown returned too early ({elapsed:?}) without honoring graceful_drain"
    );
    assert!(
        elapsed < std::time::Duration::from_millis(2_300),
        "shutdown exceeded drain_deadline + 2s bound: {elapsed:?}"
    );

    // The interrupted SSE access-log record MUST already be written synchronously BEFORE
    // `shutdown()` returned (checked with zero delay before polling `/proc/self/task`).
    let recorded = access_lines
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert!(
        recorded
            .iter()
            .any(|line| line.contains("/events") && line.contains("status=200")),
        "expected SSE access line to be written before shutdown() returned, got: {recorded:?}"
    );

    // Worker loop thread must have been joined and exited before `shutdown()` returned.
    assert_eq!(
        wait_for_zero_worker_loop_threads().await?,
        0,
        "worker loop threads must be joined before shutdown() returns"
    );

    drop(body);
    drop(sender);
    let _ = conn_task.await;
    release_upstream.notify_waiters();
    let _ = upstream_task.await;
    Ok(())
}

/// On `workers 1` (single worker event loop, so every HTTPS connection shares `miraserve-loop-0`),
/// unrelated HTTPS connections stay responsive while another connection triggers heavy static
/// file work (4 MiB on-the-fly Brotli compression + cold fallback on the blocking pool).
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn worker_loop_keeps_serving_other_connections_during_slow_static_file_work() -> TestResult {
    let _serial = worker_test_lock().lock().await;
    let tmp = TempDir::new("slow-static")?;
    fs::write(tmp.path.join("fast.txt"), b"fast-static-ok")?;
    // 4 MiB compressible file whose on-the-fly Brotli read + compression runs on the blocking pool.
    let mut big_payload = Vec::with_capacity(4 * 1024 * 1024);
    for i in 0_u32..131_072 {
        use std::io::Write as _;
        let _ = writeln!(
            big_payload,
            "{{\"row\":{i},\"msg\":\"mira-static-worker\"}}"
        );
    }
    big_payload.truncate(4 * 1024 * 1024);
    fs::write(tmp.path.join("big.json"), &big_payload)?;

    let tls_port = reserve_free_port()?;
    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
    workers 1
}}
site "static.workers.test" {{
    root "{}"
}}
"#,
        tmp.path.to_string_lossy().replace('\\', "/")
    );
    let (cfg, _) = parse_kdl("slow-static.kdl", &kdl)?;
    let server = MiraServeServer::start(
        Arc::new(ConfigStore::new(cfg)),
        ServerOptions {
            dev_tls: true,
            ..ServerOptions::default()
        },
    )
    .await?;
    assert_eq!(count_worker_loop_threads()?, 1);

    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::HttpsTcp)
        .ok_or("missing HttpsTcp listener")?
        .local_addr;
    let cert_pem = server.dev_cert_pem().ok_or("expected dev cert PEM")?;
    let mut roots = RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert_pem.as_bytes()).collect::<Result<_, _>>()?;
    roots.add_parsable_certificates(certs);

    let make_client =
        |roots: RootCertStore| -> Result<Arc<ClientConfig>, Box<dyn std::error::Error>> {
            let mut cfg = ClientConfig::builder_with_provider(build_crypto_provider(true))
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_root_certificates(roots)
                .with_no_client_auth();
            cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
            Ok(Arc::new(cfg))
        };
    let cli_cfg = make_client(roots)?;

    // Open two connections to the single worker loop (`workers 1`).
    let slow_tcp = TcpStream::connect(https_addr).await?;
    let slow_tls = TlsConnector::from(Arc::clone(&cli_cfg))
        .connect(ServerName::try_from("static.workers.test")?, slow_tcp)
        .await?;
    let (mut slow_sender, slow_conn) =
        hyper::client::conn::http1::handshake(TokioIo::new(slow_tls)).await?;
    let slow_conn_task = tokio::spawn(slow_conn);

    let fast_tcp = TcpStream::connect(https_addr).await?;
    let fast_tls = TlsConnector::from(Arc::clone(&cli_cfg))
        .connect(ServerName::try_from("static.workers.test")?, fast_tcp)
        .await?;
    let (mut fast_sender, fast_conn) =
        hyper::client::conn::http1::handshake(TokioIo::new(fast_tls)).await?;
    let fast_conn_task = tokio::spawn(fast_conn);

    // Warm `/fast.txt` on the fast connection.
    let warm = fast_sender
        .send_request(
            Request::builder()
                .uri("/fast.txt")
                .header(HOST, "static.workers.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(warm.status(), StatusCode::OK);
    let _ = warm.into_body().collect().await?;

    // Kick off the heavy 4 MiB Brotli static request on connection 1.
    let slow_req_task = tokio::spawn(async move {
        let resp = slow_sender
            .send_request(
                Request::builder()
                    .uri("/big.json")
                    .header(HOST, "static.workers.test")
                    .header(http::header::ACCEPT_ENCODING, "br")
                    .body(Empty::<Bytes>::new())?,
            )
            .await?;
        let status = resp.status();
        let enc = resp
            .headers()
            .get(http::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = resp.into_body().collect().await?.to_bytes();
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((status, enc, body))
    });

    // Concurrently send fast requests on connection 2 while the 4 MiB file work runs.
    let mut fast_served = 0_usize;
    let fast_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while fast_served < 10 && std::time::Instant::now() < fast_deadline {
        fast_sender.ready().await?;
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            fast_sender.send_request(
                Request::builder()
                    .uri("/fast.txt")
                    .header(HOST, "static.workers.test")
                    .body(Empty::<Bytes>::new())?,
            ),
        )
        .await??;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await?.to_bytes();
        assert_eq!(&body[..], b"fast-static-ok");
        fast_served += 1;
    }
    assert_eq!(fast_served, 10);

    let (slow_status, slow_enc, slow_body) =
        tokio::time::timeout(std::time::Duration::from_secs(15), slow_req_task)
            .await??
            .map_err(|e| format!("slow static request failed: {e}"))?;
    assert_eq!(slow_status, StatusCode::OK);
    assert_eq!(slow_enc.as_deref(), Some("br"));
    assert!(!slow_body.is_empty());

    drop(fast_sender);
    let _ = fast_conn_task.await;
    let _ = slow_conn_task.await;
    server.shutdown().await;
    #[cfg(target_os = "linux")]
    assert_eq!(wait_for_zero_worker_loop_threads().await?, 0);
    Ok(())
}

/// On `workers 1` (single worker loop `miraserve-loop-0`), unrelated connections keep getting
/// answered while a 4 MiB buffered proxied body is Brotli-compressed (offloaded to the blocking
/// pool) and while a 1 MiB chunked proxied body is compressed incrementally in `<= 64 KiB` pieces.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn worker_loop_keeps_serving_other_connections_while_4mib_proxied_body_compresses()
-> TestResult {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let _serial = worker_test_lock().lock().await;
    let tmp = TempDir::new("proxy-compress")?;
    fs::write(tmp.path.join("fast.txt"), b"fast-during-proxy-ok")?;

    // Build a 4 MiB compressible JSON payload (exact MAX_ONTHEFLY_COMPRESS_BYTES).
    let mut big_json = Vec::with_capacity(4 * 1024 * 1024);
    for i in 0_u32..131_072 {
        use std::io::Write as _;
        let _ = writeln!(big_json, "{{\"n\":{i},\"service\":\"miraserve-proxy-4m\"}}");
    }
    big_json.truncate(4 * 1024 * 1024);
    let big_json = Arc::new(big_json);

    let stream_chunk = Arc::new(big_json.get(..512 * 1024).unwrap_or(&big_json).to_vec());

    // Local upstream HTTP/1.1 server serving `/big-proxy` (4 MiB Content-Length) and
    // `/stream-proxy` (unknown-length chunked 1 MiB).
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let upstream_addr = upstream_listener.local_addr()?;
    let big_c = Arc::clone(&big_json);
    let chunk_c = Arc::clone(&stream_chunk);
    let upstream_task = tokio::spawn(async move {
        for _ in 0..2 {
            let Ok((mut sock, _)) = upstream_listener.accept().await else {
                break;
            };
            let big = Arc::clone(&big_c);
            let chunk = Arc::clone(&chunk_c);
            tokio::spawn(async move {
                let mut req_buf = [0_u8; 4096];
                let n = sock.read(&mut req_buf).await.unwrap_or(0);
                let req_head = String::from_utf8_lossy(req_buf.get(..n).unwrap_or(&[]));
                if req_head.starts_with("GET /big-proxy") {
                    let hdr = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        big.len()
                    );
                    let _ = sock.write_all(hdr.as_bytes()).await;
                    let _ = sock.write_all(&big).await;
                    let _ = sock.shutdown().await;
                } else if req_head.starts_with("GET /stream-proxy") {
                    let hdr = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
                    let _ = sock.write_all(hdr).await;
                    let chunk_hdr = format!("{:x}\r\n", chunk.len());
                    for _ in 0..2 {
                        let _ = sock.write_all(chunk_hdr.as_bytes()).await;
                        let _ = sock.write_all(&chunk).await;
                        let _ = sock.write_all(b"\r\n").await;
                        let _ = sock.flush().await;
                    }
                    let _ = sock.write_all(b"0\r\n\r\n").await;
                    let _ = sock.shutdown().await;
                }
            });
        }
    });

    let tls_port = reserve_free_port()?;
    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
    workers 1
}}
site "proxy.workers.test" {{
    root "{}"
    route "/big-proxy" {{
        reverse-proxy {{
            upstream "http://{upstream_addr}"
        }}
    }}
    route "/stream-proxy" {{
        reverse-proxy {{
            upstream "http://{upstream_addr}"
        }}
    }}
}}
"#,
        tmp.path.to_string_lossy().replace('\\', "/")
    );
    let (cfg, _) = parse_kdl("proxy-compress.kdl", &kdl)?;
    let server = MiraServeServer::start(
        Arc::new(ConfigStore::new(cfg)),
        ServerOptions {
            dev_tls: true,
            ..ServerOptions::default()
        },
    )
    .await?;
    assert_eq!(count_worker_loop_threads()?, 1);

    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::HttpsTcp)
        .ok_or("missing HttpsTcp listener")?
        .local_addr;
    let cert_pem = server.dev_cert_pem().ok_or("expected dev cert PEM")?;
    let mut roots = RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert_pem.as_bytes()).collect::<Result<_, _>>()?;
    roots.add_parsable_certificates(certs);

    let mut cli_cfg = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cli_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let cli_cfg = Arc::new(cli_cfg);

    let open_conn = |cfg: Arc<ClientConfig>| async move {
        let tcp = TcpStream::connect(https_addr).await?;
        let tls = TlsConnector::from(cfg)
            .connect(ServerName::try_from("proxy.workers.test")?, tcp)
            .await?;
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
        let task = tokio::spawn(conn);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((sender, task))
    };

    let (mut fast_sender, fast_conn_task) = open_conn(Arc::clone(&cli_cfg))
        .await
        .map_err(|e| format!("{e}"))?;

    // 1. 4 MiB buffered proxied body with Brotli while connection 2 serves `/fast.txt`.
    let (mut big_sender, big_conn_task) = open_conn(Arc::clone(&cli_cfg))
        .await
        .map_err(|e| format!("{e}"))?;
    let big_req_task = tokio::spawn(async move {
        let resp = big_sender
            .send_request(
                Request::builder()
                    .uri("/big-proxy")
                    .header(HOST, "proxy.workers.test")
                    .header(http::header::ACCEPT_ENCODING, "br")
                    .body(Empty::<Bytes>::new())?,
            )
            .await?;
        let status = resp.status();
        let enc = resp
            .headers()
            .get(http::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = resp.into_body().collect().await?.to_bytes();
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((status, enc, body))
    });

    for _ in 0..10 {
        fast_sender.ready().await?;
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            fast_sender.send_request(
                Request::builder()
                    .uri("/fast.txt")
                    .header(HOST, "proxy.workers.test")
                    .body(Empty::<Bytes>::new())?,
            ),
        )
        .await??;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await?.to_bytes();
        assert_eq!(&body[..], b"fast-during-proxy-ok");
    }

    let (big_status, big_enc, big_body) =
        tokio::time::timeout(std::time::Duration::from_secs(15), big_req_task)
            .await??
            .map_err(|e| format!("4 MiB proxy request failed: {e}"))?;
    assert_eq!(big_status, StatusCode::OK);
    assert_eq!(big_enc.as_deref(), Some("br"));
    assert!(
        big_body.len() < big_json.len(),
        "4 MiB JSON must be compressed"
    );

    // 2. 1 MiB unknown-length streamed proxied body with Brotli while connection 2 serves `/fast.txt`.
    let (mut stream_sender, stream_conn_task) = open_conn(Arc::clone(&cli_cfg))
        .await
        .map_err(|e| format!("{e}"))?;
    let stream_req_task = tokio::spawn(async move {
        let resp = stream_sender
            .send_request(
                Request::builder()
                    .uri("/stream-proxy")
                    .header(HOST, "proxy.workers.test")
                    .header(http::header::ACCEPT_ENCODING, "br")
                    .body(Empty::<Bytes>::new())?,
            )
            .await?;
        let status = resp.status();
        let enc = resp
            .headers()
            .get(http::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = resp.into_body().collect().await?.to_bytes();
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((status, enc, body))
    });

    for _ in 0..5 {
        fast_sender.ready().await?;
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            fast_sender.send_request(
                Request::builder()
                    .uri("/fast.txt")
                    .header(HOST, "proxy.workers.test")
                    .body(Empty::<Bytes>::new())?,
            ),
        )
        .await??;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await?.to_bytes();
        assert_eq!(&body[..], b"fast-during-proxy-ok");
    }

    let (stream_status, stream_enc, stream_body) =
        tokio::time::timeout(std::time::Duration::from_secs(15), stream_req_task)
            .await??
            .map_err(|e| format!("streamed proxy request failed: {e}"))?;
    assert_eq!(stream_status, StatusCode::OK);
    assert_eq!(stream_enc.as_deref(), Some("br"));
    assert!(!stream_body.is_empty());

    drop(fast_sender);
    let _ = fast_conn_task.await;
    let _ = big_conn_task.await;
    let _ = stream_conn_task.await;
    let _ = upstream_task.await;
    server.shutdown().await;
    #[cfg(target_os = "linux")]
    assert_eq!(wait_for_zero_worker_loop_threads().await?, 0);
    Ok(())
}

/// Large static files (> 256 KiB) streamed over real TLS + HTTP/1.1 and HTTP/2 on per-core
/// worker loops (`workers 2`): full GET, large non-zero `Range` (positional, no seek), and `HEAD`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn workers_stream_large_static_file_h1_and_h2_with_range_and_head() -> TestResult {
    let _serial = worker_test_lock().lock().await;
    let tmp = TempDir::new("stream-large")?;
    let payload: Vec<u8> = (0..1024 * 1024_usize)
        .map(|i| u8::try_from((i.wrapping_mul(131) ^ (i >> 8)) % 251).unwrap_or(0))
        .collect();
    fs::write(tmp.path.join("bundle.bin"), &payload)?;

    let tls_port = reserve_free_port()?;
    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
    workers 2
}}
site "stream.workers.test" {{
    root "{}"
}}
"#,
        tmp.path.to_string_lossy().replace('\\', "/")
    );
    let (cfg, _) = parse_kdl("stream-large.kdl", &kdl)?;
    let server = MiraServeServer::start(
        Arc::new(ConfigStore::new(cfg)),
        ServerOptions {
            dev_tls: true,
            ..ServerOptions::default()
        },
    )
    .await?;
    #[cfg(target_os = "linux")]
    assert_eq!(count_worker_loop_threads()?, 2);

    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::HttpsTcp)
        .ok_or("missing HttpsTcp listener")?
        .local_addr;
    let cert_pem = server.dev_cert_pem().ok_or("expected dev cert PEM")?;
    let mut roots = RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert_pem.as_bytes()).collect::<Result<_, _>>()?;
    roots.add_parsable_certificates(certs);

    // 1. HTTP/1.1 over TLS: full GET, large non-zero Range (> 64 KiB offset), HEAD.
    let mut h1_cfg = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    h1_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tcp1 = TcpStream::connect(https_addr).await?;
    let tls1 = TlsConnector::from(Arc::new(h1_cfg))
        .connect(ServerName::try_from("stream.workers.test")?, tcp1)
        .await?;
    let (mut h1_tx, h1_conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls1)).await?;
    let h1_task = tokio::spawn(h1_conn);

    let r_full = h1_tx
        .send_request(
            Request::builder()
                .uri("/bundle.bin")
                .header(HOST, "stream.workers.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(r_full.status(), StatusCode::OK);
    assert_eq!(
        r_full.into_body().collect().await?.to_bytes().as_ref(),
        payload.as_slice()
    );

    h1_tx.ready().await?;
    let r_range = h1_tx
        .send_request(
            Request::builder()
                .uri("/bundle.bin")
                .header(HOST, "stream.workers.test")
                .header(http::header::RANGE, "bytes=70000-450000")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(r_range.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        Some(r_range.into_body().collect().await?.to_bytes().as_ref()),
        payload.get(70_000..=450_000)
    );

    h1_tx.ready().await?;
    let r_head = h1_tx
        .send_request(
            Request::builder()
                .method(http::Method::HEAD)
                .uri("/bundle.bin")
                .header(HOST, "stream.workers.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(r_head.status(), StatusCode::OK);
    assert_eq!(
        r_head
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()),
        Some("1048576")
    );
    assert_eq!(r_head.into_body().collect().await?.to_bytes(), Bytes::new());

    // 2. HTTP/2 over TLS: concurrent full GET + large non-zero Range on worker loops.
    let mut h2_cfg = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    h2_cfg.alpn_protocols = vec![b"h2".to_vec()];
    let tcp2 = TcpStream::connect(https_addr).await?;
    let tls2 = TlsConnector::from(Arc::new(h2_cfg))
        .connect(ServerName::try_from("stream.workers.test")?, tcp2)
        .await?;
    let (mut h2_tx, h2_conn) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        TokioIo::new(tls2),
    )
    .await?;
    let h2_task = tokio::spawn(h2_conn);

    let (f_full, f_range) = tokio::join!(
        h2_tx.send_request(
            Request::builder()
                .uri("https://stream.workers.test/bundle.bin")
                .body(Empty::<Bytes>::new())?,
        ),
        h2_tx.send_request(
            Request::builder()
                .uri("https://stream.workers.test/bundle.bin")
                .header(http::header::RANGE, "bytes=131072-600000")
                .body(Empty::<Bytes>::new())?,
        ),
    );
    let h2_full = f_full?;
    assert_eq!(h2_full.status(), StatusCode::OK);
    assert_eq!(
        h2_full.into_body().collect().await?.to_bytes().as_ref(),
        payload.as_slice()
    );

    let h2_range = f_range?;
    assert_eq!(h2_range.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        Some(h2_range.into_body().collect().await?.to_bytes().as_ref()),
        payload.get(131_072..=600_000)
    );

    drop(h1_tx);
    drop(h2_tx);
    let _ = h1_task.await;
    let _ = h2_task.await;
    server.shutdown().await;
    #[cfg(target_os = "linux")]
    assert_eq!(wait_for_zero_worker_loop_threads().await?, 0);
    Ok(())
}

/// Proves that forwarding `poll_write_vectored` / `is_write_vectored` through `WriteGuardedIo`
/// lets `tokio-rustls` flush a 64 KiB plaintext write (four 16 KiB TLS records) in a single
/// vectored write instead of four separate scalar writes.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn tls_over_write_guarded_io_coalesces_four_records_into_one_vectored_write() -> TestResult {
    use std::io;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};

    #[derive(Debug)]
    struct SingleCert(Arc<rustls::sign::CertifiedKey>);

    impl rustls::server::ResolvesServerCert for SingleCert {
        fn resolve(
            &self,
            _client_hello: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            Some(Arc::clone(&self.0))
        }
    }

    struct CountingDuplex {
        inner: tokio::io::DuplexStream,
        scalar_writes: Arc<AtomicUsize>,
        vectored_writes: Arc<AtomicUsize>,
        max_slices: Arc<AtomicUsize>,
    }

    impl AsyncRead for CountingDuplex {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for CountingDuplex {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.scalar_writes.fetch_add(1, Ordering::Relaxed);
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[io::IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            self.vectored_writes.fetch_add(1, Ordering::Relaxed);
            self.max_slices.fetch_max(bufs.len(), Ordering::Relaxed);
            let mut total = 0_usize;
            for slice in bufs {
                if slice.is_empty() {
                    continue;
                }
                match Pin::new(&mut self.inner).poll_write(cx, slice) {
                    Poll::Ready(Ok(n)) => {
                        total += n;
                        if n < slice.len() {
                            break;
                        }
                    }
                    Poll::Ready(Err(err)) if total == 0 => return Poll::Ready(Err(err)),
                    Poll::Ready(Err(_)) | Poll::Pending => break,
                }
            }
            if total == 0 {
                Poll::Pending
            } else {
                Poll::Ready(Ok(total))
            }
        }

        fn is_write_vectored(&self) -> bool {
            true
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    let provider = build_crypto_provider(true);
    let (cert_key, cert_pem) =
        generate_dev_certificate(&["vec.example.test".to_owned()], &provider)?;
    let server_cfg = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCert(cert_key))),
    );
    let mut roots = RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert_pem.cert_pem.as_bytes()).collect::<Result<_, _>>()?;
    roots.add_parsable_certificates(certs);
    let client_cfg = Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );

    let (srv_io, cli_io) = tokio::io::duplex(256 * 1024);
    let scalar_writes = Arc::new(AtomicUsize::new(0));
    let vectored_writes = Arc::new(AtomicUsize::new(0));
    let max_slices = Arc::new(AtomicUsize::new(0));
    let counted = CountingDuplex {
        inner: srv_io,
        scalar_writes: Arc::clone(&scalar_writes),
        vectored_writes: Arc::clone(&vectored_writes),
        max_slices: Arc::clone(&max_slices),
    };
    let guarded =
        miraserve_http::WriteGuardedIo::new(counted, std::time::Duration::from_secs(10), 0);

    let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
    let connector = TlsConnector::from(client_cfg);
    let (mut srv_tls, mut cli_tls) = tokio::try_join!(
        acceptor.accept(guarded),
        connector.connect(ServerName::try_from("vec.example.test")?, cli_io),
    )?;

    // Reset counters after handshake so we measure only the 64 KiB body chunk write.
    scalar_writes.store(0, Ordering::Relaxed);
    vectored_writes.store(0, Ordering::Relaxed);
    max_slices.store(0, Ordering::Relaxed);

    let payload = vec![0x42_u8; 64 * 1024];
    let payload_c = payload.clone();
    let reader = tokio::spawn(async move {
        let mut received = vec![0_u8; payload_c.len()];
        cli_tls.read_exact(&mut received).await?;
        Ok::<Vec<u8>, io::Error>(received)
    });

    srv_tls.write_all(&payload).await?;
    srv_tls.flush().await?;
    let received = reader.await??;
    assert_eq!(received, payload);

    assert_eq!(
        scalar_writes.load(Ordering::Relaxed),
        0,
        "tokio-rustls through WriteGuardedIo must not fall back to scalar poll_write"
    );
    assert_eq!(
        vectored_writes.load(Ordering::Relaxed),
        1,
        "64 KiB plaintext (4 x 16 KiB TLS records) must flush in a single vectored write"
    );
    assert!(
        max_slices.load(Ordering::Relaxed) >= 4,
        "expected >= 4 TLS record slices in one vectored write, got {}",
        max_slices.load(Ordering::Relaxed)
    );
    Ok(())
}

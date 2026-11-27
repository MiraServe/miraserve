//! Full-stack real TCP + TLS 1.3 (ALPN `h2`) end-to-end tests for running HTTP/2 stream futures
//! inside the connection's own task (`miraserve-http::h2_intask`):
//! - Many concurrent streams on one connection answered in order of completion with exact bodies
//! - Slow upstream on one stream with sibling streams completing promptly
//! - Client `RST_STREAM` while a stream future is pending drops the server future and lets the
//!   connection return to idle and close at `idle-keepalive`
//! - Graceful shutdown draining in-flight HTTP/2 streams to completion
//! - Multiplexed uploads (including multi-chunk and empty-DATA-frame uploads)
//! - Fairness between two real TLS HTTP/2 connections on a single-thread runtime
//! - Single-connection vs. multi-connection CPU-heavy WASM multiplexing measurement

use std::collections::VecDeque;
use std::convert::Infallible;
use std::fs;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt as _, Empty, Full};
use hyper::body::{Body as HttpBodyTrait, Frame, Incoming};
use hyper::client::conn::http2 as h2_client;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use miraserve_config::{ConfigStore, parse_kdl};
use miraserve_core::{ListenerKind, MiraServeServer, ServerOptions};
use miraserve_tls::build_crypto_provider;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::AsyncReadExt as _;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Serializes every test in this binary across its ENTIRE Tokio runtime lifecycle (runtime build,
/// execution, `drop(rt)` teardown of all server/client/upstream/blocking tasks, and offloaded-log
/// queue drain) so process-wide test hooks, counters, latches, sinks, and offloaded queues are
/// never observed concurrently by another test or its dying runtime.
fn h2_tls_test_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

struct PostRuntimeFlushGuard;

impl Drop for PostRuntimeFlushGuard {
    fn drop(&mut self) {
        let _ = miraserve_http::flush_offloaded_logs_until_blocking(
            Instant::now() + Duration::from_secs(5),
        );
    }
}

fn run_h2_tls_test<F>(mut builder: tokio::runtime::Builder, f: F) -> TestResult
where
    F: std::future::Future<Output = TestResult>,
{
    let _serial = h2_tls_test_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let pre = miraserve_http::flush_offloaded_logs_until_blocking(
        Instant::now() + Duration::from_secs(5),
    );
    assert!(
        pre.is_clean(),
        "offloaded log queues must be clean before starting test (got {pre:?})"
    );
    // Drop order is LIFO: `rt` drops FIRST (completing all server/client/upstream/blocking task
    // teardown), then `_post_flush` drains any records enqueued during runtime teardown (even on
    // panic unwind), and finally `_serial` unlocks for the next test.
    let _post_flush = PostRuntimeFlushGuard;
    let rt = builder.enable_all().build()?;
    let res = rt.block_on(f);
    drop(rt);
    let post = miraserve_http::flush_offloaded_logs_until_blocking(
        Instant::now() + Duration::from_secs(5),
    );
    assert!(
        post.is_clean(),
        "offloaded log queues must drain cleanly after runtime teardown (got {post:?})"
    );
    res
}

fn run_h2_tls_current_thread<F>(f: F) -> TestResult
where
    F: std::future::Future<Output = TestResult>,
{
    run_h2_tls_test(tokio::runtime::Builder::new_current_thread(), f)
}

fn run_h2_tls_multi_thread<F>(worker_threads: usize, f: F) -> TestResult
where
    F: std::future::Future<Output = TestResult>,
{
    let mut b = tokio::runtime::Builder::new_multi_thread();
    b.worker_threads(worker_threads);
    run_h2_tls_test(b, f)
}

struct InTaskH2TestGuard {
    _exec: miraserve_http::TestH2ExecOverrideGuard,
}

/// Forces HTTP/2 connections in general in-task tests onto `InTaskExec` via the explicit
/// `test-h2-hooks` feature so tests pass consistently in both debug and `--release` profiles
/// even when the host/container filters `openat2` (Linux capability-specific tests exercise the
/// real capability check and skip with a printed reason when filtered).
fn enter_in_task_h2_test_mode() -> InTaskH2TestGuard {
    InTaskH2TestGuard {
        _exec: miraserve_http::test_h2_exec_override_guard(Some(true)),
    }
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Result<Self, std::io::Error> {
        static SEQ: AtomicUsize = AtomicUsize::new(1);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "miraserve-h2it-tls-{tag}-{}-{}-{nanos}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed),
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

fn build_h2_tls_client(
    dev_cert_pem: &str,
) -> Result<Arc<ClientConfig>, Box<dyn std::error::Error>> {
    let mut roots = RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(dev_cert_pem.as_bytes()).collect::<Result<_, _>>()?;
    let (added, _) = roots.add_parsable_certificates(certs);
    assert_eq!(added, 1);
    let mut cfg = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(cfg))
}

async fn connect_h2_tls<B>(
    addr: SocketAddr,
    host: &str,
    tls_cfg: &Arc<ClientConfig>,
) -> Result<(h2_client::SendRequest<B>, JoinHandle<()>), Box<dyn std::error::Error>>
where
    B: HttpBodyTrait + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let tcp = TcpStream::connect(addr).await?;
    let _ = tcp.set_nodelay(true);
    let tls = TlsConnector::from(Arc::clone(tls_cfg))
        .connect(ServerName::try_from(host.to_owned())?, tcp)
        .await?;
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (sender, conn) =
        h2_client::handshake::<_, _, B>(TokioExecutor::new(), TokioIo::new(tls)).await?;
    let task = tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok((sender, task))
}

/// Many streams on ONE real TCP + TLS 1.3 HTTP/2 connection finish in order of completion (not
/// request order) with exact response bodies.
#[test]
#[allow(clippy::too_many_lines)]
fn h2_tls_many_streams_answered_in_completion_order_with_correct_bodies() -> TestResult {
    run_h2_tls_current_thread(async {
        const STREAM_COUNT: usize = 24;
        let _mode = enter_in_task_h2_test_mode();
        let tmp = TempDir::new("order")?;
        fs::write(tmp.path.join("fast.txt"), b"fast-static-body")?;

        // Per-stream gates so we can release responses in exact reverse order (23, 22, ..., 0).
        let gates: Arc<Vec<Notify>> = Arc::new((0..STREAM_COUNT).map(|_| Notify::new()).collect());
        let entered: Arc<Vec<Notify>> =
            Arc::new((0..STREAM_COUNT).map(|_| Notify::new()).collect());

        let up_listener = TcpListener::bind("127.0.0.1:0").await?;
        let up_addr = up_listener.local_addr()?;
        let gates_srv = Arc::clone(&gates);
        let entered_srv = Arc::clone(&entered);
        let up_task = tokio::spawn(async move {
            while let Ok((stream, _)) = up_listener.accept().await {
                let gates = Arc::clone(&gates_srv);
                let entered = Arc::clone(&entered_srv);
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let gates = Arc::clone(&gates);
                        let entered = Arc::clone(&entered);
                        async move {
                            let id = req
                                .uri()
                                .path()
                                .rsplit('/')
                                .next()
                                .and_then(|s| s.parse::<usize>().ok())
                                .unwrap_or(0);
                            if let Some(e) = entered.get(id) {
                                e.notify_one();
                            }
                            if let Some(g) = gates.get(id) {
                                g.notified().await;
                            }
                            let payload = format!("stream-{id:02}:{}", "x".repeat(64 + id * 37));
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(payload))))
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });

        let tls_port = reserve_free_port()?;
        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
}}
site "order.h2it.test" {{
    root "{root}"
    route "/item/*" {{
        reverse-proxy {{
            upstream "http://{up_addr}"
        }}
    }}
}}
"#,
            root = tmp.path.to_string_lossy().replace('\\', "/"),
        );
        let (cfg, _) = parse_kdl("h2it-order.kdl", &kdl)?;
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
            .ok_or("missing HTTPS listener")?
            .local_addr;
        let tls_cfg = build_h2_tls_client(server.dev_cert_pem().ok_or("missing dev cert")?)?;
        let (mut sender, conn_task) =
            connect_h2_tls::<Empty<Bytes>>(https_addr, "order.h2it.test", &tls_cfg).await?;

        let mut handles = Vec::with_capacity(STREAM_COUNT);
        for id in 0..STREAM_COUNT {
            sender.ready().await?;
            let fut = sender.send_request(
                Request::builder()
                    .uri(format!("https://order.h2it.test/item/{id}"))
                    .body(Empty::new())?,
            );
            handles.push(tokio::spawn(async move {
                let resp = fut.await?;
                let status = resp.status();
                let body = resp.into_body().collect().await?.to_bytes();
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>((id, status, body))
            }));
        }

        // Wait until all 24 streams have reached the upstream concurrently.
        for e in entered.iter() {
            tokio::time::timeout(Duration::from_secs(10), e.notified()).await?;
        }

        // Release in exact reverse order and verify each stream finishes BEFORE earlier ones are
        // even released.
        let mut completion_order = Vec::with_capacity(STREAM_COUNT);
        for id in (0..STREAM_COUNT).rev() {
            if let Some(g) = gates.get(id) {
                g.notify_one();
            }
            let Some(handle) = handles.get_mut(id) else {
                return Err("missing handle".into());
            };
            let (got_id, status, body) = tokio::time::timeout(Duration::from_secs(5), handle)
                .await??
                .map_err(|e| e.to_string())?;
            assert_eq!(got_id, id);
            assert_eq!(status, StatusCode::OK);
            let expected = format!("stream-{id:02}:{}", "x".repeat(64 + id * 37));
            assert_eq!(body.as_ref(), expected.as_bytes());
            completion_order.push(got_id);
        }
        let expected_order: Vec<usize> = (0..STREAM_COUNT).rev().collect();
        assert_eq!(completion_order, expected_order);

        drop(sender);
        conn_task.abort();
        up_task.abort();
        server.shutdown().await;
        Ok(())
    })
}

/// A slow upstream on stream 1 must not delay sibling static or fast-upstream streams on the same
/// real TCP + TLS 1.3 HTTP/2 connection.
#[test]
#[allow(clippy::too_many_lines)]
fn h2_tls_slow_upstream_does_not_delay_sibling_streams() -> TestResult {
    run_h2_tls_current_thread(async {
        let _mode = enter_in_task_h2_test_mode();
        let tmp = TempDir::new("slow-up")?;
        fs::write(tmp.path.join("fast.txt"), b"instant-static-payload")?;

        let slow_entered = Arc::new(Notify::new());
        let slow_release = Arc::new(Notify::new());
        let slow_entered_srv = Arc::clone(&slow_entered);
        let slow_release_srv = Arc::clone(&slow_release);

        let up_listener = TcpListener::bind("127.0.0.1:0").await?;
        let up_addr = up_listener.local_addr()?;
        let up_task = tokio::spawn(async move {
            while let Ok((stream, _)) = up_listener.accept().await {
                let entered = Arc::clone(&slow_entered_srv);
                let release = Arc::clone(&slow_release_srv);
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let entered = Arc::clone(&entered);
                        let release = Arc::clone(&release);
                        async move {
                            if req.uri().path().starts_with("/up/slow") {
                                entered.notify_one();
                                release.notified().await;
                                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                                    b"finally-slow",
                                ))))
                            } else {
                                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                                    b"fast-upstream",
                                ))))
                            }
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });

        let tls_port = reserve_free_port()?;
        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
}}
site "slow.h2it.test" {{
    root "{root}"
    route "/up/*" {{
        reverse-proxy {{
            upstream "http://{up_addr}"
        }}
    }}
}}
"#,
            root = tmp.path.to_string_lossy().replace('\\', "/"),
        );
        let (cfg, _) = parse_kdl("h2it-slow.kdl", &kdl)?;
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
            .ok_or("missing HTTPS listener")?
            .local_addr;
        let tls_cfg = build_h2_tls_client(server.dev_cert_pem().ok_or("missing dev cert")?)?;
        let (mut sender, conn_task) =
            connect_h2_tls::<Empty<Bytes>>(https_addr, "slow.h2it.test", &tls_cfg).await?;

        // Start slow upstream stream and confirm it is blocked on the upstream gate.
        sender.ready().await?;
        let slow_fut = sender.send_request(
            Request::builder()
                .uri("https://slow.h2it.test/up/slow")
                .body(Empty::new())?,
        );
        let slow_handle = tokio::spawn(async move {
            let resp = slow_fut.await?;
            let status = resp.status();
            let body = resp.into_body().collect().await?.to_bytes();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((status, body))
        });
        tokio::time::timeout(Duration::from_secs(5), slow_entered.notified()).await?;

        // While the slow stream is still held, run 8 static and 8 fast-upstream siblings on the same
        // connection.
        for i in 0..16_usize {
            sender.ready().await?;
            let (uri, expected): (&str, &[u8]) = if i % 2 == 0 {
                ("https://slow.h2it.test/fast.txt", b"instant-static-payload")
            } else {
                ("https://slow.h2it.test/up/fast", b"fast-upstream")
            };
            let resp = tokio::time::timeout(
                Duration::from_secs(3),
                sender.send_request(Request::builder().uri(uri).body(Empty::new())?),
            )
            .await??;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = resp.into_body().collect().await?.to_bytes();
            assert_eq!(body.as_ref(), expected);
        }

        // Slow stream must still be pending until we release it.
        assert!(!slow_handle.is_finished());
        slow_release.notify_one();
        let (slow_status, slow_body) = tokio::time::timeout(Duration::from_secs(5), slow_handle)
            .await??
            .map_err(|e| e.to_string())?;
        assert_eq!(slow_status, StatusCode::OK);
        assert_eq!(slow_body.as_ref(), b"finally-slow");

        drop(sender);
        conn_task.abort();
        up_task.abort();
        server.shutdown().await;
        Ok(())
    })
}

/// Client `RST_STREAM` over real TCP + TLS 1.3 while a stream future is pending drops the server's
/// stream future (closing the upstream socket) and zeroes the in-flight counter so the connection
/// closes cleanly at `idle-keepalive`.
#[test]
#[allow(clippy::too_many_lines)]
fn h2_tls_client_reset_while_pending_drops_future_and_allows_idle_close() -> TestResult {
    run_h2_tls_current_thread(async {
        let _mode = enter_in_task_h2_test_mode();
        let tmp = TempDir::new("rst-idle")?;
        fs::write(tmp.path.join("ok.txt"), b"ok-after-rst")?;

        let up_entered = Arc::new(Notify::new());
        let up_saw_eof = Arc::new(Notify::new());
        let up_entered_srv = Arc::clone(&up_entered);
        let up_saw_eof_srv = Arc::clone(&up_saw_eof);

        let up_listener = TcpListener::bind("127.0.0.1:0").await?;
        let up_addr = up_listener.local_addr()?;
        let up_task = tokio::spawn(async move {
            if let Ok((mut sock, _)) = up_listener.accept().await {
                let mut buf = [0_u8; 2048];
                let _ = sock.read(&mut buf).await;
                up_entered_srv.notify_one();
                let mut probe = [0_u8; 64];
                loop {
                    match sock.read(&mut probe).await {
                        Ok(0) | Err(_) => {
                            up_saw_eof_srv.notify_one();
                            break;
                        }
                        Ok(_) => {}
                    }
                }
            }
        });

        let tls_port = reserve_free_port()?;
        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
    timeouts {{
        idle-keepalive "800ms"
        response-write-idle "400ms"
        graceful-drain "800ms"
    }}
}}
site "rst.h2it.test" {{
    root "{root}"
    route "/hang/*" {{
        reverse-proxy {{
            upstream "http://{up_addr}"
        }}
    }}
}}
"#,
            root = tmp.path.to_string_lossy().replace('\\', "/"),
        );
        let (cfg, _) = parse_kdl("h2it-rst.kdl", &kdl)?;
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
            .ok_or("missing HTTPS listener")?
            .local_addr;
        let tls_cfg = build_h2_tls_client(server.dev_cert_pem().ok_or("missing dev cert")?)?;
        let (mut sender, mut conn_task) =
            connect_h2_tls::<Empty<Bytes>>(https_addr, "rst.h2it.test", &tls_cfg).await?;

        sender.ready().await?;
        let pending_fut = sender.send_request(
            Request::builder()
                .uri("https://rst.h2it.test/hang/1")
                .body(Empty::new())?,
        );
        let pending_task = tokio::spawn(async move {
            let _ = pending_fut.await;
        });
        tokio::time::timeout(Duration::from_secs(5), up_entered.notified()).await?;

        // Drop the client's response future -> sends `RST_STREAM(CANCEL)` over TLS.
        pending_task.abort();
        let _ = pending_task.await;

        // Server must drop the pending stream future promptly.
        tokio::time::timeout(Duration::from_secs(5), up_saw_eof.notified()).await?;

        // Follow-up request succeeds on the same connection. Capture `idle_anchor` BEFORE sending
        // `/ok.txt` so the lower-bound assertion is immune to post-response scheduling jitter on a
        // loaded host (the server cannot start its `idle-keepalive` clock before `/ok.txt` finishes).
        let idle_anchor = Instant::now();
        sender.ready().await?;
        let ok_resp = sender
            .send_request(
                Request::builder()
                    .uri("https://rst.h2it.test/ok.txt")
                    .body(Empty::new())?,
            )
            .await?;
        assert_eq!(ok_resp.status(), StatusCode::OK);
        assert_eq!(
            ok_resp.into_body().collect().await?.to_bytes().as_ref(),
            b"ok-after-rst"
        );
        assert!(
            !conn_task.is_finished(),
            "connection must stay open immediately after /ok.txt"
        );

        // Keep `sender` open and silent: because the reset stream returned `in_flight` to 0, the
        // server's `h2_watch` idle timer must close the connection cleanly after `idle-keepalive`.
        tokio::time::timeout(Duration::from_secs(6), &mut conn_task)
            .await
            .map_err(
                |_| "connection must close at idle-keepalive after reset stream cleaned up",
            )??;
        assert!(
            idle_anchor.elapsed() >= Duration::from_millis(650),
            "closed too early ({:?})",
            idle_anchor.elapsed()
        );

        drop(sender);
        up_task.abort();
        server.shutdown().await;
        Ok(())
    })
}

/// Graceful shutdown (`MiraServeServer::shutdown`) drains in-flight HTTP/2 streams on a real TCP +
/// TLS 1.3 connection to completion before closing.
#[test]
#[allow(clippy::too_many_lines)]
fn h2_tls_graceful_shutdown_drains_inflight_streams() -> TestResult {
    run_h2_tls_current_thread(async {
        const INFLIGHT: usize = 4;
        let _mode = enter_in_task_h2_test_mode();
        let tmp = TempDir::new("drain")?;

        let entered = Arc::new(AtomicUsize::new(0));
        let all_entered = Arc::new(Notify::new());
        let (release_tx, release_rx) = tokio::sync::watch::channel(false);

        let entered_srv = Arc::clone(&entered);
        let all_entered_srv = Arc::clone(&all_entered);

        let up_listener = TcpListener::bind("127.0.0.1:0").await?;
        let up_addr = up_listener.local_addr()?;
        let up_task = tokio::spawn(async move {
            while let Ok((stream, _)) = up_listener.accept().await {
                let entered = Arc::clone(&entered_srv);
                let all_entered = Arc::clone(&all_entered_srv);
                let release_rx = release_rx.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let entered = Arc::clone(&entered);
                        let all_entered = Arc::clone(&all_entered);
                        let mut release_rx = release_rx.clone();
                        async move {
                            let path = req.uri().path().to_owned();
                            if entered.fetch_add(1, Ordering::AcqRel) + 1 == INFLIGHT {
                                all_entered.notify_one();
                            }
                            let _ = release_rx.wait_for(|&v| v).await;
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(format!(
                                "drained:{path}"
                            )))))
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });

        let tls_port = reserve_free_port()?;
        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
    timeouts {{
        graceful-drain "5s"
    }}
}}
site "drain.h2it.test" {{
    root "{root}"
    route "/work/*" {{
        reverse-proxy {{
            upstream "http://{up_addr}"
        }}
    }}
}}
"#,
            root = tmp.path.to_string_lossy().replace('\\', "/"),
        );
        let (cfg, _) = parse_kdl("h2it-drain.kdl", &kdl)?;
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
            .ok_or("missing HTTPS listener")?
            .local_addr;
        let tls_cfg = build_h2_tls_client(server.dev_cert_pem().ok_or("missing dev cert")?)?;
        let (mut sender, conn_task) =
            connect_h2_tls::<Empty<Bytes>>(https_addr, "drain.h2it.test", &tls_cfg).await?;

        let mut handles = Vec::with_capacity(INFLIGHT);
        for i in 0..INFLIGHT {
            sender.ready().await?;
            let fut = sender.send_request(
                Request::builder()
                    .uri(format!("https://drain.h2it.test/work/{i}"))
                    .body(Empty::new())?,
            );
            handles.push(tokio::spawn(async move {
                let resp = fut.await?;
                let status = resp.status();
                let body = resp.into_body().collect().await?.to_bytes();
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>((i, status, body))
            }));
        }

        tokio::time::timeout(Duration::from_secs(5), all_entered.notified()).await?;

        // Initiate graceful shutdown while all 4 HTTP/2 streams are in flight.
        let shutdown_task = tokio::spawn(async move { server.shutdown_with_report().await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !shutdown_task.is_finished(),
            "shutdown must wait while in-flight HTTP/2 streams are still draining"
        );

        // Release the upstream gate: every in-flight stream must complete cleanly.
        let _ = release_tx.send(true);
        for handle in handles {
            let (i, status, body) = tokio::time::timeout(Duration::from_secs(5), handle)
                .await??
                .map_err(|e| e.to_string())?;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body.as_ref(), format!("drained:/work/{i}").as_bytes());
        }

        drop(sender);
        let report = tokio::time::timeout(Duration::from_secs(5), shutdown_task).await??;
        assert!(
            !report.connections_forced_closed
                && !report.workers_join_timed_out
                && report.is_clean(),
            "clean graceful shutdown must report clean drain (got {report:?})"
        );
        let _ = tokio::time::timeout(Duration::from_secs(5), conn_task).await;
        up_task.abort();
        Ok(())
    })
}

/// Multi-frame request body for upload tests (including an explicit empty DATA frame).
struct ChunkedBody(VecDeque<Bytes>);

impl HttpBodyTrait for ChunkedBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.0.pop_front().map(|chunk| Ok(Frame::data(chunk))))
    }
}

/// Concurrent multiplexed uploads (multi-chunk, 128 KiB payload, and empty-DATA-frame uploads)
/// over one real TCP + TLS 1.3 HTTP/2 connection arrive intact at the upstream.
#[test]
#[allow(clippy::too_many_lines)]
fn h2_tls_multiplexed_uploads_including_empty_data_frames() -> TestResult {
    run_h2_tls_current_thread(async {
        let _mode = enter_in_task_h2_test_mode();
        let tmp = TempDir::new("uploads")?;

        let up_listener = TcpListener::bind("127.0.0.1:0").await?;
        let up_addr = up_listener.local_addr()?;
        let up_task = tokio::spawn(async move {
            while let Ok((stream, _)) = up_listener.accept().await {
                tokio::spawn(async move {
                    let svc = service_fn(|req: Request<Incoming>| async move {
                        let body = req
                            .into_body()
                            .collect()
                            .await
                            .map_or_else(|_| Bytes::new(), http_body_util::Collected::to_bytes);
                        Ok::<_, Infallible>(Response::new(Full::new(body)))
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });

        let tls_port = reserve_free_port()?;
        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
}}
site "upload.h2it.test" {{
    root "{root}"
    route "/echo/*" {{
        reverse-proxy {{
            upstream "http://{up_addr}"
        }}
    }}
}}
"#,
            root = tmp.path.to_string_lossy().replace('\\', "/"),
        );
        let (cfg, _) = parse_kdl("h2it-upload.kdl", &kdl)?;
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
            .ok_or("missing HTTPS listener")?
            .local_addr;
        let tls_cfg = build_h2_tls_client(server.dev_cert_pem().ok_or("missing dev cert")?)?;
        let (mut sender, conn_task) =
            connect_h2_tls::<ChunkedBody>(https_addr, "upload.h2it.test", &tls_cfg).await?;

        let mut handles = Vec::new();
        for i in 0_u8..12 {
            let mut chunks = VecDeque::new();
            let mut expected = Vec::new();
            if i == 0 {
                // 128 KiB multi-chunk upload.
                for c in 0_u8..8 {
                    let piece = vec![b'A'.wrapping_add(c); 16 * 1024];
                    expected.extend_from_slice(&piece);
                    chunks.push_back(Bytes::from(piece));
                }
            } else {
                // Non-empty chunk followed by an explicit empty DATA frame (GCP-style framing).
                let piece = vec![b'a'.wrapping_add(i); 2048 + usize::from(i) * 113];
                expected.extend_from_slice(&piece);
                chunks.push_back(Bytes::from(piece));
                chunks.push_back(Bytes::new());
            }
            sender.ready().await?;
            let fut = sender.send_request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("https://upload.h2it.test/echo/{i}"))
                    .body(ChunkedBody(chunks))?,
            );
            handles.push(tokio::spawn(async move {
                let resp = fut.await?;
                let status = resp.status();
                let got = resp.into_body().collect().await?.to_bytes();
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>((i, status, got, expected))
            }));
        }

        for handle in handles {
            let (i, status, got, expected) = tokio::time::timeout(Duration::from_secs(10), handle)
                .await??
                .map_err(|e| e.to_string())?;
            assert_eq!(status, StatusCode::OK, "upload {i}");
            assert_eq!(
                got.as_ref(),
                expected.as_slice(),
                "upload {i} payload mismatch"
            );
        }
        assert!(
            !conn_task.is_finished(),
            "connection must stay open after uploads"
        );

        drop(sender);
        conn_task.abort();
        up_task.abort();
        server.shutdown().await;
        Ok(())
    })
}

/// Fairness over real TCP + TLS 1.3 on a single-thread runtime: while Connection A continuously
/// pipelines 80-stream bursts of fast requests, Connection B completes 20 sequential requests
/// promptly without starvation.
#[test]
#[allow(clippy::too_many_lines)]
fn h2_tls_fairness_two_connections_on_single_thread_runtime() -> TestResult {
    run_h2_tls_current_thread(async {
        let _mode = enter_in_task_h2_test_mode();
        let tmp = TempDir::new("fair")?;
        fs::write(tmp.path.join("small.txt"), vec![b'z'; 1024])?;

        let tls_port = reserve_free_port()?;
        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
    limits {{
        max-concurrent-streams 256
    }}
}}
site "fair.h2it.test" {{
    root "{root}"
    route "/fast" {{
        respond 410
    }}
}}
"#,
            root = tmp.path.to_string_lossy().replace('\\', "/"),
        );
        let (cfg, _) = parse_kdl("h2it-fair.kdl", &kdl)?;
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
            .ok_or("missing HTTPS listener")?
            .local_addr;
        let tls_cfg = build_h2_tls_client(server.dev_cert_pem().ok_or("missing dev cert")?)?;

        let (sender_a, conn_a) =
            connect_h2_tls::<Empty<Bytes>>(https_addr, "fair.h2it.test", &tls_cfg).await?;
        let (mut sender_b, conn_b) =
            connect_h2_tls::<Empty<Bytes>>(https_addr, "fair.h2it.test", &tls_cfg).await?;

        let stop = Arc::new(AtomicBool::new(false));
        let a_done = Arc::new(AtomicUsize::new(0));
        let stop_a = Arc::clone(&stop);
        let a_done_c = Arc::clone(&a_done);

        let flood_a = tokio::spawn(async move {
            let mut sender = sender_a;
            while !stop_a.load(Ordering::Relaxed) {
                let mut batch = Vec::with_capacity(80);
                for _ in 0..80 {
                    if sender.ready().await.is_err() {
                        return;
                    }
                    let Ok(req) = Request::builder()
                        .uri("https://fair.h2it.test/fast")
                        .body(Empty::new())
                    else {
                        return;
                    };
                    batch.push(sender.send_request(req));
                }
                for fut in batch {
                    if let Ok(resp) = fut.await
                        && resp.into_body().collect().await.is_ok()
                    {
                        a_done_c.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });

        // Wait until A has completed at least one saturated 80-stream burst, failing promptly if the
        // producer exits early.
        let warmup_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while a_done.load(Ordering::Relaxed) < 80 {
            if flood_a.is_finished() {
                return Err(format!(
                    "connection A flooder exited early at {} completions",
                    a_done.load(Ordering::Relaxed)
                )
                .into());
            }
            if tokio::time::Instant::now() >= warmup_deadline {
                return Err(format!(
                    "connection A warmup timed out at {} completions",
                    a_done.load(Ordering::Relaxed)
                )
                .into());
            }
            tokio::task::yield_now().await;
        }

        let a_before_b = a_done.load(Ordering::Relaxed);
        for _ in 0..20 {
            sender_b.ready().await?;
            let resp = tokio::time::timeout(
                Duration::from_secs(10),
                sender_b.send_request(
                    Request::builder()
                        .uri("https://fair.h2it.test/small.txt")
                        .body(Empty::new())?,
                ),
            )
            .await??;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = resp.into_body().collect().await?.to_bytes();
            assert_eq!(body.len(), 1024);
        }
        assert!(
            !flood_a.is_finished(),
            "connection A flooder must stay active throughout connection B's requests"
        );
        let a_after_b = a_done.load(Ordering::Relaxed);
        stop.store(true, Ordering::Relaxed);
        assert!(
            a_after_b > a_before_b,
            "connection A must also keep making interleaved progress (before={a_before_b}, after={a_after_b})"
        );

        drop(sender_b);
        let _ = tokio::time::timeout(Duration::from_secs(5), flood_a).await;
        conn_a.abort();
        conn_b.abort();
        server.shutdown().await;
        Ok(())
    })
}

/// Runs a compute-heavy WASM plugin over:
/// - 1 HTTP/2 TLS connection carrying 8 concurrent requests, and
/// - 4 HTTP/2 TLS connections carrying 2 concurrent requests each.
///
/// Asserts 200 OK and expected body on all requests.
#[test]
#[allow(clippy::too_many_lines)]
fn h2_tls_single_conn_vs_multi_conn_wasm_cpu_bound() -> TestResult {
    run_h2_tls_multi_thread(4, async {
        const TOTAL_REQS: usize = 8;
        let _mode = enter_in_task_h2_test_mode();
        let tmp = TempDir::new("wasm-cpu")?;
        let wat_path = tmp.path.join("burn.wat");
        // Pure CPU loop (400,000 iterations, within the 10,000,000 `max-fuel` cap) returning 200 OK.
        fs::write(
            &wat_path,
            r#"
(module
  (import "miraserve" "set_response_body" (func $set_body (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 1024) "wasm-burned-ok")
  (func (export "miraserve_handle") (param i32 i32 i32 i32) (result i32)
    (local $i i32)
    (local $acc i32)
    (local.set $i (i32.const 0))
    (local.set $acc (i32.const 1))
    (block $done
      (loop $step
        (br_if $done (i32.ge_u (local.get $i) (i32.const 400000)))
        (local.set $acc (i32.xor (i32.mul (local.get $acc) (i32.const 1664525)) (local.get $i)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $step)
      )
    )
    (i32.store (i32.const 2048) (local.get $acc))
    (drop (call $set_body (i32.const 1024) (i32.const 14)))
    (i32.const 200)
  )
)
"#,
        )?;

        let tls_port = reserve_free_port()?;
        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
}}
site "wasm.h2it.test" {{
    route "/burn/*" {{
        wasm-plugin "{wat}" max-memory="2MB" max-fuel=10000000 timeout="10s"
    }}
}}
"#,
            wat = wat_path.to_string_lossy().replace('\\', "/"),
        );
        let (cfg, _) = parse_kdl("h2it-wasm.kdl", &kdl)?;
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
            .ok_or("missing HTTPS listener")?
            .local_addr;
        let tls_cfg = build_h2_tls_client(server.dev_cert_pem().ok_or("missing dev cert")?)?;

        // Warmup 1 request to prime JIT/caches.
        {
            let (mut warm_s, warm_c) =
                connect_h2_tls::<Empty<Bytes>>(https_addr, "wasm.h2it.test", &tls_cfg).await?;
            warm_s.ready().await?;
            let r = warm_s
                .send_request(
                    Request::builder()
                        .uri("https://wasm.h2it.test/burn/warm")
                        .body(Empty::new())?,
                )
                .await?;
            assert_eq!(r.status(), StatusCode::OK);
            let _ = r.into_body().collect().await?;
            drop(warm_s);
            warm_c.abort();
        }

        // Case A: 1 connection x 8 concurrent streams.
        let (mut s1, c1) =
            connect_h2_tls::<Empty<Bytes>>(https_addr, "wasm.h2it.test", &tls_cfg).await?;
        let t_one = Instant::now();
        let mut futs_one = Vec::with_capacity(TOTAL_REQS);
        for i in 0..TOTAL_REQS {
            s1.ready().await?;
            let f = s1.send_request(
                Request::builder()
                    .uri(format!("https://wasm.h2it.test/burn/one-{i}"))
                    .body(Empty::new())?,
            );
            futs_one.push(tokio::spawn(async move {
                let r = f.await?;
                let status = r.status();
                let body = r.into_body().collect().await?.to_bytes();
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>((status, body))
            }));
        }
        for h in futs_one {
            let (status, body) = h.await?.map_err(|e| e.to_string())?;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body.as_ref(), b"wasm-burned-ok");
        }
        let one_conn_ms = t_one.elapsed().as_millis();
        drop(s1);
        c1.abort();

        // Case B: 4 connections x 2 concurrent streams each (same 8 total requests).
        let mut senders = Vec::with_capacity(4);
        let mut conns = Vec::with_capacity(4);
        for _ in 0..4 {
            let (s, c) =
                connect_h2_tls::<Empty<Bytes>>(https_addr, "wasm.h2it.test", &tls_cfg).await?;
            senders.push(s);
            conns.push(c);
        }
        let t_four = Instant::now();
        let mut futs_four = Vec::with_capacity(TOTAL_REQS);
        for (ci, s) in senders.iter_mut().enumerate() {
            for j in 0..2 {
                s.ready().await?;
                let f = s.send_request(
                    Request::builder()
                        .uri(format!("https://wasm.h2it.test/burn/four-{ci}-{j}"))
                        .body(Empty::new())?,
                );
                futs_four.push(tokio::spawn(async move {
                    let r = f.await?;
                    let status = r.status();
                    let body = r.into_body().collect().await?.to_bytes();
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>((status, body))
                }));
            }
        }
        for h in futs_four {
            let (status, body) = h.await?.map_err(|e| e.to_string())?;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body.as_ref(), b"wasm-burned-ok");
        }
        let four_conn_ms = t_four.elapsed().as_millis();
        drop(senders);
        for c in conns {
            c.abort();
        }

        eprintln!(
            "[h2_intask wasm cpu-bound 8 reqs, 4 worker threads] 1 conn x 8 streams: {one_conn_ms} ms | 4 conns x 2 streams: {four_conn_ms} ms"
        );
        server.shutdown().await;
        Ok(())
    })
}

/// On Linux with non-blocking static capability, a stream on a suitable (`atime_free`) root whose
/// static lookup, small-file read, or nested-mount `mount_id` mismatch hits the blocking-pool path
/// must not stall a warm sibling static stream on the SAME real TCP + TLS 1.3 HTTP/2 connection.
#[cfg(target_os = "linux")]
#[test]
#[allow(clippy::too_many_lines)]
fn h2_tls_cold_static_lookup_and_read_do_not_stall_sibling_stream() -> TestResult {
    run_h2_tls_multi_thread(2, async {
        let _kernel = miraserve_static::test_nowait_kernel_in_range_override_guard(Some(true));
        let support = miraserve_core::probe_nonblocking_static_support();
        if support != miraserve_core::NonblockingStaticSupport::Available {
            eprintln!(
                "SKIP h2_tls_cold_static_lookup_and_read_do_not_stall_sibling_stream: host lacks non-blocking static support ({:?}: {})",
                support,
                support.reason()
            );
            return Ok(());
        }
        let _atime_free = miraserve_static::test_root_atime_free_override_guard(Some(true));

        let tmp = TempDir::new("cold-static")?;
        let cold_bytes = vec![b'C'; 4096];
        let warm_bytes = b"warm-inline-sibling-ok".to_vec();
        fs::write(tmp.path.join("cold.txt"), &cold_bytes)?;
        fs::write(tmp.path.join("warm.txt"), &warm_bytes)?;
        // Warm dentries/pages directly on disk without risking an overlayfs/tmpfs EOPNOTSUPP latch
        // on the StaticServer before testing the cold cases.
        let _ = fs::read(tmp.path.join("warm.txt"))?;
        let _ = fs::read(tmp.path.join("cold.txt"))?;

        let tls_port = reserve_free_port()?;
        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
}}
site "cold.h2it.test" {{
    root "{root}"
}}
"#,
            root = tmp.path.to_string_lossy().replace('\\', "/"),
        );
        let (cfg, _) = parse_kdl("h2it-cold-static.kdl", &kdl)?;
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
            .ok_or("missing HTTPS listener")?
            .local_addr;
        let tls_cfg = build_h2_tls_client(server.dev_cert_pem().ok_or("missing dev cert")?)?;
        let (mut sender, conn_task) =
            connect_h2_tls::<Empty<Bytes>>(https_addr, "cold.h2it.test", &tls_cfg).await?;

        // Verify InTaskExec ran using HEAD (never triggers filesystem NOWAIT refusal).
        let (intask_before, spawned_before) = miraserve_http::test_h2_exec_stream_counts();
        sender.ready().await?;
        let warm_resp = sender
            .send_request(
                Request::builder()
                    .method(Method::HEAD)
                    .uri("https://cold.h2it.test/warm.txt")
                    .body(Empty::new())?,
            )
            .await?;
        assert_eq!(warm_resp.status(), StatusCode::OK);
        let _ = warm_resp.into_body().collect().await?;
        let (intask_after, spawned_after) = miraserve_http::test_h2_exec_stream_counts();
        assert!(
            intask_after > intask_before && spawned_after == spawned_before,
            "expected InTaskExec on capable Linux host: before=({intask_before},{spawned_before}) after=({intask_after},{spawned_after})"
        );

        // Run all three suitable-root pool-handoff scenarios on the same HTTP/2 TLS connection:
        // (1) RESOLVE_CACHED EAGAIN (lookup offloads to blocking pool)
        // (2) RWF_NOWAIT read EAGAIN (retained descriptor offloads to blocking pool)
        // (3) Nested-mount `mount_id` mismatch (retained descriptor offloads to blocking pool with 0 preadv2 calls)
        for case in [
            "resolve_cached_eagain",
            "nowait_read_eagain",
            "mount_id_mismatch",
        ] {
            let entered_pool = Arc::new(Notify::new());
            let entered_c = Arc::clone(&entered_pool);
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            let release_rx = Arc::new(std::sync::Mutex::new(Some(release_rx)));
            let _pool_hook =
                miraserve_static::test_blocking_pool_hook_guard(Arc::new(move |rel| {
                    if rel.to_string_lossy().ends_with("cold.txt") {
                        entered_c.notify_one();
                        if let Some(rx) = release_rx
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .take()
                        {
                            let _ = rx.recv_timeout(Duration::from_secs(10));
                        }
                    }
                }));

            let force_lookup = if case == "resolve_cached_eagain" {
                Some(miraserve_static::test_force_resolve_cached_eagain_guard())
            } else {
                None
            };
            let force_read = if case == "nowait_read_eagain" {
                Some(miraserve_static::test_force_nowait_read_eagain_guard())
            } else {
                None
            };
            let force_mnt = if case == "mount_id_mismatch" {
                Some(miraserve_static::test_force_file_mount_id_mismatch_guard())
            } else {
                None
            };
            let nowait_attempts_before = miraserve_static::test_nowait_syscall_attempts();

            sender.ready().await?;
            let cold_fut = sender.send_request(
                Request::builder()
                    .uri("https://cold.h2it.test/cold.txt")
                    .body(Empty::new())?,
            );
            let cold_handle = tokio::spawn(async move {
                let resp = cold_fut.await?;
                let status = resp.status();
                let body = resp.into_body().collect().await?.to_bytes();
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>((status, body))
            });

            // Wait until `/cold.txt` is parked inside the blocking pool.
            tokio::time::timeout(Duration::from_secs(5), entered_pool.notified())
                .await
                .map_err(|_| format!("{case}: cold.txt did not enter blocking pool"))?;

            if case == "mount_id_mismatch" {
                assert_eq!(
                    miraserve_static::test_nowait_syscall_attempts(),
                    nowait_attempts_before,
                    "mount_id mismatch must hand off retained fd with 0 preadv2 attempts"
                );
            }

            // Re-enable non-blocking fast path so the sibling `/warm.txt` runs completely inline while
            // `/cold.txt` remains blocked on its pool thread.
            drop(force_lookup);
            drop(force_read);
            drop(force_mnt);

            let pool_entries_before = miraserve_static::static_blocking_pool_entries();
            // `HEAD /warm.txt` exercises `openat2(RESOLVE_CACHED)` + `statx(AT_STATX_DONT_SYNC)`
            // inline on every Linux filesystem (including container `overlayfs`/`tmpfs`, which lack
            // `FMODE_NOWAIT` for `preadv2(RWF_NOWAIT)` on `GET`) with 0 blocking-pool entries while
            // `/cold.txt` remains parked on the pool.
            for _ in 0..4 {
                sender.ready().await?;
                let head_resp = tokio::time::timeout(
                    Duration::from_secs(3),
                    sender.send_request(
                        Request::builder()
                            .method(Method::HEAD)
                            .uri("https://cold.h2it.test/warm.txt")
                            .body(Empty::new())?,
                    ),
                )
                .await??;
                assert_eq!(
                    head_resp.status(),
                    StatusCode::OK,
                    "{case}: warm HEAD sibling status"
                );
                assert!(head_resp.into_body().collect().await?.to_bytes().is_empty());
            }
            assert_eq!(
                miraserve_static::static_blocking_pool_entries(),
                pool_entries_before,
                "{case}: warm HEAD sibling must complete inline without entering the blocking pool"
            );
            assert!(
                !cold_handle.is_finished(),
                "{case}: cold stream must still be blocked on its pool barrier"
            );

            let _ = release_tx.send(());
            let (cold_status, cold_got) = tokio::time::timeout(Duration::from_secs(5), cold_handle)
                .await??
                .map_err(|e| e.to_string())?;
            assert_eq!(cold_status, StatusCode::OK, "{case}: cold status");
            assert_eq!(
                cold_got.as_ref(),
                cold_bytes.as_slice(),
                "{case}: cold body"
            );
        }

        drop(sender);
        conn_task.abort();
        server.shutdown().await;
        Ok(())
    })
}

/// On one real TCP + TLS 1.3 HTTP/2 connection running in-task:
/// - Rewritten/misclassified proxy streams (`/rw-buffered`, `/rw-streamed`) enter the Round 1–5
///   non-blocking safety net (offloading 4 MiB buffered compression to the blocking pool and using
///   `YieldingStreamingCompressedBody` for unknown-length streams) without stalling sibling static
///   streams;
/// - Direct `reverse-proxy` streams (`/big-buffered`) run SPAWNED under Round 6 per-request
///   dispatch (v0.1.4 compression path, no worker pool hop) while sibling `/fast.txt` runs in-task.
#[test]
#[allow(clippy::too_many_lines)]
fn h2_tls_large_proxied_compression_does_not_stall_sibling_stream() -> TestResult {
    use std::io::Write as _;
    use tokio::io::AsyncWriteExt as _;

    run_h2_tls_multi_thread(2, async {
        let _mode = enter_in_task_h2_test_mode();

        let tmp = TempDir::new("proxy-compress-h2")?;
        fs::write(tmp.path.join("fast.txt"), b"fast-sibling-ok")?;

        let mut big_json = Vec::with_capacity(4 * 1024 * 1024);
        for i in 0_u32..131_072 {
            let _ = writeln!(big_json, "{{\"n\":{i},\"service\":\"miraserve-h2it-4m\"}}");
        }
        big_json.truncate(4 * 1024 * 1024);
        let big_json = Arc::new(big_json);
        let stream_chunk = Arc::new(big_json.get(..512 * 1024).unwrap_or(&big_json).to_vec());

        let up_listener = TcpListener::bind("127.0.0.1:0").await?;
        let up_addr = up_listener.local_addr()?;
        let big_c = Arc::clone(&big_json);
        let chunk_c = Arc::clone(&stream_chunk);
        let up_task = tokio::spawn(async move {
            while let Ok((mut sock, _)) = up_listener.accept().await {
                let big = Arc::clone(&big_c);
                let chunk = Arc::clone(&chunk_c);
                tokio::spawn(async move {
                    let mut req_buf = [0_u8; 4096];
                    let n = sock.read(&mut req_buf).await.unwrap_or(0);
                    let head = String::from_utf8_lossy(req_buf.get(..n).unwrap_or(&[]));
                    if head.starts_with("GET /big-buffered") {
                        let hdr = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            big.len()
                        );
                        let _ = sock.write_all(hdr.as_bytes()).await;
                        let _ = sock.write_all(&big).await;
                        let _ = sock.shutdown().await;
                    } else if head.starts_with("GET /big-streamed") {
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
}}
site "compress.h2it.test" {{
    root "{root}"
    rewrite {{
        rule "^/rw-buffered$" to="/big-buffered"
        rule "^/rw-streamed$" to="/big-streamed"
    }}
    route "/big-buffered" {{
        reverse-proxy {{
            upstream "http://{up_addr}"
        }}
    }}
    route "/big-streamed" {{
        reverse-proxy {{
            upstream "http://{up_addr}"
        }}
    }}
}}
"#,
            root = tmp.path.to_string_lossy().replace('\\', "/"),
        );
        let (cfg, _) = parse_kdl("h2it-proxy-compress.kdl", &kdl)?;
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
            .ok_or("missing HTTPS listener")?
            .local_addr;
        let tls_cfg = build_h2_tls_client(server.dev_cert_pem().ok_or("missing dev cert")?)?;
        let (mut sender, conn_task) =
            connect_h2_tls::<Empty<Bytes>>(https_addr, "compress.h2it.test", &tls_cfg).await?;

        // Part A: Rewritten `/rw-buffered` -> `/big-buffered` is classified in-task (safety net):
        // 4 MiB buffered proxied compression parks on the blocking pool via hook while sibling
        // streams on the same connection finish immediately.
        let compress_entered = Arc::new(Notify::new());
        let entered_c = Arc::clone(&compress_entered);
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let release_rx = Arc::new(std::sync::Mutex::new(Some(release_rx)));
        let _compress_hook =
            miraserve_http::test_proxy_compress_pool_hook_guard(Arc::new(move || {
                entered_c.notify_one();
                if let Some(rx) = release_rx
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take()
                {
                    let _ = rx.recv_timeout(Duration::from_secs(10));
                }
            }));

        let (pool_before, yielding_before) = miraserve_http::test_proxy_compress_stats();
        sender.ready().await?;
        let big_fut = sender.send_request(
            Request::builder()
                .uri("https://compress.h2it.test/rw-buffered")
                .header(http::header::ACCEPT_ENCODING, "br")
                .body(Empty::new())?,
        );
        let big_handle = tokio::spawn(async move {
            let resp = big_fut.await?;
            let status = resp.status();
            let enc = resp
                .headers()
                .get(http::header::CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let body = resp.into_body().collect().await?.to_bytes();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((status, enc, body))
        });

        tokio::time::timeout(Duration::from_secs(10), compress_entered.notified())
            .await
            .map_err(|_| "4 MiB buffered proxied compression did not offload to blocking pool")?;

        for _ in 0..4 {
            sender.ready().await?;
            let sib = tokio::time::timeout(
                Duration::from_secs(3),
                sender.send_request(
                    Request::builder()
                        .uri("https://compress.h2it.test/fast.txt")
                        .body(Empty::new())?,
                ),
            )
            .await??;
            assert_eq!(sib.status(), StatusCode::OK);
            assert_eq!(
                sib.into_body().collect().await?.to_bytes().as_ref(),
                b"fast-sibling-ok"
            );
        }
        assert!(
            !big_handle.is_finished(),
            "4 MiB compression stream must still be parked on its pool barrier"
        );

        let _ = release_tx.send(());
        let (big_status, big_enc, big_body) =
            tokio::time::timeout(Duration::from_secs(15), big_handle)
                .await??
                .map_err(|e| e.to_string())?;
        assert_eq!(big_status, StatusCode::OK);
        assert_eq!(big_enc.as_deref(), Some("br"));
        assert!(!big_body.is_empty() && big_body.len() < big_json.len());

        // Part B: Rewritten `/rw-streamed` -> `/big-streamed` selects the yielding wrapper.
        sender.ready().await?;
        let stream_fut = sender.send_request(
            Request::builder()
                .uri("https://compress.h2it.test/rw-streamed")
                .header(http::header::ACCEPT_ENCODING, "br")
                .body(Empty::new())?,
        );
        let stream_handle = tokio::spawn(async move {
            let resp = stream_fut.await?;
            let status = resp.status();
            let enc = resp
                .headers()
                .get(http::header::CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let body = resp.into_body().collect().await?.to_bytes();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((status, enc, body))
        });
        sender.ready().await?;
        let sib2 = tokio::time::timeout(
            Duration::from_secs(5),
            sender.send_request(
                Request::builder()
                    .uri("https://compress.h2it.test/fast.txt")
                    .body(Empty::new())?,
            ),
        )
        .await??;
        assert_eq!(sib2.status(), StatusCode::OK);
        assert_eq!(
            sib2.into_body().collect().await?.to_bytes().as_ref(),
            b"fast-sibling-ok"
        );
        let (st_status, st_enc, st_body) =
            tokio::time::timeout(Duration::from_secs(15), stream_handle)
                .await??
                .map_err(|e| e.to_string())?;
        assert_eq!(st_status, StatusCode::OK);
        assert_eq!(st_enc.as_deref(), Some("br"));
        assert!(!st_body.is_empty() && st_body.len() < 1024 * 1024);

        let (pool_after, yielding_after) = miraserve_http::test_proxy_compress_stats();
        assert!(
            pool_after > pool_before,
            "expected misclassified buffered proxy compression pool offload"
        );
        assert!(
            yielding_after > yielding_before,
            "expected misclassified unknown-length proxy stream to use YieldingStreamingCompressedBody"
        );

        // Part C: Direct `/big-buffered` on the SAME connection runs SPAWNED (v0.1.4 compression
        // path, no non-blocking context -> zero worker compression pool offload), while `/fast.txt`
        // runs IN-TASK.
        let (in_before_c, sp_before_c) = miraserve_http::test_h2_exec_stream_counts();
        let (pool_before_c, yielding_before_c) = miraserve_http::test_proxy_compress_stats();
        sender.ready().await?;
        let direct_resp = sender
            .send_request(
                Request::builder()
                    .uri("https://compress.h2it.test/big-buffered")
                    .header(http::header::ACCEPT_ENCODING, "br")
                    .body(Empty::new())?,
            )
            .await?;
        assert_eq!(direct_resp.status(), StatusCode::OK);
        assert_eq!(
            direct_resp
                .headers()
                .get(http::header::CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok()),
            Some("br")
        );
        let direct_body = direct_resp.into_body().collect().await?.to_bytes();
        assert!(!direct_body.is_empty() && direct_body.len() < big_json.len());

        sender.ready().await?;
        let fast_resp = sender
            .send_request(
                Request::builder()
                    .uri("https://compress.h2it.test/fast.txt")
                    .body(Empty::new())?,
            )
            .await?;
        assert_eq!(fast_resp.status(), StatusCode::OK);
        assert_eq!(
            fast_resp.into_body().collect().await?.to_bytes().as_ref(),
            b"fast-sibling-ok"
        );

        let (in_after_c, sp_after_c) = miraserve_http::test_h2_exec_stream_counts();
        let (pool_after_c, yielding_after_c) = miraserve_http::test_proxy_compress_stats();
        assert_eq!(
            (in_after_c - in_before_c, sp_after_c - sp_before_c),
            (1, 1),
            "direct proxy must run spawned and static sibling must run in-task"
        );
        assert_eq!(
            (pool_after_c, yielding_after_c),
            (pool_before_c, yielding_before_c),
            "direct spawned proxy stream must take v0.1.4 compression path (no non-blocking context)"
        );

        drop(sender);
        conn_task.abort();
        up_task.abort();
        server.shutdown().await;
        Ok(())
    })
}

/// On one TCP + TLS 1.3 HTTP/2 connection, runs `CONCURRENT` WASM plugin requests concurrently
/// against a calibrated per-request timeout, checks executor spawn counters, and verifies
/// cancellation on stream reset and trap reporting.
#[test]
#[allow(clippy::too_many_lines)]
fn h2_tls_wasm_concurrent_requests_meet_deadlines_cancel_and_trap() -> TestResult {
    run_h2_tls_multi_thread(4, async {
        const CONCURRENT: usize = 8;
        let _mode = enter_in_task_h2_test_mode();

        let tmp = TempDir::new("wasm-deadlines")?;
        let burn_wat = tmp.path.join("burn.wat");
        let trap_wat = tmp.path.join("trap.wat");
        let slow_wat = tmp.path.join("slow.wat");

        // 2,500,000-iteration CPU loop (within the 50,000,000 `max-fuel` cap). The test runs
        // `CONCURRENT` requests concurrently against a calibrated per-request timeout and checks
        // that all concurrent responses succeed and the executor counters record spawned streams.
        fs::write(
            &burn_wat,
            r#"
(module
  (import "miraserve" "set_response_body" (func $set_body (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 1024) "wasm-deadline-ok")
  (func (export "miraserve_handle") (param i32 i32 i32 i32) (result i32)
    (local $i i32)
    (local $acc i32)
    (local.set $i (i32.const 0))
    (local.set $acc (i32.const 1))
    (block $done
      (loop $step
        (br_if $done (i32.ge_u (local.get $i) (i32.const 2500000)))
        (local.set $acc (i32.xor (i32.mul (local.get $acc) (i32.const 1664525)) (local.get $i)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $step)
      )
    )
    (i32.store (i32.const 2048) (local.get $acc))
    (drop (call $set_body (i32.const 1024) (i32.const 16)))
    (i32.const 200)
  )
)
"#,
        )?;
        fs::write(
            &trap_wat,
            r#"
(module
  (memory (export "memory") 1)
  (func (export "miraserve_handle") (param i32 i32 i32 i32) (result i32)
    (unreachable)
  )
)
"#,
        )?;
        // Core module executed inside the spawned WASM task before the test hold gate pauses it while
        // holding the sole `wasm_slots` permit, so 1-slot cancellation is deterministic in both debug
        // and `--release` regardless of CPU speed.
        fs::write(
            &slow_wat,
            r#"
(module
  (memory (export "memory") 1)
  (func (export "miraserve_handle") (param i32 i32 i32 i32) (result i32)
    (local $i i32)
    (block $done
      (loop $step
        (br_if $done (i32.ge_u (local.get $i) (i32.const 100000)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $step)
      )
    )
    (i32.const 200)
  )
)
"#,
        )?;

        let tls_port = reserve_free_port()?;
        let make_kdl = |burn_timeout_ms: u64| {
            format!(
                r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
}}
site "wasm-dl.h2it.test" {{
    rewrite {{
        rule "^/rw-slow$" to="/slow"
    }}
    route "/burn/*" {{
        wasm-plugin "{burn}" max-memory="2MB" max-fuel=50000000 timeout="{burn_timeout_ms}ms"
    }}
    route "/trap" {{
        wasm-plugin "{trap}" max-memory="2MB" max-fuel=1000000 timeout="2s"
    }}
    route "/slow" {{
        wasm-plugin "{slow}" max-memory="2MB" max-fuel=50000000 timeout="10s"
    }}
}}
"#,
                burn = burn_wat.to_string_lossy().replace('\\', "/"),
                trap = trap_wat.to_string_lossy().replace('\\', "/"),
                slow = slow_wat.to_string_lossy().replace('\\', "/"),
            )
        };
        let (cfg, _) = parse_kdl("h2it-wasm-dl.kdl", &make_kdl(10_000))?;
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
            .ok_or("missing HTTPS listener")?
            .local_addr;
        let tls_cfg = build_h2_tls_client(server.dev_cert_pem().ok_or("missing dev cert")?)?;
        let (mut sender, conn_task) =
            connect_h2_tls::<Empty<Bytes>>(https_addr, "wasm-dl.h2it.test", &tls_cfg).await?;

        // Calibrate solo runtime on this machine (warmup + median of 3 solo runs).
        let mut solo_samples = Vec::with_capacity(3);
        for i in 0..4 {
            let t0 = Instant::now();
            sender.ready().await?;
            let resp = sender
                .send_request(
                    Request::builder()
                        .uri(format!("https://wasm-dl.h2it.test/burn/cal-{i}"))
                        .body(Empty::new())?,
                )
                .await?;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = resp.into_body().collect().await?.to_bytes();
            assert_eq!(body.as_ref(), b"wasm-deadline-ok");
            if i > 0 {
                solo_samples.push(u64::try_from(t0.elapsed().as_millis()).unwrap_or(50));
            }
        }
        solo_samples.sort_unstable();
        let solo_ms = solo_samples.get(1).copied().unwrap_or(30).max(15);
        // Calibrate the per-request timeout as 5x solo, clamped to 120..=5_000 ms.
        let deadline_ms = (solo_ms.saturating_mul(5)).clamp(120, 5_000);
        server.reload_from_str("h2it-wasm-dl-tight.kdl", &make_kdl(deadline_ms))?;

        let (in_before, sp_before) = miraserve_http::test_h2_exec_stream_counts();
        let inner_wasm_spawned_before = miraserve_http::test_wasm_spawned_count();
        let mut handles = Vec::with_capacity(CONCURRENT);
        for i in 0..CONCURRENT {
            sender.ready().await?;
            let fut = sender.send_request(
                Request::builder()
                    .uri(format!("https://wasm-dl.h2it.test/burn/run-{i}"))
                    .body(Empty::new())?,
            );
            handles.push(tokio::spawn(async move {
                let r = fut.await?;
                let status = r.status();
                let body = r.into_body().collect().await?.to_bytes();
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>((status, body))
            }));
        }
        for (idx, h) in handles.into_iter().enumerate() {
            let (status, body) = tokio::time::timeout(Duration::from_secs(10), h)
                .await??
                .map_err(|e| e.to_string())?;
            assert_eq!(
                status,
                StatusCode::OK,
                "concurrent WASM stream {idx} missed deadline ({deadline_ms}ms, solo={solo_ms}ms)"
            );
            assert_eq!(body.as_ref(), b"wasm-deadline-ok");
        }
        let (in_after, sp_after) = miraserve_http::test_h2_exec_stream_counts();
        assert_eq!(
            (in_after - in_before, sp_after - sp_before),
            (0, CONCURRENT),
            "direct WASM routes must run as spawned streams via per-request handoff"
        );
        assert_eq!(
            miraserve_http::test_wasm_spawned_count(),
            inner_wasm_spawned_before,
            "direct spawned WASM streams must not double-spawn inside execute_wasm_plugin"
        );

        // Trap reporting must remain identical (`500 Internal Server Error`) without hurting the
        // connection.
        sender.ready().await?;
        let trap_resp = sender
            .send_request(
                Request::builder()
                    .uri("https://wasm-dl.h2it.test/trap")
                    .body(Empty::new())?,
            )
            .await?;
        assert_eq!(trap_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let _ = trap_resp.into_body().collect().await?;

        // P2-5 cancellation under a 1-slot configuration (exercising the Round 1–5 inner WASM
        // spawn safety net via an internal rewrite `/rw-slow` -> `/slow`, which is classified
        // in-task at `service.call` time): while `/rw-slow` holds the sole WASM slot, a concurrent
        // WASM request gets `503 Service Unavailable`; after dropping `/rw-slow` (`RST_STREAM`),
        // `AbortOnDrop` aborts the inner spawned task and releases the slot promptly.
        {
            let _one_slot = miraserve_http::test_wasm_slots_override_guard(1);
            let slow_entered = Arc::new(Notify::new());
            let slow_release = Arc::new(Notify::new());
            let _hold_gate = miraserve_http::test_wasm_hold_path_guard(
                "/slow",
                Arc::clone(&slow_entered),
                Arc::clone(&slow_release),
            );
            assert_eq!(miraserve_http::test_wasm_available_slots(), 1);
            let spawned_before_slow = miraserve_http::test_wasm_spawned_count();

            sender.ready().await?;
            let slow_fut = sender.send_request(
                Request::builder()
                    .uri("https://wasm-dl.h2it.test/rw-slow")
                    .body(Empty::new())?,
            );
            let slow_task = tokio::spawn(async move {
                let _ = slow_fut.await;
            });

            // Wait deterministically until the spawned `/slow` task has executed the module and is
            // parked holding the sole WASM slot.
            tokio::time::timeout(Duration::from_secs(5), slow_entered.notified())
                .await
                .map_err(|_| "/slow did not enter spawned WASM hold gate")?;
            assert_eq!(
                miraserve_http::test_wasm_spawned_count(),
                spawned_before_slow + 1
            );
            assert_eq!(
                miraserve_http::test_wasm_available_slots(),
                0,
                "/slow must hold the sole WASM execution slot while running"
            );

            // Concurrent request while `/slow` holds the sole slot MUST be rejected with 503.
            sender.ready().await?;
            let busy_resp = tokio::time::timeout(
                Duration::from_secs(3),
                sender.send_request(
                    Request::builder()
                        .uri("https://wasm-dl.h2it.test/burn/busy")
                        .body(Empty::new())?,
                ),
            )
            .await??;
            assert_eq!(
                busy_resp.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "second WASM request under 1-slot config must receive 503 while /slow holds the slot"
            );
            let _ = busy_resp.into_body().collect().await?;

            // Cancel `/slow` via client `RST_STREAM` and prove the sole slot is released promptly.
            slow_task.abort();
            let _ = slow_task.await;
            let release_deadline = Instant::now() + Duration::from_secs(3);
            while miraserve_http::test_wasm_available_slots() == 0
                && Instant::now() < release_deadline
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert_eq!(
                miraserve_http::test_wasm_available_slots(),
                1,
                "cancelled WASM invocation must release its execution slot promptly"
            );

            sender.ready().await?;
            let follow_resp = tokio::time::timeout(
                Duration::from_secs(5),
                sender.send_request(
                    Request::builder()
                        .uri("https://wasm-dl.h2it.test/burn/after-cancel")
                        .body(Empty::new())?,
                ),
            )
            .await??;
            assert_eq!(follow_resp.status(), StatusCode::OK);
            assert_eq!(
                follow_resp.into_body().collect().await?.to_bytes().as_ref(),
                b"wasm-deadline-ok"
            );
            assert_eq!(miraserve_http::test_wasm_available_slots(), 1);
        }

        drop(sender);
        conn_task.abort();
        server.shutdown().await;
        Ok(())
    })
}

/// Verifies per-connection HTTP/2 executor selection over real TCP + TLS 1.3:
/// - In-task (`InTaskExec`) when non-blocking static capability is available;
/// - Spawned (`TokioExecutor`, exact v0.1.4 behaviour) when a latch or kernel/platform gate says
///   non-blocking static serving is unavailable.
///
/// Both modes return exact responses and we assert which executor actually executed the streams.
#[test]
#[allow(clippy::too_many_lines)]
fn h2_tls_executor_choice_switches_between_in_task_and_spawned() -> TestResult {
    async fn run_two_requests(
        https_addr: SocketAddr,
        tls_cfg: &Arc<ClientConfig>,
    ) -> Result<(usize, usize), Box<dyn std::error::Error>> {
        let (in_before, sp_before) = miraserve_http::test_h2_exec_stream_counts();
        let (mut sender, conn_task) =
            connect_h2_tls::<Empty<Bytes>>(https_addr, "exec.h2it.test", tls_cfg).await?;
        for _ in 0..2 {
            sender.ready().await?;
            let resp = sender
                .send_request(
                    Request::builder()
                        .uri("https://exec.h2it.test/hello.txt")
                        .body(Empty::new())?,
                )
                .await?;
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(
                resp.into_body().collect().await?.to_bytes().as_ref(),
                b"executor-choice-ok"
            );
        }
        drop(sender);
        let _ = tokio::time::timeout(Duration::from_secs(5), conn_task).await;
        let (in_after, sp_after) = miraserve_http::test_h2_exec_stream_counts();
        Ok((in_after - in_before, sp_after - sp_before))
    }

    run_h2_tls_current_thread(async {
        let tmp = TempDir::new("exec-choice")?;
        fs::write(tmp.path.join("hello.txt"), b"executor-choice-ok")?;

        let tls_port = reserve_free_port()?;
        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
}}
site "exec.h2it.test" {{
    root "{root}"
}}
"#,
            root = tmp.path.to_string_lossy().replace('\\', "/"),
        );
        let (cfg, _) = parse_kdl("h2it-exec.kdl", &kdl)?;
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
            .ok_or("missing HTTPS listener")?
            .local_addr;
        let tls_cfg = build_h2_tls_client(server.dev_cert_pem().ok_or("missing dev cert")?)?;

        #[cfg(target_os = "linux")]
        {
            // 1. Capable system (`openat2` + `RESOLVE_CACHED` + kernel in 5.9-6.11) -> InTaskExec.
            {
                let _k = miraserve_static::test_nowait_kernel_in_range_override_guard(Some(true));
                let _l = miraserve_static::test_openat2_latches_guard(false, false);
                assert_eq!(
                    miraserve_core::nonblocking_static_support(),
                    miraserve_core::NonblockingStaticSupport::Available
                );
                let (in_delta, sp_delta) = run_two_requests(https_addr, &tls_cfg).await?;
                assert_eq!(
                    (in_delta, sp_delta),
                    (2, 0),
                    "capable Linux must run in-task"
                );
            }
            // 2. `OPENAT2_UNAVAILABLE` latched -> TokioExecutor (spawned).
            {
                let _k = miraserve_static::test_nowait_kernel_in_range_override_guard(Some(true));
                let _l = miraserve_static::test_openat2_latches_guard(true, false);
                assert_eq!(
                    miraserve_core::nonblocking_static_support(),
                    miraserve_core::NonblockingStaticSupport::Openat2Unavailable
                );
                let (in_delta, sp_delta) = run_two_requests(https_addr, &tls_cfg).await?;
                assert_eq!(
                    (in_delta, sp_delta),
                    (0, 2),
                    "OPENAT2_UNAVAILABLE must fall back to spawned TokioExecutor"
                );
            }
            // 3. `RESOLVE_CACHED_UNAVAILABLE` latched -> TokioExecutor (spawned).
            {
                let _k = miraserve_static::test_nowait_kernel_in_range_override_guard(Some(true));
                let _l = miraserve_static::test_openat2_latches_guard(false, true);
                assert_eq!(
                    miraserve_core::nonblocking_static_support(),
                    miraserve_core::NonblockingStaticSupport::ResolveCachedUnavailable
                );
                let (in_delta, sp_delta) = run_two_requests(https_addr, &tls_cfg).await?;
                assert_eq!(
                    (in_delta, sp_delta),
                    (0, 2),
                    "RESOLVE_CACHED_UNAVAILABLE must fall back to spawned TokioExecutor"
                );
            }
            // 4. Kernel outside 5.9-6.11 -> TokioExecutor (spawned).
            {
                let _k = miraserve_static::test_nowait_kernel_in_range_override_guard(Some(false));
                let _l = miraserve_static::test_openat2_latches_guard(false, false);
                assert_eq!(
                    miraserve_core::nonblocking_static_support(),
                    miraserve_core::NonblockingStaticSupport::KernelOutsideNowaitRange
                );
                let (in_delta, sp_delta) = run_two_requests(https_addr, &tls_cfg).await?;
                assert_eq!(
                    (in_delta, sp_delta),
                    (0, 2),
                    "kernel outside 5.9-6.11 must fall back to spawned TokioExecutor"
                );
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            // 1. Default on non-Linux: UnsupportedPlatform -> TokioExecutor (spawned).
            assert_eq!(
                miraserve_core::nonblocking_static_support(),
                miraserve_core::NonblockingStaticSupport::UnsupportedPlatform
            );
            let (in_delta, sp_delta) = run_two_requests(https_addr, &tls_cfg).await?;
            assert_eq!(
                (in_delta, sp_delta),
                (0, 2),
                "non-Linux platforms must default to spawned TokioExecutor"
            );

            // 2. Explicit in-task override -> InTaskExec.
            let _force = miraserve_http::test_h2_exec_override_guard(Some(true));
            let (in_delta2, sp_delta2) = run_two_requests(https_addr, &tls_cfg).await?;
            assert_eq!(
                (in_delta2, sp_delta2),
                (2, 0),
                "forced in-task override must run streams via InTaskExec"
            );
        }

        server.shutdown().await;
        Ok(())
    })
}

static TEST_DIAG_SINK: std::sync::Mutex<Option<miraserve_core::DiagnosticLogSink>> =
    std::sync::Mutex::new(None);

struct TestDiagSinkGuard {
    prev: Option<miraserve_core::DiagnosticLogSink>,
}

impl Drop for TestDiagSinkGuard {
    fn drop(&mut self) {
        *TEST_DIAG_SINK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = self.prev.take();
    }
}

fn install_test_diag_sink(sink: miraserve_core::DiagnosticLogSink) -> TestDiagSinkGuard {
    let prev = TEST_DIAG_SINK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .replace(sink);
    TestDiagSinkGuard { prev }
}

/// Minimal `tracing::Subscriber` enabling:
/// - `INFO` for `miraserve::access` (so the direct access-log sink receives formatted lines), and
/// - `WARN`/`ERROR` runtime diagnostics routed through `write_or_offload_diagnostic_line` into
///   `TEST_DIAG_SINK` when installed (exercising the exact off-thread diagnostic queue used by
///   `miraserve-bin`'s `NonBlockingRuntimeMakeWriter`).
struct AccessLogEnableSubscriber;

struct EventLineVisitor(String);

impl tracing::field::Visit for EventLineVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write as _;
        let _ = write!(self.0, " {}={value:?}", field.name());
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        use std::fmt::Write as _;
        let _ = write!(self.0, " {}={value}", field.name());
    }
}

impl tracing::Subscriber for AccessLogEnableSubscriber {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        (metadata.target() == "miraserve::access" && *metadata.level() <= tracing::Level::INFO)
            || (metadata.target() != "miraserve::access"
                && *metadata.level() <= tracing::Level::WARN)
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        if event.metadata().target() == "miraserve::access" {
            return;
        }
        let sink = TEST_DIAG_SINK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let Some(sink) = sink else {
            return;
        };
        let mut visitor = EventLineVisitor(format!("{}", event.metadata().level()));
        event.record(&mut visitor);
        visitor.0.push('\n');
        miraserve_core::write_or_offload_diagnostic_line(visitor.0.as_bytes(), &sink);
    }
    fn enter(&self, _span: &tracing::span::Id) {}
    fn exit(&self, _span: &tracing::span::Id) {}
}

/// P1-B: An interrupted response mid-body (both upstream mid-body truncation via `finish_now` AND
/// client `RST_STREAM` mid-body via `AccessLogBody::drop`) on an in-task HTTP/2 connection while
/// the access-log sink is blocked MUST NOT delay sibling streams on the same connection, and the
/// interrupted records are delivered once the sink unblocks.
#[test]
#[allow(clippy::too_many_lines)]
fn h2_tls_interrupted_access_log_does_not_stall_sibling_stream() -> TestResult {
    use tokio::io::AsyncWriteExt as _;

    run_h2_tls_multi_thread(2, async {
        let _mode = enter_in_task_h2_test_mode();
        let _ = tracing::subscriber::set_global_default(AccessLogEnableSubscriber);

        // Raw TCP upstream:
        // - `/trunc`: sends `Content-Length: 100000`, writes 16 bytes, then closes TCP -> body error (`finish_now`).
        // - `/stall`: sends `Content-Length: 100000`, writes 16 bytes, then waits -> client `RST_STREAM` (`AccessLogBody::drop`).
        let up_listener = TcpListener::bind("127.0.0.1:0").await?;
        let up_port = up_listener.local_addr()?.port();
        let up_task = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = up_listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0_u8; 2048];
                    let Ok(n) = sock.read(&mut buf).await else {
                        return;
                    };
                    let req = String::from_utf8_lossy(buf.get(..n).unwrap_or(&[]));
                    if req.starts_with("GET /trunc ") {
                        let _ = sock
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 100000\r\nConnection: close\r\n\r\npartial-16-bytes",
                        )
                        .await;
                        let _ = sock.shutdown().await;
                    } else if req.starts_with("GET /stall ") {
                        let _ = sock
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 100000\r\nConnection: close\r\n\r\nstalled-16-bytes",
                        )
                        .await;
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    } else {
                        let _ = sock
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 10\r\nConnection: close\r\n\r\nsibling-ok",
                        )
                        .await;
                    }
                });
            }
        });

        let tmp_log = TempDir::new("accesslog-h2")?;
        fs::write(tmp_log.path.join("fast.txt"), b"static-sibling-ok")?;
        let tls_port = reserve_free_port()?;
        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
}}
site "log.h2it.test" {{
    root "{root}"
    rewrite {{
        rule "^/rw/(.*)$" to="/proxy/$1"
    }}
    route "/proxy/*" {{
        reverse-proxy {{
            upstream "http://127.0.0.1:{up_port}"
            strip-prefix #true
        }}
    }}
}}
"#,
            root = tmp_log.path.to_string_lossy().replace('\\', "/"),
        );
        let (cfg, _) = parse_kdl("h2it-accesslog.kdl", &kdl)?;
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
            .ok_or("missing HTTPS listener")?
            .local_addr;
        let tls_cfg = build_h2_tls_client(server.dev_cert_pem().ok_or("missing dev cert")?)?;
        let (mut sender, conn_task) =
            connect_h2_tls::<Empty<Bytes>>(https_addr, "log.h2it.test", &tls_cfg).await?;

        // Install a test access-log sink that blocks on the FIRST interrupted line until we release it.
        let sink_blocked = Arc::new(Notify::new());
        let sink_blocked_c = Arc::clone(&sink_blocked);
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let release_rx = Arc::new(std::sync::Mutex::new(Some(release_rx)));
        let captured_lines: Arc<std::sync::Mutex<Vec<String>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured_c = Arc::clone(&captured_lines);
        let _sink_guard =
            miraserve_http::test_access_log_sink_override_guard(Arc::new(move |bytes| {
                let line = String::from_utf8_lossy(bytes).into_owned();
                let is_interrupted = line.contains("http request interrupted");
                if is_interrupted
                    && let Some(rx) = release_rx
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take()
                {
                    sink_blocked_c.notify_one();
                    let _ = rx.recv_timeout(Duration::from_secs(10));
                }
                captured_c
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(line);
            }));

        // 1. Trigger a mid-body upstream truncation (`AccessLogBody::finish_now` during in-task
        //    stream poll via `/rw/trunc` -> `/proxy/trunc` rewrite).
        sender.ready().await?;
        let trunc_resp = sender
            .send_request(
                Request::builder()
                    .uri("https://log.h2it.test/rw/trunc")
                    .body(Empty::new())?,
            )
            .await?;
        assert_eq!(trunc_resp.status(), StatusCode::OK);
        let _ = trunc_resp.into_body().collect().await; // errors mid-body

        // Wait until the offloaded drainer is actively parked inside the blocked test sink.
        tokio::time::timeout(Duration::from_secs(5), sink_blocked.notified())
            .await
            .map_err(|_| "interrupted access-log record never entered blocked test sink")?;

        // 2. Also trigger a client RST_STREAM mid-body (`AccessLogBody::drop`) while sink is blocked.
        sender.ready().await?;
        let mut stall_resp = sender
            .send_request(
                Request::builder()
                    .uri("https://log.h2it.test/rw/stall")
                    .body(Empty::new())?,
            )
            .await?;
        assert_eq!(stall_resp.status(), StatusCode::OK);
        let first_frame =
            tokio::time::timeout(Duration::from_secs(3), stall_resp.body_mut().frame())
                .await?
                .ok_or("missing first frame from /stall")??;
        assert!(first_frame.data_ref().is_some_and(|d| !d.is_empty()));
        drop(stall_resp); // client sends RST_STREAM mid-body

        // 3. While the sink is STILL blocked on the interrupted record, sibling in-task static and
        //    spawned proxy streams on the EXACT same HTTP/2 connection MUST complete immediately.
        for _ in 0..4 {
            sender.ready().await?;
            let sib = tokio::time::timeout(
                Duration::from_secs(2),
                sender.send_request(
                    Request::builder()
                        .uri("https://log.h2it.test/fast.txt")
                        .body(Empty::new())?,
                ),
            )
            .await??;
            assert_eq!(sib.status(), StatusCode::OK);
            assert_eq!(
                sib.into_body().collect().await?.to_bytes().as_ref(),
                b"static-sibling-ok"
            );
        }

        // 4. Unblock the sink, drain the offloaded access-log queue, and confirm BOTH interrupted
        //    records (`/rw/trunc` and `/rw/stall`) were delivered intact.
        let _ = release_tx.send(());
        assert!(
            miraserve_core::flush_offloaded_access_logs(Duration::from_secs(5)).await,
            "offloaded access-log queue must drain cleanly after sink unblocks"
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let got_both = {
                let lines = captured_lines
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let saw_trunc = lines
                    .iter()
                    .any(|l| l.contains("/rw/trunc") && l.contains("http request interrupted"));
                let saw_stall = lines
                    .iter()
                    .any(|l| l.contains("/rw/stall") && l.contains("http request interrupted"));
                saw_trunc && saw_stall
            };
            if got_both {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "missing interrupted access-log lines: {:?}",
                captured_lines
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        drop(sender);
        conn_task.abort();
        up_task.abort();
        server.shutdown().await;
        Ok(())
    })
}

/// P1-1: An upstream connect failure inside an in-task HTTP/2 proxy stream emits `warn!` during
/// the stream poll; when the runtime diagnostic sink blocks, a sibling stream on the EXACT same
/// HTTP/2 connection MUST complete immediately while the diagnostic sink is held, and the
/// warning line arrives once the sink unblocks.
#[test]
#[allow(clippy::too_many_lines)]
fn h2_tls_upstream_failure_diagnostic_does_not_stall_sibling_stream() -> TestResult {
    run_h2_tls_multi_thread(2, async {
        let _mode = enter_in_task_h2_test_mode();
        let _ = tracing::subscriber::set_global_default(AccessLogEnableSubscriber);

        // Live healthy backend on `live_port`, plus a closed/refused `dead_port`.
        let live_listener = TcpListener::bind("127.0.0.1:0").await?;
        let live_port = live_listener.local_addr()?.port();
        let live_task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = live_listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let _ = http1::Builder::new()
                        .serve_connection(
                            TokioIo::new(tcp),
                            service_fn(|_req: Request<Incoming>| async {
                                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                                    b"sibling-diag-ok",
                                ))))
                            }),
                        )
                        .await;
                });
            }
        });
        let dead_port = reserve_free_port()?;

        let tmp_diag = TempDir::new("diag-h2")?;
        fs::write(tmp_diag.path.join("ok.txt"), b"static-diag-ok")?;
        let tls_port = reserve_free_port()?;
        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
}}
site "diag.h2it.test" {{
    root "{root}"
    rewrite {{
        rule "^/rw-dead/(.*)$" to="/dead/$1"
    }}
    route "/dead/*" {{
        reverse-proxy {{
            upstream "http://127.0.0.1:{dead_port}"
            strip-prefix #true
        }}
    }}
    route "/live/*" {{
        reverse-proxy {{
            upstream "http://127.0.0.1:{live_port}"
            strip-prefix #true
        }}
    }}
}}
"#,
            root = tmp_diag.path.to_string_lossy().replace('\\', "/"),
        );
        let (cfg, _) = parse_kdl("h2it-diag.kdl", &kdl)?;
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
            .ok_or("missing HTTPS listener")?
            .local_addr;
        let tls_cfg = build_h2_tls_client(server.dev_cert_pem().ok_or("missing dev cert")?)?;
        let (mut sender, conn_task) =
            connect_h2_tls::<Empty<Bytes>>(https_addr, "diag.h2it.test", &tls_cfg).await?;

        // Install a diagnostic sink that blocks on the proxy's upstream-failure `warn!` line.
        let diag_blocked = Arc::new(Notify::new());
        let diag_blocked_c = Arc::clone(&diag_blocked);
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let release_rx = Arc::new(std::sync::Mutex::new(Some(release_rx)));
        let captured: Arc<std::sync::Mutex<Vec<String>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured_c = Arc::clone(&captured);
        let _diag_guard = install_test_diag_sink(Arc::new(move |bytes| {
            let line = String::from_utf8_lossy(bytes).into_owned();
            if line.contains("reverse-proxy upstream request failed")
                && let Some(rx) = release_rx
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take()
            {
                diag_blocked_c.notify_one();
                let _ = rx.recv_timeout(Duration::from_secs(10));
            }
            captured_c
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(line);
        }));

        // 1. Trigger upstream connect failure inside an in-task stream (`/rw-dead/fail` ->
        //    `/dead/fail` rewrite) -> emits `warn!` inside `in_nonblocking_inline_context()`.
        sender.ready().await?;
        let fail_resp = tokio::time::timeout(
            Duration::from_secs(3),
            sender.send_request(
                Request::builder()
                    .uri("https://diag.h2it.test/rw-dead/fail")
                    .body(Empty::new())?,
            ),
        )
        .await??;
        assert_eq!(fail_resp.status(), StatusCode::BAD_GATEWAY);
        let _ = fail_resp.into_body().collect().await?;

        // Confirm the off-thread diagnostic drainer is actively parked inside the blocked sink.
        tokio::time::timeout(Duration::from_secs(5), diag_blocked.notified())
            .await
            .map_err(|_| "upstream failure warning never entered blocked diagnostic sink")?;

        // 2. While the diagnostic sink is STILL held, sibling in-task static AND spawned proxy
        //    streams on the EXACT same connection must complete promptly without blocking.
        for _ in 0..4 {
            sender.ready().await?;
            let sib_static = tokio::time::timeout(
                Duration::from_secs(2),
                sender.send_request(
                    Request::builder()
                        .uri("https://diag.h2it.test/ok.txt")
                        .body(Empty::new())?,
                ),
            )
            .await??;
            assert_eq!(sib_static.status(), StatusCode::OK);
            assert_eq!(
                sib_static.into_body().collect().await?.to_bytes().as_ref(),
                b"static-diag-ok"
            );

            sender.ready().await?;
            let sib = tokio::time::timeout(
                Duration::from_secs(2),
                sender.send_request(
                    Request::builder()
                        .uri("https://diag.h2it.test/live/ok")
                        .body(Empty::new())?,
                ),
            )
            .await??;
            assert_eq!(sib.status(), StatusCode::OK);
            assert_eq!(
                sib.into_body().collect().await?.to_bytes().as_ref(),
                b"sibling-diag-ok"
            );
        }

        // Confirm shutdown drain sees the held diagnostic record as outstanding while blocked.
        let mid = miraserve_core::flush_offloaded_diagnostic_logs(Duration::from_millis(25)).await;
        assert!(!mid.drained && mid.remaining >= 1);

        // 3. Release the blocked sink and confirm the warning drains cleanly.
        let _ = release_tx.send(());
        let drained = miraserve_core::flush_offloaded_diagnostic_logs(Duration::from_secs(5)).await;
        assert!(drained.drained && drained.remaining == 0);
        assert!(
            captured
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .any(|l| l.contains("reverse-proxy upstream request failed")),
            "expected upstream connect failure warning after sink unblocked"
        );

        drop(sender);
        conn_task.abort();
        live_task.abort();
        server.shutdown().await;
        Ok(())
    })
}

/// P1-A: On an in-task HTTP/2 TLS connection serving an unsuitable (`relatime`) root:
/// - `GET` spawns a `SharedInline` static task (without blocking-pool hop and without inheriting
///   `NONBLOCKING_INLINE_CONTEXT`), so parking a slow `GET` does not stall sibling `HEAD`,
///   `file-cache` hit, or `respond` streams on the same connection;
/// - `RST_STREAM` cancels the spawned static task via `AbortOnDrop`;
/// - On a suitable (`atime_free`) root, the first `EOPNOTSUPP` latches `nowait_refused` so the
///   second `GET` skips `preadv2` completely (`0` syscall attempts) and spawns a `SharedInline`
///   static task.
#[cfg(target_os = "linux")]
#[test]
#[allow(clippy::too_many_lines)]
fn h2_tls_relatime_root_spawns_static_task_and_nowait_refusal_latches() -> TestResult {
    run_h2_tls_multi_thread(2, async {
        let _kernel = miraserve_static::test_nowait_kernel_in_range_override_guard(Some(true));
        let support = miraserve_core::probe_nonblocking_static_support();
        if support != miraserve_core::NonblockingStaticSupport::Available {
            eprintln!(
                "SKIP h2_tls_relatime_root_spawns_static_task_and_nowait_refusal_latches: host lacks non-blocking static support ({:?}: {})",
                support,
                support.reason()
            );
            return Ok(());
        }

        let tmp = TempDir::new("relatime-spawn")?;
        fs::write(tmp.path.join("slow.txt"), b"relatime-slow-body")?;
        fs::write(tmp.path.join("cancel.txt"), b"relatime-cancel-body")?;
        fs::write(tmp.path.join("cached.txt"), b"relatime-cached-body")?;
        fs::write(tmp.path.join("eop.txt"), b"nowait-eopnotsupp-body")?;

        let tls_port = reserve_free_port()?;
        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
}}
site "rel.h2it.test" {{
    root "{root}"
    file-cache "60s"
    route "/ping" {{
        respond 418
    }}
}}
"#,
            root = tmp.path.to_string_lossy().replace('\\', "/"),
        );
        let (cfg, _) = parse_kdl("h2it-relatime.kdl", &kdl)?;
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
            .ok_or("missing HTTPS listener")?
            .local_addr;
        let tls_cfg = build_h2_tls_client(server.dev_cert_pem().ok_or("missing dev cert")?)?;
        let (mut sender, conn_task) =
            connect_h2_tls::<Empty<Bytes>>(https_addr, "rel.h2it.test", &tls_cfg).await?;

        // Part 1: Unsuitable (`relatime`) root spawns `SharedInline` task for `GET`, keeps `HEAD` and
        // warm `file-cache` hits in-task with 0 spawns, and never stalls sibling streams.
        {
            let _force_relatime =
                miraserve_static::test_root_atime_free_override_guard(Some(false));

            // Warm `/cached.txt` into the opt-in file cache first.
            sender.ready().await?;
            let warm = sender
                .send_request(
                    Request::builder()
                        .uri("https://rel.h2it.test/cached.txt")
                        .body(Empty::new())?,
                )
                .await?;
            assert_eq!(warm.status(), StatusCode::OK);
            assert_eq!(
                warm.into_body().collect().await?.to_bytes().as_ref(),
                b"relatime-cached-body"
            );

            let slow_entered = Arc::new(Notify::new());
            let slow_entered_c = Arc::clone(&slow_entered);
            let saw_outside_ctx = Arc::new(AtomicBool::new(false));
            let saw_outside_c = Arc::clone(&saw_outside_ctx);
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            let release_rx = Arc::new(std::sync::Mutex::new(Some(release_rx)));
            let si_hook = miraserve_static::test_shared_inline_hook_guard(Arc::new(move |rel| {
                if rel.to_string_lossy().ends_with("slow.txt") {
                    saw_outside_c.store(
                        !miraserve_core::in_nonblocking_inline_context(),
                        Ordering::Release,
                    );
                    slow_entered_c.notify_one();
                    if let Some(rx) = release_rx
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take()
                    {
                        let _ = rx.recv_timeout(Duration::from_secs(10));
                    }
                }
            }));

            let spawned_before = miraserve_static::test_static_spawned_count();
            let pool_before = miraserve_static::static_blocking_pool_entries();
            let nowait_before = miraserve_static::test_nowait_syscall_attempts();
            sender.ready().await?;
            let slow_fut = sender.send_request(
                Request::builder()
                    .uri("https://rel.h2it.test/slow.txt")
                    .body(Empty::new())?,
            );
            let slow_handle = tokio::spawn(async move {
                let r = slow_fut.await?;
                let status = r.status();
                let body = r.into_body().collect().await?.to_bytes();
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>((status, body))
            });

            tokio::time::timeout(Duration::from_secs(5), slow_entered.notified())
                .await
                .map_err(|_| "relatime GET did not spawn SharedInline static task")?;
            assert!(
                saw_outside_ctx.load(Ordering::Acquire),
                "spawned static task must run outside NONBLOCKING_INLINE_CONTEXT"
            );
            assert_eq!(
                miraserve_static::test_static_spawned_count(),
                spawned_before + 1
            );
            assert_eq!(
                miraserve_static::static_blocking_pool_entries(),
                pool_before,
                "relatime GET must use spawned SharedInline task, not a blocking-pool hop"
            );
            assert_eq!(
                miraserve_static::test_nowait_syscall_attempts(),
                nowait_before,
                "relatime GET must make 0 preadv2 attempts"
            );

            // Sibling HEAD, file-cache hit, and respond streams finish immediately with 0 extra spawns.
            let spawned_mid = miraserve_static::test_static_spawned_count();
            for (method, uri, expected_status, expected) in [
                (
                    Method::HEAD,
                    "https://rel.h2it.test/cached.txt",
                    StatusCode::OK,
                    &b""[..],
                ),
                (
                    Method::GET,
                    "https://rel.h2it.test/cached.txt",
                    StatusCode::OK,
                    &b"relatime-cached-body"[..],
                ),
                (
                    Method::GET,
                    "https://rel.h2it.test/ping",
                    StatusCode::IM_A_TEAPOT,
                    &b""[..],
                ),
            ] {
                sender.ready().await?;
                let resp = tokio::time::timeout(
                    Duration::from_secs(2),
                    sender.send_request(
                        Request::builder()
                            .method(method)
                            .uri(uri)
                            .body(Empty::new())?,
                    ),
                )
                .await??;
                assert_eq!(resp.status(), expected_status);
                if expected.is_empty() {
                    let _ = resp.into_body().collect().await?;
                } else {
                    assert_eq!(
                        resp.into_body().collect().await?.to_bytes().as_ref(),
                        expected
                    );
                }
            }
            assert_eq!(
                miraserve_static::test_static_spawned_count(),
                spawned_mid,
                "HEAD, file-cache hit, and respond must stay in-task with 0 static task spawns"
            );
            assert!(!slow_handle.is_finished());

            let _ = release_tx.send(());
            let (st, body) = tokio::time::timeout(Duration::from_secs(5), slow_handle)
                .await??
                .map_err(|e| e.to_string())?;
            assert_eq!(st, StatusCode::OK);
            assert_eq!(body.as_ref(), b"relatime-slow-body");

            // P2-4: Cancel a spawned static child task via client RST_STREAM and PROVE the server-side
            // child task is aborted and dropped BEFORE any release notification is sent.
            drop(si_hook);
            let cancel_entered = Arc::new(Notify::new());
            let cancel_release = Arc::new(Notify::new());
            let cancel_dropped = Arc::new(Notify::new());
            let cancel_was_aborted = Arc::new(AtomicBool::new(false));
            let cancel_completed = Arc::new(AtomicBool::new(false));
            let _cancel_gate = miraserve_static::test_static_spawn_hold_gate_guard(
                Arc::clone(&cancel_entered),
                Arc::clone(&cancel_release),
                Arc::clone(&cancel_dropped),
                Arc::clone(&cancel_was_aborted),
                Arc::clone(&cancel_completed),
            );
            sender.ready().await?;
            let cancelled_fut = sender.send_request(
                Request::builder()
                    .uri("https://rel.h2it.test/cancel.txt")
                    .body(Empty::new())?,
            );
            let cancelled_task = tokio::spawn(async move {
                let _ = cancelled_fut.await;
            });
            tokio::time::timeout(Duration::from_secs(5), cancel_entered.notified())
                .await
                .map_err(|_| "cancelled relatime GET did not enter spawned static child task")?;
            assert!(
                !cancel_was_aborted.load(Ordering::Acquire),
                "spawned static child must stay alive while client stream is open"
            );
            // Pre-arm `cancel_dropped` before triggering the client `RST_STREAM(CANCEL)` (belt-and-
            // suspenders alongside `notify_one()` in `SpawnedChildAbortObserver::drop`).
            let cancel_dropped_fut = cancel_dropped.notified();
            tokio::pin!(cancel_dropped_fut);
            cancel_dropped_fut.as_mut().enable();
            // Reset the client stream (`RST_STREAM(CANCEL)`) WITHOUT releasing `cancel_release`!
            cancelled_task.abort();
            let _ = cancelled_task.await;
            tokio::time::timeout(Duration::from_secs(5), cancel_dropped_fut)
            .await
            .map_err(|_| {
                format!(
                    "server-side spawned static child was NOT aborted/dropped after client RST_STREAM (was_aborted={}, completed={})",
                    cancel_was_aborted.load(Ordering::Acquire),
                    cancel_completed.load(Ordering::Acquire),
                )
            })?;
            assert!(
                cancel_was_aborted.load(Ordering::Acquire),
                "server-side spawned static child must have been aborted before release"
            );
            assert!(
                !cancel_completed.load(Ordering::Acquire),
                "aborted spawned static child must not have completed normally"
            );
            sender.ready().await?;
            let after_cancel = tokio::time::timeout(
                Duration::from_secs(2),
                sender.send_request(
                    Request::builder()
                        .uri("https://rel.h2it.test/ping")
                        .body(Empty::new())?,
                ),
            )
            .await??;
            assert_eq!(after_cancel.status(), StatusCode::IM_A_TEAPOT);
            let _ = after_cancel.into_body().collect().await?;
        }

        // Part 2: Suitable (`atime_free`) root with `EOPNOTSUPP` latches `nowait_refused` on the
        // first GET so the second GET makes 0 preadv2 attempts and spawns a `SharedInline` task.
        {
            let _force_atime = miraserve_static::test_root_atime_free_override_guard(Some(true));
            let _force_eop = miraserve_static::test_force_nowait_eopnotsupp_guard();

            let attempts1 = miraserve_static::test_nowait_syscall_attempts();
            sender.ready().await?;
            let r1 = sender
                .send_request(
                    Request::builder()
                        .uri("https://rel.h2it.test/eop.txt")
                        .header(http::header::RANGE, "bytes=0-10")
                        .body(Empty::new())?,
                )
                .await?;
            assert_eq!(r1.status(), StatusCode::PARTIAL_CONTENT);
            assert_eq!(
                r1.into_body().collect().await?.to_bytes().as_ref(),
                b"nowait-eopn"
            );
            assert_eq!(
                miraserve_static::test_nowait_syscall_attempts(),
                attempts1 + 1,
                "first EOPNOTSUPP must attempt preadv2 once and latch"
            );

            let attempts2 = miraserve_static::test_nowait_syscall_attempts();
            let spawned2 = miraserve_static::test_static_spawned_count();
            sender.ready().await?;
            let r2 = sender
                .send_request(
                    Request::builder()
                        .uri("https://rel.h2it.test/eop.txt")
                        .header(http::header::RANGE, "bytes=0-10")
                        .body(Empty::new())?,
                )
                .await?;
            assert_eq!(r2.status(), StatusCode::PARTIAL_CONTENT);
            assert_eq!(
                r2.into_body().collect().await?.to_bytes().as_ref(),
                b"nowait-eopn"
            );
            assert_eq!(
                miraserve_static::test_nowait_syscall_attempts(),
                attempts2,
                "latched root must make 0 preadv2 attempts on subsequent requests"
            );
            assert_eq!(
                miraserve_static::test_static_spawned_count(),
                spawned2 + 1,
                "latched root must treat itself as unsuitable and spawn SharedInline static task"
            );
        }

        drop(sender);
        conn_task.abort();
        server.shutdown().await;
        Ok(())
    })
}

/// Round 6 (Requirement 3): An HTTP/2 reverse-proxy-only server (no static work) selects
/// `spawned` (`TokioExecutor`, zero overhead, exact v0.1.4) WITHOUT probing `openat2(2)`.
/// Hot-reloading a config that adds static work on Linux 5.12–6.11 actively probes `openat2`:
/// - when `openat2` is available, new connections switch to `in-task` (serving static requests
///   in-task and proxy requests spawned on the same connection);
/// - when `openat2` is unavailable, new connections stay `spawned`;
/// - reloading back to proxy-only returns new connections to `spawned` without probing `openat2`.
#[cfg(target_os = "linux")]
#[test]
#[allow(clippy::too_many_lines)]
fn h2_tls_proxy_only_runs_spawned_without_openat2_and_reprobes_on_reload() -> TestResult {
    run_h2_tls_multi_thread(2, async {
        let _kernel = miraserve_static::test_nowait_kernel_in_range_override_guard(Some(true));
        let _latches = miraserve_static::test_openat2_latches_guard(false, false);

        let up_listener = TcpListener::bind("127.0.0.1:0").await?;
        let up_port = up_listener.local_addr()?.port();
        let up_task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = up_listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let _ = http1::Builder::new()
                        .serve_connection(
                            TokioIo::new(tcp),
                            service_fn(|_req: Request<Incoming>| async {
                                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                                    b"proxy-reprobe-ok",
                                ))))
                            }),
                        )
                        .await;
                });
            }
        });

        let tmp = TempDir::new("p1c-reload")?;
        fs::create_dir_all(tmp.path.join("static"))?;
        fs::write(tmp.path.join("static/added.txt"), b"added-after-reload")?;

        let tls_port = reserve_free_port()?;
        let kdl_proxy_only = format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
}}
site "p1c.h2it.test" {{
    route "/*" {{
        reverse-proxy {{
            upstream "http://127.0.0.1:{up_port}"
        }}
    }}
}}
"#
        );
        let probe_before = miraserve_static::test_openat2_probe_calls();
        let (cfg, _) = parse_kdl("h2it-p1c-proxy.kdl", &kdl_proxy_only)?;
        let server = MiraServeServer::start(
            Arc::new(ConfigStore::new(cfg)),
            ServerOptions {
                dev_tls: true,
                ..ServerOptions::default()
            },
        )
        .await?;
        assert_eq!(
            miraserve_static::test_openat2_probe_calls(),
            probe_before,
            "proxy-only H2 startup must not call openat2 probe"
        );

        let https_addr = server
            .bound_listeners()
            .iter()
            .find(|b| b.kind == ListenerKind::HttpsTcp)
            .ok_or("missing HTTPS listener")?
            .local_addr;
        let tls_cfg = build_h2_tls_client(server.dev_cert_pem().ok_or("missing dev cert")?)?;

        // 1. Proxy-only H2 runs Spawned (`TokioExecutor`) even on Linux 5.12–6.11 with openat2
        //    available.
        let (in_before, sp_before) = miraserve_http::test_h2_exec_stream_counts();
        let (mut existing_sender, existing_conn) =
            connect_h2_tls::<Empty<Bytes>>(https_addr, "p1c.h2it.test", &tls_cfg).await?;
        existing_sender.ready().await?;
        let r = existing_sender
            .send_request(
                Request::builder()
                    .uri("https://p1c.h2it.test/before")
                    .body(Empty::new())?,
            )
            .await?;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            r.into_body().collect().await?.to_bytes().as_ref(),
            b"proxy-reprobe-ok"
        );
        let (in_after, sp_after) = miraserve_http::test_h2_exec_stream_counts();
        assert_eq!(
            (in_after - in_before, sp_after - sp_before),
            (0, 1),
            "proxy-only H2 (no static work) must run spawned via plain TokioExecutor"
        );

        // 2. Hot-reload to add a static root while openat2 is available: reload actively probes
        //    openat2 and switches new connections to InTask (static in-task, proxy spawned).
        let kdl_with_static = format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
}}
site "p1c.h2it.test" {{
    root "{root}"
    route "/proxy/*" {{
        reverse-proxy {{
            upstream "http://127.0.0.1:{up_port}"
        }}
    }}
}}
"#,
            root = tmp.path.to_string_lossy().replace('\\', "/"),
        );
        let probe_before_reload = miraserve_static::test_openat2_probe_calls();
        server.reload_from_str("h2it-p1c-static.kdl", &kdl_with_static)?;
        assert!(
            miraserve_static::test_openat2_probe_calls() > probe_before_reload,
            "reload adding static work on Linux 5.12-6.11 must actively probe openat2"
        );

        // Existing spawned connection still serves newly added static files cleanly.
        existing_sender.ready().await?;
        let r_existing = existing_sender
            .send_request(
                Request::builder()
                    .uri("https://p1c.h2it.test/static/added.txt")
                    .body(Empty::new())?,
            )
            .await?;
        assert_eq!(r_existing.status(), StatusCode::OK);
        assert_eq!(
            r_existing.into_body().collect().await?.to_bytes().as_ref(),
            b"added-after-reload"
        );

        // New connection with openat2 available uses per-request InTask: static runs in-task and
        // proxy on the SAME connection runs spawned.
        let (in_before2, sp_before2) = miraserve_http::test_h2_exec_stream_counts();
        let (mut mixed_sender, mixed_conn) =
            connect_h2_tls::<Empty<Bytes>>(https_addr, "p1c.h2it.test", &tls_cfg).await?;
        mixed_sender.ready().await?;
        let r_st = mixed_sender
            .send_request(
                Request::builder()
                    .uri("https://p1c.h2it.test/static/added.txt")
                    .body(Empty::new())?,
            )
            .await?;
        assert_eq!(r_st.status(), StatusCode::OK);
        assert_eq!(
            r_st.into_body().collect().await?.to_bytes().as_ref(),
            b"added-after-reload"
        );
        mixed_sender.ready().await?;
        let r_prx = mixed_sender
            .send_request(
                Request::builder()
                    .uri("https://p1c.h2it.test/proxy/ok")
                    .body(Empty::new())?,
            )
            .await?;
        assert_eq!(r_prx.status(), StatusCode::OK);
        assert_eq!(
            r_prx.into_body().collect().await?.to_bytes().as_ref(),
            b"proxy-reprobe-ok"
        );
        let (in_after2, sp_after2) = miraserve_http::test_h2_exec_stream_counts();
        assert_eq!(
            (in_after2 - in_before2, sp_after2 - sp_before2),
            (1, 1),
            "once openat2 is available with static work, static runs in-task and proxy runs spawned on the same connection"
        );

        // 3. When openat2 is latched unavailable (e.g. RestrictSUIDSGID=yes), new connections fall
        //    back to Spawned even with static work configured.
        {
            let _unavail = miraserve_static::test_openat2_latches_guard(true, false);
            let (in_before3, sp_before3) = miraserve_http::test_h2_exec_stream_counts();
            let (mut new_sender, new_conn) =
                connect_h2_tls::<Empty<Bytes>>(https_addr, "p1c.h2it.test", &tls_cfg).await?;
            new_sender.ready().await?;
            let r_new = new_sender
                .send_request(
                    Request::builder()
                        .uri("https://p1c.h2it.test/static/added.txt")
                        .body(Empty::new())?,
                )
                .await?;
            assert_eq!(r_new.status(), StatusCode::OK);
            assert_eq!(
                r_new.into_body().collect().await?.to_bytes().as_ref(),
                b"added-after-reload"
            );
            let (in_after3, sp_after3) = miraserve_http::test_h2_exec_stream_counts();
            assert_eq!(
                (in_after3 - in_before3, sp_after3 - sp_before3),
                (0, 1),
                "new connections with openat2 unavailable must use spawned mode"
            );
            drop(new_sender);
            new_conn.abort();
        }

        // 4. Reloading back to proxy-only (with openat2 available) skips probing openat2 and
        //    returns new connections to Spawned (`TokioExecutor`).
        let probe_before_back = miraserve_static::test_openat2_probe_calls();
        server.reload_from_str("h2it-p1c-proxy-back.kdl", &kdl_proxy_only)?;
        assert_eq!(
            miraserve_static::test_openat2_probe_calls(),
            probe_before_back,
            "reload back to proxy-only must not probe openat2"
        );
        let (in_before4, sp_before4) = miraserve_http::test_h2_exec_stream_counts();
        let (mut back_sender, back_conn) =
            connect_h2_tls::<Empty<Bytes>>(https_addr, "p1c.h2it.test", &tls_cfg).await?;
        back_sender.ready().await?;
        let r_back = back_sender
            .send_request(
                Request::builder()
                    .uri("https://p1c.h2it.test/after")
                    .body(Empty::new())?,
            )
            .await?;
        assert_eq!(r_back.status(), StatusCode::OK);
        assert_eq!(
            r_back.into_body().collect().await?.to_bytes().as_ref(),
            b"proxy-reprobe-ok"
        );
        let (in_after4, sp_after4) = miraserve_http::test_h2_exec_stream_counts();
        assert_eq!(
            (in_after4 - in_before4, sp_after4 - sp_before4),
            (0, 1),
            "reloading back to proxy-only must return new connections to spawned mode"
        );

        drop(back_sender);
        drop(mixed_sender);
        drop(existing_sender);
        back_conn.abort();
        mixed_conn.abort();
        existing_conn.abort();
        up_task.abort();
        server.shutdown().await;
        Ok(())
    })
}

/// Codex round-4 P2: when an ordinary HTTP/2 response stream is still open past the graceful
/// connection-drain deadline, core force-closes without joining the connection task. Even if
/// both offloaded log queues are empty at the snapshot, `shutdown_with_report()` MUST report
/// `connections_forced_closed == true` and `is_clean() == false` (never claiming a clean drain).
#[test]
#[allow(clippy::too_many_lines)]
fn h2_tls_forced_shutdown_marks_report_not_clean_when_connections_exceed_deadline() -> TestResult {
    run_h2_tls_multi_thread(2, async {
        let _mode = enter_in_task_h2_test_mode();
        let tmp = TempDir::new("forced-shutdown")?;

        let stream_started = Arc::new(Notify::new());
        let (hold_tx, mut hold_rx) = tokio::sync::watch::channel(false);
        let up_listener = TcpListener::bind("127.0.0.1:0").await?;
        let up_addr = up_listener.local_addr()?;
        let started_c = Arc::clone(&stream_started);
        let up_task = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            if let Ok((mut stream, _)) = up_listener.accept().await {
                let mut buf = [0_u8; 2048];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n",
                    )
                    .await;
                let _ = stream.flush().await;
                started_c.notify_one();
                let _ = hold_rx.wait_for(|&v| v).await;
            }
        });

        let tls_port = reserve_free_port()?;
        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
    timeouts {{
        graceful-drain "150ms"
    }}
}}
site "forced.h2it.test" {{
    root "{root}"
    route "/stream/*" {{
        reverse-proxy {{
            upstream "http://{up_addr}"
        }}
    }}
}}
"#,
            root = tmp.path.to_string_lossy().replace('\\', "/"),
        );
        let (cfg, _) = parse_kdl("h2it-forced-shutdown.kdl", &kdl)?;
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
            .ok_or("missing HTTPS listener")?
            .local_addr;
        let tls_cfg = build_h2_tls_client(server.dev_cert_pem().ok_or("missing dev cert")?)?;
        let (mut sender, conn_task) =
            connect_h2_tls::<Empty<Bytes>>(https_addr, "forced.h2it.test", &tls_cfg).await?;

        sender.ready().await?;
        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            sender.send_request(
                Request::builder()
                    .uri("https://forced.h2it.test/stream/open")
                    .body(Empty::new())?,
            ),
        )
        .await??;
        assert_eq!(resp.status(), StatusCode::OK);
        tokio::time::timeout(Duration::from_secs(5), stream_started.notified()).await?;

        // Keep `resp` (and its open H2 response stream) alive past `graceful-drain = 150ms`.
        let report = tokio::time::timeout(Duration::from_secs(5), server.shutdown_with_report())
            .await
            .map_err(
                |_| "forced shutdown did not complete promptly after graceful-drain expired",
            )?;
        assert!(
            report.connections_forced_closed && !report.workers_join_timed_out,
            "shutdown report must record connections_forced_closed=true (and workers_join_timed_out=false) when deadline expires with an open stream (got {report:?})"
        );
        assert!(
            !report.is_clean(),
            "shutdown report must NOT claim a clean drain when connections were force-closed (got {report:?})"
        );

        drop(resp);
        drop(sender);
        let _ = hold_tx.send(true);
        conn_task.abort();
        up_task.abort();
        Ok(())
    })
}

/// Round 6 (Requirements 1, 2, 4): End-to-end real TCP + TLS 1.3 HTTP/2 verification on ONE
/// connection mixing static files, direct reverse-proxy routes, and a WordPress-style `try-files`
/// front-controller with a proxy fallback:
/// - Static assets and extensioned `try-files` GET/HEAD run IN-TASK; direct proxy, extensionless
///   `try-files`, and `try-files` POST run SPAWNED (exact counters, zero hand-off mismatches);
/// - Blocking upstream on a spawned proxy stream does not delay concurrent in-task static streams;
/// - Abrupt connection drop with an outstanding spawned proxy stream drops it cleanly (upstream
///   observes socket close; simultaneous abrupt drop of both kinds is verified by
///   `h2_intask::tests::per_request_handoff_routes_in_task_and_spawned_streams_on_one_connection`);
/// - Graceful shutdown drains an in-flight spawned proxy stream after an in-task static stream
///   completed on the same connection (`is_clean() == true`; holding BOTH an in-task static stream
///   and a spawned proxied stream simultaneously outstanding across the same graceful shutdown is
///   verified by `h2_tls_graceful_shutdown_drains_simultaneous_in_task_static_and_spawned_proxy_streams`).
#[test]
#[allow(clippy::too_many_lines)]
fn h2_tls_per_request_multiplexed_static_and_proxy_take_separate_paths() -> TestResult {
    run_h2_tls_multi_thread(2, async {
        let _mode = enter_in_task_h2_test_mode();
        let tmp = TempDir::new("r6-mixed")?;
        fs::write(tmp.path.join("asset.css"), b"body{color:green}")?;
        fs::write(tmp.path.join("style.css"), b"try-files-asset")?;

        let block_entered = Arc::new(Notify::new());
        let (block_release_tx, block_release_rx) = tokio::sync::watch::channel(false);
        let drop_entered = Arc::new(Notify::new());
        let drop_eof = Arc::new(Notify::new());

        let up_listener = TcpListener::bind("127.0.0.1:0").await?;
        let up_port = up_listener.local_addr()?.port();
        let be = Arc::clone(&block_entered);
        let de = Arc::clone(&drop_entered);
        let df = Arc::clone(&drop_eof);
        let up_task = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            loop {
                let Ok((mut sock, _)) = up_listener.accept().await else {
                    break;
                };
                let be = Arc::clone(&be);
                let mut br = block_release_rx.clone();
                let de = Arc::clone(&de);
                let df = Arc::clone(&df);
                tokio::spawn(async move {
                    let mut buf = [0_u8; 2048];
                    let Ok(n) = sock.read(&mut buf).await else {
                        return;
                    };
                    let head = String::from_utf8_lossy(buf.get(..n).unwrap_or(&[]));
                    if head.starts_with("GET /api/block ") {
                        be.notify_one();
                        let _ = br.wait_for(|&v| v).await;
                        let _ = sock
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nblock-reply",
                            )
                            .await;
                    } else if head.starts_with("GET /api/drop ") {
                        de.notify_one();
                        let mut probe = [0_u8; 64];
                        loop {
                            match sock.read(&mut probe).await {
                                Ok(0) | Err(_) => {
                                    df.notify_one();
                                    break;
                                }
                                Ok(_) => {}
                            }
                        }
                    } else if head.starts_with("GET /api/front")
                        || head.starts_with("POST /api/front")
                    {
                        let _ = sock
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nfront-ctrl",
                            )
                            .await;
                    } else {
                        let _ = sock
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nproxy-yes",
                            )
                            .await;
                    }
                });
            }
        });

        let tls_port = reserve_free_port()?;
        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
}}
site "mixed.h2it.test" {{
    root "{root}"
    route "/api/*" {{
        reverse-proxy {{
            upstream "http://127.0.0.1:{up_port}"
        }}
    }}
    route "/static/*" {{
        root "{root}"
        static {{}}
    }}
    route "/*" {{
        try-files "{{path}}" "{{path}}/" "/api/front"
    }}
}}
"#,
            root = tmp.path.to_string_lossy().replace('\\', "/"),
        );
        let (cfg, _) = parse_kdl("h2it-r6-mixed.kdl", &kdl)?;
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
            .ok_or("missing HTTPS listener")?
            .local_addr;
        let tls_cfg = build_h2_tls_client(server.dev_cert_pem().ok_or("missing dev cert")?)?;
        let (mut sender, conn_task) =
            connect_h2_tls::<Empty<Bytes>>(https_addr, "mixed.h2it.test", &tls_cfg).await?;

        let (in_before, sp_before) = miraserve_http::test_h2_exec_stream_counts();
        let mm_before = miraserve_http::test_h2_handoff_mismatch_count();

        // 1. Hold a blocking spawned proxy stream `/api/block` while multiplexing in-task static
        //    and try-files requests on the SAME connection.
        sender.ready().await?;
        let block_fut = sender.send_request(
            Request::builder()
                .uri("https://mixed.h2it.test/api/block")
                .body(Empty::new())?,
        );
        let block_h = tokio::spawn(async move {
            let r = block_fut.await?;
            let st = r.status();
            let b = r.into_body().collect().await?.to_bytes();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((st, b))
        });
        tokio::time::timeout(Duration::from_secs(5), block_entered.notified()).await?;

        // While `/api/block` (spawned) is blocked:
        // - `/asset.css` (try-files GET with extension -> in-task) completes immediately.
        sender.ready().await?;
        let r_css = tokio::time::timeout(
            Duration::from_secs(3),
            sender.send_request(
                Request::builder()
                    .uri("https://mixed.h2it.test/asset.css")
                    .body(Empty::new())?,
            ),
        )
        .await??;
        assert_eq!(r_css.status(), StatusCode::OK);
        assert_eq!(
            r_css.into_body().collect().await?.to_bytes().as_ref(),
            b"body{color:green}"
        );

        // - `/style.css` (try-files GET with extension -> in-task).
        sender.ready().await?;
        let r_style = sender
            .send_request(
                Request::builder()
                    .uri("https://mixed.h2it.test/style.css")
                    .body(Empty::new())?,
            )
            .await?;
        assert_eq!(r_style.status(), StatusCode::OK);
        assert_eq!(
            r_style.into_body().collect().await?.to_bytes().as_ref(),
            b"try-files-asset"
        );

        // - `/posts/hello` (try-files extensionless -> spawned, falls back to `/api/front`).
        sender.ready().await?;
        let r_page = sender
            .send_request(
                Request::builder()
                    .uri("https://mixed.h2it.test/posts/hello")
                    .body(Empty::new())?,
            )
            .await?;
        assert_eq!(r_page.status(), StatusCode::OK);
        assert_eq!(
            r_page.into_body().collect().await?.to_bytes().as_ref(),
            b"front-ctrl"
        );

        // - `POST /submit.json` (try-files non-GET/HEAD even with a file extension -> spawned,
        //   falls back to `/api/front`).
        sender.ready().await?;
        let r_post = sender
            .send_request(
                Request::builder()
                    .method(Method::POST)
                    .uri("https://mixed.h2it.test/submit.json")
                    .body(Empty::new())?,
            )
            .await?;
        assert_eq!(r_post.status(), StatusCode::OK);
        assert_eq!(
            r_post.into_body().collect().await?.to_bytes().as_ref(),
            b"front-ctrl"
        );

        // - Direct `/api/data` -> spawned.
        sender.ready().await?;
        let r_api = sender
            .send_request(
                Request::builder()
                    .uri("https://mixed.h2it.test/api/data")
                    .body(Empty::new())?,
            )
            .await?;
        assert_eq!(r_api.status(), StatusCode::OK);
        assert_eq!(
            r_api.into_body().collect().await?.to_bytes().as_ref(),
            b"proxy-yes"
        );

        // Release `/api/block`.
        let _ = block_release_tx.send(true);
        let (b_st, b_bytes) = tokio::time::timeout(Duration::from_secs(5), block_h)
            .await??
            .map_err(|e| e.to_string())?;
        assert_eq!(b_st, StatusCode::OK);
        assert_eq!(b_bytes.as_ref(), b"block-reply");

        let (in_after, sp_after) = miraserve_http::test_h2_exec_stream_counts();
        assert_eq!(
            (in_after - in_before, sp_after - sp_before),
            (2, 4),
            "expected 2 in-task streams (/asset.css, /style.css) and 4 spawned streams (/api/block, /posts/hello, POST /submit.json, /api/data)"
        );
        assert_eq!(
            miraserve_http::test_h2_handoff_mismatch_count(),
            mm_before,
            "expected zero hand-off mismatches"
        );

        // 2. Abrupt connection drop with ONE spawned stream (`/api/drop`) in flight: dropping the
        //    client connection closes the upstream socket cleanly (v0.1.4 behavior).
        sender.ready().await?;
        let drop_fut = sender.send_request(
            Request::builder()
                .uri("https://mixed.h2it.test/api/drop")
                .body(Empty::new())?,
        );
        let drop_h = tokio::spawn(async move {
            let _ = drop_fut.await;
        });
        tokio::time::timeout(Duration::from_secs(5), drop_entered.notified()).await?;
        drop(sender);
        conn_task.abort();
        drop_h.abort();
        tokio::time::timeout(Duration::from_secs(5), drop_eof.notified())
            .await
            .map_err(|_| "upstream did not observe EOF after client dropped connection")?;

        // 3. On a fresh connection, serve an in-task static request to completion and then hold an
        //    in-flight spawned proxy stream across graceful shutdown, verifying a clean drain.
        let _ = block_release_tx.send(false);
        let (mut sender2, conn_task2) =
            connect_h2_tls::<Empty<Bytes>>(https_addr, "mixed.h2it.test", &tls_cfg).await?;
        sender2.ready().await?;
        let drain_sp = sender2.send_request(
            Request::builder()
                .uri("https://mixed.h2it.test/api/block")
                .body(Empty::new())?,
        );
        let drain_sp_h = tokio::spawn(async move {
            let r = drain_sp.await?;
            let st = r.status();
            let b = r.into_body().collect().await?.to_bytes();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((st, b))
        });
        tokio::time::timeout(Duration::from_secs(5), block_entered.notified()).await?;

        // Also send a fast in-task request on the same connection before shutdown.
        sender2.ready().await?;
        let pre_st = sender2
            .send_request(
                Request::builder()
                    .uri("https://mixed.h2it.test/asset.css")
                    .body(Empty::new())?,
            )
            .await?;
        assert_eq!(pre_st.status(), StatusCode::OK);
        let _ = pre_st.into_body().collect().await?;

        let shutdown_task = tokio::spawn(async move { server.shutdown_with_report().await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !shutdown_task.is_finished(),
            "graceful shutdown must wait for in-flight spawned stream on in-task connection"
        );
        let _ = block_release_tx.send(true);
        let (d_st, d_bytes) = tokio::time::timeout(Duration::from_secs(5), drain_sp_h)
            .await??
            .map_err(|e| e.to_string())?;
        assert_eq!(d_st, StatusCode::OK);
        assert_eq!(d_bytes.as_ref(), b"block-reply");
        drop(sender2);

        let report = tokio::time::timeout(Duration::from_secs(5), shutdown_task).await??;
        assert!(
            report.is_clean(),
            "graceful shutdown must drain cleanly (got {report:?})"
        );
        assert_eq!(miraserve_http::test_h2_handoff_mismatch_count(), mm_before);

        conn_task2.abort();
        up_task.abort();
        Ok(())
    })
}

/// Round 7: Holds BOTH an in-task static stream (512 KiB file paused mid-body behind a 16 KiB
/// client HTTP/2 initial stream flow-control window after response headers arrive) AND a spawned
/// reverse-proxy stream (`/api/block` parked on an upstream barrier) simultaneously outstanding on
/// ONE real TCP + TLS 1.3 HTTP/2 connection across the SAME `server.shutdown_with_report()`.
///
/// Proves:
/// - Graceful shutdown waits while both streams are held open;
/// - Releasing and completing the spawned proxy stream alone does NOT finish shutdown while the
///   in-task static stream still has unread body bytes;
/// - Draining the in-task static stream's full 512 KiB body completes graceful shutdown cleanly
///   (`report.is_clean() == true`) with exact `(1, 1)` in-task/spawned counts and zero mismatches.
#[test]
#[allow(clippy::too_many_lines)]
fn h2_tls_graceful_shutdown_drains_simultaneous_in_task_static_and_spawned_proxy_streams()
-> TestResult {
    run_h2_tls_multi_thread(2, async {
        let _mode = enter_in_task_h2_test_mode();
        let tmp = TempDir::new("r7-dual-drain")?;
        // 512 KiB deterministic static payload (> 256 KiB inline threshold and 32× larger than the
        // client's 16 KiB HTTP/2 initial stream window so the in-task static stream stays actively
        // open inside `Driven::streams` waiting for flow-control credit until drained).
        let big_payload: Vec<u8> = (0..(512 * 1024))
            .map(|i| u8::try_from((i * 31 + 17) % 251).unwrap_or(0))
            .collect();
        fs::write(tmp.path.join("big.bin"), &big_payload)?;

        let block_entered = Arc::new(Notify::new());
        let (block_release_tx, block_release_rx) = tokio::sync::watch::channel(false);

        let up_listener = TcpListener::bind("127.0.0.1:0").await?;
        let up_port = up_listener.local_addr()?.port();
        let be = Arc::clone(&block_entered);
        let up_task = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            loop {
                let Ok((mut sock, _)) = up_listener.accept().await else {
                    break;
                };
                let be = Arc::clone(&be);
                let mut br = block_release_rx.clone();
                tokio::spawn(async move {
                    let mut buf = [0_u8; 2048];
                    if sock.read(&mut buf).await.is_err() {
                        return;
                    }
                    be.notify_one();
                    let _ = br.wait_for(|&v| v).await;
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\nspawned-answer",
                        )
                        .await;
                });
            }
        });

        let tls_port = reserve_free_port()?;
        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
    timeouts {{ graceful-drain "5s" }}
}}
site "dual-drain.h2it.test" {{
    root "{root}"
    route "/api/*" {{
        reverse-proxy {{
            upstream "http://127.0.0.1:{up_port}"
        }}
    }}
}}
"#,
            root = tmp.path.to_string_lossy().replace('\\', "/"),
        );
        let (cfg, _) = parse_kdl("h2it-r7-dual-drain.kdl", &kdl)?;
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
            .ok_or("missing HTTPS listener")?
            .local_addr;
        let tls_cfg = build_h2_tls_client(server.dev_cert_pem().ok_or("missing dev cert")?)?;

        // Build an HTTP/2 client with a tight 16 KiB initial stream window so `/big.bin` sends its
        // response headers + first 16 KiB immediately and then parks inside `Driven::streams`
        // until the client drains the body.
        let tcp = TcpStream::connect(https_addr).await?;
        let _ = tcp.set_nodelay(true);
        let connector = TlsConnector::from(tls_cfg);
        let sni = ServerName::try_from("dual-drain.h2it.test".to_owned())?;
        let tls = connector.connect(sni, tcp).await?;
        let mut h2_builder = h2_client::Builder::new(TokioExecutor::new());
        h2_builder.initial_stream_window_size(16 * 1024);
        let (mut sender, conn) = h2_builder
            .handshake::<_, Empty<Bytes>>(TokioIo::new(tls))
            .await?;
        let conn_task = tokio::spawn(async move {
            let _ = conn.await;
        });

        let (in_before, sp_before) = miraserve_http::test_h2_exec_stream_counts();
        let mm_before = miraserve_http::test_h2_handoff_mismatch_count();

        // 1. Start the spawned proxied stream `/api/block` and wait until upstream holds it open.
        sender.ready().await?;
        let proxy_fut = sender.send_request(
            Request::builder()
                .uri("https://dual-drain.h2it.test/api/block")
                .body(Empty::new())?,
        );
        let proxy_h = tokio::spawn(async move {
            let r = proxy_fut.await?;
            let st = r.status();
            let b = r.into_body().collect().await?.to_bytes();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((st, b))
        });
        tokio::time::timeout(Duration::from_secs(5), block_entered.notified()).await?;

        // 2. Start the in-task static stream `/big.bin` on the SAME connection and await response
        //    headers WITHOUT reading the body yet (so 512 KiB is blocked on the 16 KiB H2 window).
        sender.ready().await?;
        let static_resp = tokio::time::timeout(
            Duration::from_secs(5),
            sender.send_request(
                Request::builder()
                    .uri("https://dual-drain.h2it.test/big.bin")
                    .body(Empty::new())?,
            ),
        )
        .await??;
        assert_eq!(static_resp.status(), StatusCode::OK);
        assert!(
            !static_resp.body().is_end_stream(),
            "in-task static stream must still have unread body bytes outstanding before shutdown"
        );

        // Verify both streams were already accepted and classified into separate paths before
        // graceful shutdown begins.
        let (in_mid, sp_mid) = miraserve_http::test_h2_exec_stream_counts();
        assert_eq!(
            (in_mid - in_before, sp_mid - sp_before),
            (1, 1),
            "expected 1 in-task static stream (/big.bin) and 1 spawned proxy stream (/api/block)"
        );

        // 3. Initiate graceful shutdown while BOTH streams are simultaneously outstanding.
        let shutdown_task = tokio::spawn(async move { server.shutdown_with_report().await });
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(
            !shutdown_task.is_finished(),
            "graceful shutdown must wait while BOTH in-task static and spawned proxy streams are open"
        );

        // 4. Release and finish ONLY the spawned proxy stream first; shutdown must STILL wait
        //    because the in-task static stream is still open mid-body.
        let _ = block_release_tx.send(true);
        let (p_st, p_bytes) = tokio::time::timeout(Duration::from_secs(5), proxy_h)
            .await??
            .map_err(|e| e.to_string())?;
        assert_eq!(p_st, StatusCode::OK);
        assert_eq!(p_bytes.as_ref(), b"spawned-answer");

        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(
            !shutdown_task.is_finished(),
            "graceful shutdown must STILL wait for the outstanding in-task static stream after spawned stream finishes"
        );

        // 5. Now drain the in-task static stream to completion and drop the client sender.
        let static_bytes =
            tokio::time::timeout(Duration::from_secs(5), static_resp.into_body().collect())
                .await??
                .to_bytes();
        assert_eq!(static_bytes.len(), big_payload.len());
        assert_eq!(static_bytes.as_ref(), big_payload.as_slice());
        drop(sender);

        // 6. Graceful shutdown must now finish cleanly with zero mismatches.
        let report = tokio::time::timeout(Duration::from_secs(5), shutdown_task).await??;
        assert!(
            report.is_clean(),
            "graceful shutdown must drain both simultaneous streams cleanly (got {report:?})"
        );
        assert_eq!(miraserve_http::test_h2_handoff_mismatch_count(), mm_before);

        conn_task.abort();
        up_task.abort();
        Ok(())
    })
}

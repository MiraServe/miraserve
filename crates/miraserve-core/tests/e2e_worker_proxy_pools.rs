//! End-to-end tests for per-worker upstream reverse-proxy connection pools (`server { workers ... }`):
//! worker-local keep-alive reuse and isolation, shared-runtime single-pool preservation,
//! reload (proxy replacement and worker-count changes), WebSocket upgrades through a worker,
//! active health-check probes on the shared client, and graceful shutdown with idle pools.

use std::collections::HashSet;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use http::header::HOST;
use http::{Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper_util::rt::TokioIo;
use miraserve_config::{ConfigStore, parse_kdl};
use miraserve_core::{CoreError, ListenerKind, MiraServeServer, RunningServer, ServerOptions};
use miraserve_http::{ProxyClientSlot, ProxyPoolEvent, test_proxy_pool_observer_guard};
use miraserve_tls::build_crypto_provider;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::ServerName;
use rustls::pki_types::pem::PemObject as _;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_rustls::TlsConnector;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Serializes tests in this binary because they install the process-wide proxy pool observer
/// and inspect `/proc/self/task` worker thread counts.
fn pool_test_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

#[cfg(target_os = "linux")]
fn count_worker_loop_threads() -> Result<usize, std::io::Error> {
    Ok(std::fs::read_dir("/proc/self/task")?
        .filter_map(Result::ok)
        .filter_map(|task| std::fs::read_to_string(task.path().join("comm")).ok())
        .filter(|name| name.starts_with("miraserve-loop-"))
        .count())
}

#[cfg(target_os = "linux")]
async fn wait_for_zero_worker_loop_threads() -> Result<usize, std::io::Error> {
    let deadline = std::time::Instant::now() + Duration::from_millis(500);
    loop {
        let count = count_worker_loop_threads()?;
        if count == 0 || std::time::Instant::now() >= deadline {
            return Ok(count);
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn reserve_free_listen_addr() -> Result<SocketAddr, std::io::Error> {
    #[cfg(target_os = "linux")]
    {
        // Linux `SO_REUSEPORT` lets two same-UID processes bind the same `(ip, port)` without
        // `EADDRINUSE` if a dropped probe port is recycled between `reserve` and `start`. Mapping
        // each live PID bijectively into `127.1..=254.0..=255.1..=254` (16.5M addresses) keeps
        // parallel test processes in disjoint `SO_REUSEPORT` socket groups.
        let pid = std::process::id();
        let d = u8::try_from((pid % 254) + 1).unwrap_or(1);
        let c = u8::try_from((pid / 254) % 256).unwrap_or(0);
        let b = u8::try_from(((pid / (254 * 256)) % 254) + 1).unwrap_or(1);
        let ip = std::net::Ipv4Addr::new(127, b, c, d);
        if let Ok(sock) = StdTcpListener::bind((ip, 0)) {
            return sock.local_addr();
        }
    }
    let sock = StdTcpListener::bind("127.0.0.1:0")?;
    sock.local_addr()
}

/// Starts `MiraServeServer` with retries on ephemeral `AddrInUse` races when many test processes
/// run in parallel.
async fn start_server_with_kdl(
    source_name: &str,
    make_kdl: impl Fn(SocketAddr) -> String,
) -> Result<(RunningServer, SocketAddr), Box<dyn std::error::Error>> {
    for attempt in 0..16_usize {
        let listen_addr = reserve_free_listen_addr()?;
        let kdl = make_kdl(listen_addr);
        let (cfg, _) = parse_kdl(source_name, &kdl)?;
        match MiraServeServer::start(
            Arc::new(ConfigStore::new(cfg)),
            ServerOptions {
                dev_tls: true,
                ..ServerOptions::default()
            },
        )
        .await
        {
            Ok(server) => return Ok((server, listen_addr)),
            Err(CoreError::Bind { source, .. })
                if source.kind() == std::io::ErrorKind::AddrInUse && attempt + 1 < 16 => {}
            Err(err) => return Err(err.into()),
        }
    }
    Err("could not bind an ephemeral test port after 16 attempts".into())
}

fn build_h1_tls_client(
    server: &RunningServer,
) -> Result<Arc<ClientConfig>, Box<dyn std::error::Error>> {
    let cert_pem = server.dev_cert_pem().ok_or("expected dev cert PEM")?;
    let mut roots = RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert_pem.as_bytes()).collect::<Result<_, _>>()?;
    roots.add_parsable_certificates(certs);

    let mut cfg = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

fn https_listener_addr(server: &RunningServer) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    Ok(server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::HttpsTcp)
        .ok_or("missing HttpsTcp listener")?
        .local_addr)
}

#[derive(Debug, Clone)]
struct UpstreamRequestRecord {
    conn_id: usize,
    peer_addr: SocketAddr,
    #[allow(dead_code)]
    request_line: String,
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

/// Persistent HTTP/1.1 keep-alive test upstream that tracks every accepted TCP connection,
/// live open-connection count, and `(conn_id, peer_addr)` for each handled request.
struct TestUpstream {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
    open: Arc<AtomicUsize>,
    closed_notify: Arc<Notify>,
    records: Arc<Mutex<Vec<UpstreamRequestRecord>>>,
    task: tokio::task::JoinHandle<()>,
}

impl TestUpstream {
    async fn start() -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let accepted = Arc::new(AtomicUsize::new(0));
        let open = Arc::new(AtomicUsize::new(0));
        let closed_notify = Arc::new(Notify::new());
        let records = Arc::new(Mutex::new(Vec::new()));

        let accepted_c = Arc::clone(&accepted);
        let open_c = Arc::clone(&open);
        let closed_c = Arc::clone(&closed_notify);
        let records_c = Arc::clone(&records);

        let task = tokio::spawn(async move {
            while let Ok((mut sock, peer_addr)) = listener.accept().await {
                let conn_id = accepted_c.fetch_add(1, Ordering::SeqCst) + 1;
                open_c.fetch_add(1, Ordering::SeqCst);
                let open_inner = Arc::clone(&open_c);
                let closed_inner = Arc::clone(&closed_c);
                let records_inner = Arc::clone(&records_c);
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
                        let head_bytes = buf.drain(..end_pos).collect::<Vec<u8>>();
                        let req_line = String::from_utf8_lossy(&head_bytes)
                            .lines()
                            .next()
                            .unwrap_or("")
                            .to_owned();
                        records_inner
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push(UpstreamRequestRecord {
                                conn_id,
                                peer_addr,
                                request_line: req_line,
                            });
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Upstream-Conn-Id: {conn_id}\r\nX-Upstream-Peer: {peer_addr}\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok"
                        );
                        if sock.write_all(resp.as_bytes()).await.is_err() {
                            break;
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
            records,
            task,
        })
    }

    fn accepted_count(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    fn open_count(&self) -> usize {
        self.open.load(Ordering::SeqCst)
    }

    fn records_snapshot(&self) -> Vec<UpstreamRequestRecord> {
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
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

impl Drop for TestUpstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

struct H1ClientConn {
    sender: hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
    conn_task: tokio::task::JoinHandle<Result<(), hyper::Error>>,
}

impl H1ClientConn {
    async fn connect(
        addr: SocketAddr,
        host: &str,
        tls_cfg: &Arc<ClientConfig>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let tcp = TcpStream::connect(addr).await?;
        let tls = TlsConnector::from(Arc::clone(tls_cfg))
            .connect(ServerName::try_from(host.to_owned())?, tcp)
            .await?;
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
        let conn_task = tokio::spawn(conn);
        Ok(Self { sender, conn_task })
    }

    async fn get_conn_id(
        &mut self,
        host: &str,
        path: &str,
    ) -> Result<(usize, SocketAddr), Box<dyn std::error::Error>> {
        self.sender.ready().await?;
        let resp = self
            .sender
            .send_request(
                Request::builder()
                    .uri(path)
                    .header(HOST, host)
                    .body(Empty::<Bytes>::new())?,
            )
            .await?;
        assert_eq!(resp.status(), StatusCode::OK, "GET {path} failed");
        let conn_id: usize = resp
            .headers()
            .get("x-upstream-conn-id")
            .and_then(|v| v.to_str().ok())
            .ok_or("missing x-upstream-conn-id")?
            .parse()?;
        let peer: SocketAddr = resp
            .headers()
            .get("x-upstream-peer")
            .and_then(|v| v.to_str().ok())
            .ok_or("missing x-upstream-peer")?
            .parse()?;
        let body = resp.into_body().collect().await?.to_bytes();
        assert_eq!(&body[..], b"ok");
        Ok((conn_id, peer))
    }

    async fn close(self) {
        drop(self.sender);
        let _ = self.conn_task.await;
    }
}

/// Opens client connections sequentially under Linux `SO_REUSEPORT` (`workers 2`) until one live
/// connection is pinned to worker 0 and one live connection is pinned to worker 1.
#[cfg(target_os = "linux")]
async fn open_worker_pinned_connections(
    addr: SocketAddr,
    host: &str,
    tls_cfg: &Arc<ClientConfig>,
    events: &Arc<Mutex<Vec<ProxyPoolEvent>>>,
) -> Result<
    (
        H1ClientConn,
        H1ClientConn,
        (usize, SocketAddr),
        (usize, SocketAddr),
    ),
    Box<dyn std::error::Error>,
> {
    let mut w0: Option<(H1ClientConn, (usize, SocketAddr))> = None;
    let mut w1: Option<(H1ClientConn, (usize, SocketAddr))> = None;

    for attempt in 0..64_usize {
        if w0.is_some() && w1.is_some() {
            break;
        }
        let mut conn = H1ClientConn::connect(addr, host, tls_cfg).await?;
        let path = format!("/api/identify-{attempt}");
        let info = conn.get_conn_id(host, &path).await?;
        let worker_idx = events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .rev()
            .find(|e| e.path == path && !e.is_health_probe)
            .and_then(|e| e.worker_index)
            .ok_or_else(|| format!("missing worker_index event for {path}"))?;

        match worker_idx {
            0 if w0.is_none() => w0 = Some((conn, info)),
            1 if w1.is_none() => w1 = Some((conn, info)),
            _ => conn.close().await,
        }
    }

    let (conn0, info0) = w0.ok_or("never landed a client connection on worker 0")?;
    let (conn1, info1) = w1.ok_or("never landed a client connection on worker 1")?;
    Ok((conn0, conn1, info0, info1))
}

/// Default runtime (`workers "shared"`) allocates no per-worker pools and reuses a single shared
/// upstream connection pool across multiple sequential client connections.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_runtime_uses_single_proxy_pool() -> TestResult {
    let _serial = pool_test_lock().lock().await;
    let events: Arc<Mutex<Vec<ProxyPoolEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let events_cb = Arc::clone(&events);
    let _observer = test_proxy_pool_observer_guard(move |ev| {
        events_cb
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(ev);
    });

    let upstream = TestUpstream::start().await?;
    let up_addr = upstream.addr;
    let (server, _) = start_server_with_kdl("default-pool.kdl", |listen_addr| {
        format!(
            r#"
server {{
    listen "{listen_addr}" protocols="h2,h1"
}}
site "shared.proxy.test" {{
    route "/api/*" {{
        reverse-proxy {{
            upstream "http://{up_addr}"
        }}
    }}
}}
"#
        )
    })
    .await?;

    let https_addr = https_listener_addr(&server)?;
    let tls_cfg = build_h1_tls_client(&server)?;

    let mut seen_conn_ids = HashSet::new();
    let mut seen_peers = HashSet::new();
    for i in 0..5_usize {
        let mut cli = H1ClientConn::connect(https_addr, "shared.proxy.test", &tls_cfg).await?;
        let (cid, peer) = cli
            .get_conn_id("shared.proxy.test", &format!("/api/shared-{i}"))
            .await?;
        seen_conn_ids.insert(cid);
        seen_peers.insert(peer);
        cli.close().await;
        // Let hyper-util's multi-thread `on_idle` readiness task return the pooled connection
        // before opening the next sequential client connection.
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert_eq!(
        upstream.accepted_count(),
        1,
        "default shared runtime must reuse exactly one upstream keep-alive connection"
    );
    assert_eq!(seen_conn_ids.len(), 1);
    assert_eq!(seen_peers.len(), 1);
    let single_peer = *seen_peers.iter().next().ok_or("missing peer")?;

    let recorded = events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(recorded.len(), 5);
    for ev in &recorded {
        assert_eq!(ev.slot, ProxyClientSlot::Shared);
        assert_eq!(ev.worker_index, None);
        assert_eq!(ev.worker_pool_count, 0);
        assert!(!ev.is_health_probe);
        assert_eq!(ev.local_addr, Some(single_peer));
    }

    let up_records = upstream.records_snapshot();
    assert_eq!(up_records.len(), 5);
    assert!(
        up_records
            .iter()
            .all(|r| r.conn_id == 1 && r.peer_addr == single_peer)
    );

    assert_eq!(upstream.open_count(), 1);
    let report = server.shutdown_with_report().await;
    assert!(report.is_clean(), "expected clean shutdown, got {report:?}");
    assert!(
        upstream.wait_open_conns(0, Duration::from_secs(5)).await,
        "shared pool's idle upstream connection must close after server shutdown"
    );
    Ok(())
}

/// Under `workers 2`, each worker creates and reuses kept-alive upstream connections in its own
/// pool and NEVER checks out an upstream connection created by the other worker.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn workers_two_each_worker_reuses_own_upstream_connection_and_never_crosses() -> TestResult {
    let _serial = pool_test_lock().lock().await;
    let events: Arc<Mutex<Vec<ProxyPoolEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let events_cb = Arc::clone(&events);
    let _observer = test_proxy_pool_observer_guard(move |ev| {
        events_cb
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(ev);
    });

    let upstream = TestUpstream::start().await?;
    let up_addr = upstream.addr;
    let (server, _) = start_server_with_kdl("workers2-pools.kdl", |listen_addr| {
        format!(
            r#"
server {{
    listen "{listen_addr}" protocols="h2,h1"
    workers 2
}}
site "pools.workers.test" {{
    route "/api/*" {{
        reverse-proxy {{
            upstream "http://{up_addr}"
        }}
    }}
}}
"#
        )
    })
    .await?;
    assert_eq!(count_worker_loop_threads()?, 2);

    let https_addr = https_listener_addr(&server)?;
    let tls_cfg = build_h1_tls_client(&server)?;

    let (mut conn_w0, mut conn_w1, (cid_w0, peer_w0), (cid_w1, peer_w1)) =
        open_worker_pinned_connections(https_addr, "pools.workers.test", &tls_cfg, &events).await?;

    assert_ne!(
        cid_w0, cid_w1,
        "worker 0 and worker 1 must create distinct upstream connections"
    );
    assert_ne!(peer_w0, peer_w1);
    assert_eq!(
        upstream.accepted_count(),
        2,
        "sequential warm-up across 2 workers must open exactly 2 upstream connections (1 per worker)"
    );

    // Clear warm-up events and drive interleaved requests across both workers.
    events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();

    for round in 0..4_usize {
        let (c0, p0) = conn_w0
            .get_conn_id("pools.workers.test", &format!("/api/w0-{round}"))
            .await?;
        assert_eq!(
            c0, cid_w0,
            "worker 0 must reuse its own upstream connection"
        );
        assert_eq!(p0, peer_w0);

        let (c1, p1) = conn_w1
            .get_conn_id("pools.workers.test", &format!("/api/w1-{round}"))
            .await?;
        assert_eq!(
            c1, cid_w1,
            "worker 1 must reuse its own upstream connection"
        );
        assert_eq!(p1, peer_w1);
    }

    assert_eq!(
        upstream.accepted_count(),
        2,
        "interleaved requests on both workers must reuse kept-alive connections with zero new accepts"
    );

    let recorded = events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(recorded.len(), 8);
    let mut w0_threads = HashSet::new();
    let mut w1_threads = HashSet::new();
    for ev in &recorded {
        assert!(!ev.is_health_probe);
        assert_eq!(ev.worker_pool_count, 2);
        if ev.path.starts_with("/api/w0-") {
            assert_eq!(ev.slot, ProxyClientSlot::Worker(0));
            assert_eq!(ev.worker_index, Some(0));
            assert_eq!(ev.local_addr, Some(peer_w0));
            w0_threads.insert(ev.thread_id);
        } else {
            assert!(ev.path.starts_with("/api/w1-"));
            assert_eq!(ev.slot, ProxyClientSlot::Worker(1));
            assert_eq!(ev.worker_index, Some(1));
            assert_eq!(ev.local_addr, Some(peer_w1));
            w1_threads.insert(ev.thread_id);
        }
    }
    assert_eq!(w0_threads.len(), 1);
    assert_eq!(w1_threads.len(), 1);
    assert!(
        w0_threads.is_disjoint(&w1_threads),
        "worker 0 and worker 1 must execute on distinct OS threads"
    );

    // Close `conn_w0` and verify a brand-new downstream connection that lands on worker 0 STILL
    // reuses worker 0's kept-alive upstream connection `cid_w0` (never worker 1's `cid_w1`).
    conn_w0.close().await;
    let mut reused_on_new_client_conn = false;
    for attempt in 0..64_usize {
        let mut fresh = H1ClientConn::connect(https_addr, "pools.workers.test", &tls_cfg).await?;
        let path = format!("/api/recheck-{attempt}");
        let (cid, peer) = fresh.get_conn_id("pools.workers.test", &path).await?;
        let ev = events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .rev()
            .find(|e| e.path == path)
            .cloned()
            .ok_or("missing recheck event")?;
        fresh.close().await;
        match ev.worker_index {
            Some(0) => {
                assert_eq!(ev.slot, ProxyClientSlot::Worker(0));
                assert_eq!(cid, cid_w0);
                assert_eq!(peer, peer_w0);
                reused_on_new_client_conn = true;
                break;
            }
            Some(1) => {
                assert_eq!(ev.slot, ProxyClientSlot::Worker(1));
                assert_eq!(cid, cid_w1);
                assert_eq!(peer, peer_w1);
            }
            other => return Err(format!("unexpected worker_index {other:?}").into()),
        }
    }
    assert!(
        reused_on_new_client_conn,
        "expected a fresh client connection to land on worker 0 and reuse cid_w0"
    );
    assert_eq!(
        upstream.accepted_count(),
        2,
        "fresh client connections must continue reusing each worker's existing upstream connection"
    );

    conn_w1.close().await;
    let report = server.shutdown_with_report().await;
    assert!(report.is_clean(), "expected clean shutdown, got {report:?}");
    assert_eq!(wait_for_zero_worker_loop_threads().await?, 0);
    Ok(())
}

/// Reloading replaces the proxy (closing old idle connections from the reload thread and creating
/// fresh per-worker pools for the new upstream) and safely handles reloads that change
/// `server.workers` (`2 -> 1 -> "shared"`, where out-of-range worker indices fall back to Shared).
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn workers_reload_replaces_proxy_and_handles_worker_count_change() -> TestResult {
    let _serial = pool_test_lock().lock().await;
    let events: Arc<Mutex<Vec<ProxyPoolEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let events_cb = Arc::clone(&events);
    let _observer = test_proxy_pool_observer_guard(move |ev| {
        events_cb
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(ev);
    });

    let upstream_a = TestUpstream::start().await?;
    let upstream_b = TestUpstream::start().await?;
    let make_kdl = |listen_addr: SocketAddr, workers: &str, up: SocketAddr| {
        format!(
            r#"
server {{
    listen "{listen_addr}" protocols="h2,h1"
    workers {workers}
}}
site "reload.workers.test" {{
    route "/api/*" {{
        reverse-proxy {{
            upstream "http://{up}"
        }}
    }}
}}
"#
        )
    };

    let (server, listen_addr) =
        start_server_with_kdl("reload-v1.kdl", |addr| make_kdl(addr, "2", upstream_a.addr)).await?;
    assert_eq!(count_worker_loop_threads()?, 2);

    let https_addr = https_listener_addr(&server)?;
    let tls_cfg = build_h1_tls_client(&server)?;

    let (mut conn_w0, mut conn_w1, _, _) =
        open_worker_pinned_connections(https_addr, "reload.workers.test", &tls_cfg, &events)
            .await?;
    assert_eq!(upstream_a.open_count(), 2);

    // 1. Reload replacing the proxy upstream (A -> B) while keeping `workers 2`.
    server.reload_from_str(
        "reload-v2.kdl",
        &make_kdl(listen_addr, "2", upstream_b.addr),
    )?;
    assert_eq!(server.restart_required(), Vec::<&str>::new());

    // Dropping the old ReverseProxy from the reload thread must cleanly close both idle upstream
    // connections on worker 0 and worker 1 against upstream A.
    assert!(
        upstream_a.wait_open_conns(0, Duration::from_secs(5)).await,
        "old proxy's idle connections on worker loops must close after reload drops old router"
    );

    events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
    let (b_cid0, b_peer0) = conn_w0
        .get_conn_id("reload.workers.test", "/api/after-swap-w0-1")
        .await?;
    let (b_cid0_again, _) = conn_w0
        .get_conn_id("reload.workers.test", "/api/after-swap-w0-2")
        .await?;
    let (b_cid1, b_peer1) = conn_w1
        .get_conn_id("reload.workers.test", "/api/after-swap-w1-1")
        .await?;
    let (b_cid1_again, _) = conn_w1
        .get_conn_id("reload.workers.test", "/api/after-swap-w1-2")
        .await?;
    assert_eq!(b_cid0, b_cid0_again);
    assert_eq!(b_cid1, b_cid1_again);
    assert_ne!(b_cid0, b_cid1);
    assert_ne!(b_peer0, b_peer1);
    assert_eq!(upstream_b.accepted_count(), 2);

    // 2. Reload lowering `workers 2 -> 1` (running process still has worker threads 0 and 1):
    //    worker 0 stays on `Worker(0)` while out-of-range worker 1 falls back to `Shared`.
    server.reload_from_str(
        "reload-v3.kdl",
        &make_kdl(listen_addr, "1", upstream_b.addr),
    )?;
    assert_eq!(server.restart_required(), vec!["server.workers"]);

    events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
    let _ = conn_w0
        .get_conn_id("reload.workers.test", "/api/shrink-w0")
        .await?;
    let _ = conn_w1
        .get_conn_id("reload.workers.test", "/api/shrink-w1")
        .await?;

    let shrink_events = events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let ev0 = shrink_events
        .iter()
        .find(|e| e.path == "/api/shrink-w0")
        .ok_or("missing shrink-w0 event")?;
    let ev1 = shrink_events
        .iter()
        .find(|e| e.path == "/api/shrink-w1")
        .ok_or("missing shrink-w1 event")?;
    assert_eq!(ev0.slot, ProxyClientSlot::Worker(0));
    assert_eq!(ev0.worker_index, Some(0));
    assert_eq!(ev0.worker_pool_count, 1);
    assert_eq!(ev1.slot, ProxyClientSlot::Shared);
    assert_eq!(ev1.worker_index, Some(1));
    assert_eq!(ev1.worker_pool_count, 1);

    // 3. Reload switching to `workers "shared"`: both running worker loops fall back to `Shared`.
    server.reload_from_str(
        "reload-v4.kdl",
        &make_kdl(listen_addr, "\"shared\"", upstream_b.addr),
    )?;
    assert_eq!(server.restart_required(), vec!["server.workers"]);

    events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
    let _ = conn_w0
        .get_conn_id("reload.workers.test", "/api/shared-w0")
        .await?;
    let _ = conn_w1
        .get_conn_id("reload.workers.test", "/api/shared-w1")
        .await?;

    let shared_events = events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    for path in ["/api/shared-w0", "/api/shared-w1"] {
        let ev = shared_events
            .iter()
            .find(|e| e.path == path)
            .ok_or_else(|| format!("missing event for {path}"))?;
        assert_eq!(ev.slot, ProxyClientSlot::Shared);
        assert_eq!(ev.worker_pool_count, 0);
    }

    conn_w0.close().await;
    conn_w1.close().await;
    let report = server.shutdown_with_report().await;
    assert!(report.is_clean(), "expected clean shutdown, got {report:?}");
    assert_eq!(wait_for_zero_worker_loop_threads().await?, 0);
    Ok(())
}

/// RFC 6455 WebSocket upgrade through a worker loop uses that worker's dedicated upgrade client
/// (`WorkerUpgrade(idx)`) and tunnels bidirectional traffic cleanly.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn workers_websocket_upgrade_uses_worker_upgrade_pool_and_tunnels() -> TestResult {
    let _serial = pool_test_lock().lock().await;
    let events: Arc<Mutex<Vec<ProxyPoolEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let events_cb = Arc::clone(&events);
    let _observer = test_proxy_pool_observer_guard(move |ev| {
        events_cb
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(ev);
    });

    // Local RFC 6455 echo upstream using hyper HTTP/1.1 upgrades.
    let ws_listener = TcpListener::bind("127.0.0.1:0").await?;
    let ws_addr = ws_listener.local_addr()?;
    let ws_upstream_task = tokio::spawn(async move {
        if let Ok((stream, _)) = ws_listener.accept().await {
            let service =
                hyper::service::service_fn(|mut req: Request<hyper::body::Incoming>| async move {
                    let on_upgrade = hyper::upgrade::on(&mut req);
                    tokio::spawn(async move {
                        if let Ok(upgraded) = on_upgrade.await {
                            let mut io = TokioIo::new(upgraded);
                            let mut buf = [0_u8; 64];
                            if let Ok(n) = io.read(&mut buf).await
                                && let Some(slice) = buf.get(..n)
                            {
                                let _ = io.write_all(slice).await;
                                let _ = io.flush().await;
                            }
                        }
                    });
                    Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(StatusCode::SWITCHING_PROTOCOLS)
                            .header(http::header::CONNECTION, "upgrade")
                            .header(http::header::UPGRADE, "websocket")
                            .header("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
                            .body(Empty::<Bytes>::new())
                            .unwrap_or_else(|_| http::Response::new(Empty::<Bytes>::new())),
                    )
                });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades()
                .await;
        }
    });

    let (server, _) = start_server_with_kdl("ws-workers.kdl", |listen_addr| {
        format!(
            r#"
server {{
    listen "{listen_addr}" protocols="h2,h1"
    workers 2
}}
site "ws.workers.test" {{
    route "/ws" {{
        reverse-proxy {{
            upstream "http://{ws_addr}"
        }}
    }}
}}
"#
        )
    })
    .await?;
    assert_eq!(count_worker_loop_threads()?, 2);

    let https_addr = https_listener_addr(&server)?;
    let tls_cfg = build_h1_tls_client(&server)?;

    let tcp = TcpStream::connect(https_addr).await?;
    let tls = TlsConnector::from(tls_cfg)
        .connect(ServerName::try_from("ws.workers.test")?, tcp)
        .await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
    let conn_task = tokio::spawn(conn.with_upgrades());

    let mut resp = sender
        .send_request(
            Request::builder()
                .uri("/ws")
                .header(HOST, "ws.workers.test")
                .header(http::header::CONNECTION, "Upgrade")
                .header(http::header::UPGRADE, "websocket")
                .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
                .header("sec-websocket-version", "13")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);

    let upgraded = hyper::upgrade::on(&mut resp).await?;
    let mut io = TokioIo::new(upgraded);
    let msg = b"hello-worker-ws-pool";
    io.write_all(msg).await?;
    io.flush().await?;
    let mut echoed = vec![0_u8; msg.len()];
    io.read_exact(&mut echoed).await?;
    assert_eq!(echoed.as_slice(), msg);
    drop(io);
    drop(sender);
    let _ = conn_task.await;

    let recorded = events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let ws_ev = recorded
        .iter()
        .find(|e| e.path == "/ws" && !e.is_health_probe)
        .ok_or("missing /ws upgrade pool event")?;
    let idx = ws_ev
        .worker_index
        .ok_or("expected /ws request to execute on a worker loop")?;
    assert!(idx < 2);
    assert_eq!(ws_ev.slot, ProxyClientSlot::WorkerUpgrade(idx));
    assert_eq!(ws_ev.worker_pool_count, 2);

    let report = server.shutdown_with_report().await;
    assert!(report.is_clean(), "expected clean shutdown, got {report:?}");
    assert_eq!(wait_for_zero_worker_loop_threads().await?, 0);
    let _ = ws_upstream_task.await;
    Ok(())
}

/// Active health-check probes ALWAYS use the shared client (both default and `preserve-host`
/// routes) with `worker_index == None`, never a worker loop's pool.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn workers_health_check_probes_use_shared_client() -> TestResult {
    let _serial = pool_test_lock().lock().await;
    let events: Arc<Mutex<Vec<ProxyPoolEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let probe_notify = Arc::new(Notify::new());
    let events_cb = Arc::clone(&events);
    let notify_cb = Arc::clone(&probe_notify);
    let _observer = test_proxy_pool_observer_guard(move |ev| {
        let is_probe = ev.is_health_probe;
        events_cb
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(ev);
        if is_probe {
            notify_cb.notify_waiters();
        }
    });

    let upstream = TestUpstream::start().await?;
    let up_addr = upstream.addr;
    let (server, _) = start_server_with_kdl("hc-workers.kdl", |listen_addr| {
        format!(
            r#"
server {{
    listen "{listen_addr}" protocols="h2,h1"
    workers 2
}}
site "hc.workers.test" {{
    route "/api/*" {{
        reverse-proxy {{
            upstream "http://{up_addr}"
            health-check path="/healthz" interval="1s" timeout="500ms"
        }}
    }}
    route "/ph/*" {{
        reverse-proxy {{
            upstream "http://{up_addr}"
            preserve-host #true
            health-check path="/healthz-ph" host="hc.workers.test" interval="1s" timeout="500ms"
        }}
    }}
}}
"#
        )
    })
    .await?;
    assert_eq!(count_worker_loop_threads()?, 2);

    // Wait until both health checkers have completed at least one probe.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let (has_std, has_ph) = {
            let guard = events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (
                guard
                    .iter()
                    .any(|e| e.is_health_probe && e.path == "/healthz"),
                guard
                    .iter()
                    .any(|e| e.is_health_probe && e.path == "/healthz-ph"),
            )
        };
        if has_std && has_ph {
            break;
        }
        assert!(
            tokio::time::timeout_at(deadline, probe_notify.notified())
                .await
                .is_ok(),
            "timed out waiting for active health-check probes"
        );
    }

    // Send real proxied traffic on both routes to verify workers use their own pools distinct from
    // the shared health-probe connections.
    let https_addr = https_listener_addr(&server)?;
    let tls_cfg = build_h1_tls_client(&server)?;
    let mut cli = H1ClientConn::connect(https_addr, "hc.workers.test", &tls_cfg).await?;
    let _ = cli.get_conn_id("hc.workers.test", "/api/real").await?;
    let _ = cli.get_conn_id("hc.workers.test", "/ph/real").await?;
    cli.close().await;

    let recorded = events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();

    let std_probes: Vec<&ProxyPoolEvent> = recorded
        .iter()
        .filter(|e| e.is_health_probe && e.path == "/healthz")
        .collect();
    let ph_probes: Vec<&ProxyPoolEvent> = recorded
        .iter()
        .filter(|e| e.is_health_probe && e.path == "/healthz-ph")
        .collect();
    assert_ne!(std_probes.len(), 0);
    assert_ne!(ph_probes.len(), 0);
    for p in &std_probes {
        assert_eq!(p.slot, ProxyClientSlot::Shared);
        assert_eq!(p.worker_index, None);
        assert_eq!(p.worker_pool_count, 2);
    }
    for p in &ph_probes {
        assert_eq!(p.slot, ProxyClientSlot::SharedUpgrade);
        assert_eq!(p.worker_index, None);
        assert_eq!(p.worker_pool_count, 2);
    }

    let probe_addrs: HashSet<SocketAddr> = std_probes
        .iter()
        .chain(ph_probes.iter())
        .filter_map(|p| p.local_addr)
        .collect();

    let api_ev = recorded
        .iter()
        .find(|e| !e.is_health_probe && e.path == "/api/real")
        .ok_or("missing /api/real event")?;
    let api_idx = api_ev.worker_index.ok_or("expected worker index")?;
    assert_eq!(api_ev.slot, ProxyClientSlot::Worker(api_idx));
    assert!(
        api_ev.local_addr.is_some_and(|a| !probe_addrs.contains(&a)),
        "worker request must not reuse a health-probe connection from the shared client"
    );

    let ph_ev = recorded
        .iter()
        .find(|e| !e.is_health_probe && e.path == "/ph/real")
        .ok_or("missing /ph/real event")?;
    let ph_idx = ph_ev.worker_index.ok_or("expected worker index")?;
    assert_eq!(ph_ev.slot, ProxyClientSlot::WorkerUpgrade(ph_idx));
    assert!(
        ph_ev.local_addr.is_some_and(|a| !probe_addrs.contains(&a)),
        "preserve-host worker request must not reuse a health-probe connection from the shared client"
    );

    let report = server.shutdown_with_report().await;
    assert!(report.is_clean(), "expected clean shutdown, got {report:?}");
    assert_eq!(wait_for_zero_worker_loop_threads().await?, 0);
    Ok(())
}

/// Graceful shutdown with idle keep-alive pooled upstream connections held on BOTH workers joins
/// every worker thread cleanly and closes both idle upstream connections.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workers_graceful_shutdown_closes_idle_pooled_connections_on_both_workers() -> TestResult {
    let _serial = pool_test_lock().lock().await;
    let events: Arc<Mutex<Vec<ProxyPoolEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let events_cb = Arc::clone(&events);
    let _observer = test_proxy_pool_observer_guard(move |ev| {
        events_cb
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(ev);
    });

    let upstream = TestUpstream::start().await?;
    let up_addr = upstream.addr;
    let (server, _) = start_server_with_kdl("shutdown-pools.kdl", |listen_addr| {
        format!(
            r#"
server {{
    listen "{listen_addr}" protocols="h2,h1"
    workers 2
    timeouts {{
        graceful-drain "2s"
    }}
}}
site "shutdown.workers.test" {{
    route "/api/*" {{
        reverse-proxy {{
            upstream "http://{up_addr}"
        }}
    }}
}}
"#
        )
    })
    .await?;
    assert_eq!(count_worker_loop_threads()?, 2);

    let https_addr = https_listener_addr(&server)?;
    let tls_cfg = build_h1_tls_client(&server)?;

    let (conn_w0, conn_w1, _, _) =
        open_worker_pinned_connections(https_addr, "shutdown.workers.test", &tls_cfg, &events)
            .await?;
    // Close the downstream client connections while leaving both workers' upstream keep-alive
    // connections idle in their per-worker pools.
    conn_w0.close().await;
    conn_w1.close().await;

    assert_eq!(upstream.accepted_count(), 2);
    assert_eq!(
        upstream.open_count(),
        2,
        "both workers should hold one idle keep-alive upstream connection before shutdown"
    );

    let report = tokio::time::timeout(Duration::from_secs(5), server.shutdown_with_report())
        .await
        .map_err(|_| "graceful shutdown timed out with idle per-worker pools")?;
    assert!(report.is_clean(), "expected clean shutdown, got {report:?}");
    assert_eq!(wait_for_zero_worker_loop_threads().await?, 0);
    assert!(
        upstream.wait_open_conns(0, Duration::from_secs(5)).await,
        "all idle upstream connections on both worker loops must close after graceful shutdown"
    );
    Ok(())
}

//! Live end-to-end tests for Wave 4 (HANDOVER §5 #5 & #6):
//! - Upgraded WebSocket tunnels are counted in graceful drain (kept open and exchanging data
//!   during `graceful-drain` instead of cut immediately on shutdown, exiting cleanly when closed
//!   or when `graceful-drain` elapses).
//! - Per-IP connection cap evicts the address's oldest idle keep-alive connection instead of
//!   locking that address out of sibling sites and the plaintext HTTP redirect listener, while
//!   still rejecting new connections when all slots are actively busy.

use std::fs;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::header::{CONNECTION, HOST, UPGRADE};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use miraserve_config::{ConfigStore, parse_kdl};
use miraserve_core::{ListenerKind, MiraServeServer, ServerOptions};
use miraserve_tls::build_crypto_provider;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Result<Self, std::io::Error> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path =
            std::env::temp_dir().join(format!("miraserve-w4-{tag}-{}-{nanos}", std::process::id()));
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

fn reserve_two_free_ports() -> Result<(u16, u16), std::io::Error> {
    let sock1 = StdTcpListener::bind("127.0.0.1:0")?;
    let sock2 = StdTcpListener::bind("127.0.0.1:0")?;
    Ok((sock1.local_addr()?.port(), sock2.local_addr()?.port()))
}

fn build_h1_tls_connector(cert_pem: &str) -> Result<TlsConnector, Box<dyn std::error::Error>> {
    let mut roots = RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert_pem.as_bytes()).collect::<Result<_, _>>()?;
    roots.add_parsable_certificates(certs);

    let mut client_cfg = ClientConfig::builder_with_provider(build_crypto_provider(false))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsConnector::from(Arc::new(client_cfg)))
}

async fn spawn_ws_echo_upstream() -> Result<(SocketAddr, tokio::task::AbortHandle), std::io::Error>
{
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(|mut req: Request<Incoming>| async move {
                    let on_upgrade = hyper::upgrade::on(&mut req);
                    tokio::spawn(async move {
                        if let Ok(upgraded) = on_upgrade.await {
                            let mut io = TokioIo::new(upgraded);
                            let mut buf = [0_u8; 256];
                            while let Ok(n) = io.read(&mut buf).await {
                                if n == 0 {
                                    break;
                                }
                                if let Some(slice) = buf.get(..n)
                                    && io.write_all(slice).await.is_err()
                                {
                                    break;
                                }
                            }
                        }
                    });
                    let resp = Response::builder()
                        .status(StatusCode::SWITCHING_PROTOCOLS)
                        .header(CONNECTION, "Upgrade")
                        .header(UPGRADE, "websocket")
                        .header("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
                        .body(Empty::<Bytes>::new())
                        .unwrap_or_else(|_| Response::new(Empty::<Bytes>::new()));
                    Ok::<_, std::convert::Infallible>(resp)
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .with_upgrades()
                    .await;
            });
        }
    });
    Ok((addr, task.abort_handle()))
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn websocket_upgrade_is_counted_in_graceful_drain_and_completes_cleanly() -> TestResult {
    let tmp = TempDir::new("ws-drain")?;
    fs::write(tmp.path.join("index.html"), b"ok")?;
    let root_str = tmp.path.to_string_lossy().replace('\\', "/");

    let (ws_upstream_addr, ws_abort) = spawn_ws_echo_upstream().await?;
    let tls_port = reserve_free_port()?;

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    timeouts {{
        graceful-drain "3s"
    }}
}}
site "ws.example" {{
    root "{root_str}"
    route "/ws" {{
        reverse-proxy {{
            upstream "http://{ws_upstream_addr}"
        }}
    }}
}}
"#
    );

    let (cfg, _) = parse_kdl("ws-drain.kdl", &kdl)?;
    let store = Arc::new(ConfigStore::new(cfg));
    let server = MiraServeServer::start(
        store,
        ServerOptions {
            dev_tls: true,
            ..ServerOptions::default()
        },
    )
    .await?;
    let cert_pem = server
        .dev_cert_pem()
        .ok_or("expected dev TLS cert")?
        .to_owned();
    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|l| l.kind == ListenerKind::HttpsTcp)
        .map(|l| l.local_addr)
        .ok_or("expected HTTPS listener")?;

    let connector = build_h1_tls_connector(&cert_pem)?;
    let tcp = TcpStream::connect(https_addr).await?;
    let tls = connector
        .connect(ServerName::try_from("ws.example".to_owned())?, tcp)
        .await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });

    let ws_req = Request::builder()
        .uri("/ws")
        .header(HOST, "ws.example")
        .header(CONNECTION, "Upgrade")
        .header(UPGRADE, "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .body(Empty::<Bytes>::new())?;
    let mut ws_resp = sender.send_request(ws_req).await?;
    assert_eq!(ws_resp.status(), StatusCode::SWITCHING_PROTOCOLS);

    let upgraded = hyper::upgrade::on(&mut ws_resp).await?;
    let mut ws_io = TokioIo::new(upgraded);

    // Exchange one message before shutdown.
    ws_io.write_all(b"before-drain").await?;
    let mut buf = [0_u8; 32];
    let n = ws_io.read(&mut buf).await?;
    assert_eq!(buf.get(..n), Some(b"before-drain".as_slice()));

    // Trigger graceful server shutdown in the background while the WebSocket is still open!
    let shutdown_started = Instant::now();
    let mut shutdown_handle = tokio::spawn(async move {
        server.shutdown().await;
    });

    // Wait 250ms: shutdown MUST still be draining (NOT finished!) and the WebSocket MUST still
    // stay open and echo data cleanly!
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(
        !shutdown_handle.is_finished(),
        "shutdown must NOT cut active upgraded WebSocket immediately before graceful-drain"
    );

    ws_io.write_all(b"during-drain").await?;
    let n2 = tokio::time::timeout(Duration::from_secs(1), ws_io.read(&mut buf)).await??;
    assert_eq!(buf.get(..n2), Some(b"during-drain".as_slice()));

    // Closing the WebSocket cleanly lets graceful shutdown finish immediately (well before 3s!).
    let close_started = Instant::now();
    ws_io.shutdown().await?;
    drop(ws_io);
    drop(sender);
    tokio::time::timeout(Duration::from_secs(1), &mut shutdown_handle).await??;
    assert!(
        close_started.elapsed() < Duration::from_secs(1),
        "shutdown should finish right after the last upgraded WebSocket closes"
    );
    assert!(
        shutdown_started.elapsed() >= Duration::from_millis(240),
        "shutdown must have waited for the open WebSocket"
    );

    // Second check: an unclosed WebSocket is cleanly force-closed once graceful-drain expires
    // (never hanging server shutdown indefinitely).
    let tls_port2 = reserve_free_port()?;
    let kdl2 = format!(
        r#"
server {{
    listen "127.0.0.1:{tls_port2}" protocols="h1"
    timeouts {{
        graceful-drain "250ms"
    }}
}}
site "ws.example" {{
    root "{root_str}"
    route "/ws" {{
        reverse-proxy {{
            upstream "http://{ws_upstream_addr}"
        }}
    }}
}}
"#
    );
    let (cfg2, _) = parse_kdl("ws-drain-timeout.kdl", &kdl2)?;
    let server2 = MiraServeServer::start(
        Arc::new(ConfigStore::new(cfg2)),
        ServerOptions {
            dev_tls: true,
            ..ServerOptions::default()
        },
    )
    .await?;
    let cert_pem2 = server2
        .dev_cert_pem()
        .ok_or("expected dev TLS cert 2")?
        .to_owned();
    let https_addr2 = server2
        .bound_listeners()
        .iter()
        .find(|l| l.kind == ListenerKind::HttpsTcp)
        .map(|l| l.local_addr)
        .ok_or("expected HTTPS listener 2")?;
    let connector2 = build_h1_tls_connector(&cert_pem2)?;
    let tcp2 = TcpStream::connect(https_addr2).await?;
    let tls2 = connector2
        .connect(ServerName::try_from("ws.example".to_owned())?, tcp2)
        .await?;
    let (mut sender2, conn2) = hyper::client::conn::http1::handshake(TokioIo::new(tls2)).await?;
    tokio::spawn(async move {
        let _ = conn2.with_upgrades().await;
    });
    let ws_req2 = Request::builder()
        .uri("/ws")
        .header(HOST, "ws.example")
        .header(CONNECTION, "Upgrade")
        .header(UPGRADE, "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .body(Empty::<Bytes>::new())?;
    let mut ws_resp2 = sender2.send_request(ws_req2).await?;
    assert_eq!(ws_resp2.status(), StatusCode::SWITCHING_PROTOCOLS);
    let _ws_io2 = TokioIo::new(hyper::upgrade::on(&mut ws_resp2).await?);

    let t0 = Instant::now();
    tokio::time::timeout(Duration::from_secs(2), server2.shutdown()).await?;
    assert!(
        t0.elapsed() >= Duration::from_millis(200) && t0.elapsed() < Duration::from_secs(1),
        "shutdown must wait ~graceful-drain (250ms) and then force-close open WebSockets cleanly, elapsed={:?}",
        t0.elapsed()
    );

    ws_abort.abort();
    Ok(())
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn per_ip_cap_evicts_oldest_idle_keepalive_across_sites_and_redirect_listener() -> TestResult
{
    let tmp_a = TempDir::new("site-a")?;
    let tmp_b = TempDir::new("site-b")?;
    fs::write(tmp_a.path.join("index.html"), b"site-a-ok")?;
    fs::write(tmp_b.path.join("index.html"), b"site-b-ok")?;
    let root_a = tmp_a.path.to_string_lossy().replace('\\', "/");
    let root_b = tmp_b.path.to_string_lossy().replace('\\', "/");

    let (tls_port, http_port) = reserve_two_free_ports()?;

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    listen "127.0.0.1:{http_port}" redirect-https=true
    limits {{
        max-connections-per-ip 4
    }}
    timeouts {{
        header-read "3s"
        idle-keepalive "60s"
        graceful-drain "1s"
    }}
}}
site "a.example" {{
    root "{root_a}"
}}
site "b.example" {{
    root "{root_b}"
}}
"#
    );

    let (cfg, _) = parse_kdl("idle-evict.kdl", &kdl)?;
    let server = MiraServeServer::start(
        Arc::new(ConfigStore::new(cfg)),
        ServerOptions {
            dev_tls: true,
            ..ServerOptions::default()
        },
    )
    .await?;
    let cert_pem = server
        .dev_cert_pem()
        .ok_or("expected dev TLS cert")?
        .to_owned();
    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|l| l.kind == ListenerKind::HttpsTcp)
        .map(|l| l.local_addr)
        .ok_or("expected HTTPS listener")?;
    let redirect_addr = server
        .bound_listeners()
        .iter()
        .find(|l| l.kind == ListenerKind::HttpRedirect)
        .map(|l| l.local_addr)
        .ok_or("expected HTTP redirect listener")?;

    let connector = build_h1_tls_connector(&cert_pem)?;

    // 1. Open 4 persistent TLS HTTP/1.1 keep-alive connections to a.example (filling the cap of 4),
    //    complete 1 request on each so they all sit idle keep-alive.
    let mut idle_senders = Vec::new();
    let mut idle_conn_tasks = Vec::new();
    for _ in 0..4 {
        let tcp = TcpStream::connect(https_addr).await?;
        let tls = connector
            .connect(ServerName::try_from("a.example".to_owned())?, tcp)
            .await?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
        let task = tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = Request::builder()
            .uri("/")
            .header(HOST, "a.example")
            .body(Empty::<Bytes>::new())?;
        let resp = sender.send_request(req).await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await?.to_bytes();
        assert_eq!(body.as_ref(), b"site-a-ok");
        idle_senders.push(sender);
        idle_conn_tasks.push(task);
        tokio::time::sleep(Duration::from_millis(15)).await;
    }

    // 2. A 5th connection from the SAME IP to sibling site b.example MUST succeed by evicting
    //    the oldest idle keep-alive (connection #0)!
    let site_b_stream = TcpStream::connect(https_addr).await?;
    let tls_b = connector
        .connect(ServerName::try_from("b.example".to_owned())?, site_b_stream)
        .await?;
    let (mut sender_b, conn_b) = hyper::client::conn::http1::handshake(TokioIo::new(tls_b)).await?;
    let task_b = tokio::spawn(async move {
        let _ = conn_b.await;
    });
    let req_b = Request::builder()
        .uri("/")
        .header(HOST, "b.example")
        .body(Empty::<Bytes>::new())?;
    let resp_b = sender_b.send_request(req_b).await?;
    assert_eq!(resp_b.status(), StatusCode::OK);
    let body_b = resp_b.into_body().collect().await?.to_bytes();
    assert_eq!(body_b.as_ref(), b"site-b-ok");

    // Verify oldest idle connection #0 was cleanly closed by eviction!
    let oldest_task = idle_conn_tasks.remove(0);
    tokio::time::timeout(Duration::from_secs(1), oldest_task).await??;

    // 3. A 6th connection from the SAME IP to the plaintext HTTP redirect listener (port 80)
    //    MUST also succeed instead of being locked out by idle HTTPS keep-alives!
    let tcp_http = TcpStream::connect(redirect_addr).await?;
    let (mut sender_http, conn_http) =
        hyper::client::conn::http1::handshake(TokioIo::new(tcp_http)).await?;
    tokio::spawn(async move {
        let _ = conn_http.await;
    });
    let req_http = Request::builder()
        .uri("/hello")
        .header(HOST, "a.example")
        .body(Empty::<Bytes>::new())?;
    let resp_http = sender_http.send_request(req_http).await?;
    assert!(
        resp_http.status().is_redirection(),
        "expected HTTP->HTTPS redirect, got {}",
        resp_http.status()
    );

    // Clean up idle connections before testing active (non-idle) cap enforcement.
    drop(idle_senders);
    drop(sender_b);
    drop(sender_http);
    let _ = task_b.await;
    for t in idle_conn_tasks {
        let _ = t.await;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 4. Open 4 ACTIVE (silent pre-request) TCP connections that never complete a request:
    //    none are idle keep-alives, so a 5th connection MUST be rejected by the per-IP cap!
    let mut active_raw = Vec::new();
    for _ in 0..4 {
        active_raw.push(TcpStream::connect(redirect_addr).await?);
    }
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut fifth = TcpStream::connect(redirect_addr).await?;
    let _ = fifth
        .write_all(b"GET / HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n")
        .await;
    let mut probe = [0_u8; 64];
    let read_res = tokio::time::timeout(Duration::from_millis(500), fifth.read(&mut probe)).await?;
    let closed_without_response = match read_res {
        Ok(0) | Err(_) => true,
        Ok(_) => false,
    };
    assert!(
        closed_without_response,
        "5th connection must be rejected when all 4 per-IP slots are active (non-idle)"
    );

    drop(active_raw);
    server.shutdown().await;
    Ok(())
}

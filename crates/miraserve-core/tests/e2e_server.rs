//! Full-stack Milestone 1 end-to-end server tests:
//! - Live HTTPS over HTTP/1.1 & HTTP/2 with TLS 1.3 + `X25519MLKEM768` PQC
//! - Live HTTP/3 over QUIC (`quinn` + `h3`) with TLS 1.3 + `X25519MLKEM768` PQC
//! - `cap-std` static serving & dotfile denial
//! - Reverse proxy forwarding
//! - Plaintext HTTP -> HTTPS `308` redirect + ACME HTTP-01 passthrough
//! - Live atomic hot reload + fail-safe invalid reload + graceful drain

use std::fs;
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::{Buf as _, Bytes};
use http::header::{HOST, LOCATION};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt as _, Empty, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use miraserve_config::{Config, ConfigStore, parse_kdl};
use miraserve_core::{CoreError, ListenerKind, MiraServeServer, RunningServer, ServerOptions};
use miraserve_tls::build_crypto_provider;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, NamedGroup, ProtocolVersion, RootCertStore};
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
        let path = std::env::temp_dir().join(format!(
            "miraserve-e2e-{tag}-{}-{nanos}",
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

/// Reserves an ephemeral loopback port that is simultaneously free on BOTH TCP and UDP
/// (for tests binding HTTPS/TCP + HTTP/3/QUIC/UDP on the same port number).
fn reserve_free_port() -> Result<u16, std::io::Error> {
    for _ in 0..64 {
        let tcp = StdTcpListener::bind("127.0.0.1:0")?;
        let port = tcp.local_addr()?.port();
        if StdUdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return Ok(port);
        }
    }
    Err(std::io::Error::new(
        ErrorKind::AddrInUse,
        "failed to reserve a port free on both 127.0.0.1 TCP and UDP",
    ))
}

/// Reserves two distinct ephemeral loopback ports, each simultaneously free on BOTH TCP and UDP,
/// holding the first port's probe sockets open while probing the second so the OS can never hand
/// out the same port twice (eliminating duplicate-listener `E102` collisions before bind).
fn reserve_two_free_ports() -> Result<(u16, u16), std::io::Error> {
    for _ in 0..64 {
        let tcp1 = StdTcpListener::bind("127.0.0.1:0")?;
        let port1 = tcp1.local_addr()?.port();
        let Ok(udp1) = StdUdpSocket::bind(("127.0.0.1", port1)) else {
            continue;
        };
        for _ in 0..64 {
            let tcp2 = StdTcpListener::bind("127.0.0.1:0")?;
            let port2 = tcp2.local_addr()?.port();
            if port2 == port1 {
                continue;
            }
            if let Ok(_udp2) = StdUdpSocket::bind(("127.0.0.1", port2)) {
                drop((udp1, tcp1));
                return Ok((port1, port2));
            }
        }
    }
    Err(std::io::Error::new(
        ErrorKind::AddrInUse,
        "failed to reserve two distinct 127.0.0.1 TCP+UDP ports",
    ))
}

/// Starts a `MiraServeServer` with freshly reserved port(s), retrying the full reservation+config+bind
/// fixture on `AddrInUse` (or transient duplicate-listener config collision) to eliminate races
/// under heavy parallel test execution.
async fn start_server_with_ports<P, R, F>(
    mut reserve: R,
    mut make_cfg: F,
) -> Result<(RunningServer, P), Box<dyn std::error::Error>>
where
    R: FnMut() -> Result<P, std::io::Error>,
    F: FnMut(&P) -> Result<Config, Box<dyn std::error::Error>>,
{
    let mut last_err: Option<Box<dyn std::error::Error>> = None;
    for _ in 0..16 {
        let ports = reserve()?;
        let cfg = match make_cfg(&ports) {
            Ok(cfg) => cfg,
            Err(err)
                if err
                    .downcast_ref::<miraserve_config::ConfigError>()
                    .is_some_and(|ce| ce.validation_errors().iter().any(|e| e.code == "E102")) =>
            {
                last_err = Some(err);
                continue;
            }
            Err(err) => return Err(err),
        };
        match MiraServeServer::start(
            Arc::new(ConfigStore::new(cfg)),
            ServerOptions {
                dev_tls: true,
                ..ServerOptions::default()
            },
        )
        .await
        {
            Ok(server) => return Ok((server, ports)),
            Err(CoreError::Bind { source, addr }) if source.kind() == ErrorKind::AddrInUse => {
                last_err = Some(CoreError::Bind { addr, source }.into());
            }
            Err(err) => return Err(err.into()),
        }
    }
    Err(last_err.unwrap_or_else(|| "exhausted bind retries".into()))
}

async fn spawn_upstream_api() -> Result<(SocketAddr, tokio::task::AbortHandle), std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let proto = req
                        .headers()
                        .get("x-forwarded-proto")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    let body = format!("api-ok:{}:{proto}", req.uri().path());
                    Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(body))))
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    Ok((addr, task.abort_handle()))
}

fn build_roots(cert_pem: &str) -> Result<RootCertStore, Box<dyn std::error::Error>> {
    let mut roots = RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert_pem.as_bytes()).collect::<Result<_, _>>()?;
    let (added, _) = roots.add_parsable_certificates(certs);
    assert_eq!(added, 1);
    Ok(roots)
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn full_stack_pqc_h1_h2_h3_static_proxy_redirect_and_hot_reload() -> TestResult {
    let tmp_v1 = TempDir::new("v1")?;
    let tmp_v2 = TempDir::new("v2")?;
    fs::write(tmp_v1.path.join("index.html"), b"<h1>MiraServe V1</h1>")?;
    fs::write(tmp_v1.path.join(".env"), b"DB_PASS=secret")?;
    fs::write(
        tmp_v2.path.join("index.html"),
        b"<h1>MiraServe V2 Reloaded</h1>",
    )?;

    let (api_addr, api_abort) = spawn_upstream_api().await?;
    let root_v1_str = tmp_v1.path.to_string_lossy().replace('\\', "/");
    let root_v2_str = tmp_v2.path.to_string_lossy().replace('\\', "/");

    let make_kdl_v1 = |tls_port: u16, redirect_port: u16| {
        format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h3,h2,h1"
    listen "127.0.0.1:{redirect_port}" redirect-https=true
    tls {{
        min-version "1.3"
        pqc-hybrid true
    }}
}}
site "app.example.test" {{
    security-headers "strict"
    root "{root_v1_str}"
    route "/api/*" {{
        reverse-proxy {{
            upstream "http://{api_addr}"
            streaming-flush "immediate"
        }}
    }}
}}
"#
        )
    };

    let (server, (tls_port, redirect_port)) =
        start_server_with_ports(reserve_two_free_ports, |&(tls_port, redirect_port)| {
            let kdl_v1 = make_kdl_v1(tls_port, redirect_port);
            let (cfg, report) = parse_kdl("e2e-v1.kdl", &kdl_v1)?;
            assert!(
                report.warnings.iter().all(|w| w.code == "W015"),
                "unexpected warnings: {:?}",
                report.warnings
            );
            Ok(cfg)
        })
        .await?;
    let kdl_v1 = make_kdl_v1(tls_port, redirect_port);

    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::HttpsTcp)
        .ok_or("missing HttpsTcp listener")?
        .local_addr;
    let h3_addr = server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::Http3Udp)
        .ok_or("missing Http3Udp listener")?
        .local_addr;
    let redirect_addr = server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::HttpRedirect)
        .ok_or("missing HttpRedirect listener")?
        .local_addr;

    let dev_pem = server.dev_cert_pem().ok_or("expected dev cert PEM")?;
    let roots = build_roots(dev_pem)?;

    // --- 1. HTTPS + HTTP/1.1 + PQC X25519MLKEM768 + Static + Security Headers + Dotfile Deny ---
    let mut h1_tls_cfg = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    h1_tls_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];

    let tcp = TcpStream::connect(https_addr).await?;
    let tls_stream = TlsConnector::from(Arc::new(h1_tls_cfg))
        .connect(ServerName::try_from("app.example.test")?, tcp)
        .await?;
    assert_eq!(
        tls_stream.get_ref().1.protocol_version(),
        Some(ProtocolVersion::TLSv1_3)
    );
    assert_eq!(
        tls_stream
            .get_ref()
            .1
            .negotiated_key_exchange_group()
            .map(rustls::crypto::SupportedKxGroup::name),
        Some(NamedGroup::X25519MLKEM768)
    );

    let (mut h1_sender, h1_conn) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_stream)).await?;
    let h1_task = tokio::spawn(async move {
        let _ = h1_conn.await;
    });

    let req = Request::builder()
        .uri("/index.html")
        .header(HOST, "app.example.test")
        .body(Empty::<Bytes>::new())?;
    let resp = h1_sender.send_request(req).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().contains_key("strict-transport-security"));
    assert_eq!(
        resp.headers()
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        resp.headers().get("alt-svc").and_then(|v| v.to_str().ok()),
        Some(format!("h3=\":{}\"; ma=86400", h3_addr.port()).as_str())
    );
    let body = resp.into_body().collect().await?.to_bytes();
    assert_eq!(body.as_ref(), b"<h1>MiraServe V1</h1>");

    // Dotfile blocked over HTTPS
    let dot_req = Request::builder()
        .uri("/.env")
        .header(HOST, "app.example.test")
        .body(Empty::<Bytes>::new())?;
    let dot_resp = h1_sender.send_request(dot_req).await?;
    assert_eq!(dot_resp.status(), StatusCode::NOT_FOUND);

    // TLS SNI vs mismatched HTTP Host header MUST fail closed with 421 Misdirected Request!
    let mismatch_req = Request::builder()
        .uri("/index.html")
        .header(HOST, "other.example.test")
        .body(Empty::<Bytes>::new())?;
    let mismatch_resp = h1_sender.send_request(mismatch_req).await?;
    assert_eq!(mismatch_resp.status(), StatusCode::MISDIRECTED_REQUEST);
    h1_task.abort();

    // --- 2. HTTPS + HTTP/2 + Reverse Proxy ---
    let mut h2_tls_cfg = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    h2_tls_cfg.alpn_protocols = vec![b"h2".to_vec()];

    let tcp2 = TcpStream::connect(https_addr).await?;
    let tls_stream2 = TlsConnector::from(Arc::new(h2_tls_cfg))
        .connect(ServerName::try_from("app.example.test")?, tcp2)
        .await?;
    assert_eq!(
        tls_stream2.get_ref().1.alpn_protocol(),
        Some(b"h2".as_slice())
    );

    let (mut h2_sender, h2_conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls_stream2))
            .await?;
    let h2_task = tokio::spawn(async move {
        let _ = h2_conn.await;
    });

    let api_req = Request::builder()
        .uri("https://app.example.test/api/hello")
        .body(Empty::<Bytes>::new())?;
    let api_resp = h2_sender.send_request(api_req).await?;
    assert_eq!(api_resp.status(), StatusCode::OK);
    assert_eq!(
        api_resp
            .headers()
            .get("x-accel-buffering")
            .and_then(|v| v.to_str().ok()),
        Some("no")
    );
    let api_body = api_resp.into_body().collect().await?.to_bytes();
    assert_eq!(api_body.as_ref(), b"api-ok:/api/hello:https");
    h2_task.abort();

    // --- 3. Live HTTP/3 over QUIC (UDP) + PQC TLS 1.3 ---
    let mut h3_tls_cfg = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    h3_tls_cfg.alpn_protocols = vec![b"h3".to_vec()];

    let quic_client_cfg =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(h3_tls_cfg)?));
    let mut quic_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    quic_endpoint.set_default_client_config(quic_client_cfg);

    let quic_conn = quic_endpoint.connect(h3_addr, "app.example.test")?.await?;
    let (mut h3_driver, mut h3_send) =
        h3::client::new(h3_quinn::Connection::new(quic_conn)).await?;
    let h3_driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| h3_driver.poll_close(cx)).await;
    });

    let h3_req = Request::builder()
        .uri("https://app.example.test/index.html")
        .body(())?;
    let mut h3_stream = h3_send.send_request(h3_req).await?;
    h3_stream.finish().await?;
    let h3_resp = h3_stream.recv_response().await?;
    assert_eq!(h3_resp.status(), StatusCode::OK);
    assert!(h3_resp.headers().contains_key("strict-transport-security"));
    let mut h3_bytes = Vec::new();
    while let Some(mut chunk) = h3_stream.recv_data().await? {
        while chunk.has_remaining() {
            let s = chunk.chunk();
            h3_bytes.extend_from_slice(s);
            let n = s.len();
            chunk.advance(n);
        }
    }
    assert_eq!(h3_bytes.as_slice(), b"<h1>MiraServe V1</h1>");
    h3_driver_task.abort();
    quic_endpoint.close(0_u32.into(), b"done");

    // --- 4. Plaintext HTTP -> HTTPS 308 Redirect + ACME HTTP-01 Passthrough ---
    let redir_tcp = TcpStream::connect(redirect_addr).await?;
    let (mut redir_sender, redir_conn) =
        hyper::client::conn::http1::handshake(TokioIo::new(redir_tcp)).await?;
    let redir_task = tokio::spawn(async move {
        let _ = redir_conn.await;
    });

    let r_req = Request::builder()
        .uri("/docs?q=1")
        .header(HOST, "app.example.test")
        .body(Empty::<Bytes>::new())?;
    let r_resp = redir_sender.send_request(r_req).await?;
    assert_eq!(r_resp.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(
        r_resp.headers().get(LOCATION).and_then(|v| v.to_str().ok()),
        Some(format!("https://app.example.test:{tls_port}/docs?q=1").as_str())
    );

    // Unknown Host on redirect listener must NOT produce an open redirect (421 Misdirected Request)
    let evil_redir = redir_sender
        .send_request(
            Request::builder()
                .uri("/phish")
                .header(HOST, "evil.attacker.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(evil_redir.status(), StatusCode::MISDIRECTED_REQUEST);

    server.acme_store().set_http01_token(
        "app.example.test",
        "challenge-tok-99",
        "challenge-tok-99.keythumb".to_owned(),
    );
    // ACME HTTP-01 token is strictly scoped to its domain (wrong Host must NOT serve token;
    // unconfigured Host fails closed with 421 Misdirected Request).
    let wrong_host_acme = redir_sender
        .send_request(
            Request::builder()
                .uri("/.well-known/acme-challenge/challenge-tok-99")
                .header(HOST, "other.example.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(wrong_host_acme.status(), StatusCode::MISDIRECTED_REQUEST);

    // ACME HTTP-01 only allows GET/HEAD (POST -> 405 Method Not Allowed).
    let post_acme = redir_sender
        .send_request(
            Request::builder()
                .method(http::Method::POST)
                .uri("/.well-known/acme-challenge/challenge-tok-99")
                .header(HOST, "app.example.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(post_acme.status(), StatusCode::METHOD_NOT_ALLOWED);

    let acme_req = Request::builder()
        .uri("/.well-known/acme-challenge/challenge-tok-99")
        .header(HOST, "app.example.test")
        .body(Empty::<Bytes>::new())?;
    let acme_resp = redir_sender.send_request(acme_req).await?;
    assert_eq!(acme_resp.status(), StatusCode::OK);
    assert_eq!(
        acme_resp.into_body().collect().await?.to_bytes().as_ref(),
        b"challenge-tok-99.keythumb"
    );
    redir_task.abort();

    // --- 5. Live Atomic Hot Reload (V1 -> V2) + Fail-Safe Invalid Reload ---
    let kdl_v2 = kdl_v1.replace(&root_v1_str, &root_v2_str);
    let new_gen = server.reload_from_str("e2e-v2.kdl", &kdl_v2)?;
    assert_eq!(new_gen, 2);

    // Invalid reload must fail without affecting V2 live serving.
    assert!(
        server
            .reload_from_str(
                "bad.kdl",
                "server { listen \":443\"; tls { min-version \"1.0\" } }"
            )
            .is_err()
    );

    // Fetch updated V2 static file over fresh HTTPS connection (keeping our trust store via manual cert? Note: dev_tls regenerated cert on reload -> verify via updated cert from server! Wait: let's check!)
    // Actually `dev_tls` regenerates cert only if no static cert was provided — wait: let's keep existing dev cert across reloads when dev_tls is true so clients don't see cert churn!
    let mut h1_after_cfg = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    h1_after_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];

    let tcp_after = TcpStream::connect(https_addr).await?;
    let tls_after = TlsConnector::from(Arc::new(h1_after_cfg))
        .connect(ServerName::try_from("app.example.test")?, tcp_after)
        .await?;
    let (mut sender_after, conn_after) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_after)).await?;
    let after_task = tokio::spawn(async move {
        let _ = conn_after.await;
    });

    let req_v2 = Request::builder()
        .uri("/index.html")
        .header(HOST, "app.example.test")
        .body(Empty::<Bytes>::new())?;
    let resp_v2 = sender_after.send_request(req_v2).await?;
    assert_eq!(resp_v2.status(), StatusCode::OK);
    assert_eq!(
        resp_v2.into_body().collect().await?.to_bytes().as_ref(),
        b"<h1>MiraServe V2 Reloaded</h1>"
    );
    after_task.abort();

    // --- 6. Graceful Shutdown ---
    server.shutdown().await;
    api_abort.abort();
    Ok(())
}

fn host_supports_ipv6() -> bool {
    StdTcpListener::bind("[::1]:0").is_ok()
}

fn try_bind_v6_only(
    ty: socket2::Type,
    proto: socket2::Protocol,
    port: u16,
) -> Option<socket2::Socket> {
    let sock = socket2::Socket::new(socket2::Domain::IPV6, ty, Some(proto)).ok()?;
    sock.set_only_v6(true).ok()?;
    let addr = SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port));
    sock.bind(&addr.into()).ok()?;
    Some(sock)
}

fn reserve_free_dual_stack_port() -> Result<u16, std::io::Error> {
    let check_v6 = host_supports_ipv6();
    for _ in 0..64 {
        let v4_tcp = StdTcpListener::bind("0.0.0.0:0")?;
        let port = v4_tcp.local_addr()?.port();
        let v4_udp = StdUdpSocket::bind(("0.0.0.0", port)).ok();
        let v6_tcp = if check_v6 {
            try_bind_v6_only(socket2::Type::STREAM, socket2::Protocol::TCP, port)
        } else {
            None
        };
        let v6_udp = if check_v6 {
            try_bind_v6_only(socket2::Type::DGRAM, socket2::Protocol::UDP, port)
        } else {
            None
        };
        let ok = v4_udp.is_some() && (!check_v6 || (v6_tcp.is_some() && v6_udp.is_some()));
        drop((v6_udp, v6_tcp, v4_udp, v4_tcp));
        if ok {
            return Ok(port);
        }
    }
    Err(std::io::Error::new(
        ErrorKind::AddrInUse,
        "failed to reserve a dual-stack port free on IPv4/IPv6 TCP and UDP",
    ))
}

fn reserve_two_free_dual_stack_ports() -> Result<(u16, u16), std::io::Error> {
    let check_v6 = host_supports_ipv6();
    for _ in 0..64 {
        let v4_tcp1 = StdTcpListener::bind("0.0.0.0:0")?;
        let port1 = v4_tcp1.local_addr()?.port();
        let Ok(v4_udp1) = StdUdpSocket::bind(("0.0.0.0", port1)) else {
            continue;
        };
        let v6_tcp1 = if check_v6 {
            let Some(s) = try_bind_v6_only(socket2::Type::STREAM, socket2::Protocol::TCP, port1)
            else {
                continue;
            };
            Some(s)
        } else {
            None
        };
        let v6_udp1 = if check_v6 {
            let Some(s) = try_bind_v6_only(socket2::Type::DGRAM, socket2::Protocol::UDP, port1)
            else {
                continue;
            };
            Some(s)
        } else {
            None
        };

        for _ in 0..64 {
            let v4_tcp2 = StdTcpListener::bind("0.0.0.0:0")?;
            let port2 = v4_tcp2.local_addr()?.port();
            if port2 == port1 {
                continue;
            }
            let Ok(_v4_udp2) = StdUdpSocket::bind(("0.0.0.0", port2)) else {
                continue;
            };
            let v6_tcp2 = if check_v6 {
                let Some(s) =
                    try_bind_v6_only(socket2::Type::STREAM, socket2::Protocol::TCP, port2)
                else {
                    continue;
                };
                Some(s)
            } else {
                None
            };
            let v6_udp2 = if check_v6 {
                let Some(s) = try_bind_v6_only(socket2::Type::DGRAM, socket2::Protocol::UDP, port2)
                else {
                    continue;
                };
                Some(s)
            } else {
                None
            };
            drop((v6_udp2, v6_tcp2, v6_udp1, v6_tcp1, v4_udp1, v4_tcp1));
            return Ok((port1, port2));
        }
    }
    Err(std::io::Error::new(
        ErrorKind::AddrInUse,
        "failed to reserve two distinct dual-stack ports free on IPv4/IPv6 TCP and UDP",
    ))
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn dual_stack_ipv4_and_ipv6_default_and_explicit_bindings_work_over_h1_and_h3() -> TestResult
{
    let root = TempDir::new("dualstack")?;
    fs::write(root.path.join("index.html"), b"dual-stack ok")?;
    let root_str = root.path.to_string_lossy().replace('\\', "/");

    // 1. Bare `:PORT` binds dual-stack (0.0.0.0 + [::] with IPV6_V6ONLY = true) by default!
    let (server, (tls_port, redir_port)) = start_server_with_ports(
        reserve_two_free_dual_stack_ports,
        |&(tls_port, redir_port)| {
            let kdl = format!(
                r#"
server {{
    listen ":{tls_port}" protocols="h3,h2,h1"
    listen ":{redir_port}" redirect-https=#true
    tls {{
        min-version "1.3"
        pqc-hybrid #true
    }}
}}

site "dual.example.test" {{
    security-headers "strict"
    root "{root_str}"
}}
"#
            );
            let (cfg, report) = parse_kdl("dual-stack.kdl", &kdl)?;
            assert!(
                report.warnings.iter().all(|w| w.code == "W015"),
                "unexpected warnings: {:?}",
                report.warnings
            );
            Ok(cfg)
        },
    )
    .await?;
    let _ = (tls_port, redir_port);

    let bound = server.bound_listeners();
    assert!(
        bound
            .iter()
            .any(|b| b.kind == ListenerKind::HttpsTcp && b.local_addr.is_ipv4()),
        "expected IPv4 HTTPS TCP listener"
    );
    assert!(
        bound
            .iter()
            .any(|b| b.kind == ListenerKind::Http3Udp && b.local_addr.is_ipv4()),
        "expected IPv4 HTTP/3 UDP listener"
    );
    assert!(
        bound
            .iter()
            .any(|b| b.kind == ListenerKind::HttpRedirect && b.local_addr.is_ipv4()),
        "expected IPv4 HTTP redirect listener"
    );

    let ipv6_active = host_supports_ipv6();
    if ipv6_active {
        assert!(
            bound
                .iter()
                .any(|b| b.kind == ListenerKind::HttpsTcp && b.local_addr.is_ipv6()),
            "expected IPv6 HTTPS TCP listener on bare :port"
        );
        assert!(
            bound
                .iter()
                .any(|b| b.kind == ListenerKind::Http3Udp && b.local_addr.is_ipv6()),
            "expected IPv6 HTTP/3 UDP listener on bare :port"
        );
        assert!(
            bound
                .iter()
                .any(|b| b.kind == ListenerKind::HttpRedirect && b.local_addr.is_ipv6()),
            "expected IPv6 HTTP redirect listener on bare :port"
        );
    }

    let dev_pem = server.dev_cert_pem().ok_or("missing dev cert PEM")?;
    let mut roots = RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(dev_pem.as_bytes()).collect::<Result<_, _>>()?;
    let (added, _) = roots.add_parsable_certificates(certs);
    assert_eq!(added, 1);

    let mut h1_cfg = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    h1_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let h1_cfg = Arc::new(h1_cfg);

    // Verify live PQC TLS 1.3 HTTP/1.1 over BOTH IPv4 (127.0.0.1) and IPv6 ([::1])!
    let mut test_targets: Vec<SocketAddr> = vec![format!("127.0.0.1:{tls_port}").parse()?];
    if ipv6_active {
        test_targets.push(format!("[::1]:{tls_port}").parse()?);
    }
    for target in test_targets {
        let tcp = TcpStream::connect(target).await?;
        let tls = TlsConnector::from(Arc::clone(&h1_cfg))
            .connect(ServerName::try_from("dual.example.test")?, tcp)
            .await?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
        let conn_task = tokio::spawn(async move {
            let _ = conn.await;
        });
        let resp = sender
            .send_request(
                Request::builder()
                    .uri("/index.html")
                    .header(HOST, "dual.example.test")
                    .body(Empty::<Bytes>::new())?,
            )
            .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.into_body().collect().await?.to_bytes().as_ref(),
            b"dual-stack ok"
        );
        conn_task.abort();
    }

    // Verify live HTTP/3 QUIC over IPv6 ([::1]) when IPv6 is enabled!
    if ipv6_active {
        let mut h3_tls = ClientConfig::builder_with_provider(build_crypto_provider(true))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth();
        h3_tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic_cli_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(h3_tls)?;
        let mut quic_ep = quinn::Endpoint::client("[::]:0".parse()?)?;
        quic_ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_cli_crypto)));
        let v6_target: SocketAddr = format!("[::1]:{tls_port}").parse()?;
        let quinn_conn = quic_ep.connect(v6_target, "dual.example.test")?.await?;
        let (mut driver, mut send_req) =
            h3::client::new(h3_quinn::Connection::new(quinn_conn)).await?;
        let driver_task = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let mut stream = send_req
            .send_request(
                Request::builder()
                    .uri("https://dual.example.test/index.html")
                    .body(())?,
            )
            .await?;
        stream.finish().await?;
        let resp = stream.recv_response().await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await? {
            body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }
        assert_eq!(body.as_slice(), b"dual-stack ok");
        driver_task.abort();
        quic_ep.close(0_u32.into(), b"done");
    }

    server.shutdown().await;

    // 2. Explicit `0.0.0.0:P` + `[::]:P` coexist cleanly without EADDRINUSE (`IPV6_V6ONLY = true`).
    if ipv6_active {
        let (exp_server, _) =
            start_server_with_ports(reserve_free_dual_stack_port, |&explicit_port| {
                let explicit_kdl = format!(
                    r#"
server {{
    listen "0.0.0.0:{explicit_port}" protocols="h2,h1"
    listen "[::]:{explicit_port}" protocols="h2,h1"
    tls {{
        min-version "1.3"
        pqc-hybrid #true
    }}
}}
site "explicit.example.test" {{
    root "{root_str}"
}}
"#
                );
                let (exp_cfg, exp_report) = parse_kdl("explicit-dual.kdl", &explicit_kdl)?;
                assert!(exp_report.warnings.iter().all(|w| w.code == "W015"));
                Ok(exp_cfg)
            })
            .await?;
        assert_eq!(exp_server.bound_listeners().len(), 2);
        exp_server.shutdown().await;
    }

    Ok(())
}

/// DOS-1 (`limits.max-connections-per-ip`) and R4-HTTP-3 (live HTTP/3 streaming body exceeding
/// `max-body-bytes` without `Content-Length` MUST return exact `413 Payload Too Large`, NOT 400/408).
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn round4_per_ip_connection_cap_and_h3_413_payload_too_large() -> TestResult {
    let root = TempDir::new("r4-cap-h3")?;
    fs::write(root.path.join("index.html"), b"cap ok")?;
    let root_str = root.path.to_string_lossy().replace('\\', "/");

    // Mock upstream that consumes the full POST body so ReverseProxy reads H3 streaming frames.
    let up_listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = up_listener.local_addr()?;
    let up_task = tokio::spawn(async move {
        while let Ok((stream, _)) = up_listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let _ = req.into_body().collect().await;
                    Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from_static(b"uploaded"))))
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let (server, tls_port) = start_server_with_ports(reserve_free_port, |&tls_port| {
        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h3,h2,h1"
    tls {{
        min-version "1.3"
        pqc-hybrid #true
    }}
    limits {{
        max-body-bytes "1KB"
        max-connections-per-ip 2
    }}
}}

site "cap.example.test" {{
    root "{root_str}"
    route "/upload/*" {{
        reverse-proxy {{
            upstream "http://{up_addr}"
        }}
    }}
}}
"#
        );
        let (cfg, _) = parse_kdl("r4-cap-h3.kdl", &kdl)?;
        Ok(cfg)
    })
    .await?;

    let dev_pem = server.dev_cert_pem().ok_or("missing dev cert PEM")?;
    let mut roots = RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(dev_pem.as_bytes()).collect::<Result<_, _>>()?;
    let (added, _) = roots.add_parsable_certificates(certs);
    assert_eq!(added, 1);

    // 1. R4-HTTP-3: Over live HTTP/3, stream a 4 KiB POST body WITHOUT Content-Length against
    //    `max-body-bytes "1KB"` -> MUST return exact `413 Payload Too Large`!
    let mut h3_tls = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    h3_tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic_cli_crypto = QuicClientConfig::try_from(h3_tls)?;
    let mut quic_ep = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    quic_ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_cli_crypto)));
    let h3_target: SocketAddr = format!("127.0.0.1:{tls_port}").parse()?;
    let quinn_conn = quic_ep.connect(h3_target, "cap.example.test")?.await?;
    let (mut driver, mut send_req) = h3::client::new(h3_quinn::Connection::new(quinn_conn)).await?;
    let driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let mut stream = send_req
        .send_request(
            Request::builder()
                .method(http::Method::POST)
                .uri("https://cap.example.test/upload/big")
                .body(())?,
        )
        .await?;
    let _ = stream.send_data(Bytes::from(vec![b'Z'; 4 * 1024])).await;
    let _ = stream.finish().await;
    let h3_resp = stream.recv_response().await?;
    assert_eq!(
        h3_resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "HTTP/3 streaming oversized body MUST return exact 413 Payload Too Large"
    );
    driver_task.abort();
    quic_ep.close(0_u32.into(), b"done");
    // Give the server a brief moment to release the closed QUIC connection slot before TCP cap test.
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;

    // 2. DOS-1: `max-connections-per-ip 2` holds 2 active (non-idle) TLS connections from
    //    127.0.0.1, drops the 3rd concurrent connection, and recovers immediately once 1 slot closes!
    //    (Idle keep-alive connections are instead eligible for oldest-idle eviction per HANDOVER §5 #6.)
    let mut h1_cfg = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    h1_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let h1_cfg = Arc::new(h1_cfg);
    let tcp_target: SocketAddr = format!("127.0.0.1:{tls_port}").parse()?;

    let mut held_active_conns = Vec::new();
    for _ in 0..2 {
        let tcp = TcpStream::connect(tcp_target).await?;
        let tls = TlsConnector::from(Arc::clone(&h1_cfg))
            .connect(ServerName::try_from("cap.example.test")?, tcp)
            .await?;
        // Handshaked but pre-first-request (not an idle keep-alive), so NOT evictable.
        held_active_conns.push(tls);
    }

    // 3rd concurrent connection from the same 127.0.0.1 IP MUST be dropped by per-IP cap!
    let tcp3 = TcpStream::connect(tcp_target).await?;
    let third_tls = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        TlsConnector::from(Arc::clone(&h1_cfg))
            .connect(ServerName::try_from("cap.example.test")?, tcp3),
    )
    .await;
    assert!(
        !matches!(third_tls, Ok(Ok(_))),
        "3rd concurrent connection from 127.0.0.1 must be rejected by max-connections-per-ip 2 when active slots are full"
    );

    // Close 1 held active connection -> slot releases -> new connection succeeds with 200 OK!
    held_active_conns.pop();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let tcp_after = TcpStream::connect(tcp_target).await?;
    let tls_after = TlsConnector::from(Arc::clone(&h1_cfg))
        .connect(ServerName::try_from("cap.example.test")?, tcp_after)
        .await?;
    let (mut sender_after, conn_after) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_after)).await?;
    let conn_after_task = tokio::spawn(async move {
        let _ = conn_after.await;
    });
    let ok_resp = sender_after
        .send_request(
            Request::builder()
                .uri("/index.html")
                .header(HOST, "cap.example.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(ok_resp.status(), StatusCode::OK);
    conn_after_task.abort();
    drop(held_active_conns);

    server.shutdown().await;
    up_task.abort();
    Ok(())
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn builtin_error_and_welcome_pages_end_to_end() -> TestResult {
    // --- Part 1: Zero-site server serves the branded Welcome page over live HTTPS ---
    let (zero_server, welcome_port) = start_server_with_ports(reserve_free_port, |&welcome_port| {
        let zero_site_kdl = format!(
            r#"
server {{
    listen "127.0.0.1:{welcome_port}" protocols="h2,h1"
}}
"#
        );
        let (zero_cfg, _) = parse_kdl("zero-site.kdl", &zero_site_kdl)?;
        Ok(zero_cfg)
    })
    .await?;
    let zero_roots = build_roots(
        zero_server
            .dev_cert_pem()
            .ok_or("expected dev_tls certificate for zero-site server")?,
    )?;
    let mut zero_tls = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(zero_roots)
        .with_no_client_auth();
    zero_tls.alpn_protocols = vec![b"http/1.1".to_vec()];

    let zero_addr: SocketAddr = format!("127.0.0.1:{welcome_port}").parse()?;
    let tcp_w = TcpStream::connect(zero_addr).await?;
    let tls_w = TlsConnector::from(Arc::new(zero_tls))
        .connect(ServerName::try_from("localhost")?, tcp_w)
        .await?;
    let (mut w_sender, w_conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls_w)).await?;
    let w_task = tokio::spawn(async move {
        let _ = w_conn.await;
    });

    // Browser Accept -> welcome.html
    let w_html_resp = w_sender
        .send_request(
            Request::builder()
                .uri("/")
                .header(HOST, "localhost")
                .header(
                    http::header::ACCEPT,
                    "text/html,application/xhtml+xml,*/*;q=0.8",
                )
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(w_html_resp.status(), StatusCode::OK);
    assert_eq!(
        w_html_resp
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(
        w_html_resp
            .headers()
            .get(http::header::VARY)
            .and_then(|v| v.to_str().ok()),
        Some("Accept")
    );
    assert_eq!(
        w_html_resp
            .headers()
            .get(http::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let w_csp = w_html_resp
        .headers()
        .get(http::header::CONTENT_SECURITY_POLICY)
        .and_then(|v| v.to_str().ok())
        .ok_or("missing CSP on welcome.html")?
        .to_owned();
    let w_nonce = w_csp
        .strip_prefix("default-src 'none'; style-src 'nonce-")
        .and_then(|s| s.split('\'').next())
        .ok_or("failed to extract CSP nonce from welcome page")?
        .to_owned();
    let w_html = String::from_utf8(w_html_resp.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(w_html.contains("MiraServe is up and serving"));
    assert!(w_html.contains("<b>localhost</b>"));
    assert!(w_html.contains("TLS 1.3 · post-quantum"));
    assert!(w_html.contains("HTTP/1.1"));
    assert!(w_html.contains(&format!("<style nonce=\"{w_nonce}\">")));
    assert!(!w_html.contains("style=\""));

    // JSON Accept -> JSON welcome
    let w_json_resp = w_sender
        .send_request(
            Request::builder()
                .uri("/")
                .header(HOST, "localhost")
                .header(http::header::ACCEPT, "application/json")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(w_json_resp.status(), StatusCode::OK);
    assert_eq!(
        w_json_resp
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json; charset=utf-8")
    );
    let w_json = String::from_utf8(w_json_resp.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(w_json.contains("\"status\": \"running\""));

    // POST on unconfigured host -> 405 Method Not Allowed with Allow: GET, HEAD
    let w_post_resp = w_sender
        .send_request(
            Request::builder()
                .method(http::Method::POST)
                .uri("/")
                .header(HOST, "localhost")
                .header(http::header::ACCEPT, "text/html")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(w_post_resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        w_post_resp
            .headers()
            .get(http::header::ALLOW)
            .and_then(|v| v.to_str().ok()),
        Some("GET, HEAD")
    );
    let _ = w_post_resp.into_body().collect().await?;
    w_task.abort();
    zero_server.shutdown().await;

    // --- Part 2: Branded error pages, content negotiation, custom override, and upstream pass-through ---
    let tmp = TempDir::new("pages-site")?;
    fs::create_dir_all(tmp.path.join("errors"))?;
    fs::write(tmp.path.join("index.html"), b"<h1>OK</h1>")?;
    fs::write(
        tmp.path.join("errors/403.html"),
        b"<!doctype html><html><body>Custom Site 403 Override</body></html>",
    )?;

    // Upstream returning its OWN custom 404 JSON body (must pass through untouched!)
    let up_listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = up_listener.local_addr()?;
    let up_task = tokio::spawn(async move {
        while let Ok((stream, _)) = up_listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(|_req: Request<Incoming>| async move {
                    let resp = Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .body(Full::new(Bytes::from_static(
                            b"{\"upstream_custom\":\"keep-me\"}",
                        )))
                        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"err"))));
                    Ok::<_, std::convert::Infallible>(resp)
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    // Hold a dedicated dead-upstream listener bound for the entire test and immediately close
    // every accepted TCP connection before writing any response bytes: no concurrent process can
    // steal `dead_upstream_port`, and reverse-proxy deterministically receives an invalid/closed
    // upstream -> guaranteed 502 without any release-to-bind race.
    let dead_listener = TcpListener::bind("127.0.0.1:0").await?;
    let dead_upstream_port = dead_listener.local_addr()?.port();
    let dead_task = tokio::spawn(async move {
        while let Ok((stream, _)) = dead_listener.accept().await {
            drop(stream);
        }
    });
    let root_str = tmp.path.to_string_lossy().replace('\\', "/");

    let (server, tls_port) = start_server_with_ports(reserve_free_port, |&tls_port| {
        let site_kdl = format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
}}
site "pages.example.test" {{
    preset "wordpress-hardened"
    root "{root_str}"
    error-pages {{
        login-url "/signin"
        page 403 "errors/403.html"
    }}
    route "/upstream-404/*" {{
        reverse-proxy {{
            upstream "http://127.0.0.1:{up_port}"
        }}
    }}
    route "/dead-upstream/*" {{
        reverse-proxy {{
            upstream "http://127.0.0.1:{dead_upstream_port}"
        }}
    }}
    route "/limited/*" {{
        rate-limit requests=1 per="1m" burst=1
        static {{}}
    }}
}}
"#,
            up_port = up_addr.port(),
        );
        let (site_cfg, _) = parse_kdl("pages-site.kdl", &site_kdl)?;
        Ok(site_cfg)
    })
    .await?;

    let roots = build_roots(server.dev_cert_pem().ok_or("missing dev_tls cert")?)?;
    let mut cli_tls = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cli_tls.alpn_protocols = vec![b"http/1.1".to_vec()];

    let https_addr: SocketAddr = format!("127.0.0.1:{tls_port}").parse()?;
    let tcp = TcpStream::connect(https_addr).await?;
    let tls = TlsConnector::from(Arc::new(cli_tls))
        .connect(ServerName::try_from("pages.example.test")?, tcp)
        .await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    // 1. HTML 404 with fresh CSP nonce and matching X-Request-Id
    let r404_a = sender
        .send_request(
            Request::builder()
                .uri("/missing-page")
                .header(HOST, "pages.example.test")
                .header(http::header::ACCEPT, "text/html")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(r404_a.status(), StatusCode::NOT_FOUND);
    let req_id_a = r404_a
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .ok_or("missing x-request-id")?
        .to_owned();
    let csp_a = r404_a
        .headers()
        .get(http::header::CONTENT_SECURITY_POLICY)
        .and_then(|v| v.to_str().ok())
        .ok_or("missing CSP")?
        .to_owned();
    let html_404_a = String::from_utf8(r404_a.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(html_404_a.contains("We can’t find that page"));
    assert!(html_404_a.contains("<code>/missing-page</code>"));
    assert!(html_404_a.contains(&req_id_a));

    // Second 404 MUST have a different CSP nonce and different Request ID
    let r404_b = sender
        .send_request(
            Request::builder()
                .uri("/missing-page")
                .header(HOST, "pages.example.test")
                .header(http::header::ACCEPT, "text/html")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    let req_id_b = r404_b
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .ok_or("missing second x-request-id")?
        .to_owned();
    let csp_b = r404_b
        .headers()
        .get(http::header::CONTENT_SECURITY_POLICY)
        .and_then(|v| v.to_str().ok())
        .ok_or("missing second CSP")?
        .to_owned();
    let _ = r404_b.into_body().collect().await?;
    assert_ne!(
        csp_a, csp_b,
        "CSP nonce must be freshly generated per response"
    );
    assert_ne!(req_id_a, req_id_b, "request_id must be unique per request");

    // 2. JSON 404 (RFC 9457)
    let r404_json = sender
        .send_request(
            Request::builder()
                .uri("/missing-json")
                .header(HOST, "pages.example.test")
                .header(http::header::ACCEPT, "application/json")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(r404_json.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        r404_json
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/problem+json; charset=utf-8")
    );
    let json_req_id = r404_json
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .ok_or("missing JSON x-request-id")?
        .to_owned();
    let json_body = String::from_utf8(r404_json.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(json_body.contains("\"type\": \"about:blank\""));
    assert!(json_body.contains("\"instance\": \"/missing-json\""));
    assert!(json_body.contains(&format!("\"request_id\": \"{json_req_id}\"")));

    // 3. Markdown 404 (AI agents)
    let r404_md = sender
        .send_request(
            Request::builder()
                .uri("/missing-md")
                .header(HOST, "pages.example.test")
                .header(http::header::ACCEPT, "text/markdown")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(r404_md.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        r404_md
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/markdown; charset=utf-8")
    );
    let md_body = String::from_utf8(r404_md.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(md_body.contains("# 404 Not Found"));
    assert!(md_body.contains("[/llms.txt](/llms.txt)"));

    // 4. Plain-text 404 (`Accept: */*`)
    let r404_txt = sender
        .send_request(
            Request::builder()
                .uri("/missing-txt")
                .header(HOST, "pages.example.test")
                .header(http::header::ACCEPT, "*/*")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(r404_txt.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        r404_txt
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/plain; charset=utf-8")
    );
    let txt_body = String::from_utf8(r404_txt.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(txt_body.starts_with("404 Not Found\n\n"));

    // 5. Custom per-site 403 override for HTML, while JSON still returns RFC 9457
    let r403_html = sender
        .send_request(
            Request::builder()
                .uri("/xmlrpc.php")
                .header(HOST, "pages.example.test")
                .header(http::header::ACCEPT, "text/html")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(r403_html.status(), StatusCode::FORBIDDEN);
    let custom_403 = String::from_utf8(r403_html.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(custom_403.contains("Custom Site 403 Override"));

    let r403_json = sender
        .send_request(
            Request::builder()
                .uri("/xmlrpc.php")
                .header(HOST, "pages.example.test")
                .header(http::header::ACCEPT, "application/json")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(r403_json.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        r403_json
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/problem+json; charset=utf-8")
    );
    let _ = r403_json.into_body().collect().await?;

    // 6. Real upstream 404 body passes through UNTOUCHED!
    let up_404 = sender
        .send_request(
            Request::builder()
                .uri("/upstream-404/item")
                .header(HOST, "pages.example.test")
                .header(http::header::ACCEPT, "text/html")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(up_404.status(), StatusCode::NOT_FOUND);
    let up_404_body = up_404.into_body().collect().await?.to_bytes();
    assert_eq!(up_404_body.as_ref(), b"{\"upstream_custom\":\"keep-me\"}");

    // 7. MiraServe proxy 502 renders branded upstream-chain page WITHOUT leaking upstream address!
    let r502 = sender
        .send_request(
            Request::builder()
                .uri("/dead-upstream/check")
                .header(HOST, "pages.example.test")
                .header(http::header::ACCEPT, "text/html")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(r502.status(), StatusCode::BAD_GATEWAY);
    let body_502 = String::from_utf8(r502.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(body_502.contains("The site’s application isn’t responding"));
    assert!(body_502.contains("Invalid response"));
    assert!(
        !body_502.contains("127.0.0.1"),
        "502 page must never leak upstream IP addresses"
    );
    assert!(
        !body_502.contains(&dead_upstream_port.to_string()),
        "502 page must never leak upstream port"
    );

    // 8. Rate-limited route triggers 429 HTML page with Retry-After header + countdown box!
    let _ = sender
        .send_request(
            Request::builder()
                .uri("/limited/a")
                .header(HOST, "pages.example.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?
        .into_body()
        .collect()
        .await?;
    let r429 = sender
        .send_request(
            Request::builder()
                .uri("/limited/b")
                .header(HOST, "pages.example.test")
                .header(http::header::ACCEPT, "text/html")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(r429.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(r429.headers().contains_key(http::header::RETRY_AFTER));
    let body_429 = String::from_utf8(r429.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(body_429.contains("Slow down a little"));
    assert!(body_429.contains("Retry-After:"));

    conn_task.abort();
    server.shutdown().await;
    dead_task.abort();
    up_task.abort();
    Ok(())
}

/// Round 5 Wave 4 live server E2E tests (`R5-PRX-2`, `R5-PRX-3`, `R5-DOS-1`, `R5-RL-1`, `R5-HTTP-3`):
/// - `R5-PRX-2`: Truncated upstream response over live HTTP/3 resets the QUIC stream with
///   `H3_INTERNAL_ERROR` (error returned by `recv_data()`, NEVER clean `Ok(None)` FIN!).
/// - `R5-PRX-3`: Per-route `reverse-proxy` `upstream-body-idle-timeout` override survives a pause
///   longer than the global `server.timeouts.upstream-body-idle-timeout`.
/// - `R5-DOS-1`: Configurable global `max-connections`, `trusted-proxies` exempting the load
///   balancer from `max-connections-per-ip` while still enforcing global `max-connections`, and
///   ONE combined TLS handshake deadline across `LazyConfigAcceptor` + `into_stream`.
/// - `R5-RL-1`: Trusted proxy `X-Forwarded-For` right-to-left peeling gives distinct clients behind
///   one CDN/LB IP independent per-client rate-limit buckets.
/// - `R5-HTTP-3`: `/api/fichier%E9.pdf` returns 200 on reverse-proxy route while `/static/fichier%E9.pdf`
///   returns 400 on static route.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn round5_wave4_h3_stream_reset_per_route_sse_timeout_trusted_proxies_and_legacy_uri()
-> TestResult {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let tmp = TempDir::new("r5-wave4")?;
    std::fs::write(tmp.path.join("index.html"), b"<h1>wave4</h1>")?;
    let root_str = tmp.path.to_string_lossy().replace('\\', "/");

    // Upstream 1: Sends 200 + first chunk, then pauses 300ms and sends "second\n" + EOF.
    // On `/short-idle/*` (global 120ms body-idle timeout) this triggers a mid-stream truncation!
    // On `/sse/*` (per-route 2s body-idle timeout) this completes cleanly with BOTH chunks!
    let up_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = up_listener.local_addr()?;
    let up_task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = up_listener.accept().await {
            tokio::spawn(async move {
                let mut req_buf = [0_u8; 1024];
                let n = stream.read(&mut req_buf).await.unwrap_or(0);
                let req_line = std::str::from_utf8(req_buf.get(..n).unwrap_or(&[]))
                    .unwrap_or("")
                    .lines()
                    .next()
                    .unwrap_or("");
                if req_line.contains("/api/") {
                    let body = req_line.as_bytes();
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(head.as_bytes()).await;
                    let _ = stream.write_all(body).await;
                    return;
                }
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\nfirst\n\r\n",
                    )
                    .await;
                tokio::time::sleep(std::time::Duration::from_millis(320)).await;
                let _ = stream.write_all(b"7\r\nsecond\n\r\n0\r\n\r\n").await;
            });
        }
    });

    let (server, tls_port) = start_server_with_ports(reserve_free_port, |&tls_port| {
        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h3,h2,h1"
    tls {{
        min-version "1.3"
        pqc-hybrid #true
    }}
    timeouts {{
        tls-handshake "400ms"
        upstream-body-idle-timeout "120ms"
    }}
    limits {{
        max-connections 3
        max-connections-per-ip 1
        trusted-proxies "127.0.0.1"
    }}
}}

site "wave4.example.test" {{
    root "{root_str}"
    route "/short-idle/*" {{
        reverse-proxy {{
            upstream "http://{up_addr}"
            streaming-flush "immediate"
        }}
    }}
    route "/sse/*" {{
        reverse-proxy {{
            upstream "http://{up_addr}"
            streaming-flush "immediate"
            upstream-body-idle-timeout "2s"
        }}
    }}
    route "/api/*" {{
        rate-limit requests=2 per="1m" burst=2 key="client-ip"
        reverse-proxy {{
            upstream "http://{up_addr}"
        }}
    }}
    route "/static/*" {{
        static {{
            index "index.html"
        }}
    }}
}}
"#
        );
        let (cfg, _) = parse_kdl("wave4-e2e.kdl", &kdl)?;
        Ok(cfg)
    })
    .await?;

    let roots = build_roots(server.dev_cert_pem().ok_or("missing dev cert PEM")?)?;

    // 1. R5-PRX-2: Over live HTTP/3, `/short-idle/stream` exceeds the 120ms global body-idle
    //    timeout mid-stream -> HTTP/3 client MUST observe a stream reset ERROR (NOT clean EOF)!
    let mut h3_tls = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    h3_tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic_cli_crypto = QuicClientConfig::try_from(h3_tls)?;
    let mut quic_ep = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    quic_ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_cli_crypto)));
    let target_addr: SocketAddr = format!("127.0.0.1:{tls_port}").parse()?;
    let quinn_conn = quic_ep.connect(target_addr, "wave4.example.test")?.await?;
    let (mut driver, mut send_req) = h3::client::new(h3_quinn::Connection::new(quinn_conn)).await?;
    let driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let mut trunc_stream = send_req
        .send_request(
            Request::builder()
                .method(http::Method::GET)
                .uri("https://wave4.example.test/short-idle/stream")
                .body(())?,
        )
        .await?;
    trunc_stream.finish().await?;
    let trunc_head = trunc_stream.recv_response().await?;
    assert_eq!(trunc_head.status(), StatusCode::OK);
    let mut saw_first_chunk = false;
    let mut saw_reset_error = false;
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(3), trunc_stream.recv_data())
            .await
            .map_err(|_| "HTTP/3 client hung waiting on truncated stream")?
        {
            Ok(Some(mut chunk)) => {
                use bytes::Buf as _;
                let mut bytes = Vec::new();
                while chunk.has_remaining() {
                    let s = chunk.chunk();
                    bytes.extend_from_slice(s);
                    let n = s.len();
                    chunk.advance(n);
                }
                if bytes == b"first\n" {
                    saw_first_chunk = true;
                }
            }
            Ok(None) => {
                break;
            }
            Err(_) => {
                saw_reset_error = true;
                break;
            }
        }
    }
    assert!(
        saw_first_chunk,
        "expected initial SSE chunk before idle cutoff"
    );
    assert!(
        saw_reset_error,
        "R5-PRX-2: truncated HTTP/3 response MUST reset stream with error instead of clean FIN EOF"
    );

    // 2. R5-PRX-3: On the SAME server, `/sse/stream` has per-route `upstream-body-idle-timeout "2s"`
    //    and MUST receive BOTH chunks cleanly across the 320ms gap (> global 120ms)!
    let mut sse_stream = send_req
        .send_request(
            Request::builder()
                .method(http::Method::GET)
                .uri("https://wave4.example.test/sse/stream")
                .body(())?,
        )
        .await?;
    sse_stream.finish().await?;
    let sse_head = sse_stream.recv_response().await?;
    assert_eq!(sse_head.status(), StatusCode::OK);
    let mut sse_bytes = Vec::new();
    while let Some(mut chunk) = sse_stream.recv_data().await? {
        use bytes::Buf as _;
        while chunk.has_remaining() {
            let s = chunk.chunk();
            sse_bytes.extend_from_slice(s);
            let n = s.len();
            chunk.advance(n);
        }
    }
    assert_eq!(
        sse_bytes, b"first\nsecond\n",
        "R5-PRX-3: per-route upstream-body-idle-timeout override must survive 320ms SSE pause"
    );
    driver_task.abort();
    quic_ep.close(0_u32.into(), b"done");
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;

    // 3. R5-DOS-1 + R5-RL-1 + R5-HTTP-3 over HTTPS TCP:
    //    - `127.0.0.1` is in `trusted-proxies`, so 3 concurrent connections succeed despite
    //      `max-connections-per-ip 1`, while the 4th is rejected by global `max-connections 3`!
    //    - Distinct `X-Forwarded-For` clients get independent `rate-limit` buckets!
    //    - `/api/fichier%E9.pdf` returns 200 on proxy while `/static/fichier%E9.pdf` returns 400!
    let mut h1_cfg = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    h1_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let h1_cfg = Arc::new(h1_cfg);

    let mut held = Vec::new();
    for _ in 0..3 {
        let tcp = TcpStream::connect(target_addr).await?;
        let tls = TlsConnector::from(Arc::clone(&h1_cfg))
            .connect(ServerName::try_from("wave4.example.test")?, tcp)
            .await?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
        let task = tokio::spawn(async move {
            let _ = conn.await;
        });
        let r = sender
            .send_request(
                Request::builder()
                    .uri("/index.html")
                    .header(HOST, "wave4.example.test")
                    .body(Empty::<Bytes>::new())?,
            )
            .await?;
        assert_eq!(r.status(), StatusCode::OK);
        let _ = r.into_body().collect().await?;
        held.push((sender, task));
    }

    // 4th concurrent connection MUST fail because global `max-connections 3` is reached!
    let tcp4 = TcpStream::connect(target_addr).await?;
    let fourth_tls = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        TlsConnector::from(Arc::clone(&h1_cfg))
            .connect(ServerName::try_from("wave4.example.test")?, tcp4),
    )
    .await;
    assert!(
        !matches!(fourth_tls, Ok(Ok(_))),
        "R5-DOS-1: 4th concurrent connection must be dropped by configurable max-connections 3"
    );

    // Use one of the open trusted-proxy connections to test R5-RL-1 XFF peeling + R5-HTTP-3!
    let (sender, _) = held.first_mut().ok_or("missing open connection")?;
    // Client A (`198.51.100.11`) behind trusted proxy gets 2 allowed, 3rd -> 429:
    for idx in 0..3_u32 {
        let resp = sender
            .send_request(
                Request::builder()
                    .uri("/api/fichier%E9.pdf")
                    .header(HOST, "wave4.example.test")
                    .header("x-forwarded-for", "198.51.100.11, 127.0.0.1")
                    .body(Empty::<Bytes>::new())?,
            )
            .await?;
        if idx < 2 {
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "R5-HTTP-3 + R5-RL-1: client A req {idx} to /api/fichier%E9.pdf must return 200"
            );
            let body = resp.into_body().collect().await?.to_bytes();
            assert!(
                std::str::from_utf8(&body)?.contains("/api/fichier%E9.pdf"),
                "upstream must receive original /api/fichier%E9.pdf"
            );
        } else {
            assert_eq!(
                resp.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "R5-RL-1: client A 3rd request must hit per-client 429"
            );
            let _ = resp.into_body().collect().await?;
        }
    }
    // Client B (`198.51.100.22`) behind the SAME trusted proxy MUST still succeed (200 OK)!
    let client_b_resp = sender
        .send_request(
            Request::builder()
                .uri("/api/fichier%E9.pdf")
                .header(HOST, "wave4.example.test")
                .header("x-forwarded-for", "198.51.100.22, 127.0.0.1")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(
        client_b_resp.status(),
        StatusCode::OK,
        "R5-RL-1: distinct client B via trusted proxy X-Forwarded-For must have its own bucket"
    );
    let _ = client_b_resp.into_body().collect().await?;

    // R5-HTTP-3: `/static/fichier%E9.pdf` on a filesystem static route MUST still return 400!
    let static_latin1 = sender
        .send_request(
            Request::builder()
                .uri("/static/fichier%E9.pdf")
                .header(HOST, "wave4.example.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(
        static_latin1.status(),
        StatusCode::BAD_REQUEST,
        "R5-HTTP-3: static filesystem route must strictly reject non-UTF-8 /static/fichier%E9.pdf"
    );
    let _ = static_latin1.into_body().collect().await?;

    for (s, t) in held {
        drop(s);
        t.abort();
    }
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;

    // 4. R5-DOS-1 single TLS handshake deadline: a raw TCP peer that waits past 400ms
    //    `tls-handshake` is closed promptly within one deadline (not 2x).
    let mut stalled_tcp = TcpStream::connect(target_addr).await?;
    let hs_start = std::time::Instant::now();
    let mut buf = [0_u8; 64];
    let read_res = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stalled_tcp.read(&mut buf),
    )
    .await;
    assert!(
        matches!(read_res, Ok(Ok(0) | Err(_))),
        "stalled TLS peer must be closed by server at tls-handshake deadline, got {read_res:?}"
    );
    assert!(
        hs_start.elapsed() < std::time::Duration::from_millis(900),
        "TLS handshake deadline took too long: {:?}",
        hs_start.elapsed()
    );

    server.shutdown().await;
    up_task.abort();
    Ok(())
}

/// An HTTP/3 connection that sends no request is closed at the header deadline, and one whose
/// requests are done at the keep-alive time, although QUIC PINGs keep its transport alive
/// (Cloudflare-skills audit of v0.1.0, claims 3 and 5).
#[tokio::test]
async fn h3_connection_without_requests_is_closed_despite_pings() -> TestResult {
    let root = TempDir::new("h3-idle")?;
    fs::write(root.path.join("index.html"), b"idle ok")?;
    let root_str = root.path.to_string_lossy().replace('\\', "/");
    let (server, tls_port) = start_server_with_ports(reserve_free_port, |&tls_port| {
        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h3,h2,h1"
    tls {{
        min-version "1.3"
        pqc-hybrid #true
    }}
    timeouts {{
        header-read "700ms"
        idle-keepalive "900ms"
    }}
}}

site "idle.example.test" {{
    root "{root_str}"
}}
"#
        );
        let (cfg, _) = parse_kdl("h3-idle.kdl", &kdl)?;
        Ok(cfg)
    })
    .await?;
    let roots = build_roots(server.dev_cert_pem().ok_or("missing dev cert PEM")?)?;
    let mut h3_tls = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    h3_tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut client = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(h3_tls)?));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(std::time::Duration::from_millis(100)));
    client.transport_config(Arc::new(transport));
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(client);
    let target: SocketAddr = format!("127.0.0.1:{tls_port}").parse()?;
    let limit = std::time::Duration::from_secs(5);

    // No request at all.
    let silent = endpoint.connect(target, "idle.example.test")?.await?;
    let started = std::time::Instant::now();
    tokio::time::timeout(limit, silent.closed()).await?;
    assert!(started.elapsed() >= std::time::Duration::from_millis(600));

    // One request, then nothing.
    let conn = endpoint.connect(target, "idle.example.test")?.await?;
    let (mut driver, mut send_req) =
        h3::client::new(h3_quinn::Connection::new(conn.clone())).await?;
    let driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let mut stream = send_req
        .send_request(
            Request::builder()
                .uri("https://idle.example.test/index.html")
                .body(())?,
        )
        .await?;
    stream.finish().await?;
    assert_eq!(stream.recv_response().await?.status(), StatusCode::OK);
    while stream.recv_data().await?.is_some() {}
    let started = std::time::Instant::now();
    tokio::time::timeout(limit, conn.closed()).await?;
    assert!(started.elapsed() >= std::time::Duration::from_millis(700));
    driver_task.abort();
    server.shutdown().await;
    Ok(())
}

/// `workers 3`: HTTPS over TCP is served by three event loops, each with its own socket on the
/// same address. Connections are answered whichever loop accepts them, a reload reaches all of
/// them, limits stay the server's (one count for all loops), and shutdown drains and returns.
/// Where the setting is not supported (not Linux) the shared runtime serves, and the test
/// checks the same answers.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn workers_serve_https_from_their_own_event_loops() -> TestResult {
    let tmp_v1 = TempDir::new("workers-v1")?;
    let tmp_v2 = TempDir::new("workers-v2")?;
    fs::write(tmp_v1.path.join("index.html"), b"<h1>loops v1</h1>")?;
    fs::write(tmp_v2.path.join("index.html"), b"<h1>loops v2</h1>")?;
    let make_config = |tls_port: u16, root: &std::path::Path, per_ip: u32| {
        format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
    workers 3
    limits {{
        max-connections-per-ip {per_ip}
    }}
}}
site "app.example.test" {{
    root "{}"
}}
"#,
            root.to_string_lossy().replace('\\', "/")
        )
    };

    let (server, tls_port) = start_server_with_ports(reserve_free_port, |&tls_port| {
        let (cfg, _) = parse_kdl("workers-v1.kdl", &make_config(tls_port, &tmp_v1.path, 64))?;
        assert_eq!(cfg.server.workers, miraserve_config::Workers::Count(3));
        Ok(cfg)
    })
    .await?;
    let config = |root: &std::path::Path, per_ip: u32| make_config(tls_port, root, per_ip);
    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::HttpsTcp)
        .ok_or("missing HttpsTcp listener")?
        .local_addr;
    let roots = build_roots(server.dev_cert_pem().ok_or("expected dev cert PEM")?)?;

    #[cfg(target_os = "linux")]
    {
        let loops = fs::read_dir("/proc/self/task")?
            .filter_map(Result::ok)
            .filter_map(|task| fs::read_to_string(task.path().join("comm")).ok())
            .filter(|name| name.starts_with("miraserve-loop-"))
            .count();
        assert_eq!(loops, 3, "one thread per event loop");
    }

    // A fresh connection for every request: the kernel spreads them over the loops' sockets.
    let fetch = |alpn: &'static [u8], roots: RootCertStore| async move {
        let mut tls_cfg = ClientConfig::builder_with_provider(build_crypto_provider(true))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls_cfg.alpn_protocols = vec![alpn.to_vec()];
        let tcp = TcpStream::connect(https_addr).await?;
        let tls = TlsConnector::from(Arc::new(tls_cfg))
            .connect(ServerName::try_from("app.example.test")?, tcp)
            .await?;
        let request = Request::builder()
            .uri("https://app.example.test/index.html")
            .header(HOST, "app.example.test")
            .body(Empty::<Bytes>::new())?;
        let response = if alpn == b"h2" {
            let (mut sender, conn) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                    .await?;
            tokio::spawn(conn);
            sender.send_request(request).await?
        } else {
            let (mut sender, conn) =
                hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
            tokio::spawn(conn);
            sender.send_request(request).await?
        };
        let status = response.status();
        let body = response.into_body().collect().await?.to_bytes();
        Ok::<_, Box<dyn std::error::Error>>((status, body))
    };

    for round in 0..24 {
        let alpn: &'static [u8] = if round % 2 == 0 { b"http/1.1" } else { b"h2" };
        let (status, body) = fetch(alpn, roots.clone()).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], b"<h1>loops v1</h1>");
    }

    // A reload reaches every loop: all of them read the same configuration.
    server.reload_from_str("workers-v2.kdl", &config(&tmp_v2.path, 64))?;
    for round in 0..24 {
        let alpn: &'static [u8] = if round % 2 == 0 { b"http/1.1" } else { b"h2" };
        let (status, body) = fetch(alpn, roots.clone()).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], b"<h1>loops v2</h1>");
    }

    // The connection limit per address is one count for the server, not one per loop: with a
    // limit of 2, the third connection held open at the same time is not accepted.
    server.reload_from_str("workers-v3.kdl", &config(&tmp_v2.path, 2))?;
    let mut held = Vec::new();
    let mut accepted = 0;
    for _ in 0..6 {
        let mut tls_cfg = ClientConfig::builder_with_provider(build_crypto_provider(true))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots.clone())
            .with_no_client_auth();
        tls_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let tcp = TcpStream::connect(https_addr).await?;
        let Ok(Ok(tls)) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            TlsConnector::from(Arc::new(tls_cfg))
                .connect(ServerName::try_from("app.example.test")?, tcp),
        )
        .await
        else {
            continue;
        };
        accepted += 1;
        held.push(tls);
    }
    assert_eq!(
        accepted, 2,
        "max-connections-per-ip counts across all event loops"
    );
    drop(held);

    // Shutdown stops every loop's accepting, drains, and returns.
    tokio::time::timeout(std::time::Duration::from_secs(15), server.shutdown()).await?;
    assert!(TcpStream::connect(https_addr).await.is_err());
    Ok(())
}

/// Codex Round-2 P1 #10 & Round-3 item 4: pins that `run` (`MiraServeServer::start` with
/// `apply_sandbox: true`) preserves exact `74a8243` `SandboxReport` and welcome-page displayed
/// sandbox state (`Not enabled` when `landlock #false` + `seccomp "off"` on EVERY platform,
/// including macOS; `Filesystem confined` on non-Linux when `landlock #true`).
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn worker_displayed_sandbox_state_matches_74a8243() -> TestResult {
    async fn fetch_welcome_html(
        server: &miraserve_core::RunningServer,
        port: u16,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let roots = build_roots(server.dev_cert_pem().ok_or("missing dev_tls cert")?)?;
        let mut tls_cfg = ClientConfig::builder_with_provider(build_crypto_provider(true))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
        let tcp = TcpStream::connect(addr).await?;
        let tls = TlsConnector::from(Arc::new(tls_cfg))
            .connect(ServerName::try_from("localhost".to_owned())?, tcp)
            .await?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
        let task = tokio::spawn(async move {
            let _ = conn.await;
        });
        let resp = sender
            .send_request(
                Request::builder()
                    .uri("/")
                    .header(HOST, "localhost")
                    .header(http::header::ACCEPT, "text/html")
                    .body(Empty::<Bytes>::new())?,
            )
            .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = String::from_utf8(resp.into_body().collect().await?.to_bytes().to_vec())?;
        task.abort();
        Ok(body)
    }

    // 1. `landlock #false` + `seccomp "off"` with `apply_sandbox: true`:
    //    MUST report `Disabled` and display "Not enabled" on BOTH Linux and macOS (74a8243 parity).
    let (server_off, port_off) = {
        let mut last_err = None;
        let mut started = None;
        for _ in 0..8 {
            let port = reserve_free_port()?;
            let kdl = format!(
                r#"
server {{
    listen "127.0.0.1:{port}" protocols="h1"
    sandbox {{
        landlock #false
        seccomp "off"
    }}
}}
"#
            );
            let (cfg, _) = parse_kdl("sbx-off.kdl", &kdl)?;
            match MiraServeServer::start(
                Arc::new(ConfigStore::new(cfg)),
                ServerOptions {
                    dev_tls: true,
                    apply_sandbox: true,
                    ..ServerOptions::default()
                },
            )
            .await
            {
                Ok(s) => {
                    started = Some((s, port));
                    break;
                }
                Err(miraserve_core::CoreError::Bind { source, .. })
                    if source.kind() == std::io::ErrorKind::AddrInUse =>
                {
                    last_err = Some(Box::new(source) as Box<dyn std::error::Error>);
                }
                Err(err) => return Err(err.into()),
            }
        }
        started.ok_or_else(|| last_err.unwrap_or_else(|| "exhausted retries".into()))?
    };

    let rep_off = server_off
        .sandbox_report()
        .ok_or("expected sandbox_report when apply_sandbox=true")?;
    assert_eq!(
        rep_off.landlock,
        miraserve_sandbox::EnforcementStatus::Disabled
    );
    assert_eq!(
        rep_off.seccomp,
        miraserve_sandbox::EnforcementStatus::Disabled
    );
    let html_off = fetch_welcome_html(&server_off, port_off).await?;
    assert!(
        html_off.contains("Not enabled"),
        "welcome page with disabled sandbox must display 'Not enabled', got: {html_off}"
    );
    assert!(
        !html_off.contains("Filesystem confined"),
        "welcome page with disabled sandbox must NOT display 'Filesystem confined'"
    );
    server_off.shutdown().await;

    // 2. Non-Linux with `landlock #true` + `seccomp "off"` and `apply_sandbox: true`:
    //    MUST report `UnsupportedPlatform` and display "Filesystem confined" (74a8243 parity).
    #[cfg(not(target_os = "linux"))]
    {
        let mut last_err = None;
        let mut started = None;
        for _ in 0..8 {
            let port = reserve_free_port()?;
            let kdl = format!(
                r#"
server {{
    listen "127.0.0.1:{port}" protocols="h1"
    sandbox {{
        landlock #true
        seccomp "off"
    }}
}}
"#
            );
            let (cfg, _) = parse_kdl("sbx-on-nonlinux.kdl", &kdl)?;
            match MiraServeServer::start(
                Arc::new(ConfigStore::new(cfg)),
                ServerOptions {
                    dev_tls: true,
                    apply_sandbox: true,
                    ..ServerOptions::default()
                },
            )
            .await
            {
                Ok(s) => {
                    started = Some((s, port));
                    break;
                }
                Err(miraserve_core::CoreError::Bind { source, .. })
                    if source.kind() == std::io::ErrorKind::AddrInUse =>
                {
                    last_err = Some(Box::new(source) as Box<dyn std::error::Error>);
                }
                Err(err) => return Err(err.into()),
            }
        }
        let (server_on, port_on) =
            started.ok_or_else(|| last_err.unwrap_or_else(|| "exhausted retries".into()))?;
        let rep_on = server_on
            .sandbox_report()
            .ok_or("expected sandbox_report when apply_sandbox=true")?;
        assert_eq!(
            rep_on.landlock,
            miraserve_sandbox::EnforcementStatus::UnsupportedPlatform
        );
        assert_eq!(
            rep_on.seccomp,
            miraserve_sandbox::EnforcementStatus::Disabled
        );
        let html_on = fetch_welcome_html(&server_on, port_on).await?;
        assert!(
            html_on.contains("Filesystem confined"),
            "non-Linux welcome page with landlock #true must display 'Filesystem confined'"
        );
        server_on.shutdown().await;
    }

    Ok(())
}

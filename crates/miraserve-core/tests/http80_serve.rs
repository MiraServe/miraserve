//! End-to-end tests over real plain-HTTP TCP connections for per-site `http "serve"` on
//! `redirect-https=#true` listeners (MiraServe 0.1.3).

#![allow(unknown_lints, clippy::assert_is_empty)]

use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use bytes::Bytes;
use http::header::{
    ALT_SVC, AUTHORIZATION, CACHE_CONTROL, CONNECTION, CONTENT_TYPE, HOST, LOCATION, RETRY_AFTER,
    STRICT_TRANSPORT_SECURITY, UPGRADE, WWW_AUTHENTICATE,
};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt as _, Empty, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use miraserve_config::{ConfigStore, parse_kdl};
use miraserve_core::{CoreError, ListenerKind, MiraServeServer, RunningServer, ServerOptions};
use miraserve_fastcgi::protocol::{
    EndRequestBody, RecordType, decode_params, read_record, write_record, write_stream_records,
};
use miraserve_tls::build_crypto_provider;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Valid bcrypt (cost 4) htpasswd entry for user `ann`, password `s3cret`.
const HTPASSWD_ANN_S3CRET: &str =
    "ann:$2y$04$euq2l0Zl/ScQTk3CQ399bOWoEjKfBFWbHiK4fmzlEbAioTmwnGI4q\n";
/// Base64("ann:s3cret").
const BASIC_ANN_VALID: &str = "Basic YW5uOnMzY3JldA==";
/// Base64("ann:wrong").
const BASIC_ANN_WRONG: &str = "Basic YW5uOndyb25n";

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Result<Self, std::io::Error> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "miraserve-http80-{tag}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn kdl_str(&self) -> String {
        self.path.to_string_lossy().replace('\\', "/")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Reserves two distinct ephemeral loopback ports, each simultaneously free on BOTH TCP and UDP,
/// holding the first port's probe sockets open while reserving the second so the OS cannot hand
/// out the same port twice (`E102` duplicate listener).
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

async fn start_server_retrying<F>(
    mut make_kdl: F,
) -> Result<(RunningServer, SocketAddr, SocketAddr, u16, u16), Box<dyn std::error::Error>>
where
    F: FnMut(u16, u16) -> String,
{
    let mut last_err: Option<Box<dyn std::error::Error>> = None;
    for _ in 0..16 {
        let (tls_port, http_port) = reserve_two_free_ports()?;
        let kdl = make_kdl(tls_port, http_port);
        let (cfg, _) = match parse_kdl("http80-test.kdl", &kdl) {
            Ok(parsed) => parsed,
            Err(err) if err.validation_errors().iter().any(|e| e.code == "E102") => {
                last_err = Some(err.into());
                continue;
            }
            Err(err) => return Err(err.into()),
        };
        let store = Arc::new(ConfigStore::new(cfg));
        match MiraServeServer::start(
            store,
            ServerOptions {
                dev_tls: true,
                ..ServerOptions::default()
            },
        )
        .await
        {
            Ok(server) => {
                let tls_addr = server
                    .bound_listeners()
                    .iter()
                    .find(|b| b.kind == ListenerKind::HttpsTcp)
                    .ok_or("missing HttpsTcp listener")?
                    .local_addr;
                let http_addr = server
                    .bound_listeners()
                    .iter()
                    .find(|b| b.kind == ListenerKind::HttpRedirect)
                    .ok_or("missing HttpRedirect listener")?
                    .local_addr;
                return Ok((server, tls_addr, http_addr, tls_port, http_port));
            }
            Err(CoreError::Bind { source, addr }) if source.kind() == ErrorKind::AddrInUse => {
                last_err = Some(CoreError::Bind { addr, source }.into());
            }
            Err(err) => return Err(err.into()),
        }
    }
    Err(last_err.unwrap_or_else(|| "exhausted bind retries".into()))
}

async fn connect_h1_plain(
    addr: SocketAddr,
) -> Result<
    (
        hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
        tokio::task::JoinHandle<()>,
    ),
    Box<dyn std::error::Error>,
> {
    let tcp = TcpStream::connect(addr).await?;
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    let handle = tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok((sender, handle))
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

async fn serve_mock_fastcgi<S>(
    mut stream: S,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut raw_params = Vec::new();
    let req_id;
    loop {
        let rec = read_record(&mut stream).await?;
        match rec.record_type {
            RecordType::Params if !rec.content.is_empty() => {
                raw_params.extend_from_slice(&rec.content);
            }
            RecordType::Stdin if rec.content.is_empty() => {
                req_id = rec.request_id;
                break;
            }
            _ => {}
        }
    }
    let params: HashMap<String, String> = decode_params(&raw_params)?.into_iter().collect();
    let get = |k: &str| params.get(k).map_or("<unset>", String::as_str);
    // Intentionally include HSTS from backend to prove MiraServe strips it over plain HTTP.
    let payload = format!(
        "Content-Type: text/plain\r\nStrict-Transport-Security: max-age=9999\r\n\r\nREQUEST_SCHEME={}\nHTTPS={}\nSERVER_PORT={}\nHTTP_HOST={}\n",
        get("REQUEST_SCHEME"),
        get("HTTPS"),
        get("SERVER_PORT"),
        get("HTTP_HOST"),
    );
    write_stream_records(
        &mut stream,
        RecordType::Stdout,
        req_id,
        payload.as_bytes(),
        true,
    )
    .await?;
    let end = EndRequestBody {
        app_status: 0,
        protocol_status: 0,
    }
    .encode();
    write_record(&mut stream, RecordType::EndRequest, req_id, &end).await?;
    stream.flush().await?;
    Ok(())
}

async fn spawn_proxy_and_ws_upstream()
-> Result<(SocketAddr, tokio::task::AbortHandle), std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(|mut req: Request<Incoming>| async move {
                    if req.uri().path() == "/ws" {
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
                            .body(Full::new(Bytes::new()))
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())));
                        return Ok::<_, std::convert::Infallible>(resp);
                    }
                    let proto = req
                        .headers()
                        .get("x-forwarded-proto")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("<missing>");
                    let body = format!("proto={proto};path={}", req.uri().path());
                    let resp = Response::builder()
                        .status(StatusCode::OK)
                        .header(STRICT_TRANSPORT_SECURITY, "max-age=12345")
                        .header(ALT_SVC, "h3=\":443\"")
                        .body(Full::new(Bytes::from(body)))
                        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())));
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
async fn plain_http_static_golden_redirect_421_acme_relative_redirects_and_h2c_redirects()
-> TestResult {
    let serve_root = TempDir::new("serve")?;
    let redir_root = TempDir::new("redir")?;
    fs::write(serve_root.path.join("hello.txt"), b"hello over http80")?;
    fs::create_dir_all(serve_root.path.join("sub"))?;
    fs::write(serve_root.path.join("sub").join("index.html"), b"sub-index")?;
    fs::write(redir_root.path.join("index.html"), b"redir-site")?;

    let (server, _https_addr, http_addr, tls_port, http_port) =
        start_server_retrying(|tls_port, http_port| {
            format!(
                r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h3,h2,h1"
    listen "127.0.0.1:{http_port}" redirect-https=#true
}}
site "plain.example.test" {{
    http "serve"
    security-headers "strict"
    headers {{
        set "Strict-Transport-Security" "max-age=63072000"
        set "Alt-Svc" "h3=\":443\""
    }}
    root "{serve_root}"
    route "/old" {{
        redirect "/new" status=302
    }}
}}
site "redir.example.test" {{
    http "redirect"
    root "{redir_root}"
}}
"#,
                serve_root = serve_root.kdl_str(),
                redir_root = redir_root.kdl_str(),
            )
        })
        .await?;
    let (mut sender, conn_task) = connect_h1_plain(http_addr).await?;

    // 1. Static file 200 over plain HTTP: no HSTS, no Alt-Svc (even with site headers rule),
    //    other strict security headers present.
    let resp = sender
        .send_request(
            Request::builder()
                .uri("/hello.txt")
                .header(HOST, format!("plain.example.test:{http_port}"))
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get(STRICT_TRANSPORT_SECURITY).is_none(),
        "plain HTTP must never emit Strict-Transport-Security"
    );
    assert!(
        resp.headers().get(ALT_SVC).is_none(),
        "plain HTTP must never emit Alt-Svc"
    );
    assert_eq!(
        resp.headers()
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        resp.headers()
            .get("x-frame-options")
            .and_then(|v| v.to_str().ok()),
        Some("DENY")
    );
    assert_eq!(
        resp.headers()
            .get("referrer-policy")
            .and_then(|v| v.to_str().ok()),
        Some("strict-origin-when-cross-origin")
    );
    assert_eq!(
        resp.into_body().collect().await?.to_bytes().as_ref(),
        b"hello over http80"
    );

    // 2. Server-generated redirects (directory slash and relative `redirect` handler) stay
    //    relative, preserving the request's scheme (`http`) and port.
    let dir_resp = sender
        .send_request(
            Request::builder()
                .uri("/sub?k=v")
                .header(HOST, format!("plain.example.test:{http_port}"))
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(dir_resp.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(
        dir_resp
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/sub/?k=v")
    );

    let rel_resp = sender
        .send_request(
            Request::builder()
                .uri("/old")
                .header(HOST, format!("plain.example.test:{http_port}"))
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(rel_resp.status(), StatusCode::FOUND);
    assert_eq!(
        rel_resp
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/new")
    );

    // 3. Unknown host -> 421 Misdirected Request.
    let unknown_resp = sender
        .send_request(
            Request::builder()
                .uri("/")
                .header(HOST, "unknown.attacker.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(unknown_resp.status(), StatusCode::MISDIRECTED_REQUEST);

    // 4. ACME HTTP-01 token served for BOTH `http "redirect"` and `http "serve"` sites.
    server.acme_store().set_http01_token(
        "redir.example.test",
        "tok-redir-01",
        "tok-redir-01.thumb".to_owned(),
    );
    server.acme_store().set_http01_token(
        "plain.example.test",
        "tok-serve-02",
        "tok-serve-02.thumb".to_owned(),
    );
    for (host, tok, expected) in [
        (
            "redir.example.test",
            "tok-redir-01",
            b"tok-redir-01.thumb".as_slice(),
        ),
        (
            "plain.example.test",
            "tok-serve-02",
            b"tok-serve-02.thumb".as_slice(),
        ),
    ] {
        let acme = sender
            .send_request(
                Request::builder()
                    .uri(format!("/.well-known/acme-challenge/{tok}"))
                    .header(HOST, host)
                    .body(Empty::<Bytes>::new())?,
            )
            .await?;
        assert_eq!(acme.status(), StatusCode::OK, "ACME token for {host}");
        assert_eq!(
            acme.into_body().collect().await?.to_bytes().as_ref(),
            expected
        );
    }
    conn_task.abort();

    // 5. Golden v0.1.2 wire bytes for `http "redirect"` site (raw TCP inspection).
    let mut raw = TcpStream::connect(http_addr).await?;
    raw.write_all(
        b"GET /docs?q=1 HTTP/1.1\r\nHost: redir.example.test\r\nConnection: close\r\n\r\n",
    )
    .await?;
    let mut wire = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), raw.read_to_end(&mut wire)).await??;
    let wire_str = String::from_utf8(wire)?;
    let normalized = normalize_http_date_header(&wire_str);
    let expected_golden = format!(
        "HTTP/1.1 308 Permanent Redirect\r\n\
location: https://redir.example.test:{tls_port}/docs?q=1\r\n\
server: MiraServe\r\n\
x-content-type-options: nosniff\r\n\
connection: close\r\n\
content-length: 0\r\n\
date: <DATE>\r\n\r\n"
    );
    assert_eq!(
        normalized, expected_golden,
        "http \"redirect\" wire bytes must match v0.1.2 golden output exactly"
    );

    // 6. Cleartext HTTP/2 (h2c prior knowledge) keeps v0.1.2 behaviour on the redirect listener
    //    and NEVER enters serve mode: a real h2c request for an `http "serve"` site receives the
    //    v0.1.2 `308 Permanent Redirect`, unknown host gets `421`, and ACME tokens still work.
    let h2c_tcp = TcpStream::connect(http_addr).await?;
    let (mut h2_sender, h2_conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(h2c_tcp)).await?;
    let h2_task = tokio::spawn(async move {
        let _ = h2_conn.await;
    });

    let h2_serve_resp = h2_sender
        .send_request(
            Request::builder()
                .uri("http://plain.example.test/hello.txt?k=1")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(
        h2_serve_resp.status(),
        StatusCode::PERMANENT_REDIRECT,
        "h2c request for an http \"serve\" site must never be served; expected v0.1.2 308"
    );
    assert_eq!(
        h2_serve_resp
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some(format!("https://plain.example.test:{tls_port}/hello.txt?k=1").as_str())
    );
    let _ = h2_serve_resp.into_body().collect().await?;

    let h2_unknown = h2_sender
        .send_request(
            Request::builder()
                .uri("http://unknown.attacker.test/")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(h2_unknown.status(), StatusCode::MISDIRECTED_REQUEST);
    let _ = h2_unknown.into_body().collect().await?;

    let h2_acme = h2_sender
        .send_request(
            Request::builder()
                .uri("http://plain.example.test/.well-known/acme-challenge/tok-serve-02")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(h2_acme.status(), StatusCode::OK);
    assert_eq!(
        h2_acme.into_body().collect().await?.to_bytes().as_ref(),
        b"tok-serve-02.thumb"
    );
    h2_task.abort();

    server.shutdown().await;
    Ok(())
}

fn normalize_http_date_header(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for part in raw.split_inclusive("\r\n") {
        if part.starts_with("date: ") {
            out.push_str("date: <DATE>\r\n");
        } else {
            out.push_str(part);
        }
    }
    out
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn plain_http_fastcgi_params_proxy_proto_and_websocket_upgrade() -> TestResult {
    let root = TempDir::new("fcgi-proxy-ws")?;
    fs::write(root.path.join("info.php"), b"<?php echo 'ok';")?;

    let fcgi_listener = TcpListener::bind("127.0.0.1:0").await?;
    let fcgi_addr = fcgi_listener.local_addr()?;
    let fcgi_task = tokio::spawn(async move {
        while let Ok((stream, _)) = fcgi_listener.accept().await {
            tokio::spawn(async move {
                let _ = serve_mock_fastcgi(stream).await;
            });
        }
    });
    let (up_addr, up_abort) = spawn_proxy_and_ws_upstream().await?;

    let root_str = root.kdl_str();
    let (server, _https_addr, http_addr, _tls_port, http_port) =
        start_server_retrying(|tls_port, http_port| {
            format!(
                r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    listen "127.0.0.1:{http_port}" redirect-https=#true
    timeouts {{ graceful-drain "2s" }}
}}
site "app.example.test" {{
    http "serve"
    root "{root_str}"
    route "*.php" {{
        fastcgi-pass "tcp://{fcgi_addr}"
    }}
    route "/api/*" {{
        reverse-proxy {{ upstream "http://{up_addr}" }}
    }}
    route "/ws" {{
        reverse-proxy {{ upstream "http://{up_addr}" }}
    }}
}}
"#
            )
        })
        .await?;
    let (mut sender, conn_task) = connect_h1_plain(http_addr).await?;

    // 1. FastCGI over plain HTTP: REQUEST_SCHEME=http, no HTTPS, SERVER_PORT=http_port, no HSTS.
    let fcgi_resp = sender
        .send_request(
            Request::builder()
                .uri("/info.php")
                .header(HOST, format!("app.example.test:{http_port}"))
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(fcgi_resp.status(), StatusCode::OK);
    assert!(fcgi_resp.headers().get(STRICT_TRANSPORT_SECURITY).is_none());
    let fcgi_body = String::from_utf8(fcgi_resp.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(
        fcgi_body.contains("REQUEST_SCHEME=http\n"),
        "body: {fcgi_body}"
    );
    assert!(fcgi_body.contains("HTTPS=<unset>\n"), "body: {fcgi_body}");
    assert!(
        fcgi_body.contains(&format!("SERVER_PORT={http_port}\n")),
        "SERVER_PORT must be the plain-HTTP listener port ({http_port}), body: {fcgi_body}"
    );

    // 2. Reverse proxy over plain HTTP: X-Forwarded-Proto=http, upstream HSTS & Alt-Svc stripped.
    let proxy_resp = sender
        .send_request(
            Request::builder()
                .uri("/api/items")
                .header(HOST, "app.example.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(proxy_resp.status(), StatusCode::OK);
    assert!(
        proxy_resp
            .headers()
            .get(STRICT_TRANSPORT_SECURITY)
            .is_none()
    );
    assert!(proxy_resp.headers().get(ALT_SVC).is_none());
    let proxy_body =
        String::from_utf8(proxy_resp.into_body().collect().await?.to_bytes().to_vec())?;
    assert_eq!(proxy_body, "proto=http;path=/api/items");
    conn_task.abort();

    // 3. WebSocket upgrade over plain HTTP works identically to HTTPS.
    let ws_tcp = TcpStream::connect(http_addr).await?;
    let (mut ws_sender, ws_conn) =
        hyper::client::conn::http1::handshake(TokioIo::new(ws_tcp)).await?;
    let ws_conn_task = tokio::spawn(async move {
        let _ = ws_conn.with_upgrades().await;
    });
    let ws_req = Request::builder()
        .method(Method::GET)
        .uri("/ws")
        .header(HOST, "app.example.test")
        .header(CONNECTION, "Upgrade")
        .header(UPGRADE, "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .body(Empty::<Bytes>::new())?;
    let ws_resp = ws_sender.send_request(ws_req).await?;
    assert_eq!(ws_resp.status(), StatusCode::SWITCHING_PROTOCOLS);
    let upgraded = hyper::upgrade::on(ws_resp).await?;
    let mut ws_io = TokioIo::new(upgraded);
    ws_io.write_all(b"ping-http80").await?;
    let mut echo = [0_u8; 11];
    tokio::time::timeout(Duration::from_secs(3), ws_io.read_exact(&mut echo)).await??;
    assert_eq!(&echo, b"ping-http80");
    drop(ws_io);
    ws_conn_task.abort();

    fcgi_task.abort();
    up_abort.abort();
    server.shutdown().await;
    Ok(())
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn plain_http_basic_auth_returns_403_without_challenge_or_credential_evaluation() -> TestResult
{
    let root = TempDir::new("basic-auth")?;
    let auth_dir = TempDir::new("htpasswd")?;
    fs::write(root.path.join("secret.txt"), b"top-secret-content")?;
    fs::write(root.path.join("403.html"), b"CUSTOM-SITE-403-MUST-NOT-LEAK")?;

    let users_path = auth_dir.path.join("users");
    fs::write(&users_path, HTPASSWD_ANN_S3CRET)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&auth_dir.path, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&users_path, fs::Permissions::from_mode(0o600))?;
    }

    let users_str = users_path.to_string_lossy().replace('\\', "/");
    let root_str = root.kdl_str();
    let (server, tls_addr, http_addr, _tls_port, _http_port) =
        start_server_retrying(|tls_port, http_port| {
            format!(
                r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    listen "127.0.0.1:{http_port}" redirect-https=#true
}}
site "members.example.test" {{
    http "serve"
    basic-auth "{users_str}" realm="Members"
    headers {{
        set "WWW-Authenticate" "Basic realm=\"SiteInjected\""
    }}
    error-pages {{ page 403 "/403.html" }}
    root "{root_str}"
    route "/secret.txt" {{
        headers {{
            set "WWW-Authenticate" "Basic realm=\"RouteInjected\""
        }}
        root "{root_str}"
        static
    }}
}}
"#
            )
        })
        .await?;
    let (mut plain, plain_task) = connect_h1_plain(http_addr).await?;

    // 1. Plain HTTP with NO credentials -> 403 standard built-in error page, no WWW-Authenticate.
    let no_creds = plain
        .send_request(
            Request::builder()
                .uri("/secret.txt")
                .header(HOST, "members.example.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(no_creds.status(), StatusCode::FORBIDDEN);
    assert!(no_creds.headers().get(WWW_AUTHENTICATE).is_none());
    assert!(no_creds.headers().get(STRICT_TRANSPORT_SECURITY).is_none());
    assert_eq!(
        no_creds
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let body = String::from_utf8(no_creds.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(
        !body.contains("CUSTOM-SITE-403-MUST-NOT-LEAK"),
        "plain-HTTP basic-auth 403 must serve the standard built-in error page, got: {body}"
    );
    assert!(!body.contains("top-secret-content"));

    // 2. Plain HTTP with VALID credentials -> still 403, never accepted over cleartext.
    let valid_plain = plain
        .send_request(
            Request::builder()
                .uri("/secret.txt")
                .header(HOST, "members.example.test")
                .header(AUTHORIZATION, BASIC_ANN_VALID)
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(valid_plain.status(), StatusCode::FORBIDDEN);
    assert!(valid_plain.headers().get(WWW_AUTHENTICATE).is_none());
    let _ = valid_plain.into_body().collect().await?;

    // 3. Repeated wrong credentials over plain HTTP -> ALWAYS 403 (never 429), proving
    //    credentials are never evaluated and the brute-force throttle is never touched.
    for _ in 0..15 {
        let r = plain
            .send_request(
                Request::builder()
                    .uri("/secret.txt")
                    .header(HOST, "members.example.test")
                    .header(AUTHORIZATION, BASIC_ANN_WRONG)
                    .body(Empty::<Bytes>::new())?,
            )
            .await?;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert!(r.headers().get(WWW_AUTHENTICATE).is_none());
        let _ = r.into_body().collect().await?;
    }
    plain_task.abort();

    // 4. Control over HTTPS: valid credentials succeed with 200 (also proving the 15 plaintext
    //    attempts did not trip HTTPS brute-force throttling!).
    let dev_pem = server.dev_cert_pem().ok_or("expected dev cert PEM")?;
    let tls_conn = build_h1_tls_connector(dev_pem)?
        .connect(
            ServerName::try_from("members.example.test".to_owned())?,
            TcpStream::connect(tls_addr).await?,
        )
        .await?;
    let (mut https, https_task) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_conn)).await?;
    let https_join = tokio::spawn(async move {
        let _ = https_task.await;
    });
    let ok_https = https
        .send_request(
            Request::builder()
                .uri("/secret.txt")
                .header(HOST, "members.example.test")
                .header(AUTHORIZATION, BASIC_ANN_VALID)
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(ok_https.status(), StatusCode::OK);
    assert_eq!(
        ok_https.into_body().collect().await?.to_bytes().as_ref(),
        b"top-secret-content"
    );
    https_join.abort();

    server.shutdown().await;
    Ok(())
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn plain_http_basic_auth_with_credentials_opt_in_throttles_and_reverts_on_reload()
-> TestResult {
    let root = TempDir::new("basic-auth-optin")?;
    let auth_dir = TempDir::new("htpasswd-optin")?;
    fs::write(root.path.join("secret.txt"), b"top-secret-optin")?;
    fs::write(root.path.join("403.html"), b"CUSTOM-SITE-403-MUST-NOT-LEAK")?;

    let users_path = auth_dir.path.join("users");
    fs::write(&users_path, HTPASSWD_ANN_S3CRET)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&auth_dir.path, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&users_path, fs::Permissions::from_mode(0o600))?;
    }

    let make_kdl_for = |tls_port: u16, http_port: u16, http_line: &str| {
        format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h3,h2,h1"
    listen "127.0.0.1:{http_port}" redirect-https=#true
}}
site "members-plain.example.test" {{
    {http_line}
    security-headers "strict"
    basic-auth "{users}" realm="Members"
    error-pages {{ page 403 "/403.html" }}
    root "{root}"
}}
"#,
            users = users_path.to_string_lossy().replace('\\', "/"),
            root = root.kdl_str(),
        )
    };

    let (server, tls_addr, http_addr, tls_port, http_port) =
        start_server_retrying(|t, h| make_kdl_for(t, h, r#"http "serve" credentials=#true"#))
            .await?;
    let make_kdl = |http_line: &str| make_kdl_for(tls_port, http_port, http_line);
    // Keep ONE plain-HTTP keep-alive connection open across all requests and reloads.
    let (mut plain, plain_task) = connect_h1_plain(http_addr).await?;

    // 1. No credentials -> 401 with WWW-Authenticate challenge and Cache-Control: no-store.
    let no_creds = plain
        .send_request(
            Request::builder()
                .uri("/secret.txt")
                .header(HOST, "members-plain.example.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(no_creds.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        no_creds
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok()),
        Some("Basic realm=\"Members\", charset=\"UTF-8\"")
    );
    assert_eq!(
        no_creds
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    assert!(no_creds.headers().get(STRICT_TRANSPORT_SECURITY).is_none());
    assert!(no_creds.headers().get(ALT_SVC).is_none());
    let _ = no_creds.into_body().collect().await?;

    // 2. Wrong credentials -> 401 with challenge and Cache-Control: no-store (failure #1).
    let wrong = plain
        .send_request(
            Request::builder()
                .uri("/secret.txt")
                .header(HOST, "members-plain.example.test")
                .header(AUTHORIZATION, BASIC_ANN_WRONG)
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        wrong
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok()),
        Some("Basic realm=\"Members\", charset=\"UTF-8\"")
    );
    assert_eq!(
        wrong
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let _ = wrong.into_body().collect().await?;

    // 3. Right credentials -> 200 OK, private Cache-Control, no HSTS/Alt-Svc.
    let ok = plain
        .send_request(
            Request::builder()
                .uri("/secret.txt")
                .header(HOST, "members-plain.example.test")
                .header(AUTHORIZATION, BASIC_ANN_VALID)
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(ok.status(), StatusCode::OK);
    assert!(ok.headers().get(STRICT_TRANSPORT_SECURITY).is_none());
    assert!(ok.headers().get(ALT_SVC).is_none());
    assert!(
        ok.headers()
            .get(CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("private")),
        "expected private Cache-Control on protected 200, got: {:?}",
        ok.headers().get(CACHE_CONTROL)
    );
    assert_eq!(
        ok.into_body().collect().await?.to_bytes().as_ref(),
        b"top-secret-optin"
    );

    // 4. Reload removing `credentials=#true` on the SAME open keep-alive connection -> 403 again
    //    (even with previously cached valid credentials, and without WWW-Authenticate).
    server.reload_from_str("remove-creds.kdl", &make_kdl(r#"http "serve""#))?;
    for maybe_auth in [Some(BASIC_ANN_VALID), None] {
        let mut req_builder = Request::builder()
            .uri("/secret.txt")
            .header(HOST, "members-plain.example.test");
        if let Some(auth_val) = maybe_auth {
            req_builder = req_builder.header(AUTHORIZATION, auth_val);
        }
        let refused = plain
            .send_request(req_builder.body(Empty::<Bytes>::new())?)
            .await?;
        assert_eq!(
            refused.status(),
            StatusCode::FORBIDDEN,
            "expected 403 after removing credentials=#true (auth={maybe_auth:?})"
        );
        assert!(refused.headers().get(WWW_AUTHENTICATE).is_none());
        assert_eq!(
            refused
                .headers()
                .get(CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
        let body = String::from_utf8(refused.into_body().collect().await?.to_bytes().to_vec())?;
        assert!(!body.contains("CUSTOM-SITE-403-MUST-NOT-LEAK"));
        assert!(!body.contains("top-secret-optin"));
    }

    // 5. Reload re-enabling `credentials=#true` -> repeated wrong attempts hit 429 Too Many
    //    Requests using the exact same shared failure table and limits as HTTPS (10/min).
    server.reload_from_str(
        "restore-creds.kdl",
        &make_kdl(r#"http "serve" credentials=#true"#),
    )?;
    // Failure #1 was recorded in step 2 (preserved across reloads); 9 more reach the 10-failure
    // limit, and the next wrong attempt must be throttled with 429 + Retry-After + no-store.
    let mut throttled = false;
    for _ in 0..12 {
        let r = plain
            .send_request(
                Request::builder()
                    .uri("/secret.txt")
                    .header(HOST, "members-plain.example.test")
                    .header(AUTHORIZATION, BASIC_ANN_WRONG)
                    .body(Empty::<Bytes>::new())?,
            )
            .await?;
        let status = r.status();
        let has_retry_after = r.headers().get(RETRY_AFTER).is_some();
        let has_www_auth = r.headers().get(WWW_AUTHENTICATE).is_some();
        let cache_control = r
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let _ = r.into_body().collect().await?;
        if status == StatusCode::TOO_MANY_REQUESTS {
            assert!(has_retry_after, "429 must include Retry-After");
            assert!(!has_www_auth, "429 must not include WWW-Authenticate");
            assert_eq!(cache_control.as_deref(), Some("no-store"));
            throttled = true;
            break;
        }
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "expected 401 before throttling"
        );
    }
    assert!(
        throttled,
        "repeated wrong credentials over plain HTTP with credentials=#true must throttle with 429"
    );
    plain_task.abort();

    // 6. Control over HTTPS from the same IP: shares the exact same FailureTable, so a wrong
    //    attempt over HTTPS is immediately throttled with 429 as well.
    let dev_pem = server.dev_cert_pem().ok_or("expected dev cert PEM")?;
    let tls_conn = build_h1_tls_connector(dev_pem)?
        .connect(
            ServerName::try_from("members-plain.example.test".to_owned())?,
            TcpStream::connect(tls_addr).await?,
        )
        .await?;
    let (mut https, https_task) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_conn)).await?;
    let https_join = tokio::spawn(async move {
        let _ = https_task.await;
    });
    let https_throttled = https
        .send_request(
            Request::builder()
                .uri("/secret.txt")
                .header(HOST, "members-plain.example.test")
                .header(AUTHORIZATION, BASIC_ANN_WRONG)
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(
        https_throttled.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "plain-HTTP failures must share the exact same throttle table with HTTPS"
    );
    https_join.abort();

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn plain_http_suspended_and_quarantined_sites_answer_503_directly() -> TestResult {
    let owner = TempDir::new("owner")?;
    let outside = TempDir::new("outside")?;
    fs::write(outside.path.join("index.html"), b"outside-root")?;

    let owner_str = owner.kdl_str();
    let outside_str = outside.kdl_str();
    let (server, _https_addr, http_addr, _tls_port, _http_port) =
        start_server_retrying(|tls_port, http_port| {
            format!(
                r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    listen "127.0.0.1:{http_port}" redirect-https=#true
}}
site "suspended.example.test" {{
    http "serve"
    route "/*" {{ respond 503 }}
}}
site "quarantined.example.test" {{
    http "serve"
    owner-dir "{owner_str}"
    root "{outside_str}"
}}
"#
            )
        })
        .await?;
    let (mut sender, conn_task) = connect_h1_plain(http_addr).await?;

    for host in ["suspended.example.test", "quarantined.example.test"] {
        let resp = sender
            .send_request(
                Request::builder()
                    .uri("/")
                    .header(HOST, host)
                    .body(Empty::<Bytes>::new())?,
            )
            .await?;
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "expected direct 503 over plain HTTP for {host}"
        );
        assert!(resp.headers().get(LOCATION).is_none());
        assert!(resp.headers().get(STRICT_TRANSPORT_SECURITY).is_none());
        assert!(resp.headers().get(ALT_SVC).is_none());
        let _ = resp.into_body().collect().await?;
    }

    conn_task.abort();
    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn plain_http_reload_flips_redirect_to_serve_and_back_on_open_keepalive_connection()
-> TestResult {
    let root = TempDir::new("reload-flip")?;
    fs::write(root.path.join("page.txt"), b"served-live-over-http")?;

    let root_str = root.kdl_str();
    let make_kdl = |tls_port: u16, http_port: u16, mode: &str| {
        format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    listen "127.0.0.1:{http_port}" redirect-https=#true
}}
site "flip.example.test" {{
    http "{mode}"
    root "{root_str}"
}}
"#
        )
    };

    let (server, _https_addr, http_addr, tls_port, http_port) =
        start_server_retrying(|tls_port, http_port| make_kdl(tls_port, http_port, "redirect"))
            .await?;
    // Keep ONE single HTTP/1.1 keep-alive TCP connection open across both reloads.
    let (mut sender, conn_task) = connect_h1_plain(http_addr).await?;

    let r1 = sender
        .send_request(
            Request::builder()
                .uri("/page.txt")
                .header(HOST, "flip.example.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(r1.status(), StatusCode::PERMANENT_REDIRECT);
    let _ = r1.into_body().collect().await?;

    // Flip `redirect` -> `serve` while the connection stays open.
    server.reload_from_str("flip-serve.kdl", &make_kdl(tls_port, http_port, "serve"))?;
    let r2 = sender
        .send_request(
            Request::builder()
                .uri("/page.txt")
                .header(HOST, "flip.example.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(r2.status(), StatusCode::OK);
    assert_eq!(
        r2.into_body().collect().await?.to_bytes().as_ref(),
        b"served-live-over-http"
    );

    // Flip `serve` -> `redirect` again on the very same open connection.
    server.reload_from_str(
        "flip-redirect.kdl",
        &make_kdl(tls_port, http_port, "redirect"),
    )?;
    let r3 = sender
        .send_request(
            Request::builder()
                .uri("/page.txt")
                .header(HOST, "flip.example.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(r3.status(), StatusCode::PERMANENT_REDIRECT);
    let _ = r3.into_body().collect().await?;

    conn_task.abort();
    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn plain_http_bad_request_strikes_close_connections_for_both_redirect_and_serve_sites()
-> TestResult {
    let root = TempDir::new("strikes")?;
    fs::write(root.path.join("ok.txt"), b"ok")?;

    let root_str = root.kdl_str();
    let (server, _https_addr, http_addr, _tls_port, _http_port) =
        start_server_retrying(|tls_port, http_port| {
            format!(
                r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    listen "127.0.0.1:{http_port}" redirect-https=#true
}}
site "redir.example.test" {{
    http "redirect"
    root "{root_str}"
}}
site "serve.example.test" {{
    http "serve"
    root "{root_str}"
}}
"#
            )
        })
        .await?;

    // Check 4 cases on separate persistent connections:
    // 1. `http "redirect"` hitting first-pass bad path (`/../bad`)
    // 2. `http "redirect"` hitting first-pass bad Host (`bad..host`)
    // 3. `http "serve"` hitting normal-pipeline bad path (`/../bad`)
    // 4. `http "serve"` hitting normal-pipeline strict-fs framing rejection (`/a%2Fb`)
    for (host, bad_uri) in [
        ("redir.example.test", "/../bad"),
        ("bad..host", "/"),
        ("serve.example.test", "/../bad"),
        ("serve.example.test", "/a%2Fb"),
    ] {
        let (mut sender, conn_task) = connect_h1_plain(http_addr).await?;
        // DEFAULT_MAX_BAD_REQUESTS = 20; strikes must be counted ONCE per request:
        // - attempts 1..=20 MUST all succeed with 400 (fails if closed early / double-counted)
        // - attempt 21 MUST return 400 and immediately trigger v0.1.2's graceful close
        // - without sending a 22nd request, the server MUST close the connection promptly
        //   (fails if closed later than v0.1.2's exact 21st-strike threshold).
        for attempt in 1..=21 {
            let req = Request::builder()
                .uri(bad_uri)
                .header(HOST, host)
                .body(Empty::<Bytes>::new())?;
            let resp = sender.send_request(req).await.map_err(|err| {
                format!(
                    "connection closed too early before strike {attempt} for {host} {bad_uri}: {err}"
                )
            })?;
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "expected 400 on attempt {attempt} for {host} {bad_uri}"
            );
            let _ = resp.into_body().collect().await?;
        }
        // Drop the client sender handle only AFTER confirming the server itself closes the
        // connection on strike 21 (the idle keep-alive timeout is 60s, so a 2s timeout fails if
        // the server did not initiate graceful close on strike 21).
        let closed_by_server = tokio::time::timeout(Duration::from_secs(2), conn_task).await;
        assert!(
            closed_by_server.is_ok(),
            "connection was not closed by server after exact 21st strike (later than v0.1.2) for {host} {bad_uri}"
        );
        drop(sender);
    }

    server.shutdown().await;
    Ok(())
}

async fn raw_tcp_exchange(
    addr: SocketAddr,
    request: &[u8],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut raw = TcpStream::connect(addr).await?;
    raw.write_all(request).await?;
    let mut wire = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), raw.read_to_end(&mut wire)).await??;
    Ok(String::from_utf8(wire)?)
}

/// Normalizes only dynamic per-response wire fields (`date`, `x-request-id` / `Request ID:`,
/// and the random CSP `nonce-...` token) while asserting their exact syntax and consistency
/// between headers and body.
fn normalize_v012_wire_response(raw: &str) -> Result<String, Box<dyn std::error::Error>> {
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .ok_or_else(|| format!("missing CRLFCRLF header terminator in raw response: {raw:?}"))?;
    let mut req_id_from_header: Option<String> = None;
    let mut norm_head = String::with_capacity(head.len());
    for (idx, line) in head.split("\r\n").enumerate() {
        if idx > 0 {
            norm_head.push_str("\r\n");
        }
        if let Some(date_val) = line.strip_prefix("date: ") {
            assert!(
                date_val.ends_with(" GMT") && date_val.len() >= 25,
                "unexpected Date header format: {date_val:?}"
            );
            norm_head.push_str("date: <DATE>");
        } else if let Some(req_id) = line.strip_prefix("x-request-id: ") {
            assert_eq!(
                req_id.len(),
                26,
                "x-request-id must be a 26-char Crockford Base32 ULID: {req_id:?}"
            );
            assert!(
                req_id.bytes().all(|b| matches!(
                    b,
                    b'0'..=b'9' | b'A'..=b'H' | b'J'..=b'K' | b'M'..=b'N' | b'P'..=b'T' | b'V'..=b'Z'
                )),
                "invalid Crockford Base32 ULID in x-request-id: {req_id:?}"
            );
            req_id_from_header = Some(req_id.to_owned());
            norm_head.push_str("x-request-id: <REQUEST_ID>");
        } else if let Some(prefix_idx) = line.find("style-src 'nonce-") {
            let after_prefix = line
                .get(prefix_idx + "style-src 'nonce-".len()..)
                .ok_or("malformed CSP nonce prefix")?;
            let end_quote = after_prefix
                .find('\'')
                .ok_or("missing closing quote on CSP nonce")?;
            let nonce = after_prefix
                .get(..end_quote)
                .ok_or("malformed CSP nonce slice")?;
            assert_eq!(
                nonce.len(),
                22,
                "CSP nonce must be 22 URL-safe base64 chars (128-bit): {nonce:?}"
            );
            assert!(
                nonce
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                "invalid base64url chars in CSP nonce: {nonce:?}"
            );
            let before = line.get(..prefix_idx).ok_or("CSP slice error")?;
            let after = after_prefix.get(end_quote..).ok_or("CSP suffix error")?;
            norm_head.push_str(before);
            norm_head.push_str("style-src 'nonce-<NONCE>");
            norm_head.push_str(after);
        } else {
            norm_head.push_str(line);
        }
    }

    let norm_body = if let Some(req_id) = req_id_from_header {
        let needle = format!("Request ID: {req_id}\n");
        assert!(
            body.contains(&needle),
            "response body must carry the same Request ID as x-request-id header ({req_id}); body: {body:?}"
        );
        body.replace(&needle, "Request ID: <REQUEST_ID>\n")
    } else {
        body.to_owned()
    };

    Ok(format!("{norm_head}\r\n\r\n{norm_body}"))
}

/// Raw-TCP golden wire-byte comparison against `v0.1.2` for the four redirect-listener cases:
/// `http "redirect"` (308 over HTTP/1.1 & HTTP/1.0), unknown host (421), bad Host (400 invalid
/// Host on HTTP/1.1, missing Host on HTTP/1.0, and missing Host on HTTP/1.1), and ACME HTTP-01
/// token (200).
///
/// Provenance: all seven normalized golden strings were captured and verified verbatim on a
/// detached worktree of tag `v0.1.2` (commit `4d5891d`, tree identical to `main` `da07274`) using
/// `cargo test -p miraserve-core --test http80_serve redirect_listener_raw_tcp_v012_golden_bytes_308_421_400_and_acme --locked`
/// (with `include_serve_site = false`).
///
/// Note: the second iteration (`include_serve_site = true`) adds a sibling `http "serve"` site
/// and therefore cannot run verbatim on `v0.1.2` (whose KDL parser rejects `http "serve"`). It
/// pins that introducing a serve-mode neighbor does not alter any redirect-listener golden bytes.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn redirect_listener_raw_tcp_v012_golden_bytes_308_421_400_and_acme() -> TestResult {
    let root = TempDir::new("golden-v012")?;
    fs::write(root.path.join("index.html"), b"golden-site")?;

    for include_serve_site in [false, true] {
        let extra_site = if include_serve_site {
            format!(
                r#"
site "plain.example.test" {{
    http "serve"
    root "{root}"
}}
"#,
                root = root.kdl_str(),
            )
        } else {
            String::new()
        };
        let (server, _tls_addr, http_addr, tls_port, _http_port) =
            start_server_retrying(|tls_port, http_port| {
                format!(
                    r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h3,h2,h1"
    listen "127.0.0.1:{http_port}" redirect-https=#true
}}
site "redir.example.test" {{
    root "{root}"
}}
{extra_site}
"#,
                    root = root.kdl_str(),
                )
            })
            .await?;
        server.acme_store().set_http01_token(
            "redir.example.test",
            "tok-golden",
            "tok-golden.thumbprint".to_owned(),
        );

        // 1. 308 Permanent Redirect (HTTP/1.1) — exact v0.1.2 wire bytes.
        let raw_308_h11 = raw_tcp_exchange(
            http_addr,
            b"GET /docs?q=1 HTTP/1.1\r\nHost: redir.example.test\r\nConnection: close\r\n\r\n",
        )
        .await?;
        assert_eq!(
            normalize_v012_wire_response(&raw_308_h11)?,
            format!(
                "HTTP/1.1 308 Permanent Redirect\r\n\
location: https://redir.example.test:{tls_port}/docs?q=1\r\n\
server: MiraServe\r\n\
x-content-type-options: nosniff\r\n\
connection: close\r\n\
content-length: 0\r\n\
date: <DATE>\r\n\
\r\n"
            ),
            "308 HTTP/1.1 mismatch (include_serve_site={include_serve_site})"
        );

        // 2. 308 Permanent Redirect (HTTP/1.0) — exact v0.1.2 wire bytes and version handling.
        let raw_308_h10 = raw_tcp_exchange(
            http_addr,
            b"GET /docs?q=1 HTTP/1.0\r\nHost: redir.example.test\r\n\r\n",
        )
        .await?;
        assert_eq!(
            normalize_v012_wire_response(&raw_308_h10)?,
            format!(
                "HTTP/1.0 308 Permanent Redirect\r\n\
location: https://redir.example.test:{tls_port}/docs?q=1\r\n\
server: MiraServe\r\n\
x-content-type-options: nosniff\r\n\
content-length: 0\r\n\
date: <DATE>\r\n\
\r\n"
            ),
            "308 HTTP/1.0 mismatch (include_serve_site={include_serve_site})"
        );

        // 3. 421 Misdirected Request (unknown host) — exact v0.1.2 wire bytes.
        let raw_421 = raw_tcp_exchange(
            http_addr,
            b"GET / HTTP/1.1\r\nHost: unknown.attacker.test\r\nConnection: close\r\n\r\n",
        )
        .await?;
        assert_eq!(
            normalize_v012_wire_response(&raw_421)?,
            "HTTP/1.1 421 Misdirected Request\r\n\
content-type: text/plain; charset=utf-8\r\n\
content-length: 161\r\n\
vary: Accept\r\n\
x-content-type-options: nosniff\r\n\
cache-control: no-store\r\n\
server: MiraServe\r\n\
content-security-policy: default-src 'none'; style-src 'nonce-<NONCE>'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n\
x-request-id: <REQUEST_ID>\r\n\
connection: close\r\n\
date: <DATE>\r\n\
\r\n\
421 Misdirected Request\n\
\n\
The request for unknown.attacker.test was sent over a connection that isn\u{2019}t configured for it.\n\
Request ID: <REQUEST_ID>\n",
            "421 mismatch (include_serve_site={include_serve_site})"
        );

        // 4. 400 Bad Request (invalid Host on HTTP/1.1) — exact v0.1.2 wire bytes.
        let raw_400_bad_host = raw_tcp_exchange(
            http_addr,
            b"GET /bad-host HTTP/1.1\r\nHost: bad..host\r\nConnection: close\r\n\r\n",
        )
        .await?;
        assert_eq!(
            normalize_v012_wire_response(&raw_400_bad_host)?,
            "HTTP/1.1 400 Bad Request\r\n\
content-type: text/plain; charset=utf-8\r\n\
content-length: 155\r\n\
vary: Accept\r\n\
x-content-type-options: nosniff\r\n\
cache-control: no-store\r\n\
server: MiraServe\r\n\
content-security-policy: default-src 'none'; style-src 'nonce-<NONCE>'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n\
x-request-id: <REQUEST_ID>\r\n\
connection: close\r\n\
date: <DATE>\r\n\
\r\n\
400 Bad Request\n\
\n\
The server couldn\u{2019}t read the request for /bad-host. It may be malformed or corrupted on the way.\n\
Request ID: <REQUEST_ID>\n",
            "400 invalid Host mismatch (include_serve_site={include_serve_site})"
        );

        // 5. 400 Bad Request (missing Host on HTTP/1.0 -> router `raw_host` check) — exact v0.1.2 wire bytes.
        let raw_400_no_host_h10 =
            raw_tcp_exchange(http_addr, b"GET /no-host HTTP/1.0\r\n\r\n").await?;
        assert_eq!(
            normalize_v012_wire_response(&raw_400_no_host_h10)?,
            "HTTP/1.0 400 Bad Request\r\n\
content-type: text/plain; charset=utf-8\r\n\
content-length: 154\r\n\
vary: Accept\r\n\
x-content-type-options: nosniff\r\n\
cache-control: no-store\r\n\
server: MiraServe\r\n\
content-security-policy: default-src 'none'; style-src 'nonce-<NONCE>'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n\
x-request-id: <REQUEST_ID>\r\n\
date: <DATE>\r\n\
\r\n\
400 Bad Request\n\
\n\
The server couldn\u{2019}t read the request for /no-host. It may be malformed or corrupted on the way.\n\
Request ID: <REQUEST_ID>\n",
            "400 missing Host HTTP/1.0 mismatch (include_serve_site={include_serve_site})"
        );

        // 6. 400 Bad Request (missing Host on HTTP/1.1 -> `validate_host_consistency` MISSING_HOST) — exact v0.1.2 wire bytes.
        let raw_400_no_host_h11 = raw_tcp_exchange(
            http_addr,
            b"GET /no-host HTTP/1.1\r\nConnection: close\r\n\r\n",
        )
        .await?;
        assert_eq!(
            normalize_v012_wire_response(&raw_400_no_host_h11)?,
            "HTTP/1.1 400 Bad Request\r\n\
content-type: text/plain; charset=utf-8\r\n\
content-length: 154\r\n\
vary: Accept\r\n\
x-content-type-options: nosniff\r\n\
cache-control: no-store\r\n\
server: MiraServe\r\n\
content-security-policy: default-src 'none'; style-src 'nonce-<NONCE>'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n\
x-request-id: <REQUEST_ID>\r\n\
connection: close\r\n\
date: <DATE>\r\n\
\r\n\
400 Bad Request\n\
\n\
The server couldn\u{2019}t read the request for /no-host. It may be malformed or corrupted on the way.\n\
Request ID: <REQUEST_ID>\n",
            "400 missing Host HTTP/1.1 mismatch (include_serve_site={include_serve_site})"
        );

        // 7. 200 OK ACME HTTP-01 token — exact v0.1.2 wire bytes.
        let raw_acme = raw_tcp_exchange(
            http_addr,
            b"GET /.well-known/acme-challenge/tok-golden HTTP/1.1\r\nHost: redir.example.test\r\nConnection: close\r\n\r\n",
        )
        .await?;
        assert_eq!(
            normalize_v012_wire_response(&raw_acme)?,
            "HTTP/1.1 200 OK\r\n\
content-type: text/plain; charset=utf-8\r\n\
x-content-type-options: nosniff\r\n\
cache-control: no-store\r\n\
connection: close\r\n\
content-length: 21\r\n\
date: <DATE>\r\n\
\r\n\
tok-golden.thumbprint",
            "ACME 200 mismatch (include_serve_site={include_serve_site})"
        );

        server.shutdown().await;
    }

    Ok(())
}

/// Pins P1-1: `Host: [::1]:80` and `Host: [::1]` are served for a configured `http "serve"`
/// IPv6 site, while an `http "redirect"` IPv6 site retains the exact unmodified `v0.1.2` bytes.
///
/// Provenance of the redirect-mode golden bytes below: captured on tag `v0.1.2` (commit
/// `4d5891d`, tree identical to `main` `da07274`) with `miraserve run --dev-tls <cfg>` (where
/// `<cfg>` declared `site "::1" { root ... }`) and raw TCP probes sending
/// `GET / HTTP/1.1\r\nHost: [::1]:80\r\nConnection: close\r\n\r\n` and
/// `GET / HTTP/1.1\r\nHost: [::1]\r\nConnection: close\r\n\r\n`.
#[tokio::test]
async fn plain_http_ipv6_host_serves_serve_mode_and_preserves_v012_redirect_bytes() -> TestResult {
    let root = TempDir::new("ipv6-host")?;
    fs::write(root.path.join("index.html"), b"hello-ipv6-serve")?;

    // 1. Serve-mode IPv6 site: both `Host: [::1]:80` and `Host: [::1]` return 200 OK.
    let root_str = root.kdl_str();
    let (serve_server, _tls_addr, serve_http_addr, _tls_p1, _http_p1) =
        start_server_retrying(|tls_port, http_port| {
            format!(
                r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    listen "127.0.0.1:{http_port}" redirect-https=#true
}}
site "::1" {{
    http "serve"
    root "{root_str}"
}}
"#
            )
        })
        .await?;
    for host in ["[::1]:80", "[::1]"] {
        let req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        let raw = raw_tcp_exchange(serve_http_addr, req.as_bytes()).await?;
        assert!(
            raw.starts_with("HTTP/1.1 200 OK\r\n"),
            "serve-mode IPv6 Host `{host}` must return 200 OK, got:\n{raw}"
        );
        assert!(
            raw.ends_with("\r\n\r\nhello-ipv6-serve"),
            "serve-mode IPv6 Host `{host}` missing body:\n{raw}"
        );
        let lower = raw.to_ascii_lowercase();
        assert!(!lower.contains("strict-transport-security:"));
        assert!(!lower.contains("alt-svc:"));
    }
    serve_server.shutdown().await;

    // 2. Redirect-mode IPv6 site: exact unmodified v0.1.2 bytes (400 Bad Request).
    let (redir_server, _tls_addr2, redir_http_addr, _tls_p2, _http_p2) =
        start_server_retrying(|tls_port2, http_port2| {
            format!(
                r#"
server {{
    listen "127.0.0.1:{tls_port2}" protocols="h1"
    listen "127.0.0.1:{http_port2}" redirect-https=#true
}}
site "::1" {{
    http "redirect"
    root "{root_str}"
}}
"#
            )
        })
        .await?;
    let expected_v012_ipv6_redirect = "HTTP/1.1 400 Bad Request\r\n\
content-type: text/plain; charset=utf-8\r\n\
content-length: 147\r\n\
vary: Accept\r\n\
x-content-type-options: nosniff\r\n\
cache-control: no-store\r\n\
server: MiraServe\r\n\
content-security-policy: default-src 'none'; style-src 'nonce-<NONCE>'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n\
x-request-id: <REQUEST_ID>\r\n\
connection: close\r\n\
date: <DATE>\r\n\
\r\n\
400 Bad Request\n\
\n\
The server couldn\u{2019}t read the request for /. It may be malformed or corrupted on the way.\n\
Request ID: <REQUEST_ID>\n";

    for host in ["[::1]:80", "[::1]"] {
        let req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        let raw = raw_tcp_exchange(redir_http_addr, req.as_bytes()).await?;
        assert_eq!(
            normalize_v012_wire_response(&raw)?,
            expected_v012_ipv6_redirect,
            "redirect-mode IPv6 Host `{host}` must preserve exact v0.1.2 bytes"
        );
    }
    redir_server.shutdown().await;
    Ok(())
}

fn encode_std_base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let lookup = |idx: u32| -> char {
        TABLE
            .get((idx & 0x3F) as usize)
            .copied()
            .map_or('A', char::from)
    };
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk.first().copied().unwrap_or(0));
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(lookup(triple >> 18));
        out.push(lookup(triple >> 12));
        if chunk.len() > 1 {
            out.push(lookup(triple >> 6));
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(lookup(triple));
        } else {
            out.push('=');
        }
    }
    out
}

/// Pins P2-b end-to-end: OAuth/JWT `mcp-gateway` over plain HTTP refuses with `403` (no Bearer
/// challenge even with site/route `WWW-Authenticate` rules, no token evaluation) unless
/// `http "serve" credentials=#true` is set; with it, behaves like HTTPS; and RFC 9728 `resource`
/// preserves non-default ports from `Host`.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn plain_http_oauth_mcp_gateway_respects_credentials_flag_and_resource_port() -> TestResult {
    let dir = TempDir::new("mcp-http80")?;
    let pubkey_path = dir.path.join("mcp-oauth.pub");
    let oauth_kp = Ed25519KeyPair::generate().map_err(|_| "ed25519 keygen failed")?;
    fs::write(
        &pubkey_path,
        format!(
            "miraserve-ed25519-pub:{}",
            encode_std_base64(oauth_kp.public_key().as_ref())
        ),
    )?;

    let hits = Arc::new(AtomicUsize::new(0));
    let hits_up = Arc::clone(&hits);
    let up_listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = up_listener.local_addr()?;
    let up_task = tokio::spawn(async move {
        while let Ok((stream, _)) = up_listener.accept().await {
            let hits_c = Arc::clone(&hits_up);
            tokio::spawn(async move {
                let svc = service_fn(move |_req: Request<Incoming>| {
                    let hits_r = Arc::clone(&hits_c);
                    async move {
                        hits_r.fetch_add(1, Ordering::AcqRel);
                        let resp = Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/json")
                            .body(Full::new(Bytes::from_static(
                                br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#,
                            )))
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())));
                        Ok::<_, std::convert::Infallible>(resp)
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let pubkey_str = pubkey_path.to_string_lossy().replace('\\', "/");
    let make_kdl = |tls_port: u16, http_port: u16, http_line: &str| {
        format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    listen "127.0.0.1:{http_port}" redirect-https=#true
}}
site "mcp.example.test" {{
    {http_line}
    headers {{
        set "WWW-Authenticate" "Bearer realm=\"SiteInjected\""
    }}
    route "/mcp/*" {{
        headers {{
            set "WWW-Authenticate" "Bearer realm=\"RouteInjected\""
        }}
        mcp-gateway upstream="http://{up_addr}" {{
            oauth-resource-metadata #true
            jwt-public-key "ed25519:{pubkey_str}"
            jwt-issuer "https://auth.example.test"
            jwt-audience "http://mcp.example.test:{http_port}"
            allow-tools "docs_search"
            audit-log "off"
        }}
    }}
}}
"#
        )
    };

    let (server, tls_addr, http_addr, tls_port, http_port) =
        start_server_retrying(|tls_port, http_port| {
            make_kdl(tls_port, http_port, r#"http "serve""#)
        })
        .await?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let valid_jwt = format!(
        "Bearer {}",
        miraserve_ai::sign_mcp_oauth_jwt(
            &oauth_kp,
            "agent-1",
            now.saturating_add(300),
            Some("https://auth.example.test"),
            Some(&format!("http://mcp.example.test:{http_port}")),
            Some("mcp:tools"),
            None,
        )
    );
    let rpc_body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"docs_search","arguments":{}}}"#;

    let (mut sender, conn_task) = {
        let tcp = TcpStream::connect(http_addr).await?;
        let (s, c) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
        let t = tokio::spawn(async move {
            let _ = c.await;
        });
        (s, t)
    };

    // 1. RFC 9728 metadata keeps non-default port from Host and drops default port 80.
    let meta_nondefault = sender
        .send_request(
            Request::builder()
                .uri("/.well-known/oauth-protected-resource")
                .header(HOST, format!("mcp.example.test:{http_port}"))
                .body(Full::new(Bytes::new()))?,
        )
        .await?;
    assert_eq!(meta_nondefault.status(), StatusCode::OK);
    let meta_json: Value =
        serde_json::from_slice(&meta_nondefault.into_body().collect().await?.to_bytes())?;
    assert_eq!(
        meta_json.get("resource").and_then(Value::as_str),
        Some(format!("http://mcp.example.test:{http_port}").as_str())
    );

    let meta_default80 = sender
        .send_request(
            Request::builder()
                .uri("/.well-known/oauth-protected-resource")
                .header(HOST, "mcp.example.test:80")
                .body(Full::new(Bytes::new()))?,
        )
        .await?;
    assert_eq!(meta_default80.status(), StatusCode::OK);
    let meta80_json: Value =
        serde_json::from_slice(&meta_default80.into_body().collect().await?.to_bytes())?;
    assert_eq!(
        meta80_json.get("resource").and_then(Value::as_str),
        Some("http://mcp.example.test")
    );

    // 1b. HTTPS control: RFC 9728 metadata preserves exact v0.1.2 `resource` URL (omits non-default port).
    let dev_pem = server.dev_cert_pem().ok_or("missing dev cert PEM")?;
    let tls_connector = build_h1_tls_connector(dev_pem)?;
    let tls_tcp = TcpStream::connect(tls_addr).await?;
    let tls_stream = tls_connector
        .connect(
            ServerName::try_from("mcp.example.test".to_owned())?,
            tls_tcp,
        )
        .await?;
    let (mut https_sender, https_conn) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_stream)).await?;
    let https_task = tokio::spawn(async move {
        let _ = https_conn.await;
    });
    let https_meta = https_sender
        .send_request(
            Request::builder()
                .uri("/.well-known/oauth-protected-resource")
                .header(HOST, format!("mcp.example.test:{tls_port}"))
                .body(Full::new(Bytes::new()))?,
        )
        .await?;
    assert_eq!(https_meta.status(), StatusCode::OK);
    let https_meta_json: Value =
        serde_json::from_slice(&https_meta.into_body().collect().await?.to_bytes())?;
    assert_eq!(
        https_meta_json.get("resource").and_then(Value::as_str),
        Some("https://mcp.example.test"),
        "HTTPS OAuth metadata must preserve v0.1.2 resource URL without port"
    );
    https_task.abort();

    // 2. Without `credentials=#true`: both unauthenticated and valid-JWT requests answer 403
    //    with NO `WWW-Authenticate` (despite site + route header rules) and never hit upstream,
    //    including when `Content-Encoding` or `Upgrade` headers are present.
    for maybe_auth in [None, Some(valid_jwt.as_str())] {
        let mut req_b = Request::builder()
            .method(Method::POST)
            .uri("/mcp/rpc")
            .header(HOST, format!("mcp.example.test:{http_port}"))
            .header(CONTENT_TYPE, "application/json");
        if let Some(auth) = maybe_auth {
            req_b = req_b.header(AUTHORIZATION, auth);
        }
        let resp = sender
            .send_request(req_b.body(Full::new(Bytes::from_static(rpc_body)))?)
            .await?;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(
            resp.headers().get(WWW_AUTHENTICATE).is_none(),
            "plain-HTTP MCP 403 must strip WWW-Authenticate even with site/route rules"
        );
        assert_eq!(
            resp.headers()
                .get(CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
        let _ = resp.into_body().collect().await?;
    }
    for (extra_hdr, extra_val) in [
        (http::header::CONTENT_ENCODING, "identity"),
        (UPGRADE, "websocket"),
    ] {
        let resp = sender
            .send_request(
                Request::builder()
                    .method(Method::POST)
                    .uri("/mcp/rpc")
                    .header(HOST, format!("mcp.example.test:{http_port}"))
                    .header(CONTENT_TYPE, "application/json")
                    .header(extra_hdr.clone(), extra_val)
                    .body(Full::new(Bytes::from_static(rpc_body)))?,
            )
            .await?;
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "plain-HTTP OAuth MCP gateway must return 403 before inspecting {extra_hdr}"
        );
        assert!(resp.headers().get(WWW_AUTHENTICATE).is_none());
        assert_eq!(
            resp.headers()
                .get(CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
        let _ = resp.into_body().collect().await?;
    }
    assert_eq!(hits.load(Ordering::Acquire), 0);

    // 3. Reload enabling `credentials=#true`: unauthenticated gets 401 + Bearer challenge with
    //    the non-default port; valid JWT succeeds with 200 OK.
    server.reload_from_str(
        "mcp-creds-on.kdl",
        &make_kdl(tls_port, http_port, r#"http "serve" credentials=#true"#),
    )?;
    let unauth = sender
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp/rpc")
                .header(HOST, format!("mcp.example.test:{http_port}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(rpc_body)))?,
        )
        .await?;
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);
    let challenge = unauth
        .headers()
        .get(WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .ok_or("expected Bearer WWW-Authenticate after credentials=#true")?;
    assert!(
        challenge.contains(&format!(
            "resource_metadata=\"http://mcp.example.test:{http_port}/.well-known/oauth-protected-resource\""
        )),
        "unexpected challenge: {challenge}"
    );
    let _ = unauth.into_body().collect().await?;
    assert_eq!(hits.load(Ordering::Acquire), 0);

    let ok = sender
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp/rpc")
                .header(HOST, format!("mcp.example.test:{http_port}"))
                .header(CONTENT_TYPE, "application/json")
                .header(AUTHORIZATION, valid_jwt.as_str())
                .body(Full::new(Bytes::from_static(rpc_body)))?,
        )
        .await?;
    assert_eq!(ok.status(), StatusCode::OK);
    let _ = ok.into_body().collect().await?;
    assert_eq!(hits.load(Ordering::Acquire), 1);

    conn_task.abort();
    up_task.abort();
    server.shutdown().await;
    Ok(())
}

/// Pins P2-e: wildcard site routing (exact precedes wildcard) and single-site default loopback
/// routing (`localhost`, `127.0.0.1`, `[::1]:80`) on the plain-HTTP listener.
#[tokio::test]
async fn plain_http_wildcard_and_single_site_default_routing() -> TestResult {
    let wild_root = TempDir::new("wild-serve")?;
    let exact_root = TempDir::new("exact-redir")?;
    fs::write(wild_root.path.join("page.txt"), b"wildcard-plain")?;
    fs::write(exact_root.path.join("page.txt"), b"exact-redir")?;

    // Part A: Wildcard serve site + exact redirect sibling.
    let wild_root_str = wild_root.kdl_str();
    let exact_root_str = exact_root.kdl_str();
    let (wild_srv, _tls1, wild_http, _tp1, _hp1) = start_server_retrying(|tls_port, http_port| {
        format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    listen "127.0.0.1:{http_port}" redirect-https=#true
}}
site "*.wild.example.test" {{
    http "serve"
    root "{wild_root_str}"
}}
site "exact.wild.example.test" {{
    http "redirect"
    root "{exact_root_str}"
}}
"#
        )
    })
    .await?;
    let (mut sender, task) = connect_h1_plain(wild_http).await?;

    let sub = sender
        .send_request(
            Request::builder()
                .uri("/page.txt")
                .header(HOST, "sub.wild.example.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(sub.status(), StatusCode::OK);
    assert_eq!(
        sub.into_body().collect().await?.to_bytes().as_ref(),
        b"wildcard-plain"
    );

    let exact = sender
        .send_request(
            Request::builder()
                .uri("/page.txt")
                .header(HOST, "exact.wild.example.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(exact.status(), StatusCode::PERMANENT_REDIRECT);
    let _ = exact.into_body().collect().await?;

    let unmatched = sender
        .send_request(
            Request::builder()
                .uri("/page.txt")
                .header(HOST, "other.example.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(unmatched.status(), StatusCode::MISDIRECTED_REQUEST);
    let _ = unmatched.into_body().collect().await?;
    task.abort();
    wild_srv.shutdown().await;

    // Part B: Single-site default loopback routing (`localhost`, `127.0.0.1`, `[::1]:80`), while
    // non-loopback unknown hosts still receive 421 and missing Host still receives 400.
    let (single_srv, _tls2, single_http, _tp2, _hp2) =
        start_server_retrying(|tls_port2, http_port2| {
            format!(
                r#"
server {{
    listen "127.0.0.1:{tls_port2}" protocols="h1"
    listen "127.0.0.1:{http_port2}" redirect-https=#true
}}
site "only.example.test" {{
    http "serve"
    root "{wild_root_str}"
}}
"#
            )
        })
        .await?;
    for host in ["localhost", "127.0.0.1", "[::1]:80"] {
        let raw = raw_tcp_exchange(
            single_http,
            format!("GET /page.txt HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
        assert!(
            raw.starts_with("HTTP/1.1 200 OK\r\n") && raw.ends_with("\r\n\r\nwildcard-plain"),
            "single-site loopback Host `{host}` must serve default site, got:\n{raw}"
        );
    }
    let unknown_raw = raw_tcp_exchange(
        single_http,
        b"GET /page.txt HTTP/1.1\r\nHost: stranger.example.test\r\nConnection: close\r\n\r\n",
    )
    .await?;
    assert!(unknown_raw.starts_with("HTTP/1.1 421 Misdirected Request\r\n"));

    let missing_host_raw = raw_tcp_exchange(single_http, b"GET /page.txt HTTP/1.0\r\n\r\n").await?;
    assert!(missing_host_raw.starts_with("HTTP/1.0 400 Bad Request\r\n"));

    single_srv.shutdown().await;
    Ok(())
}

/// Pins P2-e: two pipelined HTTP/1.1 requests on a single TCP connection targeting an
/// `http "serve"` site and an `http "redirect"` site (in both orders) receive the exact two
/// ordered responses without cross-talk.
#[tokio::test]
async fn plain_http_pipelined_serve_and_redirect_requests_on_one_connection() -> TestResult {
    let root = TempDir::new("pipelined")?;
    fs::write(root.path.join("hello.txt"), b"pipelined-body")?;

    let root_str = root.kdl_str();
    let (server, _tls_addr, http_addr, tls_port, _http_port) =
        start_server_retrying(|tls_port, http_port| {
            format!(
                r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    listen "127.0.0.1:{http_port}" redirect-https=#true
}}
site "plain.example.test" {{
    http "serve"
    root "{root_str}"
}}
site "redir.example.test" {{
    http "redirect"
    root "{root_str}"
}}
"#
            )
        })
        .await?;

    // Order 1: serve first, then redirect (sent together in one write_all).
    let wire_sr = raw_tcp_exchange(
        http_addr,
        b"GET /hello.txt HTTP/1.1\r\nHost: plain.example.test\r\n\r\n\
          GET /docs HTTP/1.1\r\nHost: redir.example.test\r\nConnection: close\r\n\r\n",
    )
    .await?;
    let expected_loc = format!("location: https://redir.example.test:{tls_port}/docs\r\n");
    assert!(
        wire_sr.starts_with("HTTP/1.1 200 OK\r\n"),
        "expected first pipelined response 200 OK:\n{wire_sr}"
    );
    let split_idx = wire_sr
        .find("pipelined-bodyHTTP/1.1 308 Permanent Redirect\r\n")
        .ok_or_else(|| format!("expected pipelined 200 body followed by 308:\n{wire_sr}"))?;
    let second_resp = wire_sr
        .get(split_idx + "pipelined-body".len()..)
        .ok_or("slice error")?;
    assert!(
        second_resp.contains(&expected_loc),
        "expected redirect Location in second pipelined response:\n{second_resp}"
    );

    // Order 2: redirect first, then serve (sent together in one write_all).
    let wire_rs = raw_tcp_exchange(
        http_addr,
        b"GET /docs HTTP/1.1\r\nHost: redir.example.test\r\n\r\n\
          GET /hello.txt HTTP/1.1\r\nHost: plain.example.test\r\nConnection: close\r\n\r\n",
    )
    .await?;
    assert!(
        wire_rs.starts_with("HTTP/1.1 308 Permanent Redirect\r\n"),
        "expected first pipelined response 308:\n{wire_rs}"
    );
    let second_idx = wire_rs
        .find("\r\n\r\nHTTP/1.1 200 OK\r\n")
        .ok_or_else(|| format!("expected pipelined 308 followed by 200:\n{wire_rs}"))?;
    let first_resp = wire_rs
        .get(..second_idx + 4)
        .ok_or("first pipelined response slice error")?;
    assert!(first_resp.contains(&expected_loc));
    assert!(wire_rs.ends_with("\r\n\r\npipelined-body"));

    server.shutdown().await;
    Ok(())
}

/// Pins P2-e: exact `max-header-bytes` boundary (`N` bytes passes, `N + 1` bytes returns `431`)
/// on the plain-HTTP listener for both `http "serve"` and `http "redirect"` sites.
#[tokio::test]
async fn plain_http_header_limit_boundary_for_serve_and_redirect_sites() -> TestResult {
    let root = TempDir::new("hdr-limit")?;
    fs::write(root.path.join("ok.txt"), b"ok-hdr")?;

    let root_str = root.kdl_str();
    let (server, _tls_addr, http_addr, _tls_port, _http_port) =
        start_server_retrying(|tls_port, http_port| {
            format!(
                r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    listen "127.0.0.1:{http_port}" redirect-https=#true
    limits {{
        max-header-bytes "1024B"
    }}
}}
site "plain.example.test" {{
    http "serve"
    root "{root_str}"
}}
site "redir.example.test" {{
    http "redirect"
    root "{root_str}"
}}
"#
            )
        })
        .await?;

    // Header budget accounting in `smuggling::validate_header_budget` sums
    // `name.len() + value.len() + 4` across all headers:
    //   "host" (4) + host.len() + 4
    //   "connection" (10) + "close" (5) + 4 = 19
    //   "x-pad" (5) + pad_len + 4 = 9 + pad_len
    for (host, expected_ok_prefix) in [
        ("plain.example.test", "HTTP/1.1 200 OK\r\n"),
        ("redir.example.test", "HTTP/1.1 308 Permanent Redirect\r\n"),
    ] {
        let base_bytes = (4 + host.len() + 4) + (10 + 5 + 4) + (5 + 4);
        let exact_pad = "a".repeat(1024 - base_bytes);
        let over_pad = "a".repeat(1025 - base_bytes);

        let req_at_limit = format!(
            "GET /ok.txt HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nX-Pad: {exact_pad}\r\n\r\n"
        );
        let resp_at = raw_tcp_exchange(http_addr, req_at_limit.as_bytes()).await?;
        assert!(
            resp_at.starts_with(expected_ok_prefix),
            "exact 1024-byte header budget must succeed for {host}, got:\n{resp_at}"
        );

        let req_over_limit = format!(
            "GET /ok.txt HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nX-Pad: {over_pad}\r\n\r\n"
        );
        let resp_over = raw_tcp_exchange(http_addr, req_over_limit.as_bytes()).await?;
        assert!(
            resp_over.starts_with("HTTP/1.1 431 Request Header Fields Too Large\r\n"),
            "1025-byte header budget must return 431 for {host}, got:\n{resp_over}"
        );
    }

    server.shutdown().await;
    Ok(())
}

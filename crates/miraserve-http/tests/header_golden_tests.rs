//! Golden response-header checks (names, values, and exact wire order) for a static file,
//! a redirect, and an error page over both HTTP/1.1 and HTTP/2.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http::header::{ACCEPT, HOST, HeaderMap, HeaderValue};
use http::{Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use miraserve_config::parse_kdl;
use miraserve_http::HttpEngine;
use miraserve_tls::AcmeChallengeStore;
use tokio::sync::watch;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const DYNAMIC_HEADERS: &[&str] = &[
    "etag",
    "last-modified",
    "content-security-policy",
    "x-request-id",
    "date",
];

/// Extracts `(name, value)` pairs in exact wire order, normalizing inherently dynamic fields
/// (`etag`, `last-modified`, `content-security-policy`, `x-request-id`, `date`) to placeholders
/// while asserting their format.
fn normalized_header_order(
    headers: &HeaderMap,
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let mut out = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        let k = name.as_str().to_owned();
        let v = value.to_str()?.to_owned();
        let norm = if k == "etag" {
            assert!(v.starts_with('"') && v.ends_with('"'), "invalid etag: {v}");
            "<ETAG>".to_owned()
        } else if k == "last-modified" {
            assert!(v.ends_with(" GMT") && v.len() == 29, "invalid date: {v}");
            "<LAST-MODIFIED>".to_owned()
        } else if k == "content-security-policy" {
            assert!(
                v.starts_with("default-src 'none'; style-src 'nonce-"),
                "invalid csp: {v}"
            );
            "<CSP>".to_owned()
        } else if k == "x-request-id" {
            assert_eq!(v.len(), 26, "invalid request id: {v}");
            "<REQUEST-ID>".to_owned()
        } else if k == "date" {
            "<DATE>".to_owned()
        } else {
            assert!(!DYNAMIC_HEADERS.contains(&k.as_str()));
            v
        };
        out.push((k, norm));
    }
    Ok(out)
}

fn build_engine(
    root: &std::path::Path,
    security_policy: &str,
    alt_svc_port: Option<u16>,
) -> Result<Arc<HttpEngine>, Box<dyn std::error::Error>> {
    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "golden.example.test" {{
    root "{root}"
    security-headers "{security_policy}"
    route "/go" {{
        redirect "/1k.txt" status=301
    }}
}}
"#,
        root = root.to_string_lossy().replace('\\', "/"),
    );
    let (cfg, _) = parse_kdl("golden.kdl", &kdl)?;
    Ok(Arc::new(HttpEngine::from_config(
        &cfg,
        Arc::new(AcmeChallengeStore::new()),
        alt_svc_port,
        8443,
    )?))
}

async fn fetch_h1(
    engine: Arc<HttpEngine>,
    path: &str,
    is_https: bool,
) -> Result<(StatusCode, Vec<(String, String)>), Box<dyn std::error::Error>> {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let peer: SocketAddr = "198.51.100.10:50000".parse()?;
    let local: SocketAddr = "127.0.0.1:8443".parse()?;
    let (_tx, rx) = watch::channel(false);
    tokio::spawn(engine.serve_hyper_connection(server, peer, local, is_https, false, None, rx));

    let (mut sender, conn) = http1::handshake(TokioIo::new(client)).await?;
    let driver = tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .uri(path)
        .header(HOST, "golden.example.test")
        .body(Empty::<Bytes>::new())?;
    let resp = sender.send_request(req).await?;
    let status = resp.status();
    let headers = normalized_header_order(resp.headers())?;
    let _ = resp.into_body().collect().await?;
    driver.abort();
    Ok((status, headers))
}

async fn fetch_h2(
    engine: Arc<HttpEngine>,
    path: &str,
    is_https: bool,
) -> Result<(StatusCode, Vec<(String, String)>), Box<dyn std::error::Error>> {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let peer: SocketAddr = "198.51.100.10:50001".parse()?;
    let local: SocketAddr = "127.0.0.1:8443".parse()?;
    let (_tx, rx) = watch::channel(false);
    tokio::spawn(engine.serve_hyper_connection(server, peer, local, is_https, false, None, rx));

    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), TokioIo::new(client)).await?;
    let driver = tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .uri(format!("https://golden.example.test{path}"))
        .body(Empty::<Bytes>::new())?;
    let resp = sender.send_request(req).await?;
    let status = resp.status();
    let headers = normalized_header_order(resp.headers())?;
    let _ = resp.into_body().collect().await?;
    driver.abort();
    Ok((status, headers))
}

fn s(k: &str, v: &str) -> (String, String) {
    (k.to_owned(), v.to_owned())
}

#[tokio::test]
async fn golden_headers_for_static_redirect_and_error_on_h1_and_h2() -> TestResult {
    let root = std::env::temp_dir().join(format!("miraserve-hdr-golden-{}", std::process::id()));
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("1k.txt"), vec![b'a'; 1024])?;

    let engine = build_engine(&root, "standard", None)?;

    // 1. Static file (200 OK)
    let mut expected_static_common = vec![
        s("content-type", "text/plain; charset=utf-8"),
        s("content-length", "1024"),
        s("accept-ranges", "bytes"),
        s("vary", "Accept-Encoding"),
    ];
    // Non-Unix builds intentionally omit `ETag` because `change_stamp` returns `None`.
    #[cfg(unix)]
    expected_static_common.push(s("etag", "<ETAG>"));
    expected_static_common.extend([
        s("last-modified", "<LAST-MODIFIED>"),
        s("server", "MiraServe"),
        s("strict-transport-security", "max-age=31536000"),
        s("x-content-type-options", "nosniff"),
        s("referrer-policy", "strict-origin-when-cross-origin"),
        s("x-frame-options", "SAMEORIGIN"),
        s("date", "<DATE>"),
    ]);
    let (st_h1, hdrs_h1) = fetch_h1(Arc::clone(&engine), "/1k.txt", true).await?;
    let (st_h2, hdrs_h2) = fetch_h2(Arc::clone(&engine), "/1k.txt", true).await?;
    assert_eq!(st_h1, StatusCode::OK);
    assert_eq!(st_h2, StatusCode::OK);
    assert_eq!(hdrs_h1, expected_static_common, "H1 static headers");
    assert_eq!(hdrs_h2, expected_static_common, "H2 static headers");

    // 2. Redirect (301 Moved Permanently)
    let expected_redirect_h1 = vec![
        s("location", "/1k.txt"),
        s("server", "MiraServe"),
        s("strict-transport-security", "max-age=31536000"),
        s("x-content-type-options", "nosniff"),
        s("referrer-policy", "strict-origin-when-cross-origin"),
        s("x-frame-options", "SAMEORIGIN"),
        s("content-length", "0"),
        s("date", "<DATE>"),
    ];
    let expected_redirect_h2 = vec![
        s("location", "/1k.txt"),
        s("server", "MiraServe"),
        s("strict-transport-security", "max-age=31536000"),
        s("x-content-type-options", "nosniff"),
        s("referrer-policy", "strict-origin-when-cross-origin"),
        s("x-frame-options", "SAMEORIGIN"),
        s("date", "<DATE>"),
    ];
    let (st_h1, hdrs_h1) = fetch_h1(Arc::clone(&engine), "/go", true).await?;
    let (st_h2, hdrs_h2) = fetch_h2(Arc::clone(&engine), "/go", true).await?;
    assert_eq!(st_h1, StatusCode::MOVED_PERMANENTLY);
    assert_eq!(st_h2, StatusCode::MOVED_PERMANENTLY);
    assert_eq!(hdrs_h1, expected_redirect_h1, "H1 redirect headers");
    assert_eq!(hdrs_h2, expected_redirect_h2, "H2 redirect headers");

    // 3. Error page (404 Not Found): `x-content-type-options` and `server` keep their
    //    built-in positions while the remaining security headers are appended in order.
    let (st_h1, hdrs_h1) = fetch_h1(Arc::clone(&engine), "/missing", true).await?;
    let (st_h2, hdrs_h2) = fetch_h2(Arc::clone(&engine), "/missing", true).await?;
    assert_eq!(st_h1, StatusCode::NOT_FOUND);
    assert_eq!(st_h2, StatusCode::NOT_FOUND);
    assert_eq!(hdrs_h1, hdrs_h2, "H1 and H2 404 headers must match");
    let expected_error_names = vec![
        "content-type",
        "content-length",
        "vary",
        "x-content-type-options",
        "cache-control",
        "server",
        "content-security-policy",
        "x-request-id",
        "strict-transport-security",
        "referrer-policy",
        "x-frame-options",
        "date",
    ];
    let actual_names: Vec<&str> = hdrs_h1.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(actual_names, expected_error_names, "404 header order");

    // 4. Strict policy + Alt-Svc on HTTP/2 redirect
    let strict_engine = build_engine(&root, "strict", Some(8443))?;
    let (st_strict, hdrs_strict) = fetch_h2(Arc::clone(&strict_engine), "/go", true).await?;
    assert_eq!(st_strict, StatusCode::MOVED_PERMANENTLY);
    assert_eq!(
        hdrs_strict,
        vec![
            s("location", "/1k.txt"),
            s("server", "MiraServe"),
            s("alt-svc", "h3=\":8443\"; ma=86400"),
            s(
                "strict-transport-security",
                "max-age=63072000; includeSubDomains"
            ),
            s("x-content-type-options", "nosniff"),
            s("referrer-policy", "strict-origin-when-cross-origin"),
            s("x-frame-options", "DENY"),
            s("cross-origin-opener-policy", "same-origin"),
            s(
                "permissions-policy",
                "geolocation=(), microphone=(), camera=()"
            ),
            s("date", "<DATE>"),
        ]
    );

    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

/// Regression test for ba5c299 P1 #4: 25,000 duplicate `Accept` values fit inside the supported
/// 1 MiB HTTP/2 header-list budget and must be answered cleanly with `431 Request Header Fields
/// Too Large` instead of panicking in `HeaderMap::with_capacity(vals.len())`.
#[tokio::test]
async fn h2_25000_duplicate_accept_headers_returns_431_without_panicking() -> TestResult {
    let kdl = r#"
server {
    listen ":8443"
    tls { cert "/c.pem"; key "/k.pem" }
    limits {
        max-header-bytes "1MiB"
    }
}
site "dup-accept.example.test" {
    route "/*" {
        redirect "/dest" status=301
    }
}
"#;
    let (cfg, _) = parse_kdl("dup-accept.kdl", kdl)?;
    let engine = Arc::new(HttpEngine::from_config(
        &cfg,
        Arc::new(AcmeChallengeStore::new()),
        None,
        8443,
    )?);

    let (client, server) = tokio::io::duplex(256 * 1024);
    let peer: SocketAddr = "198.51.100.11:50002".parse()?;
    let local: SocketAddr = "127.0.0.1:8443".parse()?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(engine.serve_hyper_connection(
        server,
        peer,
        local,
        true,
        false,
        None,
        shutdown_rx,
    ));

    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), TokioIo::new(client)).await?;
    let driver = tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut req = Request::builder()
        .uri("https://dup-accept.example.test/")
        .body(Empty::<Bytes>::new())?;
    let accept_val = HeaderValue::from_static("*/*");
    for _ in 0..25_000 {
        req.headers_mut().append(ACCEPT, accept_val.clone());
    }

    let resp = sender.send_request(req).await?;
    assert_eq!(
        resp.status(),
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
        "25,000 duplicate Accept headers must return 431"
    );
    let _ = resp.into_body().collect().await?;

    let _ = shutdown_tx.send(true);
    drop(sender);
    driver.abort();
    server_task.await?;
    Ok(())
}

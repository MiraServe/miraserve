//! Handlers a hosting panel needs: `respond <status>` (suspended sites) and
//! `reverse-proxy { strip-prefix #true }` (tools mounted under a path).

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use bytes::Bytes;
use http::header::HOST;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use miraserve_config::parse_kdl;
use miraserve_http::{HttpEngine, RequestContext, empty_http_body};
use miraserve_tls::AcmeChallengeStore;
use tokio::net::TcpListener;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn ctx() -> RequestContext {
    RequestContext {
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))),
        remote_port: Some(50_000),
        server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_port: 8443,
        is_https: true,
        tls: None,
    }
}

async fn get(
    engine: &HttpEngine,
    host: &str,
    uri: &str,
) -> Result<(StatusCode, String), Box<dyn std::error::Error>> {
    let req = Request::builder()
        .uri(uri)
        .header(HOST, host)
        .header("accept", "text/html")
        .body(empty_http_body())?;
    let resp = engine.handle_request(req, &ctx()).await;
    let status = resp.status();
    let body = resp.into_body().collect().await?.to_bytes();
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

/// A suspended site answers 503 with its own page for EVERY path, including `*.php` (which a
/// static root with a 503 page answered with 404).
#[tokio::test]
async fn respond_handler_answers_every_path_with_the_status_and_custom_page() -> TestResult {
    let root = std::env::temp_dir().join(format!("miraserve-respond-{}", std::process::id()));
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("suspended.html"), b"<h1>Account suspended</h1>")?;
    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "suspended.example.test" {{
    root "{}"
    error-pages {{ page 503 "suspended.html" }}
    route "/*" {{ respond 503 }}
}}
"#,
        root.display()
    );
    let (cfg, _) = parse_kdl("respond.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    for uri in [
        "/",
        "/index.php",
        "/wp-login.php?x=1",
        "/a/b/c.jpg",
        "/suspended.html",
    ] {
        let (status, body) = get(&engine, "suspended.example.test", uri).await?;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{uri}");
        assert!(body.contains("Account suspended"), "{uri}: {body}");
    }

    for bad in ["200", "302", "600"] {
        let bad_kdl = format!(
            "server {{ listen \":8443\"; tls {{ cert \"/c.pem\"; key \"/k.pem\" }} }}\nsite \"a.example\" {{ route \"/*\" {{ respond {bad} }} }}\n"
        );
        assert!(
            parse_kdl("bad-respond.kdl", &bad_kdl).is_err(),
            "respond {bad} must be rejected"
        );
    }
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

/// `strip-prefix` forwards `/tool/a/b?x=1` as `/a/b?x=1` and `/tool` as `/`; without it the
/// backend sees the full path.
#[tokio::test]
async fn reverse_proxy_strip_prefix_removes_the_route_prefix() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let backend = listener.local_addr()?;
    let backend_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let seen = req
                        .uri()
                        .path_and_query()
                        .map_or_else(String::new, |pq| pq.as_str().to_owned());
                    Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(
                        format!("backend saw {seen}"),
                    ))))
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "tools.example.test" {{
    route "/tool/*" {{
        reverse-proxy {{
            upstream "http://{backend}"
            strip-prefix #true
        }}
    }}
    route "/plain/*" {{
        reverse-proxy {{ upstream "http://{backend}" }}
    }}
}}
"#
    );
    let (cfg, _) = parse_kdl("strip.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    for (uri, expected) in [
        ("/tool/a/b?x=1", "backend saw /a/b?x=1"),
        ("/tool/", "backend saw /"),
        ("/tool", "backend saw /"),
        ("/tool//double", "backend saw /double"),
        ("/plain/a/b?x=1", "backend saw /plain/a/b?x=1"),
    ] {
        let (status, body) = get(&engine, "tools.example.test", uri).await?;
        assert_eq!(status, StatusCode::OK, "{uri}: {body}");
        assert_eq!(body, expected, "{uri}");
    }

    let on_catch_all = format!(
        "server {{ listen \":8443\"; tls {{ cert \"/c.pem\"; key \"/k.pem\" }} }}\nsite \"a.example\" {{ route \"/*\" {{ reverse-proxy {{ upstream \"http://{backend}\"; strip-prefix #true }} }} }}\n"
    );
    assert!(
        parse_kdl("strip-catch-all.kdl", &on_catch_all).is_err(),
        "strip-prefix needs a prefix route"
    );
    backend_task.abort();
    Ok(())
}

/// A method other than GET/HEAD on a static site: 405 only for something that exists; a path
/// that is 404 for GET is 404 for every method. An uncompressed proxied response that would be
/// compressed for another client still carries `Vary: Accept-Encoding`.
#[tokio::test]
async fn static_405_only_for_existing_paths_and_vary_on_uncompressed_proxied_text() -> TestResult {
    let root = std::env::temp_dir().join(format!("miraserve-405-{}", std::process::id()));
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("page.html"), b"<h1>page</h1>")?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let backend = listener.local_addr()?;
    let backend_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(|_req: Request<Incoming>| async move {
                    let mut resp = Response::new(Full::new(Bytes::from(vec![b'a'; 20_000])));
                    resp.headers_mut().insert(
                        http::header::CONTENT_TYPE,
                        http::HeaderValue::from_static("text/plain"),
                    );
                    Ok::<_, std::convert::Infallible>(resp)
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "m.example.test" {{
    root "{}"
    route "/api/*" {{ reverse-proxy {{ upstream "http://{backend}" }} }}
}}
"#,
        root.display()
    );
    let (cfg, _) = parse_kdl("methods.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;

    for (method, uri, expected) in [
        (
            http::Method::POST,
            "/page.html",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            http::Method::DELETE,
            "/page.html",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (http::Method::POST, "/no-such-file", StatusCode::NOT_FOUND),
        (
            http::Method::DELETE,
            "/no/such/dir/x",
            StatusCode::NOT_FOUND,
        ),
        (http::Method::GET, "/page.html", StatusCode::OK),
    ] {
        let req = Request::builder()
            .method(method.clone())
            .uri(uri)
            .header(HOST, "m.example.test")
            .body(empty_http_body())?;
        let resp = engine.handle_request(req, &ctx()).await;
        assert_eq!(resp.status(), expected, "{method} {uri}");
    }

    for (accept_encoding, expect_encoded) in [
        (Some("gzip"), true),
        (Some("identity"), false),
        (None, false),
    ] {
        let mut builder = Request::builder()
            .uri("/api/text")
            .header(HOST, "m.example.test");
        if let Some(ae) = accept_encoding {
            builder = builder.header("accept-encoding", ae);
        }
        let resp = engine
            .handle_request(builder.body(empty_http_body())?, &ctx())
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().contains_key("content-encoding"),
            expect_encoded,
            "accept-encoding {accept_encoding:?}"
        );
        let vary = resp
            .headers()
            .get_all("vary")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect::<Vec<_>>()
            .join(",")
            .to_ascii_lowercase();
        assert!(
            vary.contains("accept-encoding"),
            "a compressible proxied response needs Vary: Accept-Encoding whether or not this \
             client got it compressed (accept-encoding {accept_encoding:?}), got vary='{vary}'"
        );
    }
    backend_task.abort();
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

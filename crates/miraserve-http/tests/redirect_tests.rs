//! `redirect` route handler: per-site redirects for a hosting panel (www to bare domain, moved
//! pages), with a destination host that can never be chosen by the request.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use http::header::{HOST, LOCATION};
use http::{Method, Request, StatusCode};
use miraserve_config::{parse_kdl, redirect_target_rejection};
use miraserve_http::{HttpEngine, RequestContext, empty_http_body};
use miraserve_tls::AcmeChallengeStore;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const CONFIG: &str = r#"
server {
    listen ":8443"
    tls { cert "/c.pem"; key "/k.pem" }
}
site "www.shop.example" {
    route "/*" { redirect "https://shop.example{uri}" }
}
site "shop.example" {
    route "/old-page" { redirect "/new-page" status=302 }
    route "/blog/*" { redirect "https://blog.shop.example{path}" status=308 }
    route "/search" { redirect "/find?q={query}" status=307 }
    route "/docs/*" { redirect "/help/{rest}" status=302 }
    route "/shop/*" { redirect "https://store.shop.example/{rest}?{query}" status=302 }
    route "/*" { redirect "https://fallback.example/" }
}
"#;

async fn fetch(
    engine: &HttpEngine,
    method: Method,
    host: &str,
    uri: &str,
) -> Result<(StatusCode, String), Box<dyn std::error::Error>> {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header(HOST, host)
        .body(empty_http_body())?;
    let ctx = RequestContext {
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))),
        remote_port: Some(54321),
        server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_port: 8443,
        is_https: true,
        tls: None,
    };
    let resp = engine.handle_request(req, &ctx).await;
    let location = resp
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    Ok((resp.status(), location))
}

#[tokio::test]
async fn redirect_routes_send_the_configured_status_and_location() -> TestResult {
    let (cfg, _) = parse_kdl("redirects.kdl", CONFIG)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;

    for (host, uri, status, location) in [
        // www to bare domain keeps path and query.
        (
            "www.shop.example",
            "/cart/view?id=7&x=a%20b",
            StatusCode::MOVED_PERMANENTLY,
            "https://shop.example/cart/view?id=7&x=a%20b",
        ),
        (
            "www.shop.example",
            "/",
            StatusCode::MOVED_PERMANENTLY,
            "https://shop.example/",
        ),
        ("shop.example", "/old-page", StatusCode::FOUND, "/new-page"),
        (
            "shop.example",
            "/blog/2026/post?utm=1",
            StatusCode::PERMANENT_REDIRECT,
            "https://blog.shop.example/blog/2026/post",
        ),
        // {rest}: the path after the route prefix, without its leading slash.
        (
            "shop.example",
            "/docs/a/b.html",
            StatusCode::FOUND,
            "/help/a/b.html",
        ),
        ("shop.example", "/docs", StatusCode::FOUND, "/help/"),
        (
            "shop.example",
            "/docs//evil.example/x",
            StatusCode::FOUND,
            "/help/evil.example/x",
        ),
        // No bare `?` when the request has no query.
        (
            "shop.example",
            "/shop/item/7",
            StatusCode::FOUND,
            "https://store.shop.example/item/7",
        ),
        (
            "shop.example",
            "/search",
            StatusCode::TEMPORARY_REDIRECT,
            "/find?q=",
        ),
        (
            "shop.example",
            "/shop/item/7?c=red",
            StatusCode::FOUND,
            "https://store.shop.example/item/7?c=red",
        ),
        (
            "shop.example",
            "/search?term=shoes",
            StatusCode::TEMPORARY_REDIRECT,
            "/find?q=term=shoes",
        ),
    ] {
        let (got_status, got_location) = fetch(&engine, Method::GET, host, uri).await?;
        assert_eq!(got_status, status, "{host}{uri}");
        assert_eq!(got_location, location, "{host}{uri}");
    }

    // Other methods are redirected too.
    let (status, location) = fetch(&engine, Method::POST, "www.shop.example", "/submit").await?;
    assert_eq!(status, StatusCode::MOVED_PERMANENTLY);
    assert_eq!(location, "https://shop.example/submit");
    Ok(())
}

#[tokio::test]
async fn request_cannot_change_the_redirect_host() -> TestResult {
    let (cfg, _) = parse_kdl("redirects.kdl", CONFIG)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    for uri in [
        "//evil.example/x",
        "/@evil.example/x",
        "/.evil.example",
        "/%2f%2fevil.example",
        "/x?@evil.example",
    ] {
        let (status, location) = fetch(&engine, Method::GET, "www.shop.example", uri).await?;
        if status == StatusCode::MOVED_PERMANENTLY {
            assert!(
                location.starts_with("https://shop.example/"),
                "request '{uri}' produced Location '{location}'"
            );
        } else {
            assert!(
                location.is_empty(),
                "request '{uri}' got {status} with Location '{location}'"
            );
        }
    }
    Ok(())
}

#[test]
fn unsafe_redirect_targets_are_rejected_by_the_config() {
    for good in [
        "https://example.com",
        "https://example.com/",
        "https://example.com{uri}",
        "https://example.com{path}",
        "https://example.com/shop{path}?{query}",
        "http://example.com:8080/x",
        "/new",
        "/new{path}",
        "/find?q={query}",
        "/help/{rest}",
        "https://example.com/{rest}",
    ] {
        assert_eq!(
            redirect_target_rejection(good),
            None,
            "'{good}' must be accepted"
        );
    }
    for bad in [
        "",
        "example.com/x",
        "//example.com/x",
        "/{path}",
        "{path}",
        "{uri}",
        "https://{path}",
        "https://{query}.example.com/",
        "https://example.com{query}",
        "https://user@example.com/",
        "https:///x",
        "javascript:alert(1)",
        "/a b",
        "/a\\b",
        "/x{host}",
        "/{rest}",
        "https://example.com{rest}",
        "{rest}",
        "ftp://example.com/",
        // `{query}` is query text; before the first '?' it would be read as path.
        "/a/{query}",
        "/x{query}?a=1",
    ] {
        assert!(
            redirect_target_rejection(bad).is_some(),
            "'{bad}' must be rejected"
        );
    }

    let bad_status = r#"
server { listen ":8443"; tls { cert "/c.pem"; key "/k.pem" } }
site "a.example" { route "/*" { redirect "/x" status=200 } }
"#;
    assert!(parse_kdl("bad-status.kdl", bad_status).is_err());
    let bad_target = r#"
server { listen ":8443"; tls { cert "/c.pem"; key "/k.pem" } }
site "a.example" { route "/*" { redirect "//evil.example/" } }
"#;
    assert!(parse_kdl("bad-target.kdl", bad_target).is_err());
}

#[test]
fn rest_placeholder_needs_a_prefix_route() {
    let on_exact = r#"
server { listen ":8443"; tls { cert "/c.pem"; key "/k.pem" } }
site "a.example" { route "/old" { redirect "/new/{rest}" } }
"#;
    assert!(parse_kdl("rest-exact.kdl", on_exact).is_err());
    let on_prefix = r#"
server { listen ":8443"; tls { cert "/c.pem"; key "/k.pem" } }
site "a.example" { route "/old/*" { redirect "/new/{rest}" } }
"#;
    assert!(parse_kdl("rest-prefix.kdl", on_prefix).is_ok());
}

/// Codex review 37: a direct request for an encoded non-ASCII prefix keeps `{rest}`.
#[tokio::test]
async fn direct_redirect_keeps_rest_under_a_non_ascii_prefix() -> TestResult {
    let (cfg, _) = parse_kdl(
        "cafe.kdl",
        r#"
server {
    listen ":8443"
    tls { cert "/c.pem"; key "/k.pem" }
}
site "shop.example" {
    route "/café/*" { redirect "/new/{rest}" status=302 }
}
"#,
    )?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    let (status, location) =
        fetch(&engine, Method::GET, "shop.example", "/caf%C3%A9/article").await?;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location, "/new/article");
    Ok(())
}

/// Codex review 38: `{rest}` follows an encoded separator after the prefix, and `{path}` keeps
/// the visitor's encoding (an encoded slash stays one segment).
#[tokio::test]
async fn direct_redirect_rest_after_encoded_separator_and_path_kept_as_sent() -> TestResult {
    let (cfg, _) = parse_kdl(
        "rest.kdl",
        r#"
server {
    listen ":8443"
    tls { cert "/c.pem"; key "/k.pem" }
}
site "shop.example" {
    route "/old/*" { redirect "/new/{rest}" status=302 }
    route "/café/*" { redirect "/moved{path}" status=302 }
}
"#,
    )?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    let (status, location) = fetch(&engine, Method::GET, "shop.example", "/old%2Farticle").await?;
    assert_eq!(
        (status, location.as_str()),
        (StatusCode::FOUND, "/new/article")
    );
    let (status, location) =
        fetch(&engine, Method::GET, "shop.example", "/caf%C3%A9/a%2Fb").await?;
    assert_eq!(
        (status, location.as_str()),
        (StatusCode::FOUND, "/moved/caf%C3%A9/a%2Fb")
    );
    Ok(())
}

/// Codex review 39: a prefix matched after repeated slashes collapse keeps `{rest}` as sent.
#[tokio::test]
async fn direct_redirect_rest_after_repeated_slashes_keeps_encoding() -> TestResult {
    let (cfg, _) = parse_kdl(
        "slashes.kdl",
        r#"
server {
    listen ":8443"
    tls { cert "/c.pem"; key "/k.pem" }
}
site "shop.example" {
    route "/app/old/*" { redirect "/new/{rest}" status=302 }
}
"#,
    )?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    let (status, location) = fetch(&engine, Method::GET, "shop.example", "/app//old/a%2Fb").await?;
    assert_eq!(
        (status, location.as_str()),
        (StatusCode::FOUND, "/new/a%2Fb")
    );
    Ok(())
}

/// Codex review 40: a repeated separator written as `%2F` is skipped like routing does.
#[tokio::test]
async fn direct_redirect_rest_after_encoded_repeated_separator() -> TestResult {
    let (cfg, _) = parse_kdl(
        "encsep.kdl",
        r#"
server {
    listen ":8443"
    tls { cert "/c.pem"; key "/k.pem" }
}
site "shop.example" {
    route "/app/old/*" { redirect "/new/{rest}" status=302 }
}
"#,
    )?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    let (status, location) =
        fetch(&engine, Method::GET, "shop.example", "/app/%2Fold/a%2Fb").await?;
    assert_eq!(
        (status, location.as_str()),
        (StatusCode::FOUND, "/new/a%2Fb")
    );
    Ok(())
}

/// Regression test for bc9835b P1 #5: redirect-only listeners must still run the common
/// `ServerFramingRejection` -> `record_bad_request()` strike check so repeated bad `Host`
/// requests on one persistent connection reach the drain and close the connection.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn redirect_listener_repeated_bad_host_triggers_drain_and_close() -> TestResult {
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::sync::watch;

    // Read one HTTP/1.1 response from `client` and return its status line (or None on EOF).
    async fn read_one_status(
        client: &mut tokio::io::DuplexStream,
        buf: &mut Vec<u8>,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let mut chunk = [0_u8; 4096];
        loop {
            if let Some(head_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(buf.get(..head_end).unwrap_or(&[])).into_owned();
                let body_len = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|v| v.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                let total = head_end + 4 + body_len;
                if buf.len() >= total {
                    let status_line = head.lines().next().unwrap_or("").to_owned();
                    buf.drain(..total);
                    return Ok(Some(status_line));
                }
            }
            let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut chunk)).await??;
            if n == 0 {
                return Ok(None);
            }
            buf.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
        }
    }

    let (cfg, _) = parse_kdl(
        "redirect-drain.kdl",
        r#"
server {
    listen ":8080"
    timeouts {
        graceful-drain "200ms"
    }
}
site "shop.example" {
    route "/*" { redirect "https://shop.example{uri}" }
}
"#,
    )?;
    let engine = Arc::new(HttpEngine::from_config(
        &cfg,
        Arc::new(AcmeChallengeStore::new()),
        None,
        8443,
    )?);

    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let peer: SocketAddr = "198.51.100.25:51234".parse()?;
    let local: SocketAddr = "127.0.0.1:8080".parse()?;
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(engine.serve_hyper_connection(
        server,
        peer,
        local,
        false,
        true,
        None,
        shutdown_rx,
    ));

    let bad_req = b"GET / HTTP/1.1\r\nHost: bad/host\r\nConnection: keep-alive\r\n\r\n";
    let mut recv_buf = Vec::new();
    let mut bad_responses = 0_usize;
    let mut closed = false;
    // Default bad-request strike budget is 20 per 60s window; sending 25 must answer at least 20
    // with 400 and then trip the drain and close the connection before answering all 25.
    for i in 0..25 {
        if client.write_all(bad_req).await.is_err() {
            closed = true;
            break;
        }
        if let Ok(Some(status)) = read_one_status(&mut client, &mut recv_buf).await {
            assert!(
                status.contains("400"),
                "request {i} expected 400 Bad Request, got {status:?}"
            );
            bad_responses += 1;
        } else {
            closed = true;
            break;
        }
    }

    // Even if the 21st response was delivered cleanly before graceful shutdown took effect,
    // the connection task must drain and close on its own without the client dropping first.
    if !closed {
        let mut drain_buf = [0_u8; 256];
        closed = matches!(
            tokio::time::timeout(Duration::from_secs(1), client.read(&mut drain_buf)).await,
            Ok(Ok(0) | Err(_))
        );
    }
    assert!(
        bad_responses >= 20,
        "expected at least 20 400 responses before strike-budget close, got {bad_responses}"
    );
    assert!(
        bad_responses < 25,
        "redirect-only listener kept answering past strike budget ({bad_responses} 400 responses)"
    );
    assert!(
        closed,
        "redirect-only listener failed to drain and close after repeated bad Host strikes"
    );
    tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .map_err(|_| "redirect-only connection task did not terminate after bad-request drain")?
        .map_err(|err| format!("redirect-only connection task panicked or was cancelled: {err}"))?;
    Ok(())
}

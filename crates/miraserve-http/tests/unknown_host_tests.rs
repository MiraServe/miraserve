//! A server that hosts sites must not answer for hostnames it does not serve (returns `421`),
//! and must not describe itself to them. A configuration with no sites still returns `200`.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use http::header::HOST;
use http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use miraserve_config::parse_kdl;
use miraserve_http::{HttpEngine, RequestContext, empty_http_body};
use miraserve_tls::AcmeChallengeStore;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn ctx() -> RequestContext {
    RequestContext {
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))),
        remote_port: Some(54321),
        server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_port: 8443,
        is_https: true,
        tls: None,
    }
}

async fn get(
    engine: &HttpEngine,
    host: &str,
) -> Result<(StatusCode, String), Box<dyn std::error::Error>> {
    let req = Request::builder()
        .uri("/")
        .header(HOST, host)
        .header("accept", "text/html")
        .body(empty_http_body())?;
    let resp = engine.handle_request(req, &ctx()).await;
    let status = resp.status();
    let body = resp.into_body().collect().await?.to_bytes();
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

#[tokio::test]
async fn unknown_host_gets_421_and_no_self_description_when_sites_are_configured() -> TestResult {
    let root = std::env::temp_dir().join(format!("miraserve-unknown-host-{}", std::process::id()));
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("index.html"), b"<h1>site a</h1>")?;
    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "a.example.test" {{
    root "{}"
}}
"#,
        root.display()
    );
    let (cfg, _) = parse_kdl("unknown-host.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;

    let (known_status, known_body) = get(&engine, "a.example.test").await?;
    assert_eq!(known_status, StatusCode::OK);
    assert!(known_body.contains("site a"));

    let (status, body) = get(&engine, "not-hosted.example.test").await?;
    assert_eq!(
        status,
        StatusCode::MISDIRECTED_REQUEST,
        "a hostname this server does not serve must get 421, not a page"
    );
    assert!(
        !body.contains("sandbox") && !body.contains("Sandbox"),
        "the answer to an unserved hostname must not describe the server: {body}"
    );
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

#[tokio::test]
async fn fresh_install_with_no_sites_still_shows_the_welcome_page() -> TestResult {
    let kdl = r#"
server {
    listen ":8443"
    tls { cert "/c.pem"; key "/k.pem" }
}
"#;
    let (cfg, _) = parse_kdl("no-sites.kdl", kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    let (status, _) = get(&engine, "anything.example.test").await?;
    assert_eq!(status, StatusCode::OK);
    Ok(())
}

/// A custom error page that is missing or is a symlink leaving the site root must not fail
/// `HttpEngine::from_config`; the site keeps serving and that status falls back to the built-in
/// page without exposing the symlink target.
#[cfg(unix)]
#[tokio::test]
async fn unloadable_custom_error_pages_fall_back_instead_of_failing_the_engine() -> TestResult {
    let base = std::env::temp_dir().join(format!("miraserve-errpage-{}", std::process::id()));
    let root = base.join("site");
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("index.html"), b"<h1>ok</h1>")?;
    std::fs::write(root.join("good.html"), b"<h1>custom 403</h1>")?;
    std::fs::write(base.join("outside.html"), b"<h1>outside the root</h1>")?;
    std::os::unix::fs::symlink(base.join("outside.html"), root.join("errpage.html"))?;
    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "a.example.test" {{
    root "{}"
    error-pages {{
        page 404 "errpage.html"
        page 503 "missing.html"
        page 403 "good.html"
    }}
}}
"#,
        root.display()
    );
    let (cfg, _) = parse_kdl("errpage.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)
        .map_err(|err| format!("one site's bad error page must not fail the engine: {err}"))?;

    let (status, _) = get(&engine, "a.example.test").await?;
    assert_eq!(status, StatusCode::OK, "the site itself must keep serving");

    let req = Request::builder()
        .uri("/no-such-file")
        .header(HOST, "a.example.test")
        .header("accept", "text/html")
        .body(empty_http_body())?;
    let resp = engine.handle_request(req, &ctx()).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = resp.into_body().collect().await?.to_bytes();
    assert!(
        !String::from_utf8_lossy(&body).contains("outside the root"),
        "a symlink leaving the site root must never be served as the error page"
    );
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// `security-headers "standard"` must not send `includeSubDomains`: on shared hosting one
/// customer's site would pin HTTPS for every name under the parent domain. `strict` keeps it.
#[tokio::test]
async fn standard_hsts_has_no_include_subdomains_and_strict_keeps_it() -> TestResult {
    let root = std::env::temp_dir().join(format!("miraserve-hsts-{}", std::process::id()));
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("index.html"), b"ok")?;
    for (policy, expect_subdomains) in [("standard", false), ("strict", true)] {
        let kdl = format!(
            r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "a.example.test" {{
    root "{}"
    security-headers "{policy}"
}}
"#,
            root.display()
        );
        let (cfg, _) = parse_kdl("hsts.kdl", &kdl)?;
        let engine =
            HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
        let req = Request::builder()
            .uri("/")
            .header(HOST, "a.example.test")
            .body(empty_http_body())?;
        let resp = engine.handle_request(req, &ctx()).await;
        let hsts = resp
            .headers()
            .get("strict-transport-security")
            .and_then(|v| v.to_str().ok())
            .ok_or("HSTS header missing on an HTTPS response")?
            .to_owned();
        assert!(hsts.starts_with("max-age="), "{hsts}");
        assert_eq!(
            hsts.contains("includeSubDomains"),
            expect_subdomains,
            "security-headers \"{policy}\" sent: {hsts}"
        );
    }
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

/// A symlinked absolute `error-pages` path is refused, inside or outside the site root, and the
/// built-in page is used instead of the symlink target.
#[cfg(unix)]
#[tokio::test]
async fn absolute_error_page_symlink_is_never_served() -> TestResult {
    let base = std::env::temp_dir().join(format!("miraserve-abs-errpage-{}", std::process::id()));
    let root = base.join("site");
    let pages = base.join("pages");
    std::fs::create_dir_all(&root)?;
    std::fs::create_dir_all(&pages)?;
    std::fs::write(root.join("index.html"), b"ok")?;
    std::fs::write(base.join("other-account.txt"), b"OTHER ACCOUNT SECRET")?;
    std::fs::write(pages.join("real-403.html"), b"<h1>real custom 403</h1>")?;
    std::os::unix::fs::symlink(base.join("other-account.txt"), root.join("linked-404.html"))?;
    std::os::unix::fs::symlink(
        base.join("other-account.txt"),
        pages.join("linked-410.html"),
    )?;
    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "a.example.test" {{
    root "{root}"
    error-pages {{
        page 404 "{root}/linked-404.html"
        page 410 "{pages}/linked-410.html"
        page 403 "{pages}/real-403.html"
    }}
}}
"#,
        root = root.display(),
        pages = pages.display()
    );
    let (cfg, _) = parse_kdl("abs-errpage.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    let req = Request::builder()
        .uri("/no-such-file")
        .header(HOST, "a.example.test")
        .header("accept", "text/html")
        .body(empty_http_body())?;
    let resp = engine.handle_request(req, &ctx()).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = resp.into_body().collect().await?.to_bytes();
    assert!(
        !String::from_utf8_lossy(&body).contains("OTHER ACCOUNT SECRET"),
        "a symlinked absolute error page must not be followed"
    );
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

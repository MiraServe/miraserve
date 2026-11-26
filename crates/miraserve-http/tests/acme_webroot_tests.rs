#![forbid(unsafe_code)]
//! `server.acme-webroot`: HTTP-01 tokens an external ACME client writes into a server-owned
//! directory are answered for configured hosts, before sites and routes.
#![cfg(unix)]

use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::PermissionsExt as _;
use std::sync::Arc;

use http::header::HOST;
use http::{Method, Request, StatusCode};
use http_body_util::BodyExt as _;
use miraserve_config::parse_kdl;
use miraserve_http::{HttpEngine, RequestContext, empty_http_body};
use miraserve_tls::AcmeChallengeStore;

type TestResult = Result<(), Box<dyn std::error::Error>>;

async fn fetch(
    engine: &HttpEngine,
    host: &str,
    uri: &str,
) -> Result<(StatusCode, Vec<u8>), Box<dyn std::error::Error>> {
    let req = Request::builder()
        .method(Method::GET)
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
    let status = resp.status();
    let body = resp.into_body().collect().await?.to_bytes().to_vec();
    Ok((status, body))
}

#[tokio::test]
async fn acme_webroot_tokens_are_served_for_configured_hosts_only() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::env::temp_dir().join(format!(
        "miraserve-acme-webroot-{}-{nanos}",
        std::process::id()
    ));
    // The layout certbot and lego write: <webroot>/.well-known/acme-challenge/<token>.
    let webroot = base.join("webroot");
    let challenges = webroot.join(".well-known").join("acme-challenge");
    std::fs::create_dir_all(&challenges)?;
    std::fs::set_permissions(&challenges, std::fs::Permissions::from_mode(0o755))?;
    let token = "Tok_en-123";
    std::fs::write(
        challenges.join(token),
        b"Tok_en-123.AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdE\n",
    )?;
    std::fs::set_permissions(
        challenges.join(token),
        std::fs::Permissions::from_mode(0o644),
    )?;
    std::fs::write(challenges.join("loose"), b"loose.thumb")?;
    std::fs::set_permissions(
        challenges.join("loose"),
        std::fs::Permissions::from_mode(0o666),
    )?;
    // A token-named file that is not a key authorization (a key, say) is never returned.
    std::fs::write(
        challenges.join("KeyLike"),
        b"-----BEGIN PRIVATE KEY-----\nMII\n",
    )?;
    std::fs::set_permissions(
        challenges.join("KeyLike"),
        std::fs::Permissions::from_mode(0o644),
    )?;
    // A file directly in the webroot is not a challenge.
    std::fs::write(webroot.join("toplevel"), b"not a challenge")?;
    std::fs::set_permissions(
        webroot.join("toplevel"),
        std::fs::Permissions::from_mode(0o644),
    )?;

    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
    acme-webroot "{}"
}}
site "shop.example" {{
    route "/*" {{ respond 403 }}
}}
"#,
        webroot.display()
    );
    let (cfg, _) = parse_kdl("acme-webroot.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    let path = format!("/.well-known/acme-challenge/{token}");

    // Answered before the site's routes (which refuse everything).
    let (status, body) = fetch(&engine, "shop.example", &path).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        b"Tok_en-123.AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdE"
    );
    // Not for a host no site serves.
    let (status, _) = fetch(&engine, "other.example", &path).await?;
    assert_ne!(status, StatusCode::OK);
    // A token file writable by others is not trusted.
    let (status, _) = fetch(&engine, "shop.example", "/.well-known/acme-challenge/loose").await?;
    assert_ne!(status, StatusCode::OK);
    // Names outside the token alphabet are never looked up.
    let (status, _) = fetch(
        &engine,
        "shop.example",
        "/.well-known/acme-challenge/Tok_en-123.bak",
    )
    .await?;
    assert_ne!(status, StatusCode::OK);
    let (status, _) = fetch(
        &engine,
        "shop.example",
        "/.well-known/acme-challenge/KeyLike",
    )
    .await?;
    assert_ne!(status, StatusCode::OK);
    // Only the challenge subtree is read.
    let (status, _) = fetch(
        &engine,
        "shop.example",
        "/.well-known/acme-challenge/toplevel",
    )
    .await?;
    assert_ne!(status, StatusCode::OK);

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

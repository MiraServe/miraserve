//! Regressions for the round-12 security review: what a rewrite rule may reach, which address
//! Web Bot Auth verifies, how redirect targets are built, and the static 405 probe.

// `assert_is_empty` is new in clippy 1.100 and unknown to 1.95 (the minimum toolchain).
// `assert!(x.is_empty())` says what these tests mean.
#![allow(unknown_lints, clippy::assert_is_empty)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use base64::Engine as _;
use http::header::{ACCEPT_ENCODING, HOST, LOCATION, USER_AGENT};
use http::{HeaderMap, HeaderValue, Method, Request, StatusCode, Uri};
use http_body_util::BodyExt as _;
use miraserve_ai::sign_rfc9421_headers;
use miraserve_config::parse_kdl;
use miraserve_http::{HttpEngine, RequestContext, empty_http_body};
use miraserve_tls::AcmeChallengeStore;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SITE_HOST: &str = "r12.example.test";

struct Site {
    engine: HttpEngine,
    root: std::path::PathBuf,
}

impl Drop for Site {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn site(tag: &str, site_body: &str) -> Result<Site, Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!("miraserve-r12-{tag}-{}", std::process::id()));
    for dir in ["reports", "vault", "public/sub", "posts"] {
        std::fs::create_dir_all(root.join(dir))?;
    }
    std::fs::write(root.join("index.html"), b"FRONT")?;
    std::fs::write(root.join("reports/q3.txt"), b"INTERNAL REPORT")?;
    std::fs::write(root.join("vault/v.txt"), b"VAULT")?;
    std::fs::write(root.join("public/sub/n.txt"), b"NESTED")?;
    std::fs::write(
        root.join("public/site.css"),
        "body{color:red}\n".repeat(400),
    )?;
    std::fs::write(root.join("posts/42.html"), b"POST 42")?;
    std::fs::write(root.join("dump.sql"), b"SQL")?;
    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "{SITE_HOST}" {{
    root "{}"
{site_body}
}}
"#,
        root.display()
    );
    let (cfg, _) = parse_kdl("review12.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    Ok(Site { engine, root })
}

fn ctx() -> RequestContext {
    RequestContext {
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 12))),
        remote_port: Some(50_000),
        server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_port: 8443,
        is_https: true,
        tls: None,
    }
}

async fn send_with(
    site: &Site,
    method: Method,
    uri: &str,
    headers: &HeaderMap,
) -> Result<(StatusCode, String, String), Box<dyn std::error::Error>> {
    let mut builder = Request::builder().method(method).uri(uri);
    if !headers.contains_key(HOST) {
        builder = builder.header(HOST, SITE_HOST);
    }
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    let resp = site
        .engine
        .handle_request(builder.body(empty_http_body())?, &ctx())
        .await;
    let status = resp.status();
    let location = resp
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let body = resp.into_body().collect().await?.to_bytes();
    Ok((
        status,
        location,
        String::from_utf8_lossy(&body).into_owned(),
    ))
}

async fn get(
    site: &Site,
    uri: &str,
) -> Result<(StatusCode, String, String), Box<dyn std::error::Error>> {
    send_with(site, Method::GET, uri, &HeaderMap::new()).await
}

const REWRITES: &str = r#"
    rewrite {
        rule "^/pub/(.*)$" to="/reports/$1"
        rule "^/reports/" deny=403
        rule "^/dl/(.*)$" to="/vault/$1"
        rule "^/vault/" deny=404 method="GET"
        rule "^/files/(.*)$" to="/public/$1"
        rule "^/out/(.*)\\.txt$" redirect="/dl2/$1/x"
    }
"#;

/// Finding 2: a `deny` rule protects a path, not one of its names. The alias rules come first
/// in the file, so only a check of the final path can stop them.
#[tokio::test]
async fn deny_rule_applies_to_the_path_an_alias_rewrites_to() -> TestResult {
    let s = site("deny", REWRITES)?;

    assert_eq!(get(&s, "/reports/q3.txt").await?.0, StatusCode::FORBIDDEN);
    let (status, _, body) = get(&s, "/pub/q3.txt").await?;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an alias must not serve what a direct request is refused (body: {body:?})"
    );

    // A deny rule with a condition is evaluated for the final path with the same condition.
    assert_eq!(get(&s, "/vault/v.txt").await?.0, StatusCode::NOT_FOUND);
    let (status, _, body) = get(&s, "/dl/v.txt").await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {body:?}");
    let (status, _, _) = send_with(&s, Method::HEAD, "/dl/v.txt", &HeaderMap::new()).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "the deny rule is limited to GET, so HEAD through the alias is served"
    );

    // An alias into a path no rule denies still works.
    let (status, _, body) = get(&s, "/files/sub/n.txt").await?;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "NESTED"));
    Ok(())
}

/// Finding 13: an encoded `/` that a filesystem route refuses directly is still refused when it
/// arrives through an alias.
#[tokio::test]
async fn alias_keeps_the_strict_path_rules_of_the_visitors_own_path() -> TestResult {
    let s = site("flags", REWRITES)?;
    assert_eq!(
        get(&s, "/public/sub%2Fn.txt").await?.0,
        StatusCode::BAD_REQUEST
    );
    let (status, _, body) = get(&s, "/files/sub%2Fn.txt").await?;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the encoded separator must not be laundered by the rewrite (body: {body:?})"
    );
    Ok(())
}

/// Finding 6: a capture between two literal `/` must not become a `..` segment of a redirect.
#[tokio::test]
async fn redirect_capture_cannot_form_a_parent_directory_segment() -> TestResult {
    let s = site("dots", REWRITES)?;
    let (status, location, _) = get(&s, "/out/a.txt").await?;
    assert_eq!(
        (status, location.as_str()),
        (StatusCode::MOVED_PERMANENTLY, "/dl2/a/x")
    );
    // "/out/...txt": the pattern captures "..", which would give "/dl2/../x".
    let (status, location, _) = get(&s, "/out/...txt").await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "Location: {location:?}");
    assert!(location.is_empty());
    Ok(())
}

/// Finding 8: a rewrite redirect is subject to the site's rate limit like a redirect route.
#[tokio::test]
async fn rewrite_redirect_runs_after_the_site_rate_limit() -> TestResult {
    let s = site(
        "limit",
        r#"
    rate-limit requests=2 per="1m" burst=2
    rewrite {
        rule "^/gone/(.*)$" redirect="/new/$1"
    }
"#,
    )?;
    let mut statuses = Vec::new();
    for _ in 0..3 {
        statuses.push(get(&s, "/gone/x").await?.0);
    }
    assert_eq!(
        statuses,
        vec![
            StatusCode::MOVED_PERMANENTLY,
            StatusCode::MOVED_PERMANENTLY,
            StatusCode::TOO_MANY_REQUESTS
        ]
    );
    Ok(())
}

fn signed_headers(
    uri: &str,
    key_id: &str,
    key: &Ed25519KeyPair,
) -> Result<HeaderMap, Box<dyn std::error::Error>> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut headers = HeaderMap::new();
    headers.insert(HOST, HeaderValue::from_static(SITE_HOST));
    headers.insert(USER_AGENT, HeaderValue::from_static("GPTBot/1.0"));
    let uri: Uri = uri.parse()?;
    sign_rfc9421_headers(
        &Method::GET,
        &uri,
        &mut headers,
        key_id,
        key,
        now,
        now.saturating_add(120),
    )?;
    Ok(headers)
}

/// Finding 3: Web Bot Auth verifies the address the visitor signed and sent, not the internal
/// path a rewrite rule maps it to.
#[tokio::test]
async fn web_bot_auth_verifies_the_address_the_visitor_signed() -> TestResult {
    let key = Ed25519KeyPair::generate().map_err(|_| "key generation failed")?;
    let public_b64 = base64::engine::general_purpose::STANDARD.encode(key.public_key().as_ref());
    let s = site(
        "bot",
        &format!(
            r#"
    bot-auth {{
        verify-rfc9421 #true
        allow-agent "verified-ai-agents"
        on-unverified-ai-ua "block"
        agent-key "k1" agent-id="bot-k1" group="verified-ai-agents" ed25519="{public_b64}"
    }}
    rewrite {{
        rule "^/alias$" to="/posts/42.html"
        rule "^/other$" to="/posts/42.html"
    }}
"#
        ),
    )?;

    // Unsigned AI crawler: blocked (the policy is active).
    let mut unsigned = HeaderMap::new();
    unsigned.insert(USER_AGENT, HeaderValue::from_static("GPTBot/1.0"));
    assert_ne!(
        send_with(&s, Method::GET, "/alias", &unsigned).await?.0,
        StatusCode::OK
    );

    // A signature over the public alias is valid for a request to that alias.
    let headers = signed_headers("/alias", "k1", &key)?;
    let (status, _, body) = send_with(&s, Method::GET, "/alias", &headers).await?;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::OK, "POST 42"),
        "a bot that signs the address it requests must be verified"
    );

    // A signature bound to a different address does not authenticate this request, even though
    // both addresses are rewritten to the same internal path.
    let for_internal = signed_headers("/posts/42.html", "k1", &key)?;
    let (status, _, body) = send_with(&s, Method::GET, "/other", &for_internal).await?;
    assert_ne!(
        status,
        StatusCode::OK,
        "a signature for the internal path must not verify a request for another address (body: {body:?})"
    );
    let for_alias = signed_headers("/alias", "k1", &key)?;
    assert_ne!(
        send_with(&s, Method::GET, "/other", &for_alias).await?.0,
        StatusCode::OK
    );
    Ok(())
}

const REDIRECT_ROUTES: &str = r#"
    route "/s/*" { redirect "https://t.example.test/{rest}?{query}" status=302 }
    route "/q" { redirect "/new?{query}&a=1" status=302 }
    route "/w/*" { redirect "/?{query}/{rest}" status=302 }
    route "/n" { redirect "/login?next={uri}" status=302 }
    route "/big/*" { redirect "/x{path}{path}{path}" status=302 }
"#;

/// Finding 4: the template is read once; placeholder-shaped text that arrives in the request
/// is data and is never expanded.
#[tokio::test]
async fn placeholder_text_in_the_request_is_not_expanded() -> TestResult {
    let s = site("tokens", REDIRECT_ROUTES)?;
    let (status, location, _) = get(&s, "/s/%7Bquery%7D?next=%7Bpath%7D").await?;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        location,
        "https://t.example.test/%7Bquery%7D?next=%7Bpath%7D"
    );
    // Raw braces, where the HTTP library accepts them in a request target.
    if let Ok(uri) = "/s/{query}?next={path}".parse::<Uri>() {
        let (status, location, _) = get(&s, &uri.to_string()).await?;
        assert_eq!(status, StatusCode::FOUND);
        assert_eq!(location, "https://t.example.test/{query}?next={path}");
    }
    Ok(())
}

/// Finding 7: path and query are expanded separately, so an empty query can neither join two
/// slashes into a `//host` form nor turn a fixed query parameter into path text.
#[tokio::test]
async fn empty_query_cannot_change_the_shape_of_a_redirect() -> TestResult {
    let s = site("query", REDIRECT_ROUTES)?;

    assert_eq!(get(&s, "/q").await?.1, "/new?a=1");
    assert_eq!(get(&s, "/q?x=1&y=2").await?.1, "/new?x=1&y=2&a=1");

    let (status, location, _) = get(&s, "/w/evil.example.test/x").await?;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(location, "/?/evil.example.test/x");
    assert!(
        !location.starts_with("//"),
        "a local redirect must stay local: {location}"
    );

    // A path or URI used as a query value stays one value.
    assert_eq!(
        get(&s, "/n?x=1&y=2").await?.1,
        "/login?next=/n%3Fx%3D1%26y%3D2"
    );
    Ok(())
}

/// Finding 4: a template that repeats a placeholder cannot turn a bounded request into an
/// unbounded header.
#[tokio::test]
async fn redirect_target_has_a_size_limit() -> TestResult {
    let s = site("budget", REDIRECT_ROUTES)?;
    let (status, location, _) = get(&s, "/big/short").await?;
    assert_eq!(
        (status, location.as_str()),
        (StatusCode::FOUND, "/x/big/short/big/short/big/short")
    );
    let long = format!("/big/{}", "a".repeat(3_000));
    let (status, location, _) = get(&s, &long).await?;
    assert_eq!(status, StatusCode::URI_TOO_LONG);
    assert!(location.is_empty());
    Ok(())
}

/// Finding 11: the 405 answer for a write method needs to know only whether GET would find the
/// path. It answers the same for a large compressible file, a missing file and a hidden one.
#[tokio::test]
async fn write_method_on_static_files_is_405_only_for_what_get_would_serve() -> TestResult {
    let s = site("probe", "")?;
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip, br, zstd"));

    let (status, _, body) = send_with(&s, Method::POST, "/public/site.css", &headers).await?;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert!(
        body.len() < 2_000,
        "405 must not carry the file ({} bytes)",
        body.len()
    );
    assert_eq!(
        send_with(&s, Method::POST, "/public/missing.css", &headers)
            .await?
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send_with(&s, Method::POST, "/dump.sql", &headers).await?.0,
        StatusCode::NOT_FOUND,
        "a path GET refuses to serve is not revealed by 405"
    );
    assert_eq!(
        send_with(&s, Method::DELETE, "/public/sub", &headers)
            .await?
            .0,
        StatusCode::NOT_FOUND,
        "a directory without an index is not found for GET either"
    );
    Ok(())
}

fn config_error(site_body: &str) -> Option<String> {
    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "{SITE_HOST}" {{
    root "/srv/www"
{site_body}
}}
"#
    );
    parse_kdl("review12-config.kdl", &kdl)
        .err()
        .map(|err| format!("{err:?}"))
}

/// Finding 1: an internal rewrite target has no fragment. The HTTP library would drop it while
/// route matching still saw it, so the two could disagree about the path.
#[test]
fn internal_rewrite_target_with_a_fragment_is_rejected_by_the_config() {
    let err = config_error(r#"    rewrite { rule "^/s$" to="/staff#overview" }"#);
    assert!(
        err.as_deref().is_some_and(|e| e.contains("E308")),
        "expected E308, got {err:?}"
    );
    // A redirect may carry a fragment: it is only sent to the browser.
    assert_eq!(
        config_error(r#"    rewrite { rule "^/s$" redirect="/staff#overview" }"#),
        None
    );
}

/// Finding 12: a fixed response cannot send the header these statuses require.
#[test]
fn respond_statuses_that_need_a_header_are_rejected_by_the_config() {
    for status in [401, 405, 407, 426] {
        let err = config_error(&format!(r#"    route "/x" {{ respond {status} }}"#));
        assert!(
            err.as_deref().is_some_and(|e| e.contains("E306")),
            "respond {status} must be rejected with E306, got {err:?}"
        );
    }
    for status in [403, 404, 410, 503] {
        assert_eq!(
            config_error(&format!(r#"    route "/x" {{ respond {status} }}"#)),
            None,
            "respond {status} must stay allowed"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Round 13
// ---------------------------------------------------------------------------------------------

/// Review 13, P1: a `deny` rule also covers the script the server itself selects, as a
/// directory index or as a `try-files` fallback. The backend must not be contacted at all.
#[tokio::test]
async fn deny_rule_covers_the_script_selected_as_index_or_fallback() -> TestResult {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let contacted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&contacted);
    let backend = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });

    let s = site(
        "final-script",
        &format!(
            r#"
    index "index.php" "index.html"
    rewrite {{
        rule "^/admin/index\\.php$" deny=403
    }}
    route "/app/*" {{
        try-files "{{path}}" "/admin/index.php?{{query}}"
    }}
    route "*.php" {{ fastcgi-pass "tcp://127.0.0.1:{port}" }}
"#
        ),
    )?;
    std::fs::create_dir_all(s.root.join("admin"))?;
    std::fs::write(s.root.join("admin/index.php"), b"<?php echo 'admin';")?;

    assert_eq!(get(&s, "/admin/index.php").await?.0, StatusCode::FORBIDDEN);
    let (status, _, body) = get(&s, "/admin/").await?;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the directory index selects the denied script (body: {body:?})"
    );
    let (status, _, body) = get(&s, "/app/nothing-here").await?;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the try-files fallback selects the denied script (body: {body:?})"
    );
    assert_eq!(
        contacted.load(Ordering::SeqCst),
        0,
        "the PHP backend must not be contacted for a denied script"
    );
    backend.abort();
    Ok(())
}

/// Review 13: a redirect's fragment comes after the query the request contributes.
#[tokio::test]
async fn kept_query_goes_before_a_redirect_fragment() -> TestResult {
    let s = site(
        "fragment",
        r#"
    rewrite {
        rule "^/old$" redirect="/help#intro"
        rule "^/old2$" redirect="/help?page=1#intro"
    }
"#,
    )?;
    assert_eq!(get(&s, "/old?lang=lo").await?.1, "/help?lang=lo#intro");
    assert_eq!(get(&s, "/old").await?.1, "/help#intro");
    assert_eq!(
        get(&s, "/old2?lang=lo").await?.1,
        "/help?page=1&lang=lo#intro"
    );
    Ok(())
}

/// Review 13: a header value with a byte that is not UTF-8 is still a value that is present.
#[tokio::test]
async fn header_conditions_see_values_with_opaque_bytes() -> TestResult {
    let s = site(
        "opaque-header",
        r#"
    rewrite {
        rule "^/img/" deny=403 {
            header "Referer" "."
            not-header "Referer" "^https://r12[.]example[.]test/"
        }
    }
"#,
    )?;
    std::fs::create_dir_all(s.root.join("img"))?;
    std::fs::write(s.root.join("img/a.txt"), b"IMG")?;

    let mut own = HeaderMap::new();
    own.insert(
        "referer",
        HeaderValue::from_static("https://r12.example.test/page"),
    );
    assert_eq!(
        send_with(&s, Method::GET, "/img/a.txt", &own).await?.0,
        StatusCode::OK
    );
    assert_eq!(get(&s, "/img/a.txt").await?.0, StatusCode::OK, "no Referer");

    let mut opaque = HeaderMap::new();
    opaque.insert(
        "referer",
        HeaderValue::from_bytes(b"https://evil.example/\xff")?,
    );
    assert_eq!(
        send_with(&s, Method::GET, "/img/a.txt", &opaque).await?.0,
        StatusCode::FORBIDDEN,
        "a foreign Referer with a high byte is present and not on the allow-list"
    );
    Ok(())
}

/// Review 13: the file tests of a rule agree with what the static server serves. A regular file
/// named with a trailing slash is not served, so it does not count as an existing file.
#[tokio::test]
async fn file_conditions_treat_a_file_with_trailing_slash_as_absent() -> TestResult {
    let s = site(
        "slash",
        r#"
    rewrite {
        rule "^/public/" redirect="/fallback" status=302 if-not-regular-file=#true
    }
"#,
    )?;
    assert_eq!(get(&s, "/public/sub/n.txt").await?.0, StatusCode::OK);
    assert_eq!(get(&s, "/public/missing.txt").await?.0, StatusCode::FOUND);
    assert_eq!(
        get(&s, "/public/sub/n.txt/").await?.0,
        StatusCode::FOUND,
        "the spelling the static server refuses takes the fallback like a missing path"
    );
    Ok(())
}

/// Review 13: configuration that would be dropped silently, or expanded on every request, is
/// refused when it is loaded.
#[test]
fn round13_config_rejections() {
    // A property or child block on a condition line.
    for body in [
        r#"    rewrite { rule "^/a" pass=#true { header "X-A" "1" extra="2" } }"#,
        r#"    rewrite { rule "^/a" pass=#true { header "X-A" "1" { query "x" } } }"#,
    ] {
        let err = config_error(body);
        assert!(
            err.as_deref().is_some_and(|e| e.contains("E306")),
            "expected E306 for {body}, got {err:?}"
        );
    }
    // Oversized templates.
    let long = "a".repeat(2_100);
    for body in [
        format!(r#"    route "/x" {{ redirect "/{long}" }}"#),
        format!(r#"    rewrite {{ rule "^/x$" to="/{long}" }}"#),
    ] {
        assert!(
            config_error(&body).is_some(),
            "a 2 KiB template must be refused"
        );
    }
    // try-files terminal statuses that need a header.
    for status in [401, 405] {
        let err = config_error(&format!(
            r#"    route "/t/*" {{ try-files "{{path}}" "={status}" }}"#
        ));
        assert!(
            err.as_deref().is_some_and(|e| e.contains("E306")),
            "try-files ={status} must be rejected, got {err:?}"
        );
    }
    assert_eq!(
        config_error(r#"    route "/t/*" { try-files "{path}" "=404" }"#),
        None
    );
}

// ---------------------------------------------------------------------------------------------
// Per-site and per-route response headers (`headers { set; add; remove }`)
// ---------------------------------------------------------------------------------------------

async fn get_headers(
    site: &Site,
    uri: &str,
) -> Result<(StatusCode, http::HeaderMap), Box<dyn std::error::Error>> {
    let resp = site
        .engine
        .handle_request(
            Request::builder()
                .uri(uri)
                .header(HOST, SITE_HOST)
                .body(empty_http_body())?,
            &ctx(),
        )
        .await;
    Ok((resp.status(), resp.headers().clone()))
}

#[tokio::test]
async fn site_and_route_headers_apply_to_every_response() -> TestResult {
    let s = site(
        "resp-headers",
        r#"
    headers {
        set "Cache-Control" "public, max-age=600"
        set "X-Frame-Options" "SAMEORIGIN"
        add "Vary" "Cookie"
        remove "Referrer-Policy"
    }
    route "/posts/*" {
        static
        headers {
            set "Cache-Control" "no-store"
            set "X-Route" "posts"
        }
    }
"#,
    )?;
    let (status, h) = get_headers(&s, "/index.html").await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        h.get("cache-control").and_then(|v| v.to_str().ok()),
        Some("public, max-age=600")
    );
    assert_eq!(
        h.get("x-frame-options").and_then(|v| v.to_str().ok()),
        Some("SAMEORIGIN")
    );
    let vary: Vec<&str> = h
        .get_all("vary")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    assert!(
        vary.contains(&"Cookie"),
        "add keeps existing values: {vary:?}"
    );
    assert!(vary.len() >= 2, "the server's own Vary stays: {vary:?}");
    assert!(
        h.get("referrer-policy").is_none(),
        "remove takes out a security header"
    );

    // The route's changes come after the site's.
    let (status, h) = get_headers(&s, "/posts/42.html").await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        h.get("cache-control").and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        h.get("x-route").and_then(|v| v.to_str().ok()),
        Some("posts")
    );
    assert_eq!(
        h.get("x-frame-options").and_then(|v| v.to_str().ok()),
        Some("SAMEORIGIN")
    );

    // Error responses of the site get the site's headers too (Apache "Header always set").
    let (status, h) = get_headers(&s, "/missing.txt").await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        h.get("x-frame-options").and_then(|v| v.to_str().ok()),
        Some("SAMEORIGIN")
    );
    Ok(())
}

#[test]
fn unsafe_header_changes_are_rejected_by_the_config() {
    for body in [
        r#"    headers { set "Content-Length" "5" }"#,
        r#"    headers { set "Transfer-Encoding" "chunked" }"#,
        r#"    headers { remove "Connection" }"#,
        r#"    headers { set "Bad Name" "x" }"#,
        r#"    headers { set "X-A" }"#,
        r#"    headers { remove "X-A" "value" }"#,
        r#"    headers { replace "X-A" "1" }"#,
        r#"    headers { set "X-A" "1" extra=#true }"#,
        r#"    route "/a/*" { static; headers { set "Content-Encoding" "gzip" } }"#,
    ] {
        let err = config_error(body);
        assert!(
            err.as_deref()
                .is_some_and(|e| e.contains("E309") || e.contains("E002")),
            "{body} must be rejected, got {err:?}"
        );
    }
    let mut many = String::from("    headers {\n");
    for i in 0..65 {
        many.push_str("        set \"X-H");
        many.push_str(&i.to_string());
        many.push_str("\" \"v\"\n");
    }
    many.push_str("    }");
    assert!(
        config_error(&many).is_some(),
        "more than 64 changes are refused"
    );
    assert_eq!(
        config_error(
            r#"    headers { set "Strict-Transport-Security" "max-age=60"; remove "X-Powered-By" }"#
        ),
        None
    );
}

/// `if-file` and `if-regular-file`: the positive file tests (Apache `-f`/`-d` and `-f`).
#[tokio::test]
async fn positive_file_tests_match_only_existing_paths() -> TestResult {
    let s = site(
        "if-file",
        r#"
    rewrite {
        rule "^/public/(.*)$" redirect="/found/$1" status=302 if-regular-file=#true
        rule "^/posts(/.*)?$" redirect="/exists" status=302 if-file=#true
    }
"#,
    )?;
    let (status, location, _) = get(&s, "/public/sub/n.txt").await?;
    assert_eq!(
        (status, location.as_str()),
        (StatusCode::FOUND, "/found/sub/n.txt")
    );
    assert_eq!(
        get(&s, "/public/missing.txt").await?.0,
        StatusCode::NOT_FOUND
    );
    let (status, location, _) = get(&s, "/public/sub").await?;
    assert_eq!(
        (status, location.as_str()),
        (StatusCode::NOT_FOUND, ""),
        "a directory is not a regular file: the rule does not apply (and it has no index)"
    );
    assert_eq!(get(&s, "/posts").await?.1, "/exists", "a directory exists");
    assert_eq!(get(&s, "/posts/42.html").await?.1, "/exists");
    assert_eq!(get(&s, "/posts/nope.html").await?.0, StatusCode::NOT_FOUND);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Visitor address: `access { allow; deny }` and the `client-ip` rewrite condition.
// The test client is 198.51.100.12 (see `ctx`).
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn access_lists_allow_and_deny_by_visitor_address() -> TestResult {
    let s = site(
        "access",
        r#"
    access {
        allow "198.51.100.0/24"
        deny "all"
    }
"#,
    )?;
    assert_eq!(
        get(&s, "/index.html").await?.0,
        StatusCode::OK,
        "inside the /24"
    );
    let s = site(
        "access-office",
        r#"
    access {
        allow "10.0.0.0/8"
        deny "all"
    }
"#,
    )?;
    assert_eq!(
        get(&s, "/vault/v.txt").await?.0,
        StatusCode::FORBIDDEN,
        "not in 10.0.0.0/8"
    );
    // A forwarded address from an untrusted peer is ignored.
    let mut spoof = HeaderMap::new();
    spoof.insert("x-forwarded-for", HeaderValue::from_static("10.1.2.3"));
    assert_eq!(
        send_with(&s, Method::GET, "/vault/v.txt", &spoof).await?.0,
        StatusCode::FORBIDDEN
    );
    assert!(
        config_error(r#"    route "/v/*" { static; access { deny "all" } }"#).is_some(),
        "route-level visitor lists are refused in this release"
    );

    let denied_site = site(
        "access-site",
        r#"
    access {
        allow "203.0.113.0/24"
        deny "all"
    }
"#,
    )?;
    assert_eq!(
        get(&denied_site, "/index.html").await?.0,
        StatusCode::FORBIDDEN,
        "the site list applies to every path"
    );
    Ok(())
}

#[tokio::test]
async fn rewrite_condition_on_the_visitor_address() -> TestResult {
    let s = site(
        "client-ip",
        r#"
    rewrite {
        rule "^/office$" redirect="/inside" status=302 {
            client-ip "198.51.100.0/24"
        }
        rule "^/office$" redirect="/outside" status=302
        rule "^/other$" redirect="/not-in-ten" status=302 {
            not-client-ip "10.0.0.0/8"
        }
    }
"#,
    )?;
    assert_eq!(get(&s, "/office").await?.1, "/inside");
    assert_eq!(get(&s, "/other").await?.1, "/not-in-ten");
    Ok(())
}

#[test]
fn invalid_access_lines_and_client_ip_conditions_are_rejected() {
    for body in [
        r#"    access { allow "not-an-ip" }"#,
        r#"    access { allow "10.0.0.0/33" }"#,
        r#"    access { permit "all" }"#,
        r#"    access { allow "all" "extra" }"#,
        r#"    rewrite { rule "^/a$" pass=#true { client-ip "nope" } }"#,
    ] {
        assert!(config_error(body).is_some(), "{body} must be rejected");
    }
    assert_eq!(
        config_error(r#"    access { allow "2001:db8::/32"; deny "all" }"#),
        None
    );
}

// ---------------------------------------------------------------------------------------------
// Password-protected paths (`basic-auth`)
// ---------------------------------------------------------------------------------------------

fn basic(user: &str, password: &str) -> Result<HeaderMap, Box<dyn std::error::Error>> {
    let mut headers = HeaderMap::new();
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
    headers.insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Basic {token}"))?,
    );
    Ok(headers)
}

fn users_file(tag: &str) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!("miraserve-htpasswd-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let dir = dir.join(".htpasswds");
    std::fs::create_dir_all(&dir)?;
    let users = dir.join("users");
    std::fs::write(&users, format!("ann:{}\n", bcrypt::hash("s3cret", 4)?))?;
    Ok(users)
}

#[tokio::test]
async fn rewrite_deny_covers_a_php_script_reached_with_path_info() -> TestResult {
    let s = site("deny-path-info", "")?;
    std::fs::write(s.root.join("admin.php"), b"<?php echo 1;")?;
    let s = site(
        "deny-path-info",
        r#"
    rewrite {
        rule "^/admin\\.php$" deny=403
    }
    route "*.php" {
        fastcgi-pass "tcp://127.0.0.1:9"
    }
"#,
    )?;
    assert_eq!(get(&s, "/admin.php").await?.0, StatusCode::FORBIDDEN);
    assert_eq!(get(&s, "/admin.php/extra").await?.0, StatusCode::FORBIDDEN);
    Ok(())
}

#[test]
fn users_files_need_one_cost_and_decodable_records() -> TestResult {
    let mixed = format!("a:{}\nb:{}\n", bcrypt::hash("x", 4)?, bcrypt::hash("y", 5)?);
    let err = miraserve_config::parse_htpasswd(&mixed)
        .err()
        .unwrap_or_default();
    assert!(err.contains("line 2"), "{err}");
    // Valid alphabet and length, but the last digest character has trailing bits set.
    let mut damaged = bcrypt::hash("x", 4)?;
    damaged.pop();
    damaged.push('z');
    assert!(miraserve_config::parse_htpasswd(&format!("a:{damaged}\n")).is_err());
    Ok(())
}

#[tokio::test]
async fn site_basic_auth_protects_every_path_of_the_site() -> TestResult {
    let users = users_file("site")?;
    let s = site(
        "basic-auth-site",
        &format!(
            r#"
    basic-auth "{}" realm="Members only"
    headers {{ set "cache-control" "public, max-age=600" }}
    route "/*" {{
        try-files "{{path}}" "/vault/v.txt"
    }}
"#,
            users.display()
        ),
    )?;
    for path in ["/index.html", "/vault/v.txt", "/no-such-page", "/"] {
        let resp = s
            .engine
            .handle_request(
                Request::builder()
                    .uri(path)
                    .header(HOST, SITE_HOST)
                    .body(empty_http_body())?,
                &ctx(),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(
            resp.headers()
                .get(http::header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok()),
            Some("Basic realm=\"Members only\", charset=\"UTF-8\""),
            "{path}"
        );
        assert_eq!(
            resp.headers()
                .get(http::header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store"),
            "{path}: a refusal is never cacheable"
        );
    }
    assert_eq!(
        send_with(&s, Method::GET, "/vault/v.txt", &basic("ann", "wrong")?)
            .await?
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send_with(&s, Method::GET, "/vault/v.txt", &basic("bob", "s3cret")?)
            .await?
            .0,
        StatusCode::UNAUTHORIZED
    );
    let mut ok = basic("ann", "s3cret")?;
    ok.insert(HOST, HeaderValue::from_static(SITE_HOST));
    let req = ok
        .iter()
        .fold(Request::builder().uri("/no-such-page"), |b, (n, v)| {
            b.header(n, v)
        });
    let resp = s
        .engine
        .handle_request(req.body(empty_http_body())?, &ctx())
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let cache = resp
        .headers()
        .get(http::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    assert!(
        cache.starts_with("private") && !cache.contains("public"),
        "{cache}"
    );
    Ok(())
}

#[tokio::test]
async fn site_basic_auth_with_an_unusable_users_file_answers_503() -> TestResult {
    let dir = std::env::temp_dir().join(format!("miraserve-htpasswd-md5-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let dir = dir.join(".htpasswds");
    std::fs::create_dir_all(&dir)?;
    let users = dir.join("legacy");
    std::fs::write(&users, "old:$apr1$salt$hashhashhash\n")?;
    let s = site(
        "basic-auth-md5",
        &format!(r#"    basic-auth "{}""#, users.display()),
    )?;
    assert_eq!(
        get(&s, "/index.html").await?.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let err = miraserve_config::parse_htpasswd("ok:x\nold:$apr1$salt$hashhashhash\n")
        .err()
        .unwrap_or_default();
    assert!(err.contains("line 1") && !err.contains("$apr1$"), "{err}");
    assert!(
        miraserve_config::parse_htpasswd(&format!("a:{h}\na:{h}\n", h = bcrypt::hash("x", 4)?))
            .is_err(),
        "duplicate users are refused"
    );
    assert!(
        miraserve_config::parse_htpasswd(&format!("a:{}\n", bcrypt::hash("x", 13)?)).is_err(),
        "costs above 12 are refused"
    );
    assert!(config_error(r#"    basic-auth "relative/.dir/file""#).is_some());

    assert!(
        config_error(r#"    route "/v/*" { static; basic-auth "/etc/x" }"#).is_some(),
        "route-level passwords are refused in this release"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn users_file_inside_a_served_root_refuses_the_configuration() -> TestResult {
    let s = site("basic-auth-in-root", "")?;
    std::fs::create_dir_all(s.root.join(".htpasswds"))?;
    let users = s.root.join(".htpasswds/users");
    std::fs::write(&users, format!("ann:{}\n", bcrypt::hash("s3cret", 4)?))?;
    let refused = site(
        "basic-auth-in-root",
        &format!(r#"    basic-auth "{}""#, users.display()),
    );
    let err = refused.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(err.contains("could be downloaded"), "{err}");
    Ok(())
}

#[tokio::test]
async fn ip_policy_sites_ask_a_migrated_http3_client_to_reconnect() -> TestResult {
    async fn send(s: &Site, migrated: bool) -> Result<StatusCode, Box<dyn std::error::Error>> {
        let mut req = Request::builder()
            .uri("/index.html")
            .header(HOST, SITE_HOST)
            .body(empty_http_body())?;
        if migrated {
            req.extensions_mut().insert(miraserve_http::PeerMigrated);
        }
        Ok(s.engine.handle_request(req, &ctx()).await.status())
    }
    let guarded = site(
        "h3-migrate",
        r#"    access { allow "198.51.100.0/24"; deny "all" }"#,
    )?;
    assert_eq!(send(&guarded, false).await?, StatusCode::OK);
    assert_eq!(send(&guarded, true).await?, StatusCode::MISDIRECTED_REQUEST);
    let public = site("h3-migrate-public", "")?;
    assert_eq!(
        send(&public, true).await?,
        StatusCode::OK,
        "sites without IP rules serve migrated requests as before this release"
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn users_file_writable_by_others_makes_the_site_unavailable() -> TestResult {
    use std::os::unix::fs::PermissionsExt as _;
    let users = users_file("owner")?;
    let dir = users.parent().ok_or("no dir")?.to_path_buf();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777))?;
    let s = site(
        "basic-auth-owner",
        &format!(r#"    basic-auth "{}""#, users.display()),
    )?;
    assert_eq!(
        send_with(&s, Method::GET, "/index.html", &basic("ann", "s3cret")?)
            .await?
            .0,
        StatusCode::SERVICE_UNAVAILABLE,
        "a users file in a directory others can write is not used"
    );
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))?;
    let s = site(
        "basic-auth-owner",
        &format!(r#"    basic-auth "{}""#, users.display()),
    )?;
    assert_eq!(
        send_with(&s, Method::GET, "/index.html", &basic("ann", "s3cret")?)
            .await?
            .0,
        StatusCode::OK
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn users_files_are_never_served_through_a_linked_root() -> TestResult {
    let users = users_file("linked-root")?;
    let auth_dir = users.parent().ok_or("no dir")?.to_path_buf();
    let base = std::env::temp_dir().join(format!("miraserve-linked-root-{}", std::process::id()));
    std::fs::create_dir_all(&base)?;
    let public_root = base.join("public");
    let _ = std::fs::remove_file(&public_root);
    std::os::unix::fs::symlink(&auth_dir, &public_root)?;
    std::fs::write(auth_dir.join("ok.txt"), b"PUBLIC")?;
    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "a.example.test" {{
    root "{a}"
    basic-auth "{users}"
}}
site "b.example.test" {{
    root "{b}"
}}
"#,
        a = base.display(),
        users = users.display(),
        b = public_root.display(),
    );
    let (cfg, _) = parse_kdl("linked.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    let get_b = |path: &'static str| {
        Request::builder()
            .uri(path)
            .header(HOST, "b.example.test")
            .body(empty_http_body())
    };
    let users_name = format!(
        "/{}",
        users.file_name().and_then(|n| n.to_str()).unwrap_or("")
    );
    let resp = engine
        .handle_request(
            Request::builder()
                .uri(users_name.as_str())
                .header(HOST, "b.example.test")
                .body(empty_http_body())?,
            &ctx(),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "the users file is never served"
    );
    let resp = engine.handle_request(get_b("/ok.txt")?, &ctx()).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "other files of that root are served"
    );
    let _ = std::fs::remove_file(auth_dir.join("ok.txt"));
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn owner_dir_confines_each_site_to_its_account() -> TestResult {
    let base = std::env::temp_dir().join(format!("miraserve-owner-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let alice = base.join("home/alice");
    let bob = base.join("home/bob");
    std::fs::create_dir_all(alice.join("releases/v2"))?;
    std::fs::create_dir_all(bob.join("public_html"))?;
    std::fs::write(alice.join("releases/v2/index.html"), b"ALICE")?;
    std::fs::write(bob.join("public_html/index.html"), b"BOB")?;
    // A deployment link inside Alice's home, and one pointing into Bob's.
    std::os::unix::fs::symlink(alice.join("releases/v2"), alice.join("current"))?;
    std::os::unix::fs::symlink(bob.join("public_html"), alice.join("stolen"))?;
    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "alice.example.test" {{
    owner-dir "{alice}"
    root "{alice}/current"
}}
site "thief.example.test" {{
    owner-dir "{alice}"
    root "{alice}/stolen"
}}
site "bob.example.test" {{
    owner-dir "{bob}"
    root "{bob}/public_html"
}}
"#,
        alice = alice.display(),
        bob = bob.display(),
    );
    let (cfg, _) = parse_kdl("owner.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    for (host, status) in [
        ("alice.example.test", StatusCode::OK),
        ("thief.example.test", StatusCode::SERVICE_UNAVAILABLE),
        ("bob.example.test", StatusCode::OK),
    ] {
        let resp = engine
            .handle_request(
                Request::builder()
                    .uri("/index.html")
                    .header(HOST, host)
                    .body(empty_http_body())?,
                &ctx(),
            )
            .await;
        assert_eq!(resp.status(), status, "{host}");
    }
    assert!(config_error(r#"    owner-dir "relative/home""#).is_some());
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// A reload that leaves a limit as it was keeps its counts (site, route and the WordPress login
/// throttle of the preset); a changed limit starts anew (Cloudflare-skills audit of v0.1.0,
/// claim 34).
#[tokio::test]
async fn rate_limits_count_on_across_a_reload() -> TestResult {
    let s = site("limit-reload", "")?;
    let config = |site_limit: u32| {
        let kdl = format!(
            r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "{SITE_HOST}" {{
    root "{root}"
    preset "wordpress-hardened"
    rate-limit requests={site_limit} per="1m" burst={site_limit}
    route "/reports/*" {{
        rate-limit requests=1 per="1m" burst=1
        try-files "{{path}}" "=404"
    }}
}}
"#,
            root = s.root.display()
        );
        parse_kdl("limit-reload.kdl", &kdl).map(|(cfg, _)| cfg)
    };
    s.engine.reload(&config(3)?)?;
    let site = &s;
    let status = |uri: &'static str| async move { get(site, uri).await.map(|answer| answer.0) };
    // The route's one request, then the site's remaining two.
    assert_eq!(status("/reports/q3.txt").await?, StatusCode::OK);
    assert_eq!(
        status("/reports/q3.txt").await?,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(status("/").await?, StatusCode::OK);
    assert_eq!(status("/").await?, StatusCode::TOO_MANY_REQUESTS);

    // The same configuration again: nobody is let in again.
    s.engine.reload(&config(3)?)?;
    assert_eq!(status("/").await?, StatusCode::TOO_MANY_REQUESTS);

    // Another site limit: that one starts anew, the route's is as it was.
    s.engine.reload(&config(50)?)?;
    assert_eq!(status("/").await?, StatusCode::OK);
    assert_eq!(
        status("/reports/q3.txt").await?,
        StatusCode::TOO_MANY_REQUESTS
    );
    Ok(())
}

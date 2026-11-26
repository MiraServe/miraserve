//! End-to-end HTTP/1.1 & HTTP/2 integration tests for the opt-in static file cache.
//!
//! The tests of fills and hits are compiled for Linux and Android only: the cache admits a
//! response only when its file was opened by one whole-path kernel lookup, which exists on
//! those platforms alone; elsewhere nothing is ever stored (pinned by
//! `file_cache_without_link_free_lookup_tests` in `miraserve-static`). The other tests run everywhere.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine as _;
use bytes::Bytes;
#[cfg_attr(
    not(any(target_os = "linux", target_os = "android")),
    allow(dead_code, unused_imports)
)]
use http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, HOST};
use http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use miraserve_config::parse_kdl;
use miraserve_http::{CredentialSources, HttpBody, HttpEngine, ManualClock, RequestContext};
use miraserve_tls::AcmeChallengeStore;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::watch;

type TestResult = Result<(), Box<dyn std::error::Error>>;

static TEST_SEQ: AtomicU64 = AtomicU64::new(1);

/// Serializes tests that publish process-wide credentials (`CREDENTIAL_EPOCH` bumps) against
/// sibling cache-hit/fill tests running concurrently in the same test binary.
static CRED_EPOCH_TEST_LOCK: tokio::sync::RwLock<()> = tokio::sync::RwLock::const_new(());

fn temp_dir(label: &str) -> Result<PathBuf, std::io::Error> {
    let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let dir = std::env::temp_dir().join(format!(
        "miraserve-http-fc-{label}-{}-{seq}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn kdl_path(path: &Path) -> String {
    let raw = path.to_string_lossy();
    let stripped = raw.strip_prefix(r"\\?\").unwrap_or(&raw);
    stripped.replace('\\', "/")
}

fn empty_http_body() -> HttpBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn req_ctx(ip: &str, is_https: bool) -> Result<RequestContext, Box<dyn std::error::Error>> {
    Ok(RequestContext {
        client_ip: Some(ip.parse()?),
        remote_port: Some(50_000),
        server_addr: Some("127.0.0.1".parse()?),
        server_port: 8443,
        is_https,
        tls: None,
    })
}

fn build_engine(
    kdl: &str,
    clock: &ManualClock,
) -> Result<Arc<HttpEngine>, Box<dyn std::error::Error>> {
    let (cfg, _) = parse_kdl("test.kdl", kdl)?;
    Ok(Arc::new(HttpEngine::from_config_with_file_cache_clock(
        &cfg,
        Arc::new(AcmeChallengeStore::new()),
        None,
        8443,
        CredentialSources::default(),
        clock.cache_clock(),
    )?))
}

#[cfg_attr(
    not(any(target_os = "linux", target_os = "android")),
    allow(dead_code, unused_imports)
)]
/// Sends a raw HTTP/1.1 request over an in-memory duplex stream and returns the exact response
/// wire bytes with only the `date:` header value normalized so a second-boundary tick cannot flake.
async fn raw_h1_wire_response(
    engine: Arc<HttpEngine>,
    raw_request: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let (mut client, server) = tokio::io::duplex(128 * 1024);
    let peer: SocketAddr = "198.51.100.10:50000".parse()?;
    let local: SocketAddr = "127.0.0.1:8443".parse()?;
    let (_tx, rx) = watch::channel(false);
    tokio::spawn(engine.serve_hyper_connection(server, peer, local, true, false, None, rx));

    client.write_all(raw_request.as_bytes()).await?;
    client.flush().await?;
    let mut buf = Vec::new();
    client.read_to_end(&mut buf).await?;

    // Normalize ONLY the dynamic `date: <IMF-fixdate>\r\n` header line.
    if let Some(hdr_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        let head = buf.get(..hdr_end).unwrap_or(&[]);
        let tail = buf.get(hdr_end..).unwrap_or(&[]);
        let head_str = String::from_utf8_lossy(head);
        let mut normalized = String::with_capacity(head_str.len());
        for (i, line) in head_str.split("\r\n").enumerate() {
            if i > 0 {
                normalized.push_str("\r\n");
            }
            if line
                .get(..5)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("date:"))
            {
                normalized.push_str("date: <DATE>");
            } else {
                normalized.push_str(line);
            }
        }
        let mut out = normalized.into_bytes();
        out.extend_from_slice(tail);
        return Ok(out);
    }
    Ok(buf)
}

#[cfg_attr(
    not(any(target_os = "linux", target_os = "android")),
    allow(dead_code, unused_imports)
)]
async fn fetch_h2(
    engine: Arc<HttpEngine>,
    host: &str,
    method: Method,
    path: &str,
    extra_headers: &[(&str, &str)],
) -> Result<(StatusCode, Vec<(String, String)>, Vec<u8>), Box<dyn std::error::Error>> {
    let (client, server) = tokio::io::duplex(128 * 1024);
    let peer: SocketAddr = "198.51.100.10:50001".parse()?;
    let local: SocketAddr = "127.0.0.1:8443".parse()?;
    let (_tx, rx) = watch::channel(false);
    tokio::spawn(engine.serve_hyper_connection(server, peer, local, true, false, None, rx));

    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), TokioIo::new(client)).await?;
    let driver = tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("https://{host}{path}"));
    for (k, v) in extra_headers {
        builder = builder.header(*k, *v);
    }
    let resp = sender
        .send_request(builder.body(Empty::<Bytes>::new())?)
        .await?;
    let status = resp.status();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            let name = k.as_str().to_owned();
            let val = if name == "date" {
                "<DATE>".to_owned()
            } else {
                v.to_str().unwrap_or("").to_owned()
            };
            (name, val)
        })
        .collect();
    let body = resp.into_body().collect().await?.to_bytes().to_vec();
    driver.abort();
    Ok((status, headers, body))
}

async fn fetch_h1(
    engine: Arc<HttpEngine>,
    host: &str,
    method: Method,
    path: &str,
    extra_headers: &[(&str, &str)],
) -> Result<(StatusCode, HeaderMap, Vec<u8>), Box<dyn std::error::Error>> {
    let (client, server) = tokio::io::duplex(128 * 1024);
    let peer: SocketAddr = "198.51.100.10:50002".parse()?;
    let local: SocketAddr = "127.0.0.1:8443".parse()?;
    let (_tx, rx) = watch::channel(false);
    tokio::spawn(engine.serve_hyper_connection(server, peer, local, true, false, None, rx));

    let (mut sender, conn) = http1::handshake(TokioIo::new(client)).await?;
    let driver = tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(HOST, host);
    for (k, v) in extra_headers {
        builder = builder.header(*k, *v);
    }
    let resp = sender
        .send_request(builder.body(Empty::<Bytes>::new())?)
        .await?;
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await?.to_bytes().to_vec();
    driver.abort();
    Ok((status, headers, body))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn golden_hit_equals_miss_wire_bytes_on_h1_and_h2_with_no_extra_header() -> TestResult {
    let _epoch_guard = CRED_EPOCH_TEST_LOCK.read().await;
    let root = temp_dir("golden")?;
    fs::write(root.join("1k.txt"), vec![b'z'; 1024])?;
    fs::write(root.join("page.html"), b"<!doctype html><h1>Golden</h1>")?;
    fs::write(root.join("app.js"), b"console.log('golden');")?;
    fs::write(root.join("app.js.br"), b"BR-GOLDEN")?;

    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "golden.example.test" {{
    root "{root}"
    precompressed "all"
    security-headers "standard"
    file-cache "5s"
}}
"#,
        root = kdl_path(&root)
    );
    let clock = ManualClock::new();
    let engine = build_engine(&kdl, &clock)?;

    // 1. Raw HTTP/1.1 wire-level byte equality (status line + exact header order + body).
    let req_txt = "GET /1k.txt HTTP/1.1\r\nHost: golden.example.test\r\nConnection: close\r\n\r\n";
    let miss_wire = raw_h1_wire_response(Arc::clone(&engine), req_txt).await?;
    assert_eq!(engine.telemetry().file_cache_counts(), (0, 1, 1, 0));
    let hit_wire = raw_h1_wire_response(Arc::clone(&engine), req_txt).await?;
    assert_eq!(engine.telemetry().file_cache_counts(), (1, 1, 1, 0));
    assert_eq!(
        hit_wire, miss_wire,
        "HTTP/1.1 hit wire bytes must equal miss wire bytes exactly"
    );
    let wire_text = String::from_utf8_lossy(&hit_wire);
    assert!(
        !wire_text.to_ascii_lowercase().contains("x-cache"),
        "cache must not add extra response headers"
    );

    // 2. HTTP/2 exact status, header order/values, and body on HTML (Vary: Accept, Accept-Encoding)
    //    and precompressed Brotli.
    let miss_html = fetch_h2(
        Arc::clone(&engine),
        "golden.example.test",
        Method::GET,
        "/page.html",
        &[],
    )
    .await?;
    let hit_html = fetch_h2(
        Arc::clone(&engine),
        "golden.example.test",
        Method::GET,
        "/page.html",
        &[],
    )
    .await?;
    assert_eq!(
        hit_html, miss_html,
        "HTTP/2 HTML hit must equal miss exactly"
    );
    assert!(
        hit_html
            .1
            .iter()
            .any(|(k, v)| k == "vary" && v == "Accept, Accept-Encoding"),
        "HTML Vary header preserved: {:?}",
        hit_html.1
    );

    let miss_br = fetch_h2(
        Arc::clone(&engine),
        "golden.example.test",
        Method::GET,
        "/app.js",
        &[("accept-encoding", "br, gzip")],
    )
    .await?;
    let hit_br = fetch_h2(
        Arc::clone(&engine),
        "golden.example.test",
        Method::GET,
        "/app.js",
        &[("accept-encoding", "br, gzip")],
    )
    .await?;
    assert_eq!(hit_br, miss_br, "HTTP/2 Brotli hit must equal miss exactly");

    // 3. 304 Not Modified on hit equals 304 on uncached engine (exact header order and values).
    let etag = miss_br
        .1
        .iter()
        .find(|(k, _)| k == "etag")
        .map(|(_, v)| v.clone());
    if let Some(etag) = etag {
        let hit_304 = fetch_h2(
            Arc::clone(&engine),
            "golden.example.test",
            Method::GET,
            "/app.js",
            &[("accept-encoding", "br, gzip"), ("if-none-match", &etag)],
        )
        .await?;
        let uncached_kdl = kdl.replace("file-cache \"5s\"", "");
        let uncached_engine = build_engine(&uncached_kdl, &clock)?;
        let uncached_304 = fetch_h2(
            uncached_engine,
            "golden.example.test",
            Method::GET,
            "/app.js",
            &[("accept-encoding", "br, gzip"), ("if-none-match", &etag)],
        )
        .await?;
        assert_eq!(hit_304.0, StatusCode::NOT_MODIFIED);
        assert_eq!(hit_304, uncached_304, "cached 304 must equal uncached 304");
    }

    // 4. HEAD after GET hits cache and matches uncached HEAD wire headers exactly; Range bypasses.
    let hit_head = fetch_h2(
        Arc::clone(&engine),
        "golden.example.test",
        Method::HEAD,
        "/1k.txt",
        &[],
    )
    .await?;
    let uncached_kdl = kdl.replace("file-cache \"5s\"", "");
    let uncached_engine = build_engine(&uncached_kdl, &clock)?;
    let uncached_head = fetch_h2(
        uncached_engine,
        "golden.example.test",
        Method::HEAD,
        "/1k.txt",
        &[],
    )
    .await?;
    assert_eq!(hit_head.0, StatusCode::OK);
    assert_eq!(hit_head.2, b"");
    assert_eq!(
        hit_head, uncached_head,
        "cached HEAD must equal uncached HEAD"
    );

    let counts_before_range = engine.telemetry().file_cache_counts();
    let (st_range, _, body_range) = fetch_h1(
        Arc::clone(&engine),
        "golden.example.test",
        Method::GET,
        "/1k.txt",
        &[("range", "bytes=0-9")],
    )
    .await?;
    assert_eq!(st_range, StatusCode::PARTIAL_CONTENT);
    assert_eq!(body_range, vec![b'z'; 10]);
    assert_eq!(
        engine.telemetry().file_cache_counts(),
        counts_before_range,
        "Range request must bypass file cache"
    );

    let _ = fs::remove_dir_all(&root);
    Ok(())
}

#[tokio::test]
async fn off_by_default_sees_change_on_very_next_request_and_records_zero_cache_events()
-> TestResult {
    let root = temp_dir("off")?;
    let file = root.join("item.txt");
    fs::write(&file, b"v1")?;

    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "plain.example.test" {{
    root "{root}"
}}
"#,
        root = kdl_path(&root)
    );
    let clock = ManualClock::new();
    let engine = build_engine(&kdl, &clock)?;

    let (st1, _, b1) = fetch_h1(
        Arc::clone(&engine),
        "plain.example.test",
        Method::GET,
        "/item.txt",
        &[],
    )
    .await?;
    assert_eq!(st1, StatusCode::OK);
    assert_eq!(b1, b"v1");

    fs::write(&file, b"v2")?;
    let (st2, _, b2) = fetch_h1(
        Arc::clone(&engine),
        "plain.example.test",
        Method::GET,
        "/item.txt",
        &[],
    )
    .await?;
    assert_eq!(st2, StatusCode::OK);
    assert_eq!(b2, b"v2");

    fs::remove_file(&file)?;
    let (st3, _, _) = fetch_h1(
        Arc::clone(&engine),
        "plain.example.test",
        Method::GET,
        "/item.txt",
        &[],
    )
    .await?;
    assert_eq!(st3, StatusCode::NOT_FOUND);

    assert_eq!(engine.telemetry().file_cache_counts(), (0, 0, 0, 0));
    assert_eq!(engine.file_cache_budget_used(), 0);

    let _ = fs::remove_dir_all(&root);
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn pre_static_access_basic_auth_rate_limit_headers_and_methods_still_run_on_hit() -> TestResult
{
    let _epoch_guard = CRED_EPOCH_TEST_LOCK.write().await;
    let base = temp_dir("middleware")?;
    let root = base.join("www");
    let auth_dir = base.join("auth");
    fs::create_dir_all(&root)?;
    fs::create_dir_all(&auth_dir)?;
    fs::write(root.join("secret-doc.txt"), b"authorized-payload")?;

    let hash = bcrypt::hash("s3cret", 4)?;
    let users_file = auth_dir.join("users.htpasswd");
    fs::write(&users_file, format!("alice:{hash}\n"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&auth_dir, fs::Permissions::from_mode(0o755))?;
        fs::set_permissions(&users_file, fs::Permissions::from_mode(0o644))?;
    }

    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "guarded.example.test" {{
    root "{root}"
    file-cache "10s"
    access {{
        allow "198.51.100.1/32"
        deny "all"
    }}
    basic-auth "{users}" realm="Members"
    rate-limit requests=10 per="1m" burst=3 key="client-ip"
    headers {{
        set "X-Site-Rule" "present"
    }}
}}
"#,
        root = kdl_path(&root),
        users = kdl_path(&users_file),
    );
    let clock = ManualClock::new();
    let engine = build_engine(&kdl, &clock)?;
    let auth_hdr = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("alice:s3cret")
    );

    // 1. Authorized request fills cache.
    let req = Request::builder()
        .method(Method::GET)
        .uri("/secret-doc.txt")
        .header(HOST, "guarded.example.test")
        .header(AUTHORIZATION, &auth_hdr)
        .body(empty_http_body())?;
    let resp1 = engine
        .handle_request(req, &req_ctx("198.51.100.1", true)?)
        .await;
    assert_eq!(resp1.status(), StatusCode::OK);
    assert_eq!(
        resp1
            .headers()
            .get("x-site-rule")
            .and_then(|v| v.to_str().ok()),
        Some("present")
    );
    assert!(
        resp1
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("private"))
    );
    assert_eq!(
        resp1.into_body().collect().await?.to_bytes().as_ref(),
        b"authorized-payload"
    );
    assert_eq!(engine.telemetry().file_cache_counts(), (0, 1, 1, 0));

    // Delete file on disk so any 200 below proves cache hit.
    fs::remove_file(root.join("secret-doc.txt"))?;

    // 2. Denied IP gets 403 Forbidden (access rule NOT skipped by cache).
    let denied_req = Request::builder()
        .method(Method::GET)
        .uri("/secret-doc.txt")
        .header(HOST, "guarded.example.test")
        .header(AUTHORIZATION, &auth_hdr)
        .body(empty_http_body())?;
    let denied = engine
        .handle_request(denied_req, &req_ctx("203.0.113.99", true)?)
        .await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    // 3. Allowed IP without Basic Auth gets 401 Unauthorized (basic-auth NOT skipped).
    let unauth_req = Request::builder()
        .method(Method::GET)
        .uri("/secret-doc.txt")
        .header(HOST, "guarded.example.test")
        .body(empty_http_body())?;
    let unauth = engine
        .handle_request(unauth_req, &req_ctx("198.51.100.1", true)?)
        .await;
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

    // 4. Authorized POST bypasses cache (does NOT return cached 200).
    let post_req = Request::builder()
        .method(Method::POST)
        .uri("/secret-doc.txt")
        .header(HOST, "guarded.example.test")
        .header(AUTHORIZATION, &auth_hdr)
        .body(empty_http_body())?;
    let post_resp = engine
        .handle_request(post_req, &req_ctx("198.51.100.1", true)?)
        .await;
    assert_ne!(post_resp.status(), StatusCode::OK);

    // 5. Authorized GET hits cache with fresh site header rules & private cache-control.
    let hit_req = Request::builder()
        .method(Method::GET)
        .uri("/secret-doc.txt")
        .header(HOST, "guarded.example.test")
        .header(AUTHORIZATION, &auth_hdr)
        .body(empty_http_body())?;
    let hit = engine
        .handle_request(hit_req, &req_ctx("198.51.100.1", true)?)
        .await;
    assert_eq!(hit.status(), StatusCode::OK);
    assert_eq!(
        hit.headers()
            .get("x-site-rule")
            .and_then(|v| v.to_str().ok()),
        Some("present")
    );
    assert_eq!(
        hit.into_body().collect().await?.to_bytes().as_ref(),
        b"authorized-payload"
    );
    assert_eq!(engine.telemetry().file_cache_counts(), (1, 1, 1, 0));

    // 6. Exhaust burst rate limit (burst=3; we used 3 authorized requests above) -> 429!
    let rl_req = Request::builder()
        .method(Method::GET)
        .uri("/secret-doc.txt")
        .header(HOST, "guarded.example.test")
        .header(AUTHORIZATION, &auth_hdr)
        .body(empty_http_body())?;
    let rl = engine
        .handle_request(rl_req, &req_ctx("198.51.100.1", true)?)
        .await;
    assert_eq!(rl.status(), StatusCode::TOO_MANY_REQUESTS);

    let _ = fs::remove_dir_all(&base);
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn fastcgi_site_index_fast_path_try_files_markdown_and_credentials() -> TestResult {
    let _epoch_guard = CRED_EPOCH_TEST_LOCK.write().await;
    let base = temp_dir("mixed")?;
    let root = base.join("www");
    let cred_dir = base.join("creds");
    fs::create_dir_all(&root)?;
    fs::create_dir_all(&cred_dir)?;

    fs::write(root.join("asset.txt"), b"fastcgi-site-static")?;
    fs::write(
        root.join("doc.html"),
        b"<!doctype html><h1>Title</h1><p>Hello</p>",
    )?;
    let tls_key = cred_dir.join("server.key");
    fs::write(&tls_key, b"-----BEGIN PRIVATE KEY-----\nSECRET\n")?;
    fs::hard_link(&tls_key, root.join("leaked.txt"))?;

    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "{key}" }}
}}
site "fcgi.example.test" {{
    root "{root}"
    file-cache "1s"
    route "*.php" {{
        fastcgi-pass "unix:/nonexistent/php.sock"
    }}
}}
site "tf.example.test" {{
    root "{root}"
    file-cache "1s"
    route "*.php" {{
        fastcgi-pass "unix:/nonexistent/php.sock"
    }}
    route "/*" {{
        try-files "{{path}}" "{{path}}/" "=404"
    }}
}}
"#,
        key = kdl_path(&tls_key),
        root = kdl_path(&root),
    );
    let clock = ManualClock::new();
    let engine = build_engine(&kdl, &clock)?;

    // 1. Credential file hard-linked into docroot is NEVER served and NEVER cached.
    let (st_cred, _, _) = fetch_h1(
        Arc::clone(&engine),
        "fcgi.example.test",
        Method::GET,
        "/leaked.txt",
        &[],
    )
    .await?;
    assert_eq!(st_cred, StatusCode::NOT_FOUND);
    assert_eq!(
        engine.telemetry().file_cache_counts().2,
        0,
        "credential must not fill cache"
    );

    // 2. Site with FastCGI route + default static root: hit skips resolve_script_directory_index
    //    probe completely (file deleted on disk -> still 200 inside window, 404 after deadline!).
    let (st1, _, b1) = fetch_h1(
        Arc::clone(&engine),
        "fcgi.example.test",
        Method::GET,
        "/asset.txt",
        &[],
    )
    .await?;
    assert_eq!(st1, StatusCode::OK);
    assert_eq!(b1, b"fastcgi-site-static");

    // Also prime try-files route for /asset.txt.
    let (st_tf1, _, b_tf1) = fetch_h1(
        Arc::clone(&engine),
        "tf.example.test",
        Method::GET,
        "/asset.txt",
        &[],
    )
    .await?;
    assert_eq!(st_tf1, StatusCode::OK);
    assert_eq!(b_tf1, b"fastcgi-site-static");

    // Delete /asset.txt on disk.
    fs::remove_file(root.join("asset.txt"))?;

    // Inside window: BOTH sites hit cache with zero disk calls.
    clock.advance(Duration::from_millis(500));
    let (st2, _, b2) = fetch_h1(
        Arc::clone(&engine),
        "fcgi.example.test",
        Method::GET,
        "/asset.txt",
        &[],
    )
    .await?;
    assert_eq!(st2, StatusCode::OK);
    assert_eq!(b2, b"fastcgi-site-static");

    let (st_tf2, _, b_tf2) = fetch_h1(
        Arc::clone(&engine),
        "tf.example.test",
        Method::GET,
        "/asset.txt",
        &[],
    )
    .await?;
    assert_eq!(st_tf2, StatusCode::OK);
    assert_eq!(b_tf2, b"fastcgi-site-static");

    // Past deadline: BOTH see 404 immediately.
    clock.advance(Duration::from_millis(500));
    let (st3, _, _) = fetch_h1(
        Arc::clone(&engine),
        "fcgi.example.test",
        Method::GET,
        "/asset.txt",
        &[],
    )
    .await?;
    assert_eq!(st3, StatusCode::NOT_FOUND);
    let (st_tf3, _, _) = fetch_h1(
        Arc::clone(&engine),
        "tf.example.test",
        Method::GET,
        "/asset.txt",
        &[],
    )
    .await?;
    assert_eq!(st_tf3, StatusCode::NOT_FOUND);

    // 3. Markdown conversion is NOT cached, while normal HTML GET is cached independently.
    let fills_before_md = engine.telemetry().file_cache_counts().2;
    let (st_md, hdrs_md, body_md) = fetch_h1(
        Arc::clone(&engine),
        "fcgi.example.test",
        Method::GET,
        "/doc.html",
        &[("accept", "text/markdown")],
    )
    .await?;
    assert_eq!(st_md, StatusCode::OK);
    assert_eq!(
        hdrs_md.get(CONTENT_TYPE).and_then(|v| v.to_str().ok()),
        Some("text/markdown; charset=utf-8")
    );
    assert!(String::from_utf8_lossy(&body_md).contains("Title"));
    assert_eq!(
        engine.telemetry().file_cache_counts().2,
        fills_before_md,
        "Markdown conversion must not fill file cache"
    );

    // Prime normal HTML GET, delete doc.html: HTML GET hits cache, Markdown GET returns 404!
    let (st_html, _, _) = fetch_h1(
        Arc::clone(&engine),
        "fcgi.example.test",
        Method::GET,
        "/doc.html",
        &[],
    )
    .await?;
    assert_eq!(st_html, StatusCode::OK);
    fs::remove_file(root.join("doc.html"))?;

    let (st_html_hit, _, _) = fetch_h1(
        Arc::clone(&engine),
        "fcgi.example.test",
        Method::GET,
        "/doc.html",
        &[],
    )
    .await?;
    assert_eq!(st_html_hit, StatusCode::OK);

    let (st_md_after, _, _) = fetch_h1(
        Arc::clone(&engine),
        "fcgi.example.test",
        Method::GET,
        "/doc.html",
        &[("accept", "text/markdown")],
    )
    .await?;
    assert_eq!(st_md_after, StatusCode::NOT_FOUND);

    // 4. Verify Prometheus exposition exposes all 4 counters.
    let prom = engine.telemetry().render_prometheus();
    let (hits, misses, fills, budget) = engine.telemetry().file_cache_counts();
    assert!(hits >= 3, "prom:\n{prom}");
    assert!(prom.contains(&format!(
        "miraserve_file_cache_events_total{{outcome=\"hit\"}} {hits}"
    )));
    assert!(prom.contains(&format!(
        "miraserve_file_cache_events_total{{outcome=\"miss\"}} {misses}"
    )));
    assert!(prom.contains(&format!(
        "miraserve_file_cache_events_total{{outcome=\"fill\"}} {fills}"
    )));
    assert!(prom.contains(&format!(
        "miraserve_file_cache_events_total{{outcome=\"not_cached_budget\"}} {budget}"
    )));

    let _ = fs::remove_dir_all(&base);
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn reload_empties_cache_slow_reader_pins_budget_and_zero_budget_disables() -> TestResult {
    let _epoch_guard = CRED_EPOCH_TEST_LOCK.read().await;
    let root = temp_dir("reload")?;
    let body_a = vec![b'A'; 4_096];
    let body_b = vec![b'B'; 4_096];
    fs::write(root.join("a.bin"), &body_a)?;
    fs::write(root.join("b.bin"), &body_b)?;

    let make_kdl = |budget_str: &str| {
        format!(
            r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
    limits {{
        file-cache-bytes "{budget_str}"
    }}
}}
site "reload.example.test" {{
    root "{root}"
    file-cache "10s"
}}
"#,
            root = kdl_path(&root)
        )
    };

    let clock = ManualClock::new();
    let engine = build_engine(&make_kdl("6000B"), &clock)?;
    let ctx = req_ctx("198.51.100.1", true)?;

    // 1. Fill /a.bin (fits in 6000B), then /b.bin hits budget exhaustion (200 OK, not cached).
    let alpha_req = Request::builder()
        .uri("/a.bin")
        .header(HOST, "reload.example.test")
        .body(empty_http_body())?;
    let alpha_resp = engine.handle_request(alpha_req, &ctx).await;
    assert_eq!(alpha_resp.status(), StatusCode::OK);
    assert_eq!(
        alpha_resp.into_body().collect().await?.to_bytes().as_ref(),
        &body_a
    );
    assert_eq!(engine.telemetry().file_cache_counts(), (0, 1, 1, 0));

    let beta_req = Request::builder()
        .uri("/b.bin")
        .header(HOST, "reload.example.test")
        .body(empty_http_body())?;
    let beta_resp = engine.handle_request(beta_req, &ctx).await;
    assert_eq!(beta_resp.status(), StatusCode::OK);
    assert_eq!(
        beta_resp.into_body().collect().await?.to_bytes().as_ref(),
        &body_b
    );
    assert_eq!(engine.telemetry().file_cache_counts(), (0, 2, 1, 1));

    // 2. Slow reader holds a HIT response body for /a.bin without draining it.
    let req_slow = Request::builder()
        .uri("/a.bin")
        .header(HOST, "reload.example.test")
        .body(empty_http_body())?;
    let slow_resp = engine.handle_request(req_slow, &ctx).await;
    assert_eq!(slow_resp.status(), StatusCode::OK);
    assert_eq!(engine.telemetry().file_cache_counts().0, 1);

    // 3. Reload the engine: new generation starts EMPTY (old entries dropped), while the slow
    //    reader's body stays charged to the shared process-wide budget!
    let (next_cfg, _) = parse_kdl("reload.kdl", &make_kdl("6000B"))?;
    engine.reload(&next_cfg)?;

    // After reload, /a.bin's entry is gone (metadata + shard table released) while the slow
    // reader still holds the 4096-byte exact body + owner box!
    assert_eq!(
        engine.file_cache_budget_used(),
        miraserve_static::charged_body_bytes(4_096)
    );

    // Delete /a.bin on disk: reload emptied the cache, so next request sees 404 immediately!
    fs::remove_file(root.join("a.bin"))?;
    let req_a_after_reload = Request::builder()
        .uri("/a.bin")
        .header(HOST, "reload.example.test")
        .body(empty_http_body())?;
    let resp_a_after = engine.handle_request(req_a_after_reload, &ctx).await;
    assert_eq!(resp_a_after.status(), StatusCode::NOT_FOUND);

    // /b.bin STILL hits budget exhaustion while the slow reader pins 4096 of 6000 bytes!
    let req_b_while_slow = Request::builder()
        .uri("/b.bin")
        .header(HOST, "reload.example.test")
        .body(empty_http_body())?;
    let resp_b_while_slow = engine.handle_request(req_b_while_slow, &ctx).await;
    assert_eq!(resp_b_while_slow.status(), StatusCode::OK);
    assert_eq!(
        resp_b_while_slow
            .into_body()
            .collect()
            .await?
            .to_bytes()
            .as_ref(),
        &body_b
    );
    assert_eq!(engine.telemetry().file_cache_counts().3, 2);

    // Drain & drop the slow reader -> budget drops to 0!
    assert_eq!(
        slow_resp.into_body().collect().await?.to_bytes().as_ref(),
        &body_a
    );
    assert_eq!(engine.file_cache_budget_used(), 0);

    // Now /b.bin fits and fills in the new generation!
    let req_b_fits = Request::builder()
        .uri("/b.bin")
        .header(HOST, "reload.example.test")
        .body(empty_http_body())?;
    let resp_b_fits = engine.handle_request(req_b_fits, &ctx).await;
    assert_eq!(resp_b_fits.status(), StatusCode::OK);
    assert_eq!(
        resp_b_fits.into_body().collect().await?.to_bytes().as_ref(),
        &body_b
    );
    assert_eq!(engine.telemetry().file_cache_counts().2, 2);
    assert!(engine.file_cache_budget_used() > 4_096);

    // 4. Aborted prepare_reload with file-cache-bytes "0" does NOT alter active budget or cache.
    let (zero_cfg, _) = parse_kdl("zero.kdl", &make_kdl("0"))?;
    let prepared = engine.prepare_reload(&zero_cfg)?;
    drop(prepared);
    let hits_before = engine.telemetry().file_cache_counts().0;
    let req_b_still_cached = Request::builder()
        .uri("/b.bin")
        .header(HOST, "reload.example.test")
        .body(empty_http_body())?;
    let resp_b_hit = engine.handle_request(req_b_still_cached, &ctx).await;
    assert_eq!(resp_b_hit.status(), StatusCode::OK);
    assert_eq!(engine.telemetry().file_cache_counts().0, hits_before + 1);

    // 5. Commit reload with file-cache-bytes "0": disables caching globally even though site sets
    //    `file-cache "10s"`, drops old cache entries, and keeps `resp_b_hit`'s body charged until
    //    it is drained/dropped.
    engine.reload(&zero_cfg)?;
    assert_eq!(
        engine.file_cache_budget_used(),
        miraserve_static::charged_body_bytes(4_096)
    );
    assert_eq!(
        resp_b_hit.into_body().collect().await?.to_bytes().as_ref(),
        &body_b
    );
    assert_eq!(engine.file_cache_budget_used(), 0);
    let counts_before_zero = engine.telemetry().file_cache_counts();
    fs::write(root.join("b.bin"), b"live-zero-budget")?;
    let req_live = Request::builder()
        .uri("/b.bin")
        .header(HOST, "reload.example.test")
        .body(empty_http_body())?;
    let resp_live = engine.handle_request(req_live, &ctx).await;
    assert_eq!(resp_live.status(), StatusCode::OK);
    assert_eq!(
        resp_live.into_body().collect().await?.to_bytes().as_ref(),
        b"live-zero-budget"
    );
    assert_eq!(
        engine.telemetry().file_cache_counts(),
        counts_before_zero,
        "file-cache-bytes 0 must bypass caching completely"
    );

    let _ = fs::remove_dir_all(&root);
    Ok(())
}

/// P1-3 (both parts) over `HttpEngine`:
/// (a) `prepare_reload` publishing a new credential identity immediately invalidates cached
///     entries on the still-active old router BEFORE `commit_reload`.
/// (b) While `UNIDENTIFIED_CREDENTIAL` is present (triggered by an unopenable credential symlink
///     loop that fails with `ELOOP` even as root), the engine serves single-link files without
///     caching them and immediately refuses a file once it gains a second hard link.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[cfg(unix)]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn p1_3_prepare_reload_credential_publication_and_unidentified_credential() -> TestResult {
    let _epoch_guard = CRED_EPOCH_TEST_LOCK.write().await;
    let base = temp_dir("p1-3-http")?;
    let root = base.join("www");
    let auth_dir = base.join("auth");
    fs::create_dir_all(&root)?;
    fs::create_dir_all(&auth_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&auth_dir, fs::Permissions::from_mode(0o755))?;
    }

    // Create a multiply-linked file inside docroot + auth_dir.
    let doc_file = root.join("doc.txt");
    let future_cred = auth_dir.join("users.htpasswd");
    let hash = bcrypt::hash("pw", 4)?;
    fs::write(&doc_file, format!("alice:{hash}\n"))?;
    fs::hard_link(&doc_file, &future_cred)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&future_cred, fs::Permissions::from_mode(0o644))?;
    }

    // Config 1: no basic-auth yet; `/doc.txt` is an ordinary cached static file.
    let kdl_v1 = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "cred-epoch.example.test" {{
    root "{root}"
    file-cache "60s"
}}
"#,
        root = kdl_path(&root)
    );
    let clock = ManualClock::new();
    let engine = build_engine(&kdl_v1, &clock)?;
    let ctx = req_ctx("198.51.100.20", true)?;

    // Warm `/doc.txt` on the active v1 router.
    let r1 = engine
        .handle_request(
            Request::builder()
                .uri("/doc.txt")
                .header(HOST, "cred-epoch.example.test")
                .body(empty_http_body())?,
            &ctx,
        )
        .await;
    assert_eq!(r1.status(), StatusCode::OK);
    assert_eq!(engine.telemetry().file_cache_counts(), (0, 1, 1, 0));

    // Config 2 names `future_cred` as a `basic-auth` users file.
    // Call `prepare_reload` ONLY (do NOT commit yet!): this publishes the credential identity
    // and must immediately invalidate the old active router's cache via the credential epoch.
    let kdl_v2 = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "cred-epoch.example.test" {{
    root "{root}"
    file-cache "60s"
    basic-auth "{users}" realm="Admin"
}}
"#,
        root = kdl_path(&root),
        users = kdl_path(&future_cred)
    );
    let (cfg_v2, _) = parse_kdl("v2.kdl", &kdl_v2)?;
    let _prepared = engine.prepare_reload(&cfg_v2)?;

    // Still on OLD router (no basic-auth yet), inside the 60s window: `/doc.txt` MUST NOT hit
    // the cache and MUST be refused with 404 by the live disk credential check!
    let r2 = engine
        .handle_request(
            Request::builder()
                .uri("/doc.txt")
                .header(HOST, "cred-epoch.example.test")
                .body(empty_http_body())?,
            &ctx,
        )
        .await;
    assert_eq!(
        r2.status(),
        StatusCode::NOT_FOUND,
        "P1-3(a): prepare_reload credential publication must immediately invalidate active router hits"
    );
    assert_eq!(engine.telemetry().file_cache_counts().0, 0);

    // Part (b): UNIDENTIFIED_CREDENTIAL via a symlink loop in CredentialSources (`ELOOP` even as
    // root in Docker). Single-link file must NOT be cached, and hard-linking it immediately gives 404.
    let loop_a = auth_dir.join("loop_a");
    let loop_b = auth_dir.join("loop_b");
    std::os::unix::fs::symlink(&loop_b, &loop_a)?;
    std::os::unix::fs::symlink(&loop_a, &loop_b)?;

    let single_file = root.join("single.txt");
    fs::write(&single_file, b"single-link-http")?;

    let (cfg_unid, _) = parse_kdl("unid.kdl", &kdl_v1)?;
    let unid_engine = Arc::new(HttpEngine::from_config_with_file_cache_clock(
        &cfg_unid,
        Arc::new(AcmeChallengeStore::new()),
        None,
        8443,
        CredentialSources {
            files: vec![loop_a],
            dirs: Vec::new(),
        },
        clock.cache_clock(),
    )?);

    let ru1 = unid_engine
        .handle_request(
            Request::builder()
                .uri("/single.txt")
                .header(HOST, "cred-epoch.example.test")
                .body(empty_http_body())?,
            &ctx,
        )
        .await;
    assert_eq!(ru1.status(), StatusCode::OK);
    assert_eq!(
        ru1.into_body().collect().await?.to_bytes().as_ref(),
        b"single-link-http"
    );
    assert_eq!(
        unid_engine.telemetry().file_cache_counts(),
        (0, 0, 0, 0),
        "P1-3(b): UNIDENTIFIED_CREDENTIAL must disable cache hits and admissions"
    );
    assert_eq!(unid_engine.file_cache_budget_used(), 0);

    // Add a second hard link inside the window -> must immediately return 404.
    fs::hard_link(&single_file, root.join("single_alias.txt"))?;
    let ru2 = unid_engine
        .handle_request(
            Request::builder()
                .uri("/single.txt")
                .header(HOST, "cred-epoch.example.test")
                .body(empty_http_body())?,
            &ctx,
        )
        .await;
    assert_eq!(ru2.status(), StatusCode::NOT_FOUND);

    let _ = fs::remove_dir_all(&base);
    Ok(())
}

/// P1-4 over `HttpEngine`: `HEAD` with `Range` (which the router strips to preserve whole-file
/// `HEAD` semantics) and `GET`/`HEAD` with `If-Range` must never hit or admit cache entries, on
/// both plain static sites and FastCGI-enabled sites.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn p1_4_head_with_range_and_if_range_bypass_while_preserving_whole_file_head() -> TestResult {
    let _epoch_guard = CRED_EPOCH_TEST_LOCK.read().await;
    let root = temp_dir("p1-4-http")?;
    let payload = b"0123456789abcdef";
    fs::write(root.join("a.txt"), payload)?;
    fs::write(root.join("live.txt"), payload)?;

    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "plain.example.test" {{
    root "{root}"
    file-cache "60s"
}}
site "php.example.test" {{
    root "{root}"
    index "index.php" "index.html"
    file-cache "60s"
    route "*.php" {{
        fastcgi-pass "127.0.0.1:9000"
    }}
}}
"#,
        root = kdl_path(&root)
    );
    let clock = ManualClock::new();
    let engine = build_engine(&kdl, &clock)?;

    for host in ["plain.example.test", "php.example.test"] {
        // 1. Live HEAD with Range keeps whole-file HEAD semantics (200 OK, full Content-Length,
        //    empty body) and records zero cache activity.
        let counts_before = engine.telemetry().file_cache_counts();
        let (st_live_head, hdrs_live_head, body_live_head) = fetch_h1(
            Arc::clone(&engine),
            host,
            Method::HEAD,
            "/live.txt",
            &[("range", "bytes=0-0")],
        )
        .await?;
        assert_eq!(st_live_head, StatusCode::OK);
        assert_eq!(
            hdrs_live_head
                .get(http::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()),
            Some("16"),
            "whole-file HEAD semantics must be preserved on {host}"
        );
        assert_eq!(body_live_head, b"");
        assert_eq!(engine.telemetry().file_cache_counts(), counts_before);

        // 2. Live GET with If-Range (no Range) must NOT admit into cache.
        let (st_ir, _, body_ir) = fetch_h1(
            Arc::clone(&engine),
            host,
            Method::GET,
            "/live.txt",
            &[("if-range", "\"other\"")],
        )
        .await?;
        assert_eq!(st_ir, StatusCode::OK);
        assert_eq!(body_ir, payload);
        assert_eq!(engine.telemetry().file_cache_counts(), counts_before);

        // 3. Warm `/a.txt`, then delete it on disk.
        fs::write(root.join("a.txt"), payload)?;
        let (st_warm, _, body_warm) =
            fetch_h1(Arc::clone(&engine), host, Method::GET, "/a.txt", &[]).await?;
        assert_eq!(st_warm, StatusCode::OK);
        assert_eq!(body_warm, payload);
        fs::remove_file(root.join("a.txt"))?;

        // Ordinary HEAD hits cached `/a.txt` (200 OK, full length).
        let (st_head_hit, _, _) =
            fetch_h1(Arc::clone(&engine), host, Method::HEAD, "/a.txt", &[]).await?;
        assert_eq!(st_head_hit, StatusCode::OK);

        // HEAD + Range MUST bypass cache (despite router removing Range/If-Range) and return 404!
        let (st_head_range, _, _) = fetch_h1(
            Arc::clone(&engine),
            host,
            Method::HEAD,
            "/a.txt",
            &[("range", "bytes=0-0")],
        )
        .await?;
        assert_eq!(
            st_head_range,
            StatusCode::NOT_FOUND,
            "P1-4: HEAD with Range must bypass cache on {host}"
        );

        // HEAD + If-Range and GET + If-Range MUST bypass cache and return 404!
        let (st_head_ir, _, _) = fetch_h1(
            Arc::clone(&engine),
            host,
            Method::HEAD,
            "/a.txt",
            &[("if-range", "\"etag\"")],
        )
        .await?;
        assert_eq!(st_head_ir, StatusCode::NOT_FOUND);

        let (st_get_ir, _, _) = fetch_h1(
            Arc::clone(&engine),
            host,
            Method::GET,
            "/a.txt",
            &[("if-range", "\"etag\"")],
        )
        .await?;
        assert_eq!(st_get_ir, StatusCode::NOT_FOUND);
    }

    let _ = fs::remove_dir_all(&root);
    Ok(())
}

/// P1-8: Runs the exact 17-request corpus through an `HttpEngine` with `file-cache` OFF (default)
/// and compares complete HTTP/1.1 wire response bytes (normalizing only `date`, `x-request-id`,
/// and the OS-assigned inode `ctime` inside `etag`) against goldens captured directly from commit
/// `7dcbd97c231a0bf3482f4c736abb605bc3467cd9`.
#[cfg(unix)]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn p1_8_off_mode_wire_bytes_match_7dcbd97_goldens() -> TestResult {
    const FIXED_MTIME_SECS: u64 = 1_700_000_000;

    fn write_fixed(path: &Path, data: &[u8]) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, data)?;
        let f = fs::OpenOptions::new().write(true).open(path)?;
        f.set_modified(std::time::UNIX_EPOCH + Duration::from_secs(FIXED_MTIME_SECS))?;
        Ok(())
    }

    fn file_ctime_tag(path: &Path) -> Option<String> {
        use std::os::unix::fs::MetadataExt as _;
        let m = fs::metadata(path).ok()?;
        Some(format!(
            "-{:x}.{:x}",
            m.ctime().unsigned_abs(),
            m.ctime_nsec().unsigned_abs()
        ))
    }

    async fn raw_h1_unmodified(
        engine: Arc<HttpEngine>,
        raw_req: &str,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let (mut client, server) = tokio::io::duplex(128 * 1024);
        let peer: SocketAddr = "198.51.100.10:50000".parse()?;
        let local: SocketAddr = "127.0.0.1:8443".parse()?;
        let (_tx, rx) = watch::channel(false);
        tokio::spawn(engine.serve_hyper_connection(server, peer, local, true, false, None, rx));

        client.write_all(raw_req.as_bytes()).await?;
        client.flush().await?;
        let mut buf = Vec::new();
        client.read_to_end(&mut buf).await?;
        Ok(buf)
    }

    fn normalize_wire(raw: &[u8], ctime_tag: Option<&str>) -> Vec<u8> {
        let Some(hdr_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
            return raw.to_vec();
        };
        let head = raw.get(..hdr_end).unwrap_or(&[]);
        let body = raw.get(hdr_end + 4..).unwrap_or(&[]);
        let head_str = String::from_utf8_lossy(head);
        let mut request_id: Option<String> = None;
        let mut norm_head = String::with_capacity(head_str.len());
        for (i, line) in head_str.split("\r\n").enumerate() {
            if i > 0 {
                norm_head.push_str("\r\n");
            }
            if line
                .get(..5)
                .is_some_and(|p| p.eq_ignore_ascii_case("date:"))
            {
                norm_head.push_str("date: <DATE>");
            } else if line
                .get(..13)
                .is_some_and(|p| p.eq_ignore_ascii_case("x-request-id:"))
            {
                let val = line.get(13..).unwrap_or("").trim();
                if !val.is_empty() {
                    request_id = Some(val.to_owned());
                }
                norm_head.push_str("x-request-id: <REQUEST_ID>");
            } else if line
                .get(..24)
                .is_some_and(|p| p.eq_ignore_ascii_case("content-security-policy:"))
            {
                if let Some(start) = line.find("'nonce-")
                    && let Some(tail) = line.get(start + 7..)
                    && let Some(end_rel) = tail.find('\'')
                {
                    let prefix = line.get(..start + 7).unwrap_or("");
                    let suffix = tail.get(end_rel..).unwrap_or("");
                    norm_head.push_str(prefix);
                    norm_head.push_str("<NONCE>");
                    norm_head.push_str(suffix);
                } else {
                    norm_head.push_str(line);
                }
            } else if let Some(ct) = ctime_tag
                && line
                    .get(..5)
                    .is_some_and(|p| p.eq_ignore_ascii_case("etag:"))
            {
                norm_head.push_str(&line.replace(ct, "-<CTIME>"));
            } else {
                norm_head.push_str(line);
            }
        }
        let mut out = norm_head.into_bytes();
        out.extend_from_slice(b"\r\n\r\n");
        if let Some(rid) = request_id {
            let body_str = String::from_utf8_lossy(body);
            out.extend_from_slice(body_str.replace(&rid, "<REQUEST_ID>").as_bytes());
        } else {
            out.extend_from_slice(body);
        }
        out
    }

    fn extract_etag(raw: &[u8]) -> Option<String> {
        let hdr_end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
        let head_str = String::from_utf8_lossy(raw.get(..hdr_end)?);
        for line in head_str.split("\r\n") {
            if line
                .get(..5)
                .is_some_and(|p| p.eq_ignore_ascii_case("etag:"))
            {
                return Some(line.get(5..)?.trim().to_owned());
            }
        }
        None
    }

    let golden_raw = include_str!("fixtures/off_mode_7dcbd97.json");
    let golden_doc: serde_json::Value = serde_json::from_str(golden_raw)?;
    let golden_cases = golden_doc
        .get("cases")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing cases array in 7dcbd97 golden fixture")?;

    let root = temp_dir("p1-8-golden-7dcbd97")?;
    let plain_path = root.join("plain.txt");
    let css_path = root.join("style.css");
    let js_path = root.join("app.js");
    let js_br_path = root.join("app.js.br");
    let html_path = root.join("page.html");
    let sub_index_path = root.join("sub").join("index.html");
    let spa_index_path = root.join("spa_root").join("index.html");

    write_fixed(&plain_path, b"hello-off-mode-golden-payload\n")?;
    write_fixed(
        &css_path,
        &b"body { color: #123456; margin: 0; padding: 0; }\n".repeat(64),
    )?;
    write_fixed(&js_path, b"console.log('base-js-payload');\n")?;
    write_fixed(&js_br_path, b"PRECOMPRESSED-BROTLI-SIBLING-BYTES")?;
    write_fixed(&html_path, b"<!doctype html><title>Off</title><p>Hello</p>")?;
    write_fixed(&sub_index_path, b"<!doctype html><h1>Sub Index</h1>")?;
    write_fixed(&spa_index_path, b"<!doctype html><h1>SPA Fallback</h1>")?;

    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "off.example.test" {{
    root "{root}"
    index "index.php" "index.html"
    precompressed "all"
    security-headers "standard"
    route "*.php" {{
        fastcgi-pass "127.0.0.1:9000"
    }}
    route "/spa/*" {{
        try-files "{{path}}" "/spa_root/index.html"
    }}
}}
"#,
        root = kdl_path(&root)
    );
    let (cfg, _) = parse_kdl("off.kdl", &kdl)?;
    let engine = Arc::new(HttpEngine::from_config_with_credentials(
        &cfg,
        Arc::new(AcmeChallengeStore::new()),
        None,
        8443,
        CredentialSources::default(),
    )?);

    let plain_ct = file_ctime_tag(&plain_path);
    let css_ct = file_ctime_tag(&css_path);
    let js_br_ct = file_ctime_tag(&js_br_path);
    let html_ct = file_ctime_tag(&html_path);
    let sub_ct = file_ctime_tag(&sub_index_path);
    let spa_ct = file_ctime_tag(&spa_index_path);

    let plain_probe = raw_h1_unmodified(
        Arc::clone(&engine),
        "GET /plain.txt HTTP/1.1\r\nHost: off.example.test\r\nConnection: close\r\n\r\n",
    )
    .await?;
    let plain_etag = extract_etag(&plain_probe).ok_or("missing etag on /plain.txt")?;

    let requests: Vec<(&str, String, Option<String>)> = vec![
        (
            "get_plain_identity",
            "GET /plain.txt HTTP/1.1\r\nHost: off.example.test\r\nConnection: close\r\n\r\n"
                .to_owned(),
            plain_ct.clone(),
        ),
        (
            "head_plain",
            "HEAD /plain.txt HTTP/1.1\r\nHost: off.example.test\r\nConnection: close\r\n\r\n"
                .to_owned(),
            plain_ct.clone(),
        ),
        (
            "head_plain_with_range",
            "HEAD /plain.txt HTTP/1.1\r\nHost: off.example.test\r\nRange: bytes=0-4\r\nConnection: close\r\n\r\n"
                .to_owned(),
            plain_ct.clone(),
        ),
        (
            "get_plain_range_206",
            "GET /plain.txt HTTP/1.1\r\nHost: off.example.test\r\nRange: bytes=0-4\r\nConnection: close\r\n\r\n"
                .to_owned(),
            plain_ct.clone(),
        ),
        (
            "get_plain_if_none_match_304",
            format!(
                "GET /plain.txt HTTP/1.1\r\nHost: off.example.test\r\nIf-None-Match: {plain_etag}\r\nConnection: close\r\n\r\n"
            ),
            plain_ct,
        ),
        (
            "get_css_gzip_cold",
            "GET /style.css HTTP/1.1\r\nHost: off.example.test\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n"
                .to_owned(),
            css_ct.clone(),
        ),
        (
            "get_css_gzip_warm",
            "GET /style.css HTTP/1.1\r\nHost: off.example.test\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n"
                .to_owned(),
            css_ct.clone(),
        ),
        (
            "get_css_br",
            "GET /style.css HTTP/1.1\r\nHost: off.example.test\r\nAccept-Encoding: br, gzip\r\nConnection: close\r\n\r\n"
                .to_owned(),
            css_ct.clone(),
        ),
        (
            "get_css_zstd",
            "GET /style.css HTTP/1.1\r\nHost: off.example.test\r\nAccept-Encoding: zstd, br, gzip\r\nConnection: close\r\n\r\n"
                .to_owned(),
            css_ct.clone(),
        ),
        (
            "get_css_q0_and_unknown_tokens",
            "GET /style.css HTTP/1.1\r\nHost: off.example.test\r\nAccept-Encoding: deflate;q=0.8, br;q=0, weird-enc;foo=bar, GZIP;q=0.5, *\r\nConnection: close\r\n\r\n"
                .to_owned(),
            css_ct,
        ),
        (
            "get_precomp_br",
            "GET /app.js HTTP/1.1\r\nHost: off.example.test\r\nAccept-Encoding: br, gzip\r\nConnection: close\r\n\r\n"
                .to_owned(),
            js_br_ct,
        ),
        (
            "get_html_vary",
            "GET /page.html HTTP/1.1\r\nHost: off.example.test\r\nConnection: close\r\n\r\n"
                .to_owned(),
            html_ct,
        ),
        (
            "get_dir_redirect_301",
            "GET /sub HTTP/1.1\r\nHost: off.example.test\r\nConnection: close\r\n\r\n".to_owned(),
            None,
        ),
        (
            "get_dir_index_200",
            "GET /sub/ HTTP/1.1\r\nHost: off.example.test\r\nConnection: close\r\n\r\n".to_owned(),
            sub_ct,
        ),
        (
            "get_try_files_fallback",
            "GET /spa/dashboard HTTP/1.1\r\nHost: off.example.test\r\nConnection: close\r\n\r\n"
                .to_owned(),
            spa_ct,
        ),
        (
            "get_missing_404",
            "GET /does-not-exist.txt HTTP/1.1\r\nHost: off.example.test\r\nConnection: close\r\n\r\n"
                .to_owned(),
            None,
        ),
        (
            "post_plain_405",
            "POST /plain.txt HTTP/1.1\r\nHost: off.example.test\r\nConnection: close\r\n\r\n"
                .to_owned(),
            None,
        ),
    ];

    assert_eq!(requests.len(), golden_cases.len());
    for ((name, raw_req, ct), golden) in requests.iter().zip(golden_cases.iter()) {
        let g_name = golden
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or("golden case missing name")?;
        assert_eq!(g_name, *name);
        let g_b64 = golden
            .get("wire_base64")
            .and_then(serde_json::Value::as_str)
            .ok_or("golden case missing wire_base64")?;
        let expected_wire = normalize_wire(
            &base64::engine::general_purpose::STANDARD.decode(g_b64)?,
            None,
        );

        let actual_raw = raw_h1_unmodified(Arc::clone(&engine), raw_req).await?;
        let actual_wire = normalize_wire(&actual_raw, ct.as_deref());
        assert_eq!(
            actual_wire,
            expected_wire,
            "P1-8 golden mismatch against 7dcbd97 for case '{name}':\nACTUAL:\n{}\nEXPECTED:\n{}",
            String::from_utf8_lossy(&actual_wire),
            String::from_utf8_lossy(&expected_wire),
        );
    }

    assert_eq!(engine.telemetry().file_cache_counts(), (0, 0, 0, 0));
    assert_eq!(engine.file_cache_budget_used(), 0);

    let _ = fs::remove_dir_all(&root);
    Ok(())
}

/// Review round 2, P1-1 over `HttpEngine`: a prepared reload generation holds a credential inode K
/// open while K has only ONE public name left (`nlink == 1`) in the active router's docroot.
/// Under the current credential epoch, an ordinary GET on the old active router still returns
/// `200 OK` from live disk, MUST NOT admit K into the cache, and once K acquires a second hard
/// link (`nlink == 2`) while the prepared generation still holds it, the next GET MUST return
/// `404 Not Found` (never a cached `200 OK`).
#[cfg(unix)]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn p1_1_r2_prepared_generation_credential_single_link_then_second_link_returns_404()
-> TestResult {
    use std::os::unix::fs::PermissionsExt as _;

    let _epoch_guard = CRED_EPOCH_TEST_LOCK.write().await;
    let base = temp_dir("p1-1-r2-http")?;
    let root = base.join("root");
    let auth_dir = base.join("auth");
    fs::create_dir_all(&root)?;
    fs::create_dir_all(&auth_dir)?;
    fs::set_permissions(&auth_dir, fs::Permissions::from_mode(0o700))?;

    let public_file = root.join("public.txt");
    let cred_file = auth_dir.join("users.htpasswd");
    let hash = bcrypt::hash("s3cr3t", 4)?;
    fs::write(&public_file, format!("alice:{hash}\n"))?;
    fs::set_permissions(&public_file, fs::Permissions::from_mode(0o600))?;
    // Hard-link into auth_dir so `prepare_reload` opens inode K as a credential file.
    fs::hard_link(&public_file, &cred_file)?;

    let kdl_v1 = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "r2-p1-1.example.test" {{
    root "{root}"
    file-cache "60s"
}}
"#,
        root = kdl_path(&root)
    );
    let (cfg_v1, _) = parse_kdl("v1.kdl", &kdl_v1)?;
    let clock = ManualClock::new();
    let engine = Arc::new(HttpEngine::from_config_with_file_cache_clock(
        &cfg_v1,
        Arc::new(AcmeChallengeStore::new()),
        None,
        8443,
        CredentialSources::default(),
        clock.cache_clock(),
    )?);

    // Prepare v2 referencing `cred_file` (same inode K): `prepare_reload` opens handle to K and
    // publishes K's identity into `PUBLISHED` (and advances the epoch).
    let kdl_v2 = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "r2-p1-1.example.test" {{
    root "{root}"
    file-cache "60s"
    basic-auth "{users}" realm="Admin"
}}
"#,
        root = kdl_path(&root),
        users = kdl_path(&cred_file)
    );
    let (cfg_v2, _) = parse_kdl("v2.kdl", &kdl_v2)?;
    let prepared = engine.prepare_reload(&cfg_v2)?;

    // Unlink `cred_file` (e.g., key rotation): inode K now has ONLY ONE public name left
    // (`root/public.txt`, `nlink == 1`), while `prepared` still holds its open handle and
    // published identity!
    fs::remove_file(&cred_file)?;

    let ctx = req_ctx("198.51.100.77", true)?;

    // 1. Ordinary GET on the old active router under the CURRENT epoch: on Linux 0.1.4's
    //    retained-credential predicate denies any live published credential at any link count
    //    (404); on other platforms live disk returns 200 OK while `nlink == 1`. Neither platform
    //    may admit inode K into the cache.
    let r1 = engine
        .handle_request(
            Request::builder()
                .uri("/public.txt")
                .header(HOST, "r2-p1-1.example.test")
                .body(empty_http_body())?,
            &ctx,
        )
        .await;
    #[cfg(target_os = "linux")]
    assert_eq!(
        r1.status(),
        StatusCode::NOT_FOUND,
        "Linux 0.1.4 retained-credential predicate must deny live published credential even at nlink == 1"
    );
    #[cfg(not(target_os = "linux"))]
    assert_eq!(
        r1.status(),
        StatusCode::OK,
        "live disk response for single-link file on old router must stay unchanged (200 OK)"
    );
    assert_eq!(
        engine.telemetry().file_cache_counts().2,
        0,
        "P1-1: file matching a credential published by a live prepared generation must NOT be admitted"
    );
    assert_eq!(engine.file_cache_budget_used(), 0);

    // 2. Inode K now acquires a second hard link (`nlink == 2`) while `prepared` still holds it
    //    (no new credential epoch published). The next GET MUST NOT hit any cached 200 and MUST
    //    return 404 Not Found!
    fs::hard_link(&public_file, root.join("public_link2.txt"))?;
    let r2 = engine
        .handle_request(
            Request::builder()
                .uri("/public.txt")
                .header(HOST, "r2-p1-1.example.test")
                .body(empty_http_body())?,
            &ctx,
        )
        .await;
    assert_eq!(
        r2.status(),
        StatusCode::NOT_FOUND,
        "P1-1: once second link exists, next GET must return 404 (not a cached 200)"
    );
    assert_eq!(engine.telemetry().file_cache_counts().0, 0);

    drop(prepared);
    let _ = fs::remove_dir_all(&base);
    Ok(())
}

/// M015 Intersection 2: `precompressed` defaults to `"off"` (a site with `file-cache` and
/// default `precompressed` must never serve or cache a precompressed sibling), changing the
/// policy on live reload starts a fresh cache generation and never serves an entry filled under
/// the old policy, and mutating `StaticServer::set_precompressed` isolates namespaces.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn m015_intersection_2_precompressed_default_off_and_reload_policy_change() -> TestResult {
    use http::HeaderValue;
    use http::header::{ACCEPT_ENCODING, CONTENT_ENCODING};

    let _epoch_guard = CRED_EPOCH_TEST_LOCK.read().await;
    let root = temp_dir("m015-i2-precomp")?;
    let base_bytes = b"console.log('base-identity');";
    let br_bytes = b"PRECOMP-BROTLI-SIBLING";
    let gz_bytes = b"PRECOMP-GZIP-SIBLING";
    fs::write(root.join("app.js"), base_bytes)?;
    fs::write(root.join("app.js.br"), br_bytes)?;
    fs::write(root.join("app.js.gz"), gz_bytes)?;

    let make_kdl = |precomp_line: &str| {
        format!(
            r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "precomp.example.test" {{
    root "{root}"
    file-cache "60s"
    {precomp_line}
}}
"#,
            root = kdl_path(&root)
        )
    };

    let clock = ManualClock::new();
    let ctx = req_ctx("198.51.100.88", true)?;

    // 1. Default policy (`precompressed` omitted -> `"off"`): never serves or caches sibling.
    let (cfg_off, _) = parse_kdl("off.kdl", &make_kdl(""))?;
    let engine = Arc::new(HttpEngine::from_config_with_file_cache_clock(
        &cfg_off,
        Arc::new(AcmeChallengeStore::new()),
        None,
        8443,
        CredentialSources::default(),
        clock.cache_clock(),
    )?);

    for expected_hits in [0_u64, 1_u64] {
        let resp = engine
            .handle_request(
                Request::builder()
                    .uri("/app.js")
                    .header(HOST, "precomp.example.test")
                    .header(ACCEPT_ENCODING, "br, gzip")
                    .body(empty_http_body())?,
                &ctx,
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(CONTENT_ENCODING),
            None,
            "default precompressed=\"off\" must not serve sibling"
        );
        let body = resp.into_body().collect().await?.to_bytes();
        assert_eq!(body.as_ref(), base_bytes);
        assert_eq!(engine.telemetry().file_cache_counts().0, expected_hits);
    }

    // 2. Live reload enabling `precompressed "br"`: must NOT serve cached identity from old
    //    generation; fills and serves `.br` sibling.
    let (cfg_br, _) = parse_kdl("br.kdl", &make_kdl(r#"precompressed "br""#))?;
    let prep_br = engine.prepare_reload(&cfg_br)?;
    engine.commit_reload(prep_br);

    let r_br_miss = engine
        .handle_request(
            Request::builder()
                .uri("/app.js")
                .header(HOST, "precomp.example.test")
                .header(ACCEPT_ENCODING, "br, gzip")
                .body(empty_http_body())?,
            &ctx,
        )
        .await;
    assert_eq!(r_br_miss.status(), StatusCode::OK);
    assert_eq!(
        r_br_miss
            .headers()
            .get(CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        Some("br")
    );
    assert_eq!(
        r_br_miss.into_body().collect().await?.to_bytes().as_ref(),
        br_bytes
    );

    // 3. Live reload switching to `precompressed "gz"`: must NOT serve cached `.br` sibling.
    let (cfg_gz, _) = parse_kdl("gz.kdl", &make_kdl(r#"precompressed "gz""#))?;
    let prep_gz = engine.prepare_reload(&cfg_gz)?;
    engine.commit_reload(prep_gz);

    let r_gz = engine
        .handle_request(
            Request::builder()
                .uri("/app.js")
                .header(HOST, "precomp.example.test")
                .header(ACCEPT_ENCODING, "br, gzip")
                .body(empty_http_body())?,
            &ctx,
        )
        .await;
    assert_eq!(r_gz.status(), StatusCode::OK);
    assert_eq!(
        r_gz.headers()
            .get(CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        Some("gzip"),
        "reload changing precompressed \"br\" -> \"gz\" must not serve cached .br entry"
    );
    assert_eq!(
        r_gz.into_body().collect().await?.to_bytes().as_ref(),
        gz_bytes
    );

    // 4. Live reload back to `precompressed "off"`: must NOT serve cached `.gz` sibling.
    let prep_off2 = engine.prepare_reload(&cfg_off)?;
    engine.commit_reload(prep_off2);

    let r_off2 = engine
        .handle_request(
            Request::builder()
                .uri("/app.js")
                .header(HOST, "precomp.example.test")
                .header(ACCEPT_ENCODING, "br, gzip")
                .body(empty_http_body())?,
            &ctx,
        )
        .await;
    assert_eq!(r_off2.status(), StatusCode::OK);
    assert_eq!(r_off2.headers().get(CONTENT_ENCODING), None);
    assert_eq!(
        r_off2.into_body().collect().await?.to_bytes().as_ref(),
        base_bytes
    );

    // 5. Direct `StaticServer::set_precompressed` mutation allocates a fresh cache namespace ID.
    let direct_cache = miraserve_static::FileCache::with_clock(
        Arc::new(miraserve_static::FileCacheBudget::new(1024 * 1024)),
        miraserve_static::FileCacheCounters::new(),
        clock.cache_clock(),
    );
    let mut srv_all = miraserve_static::StaticServer::open(
        &root,
        miraserve_config::StaticConfig {
            precompressed: miraserve_config::PrecompressedPolicy::ALL,
            ..miraserve_config::StaticConfig::default()
        },
    )?
    .with_file_cache(Arc::clone(&direct_cache), Duration::from_secs(60));
    let mut br_hdrs = http::HeaderMap::new();
    br_hdrs.insert(ACCEPT_ENCODING, HeaderValue::from_static("br"));
    let r_s1 = srv_all
        .serve_canonical(&Method::GET, "/app.js", &br_hdrs)
        .await;
    assert_eq!(
        r_s1.into_body().collect().await?.to_bytes().as_ref(),
        br_bytes
    );
    srv_all.set_precompressed(miraserve_config::PrecompressedPolicy::OFF);
    let r_s2 = srv_all
        .serve_canonical(&Method::GET, "/app.js", &br_hdrs)
        .await;
    assert_eq!(r_s2.headers().get(CONTENT_ENCODING), None);
    assert_eq!(
        r_s2.into_body().collect().await?.to_bytes().as_ref(),
        base_bytes,
        "set_precompressed(OFF) must refresh namespace and never hit old .br entry"
    );

    let _ = fs::remove_dir_all(&root);
    Ok(())
}

/// M015 Intersection 5: Status-conditioned `headers` rules and `try-files` fallback header
/// ownership are applied by the router AFTER static cache lookup/fill:
/// - A cached `try-files` fallback candidate receives the fallback owner route's `headers` rules
///   (for both `200` and conditional `304` hits), NOT the originating route's rules.
/// - A refused `try-files` candidate (`400 Bad Request`) is never cached and keeps the originating
///   route's `headers` rules.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn m015_intersection_5_status_headers_and_try_files_fallback_ownership_on_cache_hit()
-> TestResult {
    use http::header::{ETAG, IF_NONE_MATCH};

    let _epoch_guard = CRED_EPOCH_TEST_LOCK.read().await;
    let root = temp_dir("m015-i5-headers")?;
    let shell_dir = root.join("shell");
    fs::create_dir_all(&shell_dir)?;
    let shell_index = shell_dir.join("index.html");
    fs::write(&shell_index, b"<!doctype html><h1>SPA Shell</h1>")?;

    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "headers.example.test" {{
    root "{root}"
    file-cache "60s"
    headers {{
        set "X-Site-200" "site-ok" status="200"
        set "X-Site-304" "site-not-mod" status="304"
        set "X-Site-400" "site-bad-req" status="400"
    }}
    route "/shell/*" {{
        static
        headers {{
            set "X-Owner" "shell-route" status="200 304"
            set "X-Shell-Only-200" "yes" status="200"
            set "X-Shell-Only-304" "yes" status="304"
        }}
    }}
    route "/app/*" {{
        try-files "{{path}}" "/shell/index.html"
        headers {{
            set "X-Owner" "app-origin" status="200 304 400"
        }}
    }}
    route "/bad/*" {{
        try-files "/shell/../escape"
        headers {{
            set "X-Owner" "bad-origin" status="200 400"
        }}
    }}
}}
"#,
        root = kdl_path(&root)
    );

    let clock = ManualClock::new();
    let engine = build_engine(&kdl, &clock)?;
    let ctx = req_ctx("198.51.100.89", true)?;

    // 1. Miss on `/app/dashboard` -> falls back to `/shell/index.html`, fills cache, gets
    //    `/shell/*` owner headers for status 200.
    let r_miss = engine
        .handle_request(
            Request::builder()
                .uri("/app/dashboard")
                .header(HOST, "headers.example.test")
                .body(empty_http_body())?,
            &ctx,
        )
        .await;
    assert_eq!(r_miss.status(), StatusCode::OK);
    assert_eq!(
        r_miss
            .headers()
            .get("x-owner")
            .and_then(|v| v.to_str().ok()),
        Some("shell-route")
    );
    assert_eq!(
        r_miss
            .headers()
            .get("x-shell-only-200")
            .and_then(|v| v.to_str().ok()),
        Some("yes")
    );
    assert!(r_miss.headers().get("x-shell-only-304").is_none());
    assert_eq!(
        r_miss
            .headers()
            .get("x-site-200")
            .and_then(|v| v.to_str().ok()),
        Some("site-ok")
    );
    let etag = r_miss
        .headers()
        .get(ETAG)
        .cloned()
        .ok_or("missing ETag on fallback miss")?;
    assert_eq!(
        r_miss.into_body().collect().await?.to_bytes().as_ref(),
        b"<!doctype html><h1>SPA Shell</h1>"
    );
    assert_eq!(engine.telemetry().file_cache_counts(), (0, 1, 1, 0));

    // Delete `/shell/index.html` on disk to prove subsequent responses come strictly from cache!
    fs::remove_file(&shell_index)?;

    // 2. Cached 200 HIT on `/app/dashboard`: MUST STILL receive `/shell/*` owner rules!
    let r_hit_200 = engine
        .handle_request(
            Request::builder()
                .uri("/app/dashboard")
                .header(HOST, "headers.example.test")
                .body(empty_http_body())?,
            &ctx,
        )
        .await;
    assert_eq!(r_hit_200.status(), StatusCode::OK);
    assert_eq!(
        r_hit_200
            .headers()
            .get("x-owner")
            .and_then(|v| v.to_str().ok()),
        Some("shell-route"),
        "cached try-files fallback hit must keep fallback owner route headers"
    );
    assert_eq!(
        r_hit_200
            .headers()
            .get("x-shell-only-200")
            .and_then(|v| v.to_str().ok()),
        Some("yes")
    );
    assert!(r_hit_200.headers().get("x-shell-only-304").is_none());
    assert_eq!(
        r_hit_200
            .headers()
            .get("x-site-200")
            .and_then(|v| v.to_str().ok()),
        Some("site-ok")
    );
    assert_eq!(
        r_hit_200.into_body().collect().await?.to_bytes().as_ref(),
        b"<!doctype html><h1>SPA Shell</h1>"
    );
    assert_eq!(engine.telemetry().file_cache_counts(), (1, 1, 1, 0));

    // 3. Cached conditional 304 HIT on `/app/dashboard`: router evaluates status-conditioned
    //    rules against `304` (NOT the cached `200`!), keeping `/shell/*` ownership.
    let r_hit_304 = engine
        .handle_request(
            Request::builder()
                .uri("/app/dashboard")
                .header(HOST, "headers.example.test")
                .header(IF_NONE_MATCH, etag)
                .body(empty_http_body())?,
            &ctx,
        )
        .await;
    assert_eq!(r_hit_304.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(
        r_hit_304
            .headers()
            .get("x-owner")
            .and_then(|v| v.to_str().ok()),
        Some("shell-route")
    );
    assert!(r_hit_304.headers().get("x-shell-only-200").is_none());
    assert_eq!(
        r_hit_304
            .headers()
            .get("x-shell-only-304")
            .and_then(|v| v.to_str().ok()),
        Some("yes")
    );
    assert!(r_hit_304.headers().get("x-site-200").is_none());
    assert_eq!(
        r_hit_304
            .headers()
            .get("x-site-304")
            .and_then(|v| v.to_str().ok()),
        Some("site-not-mod")
    );
    assert_eq!(engine.telemetry().file_cache_counts(), (2, 1, 1, 0));

    // 4. Refused candidate (`try-files "/shell/../escape"` -> 400 Bad Request): NEVER cached and
    //    keeps originating `/bad/*` route's rules (even though raw text starts with `/shell/`).
    let fills_before_bad = engine.telemetry().file_cache_counts().2;
    let r_bad = engine
        .handle_request(
            Request::builder()
                .uri("/bad/anything")
                .header(HOST, "headers.example.test")
                .body(empty_http_body())?,
            &ctx,
        )
        .await;
    assert_eq!(r_bad.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        r_bad.headers().get("x-owner").and_then(|v| v.to_str().ok()),
        Some("bad-origin"),
        "refused try-files candidate must keep originating route headers"
    );
    assert_eq!(
        r_bad
            .headers()
            .get("x-site-400")
            .and_then(|v| v.to_str().ok()),
        Some("site-bad-req")
    );
    assert_eq!(
        engine.telemetry().file_cache_counts().2,
        fills_before_bad,
        "400 Bad Request from refused candidate must never be cached"
    );

    let _ = fs::remove_dir_all(&root);
    Ok(())
}

/// Review round 1, Item 5 (P2): explicit route `static { precompressed ... }` overrides must take
/// precedence over site-level `precompressed` policy with a warm `file-cache`, in both
/// directions (site `"off"` + route `"br"`, and site `"all"` + route `"off"`).
#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn m015_r1_item5_explicit_route_precompressed_override_with_warm_cache() -> TestResult {
    use http::header::{ACCEPT_ENCODING, CONTENT_ENCODING};

    let _epoch_guard = CRED_EPOCH_TEST_LOCK.read().await;
    let root = temp_dir("m015-r1-i5-route-precomp")?;
    let assets_dir = root.join("assets");
    let plain_dir = root.join("plain");
    let no_sib_dir = root.join("no-sibling");
    fs::create_dir_all(&assets_dir)?;
    fs::create_dir_all(&plain_dir)?;
    fs::create_dir_all(&no_sib_dir)?;

    let base_bytes = b"console.log('route-override-identity');";
    let br_bytes = b"ROUTE-OVERRIDE-BROTLI-SIBLING";
    let gz_bytes = b"ROUTE-OVERRIDE-GZIP-SIBLING";
    for dir in [&root, &assets_dir, &plain_dir, &no_sib_dir] {
        fs::write(dir.join("app.js"), base_bytes)?;
        fs::write(dir.join("app.js.br"), br_bytes)?;
        fs::write(dir.join("app.js.gz"), gz_bytes)?;
    }

    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "site-off.example.test" {{
    root "{root}"
    file-cache "60s"
    precompressed "off"
    route "/assets/*" {{
        static {{ precompressed "br" }}
    }}
    route "/plain/*" {{
        static
    }}
}}
site "site-all.example.test" {{
    root "{root}"
    file-cache "60s"
    precompressed "all"
    route "/no-sibling/*" {{
        static {{ precompressed "off" }}
    }}
}}
"#,
        root = kdl_path(&root)
    );

    let clock = ManualClock::new();
    let engine = build_engine(&kdl, &clock)?;
    let ctx = req_ctx("198.51.100.91", true)?;

    // Warm all 4 routes (misses -> fills).
    let cases = [
        (
            "site-off.example.test",
            "/assets/app.js",
            Some("br"),
            br_bytes.as_slice(),
        ),
        (
            "site-off.example.test",
            "/plain/app.js",
            None,
            base_bytes.as_slice(),
        ),
        (
            "site-all.example.test",
            "/no-sibling/app.js",
            None,
            base_bytes.as_slice(),
        ),
        (
            "site-all.example.test",
            "/app.js",
            Some("br"),
            br_bytes.as_slice(),
        ),
    ];
    for (host, uri, expected_enc, expected_body) in cases {
        let resp = engine
            .handle_request(
                Request::builder()
                    .uri(uri)
                    .header(HOST, host)
                    .header(ACCEPT_ENCODING, "br, gzip")
                    .body(empty_http_body())?,
                &ctx,
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK, "miss {host}{uri}");
        assert_eq!(
            resp.headers()
                .get(CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok()),
            expected_enc,
            "miss encoding mismatch for {host}{uri}"
        );
        assert_eq!(
            resp.into_body().collect().await?.to_bytes().as_ref(),
            expected_body,
            "miss body mismatch for {host}{uri}"
        );
    }
    assert_eq!(engine.telemetry().file_cache_counts(), (0, 4, 4, 0));

    // Delete all files on disk so the second pass proves every answer comes from the warm cache.
    for dir in [&root, &assets_dir, &plain_dir, &no_sib_dir] {
        fs::remove_file(dir.join("app.js"))?;
        fs::remove_file(dir.join("app.js.br"))?;
        fs::remove_file(dir.join("app.js.gz"))?;
    }

    for (host, uri, expected_enc, expected_body) in cases {
        let resp = engine
            .handle_request(
                Request::builder()
                    .uri(uri)
                    .header(HOST, host)
                    .header(ACCEPT_ENCODING, "br, gzip")
                    .body(empty_http_body())?,
                &ctx,
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK, "warm hit {host}{uri}");
        assert_eq!(
            resp.headers()
                .get(CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok()),
            expected_enc,
            "warm hit encoding mismatch for {host}{uri}"
        );
        assert_eq!(
            resp.into_body().collect().await?.to_bytes().as_ref(),
            expected_body,
            "warm hit body mismatch for {host}{uri}"
        );
    }
    assert_eq!(engine.telemetry().file_cache_counts(), (4, 4, 4, 0));

    let _ = fs::remove_dir_all(&root);
    Ok(())
}

/// Review round 1, Item 5 (P2): on a `try-files "{path}" "/shell/index.html"` route, after a
/// cached fallback entry expires and a direct file is created at `{path}`, refilling caches a
/// direct-template entry (`TryFilesOutcome::Response`) whose subsequent 200 and 304 cache hits
/// receive the originating route's headers (never stale fallback owner headers).
#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn m015_r1_item5_try_files_direct_template_hit_after_refill() -> TestResult {
    use http::header::{ETAG, IF_NONE_MATCH};

    let _epoch_guard = CRED_EPOCH_TEST_LOCK.read().await;
    let root = temp_dir("m015-r1-i5-direct-refill")?;
    let shell_dir = root.join("shell");
    let app_dir = root.join("app");
    fs::create_dir_all(&shell_dir)?;
    fs::create_dir_all(&app_dir)?;
    fs::write(shell_dir.join("index.html"), b"<h1>Fallback Shell</h1>")?;

    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "refill.example.test" {{
    root "{root}"
    file-cache "10s"
    route "/shell/*" {{
        static
        headers {{
            set "X-Owner" "shell-fallback" status="200 304"
            set "X-Shell-Only" "yes" status="200 304"
        }}
    }}
    route "/app/*" {{
        try-files "{{path}}" "/shell/index.html"
        headers {{
            set "X-Owner" "app-direct" status="200 304"
            set "X-Direct-200" "yes" status="200"
            set "X-Direct-304" "yes" status="304"
        }}
    }}
}}
"#,
        root = kdl_path(&root)
    );

    let clock = ManualClock::new();
    let engine = build_engine(&kdl, &clock)?;
    let ctx = req_ctx("198.51.100.92", true)?;

    // 1. `/app/dashboard` does not exist yet -> fallback to `/shell/index.html`, cached under
    //    `/shell/*` owner headers.
    let r_fb_miss = engine
        .handle_request(
            Request::builder()
                .uri("/app/dashboard")
                .header(HOST, "refill.example.test")
                .body(empty_http_body())?,
            &ctx,
        )
        .await;
    assert_eq!(r_fb_miss.status(), StatusCode::OK);
    assert_eq!(
        r_fb_miss
            .headers()
            .get("x-owner")
            .and_then(|v| v.to_str().ok()),
        Some("shell-fallback")
    );
    assert_eq!(
        r_fb_miss.into_body().collect().await?.to_bytes().as_ref(),
        b"<h1>Fallback Shell</h1>"
    );
    assert_eq!(engine.telemetry().file_cache_counts(), (0, 1, 1, 0));

    // 2. Expire the fallback entry and create the direct file `/app/dashboard`.
    clock.advance(Duration::from_secs(11));
    let direct_file = app_dir.join("dashboard");
    fs::write(&direct_file, b"DIRECT-DASHBOARD-CONTENT")?;

    // 3. Refill miss -> matches `{path}` directly, caches direct-template entry (`fallback == None`)
    //    with originating `/app/*` route headers!
    let r_direct_miss = engine
        .handle_request(
            Request::builder()
                .uri("/app/dashboard")
                .header(HOST, "refill.example.test")
                .body(empty_http_body())?,
            &ctx,
        )
        .await;
    assert_eq!(r_direct_miss.status(), StatusCode::OK);
    assert_eq!(
        r_direct_miss
            .headers()
            .get("x-owner")
            .and_then(|v| v.to_str().ok()),
        Some("app-direct")
    );
    assert!(r_direct_miss.headers().get("x-shell-only").is_none());
    assert_eq!(
        r_direct_miss
            .headers()
            .get("x-direct-200")
            .and_then(|v| v.to_str().ok()),
        Some("yes")
    );
    let direct_etag = r_direct_miss
        .headers()
        .get(ETAG)
        .cloned()
        .ok_or("missing ETag on direct refill")?;
    assert_eq!(
        r_direct_miss
            .into_body()
            .collect()
            .await?
            .to_bytes()
            .as_ref(),
        b"DIRECT-DASHBOARD-CONTENT"
    );
    assert_eq!(engine.telemetry().file_cache_counts(), (0, 2, 2, 0));

    // Remove the direct file on disk so subsequent 200 and 304 responses MUST come from cache!
    fs::remove_file(&direct_file)?;

    // 4. Direct-template 200 CACHE HIT after refill: keeps originating `/app/*` headers!
    let r_direct_hit = engine
        .handle_request(
            Request::builder()
                .uri("/app/dashboard")
                .header(HOST, "refill.example.test")
                .body(empty_http_body())?,
            &ctx,
        )
        .await;
    assert_eq!(r_direct_hit.status(), StatusCode::OK);
    assert_eq!(
        r_direct_hit
            .headers()
            .get("x-owner")
            .and_then(|v| v.to_str().ok()),
        Some("app-direct"),
        "direct-template cache hit after refill must keep originating route headers"
    );
    assert!(r_direct_hit.headers().get("x-shell-only").is_none());
    assert_eq!(
        r_direct_hit
            .headers()
            .get("x-direct-200")
            .and_then(|v| v.to_str().ok()),
        Some("yes")
    );
    assert!(r_direct_hit.headers().get("x-direct-304").is_none());
    assert_eq!(
        r_direct_hit
            .into_body()
            .collect()
            .await?
            .to_bytes()
            .as_ref(),
        b"DIRECT-DASHBOARD-CONTENT"
    );
    assert_eq!(engine.telemetry().file_cache_counts(), (1, 2, 2, 0));

    // 5. Direct-template 304 CACHE HIT after refill: evaluates status-conditioned rules on 304!
    let r_direct_304 = engine
        .handle_request(
            Request::builder()
                .uri("/app/dashboard")
                .header(HOST, "refill.example.test")
                .header(IF_NONE_MATCH, direct_etag)
                .body(empty_http_body())?,
            &ctx,
        )
        .await;
    assert_eq!(r_direct_304.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(
        r_direct_304
            .headers()
            .get("x-owner")
            .and_then(|v| v.to_str().ok()),
        Some("app-direct")
    );
    assert!(r_direct_304.headers().get("x-shell-only").is_none());
    assert!(r_direct_304.headers().get("x-direct-200").is_none());
    assert_eq!(
        r_direct_304
            .headers()
            .get("x-direct-304")
            .and_then(|v| v.to_str().ok()),
        Some("yes")
    );
    assert_eq!(engine.telemetry().file_cache_counts(), (2, 2, 2, 0));

    let _ = fs::remove_dir_all(&root);
    Ok(())
}

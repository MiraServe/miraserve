//! Oracle and regression tests for `try-files ... fallback-unless-extension=#true` (0.1.6 Item 3).

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use http::header::HOST;
use http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::BodyExt as _;
use miraserve_config::{LimitsConfig, parse_kdl};
use miraserve_http::{HttpEngine, RequestContext, empty_http_body};
use miraserve_security::validate_request_framing;
use miraserve_tls::AcmeChallengeStore;
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpListener;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn kdl_escape_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

fn host_allows_file_cache_admission() -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        miraserve_static::test_host_allows_file_cache_admission()
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        false
    }
}

fn ctx() -> RequestContext {
    RequestContext {
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10))),
        remote_port: Some(50_000),
        server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_port: 8443,
        is_https: true,
        tls: None,
    }
}

fn make_temp_root(tag: &str) -> Result<PathBuf, std::io::Error> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let dir = std::env::temp_dir().join(format!(
        "miraserve-tf-ext-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

async fn send(
    engine: &HttpEngine,
    method: Method,
    host: &str,
    uri: &str,
) -> Result<(StatusCode, HeaderMap, String), Box<dyn std::error::Error>> {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header(HOST, host)
        .body(empty_http_body())?;
    let resp = engine.handle_request(req, &ctx()).await;
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await?.to_bytes();
    Ok((status, headers, String::from_utf8_lossy(&body).into_owned()))
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn try_files_fallback_unless_extension_examples_headers_and_single_candidate() -> TestResult {
    let root = make_temp_root("examples")?;
    std::fs::create_dir_all(root.join("assets"))?;
    std::fs::create_dir_all(root.join("dir.v2"))?;
    std::fs::write(root.join("index.html"), b"SPA_INDEX")?;
    std::fs::write(root.join("404.html"), b"CUSTOM_404")?;
    std::fs::write(root.join("assets/real.js"), b"REAL_JS")?;
    std::fs::write(root.join("dir.v2/index.html"), b"DIR_V2_INDEX")?;

    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "spa.example.test" {{
    root "{root}"
    error-pages {{ page 404 "404.html" }}
    route "/index.html" {{
        static {{}}
        headers {{
            set "x-owner" "index-route"
        }}
    }}
    route "/*" {{
        try-files "{{path}}" "{{path}}/" "/index.html" fallback-unless-extension=#true
        headers {{
            set "x-owner" "catchall-route"
            set "x-not-found" "yes" status="404"
        }}
    }}
}}
site "default.example.test" {{
    root "{root}"
    route "/*" {{
        try-files "{{path}}" "{{path}}/" "/index.html"
    }}
}}
site "explicit-false.example.test" {{
    root "{root}"
    route "/*" {{
        try-files "{{path}}" "{{path}}/" "/index.html" fallback-unless-extension=#false
    }}
}}
site "single.example.test" {{
    root "{root}"
    route "/*" {{
        try-files "/index.html" fallback-unless-extension=#true
    }}
}}
site "dispatch-semantics.example.test" {{
    root "{root}"
    error-pages {{ page 404 "404.html" }}
    route "/dispatch" {{
        try-files "=204"
        headers {{
            set "x-dispatch" "from-dispatch"
        }}
    }}
    route "/*" {{
        try-files "/dispatch" "/index.html" fallback-unless-extension=#true
        headers {{
            set "x-owner" "catchall-route"
            set "x-not-found" "yes" status="404"
        }}
    }}
}}
site "status-semantics.example.test" {{
    root "{root}"
    error-pages {{ page 404 "404.html" }}
    route "/*" {{
        try-files "=410" "/index.html" fallback-unless-extension=#true
        headers {{
            set "x-owner" "status-catchall"
        }}
    }}
}}
"#,
        root = kdl_escape_path(&root),
    );

    let (cfg, _) = parse_kdl("spa.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;

    // Confirm MiraServe's own request validation (`miraserve_security::smuggling::validate_raw_path`)
    // permits percent-encoded `%0A`/`%0D` in paths (so they reach routing and the fallback
    // predicate), while rejecting raw unencoded control bytes (`URI_CTRL_CHAR`).
    let limits = LimitsConfig::default();
    for encoded_uri in ["/missing.js%0A", "/missing.js%0A%0A", "/missing.js%0D"] {
        let probe_req = Request::builder()
            .method(Method::GET)
            .uri(encoded_uri)
            .header(HOST, "spa.example.test")
            .body(())?;
        assert!(
            validate_request_framing(&probe_req, &limits).is_ok(),
            "encoded control byte URI {encoded_uri} should reach routing (not be rejected in smuggling validation)"
        );
    }
    let raw_lf_rej = miraserve_security::validate_request_target("/missing.js\n");
    assert_eq!(
        raw_lf_rej.err().map(|r| r.rule),
        Some("URI_CTRL_CHAR"),
        "raw unencoded LF in request target must still be rejected by URI_CTRL_CHAR"
    );

    // All required path cases on `spa.example.test` (including Nginx PCRE single-final-LF parity):
    let not_found_paths = [
        "/assets/nope.js",
        "/assets/nope.js?v=1",
        "/user/john.doe",
        "/files/archive.tar.gz",
        "/docs/v1.2",
        "/assets/nope%2ejs",
        "/assets/nope%2EJS",
        "//assets//nope.js",
        "/missing.js%0A",
        "/missing.js%0a",
    ];
    for uri in not_found_paths {
        let (st, hdrs, body) = send(&engine, Method::GET, "spa.example.test", uri).await?;
        assert_eq!(
            st,
            StatusCode::NOT_FOUND,
            "expected 404 for {uri}, got {st}"
        );
        assert_eq!(body, "CUSTOM_404", "expected site 404 page for {uri}");
        assert_eq!(
            hdrs.get("x-owner").and_then(|v| v.to_str().ok()),
            Some("catchall-route"),
            "refused fallback for {uri} must keep originating route headers"
        );
        assert_eq!(
            hdrs.get("x-not-found").and_then(|v| v.to_str().ok()),
            Some("yes"),
            "refused fallback for {uri} must apply status=404 rule on originating route"
        );
    }

    let fallback_paths = [
        "/about",
        "/about?file=nope.js",
        "/release/v1.2.x/notes",
        "/a.b/c",
        "/a%2eb/c",
        "/report.2026-11",
        "/photo.jpeg2000x",
        "/photo%2ejpeg2000x",
        "/app.v2/",
        "/app.v2//",
        "/missing.js%0A%0A",
        "/missing.js%0D",
        "/missing.js%0D%0A",
    ];
    for uri in fallback_paths {
        let (st, hdrs, body) = send(&engine, Method::GET, "spa.example.test", uri).await?;
        assert_eq!(
            st,
            StatusCode::OK,
            "expected 200 fallback for {uri}, got {st}"
        );
        assert_eq!(body, "SPA_INDEX", "expected /index.html fallback for {uri}");
        assert_eq!(
            hdrs.get("x-owner").and_then(|v| v.to_str().ok()),
            Some("index-route"),
            "fallback for {uri} must preserve 0.1.4/0.1.5 fallback route header ownership"
        );
        assert!(
            hdrs.get("x-not-found").is_none(),
            "fallback for {uri} must not carry originating route 404 header"
        );
    }

    // Encoded slash cases behave as MiraServe's normalised path rules say (400 on try-files).
    for uri in ["/a.b%2Fc", "/assets%2Fnope.js"] {
        let (st, _, _) = send(&engine, Method::GET, "spa.example.test", uri).await?;
        assert_eq!(
            st,
            StatusCode::BAD_REQUEST,
            "encoded slash {uri} must be rejected 400 on try-files"
        );
    }

    // Existing files and directories are ALWAYS served as today, whatever their name.
    let (st, hdrs, body) =
        send(&engine, Method::GET, "spa.example.test", "/assets/real.js").await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, "REAL_JS");
    assert_eq!(
        hdrs.get("x-owner").and_then(|v| v.to_str().ok()),
        Some("catchall-route")
    );

    let (st, hdrs, _) = send(&engine, Method::GET, "spa.example.test", "/dir.v2").await?;
    assert_eq!(st, StatusCode::MOVED_PERMANENTLY);
    assert_eq!(
        hdrs.get("location").and_then(|v| v.to_str().ok()),
        Some("/dir.v2/")
    );
    let (st, _, body) = send(&engine, Method::GET, "spa.example.test", "/dir.v2/").await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, "DIR_V2_INDEX");

    // Non-read method (POST): extension-like missing -> 404; existing file -> 405; extensionless -> fallback.
    let (st, _, _) = send(&engine, Method::POST, "spa.example.test", "/assets/nope.js").await?;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _, _) = send(&engine, Method::POST, "spa.example.test", "/assets/real.js").await?;
    assert_eq!(st, StatusCode::METHOD_NOT_ALLOWED);
    let (st, _, _) = send(&engine, Method::POST, "spa.example.test", "/about").await?;
    assert_eq!(st, StatusCode::METHOD_NOT_ALLOWED);

    // Default (omitted) and explicit `#false`: 0.1.5 behaviour byte-for-byte (/assets/nope.js falls back).
    for host in ["default.example.test", "explicit-false.example.test"] {
        let (st, _, body) = send(&engine, Method::GET, host, "/assets/nope.js").await?;
        assert_eq!(st, StatusCode::OK, "{host} must keep 0.1.5 fallback");
        assert_eq!(body, "SPA_INDEX");
    }

    // Single-candidate list: accepted, means no fallback for extension-like paths.
    let (st, _, body) = send(&engine, Method::GET, "single.example.test", "/about").await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, "SPA_INDEX");
    let (st, _, _) = send(
        &engine,
        Method::GET,
        "single.example.test",
        "/assets/nope.js",
    )
    .await?;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _, _) = send(
        &engine,
        Method::POST,
        "single.example.test",
        "/assets/nope.js",
    )
    .await?;
    assert_eq!(st, StatusCode::NOT_FOUND);

    // P2 #9 semantics: when fallback is refused, the route answers its own 404 (with its headers
    // and site error page) — it does NOT emulate removing the last candidate from the list.
    // Example 1: exact `/dispatch` route (204) before catch-all `try-files "/dispatch" "/index.html"`.
    let (st_direct, hdrs_direct, _) = send(
        &engine,
        Method::GET,
        "dispatch-semantics.example.test",
        "/dispatch",
    )
    .await?;
    assert_eq!(st_direct, StatusCode::NO_CONTENT);
    assert_eq!(
        hdrs_direct.get("x-dispatch").and_then(|v| v.to_str().ok()),
        Some("from-dispatch")
    );
    let (st, hdrs, body) = send(
        &engine,
        Method::GET,
        "dispatch-semantics.example.test",
        "/missing.js",
    )
    .await?;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_eq!(body, "CUSTOM_404");
    assert_eq!(
        hdrs.get("x-owner").and_then(|v| v.to_str().ok()),
        Some("catchall-route")
    );
    assert_eq!(
        hdrs.get("x-not-found").and_then(|v| v.to_str().ok()),
        Some("yes")
    );
    assert!(
        hdrs.get("x-dispatch").is_none(),
        "refused fallback must not promote penultimate /dispatch into an internal rewrite"
    );

    // Example 2: `POST` with `try-files "=410" "/index.html" fallback-unless-extension=#true`
    // answers 404 (non-read methods ignore earlier `=status` candidates and refusing the final
    // candidate returns the originating route's 404). On `GET`, earlier `=410` still runs before
    // reaching the skipped last candidate and answers 410.
    let (st, hdrs, body) = send(
        &engine,
        Method::POST,
        "status-semantics.example.test",
        "/missing.js",
    )
    .await?;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_eq!(body, "CUSTOM_404");
    assert_eq!(
        hdrs.get("x-owner").and_then(|v| v.to_str().ok()),
        Some("status-catchall")
    );
    let (st, _, _) = send(
        &engine,
        Method::GET,
        "status-semantics.example.test",
        "/missing.js",
    )
    .await?;
    assert_eq!(st, StatusCode::GONE);

    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

#[tokio::test]
async fn try_files_fallback_unless_extension_applies_to_fastcgi_last_candidate() -> TestResult {
    let root = make_temp_root("fcgi")?;
    std::fs::write(root.join("index.php"), b"<?php echo 'ok';")?;
    std::fs::write(root.join("exists.js"), b"JS_OK")?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepts_bg = Arc::clone(&accepts);
    let bg = tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            accepts_bg.fetch_add(1, Ordering::SeqCst);
            let _ = sock.shutdown().await;
        }
    });

    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "php-spa.example.test" {{
    root "{root}"
    route "*.php" {{
        fastcgi-pass "tcp://127.0.0.1:{port}"
    }}
    route "/*" {{
        try-files "{{path}}" "{{path}}/" "/index.php?{{query}}" fallback-unless-extension=#true
    }}
}}
"#,
        root = kdl_escape_path(&root),
    );
    let (cfg, _) = parse_kdl("php-spa.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;

    // Existing file served statically; FastCGI untouched.
    let (st, _, body) = send(&engine, Method::GET, "php-spa.example.test", "/exists.js").await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, "JS_OK");
    assert_eq!(accepts.load(Ordering::SeqCst), 0);

    // Missing extension-like path: last candidate `/index.php?{query}` is skipped -> 404, 0 FastCGI connects.
    let (st, _, _) = send(
        &engine,
        Method::GET,
        "php-spa.example.test",
        "/assets/nope.js",
    )
    .await?;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        0,
        "extension-like missing path must never invoke FastCGI fallback"
    );

    // Extensionless path: falls back to `/index.php?{query}` -> FastCGI IS invoked (502 from immediate EOF).
    let (st, _, _) = send(&engine, Method::GET, "php-spa.example.test", "/about?tab=1").await?;
    assert_eq!(st, StatusCode::BAD_GATEWAY);
    assert!(
        accepts.load(Ordering::SeqCst) >= 1,
        "extensionless path must invoke FastCGI fallback"
    );

    bg.abort();
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

#[tokio::test]
async fn try_files_fallback_unless_extension_never_hits_or_creates_cached_fallback() -> TestResult {
    let root = make_temp_root("cache")?;
    std::fs::create_dir_all(root.join("assets"))?;
    std::fs::write(root.join("index.html"), b"CACHED_SPA_INDEX")?;
    std::fs::write(root.join("assets/real.js"), b"CACHED_REAL_JS")?;

    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "cached-spa.example.test" {{
    root "{root}"
    file-cache "60s"
    route "/index.html" {{
        static {{}}
        headers {{
            set "x-owner" "index-route"
        }}
    }}
    route "/*" {{
        try-files "{{path}}" "{{path}}/" "/index.html" fallback-unless-extension=#true
        headers {{
            set "x-owner" "catchall-route"
        }}
    }}
}}
"#,
        root = kdl_escape_path(&root),
    );
    let (cfg, _) = parse_kdl("cached-spa.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    let openat2_available = host_allows_file_cache_admission();

    // 1. Warm cached fallback entry via `/about`.
    for _ in 0..2 {
        let (st, hdrs, body) =
            send(&engine, Method::GET, "cached-spa.example.test", "/about").await?;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body, "CACHED_SPA_INDEX");
        assert_eq!(
            hdrs.get("x-owner").and_then(|v| v.to_str().ok()),
            Some("index-route")
        );
    }

    let (hits_before, _, fills_before, _) = engine.telemetry().file_cache_counts();
    if openat2_available {
        assert!(
            fills_before >= 1 && hits_before >= 1,
            "expected `/about` fallback to fill and hit file cache when openat2 is available, got hits={hits_before} fills={fills_before}"
        );
    } else {
        assert_eq!(
            (fills_before, hits_before),
            (0, 0),
            "expected non-openat2 environment to store nothing, got hits={hits_before} fills={fills_before}"
        );
    }

    // 2. Request `/assets/nope.js` twice: must NEVER answer from a cached fallback entry and
    //    must NEVER create one (`hit` and `fill` stay unchanged).
    for _ in 0..2 {
        let (st, hdrs, _) = send(
            &engine,
            Method::GET,
            "cached-spa.example.test",
            "/assets/nope.js",
        )
        .await?;
        assert_eq!(st, StatusCode::NOT_FOUND);
        assert_eq!(
            hdrs.get("x-owner").and_then(|v| v.to_str().ok()),
            Some("catchall-route")
        );
    }

    let (hits_after, _, fills_after, _) = engine.telemetry().file_cache_counts();
    assert_eq!(
        hits_after, hits_before,
        "refused fallback path must never hit file cache"
    );
    assert_eq!(
        fills_after, fills_before,
        "refused fallback path must never admit to file cache"
    );

    // 3. Existing extensioned file `/assets/real.js` is still served and cached directly.
    for _ in 0..2 {
        let (st, hdrs, body) = send(
            &engine,
            Method::GET,
            "cached-spa.example.test",
            "/assets/real.js",
        )
        .await?;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body, "CACHED_REAL_JS");
        assert_eq!(
            hdrs.get("x-owner").and_then(|v| v.to_str().ok()),
            Some("catchall-route")
        );
    }
    let (hits_final, _, fills_final, _) = engine.telemetry().file_cache_counts();
    if openat2_available {
        assert!(
            fills_final > fills_after && hits_final > hits_after,
            "existing file `/assets/real.js` should still fill and hit cache when openat2 is available"
        );
    } else {
        assert_eq!(
            (fills_final, hits_final),
            (fills_after, hits_after),
            "expected non-openat2 environment to store nothing for `/assets/real.js`"
        );
    }

    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

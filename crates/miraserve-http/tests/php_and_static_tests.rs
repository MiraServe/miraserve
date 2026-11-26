//! Regression tests for hosting-panel staging VM bugs #2 and #3:
//! - FastCGI `PATH_INFO` routing (`/script.php/extra`) + `PATH_INFO`, `SERVER_ADDR`, `REMOTE_PORT`
//! - Configurable site `index` order (`index "index.php" "index.html"` vs `index "index.html" "index.php"`)
//! - Static directory `/dir` -> `/dir/` `301` redirect preserving query string
//! - `POST`/`OPTIONS` on existing static files returning `405 Method Not Allowed` (`Allow: GET, HEAD`)

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use http::header::{ALLOW, HOST, LOCATION};
use http::{Method, Request, StatusCode};
use http_body_util::BodyExt as _;
use miraserve_config::parse_kdl;
use miraserve_fastcgi::protocol::{
    EndRequestBody, RecordType, decode_params, read_record, write_record, write_stream_records,
};
use miraserve_http::{HttpEngine, RequestContext, empty_http_body};
use miraserve_tls::AcmeChallengeStore;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpListener;

type TestResult = Result<(), Box<dyn std::error::Error>>;

async fn serve_mock_fastcgi<S>(
    mut stream: S,
    hits: Arc<AtomicUsize>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    hits.fetch_add(1, Ordering::AcqRel);
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
    let payload = format!(
        "Content-Type: text/plain\r\n\r\nSCRIPT_NAME={}\nSCRIPT_FILENAME={}\nPATH_INFO={}\nQUERY_STRING={}\nREQUEST_URI={}\nSERVER_ADDR={}\nSERVER_PORT={}\nREMOTE_ADDR={}\nREMOTE_PORT={}",
        get("SCRIPT_NAME"),
        get("SCRIPT_FILENAME"),
        get("PATH_INFO"),
        get("QUERY_STRING"),
        get("REQUEST_URI"),
        get("SERVER_ADDR"),
        get("SERVER_PORT"),
        get("REMOTE_ADDR"),
        get("REMOTE_PORT"),
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

fn test_ctx() -> RequestContext {
    RequestContext {
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42))),
        remote_port: Some(54321),
        server_addr: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
        server_port: 8443,
        is_https: true,
        tls: None,
    }
}

#[tokio::test]
async fn fastcgi_path_info_server_addr_remote_port_and_confinement() -> TestResult {
    let fcgi_listener = TcpListener::bind("127.0.0.1:0").await?;
    let fcgi_addr = fcgi_listener.local_addr()?;
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_srv = Arc::clone(&hits);
    let fcgi_task = tokio::spawn(async move {
        while let Ok((stream, _)) = fcgi_listener.accept().await {
            let h = Arc::clone(&hits_srv);
            tokio::spawn(async move {
                let _ = serve_mock_fastcgi(stream, h).await;
            });
        }
    });

    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "miraserve-php-pathinfo-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(root.join("uploads"))?;
    std::fs::write(root.join("script.php"), b"<?php echo 'ok';")?;
    std::fs::write(root.join("wp-config.php"), b"<?php // secret")?;
    std::fs::write(root.join("uploads").join("photo.jpg"), b"JPEG")?;

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/tmp/c.crt"; key "/tmp/c.key" }}
}}
site "php.example.test" {{
    preset "wordpress-hardened"
    root "{}"
    route "*.php" {{
        fastcgi-pass "tcp://{}"
    }}
    route "/*" {{
        try-files "{{path}}" "{{path}}/" "=404"
    }}
}}
"#,
        root.display(),
        fcgi_addr,
    );
    let (cfg, _) = parse_kdl("php-pathinfo.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    let ctx = test_ctx();

    // 1. `/script.php/extra/path?a=1` splits cleanly into SCRIPT_NAME + PATH_INFO + CGI vars.
    let req = Request::builder()
        .method(Method::GET)
        .uri("/script.php/extra/path?a=1")
        .header(HOST, "php.example.test")
        .body(empty_http_body())?;
    let resp = engine.handle_request(req, &ctx).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(resp.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(body.contains("SCRIPT_NAME=/script.php\n"), "got:\n{body}");
    assert!(body.contains("PATH_INFO=/extra/path\n"), "got:\n{body}");
    assert!(body.contains("QUERY_STRING=a=1\n"), "got:\n{body}");
    assert!(
        body.contains("REQUEST_URI=/script.php/extra/path?a=1\n"),
        "got:\n{body}"
    );
    assert!(body.contains("SERVER_ADDR=203.0.113.10\n"), "got:\n{body}");
    assert!(body.contains("SERVER_PORT=8443\n"), "got:\n{body}");
    assert!(body.contains("REMOTE_ADDR=198.51.100.42\n"), "got:\n{body}");
    assert!(body.contains("REMOTE_PORT=54321"), "got:\n{body}");

    // 2. Plain `/script.php` leaves PATH_INFO unset while still setting SERVER_ADDR & REMOTE_PORT.
    let req_plain = Request::builder()
        .method(Method::GET)
        .uri("/script.php")
        .header(HOST, "php.example.test")
        .body(empty_http_body())?;
    let resp_plain = engine.handle_request(req_plain, &ctx).await;
    assert_eq!(resp_plain.status(), StatusCode::OK);
    let body_plain =
        String::from_utf8(resp_plain.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(
        body_plain.contains("PATH_INFO=<unset>\n"),
        "got:\n{body_plain}"
    );
    assert!(
        body_plain.contains("SERVER_ADDR=203.0.113.10\n"),
        "got:\n{body_plain}"
    );
    assert!(
        body_plain.contains("REMOTE_PORT=54321"),
        "got:\n{body_plain}"
    );

    // 3. Security invariants remain intact: nonexistent script & wordpress-hardened PATH_INFO bypasses
    //    never invoke PHP-FPM.
    let hits_before_evil = hits.load(Ordering::Acquire);
    for evil in [
        "/uploads/photo.jpg/evil.php",
        "/missing.php/extra",
        "/wp-config.php/extra",
    ] {
        let r = Request::builder()
            .method(Method::GET)
            .uri(evil)
            .header(HOST, "php.example.test")
            .body(empty_http_body())?;
        let resp = engine.handle_request(r, &ctx).await;
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "unexpected status for {evil}"
        );
    }
    assert_eq!(
        hits.load(Ordering::Acquire),
        hits_before_evil,
        "blocked/nonexistent PATH_INFO requests must never reach PHP-FPM"
    );

    fcgi_task.abort();
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

#[tokio::test]
async fn static_index_order_dir_redirect_and_405_on_static_files() -> TestResult {
    let fcgi_listener = TcpListener::bind("127.0.0.1:0").await?;
    let fcgi_addr = fcgi_listener.local_addr()?;
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_srv = Arc::clone(&hits);
    let fcgi_task = tokio::spawn(async move {
        while let Ok((stream, _)) = fcgi_listener.accept().await {
            let h = Arc::clone(&hits_srv);
            tokio::spawn(async move {
                let _ = serve_mock_fastcgi(stream, h).await;
            });
        }
    });

    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "miraserve-static-php-order-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(root.join("sub"))?;
    std::fs::create_dir_all(root.join("staticdir"))?;
    std::fs::create_dir_all(root.join("emptydir"))?;
    std::fs::write(root.join("index.php"), b"<?php echo 'root php';")?;
    std::fs::write(root.join("index.html"), b"<h1>root html</h1>")?;
    std::fs::write(root.join("sub").join("index.php"), b"<?php echo 'sub php';")?;
    std::fs::write(root.join("sub").join("index.html"), b"<h1>sub html</h1>")?;
    std::fs::write(
        root.join("staticdir").join("index.html"),
        b"<h1>staticdir html</h1>",
    )?;
    std::fs::write(root.join("style.css"), b"body { color: black; }")?;
    std::fs::write(root.join(".env"), b"SECRET=1")?;

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/tmp/c.crt"; key "/tmp/c.key" }}
}}
site "php-first.example.test" {{
    root "{root}"
    index "index.php" "index.html"
    route "*.php" {{
        fastcgi-pass "tcp://{fcgi}"
    }}
    route "/*" {{
        try-files "{{path}}" "{{path}}/" "=404"
    }}
}}
site "php-first-notry.example.test" {{
    root "{root}"
    index "index.php" "index.html"
    route "*.php" {{
        fastcgi-pass "tcp://{fcgi}"
    }}
}}
site "html-first.example.test" {{
    root "{root}"
    index "index.html" "index.php"
    route "*.php" {{
        fastcgi-pass "tcp://{fcgi}"
    }}
    route "/*" {{
        try-files "{{path}}" "{{path}}/" "=404"
    }}
}}
site "wp-fallback.example.test" {{
    root "{root}"
    index "index.php" "index.html"
    route "*.php" {{
        fastcgi-pass "tcp://{fcgi}"
    }}
    route "/*" {{
        try-files "{{path}}" "{{path}}/" "/index.php?{{query}}"
    }}
}}
"#,
        root = root.display(),
        fcgi = fcgi_addr,
    );
    let (cfg, _) = parse_kdl("static-index-order.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    let ctx = test_ctx();

    // 1. `index "index.php" "index.html"`: `index.php` wins over `index.html` on BOTH try-files
    //    AND plain default static sites (at `/` and `/sub/`).
    for host in ["php-first.example.test", "php-first-notry.example.test"] {
        for (uri, expected_script) in [("/", "/index.php"), ("/sub/", "/sub/index.php")] {
            let req = Request::builder()
                .method(Method::GET)
                .uri(uri)
                .header(HOST, host)
                .body(empty_http_body())?;
            let resp = engine.handle_request(req, &ctx).await;
            assert_eq!(resp.status(), StatusCode::OK, "{host}{uri}");
            let body = String::from_utf8(resp.into_body().collect().await?.to_bytes().to_vec())?;
            assert!(
                body.contains(&format!("SCRIPT_NAME={expected_script}\n")),
                "{host}{uri} must execute {expected_script}, got:\n{body}"
            );
        }
    }

    // 2. `index "index.html" "index.php"`: `index.html` wins over `index.php`.
    let req_html = Request::builder()
        .method(Method::GET)
        .uri("/")
        .header(HOST, "html-first.example.test")
        .body(empty_http_body())?;
    let resp_html = engine.handle_request(req_html, &ctx).await;
    assert_eq!(resp_html.status(), StatusCode::OK);
    let body_html = String::from_utf8(resp_html.into_body().collect().await?.to_bytes().to_vec())?;
    assert_eq!(body_html, "<h1>root html</h1>");

    // 3. `/dir` -> `/dir/` 301 redirect (preserving query string) for BOTH static dirs and PHP dirs,
    //    while empty directories return 404 (no redirect).
    for (host, uri, expected_loc) in [
        ("html-first.example.test", "/staticdir", "/staticdir/"),
        (
            "html-first.example.test",
            "/staticdir?tab=1",
            "/staticdir/?tab=1",
        ),
        (
            "php-first-notry.example.test",
            "/staticdir?x=2",
            "/staticdir/?x=2",
        ),
        ("php-first.example.test", "/sub?k=v", "/sub/?k=v"),
        ("php-first-notry.example.test", "/sub?k=v", "/sub/?k=v"),
    ] {
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(HOST, host)
            .body(empty_http_body())?;
        let resp = engine.handle_request(req, &ctx).await;
        assert_eq!(
            resp.status(),
            StatusCode::MOVED_PERMANENTLY,
            "expected 301 for {host}{uri}"
        );
        assert_eq!(
            resp.headers().get(LOCATION).and_then(|v| v.to_str().ok()),
            Some(expected_loc),
            "wrong Location for {host}{uri}"
        );
    }
    let empty_req = Request::builder()
        .method(Method::GET)
        .uri("/emptydir")
        .header(HOST, "html-first.example.test")
        .body(empty_http_body())?;
    assert_eq!(
        engine.handle_request(empty_req, &ctx).await.status(),
        StatusCode::NOT_FOUND
    );

    // 4. `POST` and `OPTIONS` on an existing static file return `405 Method Not Allowed` with
    //    `Allow: GET, HEAD` across both `=404` and `/index.php?{query}` try-files routes, while
    //    missing files still return 404 (on `=404`) or rewrite to `/index.php` (on WordPress).
    for host in ["php-first.example.test", "wp-fallback.example.test"] {
        for method in [Method::POST, Method::OPTIONS] {
            let req = Request::builder()
                .method(method.clone())
                .uri("/style.css")
                .header(HOST, host)
                .body(empty_http_body())?;
            let resp = engine.handle_request(req, &ctx).await;
            assert_eq!(
                resp.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "{method} {host}/style.css must return 405"
            );
            assert_eq!(
                resp.headers().get(ALLOW).and_then(|v| v.to_str().ok()),
                Some("GET, HEAD"),
                "{method} {host}/style.css must send Allow: GET, HEAD"
            );
        }
    }
    // Missing path + dotfile on `=404` still return 404 (never 405 existence leak).
    for path in ["/missing.css", "/.env"] {
        let req = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(HOST, "php-first.example.test")
            .body(empty_http_body())?;
        assert_eq!(
            engine.handle_request(req, &ctx).await.status(),
            StatusCode::NOT_FOUND,
            "POST {path} on =404 must return 404"
        );
    }
    // Missing REST route on WordPress try-files still rewrites POST to `/index.php`.
    let wp_post = Request::builder()
        .method(Method::POST)
        .uri("/wp-json/wp/v2/posts?draft=1")
        .header(HOST, "wp-fallback.example.test")
        .body(empty_http_body())?;
    let wp_resp = engine.handle_request(wp_post, &ctx).await;
    assert_eq!(wp_resp.status(), StatusCode::OK);
    let wp_body = String::from_utf8(wp_resp.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(
        wp_body.contains("SCRIPT_NAME=/index.php\n"),
        "got:\n{wp_body}"
    );

    fcgi_task.abort();
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

/// Codex G4: A `PATH_INFO` URL such as `/wp-login.php/extra` MUST NOT bypass an exact script
/// route's rate limit or non-FastCGI restriction by falling through to a general `*.php` route.
#[tokio::test]
async fn g4_php_path_info_enforces_exact_script_route_rate_limit_and_restrictions() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let fcgi_addr = listener.local_addr()?;
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_srv = Arc::clone(&hits);
    let fcgi_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let h = Arc::clone(&hits_srv);
            tokio::spawn(async move {
                let _ = serve_mock_fastcgi(stream, h).await;
            });
        }
    });

    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "miraserve-g4-path-info-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("wp-login.php"), b"<?php echo 'login'; ?>")?;
    std::fs::write(root.join("secret.php"), b"<?php echo 'secret'; ?>")?;
    std::fs::write(root.join("info.php"), b"<?php echo 'info'; ?>")?;

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/tmp/c.crt"; key "/tmp/c.key" }}
}}
site "wp-strict.example.test" {{
    root "{root}"
    route "/wp-login.php" {{
        rate-limit requests=1 per="1m" burst=1
        fastcgi-pass "tcp://{fcgi}"
    }}
    route "/secret.php" {{
        static
    }}
    route "*.php" {{
        fastcgi-pass "tcp://{fcgi}"
    }}
}}
"#,
        root = root.display(),
        fcgi = fcgi_addr,
    );
    let (cfg, _) = parse_kdl("g4-path-info.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    let ctx = test_ctx();

    // 1. First request to `/wp-login.php/extra` succeeds with PATH_INFO=/extra and consumes the
    //    exact `/wp-login.php` route's 1/m burst=1 token.
    let req1 = Request::builder()
        .method(Method::GET)
        .uri("/wp-login.php/extra")
        .header(HOST, "wp-strict.example.test")
        .body(empty_http_body())?;
    let resp1 = engine.handle_request(req1, &ctx).await;
    assert_eq!(resp1.status(), StatusCode::OK);
    let body1 = String::from_utf8(resp1.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(
        body1.contains("SCRIPT_NAME=/wp-login.php\n") && body1.contains("PATH_INFO=/extra\n"),
        "expected exact route to execute /wp-login.php with PATH_INFO=/extra, got:\n{body1}"
    );

    // 2. Second request to `/wp-login.php/other` MUST hit 429 Too Many Requests from the exact
    //    `/wp-login.php` route (cannot bypass via PATH_INFO to general `*.php`).
    let req2 = Request::builder()
        .method(Method::GET)
        .uri("/wp-login.php/other")
        .header(HOST, "wp-strict.example.test")
        .body(empty_http_body())?;
    let resp2 = engine.handle_request(req2, &ctx).await;
    assert_eq!(
        resp2.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "PATH_INFO on /wp-login.php must enforce the exact route's rate limit"
    );

    // 3. `/secret.php/extra` MUST NOT bypass the exact non-FastCGI `/secret.php` route via `*.php`.
    let req_secret = Request::builder()
        .method(Method::GET)
        .uri("/secret.php/extra")
        .header(HOST, "wp-strict.example.test")
        .body(empty_http_body())?;
    let resp_secret = engine.handle_request(req_secret, &ctx).await;
    assert_eq!(
        resp_secret.status(),
        StatusCode::NOT_FOUND,
        "PATH_INFO must never allow *.php to execute a script owned by a non-FastCGI exact route"
    );

    // 4. General `/info.php/extra` still works normally via `*.php`.
    let req_info = Request::builder()
        .method(Method::GET)
        .uri("/info.php/extra")
        .header(HOST, "wp-strict.example.test")
        .body(empty_http_body())?;
    let resp_info = engine.handle_request(req_info, &ctx).await;
    assert_eq!(resp_info.status(), StatusCode::OK);
    let body_info = String::from_utf8(resp_info.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(
        body_info.contains("SCRIPT_NAME=/info.php\n") && body_info.contains("PATH_INFO=/extra\n"),
        "general *.php route must continue serving PATH_INFO normally, got:\n{body_info}"
    );

    fcgi_task.abort();
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

/// Codex G9: Explicit `static` routes that omit `index` MUST inherit `site.index` (including
/// PHP-first order on FastCGI sites), while explicit route-level `static { index ... }` overrides
/// MUST be preserved.
#[tokio::test]
async fn g9_explicit_static_routes_inherit_site_index_and_preserve_route_override() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let fcgi_addr = listener.local_addr()?;
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_srv = Arc::clone(&hits);
    let fcgi_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let h = Arc::clone(&hits_srv);
            tokio::spawn(async move {
                let _ = serve_mock_fastcgi(stream, h).await;
            });
        }
    });

    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "miraserve-g9-static-index-{}-{nanos}",
        std::process::id()
    ));
    for sub in ["inherited", "override", "docs", "legacy"] {
        std::fs::create_dir_all(root.join(sub))?;
    }
    std::fs::write(root.join("inherited/index.php"), b"<?php echo 'inh'; ?>")?;
    std::fs::write(
        root.join("inherited/index.html"),
        b"<h1>inherited html</h1>",
    )?;
    std::fs::write(root.join("override/index.php"), b"<?php echo 'ovr'; ?>")?;
    std::fs::write(root.join("override/index.html"), b"<h1>override html</h1>")?;
    std::fs::write(root.join("docs/home.html"), b"<h1>docs home</h1>")?;
    std::fs::write(root.join("docs/index.html"), b"<h1>docs index</h1>")?;
    std::fs::write(root.join("legacy/home.html"), b"<h1>legacy home</h1>")?;
    std::fs::write(root.join("legacy/index.html"), b"<h1>legacy index</h1>")?;

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/tmp/c.crt"; key "/tmp/c.key" }}
}}
site "php-static.example.test" {{
    root "{root}"
    index "index.php" "index.html"
    route "*.php" {{
        fastcgi-pass "tcp://{fcgi}"
    }}
    route "/inherited/*" {{
        static
    }}
    route "/override/*" {{
        static {{
            index "index.html" "index.php"
        }}
    }}
}}
site "html-static.example.test" {{
    root "{root}"
    index "home.html" "index.html"
    route "/docs/*" {{
        static
    }}
    route "/legacy/*" {{
        static {{
            index "index.html" "home.html"
        }}
    }}
}}
"#,
        root = root.display(),
        fcgi = fcgi_addr,
    );
    let (cfg, _) = parse_kdl("g9-static-index.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    let ctx = test_ctx();

    // 1. Explicit `static` route omitting `index` inherits PHP-first `site.index` -> executes
    //    `/inherited/index.php` via FastCGI instead of serving `index.html`!
    let r_inh = engine
        .handle_request(
            Request::builder()
                .uri("/inherited/")
                .header(HOST, "php-static.example.test")
                .body(empty_http_body())?,
            &ctx,
        )
        .await;
    assert_eq!(r_inh.status(), StatusCode::OK);
    let b_inh = String::from_utf8(r_inh.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(
        b_inh.contains("SCRIPT_NAME=/inherited/index.php\n"),
        "explicit static route without index must inherit site PHP-first order, got:\n{b_inh}"
    );

    // 2. Explicit `static { index "index.html" "index.php" }` preserves its HTML-first override.
    let r_ovr = engine
        .handle_request(
            Request::builder()
                .uri("/override/")
                .header(HOST, "php-static.example.test")
                .body(empty_http_body())?,
            &ctx,
        )
        .await;
    assert_eq!(r_ovr.status(), StatusCode::OK);
    let b_ovr = String::from_utf8(r_ovr.into_body().collect().await?.to_bytes().to_vec())?;
    assert_eq!(b_ovr, "<h1>override html</h1>");

    // 3. Explicit `static` route omitting `index` inherits custom HTML order (`home.html` first).
    let r_docs = engine
        .handle_request(
            Request::builder()
                .uri("/docs/")
                .header(HOST, "html-static.example.test")
                .body(empty_http_body())?,
            &ctx,
        )
        .await;
    assert_eq!(r_docs.status(), StatusCode::OK);
    let b_docs = String::from_utf8(r_docs.into_body().collect().await?.to_bytes().to_vec())?;
    assert_eq!(b_docs, "<h1>docs home</h1>");

    // 4. Explicit `static { index "index.html" "home.html" }` preserves its route override.
    let r_leg = engine
        .handle_request(
            Request::builder()
                .uri("/legacy/")
                .header(HOST, "html-static.example.test")
                .body(empty_http_body())?,
            &ctx,
        )
        .await;
    assert_eq!(r_leg.status(), StatusCode::OK);
    let b_leg = String::from_utf8(r_leg.into_body().collect().await?.to_bytes().to_vec())?;
    assert_eq!(b_leg, "<h1>legacy index</h1>");

    fcgi_task.abort();
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

/// Codex P1 (G4 exact-only + internal rewrites):
/// 1. An exact-only PHP site (`route "/wp-login.php"` with NO `*.php`) must NOT accept
///    `/wp-login.php/extra` (preserving anchored Nginx allowlists).
/// 2. Directory indexes and `try-files` internal rewrites must use the exact same route-ownership
///    check as direct requests so an earlier non-FastCGI route protecting `/protected/index.php`
///    cannot be bypassed via `/protected/` or a `try-files` fallback, and a rate-limited exact
///    script route `/gated/index.php` is enforced via `/gated/`.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn g4_p1_exact_only_blocks_path_info_and_internal_rewrites_enforce_owner_route() -> TestResult
{
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let fcgi_addr = listener.local_addr()?;
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_srv = Arc::clone(&hits);
    let fcgi_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let h = Arc::clone(&hits_srv);
            tokio::spawn(async move {
                let _ = serve_mock_fastcgi(stream, h).await;
            });
        }
    });

    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "miraserve-g4-p1-exact-rewrite-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(root.join("protected"))?;
    std::fs::create_dir_all(root.join("gated"))?;
    std::fs::write(root.join("wp-login.php"), b"<?php echo 'login'; ?>")?;
    std::fs::write(
        root.join("protected/index.php"),
        b"<?php echo 'blocked'; ?>",
    )?;
    std::fs::write(root.join("gated/index.php"), b"<?php echo 'gated'; ?>")?;

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/tmp/c.crt"; key "/tmp/c.key" }}
}}
site "exact-only.example.test" {{
    root "{root}"
    route "/wp-login.php" {{
        fastcgi-pass "tcp://{fcgi}"
    }}
}}
site "rewrite-owner.example.test" {{
    root "{root}"
    index "index.php" "index.html"
    route "/protected/index.php" {{
        static
    }}
    route "/gated/index.php" {{
        rate-limit requests=1 per="1m" burst=1
        fastcgi-pass "tcp://{fcgi}"
    }}
    route "*.php" {{
        fastcgi-pass "tcp://{fcgi}"
    }}
    route "/*" {{
        try-files "{{path}}" "{{path}}/" "/protected/index.php"
    }}
}}
"#,
        root = root.display(),
        fcgi = fcgi_addr,
    );
    let (cfg, _) = parse_kdl("g4-p1.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    let ctx = test_ctx();

    // 1. Exact-only site: `/wp-login.php` executes, `/wp-login.php/extra` is rejected (404)!
    let r_exact = engine
        .handle_request(
            Request::builder()
                .uri("/wp-login.php")
                .header(HOST, "exact-only.example.test")
                .body(empty_http_body())?,
            &ctx,
        )
        .await;
    assert_eq!(r_exact.status(), StatusCode::OK);
    let r_suffix = engine
        .handle_request(
            Request::builder()
                .uri("/wp-login.php/extra")
                .header(HOST, "exact-only.example.test")
                .body(empty_http_body())?,
            &ctx,
        )
        .await;
    assert_eq!(
        r_suffix.status(),
        StatusCode::NOT_FOUND,
        "exact-only FastCGI route must NOT accept PATH_INFO suffix"
    );

    // 2. Internal rewrite ownership: direct `/protected/index.php`, directory `/protected/`, and
    //    `try-files` fallback `/missing-page` MUST ALL be blocked (404), never reaching PHP-FPM!
    let hits_before = hits.load(Ordering::Acquire);
    for uri in ["/protected/index.php", "/protected/", "/missing-page"] {
        let resp = engine
            .handle_request(
                Request::builder()
                    .uri(uri)
                    .header(HOST, "rewrite-owner.example.test")
                    .body(empty_http_body())?,
                &ctx,
            )
            .await;
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "protected PHP script must remain blocked via {uri}"
        );
    }
    assert_eq!(
        hits.load(Ordering::Acquire),
        hits_before,
        "PHP-FPM must never be invoked for protected/index.php via direct, dir, or try-files URL"
    );

    // 3. Rate-limited exact PHP index `/gated/index.php` is enforced via directory `/gated/`!
    let g1 = engine
        .handle_request(
            Request::builder()
                .uri("/gated/")
                .header(HOST, "rewrite-owner.example.test")
                .body(empty_http_body())?,
            &ctx,
        )
        .await;
    assert_eq!(g1.status(), StatusCode::OK);
    let g2 = engine
        .handle_request(
            Request::builder()
                .uri("/gated/")
                .header(HOST, "rewrite-owner.example.test")
                .body(empty_http_body())?,
            &ctx,
        )
        .await;
    assert_eq!(
        g2.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "directory index /gated/ must enforce /gated/index.php rate limit"
    );

    fcgi_task.abort();
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

/// Codex G9 (explicit PHP-first override): When a site defaults to HTML-first (`index "index.html"
/// "index.php"`), an explicit `static { index "index.php" "index.html" }` route override on a
/// directory containing BOTH `index.php` and `index.html` MUST use the unified directory-index
/// resolver and execute `index.php` via FastCGI instead of silently serving `index.html`.
#[tokio::test]
async fn g9_explicit_php_first_override_on_static_route_executes_php_over_html() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let fcgi_addr = listener.local_addr()?;
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_srv = Arc::clone(&hits);
    let fcgi_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let h = Arc::clone(&hits_srv);
            tokio::spawn(async move {
                let _ = serve_mock_fastcgi(stream, h).await;
            });
        }
    });

    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "miraserve-g9-php-override-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(root.join("php-override"))?;
    std::fs::create_dir_all(root.join("blocked-override"))?;
    std::fs::write(root.join("php-override/index.php"), b"<?php echo 'php'; ?>")?;
    std::fs::write(root.join("php-override/index.html"), b"<h1>html</h1>")?;
    std::fs::write(
        root.join("blocked-override/index.php"),
        b"<?php echo 'secret'; ?>",
    )?;
    std::fs::write(
        root.join("blocked-override/index.html"),
        b"<h1>blocked html</h1>",
    )?;

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/tmp/c.crt"; key "/tmp/c.key" }}
}}
site "override-php.example.test" {{
    root "{root}"
    index "index.html" "index.php"
    route "/blocked-override/index.php" {{
        static
    }}
    route "*.php" {{
        fastcgi-pass "tcp://{fcgi}"
    }}
    route "/php-override/*" {{
        static {{
            index "index.php" "index.html"
        }}
    }}
    route "/blocked-override/*" {{
        static {{
            index "index.php" "index.html"
        }}
    }}
}}
"#,
        root = root.display(),
        fcgi = fcgi_addr,
    );
    let (cfg, _) = parse_kdl("g9-php-override.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    let ctx = test_ctx();

    // 1. Explicit `static { index "index.php" "index.html" }` executes PHP over HTML when `*.php`
    //    owns `/php-override/index.php`.
    let r_php = engine
        .handle_request(
            Request::builder()
                .uri("/php-override/")
                .header(HOST, "override-php.example.test")
                .body(empty_http_body())?,
            &ctx,
        )
        .await;
    assert_eq!(r_php.status(), StatusCode::OK);
    let b_php = String::from_utf8(r_php.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(
        b_php.contains("SCRIPT_NAME=/php-override/index.php\n"),
        "explicit PHP-first static route override must execute index.php over index.html, got:\n{b_php}"
    );

    // 2. When an earlier route blocks `/blocked-override/index.php`, the unified route-ownership
    //    check refuses PHP execution (404) rather than bypassing via `*.php`.
    let r_blk = engine
        .handle_request(
            Request::builder()
                .uri("/blocked-override/")
                .header(HOST, "override-php.example.test")
                .body(empty_http_body())?,
            &ctx,
        )
        .await;
    assert_eq!(
        r_blk.status(),
        StatusCode::NOT_FOUND,
        "explicit PHP-first override must still honor an earlier blocking route on index.php"
    );

    fcgi_task.abort();
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

/// Codex Round-3 P2 #1 (G4): An internal `try-files` rewrite to a `PATH_INFO` URL
/// (`/alias` -> `/wp-login.php/extra`) matched by a wildcard FastCGI route (`*.php`) when an
/// earlier exact FastCGI route (`/wp-login.php`) owns the script MUST enforce BOTH the wildcard
/// route's rate limit AND exact-route parity — identically to a direct `/wp-login.php/extra`
/// request (with exact single-token accounting, no skipping and no double-charging).
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn g4_r3_p2_rewritten_path_info_enforces_wildcard_fastcgi_route_rate_limit_parity()
-> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let fcgi_addr = listener.local_addr()?;
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_srv = Arc::clone(&hits);
    let fcgi_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let h = Arc::clone(&hits_srv);
            tokio::spawn(async move {
                let _ = serve_mock_fastcgi(stream, h).await;
            });
        }
    });

    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "miraserve-g4-r3-rewrite-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("wp-login.php"), b"<?php echo 'login'; ?>")?;

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/tmp/c.crt"; key "/tmp/c.key" }}
}}
site "rewrite-parity.example.test" {{
    root "{root}"
    route "/wp-login.php" {{
        fastcgi-pass "tcp://{fcgi}"
    }}
    route "*.php" {{
        rate-limit requests=2 per="1m" burst=2
        fastcgi-pass "tcp://{fcgi}"
    }}
    route "/*" {{
        try-files "$uri" "/wp-login.php/extra"
    }}
}}
"#,
        root = root.display(),
        fcgi = fcgi_addr,
    );
    let (cfg, _) = parse_kdl("g4-r3-rewrite.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;

    let ctx_for_ip = |last_octet: u8| RequestContext {
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, last_octet))),
        remote_port: Some(40000 + u16::from(last_octet)),
        server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_port: 8443,
        is_https: true,
        tls: None,
    };

    // 1. Direct `/wp-login.php/extra` from IP .10: allowed twice (burst=2), blocked on 3rd.
    let direct_ctx = ctx_for_ip(10);
    for attempt in 1..=2 {
        let req = Request::builder()
            .method(Method::GET)
            .uri("/wp-login.php/extra")
            .header(HOST, "rewrite-parity.example.test")
            .body(empty_http_body())?;
        let resp = engine.handle_request(req, &direct_ctx).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "direct PATH_INFO attempt {attempt} must succeed (no double-charging)"
        );
        let body = String::from_utf8(resp.into_body().collect().await?.to_bytes().to_vec())?;
        assert!(
            body.contains("SCRIPT_NAME=/wp-login.php\n") && body.contains("PATH_INFO=/extra\n"),
            "direct PATH_INFO body mismatch:\n{body}"
        );
    }
    let direct_third = engine
        .handle_request(
            Request::builder()
                .method(Method::GET)
                .uri("/wp-login.php/extra")
                .header(HOST, "rewrite-parity.example.test")
                .body(empty_http_body())?,
            &direct_ctx,
        )
        .await;
    assert_eq!(
        direct_third.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "direct PATH_INFO 3rd request must hit *.php rate limit"
    );

    // 2. Rewritten `/alias` -> `/wp-login.php/extra` from fresh IP .20: MUST match direct parity
    //    (allowed twice for burst=2, blocked with 429 on 3rd — NEVER skipping *.php's rate limit!).
    let rewrite_ctx = ctx_for_ip(20);
    for attempt in 1..=2 {
        let req = Request::builder()
            .method(Method::GET)
            .uri("/alias")
            .header(HOST, "rewrite-parity.example.test")
            .body(empty_http_body())?;
        let resp = engine.handle_request(req, &rewrite_ctx).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "rewritten PATH_INFO attempt {attempt} must succeed (no double-charging)"
        );
        let body = String::from_utf8(resp.into_body().collect().await?.to_bytes().to_vec())?;
        assert!(
            body.contains("SCRIPT_NAME=/wp-login.php\n") && body.contains("PATH_INFO=/extra\n"),
            "rewritten PATH_INFO body mismatch:\n{body}"
        );
    }
    let rewrite_third = engine
        .handle_request(
            Request::builder()
                .method(Method::GET)
                .uri("/alias")
                .header(HOST, "rewrite-parity.example.test")
                .body(empty_http_body())?,
            &rewrite_ctx,
        )
        .await;
    assert_eq!(
        rewrite_third.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "rewritten PATH_INFO 3rd request must enforce *.php rate limit identically to direct requests"
    );

    fcgi_task.abort();
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

/// A HEAD answer from FastCGI has no body, with the length a GET would have (Cloudflare-skills
/// audit of v0.1.0, claim 10): HTTP/2 and HTTP/3 send whatever body the response holds.
#[tokio::test]
async fn fastcgi_head_has_no_body() -> TestResult {
    let fcgi_listener = TcpListener::bind("127.0.0.1:0").await?;
    let fcgi_addr = fcgi_listener.local_addr()?;
    let hits = Arc::new(AtomicUsize::new(0));
    let fcgi_task = tokio::spawn(async move {
        while let Ok((stream, _)) = fcgi_listener.accept().await {
            let h = Arc::clone(&hits);
            tokio::spawn(async move {
                let _ = serve_mock_fastcgi(stream, h).await;
            });
        }
    });
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root =
        std::env::temp_dir().join(format!("miraserve-php-head-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("script.php"), b"<?php echo 'ok';")?;
    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/tmp/c.crt"; key "/tmp/c.key" }}
}}
site "php.example.test" {{
    root "{}"
    route "*.php" {{
        fastcgi-pass "tcp://{fcgi_addr}"
    }}
}}
"#,
        root.display(),
    );
    let (cfg, _) = parse_kdl("php-head.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    let ctx = test_ctx();
    let mut lengths = Vec::new();
    for method in [Method::GET, Method::HEAD] {
        let req = Request::builder()
            .method(method.clone())
            .uri("/script.php")
            .header(HOST, "php.example.test")
            .body(empty_http_body())?;
        let resp = engine.handle_request(req, &ctx).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let declared = resp
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = resp.into_body().collect().await?.to_bytes();
        assert_eq!(body.is_empty(), method == Method::HEAD);
        lengths.push(declared);
    }
    let [get, head] = lengths.as_slice() else {
        return Err("two answers".into());
    };
    assert!(get.is_some());
    assert_eq!(get, head);
    fcgi_task.abort();
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

/// A backend that answers `/big.php` with `BIG_ANSWER` bytes, and `/broken.php` with the same
/// start but closes the connection before the end of the request.
const BIG_ANSWER: usize = 40 * 1024 * 1024;

async fn serve_big_fastcgi<S>(mut stream: S) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
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
    let broken = params
        .get("SCRIPT_NAME")
        .is_some_and(|name| name == "/broken.php");
    let mut answer =
        b"Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"backup.bin\"\r\n\r\n"
            .to_vec();
    let sent = if broken {
        BIG_ANSWER - 1024 * 1024
    } else {
        BIG_ANSWER
    };
    answer.extend((0..sent).map(|i| u8::try_from(i % 251).unwrap_or(0)));
    write_stream_records(&mut stream, RecordType::Stdout, req_id, &answer, !broken).await?;
    if !broken {
        let end = EndRequestBody {
            app_status: 0,
            protocol_status: 0,
        }
        .encode();
        write_record(&mut stream, RecordType::EndRequest, req_id, &end).await?;
    }
    stream.flush().await?;
    Ok(())
}

/// A PHP answer larger than what is buffered (32 MiB) is sent on as it comes instead of being
/// refused with 502, which is what v0.1.0 and v0.1.1 did (a download made by PHP: a backup, an
/// export). Every byte arrives once and in order; no length is claimed; HEAD has no body; and a
/// backend that fails on the way gives a broken transfer, not a short answer that looks whole.
#[tokio::test]
async fn fastcgi_answer_above_the_buffer_limit_is_streamed() -> TestResult {
    let fcgi_listener = TcpListener::bind("127.0.0.1:0").await?;
    let fcgi_addr = fcgi_listener.local_addr()?;
    let fcgi_task = tokio::spawn(async move {
        while let Ok((stream, _)) = fcgi_listener.accept().await {
            tokio::spawn(async move {
                let _ = serve_big_fastcgi(stream).await;
            });
        }
    });
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root =
        std::env::temp_dir().join(format!("miraserve-php-big-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("big.php"), b"<?php")?;
    std::fs::write(root.join("broken.php"), b"<?php")?;
    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/tmp/c.crt"; key "/tmp/c.key" }}
}}
site "php.example.test" {{
    root "{}"
    route "*.php" {{
        fastcgi-pass "tcp://{fcgi_addr}"
    }}
}}
"#,
        root.display(),
    );
    let (cfg, _) = parse_kdl("php-big.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    let ctx = test_ctx();
    let request = |method: Method, path: &str| {
        Request::builder()
            .method(method)
            .uri(path)
            .header(HOST, "php.example.test")
            .body(empty_http_body())
    };

    let resp = engine
        .handle_request(request(Method::GET, "/big.php")?, &ctx)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get(http::header::CONTENT_LENGTH).is_none());
    assert_eq!(
        resp.headers()
            .get(http::header::CONTENT_DISPOSITION)
            .and_then(|v| v.to_str().ok()),
        Some("attachment; filename=\"backup.bin\"")
    );
    let body = resp.into_body().collect().await?.to_bytes();
    assert_eq!(body.len(), BIG_ANSWER);
    assert!(
        body.iter()
            .enumerate()
            .all(|(i, byte)| *byte == u8::try_from(i % 251).unwrap_or(0))
    );
    drop(body);

    let resp = engine
        .handle_request(request(Method::HEAD, "/big.php")?, &ctx)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get(http::header::CONTENT_LENGTH).is_none());
    assert!(resp.into_body().collect().await?.to_bytes().is_empty());

    let resp = engine
        .handle_request(request(Method::GET, "/broken.php")?, &ctx)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.into_body().collect().await.is_err());

    // Nothing stays counted for the address afterwards: an ordinary answer still fits.
    let resp = engine
        .handle_request(request(Method::GET, "/big.php")?, &ctx)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.into_body().collect().await?.to_bytes().len(),
        BIG_ANSWER
    );

    fcgi_task.abort();
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

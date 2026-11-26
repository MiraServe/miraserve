//! Site rewrite rules: internal rewrites, redirects and denials with conditions, and the
//! guarantees that text taken from the request cannot leave the target the rule wrote, reach a
//! protected route, or choose a redirect host.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use http::header::{HOST, LOCATION};
use http::{Method, Request, StatusCode};
use http_body_util::BodyExt as _;
use miraserve_config::parse_kdl;
use miraserve_http::{HttpEngine, RequestContext, empty_http_body};
use miraserve_tls::AcmeChallengeStore;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Site {
    engine: HttpEngine,
    root: std::path::PathBuf,
}

fn site(tag: &str) -> Result<Site, Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!("miraserve-rw-{tag}-{}", std::process::id()));
    for dir in ["posts", "public", "admin", "app"] {
        std::fs::create_dir_all(root.join(dir))?;
    }
    std::fs::write(root.join("index.html"), b"FRONT")?;
    std::fs::write(root.join("posts/42.html"), b"POST 42")?;
    std::fs::write(root.join("public/a.txt"), b"PUBLIC A")?;
    std::fs::write(root.join("admin/secret.html"), b"ADMIN SECRET")?;
    std::fs::write(root.join("app/real.txt"), b"REAL FILE")?;
    std::fs::write(root.join("top-secret.txt"), b"TOP SECRET")?;
    std::fs::write(root.join("dump.sql"), b"SQL")?;
    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "rw.example.test" {{
    root "{}"
    rewrite {{
        rule "\\.(bak|sql)$" deny=403
        rule "^/blog/(\\d+)$" to="/posts/$1.html"
        rule "^/old/(.*)$" redirect="/new/$1"
        rule "^/moved$" redirect="https://other.example.test/landing" status=302 keep-query=#false
        rule "^/files/(.*)$" to="/public/$1"
        rule "^/sneak$" to="/admin/secret.html"
        rule "^/app/" to="/index.html" if-not-file=#true
        rule "^/only-post$" to="/index.html" method="POST"
        rule "^/preview$" to="/posts/42.html" query="^key=abc$"
        rule "^/ajax$" to="/public/a.txt" header="X-Requested-With=^XMLHttpRequest$"
        rule "^/host-only$" to="/index.html" host="other.example.test"
    }}
    route "/admin/*" {{ respond 403 }}
}}
"#,
        root.display()
    );
    let (cfg, _) = parse_kdl("rewrite.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    Ok(Site { engine, root })
}

async fn send(
    site: &Site,
    method: Method,
    uri: &str,
    extra: &[(&str, &str)],
) -> Result<(StatusCode, String, String), Box<dyn std::error::Error>> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(HOST, "rw.example.test");
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    let ctx = RequestContext {
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))),
        remote_port: Some(50_000),
        server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_port: 8443,
        is_https: true,
        tls: None,
    };
    let resp = site
        .engine
        .handle_request(builder.body(empty_http_body())?, &ctx)
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

#[tokio::test]
async fn rules_rewrite_redirect_and_deny_with_conditions() -> TestResult {
    let s = site("basic")?;
    let get = |uri: &'static str| send(&s, Method::GET, uri, &[]);

    // Internal rewrite with a capture; the visitor's address does not change (no Location).
    let (status, location, body) = get("/blog/42").await?;
    assert_eq!(
        (status, location.as_str(), body.as_str()),
        (StatusCode::OK, "", "POST 42")
    );
    assert_eq!(
        get("/blog/abc").await?.0,
        StatusCode::NOT_FOUND,
        "pattern is anchored"
    );

    // Redirect keeps the query by default; keep-query=#false drops it.
    let (status, location, _) = get("/old/a/b?x=1&y=2").await?;
    assert_eq!(
        (status, location.as_str()),
        (StatusCode::MOVED_PERMANENTLY, "/new/a/b?x=1&y=2")
    );
    let (status, location, _) = get("/moved?x=1").await?;
    assert_eq!(
        (status, location.as_str()),
        (StatusCode::FOUND, "https://other.example.test/landing")
    );

    // Deny comes first and wins.
    assert_eq!(get("/dump.sql").await?.0, StatusCode::FORBIDDEN);
    assert_eq!(get("/old/x.bak").await?.0, StatusCode::FORBIDDEN);

    // Front controller: only when nothing exists at the path.
    assert_eq!(get("/app/no/such/page").await?.2, "FRONT");
    assert_eq!(get("/app/real.txt").await?.2, "REAL FILE");

    // Conditions.
    assert_eq!(get("/only-post").await?.0, StatusCode::NOT_FOUND);
    assert_eq!(get("/preview?key=abc").await?.2, "POST 42");
    assert_eq!(get("/preview?key=wrong").await?.0, StatusCode::NOT_FOUND);
    assert_eq!(get("/ajax").await?.0, StatusCode::NOT_FOUND);
    let (status, _, body) = send(
        &s,
        Method::GET,
        "/ajax",
        &[("x-requested-with", "XMLHttpRequest")],
    )
    .await?;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "PUBLIC A"));
    assert_eq!(
        get("/host-only").await?.0,
        StatusCode::NOT_FOUND,
        "rule is for another host"
    );

    let _ = std::fs::remove_dir_all(&s.root);
    Ok(())
}

#[tokio::test]
async fn captured_text_cannot_escape_the_target_or_bypass_routes() -> TestResult {
    let s = site("safety")?;
    let get = |uri: &'static str| send(&s, Method::GET, uri, &[]);

    // The rewritten path goes through the routes: a rule cannot reach a protected route.
    let (status, _, body) = get("/sneak").await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(!body.contains("ADMIN SECRET"));

    assert_eq!(get("/files/a.txt").await?.2, "PUBLIC A");
    // Attempts to climb out of /public/ through the capture never serve the file above it.
    for uri in [
        "/files/../top-secret.txt",
        "/files/%2e%2e/top-secret.txt",
        "/files/..%2ftop-secret.txt",
        "/files/%252e%252e%252ftop-secret.txt",
        "/files//../top-secret.txt",
        "/files/a.txt/../../top-secret.txt",
    ] {
        let (status, _, body) = get(uri).await?;
        assert!(
            !body.contains("TOP SECRET"),
            "'{uri}' escaped the rule's target directory (status {status})"
        );
    }

    // Redirect: captured text is encoded and can neither end the path nor choose a host.
    for (uri, expected) in [
        ("/old/a%3Fb%23c", "/new/a%3Fb%23c"),
        // Duplicate slashes are collapsed by path normalisation before the rule runs.
        ("/old//evil.example/x", "/new/evil.example/x"),
        ("/old/a%0d%0aSet-Cookie:x", ""),
    ] {
        let (status, location, _) = get(uri).await?;
        if status == StatusCode::MOVED_PERMANENTLY {
            assert!(location.starts_with("/new/"), "'{uri}' -> '{location}'");
            if !expected.is_empty() {
                assert_eq!(location, expected, "{uri}");
            }
            assert!(!location.contains('\r') && !location.contains('\n'));
        } else {
            assert!(
                location.is_empty(),
                "'{uri}' got {status} with Location '{location}'"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&s.root);
    Ok(())
}

#[test]
fn unsafe_or_invalid_rules_are_rejected_by_the_config() {
    let config = |rule: &str| {
        format!(
            "server {{ listen \":8443\"; tls {{ cert \"/c.pem\"; key \"/k.pem\" }} }}\nsite \"a.example\" {{\n root \"/var/www/a\"\n rewrite {{\n  {rule}\n }}\n}}\n"
        )
    };
    for good in [
        r#"rule "^/a/(.*)$" to="/b/$1""#,
        r#"rule "^/a$" to="/index.php?route=a""#,
        r#"rule "^/a/(.*)$" redirect="https://example.com/x/$1" status=308"#,
        r#"rule "\\.env$" deny=404"#,
        r#"rule "^/(.*)$" to="/index.php" if-not-file=#true"#,
    ] {
        assert!(
            parse_kdl("good.kdl", &config(good)).is_ok(),
            "{good} must be accepted"
        );
    }
    for bad in [
        r#"rule "^/a/(.*)$" to="$1""#,  // target chosen by the request
        r#"rule "^/a/(.*)$" to="/$1""#, // could become //host
        r#"rule "^/a/(.*)$" to="//evil.example/$1""#,
        r#"rule "^/a/(.*)$" to="https://evil.example/$1""#, // internal must be a path
        r#"rule "^/a/(.*)$" redirect="https://$1/""#,       // host from the request
        r#"rule "^/a/(.*)$" redirect="https://x.$1.example/""#,
        r#"rule "^/a/(.*)$" redirect="//evil.example/""#,
        r#"rule "^/a$" to="/b/$2""#, // no such group
        r#"rule "^/a(" to="/b""#,    // bad pattern
        r#"rule "^/a$" redirect="/b" status=200"#,
        r#"rule "^/a$" deny=500"#,
        r#"rule "^/a$""#,                       // no action
        r#"rule "^/a$" to="/b" redirect="/c""#, // two actions
        r#"rule "^/a$" to="/b" query="(""#,
        r#"rule "^/a$" to="/b" header="=x""#,
        r#"rule "^/a$" to="/b" method="get""#,
        r#"rule "^/a$" to="/b c""#,
    ] {
        assert!(
            parse_kdl("bad.kdl", &config(bad)).is_err(),
            "{bad} must be rejected"
        );
    }
    // if-not-file needs a site root.
    let no_root = "server { listen \":8443\"; tls { cert \"/c.pem\"; key \"/k.pem\" } }\nsite \"a.example\" {\n rewrite { rule \"^/(.*)$\" to=\"/index.php\" if-not-file=#true }\n route \"/*\" { respond 404 }\n}\n";
    assert!(parse_kdl("no-root.kdl", no_root).is_err());
}

/// The front-controller pattern for PHP applications: a path with no file behind it is handed
/// to `index.php`, which still sees the visitor's original address in `REQUEST_URI` and the
/// rewritten script in `SCRIPT_NAME`.
#[tokio::test]
async fn front_controller_rewrite_runs_php_with_the_original_request_uri() -> TestResult {
    use std::collections::HashMap;

    use miraserve_fastcgi::protocol::{
        EndRequestBody, RecordType, decode_params, read_record, write_record, write_stream_records,
    };
    use tokio::io::AsyncWriteExt as _;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let fcgi = listener.local_addr()?;
    let backend = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut raw = Vec::new();
                let req_id = loop {
                    let Ok(rec) = read_record(&mut stream).await else {
                        return;
                    };
                    match rec.record_type {
                        RecordType::Params if !rec.content.is_empty() => {
                            raw.extend_from_slice(&rec.content);
                        }
                        RecordType::Stdin if rec.content.is_empty() => break rec.request_id,
                        _ => {}
                    }
                };
                let params: HashMap<String, String> = decode_params(&raw)
                    .map(|p| p.into_iter().collect())
                    .unwrap_or_default();
                let field = |k: &str| params.get(k).cloned().unwrap_or_default();
                let payload = format!(
                    "Content-Type: text/plain\r\n\r\nSCRIPT_NAME={} REQUEST_URI={} QUERY_STRING={}",
                    field("SCRIPT_NAME"),
                    field("REQUEST_URI"),
                    field("QUERY_STRING")
                );
                let _ = write_stream_records(
                    &mut stream,
                    RecordType::Stdout,
                    req_id,
                    payload.as_bytes(),
                    true,
                )
                .await;
                let end = EndRequestBody {
                    app_status: 0,
                    protocol_status: 0,
                }
                .encode();
                let _ = write_record(&mut stream, RecordType::EndRequest, req_id, &end).await;
                let _ = stream.flush().await;
            });
        }
    });

    let root = std::env::temp_dir().join(format!("miraserve-rw-php-{}", std::process::id()));
    std::fs::create_dir_all(root.join("assets"))?;
    std::fs::write(root.join("index.php"), b"<?php // front controller")?;
    std::fs::write(root.join("assets/site.css"), b"body{}")?;
    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "rw.example.test" {{
    root "{}"
    rewrite {{
        rule "^/(.*)$" to="/index.php" if-not-file=#true
    }}
    route "*.php" {{ fastcgi-pass "tcp://127.0.0.1:{}" }}
}}
"#,
        root.display(),
        fcgi.port()
    );
    let (cfg, _) = parse_kdl("rewrite-php.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    let s = Site { engine, root };

    let (status, _, body) = send(&s, Method::GET, "/products/blue-shoes?size=42", &[]).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        "SCRIPT_NAME=/index.php REQUEST_URI=/products/blue-shoes?size=42 QUERY_STRING=size=42"
    );
    // A real file is served as itself, not through the front controller.
    let (status, _, body) = send(&s, Method::GET, "/assets/site.css", &[]).await?;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "body{}"));

    backend.abort();
    let _ = std::fs::remove_dir_all(&s.root);
    Ok(())
}

/// Additions driven by 436 real `.htaccess` files: a file-only test (`!-f` alone), negated and
/// multiple conditions (hotlink protection), a `pass` action, and case-insensitive patterns.
#[tokio::test]
async fn file_only_test_negated_conditions_pass_and_case_insensitive_patterns() -> TestResult {
    let root = std::env::temp_dir().join(format!("miraserve-rw-ext-{}", std::process::id()));
    std::fs::create_dir_all(root.join("docs"))?;
    std::fs::create_dir_all(root.join("img"))?;
    std::fs::write(root.join("index.html"), b"FRONT")?;
    std::fs::write(root.join("docs/readme.txt"), b"README")?;
    std::fs::write(root.join("img/logo.png"), b"PNG")?;
    std::fs::write(root.join("keep.txt"), b"KEEP")?;
    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "rw.example.test" {{
    root "{}"
    rewrite {{
        rule "^/keep\\.txt$" pass=#true
        rule "(?i)\\.PNG$" deny=403 {{
            header "Referer" "."
            not-header "Referer" "^https://rw\\.example\\.test/"
        }}
        rule "^/api/" deny=404 {{
            not-query "(^|&)token="
        }}
        rule "^/" to="/index.html" if-not-regular-file=#true
    }}
}}
"#,
        root.display()
    );
    let (cfg, _) = parse_kdl("rewrite-ext.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    let s = Site { engine, root };
    let get = |uri: &'static str| send(&s, Method::GET, uri, &[]);

    // `!-f` alone: a directory is not a file, so it is rewritten too (if-not-file would not).
    assert_eq!(get("/docs/").await?.2, "FRONT");
    assert_eq!(get("/docs/readme.txt").await?.2, "README");
    assert_eq!(get("/no/such").await?.2, "FRONT");

    // pass: the list ends, the request is unchanged.
    assert_eq!(get("/keep.txt").await?.2, "KEEP");

    // Hotlink protection: Referer present AND not ours -> 403; ours or absent -> served.
    // The pattern is case-insensitive.
    let png = |referer: Option<&'static str>| {
        let s = &s;
        async move {
            match referer {
                Some(r) => send(s, Method::GET, "/img/logo.png", &[("referer", r)]).await,
                None => send(s, Method::GET, "/img/logo.png", &[]).await,
            }
        }
    };
    assert_eq!(
        png(Some("https://thief.example/page")).await?.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(png(Some("https://rw.example.test/gallery")).await?.2, "PNG");
    assert_eq!(png(None).await?.2, "PNG");

    // Negated query condition.
    assert_eq!(get("/api/items").await?.0, StatusCode::NOT_FOUND);
    assert_eq!(get("/api/items?token=abc").await?.2, "FRONT");

    let _ = std::fs::remove_dir_all(&s.root);
    Ok(())
}

#[test]
fn status_needs_redirect_and_303_is_allowed() {
    let config = |rule: &str| {
        format!(
            "server {{ listen \":8443\"; tls {{ cert \"/c.pem\"; key \"/k.pem\" }} }}\nsite \"a.example\" {{\n root \"/var/www/a\"\n rewrite {{\n  {rule}\n }}\n}}\n"
        )
    };
    assert!(
        parse_kdl(
            "s303.kdl",
            &config(r#"rule "^/a$" redirect="/b" status=303"#)
        )
        .is_ok()
    );
    assert!(parse_kdl("pass.kdl", &config(r#"rule "^/a$" pass=#true"#)).is_ok());
    assert!(parse_kdl("ci.kdl", &config(r#"rule "(?i)^/a$" to="/b""#)).is_ok());
    for bad in [
        r#"rule "^/a$" to="/b" status=301"#,
        r#"rule "^/a$" deny=403 status=403"#,
        r#"rule "^/a$" pass=#true to="/b""#,
        r#"rule "^/a$" to="/b" { header "Referer" }"#,
        r#"rule "^/a$" to="/b" { cookie "x" "y" }"#,
        r#"rule "^/a$" to="/b" { not-query "(" }"#,
    ] {
        assert!(
            parse_kdl("bad.kdl", &config(bad)).is_err(),
            "{bad} must be rejected"
        );
    }
}

/// A Markdown sibling is served only if it could have been requested itself: not when a route
/// or a `deny` rule covers its own path (Cloudflare-skills audit of v0.1.0, claim 2). The
/// Markdown made from a page is another representation: the page's validators do not answer
/// for it, and a page's 304 varies like its 200 (claim 20).
#[tokio::test]
async fn markdown_siblings_obey_routes_and_deny_rules() -> TestResult {
    let root = std::env::temp_dir().join(format!("miraserve-rw-md-{}", std::process::id()));
    for dir in ["docs", "notes", "open"] {
        std::fs::create_dir_all(root.join(dir))?;
    }
    for dir in ["docs", "notes", "open"] {
        std::fs::write(root.join(dir).join("page.html"), b"<h1>PAGE</h1>")?;
        std::fs::write(root.join(dir).join("page.md"), b"SECRET MARKDOWN")?;
    }
    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "rw.example.test" {{
    root "{}"
    rewrite {{
        rule "^/notes/.*\\.md$" deny=403
    }}
    route "/docs/page.md" {{ respond 403 }}
}}
"#,
        root.display()
    );
    let (cfg, _) = parse_kdl("md.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    let s = Site { engine, root };
    let md = [("accept", "text/markdown")];
    for dir in ["docs", "notes"] {
        let direct = send(&s, Method::GET, &format!("/{dir}/page.md"), &[]).await?;
        assert_eq!(direct.0, StatusCode::FORBIDDEN, "{dir}");
        let (status, _, body) = send(&s, Method::GET, &format!("/{dir}/page.html"), &md).await?;
        assert_eq!(status, StatusCode::OK, "{dir}");
        assert!(!body.contains("SECRET"), "{dir}: {body}");
        assert!(body.contains("PAGE"), "{dir}: {body}");
    }
    let (status, _, body) = send(&s, Method::GET, "/open/page.html", &md).await?;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "SECRET MARKDOWN"));

    // Validators of the HTML page.
    let page = Request::builder()
        .uri("/docs/page.html")
        .header(HOST, "rw.example.test");
    let ctx = RequestContext {
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))),
        remote_port: Some(50_000),
        server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_port: 8443,
        is_https: true,
        tls: None,
    };
    let first = s
        .engine
        .handle_request(page.body(empty_http_body())?, &ctx)
        .await;
    let header = |resp: &http::Response<_>, name: &str| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned()
    };
    let (etag, modified) = (header(&first, "etag"), header(&first, "last-modified"));
    assert_eq!(header(&first, "vary"), "Accept, Accept-Encoding");
    let conditional = |accept: Option<&'static str>| {
        let mut builder = Request::builder()
            .uri("/docs/page.html")
            .header(HOST, "rw.example.test")
            .header("if-modified-since", modified.clone());
        if !etag.is_empty() {
            builder = builder.header("if-none-match", etag.clone());
        }
        if let Some(accept) = accept {
            builder = builder.header("accept", accept);
        }
        builder.body(empty_http_body())
    };
    let html = s.engine.handle_request(conditional(None)?, &ctx).await;
    assert_eq!(html.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(header(&html, "vary"), "Accept, Accept-Encoding");
    let markdown = s
        .engine
        .handle_request(conditional(Some("text/markdown"))?, &ctx)
        .await;
    assert_eq!(markdown.status(), StatusCode::OK);
    assert!(header(&markdown, "content-type").starts_with("text/markdown"));
    let _ = std::fs::remove_dir_all(&s.root);
    Ok(())
}

/// Codex review 70: a sibling whose own path an internal rewrite sends elsewhere is not served
/// in the page's place (finding 10); a file that is not converted keeps its validators with a
/// Markdown `Accept` (finding 11); `try-files` hands a script index on only when a FastCGI route
/// runs that path, whatever its pattern (finding 16).
/// Which answer a Markdown request gets can depend on a rule on a request header, written
/// inline or as a condition: then neither the sibling nor what is served in its place is for
/// a shared cache (Codex 75, Antigravity 31).
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn markdown_answers_chosen_by_header_rules_stay_private() -> TestResult {
    for (n, rule) in [
        r#"rule "\\.md$" deny=403 header="Referer=^https://blocked\\.example/""#,
        r#"rule "\\.md$" deny=403 { header "Referer" "^https://blocked\\.example/" }"#,
    ]
    .into_iter()
    .enumerate()
    {
        let root = std::env::temp_dir().join(format!("miraserve-rw-mdh{n}-{}", std::process::id()));
        std::fs::create_dir_all(&root)?;
        std::fs::write(root.join("page.html"), b"<h1>PAGE</h1>")?;
        std::fs::write(root.join("page.md"), b"AUTHORED")?;
        let kdl = format!(
            r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "rw.example.test" {{
    root "{}"
    precompressed "all"
    rewrite {{
        {rule}
    }}
}}
"#,
            root.display()
        );
        let (cfg, _) = parse_kdl("mdh.kdl", &kdl)?;
        let engine =
            HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
        let ctx = RequestContext {
            client_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))),
            remote_port: Some(50_000),
            server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            server_port: 8443,
            is_https: true,
            tls: None,
        };
        for (referer, expected) in [
            ("https://rw.example.test/", "AUTHORED"),
            ("https://blocked.example/x", "PAGE"),
        ] {
            let req = Request::builder()
                .uri("/page.html")
                .header(HOST, "rw.example.test")
                .header("accept", "text/markdown")
                .header("referer", referer)
                .body(empty_http_body())?;
            let resp = engine.handle_request(req, &ctx).await;
            assert_eq!(resp.status(), StatusCode::OK, "{rule} {referer}");
            let cache = resp
                .headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();
            assert!(cache.contains("private"), "{rule} {referer}: {cache}");
            let body = resp.into_body().collect().await?.to_bytes();
            let body = String::from_utf8_lossy(&body);
            assert!(body.contains(expected), "{rule} {referer}: {body}");
        }
        // A page too large to convert that has a precompressed variant is served as that
        // variant (another file, with its own times), not refused as changing.
        let mut large = b"<h1>LARGE</h1>".to_vec();
        large.resize(1_100_000, b' ');
        std::fs::write(root.join("large.html"), &large)?;
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(root.join("large.html.gz"), b"not really gzip")?;
        let req = Request::builder()
            .uri("/large.html")
            .header(HOST, "rw.example.test")
            .header("accept", "text/markdown")
            .header("accept-encoding", "gzip")
            .body(empty_http_body())?;
        let resp = engine.handle_request(req, &ctx).await;
        assert_eq!(resp.status(), StatusCode::OK, "{rule}");
        let encoding = resp.headers().get("content-encoding");
        assert_eq!(
            encoding.map(http::HeaderValue::as_bytes),
            Some(&b"gzip"[..])
        );
        // And revalidated by that variant's tag (the 304 names no encoding).
        let tag = resp.headers().get("etag").cloned();
        if let Some(tag) = tag {
            let req = Request::builder()
                .uri("/large.html")
                .header(HOST, "rw.example.test")
                .header("accept", "text/markdown")
                .header("accept-encoding", "gzip")
                .header("if-none-match", tag)
                .body(empty_http_body())?;
            let resp = engine.handle_request(req, &ctx).await;
            assert_eq!(resp.status(), StatusCode::NOT_MODIFIED, "{rule}");
        }
        // A range beyond the page is refused as such.
        let req = Request::builder()
            .uri("/large.html")
            .header(HOST, "rw.example.test")
            .header("accept", "text/markdown")
            .header("range", "bytes=9000000-")
            .body(empty_http_body())?;
        let resp = engine.handle_request(req, &ctx).await;
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE, "{rule}");
        // Without Markdown asked for, the page is an ordinary public file.
        let req = Request::builder()
            .uri("/page.html")
            .header(HOST, "rw.example.test")
            .body(empty_http_body())?;
        let resp = engine.handle_request(req, &ctx).await;
        let cache = resp.headers().get("cache-control");
        assert!(
            cache.is_none_or(|v| !v.as_bytes().windows(7).any(|w| w == b"private")),
            "{rule}: {cache:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
    Ok(())
}

#[tokio::test]
async fn markdown_rewrites_validators_and_script_indexes() -> TestResult {
    let root = std::env::temp_dir().join(format!("miraserve-rw-c70-{}", std::process::id()));
    for dir in ["wiki", "files", "plain", "app", "multi"] {
        std::fs::create_dir_all(root.join(dir))?;
    }
    for name in ["old.php", "live.php", "index.html"] {
        std::fs::write(root.join("multi").join(name), b"x")?;
    }
    // Above the conversion limit: sent as it is.
    std::fs::write(root.join("wiki/big.html"), vec![b'a'; 1024 * 1024 + 10])?;
    std::fs::write(root.join("wiki/page.html"), b"<h1>WIKI</h1>")?;
    std::fs::write(root.join("wiki/page.md"), b"RAW SOURCE")?;
    std::fs::write(root.join("files/doc.pdf"), b"%PDF-1.7 not really")?;
    for dir in ["legacy", "gone", "off"] {
        std::fs::create_dir_all(root.join(dir))?;
    }
    for dir in ["plain", "app", "legacy", "gone", "off"] {
        std::fs::write(root.join(dir).join("index.php"), b"<?php echo 1;")?;
        std::fs::write(root.join(dir).join("index.html"), b"HTML INDEX")?;
    }
    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "rw.example.test" {{
    root "{root}"
    index "old.php" "live.php" "index.php" "index.html"
    rewrite {{
        rule "^/wiki/(.*)\\.md$" to="/wiki/$1.html"
    }}
    route "/app/" {{
        try-files "{{path}}" "{{path}}/" "=404"
    }}
    route "/app/*" {{
        fastcgi-pass "tcp://127.0.0.1:9"
    }}
    route "/run.php" {{
        fastcgi-pass "tcp://127.0.0.1:9"
    }}
    route "/plain/*" {{
        try-files "{{path}}" "{{path}}/" "=404"
    }}
    route "/legacy/index.php" {{ respond 410 }}
    route "/gone/index.php" {{
        try-files "{{path}}" "=410"
    }}
    route "/off/index.php" {{
        static
    }}
    route "/off/*" {{
        try-files "{{path}}" "{{path}}/" "=404"
    }}
    route "/gone/*" {{
        try-files "{{path}}" "{{path}}/" "=404"
    }}
    route "/legacy/*" {{
        try-files "{{path}}" "{{path}}/" "=404"
    }}
    route "/multi/live.php" {{
        fastcgi-pass "tcp://127.0.0.1:9"
    }}
    route "/multi/*" {{
        try-files "{{path}}" "{{path}}/" "=404"
    }}
}}
"#,
        root = root.display()
    );
    let (cfg, _) = parse_kdl("c70.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    let s = Site { engine, root };
    let md = [("accept", "text/markdown")];

    let (status, _, body) = send(&s, Method::GET, "/wiki/page.html", &md).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("WIKI") && !body.contains("RAW SOURCE"),
        "{body}"
    );

    // The site's own static files serve /wiki and /files (no route takes them), so these go
    // through the Markdown negotiation.
    // A PDF is not converted: a matching validator still answers 304.
    let ctx = RequestContext {
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))),
        remote_port: Some(50_000),
        server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_port: 8443,
        is_https: true,
        tls: None,
    };
    let pdf = |path: &'static str, validator: Option<String>| {
        let mut builder = Request::builder()
            .uri(path)
            .header(HOST, "rw.example.test")
            .header("accept", "text/markdown, */*;q=0.5");
        if let Some(modified) = validator {
            builder = builder.header("if-modified-since", modified);
        }
        builder.body(empty_http_body())
    };
    // Neither is a page above the conversion limit. The Markdown made from a page has no
    // validator of its own (whether a request gets it also depends on a free conversion
    // slot), so it carries no date and a date sent with the request does not apply to it.
    let page = s
        .engine
        .handle_request(pdf("/wiki/page.html", None)?, &ctx)
        .await;
    assert_eq!(page.status(), StatusCode::OK);
    assert!(page.headers().get("last-modified").is_none());
    assert!(page.headers().get("etag").is_none());
    let dated = pdf(
        "/wiki/page.html",
        Some("Sun, 01 Jan 2040 00:00:00 GMT".to_owned()),
    )?;
    let page = s.engine.handle_request(dated, &ctx).await;
    assert_eq!(page.status(), StatusCode::OK);
    for (path, revalidated) in [
        ("/files/doc.pdf", StatusCode::NOT_MODIFIED),
        ("/wiki/big.html", StatusCode::NOT_MODIFIED),
    ] {
        let first = s.engine.handle_request(pdf(path, None)?, &ctx).await;
        assert_eq!(first.status(), StatusCode::OK, "{path}");
        let modified = first
            .headers()
            .get("last-modified")
            .and_then(|v| v.to_str().ok())
            .ok_or("last-modified")?
            .to_owned();
        let again = s
            .engine
            .handle_request(pdf(path, Some(modified))?, &ctx)
            .await;
        assert_eq!(again.status(), revalidated, "{path}");
    }

    // No route runs /plain/index.php: the next index is served. /app/ is a try-files route
    // and /app/* a FastCGI route (a prefix pattern), which runs /app/index.php: the script
    // index is handed to it (nothing listens there: 502 or 504).
    let (status, _, body) = send(&s, Method::GET, "/plain/", &[]).await?;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "HTML INDEX"));
    let (status, _, body) = send(&s, Method::GET, "/app/", &[]).await?;
    assert!(status.is_server_error(), "{status}");
    assert!(!body.contains("HTML INDEX"));
    // Of several script indexes the one a route runs is chosen, not the first nor none
    // (Codex 71 finding 7).
    let (status, _, _) = send(&s, Method::GET, "/multi/", &[]).await?;
    assert!(status.is_server_error(), "{status}");
    // A script index with a route of its own that is not FastCGI (a reverse proxy, here a
    // fixed answer) is that route's, as in v0.1.0 (Codex 80).
    let (status, _, body) = send(&s, Method::GET, "/legacy/", &[]).await?;
    assert_eq!(status, StatusCode::GONE);
    assert!(!body.contains("HTML INDEX"));
    // Also when that route is another `try-files` route (Codex 86): the directory answers
    // as the script's own path does, as in v0.1.0. (A `try-files` route refuses a script's
    // path with 404 before it looks at its candidates, in v0.1.0 as now.)
    let direct = send(&s, Method::GET, "/gone/index.php", &[]).await?;
    let (status, _, body) = send(&s, Method::GET, "/gone/", &[]).await?;
    assert_eq!(
        (status, direct.0),
        (StatusCode::NOT_FOUND, StatusCode::NOT_FOUND)
    );
    assert!(!body.contains("HTML INDEX"));
    // And when it is a plain file route, the way a single script is switched off
    // (Antigravity 43): the directory is refused like the script, as in v0.1.0.
    let direct = send(&s, Method::GET, "/off/index.php", &[]).await?;
    let (status, _, body) = send(&s, Method::GET, "/off/", &[]).await?;
    assert_eq!(
        (status, direct.0),
        (StatusCode::NOT_FOUND, StatusCode::NOT_FOUND)
    );
    assert!(!body.contains("HTML INDEX"));
    let _ = std::fs::remove_dir_all(&s.root);
    Ok(())
}

/// Codex review 72: a range of a Markdown sibling comes from the sibling (finding 4); a
/// converted page has no validator, so a specific `If-Match` fails (finding 5); HEAD answers
/// for the whole file (finding 6); an `.shtml` page's 304 varies with `Accept` like its 200
/// (finding 7).
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn markdown_ranges_preconditions_and_head() -> TestResult {
    let root = std::env::temp_dir().join(format!("miraserve-rw-c72-{}", std::process::id()));
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("both.html"), vec![b'h'; 1024 * 1024 + 10])?;
    std::fs::write(root.join("both.md"), b"MARKDOWN SIBLING")?;
    std::fs::write(root.join("small.html"), b"<p>small</p>")?;
    std::fs::write(root.join("big.html"), vec![b'b'; 1024 * 1024 + 10])?;
    std::fs::write(root.join("inc.shtml"), b"<p>shtml</p>")?;
    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "rw.example.test" {{
    root "{}"
}}
"#,
        root.display()
    );
    let (cfg, _) = parse_kdl("c72.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    let s = Site { engine, root };
    let ctx = RequestContext {
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))),
        remote_port: Some(50_000),
        server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_port: 8443,
        is_https: true,
        tls: None,
    };
    let ask = |method: Method, path: &'static str, extra: Vec<(&'static str, String)>| {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header(HOST, "rw.example.test");
        for (name, value) in extra {
            builder = builder.header(name, value);
        }
        builder.body(empty_http_body())
    };
    let markdown = || ("accept", "text/markdown".to_owned());
    let header = |resp: &http::Response<_>, name: &str| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned()
    };

    // A range of the sibling.
    let ranged = ask(
        Method::GET,
        "/both.html",
        vec![markdown(), ("range", "bytes=0-7".to_owned())],
    )?;
    let resp = s.engine.handle_request(ranged, &ctx).await;
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    let body = resp.into_body().collect().await?.to_bytes();
    assert_eq!(&body[..], b"MARKDOWN");

    // A converted page and `If-Match`.
    let stale = ask(
        Method::GET,
        "/small.html",
        vec![markdown(), ("if-match", "\"obsolete\"".to_owned())],
    )?;
    let resp = s.engine.handle_request(stale, &ctx).await;
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);

    // HEAD of a page that is sent as it is, with a range.
    let head = ask(
        Method::HEAD,
        "/big.html",
        vec![markdown(), ("range", "bytes=0-0".to_owned())],
    )?;
    let resp = s.engine.handle_request(head, &ctx).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(header(&resp, "content-range"), "");

    // An extensionless file that may have a sibling varies with `Accept` on its 200 (Codex 73
    // finding 7); HEAD of a sibling ignores a range (finding 3).
    std::fs::write(s.root.join("guide"), b"plain guide")?;
    std::fs::write(s.root.join("guide.md"), b"GUIDE MARKDOWN")?;
    let plain = s
        .engine
        .handle_request(ask(Method::GET, "/guide", Vec::new())?, &ctx)
        .await;
    assert_eq!(plain.status(), StatusCode::OK);
    assert_eq!(header(&plain, "vary"), "Accept, Accept-Encoding");
    let head = ask(
        Method::HEAD,
        "/guide",
        vec![markdown(), ("range", "bytes=0-3".to_owned())],
    )?;
    let resp = s.engine.handle_request(head, &ctx).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(header(&resp, "content-range"), "");

    // `.shtml`: 200 and 304 vary alike.
    let first = s
        .engine
        .handle_request(ask(Method::GET, "/inc.shtml", Vec::new())?, &ctx)
        .await;
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(header(&first, "vary"), "Accept, Accept-Encoding");
    let modified = header(&first, "last-modified");
    let again = ask(
        Method::GET,
        "/inc.shtml",
        vec![("if-modified-since", modified)],
    )?;
    let resp = s.engine.handle_request(again, &ctx).await;
    assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(header(&resp, "vary"), "Accept, Accept-Encoding");
    // A range beyond the sibling: its refusal comes with the site's page for it, as for
    // the file asked for by its own name and as v0.1.0 did (Codex 88).
    let beyond = [("accept", "text/markdown"), ("range", "bytes=16-")];
    let (status, _, body) = send(&s, Method::GET, "/both.html", &beyond).await?;
    assert_eq!(status, StatusCode::RANGE_NOT_SATISFIABLE);
    assert_ne!(body, "");
    let own = send(&s, Method::GET, "/both.md", &[("range", "bytes=16-")]).await?;
    assert_eq!(
        (own.0, own.2.is_empty()),
        (StatusCode::RANGE_NOT_SATISFIABLE, false)
    );
    let _ = std::fs::remove_dir_all(&s.root);
    Ok(())
}

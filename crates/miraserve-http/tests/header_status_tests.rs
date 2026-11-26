//! Tests for status-conditioned response header rules (`headers { set|add|remove ... status="..." }`)
//! and route-header ownership on `try-files` fallbacks and internal rewrites (Rule (b)).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use base64::Engine as _;
use bytes::Bytes;
use http::header::{
    ALT_SVC, AUTHORIZATION, CACHE_CONTROL, ETAG, HOST, HeaderMap, HeaderValue, IF_MODIFIED_SINCE,
    IF_NONE_MATCH, LAST_MODIFIED, RANGE, RETRY_AFTER, STRICT_TRANSPORT_SECURITY, WWW_AUTHENTICATE,
};
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use miraserve_config::parse_kdl;
use miraserve_http::{HttpEngine, RequestContext, empty_http_body};
use miraserve_tls::AcmeChallengeStore;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::watch;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SITE_HOST: &str = "assets.example.test";
const IMMUTABLE: &str = "public, max-age=31536000, immutable";

fn https_ctx() -> RequestContext {
    RequestContext {
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 40))),
        remote_port: Some(54_000),
        server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_port: 8443,
        is_https: true,
        tls: None,
    }
}

fn plain_http_ctx() -> RequestContext {
    RequestContext {
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 41))),
        remote_port: Some(54_001),
        server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_port: 8080,
        is_https: false,
        tls: None,
    }
}

fn build_engine(
    root: &Path,
    site_body: &str,
    alt_svc_port: Option<u16>,
) -> Result<Arc<HttpEngine>, Box<dyn std::error::Error>> {
    let kdl = format!(
        r#"
server {{
    listen ":8443"
    listen ":8080" redirect-https=#true
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "{SITE_HOST}" {{
    root "{root}"
{site_body}
}}
"#,
        root = root.to_string_lossy().replace('\\', "/"),
    );
    let (cfg, _) = parse_kdl("header-status.kdl", &kdl)?;
    Ok(Arc::new(HttpEngine::from_config(
        &cfg,
        Arc::new(AcmeChallengeStore::new()),
        alt_svc_port,
        8443,
    )?))
}

async fn send(
    engine: &HttpEngine,
    ctx: &RequestContext,
    method: Method,
    uri: &str,
    extra: &[(&str, &str)],
) -> Result<(StatusCode, HeaderMap, Bytes), Box<dyn std::error::Error>> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(HOST, SITE_HOST);
    for &(name, value) in extra {
        builder = builder.header(name, value);
    }
    let resp = engine
        .handle_request(builder.body(empty_http_body())?, ctx)
        .await;
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await?.to_bytes();
    Ok((status, headers, body))
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn asset_route_304_head_206_404_and_spa_fallback_with_site_no_cache() -> TestResult {
    let root = std::env::temp_dir().join(format!(
        "miraserve-hdr-status-spa-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("assets"))?;
    std::fs::create_dir_all(root.join("static-assets"))?;
    std::fs::write(root.join("index.html"), b"<html>SPA SHELL</html>")?;
    std::fs::write(root.join("assets/app.abcdef.js"), b"console.log('asset');")?;
    std::fs::write(
        root.join("static-assets/logo.svg"),
        b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>",
    )?;

    // Case A: site-level `set "cache-control" "no-cache"` + asset route with `status="200 206 304"`
    // and NO route owning `/index.html` (site default static produces the fallback).
    let engine_site_default = build_engine(
        &root,
        r#"
    headers {
        set "cache-control" "no-cache"
    }
    route "/static-assets/*" {
        static
        headers {
            set "cache-control" "public, max-age=31536000, immutable" status="200 206 304"
            set "x-asset-only" "yes" status="200 206 304"
        }
    }
    route "/assets/*" {
        try-files "{path}" "/index.html"
        headers {
            set "cache-control" "public, max-age=31536000, immutable" status="200 206 304"
            set "x-asset-route" "r1"
        }
    }
"#,
        None,
    )?;
    let ctx = https_ctx();

    // 1. 200 GET on existing asset gets `immutable`.
    let (st, hdrs, body) = send(
        &engine_site_default,
        &ctx,
        Method::GET,
        "/assets/app.abcdef.js",
        &[],
    )
    .await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(header_str(&hdrs, "cache-control"), Some(IMMUTABLE));
    assert_eq!(header_str(&hdrs, "x-asset-route"), Some("r1"));
    assert_eq!(body.as_ref(), b"console.log('asset');");

    // 2. Panel-named test: 304 carries the EXACT same Cache-Control as 200.
    //    Use `If-Modified-Since` for cross-platform coverage (Windows deliberately omits `ETag`),
    //    and additionally verify `If-None-Match` where the platform emits `ETag`.
    let last_modified = hdrs
        .get(LAST_MODIFIED)
        .and_then(|v| v.to_str().ok())
        .ok_or("expected Last-Modified on 200 asset")?
        .to_owned();
    let (st304_ims, hdrs304_ims, body304_ims) = send(
        &engine_site_default,
        &ctx,
        Method::GET,
        "/assets/app.abcdef.js",
        &[("if-modified-since", &last_modified)],
    )
    .await?;
    assert_eq!(st304_ims, StatusCode::NOT_MODIFIED);
    assert_eq!(
        header_str(&hdrs304_ims, "cache-control"),
        Some(IMMUTABLE),
        "304 (If-Modified-Since) must carry the exact same Cache-Control as 200"
    );
    assert_eq!(header_str(&hdrs304_ims, "x-asset-route"), Some("r1"));
    assert!(body304_ims.is_empty());

    #[cfg(unix)]
    assert!(hdrs.get(ETAG).is_some(), "Unix builds must emit ETag");
    if let Some(etag) = hdrs.get(ETAG).and_then(|v| v.to_str().ok()) {
        let (st304, hdrs304, body304) = send(
            &engine_site_default,
            &ctx,
            Method::GET,
            "/assets/app.abcdef.js",
            &[("if-none-match", etag)],
        )
        .await?;
        assert_eq!(st304, StatusCode::NOT_MODIFIED);
        assert_eq!(
            header_str(&hdrs304, "cache-control"),
            Some(IMMUTABLE),
            "304 (If-None-Match) must carry the exact same Cache-Control as 200"
        );
        assert_eq!(header_str(&hdrs304, "x-asset-route"), Some("r1"));
        assert!(body304.is_empty());
    }

    // 3. Panel-named test: HEAD gets the EXACT same Cache-Control as GET.
    let (st_head, hdrs_head, body_head) = send(
        &engine_site_default,
        &ctx,
        Method::HEAD,
        "/assets/app.abcdef.js",
        &[],
    )
    .await?;
    assert_eq!(st_head, StatusCode::OK);
    assert_eq!(header_str(&hdrs_head, "cache-control"), Some(IMMUTABLE));
    assert_eq!(header_str(&hdrs_head, "x-asset-route"), Some("r1"));
    assert!(body_head.is_empty());

    // 4. 206 Partial Content gets `immutable`.
    let (st206, hdrs206, body206) = send(
        &engine_site_default,
        &ctx,
        Method::GET,
        "/assets/app.abcdef.js",
        &[("range", "bytes=0-6")],
    )
    .await?;
    assert_eq!(st206, StatusCode::PARTIAL_CONTENT);
    assert_eq!(header_str(&hdrs206, "cache-control"), Some(IMMUTABLE));
    assert_eq!(body206.as_ref(), b"console");

    // 5. Missing file under static asset route answers 404 WITHOUT `immutable` (site `no-cache` wins).
    let (st404, hdrs404, _) = send(
        &engine_site_default,
        &ctx,
        Method::GET,
        "/static-assets/missing.svg",
        &[],
    )
    .await?;
    assert_eq!(st404, StatusCode::NOT_FOUND);
    assert_eq!(header_str(&hdrs404, "cache-control"), Some("no-cache"));
    assert!(hdrs404.get("x-asset-only").is_none());

    // 6. Rule (b): SPA fallback (`try-files "{path}" "/index.html"`) for a missing asset under
    //    `/assets/*` serves `/index.html` (200) and MUST NOT inherit ANY rule from `/assets/*`
    //    (neither conditioned `Cache-Control: immutable` nor unconditional `X-Asset-Route: r1`);
    //    site-level `set "cache-control" "no-cache"` applies!
    let (st_fb, hdrs_fb, body_fb) = send(
        &engine_site_default,
        &ctx,
        Method::GET,
        "/assets/does-not-exist.js",
        &[],
    )
    .await?;
    assert_eq!(st_fb, StatusCode::OK);
    assert_eq!(body_fb.as_ref(), b"<html>SPA SHELL</html>");
    assert_eq!(
        header_str(&hdrs_fb, "cache-control"),
        Some("no-cache"),
        "SPA fallback must inherit site no-cache, never asset route immutable"
    );
    assert!(
        hdrs_fb.get("x-asset-route").is_none(),
        "SPA fallback must not inherit unconditional headers from originating asset route"
    );

    // 7. Direct request to `/index.html` also gets site `no-cache`.
    let (st_idx, hdrs_idx, _) =
        send(&engine_site_default, &ctx, Method::GET, "/index.html", &[]).await?;
    assert_eq!(st_idx, StatusCode::OK);
    assert_eq!(header_str(&hdrs_idx, "cache-control"), Some("no-cache"));

    // Case B: Rule (b) when a second route R2 owns `/index.html`.
    let engine_two_routes = build_engine(
        &root,
        r#"
    headers {
        set "cache-control" "no-cache"
    }
    route "/assets/*" {
        try-files "{path}" "/index.html"
        headers {
            set "cache-control" "public, max-age=31536000, immutable" status="200 206 304"
            set "x-asset-route" "r1"
        }
    }
    route "/*" {
        try-files "{path}" "/index.html"
        headers {
            set "x-owner" "r2-shell"
        }
    }
"#,
        None,
    )?;

    let (st_r2, hdrs_r2, body_r2) = send(
        &engine_two_routes,
        &ctx,
        Method::GET,
        "/assets/missing.js",
        &[],
    )
    .await?;
    assert_eq!(st_r2, StatusCode::OK);
    assert_eq!(body_r2.as_ref(), b"<html>SPA SHELL</html>");
    assert_eq!(header_str(&hdrs_r2, "cache-control"), Some("no-cache"));
    assert_eq!(header_str(&hdrs_r2, "x-owner"), Some("r2-shell"));
    assert!(hdrs_r2.get("x-asset-route").is_none());

    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

#[tokio::test]
async fn header_rule_status_classes_and_actions_set_add_remove() -> TestResult {
    let root = std::env::temp_dir().join(format!(
        "miraserve-hdr-classes-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("ok.txt"), b"hello world")?;

    let engine = build_engine(
        &root,
        r#"
    headers {
        set "x-always" "every"
        set "x-removable" "present"
        set "x-2xx" "ok" status="2xx"
        add "x-3xx" "redir" status="3xx"
        remove "x-removable" status="4xx"
        set "x-5xx" "err" status="5xx"
        set "x-mixed" "hit" status="2xx 304"
    }
    route "/go" {
        redirect "/ok.txt" status=301
    }
    route "/down" {
        respond 503
    }
"#,
        None,
    )?;
    let ctx = https_ctx();

    // 200 OK
    let (st200, h200, _) = send(&engine, &ctx, Method::GET, "/ok.txt", &[]).await?;
    assert_eq!(st200, StatusCode::OK);
    assert_eq!(header_str(&h200, "x-always"), Some("every"));
    assert_eq!(header_str(&h200, "x-removable"), Some("present"));
    assert_eq!(header_str(&h200, "x-2xx"), Some("ok"));
    assert!(h200.get("x-3xx").is_none());
    assert!(h200.get("x-5xx").is_none());
    assert_eq!(header_str(&h200, "x-mixed"), Some("hit"));

    // 304 Not Modified (matches 3xx and explicit 304 in mixed, NOT 2xx).
    // Cross-platform via `If-Modified-Since`; additionally via `If-None-Match` where ETag exists.
    let last_modified = h200
        .get(LAST_MODIFIED)
        .and_then(|v| v.to_str().ok())
        .ok_or("missing last-modified")?
        .to_owned();
    let (st304_ims, h304_ims, _) = send(
        &engine,
        &ctx,
        Method::GET,
        "/ok.txt",
        &[("if-modified-since", &last_modified)],
    )
    .await?;
    assert_eq!(st304_ims, StatusCode::NOT_MODIFIED);
    assert_eq!(header_str(&h304_ims, "x-always"), Some("every"));
    assert!(h304_ims.get("x-2xx").is_none());
    assert_eq!(header_str(&h304_ims, "x-3xx"), Some("redir"));
    assert_eq!(header_str(&h304_ims, "x-mixed"), Some("hit"));

    #[cfg(unix)]
    assert!(h200.get(ETAG).is_some(), "Unix builds must emit ETag");
    if let Some(etag) = h200.get(ETAG).and_then(|v| v.to_str().ok()) {
        let (st304, h304, _) = send(
            &engine,
            &ctx,
            Method::GET,
            "/ok.txt",
            &[("if-none-match", etag)],
        )
        .await?;
        assert_eq!(st304, StatusCode::NOT_MODIFIED);
        assert_eq!(header_str(&h304, "x-always"), Some("every"));
        assert!(h304.get("x-2xx").is_none());
        assert_eq!(header_str(&h304, "x-3xx"), Some("redir"));
        assert_eq!(header_str(&h304, "x-mixed"), Some("hit"));
    }

    // 301 Redirect (matches 3xx, NOT 2xx or "2xx 304")
    let (st301, h301, _) = send(&engine, &ctx, Method::GET, "/go", &[]).await?;
    assert_eq!(st301, StatusCode::MOVED_PERMANENTLY);
    assert_eq!(header_str(&h301, "x-always"), Some("every"));
    assert!(h301.get("x-2xx").is_none());
    assert_eq!(header_str(&h301, "x-3xx"), Some("redir"));
    assert!(h301.get("x-mixed").is_none());

    // 404 Not Found (4xx removes x-removable)
    let (st404, h404, _) = send(&engine, &ctx, Method::GET, "/nope", &[]).await?;
    assert_eq!(st404, StatusCode::NOT_FOUND);
    assert_eq!(header_str(&h404, "x-always"), Some("every"));
    assert!(h404.get("x-removable").is_none());
    assert!(h404.get("x-2xx").is_none());
    assert!(h404.get("x-5xx").is_none());

    // 503 Service Unavailable (matches 5xx, NOT 4xx so x-removable stays)
    let (st503, h503, _) = send(&engine, &ctx, Method::GET, "/down", &[]).await?;
    assert_eq!(st503, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(header_str(&h503, "x-always"), Some("every"));
    assert_eq!(header_str(&h503, "x-removable"), Some("present"));
    assert_eq!(header_str(&h503, "x-5xx"), Some("err"));

    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn server_owned_headers_and_plain_http_stripping_remain_protected() -> TestResult {
    let base = std::env::temp_dir().join(format!(
        "miraserve-hdr-protect-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let root = base.join("www");
    let auth_dir = base.join("auth");
    std::fs::create_dir_all(root.join("assets"))?;
    std::fs::create_dir_all(&auth_dir)?;
    std::fs::write(root.join("index.html"), b"HOME")?;
    std::fs::write(root.join("assets/a.js"), b"JS")?;
    let users = auth_dir.join("users");
    std::fs::write(&users, format!("alice:{}\n", bcrypt::hash("pw", 4)?))?;

    // 1. HTTPS with Alt-Svc, Basic Auth (401), and Rate Limit (429):
    //    Status-conditioned rules MUST NOT overwrite or remove server-owned fields.
    let engine = build_engine(
        &root,
        &format!(
            r#"
    http "serve"
    basic-auth "{users}" realm="Vault"
    headers {{
        remove "www-authenticate" status="401"
        set "www-authenticate" "Basic realm=\"Spoof\"" status="4xx"
        remove "alt-svc" status="200 401 429"
        set "alt-svc" "h3=\":9999\"" status="2xx"
        remove "retry-after" status="429"
        set "retry-after" "9999" status="4xx"
        set "strict-transport-security" "max-age=63072000" status="200 403"
        set "x-plain-ok" "1" status="200 304"
    }}
    route "/limited" {{
        rate-limit requests=1 per="1m" burst=1
        static
    }}
"#,
            users = users.to_string_lossy().replace('\\', "/"),
        ),
        Some(8443),
    )?;

    let https = https_ctx();
    let (st401, h401, _) = send(&engine, &https, Method::GET, "/index.html", &[]).await?;
    assert_eq!(st401, StatusCode::UNAUTHORIZED);
    assert_eq!(
        h401.get(WWW_AUTHENTICATE).and_then(|v| v.to_str().ok()),
        Some("Basic realm=\"Vault\", charset=\"UTF-8\""),
        "401 challenge must survive status-conditioned header rules"
    );
    assert_eq!(
        h401.get(ALT_SVC).and_then(|v| v.to_str().ok()),
        Some("h3=\":8443\"; ma=86400"),
        "Alt-Svc must survive status-conditioned header rules on HTTPS"
    );

    // Authenticated request hits rate-limited route twice -> 2nd gets 429 with real Retry-After.
    let token = base64::engine::general_purpose::STANDARD.encode("alice:pw");
    let auth_header = format!("Basic {token}");
    let (st_ok, h_ok, _) = send(
        &engine,
        &https,
        Method::GET,
        "/limited",
        &[(AUTHORIZATION.as_str(), &auth_header)],
    )
    .await?;
    assert_eq!(st_ok, StatusCode::NOT_FOUND);
    assert_eq!(
        h_ok.get(ALT_SVC).and_then(|v| v.to_str().ok()),
        Some("h3=\":8443\"; ma=86400")
    );
    let (st429, h429, _) = send(
        &engine,
        &https,
        Method::GET,
        "/limited",
        &[(AUTHORIZATION.as_str(), &auth_header)],
    )
    .await?;
    assert_eq!(st429, StatusCode::TOO_MANY_REQUESTS);
    let retry = h429
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .ok_or("missing Retry-After on 429")?;
    assert_ne!(
        retry, "9999",
        "server throttle Retry-After must survive status-conditioned header rules"
    );

    // 2. Plain HTTP (`http "serve"`, default `credentials=#false`):
    //    403 must strip WWW-Authenticate, HSTS, and Alt-Svc even when status="4xx"/"403" sets them.
    let plain = plain_http_ctx();
    let (st403, h403, _) = send(&engine, &plain, Method::GET, "/index.html", &[]).await?;
    assert_eq!(st403, StatusCode::FORBIDDEN);
    assert!(
        h403.get(WWW_AUTHENTICATE).is_none(),
        "plain-HTTP 403 must strip WWW-Authenticate even if status=4xx sets it"
    );
    assert!(
        h403.get(STRICT_TRANSPORT_SECURITY).is_none(),
        "plain-HTTP response must strip HSTS even if status=403 sets it"
    );
    assert!(
        h403.get(ALT_SVC).is_none(),
        "plain-HTTP response must strip Alt-Svc"
    );

    // 3. Plain-HTTP served site without basic-auth: status-conditioned Cache-Control works,
    //    while HSTS and Alt-Svc set by status-conditioned rules are still stripped.
    let plain_site = build_engine(
        &root,
        r#"
    http "serve"
    headers {
        set "cache-control" "no-cache"
        set "strict-transport-security" "max-age=31536000" status="200 304"
        set "alt-svc" "h3=\":8443\"" status="2xx"
    }
    route "/assets/*" {
        try-files "{path}" "/index.html"
        headers {
            set "cache-control" "public, max-age=31536000, immutable" status="200 206 304"
        }
    }
"#,
        Some(8443),
    )?;
    let (st_p200, h_p200, _) = send(&plain_site, &plain, Method::GET, "/assets/a.js", &[]).await?;
    assert_eq!(st_p200, StatusCode::OK);
    assert_eq!(header_str(&h_p200, "cache-control"), Some(IMMUTABLE));
    assert!(h_p200.get(STRICT_TRANSPORT_SECURITY).is_none());
    assert!(h_p200.get(ALT_SVC).is_none());

    let (st_pfb, h_pfb, body_pfb) =
        send(&plain_site, &plain, Method::GET, "/assets/missing.js", &[]).await?;
    assert_eq!(st_pfb, StatusCode::OK);
    assert_eq!(body_pfb.as_ref(), b"HOME");
    assert_eq!(header_str(&h_pfb, "cache-control"), Some("no-cache"));
    assert!(h_pfb.get(STRICT_TRANSPORT_SECURITY).is_none());

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn status_conditioned_headers_work_over_h1_and_h2_wire() -> TestResult {
    let root = std::env::temp_dir().join(format!(
        "miraserve-hdr-h12-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("assets"))?;
    std::fs::create_dir_all(root.join("strict-assets"))?;
    std::fs::write(root.join("index.html"), b"SPA")?;
    std::fs::write(root.join("assets/main.js"), b"console.log(42);")?;
    std::fs::write(root.join("strict-assets/img.png"), b"PNGDATA")?;

    let engine = build_engine(
        &root,
        r#"
    headers {
        set "cache-control" "no-cache"
    }
    route "/strict-assets/*" {
        static
        headers {
            set "cache-control" "public, max-age=31536000, immutable" status="200 206 304"
        }
    }
    route "/assets/*" {
        try-files "{path}" "/index.html"
        headers {
            set "cache-control" "public, max-age=31536000, immutable" status="200 206 304"
        }
    }
"#,
        None,
    )?;

    let peer: SocketAddr = "198.51.100.42:50000".parse()?;
    let local: SocketAddr = "127.0.0.1:8443".parse()?;

    // Helper closures for H1 and H2 requests.
    let fetch_h1 = |method: Method, path: &str, hdrs: Vec<(http::HeaderName, HeaderValue)>| {
        let engine = Arc::clone(&engine);
        let path = path.to_owned();
        async move {
            let (client, server) = tokio::io::duplex(64 * 1024);
            let (_tx, rx) = watch::channel(false);
            tokio::spawn(engine.serve_hyper_connection(server, peer, local, true, false, None, rx));
            let (mut sender, conn) = http1::handshake(TokioIo::new(client)).await?;
            let driver = tokio::spawn(async move {
                let _ = conn.await;
            });
            let mut b = Request::builder()
                .method(method)
                .uri(path)
                .header(HOST, SITE_HOST);
            for (k, v) in hdrs {
                b = b.header(k, v);
            }
            let resp = sender.send_request(b.body(Empty::<Bytes>::new())?).await?;
            let status = resp.status();
            let headers = resp.headers().clone();
            let _ = resp.into_body().collect().await?;
            driver.abort();
            Ok::<_, Box<dyn std::error::Error>>((status, headers))
        }
    };

    let fetch_h2 = |method: Method, path: &str, hdrs: Vec<(http::HeaderName, HeaderValue)>| {
        let engine = Arc::clone(&engine);
        let path = path.to_owned();
        async move {
            let (client, server) = tokio::io::duplex(64 * 1024);
            let (_tx, rx) = watch::channel(false);
            tokio::spawn(engine.serve_hyper_connection(server, peer, local, true, false, None, rx));
            let (mut sender, conn) =
                http2::handshake(TokioExecutor::new(), TokioIo::new(client)).await?;
            let driver = tokio::spawn(async move {
                let _ = conn.await;
            });
            let mut b = Request::builder()
                .method(method)
                .uri(format!("https://{SITE_HOST}{path}"));
            for (k, v) in hdrs {
                b = b.header(k, v);
            }
            let resp = sender.send_request(b.body(Empty::<Bytes>::new())?).await?;
            let status = resp.status();
            let headers = resp.headers().clone();
            let _ = resp.into_body().collect().await?;
            driver.abort();
            Ok::<_, Box<dyn std::error::Error>>((status, headers))
        }
    };

    for is_h2 in [false, true] {
        let proto = if is_h2 { "H2" } else { "H1" };
        let (st200, h200) = if is_h2 {
            fetch_h2(Method::GET, "/assets/main.js", vec![]).await?
        } else {
            fetch_h1(Method::GET, "/assets/main.js", vec![]).await?
        };
        assert_eq!(st200, StatusCode::OK, "{proto} 200");
        assert_eq!(
            h200.get(CACHE_CONTROL).and_then(|v| v.to_str().ok()),
            Some(IMMUTABLE),
            "{proto} 200 cache-control"
        );
        let last_modified = h200
            .get(LAST_MODIFIED)
            .cloned()
            .ok_or("missing last-modified")?;
        let (st304_ims, h304_ims) = if is_h2 {
            fetch_h2(
                Method::GET,
                "/assets/main.js",
                vec![(IF_MODIFIED_SINCE, last_modified)],
            )
            .await?
        } else {
            fetch_h1(
                Method::GET,
                "/assets/main.js",
                vec![(IF_MODIFIED_SINCE, last_modified)],
            )
            .await?
        };
        assert_eq!(st304_ims, StatusCode::NOT_MODIFIED, "{proto} 304 (IMS)");
        assert_eq!(
            h304_ims.get(CACHE_CONTROL).and_then(|v| v.to_str().ok()),
            Some(IMMUTABLE),
            "{proto} 304 (IMS) cache-control"
        );

        #[cfg(unix)]
        assert!(h200.get(ETAG).is_some(), "{proto} Unix must emit ETag");
        if let Some(etag) = h200.get(ETAG).cloned() {
            let (st304, h304) = if is_h2 {
                fetch_h2(Method::GET, "/assets/main.js", vec![(IF_NONE_MATCH, etag)]).await?
            } else {
                fetch_h1(Method::GET, "/assets/main.js", vec![(IF_NONE_MATCH, etag)]).await?
            };
            assert_eq!(st304, StatusCode::NOT_MODIFIED, "{proto} 304 (ETag)");
            assert_eq!(
                h304.get(CACHE_CONTROL).and_then(|v| v.to_str().ok()),
                Some(IMMUTABLE),
                "{proto} 304 (ETag) cache-control"
            );
        }

        let (st_head, h_head) = if is_h2 {
            fetch_h2(Method::HEAD, "/assets/main.js", vec![]).await?
        } else {
            fetch_h1(Method::HEAD, "/assets/main.js", vec![]).await?
        };
        assert_eq!(st_head, StatusCode::OK, "{proto} HEAD");
        assert_eq!(
            h_head.get(CACHE_CONTROL).and_then(|v| v.to_str().ok()),
            Some(IMMUTABLE),
            "{proto} HEAD cache-control"
        );

        let (st206, h206) = if is_h2 {
            fetch_h2(
                Method::GET,
                "/assets/main.js",
                vec![(RANGE, HeaderValue::from_static("bytes=0-3"))],
            )
            .await?
        } else {
            fetch_h1(
                Method::GET,
                "/assets/main.js",
                vec![(RANGE, HeaderValue::from_static("bytes=0-3"))],
            )
            .await?
        };
        assert_eq!(st206, StatusCode::PARTIAL_CONTENT, "{proto} 206");
        assert_eq!(
            h206.get(CACHE_CONTROL).and_then(|v| v.to_str().ok()),
            Some(IMMUTABLE),
            "{proto} 206 cache-control"
        );

        let (st404, h404) = if is_h2 {
            fetch_h2(Method::GET, "/strict-assets/nope.png", vec![]).await?
        } else {
            fetch_h1(Method::GET, "/strict-assets/nope.png", vec![]).await?
        };
        assert_eq!(st404, StatusCode::NOT_FOUND, "{proto} 404");
        assert_eq!(
            h404.get(CACHE_CONTROL).and_then(|v| v.to_str().ok()),
            Some("no-cache"),
            "{proto} 404 must not receive immutable"
        );

        let (st_fb, h_fb) = if is_h2 {
            fetch_h2(Method::GET, "/assets/missing.js", vec![]).await?
        } else {
            fetch_h1(Method::GET, "/assets/missing.js", vec![]).await?
        };
        assert_eq!(st_fb, StatusCode::OK, "{proto} SPA fallback");
        assert_eq!(
            h_fb.get(CACHE_CONTROL).and_then(|v| v.to_str().ok()),
            Some("no-cache"),
            "{proto} SPA fallback must not receive immutable"
        );
    }

    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

#[tokio::test]
async fn rules_without_status_remain_unchanged_and_non_last_try_files_fallback_respects_owner()
-> TestResult {
    let root = std::env::temp_dir().join(format!(
        "miraserve-hdr-golden-compat-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("assets"))?;
    std::fs::write(root.join("index.html"), b"SHELL")?;
    std::fs::write(root.join("assets/a.txt"), b"ASSET")?;

    let engine = build_engine(
        &root,
        r#"
    headers {
        set "cache-control" "public, max-age=600"
        add "vary" "Cookie"
        remove "referrer-policy"
    }
    route "/assets/*" {
        try-files "{path}" "/index.html" "=410"
        headers {
            set "x-route" "assets"
        }
    }
    route "/gone/*" {
        try-files "{path}" "=404"
        headers {
            set "x-route" "gone"
        }
    }
"#,
        None,
    )?;
    let ctx = https_ctx();

    // Unconditional rules apply to 200, 304, and 404 identically to v0.1.3.
    let (st200, h200, _) = send(&engine, &ctx, Method::GET, "/assets/a.txt", &[]).await?;
    assert_eq!(st200, StatusCode::OK);
    assert_eq!(
        header_str(&h200, "cache-control"),
        Some("public, max-age=600")
    );
    assert_eq!(header_str(&h200, "x-route"), Some("assets"));
    assert!(h200.get("referrer-policy").is_none());
    let vary: Vec<&str> = h200
        .get_all("vary")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    assert!(vary.contains(&"Cookie") && vary.contains(&"Accept-Encoding"));

    let (st404, h404, _) = send(&engine, &ctx, Method::GET, "/gone/missing", &[]).await?;
    assert_eq!(st404, StatusCode::NOT_FOUND);
    assert_eq!(
        header_str(&h404, "cache-control"),
        Some("public, max-age=600")
    );
    assert_eq!(header_str(&h404, "x-route"), Some("gone"));
    assert!(h404.get("referrer-policy").is_none());

    // Non-last fallback candidate `/index.html` in `try-files "{path}" "/index.html" "=410"`
    // belongs to no route (site default), so `/assets/*` route headers do NOT leak onto it.
    let (st_fb, h_fb, body_fb) =
        send(&engine, &ctx, Method::GET, "/assets/missing.txt", &[]).await?;
    assert_eq!(st_fb, StatusCode::OK);
    assert_eq!(body_fb.as_ref(), b"SHELL");
    assert_eq!(
        header_str(&h_fb, "cache-control"),
        Some("public, max-age=600")
    );
    assert!(h_fb.get("x-route").is_none());

    // Remove `/index.html`: candidate 1 now misses and falls through to `=410` (owned by `/assets/*`).
    std::fs::remove_file(root.join("index.html"))?;
    let (st410, h410, _) = send(&engine, &ctx, Method::GET, "/assets/missing.txt", &[]).await?;
    assert_eq!(st410, StatusCode::GONE);
    assert_eq!(header_str(&h410, "x-route"), Some("assets"));

    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

fn build_raw_engine(kdl_sites: &str) -> Result<Arc<HttpEngine>, Box<dyn std::error::Error>> {
    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
{kdl_sites}
"#
    );
    let (cfg, _) = parse_kdl("v013-golden.kdl", &kdl)?;
    Ok(Arc::new(HttpEngine::from_config(
        &cfg,
        Arc::new(AcmeChallengeStore::new()),
        None,
        8443,
    )?))
}

async fn raw_h1_normalized(
    engine: Arc<HttpEngine>,
    req_bytes: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let peer: SocketAddr = "198.51.100.50:50000".parse()?;
    let local: SocketAddr = "127.0.0.1:8443".parse()?;
    let (_tx, rx) = watch::channel(false);
    tokio::spawn(engine.serve_hyper_connection(server, peer, local, true, false, None, rx));

    client.write_all(req_bytes.as_bytes()).await?;
    client.flush().await?;
    let mut out = Vec::new();
    client.read_to_end(&mut out).await?;
    let raw = String::from_utf8(out)?;
    normalize_h1_wire(&raw)
}

/// Normalizes ONLY per-run non-deterministic fields (`etag`, `last-modified`, `date`,
/// `x-request-id`, and the CSP `style-src 'nonce-...'` token in both header and body), while
/// preserving status line, header order, every deterministic header, and every remaining body byte.
fn normalize_h1_wire(raw: &str) -> Result<String, Box<dyn std::error::Error>> {
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .ok_or("missing HTTP header/body separator")?;
    let mut req_id: Option<String> = None;
    let mut csp_nonce: Option<String> = None;
    let mut norm_lines = Vec::new();

    for (idx, line) in head.split("\r\n").enumerate() {
        if idx == 0 {
            norm_lines.push(line.to_owned());
            continue;
        }
        let (k, v) = line
            .split_once(": ")
            .ok_or_else(|| format!("malformed header line: {line}"))?;
        match k {
            "etag" => {
                assert!(v.starts_with('"') && v.ends_with('"'), "invalid etag: {v}");
                norm_lines.push("etag: <ETAG>".to_owned());
            }
            "last-modified" => {
                assert!(v.ends_with(" GMT") && v.len() == 29, "invalid date: {v}");
                norm_lines.push("last-modified: <LAST-MODIFIED>".to_owned());
            }
            "date" => norm_lines.push("date: <DATE>".to_owned()),
            "x-request-id" => {
                assert_eq!(v.len(), 26, "invalid request id: {v}");
                req_id = Some(v.to_owned());
                norm_lines.push("x-request-id: <REQUEST-ID>".to_owned());
            }
            "content-security-policy" => {
                if let Some(nonce) = v
                    .split("style-src 'nonce-")
                    .nth(1)
                    .and_then(|after| after.split_once('\''))
                    .map(|(n, _)| n)
                {
                    csp_nonce = Some(nonce.to_owned());
                    norm_lines.push(format!(
                        "content-security-policy: {}",
                        v.replace(nonce, "<NONCE>")
                    ));
                } else {
                    norm_lines.push(line.to_owned());
                }
            }
            _ => norm_lines.push(line.to_owned()),
        }
    }

    let mut norm_body = body.to_owned();
    if let Some(id) = &req_id {
        norm_body = norm_body.replace(id, "<REQUEST-ID>");
    }
    if let Some(nonce) = &csp_nonce {
        norm_body = norm_body.replace(nonce, "<NONCE>");
    }
    Ok(format!("{}\r\n\r\n{}", norm_lines.join("\r\n"), norm_body))
}

/// Adjusts a captured Unix v0.1.3 static-file wire golden for non-Unix targets where MiraServe
/// intentionally omits `ETag` (because `change_stamp` returns `None`).
fn platform_static_golden(unix_golden: &str) -> String {
    #[cfg(unix)]
    {
        unix_golden.to_owned()
    }
    #[cfg(not(unix))]
    {
        unix_golden.replace("etag: <ETAG>\r\n", "")
    }
}

/// Byte-for-byte complete HTTP/1.1 response goldens captured directly from a detached `v0.1.3`
/// (`2753957`) worktree:
///
/// ```text
/// git worktree add --detach /tmp/miraserve-v013-golden v0.1.3
/// # Run raw HTTP/1.1 requests over `serve_hyper_connection` (`tokio::io::duplex`) with
/// # `Connection: close` and print each normalized response string via:
/// CARGO_TARGET_DIR=target \
///   cargo test -p miraserve-http --test capture_v013_goldens --locked -- --nocapture
/// git worktree remove --force /tmp/miraserve-v013-golden
/// ```
///
/// Pins that removing the `try-files` redispatch preserves v0.1.3 wire responses byte for byte for:
/// 1. A route with its own `root` and fallback present there (both without a site root and with a
///    divergent site root + competing redirect route at `/index.html`).
/// 2. A Markdown sibling `index.md` next to the HTML fallback (`Accept: text/markdown` and
///    `Accept: text/html` — no Markdown negotiation and unchanged `Vary: Accept-Encoding`).
/// 3. A fallback to a directory with an index (`/shell` -> `shell/index.html`, `200` with no 301).
/// 4. Divergent `security-headers` policies (site `"off"`, enclosing route `"strict"`) on
///    internal-rewrite `deny`, preset refusal, and rewrite-limit `500`.
/// 5. `POST` to a path whose static fallback exists (directory index, non-last file, single
///    literal `try-files "/index.html"` -> `405`).
/// 6. Site `rewrite ... deny` on a script reached via `PATH_INFO` (`/index.php/info`).
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn v013_wire_goldens_preserved_across_fallbacks_rewrites_and_405() -> TestResult {
    const GOLDEN_HOST: &str = "golden.example.test";
    const V013_CASE_1A: &str = "HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\ncontent-length: 29\r\naccept-ranges: bytes\r\nvary: Accept-Encoding\r\netag: <ETAG>\r\nlast-modified: <LAST-MODIFIED>\r\nserver: MiraServe\r\nstrict-transport-security: max-age=63072000; includeSubDomains\r\nx-content-type-options: nosniff\r\nreferrer-policy: strict-origin-when-cross-origin\r\nx-frame-options: DENY\r\ncross-origin-opener-policy: same-origin\r\npermissions-policy: geolocation=(), microphone=(), camera=()\r\nconnection: close\r\ndate: <DATE>\r\n\r\n<html>ROUTE-ROOT-SHELL</html>";
    const V013_CASE_2: &str = "HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\ncontent-length: 23\r\naccept-ranges: bytes\r\nvary: Accept-Encoding\r\netag: <ETAG>\r\nlast-modified: <LAST-MODIFIED>\r\nserver: MiraServe\r\nstrict-transport-security: max-age=63072000; includeSubDomains\r\nx-content-type-options: nosniff\r\nreferrer-policy: strict-origin-when-cross-origin\r\nx-frame-options: DENY\r\ncross-origin-opener-policy: same-origin\r\npermissions-policy: geolocation=(), microphone=(), camera=()\r\nconnection: close\r\ndate: <DATE>\r\n\r\n<html>HTML SHELL</html>";
    const V013_CASE_3: &str = "HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\ncontent-length: 22\r\naccept-ranges: bytes\r\nvary: Accept-Encoding\r\netag: <ETAG>\r\nlast-modified: <LAST-MODIFIED>\r\nserver: MiraServe\r\nstrict-transport-security: max-age=63072000; includeSubDomains\r\nx-content-type-options: nosniff\r\nreferrer-policy: strict-origin-when-cross-origin\r\nx-frame-options: DENY\r\ncross-origin-opener-policy: same-origin\r\npermissions-policy: geolocation=(), microphone=(), camera=()\r\nconnection: close\r\ndate: <DATE>\r\n\r\n<html>DIR SHELL</html>";
    const V013_CASE_4A: &str = "HTTP/1.1 403 Forbidden\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: 149\r\nvary: Accept\r\nx-content-type-options: nosniff\r\ncache-control: no-store\r\nserver: MiraServe\r\ncontent-security-policy: default-src 'none'; style-src 'nonce-<NONCE>'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\nx-request-id: <REQUEST-ID>\r\nstrict-transport-security: max-age=63072000; includeSubDomains\r\nreferrer-policy: strict-origin-when-cross-origin\r\nx-frame-options: DENY\r\ncross-origin-opener-policy: same-origin\r\npermissions-policy: geolocation=(), microphone=(), camera=()\r\nconnection: close\r\ndate: <DATE>\r\n\r\n403 Forbidden\n\nThe server understood the request for /assets/missing.js but is not allowed to show it to you.\nRequest ID: <REQUEST-ID>\n";
    const V013_CASE_4B: &str = "HTTP/1.1 404 Not Found\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: 187\r\nvary: Accept\r\nx-content-type-options: nosniff\r\ncache-control: no-store\r\nserver: MiraServe\r\ncontent-security-policy: default-src 'none'; style-src 'nonce-<NONCE>'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\nx-request-id: <REQUEST-ID>\r\nstrict-transport-security: max-age=63072000; includeSubDomains\r\nreferrer-policy: strict-origin-when-cross-origin\r\nx-frame-options: DENY\r\ncross-origin-opener-policy: same-origin\r\npermissions-policy: geolocation=(), microphone=(), camera=()\r\nconnection: close\r\ndate: <DATE>\r\n\r\n404 Not Found\n\nThere is nothing at /assets/missing.js on golden.example.test. The page may have moved or been deleted, or the link may have a typo.\nRequest ID: <REQUEST-ID>\n";
    const V013_CASE_4C: &str = "HTTP/1.1 500 Internal Server Error\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: 264\r\nvary: Accept\r\nx-content-type-options: nosniff\r\ncache-control: no-store\r\nserver: MiraServe\r\ncontent-security-policy: default-src 'none'; style-src 'nonce-<NONCE>'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\nx-request-id: <REQUEST-ID>\r\nstrict-transport-security: max-age=63072000; includeSubDomains\r\nreferrer-policy: strict-origin-when-cross-origin\r\nx-frame-options: DENY\r\ncross-origin-opener-policy: same-origin\r\npermissions-policy: geolocation=(), microphone=(), camera=()\r\nconnection: close\r\ndate: <DATE>\r\n\r\n500 Internal Server Error\n\nThe server hit an unexpected problem and couldn’t finish your request. For your security, no technical details are shown here; the site owner can find them in the server log using the request ID.\nRequest ID: <REQUEST-ID>\n";
    const V013_CASE_5A: &str = "HTTP/1.1 405 Method Not Allowed\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: 114\r\nvary: Accept\r\nx-content-type-options: nosniff\r\ncache-control: no-store\r\nserver: MiraServe\r\ncontent-security-policy: default-src 'none'; style-src 'nonce-<NONCE>'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\nx-request-id: <REQUEST-ID>\r\nallow: GET, HEAD\r\nstrict-transport-security: max-age=63072000; includeSubDomains\r\nreferrer-policy: strict-origin-when-cross-origin\r\nx-frame-options: DENY\r\ncross-origin-opener-policy: same-origin\r\npermissions-policy: geolocation=(), microphone=(), camera=()\r\nconnection: close\r\ndate: <DATE>\r\n\r\n405 Method Not Allowed\n\n/dir-fb/missing.js doesn’t accept POST requests.\nRequest ID: <REQUEST-ID>\n";
    const V013_CASE_5B: &str = "HTTP/1.1 405 Method Not Allowed\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: 115\r\nvary: Accept\r\nx-content-type-options: nosniff\r\ncache-control: no-store\r\nserver: MiraServe\r\ncontent-security-policy: default-src 'none'; style-src 'nonce-<NONCE>'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\nx-request-id: <REQUEST-ID>\r\nallow: GET, HEAD\r\nstrict-transport-security: max-age=63072000; includeSubDomains\r\nreferrer-policy: strict-origin-when-cross-origin\r\nx-frame-options: DENY\r\ncross-origin-opener-policy: same-origin\r\npermissions-policy: geolocation=(), microphone=(), camera=()\r\nconnection: close\r\ndate: <DATE>\r\n\r\n405 Method Not Allowed\n\n/file-fb/missing.js doesn’t accept POST requests.\nRequest ID: <REQUEST-ID>\n";
    const V013_CASE_5C: &str = "HTTP/1.1 405 Method Not Allowed\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: 109\r\nvary: Accept\r\nx-content-type-options: nosniff\r\ncache-control: no-store\r\nserver: MiraServe\r\ncontent-security-policy: default-src 'none'; style-src 'nonce-<NONCE>'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\nx-request-id: <REQUEST-ID>\r\nallow: GET, HEAD\r\nstrict-transport-security: max-age=63072000; includeSubDomains\r\nreferrer-policy: strict-origin-when-cross-origin\r\nx-frame-options: DENY\r\ncross-origin-opener-policy: same-origin\r\npermissions-policy: geolocation=(), microphone=(), camera=()\r\nconnection: close\r\ndate: <DATE>\r\n\r\n405 Method Not Allowed\n\n/lit/anything doesn’t accept POST requests.\nRequest ID: <REQUEST-ID>\n";
    const V013_CASE_6: &str = "HTTP/1.1 403 Forbidden\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: 143\r\nvary: Accept\r\nx-content-type-options: nosniff\r\ncache-control: no-store\r\nserver: MiraServe\r\ncontent-security-policy: default-src 'none'; style-src 'nonce-<NONCE>'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\nx-request-id: <REQUEST-ID>\r\nstrict-transport-security: max-age=63072000; includeSubDomains\r\nreferrer-policy: strict-origin-when-cross-origin\r\nx-frame-options: DENY\r\ncross-origin-opener-policy: same-origin\r\npermissions-policy: geolocation=(), microphone=(), camera=()\r\nx-script: yes\r\nconnection: close\r\ndate: <DATE>\r\n\r\n403 Forbidden\n\nThe server understood the request for /app/missing but is not allowed to show it to you.\nRequest ID: <REQUEST-ID>\n";
    let base = std::env::temp_dir().join(format!(
        "miraserve-v013-wire-golden-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let route_root = base.join("route-root");
    let site_root = base.join("site-root");
    let md_root = base.join("md-root");
    let dir_root = base.join("dir-root");
    std::fs::create_dir_all(&route_root)?;
    std::fs::create_dir_all(&site_root)?;
    std::fs::create_dir_all(&md_root)?;
    std::fs::create_dir_all(dir_root.join("shell"))?;

    std::fs::write(
        route_root.join("index.html"),
        b"<html>ROUTE-ROOT-SHELL</html>",
    )?;
    std::fs::write(
        site_root.join("index.html"),
        b"<html>SITE-ROOT-OTHER</html>",
    )?;
    std::fs::write(md_root.join("index.html"), b"<html>HTML SHELL</html>")?;
    std::fs::write(md_root.join("index.md"), b"# MARKDOWN SHELL\n")?;
    std::fs::write(dir_root.join("index.html"), b"<html>TOP SHELL</html>")?;
    std::fs::write(dir_root.join("shell/index.html"), b"<html>DIR SHELL</html>")?;

    let p = |path: &Path| path.to_string_lossy().replace('\\', "/");

    // Case 1a: Route with its own root and NO site-level root.
    let e1a = build_raw_engine(&format!(
        r#"
site "{GOLDEN_HOST}" {{
    route "/assets/*" {{
        root "{rr}"
        try-files "{{path}}" "/index.html"
    }}
}}
"#,
        rr = p(&route_root)
    ))?;
    let r1a = raw_h1_normalized(
        e1a,
        &format!(
            "GET /assets/missing.js HTTP/1.1\r\nHost: {GOLDEN_HOST}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await?;
    assert_eq!(
        r1a,
        platform_static_golden(V013_CASE_1A),
        "Case 1a (route own root, no site root) must match v0.1.3 byte-for-byte"
    );

    // Case 1b: Route with its own root, divergent site root, and competing redirect at `/index.html`.
    let e1b = build_raw_engine(&format!(
        r#"
site "{GOLDEN_HOST}" {{
    root "{sr}"
    route "/index.html" {{
        redirect "/elsewhere" status=301
    }}
    route "/assets/*" {{
        root "{rr}"
        try-files "{{path}}" "/index.html"
    }}
}}
"#,
        sr = p(&site_root),
        rr = p(&route_root)
    ))?;
    let r1b = raw_h1_normalized(
        e1b,
        &format!(
            "GET /assets/missing.js HTTP/1.1\r\nHost: {GOLDEN_HOST}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await?;
    assert_eq!(
        r1b,
        platform_static_golden(V013_CASE_1A),
        "Case 1b (route own root + competing site root/redirect) must match v0.1.3 byte-for-byte"
    );

    // Case 2a & 2b: Markdown sibling present next to fallback.
    let e2 = build_raw_engine(&format!(
        r#"
site "{GOLDEN_HOST}" {{
    root "{mr}"
    route "/assets/*" {{
        try-files "{{path}}" "/index.html"
    }}
}}
"#,
        mr = p(&md_root)
    ))?;
    let r2a = raw_h1_normalized(
        Arc::clone(&e2),
        &format!("GET /assets/missing.js HTTP/1.1\r\nHost: {GOLDEN_HOST}\r\nAccept: text/markdown\r\nConnection: close\r\n\r\n"),
    )
    .await?;
    assert_eq!(
        r2a,
        platform_static_golden(V013_CASE_2),
        "Case 2a (Markdown sibling + Accept: text/markdown) must match v0.1.3 byte-for-byte"
    );
    let r2b = raw_h1_normalized(
        e2,
        &format!("GET /assets/missing.js HTTP/1.1\r\nHost: {GOLDEN_HOST}\r\nAccept: text/html\r\nConnection: close\r\n\r\n"),
    )
    .await?;
    assert_eq!(
        r2b,
        platform_static_golden(V013_CASE_2),
        "Case 2b (Markdown sibling + Accept: text/html Vary preservation) must match v0.1.3 byte-for-byte"
    );

    // Case 3: Fallback to a directory with an index (`/shell` -> `shell/index.html`, no 301).
    let e3 = build_raw_engine(&format!(
        r#"
site "{GOLDEN_HOST}" {{
    root "{dr}"
    route "/assets/*" {{
        try-files "{{path}}" "/shell"
    }}
}}
"#,
        dr = p(&dir_root)
    ))?;
    let r3 = raw_h1_normalized(
        e3,
        &format!(
            "GET /assets/missing.js HTTP/1.1\r\nHost: {GOLDEN_HOST}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await?;
    assert_eq!(
        r3,
        platform_static_golden(V013_CASE_3),
        "Case 3 (fallback directory with index, no redirect) must match v0.1.3 byte-for-byte"
    );

    // Case 4a, 4b, 4c: Divergent security-header policies on internal-rewrite refusals / errors.
    let e4a = build_raw_engine(&format!(
        r#"
site "{GOLDEN_HOST}" {{
    root "{dr}"
    security-headers "off"
    rewrite {{
        rule "^/index\\.php$" deny=403
    }}
    route "/assets/*" {{
        security-headers "strict"
        try-files "{{path}}" "/index.php?{{query}}"
    }}
    route "*.php" {{
        fastcgi-pass "tcp://127.0.0.1:9"
    }}
}}
"#,
        dr = p(&dir_root)
    ))?;
    let r4a = raw_h1_normalized(
        e4a,
        &format!(
            "GET /assets/missing.js HTTP/1.1\r\nHost: {GOLDEN_HOST}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await?;
    assert_eq!(
        r4a, V013_CASE_4A,
        "Case 4a (divergent security-headers on rewrite deny) must match v0.1.3 byte-for-byte"
    );

    let e4b = build_raw_engine(&format!(
        r#"
site "{GOLDEN_HOST}" {{
    root "{dr}"
    preset "wordpress-hardened"
    security-headers "off"
    route "/assets/*" {{
        security-headers "strict"
        try-files "{{path}}" "/wp-config.php?{{query}}"
    }}
}}
"#,
        dr = p(&dir_root)
    ))?;
    let r4b = raw_h1_normalized(
        e4b,
        &format!(
            "GET /assets/missing.js HTTP/1.1\r\nHost: {GOLDEN_HOST}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await?;
    assert_eq!(
        r4b, V013_CASE_4B,
        "Case 4b (divergent security-headers on preset refusal) must match v0.1.3 byte-for-byte"
    );

    let e4c = build_raw_engine(&format!(
        r#"
site "{GOLDEN_HOST}" {{
    root "{dr}"
    security-headers "off"
    route "/a/*" {{
        security-headers "strict"
        try-files "{{path}}" "/b/x?{{query}}"
    }}
    route "/b/*" {{
        security-headers "off"
        try-files "{{path}}" "/a/x?{{query}}"
    }}
}}
"#,
        dr = p(&dir_root)
    ))?;
    let r4c = raw_h1_normalized(
        e4c,
        &format!("GET /a/missing HTTP/1.1\r\nHost: {GOLDEN_HOST}\r\nConnection: close\r\n\r\n"),
    )
    .await?;
    assert_eq!(
        r4c, V013_CASE_4C,
        "Case 4c (divergent security-headers on rewrite-limit 500) must match v0.1.3 byte-for-byte"
    );

    // Case 5a, 5b, 5c: POST to a path whose fallback exists (405).
    let e5 = build_raw_engine(&format!(
        r#"
site "{GOLDEN_HOST}" {{
    root "{dr}"
    route "/dir-fb/*" {{
        try-files "{{path}}" "/shell/" "=410"
    }}
    route "/file-fb/*" {{
        try-files "{{path}}" "/index.html" "=410"
    }}
    route "/lit/*" {{
        try-files "/index.html"
    }}
}}
"#,
        dr = p(&dir_root)
    ))?;
    let r5a = raw_h1_normalized(
        Arc::clone(&e5),
        &format!("POST /dir-fb/missing.js HTTP/1.1\r\nHost: {GOLDEN_HOST}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
    )
    .await?;
    assert_eq!(
        r5a, V013_CASE_5A,
        "Case 5a (POST to directory fallback 405) must match v0.1.3 byte-for-byte"
    );
    let r5b = raw_h1_normalized(
        Arc::clone(&e5),
        &format!("POST /file-fb/missing.js HTTP/1.1\r\nHost: {GOLDEN_HOST}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
    )
    .await?;
    assert_eq!(
        r5b, V013_CASE_5B,
        "Case 5b (POST to file fallback 405) must match v0.1.3 byte-for-byte"
    );
    let r5c = raw_h1_normalized(
        e5,
        &format!("POST /lit/anything HTTP/1.1\r\nHost: {GOLDEN_HOST}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
    )
    .await?;
    assert_eq!(
        r5c, V013_CASE_5C,
        "Case 5c (POST to single literal fallback 405) must match v0.1.3 byte-for-byte"
    );

    // Case 6: Site denial on a script with PATH_INFO.
    let e6 = build_raw_engine(&format!(
        r#"
site "{GOLDEN_HOST}" {{
    root "{dr}"
    rewrite {{
        rule "^/index\\.php$" deny=403
    }}
    route "/app/*" {{
        try-files "{{path}}" "/index.php/info"
        headers {{
            set "x-app" "r1"
        }}
    }}
    route "*.php" {{
        fastcgi-pass "tcp://127.0.0.1:9"
        headers {{
            set "x-script" "yes"
        }}
    }}
}}
"#,
        dr = p(&dir_root)
    ))?;
    let r6 = raw_h1_normalized(
        e6,
        &format!("GET /app/missing HTTP/1.1\r\nHost: {GOLDEN_HOST}\r\nConnection: close\r\n\r\n"),
    )
    .await?;
    assert_eq!(
        r6, V013_CASE_6,
        "Case 6 (site denial on script with PATH_INFO) must match v0.1.3 byte-for-byte"
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Pins Rule (b) pure path-lookup header ownership without redispatch:
/// - Target route's handler and rate limiter NEVER run during a static `try-files` fallback.
/// - Every status produced by a static fallback — including 200 (route-only root, directory
///   index) and 405 (`POST` to directory index, non-last file, single literal) — gets the `headers`
///   rules of the route matching the fallback candidate path (or site-only when none matches).
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn static_try_files_fallback_pure_header_lookup_and_405_ownership() -> TestResult {
    let base = std::env::temp_dir().join(format!(
        "miraserve-hdr-pure-lookup-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let route_root = base.join("route-root");
    let site_root = base.join("site-root");
    std::fs::create_dir_all(route_root.join("assets"))?;
    std::fs::create_dir_all(site_root.join("shell"))?;
    std::fs::write(route_root.join("index.html"), b"<html>ROUTE SHELL</html>")?;
    std::fs::write(route_root.join("assets/fallback.js"), b"// self-owned")?;
    std::fs::write(site_root.join("index.html"), b"<html>SITE SHELL</html>")?;
    std::fs::write(site_root.join("unowned.html"), b"<html>UNOWNED</html>")?;
    std::fs::write(
        site_root.join("shell/index.html"),
        b"<html>DIR SHELL</html>",
    )?;

    let engine = build_engine(
        &site_root,
        &format!(
            r#"
    headers {{
        set "x-site" "always"
    }}
    route "/index.html" {{
        redirect "/never-run" status=301
        rate-limit requests=1 per="1m" burst=1
        headers {{
            set "x-r2-index" "owned" status="200 405"
        }}
    }}
    route "/shell/*" {{
        static
        headers {{
            set "x-r2-shell" "owned"
            set "x-r2-shell-405" "yes" status="405"
        }}
    }}
    route "/own-root/*" {{
        root "{rr}"
        try-files "{{path}}" "/index.html"
        headers {{
            set "x-r1" "leaked"
            set "x-r1-200" "leaked" status="200"
        }}
    }}
    route "/assets/*" {{
        root "{rr}"
        try-files "{{path}}" "/assets/fallback.js"
        headers {{
            set "x-assets-self" "kept" status="200"
        }}
    }}
    route "/dir-fb/*" {{
        try-files "{{path}}" "/shell/" "=410"
        headers {{
            set "x-r1" "leaked"
            set "x-r1-405" "leaked" status="405"
        }}
    }}
    route "/dir-noslash/*" {{
        try-files "{{path}}" "/shell"
        headers {{
            set "x-r1" "leaked"
        }}
    }}
    route "/file-fb/*" {{
        try-files "{{path}}" "/index.html" "=410"
        headers {{
            set "x-r1" "leaked"
            set "x-r1-405" "leaked" status="405"
        }}
    }}
    route "/lit/*" {{
        try-files "/index.html"
        headers {{
            set "x-r1" "leaked"
            set "x-r1-405" "leaked" status="405"
        }}
    }}
    route "/unowned-fb/*" {{
        try-files "{{path}}" "/unowned.html" "=410"
        headers {{
            set "x-r1" "leaked"
            set "x-r1-405" "leaked" status="405"
        }}
    }}
"#,
            rr = route_root.to_string_lossy().replace('\\', "/"),
        ),
        None,
    )?;
    let ctx = https_ctx();

    // 1. Route with its own root falls back to `/index.html`: R2's redirect handler NEVER runs
    //    and R2's 1-request rate limit is NEVER consulted across repeated requests, yet R2's
    //    `headers` rules apply instead of R1's.
    for attempt in 0..3 {
        let (st, h, body) = send(&engine, &ctx, Method::GET, "/own-root/missing.js", &[]).await?;
        assert_eq!(st, StatusCode::OK, "attempt {attempt}");
        assert_eq!(body.as_ref(), b"<html>ROUTE SHELL</html>");
        assert_eq!(header_str(&h, "x-site"), Some("always"));
        assert_eq!(header_str(&h, "x-r2-index"), Some("owned"));
        assert!(h.get("x-r1").is_none());
        assert!(h.get("x-r1-200").is_none());
    }

    // 2. Fallback to a path still owned by R1 itself keeps R1's headers.
    let (st_self, h_self, body_self) =
        send(&engine, &ctx, Method::GET, "/assets/missing.js", &[]).await?;
    assert_eq!(st_self, StatusCode::OK);
    assert_eq!(body_self.as_ref(), b"// self-owned");
    assert_eq!(header_str(&h_self, "x-assets-self"), Some("kept"));

    // 3. Fallback to `/shell` (directory with index) returns 200 without redirect, with R2 headers.
    let (st_dir, h_dir, body_dir) =
        send(&engine, &ctx, Method::GET, "/dir-noslash/missing", &[]).await?;
    assert_eq!(st_dir, StatusCode::OK);
    assert_eq!(body_dir.as_ref(), b"<html>DIR SHELL</html>");
    assert_eq!(header_str(&h_dir, "x-site"), Some("always"));
    assert_eq!(header_str(&h_dir, "x-r2-shell"), Some("owned"));
    assert!(h_dir.get("x-r1").is_none());

    // 4. POST 405 ownership on directory-index fallback (`/shell/` -> owned by `/shell/*`).
    let (st_p1, h_p1, _) = send(&engine, &ctx, Method::POST, "/dir-fb/missing.js", &[]).await?;
    assert_eq!(st_p1, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(header_str(&h_p1, "x-site"), Some("always"));
    assert_eq!(header_str(&h_p1, "x-r2-shell"), Some("owned"));
    assert_eq!(header_str(&h_p1, "x-r2-shell-405"), Some("yes"));
    assert!(h_p1.get("x-r1").is_none());
    assert!(h_p1.get("x-r1-405").is_none());

    // 5. POST 405 ownership on non-last file fallback (`/index.html` -> owned by `/index.html`).
    let (st_p2, h_p2, _) = send(&engine, &ctx, Method::POST, "/file-fb/missing.js", &[]).await?;
    assert_eq!(st_p2, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(header_str(&h_p2, "x-site"), Some("always"));
    assert_eq!(header_str(&h_p2, "x-r2-index"), Some("owned"));
    assert!(h_p2.get("x-r1").is_none());
    assert!(h_p2.get("x-r1-405").is_none());

    // 6. POST 405 ownership on single literal `try-files "/index.html"`.
    let (st_p3, h_p3, _) = send(&engine, &ctx, Method::POST, "/lit/anything", &[]).await?;
    assert_eq!(st_p3, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(header_str(&h_p3, "x-site"), Some("always"));
    assert_eq!(header_str(&h_p3, "x-r2-index"), Some("owned"));
    assert!(h_p3.get("x-r1").is_none());
    assert!(h_p3.get("x-r1-405").is_none());

    // 7. POST 405 ownership when no route owns the fallback (`/unowned.html` -> site-only headers).
    let (st_p4, h_p4, _) = send(&engine, &ctx, Method::POST, "/unowned-fb/missing.js", &[]).await?;
    assert_eq!(st_p4, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(header_str(&h_p4, "x-site"), Some("always"));
    assert!(h_p4.get("x-r1").is_none());
    assert!(h_p4.get("x-r1-405").is_none());

    // Verify R2's 1-request rate limit was STILL untouched: a direct request to `/index.html`
    // succeeds with its 301 redirect!
    let (st_direct, _, _) = send(&engine, &ctx, Method::GET, "/index.html", &[]).await?;
    assert_eq!(st_direct, StatusCode::MOVED_PERMANENTLY);

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Pins Review round 2 P2 #1: dot-segment static fallbacks normalize identically to static
/// resolution (`try-files "{path}" "/./version.json"` matches `route "/version.json"`, and
/// `try-files "{path}" "/./shell/."` matches exact `route "/shell/"`).
#[tokio::test]
async fn dot_segment_try_files_fallback_finds_normalized_header_owner() -> TestResult {
    let base = std::env::temp_dir().join(format!(
        "miraserve-hdr-dotseg-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(base.join("shell"))?;
    std::fs::write(base.join("version.json"), br#"{"version":"0.1.4"}"#)?;
    std::fs::write(base.join("shell/index.html"), b"<html>SHELL</html>")?;

    let engine = build_engine(
        &base,
        r#"
    headers {
        set "x-site" "always"
    }
    route "/version.json" {
        static
        headers {
            set "x-owner" "version" status="200 405"
        }
    }
    route "/shell/" {
        static
        headers {
            set "x-owner" "shell-slash"
        }
    }
    route "/app/*" {
        try-files "{path}" "/./version.json"
        headers {
            set "x-app" "leaked"
        }
    }
    route "/app-post/*" {
        try-files "{path}" "/./version.json" "=410"
        headers {
            set "x-app" "leaked"
        }
    }
    route "/dir-dot/*" {
        try-files "{path}" "/./shell/."
        headers {
            set "x-app" "leaked"
        }
    }
"#,
        None,
    )?;
    let ctx = https_ctx();

    // GET /app/missing -> fallback `/./version.json` normalizes to `/version.json`.
    let (st, h, body) = send(&engine, &ctx, Method::GET, "/app/missing", &[]).await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body.as_ref(), br#"{"version":"0.1.4"}"#);
    assert_eq!(header_str(&h, "x-site"), Some("always"));
    assert_eq!(header_str(&h, "x-owner"), Some("version"));
    assert!(h.get("x-app").is_none());

    // POST /app-post/missing -> 405 fallback `/./version.json` normalizes to `/version.json`.
    let (st_post, h_post, _) = send(&engine, &ctx, Method::POST, "/app-post/missing", &[]).await?;
    assert_eq!(st_post, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(header_str(&h_post, "x-site"), Some("always"));
    assert_eq!(header_str(&h_post, "x-owner"), Some("version"));
    assert!(h_post.get("x-app").is_none());

    // GET /dir-dot/missing -> fallback `/./shell/.` normalizes to `/shell/` (matches exact `/shell/`).
    let (st_dir, h_dir, body_dir) =
        send(&engine, &ctx, Method::GET, "/dir-dot/missing", &[]).await?;
    assert_eq!(st_dir, StatusCode::OK);
    assert_eq!(body_dir.as_ref(), b"<html>SHELL</html>");
    assert_eq!(header_str(&h_dir, "x-site"), Some("always"));
    assert_eq!(header_str(&h_dir, "x-owner"), Some("shell-slash"));
    assert!(h_dir.get("x-app").is_none());

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// A fallback candidate the static handler refuses (`..` after substitution) selected no file:
/// the 400 is the originating route's answer and carries that route's `headers` rules, exactly
/// as in v0.1.3. It must not lose them because the candidate has no normalised form.
#[tokio::test]
async fn refused_try_files_candidate_keeps_the_originating_routes_headers() -> TestResult {
    let base = std::env::temp_dir().join(format!(
        "miraserve-hdr-refused-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(base.join("pages"))?;
    std::fs::create_dir_all(base.join("archive"))?;
    std::fs::write(base.join("archive/index.html"), b"ARCHIVE")?;

    let engine = build_engine(
        &base,
        r#"
    route "/pages/*" {
        try-files "{path}" "/pages/{query}/index.html"
        headers {
            set "x-section" "pages"
        }
    }
    route "/plain/*" {
        try-files "{path}" "/plain/{query}/index.html"
    }
    route "/cross/*" {
        try-files "{path}" "/archive/{query}/index.html"
        headers {
            set "x-section" "cross"
        }
    }
    route "/archive/*" {
        static
        headers {
            set "x-section" "archive"
        }
    }
"#,
        None,
    )?;
    let ctx = https_ctx();

    let (st, h, body) = send(&engine, &ctx, Method::GET, "/pages/missing?../archive", &[]).await?;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_ne!(body.as_ref(), b"ARCHIVE");
    assert_eq!(header_str(&h, "x-section"), Some("pages"));

    // The refused candidate's text begins with ANOTHER route's prefix: the answer still carries
    // the originating route's rules (a lookup on the raw candidate would pick `archive`).
    let (st, h, _) = send(&engine, &ctx, Method::GET, "/cross/missing?../archive", &[]).await?;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(header_str(&h, "x-section"), Some("cross"));

    // An originating route without rules adds none, and no other route's rules appear.
    let (st, h, _) = send(&engine, &ctx, Method::GET, "/plain/missing?../archive", &[]).await?;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(h.get("x-section").is_none());

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// An internal rewrite to a route without `headers` rules still leaves that route's marker, so
/// the step that restores server-owned fields runs for its answer as it did in v0.1.3: of two
/// `WWW-Authenticate` fields sent by an upstream on a 401, the first one reaches the client.
/// (v0.1.3 behaviour, pinned so that it only changes deliberately.)
#[tokio::test]
async fn rewritten_proxy_401_keeps_v013_challenge_handling_without_header_rules() -> TestResult {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    let upstream = tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = Vec::with_capacity(1024);
                let mut chunk = [0_u8; 512];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut chunk).await {
                        Ok(n) if n > 0 => buf.extend_from_slice(chunk.get(..n).unwrap_or(&[])),
                        _ => return,
                    }
                }
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 401 Unauthorized\r\n\
                          www-authenticate: Bearer realm=\"api\"\r\n\
                          www-authenticate: Basic realm=\"api\"\r\n\
                          content-length: 0\r\n\
                          connection: close\r\n\r\n",
                    )
                    .await;
                let _ = sock.shutdown().await;
            });
        }
    });

    let base = std::env::temp_dir().join(format!(
        "miraserve-hdr-rewrite401-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(base.join("app"))?;
    let engine = build_engine(
        &base,
        &format!(
            r#"
    route "/auth" {{
        reverse-proxy {{
            upstream "http://127.0.0.1:{port}"
        }}
    }}
    route "/app/*" {{
        try-files "{{path}}" "/auth?{{query}}"
    }}
"#
        ),
        None,
    )?;
    let ctx = https_ctx();

    let (st, h, _) = send(&engine, &ctx, Method::GET, "/app/missing", &[]).await?;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let challenges: Vec<&str> = h
        .get_all(WWW_AUTHENTICATE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    assert_eq!(challenges, ["Bearer realm=\"api\""]);

    upstream.abort();
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

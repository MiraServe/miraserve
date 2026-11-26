//! End-to-end tests for per-site and per-route `precompressed` sibling policy, including
//! default `"off"`, encoding subsets, `"all"`, image/font sidecars, route-level `static`
//! overrides, live reload switching, and HTTP/1.1 + HTTP/2 wire behaviour.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use http::header::{ACCEPT_ENCODING, CONTENT_ENCODING, ETAG, HOST, IF_NONE_MATCH, RANGE, VARY};
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use miraserve_config::parse_kdl;
use miraserve_http::{HttpEngine, RequestContext, empty_http_body};
use miraserve_tls::AcmeChallengeStore;
use tokio::sync::watch;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn https_ctx() -> RequestContext {
    RequestContext {
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 14))),
        remote_port: Some(52_000),
        server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_port: 8443,
        is_https: true,
        tls: None,
    }
}

fn build_config(
    root: &Path,
    site_body: &str,
) -> Result<miraserve_config::Config, Box<dyn std::error::Error>> {
    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "pre.example.test" {{
    root "{root}"
{site_body}
}}
"#,
        root = root.to_string_lossy().replace('\\', "/"),
    );
    let (cfg, _) = parse_kdl("precompressed.kdl", &kdl)?;
    Ok(cfg)
}

async fn send_req(
    engine: &HttpEngine,
    method: Method,
    uri: &str,
    extra: &[(&str, &str)],
) -> Result<(StatusCode, http::HeaderMap, Bytes), Box<dyn std::error::Error>> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(HOST, "pre.example.test");
    for &(name, value) in extra {
        builder = builder.header(name, value);
    }
    let resp = engine
        .handle_request(builder.body(empty_http_body())?, &https_ctx())
        .await;
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await?.to_bytes();
    Ok((status, headers, body))
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn precompressed_default_off_subset_all_sidecars_route_override_and_reload() -> TestResult {
    let root = std::env::temp_dir().join(format!(
        "miraserve-http-precomp-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("assets"))?;
    std::fs::create_dir_all(root.join("raw"))?;
    std::fs::create_dir_all(root.join("spa"))?;

    std::fs::write(root.join("bundle.js"), b"console.log('identity');")?;
    std::fs::write(root.join("bundle.js.zst"), b"PRECOMP_ZST")?;
    std::fs::write(root.join("bundle.js.gz"), b"PRECOMP_GZ")?;

    let big_css = format!("body {{ content: \"{}\"; }}", "a".repeat(2048));
    std::fs::write(root.join("style.css"), big_css.as_bytes())?;
    std::fs::write(root.join("style.css.br"), b"FAKE_STYLE_BR")?;

    // Image & font sidecars (non-compressible MIME types).
    std::fs::write(root.join("logo.png"), b"\x89PNG\r\n\x1a\nRAW_PNG")?;
    std::fs::write(root.join("logo.png.br"), b"PRECOMP_PNG_BR")?;
    std::fs::write(root.join("type.woff2"), b"wOF2RAW_FONT")?;
    std::fs::write(root.join("type.woff2.gz"), b"PRECOMP_FONT_GZ")?;

    // Route-override directories.
    std::fs::write(root.join("assets/a.js"), b"ASSET_IDENTITY")?;
    std::fs::write(root.join("assets/a.js.br"), b"ASSET_BR")?;
    std::fs::write(root.join("raw/r.js"), b"RAW_IDENTITY")?;
    std::fs::write(root.join("raw/r.js.br"), b"RAW_BR")?;
    std::fs::write(root.join("spa/app.js"), b"SPA_IDENTITY")?;
    std::fs::write(root.join("spa/app.js.gz"), b"SPA_GZ")?;

    // 1. Omitted `precompressed` defaults to "off": identity served for small files and
    //    sidecars, while on-the-fly compression still runs for compressible files >= 1 KiB.
    //    Route-level `static { precompressed "br" }` overrides the site's "off".
    let cfg_default = build_config(
        &root,
        r#"
    route "/assets/*" {
        static {
            precompressed "br"
        }
    }
    route "/spa/*" {
        try-files "{path}" "=404"
    }
"#,
    )?;
    let engine = HttpEngine::from_config(
        &cfg_default,
        Arc::new(AcmeChallengeStore::new()),
        None,
        8443,
    )?;

    let ae = [("accept-encoding", "zstd, br, gzip")];
    let (st, hdrs, body) = send_req(&engine, Method::GET, "/bundle.js", &ae).await?;
    assert_eq!(st, StatusCode::OK);
    assert!(hdrs.get(CONTENT_ENCODING).is_none());
    assert_eq!(
        hdrs.get(VARY).and_then(|v| v.to_str().ok()),
        Some("Accept-Encoding")
    );
    assert_eq!(body.as_ref(), b"console.log('identity');");

    let (st, hdrs, body) = send_req(
        &engine,
        Method::GET,
        "/style.css",
        &[("accept-encoding", "br")],
    )
    .await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        hdrs.get(CONTENT_ENCODING).and_then(|v| v.to_str().ok()),
        Some("br")
    );
    assert_ne!(
        body.as_ref(),
        b"FAKE_STYLE_BR",
        "must compress on the fly, not serve sibling"
    );
    assert_eq!(
        miraserve_static::compress::decompress_brotli(&body)?,
        big_css.as_bytes()
    );

    let (st, hdrs, body) = send_req(&engine, Method::GET, "/logo.png", &ae).await?;
    assert_eq!(st, StatusCode::OK);
    assert!(hdrs.get(CONTENT_ENCODING).is_none());
    assert_eq!(body.as_ref(), b"\x89PNG\r\n\x1a\nRAW_PNG");

    let (st, hdrs, body) = send_req(&engine, Method::GET, "/spa/app.js", &ae).await?;
    assert_eq!(st, StatusCode::OK);
    assert!(hdrs.get(CONTENT_ENCODING).is_none());
    assert_eq!(body.as_ref(), b"SPA_IDENTITY");

    // Route override enables .br even while site default is off.
    let (st, hdrs, body) = send_req(&engine, Method::GET, "/assets/a.js", &ae).await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        hdrs.get(CONTENT_ENCODING).and_then(|v| v.to_str().ok()),
        Some("br")
    );
    assert_eq!(body.as_ref(), b"ASSET_BR");

    // 2. Reload to `precompressed "gz" "br"`: negotiation order stays `br > gz`, `.zst` ignored,
    //    `try-files` inherits site policy, and `static { precompressed "off" }` disables it on `/raw/*`.
    let cfg_subset = build_config(
        &root,
        r#"
    precompressed "gz" "br"
    route "/raw/*" {
        static {
            precompressed "off"
        }
    }
    route "/assets/*" {
        static
    }
    route "/spa/*" {
        try-files "{path}" "=404"
    }
"#,
    )?;
    engine.reload(&cfg_subset)?;

    // `.zst` is present but NOT listed -> `.gz` wins first (no `.br` yet).
    let (st, hdrs, body) = send_req(&engine, Method::GET, "/bundle.js", &ae).await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        hdrs.get(CONTENT_ENCODING).and_then(|v| v.to_str().ok()),
        Some("gzip")
    );
    assert_eq!(body.as_ref(), b"PRECOMP_GZ");

    // Publish `.br` between two requests -> `.br` wins immediately on the next request.
    std::fs::write(root.join("bundle.js.br"), b"PRECOMP_BR_NEW")?;
    let (st, hdrs, body) = send_req(&engine, Method::GET, "/bundle.js", &ae).await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        hdrs.get(CONTENT_ENCODING).and_then(|v| v.to_str().ok()),
        Some("br")
    );
    assert_eq!(body.as_ref(), b"PRECOMP_BR_NEW");

    // Image & font sidecars are served under `precompressed "gz" "br"`.
    let (st, hdrs, body) = send_req(&engine, Method::GET, "/logo.png", &ae).await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        hdrs.get(CONTENT_ENCODING).and_then(|v| v.to_str().ok()),
        Some("br")
    );
    assert_eq!(body.as_ref(), b"PRECOMP_PNG_BR");

    let (st, hdrs, body) = send_req(&engine, Method::GET, "/type.woff2", &ae).await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        hdrs.get(CONTENT_ENCODING).and_then(|v| v.to_str().ok()),
        Some("gzip")
    );
    assert_eq!(body.as_ref(), b"PRECOMP_FONT_GZ");

    // `static` route omitting `precompressed` inherits site policy (`br`, `gz`).
    let (st, hdrs, body) = send_req(&engine, Method::GET, "/assets/a.js", &ae).await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        hdrs.get(CONTENT_ENCODING).and_then(|v| v.to_str().ok()),
        Some("br")
    );
    assert_eq!(body.as_ref(), b"ASSET_BR");

    // `try-files` route inherits site policy (`br`, `gz`).
    let (st, hdrs, body) = send_req(&engine, Method::GET, "/spa/app.js", &ae).await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        hdrs.get(CONTENT_ENCODING).and_then(|v| v.to_str().ok()),
        Some("gzip")
    );
    assert_eq!(body.as_ref(), b"SPA_GZ");

    // Route-level `static { precompressed "off" }` disables sibling lookup on `/raw/*`.
    let (st, hdrs, body) = send_req(&engine, Method::GET, "/raw/r.js", &ae).await?;
    assert_eq!(st, StatusCode::OK);
    assert!(hdrs.get(CONTENT_ENCODING).is_none());
    assert_eq!(body.as_ref(), b"RAW_IDENTITY");

    // 3. Reload to `precompressed "all"`: exact v0.1.3 behaviour (`zst > br > gz`), plus 304/HEAD/Range.
    let cfg_all = build_config(&root, r#"    precompressed "all""#)?;
    engine.reload(&cfg_all)?;

    let (st, hdrs, body) = send_req(&engine, Method::GET, "/bundle.js", &ae).await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        hdrs.get(CONTENT_ENCODING).and_then(|v| v.to_str().ok()),
        Some("zstd")
    );
    assert_eq!(body.as_ref(), b"PRECOMP_ZST");
    if let Some(etag) = hdrs.get(ETAG).and_then(|v| v.to_str().ok()) {
        let (st304, _, body304) = send_req(
            &engine,
            Method::GET,
            "/bundle.js",
            &[
                ("accept-encoding", "zstd, br, gzip"),
                ("if-none-match", etag),
            ],
        )
        .await?;
        assert_eq!(st304, StatusCode::NOT_MODIFIED);
        assert!(body304.is_empty());
    }
    let (st_head, hdrs_head, body_head) =
        send_req(&engine, Method::HEAD, "/bundle.js", &ae).await?;
    assert_eq!(st_head, StatusCode::OK);
    assert_eq!(
        hdrs_head
            .get(CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        Some("zstd")
    );
    assert!(body_head.is_empty());

    let (st_range, hdrs_range, body_range) = send_req(
        &engine,
        Method::GET,
        "/bundle.js",
        &[
            ("accept-encoding", "zstd, br, gzip"),
            ("range", "bytes=0-6"),
        ],
    )
    .await?;
    assert_eq!(st_range, StatusCode::PARTIAL_CONTENT);
    assert!(hdrs_range.get(CONTENT_ENCODING).is_none());
    assert_eq!(body_range.as_ref(), b"console");

    // 4. Reload back to `precompressed "off"`: immediately stops serving siblings.
    let cfg_off = build_config(&root, r#"    precompressed "off""#)?;
    engine.reload(&cfg_off)?;
    let (st, hdrs, body) = send_req(&engine, Method::GET, "/bundle.js", &ae).await?;
    assert_eq!(st, StatusCode::OK);
    assert!(hdrs.get(CONTENT_ENCODING).is_none());
    assert_eq!(body.as_ref(), b"console.log('identity');");

    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

#[tokio::test]
async fn precompressed_policy_matches_across_h1_and_h2() -> TestResult {
    let root = std::env::temp_dir().join(format!(
        "miraserve-h12-precomp-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("app.js"), b"identity")?;
    std::fs::write(root.join("app.js.br"), b"brotli-bytes")?;

    let cfg = build_config(&root, r#"    precompressed "br""#)?;
    let engine = Arc::new(HttpEngine::from_config(
        &cfg,
        Arc::new(AcmeChallengeStore::new()),
        None,
        8443,
    )?);

    // HTTP/1.1
    let (c1, s1) = tokio::io::duplex(64 * 1024);
    let peer: SocketAddr = "198.51.100.15:50001".parse()?;
    let local: SocketAddr = "127.0.0.1:8443".parse()?;
    let (_tx1, rx1) = watch::channel(false);
    tokio::spawn(
        Arc::clone(&engine).serve_hyper_connection(s1, peer, local, true, false, None, rx1),
    );
    let (mut sender1, conn1) = http1::handshake(TokioIo::new(c1)).await?;
    let d1 = tokio::spawn(async move {
        let _ = conn1.await;
    });
    let req1 = Request::builder()
        .uri("/app.js")
        .header(HOST, "pre.example.test")
        .header(ACCEPT_ENCODING, "zstd, br, gzip")
        .body(Empty::<Bytes>::new())?;
    let resp1 = sender1.send_request(req1).await?;
    assert_eq!(resp1.status(), StatusCode::OK);
    assert_eq!(
        resp1
            .headers()
            .get(CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        Some("br")
    );
    let body1 = resp1.into_body().collect().await?.to_bytes();
    assert_eq!(body1.as_ref(), b"brotli-bytes");
    d1.abort();

    // HTTP/2
    let (c2, s2) = tokio::io::duplex(64 * 1024);
    let (_tx2, rx2) = watch::channel(false);
    tokio::spawn(
        Arc::clone(&engine).serve_hyper_connection(s2, peer, local, true, false, None, rx2),
    );
    let (mut sender2, conn2) = http2::handshake(TokioExecutor::new(), TokioIo::new(c2)).await?;
    let d2 = tokio::spawn(async move {
        let _ = conn2.await;
    });
    let req2 = Request::builder()
        .uri("https://pre.example.test/app.js")
        .header(ACCEPT_ENCODING, "zstd, br, gzip")
        .body(Empty::<Bytes>::new())?;
    let resp2 = sender2.send_request(req2).await?;
    assert_eq!(resp2.status(), StatusCode::OK);
    assert_eq!(
        resp2
            .headers()
            .get(CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        Some("br")
    );
    let body2 = resp2.into_body().collect().await?.to_bytes();
    assert_eq!(body2.as_ref(), b"brotli-bytes");
    d2.abort();

    // Unused imports check guard (ensures conditional & range constants stay exercised via tests).
    let _ = (IF_NONE_MATCH, RANGE);

    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

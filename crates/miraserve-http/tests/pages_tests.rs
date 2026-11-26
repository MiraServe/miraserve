//! Snapshot, content-negotiation, escaping, header, and security tests for MiraServe's
//! built-in error and welcome pages (`design/default-pages/` and `design/brand/`).

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use bytes::Bytes;
use http::header::{
    ACCEPT, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_SECURITY_POLICY, CONTENT_TYPE, RETRY_AFTER,
    SERVER, VARY, X_CONTENT_TYPE_OPTIONS,
};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use http_body_util::BodyExt as _;
use miraserve_http::pages::{
    CustomErrorPage, DeterministicRenderOptions, ErrorPageContext, PageFormat, SiteErrorPages,
    WelcomePageContext, catalog_status_codes, format_unix_secs_utc, generate_csp_nonce,
    generate_request_id, is_safe_action_href, negotiate_format, render_error_html_deterministic,
    render_error_html_preview_compat, render_error_markdown, render_error_problem_json,
    render_error_response, render_error_text, render_welcome_html_deterministic,
    render_welcome_response,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn design_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("design")
}

fn preview_opts() -> DeterministicRenderOptions<'static> {
    DeterministicRenderOptions {
        path: "/old-pricing",
        host: "shop.example.com",
        method: "DELETE",
        request_id: "01JDV8K3N7Q2X4M6ZP",
        time_utc: "2026-11-19 08:42:10 UTC",
        csp_nonce: "PREVIEW",
        retry_after_secs: Some(30),
        login_url: Some("/login"),
    }
}

#[test]
fn snapshot_all_12_error_pages_and_welcome_match_design_previews() -> TestResult {
    let expected_codes = [400, 401, 403, 404, 405, 408, 413, 429, 500, 502, 503, 504];
    assert_eq!(catalog_status_codes(), expected_codes);

    let opts = preview_opts();
    let previews_dir = design_dir().join("default-pages").join("previews");

    for code in expected_codes {
        let status = StatusCode::from_u16(code)?;
        let compat_html = render_error_html_preview_compat(status, &opts);
        let live_html = render_error_html_deterministic(status, &opts);

        // Runtime HTML must carry the exact same markup, using RFC 3986 same-document reload `href=""`
        // for empty action hrefs per design/README.md.
        assert!(live_html.contains("<meta name=\"robots\" content=\"noindex\">"));
        assert!(live_html.contains("<style nonce=\"PREVIEW\">"));
        assert!(live_html.contains("Served by MiraServe"));
        assert!(
            !live_html.contains("style=\""),
            "inline style attr violates strict nonce CSP"
        );
        assert!(
            !live_html.contains("{{"),
            "unreplaced template placeholder in {code}"
        );

        // Snapshot comparison against design/default-pages/previews/{code}.html when design/ is present.
        let preview_file = previews_dir.join(format!("{code}.html"));
        if preview_file.exists() {
            let expected = fs::read_to_string(&preview_file)?;
            assert_eq!(
                compat_html, expected,
                "rendered {code}.html diverged from design/default-pages/previews/{code}.html"
            );
            assert_eq!(
                live_html.replace("href=\"\"", "href=\"./\""),
                expected,
                "live {code}.html diverged outside empty-href reload semantics"
            );
        }
    }

    // Welcome page snapshot check (with footer border:0 cleanly moved into nonce'd <style>).
    let welcome_html = render_welcome_html_deterministic(
        "example.com",
        "TLS 1.3 · post-quantum",
        "HTTP/3",
        "Enabled",
        "PREVIEW",
    );
    assert!(welcome_html.contains("<meta name=\"robots\" content=\"noindex\">"));
    assert!(welcome_html.contains("<style nonce=\"PREVIEW\">"));
    assert!(welcome_html.contains("MiraServe is up and serving"));
    assert!(welcome_html.contains("footer{border:0}"));
    assert!(
        !welcome_html.contains("style=\""),
        "welcome.html must not contain inline style attributes under strict CSP"
    );
    assert!(!welcome_html.contains("{{"));

    let welcome_preview = previews_dir.join("welcome.html");
    if welcome_preview.exists() {
        let expected_welcome = fs::read_to_string(&welcome_preview)?;
        let normalized_expected = expected_welcome
            .replace(
                "a{color:#0062D9}@media (prefers-color-scheme:dark){a{color:#7DD3FC}}\n</style>",
                "a{color:#0062D9}@media (prefers-color-scheme:dark){a{color:#7DD3FC}}\nfooter{border:0}\n</style>",
            )
            .replace(
                "<footer style=\"border:0\">Served by MiraServe</footer>",
                "<footer>Served by MiraServe</footer>",
            );
        assert_eq!(
            welcome_html, normalized_expected,
            "rendered welcome.html diverged from design/default-pages/previews/welcome.html"
        );
    }

    // Verify embedded template assets remain synced with design/default-pages/ when present.
    let design_default = design_dir().join("default-pages");
    let crate_assets = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join("default-pages");
    if design_default.exists() {
        for (src_rel, dst_name) in [
            ("messages.json", "messages.json"),
            ("templates/extras.json", "extras.json"),
            ("templates/error.html", "error.html"),
            ("templates/error.problem.json", "error.problem.json"),
            ("templates/error.md", "error.md"),
            ("templates/error.txt", "error.txt"),
        ] {
            assert_eq!(
                fs::read_to_string(crate_assets.join(dst_name))?,
                fs::read_to_string(design_default.join(src_rel))?,
                "embedded asset {dst_name} drifted from design/default-pages/{src_rel}"
            );
        }
    }
    Ok(())
}

#[test]
fn content_negotiation_honors_accept_qvalues_and_precedence() {
    let fmt = |accept: Option<&str>| {
        let mut h = HeaderMap::new();
        if let Some(a) = accept
            && let Ok(v) = HeaderValue::from_str(a)
        {
            h.insert(ACCEPT, v);
        }
        negotiate_format(&h)
    };

    // Omitted or wildcard -> plain text (curl / */*)
    assert_eq!(fmt(None), PageFormat::Text);
    assert_eq!(fmt(Some("*/*")), PageFormat::Text);
    assert_eq!(fmt(Some("text/plain, */*;q=0.5")), PageFormat::Text);
    assert_eq!(
        fmt(Some("image/avif,image/webp,*/*;q=0.8")),
        PageFormat::Text
    );

    // Real browsers -> HTML
    assert_eq!(
        fmt(Some(
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8"
        )),
        PageFormat::Html
    );

    // API clients -> RFC 9457 JSON
    assert_eq!(fmt(Some("application/json")), PageFormat::ProblemJson);
    assert_eq!(
        fmt(Some("application/problem+json")),
        PageFormat::ProblemJson
    );
    assert_eq!(
        fmt(Some("text/html;q=0.5, application/json;q=0.9")),
        PageFormat::ProblemJson
    );

    // AI agents -> Markdown
    assert_eq!(fmt(Some("text/markdown")), PageFormat::Markdown);
    assert_eq!(
        fmt(Some("text/markdown, text/html;q=0.8")),
        PageFormat::Markdown
    );
    assert_eq!(
        fmt(Some("text/html;q=0.9, text/markdown;q=0.5")),
        PageFormat::Html
    );

    // Explicit q=0 excludes a format
    assert_eq!(fmt(Some("text/html;q=0, */*;q=0.8")), PageFormat::Text);
    assert_eq!(
        fmt(Some("application/json;q=0, text/markdown;q=0.7")),
        PageFormat::Markdown
    );

    // Pathological huge Accept header never panics and stays bounded
    let huge = vec!["image/png"; 128].join(", ");
    assert_eq!(fmt(Some(&huge)), PageFormat::Text);
}

#[test]
fn escaping_defeats_xss_json_breakout_markdown_injection_and_unsafe_login_url() -> TestResult {
    let hostile = DeterministicRenderOptions {
        path: "/x\"><script>alert(1)</script>\r\n[click](https://evil.test)`code`",
        host: "evil\"><img src=x onerror=alert(1)>'&host",
        method: "GET<script>\"'&",
        request_id: "REQ<1>\"'&",
        time_utc: "2026-11-19 08:42:10 UTC",
        csp_nonce: "NONCE123",
        retry_after_secs: Some(30),
        login_url: Some("javascript:alert(1)"),
    };

    // 1. HTML escaping + unsafe login_url rejection on 401
    let html_401 = render_error_html_deterministic(StatusCode::UNAUTHORIZED, &hostile);
    assert!(!html_401.contains("<script>"));
    assert!(!html_401.contains("<img "));
    assert!(!html_401.contains("javascript:"));
    assert!(html_401.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(html_401.contains("&quot;"));
    assert!(html_401.contains("&#39;"));
    assert!(html_401.contains("&amp;"));
    // Unsafe login_url must drop Sign in and promote Go to homepage to btn primary.
    assert!(html_401.contains("<a class=\"btn primary\" href=\"/\">Go to homepage</a>"));
    assert!(!html_401.contains("Sign in</a>"));

    // 2. Method escaping on 405
    let html_405 = render_error_html_deterministic(StatusCode::METHOD_NOT_ALLOWED, &hostile);
    assert!(!html_405.contains("<script>"));
    assert!(html_405.contains("GET&lt;script&gt;&quot;&#39;&amp;"));

    // 3. Valid RFC 9457 JSON despite quotes, backslashes, and control characters
    let json_404 = render_error_problem_json(StatusCode::NOT_FOUND, &hostile);
    let parsed: serde_json::Value = serde_json::from_str(&json_404)?;
    assert_eq!(
        parsed.get("type").and_then(|v| v.as_str()),
        Some("about:blank")
    );
    assert_eq!(
        parsed.get("title").and_then(|v| v.as_str()),
        Some("Not Found")
    );
    assert_eq!(
        parsed.get("status").and_then(serde_json::Value::as_u64),
        Some(404)
    );
    assert!(
        parsed
            .get("instance")
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.contains('\r') && !s.contains('\n'))
    );
    assert!(
        parsed
            .get("detail")
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.contains("<code>") && !s.contains("</code>"))
    );

    // 4. Markdown escaping neutralizes link injection, raw HTML, and newline prompt injection
    let md_404 = render_error_markdown(StatusCode::NOT_FOUND, &hostile);
    assert!(!md_404.contains("<script>"));
    assert!(!md_404.contains("[click](https://evil.test)"));
    assert!(md_404.contains("\\[click\\]"));
    assert!(md_404.contains("&lt;script&gt;"));

    // 5. Plain text strips CR/LF controls and HTML tags
    let txt_404 = render_error_text(StatusCode::NOT_FOUND, &hostile);
    assert!(txt_404.starts_with("404 Not Found\n\n"));
    assert!(!txt_404.contains("<code>"));
    assert!(!txt_404.contains('\r'));

    // 6. Welcome page escapes hostile host in BOTH <b> and <pre>
    let welcome_html = render_welcome_html_deterministic(
        "evil.com\"<script>alert(1)</script>",
        "TLS 1.3",
        "HTTP/2",
        "Enabled",
        "NONCE",
    );
    assert!(!welcome_html.contains("<script>"));
    assert!(welcome_html.contains("evil.com&quot;&lt;script&gt;alert(1)&lt;/script&gt;"));

    // 7. Safe action href validator
    assert!(is_safe_action_href(""));
    assert!(is_safe_action_href("/login"));
    assert!(is_safe_action_href("/auth/login?next=/app"));
    assert!(is_safe_action_href("https://sso.example.com/login"));
    assert!(!is_safe_action_href("//evil.example/phish"));
    assert!(!is_safe_action_href("javascript:alert(1)"));
    assert!(!is_safe_action_href("data:text/html,<script>"));
    assert!(!is_safe_action_href("/login\r\nSet-Cookie: a=b"));
    Ok(())
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn built_in_responses_set_strict_headers_unique_nonces_retry_after_and_zero_leaks()
-> TestResult {
    // Check uniqueness of CSP nonces and Crockford Base32 ULID request IDs
    let mut nonces = HashSet::new();
    let mut req_ids = HashSet::new();
    let crockford_alphabet = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    for _ in 0..32 {
        let n = generate_csp_nonce();
        let id = generate_request_id();
        assert!(n.len() >= 20, "nonce must carry >= 128 bits of entropy");
        assert_eq!(id.len(), 26, "request ID should be a 26-char ULID");
        assert!(
            id.bytes().all(|b| crockford_alphabet.contains(&b)),
            "unexpected char in request ID: {id}"
        );
        assert!(nonces.insert(n), "duplicate CSP nonce generated");
        assert!(req_ids.insert(id), "duplicate request ID generated");
    }

    // Verify timestamp prefix accuracy and uniqueness across >1000 IDs (spanning multiple
    // thread-local CSPRNG refills) and concurrent threads.
    let before_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();
    let sample_id = generate_request_id();
    let after_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();
    let mut decoded_ms: u128 = 0;
    for b in sample_id.bytes().take(10) {
        let digit = crockford_alphabet
            .iter()
            .position(|&c| c == b)
            .ok_or("non-Crockford digit")?;
        decoded_ms = (decoded_ms << 5) | (digit as u128);
    }
    assert!(
        decoded_ms >= before_ms && decoded_ms <= after_ms,
        "ULID timestamp {decoded_ms} outside [{before_ms}, {after_ms}] for {sample_id}"
    );
    let mut handles = Vec::new();
    for _ in 0..4 {
        handles.push(std::thread::spawn(|| {
            (0..300).map(|_| generate_request_id()).collect::<Vec<_>>()
        }));
    }
    let mut all_ids = HashSet::with_capacity(1200);
    for h in handles {
        let batch = h.join().map_err(|_| "request id thread panicked")?;
        for id in batch {
            assert_eq!(id.len(), 26);
            assert!(id.bytes().all(|b| crockford_alphabet.contains(&b)));
            assert!(all_ids.insert(id), "duplicate request ID across threads");
        }
    }

    // Verify 429 HTML response carries dynamic Retry-After + matching CSS --retry + strict CSP
    let mut html_accept = HeaderMap::new();
    html_accept.insert(ACCEPT, HeaderValue::from_static("text/html"));
    let req_id = generate_request_id();
    let resp_429 = render_error_response(
        &html_accept,
        &ErrorPageContext {
            status: StatusCode::TOO_MANY_REQUESTS,
            method: &Method::GET,
            path: "/api/search",
            host: Some("api.example.com"),
            request_id: &req_id,
            retry_after_secs: Some(17),
            site_pages: None,
        },
    );
    assert_eq!(resp_429.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        resp_429
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(
        resp_429.headers().get(VARY).and_then(|v| v.to_str().ok()),
        Some("Accept")
    );
    assert_eq!(
        resp_429
            .headers()
            .get(X_CONTENT_TYPE_OPTIONS)
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        resp_429
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        resp_429
            .headers()
            .get(RETRY_AFTER)
            .and_then(|v| v.to_str().ok()),
        Some("17")
    );
    assert_eq!(
        resp_429.headers().get(SERVER).and_then(|v| v.to_str().ok()),
        Some("MiraServe")
    );
    assert_eq!(
        resp_429
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok()),
        Some(req_id.as_str())
    );
    let csp = resp_429
        .headers()
        .get(CONTENT_SECURITY_POLICY)
        .and_then(|v| v.to_str().ok())
        .ok_or("missing Content-Security-Policy header")?;
    assert!(csp.starts_with("default-src 'none'; style-src 'nonce-"));
    assert!(csp.ends_with(
        "'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ));
    let nonce = csp
        .strip_prefix("default-src 'none'; style-src 'nonce-")
        .and_then(|s| s.split('\'').next())
        .ok_or("failed to parse CSP nonce")?
        .to_owned();

    let body_429 = String::from_utf8(resp_429.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(body_429.contains(&format!("<style nonce=\"{nonce}\">")));
    assert!(body_429.contains(":root{--retry:17s}"));
    assert!(body_429.contains("You can try again in 17 seconds"));
    assert!(body_429.contains(&req_id));
    // Zero leakage of version, OS, paths, or upstream internals.
    for forbidden in [
        "0.1.0",
        "alpha",
        "darwin",
        "linux",
        "windows",
        "/var/www",
        "127.0.0.1",
    ] {
        assert!(
            !body_429.to_ascii_lowercase().contains(forbidden),
            "error page leaked forbidden string '{forbidden}'"
        );
    }

    // 503 always carries Retry-After even when caller omits retry_after_secs.
    let resp_503 = render_error_response(
        &html_accept,
        &ErrorPageContext {
            status: StatusCode::SERVICE_UNAVAILABLE,
            method: &Method::GET,
            path: "/",
            host: Some("shop.example.com"),
            request_id: &req_id,
            retry_after_secs: None,
            site_pages: None,
        },
    );
    assert_eq!(
        resp_503
            .headers()
            .get(RETRY_AFTER)
            .and_then(|v| v.to_str().ok()),
        Some("30")
    );

    // HEAD response carries Content-Length + headers but empty body.
    let head_resp = render_error_response(
        &html_accept,
        &ErrorPageContext {
            status: StatusCode::NOT_FOUND,
            method: &Method::HEAD,
            path: "/missing",
            host: Some("shop.example.com"),
            request_id: &req_id,
            retry_after_secs: None,
            site_pages: None,
        },
    );
    assert!(
        head_resp
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok())
            .is_some_and(|n| n > 1_000)
    );
    let head_bytes = head_resp.into_body().collect().await?.to_bytes();
    assert!(
        head_bytes.is_empty(),
        "HEAD error response must have empty body"
    );

    // Per-site custom HTML override serves custom bytes for HTML, while JSON still renders RFC 9457.
    let mut site_pages = SiteErrorPages {
        login_url: Some("/signin".to_owned()),
        pages: std::collections::BTreeMap::new(),
    };
    site_pages.pages.insert(
        404,
        CustomErrorPage {
            body: Bytes::from_static(b"<html><body>Custom 404</body></html>"),
            content_type: "text/html; charset=utf-8",
        },
    );
    let custom_html = render_error_response(
        &html_accept,
        &ErrorPageContext {
            status: StatusCode::NOT_FOUND,
            method: &Method::GET,
            path: "/nope",
            host: Some("shop.example.com"),
            request_id: &req_id,
            retry_after_secs: None,
            site_pages: Some(&site_pages),
        },
    );
    assert_eq!(custom_html.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        custom_html.into_body().collect().await?.to_bytes().as_ref(),
        b"<html><body>Custom 404</body></html>"
    );

    // Embedder API parity with v0.1.2: an invalid custom `content_type` (e.g. embedded newline)
    // must never panic; it returns the requested error status with an empty body.
    let mut bad_ct_pages = SiteErrorPages::default();
    bad_ct_pages.pages.insert(
        404,
        CustomErrorPage {
            body: Bytes::from_static(b"<html>bad</html>"),
            content_type: "text/html\n",
        },
    );
    let bad_ct_resp = render_error_response(
        &html_accept,
        &ErrorPageContext {
            status: StatusCode::NOT_FOUND,
            method: &Method::GET,
            path: "/bad-ct",
            host: Some("shop.example.com"),
            request_id: &req_id,
            retry_after_secs: None,
            site_pages: Some(&bad_ct_pages),
        },
    );
    assert_eq!(bad_ct_resp.status(), StatusCode::NOT_FOUND);
    assert!(
        bad_ct_resp
            .into_body()
            .collect()
            .await?
            .to_bytes()
            .is_empty(),
        "invalid CustomErrorPage content_type must fall back to an empty body"
    );

    // HANDOVER §5 #11: `Accept: */*`, `Accept: text/*`, and omitted `Accept` (curl/browser
    // defaults) ALSO receive the site's custom HTML error page, while explicit `text/plain`
    // (without wildcard) still negotiates plain text!
    for hdr_val in [None, Some("*/*"), Some("text/*")] {
        let mut hdrs = HeaderMap::new();
        if let Some(v) = hdr_val {
            hdrs.insert(ACCEPT, HeaderValue::from_str(v)?);
        }
        let resp = render_error_response(
            &hdrs,
            &ErrorPageContext {
                status: StatusCode::NOT_FOUND,
                method: &Method::GET,
                path: "/nope",
                host: Some("shop.example.com"),
                request_id: &req_id,
                retry_after_secs: None,
                site_pages: Some(&site_pages),
            },
        );
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            resp.into_body().collect().await?.to_bytes().as_ref(),
            b"<html><body>Custom 404</body></html>",
            "expected custom error page for Accept={hdr_val:?}"
        );
    }

    let mut plain_only = HeaderMap::new();
    plain_only.insert(ACCEPT, HeaderValue::from_static("text/plain"));
    let plain_404 = render_error_response(
        &plain_only,
        &ErrorPageContext {
            status: StatusCode::NOT_FOUND,
            method: &Method::GET,
            path: "/nope",
            host: Some("shop.example.com"),
            request_id: &req_id,
            retry_after_secs: None,
            site_pages: Some(&site_pages),
        },
    );
    assert_eq!(
        plain_404
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/plain; charset=utf-8")
    );

    let mut json_accept = HeaderMap::new();
    json_accept.insert(ACCEPT, HeaderValue::from_static("application/json"));
    let json_404 = render_error_response(
        &json_accept,
        &ErrorPageContext {
            status: StatusCode::NOT_FOUND,
            method: &Method::GET,
            path: "/nope",
            host: Some("shop.example.com"),
            request_id: &req_id,
            retry_after_secs: None,
            site_pages: Some(&site_pages),
        },
    );
    assert_eq!(
        json_404
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/problem+json; charset=utf-8")
    );
    let json_body: serde_json::Value =
        serde_json::from_slice(&json_404.into_body().collect().await?.to_bytes())?;
    assert_eq!(
        json_body.get("status").and_then(serde_json::Value::as_u64),
        Some(404)
    );
    assert_eq!(
        json_body.get("instance").and_then(|v| v.as_str()),
        Some("/nope")
    );
    assert_eq!(
        json_body.get("request_id").and_then(|v| v.as_str()),
        Some(req_id.as_str())
    );

    // Welcome page across HTML, JSON, Markdown, and plain text.
    let welcome_ctx = WelcomePageContext {
        method: &Method::GET,
        host: Some("newsite.example"),
        tls_summary: "TLS 1.3 · post-quantum",
        protocol: "HTTP/3",
        sandbox_state: "Enabled",
        request_id: &req_id,
    };
    let w_html = render_welcome_response(&html_accept, &welcome_ctx);
    assert_eq!(w_html.status(), StatusCode::OK);
    assert_eq!(
        w_html.headers().get(VARY).and_then(|v| v.to_str().ok()),
        Some("Accept")
    );
    assert!(w_html.headers().contains_key(CONTENT_SECURITY_POLICY));
    let w_html_str = String::from_utf8(w_html.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(w_html_str.contains("newsite.example"));
    assert!(w_html_str.contains("TLS 1.3 · post-quantum"));

    let w_json = render_welcome_response(&json_accept, &welcome_ctx);
    let w_json_val: serde_json::Value =
        serde_json::from_slice(&w_json.into_body().collect().await?.to_bytes())?;
    assert_eq!(
        w_json_val.get("status").and_then(|v| v.as_str()),
        Some("running")
    );
    assert_eq!(
        w_json_val.get("host").and_then(|v| v.as_str()),
        Some("newsite.example")
    );
    assert_eq!(
        w_json_val.get("request_id").and_then(|v| v.as_str()),
        Some(req_id.as_str())
    );

    let mut md_accept = HeaderMap::new();
    md_accept.insert(ACCEPT, HeaderValue::from_static("text/markdown"));
    let w_md = render_welcome_response(&md_accept, &welcome_ctx);
    assert_eq!(
        w_md.headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/markdown; charset=utf-8")
    );

    let w_txt = render_welcome_response(&HeaderMap::new(), &welcome_ctx);
    assert_eq!(
        w_txt
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/plain; charset=utf-8")
    );
    Ok(())
}

#[test]
fn utc_timestamp_formatting_and_unlisted_status_fallback() {
    assert_eq!(format_unix_secs_utc(0), "1970-01-01 00:00:00 UTC");
    assert_eq!(
        format_unix_secs_utc(1_709_251_199),
        "2024-02-29 23:59:59 UTC"
    );
    assert_eq!(
        format_unix_secs_utc(1_795_077_730),
        "2026-11-19 08:42:10 UTC"
    );

    // Unlisted 4xx/5xx (421, 431, 501) render cleanly with zero unresolved placeholders.
    let opts = preview_opts();
    for status in [
        StatusCode::MISDIRECTED_REQUEST,
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
        StatusCode::NOT_IMPLEMENTED,
    ] {
        let html = render_error_html_deterministic(status, &opts);
        assert!(html.contains(&status.as_u16().to_string()));
        assert!(!html.contains("{{"));
        assert!(!html.contains("style=\""));
    }
}

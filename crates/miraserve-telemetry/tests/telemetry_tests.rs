//! Tests for Prometheus exposition, secret redaction, live metrics scraping, and OTLP export.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::header::{AUTHORIZATION, COOKIE, HOST, HeaderName, HeaderValue, USER_AGENT};
use http::{HeaderMap, Request, Response, StatusCode};
use http_body_util::{BodyExt as _, Empty, Full};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use miraserve_telemetry::{
    AccessLogRecord, FileCacheOutcome, MetricsServer, OtlpExporter, PROMETHEUS_CONTENT_TYPE,
    SecurityBlockReason, TelemetryRegistry, redact_request_target, redact_uri_query,
};
use tokio::net::{TcpListener, TcpStream};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn redacts_secrets_in_query_strings_and_headers() {
    assert_eq!(
        redact_uri_query("/mcp/rpc?token=supersecret123&q=rust&api_key=sk-ant-12345"),
        "/mcp/rpc?token=[REDACTED]&q=rust&api_key=[REDACTED]"
    );
    // R2-TEL-1: `code`, `pass`, `pwd`, `otp` query parameters redacted while benign words preserved
    assert_eq!(
        redact_uri_query("/cb?code=oauth123&pass=p1&pwd=p2&otp=999999&encode=utf8"),
        "/cb?code=[REDACTED]&pass=[REDACTED]&pwd=[REDACTED]&otp=[REDACTED]&encode=utf8"
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer eyJhbGciOi.abc.def"),
    );
    headers.insert(COOKIE, HeaderValue::from_static("session=xyz999"));
    headers.insert(
        HeaderName::from_static("x-api-key"),
        HeaderValue::from_static("secret-key-42"),
    );
    headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0"));

    let rec = AccessLogRecord::build(
        "GET",
        "/v1/search?q=pqc&access_token=topsecret",
        "h3",
        200,
        1420,
        &headers,
        true,
    );
    assert_eq!(rec.target, "/v1/search?q=pqc&access_token=[REDACTED]");
    assert_eq!(
        rec.headers.get("authorization").map(String::as_str),
        Some("[REDACTED]")
    );
    assert_eq!(
        rec.headers.get("cookie").map(String::as_str),
        Some("[REDACTED]")
    );
    assert_eq!(
        rec.headers.get("x-api-key").map(String::as_str),
        Some("[REDACTED]")
    );
    assert_eq!(
        rec.headers.get("user-agent").map(String::as_str),
        Some("Mozilla/5.0")
    );
}

#[test]
fn redaction_blocks_semicolon_percent_encoding_referer_duplicates_and_log_injection() {
    // Semicolon-delimited query secret, percent-encoded key, suffixed key, keyless secret, URL-encoded Bearer
    assert_eq!(
        redact_uri_query(
            "/api?q=1;token=s3cr3t&%74oken=abc&token_v2=xyz&sk-ant-999&a=Bearer%20tok"
        ),
        "/api?q=1;token=[REDACTED]&%74oken=[REDACTED]&token_v2=[REDACTED]&[REDACTED]&a=[REDACTED]"
    );

    // Control characters and Unicode line separators are escaped
    let injected = redact_uri_query("/path\r\nFAKE\u{2028}LOG?q=ok\x1b[31m");
    assert!(!injected.contains('\r'));
    assert!(!injected.contains('\n'));
    assert!(!injected.contains('\u{2028}'));
    assert!(!injected.contains('\x1b'));

    // Referer query scrubbing, underscore header names, and duplicate header joining
    let mut headers = HeaderMap::new();
    headers.append(
        HeaderName::from_static("referer"),
        HeaderValue::from_static("https://app.example/cb?access_token=topsecret&ok=1"),
    );
    headers.append(
        HeaderName::from_static("x-api_key"),
        HeaderValue::from_static("k-123"),
    );
    headers.append(
        HeaderName::from_static("x-trace"),
        HeaderValue::from_static("one"),
    );
    headers.append(
        HeaderName::from_static("x-trace"),
        HeaderValue::from_static("two"),
    );

    let rec = AccessLogRecord::build("GET\n", "/ok", "h2\r", 200, 10, &headers, true);
    assert_eq!(rec.method, "GET\\n");
    assert_eq!(rec.protocol, "h2\\r");
    assert_eq!(
        rec.headers.get("referer").map(String::as_str),
        Some("https://app.example/cb?access_token=[REDACTED]&ok=1")
    );
    assert_eq!(
        rec.headers.get("x-api_key").map(String::as_str),
        Some("[REDACTED]")
    );
    assert_eq!(
        rec.headers.get("x-trace").map(String::as_str),
        Some("one, two")
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn live_prometheus_scrape_and_otlp_json_export() -> TestResult {
    let reg = Arc::new(TelemetryRegistry::new());
    reg.inc_active_connections();
    reg.record_tls_handshake(true, true);
    reg.record_http_request("h3", 200, Duration::from_millis(4));
    reg.record_security_block(SecurityBlockReason::McpRbac);
    reg.record_wasm_invocation("ok", 12_500);
    reg.record_file_cache_event(FileCacheOutcome::Hit);
    reg.record_file_cache_event(FileCacheOutcome::Hit);
    reg.record_file_cache_event(FileCacheOutcome::Miss);
    reg.record_file_cache_event(FileCacheOutcome::Fill);
    reg.record_file_cache_event(FileCacheOutcome::NotCachedBudget);
    assert_eq!(reg.file_cache_counts(), (2, 1, 1, 1));

    // 1. Live Prometheus scrape over HTTP/1.1
    let metrics_srv = MetricsServer::start(
        "127.0.0.1:0".parse()?,
        "/metrics".to_owned(),
        Arc::clone(&reg),
    )
    .await?;
    let tcp = TcpStream::connect(metrics_srv.local_addr()).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let resp = sender
        .send_request(
            Request::builder()
                .uri("/metrics")
                .header(HOST, "127.0.0.1")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some(PROMETHEUS_CONTENT_TYPE)
    );
    let body = String::from_utf8(resp.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(body.contains("miraserve_http_requests_total{protocol=\"h3\",status_class=\"2xx\"} 1"));
    assert!(
        body.contains("miraserve_tls_handshakes_total{pqc=\"true\",isolation=\"split-daemon\"} 1")
    );
    assert!(body.contains("miraserve_security_blocks_total{reason=\"mcp_rbac\"} 1"));
    assert!(body.contains("miraserve_wasm_fuel_consumed_total 12500"));
    assert!(body.contains("miraserve_file_cache_events_total{outcome=\"hit\"} 2"));
    assert!(body.contains("miraserve_file_cache_events_total{outcome=\"miss\"} 1"));
    assert!(body.contains("miraserve_file_cache_events_total{outcome=\"fill\"} 1"));
    assert!(body.contains("miraserve_file_cache_events_total{outcome=\"not_cached_budget\"} 1"));
    conn_task.abort();
    metrics_srv.shutdown().await;

    // 2. Live OTLP/HTTP JSON collector export
    let received_otlp: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));
    let otlp_listener = TcpListener::bind("127.0.0.1:0").await?;
    let otlp_addr = otlp_listener.local_addr()?;
    let recv_c = Arc::clone(&received_otlp);
    let otlp_task = tokio::spawn(async move {
        if let Ok((stream, _)) = otlp_listener.accept().await {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                let recv_inner = Arc::clone(&recv_c);
                async move {
                    let bytes = req
                        .into_body()
                        .collect()
                        .await
                        .map(http_body_util::Collected::to_bytes)
                        .unwrap_or_default();
                    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&bytes)
                        && let Ok(mut guard) = recv_inner.lock()
                    {
                        *guard = Some(val);
                    }
                    Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from_static(
                        b"{}",
                    ))))
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .keep_alive(false)
                .serve_connection(io, svc)
                .await;
        }
    });

    let exporter = OtlpExporter::new(&format!("http://{otlp_addr}"), "miraserve-test")?;
    let status = exporter.export_once(&reg).await?;
    assert_eq!(status, StatusCode::OK);
    drop(exporter);
    let _ = otlp_task.await;

    let captured = received_otlp
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .ok_or("missing captured OTLP payload")?;
    assert_eq!(
        captured
            .pointer("/resourceMetrics/0/resource/attributes/0/value/stringValue")
            .and_then(serde_json::Value::as_str),
        Some("miraserve-test")
    );
    assert_eq!(
        captured
            .pointer("/resourceMetrics/0/scopeMetrics/0/metrics/3/name")
            .and_then(serde_json::Value::as_str),
        Some("miraserve.file_cache.events")
    );
    Ok(())
}

/// Logged URLs lose the user and password of an absolute URL, credentials in a fragment, and
/// path segments that look like credentials (Cloudflare-skills audit of v0.1.0, claim 14);
/// ordinary paths, queries and fragments stay readable.
#[test]
#[allow(clippy::too_many_lines)]
fn logged_urls_lose_userinfo_fragment_and_path_credentials() {
    for (raw, logged) in [
        (
            "https://ann:s3cret@app.example.test/cb?state=ok",
            "https://[REDACTED]@app.example.test/cb?state=ok",
        ),
        (
            "https://app.example.test/cb#access_token=abc123&state=ok",
            "https://app.example.test/cb#access_token=[REDACTED]&state=ok",
        ),
        // A route in the fragment with parameters of its own (Codex 79).
        (
            "https://app.example.test/#/callback?code=472619&state=ok",
            "https://app.example.test/#/callback?code=[REDACTED]&state=ok",
        ),
        (
            "https://app.example.test/a?x=1#/callback?code=472619",
            "https://app.example.test/a?x=1#/callback?code=[REDACTED]",
        ),
        // Parameters before a value that is a URL with parameters of its own (Codex 80).
        (
            "https://site.test/?view=1#state=ok&code=472619&next=/app?lang=en",
            "https://site.test/?view=1#state=ok&code=[REDACTED]&next=/app?lang=en",
        ),
        (
            "https://site.test/?next=/cb?code=472619&view=1",
            "https://site.test/?next=/cb?code=[REDACTED]&view=1",
        ),
        // A sensitive value is redacted whole, also with a `?` in it (Codex 81); a value
        // that is a URL keeps its own parameters apart.
        (
            "/callback?password=left?right",
            "/callback?password=[REDACTED]",
        ),
        (
            "/callback?password=left?right=1&ok=2",
            "/callback?password=[REDACTED]&ok=2",
        ),
        (
            "/go?next=/a?b=1?token=abc&view=2",
            "/go?next=/a?b=1?token=[REDACTED]&view=2",
        ),
        ("/search?q=what?&page=2", "/search?q=what?&page=2"),
        // A route in a fragment is checked like any path piece (Codex 83).
        (
            "https://app.example.test/?view=1#/preview/ghp_abcdefghijklmnopqrstuvwxyz0123456789?page=2",
            "https://app.example.test/?view=[REDACTED]",
        ),
        (
            "https://app.example.test/#/preview/item?page=2",
            "https://app.example.test/#/preview/item?page=2",
        ),
        // Also when the parameter behind the route is a sensitive one (Codex 84): the name is
        // checked like everything else that is written.
        (
            "https://app.example.test/?view=1#/preview/ghp_abcdefghijklmnopqrstuvwxyz0123456789?token=abc",
            "https://app.example.test/?view=[REDACTED]",
        ),
        (
            "/cb?x=1&/hooks/ghp_abcdefghijklmnopqrstuvwxyz0123456789?page=2",
            "/cb?x=1&[REDACTED]?page=2",
        ),
        (
            "/cb?ghp_abcdefghijklmnopqrstuvwxyz0123456789=1&ok=2",
            "/cb?[REDACTED]&ok=2",
        ),
        // A credential in front of a `=` that is part of it (Antigravity 40).
        (
            "https://app.example.test/?view=1#Basic%20YWxpY2U6c2VjcmV0MQ==",
            "https://app.example.test/?view=[REDACTED]",
        ),
        (
            "https://app.example.test/?view=1#Bearer%20abcdefghijklmnopqrstuvwxyz012345=",
            "https://app.example.test/?view=[REDACTED]",
        ),
        (
            "https://app.example.test/?view=1#/preview/ghp_abcdefghijklmnopqrstuvwxyz0123456789/tab=details",
            "https://app.example.test/?view=[REDACTED]",
        ),
        (
            "https://app.example.test/?view=1#/preview/ghp_abcdefghijklmnopqrstuvwxyz0123456789?next=ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            "https://app.example.test/?view=[REDACTED]",
        ),
        // What v0.1.0 redacted is redacted the same way: its query runs from the first `?`
        // to the end, a fragment included (Codex 85).
        (
            "https://app.example.test/#/step=login?eyJ_password=?orchid",
            "https://app.example.test/#/step=login?[REDACTED]=[REDACTED]",
        ),
        (
            "https://app.example.test/share?token=demo#next=https://reader:example-pass@files.example.test/private",
            "https://app.example.test/share?token=[REDACTED]",
        ),
        (
            "https://app.example.test/cb?x=1#access_token=abc123&state=ok",
            "https://app.example.test/cb?x=1#access_token=[REDACTED]&state=ok",
        ),
        (
            "https://app.example.test/cb#state=ok&code=472619",
            "https://app.example.test/cb#state=ok&code=[REDACTED]",
        ),
        // The whole name is judged first, as in v0.1.0 (Codex 82).
        (
            "/reset?reset_token?format=example-value&ok=1",
            "/reset?reset_token?format=[REDACTED]&ok=1",
        ),
        (
            "/go?next=/a?token=abc?x=1&view=2",
            "/go?next=/a?token=[REDACTED]&view=2",
        ),
        (
            "/hooks/ghp_abcdefghijklmnopqrstuvwxyz0123456789/push",
            "/hooks/[REDACTED]/push",
        ),
        (
            "/v/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig/done?q=1",
            "/v/[REDACTED]/done?q=1",
        ),
        (
            "//ann:s3cret@app.example.test/page",
            "//[REDACTED]@app.example.test/page",
        ),
        ("//cdn.example.test/lib.js", "//cdn.example.test/lib.js"),
        ("/docs/page.html#section-2", "/docs/page.html#section-2"),
        ("/a/b?x=1&y=2", "/a/b?x=1&y=2"),
        (
            "https://app.example.test:8443/p",
            "https://app.example.test:8443/p",
        ),
    ] {
        assert_eq!(redact_uri_query(raw), logged, "{raw}");
    }
    // A request target that starts with two slashes is a path: its first segment is no host
    // (Codex 72 finding 3).
    assert_eq!(
        redact_request_target("//ghp_abcdefghijklmnopqrstuvwxyz0123456789/events?x=1"),
        "//[REDACTED]/events?x=1"
    );
    assert_eq!(
        redact_request_target("http://ann:pw@site.example.test/p"),
        "http://[REDACTED]@site.example.test/p"
    );
}

#[test]
fn cow_redaction_borrows_clean_inputs_and_matches_edge_cases() {
    use miraserve_telemetry::redact::{
        escape_log_controls_cow, redact_header_value_cow, redact_request_target_cow,
        redact_uri_query_cow,
    };
    use std::borrow::Cow;

    // Clean paths, URLs, and headers return Cow::Borrowed without allocating.
    assert!(matches!(
        redact_request_target_cow("/1k.txt"),
        Cow::Borrowed("/1k.txt")
    ));
    assert!(matches!(
        redact_request_target_cow("/go"),
        Cow::Borrowed("/go")
    ));
    assert!(matches!(
        redact_uri_query_cow("https://shop.example/catalog/item"),
        Cow::Borrowed("https://shop.example/catalog/item")
    ));
    assert!(matches!(
        redact_header_value_cow(&USER_AGENT, "Mozilla/5.0 (X11; Linux x86_64)"),
        Cow::Borrowed("Mozilla/5.0 (X11; Linux x86_64)")
    ));
    assert!(matches!(
        escape_log_controls_cow("GET"),
        Cow::Borrowed("GET")
    ));

    // Secret token detection edge cases (mixed case Bearer/Basic, JWT start vs embedded dot,
    // percent/plus decoding, and >64-byte header/query names).
    for (raw, expected) in [
        ("BeArEr secret123", "[REDACTED]"),
        ("  BaSiC dXNlcjpwYXNz  ", "[REDACTED]"),
        ("Bearer+secret123", "[REDACTED]"),
        ("prefix sk-proj-abc123", "[REDACTED]"),
        ("prefix sk_live_abc123", "[REDACTED]"),
        ("prefix github_pat_abc123", "[REDACTED]"),
        ("prefix AKIAIOSFODNN7EXAMPLE", "[REDACTED]"),
        ("eyJnodotatstart", "[REDACTED]"),
        ("  eyJnodottrimmed  ", "[REDACTED]"),
        ("prefix eyJwith.dot", "[REDACTED]"),
        // Embedded `eyJ` without a subsequent `.` is not a compact JWT.
        ("prefix eyJwithoutdot", "prefix eyJwithoutdot"),
        ("prefix.before eyJwithoutdot", "prefix.before eyJwithoutdot"),
        ("ab", "ab"),
    ] {
        assert_eq!(
            redact_header_value_cow(&USER_AGENT, raw).as_ref(),
            expected,
            "USER_AGENT value {raw:?}"
        );
    }

    // Long (>64-byte) sensitive header name and query key exercise the heap fallback path.
    let long_sensitive_hdr = HeaderName::from_bytes(
        b"x-very-long-custom-prefix-exceeding-sixty-four-bytes-for-testing-token",
    );
    assert!(long_sensitive_hdr.is_ok());
    if let Ok(hdr) = long_sensitive_hdr {
        assert_eq!(
            redact_header_value_cow(&hdr, "plain").as_ref(),
            "[REDACTED]"
        );
    }
    let long_query = format!("/api?{}_secret=val123&safe=1", "a".repeat(70));
    assert_eq!(
        redact_request_target(&long_query),
        format!("/api?{}_secret=[REDACTED]&safe=1", "a".repeat(70))
    );
}

#[test]
fn file_cache_striped_counters_sum_across_threads() {
    let reg = Arc::new(TelemetryRegistry::new());
    let mut threads = Vec::new();
    for _ in 0..8 {
        let r = Arc::clone(&reg);
        threads.push(std::thread::spawn(move || {
            for _ in 0..100 {
                r.record_file_cache_event(FileCacheOutcome::Hit);
                r.record_file_cache_event(FileCacheOutcome::Miss);
            }
        }));
    }
    for t in threads {
        assert!(t.join().is_ok());
    }
    assert_eq!(reg.file_cache_counts(), (800, 800, 0, 0));
    let prom = reg.render_prometheus();
    assert!(prom.contains("miraserve_file_cache_events_total{outcome=\"hit\"} 800"));
    assert!(prom.contains("miraserve_file_cache_events_total{outcome=\"miss\"} 800"));
}

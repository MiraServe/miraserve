//! Same-build fused vs. fresh-resolution parity tests on stable trees through the real
//! `CompiledRouter` (`HttpEngine`).
//!
//! Compares the Linux single-open / single-status-read (fused) static path against the
//! fresh-resolution (non-reuse / non-fused) path of **this same build** (engaged via a
//! serving-generation `UNIDENTIFIED_CREDENTIAL` marker) across routing, index, `try-files`,
//! forbidden directory names, `precompressed`, on-the-fly compression, conditionals, ranges,
//! dotfiles, rewrites, `404`/`405`, Markdown negotiation (including non-read cache protection),
//! and (on Unix) symlinks and encoded `?` filenames.
//!
//! Each arm executes in its own child process so process-wide state (the on-the-fly compression
//! cache, published credential registry, and thread-local memos) is never shared between arms.
//! On non-Unix platforms (Windows), the suite asserts the non-Unix validator contract (ETag
//! intentionally omitted without an inode change stamp, date-based conditionals and `If-Range`),
//! keeps the credential-sibling denial reachable, and runs the single applicable arm.
//! Cross-revision comparisons against v0.1.3 or the base commit are outside this suite.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use http::header::{
    ACCEPT, ACCEPT_ENCODING, ALLOW, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_RANGE, CONTENT_TYPE,
    ETAG, HOST, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_RANGE, LAST_MODIFIED, LOCATION, RANGE, VARY,
};
use http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::BodyExt as _;
use miraserve_ai::AgentKeyRegistry;
use miraserve_config::{LimitsConfig, parse_kdl};
use miraserve_fastcgi::protocol::{
    EndRequestBody, RecordType, decode_params, read_record, write_record, write_stream_records,
};
use miraserve_http::{CompiledRouter, CredentialSources, RequestContext, empty_http_body};
use miraserve_telemetry::TelemetryRegistry;
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
        "Content-Type: text/plain\r\n\r\nSCRIPT_NAME={}|QUERY_STRING={}|REQUEST_URI={}|METHOD={}",
        get("SCRIPT_NAME"),
        get("QUERY_STRING"),
        get("REQUEST_URI"),
        get("REQUEST_METHOD"),
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

fn https_ctx() -> RequestContext {
    RequestContext {
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77))),
        remote_port: Some(50_000),
        server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_port: 8443,
        is_https: true,
        tls: None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CapturedResponse {
    status: StatusCode,
    headers: Vec<(String, String)>,
    body: Bytes,
}

fn normalize_response(status: StatusCode, map: &HeaderMap, body: Bytes) -> CapturedResponse {
    let req_id = map
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let mut headers: Vec<(String, String)> = map
        .iter()
        .map(|(k, v)| {
            let name = k.as_str().to_owned();
            let raw = v.to_str().unwrap_or("<bin>");
            let normalized = if name == "x-request-id" {
                format!("<req-id:len={}>", raw.len())
            } else if name == "content-security-policy" {
                if let Some(start) = raw.find("'nonce-")
                    && let Some(after) = raw.get(start + 7..)
                    && let Some(end_rel) = after.find('\'')
                    && let Some(prefix) = raw.get(..start + 7)
                    && let Some(suffix) = after.get(end_rel..)
                {
                    format!("{prefix}<nonce>{suffix}")
                } else {
                    raw.to_owned()
                }
            } else {
                raw.to_owned()
            };
            (name, normalized)
        })
        .collect();
    headers.sort();

    let body = if let Some(id) = req_id
        && let Ok(text) = std::str::from_utf8(&body)
        && text.contains(&id)
    {
        Bytes::from(text.replace(&id, "<req-id>"))
    } else {
        body
    };

    CapturedResponse {
        status,
        headers,
        body,
    }
}

async fn dispatch_one(
    router: &CompiledRouter,
    host: &str,
    method: Method,
    uri: &str,
    extra: &[(&str, &str)],
) -> Result<CapturedResponse, Box<dyn std::error::Error>> {
    let limits = LimitsConfig::default();
    let acme = AcmeChallengeStore::new();
    let telemetry = TelemetryRegistry::new();
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(HOST, host);
    for &(k, v) in extra {
        builder = builder.header(k, v);
    }
    let resp = router
        .dispatch(
            builder.body(empty_http_body())?,
            &https_ctx(),
            &limits,
            &acme,
            None,
            &telemetry,
        )
        .await;
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await?.to_bytes();
    Ok(normalize_response(status, &headers, body))
}

fn build_parity_kdl(
    root_a: &Path,
    root_b: &Path,
    fcgi_addr: std::net::SocketAddr,
    tls_key: &Path,
) -> String {
    let ra = root_a.to_string_lossy().replace('\\', "/");
    let rb = root_b.to_string_lossy().replace('\\', "/");
    let key = tls_key.to_string_lossy().replace('\\', "/");
    format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "{key}" }}
}}
site "php-first.example.test" {{
    root "{ra}"
    index "index.php" "index.html"
    rewrite {{
        rule "^/denied-md\\.md$" deny=403
    }}
    route "*.php" {{
        fastcgi-pass "tcp://{fcgi_addr}"
    }}
    route "/precomp/*" {{
        static {{
            precompressed "all"
        }}
    }}
    route "/app/*" {{
        root "{rb}"
        try-files "{{path}}" "/landing.txt"
    }}
    route "/tf/*" {{
        try-files "{{path}}" "{{path}}/" "/index.php?p={{path}}&{{query}}"
    }}
}}
site "html-first.example.test" {{
    root "{ra}"
    index "index.html" "index.php"
    route "*.php" {{
        fastcgi-pass "tcp://{fcgi_addr}"
    }}
}}
site "unowned-php.example.test" {{
    root "{ra}"
    index "index.php" "index.html"
    route "/*" {{
        try-files "{{path}}" "{{path}}/" "=404"
    }}
}}
site "legacy-php.example.test" {{
    root "{ra}"
    index "index.html"
    route "*.php" {{
        fastcgi-pass "tcp://{fcgi_addr}"
    }}
}}
site "md-prot.example.test" {{
    root "{ra}"
    rewrite {{
        rule "\\.md$" deny=403 header="X-Preview=^blocked$"
    }}
    headers {{
        set "Cache-Control" "public, max-age=300"
        set "CDN-Cache-Control" "public, max-age=300"
    }}
}}
"#
    )
}

#[allow(clippy::too_many_lines)]
async fn run_stable_suite(
    router: &CompiledRouter,
    label: &str,
) -> Result<Vec<(String, CapturedResponse)>, Box<dyn std::error::Error>> {
    let mut results = Vec::new();
    let mut record = |name: &str, resp: CapturedResponse| {
        results.push((name.to_owned(), resp));
    };

    // 1. Direct file GET & HEAD + validators + conditionals (304 / 200) + ranges (206 / 416 / If-Range)
    let direct = dispatch_one(
        router,
        "php-first.example.test",
        Method::GET,
        "/hello.txt",
        &[],
    )
    .await?;
    assert_eq!(direct.status, StatusCode::OK, "{label}: direct GET");
    assert_eq!(
        direct.body.as_ref(),
        b"0123456789abcdef",
        "{label}: direct body"
    );
    let etag_opt = direct
        .headers
        .iter()
        .find(|(k, _)| k == ETAG.as_str())
        .map(|(_, v)| v.clone());
    // Unix platforms supply an inode change stamp and emit a strong ETag; non-Unix platforms
    // (Windows) have no change stamp and intentionally omit ETag (`change_stamp` -> `None`),
    // relying on `Last-Modified` for date revalidation.
    #[cfg(unix)]
    let etag = etag_opt.ok_or("missing ETag")?;
    #[cfg(not(unix))]
    assert!(
        etag_opt.is_none(),
        "{label}: non-Unix platforms must omit ETag when no change stamp is available"
    );
    let last_mod = direct
        .headers
        .iter()
        .find(|(k, _)| k == LAST_MODIFIED.as_str())
        .map(|(_, v)| v.clone())
        .ok_or("missing Last-Modified")?;
    record("direct_get", direct);

    let head = dispatch_one(
        router,
        "php-first.example.test",
        Method::HEAD,
        "/hello.txt",
        &[
            (RANGE.as_str(), "bytes=0-3"),
            (ACCEPT_ENCODING.as_str(), "br"),
        ],
    )
    .await?;
    assert_eq!(head.status, StatusCode::OK, "{label}: HEAD strips Range");
    assert!(head.body.is_empty());
    record("direct_head_with_range", head);

    #[cfg(unix)]
    let inm_match_val = etag.as_str();
    #[cfg(not(unix))]
    let inm_match_val = "*";
    let cond_304 = dispatch_one(
        router,
        "php-first.example.test",
        Method::GET,
        "/hello.txt",
        &[(IF_NONE_MATCH.as_str(), inm_match_val)],
    )
    .await?;
    assert_eq!(cond_304.status, StatusCode::NOT_MODIFIED);
    record("cond_inm_304", cond_304);

    let cond_ims_304 = dispatch_one(
        router,
        "php-first.example.test",
        Method::GET,
        "/hello.txt",
        &[(IF_MODIFIED_SINCE.as_str(), last_mod.as_str())],
    )
    .await?;
    assert_eq!(cond_ims_304.status, StatusCode::NOT_MODIFIED);
    record("cond_ims_304", cond_ims_304);

    let cond_ims_stale = dispatch_one(
        router,
        "php-first.example.test",
        Method::GET,
        "/hello.txt",
        &[(IF_MODIFIED_SINCE.as_str(), "Thu, 01 Jan 1970 00:00:00 GMT")],
    )
    .await?;
    assert_eq!(cond_ims_stale.status, StatusCode::OK);
    record("cond_ims_stale", cond_ims_stale);

    let cond_miss = dispatch_one(
        router,
        "php-first.example.test",
        Method::GET,
        "/hello.txt",
        &[(IF_NONE_MATCH.as_str(), "\"mismatch\"")],
    )
    .await?;
    assert_eq!(cond_miss.status, StatusCode::OK);
    record("cond_inm_miss", cond_miss);

    let range_206_plain = dispatch_one(
        router,
        "php-first.example.test",
        Method::GET,
        "/hello.txt",
        &[(RANGE.as_str(), "bytes=2-5")],
    )
    .await?;
    assert_eq!(range_206_plain.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(range_206_plain.body.as_ref(), b"2345");
    assert!(
        range_206_plain
            .headers
            .iter()
            .any(|(k, v)| k == CONTENT_RANGE.as_str() && v == "bytes 2-5/16")
    );
    record("range_206", range_206_plain);

    #[cfg(unix)]
    {
        let range_206 = dispatch_one(
            router,
            "php-first.example.test",
            Method::GET,
            "/hello.txt",
            &[
                (RANGE.as_str(), "bytes=2-5"),
                (IF_RANGE.as_str(), etag.as_str()),
            ],
        )
        .await?;
        assert_eq!(range_206.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(range_206.body.as_ref(), b"2345");
        assert!(
            range_206
                .headers
                .iter()
                .any(|(k, v)| k == CONTENT_RANGE.as_str() && v == "bytes 2-5/16")
        );
        record("range_206_if_range_match", range_206);
    }

    // HTTP-date `If-Range` is intentionally never accepted for partial resume (`if_range_matches`
    // sends the full 200 representation per RFC 9110 §13.1.5 rather than splicing on mtime); this
    // also exercises the date `If-Range` case on Windows where no ETag is emitted.
    let range_if_date = dispatch_one(
        router,
        "php-first.example.test",
        Method::GET,
        "/hello.txt",
        &[
            (RANGE.as_str(), "bytes=2-5"),
            (IF_RANGE.as_str(), last_mod.as_str()),
        ],
    )
    .await?;
    assert_eq!(range_if_date.status, StatusCode::OK);
    assert_eq!(range_if_date.body.as_ref(), b"0123456789abcdef");
    record("range_if_range_date_full", range_if_date);

    let range_if_mismatch = dispatch_one(
        router,
        "php-first.example.test",
        Method::GET,
        "/hello.txt",
        &[
            (RANGE.as_str(), "bytes=2-5"),
            (IF_RANGE.as_str(), "\"stale\""),
        ],
    )
    .await?;
    assert_eq!(range_if_mismatch.status, StatusCode::OK);
    assert_eq!(range_if_mismatch.body.as_ref(), b"0123456789abcdef");
    record("range_if_range_mismatch", range_if_mismatch);

    let range_416 = dispatch_one(
        router,
        "php-first.example.test",
        Method::GET,
        "/hello.txt",
        &[(RANGE.as_str(), "bytes=999-1000")],
    )
    .await?;
    assert_eq!(range_416.status, StatusCode::RANGE_NOT_SATISFIABLE);
    record("range_416", range_416);

    // 2. Both index orders + unowned script index + legacy `index<ext>` fallback
    let idx_php_wins =
        dispatch_one(router, "php-first.example.test", Method::GET, "/both/", &[]).await?;
    assert_eq!(idx_php_wins.status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&idx_php_wins.body).contains("SCRIPT_NAME=/both/index.php"));
    record("index_order_php_first", idx_php_wins);

    let idx_html_wins = dispatch_one(
        router,
        "html-first.example.test",
        Method::GET,
        "/both/",
        &[],
    )
    .await?;
    assert_eq!(idx_html_wins.status, StatusCode::OK);
    assert_eq!(idx_html_wins.body.as_ref(), b"<html>both-html</html>");
    record("index_order_html_first", idx_html_wins);

    let idx_unowned = dispatch_one(
        router,
        "unowned-php.example.test",
        Method::GET,
        "/both/",
        &[],
    )
    .await?;
    assert_eq!(idx_unowned.status, StatusCode::OK);
    assert_eq!(idx_unowned.body.as_ref(), b"<html>both-html</html>");
    record("index_unowned_script_skipped", idx_unowned);

    let idx_legacy = dispatch_one(
        router,
        "legacy-php.example.test",
        Method::GET,
        "/onlyphp/",
        &[],
    )
    .await?;
    assert_eq!(idx_legacy.status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&idx_legacy.body).contains("SCRIPT_NAME=/onlyphp/index.php"));
    record("index_legacy_php_fallback", idx_legacy);

    // 3. Static & script directory slash redirects preserving queries
    let redir_static = dispatch_one(
        router,
        "php-first.example.test",
        Method::GET,
        "/staticdir?a=1&b=2",
        &[],
    )
    .await?;
    assert_eq!(redir_static.status, StatusCode::MOVED_PERMANENTLY);
    assert!(
        redir_static
            .headers
            .iter()
            .any(|(k, v)| k == LOCATION.as_str() && v == "/staticdir/?a=1&b=2")
    );
    record("redirect_static_dir_query", redir_static);

    let redir_script = dispatch_one(
        router,
        "php-first.example.test",
        Method::GET,
        "/both?q=9",
        &[],
    )
    .await?;
    assert_eq!(redir_script.status, StatusCode::MOVED_PERMANENTLY);
    assert!(
        redir_script
            .headers
            .iter()
            .any(|(k, v)| k == LOCATION.as_str() && v == "/both/?q=9")
    );
    record("redirect_script_dir_query", redir_script);

    // 4. Internal rewrites across roots (`/app/*` in root_b -> `/landing.txt` in default root_a)
    let cross_root = dispatch_one(
        router,
        "php-first.example.test",
        Method::GET,
        "/app/missing-in-b",
        &[],
    )
    .await?;
    assert_eq!(cross_root.status, StatusCode::OK);
    assert_eq!(cross_root.body.as_ref(), b"LANDING-IN-ROOT-A");
    record("rewrite_across_roots", cross_root);

    // 5. Encoded query delimiters (`%3F`, `%23`, `%25`) in direct path (Unix only, since `?` is
    //    illegal in Windows filenames) and try-files (all platforms).
    #[cfg(unix)]
    {
        let enc_q = dispatch_one(
            router,
            "php-first.example.test",
            Method::GET,
            "/note%3Fcopy.txt",
            &[],
        )
        .await?;
        assert_eq!(enc_q.status, StatusCode::OK);
        assert_eq!(enc_q.body.as_ref(), b"LITERAL-QUESTION-MARK");
        record("encoded_query_delimiter_direct", enc_q);
    }

    let enc_tf = dispatch_one(
        router,
        "php-first.example.test",
        Method::GET,
        "/tf/foo%3Fbar%23baz?orig=1",
        &[],
    )
    .await?;
    assert_eq!(enc_tf.status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&enc_tf.body).contains("SCRIPT_NAME=/index.php"));
    record("encoded_query_delimiter_try_files", enc_tf);

    // 5b. Forbidden requested directory name on a script-routed site (Finding 1):
    //     `/archive.bak/` and `/archive.bak` both return 404 (not 200, not 301).
    for (name, path) in [
        ("forbidden_dir_slash", "/archive.bak/"),
        ("forbidden_dir_noslash", "/archive.bak"),
    ] {
        let r = dispatch_one(router, "php-first.example.test", Method::GET, path, &[]).await?;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{label}: {name}");
        record(name, r);
    }

    // 6. Dotfiles & `.well-known`
    for (name, path, expect) in [
        ("dotfile_env", "/.env", StatusCode::NOT_FOUND),
        ("dotfile_git", "/.git/config", StatusCode::NOT_FOUND),
        (
            "well_known_allowed",
            "/.well-known/security.txt",
            StatusCode::OK,
        ),
        (
            "well_known_dotfile_denied",
            "/.well-known/.env",
            StatusCode::NOT_FOUND,
        ),
    ] {
        let r = dispatch_one(router, "php-first.example.test", Method::GET, path, &[]).await?;
        assert_eq!(r.status, expect, "{label}: {name}");
        record(name, r);
    }

    // 7. Symlinks (Unix only): valid in-root symlink allowed; dotfile/script/escape symlinks denied
    #[cfg(unix)]
    for (name, path, expect) in [
        ("symlink_valid", "/sym-ok.txt", StatusCode::OK),
        ("symlink_dotfile", "/sym-env.txt", StatusCode::NOT_FOUND),
        ("symlink_script", "/sym-php.txt", StatusCode::NOT_FOUND),
        ("symlink_escape", "/sym-out.txt", StatusCode::NOT_FOUND),
    ] {
        let r = dispatch_one(router, "php-first.example.test", Method::GET, path, &[]).await?;
        assert_eq!(r.status, expect, "{label}: {name}");
        record(name, r);
    }

    // 8. 404 / 405 distinction and POST script index
    let post_file = dispatch_one(
        router,
        "php-first.example.test",
        Method::POST,
        "/hello.txt",
        &[],
    )
    .await?;
    assert_eq!(post_file.status, StatusCode::METHOD_NOT_ALLOWED);
    assert!(
        post_file
            .headers
            .iter()
            .any(|(k, v)| k == ALLOW.as_str() && v == "GET, HEAD")
    );
    record("post_405_file", post_file);

    let post_miss = dispatch_one(
        router,
        "php-first.example.test",
        Method::POST,
        "/no-such.txt",
        &[],
    )
    .await?;
    assert_eq!(post_miss.status, StatusCode::NOT_FOUND);
    record("post_404_missing", post_miss);

    let post_php_idx = dispatch_one(
        router,
        "php-first.example.test",
        Method::POST,
        "/both/",
        &[],
    )
    .await?;
    assert_eq!(post_php_idx.status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&post_php_idx.body).contains("METHOD=POST"));
    record("post_script_index", post_php_idx);

    // 9. Precompressed "all": hit, miss, non-regular sibling (dir at .br -> .gz), secret sibling
    let sib_hit = dispatch_one(
        router,
        "php-first.example.test",
        Method::GET,
        "/precomp/app.js",
        &[(ACCEPT_ENCODING.as_str(), "br, gzip")],
    )
    .await?;
    assert_eq!(sib_hit.status, StatusCode::OK);
    assert_eq!(sib_hit.body.as_ref(), b"PRECOMP-BR");
    assert!(
        sib_hit
            .headers
            .iter()
            .any(|(k, v)| k == CONTENT_ENCODING.as_str() && v == "br")
    );
    record("precomp_hit", sib_hit);

    let sib_miss = dispatch_one(
        router,
        "php-first.example.test",
        Method::GET,
        "/precomp/plain.js",
        &[(ACCEPT_ENCODING.as_str(), "br, gzip")],
    )
    .await?;
    assert_eq!(sib_miss.status, StatusCode::OK);
    assert_eq!(sib_miss.body.as_ref(), b"PLAIN-JS");
    record("precomp_miss", sib_miss);

    let sib_nonreg = dispatch_one(
        router,
        "php-first.example.test",
        Method::GET,
        "/precomp/dirsib.js",
        &[(ACCEPT_ENCODING.as_str(), "br, gzip")],
    )
    .await?;
    assert_eq!(sib_nonreg.status, StatusCode::OK);
    assert_eq!(sib_nonreg.body.as_ref(), b"PRECOMP-GZ-FALLBACK");
    record("precomp_nonregular_fallback", sib_nonreg);

    let sib_secret = dispatch_one(
        router,
        "php-first.example.test",
        Method::GET,
        "/precomp/secret.js",
        &[(ACCEPT_ENCODING.as_str(), "br, gzip")],
    )
    .await?;
    assert_eq!(
        sib_secret.status,
        StatusCode::NOT_FOUND,
        "{label}: secret .br sibling must deny with 404 and never fall through to .gz"
    );
    record("precomp_secret_denied", sib_secret);

    // 10. Cold and warm on-the-fly compression (precompressed off on default root)
    for pass in ["otf_cold", "otf_warm"] {
        let comp = dispatch_one(
            router,
            "php-first.example.test",
            Method::GET,
            "/big.json",
            &[(ACCEPT_ENCODING.as_str(), "gzip")],
        )
        .await?;
        assert_eq!(comp.status, StatusCode::OK, "{label}: {pass}");
        assert!(
            comp.headers
                .iter()
                .any(|(k, v)| k == CONTENT_ENCODING.as_str() && v == "gzip")
        );
        record(pass, comp);
    }

    // 11. Markdown (deferred): authored `.md`, HTML conversion (GET + HEAD), denied `.md` sibling
    let md_authored = dispatch_one(
        router,
        "php-first.example.test",
        Method::GET,
        "/authored.html",
        &[(ACCEPT.as_str(), "text/markdown")],
    )
    .await?;
    assert_eq!(md_authored.status, StatusCode::OK);
    assert_eq!(md_authored.body.as_ref(), b"# Authored Markdown\n");
    assert!(
        md_authored
            .headers
            .iter()
            .any(|(k, v)| k == CONTENT_TYPE.as_str() && v == "text/markdown; charset=utf-8")
    );
    assert!(
        md_authored
            .headers
            .iter()
            .any(|(k, v)| k == VARY.as_str() && v == "Accept, Accept-Encoding")
    );
    record("markdown_authored", md_authored);

    let md_convert = dispatch_one(
        router,
        "php-first.example.test",
        Method::GET,
        "/convert.html",
        &[(ACCEPT.as_str(), "text/markdown")],
    )
    .await?;
    assert_eq!(md_convert.status, StatusCode::OK);
    assert!(
        md_convert
            .headers
            .iter()
            .any(|(k, v)| k == CONTENT_TYPE.as_str() && v == "text/markdown; charset=utf-8")
    );
    assert!(String::from_utf8_lossy(&md_convert.body).contains("Hello Convert"));
    record("markdown_convert_get", md_convert);

    let md_convert_head = dispatch_one(
        router,
        "php-first.example.test",
        Method::HEAD,
        "/convert.html",
        &[(ACCEPT.as_str(), "text/markdown")],
    )
    .await?;
    assert_eq!(md_convert_head.status, StatusCode::OK);
    assert!(md_convert_head.body.is_empty());
    record("markdown_convert_head", md_convert_head);

    let md_denied_sib = dispatch_one(
        router,
        "php-first.example.test",
        Method::GET,
        "/denied-md.html",
        &[(ACCEPT.as_str(), "text/markdown")],
    )
    .await?;
    assert_eq!(md_denied_sib.status, StatusCode::OK);
    assert!(
        !String::from_utf8_lossy(&md_denied_sib.body).contains("FORBIDDEN-MD-SIBLING"),
        "{label}: denied .md sibling must NOT be served"
    );
    assert!(String::from_utf8_lossy(&md_denied_sib.body).contains("Converted Fallback"));
    record("markdown_denied_sibling", md_denied_sib);

    // 12. Non-read request with Markdown preference on a header-testing rewrite site (Finding 2):
    //     405 with Cache-Control: no-store and CDN-Cache-Control stripped.
    let md_post_prot = dispatch_one(
        router,
        "md-prot.example.test",
        Method::POST,
        "/convert.html",
        &[(ACCEPT.as_str(), "text/markdown")],
    )
    .await?;
    assert_eq!(md_post_prot.status, StatusCode::METHOD_NOT_ALLOWED);
    assert!(
        md_post_prot
            .headers
            .iter()
            .any(|(k, v)| k == CACHE_CONTROL.as_str() && v == "no-store")
    );
    assert!(
        !md_post_prot
            .headers
            .iter()
            .any(|(k, _)| k == "cdn-cache-control")
    );
    record("markdown_post_protected", md_post_prot);

    Ok(results)
}

fn write_u32(out: &mut Vec<u8>, v: usize) -> Result<(), Box<dyn std::error::Error>> {
    let n = u32::try_from(v)?;
    out.extend_from_slice(&n.to_le_bytes());
    Ok(())
}

fn write_bytes(out: &mut Vec<u8>, b: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    write_u32(out, b.len())?;
    out.extend_from_slice(b);
    Ok(())
}

fn read_u32(src: &mut &[u8]) -> Result<usize, Box<dyn std::error::Error>> {
    let (head, rest) = src
        .split_at_checked(4)
        .ok_or("truncated u32 in parity capture")?;
    *src = rest;
    let arr: [u8; 4] = head.try_into()?;
    Ok(usize::try_from(u32::from_le_bytes(arr))?)
}

fn read_bytes<'a>(src: &mut &'a [u8]) -> Result<&'a [u8], Box<dyn std::error::Error>> {
    let len = read_u32(src)?;
    let (head, rest) = src
        .split_at_checked(len)
        .ok_or("truncated bytes in parity capture")?;
    *src = rest;
    Ok(head)
}

fn serialize_results(
    results: &[(String, CapturedResponse)],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    write_u32(&mut out, results.len())?;
    for (name, resp) in results {
        write_bytes(&mut out, name.as_bytes())?;
        out.extend_from_slice(&resp.status.as_u16().to_le_bytes());
        write_u32(&mut out, resp.headers.len())?;
        for (k, v) in &resp.headers {
            write_bytes(&mut out, k.as_bytes())?;
            write_bytes(&mut out, v.as_bytes())?;
        }
        write_bytes(&mut out, &resp.body)?;
    }
    Ok(out)
}

fn deserialize_results(
    raw: &[u8],
) -> Result<Vec<(String, CapturedResponse)>, Box<dyn std::error::Error>> {
    let mut cur = raw;
    let count = read_u32(&mut cur)?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let name = std::str::from_utf8(read_bytes(&mut cur)?)?.to_owned();
        let (st_bytes, rest) = cur
            .split_at_checked(2)
            .ok_or("truncated status in parity capture")?;
        cur = rest;
        let st_arr: [u8; 2] = st_bytes.try_into()?;
        let status = StatusCode::from_u16(u16::from_le_bytes(st_arr))?;
        let hdr_count = read_u32(&mut cur)?;
        let mut headers = Vec::with_capacity(hdr_count);
        for _ in 0..hdr_count {
            let k = std::str::from_utf8(read_bytes(&mut cur)?)?.to_owned();
            let v = std::str::from_utf8(read_bytes(&mut cur)?)?.to_owned();
            headers.push((k, v));
        }
        let body = Bytes::copy_from_slice(read_bytes(&mut cur)?);
        out.push((
            name,
            CapturedResponse {
                status,
                headers,
                body,
            },
        ));
    }
    if !cur.is_empty() {
        return Err("trailing bytes in parity capture".into());
    }
    Ok(out)
}

async fn run_arm_in_isolated_process(arm: &str, base: &Path, out_path: &Path) -> TestResult {
    let root_a = base.join("root_a");
    let root_b = base.join("root_b");
    let creds = base.join("creds");
    let tls_key = creds.join("tls.key");
    let secret_sib = root_a.join("precomp/secret.js.br");

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let fcgi_addr = listener.local_addr()?;
    let fcgi_hits = Arc::new(AtomicUsize::new(0));
    let fcgi_hits_bg = Arc::clone(&fcgi_hits);
    let server_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let hits = Arc::clone(&fcgi_hits_bg);
            tokio::spawn(async move {
                let _ = serve_mock_fastcgi(stream, hits).await;
            });
        }
    });

    let kdl = build_parity_kdl(&root_a, &root_b, fcgi_addr, &tls_key);
    let (cfg, _) = parse_kdl("parity.kdl", &kdl)?;
    let keys = Arc::new(AgentKeyRegistry::default());

    let cred_files = match arm {
        "fused" => vec![secret_sib],
        "fresh" => vec![secret_sib, creds.join("eloop_trigger")],
        other => return Err(format!("unknown parity arm '{other}'").into()),
    };
    let creds_src = CredentialSources {
        files: cred_files,
        dirs: Vec::new(),
    };
    let router = CompiledRouter::compile_with_credentials(&cfg, &keys, false, &creds_src)?;
    let results = run_stable_suite(&router, arm).await?;
    drop(router);

    assert!(
        fcgi_hits.load(Ordering::Acquire) >= 4,
        "{arm}: expected FastCGI backend to execute script indexes and try-files rewrites"
    );
    server_task.abort();

    let encoded = serialize_results(&results)?;
    std::fs::write(out_path, encoded)?;
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn fused_vs_fresh_resolution_parity_on_stable_trees_through_real_router() -> TestResult {
    // Child-process worker entry: runs a single arm with completely isolated process state
    // (fresh compression cache, published credential registry, and thread-local memos).
    if let Ok(arm) = std::env::var("MIRASERVE_PARITY_ARM") {
        let base = PathBuf::from(std::env::var("MIRASERVE_PARITY_BASE")?);
        let out_path = PathBuf::from(std::env::var("MIRASERVE_PARITY_OUT")?);
        return run_arm_in_isolated_process(&arm, &base, &out_path).await;
    }

    let base = std::env::temp_dir().join(format!(
        "miraserve-fused-fresh-parity-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let root_a = base.join("root_a");
    let root_b = base.join("root_b");
    let creds = base.join("creds");
    for d in [
        root_a.join("both"),
        root_a.join("onlyphp"),
        root_a.join("staticdir"),
        root_a.join("archive.bak"),
        root_a.join(".well-known"),
        root_a.join(".git"),
        root_a.join("precomp/dirsib.js.br"),
        root_a.join("tf"),
        root_b.clone(),
        creds.clone(),
    ] {
        std::fs::create_dir_all(&d)?;
    }

    let tls_key = creds.join("tls.key");
    std::fs::write(&tls_key, b"TLS-KEY-MATERIAL")?;
    std::fs::write(root_a.join("hello.txt"), b"0123456789abcdef")?;
    std::fs::write(root_a.join("index.php"), b"<?php echo 'root-fcgi';")?;
    std::fs::write(root_a.join("landing.txt"), b"LANDING-IN-ROOT-A")?;
    std::fs::write(root_a.join("both/index.php"), b"<?php echo 'both-php';")?;
    std::fs::write(root_a.join("both/index.html"), b"<html>both-html</html>")?;
    std::fs::write(root_a.join("onlyphp/index.php"), b"<?php echo 'only-php';")?;
    std::fs::write(
        root_a.join("staticdir/index.html"),
        b"<html>staticdir</html>",
    )?;
    std::fs::write(
        root_a.join("archive.bak/index.html"),
        b"<html>forbidden-dir-index</html>",
    )?;
    #[cfg(unix)]
    std::fs::write(root_a.join("note?copy.txt"), b"LITERAL-QUESTION-MARK")?;
    std::fs::write(root_a.join(".env"), b"SECRET=1")?;
    std::fs::write(root_a.join(".git/config"), b"[core]")?;
    std::fs::write(
        root_a.join(".well-known/security.txt"),
        b"Contact: security@example.test",
    )?;
    std::fs::write(root_a.join(".well-known/.env"), b"HIDDEN")?;
    std::fs::write(root_a.join("precomp/app.js"), b"BASE-APP")?;
    std::fs::write(root_a.join("precomp/app.js.br"), b"PRECOMP-BR")?;
    std::fs::write(root_a.join("precomp/plain.js"), b"PLAIN-JS")?;
    std::fs::write(root_a.join("precomp/dirsib.js"), b"DIRSIB-BASE")?;
    std::fs::write(root_a.join("precomp/dirsib.js.gz"), b"PRECOMP-GZ-FALLBACK")?;
    std::fs::write(root_a.join("precomp/secret.js"), b"SECRET-BASE")?;
    let secret_sib = root_a.join("precomp/secret.js.br");
    std::fs::write(&secret_sib, b"SECRET-SIBLING-CRED")?;
    std::fs::write(root_a.join("precomp/secret.js.gz"), b"MUST-NOT-FALLTHROUGH")?;
    let big_json = format!("{{\"items\":\"{}\"}}", "abc123".repeat(400));
    std::fs::write(root_a.join("big.json"), big_json.as_bytes())?;
    std::fs::write(root_a.join("authored.html"), b"<h1>Authored HTML</h1>")?;
    std::fs::write(root_a.join("authored.md"), b"# Authored Markdown\n")?;
    std::fs::write(
        root_a.join("convert.html"),
        b"<h1>Hello Convert</h1><p>Body</p>",
    )?;
    std::fs::write(
        root_a.join("denied-md.html"),
        b"<h1>Converted Fallback</h1>",
    )?;
    std::fs::write(root_a.join("denied-md.md"), b"FORBIDDEN-MD-SIBLING")?;
    std::fs::write(root_b.join("app_only.txt"), b"IN-ROOT-B")?;

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("hello.txt", root_a.join("sym-ok.txt"))?;
        std::os::unix::fs::symlink(".env", root_a.join("sym-env.txt"))?;
        std::os::unix::fs::symlink("both/index.php", root_a.join("sym-php.txt"))?;
        std::os::unix::fs::symlink(&tls_key, root_a.join("sym-out.txt"))?;
        // Self-referencing symlink in `creds/` triggers `UNIDENTIFIED_CREDENTIAL` in the
        // `fresh` arm's serving generation so it exercises the fresh-resolution path of this
        // same build even when running as root.
        std::os::unix::fs::symlink("eloop_trigger", creds.join("eloop_trigger"))?;
    }

    let exe = std::env::current_exe()?;
    let run_child = |arm: &str,
                     out_path: &Path|
     -> Result<Vec<(String, CapturedResponse)>, Box<dyn std::error::Error>> {
        let output = std::process::Command::new(&exe)
            .arg("--exact")
            .arg("fused_vs_fresh_resolution_parity_on_stable_trees_through_real_router")
            .arg("--nocapture")
            .env("MIRASERVE_PARITY_ARM", arm)
            .env("MIRASERVE_PARITY_BASE", &base)
            .env("MIRASERVE_PARITY_OUT", out_path)
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "parity child arm '{arm}' failed ({}):\nstdout:\n{}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        let raw = std::fs::read(out_path)?;
        deserialize_results(&raw)
    };

    // Arm 1 (isolated child process): fused single-open / single-status-read path of this build.
    let fused_out = base.join("fused.bin");
    let fused_results = run_child("fused", &fused_out)?;
    assert!(fused_results.len() >= 25);

    // Arm 2 (separate isolated child process): fresh-resolution path of this same build, with
    // zero shared compression cache or process-wide state between the two arms.
    #[cfg(unix)]
    {
        let fresh_out = base.join("fresh.bin");
        let fresh_results = run_child("fresh", &fresh_out)?;

        assert_eq!(fused_results.len(), fresh_results.len());
        for ((name_fused, resp_fused), (name_fresh, resp_fresh)) in
            fused_results.iter().zip(fresh_results.iter())
        {
            assert_eq!(name_fused, name_fresh);
            assert_eq!(
                resp_fused.status, resp_fresh.status,
                "status mismatch on case '{name_fused}'"
            );
            assert_eq!(
                resp_fused.headers, resp_fresh.headers,
                "header mismatch on case '{name_fused}'"
            );
            assert_eq!(
                resp_fused.body, resp_fresh.body,
                "body mismatch on case '{name_fused}'"
            );
        }
    }

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

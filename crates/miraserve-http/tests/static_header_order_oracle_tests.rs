//! Independent `416f01f` wire-order oracle tests for static responses.
//!
//! Proves that single-shot static `HeaderMap` sizing produces the EXACT same raw-byte wire-order
//! header sequence as `416f01f`'s `reserve(12)` / `reserve(8)` + regrow path across:
//! - every static file response kind (`200`, `206`, `304`, `HEAD`, precompressed `.gz`/`.br`,
//!   on-the-fly compressed, file-cache hit & miss) with ALL expected header values (`Content-Type`,
//!   `Content-Length`, `ETag`, `Last-Modified`, `Content-Encoding`, `Content-Range`) computed
//!   independently from fixture disk metadata and payload bytes (never copied from the response),
//! - generated error pages (`403`, `404`, `416`), with expected body text, `Content-Length`, and
//!   CSP directives computed independently (never copied from the response; random per-request
//!   128-bit CSP nonce and 26-char Crockford Base32 ULID `X-Request-Id` are checked strictly for
//!   shape and header/body agreement),
//! - every `SecurityHeadersPolicy` (`off`, `standard`, `strict`), HTTP and HTTPS, with and without
//!   `Alt-Svc`, HTTP/1.1 / HTTP/2 / HTTP/3, and site/route `headers` rules (`add`, `set`, `remove`),
//! - and real HTTP/1.1 wire serialization through `HttpEngine::serve_hyper_connection`.

use std::fmt::Write as _;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use http::header::{
    ACCEPT_ENCODING, ACCEPT_RANGES, ALT_SVC, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH,
    CONTENT_RANGE, CONTENT_SECURITY_POLICY, CONTENT_TYPE, ETAG, HOST, HeaderMap, HeaderName,
    HeaderValue, IF_NONE_MATCH, LAST_MODIFIED, RANGE, REFERRER_POLICY, SERVER,
    STRICT_TRANSPORT_SECURITY, VARY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use http::{Method, Request, StatusCode, Version};
use http_body_util::BodyExt as _;
use miraserve_config::{SecurityHeadersPolicy, parse_kdl};
use miraserve_http::{HttpEngine, RequestContext, empty_http_body};
use miraserve_static::compress::{ContentEncoding, compress_bytes};
use miraserve_tls::AcmeChallengeStore;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::watch;

type TestResult = Result<(), Box<dyn std::error::Error>>;

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDirGuard {
    path: PathBuf,
}

impl TempDirGuard {
    fn new(prefix: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let id = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "miraserve-static-hdr-oracle-{prefix}-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir)?;
        Ok(Self { path: dir })
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

// =============================================================================
// Independent Metadata Oracle Helpers (NEVER read expected values from response)
// =============================================================================

/// Independently computes `416f01f`'s `ETag` header from on-disk file metadata and encoding.
#[cfg(unix)]
fn oracle_compute_etag(meta: &fs::Metadata, encoding: Option<&str>) -> Option<HeaderValue> {
    use std::os::unix::fs::MetadataExt as _;

    let len = meta.len();
    let (secs, nanos) = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or((0_u64, 0_u32), |d| (d.as_secs(), d.subsec_nanos()));
    let c_secs = meta.ctime().unsigned_abs();
    let c_nanos = meta.ctime_nsec().unsigned_abs();
    let tag = match encoding {
        Some(enc) => format!("\"{len:x}-{secs:x}-{nanos:x}-{c_secs:x}.{c_nanos:x}-{enc}\""),
        None => format!("\"{len:x}-{secs:x}-{nanos:x}-{c_secs:x}.{c_nanos:x}\""),
    };
    HeaderValue::from_str(&tag).ok()
}

#[cfg(not(unix))]
fn oracle_compute_etag(_meta: &fs::Metadata, _encoding: Option<&str>) -> Option<HeaderValue> {
    None
}

/// Independently formats `Last-Modified` IMF-fixdate (`Day, DD Mon YYYY HH:MM:SS GMT`) from
/// `SystemTime` without calling into `miraserve-static`.
fn oracle_format_http_date(t: SystemTime) -> Option<HeaderValue> {
    let secs = t.duration_since(UNIX_EPOCH).ok()?.as_secs();
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let hour = rem / 3_600;
    let min = (rem % 3_600) / 60;
    let sec = rem % 60;

    let days_i64 = i64::try_from(days).ok()?;
    let z = days_i64.checked_add(719_468)?;
    let era = z.div_euclid(146_097);
    let doe = u64::try_from(z - era * 146_097).ok()?;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = i64::try_from(yoe).ok()? + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + i64::from(month <= 2);

    let dow = match (days + 4) % 7 {
        0 => "Sun",
        1 => "Mon",
        2 => "Tue",
        3 => "Wed",
        4 => "Thu",
        5 => "Fri",
        _ => "Sat",
    };
    let mon = match month {
        1 => "Jan",
        2 => "Feb",
        3 => "Mar",
        4 => "Apr",
        5 => "May",
        6 => "Jun",
        7 => "Jul",
        8 => "Aug",
        9 => "Sep",
        10 => "Oct",
        11 => "Nov",
        _ => "Dec",
    };
    HeaderValue::from_str(&format!(
        "{dow}, {day:02} {mon} {year:04} {hour:02}:{min:02}:{sec:02} GMT"
    ))
    .ok()
}

struct FileFixtureMeta {
    len: u64,
    etag: Option<HeaderValue>,
    last_modified: Option<HeaderValue>,
}

impl FileFixtureMeta {
    fn from_path(path: &Path, encoding: Option<&str>) -> Result<Self, Box<dyn std::error::Error>> {
        let meta = fs::metadata(path)?;
        let len = meta.len();
        let etag = oracle_compute_etag(&meta, encoding);
        let last_modified = meta.modified().ok().and_then(oracle_format_http_date);
        Ok(Self {
            len,
            etag,
            last_modified,
        })
    }
}

// =============================================================================
// Verbatim `416f01f` Oracle (old reserve(12) / reserve(8) + regrow pipeline)
// =============================================================================

const ORACLE_COOP: HeaderName = HeaderName::from_static("cross-origin-opener-policy");
const ORACLE_PERMISSIONS: HeaderName = HeaderName::from_static("permissions-policy");
const ORACLE_X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

const ORACLE_TEXT_PLAIN_UTF8: HeaderValue = HeaderValue::from_static("text/plain; charset=utf-8");
const ORACLE_ACCEPT_RANGES_BYTES: HeaderValue = HeaderValue::from_static("bytes");
const ORACLE_VARY_ACCEPT_ENCODING: HeaderValue = HeaderValue::from_static("Accept-Encoding");
const ORACLE_VARY_ACCEPT: HeaderValue = HeaderValue::from_static("Accept");
const ORACLE_NO_STORE: HeaderValue = HeaderValue::from_static("no-store");
const ORACLE_SERVER: HeaderValue = HeaderValue::from_static("MiraServe");
const ORACLE_HSTS_STANDARD: HeaderValue = HeaderValue::from_static("max-age=31536000");
const ORACLE_HSTS_STRICT: HeaderValue =
    HeaderValue::from_static("max-age=63072000; includeSubDomains");
const ORACLE_NOSNIFF: HeaderValue = HeaderValue::from_static("nosniff");
const ORACLE_REFERRER: HeaderValue = HeaderValue::from_static("strict-origin-when-cross-origin");
const ORACLE_XFO_SAMEORIGIN: HeaderValue = HeaderValue::from_static("SAMEORIGIN");
const ORACLE_XFO_DENY: HeaderValue = HeaderValue::from_static("DENY");
const ORACLE_COOP_VAL: HeaderValue = HeaderValue::from_static("same-origin");
const ORACLE_PERMISSIONS_VAL: HeaderValue =
    HeaderValue::from_static("geolocation=(), microphone=(), camera=()");

#[derive(Clone, Copy)]
enum OracleRule<'a> {
    Set(&'a str, &'a str),
    Add(&'a str, &'a str),
    Remove(&'a str),
}

/// Verbatim `416f01f` `build_file_response` header construction (`reserve(12)`).
fn oracle_416f01f_file_headers(
    content_type: HeaderValue,
    content_len: u64,
    etag: Option<HeaderValue>,
    last_modified: Option<HeaderValue>,
    encoding: Option<&'static str>,
    content_range: Option<&str>,
) -> Result<HeaderMap, Box<dyn std::error::Error>> {
    let mut headers = HeaderMap::new();
    headers.reserve(12);
    headers.insert(CONTENT_TYPE, content_type);
    headers.insert(CONTENT_LENGTH, HeaderValue::from(content_len));
    headers.insert(ACCEPT_RANGES, ORACLE_ACCEPT_RANGES_BYTES);
    headers.insert(VARY, ORACLE_VARY_ACCEPT_ENCODING);
    if let Some(val) = etag {
        headers.insert(ETAG, val);
    }
    if let Some(val) = last_modified {
        headers.insert(LAST_MODIFIED, val);
    }
    if let Some(enc) = encoding {
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static(enc));
    }
    if let Some(cr) = content_range {
        headers.insert(CONTENT_RANGE, HeaderValue::from_str(cr)?);
    }
    Ok(headers)
}

/// Verbatim `416f01f` 304 Not Modified header construction (`reserve(8)`).
fn oracle_416f01f_304_headers(
    etag: Option<HeaderValue>,
    last_modified: Option<HeaderValue>,
) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.reserve(8);
    headers.insert(VARY, ORACLE_VARY_ACCEPT_ENCODING);
    if let Some(val) = etag {
        headers.insert(ETAG, val);
    }
    if let Some(val) = last_modified {
        headers.insert(LAST_MODIFIED, val);
    }
    headers
}

const ORACLE_DYNAMIC_CSP_SENTINEL: HeaderValue =
    HeaderValue::from_static("__oracle_dynamic_csp_nonce__");
const ORACLE_DYNAMIC_REQ_ID_SENTINEL: HeaderValue =
    HeaderValue::from_static("__oracle_dynamic_ulid_req_id__");
const ORACLE_REQUEST_ID_LEN: usize = 26;

/// Verbatim `416f01f` `build_builtin_response` + `upgrade_generated_error` header construction.
///
/// Uses fixed sentinel placeholders (NEVER copied from the actual response) for the two random
/// per-request headers (`Content-Security-Policy` nonce and `X-Request-Id` ULID) so `HeaderMap`
/// produces the exact `416f01f` wire slot order while value validation runs independently in
/// [`assert_error_wire_headers_match_oracle`].
fn oracle_416f01f_error_headers(
    content_len: usize,
    content_range: Option<&str>,
) -> Result<HeaderMap, Box<dyn std::error::Error>> {
    let mut headers = HeaderMap::new();
    headers.reserve(12);
    headers.insert(CONTENT_TYPE, ORACLE_TEXT_PLAIN_UTF8);
    headers.insert(CONTENT_LENGTH, HeaderValue::from(content_len));
    headers.insert(VARY, ORACLE_VARY_ACCEPT);
    headers.insert(X_CONTENT_TYPE_OPTIONS, ORACLE_NOSNIFF);
    headers.insert(CACHE_CONTROL, ORACLE_NO_STORE);
    headers.insert(SERVER, ORACLE_SERVER);
    headers.insert(CONTENT_SECURITY_POLICY, ORACLE_DYNAMIC_CSP_SENTINEL);
    headers.insert(ORACLE_X_REQUEST_ID, ORACLE_DYNAMIC_REQ_ID_SENTINEL);
    if let Some(cr) = content_range {
        headers.insert(CONTENT_RANGE, HeaderValue::from_str(cr)?);
    }
    Ok(headers)
}

/// Verbatim `416f01f` `apply_security_headers` (including `try_reserve` regrow on Strict).
fn oracle_416f01f_apply_security_headers(
    headers: &mut HeaderMap,
    policy: SecurityHeadersPolicy,
    is_https: bool,
    alt_svc: Option<&HeaderValue>,
    version: Version,
) {
    let emit_alt_svc = if is_https && version != Version::HTTP_3 {
        alt_svc
    } else {
        None
    };
    let extra: &[(HeaderName, HeaderValue)] = match (policy, is_https) {
        (SecurityHeadersPolicy::Off, _) => &[],
        (SecurityHeadersPolicy::Standard, false) => &[
            (X_CONTENT_TYPE_OPTIONS, ORACLE_NOSNIFF),
            (REFERRER_POLICY, ORACLE_REFERRER),
            (X_FRAME_OPTIONS, ORACLE_XFO_SAMEORIGIN),
        ],
        (SecurityHeadersPolicy::Standard, true) => &[
            (STRICT_TRANSPORT_SECURITY, ORACLE_HSTS_STANDARD),
            (X_CONTENT_TYPE_OPTIONS, ORACLE_NOSNIFF),
            (REFERRER_POLICY, ORACLE_REFERRER),
            (X_FRAME_OPTIONS, ORACLE_XFO_SAMEORIGIN),
        ],
        (SecurityHeadersPolicy::Strict, false) => &[
            (X_CONTENT_TYPE_OPTIONS, ORACLE_NOSNIFF),
            (REFERRER_POLICY, ORACLE_REFERRER),
            (X_FRAME_OPTIONS, ORACLE_XFO_DENY),
            (ORACLE_COOP, ORACLE_COOP_VAL),
            (ORACLE_PERMISSIONS, ORACLE_PERMISSIONS_VAL),
        ],
        (SecurityHeadersPolicy::Strict, true) => &[
            (STRICT_TRANSPORT_SECURITY, ORACLE_HSTS_STRICT),
            (X_CONTENT_TYPE_OPTIONS, ORACLE_NOSNIFF),
            (REFERRER_POLICY, ORACLE_REFERRER),
            (X_FRAME_OPTIONS, ORACLE_XFO_DENY),
            (ORACLE_COOP, ORACLE_COOP_VAL),
            (ORACLE_PERMISSIONS, ORACLE_PERMISSIONS_VAL),
        ],
    };

    let max_new = 1 + usize::from(emit_alt_svc.is_some()) + extra.len();
    if headers.capacity() < headers.keys_len().saturating_add(max_new) {
        let _ = headers.try_reserve(max_new);
    }

    headers.entry(SERVER).or_insert(ORACLE_SERVER);
    headers.remove(ALT_SVC);
    if !is_https {
        headers.remove(STRICT_TRANSPORT_SECURITY);
    }
    if let Some(val) = emit_alt_svc {
        headers.insert(ALT_SVC, val.clone());
    }
    let overwrite = policy == SecurityHeadersPolicy::Strict;
    for (name, value) in extra {
        if overwrite {
            headers.insert(name.clone(), value.clone());
        } else {
            headers.entry(name.clone()).or_insert_with(|| value.clone());
        }
    }
}

/// Verbatim `416f01f` site + route `apply_header_rules` + server-owned restore.
fn oracle_416f01f_apply_rules(
    headers: &mut HeaderMap,
    site_rules: &[OracleRule<'_>],
    route_rules: &[OracleRule<'_>],
    has_route_marker: bool,
    is_https: bool,
) -> TestResult {
    if site_rules.is_empty() && !has_route_marker {
        return Ok(());
    }
    let alt_svc = headers.get(ALT_SVC).cloned();
    for rule in site_rules.iter().chain(route_rules.iter()) {
        match *rule {
            OracleRule::Set(k, v) => {
                headers.insert(
                    HeaderName::from_bytes(k.as_bytes())?,
                    HeaderValue::from_str(v)?,
                );
            }
            OracleRule::Add(k, v) => {
                headers.append(
                    HeaderName::from_bytes(k.as_bytes())?,
                    HeaderValue::from_str(v)?,
                );
            }
            OracleRule::Remove(k) => {
                headers.remove(HeaderName::from_bytes(k.as_bytes())?);
            }
        }
    }
    if let Some(alt_svc) = alt_svc {
        headers.insert(ALT_SVC, alt_svc);
    }
    if !is_https {
        headers.remove(STRICT_TRANSPORT_SECURITY);
        headers.remove(ALT_SVC);
    }
    Ok(())
}

/// Exact ordered raw-byte header snapshot (`(lowercase_name, raw_value_bytes)`). Never collapses
/// non-UTF-8 values to `""`.
fn ordered_wire_headers(headers: &HeaderMap) -> Vec<(String, Vec<u8>)> {
    headers
        .iter()
        .map(|(k, v)| (k.as_str().to_owned(), v.as_bytes().to_vec()))
        .collect()
}

fn encode_kdl_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

fn format_kdl_rules(rules: &[OracleRule<'_>]) -> String {
    if rules.is_empty() {
        return String::new();
    }
    let mut out = String::from("headers {\n");
    for rule in rules {
        match *rule {
            OracleRule::Set(k, v) => {
                let _ = writeln!(out, "        set \"{k}\" \"{v}\"");
            }
            OracleRule::Add(k, v) => {
                let _ = writeln!(out, "        add \"{k}\" \"{v}\"");
            }
            OracleRule::Remove(k) => {
                let _ = writeln!(out, "        remove \"{k}\"");
            }
        }
    }
    out.push_str("    }\n");
    out
}

struct ExpectedErrorBody {
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    len: usize,
}

/// Independently computes the deterministic plain-text error body prefix/suffix and exact byte
/// length for built-in MiraServe `text/plain` error pages (`403`, `404`, `416`) without inspecting
/// the actual response body.
///
/// The 26-character Crockford Base32 ULID request ID is randomly generated inside
/// `HttpEngine::handle_request`, so its length (`26`) is fixed and its value can only be checked
/// for exact ULID shape and header/body agreement.
fn oracle_expected_plain_error_body_parts(
    status: StatusCode,
    uri_path: &str,
    host: &str,
) -> Result<ExpectedErrorBody, Box<dyn std::error::Error>> {
    let prefix = match status {
        StatusCode::FORBIDDEN => format!(
            "403 Forbidden\n\nThe server understood the request for {uri_path} but is not allowed to show it to you.\nRequest ID: "
        ),
        StatusCode::NOT_FOUND => format!(
            "404 Not Found\n\nThere is nothing at {uri_path} on {host}. The page may have moved or been deleted, or the link may have a typo.\nRequest ID: "
        ),
        StatusCode::RANGE_NOT_SATISFIABLE => format!(
            "416 Range Not Satisfiable\n\nThe server couldn\u{2019}t fulfill the request for {uri_path}.\nRequest ID: "
        ),
        other => return Err(format!("unsupported oracle error status: {other}").into()),
    };
    let prefix_bytes = prefix.into_bytes();
    let suffix_bytes = b"\n".to_vec();
    let len = prefix_bytes.len() + ORACLE_REQUEST_ID_LEN + suffix_bytes.len();
    Ok(ExpectedErrorBody {
        prefix: prefix_bytes,
        suffix: suffix_bytes,
        len,
    })
}

/// Validates a `Content-Security-Policy` header value independently against the exact built-in
/// policy template and 128-bit URL-safe unpadded Base64 nonce shape (`22` chars, last char carrying
/// 2 data bits + 4 zero pad bits).
fn assert_valid_builtin_error_csp(raw: &[u8], ctx_msg: &str) -> TestResult {
    let csp_str = std::str::from_utf8(raw)?;
    let nonce_rest = csp_str
        .strip_prefix("default-src 'none'; style-src 'nonce-")
        .ok_or_else(|| format!("{ctx_msg}: unexpected CSP prefix: {csp_str}"))?;
    let nonce = nonce_rest
        .strip_suffix(
            "'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        )
        .ok_or_else(|| format!("{ctx_msg}: unexpected CSP suffix: {csp_str}"))?;
    assert_eq!(
        nonce.len(),
        22,
        "{ctx_msg}: expected 22-char base64url 128-bit CSP nonce, got {nonce:?}"
    );
    assert!(
        nonce
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "{ctx_msg}: non-base64url byte in CSP nonce: {nonce:?}"
    );
    let last = nonce.as_bytes().last().copied().ok_or("empty CSP nonce")?;
    // 16 bytes = 128 bits = 21*6 + 2 bits: the final 6-bit Base64 index carries 2 data bits
    // followed by 4 zero pad bits (indices 0, 16, 32, 48 -> 'A', 'Q', 'g', 'w').
    assert!(
        b"AQgw".contains(&last),
        "{ctx_msg}: non-zero trailing pad bits in 128-bit base64url CSP nonce: {nonce:?}"
    );
    Ok(())
}

/// Validates an `X-Request-Id` header value strictly against the 26-character Crockford Base32
/// ULID alphabet (`0-9A-HJKMNP-TV-Z`, first timestamp digit `0..=7`). Because the server generates
/// a fresh random ULID per request, shape plus header/body equality is the strongest independent
/// check possible.
fn assert_valid_ulid_request_id(raw: &[u8], ctx_msg: &str) {
    const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    assert_eq!(
        raw.len(),
        ORACLE_REQUEST_ID_LEN,
        "{ctx_msg}: expected 26-byte ULID X-Request-Id, got {:?}",
        String::from_utf8_lossy(raw)
    );
    assert!(
        raw.first().is_some_and(|&b| (b'0'..=b'7').contains(&b)),
        "{ctx_msg}: ULID first timestamp char must be 0..=7, got {:?}",
        String::from_utf8_lossy(raw)
    );
    assert!(
        raw.iter().all(|b| CROCKFORD.contains(b)),
        "{ctx_msg}: invalid Crockford Base32 char in X-Request-Id: {:?}",
        String::from_utf8_lossy(raw)
    );
}

/// Compares actual error wire headers in exact order against the independently built `416f01f`
/// oracle without ever copying actual CSP or request ID values into the expected map. Returns the
/// validated 26-byte `X-Request-Id` header value so the caller can assert exact body equality.
fn assert_error_wire_headers_match_oracle(
    actual_headers: &HeaderMap,
    expected_headers: &HeaderMap,
    ctx_msg: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let actual = ordered_wire_headers(actual_headers);
    let expected = ordered_wire_headers(expected_headers);
    assert_eq!(
        actual.len(),
        expected.len(),
        "{ctx_msg}: header count mismatch\nactual:   {actual:?}\nexpected: {expected:?}"
    );
    let mut validated_req_id: Option<Vec<u8>> = None;
    for (idx, ((act_name, act_val), (exp_name, exp_val))) in
        actual.iter().zip(expected.iter()).enumerate()
    {
        assert_eq!(
            act_name, exp_name,
            "{ctx_msg}: wire header name mismatch at index {idx}\nactual:   {actual:?}\nexpected: {expected:?}"
        );
        if exp_name == "content-security-policy"
            && exp_val.as_slice() == ORACLE_DYNAMIC_CSP_SENTINEL.as_bytes()
        {
            assert_valid_builtin_error_csp(act_val, ctx_msg)?;
        } else if exp_name == "x-request-id"
            && exp_val.as_slice() == ORACLE_DYNAMIC_REQ_ID_SENTINEL.as_bytes()
        {
            assert_valid_ulid_request_id(act_val, ctx_msg);
            validated_req_id = Some(act_val.clone());
        } else {
            assert_eq!(
                act_val, exp_val,
                "{ctx_msg}: header `{act_name}` value mismatch at index {idx}"
            );
        }
    }
    validated_req_id.ok_or_else(|| format!("{ctx_msg}: missing x-request-id header").into())
}

struct DirFixtures {
    plain: FileFixtureMeta,
    gz: FileFixtureMeta,
    br: FileFixtureMeta,
    live: FileFixtureMeta,
    live_gzip_len: u64,
}

impl DirFixtures {
    fn write_and_stat(
        dir: &Path,
        body_text: &str,
        gz_bytes: &[u8],
        br_bytes: &[u8],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        fs::create_dir_all(dir)?;
        let plain_path = dir.join("asset.txt");
        let gz_path = dir.join("asset.txt.gz");
        let br_path = dir.join("asset.txt.br");
        let live_path = dir.join("live.txt");
        fs::write(&plain_path, body_text.as_bytes())?;
        fs::write(&gz_path, gz_bytes)?;
        fs::write(&br_path, br_bytes)?;
        fs::write(&live_path, body_text.as_bytes())?;
        // Dotfile used to trigger deterministic 403 Forbidden.
        fs::write(dir.join(".env"), b"SECRET=1\n")?;
        Ok(Self {
            plain: FileFixtureMeta::from_path(&plain_path, None)?,
            gz: FileFixtureMeta::from_path(&gz_path, Some("gzip"))?,
            br: FileFixtureMeta::from_path(&br_path, Some("br"))?,
            live: FileFixtureMeta::from_path(&live_path, Some("gzip"))?,
            live_gzip_len: gz_bytes.len() as u64,
        })
    }
}

struct ErrorCase<'a> {
    tail: &'a str,
    status: StatusCode,
    range_req: Option<&'a str>,
    expected_cr: Option<&'a str>,
    is_denied_route: bool,
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn static_responses_match_416f01f_oracle_exact_wire_order_across_matrix() -> TestResult {
    let dir = TempDirGuard::new("matrix")?;
    let body_text = "MiraServe static wire-order oracle payload line.\n".repeat(48);
    let gz_bytes = compress_bytes(ContentEncoding::Gzip, body_text.as_bytes())?;
    let br_bytes = compress_bytes(ContentEncoding::Brotli, body_text.as_bytes())?;

    let root_fx = DirFixtures::write_and_stat(&dir.path, &body_text, &gz_bytes, &br_bytes)?;
    let assets_fx =
        DirFixtures::write_and_stat(&dir.path.join("assets"), &body_text, &gz_bytes, &br_bytes)?;

    let root_kdl = encode_kdl_string(&dir.path.to_string_lossy());

    let policies: &[(&str, SecurityHeadersPolicy)] = &[
        ("off", SecurityHeadersPolicy::Off),
        ("standard", SecurityHeadersPolicy::Standard),
        ("strict", SecurityHeadersPolicy::Strict),
    ];

    let rule_sets: &[(&str, &[OracleRule<'_>], &[OracleRule<'_>])] = &[
        ("no_rules", &[], &[]),
        (
            "site_and_route_add_set_remove",
            &[
                OracleRule::Set("cache-control", "public, max-age=3600"),
                OracleRule::Add("x-site-tag", "s1"),
                OracleRule::Add("x-site-tag", "s2"),
                OracleRule::Set("x-frame-options", "SAMEORIGIN"),
                OracleRule::Remove("x-content-type-options"),
            ],
            &[
                OracleRule::Set("x-route-id", "assets"),
                OracleRule::Add("x-route-multi", "r1"),
                OracleRule::Add("x-route-multi", "r2"),
                OracleRule::Set("x-extra-1", "v1"),
                OracleRule::Set("x-extra-2", "v2"),
                OracleRule::Set("x-extra-3", "v3"),
                OracleRule::Set("x-extra-4", "v4"),
                OracleRule::Set("x-extra-5", "v5"),
                OracleRule::Set("x-extra-6", "v6"),
                OracleRule::Remove("referrer-policy"),
            ],
        ),
    ];

    for &(policy_name, policy) in policies {
        for &(rule_label, site_rules, route_rules) in rule_sets {
            for file_cache in [false, true] {
                let site_rules_kdl = format_kdl_rules(site_rules);
                let route_rules_kdl = format_kdl_rules(route_rules);
                let cache_kdl = if file_cache { "file-cache \"10s\"" } else { "" };
                let kdl = format!(
                    r#"
server {{
    listen "127.0.0.1:8443" protocols="h1,h2,h3"
    limits {{
        file-cache-bytes "4MiB"
    }}
}}
site "oracle.test" {{
    root {root_kdl}
    http "serve"
    security-headers "{policy_name}"
    precompressed "all"
    {cache_kdl}
    {site_rules_kdl}
    route "/assets/*" {{
        root {root_kdl}
        static {{
            compression #true
            precompressed "all"
        }}
        {route_rules_kdl}
    }}
    route "/denied/*" {{
        root {root_kdl}
        try-files "{{path}}" "=403"
        {route_rules_kdl}
    }}
}}
"#
                );
                let (cfg, _) = parse_kdl("oracle.kdl", &kdl)?;
                for alt_port in [None, Some(8443_u16)] {
                    let alt_val = alt_port
                        .map(|p| HeaderValue::from_str(&format!("h3=\":{p}\"; ma=86400")))
                        .transpose()?;
                    let engine = HttpEngine::from_config(
                        &cfg,
                        Arc::new(AcmeChallengeStore::new()),
                        alt_port,
                        8443,
                    )?;

                    for is_https in [false, true] {
                        let ctx = RequestContext {
                            client_ip: Some("198.51.100.10".parse()?),
                            remote_port: Some(40000),
                            server_addr: Some("127.0.0.1".parse()?),
                            server_port: 8443,
                            is_https,
                            tls: None,
                        };

                        for (route_prefix, active_route_rules, has_route_marker, fx) in [
                            ("", &[][..], false, &root_fx),
                            ("/assets", route_rules, true, &assets_fx),
                        ] {
                            // 1. 200 GET (twice when file_cache=true to cover both miss and hit!)
                            let passes = if file_cache { 2 } else { 1 };
                            for pass in 0..passes {
                                for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3]
                                {
                                    let req = Request::builder()
                                        .method(Method::GET)
                                        .version(version)
                                        .uri(format!("{route_prefix}/asset.txt"))
                                        .header(HOST, "oracle.test")
                                        .body(empty_http_body())?;
                                    let resp = engine.handle_request(req, &ctx).await;
                                    assert_eq!(resp.status(), StatusCode::OK);

                                    let mut expected = oracle_416f01f_file_headers(
                                        ORACLE_TEXT_PLAIN_UTF8,
                                        fx.plain.len,
                                        fx.plain.etag.clone(),
                                        fx.plain.last_modified.clone(),
                                        None,
                                        None,
                                    )?;
                                    oracle_416f01f_apply_security_headers(
                                        &mut expected,
                                        policy,
                                        is_https,
                                        alt_val.as_ref(),
                                        version,
                                    );
                                    oracle_416f01f_apply_rules(
                                        &mut expected,
                                        site_rules,
                                        active_route_rules,
                                        has_route_marker,
                                        is_https,
                                    )?;
                                    assert_eq!(
                                        ordered_wire_headers(resp.headers()),
                                        ordered_wire_headers(&expected),
                                        "200 GET mismatch: policy={policy_name} rules={rule_label} cache={file_cache} pass={pass} alt={alt_port:?} https={is_https} ver={version:?} prefix={route_prefix}"
                                    );
                                }
                            }

                            // 2. 206 Partial Content (Range)
                            {
                                let req = Request::builder()
                                    .method(Method::GET)
                                    .uri(format!("{route_prefix}/asset.txt"))
                                    .header(HOST, "oracle.test")
                                    .header(RANGE, "bytes=0-127")
                                    .body(empty_http_body())?;
                                let resp = engine.handle_request(req, &ctx).await;
                                assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
                                let cr = format!("bytes 0-127/{}", fx.plain.len);
                                let mut expected = oracle_416f01f_file_headers(
                                    ORACLE_TEXT_PLAIN_UTF8,
                                    128,
                                    fx.plain.etag.clone(),
                                    fx.plain.last_modified.clone(),
                                    None,
                                    Some(&cr),
                                )?;
                                oracle_416f01f_apply_security_headers(
                                    &mut expected,
                                    policy,
                                    is_https,
                                    alt_val.as_ref(),
                                    Version::HTTP_11,
                                );
                                oracle_416f01f_apply_rules(
                                    &mut expected,
                                    site_rules,
                                    active_route_rules,
                                    has_route_marker,
                                    is_https,
                                )?;
                                assert_eq!(
                                    ordered_wire_headers(resp.headers()),
                                    ordered_wire_headers(&expected),
                                    "206 mismatch: policy={policy_name} rules={rule_label} https={is_https} prefix={route_prefix}"
                                );
                            }

                            // 3. 304 Not Modified (using independently computed ETag!)
                            if let Some(etag_val) = fx.plain.etag.clone() {
                                let req = Request::builder()
                                    .method(Method::GET)
                                    .uri(format!("{route_prefix}/asset.txt"))
                                    .header(HOST, "oracle.test")
                                    .header(IF_NONE_MATCH, etag_val)
                                    .body(empty_http_body())?;
                                let resp = engine.handle_request(req, &ctx).await;
                                assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
                                let mut expected = oracle_416f01f_304_headers(
                                    fx.plain.etag.clone(),
                                    fx.plain.last_modified.clone(),
                                );
                                oracle_416f01f_apply_security_headers(
                                    &mut expected,
                                    policy,
                                    is_https,
                                    alt_val.as_ref(),
                                    Version::HTTP_11,
                                );
                                oracle_416f01f_apply_rules(
                                    &mut expected,
                                    site_rules,
                                    active_route_rules,
                                    has_route_marker,
                                    is_https,
                                )?;
                                assert_eq!(
                                    ordered_wire_headers(resp.headers()),
                                    ordered_wire_headers(&expected),
                                    "304 mismatch: policy={policy_name} rules={rule_label} https={is_https} prefix={route_prefix}"
                                );
                            }

                            // 4. HEAD (200)
                            {
                                let req = Request::builder()
                                    .method(Method::HEAD)
                                    .uri(format!("{route_prefix}/asset.txt"))
                                    .header(HOST, "oracle.test")
                                    .body(empty_http_body())?;
                                let resp = engine.handle_request(req, &ctx).await;
                                assert_eq!(resp.status(), StatusCode::OK);
                                let mut expected = oracle_416f01f_file_headers(
                                    ORACLE_TEXT_PLAIN_UTF8,
                                    fx.plain.len,
                                    fx.plain.etag.clone(),
                                    fx.plain.last_modified.clone(),
                                    None,
                                    None,
                                )?;
                                oracle_416f01f_apply_security_headers(
                                    &mut expected,
                                    policy,
                                    is_https,
                                    alt_val.as_ref(),
                                    Version::HTTP_11,
                                );
                                oracle_416f01f_apply_rules(
                                    &mut expected,
                                    site_rules,
                                    active_route_rules,
                                    has_route_marker,
                                    is_https,
                                )?;
                                assert_eq!(
                                    ordered_wire_headers(resp.headers()),
                                    ordered_wire_headers(&expected),
                                    "HEAD mismatch: policy={policy_name} rules={rule_label} https={is_https} prefix={route_prefix}"
                                );
                            }

                            // 5. Precompressed `.br` and `.gz` GET, plus on-the-fly gzip `/live.txt`
                            for (uri_tail, ae_header, expected_len, meta_fx, enc) in [
                                ("/asset.txt", "br", fx.br.len, &fx.br, "br"),
                                ("/asset.txt", "gzip", fx.gz.len, &fx.gz, "gzip"),
                                ("/live.txt", "gzip", fx.live_gzip_len, &fx.live, "gzip"),
                            ] {
                                let req = Request::builder()
                                    .method(Method::GET)
                                    .uri(format!("{route_prefix}{uri_tail}"))
                                    .header(HOST, "oracle.test")
                                    .header(ACCEPT_ENCODING, ae_header)
                                    .body(empty_http_body())?;
                                let resp = engine.handle_request(req, &ctx).await;
                                assert_eq!(resp.status(), StatusCode::OK);
                                let mut expected = oracle_416f01f_file_headers(
                                    ORACLE_TEXT_PLAIN_UTF8,
                                    expected_len,
                                    meta_fx.etag.clone(),
                                    meta_fx.last_modified.clone(),
                                    Some(enc),
                                    None,
                                )?;
                                oracle_416f01f_apply_security_headers(
                                    &mut expected,
                                    policy,
                                    is_https,
                                    alt_val.as_ref(),
                                    Version::HTTP_11,
                                );
                                oracle_416f01f_apply_rules(
                                    &mut expected,
                                    site_rules,
                                    active_route_rules,
                                    has_route_marker,
                                    is_https,
                                )?;
                                assert_eq!(
                                    ordered_wire_headers(resp.headers()),
                                    ordered_wire_headers(&expected),
                                    "compressed mismatch: {uri_tail} AE={ae_header} policy={policy_name} rules={rule_label} https={is_https} prefix={route_prefix}"
                                );
                            }

                            // 6. Generated error pages: 403 (`try-files "=403"`), 404 (missing &
                            //    dotfile), and 416 (unsatisfiable Range)
                            let unsat_cr = format!("bytes */{}", fx.plain.len);
                            let error_cases = [
                                ErrorCase {
                                    tail: "/denied/secret.txt",
                                    status: StatusCode::FORBIDDEN,
                                    range_req: None,
                                    expected_cr: None,
                                    is_denied_route: true,
                                },
                                ErrorCase {
                                    tail: "/.env",
                                    status: StatusCode::NOT_FOUND,
                                    range_req: None,
                                    expected_cr: None,
                                    is_denied_route: false,
                                },
                                ErrorCase {
                                    tail: "/does-not-exist.txt",
                                    status: StatusCode::NOT_FOUND,
                                    range_req: None,
                                    expected_cr: None,
                                    is_denied_route: false,
                                },
                                ErrorCase {
                                    tail: "/asset.txt",
                                    status: StatusCode::RANGE_NOT_SATISFIABLE,
                                    range_req: Some("bytes=999999-1000000"),
                                    expected_cr: Some(unsat_cr.as_str()),
                                    is_denied_route: false,
                                },
                            ];
                            for case in &error_cases {
                                let (uri, err_route_rules, err_has_marker) = if case.is_denied_route
                                {
                                    if !route_prefix.is_empty() {
                                        continue;
                                    }
                                    (case.tail.to_owned(), route_rules, true)
                                } else {
                                    (
                                        format!("{route_prefix}{}", case.tail),
                                        active_route_rules,
                                        has_route_marker,
                                    )
                                };
                                let mut builder = Request::builder()
                                    .method(Method::GET)
                                    .uri(&uri)
                                    .header(HOST, "oracle.test");
                                if let Some(range_val) = case.range_req {
                                    builder = builder.header(RANGE, range_val);
                                }
                                let resp = engine
                                    .handle_request(builder.body(empty_http_body())?, &ctx)
                                    .await;
                                assert_eq!(resp.status(), case.status);
                                let actual_headers = resp.headers().clone();
                                let body_bytes = resp.into_body().collect().await?.to_bytes();

                                let expected_body_parts = oracle_expected_plain_error_body_parts(
                                    case.status,
                                    &uri,
                                    "oracle.test",
                                )?;

                                let mut expected = oracle_416f01f_error_headers(
                                    expected_body_parts.len,
                                    case.expected_cr,
                                )?;
                                oracle_416f01f_apply_security_headers(
                                    &mut expected,
                                    policy,
                                    is_https,
                                    alt_val.as_ref(),
                                    Version::HTTP_11,
                                );
                                oracle_416f01f_apply_rules(
                                    &mut expected,
                                    site_rules,
                                    err_route_rules,
                                    err_has_marker,
                                    is_https,
                                )?;
                                let ctx_msg = format!(
                                    "error {} mismatch: path={} policy={policy_name} rules={rule_label} https={is_https} prefix={route_prefix}",
                                    case.status, case.tail
                                );
                                let req_id_bytes = assert_error_wire_headers_match_oracle(
                                    &actual_headers,
                                    &expected,
                                    &ctx_msg,
                                )?;
                                let mut expected_body = Vec::with_capacity(expected_body_parts.len);
                                expected_body.extend_from_slice(&expected_body_parts.prefix);
                                expected_body.extend_from_slice(&req_id_bytes);
                                expected_body.extend_from_slice(&expected_body_parts.suffix);
                                assert_eq!(
                                    body_bytes.as_ref(),
                                    expected_body.as_slice(),
                                    "{ctx_msg}: error body diverged from independent oracle"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Verifies real HTTP/1.1 wire serialization through `HttpEngine::serve_hyper_connection` for a
/// routed HTTPS 200 static file response with `Strict` security headers, `Alt-Svc`, and multi-value
/// site+route header rules, comparing exact raw wire header lines and byte values against the
/// independent `416f01f` oracle.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn static_200_real_http1_wire_serialization_matches_416f01f_oracle() -> TestResult {
    let dir = TempDirGuard::new("wire-h1")?;
    let body_text = "MiraServe real HTTP/1.1 wire serialization oracle payload.\n".repeat(32);
    let gz_bytes = compress_bytes(ContentEncoding::Gzip, body_text.as_bytes())?;
    let br_bytes = compress_bytes(ContentEncoding::Brotli, body_text.as_bytes())?;
    let assets_fx =
        DirFixtures::write_and_stat(&dir.path.join("assets"), &body_text, &gz_bytes, &br_bytes)?;

    let site_rules: &[OracleRule<'_>] = &[
        OracleRule::Set("cache-control", "public, max-age=3600"),
        OracleRule::Add("x-site-tag", "s1"),
        OracleRule::Add("x-site-tag", "s2"),
        OracleRule::Remove("x-content-type-options"),
    ];
    let route_rules: &[OracleRule<'_>] = &[
        OracleRule::Set("x-route-id", "assets"),
        OracleRule::Add("x-route-multi", "r1"),
        OracleRule::Add("x-route-multi", "r2"),
    ];

    let root_kdl = encode_kdl_string(&dir.path.to_string_lossy());
    let site_rules_kdl = format_kdl_rules(site_rules);
    let route_rules_kdl = format_kdl_rules(route_rules);
    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443" protocols="h1,h2,h3"
}}
site "oracle.test" {{
    root {root_kdl}
    http "serve"
    security-headers "strict"
    {site_rules_kdl}
    route "/assets/*" {{
        root {root_kdl}
        static {{ }}
        {route_rules_kdl}
    }}
}}
"#
    );
    let (cfg, _) = parse_kdl("wire-oracle.kdl", &kdl)?;
    let alt_val = HeaderValue::from_static("h3=\":8443\"; ma=86400");
    let engine = Arc::new(HttpEngine::from_config(
        &cfg,
        Arc::new(AcmeChallengeStore::new()),
        Some(8443),
        8443,
    )?);

    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let peer: SocketAddr = "198.51.100.30:51000".parse()?;
    let local: SocketAddr = "127.0.0.1:8443".parse()?;
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(engine.serve_hyper_connection(
        server,
        peer,
        local,
        true,
        false,
        None,
        shutdown_rx,
    ));

    client
        .write_all(
            b"GET /assets/asset.txt HTTP/1.1\r\nHost: oracle.test\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let mut raw = Vec::new();
    client.read_to_end(&mut raw).await?;
    server_task.await?;

    let head_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("missing HTTP/1.1 header terminator on wire")?;
    let head_bytes = raw.get(..head_end).ok_or("header slice out of bounds")?;
    let body_bytes = raw.get(head_end + 4..).ok_or("body slice out of bounds")?;
    assert_eq!(body_bytes, body_text.as_bytes());

    let mut lines = head_bytes.split(|&b| b == b'\n');
    let status_line = lines
        .next()
        .ok_or("missing status line")?
        .strip_suffix(b"\r")
        .unwrap_or(&[]);
    assert_eq!(status_line, b"HTTP/1.1 200 OK");

    let mut wire_headers: Vec<(String, Vec<u8>)> = Vec::new();
    for line in lines {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let colon = line
            .iter()
            .position(|&b| b == b':')
            .ok_or("malformed wire header line")?;
        let name = std::str::from_utf8(line.get(..colon).unwrap_or(&[]))?.to_ascii_lowercase();
        let val = line
            .get(colon + 1..)
            .unwrap_or(&[])
            .strip_prefix(b" ")
            .unwrap_or_else(|| line.get(colon + 1..).unwrap_or(&[]))
            .to_vec();
        wire_headers.push((name, val));
    }

    // Hyper appends transport-level `connection: close` (matching our request) and `date` on the
    // wire after all response headers; validate and strip only those trailing transport lines
    // before comparing exact wire order against `416f01f`.
    if wire_headers.last().is_some_and(|(k, _)| k == "date") {
        let (_, date_bytes) = wire_headers.pop().ok_or("date missing")?;
        assert!(
            date_bytes.ends_with(b" GMT"),
            "unexpected hyper wire Date header: {:?}",
            String::from_utf8_lossy(&date_bytes)
        );
    }
    if wire_headers.last().is_some_and(|(k, _)| k == "connection") {
        let (_, conn_bytes) = wire_headers.pop().ok_or("connection missing")?;
        assert_eq!(
            conn_bytes, b"close",
            "unexpected hyper wire Connection header"
        );
    }

    let mut expected = oracle_416f01f_file_headers(
        ORACLE_TEXT_PLAIN_UTF8,
        assets_fx.plain.len,
        assets_fx.plain.etag.clone(),
        assets_fx.plain.last_modified.clone(),
        None,
        None,
    )?;
    oracle_416f01f_apply_security_headers(
        &mut expected,
        SecurityHeadersPolicy::Strict,
        true,
        Some(&alt_val),
        Version::HTTP_11,
    );
    oracle_416f01f_apply_rules(&mut expected, site_rules, route_rules, true, true)?;

    assert_eq!(
        wire_headers,
        ordered_wire_headers(&expected),
        "real HTTP/1.1 wire header serialization diverged from 416f01f oracle"
    );
    Ok(())
}

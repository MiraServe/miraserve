//! Built-in MiraServe error pages and default welcome page.
//!
//! Sources of truth live in `design/default-pages/` and `design/brand/` and are embedded
//! hermetically from `assets/default-pages/` so `miraserve-http` has zero runtime file I/O
//! for built-in responses.
//!
//! # Security Invariants
//! - Strict `Accept` content negotiation (`application/problem+json` / `application/json`,
//!   `text/markdown`, `text/html`, fallback `text/plain`), always emitting `Vary: Accept`.
//! - Fresh 128-bit cryptographic CSP nonce per response (`default-src 'none'; style-src 'nonce-...'`).
//! - Server-generated Crockford Base32 ULID `request_id` displayed on every error page and
//!   written identically to `miraserve::access` and security logs.
//! - Attacker-controlled request fields (`path`, `host`, `method`, `login_url`) are strictly
//!   sanitized and escaped for the target output format (HTML, JSON, Markdown, or plain text).
//! - Never reveals MiraServe version, OS, module list, stack traces, file paths, or upstreams.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use http::header::{
    ACCEPT, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_SECURITY_POLICY, CONTENT_TYPE, HeaderName,
    HeaderValue, RETRY_AFTER, SERVER, VARY, X_CONTENT_TYPE_OPTIONS,
};
use http::{HeaderMap, Method, Response, StatusCode, Version};
use serde::Deserialize;

use crate::{HttpBody, TlsConnectionInfo, empty_http_body, full_http_body};

const MESSAGES_JSON: &str = include_str!("../assets/default-pages/messages.json");
const EXTRAS_JSON: &str = include_str!("../assets/default-pages/extras.json");
const ERROR_HTML_TEMPLATE: &str = include_str!("../assets/default-pages/error.html");
const WELCOME_HTML_TEMPLATE: &str = include_str!("../assets/default-pages/welcome.html");
const ERROR_PROBLEM_JSON_TEMPLATE: &str =
    include_str!("../assets/default-pages/error.problem.json");
const ERROR_MD_TEMPLATE: &str = include_str!("../assets/default-pages/error.md");
const ERROR_TXT_TEMPLATE: &str = include_str!("../assets/default-pages/error.txt");

/// Default `Retry-After` interval in seconds emitted on `503 Service Unavailable` when
/// no explicit upstream/limiter value is present.
pub const DEFAULT_RETRY_AFTER_SECS: u64 = 30;

/// Maximum size in bytes permitted for a per-site custom error page override file (512 KiB).
pub const MAX_CUSTOM_ERROR_PAGE_BYTES: u64 = 512 * 1024;

/// Maximum number of comma-separated `Accept` media ranges parsed per request (anti-DoS cap).
const MAX_ACCEPT_RANGES: usize = 32;

/// Maximum displayed length (in Unicode scalar values) for attacker-controlled request fields.
const MAX_DISPLAY_PATH_CHARS: usize = 512;
const MAX_DISPLAY_HOST_CHARS: usize = 255;
const MAX_DISPLAY_METHOD_CHARS: usize = 32;

/// Custom header carrying the server-generated request ID matching access and audit logs.
const X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// Negotiated representation format for built-in error and welcome pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageFormat {
    /// RFC 9457 Problem Details JSON (`application/problem+json` for errors, `application/json` for welcome).
    ProblemJson,
    /// Compact Markdown (`text/markdown`) for AI agents.
    Markdown,
    /// Self-contained branded HTML (`text/html`) with nonce'd CSS and inline SVG mark.
    Html,
    /// Minimal plain text (`text/plain`) fallback for `curl`, `*/*`, or omitted `Accept`.
    Text,
}

/// Pre-loaded custom error page file for a specific HTTP status code on a site.
#[derive(Debug, Clone)]
pub struct CustomErrorPage {
    /// Raw file contents loaded at compile/reload time.
    pub body: Bytes,
    /// Content-Type derived from file extension (defaults to `text/html; charset=utf-8`).
    pub content_type: &'static str,
}

/// Per-site error page configuration compiled into `CompiledSite`.
#[derive(Debug, Clone, Default)]
pub struct SiteErrorPages {
    /// Optional validated sign-in URL rendered for `401 Unauthorized` actions.
    pub login_url: Option<String>,
    /// Pre-loaded per-status custom error page replacements (`400..=599`).
    pub pages: BTreeMap<u16, CustomErrorPage>,
}

/// Request and error context passed to [`render_error_response`].
#[derive(Debug, Clone, Copy)]
pub struct ErrorPageContext<'a> {
    /// HTTP error status code to render.
    pub status: StatusCode,
    /// Request HTTP method (used for `405` copy and `HEAD` empty-body semantics).
    pub method: &'a Method,
    /// Request URI path (without query string).
    pub path: &'a str,
    /// Request host (if available).
    pub host: Option<&'a str>,
    /// Server-generated request ID matching access/audit logs.
    pub request_id: &'a str,
    /// Optional `Retry-After` delay in seconds (used on `429` and `503`).
    pub retry_after_secs: Option<u64>,
    /// Optional site-level custom error pages and `login-url`.
    pub site_pages: Option<&'a SiteErrorPages>,
}

/// Connection context passed to [`render_welcome_response`].
#[derive(Debug, Clone, Copy)]
pub struct WelcomePageContext<'a> {
    /// Request HTTP method (`GET` or `HEAD`).
    pub method: &'a Method,
    /// Request host (if available).
    pub host: Option<&'a str>,
    /// Human-readable TLS summary (`"TLS 1.3 · post-quantum"`, `"TLS 1.3"`, `"TLS 1.2"`, or `"Plaintext HTTP"`).
    pub tls_summary: &'a str,
    /// Human-readable HTTP protocol (`"HTTP/3"`, `"HTTP/2"`, `"HTTP/1.1"`, or `"HTTP/1.0"`).
    pub protocol: &'a str,
    /// Human-readable worker sandbox state (`"Enabled"`, `"Filesystem confined"`, or `"Not enabled"`).
    pub sandbox_state: &'a str,
    /// Server-generated request ID matching access/audit logs.
    pub request_id: &'a str,
}

/// Deterministic rendering options exposed for snapshot testing against `design/default-pages/previews/`.
#[derive(Debug, Clone, Copy)]
pub struct DeterministicRenderOptions<'a> {
    /// Request path (e.g. `"/old-pricing"`).
    pub path: &'a str,
    /// Request host (e.g. `"shop.example.com"`).
    pub host: &'a str,
    /// HTTP method (e.g. `"DELETE"`).
    pub method: &'a str,
    /// Fixed request ID (e.g. `"01JDV8K3N7Q2X4M6ZP"`).
    pub request_id: &'a str,
    /// Fixed formatted UTC timestamp (e.g. `"2026-11-19 08:42:10 UTC"`).
    pub time_utc: &'a str,
    /// Fixed CSP nonce (e.g. `"PREVIEW"`).
    pub csp_nonce: &'a str,
    /// Optional `Retry-After` seconds (defaults to `30`).
    pub retry_after_secs: Option<u64>,
    /// Optional `401` sign-in URL (e.g. `Some("/login")`).
    pub login_url: Option<&'a str>,
}

#[derive(Debug, Clone, Deserialize)]
struct CatalogEntry {
    reason: String,
    kind: String,
    heading: String,
    explanation: String,
    tips: Vec<String>,
    actions: Vec<[String; 2]>,
    #[serde(default)]
    extra: Option<String>,
    #[serde(default)]
    upstream_state: Option<String>,
}

#[derive(Debug)]
struct PageCatalog {
    messages: BTreeMap<u16, CatalogEntry>,
    extras: BTreeMap<String, String>,
}

fn catalog() -> &'static PageCatalog {
    static CATALOG: OnceLock<PageCatalog> = OnceLock::new();
    CATALOG.get_or_init(|| {
        let raw_msgs: BTreeMap<String, CatalogEntry> =
            serde_json::from_str(MESSAGES_JSON).unwrap_or_default();
        let mut messages = BTreeMap::new();
        for (k, v) in raw_msgs {
            if let Ok(code) = k.parse::<u16>() {
                messages.insert(code, v);
            }
        }
        let extras: BTreeMap<String, String> =
            serde_json::from_str(EXTRAS_JSON).unwrap_or_default();
        PageCatalog { messages, extras }
    })
}

fn fallback_catalog_entry(status: StatusCode) -> CatalogEntry {
    let code = status.as_u16();
    let reason = status.canonical_reason().unwrap_or("Error").to_owned();
    let kind = if status.is_server_error() {
        "server"
    } else {
        "client"
    }
    .to_owned();

    match code {
        421 => CatalogEntry {
            reason,
            kind,
            heading: "This connection can’t serve that site".to_owned(),
            explanation: "The request for {{host}} was sent over a connection that isn’t configured for it.".to_owned(),
            tips: vec![
                "Retry the request on a fresh connection.".to_owned(),
                "Check that the address matches the site you intended to visit.".to_owned(),
            ],
            actions: vec![
                ["Try again".to_owned(), String::new()],
                ["Go to homepage".to_owned(), "/".to_owned()],
            ],
            extra: None,
            upstream_state: None,
        },
        431 => CatalogEntry {
            reason,
            kind,
            heading: "The request headers are too large".to_owned(),
            explanation: "The client sent more header data than this site allows.".to_owned(),
            tips: vec![
                "Clear cookies for this site and try again.".to_owned(),
                "Start again from the homepage.".to_owned(),
            ],
            actions: vec![["Go to homepage".to_owned(), "/".to_owned()]],
            extra: None,
            upstream_state: None,
        },
        _ if status.is_server_error() => CatalogEntry {
            reason,
            kind,
            heading: "Something went wrong on our side".to_owned(),
            explanation: "The server couldn’t finish your request. For your security, no technical details are shown here; the site owner can find them in the server log using the request ID.".to_owned(),
            tips: vec![
                "Refresh the page in a moment.".to_owned(),
                "If the problem continues, contact the site owner and include the request ID.".to_owned(),
            ],
            actions: vec![
                ["Try again".to_owned(), String::new()],
                ["Go to homepage".to_owned(), "/".to_owned()],
            ],
            extra: None,
            upstream_state: None,
        },
        _ => CatalogEntry {
            reason,
            kind,
            heading: "The request couldn’t be completed".to_owned(),
            explanation: "The server couldn’t fulfill the request for <code>{{path}}</code>.".to_owned(),
            tips: vec![
                "Check the address and try again.".to_owned(),
                "Start again from the homepage.".to_owned(),
            ],
            actions: vec![["Go to homepage".to_owned(), "/".to_owned()]],
            extra: None,
            upstream_state: None,
        },
    }
}

/// Returns the built-in catalog status codes (`400..=504`).
#[must_use]
pub fn catalog_status_codes() -> Vec<u16> {
    catalog().messages.keys().copied().collect()
}

/// Number of random bytes consumed per request ID (80 bits, ULID spec).
const REQUEST_ID_RAND_CHUNK: usize = 10;

/// Number of request IDs served from each `SystemRandom` refill on a worker thread.
///
/// Security argument: every byte still comes directly from `aws_lc_rs::rand::SystemRandom`
/// (`RAND_bytes`, AWS-LC's CSPRNG). Slicing disjoint 10-byte segments from a 2560-byte
/// `SystemRandom::fill` call has the exact same joint uniform distribution (80 bits of
/// independent cryptographic entropy per ID) as 256 separate 10-byte calls, while cutting FFI
/// calls into `RAND_bytes` by 256x. The buffer is thread-local (no lock contention, no
/// cross-thread sharing), consumed slices are zeroed immediately, and remaining bytes are zeroed
/// on thread exit. Worker threads never `fork()` after serving begins, and CSP nonces
/// (`generate_csp_nonce`) remain unbuffered direct `SystemRandom` calls.
const REQUEST_ID_RAND_BATCH: usize = 256;
const REQUEST_ID_RAND_BUF_LEN: usize = REQUEST_ID_RAND_CHUNK * REQUEST_ID_RAND_BATCH;

struct RequestIdRngBuf {
    buf: [u8; REQUEST_ID_RAND_BUF_LEN],
    offset: usize,
}

impl RequestIdRngBuf {
    const fn new() -> Self {
        Self {
            buf: [0_u8; REQUEST_ID_RAND_BUF_LEN],
            offset: REQUEST_ID_RAND_BUF_LEN,
        }
    }

    fn next_ten_bytes(&mut self) -> Result<[u8; REQUEST_ID_RAND_CHUNK], ()> {
        if self.offset + REQUEST_ID_RAND_CHUNK > self.buf.len() {
            if SystemRandom::new().fill(&mut self.buf).is_err() {
                self.offset = self.buf.len();
                return Err(());
            }
            self.offset = 0;
        }
        let start = self.offset;
        let end = start + REQUEST_ID_RAND_CHUNK;
        self.offset = end;
        let mut out = [0_u8; REQUEST_ID_RAND_CHUNK];
        if let Some(src) = self.buf.get_mut(start..end) {
            out.copy_from_slice(src);
            src.fill(0);
            Ok(out)
        } else {
            Err(())
        }
    }
}

impl Drop for RequestIdRngBuf {
    fn drop(&mut self) {
        self.buf.fill(0);
    }
}

thread_local! {
    static REQUEST_ID_RNG: RefCell<RequestIdRngBuf> = const { RefCell::new(RequestIdRngBuf::new()) };
}

fn fill_request_id_random_bytes() -> Result<[u8; REQUEST_ID_RAND_CHUNK], ()> {
    let direct = || {
        let mut out = [0_u8; REQUEST_ID_RAND_CHUNK];
        SystemRandom::new()
            .fill(&mut out)
            .map(|()| out)
            .map_err(|_| ())
    };
    REQUEST_ID_RNG
        .try_with(|cell| {
            if let Ok(mut rng) = cell.try_borrow_mut() {
                rng.next_ten_bytes()
            } else {
                direct()
            }
        })
        .unwrap_or_else(|_| direct())
}

const fn crockford_digit(val: u64) -> u8 {
    match val & 0x1F {
        0 => b'0',
        1 => b'1',
        2 => b'2',
        3 => b'3',
        4 => b'4',
        5 => b'5',
        6 => b'6',
        7 => b'7',
        8 => b'8',
        9 => b'9',
        10 => b'A',
        11 => b'B',
        12 => b'C',
        13 => b'D',
        14 => b'E',
        15 => b'F',
        16 => b'G',
        17 => b'H',
        18 => b'J',
        19 => b'K',
        20 => b'M',
        21 => b'N',
        22 => b'P',
        23 => b'Q',
        24 => b'R',
        25 => b'S',
        26 => b'T',
        27 => b'V',
        28 => b'W',
        29 => b'X',
        30 => b'Y',
        _ => b'Z',
    }
}

/// Stack-stored 26-character Crockford Base32 ULID request identifier (zero heap allocation).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct RequestId {
    bytes: [u8; 26],
}

impl RequestId {
    /// Encodes a 48-bit Unix millisecond timestamp and 80 random bits into 26 Crockford Base32
    /// ASCII bytes (10 timestamp chars followed by 16 random chars, most significant first).
    #[must_use]
    pub(crate) const fn from_parts(millis: u64, rand_bytes: [u8; 10]) -> Self {
        let [r0, r1, r2, r3, r4, r5, r6, r7, r8, r9] = rand_bytes;
        let hi = ((r0 as u64) << 32)
            | ((r1 as u64) << 24)
            | ((r2 as u64) << 16)
            | ((r3 as u64) << 8)
            | (r4 as u64);
        let lo = ((r5 as u64) << 32)
            | ((r6 as u64) << 24)
            | ((r7 as u64) << 16)
            | ((r8 as u64) << 8)
            | (r9 as u64);
        Self {
            bytes: [
                crockford_digit(millis >> 45),
                crockford_digit(millis >> 40),
                crockford_digit(millis >> 35),
                crockford_digit(millis >> 30),
                crockford_digit(millis >> 25),
                crockford_digit(millis >> 20),
                crockford_digit(millis >> 15),
                crockford_digit(millis >> 10),
                crockford_digit(millis >> 5),
                crockford_digit(millis),
                crockford_digit(hi >> 35),
                crockford_digit(hi >> 30),
                crockford_digit(hi >> 25),
                crockford_digit(hi >> 20),
                crockford_digit(hi >> 15),
                crockford_digit(hi >> 10),
                crockford_digit(hi >> 5),
                crockford_digit(hi),
                crockford_digit(lo >> 35),
                crockford_digit(lo >> 30),
                crockford_digit(lo >> 25),
                crockford_digit(lo >> 20),
                crockford_digit(lo >> 15),
                crockford_digit(lo >> 10),
                crockford_digit(lo >> 5),
                crockford_digit(lo),
            ],
        }
    }

    #[cfg(test)]
    pub(crate) const fn from_ascii_bytes(bytes: [u8; 26]) -> Self {
        Self { bytes }
    }

    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes).unwrap_or("")
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

/// Generates a fresh 26-character Crockford Base32 ULID request identifier on the stack using
/// the current Unix millisecond timestamp and 80 bits from a thread-local buffer refilled from
/// `aws_lc_rs::rand::SystemRandom`.
#[must_use]
pub(crate) fn generate_request_id_inline() -> RequestId {
    static FALLBACK_COUNTER: AtomicU64 = AtomicU64::new(1);

    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0_u64, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));

    let rand_bytes = fill_request_id_random_bytes().unwrap_or_else(|()| {
        let seq = FALLBACK_COUNTER.fetch_add(1, Ordering::Relaxed);
        let [b0, b1, b2, b3, b4, b5, b6, b7] = seq.to_be_bytes();
        let m0 = u8::try_from(millis & 0xFF).unwrap_or(0);
        let m1 = u8::try_from((millis >> 8) & 0xFF).unwrap_or(0);
        [b0, b1, b2, b3, b4, b5, b6, b7, m0, m1]
    });

    RequestId::from_parts(millis, rand_bytes)
}

/// Generates a fresh 26-character Crockford Base32 ULID request identifier using the current
/// Unix millisecond timestamp and 80 bits from `aws_lc_rs::rand::SystemRandom`.
#[must_use]
pub fn generate_request_id() -> String {
    generate_request_id_inline().as_str().to_owned()
}

/// Generates a fresh 128-bit cryptographic random CSP nonce encoded as URL-safe Base64 (no padding).
#[must_use]
pub fn generate_csp_nonce() -> String {
    static FALLBACK_NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);

    let mut bytes = [0_u8; 16];
    if SystemRandom::new().fill(&mut bytes).is_err() {
        let seq = FALLBACK_NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0_u64, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
        let [s0, s1, s2, s3, s4, s5, s6, s7] = seq.to_be_bytes();
        let [n0, n1, n2, n3, n4, n5, n6, n7] = nanos.to_be_bytes();
        bytes = [
            s0, s1, s2, s3, s4, s5, s6, s7, n0, n1, n2, n3, n4, n5, n6, n7,
        ];
    }
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Formats `time` in UTC as `YYYY-MM-DD HH:MM:SS UTC` using integer civil-calendar arithmetic.
#[must_use]
pub fn format_utc_timestamp(time: SystemTime) -> String {
    let secs = time
        .duration_since(UNIX_EPOCH)
        .map_or(0_u64, |d| d.as_secs());
    format_unix_secs_utc(secs)
}

/// Formats Unix epoch seconds as `YYYY-MM-DD HH:MM:SS UTC`.
#[must_use]
pub fn format_unix_secs_utc(secs: u64) -> String {
    let days_u64 = secs / 86_400;
    let rem = secs % 86_400;
    let hour = rem / 3_600;
    let minute = (rem % 3_600) / 60;
    let second = rem % 60;

    // Howard Hinnant's proleptic Gregorian civil_from_days algorithm.
    let z = i64::try_from(days_u64).unwrap_or(0).saturating_add(719_468);
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = u64::try_from(z - era * 146_097).unwrap_or(0);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = i64::try_from(yoe).unwrap_or(0) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + i64::from(month <= 2);

    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC")
}

/// Formats a human-readable connection TLS summary for `welcome.html` without leaking
/// software versions, ciphersuite internals, or OS details.
#[must_use]
pub const fn format_tls_summary(is_https: bool, tls: Option<&TlsConnectionInfo>) -> &'static str {
    if !is_https {
        return "Plaintext HTTP";
    }
    match tls {
        Some(info) if info.is_tls13 && info.is_pqc => "TLS 1.3 · post-quantum",
        Some(info) if info.is_tls13 => "TLS 1.3",
        Some(_) => "TLS 1.2",
        None => "TLS 1.3",
    }
}

/// Formats a human-readable HTTP protocol label for `welcome.html`.
#[must_use]
pub const fn format_http_protocol(version: Version) -> &'static str {
    match version {
        Version::HTTP_3 => "HTTP/3",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_10 => "HTTP/1.0",
        _ => "HTTP/1.1",
    }
}

/// Selects the output representation from the request's `Accept` header(s) per `design/README.md`:
/// - `application/json` or `application/problem+json` -> [`PageFormat::ProblemJson`]
/// - `text/markdown` -> [`PageFormat::Markdown`]
/// - `text/html` -> [`PageFormat::Html`]
/// - anything else (`*/*`, omitted `Accept`, `text/plain`, etc.) -> [`PageFormat::Text`]
///
/// Honors RFC 9110 `q`-values (`0.000..=1.000`, `q=0` explicitly excludes a media type) and
/// caps parsed media ranges to 32 entries.
#[must_use]
pub fn negotiate_format(headers: &HeaderMap) -> PageFormat {
    let mut best_json: Option<u16> = None;
    let mut best_md: Option<u16> = None;
    let mut best_html: Option<u16> = None;
    let mut json_forbidden = false;
    let mut md_forbidden = false;
    let mut html_forbidden = false;
    let mut count = 0_usize;

    for val in headers.get_all(ACCEPT) {
        let Ok(raw) = val.to_str() else {
            continue;
        };
        for item in raw.split(',') {
            if count >= MAX_ACCEPT_RANGES {
                break;
            }
            count += 1;

            let mut parts = item.split(';');
            let Some(media_raw) = parts.next() else {
                continue;
            };
            let media = media_raw.trim().to_ascii_lowercase();
            let target = match media.as_str() {
                "application/problem+json" | "application/json" => PageFormat::ProblemJson,
                "text/markdown" => PageFormat::Markdown,
                "text/html" => PageFormat::Html,
                _ => continue,
            };

            let mut q_milli: u16 = 1_000;
            let mut valid_q = true;
            for param in parts {
                let Some((k, v)) = param.split_once('=') else {
                    continue;
                };
                if k.trim().eq_ignore_ascii_case("q") {
                    if let Some(parsed) = parse_qvalue_milli(v.trim()) {
                        q_milli = parsed;
                    } else {
                        valid_q = false;
                    }
                    break;
                }
            }
            if !valid_q {
                continue;
            }

            match target {
                PageFormat::ProblemJson => {
                    if q_milli == 0 {
                        json_forbidden = true;
                    } else {
                        best_json = Some(best_json.map_or(q_milli, |cur| cur.max(q_milli)));
                    }
                }
                PageFormat::Markdown => {
                    if q_milli == 0 {
                        md_forbidden = true;
                    } else {
                        best_md = Some(best_md.map_or(q_milli, |cur| cur.max(q_milli)));
                    }
                }
                PageFormat::Html => {
                    if q_milli == 0 {
                        html_forbidden = true;
                    } else {
                        best_html = Some(best_html.map_or(q_milli, |cur| cur.max(q_milli)));
                    }
                }
                PageFormat::Text => {}
            }
        }
    }

    let mut winner = PageFormat::Text;
    let mut winner_score = (0_u16, 0_u8);

    // Spec precedence on equal q-value: ProblemJson (3) > Markdown (2) > Html (1).
    let candidates = [
        (
            PageFormat::ProblemJson,
            if json_forbidden { None } else { best_json },
            3_u8,
        ),
        (
            PageFormat::Markdown,
            if md_forbidden { None } else { best_md },
            2_u8,
        ),
        (
            PageFormat::Html,
            if html_forbidden { None } else { best_html },
            1_u8,
        ),
    ];

    for (fmt, q_opt, prio) in candidates {
        if let Some(q) = q_opt
            && q > 0
            && (q, prio) > winner_score
        {
            winner = fmt;
            winner_score = (q, prio);
        }
    }
    winner
}

/// Parses an RFC 9110 §12.4.2 `qvalue` (`0`..`1`, up to 3 decimal digits) into `0..=1000`.
fn parse_qvalue_milli(raw: &str) -> Option<u16> {
    if raw.is_empty() || raw.len() > 5 {
        return None;
    }
    if let Some(frac) = raw.strip_prefix("1.") {
        if frac.len() <= 3 && frac.bytes().all(|b| b == b'0') {
            return Some(1_000);
        }
        return None;
    }
    if raw == "1" {
        return Some(1_000);
    }
    if raw == "0" {
        return Some(0);
    }
    if let Some(frac) = raw.strip_prefix("0.") {
        if frac.is_empty() || frac.len() > 3 || !frac.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let mut val: u16 = 0;
        for b in frac.bytes() {
            val = val * 10 + u16::from(b - b'0');
        }
        for _ in frac.len()..3 {
            val *= 10;
        }
        return Some(val);
    }
    None
}

/// Determines a safe `Content-Type` for a per-site custom error page based on file extension.
#[must_use]
pub fn custom_page_content_type(path: &str) -> &'static str {
    let Some(ext) = std::path::Path::new(path)
        .extension()
        .and_then(std::ffi::OsStr::to_str)
    else {
        return "text/html; charset=utf-8";
    };
    if ext.eq_ignore_ascii_case("json") {
        "application/problem+json; charset=utf-8"
    } else if ext.eq_ignore_ascii_case("md") || ext.eq_ignore_ascii_case("markdown") {
        "text/markdown; charset=utf-8"
    } else if ext.eq_ignore_ascii_case("txt") {
        "text/plain; charset=utf-8"
    } else {
        "text/html; charset=utf-8"
    }
}

/// Returns `true` when the request's `Accept` header allows serving a site's custom error page.
///
/// Matches exact format (`text/html`, `application/problem+json`, `text/markdown`, `text/plain`)
/// AND wildcard / omitted `Accept` headers (`*/*`, `text/*`, no `Accept`) unless the client
/// explicitly rejected the custom page's media type with `q=0` or explicitly asked ONLY for
/// another media type (such as `Accept: application/json`, `text/markdown`, or `text/plain`).
fn accepts_custom_error_page(
    headers: &HeaderMap,
    negotiated: PageFormat,
    custom_content_type: &str,
) -> bool {
    let custom_mime = custom_content_type
        .split(';')
        .next()
        .unwrap_or("text/html")
        .trim();
    let custom_format = match custom_mime {
        "application/problem+json" | "application/json" => PageFormat::ProblemJson,
        "text/markdown" => PageFormat::Markdown,
        "text/plain" => PageFormat::Text,
        _ => PageFormat::Html,
    };
    if negotiated == custom_format {
        return true;
    }
    // If the client explicitly negotiated JSON, Markdown, or HTML and that differs from the
    // custom page's format, honor the client's explicit format negotiation.
    if negotiated != PageFormat::Text {
        return false;
    }

    let custom_type = custom_mime.split('/').next().unwrap_or("text");
    let mut saw_any_header = false;
    let mut allows_wildcard = false;
    let mut custom_forbidden = false;
    let mut count = 0_usize;

    for val in headers.get_all(ACCEPT) {
        let Ok(raw) = val.to_str() else {
            continue;
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        saw_any_header = true;
        for item in trimmed.split(',') {
            if count >= MAX_ACCEPT_RANGES {
                break;
            }
            count += 1;
            let mut parts = item.split(';');
            let Some(media_raw) = parts.next() else {
                continue;
            };
            let media = media_raw.trim().to_ascii_lowercase();
            let mut q_milli: u16 = 1_000;
            let mut valid_q = true;
            for param in parts {
                let Some((k, v)) = param.split_once('=') else {
                    continue;
                };
                if k.trim().eq_ignore_ascii_case("q") {
                    if let Some(parsed) = parse_qvalue_milli(v.trim()) {
                        q_milli = parsed;
                    } else {
                        valid_q = false;
                    }
                    break;
                }
            }
            if !valid_q {
                continue;
            }
            if media == custom_mime && q_milli == 0 {
                custom_forbidden = true;
            } else if (media == "*/*"
                || media
                    .strip_suffix("/*")
                    .is_some_and(|prefix| prefix == custom_type))
                && q_milli > 0
            {
                allows_wildcard = true;
            }
        }
    }

    if !saw_any_header {
        return true;
    }
    allows_wildcard && !custom_forbidden
}

/// Validates that an action `href` (such as a configured `login-url`) uses a safe scheme
/// (`/` site-relative without `//`, `https://`, or `http://`) and contains no control chars.
#[must_use]
pub fn is_safe_action_href(href: &str) -> bool {
    if href.is_empty() {
        return true;
    }
    if href.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return false;
    }
    if href.starts_with('/') {
        return !href.starts_with("//");
    }
    if href == "./" {
        return true;
    }
    if let Some(rest) = href.strip_prefix("https://") {
        return !rest.is_empty();
    }
    if let Some(rest) = href.strip_prefix("http://") {
        return !rest.is_empty();
    }
    false
}

/// Renders a complete, content-negotiated MiraServe error [`Response`] with strict security headers.
#[must_use]
pub fn render_error_response(
    req_headers: &HeaderMap,
    ctx: &ErrorPageContext<'_>,
) -> Response<HttpBody> {
    let format = negotiate_format(req_headers);
    let status_u16 = ctx.status.as_u16();

    // Effective Retry-After for 429 and 503 (always present on both statuses per design/README.md).
    let retry_after = match status_u16 {
        429 | 503 => Some(
            ctx.retry_after_secs
                .unwrap_or(DEFAULT_RETRY_AFTER_SECS)
                .max(1),
        ),
        _ => ctx.retry_after_secs,
    };

    // Per-site custom error page override: serve when the negotiated format matches the custom
    // page OR when the client sent `*/*`, `text/*`, or omitted `Accept` (e.g. curl/browsers
    // without an explicit `text/html` range) while keeping explicit `application/json`,
    // `text/markdown`, or `text/plain`-only API negotiation intact (HANDOVER §5 #11).
    if let Some(site_pages) = ctx.site_pages
        && let Some(custom) = site_pages.pages.get(&status_u16)
        && accepts_custom_error_page(req_headers, format, custom.content_type)
    {
        return build_custom_error_response(
            ctx.status,
            ctx.method,
            custom,
            ctx.request_id,
            retry_after,
        );
    }

    let nonce = generate_csp_nonce();
    let time_utc = format_utc_timestamp(SystemTime::now());
    let clean_path = sanitize_display_value(ctx.path, MAX_DISPLAY_PATH_CHARS);
    let clean_host = ctx
        .host
        .map(|h| sanitize_display_value(h, MAX_DISPLAY_HOST_CHARS))
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "this site".to_owned());
    let clean_method = sanitize_display_value(ctx.method.as_str(), MAX_DISPLAY_METHOD_CHARS);
    let login_url = ctx
        .site_pages
        .and_then(|sp| sp.login_url.as_deref())
        .filter(|u| !u.is_empty() && is_safe_action_href(u));

    let opts = DeterministicRenderOptions {
        path: &clean_path,
        host: &clean_host,
        method: &clean_method,
        request_id: ctx.request_id,
        time_utc: &time_utc,
        csp_nonce: &nonce,
        retry_after_secs: retry_after,
        login_url,
    };

    let (content_type, rendered) = match format {
        PageFormat::Html => (
            "text/html; charset=utf-8",
            render_error_html_with_options(ctx.status, &opts, false),
        ),
        PageFormat::ProblemJson => (
            "application/problem+json; charset=utf-8",
            render_error_problem_json(ctx.status, &opts),
        ),
        PageFormat::Markdown => (
            "text/markdown; charset=utf-8",
            render_error_markdown(ctx.status, &opts),
        ),
        PageFormat::Text => (
            "text/plain; charset=utf-8",
            render_error_text(ctx.status, &opts),
        ),
    };

    build_builtin_response(
        ctx.status,
        ctx.method,
        content_type,
        rendered.into_bytes(),
        &nonce,
        ctx.request_id,
        retry_after,
    )
}

/// Renders the built-in default Welcome page (`welcome.html` for browsers, plus clean JSON /
/// Markdown / plain-text equivalents for APIs, AI agents, and CLI tools) with `200 OK`.
#[must_use]
pub fn render_welcome_response(
    req_headers: &HeaderMap,
    ctx: &WelcomePageContext<'_>,
) -> Response<HttpBody> {
    let format = negotiate_format(req_headers);
    let nonce = generate_csp_nonce();
    let clean_host = ctx
        .host
        .map(|h| sanitize_display_value(h, MAX_DISPLAY_HOST_CHARS))
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "example.com".to_owned());

    let (content_type, rendered) = match format {
        PageFormat::Html => (
            "text/html; charset=utf-8",
            render_welcome_html_deterministic(
                &clean_host,
                ctx.tls_summary,
                ctx.protocol,
                ctx.sandbox_state,
                &nonce,
            ),
        ),
        PageFormat::ProblemJson => (
            "application/json; charset=utf-8",
            render_welcome_json(
                &clean_host,
                ctx.tls_summary,
                ctx.protocol,
                ctx.sandbox_state,
                ctx.request_id,
            ),
        ),
        PageFormat::Markdown => (
            "text/markdown; charset=utf-8",
            render_welcome_markdown(
                &clean_host,
                ctx.tls_summary,
                ctx.protocol,
                ctx.sandbox_state,
                ctx.request_id,
            ),
        ),
        PageFormat::Text => (
            "text/plain; charset=utf-8",
            render_welcome_text(
                &clean_host,
                ctx.tls_summary,
                ctx.protocol,
                ctx.sandbox_state,
                ctx.request_id,
            ),
        ),
    };

    build_builtin_response(
        StatusCode::OK,
        ctx.method,
        content_type,
        rendered.into_bytes(),
        &nonce,
        ctx.request_id,
        None,
    )
}

/// Renders the built-in HTML error page deterministically for testing and snapshot verification.
///
/// Uses `href=""` (RFC 3986 same-document reload) for empty action hrefs per `design/README.md`.
#[must_use]
pub fn render_error_html_deterministic(
    status: StatusCode,
    opts: &DeterministicRenderOptions<'_>,
) -> String {
    render_error_html_with_options(status, opts, false)
}

/// Renders the built-in HTML error page matching the static preview convention (`href="./"`
/// for empty action hrefs) used when generating `design/default-pages/previews/*.html`.
#[must_use]
pub fn render_error_html_preview_compat(
    status: StatusCode,
    opts: &DeterministicRenderOptions<'_>,
) -> String {
    render_error_html_with_options(status, opts, true)
}

fn render_error_html_with_options(
    status: StatusCode,
    opts: &DeterministicRenderOptions<'_>,
    use_dot_slash_reload: bool,
) -> String {
    let cat = catalog();
    let owned_fallback;
    let entry = if let Some(found) = cat.messages.get(&status.as_u16()) {
        found
    } else {
        owned_fallback = fallback_catalog_entry(status);
        &owned_fallback
    };

    let status_str = status.as_u16().to_string();
    let kind_label = if entry.kind == "server" {
        "Server error"
    } else {
        "Client error"
    };

    let escaped_path = html_escape(&sanitize_display_value(opts.path, MAX_DISPLAY_PATH_CHARS));
    let escaped_host = html_escape(&sanitize_display_value(opts.host, MAX_DISPLAY_HOST_CHARS));
    let escaped_method = html_escape(&sanitize_display_value(
        opts.method,
        MAX_DISPLAY_METHOD_CHARS,
    ));
    let escaped_request_id = html_escape(&sanitize_display_value(opts.request_id, 64));
    let escaped_time = html_escape(&sanitize_display_value(opts.time_utc, 64));
    let escaped_nonce = html_escape(&sanitize_display_value(opts.csp_nonce, 128));

    let explanation = entry
        .explanation
        .replace("{{path}}", &escaped_path)
        .replace("{{host}}", &escaped_host)
        .replace("{{method}}", &escaped_method);

    let mut tips_html = String::new();
    for tip in &entry.tips {
        tips_html.push_str("<li>");
        tips_html.push_str(&html_escape(tip));
        tips_html.push_str("</li>");
    }

    let actions_html = render_actions_html(&entry.actions, opts.login_url, use_dot_slash_reload);

    let retry_secs = opts
        .retry_after_secs
        .unwrap_or(DEFAULT_RETRY_AFTER_SECS)
        .max(1);
    let extra_html = entry
        .extra
        .as_deref()
        .and_then(|key| cat.extras.get(key))
        .map_or_else(String::new, |tpl| {
            let upstream_state = entry.upstream_state.as_deref().unwrap_or("");
            tpl.replace("{{retry_after}}", &retry_secs.to_string())
                .replace("{{upstream_state}}", &html_escape(upstream_state))
        });

    let mut rendered = ERROR_HTML_TEMPLATE
        .replace("{{csp_nonce}}", &escaped_nonce)
        .replace("{{status}}", &status_str)
        .replace("{{reason}}", &html_escape(&entry.reason))
        .replace("{{kind}}", &html_escape(&entry.kind))
        .replace("{{kind_label}}", kind_label)
        .replace("{{heading}}", &html_escape(&entry.heading))
        .replace("{{explanation}}", &explanation)
        .replace("{{extra}}", &extra_html)
        .replace("{{tips}}", &tips_html)
        .replace("{{actions}}", &actions_html)
        .replace("{{request_id}}", &escaped_request_id)
        .replace("{{time}}", &escaped_time);

    // Sync the CSS progress-bar animation duration with dynamic Retry-After values inside the
    // existing nonce'd `<style>` block (zero inline style attributes, 100% strict CSP compliant!).
    if entry.extra.as_deref() == Some("retry") && retry_secs != DEFAULT_RETRY_AFTER_SECS {
        let clamped_css_secs = retry_secs.min(86_400);
        let override_css = format!(":root{{--retry:{clamped_css_secs}s}}\n</style>");
        rendered = rendered.replacen("</style>", &override_css, 1);
    }

    rendered
}

fn render_actions_html(
    actions: &[[String; 2]],
    login_url: Option<&str>,
    use_dot_slash_reload: bool,
) -> String {
    let mut resolved: Vec<(&str, String)> = Vec::with_capacity(actions.len());
    for [label, raw_href] in actions {
        if raw_href == "{{login_url}}" {
            if let Some(login) = login_url.filter(|u| !u.is_empty() && is_safe_action_href(u)) {
                resolved.push((label.as_str(), login.to_owned()));
            }
            continue;
        }
        let href = if raw_href.is_empty() {
            if use_dot_slash_reload {
                "./".to_owned()
            } else {
                String::new()
            }
        } else {
            raw_href.clone()
        };
        resolved.push((label.as_str(), href));
    }

    let mut out = String::new();
    for (idx, (label, href)) in resolved.iter().enumerate() {
        let cls = if idx == 0 {
            "btn primary"
        } else {
            "btn secondary"
        };
        out.push_str("<a class=\"");
        out.push_str(cls);
        out.push_str("\" href=\"");
        out.push_str(&html_escape(href));
        out.push_str("\">");
        out.push_str(&html_escape(label));
        out.push_str("</a>");
    }
    out
}

/// Renders an RFC 9457 Problem Details JSON error body deterministically.
#[must_use]
pub fn render_error_problem_json(
    status: StatusCode,
    opts: &DeterministicRenderOptions<'_>,
) -> String {
    let cat = catalog();
    let owned_fallback;
    let entry = if let Some(found) = cat.messages.get(&status.as_u16()) {
        found
    } else {
        owned_fallback = fallback_catalog_entry(status);
        &owned_fallback
    };

    let clean_path = sanitize_display_value(opts.path, MAX_DISPLAY_PATH_CHARS);
    let clean_host = sanitize_display_value(opts.host, MAX_DISPLAY_HOST_CHARS);
    let clean_method = sanitize_display_value(opts.method, MAX_DISPLAY_METHOD_CHARS);
    let clean_req_id = sanitize_display_value(opts.request_id, 64);

    let detail_plain = strip_html_tags(&entry.explanation)
        .replace("{{path}}", &clean_path)
        .replace("{{host}}", &clean_host)
        .replace("{{method}}", &clean_method);

    ERROR_PROBLEM_JSON_TEMPLATE
        .replace("{{reason}}", &json_escape_inner(&entry.reason))
        .replace("{{status}}", &status.as_u16().to_string())
        .replace("{{detail_plain}}", &json_escape_inner(&detail_plain))
        .replace("{{path}}", &json_escape_inner(&clean_path))
        .replace("{{request_id}}", &json_escape_inner(&clean_req_id))
}

/// Renders a compact Markdown error body (`text/markdown`) for AI agents.
#[must_use]
pub fn render_error_markdown(status: StatusCode, opts: &DeterministicRenderOptions<'_>) -> String {
    let cat = catalog();
    let owned_fallback;
    let entry = if let Some(found) = cat.messages.get(&status.as_u16()) {
        found
    } else {
        owned_fallback = fallback_catalog_entry(status);
        &owned_fallback
    };

    let md_path =
        markdown_escape_inline(&sanitize_display_value(opts.path, MAX_DISPLAY_PATH_CHARS));
    let md_host =
        markdown_escape_inline(&sanitize_display_value(opts.host, MAX_DISPLAY_HOST_CHARS));
    let md_method = markdown_escape_inline(&sanitize_display_value(
        opts.method,
        MAX_DISPLAY_METHOD_CHARS,
    ));
    let md_req_id = markdown_escape_inline(&sanitize_display_value(opts.request_id, 64));

    let detail_plain = strip_html_tags(&entry.explanation)
        .replace("{{path}}", &md_path)
        .replace("{{host}}", &md_host)
        .replace("{{method}}", &md_method);

    ERROR_MD_TEMPLATE
        .replace("{{status}}", &status.as_u16().to_string())
        .replace("{{reason}}", &entry.reason)
        .replace("{{detail_plain}}", &detail_plain)
        .replace("{{request_id}}", &md_req_id)
}

/// Renders a minimal plain-text error body (`text/plain`) for `curl` and `*/*` clients.
#[must_use]
pub fn render_error_text(status: StatusCode, opts: &DeterministicRenderOptions<'_>) -> String {
    let cat = catalog();
    let owned_fallback;
    let entry = if let Some(found) = cat.messages.get(&status.as_u16()) {
        found
    } else {
        owned_fallback = fallback_catalog_entry(status);
        &owned_fallback
    };

    let clean_path = sanitize_display_value(opts.path, MAX_DISPLAY_PATH_CHARS);
    let clean_host = sanitize_display_value(opts.host, MAX_DISPLAY_HOST_CHARS);
    let clean_method = sanitize_display_value(opts.method, MAX_DISPLAY_METHOD_CHARS);
    let clean_req_id = sanitize_display_value(opts.request_id, 64);

    let detail_plain = strip_html_tags(&entry.explanation)
        .replace("{{path}}", &clean_path)
        .replace("{{host}}", &clean_host)
        .replace("{{method}}", &clean_method);

    ERROR_TXT_TEMPLATE
        .replace("{{status}}", &status.as_u16().to_string())
        .replace("{{reason}}", &entry.reason)
        .replace("{{detail_plain}}", &detail_plain)
        .replace("{{request_id}}", &clean_req_id)
}

/// Renders the built-in HTML Welcome page deterministically for testing and snapshot verification.
#[must_use]
pub fn render_welcome_html_deterministic(
    host: &str,
    tls_summary: &str,
    protocol: &str,
    sandbox_state: &str,
    csp_nonce: &str,
) -> String {
    let escaped_host = html_escape(&sanitize_display_value(host, MAX_DISPLAY_HOST_CHARS));
    let escaped_tls = html_escape(&sanitize_display_value(tls_summary, 64));
    let escaped_proto = html_escape(&sanitize_display_value(protocol, 32));
    let escaped_sandbox = html_escape(&sanitize_display_value(sandbox_state, 64));
    let escaped_nonce = html_escape(&sanitize_display_value(csp_nonce, 128));

    WELCOME_HTML_TEMPLATE
        .replace("{{csp_nonce}}", &escaped_nonce)
        .replace("{{host}}", &escaped_host)
        .replace("{{tls_summary}}", &escaped_tls)
        .replace("{{protocol}}", &escaped_proto)
        .replace("{{sandbox_state}}", &escaped_sandbox)
}

fn render_welcome_json(
    host: &str,
    tls_summary: &str,
    protocol: &str,
    sandbox_state: &str,
    request_id: &str,
) -> String {
    let clean_host = sanitize_display_value(host, MAX_DISPLAY_HOST_CHARS);
    let clean_req_id = sanitize_display_value(request_id, 64);
    let detail = format!("No site is configured for {clean_host} yet.");
    format!(
        "{{\n  \"status\": \"running\",\n  \"title\": \"MiraServe is up and serving\",\n  \"detail\": \"{}\",\n  \"host\": \"{}\",\n  \"connection\": \"{}\",\n  \"protocol\": \"{}\",\n  \"worker_sandbox\": \"{}\",\n  \"request_id\": \"{}\"\n}}",
        json_escape_inner(&detail),
        json_escape_inner(&clean_host),
        json_escape_inner(tls_summary),
        json_escape_inner(protocol),
        json_escape_inner(sandbox_state),
        json_escape_inner(&clean_req_id),
    )
}

fn render_welcome_markdown(
    host: &str,
    tls_summary: &str,
    protocol: &str,
    sandbox_state: &str,
    request_id: &str,
) -> String {
    let md_host = markdown_escape_inline(&sanitize_display_value(host, MAX_DISPLAY_HOST_CHARS));
    let md_req_id = markdown_escape_inline(&sanitize_display_value(request_id, 64));
    format!(
        "# MiraServe is up and serving\n\nNo site is configured for {md_host} yet.\n\n- Connection: {tls_summary}\n- Protocol: {protocol}\n- Worker sandbox: {sandbox_state}\n\nRequest ID: {md_req_id}"
    )
}

fn render_welcome_text(
    host: &str,
    tls_summary: &str,
    protocol: &str,
    sandbox_state: &str,
    request_id: &str,
) -> String {
    let clean_host = sanitize_display_value(host, MAX_DISPLAY_HOST_CHARS);
    let clean_req_id = sanitize_display_value(request_id, 64);
    format!(
        "MiraServe is up and serving\n\nNo site is configured for {clean_host} yet.\nConnection: {tls_summary}\nProtocol: {protocol}\nWorker sandbox: {sandbox_state}\nRequest ID: {clean_req_id}\n"
    )
}

const VARY_ACCEPT: HeaderValue = HeaderValue::from_static("Accept");
const NOSNIFF_VALUE: HeaderValue = HeaderValue::from_static("nosniff");
const NO_STORE_VALUE: HeaderValue = HeaderValue::from_static("no-store");
const SERVER_VALUE: HeaderValue = HeaderValue::from_static("MiraServe");

fn build_builtin_response(
    status: StatusCode,
    method: &Method,
    content_type: &'static str,
    body_bytes: Vec<u8>,
    csp_nonce: &str,
    request_id: &str,
    retry_after_secs: Option<u64>,
) -> Response<HttpBody> {
    let csp = format!(
        "default-src 'none'; style-src 'nonce-{csp_nonce}'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    );
    let len = body_bytes.len();
    let body = if *method == Method::HEAD {
        empty_http_body()
    } else {
        full_http_body(Bytes::from(body_bytes))
    };

    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    let headers = resp.headers_mut();
    headers.reserve(12);
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(CONTENT_LENGTH, HeaderValue::from(len));
    headers.insert(VARY, VARY_ACCEPT);
    headers.insert(X_CONTENT_TYPE_OPTIONS, NOSNIFF_VALUE);
    headers.insert(CACHE_CONTROL, NO_STORE_VALUE);
    headers.insert(SERVER, SERVER_VALUE);

    if let Ok(csp_val) = HeaderValue::from_str(&csp) {
        headers.insert(CONTENT_SECURITY_POLICY, csp_val);
    }
    if let Ok(req_id_val) = HeaderValue::from_str(request_id) {
        headers.insert(X_REQUEST_ID, req_id_val);
    }
    if let Some(secs) = retry_after_secs {
        headers.insert(RETRY_AFTER, HeaderValue::from(secs));
    }

    resp
}

fn build_custom_error_response(
    status: StatusCode,
    method: &Method,
    custom: &CustomErrorPage,
    request_id: &str,
    retry_after_secs: Option<u64>,
) -> Response<HttpBody> {
    let Ok(content_type) = HeaderValue::from_str(custom.content_type) else {
        let mut fallback = Response::new(empty_http_body());
        *fallback.status_mut() = status;
        return fallback;
    };
    let len = custom.body.len();
    let body = if *method == Method::HEAD {
        empty_http_body()
    } else {
        full_http_body(custom.body.clone())
    };

    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    let headers = resp.headers_mut();
    headers.reserve(12);
    headers.insert(CONTENT_TYPE, content_type);
    headers.insert(CONTENT_LENGTH, HeaderValue::from(len));
    headers.insert(VARY, VARY_ACCEPT);
    headers.insert(X_CONTENT_TYPE_OPTIONS, NOSNIFF_VALUE);
    headers.insert(CACHE_CONTROL, NO_STORE_VALUE);
    headers.insert(SERVER, SERVER_VALUE);

    if let Ok(req_id_val) = HeaderValue::from_str(request_id) {
        headers.insert(X_REQUEST_ID, req_id_val);
    }
    if let Some(secs) = retry_after_secs {
        headers.insert(RETRY_AFTER, HeaderValue::from(secs));
    }

    resp
}

/// Strips control characters and caps Unicode scalar length for safe display of untrusted request inputs.
fn sanitize_display_value(raw: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(raw.len().min(max_chars));
    let mut count = 0_usize;
    let mut truncated = false;
    for ch in raw.chars() {
        if ch.is_control() {
            continue;
        }
        if count >= max_chars {
            truncated = true;
            break;
        }
        out.push(ch);
        count += 1;
    }
    if truncated {
        out.push('…');
    }
    out
}

/// HTML-escapes `&`, `<`, `>`, `"`, and `'`.
#[must_use]
pub fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// Escapes `input` for safe inclusion inside a JSON string literal (without outer quotes).
#[must_use]
pub fn json_escape_inner(input: &str) -> String {
    serde_json::to_string(input).map_or_else(
        |_| String::new(),
        |quoted| {
            if let Some(inner) = quoted.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
                inner.to_owned()
            } else {
                quoted
            }
        },
    )
}

/// Escapes inline Markdown and HTML metacharacters so attacker-controlled request fields cannot
/// inject Markdown links, code fences, or raw HTML into `text/markdown` agent responses.
#[must_use]
pub fn markdown_escape_inline(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_control() {
            continue;
        }
        match ch {
            '\\' => out.push_str("\\\\"),
            '`' => out.push_str("\\`"),
            '[' => out.push_str("\\["),
            ']' => out.push_str("\\]"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            other => out.push(other),
        }
    }
    out
}

/// Strips inline HTML tags (such as `<code>...</code>`) from trusted catalog templates to build `{{detail_plain}}`.
fn strip_html_tags(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut inside_tag = false;
    for ch in input.chars() {
        match ch {
            '<' => inside_tag = true,
            '>' if inside_tag => inside_tag = false,
            _ if !inside_tag => out.push(ch),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod request_id_tests {
    use super::{REQUEST_ID_RAND_BATCH, RequestId, crockford_digit, generate_request_id_inline};

    const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    fn reference_encode(millis: u64, rand_bytes: [u8; 10]) -> String {
        let mut out = String::with_capacity(26);
        for shift in (0..10).rev() {
            let idx = usize::try_from((millis >> (shift * 5)) & 0x1F).unwrap_or(0);
            if let Some(&ch) = CROCKFORD.get(idx) {
                out.push(char::from(ch));
            }
        }
        for chunk in rand_bytes.as_chunks::<5>().0 {
            let mut val: u64 = 0;
            for &byte in chunk {
                val = (val << 8) | u64::from(byte);
            }
            for shift in (0..8).rev() {
                let idx = usize::try_from((val >> (shift * 5)) & 0x1F).unwrap_or(0);
                if let Some(&ch) = CROCKFORD.get(idx) {
                    out.push(char::from(ch));
                }
            }
        }
        out
    }

    #[test]
    fn crockford_table_matches_alphabet() {
        for (i, &expected) in CROCKFORD.iter().enumerate() {
            assert_eq!(crockford_digit(i as u64), expected, "index {i}");
        }
    }

    #[test]
    fn inline_request_id_matches_reference_golden_vectors() {
        let vectors = [
            (0_u64, [0_u8; 10], "00000000000000000000000000"),
            (
                (1_u64 << 48) - 1,
                [0xFF_u8; 10],
                "7ZZZZZZZZZZZZZZZZZZZZZZZZZ",
            ),
            (
                1_795_322_791_112_u64,
                [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22],
                "01M80S7H6828T5CY4TQKFF0492",
            ),
        ];
        for (millis, rand_bytes, golden) in vectors {
            let encoded = RequestId::from_parts(millis, rand_bytes);
            let expected = reference_encode(millis, rand_bytes);
            assert_eq!(encoded.as_str(), expected);
            assert_eq!(encoded.as_str(), golden);
        }
    }

    #[test]
    fn buffered_rng_produces_unique_valid_ids_across_multiple_refills() {
        let count = REQUEST_ID_RAND_BATCH * 4 + 17;
        let mut seen = std::collections::HashSet::with_capacity(count);
        for _ in 0..count {
            let id = generate_request_id_inline();
            let s = id.as_str();
            assert_eq!(s.len(), 26);
            assert!(
                s.bytes().all(|b| CROCKFORD.contains(&b)),
                "non-Crockford char in {s}"
            );
            assert!(seen.insert(id.bytes), "duplicate request id {s}");
        }
    }
}

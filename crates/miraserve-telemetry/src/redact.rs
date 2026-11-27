//! Secret-redacting access and audit log sanitizer (Threat Model T1 / T6).
//!
//! Ensures bearer tokens, cookies, API keys, sensitive query parameters, and control
//! characters are stripped or escaped before structured access or audit logs ever reach
//! stdout, disk, or OTLP collectors.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::Write as _;

use http::HeaderMap;
use http::header::HeaderName;
use serde::Serialize;

const REDACTED: &str = "[REDACTED]";

/// Sensitive HTTP header substrings (matched after lowercasing and stripping `-`/`_`)
/// whose values are always replaced with `[REDACTED]`.
const SENSITIVE_HEADER_TOKENS: &[&str] = &[
    "authorization",
    "cookie",
    "token",
    "secret",
    "apikey",
    "password",
    "passwd",
    "credential",
    "session",
    "signature",
    "jwt",
    "xauth",
    "xkey",
];

/// Headers whose values may contain URLs with sensitive query strings.
const URL_BEARING_HEADERS: &[&str] = &[
    "referer",
    "referrer",
    "location",
    "x-original-url",
    "x-rewrite-url",
];

/// Sensitive URL query parameter substrings (matched after percent-decoding, lowercasing,
/// and stripping `-`/`_`).
const SENSITIVE_QUERY_SUBSTRINGS: &[&str] = &[
    "token",
    "secret",
    "apikey",
    "password",
    "passwd",
    "auth",
    "signature",
    "session",
    "cookie",
    "jwt",
    "credential",
];

/// Exact or delimiter-bounded sensitive query key names (`key`, `*_key`, `sig`, `*_sig`,
/// `code`, `pass`, `pwd`, `otp`, `R2-TEL-1`).
const SENSITIVE_QUERY_BOUNDED: &[&str] = &["key", "sig", "code", "pass", "pwd", "otp"];

/// Returns `true` when every byte is printable ASCII (`0x20..=0x7E`) and therefore needs no
/// log-control escaping.
#[inline]
fn is_clean_log_ascii(input: &str) -> bool {
    input.bytes().all(|b| (0x20..0x7f).contains(&b))
}

fn append_escaped_log_controls(out: &mut String, input: &str) {
    if is_clean_log_ascii(input) {
        out.push_str(input);
        return;
    }
    for ch in input.chars() {
        match ch {
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') => {
                let _ = write!(out, "\\u{{{:04X}}}", u32::from(c));
            }
            c => out.push(c),
        }
    }
}

/// Borrowing variant of [`escape_log_controls`] that avoids allocation when `input` contains no
/// control characters or Unicode line/paragraph separators.
#[must_use]
pub fn escape_log_controls_cow(input: &str) -> Cow<'_, str> {
    if is_clean_log_ascii(input)
        || !input
            .chars()
            .any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}'))
    {
        return Cow::Borrowed(input);
    }
    let mut out = String::with_capacity(input.len());
    append_escaped_log_controls(&mut out, input);
    Cow::Owned(out)
}

/// Escapes ASCII control characters (`< 0x20`, `0x7F`), Unicode Cc controls, and
/// Unicode line/paragraph separators (`U+2028`, `U+2029`) to prevent log injection.
#[must_use]
pub fn escape_log_controls(input: &str) -> String {
    escape_log_controls_cow(input).into_owned()
}

/// Borrowing variant of [`redact_uri_query`] that returns `Cow::Borrowed` when no redaction or
/// control-character escaping is needed.
#[must_use]
pub fn redact_uri_query_cow(path_and_query: &str) -> Cow<'_, str> {
    redact_url_cow(path_and_query, true)
}

/// Redacts sensitive values from a URL path + query string (e.g. `"/api?token=abc&q=rust"` -> `"/api?token=[REDACTED]&q=rust"`).
///
/// Handles both `&` and `;` parameter delimiters, percent-encoded keys/values, keyless
/// secret segments, and escapes control characters to prevent log injection.
#[must_use]
pub fn redact_uri_query(path_and_query: &str) -> String {
    redact_url_cow(path_and_query, true).into_owned()
}

/// Borrowing variant of [`redact_request_target`] that returns `Cow::Borrowed` when no redaction
/// or control-character escaping is needed.
#[must_use]
pub fn redact_request_target_cow(path_and_query: &str) -> Cow<'_, str> {
    let absolute = !path_and_query.starts_with('/') && path_and_query.contains("://");
    redact_url_cow(path_and_query, absolute)
}

/// [`redact_uri_query`] for the target of a request: it is a path (`//x/y` is two segments,
/// not a host), so every segment is looked at.
#[must_use]
pub fn redact_request_target(path_and_query: &str) -> String {
    redact_request_target_cow(path_and_query).into_owned()
}

/// Splits `scheme://authority` or scheme-relative `//authority` from `path` when
/// `may_have_authority` is `true`.
fn split_authority(path: &str, may_have_authority: bool) -> Option<(Option<&str>, &str, &str)> {
    if !may_have_authority {
        return None;
    }
    let absolute = path.split_once("://").filter(|(scheme, _)| {
        !scheme.is_empty()
            && scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    });
    let (scheme, after) = absolute
        .map(|(scheme, after)| (Some(scheme), after))
        .or_else(|| path.strip_prefix("//").map(|after| (None, after)))?;
    let authority_len = after.find('/').unwrap_or(after.len());
    let (authority, tail) = after.split_at(authority_len);
    Some((scheme, authority, tail))
}

fn redact_url_cow(path_and_query: &str, may_have_authority: bool) -> Cow<'_, str> {
    // Fast zero-allocation path for queryless/fragmentless URLs with no userinfo, no secret-like
    // segments, and only printable ASCII bytes.
    if !path_and_query.contains(['?', '#']) {
        let rest = match split_authority(path_and_query, may_have_authority) {
            Some((scheme, authority, tail)) => {
                if authority.contains('@')
                    || !is_clean_log_ascii(authority)
                    || scheme.is_some_and(|s| !is_clean_log_ascii(s))
                {
                    return Cow::Owned(redact_url(path_and_query, may_have_authority));
                }
                tail
            }
            None => path_and_query,
        };
        if rest
            .split('/')
            .all(|seg| is_clean_log_ascii(seg) && !looks_like_secret_token_or_decoded(seg, false))
        {
            return Cow::Borrowed(path_and_query);
        }
    }
    Cow::Owned(redact_url(path_and_query, may_have_authority))
}

fn redact_url(path_and_query: &str, may_have_authority: bool) -> String {
    // The query is everything after the first `?`, a fragment included, exactly as in v0.1.0:
    // what that version redacted (a sensitive parameter's value up to the next `&` or `;`,
    // whatever it contains) is redacted here in the same way, and the rest of this file only
    // ever takes more out. A fragment in front of any `?` (`/cb#access_token=...`), which a
    // `Referer` or `Location` can carry, is read as parameters.
    let (path, query) = match path_and_query.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (path_and_query, None),
    };
    let (path, fragment) = match path.split_once('#') {
        Some((path, fragment)) => (path, Some(fragment)),
        None => (path, None),
    };

    let mut out = String::with_capacity(path_and_query.len());
    append_redacted_path(&mut out, path, may_have_authority);
    if let Some(fragment) = fragment {
        out.push('#');
        append_redacted_parameters(&mut out, fragment);
    }
    if let Some(query) = query {
        out.push('?');
        append_redacted_parameters(&mut out, query);
    }
    out
}

/// The part before the query: the user and password of an absolute URL (`https://user:pass@host`)
/// are removed, and a path segment that looks like a credential is redacted.
fn append_redacted_path(out: &mut String, path: &str, may_have_authority: bool) {
    let mut rest = path;
    // `scheme://authority` or a scheme-relative `//authority`.
    if let Some((scheme, authority, tail)) = split_authority(path, may_have_authority) {
        if let Some(scheme) = scheme {
            append_escaped_log_controls(out, scheme);
            out.push(':');
        }
        out.push_str("//");
        match authority.rsplit_once('@') {
            Some((_, host)) => {
                out.push_str(REDACTED);
                out.push('@');
                append_escaped_log_controls(out, host);
            }
            None => append_escaped_log_controls(out, authority),
        }
        rest = tail;
    }
    for (index, segment) in rest.split('/').enumerate() {
        if index > 0 {
            out.push('/');
        }
        if looks_like_secret_token_or_decoded(segment, false) {
            out.push_str(REDACTED);
        } else {
            append_escaped_log_controls(out, segment);
        }
    }
}

/// `key=value` parameters separated by `&` or `;` (a query, or a fragment built like one).
/// Parameters are separated by `&` and `;`. Each is judged by its own name; one that is
/// sensitive is redacted whole, whatever its value contains.
fn append_redacted_parameters(out: &mut String, query: &str) {
    let mut seg_start = 0_usize;
    for (idx, ch) in query.char_indices() {
        if ch == '&' || ch == ';' {
            if let Some(seg) = query.get(seg_start..idx) {
                append_redacted_query_segment(out, seg);
            }
            out.push(ch);
            seg_start = idx.saturating_add(1);
        }
    }
    if let Some(tail) = query.get(seg_start..) {
        append_redacted_query_segment(out, tail);
    }
}

/// One parameter.
///
/// First v0.1.0's decision, unchanged: the name is everything before the first `=`, and a
/// sensitive name (or a value that looks like a credential) redacts all of the value.
///
/// Only a parameter which that decision keeps is looked at once more, to take more out and
/// never less: in one pass (no recursion, each piece decoded once) over its pieces between
/// `?` and `#`, which can start parameters of their own (a URL in a value,
/// `next=/app?code=...`; a fragment, `x=1#access_token=...`; a route, `/callback?code=...`).
/// A piece with a sensitive name redacts the rest of the parameter; a piece that looks like a
/// credential as a whole is redacted whole; every name and value is checked before it is
/// written.
fn append_redacted_query_segment(out: &mut String, pair: &str) {
    let Some((k, v)) = pair.split_once('=') else {
        append_redacted_plain(out, pair);
        return;
    };
    let decoded_k = percent_decode_lossy(k, false);
    if is_sensitive_query_key(&decoded_k) || looks_like_secret_token_or_decoded(v, true) {
        append_redacted_name(out, k);
        out.push('=');
        out.push_str(REDACTED);
        return;
    }
    let mut rest = pair;
    loop {
        let (piece, delimiter, after) = match rest.find(['?', '#']) {
            Some(at) => (
                rest.get(..at).unwrap_or(""),
                rest.get(at..=at),
                rest.get(at.saturating_add(1)..).unwrap_or(""),
            ),
            None => (rest, None, ""),
        };
        let assignment = piece.split_once('=');
        // A sensitive name first: its value runs to the end of the parameter, whatever the
        // piece itself looks like.
        if let Some((name, _)) = assignment
            && is_sensitive_query_key(&percent_decode_lossy(name, false))
        {
            append_redacted_plain(out, name);
            out.push('=');
            out.push_str(REDACTED);
            return;
        }
        // A piece that is a credential as a whole, with a `=` of its own in it (the padding
        // of `Basic ...==`, a token cut in two by a `=`), is not taken apart.
        let whole = looks_like_secret_token_or_decoded(piece, true);
        match assignment {
            Some((name, value)) if !whole => {
                append_redacted_plain(out, name);
                out.push('=');
                if looks_like_secret_token_or_decoded(value, true) {
                    out.push_str(REDACTED);
                } else {
                    append_escaped_log_controls(out, value);
                }
            }
            _ => append_redacted_plain(out, piece),
        }
        let Some(delimiter) = delimiter else {
            return;
        };
        out.push_str(delimiter);
        rest = after;
    }
}

/// A parameter's name. It can hold more in front of the name proper (a route,
/// `/preview/<token>?token`), so each of its pieces between `?` and `#` is checked.
fn append_redacted_name(out: &mut String, name: &str) {
    let mut rest = name;
    while let Some(at) = rest.find(['?', '#']) {
        append_redacted_plain(out, rest.get(..at).unwrap_or(""));
        out.push_str(rest.get(at..=at).unwrap_or(""));
        rest = rest.get(at.saturating_add(1)..).unwrap_or("");
    }
    append_redacted_plain(out, rest);
}

/// A piece without a name: redacted when it looks like a credential itself.
fn append_redacted_plain(out: &mut String, piece: &str) {
    if looks_like_secret_token_or_decoded(piece, true) {
        out.push_str(REDACTED);
    } else {
        append_escaped_log_controls(out, piece);
    }
}

fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn compact_contains_any(input: &str, skip_dot: bool, needles: &[&str]) -> bool {
    let mut stack = [0_u8; 64];
    if input.len() <= stack.len() {
        let mut len = 0_usize;
        for b in input.bytes() {
            if matches!(b, b'-' | b'_' | b' ') || (skip_dot && b == b'.') {
                continue;
            }
            if let Some(slot) = stack.get_mut(len) {
                *slot = b.to_ascii_lowercase();
                len += 1;
            }
        }
        let compact = stack.get(..len).unwrap_or(&[]);
        return needles.iter().any(|n| bytes_contain(compact, n.as_bytes()));
    }
    let mut heap = Vec::with_capacity(input.len());
    for b in input.bytes() {
        if matches!(b, b'-' | b'_' | b' ') || (skip_dot && b == b'.') {
            continue;
        }
        heap.push(b.to_ascii_lowercase());
    }
    needles.iter().any(|n| bytes_contain(&heap, n.as_bytes()))
}

fn is_sensitive_query_key(decoded_key: &str) -> bool {
    let trimmed = decoded_key.trim();
    if compact_contains_any(trimmed, true, SENSITIVE_QUERY_SUBSTRINGS) {
        return true;
    }
    // Check bounded tokens like `key`, `api_key`, `key_id`, `sig`, `url_sig`
    trimmed.split(['-', '_', '.']).any(|part| {
        SENSITIVE_QUERY_BOUNDED
            .iter()
            .any(|bounded| part.eq_ignore_ascii_case(bounded))
    })
}

fn is_sensitive_header_name(name: &HeaderName) -> bool {
    let raw = name.as_str();
    if compact_contains_any(raw, false, SENSITIVE_HEADER_TOKENS) {
        return true;
    }
    raw.split(['-', '_']).any(|part| {
        part.eq_ignore_ascii_case("auth")
            || part.eq_ignore_ascii_case("key")
            || part.eq_ignore_ascii_case("sig")
    })
}

fn is_url_bearing_header(name: &HeaderName) -> bool {
    let raw = name.as_str();
    URL_BEARING_HEADERS
        .iter()
        .any(|h| raw.eq_ignore_ascii_case(h))
}

/// Borrowing variant of [`redact_header_value`] that avoids allocation when the header value is
/// clean and does not require redaction.
#[must_use]
pub fn redact_header_value_cow<'a>(name: &HeaderName, raw_value: &'a str) -> Cow<'a, str> {
    if is_sensitive_header_name(name) || looks_like_secret_token_or_decoded(raw_value, true) {
        return Cow::Borrowed(REDACTED);
    }
    if is_url_bearing_header(name) {
        return redact_uri_query_cow(raw_value);
    }
    escape_log_controls_cow(raw_value)
}

/// Redacts a header value when the header name or inline token pattern is sensitive,
/// scrubs sensitive query parameters inside URL-bearing headers (`Referer`, `Location`),
/// and escapes control characters.
#[must_use]
pub fn redact_header_value(name: &HeaderName, raw_value: &str) -> String {
    redact_header_value_cow(name, raw_value).into_owned()
}

/// Produces a sanitized header map suitable for structured audit/access logs.
///
/// Duplicate header names are joined with `", "` (preserving all values instead of
/// overwriting earlier occurrences), and control characters are always escaped.
#[must_use]
pub fn sanitize_headers_for_log(headers: &HeaderMap, redact: bool) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for name in headers.keys() {
        let mut combined = String::new();
        for (idx, val) in headers.get_all(name).iter().enumerate() {
            if idx > 0 {
                combined.push_str(", ");
            }
            let raw = val.to_str().unwrap_or("<non-utf8>");
            let clean = if redact {
                redact_header_value(name, raw)
            } else {
                escape_log_controls(raw)
            };
            combined.push_str(&clean);
        }
        out.insert(name.as_str().to_owned(), combined);
    }
    out
}

/// Structured HTTP access log record with automatic secret redaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccessLogRecord {
    /// HTTP method (`GET`, `POST`, etc.).
    pub method: String,
    /// Path and (optionally redacted) query string.
    pub target: String,
    /// Negotiated HTTP protocol (`h1`, `h2`, `h3`).
    pub protocol: String,
    /// HTTP response status code.
    pub status: u16,
    /// Request latency in microseconds.
    pub latency_us: u64,
    /// Sanitized request headers.
    pub headers: BTreeMap<String, String>,
}

impl AccessLogRecord {
    /// Builds a structured [`AccessLogRecord`], redacting secrets when `redact_logs` is `true`
    /// and always escaping control characters across all string fields.
    #[must_use]
    pub fn build(
        method: &str,
        path_and_query: &str,
        protocol: &str,
        status: u16,
        latency_us: u64,
        headers: &HeaderMap,
        redact_logs: bool,
    ) -> Self {
        let target = if redact_logs {
            redact_request_target(path_and_query)
        } else {
            escape_log_controls(path_and_query)
        };
        Self {
            method: escape_log_controls(method),
            target,
            protocol: escape_log_controls(protocol),
            status,
            latency_us,
            headers: sanitize_headers_for_log(headers, redact_logs),
        }
    }
}

trait ScanCounter {
    fn count(&mut self, bytes: usize);
}

struct NoopScanCounter;

impl ScanCounter for NoopScanCounter {
    #[inline]
    fn count(&mut self, _bytes: usize) {}
}

struct ScannedBytes<'a, C: ScanCounter> {
    bytes: &'a [u8],
    counter: &'a mut C,
}

impl<'a, C: ScanCounter> ScannedBytes<'a, C> {
    #[inline]
    fn new(bytes: &'a [u8], counter: &'a mut C) -> Self {
        Self { bytes, counter }
    }

    #[inline]
    const fn len(&self) -> usize {
        self.bytes.len()
    }

    #[inline]
    fn get_byte(&mut self, idx: usize) -> Option<u8> {
        let b = *self.bytes.get(idx)?;
        self.counter.count(1);
        Some(b)
    }

    #[inline]
    fn starts_with(&mut self, start: usize, needle: &[u8]) -> bool {
        let Some(slice) = self.bytes.get(start..start.saturating_add(needle.len())) else {
            return false;
        };
        for (&a, &b) in slice.iter().zip(needle) {
            self.counter.count(1);
            if a != b {
                return false;
            }
        }
        true
    }

    #[inline]
    fn starts_with_ignore_ascii_case(&mut self, start: usize, needle: &[u8]) -> bool {
        let Some(slice) = self.bytes.get(start..start.saturating_add(needle.len())) else {
            return false;
        };
        for (&a, &b) in slice.iter().zip(needle) {
            self.counter.count(1);
            if !a.eq_ignore_ascii_case(&b) {
                return false;
            }
        }
        true
    }

    #[cfg(test)]
    fn contains_from(&mut self, start: usize, needle: u8) -> bool {
        let Some(rest) = self.bytes.get(start..) else {
            return false;
        };
        for &b in rest {
            self.counter.count(1);
            if b == needle {
                return true;
            }
        }
        false
    }
}

fn looks_like_secret_token(value: &str) -> bool {
    looks_like_secret_token_with_counter(value, &mut NoopScanCounter)
}

fn looks_like_secret_token_with_counter<C: ScanCounter>(value: &str, counter: &mut C) -> bool {
    let trimmed = value.trim();
    let mut scan = ScannedBytes::new(trimmed.as_bytes(), counter);
    let len = scan.len();
    if len < 3 {
        return false;
    }
    let mut seen_eyj = false;
    for i in 0..len {
        let Some(b) = scan.get_byte(i) else {
            break;
        };
        match b {
            b'b' | b'B'
                if scan.starts_with_ignore_ascii_case(i, b"bearer ")
                    || scan.starts_with_ignore_ascii_case(i, b"basic ") =>
            {
                return true;
            }
            b's' if scan.starts_with(i, b"sk-ant-")
                || scan.starts_with(i, b"sk-proj-")
                || scan.starts_with(i, b"sk_live_") =>
            {
                return true;
            }
            b'g' if scan.starts_with(i, b"ghp_") || scan.starts_with(i, b"github_pat_") => {
                return true;
            }
            b'A' if scan.starts_with(i, b"AKIA") => {
                return true;
            }
            // Detect JWT compact serialization (`eyJ...<dot>...`) or leading `eyJ` in O(n)
            // without re-scanning suffixes on repeated `eyJ` markers.
            b'e' if scan.starts_with(i, b"eyJ") => {
                if i == 0 {
                    return true;
                }
                seen_eyj = true;
            }
            b'.' if seen_eyj => {
                return true;
            }
            _ => {}
        }
    }
    false
}

#[inline]
fn needs_percent_decode(input: &str, plus_as_space: bool) -> bool {
    input
        .as_bytes()
        .iter()
        .any(|&b| b == b'%' || (plus_as_space && b == b'+'))
}

fn looks_like_secret_token_or_decoded(input: &str, plus_as_space: bool) -> bool {
    if looks_like_secret_token(input) {
        return true;
    }
    if !needs_percent_decode(input, plus_as_space) {
        return false;
    }
    looks_like_secret_token(&percent_decode_lossy(input, plus_as_space))
}

fn percent_decode_lossy(input: &str, plus_as_space: bool) -> Cow<'_, str> {
    if !needs_percent_decode(input, plus_as_space) {
        return Cow::Borrowed(input);
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0_usize;
    while let Some(&b) = bytes.get(i) {
        if b == b'%'
            && let (Some(&h1), Some(&h2)) = (
                bytes.get(i.saturating_add(1)),
                bytes.get(i.saturating_add(2)),
            )
            && let (Some(n1), Some(n2)) = (hex_nibble(h1), hex_nibble(h2))
        {
            out.push((n1 << 4) | n2);
            i = i.saturating_add(3);
            continue;
        }
        if plus_as_space && b == b'+' {
            out.push(b' ');
        } else {
            out.push(b);
        }
        i = i.saturating_add(1);
    }
    Cow::Owned(String::from_utf8_lossy(&out).into_owned())
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ScanCounter, ScannedBytes, looks_like_secret_token, looks_like_secret_token_with_counter,
    };

    #[derive(Default)]
    struct CountingScanner(usize);

    impl ScanCounter for CountingScanner {
        fn count(&mut self, bytes: usize) {
            self.0 = self.0.saturating_add(bytes);
        }
    }

    /// Reference v0.1.2 `looks_like_secret_token` semantics.
    fn v012_reference(value: &str) -> bool {
        let trimmed = value.trim();
        let lower = trimmed.to_ascii_lowercase();
        if lower.contains("bearer ")
            || lower.contains("basic ")
            || trimmed.contains("sk-ant-")
            || trimmed.contains("sk-proj-")
            || trimmed.contains("sk_live_")
            || trimmed.contains("ghp_")
            || trimmed.contains("github_pat_")
            || trimmed.contains("AKIA")
        {
            return true;
        }
        if let Some(idx) = trimmed.find("eyJ")
            && let Some(rest) = trimmed.get(idx..)
            && rest.contains('.')
        {
            return true;
        }
        trimmed.starts_with("eyJ")
    }

    /// Model of the reverted 600c0d9 inner suffix scan over the SAME `ScannedBytes` abstraction
    /// (so restoring `contains_from` inside `looks_like_secret_token_with_counter` charges every
    /// byte read in the inner scan and trips the linear step bound).
    fn old_quadratic_scan_with_counter<C: ScanCounter>(value: &str, counter: &mut C) -> bool {
        let trimmed = value.trim();
        let mut scan = ScannedBytes::new(trimmed.as_bytes(), counter);
        let len = scan.len();
        if len < 3 {
            return false;
        }
        for i in 0..len {
            let Some(b) = scan.get_byte(i) else {
                break;
            };
            if b == b'e'
                && scan.starts_with(i, b"eyJ")
                && (i == 0 || scan.contains_from(i.saturating_add(3), b'.'))
            {
                return true;
            }
        }
        false
    }

    /// Regression test for 600c0d9 P1 #3: scanning repeated `eyJ` markers without a dot must
    /// stay strictly linear in input length (charging every outer, prefix, and inner byte read
    /// through `ScannedBytes`) and match v0.1.2 output.
    #[test]
    fn looks_like_secret_token_is_linear_and_matches_v012() {
        let small = format!("x{}", "eyJ".repeat(100));
        let large = format!("x{}", "eyJ".repeat(1_000));

        let mut c_small = CountingScanner::default();
        assert!(!looks_like_secret_token_with_counter(&small, &mut c_small));
        let mut c_large = CountingScanner::default();
        assert!(!looks_like_secret_token_with_counter(&large, &mut c_large));

        // Charging both outer byte reads and prefix comparisons keeps total reads <= 2 * len.
        assert!(
            c_large.0 <= large.len() * 2,
            "expected linear scan (<= {} byte reads), got {} for len {}",
            large.len() * 2,
            c_large.0,
            large.len()
        );
        // Scaling input by ~10x must scale work by <= 11x, never ~100x.
        assert!(
            c_large.0 <= c_small.0.saturating_mul(11),
            "superlinear growth: small={} reads (len {}), large={} reads (len {})",
            c_small.0,
            small.len(),
            c_large.0,
            large.len()
        );

        // Verify the inner-scan counter catches quadratic suffix scanning: the reference quadratic
        // model must trip both the superlinear byte-read bound and the quadratic scaling bound.
        let mut old_small = CountingScanner::default();
        assert!(!old_quadratic_scan_with_counter(&small, &mut old_small));
        let mut old_large = CountingScanner::default();
        assert!(!old_quadratic_scan_with_counter(&large, &mut old_large));
        assert!(
            old_large.0 > large.len() * 2 && old_large.0 > 1_500_000,
            "inner scan must charge quadratic byte reads, got {}",
            old_large.0
        );
        assert!(
            old_large.0 > old_small.0.saturating_mul(80),
            "expected quadratic ~100x growth on old algorithm: small={}, large={}",
            old_small.0,
            old_large.0
        );

        let with_dot = format!("x{}.tail", "eyJ".repeat(50));
        let mut c_dot = CountingScanner::default();
        assert!(looks_like_secret_token_with_counter(&with_dot, &mut c_dot));
        assert!(c_dot.0 <= with_dot.len() * 2, "reads={}", c_dot.0);

        for sample in [
            "",
            "ab",
            "eyJ",
            "  eyJabc  ",
            "xeyJ",
            "xeyJeyJeyJ",
            "x.y eyJnodot",
            "x.y eyJwith.dot",
            "prefix eyJ.suffix",
            "prefix eyJabc.def",
            "prefix eyJeyJ.def",
            "Bearer abc",
            "x bEaReR y",
            "basic dXNlcjpwYXNz",
            "sk-ant-123",
            "sk-proj-123",
            "sk_live_123",
            "ghp_123",
            "github_pat_123",
            "AKIA123456",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X)",
        ] {
            assert_eq!(
                looks_like_secret_token(sample),
                v012_reference(sample),
                "mismatch on {sample:?}"
            );
        }
    }

    /// Direct black-box check against `looks_like_secret_token`: on 20,000 repeated `eyJ` markers,
    /// the best-of-5 scan time stays within the larger of 30 times the control time and 1 ms.
    #[test]
    fn looks_like_secret_token_direct_scaling_rejects_quadratic_suffix_scan() {
        use std::time::{Duration, Instant};

        let eyj = format!("x{}", "eyJ".repeat(20_000));
        let ctrl = format!("x{}", "abc".repeat(20_000));

        let mut min_ctrl = Duration::MAX;
        let mut min_eyj = Duration::MAX;
        for _ in 0..5 {
            let t0 = Instant::now();
            assert!(!std::hint::black_box(looks_like_secret_token(
                std::hint::black_box(&ctrl)
            )));
            min_ctrl = min_ctrl.min(t0.elapsed());

            let t1 = Instant::now();
            assert!(!std::hint::black_box(looks_like_secret_token(
                std::hint::black_box(&eyj)
            )));
            min_eyj = min_eyj.min(t1.elapsed());
        }
        let budget = min_ctrl.saturating_mul(30).max(Duration::from_millis(1));
        assert!(
            min_eyj <= budget,
            "repeated `eyJ` scan looks superlinear: min_eyj={min_eyj:?}, min_ctrl={min_ctrl:?}, budget={budget:?}"
        );
    }
}

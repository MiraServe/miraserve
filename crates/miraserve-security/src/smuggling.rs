//! Strict RFC 9110 / RFC 9112 / RFC 9113 / RFC 9114 HTTP anti-smuggling normalizer (Threat Model T4).
//!
//! Rejects ambiguous framing, connection-specific H2/H3 headers, malformed `Host` headers,
//! and path traversal vectors before requests ever reach static handlers, reverse proxies,
//! FastCGI backends, or MCP gateways.

use http::header::{CONNECTION, CONTENT_LENGTH, HOST, HeaderName, TE, TRANSFER_ENCODING, UPGRADE};
use http::{HeaderMap, Request, StatusCode, Version};
use miraserve_config::LimitsConfig;

/// Maximum permitted HTTP header count per request to mitigate header-table floods.
const MAX_HEADER_COUNT: usize = 100;

/// Additional RFC 9113 §8.2.2 / RFC 9114 §4.2 forbidden connection-specific header names.
const KEEP_ALIVE_HEADER: HeaderName = HeaderName::from_static("keep-alive");
const PROXY_CONNECTION_HEADER: HeaderName = HeaderName::from_static("proxy-connection");

/// Specific reason a request failed anti-smuggling inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmugglingRejection {
    /// HTTP status code to return (`400`, `413`, `431`, etc.).
    pub status: StatusCode,
    /// Stable rule identifier (e.g. `"SMUGGLE_CL_TE"`).
    pub rule: &'static str,
    /// Human-readable rejection reason (safe to log/return).
    pub reason: &'static str,
}

/// Validates an incoming HTTP request against RFC 9110/9112/9113/9114 smuggling vectors
/// and protocol limits.
///
/// # Errors
/// Returns [`SmugglingRejection`] if the request violates framing, header hygiene, or size limits.
pub fn validate_request_framing<B>(
    req: &Request<B>,
    limits: &LimitsConfig,
) -> Result<(), SmugglingRejection> {
    validate_uri_ref(req.uri())?;
    validate_header_budget(req.headers(), limits)?;
    validate_host_consistency(req)?;
    validate_content_length_and_te(req.headers(), req.version(), limits)?;
    validate_header_hygiene(req.headers())?;
    Ok(())
}

/// Validates RFC 3986 `host [":" port]` strictly (blocking `?`, `#`, `/`, `@`, whitespace, etc.).
#[must_use]
pub fn is_valid_rfc3986_host_port(host_port: &str) -> bool {
    // The host part has its own limit below: 255 bytes, which v0.1.0 allowed for host and port
    // together, so no host that version took is refused here (a DNS name of 253 bytes with
    // its final root dot is 254). The whole has none: a port may be written with any number
    // of leading zeros, and the header budget bounds the request. A name no site has gets
    // 421 from the router, not 400 from here.
    if host_port.is_empty() {
        return false;
    }
    if let Some(rest) = host_port.strip_prefix('[') {
        let Some((ipv6, after)) = rest.split_once(']') else {
            return false;
        };
        if ipv6.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        if after.is_empty() {
            return true;
        }
        return after.strip_prefix(':').is_some_and(|p| {
            !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u16>().is_ok()
        });
    }

    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (host_port, None),
    };
    if host.is_empty() || host.len() > 255 || host.contains(':') {
        return false;
    }
    if let Some(p) = port
        && (p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) || p.parse::<u16>().is_err())
    {
        return false;
    }
    // R2-HTTP-3: Allow `_` in DNS/internal service Host labels (e.g. Docker / K8s service names)
    // while strictly blocking `?`, `#`, `/`, `@`, whitespace, and control bytes.
    host.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        && !host.starts_with('.')
        && !host.starts_with('-')
        && !host.ends_with('-')
        && !host.contains("..")
}

/// Applies the request-target rules of [`validate_request_framing`] (length limit, control
/// bytes, backslashes, forbidden escapes, raw and decoded dot-segments including matrix
/// parameters, overlong UTF-8) to a target the server built itself, such as the result of an
/// internal rewrite, so it is held to the same rules as a target a client sent.
///
/// # Errors
/// Returns the rejection a client would have received for the same target.
pub fn validate_request_target(raw_target: &str) -> Result<(), SmugglingRejection> {
    validate_uri(raw_target)
}

fn has_uri_ctrl_or_space(s: &str) -> bool {
    s.bytes().any(|b| b <= 0x1F || b == 0x7F || b == b' ')
}

fn extract_raw_path(raw_uri: &str) -> &str {
    // Extract raw path portion (strip scheme+authority if absolute-form and strip query/fragment).
    let path_without_query = raw_uri.split(['?', '#']).next().unwrap_or(raw_uri);
    // Absolute-form is recognised by structure, not by finding "://" somewhere: an
    // origin-form path starts with '/', and "://" later in it is ordinary path text that must
    // be checked like the rest.
    let absolute_form = !path_without_query.starts_with('/');
    if absolute_form && let Some(after_scheme) = path_without_query.find("://") {
        let rest = path_without_query
            .get(after_scheme.saturating_add(3)..)
            .unwrap_or("");
        rest.find('/')
            .and_then(|slash| rest.get(slash..))
            .unwrap_or("/")
    } else {
        path_without_query
    }
}

fn validate_uri_ref(uri: &http::Uri) -> Result<(), SmugglingRejection> {
    let scheme = uri.scheme_str();
    let authority = uri.authority().map(http::uri::Authority::as_str);
    let path = uri.path();
    let query = uri.query();

    // Matches `http::Uri`'s `Display` format: `[scheme "://"] [authority] path ["?" query]`.
    let total_len = scheme
        .map_or(0, |s| s.len().saturating_add(3))
        .saturating_add(authority.map_or(0, str::len))
        .saturating_add(path.len())
        .saturating_add(query.map_or(0, |q| q.len().saturating_add(1)));

    if total_len == 0 {
        return Err(SmugglingRejection {
            status: StatusCode::BAD_REQUEST,
            rule: "URI_EMPTY",
            reason: "empty request target",
        });
    }
    if total_len > 8_192 {
        return Err(SmugglingRejection {
            status: StatusCode::URI_TOO_LONG,
            rule: "URI_TOO_LONG",
            reason: "request target exceeds 8192 bytes",
        });
    }
    if scheme.is_some_and(has_uri_ctrl_or_space)
        || authority.is_some_and(has_uri_ctrl_or_space)
        || has_uri_ctrl_or_space(path)
        || query.is_some_and(has_uri_ctrl_or_space)
    {
        return Err(SmugglingRejection {
            status: StatusCode::BAD_REQUEST,
            rule: "URI_CTRL_CHAR",
            reason: "request target contains forbidden control or whitespace byte",
        });
    }

    if scheme.is_none() && authority.is_none() {
        return validate_raw_path(extract_raw_path(path));
    }
    if scheme.is_some()
        && path.starts_with('/')
        && !authority.is_some_and(|a| a.contains(['/', '?', '#']))
        && !path.contains(['?', '#'])
    {
        return validate_raw_path(path);
    }

    // Rare fallback (e.g. authority-form `CONNECT host:443` with no scheme).
    let raw_uri = uri.to_string();
    validate_uri(&raw_uri)
}

fn validate_uri(raw_uri: &str) -> Result<(), SmugglingRejection> {
    if raw_uri.is_empty() {
        return Err(SmugglingRejection {
            status: StatusCode::BAD_REQUEST,
            rule: "URI_EMPTY",
            reason: "empty request target",
        });
    }
    if raw_uri.len() > 8_192 {
        return Err(SmugglingRejection {
            status: StatusCode::URI_TOO_LONG,
            rule: "URI_TOO_LONG",
            reason: "request target exceeds 8192 bytes",
        });
    }
    if has_uri_ctrl_or_space(raw_uri) {
        return Err(SmugglingRejection {
            status: StatusCode::BAD_REQUEST,
            rule: "URI_CTRL_CHAR",
            reason: "request target contains forbidden control or whitespace byte",
        });
    }

    validate_raw_path(extract_raw_path(raw_uri))
}

fn validate_raw_path(raw_path: &str) -> Result<(), SmugglingRejection> {
    let has_percent = raw_path.as_bytes().contains(&b'%');

    // Reject backslashes, encoded backslashes/NULs, and dot-segments in the request path
    // to prevent route-prefix and upstream base_url path traversal.
    // R2-HTTP-3: Encoded slashes (`%2F`) within a non-traversal segment are permitted through
    // framing so reverse-proxy/WASM/MCP APIs (e.g. GitLab, npm) work; filesystem/static/FastCGI/
    // publish routes still reject `%2F` strictly in `miraserve-http::router`.
    if raw_path.contains('\\') || (has_percent && contains_forbidden_uri_escape(raw_path)) {
        return Err(SmugglingRejection {
            status: StatusCode::BAD_REQUEST,
            rule: "URI_PATH_TRAVERSAL",
            reason: "request path contains forbidden backslash, encoded backslash/NUL, or IIS %uXXXX escape",
        });
    }
    if raw_path
        .as_bytes()
        .split(|&b| b == b'/')
        .any(is_dot_segment_bytes)
    {
        return Err(SmugglingRejection {
            status: StatusCode::BAD_REQUEST,
            rule: "URI_PATH_TRAVERSAL",
            reason: "request path contains forbidden dot-segment traversal",
        });
    }
    // Without `%`, `decode_uri_path_once_bytes` returns `raw_path.as_bytes()` verbatim, which is
    // valid UTF-8 (so overlong/surrogate checks are guaranteed false) and already checked for
    // control/NUL bytes (before calling `validate_raw_path`), backslashes, and dot-segments.
    if !has_percent {
        return Ok(());
    }
    let decoded = decode_uri_path_once_bytes(raw_path);
    // R4-PRX-1, R5-HTTP-3 & R6-HTTP-2: Reject RFC 3629 invalid/overlong UTF-8 (`0xC0`, `0xC1`,
    // `0xF5..=0xFF`, `%E0%80%AE`, `%F0%80%80%AE`) and UTF-16 surrogates (`%ED%A0%80`) globally,
    // while permitting other legacy single-byte escapes (e.g. Latin-1 `%E9` in `/fichier%E9.pdf`)
    // on reverse-proxy routes (filesystem/static/FastCGI routes still enforce strict UTF-8).
    if contains_overlong_or_surrogate_utf8(&decoded) {
        return Err(SmugglingRejection {
            status: StatusCode::BAD_REQUEST,
            rule: "URI_OVERLONG_OR_SURROGATE_UTF8",
            reason: "request path contains forbidden overlong UTF-8 or UTF-16 surrogate sequence",
        });
    }
    if decoded.contains(&0x00)
        || decoded.contains(&b'\\')
        || decoded.split(|&b| b == b'/').any(is_dot_segment_bytes)
    {
        return Err(SmugglingRejection {
            status: StatusCode::BAD_REQUEST,
            rule: "URI_PATH_TRAVERSAL",
            reason: "decoded request path contains forbidden traversal or control byte",
        });
    }
    Ok(())
}

/// Returns `true` if a path segment is a dot-segment (`.` or `..`), stripping any RFC 3986 /
/// Tomcat / Jetty matrix parameters (`;...`, e.g. `..;`, `..;jsessionid=1`, `.;`) before
/// comparison (`R7-HTTP-2`).
#[must_use]
pub fn is_dot_segment_bytes(seg: &[u8]) -> bool {
    let base = seg.split(|&b| b == b';').next().unwrap_or(seg);
    base == b"." || base == b".."
}

/// Returns `true` if `bytes` contains any RFC 3629 overlong UTF-8 encoding (`%C0%AF`,
/// `%C0%2F`, `%C0.`, `%E0%80.`, `%E0%80%AE`, `%F0%80%80%AE`, legacy 5/6-byte `%F5..%FF`
/// sequences), out-of-range `> U+10FFFF` UTF-8 (`%F4%90..%F7`), or UTF-16 surrogate
/// (`%ED%A0..%BF`) byte sequence (`R5-HTTP-3`, `R6-HTTP-2`).
///
/// Standalone legacy single-byte non-UTF-8 characters (e.g. Latin-1 `%E9` in `/fichier%E9.pdf`
/// followed by ASCII `.`) return `false` so reverse-proxy routes remain compatible with legacy
/// upstreams while filesystem routes still enforce strict UTF-8 separately.
#[must_use]
pub fn contains_overlong_or_surrogate_utf8(bytes: &[u8]) -> bool {
    let mut i = 0_usize;
    while let Some(&b0) = bytes.get(i) {
        match b0 {
            // R6-HTTP-2: RFC 3629 forbids `0xC0`, `0xC1`, and `0xF5..=0xFF` unconditionally
            // (defeats `%C0%2F`, `%C0.`, `%C0%AF`, and 5/6-byte overlongs).
            0xC0 | 0xC1 | 0xF5..=0xFF => {
                return true;
            }
            // 3-byte overlong UTF-8 prefix (`< U+0800`): E0 [80..9F] (even if truncated like `%E0%80.`).
            0xE0 if bytes
                .get(i + 1)
                .copied()
                .is_some_and(|b1| (0x80..=0x9F).contains(&b1)) =>
            {
                return true;
            }
            // 3-byte UTF-16 surrogate prefix (`U+D800..=U+DFFF`): ED [A0..BF] (even if truncated).
            0xED if bytes
                .get(i + 1)
                .copied()
                .is_some_and(|b1| (0xA0..=0xBF).contains(&b1)) =>
            {
                return true;
            }
            // 4-byte overlong UTF-8 prefix (`< U+10000`): F0 [80..8F] (even if truncated).
            0xF0 if bytes
                .get(i + 1)
                .copied()
                .is_some_and(|b1| (0x80..=0x8F).contains(&b1)) =>
            {
                return true;
            }
            // 4-byte > U+10FFFF prefix: F4 [90..BF] (even if truncated).
            0xF4 if bytes
                .get(i + 1)
                .copied()
                .is_some_and(|b1| (0x90..=0xBF).contains(&b1)) =>
            {
                return true;
            }
            _ => {}
        }
        i = i.saturating_add(1);
    }
    false
}

fn contains_forbidden_uri_escape(path: &str) -> bool {
    let bytes = path.as_bytes();
    let mut i = 0_usize;
    while let Some(&b) = bytes.get(i) {
        if b == b'%' {
            // R4-PRX-1: Reject IIS non-standard `%uXXXX`/`%UXXXX` Unicode escapes globally so
            // legacy upstream decoders cannot turn `%u002e%u002e` into `..`.
            if matches!(bytes.get(i.saturating_add(1)), Some(b'u' | b'U'))
                && bytes
                    .get(i.saturating_add(2)..i.saturating_add(6))
                    .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
            {
                return true;
            }
            if let (Some(&h1), Some(&h2)) = (
                bytes.get(i.saturating_add(1)),
                bytes.get(i.saturating_add(2)),
            ) && let (Some(n1), Some(n2)) = (hex_val(h1), hex_val(h2))
            {
                let decoded = (n1 << 4) | n2;
                if matches!(decoded, 0x00 | b'\\') {
                    return true;
                }
                i = i.saturating_add(3);
                continue;
            }
        }
        i = i.saturating_add(1);
    }
    false
}

/// Decodes valid `%XX` escapes once into raw bytes so overlong UTF-8 / surrogate checks and
/// traversal inspection run on decoded bytes without rejecting legacy non-UTF-8 proxy URLs.
fn decode_uri_path_once_bytes(path: &str) -> Vec<u8> {
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0_usize;
    while let Some(&b) = bytes.get(i) {
        if b == b'%'
            && let (Some(&h1), Some(&h2)) = (
                bytes.get(i.saturating_add(1)),
                bytes.get(i.saturating_add(2)),
            )
            && let (Some(n1), Some(n2)) = (hex_val(h1), hex_val(h2))
        {
            out.push((n1 << 4) | n2);
            i = i.saturating_add(3);
            continue;
        }
        out.push(b);
        i = i.saturating_add(1);
    }
    out
}

const fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn validate_header_budget(
    headers: &HeaderMap,
    limits: &LimitsConfig,
) -> Result<(), SmugglingRejection> {
    if headers.len() > MAX_HEADER_COUNT {
        return Err(SmugglingRejection {
            status: StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            rule: "HEADER_COUNT_LIMIT",
            reason: "request exceeds maximum header count",
        });
    }

    let mut total_bytes: u64 = 0;
    for (name, value) in headers {
        total_bytes = total_bytes
            .saturating_add(name.as_str().len() as u64)
            .saturating_add(value.len() as u64)
            .saturating_add(4); // ": " + "\r\n"
    }
    if total_bytes > limits.max_header_bytes.as_bytes() {
        return Err(SmugglingRejection {
            status: StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            rule: "HEADER_BYTES_LIMIT",
            reason: "total request header size exceeds server max-header-bytes limit",
        });
    }

    Ok(())
}

/// Validates `Host` header / URI authority presence, syntax, and consistency (RFC 9112 §3.2,
/// RFC 9113 §8.3.1).
///
/// # Errors
/// Returns [`SmugglingRejection`] if `Host` is missing on HTTP/1.1, duplicated, malformed, or
/// disagrees with the request target's authority.
pub fn validate_host_consistency<B>(req: &Request<B>) -> Result<(), SmugglingRejection> {
    let mut host_iter = req.headers().get_all(HOST).iter();
    let first_host = host_iter.next();
    if host_iter.next().is_some() {
        return Err(SmugglingRejection {
            status: StatusCode::BAD_REQUEST,
            rule: "DUPLICATE_HOST",
            reason: "multiple Host headers are forbidden (RFC 9112 §3.2)",
        });
    }

    // RFC 9112 section 3.2: every HTTP/1.1 request carries Host, absolute-form included.
    if req.version() == Version::HTTP_11 && first_host.is_none() {
        return Err(SmugglingRejection {
            status: StatusCode::BAD_REQUEST,
            rule: "MISSING_HOST",
            reason: "HTTP/1.1 request missing required Host header",
        });
    }

    // The target's authority is validated on its own: with HTTP/2 and HTTP/3 it usually comes
    // without Host, and routing reads only its host while forwarding uses all of it (userinfo
    // such as `evil.test:443@site` would reach `X-Forwarded-Host`).
    if let Some(auth) = req.uri().authority()
        && !is_valid_rfc3986_host_port(auth.as_str())
    {
        return Err(SmugglingRejection {
            status: StatusCode::BAD_REQUEST,
            rule: "INVALID_AUTHORITY",
            reason: "malformed authority in the request target",
        });
    }

    if let Some(host_val) = first_host {
        let Ok(host_str) = host_val.to_str() else {
            return Err(SmugglingRejection {
                status: StatusCode::BAD_REQUEST,
                rule: "INVALID_HOST",
                reason: "Host header contains non-ASCII bytes",
            });
        };
        let trimmed = host_str.trim();
        if trimmed.is_empty() || trimmed != host_str || !is_valid_rfc3986_host_port(trimmed) {
            return Err(SmugglingRejection {
                status: StatusCode::BAD_REQUEST,
                rule: "INVALID_HOST",
                reason: "malformed Host header",
            });
        }
        // RFC 9113 §8.3.1: if both :authority and Host exist on H2/H3, they MUST match.
        if let Some(auth) = req.uri().authority()
            && !auth.as_str().eq_ignore_ascii_case(trimmed)
        {
            return Err(SmugglingRejection {
                status: StatusCode::BAD_REQUEST,
                rule: "HOST_AUTHORITY_MISMATCH",
                reason: "Host header disagrees with :authority pseudo-header",
            });
        }
    }

    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_content_length_and_te(
    headers: &HeaderMap,
    version: Version,
    limits: &LimitsConfig,
) -> Result<(), SmugglingRejection> {
    let mut cl_iter = headers.get_all(CONTENT_LENGTH).iter();
    let first_cl = cl_iter.next();
    let has_dup_cl = cl_iter.next().is_some();
    let mut te_iter = headers.get_all(TRANSFER_ENCODING).iter();
    let first_te = te_iter.next();
    let has_dup_te = te_iter.next().is_some();

    // RFC 9112 §6.3: Reject simultaneous Content-Length and Transfer-Encoding (CL.TE / TE.CL).
    if first_cl.is_some() && first_te.is_some() {
        return Err(SmugglingRejection {
            status: StatusCode::BAD_REQUEST,
            rule: "SMUGGLE_CL_TE",
            reason: "simultaneous Content-Length and Transfer-Encoding headers are forbidden",
        });
    }

    // Reject duplicate Content-Length headers outright (strict zero-ambiguity policy).
    if has_dup_cl {
        return Err(SmugglingRejection {
            status: StatusCode::BAD_REQUEST,
            rule: "SMUGGLE_DUPLICATE_CL",
            reason: "multiple Content-Length headers are forbidden",
        });
    }

    if let Some(cl_val) = first_cl {
        let Ok(cl_str) = cl_val.to_str() else {
            return Err(SmugglingRejection {
                status: StatusCode::BAD_REQUEST,
                rule: "INVALID_CL",
                reason: "Content-Length contains non-ASCII bytes",
            });
        };
        if cl_str.is_empty() || !cl_str.bytes().all(|b| b.is_ascii_digit()) {
            return Err(SmugglingRejection {
                status: StatusCode::BAD_REQUEST,
                rule: "INVALID_CL",
                reason: "Content-Length must consist exclusively of ASCII digits",
            });
        }
        let Ok(cl_num) = cl_str.parse::<u64>() else {
            return Err(SmugglingRejection {
                status: StatusCode::BAD_REQUEST,
                rule: "INVALID_CL",
                reason: "Content-Length integer overflow",
            });
        };
        if cl_num > limits.max_body_bytes.as_bytes() {
            return Err(SmugglingRejection {
                status: StatusCode::PAYLOAD_TOO_LARGE,
                rule: "BODY_TOO_LARGE",
                reason: "Content-Length exceeds server max-body-bytes limit",
            });
        }
    }

    if let Some(te_val) = first_te {
        // RFC 9113 §8.2.2 / RFC 9114 §4.2: Transfer-Encoding is forbidden in HTTP/2 and HTTP/3.
        if matches!(version, Version::HTTP_2 | Version::HTTP_3) {
            return Err(SmugglingRejection {
                status: StatusCode::BAD_REQUEST,
                rule: "SMUGGLE_H2_H3_TE",
                reason: "Transfer-Encoding header is forbidden in HTTP/2 and HTTP/3",
            });
        }

        // Only a single clean "chunked" token is permitted on HTTP/1.1 requests.
        if has_dup_te {
            return Err(SmugglingRejection {
                status: StatusCode::BAD_REQUEST,
                rule: "SMUGGLE_DUPLICATE_TE",
                reason: "multiple Transfer-Encoding headers are forbidden",
            });
        }

        let Ok(te_str) = te_val.to_str() else {
            return Err(SmugglingRejection {
                status: StatusCode::BAD_REQUEST,
                rule: "SMUGGLE_OBFUSCATED_TE",
                reason: "Transfer-Encoding contains non-ASCII bytes",
            });
        };
        if !te_str.eq_ignore_ascii_case("chunked") {
            return Err(SmugglingRejection {
                status: StatusCode::BAD_REQUEST,
                rule: "SMUGGLE_OBFUSCATED_TE",
                reason: "only exact 'Transfer-Encoding: chunked' is supported on HTTP/1.1",
            });
        }
    }

    // RFC 9113 §8.2.2 / RFC 9114 §4.2: Reject HTTP/1.1 connection-specific headers on H2/H3.
    if matches!(version, Version::HTTP_2 | Version::HTTP_3) {
        if headers.contains_key(CONNECTION)
            || headers.contains_key(UPGRADE)
            || headers.contains_key(&KEEP_ALIVE_HEADER)
            || headers.contains_key(&PROXY_CONNECTION_HEADER)
        {
            return Err(SmugglingRejection {
                status: StatusCode::BAD_REQUEST,
                rule: "SMUGGLE_H2_H3_CONN_HEADER",
                reason: "connection-specific header is forbidden in HTTP/2 and HTTP/3",
            });
        }
        for te_val in headers.get_all(TE) {
            let Ok(te_str) = te_val.to_str() else {
                return Err(SmugglingRejection {
                    status: StatusCode::BAD_REQUEST,
                    rule: "SMUGGLE_H2_H3_CONN_HEADER",
                    reason: "invalid TE header in HTTP/2 or HTTP/3",
                });
            };
            if !te_str.eq_ignore_ascii_case("trailers") {
                return Err(SmugglingRejection {
                    status: StatusCode::BAD_REQUEST,
                    rule: "SMUGGLE_H2_H3_CONN_HEADER",
                    reason: "only 'TE: trailers' is permitted in HTTP/2 and HTTP/3",
                });
            }
        }
    }

    Ok(())
}

fn validate_header_hygiene(headers: &HeaderMap) -> Result<(), SmugglingRejection> {
    for value in headers.values() {
        let bytes = value.as_bytes();
        // Reject CTL bytes (except HTAB 0x09) and obs-fold / CRLF injection attempts.
        if bytes
            .iter()
            .any(|&b| (b <= 0x1F && b != b'\t') || b == 0x7F)
        {
            return Err(SmugglingRejection {
                status: StatusCode::BAD_REQUEST,
                rule: "HEADER_CTRL_CHAR",
                reason: "header value contains forbidden control character",
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_uri, validate_uri_ref};
    use http::Uri;

    #[test]
    fn validate_uri_ref_matches_to_string_validation_across_uri_forms() {
        let exact_limit = format!("/{}", "a".repeat(8_191));
        let over_limit = format!("/{}", "a".repeat(8_192));
        let abs_exact = format!("https://example.test/{}", "b".repeat(8_192 - 21));
        let abs_over = format!("https://example.test/{}", "b".repeat(8_193 - 21));
        let query_exact = format!("/p?{}", "q".repeat(8_192 - 3));
        let query_over = format!("/p?{}", "q".repeat(8_193 - 3));

        let cases = [
            "/",
            "/1k.txt",
            "/1k.txt?a=1&b=2",
            "/a/b/c/",
            "/hello%20world.txt",
            "/api/pkg%2Fname",
            "/fichier%E9.pdf",
            "/..",
            "/a/../b",
            "/a/./b",
            "/..;jsessionid=1/secret",
            "/%2e%2e/etc/passwd",
            "/%2e%2e;foo/bar",
            "/%u002e%u002e/etc/passwd",
            "/%5c/evil",
            "/%00/null",
            "/%C0%AF/overlong",
            "/%E0%80%AE/overlong",
            "/%ED%A0%80/surrogate",
            "/%F0%80%80%AE/overlong",
            "/foo://bar/ok",
            "/foo://bar/..",
            "https://example.test",
            "https://example.test/",
            "https://example.test/1k.txt?x=1",
            "https://example.test/a/../b",
            "https://example.test/%2e%2e/x",
            "http://[::1]:8080/ok",
            "example.test:443",
            "*",
            exact_limit.as_str(),
            over_limit.as_str(),
            abs_exact.as_str(),
            abs_over.as_str(),
            query_exact.as_str(),
            query_over.as_str(),
        ];

        for raw in cases {
            if let Ok(uri) = raw.parse::<Uri>() {
                let via_string = validate_uri(&uri.to_string());
                let via_ref = validate_uri_ref(&uri);
                assert_eq!(via_ref, via_string, "mismatch for URI {raw:?}");
            }
        }
        let default_uri = Uri::default();
        assert_eq!(
            validate_uri_ref(&default_uri),
            validate_uri(&default_uri.to_string())
        );
    }
}

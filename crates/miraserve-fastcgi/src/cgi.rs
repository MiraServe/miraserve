//! RFC 3875 CGI/1.1 response parser converting `FCGI_STDOUT` into an [`http::Response`].
//!
//! Enforces strict header-block bounds, rejects `1xx` interim status smuggling and
//! whitespace-before-colon header names, strips hop-by-hop/framing/`Alt-Svc` headers,
//! and authoritatively computes `Content-Length` from the actual buffered body.

use bytes::Bytes;
use http::header::{
    ALT_SVC, CONNECTION, CONTENT_LENGTH, HeaderName, HeaderValue, LOCATION, PROXY_AUTHENTICATE,
    PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use http::{Response, StatusCode};

use crate::FastCgiError;

/// Maximum permitted CGI header section size (64 KiB).
const MAX_CGI_HEADER_BYTES: usize = 64 * 1024;

/// Maximum permitted CGI response headers.
const MAX_CGI_HEADERS: usize = 128;

/// Parses a raw CGI/1.1 stdout payload (`Header: Value\r\n\r\n<body>`) into an HTTP response.
///
/// # Errors
/// Returns [`FastCgiError::InvalidCgiResponse`] if headers lack a valid terminator, exceed
/// header size/count caps, emit `1xx` status codes, or contain malformed syntax.
#[allow(clippy::too_many_lines)]
pub fn parse_cgi_response(stdout: &[u8]) -> Result<Response<Bytes>, FastCgiError> {
    parse_cgi_bytes(&Bytes::copy_from_slice(stdout))
}

/// [`parse_cgi_response`] of output that is already owned: the answer's body shares its memory
/// instead of being a second copy.
///
/// # Errors
/// As [`parse_cgi_response`].
#[allow(clippy::too_many_lines)]
pub fn parse_cgi_bytes(stdout: &Bytes) -> Result<Response<Bytes>, FastCgiError> {
    let (header_bytes, body_bytes) = split_cgi_headers(stdout).ok_or_else(|| {
        FastCgiError::InvalidCgiResponse(
            "FastCGI stdout missing CGI header/body separator".to_owned(),
        )
    })?;

    if header_bytes.len() > MAX_CGI_HEADER_BYTES {
        return Err(FastCgiError::InvalidCgiResponse(format!(
            "FastCGI header section ({} bytes) exceeds limit of {MAX_CGI_HEADER_BYTES} bytes",
            header_bytes.len()
        )));
    }

    let header_str = std::str::from_utf8(header_bytes).map_err(|_| {
        FastCgiError::InvalidCgiResponse("FastCGI headers contain non-UTF-8 bytes".to_owned())
    })?;

    let mut status: Option<StatusCode> = None;
    let mut parsed_headers: Vec<(HeaderName, HeaderValue)> = Vec::new();
    let mut has_location = false;
    let mut connection_tokens: Vec<String> = Vec::new();

    for raw_line in header_str.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let Some((name_raw, val_raw)) = line.split_once(':') else {
            return Err(FastCgiError::InvalidCgiResponse(format!(
                "malformed CGI header line '{line}'"
            )));
        };
        // RFC 9112 §5.1: Reject whitespace in or before header field-name colon.
        if name_raw.is_empty() || name_raw != name_raw.trim() {
            return Err(FastCgiError::InvalidCgiResponse(
                "CGI header field-name must not contain leading or trailing whitespace".to_owned(),
            ));
        }

        let val = val_raw.trim();

        if name_raw.eq_ignore_ascii_case("status") {
            let code_token = val.split_whitespace().next().unwrap_or("");
            let code_u16: u16 = code_token.parse().map_err(|_| {
                FastCgiError::InvalidCgiResponse(format!("invalid CGI Status header '{val}'"))
            })?;
            // Reject 1xx informational/upgrade statuses from CGI scripts (prevents 101 smuggling).
            if (100..200).contains(&code_u16) {
                return Err(FastCgiError::InvalidCgiResponse(format!(
                    "1xx interim CGI Status code {code_u16} is forbidden"
                )));
            }
            let parsed_status = StatusCode::from_u16(code_u16).map_err(|_| {
                FastCgiError::InvalidCgiResponse(format!("out-of-range CGI Status code {code_u16}"))
            })?;
            status = Some(parsed_status);
            continue;
        }

        if parsed_headers.len() >= MAX_CGI_HEADERS {
            return Err(FastCgiError::InvalidCgiResponse(format!(
                "FastCGI response exceeded maximum header count of {MAX_CGI_HEADERS}"
            )));
        }

        let header_name = HeaderName::from_bytes(name_raw.as_bytes()).map_err(|err| {
            FastCgiError::InvalidCgiResponse(format!("invalid CGI header name '{name_raw}': {err}"))
        })?;
        let header_val = HeaderValue::from_str(val).map_err(|err| {
            FastCgiError::InvalidCgiResponse(format!(
                "invalid CGI header value for '{name_raw}': {err}"
            ))
        })?;

        if header_name == CONNECTION {
            for tok in val.split(',') {
                let t = tok.trim();
                if !t.is_empty() {
                    connection_tokens.push(t.to_ascii_lowercase());
                }
            }
            continue;
        }

        if is_forbidden_cgi_response_header(&header_name) {
            continue;
        }

        if header_name == LOCATION {
            has_location = true;
        }
        parsed_headers.push((header_name, header_val));
    }

    // RFC 3875 §6.2.2: Location without explicit Status defaults to 302 Found.
    let final_status = status.unwrap_or(if has_location {
        StatusCode::FOUND
    } else {
        StatusCode::OK
    });

    let mut builder = Response::builder().status(final_status);
    for (name, val) in parsed_headers {
        // Also drop any hop-by-hop header dynamically named in CGI `Connection:`.
        if connection_tokens.iter().any(|tok| tok == name.as_str()) {
            continue;
        }
        builder = builder.header(name, val);
    }

    let final_body = if matches!(
        final_status,
        StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED
    ) {
        Bytes::new()
    } else {
        builder = builder.header(CONTENT_LENGTH, body_bytes.len().to_string());
        stdout.slice_ref(body_bytes)
    };

    builder
        .body(final_body)
        .map_err(|err| FastCgiError::InvalidCgiResponse(err.to_string()))
}

fn is_forbidden_cgi_response_header(name: &HeaderName) -> bool {
    let s = name.as_str();
    *name == CONTENT_LENGTH
        || *name == TRANSFER_ENCODING
        || *name == CONNECTION
        || *name == UPGRADE
        || *name == TE
        || *name == TRAILER
        || *name == PROXY_AUTHENTICATE
        || *name == PROXY_AUTHORIZATION
        || *name == ALT_SVC
        || s == "keep-alive"
        || s == "proxy-connection"
}

/// The `Content-Length` a CGI head declares, when it declares exactly one valid length. The
/// parser above never passes it on (the answer's real length is used); a streamed answer, whose
/// length is not known when its head is sent, can use it and enforce it.
#[must_use]
pub fn declared_content_length(stdout: &[u8]) -> Option<u64> {
    let (head, _) = split_cgi_headers(stdout)?;
    let head = std::str::from_utf8(head).ok()?;
    let mut declared: Option<u64> = None;
    for line in head.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        // A length the script itself marks as belonging to its connection is not a statement
        // about the answer (the parser drops such a header by the same rule).
        if name.eq_ignore_ascii_case("connection")
            && value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("content-length"))
        {
            return None;
        }
        if !name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        let value = value.trim();
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let length: u64 = value.parse().ok()?;
        if declared.is_some_and(|earlier| earlier != length) {
            return None;
        }
        declared = Some(length);
    }
    declared
}

fn split_cgi_headers(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let search_limit = bytes.len().min(MAX_CGI_HEADER_BYTES.saturating_add(4));
    let mut i = 0_usize;
    while i < search_limit {
        if bytes.get(i..i.saturating_add(4)) == Some(b"\r\n\r\n") {
            let head = bytes.get(..i)?;
            let body = bytes.get(i.saturating_add(4)..)?;
            return Some((head, body));
        }
        if bytes.get(i..i.saturating_add(2)) == Some(b"\n\n") {
            let head = bytes.get(..i)?;
            let body = bytes.get(i.saturating_add(2)..)?;
            return Some((head, body));
        }
        i = i.saturating_add(1);
    }
    None
}

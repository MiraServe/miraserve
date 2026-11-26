#![no_main]
#![forbid(unsafe_code)]

use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Uri, Version};
use libfuzzer_sys::fuzz_target;
use miraserve_config::{LimitsConfig, SitePreset};
use miraserve_security::{SitePresetGuard, is_valid_rfc3986_host_port, validate_request_framing};

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = is_valid_rfc3986_host_port(text);
        let guard = SitePresetGuard::new(SitePreset::WordpressHardened);
        let empty_headers = HeaderMap::new();
        let _ = guard.evaluate(&Method::GET, text, &empty_headers, None);
    }

    // Exercise validate_request_framing across HTTP/1.1, HTTP/2, and HTTP/3 using raw
    // byte-level HeaderValue::from_bytes (reaching obs-text, duplicate headers, CL/TE tricks
    // that Request::builder() string helpers would reject early).
    let limits = LimitsConfig::default();
    let version = match data.first().copied().unwrap_or(0) % 3 {
        0 => Version::HTTP_11,
        1 => Version::HTTP_2,
        _ => Version::HTTP_3,
    };
    let rest = data.get(1..).unwrap_or(&[]);
    let mut parts = rest.split(|&b| b == b'\n');
    let raw_uri = parts.next().unwrap_or(b"/");
    let uri = Uri::try_from(raw_uri).unwrap_or_else(|_| Uri::from_static("/"));

    let mut req = Request::new(());
    *req.version_mut() = version;
    *req.uri_mut() = uri;
    for line in parts.take(24) {
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            let name_bytes = line.get(..colon).unwrap_or(&[]);
            let val_bytes = line.get(colon.saturating_add(1)..).unwrap_or(&[]);
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(name_bytes.trim_ascii()),
                HeaderValue::from_bytes(val_bytes.trim_ascii()),
            ) {
                req.headers_mut().append(name, val);
            }
        }
    }
    let _ = validate_request_framing(&req, &limits);
});

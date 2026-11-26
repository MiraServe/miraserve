#![no_main]
#![forbid(unsafe_code)]

use http::HeaderName;
use libfuzzer_sys::fuzz_target;
use miraserve_telemetry::{redact_header_value, redact_uri_query};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = redact_uri_query(text);
    if let Some((k, v)) = text.split_once(':')
        && let Ok(name) = HeaderName::from_bytes(k.trim().as_bytes())
    {
        let _ = redact_header_value(&name, v);
    }
});

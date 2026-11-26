#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use miraserve_migrate::{SourceFormat, detect_format, migrate_str};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = detect_format(text);
    for fmt in [
        SourceFormat::Nginx,
        SourceFormat::Caddy,
        SourceFormat::Apache,
        SourceFormat::OpenLiteSpeed,
    ] {
        let _ = migrate_str(text, fmt);
    }
});

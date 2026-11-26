#![no_main]
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;
use miraserve_config::{ByteSize, PreflightCheck};
use miraserve_publish::{SiteBundle, run_preflight_checks};

fuzz_target!(|data: &[u8]| {
    let mut files = BTreeMap::new();
    files.insert("index.html".to_owned(), data.to_vec());
    if let Ok(text) = std::str::from_utf8(data)
        && let Some((path, body)) = text.split_once('\n')
        && !path.is_empty()
        && path.len() <= 256
    {
        files.insert(path.to_owned(), body.as_bytes().to_vec());
    }
    let bundle = SiteBundle {
        site_id: None,
        files,
        note: None,
        created_at_unix: 1_760_000_000,
    };
    let checks = [
        PreflightCheck::NoSecrets,
        PreflightCheck::NoInlineScripts,
        PreflightCheck::CspValid,
        PreflightCheck::MaxSize(ByteSize::from_bytes(1024 * 1024)),
        PreflightCheck::MaxFiles(64),
    ];
    let _ = run_preflight_checks(&bundle, &checks);
});

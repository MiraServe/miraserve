#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use miraserve_fastcgi::cgi::parse_cgi_response;
use miraserve_fastcgi::protocol::{EndRequestBody, decode_params, decode_record_header};

fuzz_target!(|data: &[u8]| {
    if let Some(hdr_slice) = data.get(..8)
        && let Ok(hdr) = <[u8; 8]>::try_from(hdr_slice)
    {
        let _ = decode_record_header(hdr);
    }
    let _ = EndRequestBody::decode(data);
    let _ = decode_params(data);
    let _ = parse_cgi_response(data);
});

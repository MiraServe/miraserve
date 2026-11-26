#![no_main]
#![forbid(unsafe_code)]

use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};
use libfuzzer_sys::fuzz_target;
use miraserve_ai::{AgentKeyRegistry, RegisteredAgent, html_to_markdown, verify_rfc9421_request};

// Valid deterministic Ed25519 public key (RFC 8032 test vector 1 public key) so libFuzzer
// actually passes key lookup and reaches RFC 9421 signature-base construction & verification!
const FUZZ_ED25519_PUBKEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = html_to_markdown(text);

    let registry = AgentKeyRegistry::new();
    registry.register(
        "fuzz-key",
        RegisteredAgent {
            agent_id: "fuzz-agent".to_owned(),
            group: "verified-ai-agents".to_owned(),
            public_key: FUZZ_ED25519_PUBKEY,
        },
    );

    // 1. Direct fuzzed headers (may reference keyid="fuzz-key" or arbitrary structured fields)
    let mut headers = HeaderMap::new();
    for line in text.lines().take(12) {
        if let Some((k, v)) = line.split_once(':')
            && let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(k.trim().as_bytes()),
                HeaderValue::from_str(v.trim()),
            )
        {
            headers.append(name, val);
        }
    }
    let uri = Uri::from_static("/docs?q=1");
    let _ = verify_rfc9421_request(&Method::GET, &uri, &headers, &registry, 1_760_000_000);

    // 2. Guided harness pinning keyid="fuzz-key" & tag="web-bot-auth" so fuzzer always exercises
    //    covered-component parsing, signature-base assembly, and Ed25519 verification!
    let mut guided = HeaderMap::new();
    guided.insert(
        http::header::HOST,
        HeaderValue::from_static("fuzz.example.test"),
    );
    if let Some((sig_in, sig_val)) = text.split_once('\n') {
        let input_hdr = format!(
            "sig1=({sig_in});created=1760000000;expires=1760000300;keyid=\"fuzz-key\";alg=\"ed25519\";tag=\"web-bot-auth\""
        );
        if let Ok(v) = HeaderValue::from_str(&input_hdr) {
            guided.insert(HeaderName::from_static("signature-input"), v);
        }
        let sig_hdr = format!("sig1=:{sig_val}:");
        if let Ok(v) = HeaderValue::from_str(&sig_hdr) {
            guided.insert(HeaderName::from_static("signature"), v);
        }
        let _ = verify_rfc9421_request(&Method::GET, &uri, &guided, &registry, 1_760_000_050);
    }
});

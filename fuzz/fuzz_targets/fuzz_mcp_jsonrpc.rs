#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use miraserve_ai::{
    McpGateway, check_json_nesting_depth, filter_tools_list_response, glob_matches,
    parse_strict_json_no_duplicate_keys, redact_json_secrets,
};
use miraserve_config::{AuditLogMode, ByteSize, McpGatewayConfig};

fuzz_target!(|data: &[u8]| {
    let _ = check_json_nesting_depth(data, 32);

    // Exercise the real duplicate-key rejecting MCP JSON parser (`R2-MCP-3`)
    if check_json_nesting_depth(data, 32).is_ok()
        && let Ok(mut val) = parse_strict_json_no_duplicate_keys(data)
    {
        let _ = redact_json_secrets(&val);
        if let Ok(gw) = McpGateway::new(McpGatewayConfig {
            upstream: "http://127.0.0.1:9999".to_owned(),
            oauth_resource_metadata: false,
            jwt_public_key: None,
            jwks_url: None,
            jwt_issuer: None,
            jwt_audience: None,
            required_scope: None,
            allow_tools: vec!["docs_*".to_owned(), "catalog_read".to_owned()],
            deny_tools: vec!["*_delete".to_owned(), "shell_*".to_owned()],
            max_json_depth: 32,
            max_request_bytes: ByteSize::from_bytes(64 * 1024),
            audit_log: AuditLogMode::Off,
            upstream_connect_timeout: None,
            upstream_response_timeout: None,
            upstream_body_idle_timeout: None,
        }) {
            if let Some(tool_name) = val
                .get("params")
                .and_then(|p| p.get("name"))
                .and_then(serde_json::Value::as_str)
            {
                let _ = gw.check_tool_allowed(tool_name);
            }
            filter_tools_list_response(&gw, &mut val);
        }
    }

    if let Ok(text) = std::str::from_utf8(data)
        && let Some((pat, cand)) = text.split_once('\n')
    {
        let _ = glob_matches(pat, cand);
    }
});

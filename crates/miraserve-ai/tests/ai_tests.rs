//! Integration tests for `miraserve-ai`: RFC 9421 Web Bot Auth, MCP Security Gateway
//! (OAuth RFC 9728, tool RBAC, nesting depth, secret redaction), and Markdown negotiation.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use base64::Engine as _;
use bytes::Bytes;
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HOST, HeaderValue, USER_AGENT};
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use miraserve_ai::{
    AgentKeyRegistry, BotAuthGuard, BotAuthOutcome, McpGateway, RegisteredAgent,
    check_json_nesting_depth, filter_tools_list_response, html_to_markdown, markdown_sibling_path,
    prefers_markdown, redact_json_secrets, sign_rfc9421_headers, verify_rfc9421_request,
};
use miraserve_config::{
    AllowedAgentConfig, AuditLogMode, BotAuthConfig, ByteSize, McpGatewayConfig,
    UnverifiedBotAction,
};
use miraserve_proxy::full_body;
use serde_json::{Value, json};
use tokio::net::TcpListener;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
#[allow(clippy::too_many_lines)]
fn rfc9421_web_bot_auth_verifies_ed25519_and_enforces_unverified_ai_ua_policy() -> TestResult {
    let key_pair = Ed25519KeyPair::generate().map_err(|_| "ed25519 keygen failed")?;
    let mut pub_bytes = [0_u8; 32];
    pub_bytes.copy_from_slice(
        key_pair
            .public_key()
            .as_ref()
            .get(..32)
            .ok_or("bad pubkey len")?,
    );

    let registry = Arc::new(AgentKeyRegistry::new());
    registry.register(
        "agent-key-1",
        RegisteredAgent {
            agent_id: "claude-search".to_owned(),
            group: "verified-ai-agents".to_owned(),
            public_key: pub_bytes,
        },
    );

    let guard = BotAuthGuard::new(
        BotAuthConfig {
            verify_rfc9421: true,
            allow_agents: vec![AllowedAgentConfig {
                name: "verified-ai-agents".to_owned(),
                serve_markdown: true,
            }],
            on_unverified_ai_ua: UnverifiedBotAction::Throttle,
            ..BotAuthConfig::default()
        },
        Arc::clone(&registry),
    );

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    // 1. Valid RFC 9421 signed request -> Verified + serve_markdown=true
    let uri: Uri = "/docs/architecture".parse()?;
    let mut headers = HeaderMap::new();
    headers.insert(HOST, HeaderValue::from_static("future.example.com"));
    headers.insert(USER_AGENT, HeaderValue::from_static("ClaudeBot/1.0"));
    sign_rfc9421_headers(
        &Method::GET,
        &uri,
        &mut headers,
        "agent-key-1",
        &key_pair,
        now,
        now.saturating_add(300),
    )?;

    let outcome = guard.evaluate(&Method::GET, &uri, &headers, None);
    match outcome {
        BotAuthOutcome::Verified {
            agent,
            serve_markdown,
        } => {
            assert_eq!(agent.agent_id, "claude-search");
            assert_eq!(agent.group, "verified-ai-agents");
            assert!(serve_markdown);
        }
        other => return Err(format!("expected Verified, got {other:?}").into()),
    }

    // 2. Tampered path invalidates RFC 9421 signature!
    let tampered_uri: Uri = "/admin/secrets".parse()?;
    assert!(verify_rfc9421_request(&Method::GET, &tampered_uri, &headers, &registry, now).is_err());

    // 3. Expired signature rejected
    assert!(
        verify_rfc9421_request(
            &Method::GET,
            &uri,
            &headers,
            &registry,
            now.saturating_add(600),
        )
        .is_err()
    );

    // 4. Unverified GPTBot hits burst=3 then gets throttled (429)
    let mut bot_hdrs = HeaderMap::new();
    bot_hdrs.insert(
        USER_AGENT,
        HeaderValue::from_static("Mozilla/5.0 GPTBot/1.2"),
    );
    let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99)));
    for _ in 0..3 {
        assert_eq!(
            guard.evaluate(&Method::GET, &uri, &bot_hdrs, ip),
            BotAuthOutcome::Pass {
                serve_markdown: false
            }
        );
    }
    assert!(matches!(
        guard.evaluate(&Method::GET, &uri, &bot_hdrs, ip),
        BotAuthOutcome::Throttle { .. }
    ));

    // 5. Invalid RFC 9421 signature MUST fail closed (403), NEVER fall through to Pass!
    let mut bad_sig_hdrs = headers.clone();
    bad_sig_hdrs.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0"));
    assert!(matches!(
        guard.evaluate(&Method::GET, &tampered_uri, &bad_sig_hdrs, ip),
        BotAuthOutcome::Reject {
            status: StatusCode::FORBIDDEN,
            ..
        }
    ));

    // 6. Registered agent NOT in site allow_agents MUST be rejected (403)!
    let other_kp = Ed25519KeyPair::generate().map_err(|_| "ed25519 keygen failed")?;
    let mut other_pub = [0_u8; 32];
    other_pub.copy_from_slice(
        other_kp
            .public_key()
            .as_ref()
            .get(..32)
            .ok_or("bad pubkey len")?,
    );
    registry.register(
        "other-key",
        RegisteredAgent {
            agent_id: "untrusted-bot".to_owned(),
            group: "other-group".to_owned(),
            public_key: other_pub,
        },
    );
    let mut other_hdrs = HeaderMap::new();
    other_hdrs.insert(HOST, HeaderValue::from_static("future.example.com"));
    sign_rfc9421_headers(
        &Method::GET,
        &uri,
        &mut other_hdrs,
        "other-key",
        &other_kp,
        now,
        now.saturating_add(120),
    )?;
    assert!(matches!(
        guard.evaluate(&Method::GET, &uri, &other_hdrs, ip),
        BotAuthOutcome::Reject {
            status: StatusCode::FORBIDDEN,
            ..
        }
    ));

    // 7. Signature with excessive replay window (> 300s) rejected
    let mut long_hdrs = HeaderMap::new();
    long_hdrs.insert(HOST, HeaderValue::from_static("future.example.com"));
    sign_rfc9421_headers(
        &Method::GET,
        &uri,
        &mut long_hdrs,
        "agent-key-1",
        &key_pair,
        now,
        now.saturating_add(9999),
    )?;
    assert!(verify_rfc9421_request(&Method::GET, &uri, &long_hdrs, &registry, now).is_err());

    // 8. BOT-1: AgentKeyRegistry loads inline KDL `agent-key` configs atomically
    let inline_reg = AgentKeyRegistry::new();
    let cfg_with_keys = BotAuthConfig {
        verify_rfc9421: true,
        allow_agents: vec![AllowedAgentConfig {
            name: "verified-ai-agents".to_owned(),
            serve_markdown: true,
        }],
        on_unverified_ai_ua: UnverifiedBotAction::Block,
        agent_keys: vec![miraserve_config::BotAgentKeyConfig {
            key_id: "cfg-key-1".to_owned(),
            agent_id: "cfg-bot".to_owned(),
            group: "verified-ai-agents".to_owned(),
            ed25519_b64: base64::engine::general_purpose::STANDARD.encode(pub_bytes),
        }],
        agent_keys_file: None,
    };
    assert_eq!(inline_reg.load_from_bot_auth_config(&cfg_with_keys)?, 1);
    assert!(inline_reg.get("cfg-key-1").is_some());

    Ok(())
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn mcp_gateway_enforces_rbac_depth_oauth_metadata_and_redacts_secrets() -> TestResult {
    // Spawn mock upstream MCP server
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = listener.local_addr()?;
    let up_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let bytes = req
                        .into_body()
                        .collect()
                        .await
                        .map_or_else(|_| Bytes::new(), http_body_util::Collected::to_bytes);
                    let parsed: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                    let tool = parsed
                        .get("params")
                        .and_then(|p| p.get("name"))
                        .and_then(Value::as_str)
                        .unwrap_or("none");
                    let reply = serde_json::to_vec(&json!({
                        "jsonrpc": "2.0",
                        "id": parsed.get("id").cloned().unwrap_or(Value::Null),
                        "result": { "executed": tool }
                    }))
                    .unwrap_or_default();
                    Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(reply))))
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let oauth_kp =
        Ed25519KeyPair::generate().map_err(|_| "failed to generate OAuth JWT keypair")?;
    let oauth_pub_encoded = format!(
        "miraserve-ed25519-pub:{}",
        base64::engine::general_purpose::STANDARD.encode(oauth_kp.public_key().as_ref())
    );
    let now_jwt = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let valid_jwt = format!(
        "Bearer {}",
        miraserve_ai::sign_mcp_oauth_jwt(
            &oauth_kp,
            "agent-alice",
            now_jwt.saturating_add(300),
            Some("https://auth.example.com"),
            Some("https://ai.example.com"),
            Some("mcp:tools"),
            None,
        )
    );
    let valid_jwt = valid_jwt.as_str();

    let gateway = McpGateway::new(McpGatewayConfig {
        upstream: format!("http://{up_addr}"),
        oauth_resource_metadata: true,
        jwt_public_key: Some(oauth_pub_encoded),
        jwks_url: None,
        jwt_issuer: Some("https://auth.example.com".to_owned()),
        jwt_audience: Some("https://ai.example.com".to_owned()),
        required_scope: Some("mcp:tools".to_owned()),
        allow_tools: vec!["docs_*".to_owned(), "catalog_read".to_owned()],
        deny_tools: vec!["*_delete".to_owned(), "*_exec".to_owned()],
        audit_log: AuditLogMode::StructuredJson,
        max_json_depth: 8,
        max_request_bytes: ByteSize::from_bytes(4096),
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
    })?;

    // MCP-3: Empty allow-tools MUST be fail-closed default-deny!
    let empty_allow_gw = McpGateway::new(McpGatewayConfig {
        upstream: format!("http://{up_addr}"),
        oauth_resource_metadata: false,
        jwt_public_key: None,
        jwks_url: None,
        jwt_issuer: None,
        jwt_audience: None,
        required_scope: None,
        allow_tools: Vec::new(),
        deny_tools: Vec::new(),
        audit_log: AuditLogMode::Off,
        max_json_depth: 8,
        max_request_bytes: ByteSize::from_bytes(4096),
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
    })?;
    assert!(matches!(
        empty_allow_gw.check_tool_allowed("docs_search"),
        miraserve_ai::ToolRbacDecision::Deny { .. }
    ));

    // 1. OAuth RFC 9728 metadata
    let meta = gateway.oauth_protected_resource_metadata("https://ai.example.com/mcp");
    assert_eq!(meta.status(), StatusCode::OK);
    let meta_json: Value = serde_json::from_slice(&meta.into_body().collect().await?.to_bytes())?;
    assert_eq!(
        meta_json.get("resource").and_then(Value::as_str),
        Some("https://ai.example.com/mcp")
    );

    // 2. Allowed tool (`docs_search`) with verified EdDSA JWT forwards to upstream MCP server
    let ok_payload = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": { "name": "docs_search", "arguments": { "query": "pqc", "api_key": "super-secret" } }
    }))?;
    let ok_req = Request::builder()
        .method(Method::POST)
        .uri("/mcp/rpc")
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, valid_jwt)
        .body(full_body(Bytes::from(ok_payload)))?;
    let (ok_resp, blocked) = gateway.handle_with_outcome(ok_req, None, "https").await;
    assert!(!blocked);
    assert_eq!(ok_resp.status(), StatusCode::OK);
    let ok_json: Value = serde_json::from_slice(&ok_resp.into_body().collect().await?.to_bytes())?;
    assert_eq!(
        ok_json
            .get("result")
            .and_then(|r| r.get("executed"))
            .and_then(Value::as_str),
        Some("docs_search")
    );

    // 2.5 Unauthenticated, forged, expired, or wrong-scope MCP JWT -> 401 + WWW-Authenticate
    let wrong_scope_jwt = format!(
        "Bearer {}",
        miraserve_ai::sign_mcp_oauth_jwt(
            &oauth_kp,
            "agent-alice",
            now_jwt.saturating_add(300),
            Some("https://auth.example.com"),
            Some("https://ai.example.com"),
            Some("other:scope"),
            None,
        )
    );
    for bad_auth in [
        None,
        Some("Bearer forged-opaque-token"),
        Some("Bearer a.b.c"),
        Some(wrong_scope_jwt.as_str()),
    ] {
        let mut b = Request::builder()
            .method(Method::POST)
            .uri("/mcp/rpc")
            .header(CONTENT_TYPE, "application/json");
        if let Some(h) = bad_auth {
            b = b.header(AUTHORIZATION, h);
        }
        let req = b.body(full_body(Bytes::from_static(
            br#"{"jsonrpc":"2.0","id":9,"method":"tools/list"}"#,
        )))?;
        let (resp, was_blocked) = gateway.handle_with_outcome(req, None, "https").await;
        assert!(was_blocked);
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(resp.headers().get(http::header::WWW_AUTHENTICATE).is_some());
    }

    // 3. Denied tool matching `*_delete` (even though it ALSO matches `docs_*`!) -> 403
    let deny_payload = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "tools/call",
        "params": { "name": "docs_delete", "arguments": {} }
    }))?;
    let deny_req = Request::builder()
        .method(Method::POST)
        .uri("/mcp/rpc")
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, valid_jwt)
        .body(full_body(Bytes::from(deny_payload)))?;
    let (deny_resp, was_blocked) = gateway.handle_with_outcome(deny_req, None, "https").await;
    assert!(was_blocked);
    assert_eq!(deny_resp.status(), StatusCode::FORBIDDEN);

    // 4. Unlisted tool (`shell_run`) -> 403 default-deny
    let unlisted_payload = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 12,
        "method": "tools/call",
        "params": { "name": "shell_run", "arguments": {} }
    }))?;
    let unlisted_req = Request::builder()
        .method(Method::POST)
        .uri("/mcp/rpc")
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, valid_jwt)
        .body(full_body(Bytes::from(unlisted_payload)))?;
    assert_eq!(
        gateway.handle(unlisted_req, None, "https").await.status(),
        StatusCode::FORBIDDEN
    );

    // 5. Deeply nested JSON exceeds max_json_depth=8 -> 400
    let deep = format!("{}{}", "[".repeat(16), "]".repeat(16));
    assert!(check_json_nesting_depth(deep.as_bytes(), 8).is_err());
    let deep_req = Request::builder()
        .method(Method::POST)
        .uri("/mcp/rpc")
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, valid_jwt)
        .body(full_body(Bytes::from(deep)))?;
    assert_eq!(
        gateway.handle(deep_req, None, "https").await.status(),
        StatusCode::BAD_REQUEST
    );

    // 5.5 JSON-RPC batch arrays and malformed JSON fail closed (400), never reaching upstream!
    for bad_body in [
        br#"[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shell_exec"}}]"#
            .as_slice(),
        b"{not valid json".as_slice(),
    ] {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp/rpc")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, valid_jwt)
            .body(full_body(Bytes::copy_from_slice(bad_body)))?;
        assert_eq!(
            gateway.handle(req, None, "https").await.status(),
            StatusCode::BAD_REQUEST
        );
    }

    // 5.6 Content-Encoding rejected (415) and Upgrade rejected (400)
    let gz_req = Request::builder()
        .method(Method::POST)
        .uri("/mcp/rpc")
        .header(AUTHORIZATION, valid_jwt)
        .header(http::header::CONTENT_ENCODING, "gzip")
        .body(full_body(Bytes::from_static(b"compressed")))?;
    assert_eq!(
        gateway.handle(gz_req, None, "https").await.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );

    // 5.7 Raw Authorization header without space MUST NOT leak into redacted principal!
    let mut raw_auth = HeaderMap::new();
    raw_auth.insert(
        AUTHORIZATION,
        HeaderValue::from_static("sk-ant-supersecret-no-space"),
    );
    assert_eq!(
        miraserve_ai::extract_redacted_principal(&raw_auth).as_deref(),
        Some("Auth [REDACTED]")
    );
    // Hyphenated keys & inline token values redacted in audit arguments
    let hyphen_secret = json!({
        "x-api-key": "k-1",
        "note": "Authorization: Bearer eyJhbGciOi.payload.sig"
    });
    let clean_args = redact_json_secrets(&hyphen_secret);
    assert_eq!(
        clean_args.get("x-api-key").and_then(Value::as_str),
        Some("[REDACTED]")
    );
    assert_eq!(
        clean_args.get("note").and_then(Value::as_str),
        Some("[REDACTED]")
    );

    // 6. tools/list filtering strips denied and unlisted tools
    let mut tools_list = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": [
                { "name": "docs_search" },
                { "name": "docs_delete" },
                { "name": "shell_exec" },
                { "name": "catalog_read" }
            ]
        }
    });
    filter_tools_list_response(&gateway, &mut tools_list);
    let kept: Vec<&str> = tools_list
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|t| t.get("name").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(kept, vec!["docs_search", "catalog_read"]);

    // 7. Codex Finding 3: `required_scope` / `jwt_issuer` / `jwt_audience` with
    //    `oauth_resource_metadata = false` and NO verifier key MUST fail closed (401), never forward!
    let claim_only_gw = McpGateway::new(McpGatewayConfig {
        upstream: format!("http://{up_addr}"),
        oauth_resource_metadata: false,
        jwt_public_key: None,
        jwks_url: None,
        jwt_issuer: None,
        jwt_audience: None,
        required_scope: Some("mcp:admin".to_owned()),
        allow_tools: vec!["docs_search".to_owned()],
        deny_tools: vec![],
        max_json_depth: 16,
        max_request_bytes: ByteSize::from_bytes(64 * 1024),
        audit_log: AuditLogMode::Off,
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
    })?;
    let req_claim_only = Request::builder()
        .method(Method::POST)
        .uri("/mcp/rpc")
        .header("content-type", "application/json")
        .body(full_body(Bytes::from(serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": { "name": "docs_search", "arguments": {} }
        }))?)))?;
    let (resp_claim_only, blocked_claim_only) = claim_only_gw
        .handle_with_outcome(req_claim_only, None, "https")
        .await;
    assert!(
        blocked_claim_only,
        "unauthenticated MCP request with required_scope set MUST be blocked by gateway"
    );
    assert_eq!(resp_claim_only.status(), StatusCode::UNAUTHORIZED);

    // 8. Secret redaction masks nested passwords/tokens/api_keys
    let raw = json!({ "query": "rust", "api_key": "sk-1234", "nested": { "user_password": "pw" } });
    let redacted = redact_json_secrets(&raw);
    assert_eq!(redacted.get("query").and_then(Value::as_str), Some("rust"));
    assert_eq!(
        redacted.get("api_key").and_then(Value::as_str),
        Some("[REDACTED]")
    );
    assert_eq!(
        redacted
            .get("nested")
            .and_then(|n| n.get("user_password"))
            .and_then(Value::as_str),
        Some("[REDACTED]")
    );

    up_task.abort();
    Ok(())
}

#[test]
fn markdown_content_negotiation_and_html_conversion() {
    let mut hdrs = HeaderMap::new();
    hdrs.insert(
        ACCEPT,
        HeaderValue::from_static("text/markdown, text/html;q=0.8"),
    );
    assert!(prefers_markdown(&hdrs, false));
    assert!(!prefers_markdown(&HeaderMap::new(), false));
    assert!(prefers_markdown(&HeaderMap::new(), true));

    assert_eq!(markdown_sibling_path("/").as_deref(), Some("/index.md"));
    assert_eq!(
        markdown_sibling_path("/docs/intro.html").as_deref(),
        Some("/docs/intro.md")
    );
    assert_eq!(markdown_sibling_path("/assets/logo.png"), None);
    assert_eq!(markdown_sibling_path("/llms.txt"), None);

    let html = "<html><head><style>body{color:red}</style></head><body><h1>MiraServe</h1><script>alert(1)</script><p>Fast &amp; safe.</p><ul><li>PQC</li><li>MCP</li></ul></body></html>";
    let md = html_to_markdown(html);
    assert!(md.contains("# MiraServe"));
    assert!(md.contains("Fast & safe."));
    assert!(md.contains("- PQC"));
    assert!(!md.contains("alert(1)"));
    assert!(!md.contains("color:red"));
}

/// R2-MCP-1 & R2-MCP-2: Verify live HTTP JWKS fetching uses the exact `/.well-known/jwks.json`
/// path (never doubled!), verifies tokens signed with `kid`, and purges revoked keys cleanly.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn mcp_gateway_fetches_jwks_at_exact_path_and_verifies_eddsa_jwt() -> TestResult {
    let kp1 = Ed25519KeyPair::generate().map_err(|_| "kp1")?;
    let kp2 = Ed25519KeyPair::generate().map_err(|_| "kp2")?;
    let x1 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(kp1.public_key().as_ref());
    let x2 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(kp2.public_key().as_ref());

    let jwks_body = Arc::new(std::sync::Mutex::new(
        json!({
            "keys": [
                { "kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": x1 }
            ]
        })
        .to_string(),
    ));
    let seen_jwks_paths = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));

    // Spawn mock JWKS HTTP server recording exact requested path.
    let jwks_listener = TcpListener::bind("127.0.0.1:0").await?;
    let jwks_addr = jwks_listener.local_addr()?;
    let jwks_body_srv = Arc::clone(&jwks_body);
    let seen_paths_srv = Arc::clone(&seen_jwks_paths);
    let jwks_task = tokio::spawn(async move {
        while let Ok((stream, _)) = jwks_listener.accept().await {
            let body_ref = Arc::clone(&jwks_body_srv);
            let paths_ref = Arc::clone(&seen_paths_srv);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let body_ref = Arc::clone(&body_ref);
                    let paths_ref = Arc::clone(&paths_ref);
                    async move {
                        let req_path = req
                            .uri()
                            .path_and_query()
                            .map_or("/", http::uri::PathAndQuery::as_str)
                            .to_owned();
                        if let Ok(mut guard) = paths_ref.lock() {
                            guard.push(req_path.clone());
                        }
                        if req_path == "/.well-known/jwks.json" {
                            let body = body_ref
                                .lock()
                                .map_or_else(|_| "{}".to_owned(), |g| g.clone());
                            Ok::<_, hyper::Error>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header("content-type", "application/json")
                                    .body(Full::new(Bytes::from(body)))
                                    .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                            )
                        } else {
                            Ok::<_, hyper::Error>(
                                Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Full::new(Bytes::from_static(b"wrong path")))
                                    .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                            )
                        }
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    // Spawn mock upstream MCP server echoing 200 OK.
    let up_listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = up_listener.local_addr()?;
    let up_task = tokio::spawn(async move {
        while let Ok((stream, _)) = up_listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(move |_req: Request<Incoming>| async move {
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "application/json")
                            .body(Full::new(Bytes::from_static(
                                br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#,
                            )))
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                    )
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let gateway = McpGateway::new(McpGatewayConfig {
        upstream: format!("http://{up_addr}"),
        oauth_resource_metadata: true,
        jwt_public_key: None,
        jwks_url: Some(format!("http://{jwks_addr}/.well-known/jwks.json")),
        jwt_issuer: Some("https://idp.example.test".to_owned()),
        jwt_audience: Some("mcp.example.test".to_owned()),
        required_scope: Some("mcp:read".to_owned()),
        allow_tools: vec!["docs_search".to_owned()],
        deny_tools: vec![],
        max_json_depth: 16,
        max_request_bytes: ByteSize::from_bytes(64 * 1024),
        audit_log: AuditLogMode::Off,
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
    })?;

    let sign_jwt = |kp: &Ed25519KeyPair, kid: &str, aud: &str| -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let hdr = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(json!({"alg":"EdDSA","typ":"JWT","kid":kid}).to_string());
        let pay = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            json!({
                "sub": "agent-jwks",
                "iss": "https://idp.example.test",
                "aud": aud,
                "scope": "mcp:read",
                "iat": now,
                "exp": now.saturating_add(300)
            })
            .to_string(),
        );
        let input = format!("{hdr}.{pay}");
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(kp.sign(input.as_bytes()).as_ref());
        format!("{input}.{sig}")
    };

    let make_rpc_req = |token: &str| -> Result<Request<miraserve_proxy::ProxyBody>, http::Error> {
        Request::builder()
            .method(Method::POST)
            .uri("/mcp/rpc")
            .header("content-type", "application/json")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(full_body(Bytes::from_static(
                br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"docs_search","arguments":{}}}"#,
            )))
    };

    // 1. Valid JWT with kid="k1" triggers JWKS fetch to EXACT path `/.well-known/jwks.json` and succeeds!
    let token_k1 = sign_jwt(&kp1, "k1", "mcp.example.test");
    let (resp_ok, blocked_ok) = gateway
        .handle_with_outcome(make_rpc_req(&token_k1)?, None, "https")
        .await;
    assert!(!blocked_ok);
    assert_eq!(resp_ok.status(), StatusCode::OK);

    let paths = seen_jwks_paths
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default();
    assert_eq!(
        paths,
        vec!["/.well-known/jwks.json".to_owned()],
        "JWKS fetch path must NOT be doubled"
    );

    // 2. Wrong audience MUST be rejected 401
    let token_bad_aud = sign_jwt(&kp1, "k1", "other-service.example.test");
    let (resp_bad_aud, blocked_bad_aud) = gateway
        .handle_with_outcome(make_rpc_req(&token_bad_aud)?, None, "https")
        .await;
    assert!(blocked_bad_aud);
    assert_eq!(resp_bad_aud.status(), StatusCode::UNAUTHORIZED);

    // 3. Unknown kid="k2" (not yet in JWKS) is rejected 401
    let token_k2 = sign_jwt(&kp2, "k2", "mcp.example.test");
    let (resp_unknown, blocked_unknown) = gateway
        .handle_with_outcome(make_rpc_req(&token_k2)?, None, "https")
        .await;
    assert!(blocked_unknown);
    assert_eq!(resp_unknown.status(), StatusCode::UNAUTHORIZED);

    // 4. Fresh gateway pointing at rotated JWKS (containing ONLY k2, revoking k1) accepts k2 & rejects k1
    if let Ok(mut guard) = jwks_body.lock() {
        *guard = json!({
            "keys": [
                { "kty": "OKP", "crv": "Ed25519", "kid": "k2", "x": x2 }
            ]
        })
        .to_string();
    }
    let rotated_gw = McpGateway::new(McpGatewayConfig {
        upstream: format!("http://{up_addr}"),
        oauth_resource_metadata: true,
        jwt_public_key: None,
        jwks_url: Some(format!("http://{jwks_addr}/.well-known/jwks.json")),
        jwt_issuer: Some("https://idp.example.test".to_owned()),
        jwt_audience: Some("mcp.example.test".to_owned()),
        required_scope: Some("mcp:read".to_owned()),
        allow_tools: vec!["docs_search".to_owned()],
        deny_tools: vec![],
        max_json_depth: 16,
        max_request_bytes: ByteSize::from_bytes(64 * 1024),
        audit_log: AuditLogMode::Off,
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
    })?;
    let (resp_k2_ok, _) = rotated_gw
        .handle_with_outcome(make_rpc_req(&token_k2)?, None, "https")
        .await;
    assert_eq!(resp_k2_ok.status(), StatusCode::OK);
    let (resp_k1_revoked, blocked_k1) = rotated_gw
        .handle_with_outcome(make_rpc_req(&token_k1)?, None, "https")
        .await;
    assert!(blocked_k1);
    assert_eq!(resp_k1_revoked.status(), StatusCode::UNAUTHORIZED);

    jwks_task.abort();
    up_task.abort();
    Ok(())
}

/// R2-MCP-3, R2-MCP-4, R2-BOT-1 regression tests:
/// - Duplicate JSON keys rejected (400) so `serde_json` vs upstream parsers cannot diverge
/// - Non-JSON `Content-Type` rejected (415)
/// - JSON-RPC 2.0 client responses (`id` + `result`, no `method`) forwarded cleanly
/// - `tools/list` SSE (`text/event-stream`) responses have disallowed tools stripped
/// - RFC 9728 metadata includes `authorization_servers` and `WWW-Authenticate` emits absolute URL
/// - Unrelated `Signature` headers (e.g. `ActivityPub` / webhooks without `tag="web-bot-auth"`)
///   pass through `BotAuthGuard` instead of getting rejected 403.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn mcp_wave2_hardening_and_bot_auth_non_web_bot_signature_passthrough() -> TestResult {
    // Spawn mock upstream MCP server handling JSON-RPC client responses and SSE tools/list.
    let up_listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = up_listener.local_addr()?;
    let up_task = tokio::spawn(async move {
        while let Ok((stream, _)) = up_listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let body = req
                        .into_body()
                        .collect()
                        .await
                        .map(http_body_util::Collected::to_bytes)
                        .unwrap_or_default();
                    let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                    if parsed.get("method").and_then(Value::as_str) == Some("tools/list") {
                        let sse = concat!(
                            "event: message\n",
                            "data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"tools\":[",
                            "{\"name\":\"docs_search\"},{\"name\":\"docs_delete\"},{\"name\":\"shell_exec\"}",
                            "]}}\n\n"
                        );
                        return Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header(CONTENT_TYPE, "text/event-stream")
                                .body(Full::new(Bytes::from(sse)))
                                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                        );
                    }
                    // Client JSON-RPC response -> HTTP 202 Accepted per MCP Streamable HTTP
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(StatusCode::ACCEPTED)
                            .header(CONTENT_TYPE, "application/json")
                            .body(Full::new(Bytes::from_static(br#"{"ack":true}"#)))
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                    )
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let oauth_kp = Ed25519KeyPair::generate().map_err(|_| "oauth kp")?;
    let pub_b64 = base64::engine::general_purpose::STANDARD.encode(oauth_kp.public_key().as_ref());
    let now_jwt = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let valid_jwt = format!(
        "Bearer {}",
        miraserve_ai::sign_mcp_oauth_jwt(
            &oauth_kp,
            "agent-wave2",
            now_jwt.saturating_add(300),
            Some("https://idp.example.test"),
            Some("https://ai.example.test"),
            Some("mcp:read"),
            None,
        )
    );

    let gateway = McpGateway::new(McpGatewayConfig {
        upstream: format!("http://{up_addr}"),
        oauth_resource_metadata: true,
        jwt_public_key: Some(pub_b64),
        jwks_url: None,
        jwt_issuer: Some("https://idp.example.test".to_owned()),
        jwt_audience: Some("https://ai.example.test".to_owned()),
        required_scope: Some("mcp:read".to_owned()),
        allow_tools: vec!["docs_*".to_owned()],
        deny_tools: vec!["*_delete".to_owned()],
        max_json_depth: 16,
        max_request_bytes: ByteSize::from_bytes(64 * 1024),
        audit_log: AuditLogMode::Off,
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
    })?;

    // 1. R2-MCP-4: RFC 9728 metadata includes `authorization_servers`
    let meta = gateway.oauth_protected_resource_metadata("https://ai.example.test/mcp");
    let meta_json: Value = serde_json::from_slice(&meta.into_body().collect().await?.to_bytes())?;
    assert_eq!(
        meta_json
            .get("authorization_servers")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(Value::as_str),
        Some("https://idp.example.test")
    );

    // 2. R2-MCP-4: `WWW-Authenticate` emits absolute `resource_metadata` URL when Host is present
    let unauth_req = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header(HOST, "ai.example.test")
        .header(CONTENT_TYPE, "application/json")
        .body(full_body(Bytes::from_static(
            br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
        )))?;
    let (unauth_resp, blocked) = gateway.handle_with_outcome(unauth_req, None, "https").await;
    assert!(blocked);
    assert_eq!(unauth_resp.status(), StatusCode::UNAUTHORIZED);
    let www = unauth_resp
        .headers()
        .get(http::header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        www.contains(
            "resource_metadata=\"https://ai.example.test/.well-known/oauth-protected-resource\""
        ),
        "expected absolute resource_metadata URL, got: {www}"
    );

    // 3. R2-MCP-3: Wrong Content-Type -> 415 Unsupported Media Type
    let wrong_ct = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header(CONTENT_TYPE, "text/plain")
        .header(AUTHORIZATION, valid_jwt.as_str())
        .body(full_body(Bytes::from_static(
            br#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#,
        )))?;
    let (wrong_ct_resp, blocked) = gateway.handle_with_outcome(wrong_ct, None, "https").await;
    assert!(blocked);
    assert_eq!(wrong_ct_resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    // 4. R2-MCP-3: Duplicate JSON keys (`method` smuggled twice) -> 400 Bad Request
    let dup_key_body = br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"docs_delete"},"method":"ping"}"#;
    let dup_req = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, valid_jwt.as_str())
        .body(full_body(Bytes::from_static(dup_key_body)))?;
    let (dup_resp, blocked) = gateway.handle_with_outcome(dup_req, None, "https").await;
    assert!(blocked);
    assert_eq!(dup_resp.status(), StatusCode::BAD_REQUEST);

    // 5. R2-MCP-4: JSON-RPC 2.0 client response (`id` + `result`, no `method`) passes through!
    let client_resp_req = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, valid_jwt.as_str())
        .body(full_body(Bytes::from_static(
            br#"{"jsonrpc":"2.0","id":42,"result":{"sampling":"ok"}}"#,
        )))?;
    let (client_resp_out, blocked) = gateway
        .handle_with_outcome(client_resp_req, None, "https")
        .await;
    assert!(!blocked, "valid JSON-RPC client response must be allowed");
    assert_eq!(client_resp_out.status(), StatusCode::ACCEPTED);

    // 6. R2-MCP-4: `tools/list` SSE (`text/event-stream`) response strips denied & unlisted tools!
    let sse_req = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, valid_jwt.as_str())
        .body(full_body(Bytes::from_static(
            br#"{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{}}"#,
        )))?;
    let (sse_resp, blocked) = gateway.handle_with_outcome(sse_req, None, "https").await;
    assert!(!blocked);
    assert_eq!(sse_resp.status(), StatusCode::OK);
    let sse_bytes = sse_resp.into_body().collect().await?.to_bytes();
    let sse_text = String::from_utf8(sse_bytes.to_vec())?;
    assert!(sse_text.contains("docs_search"), "sse: {sse_text}");
    assert!(
        !sse_text.contains("docs_delete"),
        "denied tool leaked in SSE: {sse_text}"
    );
    assert!(
        !sse_text.contains("shell_exec"),
        "unlisted tool leaked in SSE: {sse_text}"
    );

    // 7. R2-BOT-1: Non-`web-bot-auth` `Signature` header (e.g. ActivityPub / Stripe webhook)
    //    must NOT be rejected by BotAuthGuard!
    let registry = Arc::new(AgentKeyRegistry::new());
    let guard = BotAuthGuard::new(
        BotAuthConfig {
            verify_rfc9421: true,
            allow_agents: vec![AllowedAgentConfig {
                name: "verified-agent".to_owned(),
                serve_markdown: false,
            }],
            agent_keys: vec![],
            agent_keys_file: None,
            on_unverified_ai_ua: UnverifiedBotAction::Challenge,
        },
        registry,
    );
    let mut ap_headers = HeaderMap::new();
    ap_headers.insert(HOST, HeaderValue::from_static("social.example.test"));
    ap_headers.insert(
        USER_AGENT,
        HeaderValue::from_static("Mastodon/4.3 (+https://mastodon.social/)"),
    );
    ap_headers.insert(
        "signature",
        HeaderValue::from_static(
            "keyId=\"https://mastodon.social/users/alice#main-key\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date\",signature=\"ZmFrZQ==\"",
        ),
    );
    let uri = Uri::from_static("/inbox");
    let outcome = guard.evaluate(
        &Method::POST,
        &uri,
        &ap_headers,
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    );
    assert!(
        matches!(
            outcome,
            BotAuthOutcome::Pass {
                serve_markdown: false
            }
        ),
        "ActivityPub Signature header must pass through BotAuthGuard, got: {outcome:?}"
    );

    up_task.abort();
    Ok(())
}

struct MpscFrameBody(
    tokio::sync::mpsc::Receiver<Result<hyper::body::Frame<Bytes>, std::convert::Infallible>>,
);

impl hyper::body::Body for MpscFrameBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        self.0.poll_recv(cx)
    }
}

/// R3-MCP-1 & R2-MCP-4 regression tests:
/// - Large JSON integers > `u64::MAX` and high-precision decimals are forwarded verbatim (no rounding)
/// - Hanging SSE `tools/list` stream is bounded by `tools_list_timeout` (`504 Gateway Timeout`)
/// - `kid`-less JWT does NOT silently fall back to `static_jwt_key` when JWKS contains 2 keys
/// - OAuth RFC 9728 metadata derives `authorization_servers` from `jwks-url` when `jwt-issuer` is omitted
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn round3_mcp_precision_sse_timeout_kidless_jwks_and_metadata() -> TestResult {
    use base64::engine::general_purpose::{STANDARD as B64_STD, URL_SAFE_NO_PAD as B64_URL};
    use std::time::Duration;

    let seen_raw_body = Arc::new(std::sync::Mutex::new(String::new()));
    let seen_raw_srv = Arc::clone(&seen_raw_body);

    let up_listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = up_listener.local_addr()?;
    let up_task = tokio::spawn(async move {
        while let Ok((stream, _)) = up_listener.accept().await {
            let body_slot = Arc::clone(&seen_raw_srv);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let body_slot = Arc::clone(&body_slot);
                    async move {
                        let raw = req
                            .into_body()
                            .collect()
                            .await
                            .map(http_body_util::Collected::to_bytes)
                            .unwrap_or_default();
                        let text = String::from_utf8_lossy(&raw).into_owned();
                        if text.contains("\"tools/list\"") {
                            // Stream a partial SSE event and NEVER close the response body!
                            let (tx, rx) = tokio::sync::mpsc::channel::<
                                Result<hyper::body::Frame<Bytes>, std::convert::Infallible>,
                            >(2);
                            tokio::spawn(async move {
                                let _ = tx
                                    .send(Ok(hyper::body::Frame::data(Bytes::from_static(
                                        b"event: message\n",
                                    ))))
                                    .await;
                                std::future::pending::<()>().await;
                            });
                            let resp = Response::builder()
                                .status(StatusCode::OK)
                                .header(CONTENT_TYPE, "text/event-stream")
                                .body(MpscFrameBody(rx).boxed())
                                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()).boxed()));
                            return Ok::<_, hyper::Error>(resp);
                        }
                        if let Ok(mut guard) = body_slot.lock() {
                            *guard = text;
                        }
                        Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/json")
                            .body(
                                Full::new(Bytes::from_static(
                                    br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#,
                                ))
                                .boxed(),
                            )
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()).boxed())))
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let rng = aws_lc_rs::rand::SystemRandom::new();
    let kp1 = Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng)?.as_ref())?;
    let kp2 = Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng)?.as_ref())?;
    let kp_static = Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng)?.as_ref())?;
    let jwks_json = json!({
        "keys": [
            { "kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": B64_URL.encode(kp1.public_key().as_ref()) },
            { "kty": "OKP", "crv": "Ed25519", "kid": "k2", "x": B64_URL.encode(kp2.public_key().as_ref()) }
        ]
    })
    .to_string();

    let jwks_listener = TcpListener::bind("127.0.0.1:0").await?;
    let jwks_addr = jwks_listener.local_addr()?;
    let jwks_task = tokio::spawn(async move {
        while let Ok((stream, _)) = jwks_listener.accept().await {
            let payload = jwks_json.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |_req: Request<Incoming>| {
                    let payload = payload.clone();
                    async move {
                        Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header(CONTENT_TYPE, "application/json")
                                .body(Full::new(Bytes::from(payload)))
                                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                        )
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let sign_jwt = |kp: &Ed25519KeyPair, hdr: &Value, claims: &Value| -> String {
        let h_b64 = B64_URL.encode(hdr.to_string().as_bytes());
        let p_b64 = B64_URL.encode(claims.to_string().as_bytes());
        let signing_input = format!("{h_b64}.{p_b64}");
        let sig = kp.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", B64_URL.encode(sig.as_ref()))
    };

    let gateway = McpGateway::new(McpGatewayConfig {
        upstream: format!("http://{up_addr}"),
        allow_tools: vec!["calc_*".to_owned()],
        deny_tools: vec![],
        audit_log: AuditLogMode::Off,
        oauth_resource_metadata: true,
        max_json_depth: 16,
        max_request_bytes: ByteSize::from_bytes(64 * 1024),
        jwt_public_key: Some(B64_STD.encode(kp_static.public_key().as_ref())),
        jwks_url: Some(format!("http://{jwks_addr}/.well-known/jwks.json")),
        jwt_issuer: None,
        jwt_audience: None,
        required_scope: None,
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
    })?
    .with_tools_list_timeout(Duration::from_millis(150));

    // 1. R4-MCP-2: RFC 9728 metadata MUST NOT fabricate `authorization_servers` from `jwks-url`
    //    origin when `jwt-issuer` is unset!
    let meta_resp = gateway.oauth_protected_resource_metadata("https://mcp.example.com");
    let meta_json: Value =
        serde_json::from_slice(&meta_resp.into_body().collect().await?.to_bytes())?;
    assert!(
        meta_json.get("authorization_servers").is_none(),
        "authorization_servers must NOT be fabricated from jwks-url origin when jwt-issuer is None: {meta_json}"
    );

    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .saturating_add(300);

    // 2. R3-MCP-1: Valid JWT with `kid: "k1"` forwards huge integer > u64::MAX and long decimal VERBATIM!
    let jwt_k1 = sign_jwt(
        &kp1,
        &json!({ "alg": "EdDSA", "typ": "JWT", "kid": "k1" }),
        &json!({ "sub": "bot-1", "exp": exp }),
    );
    let huge_num_payload = br#"{"jsonrpc":"2.0","id":999999999999999999999999999999,"method":"tools/call","params":{"name":"calc_exact","arguments":{"precise":0.12345678901234567890123456789}}}"#;
    let prec_req = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, format!("Bearer {jwt_k1}"))
        .body(full_body(Bytes::from_static(huge_num_payload)))?;
    let (prec_resp, blocked) = gateway.handle_with_outcome(prec_req, None, "https").await;
    assert!(!blocked);
    assert_eq!(prec_resp.status(), StatusCode::OK);
    let forwarded = seen_raw_body.lock().map_err(|_| "mutex poisoned")?.clone();
    assert!(
        forwarded.contains("999999999999999999999999999999"),
        "integer > u64::MAX must NOT be rounded: {forwarded}"
    );
    assert!(
        forwarded.contains("0.12345678901234567890123456789"),
        "high-precision decimal must NOT be rounded: {forwarded}"
    );

    // 3. R3-MCP-1: `kid`-less JWT signed by `static_jwt_key` MUST BE REJECTED when JWKS is active
    //    (never silently switching keys based on JWKS size!).
    let kidless_static_jwt = sign_jwt(
        &kp_static,
        &json!({ "alg": "EdDSA", "typ": "JWT" }),
        &json!({ "sub": "rogue-static", "exp": exp }),
    );
    let kidless_req = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, format!("Bearer {kidless_static_jwt}"))
        .body(full_body(Bytes::from_static(
            br#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#,
        )))?;
    let (kidless_resp, blocked) = gateway
        .handle_with_outcome(kidless_req, None, "https")
        .await;
    assert!(blocked);
    assert_eq!(kidless_resp.status(), StatusCode::UNAUTHORIZED);

    // 4. R3-MCP-1: Hanging SSE `tools/list` stream MUST time out with 504 Gateway Timeout!
    let sse_hang_req = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, format!("Bearer {jwt_k1}"))
        .body(full_body(Bytes::from_static(
            br#"{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}"#,
        )))?;
    let (sse_timeout_resp, blocked) = tokio::time::timeout(
        Duration::from_secs(3),
        gateway.handle_with_outcome(sse_hang_req, None, "https"),
    )
    .await
    .map_err(|_| "SSE tools/list hung past tools_list_timeout")?;
    assert!(blocked);
    assert_eq!(sse_timeout_resp.status(), StatusCode::GATEWAY_TIMEOUT);

    up_task.abort();
    jwks_task.abort();
    Ok(())
}

/// R4-MCP-1 (canonical allow-listed JSON-RPC 2.0 envelope + case-folding duplicate rejection
/// including Go `strings.EqualFold` Unicode folds, while preserving arbitrary-precision numbers)
/// and R4-MCP-2 (explicit `jwt-issuer` required for `authorization_servers`).
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn round4_mcp_canonical_envelope_blocks_case_folding_and_smuggled_fields() -> TestResult {
    let seen_bodies: Arc<std::sync::Mutex<Vec<String>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen_clone = Arc::clone(&seen_bodies);

    let up_listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = up_listener.local_addr()?;
    let up_task = tokio::spawn(async move {
        while let Ok((stream, _)) = up_listener.accept().await {
            let seen = Arc::clone(&seen_clone);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let seen = Arc::clone(&seen);
                    async move {
                        let raw = req
                            .into_body()
                            .collect()
                            .await
                            .map(http_body_util::Collected::to_bytes)
                            .unwrap_or_default();
                        if let Ok(mut guard) = seen.lock() {
                            guard.push(String::from_utf8_lossy(&raw).into_owned());
                        }
                        Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header(CONTENT_TYPE, "application/json")
                                .body(Full::new(Bytes::from_static(
                                    br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#,
                                )))
                                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                        )
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let kp = Ed25519KeyPair::generate().map_err(|_| "ed25519 keygen failed")?;
    let gateway = McpGateway::new(McpGatewayConfig {
        upstream: format!("http://{up_addr}"),
        allow_tools: vec!["allowed_tool".to_owned()],
        deny_tools: vec!["dangerous".to_owned()],
        audit_log: AuditLogMode::Off,
        oauth_resource_metadata: true,
        max_json_depth: 16,
        max_request_bytes: ByteSize::from_bytes(64 * 1024),
        jwt_public_key: Some(
            base64::engine::general_purpose::STANDARD.encode(kp.public_key().as_ref()),
        ),
        jwks_url: None,
        jwt_issuer: Some("https://idp.example.com/oauth".to_owned()),
        jwt_audience: Some("https://mcp.example.com".to_owned()),
        required_scope: None,
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
    })?;

    // R4-MCP-2: Explicit `jwt_issuer` appears verbatim in RFC 9728 `authorization_servers`.
    let meta_resp = gateway.oauth_protected_resource_metadata("https://mcp.example.com");
    let meta_json: Value =
        serde_json::from_slice(&meta_resp.into_body().collect().await?.to_bytes())?;
    assert_eq!(
        meta_json.get("authorization_servers"),
        Some(&json!(["https://idp.example.com/oauth"]))
    );

    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .saturating_add(300);
    let jwt = miraserve_ai::sign_mcp_oauth_jwt(
        &kp,
        "mcp-client",
        exp,
        Some("https://idp.example.com/oauth"),
        Some("https://mcp.example.com"),
        None,
        None,
    );

    // R4-MCP-1 Attack payloads (Input A, Input B, Unicode Go EqualFold `ſ`, extra params key,
    // client response with both result & error) MUST ALL be rejected with 400 before upstream!
    let evil_payloads: &[(&str, &str)] = &[
        (
            "Input A: params + Params",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"allowed_tool"},"Params":{"name":"dangerous"}}"#,
        ),
        (
            "Input B: client response + Method",
            r#"{"id":1,"result":{},"Method":"tools/call","params":{"name":"dangerous"}}"#,
        ),
        (
            "Unicode EqualFold long-s param\u{017F}",
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"allowed_tool\"},\"param\u{017F}\":{\"name\":\"dangerous\"}}",
        ),
        (
            "Case-colliding Name in tools/call params",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"allowed_tool","Name":"dangerous"}}"#,
        ),
        (
            "Unexpected top-level field in request",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"allowed_tool"},"extra":"smuggled"}"#,
        ),
        (
            "Unexpected field in tools/call params",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"allowed_tool","injected":true}}"#,
        ),
        (
            "Client response with both result and error",
            r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-1,"message":"x"}}"#,
        ),
    ];

    for (label, payload) in evil_payloads {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {jwt}"))
            .body(full_body(Bytes::copy_from_slice(payload.as_bytes())))?;
        let (resp, blocked) = gateway.handle_with_outcome(req, None, "https").await;
        assert!(blocked, "{label}: must be marked blocked by gateway");
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "{label}: expected 400 Bad Request, got {}",
            resp.status()
        );
    }
    assert!(
        seen_bodies.lock().map_err(|_| "mutex poisoned")?.is_empty(),
        "upstream must NEVER receive any smuggled/case-colliding payload"
    );

    // Valid tools/call with `_meta` + arbitrary-precision numbers forwards canonical JSON cleanly!
    let valid_payload = r#"{"jsonrpc":"2.0","id":18014398509481983,"method":"tools/call","params":{"name":"allowed_tool","arguments":{"huge":99999999999999999999999999999,"tiny":1e-50},"_meta":{"progressToken":"p1"}}}"#;
    let ok_req = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, format!("Bearer {jwt}"))
        .body(full_body(Bytes::copy_from_slice(valid_payload.as_bytes())))?;
    let (ok_resp, blocked) = gateway.handle_with_outcome(ok_req, None, "https").await;
    assert!(!blocked);
    assert_eq!(ok_resp.status(), StatusCode::OK);
    let forwarded = seen_bodies
        .lock()
        .map_err(|_| "mutex poisoned")?
        .first()
        .cloned()
        .ok_or("expected upstream to receive canonical request")?;
    assert!(forwarded.contains("18014398509481983"), "got: {forwarded}");
    assert!(
        forwarded.contains("99999999999999999999999999999"),
        "got: {forwarded}"
    );
    assert!(forwarded.contains("1e-50"), "got: {forwarded}");
    assert!(forwarded.contains("progressToken"), "got: {forwarded}");

    up_task.abort();
    Ok(())
}

/// Round 5 Wave 2 MCP gateway regressions (`R5-MCP-1..6`):
/// - `R5-MCP-1`: Rejects `Content-Type: application/json; charset=utf-7` with 415 and always
///   forwards canonical `Content-Type: application/json` upstream.
/// - `R5-MCP-2`: Enforces explicit MCP method allow-list (`admin/exec`, `Tools/Call` -> 403) and
///   case-insensitive tool matching (`DELETE_all` matched by `deny-tools "delete_*"` -> 403).
/// - `R5-MCP-3`: Allows distinct-case keys inside nested tool arguments (`{"headers":{"Accept":"a","accept":"b"}}`)
///   while still rejecting case-colliding keys on the JSON-RPC envelope and `params`.
/// - `R5-MCP-4`: Rejects client objects keyed `$serde_json::private::Number` (literal & `\u0024` escaped).
/// - `R5-MCP-5`: Filters `tools/list` results on GET SSE stream resumption AND SSE with bare `\r` endings.
/// - `R5-MCP-6`: Permits MCP 2025-11-25 `params.task` in `tools/call`.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn round5_mcp_charset_bypass_method_allowlist_case_fold_sentinel_and_get_sse() -> TestResult {
    let seen_ct: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen_bodies: Arc<std::sync::Mutex<Vec<String>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen_ct_srv = Arc::clone(&seen_ct);
    let seen_bodies_srv = Arc::clone(&seen_bodies);

    let up_listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = up_listener.local_addr()?;
    let up_task = tokio::spawn(async move {
        while let Ok((stream, _)) = up_listener.accept().await {
            let ct_log = Arc::clone(&seen_ct_srv);
            let body_log = Arc::clone(&seen_bodies_srv);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let ct_log = Arc::clone(&ct_log);
                    let body_log = Arc::clone(&body_log);
                    async move {
                        let method = req.method().clone();
                        let ct = req
                            .headers()
                            .get(CONTENT_TYPE)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_owned();
                        let raw = req
                            .into_body()
                            .collect()
                            .await
                            .map(http_body_util::Collected::to_bytes)
                            .unwrap_or_default();
                        if method == Method::GET {
                            let sse = "event: message\rdata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"allowed_tool\"},{\"name\":\"DELETE_all\"}]}}\r\r";
                            return Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header(CONTENT_TYPE, "text/event-stream")
                                    .body(Full::new(Bytes::from_static(sse.as_bytes())))
                                    .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                            );
                        }
                        if let Ok(mut g) = ct_log.lock() {
                            g.push(ct);
                        }
                        let body_text = String::from_utf8_lossy(&raw).into_owned();
                        if let Ok(mut g) = body_log.lock() {
                            g.push(body_text.clone());
                        }
                        if body_text.contains("\"tools/list\"") {
                            let sse = "data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"allowed_tool\"},{\"name\":\"delete_users\"}]}}\r\r";
                            return Ok(Response::builder()
                                .status(StatusCode::OK)
                                .header(CONTENT_TYPE, "text/event-stream")
                                .body(Full::new(Bytes::from_static(sse.as_bytes())))
                                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))));
                        }
                        Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/json")
                            .body(Full::new(Bytes::from_static(
                                br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#,
                            )))
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))))
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let kp = Ed25519KeyPair::generate().map_err(|_| "ed25519 keygen failed")?;
    let pub_b64 = base64::engine::general_purpose::STANDARD.encode(kp.public_key().as_ref());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let jwt = miraserve_ai::sign_mcp_oauth_jwt(
        &kp,
        "agent",
        now + 300,
        Some("https://idp.example.test"),
        Some("https://mcp.example.test"),
        None,
        None,
    );

    let cfg = McpGatewayConfig {
        upstream: format!("http://{up_addr}"),
        oauth_resource_metadata: true,
        jwt_public_key: Some(format!("miraserve-ed25519-pub:{pub_b64}")),
        jwks_url: None,
        jwt_issuer: Some("https://idp.example.test".to_owned()),
        jwt_audience: Some("https://mcp.example.test".to_owned()),
        required_scope: None,
        allow_tools: vec!["allowed_*".to_owned(), "delete_*".to_owned()],
        deny_tools: vec!["delete_*".to_owned()],
        audit_log: AuditLogMode::Off,
        max_json_depth: 16,
        max_request_bytes: ByteSize::from_bytes(1024 * 1024),
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
    };
    let gateway = McpGateway::new(cfg)?;

    let utf7_payload = r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"+ACIAfQAsACIAbQBlAHQAaABvAGQAIgA6ACIAdABvAG8AbABzAC8AYwBhAGwAbAAiACwAIgBwAGEAcgBhAG0AcwAiADoAewAiAG4AYQBtAGUAIgA6ACIAZABhAG4AZwBlAHIAbwB1AHMAIgAsACIAcQAiADoAIg-"}}"#;
    let utf7_req = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header(CONTENT_TYPE, "application/json; charset=utf-7")
        .header(AUTHORIZATION, format!("Bearer {jwt}"))
        .body(full_body(Bytes::from(utf7_payload)))?;
    let (utf7_resp, blocked) = gateway.handle_with_outcome(utf7_req, None, "https").await;
    assert!(blocked);
    assert_eq!(utf7_resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    for bad_method_or_tool in [
        r#"{"jsonrpc":"2.0","id":1,"method":"admin/exec","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"Tools/Call","params":{"name":"allowed_tool"}}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"DELETE_all"}}"#,
    ] {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {jwt}"))
            .body(full_body(Bytes::from(bad_method_or_tool)))?;
        let (resp, blocked) = gateway.handle_with_outcome(req, None, "https").await;
        assert!(blocked, "expected deny for {bad_method_or_tool}");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    for sentinel_payload in [
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"allowed_tool","arguments":{"v":{"$serde_json::private::Number":"42"}}}}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"allowed_tool","arguments":{"v":{"\u0024serde_json::private::Number":"42"}}}}"#,
    ] {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {jwt}"))
            .body(full_body(Bytes::from(sentinel_payload)))?;
        let (resp, blocked) = gateway.handle_with_outcome(req, None, "https").await;
        assert!(blocked, "expected reject for sentinel {sentinel_payload}");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    assert!(seen_bodies.lock().map_err(|_| "poison")?.is_empty());

    let rich_valid = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"allowed_tool","arguments":{"headers":{"Accept":"text/plain","accept":"application/json"}},"task":{"ttl":60000}}}"#;
    let ok_req = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header(CONTENT_TYPE, "application/json; charset=UTF-8")
        .header(AUTHORIZATION, format!("Bearer {jwt}"))
        .body(full_body(Bytes::from(rich_valid)))?;
    let (ok_resp, blocked) = gateway.handle_with_outcome(ok_req, None, "https").await;
    assert!(!blocked);
    assert_eq!(ok_resp.status(), StatusCode::OK);
    assert_eq!(
        seen_ct
            .lock()
            .map_err(|_| "poison")?
            .first()
            .map(String::as_str),
        Some("application/json"),
    );
    let fwd_body = seen_bodies
        .lock()
        .map_err(|_| "poison")?
        .first()
        .cloned()
        .ok_or("expected forwarded body")?;
    assert!(fwd_body.contains("\"task\""), "got: {fwd_body}");
    assert!(fwd_body.contains("\"Accept\"") && fwd_body.contains("\"accept\""));

    let get_sse_req = Request::builder()
        .method(Method::GET)
        .uri("/mcp")
        .header(AUTHORIZATION, format!("Bearer {jwt}"))
        .body(full_body(Bytes::new()))?;
    let (get_resp, blocked) = gateway
        .handle_with_outcome(get_sse_req, None, "https")
        .await;
    assert!(!blocked);
    assert_eq!(get_resp.status(), StatusCode::OK);
    let get_bytes = get_resp.into_body().collect().await?.to_bytes();
    let get_text = String::from_utf8_lossy(&get_bytes);
    assert!(get_text.contains("allowed_tool"), "got: {get_text}");
    assert!(!get_text.contains("DELETE_all"), "got: {get_text}");

    let post_sse_req = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, format!("Bearer {jwt}"))
        .body(full_body(Bytes::from_static(
            br#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        )))?;
    let (post_resp, blocked) = gateway
        .handle_with_outcome(post_sse_req, None, "https")
        .await;
    assert!(!blocked);
    assert_eq!(post_resp.status(), StatusCode::OK);
    let post_bytes = post_resp.into_body().collect().await?.to_bytes();
    let post_text = String::from_utf8_lossy(&post_bytes);
    assert!(post_text.contains("allowed_tool"), "got: {post_text}");
    assert!(!post_text.contains("delete_users"), "got: {post_text}");

    up_task.abort();
    Ok(())
}

/// R6-MCP-1: `allow-tools` matches case-sensitively (`read_file` does NOT widen to `READ_FILE`),
/// `deny-tools` matches case-insensitively (`kill_*` blocks `KILL_POD`), and non-ASCII tool names
/// (e.g. Kelvin sign U+212A) are always denied.
#[test]
fn r6_mcp_1_allow_tools_is_case_sensitive_deny_is_case_insensitive_and_blocks_non_ascii()
-> TestResult {
    let gw = McpGateway::new(McpGatewayConfig {
        upstream: "http://127.0.0.1:1".to_owned(),
        oauth_resource_metadata: false,
        jwt_public_key: None,
        jwks_url: None,
        jwt_issuer: None,
        jwt_audience: None,
        required_scope: None,
        allow_tools: vec!["read_file".to_owned(), "*_pod".to_owned()],
        deny_tools: vec!["kill_*".to_owned()],
        audit_log: AuditLogMode::Off,
        max_json_depth: 16,
        max_request_bytes: ByteSize::from_bytes(64 * 1024),
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
    })?;

    assert_eq!(
        gw.check_tool_allowed("read_file"),
        miraserve_ai::ToolRbacDecision::Allow
    );
    assert!(matches!(
        gw.check_tool_allowed("READ_FILE"),
        miraserve_ai::ToolRbacDecision::Deny { .. }
    ));
    assert!(matches!(
        gw.check_tool_allowed("Read_File"),
        miraserve_ai::ToolRbacDecision::Deny { .. }
    ));
    // Deny stays case-insensitive
    assert!(matches!(
        gw.check_tool_allowed("kill_pod"),
        miraserve_ai::ToolRbacDecision::Deny { .. }
    ));
    assert!(matches!(
        gw.check_tool_allowed("KILL_pod"),
        miraserve_ai::ToolRbacDecision::Deny { .. }
    ));
    // Non-ASCII tool names (Kelvin sign U+212A + accented chars) are denied!
    assert!(matches!(
        gw.check_tool_allowed("\u{212A}ill_pod"),
        miraserve_ai::ToolRbacDecision::Deny { .. }
    ));
    assert!(matches!(
        gw.check_tool_allowed("r\u{00E9}ad_file"),
        miraserve_ai::ToolRbacDecision::Deny { .. }
    ));

    // Also verify `filter_tools_list_response` applies exact same rules.
    let mut payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": [
                {"name": "read_file"},
                {"name": "READ_FILE"},
                {"name": "KILL_pod"},
                {"name": "\u{212A}ill_pod"}
            ]
        }
    });
    filter_tools_list_response(&gw, &mut payload);
    let names: Vec<&str> = payload
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(Value::as_array)
        .ok_or("missing tools")?
        .iter()
        .filter_map(|t| t.get("name").and_then(Value::as_str))
        .collect();
    assert_eq!(names, vec!["read_file"]);
    Ok(())
}

/// R6-MCP-2: Leading UTF-8 BOM (`\u{FEFF}`) on POST `tools/list` SSE and streaming GET SSE
/// (including split across initial chunks) is stripped so denied tools cannot bypass filtering.
#[tokio::test]
async fn r6_mcp_2_sse_filter_strips_leading_utf8_bom_on_post_and_get_streams() -> TestResult {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = listener.local_addr()?;

    let up_task = tokio::spawn(async move {
        for _ in 0..2_u8 {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let mut req_buf = [0_u8; 4096];
            let n = sock.read(&mut req_buf).await.unwrap_or(0);
            let req_head = String::from_utf8_lossy(req_buf.get(..n).unwrap_or(&[]));
            let event = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"read_file\"},{\"name\":\"secret_exec\"}]}}\n\n";
            if req_head.starts_with("GET ") {
                // Split the 3-byte UTF-8 BOM across two chunked HTTP writes!
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
                    .await;
                let _ = sock.write_all(b"2\r\n\xEF\xBB\r\n").await;
                let _ = sock.flush().await;
                let rest = format!("\u{0000}{event}");
                let mut rest_bytes = Vec::with_capacity(1 + event.len());
                rest_bytes.push(0xBF);
                rest_bytes.extend_from_slice(event.as_bytes());
                let _ = rest;
                let chunk_hdr = format!("{:x}\r\n", rest_bytes.len());
                let _ = sock.write_all(chunk_hdr.as_bytes()).await;
                let _ = sock.write_all(&rest_bytes).await;
                let _ = sock.write_all(b"\r\n0\r\n\r\n").await;
            } else {
                let mut body = Vec::new();
                body.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
                body.extend_from_slice(event.as_bytes());
                let hdr = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(hdr.as_bytes()).await;
                let _ = sock.write_all(&body).await;
            }
            let _ = sock.shutdown().await;
        }
    });

    let gw = McpGateway::new(McpGatewayConfig {
        upstream: format!("http://{up_addr}"),
        oauth_resource_metadata: false,
        jwt_public_key: None,
        jwks_url: None,
        jwt_issuer: None,
        jwt_audience: None,
        required_scope: None,
        allow_tools: vec!["read_file".to_owned()],
        deny_tools: vec!["secret_*".to_owned()],
        audit_log: AuditLogMode::Off,
        max_json_depth: 16,
        max_request_bytes: ByteSize::from_bytes(64 * 1024),
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
    })?;

    // 1. GET SSE with split BOM
    let get_req = Request::builder()
        .method(Method::GET)
        .uri("/mcp")
        .header(ACCEPT, "text/event-stream")
        .body(full_body(Bytes::new()))?;
    let (get_resp, blocked) = gw.handle_with_outcome(get_req, None, "https").await;
    assert!(!blocked);
    assert_eq!(get_resp.status(), StatusCode::OK);
    let get_text = String::from_utf8(get_resp.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(get_text.contains("read_file"), "got: {get_text}");
    assert!(
        !get_text.contains("secret_exec"),
        "R6-MCP-2: split BOM must NOT bypass GET SSE filter: {get_text}"
    );

    // 2. POST tools/list SSE with BOM
    let post_req = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header(CONTENT_TYPE, "application/json")
        .body(full_body(Bytes::from_static(
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
        )))?;
    let (post_resp, blocked) = gw.handle_with_outcome(post_req, None, "https").await;
    assert!(!blocked);
    assert_eq!(post_resp.status(), StatusCode::OK);
    let post_text = String::from_utf8(post_resp.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(post_text.contains("read_file"), "got: {post_text}");
    assert!(
        !post_text.contains("secret_exec"),
        "R6-MCP-2: leading BOM must NOT bypass POST SSE filter: {post_text}"
    );

    up_task.abort();
    Ok(())
}

/// R6-MCP-3: A GET SSE event terminated by bare `\r\r` is filtered and emitted immediately without
/// stalling waiting for more bytes, and a split `\r\n\r` + `\n` boundary does not corrupt the next event.
#[tokio::test]
async fn r6_mcp_3_get_sse_emits_bare_cr_cr_events_immediately_without_stalling() -> TestResult {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = listener.local_addr()?;
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();

    let up_task = tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        let mut req_buf = [0_u8; 2048];
        let _ = sock.read(&mut req_buf).await;
        let _ = sock
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
            .await;
        let ev1 = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"read_file\"},{\"name\":\"bad_tool\"}]}}\r\r";
        let _ = sock
            .write_all(format!("{:x}\r\n{ev1}\r\n", ev1.len()).as_bytes())
            .await;
        let _ = sock.flush().await;
        // Hold stream open until client proves it ALREADY received event 1!
        let _ = release_rx.await;
        let ev2 = "data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"read_file\"}]}}\r\n\r\n";
        let _ = sock
            .write_all(format!("{:x}\r\n{ev2}\r\n0\r\n\r\n", ev2.len()).as_bytes())
            .await;
        let _ = sock.shutdown().await;
    });

    let gw = McpGateway::new(McpGatewayConfig {
        upstream: format!("http://{up_addr}"),
        oauth_resource_metadata: false,
        jwt_public_key: None,
        jwks_url: None,
        jwt_issuer: None,
        jwt_audience: None,
        required_scope: None,
        allow_tools: vec!["read_file".to_owned()],
        deny_tools: vec!["bad_*".to_owned()],
        audit_log: AuditLogMode::Off,
        max_json_depth: 16,
        max_request_bytes: ByteSize::from_bytes(64 * 1024),
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
    })?;

    let req = Request::builder()
        .method(Method::GET)
        .uri("/mcp")
        .header(ACCEPT, "text/event-stream")
        .body(full_body(Bytes::new()))?;
    let (resp, blocked) = gw.handle_with_outcome(req, None, "https").await;
    assert!(!blocked);
    assert_eq!(resp.status(), StatusCode::OK);

    let mut body = resp.into_body();
    let frame1 = tokio::time::timeout(std::time::Duration::from_millis(500), body.frame())
        .await
        .map_err(|_| "R6-MCP-3: bare \\r\\r SSE event stalled instead of emitting immediately")?
        .ok_or("unexpected EOF")??;
    let text1 = String::from_utf8(frame1.into_data().map_err(|_| "non-data")?.to_vec())?;
    assert!(text1.contains("read_file"), "got: {text1}");
    assert!(!text1.contains("bad_tool"), "got: {text1}");

    let _ = release_tx.send(());
    let tail_bytes = body.collect().await?.to_bytes();
    let text2 = String::from_utf8(tail_bytes.to_vec())?;
    assert!(text2.contains("read_file"), "got: {text2}");
    up_task.abort();
    Ok(())
}

/// R6-MCP-4 & R5-MCP-5: `notifications/tasks/status` (MCP 2025-11-25) is permitted, AND a GET SSE
/// stream with empty `allow-tools` & `deny-tools` (default-deny) still filters all tools out.
#[tokio::test]
async fn r6_mcp_4_allows_notifications_tasks_status_and_r5_mcp_5_filters_empty_allow_get_sse()
-> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = listener.local_addr()?;

    let up_task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                let svc = service_fn(|req: Request<Incoming>| async move {
                    if req.method() == Method::GET {
                        let sse = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"hidden_tool\"}]}}\n\n";
                        return Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header(CONTENT_TYPE, "text/event-stream")
                                .body(Full::new(Bytes::from(sse)))
                                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                        );
                    }
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(StatusCode::ACCEPTED)
                            .body(Full::new(Bytes::new()))
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                    )
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    // Empty allow-tools + empty deny-tools = default-deny!
    let gw = McpGateway::new(McpGatewayConfig {
        upstream: format!("http://{up_addr}"),
        oauth_resource_metadata: false,
        jwt_public_key: None,
        jwks_url: None,
        jwt_issuer: None,
        jwt_audience: None,
        required_scope: None,
        allow_tools: Vec::new(),
        deny_tools: Vec::new(),
        audit_log: AuditLogMode::Off,
        max_json_depth: 16,
        max_request_bytes: ByteSize::from_bytes(64 * 1024),
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
    })?;

    // 1. R6-MCP-4: `notifications/tasks/status` is allowed (not 403)!
    let notif_req = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header(CONTENT_TYPE, "application/json")
        .body(full_body(Bytes::from_static(
            br#"{"jsonrpc":"2.0","method":"notifications/tasks/status","params":{"taskId":"t1","status":"working"}}"#,
        )))?;
    let (notif_resp, blocked) = gw.handle_with_outcome(notif_req, None, "https").await;
    assert!(
        !blocked && notif_resp.status() == StatusCode::ACCEPTED,
        "R6-MCP-4: notifications/tasks/status must be permitted, got status={} blocked={blocked}",
        notif_resp.status()
    );

    // 2. R5-MCP-5: GET SSE with empty allow/deny MUST still filter out `hidden_tool`!
    let get_req = Request::builder()
        .method(Method::GET)
        .uri("/mcp")
        .header(ACCEPT, "text/event-stream")
        .body(full_body(Bytes::new()))?;
    let (get_resp, blocked) = gw.handle_with_outcome(get_req, None, "https").await;
    assert!(!blocked);
    assert_eq!(get_resp.status(), StatusCode::OK);
    let get_text = String::from_utf8(get_resp.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(
        !get_text.contains("hidden_tool"),
        "R5-MCP-5: default-deny GET SSE must filter all tools out, got: {get_text}"
    );

    up_task.abort();
    Ok(())
}

/// R7-MCP-1, R7-MCP-2 & R7-MCP-3:
/// - R7-MCP-1: `tools/list` filters across ALL 2xx statuses (e.g. `201 Created`) with exact media
///   type essence (ignoring `; charset=utf-8` params) and rejects JSON array roots (`502`).
/// - R7-MCP-2: Tool names must match `[A-Za-z0-9_./:-]`; `"exec "` and `"exec\u{0000}"` are denied
///   even with `allow-tools "*"` and `deny-tools "exec"`.
/// - R7-MCP-3: GET SSE strips UTF-8 BOM ONLY at stream start (not per-event) and passes benign
///   non-JSON `data: ping` keep-alive frames without killing the stream.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn r7_mcp_1_2_3_status_2xx_array_root_tool_name_charset_and_get_sse_keepalive_bom()
-> TestResult {
    let up_listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = up_listener.local_addr()?;

    let up_task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = up_listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let method = req.method().clone();
                    let path = req.uri().path().to_owned();
                    let _ = req.into_body().collect().await;

                    // R7-MCP-1: 201 Created JSON response with `; charset=utf-8`
                    if method == Method::POST && path == "/mcp-201" {
                        let body = json!({
                            "jsonrpc": "2.0",
                            "id": 1,
                            "result": {
                                "tools": [
                                    { "name": "read_file" },
                                    { "name": "exec" }
                                ]
                            }
                        });
                        return Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(StatusCode::CREATED)
                                .header(CONTENT_TYPE, "application/json; charset=utf-8")
                                .body(Full::new(Bytes::from(
                                    serde_json::to_vec(&body).unwrap_or_default(),
                                )))
                                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                        );
                    }

                    // R7-MCP-1: JSON array root response on tools/list -> must be rejected 502!
                    if method == Method::POST && path == "/mcp-array" {
                        let body = json!([{
                            "jsonrpc": "2.0",
                            "id": 1,
                            "result": {
                                "tools": [{ "name": "exec" }]
                            }
                        }]);
                        return Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header(CONTENT_TYPE, "application/json")
                                .body(Full::new(Bytes::from(
                                    serde_json::to_vec(&body).unwrap_or_default(),
                                )))
                                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                        );
                    }

                    // R7-MCP-3: GET SSE stream with leading BOM, non-JSON `data: ping` keep-alive,
                    // then a JSON `tools/list` event containing both allowed and denied tools!
                    if method == Method::GET && path == "/mcp-keepalive" {
                        let mut payload = Vec::new();
                        payload.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
                        payload.extend_from_slice(
                            b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"read_file\"},{\"name\":\"exec\"}]}}\n\n",
                        );
                        payload.extend_from_slice(b"data: ping\n\n");
                        payload.extend_from_slice(
                            b"data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"safe_tool\"},{\"name\":\"exec\"}]}}\n\n",
                        );
                        return Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header(CONTENT_TYPE, " text/event-stream ; charset=utf-8")
                                .body(Full::new(Bytes::from(payload)))
                                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                        );
                    }

                    // Default tools/call success
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/json")
                            .body(Full::new(Bytes::from_static(
                                br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#,
                            )))
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                    )
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    let gw = McpGateway::new(McpGatewayConfig {
        upstream: format!("http://{up_addr}"),
        oauth_resource_metadata: false,
        jwt_public_key: None,
        jwks_url: None,
        jwt_issuer: None,
        jwt_audience: None,
        required_scope: None,
        allow_tools: vec!["*".to_owned()],
        deny_tools: vec!["exec".to_owned()],
        audit_log: AuditLogMode::Off,
        max_json_depth: 16,
        max_request_bytes: ByteSize::from_bytes(64 * 1024),
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
    })?;

    // 1. R7-MCP-1: 201 Created `tools/list` MUST be filtered!
    let list_201 = Request::builder()
        .method(Method::POST)
        .uri("/mcp-201")
        .header(CONTENT_TYPE, "application/json")
        .body(full_body(Bytes::from_static(
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
        )))?;
    let (resp_201, blocked_201) = gw.handle_with_outcome(list_201, None, "https").await;
    assert!(!blocked_201);
    assert_eq!(resp_201.status(), StatusCode::CREATED);
    let body_201 = String::from_utf8(resp_201.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(
        body_201.contains("read_file") && !body_201.contains("\"exec\""),
        "R7-MCP-1: 201 Created tools/list must filter denied tools, got: {body_201}"
    );

    // 2. R7-MCP-1: JSON array root on `tools/list` MUST be rejected fail-closed (502)!
    let list_arr = Request::builder()
        .method(Method::POST)
        .uri("/mcp-array")
        .header(CONTENT_TYPE, "application/json")
        .body(full_body(Bytes::from_static(
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
        )))?;
    let (resp_arr, blocked_arr) = gw.handle_with_outcome(list_arr, None, "https").await;
    assert!(
        blocked_arr && resp_arr.status() == StatusCode::BAD_GATEWAY,
        "R7-MCP-1: JSON array root on tools/list must fail closed with 502, got status={} blocked={blocked_arr}",
        resp_arr.status()
    );

    // 3. R7-MCP-2: `"exec "`, `"exec\u{0000}"`, `"exec\n"` MUST be denied even with allow "*" & deny "exec"!
    for bad_tool in ["exec ", "exec\u{0000}", "exec\n", "bad tool", "bad*name"] {
        let payload = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": { "name": bad_tool, "arguments": {} }
        }))?;
        let call_req = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header(CONTENT_TYPE, "application/json")
            .body(full_body(Bytes::from(payload)))?;
        let (call_resp, blocked) = gw.handle_with_outcome(call_req, None, "https").await;
        assert!(
            blocked && call_resp.status() == StatusCode::FORBIDDEN,
            "R7-MCP-2: malformed tool name {:?} must be denied 403, got status={} blocked={blocked}",
            bad_tool,
            call_resp.status()
        );
    }
    // Valid safe charset tool name succeeds!
    let ok_payload = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": { "name": "ns.v1:read/file-ok_2", "arguments": {} }
    }))?;
    let ok_req = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header(CONTENT_TYPE, "application/json")
        .body(full_body(Bytes::from(ok_payload)))?;
    let (ok_resp, ok_blocked) = gw.handle_with_outcome(ok_req, None, "https").await;
    assert!(!ok_blocked && ok_resp.status() == StatusCode::OK);

    // 4. R7-MCP-3: GET SSE stream with leading BOM + `data: ping` keep-alive + second JSON event
    //    must strip BOM on event 1, keep `data: ping` alive, and filter both JSON events!
    let get_req = Request::builder()
        .method(Method::GET)
        .uri("/mcp-keepalive")
        .header(ACCEPT, "text/event-stream")
        .body(full_body(Bytes::new()))?;
    let (get_resp, get_blocked) = gw.handle_with_outcome(get_req, None, "https").await;
    assert!(!get_blocked && get_resp.status() == StatusCode::OK);
    let get_text = String::from_utf8(get_resp.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(
        get_text.contains("read_file")
            && get_text.contains("data: ping")
            && get_text.contains("safe_tool")
            && !get_text.contains("\"exec\""),
        "R7-MCP-3: GET SSE must strip leading BOM, preserve `data: ping`, and filter denied tools, got: {get_text}"
    );

    up_task.abort();
    Ok(())
}

/// Pins P2-c: RFC 9421 `@scheme` always binds to the connection's scheme, including when the
/// client sends an absolute-form request target carrying a different scheme.
#[allow(clippy::too_many_lines)]
#[test]
fn bot_auth_scheme_uses_connection_scheme_even_for_absolute_form_targets() -> TestResult {
    let key_pair = Ed25519KeyPair::generate().map_err(|_| "ed25519 keygen failed")?;
    let mut pub_bytes = [0_u8; 32];
    pub_bytes.copy_from_slice(
        key_pair
            .public_key()
            .as_ref()
            .get(..32)
            .ok_or("bad pubkey len")?,
    );

    let registry = Arc::new(AgentKeyRegistry::new());
    registry.register(
        "scheme-key-1",
        RegisteredAgent {
            agent_id: "scheme-bot".to_owned(),
            group: "verified-ai-agents".to_owned(),
            public_key: pub_bytes,
        },
    );
    let guard = BotAuthGuard::new(
        BotAuthConfig {
            verify_rfc9421: true,
            allow_agents: vec![AllowedAgentConfig {
                name: "verified-ai-agents".to_owned(),
                serve_markdown: false,
            }],
            on_unverified_ai_ua: UnverifiedBotAction::Block,
            ..BotAuthConfig::default()
        },
        Arc::clone(&registry),
    );

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let sign_with_scheme = |signed_scheme: &str| -> Result<HeaderMap, Box<dyn std::error::Error>> {
        let params = format!(
            "(\"@method\" \"@scheme\" \"@authority\" \"@path\");created={now};expires={};keyid=\"scheme-key-1\";alg=\"ed25519\";tag=\"web-bot-auth\"",
            now.saturating_add(300)
        );
        let base = format!(
            "\"@method\": GET\n\"@scheme\": {signed_scheme}\n\"@authority\": bot.example.test\n\"@path\": /docs\n\"@signature-params\": {params}"
        );
        let sig_b64 = base64::engine::general_purpose::STANDARD
            .encode(key_pair.sign(base.as_bytes()).as_ref());
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("bot.example.test"));
        headers.insert(USER_AGENT, HeaderValue::from_static("GPTBot/1.0"));
        headers.insert(
            "signature-input",
            HeaderValue::from_str(&format!("sig1={params}"))?,
        );
        headers.insert(
            "signature",
            HeaderValue::from_str(&format!("sig1=:{sig_b64}:"))?,
        );
        Ok(headers)
    };

    // Absolute-form `https://` target arriving over a plain `"http"` connection:
    // signature covering `@scheme = "https"` MUST fail; `@scheme = "http"` MUST verify.
    let abs_https_uri: Uri = "https://bot.example.test/docs".parse()?;
    let hdrs_signed_https = sign_with_scheme("https")?;
    let hdrs_signed_http = sign_with_scheme("http")?;

    assert!(
        !matches!(
            guard.evaluate_with_scheme(
                &Method::GET,
                &abs_https_uri,
                &hdrs_signed_https,
                None,
                "http"
            ),
            BotAuthOutcome::Verified { .. }
        ),
        "plain-HTTP connection must not verify an @scheme=\"https\" signature even for absolute-form https:// URI"
    );
    assert!(
        matches!(
            guard.evaluate_with_scheme(
                &Method::GET,
                &abs_https_uri,
                &hdrs_signed_http,
                None,
                "http"
            ),
            BotAuthOutcome::Verified { .. }
        ),
        "plain-HTTP connection must bind @scheme to \"http\" even for absolute-form https:// URI"
    );

    // HTTPS control: preserve exact v0.1.2 `@scheme` selection (`uri.scheme_str().unwrap_or("https")`)
    // so existing TLS sites see zero behavior change for both absolute-form and origin-form targets.
    let plain_target_uri: Uri = "http://bot.example.test/docs".parse()?;
    assert!(
        matches!(
            guard.evaluate_with_scheme(
                &Method::GET,
                &plain_target_uri,
                &hdrs_signed_http,
                None,
                "https"
            ),
            BotAuthOutcome::Verified { .. }
        ),
        "HTTPS connection must preserve v0.1.2 @scheme selection for absolute-form http:// URI"
    );
    assert!(
        !matches!(
            guard.evaluate_with_scheme(
                &Method::GET,
                &plain_target_uri,
                &hdrs_signed_https,
                None,
                "https"
            ),
            BotAuthOutcome::Verified { .. }
        ),
        "HTTPS connection must preserve v0.1.2 @scheme selection (not overriding absolute-form http://)"
    );
    let origin_form_uri: Uri = "/docs".parse()?;
    assert!(
        matches!(
            guard.evaluate_with_scheme(
                &Method::GET,
                &origin_form_uri,
                &hdrs_signed_https,
                None,
                "https"
            ),
            BotAuthOutcome::Verified { .. }
        ),
        "HTTPS connection with origin-form target must still resolve @scheme to \"https\""
    );

    Ok(())
}

/// Pins P2-b at the `McpGateway` unit level: OAuth/JWT bearer verification refuses plain HTTP
/// with `403` (no `WWW-Authenticate` Bearer challenge, no token evaluation) unless explicitly
/// opted in via `allow_plaintext_credentials = true`.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn mcp_gateway_refuses_oauth_jwt_over_plain_http_unless_opted_in() -> TestResult {
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let hits_up = Arc::clone(&hits);
    let up_listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = up_listener.local_addr()?;
    let up_task = tokio::spawn(async move {
        while let Ok((stream, _)) = up_listener.accept().await {
            let hits_c = Arc::clone(&hits_up);
            tokio::spawn(async move {
                let svc = service_fn(move |_req: Request<Incoming>| {
                    let hits_r = Arc::clone(&hits_c);
                    async move {
                        hits_r.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                        let resp = Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/json")
                            .body(Full::new(Bytes::from_static(
                                br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#,
                            )))
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())));
                        Ok::<_, std::convert::Infallible>(resp)
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let oauth_kp = Ed25519KeyPair::generate().map_err(|_| "ed25519 keygen failed")?;
    let oauth_pub = format!(
        "miraserve-ed25519-pub:{}",
        base64::engine::general_purpose::STANDARD.encode(oauth_kp.public_key().as_ref())
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let valid_jwt = format!(
        "Bearer {}",
        miraserve_ai::sign_mcp_oauth_jwt(
            &oauth_kp,
            "agent-plain",
            now.saturating_add(300),
            Some("https://auth.example.test"),
            Some("http://panel.example:8080"),
            Some("mcp:tools"),
            None,
        )
    );
    let gateway = McpGateway::new(McpGatewayConfig {
        upstream: format!("http://{up_addr}"),
        oauth_resource_metadata: true,
        jwt_public_key: Some(oauth_pub),
        jwks_url: None,
        jwt_issuer: Some("https://auth.example.test".to_owned()),
        jwt_audience: Some("http://panel.example:8080".to_owned()),
        required_scope: Some("mcp:tools".to_owned()),
        allow_tools: vec!["docs_search".to_owned()],
        deny_tools: Vec::new(),
        audit_log: AuditLogMode::Off,
        max_json_depth: 8,
        max_request_bytes: ByteSize::from_bytes(4096),
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
    })?;
    assert!(gateway.requires_jwt());

    let make_req = |auth: Option<&str>| -> Result<
        Request<miraserve_proxy::ProxyBody>,
        Box<dyn std::error::Error>,
    > {
        let mut b = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header(HOST, "panel.example:8080")
            .header(CONTENT_TYPE, "application/json");
        if let Some(tok) = auth {
            b = b.header(AUTHORIZATION, tok);
        }
        Ok(b.body(full_body(Bytes::from_static(
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"docs_search","arguments":{}}}"#,
        )))?)
    };

    // 1. Default (`credentials=#false`): 403 without WWW-Authenticate both with and without valid JWT,
    //    AND checked FIRST before `Content-Encoding` (415) or `Upgrade` (400) inspection.
    for auth in [None, Some(valid_jwt.as_str())] {
        let (resp, blocked) = gateway
            .handle_with_outcome(make_req(auth)?, None, "http")
            .await;
        assert!(blocked);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(resp.headers().get(http::header::WWW_AUTHENTICATE).is_none());
        assert_eq!(
            resp.headers()
                .get(http::header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
    }
    for (extra_hdr_name, extra_hdr_val, expected_https_status) in [
        (
            http::header::CONTENT_ENCODING,
            "identity",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (http::header::UPGRADE, "websocket", StatusCode::BAD_REQUEST),
    ] {
        let mut plain_req = make_req(Some(valid_jwt.as_str()))?;
        plain_req.headers_mut().insert(
            extra_hdr_name.clone(),
            HeaderValue::from_static(extra_hdr_val),
        );
        let (resp, blocked) = gateway.handle_with_outcome(plain_req, None, "http").await;
        assert!(blocked);
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "plain-HTTP OAuth gateway must return 403 before inspecting {extra_hdr_name}"
        );
        assert!(resp.headers().get(http::header::WWW_AUTHENTICATE).is_none());
        assert_eq!(
            resp.headers()
                .get(http::header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );

        // HTTPS control: existing v0.1.2 check order (415 / 400) is preserved.
        let mut https_req = make_req(Some(valid_jwt.as_str()))?;
        https_req.headers_mut().insert(
            extra_hdr_name.clone(),
            HeaderValue::from_static(extra_hdr_val),
        );
        let (https_resp, https_blocked) =
            gateway.handle_with_outcome(https_req, None, "https").await;
        assert!(https_blocked);
        assert_eq!(
            https_resp.status(),
            expected_https_status,
            "HTTPS MCP gateway must preserve v0.1.2 {extra_hdr_name} status"
        );
    }
    assert_eq!(hits.load(std::sync::atomic::Ordering::Acquire), 0);

    // 2. Opt-in (`allow_plaintext_credentials = true`): 401 + Bearer challenge without token,
    //    200 with valid JWT.
    let (unauth, blocked_unauth) = gateway
        .handle_with_outcome_for_transport(make_req(None)?, None, "http", true)
        .await;
    assert!(blocked_unauth);
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);
    let challenge = unauth
        .headers()
        .get(http::header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .ok_or("expected WWW-Authenticate on opted-in plain-HTTP 401")?;
    assert!(
        challenge.contains(
            "resource_metadata=\"http://panel.example:8080/.well-known/oauth-protected-resource\""
        ),
        "unexpected challenge: {challenge}"
    );
    assert_eq!(hits.load(std::sync::atomic::Ordering::Acquire), 0);

    let (ok, blocked_ok) = gateway
        .handle_with_outcome_for_transport(make_req(Some(valid_jwt.as_str()))?, None, "http", true)
        .await;
    assert!(!blocked_ok);
    assert_eq!(ok.status(), StatusCode::OK);
    assert_eq!(hits.load(std::sync::atomic::Ordering::Acquire), 1);

    up_task.abort();
    Ok(())
}

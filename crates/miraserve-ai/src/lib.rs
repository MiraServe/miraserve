#![forbid(unsafe_code)]
//! AI-Native Edge capabilities for MiraServe (Milestone 3 / Threat Model T6):
//! - **RFC 9421 / Web Bot Auth** cryptographic agent verification ([`BotAuthGuard`], [`AgentKeyRegistry`])
//! - **MCP Security Gateway** with OAuth 2.1 `RFC 9728` metadata, strict JSON nesting/size bounds,
//!   JSON-RPC tool RBAC (`allow-tools` / `deny-tools`), and secret-redacted audit logging ([`McpGateway`])
//! - **`llms.txt` & `Accept: text/markdown`** content negotiation ([`prefers_markdown`], [`html_to_markdown`])

pub mod bot_auth;
pub mod markdown;
pub mod mcp_gateway;

pub use bot_auth::{
    AgentKeyRegistry, BotAuthGuard, BotAuthOutcome, RegisteredAgent, VerifiedAgent,
    is_declared_ai_user_agent, sign_rfc9421_headers, verify_rfc9421_request,
    verify_rfc9421_request_with_scheme,
};
pub use markdown::{html_to_markdown, markdown_sibling_path, prefers_markdown};
pub use mcp_gateway::{
    McpAuditRecord, McpGateway, ToolRbacDecision, check_json_nesting_depth,
    extract_redacted_principal, filter_tools_list_response, glob_matches,
    parse_strict_json_no_duplicate_keys, redact_json_secrets, sign_mcp_oauth_jwt,
};

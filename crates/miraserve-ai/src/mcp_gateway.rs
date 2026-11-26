//! MCP Security Gateway (`miraserve-ai`):
//! - OAuth 2.1 Protected Resource Metadata (`RFC 9728`: `/.well-known/oauth-protected-resource`)
//!   plus fail-closed Bearer authorization presence enforcement (`401` + `WWW-Authenticate`)
//! - Strict JSON nesting depth & body size bounds (iterative scanner — zero recursion DoS)
//! - Fail-closed JSON-RPC parsing (rejects batch arrays, compressed bodies, HTTP upgrades, and malformed JSON)
//! - JSON-RPC tool-level RBAC (`deny-tools` overrides `allow-tools`, default-deny when allowlisted)
//! - Bounded, fail-closed `tools/list` response filtering (strips `Accept-Encoding`, rejects SSE/gzip bypass)
//! - Secret-redacted structured JSON / text audit logging (Threat Model T6)

use std::collections::HashMap;
use std::fs::File;
use std::io::Read as _;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64URL};
use bytes::Bytes;
use http::header::{
    ACCEPT_ENCODING, AUTHORIZATION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue,
    TRANSFER_ENCODING, UPGRADE, WWW_AUTHENTICATE,
};
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body::{Body, Frame};
use http_body_util::{BodyExt as _, Limited};
use miraserve_config::{
    AuditLogMode, LoadBalancePolicy, McpGatewayConfig, ReverseProxyConfig, StreamingFlushMode,
    UpstreamConfig,
};
use miraserve_proxy::{ProxyBody, ProxyError, ReverseProxy, full_body};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{info, warn};

/// Maximum `tools/list` upstream JSON response size buffered for RBAC filtering (4 MiB).
const MAX_TOOLS_LIST_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum size of a local Ed25519 public key file (4 KiB).
const MAX_JWT_KEY_FILE_BYTES: u64 = 4096;
/// Maximum size of an upstream RFC 7517 JWKS JSON document (256 KiB).
const MAX_JWKS_RESPONSE_BYTES: usize = 256 * 1024;
/// Minimum seconds between successful JWKS refresh fetches to prevent upstream amplification.
const JWKS_MIN_REFRESH_INTERVAL_SECS: u64 = 60;
/// Retry backoff (seconds) after a failed JWKS fetch so a hanging `IdP` cannot stall requests
/// every 5 seconds while still recovering quickly (`R3-MCP-1`).
const JWKS_FAILURE_BACKOFF_SECS: u64 = 15;
/// Hard timeout (seconds) covering upstream JWKS HTTP fetch + body collection (`R2-MCP-2`, `R3-MCP-1`).
const JWKS_FETCH_TIMEOUT_SECS: u64 = 5;
/// Default bounded timeout collecting upstream `tools/list` JSON or SSE responses (`R3-MCP-1`).
const DEFAULT_TOOLS_LIST_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum allowed clock skew for JWT `nbf`/`iat` validation (seconds).
const MAX_JWT_SKEW_SECS: u64 = 60;

/// Allowlisted HTTP Authorization schemes safe to record in redacted audit logs.
const SAFE_AUTH_SCHEMES: &[&str] = &[
    "bearer",
    "basic",
    "dpop",
    "digest",
    "hoba",
    "mutual",
    "negotiate",
    "oauth",
    "scram-sha-256",
    "vapid",
];

/// Sensitive JSON key substrings (matched after lowercasing and stripping `-`/`_`)
/// automatically redacted from MCP audit records.
const REDACTED_KEYS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "authorization",
    "credential",
    "privatekey",
    "cookie",
    "bearer",
    "session",
    "jwt",
    "signature",
];

/// Structured audit record emitted for every MCP JSON-RPC tool evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct McpAuditRecord {
    /// Unix timestamp in seconds.
    pub timestamp_unix: u64,
    /// Client IP address if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    /// JSON-RPC method name (e.g. `"tools/call"`, `"tools/list"`).
    pub rpc_method: String,
    /// Tool name when `rpc_method == "tools/call"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Policy decision (`"allow"` or `"deny"`).
    pub decision: &'static str,
    /// Matched rule or denial reason.
    pub reason: String,
    /// Redacted principal / bearer token scheme (NEVER logs raw tokens or unknown schemes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    /// Redacted copy of JSON-RPC tool arguments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments_redacted: Option<Value>,
}

/// Evaluation outcome of MCP tool RBAC policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolRbacDecision {
    /// Tool invocation is permitted.
    Allow,
    /// Tool invocation is forbidden by `deny-tools` or omitted from `allow-tools`.
    Deny {
        /// Explanation for audit log and JSON-RPC error.
        reason: String,
    },
}

/// Runtime MCP Security Gateway fronting an upstream MCP server.
#[derive(Debug)]
pub struct McpGateway {
    config: McpGatewayConfig,
    proxy: ReverseProxy,
    /// Optional static Ed25519 verifying key from `jwt-public-key`.
    static_jwt_key: Option<[u8; 32]>,
    /// Dynamic RFC 7517 JWKS Ed25519 public keys keyed by `kid` (replaced atomically on refresh
    /// so revoked keys are removed immediately, `R2-MCP-2`).
    jwks_keys: Arc<ArcSwap<HashMap<String, [u8; 32]>>>,
    /// Optional reverse-proxy client targeting `scheme://authority` of `config.jwks_url` plus
    /// the exact path+query (`R2-MCP-1`), wrapped in `Arc` for non-blocking background refresh
    /// (`R3-MCP-1`).
    jwks_proxy: Option<(Arc<ReverseProxy>, Arc<str>)>,
    /// Next Unix timestamp when a JWKS refresh is permitted (`now + 60s` on success or
    /// `now + 15s` on failure, `R2-MCP-2`, `R3-MCP-1`).
    next_jwks_refresh_allowed: Arc<AtomicU64>,
    /// Hard wall-clock timeout bounding `tools/list` JSON / SSE collection (`R3-MCP-1`).
    tools_list_timeout: Duration,
}

impl McpGateway {
    /// Initializes an [`McpGateway`] with default upstream proxy timeouts.
    ///
    /// # Errors
    /// Returns [`ProxyError`] if the upstream URL, JWKS URL, TLS setup, or JWT public key fails.
    pub fn new(config: McpGatewayConfig) -> Result<Self, ProxyError> {
        Self::new_with_timeouts(
            config,
            Duration::from_secs(10),
            Duration::from_secs(60),
            Duration::from_secs(60),
        )
    }

    /// Initializes an [`McpGateway`] with explicit upstream connect, response-header, and
    /// response-body idle timeouts (`R2-PRX-2`, `DOS-7`).
    ///
    /// # Errors
    /// Returns [`ProxyError`] if the upstream URL, JWKS URL, TLS setup, or JWT public key fails.
    pub fn new_with_timeouts(
        config: McpGatewayConfig,
        connect_timeout: Duration,
        response_timeout: Duration,
        body_idle_timeout: Duration,
    ) -> Result<Self, ProxyError> {
        let rp_cfg = ReverseProxyConfig {
            upstreams: vec![UpstreamConfig {
                url: config.upstream.clone(),
                weight: 1,
            }],
            // MCP Streamable HTTP uses SSE streams, so flush chunks immediately.
            streaming_flush: StreamingFlushMode::Immediate,
            lb_policy: LoadBalancePolicy::RoundRobin,
            health_check: None,
            upstream_tls: None,
            upstream_connect_timeout: None,
            upstream_response_timeout: None,
            upstream_body_idle_timeout: None,
            preserve_host: false,
            allow_upgrades: true,
            strip_prefix: false,
        };
        let proxy = ReverseProxy::new_with_timeouts(
            &rp_cfg,
            connect_timeout,
            response_timeout,
            body_idle_timeout,
        )?
        .with_upgrades_enabled(false);

        let static_jwt_key = match &config.jwt_public_key {
            Some(pk_spec) => Some(load_jwt_ed25519_key(pk_spec).map_err(|msg| {
                ProxyError::InvalidUpstream(format!("jwt-public-key '{pk_spec}': {msg}"))
            })?),
            None => None,
        };

        let jwks_proxy = if let Some(jwks_url) = &config.jwks_url {
            let parsed_uri: http::Uri =
                jwks_url.parse().map_err(|err: http::uri::InvalidUri| {
                    ProxyError::InvalidUpstream(format!("jwks-url '{jwks_url}': {err}"))
                })?;
            let scheme = parsed_uri.scheme_str().ok_or_else(|| {
                ProxyError::InvalidUpstream(format!("jwks-url '{jwks_url}' is missing a scheme"))
            })?;
            let authority = parsed_uri.authority().ok_or_else(|| {
                ProxyError::InvalidUpstream(format!(
                    "jwks-url '{jwks_url}' is missing host/authority"
                ))
            })?;
            // R2-MCP-1: Build the JWKS ReverseProxy strictly from `scheme://authority` so
            // `build_upstream_uri` does NOT double the JWKS path!
            let origin_url = format!("{scheme}://{authority}");
            let path: Arc<str> = parsed_uri
                .path_and_query()
                .map_or("/.well-known/jwks.json", http::uri::PathAndQuery::as_str)
                .into();
            let jwks_rp = ReverseProxyConfig {
                upstreams: vec![UpstreamConfig {
                    url: origin_url,
                    weight: 1,
                }],
                streaming_flush: StreamingFlushMode::Buffered,
                lb_policy: LoadBalancePolicy::RoundRobin,
                health_check: None,
                upstream_tls: None,
                upstream_connect_timeout: None,
                upstream_response_timeout: None,
                upstream_body_idle_timeout: None,
                preserve_host: false,
                allow_upgrades: true,
                strip_prefix: false,
            };
            Some((
                Arc::new(
                    ReverseProxy::new(&jwks_rp)?
                        .with_upgrades_enabled(false)
                        .with_upstream_timeout(Duration::from_secs(JWKS_FETCH_TIMEOUT_SECS)),
                ),
                path,
            ))
        } else {
            None
        };

        Ok(Self {
            config,
            proxy,
            static_jwt_key,
            jwks_keys: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            jwks_proxy,
            next_jwks_refresh_allowed: Arc::new(AtomicU64::new(0)),
            tools_list_timeout: DEFAULT_TOOLS_LIST_TIMEOUT,
        })
    }

    /// Overrides the wall-clock timeout for collecting upstream `tools/list` JSON or SSE responses
    /// (`R3-MCP-1`, primarily for deterministic testing or strict latency budgets).
    #[must_use]
    pub const fn with_tools_list_timeout(mut self, timeout: Duration) -> Self {
        self.tools_list_timeout = timeout;
        self
    }

    /// Returns the configured [`McpGatewayConfig`].
    #[must_use]
    pub fn config(&self) -> &McpGatewayConfig {
        &self.config
    }

    /// Returns `true` if any `allow-tools` or `deny-tools` filter is configured.
    #[must_use]
    pub fn has_tool_filters(&self) -> bool {
        !self.config.allow_tools.is_empty() || !self.config.deny_tools.is_empty()
    }

    /// Returns `true` when this gateway requires OAuth 2.1 Bearer JWT verification
    /// (`oauth-resource-metadata`, a verifier key/JWKS, or any claim policy).
    #[must_use]
    pub const fn requires_jwt(&self) -> bool {
        self.config.oauth_resource_metadata
            || self.config.jwt_public_key.is_some()
            || self.config.jwks_url.is_some()
            || self.config.jwt_issuer.is_some()
            || self.config.jwt_audience.is_some()
            || self.config.required_scope.is_some()
    }

    /// Evaluates tool-level RBAC policy for `tool_name` (`deny-tools` always takes precedence;
    /// empty `allow-tools` is fail-closed default-deny per `MCP-3`; matching is ASCII
    /// case-insensitive per `R5-MCP-2` so `deny-tools "delete_*"` also blocks `DELETE_all`).
    #[must_use]
    pub fn check_tool_allowed(&self, tool_name: &str) -> ToolRbacDecision {
        check_tool_allowed_rules(&self.config.allow_tools, &self.config.deny_tools, tool_name)
    }

    /// Serves RFC 9728 OAuth 2.1 Protected Resource Metadata JSON for `resource_url`.
    #[must_use]
    pub fn oauth_protected_resource_metadata(&self, resource_url: &str) -> Response<ProxyBody> {
        let scopes: Vec<&str> = self
            .config
            .required_scope
            .as_deref()
            .map_or_else(|| vec!["mcp:tools", "mcp:resources"], |s| vec![s]);
        let mut obj = serde_json::Map::new();
        obj.insert("resource".to_owned(), json!(resource_url));
        // R4-MCP-2: Only advertise `authorization_servers` from an explicit `jwt-issuer`
        // (never fabricating an issuer URL from the `jwks-url` origin).
        if let Some(iss) = &self.config.jwt_issuer {
            obj.insert("authorization_servers".to_owned(), json!([iss]));
        }
        obj.insert("bearer_methods_supported".to_owned(), json!(["header"]));
        obj.insert("scopes_supported".to_owned(), json!(scopes));
        obj.insert(
            "miraserve_mcp_gateway".to_owned(),
            json!({
                "oauth_rfc9728": true,
                "jwt_alg": "EdDSA",
                "audit_log": self.config.audit_log,
                "max_json_depth": self.config.max_json_depth
            }),
        );
        let payload = Value::Object(obj);
        json_proxy_response(StatusCode::OK, &payload)
    }

    /// Handles an MCP gateway request and returns `(response, blocked_by_gateway)` so callers
    /// can count only gateway-originated security blocks (`MCP-4`) without misattributing
    /// upstream `400`/`403` application errors.
    ///
    /// Refuses OAuth/JWT bearer credentials over non-HTTPS transports unless
    /// [`Self::handle_with_outcome_for_transport`] explicitly opts in (`allow_plaintext_credentials`).
    pub async fn handle_with_outcome(
        &self,
        req: Request<ProxyBody>,
        client_ip: Option<IpAddr>,
        client_scheme: &str,
    ) -> (Response<ProxyBody>, bool) {
        self.handle_inner(req, client_ip, client_scheme, false)
            .await
    }

    /// Like [`Self::handle_with_outcome`], with an explicit per-site policy flag controlling
    /// whether OAuth/JWT bearer credentials may be challenged and verified over plain HTTP
    /// (`http "serve" credentials=#true`).
    pub async fn handle_with_outcome_for_transport(
        &self,
        req: Request<ProxyBody>,
        client_ip: Option<IpAddr>,
        client_scheme: &str,
        allow_plaintext_credentials: bool,
    ) -> (Response<ProxyBody>, bool) {
        self.handle_inner(req, client_ip, client_scheme, allow_plaintext_credentials)
            .await
    }

    /// Inspects, enforces cryptographic OAuth 2.1 Bearer JWT verification (when enabled),
    /// body/depth bounds, fail-closed JSON-RPC validation & tool RBAC, emits redacted audit logs,
    /// and forwards permitted MCP JSON-RPC requests to the upstream MCP server.
    pub async fn handle(
        &self,
        req: Request<ProxyBody>,
        client_ip: Option<IpAddr>,
        client_scheme: &str,
    ) -> Response<ProxyBody> {
        self.handle_inner(req, client_ip, client_scheme, false)
            .await
            .0
    }

    #[allow(clippy::too_many_lines)]
    async fn handle_inner(
        &self,
        req: Request<ProxyBody>,
        client_ip: Option<IpAddr>,
        client_scheme: &str,
        allow_plaintext_credentials: bool,
    ) -> (Response<ProxyBody>, bool) {
        // 0. Refuse OAuth/JWT bearer credential routes over plain HTTP unless explicitly opted in
        //    (`http "serve" credentials=#true`), BEFORE inspecting Upgrade, Content-Encoding, or
        //    any other request header or body.
        if self.requires_jwt()
            && !client_scheme.eq_ignore_ascii_case("https")
            && !allow_plaintext_credentials
        {
            let reason = "OAuth/JWT credentials are refused over plain HTTP unless http \"serve\" credentials=#true is set";
            self.emit_audit(&McpAuditRecord {
                timestamp_unix: current_unix_secs(),
                client_ip: client_ip.map(|ip| ip.to_string()),
                rpc_method: "<unauthenticated>".to_owned(),
                tool: None,
                decision: "deny",
                reason: reason.to_owned(),
                principal: None,
                arguments_redacted: None,
            });
            let mut resp = json_proxy_response(
                StatusCode::FORBIDDEN,
                &json!({
                    "error": "forbidden",
                    "error_description": reason
                }),
            );
            resp.headers_mut().insert(
                http::header::CACHE_CONTROL,
                HeaderValue::from_static("no-store"),
            );
            return (resp, true);
        }

        let max_bytes = self.config.max_request_bytes.as_bytes();
        let (mut parts, mut body) = req.into_parts();

        // 1. Reject protocol upgrades and compressed request bodies that would evade JSON inspection.
        if parts.headers.contains_key(UPGRADE) {
            return (
                json_proxy_response(
                    StatusCode::BAD_REQUEST,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": Value::Null,
                        "error": { "code": -32600, "message": "HTTP Upgrade is forbidden on MCP gateway routes" }
                    }),
                ),
                true,
            );
        }
        if parts.headers.contains_key(CONTENT_ENCODING) {
            return (
                json_proxy_response(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": Value::Null,
                        "error": { "code": -32600, "message": "Content-Encoding is not permitted on MCP JSON-RPC requests" }
                    }),
                ),
                true,
            );
        }

        // 2. Cryptographic OAuth 2.1 EdDSA Bearer JWT verification (MCP-2) whenever
        //    `oauth-resource-metadata`, a verifier, OR any claim policy (`jwt-issuer`,
        //    `jwt-audience`, `required-scope`) is configured — never silently skipping claims!
        let mut verified_principal: Option<String> = None;
        if self.requires_jwt() {
            match self.verify_bearer_jwt(&parts.headers).await {
                Ok(sub) => {
                    verified_principal = Some(format!("sub:{sub}"));
                }
                Err(reason) => {
                    self.emit_audit(&McpAuditRecord {
                        timestamp_unix: current_unix_secs(),
                        client_ip: client_ip.map(|ip| ip.to_string()),
                        rpc_method: "<unauthenticated>".to_owned(),
                        tool: None,
                        decision: "deny",
                        reason: reason.clone(),
                        principal: extract_redacted_principal(&parts.headers),
                        arguments_redacted: None,
                    });
                    let mut resp = json_proxy_response(
                        StatusCode::UNAUTHORIZED,
                        &json!({
                            "error": "unauthorized",
                            "error_description": reason
                        }),
                    );
                    let metadata_url = parts
                        .headers
                        .get(http::header::HOST)
                        .and_then(|v| v.to_str().ok())
                        .or_else(|| parts.uri.authority().map(http::uri::Authority::as_str))
                        .filter(|h| {
                            !h.is_empty() && !h.contains('"') && !h.chars().any(char::is_control)
                        })
                        .map_or_else(
                            || "/.well-known/oauth-protected-resource".to_owned(),
                            |h| {
                                format!(
                                    "{client_scheme}://{h}/.well-known/oauth-protected-resource"
                                )
                            },
                        );
                    let www_val = HeaderValue::from_str(&format!(
                        "Bearer resource_metadata=\"{metadata_url}\", error=\"invalid_token\""
                    ))
                    .unwrap_or_else(|_| {
                        HeaderValue::from_static(
                            "Bearer resource_metadata=\"/.well-known/oauth-protected-resource\", error=\"invalid_token\"",
                        )
                    });
                    resp.headers_mut().insert(WWW_AUTHENTICATE, www_val);
                    return (resp, true);
                }
            }
        }
        let audit_principal =
            verified_principal.or_else(|| extract_redacted_principal(&parts.headers));

        // 3. Collect bounded JSON-RPC request body (GET SSE streams have empty bodies).
        let mut raw_body = Vec::new();
        while let Some(frame_res) = body.frame().await {
            match frame_res {
                Ok(frame) => {
                    if let Ok(data) = frame.into_data() {
                        if (raw_body.len() as u64).saturating_add(data.len() as u64) > max_bytes {
                            return (
                                json_proxy_response(
                                    StatusCode::PAYLOAD_TOO_LARGE,
                                    &json!({
                                        "jsonrpc": "2.0",
                                        "id": Value::Null,
                                        "error": {
                                            "code": -32600,
                                            "message": "MCP request exceeds max-request-bytes limit"
                                        }
                                    }),
                                ),
                                true,
                            );
                        }
                        raw_body.extend_from_slice(&data);
                    }
                }
                Err(_) => {
                    return (
                        json_proxy_response(
                            StatusCode::BAD_REQUEST,
                            &json!({ "error": "failed to read MCP request body" }),
                        ),
                        true,
                    );
                }
            }
        }

        // 4. Enforce Content-Type (`application/json` + strictly UTF-8 charset if present, `R5-MCP-1`),
        //    strict JSON nesting depth, case-folding duplicate-key rejection on envelope & `params`
        //    (`R5-MCP-3`), `$serde_json::*` sentinel key rejection (`R5-MCP-4`), explicit MCP method
        //    allow-list (`R5-MCP-2`), single-object allow-listed JSON-RPC 2.0 canonical envelope
        //    rebuild (`R2-MCP-3`, `R3-MCP-1`, `R4-MCP-1`), authenticated client responses
        //    (`R2-MCP-4`), and case-insensitive tool RBAC.
        let is_get_request = parts.method == Method::GET;
        let mut is_tools_list = false;
        let mut forward_body_bytes = raw_body;
        if !forward_body_bytes.is_empty() {
            let ct_ok = parts
                .headers
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(is_allowed_json_content_type);
            if !ct_ok {
                return (
                    json_proxy_response(
                        StatusCode::UNSUPPORTED_MEDIA_TYPE,
                        &json!({
                            "jsonrpc": "2.0",
                            "id": Value::Null,
                            "error": {
                                "code": -32600,
                                "message": "MCP JSON-RPC requests require Content-Type: application/json (UTF-8 charset only)"
                            }
                        }),
                    ),
                    true,
                );
            }

            if let Err(depth_err) =
                check_json_nesting_depth(&forward_body_bytes, self.config.max_json_depth)
            {
                self.emit_audit(&McpAuditRecord {
                    timestamp_unix: current_unix_secs(),
                    client_ip: client_ip.map(|ip| ip.to_string()),
                    rpc_method: "<invalid>".to_owned(),
                    tool: None,
                    decision: "deny",
                    reason: depth_err.to_owned(),
                    principal: audit_principal.clone(),
                    arguments_redacted: None,
                });
                return (
                    json_proxy_response(
                        StatusCode::BAD_REQUEST,
                        &json!({
                            "jsonrpc": "2.0",
                            "id": Value::Null,
                            "error": { "code": -32600, "message": depth_err }
                        }),
                    ),
                    true,
                );
            }

            // R2-MCP-3 & R4-MCP-1: Reject exact & case-folding duplicate JSON object keys and
            // non-object roots (batches) so gateway and upstream (including Go `encoding/json`)
            // can never disagree on `method` or `params.name`!
            let json_val = match parse_strict_json_no_duplicate_keys(&forward_body_bytes) {
                Ok(v) if v.is_object() => v,
                Ok(_) => {
                    let reason = "JSON-RPC batch arrays and non-object roots are forbidden";
                    self.emit_audit(&McpAuditRecord {
                        timestamp_unix: current_unix_secs(),
                        client_ip: client_ip.map(|ip| ip.to_string()),
                        rpc_method: "<batch-or-non-object>".to_owned(),
                        tool: None,
                        decision: "deny",
                        reason: reason.to_owned(),
                        principal: audit_principal.clone(),
                        arguments_redacted: None,
                    });
                    return (
                        json_proxy_response(
                            StatusCode::BAD_REQUEST,
                            &json!({
                                "jsonrpc": "2.0",
                                "id": Value::Null,
                                "error": { "code": -32600, "message": reason }
                            }),
                        ),
                        true,
                    );
                }
                Err(parse_reason) => {
                    self.emit_audit(&McpAuditRecord {
                        timestamp_unix: current_unix_secs(),
                        client_ip: client_ip.map(|ip| ip.to_string()),
                        rpc_method: "<parse-error>".to_owned(),
                        tool: None,
                        decision: "deny",
                        reason: parse_reason.clone(),
                        principal: audit_principal.clone(),
                        arguments_redacted: None,
                    });
                    return (
                        json_proxy_response(
                            StatusCode::BAD_REQUEST,
                            &json!({
                                "jsonrpc": "2.0",
                                "id": Value::Null,
                                "error": { "code": -32700, "message": parse_reason }
                            }),
                        ),
                        true,
                    );
                }
            };

            let Some(root_map) = json_val.as_object() else {
                return (
                    json_proxy_response(
                        StatusCode::BAD_REQUEST,
                        &json!({
                            "jsonrpc": "2.0",
                            "id": Value::Null,
                            "error": { "code": -32600, "message": "JSON-RPC payload must be an object" }
                        }),
                    ),
                    true,
                );
            };
            let rpc_id = root_map.get("id").cloned().unwrap_or(Value::Null);
            let is_client_response = !root_map.contains_key("method")
                && root_map.contains_key("id")
                && (root_map.contains_key("result") || root_map.contains_key("error"));

            let mut canonical_envelope = serde_json::Map::new();

            if is_client_response {
                // R4-MCP-1: Strict JSON-RPC 2.0 response envelope allow-list (`jsonrpc`, `id`,
                // `result` OR `error`). Blocks `{"id":1,"result":{},"Method":"tools/call",...}`!
                let bad_key = root_map
                    .keys()
                    .find(|k| !matches!(k.as_str(), "jsonrpc" | "id" | "result" | "error"));
                if let Some(unexpected) = bad_key {
                    let reason = format!(
                        "unexpected top-level field '{unexpected}' in JSON-RPC client response"
                    );
                    self.emit_audit(&McpAuditRecord {
                        timestamp_unix: current_unix_secs(),
                        client_ip: client_ip.map(|ip| ip.to_string()),
                        rpc_method: "<client-response>".to_owned(),
                        tool: None,
                        decision: "deny",
                        reason: escape_controls(&reason),
                        principal: audit_principal.clone(),
                        arguments_redacted: None,
                    });
                    return (
                        json_proxy_response(
                            StatusCode::BAD_REQUEST,
                            &json!({
                                "jsonrpc": "2.0",
                                "id": rpc_id,
                                "error": { "code": -32600, "message": reason }
                            }),
                        ),
                        true,
                    );
                }
                if root_map.contains_key("result") && root_map.contains_key("error") {
                    let reason =
                        "JSON-RPC client response cannot contain both 'result' and 'error'";
                    return (
                        json_proxy_response(
                            StatusCode::BAD_REQUEST,
                            &json!({
                                "jsonrpc": "2.0",
                                "id": rpc_id,
                                "error": { "code": -32600, "message": reason }
                            }),
                        ),
                        true,
                    );
                }
                for key in ["jsonrpc", "id", "result", "error"] {
                    if let Some(v) = root_map.get(key) {
                        canonical_envelope.insert(key.to_owned(), v.clone());
                    }
                }
                // R2-MCP-4: Permit authenticated JSON-RPC 2.0 client responses to server-initiated
                // requests (MCP sampling, elicitation, roots).
                self.emit_audit(&McpAuditRecord {
                    timestamp_unix: current_unix_secs(),
                    client_ip: client_ip.map(|ip| ip.to_string()),
                    rpc_method: "<client-response>".to_owned(),
                    tool: None,
                    decision: "allow",
                    reason: "JSON-RPC 2.0 client response".to_owned(),
                    principal: audit_principal.clone(),
                    arguments_redacted: None,
                });
            } else {
                // R4-MCP-1: Strict JSON-RPC 2.0 request envelope allow-list (`jsonrpc`, `id`,
                // `method`, `params`). Rejects case-variant smuggling (`Params`, `Method`, etc.)!
                let bad_key = root_map
                    .keys()
                    .find(|k| !matches!(k.as_str(), "jsonrpc" | "id" | "method" | "params"));
                if let Some(unexpected) = bad_key {
                    let reason = format!(
                        "unexpected top-level field '{unexpected}' in JSON-RPC request envelope"
                    );
                    self.emit_audit(&McpAuditRecord {
                        timestamp_unix: current_unix_secs(),
                        client_ip: client_ip.map(|ip| ip.to_string()),
                        rpc_method: "<invalid-envelope>".to_owned(),
                        tool: None,
                        decision: "deny",
                        reason: escape_controls(&reason),
                        principal: audit_principal.clone(),
                        arguments_redacted: None,
                    });
                    return (
                        json_proxy_response(
                            StatusCode::BAD_REQUEST,
                            &json!({
                                "jsonrpc": "2.0",
                                "id": rpc_id,
                                "error": { "code": -32600, "message": reason }
                            }),
                        ),
                        true,
                    );
                }

                let Some(rpc_method) = root_map
                    .get("method")
                    .and_then(Value::as_str)
                    .filter(|m| !m.is_empty())
                else {
                    let reason = "JSON-RPC request missing string 'method' field";
                    self.emit_audit(&McpAuditRecord {
                        timestamp_unix: current_unix_secs(),
                        client_ip: client_ip.map(|ip| ip.to_string()),
                        rpc_method: "<missing-method>".to_owned(),
                        tool: None,
                        decision: "deny",
                        reason: reason.to_owned(),
                        principal: audit_principal.clone(),
                        arguments_redacted: None,
                    });
                    return (
                        json_proxy_response(
                            StatusCode::BAD_REQUEST,
                            &json!({
                                "jsonrpc": "2.0",
                                "id": rpc_id,
                                "error": { "code": -32600, "message": reason }
                            }),
                        ),
                        true,
                    );
                };
                // R5-MCP-2: Explicit JSON-RPC method allow-list (exact standard MCP method names;
                // rejects unknown methods and wrong-case variants such as `Tools/Call`).
                if !is_allowed_mcp_method(rpc_method) {
                    let reason = format!(
                        "JSON-RPC method '{rpc_method}' is not in the MCP gateway method allow-list"
                    );
                    self.emit_audit(&McpAuditRecord {
                        timestamp_unix: current_unix_secs(),
                        client_ip: client_ip.map(|ip| ip.to_string()),
                        rpc_method: escape_controls(rpc_method),
                        tool: None,
                        decision: "deny",
                        reason: escape_controls(&reason),
                        principal: audit_principal.clone(),
                        arguments_redacted: None,
                    });
                    return (
                        json_proxy_response(
                            StatusCode::FORBIDDEN,
                            &json!({
                                "jsonrpc": "2.0",
                                "id": rpc_id,
                                "error": { "code": -32601, "message": reason }
                            }),
                        ),
                        true,
                    );
                }

                is_tools_list = rpc_method == "tools/list";

                for key in ["jsonrpc", "id", "method"] {
                    if let Some(v) = root_map.get(key) {
                        canonical_envelope.insert(key.to_owned(), v.clone());
                    }
                }

                if rpc_method == "tools/call" {
                    let Some(params_obj) = root_map.get("params").and_then(Value::as_object) else {
                        let reason = "tools/call requires a JSON object 'params' field";
                        self.emit_audit(&McpAuditRecord {
                            timestamp_unix: current_unix_secs(),
                            client_ip: client_ip.map(|ip| ip.to_string()),
                            rpc_method: "tools/call".to_owned(),
                            tool: None,
                            decision: "deny",
                            reason: reason.to_owned(),
                            principal: audit_principal.clone(),
                            arguments_redacted: None,
                        });
                        return (
                            json_proxy_response(
                                StatusCode::BAD_REQUEST,
                                &json!({
                                    "jsonrpc": "2.0",
                                    "id": rpc_id,
                                    "error": { "code": -32602, "message": reason }
                                }),
                            ),
                            true,
                        );
                    };
                    // R4-MCP-1 & R5-MCP-6: Strict allow-list for `tools/call` params
                    // (`name`, `arguments`, `_meta`, and MCP 2025-11-25 `task`).
                    if let Some(bad_param) = params_obj
                        .keys()
                        .find(|k| !matches!(k.as_str(), "name" | "arguments" | "_meta" | "task"))
                    {
                        let reason =
                            format!("unexpected field '{bad_param}' in tools/call params object");
                        self.emit_audit(&McpAuditRecord {
                            timestamp_unix: current_unix_secs(),
                            client_ip: client_ip.map(|ip| ip.to_string()),
                            rpc_method: "tools/call".to_owned(),
                            tool: None,
                            decision: "deny",
                            reason: escape_controls(&reason),
                            principal: audit_principal.clone(),
                            arguments_redacted: None,
                        });
                        return (
                            json_proxy_response(
                                StatusCode::BAD_REQUEST,
                                &json!({
                                    "jsonrpc": "2.0",
                                    "id": rpc_id,
                                    "error": { "code": -32602, "message": reason }
                                }),
                            ),
                            true,
                        );
                    }
                    let Some(tool_name) = params_obj
                        .get("name")
                        .and_then(Value::as_str)
                        .filter(|n| !n.is_empty())
                    else {
                        let reason = "tools/call missing string params.name";
                        self.emit_audit(&McpAuditRecord {
                            timestamp_unix: current_unix_secs(),
                            client_ip: client_ip.map(|ip| ip.to_string()),
                            rpc_method: "tools/call".to_owned(),
                            tool: None,
                            decision: "deny",
                            reason: reason.to_owned(),
                            principal: audit_principal.clone(),
                            arguments_redacted: None,
                        });
                        return (
                            json_proxy_response(
                                StatusCode::BAD_REQUEST,
                                &json!({
                                    "jsonrpc": "2.0",
                                    "id": rpc_id,
                                    "error": { "code": -32602, "message": reason }
                                }),
                            ),
                            true,
                        );
                    };
                    let args_redacted = params_obj.get("arguments").map(redact_json_secrets);

                    match self.check_tool_allowed(tool_name) {
                        ToolRbacDecision::Deny { reason } => {
                            self.emit_audit(&McpAuditRecord {
                                timestamp_unix: current_unix_secs(),
                                client_ip: client_ip.map(|ip| ip.to_string()),
                                rpc_method: escape_controls(rpc_method),
                                tool: Some(escape_controls(tool_name)),
                                decision: "deny",
                                reason: escape_controls(&reason),
                                principal: audit_principal.clone(),
                                arguments_redacted: args_redacted,
                            });
                            return (
                                json_proxy_response(
                                    StatusCode::FORBIDDEN,
                                    &json!({
                                        "jsonrpc": "2.0",
                                        "id": rpc_id,
                                        "error": {
                                            "code": -32003,
                                            "message": reason
                                        }
                                    }),
                                ),
                                true,
                            );
                        }
                        ToolRbacDecision::Allow => {
                            self.emit_audit(&McpAuditRecord {
                                timestamp_unix: current_unix_secs(),
                                client_ip: client_ip.map(|ip| ip.to_string()),
                                rpc_method: escape_controls(rpc_method),
                                tool: Some(escape_controls(tool_name)),
                                decision: "allow",
                                reason: "permitted by MCP RBAC policy".to_owned(),
                                principal: audit_principal.clone(),
                                arguments_redacted: args_redacted,
                            });
                        }
                    }

                    let mut canonical_params = serde_json::Map::new();
                    for key in ["name", "arguments", "_meta", "task"] {
                        if let Some(v) = params_obj.get(key) {
                            canonical_params.insert(key.to_owned(), v.clone());
                        }
                    }
                    canonical_envelope.insert("params".to_owned(), Value::Object(canonical_params));
                } else {
                    if let Some(params_val) = root_map.get("params") {
                        canonical_envelope.insert("params".to_owned(), params_val.clone());
                    }
                    self.emit_audit(&McpAuditRecord {
                        timestamp_unix: current_unix_secs(),
                        client_ip: client_ip.map(|ip| ip.to_string()),
                        rpc_method: escape_controls(rpc_method),
                        tool: None,
                        decision: "allow",
                        reason: "permitted MCP JSON-RPC method".to_owned(),
                        principal: audit_principal.clone(),
                        arguments_redacted: None,
                    });
                }
            }

            // R4-MCP-1 & R3-MCP-1: Serialize the rebuilt canonical allow-listed JSON-RPC 2.0
            // envelope with `serde_json` `arbitrary_precision`, so case-insensitive decoders (e.g.
            // Go `encoding/json`) NEVER see smuggled fields AND large integers / high-precision
            // decimals are preserved verbatim without rounding!
            let Ok(canonical_bytes) = serde_json::to_vec(&Value::Object(canonical_envelope)) else {
                return (
                    json_proxy_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &json!({
                            "jsonrpc": "2.0",
                            "id": rpc_id,
                            "error": { "code": -32603, "message": "failed to encode canonical JSON-RPC envelope" }
                        }),
                    ),
                    true,
                );
            };
            parts.headers.remove(TRANSFER_ENCODING);
            // R5-MCP-1: Always send canonical UTF-8 `application/json` upstream (never forwarding
            // caller-supplied `charset=...` parameters!).
            parts
                .headers
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            if let Ok(len_val) = HeaderValue::from_str(&canonical_bytes.len().to_string()) {
                parts.headers.insert(CONTENT_LENGTH, len_val);
            }
            forward_body_bytes = canonical_bytes;
        }

        // 5. Strip Accept-Encoding on `tools/list` AND GET SSE stream resumptions (`R5-MCP-5`)
        //    so upstream returns filterable plaintext JSON/SSE (even when `allow-tools` is empty,
        //    because default-deny must filter every tool out of resumed SSE streams!).
        if is_tools_list || is_get_request {
            parts.headers.remove(ACCEPT_ENCODING);
        }

        let forwarded_req = Request::from_parts(parts, full_body(Bytes::from(forward_body_bytes)));
        let resp = self
            .proxy
            .forward(forwarded_req, client_ip, client_scheme)
            .await;

        // 6a. R5-MCP-5 & R7-MCP-1: Filter `tools/list` results delivered on GET SSE stream
        //     resumption (`text/event-stream`) across ALL 2xx responses incrementally so denied or
        //     unlisted tools never leak across resumed streams.
        if is_get_request
            && !is_tools_list
            && resp.status().is_success()
            && content_type_essence(resp.headers()).as_deref() == Some("text/event-stream")
        {
            if resp.headers().contains_key(CONTENT_ENCODING) {
                return (
                    json_proxy_response(
                        StatusCode::BAD_GATEWAY,
                        &json!({
                            "error": "upstream MCP GET SSE stream must be uncompressed when tool RBAC filtering is active"
                        }),
                    ),
                    true,
                );
            }
            let (mut resp_parts, resp_body) = resp.into_parts();
            resp_parts.headers.remove(CONTENT_LENGTH);
            resp_parts.headers.remove(TRANSFER_ENCODING);
            let filtered_body = SseToolsFilterBody::new(
                resp_body,
                self.config.allow_tools.clone(),
                self.config.deny_tools.clone(),
            );
            return (
                Response::from_parts(resp_parts, filtered_body.boxed()),
                false,
            );
        }

        // 6. Fail-closed bounded `tools/list` response filtering across ALL 2xx responses
        //    (`R2-MCP-4`, `R3-MCP-1`, `R7-MCP-1`), matching exact media type essence and rejecting
        //    JSON array roots (`Value::Array`) fail-closed.
        if is_tools_list && resp.status().is_success() && resp.status() != StatusCode::NO_CONTENT {
            let ct_essence = content_type_essence(resp.headers());
            let is_json = ct_essence.as_deref() == Some("application/json");
            let is_sse = ct_essence.as_deref() == Some("text/event-stream");
            let is_encoded = resp.headers().contains_key(CONTENT_ENCODING);

            if (!is_json && !is_sse) || is_encoded {
                return (
                    json_proxy_response(
                        StatusCode::BAD_GATEWAY,
                        &json!({
                            "error": "upstream tools/list response must be uncompressed application/json or text/event-stream when tool RBAC filtering is active"
                        }),
                    ),
                    true,
                );
            }

            let (mut resp_parts, resp_body) = resp.into_parts();
            let collected = match tokio::time::timeout(
                self.tools_list_timeout,
                Limited::new(resp_body, MAX_TOOLS_LIST_RESPONSE_BYTES).collect(),
            )
            .await
            {
                Ok(Ok(c)) => c,
                Ok(Err(_)) => {
                    return (
                        json_proxy_response(
                            StatusCode::BAD_GATEWAY,
                            &json!({ "error": "upstream MCP tools/list response exceeded size limit or failed" }),
                        ),
                        true,
                    );
                }
                Err(_) => {
                    return (
                        json_proxy_response(
                            StatusCode::GATEWAY_TIMEOUT,
                            &json!({ "error": "upstream MCP tools/list response stream timed out" }),
                        ),
                        true,
                    );
                }
            };
            let raw_resp = collected.to_bytes();
            if is_sse {
                let Ok(sse_text) = std::str::from_utf8(&raw_resp) else {
                    return (
                        json_proxy_response(
                            StatusCode::BAD_GATEWAY,
                            &json!({ "error": "upstream MCP tools/list SSE response was not valid UTF-8" }),
                        ),
                        true,
                    );
                };
                let Ok(filtered_sse) = filter_tools_list_sse(self, sse_text) else {
                    return (
                        json_proxy_response(
                            StatusCode::BAD_GATEWAY,
                            &json!({ "error": "upstream MCP tools/list SSE event returned invalid JSON" }),
                        ),
                        true,
                    );
                };
                resp_parts.headers.remove(TRANSFER_ENCODING);
                if let Ok(len_val) = HeaderValue::from_str(&filtered_sse.len().to_string()) {
                    resp_parts.headers.insert(CONTENT_LENGTH, len_val);
                }
                return (
                    Response::from_parts(resp_parts, full_body(Bytes::from(filtered_sse))),
                    false,
                );
            }
            let Ok(mut parsed) = serde_json::from_slice::<Value>(&raw_resp) else {
                return (
                    json_proxy_response(
                        StatusCode::BAD_GATEWAY,
                        &json!({ "error": "upstream MCP tools/list returned invalid JSON" }),
                    ),
                    true,
                );
            };
            if !parsed.is_object() {
                return (
                    json_proxy_response(
                        StatusCode::BAD_GATEWAY,
                        &json!({ "error": "upstream MCP tools/list response must be a JSON object (R7-MCP-1)" }),
                    ),
                    true,
                );
            }
            filter_tools_list_response(self, &mut parsed);
            if let Ok(filtered_bytes) = serde_json::to_vec(&parsed) {
                resp_parts.headers.remove(TRANSFER_ENCODING);
                if let Ok(len_val) = HeaderValue::from_str(&filtered_bytes.len().to_string()) {
                    resp_parts.headers.insert(CONTENT_LENGTH, len_val);
                }
                return (
                    Response::from_parts(resp_parts, full_body(Bytes::from(filtered_bytes))),
                    false,
                );
            }
            return (
                json_proxy_response(
                    StatusCode::BAD_GATEWAY,
                    &json!({ "error": "failed to re-encode filtered MCP tools/list response" }),
                ),
                true,
            );
        }

        (resp, false)
    }

    #[allow(clippy::too_many_lines)]
    async fn verify_bearer_jwt(&self, headers: &HeaderMap) -> Result<String, String> {
        #[derive(Deserialize)]
        struct JwtHeader {
            alg: String,
            #[serde(default)]
            kid: Option<String>,
        }
        #[derive(Deserialize)]
        struct JwtClaims {
            sub: String,
            exp: u64,
            #[serde(default)]
            nbf: Option<u64>,
            #[serde(default)]
            iat: Option<u64>,
            #[serde(default)]
            iss: Option<String>,
            #[serde(default)]
            aud: Option<Value>,
            #[serde(default)]
            scope: Option<String>,
            #[serde(default)]
            scp: Option<Vec<String>>,
        }

        let auth_val = headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| "missing Authorization: Bearer JWT header".to_owned())?;
        let Some((scheme, raw_token)) = auth_val.split_once(' ') else {
            return Err("malformed Authorization header".to_owned());
        };
        if !scheme.eq_ignore_ascii_case("bearer") {
            return Err("Authorization scheme must be Bearer".to_owned());
        }
        let token = raw_token.trim();
        let mut parts = token.split('.');
        let (Some(hdr_b64), Some(pay_b64), Some(sig_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err("Bearer token must be a compact 3-part JWT".to_owned());
        };

        let hdr_bytes = BASE64URL
            .decode(hdr_b64.as_bytes())
            .map_err(|_| "invalid base64url JWT header".to_owned())?;
        let hdr: JwtHeader =
            serde_json::from_slice(&hdr_bytes).map_err(|_| "invalid JWT header JSON".to_owned())?;
        if hdr.alg != "EdDSA" {
            return Err("unsupported JWT alg (only EdDSA is accepted)".to_owned());
        }

        let sig_bytes = BASE64URL
            .decode(sig_b64.as_bytes())
            .map_err(|_| "invalid base64url JWT signature".to_owned())?;
        if sig_bytes.len() != 64 {
            return Err("invalid EdDSA JWT signature length".to_owned());
        }

        let pk = self.resolve_jwt_verifying_key(hdr.kid.as_deref()).await?;
        let signing_input = format!("{hdr_b64}.{pay_b64}");
        UnparsedPublicKey::new(&ED25519, pk)
            .verify(signing_input.as_bytes(), &sig_bytes)
            .map_err(|_| "JWT EdDSA cryptographic signature verification failed".to_owned())?;

        let pay_bytes = BASE64URL
            .decode(pay_b64.as_bytes())
            .map_err(|_| "invalid base64url JWT payload".to_owned())?;
        let claims: JwtClaims = serde_json::from_slice(&pay_bytes)
            .map_err(|_| "invalid JWT claims JSON (sub and exp required)".to_owned())?;

        if claims.sub.trim().is_empty() {
            return Err("JWT sub claim must not be empty".to_owned());
        }
        let now_unix = current_unix_secs();
        if now_unix >= claims.exp {
            return Err("JWT token has expired".to_owned());
        }
        if let Some(nbf) = claims.nbf
            && now_unix.saturating_add(MAX_JWT_SKEW_SECS) < nbf
        {
            return Err("JWT token is not yet valid (nbf)".to_owned());
        }
        if let Some(iat) = claims.iat
            && iat > now_unix.saturating_add(MAX_JWT_SKEW_SECS.saturating_mul(2))
        {
            return Err("JWT iat timestamp is too far in the future".to_owned());
        }
        if let Some(expected_iss) = &self.config.jwt_issuer
            && claims.iss.as_deref() != Some(expected_iss.as_str())
        {
            return Err("JWT iss claim does not match configured jwt-issuer".to_owned());
        }
        if let Some(expected_aud) = &self.config.jwt_audience {
            let aud_ok = match &claims.aud {
                Some(Value::String(s)) => s == expected_aud,
                Some(Value::Array(arr)) => arr
                    .iter()
                    .any(|v| v.as_str() == Some(expected_aud.as_str())),
                _ => false,
            };
            if !aud_ok {
                return Err("JWT aud claim does not match configured jwt-audience".to_owned());
            }
        }
        if let Some(req_scope) = &self.config.required_scope {
            let has_scope = claims
                .scope
                .as_deref()
                .is_some_and(|s| s.split_whitespace().any(|tok| tok == req_scope))
                || claims
                    .scp
                    .as_ref()
                    .is_some_and(|arr| arr.iter().any(|tok| tok == req_scope));
            if !has_scope {
                return Err(format!("JWT missing required scope '{req_scope}'"));
            }
        }

        let safe_sub: String = claims
            .sub
            .chars()
            .filter(|c| !c.is_control())
            .take(128)
            .collect();
        Ok(safe_sub)
    }

    async fn resolve_jwt_verifying_key(&self, kid: Option<&str>) -> Result<[u8; 32], String> {
        let lookup_jwks = |map: &HashMap<String, [u8; 32]>| -> Option<[u8; 32]> {
            if let Some(k) = kid {
                return map.get(k).copied();
            }
            if map.len() == 1 {
                return map.values().next().copied();
            }
            None
        };

        // 1. If JWKS is configured, ALWAYS resolve exclusively from JWKS (never silently
        //    switching to `static_jwt_key` when JWKS grows from 1 to 2 keys on `kid`-less tokens,
        //    `R3-MCP-1`), and refresh in the background whenever a cached key hit already exists
        //    so a hanging IdP never stalls warm client requests!
        if let Some((jwks_proxy, jwks_path)) = &self.jwks_proxy {
            let now = current_unix_secs();
            let next_allowed = self.next_jwks_refresh_allowed.load(Ordering::Acquire);
            let cached_hit = lookup_jwks(&self.jwks_keys.load());

            if let Some(pk) = cached_hit {
                if now >= next_allowed
                    && self
                        .next_jwks_refresh_allowed
                        .compare_exchange(
                            next_allowed,
                            now.saturating_add(JWKS_FAILURE_BACKOFF_SECS),
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                {
                    let proxy_bg = Arc::clone(jwks_proxy);
                    let path_bg = Arc::clone(jwks_path);
                    let keys_bg = Arc::clone(&self.jwks_keys);
                    let next_bg = Arc::clone(&self.next_jwks_refresh_allowed);
                    tokio::spawn(async move {
                        refresh_jwks_once(&proxy_bg, &path_bg, &keys_bg, &next_bg).await;
                    });
                }
                return Ok(pk);
            }

            // Cold cache or unknown `kid`: perform one bounded inline fetch when backoff allows.
            if now >= next_allowed
                && self
                    .next_jwks_refresh_allowed
                    .compare_exchange(
                        next_allowed,
                        now.saturating_add(JWKS_FAILURE_BACKOFF_SECS),
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
            {
                refresh_jwks_once(
                    jwks_proxy,
                    jwks_path,
                    &self.jwks_keys,
                    &self.next_jwks_refresh_allowed,
                )
                .await;
            }

            if let Some(pk) = lookup_jwks(&self.jwks_keys.load()) {
                return Ok(pk);
            }
            return Err(if kid.is_some() {
                "JWT kid not found in active JWKS keyset (revoked or unknown key)".to_owned()
            } else {
                "JWT missing 'kid' header cannot be disambiguated against active JWKS keyset"
                    .to_owned()
            });
        }

        if let Some(pk) = self.static_jwt_key {
            return Ok(pk);
        }

        Err(
            "no matching Ed25519 JWT verifying key configured (check jwt-public-key / jwks-url)"
                .to_owned(),
        )
    }

    /// Emits a redacted audit record according to `config.audit_log`.
    pub fn emit_audit(&self, record: &McpAuditRecord) {
        match self.config.audit_log {
            AuditLogMode::Off => {}
            AuditLogMode::StructuredJson => {
                if let Ok(json_line) = serde_json::to_string(record) {
                    if record.decision == "deny" {
                        warn!(mcp_audit = %json_line, "MCP gateway denied request");
                    } else {
                        info!(mcp_audit = %json_line, "MCP gateway allowed request");
                    }
                }
            }
            AuditLogMode::RedactedText => {
                if record.decision == "deny" {
                    warn!(
                        method = %record.rpc_method,
                        tool = ?record.tool,
                        reason = %record.reason,
                        "MCP gateway DENIED"
                    );
                } else {
                    info!(
                        method = %record.rpc_method,
                        tool = ?record.tool,
                        "MCP gateway ALLOWED"
                    );
                }
            }
        }
    }
}

async fn refresh_jwks_once(
    jwks_proxy: &ReverseProxy,
    jwks_path: &str,
    jwks_keys: &ArcSwap<HashMap<String, [u8; 32]>>,
    next_jwks_refresh_allowed: &AtomicU64,
) {
    let Ok(req) = Request::builder()
        .method(Method::GET)
        .uri(jwks_path)
        .body(full_body(Bytes::new()))
    else {
        return;
    };
    let fetch_timeout = Duration::from_secs(JWKS_FETCH_TIMEOUT_SECS);
    let fetched = tokio::time::timeout(fetch_timeout, async {
        let resp = jwks_proxy.forward(req, None, "https").await;
        if resp.status() != StatusCode::OK {
            return None;
        }
        let collected = Limited::new(resp.into_body(), MAX_JWKS_RESPONSE_BYTES)
            .collect()
            .await
            .ok()?;
        parse_ed25519_jwks(&collected.to_bytes()).ok()
    })
    .await
    .ok()
    .flatten();

    if let Some(parsed) = fetched {
        // Replace the entire JWKS map so rotated/revoked keys are purged immediately!
        jwks_keys.store(Arc::new(parsed));
        next_jwks_refresh_allowed.store(
            current_unix_secs().saturating_add(JWKS_MIN_REFRESH_INTERVAL_SECS),
            Ordering::Release,
        );
    }
}

/// Checks an incoming `Content-Type` header (`R5-MCP-1`): media type MUST be `application/json`,
/// and if any `charset` parameter is present it MUST appear at most once and equal `utf-8`
/// (case-insensitive, stripping optional matching quotes), blocking `charset=utf-7` bypasses.
fn is_allowed_json_content_type(ct: &str) -> bool {
    let mut parts = ct.split(';');
    let media = parts.next().unwrap_or("").trim();
    if !media.eq_ignore_ascii_case("application/json") {
        return false;
    }
    let mut saw_charset = false;
    for param in parts {
        let trimmed = param.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((raw_name, raw_val)) = trimmed.split_once('=') else {
            return false;
        };
        let name = raw_name.trim();
        let val = raw_val.trim();
        let unquoted = val
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or(val)
            .trim();
        if name.eq_ignore_ascii_case("charset") {
            if saw_charset || !unquoted.eq_ignore_ascii_case("utf-8") {
                return false;
            }
            saw_charset = true;
        }
    }
    true
}

/// Explicit JSON-RPC 2.0 method allow-list for standard MCP client-to-server methods (`R5-MCP-2`).
fn is_allowed_mcp_method(method: &str) -> bool {
    matches!(
        method,
        "initialize"
            | "notifications/initialized"
            | "ping"
            | "tools/list"
            | "tools/call"
            | "resources/list"
            | "resources/read"
            | "resources/templates/list"
            | "resources/subscribe"
            | "resources/unsubscribe"
            | "prompts/list"
            | "prompts/get"
            | "completion/complete"
            | "logging/setLevel"
            | "notifications/cancelled"
            | "notifications/progress"
            | "notifications/roots/list_changed"
            | "notifications/tasks/status"
            | "tasks/get"
            | "tasks/list"
            | "tasks/result"
            | "tasks/cancel"
    )
}

fn content_type_essence(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(CONTENT_TYPE)?.to_str().ok()?;
    let essence = raw.split(';').next()?.trim();
    if essence.is_empty() {
        None
    } else {
        Some(essence.to_ascii_lowercase())
    }
}

/// Validates MCP tool names strictly against `[A-Za-z0-9_./:-]` (`1..=128` bytes), rejecting
/// trailing whitespace (`"exec "`), NUL bytes (`"exec\u{0000}"`), control characters, glob
/// wildcards, and non-ASCII characters (`R7-MCP-2`).
fn is_valid_mcp_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'/' | b':' | b'-'))
}

/// Evaluates tool-level RBAC rules (`R5-MCP-2`, `R6-MCP-1`, `R7-MCP-2`):
/// - Tool names must match `[A-Za-z0-9_./:-]` (rejecting whitespace, NUL/control bytes, and
///   non-ASCII Unicode case-folding tricks such as Kelvin sign `K` U+212A).
/// - `deny-tools` matches case-insensitively so uppercase/mixed-case variants of denied tools
///   cannot bypass a deny rule.
/// - `allow-tools` matches **case-sensitively** (matching MCP spec tool-name case sensitivity) so
///   `allow-tools "read_file"` never widens access to a distinct upstream tool `READ_FILE`.
fn check_tool_allowed_rules(
    allow_tools: &[String],
    deny_tools: &[String],
    tool_name: &str,
) -> ToolRbacDecision {
    if !is_valid_mcp_tool_name(tool_name) {
        return ToolRbacDecision::Deny {
            reason: format!(
                "tool '{}' denied: tool names must match [A-Za-z0-9_./:-] (1..=128 bytes, R7-MCP-2)",
                escape_controls(tool_name)
            ),
        };
    }

    let tool_lower = tool_name.to_ascii_lowercase();
    for deny_pat in deny_tools {
        if glob_matches(&deny_pat.to_ascii_lowercase(), &tool_lower) {
            return ToolRbacDecision::Deny {
                reason: format!("tool '{tool_name}' matched deny-tools pattern '{deny_pat}'"),
            };
        }
    }

    if allow_tools.is_empty() {
        return ToolRbacDecision::Deny {
            reason: format!(
                "tool '{tool_name}' denied because allow-tools is empty (default-deny)"
            ),
        };
    }

    let allowed = allow_tools.iter().any(|pat| glob_matches(pat, tool_name));
    if !allowed {
        return ToolRbacDecision::Deny {
            reason: format!("tool '{tool_name}' is not listed in allow-tools (default-deny)"),
        };
    }

    ToolRbacDecision::Allow
}

fn filter_tools_list_response_with_rules(
    allow_tools: &[String],
    deny_tools: &[String],
    response_json: &mut Value,
) {
    if let Value::Array(items) = response_json {
        for item in items {
            filter_tools_list_response_with_rules(allow_tools, deny_tools, item);
        }
        return;
    }
    if let Some(tools) = response_json
        .get_mut("result")
        .and_then(|r| r.get_mut("tools"))
        .and_then(Value::as_array_mut)
    {
        tools.retain(|tool| {
            tool.get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| {
                    check_tool_allowed_rules(allow_tools, deny_tools, name)
                        == ToolRbacDecision::Allow
                })
        });
    }
}

/// Filters a JSON-RPC `tools/list` response in place, removing tools forbidden by RBAC.
pub fn filter_tools_list_response(gateway: &McpGateway, response_json: &mut Value) {
    filter_tools_list_response_with_rules(
        &gateway.config.allow_tools,
        &gateway.config.deny_tools,
        response_json,
    );
}

/// Splits SSE text into `(content, ending)` pairs honoring ALL WHATWG `EventSource` line endings:
/// `\r\n`, `\n`, and bare `\r` (`R5-MCP-5`).
fn split_sse_lines(text: &str) -> Vec<(&str, &str)> {
    let bytes = text.as_bytes();
    let mut lines = Vec::new();
    let mut start = 0_usize;
    let mut i = 0_usize;
    while i < bytes.len() {
        match bytes.get(i).copied() {
            Some(b'\r') => {
                let end = if bytes.get(i + 1) == Some(&b'\n') {
                    i + 2
                } else {
                    i + 1
                };
                if let (Some(content), Some(ending)) = (text.get(start..i), text.get(i..end)) {
                    lines.push((content, ending));
                }
                i = end;
                start = end;
            }
            Some(b'\n') => {
                if let (Some(content), Some(ending)) = (text.get(start..i), text.get(i..i + 1)) {
                    lines.push((content, ending));
                }
                i += 1;
                start = i;
            }
            _ => {
                i += 1;
            }
        }
    }
    if start < text.len()
        && let Some(tail) = text.get(start..)
    {
        lines.push((tail, ""));
    }
    lines
}

fn filter_sse_event_block(
    lines: &[(&str, &str)],
    allow_tools: &[String],
    deny_tools: &[String],
    allow_non_json_keepalive: bool,
    reject_array_roots: bool,
    out: &mut String,
) -> Result<(), ()> {
    let mut data_parts: Vec<&str> = Vec::new();
    let mut non_data_prefix: Vec<(&str, &str)> = Vec::new();
    let mut trailing_blank: Option<&str> = None;

    for &(content, ending) in lines {
        if content.is_empty() && !ending.is_empty() {
            trailing_blank = Some(ending);
            continue;
        }
        if let Some(rest) = content.strip_prefix("data:") {
            let val = rest.strip_prefix(' ').unwrap_or(rest);
            data_parts.push(val);
        } else {
            non_data_prefix.push((content, ending));
        }
    }

    if data_parts.is_empty() {
        for &(content, ending) in lines {
            out.push_str(content);
            out.push_str(ending);
        }
        return Ok(());
    }

    let combined = data_parts.join("\n");
    let trimmed = combined.trim();
    if trimmed.is_empty() || trimmed == "[DONE]" {
        for &(content, ending) in lines {
            out.push_str(content);
            out.push_str(ending);
        }
        return Ok(());
    }

    let Ok(mut val) = serde_json::from_str::<Value>(trimmed) else {
        // R7-MCP-3: On GET SSE stream resumptions, pass through benign non-JSON keep-alive
        // frames (e.g. `data: ping`, `data: keep-alive`) without killing the stream, while
        // failing closed on malformed JSON objects/arrays (`{...`, `[...`) or payloads
        // referencing `"tools"`.
        if allow_non_json_keepalive
            && !trimmed.starts_with('{')
            && !trimmed.starts_with('[')
            && !trimmed.contains("\"tools\"")
            && !trimmed.contains('\u{FEFF}')
        {
            for &(content, ending) in lines {
                out.push_str(content);
                out.push_str(ending);
            }
            return Ok(());
        }
        return Err(());
    };
    if reject_array_roots && !val.is_object() {
        return Err(());
    }
    filter_tools_list_response_with_rules(allow_tools, deny_tools, &mut val);
    let serialized = serde_json::to_string(&val).map_err(|_| ())?;

    for (content, ending) in non_data_prefix {
        out.push_str(content);
        out.push_str(ending);
    }
    out.push_str("data: ");
    out.push_str(&serialized);
    out.push('\n');
    if let Some(blank_end) = trailing_blank {
        out.push_str(blank_end);
    }
    Ok(())
}

/// Filters SSE events WITHOUT stripping a leading BOM — callers MUST strip any single stream-start
/// UTF-8 BOM (`0xEF 0xBB 0xBF` / `\u{FEFF}`) once before calling (`R7-MCP-3`).
fn filter_sse_events_no_bom(
    allow_tools: &[String],
    deny_tools: &[String],
    sse_text: &str,
    allow_non_json_keepalive: bool,
    reject_array_roots: bool,
) -> Result<Vec<u8>, ()> {
    let mut out = String::with_capacity(sse_text.len());
    let mut block: Vec<(&str, &str)> = Vec::new();
    for (content, ending) in split_sse_lines(sse_text) {
        let is_blank = content.is_empty() && !ending.is_empty();
        block.push((content, ending));
        if is_blank {
            filter_sse_event_block(
                &block,
                allow_tools,
                deny_tools,
                allow_non_json_keepalive,
                reject_array_roots,
                &mut out,
            )?;
            block.clear();
        }
    }
    if !block.is_empty() {
        filter_sse_event_block(
            &block,
            allow_tools,
            deny_tools,
            allow_non_json_keepalive,
            reject_array_roots,
            &mut out,
        )?;
    }
    Ok(out.into_bytes())
}

/// Filters a buffered Streamable HTTP `text/event-stream` SSE response for `tools/list`, stripping
/// a single leading UTF-8 BOM `\u{FEFF}` at stream start (`R2-MCP-4`, `R5-MCP-5`, `R6-MCP-2`,
/// `R7-MCP-1`, `R7-MCP-3`).
fn filter_tools_list_sse_with_rules(
    allow_tools: &[String],
    deny_tools: &[String],
    sse_text: &str,
) -> Result<Vec<u8>, ()> {
    let sse_text = sse_text.strip_prefix('\u{FEFF}').unwrap_or(sse_text);
    filter_sse_events_no_bom(allow_tools, deny_tools, sse_text, false, true)
}

fn filter_tools_list_sse(gateway: &McpGateway, sse_text: &str) -> Result<Vec<u8>, ()> {
    filter_tools_list_sse_with_rules(
        &gateway.config.allow_tools,
        &gateway.config.deny_tools,
        sse_text,
    )
}

/// Streaming SSE response body wrapper that filters `tools/list` events incrementally on GET
/// Streamable HTTP SSE stream resumptions (`R5-MCP-5`), stripping a leading UTF-8 BOM (`R6-MCP-2`)
/// and supporting `\r\n`, `\n`, and bare `\r\r` terminators without stalling (`R6-MCP-3`).
struct SseToolsFilterBody {
    inner: ProxyBody,
    allow_tools: Vec<String>,
    deny_tools: Vec<String>,
    pending: Vec<u8>,
    bom_checked: bool,
    skip_leading_lf: bool,
    eof: bool,
}

impl SseToolsFilterBody {
    const fn new(inner: ProxyBody, allow_tools: Vec<String>, deny_tools: Vec<String>) -> Self {
        Self {
            inner,
            allow_tools,
            deny_tools,
            pending: Vec::new(),
            bom_checked: false,
            skip_leading_lf: false,
            eof: false,
        }
    }

    /// Finds the byte offset just past the first complete SSE event boundary (a blank line using
    /// `\r\n`, `\n`, or bare `\r`).
    ///
    /// Returns `(end_offset, ended_with_bare_trailing_cr)`. When a blank line ends at the end of
    /// `buf` with a bare `\r` (e.g. `data: {...}\r\r` or `data: {...}\r\n\r`), the event is
    /// emitted immediately (`R6-MCP-3`) and `ended_with_bare_trailing_cr == true` tells the caller
    /// to consume a single following `\n` if the next chunk completes a split `\r\n`.
    fn find_complete_event_end(buf: &[u8]) -> Option<(usize, bool)> {
        let mut i = 0_usize;
        let mut line_start = 0_usize;
        while i < buf.len() {
            match buf.get(i).copied() {
                Some(b'\r') => {
                    let line_empty = i == line_start;
                    if i + 1 == buf.len() {
                        if line_empty {
                            // Blank line completed by bare `\r` (e.g. `data: {...}\r\r` or
                            // `data: {...}\r\n\r`): emit immediately without stalling (`R6-MCP-3`).
                            return Some((i + 1, true));
                        }
                        // Ambiguous trailing `\r` after non-empty line (could be `\r\n` split
                        // across chunks); wait for the next byte.
                        return None;
                    }
                    let end = if buf.get(i + 1) == Some(&b'\n') {
                        i + 2
                    } else {
                        i + 1
                    };
                    if line_empty {
                        return Some((end, false));
                    }
                    i = end;
                    line_start = end;
                }
                Some(b'\n') => {
                    let line_empty = i == line_start;
                    let end = i + 1;
                    if line_empty {
                        return Some((end, false));
                    }
                    i = end;
                    line_start = end;
                }
                _ => {
                    i += 1;
                }
            }
        }
        None
    }

    fn drain_ready_events(&mut self, flush_all: bool) -> Result<Option<Bytes>, ProxyError> {
        // R6-MCP-2: Strip one leading UTF-8 BOM (`EF BB BF`) at stream start per WHATWG EventSource,
        // even if the 3 BOM bytes arrive split across initial chunks.
        if !self.bom_checked {
            const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];
            if self.pending.starts_with(&UTF8_BOM) {
                self.pending.drain(..3);
                self.bom_checked = true;
            } else if !flush_all
                && !self.pending.is_empty()
                && self.pending.len() < 3
                && UTF8_BOM.starts_with(&self.pending)
            {
                return Ok(None);
            } else if !self.pending.is_empty() || flush_all {
                self.bom_checked = true;
            }
        }

        let mut emitted = Vec::new();
        loop {
            if self.skip_leading_lf {
                if self.pending.first() == Some(&b'\n') {
                    self.pending.drain(..1);
                    self.skip_leading_lf = false;
                } else if !self.pending.is_empty() {
                    self.skip_leading_lf = false;
                }
            }
            let Some((end, bare_cr_end)) = Self::find_complete_event_end(&self.pending) else {
                break;
            };
            let chunk: Vec<u8> = self.pending.drain(..end).collect();
            self.skip_leading_lf = bare_cr_end;
            let text = std::str::from_utf8(&chunk).map_err(|_| {
                ProxyError::Body("upstream MCP GET SSE stream contained invalid UTF-8".to_owned())
            })?;
            let filtered =
                filter_sse_events_no_bom(&self.allow_tools, &self.deny_tools, text, true, false)
                    .map_err(|()| {
                        ProxyError::Body(
                            "upstream MCP GET SSE stream event contained invalid JSON".to_owned(),
                        )
                    })?;
            emitted.extend_from_slice(&filtered);
        }
        if flush_all && !self.pending.is_empty() {
            if self.skip_leading_lf && self.pending.first() == Some(&b'\n') {
                self.pending.drain(..1);
                self.skip_leading_lf = false;
            }
            if !self.pending.is_empty() {
                let chunk = std::mem::take(&mut self.pending);
                let text = std::str::from_utf8(&chunk).map_err(|_| {
                    ProxyError::Body(
                        "upstream MCP GET SSE stream contained invalid UTF-8".to_owned(),
                    )
                })?;
                let filtered = filter_sse_events_no_bom(
                    &self.allow_tools,
                    &self.deny_tools,
                    text,
                    true,
                    false,
                )
                .map_err(|()| {
                    ProxyError::Body(
                        "upstream MCP GET SSE stream event contained invalid JSON".to_owned(),
                    )
                })?;
                emitted.extend_from_slice(&filtered);
            }
        }
        if emitted.is_empty() {
            Ok(None)
        } else {
            Ok(Some(Bytes::from(emitted)))
        }
    }
}

impl Body for SseToolsFilterBody {
    type Data = Bytes;
    type Error = ProxyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        loop {
            match this.drain_ready_events(this.eof) {
                Ok(Some(bytes)) => return Poll::Ready(Some(Ok(Frame::data(bytes)))),
                Ok(None) if this.eof => return Poll::Ready(None),
                Ok(None) => {}
                Err(err) => {
                    this.eof = true;
                    return Poll::Ready(Some(Err(err)));
                }
            }

            match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(frame))) => {
                    if let Ok(data) = frame.into_data() {
                        if this.pending.len().saturating_add(data.len())
                            > MAX_TOOLS_LIST_RESPONSE_BYTES
                        {
                            this.eof = true;
                            return Poll::Ready(Some(Err(ProxyError::Body(
                                "upstream MCP GET SSE event exceeded size limit".to_owned(),
                            ))));
                        }
                        this.pending.extend_from_slice(&data);
                    }
                }
                Poll::Ready(Some(Err(err))) => {
                    this.eof = true;
                    return Poll::Ready(Some(Err(err)));
                }
                Poll::Ready(None) => {
                    this.eof = true;
                }
            }
        }
    }
}

/// Scans raw JSON bytes BEFORE `serde_json` deserialization to reject any client-supplied object
/// key matching `serde_json`'s internal `$serde_json::*` sentinels (e.g.
/// `{"$serde_json::private::Number":"1"}`, `R5-MCP-4`), including `\uXXXX`-escaped forms, without
/// affecting genuine JSON numbers (which are never quoted strings).
fn reject_serde_json_private_keys(raw: &[u8]) -> Result<(), String> {
    let text =
        std::str::from_utf8(raw).map_err(|_| "JSON-RPC payload is not valid UTF-8".to_owned())?;
    let bytes = text.as_bytes();
    let mut i = 0_usize;
    while i < bytes.len() {
        if bytes.get(i) != Some(&b'"') {
            i += 1;
            continue;
        }
        // Decode JSON string starting at `i`
        i += 1;
        let mut decoded = String::new();
        let mut closed = false;
        while i < bytes.len() {
            match bytes.get(i).copied() {
                Some(b'"') => {
                    i += 1;
                    closed = true;
                    break;
                }
                Some(b'\\') => {
                    i += 1;
                    match bytes.get(i).copied() {
                        Some(b'"') => {
                            decoded.push('"');
                            i += 1;
                        }
                        Some(b'\\') => {
                            decoded.push('\\');
                            i += 1;
                        }
                        Some(b'/') => {
                            decoded.push('/');
                            i += 1;
                        }
                        Some(b'b') => {
                            decoded.push('\u{0008}');
                            i += 1;
                        }
                        Some(b'f') => {
                            decoded.push('\u{000C}');
                            i += 1;
                        }
                        Some(b'n') => {
                            decoded.push('\n');
                            i += 1;
                        }
                        Some(b'r') => {
                            decoded.push('\r');
                            i += 1;
                        }
                        Some(b't') => {
                            decoded.push('\t');
                            i += 1;
                        }
                        Some(b'u') => {
                            i += 1;
                            if let Some(hex) = text.get(i..i + 4)
                                && let Ok(code) = u16::from_str_radix(hex, 16)
                            {
                                i += 4;
                                if let Some(ch) = char::from_u32(u32::from(code)) {
                                    decoded.push(ch);
                                }
                            } else {
                                return Err("invalid \\u escape in JSON string".to_owned());
                            }
                        }
                        _ => return Err("invalid escape sequence in JSON string".to_owned()),
                    }
                }
                Some(_) => {
                    let ch = text.get(i..).and_then(|s| s.chars().next()).unwrap_or('\0');
                    decoded.push(ch);
                    i += ch.len_utf8();
                }
                None => break,
            }
        }
        if !closed {
            return Err("unterminated JSON string".to_owned());
        }
        // Check whether this string is an object key (followed by optional JSON whitespace + `:`).
        let mut j = i;
        while matches!(bytes.get(j).copied(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            j += 1;
        }
        if bytes.get(j) == Some(&b':') && decoded.starts_with("$serde_json::") {
            return Err(format!(
                "forbidden internal JSON sentinel object key '{decoded}'"
            ));
        }
    }
    Ok(())
}

/// Depth-aware strict JSON `DeserializeSeed` (`R2-MCP-3`, `R4-MCP-1`, `R5-MCP-3`):
/// - Rejects EXACT duplicate object keys at EVERY nesting level.
/// - Rejects CASE-FOLDING duplicate object keys (`Method` vs `method`, Unicode `\u{017F}`/`\u{212A}`)
///   at `depth <= 1` (the JSON-RPC envelope and its `params` object), while permitting distinct-case
///   keys inside nested tool arguments (e.g. `params.arguments.headers = {"Accept":"a","accept":"b"}`).
struct StrictJsonSeed {
    depth: usize,
}

impl<'de> serde::de::DeserializeSeed<'de> for StrictJsonSeed {
    type Value = Value;

    #[allow(clippy::too_many_lines)]
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StrictVisitor {
            depth: usize,
        }

        impl<'de> serde::de::Visitor<'de> for StrictVisitor {
            type Value = Value;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("any valid JSON value without duplicate object keys")
            }

            fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
                Ok(Value::Bool(v))
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
                Ok(Value::Number(v.into()))
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
                Ok(Value::Number(v.into()))
            }

            fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                serde_json::Number::from_f64(v)
                    .map(Value::Number)
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
                Ok(Value::String(v.to_owned()))
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
                Ok(Value::String(v))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(Value::Null)
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(Value::Null)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut vec = Vec::new();
                let next_depth = self.depth.saturating_add(1);
                while let Some(elem) =
                    seq.next_element_seed(StrictJsonSeed { depth: next_depth })?
                {
                    vec.push(elem);
                }
                Ok(Value::Array(vec))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut obj = serde_json::Map::new();
                let check_case_fold = self.depth <= 1;
                let mut seen_folded = std::collections::HashSet::<String>::new();
                let next_depth = self.depth.saturating_add(1);
                while let Some(k) = map.next_key::<String>()? {
                    // `serde_json` `arbitrary_precision` delivers every genuine JSON number via
                    // `visit_map` with `$serde_json::private::Number` (client-supplied object keys
                    // with this name were already rejected by `reject_serde_json_private_keys`).
                    if k == "$serde_json::private::Number" {
                        if !obj.is_empty() {
                            return Err(serde::de::Error::custom(
                                "unexpected internal number sentinel inside JSON object",
                            ));
                        }
                        let raw_num = map.next_value::<String>()?;
                        if map.next_key::<serde::de::IgnoredAny>()?.is_some() {
                            return Err(serde::de::Error::custom(
                                "unexpected trailing key after JSON number sentinel",
                            ));
                        }
                        let num: serde_json::Number =
                            serde_json::from_str(&raw_num).map_err(|_| {
                                serde::de::Error::custom("invalid arbitrary-precision JSON number")
                            })?;
                        return Ok(Value::Number(num));
                    }
                    if obj.contains_key(&k) {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate JSON object key '{k}' is forbidden"
                        )));
                    }
                    if check_case_fold {
                        // R4-MCP-1 & R5-MCP-3: Enforce case-folding uniqueness on the JSON-RPC
                        // envelope (`depth == 0`) and `params` (`depth == 1`), including Go
                        // `strings.EqualFold` Unicode folds (`\u{017F}` -> 's', `\u{212A}` -> 'k').
                        let folded: String = k
                            .to_lowercase()
                            .chars()
                            .map(|c| match c {
                                '\u{017F}' => 's',
                                '\u{212A}' => 'k',
                                other => other,
                            })
                            .collect();
                        if !seen_folded.insert(folded) {
                            return Err(serde::de::Error::custom(format!(
                                "case-colliding JSON-RPC envelope/params key '{k}' is forbidden"
                            )));
                        }
                    }
                    let v = map.next_value_seed(StrictJsonSeed { depth: next_depth })?;
                    obj.insert(k, v);
                }
                Ok(Value::Object(obj))
            }
        }

        deserializer.deserialize_any(StrictVisitor { depth: self.depth })
    }
}

/// Parses JSON while rejecting exact duplicate object keys at every nesting level (`R2-MCP-3`),
/// case-folding duplicate keys on the envelope and `params` (`R4-MCP-1`, `R5-MCP-3`), and
/// client-supplied `$serde_json::*` sentinel object keys (`R5-MCP-4`).
///
/// # Errors
/// Returns an error description if `raw` is invalid JSON or violates key uniqueness / sentinel rules.
pub fn parse_strict_json_no_duplicate_keys(raw: &[u8]) -> Result<Value, String> {
    reject_serde_json_private_keys(raw)?;
    let mut de = serde_json::Deserializer::from_slice(raw);
    let val = serde::de::DeserializeSeed::deserialize(StrictJsonSeed { depth: 0 }, &mut de)
        .map_err(|err| format!("malformed or ambiguous JSON-RPC payload rejected: {err}"))?;
    de.end()
        .map_err(|err| format!("trailing tokens after JSON-RPC payload rejected: {err}"))?;
    Ok(val)
}

/// Recursively redacts sensitive keys (normalizing `-`/`_`) AND inline secret token values
/// in JSON arguments before audit logging.
#[must_use]
pub fn redact_json_secrets(val: &Value) -> Value {
    match val {
        Value::Object(map) => {
            let mut clean = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                let compact: String = k
                    .to_ascii_lowercase()
                    .chars()
                    .filter(|c| !matches!(c, '-' | '_' | '.' | ' '))
                    .collect();
                if REDACTED_KEYS.iter().any(|needle| compact.contains(needle)) {
                    clean.insert(k.clone(), Value::String("[REDACTED]".to_owned()));
                } else {
                    clean.insert(k.clone(), redact_json_secrets(v));
                }
            }
            Value::Object(clean)
        }
        Value::Array(items) => Value::Array(items.iter().map(redact_json_secrets).collect()),
        Value::String(s) => {
            if value_looks_like_secret(s) {
                Value::String("[REDACTED]".to_owned())
            } else {
                Value::String(s.clone())
            }
        }
        other => other.clone(),
    }
}

fn value_looks_like_secret(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    if lower.contains("bearer ")
        || lower.contains("basic ")
        || s.contains("sk-ant-")
        || s.contains("sk-proj-")
        || s.contains("sk_live_")
        || s.contains("ghp_")
        || s.contains("github_pat_")
        || s.contains("AKIA")
        || s.contains("-----BEGIN ")
    {
        return true;
    }
    if let Some(pos) = s.find("eyJ")
        && let Some(rest) = s.get(pos..)
        && rest.contains('.')
    {
        return true;
    }
    false
}

/// Iterative O(n), O(1)-stack JSON nesting depth checker (defends against recursive parser DoS).
///
/// # Errors
/// Returns a static error description if `{`/`[` nesting exceeds `max_depth`.
pub fn check_json_nesting_depth(bytes: &[u8], max_depth: u32) -> Result<(), &'static str> {
    let mut depth: u32 = 0;
    let mut in_string = false;
    let mut escaped = false;

    for &b in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth = depth.saturating_add(1);
                if depth > max_depth {
                    return Err("JSON nesting depth exceeds mcp-gateway max-json-depth limit");
                }
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    Ok(())
}

/// Wildcard glob matcher supporting `*` (zero or more chars) for MCP tool patterns.
#[must_use]
pub fn glob_matches(pattern: &str, candidate: &str) -> bool {
    let p = pattern.as_bytes();
    let s = candidate.as_bytes();
    let (mut pi, mut si) = (0_usize, 0_usize);
    let mut star_idx: Option<usize> = None;
    let mut match_idx: usize = 0;

    while si < s.len() {
        // Check wildcard '*' BEFORE literal equality so literal '*' in candidate never defeats globbing.
        if p.get(pi) == Some(&b'*') {
            star_idx = Some(pi);
            match_idx = si;
            pi = pi.saturating_add(1);
        } else if p.get(pi) == s.get(si) {
            pi = pi.saturating_add(1);
            si = si.saturating_add(1);
        } else if let Some(star) = star_idx {
            pi = star.saturating_add(1);
            match_idx = match_idx.saturating_add(1);
            si = match_idx;
        } else {
            return false;
        }
    }

    while p.get(pi) == Some(&b'*') {
        pi = pi.saturating_add(1);
    }
    pi == p.len()
}

/// Extracts ONLY an allowlisted HTTP auth scheme (never leaking raw tokens when no space exists).
#[must_use]
pub fn extract_redacted_principal(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok())?;
    let trimmed = auth.trim();
    if let Some((scheme, _rest)) = trimmed.split_once(char::is_whitespace)
        && let Some(canonical) = SAFE_AUTH_SCHEMES
            .iter()
            .find(|s| s.eq_ignore_ascii_case(scheme))
    {
        return Some(format!("{canonical} [REDACTED]"));
    }
    Some("Auth [REDACTED]".to_owned())
}

fn escape_controls(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn json_proxy_response(status: StatusCode, payload: &Value) -> Response<ProxyBody> {
    let bytes = serde_json::to_vec(payload).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json; charset=utf-8")
        .body(full_body(Bytes::from(bytes)))
        .unwrap_or_else(|_| {
            let mut r = Response::new(full_body(Bytes::new()));
            *r.status_mut() = status;
            r
        })
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Signs a compact `EdDSA` (`alg: "EdDSA"`) OAuth 2.1 Bearer JWT for [`McpGateway`] verification.
#[must_use]
pub fn sign_mcp_oauth_jwt(
    key_pair: &Ed25519KeyPair,
    subject: &str,
    exp_unix: u64,
    issuer: Option<&str>,
    audience: Option<&str>,
    scope: Option<&str>,
    kid: Option<&str>,
) -> String {
    let header_val = match kid {
        Some(k) => json!({ "alg": "EdDSA", "typ": "JWT", "kid": k }),
        None => json!({ "alg": "EdDSA", "typ": "JWT" }),
    };
    let mut claims = serde_json::Map::new();
    claims.insert("sub".to_owned(), Value::String(subject.to_owned()));
    claims.insert("exp".to_owned(), Value::from(exp_unix));
    if let Some(iss) = issuer {
        claims.insert("iss".to_owned(), Value::String(iss.to_owned()));
    }
    if let Some(aud) = audience {
        claims.insert("aud".to_owned(), Value::String(aud.to_owned()));
    }
    if let Some(sc) = scope {
        claims.insert("scope".to_owned(), Value::String(sc.to_owned()));
    }
    let hdr_b64 =
        BASE64URL.encode(serde_json::to_vec(&header_val).unwrap_or_else(|_| b"{}".to_vec()));
    let pay_b64 = BASE64URL
        .encode(serde_json::to_vec(&Value::Object(claims)).unwrap_or_else(|_| b"{}".to_vec()));
    let signing_input = format!("{hdr_b64}.{pay_b64}");
    let sig = key_pair.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", BASE64URL.encode(sig.as_ref()))
}

fn load_jwt_ed25519_key(spec: &str) -> Result<[u8; 32], String> {
    let raw_text = if let Some(path) = spec.strip_prefix("ed25519:") {
        let file =
            File::open(path).map_err(|err| format!("failed to open JWT key '{path}': {err}"))?;
        let meta = file
            .metadata()
            .map_err(|err| format!("failed to stat JWT key '{path}': {err}"))?;
        if !meta.is_file() {
            return Err(format!("JWT key '{path}' is not a regular file"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_JWT_KEY_FILE_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|err| format!("failed to read JWT key '{path}': {err}"))?;
        if (bytes.len() as u64) > MAX_JWT_KEY_FILE_BYTES {
            return Err(format!("JWT key '{path}' exceeds size limit"));
        }
        String::from_utf8(bytes).map_err(|_| format!("JWT key '{path}' is not valid UTF-8"))?
    } else {
        spec.to_owned()
    };

    let trimmed = raw_text.trim();
    let b64 = trimmed
        .strip_prefix("miraserve-ed25519-pub:")
        .unwrap_or(trimmed);
    let decoded = BASE64
        .decode(b64.as_bytes())
        .or_else(|_| BASE64URL.decode(b64.as_bytes()))
        .map_err(|err| format!("invalid base64 Ed25519 JWT key: {err}"))?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| format!("expected 32-byte Ed25519 public key, got {}", decoded.len()))
}

fn parse_ed25519_jwks(raw: &[u8]) -> Result<HashMap<String, [u8; 32]>, String> {
    #[derive(Deserialize)]
    struct JwkEntry {
        kty: String,
        #[serde(default)]
        crv: Option<String>,
        #[serde(default)]
        x: Option<String>,
        #[serde(default)]
        kid: Option<String>,
    }
    #[derive(Deserialize)]
    struct JwksDoc {
        keys: Vec<JwkEntry>,
    }

    let doc: JwksDoc =
        serde_json::from_slice(raw).map_err(|err| format!("invalid JWKS JSON: {err}"))?;
    let mut out = HashMap::new();
    for entry in doc.keys {
        if entry.kty == "OKP"
            && entry.crv.as_deref() == Some("Ed25519")
            && let Some(x_b64) = entry.x
            && let Ok(decoded) = BASE64URL.decode(x_b64.as_bytes())
            && let Ok(pk) = <[u8; 32]>::try_from(decoded.as_slice())
        {
            out.insert(entry.kid.unwrap_or_default(), pk);
        }
    }
    Ok(out)
}

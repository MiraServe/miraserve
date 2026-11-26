//! Built-in cryptographically authenticated MCP JSON-RPC 2.0 publishing endpoint (`/_miraserve/publish`).
//!
//! Exposes `site_publish`, `site_rollback`, `site_list_releases`, and `site_status` tools
//! so verified AI agents can deploy and roll back self-updating sites safely:
//! - `OAuthJwt`: verifies compact `EdDSA` (`alg="EdDSA"`) JWT signature and `sub`/`exp`/`nbf`/`iat`
//!   claims cryptographically against `store.verifying_key()` (failing closed if absent).
//! - `Mtls`: requires out-of-band TLS-verified peer certificate subject DN (`verified_client_cert_dn`);
//!   NEVER trusts client-supplied HTTP headers such as `X-Client-Cert-DN`.
//! - `Ed25519`: requires fresh `X-MiraServe-Timestamp` (±300s) and valid `X-MiraServe-Signature`
//!   over `POST\n<endpoint_path>\n<ts>\n<sha256_hex(body)>` verified against `store.verifying_key()`
//!   for EVERY MCP method (failing closed if absent).

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::digest::{SHA256, digest};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64URL};
use http::header::{AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE};
use http::{HeaderMap, HeaderValue, Response, StatusCode};
use miraserve_config::PublishAuthMode;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::crypto::{SignedBundle, SiteBundle, canonical_mcp_request_signing_input};
use crate::store::ReleaseStore;

/// Maximum permitted clock skew for `PublishAuthMode::Ed25519` signed requests (5 minutes).
const MAX_ED25519_CLOCK_SKEW_SECS: u64 = 300;

/// Maximum tolerated clock skew for JWT `nbf`/`iat` claims (30 seconds).
const MAX_JWT_SKEW_SECS: u64 = 30;

/// Maximum allowed publish JWT lifetime (`exp - iat` and remaining TTL) (15 minutes, `R3-PUB-3`).
/// Bearer JWTs are intentionally usable across an entire multi-step MCP session (`initialize` ->
/// `tools/list` -> `tools/call`); use `PublishAuthMode::Ed25519` for per-request replay defense.
const MAX_PUBLISH_JWT_LIFETIME_SECS: u64 = 900;

/// Out-of-band request context provided by the HTTP/TLS layer to [`handle_mcp_publish_http`].
#[derive(Debug, Clone, Copy)]
pub struct McpPublishAuthContext<'a> {
    /// Canonical configured endpoint path (e.g. `"/_miraserve/publish"`).
    pub endpoint_path: &'a str,
    /// Matched site hostname (used to bind Ed25519 request signatures and JWT `aud`, `R2-PUB-2`/`R2-PUB-3`).
    pub site_host: &'a str,
    /// Whether the request arrived over TLS/HTTPS (`R2-PUB-2`: plaintext HTTP is refused).
    pub is_https: bool,
    /// Client certificate subject DN cryptographically verified by the TLS handshake
    /// (`None` when mTLS client auth is not enabled on the listener).
    pub verified_client_cert_dn: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    #[serde(default)]
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Deserialize)]
struct ToolCallParams {
    name: String,
    #[serde(default)]
    arguments: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishToolArgs {
    /// Map of relative path -> UTF-8 string OR base64-encoded content (when `encoding = "base64"`).
    files: BTreeMap<String, String>,
    #[serde(default)]
    encoding: Option<String>,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    created_at_unix: Option<u64>,
    #[serde(default)]
    signature_b64: Option<String>,
    /// Canonical target site identifier bound into `miraserve-bundle-v3` signatures (`R3-PUB-5`).
    #[serde(default)]
    site_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RollbackToolArgs {
    #[serde(default)]
    release_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
}

#[derive(Debug, Deserialize)]
struct JwtClaims {
    sub: String,
    exp: u64,
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    aud: Option<Value>,
    #[serde(default)]
    nbf: Option<u64>,
    #[serde(default)]
    iat: Option<u64>,
    #[serde(default)]
    jti: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    scp: Option<Vec<String>>,
}

/// Verified JWT scope claims passed to `dispatch_tool_call` (`R2-PUB-3`).
struct VerifiedScopes {
    scopes: Vec<String>,
}

impl VerifiedScopes {
    fn allows_tool(&self, tool: &str) -> bool {
        let has = |s: &str| self.scopes.iter().any(|tok| tok == s);
        if has("publish") || has("publish:admin") {
            return true;
        }
        match tool {
            "site_publish" => has("publish:write"),
            "site_rollback" => has("publish:rollback") || has("publish:write"),
            "site_list_releases" | "site_status" => {
                has("publish:read") || has("publish:write") || has("publish:rollback")
            }
            _ => false,
        }
    }
}

/// Fast header-only authentication pre-check invoked BEFORE buffering large HTTP request bodies.
///
/// Enforces TLS (`ctx.is_https`), validates JWT/mTLS completely, and checks Ed25519 key presence,
/// fresh timestamp, and signature header structure before reading the body.
#[must_use]
pub fn precheck_mcp_publish_auth(
    store: &ReleaseStore,
    auth_mode: PublishAuthMode,
    headers: &HeaderMap,
    ctx: &McpPublishAuthContext<'_>,
) -> Option<Response<Vec<u8>>> {
    if !ctx.is_https {
        return Some(unauthorized_response(
            "MCP publish endpoint requires HTTPS/TLS (plaintext HTTP rejected)",
        ));
    }
    let now_unix = current_unix_secs();
    match auth_mode {
        PublishAuthMode::OAuthJwt => verify_oauth_jwt(store, headers, ctx, now_unix)
            .err()
            .map(bearer_unauthorized_response),
        PublishAuthMode::Mtls => verify_mtls_context(store, ctx),
        PublishAuthMode::Ed25519 => {
            if store.verifying_key().is_none() {
                return Some(unauthorized_response(
                    "Ed25519 publish authentication requires require-signature public key",
                ));
            }
            if parse_fresh_ed25519_headers(headers, now_unix).is_err() {
                return Some(unauthorized_response(
                    "missing or expired X-MiraServe-Timestamp / X-MiraServe-Signature headers",
                ));
            }
            None
        }
    }
}

/// Processes an incoming HTTP POST JSON-RPC 2.0 request to the MCP publishing endpoint.
#[must_use]
pub fn handle_mcp_publish_http(
    store: &ReleaseStore,
    auth_mode: PublishAuthMode,
    headers: &HeaderMap,
    body: &[u8],
    ctx: &McpPublishAuthContext<'_>,
) -> Response<Vec<u8>> {
    // 1. Cryptographically enforce TLS + configured authentication mode for ALL methods (Threat Model T6).
    let verified_scopes = match verify_endpoint_auth(store, auth_mode, headers, body, ctx) {
        Ok(scopes) => scopes,
        Err(unauth_resp) => return *unauth_resp,
    };

    // 2. Parse single JSON-RPC 2.0 object (rejecting batch arrays or invalid JSON).
    let parsed_val: Value = match serde_json::from_slice::<Value>(body) {
        Ok(v) if v.is_object() => v,
        _ => {
            return json_response(
                StatusCode::BAD_REQUEST,
                &jsonrpc_error(&Value::Null, -32700, "invalid JSON-RPC 2.0 request"),
            );
        }
    };
    let rpc = match serde_json::from_value::<JsonRpcRequest>(parsed_val) {
        Ok(r) if r.jsonrpc == "2.0" => r,
        _ => {
            return json_response(
                StatusCode::BAD_REQUEST,
                &jsonrpc_error(&Value::Null, -32700, "invalid JSON-RPC 2.0 request"),
            );
        }
    };

    let reply = match rpc.method.as_str() {
        "initialize" => jsonrpc_ok(
            &rpc.id,
            &json!({
                "protocolVersion": "2025-03-26",
                "serverInfo": {
                    "name": "miraserve-publish",
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "capabilities": {
                    "tools": { "listChanged": false }
                }
            }),
        ),
        "tools/list" => jsonrpc_ok(
            &rpc.id,
            &json!({
                "tools": [
                    {
                        "name": "site_publish",
                        "description": "Verify Ed25519 signature, run pre-flight secret/CSP checks, and atomically publish a new immutable site release.",
                        "inputSchema": {
                            "type": "object",
                            "required": ["files"],
                            "properties": {
                                "files": { "type": "object" },
                                "encoding": { "type": "string", "enum": ["utf8", "base64"] },
                                "note": { "type": "string" },
                                "created_at_unix": { "type": "integer" },
                                "signature_b64": { "type": "string" },
                                "site_id": { "type": "string" }
                            }
                        }
                    },
                    {
                        "name": "site_rollback",
                        "description": "Atomically roll back the live site to the previous or specified immutable release.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "release_id": { "type": "string" }
                            }
                        }
                    },
                    {
                        "name": "site_list_releases",
                        "description": "List retained immutable releases and the currently active release.",
                        "inputSchema": { "type": "object" }
                    },
                    {
                        "name": "site_status",
                        "description": "Return metadata for the currently active release.",
                        "inputSchema": { "type": "object" }
                    }
                ]
            }),
        ),
        "tools/call" => dispatch_tool_call(store, &rpc.id, rpc.params, verified_scopes.as_ref()),
        other => jsonrpc_error(
            &rpc.id,
            -32601,
            &format!("unsupported MCP method '{other}'"),
        ),
    };

    let status = if reply
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(Value::as_i64)
        == Some(-32003)
    {
        StatusCode::FORBIDDEN
    } else {
        StatusCode::OK
    };
    json_response(status, &reply)
}

fn verify_endpoint_auth(
    store: &ReleaseStore,
    auth_mode: PublishAuthMode,
    headers: &HeaderMap,
    body: &[u8],
    ctx: &McpPublishAuthContext<'_>,
) -> Result<Option<VerifiedScopes>, Box<Response<Vec<u8>>>> {
    if !ctx.is_https {
        return Err(Box::new(unauthorized_response(
            "MCP publish endpoint requires HTTPS/TLS (plaintext HTTP rejected)",
        )));
    }
    let now_unix = current_unix_secs();
    match auth_mode {
        PublishAuthMode::OAuthJwt => verify_oauth_jwt(store, headers, ctx, now_unix)
            .map(Some)
            .map_err(|msg| Box::new(bearer_unauthorized_response(msg))),
        PublishAuthMode::Mtls => match verify_mtls_context(store, ctx) {
            Some(err) => Err(Box::new(err)),
            None => Ok(None),
        },
        PublishAuthMode::Ed25519 => {
            match verify_ed25519_request(store, headers, body, ctx, now_unix) {
                Some(err) => Err(Box::new(err)),
                None => Ok(None),
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
fn verify_oauth_jwt(
    store: &ReleaseStore,
    headers: &HeaderMap,
    ctx: &McpPublishAuthContext<'_>,
    now_unix: u64,
) -> Result<VerifiedScopes, &'static str> {
    // R5-PUB-3: Defense-in-depth — `auth="oauth-jwt"` MUST also require signed bundles
    // (`require-signature`), matching `auth="mtls"`, so a compromised bearer token alone can never
    // publish unsigned content or bypass site-id signature binding.
    if store.verifying_key().is_none() {
        return Err(
            "OAuth JWT publish requires require-signature Ed25519 policy to prevent unsigned deploys",
        );
    }
    let Some(vk) = store.jwt_verifying_key() else {
        return Err("OAuth JWT verification key not configured (fail-closed)");
    };

    let Some(token) = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
    else {
        return Err("valid OAuth 2.1 Bearer EdDSA JWT required");
    };

    let mut parts = token.split('.');
    let (Some(h_b64), Some(p_b64), Some(s_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("malformed JWT structure");
    };

    let Ok(header_bytes) = BASE64URL.decode(h_b64) else {
        return Err("invalid JWT header encoding");
    };
    let Ok(header) = serde_json::from_slice::<JwtHeader>(&header_bytes) else {
        return Err("invalid JWT header JSON");
    };
    // Strictly require asymmetric EdDSA (reject alg=none, HS256, etc.).
    if header.alg != "EdDSA" {
        return Err("unsupported JWT algorithm (EdDSA required)");
    }

    let Ok(sig_bytes) = BASE64URL.decode(s_b64) else {
        return Err("invalid JWT signature encoding");
    };
    let signing_input = format!("{h_b64}.{p_b64}");
    if vk.verify(signing_input.as_bytes(), &sig_bytes).is_err() {
        return Err("JWT cryptographic signature verification failed");
    }

    let Ok(payload_bytes) = BASE64URL.decode(p_b64) else {
        return Err("invalid JWT payload encoding");
    };
    let Ok(claims) = serde_json::from_slice::<JwtClaims>(&payload_bytes) else {
        return Err("JWT payload missing required sub/exp claims");
    };
    if claims.sub.trim().is_empty() {
        return Err("JWT sub claim must not be empty");
    }
    if now_unix >= claims.exp {
        return Err("JWT token has expired");
    }
    if let Some(nbf) = claims.nbf
        && now_unix.saturating_add(MAX_JWT_SKEW_SECS) < nbf
    {
        return Err("JWT token is not yet valid");
    }
    if let Some(iat) = claims.iat {
        if iat > now_unix.saturating_add(MAX_JWT_SKEW_SECS.saturating_mul(2)) {
            return Err("JWT iat timestamp is too far in the future");
        }
        // R3-PUB-3: Enforce short maximum publish JWT lifetime (`exp - iat <= 900s`).
        if claims.exp.saturating_sub(iat) > MAX_PUBLISH_JWT_LIFETIME_SECS {
            return Err("JWT lifetime exceeds maximum permitted 900s for publish tokens");
        }
    } else if claims.exp.saturating_sub(now_unix) > MAX_PUBLISH_JWT_LIFETIME_SECS {
        return Err("JWT remaining lifetime exceeds maximum permitted 900s for publish tokens");
    }

    // §4 Q4: Enforce expected `iss` claim when `ai-publish.jwt-issuer` is configured.
    if let Some(expected_iss) = store.config().jwt_issuer.as_deref()
        && claims.iss.as_deref() != Some(expected_iss)
    {
        return Err("JWT iss claim missing or does not match configured jwt-issuer");
    }

    // R2-PUB-3 & R4-PUB-3: Require `aud` claim bound strictly to this site's canonical ID!
    if !ctx.site_host.is_empty() {
        let expected_aud = ctx.site_host.to_ascii_lowercase();
        let aud_ok = match &claims.aud {
            Some(Value::String(s)) => s.eq_ignore_ascii_case(&expected_aud),
            Some(Value::Array(arr)) => arr.iter().any(|v| {
                v.as_str()
                    .is_some_and(|s| s.eq_ignore_ascii_case(&expected_aud))
            }),
            _ => false,
        };
        if !aud_ok {
            return Err("JWT aud claim missing or does not match target site host");
        }
    }

    // R2-PUB-3: Enforce explicit publish scope claim (`scope` or `scp`).
    let mut scopes = Vec::new();
    if let Some(sc) = &claims.scope {
        for tok in sc.split_whitespace() {
            scopes.push(tok.to_owned());
        }
    }
    if let Some(scp) = &claims.scp {
        scopes.extend(scp.iter().cloned());
    }
    if scopes.is_empty() {
        return Err(
            "JWT missing required publish scope claim (e.g. publish:write, publish:rollback, publish:read)",
        );
    }

    // R3-PUB-3: Do NOT burn bearer JWT `jti` as a single-use nonce (an MCP session legitimately
    // sends `initialize` -> `tools/list` -> `tools/call` under the same short-lived bearer token).
    // Short 900s TTL bounds bearer exposure; use `PublishAuthMode::Ed25519` for per-request replay defense.
    let _ = claims.jti.as_deref();

    Ok(VerifiedScopes { scopes })
}

fn verify_mtls_context(
    store: &ReleaseStore,
    ctx: &McpPublishAuthContext<'_>,
) -> Option<Response<Vec<u8>>> {
    // NEVER inspect HTTP headers such as X-Client-Cert-DN: require out-of-band TLS-verified DN.
    let Some(dn) = ctx
        .verified_client_cert_dn
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Some(unauthorized_response(
            "verified mTLS client certificate required; HTTP identity headers are never trusted",
        ));
    };
    // R2-PUB-4: Defense-in-depth — require an active Ed25519 bundle signing policy alongside mTLS
    // so a broad organizational CA cannot push unsigned site bundles.
    if store.verifying_key().is_none() {
        return Some(unauthorized_response(
            "mTLS publish requires require-signature Ed25519 policy to prevent unsigned deploys",
        ));
    }
    // §4 Q4 & R5-PUB-2: Enforce explicit `allowed-subjects` FULL-DN comparison over parsed
    // RFC 4514 RDN sequences (OID/attr + unescaped value) so embedded commas like
    // `CN="laptop, CN=deploy-bot"` and broad partial RDNs like `O=Corp` can NEVER spoof matches!
    let allowed = &store.config().allowed_subjects;
    if !allowed.is_empty() {
        let matched = parse_rfc4514_dn(dn).is_some_and(|peer_rdns| {
            allowed
                .iter()
                .filter_map(|entry| parse_rfc4514_dn(entry))
                .any(|allowed_rdns| peer_rdns == allowed_rdns)
        });
        if !matched {
            return Some(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header(CONTENT_TYPE, "application/json")
                .body(
                    serde_json::to_vec(&json!({
                        "jsonrpc": "2.0",
                        "id": null,
                        "error": {
                            "code": -32003,
                            "message": "mTLS client certificate subject is not in ai-publish allowed-subjects"
                        }
                    }))
                    .unwrap_or_default(),
                )
                .unwrap_or_else(|_| Response::new(Vec::new())));
        }
    }
    None
}

/// Parses an RFC 4514 Distinguished Name string into a canonical sequence of RDNs, where each RDN
/// is a sorted list of `(canonical_attr_type, unescaped_value)` pairs (`R5-PUB-2`).
///
/// Handles RFC 4514 §2.4 backslash escapes (`\,`, `\=`, `\+`, `\\`, `\"`, `\<`, `\>`, `\;`, `\ `,
/// `\#`, and `\XX` hex bytes) and multi-valued RDNs (`+`), returning `None` on malformed syntax.
#[allow(clippy::too_many_lines)]
fn parse_rfc4514_dn(input: &str) -> Option<Vec<Vec<(String, String)>>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    let bytes = trimmed.as_bytes();
    let mut pos = 0_usize;
    let mut rdns: Vec<Vec<(String, String)>> = Vec::new();

    while pos < bytes.len() {
        let mut rdn: Vec<(String, String)> = Vec::new();
        loop {
            while matches!(bytes.get(pos), Some(b' ' | b'\t')) {
                pos += 1;
            }
            // Parse attribute type (short name or dotted OID) up to `=`
            let key_start = pos;
            while pos < bytes.len() && bytes.get(pos) != Some(&b'=') {
                if matches!(bytes.get(pos), Some(b',' | b'+' | b'\\')) {
                    return None;
                }
                pos += 1;
            }
            if bytes.get(pos) != Some(&b'=') {
                return None;
            }
            let raw_key = trimmed.get(key_start..pos)?.trim();
            if raw_key.is_empty() {
                return None;
            }
            let canon_key = canonicalize_dn_attr_type(raw_key)?;
            pos += 1; // skip '='

            while matches!(bytes.get(pos), Some(b' ' | b'\t')) {
                pos += 1;
            }
            // Parse attribute value up to unescaped `,` or `+` or end-of-string
            let mut value_bytes: Vec<u8> = Vec::new();
            let mut trailing_unescaped_spaces = 0_usize;
            while pos < bytes.len() {
                match bytes.get(pos).copied()? {
                    b',' | b'+' => break,
                    b'\\' => {
                        trailing_unescaped_spaces = 0;
                        pos += 1;
                        let next = bytes.get(pos).copied()?;
                        if next.is_ascii_hexdigit() {
                            let next2 = bytes.get(pos + 1).copied()?;
                            if !next2.is_ascii_hexdigit() {
                                return None;
                            }
                            let hex_str = trimmed.get(pos..pos + 2)?;
                            let decoded_byte = u8::from_str_radix(hex_str, 16).ok()?;
                            value_bytes.push(decoded_byte);
                            pos += 2;
                        } else {
                            value_bytes.push(next);
                            pos += 1;
                        }
                    }
                    b' ' => {
                        value_bytes.push(b' ');
                        trailing_unescaped_spaces += 1;
                        pos += 1;
                    }
                    b => {
                        trailing_unescaped_spaces = 0;
                        value_bytes.push(b);
                        pos += 1;
                    }
                }
            }
            // Strip unescaped trailing spaces per RFC 4514 §3
            let final_len = value_bytes.len().saturating_sub(trailing_unescaped_spaces);
            value_bytes.truncate(final_len);
            let mut val_str = String::from_utf8(value_bytes).ok()?;
            // Normalize RFC 4514 §2.4 hex-encoded DER values (`#<hex>`) to uppercase hex so
            // lowercase operator config matches uppercase formatter output (`R5-PUB-2`).
            if let Some(hex_body) = val_str.strip_prefix('#')
                && !hex_body.is_empty()
                && hex_body.len().is_multiple_of(2)
                && hex_body.bytes().all(|b| b.is_ascii_hexdigit())
            {
                val_str = format!("#{}", hex_body.to_ascii_uppercase());
            }
            rdn.push((canon_key, val_str));

            match bytes.get(pos).copied() {
                Some(b'+') => {
                    pos += 1;
                    if pos >= bytes.len() {
                        return None;
                    }
                }
                Some(b',') => {
                    pos += 1;
                    if pos >= bytes.len() {
                        return None;
                    }
                    break;
                }
                None => break,
                _ => return None,
            }
        }
        if rdn.is_empty() {
            return None;
        }
        rdn.sort();
        rdns.push(rdn);
    }

    if rdns.is_empty() { None } else { Some(rdns) }
}

fn canonicalize_dn_attr_type(raw: &str) -> Option<String> {
    if raw.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return match raw {
            "2.5.4.3" => Some("CN".to_owned()),
            "2.5.4.6" => Some("C".to_owned()),
            "2.5.4.7" => Some("L".to_owned()),
            "2.5.4.8" => Some("ST".to_owned()),
            "2.5.4.9" => Some("STREET".to_owned()),
            "2.5.4.10" => Some("O".to_owned()),
            "2.5.4.11" => Some("OU".to_owned()),
            "0.9.2342.19200300.100.1.1" => Some("UID".to_owned()),
            "0.9.2342.19200300.100.1.25" => Some("DC".to_owned()),
            "1.2.840.113549.1.9.1" => Some("EMAILADDRESS".to_owned()),
            oid => Some(oid.to_owned()),
        };
    }
    if !raw.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return None;
    }
    let upper = raw.to_ascii_uppercase();
    if upper == "E" {
        Some("EMAILADDRESS".to_owned())
    } else {
        Some(upper)
    }
}

fn verify_ed25519_request(
    store: &ReleaseStore,
    headers: &HeaderMap,
    body: &[u8],
    ctx: &McpPublishAuthContext<'_>,
    now_unix: u64,
) -> Option<Response<Vec<u8>>> {
    let Some(vk) = store.verifying_key() else {
        return Some(unauthorized_response(
            "Ed25519 request authentication requires require-signature public key",
        ));
    };
    let Ok((ts, sig_bytes, nonce)) = parse_fresh_ed25519_headers(headers, now_unix) else {
        return Some(unauthorized_response(
            "missing, invalid, or expired X-MiraServe-Timestamp / X-MiraServe-Signature headers",
        ));
    };
    let canonical = canonical_mcp_request_signing_input(
        ctx.site_host,
        ctx.endpoint_path,
        ts,
        nonce.as_deref(),
        body,
    );
    if vk.verify(canonical.as_bytes(), &sig_bytes).is_err() {
        return Some(unauthorized_response(
            "Ed25519 HTTP request signature verification failed",
        ));
    }
    // R2-PUB-2 & R3-PUB-6: Reject replays of any captured signed request across its ENTIRE
    // acceptance window `[ts - 300, ts + 300]` plus a 60s safety margin, so a future-stamped
    // request (`ts = t0 + 300`) can never be replayed again at `t0 + 600`!
    let replay_fp = sha256_32(&sig_bytes);
    let expires_at = ts
        .saturating_add(MAX_ED25519_CLOCK_SKEW_SECS)
        .saturating_add(60);
    let replay_ttl = expires_at.saturating_sub(now_unix).max(60);
    match store.check_and_record_replay(replay_fp, now_unix, replay_ttl) {
        crate::store::ReplayCheckOutcome::Accepted => None,
        crate::store::ReplayCheckOutcome::Replayed => Some(unauthorized_response(
            "replayed Ed25519 publish request rejected",
        )),
        crate::store::ReplayCheckOutcome::CacheFault(detail) => Some(service_unavailable_response(
            &format!("publish replay-protection cache unavailable: {detail}"),
        )),
    }
}

fn parse_fresh_ed25519_headers(
    headers: &HeaderMap,
    now_unix: u64,
) -> Result<(u64, Vec<u8>, Option<String>), ()> {
    let ts_str = headers
        .get("x-miraserve-timestamp")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .ok_or(())?;
    let ts: u64 = ts_str.parse().map_err(|_| ())?;
    if now_unix.abs_diff(ts) > MAX_ED25519_CLOCK_SKEW_SECS {
        return Err(());
    }
    let sig_str = headers
        .get("x-miraserve-signature")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .ok_or(())?;
    let sig_bytes = BASE64
        .decode(sig_str)
        .or_else(|_| BASE64URL.decode(sig_str))
        .map_err(|_| ())?;
    if sig_bytes.len() != 64 {
        return Err(());
    }
    let nonce = headers
        .get("x-miraserve-nonce")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= 128)
        .map(str::to_owned);
    Ok((ts, sig_bytes, nonce))
}

fn sha256_32(input: &[u8]) -> [u8; 32] {
    let d = digest(&SHA256, input);
    let mut out = [0_u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn bearer_unauthorized_response(detail: &str) -> Response<Vec<u8>> {
    let mut resp = unauthorized_response(detail);
    resp.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer error=\"invalid_token\""),
    );
    resp
}

fn unauthorized_response(detail: &str) -> Response<Vec<u8>> {
    json_response(
        StatusCode::UNAUTHORIZED,
        &json!({ "error": "unauthorized", "detail": detail }),
    )
}

fn service_unavailable_response(detail: &str) -> Response<Vec<u8>> {
    json_response(
        StatusCode::SERVICE_UNAVAILABLE,
        &json!({ "error": "service_unavailable", "detail": detail }),
    )
}

#[allow(clippy::too_many_lines)]
fn dispatch_tool_call(
    store: &ReleaseStore,
    id: &Value,
    params: Value,
    verified_scopes: Option<&VerifiedScopes>,
) -> Value {
    let call: ToolCallParams = match serde_json::from_value(params) {
        Ok(c) => c,
        Err(err) => return jsonrpc_error(id, -32602, &format!("invalid tools/call params: {err}")),
    };

    if let Some(scopes) = verified_scopes
        && !scopes.allows_tool(&call.name)
    {
        return jsonrpc_error(
            id,
            -32003,
            &format!("JWT scope does not authorize publish tool '{}'", call.name),
        );
    }

    match call.name.as_str() {
        "site_publish" => {
            let args: PublishToolArgs = match serde_json::from_value(call.arguments) {
                Ok(a) => a,
                Err(err) => {
                    return jsonrpc_error(id, -32602, &format!("invalid site_publish args: {err}"));
                }
            };
            let is_b64 = args
                .encoding
                .as_deref()
                .is_some_and(|e| e.eq_ignore_ascii_case("base64"));
            let mut files = BTreeMap::new();
            for (path, content) in args.files {
                let bytes = if is_b64 {
                    match BASE64.decode(content.trim()) {
                        Ok(b) => b,
                        Err(err) => {
                            return jsonrpc_error(
                                id,
                                -32602,
                                &format!("invalid base64 for '{path}': {err}"),
                            );
                        }
                    }
                } else {
                    content.into_bytes()
                };
                files.insert(path, bytes);
            }

            let created_at_unix = args.created_at_unix.unwrap_or_else(current_unix_secs);

            let signed = SignedBundle {
                bundle: SiteBundle {
                    files,
                    note: args.note,
                    created_at_unix,
                    site_id: args.site_id,
                },
                signature_b64: args.signature_b64,
            };

            match store.publish(&signed) {
                Ok(meta) => mcp_tool_ok(
                    id,
                    &json!({ "status": "published", "release": meta.redacted_for_listing() }),
                ),
                Err(err) => jsonrpc_error(id, -32001, &err.to_string()),
            }
        }
        "site_rollback" => {
            // PUB-14: Never swallow malformed `site_rollback` arguments.
            if !call.arguments.is_object() {
                return jsonrpc_error(id, -32602, "site_rollback arguments must be a JSON object");
            }
            let args: RollbackToolArgs = match serde_json::from_value(call.arguments) {
                Ok(a) => a,
                Err(err) => {
                    return jsonrpc_error(
                        id,
                        -32602,
                        &format!("invalid site_rollback args: {err}"),
                    );
                }
            };
            match store.rollback(args.release_id.as_deref()) {
                Ok(meta) => mcp_tool_ok(
                    id,
                    &json!({ "status": "rolled_back", "release": meta.redacted_for_listing() }),
                ),
                Err(err) => jsonrpc_error(id, -32002, &err.to_string()),
            }
        }
        "site_list_releases" => {
            // R3-PUB-7: Sync from disk before listing so CLI deploys appear immediately even
            // without unmatched static HTTP traffic (already running inside `spawn_blocking`).
            store.sync_from_disk();
            let active = store.active_release().map(|r| r.release_id);
            // R3-PUB-5: Omit `signature_b64` from listings so read-only callers cannot harvest signatures.
            let releases: Vec<_> = store
                .list_releases()
                .into_iter()
                .map(|r| r.redacted_for_listing())
                .collect();
            mcp_tool_ok(
                id,
                &json!({ "active_release_id": active, "releases": releases }),
            )
        }
        "site_status" => {
            store.sync_from_disk();
            let active = store.active_release().map(|r| r.redacted_for_listing());
            mcp_tool_ok(id, &json!({ "active": active }))
        }
        other => jsonrpc_error(id, -32601, &format!("unknown publish tool '{other}'")),
    }
}

fn mcp_tool_ok(id: &Value, payload: &Value) -> Value {
    let text = serde_json::to_string_pretty(payload).unwrap_or_else(|_| "{}".to_owned());
    jsonrpc_ok(
        id,
        &json!({
            "content": [{ "type": "text", "text": text }],
            "structuredContent": payload,
            "isError": false
        }),
    )
}

fn jsonrpc_ok(id: &Value, result: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })
}

fn jsonrpc_error(id: &Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    })
}

fn json_response(status: StatusCode, body: &Value) -> Response<Vec<u8>> {
    let bytes = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json; charset=utf-8")
        .body(bytes)
        .unwrap_or_else(|_| {
            let mut r = Response::new(Vec::new());
            *r.status_mut() = status;
            r
        })
}

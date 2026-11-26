//! RFC 9421 HTTP Message Signatures / Web Bot Auth verification and unverified AI crawler
//! policy enforcement (Threat Model T6).

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use http::header::{HOST, HeaderName, HeaderValue, USER_AGENT};
use http::{HeaderMap, Method, StatusCode, Uri};
use miraserve_config::{BotAuthConfig, UnverifiedBotAction};
use miraserve_security::GcraRateLimiter;

/// Maximum clock skew and replay window tolerated on RFC 9421 timestamps (5 minutes).
const MAX_CLOCK_SKEW_SECS: u64 = 300;

/// Known AI crawler/agent User-Agent tokens inspected when RFC 9421 auth is absent.
const KNOWN_AI_USER_AGENTS: &[&str] = &[
    "gptbot",
    "oai-searchbot",
    "chatgpt-user",
    "claudebot",
    "claude-web",
    "anthropic-ai",
    "perplexitybot",
    "google-extended",
    "ccbot",
    "applebot-extended",
    "bytespider",
    "amazonbot",
    "meta-externalagent",
    "cohere-ai",
    "diffbot",
];

/// Registered cryptographic AI agent identity trusted for RFC 9421 verification.
#[derive(Debug, Clone)]
pub struct RegisteredAgent {
    /// Unique agent identifier (e.g. `"openai-search-agent"`).
    pub agent_id: String,
    /// Policy group name referenced by `allow-agent` (e.g. `"verified-ai-agents"`).
    pub group: String,
    /// Raw 32-byte Ed25519 public key.
    pub public_key: [u8; 32],
}

/// Lock-free registry of trusted Ed25519 agent keys keyed by RFC 9421 `keyid`.
#[derive(Debug, Default)]
pub struct AgentKeyRegistry {
    keys: ArcSwap<HashMap<String, RegisteredAgent>>,
}

impl AgentKeyRegistry {
    /// Creates an empty key registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers or replaces an Ed25519 verifying key under `keyid` using atomic RCU.
    #[allow(clippy::needless_pass_by_value)]
    pub fn register(&self, keyid: impl Into<String>, agent: RegisteredAgent) {
        let keyid = keyid.into();
        self.keys.rcu(|current| {
            let mut next = (**current).clone();
            next.insert(keyid.clone(), agent.clone());
            next
        });
    }

    /// Removes a previously registered Ed25519 verifying key by `keyid` using atomic RCU.
    pub fn remove(&self, keyid: &str) {
        self.keys.rcu(|current| {
            let mut next = (**current).clone();
            next.remove(keyid);
            next
        });
    }

    /// Atomically replaces the entire key table with `keys`.
    pub fn replace_all(&self, keys: HashMap<String, RegisteredAgent>) {
        self.keys.store(Arc::new(keys));
    }

    /// Looks up a registered agent by RFC 9421 `keyid`.
    #[must_use]
    pub fn get(&self, keyid: &str) -> Option<RegisteredAgent> {
        self.keys.load().get(keyid).cloned()
    }

    /// Loads inline `agent-key` directives and an optional `agent-keys-file` JSON registry
    /// from [`BotAuthConfig`] into this registry atomically (`BOT-1`).
    ///
    /// # Errors
    /// Returns a descriptive error string if any public key fails to decode or the key file
    /// cannot be safely read as a bounded regular file.
    pub fn load_from_bot_auth_config(&self, cfg: &BotAuthConfig) -> Result<usize, String> {
        let mut count = 0_usize;

        for entry in &cfg.agent_keys {
            let pk = decode_ed25519_pubkey(&entry.ed25519_b64).map_err(|err| {
                format!(
                    "invalid Ed25519 key for bot-auth agent-key '{}': {err}",
                    entry.key_id
                )
            })?;
            self.register(
                entry.key_id.clone(),
                RegisteredAgent {
                    agent_id: entry.agent_id.clone(),
                    group: entry.group.clone(),
                    public_key: pk,
                },
            );
            count = count.saturating_add(1);
        }

        if let Some(path_str) = &cfg.agent_keys_file {
            use std::fs::File;
            use std::io::Read as _;

            const MAX_AGENT_KEYS_FILE_BYTES: u64 = 256 * 1024;
            #[derive(serde::Deserialize)]
            struct JsonAgentKey {
                key_id: String,
                #[serde(default)]
                agent_id: Option<String>,
                group: String,
                ed25519: String,
            }
            #[derive(serde::Deserialize)]
            #[serde(untagged)]
            enum JsonAgentKeyFile {
                List(Vec<JsonAgentKey>),
                Wrapped { keys: Vec<JsonAgentKey> },
            }

            let file = File::open(path_str).map_err(|err| {
                format!("failed to open bot-auth agent-keys-file '{path_str}': {err}")
            })?;
            let meta = file.metadata().map_err(|err| {
                format!("failed to stat bot-auth agent-keys-file '{path_str}': {err}")
            })?;
            if !meta.is_file() {
                return Err(format!(
                    "bot-auth agent-keys-file '{path_str}' is not a regular file"
                ));
            }
            let mut raw = Vec::new();
            file.take(MAX_AGENT_KEYS_FILE_BYTES.saturating_add(1))
                .read_to_end(&mut raw)
                .map_err(|err| {
                    format!("failed to read bot-auth agent-keys-file '{path_str}': {err}")
                })?;
            if (raw.len() as u64) > MAX_AGENT_KEYS_FILE_BYTES {
                return Err(format!(
                    "bot-auth agent-keys-file '{path_str}' exceeds {MAX_AGENT_KEYS_FILE_BYTES} bytes"
                ));
            }

            let parsed: JsonAgentKeyFile = serde_json::from_slice(&raw).map_err(|err| {
                format!("invalid JSON in bot-auth agent-keys-file '{path_str}': {err}")
            })?;
            let items = match parsed {
                JsonAgentKeyFile::List(v) | JsonAgentKeyFile::Wrapped { keys: v } => v,
            };
            for item in items {
                let pk = decode_ed25519_pubkey(&item.ed25519).map_err(|err| {
                    format!(
                        "invalid Ed25519 key for '{}' in '{path_str}': {err}",
                        item.key_id
                    )
                })?;
                let agent_id = item.agent_id.unwrap_or_else(|| item.key_id.clone());
                self.register(
                    item.key_id,
                    RegisteredAgent {
                        agent_id,
                        group: item.group,
                        public_key: pk,
                    },
                );
                count = count.saturating_add(1);
            }
        }

        Ok(count)
    }
}

fn decode_ed25519_pubkey(raw: &str) -> Result<[u8; 32], String> {
    let trimmed = raw.trim();
    let b64 = trimmed
        .strip_prefix("miraserve-ed25519-pub:")
        .unwrap_or(trimmed);
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64.as_bytes()))
        .map_err(|err| format!("base64 decode failed: {err}"))?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| format!("expected 32-byte Ed25519 key, got {} bytes", decoded.len()))
}

/// Verified cryptographic identity extracted from an RFC 9421 HTTP Message Signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAgent {
    /// Verified agent identifier.
    pub agent_id: String,
    /// Policy group the agent belongs to.
    pub group: String,
    /// RFC 9421 `keyid` that matched.
    pub keyid: String,
}

/// Outcome of evaluating [`BotAuthGuard`] on an incoming request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BotAuthOutcome {
    /// Normal non-AI request or allowed unverified request.
    Pass {
        /// Whether Markdown negotiation should be preferred.
        serve_markdown: bool,
    },
    /// Cryptographically verified RFC 9421 AI agent.
    Verified {
        /// Verified agent identity.
        agent: VerifiedAgent,
        /// Whether `allow-agent ... serve-markdown=true` matched.
        serve_markdown: bool,
    },
    /// Unverified AI crawler throttled by GCRA rate limit (`429`).
    Throttle {
        /// Seconds before retry.
        retry_after_secs: u64,
    },
    /// Unverified or unauthorized AI crawler rejected or challenged (`403`).
    Reject {
        /// HTTP status code (`403`).
        status: StatusCode,
        /// Human-readable reason.
        reason: &'static str,
        /// Whether a Web Bot Auth challenge header should be attached.
        challenge: bool,
    },
}

/// Runtime guard enforcing `site.bot-auth { ... }` configuration.
#[derive(Debug)]
pub struct BotAuthGuard {
    config: BotAuthConfig,
    registry: Arc<AgentKeyRegistry>,
    /// Optional engine-level runtime key registry for programmatically registered keys,
    /// kept distinct from per-site KDL-loaded keys so reloads cleanly revoke removed KDL keys.
    fallback_registry: Option<Arc<AgentKeyRegistry>>,
    unverified_throttle: GcraRateLimiter,
}

impl BotAuthGuard {
    /// Creates a new [`BotAuthGuard`] backed by a shared [`AgentKeyRegistry`].
    #[must_use]
    pub fn new(config: BotAuthConfig, registry: Arc<AgentKeyRegistry>) -> Self {
        Self::new_with_fallback(config, registry, None)
    }

    /// Creates a new [`BotAuthGuard`] with an isolated per-site key registry (atomically
    /// replaced on hot reload) and an optional engine-level programmatic fallback registry.
    #[must_use]
    pub fn new_with_fallback(
        config: BotAuthConfig,
        registry: Arc<AgentKeyRegistry>,
        fallback_registry: Option<Arc<AgentKeyRegistry>>,
    ) -> Self {
        Self {
            config,
            registry,
            fallback_registry,
            // Default throttle for unverified AI user-agents: 10 req/min, burst 3 per IP.
            unverified_throttle: GcraRateLimiter::per_ip(10, Duration::from_secs(60), 3),
        }
    }

    /// Evaluates an incoming HTTP request for RFC 9421 Web Bot Auth and unverified AI UAs.
    ///
    /// Fails closed (403) if RFC 9421 signature headers are supplied but invalid, and
    /// enforces per-site `allow-agent` admission when non-empty.
    #[must_use]
    pub fn evaluate(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        client_ip: Option<IpAddr>,
    ) -> BotAuthOutcome {
        self.evaluate_with_scheme(method, uri, headers, client_ip, "https")
    }

    fn is_web_bot_auth_signature(&self, headers: &HeaderMap) -> bool {
        let mut inputs = headers.get_all("signature-input").iter();
        let Some(first) = inputs.next() else {
            return false;
        };
        let Ok(raw) = first.to_str() else {
            return false;
        };
        if inputs.next().is_some() {
            return raw.contains("web-bot-auth");
        }
        let Ok(parsed) = parse_signature_input(raw) else {
            return raw.contains("web-bot-auth");
        };
        if parsed.tag.as_deref() == Some("web-bot-auth") {
            return true;
        }
        if let Some(kid) = parsed.keyid.as_deref() {
            if self.registry.get(kid).is_some() {
                return true;
            }
            if self
                .fallback_registry
                .as_ref()
                .is_some_and(|fb| fb.get(kid).is_some())
            {
                return true;
            }
        }
        false
    }

    /// Evaluates an incoming HTTP request with an explicit connection scheme (`"https"` / `"http"`).
    #[must_use]
    pub fn evaluate_with_scheme(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        client_ip: Option<IpAddr>,
        connection_scheme: &str,
    ) -> BotAuthOutcome {
        // 1. Claim RFC 9421 verification ONLY for requests targeting Web Bot Auth (explicit
        //    `tag="web-bot-auth"` OR a `keyid` registered in this site's bot registry) so
        //    unrelated `Signature` headers (ActivityPub, signed webhooks) pass through (`R2-BOT-1`).
        if self.config.verify_rfc9421 && self.is_web_bot_auth_signature(headers) {
            let now = current_unix_secs();
            let verify_res = verify_rfc9421_request_with_scheme(
                method,
                uri,
                headers,
                &self.registry,
                now,
                connection_scheme,
            )
            .or_else(|err| {
                if err == "unknown RFC 9421 keyid"
                    && let Some(fallback) = &self.fallback_registry
                {
                    verify_rfc9421_request_with_scheme(
                        method,
                        uri,
                        headers,
                        fallback,
                        now,
                        connection_scheme,
                    )
                } else {
                    Err(err)
                }
            });
            match verify_res {
                Ok(verified) => {
                    if !self.config.allow_agents.is_empty() {
                        let matching_rule = self.config.allow_agents.iter().find(|rule| {
                            rule.name == verified.agent_id
                                || rule.name == verified.group
                                || rule.name == "*"
                        });
                        let Some(rule) = matching_rule else {
                            return BotAuthOutcome::Reject {
                                status: StatusCode::FORBIDDEN,
                                reason: "verified agent is not permitted by site allow-agent policy",
                                challenge: false,
                            };
                        };
                        return BotAuthOutcome::Verified {
                            agent: verified,
                            serve_markdown: rule.serve_markdown,
                        };
                    }
                    return BotAuthOutcome::Verified {
                        agent: verified,
                        serve_markdown: false,
                    };
                }
                Err(reason) => {
                    // Fail closed: invalid or tampered RFC 9421 signature NEVER falls through to Pass!
                    return BotAuthOutcome::Reject {
                        status: StatusCode::FORBIDDEN,
                        reason,
                        challenge: true,
                    };
                }
            }
        }

        // 2. Check if User-Agent declares an AI crawler/bot without valid RFC 9421 proof.
        if is_declared_ai_user_agent(headers) {
            return match self.config.on_unverified_ai_ua {
                UnverifiedBotAction::Allow => BotAuthOutcome::Pass {
                    serve_markdown: false,
                },
                UnverifiedBotAction::Throttle => {
                    let decision = self
                        .unverified_throttle
                        .check_request(client_ip, headers, None);
                    if decision.allowed {
                        BotAuthOutcome::Pass {
                            serve_markdown: false,
                        }
                    } else {
                        BotAuthOutcome::Throttle {
                            retry_after_secs: decision.retry_after_secs,
                        }
                    }
                }
                UnverifiedBotAction::Challenge => BotAuthOutcome::Reject {
                    status: StatusCode::FORBIDDEN,
                    reason: "RFC 9421 Web Bot Auth signature required for AI agents",
                    challenge: true,
                },
                UnverifiedBotAction::Block => BotAuthOutcome::Reject {
                    status: StatusCode::FORBIDDEN,
                    reason: "unverified AI user-agent blocked",
                    challenge: false,
                },
            };
        }

        BotAuthOutcome::Pass {
            serve_markdown: false,
        }
    }
}

/// Returns `true` if the `User-Agent` header matches a known AI crawler/agent token.
#[must_use]
pub fn is_declared_ai_user_agent(headers: &HeaderMap) -> bool {
    headers
        .get_all(USER_AGENT)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|ua| {
            let lower = ua.to_ascii_lowercase();
            KNOWN_AI_USER_AGENTS.iter().any(|tok| lower.contains(tok))
        })
}

/// Verifies an RFC 9421 Ed25519 HTTP Message Signature (`Signature-Input` + `Signature`)
/// assuming `"https"` connection scheme.
///
/// # Errors
/// Returns a static error reason if headers are malformed, missing mandatory covered
/// components (`@authority`, `@method`, `@path`, and `@query` when present), missing
/// `tag="web-bot-auth"`, missing/expired/overlong replay window, unknown `keyid`, or
/// Ed25519 signature verification fails.
pub fn verify_rfc9421_request(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    registry: &AgentKeyRegistry,
    now_unix: u64,
) -> Result<VerifiedAgent, &'static str> {
    verify_rfc9421_request_with_scheme(method, uri, headers, registry, now_unix, "https")
}

/// Verifies an RFC 9421 Ed25519 HTTP Message Signature with an explicit connection scheme.
///
/// # Errors
/// Returns a static error reason on any structural, freshness, policy, or cryptographic failure.
pub fn verify_rfc9421_request_with_scheme(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    registry: &AgentKeyRegistry,
    now_unix: u64,
    connection_scheme: &str,
) -> Result<VerifiedAgent, &'static str> {
    let mut sig_inputs = headers.get_all("signature-input").iter();
    let sig_input_raw = sig_inputs
        .next()
        .and_then(|v| v.to_str().ok())
        .ok_or("missing Signature-Input header")?;
    if sig_inputs.next().is_some() {
        return Err("multiple Signature-Input headers are forbidden");
    }

    let mut sigs = headers.get_all("signature").iter();
    let sig_raw = sigs
        .next()
        .and_then(|v| v.to_str().ok())
        .ok_or("missing Signature header")?;
    if sigs.next().is_some() {
        return Err("multiple Signature headers are forbidden");
    }

    let parsed_input = parse_signature_input(sig_input_raw)?;

    // Enforce unique covered components and mandatory request-binding components.
    let mut seen = HashSet::with_capacity(parsed_input.components.len());
    for &comp in &parsed_input.components {
        if !seen.insert(comp) {
            return Err("duplicate component identifier in Signature-Input");
        }
    }
    if !seen.contains("@authority") || !seen.contains("@method") || !seen.contains("@path") {
        return Err("Signature-Input must cover @authority, @method, and @path");
    }
    if uri.query().is_some() && !seen.contains("@query") {
        return Err("Signature-Input must cover @query when request contains a query string");
    }

    // Enforce Web Bot Auth domain separation tag.
    if parsed_input.tag.as_deref() != Some("web-bot-auth") {
        return Err("Signature-Input missing required tag=\"web-bot-auth\"");
    }

    // Enforce mandatory created & expires timestamps with bounded replay window (<= 300s).
    let created = parsed_input
        .created
        .ok_or("Signature-Input missing required created timestamp")?;
    let expires = parsed_input
        .expires
        .ok_or("Signature-Input missing required expires timestamp")?;

    if created > now_unix.saturating_add(MAX_CLOCK_SKEW_SECS) {
        return Err("signature created timestamp is in the future");
    }
    if now_unix > expires {
        return Err("signature has expired");
    }
    if expires < created || expires.saturating_sub(created) > MAX_CLOCK_SKEW_SECS {
        return Err("signature replay window (expires - created) exceeds maximum 300s");
    }
    if let Some(alg) = &parsed_input.alg
        && !alg.eq_ignore_ascii_case("ed25519")
    {
        return Err("unsupported RFC 9421 signature algorithm (expected ed25519)");
    }

    let keyid = parsed_input
        .keyid
        .as_deref()
        .ok_or("Signature-Input missing required keyid parameter")?;
    let agent = registry.get(keyid).ok_or("unknown RFC 9421 keyid")?;

    let sig_bytes = parse_signature_bytes(sig_raw, &parsed_input.label)?;
    let sig_base = build_signature_base(
        method,
        uri,
        headers,
        &parsed_input.components,
        parsed_input.raw_params,
        connection_scheme,
    )?;

    let verifier = UnparsedPublicKey::new(&ED25519, agent.public_key);
    verifier
        .verify(sig_base.as_bytes(), &sig_bytes)
        .map_err(|_| "RFC 9421 Ed25519 signature verification failed")?;

    Ok(VerifiedAgent {
        agent_id: agent.agent_id,
        group: agent.group,
        keyid: keyid.to_owned(),
    })
}

/// Signs an outgoing HTTP request with RFC 9421 `Signature-Input` and `Signature` headers
/// using Ed25519 (automatically covering `@query` when a query string is present).
///
/// # Errors
/// Returns an error description if required components are missing or header encoding fails.
pub fn sign_rfc9421_headers(
    method: &Method,
    uri: &Uri,
    headers: &mut HeaderMap,
    keyid: &str,
    key_pair: &Ed25519KeyPair,
    created: u64,
    expires: u64,
) -> Result<(), &'static str> {
    let (components, comp_str) = if uri.query().is_some() {
        (
            vec!["@method", "@authority", "@path", "@query"],
            "(\"@method\" \"@authority\" \"@path\" \"@query\")",
        )
    } else {
        (
            vec!["@method", "@authority", "@path"],
            "(\"@method\" \"@authority\" \"@path\")",
        )
    };
    let raw_params = format!(
        "{comp_str};created={created};expires={expires};keyid=\"{keyid}\";alg=\"ed25519\";tag=\"web-bot-auth\""
    );
    let sig_base = build_signature_base(method, uri, headers, &components, &raw_params, "https")?;
    let sig = key_pair.sign(sig_base.as_bytes());
    let sig_b64 = BASE64.encode(sig.as_ref());

    let input_val = HeaderValue::from_str(&format!("sig1={raw_params}"))
        .map_err(|_| "invalid Signature-Input header value")?;
    let sig_val = HeaderValue::from_str(&format!("sig1=:{sig_b64}:"))
        .map_err(|_| "invalid Signature header value")?;

    headers.insert(HeaderName::from_static("signature-input"), input_val);
    headers.insert(HeaderName::from_static("signature"), sig_val);
    Ok(())
}

struct ParsedSigInput<'a> {
    label: String,
    components: Vec<&'a str>,
    raw_params: &'a str,
    keyid: Option<String>,
    alg: Option<String>,
    tag: Option<String>,
    created: Option<u64>,
    expires: Option<u64>,
}

fn parse_signature_input(raw: &str) -> Result<ParsedSigInput<'_>, &'static str> {
    let trimmed = raw.trim();
    let (label_raw, rhs) = trimmed
        .split_once('=')
        .ok_or("Signature-Input missing '=' label separator")?;
    let label = label_raw.trim();
    if label.is_empty() {
        return Err("empty Signature-Input label");
    }

    let inner_start = rhs
        .find('(')
        .ok_or("Signature-Input missing component list '('")?;
    let inner_end = rhs.find(')').ok_or("Signature-Input missing closing ')'")?;
    if inner_end < inner_start {
        return Err("malformed Signature-Input component list");
    }

    let comp_slice = rhs
        .get(inner_start.saturating_add(1)..inner_end)
        .ok_or("invalid component slice")?;
    let mut components = Vec::new();
    for tok in comp_slice.split_whitespace() {
        let unquoted = tok
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .ok_or("RFC 9421 component identifiers must be quoted strings")?;
        components.push(unquoted);
    }
    if components.is_empty() {
        return Err("Signature-Input must cover at least one component");
    }

    let mut keyid = None;
    let mut alg = None;
    let mut tag = None;
    let mut created = None;
    let mut expires = None;

    let params_part = rhs.get(inner_end.saturating_add(1)..).unwrap_or("");
    for param in params_part.split(';').filter(|p| !p.trim().is_empty()) {
        let Some((k, v)) = param.trim().split_once('=') else {
            return Err("malformed RFC 9421 signature parameter");
        };
        let key = k.trim();
        let val_raw = v.trim();
        let val = val_raw.trim_matches('"');
        match key {
            "keyid" => keyid = Some(val.to_owned()),
            "alg" => alg = Some(val.to_owned()),
            "tag" => tag = Some(val.to_owned()),
            "created" => {
                // Reject malformed or duplicate created parameters instead of silently ignoring!
                if created.is_some() || val_raw.starts_with('"') {
                    return Err("invalid or duplicate created parameter");
                }
                let parsed = val_raw
                    .parse::<u64>()
                    .map_err(|_| "malformed RFC 9421 created integer")?;
                created = Some(parsed);
            }
            "expires" => {
                if expires.is_some() || val_raw.starts_with('"') {
                    return Err("invalid or duplicate expires parameter");
                }
                let parsed = val_raw
                    .parse::<u64>()
                    .map_err(|_| "malformed RFC 9421 expires integer")?;
                expires = Some(parsed);
            }
            _ => {}
        }
    }

    Ok(ParsedSigInput {
        label: label.to_owned(),
        components,
        raw_params: rhs.trim(),
        keyid,
        alg,
        tag,
        created,
        expires,
    })
}

fn parse_signature_bytes(raw: &str, expected_label: &str) -> Result<Vec<u8>, &'static str> {
    for member in raw.split(',') {
        let Some((label, val)) = member.trim().split_once('=') else {
            continue;
        };
        if label.trim() != expected_label {
            continue;
        }
        let b64 = val
            .trim()
            .strip_prefix(':')
            .and_then(|s| s.strip_suffix(':'))
            .ok_or("RFC 9421 Signature byte sequence must be wrapped in ':'")?;
        return BASE64
            .decode(b64)
            .map_err(|_| "invalid base64 in RFC 9421 Signature header");
    }
    Err("Signature header missing matching label")
}

fn build_signature_base(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    components: &[&str],
    raw_params: &str,
    connection_scheme: &str,
) -> Result<String, &'static str> {
    let mut base = String::new();
    for &comp in components {
        let val = resolve_component(comp, method, uri, headers, connection_scheme)?;
        let _ = writeln!(base, "\"{comp}\": {val}");
    }
    let _ = write!(base, "\"@signature-params\": {raw_params}");
    Ok(base)
}

fn resolve_component(
    comp: &str,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    connection_scheme: &str,
) -> Result<String, &'static str> {
    match comp {
        "@method" => Ok(method.as_str().to_owned()),
        "@path" => Ok(uri.path().to_owned()),
        "@query" => Ok(uri
            .query()
            .map_or_else(|| "?".to_owned(), |q| format!("?{q}"))),
        "@scheme" => {
            if connection_scheme.eq_ignore_ascii_case("https") {
                Ok(uri
                    .scheme_str()
                    .unwrap_or(connection_scheme)
                    .to_ascii_lowercase())
            } else {
                Ok(connection_scheme.to_ascii_lowercase())
            }
        }
        "@authority" => {
            if let Some(host) = headers.get(HOST).and_then(|v| v.to_str().ok()) {
                Ok(host.trim().to_ascii_lowercase())
            } else if let Some(auth) = uri.authority() {
                Ok(auth.as_str().to_ascii_lowercase())
            } else {
                Err("missing @authority / Host header")
            }
        }
        header_name => {
            // RFC 9421 §2.1: Combine all occurrences of a multi-valued field with ", ".
            let mut joined = String::new();
            let mut count = 0_usize;
            for v in headers.get_all(header_name) {
                let s = v.to_str().map_err(|_| "non-UTF-8 covered HTTP header")?;
                if count > 0 {
                    joined.push_str(", ");
                }
                joined.push_str(s.trim());
                count = count.saturating_add(1);
            }
            if count == 0 {
                return Err("covered HTTP header missing from request");
            }
            Ok(joined)
        }
    }
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

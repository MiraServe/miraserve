//! Strict, fail-closed KDL parser converting raw KDL documents into typed [`Config`]
//! structs while recording exact source spans for semantic validation.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use kdl::{KdlDocument, KdlEntry, KdlNode, KdlValue};
use miette::SourceSpan;

use crate::error::{ConfigIssue, MAX_CONFIG_FILE_BYTES};
use crate::schema::Workers;
use crate::schema::{
    AccessRule, AcmeChallenge, AcmeConfig, AiPublishConfig, AllowedAgentConfig, AuditLogMode,
    BasicAuthConfig, BotAgentKeyConfig, BotAuthConfig, Config, DotfilesPolicy, ErrorPagesConfig,
    FastCgiConfig, FastCgiTarget, HeaderAction, HeaderRule, HeaderStatusMatcher, HealthCheckConfig,
    KeyIsolation, LimitsConfig, ListenConfig, LoadBalancePolicy, MAX_ACCESS_RULES,
    MAX_HEADER_RULES, McpGatewayConfig, McpPublishEndpoint, PrecompressedPolicy, PreflightCheck,
    PublishAuthMode, RateLimitConfig, RateLimitKey, RedirectConfig, ReverseProxyConfig,
    RewriteAction, RewriteCondition, RewriteConditionKind, RewriteRule, RouteConfig, RouteHandler,
    SandboxConfig, SeccompMode, SecurityHeadersPolicy, ServerConfig, SignatureAlgorithm,
    SignatureRequirement, SiteConfig, SiteHttpMode, SitePreset, SiteTlsConfig, StaticConfig,
    StreamingFlushMode, TelemetryConfig, TimeoutsConfig, TlsConfig, TlsVersion, TryFilesConfig,
    UnverifiedBotAction, UpstreamConfig, UpstreamTlsConfig, WasmPluginConfig,
    header_rule_rejection, parse_header_status_list,
};
use crate::units::{BindAddr, ByteSize, IpCidr, Protocol, parse_duration};

/// Index mapping semantic configuration paths (e.g. `"site[1].tls.compat-tls-1-2"`)
/// to their byte spans in the original KDL source text.
pub(crate) type SpanMap = HashMap<String, SourceSpan>;

/// Output of the parsing stage before semantic/security validation.
pub(crate) struct ParsedDocument {
    pub(crate) config: Config,
    pub(crate) spans: SpanMap,
    pub(crate) errors: Vec<ConfigIssue>,
}

/// Maximum permitted KDL block (`{ ... }`) or block-comment (`/* ... */`) nesting depth.
///
/// Defends against recursive-descent parser stack-overflow DoS on hostile inputs
/// (Threat Model T1). Legitimate MiraServe configs have nesting depth <= 5.
const MAX_KDL_NESTING_DEPTH: usize = 32;

/// Parses a KDL configuration string into a [`ParsedDocument`].
///
/// Accepts both KDL v2 (`#true`) and KDL v1 (`true`) syntax via `kdl`'s `v1-fallback`.
pub(crate) fn parse_document(source: &str) -> ParsedDocument {
    let sanitized = match preflight_input_safety(source) {
        Ok(s) => s,
        Err(issue) => {
            return ParsedDocument {
                config: Config {
                    server: ServerConfig::default(),
                    sites: Vec::new(),
                },
                spans: SpanMap::new(),
                errors: vec![*issue],
            };
        }
    };

    let doc = match KdlDocument::parse(sanitized.as_ref()) {
        Ok(doc) => doc,
        Err(err) => {
            let mut errors = Vec::new();
            for diag in &err.diagnostics {
                let message = diag
                    .message
                    .clone()
                    .unwrap_or_else(|| "KDL syntax error".to_owned());
                let mut issue = ConfigIssue::error("E001", message, source, Some(diag.span));
                if let Some(label) = &diag.label {
                    issue = issue.with_label(label.clone());
                }
                if let Some(help) = &diag.help {
                    issue = issue.with_help(help.clone());
                }
                errors.push(issue);
            }
            if errors.is_empty() {
                errors.push(ConfigIssue::error("E001", err.to_string(), source, None));
            }
            return ParsedDocument {
                config: Config {
                    server: ServerConfig::default(),
                    sites: Vec::new(),
                },
                spans: SpanMap::new(),
                errors,
            };
        }
    };

    let mut ctx = ParserCtx::new(source);
    let config = ctx.parse_root(&doc);
    ParsedDocument {
        config,
        spans: ctx.spans,
        errors: ctx.errors,
    }
}

struct ParserCtx<'a> {
    source: &'a str,
    spans: SpanMap,
    errors: Vec<ConfigIssue>,
}

impl<'a> ParserCtx<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            spans: SpanMap::new(),
            errors: Vec::new(),
        }
    }

    fn record_span(&mut self, key: impl Into<String>, span: SourceSpan) {
        self.spans.insert(key.into(), span);
    }

    fn push_error(
        &mut self,
        code: &str,
        message: impl Into<String>,
        span: Option<SourceSpan>,
        help: Option<&str>,
    ) {
        let mut issue = ConfigIssue::error(code, message, self.source, span);
        if let Some(h) = help {
            issue = issue.with_help(h);
        }
        self.errors.push(issue);
    }

    fn parse_root(&mut self, doc: &KdlDocument) -> Config {
        let mut server: Option<ServerConfig> = None;
        let mut sites = Vec::new();

        for node in doc.nodes() {
            let name = node.name().value();
            match name {
                "server" => {
                    if server.is_some() {
                        self.push_error(
                            "E005",
                            "duplicate 'server' block (only one top-level 'server' block is allowed)",
                            Some(node.span()),
                            Some("merge all global server directives into a single 'server { ... }' block"),
                        );
                        continue;
                    }
                    self.record_span("server", node.span());
                    server = Some(self.parse_server(node));
                }
                "site" => {
                    let site_idx = sites.len();
                    self.record_span(format!("site[{site_idx}]"), node.span());
                    if let Some(site) = self.parse_site(node, site_idx) {
                        sites.push(site);
                    }
                }
                other => {
                    self.push_error(
                        "E002",
                        format!("unknown top-level directive '{other}'"),
                        Some(node.span()),
                        Some("allowed top-level directives are 'server' and 'site'"),
                    );
                }
            }
        }

        if server.is_none() {
            self.push_error(
                "E006",
                "missing required top-level 'server { ... }' block",
                None,
                Some("add a 'server { listen \":443\" }' block to configure network listeners"),
            );
        }

        Config {
            server: server.unwrap_or_default(),
            sites,
        }
    }

    fn parse_server(&mut self, node: &KdlNode) -> ServerConfig {
        self.expect_no_entries(node, "server");
        let Some(children) = self.expect_children(node, "server") else {
            return ServerConfig::default();
        };

        let mut config = ServerConfig::default();
        let mut seen_tls = false;
        let mut seen_sandbox = false;
        let mut seen_timeouts = false;
        let mut seen_limits = false;
        let mut seen_telemetry = false;

        for child in children.nodes() {
            match child.name().value() {
                "listen" => {
                    let idx = config.listeners.len();
                    self.record_span(format!("server.listen[{idx}]"), child.span());
                    if let Some(listen) = self.parse_listen(child) {
                        config.listeners.push(listen);
                    }
                }
                "tls" => {
                    if !self.mark_singleton(&mut seen_tls, "server.tls", child.span()) {
                        continue;
                    }
                    self.record_span("server.tls", child.span());
                    config.tls = self.parse_server_tls(child);
                }
                "sandbox" => {
                    if !self.mark_singleton(&mut seen_sandbox, "server.sandbox", child.span()) {
                        continue;
                    }
                    self.record_span("server.sandbox", child.span());
                    config.sandbox = self.parse_sandbox(child);
                }
                "timeouts" => {
                    if !self.mark_singleton(&mut seen_timeouts, "server.timeouts", child.span()) {
                        continue;
                    }
                    self.record_span("server.timeouts", child.span());
                    config.timeouts = self.parse_timeouts(child);
                }
                "limits" => {
                    if !self.mark_singleton(&mut seen_limits, "server.limits", child.span()) {
                        continue;
                    }
                    self.record_span("server.limits", child.span());
                    config.limits = self.parse_limits(child);
                }
                "telemetry" => {
                    if !self.mark_singleton(&mut seen_telemetry, "server.telemetry", child.span()) {
                        continue;
                    }
                    self.record_span("server.telemetry", child.span());
                    config.telemetry = self.parse_telemetry(child);
                }
                "workers" => {
                    self.record_span("server.workers", child.span());
                    if let Some(workers) = self.parse_workers(child) {
                        config.workers = workers;
                    }
                }
                "acme-webroot" => {
                    self.record_span("server.acme-webroot", child.span());
                    if let Some(val) = self.expect_single_string_node(child) {
                        config.acme_webroot = Some(val.to_owned());
                    }
                }
                "allow-docroot" => {
                    self.record_span("server.allow-docroot", child.span());
                    if let Some(items) = self.parse_string_list_node(child, "allow-docroot") {
                        for item in items {
                            let idx = config.allow_docroots.len();
                            self.record_span(format!("server.allow-docroot[{idx}]"), child.span());
                            config.allow_docroots.push(item);
                        }
                    }
                }
                other => {
                    self.push_error(
                        "E002",
                        format!("unknown directive '{other}' inside 'server'"),
                        Some(child.span()),
                        Some("allowed directives in 'server' are: listen, tls, sandbox, timeouts, limits, telemetry, allow-docroot, acme-webroot, workers"),
                    );
                }
            }
        }

        config
    }

    fn parse_listen(&mut self, node: &KdlNode) -> Option<ListenConfig> {
        self.expect_no_children(node, "listen");
        let (args, props) = self.split_entries(node);

        let addr_entry = self
            .expect_exact_arg_count(&args, 1, "listen", node.span())
            .and_then(|()| args.first().copied())?;

        let addr_str = self.expect_string(addr_entry, "listen address")?;
        let addr = match BindAddr::parse(addr_str) {
            Ok(a) => a,
            Err(err) => {
                self.push_error(
                    "E101",
                    err.to_string(),
                    Some(addr_entry.span()),
                    Some("examples: \":443\", \"0.0.0.0:443\", \"[::]:443\""),
                );
                return None;
            }
        };

        let mut protocols: Option<Vec<Protocol>> = None;
        let mut redirect_https = false;

        for (key, entry) in props {
            match key {
                "protocols" => {
                    if let Some(raw) = self.expect_string(entry, "protocols") {
                        match Protocol::parse_list(raw) {
                            Ok(parsed) => protocols = Some(parsed),
                            Err(err) => {
                                self.push_error(
                                    "E103",
                                    err.to_string(),
                                    Some(entry.span()),
                                    Some("use a comma-separated subset of h3, h2, h1 (e.g. \"h3,h2,h1\")"),
                                );
                            }
                        }
                    }
                }
                "redirect-https" => {
                    if let Some(flag) = self.expect_bool(entry, "redirect-https") {
                        redirect_https = flag;
                    }
                }
                other => {
                    self.push_error(
                        "E003",
                        format!("unknown property '{other}' on 'listen'"),
                        Some(entry.span()),
                        Some("allowed properties on 'listen' are: protocols, redirect-https"),
                    );
                }
            }
        }

        let resolved_protocols = protocols.unwrap_or_else(|| {
            if redirect_https {
                vec![Protocol::H1]
            } else {
                vec![Protocol::H3, Protocol::H2, Protocol::H1]
            }
        });

        Some(ListenConfig {
            addr,
            protocols: resolved_protocols,
            redirect_https,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn parse_server_tls(&mut self, node: &KdlNode) -> TlsConfig {
        self.expect_no_entries(node, "tls");
        let Some(children) = self.expect_children(node, "tls") else {
            return TlsConfig::default();
        };

        let mut cfg = TlsConfig::default();
        let mut seen = HashSet::new();

        for child in children.nodes() {
            let name = child.name().value();
            if !seen.insert(name.to_owned()) {
                self.push_error(
                    "E005",
                    format!("duplicate directive '{name}' inside 'server.tls'"),
                    Some(child.span()),
                    None,
                );
                continue;
            }

            match name {
                "min-version" => {
                    self.record_span("server.tls.min-version", child.span());
                    if let Some(ver) = self.expect_single_string_node(child) {
                        match ver {
                            "1.3" => cfg.min_version = TlsVersion::V1_3,
                            "1.2" => cfg.min_version = TlsVersion::V1_2,
                            other => {
                                self.push_error(
                                    "E104",
                                    format!("unsupported or insecure TLS version '{other}'"),
                                    Some(child.span()),
                                    Some("TLS 1.0 and 1.1 are forbidden; use \"1.3\" (default) or \"1.2\""),
                                );
                            }
                        }
                    }
                }
                "pqc-hybrid" => {
                    self.record_span("server.tls.pqc-hybrid", child.span());
                    if let Some(val) = self.expect_single_bool_node(child) {
                        cfg.pqc_hybrid = val;
                    }
                }
                "key-isolation" => {
                    self.record_span("server.tls.key-isolation", child.span());
                    if let Some(mode) = self.expect_single_string_node(child) {
                        match mode {
                            "in-process" => cfg.key_isolation = KeyIsolation::InProcess,
                            "split-daemon" => cfg.key_isolation = KeyIsolation::SplitDaemon,
                            other => {
                                self.push_error(
                                    "E203",
                                    format!("invalid key-isolation mode '{other}'"),
                                    Some(child.span()),
                                    Some("allowed values are \"in-process\" and \"split-daemon\""),
                                );
                            }
                        }
                    }
                }
                "keyd-socket" => {
                    self.record_span("server.tls.keyd-socket", child.span());
                    if let Some(val) = self.expect_single_string_node(child) {
                        cfg.keyd_socket = Some(val.to_owned());
                    }
                }
                "ech" => {
                    self.record_span("server.tls.ech", child.span());
                    if let Some(val) = self.expect_single_bool_node(child) {
                        cfg.ech = val;
                    }
                }
                "ech-public-name" => {
                    self.record_span("server.tls.ech-public-name", child.span());
                    if let Some(val) = self.expect_single_string_node(child) {
                        cfg.ech_public_name = Some(val.to_owned());
                    }
                }
                "ech-rotate" => {
                    self.record_span("server.tls.ech-rotate", child.span());
                    if let Some(raw) = self.expect_single_string_node(child) {
                        match parse_duration(raw) {
                            Ok(d) => cfg.ech_rotate_interval = d,
                            Err(err) => {
                                self.push_error(
                                    "E007",
                                    format!("invalid 'ech-rotate' duration: {err}"),
                                    Some(child.span()),
                                    Some("examples: \"1h\", \"30m\""),
                                );
                            }
                        }
                    }
                }
                "cert" => {
                    self.record_span("server.tls.cert", child.span());
                    if let Some(val) = self.expect_single_string_node(child) {
                        cfg.cert = Some(val.to_owned());
                    }
                }
                "key" => {
                    self.record_span("server.tls.key", child.span());
                    if let Some(val) = self.expect_single_string_node(child) {
                        cfg.key = Some(val.to_owned());
                    }
                }
                "client-ca" => {
                    self.record_span("server.tls.client-ca", child.span());
                    if let Some(val) = self.expect_single_string_node(child) {
                        cfg.client_ca = Some(val.to_owned());
                    }
                }
                "acme" => {
                    self.record_span("server.tls.acme", child.span());
                    cfg.acme = self.parse_acme(child);
                }
                other => {
                    self.push_error(
                        "E002",
                        format!("unknown directive '{other}' inside 'server.tls'"),
                        Some(child.span()),
                        Some("allowed directives in 'server.tls' are: min-version, pqc-hybrid, key-isolation, keyd-socket, ech, ech-public-name, ech-rotate, cert, key, client-ca, acme"),
                    );
                }
            }
        }

        cfg
    }

    fn parse_acme(&mut self, node: &KdlNode) -> Option<AcmeConfig> {
        self.expect_no_entries(node, "acme");
        let children = self.expect_children(node, "acme")?;

        let mut email: Option<String> = None;
        let mut challenge = AcmeChallenge::TlsAlpn01;
        let mut short_lived = true;
        let mut ari = true;
        let mut directory: Option<String> = None;
        let mut seen = HashSet::new();

        for child in children.nodes() {
            let name = child.name().value();
            if !seen.insert(name.to_owned()) {
                self.push_error(
                    "E005",
                    format!("duplicate directive '{name}' inside 'acme'"),
                    Some(child.span()),
                    None,
                );
                continue;
            }
            match name {
                "email" => {
                    self.record_span("server.tls.acme.email", child.span());
                    if let Some(val) = self.expect_single_string_node(child) {
                        email = Some(val.to_owned());
                    }
                }
                "challenge" => {
                    self.record_span("server.tls.acme.challenge", child.span());
                    if let Some(val) = self.expect_single_string_node(child) {
                        match val {
                            "tls-alpn-01" => challenge = AcmeChallenge::TlsAlpn01,
                            "http-01" => challenge = AcmeChallenge::Http01,
                            "dns-01" => challenge = AcmeChallenge::Dns01,
                            other => {
                                self.push_error(
                                    "E106",
                                    format!("unknown ACME challenge '{other}'"),
                                    Some(child.span()),
                                    Some("allowed challenges are: \"tls-alpn-01\", \"http-01\", \"dns-01\""),
                                );
                            }
                        }
                    }
                }
                "short-lived" => {
                    if let Some(val) = self.expect_single_bool_node(child) {
                        short_lived = val;
                    }
                }
                "ari" => {
                    if let Some(val) = self.expect_single_bool_node(child) {
                        ari = val;
                    }
                }
                "directory" => {
                    self.record_span("server.tls.acme.directory", child.span());
                    if let Some(val) = self.expect_single_string_node(child) {
                        directory = Some(val.to_owned());
                    }
                }
                other => {
                    self.push_error(
                        "E002",
                        format!("unknown directive '{other}' inside 'acme'"),
                        Some(child.span()),
                        Some("allowed directives in 'acme' are: email, challenge, short-lived, ari, directory"),
                    );
                }
            }
        }

        let Some(email) = email else {
            self.push_error(
                "E006",
                "'acme' block is missing required 'email' directive",
                Some(node.span()),
                Some("add: email \"ops@example.com\""),
            );
            return None;
        };

        Some(AcmeConfig {
            email,
            challenge,
            short_lived,
            ari,
            directory,
        })
    }

    fn parse_sandbox(&mut self, node: &KdlNode) -> SandboxConfig {
        self.expect_no_entries(node, "sandbox");
        let Some(children) = self.expect_children(node, "sandbox") else {
            return SandboxConfig::default();
        };

        let mut cfg = SandboxConfig::default();
        let mut seen = HashSet::new();

        for child in children.nodes() {
            let name = child.name().value();
            if !seen.insert(name.to_owned()) {
                self.push_error(
                    "E005",
                    format!("duplicate directive '{name}' inside 'sandbox'"),
                    Some(child.span()),
                    None,
                );
                continue;
            }
            match name {
                "user" => {
                    self.record_span("server.sandbox.user", child.span());
                    if let Some(val) = self.expect_single_string_node(child) {
                        cfg.user = Some(val.to_owned());
                    }
                }
                "group" => {
                    self.record_span("server.sandbox.group", child.span());
                    if let Some(val) = self.expect_single_string_node(child) {
                        cfg.group = Some(val.to_owned());
                    }
                }
                "read-tree" => {
                    self.record_span("server.sandbox.read-tree", child.span());
                    if let Some(items) = self.parse_string_list_node(child, "read-tree") {
                        cfg.read_trees = items;
                    }
                }
                "socket-tree" => {
                    self.record_span("server.sandbox.socket-tree", child.span());
                    if let Some(items) = self.parse_string_list_node(child, "socket-tree") {
                        cfg.socket_trees = items;
                    }
                }
                "landlock" => {
                    self.record_span("server.sandbox.landlock", child.span());
                    if let Some(val) = self.expect_single_bool_node(child) {
                        cfg.landlock = val;
                    }
                }
                "seccomp" => {
                    self.record_span("server.sandbox.seccomp", child.span());
                    if let Some(val) = self.expect_single_string_node(child) {
                        match val {
                            "strict" => cfg.seccomp = SeccompMode::Strict,
                            "standard" => cfg.seccomp = SeccompMode::Standard,
                            "off" => cfg.seccomp = SeccompMode::Off,
                            other => {
                                self.push_error(
                                    "E203",
                                    format!("invalid seccomp mode '{other}'"),
                                    Some(child.span()),
                                    Some("allowed values are: \"strict\", \"standard\", \"off\""),
                                );
                            }
                        }
                    }
                }
                other => {
                    self.push_error(
                        "E002",
                        format!("unknown directive '{other}' inside 'sandbox'"),
                        Some(child.span()),
                        Some("allowed directives in 'sandbox' are: user, group, landlock, seccomp, read-tree, socket-tree"),
                    );
                }
            }
        }

        cfg
    }

    #[allow(clippy::too_many_lines)]
    fn parse_timeouts(&mut self, node: &KdlNode) -> TimeoutsConfig {
        self.expect_no_entries(node, "timeouts");
        let Some(children) = self.expect_children(node, "timeouts") else {
            return TimeoutsConfig::default();
        };

        let mut cfg = TimeoutsConfig::default();
        let mut seen = HashSet::new();

        let mut min_rate_name: Option<&str> = None;
        for child in children.nodes() {
            let name = child.name().value();
            if !seen.insert(name.to_owned()) {
                self.push_error(
                    "E005",
                    format!("duplicate directive '{name}' inside 'timeouts'"),
                    Some(child.span()),
                    None,
                );
                continue;
            }
            match name {
                "tls-handshake" => {
                    self.record_span("server.timeouts.tls-handshake", child.span());
                    if let Some(d) = self.expect_single_duration_node(child) {
                        cfg.tls_handshake = d;
                    }
                }
                "header-read" => {
                    self.record_span("server.timeouts.header-read", child.span());
                    if let Some(d) = self.expect_single_duration_node(child) {
                        cfg.header_read = d;
                    }
                }
                "idle-keepalive" => {
                    self.record_span("server.timeouts.idle-keepalive", child.span());
                    if let Some(d) = self.expect_single_duration_node(child) {
                        cfg.idle_keepalive = d;
                    }
                }
                "graceful-drain" => {
                    self.record_span("server.timeouts.graceful-drain", child.span());
                    if let Some(d) = self.expect_single_duration_node(child) {
                        cfg.graceful_drain = d;
                    }
                }
                "body-idle-timeout" => {
                    self.record_span("server.timeouts.body-idle-timeout", child.span());
                    if let Some(d) = self.expect_single_duration_node(child) {
                        cfg.body_idle_timeout = d;
                    }
                }
                "max-body-duration" => {
                    self.record_span("server.timeouts.max-body-duration", child.span());
                    if let Some(d) = self.expect_single_duration_node(child) {
                        cfg.max_body_duration = d;
                    }
                }
                "min-body-rate-bps" => {
                    self.record_span("server.timeouts.min-body-rate-bps", child.span());
                    if let Some(v) = self.expect_single_u64_node(child) {
                        cfg.min_body_rate_bps = v;
                    }
                }
                "upstream-connect-timeout" => {
                    self.record_span("server.timeouts.upstream-connect-timeout", child.span());
                    if let Some(d) = self.expect_single_duration_node(child) {
                        cfg.upstream_connect = d;
                    }
                }
                "upstream-response-timeout" => {
                    self.record_span("server.timeouts.upstream-response-timeout", child.span());
                    if let Some(d) = self.expect_single_duration_node(child) {
                        cfg.upstream_response = d;
                    }
                }
                "upstream-body-idle-timeout" => {
                    self.record_span("server.timeouts.upstream-body-idle-timeout", child.span());
                    if let Some(d) = self.expect_single_duration_node(child) {
                        cfg.upstream_body_idle = d;
                    }
                }
                "response-write-idle" => {
                    self.record_span("server.timeouts.response-write-idle", child.span());
                    if let Some(d) = self.expect_single_duration_node(child) {
                        cfg.response_write_idle = d;
                    }
                }
                // `-bytes-per-sec` is the clear name; `-bps` (read by many as bits per second)
                // stays accepted. Setting both is refused rather than letting one win silently.
                name @ ("min-response-rate-bps" | "min-response-rate-bytes-per-sec") => {
                    self.record_span(format!("server.timeouts.{name}"), child.span());
                    if let Some(previous) = min_rate_name.replace(name) {
                        self.push_error(
                            "E003",
                            format!("'{name}' and '{previous}' are the same setting; use only 'min-response-rate-bytes-per-sec'"),
                            Some(child.span()),
                            Some("the value is in bytes per second, for example 2048"),
                        );
                    } else if let Some(v) = self.expect_single_u64_node(child) {
                        cfg.min_response_rate_bps = v;
                    }
                }
                other => {
                    self.push_error(
                        "E002",
                        format!("unknown directive '{other}' inside 'timeouts'"),
                        Some(child.span()),
                        Some("allowed directives in 'timeouts' are: tls-handshake, header-read, idle-keepalive, graceful-drain, body-idle-timeout, max-body-duration, min-body-rate-bps, upstream-connect-timeout, upstream-response-timeout, upstream-body-idle-timeout, response-write-idle, min-response-rate-bytes-per-sec (also accepted: min-response-rate-bps)"),
                    );
                }
            }
        }

        cfg
    }

    #[allow(clippy::too_many_lines, reason = "one arm per directive")]
    fn parse_limits(&mut self, node: &KdlNode) -> LimitsConfig {
        self.expect_no_entries(node, "limits");
        let Some(children) = self.expect_children(node, "limits") else {
            return LimitsConfig::default();
        };

        let mut cfg = LimitsConfig::default();
        let mut seen = HashSet::new();

        for child in children.nodes() {
            let name = child.name().value();
            if name != "trusted-proxies" && !seen.insert(name.to_owned()) {
                self.push_error(
                    "E005",
                    format!("duplicate directive '{name}' inside 'limits'"),
                    Some(child.span()),
                    None,
                );
                continue;
            }
            match name {
                "max-header-bytes" => {
                    self.record_span("server.limits.max-header-bytes", child.span());
                    if let Some(sz) = self.expect_single_byte_size_node(child) {
                        cfg.max_header_bytes = sz;
                    }
                }
                "max-body-bytes" => {
                    self.record_span("server.limits.max-body-bytes", child.span());
                    if let Some(sz) = self.expect_single_byte_size_node(child) {
                        cfg.max_body_bytes = sz;
                    }
                }
                "max-concurrent-streams" => {
                    self.record_span("server.limits.max-concurrent-streams", child.span());
                    if let Some(v) = self.expect_single_u32_node(child) {
                        cfg.max_concurrent_streams = v;
                    }
                }
                "max-h2-rst-stream-per-sec" => {
                    self.record_span("server.limits.max-h2-rst-stream-per-sec", child.span());
                    if let Some(v) = self.expect_single_u32_node(child) {
                        cfg.max_h2_rst_stream_per_sec = v;
                    }
                }
                "max-connections" => {
                    self.record_span("server.limits.max-connections", child.span());
                    if let Some(v) = self.expect_single_u32_node(child) {
                        cfg.max_connections = v;
                    }
                }
                "max-connections-per-ip" => {
                    self.record_span("server.limits.max-connections-per-ip", child.span());
                    if let Some(v) = self.expect_single_u32_node(child) {
                        cfg.max_connections_per_ip = v;
                    }
                }
                "max-streamed-answers-per-ip" => {
                    self.record_span("server.limits.max-streamed-answers-per-ip", child.span());
                    if let Some(v) = self.expect_single_u32_node(child) {
                        cfg.max_streamed_answers_per_ip = v;
                    }
                }
                "max-streamed-answers-per-backend" => {
                    self.record_span(
                        "server.limits.max-streamed-answers-per-backend",
                        child.span(),
                    );
                    if let Some(v) = self.expect_single_u32_node(child) {
                        cfg.max_streamed_answers_per_backend = v;
                    }
                }
                "ipv6-prefix-conn-multiplier" => {
                    self.record_span("server.limits.ipv6-prefix-conn-multiplier", child.span());
                    if let Some(v) = self.expect_single_u32_node(child) {
                        cfg.ipv6_prefix_conn_multiplier = v;
                    }
                }
                "trusted-proxies" => {
                    self.record_span("server.limits.trusted-proxies", child.span());
                    if let Some(items) = self.parse_string_list_node(child, "trusted-proxies") {
                        for raw in items {
                            match IpCidr::parse(&raw) {
                                Ok(cidr) => cfg.trusted_proxies.push(cidr),
                                Err(err) => {
                                    self.push_error(
                                        "E007",
                                        format!("invalid 'trusted-proxies' entry: {err}"),
                                        Some(child.span()),
                                        Some("examples: \"127.0.0.1/32\", \"192.168.1.10/32\", \"2001:db8:1::1/128\""),
                                    );
                                }
                            }
                        }
                    }
                }
                "file-cache-bytes" => {
                    self.record_span("server.limits.file-cache-bytes", child.span());
                    self.expect_no_children(child, "file-cache-bytes");
                    let (args, props) = self.split_entries(child);
                    for (prop, entry) in props {
                        self.push_error(
                            "E003",
                            format!("unexpected property '{prop}' on 'file-cache-bytes'"),
                            Some(entry.span()),
                            None,
                        );
                    }
                    if let Some(()) =
                        self.expect_exact_arg_count(&args, 1, "file-cache-bytes", child.span())
                        && let Some(arg) = args.first().copied()
                    {
                        match arg.value() {
                            KdlValue::String(raw) => match ByteSize::parse(raw) {
                                Ok(sz) => cfg.file_cache_bytes = sz,
                                Err(err) => {
                                    self.push_error(
                                        "E007",
                                        format!("invalid byte size for 'file-cache-bytes': {err}"),
                                        Some(arg.span()),
                                        Some("examples: \"64MiB\", \"16MiB\", \"0\" (0 disables the file cache globally)"),
                                    );
                                }
                            },
                            KdlValue::Integer(0) => {
                                cfg.file_cache_bytes = ByteSize::from_bytes(0);
                            }
                            _ => {
                                self.push_error(
                                    "E007",
                                    "expected a byte-size string (e.g. \"64MiB\") or 0 for 'file-cache-bytes'",
                                    Some(arg.span()),
                                    Some("examples: \"64MiB\", \"16MiB\", \"0\" (0 disables the file cache globally)"),
                                );
                            }
                        }
                    }
                }
                other => {
                    self.push_error(
                        "E002",
                        format!("unknown directive '{other}' inside 'limits'"),
                        Some(child.span()),
                        Some("allowed directives in 'limits' are: max-header-bytes, max-body-bytes, max-concurrent-streams, max-h2-rst-stream-per-sec, max-connections, max-connections-per-ip, ipv6-prefix-conn-multiplier, max-streamed-answers-per-ip, max-streamed-answers-per-backend, trusted-proxies, file-cache-bytes"),
                    );
                }
            }
        }

        cfg
    }

    fn parse_telemetry(&mut self, node: &KdlNode) -> TelemetryConfig {
        self.expect_no_entries(node, "telemetry");
        let Some(children) = self.expect_children(node, "telemetry") else {
            return TelemetryConfig::default();
        };

        let mut cfg = TelemetryConfig::default();
        let mut seen = HashSet::new();

        for child in children.nodes() {
            let name = child.name().value();
            if !seen.insert(name.to_owned()) {
                self.push_error(
                    "E005",
                    format!("duplicate directive '{name}' inside 'telemetry'"),
                    Some(child.span()),
                    None,
                );
                continue;
            }
            match name {
                "metrics-listen" => {
                    self.record_span("server.telemetry.metrics-listen", child.span());
                    if let Some(raw) = self.expect_single_string_node(child) {
                        match BindAddr::parse(raw) {
                            Ok(addr) => cfg.metrics_listen = Some(addr),
                            Err(err) => {
                                self.push_error(
                                    "E101",
                                    format!("invalid 'metrics-listen' address: {err}"),
                                    Some(child.span()),
                                    Some("example: metrics-listen \"127.0.0.1:9090\""),
                                );
                            }
                        }
                    }
                }
                "metrics-path" => {
                    self.record_span("server.telemetry.metrics-path", child.span());
                    if let Some(val) = self.expect_single_string_node(child) {
                        val.clone_into(&mut cfg.metrics_path);
                    }
                }
                "otlp-endpoint" => {
                    self.record_span("server.telemetry.otlp-endpoint", child.span());
                    if let Some(val) = self.expect_single_string_node(child) {
                        cfg.otlp_endpoint = Some(val.to_owned());
                    }
                }
                "service-name" => {
                    self.record_span("server.telemetry.service-name", child.span());
                    if let Some(val) = self.expect_single_string_node(child) {
                        val.clone_into(&mut cfg.service_name);
                    }
                }
                "redact-logs" => {
                    self.record_span("server.telemetry.redact-logs", child.span());
                    if let Some(flag) = self.expect_single_bool_node(child) {
                        cfg.redact_logs = flag;
                    }
                }
                other => {
                    self.push_error(
                        "E002",
                        format!("unknown directive '{other}' inside 'telemetry'"),
                        Some(child.span()),
                        Some("allowed directives in 'telemetry' are: metrics-listen, metrics-path, otlp-endpoint, service-name, redact-logs"),
                    );
                }
            }
        }

        cfg
    }

    fn parse_wasm_plugin(
        &mut self,
        node: &KdlNode,
        route_prefix: &str,
    ) -> Option<WasmPluginConfig> {
        let (args, props) = self.split_entries(node);
        self.expect_exact_arg_count(&args, 1, "wasm-plugin", node.span())?;
        let path_entry = args.first().copied()?;
        let module_path = self
            .expect_string(path_entry, "wasm-plugin module path")?
            .to_owned();

        let mut cfg = WasmPluginConfig {
            module_path,
            ..WasmPluginConfig::default()
        };

        for (prop, entry) in props {
            match prop {
                "max-memory" => {
                    self.record_span(
                        format!("{route_prefix}.wasm-plugin.max-memory"),
                        entry.span(),
                    );
                    if let Some(raw) = self.expect_string(entry, "max-memory") {
                        match ByteSize::parse(raw) {
                            Ok(sz) => cfg.max_memory = sz,
                            Err(err) => {
                                self.push_error(
                                    "E007",
                                    format!("invalid wasm-plugin 'max-memory': {err}"),
                                    Some(entry.span()),
                                    Some("example: max-memory=\"16MB\""),
                                );
                            }
                        }
                    }
                }
                "max-fuel" => {
                    self.record_span(format!("{route_prefix}.wasm-plugin.max-fuel"), entry.span());
                    if let Some(fuel) = self.expect_u64(entry, "max-fuel") {
                        cfg.max_fuel = fuel;
                    }
                }
                "timeout" => {
                    self.record_span(format!("{route_prefix}.wasm-plugin.timeout"), entry.span());
                    if let Some(raw) = self.expect_string(entry, "timeout") {
                        match parse_duration(raw) {
                            Ok(d) => cfg.timeout = d,
                            Err(err) => {
                                self.push_error(
                                    "E007",
                                    format!("invalid wasm-plugin 'timeout': {err}"),
                                    Some(entry.span()),
                                    Some("example: timeout=\"100ms\""),
                                );
                            }
                        }
                    }
                }
                other => {
                    self.push_error(
                        "E003",
                        format!("unknown property '{other}' on 'wasm-plugin'"),
                        Some(entry.span()),
                        Some("allowed properties on 'wasm-plugin' are: max-memory, max-fuel, timeout"),
                    );
                }
            }
        }

        if let Some(children) = node.children() {
            for child in children.nodes() {
                match child.name().value() {
                    "allow-hosts" => {
                        if let Some(hosts) = self.parse_string_list_node(child, "allow-hosts") {
                            cfg.allow_outbound_hosts.extend(hosts);
                        }
                    }
                    other => {
                        self.push_error(
                            "E002",
                            format!("unknown directive '{other}' inside 'wasm-plugin'"),
                            Some(child.span()),
                            Some("allowed child directive inside 'wasm-plugin' is: allow-hosts"),
                        );
                    }
                }
            }
        }

        Some(cfg)
    }

    #[allow(clippy::too_many_lines)]
    fn parse_site(&mut self, node: &KdlNode, site_idx: usize) -> Option<SiteConfig> {
        let (args, props) = self.split_entries(node);
        for (key, entry) in props {
            self.push_error(
                "E003",
                format!("unknown property '{key}' on 'site'"),
                Some(entry.span()),
                Some("pass hostnames as positional string arguments: site \"example.com\" { ... }"),
            );
        }

        if args.is_empty() {
            self.push_error(
                "E004",
                "'site' requires at least one hostname argument",
                Some(node.span()),
                Some("example: site \"example.com\" { ... }"),
            );
            return None;
        }

        let mut hosts = Vec::with_capacity(args.len());
        for (h_idx, arg) in args.iter().enumerate() {
            self.record_span(format!("site[{site_idx}].host[{h_idx}]"), arg.span());
            if let Some(h) = self.expect_string(arg, "site hostname") {
                hosts.push(h.to_owned());
            }
        }

        let children = self.expect_children(node, "site")?;
        let prefix = format!("site[{site_idx}]");

        let mut preset: Option<SitePreset> = None;
        let mut security_headers = SecurityHeadersPolicy::Strict;
        let mut http = SiteHttpMode::Redirect;
        let mut http_credentials = false;
        let mut rate_limit: Option<RateLimitConfig> = None;
        let mut tls: Option<SiteTlsConfig> = None;
        let mut root: Option<String> = None;
        let mut index: Option<Vec<String>> = None;
        let mut precompressed = PrecompressedPolicy::OFF;
        let mut bot_auth: Option<BotAuthConfig> = None;
        let mut ai_publish: Option<AiPublishConfig> = None;
        let mut error_pages: Option<ErrorPagesConfig> = None;
        let mut rewrites: Vec<RewriteRule> = Vec::new();
        let mut headers: Vec<HeaderRule> = Vec::new();
        let mut access: Vec<AccessRule> = Vec::new();
        let mut basic_auth: Option<BasicAuthConfig> = None;
        let mut owner_dir: Option<String> = None;
        let mut file_cache: Option<Duration> = None;
        let mut routes = Vec::new();
        let mut seen = HashSet::new();

        for child in children.nodes() {
            let name = child.name().value();
            if name != "route" && !seen.insert(name.to_owned()) {
                self.push_error(
                    "E005",
                    format!("duplicate directive '{name}' inside 'site'"),
                    Some(child.span()),
                    None,
                );
                continue;
            }

            match name {
                "preset" => {
                    self.record_span(format!("{prefix}.preset"), child.span());
                    if let Some(val) = self.expect_single_string_node(child) {
                        match val {
                            "wordpress-hardened" => preset = Some(SitePreset::WordpressHardened),
                            "static-strict" => preset = Some(SitePreset::StaticStrict),
                            "api-gateway" => preset = Some(SitePreset::ApiGateway),
                            other => {
                                self.push_error(
                                    "E203",
                                    format!("unknown site preset '{other}'"),
                                    Some(child.span()),
                                    Some("supported presets: \"wordpress-hardened\", \"static-strict\", \"api-gateway\""),
                                );
                            }
                        }
                    }
                }
                "security-headers" => {
                    self.record_span(format!("{prefix}.security-headers"), child.span());
                    if let Some(policy) = self.parse_security_headers(child) {
                        security_headers = policy;
                    }
                }
                "http" => {
                    self.record_span(format!("{prefix}.http"), child.span());
                    let (mode, creds) = self.parse_site_http(child);
                    http = mode;
                    http_credentials = creds;
                }
                "rate-limit" => {
                    self.record_span(format!("{prefix}.rate-limit"), child.span());
                    rate_limit = self.parse_rate_limit(child);
                }
                "tls" => {
                    self.record_span(format!("{prefix}.tls"), child.span());
                    tls = Some(self.parse_site_tls(child, &prefix));
                }
                "root" => {
                    self.record_span(format!("{prefix}.root"), child.span());
                    if let Some(val) = self.expect_single_string_node(child) {
                        root = Some(val.to_owned());
                    }
                }
                "index" => {
                    self.record_span(format!("{prefix}.index"), child.span());
                    if let Some(items) = self.parse_string_list_node(child, "index") {
                        index = Some(items);
                    }
                }
                "precompressed" => {
                    self.record_span(format!("{prefix}.precompressed"), child.span());
                    if let Some(policy) = self.parse_precompressed(child) {
                        precompressed = policy;
                    }
                }
                "bot-auth" => {
                    self.record_span(format!("{prefix}.bot-auth"), child.span());
                    bot_auth = Some(self.parse_bot_auth(child, &prefix));
                }
                "ai-publish" => {
                    self.record_span(format!("{prefix}.ai-publish"), child.span());
                    ai_publish = self.parse_ai_publish(child, &prefix);
                }
                "error-pages" => {
                    self.record_span(format!("{prefix}.error-pages"), child.span());
                    error_pages = Some(self.parse_error_pages(child, &prefix));
                }
                "owner-dir" => {
                    self.record_span(format!("{prefix}.owner-dir"), child.span());
                    self.expect_no_children(child, "owner-dir");
                    let (args, _) = self.split_entries(child);
                    if let Some(()) =
                        self.expect_exact_arg_count(&args, 1, "owner-dir", child.span())
                        && let Some(dir) = args
                            .first()
                            .and_then(|arg| self.expect_string(arg, "owner-dir"))
                            .map(str::to_owned)
                    {
                        if !std::path::Path::new(&dir).is_absolute() {
                            self.push_error(
                                "E301",
                                format!("owner-dir '{dir}' must be an absolute path"),
                                Some(child.span()),
                                None,
                            );
                        } else if owner_dir.replace(dir).is_some() {
                            self.push_error(
                                "E005",
                                "duplicate 'owner-dir' inside 'site'",
                                Some(child.span()),
                                None,
                            );
                        }
                    }
                }
                "basic-auth" => {
                    self.record_span(format!("{prefix}.basic-auth"), child.span());
                    if basic_auth.is_some() {
                        self.push_error(
                            "E005",
                            "duplicate 'basic-auth' inside 'site'",
                            Some(child.span()),
                            None,
                        );
                    } else {
                        basic_auth = self.parse_basic_auth(child);
                    }
                }
                "access" => {
                    self.record_span(format!("{prefix}.access"), child.span());
                    let parsed = self.parse_access_block(child, access.len());
                    access.extend(parsed);
                }
                "headers" => {
                    self.record_span(format!("{prefix}.headers"), child.span());
                    let parsed = self.parse_headers_block(child, headers.len());
                    headers.extend(parsed);
                }
                "rewrite" => {
                    self.record_span(format!("{prefix}.rewrite"), child.span());
                    let parsed = self.parse_rewrite_block(child, &prefix, rewrites.len());
                    rewrites.extend(parsed);
                }
                "file-cache" => {
                    self.record_span(format!("{prefix}.file-cache"), child.span());
                    if let Some(raw) = self.expect_single_string_node(child) {
                        if raw == "off" {
                            file_cache = None;
                        } else {
                            match parse_duration(raw) {
                                Ok(d) => file_cache = Some(d),
                                Err(err) => {
                                    self.push_error(
                                        "E007",
                                        format!("invalid duration for 'file-cache': {err}"),
                                        Some(child.span()),
                                        Some("examples: \"1s\", \"500ms\", \"off\" (range: 100ms to 60s)"),
                                    );
                                }
                            }
                        }
                    }
                }
                "route" => {
                    let route_idx = routes.len();
                    let route_prefix = format!("{prefix}.route[{route_idx}]");
                    self.record_span(route_prefix.clone(), child.span());
                    if let Some(route) = self.parse_route(child, &route_prefix) {
                        routes.push(route);
                    }
                }
                other => {
                    self.push_error(
                        "E002",
                        format!("unknown directive '{other}' inside 'site'"),
                        Some(child.span()),
                        Some("allowed directives in 'site' are: preset, security-headers, http, rate-limit, tls, root, owner-dir, index, precompressed, file-cache, bot-auth, ai-publish, error-pages, access, basic-auth, headers, rewrite, route"),
                    );
                }
            }
        }

        Some(SiteConfig {
            hosts,
            preset,
            security_headers,
            http,
            http_credentials,
            rate_limit,
            tls,
            root,
            index,
            precompressed,
            bot_auth,
            ai_publish,
            error_pages,
            routes,
            rewrites,
            headers,
            access,
            basic_auth,
            owner_dir,
            file_cache,
            quarantine: None,
            quarantine_field: None,
        })
    }

    /// Parses `precompressed "off" | "all" | "zst" "br" "gz"`.
    fn parse_precompressed(&mut self, node: &KdlNode) -> Option<PrecompressedPolicy> {
        self.expect_no_children(node, "precompressed");
        let (args, props) = self.split_entries(node);
        for (prop, entry) in props {
            self.push_error(
                "E003",
                format!("unknown property '{prop}' on 'precompressed'"),
                Some(entry.span()),
                Some("pass values as positional strings, e.g.: precompressed \"off\", precompressed \"all\", or precompressed \"br\" \"gz\""),
            );
        }
        if args.is_empty() {
            self.push_error(
                "E004",
                "'precompressed' requires at least one argument",
                Some(node.span()),
                Some("allowed values: \"off\", \"all\", or any combination of \"zst\", \"br\", \"gz\""),
            );
            return None;
        }

        let mut seen_tokens = HashSet::new();
        let mut saw_off = false;
        let mut saw_all = false;
        let mut policy = PrecompressedPolicy::OFF;
        let mut has_error = false;

        for arg in &args {
            let Some(val) = self.expect_string(arg, "precompressed") else {
                has_error = true;
                continue;
            };
            if !seen_tokens.insert(val) {
                self.push_error(
                    "E005",
                    format!("duplicate precompressed value '{val}'"),
                    Some(arg.span()),
                    None,
                );
                has_error = true;
                continue;
            }
            match val {
                "off" => saw_off = true,
                "all" => saw_all = true,
                "zst" => policy.zst = true,
                "br" => policy.br = true,
                "gz" => policy.gz = true,
                other => {
                    self.push_error(
                        "E203",
                        format!("unknown precompressed encoding '{other}'"),
                        Some(arg.span()),
                        Some("allowed values: \"off\", \"all\", or any combination of \"zst\", \"br\", \"gz\""),
                    );
                    has_error = true;
                }
            }
        }

        if saw_off && (saw_all || policy.any()) {
            self.push_error(
                "E203",
                "'precompressed \"off\"' cannot be combined with other values",
                Some(node.span()),
                Some("use either `precompressed \"off\"`, `precompressed \"all\"`, or encoding names from \"zst\", \"br\", \"gz\""),
            );
            has_error = true;
        } else if saw_all && policy.any() {
            self.push_error(
                "E203",
                "'precompressed \"all\"' cannot be combined with individual encoding names",
                Some(node.span()),
                Some("use either `precompressed \"all\"` or individual encoding names from \"zst\", \"br\", \"gz\""),
            );
            has_error = true;
        }

        if has_error {
            None
        } else if saw_off {
            Some(PrecompressedPolicy::OFF)
        } else if saw_all {
            Some(PrecompressedPolicy::ALL)
        } else {
            Some(policy)
        }
    }

    /// Parses `http "redirect"` or `http "serve" [credentials=#true|#false]`.
    fn parse_site_http(&mut self, node: &KdlNode) -> (SiteHttpMode, bool) {
        self.expect_no_children(node, "http");
        let (args, props) = self.split_entries(node);
        let mode = self
            .expect_exact_arg_count(&args, 1, "http", node.span())
            .and_then(|()| args.first().copied())
            .and_then(|entry| self.expect_string(entry, "http"))
            .and_then(|val| match val {
                "redirect" => Some(SiteHttpMode::Redirect),
                "serve" => Some(SiteHttpMode::Serve),
                other => {
                    self.push_error(
                        "E203",
                        format!("unknown site http mode '{other}'"),
                        Some(node.span()),
                        Some("supported http modes: \"redirect\", \"serve\""),
                    );
                    None
                }
            });

        let mut credentials = false;
        for (prop, entry) in props {
            if prop == "credentials" {
                if mode == Some(SiteHttpMode::Redirect) {
                    self.push_error(
                        "E003",
                        "property 'credentials' is not valid on `http \"redirect\"`",
                        Some(entry.span()),
                        Some("remove 'credentials' or switch to `http \"serve\"`"),
                    );
                } else if let Some(val) = self.expect_bool(entry, "credentials") {
                    credentials = val;
                }
            } else {
                self.push_error(
                    "E003",
                    format!("unknown property '{prop}' on 'http'"),
                    Some(entry.span()),
                    Some("allowed property on `http \"serve\"` is: credentials"),
                );
            }
        }

        match mode {
            Some(m) => (m, m == SiteHttpMode::Serve && credentials),
            None => (SiteHttpMode::Redirect, false),
        }
    }

    /// Parses `basic-auth "/abs/path/htpasswd" realm="Members"`.
    fn parse_basic_auth(&mut self, node: &KdlNode) -> Option<BasicAuthConfig> {
        self.expect_no_children(node, "basic-auth");
        let (args, props) = self.split_entries(node);
        self.expect_exact_arg_count(&args, 1, "basic-auth", node.span())?;
        let users_file = self
            .expect_string(*args.first()?, "basic-auth users file")?
            .to_owned();
        if !std::path::Path::new(&users_file).is_absolute() {
            self.push_error(
                "E311",
                format!("basic-auth users file '{users_file}' must be an absolute path"),
                Some(node.span()),
                None,
            );
            return None;
        }
        let mut realm = "Restricted".to_owned();
        for (prop, entry) in props {
            if prop == "realm" {
                if let Some(value) = self.expect_string(entry, "basic-auth realm") {
                    if value.is_empty()
                        || value.len() > 128
                        || value
                            .bytes()
                            .any(|b| b.is_ascii_control() || b == b'"' || b == b'\\')
                    {
                        self.push_error(
                            "E311",
                            "basic-auth realm must be 1-128 characters without quotes, backslashes or control characters",
                            Some(entry.span()),
                            None,
                        );
                        return None;
                    }
                    value.clone_into(&mut realm);
                }
            } else {
                self.push_error(
                    "E003",
                    format!("unknown property '{prop}' on 'basic-auth'"),
                    Some(entry.span()),
                    Some("allowed property on 'basic-auth' is: realm"),
                );
            }
        }
        Some(BasicAuthConfig { users_file, realm })
    }

    /// Parses `access { allow "10.0.0.0/8"; deny "all" }`.
    fn parse_access_block(&mut self, node: &KdlNode, already: usize) -> Vec<AccessRule> {
        self.expect_no_entries(node, "access");
        let Some(children) = self.expect_children(node, "access") else {
            return Vec::new();
        };
        let mut rules = Vec::new();
        for child in children.nodes() {
            let allow = match child.name().value() {
                "allow" => true,
                "deny" => false,
                other => {
                    self.push_error(
                        "E002",
                        format!("unknown directive '{other}' inside 'access'"),
                        Some(child.span()),
                        Some("allowed directives in 'access' are: allow \"<ip, cidr or all>\", deny \"<ip, cidr or all>\""),
                    );
                    continue;
                }
            };
            let (args, props) = self.split_entries(child);
            let source = match (
                args.as_slice(),
                props.is_empty(),
                child.children().is_none(),
            ) {
                ([only], true, true) => only.value().as_string().map(|v| v.trim().to_owned()),
                _ => None,
            };
            let Some(source) = source else {
                self.push_error(
                    "E310",
                    format!("invalid access line '{}'", child.name().value()),
                    Some(child.span()),
                    Some("write: allow \"10.0.0.0/8\" or deny \"all\""),
                );
                continue;
            };
            if source != "all" && IpCidr::parse(&source).is_err() {
                self.push_error(
                    "E310",
                    format!("'{source}' is not an IP address, a CIDR range or \"all\""),
                    Some(child.span()),
                    None,
                );
                continue;
            }
            if already + rules.len() >= MAX_ACCESS_RULES {
                self.push_error(
                    "E310",
                    format!("more than {MAX_ACCESS_RULES} access lines"),
                    Some(child.span()),
                    None,
                );
                break;
            }
            rules.push(AccessRule { allow, source });
        }
        rules
    }

    /// Parses `headers { set "Name" "value"; add "Name" "value"; remove "Name" }`.
    fn parse_headers_block(&mut self, node: &KdlNode, already: usize) -> Vec<HeaderRule> {
        self.expect_no_entries(node, "headers");
        let Some(children) = self.expect_children(node, "headers") else {
            return Vec::new();
        };
        let mut rules = Vec::new();
        for child in children.nodes() {
            let action = match child.name().value() {
                "set" => HeaderAction::Set,
                "add" => HeaderAction::Add,
                "remove" => HeaderAction::Remove,
                other => {
                    self.push_error(
                        "E002",
                        format!("unknown directive '{other}' inside 'headers'"),
                        Some(child.span()),
                        Some("allowed directives in 'headers' are: set \"Name\" \"value\", add \"Name\" \"value\", remove \"Name\""),
                    );
                    continue;
                }
            };
            let (args, props) = self.split_entries(child);
            let strings: Vec<String> = args
                .iter()
                .filter_map(|e| e.value().as_string().map(str::to_owned))
                .collect();
            let expected = if action == HeaderAction::Remove { 1 } else { 2 };
            if child.children().is_some()
                || strings.len() != args.len()
                || strings.len() != expected
            {
                self.push_error(
                    "E309",
                    format!("invalid header change '{}'", child.name().value()),
                    Some(child.span()),
                    Some(
                        "write: set \"Name\" \"value\" [status=\"...\"], add \"Name\" \"value\" [status=\"...\"] or remove \"Name\" [status=\"...\"]",
                    ),
                );
                continue;
            }
            let Some(status) = self.parse_header_rule_props(child.name().value(), &props) else {
                continue;
            };
            let mut strings = strings.into_iter();
            let rule = HeaderRule {
                action,
                name: strings
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_ascii_lowercase(),
                value: strings.next(),
                status,
            };
            if let Some(reason) = header_rule_rejection(&rule) {
                self.push_error(
                    "E309",
                    format!("invalid header change: {reason}"),
                    Some(child.span()),
                    None,
                );
                continue;
            }
            if already + rules.len() >= MAX_HEADER_RULES {
                self.push_error(
                    "E309",
                    format!("more than {MAX_HEADER_RULES} header changes"),
                    Some(child.span()),
                    None,
                );
                break;
            }
            rules.push(rule);
        }
        rules
    }

    fn parse_header_rule_props(
        &mut self,
        directive: &str,
        props: &[(&str, &KdlEntry)],
    ) -> Option<Vec<HeaderStatusMatcher>> {
        let mut status = Vec::new();
        let mut seen_status = false;
        let mut ok = true;
        for &(prop, entry) in props {
            if prop == "status" {
                if seen_status {
                    self.push_error(
                        "E309",
                        format!("duplicate property 'status' on header change '{directive}'"),
                        Some(entry.span()),
                        Some("combine codes/classes in a single status=\"...\" property"),
                    );
                    ok = false;
                    continue;
                }
                seen_status = true;
                let Some(raw) = entry.value().as_string() else {
                    self.push_error(
                        "E309",
                        "header rule property 'status' must be a string",
                        Some(entry.span()),
                        Some("example: status=\"200 206 304\" or status=\"2xx 304\""),
                    );
                    ok = false;
                    continue;
                };
                match parse_header_status_list(raw) {
                    Ok(parsed) => status = parsed,
                    Err(reason) => {
                        self.push_error(
                            "E309",
                            format!("invalid header change: {reason}"),
                            Some(entry.span()),
                            Some("example: status=\"200 206 304\" or status=\"2xx 304\""),
                        );
                        ok = false;
                    }
                }
            } else {
                self.push_error(
                    "E309",
                    format!("unknown property '{prop}' on header change '{directive}'"),
                    Some(entry.span()),
                    Some("allowed optional property is: status=\"<codes or classes>\""),
                );
                ok = false;
            }
        }
        ok.then_some(status)
    }

    fn parse_error_pages(&mut self, node: &KdlNode, site_prefix: &str) -> ErrorPagesConfig {
        self.expect_no_entries(node, "error-pages");
        let mut cfg = ErrorPagesConfig::default();
        let Some(children) = self.expect_children(node, "error-pages") else {
            return cfg;
        };
        let mut seen_login_url = false;
        for child in children.nodes() {
            match child.name().value() {
                "login-url" => {
                    if seen_login_url {
                        self.push_error(
                            "E005",
                            "duplicate directive 'login-url' inside 'error-pages'",
                            Some(child.span()),
                            None,
                        );
                        continue;
                    }
                    seen_login_url = true;
                    self.record_span(format!("{site_prefix}.error-pages.login-url"), child.span());
                    if let Some(val) = self.expect_single_string_node(child) {
                        cfg.login_url = Some(val.to_owned());
                    }
                }
                "page" => {
                    self.expect_no_children(child, "page");
                    let (args, props) = self.split_entries(child);
                    if !props.is_empty() || args.len() != 2 {
                        self.push_error(
                            "E004",
                            "'page' expects a status code and a file path",
                            Some(child.span()),
                            Some("example: page 404 \"errors/404.html\""),
                        );
                        continue;
                    }
                    let Some(status_entry) = args.first() else {
                        continue;
                    };
                    let Some(path_entry) = args.get(1) else {
                        continue;
                    };
                    let Some(status_u32) = self.expect_u32(status_entry, "error page status")
                    else {
                        continue;
                    };
                    let Ok(status_u16) = u16::try_from(status_u32) else {
                        self.push_error(
                            "E203",
                            format!("invalid HTTP status code '{status_u32}' in 'error-pages'"),
                            Some(status_entry.span()),
                            Some("use an HTTP error status code between 400 and 599"),
                        );
                        continue;
                    };
                    let Some(path) = self.expect_string(path_entry, "error page path") else {
                        continue;
                    };
                    let span_key = format!("{site_prefix}.error-pages.page.{status_u16}");
                    self.record_span(span_key, child.span());
                    if cfg.pages.contains_key(&status_u16) {
                        self.push_error(
                            "E005",
                            format!("duplicate error page override for status {status_u16}"),
                            Some(child.span()),
                            None,
                        );
                        continue;
                    }
                    cfg.pages.insert(status_u16, path.to_owned());
                }
                other => {
                    self.push_error(
                        "E002",
                        format!("unknown directive '{other}' inside 'error-pages'"),
                        Some(child.span()),
                        Some("allowed directives in 'error-pages' are: login-url, page"),
                    );
                }
            }
        }
        cfg
    }

    fn parse_security_headers(&mut self, node: &KdlNode) -> Option<SecurityHeadersPolicy> {
        let val = self.expect_single_string_node(node)?;
        match val {
            "strict" => Some(SecurityHeadersPolicy::Strict),
            "standard" => Some(SecurityHeadersPolicy::Standard),
            "off" => Some(SecurityHeadersPolicy::Off),
            other => {
                self.push_error(
                    "E203",
                    format!("invalid security-headers policy '{other}'"),
                    Some(node.span()),
                    Some("allowed values are: \"strict\", \"standard\", \"off\""),
                );
                None
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn parse_rate_limit(&mut self, node: &KdlNode) -> Option<RateLimitConfig> {
        self.expect_no_children(node, "rate-limit");
        let (args, props) = self.split_entries(node);
        if !args.is_empty() {
            self.push_error(
                "E004",
                "'rate-limit' takes named properties, not positional arguments",
                Some(node.span()),
                Some("example: rate-limit requests=200 per=\"1m\" burst=40 key=\"client-ip\""),
            );
            return None;
        }

        let mut requests: Option<u32> = None;
        let mut per: Option<Duration> = None;
        let mut burst: Option<u32> = None;
        let mut key = RateLimitKey::ClientIp;
        let mut ip_ceiling_multiplier: Option<u32> = None;
        let mut max_keys_per_ip: Option<u32> = None;

        for (prop, entry) in props {
            match prop {
                "requests" => {
                    requests = self.expect_u32(entry, "requests");
                }
                "per" => {
                    if let Some(raw) = self.expect_string(entry, "per") {
                        match parse_duration(raw) {
                            Ok(dur) => per = Some(dur),
                            Err(err) => {
                                self.push_error(
                                    "E007",
                                    format!("invalid 'per' duration: {err}"),
                                    Some(entry.span()),
                                    Some("examples: \"1s\", \"1m\", \"10s\""),
                                );
                            }
                        }
                    }
                }
                "burst" => {
                    burst = self.expect_u32(entry, "burst");
                }
                "ip-ceiling-multiplier" => {
                    ip_ceiling_multiplier = self.expect_u32(entry, "ip-ceiling-multiplier");
                }
                "max-keys-per-ip" => {
                    max_keys_per_ip = self.expect_u32(entry, "max-keys-per-ip");
                }
                "key" => {
                    if let Some(raw) = self.expect_string(entry, "key") {
                        if raw == "client-ip" {
                            key = RateLimitKey::ClientIp;
                        } else if raw == "agent-id" {
                            key = RateLimitKey::AgentId;
                        } else if let Some(header_name) = raw.strip_prefix("header:") {
                            if is_valid_http_header_name(header_name) {
                                key = RateLimitKey::Header(header_name.to_owned());
                            } else {
                                self.push_error(
                                    "E204",
                                    format!("invalid HTTP header name '{header_name}' in rate-limit key"),
                                    Some(entry.span()),
                                    Some("header names must use valid HTTP token characters (e.g. \"header:x-api-key\")"),
                                );
                            }
                        } else {
                            self.push_error(
                                "E204",
                                format!("unknown rate-limit key '{raw}'"),
                                Some(entry.span()),
                                Some("allowed values: \"client-ip\", \"agent-id\", or \"header:<name>\""),
                            );
                        }
                    }
                }
                other => {
                    self.push_error(
                        "E003",
                        format!("unknown property '{other}' on 'rate-limit'"),
                        Some(entry.span()),
                        Some("allowed properties on 'rate-limit' are: requests, per, burst, key, ip-ceiling-multiplier, max-keys-per-ip"),
                    );
                }
            }
        }

        let Some(requests) = requests else {
            self.push_error(
                "E006",
                "'rate-limit' requires property 'requests=<n>'",
                Some(node.span()),
                None,
            );
            return None;
        };
        let Some(per) = per else {
            self.push_error(
                "E006",
                "'rate-limit' requires property 'per=\"<duration>\"'",
                Some(node.span()),
                None,
            );
            return None;
        };

        Some(RateLimitConfig {
            requests,
            per,
            burst: burst.unwrap_or(requests),
            key,
            ip_ceiling_multiplier,
            max_keys_per_ip,
        })
    }

    fn parse_site_tls(&mut self, node: &KdlNode, site_prefix: &str) -> SiteTlsConfig {
        self.expect_no_entries(node, "tls");
        let Some(children) = self.expect_children(node, "tls") else {
            return SiteTlsConfig::default();
        };

        let mut cfg = SiteTlsConfig::default();
        let mut seen = HashSet::new();

        for child in children.nodes() {
            let name = child.name().value();
            if !seen.insert(name.to_owned()) {
                self.push_error(
                    "E005",
                    format!("duplicate directive '{name}' inside 'site.tls'"),
                    Some(child.span()),
                    None,
                );
                continue;
            }
            match name {
                "compat-tls-1-2" => {
                    self.record_span(format!("{site_prefix}.tls.compat-tls-1-2"), child.span());
                    if let Some(val) = self.expect_single_bool_node(child) {
                        cfg.compat_tls_1_2 = val;
                    }
                }
                "pqc-hybrid" => {
                    self.record_span(format!("{site_prefix}.tls.pqc-hybrid"), child.span());
                    if let Some(val) = self.expect_single_bool_node(child) {
                        cfg.pqc_hybrid = Some(val);
                    }
                }
                "cert" => {
                    self.record_span(format!("{site_prefix}.tls.cert"), child.span());
                    if let Some(val) = self.expect_single_string_node(child) {
                        cfg.cert = Some(val.to_owned());
                    }
                }
                "key" => {
                    self.record_span(format!("{site_prefix}.tls.key"), child.span());
                    if let Some(val) = self.expect_single_string_node(child) {
                        cfg.key = Some(val.to_owned());
                    }
                }
                "client-ca" => {
                    self.record_span(format!("{site_prefix}.tls.client-ca"), child.span());
                    if let Some(val) = self.expect_single_string_node(child) {
                        cfg.client_ca = Some(val.to_owned());
                    }
                }
                other => {
                    self.push_error(
                        "E002",
                        format!("unknown directive '{other}' inside 'site.tls'"),
                        Some(child.span()),
                        Some("allowed directives in 'site.tls' are: compat-tls-1-2, pqc-hybrid, cert, key, client-ca"),
                    );
                }
            }
        }

        cfg
    }

    #[allow(clippy::too_many_lines)]
    fn parse_bot_auth(&mut self, node: &KdlNode, site_prefix: &str) -> BotAuthConfig {
        self.expect_no_entries(node, "bot-auth");
        let Some(children) = self.expect_children(node, "bot-auth") else {
            return BotAuthConfig::default();
        };

        let mut cfg = BotAuthConfig::default();
        let mut seen = HashSet::new();

        for child in children.nodes() {
            let name = child.name().value();
            if !matches!(name, "allow-agent" | "agent-key") && !seen.insert(name.to_owned()) {
                self.push_error(
                    "E005",
                    format!("duplicate directive '{name}' inside 'bot-auth'"),
                    Some(child.span()),
                    None,
                );
                continue;
            }
            match name {
                "verify-rfc9421" => {
                    self.record_span(
                        format!("{site_prefix}.bot-auth.verify-rfc9421"),
                        child.span(),
                    );
                    if let Some(val) = self.expect_single_bool_node(child) {
                        cfg.verify_rfc9421 = val;
                    }
                }
                "allow-agent" => {
                    self.expect_no_children(child, "allow-agent");
                    let (args, props) = self.split_entries(child);
                    if self
                        .expect_exact_arg_count(&args, 1, "allow-agent", child.span())
                        .is_none()
                    {
                        continue;
                    }
                    let Some(name_entry) = args.first().copied() else {
                        continue;
                    };
                    let Some(agent_name) = self.expect_string(name_entry, "allow-agent name")
                    else {
                        continue;
                    };
                    let mut serve_markdown = false;
                    for (prop, entry) in props {
                        match prop {
                            "serve-markdown" => {
                                if let Some(b) = self.expect_bool(entry, "serve-markdown") {
                                    serve_markdown = b;
                                }
                            }
                            other => {
                                self.push_error(
                                    "E003",
                                    format!("unknown property '{other}' on 'allow-agent'"),
                                    Some(entry.span()),
                                    Some("allowed property on 'allow-agent' is: serve-markdown"),
                                );
                            }
                        }
                    }
                    if agent_name.trim().is_empty() {
                        self.push_error(
                            "E404",
                            "'allow-agent' name must not be empty",
                            Some(name_entry.span()),
                            None,
                        );
                    } else {
                        cfg.allow_agents.push(AllowedAgentConfig {
                            name: agent_name.to_owned(),
                            serve_markdown,
                        });
                    }
                }
                "agent-key" => {
                    self.record_span(format!("{site_prefix}.bot-auth.agent-key"), child.span());
                    self.expect_no_children(child, "agent-key");
                    let (args, props) = self.split_entries(child);
                    if self
                        .expect_exact_arg_count(&args, 1, "agent-key", child.span())
                        .is_none()
                    {
                        continue;
                    }
                    let Some(key_id_entry) = args.first().copied() else {
                        continue;
                    };
                    let Some(key_id) = self.expect_string(key_id_entry, "agent-key keyid") else {
                        continue;
                    };
                    let mut agent_id: Option<String> = None;
                    let mut group: Option<String> = None;
                    let mut ed25519_b64: Option<String> = None;
                    for (prop, entry) in props {
                        match prop {
                            "agent-id" => {
                                if let Some(v) = self.expect_string(entry, "agent-id") {
                                    agent_id = Some(v.to_owned());
                                }
                            }
                            "group" => {
                                if let Some(v) = self.expect_string(entry, "group") {
                                    group = Some(v.to_owned());
                                }
                            }
                            "ed25519" => {
                                if let Some(v) = self.expect_string(entry, "ed25519") {
                                    ed25519_b64 = Some(v.to_owned());
                                }
                            }
                            other => {
                                self.push_error(
                                    "E003",
                                    format!("unknown property '{other}' on 'agent-key'"),
                                    Some(entry.span()),
                                    Some("allowed properties on 'agent-key' are: group, ed25519, agent-id"),
                                );
                            }
                        }
                    }
                    match (group, ed25519_b64) {
                        (Some(grp), Some(pk)) => {
                            cfg.agent_keys.push(BotAgentKeyConfig {
                                key_id: key_id.to_owned(),
                                agent_id: agent_id.unwrap_or_else(|| key_id.to_owned()),
                                group: grp,
                                ed25519_b64: pk,
                            });
                        }
                        _ => {
                            self.push_error(
                                "E404",
                                "'agent-key' requires properties 'group=\"...\"' and 'ed25519=\"<base64>\"'",
                                Some(child.span()),
                                Some("example: agent-key \"bot-2026\" group=\"verified-ai-agents\" ed25519=\"<base64>\""),
                            );
                        }
                    }
                }
                "agent-keys-file" => {
                    self.record_span(
                        format!("{site_prefix}.bot-auth.agent-keys-file"),
                        child.span(),
                    );
                    if let Some(val) = self.expect_single_string_node(child) {
                        cfg.agent_keys_file = Some(val.to_owned());
                    }
                }
                "on-unverified-ai-ua" => {
                    if let Some(val) = self.expect_single_string_node(child) {
                        match val {
                            "allow" => cfg.on_unverified_ai_ua = UnverifiedBotAction::Allow,
                            "throttle" => cfg.on_unverified_ai_ua = UnverifiedBotAction::Throttle,
                            "challenge" => cfg.on_unverified_ai_ua = UnverifiedBotAction::Challenge,
                            "block" => cfg.on_unverified_ai_ua = UnverifiedBotAction::Block,
                            other => {
                                self.push_error(
                                    "E404",
                                    format!("invalid on-unverified-ai-ua action '{other}'"),
                                    Some(child.span()),
                                    Some("allowed values: \"allow\", \"throttle\", \"challenge\", \"block\""),
                                );
                            }
                        }
                    }
                }
                other => {
                    self.push_error(
                        "E002",
                        format!("unknown directive '{other}' inside 'bot-auth'"),
                        Some(child.span()),
                        Some("allowed directives in 'bot-auth' are: verify-rfc9421, allow-agent, agent-key, agent-keys-file, on-unverified-ai-ua"),
                    );
                }
            }
        }

        cfg
    }

    #[allow(clippy::too_many_lines)]
    fn parse_ai_publish(&mut self, node: &KdlNode, site_prefix: &str) -> Option<AiPublishConfig> {
        self.expect_no_entries(node, "ai-publish");
        let children = self.expect_children(node, "ai-publish")?;

        let mut storage: Option<String> = None;
        let mut site_id: Option<String> = None;
        let mut keep_versions: u32 = 10;
        let mut require_signature: Option<SignatureRequirement> = None;
        let mut jwt_public_key: Option<String> = None;
        let mut jwt_issuer: Option<String> = None;
        let mut allowed_subjects: Vec<String> = Vec::new();
        let mut preflight_checks: Vec<PreflightCheck> = Vec::new();
        let mut preflight_explicitly_set = false;
        let mut mcp_endpoint: Option<McpPublishEndpoint> = None;
        let mut seen = HashSet::new();

        for child in children.nodes() {
            let name = child.name().value();
            if name != "preflight-checks"
                && name != "allowed-subjects"
                && !seen.insert(name.to_owned())
            {
                self.push_error(
                    "E005",
                    format!("duplicate directive '{name}' inside 'ai-publish'"),
                    Some(child.span()),
                    None,
                );
                continue;
            }
            match name {
                "storage" => {
                    self.record_span(format!("{site_prefix}.ai-publish.storage"), child.span());
                    if let Some(val) = self.expect_single_string_node(child) {
                        storage = Some(val.to_owned());
                    }
                }
                "site-id" => {
                    self.record_span(format!("{site_prefix}.ai-publish.site-id"), child.span());
                    if let Some(val) = self.expect_single_string_node(child) {
                        site_id = Some(val.to_owned());
                    }
                }
                "jwt-public-key" => {
                    self.record_span(
                        format!("{site_prefix}.ai-publish.jwt-public-key"),
                        child.span(),
                    );
                    if let Some(val) = self.expect_single_string_node(child) {
                        jwt_public_key = Some(val.to_owned());
                    }
                }
                "jwt-issuer" => {
                    self.record_span(format!("{site_prefix}.ai-publish.jwt-issuer"), child.span());
                    if let Some(val) = self.expect_single_string_node(child) {
                        jwt_issuer = Some(val.to_owned());
                    }
                }
                "allowed-subjects" => {
                    self.record_span(
                        format!("{site_prefix}.ai-publish.allowed-subjects"),
                        child.span(),
                    );
                    self.expect_no_children(child, "allowed-subjects");
                    let (args, props) = self.split_entries(child);
                    for (prop, entry) in props {
                        self.push_error(
                            "E003",
                            format!("unknown property '{prop}' on 'allowed-subjects'"),
                            Some(entry.span()),
                            Some("pass certificate subjects as string arguments, e.g.: allowed-subjects \"CN=deploy-bot\""),
                        );
                    }
                    if args.is_empty() {
                        self.push_error(
                            "E401",
                            "'allowed-subjects' requires at least one subject string",
                            Some(child.span()),
                            None,
                        );
                    }
                    for arg in args {
                        if let Some(raw) = self.expect_string(arg, "allowed-subjects") {
                            allowed_subjects.push(raw.to_owned());
                        }
                    }
                }
                "keep-versions" => {
                    self.record_span(
                        format!("{site_prefix}.ai-publish.keep-versions"),
                        child.span(),
                    );
                    if let Some(v) = self.expect_single_u32_node(child) {
                        keep_versions = v;
                    }
                }
                "require-signature" => {
                    self.record_span(
                        format!("{site_prefix}.ai-publish.require-signature"),
                        child.span(),
                    );
                    if let Some(val) = self.expect_single_string_node(child) {
                        if let Some((algo_raw, key_path)) = val.split_once(':') {
                            match algo_raw {
                                "ed25519" => {
                                    if key_path.trim().is_empty() {
                                        self.push_error(
                                            "E401",
                                            "require-signature public key path must not be empty",
                                            Some(child.span()),
                                            Some("example: require-signature \"ed25519:/etc/miraserve/deploy-agent.pub\""),
                                        );
                                    } else {
                                        require_signature = Some(SignatureRequirement {
                                            algorithm: SignatureAlgorithm::Ed25519,
                                            public_key_path: key_path.to_owned(),
                                        });
                                    }
                                }
                                other => {
                                    self.push_error(
                                        "E401",
                                        format!("unsupported signature algorithm '{other}'"),
                                        Some(child.span()),
                                        Some("supported signature algorithm is \"ed25519:<public-key-path>\""),
                                    );
                                }
                            }
                        } else {
                            self.push_error(
                                "E401",
                                format!("invalid require-signature format '{val}'"),
                                Some(child.span()),
                                Some("expected \"ed25519:<public-key-path>\""),
                            );
                        }
                    }
                }
                "preflight-checks" => {
                    preflight_explicitly_set = true;
                    self.record_span(
                        format!("{site_prefix}.ai-publish.preflight-checks"),
                        child.span(),
                    );
                    self.expect_no_children(child, "preflight-checks");
                    let (args, props) = self.split_entries(child);
                    for (prop, entry) in props {
                        self.push_error(
                            "E003",
                            format!("unknown property '{prop}' on 'preflight-checks'"),
                            Some(entry.span()),
                            Some("pass checks as string arguments, e.g.: preflight-checks \"no-secrets\" \"csp-valid\" \"max-size=50MB\""),
                        );
                    }
                    if args.is_empty() {
                        self.push_error(
                            "E402",
                            "'preflight-checks' requires at least one check argument",
                            Some(child.span()),
                            None,
                        );
                    }
                    for arg in args {
                        if let Some(raw) = self.expect_string(arg, "preflight check") {
                            if raw == "none" {
                                continue;
                            }
                            if let Some(check) = self.parse_preflight_check(raw, arg.span()) {
                                preflight_checks.push(check);
                            }
                        }
                    }
                }
                "mcp-endpoint" => {
                    self.record_span(
                        format!("{site_prefix}.ai-publish.mcp-endpoint"),
                        child.span(),
                    );
                    mcp_endpoint = self.parse_mcp_publish_endpoint(child);
                }
                other => {
                    self.push_error(
                        "E002",
                        format!("unknown directive '{other}' inside 'ai-publish'"),
                        Some(child.span()),
                        Some("allowed directives in 'ai-publish' are: storage, site-id, keep-versions, require-signature, jwt-public-key, jwt-issuer, allowed-subjects, preflight-checks, mcp-endpoint"),
                    );
                }
            }
        }

        let Some(storage) = storage else {
            self.push_error(
                "E401",
                "'ai-publish' block is missing required 'storage' directory",
                Some(node.span()),
                Some("add: storage \"/var/lib/miraserve/releases/my-site\""),
            );
            return None;
        };

        // Threat Model T6 (PUB-13): enable safe mandatory defaults when `preflight-checks` is omitted.
        if !preflight_explicitly_set {
            preflight_checks.push(PreflightCheck::NoSecrets);
            preflight_checks.push(PreflightCheck::MaxSize(ByteSize::from_bytes(
                50 * ByteSize::MIB,
            )));
        }

        Some(AiPublishConfig {
            storage,
            site_id,
            keep_versions,
            require_signature,
            jwt_public_key,
            jwt_issuer,
            allowed_subjects,
            preflight_checks,
            mcp_endpoint,
        })
    }

    fn parse_preflight_check(&mut self, raw: &str, span: SourceSpan) -> Option<PreflightCheck> {
        if raw == "no-secrets" {
            return Some(PreflightCheck::NoSecrets);
        }
        if raw == "csp-valid" {
            return Some(PreflightCheck::CspValid);
        }
        if raw == "no-inline-scripts" {
            return Some(PreflightCheck::NoInlineScripts);
        }
        if let Some(size_str) = raw.strip_prefix("max-size=") {
            match ByteSize::parse(size_str) {
                Ok(size) if size.as_bytes() > 0 => return Some(PreflightCheck::MaxSize(size)),
                Ok(_) => {
                    self.push_error(
                        "E402",
                        "preflight check 'max-size' must be greater than zero",
                        Some(span),
                        None,
                    );
                    return None;
                }
                Err(err) => {
                    self.push_error(
                        "E402",
                        format!("invalid 'max-size' preflight check: {err}"),
                        Some(span),
                        Some("example: \"max-size=50MB\""),
                    );
                    return None;
                }
            }
        }
        if let Some(files_str) = raw.strip_prefix("max-files=") {
            match files_str.parse::<u32>() {
                Ok(n) if n > 0 => return Some(PreflightCheck::MaxFiles(n)),
                _ => {
                    self.push_error(
                        "E402",
                        format!(
                            "invalid 'max-files' value '{files_str}' (must be a positive integer)"
                        ),
                        Some(span),
                        Some("example: \"max-files=5000\""),
                    );
                    return None;
                }
            }
        }

        self.push_error(
            "E402",
            format!("unknown ai-publish preflight check '{raw}'"),
            Some(span),
            Some("supported checks: \"no-secrets\", \"csp-valid\", \"no-inline-scripts\", \"max-size=<size>\", \"max-files=<n>\""),
        );
        None
    }

    fn parse_mcp_publish_endpoint(&mut self, node: &KdlNode) -> Option<McpPublishEndpoint> {
        self.expect_no_children(node, "mcp-endpoint");
        let (args, props) = self.split_entries(node);
        self.expect_exact_arg_count(&args, 1, "mcp-endpoint", node.span())?;
        let path_entry = args.first().copied()?;
        let path = self.expect_string(path_entry, "mcp-endpoint path")?;

        let mut auth: Option<PublishAuthMode> = None;
        for (prop, entry) in props {
            match prop {
                "auth" => {
                    if let Some(mode) = self.expect_string(entry, "auth") {
                        match mode {
                            "oauth-jwt" => auth = Some(PublishAuthMode::OAuthJwt),
                            "mtls" => auth = Some(PublishAuthMode::Mtls),
                            "ed25519" => auth = Some(PublishAuthMode::Ed25519),
                            "none" => {
                                self.push_error(
                                    "E401",
                                    "unauthenticated 'mcp-endpoint' (auth=\"none\") is forbidden",
                                    Some(entry.span()),
                                    Some("Threat Model T6 requires cryptographic auth: \"oauth-jwt\", \"mtls\", or \"ed25519\""),
                                );
                            }
                            other => {
                                self.push_error(
                                    "E401",
                                    format!("unsupported mcp-endpoint auth mode '{other}'"),
                                    Some(entry.span()),
                                    Some("allowed values: \"oauth-jwt\", \"mtls\", \"ed25519\""),
                                );
                            }
                        }
                    }
                }
                other => {
                    self.push_error(
                        "E003",
                        format!("unknown property '{other}' on 'mcp-endpoint'"),
                        Some(entry.span()),
                        Some("allowed property on 'mcp-endpoint' is: auth"),
                    );
                }
            }
        }

        let Some(auth) = auth else {
            self.push_error(
                "E401",
                "'mcp-endpoint' requires explicit authentication via 'auth=\"oauth-jwt\"|\"mtls\"|\"ed25519\"'",
                Some(node.span()),
                None,
            );
            return None;
        };

        Some(McpPublishEndpoint {
            path: path.to_owned(),
            auth,
        })
    }

    fn parse_route(&mut self, node: &KdlNode, route_prefix: &str) -> Option<RouteConfig> {
        let (args, props) = self.split_entries(node);
        for (prop, entry) in props {
            self.push_error(
                "E003",
                format!("unknown property '{prop}' on 'route'"),
                Some(entry.span()),
                Some("pass the route pattern as a positional string: route \"/*\" { ... }"),
            );
        }
        self.expect_exact_arg_count(&args, 1, "route", node.span())?;
        let pattern_entry = args.first().copied()?;
        let pattern = self
            .expect_string(pattern_entry, "route pattern")?
            .to_owned();
        let children = self.expect_children(node, "route")?;

        let mut root: Option<String> = None;
        let mut rate_limit: Option<RateLimitConfig> = None;
        let mut security_headers: Option<SecurityHeadersPolicy> = None;
        let mut handler: Option<RouteHandler> = None;
        let mut headers: Vec<HeaderRule> = Vec::new();
        let mut access: Vec<AccessRule> = Vec::new();
        let mut basic_auth: Option<BasicAuthConfig> = None;
        let mut seen_meta = HashSet::new();

        for child in children.nodes() {
            let name = child.name().value();
            match name {
                "root" => {
                    if !seen_meta.insert("root") {
                        self.push_error(
                            "E005",
                            "duplicate 'root' inside 'route'",
                            Some(child.span()),
                            None,
                        );
                        continue;
                    }
                    self.record_span(format!("{route_prefix}.root"), child.span());
                    if let Some(val) = self.expect_single_string_node(child) {
                        root = Some(val.to_owned());
                    }
                }
                "basic-auth" => {
                    self.record_span(format!("{route_prefix}.basic-auth"), child.span());
                    if basic_auth.is_some() {
                        self.push_error(
                            "E005",
                            "duplicate 'basic-auth' inside 'route'",
                            Some(child.span()),
                            None,
                        );
                    } else {
                        basic_auth = self.parse_basic_auth(child);
                    }
                }
                "access" => {
                    self.record_span(format!("{route_prefix}.access"), child.span());
                    let parsed = self.parse_access_block(child, access.len());
                    access.extend(parsed);
                }
                "headers" => {
                    self.record_span(format!("{route_prefix}.headers"), child.span());
                    let parsed = self.parse_headers_block(child, headers.len());
                    headers.extend(parsed);
                }
                "rate-limit" => {
                    if !seen_meta.insert("rate-limit") {
                        self.push_error(
                            "E005",
                            "duplicate 'rate-limit' inside 'route'",
                            Some(child.span()),
                            None,
                        );
                        continue;
                    }
                    self.record_span(format!("{route_prefix}.rate-limit"), child.span());
                    rate_limit = self.parse_rate_limit(child);
                }
                "security-headers" => {
                    if !seen_meta.insert("security-headers") {
                        self.push_error(
                            "E005",
                            "duplicate 'security-headers' inside 'route'",
                            Some(child.span()),
                            None,
                        );
                        continue;
                    }
                    self.record_span(format!("{route_prefix}.security-headers"), child.span());
                    security_headers = self.parse_security_headers(child);
                }
                "fastcgi-pass" => {
                    if handler.is_some() {
                        self.push_error(
                            "E302",
                            "route cannot configure multiple terminal handlers",
                            Some(child.span()),
                            Some("define each handler in its own 'route' block"),
                        );
                        continue;
                    }
                    self.record_span(format!("{route_prefix}.fastcgi-pass"), child.span());
                    if let Some(fcgi) = self.parse_fastcgi_pass(child) {
                        handler = Some(RouteHandler::FastCgi(fcgi));
                    }
                }
                "try-files" => {
                    if handler.is_some() {
                        self.push_error(
                            "E302",
                            "route cannot configure multiple terminal handlers",
                            Some(child.span()),
                            Some("define each handler in its own 'route' block"),
                        );
                        continue;
                    }
                    self.record_span(format!("{route_prefix}.try-files"), child.span());
                    if let Some(tf) = self.parse_try_files(child) {
                        handler = Some(RouteHandler::TryFiles(tf));
                    }
                }
                "mcp-gateway" => {
                    if handler.is_some() {
                        self.push_error(
                            "E302",
                            "route cannot configure multiple terminal handlers",
                            Some(child.span()),
                            Some("define each handler in its own 'route' block"),
                        );
                        continue;
                    }
                    self.record_span(format!("{route_prefix}.mcp-gateway"), child.span());
                    if let Some(mcp) = self.parse_mcp_gateway(child, route_prefix) {
                        handler = Some(RouteHandler::McpGateway(mcp));
                    }
                }
                "reverse-proxy" => {
                    if handler.is_some() {
                        self.push_error(
                            "E302",
                            "route cannot configure multiple terminal handlers",
                            Some(child.span()),
                            Some("define each handler in its own 'route' block"),
                        );
                        continue;
                    }
                    self.record_span(format!("{route_prefix}.reverse-proxy"), child.span());
                    if let Some(rp) = self.parse_reverse_proxy(child, route_prefix) {
                        handler = Some(RouteHandler::ReverseProxy(rp));
                    }
                }
                "static" => {
                    if handler.is_some() {
                        self.push_error(
                            "E302",
                            "route cannot configure multiple terminal handlers",
                            Some(child.span()),
                            Some("define each handler in its own 'route' block"),
                        );
                        continue;
                    }
                    self.record_span(format!("{route_prefix}.static"), child.span());
                    handler = Some(RouteHandler::Static(self.parse_static(child, route_prefix)));
                }
                "wasm-plugin" => {
                    if handler.is_some() {
                        self.push_error(
                            "E302",
                            "route cannot configure multiple terminal handlers",
                            Some(child.span()),
                            Some("define each handler in its own 'route' block"),
                        );
                        continue;
                    }
                    self.record_span(format!("{route_prefix}.wasm-plugin"), child.span());
                    if let Some(wasm) = self.parse_wasm_plugin(child, route_prefix) {
                        handler = Some(RouteHandler::WasmPlugin(wasm));
                    }
                }
                "respond" => {
                    if handler.is_some() {
                        self.push_error(
                            "E302",
                            "route cannot configure multiple terminal handlers",
                            Some(child.span()),
                            Some("define each handler in its own 'route' block"),
                        );
                        continue;
                    }
                    self.record_span(format!("{route_prefix}.respond"), child.span());
                    if let Some(code) = self.expect_single_u32_node(child) {
                        handler = Some(RouteHandler::Respond(u16::try_from(code).unwrap_or(0)));
                    }
                }
                "redirect" => {
                    if handler.is_some() {
                        self.push_error(
                            "E302",
                            "route cannot configure multiple terminal handlers",
                            Some(child.span()),
                            Some("define each handler in its own 'route' block"),
                        );
                        continue;
                    }
                    self.record_span(format!("{route_prefix}.redirect"), child.span());
                    if let Some(redirect) = self.parse_redirect(child) {
                        handler = Some(RouteHandler::Redirect(redirect));
                    }
                }
                other => {
                    self.push_error(
                        "E002",
                        format!("unknown directive '{other}' inside 'route'"),
                        Some(child.span()),
                        Some("allowed directives in 'route' are: fastcgi-pass, try-files, mcp-gateway, reverse-proxy, static, wasm-plugin, redirect, respond, root, rate-limit, security-headers, access, basic-auth, headers"),
                    );
                }
            }
        }

        let Some(handler) = handler else {
            self.push_error(
                "E302",
                format!("route '{pattern}' does not configure a handler"),
                Some(node.span()),
                Some("add one of: fastcgi-pass, try-files, mcp-gateway, reverse-proxy, or static"),
            );
            return None;
        };

        Some(RouteConfig {
            pattern,
            root,
            rate_limit,
            security_headers,
            handler,
            headers,
            access,
            basic_auth,
        })
    }

    fn parse_try_files(&mut self, node: &KdlNode) -> Option<TryFilesConfig> {
        self.expect_no_children(node, "try-files");
        let (args, props) = self.split_entries(node);
        let mut fallback_unless_extension = false;
        for (prop, entry) in props {
            match prop {
                "fallback-unless-extension" => {
                    if let Some(flag) =
                        self.expect_bool(entry, "try-files fallback-unless-extension")
                    {
                        fallback_unless_extension = flag;
                    }
                }
                other => {
                    self.push_error(
                        "E003",
                        format!("unexpected property '{other}' on 'try-files'"),
                        Some(entry.span()),
                        None,
                    );
                }
            }
        }
        if args.is_empty() {
            self.push_error(
                "E004",
                "'try-files' requires at least one string argument",
                Some(node.span()),
                None,
            );
            return None;
        }
        let mut candidates = Vec::with_capacity(args.len());
        for arg in args {
            if let Some(s) = self.expect_string(arg, "try-files") {
                candidates.push(s.to_owned());
            }
        }
        Some(TryFilesConfig {
            candidates,
            fallback_unless_extension,
        })
    }

    #[allow(clippy::too_many_lines, reason = "one arm per property")]
    fn parse_fastcgi_pass(&mut self, node: &KdlNode) -> Option<FastCgiConfig> {
        self.expect_no_children(node, "fastcgi-pass");
        let (args, props) = self.split_entries(node);
        self.expect_exact_arg_count(&args, 1, "fastcgi-pass", node.span())?;
        let raw = self.expect_string(*args.first()?, "fastcgi-pass endpoint")?;

        let mut timeout = Duration::from_secs(30);
        let mut replay_safe_methods = false;
        let mut max_streamed_answers = None;
        for (prop, entry) in props {
            match prop {
                "max-streamed-answers" => {
                    if let Some(max) = self.expect_u32(entry, "fastcgi-pass max-streamed-answers") {
                        if (1..=10_000).contains(&max) {
                            max_streamed_answers = Some(max);
                        } else {
                            self.push_error(
                                "E007",
                                "'max-streamed-answers' must be between 1 and 10000".to_owned(),
                                Some(entry.span()),
                                Some("example: max-streamed-answers=4 (about half of the pool's workers)"),
                            );
                        }
                    }
                }
                "replay-safe-methods" => {
                    if let Some(flag) = self.expect_bool(entry, "fastcgi-pass replay-safe-methods")
                    {
                        replay_safe_methods = flag;
                    }
                }
                "timeout" => {
                    if let Some(raw_dur) = self.expect_string(entry, "fastcgi-pass timeout") {
                        match parse_duration(raw_dur) {
                            Ok(d) => timeout = d,
                            Err(err) => {
                                self.push_error(
                                    "E304",
                                    format!("invalid fastcgi-pass timeout '{raw_dur}': {err}"),
                                    Some(entry.span()),
                                    Some("example: timeout=\"30s\""),
                                );
                            }
                        }
                    }
                }
                other => {
                    self.push_error(
                        "E003",
                        format!("unknown property '{other}' on 'fastcgi-pass'"),
                        Some(entry.span()),
                        Some("allowed properties on 'fastcgi-pass' are: timeout, replay-safe-methods, max-streamed-answers"),
                    );
                }
            }
        }

        let target = if let Some(sock_path) = raw.strip_prefix("unix:") {
            if sock_path.trim().is_empty() {
                self.push_error(
                    "E304",
                    "FastCGI Unix socket path must not be empty",
                    Some(node.span()),
                    Some("example: fastcgi-pass \"unix:/run/php/php8.3-fpm.sock\""),
                );
                return None;
            }
            FastCgiTarget::Unix {
                path: sock_path.to_owned(),
            }
        } else {
            let stripped = raw.strip_prefix("tcp://").unwrap_or(raw);
            let Some((host, port_str)) = stripped.rsplit_once(':') else {
                self.push_error(
                    "E304",
                    format!("invalid FastCGI endpoint '{raw}'"),
                    Some(node.span()),
                    Some("use \"unix:/path/to/php-fpm.sock\" or \"tcp://127.0.0.1:9000\""),
                );
                return None;
            };
            let host_clean = host.trim_start_matches('[').trim_end_matches(']');
            let Ok(port) = port_str.parse::<u16>() else {
                self.push_error(
                    "E304",
                    format!("invalid FastCGI port in '{raw}'"),
                    Some(node.span()),
                    None,
                );
                return None;
            };
            if host_clean.is_empty() || port == 0 {
                self.push_error(
                    "E304",
                    format!(
                        "invalid FastCGI TCP target '{raw}' (host must be non-empty and port > 0)"
                    ),
                    Some(node.span()),
                    None,
                );
                return None;
            }
            FastCgiTarget::Tcp {
                host: host_clean.to_owned(),
                port,
            }
        };

        Some(FastCgiConfig {
            target,
            timeout,
            replay_safe_methods,
            max_streamed_answers,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn parse_mcp_gateway(
        &mut self,
        node: &KdlNode,
        route_prefix: &str,
    ) -> Option<McpGatewayConfig> {
        let (args, props) = self.split_entries(node);
        if !args.is_empty() {
            self.push_error(
                "E004",
                "'mcp-gateway' takes property 'upstream=\"...\"', not positional arguments",
                Some(node.span()),
                None,
            );
        }

        let mut upstream: Option<String> = None;
        for (prop, entry) in props {
            match prop {
                "upstream" => {
                    self.record_span(format!("{route_prefix}.mcp-gateway.upstream"), entry.span());
                    if let Some(val) = self.expect_string(entry, "upstream") {
                        upstream = Some(val.to_owned());
                    }
                }
                other => {
                    self.push_error(
                        "E003",
                        format!("unknown property '{other}' on 'mcp-gateway'"),
                        Some(entry.span()),
                        Some("allowed property on 'mcp-gateway' is: upstream"),
                    );
                }
            }
        }

        let mut oauth_resource_metadata = true;
        let mut jwt_public_key: Option<String> = None;
        let mut jwks_url: Option<String> = None;
        let mut jwt_issuer: Option<String> = None;
        let mut jwt_audience: Option<String> = None;
        let mut required_scope: Option<String> = None;
        let mut allow_tools = Vec::new();
        let mut deny_tools = Vec::new();
        let mut audit_log = AuditLogMode::StructuredJson;
        let mut max_json_depth: u32 = 32;
        let mut max_request_bytes = ByteSize::from_bytes(ByteSize::MB);
        let mut upstream_connect_timeout: Option<Duration> = None;
        let mut upstream_response_timeout: Option<Duration> = None;
        let mut upstream_body_idle_timeout: Option<Duration> = None;

        if let Some(children) = node.children() {
            let mut seen = HashSet::new();
            for child in children.nodes() {
                let name = child.name().value();
                if name != "allow-tools" && name != "deny-tools" && !seen.insert(name.to_owned()) {
                    self.push_error(
                        "E005",
                        format!("duplicate directive '{name}' inside 'mcp-gateway'"),
                        Some(child.span()),
                        None,
                    );
                    continue;
                }
                match name {
                    "oauth-resource-metadata" => {
                        self.record_span(
                            format!("{route_prefix}.mcp-gateway.oauth-resource-metadata"),
                            child.span(),
                        );
                        if let Some(val) = self.expect_single_bool_node(child) {
                            oauth_resource_metadata = val;
                        }
                    }
                    "jwt-public-key" => {
                        self.record_span(
                            format!("{route_prefix}.mcp-gateway.jwt-public-key"),
                            child.span(),
                        );
                        if let Some(val) = self.expect_single_string_node(child) {
                            jwt_public_key = Some(val.to_owned());
                        }
                    }
                    "jwks-url" => {
                        self.record_span(
                            format!("{route_prefix}.mcp-gateway.jwks-url"),
                            child.span(),
                        );
                        if let Some(val) = self.expect_single_string_node(child) {
                            jwks_url = Some(val.to_owned());
                        }
                    }
                    "jwt-issuer" => {
                        self.record_span(
                            format!("{route_prefix}.mcp-gateway.jwt-issuer"),
                            child.span(),
                        );
                        if let Some(val) = self.expect_single_string_node(child) {
                            jwt_issuer = Some(val.to_owned());
                        }
                    }
                    "jwt-audience" => {
                        self.record_span(
                            format!("{route_prefix}.mcp-gateway.jwt-audience"),
                            child.span(),
                        );
                        if let Some(val) = self.expect_single_string_node(child) {
                            jwt_audience = Some(val.to_owned());
                        }
                    }
                    "required-scope" => {
                        self.record_span(
                            format!("{route_prefix}.mcp-gateway.required-scope"),
                            child.span(),
                        );
                        if let Some(val) = self.expect_single_string_node(child) {
                            required_scope = Some(val.to_owned());
                        }
                    }
                    "allow-tools" => {
                        self.record_span(
                            format!("{route_prefix}.mcp-gateway.allow-tools"),
                            child.span(),
                        );
                        if let Some(items) = self.parse_string_list_node(child, "allow-tools") {
                            allow_tools.extend(items);
                        }
                    }
                    "deny-tools" => {
                        self.record_span(
                            format!("{route_prefix}.mcp-gateway.deny-tools"),
                            child.span(),
                        );
                        if let Some(items) = self.parse_string_list_node(child, "deny-tools") {
                            deny_tools.extend(items);
                        }
                    }
                    "audit-log" => {
                        self.record_span(
                            format!("{route_prefix}.mcp-gateway.audit-log"),
                            child.span(),
                        );
                        if let Some(val) = self.expect_single_string_node(child) {
                            match val {
                                "structured-json" => audit_log = AuditLogMode::StructuredJson,
                                "redacted-text" => audit_log = AuditLogMode::RedactedText,
                                "off" => audit_log = AuditLogMode::Off,
                                other => {
                                    self.push_error(
                                        "E403",
                                        format!("invalid mcp-gateway audit-log mode '{other}'"),
                                        Some(child.span()),
                                        Some("allowed values: \"structured-json\", \"redacted-text\", \"off\""),
                                    );
                                }
                            }
                        }
                    }
                    "max-json-depth" => {
                        self.record_span(
                            format!("{route_prefix}.mcp-gateway.max-json-depth"),
                            child.span(),
                        );
                        if let Some(v) = self.expect_single_u32_node(child) {
                            max_json_depth = v;
                        }
                    }
                    "max-request-bytes" => {
                        self.record_span(
                            format!("{route_prefix}.mcp-gateway.max-request-bytes"),
                            child.span(),
                        );
                        if let Some(sz) = self.expect_single_byte_size_node(child) {
                            max_request_bytes = sz;
                        }
                    }
                    "upstream-connect-timeout" => {
                        self.record_span(
                            format!("{route_prefix}.mcp-gateway.upstream-connect-timeout"),
                            child.span(),
                        );
                        if let Some(d) = self.expect_single_duration_node(child) {
                            upstream_connect_timeout = Some(d);
                        }
                    }
                    "upstream-response-timeout" => {
                        self.record_span(
                            format!("{route_prefix}.mcp-gateway.upstream-response-timeout"),
                            child.span(),
                        );
                        if let Some(d) = self.expect_single_duration_node(child) {
                            upstream_response_timeout = Some(d);
                        }
                    }
                    "upstream-body-idle-timeout" => {
                        self.record_span(
                            format!("{route_prefix}.mcp-gateway.upstream-body-idle-timeout"),
                            child.span(),
                        );
                        if let Some(d) = self.expect_single_duration_node(child) {
                            upstream_body_idle_timeout = Some(d);
                        }
                    }
                    other => {
                        self.push_error(
                            "E002",
                            format!("unknown directive '{other}' inside 'mcp-gateway'"),
                            Some(child.span()),
                            Some("allowed directives in 'mcp-gateway' are: oauth-resource-metadata, jwt-public-key, jwks-url, jwt-issuer, jwt-audience, required-scope, allow-tools, deny-tools, audit-log, max-json-depth, max-request-bytes, upstream-connect-timeout, upstream-response-timeout, upstream-body-idle-timeout"),
                        );
                    }
                }
            }
        }

        let Some(upstream) = upstream else {
            self.push_error(
                "E403",
                "'mcp-gateway' requires property 'upstream=\"https://...\"'",
                Some(node.span()),
                None,
            );
            return None;
        };

        Some(McpGatewayConfig {
            upstream,
            oauth_resource_metadata,
            jwt_public_key,
            jwks_url,
            jwt_issuer,
            jwt_audience,
            required_scope,
            allow_tools,
            deny_tools,
            audit_log,
            max_json_depth,
            max_request_bytes,
            upstream_connect_timeout,
            upstream_response_timeout,
            upstream_body_idle_timeout,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn parse_reverse_proxy(
        &mut self,
        node: &KdlNode,
        route_prefix: &str,
    ) -> Option<ReverseProxyConfig> {
        self.expect_no_entries(node, "reverse-proxy");
        let children = self.expect_children(node, "reverse-proxy")?;

        let mut upstreams = Vec::new();
        let mut streaming_flush = StreamingFlushMode::Buffered;
        let mut lb_policy = LoadBalancePolicy::RoundRobin;
        let mut health_check: Option<HealthCheckConfig> = None;
        let mut upstream_tls: Option<UpstreamTlsConfig> = None;
        let mut upstream_connect_timeout: Option<Duration> = None;
        let mut upstream_response_timeout: Option<Duration> = None;
        let mut upstream_body_idle_timeout: Option<Duration> = None;
        let mut preserve_host = false;
        let mut allow_upgrades = true;
        let mut strip_prefix = false;
        let mut seen = HashSet::new();

        for child in children.nodes() {
            let name = child.name().value();
            if name != "upstream" && !seen.insert(name.to_owned()) {
                self.push_error(
                    "E005",
                    format!("duplicate directive '{name}' inside 'reverse-proxy'"),
                    Some(child.span()),
                    None,
                );
                continue;
            }
            match name {
                "upstream" => {
                    self.expect_no_children(child, "upstream");
                    let (args, props) = self.split_entries(child);
                    if self
                        .expect_exact_arg_count(&args, 1, "upstream", child.span())
                        .is_none()
                    {
                        continue;
                    }
                    let Some(url_entry) = args.first().copied() else {
                        continue;
                    };
                    let Some(url_str) = self.expect_string(url_entry, "upstream URL") else {
                        continue;
                    };
                    let mut weight: u32 = 1;
                    for (prop, entry) in props {
                        match prop {
                            "weight" => {
                                if let Some(w) = self.expect_u32(entry, "weight") {
                                    weight = w;
                                }
                            }
                            other => {
                                self.push_error(
                                    "E003",
                                    format!("unknown property '{other}' on 'upstream'"),
                                    Some(entry.span()),
                                    Some("allowed property on 'upstream' is: weight"),
                                );
                            }
                        }
                    }
                    let u_idx = upstreams.len();
                    self.record_span(
                        format!("{route_prefix}.reverse-proxy.upstream[{u_idx}]"),
                        child.span(),
                    );
                    upstreams.push(UpstreamConfig {
                        url: url_str.to_owned(),
                        weight,
                    });
                }
                "streaming-flush" => {
                    if let Some(val) = self.expect_single_string_node(child) {
                        match val {
                            "immediate" => streaming_flush = StreamingFlushMode::Immediate,
                            "buffered" => streaming_flush = StreamingFlushMode::Buffered,
                            other => {
                                self.push_error(
                                    "E305",
                                    format!("invalid streaming-flush mode '{other}'"),
                                    Some(child.span()),
                                    Some("allowed values: \"immediate\" (for SSE/LLM streaming) or \"buffered\""),
                                );
                            }
                        }
                    }
                }
                "lb-policy" => {
                    if let Some(val) = self.expect_single_string_node(child) {
                        match val {
                            "round-robin" => lb_policy = LoadBalancePolicy::RoundRobin,
                            "least-conn" => lb_policy = LoadBalancePolicy::LeastConn,
                            "random" => lb_policy = LoadBalancePolicy::Random,
                            other => {
                                self.push_error(
                                    "E305",
                                    format!("invalid lb-policy '{other}'"),
                                    Some(child.span()),
                                    Some("allowed values: \"round-robin\", \"least-conn\", \"random\""),
                                );
                            }
                        }
                    }
                }
                "health-check" => {
                    self.record_span(
                        format!("{route_prefix}.reverse-proxy.health-check"),
                        child.span(),
                    );
                    health_check = self.parse_health_check(child);
                }
                "upstream-tls" => {
                    let tls_prefix = format!("{route_prefix}.reverse-proxy.upstream-tls");
                    self.record_span(tls_prefix.clone(), child.span());
                    upstream_tls = Some(self.parse_upstream_tls(child, &tls_prefix));
                }
                "upstream-connect-timeout" => {
                    self.record_span(
                        format!("{route_prefix}.reverse-proxy.upstream-connect-timeout"),
                        child.span(),
                    );
                    if let Some(d) = self.expect_single_duration_node(child) {
                        upstream_connect_timeout = Some(d);
                    }
                }
                "upstream-response-timeout" => {
                    self.record_span(
                        format!("{route_prefix}.reverse-proxy.upstream-response-timeout"),
                        child.span(),
                    );
                    if let Some(d) = self.expect_single_duration_node(child) {
                        upstream_response_timeout = Some(d);
                    }
                }
                "upstream-body-idle-timeout" => {
                    self.record_span(
                        format!("{route_prefix}.reverse-proxy.upstream-body-idle-timeout"),
                        child.span(),
                    );
                    if let Some(d) = self.expect_single_duration_node(child) {
                        upstream_body_idle_timeout = Some(d);
                    }
                }
                "allow-upgrades" => {
                    self.record_span(
                        format!("{route_prefix}.reverse-proxy.allow-upgrades"),
                        child.span(),
                    );
                    if let Some(flag) = self.expect_single_bool_node(child) {
                        allow_upgrades = flag;
                    }
                }
                "strip-prefix" => {
                    self.record_span(
                        format!("{route_prefix}.reverse-proxy.strip-prefix"),
                        child.span(),
                    );
                    if let Some(flag) = self.expect_single_bool_node(child) {
                        strip_prefix = flag;
                    }
                }
                "preserve-host" => {
                    self.record_span(
                        format!("{route_prefix}.reverse-proxy.preserve-host"),
                        child.span(),
                    );
                    if let Some(flag) = self.expect_single_bool_node(child) {
                        preserve_host = flag;
                    }
                }
                other => {
                    self.push_error(
                        "E002",
                        format!("unknown directive '{other}' inside 'reverse-proxy'"),
                        Some(child.span()),
                        Some("allowed directives in 'reverse-proxy' are: upstream, streaming-flush, lb-policy, health-check, upstream-tls, upstream-connect-timeout, upstream-response-timeout, upstream-body-idle-timeout, strip-prefix, preserve-host, allow-upgrades"),
                    );
                }
            }
        }

        Some(ReverseProxyConfig {
            upstreams,
            streaming_flush,
            lb_policy,
            health_check,
            upstream_tls,
            upstream_connect_timeout,
            upstream_response_timeout,
            upstream_body_idle_timeout,
            preserve_host,
            allow_upgrades,
            strip_prefix,
        })
    }

    fn parse_health_check(&mut self, node: &KdlNode) -> Option<HealthCheckConfig> {
        self.expect_no_children(node, "health-check");
        let (args, props) = self.split_entries(node);
        if !args.is_empty() {
            self.push_error(
                "E004",
                "'health-check' takes named properties, not positional arguments",
                Some(node.span()),
                Some("example: health-check path=\"/health\" interval=\"5s\""),
            );
        }

        let mut path: Option<String> = None;
        let mut interval: Option<Duration> = None;
        let mut timeout: Option<Duration> = None;
        let mut unhealthy_threshold: u32 = 3;
        let mut host: Option<String> = None;

        for (prop, entry) in props {
            match prop {
                "path" => {
                    if let Some(val) = self.expect_string(entry, "path") {
                        path = Some(val.to_owned());
                    }
                }
                "host" => {
                    if let Some(val) = self.expect_string(entry, "host") {
                        host = Some(val.to_owned());
                    }
                }
                "interval" => {
                    if let Some(raw) = self.expect_string(entry, "interval") {
                        match parse_duration(raw) {
                            Ok(d) => interval = Some(d),
                            Err(err) => self.push_error(
                                "E007",
                                format!("invalid health-check interval: {err}"),
                                Some(entry.span()),
                                None,
                            ),
                        }
                    }
                }
                "timeout" => {
                    if let Some(raw) = self.expect_string(entry, "timeout") {
                        match parse_duration(raw) {
                            Ok(d) => timeout = Some(d),
                            Err(err) => self.push_error(
                                "E007",
                                format!("invalid health-check timeout: {err}"),
                                Some(entry.span()),
                                None,
                            ),
                        }
                    }
                }
                "unhealthy-threshold" => {
                    if let Some(v) = self.expect_u32(entry, "unhealthy-threshold") {
                        unhealthy_threshold = v;
                    }
                }
                other => {
                    self.push_error(
                        "E003",
                        format!("unknown property '{other}' on 'health-check'"),
                        Some(entry.span()),
                        Some("allowed properties: path, interval, timeout, unhealthy-threshold, host"),
                    );
                }
            }
        }

        let Some(path) = path else {
            self.push_error(
                "E305",
                "'health-check' requires property 'path=\"/...\"'",
                Some(node.span()),
                None,
            );
            return None;
        };
        let Some(interval) = interval else {
            self.push_error(
                "E305",
                "'health-check' requires property 'interval=\"<duration>\"'",
                Some(node.span()),
                None,
            );
            return None;
        };

        Some(HealthCheckConfig {
            path,
            interval,
            timeout,
            unhealthy_threshold,
            host,
        })
    }

    fn parse_upstream_tls(&mut self, node: &KdlNode, prefix: &str) -> UpstreamTlsConfig {
        self.expect_no_entries(node, "upstream-tls");
        let Some(children) = self.expect_children(node, "upstream-tls") else {
            return UpstreamTlsConfig {
                ca_cert: None,
                client_cert: None,
                client_key: None,
            };
        };

        let mut ca_cert = None;
        let mut client_cert = None;
        let mut client_key = None;
        let mut seen = HashSet::new();

        for child in children.nodes() {
            let name = child.name().value();
            if !seen.insert(name.to_owned()) {
                self.push_error(
                    "E005",
                    format!("duplicate directive '{name}' inside 'upstream-tls'"),
                    Some(child.span()),
                    None,
                );
                continue;
            }
            match name {
                "ca-cert" => {
                    self.record_span(format!("{prefix}.ca-cert"), child.span());
                    if let Some(v) = self.expect_single_string_node(child) {
                        ca_cert = Some(v.to_owned());
                    }
                }
                "client-cert" => {
                    self.record_span(format!("{prefix}.client-cert"), child.span());
                    if let Some(v) = self.expect_single_string_node(child) {
                        client_cert = Some(v.to_owned());
                    }
                }
                "client-key" => {
                    self.record_span(format!("{prefix}.client-key"), child.span());
                    if let Some(v) = self.expect_single_string_node(child) {
                        client_key = Some(v.to_owned());
                    }
                }
                other => {
                    self.push_error(
                        "E002",
                        format!("unknown directive '{other}' inside 'upstream-tls'"),
                        Some(child.span()),
                        Some("allowed directives: ca-cert, client-cert, client-key"),
                    );
                }
            }
        }

        UpstreamTlsConfig {
            ca_cert,
            client_cert,
            client_key,
        }
    }

    fn parse_static(&mut self, node: &KdlNode, route_prefix: &str) -> StaticConfig {
        self.expect_no_entries(node, "static");
        let mut cfg = StaticConfig::default();
        let Some(children) = node.children() else {
            return cfg;
        };

        let mut seen = HashSet::new();
        for child in children.nodes() {
            let name = child.name().value();
            if !seen.insert(name.to_owned()) {
                self.push_error(
                    "E005",
                    format!("duplicate directive '{name}' inside 'static'"),
                    Some(child.span()),
                    None,
                );
                continue;
            }
            match name {
                "index" => {
                    self.record_span(format!("{route_prefix}.static.index"), child.span());
                    if let Some(items) = self.parse_string_list_node(child, "index") {
                        cfg.index = items;
                        cfg.index_explicit = true;
                    }
                }
                "dotfiles" => {
                    self.record_span(format!("{route_prefix}.static.dotfiles"), child.span());
                    if let Some(val) = self.expect_single_string_node(child) {
                        match val {
                            "deny" => cfg.dotfiles = DotfilesPolicy::Deny,
                            "allow" => cfg.dotfiles = DotfilesPolicy::Allow,
                            other => {
                                self.push_error(
                                    "E203",
                                    format!("invalid dotfiles policy '{other}'"),
                                    Some(child.span()),
                                    Some("allowed values: \"deny\" (default) or \"allow\""),
                                );
                            }
                        }
                    }
                }
                "compression" => {
                    if let Some(val) = self.expect_single_bool_node(child) {
                        cfg.compression = val;
                    }
                }
                "precompressed" => {
                    self.record_span(format!("{route_prefix}.static.precompressed"), child.span());
                    if let Some(policy) = self.parse_precompressed(child) {
                        cfg.precompressed = policy;
                        cfg.precompressed_explicit = true;
                    }
                }
                other => {
                    self.push_error(
                        "E002",
                        format!("unknown directive '{other}' inside 'static'"),
                        Some(child.span()),
                        Some("allowed directives in 'static' are: index, dotfiles, compression, precompressed"),
                    );
                }
            }
        }

        cfg
    }

    // ---- Low-level strict KDL entry helpers ----

    fn mark_singleton(&mut self, flag: &mut bool, label: &str, span: SourceSpan) -> bool {
        if *flag {
            self.push_error(
                "E005",
                format!("duplicate '{label}' block"),
                Some(span),
                None,
            );
            false
        } else {
            *flag = true;
            true
        }
    }

    fn split_entries<'n>(
        &mut self,
        node: &'n KdlNode,
    ) -> (Vec<&'n KdlEntry>, Vec<(&'n str, &'n KdlEntry)>) {
        let mut args = Vec::new();
        let mut props = Vec::new();
        let mut seen_props = HashSet::new();

        for entry in node.entries() {
            if let Some(name) = entry.name() {
                let key = name.value();
                if !seen_props.insert(key) {
                    self.push_error(
                        "E005",
                        format!("duplicate property '{key}' on '{}'", node.name().value()),
                        Some(entry.span()),
                        None,
                    );
                    continue;
                }
                props.push((key, entry));
            } else {
                args.push(entry);
            }
        }

        (args, props)
    }

    fn expect_no_entries(&mut self, node: &KdlNode, directive: &str) {
        if !node.entries().is_empty() {
            self.push_error(
                "E004",
                format!("'{directive}' does not accept arguments or properties"),
                Some(node.span()),
                None,
            );
        }
    }

    fn expect_no_children(&mut self, node: &KdlNode, directive: &str) {
        if node.children().is_some() {
            self.push_error(
                "E004",
                format!("'{directive}' does not accept a child '{{ ... }}' block"),
                Some(node.span()),
                None,
            );
        }
    }

    fn expect_children<'n>(
        &mut self,
        node: &'n KdlNode,
        directive: &str,
    ) -> Option<&'n KdlDocument> {
        if let Some(children) = node.children() {
            Some(children)
        } else {
            self.push_error(
                "E004",
                format!("'{directive}' requires a child '{{ ... }}' block"),
                Some(node.span()),
                None,
            );
            None
        }
    }

    fn expect_exact_arg_count(
        &mut self,
        args: &[&KdlEntry],
        expected: usize,
        directive: &str,
        span: SourceSpan,
    ) -> Option<()> {
        if args.len() != expected {
            self.push_error(
                "E004",
                format!(
                    "'{directive}' expects {expected} positional argument(s), found {}",
                    args.len()
                ),
                Some(span),
                None,
            );
            return None;
        }
        Some(())
    }

    /// Parses a site's `rewrite { rule "<regex>" ... }` block.
    fn parse_rewrite_block(
        &mut self,
        node: &KdlNode,
        site_prefix: &str,
        first_index: usize,
    ) -> Vec<RewriteRule> {
        self.expect_no_entries(node, "rewrite");
        let Some(children) = self.expect_children(node, "rewrite") else {
            return Vec::new();
        };
        let mut rules = Vec::new();
        for child in children.nodes() {
            if child.name().value() != "rule" {
                self.push_error(
                    "E002",
                    format!(
                        "unknown directive '{}' inside 'rewrite'",
                        child.name().value()
                    ),
                    Some(child.span()),
                    Some("the only directive in 'rewrite' is: rule"),
                );
                continue;
            }
            let idx = first_index.saturating_add(rules.len());
            self.record_span(format!("{site_prefix}.rewrite.rule[{idx}]"), child.span());
            if let Some(rule) = self.parse_rewrite_rule(child) {
                rules.push(rule);
            }
        }
        rules
    }

    #[allow(clippy::too_many_lines)]
    fn parse_rewrite_rule(&mut self, node: &KdlNode) -> Option<RewriteRule> {
        let conditions = self.parse_rewrite_conditions(node);
        let (args, props) = self.split_entries(node);
        let mut pass = false;
        let mut if_not_regular_file = false;
        let mut if_file = false;
        let mut if_regular_file = false;
        let mut to: Option<String> = None;
        let mut redirect: Option<String> = None;
        let mut deny: Option<u16> = None;
        let mut status: Option<u16> = None;
        let mut keep_query = true;
        let mut if_not_file = false;
        let mut host = None;
        let mut method = None;
        let mut query = None;
        let mut header = None;
        for (prop, entry) in props {
            match prop {
                "to" => to = self.expect_string(entry, "to").map(str::to_owned),
                "redirect" => redirect = self.expect_string(entry, "redirect").map(str::to_owned),
                "deny" => {
                    deny = self
                        .expect_u32(entry, "deny")
                        .map(|v| u16::try_from(v).unwrap_or(0));
                }
                "status" => {
                    status = self
                        .expect_u32(entry, "status")
                        .map(|v| u16::try_from(v).unwrap_or(0));
                }
                "keep-query" => {
                    if let Some(flag) = self.expect_bool(entry, "keep-query") {
                        keep_query = flag;
                    }
                }
                "if-not-file" => {
                    if let Some(flag) = self.expect_bool(entry, "if-not-file") {
                        if_not_file = flag;
                    }
                }
                "if-not-regular-file" => {
                    if let Some(flag) = self.expect_bool(entry, "if-not-regular-file") {
                        if_not_regular_file = flag;
                    }
                }
                "if-file" => {
                    if let Some(flag) = self.expect_bool(entry, "if-file") {
                        if_file = flag;
                    }
                }
                "if-regular-file" => {
                    if let Some(flag) = self.expect_bool(entry, "if-regular-file") {
                        if_regular_file = flag;
                    }
                }
                "pass" => {
                    if let Some(flag) = self.expect_bool(entry, "pass") {
                        pass = flag;
                    }
                }
                "host" => {
                    host = self
                        .expect_string(entry, "host")
                        .map(str::to_ascii_lowercase);
                }
                "method" => method = self.expect_string(entry, "method").map(str::to_owned),
                "query" => query = self.expect_string(entry, "query").map(str::to_owned),
                "header" => {
                    if let Some(raw) = self.expect_string(entry, "header") {
                        let (name, value) = raw.split_once('=').unwrap_or((raw, ""));
                        header = Some((name.trim().to_ascii_lowercase(), value.to_owned()));
                    }
                }
                other => {
                    self.push_error(
                        "E003",
                        format!("unexpected property '{other}' on 'rule'"),
                        Some(entry.span()),
                        Some("allowed properties on 'rule' are: to, redirect, status, deny, pass, keep-query, if-not-file, if-not-regular-file, if-file, if-regular-file, host, method, query, header"),
                    );
                }
            }
        }
        self.expect_exact_arg_count(&args, 1, "rule", node.span())?;
        let entry = args.first().copied()?;
        let pattern = self.expect_string(entry, "rule")?.to_owned();
        if status.is_some() && redirect.is_none() {
            self.push_error(
                "E306",
                "'status' on a rewrite rule is only valid together with 'redirect'",
                Some(node.span()),
                Some("use deny=<status> to refuse, or redirect=\"...\" status=301 to redirect"),
            );
            return None;
        }
        let action = match (to, redirect, deny, pass) {
            (Some(to), None, None, false) => RewriteAction::Internal { to, keep_query },
            (None, Some(to), None, false) => RewriteAction::Redirect {
                to,
                status: status.unwrap_or(301),
                keep_query,
            },
            (None, None, Some(code), false) => RewriteAction::Deny(code),
            (None, None, None, true) => RewriteAction::Pass,
            _ => {
                self.push_error(
                    "E306",
                    "a rewrite rule needs exactly one of: to, redirect, deny, pass",
                    Some(node.span()),
                    Some(
                        "for example: to=\"/index.php?route=$1\", redirect=\"/new/$1\" or deny=403",
                    ),
                );
                return None;
            }
        };
        Some(RewriteRule {
            pattern,
            action,
            if_not_file,
            host,
            method,
            query,
            header,
            if_not_regular_file,
            if_file,
            if_regular_file,
            conditions,
        })
    }

    /// Parses the optional child block of a rewrite rule:
    /// `{ header "Name" "<regex>"; not-header ...; query "<regex>"; not-query; host; not-host }`.
    fn parse_rewrite_conditions(&mut self, node: &KdlNode) -> Vec<RewriteCondition> {
        let Some(children) = node.children() else {
            return Vec::new();
        };
        let mut conditions = Vec::new();
        for child in children.nodes() {
            let raw_name = child.name().value();
            let (negate, name) = raw_name
                .strip_prefix("not-")
                .map_or((false, raw_name), |rest| (true, rest));
            let (args, props) = self.split_entries(child);
            if !props.is_empty() || child.children().is_some() {
                // A property or nested block here would be dropped silently and the rule
                // would match more than it appears to.
                self.push_error(
                    "E306",
                    format!("rewrite condition '{raw_name}' takes no properties and no child block"),
                    Some(child.span()),
                    Some("conditions are: header \"Name\" \"<regex>\", query \"<regex>\", host \"<regex>\", client-ip \"<ip or cidr>\", each also with a not- prefix"),
                );
                continue;
            }
            let strings: Vec<String> = args
                .iter()
                .filter_map(|e| e.value().as_string().map(str::to_owned))
                .collect();
            let parsed = match (name, strings.as_slice()) {
                ("header", [header, pattern]) => Some((
                    RewriteConditionKind::Header(header.trim().to_ascii_lowercase()),
                    pattern.clone(),
                )),
                ("query", [pattern]) => Some((RewriteConditionKind::Query, pattern.clone())),
                ("host", [pattern]) => Some((RewriteConditionKind::Host, pattern.clone())),
                ("client-ip", [cidr]) => {
                    Some((RewriteConditionKind::ClientIp, cidr.trim().to_owned()))
                }
                _ => None,
            };
            match parsed {
                Some((kind, pattern)) if strings.len() == args.len() => {
                    conditions.push(RewriteCondition {
                        kind,
                        pattern,
                        negate,
                    });
                }
                _ => self.push_error(
                    "E306",
                    format!("invalid rewrite condition '{raw_name}'"),
                    Some(child.span()),
                    Some("conditions are: header \"Name\" \"<regex>\", query \"<regex>\", host \"<regex>\", client-ip \"<ip or cidr>\", each also with a not- prefix"),
                ),
            }
        }
        conditions
    }

    /// Parses `redirect "<target>" status=301`.
    fn parse_redirect(&mut self, node: &KdlNode) -> Option<RedirectConfig> {
        self.expect_no_children(node, "redirect");
        let (args, props) = self.split_entries(node);
        let mut status: u16 = 301;
        for (prop, entry) in props {
            if prop == "status" {
                if let Some(code) = self.expect_u32(entry, "status") {
                    status = u16::try_from(code).unwrap_or(0);
                }
            } else {
                self.push_error(
                    "E003",
                    format!("unexpected property '{prop}' on 'redirect'"),
                    Some(entry.span()),
                    Some("allowed properties on 'redirect' are: status"),
                );
            }
        }
        self.expect_exact_arg_count(&args, 1, "redirect", node.span())?;
        let entry = args.first().copied()?;
        let target = self.expect_string(entry, "redirect")?.to_owned();
        Some(RedirectConfig { target, status })
    }

    /// `workers "shared"`, `workers "auto"` or `workers <N>`.
    fn parse_workers(&mut self, node: &KdlNode) -> Option<Workers> {
        self.expect_no_children(node, "workers");
        let (args, props) = self.split_entries(node);
        for (prop, entry) in props {
            self.push_error(
                "E003",
                format!("unexpected property '{prop}' on 'workers'"),
                Some(entry.span()),
                None,
            );
        }
        self.expect_exact_arg_count(&args, 1, "workers", node.span())?;
        let entry = args.first().copied()?;
        if entry.value().as_integer().is_some() {
            let count = self.expect_u32(entry, "workers")?;
            if (1..=256).contains(&count) {
                return Some(Workers::Count(count));
            }
            self.push_error(
                "E007",
                "'workers' must be between 1 and 256".to_owned(),
                Some(entry.span()),
                Some("example: workers \"auto\" (one event loop per core)"),
            );
            return None;
        }
        match self.expect_string(entry, "workers")? {
            "shared" => Some(Workers::Shared),
            "auto" => Some(Workers::Auto),
            other => {
                self.push_error(
                    "E004",
                    format!("unknown value '{other}' for 'workers'"),
                    Some(entry.span()),
                    Some("allowed: \"shared\", \"auto\" or a number from 1 to 256"),
                );
                None
            }
        }
    }

    fn expect_single_string_node<'n>(&mut self, node: &'n KdlNode) -> Option<&'n str> {
        let directive = node.name().value();
        self.expect_no_children(node, directive);
        let (args, props) = self.split_entries(node);
        for (prop, entry) in props {
            self.push_error(
                "E003",
                format!("unexpected property '{prop}' on '{directive}'"),
                Some(entry.span()),
                None,
            );
        }
        self.expect_exact_arg_count(&args, 1, directive, node.span())?;
        let entry = args.first().copied()?;
        self.expect_string(entry, directive)
    }

    fn expect_single_bool_node(&mut self, node: &KdlNode) -> Option<bool> {
        let directive = node.name().value();
        self.expect_no_children(node, directive);
        let (args, props) = self.split_entries(node);
        for (prop, entry) in props {
            self.push_error(
                "E003",
                format!("unexpected property '{prop}' on '{directive}'"),
                Some(entry.span()),
                None,
            );
        }
        self.expect_exact_arg_count(&args, 1, directive, node.span())?;
        let entry = args.first().copied()?;
        self.expect_bool(entry, directive)
    }

    fn expect_single_u32_node(&mut self, node: &KdlNode) -> Option<u32> {
        let directive = node.name().value();
        self.expect_no_children(node, directive);
        let (args, props) = self.split_entries(node);
        for (prop, entry) in props {
            self.push_error(
                "E003",
                format!("unexpected property '{prop}' on '{directive}'"),
                Some(entry.span()),
                None,
            );
        }
        self.expect_exact_arg_count(&args, 1, directive, node.span())?;
        let entry = args.first().copied()?;
        self.expect_u32(entry, directive)
    }

    fn expect_single_u64_node(&mut self, node: &KdlNode) -> Option<u64> {
        let directive = node.name().value();
        self.expect_no_children(node, directive);
        let (args, props) = self.split_entries(node);
        for (prop, entry) in props {
            self.push_error(
                "E003",
                format!("unexpected property '{prop}' on '{directive}'"),
                Some(entry.span()),
                None,
            );
        }
        self.expect_exact_arg_count(&args, 1, directive, node.span())?;
        let entry = args.first().copied()?;
        self.expect_u64(entry, directive)
    }

    fn expect_single_duration_node(&mut self, node: &KdlNode) -> Option<Duration> {
        let directive = node.name().value();
        let raw = self.expect_single_string_node(node)?;
        match parse_duration(raw) {
            Ok(d) => Some(d),
            Err(err) => {
                self.push_error(
                    "E007",
                    format!("invalid duration for '{directive}': {err}"),
                    Some(node.span()),
                    Some("examples: \"500ms\", \"5s\", \"1m\""),
                );
                None
            }
        }
    }

    fn expect_single_byte_size_node(&mut self, node: &KdlNode) -> Option<ByteSize> {
        let directive = node.name().value();
        let raw = self.expect_single_string_node(node)?;
        match ByteSize::parse(raw) {
            Ok(sz) => Some(sz),
            Err(err) => {
                self.push_error(
                    "E007",
                    format!("invalid byte size for '{directive}': {err}"),
                    Some(node.span()),
                    Some("examples: \"16KiB\", \"10MB\", \"1GiB\""),
                );
                None
            }
        }
    }

    fn parse_string_list_node(&mut self, node: &KdlNode, directive: &str) -> Option<Vec<String>> {
        self.expect_no_children(node, directive);
        let (args, props) = self.split_entries(node);
        for (prop, entry) in props {
            self.push_error(
                "E003",
                format!("unexpected property '{prop}' on '{directive}'"),
                Some(entry.span()),
                None,
            );
        }
        if args.is_empty() {
            self.push_error(
                "E004",
                format!("'{directive}' requires at least one string argument"),
                Some(node.span()),
                None,
            );
            return None;
        }
        let mut out = Vec::with_capacity(args.len());
        for arg in args {
            if let Some(s) = self.expect_string(arg, directive) {
                out.push(s.to_owned());
            }
        }
        Some(out)
    }

    fn expect_string<'n>(&mut self, entry: &'n KdlEntry, label: &str) -> Option<&'n str> {
        if let Some(s) = entry.value().as_string() {
            Some(s)
        } else {
            self.push_error(
                "E004",
                format!(
                    "expected string value for '{label}', found {}",
                    value_kind_name(entry.value())
                ),
                Some(entry.span()),
                None,
            );
            None
        }
    }

    fn expect_bool(&mut self, entry: &KdlEntry, label: &str) -> Option<bool> {
        if let Some(b) = entry.value().as_bool() {
            Some(b)
        } else {
            self.push_error(
                "E004",
                format!(
                    "expected boolean value for '{label}', found {}",
                    value_kind_name(entry.value())
                ),
                Some(entry.span()),
                None,
            );
            None
        }
    }

    fn expect_u32(&mut self, entry: &KdlEntry, label: &str) -> Option<u32> {
        let Some(raw) = entry.value().as_integer() else {
            self.push_error(
                "E004",
                format!(
                    "expected integer value for '{label}', found {}",
                    value_kind_name(entry.value())
                ),
                Some(entry.span()),
                None,
            );
            return None;
        };
        if let Ok(v) = u32::try_from(raw) {
            Some(v)
        } else {
            self.push_error(
                "E007",
                format!(
                    "integer value '{raw}' for '{label}' is out of range (expected 0..={})",
                    u32::MAX
                ),
                Some(entry.span()),
                None,
            );
            None
        }
    }

    fn expect_u64(&mut self, entry: &KdlEntry, label: &str) -> Option<u64> {
        let Some(raw) = entry.value().as_integer() else {
            self.push_error(
                "E004",
                format!(
                    "expected integer value for '{label}', found {}",
                    value_kind_name(entry.value())
                ),
                Some(entry.span()),
                None,
            );
            return None;
        };
        if let Ok(v) = u64::try_from(raw) {
            Some(v)
        } else {
            self.push_error(
                "E007",
                format!(
                    "integer value '{raw}' for '{label}' is out of range (expected 0..={})",
                    u64::MAX
                ),
                Some(entry.span()),
                None,
            );
            None
        }
    }
}

fn value_kind_name(val: &KdlValue) -> &'static str {
    if val.is_string() {
        "string"
    } else if val.is_integer() {
        "integer"
    } else if val.is_float() {
        "float"
    } else if val.is_bool() {
        "boolean"
    } else if val.is_null() {
        "null"
    } else {
        "unknown"
    }
}

/// Validates an RFC 9110 HTTP header token name (tchar).
fn is_valid_http_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Maximum consecutive or unmatched stray `/-` tokens permitted before rejecting as hostile input.
const MAX_SLASH_DASH_CHAIN: usize = 32;

/// Linear-time, constant-stack pre-flight guard against oversized inputs and recursive
/// parser stack overflows from deeply nested `{ ... }` blocks, `/* ... */` comments,
/// KDL v1/v2 raw or multiline strings, non-LF line terminators, or hostile token chains.
///
/// Neutralizes valid outer `/* ... */` block-comment spans to byte-length-preserving ASCII
/// spaces (keeping `\n`/`\r` intact so all `SourceSpan` offsets match `source` 1:1), eliminating
/// `kdl::commented_block` recursion without rejecting legitimate comments containing >512 `*`/`/`
/// characters (`R2-CFG-1`).
#[allow(clippy::too_many_lines)]
fn preflight_input_safety(source: &str) -> Result<std::borrow::Cow<'_, str>, Box<ConfigIssue>> {
    if (source.len() as u64) > MAX_CONFIG_FILE_BYTES {
        return Err(Box::new(ConfigIssue::error(
            "E001",
            format!(
                "configuration input is {} bytes, exceeding maximum safety limit of {MAX_CONFIG_FILE_BYTES} bytes",
                source.len()
            ),
            source,
            None,
        )));
    }

    let bytes = source.as_bytes();
    let mut i = 0_usize;
    let mut brace_depth = 0_usize;
    let mut comment_depth = 0_usize;
    let mut outer_comment_start = 0_usize;
    let mut comment_spans: Vec<(usize, usize)> = Vec::new();
    let mut slash_dash_chain = 0_usize;

    while let Some(&b) = bytes.get(i) {
        let next = bytes.get(i.saturating_add(1)).copied();

        if comment_depth > 0 {
            if b == b'/' && next == Some(b'*') {
                comment_depth = comment_depth.saturating_add(1);
                if comment_depth > MAX_KDL_NESTING_DEPTH {
                    return Err(Box::new(depth_exceeded_issue(
                        source,
                        "block comment",
                        i,
                        2,
                    )));
                }
                i = i.saturating_add(2);
            } else if b == b'*' && next == Some(b'/') {
                comment_depth = comment_depth.saturating_sub(1);
                i = i.saturating_add(2);
                if comment_depth == 0 {
                    comment_spans.push((outer_comment_start, i));
                }
            } else {
                i = i.saturating_add(1);
            }
            continue;
        }

        // Line comment (`// ...` terminated by any KDL v1/v2 newline: LF, CR, VT, FF, NEL, LS, PS)
        if b == b'/' && next == Some(b'/') {
            i = i.saturating_add(2);
            while i < bytes.len() {
                if let Some(nl_len) = kdl_newline_len(bytes, i) {
                    i = i.saturating_add(nl_len);
                    break;
                }
                i = i.saturating_add(1);
            }
            continue;
        }

        // Slashdash (`/-`) chain depth guard
        if b == b'/' && next == Some(b'-') {
            slash_dash_chain = slash_dash_chain.saturating_add(1);
            if slash_dash_chain > MAX_SLASH_DASH_CHAIN {
                return Err(Box::new(depth_exceeded_issue(
                    source,
                    "slashdash comment",
                    i,
                    2,
                )));
            }
            i = i.saturating_add(2);
            continue;
        }

        // Block comment open (`/*`)
        if b == b'/' && next == Some(b'*') {
            comment_depth = 1;
            outer_comment_start = i;
            i = i.saturating_add(2);
            continue;
        }

        // KDL v2 raw strings (`#+"..."+#` or `#+"\"\"...\"\"\"+#`)
        if b == b'#' {
            match try_skip_raw_string(bytes, i, false) {
                RawStringScan::NotRaw => {}
                RawStringScan::Closed(next_i) => {
                    slash_dash_chain = 0;
                    i = next_i;
                    continue;
                }
                RawStringScan::Unterminated => {
                    return Err(Box::new(ConfigIssue::error(
                        "E001",
                        "unterminated raw string literal in configuration",
                        source,
                        Some(SourceSpan::new(i.into(), 1)),
                    )));
                }
            }
        }

        // KDL v1 raw strings (`r#*"..."#*`)
        if b == b'r' && matches!(next, Some(b'#' | b'"')) {
            match try_skip_raw_string(bytes, i.saturating_add(1), true) {
                RawStringScan::NotRaw => {}
                RawStringScan::Closed(next_i) => {
                    slash_dash_chain = 0;
                    i = next_i;
                    continue;
                }
                RawStringScan::Unterminated => {
                    return Err(Box::new(ConfigIssue::error(
                        "E001",
                        "unterminated raw string literal in configuration",
                        source,
                        Some(SourceSpan::new(i.into(), 1)),
                    )));
                }
            }
        }

        // KDL v2 multiline strings (`"""..."""`) or standard quoted strings (`"..."`)
        if b == b'"' {
            slash_dash_chain = 0;
            let is_multiline = bytes.get(i.saturating_add(1)) == Some(&b'"')
                && bytes.get(i.saturating_add(2)) == Some(&b'"');
            let Some(after) = skip_quoted_string(bytes, i, is_multiline) else {
                return Err(Box::new(ConfigIssue::error(
                    "E001",
                    "unterminated string literal in configuration",
                    source,
                    Some(SourceSpan::new(i.into(), 1)),
                )));
            };
            i = after;
            continue;
        }

        match b {
            b'{' => {
                slash_dash_chain = 0;
                brace_depth = brace_depth.saturating_add(1);
                if brace_depth > MAX_KDL_NESTING_DEPTH {
                    return Err(Box::new(depth_exceeded_issue(
                        source,
                        "configuration block",
                        i,
                        1,
                    )));
                }
            }
            b'}' => {
                slash_dash_chain = 0;
                if brace_depth == 0 {
                    return Err(Box::new(ConfigIssue::error(
                        "E001",
                        "unexpected unmatched closing brace '}' in configuration",
                        source,
                        Some(SourceSpan::new(i.into(), 1)),
                    )));
                }
                brace_depth = brace_depth.saturating_sub(1);
            }
            b' ' | b'\t' | b'\r' | b'\n' => {}
            _ => {
                slash_dash_chain = 0;
            }
        }
        i = i.saturating_add(1);
    }

    if comment_depth > 0 {
        return Err(Box::new(ConfigIssue::error(
            "E001",
            "unterminated block comment in configuration",
            source,
            None,
        )));
    }

    if comment_spans.is_empty() {
        return Ok(std::borrow::Cow::Borrowed(source));
    }

    let mut sanitized = bytes.to_vec();
    for (start, end) in comment_spans {
        if let Some(slice) = sanitized.get_mut(start..end) {
            for b in slice {
                if *b != b'\n' && *b != b'\r' {
                    *b = b' ';
                }
            }
        }
    }
    match String::from_utf8(sanitized) {
        Ok(s) => Ok(std::borrow::Cow::Owned(s)),
        Err(_) => Ok(std::borrow::Cow::Borrowed(source)),
    }
}

/// Returns the UTF-8 byte length of a KDL v1/v2 newline at `bytes[idx..]`, if present.
/// Covers `\n`, `\r`, `\x0b` (VT), `\x0c` (FF), U+0085 (NEL), U+2028 (LS), and U+2029 (PS).
fn kdl_newline_len(bytes: &[u8], idx: usize) -> Option<usize> {
    let b0 = *bytes.get(idx)?;
    if matches!(b0, b'\n' | b'\r' | 0x0B | 0x0C) {
        return Some(1);
    }
    // U+0085 (NEL): C2 85
    if b0 == 0xC2 && bytes.get(idx.saturating_add(1)) == Some(&0x85) {
        return Some(2);
    }
    // U+2028 (LS): E2 80 A8, U+2029 (PS): E2 80 A9
    if b0 == 0xE2
        && bytes.get(idx.saturating_add(1)) == Some(&0x80)
        && matches!(bytes.get(idx.saturating_add(2)), Some(0xA8 | 0xA9))
    {
        return Some(3);
    }
    None
}

enum RawStringScan {
    NotRaw,
    Unterminated,
    Closed(usize),
}

/// Attempts to skip a KDL v2 (`#+"..."+#` / `#+"\"\"...\"\"\"+#`) or v1 (`r#*"..."#*`) raw string.
fn try_skip_raw_string(bytes: &[u8], start: usize, allow_zero_hashes: bool) -> RawStringScan {
    let mut hashes = 0_usize;
    let mut pos = start;
    while bytes.get(pos) == Some(&b'#') {
        hashes = hashes.saturating_add(1);
        pos = pos.saturating_add(1);
    }
    if (!allow_zero_hashes && hashes == 0) || bytes.get(pos) != Some(&b'"') {
        return RawStringScan::NotRaw;
    }

    let is_multiline = bytes.get(pos.saturating_add(1)) == Some(&b'"')
        && bytes.get(pos.saturating_add(2)) == Some(&b'"');
    let quote_count = if is_multiline { 3_usize } else { 1_usize };
    pos = pos.saturating_add(quote_count);

    while pos < bytes.len() {
        if bytes.get(pos) == Some(&b'"') {
            let mut q = 0_usize;
            while q < quote_count && bytes.get(pos.saturating_add(q)) == Some(&b'"') {
                q = q.saturating_add(1);
            }
            if q == quote_count {
                let hash_start = pos.saturating_add(quote_count);
                let mut h = 0_usize;
                while h < hashes && bytes.get(hash_start.saturating_add(h)) == Some(&b'#') {
                    h = h.saturating_add(1);
                }
                if h == hashes {
                    return RawStringScan::Closed(hash_start.saturating_add(hashes));
                }
            }
        }
        pos = pos.saturating_add(1);
    }
    RawStringScan::Unterminated
}

/// Skips a standard `"..."` or multiline `"""..."""` quoted string honoring backslash escapes.
fn skip_quoted_string(bytes: &[u8], start: usize, is_multiline: bool) -> Option<usize> {
    let mut pos = start.saturating_add(if is_multiline { 3 } else { 1 });
    let mut escaped = false;
    while let Some(&b) = bytes.get(pos) {
        if escaped {
            escaped = false;
            pos = pos.saturating_add(1);
            continue;
        }
        if b == b'\\' {
            escaped = true;
            pos = pos.saturating_add(1);
            continue;
        }
        if b == b'"' {
            if is_multiline {
                if bytes.get(pos.saturating_add(1)) == Some(&b'"')
                    && bytes.get(pos.saturating_add(2)) == Some(&b'"')
                {
                    return Some(pos.saturating_add(3));
                }
            } else {
                return Some(pos.saturating_add(1));
            }
        }
        pos = pos.saturating_add(1);
    }
    None
}

fn depth_exceeded_issue(source: &str, kind: &str, offset: usize, len: usize) -> ConfigIssue {
    ConfigIssue::error(
        "E001",
        format!("{kind} nesting exceeds maximum safety depth of {MAX_KDL_NESTING_DEPTH}"),
        source,
        Some(SourceSpan::new(offset.into(), len)),
    )
    .with_help("valid MiraServe configurations require at most 5 levels of nesting")
}

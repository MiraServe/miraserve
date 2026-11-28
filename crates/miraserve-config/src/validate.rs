//! Semantic and security validation enforcing MiraServe's Threat Model (`docs/THREAT_MODEL.md`).

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use miette::SourceSpan;
use url::Url;

use crate::error::ConfigIssue;
use crate::parser::SpanMap;
use crate::schema::{
    AcmeChallenge, AiPublishConfig, AuditLogMode, Config, DotfilesPolicy, ErrorPagesConfig,
    FastCgiTarget, KeyIsolation, McpGatewayConfig, PreflightCheck, PublishAuthMode,
    RateLimitConfig, ReverseProxyConfig, RouteHandler, SeccompMode, SecurityHeadersPolicy,
    ServerConfig, SiteConfig, SiteHttpMode, TelemetryConfig, TlsVersion, WasmPluginConfig,
};
use crate::units::{ByteSize, Protocol};

/// Outcome of semantic and security validation.
pub(crate) struct ValidationOutput {
    pub(crate) errors: Vec<ConfigIssue>,
    pub(crate) warnings: Vec<ConfigIssue>,
}

/// Validates a parsed [`Config`] against semantic and security invariants.
#[allow(clippy::too_many_lines)]
pub(crate) fn validate_config(
    config: &Config,
    source: &str,
    spans: &SpanMap,
    mut errors: Vec<ConfigIssue>,
    config_base_dir: Option<&std::path::Path>,
) -> ValidationOutput {
    let mut ctx = ValidatorCtx {
        source,
        spans,
        allow_docroots: &config.server.allow_docroots,
        errors: Vec::new(),
        warnings: Vec::new(),
    };

    ctx.validate_server(&config.server);
    ctx.validate_acme_webroot_credentials(config);
    ctx.validate_sites(&config.sites, config.server.tls.client_ca.is_some());

    // R7-CFG-1: Refuse any site/route document root that equals or is an ancestor of the
    // configuration file's directory so `root "."` (or an ancestor) can never serve the `.kdl`
    // config file itself or neighbouring secrets over HTTP!
    if let Some(cfg_dir) = config_base_dir {
        for (site_idx, site) in config.sites.iter().enumerate() {
            if let Some(root) = &site.root
                && root == root.trim()
                && docroot_contains_config_dir(root, cfg_dir)
            {
                let key = format!("site[{site_idx}].root");
                ctx.error(
                    "E202",
                    format!(
                        "site.root '{root}' contains the configuration directory '{}' and would expose the config file over HTTP (R7-CFG-1)",
                        cfg_dir.display()
                    ),
                    &key,
                    Some(
                        "place public web assets in a dedicated subdirectory (e.g. `root \"www\"`) separate from the `.kdl` config file",
                    ),
                );
            }
            for (route_idx, route) in site.routes.iter().enumerate() {
                if let Some(root) = &route.root
                    && root == root.trim()
                    && docroot_contains_config_dir(root, cfg_dir)
                {
                    let key = format!("site[{site_idx}].route[{route_idx}].root");
                    ctx.error(
                        "E202",
                        format!(
                            "route.root '{root}' contains the configuration directory '{}' and would expose the config file over HTTP (R7-CFG-1)",
                            cfg_dir.display()
                        ),
                        &key,
                        Some(
                            "place public web assets in a dedicated subdirectory separate from the `.kdl` config file",
                        ),
                    );
                }
            }
        }
    }

    // R2-ACME-3: `acme` with `key-isolation "split-daemon"` disables worker ACME issuance so keys
    // never enter worker memory. Fail closed unless manual cert/key pairs cover all sites.
    if config.server.tls.acme.is_some()
        && config.server.tls.key_isolation == KeyIsolation::SplitDaemon
    {
        let has_global_manual = config.server.tls.cert.is_some() && config.server.tls.key.is_some();
        let any_site_needs_acme = !has_global_manual
            && config.sites.iter().any(|s| {
                s.tls
                    .as_ref()
                    .is_none_or(|t| t.cert.is_none() || t.key.is_none())
            });
        if any_site_needs_acme || config.sites.is_empty() && !has_global_manual {
            ctx.error(
                "E106",
                "server.tls.acme cannot issue certificates when key-isolation is \"split-daemon\"",
                "server.tls.acme",
                Some(
                    "use key-isolation \"in-process\" for built-in ACME, or supply manual cert/key pairs to miraserve-keyd and remove the acme block",
                ),
            );
        }
    }

    // R3-PKG-1: Warn clearly when HTTPS listeners are configured with no certificates, no ACME,
    // and no split-daemon keyd, because `miraserve run` (without `--dev-tls`) will exit with
    // "no TLS certificates available".
    let has_https_listener = config.server.listeners.iter().any(|l| !l.redirect_https);
    let has_any_cert = (config.server.tls.cert.is_some() && config.server.tls.key.is_some())
        || config.sites.iter().any(|s| {
            s.tls
                .as_ref()
                .is_some_and(|t| t.cert.is_some() && t.key.is_some())
        });
    if has_https_listener
        && !has_any_cert
        && config.server.tls.acme.is_none()
        && config.server.tls.key_isolation != KeyIsolation::SplitDaemon
    {
        ctx.warn(
            "W015",
            "no TLS certificate, ACME block, or split-daemon keyd is configured; `miraserve run` will fail unless started with `--dev-tls`",
            "server.tls",
            Some(
                "configure `cert`/`key`, add a `server.tls.acme` block, generate a starter cert with `miraserve cert generate-dev`, or start with `--dev-tls`",
            ),
        );
    }

    let has_redirect_listener = config.server.listeners.iter().any(|l| l.redirect_https);
    if !has_redirect_listener {
        for (site_idx, site) in config.sites.iter().enumerate() {
            if site.http == SiteHttpMode::Serve {
                let host = site.hosts.first().map_or("<site>", String::as_str);
                ctx.warn(
                    "W031",
                    format!(
                        "site '{host}' sets `http \"serve\"`, but no listener has `redirect-https=#true`; the setting has no effect"
                    ),
                    &format!("site[{site_idx}].http"),
                    Some(
                        "add a plain-HTTP listener (e.g. `listen \":80\" redirect-https=#true`) or remove `http \"serve\"`",
                    ),
                );
            }
        }
    }

    // R6-DOS-1: Warn when binding an internal/private IP (or loopback with a non-local
    // production hostname) without `trusted-proxies` and default/low `max-connections-per-ip`,
    // because a front proxy/load balancer will hit the per-IP connection cap and return 502s.
    if config.server.limits.trusted_proxies.is_empty()
        && config.server.limits.max_connections_per_ip <= 256
    {
        let has_private_listener = config
            .server
            .listeners
            .iter()
            .any(|l| l.addr.host.is_some_and(is_private_non_loopback_ip));
        let has_loopback_listener = config
            .server
            .listeners
            .iter()
            .any(|l| l.addr.host.is_some_and(|ip| ip.is_loopback()));
        // R6-DOS-1: Also warn on wildcard listeners bound to non-standard high ports (e.g. `:8443`
        // or `0.0.0.0:8080`, typical container/LB backend binds) serving production hostnames!
        // A server that also listens on 443 or 80 is directly exposed; an extra port next to
        // them (a panel, a tool) is not a sign of sitting behind a load balancer.
        let is_wildcard =
            |l: &crate::schema::ListenConfig| l.addr.host.is_none_or(|ip| ip.is_unspecified());
        let has_standard_public_port = config
            .server
            .listeners
            .iter()
            .any(|l| is_wildcard(l) && (l.addr.port == 443 || l.addr.port == 80));
        let has_wildcard_nonstandard_port = !has_standard_public_port
            && config.server.listeners.iter().any(|l| {
                is_wildcard(l) && !l.redirect_https && l.addr.port != 443 && l.addr.port != 80
            });
        let has_non_dev_site_host = config.sites.iter().any(|s| {
            s.hosts.iter().any(|h| {
                let low = h.to_ascii_lowercase();
                let tld = low.rsplit('.').next().unwrap_or("");
                low != "localhost"
                    && !matches!(tld, "localhost" | "test" | "invalid" | "local")
                    && low
                        .trim_start_matches('[')
                        .trim_end_matches(']')
                        .parse::<std::net::IpAddr>()
                        .is_err()
            })
        });
        if has_private_listener
            || ((has_loopback_listener || has_wildcard_nonstandard_port) && has_non_dev_site_host)
        {
            ctx.warn(
                "W021",
                format!(
                    "listener binds a private/loopback or non-standard backend port without `server.limits.trusted-proxies` while `max-connections-per-ip` is {}; a front reverse proxy or load balancer will hit this cap and return 502s",
                    config.server.limits.max_connections_per_ip
                ),
                "server.limits",
                Some(
                    "add your exact front proxy IP(s) to `server.limits.trusted-proxies` (e.g. `trusted-proxies \"127.0.0.1/32\" \"10.0.1.10/32\"`) or raise `max-connections-per-ip`",
                ),
            );
        }
    }

    // R6-SBX-1: Refuse any `site.root` or `route.root` that equals, lies inside, or is an
    // ancestor of ANY configured `ai-publish.storage` directory (which contains `audit.log`,
    // `replay-cache.json`, `legacy-v2-allowlist.json`, and staged bundles).
    // Each store as written and as resolved: roots are compared as written, so a root must not
    // slip past a store whose resolved form differs only by platform spelling (a drive prefix).
    let publish_stores: Vec<(String, String)> = config
        .sites
        .iter()
        .filter_map(|s| s.ai_publish.as_ref())
        .filter(|p| p.storage == p.storage.trim())
        .flat_map(|p| {
            [
                (p.storage.clone(), lexical_path_key(&p.storage)),
                (p.storage.clone(), normalize_storage_path_key(&p.storage)),
            ]
        })
        .collect();
    if !publish_stores.is_empty() {
        for (site_idx, site) in config.sites.iter().enumerate() {
            let prefix = format!("sites.{site_idx}");
            if let Some(root) = &site.root
                && root == root.trim()
            {
                let root_key = lexical_path_key(root);
                if let Some((store_raw, _)) = publish_stores
                    .iter()
                    .find(|(_, store_key)| storage_paths_overlap(&root_key, store_key))
                {
                    {
                        ctx.error(
                            "E202",
                            format!(
                                "site root '{root}' overlaps ai-publish.storage '{store_raw}' and would expose publish metadata/releases"
                            ),
                            &format!("{prefix}.root"),
                            Some("keep static document roots completely disjoint from `ai-publish.storage` directories"),
                        );
                    }
                }
            }
            for (r_idx, route) in site.routes.iter().enumerate() {
                if let Some(r_root) = &route.root
                    && r_root == r_root.trim()
                {
                    let root_key = lexical_path_key(r_root);
                    if let Some((store_raw, _)) = publish_stores
                        .iter()
                        .find(|(_, store_key)| storage_paths_overlap(&root_key, store_key))
                    {
                        {
                            ctx.error(
                                "E202",
                                format!(
                                    "route root '{r_root}' overlaps ai-publish.storage '{store_raw}' and would expose publish metadata/releases"
                                ),
                                &format!("{prefix}.routes.{r_idx}.root"),
                                Some("keep static document roots completely disjoint from `ai-publish.storage` directories"),
                            );
                        }
                    }
                }
            }
        }
    }

    errors.extend(ctx.errors);
    ValidationOutput {
        errors,
        warnings: ctx.warnings,
    }
}

struct ValidatorCtx<'a> {
    source: &'a str,
    spans: &'a SpanMap,
    allow_docroots: &'a [String],
    errors: Vec<ConfigIssue>,
    warnings: Vec<ConfigIssue>,
}

impl ValidatorCtx<'_> {
    fn span(&self, key: &str) -> Option<SourceSpan> {
        self.spans.get(key).copied()
    }

    fn error(&mut self, code: &str, msg: impl Into<String>, key: &str, help: Option<&str>) {
        let mut issue = ConfigIssue::error(code, msg, self.source, self.span(key)).with_path(key);
        if let Some(h) = help {
            issue = issue.with_help(h);
        }
        self.errors.push(issue);
    }

    fn warn(&mut self, code: &str, msg: impl Into<String>, key: &str, help: Option<&str>) {
        let mut issue = ConfigIssue::warning(code, msg, self.source, self.span(key)).with_path(key);
        if let Some(h) = help {
            issue = issue.with_help(h);
        }
        self.warnings.push(issue);
    }

    fn validate_server(&mut self, server: &ServerConfig) {
        self.validate_listeners(server);
        self.validate_server_tls(server);
        self.validate_sandbox(server);
        self.validate_timeouts_and_limits(server);
        self.validate_telemetry(&server.telemetry, &server.listeners);
        self.validate_allow_docroots(&server.allow_docroots);
        if let Some(webroot) = &server.acme_webroot {
            self.validate_acme_webroot(webroot);
        }
    }

    /// No configured credential (users file, private key) may sit inside `acme-webroot`: its
    /// challenge files are answered before any site check.
    fn validate_acme_webroot_credentials(&mut self, config: &Config) {
        let Some(webroot) = config.server.acme_webroot.as_deref() else {
            return;
        };
        if webroot != webroot.trim() {
            return;
        }
        // Only the challenge directory is ever answered: credentials elsewhere under the
        // webroot are not reachable through it.
        let root_key = lexical_path_key(&format!(
            "{}/.well-known/acme-challenge",
            webroot.trim_end_matches('/')
        ));
        let root = root_key.trim_end_matches('/');
        if root.is_empty() {
            return;
        }
        // Exactly what the responder could answer: a file directly in the challenge directory
        // whose name is a token (base64url). Anything deeper, or another name, is unreachable.
        let inside = |path: &str| {
            let key = lexical_path_key(path);
            key.strip_prefix(root)
                .and_then(|rest| rest.strip_prefix('/'))
                .is_some_and(|name| {
                    !name.is_empty()
                        && name
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                })
        };
        let mut credentials: Vec<(String, &str)> = Vec::new();
        if let Some(key) = config.server.tls.key.as_deref() {
            credentials.push(("server.tls.key".to_owned(), key));
        }
        for (i, site) in config.sites.iter().enumerate() {
            if let Some(key) = site.tls.as_ref().and_then(|tls| tls.key.as_deref()) {
                credentials.push((format!("site[{i}].tls.key"), key));
            }
            if let Some(auth) = &site.basic_auth {
                credentials.push((format!("site[{i}].basic-auth"), auth.users_file.as_str()));
            }
            for (j, route) in site.routes.iter().enumerate() {
                if let Some(auth) = &route.basic_auth {
                    credentials.push((
                        format!("site[{i}].route[{j}].basic-auth"),
                        auth.users_file.as_str(),
                    ));
                }
                if let crate::RouteHandler::ReverseProxy(rp) = &route.handler
                    && let Some(key) = rp
                        .upstream_tls
                        .as_ref()
                        .and_then(|t| t.client_key.as_deref())
                {
                    credentials.push((format!("site[{i}].route[{j}].upstream-tls"), key));
                }
            }
        }
        for (key_path, file) in credentials {
            if file == file.trim() && inside(file) {
                self.error(
                    "E202",
                    format!(
                        "credential file '{file}' is inside the challenge directory of \
                         server.acme-webroot '{webroot}', whose files are served before any site \
                         check; keep credentials elsewhere"
                    ),
                    &key_path,
                    None,
                );
            }
        }
    }

    /// `acme-webroot`: an absolute, ordinary directory path (never `/` or a forbidden tree).
    fn validate_acme_webroot(&mut self, raw: &str) {
        let key = "server.acme-webroot";
        if raw != raw.trim() {
            return;
        }
        self.validate_safe_file_path(raw, key, "server.acme-webroot");
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.contains('\0') || has_parent_traversal(trimmed) {
            return;
        }
        if !is_absolute_config_path(trimmed) || trimmed.trim_end_matches('/').is_empty() {
            self.error(
                "E202",
                format!(
                    "server.acme-webroot '{raw}' must be an absolute directory path other than '/'"
                ),
                key,
                Some("example: acme-webroot \"/var/lib/acme-webroot\""),
            );
            return;
        }
        if matches!(
            classify_dir_path(trimmed, true, &[]),
            DirPathVerdict::UnconditionallyForbidden
        ) {
            self.error(
                "E202",
                format!(
                    "server.acme-webroot '{raw}' points to a forbidden OS or MiraServe directory"
                ),
                key,
                None,
            );
        }
    }

    fn validate_allow_docroots(&mut self, allow_docroots: &[String]) {
        for (i, raw) in allow_docroots.iter().enumerate() {
            if raw != raw.trim() {
                continue;
            }
            let key = format!("server.allow-docroot[{i}]");
            self.validate_safe_file_path(raw, &key, "server.allow-docroot");
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.contains('\0') || has_parent_traversal(trimmed) {
                continue;
            }
            if !is_absolute_config_path(trimmed) {
                self.error(
                    "E202",
                    format!("server.allow-docroot '{raw}' must be an absolute path"),
                    &key,
                    Some("example: allow-docroot \"/var/lib/my-app/public\""),
                );
                continue;
            }
            if matches!(
                classify_dir_path(trimmed, true, &[]),
                DirPathVerdict::UnconditionallyForbidden
            ) {
                self.error(
                    "E202",
                    format!(
                        "server.allow-docroot '{raw}' points to an unconditionally forbidden OS or MiraServe directory and cannot be exempted"
                    ),
                    &key,
                    Some(
                        "allow-docroot may only open specific subdirectories under default-denied trees (e.g. '/var/lib/my-app/public'), never '/', top-level directories, '/etc', '/var/lib', or MiraServe's own state paths",
                    ),
                );
            }
        }
    }

    fn validate_listeners(&mut self, server: &ServerConfig) {
        if server.listeners.is_empty() {
            self.error(
                "E006",
                "'server' block must define at least one 'listen' directive",
                "server",
                Some("example: listen \":443\" protocols=\"h3,h2,h1\""),
            );
        }

        for (i, listen) in server.listeners.iter().enumerate() {
            let key = format!("server.listen[{i}]");
            if listen.redirect_https && listen.protocols.contains(&Protocol::H3) {
                self.error(
                    "E103",
                    format!(
                        "listener '{}' enables 'redirect-https=true' and cannot serve HTTP/3 (QUIC requires TLS)",
                        listen.addr
                    ),
                    &key,
                    Some("remove 'h3' from protocols on plaintext HTTP redirect listeners"),
                );
            }

            for (j, prev) in server.listeners.iter().take(i).enumerate() {
                if listen.addr.conflicts_with(&prev.addr) {
                    self.error(
                        "E102",
                        format!(
                            "listener '{}' conflicts with earlier listener '{}' (index {j})",
                            listen.addr, prev.addr
                        ),
                        &key,
                        Some("bind each listener to a distinct port or non-overlapping IP address"),
                    );
                }
            }
        }

        if !server.listeners.is_empty() && server.listeners.iter().all(|l| l.redirect_https) {
            self.warn(
                "W011",
                "all configured listeners have 'redirect-https=true'; no HTTPS listener is defined",
                "server",
                Some("add an HTTPS listener such as: listen \":443\" protocols=\"h3,h2,h1\""),
            );
        }
    }

    #[allow(clippy::too_many_lines)]
    fn validate_server_tls(&mut self, server: &ServerConfig) {
        let tls = &server.tls;
        if tls.min_version == TlsVersion::V1_2 {
            self.warn(
                "W002",
                "global TLS min-version is downgraded to 1.2",
                "server.tls.min-version",
                Some("keep global min-version \"1.3\" and opt in per legacy site via 'tls { compat-tls-1-2 true }'"),
            );
        }
        if !tls.pqc_hybrid {
            self.warn(
                "W001",
                "post-quantum hybrid key exchange (X25519MLKEM768) is disabled globally",
                "server.tls.pqc-hybrid",
                Some("set 'pqc-hybrid true' to defend against harvest-now-decrypt-later attacks (Threat Model T3)"),
            );
        }

        self.validate_cert_key_pair(
            tls.cert.as_deref(),
            tls.key.as_deref(),
            "server.tls.cert",
            "server.tls.key",
            "server.tls",
        );

        if let Some(ca) = &tls.client_ca {
            self.validate_safe_file_path(ca, "server.tls.client-ca", "mTLS client CA bundle");
        }

        if tls.key_isolation == KeyIsolation::SplitDaemon && tls.keyd_socket.is_none() {
            self.error(
                "E105",
                "key-isolation \"split-daemon\" requires 'keyd-socket' to be configured",
                "server.tls.key-isolation",
                Some("set 'keyd-socket \"/run/miraserve/keyd.sock\"' or 'keyd-socket \"tcp://127.0.0.1:9444\"'"),
            );
        }

        if let Some(sock) = &tls.keyd_socket {
            if tls.key_isolation != KeyIsolation::SplitDaemon {
                self.error(
                    "E105",
                    "'keyd-socket' is configured but 'key-isolation' is not set to \"split-daemon\"",
                    "server.tls.keyd-socket",
                    Some("set 'key-isolation \"split-daemon\"' or remove 'keyd-socket'"),
                );
            }
            if crate::parser::keyd_socket_whitespace_reason(sock).is_some() {
                // Already rejected with E202 at parse time.
            } else if let Some(tcp_target) = sock.strip_prefix("tcp://") {
                match std::net::SocketAddr::from_str(tcp_target) {
                    Ok(addr) if addr.ip().is_loopback() && addr.port() > 0 => {}
                    Ok(_) => {
                        self.error(
                            "E105",
                            format!("'keyd-socket' TCP endpoint '{sock}' must bind strictly to loopback (127.0.0.1 or [::1])"),
                            "server.tls.keyd-socket",
                            Some("never expose the TLS signing daemon over non-loopback networks (Threat Model T2)"),
                        );
                    }
                    Err(_) => {
                        self.error(
                            "E105",
                            format!("invalid 'keyd-socket' TCP address '{sock}'"),
                            "server.tls.keyd-socket",
                            Some(
                                "example: \"tcp://127.0.0.1:9444\" or \"/run/miraserve/keyd.sock\"",
                            ),
                        );
                    }
                }
            } else {
                self.validate_safe_file_path(sock, "server.tls.keyd-socket", "keyd-socket");
            }
        }

        // ECH-1 & R2-ACME-5: Reject `tls.ech true`, `ech-public-name`, and explicit `ech-rotate`
        // fail-closed until rustls ships server-side ECH decryption so operators never configure
        // dead ECH settings or publish undecryptable RFC 9849 DNS HTTPS records.
        if tls.ech {
            self.error(
                "E107",
                "TLS 'ech true' is not yet supported for server termination (rustls 0.23 lacks server-side ECH decryption)",
                "server.tls.ech",
                Some("set 'ech false' (or omit it); ECH server decryption is not yet active at runtime"),
            );
        }

        if let Some(pub_name) = &tls.ech_public_name {
            if pub_name.is_empty()
                || pub_name.chars().any(char::is_whitespace)
                || pub_name.contains('/')
                || pub_name.contains('*')
            {
                self.error(
                    "E107",
                    format!("invalid ECH public name '{pub_name}'"),
                    "server.tls.ech-public-name",
                    Some("remove 'ech-public-name'; ECH server decryption is not yet active at runtime"),
                );
            } else {
                self.error(
                    "E107",
                    "TLS 'ech-public-name' is not yet supported because ECH server termination is inactive",
                    "server.tls.ech-public-name",
                    Some("remove 'ech-public-name' until server-side ECH decryption is implemented"),
                );
            }
        }
        if tls.ech_rotate_interval.is_zero() {
            self.error(
                "E107",
                "TLS 'ech-rotate' interval must be greater than zero",
                "server.tls.ech-rotate",
                Some("remove 'ech-rotate'; ECH server decryption is not yet active at runtime"),
            );
        } else if self.spans.contains_key("server.tls.ech-rotate") {
            self.error(
                "E107",
                "TLS 'ech-rotate' is not yet supported because ECH server termination is inactive",
                "server.tls.ech-rotate",
                Some("remove 'ech-rotate' until server-side ECH decryption is implemented"),
            );
        }

        if let Some(acme) = &tls.acme {
            if !is_valid_email(&acme.email) {
                self.error(
                    "E106",
                    format!("invalid ACME contact email '{}'", acme.email),
                    "server.tls.acme.email",
                    Some("provide a valid contact email such as \"ops@example.com\""),
                );
            }
            // ACME-1: Reject dns-01 fail-closed because no DNS provider API is bundled.
            if acme.challenge == AcmeChallenge::Dns01 {
                self.error(
                    "E106",
                    "ACME challenge \"dns-01\" is not yet supported (no DNS provider integration)",
                    "server.tls.acme",
                    Some("use challenge \"tls-alpn-01\" (RFC 8737) or \"http-01\" (RFC 8555)"),
                );
            }
            if let Some(dir_url) = &acme.directory {
                match Url::parse(dir_url) {
                    Ok(parsed) if parsed.scheme() == "https" && parsed.has_host() => {}
                    _ => {
                        self.error(
                            "E106",
                            format!("ACME directory URL '{dir_url}' must be a valid https:// URL"),
                            "server.tls.acme.directory",
                            None,
                        );
                    }
                }
            }
        }
    }

    fn validate_sandbox(&mut self, server: &ServerConfig) {
        let sb = &server.sandbox;
        if let Some(user) = &sb.user {
            let trimmed = user.trim();
            if trimmed.is_empty()
                || trimmed.eq_ignore_ascii_case("root")
                || trimmed.parse::<u32>().ok() == Some(0)
            {
                self.error(
                    "E201",
                    format!(
                        "forbidden sandbox user '{user}': worker processes must not run as root"
                    ),
                    "server.sandbox.user",
                    Some("configure a dedicated unprivileged user such as \"miraserve\""),
                );
            } else if !is_valid_os_identity(trimmed) {
                self.error(
                    "E201",
                    format!("invalid sandbox user identifier '{user}'"),
                    "server.sandbox.user",
                    None,
                );
            }
        }
        if let Some(group) = &sb.group {
            let trimmed = group.trim();
            if trimmed.is_empty()
                || trimmed.eq_ignore_ascii_case("root")
                || trimmed.parse::<u32>().ok() == Some(0)
            {
                self.error(
                    "E201",
                    format!("forbidden sandbox group '{group}': worker processes must not run as root group"),
                    "server.sandbox.group",
                    Some("configure a dedicated unprivileged group such as \"miraserve\""),
                );
            } else if !is_valid_os_identity(trimmed) {
                self.error(
                    "E201",
                    format!("invalid sandbox group identifier '{group}'"),
                    "server.sandbox.group",
                    None,
                );
            }
        }
        for (directive, trees) in [
            ("read-tree", &sb.read_trees),
            ("socket-tree", &sb.socket_trees),
        ] {
            for tree in trees {
                if let Some(reason) = sandbox_tree_rejection(tree) {
                    self.error(
                        "E202",
                        format!("sandbox '{directive}' path '{tree}' is not allowed: {reason}"),
                        &format!("server.sandbox.{directive}"),
                        Some("list a directory that holds only site document roots (for example \"/home\" or \"/var/www\") or only application sockets (for example \"/run/php\")"),
                    );
                }
            }
        }
        if !sb.landlock {
            self.warn(
                "W003",
                "Linux Landlock LSM filesystem confinement is disabled",
                "server.sandbox.landlock",
                Some("set 'landlock true' for defense-in-depth worker isolation"),
            );
        }
        if sb.seccomp == SeccompMode::Off {
            self.warn(
                "W003",
                "Linux seccomp-bpf syscall filtering is disabled (including MiraServe's in-process set-ID protection)",
                "server.sandbox.seccomp",
                Some("set 'seccomp \"strict\"' or \"standard\" in production; never pair 'seccomp \"off\"' with a systemd unit that omits RestrictSUIDSGID=yes"),
            );
        }
    }

    #[allow(clippy::too_many_lines)]
    fn validate_timeouts_and_limits(&mut self, server: &ServerConfig) {
        let t = &server.timeouts;
        self.validate_positive_duration(
            t.tls_handshake,
            "server.timeouts.tls-handshake",
            "tls-handshake",
        );
        if t.tls_handshake > Duration::from_secs(120) {
            self.error(
                "E007",
                "'tls-handshake' timeout must not exceed 120s",
                "server.timeouts.tls-handshake",
                None,
            );
        }
        self.validate_positive_duration(
            t.header_read,
            "server.timeouts.header-read",
            "header-read",
        );
        if t.header_read > Duration::from_secs(300) {
            self.error(
                "E007",
                "'header-read' timeout must not exceed 300s",
                "server.timeouts.header-read",
                None,
            );
        }
        self.validate_positive_duration(
            t.idle_keepalive,
            "server.timeouts.idle-keepalive",
            "idle-keepalive",
        );
        if t.idle_keepalive > Duration::from_secs(3_600) {
            self.error(
                "E007",
                "'idle-keepalive' timeout must not exceed 3600s",
                "server.timeouts.idle-keepalive",
                None,
            );
        }
        self.validate_positive_duration(
            t.graceful_drain,
            "server.timeouts.graceful-drain",
            "graceful-drain",
        );
        if t.graceful_drain > Duration::from_secs(600) {
            self.error(
                "E007",
                "'graceful-drain' timeout must not exceed 600s",
                "server.timeouts.graceful-drain",
                None,
            );
        }
        self.validate_positive_duration(
            t.body_idle_timeout,
            "server.timeouts.body-idle-timeout",
            "body-idle-timeout",
        );
        if t.body_idle_timeout > Duration::from_secs(600) {
            self.error(
                "E007",
                "'body-idle-timeout' timeout must not exceed 600s",
                "server.timeouts.body-idle-timeout",
                None,
            );
        }
        self.validate_positive_duration(
            t.max_body_duration,
            "server.timeouts.max-body-duration",
            "max-body-duration",
        );
        if t.max_body_duration > Duration::from_hours(24) {
            self.error(
                "E007",
                "'max-body-duration' timeout must not exceed 86400s (24h)",
                "server.timeouts.max-body-duration",
                None,
            );
        }
        // R3-HTTP-1, R4-HTTP-1, R5-HTTP-2: Allow `min-body-rate-bps 0` as an explicit opt-out for
        // mobile/high-latency uploads while keeping `body-idle-timeout` and `max-body-duration` active.
        if t.min_body_rate_bps == 0 {
            self.warn(
                "W016",
                "'min-body-rate-bps 0' disables Slowloris minimum request body transfer-rate enforcement (body-idle-timeout and max-body-duration remain active)",
                "server.timeouts.min-body-rate-bps",
                Some("set a positive rate such as 1024 (or tune 'body-idle-timeout' / 'max-body-duration') on public-facing listeners"),
            );
        }
        self.validate_positive_duration(
            t.upstream_connect,
            "server.timeouts.upstream-connect-timeout",
            "upstream-connect-timeout",
        );
        if t.upstream_connect > Duration::from_secs(120) {
            self.error(
                "E007",
                "'upstream-connect-timeout' must not exceed 120s",
                "server.timeouts.upstream-connect-timeout",
                None,
            );
        }
        self.validate_positive_duration(
            t.upstream_response,
            "server.timeouts.upstream-response-timeout",
            "upstream-response-timeout",
        );
        if t.upstream_response > Duration::from_secs(3_600) {
            self.error(
                "E007",
                "'upstream-response-timeout' must not exceed 3600s",
                "server.timeouts.upstream-response-timeout",
                None,
            );
        }
        self.validate_positive_duration(
            t.upstream_body_idle,
            "server.timeouts.upstream-body-idle-timeout",
            "upstream-body-idle-timeout",
        );
        self.validate_positive_duration(
            t.response_write_idle,
            "server.timeouts.response-write-idle",
            "response-write-idle",
        );
        if t.response_write_idle > Duration::from_secs(600) {
            self.error(
                "E007",
                "'response-write-idle' timeout must not exceed 600s",
                "server.timeouts.response-write-idle",
                None,
            );
        }
        if t.upstream_body_idle > Duration::from_secs(3_600) {
            self.error(
                "E007",
                "'upstream-body-idle-timeout' must not exceed 3600s",
                "server.timeouts.upstream-body-idle-timeout",
                None,
            );
        }

        let lim = &server.limits;
        if lim.max_connections == 0 || lim.max_connections > 1_000_000 {
            self.error(
                "E007",
                "'max-connections' must be between 1 and 1000000",
                "server.limits.max-connections",
                None,
            );
        }
        if lim.max_connections_per_ip == 0 || lim.max_connections_per_ip > 1_000_000 {
            self.error(
                "E007",
                "'max-connections-per-ip' must be between 1 and 1000000",
                "server.limits.max-connections-per-ip",
                None,
            );
        }
        if lim.max_streamed_answers_per_ip == 0 || lim.max_streamed_answers_per_ip > 10_000 {
            self.error(
                "E007",
                "'max-streamed-answers-per-ip' must be between 1 and 10000",
                "server.limits.max-streamed-answers-per-ip",
                None,
            );
        }
        if lim.max_streamed_answers_per_backend == 0
            || lim.max_streamed_answers_per_backend > 10_000
        {
            self.error(
                "E007",
                "'max-streamed-answers-per-backend' must be between 1 and 10000",
                "server.limits.max-streamed-answers-per-backend",
                None,
            );
        }
        if lim.ipv6_prefix_conn_multiplier == 0 || lim.ipv6_prefix_conn_multiplier > 1_000 {
            self.error(
                "E007",
                "'ipv6-prefix-conn-multiplier' must be between 1 and 1000",
                "server.limits.ipv6-prefix-conn-multiplier",
                None,
            );
        }
        let mut v4_ranges: Vec<(u64, u64)> = Vec::new();
        let mut v6_ranges: Vec<(u128, u128)> = Vec::new();
        for cidr in &lim.trusted_proxies {
            if cidr.prefix_len() == 0 {
                self.error(
                    "E007",
                    format!(
                        "'trusted-proxies' entry '{cidr}' matches the entire internet (/0) and is forbidden"
                    ),
                    "server.limits.trusted-proxies",
                    Some("restrict 'trusted-proxies' to your exact load balancer or proxy IPs (e.g. '/32' or '/128')"),
                );
                continue;
            }
            match cidr.network() {
                IpAddr::V4(v4) => {
                    let prefix = cidr.prefix_len();
                    if prefix < 8 {
                        // R6-XFF-4: Reject ultra-broad IPv4 CIDRs (`< /8`).
                        self.error(
                            "E007",
                            format!(
                                "'trusted-proxies' IPv4 entry '{cidr}' is overly broad (prefix < /8) and is forbidden"
                            ),
                            "server.limits.trusted-proxies",
                            Some("restrict 'trusted-proxies' to exact /32 proxy IPs or narrow /24+ subnets owned by your load balancer"),
                        );
                    } else if v4.octets()[0] == 0 {
                        // R6-XFF-4: Reject unspecified/this-network `0.0.0.0/8`.
                        self.error(
                            "E007",
                            format!(
                                "'trusted-proxies' entry '{cidr}' targets unspecified network 0.0.0.0/8 and is forbidden"
                            ),
                            "server.limits.trusted-proxies",
                            Some("list your specific proxy IPv4 addresses (e.g. '127.0.0.1/32', '10.0.1.10/32')"),
                        );
                    } else {
                        let start = u64::from(u32::from(v4));
                        let size = 1_u64 << (32 - u32::from(prefix));
                        v4_ranges.push((start, start.saturating_add(size).saturating_sub(1)));
                        if prefix < 24 {
                            // R7-XFF-2: Warn on overly broad IPv4 CIDRs broader than /24.
                            self.warn(
                                "W022",
                                format!(
                                    "'trusted-proxies' IPv4 entry '{cidr}' is broader than /24; every host in this range skips per-IP connection caps and may forge X-Forwarded-For"
                                ),
                                "server.limits.trusted-proxies",
                                Some("prefer exact /32 proxy IPs (e.g. '10.0.1.10/32') or at most a dedicated /24 proxy subnet"),
                            );
                        }
                    }
                }
                IpAddr::V6(v6) => {
                    let prefix = cidr.prefix_len();
                    if prefix < 16 {
                        self.error(
                            "E007",
                            format!(
                                "'trusted-proxies' IPv6 entry '{cidr}' is overly broad (prefix < /16) and is forbidden"
                            ),
                            "server.limits.trusted-proxies",
                            Some("restrict 'trusted-proxies' to exact /128 proxy IPs or narrow /64+ subnets owned by your load balancer"),
                        );
                    } else if v6.segments()[0] == 0 && prefix <= 16 {
                        // R6-XFF-4: Reject unspecified/reserved `::/16`.
                        self.error(
                            "E007",
                            format!(
                                "'trusted-proxies' entry '{cidr}' targets reserved IPv6 prefix ::/16 and is forbidden"
                            ),
                            "server.limits.trusted-proxies",
                            Some("list your specific proxy IPv6 addresses (e.g. '::1/128', 'fd00::10/128')"),
                        );
                    } else {
                        let start = u128::from(v6);
                        let host_bits = 128_u32.saturating_sub(u32::from(prefix));
                        let end = if host_bits >= 128 {
                            u128::MAX
                        } else {
                            start.saturating_add((1_u128 << host_bits).saturating_sub(1))
                        };
                        v6_ranges.push((start, end));
                        if prefix < 64 {
                            // R7-XFF-2: Warn on overly broad IPv6 CIDRs broader than /64.
                            self.warn(
                                "W022",
                                format!(
                                    "'trusted-proxies' IPv6 entry '{cidr}' is broader than /64; every host in this range skips per-IP connection caps and may forge X-Forwarded-For"
                                ),
                                "server.limits.trusted-proxies",
                                Some("prefer exact /128 proxy IPs or at most a dedicated /64 proxy subnet"),
                            );
                        }
                    }
                }
            }
        }
        // R6-XFF-4: Reject aggregate `trusted-proxies` unions covering >= 50% of IPv4 or IPv6
        // address space (blocks splitting 0.0.0.0/0 into 256 /8s or 128+ /8s!).
        if merged_u64_interval_coverage(&mut v4_ranges) >= (1_u64 << 31) {
            self.error(
                "E007",
                "'trusted-proxies' entries cumulatively cover >= 50% of IPv4 address space and are forbidden (R6-XFF-4)",
                "server.limits.trusted-proxies",
                Some("restrict 'trusted-proxies' to exact /32 proxy IPs or dedicated load-balancer subnets"),
            );
        }
        if merged_u128_interval_coverage(&mut v6_ranges) >= (1_u128 << 127) {
            self.error(
                "E007",
                "'trusted-proxies' entries cumulatively cover >= 50% of IPv6 address space and are forbidden (R6-XFF-4)",
                "server.limits.trusted-proxies",
                Some("restrict 'trusted-proxies' to exact /128 proxy IPs or dedicated load-balancer subnets"),
            );
        }
        if lim.max_header_bytes.as_bytes() == 0 || lim.max_header_bytes.as_bytes() > ByteSize::MIB {
            self.error(
                "E007",
                "'max-header-bytes' must be between 1 byte and 1MiB",
                "server.limits.max-header-bytes",
                None,
            );
        }
        if lim.max_body_bytes.as_bytes() == 0
            || lim.max_body_bytes.as_bytes() > 1_024 * ByteSize::MIB
        {
            self.error(
                "E007",
                "'max-body-bytes' must be between 1 byte and 1GiB",
                "server.limits.max-body-bytes",
                None,
            );
        }
        if lim.max_concurrent_streams == 0 || lim.max_concurrent_streams > 1_024 {
            self.error(
                "E007",
                "'max-concurrent-streams' must be between 1 and 1024",
                "server.limits.max-concurrent-streams",
                None,
            );
        }
        if lim.max_h2_rst_stream_per_sec == 0 || lim.max_h2_rst_stream_per_sec > 10_000 {
            self.error(
                "E007",
                "'max-h2-rst-stream-per-sec' must be between 1 and 10000",
                "server.limits.max-h2-rst-stream-per-sec",
                None,
            );
        }
        if lim.file_cache_bytes.as_bytes() > crate::schema::MAX_FILE_CACHE_BYTES {
            self.error(
                "E007",
                "'file-cache-bytes' must be 0 (disabled) or at most 1GiB",
                "server.limits.file-cache-bytes",
                Some("example: file-cache-bytes \"64MiB\" (or \"0\" to disable everywhere)"),
            );
        }
    }

    fn validate_sites(&mut self, sites: &[SiteConfig], server_has_client_ca: bool) {
        if sites.is_empty() {
            self.warn(
                "W015",
                "configuration defines zero 'site' blocks; all requests will return 404/421",
                "server",
                Some("add at least one `site \"example.com\" { ... }` block"),
            );
        }
        let mut seen_hosts: HashSet<String> = HashSet::new();
        let mut seen_publish_site_ids: HashMap<String, String> = HashMap::new();
        let mut seen_publish_storages: Vec<(String, String, String)> = Vec::new();
        for (site_idx, site) in sites.iter().enumerate() {
            self.validate_site(site, site_idx, &mut seen_hosts, server_has_client_ca);
            // R5-PUB-5: Enforce cross-site uniqueness and non-overlapping containment for both
            // effective `ai-publish.site-id` and `ai-publish.storage` (canonicalizing symlinks and
            // case-folding aliases) so two sites can never share or nest release stores!
            if let Some(publish) = &site.ai_publish {
                let prefix = format!("site[{site_idx}]");
                let primary_host = site.hosts.first().map_or("<unnamed>", String::as_str);
                let effective_sid = publish
                    .site_id
                    .as_deref()
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| primary_host.to_ascii_lowercase());
                if let Some(prev_site) =
                    seen_publish_site_ids.insert(effective_sid.clone(), primary_host.to_owned())
                {
                    let span_key = if publish.site_id.is_some() {
                        format!("{prefix}.ai-publish.site-id")
                    } else {
                        format!("{prefix}.ai-publish")
                    };
                    self.error(
                        "E401",
                        format!(
                            "duplicate ai-publish site-id '{effective_sid}' shared between sites '{prev_site}' and '{primary_host}'"
                        ),
                        &span_key,
                        Some("assign a unique `site-id` to every ai-publish site so signed bundles and JWT audiences remain isolated (R5-PUB-5)"),
                    );
                }
                if publish.storage != publish.storage.trim() {
                    continue;
                }
                let norm_storage = normalize_storage_path_key(&publish.storage);
                if let Some((prev_norm, prev_raw, prev_site)) = seen_publish_storages
                    .iter()
                    .find(|(prev_norm, _, _)| storage_paths_overlap(prev_norm, &norm_storage))
                {
                    let relation = if prev_norm == &norm_storage {
                        "duplicate ai-publish storage directory"
                    } else {
                        "nested ai-publish storage directory"
                    };
                    self.error(
                        "E401",
                        format!(
                            "{relation} '{}' overlaps site '{prev_site}' storage '{prev_raw}'",
                            publish.storage
                        ),
                        &format!("{prefix}.ai-publish.storage"),
                        Some("give each ai-publish site its own disjoint, non-nested storage directory (R5-PUB-5)"),
                    );
                } else {
                    seen_publish_storages.push((
                        norm_storage,
                        publish.storage.clone(),
                        primary_host.to_owned(),
                    ));
                }
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn validate_site(
        &mut self,
        site: &SiteConfig,
        site_idx: usize,
        seen_hosts: &mut HashSet<String>,
        server_has_client_ca: bool,
    ) {
        let prefix = format!("site[{site_idx}]");

        if site.rewrites.len() > crate::schema::MAX_REWRITE_RULES_PER_SITE {
            self.error(
                "E308",
                format!(
                    "site defines {} rewrite rules; the limit is {}",
                    site.rewrites.len(),
                    crate::schema::MAX_REWRITE_RULES_PER_SITE
                ),
                &format!("{prefix}.rewrite"),
                None,
            );
        }
        for (r_idx, rule) in site.rewrites.iter().enumerate() {
            let key = format!("{prefix}.rewrite.rule[{r_idx}]");
            if let Some(reason) = crate::schema::rewrite_rule_rejection(rule) {
                self.error(
                    "E308",
                    format!("rewrite rule '{}' is not allowed: {reason}", rule.pattern),
                    &key,
                    Some("see the rewrite section of docs/DEPLOYMENT.md for the accepted forms"),
                );
            }
            if (rule.if_not_file
                || rule.if_not_regular_file
                || rule.if_file
                || rule.if_regular_file)
                && site.root.is_none()
            {
                self.error(
                    "E308",
                    format!(
                        "rewrite rule '{}' uses if-not-file but the site has no root",
                        rule.pattern
                    ),
                    &key,
                    Some("add a site 'root' or remove if-not-file"),
                );
            }
        }

        for (h_idx, host) in site.hosts.iter().enumerate() {
            let h_key = format!("{prefix}.host[{h_idx}]");
            if is_valid_site_host(host) {
                let canonical = normalize_site_host(host);
                if !seen_hosts.insert(canonical.into_owned()) {
                    self.error(
                        "E107",
                        format!("duplicate site hostname '{host}'"),
                        &h_key,
                        Some("each hostname may only be bound to one 'site' block"),
                    );
                }
            } else {
                self.error(
                    "E107",
                    format!("invalid site hostname '{host}'"),
                    &h_key,
                    Some("use a bare DNS hostname (e.g. \"example.com\" or \"*.example.com\") or IP literal (e.g. \"127.0.0.1\" or \"[::1]\") without scheme, port, or path"),
                );
            }
        }

        let primary_host = site.hosts.first().map_or("<unnamed>", String::as_str);

        if site.root.is_none() && site.ai_publish.is_none() && site.routes.is_empty() {
            self.error(
                "E006",
                format!(
                    "site '{primary_host}' defines no 'root', 'ai-publish', or 'route' directives"
                ),
                &prefix,
                Some("add a 'root', 'ai-publish', or at least one 'route' block"),
            );
        }

        if site.security_headers == SecurityHeadersPolicy::Off {
            self.warn(
                "W004",
                format!("default security headers are disabled for site '{primary_host}'"),
                &format!("{prefix}.security-headers"),
                Some(
                    "use \"strict\" or \"standard\" unless an upstream injects equivalent headers",
                ),
            );
        }

        if site.http == SiteHttpMode::Redirect && site.http_credentials {
            self.error(
                "E003",
                "property 'credentials' is not valid on `http \"redirect\"`",
                &format!("{prefix}.http"),
                Some("remove 'credentials' or switch to `http \"serve\"`"),
            );
        } else if site.http == SiteHttpMode::Serve && site.http_credentials {
            self.warn(
                "W032",
                format!(
                    "passwords for {primary_host} travel unencrypted over plain HTTP (http \"serve\" credentials=#true)"
                ),
                &format!("{prefix}.http"),
                Some(
                    "remove `credentials=#true` once the site has a TLS certificate and serves over HTTPS",
                ),
            );
        }

        if let Some(rl) = &site.rate_limit {
            self.validate_rate_limit(rl, &format!("{prefix}.rate-limit"));
        }

        if let Some(tls) = &site.tls {
            if tls.compat_tls_1_2 {
                self.warn(
                    "W002",
                    format!("legacy TLS 1.2 compatibility is enabled for site '{primary_host}'"),
                    &format!("{prefix}.tls.compat-tls-1-2"),
                    Some("remove 'compat-tls-1-2 true' once legacy clients migrate to TLS 1.3"),
                );
            }
            if tls.pqc_hybrid == Some(false) {
                self.warn(
                    "W001",
                    format!(
                        "post-quantum hybrid key exchange is disabled for site '{primary_host}'"
                    ),
                    &format!("{prefix}.tls.pqc-hybrid"),
                    None,
                );
            }
            self.validate_cert_key_pair(
                tls.cert.as_deref(),
                tls.key.as_deref(),
                &format!("{prefix}.tls.cert"),
                &format!("{prefix}.tls.key"),
                &format!("{prefix}.tls"),
            );
            if let Some(ca) = &tls.client_ca {
                self.validate_safe_file_path(
                    ca,
                    &format!("{prefix}.tls.client-ca"),
                    "site mTLS client CA bundle",
                );
            }
        }

        if let Some(root) = &site.root {
            self.validate_safe_dir_path(root, &format!("{prefix}.root"), "site root");
        }

        if let Some(bot_auth) = &site.bot_auth {
            if !bot_auth.verify_rfc9421 {
                self.warn(
                    "W010",
                    format!("RFC 9421 cryptographic bot verification is disabled on site '{primary_host}'"),
                    &format!("{prefix}.bot-auth.verify-rfc9421"),
                    Some("enable 'verify-rfc9421 true' instead of trusting spoofable User-Agent headers (Threat Model T6)"),
                );
            }
            if let Some(keys_file) = &bot_auth.agent_keys_file {
                self.validate_safe_file_path(
                    keys_file,
                    &format!("{prefix}.bot-auth.agent-keys-file"),
                    "bot-auth agent-keys-file",
                );
            }
            for k in &bot_auth.agent_keys {
                if k.key_id.trim().is_empty()
                    || k.group.trim().is_empty()
                    || k.ed25519_b64.trim().is_empty()
                {
                    self.error(
                        "E404",
                        format!("invalid 'agent-key' entry on site '{primary_host}' (keyid, group, and ed25519 must be non-empty)"),
                        &format!("{prefix}.bot-auth.agent-key"),
                        None,
                    );
                }
            }
        }

        let site_has_client_ca =
            server_has_client_ca || site.tls.as_ref().is_some_and(|t| t.client_ca.is_some());
        if let Some(publish) = &site.ai_publish {
            self.validate_ai_publish(
                publish,
                &prefix,
                primary_host,
                site.hosts.len(),
                site_has_client_ca,
            );
        }

        if let Some(index_files) = &site.index {
            self.validate_index_list(index_files, &format!("{prefix}.index"));
        }

        if let Some(window) = site.file_cache
            && !(crate::schema::MIN_FILE_CACHE_WINDOW..=crate::schema::MAX_FILE_CACHE_WINDOW)
                .contains(&window)
        {
            self.error(
                "E007",
                "'file-cache' window must be between 100ms and 60s (or \"off\")",
                &format!("{prefix}.file-cache"),
                Some("examples: \"100ms\", \"1s\", \"60s\", \"off\""),
            );
        }

        if let Some(error_pages) = &site.error_pages {
            self.validate_error_pages(error_pages, &prefix, site.root.is_some());
        }

        self.validate_routes(site, &prefix, primary_host);
    }

    fn validate_index_list(&mut self, items: &[String], span_key: &str) {
        if items.is_empty() {
            self.error(
                "E004",
                "'index' requires at least one filename",
                span_key,
                Some("example: index \"index.php\" \"index.html\""),
            );
            return;
        }
        for entry in items {
            if entry.is_empty()
                || entry.contains('/')
                || entry.contains('\\')
                || entry.contains('\0')
                || entry == "."
                || entry == ".."
                || entry.starts_with('.')
            {
                self.error(
                    "E203",
                    format!("invalid directory index filename '{entry}'"),
                    span_key,
                    Some("index entries must be plain non-dotfile filenames without path separators (e.g. \"index.php\" \"index.html\")"),
                );
            }
        }
    }

    fn validate_error_pages(
        &mut self,
        error_pages: &ErrorPagesConfig,
        prefix: &str,
        has_site_root: bool,
    ) {
        if let Some(login_url) = &error_pages.login_url {
            let trimmed = login_url.trim();
            let span_key = format!("{prefix}.error-pages.login-url");
            let has_controls = trimmed.chars().any(|c| c.is_control() || c.is_whitespace());
            let is_safe_relative = trimmed.starts_with('/') && !trimmed.starts_with("//");
            let is_https = trimmed.starts_with("https://") && trimmed.len() > "https://".len();
            let is_http = trimmed.starts_with("http://") && trimmed.len() > "http://".len();
            if trimmed.is_empty() || has_controls || !(is_safe_relative || is_https || is_http) {
                self.error(
                    "E203",
                    format!("unsafe or invalid 'login-url' '{login_url}'"),
                    &span_key,
                    Some("use a site-relative path starting with '/' (e.g. \"/login\") or an https:// URL"),
                );
            } else if is_http {
                self.warn(
                    "W019",
                    format!("'login-url' '{login_url}' uses plaintext http://"),
                    &span_key,
                    Some("use a site-relative path or https:// URL for sign-in links"),
                );
            }
        }

        for (&status, path) in &error_pages.pages {
            let span_key = format!("{prefix}.error-pages.page.{status}");
            if !(400..=599).contains(&status) {
                self.error(
                    "E203",
                    format!("error page status '{status}' must be between 400 and 599"),
                    &span_key,
                    Some("only HTTP 4xx and 5xx error pages can be overridden"),
                );
            }
            self.validate_safe_file_path(path, &span_key, "error page");
            if path == path.trim() && !std::path::Path::new(path).is_absolute() && !has_site_root {
                self.error(
                    "E202",
                    format!("relative error page path '{path}' requires a site 'root' directory"),
                    &span_key,
                    Some("set `root \"/path/to/site\"` or use an absolute path for the custom error page"),
                );
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn validate_ai_publish(
        &mut self,
        publish: &AiPublishConfig,
        prefix: &str,
        primary_host: &str,
        host_count: usize,
        has_client_ca: bool,
    ) {
        self.validate_safe_dir_path(
            &publish.storage,
            &format!("{prefix}.ai-publish.storage"),
            "ai-publish storage",
        );
        if let Some(sid) = &publish.site_id {
            let trimmed = sid.trim();
            if trimmed.is_empty()
                || trimmed.len() > 255
                || trimmed
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '/' | '\\'))
            {
                self.error(
                    "E401",
                    format!("invalid ai-publish 'site-id' '{sid}'"),
                    &format!("{prefix}.ai-publish.site-id"),
                    Some("use a stable non-empty identifier without whitespace or slashes (e.g. \"prod-marketing-site\")"),
                );
            }
        } else if host_count > 1 || primary_host.starts_with("*.") {
            self.warn(
                "W018",
                format!(
                    "ai-publish on site '{primary_host}' omits 'site-id' while using multiple or wildcard hosts; reordering hosts changes the derived publish identity and JWT audience"
                ),
                &format!("{prefix}.ai-publish"),
                Some("set an explicit stable `site-id` matching the current first host, or re-sign existing releases with `miraserve publish resign --config <CONFIG> --site <SITE> --old-pubkey <PUBKEY> --key <SECRET_KEY> --rebind-site-id` when migrating to a new site-id (R4-PUB-3 / R5-PUB-1)"),
            );
        }
        if publish.keep_versions == 0 || publish.keep_versions > 1_000 {
            self.error(
                "E401",
                format!(
                    "ai-publish 'keep-versions' must be between 1 and 1000, found {}",
                    publish.keep_versions
                ),
                &format!("{prefix}.ai-publish.keep-versions"),
                None,
            );
        }
        if let Some(sig) = &publish.require_signature {
            self.validate_safe_file_path(
                &sig.public_key_path,
                &format!("{prefix}.ai-publish.require-signature"),
                "require-signature public key",
            );
        }
        if let Some(pk) = &publish.jwt_public_key {
            if let Some(path) = pk.strip_prefix("ed25519:") {
                self.validate_safe_file_path(
                    path,
                    &format!("{prefix}.ai-publish.jwt-public-key"),
                    "ai-publish JWT public key",
                );
            } else if crate::parser::tagged_path_whitespace_reason(pk, "ed25519:").is_none()
                && (!pk.starts_with("miraserve-ed25519-pub:") || pk.trim().len() <= 24)
            {
                self.error(
                    "E401",
                    format!("invalid ai-publish 'jwt-public-key' format '{pk}'"),
                    &format!("{prefix}.ai-publish.jwt-public-key"),
                    Some("use \"ed25519:/path/to/jwt.pub\" or \"miraserve-ed25519-pub:<base64>\""),
                );
            }
            if publish
                .mcp_endpoint
                .as_ref()
                .is_none_or(|ep| ep.auth != PublishAuthMode::OAuthJwt)
            {
                self.error(
                    "E401",
                    format!(
                        "ai-publish 'jwt-public-key' on site '{primary_host}' requires mcp-endpoint with auth=\"oauth-jwt\""
                    ),
                    &format!("{prefix}.ai-publish.jwt-public-key"),
                    Some("pair `jwt-public-key` with `mcp-endpoint \"/_miraserve/publish\" auth=\"oauth-jwt\"`"),
                );
            }
        }
        if let Some(iss) = &publish.jwt_issuer {
            if iss.trim().is_empty() || iss.chars().any(char::is_control) {
                self.error(
                    "E401",
                    "ai-publish 'jwt-issuer' must be a non-empty string without control characters",
                    &format!("{prefix}.ai-publish.jwt-issuer"),
                    None,
                );
            }
            if publish
                .mcp_endpoint
                .as_ref()
                .is_none_or(|ep| ep.auth != PublishAuthMode::OAuthJwt)
            {
                self.error(
                    "E401",
                    format!(
                        "ai-publish 'jwt-issuer' on site '{primary_host}' requires mcp-endpoint with auth=\"oauth-jwt\""
                    ),
                    &format!("{prefix}.ai-publish.jwt-issuer"),
                    Some("pair `jwt-issuer` with `mcp-endpoint \"/_miraserve/publish\" auth=\"oauth-jwt\"`"),
                );
            }
        }
        if !publish.allowed_subjects.is_empty() {
            for subj in &publish.allowed_subjects {
                let trimmed = subj.trim();
                let valid_dn = !trimmed.is_empty()
                    && !trimmed.chars().any(char::is_control)
                    && trimmed
                        .split_once('=')
                        .is_some_and(|(k, v)| !k.trim().is_empty() && !v.trim().is_empty());
                if !valid_dn {
                    self.error(
                        "E401",
                        format!(
                            "ai-publish 'allowed-subjects' entry '{subj}' must be a non-empty RFC 4514 Distinguished Name (e.g. \"O=Corp, CN=deploy-bot\")"
                        ),
                        &format!("{prefix}.ai-publish.allowed-subjects"),
                        Some("specify the full client certificate Subject DN (R5-PUB-2)"),
                    );
                }
            }
            if publish
                .mcp_endpoint
                .as_ref()
                .is_none_or(|ep| ep.auth != PublishAuthMode::Mtls)
            {
                self.error(
                    "E401",
                    format!(
                        "ai-publish 'allowed-subjects' on site '{primary_host}' requires mcp-endpoint with auth=\"mtls\""
                    ),
                    &format!("{prefix}.ai-publish.allowed-subjects"),
                    Some("pair `allowed-subjects` with `mcp-endpoint \"/_miraserve/publish\" auth=\"mtls\"`"),
                );
            }
        }
        if let Some(ep) = &publish.mcp_endpoint {
            if !ep.path.starts_with('/')
                || ep.path.contains("..")
                || ep.path.chars().any(char::is_whitespace)
            {
                self.error(
                    "E401",
                    format!("invalid ai-publish mcp-endpoint path '{}'", ep.path),
                    &format!("{prefix}.ai-publish.mcp-endpoint"),
                    Some("path must start with '/' and contain no '..' or whitespace (e.g. \"/_miraserve/publish\")"),
                );
            }
            match ep.auth {
                PublishAuthMode::Ed25519 => {
                    if publish.require_signature.is_none() {
                        self.error(
                            "E401",
                            format!(
                                "ai-publish mcp-endpoint with auth=\"ed25519\" on site '{primary_host}' requires 'require-signature'"
                            ),
                            &format!("{prefix}.ai-publish.mcp-endpoint"),
                            Some("configure require-signature \"ed25519:/path/to/key.pub\" so requests and bundles are cryptographically verified"),
                        );
                    }
                }
                PublishAuthMode::OAuthJwt => {
                    // R5-PUB-3: Keep `require-signature` MANDATORY for `auth="oauth-jwt"` just
                    // like `auth="mtls"`, so a compromised bearer token alone can never deploy
                    // unsigned content or bypass site-id signature binding!
                    if publish.require_signature.is_none() {
                        self.error(
                            "E401",
                            format!(
                                "ai-publish mcp-endpoint with auth=\"oauth-jwt\" on site '{primary_host}' requires 'require-signature' to prevent unsigned bundle deploys"
                            ),
                            &format!("{prefix}.ai-publish.mcp-endpoint"),
                            Some("configure `require-signature \"ed25519:/path/to/deploy.pub\"` alongside `jwt-public-key` (R5-PUB-3)"),
                        );
                    } else if publish.jwt_public_key.is_none() {
                        // Emit explicit warning W020 when oauth-jwt falls back to reusing the
                        // bundle `require-signature` key instead of a dedicated `jwt-public-key`.
                        self.warn(
                            "W020",
                            format!(
                                "ai-publish mcp-endpoint with auth=\"oauth-jwt\" on site '{primary_host}' omits 'jwt-public-key' and falls back to reusing the bundle 'require-signature' key for OAuth JWT verification"
                            ),
                            &format!("{prefix}.ai-publish.mcp-endpoint"),
                            Some("configure a dedicated `jwt-public-key \"ed25519:/path/to/jwt.pub\"` to separate request authentication from bundle signing"),
                        );
                    }
                }
                PublishAuthMode::Mtls => {
                    if !has_client_ca {
                        self.error(
                            "E401",
                            format!(
                                "ai-publish mcp-endpoint with auth=\"mtls\" on site '{primary_host}' requires 'client-ca' in server.tls or site.tls"
                            ),
                            &format!("{prefix}.ai-publish.mcp-endpoint"),
                            Some("configure `client-ca \"/path/to/client-ca.pem\"` in `server.tls` or `site.tls`"),
                        );
                    }
                    // R2-PUB-4: Require Ed25519 bundle signature alongside mTLS so a broad
                    // organizational CA cannot push unsigned site bundles.
                    if publish.require_signature.is_none() {
                        self.error(
                            "E401",
                            format!(
                                "ai-publish mcp-endpoint with auth=\"mtls\" on site '{primary_host}' also requires 'require-signature' to prevent any CA-issued certificate from publishing unsigned bundles"
                            ),
                            &format!("{prefix}.ai-publish.mcp-endpoint"),
                            Some("configure `require-signature \"ed25519:/path/to/deploy.pub\"` alongside `client-ca`"),
                        );
                    }
                    if publish.allowed_subjects.is_empty() {
                        self.warn(
                            "W019",
                            format!(
                                "ai-publish mcp-endpoint with auth=\"mtls\" on site '{primary_host}' omits 'allowed-subjects'; any certificate issued by client-ca can call site_rollback and site_list_releases"
                            ),
                            &format!("{prefix}.ai-publish.mcp-endpoint"),
                            Some("configure `allowed-subjects \"CN=deploy-agent\"` to restrict mTLS publisher identities"),
                        );
                    }
                }
            }
        }
        if publish.require_signature.is_none() && publish.mcp_endpoint.is_none() {
            self.error(
                "E401",
                format!("ai-publish on site '{primary_host}' requires 'require-signature' or an authenticated 'mcp-endpoint'"),
                &format!("{prefix}.ai-publish"),
                Some("Threat Model T6 forbids unauthenticated site publishing"),
            );
        }
        if !publish
            .preflight_checks
            .contains(&PreflightCheck::NoSecrets)
        {
            self.warn(
                "W009",
                format!("ai-publish on site '{primary_host}' omits the recommended \"no-secrets\" preflight check"),
                &format!("{prefix}.ai-publish"),
                Some("add \"no-secrets\" to 'preflight-checks' to prevent accidental credential publication"),
            );
        }
    }

    #[allow(clippy::too_many_lines)]
    fn validate_routes(&mut self, site: &SiteConfig, site_prefix: &str, primary_host: &str) {
        let mut seen_patterns = HashSet::new();
        let mut prior_patterns: Vec<&str> = Vec::new();

        for (r_idx, route) in site.routes.iter().enumerate() {
            let r_prefix = format!("{site_prefix}.route[{r_idx}]");

            // This release protects whole sites only: a route-level visitor list or password
            // could be bypassed through the many ways a request reaches a file (fallbacks,
            // directory indexes, PHP scripts, links).
            if !route.access.is_empty() || route.basic_auth.is_some() {
                self.error(
                    "E311",
                    format!(
                        "route '{}' on site '{primary_host}': `access` and `basic-auth` are \
                         available for a whole site only; move them to the site block",
                        route.pattern
                    ),
                    &r_prefix,
                    None,
                );
            }

            if is_valid_route_pattern(&route.pattern) {
                if !seen_patterns.insert(route.pattern.clone()) {
                    self.error(
                        "E301",
                        format!(
                            "duplicate route pattern '{}' on site '{primary_host}'",
                            route.pattern
                        ),
                        &r_prefix,
                        None,
                    );
                } else if let Some(shadowed_by) = prior_patterns
                    .iter()
                    .copied()
                    .find(|earlier| route_pattern_shadows(earlier, &route.pattern))
                {
                    self.warn(
                        "W014",
                        format!(
                            "route '{}' on site '{primary_host}' is shadowed by earlier broader route '{shadowed_by}'",
                            route.pattern
                        ),
                        &r_prefix,
                        Some("place more specific routes (e.g. \"/admin/*\" or \"*.php\") BEFORE catch-all/prefix routes like \"/*\""),
                    );
                }
                prior_patterns.push(route.pattern.as_str());
            } else {
                self.error(
                    "E301",
                    format!("invalid route pattern '{}' on site '{primary_host}'", route.pattern),
                    &r_prefix,
                    Some("route patterns must be exact ('/foo'), prefix ('/api/*', '/*'), or extension ('*.php') with no mid-path wildcards"),
                );
            }

            if let Some(root) = &route.root {
                self.validate_safe_dir_path(root, &format!("{r_prefix}.root"), "route root");
            }
            if let Some(rl) = &route.rate_limit {
                self.validate_rate_limit(rl, &format!("{r_prefix}.rate-limit"));
            }
            if route.security_headers == Some(SecurityHeadersPolicy::Off) {
                self.warn(
                    "W004",
                    format!(
                        "security headers disabled on route '{}' of site '{primary_host}'",
                        route.pattern
                    ),
                    &format!("{r_prefix}.security-headers"),
                    None,
                );
            }

            // CFG-1: Static and try-files routes always require a filesystem `root`
            // (sites using only `ai-publish` serve from the release store without static/try-files).
            let has_filesystem_root = route.root.is_some() || site.root.is_some();

            match &route.handler {
                RouteHandler::FastCgi(fcgi) => {
                    if !has_filesystem_root {
                        self.error(
                            "E303",
                            format!(
                                "FastCGI route '{}' on site '{primary_host}' requires a 'root' directory on the route or site",
                                route.pattern
                            ),
                            &format!("{r_prefix}.fastcgi-pass"),
                            Some("set `root \"/var/www/site\"` on the site or route so FastCGI never falls back to the current working directory"),
                        );
                    }
                    match &fcgi.target {
                        FastCgiTarget::Unix { path } => {
                            self.validate_safe_file_path(
                                path,
                                &format!("{r_prefix}.fastcgi-pass"),
                                "FastCGI Unix socket",
                            );
                        }
                        FastCgiTarget::Tcp { host, .. } => {
                            if !is_loopback_host(host) {
                                self.warn(
                                    "W005",
                                    format!(
                                        "plaintext FastCGI TCP target '{host}' on route '{}' is non-loopback",
                                        route.pattern
                                    ),
                                    &format!("{r_prefix}.fastcgi-pass"),
                                    Some("prefer a local Unix domain socket (`unix:/run/php/...`) or loopback TCP"),
                                );
                            }
                        }
                    }
                    if fcgi.timeout.is_zero() || fcgi.timeout > Duration::from_secs(300) {
                        self.error(
                            "E304",
                            "fastcgi-pass 'timeout' must be between 1ms and 300s",
                            &format!("{r_prefix}.fastcgi-pass"),
                            None,
                        );
                    }
                }
                RouteHandler::TryFiles(tf) => {
                    if !has_filesystem_root {
                        self.error(
                            "E303",
                            format!(
                                "route '{}' uses 'try-files' without a configured 'root' on site '{primary_host}'",
                                route.pattern
                            ),
                            &format!("{r_prefix}.try-files"),
                            Some("add a 'root \"/path/to/docroot\"' directive to the site or route"),
                        );
                    }
                    for candidate in &tf.candidates {
                        if let Some(status) = candidate
                            .strip_prefix('=')
                            .and_then(|code| code.parse::<u16>().ok())
                            && let Some(header) = respond_status_required_header(status)
                        {
                            self.error(
                                "E306",
                                format!(
                                    "try-files status ={status} on route '{}' needs a {header} header, which a fixed response cannot send",
                                    route.pattern
                                ),
                                &format!("{r_prefix}.try-files"),
                                Some("use =404 or =403"),
                            );
                        }
                        if candidate.trim().is_empty() || candidate.contains('\0') {
                            self.error(
                                "E303",
                                "try-files candidate must be a non-empty string without null bytes",
                                &format!("{r_prefix}.try-files"),
                                None,
                            );
                        }
                    }
                }
                RouteHandler::McpGateway(mcp) => {
                    self.validate_mcp_gateway(mcp, &route.pattern, &r_prefix);
                }
                RouteHandler::ReverseProxy(rp) => {
                    if rp.strip_prefix && (route.pattern == "/*" || !route.pattern.ends_with("/*"))
                    {
                        self.error(
                            "E306",
                            format!(
                                "reverse-proxy strip-prefix on route '{}' needs a prefix route",
                                route.pattern
                            ),
                            &format!("{r_prefix}.reverse-proxy.strip-prefix"),
                            Some("use it on a route such as \"/tool/*\""),
                        );
                    }
                    self.validate_reverse_proxy(rp, &route.pattern, &r_prefix);
                }
                RouteHandler::Static(st) => {
                    if !has_filesystem_root {
                        self.error(
                            "E303",
                            format!(
                                "route '{}' uses 'static' handler without a configured 'root' on site '{primary_host}'",
                                route.pattern
                            ),
                            &format!("{r_prefix}.static"),
                            None,
                        );
                    }
                    self.validate_index_list(&st.index, &format!("{r_prefix}.static.index"));
                    if st.dotfiles == DotfilesPolicy::Allow {
                        self.warn(
                            "W008",
                            format!("dotfile access (.env, .git) is allowed on route '{}' of site '{primary_host}'", route.pattern),
                            &format!("{r_prefix}.static.dotfiles"),
                            Some("set 'dotfiles \"deny\"' to prevent leaking secrets and VCS metadata (Threat Model T5)"),
                        );
                    }
                }
                RouteHandler::WasmPlugin(wasm) => {
                    self.validate_wasm_plugin(wasm, &r_prefix);
                }
                RouteHandler::Respond(status) => {
                    if !(400..=599).contains(status) {
                        self.error(
                            "E306",
                            format!(
                                "respond status {status} on route '{}' is not allowed",
                                route.pattern
                            ),
                            &format!("{r_prefix}.respond"),
                            Some("use an error status from 400 to 599, for example 503 for a suspended site"),
                        );
                    } else if let Some(header) = respond_status_required_header(*status) {
                        // RFC 9110 requires these statuses to carry a header that says how to
                        // proceed; a fixed response has no way to supply it.
                        self.error(
                            "E306",
                            format!(
                                "respond status {status} on route '{}' needs a {header} header, which a fixed response cannot send",
                                route.pattern
                            ),
                            &format!("{r_prefix}.respond"),
                            Some("use 403 to refuse access, 404 to hide the path, or 503 for a suspended site"),
                        );
                    }
                }
                RouteHandler::Redirect(redirect) => {
                    if !matches!(redirect.status, 301 | 302 | 307 | 308) {
                        self.error(
                            "E306",
                            format!(
                                "redirect status {} on route '{}' is not allowed",
                                redirect.status, route.pattern
                            ),
                            &format!("{r_prefix}.redirect"),
                            Some("use 301, 302, 307 or 308"),
                        );
                    }
                    if redirect.target.contains("{rest}") && !route.pattern.ends_with("/*") {
                        self.error(
                            "E306",
                            format!(
                                "redirect target '{}' uses {{rest}} but route '{}' is not a prefix route",
                                redirect.target, route.pattern
                            ),
                            &format!("{r_prefix}.redirect"),
                            Some("{rest} is the path after the prefix of a route such as \"/old/*\""),
                        );
                    }
                    if let Some(reason) = crate::schema::redirect_target_rejection(&redirect.target)
                    {
                        self.error(
                            "E306",
                            format!(
                                "redirect target '{}' on route '{}' is not allowed: {reason}",
                                redirect.target, route.pattern
                            ),
                            &format!("{r_prefix}.redirect"),
                            Some("examples: \"https://example.com{uri}\", \"/new-place\", \"/shop{path}\""),
                        );
                    }
                }
            }
        }
    }

    fn validate_telemetry(
        &mut self,
        tel: &TelemetryConfig,
        listeners: &[crate::schema::ListenConfig],
    ) {
        if !tel.metrics_path.starts_with('/') || tel.metrics_path.contains("..") {
            self.error(
                "E108",
                format!(
                    "telemetry 'metrics-path' '{}' must be an absolute path without '..'",
                    tel.metrics_path
                ),
                "server.telemetry.metrics-path",
                Some("example: metrics-path \"/metrics\""),
            );
        }
        if let Some(listen) = &tel.metrics_listen {
            if !listen.host.is_some_and(|ip| ip.is_loopback()) {
                self.warn(
                    "W012",
                    format!("Prometheus metrics listener '{listen}' binds a non-loopback address"),
                    "server.telemetry.metrics-listen",
                    Some("bind Prometheus metrics to 127.0.0.1 or protect with a firewall/mTLS"),
                );
            }
            for srv_listen in listeners {
                if listen.conflicts_with(&srv_listen.addr) {
                    self.error(
                        "E102",
                        format!(
                            "telemetry 'metrics-listen' '{listen}' conflicts with server listener '{}'",
                            srv_listen.addr
                        ),
                        "server.telemetry.metrics-listen",
                        Some("bind Prometheus metrics to a dedicated loopback port such as \"127.0.0.1:9090\""),
                    );
                }
            }
        }
        if let Some(otlp) = &tel.otlp_endpoint {
            self.validate_upstream_url(
                otlp,
                "server.telemetry.otlp-endpoint",
                "E108",
                "OTLP endpoint",
            );
        }
        if tel.service_name.trim().is_empty() {
            self.error(
                "E108",
                "telemetry 'service-name' cannot be empty",
                "server.telemetry.service-name",
                None,
            );
        }
        if !tel.redact_logs {
            self.warn(
                "W013",
                "automatic secret redaction in access/audit logs is disabled",
                "server.telemetry.redact-logs",
                Some("keep 'redact-logs true' to prevent leaking Authorization headers, cookies, and API keys"),
            );
        }
    }

    fn validate_wasm_plugin(&mut self, wasm: &WasmPluginConfig, r_prefix: &str) {
        self.validate_safe_file_path(
            &wasm.module_path,
            &format!("{r_prefix}.wasm-plugin"),
            "wasm-plugin module",
        );
        let min_mem = 64 * ByteSize::KIB;
        let max_mem = 256 * ByteSize::MIB;
        let bytes = wasm.max_memory.as_bytes();
        if bytes < min_mem || bytes > max_mem {
            self.error(
                "E501",
                format!(
                    "wasm-plugin 'max-memory' ({bytes} bytes) must be between 64KB and 256MB"
                ),
                &format!("{r_prefix}.wasm-plugin.max-memory"),
                Some("Threat Model T7 requires bounded deterministic WASM linear memory (default 16MB)"),
            );
        }
        let max_wasm_fuel: u64 = 50_000_000;
        if wasm.max_fuel == 0 || wasm.max_fuel > max_wasm_fuel {
            self.error(
                "E501",
                format!("wasm-plugin 'max-fuel' must be between 1 and {max_wasm_fuel}"),
                &format!("{r_prefix}.wasm-plugin.max-fuel"),
                Some("Threat Model T7 requires a bounded finite CPU fuel budget per request"),
            );
        }
        if wasm.timeout.is_zero() || wasm.timeout > Duration::from_secs(30) {
            self.error(
                "E501",
                "wasm-plugin 'timeout' must be between 1ms and 30s",
                &format!("{r_prefix}.wasm-plugin.timeout"),
                None,
            );
        }
        // WASM-6: Reject non-empty `allow-hosts` fail-closed while outbound wasi:http is disabled.
        if !wasm.allow_outbound_hosts.is_empty() {
            self.error(
                "E501",
                "wasm-plugin 'allow-hosts' is not yet supported (outbound wasi:http requests remain denied fail-closed)",
                &format!("{r_prefix}.wasm-plugin.allow-hosts"),
                Some("remove 'allow-hosts' until outbound WASM HTTP proxying is enabled"),
            );
        }
    }

    #[allow(clippy::too_many_lines)]
    fn validate_mcp_gateway(&mut self, mcp: &McpGatewayConfig, pattern: &str, r_prefix: &str) {
        self.validate_upstream_url(
            &mcp.upstream,
            &format!("{r_prefix}.mcp-gateway.upstream"),
            "E403",
            "mcp-gateway upstream",
        );

        if mcp.max_json_depth == 0 || mcp.max_json_depth > 128 {
            self.error(
                "E403",
                format!(
                    "mcp-gateway 'max-json-depth' must be between 1 and 128, found {}",
                    mcp.max_json_depth
                ),
                &format!("{r_prefix}.mcp-gateway.max-json-depth"),
                Some("aligned with serde_json recursion depth limit (128) so JSON inspection never fails open"),
            );
        }
        if mcp.max_request_bytes.as_bytes() == 0 {
            self.error(
                "E403",
                "mcp-gateway 'max-request-bytes' must be greater than zero",
                &format!("{r_prefix}.mcp-gateway.max-request-bytes"),
                None,
            );
        }

        // MCP-3: Empty `allow-tools` is forbidden (least-privilege default-deny).
        if mcp.allow_tools.is_empty() {
            self.error(
                "E403",
                format!("mcp-gateway route '{pattern}' must specify at least one pattern in 'allow-tools' (default-deny)"),
                &format!("{r_prefix}.mcp-gateway.allow-tools"),
                Some("list explicit permitted tools such as: allow-tools \"docs_search\" \"catalog_read\""),
            );
        }

        for pat in mcp.allow_tools.iter().chain(mcp.deny_tools.iter()) {
            if pat.trim().is_empty() || pat.chars().any(char::is_whitespace) {
                self.error(
                    "E403",
                    format!("invalid MCP tool pattern '{pat}'"),
                    &format!("{r_prefix}.mcp-gateway"),
                    None,
                );
            }
        }

        if let Some(pk) = &mcp.jwt_public_key {
            if let Some(path) = pk.strip_prefix("ed25519:") {
                self.validate_safe_file_path(
                    path,
                    &format!("{r_prefix}.mcp-gateway.jwt-public-key"),
                    "mcp-gateway JWT public key",
                );
            } else if crate::parser::tagged_path_whitespace_reason(pk, "ed25519:").is_none()
                && (!pk.starts_with("miraserve-ed25519-pub:") || pk.trim().len() <= 24)
            {
                self.error(
                    "E403",
                    format!("invalid mcp-gateway 'jwt-public-key' format '{pk}'"),
                    &format!("{r_prefix}.mcp-gateway.jwt-public-key"),
                    Some("use \"ed25519:/path/to/key.pub\" or \"miraserve-ed25519-pub:<base64>\""),
                );
            }
        }
        if let Some(jwks) = &mcp.jwks_url {
            self.validate_upstream_url(
                jwks,
                &format!("{r_prefix}.mcp-gateway.jwks-url"),
                "E403",
                "mcp-gateway jwks-url",
            );
            // R2-MCP-2: Plain HTTP JWKS over a non-loopback network allows active MITM key
            // substitution — reject as a hard error!
            if let Ok(parsed) = Url::parse(jwks)
                && parsed.scheme() == "http"
                && !parsed.host_str().is_some_and(is_loopback_host)
            {
                self.error(
                    "E403",
                    format!(
                        "mcp-gateway jwks-url '{jwks}' must use https:// for non-loopback hosts"
                    ),
                    &format!("{r_prefix}.mcp-gateway.jwks-url"),
                    Some("switch jwks-url to https:// to prevent MITM key injection"),
                );
            }
            if mcp.jwt_audience.is_none() {
                self.warn(
                    "W006",
                    format!(
                        "mcp-gateway route '{pattern}' uses 'jwks-url' without 'jwt-audience'; tokens minted for other services by the same IdP may be accepted"
                    ),
                    &format!("{r_prefix}.mcp-gateway.jwks-url"),
                    Some("set `jwt-audience \"<this-mcp-service-id>\"` (and `jwt-issuer`)"),
                );
            }
        }

        // MCP-2: OAuth 2.1 metadata OR any JWT claim policy (`jwt-issuer`, `jwt-audience`,
        // `required-scope`) requires a cryptographic JWT verifier (`jwt-public-key` or `jwks-url`).
        let has_claim_policy =
            mcp.jwt_issuer.is_some() || mcp.jwt_audience.is_some() || mcp.required_scope.is_some();
        if (mcp.oauth_resource_metadata || has_claim_policy)
            && mcp.jwt_public_key.is_none()
            && mcp.jwks_url.is_none()
        {
            self.error(
                "E403",
                format!(
                    "mcp-gateway route '{pattern}' configures OAuth/JWT claim enforcement without 'jwt-public-key' or 'jwks-url'"
                ),
                &format!("{r_prefix}.mcp-gateway"),
                Some("configure `jwt-public-key \"ed25519:/path/to/oauth.pub\"` or `jwks-url \"https://.../.well-known/jwks.json\"` to cryptographically verify OAuth 2.1 Bearer JWTs"),
            );
        }

        // R4-MCP-2 & R5-MCP-7: RFC 9728 Protected Resource Metadata advertises
        // `authorization_servers` and identifies this protected resource; require BOTH an
        // explicit `jwt-issuer` AND an explicit `jwt-audience` so tokens minted for other
        // services by the same IdP can never be replayed here!
        if mcp.oauth_resource_metadata
            && mcp
                .jwt_issuer
                .as_deref()
                .is_none_or(|s| s.trim().is_empty())
        {
            self.error(
                "E403",
                format!(
                    "mcp-gateway route '{pattern}' enables 'oauth-resource-metadata' without an explicit 'jwt-issuer'"
                ),
                &format!("{r_prefix}.mcp-gateway.jwt-issuer"),
                Some("set `jwt-issuer \"https://auth.example.com\"` so RFC 9728 `authorization_servers` advertises the real OAuth issuer"),
            );
        }
        if mcp.oauth_resource_metadata
            && mcp
                .jwt_audience
                .as_deref()
                .is_none_or(|s| s.trim().is_empty())
        {
            self.error(
                "E403",
                format!(
                    "mcp-gateway route '{pattern}' enables 'oauth-resource-metadata' without an explicit 'jwt-audience'"
                ),
                &format!("{r_prefix}.mcp-gateway.jwt-audience"),
                Some("set `jwt-audience \"https://your-site.example.com/mcp\"` so tokens minted for other resources are rejected (R5-MCP-7)"),
            );
        }

        if !mcp.oauth_resource_metadata {
            self.warn(
                "W006",
                format!("OAuth 2.1 RFC 9728 metadata disabled on mcp-gateway route '{pattern}'"),
                &format!("{r_prefix}.mcp-gateway.oauth-resource-metadata"),
                Some("keep 'oauth-resource-metadata true' for standards-compliant MCP authentication"),
            );
        }
        if mcp.audit_log == AuditLogMode::Off {
            self.warn(
                "W006",
                format!("MCP audit logging is disabled on route '{pattern}'"),
                &format!("{r_prefix}.mcp-gateway.audit-log"),
                Some("set 'audit-log \"structured-json\"' for tamper-evident redacted audit trails (Threat Model T6)"),
            );
        }
        if mcp.allow_tools.iter().any(|t| t == "*") && mcp.deny_tools.is_empty() {
            self.warn(
                "W006",
                format!("mcp-gateway route '{pattern}' allows all tools ('*') without any 'deny-tools' exclusions"),
                &format!("{r_prefix}.mcp-gateway.allow-tools"),
                Some("prefer an explicit tool allowlist (default-deny) per Threat Model T6"),
            );
        }
        for allowed in &mcp.allow_tools {
            if mcp.deny_tools.contains(allowed) {
                self.warn(
                    "W007",
                    format!("MCP tool pattern '{allowed}' appears in both 'allow-tools' and 'deny-tools' (deny takes precedence)"),
                    &format!("{r_prefix}.mcp-gateway.deny-tools"),
                    None,
                );
            }
        }
        if let Some(connect_tmo) = mcp.upstream_connect_timeout {
            let k = format!("{r_prefix}.mcp-gateway.upstream-connect-timeout");
            self.validate_positive_duration(connect_tmo, &k, "upstream-connect-timeout");
            if connect_tmo > Duration::from_secs(120) {
                self.error(
                    "E007",
                    "'upstream-connect-timeout' must not exceed 120s",
                    &k,
                    None,
                );
            }
        }
        if let Some(resp_tmo) = mcp.upstream_response_timeout {
            let k = format!("{r_prefix}.mcp-gateway.upstream-response-timeout");
            self.validate_positive_duration(resp_tmo, &k, "upstream-response-timeout");
            if resp_tmo > Duration::from_secs(3_600) {
                self.error(
                    "E007",
                    "'upstream-response-timeout' must not exceed 3600s",
                    &k,
                    None,
                );
            }
        }
        if let Some(idle_tmo) = mcp.upstream_body_idle_timeout {
            let k = format!("{r_prefix}.mcp-gateway.upstream-body-idle-timeout");
            self.validate_positive_duration(idle_tmo, &k, "upstream-body-idle-timeout");
            if idle_tmo > Duration::from_hours(24) {
                self.error(
                    "E007",
                    "'upstream-body-idle-timeout' must not exceed 86400s (24h)",
                    &k,
                    None,
                );
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn validate_reverse_proxy(&mut self, rp: &ReverseProxyConfig, pattern: &str, r_prefix: &str) {
        if rp.upstreams.is_empty() {
            self.error(
                "E305",
                format!(
                    "'reverse-proxy' on route '{pattern}' must configure at least one 'upstream'"
                ),
                &format!("{r_prefix}.reverse-proxy"),
                Some("add: upstream \"https://10.0.1.30:8000\""),
            );
        }
        for (u_idx, upstream) in rp.upstreams.iter().enumerate() {
            let u_key = format!("{r_prefix}.reverse-proxy.upstream[{u_idx}]");
            if upstream.weight == 0 {
                self.error(
                    "E305",
                    format!("upstream '{}' weight must be at least 1", upstream.url),
                    &u_key,
                    None,
                );
            }
            self.validate_upstream_url(&upstream.url, &u_key, "E305", "reverse-proxy upstream");
        }
        if let Some(hc) = &rp.health_check {
            let hc_key = format!("{r_prefix}.reverse-proxy.health-check");
            if !hc.path.starts_with('/') || hc.path.chars().any(char::is_whitespace) {
                self.error(
                    "E305",
                    format!(
                        "health-check path '{}' must start with '/' and contain no whitespace",
                        hc.path
                    ),
                    &hc_key,
                    None,
                );
            }
            if hc.interval.is_zero() {
                self.error(
                    "E305",
                    "health-check 'interval' must be greater than zero",
                    &hc_key,
                    None,
                );
            }
            if hc.unhealthy_threshold == 0 {
                self.error(
                    "E305",
                    "health-check 'unhealthy-threshold' must be at least 1",
                    &hc_key,
                    None,
                );
            }
            if let Some(timeout) = hc.timeout {
                if timeout.is_zero() {
                    self.error(
                        "E305",
                        "health-check 'timeout' must be greater than zero",
                        &hc_key,
                        None,
                    );
                } else if !hc.interval.is_zero() && timeout >= hc.interval {
                    self.error(
                        "E305",
                        "health-check 'timeout' must be strictly less than 'interval'",
                        &hc_key,
                        None,
                    );
                }
            }
        }
        if let Some(utls) = &rp.upstream_tls {
            let utls_key = format!("{r_prefix}.reverse-proxy.upstream-tls");
            if let Some(ca) = &utls.ca_cert {
                self.validate_safe_file_path(ca, &utls_key, "upstream-tls ca-cert");
            }
            self.validate_cert_key_pair(
                utls.client_cert.as_deref(),
                utls.client_key.as_deref(),
                &utls_key,
                &utls_key,
                &utls_key,
            );
        }
        if let Some(connect_tmo) = rp.upstream_connect_timeout {
            let k = format!("{r_prefix}.reverse-proxy.upstream-connect-timeout");
            self.validate_positive_duration(connect_tmo, &k, "upstream-connect-timeout");
            if connect_tmo > Duration::from_secs(120) {
                self.error(
                    "E007",
                    "'upstream-connect-timeout' must not exceed 120s",
                    &k,
                    None,
                );
            }
        }
        if let Some(resp_tmo) = rp.upstream_response_timeout {
            let k = format!("{r_prefix}.reverse-proxy.upstream-response-timeout");
            self.validate_positive_duration(resp_tmo, &k, "upstream-response-timeout");
            if resp_tmo > Duration::from_secs(3_600) {
                self.error(
                    "E007",
                    "'upstream-response-timeout' must not exceed 3600s",
                    &k,
                    None,
                );
            }
        }
        // A probe must test what real requests reach. With `preserve-host` real requests carry
        // the visitor's host over HTTP/1.1, so the probe needs an explicit host to send; without
        // `preserve-host` real requests carry the upstream's own name, so a probe host would
        // make the probe test something else.
        if let Some(hc) = &rp.health_check {
            let k = format!("{r_prefix}.reverse-proxy.health-check");
            match (&hc.host, rp.preserve_host) {
                (None, true) => self.error(
                    "E305",
                    "'health-check' needs 'host=\"<hostname>\"' when 'preserve-host' is on, so probes reach the same virtual host as real requests",
                    &k,
                    Some("add host=\"<one of this site's hostnames>\" to health-check"),
                ),
                (Some(_), false) => self.error(
                    "E305",
                    "'health-check' property 'host' is only valid together with 'preserve-host #true'",
                    &k,
                    None,
                ),
                (Some(h), true) => {
                    let ok = !h.is_empty()
                        && h.len() <= 253
                        && h.bytes().all(|b| {
                            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':')
                        });
                    if !ok {
                        self.error(
                            "E305",
                            "'health-check' property 'host' must be a plain hostname, optionally with a port",
                            &k,
                            None,
                        );
                    }
                }
                (None, false) => {}
            }
        }
        if let Some(idle_tmo) = rp.upstream_body_idle_timeout {
            let k = format!("{r_prefix}.reverse-proxy.upstream-body-idle-timeout");
            self.validate_positive_duration(idle_tmo, &k, "upstream-body-idle-timeout");
            if idle_tmo > Duration::from_hours(24) {
                self.error(
                    "E007",
                    "'upstream-body-idle-timeout' must not exceed 86400s (24h)",
                    &k,
                    None,
                );
            }
        }
    }

    fn validate_rate_limit(&mut self, rl: &RateLimitConfig, key: &str) {
        if rl.requests == 0 {
            self.error(
                "E204",
                "'rate-limit' requests must be greater than zero",
                key,
                None,
            );
        }
        if rl.per.is_zero() {
            self.error(
                "E204",
                "'rate-limit' period ('per') must be greater than zero",
                key,
                None,
            );
        }
        if rl.burst == 0 {
            self.error(
                "E204",
                "'rate-limit' burst must be greater than zero",
                key,
                None,
            );
        }
        if let Some(mult) = rl.ip_ceiling_multiplier
            && (mult == 0 || mult > 10_000)
        {
            self.error(
                "E204",
                "'rate-limit' ip-ceiling-multiplier must be between 1 and 10000",
                key,
                None,
            );
        }
        if let Some(cap) = rl.max_keys_per_ip
            && (cap == 0 || cap > 1_024)
        {
            self.error(
                "E204",
                "'rate-limit' max-keys-per-ip must be between 1 and 1024",
                key,
                Some("keep max-keys-per-ip <= 1024 to bound per-IP rate-limiter memory (R6-DOS-2)"),
            );
        }
    }

    fn validate_positive_duration(&mut self, d: Duration, key: &str, name: &str) {
        if d.is_zero() {
            self.error(
                "E007",
                format!("timeout '{name}' must be greater than zero"),
                key,
                None,
            );
        }
    }

    fn validate_cert_key_pair(
        &mut self,
        cert: Option<&str>,
        key: Option<&str>,
        cert_span_key: &str,
        key_span_key: &str,
        block_span_key: &str,
    ) {
        match (cert, key) {
            (Some(c), Some(k)) => {
                self.validate_safe_file_path(c, cert_span_key, "TLS certificate");
                self.validate_safe_file_path(k, key_span_key, "TLS private key");
            }
            (Some(_), None) => {
                self.error(
                    "E105",
                    "TLS certificate configured without a matching private key",
                    block_span_key,
                    Some("specify both certificate and key paths together"),
                );
            }
            (None, Some(_)) => {
                self.error(
                    "E105",
                    "TLS private key configured without a matching certificate",
                    block_span_key,
                    Some("specify both certificate and key paths together"),
                );
            }
            (None, None) => {}
        }
    }

    fn validate_upstream_url(&mut self, raw: &str, span_key: &str, err_code: &str, label: &str) {
        let Ok(parsed) = Url::parse(raw) else {
            self.error(
                err_code,
                format!("invalid {label} URL '{raw}'"),
                span_key,
                Some("expected a valid https:// or http:// URL (e.g. \"https://10.0.1.20:8443\")"),
            );
            return;
        };

        let scheme = parsed.scheme();
        if scheme != "https" && scheme != "http" {
            self.error(
                err_code,
                format!("unsupported {label} URL scheme '{scheme}' in '{raw}'"),
                span_key,
                Some("use \"https://\" (recommended) or \"http://\" for loopback backends"),
            );
            return;
        }

        let Some(host) = parsed.host_str() else {
            self.error(
                err_code,
                format!("{label} URL '{raw}' must include a host"),
                span_key,
                None,
            );
            return;
        };

        if scheme == "http" && !is_loopback_host(host) {
            self.warn(
                "W005",
                format!("{label} '{raw}' uses unencrypted HTTP to non-loopback host '{host}'"),
                span_key,
                Some("use https:// (optionally with upstream mTLS) to protect backend traffic in transit"),
            );
        }
    }

    fn validate_safe_file_path(&mut self, path: &str, span_key: &str, label: &str) {
        let trimmed = path.trim();
        if path != trimmed {
            return;
        }
        if trimmed.is_empty() {
            self.error(
                "E202",
                format!("{label} path must not be empty"),
                span_key,
                None,
            );
            return;
        }
        if trimmed.contains('\0') {
            self.error(
                "E202",
                format!("{label} path must not contain null bytes"),
                span_key,
                None,
            );
            return;
        }
        if has_parent_traversal(trimmed) {
            self.error(
                "E202",
                format!("{label} path '{path}' contains forbidden '..' parent traversal segment"),
                span_key,
                Some("use an absolute normalized path without '..' segments (Threat Model T5)"),
            );
        }
    }

    fn validate_safe_dir_path(&mut self, path: &str, span_key: &str, label: &str) {
        let trimmed = path.trim();
        if path != trimmed {
            return;
        }
        self.validate_safe_file_path(path, span_key, label);
        if trimmed.is_empty() || trimmed.contains('\0') || has_parent_traversal(trimmed) {
            return;
        }
        // R5-SBX-1: Reject relative directory paths (under systemd cwd `/` a relative path like
        // `"etc/miraserve"` would resolve into `/etc/miraserve`, which holds private keys!).
        if !is_absolute_config_path(trimmed) {
            self.error(
                "E202",
                format!("{label} path '{path}' must be an absolute path"),
                span_key,
                Some("use an absolute directory path such as '/var/www/site' or '/var/lib/miraserve/releases'"),
            );
            return;
        }
        let is_docroot = label != "ai-publish storage";
        match classify_dir_path(trimmed, is_docroot, self.allow_docroots) {
            DirPathVerdict::Allowed => {}
            DirPathVerdict::DefaultDenied => {
                let help = if is_docroot {
                    "move the document root out of /var/lib, /var/log, or /run (e.g. '/var/www/...'), or add an explicit 'allow-docroot \"<dir>\"' exception inside 'server { ... }'"
                } else {
                    "confine release stores to dedicated paths such as '/var/lib/miraserve/releases/<site>'"
                };
                self.error(
                    "E202",
                    format!(
                        "{label} path '{path}' points to a default-denied system state directory"
                    ),
                    span_key,
                    Some(help),
                );
            }
            DirPathVerdict::UnconditionallyForbidden => {
                self.error(
                    "E202",
                    format!("{label} path '{path}' points to a sensitive or overly broad system directory"),
                    span_key,
                    Some("confine document roots to dedicated web directories such as '/var/www/...' and release stores to dedicated paths such as '/var/lib/miraserve/releases/...'"),
                );
            }
        }
    }
}

pub(crate) fn is_absolute_config_path(path: &str) -> bool {
    if path.starts_with('/') {
        return true;
    }
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes.first().is_some_and(u8::is_ascii_alphabetic)
        && bytes.get(1) == Some(&b':')
        && matches!(bytes.get(2), Some(b'/' | b'\\'))
}

/// Checks for `..` path traversal components across both POSIX (`/`) and Windows (`\`) separators.
pub(crate) fn has_parent_traversal(path: &str) -> bool {
    path.split(['/', '\\']).any(|seg| seg == "..")
}

/// Classification of a configured directory path (`site.root`, `route.root`, or
/// `ai-publish.storage`) for Section 5 default-deny docroot confinement (`R5-SBX-1`, `R6-SBX-1`,
/// `R7-SBX-1`, `R7-SBX-2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirPathVerdict {
    /// Directory is permitted (either outside restricted trees or explicitly exempted via `server.allow-docroot`).
    Allowed,
    /// Directory lies under a default-denied state/runtime/log tree (`/var/lib`, `/var/log`, `/run`)
    /// and is refused unless explicitly opened via `server { allow-docroot "..." }`.
    DefaultDenied,
    /// Directory is unconditionally forbidden (filesystem root, single-segment top-level directory,
    /// hidden dot-directory, OS credentials/kernel/config trees, or MiraServe's own config/state/runtime
    /// paths on any prefix) and cannot be exempted even via `allow-docroot`.
    UnconditionallyForbidden,
}

/// Convenience helper returning `true` when [`classify_dir_path`] refuses `path`.
#[must_use]
pub fn is_forbidden_dir_path(path: &str, is_docroot: bool, allow_docroots: &[String]) -> bool {
    !matches!(
        classify_dir_path(path, is_docroot, allow_docroots),
        DirPathVerdict::Allowed
    )
}

fn normalize_dir_segments(path: &str) -> (bool, Vec<String>) {
    let normalized = path.replace('\\', "/");
    let has_leading_slash = normalized.starts_with('/');
    let segs: Vec<String> = normalized
        .split('/')
        .filter(|seg| !seg.is_empty() && *seg != ".")
        .map(str::to_ascii_lowercase)
        .collect();
    (has_leading_slash, segs)
}

fn matches_prefix(lower: &str, prefix: &str) -> bool {
    lower == prefix
        || (lower.len() > prefix.len()
            && lower.starts_with(prefix)
            && lower.as_bytes().get(prefix.len()) == Some(&b'/'))
}

fn has_consecutive_segs(segs: &[String], needle: &[&str]) -> bool {
    if needle.is_empty() || segs.len() < needle.len() {
        return false;
    }
    segs.windows(needle.len())
        .any(|w| w.iter().zip(needle).all(|(a, b)| a == b))
}

fn is_miraserve_own_state_dir(segs: &[String], is_docroot: bool) -> bool {
    // Any prefix containing `.../etc/miraserve` (e.g. `/etc/miraserve`, `/opt/homebrew/etc/miraserve`,
    // `/usr/local/etc/miraserve`, `/private/etc/miraserve`).
    if has_consecutive_segs(segs, &["etc", "miraserve"]) {
        return true;
    }
    // Any prefix containing `.../run/miraserve*` (e.g. `/run/miraserve`, `/run/miraserve-keyd`,
    // `/var/run/miraserve-keyd`, `/private/var/run/miraserve`, `/opt/homebrew/var/run/miraserve`).
    for w in segs.windows(2) {
        if w.first().map(String::as_str) == Some("run")
            && w.get(1).is_some_and(|s| s.starts_with("miraserve"))
        {
            return true;
        }
    }
    // Any prefix containing `.../var/lib/miraserve` (e.g. `/var/lib/miraserve/**`,
    // `/opt/homebrew/var/lib/miraserve/acme`, `/private/var/lib/miraserve/acme`,
    // `/usr/local/var/lib/miraserve/acme`).
    if has_consecutive_segs(segs, &["var", "lib", "miraserve"]) {
        if is_docroot {
            return true;
        }
        // For `ai-publish storage`: forbid the bare `.../var/lib/miraserve` root itself as well
        // as `.../var/lib/miraserve/acme` and `.../var/lib/miraserve/keys`, while allowing
        // dedicated release directories like `/var/lib/miraserve/releases/<site>`.
        if segs.ends_with(&["var".to_owned(), "lib".to_owned(), "miraserve".to_owned()])
            || has_consecutive_segs(segs, &["var", "lib", "miraserve", "acme"])
            || has_consecutive_segs(segs, &["var", "lib", "miraserve", "keys"])
        {
            return true;
        }
    }
    false
}

/// Classifies `path` under MiraServe's Section 5 default-deny docroot confinement policy
/// (`R5-SBX-1`, `R6-SBX-1`, `R7-SBX-1`, `R7-SBX-2`).
///
/// - **Unconditionally forbidden** (never exempted by `allow-docroot`): filesystem root,
///   single-segment top-level directories (`/srv`, `/opt`, `/mnt`, `/data`, `/System`, `/Volumes`,
///   etc.), parent traversal, hidden dot-directory segments, OS config/credential/device/kernel
///   trees (`/etc`, `/root`, `/proc`, `/sys`, `/dev`, `/boot`, `/Library/Keychains`, `/System`,
///   `/usr/lib/ssl`, `/var/spool`, `/var/backups`, `/var/mail`, `/run/secrets`, `/run/credentials`,
///   `/var/run/secrets`, `/home/<user>`), broad shared base dirs (`/var/lib`, `/var/log`, `/run`),
///   and MiraServe's own config/state/runtime trees on ANY prefix (`/var/lib/miraserve/**`,
///   `/opt/homebrew/var/lib/miraserve/**`, `/opt/homebrew/etc/miraserve/**`, `/usr/local/var/lib/miraserve/**`,
///   `/private/var/lib/miraserve/**`, `/run/miraserve*`).
/// - **Default-denied** (overridable via `server { allow-docroot "/var/lib/x" }`): anything else
///   under `/var/lib`, `/var/log`, or `/run` (across `/`, `/private`, `/usr/local`, `/opt/homebrew`),
///   such as `/var/lib/letsencrypt`, `/var/lib/mariadb`, `/var/lib/pgsql`, `/var/lib/php/sessions`,
///   `/var/lib/kubelet`, `/var/log/nginx`, `/run/user/1000`.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn classify_dir_path(
    path: &str,
    is_docroot: bool,
    allow_docroots: &[String],
) -> DirPathVerdict {
    if path.trim().is_empty() || path.contains('\0') {
        return DirPathVerdict::UnconditionallyForbidden;
    }

    let (has_leading_slash, segs) = normalize_dir_segments(path.trim());

    // Unix root "/", "/.", "//"
    if segs.is_empty() {
        return DirPathVerdict::UnconditionallyForbidden;
    }

    // Refuse parent traversal and hidden dot-directory segments (`/.ssh`, `/.gnupg`, `/.aws`, etc.)
    if segs.iter().any(|seg| seg == ".." || seg.starts_with('.')) {
        return DirPathVerdict::UnconditionallyForbidden;
    }

    let canonical = if has_leading_slash {
        format!("/{}", segs.join("/"))
    } else {
        segs.join("/")
    };

    // Windows drive root like "c:" or "c:/"
    let bytes = canonical.as_bytes();
    if bytes.len() == 2
        && bytes.first().is_some_and(u8::is_ascii_alphabetic)
        && bytes.get(1) == Some(&b':')
    {
        return DirPathVerdict::UnconditionallyForbidden;
    }

    // Section 5: Refuse ALL single-segment top-level directories on Unix (`/srv`, `/opt`, `/mnt`,
    // `/data`, `/System`, `/Volumes`, `/var`, `/usr`, `/tmp`, `/run`, `/etc`, `/home`, etc.).
    if has_leading_slash && segs.len() == 1 {
        return DirPathVerdict::UnconditionallyForbidden;
    }

    // Section 5: Unconditionally refuse MiraServe's own state/config/runtime trees on ANY prefix.
    if is_miraserve_own_state_dir(&segs, is_docroot) {
        return DirPathVerdict::UnconditionallyForbidden;
    }

    let unconditionally_forbidden_prefixes = [
        "/etc",
        "/private/etc",
        "/usr/local/etc",
        "/opt/homebrew/etc",
        "/root",
        "/proc",
        "/sys",
        "/dev",
        "/boot",
        "/system",
        "/library/keychains",
        "/var/db",
        "/private/var/db",
        "/usr/lib/ssl",
        "/usr/share/ca-certificates",
        "/var/spool",
        "/private/var/spool",
        "/var/backups",
        "/private/var/backups",
        "/var/mail",
        "/private/var/mail",
        "/run/secrets",
        "/run/credentials",
        "/var/run/secrets",
        "/var/run/credentials",
        "/private/var/run/secrets",
        "/private/var/run/credentials",
        "c:/windows",
        "c:/programdata/microsoft",
    ];
    for prefix in unconditionally_forbidden_prefixes {
        if matches_prefix(&canonical, prefix) {
            return DirPathVerdict::UnconditionallyForbidden;
        }
    }

    let unconditionally_forbidden_exact = [
        "/var/lib",
        "/var/log",
        "/var/run",
        "/var/tmp",
        "/var/cache",
        "/private/var",
        "/private/var/lib",
        "/private/var/log",
        "/private/var/run",
        "/private/tmp",
        "/usr/local",
        "/usr/local/var",
        "/usr/local/var/lib",
        "/usr/local/var/log",
        "/usr/local/var/run",
        "/opt/homebrew",
        "/opt/homebrew/var",
        "/opt/homebrew/var/lib",
        "/opt/homebrew/var/log",
        "/opt/homebrew/var/run",
        "/usr/share",
        "/usr/lib",
        "/usr/bin",
        "/usr/sbin",
    ];
    if unconditionally_forbidden_exact.contains(&canonical.as_str()) {
        return DirPathVerdict::UnconditionallyForbidden;
    }

    if has_leading_slash
        && segs.len() == 2
        && matches!(segs.first().map(String::as_str), Some("home" | "users"))
    {
        return DirPathVerdict::UnconditionallyForbidden;
    }

    // Section 5: Default-deny anything under `/var/lib`, `/var/log`, `/run`, or `/var/run`
    // (across Linux, macOS `/private`, `/usr/local`, and Homebrew `/opt/homebrew` prefixes).
    let default_denied_trees = [
        "/var/lib",
        "/private/var/lib",
        "/usr/local/var/lib",
        "/opt/homebrew/var/lib",
        "/var/log",
        "/private/var/log",
        "/usr/local/var/log",
        "/opt/homebrew/var/log",
        "/run",
        "/var/run",
        "/private/var/run",
        "/usr/local/var/run",
        "/opt/homebrew/var/run",
    ];
    let in_default_denied_tree = default_denied_trees
        .iter()
        .any(|tree| matches_prefix(&canonical, tree));

    if in_default_denied_tree {
        // Dedicated `ai-publish storage` under `.../var/lib/miraserve/<subdir>` (already filtered
        // against bare `.../var/lib/miraserve`, `acme`, and `keys` above!) is permitted by default.
        if !is_docroot && has_consecutive_segs(&segs, &["var", "lib", "miraserve"]) {
            return DirPathVerdict::Allowed;
        }
        // Check explicit `server { allow-docroot "..." }` exceptions for HTTP docroots!
        if is_docroot && matches_allow_docroots(&canonical, allow_docroots) {
            return DirPathVerdict::Allowed;
        }
        return DirPathVerdict::DefaultDenied;
    }

    DirPathVerdict::Allowed
}

fn matches_allow_docroots(canonical_lower: &str, allow_docroots: &[String]) -> bool {
    let macos_unprefixed = canonical_lower.strip_prefix("/private");
    for raw in allow_docroots {
        let trimmed = raw.trim();
        if trimmed.is_empty()
            || !is_absolute_config_path(trimmed)
            || matches!(
                classify_dir_path(trimmed, true, &[]),
                DirPathVerdict::UnconditionallyForbidden
            )
        {
            continue;
        }
        let (has_slash, segs) = normalize_dir_segments(trimmed);
        let allowed_norm = if has_slash {
            format!("/{}", segs.join("/"))
        } else {
            segs.join("/")
        };
        if matches_prefix(canonical_lower, &allowed_norm) {
            return true;
        }
        if let Some(unprefixed) = macos_unprefixed
            && matches_prefix(unprefixed, &allowed_norm)
        {
            return true;
        }
    }
    false
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    IpAddr::from_str(bare).is_ok_and(|ip| ip.is_loopback())
}

fn is_valid_email(email: &str) -> bool {
    if email.is_empty() || email.chars().any(char::is_whitespace) {
        return false;
    }
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && !domain.contains('@')
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
}

fn is_valid_os_identity(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

struct StackAscii<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> StackAscii<N> {
    const fn new() -> Self {
        Self {
            buf: [0; N],
            len: 0,
        }
    }

    fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(self.buf.get(..self.len)?).ok()
    }
}

impl<const N: usize> std::fmt::Write for StackAscii<N> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let bytes = s.as_bytes();
        let end = self.len.checked_add(bytes.len()).ok_or(std::fmt::Error)?;
        let dst = self.buf.get_mut(self.len..end).ok_or(std::fmt::Error)?;
        dst.copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
}

/// Canonicalizes a configured site hostname or incoming request host for matching and
/// deduplication: lowercases DNS names and canonicalizes bare or bracketed IPv6 literals
/// (e.g. `"[2001:DB8:0:0::1]"` and `"2001:db8::1"` both become `"2001:db8::1"`).
///
/// Borrows directly from `host` when the trimmed (or unbracketed IPv6) slice is already
/// canonical, avoiding heap allocation on the common lowercase request path.
#[must_use]
pub fn normalize_site_host(host: &str) -> Cow<'_, str> {
    let trimmed = host.trim();
    let unbracketed = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(trimmed);
    if unbracketed.as_bytes().contains(&b':')
        && let Ok(v6) = std::net::Ipv6Addr::from_str(unbracketed)
    {
        use std::fmt::Write as _;

        let mut buf = StackAscii::<45>::new();
        if write!(buf, "{v6}").is_ok()
            && let Some(formatted) = buf.as_str()
        {
            if unbracketed == formatted {
                return Cow::Borrowed(unbracketed);
            }
            return Cow::Owned(formatted.to_owned());
        }
        return Cow::Owned(v6.to_string());
    }
    if !trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
        return Cow::Borrowed(trimmed);
    }
    Cow::Owned(trimmed.to_ascii_lowercase())
}

fn is_valid_site_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || host.chars().any(char::is_whitespace) {
        return false;
    }
    if host.contains("://") || host.contains('/') {
        return false;
    }
    // Accept bare (`::1`, `2001:db8::1`) or bracketed (`[::1]`, `[2001:db8::1]`) IPv6 literals
    // while still rejecting host:port strings, wildcard IPs, and invalid brackets (HANDOVER §5 #11).
    if let Some(inner) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return std::net::Ipv6Addr::from_str(inner).is_ok();
    }
    if std::net::Ipv6Addr::from_str(host).is_ok() {
        return true;
    }
    if host.contains(':') || host.contains('[') || host.contains(']') {
        return false;
    }
    let check_part = host.strip_prefix("*.").unwrap_or(host);
    if check_part.is_empty() || check_part.contains('*') {
        return false;
    }

    if IpAddr::from_str(check_part).is_ok() {
        return true;
    }

    let mut label_count = 0_usize;
    for label in check_part.split('.') {
        label_count = label_count.saturating_add(1);
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return false;
        }
    }

    label_count >= 1
}

fn is_valid_route_pattern(pattern: &str) -> bool {
    if pattern.is_empty() || pattern.chars().any(char::is_whitespace) || pattern.contains('\0') {
        return false;
    }
    if let Some(ext) = pattern.strip_prefix("*.") {
        return !ext.is_empty()
            && !ext.contains('/')
            && !ext.contains('*')
            && ext.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.');
    }
    if !pattern.starts_with('/') {
        return false;
    }
    if pattern == "/*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return !prefix.contains('*');
    }
    !pattern.contains('*')
}

/// Returns `true` if `earlier` completely shadows `later` during first-match route evaluation.
fn route_pattern_shadows(earlier: &str, later: &str) -> bool {
    if earlier == "/*" {
        return true;
    }
    if let Some(earlier_prefix) = earlier.strip_suffix("/*") {
        if let Some(later_prefix) = later.strip_suffix("/*") {
            return later_prefix == earlier_prefix
                || later_prefix.starts_with(&format!("{earlier_prefix}/"));
        }
        if later.starts_with('/') {
            return later == earlier_prefix || later.starts_with(&format!("{earlier_prefix}/"));
        }
    }
    false
}

/// Canonicalizes existing ancestor symlinks and normalizes a configured storage directory path
/// (with ASCII case-folding) for cross-site uniqueness and nesting checks (`R5-PUB-5`).
fn normalize_storage_path_key(raw: &str) -> String {
    use std::path::{Component, Path, PathBuf};

    let original = Path::new(raw.trim());
    let mut existing = original.to_path_buf();
    let mut missing_tail: Vec<std::ffi::OsString> = Vec::new();
    while !existing.exists() {
        let Some(name) = existing.file_name() else {
            break;
        };
        missing_tail.push(name.to_os_string());
        if !existing.pop() {
            break;
        }
    }
    let resolved: PathBuf = if existing.exists()
        && let Ok(canon) = std::fs::canonicalize(&existing)
    {
        let mut combined = canon;
        for seg in missing_tail.into_iter().rev() {
            combined.push(seg);
        }
        combined
    } else {
        original.to_path_buf()
    };

    let mut parts: Vec<String> = Vec::new();
    let mut has_root = false;
    for comp in resolved.components() {
        match comp {
            Component::RootDir => has_root = true,
            Component::CurDir => {}
            Component::Normal(seg) => {
                parts.push(seg.to_string_lossy().to_ascii_lowercase());
            }
            Component::Prefix(p) => {
                let s = p.as_os_str().to_string_lossy();
                let stripped = s.strip_prefix(r"\\?\").unwrap_or(&s);
                parts.push(stripped.to_ascii_lowercase());
            }
            Component::ParentDir => parts.push("..".to_owned()),
        }
    }
    if has_root {
        format!("/{}", parts.join("/"))
    } else {
        parts.join("/")
    }
}

/// [`normalize_storage_path_key`] without following any link: the path as written.
fn lexical_path_key(raw: &str) -> String {
    use std::path::{Component, Path};
    let mut parts: Vec<String> = Vec::new();
    let mut has_root = false;
    for comp in Path::new(raw.trim()).components() {
        match comp {
            Component::RootDir => has_root = true,
            Component::CurDir => {}
            Component::ParentDir => {
                parts.pop();
            }
            // Names differ by case only on case-insensitive Windows paths; elsewhere `/srv/Store`
            // and `/srv/store` are different directories.
            Component::Normal(seg) => parts.push(if cfg!(windows) {
                seg.to_string_lossy().to_ascii_lowercase()
            } else {
                seg.to_string_lossy().into_owned()
            }),
            Component::Prefix(p) => {
                // Strip Windows verbatim prefix `\\?\` (matching `normalize_storage_path_key`) so
                // canonicalized and non-canonicalized Windows paths compare consistently.
                let s = p.as_os_str().to_string_lossy();
                let stripped = s.strip_prefix(r"\\?\").unwrap_or(&s);
                parts.push(stripped.to_ascii_lowercase());
            }
        }
    }
    if has_root {
        format!("/{}", parts.join("/"))
    } else {
        parts.join("/")
    }
}

/// Returns `true` when two normalized storage directory keys are identical OR one is nested
/// inside the other (`a` vs `a/releases`, `R5-PUB-5`).
fn storage_paths_overlap(a: &str, b: &str) -> bool {
    let a = a.trim_end_matches('/');
    let b = b.trim_end_matches('/');
    if a.is_empty() || b.is_empty() {
        return a == b;
    }
    a == b
        || a.strip_prefix(b).is_some_and(|rest| rest.starts_with('/'))
        || b.strip_prefix(a).is_some_and(|rest| rest.starts_with('/'))
}

/// Returns `true` when `root_raw` equals or is an ancestor of `cfg_dir` (`R7-CFG-1`), which
/// would expose the loaded `.kdl` configuration file itself over HTTP.
fn docroot_contains_config_dir(root_raw: &str, cfg_dir: &std::path::Path) -> bool {
    // The root is compared as written (relative roots are relative to the configuration
    // directory): links under a document root may be tenant-controlled, and the load-time
    // checks resolve them and quarantine just that site (503).
    let root_path = std::path::Path::new(root_raw.trim());
    let root_key = if root_path.is_absolute() {
        lexical_path_key(root_raw)
    } else {
        lexical_path_key(&cfg_dir.join(root_path).to_string_lossy())
    };
    let root_trim = root_key.trim_end_matches('/');
    if root_trim.is_empty() {
        return false;
    }
    [
        lexical_path_key(&cfg_dir.to_string_lossy()),
        normalize_storage_path_key(&cfg_dir.to_string_lossy()),
    ]
    .iter()
    .any(|cfg_key| {
        let cfg_trim = cfg_key.trim_end_matches('/');
        !cfg_trim.is_empty()
            && (cfg_trim == root_trim
                || cfg_trim
                    .strip_prefix(root_trim)
                    .is_some_and(|rest| rest.starts_with('/')))
    })
}

fn is_private_non_loopback_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        std::net::IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                mapped.is_private() || mapped.is_link_local()
            } else {
                let seg0 = v6.segments()[0];
                // ULA fc00::/7 or link-local fe80::/10
                (seg0 & 0xFE00) == 0xFC00 || (seg0 & 0xFFC0) == 0xFE80
            }
        }
    }
}

fn merged_u64_interval_coverage(ranges: &mut [(u64, u64)]) -> u64 {
    if ranges.is_empty() {
        return 0;
    }
    ranges.sort_unstable();
    let mut total: u64 = 0;
    let Some(&(mut cur_start, mut cur_end)) = ranges.first() else {
        return 0;
    };
    for &(start, end) in ranges.iter().skip(1) {
        if start <= cur_end.saturating_add(1) {
            cur_end = cur_end.max(end);
        } else {
            total = total.saturating_add(cur_end.saturating_sub(cur_start).saturating_add(1));
            cur_start = start;
            cur_end = end;
        }
    }
    total.saturating_add(cur_end.saturating_sub(cur_start).saturating_add(1))
}

fn merged_u128_interval_coverage(ranges: &mut [(u128, u128)]) -> u128 {
    if ranges.is_empty() {
        return 0;
    }
    ranges.sort_unstable();
    let mut total: u128 = 0;
    let Some(&(mut cur_start, mut cur_end)) = ranges.first() else {
        return 0;
    };
    for &(start, end) in ranges.iter().skip(1) {
        if start <= cur_end.saturating_add(1) {
            cur_end = cur_end.max(end);
        } else {
            total = total.saturating_add(cur_end.saturating_sub(cur_start).saturating_add(1));
            cur_start = start;
            cur_end = end;
        }
    }
    total.saturating_add(cur_end.saturating_sub(cur_start).saturating_add(1))
}

/// Directories a sandbox `read-tree` / `socket-tree` must never equal, contain or sit inside:
/// system configuration and secrets, kernel interfaces, and MiraServe's own state.
const SANDBOX_TREE_FORBIDDEN: &[&str] = &[
    "/etc",
    "/root",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    "/var/lib/miraserve",
    "/var/backups",
    "/var/mail",
    "/var/spool",
    "/run/miraserve",
    "/run/miraserve-keyd",
    "/run/secrets",
    "/run/credentials",
    "/usr/local/etc",
    "/opt/homebrew/etc",
    "/Library/Keychains",
];

/// Returns why `raw` may not be granted to the worker as a whole directory tree, or `None`.
///
/// A tree is a much wider grant than a document root, so the rule is strict: an absolute,
/// already-normalised path, never the filesystem root, and never equal to, an ancestor of, or
/// inside one of the directories in `SANDBOX_TREE_FORBIDDEN`. `/var` and `/run` are therefore rejected (they
/// contain forbidden directories) while `/home`, `/var/www`, `/srv/www` and `/run/php` pass.
#[must_use]
pub fn sandbox_tree_rejection(raw: &str) -> Option<&'static str> {
    if !raw.starts_with('/') {
        return Some("it must be an absolute path");
    }
    if raw.contains('\\') || raw.bytes().any(|b| b.is_ascii_control()) {
        return Some("it contains a backslash or control character");
    }
    let trimmed = raw.trim_end_matches('/');
    if trimmed.is_empty() {
        return Some("the filesystem root cannot be granted");
    }
    if trimmed
        .split('/')
        .skip(1)
        .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return Some("it must not contain empty, '.' or '..' segments");
    }
    // macOS: `/etc`, `/var` and `/tmp` are symlinks into `/private`.
    let logical = trimmed.strip_prefix("/private").unwrap_or(trimmed);
    let logical = if logical.is_empty() { "/" } else { logical };
    let lower = logical.to_ascii_lowercase();
    let within = |child: &str, parent: &str| {
        child == parent
            || child
                .strip_prefix(parent)
                .is_some_and(|rest| rest.starts_with('/'))
    };
    for forbidden in SANDBOX_TREE_FORBIDDEN {
        let f = forbidden.to_ascii_lowercase();
        if within(&lower, &f) {
            return Some("it is inside a system, secret or MiraServe state directory");
        }
        if within(&f, &lower) {
            return Some("it contains a system, secret or MiraServe state directory");
        }
    }
    None
}

/// The header RFC 9110 requires on a response with this status, when a `respond` route cannot
/// provide it (`401` challenge, `405` method list, `407` proxy challenge, `426` protocol list).
const fn respond_status_required_header(status: u16) -> Option<&'static str> {
    match status {
        401 => Some("WWW-Authenticate"),
        405 => Some("Allow"),
        407 => Some("Proxy-Authenticate"),
        426 => Some("Upgrade"),
        _ => None,
    }
}

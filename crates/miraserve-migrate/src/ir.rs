//! Intermediate representation and MiraServe KDL v2 renderer shared by all config importers.

use std::collections::HashSet;
use std::fmt::Write as _;

use serde::Serialize;

/// Supported legacy server configuration formats for `miraserve import`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceFormat {
    /// Automatically detect format from syntax heuristics.
    Auto,
    /// Nginx `nginx.conf` / `sites-enabled/*.conf`.
    Nginx,
    /// Caddy `Caddyfile`.
    Caddy,
    /// Apache HTTP Server `<VirtualHost>` configuration.
    Apache,
    /// OpenLiteSpeed `vhconf.conf` / `httpd_config.conf`.
    OpenLiteSpeed,
}

impl std::fmt::Display for SourceFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => f.write_str("auto"),
            Self::Nginx => f.write_str("nginx"),
            Self::Caddy => f.write_str("caddy"),
            Self::Apache => f.write_str("apache"),
            Self::OpenLiteSpeed => f.write_str("openlitespeed"),
        }
    }
}

/// Informational, manual-review, or security-downgrade note emitted during migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MigrationNote {
    /// Optional included source file name when this diagnostic came from an expanded include (`R6-MIG-11`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Optional 1-based line number in the legacy config file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    /// Legacy directive or construct name.
    pub directive: String,
    /// Explanation of how it was handled or what needs manual review.
    pub message: String,
}

/// Strips ASCII control characters (including ANSI escapes, `\r`, `\n`, `\0`), Unicode line
/// separators (`U+0085`, `U+2028`, `U+2029`), and Unicode bidirectional control characters from
/// untrusted source-config text before placing it into KDL comments, terminal diagnostics, or
/// JSON reports (`R6-MIG-1`, `R6-MIG-10`).
#[must_use]
pub(crate) fn sanitize_diagnostic_text(raw: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(raw.len().min(max_chars));
    let mut prev_space = true;
    let mut count = 0_usize;
    let mut chars = raw.chars().peekable();
    while let Some(ch) = chars.next() {
        // Strip full ANSI CSI (`ESC [` ... final byte) and OSC (`ESC ]` ... BEL/ST) escape sequences
        // so terminal escape codes never reach stdout/stderr or logs (`R6-MIG-10`).
        if ch == '\x1b' {
            if matches!(chars.peek(), Some('[')) {
                chars.next();
                for seq_ch in chars.by_ref() {
                    if ('@'..='~').contains(&seq_ch) {
                        break;
                    }
                }
            } else if matches!(chars.peek(), Some(']')) {
                chars.next();
                for seq_ch in chars.by_ref() {
                    if seq_ch == '\x07' || seq_ch == '\\' {
                        break;
                    }
                }
            }
            continue;
        }
        let forbidden = ch.is_control()
            || matches!(
                ch,
                '\u{0085}'
                    | '\u{2028}'
                    | '\u{2029}'
                    | '\u{200E}'
                    | '\u{200F}'
                    | '\u{202A}'..='\u{202E}'
                    | '\u{2066}'..='\u{2069}'
            );
        if forbidden || ch.is_whitespace() {
            if !prev_space && count < max_chars {
                out.push(' ');
                count += 1;
                prev_space = true;
            }
        } else {
            if count >= max_chars {
                break;
            }
            out.push(ch);
            count += 1;
            prev_space = false;
        }
    }
    while out.ends_with(' ') {
        out.pop();
    }
    out
}

/// Sanitizes an arbitrary legacy directive token for diagnostic reporting (`R6-MIG-10`).
#[must_use]
pub(crate) fn sanitize_directive_label(raw: &str) -> String {
    let cleaned = sanitize_diagnostic_text(raw, 64);
    if cleaned.is_empty() {
        "<directive>".to_owned()
    } else {
        cleaned
    }
}

/// Strictly validates an untrusted directive token before echoing it in "manual review" notes so
/// non-config files (e.g. `/etc/shadow` password hash lines or PEM keys) are NEVER echoed into
/// diagnostics (`R6-MIG-10`).
#[must_use]
pub(crate) fn sanitize_untrusted_directive_token(raw: &str) -> String {
    if !raw.is_empty()
        && raw.len() <= 48
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'@'))
    {
        raw.to_owned()
    } else {
        "<non-directive>".to_owned()
    }
}

/// Full output returned by [`crate::migrate_str`] and [`crate::migrate_file`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MigrationReport {
    /// Detected (or explicitly chosen) source configuration format.
    pub source_format: SourceFormat,
    /// Generated MiraServe KDL v2 configuration text (pre-validated by `miraserve-config`).
    pub kdl: String,
    /// Number of sites extracted into `site { ... }` blocks.
    pub migrated_sites: usize,
    /// Number of routes extracted across all sites.
    pub migrated_routes: usize,
    /// Automatic security upgrades applied during migration.
    pub security_upgrades: Vec<String>,
    /// Security controls (auth, ACLs, rate limits, mTLS, deny rules) present in the source
    /// config that could not be automatically translated; affected routes/sites are withheld
    /// unless `--allow-insecure` is explicitly passed (`MIG-2`, `MIG-3`, `R4-MIG-2`).
    pub security_downgrades: Vec<MigrationNote>,
    /// Site hostnames that had site-wide security blockers and were STILL emitted into `kdl`
    /// because `--allow-insecure` was enabled (`R4-MIG-2`; empty when fail-closed).
    pub insecure_sites_emitted: Vec<String>,
    /// Manual review items or unsupported legacy directives encountered.
    pub notes: Vec<MigrationNote>,
    /// Non-fatal `miraserve-config` validation warnings on the generated KDL.
    pub validation_warnings: Vec<String>,
}

#[derive(Debug, Default)]
pub(crate) struct MigratedDoc {
    /// Explicit HTTPS listener bind addresses (e.g. `"127.0.0.1:8443"`, `":443"`).
    /// Empty means default `":443"`.
    pub(crate) https_binds: Vec<String>,
    /// O(1) deduplication set for `https_binds` (`R5-MIG-8`).
    https_binds_set: HashSet<String>,
    /// Explicit HTTP->HTTPS redirect listener bind addresses (e.g. `":80"`, `"127.0.0.1:8080"`).
    pub(crate) http_binds: Vec<String>,
    /// O(1) deduplication set for `http_binds` (`R5-MIG-8`).
    http_binds_set: HashSet<String>,
    /// Whether to emit an HTTP->HTTPS redirect listener when no explicit bind conflicts.
    pub(crate) redirect_http: bool,
    pub(crate) acme_email: Option<String>,
    pub(crate) sites: Vec<MigratedSite>,
    pub(crate) security_upgrades: Vec<String>,
    /// O(1) deduplication set for `security_upgrades` (`R5-MIG-8`).
    security_upgrades_set: HashSet<String>,
    pub(crate) security_downgrades: Vec<MigrationNote>,
    pub(crate) notes: Vec<MigrationNote>,
    /// Active included file name pushed while expanding local includes (`R6-MIG-11`).
    pub(crate) current_source_file: Option<String>,
    /// Fatal safety-limit error (e.g. Caddy snippet expansion cap, `R7-MIG-8`, `R7-MIG-17`) that
    /// MUST abort migration cleanly instead of silently truncating trailing sites.
    pub(crate) fatal_error: Option<String>,
}

#[derive(Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct MigratedSite {
    pub(crate) hosts: Vec<String>,
    pub(crate) root: Option<String>,
    pub(crate) wordpress: bool,
    pub(crate) compat_tls_1_2: bool,
    pub(crate) cert: Option<String>,
    pub(crate) key: Option<String>,
    pub(crate) routes: Vec<MigratedRoute>,
    /// Per-site HTTPS listener bind addresses declared on this site (`R3-MIG-4`).
    pub(crate) https_binds: Vec<String>,
    https_binds_set: HashSet<String>,
    /// Per-site HTTP listener bind addresses declared on this site (`R3-MIG-4`).
    pub(crate) http_binds: Vec<String>,
    http_binds_set: HashSet<String>,
    /// Location/route patterns on this site that had untranslatable security controls (`R5-MIG-4`).
    /// Any emitted route OR static `root` overlapping one of these patterns is withheld (or
    /// tagged `// INSECURE:` under `--allow-insecure`).
    pub(crate) blocked_locations: Vec<(String, Option<usize>, String)>,
    /// URL prefixes whose source behaviour (a redirect, an alias, a rewrite) is not migrated
    /// and which must not fall through to another route or the document root (`R8-MIG-7`,
    /// `R8-MIG-8`). `finalize_doc_with_options` closes each with an explicit 404 route when
    /// the site has a document root, and otherwise treats it as a blocked location.
    pub(crate) closed_prefixes: Vec<(String, Option<usize>, String)>,
    /// Set when the source only serves files where a file-serving directive says so (Caddy:
    /// `root` alone serves nothing). MiraServe serves every unmatched path from `root`, so unless
    /// `static_fallback_confirmed` is also set, `finalize_doc_with_options` closes that fallback
    /// with a catch-all 404 route.
    pub(crate) static_fallback_must_be_confirmed: bool,
    /// Set by a site-wide file-serving directive (Caddy site-level `file_server`).
    pub(crate) static_fallback_confirmed: bool,
    /// Line of a site-wide directive whose translation returns file contents (`try-files`
    /// candidates) although the source directive only rewrites: Caddy `php_fastcgi` and
    /// `try_files`. Without `static_fallback_confirmed` the site is withheld.
    pub(crate) file_content_needs_file_server: Option<usize>,
    /// Explicit Apache `ProxyPreserveHost` setting of this virtual host (`None` = inherit the
    /// server-wide setting). Applied to the site's reverse-proxy routes when parsing ends.
    pub(crate) proxy_preserve_host: Option<bool>,
    /// Line of a matcher-less redirect/rewrite that applies to every request of this site
    /// block (`R8-MIG-7`). Harmless on a redirect-only site block; a blocker when the same
    /// block also defines content, because that content was never reachable in the source.
    pub(crate) whole_site_redirect: Option<(Option<usize>, String)>,
    /// Set when a site-wide auth/ACL/mTLS directive cannot be translated; prevents emitting
    /// any routes or static root open unless `allow_insecure` is set (`MIG-2`, `MIG-3`).
    pub(crate) site_wide_auth_blocked: bool,
    /// Human-readable directive/line tags explaining why `site_wide_auth_blocked` was set
    /// (rendered as `// INSECURE: emitted despite ...` when `--allow-insecure` emits it, `R4-MIG-2`).
    pub(crate) insecure_reasons: Vec<String>,
    insecure_reasons_set: HashSet<String>,
    /// Set to `true` by `finalize_doc_with_options` when a blocked site was actually emitted
    /// under `allow_insecure` (`R4-MIG-2`).
    pub(crate) emitted_insecure: bool,
}

impl MigratedSite {
    pub(crate) fn push_insecure_reason(&mut self, reason: impl Into<String>) {
        // R6-MIG-1: Strictly strip all newlines, control chars, and Unicode line breaks so
        // untrusted source text can NEVER break out of a `// INSECURE:` KDL comment!
        let r = sanitize_diagnostic_text(&reason.into(), 160);
        if !r.is_empty() && self.insecure_reasons_set.insert(r.clone()) {
            self.insecure_reasons.push(r);
        }
    }

    pub(crate) fn block_site(&mut self, line: Option<usize>, directive: &str) {
        self.site_wide_auth_blocked = true;
        let clean_dir = sanitize_directive_label(directive);
        let tag = match line {
            Some(l) => format!("{clean_dir} (line {l})"),
            None => clean_dir,
        };
        self.push_insecure_reason(tag);
    }

    /// Records a location/route-scoped security blocker (`R5-MIG-4`) so `finalize_doc_with_options`
    /// can block overlapping catch-all/prefix/extension routes AND static `root` fallback.
    pub(crate) fn add_blocked_location(
        &mut self,
        pattern: String,
        line: Option<usize>,
        directive: &str,
    ) {
        self.blocked_locations
            .push((pattern, line, directive.to_owned()));
    }

    pub(crate) fn add_https_bind(&mut self, bind: String) {
        if self.https_binds_set.insert(bind.clone()) {
            self.https_binds.push(bind);
        }
    }

    pub(crate) fn add_http_bind(&mut self, bind: String) {
        if self.http_binds_set.insert(bind.clone()) {
            self.http_binds.push(bind);
        }
    }

    /// Returns `true` when this site declared explicit binds and ALL of them are scoped
    /// (loopback or specific non-wildcard interface IPs, `R3-MIG-4`).
    pub(crate) fn is_exclusively_scoped(&self) -> bool {
        let total = self.https_binds.len().saturating_add(self.http_binds.len());
        total > 0
            && self.https_binds.iter().all(|b| is_scoped_bind(b))
            && self.http_binds.iter().all(|b| is_scoped_bind(b))
    }

    /// Returns `true` when this site is publicly exposed (either no explicit binds, defaulting to
    /// public `:443`, or at least one non-scoped wildcard bind like `:443` / `0.0.0.0:443`).
    pub(crate) fn is_public_site(&self) -> bool {
        let total = self.https_binds.len().saturating_add(self.http_binds.len());
        total == 0
            || self.https_binds.iter().any(|b| !is_scoped_bind(b))
            || self.http_binds.iter().any(|b| !is_scoped_bind(b))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MigratedRoute {
    pub(crate) pattern: String,
    pub(crate) handler: MigratedHandler,
    /// Set for Nginx `location ^~ /prefix/` preferential prefix routes (`R7-MIG-3`), which MUST
    /// sort BEFORE regex/extension routes (`*.php`) so `/files/x.php` stays matched by `/files/*`.
    pub(crate) preferential_prefix: bool,
}

impl MigratedRoute {
    pub(crate) const fn new(pattern: String, handler: MigratedHandler) -> Self {
        Self {
            pattern,
            handler,
            preferential_prefix: false,
        }
    }

    pub(crate) const fn with_preferential_prefix(mut self, preferential: bool) -> Self {
        self.preferential_prefix = preferential;
        self
    }
}

#[derive(Debug, Clone)]
pub(crate) enum MigratedHandler {
    ReverseProxy {
        upstreams: Vec<String>,
        /// Emit `preserve-host #true`: the source forwarded the client's own `Host`.
        preserve_host: bool,
        /// `false` emits `allow-upgrades #false`: the source did not tunnel WebSocket upgrades
        /// on this route, so the migrated route must not start to.
        allow_upgrades: bool,
    },
    FastCgi {
        target: String,
    },
    TryFiles {
        candidates: Vec<String>,
    },
    Static,
}

impl MigratedDoc {
    pub(crate) fn new() -> Self {
        let default_upgrades = vec![
            "Enforced TLS 1.3 default with X25519MLKEM768 post-quantum hybrid key exchange"
                .to_owned(),
            "Enabled HTTP/3 + HTTP/2 + HTTP/1.1 listener defaults and strict security headers"
                .to_owned(),
            "Enabled Linux Landlock LSM and seccomp-bpf worker sandboxing defaults".to_owned(),
        ];
        let security_upgrades_set: HashSet<String> = default_upgrades.iter().cloned().collect();
        Self {
            https_binds: Vec::new(),
            https_binds_set: HashSet::new(),
            http_binds: Vec::new(),
            http_binds_set: HashSet::new(),
            redirect_http: true,
            acme_email: None,
            sites: Vec::new(),
            security_upgrades: default_upgrades,
            security_upgrades_set,
            security_downgrades: Vec::new(),
            notes: Vec::new(),
            current_source_file: None,
            fatal_error: None,
        }
    }

    pub(crate) fn set_source_file(&mut self, file: Option<String>) -> Option<String> {
        let clean = file.map(|f| sanitize_diagnostic_text(&f, 160));
        std::mem::replace(&mut self.current_source_file, clean)
    }

    pub(crate) fn add_https_bind(&mut self, bind: String) {
        if self.https_binds_set.insert(bind.clone()) {
            self.https_binds.push(bind);
        }
    }

    pub(crate) fn add_http_bind(&mut self, bind: String) {
        if self.http_binds_set.insert(bind.clone()) {
            self.http_binds.push(bind);
        }
    }

    pub(crate) fn push_upgrade(&mut self, msg: impl Into<String>) {
        let s = sanitize_diagnostic_text(&msg.into(), 512);
        if !s.is_empty() && self.security_upgrades_set.insert(s.clone()) {
            self.security_upgrades.push(s);
        }
    }

    pub(crate) fn push_security_downgrade(
        &mut self,
        line: Option<usize>,
        directive: impl Into<String>,
        message: impl Into<String>,
    ) {
        self.security_downgrades.push(MigrationNote {
            file: self.current_source_file.clone(),
            line,
            directive: sanitize_directive_label(&directive.into()),
            message: sanitize_diagnostic_text(&message.into(), 512),
        });
    }

    pub(crate) fn push_note(
        &mut self,
        line: Option<usize>,
        directive: impl Into<String>,
        message: impl Into<String>,
    ) {
        self.notes.push(MigrationNote {
            file: self.current_source_file.clone(),
            line,
            directive: sanitize_directive_label(&directive.into()),
            message: sanitize_diagnostic_text(&message.into(), 512),
        });
    }
}

/// Returns `true` if a normalized bind string targets loopback or a specific non-wildcard IP.
#[must_use]
pub(crate) fn is_scoped_bind(bind: &str) -> bool {
    !bind.starts_with(':') && !bind.starts_with("0.0.0.0:") && !bind.starts_with("[::]:")
}

/// Normalizes a legacy host:port / port / bare-IP listener into a MiraServe `BindAddr` string,
/// preserving explicit loopback or interface IPs so internal listeners never become public
/// (`MIG-4`, `R2-MIG-3`, `R3-MIG-8`), supplying `default_port` when `raw` is a bare IP address.
#[must_use]
pub(crate) fn normalize_bind_addr_with_default_port(
    raw: &str,
    default_port: u16,
) -> Option<(String, u16)> {
    let clean = raw.trim().trim_end_matches(';').trim_matches('"');
    if clean.is_empty() {
        return None;
    }

    // Bare port number (e.g. `443` or `80`)
    if let Ok(port) = clean.parse::<u16>() {
        return (port > 0).then(|| (format!(":{port}"), port));
    }

    // Wildcard bare tokens (`*` or Apache `_default_`) (`R5-MIG-7`)
    if (clean == "*" || clean.eq_ignore_ascii_case("_default_")) && default_port > 0 {
        return Some((format!(":{default_port}"), default_port));
    }

    // IPv6 bracketed form `[::1]:8443`, `[::]:443`, or OpenLiteSpeed `[ANY]:443` / `[*]:443` (`R3-MIG-8`)
    if let Some(rest) = clean.strip_prefix('[')
        && let Some((host, port_str)) = rest.split_once("]:")
        && let Ok(port) = port_str.parse::<u16>()
        && port > 0
    {
        let normalized = if host == "::" || host == "*" || host.eq_ignore_ascii_case("any") {
            format!(":{port}")
        } else if host.parse::<std::net::IpAddr>().is_ok() {
            format!("[{host}]:{port}")
        } else {
            return None;
        };
        return Some((normalized, port));
    }

    // Bare bracketed IPv6 `[::1]` or `[ANY]` without port
    if let Some(host) = clean.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
        && default_port > 0
    {
        if host == "::" || host == "*" || host.eq_ignore_ascii_case("any") {
            return Some((format!(":{default_port}"), default_port));
        }
        if host.parse::<std::net::IpAddr>().is_ok() {
            return Some((format!("[{host}]:{default_port}"), default_port));
        }
        return None;
    }

    // Bare IP address without port (`127.0.0.1`, `::1`, `localhost`) (`R2-MIG-3`)
    if clean == "localhost" && default_port > 0 {
        return Some((format!("127.0.0.1:{default_port}"), default_port));
    }
    if clean.parse::<std::net::IpAddr>().is_ok() && default_port > 0 {
        let normalized = if clean == "0.0.0.0" || clean == "::" {
            format!(":{default_port}")
        } else if clean.contains(':') {
            format!("[{clean}]:{default_port}")
        } else {
            format!("{clean}:{default_port}")
        };
        return Some((normalized, default_port));
    }

    // Host:port (`127.0.0.1:8443`, `*:443`, `_default_:443`, `0.0.0.0:443`, `localhost:8443`, `:8443`)
    if let Some((host, port_str)) = clean.rsplit_once(':')
        && let Ok(port) = port_str.parse::<u16>()
        && port > 0
    {
        let normalized = match host {
            "" | "*" | "0.0.0.0" | "::" => format!(":{port}"),
            h if h.eq_ignore_ascii_case("_default_") => format!(":{port}"),
            "localhost" => format!("127.0.0.1:{port}"),
            other if other.parse::<std::net::IpAddr>().is_ok() => {
                if other.contains(':') {
                    format!("[{other}]:{port}")
                } else {
                    format!("{other}:{port}")
                }
            }
            _ => return None,
        };
        return Some((normalized, port));
    }

    None
}

/// Classification of legacy HTTP response header directives (`R5-MIG-3`, `R6-MIG-5`, `R7-MIG-7`,
/// `R7-MIG-12`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeaderClassification {
    /// Already covered at equal-or-stronger strength by MiraServe's `security-headers "strict"`.
    CoveredByStrict,
    /// Benign caching/diagnostic/negotiation header safe to drop with a manual-review note
    /// (`Cache-Control` without `no-store`/`private`/`no-cache`/`must-revalidate`, `Expires`,
    /// `Vary`, `ETag`, `X-Powered-By`, etc.) so real-world static/WordPress/Caddy configs are not
    /// over-refused (`R7-MIG-12`).
    SafeToDropWithNote(&'static str),
    /// Security-relevant or unknown header that cannot be auto-translated — fail closed!
    SecurityDowngrade(&'static str),
}

/// Default-deny classifier for legacy HTTP response header directives (`R5-MIG-3`, `R6-MIG-5`,
/// `R7-MIG-7`, `R7-MIG-12`).
#[must_use]
pub(crate) fn classify_untranslated_security_header(
    raw_name: &str,
    raw_value: &str,
) -> HeaderClassification {
    let trimmed_name = raw_name.trim().trim_matches('"').trim_matches('\'');
    // Caddy `-Header` / Nginx `proxy_hide_header` / `more_clear_headers` removes a response header:
    // only safe to drop for `Server` / `X-Powered-By`.
    if let Some(removed) = trimmed_name.strip_prefix('-') {
        let low_rem = removed.trim().to_ascii_lowercase();
        if matches!(low_rem.as_str(), "server" | "x-powered-by") {
            return HeaderClassification::CoveredByStrict;
        }
        return HeaderClassification::SecurityDowngrade(
            "response header removal is not auto-translated by MiraServe `security-headers \"strict\"`",
        );
    }
    let name = trimmed_name
        .trim_start_matches(['+', '?'])
        .to_ascii_lowercase();
    let val = raw_value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_ascii_lowercase();

    match name.as_str() {
        "x-content-type-options" if val == "nosniff" => HeaderClassification::CoveredByStrict,
        "x-frame-options" if matches!(val.as_str(), "deny" | "sameorigin") => {
            HeaderClassification::CoveredByStrict
        }
        "cross-origin-opener-policy"
            if matches!(
                val.as_str(),
                "same-origin" | "same-origin-allow-popups" | "unsafe-none"
            ) =>
        {
            HeaderClassification::CoveredByStrict
        }
        "referrer-policy"
            if matches!(
                val.as_str(),
                "strict-origin-when-cross-origin"
                    | "no-referrer-when-downgrade"
                    | "origin-when-cross-origin"
                    | "unsafe-url"
            ) =>
        {
            HeaderClassification::CoveredByStrict
        }
        "permissions-policy" if val == "geolocation=(), microphone=(), camera=()" => {
            HeaderClassification::CoveredByStrict
        }
        "strict-transport-security" if is_hsts_covered_by_strict(&val) => {
            HeaderClassification::CoveredByStrict
        }
        "x-xss-protection" if matches!(val.as_str(), "0" | "1" | "1; mode=block") => {
            HeaderClassification::CoveredByStrict
        }
        "cache-control" if is_benign_public_cache_control(&val) => {
            HeaderClassification::SafeToDropWithNote(
                "public caching `Cache-Control` header is not auto-translated; configure CDN/response caching manually if needed",
            )
        }
        "expires" | "vary" | "etag" | "age" | "last-modified" | "accept-ranges"
        | "x-powered-by" | "server" | "x-cache" | "x-cache-status" | "x-served-by"
        | "x-ua-compatible" | "x-request-id" => HeaderClassification::SafeToDropWithNote(
            "non-security caching/diagnostic response header is not auto-translated",
        ),
        "content-security-policy" => HeaderClassification::SecurityDowngrade(
            "Content-Security-Policy is not emitted by MiraServe `security-headers \"strict\"`",
        ),
        "content-security-policy-report-only" => HeaderClassification::SecurityDowngrade(
            "Content-Security-Policy-Report-Only is not emitted by MiraServe `security-headers \"strict\"`",
        ),
        "strict-transport-security" => HeaderClassification::SecurityDowngrade(
            "Strict-Transport-Security policy (`preload` or custom `max-age`) differs from MiraServe `security-headers \"strict\"` (`max-age=63072000; includeSubDomains`)",
        ),
        "referrer-policy" => HeaderClassification::SecurityDowngrade(
            "Referrer-Policy is stricter than or differs from MiraServe `security-headers \"strict\"` (`strict-origin-when-cross-origin`)",
        ),
        "permissions-policy" => HeaderClassification::SecurityDowngrade(
            "custom Permissions-Policy may restrict browser features beyond MiraServe `security-headers \"strict\"`",
        ),
        "set-cookie" => HeaderClassification::SecurityDowngrade(
            "Set-Cookie policy/flag mutation cannot be auto-translated by MiraServe `security-headers \"strict\"`",
        ),
        _ => HeaderClassification::SecurityDowngrade(
            "response header is not auto-translated by MiraServe `security-headers \"strict\"`",
        ),
    }
}

/// Returns `true` ONLY for public/static caching `Cache-Control` values (containing none of
/// `no-store`, `private`, `no-cache`, or `must-revalidate`, which are security/privacy sensitive).
fn is_benign_public_cache_control(val_lower: &str) -> bool {
    if val_lower.is_empty() {
        return false;
    }
    let mut saw_token = false;
    for raw_dir in val_lower.split([',', ';']) {
        let dir = raw_dir.trim();
        if dir.is_empty() {
            continue;
        }
        saw_token = true;
        let key = dir.split('=').next().unwrap_or(dir).trim();
        if matches!(
            key,
            "no-store" | "private" | "no-cache" | "must-revalidate" | "proxy-revalidate"
        ) {
            return false;
        }
        if !matches!(
            key,
            "public"
                | "max-age"
                | "s-maxage"
                | "immutable"
                | "no-transform"
                | "stale-while-revalidate"
                | "stale-if-error"
        ) {
            return false;
        }
    }
    saw_token
}

fn is_hsts_covered_by_strict(val_lower: &str) -> bool {
    if val_lower.is_empty() || val_lower.contains("preload") {
        return false;
    }
    let mut saw_max_age = false;
    for part in val_lower.split(';') {
        let tok = part.trim();
        if tok.is_empty() {
            continue;
        }
        if tok == "includesubdomains" {
            continue;
        }
        if let Some(secs_str) = tok.strip_prefix("max-age=")
            && let Ok(secs) = secs_str.trim().parse::<u64>()
            && secs <= 63_072_000
        {
            saw_max_age = true;
            continue;
        }
        return false;
    }
    saw_max_age
}

/// Classification of a legacy PHP regex location / `<FilesMatch>` pattern (`R6-MIG-2`, `R6-MIG-3`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PhpLocationPattern {
    /// Site-wide plain extension list (e.g. `["*.php"]` or `["*.php", "*.phtml", "*.php5"]`).
    Extensions(Vec<String>),
    /// Anchored exact-path allow-list (e.g. `["/index.php", "/wp-login.php", "/wp-cron.php"]`).
    ExactPaths(Vec<String>),
    /// Complex or path-scoped regex (e.g. `^/app/.*\.php$`, negative lookahead) that cannot be
    /// represented faithfully without widening or narrowing execution — caller MUST fail closed!
    Untranslatable,
}

/// Strictly classifies a PHP regex from Nginx `location ~ ...` or Apache `<FilesMatch ...>` so:
/// - Allow-list regexes like `^/(index|wp-login|wp-cron)\.php$` emit exact paths (`R6-MIG-2`),
///   NEVER widened to `*.php`.
/// - Multi-extension regexes like `\.(php|phtml|php5)$` or `.+\.ph(ar|p|tml)$` emit ONE route per
///   executed extension (`R6-MIG-3`).
/// - Any regex that cannot be represented faithfully returns [`PhpLocationPattern::Untranslatable`].
#[must_use]
pub(crate) fn classify_php_regex_pattern(raw_regex: &str) -> PhpLocationPattern {
    let mut s = raw_regex.trim().trim_matches('"').trim_matches('\'');
    if let Some(rest) = s.strip_prefix("(?i)") {
        s = rest;
    }

    // Case 1: Anchored exact-path allow-list (`^/index\.php$` or `^/(index|wp-login|wp-cron)\.php$`).
    if let Some(after_caret) = s.strip_prefix("^/")
        && let Some(before_dollar) = after_caret.strip_suffix('$')
        && let Some(prefix_body) = before_dollar.strip_suffix(r"\.php")
    {
        if let Some(inner) = prefix_body
            .strip_prefix('(')
            .and_then(|x| x.strip_suffix(')'))
        {
            let inner = inner.strip_prefix("?:").unwrap_or(inner);
            let mut paths = Vec::new();
            let mut all_clean = true;
            for branch in inner.split('|') {
                if let Some(clean) = decode_clean_exact_path_segment(branch) {
                    let route = format!("/{clean}.php");
                    if !paths.contains(&route) {
                        paths.push(route);
                    }
                } else {
                    all_clean = false;
                    break;
                }
            }
            if all_clean && !paths.is_empty() {
                return PhpLocationPattern::ExactPaths(paths);
            }
        } else if let Some(clean) = decode_clean_exact_path_segment(prefix_body) {
            return PhpLocationPattern::ExactPaths(vec![format!("/{clean}.php")]);
        }
        return PhpLocationPattern::Untranslatable;
    }

    // Case 2: Site-wide plain extension regex (`\.php$`, `[^/]\.php(/|$)`, `\.(php|phtml|php5)$`,
    // `.+\.ph(ar|p|tml)$`, `\.php[57]?$`). Never match path-anchored `^/...` regexes!
    if s.starts_with('^') && s.starts_with("^/") {
        return PhpLocationPattern::Untranslatable;
    }
    let mut body = s;
    for prefix in [
        "^.+?", "^.+", "^.*", "^[^/]+", "^[^/]", ".+?", ".+", ".*", "[^/]+", "[^/]",
    ] {
        if let Some(rest) = body.strip_prefix(prefix) {
            body = rest;
            break;
        }
    }
    let Some(after_dot) = body.strip_prefix(r"\.") else {
        return PhpLocationPattern::Untranslatable;
    };

    // Must end with a standard end-of-string or PATH_INFO boundary.
    let mut ext_spec = None;
    for suffix in [
        r"(/.*)?$",
        r"(\/.*)?$",
        r"(/.*)?",
        r"(\/.*)?",
        r"(/|$)?",
        r"(\/|$)?",
        r"(/|$)",
        r"(\/|$)",
        "$",
    ] {
        if let Some(before) = after_dot.strip_suffix(suffix) {
            ext_spec = Some(before);
            break;
        }
    }
    let Some(spec) = ext_spec else {
        return PhpLocationPattern::Untranslatable;
    };

    let exts = expand_plain_extension_spec(spec);
    if exts.is_empty() {
        PhpLocationPattern::Untranslatable
    } else {
        PhpLocationPattern::Extensions(exts)
    }
}

fn decode_clean_exact_path_segment(raw: &str) -> Option<String> {
    if raw.is_empty() || raw.starts_with('/') || raw.ends_with('/') {
        return None;
    }
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some(esc @ ('.' | '-' | '_' | '/')) => out.push(esc),
                _ => return None,
            }
        } else if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '/') {
            out.push(ch);
        } else {
            return None;
        }
    }
    if out.contains("..") {
        return None;
    }
    Some(out)
}

fn expand_plain_extension_spec(spec: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut push_ext = |ext: String| {
        if !ext.is_empty() && ext.bytes().all(|b| b.is_ascii_alphanumeric()) {
            let pat = format!("*.{}", ext.to_ascii_lowercase());
            if !out.contains(&pat) {
                out.push(pat);
            }
        }
    };

    // Simple single extension: `php`, `phtml`, `php5`
    if !spec.is_empty() && spec.bytes().all(|b| b.is_ascii_alphanumeric()) {
        push_ext(spec.to_owned());
        return out;
    }

    // Group alternation with optional prefix and optional `?`:
    // `(php|phtml|php5)`, `(?:php|php5|php7|inc)`, `ph(ar|p|tml)`, `php(5|7)?`
    if let Some(open) = spec.find('(') {
        let prefix = spec.get(..open).unwrap_or("");
        let rest = spec.get(open + 1..).unwrap_or("");
        let (inner, optional) = if let Some(b) = rest.strip_suffix(")?") {
            (b, true)
        } else if let Some(b) = rest.strip_suffix(')') {
            (b, false)
        } else {
            return Vec::new();
        };
        if !prefix.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Vec::new();
        }
        let inner = inner.strip_prefix("?:").unwrap_or(inner);
        if inner.is_empty() || inner.contains('(') || inner.contains(')') {
            return Vec::new();
        }
        if optional && !prefix.is_empty() {
            push_ext(prefix.to_owned());
        }
        for branch in inner.split('|') {
            if !branch.bytes().all(|b| b.is_ascii_alphanumeric()) {
                return Vec::new();
            }
            let combined = format!("{prefix}{branch}");
            if combined.is_empty() {
                return Vec::new();
            }
            push_ext(combined);
        }
        return out;
    }

    // Character class suffix: `php[57]?` or `php[578]`
    if let Some(open) = spec.find('[') {
        let prefix = spec.get(..open).unwrap_or("");
        let rest = spec.get(open + 1..).unwrap_or("");
        let (chars_spec, optional) = if let Some(b) = rest.strip_suffix("]?") {
            (b, true)
        } else if let Some(b) = rest.strip_suffix(']') {
            (b, false)
        } else {
            return Vec::new();
        };
        if prefix.is_empty()
            || !prefix.bytes().all(|b| b.is_ascii_alphanumeric())
            || chars_spec.is_empty()
            || !chars_spec.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            return Vec::new();
        }
        if optional {
            push_ext(prefix.to_owned());
        }
        for ch in chars_spec.chars() {
            push_ext(format!("{prefix}{ch}"));
        }
        return out;
    }

    Vec::new()
}

/// Case-insensitive parser for Apache / OpenLiteSpeed bracketed `RewriteRule` flags (`[F]`,
/// `[G]`, `[L,R=403]`, `[R=405,L]`, `[nc,f]`, any `R=4xx/5xx`, `R5-MIG-6`).
#[must_use]
pub(crate) fn has_blocking_rewrite_flag(line: &str) -> bool {
    let trimmed = line.trim();
    let Some(open) = trimmed.rfind('[') else {
        return false;
    };
    let Some(rest) = trimmed.get(open.saturating_add(1)..) else {
        return false;
    };
    let Some(close) = rest.find(']') else {
        return false;
    };
    // Ensure the bracket block is actually the trailing flag group (not a regex character class).
    if rest
        .get(close.saturating_add(1)..)
        .is_some_and(|tail| !tail.trim().is_empty())
    {
        return false;
    }
    let flags = rest.get(..close).unwrap_or("");
    flags.split(',').any(|tok| {
        let f = tok.trim().to_ascii_lowercase();
        if matches!(f.as_str(), "f" | "forbidden" | "g" | "gone") {
            return true;
        }
        if let Some(code) = f.strip_prefix("r=").or_else(|| f.strip_prefix("redirect=")) {
            return code
                .parse::<u16>()
                .is_ok_and(|status| (400..=599).contains(&status));
        }
        false
    })
}

/// Returns `true` when `blocked_pat` (from a security-blocked location/context) overlaps
/// `route_pat` (an emitted MiraServe route pattern) (`R5-MIG-4`).
#[must_use]
pub(crate) fn route_patterns_overlap(blocked_pat: &str, route_pat: &str) -> bool {
    if blocked_pat.is_empty()
        || route_pat.is_empty()
        || blocked_pat == "/*"
        || blocked_pat == "*"
        || route_pat == "/*"
        || route_pat == "*"
    {
        return true;
    }
    if let Some(b_ext) = blocked_pat.strip_prefix("*.") {
        if let Some(r_ext) = route_pat.strip_prefix("*.") {
            return b_ext.eq_ignore_ascii_case(r_ext);
        }
        if route_pat.ends_with("/*") {
            return true;
        }
        let suffix = format!(".{}", b_ext.to_ascii_lowercase());
        return route_pat.to_ascii_lowercase().ends_with(&suffix);
    }
    if let Some(r_ext) = route_pat.strip_prefix("*.") {
        if blocked_pat.ends_with("/*") {
            return true;
        }
        let suffix = format!(".{}", r_ext.to_ascii_lowercase());
        return blocked_pat.to_ascii_lowercase().ends_with(&suffix);
    }

    let (b_base, b_prefix) = split_path_pattern(blocked_pat);
    let (r_base, r_prefix) = split_path_pattern(route_pat);
    if b_base == r_base {
        return true;
    }
    if b_prefix && is_descendant_path(b_base, r_base) {
        return true;
    }
    if r_prefix && is_descendant_path(r_base, b_base) {
        return true;
    }
    false
}

fn split_path_pattern(pattern: &str) -> (&str, bool) {
    if let Some(prefix) = pattern.strip_suffix("/*") {
        (prefix.trim_end_matches('/'), true)
    } else if pattern == "/" {
        ("", false)
    } else {
        (pattern.trim_end_matches('/'), false)
    }
}

fn is_descendant_path(ancestor: &str, descendant: &str) -> bool {
    if ancestor.is_empty() {
        return true;
    }
    descendant == ancestor
        || descendant
            .strip_prefix(ancestor)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Renders a [`MigratedDoc`] into clean, properly escaped MiraServe KDL v2 text.
#[allow(clippy::too_many_lines)]
pub(crate) fn render_kdl(
    doc: &MigratedDoc,
    source_format: SourceFormat,
    allow_insecure: bool,
) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "// Generated by `miraserve import` from {source_format} configuration"
    );
    let _ = writeln!(
        out,
        "// Review notes and validate with: miraserve check <file>"
    );
    let insecure_emitted_count = doc.sites.iter().filter(|s| s.emitted_insecure).count();
    if insecure_emitted_count > 0 {
        let _ = writeln!(
            out,
            "// INSECURE OUTPUT (--allow-insecure): {} security directive(s) could not be translated; {insecure_emitted_count} blocked site(s) WERE EMITTED PUBLICLY WITHOUT THOSE CONTROLS (DO NOT DEPLOY AS-IS)!",
            doc.security_downgrades.len()
        );
    } else if !doc.security_downgrades.is_empty() {
        let mode_note = if allow_insecure {
            " (--allow-insecure: affected routes were omitted; review before deploying)"
        } else {
            "; affected routes/sites were omitted!"
        };
        let _ = writeln!(
            out,
            "// SECURITY WARNING: {} security directive(s) could not be translated{mode_note}",
            doc.security_downgrades.len()
        );
    }
    let _ = writeln!(out);

    // R2-MIG-2 & R3-MIG-8: Never silently widen a loopback/scoped-only HTTP config onto public
    // `0.0.0.0:443`, AND never put TLS onto port 80 (promote scoped `:80` to `:443` while keeping
    // the scoped `:80` as an HTTP->HTTPS redirect listener)!
    let https_binds: Vec<String> = if !doc.https_binds.is_empty() {
        doc.https_binds.clone()
    } else if !doc.http_binds.is_empty() && doc.http_binds.iter().all(|b| is_scoped_bind(b)) {
        doc.http_binds
            .iter()
            .map(|b| promote_scoped_port80_to_https(b))
            .collect()
    } else {
        vec![":443".to_owned()]
    };

    // MIG-4: Never emit a public `:80` redirect listener if all HTTPS listeners are scoped
    // (e.g. loopback `127.0.0.1:8443` or `[::1]:8443`)!
    let all_https_scoped = https_binds.iter().all(|b| is_scoped_bind(b));

    let https_binds_lookup: HashSet<&str> = https_binds.iter().map(String::as_str).collect();
    let _ = writeln!(out, "server {{");
    for bind in &https_binds {
        let _ = writeln!(out, "    listen {} protocols=\"h3,h2,h1\"", kdl_quote(bind));
    }
    if !doc.http_binds.is_empty() {
        for bind in &doc.http_binds {
            if !https_binds_lookup.contains(bind.as_str()) {
                let _ = writeln!(out, "    listen {} redirect-https=#true", kdl_quote(bind));
            }
        }
    } else if doc.redirect_http && !all_https_scoped && !https_binds_lookup.contains(":80") {
        let _ = writeln!(out, "    listen \":80\" redirect-https=#true");
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "    tls {{");
    let _ = writeln!(out, "        min-version \"1.3\"");
    let _ = writeln!(out, "        pqc-hybrid #true");
    let _ = writeln!(out, "        key-isolation \"in-process\"");
    if let Some(email) = &doc.acme_email {
        let _ = writeln!(out, "        acme {{");
        let _ = writeln!(out, "            email {}", kdl_quote(email));
        let _ = writeln!(out, "            challenge \"tls-alpn-01\"");
        let _ = writeln!(out, "            short-lived #true");
        let _ = writeln!(out, "        }}");
    }
    let _ = writeln!(out, "    }}");
    let _ = writeln!(out);
    let _ = writeln!(out, "    sandbox {{");
    let _ = writeln!(out, "        landlock #true");
    let _ = writeln!(out, "        seccomp \"strict\"");
    let _ = writeln!(out, "    }}");
    let _ = writeln!(out, "}}");

    for site in &doc.sites {
        let _ = writeln!(out);
        if site.emitted_insecure {
            let raw_reasons = if site.insecure_reasons.is_empty() {
                "untranslatable security directive(s)".to_owned()
            } else {
                site.insecure_reasons.join(", ")
            };
            // R6-MIG-1: Final defense-in-depth sanitization before writing any KDL `//` comment!
            let safe_reasons = sanitize_diagnostic_text(&raw_reasons, 320);
            let _ = writeln!(out, "// INSECURE: emitted despite {safe_reasons}");
        }
        let host_args: Vec<String> = site.hosts.iter().map(|h| kdl_quote(h)).collect();
        let _ = writeln!(out, "site {} {{", host_args.join(" "));
        if site.wordpress {
            let _ = writeln!(out, "    preset \"wordpress-hardened\"");
        }
        let _ = writeln!(out, "    security-headers \"strict\"");

        let has_tls_override = site.compat_tls_1_2 || (site.cert.is_some() && site.key.is_some());
        if has_tls_override {
            let _ = writeln!(out, "    tls {{");
            if site.compat_tls_1_2 {
                let _ = writeln!(out, "        compat-tls-1-2 #true");
            }
            if let (Some(cert), Some(key)) = (&site.cert, &site.key) {
                let _ = writeln!(out, "        cert {}", kdl_quote(cert));
                let _ = writeln!(out, "        key {}", kdl_quote(key));
            }
            let _ = writeln!(out, "    }}");
        }

        if let Some(root) = &site.root {
            let _ = writeln!(out, "    root {}", kdl_quote(root));
        }

        for route in &site.routes {
            let _ = writeln!(out);
            let _ = writeln!(out, "    route {} {{", kdl_quote(&route.pattern));
            match &route.handler {
                MigratedHandler::ReverseProxy {
                    upstreams,
                    preserve_host,
                    allow_upgrades,
                } => {
                    let _ = writeln!(out, "        reverse-proxy {{");
                    for up in upstreams {
                        let _ = writeln!(out, "            upstream {}", kdl_quote(up));
                    }
                    if *preserve_host {
                        let _ = writeln!(out, "            preserve-host #true");
                    }
                    if !*allow_upgrades {
                        let _ = writeln!(out, "            allow-upgrades #false");
                    }
                    let _ = writeln!(out, "        }}");
                }
                MigratedHandler::FastCgi { target } => {
                    let _ = writeln!(out, "        fastcgi-pass {}", kdl_quote(target));
                }
                MigratedHandler::TryFiles { candidates } => {
                    let args: Vec<String> = candidates.iter().map(|c| kdl_quote(c)).collect();
                    let _ = writeln!(out, "        try-files {}", args.join(" "));
                }
                MigratedHandler::Static => {
                    let _ = writeln!(out, "        static {{");
                    let _ = writeln!(out, "            dotfiles \"deny\"");
                    let _ = writeln!(out, "        }}");
                }
            }
            let _ = writeln!(out, "    }}");
        }

        let _ = writeln!(out, "}}");
    }

    out
}

/// Escapes a string as a double-quoted KDL v2 literal, encoding all control characters,
/// Unicode line separators (`U+0085`, `U+2028`, `U+2029`), Unicode bidi controls
/// (`U+200E..=U+200F`, `U+202A..=U+202E`, `U+2066..=U+2069`), and `U+FEFF` safely
/// (`R6-MIG-1`, `R7-MIG-16`).
pub(crate) fn kdl_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len().saturating_add(2));
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control()
                || matches!(
                    c,
                    '\u{0085}'
                        | '\u{2028}'
                        | '\u{2029}'
                        | '\u{200E}'..='\u{200F}'
                        | '\u{202A}'..='\u{202E}'
                        | '\u{2066}'..='\u{2069}'
                        | '\u{FEFF}'
                ) =>
            {
                let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// Normalizes a legacy upstream target into a valid `http://` or `https://` URL.
pub(crate) fn normalize_upstream_url(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches(';').trim_matches('"');
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_owned()
    } else if let Some(rest) = trimmed.strip_prefix(':') {
        format!("http://127.0.0.1:{rest}")
    } else {
        format!("http://{trimmed}")
    }
}

/// Returns `true` when `raw` looks like a routable ACME contact email (rejecting stock
/// placeholders like `webmaster@localhost`, `root@localhost`, or `*.local` that fail ACME
/// validation, `R4-MIG-3`).
#[must_use]
pub(crate) fn is_routable_acme_email(raw: &str) -> bool {
    let clean = raw.trim().trim_matches('"');
    let Some((local, domain)) = clean.split_once('@') else {
        return false;
    };
    if local.is_empty()
        || domain.is_empty()
        || domain.contains('@')
        || clean.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return false;
    }
    let lower_dom = domain.to_ascii_lowercase();
    let tld = lower_dom.rsplit('.').next().unwrap_or("");
    !(lower_dom == "localhost"
        || tld == "localhost"
        || tld == "local"
        || !lower_dom.contains('.')
        || lower_dom.starts_with('.')
        || lower_dom.ends_with('.'))
}

/// Normalizes a legacy FastCGI endpoint into MiraServe's `unix:/path` or `tcp://host:port`.
pub(crate) fn normalize_fastcgi_target(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches(';').trim_matches('"');
    if let Some(rest) = trimmed.strip_prefix("unix://") {
        if rest.starts_with('/') {
            format!("unix:{rest}")
        } else {
            format!("unix:/{rest}")
        }
    } else if let Some(rest) = trimmed.strip_prefix("unix//") {
        // R4-MIG-3: Caddy writes Unix domain sockets as `unix//run/php/php8.3-fpm.sock`.
        if rest.starts_with('/') {
            format!("unix:{rest}")
        } else {
            format!("unix:/{rest}")
        }
    } else if let Some(rest) = trimmed.strip_prefix("unix:") {
        if rest.starts_with('/') {
            format!("unix:{rest}")
        } else {
            format!("unix:/{rest}")
        }
    } else if let Some(rest) = trimmed.strip_prefix("uds://") {
        if rest.starts_with('/') {
            format!("unix:{rest}")
        } else {
            format!("unix:/{rest}")
        }
    } else if let Some(rest) = trimmed.strip_prefix("fcgi://") {
        let host_port = rest.split('/').next().unwrap_or(rest);
        format!("tcp://{host_port}")
    } else if trimmed.starts_with("tcp://") {
        trimmed.to_owned()
    } else {
        format!("tcp://{trimmed}")
    }
}

/// Normalizes legacy route prefixes/locations into valid MiraServe route patterns.
///
/// When `exact == true` (e.g. Nginx `location = /health`), preserves the exact path without
/// widening it to a prefix wildcard (`MIG-7`). Never widens literal paths containing `.php`
/// (e.g. `location /status.php`) into site-wide `*.php` (`R7-MIG-1`).
pub(crate) fn normalize_route_pattern_with_mode(raw: &str, exact: bool) -> String {
    let trimmed = raw.trim().trim_matches('"');
    if trimmed.is_empty() || trimmed == "/" {
        return if exact {
            "/".to_owned()
        } else {
            "/*".to_owned()
        };
    }
    if trimmed == "/*" {
        return "/*".to_owned();
    }
    if trimmed.starts_with("*.") {
        return trimmed.to_owned();
    }
    let with_slash = if trimmed.starts_with('/') {
        trimmed.to_owned()
    } else {
        format!("/{trimmed}")
    };
    if exact {
        return with_slash;
    }
    if with_slash.ends_with("/*") {
        with_slash
    } else if with_slash.ends_with('/') {
        format!("{with_slash}*")
    } else {
        format!("{with_slash}/*")
    }
}

/// Normalizes a prefix-style legacy route pattern into a valid MiraServe route pattern.
pub(crate) fn normalize_route_pattern(raw: &str) -> String {
    normalize_route_pattern_with_mode(raw, false)
}

/// Validates whether a migrated hostname is accepted by `miraserve-config` (`R5-MIG-7`:
/// matches `validate::is_valid_site_host` strictly so regexes, IDNs, and `${VAR}`/`{$DOMAIN}`
/// placeholders are rejected cleanly with a migration note instead of aborting KDL validation).
fn is_valid_migrated_host(host: &str) -> bool {
    if host.is_empty()
        || host.len() > 253
        || host == "_"
        || host == "*"
        || host.chars().any(char::is_whitespace)
        || host.contains("://")
        || host.contains('/')
        || host.contains(':')
    {
        return false;
    }
    let (is_wildcard, check_part) = match host.strip_prefix("*.") {
        Some(rest) => (true, rest),
        None => (false, host),
    };
    if check_part.is_empty() || check_part.contains('*') {
        return false;
    }
    if check_part.parse::<std::net::IpAddr>().is_ok() {
        return !is_wildcard;
    }
    let mut label_count = 0_usize;
    for label in check_part.split('.') {
        label_count = label_count.saturating_add(1);
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return false;
        }
    }
    label_count >= 1
}

/// Promotes a scoped HTTP port-80 bind (`127.0.0.1:80`, `[::1]:80`) to port `443` for TLS
/// termination so MiraServe never speaks HTTPS on port 80 (`R3-MIG-8`).
fn promote_scoped_port80_to_https(bind: &str) -> String {
    if let Some(host) = bind.strip_suffix(":80") {
        format!("{host}:443")
    } else {
        bind.to_owned()
    }
}

/// Merges `incoming` into an existing site that already owns the same virtual host(s)
/// (such as Certbot HTTP + HTTPS vhost pairs, `R5-MIG-7`), preserving all TLS certs/keys,
/// binds, routes, and security blockers (never weakening security across merged blocks).
fn merge_into_existing_site(
    target: &mut MigratedSite,
    incoming: MigratedSite,
    downgrades_to_add: &mut Vec<(Option<usize>, String, String)>,
) {
    if target.root.is_none() {
        target.root = incoming.root;
    } else if let (Some(existing_root), Some(inc_root)) = (&target.root, &incoming.root)
        && existing_root != inc_root
    {
        // R6-MIG-11: Conflicting HTTP vs HTTPS DocumentRoots cannot be merged silently without
        // risking exposing the wrong directory — fail closed with a security downgrade!
        let msg = format!(
            "Merged virtual hosts for '{}' had differing document roots ('{existing_root}' vs '{inc_root}'); site withheld until roots are reconciled",
            target.hosts.join(", ")
        );
        target.block_site(None, "root (conflicting virtual host roots)");
        downgrades_to_add.push((None, "root".to_owned(), msg));
    }
    target.wordpress |= incoming.wordpress;
    target.compat_tls_1_2 |= incoming.compat_tls_1_2;
    if incoming.cert.is_some() && incoming.key.is_some() {
        target.cert = incoming.cert;
        target.key = incoming.key;
    } else {
        if target.cert.is_none() {
            target.cert = incoming.cert;
        }
        if target.key.is_none() {
            target.key = incoming.key;
        }
    }
    for b in incoming.https_binds {
        target.add_https_bind(b);
    }
    for b in incoming.http_binds {
        target.add_http_bind(b);
    }
    target.routes.extend(incoming.routes);
    target.blocked_locations.extend(incoming.blocked_locations);
    target.closed_prefixes.extend(incoming.closed_prefixes);
    target.static_fallback_must_be_confirmed |= incoming.static_fallback_must_be_confirmed;
    target.static_fallback_confirmed |= incoming.static_fallback_confirmed;
    if target.file_content_needs_file_server.is_none() {
        target.file_content_needs_file_server = incoming.file_content_needs_file_server;
    }
    if incoming.site_wide_auth_blocked {
        target.site_wide_auth_blocked = true;
    }
    for reason in incoming.insecure_reasons {
        target.push_insecure_reason(reason);
    }
}

/// Deduplicates route patterns within a site, merges HTTP/HTTPS duplicate virtual hosts
/// (`R5-MIG-7`), enforces scoped-vs-public listener isolation (`R3-MIG-4`), checks location-scoped
/// security blockers against overlapping routes and static `root` fallback (`R5-MIG-4`), preserves
/// valid wildcard hosts (`*.example.com`), notes invalid/conflicting hosts (`MIG-6`), and filters
/// out sites whose routes/root were withheld due to untranslatable security controls (`MIG-3`)
/// unless `allow_insecure` is set (`R3-MIG-3`, `R4-MIG-2`).
#[allow(clippy::too_many_lines)]
pub(crate) fn finalize_doc_with_options(doc: &mut MigratedDoc, allow_insecure: bool) {
    let mut host_to_site_idx: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut merged: Vec<MigratedSite> = Vec::new();
    let mut notes_to_add: Vec<(Option<usize>, String, String)> = Vec::new();
    let mut downgrades_to_add: Vec<(Option<usize>, String, String)> = Vec::new();

    // Step 1: Normalize hostnames and merge duplicate HTTP/HTTPS vhost blocks sharing hosts
    // (e.g. Certbot `000-default.conf` + `000-default-le-ssl.conf`, `R5-MIG-7`) BEFORE security
    // and scope filtering so merged blocks inherit all TLS certificates and all security blockers.
    for mut site in std::mem::take(&mut doc.sites) {
        // Caddy `php_fastcgi` and `try_files` only rewrite and hand `.php` to FastCGI; they never
        // return a file's contents. Their translation (`try-files` with file candidates) does.
        // That is the source's behaviour only when a site-wide `file_server` is also present.
        if let Some(line) = site.file_content_needs_file_server.take()
            && !site.static_fallback_confirmed
        {
            downgrades_to_add.push((
                Some(line),
                "file_server".to_owned(),
                "this site rewrites requests (`php_fastcgi` / `try_files`) but has no site-wide `file_server`, so the source never returns static files; the translation would. Site withheld".to_owned(),
            ));
            site.block_site(Some(line), "php_fastcgi/try_files without file_server");
        }
        // R8-MIG-7: judge a whole-site redirect per source block, BEFORE merging, so the usual
        // `http://host { redir https://host{uri} }` companion block does not taint the real one.
        if let Some((line, directive)) = site.whole_site_redirect.take() {
            if site.root.is_some() || !site.routes.is_empty() {
                downgrades_to_add.push((
                    line,
                    directive.clone(),
                    format!(
                        "'{directive}' redirects or rewrites every request of this site, so its other content was never reachable in the source; site withheld rather than exposing that content"
                    ),
                ));
                site.block_site(line, &format!("{directive} (whole site)"));
            } else {
                notes_to_add.push((
                    line,
                    directive.clone(),
                    format!(
                        "'{directive}' on a redirect-only site block was not migrated (MiraServe's HTTP listener already redirects to HTTPS)"
                    ),
                ));
            }
        }
        let mut valid_hosts = Vec::new();
        let mut seen_in_site = HashSet::new();
        for h in std::mem::take(&mut site.hosts) {
            let lower = h.trim().to_ascii_lowercase();
            if lower.is_empty() || lower == "_" {
                continue;
            }
            if !is_valid_migrated_host(&lower) {
                notes_to_add.push((
                    None,
                    "host".to_owned(),
                    format!(
                        "Unsupported wildcard/regex/IDN/variable host pattern '{h}' could not be migrated directly (use explicit ASCII or Punycode hostnames)"
                    ),
                ));
                continue;
            }
            if seen_in_site.insert(lower.clone()) {
                valid_hosts.push(lower);
            }
        }

        // Check whether all claimed hosts already belong to a single existing site (HTTP+HTTPS pair).
        let mut matched_targets: HashSet<usize> = HashSet::new();
        let mut unclaimed_hosts: Vec<String> = Vec::new();
        for h in &valid_hosts {
            if let Some(&idx) = host_to_site_idx.get(h) {
                matched_targets.insert(idx);
            } else {
                unclaimed_hosts.push(h.clone());
            }
        }

        if matched_targets.len() == 1
            && let Some(&target_idx) = matched_targets.iter().next()
            && let Some(existing) = merged.get_mut(target_idx)
        {
            for new_h in unclaimed_hosts {
                host_to_site_idx.insert(new_h.clone(), target_idx);
                existing.hosts.push(new_h);
            }
            merge_into_existing_site(existing, site, &mut downgrades_to_add);
            continue;
        }

        let mut clean_hosts = Vec::new();
        let new_idx = merged.len();
        for h in valid_hosts {
            if host_to_site_idx.contains_key(&h) {
                notes_to_add.push((
                    None,
                    "host".to_owned(),
                    format!("Duplicate virtual host '{h}' skipped; merge routes manually"),
                ));
                continue;
            }
            host_to_site_idx.insert(h.clone(), new_idx);
            clean_hosts.push(h);
        }
        site.hosts = clean_hosts;
        merged.push(site);
    }

    // Step 2 (R3-MIG-4): Detect multi-site configs that mix public sites (serving on `:443` / `0.0.0.0`)
    // with loopback/interface-scoped sites (e.g. `127.0.0.1:8080`).
    let has_public_site = merged
        .iter()
        .any(|s| (!s.site_wide_auth_blocked || allow_insecure) && s.is_public_site());
    let has_scoped_site = merged
        .iter()
        .any(|s| (!s.site_wide_auth_blocked || allow_insecure) && s.is_exclusively_scoped());
    let mixed_scope = has_public_site && has_scoped_site;

    let mut any_site_has_binds = false;
    for site in &merged {
        if !site.https_binds.is_empty() || !site.http_binds.is_empty() {
            any_site_has_binds = true;
            break;
        }
    }

    let mut kept = Vec::new();
    let mut used_placeholder_hosts: HashSet<String> = host_to_site_idx.into_keys().collect();

    for mut site in merged {
        if mixed_scope && site.is_exclusively_scoped() {
            let label = if site.hosts.is_empty() {
                "<unnamed>".to_owned()
            } else {
                site.hosts.join(", ")
            };
            let binds: Vec<&str> = site
                .https_binds
                .iter()
                .chain(site.http_binds.iter())
                .map(String::as_str)
                .collect();
            let action_note = if allow_insecure {
                "EMITTED INSECURELY across public listeners via --allow-insecure (deploy in a separate MiraServe instance instead)"
            } else {
                "withheld to avoid public exposure (deploy in a separate MiraServe instance)"
            };
            downgrades_to_add.push((
                None,
                "listen".to_owned(),
                format!(
                    "Site '{label}' was restricted to scoped/loopback bind(s) ({}) alongside public listener(s); MiraServe serves all sites across all listeners, so this scoped site was {action_note}",
                    binds.join(", ")
                ),
            ));
            site.block_site(None, "listen (scoped/loopback bind)");
        }

        // R8-MIG-7 & R8-MIG-8: close un-migrated redirect/alias/rewrite prefixes. With a
        // document root the prefix gets an explicit 404 route that sorts ahead of `*.php` and
        // `/*`; without one there is nothing to answer 404 from, so the prefix is a blocker and
        // any overlapping proxy route is withheld by Step 3.
        for (pattern, line, directive) in std::mem::take(&mut site.closed_prefixes) {
            if site.root.is_some() {
                if let Some(existing) = site.routes.iter_mut().find(|r| r.pattern == pattern) {
                    *existing = MigratedRoute::new(
                        pattern.clone(),
                        MigratedHandler::TryFiles {
                            candidates: vec!["=404".to_owned()],
                        },
                    )
                    .with_preferential_prefix(true);
                } else {
                    site.routes.push(
                        MigratedRoute::new(
                            pattern.clone(),
                            MigratedHandler::TryFiles {
                                candidates: vec!["=404".to_owned()],
                            },
                        )
                        .with_preferential_prefix(true),
                    );
                }
                notes_to_add.push((
                    line,
                    directive.clone(),
                    format!(
                        "'{directive}' for '{pattern}' was not migrated; the path now answers 404 so nothing under it is exposed. Re-create it as an explicit MiraServe route if it is still needed"
                    ),
                ));
            } else {
                downgrades_to_add.push((
                    line,
                    directive.clone(),
                    format!(
                        "'{directive}' for '{pattern}' cannot be migrated and this site has no document root to answer 404 from; overlapping routes withheld"
                    ),
                ));
                site.blocked_locations.push((pattern, line, directive));
            }
        }

        // The source served files only inside explicit scopes (e.g. Caddy
        // `handle /public/* { file_server }` under a site `root`). MiraServe would serve every
        // other path from the document root too, so that fallback is closed with a catch-all
        // 404 route. The scoped static routes sort ahead of it and keep working.
        if site.root.is_some()
            && site.static_fallback_must_be_confirmed
            && !site.static_fallback_confirmed
            && !site
                .routes
                .iter()
                .any(|r| r.pattern == "/*" || r.pattern == "*")
        {
            site.routes.push(MigratedRoute::new(
                "/*".to_owned(),
                MigratedHandler::TryFiles {
                    candidates: vec!["=404".to_owned()],
                },
            ));
            notes_to_add.push((
                None,
                "root".to_owned(),
                "The source serves files only inside explicit scopes, not for the whole site; every other path now answers 404 instead of falling back to the document root".to_owned(),
            ));
        }

        // Step 3 (R5-MIG-4): Enforce location-scoped blockers against EVERY emitted route whose
        // pattern overlaps a blocked location AND against static `site.root` fallback!
        if !site.blocked_locations.is_empty() {
            let blocked_snapshot = site.blocked_locations.clone();
            let mut overlapping_routes: Vec<(String, String, Option<usize>, String)> = Vec::new();
            for route in &site.routes {
                if let Some((b_pat, b_line, b_dir)) = blocked_snapshot
                    .iter()
                    .find(|(b_pat, _, _)| route_patterns_overlap(b_pat, &route.pattern))
                {
                    overlapping_routes.push((
                        route.pattern.clone(),
                        b_pat.clone(),
                        *b_line,
                        b_dir.clone(),
                    ));
                }
            }

            if allow_insecure {
                for (r_pat, b_pat, b_line, b_dir) in &overlapping_routes {
                    site.block_site(
                        *b_line,
                        &format!("{b_dir} on {b_pat} overlapped by {r_pat}"),
                    );
                }
                if site.root.is_some() {
                    for (b_pat, b_line, b_dir) in &blocked_snapshot {
                        site.block_site(
                            *b_line,
                            &format!("{b_dir} on {b_pat} (static root fallback)"),
                        );
                    }
                }
            } else {
                if !overlapping_routes.is_empty() {
                    site.routes.retain(|r| {
                        !blocked_snapshot
                            .iter()
                            .any(|(b_pat, _, _)| route_patterns_overlap(b_pat, &r.pattern))
                    });
                    for (r_pat, b_pat, b_line, b_dir) in &overlapping_routes {
                        downgrades_to_add.push((
                            *b_line,
                            b_dir.clone(),
                            format!(
                                "Route '{r_pat}' overlaps blocked location '{b_pat}' ({b_dir}) and was withheld so the protected path is not exposed"
                            ),
                        ));
                    }
                }
                if site.root.is_some() {
                    for (b_pat, b_line, b_dir) in &blocked_snapshot {
                        site.block_site(*b_line, &format!("{b_dir} ({b_pat})"));
                    }
                }
            }
        }

        if site.site_wide_auth_blocked {
            if !allow_insecure {
                site.routes.clear();
                site.root = None;
                continue;
            }
            site.emitted_insecure = true;
        }

        // Deduplicate route patterns preserving first occurrence, and ensure static/try-files
        // routes only appear when `site.root` is set (`CFG-1`).
        let mut seen_patterns = HashSet::new();
        let has_root = site.root.is_some();
        site.routes.retain(|r| {
            if !has_root
                && matches!(
                    r.handler,
                    MigratedHandler::Static | MigratedHandler::TryFiles { .. }
                )
            {
                return false;
            }
            seen_patterns.insert(r.pattern.clone())
        });

        // R6-MIG-7 & R7-MIG-3: MiraServe's router matches routes in declaration order
        // (first-match). Sort routes stably matching Nginx location precedence:
        // exact paths -> preferential `^~` prefixes -> extension routes (`*.php`) -> plain
        // prefixes -> catch-all `/*` last!
        site.routes.sort_by_key(route_specificity_key);

        if site.root.is_none() && site.routes.is_empty() {
            continue;
        }

        if site.hosts.is_empty() {
            let mut idx = kept.len().saturating_add(1);
            let fallback = loop {
                let cand = format!("site-{idx}.local");
                if used_placeholder_hosts.insert(cand.clone()) {
                    break cand;
                }
                idx = idx.saturating_add(1);
            };
            notes_to_add.push((
                None,
                "host".to_owned(),
                format!("No unique non-wildcard hostname found; assigned placeholder '{fallback}'"),
            ));
            site.hosts.push(fallback);
        }
        kept.push(site);
    }

    // Recompute listener binds from the kept sites when mixed-scope filtering withheld scoped sites,
    // using O(1) HashSet deduplication (`R5-MIG-8`).
    if mixed_scope && !allow_insecure && any_site_has_binds {
        let mut rebuilt_https = Vec::new();
        let mut rebuilt_https_set = HashSet::new();
        let mut rebuilt_http = Vec::new();
        let mut rebuilt_http_set = HashSet::new();
        for site in &kept {
            for b in &site.https_binds {
                if rebuilt_https_set.insert(b.clone()) {
                    rebuilt_https.push(b.clone());
                }
            }
            for b in &site.http_binds {
                if rebuilt_http_set.insert(b.clone()) {
                    rebuilt_http.push(b.clone());
                }
            }
        }
        // Keep any non-scoped redirect-only HTTP binds (e.g. `:80`) from redirect servers.
        for b in &doc.http_binds {
            if !is_scoped_bind(b) && rebuilt_http_set.insert(b.clone()) {
                rebuilt_http.push(b.clone());
            }
        }
        doc.https_binds = rebuilt_https;
        doc.https_binds_set = rebuilt_https_set;
        doc.http_binds = rebuilt_http;
        doc.http_binds_set = rebuilt_http_set;
    }

    for (line, directive, msg) in downgrades_to_add {
        doc.push_security_downgrade(line, directive, msg);
    }
    // R4-MIG-2 & R5-MIG-4: Never let downgrade messages claim blocked sites/routes were
    // "withheld" or "omitted" when `--allow-insecure` actually emitted those sites into `kdl`!
    if allow_insecure && kept.iter().any(|s| s.emitted_insecure) {
        for dg in &mut doc.security_downgrades {
            if dg.message.contains("site routes withheld")
                || dg.message.contains("server routes withheld")
                || dg.message.contains("sites withheld")
                || dg.message.contains("site withheld")
                || dg.message.contains("route omitted")
                || dg.message.contains("route withheld")
                || dg.message.contains("affected routes withheld")
            {
                dg.message = dg
                    .message
                    .replace(
                        "site routes withheld",
                        "EMITTED INSECURELY via --allow-insecure",
                    )
                    .replace(
                        "server routes withheld",
                        "EMITTED INSECURELY via --allow-insecure",
                    )
                    .replace(
                        "affected routes withheld",
                        "EMITTED INSECURELY via --allow-insecure",
                    )
                    .replace("sites withheld", "EMITTED INSECURELY via --allow-insecure")
                    .replace("site withheld", "EMITTED INSECURELY via --allow-insecure")
                    .replace("route omitted", "EMITTED INSECURELY via --allow-insecure")
                    .replace("route withheld", "EMITTED INSECURELY via --allow-insecure");
            }
        }
    }
    // R6-MIG-8: When a plain-HTTP-only config has scoped non-80 listeners (e.g. `127.0.0.1:8081`,
    // `10.0.0.5:8080`, `[::1]:8080`, `127.0.0.1:8088`), `render_kdl` upgrades them to TLS on the
    // same scoped address rather than widening onto public `:443`/`:80`. Always emit an explicit
    // note so the operator knows plain HTTP became TLS!
    if doc.https_binds.is_empty() && !doc.http_binds.is_empty() {
        let all_scoped = doc.http_binds.iter().all(|b| is_scoped_bind(b));
        if all_scoped {
            for b in &doc.http_binds {
                let target = promote_scoped_port80_to_https(b);
                if target == *b {
                    notes_to_add.push((
                        None,
                        "listen".to_owned(),
                        format!(
                            "Scoped plain-HTTP listener '{b}' was upgraded to HTTPS (TLS 1.3) on '{b}' (MiraServe does not serve cleartext HTTP; verify local clients use HTTPS or adjust the port)"
                        ),
                    ));
                } else {
                    notes_to_add.push((
                        None,
                        "listen".to_owned(),
                        format!(
                            "Scoped plain-HTTP listener '{b}' was paired with HTTPS on '{target}' plus HTTP->HTTPS redirect on '{b}'"
                        ),
                    ));
                }
            }
        } else {
            let has_port80 = doc
                .http_binds
                .iter()
                .any(|b| b == ":80" || b.ends_with(":80"));
            if !has_port80 {
                doc.redirect_http = false;
                notes_to_add.push((
                    None,
                    "listen".to_owned(),
                    format!(
                        "Plain-HTTP non-80 listener(s) ({}) mapped to HTTP->HTTPS redirect alongside ':443' (MiraServe requires TLS; no ':80' listener was invented)",
                        doc.http_binds.join(", ")
                    ),
                ));
            }
        }
    }

    for (line, directive, msg) in notes_to_add {
        doc.push_note(line, directive, msg);
    }

    doc.sites = kept;
}

/// Orders emitted routes matching Nginx location precedence (`R6-MIG-7`, `R7-MIG-3`):
/// - Rank 0: Exact path routes (no `*`), longer paths first
/// - Rank 1: Preferential prefix routes (`^~`, e.g. `location ^~ /files/`), longer prefixes first
/// - Rank 2: Extension routes (`*.php`, `*.php5`, etc.)
/// - Rank 3: Specific plain prefix routes (`/api/*`, `/admin/*`), longer prefixes first
/// - Rank 4: Catch-all (`/*` or `*`) ALWAYS last
fn route_specificity_key(route: &MigratedRoute) -> (u8, std::cmp::Reverse<usize>) {
    let pattern = route.pattern.as_str();
    if pattern == "/*" || pattern == "*" {
        (4, std::cmp::Reverse(0))
    } else if !pattern.contains('*') {
        (0, std::cmp::Reverse(pattern.len()))
    } else if route.preferential_prefix {
        (1, std::cmp::Reverse(pattern.len()))
    } else if pattern.starts_with("*.") {
        (2, std::cmp::Reverse(pattern.len()))
    } else {
        (3, std::cmp::Reverse(pattern.len()))
    }
}

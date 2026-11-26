//! Apache HTTP Server (`<VirtualHost>` / `apache2.conf` / `httpd.conf`) -> MiraServe KDL importer.
//!
//! Supports bounded local `Include` / `IncludeOptional` expansion when importing from disk
//! (`R4-MIG-5`, `R5-MIG-5`), backslash line continuations (`R5-MIG-6`), quote-aware argument
//! tokenization (`R5-MIG-8`), Apache 2.2 per-scope `Order`/`Allow`/`Deny` semantics (`R5-MIG-7`),
//! global `DocumentRoot` inheritance (`R5-MIG-7`), PHP execution detection (`R5-MIG-1`),
//! untranslated security-header checks (`R5-MIG-3`), location-scoped overlap tracking (`R5-MIG-4`),
//! `ProxyPass` path-rewriting downgrades (`MIG-6`), and strict fail-closed handling for
//! `Require`, `AllowOverride`, `AuthType`, `SSLVerifyClient`, `SSLRequire`, `ModSecurity`,
//! access-conditional `RewriteCond`/`RewriteRule`, blocking `RewriteRule`/`Redirect` codes, and
//! unresolvable hostname binds (`MIG-2`, `MIG-3`, `R3-MIG-5`, `R4-MIG-1`, `R4-MIG-6`, `R5-MIG-5`).

use std::collections::HashSet;
use std::path::Path;

use crate::includes::{BoundedIncludeResult, IncludeContext};
use crate::ir::{
    HeaderClassification, MigratedDoc, MigratedHandler, MigratedRoute, MigratedSite,
    PhpLocationPattern, classify_php_regex_pattern, classify_untranslated_security_header,
    has_blocking_rewrite_flag, is_routable_acme_email, is_scoped_bind,
    normalize_bind_addr_with_default_port, normalize_fastcgi_target, normalize_route_pattern,
    normalize_upstream_url, sanitize_diagnostic_text, sanitize_untrusted_directive_token,
};

#[derive(Debug, Clone, Default)]
struct Apache22AclState {
    order_allow_deny: Option<(usize, String)>,
    allow_all: bool,
    restricted_allows: Vec<(usize, String)>,
    denies: Vec<(usize, String)>,
}

impl Apache22AclState {
    fn is_empty(&self) -> bool {
        self.order_allow_deny.is_none()
            && !self.allow_all
            && self.restricted_allows.is_empty()
            && self.denies.is_empty()
    }

    /// Returns blocking Apache 2.2 ACL directives in this scope (`R5-MIG-7`).
    ///
    /// Apache 2.2's `Order allow,deny` + `Allow from all` (with zero `Deny` and zero restricted
    /// `Allow`) is the standard open-access idiom equivalent to Apache 2.4 `Require all granted`.
    /// Conversely, any `Deny`, any restricted `Allow`, or `Order allow,deny` *without*
    /// `Allow from all` (which denies by default) is a genuine access restriction!
    fn blocking_rules(&self) -> Vec<(usize, &'static str, String)> {
        let mut out = Vec::new();
        for (line, text) in &self.denies {
            out.push((*line, "Deny", text.clone()));
        }
        for (line, text) in &self.restricted_allows {
            out.push((*line, "Allow", text.clone()));
        }
        if out.is_empty()
            && !self.allow_all
            && let Some((line, text)) = &self.order_allow_deny
        {
            out.push((*line, "Order", text.clone()));
        }
        out
    }

    fn clear(&mut self) {
        self.order_allow_deny = None;
        self.allow_all = false;
        self.restricted_allows.clear();
        self.denies.clear();
    }
}

#[derive(Debug, Clone)]
enum ApacheScope {
    Directory {
        id: usize,
        path: String,
        is_literal: bool,
        blocked: bool,
        acl22: Apache22AclState,
    },
    Location {
        id: usize,
        path: String,
        is_regex: bool,
        blocked: bool,
        acl22: Apache22AclState,
    },
    Files {
        id: usize,
        pattern: String,
        is_regex: bool,
        blocked: bool,
        acl22: Apache22AclState,
    },
    Limit {
        id: usize,
    },
    Other {
        id: usize,
        acl22: Apache22AclState,
        /// `true` for a positive `<IfModule mod_x>`: its body applies in the source only when
        /// that module is loaded, which the importer cannot know.
        module_conditional: bool,
    },
}

impl ApacheScope {
    const fn id(&self) -> usize {
        match self {
            Self::Directory { id, .. }
            | Self::Location { id, .. }
            | Self::Files { id, .. }
            | Self::Limit { id }
            | Self::Other { id, .. } => *id,
        }
    }

    fn acl22_mut(&mut self) -> Option<&mut Apache22AclState> {
        match self {
            Self::Directory { acl22, .. }
            | Self::Location { acl22, .. }
            | Self::Files { acl22, .. }
            | Self::Other { acl22, .. } => Some(acl22),
            Self::Limit { .. } => None,
        }
    }
}

#[derive(Debug, Clone)]
enum GlobalDirScope {
    Root,
    Literal(String),
    /// Path glob with a non-root literal prefix (e.g. `/home/*/public_html` -> prefix `/home`, `R6-MIG-9`).
    GlobPrefix {
        prefix: String,
        pattern: String,
    },
    NonLiteral(String),
}

#[derive(Debug, Default)]
struct GlobalLocationScope {
    path: String,
    is_internal_status_or_info: bool,
    has_non_internal_handler: bool,
    acl22: Apache22AclState,
    pending_rules: Vec<(Option<String>, usize, String, String)>,
}

#[derive(Debug)]
struct PendingApacheRoute {
    pattern: String,
    handler: MigratedHandler,
    owner_scope_ids: Vec<usize>,
    /// Enclosing non-regex `<Directory>` paths that MUST cover `DocumentRoot` for a FastCGI
    /// `SetHandler` route to apply site-wide without widening execution (`R7-MIG-4`).
    enclosing_dir_paths: Vec<(String, usize)>,
}

/// Joins Apache backslash line continuations (`\` at end of line, `R5-MIG-6`) while preserving
/// each logical directive's starting 1-based line number and ignoring full-line `#` comments.
fn join_apache_continued_lines(input: &str) -> Vec<(usize, String)> {
    let mut logical_lines = Vec::new();
    let mut cur_line_no: Option<usize> = None;
    let mut cur_buf = String::new();

    for (idx, raw_line) in input.lines().enumerate() {
        let line_no = idx.saturating_add(1);
        let trimmed_end = raw_line.trim_end_matches('\r');
        let trimmed = trimmed_end.trim();

        if cur_line_no.is_none() {
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            cur_line_no = Some(line_no);
        }

        // Apache joins lines ending with a single unescaped trailing `\`.
        if let Some(without_slash) = trimmed_end.strip_suffix('\\')
            && !without_slash.ends_with('\\')
        {
            let piece = without_slash.trim();
            if !piece.is_empty() {
                if !cur_buf.is_empty() {
                    cur_buf.push(' ');
                }
                cur_buf.push_str(piece);
            }
            continue;
        }

        if !trimmed.is_empty() {
            if !cur_buf.is_empty() {
                cur_buf.push(' ');
            }
            cur_buf.push_str(trimmed);
        }
        if let Some(start_no) = cur_line_no.take() {
            let final_line = std::mem::take(&mut cur_buf);
            if !final_line.is_empty() {
                logical_lines.push((start_no, final_line));
            }
        }
    }

    if let Some(start_no) = cur_line_no
        && !cur_buf.is_empty()
    {
        logical_lines.push((start_no, cur_buf));
    }
    logical_lines
}

/// Quote-aware Apache directive argument tokenizer (`R5-MIG-8`: preserves spaces inside
/// `DocumentRoot "/var/www/my site"` and escaped quotes `\"`).
fn tokenize_apache_line(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut chars = line.chars().peekable();

    while let Some(&ch) = chars.peek() {
        if ch.is_whitespace() {
            chars.next();
            continue;
        }
        if ch == '"' || ch == '\'' {
            let quote = ch;
            chars.next();
            let mut tok = String::new();
            while let Some(c) = chars.next() {
                if c == '\\'
                    && quote == '"'
                    && let Some(&next_c) = chars.peek()
                    && matches!(next_c, '"' | '\\')
                {
                    tok.push(next_c);
                    chars.next();
                    continue;
                }
                if c == quote {
                    break;
                }
                tok.push(c);
            }
            tokens.push(tok);
        } else {
            let mut tok = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() {
                    break;
                }
                tok.push(c);
                chars.next();
            }
            if !tok.is_empty() {
                tokens.push(tok);
            }
        }
    }
    tokens
}

fn contains_apache_env_var(raw: &str) -> bool {
    raw.find("${").is_some_and(|idx| {
        raw.get(idx.saturating_add(2)..)
            .is_some_and(|r| r.contains('}'))
    })
}

fn canonicalize_include_path(raw: &str) -> Option<String> {
    let clean = raw.trim().trim_matches('"').trim_matches('\'');
    if clean.is_empty() || clean.contains('\\') {
        return None;
    }
    let mut parts: Vec<&str> = Vec::new();
    let is_abs = clean.starts_with('/');
    for seg in clean.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return None;
        }
        parts.push(seg);
    }
    if parts.is_empty() {
        return None;
    }
    // R4-MIG-5: Case-sensitive canonical path so `/etc/apache2/Mods-Enabled/*.conf` never matches.
    let joined = parts.join("/");
    if is_abs {
        Some(format!("/{joined}"))
    } else {
        Some(joined)
    }
}

/// Strictly canonical, case-sensitive non-ACL stock Apache/Certbot TLS and module include paths
/// (`R4-MIG-5`, `R5-MIG-5`). `ports.conf` is intentionally NOT on this list because it defines
/// `Listen` address scoping!
fn is_safe_apache_include_target(target: &str) -> bool {
    let Some(canon) = canonicalize_include_path(target) else {
        return false;
    };
    matches!(
        canon.as_str(),
        "mods-enabled/*.load"
            | "mods-enabled/*.conf"
            | "/etc/apache2/mods-enabled/*.load"
            | "/etc/apache2/mods-enabled/*.conf"
            | "conf.modules.d/*.conf"
            | "/etc/httpd/conf.modules.d/*.conf"
            | "/etc/letsencrypt/options-ssl-apache.conf"
    )
}

fn is_ports_conf_include_target(target: &str) -> bool {
    let Some(canon) = canonicalize_include_path(target) else {
        return false;
    };
    matches!(canon.as_str(), "ports.conf" | "/etc/apache2/ports.conf")
}

/// Expands bounded local Apache `Include` / `IncludeOptional` directives when importing from a
/// file on disk (`R4-MIG-5`, `R5-MIG-5`, `R5-MIG-7`), tagging each line with its included file
/// name (`R6-MIG-11`).
fn expand_apache_lines(
    input: &str,
    current_file: Option<&str>,
    inc_ctx: Option<&mut IncludeContext>,
    doc: &mut MigratedDoc,
) -> Vec<(Option<String>, usize, String)> {
    let logical = join_apache_continued_lines(input);
    let Some(ctx) = inc_ctx else {
        return logical
            .into_iter()
            .map(|(line_no, line)| (current_file.map(str::to_owned), line_no, line))
            .collect();
    };

    let mut out = Vec::with_capacity(logical.len());
    for (line_no, line) in logical {
        let toks = tokenize_apache_line(&line);
        let Some(first) = toks.first() else {
            continue;
        };
        let lower = first.to_ascii_lowercase();
        if (lower == "include" || lower == "includeoptional")
            && let Some(target) = toks.get(1)
        {
            let optional = lower == "includeoptional";
            match ctx.expand(target, optional) {
                BoundedIncludeResult::Expanded(files) => {
                    let prev_file = doc.set_source_file(current_file.map(str::to_owned));
                    let safe_target = sanitize_diagnostic_text(target, 120);
                    doc.push_note(
                        Some(line_no),
                        first.clone(),
                        format!(
                            "Expanded Apache `{first} {safe_target}` from local config tree ({} file(s))",
                            files.len()
                        ),
                    );
                    doc.set_source_file(prev_file);
                    for (canon_path, content) in files {
                        if !ctx.enter(canon_path.clone()) {
                            out.push((current_file.map(str::to_owned), line_no, line.clone()));
                            continue;
                        }
                        let label = canon_path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .map_or_else(|| canon_path.display().to_string(), str::to_owned);
                        let sub_lines = expand_apache_lines(&content, Some(&label), Some(ctx), doc);
                        out.extend(sub_lines);
                        ctx.leave(&canon_path);
                    }
                    continue;
                }
                BoundedIncludeResult::Unavailable => {}
            }
        }
        out.push((current_file.map(str::to_owned), line_no, line));
    }
    out
}

/// Returns `true` for Apache stock dotfile `<Files>` / `<FilesMatch>` patterns (`.ht*`, `^\.ht`,
/// `^\.ph(ar|p|ps|tml)$`) or stock PHP-source denial patterns (`.+\.phps$`, `\.phps$`) that
/// MiraServe's `StaticServer` natively refuses by default (`R4-MIG-3`, `R6-MIG-9`).
fn is_apache_dotfile_files_pattern(pattern: &str) -> bool {
    let clean = pattern.trim().trim_matches('"').trim_matches('\'');
    if matches!(
        clean,
        ".ht*"
            | "^\\.ht"
            | "^\\.ht.*"
            | "^\\.ht$"
            | "^\\.ht.*$"
            | "~ \"^\\.ht\""
            | "~ ^\\.ht"
            | "^\\.ph(ar|p|ps|tml)$"
            | "^\\.ph(p|ps|ar|tml)$"
            | "^\\.php$"
            | "^\\.phps$"
    ) {
        return true;
    }
    // Stock Debian PHP packages ship `<FilesMatch ".+\.phps$"> Require all denied </FilesMatch>`.
    if let PhpLocationPattern::Extensions(exts) = classify_php_regex_pattern(clean)
        && !exts.is_empty()
        && exts.iter().all(|e| {
            matches!(
                e.as_str(),
                "*.php"
                    | "*.phtml"
                    | "*.phar"
                    | "*.phps"
                    | "*.php5"
                    | "*.php7"
                    | "*.php8"
                    | "*.pht"
                    | "*.phpt"
                    | "*.inc"
            )
        })
    {
        return true;
    }
    false
}

/// Returns `true` if `Redirect` / `RedirectMatch` arguments specify a blocking 4xx/5xx status
/// (`R3-MIG-5`, `R4-MIG-6`, `R5-MIG-6`).
fn is_apache_blocking_redirect(args: &[String]) -> bool {
    args.first().is_some_and(|first| {
        let lower = first.to_ascii_lowercase();
        matches!(lower.as_str(), "gone" | "forbidden")
            || lower
                .parse::<u16>()
                .is_ok_and(|status| (400..=599).contains(&status))
    })
}

/// Parses the tag name and raw argument of an Apache `<Tag arg>` opening section line.
fn parse_apache_section_open(line: &str) -> Option<(String, String)> {
    let inner = line.strip_prefix('<')?.strip_suffix('>')?.trim();
    if inner.is_empty() || inner.starts_with('/') {
        return None;
    }
    let split_idx = inner.find(char::is_whitespace).unwrap_or(inner.len());
    let tag = inner.get(..split_idx)?.to_ascii_lowercase();
    let arg = inner.get(split_idx..).unwrap_or("").trim().to_owned();
    Some((tag, arg))
}

/// Classifies a `<Directory ...>` or `<DirectoryMatch ...>` argument as root, literal path, or
/// non-literal (regex, wildcard, or unparseable) (`R4-MIG-1`).
fn classify_directory_scope(tag: &str, raw_arg: &str) -> GlobalDirScope {
    if tag == "directorymatch" {
        return GlobalDirScope::NonLiteral(raw_arg.to_owned());
    }
    let trimmed = raw_arg.trim();
    if trimmed.is_empty() {
        return GlobalDirScope::NonLiteral(String::new());
    }
    if trimmed == "~"
        || trimmed.starts_with("~ ")
        || trimmed.starts_with("~\t")
        || trimmed.starts_with("~\"")
    {
        return GlobalDirScope::NonLiteral(trimmed.to_owned());
    }
    let unquoted = if let Some(inner) = trimmed.strip_prefix('"').and_then(|s| s.strip_suffix('"'))
    {
        if inner.contains('"') {
            return GlobalDirScope::NonLiteral(trimmed.to_owned());
        }
        inner
    } else if let Some(inner) = trimmed
        .strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
    {
        if inner.contains('\'') {
            return GlobalDirScope::NonLiteral(trimmed.to_owned());
        }
        inner
    } else {
        if trimmed.chars().any(char::is_whitespace) || trimmed.contains('"') {
            return GlobalDirScope::NonLiteral(trimmed.to_owned());
        }
        trimmed
    };

    if unquoted.is_empty() || !unquoted.starts_with('/') {
        return GlobalDirScope::NonLiteral(trimmed.to_owned());
    }
    if unquoted
        .chars()
        .any(|c| matches!(c, '*' | '?' | '[' | ']' | '^' | '$' | '|'))
    {
        // R6-MIG-9: Preserve a non-root literal path prefix on simple globs such as RHEL stock
        // `<Directory "/home/*/public_html">` so it only constrains sites under `/home/...`
        // rather than blocking `/var/www/html`!
        let mut lit_segs = Vec::new();
        for seg in unquoted.split('/').skip(1) {
            if seg.is_empty() {
                continue;
            }
            if seg
                .chars()
                .any(|c| matches!(c, '*' | '?' | '[' | ']' | '^' | '$' | '|'))
            {
                break;
            }
            lit_segs.push(seg);
        }
        if !lit_segs.is_empty() {
            return GlobalDirScope::GlobPrefix {
                prefix: format!("/{}", lit_segs.join("/")),
                pattern: unquoted.to_owned(),
            };
        }
        return GlobalDirScope::NonLiteral(trimmed.to_owned());
    }
    let clean = unquoted.trim_end_matches('/');
    if clean.is_empty() {
        GlobalDirScope::Root
    } else {
        GlobalDirScope::Literal(clean.to_owned())
    }
}

/// R4-MIG-1: Returns `true` when EITHER path equals or is an ancestor of the other so BOTH
/// `<Directory /var/www>` covering `DocumentRoot /var/www/site` AND `<Directory /var/www/site/admin>`
/// inside `DocumentRoot /var/www/site` match!
fn dir_paths_overlap(dir_path: &str, site_root: &str) -> bool {
    let d = dir_path.trim_end_matches('/');
    let r = site_root.trim_end_matches('/');
    if d.is_empty() || r.is_empty() {
        return false;
    }
    r == d
        || r.strip_prefix(d).is_some_and(|rest| rest.starts_with('/'))
        || d.strip_prefix(r).is_some_and(|rest| rest.starts_with('/'))
}

fn clean_apache_host(raw: &str) -> String {
    let stripped = raw.trim().trim_matches('"');
    let without_scheme = stripped
        .strip_prefix("https://")
        .or_else(|| stripped.strip_prefix("http://"))
        .unwrap_or(stripped);
    if without_scheme.starts_with('[') {
        without_scheme
            .split(']')
            .next()
            .map_or_else(String::new, |s| s.trim_start_matches('[').to_owned())
    } else if let Some((host, port)) = without_scheme.rsplit_once(':')
        && port.parse::<u16>().is_ok()
    {
        host.to_owned()
    } else {
        without_scheme.to_owned()
    }
}

fn is_wordpress_indicator_path(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    lower.contains("wordpress")
        || lower.contains("wp-content")
        || lower.contains("wp-includes")
        || lower.contains("wp-config.php")
        || lower.contains("xmlrpc.php")
        || lower.contains("wp-login.php")
        || lower.contains("wp-admin")
}

fn is_php_filename(tok: &str) -> bool {
    Path::new(tok.trim()).extension().is_some_and(|ext| {
        ext.eq_ignore_ascii_case("php")
            || ext.eq_ignore_ascii_case("phtml")
            || ext.eq_ignore_ascii_case("phar")
    })
}

/// Returns `true` when an Apache `RewriteCond` tests an access/client/auth/header/method/TLS
/// attribute rather than a benign host/HTTPS/file-existence check (`R5-MIG-6`).
fn is_access_control_rewrite_cond(args_joined: &str) -> bool {
    let upper = args_joined.to_ascii_uppercase();
    upper.contains("%{REMOTE_ADDR}")
        || upper.contains("%{REMOTE_HOST}")
        || upper.contains("%{REMOTE_USER}")
        || upper.contains("%{CONN_REMOTE_ADDR}")
        || upper.contains("%{SSL_")
        || upper.contains("%{HTTP_AUTHORIZATION}")
        || upper.contains("%{HTTP:AUTHORIZATION}")
        || upper.contains("%{HTTP_COOKIE}")
        || upper.contains("%{HTTP:COOKIE}")
        || upper.contains("%{REQUEST_METHOD}")
        || upper.contains("%{HTTP_USER_AGENT}")
        || upper.contains("%{HTTP_REFERER}")
        || upper.contains("%{HTTP_X_")
        || upper.contains("%{HTTP:X-")
        || upper.contains("%{QUERY_STRING}")
        || upper.contains("%{ENV:")
}

/// Returns `true` when an Apache `RewriteRule` is a pure HTTP->HTTPS redirect (e.g. Certbot's
/// `RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]`).
fn is_https_redirect_rewrite_rule(args: &[String], line: &str) -> bool {
    let targets_https = args.get(1).is_some_and(|t| t.starts_with("https://"));
    if !targets_https {
        return false;
    }
    let upper = line.to_ascii_uppercase();
    upper.contains("R=301")
        || upper.contains("R=302")
        || upper.contains("R=307")
        || upper.contains("R=308")
        || upper.contains("R=PERMANENT")
        || upper.contains("R=TEMP")
        || upper.contains("[R]")
        || upper.contains("[R,")
        || upper.contains(",R]")
        || upper.contains(",R,")
}

/// Returns `true` when `dir_path` covers the entire `site_root` (i.e. `dir_path` is `/`, equals
/// `site_root`, or is an ancestor directory of `site_root`), so a `<Directory>`-scoped handler
/// does NOT narrow execution to a subdirectory of `DocumentRoot` (`R7-MIG-4`).
fn dir_covers_docroot(dir_path: &str, site_root: &str) -> bool {
    let dir_norm = dir_path.trim().trim_end_matches('/');
    let root_norm = site_root.trim().trim_end_matches('/');
    if dir_norm.is_empty() {
        return true; // `<Directory />` covers every path
    }
    if root_norm.is_empty() {
        return false;
    }
    dir_norm == root_norm
        || root_norm
            .strip_prefix(dir_norm)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Parses Apache `Header [always|onsuccess] <action> <header-name> [value...]` (`R5-MIG-3`,
/// `R6-MIG-5`, `R7-MIG-12`). Default-refuses any security/unknown header mutation not covered by
/// MiraServe's `security-headers "strict"`, while returning `SafeToDropWithNote` for benign
/// caching/diagnostic headers.
fn check_apache_security_header(args: &[String]) -> Option<(String, HeaderClassification)> {
    let mut idx = 0_usize;
    if let Some(first) = args.first()
        && (first.eq_ignore_ascii_case("always") || first.eq_ignore_ascii_case("onsuccess"))
    {
        idx = 1;
    }
    let action = args.get(idx)?.to_ascii_lowercase();
    let hdr_name = args.get(idx.saturating_add(1))?;
    match action.as_str() {
        "edit" | "edit*" => Some((
            hdr_name.clone(),
            HeaderClassification::SecurityDowngrade(
                "Apache `Header edit` / `edit*` response header rewrite (e.g. Set-Cookie flags) cannot be auto-translated",
            ),
        )),
        "unset" => {
            if matches!(
                hdr_name.to_ascii_lowercase().as_str(),
                "server" | "x-powered-by"
            ) {
                None
            } else {
                Some((
                    hdr_name.clone(),
                    HeaderClassification::SecurityDowngrade(
                        "Apache `Header unset` cannot be auto-translated by MiraServe `security-headers \"strict\"`",
                    ),
                ))
            }
        }
        "set" | "append" | "add" | "merge" | "setifempty" | "note" => {
            let hdr_val = args
                .get(idx.saturating_add(2)..)
                .map_or_else(String::new, |s| s.join(" "));
            match classify_untranslated_security_header(hdr_name, &hdr_val) {
                HeaderClassification::CoveredByStrict => None,
                other => Some((hdr_name.clone(), other)),
            }
        }
        _ => Some((
            hdr_name.clone(),
            HeaderClassification::SecurityDowngrade(
                "Apache `Header` action cannot be auto-translated",
            ),
        )),
    }
}

/// Strips any URI path from an Apache `ProxyPass` target so MiraServe receives a clean
/// `scheme://host[:port]` upstream URL, and emits a security downgrade (`MIG-6`) when the
/// target URI path differs from the matched `ProxyPass` prefix (path rewriting / prefix stripping).
fn resolve_apache_proxy_target(
    route_path: &str,
    raw_target: &str,
    line_no: usize,
    doc: &mut MigratedDoc,
) -> String {
    let normalized = normalize_upstream_url(raw_target);
    let after_scheme = normalized
        .strip_prefix("https://")
        .or_else(|| normalized.strip_prefix("http://"))
        .unwrap_or(&normalized);

    let (host_part, path_part) = match after_scheme.split_once('/') {
        Some((h, rest)) => (h, Some(format!("/{rest}"))),
        None => (after_scheme, None),
    };
    if let Some(suffix) = path_part.as_deref()
        && !suffix.is_empty()
    {
        let norm_route = route_path.trim_end_matches('/');
        let norm_suffix = suffix.trim_end_matches('/');
        if norm_suffix != norm_route {
            doc.push_security_downgrade(
                Some(line_no),
                "ProxyPass",
                format!(
                    "Apache `ProxyPass {route_path} {raw_target}` rewrites/strips path prefix '{route_path}' to '{suffix}'; MiraServe forwards the original request path unchanged — adjust upstream routing before cutover"
                ),
            );
        }
    }

    let scheme = if normalized.starts_with("https://") {
        "https://"
    } else {
        "http://"
    };
    format!("{scheme}{host_part}")
}

fn record_apache22_directive(
    state: &mut Apache22AclState,
    dir_lower: &str,
    args: &[String],
    line_no: usize,
    line: &str,
) {
    let joined = args.join(" ").to_ascii_lowercase();
    match dir_lower {
        "order" => {
            let compact: String = joined.chars().filter(|c| !c.is_whitespace()).collect();
            if compact == "allow,deny" {
                state.order_allow_deny = Some((line_no, line.to_owned()));
            }
        }
        "allow" => {
            if joined == "from all" {
                state.allow_all = true;
            } else {
                state.restricted_allows.push((line_no, line.to_owned()));
            }
        }
        "deny" => {
            state.denies.push((line_no, line.to_owned()));
        }
        _ => {}
    }
}

fn is_global_apache_security_rule(
    directive: &str,
    args: &[String],
    args_joined: &str,
    line: &str,
) -> bool {
    (directive == "require" && !args_joined.eq_ignore_ascii_case("all granted"))
        || (directive == "allowoverride" && !args_joined.eq_ignore_ascii_case("none"))
        || (directive == "sslverifyclient" && !args_joined.eq_ignore_ascii_case("none"))
        || (directive == "secruleengine" && !args_joined.eq_ignore_ascii_case("off"))
        || (directive == "rewriterule" && has_blocking_rewrite_flag(line))
        || (matches!(directive, "redirect" | "redirectmatch") && is_apache_blocking_redirect(args))
        || matches!(
            directive,
            "authtype"
                | "authuserfile"
                | "authgroupfile"
                | "authrequire"
                | "sslrequire"
                | "sslrequiressl"
                | "secrule"
                | "secaction"
                | "secdefaultaction"
                | "php_admin_value"
                | "php_admin_flag"
                | "php_value"
                | "php_flag"
        )
}

fn is_stock_generic_directory_index(args: &[String]) -> bool {
    let first_is_html = args
        .first()
        .is_some_and(|a| a.eq_ignore_ascii_case("index.html"));
    let has_non_php_script = args
        .iter()
        .any(|a| a.eq_ignore_ascii_case("index.cgi") || a.eq_ignore_ascii_case("index.pl"));
    first_is_html && has_non_php_script
}

/// Resolves an Apache `<Files ...>` or `<FilesMatch ...>` pattern into concrete MiraServe route
/// patterns (`R6-MIG-2`, `R6-MIG-3`), failing closed if the pattern cannot be represented
/// faithfully without widening or narrowing execution.
fn resolve_apache_files_pattern(
    pattern: &str,
    is_regex: bool,
) -> Result<Vec<String>, &'static str> {
    let raw = pattern.trim();
    let (effective_regex, clean) = if is_regex {
        (true, raw.trim_start_matches('~').trim())
    } else if let Some(rest) = raw.strip_prefix('~') {
        (true, rest.trim())
    } else {
        (false, raw)
    };
    let clean = clean.trim_matches('"').trim_matches('\'');
    if effective_regex {
        match classify_php_regex_pattern(clean) {
            PhpLocationPattern::Extensions(exts) if !exts.is_empty() => Ok(exts),
            PhpLocationPattern::ExactPaths(_) => Err(
                "Apache `<FilesMatch>` matches basenames across directories and cannot be faithfully translated to exact URL routes",
            ),
            PhpLocationPattern::Extensions(_) | PhpLocationPattern::Untranslatable => Err(
                "Apache `<FilesMatch>` pattern cannot be faithfully translated to MiraServe extension matchers without widening or narrowing execution",
            ),
        }
    } else if let Some(ext) = clean.strip_prefix("*.")
        && !ext.is_empty()
        && ext.len() <= 16
        && ext.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        Ok(vec![format!("*.{}", ext.to_ascii_lowercase())])
    } else {
        Err(
            "Apache `<Files>` pattern cannot be faithfully translated to a MiraServe extension route without widening execution",
        )
    }
}

/// Resolves the FULL enclosing `<Directory>`/`<Location>`/`<FilesMatch>`/`<Files>` scope stack
/// for an Apache `SetHandler proxy:fcgi...` directive (`R6-MIG-2`, `R6-MIG-3`, `R7-MIG-4`).
///
/// Refuses any `<DirectoryMatch>`, any enclosing non-root `<Location>`/`<LocationMatch>` around
/// `<FilesMatch>`, and returns all enclosing literal `<Directory>` paths so callers verify they
/// cover the vhost's `DocumentRoot` (preventing `<Directory /var/www/d/app><FilesMatch \.php$>`
/// from widening to site-wide `*.php`!).
fn resolve_apache_sethandler_patterns(
    scopes: &[ApacheScope],
) -> Result<(Vec<String>, Vec<String>), &'static str> {
    let mut enclosing_dirs: Vec<String> = Vec::new();
    let mut inner_patterns: Option<Vec<String>> = None;
    let mut matched_idx: Option<usize> = None;

    for (idx, scope) in scopes.iter().enumerate().rev() {
        match scope {
            ApacheScope::Files {
                pattern, is_regex, ..
            } => {
                inner_patterns = Some(resolve_apache_files_pattern(pattern, *is_regex)?);
                matched_idx = Some(idx);
                break;
            }
            ApacheScope::Location { path, is_regex, .. } => {
                if *is_regex {
                    let pats = match classify_php_regex_pattern(path) {
                        PhpLocationPattern::Extensions(exts) if !exts.is_empty() => exts,
                        PhpLocationPattern::ExactPaths(paths) if !paths.is_empty() => paths,
                        _ => {
                            return Err(
                                "Apache `<LocationMatch>` PHP pattern cannot be faithfully translated without widening or narrowing execution",
                            );
                        }
                    };
                    inner_patterns = Some(pats);
                    matched_idx = Some(idx);
                    break;
                }
                let trimmed = path.trim();
                if trimmed.starts_with('/') && !trimmed.contains('*') && is_php_filename(trimmed) {
                    inner_patterns = Some(vec![trimmed.to_owned()]);
                    matched_idx = Some(idx);
                    break;
                }
                return Err(
                    "Apache `<Location>` `SetHandler proxy:fcgi` on a prefix cannot be faithfully translated without changing handler scope",
                );
            }
            ApacheScope::Directory {
                path, is_literal, ..
            } => {
                if !*is_literal {
                    return Err(
                        "Apache `<DirectoryMatch>` or wildcard `<Directory>` scoping `SetHandler proxy:fcgi` cannot be translated without widening PHP execution",
                    );
                }
                enclosing_dirs.push(path.clone());
            }
            ApacheScope::Limit { .. } | ApacheScope::Other { .. } => {}
        }
    }

    let Some(patterns) = inner_patterns else {
        return Err(
            "Apache `SetHandler proxy:fcgi` outside `<FilesMatch>`/`<Location>` applies to every resource and cannot be safely narrowed to `*.php`",
        );
    };

    // R7-MIG-4: Inspect EVERY outer scope enclosing the matched `<FilesMatch>` / `<Location>`!
    if let Some(m_idx) = matched_idx {
        for outer in scopes.get(..m_idx).unwrap_or(&[]) {
            match outer {
                ApacheScope::Directory {
                    path, is_literal, ..
                } => {
                    if !*is_literal {
                        return Err(
                            "Apache `<DirectoryMatch>` or wildcard `<Directory>` enclosing `<FilesMatch>`/`SetHandler` narrows PHP execution and cannot be translated to site-wide `*.php`",
                        );
                    }
                    enclosing_dirs.push(path.clone());
                }
                ApacheScope::Location { path, is_regex, .. } => {
                    if *is_regex || path.trim() != "/" {
                        return Err(
                            "Apache `<Location>`/`<LocationMatch>` enclosing `<FilesMatch>`/`SetHandler` narrows PHP execution to a URL subset and cannot be translated to site-wide `*.php`",
                        );
                    }
                }
                ApacheScope::Files { .. } => {
                    return Err(
                        "Nested Apache `<Files>`/`<FilesMatch>` scoping `SetHandler` cannot be translated faithfully without widening execution",
                    );
                }
                ApacheScope::Limit { .. } | ApacheScope::Other { .. } => {}
            }
        }
    }

    Ok((patterns, enclosing_dirs))
}

/// Parses Apache `<VirtualHost ...>` and top-level `apache2.conf`/`httpd.conf` directives into
/// an unfinalized [`MigratedDoc`] (`lib.rs` runs `finalize_doc_with_options`), expanding bounded
/// local `Include`/`IncludeOptional` directives when `source_path` is provided (`R5-MIG-5`,
/// `R7-MIG-13`).
#[allow(clippy::too_many_lines)]
pub(crate) fn parse_apache_raw_with_path(
    input: &str,
    source_path: Option<&Path>,
    source_root: Option<&Path>,
) -> MigratedDoc {
    let mut doc = MigratedDoc::new();
    let mut inc_ctx =
        source_path.and_then(|p| IncludeContext::from_source_path(p, true, source_root));
    let logical_lines = expand_apache_lines(input, None, inc_ctx.as_mut(), &mut doc);

    let mut in_vhost = false;
    let mut saw_vhost = false;
    let mut current_site = MigratedSite::default();
    let mut current_vhost_has_ssl = false;
    let mut current_vhost_php: Option<(usize, String)> = None;
    let mut current_vhost_acl22 = Apache22AclState::default();
    let mut current_vhost_dir_blocks: Vec<(String, bool, usize, String)> = Vec::new();
    let mut default_site = MigratedSite::default();
    let mut default_php_indicator: Option<(usize, String)> = None;
    let mut global_fcgi_routes: Vec<(MigratedRoute, Option<(String, usize)>)> = Vec::new();
    let mut pending_routes: Vec<PendingApacheRoute> = Vec::new();
    let mut scopes: Vec<ApacheScope> = Vec::new();
    let mut next_scope_id: usize = 1;
    let mut vhost_binds: Vec<(String, u16)> = Vec::new();
    let mut site_raw_binds: Vec<(Vec<(String, u16)>, bool)> = Vec::new();
    let mut redirect_raw_binds: Vec<(String, u16)> = Vec::new();
    let mut global_binds: Vec<(String, u16)> = Vec::new();
    let mut global_https_ports: HashSet<u16> = HashSet::new();
    let mut global_block_reasons: Vec<(usize, String)> = Vec::new();
    // R8-MIG-1 & R8-MIG-8: literal URL prefixes that a global `Alias`/`ScriptAlias` maps outside
    // the document-root lookup; every site answers 404 under them instead of falling through.
    let mut global_closed_prefixes: Vec<(usize, String, String)> = Vec::new();
    // Server-wide `ProxyPreserveHost`, inherited by every virtual host that does not set its own.
    let mut global_preserve_host = false;
    let mut global_dir_scope: Option<GlobalDirScope> = None;
    let mut global_dir_acl22 = Apache22AclState::default();
    let mut global_files_scope: Option<(String, bool)> = None;
    let mut global_location_scope: Option<GlobalLocationScope> = None;
    let mut global_dir_restrictions: Vec<(String, bool, Option<String>, usize, String, String)> =
        Vec::new();
    let mut unread_ports_conf: Option<(usize, String)> = None;
    let mut has_root_https_redirect = false;
    let mut has_non_redirect_content = false;
    let mut pending_access_rewrite_cond: Option<(usize, String)> = None;
    let mut global_pending_access_rewrite_cond: Option<(usize, String)> = None;

    for (source_file, line_no, line) in logical_lines {
        doc.set_source_file(source_file.clone());
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("<virtualhost") {
            in_vhost = true;
            saw_vhost = true;
            current_site = MigratedSite::default();
            current_vhost_has_ssl = false;
            current_vhost_php = None;
            current_vhost_acl22.clear();
            current_vhost_dir_blocks.clear();
            pending_routes.clear();
            scopes.clear();
            vhost_binds.clear();
            has_root_https_redirect = false;
            has_non_redirect_content = false;
            pending_access_rewrite_cond = None;

            if let Some(inner) = line
                .strip_prefix('<')
                .and_then(|s| s.strip_suffix('>'))
                .map(str::trim)
            {
                for addr_tok in inner.split_whitespace().skip(1) {
                    if contains_apache_env_var(addr_tok) {
                        current_site.block_site(Some(line_no), "VirtualHost");
                        doc.push_security_downgrade(
                            Some(line_no),
                            "VirtualHost",
                            format!(
                                "Apache `<VirtualHost {addr_tok}>` contains unexpanded variable(s) and cannot be resolved safely; site withheld"
                            ),
                        );
                    } else if let Some((bind, port)) =
                        normalize_bind_addr_with_default_port(addr_tok, 443)
                    {
                        vhost_binds.push((bind, port));
                    } else {
                        // R5-MIG-5: Never silently drop `<VirtualHost internal.corp:80>`!
                        current_site.block_site(Some(line_no), "VirtualHost");
                        doc.push_security_downgrade(
                            Some(line_no),
                            "VirtualHost",
                            format!(
                                "Apache `<VirtualHost {addr_tok}>` uses a hostname or unsupported bind address that cannot be resolved safely; site withheld to prevent unintended public exposure"
                            ),
                        );
                    }
                }
            }
            continue;
        }
        if lower.starts_with("</virtualhost") {
            if in_vhost {
                // Flush any vhost-level Apache 2.2 ACL directives.
                for (acl_line, acl_dir, acl_text) in current_vhost_acl22.blocking_rules() {
                    current_site.block_site(Some(acl_line), acl_dir);
                    doc.push_security_downgrade(
                        Some(acl_line),
                        acl_dir,
                        format!(
                            "Apache 2.2 access rule `{acl_text}` (<VirtualHost>) cannot be auto-translated; site routes withheld"
                        ),
                    );
                }
                current_vhost_acl22.clear();

                let is_redirect_only = has_root_https_redirect && !has_non_redirect_content;
                if is_redirect_only {
                    doc.redirect_http = true;
                    redirect_raw_binds.append(&mut vhost_binds);
                } else {
                    // R5-MIG-7: Inherit global `DocumentRoot` / `ServerName` when a `<VirtualHost>`
                    // omits them (standard RHEL `httpd.conf` + `conf.d/ssl.conf` layout).
                    if current_site.root.is_none() && default_site.root.is_some() {
                        current_site.root.clone_from(&default_site.root);
                        current_site.wordpress |= default_site.wordpress;
                        if current_vhost_php.is_none() {
                            current_vhost_php.clone_from(&default_php_indicator);
                        }
                    }
                    if current_site.hosts.is_empty() && !default_site.hosts.is_empty() {
                        current_site.hosts.clone_from(&default_site.hosts);
                    }

                    // Re-check any `<Directory>` restrictions inside `<VirtualHost>` that appeared
                    // before `DocumentRoot` (or inherited global `DocumentRoot`).
                    for (dir_path, is_literal, dir_line, dir_name) in
                        current_vhost_dir_blocks.drain(..)
                    {
                        if !is_literal
                            || dir_path == "/"
                            || current_site
                                .root
                                .as_deref()
                                .is_none_or(|r| dir_paths_overlap(&dir_path, r))
                        {
                            current_site.block_site(Some(dir_line), &dir_name);
                        }
                    }

                    for pr in pending_routes.drain(..) {
                        if !pr.enclosing_dir_paths.is_empty()
                            && matches!(pr.handler, MigratedHandler::FastCgi { .. })
                        {
                            let mut narrowed_dir: Option<(String, usize)> = None;
                            for (dir_path, dir_line) in &pr.enclosing_dir_paths {
                                let covers = current_site
                                    .root
                                    .as_deref()
                                    .is_some_and(|r| dir_covers_docroot(dir_path, r));
                                if !covers {
                                    narrowed_dir = Some((dir_path.clone(), *dir_line));
                                    break;
                                }
                            }
                            if let Some((dir_path, dir_line)) = narrowed_dir {
                                current_site.block_site(Some(dir_line), "SetHandler (Directory)");
                                doc.push_security_downgrade(
                                    Some(dir_line),
                                    "SetHandler",
                                    format!(
                                        "Apache `<Directory {dir_path}>` scoping `SetHandler proxy:fcgi` is narrower than DocumentRoot ({}); refusing to widen PHP execution to site-wide '{}'",
                                        current_site.root.as_deref().unwrap_or("<unset>"),
                                        pr.pattern
                                    ),
                                );
                                continue;
                            }
                        }
                        current_site
                            .routes
                            .push(MigratedRoute::new(pr.pattern, pr.handler));
                    }

                    // Inherit global PHP-FPM FastCGI routes (e.g. Debian `conf-enabled/php8.2-fpm.conf`)
                    // when the vhost does not define its own FastCGI routes (`R6-MIG-9`), refusing
                    // any global `<Directory>`-scoped FastCGI narrower than this vhost's DocumentRoot (`R7-MIG-4`).
                    if !global_fcgi_routes.is_empty()
                        && !current_site
                            .routes
                            .iter()
                            .any(|r| matches!(r.handler, MigratedHandler::FastCgi { .. }))
                    {
                        for (route, enclosing_dir) in &global_fcgi_routes {
                            if let Some((dir_path, dir_line)) = enclosing_dir {
                                let covers = current_site
                                    .root
                                    .as_deref()
                                    .is_some_and(|r| dir_covers_docroot(dir_path, r));
                                if !covers {
                                    if current_site
                                        .root
                                        .as_deref()
                                        .is_some_and(|r| dir_paths_overlap(dir_path, r))
                                    {
                                        current_site
                                            .block_site(Some(*dir_line), "SetHandler (Directory)");
                                        doc.push_security_downgrade(
                                            Some(*dir_line),
                                            "SetHandler",
                                            format!(
                                                "Global Apache `<Directory {dir_path}>` scoping `SetHandler proxy:fcgi` is narrower than DocumentRoot ({}); refusing to widen PHP execution site-wide",
                                                current_site.root.as_deref().unwrap_or("<unset>")
                                            ),
                                        );
                                    }
                                    continue;
                                }
                            }
                            current_site.routes.push(route.clone());
                        }
                    }

                    // R5-MIG-1: Fail closed if this site indicates PHP execution without any
                    // emitted FastCGI route!
                    if let Some((php_line, php_src)) = current_vhost_php.take()
                        && !current_site
                            .routes
                            .iter()
                            .any(|r| matches!(r.handler, MigratedHandler::FastCgi { .. }))
                    {
                        current_site.block_site(Some(php_line), "php");
                        doc.push_security_downgrade(
                            Some(php_line),
                            "php",
                            format!(
                                "Apache site indicates PHP execution ({php_src}) but no FastCGI route was emitted; configure `php-fpm` with `fastcgi-pass` manually"
                            ),
                        );
                    }

                    let vhost_ssl = current_vhost_has_ssl
                        || (current_site.cert.is_some() && current_site.key.is_some());
                    site_raw_binds.push((std::mem::take(&mut vhost_binds), vhost_ssl));
                    doc.sites.push(std::mem::take(&mut current_site));
                }
            }
            in_vhost = false;
            scopes.clear();
            pending_access_rewrite_cond = None;
            continue;
        }

        if !in_vhost {
            if lower.starts_with("</directory") {
                if !global_dir_acl22.is_empty() {
                    for (acl_line, acl_dir, acl_text) in global_dir_acl22.blocking_rules() {
                        record_global_dir_or_site_block(
                            global_dir_scope.as_ref(),
                            global_files_scope.as_ref().map(|(p, _)| p.as_str()),
                            source_file.as_deref(),
                            acl_line,
                            acl_dir,
                            &acl_text,
                            &mut global_dir_restrictions,
                            &mut global_block_reasons,
                            &mut doc,
                        );
                    }
                    global_dir_acl22.clear();
                }
                global_dir_scope = None;
                global_pending_access_rewrite_cond = None;
                continue;
            }
            if lower.starts_with("</files") {
                global_files_scope = None;
                continue;
            }
            if lower.starts_with("</location") {
                if let Some(loc) = global_location_scope.take() {
                    let is_stock_status_endpoint = loc.is_internal_status_or_info
                        && !loc.has_non_internal_handler
                        && matches!(
                            loc.path.trim_end_matches('/'),
                            "/server-status" | "/server-info"
                        );
                    if is_stock_status_endpoint {
                        // R6-MIG-9: Stock Debian `mods-enabled/status.conf` (`<Location /server-status>`
                        // with `SetHandler server-status` and `Require local`) guards Apache's
                        // built-in status handler which MiraServe does not serve.
                        doc.push_note(
                            Some(line_no),
                            "Location",
                            format!(
                                "Skipped stock Apache internal `<Location {}>` (`SetHandler server-status`/`server-info`); MiraServe does not expose this endpoint",
                                loc.path
                            ),
                        );
                    } else {
                        for (acl_line, acl_dir, acl_text) in loc.acl22.blocking_rules() {
                            global_block_reasons.push((acl_line, acl_dir.to_owned()));
                            doc.push_security_downgrade(
                                Some(acl_line),
                                acl_dir,
                                format!(
                                    "Global Apache `<Location {}>` access rule `{acl_text}` cannot be auto-translated; sites withheld",
                                    loc.path
                                ),
                            );
                        }
                        for (rule_file, rule_line, rule_dir, rule_text) in loc.pending_rules {
                            let prev = doc.set_source_file(rule_file);
                            global_block_reasons.push((rule_line, rule_dir.clone()));
                            doc.push_security_downgrade(
                                Some(rule_line),
                                rule_dir,
                                format!(
                                    "Global Apache `<Location {}>` access control `{rule_text}` cannot be auto-translated; sites withheld",
                                    loc.path
                                ),
                            );
                            doc.set_source_file(prev);
                        }
                    }
                }
                global_pending_access_rewrite_cond = None;
                continue;
            }
            if lower.starts_with("</") {
                global_pending_access_rewrite_cond = None;
                continue;
            }
            if line.starts_with('<') && line.ends_with('>') {
                if let Some((tag, raw_arg)) = parse_apache_section_open(&line) {
                    match tag.as_str() {
                        "directory" | "directorymatch" => {
                            global_dir_acl22.clear();
                            global_dir_scope = Some(classify_directory_scope(&tag, &raw_arg));
                        }
                        "files" | "filesmatch" => {
                            let is_regex =
                                tag == "filesmatch" || raw_arg.trim_start().starts_with('~');
                            global_files_scope = Some((raw_arg, is_regex));
                        }
                        "location" | "locationmatch" => {
                            let clean_path = raw_arg
                                .trim()
                                .trim_start_matches('~')
                                .trim()
                                .trim_matches('"')
                                .trim_matches('\'')
                                .to_owned();
                            global_location_scope = Some(GlobalLocationScope {
                                path: clean_path,
                                ..GlobalLocationScope::default()
                            });
                        }
                        "if" | "elseif" | "else" | "ifdefine" | "ifversion" | "iffile"
                        | "ifdirective" | "ifsection" => {
                            // R8-MIG-2: content of a conditional container must not become
                            // unconditional for every site.
                            global_block_reasons.push((line_no, tag.clone()));
                            doc.push_security_downgrade(
                                Some(line_no),
                                tag.clone(),
                                format!(
                                    "Global Apache conditional container <{tag}> cannot be evaluated; its content would become unconditional, so sites are withheld"
                                ),
                            );
                        }
                        "ifmodule"
                            if raw_arg.trim().trim_matches('"').starts_with('!')
                                && !raw_arg.to_ascii_lowercase().contains("php") =>
                        {
                            // R8-MIG-2: `<IfModule !mod_x>` content applies only when the module
                            // is ABSENT. The one stock use, Debian's `<IfModule !mod_php8.c>`
                            // around the PHP-FPM handler, stays transparent (R6-MIG-9).
                            global_block_reasons.push((line_no, tag.clone()));
                            doc.push_security_downgrade(
                                Some(line_no),
                                tag.clone(),
                                "Global Apache negated <IfModule !...> cannot be evaluated; its content would become unconditional, so sites are withheld",
                            );
                        }
                        "limit" | "limitexcept" => {
                            global_block_reasons.push((line_no, tag.clone()));
                            doc.push_security_downgrade(
                                Some(line_no),
                                tag.clone(),
                                format!(
                                    "Global Apache <{tag}> HTTP method restriction cannot be auto-translated; sites withheld"
                                ),
                            );
                        }
                        _ => {}
                    }
                }
                continue;
            }

            let parts = tokenize_apache_line(&line);
            let directive = parts
                .first()
                .map_or_else(String::new, |s| s.to_ascii_lowercase());
            let args = parts.get(1..).unwrap_or(&[]);
            let args_joined = args.join(" ");

            match directive.as_str() {
                "listen" => {
                    if let Some(addr_tok) = args.first() {
                        if contains_apache_env_var(addr_tok) {
                            global_block_reasons.push((line_no, "Listen".to_owned()));
                            doc.push_security_downgrade(
                                Some(line_no),
                                "Listen",
                                format!(
                                    "Global Apache `Listen {addr_tok}` contains unexpanded variable(s) and cannot be resolved safely; sites withheld"
                                ),
                            );
                        } else if let Some((bind, port)) =
                            normalize_bind_addr_with_default_port(addr_tok, 80)
                        {
                            if args.get(1).is_some_and(|p| p.eq_ignore_ascii_case("https")) {
                                global_https_ports.insert(port);
                            }
                            global_binds.push((bind, port));
                        } else {
                            global_block_reasons.push((line_no, "Listen".to_owned()));
                            doc.push_security_downgrade(
                                Some(line_no),
                                "Listen",
                                format!(
                                    "Global Apache `Listen {addr_tok}` uses a hostname or unsupported bind address that cannot be resolved safely; sites withheld"
                                ),
                            );
                        }
                    }
                }
                "include" | "includeoptional" => {
                    let target = args.first().map_or(args_joined.as_str(), String::as_str);
                    if is_safe_apache_include_target(target) {
                        doc.push_note(
                            Some(line_no),
                            directive,
                            format!(
                                "Apache include `{target}` matched known stock non-ACL path (assumed safe, not read)"
                            ),
                        );
                    } else if is_ports_conf_include_target(target) {
                        // R5-MIG-5: Track unread `ports.conf` so wildcard `<VirtualHost *:port>`
                        // without a visible `Listen` fails closed!
                        unread_ports_conf = Some((line_no, target.to_owned()));
                        doc.push_note(
                            Some(line_no),
                            directive,
                            format!(
                                "Apache include `{target}` was not read from disk; wildcard `<VirtualHost *:port>` entries without inline `Listen` will fail closed"
                            ),
                        );
                    } else {
                        global_block_reasons.push((line_no, directive.clone()));
                        doc.push_security_downgrade(
                            Some(line_no),
                            directive,
                            format!(
                                "Unexpanded global Apache `Include {target}` may contain access/auth controls; import from disk so included files can be inspected, or pass --allow-insecure"
                            ),
                        );
                    }
                }
                "documentroot" if global_dir_scope.is_none() && global_files_scope.is_none() => {
                    if let Some(root) = args.first() {
                        if contains_apache_env_var(root) {
                            global_block_reasons.push((line_no, "DocumentRoot".to_owned()));
                            doc.push_security_downgrade(
                                Some(line_no),
                                "DocumentRoot",
                                format!(
                                    "Apache DocumentRoot '{root}' contains unexpanded variable(s) '${{...}}' and cannot be migrated literally; substitute the concrete path first"
                                ),
                            );
                        } else {
                            if is_wordpress_indicator_path(root) {
                                default_site.wordpress = true;
                                doc.push_upgrade(
                                    "Detected WordPress DocumentRoot — enabled preset \"wordpress-hardened\"",
                                );
                            }
                            default_site.root = Some(root.clone());
                        }
                    }
                }
                "servername" | "serveralias"
                    if global_dir_scope.is_none() && global_files_scope.is_none() =>
                {
                    for host in args {
                        if contains_apache_env_var(host) {
                            doc.push_note(
                                Some(line_no),
                                directive.clone(),
                                format!(
                                    "Skipped Apache hostname '{host}' containing unexpanded environment variable"
                                ),
                            );
                            continue;
                        }
                        let cleaned = clean_apache_host(host);
                        if !cleaned.is_empty() {
                            default_site.hosts.push(cleaned);
                        }
                    }
                }
                "serveradmin" => {
                    if let Some(email) = args.first() {
                        if is_routable_acme_email(email) {
                            doc.acme_email = Some(email.clone());
                        } else {
                            doc.push_note(
                                Some(line_no),
                                "ServerAdmin",
                                format!(
                                    "Skipped non-routable Apache ServerAdmin '{email}' instead of configuring ACME email"
                                ),
                            );
                        }
                    }
                }
                "directoryindex" => {
                    if !is_stock_generic_directory_index(args)
                        && args.iter().any(|a| is_php_filename(a))
                        && default_php_indicator.is_none()
                    {
                        default_php_indicator =
                            Some((line_no, format!("DirectoryIndex {args_joined}")));
                    }
                }
                "sethandler" => {
                    if let Some(loc) = global_location_scope.as_mut() {
                        if let Some(handler) = args.first() {
                            if handler.eq_ignore_ascii_case("server-status")
                                || handler.eq_ignore_ascii_case("server-info")
                            {
                                loc.is_internal_status_or_info = true;
                            } else {
                                loc.has_non_internal_handler = true;
                            }
                        }
                    } else if let Some(raw_handler) = args.first()
                        && let Some(after_proxy) = raw_handler.strip_prefix("proxy:")
                    {
                        if contains_apache_env_var(after_proxy) {
                            global_block_reasons.push((line_no, "SetHandler".to_owned()));
                            doc.push_security_downgrade(
                                Some(line_no),
                                "SetHandler",
                                format!(
                                    "Global Apache `SetHandler {raw_handler}` contains unexpanded variable(s)"
                                ),
                            );
                        } else if global_location_scope.is_some()
                            || matches!(
                                global_dir_scope,
                                Some(
                                    GlobalDirScope::NonLiteral(_)
                                        | GlobalDirScope::GlobPrefix { .. }
                                )
                            )
                        {
                            global_block_reasons.push((line_no, "SetHandler".to_owned()));
                            doc.push_security_downgrade(
                                Some(line_no),
                                "SetHandler",
                                "Global Apache `SetHandler proxy:fcgi` inside `<Location>` or `<DirectoryMatch>` narrows PHP execution and cannot be translated to site-wide `*.php`; sites withheld",
                            );
                        } else if let Some((pat, is_regex)) = &global_files_scope {
                            let enclosing_dir = match &global_dir_scope {
                                Some(GlobalDirScope::Literal(p)) => Some((p.clone(), line_no)),
                                _ => None,
                            };
                            match resolve_apache_files_pattern(pat, *is_regex) {
                                Ok(patterns) => {
                                    let endpoint =
                                        after_proxy.split('|').next().unwrap_or(after_proxy);
                                    let target = normalize_fastcgi_target(endpoint);
                                    for p in patterns {
                                        global_fcgi_routes.push((
                                            MigratedRoute::new(
                                                p,
                                                MigratedHandler::FastCgi {
                                                    target: target.clone(),
                                                },
                                            ),
                                            enclosing_dir.clone(),
                                        ));
                                    }
                                    doc.push_upgrade(
                                        "Replaced global Apache SetHandler proxy:fcgi with isolated pure-Rust FastCGI",
                                    );
                                }
                                Err(reason) => {
                                    global_block_reasons.push((line_no, "SetHandler".to_owned()));
                                    doc.push_security_downgrade(
                                        Some(line_no),
                                        "SetHandler",
                                        format!("{reason}; sites withheld"),
                                    );
                                }
                            }
                        } else {
                            global_block_reasons.push((line_no, "SetHandler".to_owned()));
                            doc.push_security_downgrade(
                                Some(line_no),
                                "SetHandler",
                                "Global Apache `SetHandler proxy:fcgi` outside `<FilesMatch>` cannot be safely narrowed to `*.php`; sites withheld",
                            );
                        }
                    } else {
                        let low = args_joined.to_ascii_lowercase();
                        let is_denied_phps_handler = low.contains("php-source")
                            && global_files_scope
                                .as_ref()
                                .is_some_and(|(p, _)| is_apache_dotfile_files_pattern(p));
                        if !is_denied_phps_handler
                            && low.contains("php")
                            && default_php_indicator.is_none()
                        {
                            default_php_indicator =
                                Some((line_no, format!("{directive} {args_joined}")));
                        }
                        if !low.contains("php") && !args.is_empty() {
                            // R8-MIG-1 & R8-MIG-3: `none`, `default-handler`, `cgi-script`,
                            // `wsgi-script`, ... change what the scope does and are not
                            // translatable; withhold the sites the scope applies to.
                            record_global_dir_or_site_block(
                                global_dir_scope.as_ref(),
                                global_files_scope.as_ref().map(|(p, _)| p.as_str()),
                                source_file.as_deref(),
                                line_no,
                                "SetHandler",
                                "SetHandler (non-proxy handler)",
                                &mut global_dir_restrictions,
                                &mut global_block_reasons,
                                &mut doc,
                            );
                        }
                    }
                }
                "proxypreservehost"
                    if global_dir_scope.is_none()
                        && global_files_scope.is_none()
                        && global_location_scope.is_none() =>
                {
                    global_preserve_host =
                        args.first().is_some_and(|v| v.eq_ignore_ascii_case("on"));
                }
                "alias" | "scriptalias"
                    if global_dir_scope.is_none()
                        && global_files_scope.is_none()
                        && global_location_scope.is_none()
                        && args.first().is_some_and(|u| {
                            let u = u.trim();
                            u.starts_with('/')
                                && u.trim_end_matches('/').len() > 1
                                && !u.contains(['*', '?', '$', '(', '[', '\\', '{'])
                        }) =>
                {
                    if let Some(url_path) = args.first() {
                        global_closed_prefixes.push((
                            line_no,
                            directive.clone(),
                            normalize_route_pattern(url_path.trim()),
                        ));
                    }
                }
                "alias"
                | "aliasmatch"
                | "scriptalias"
                | "scriptaliasmatch"
                | "wsgiscriptalias"
                | "wsgiscriptaliasmatch"
                | "removehandler"
                | "removetype"
                | "forcetype"
                | "action" => {
                    // R8-MIG-1 & R8-MIG-8: remaps what a URL or scope serves and cannot be
                    // closed with a literal 404 prefix.
                    record_global_dir_or_site_block(
                        global_dir_scope.as_ref(),
                        global_files_scope.as_ref().map(|(p, _)| p.as_str()),
                        source_file.as_deref(),
                        line_no,
                        &directive,
                        &format!("{directive} (remaps served content)"),
                        &mut global_dir_restrictions,
                        &mut global_block_reasons,
                        &mut doc,
                    );
                }
                "addhandler" | "addtype" => {
                    if args_joined.to_ascii_lowercase().contains("php")
                        && default_php_indicator.is_none()
                    {
                        default_php_indicator =
                            Some((line_no, format!("{directive} {args_joined}")));
                    }
                }
                "header" => {
                    // R5-MIG-3, R6-MIG-5 & R7-MIG-12: Catch global untranslated security headers
                    // (default-refuse) while noting benign caching/diagnostic headers.
                    if let Some((hdr_name, class)) = check_apache_security_header(args) {
                        match class {
                            HeaderClassification::CoveredByStrict => {}
                            HeaderClassification::SafeToDropWithNote(reason) => {
                                doc.push_note(
                                    Some(line_no),
                                    "Header",
                                    format!(
                                        "Global Apache `Header` setting `{hdr_name}` was not auto-translated ({reason})"
                                    ),
                                );
                            }
                            HeaderClassification::SecurityDowngrade(reason) => {
                                record_global_dir_or_site_block(
                                    global_dir_scope.as_ref(),
                                    global_files_scope.as_ref().map(|(p, _)| p.as_str()),
                                    source_file.as_deref(),
                                    line_no,
                                    "Header",
                                    &format!("Header {hdr_name} ({reason})"),
                                    &mut global_dir_restrictions,
                                    &mut global_block_reasons,
                                    &mut doc,
                                );
                            }
                        }
                    }
                }
                "rewritecond" => {
                    if is_access_control_rewrite_cond(&args_joined) {
                        global_pending_access_rewrite_cond = Some((line_no, args_joined));
                    }
                }
                "rewriterule" => {
                    if let Some((cond_line, cond_str)) = global_pending_access_rewrite_cond.take() {
                        record_global_dir_or_site_block(
                            global_dir_scope.as_ref(),
                            global_files_scope.as_ref().map(|(p, _)| p.as_str()),
                            source_file.as_deref(),
                            cond_line,
                            "RewriteCond/RewriteRule",
                            &format!("RewriteCond {cond_str} -> {line}"),
                            &mut global_dir_restrictions,
                            &mut global_block_reasons,
                            &mut doc,
                        );
                    } else if has_blocking_rewrite_flag(&line) {
                        record_global_dir_or_site_block(
                            global_dir_scope.as_ref(),
                            global_files_scope.as_ref().map(|(p, _)| p.as_str()),
                            source_file.as_deref(),
                            line_no,
                            "RewriteRule",
                            &line,
                            &mut global_dir_restrictions,
                            &mut global_block_reasons,
                            &mut doc,
                        );
                    }
                }
                "order" | "allow" | "deny" => {
                    let is_stock_root_deny = matches!(global_dir_scope, Some(GlobalDirScope::Root))
                        && directive == "deny"
                        && args_joined.eq_ignore_ascii_case("from all");
                    let is_stock_ht_deny = global_files_scope
                        .as_ref()
                        .is_some_and(|(p, _)| is_apache_dotfile_files_pattern(p))
                        && ((directive == "deny" && args_joined.eq_ignore_ascii_case("from all"))
                            || directive == "order");
                    if is_stock_root_deny {
                        doc.push_upgrade(
                            "Preserved Apache stock `<Directory /> Deny from all` via MiraServe `cap-std` document-root confinement",
                        );
                    } else if is_stock_ht_deny {
                        doc.push_upgrade(
                            "Preserved Apache stock `<Files .ht*>` / `<FilesMatch ^\\.ht>` / `.phps` denial via MiraServe `dotfiles \"deny\"` & static PHP denial",
                        );
                    } else if let Some(loc) = global_location_scope.as_mut() {
                        record_apache22_directive(&mut loc.acl22, &directive, args, line_no, &line);
                    } else if global_dir_scope.is_some() && global_files_scope.is_none() {
                        record_apache22_directive(
                            &mut global_dir_acl22,
                            &directive,
                            args,
                            line_no,
                            &line,
                        );
                    } else {
                        let is_noop_allow_all =
                            directive == "allow" && args_joined.eq_ignore_ascii_case("from all");
                        if !is_noop_allow_all {
                            global_block_reasons.push((line_no, directive.clone()));
                            doc.push_security_downgrade(
                                Some(line_no),
                                directive,
                                format!(
                                    "Global Apache access control `{line}` outside `<VirtualHost>` cannot be auto-translated; sites withheld"
                                ),
                            );
                        }
                    }
                }
                _ => {
                    // Stock `<Directory /> Require all denied` / `AllowOverride none` -> cap-std confinement.
                    let is_stock_root_deny = matches!(global_dir_scope, Some(GlobalDirScope::Root))
                        && ((directive == "require"
                            && args_joined.eq_ignore_ascii_case("all denied"))
                            || (directive == "allowoverride"
                                && args_joined.eq_ignore_ascii_case("none")));
                    if is_stock_root_deny {
                        doc.push_upgrade(
                            "Preserved Apache stock `<Directory /> Require all denied` via MiraServe `cap-std` document-root confinement",
                        );
                        continue;
                    }

                    // R4-MIG-3 & R6-MIG-9: Stock `<Files ".ht*">` / `<FilesMatch "^\.ht">` / `.phps`
                    // denial -> native `dotfiles "deny"` & static PHP refusal.
                    let is_stock_ht_deny = global_files_scope
                        .as_ref()
                        .is_some_and(|(p, _)| is_apache_dotfile_files_pattern(p))
                        && ((directive == "require"
                            && args_joined.eq_ignore_ascii_case("all denied"))
                            || directive == "satisfy");
                    if is_stock_ht_deny {
                        doc.push_upgrade(
                            "Preserved Apache stock `<Files .ht*>` / `<FilesMatch ^\\.ht>` / `.phps` denial via MiraServe `dotfiles \"deny\"` & static PHP denial",
                        );
                        continue;
                    }

                    if is_global_apache_security_rule(&directive, args, &args_joined, &line) {
                        if let Some(loc) = global_location_scope.as_mut()
                            && directive == "require"
                        {
                            loc.pending_rules.push((
                                source_file.clone(),
                                line_no,
                                directive.clone(),
                                line.clone(),
                            ));
                        } else {
                            record_global_dir_or_site_block(
                                global_dir_scope.as_ref(),
                                global_files_scope.as_ref().map(|(p, _)| p.as_str()),
                                source_file.as_deref(),
                                line_no,
                                &directive,
                                &line,
                                &mut global_dir_restrictions,
                                &mut global_block_reasons,
                                &mut doc,
                            );
                        }
                    }
                }
            }
            continue;
        }

        // Inside `<VirtualHost>`: track nested Apache section tags.
        if line.starts_with("</") {
            pending_access_rewrite_cond = None;
            if let Some(mut closed) = scopes.pop() {
                // Evaluate per-scope Apache 2.2 ACL directives (`R5-MIG-7`) before finalizing scope!
                let blocking_acl22 = closed
                    .acl22_mut()
                    .map_or_else(Vec::new, |acl| acl.blocking_rules());
                let closed_id = closed.id();
                let mut was_blocked = match &closed {
                    ApacheScope::Directory { blocked, .. }
                    | ApacheScope::Location { blocked, .. }
                    | ApacheScope::Files { blocked, .. } => *blocked,
                    ApacheScope::Limit { .. } => true,
                    ApacheScope::Other { .. } => false,
                };
                if !blocking_acl22.is_empty() {
                    was_blocked = true;
                    for (acl_line, acl_dir, acl_text) in blocking_acl22 {
                        let scope_desc = describe_single_scope(&closed);
                        doc.push_security_downgrade(
                            Some(acl_line),
                            acl_dir,
                            format!(
                                "Apache 2.2 access rule `{acl_text}` ({scope_desc}) cannot be auto-translated; affected routes withheld"
                            ),
                        );
                        apply_scope_block_to_site(
                            &closed,
                            &mut current_site,
                            &mut current_vhost_dir_blocks,
                            acl_line,
                            acl_dir,
                        );
                    }
                }
                if was_blocked {
                    pending_routes.retain(|r| !r.owner_scope_ids.contains(&closed_id));
                }
            }
            continue;
        }
        if line.starts_with('<') && line.ends_with('>') {
            if let Some((tag, raw_arg)) = parse_apache_section_open(&line) {
                let id = next_scope_id;
                next_scope_id = next_scope_id.saturating_add(1);
                match tag.as_str() {
                    "directory" | "directorymatch" => {
                        match classify_directory_scope(&tag, &raw_arg) {
                            GlobalDirScope::Root => scopes.push(ApacheScope::Directory {
                                id,
                                path: "/".to_owned(),
                                is_literal: true,
                                blocked: false,
                                acl22: Apache22AclState::default(),
                            }),
                            GlobalDirScope::Literal(p) => scopes.push(ApacheScope::Directory {
                                id,
                                path: p,
                                is_literal: true,
                                blocked: false,
                                acl22: Apache22AclState::default(),
                            }),
                            GlobalDirScope::GlobPrefix { pattern, .. }
                            | GlobalDirScope::NonLiteral(pattern) => {
                                scopes.push(ApacheScope::Directory {
                                    id,
                                    path: pattern,
                                    is_literal: false,
                                    blocked: false,
                                    acl22: Apache22AclState::default(),
                                });
                            }
                        }
                    }
                    "location" | "locationmatch" => {
                        let is_regex =
                            tag == "locationmatch" || raw_arg.trim_start().starts_with('~');
                        let clean_path = raw_arg
                            .trim()
                            .trim_start_matches('~')
                            .trim()
                            .trim_matches('"')
                            .trim_matches('\'')
                            .to_owned();
                        scopes.push(ApacheScope::Location {
                            id,
                            path: clean_path,
                            is_regex,
                            blocked: false,
                            acl22: Apache22AclState::default(),
                        });
                    }
                    "files" | "filesmatch" => {
                        let is_regex = tag == "filesmatch" || raw_arg.trim_start().starts_with('~');
                        scopes.push(ApacheScope::Files {
                            id,
                            pattern: raw_arg,
                            is_regex,
                            blocked: false,
                            acl22: Apache22AclState::default(),
                        });
                    }
                    "limit" | "limitexcept" => {
                        doc.push_security_downgrade(
                            Some(line_no),
                            tag.clone(),
                            format!(
                                "Apache <{tag}> HTTP method access restriction cannot be auto-translated; affected routes withheld"
                            ),
                        );
                        mark_enclosing_scope_blocked(
                            &mut scopes,
                            &mut current_site,
                            &mut current_vhost_dir_blocks,
                            line_no,
                            &tag,
                        );
                        scopes.push(ApacheScope::Limit { id });
                    }
                    _ if is_transparent_apache_container(&tag, &raw_arg) => {
                        scopes.push(ApacheScope::Other {
                            id,
                            acl22: Apache22AclState::default(),
                            module_conditional: tag == "ifmodule",
                        });
                    }
                    _ => {
                        // R8-MIG-2: `<If>`, `<ElseIf>`, `<Else>`, `<IfDefine>`, `<IfVersion>`,
                        // negated `<IfModule !mod>` and any container the importer does not know
                        // make their content conditional. Flattening them would apply an
                        // IP-restricted proxy, handler or ACL to everyone, so the enclosing scope
                        // (or the whole site) is withheld and nothing inside is trusted.
                        let safe_tag = sanitize_untrusted_directive_token(&tag);
                        doc.push_security_downgrade(
                            Some(line_no),
                            safe_tag.clone(),
                            format!(
                                "Apache conditional or unknown container <{safe_tag}> ({}) cannot be evaluated; its content would become unconditional, so affected routes are withheld",
                                describe_scope(&scopes)
                            ),
                        );
                        mark_enclosing_scope_blocked(
                            &mut scopes,
                            &mut current_site,
                            &mut current_vhost_dir_blocks,
                            line_no,
                            &safe_tag,
                        );
                        scopes.push(ApacheScope::Limit { id });
                    }
                }
            }
            continue;
        }

        let tokens = tokenize_apache_line(&line);
        let Some(directive) = tokens.first() else {
            continue;
        };
        let args = tokens.get(1..).unwrap_or(&[]);
        let args_joined = args.join(" ");
        let dir_lower = directive.to_ascii_lowercase();

        // Check for stock `<Files ".ht*">` / `<FilesMatch "^\.ht">` inside `<VirtualHost>`.
        if let Some(ApacheScope::Files { pattern, .. }) = scopes.last()
            && is_apache_dotfile_files_pattern(pattern)
            && ((dir_lower == "require" && args_joined.eq_ignore_ascii_case("all denied"))
                || (dir_lower == "deny" && args_joined.eq_ignore_ascii_case("from all"))
                || dir_lower == "order"
                || dir_lower == "satisfy")
        {
            doc.push_upgrade(
                "Preserved Apache `<Files .ht*>` denial via MiraServe `dotfiles \"deny\"`",
            );
            continue;
        }

        // A positive `<IfModule mod_x>` is skipped by Apache when the module is not loaded, and
        // the importer does not know the source's module set. Restrictions inside it are kept
        // (assuming they apply can only make the result stricter), but a directive that CREATES
        // something reachable must not be assumed active: a `ProxyPass` that was dormant in the
        // source would become a live route.
        if scopes.iter().any(|s| {
            matches!(
                s,
                ApacheScope::Other {
                    module_conditional: true,
                    ..
                }
            )
        }) && matches!(
            dir_lower.as_str(),
            "proxypass"
                | "proxypassmatch"
                | "sethandler"
                | "addhandler"
                | "alias"
                | "aliasmatch"
                | "scriptalias"
                | "scriptaliasmatch"
                | "wsgiscriptalias"
                | "documentroot"
                | "servername"
                | "serveralias"
                | "proxypreservehost"
        ) {
            doc.push_security_downgrade(
                Some(line_no),
                directive.clone(),
                format!(
                    "Apache `{directive}` inside <IfModule> ({}) is active only when that module is loaded in the source server, which cannot be determined; affected routes withheld. Move the directive out of <IfModule> if it is live",
                    describe_scope(&scopes)
                ),
            );
            current_site.block_site(Some(line_no), &format!("{directive} (inside IfModule)"));
            continue;
        }

        // MIG-2, MIG-3, R4-MIG-6, R5-MIG-3, R5-MIG-6, R5-MIG-7: Security & Apache 2.2 ACL handling.
        match dir_lower.as_str() {
            "order" | "allow" | "deny" => {
                if let Some(acl) = scopes.last_mut().and_then(ApacheScope::acl22_mut) {
                    record_apache22_directive(acl, &dir_lower, args, line_no, &line);
                } else {
                    record_apache22_directive(
                        &mut current_vhost_acl22,
                        &dir_lower,
                        args,
                        line_no,
                        &line,
                    );
                }
                continue;
            }
            "require" => {
                let expr = args_joined.to_ascii_lowercase();
                if expr != "all granted" {
                    let scope_desc = describe_scope(&scopes);
                    doc.push_security_downgrade(
                        Some(line_no),
                        "Require",
                        format!(
                            "Apache `Require {args_joined}` ({scope_desc}) cannot be auto-translated; affected routes withheld to prevent open exposure"
                        ),
                    );
                    mark_enclosing_scope_blocked(
                        &mut scopes,
                        &mut current_site,
                        &mut current_vhost_dir_blocks,
                        line_no,
                        "Require",
                    );
                }
                continue;
            }
            "authtype" | "authuserfile" | "authgroupfile" | "authrequire" | "sslrequire"
            | "sslrequiressl" | "secrule" | "secaction" | "secdefaultaction" => {
                let scope_desc = describe_scope(&scopes);
                doc.push_security_downgrade(
                    Some(line_no),
                    directive.clone(),
                    format!(
                        "Apache security directive `{directive}` ({scope_desc}) cannot be auto-translated; affected routes withheld"
                    ),
                );
                mark_enclosing_scope_blocked(
                    &mut scopes,
                    &mut current_site,
                    &mut current_vhost_dir_blocks,
                    line_no,
                    directive,
                );
                continue;
            }
            "php_admin_value" | "php_admin_flag" | "php_value" | "php_flag" => {
                // R5-MIG-1 & R5-MIG-6: Indicates PHP AND may enforce `open_basedir` / `disable_functions`.
                if current_vhost_php.is_none() {
                    current_vhost_php = Some((line_no, format!("{directive} {args_joined}")));
                }
                let scope_desc = describe_scope(&scopes);
                doc.push_security_downgrade(
                    Some(line_no),
                    directive.clone(),
                    format!(
                        "Apache PHP override `{directive} {args_joined}` ({scope_desc}) cannot be auto-translated; configure PHP-FPM pool settings manually"
                    ),
                );
                mark_enclosing_scope_blocked(
                    &mut scopes,
                    &mut current_site,
                    &mut current_vhost_dir_blocks,
                    line_no,
                    directive,
                );
                continue;
            }
            "secruleengine" => {
                let val = args
                    .first()
                    .map_or_else(String::new, |v| v.to_ascii_lowercase());
                if val != "off" {
                    let scope_desc = describe_scope(&scopes);
                    doc.push_security_downgrade(
                        Some(line_no),
                        directive.clone(),
                        format!(
                            "Apache ModSecurity `{directive} {val}` ({scope_desc}) cannot be auto-translated; affected routes withheld"
                        ),
                    );
                    mark_enclosing_scope_blocked(
                        &mut scopes,
                        &mut current_site,
                        &mut current_vhost_dir_blocks,
                        line_no,
                        directive,
                    );
                }
                continue;
            }
            "sslverifyclient" => {
                let val = args
                    .first()
                    .map_or_else(String::new, |v| v.to_ascii_lowercase());
                if val != "none" {
                    current_site.block_site(Some(line_no), "SSLVerifyClient");
                    doc.push_security_downgrade(
                        Some(line_no),
                        "SSLVerifyClient",
                        format!(
                            "Apache `SSLVerifyClient {val}` enforces client certificate auth; configure MiraServe `client-ca` manually before exposing this site"
                        ),
                    );
                }
                continue;
            }
            "allowoverride" => {
                let val = args_joined.to_ascii_lowercase();
                if val != "none" {
                    let scope_desc = describe_scope(&scopes);
                    doc.push_security_downgrade(
                        Some(line_no),
                        "AllowOverride",
                        format!(
                            "Apache `AllowOverride {args_joined}` ({scope_desc}) allows `.htaccess` access/auth rules which MiraServe does not load; audit `.htaccess` files manually"
                        ),
                    );
                    mark_enclosing_scope_blocked(
                        &mut scopes,
                        &mut current_site,
                        &mut current_vhost_dir_blocks,
                        line_no,
                        "AllowOverride",
                    );
                }
                continue;
            }
            "header" => {
                // R5-MIG-3, R6-MIG-5 & R7-MIG-12: Never silently drop CSP / COEP / CORP / HSTS
                // preload / custom Permissions-Policy, while allowing benign caching headers with
                // an informational note.
                match check_apache_security_header(args) {
                    Some((hdr_name, HeaderClassification::SecurityDowngrade(reason))) => {
                        let scope_desc = describe_scope(&scopes);
                        doc.push_security_downgrade(
                            Some(line_no),
                            "Header",
                            format!(
                                "Apache `Header` setting `{hdr_name}` ({scope_desc}) cannot be auto-translated ({reason}); affected routes withheld"
                            ),
                        );
                        mark_enclosing_scope_blocked(
                            &mut scopes,
                            &mut current_site,
                            &mut current_vhost_dir_blocks,
                            line_no,
                            &format!("Header {hdr_name}"),
                        );
                    }
                    Some((hdr_name, HeaderClassification::SafeToDropWithNote(reason))) => {
                        doc.push_note(
                            Some(line_no),
                            "Header",
                            format!(
                                "Apache `Header` setting `{hdr_name}` was not auto-translated ({reason})"
                            ),
                        );
                    }
                    Some((_, HeaderClassification::CoveredByStrict)) | None => {
                        doc.push_note(
                            Some(line_no),
                            "Header",
                            format!("Apache `Header {args_joined}` requires manual review"),
                        );
                    }
                }
                continue;
            }
            "options" => {
                if args_joined.to_ascii_lowercase().contains("-indexes") {
                    doc.push_upgrade(
                        "Preserved Apache `Options -Indexes` (MiraServe disables directory listing by default)",
                    );
                } else {
                    doc.push_note(
                        Some(line_no),
                        "Options",
                        format!("Apache `Options {args_joined}` requires manual review"),
                    );
                }
                continue;
            }
            _ => {}
        }

        match dir_lower.as_str() {
            "servername" | "serveralias" => {
                for host in args {
                    if contains_apache_env_var(host) {
                        doc.push_note(
                            Some(line_no),
                            directive.clone(),
                            format!(
                                "Skipped Apache hostname '{host}' containing unexpanded environment variable"
                            ),
                        );
                        continue;
                    }
                    let cleaned = clean_apache_host(host);
                    if !cleaned.is_empty() {
                        current_site.hosts.push(cleaned);
                    }
                }
            }
            "documentroot" => {
                if let Some(root) = args.first() {
                    has_non_redirect_content = true;
                    if contains_apache_env_var(root) {
                        current_site.block_site(Some(line_no), "DocumentRoot");
                        doc.push_security_downgrade(
                            Some(line_no),
                            "DocumentRoot",
                            format!(
                                "Apache DocumentRoot '{root}' contains unexpanded variable(s) '${{...}}' and cannot be migrated literally; substitute the concrete path first"
                            ),
                        );
                    } else {
                        if is_wordpress_indicator_path(root) {
                            current_site.wordpress = true;
                            doc.push_upgrade(
                                "Detected WordPress DocumentRoot — enabled preset \"wordpress-hardened\"",
                            );
                        }
                        current_site.root = Some(root.clone());
                    }
                }
            }
            "directoryindex" => {
                // R5-MIG-1: Detect PHP sites that rely on mod_php + `DirectoryIndex index.php`!
                if args.iter().any(|a| is_php_filename(a)) && current_vhost_php.is_none() {
                    current_vhost_php = Some((line_no, format!("DirectoryIndex {args_joined}")));
                }
            }
            "addhandler" | "addtype" => {
                if args_joined.to_ascii_lowercase().contains("php") && current_vhost_php.is_none() {
                    current_vhost_php = Some((line_no, format!("{directive} {args_joined}")));
                }
            }
            "proxypassmatch" => {
                has_non_redirect_content = true;
                let lower_args = args_joined.to_ascii_lowercase();
                if (lower_args.contains(".php")
                    || lower_args.contains("fcgi://")
                    || lower_args.contains("php"))
                    && current_vhost_php.is_none()
                {
                    current_vhost_php = Some((line_no, format!("ProxyPassMatch {args_joined}")));
                } else {
                    doc.push_note(
                        Some(line_no),
                        "ProxyPassMatch",
                        format!(
                            "Apache regex `ProxyPassMatch {args_joined}` requires manual review"
                        ),
                    );
                }
            }
            "proxypass" => {
                if let (Some(path), Some(target)) = (args.first(), args.get(1))
                    && target != "!"
                {
                    has_non_redirect_content = true;
                    if contains_apache_env_var(target) {
                        doc.push_security_downgrade(
                            Some(line_no),
                            "ProxyPass",
                            format!(
                                "Apache `ProxyPass {path} {target}` contains unexpanded variable(s) and cannot be migrated literally"
                            ),
                        );
                        mark_enclosing_scope_blocked(
                            &mut scopes,
                            &mut current_site,
                            &mut current_vhost_dir_blocks,
                            line_no,
                            "ProxyPass",
                        );
                    } else if !current_scope_is_blocked(&scopes) {
                        let resolved = resolve_apache_proxy_target(path, target, line_no, &mut doc);
                        pending_routes.push(PendingApacheRoute {
                            pattern: normalize_route_pattern(path),
                            handler: MigratedHandler::ReverseProxy {
                                upstreams: vec![resolved],
                                preserve_host: false,
                                // A plain `ProxyPass http(s)://` does not tunnel WebSockets.
                                allow_upgrades: false,
                            },
                            owner_scope_ids: scopes.iter().map(ApacheScope::id).collect(),
                            enclosing_dir_paths: Vec::new(),
                        });
                    }
                } else if let Some(target) = args.first()
                    && target != "!"
                    && let Some(loc_path) = current_location_path(&scopes)
                {
                    has_non_redirect_content = true;
                    if contains_apache_env_var(target) {
                        doc.push_security_downgrade(
                            Some(line_no),
                            "ProxyPass",
                            format!(
                                "Apache `ProxyPass {target}` contains unexpanded variable(s) and cannot be migrated literally"
                            ),
                        );
                        mark_enclosing_scope_blocked(
                            &mut scopes,
                            &mut current_site,
                            &mut current_vhost_dir_blocks,
                            line_no,
                            "ProxyPass",
                        );
                    } else if !current_scope_is_blocked(&scopes) {
                        let resolved =
                            resolve_apache_proxy_target(loc_path, target, line_no, &mut doc);
                        pending_routes.push(PendingApacheRoute {
                            pattern: normalize_route_pattern(loc_path),
                            handler: MigratedHandler::ReverseProxy {
                                upstreams: vec![resolved],
                                preserve_host: false,
                                // A plain `ProxyPass http(s)://` does not tunnel WebSockets.
                                allow_upgrades: false,
                            },
                            owner_scope_ids: scopes.iter().map(ApacheScope::id).collect(),
                            enclosing_dir_paths: Vec::new(),
                        });
                    }
                }
            }
            "sethandler" => {
                if let Some(raw_handler) = args.first() {
                    if let Some(after_proxy) = raw_handler.strip_prefix("proxy:") {
                        has_non_redirect_content = true;
                        if contains_apache_env_var(after_proxy) {
                            doc.push_security_downgrade(
                                Some(line_no),
                                "SetHandler",
                                format!(
                                    "Apache `SetHandler {raw_handler}` contains unexpanded variable(s)"
                                ),
                            );
                            mark_enclosing_scope_blocked(
                                &mut scopes,
                                &mut current_site,
                                &mut current_vhost_dir_blocks,
                                line_no,
                                "SetHandler",
                            );
                        } else if !current_scope_is_blocked(&scopes) {
                            match resolve_apache_sethandler_patterns(&scopes) {
                                Ok((patterns, enclosing_dirs)) => {
                                    let endpoint =
                                        after_proxy.split('|').next().unwrap_or(after_proxy);
                                    let target = normalize_fastcgi_target(endpoint);
                                    let owner_scope_ids: Vec<usize> =
                                        scopes.iter().map(ApacheScope::id).collect();
                                    let enclosing_dir_paths: Vec<(String, usize)> =
                                        enclosing_dirs.into_iter().map(|d| (d, line_no)).collect();
                                    for pattern in patterns {
                                        pending_routes.push(PendingApacheRoute {
                                            pattern,
                                            handler: MigratedHandler::FastCgi {
                                                target: target.clone(),
                                            },
                                            owner_scope_ids: owner_scope_ids.clone(),
                                            enclosing_dir_paths: enclosing_dir_paths.clone(),
                                        });
                                    }
                                    doc.push_upgrade(
                                        "Replaced Apache SetHandler proxy:fcgi with isolated pure-Rust FastCGI",
                                    );
                                }
                                Err(reason) => {
                                    doc.push_security_downgrade(
                                        Some(line_no),
                                        "SetHandler",
                                        format!(
                                            "{reason} ({}); affected routes withheld",
                                            describe_scope(&scopes)
                                        ),
                                    );
                                    mark_enclosing_scope_blocked(
                                        &mut scopes,
                                        &mut current_site,
                                        &mut current_vhost_dir_blocks,
                                        line_no,
                                        "SetHandler",
                                    );
                                }
                            }
                        } else if current_vhost_php.is_none() {
                            current_vhost_php =
                                Some((line_no, format!("SetHandler {raw_handler}")));
                        }
                    } else {
                        // R8-MIG-1 & R8-MIG-3: every other handler changes what the scope does.
                        // `none` / `default-handler` switch PHP OFF for an uploads directory;
                        // `cgi-script`, `wsgi-script`, `server-status`, `application/x-httpd-php`
                        // make the scope executable or special. None of them is translatable, and
                        // ignoring one either executes uploaded scripts or serves program source.
                        if raw_handler.to_ascii_lowercase().contains("php")
                            && !raw_handler.to_ascii_lowercase().contains("php-source")
                            && current_vhost_php.is_none()
                        {
                            current_vhost_php =
                                Some((line_no, format!("SetHandler {raw_handler}")));
                        }
                        let safe_handler = sanitize_untrusted_directive_token(raw_handler);
                        doc.push_security_downgrade(
                            Some(line_no),
                            "SetHandler",
                            format!(
                                "Apache `SetHandler {safe_handler}` ({}) changes how this scope is handled and cannot be auto-translated; affected routes withheld",
                                describe_scope(&scopes)
                            ),
                        );
                        mark_enclosing_scope_blocked(
                            &mut scopes,
                            &mut current_site,
                            &mut current_vhost_dir_blocks,
                            line_no,
                            "SetHandler",
                        );
                    }
                }
            }
            "sslengine" => {
                if args.first().is_some_and(|v| v.eq_ignore_ascii_case("on")) {
                    current_vhost_has_ssl = true;
                }
            }
            "sslcertificatefile" => {
                if let Some(c) = args.first() {
                    if contains_apache_env_var(c) {
                        current_site.block_site(Some(line_no), "SSLCertificateFile");
                        doc.push_security_downgrade(
                            Some(line_no),
                            "SSLCertificateFile",
                            format!(
                                "Apache SSLCertificateFile '{c}' contains unexpanded variable(s)"
                            ),
                        );
                    } else {
                        current_site.cert = Some(c.clone());
                    }
                }
            }
            "sslcertificatekeyfile" => {
                if let Some(k) = args.first() {
                    if contains_apache_env_var(k) {
                        current_site.block_site(Some(line_no), "SSLCertificateKeyFile");
                        doc.push_security_downgrade(
                            Some(line_no),
                            "SSLCertificateKeyFile",
                            format!(
                                "Apache SSLCertificateKeyFile '{k}' contains unexpanded variable(s)"
                            ),
                        );
                    } else {
                        current_site.key = Some(k.clone());
                    }
                }
            }
            "serveradmin" => {
                if let Some(email) = args.first() {
                    if is_routable_acme_email(email) {
                        doc.acme_email = Some(email.clone());
                    } else {
                        doc.push_note(
                            Some(line_no),
                            "ServerAdmin",
                            format!(
                                "Skipped non-routable Apache ServerAdmin '{email}' instead of configuring ACME email"
                            ),
                        );
                    }
                }
            }
            "redirect" | "redirectpermanent" | "redirectmatch" => {
                if is_apache_blocking_redirect(args) {
                    doc.push_security_downgrade(
                        Some(line_no),
                        directive.clone(),
                        format!(
                            "Apache blocking redirect `{line}` cannot be auto-translated; affected routes withheld"
                        ),
                    );
                    mark_enclosing_scope_blocked(
                        &mut scopes,
                        &mut current_site,
                        &mut current_vhost_dir_blocks,
                        line_no,
                        directive,
                    );
                } else if dir_lower != "redirectmatch"
                    && scopes.is_empty()
                    && args.iter().any(|a| a.starts_with("https://"))
                    && args.iter().any(|a| a == "/")
                {
                    has_root_https_redirect = true;
                } else {
                    doc.push_note(
                        Some(line_no),
                        directive.clone(),
                        format!("Apache redirect '{line}' requires manual review"),
                    );
                }
            }
            "rewritecond" => {
                // R5-MIG-6: Track access/client-conditional RewriteCond (e.g. `%{REMOTE_ADDR}`).
                if is_access_control_rewrite_cond(&args_joined) {
                    pending_access_rewrite_cond = Some((line_no, args_joined));
                }
            }
            "rewriterule" => {
                if let Some((cond_line, cond_str)) = pending_access_rewrite_cond.take() {
                    doc.push_security_downgrade(
                        Some(cond_line),
                        "RewriteCond/RewriteRule",
                        format!(
                            "Apache access-conditional `RewriteCond {cond_str}` + `{line}` cannot be auto-translated; affected routes withheld"
                        ),
                    );
                    mark_enclosing_scope_blocked(
                        &mut scopes,
                        &mut current_site,
                        &mut current_vhost_dir_blocks,
                        cond_line,
                        "RewriteCond/RewriteRule",
                    );
                } else if has_blocking_rewrite_flag(&line) {
                    doc.push_security_downgrade(
                        Some(line_no),
                        "RewriteRule",
                        format!("Apache blocking RewriteRule '{line}' cannot be auto-translated"),
                    );
                    mark_enclosing_scope_blocked(
                        &mut scopes,
                        &mut current_site,
                        &mut current_vhost_dir_blocks,
                        line_no,
                        "RewriteRule",
                    );
                } else if scopes.is_empty() && is_https_redirect_rewrite_rule(args, &line) {
                    has_root_https_redirect = true;
                } else if line.contains("index.php") {
                    has_non_redirect_content = true;
                    if current_vhost_php.is_none() {
                        current_vhost_php = Some((line_no, line.clone()));
                    }
                    if !current_scope_is_blocked(&scopes) {
                        pending_routes.push(PendingApacheRoute {
                            pattern: "/*".to_owned(),
                            handler: MigratedHandler::TryFiles {
                                candidates: vec![
                                    "{path}".to_owned(),
                                    "{path}/".to_owned(),
                                    "/index.php?{query}".to_owned(),
                                ],
                            },
                            owner_scope_ids: scopes.iter().map(ApacheScope::id).collect(),
                            enclosing_dir_paths: Vec::new(),
                        });
                        doc.push_upgrade(
                            "Converted Apache front-controller RewriteRule into safe try-files route",
                        );
                    }
                } else {
                    doc.push_note(
                        Some(line_no),
                        "RewriteRule",
                        "Complex Apache mod_rewrite rule requires manual review",
                    );
                }
            }
            "include" | "includeoptional" => {
                let target = args.first().map_or(args_joined.as_str(), String::as_str);
                if is_safe_apache_include_target(target) {
                    doc.push_note(
                        Some(line_no),
                        directive.clone(),
                        format!(
                            "Apache include `{target}` matched known stock non-ACL path (assumed safe, not read)"
                        ),
                    );
                } else {
                    doc.push_security_downgrade(
                        Some(line_no),
                        directive.clone(),
                        format!(
                            "Unexpanded Apache `{line}` inside {} may enforce auth/ACLs; affected routes withheld",
                            describe_scope(&scopes)
                        ),
                    );
                    mark_enclosing_scope_blocked(
                        &mut scopes,
                        &mut current_site,
                        &mut current_vhost_dir_blocks,
                        line_no,
                        directive,
                    );
                }
            }
            "proxypreservehost" => {
                // `On` makes the backend see the client's `Host`; MiraServe reproduces that with
                // `preserve-host #true`. It is a per-server setting here: inside a narrower
                // section it cannot be scoped, so that section is withheld.
                let on = args.first().is_some_and(|v| v.eq_ignore_ascii_case("on"));
                if scopes.is_empty() {
                    current_site.proxy_preserve_host = Some(on);
                } else {
                    doc.push_security_downgrade(
                        Some(line_no),
                        directive.clone(),
                        format!(
                            "Apache `ProxyPreserveHost` inside {} cannot be scoped to that section; affected routes withheld",
                            describe_scope(&scopes)
                        ),
                    );
                    mark_enclosing_scope_blocked(
                        &mut scopes,
                        &mut current_site,
                        &mut current_vhost_dir_blocks,
                        line_no,
                        directive,
                    );
                }
            }
            "proxypassreverse"
            | "errorlog"
            | "customlog"
            | "transferlog"
            | "rewriteengine"
            | "authname"
            | "loglevel"
            | "ssloptions"
            | "sslciphersuite"
            | "sslproxyciphersuite"
            | "sslhonorcipherorder"
            | "sslprotocol"
            | "sslproxyprotocol"
            | "browsermatch" => {}
            "alias" | "scriptalias" | "wsgiscriptalias" => {
                // R8-MIG-1 & R8-MIG-8: these map a URL prefix to a directory or program OUTSIDE
                // the normal document-root lookup. MiraServe cannot serve that mapping, and
                // letting the prefix fall through to the document root could serve a shadowed
                // directory or program source. A literal non-root prefix at vhost level is
                // closed with an explicit 404 route (sorted ahead of `*.php`); anything else
                // (the whole site, a regex, a variable, a nested scope) withholds the scope.
                let url_path = args.first().map_or("", |a| a.trim());
                let is_literal_prefix = url_path.starts_with('/')
                    && url_path.trim_end_matches('/').len() > 1
                    && !url_path.contains(['*', '?', '$', '(', '[', '\\', '{'])
                    && !contains_apache_env_var(url_path);
                if is_literal_prefix && scopes.is_empty() {
                    current_site.routes.push(
                        MigratedRoute::new(
                            normalize_route_pattern(url_path),
                            MigratedHandler::TryFiles {
                                candidates: vec!["=404".to_owned()],
                            },
                        )
                        .with_preferential_prefix(true),
                    );
                    let safe_path = sanitize_untrusted_directive_token(url_path);
                    doc.push_note(
                        Some(line_no),
                        directive.clone(),
                        format!(
                            "Apache `{directive} {safe_path}` maps a URL prefix outside the document root and was not migrated; the prefix now answers 404 so nothing under it is exposed. Re-create it as an explicit MiraServe route if it is still needed"
                        ),
                    );
                } else {
                    doc.push_security_downgrade(
                        Some(line_no),
                        directive.clone(),
                        format!(
                            "Apache `{directive}` ({}) remaps what this scope serves and cannot be auto-translated; affected routes withheld",
                            describe_scope(&scopes)
                        ),
                    );
                    mark_enclosing_scope_blocked(
                        &mut scopes,
                        &mut current_site,
                        &mut current_vhost_dir_blocks,
                        line_no,
                        directive,
                    );
                }
            }
            other if is_apache_inert_directive(other, args) => {}
            other => {
                // R8-MIG-1: fail closed. A directive that is neither translated nor known to be
                // inert (`WSGIScriptAlias`, `ScriptAlias`, `Alias`, `RemoveHandler`, `ForceType`,
                // `Action`, a typo, a third-party module) may decide what this scope serves or
                // to whom, so the enclosing scope (or the site) is withheld.
                let safe_dir = sanitize_untrusted_directive_token(other);
                doc.push_security_downgrade(
                    Some(line_no),
                    safe_dir.clone(),
                    format!(
                        "Apache directive '{safe_dir}' ({}) is not translated and is not known to be inert; affected routes withheld because it may change what is served or who may reach it",
                        describe_scope(&scopes)
                    ),
                );
                mark_enclosing_scope_blocked(
                    &mut scopes,
                    &mut current_site,
                    &mut current_vhost_dir_blocks,
                    line_no,
                    &safe_dir,
                );
            }
        }
    }

    // Clear active included file context before post-loop reconciliation.
    doc.set_source_file(None);

    // R4-MIG-3: Stock RHEL `httpd.conf` without `<VirtualHost>` defines a top-level `DocumentRoot`.
    if !saw_vhost && (default_site.root.is_some() || !default_site.routes.is_empty()) {
        if !global_fcgi_routes.is_empty()
            && !default_site
                .routes
                .iter()
                .any(|r| matches!(r.handler, MigratedHandler::FastCgi { .. }))
        {
            for (route, enclosing_dir) in global_fcgi_routes {
                if let Some((dir_path, dir_line)) = enclosing_dir {
                    let covers = default_site
                        .root
                        .as_deref()
                        .is_some_and(|r| dir_covers_docroot(&dir_path, r));
                    if !covers {
                        if default_site
                            .root
                            .as_deref()
                            .is_some_and(|r| dir_paths_overlap(&dir_path, r))
                        {
                            default_site.block_site(Some(dir_line), "SetHandler (Directory)");
                            doc.push_security_downgrade(
                                Some(dir_line),
                                "SetHandler",
                                format!(
                                    "Global Apache `<Directory {dir_path}>` scoping `SetHandler proxy:fcgi` is narrower than DocumentRoot ({}); refusing to widen PHP execution site-wide",
                                    default_site.root.as_deref().unwrap_or("<unset>")
                                ),
                            );
                        }
                        continue;
                    }
                }
                default_site.routes.push(route);
            }
        }
        if let Some((php_line, php_src)) = default_php_indicator
            && !default_site
                .routes
                .iter()
                .any(|r| matches!(r.handler, MigratedHandler::FastCgi { .. }))
        {
            default_site.block_site(Some(php_line), "php");
            doc.push_security_downgrade(
                Some(php_line),
                "php",
                format!(
                    "Apache server indicates PHP execution ({php_src}) but no FastCGI route was emitted; configure `php-fpm` with `fastcgi-pass` manually"
                ),
            );
        }
        site_raw_binds.push((Vec::new(), false));
        doc.sites.push(default_site);
    }

    // Apply the effective `ProxyPreserveHost` (the virtual host's own setting, else the
    // server-wide one) to every reverse-proxy route.
    for site in &mut doc.sites {
        let preserve = site.proxy_preserve_host.unwrap_or(global_preserve_host);
        for route in &mut site.routes {
            if let MigratedHandler::ReverseProxy { preserve_host, .. } = &mut route.handler {
                *preserve_host = preserve;
            }
        }
    }

    // R8-MIG-1 & R8-MIG-8: close every globally aliased URL prefix on every site.
    for (line_no, directive, pattern) in &global_closed_prefixes {
        for site in &mut doc.sites {
            if site.root.is_some() && !site.routes.iter().any(|r| &r.pattern == pattern) {
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
        }
        doc.push_note(
            Some(*line_no),
            directive.clone(),
            format!(
                "Global Apache `{directive}` for `{pattern}` maps a URL prefix outside the document root and was not migrated; the prefix answers 404 on every site so nothing under it is exposed"
            ),
        );
    }

    // Propagate global blockers to all sites with explicit directive/line reasons (`R4-MIG-2`).
    for (line_no, directive) in &global_block_reasons {
        for site in &mut doc.sites {
            site.block_site(Some(*line_no), directive);
        }
    }

    // R4-MIG-1, R4-MIG-6 & R6-MIG-9: Match global `<Directory X>` restrictions when EITHER path
    // is a prefix of the other, emit ONE downgrade per restriction, and fail closed if a
    // non-userdir restriction matches NO site!
    for (dir_path, is_userdir_glob, rule_file, line_no, directive, msg) in &global_dir_restrictions
    {
        let prev_file = doc.set_source_file(rule_file.clone());
        let mut matched_any = false;
        for site in &mut doc.sites {
            if site
                .root
                .as_deref()
                .is_some_and(|root| dir_paths_overlap(dir_path, root))
            {
                site.block_site(Some(*line_no), directive);
                matched_any = true;
            }
        }
        if matched_any {
            doc.push_security_downgrade(Some(*line_no), directive.clone(), msg.clone());
        } else if *is_userdir_glob {
            // R6-MIG-9: Stock RHEL `conf.d/userdir.conf` `<Directory "/home/*/public_html">`
            // does not apply to `/var/www/...` sites and MiraServe does not serve `mod_userdir`.
            doc.push_note(
                Some(*line_no),
                directive.clone(),
                format!(
                    "Skipped stock Apache userdir `<Directory {dir_path}/*/public_html>` rule `{directive}` (no site DocumentRoot is under `{dir_path}` and MiraServe does not enable mod_userdir)"
                ),
            );
        } else {
            for site in &mut doc.sites {
                site.block_site(Some(*line_no), directive);
            }
            doc.push_security_downgrade(
                Some(*line_no),
                directive.clone(),
                format!(
                    "Global Apache `<Directory {dir_path}>` security rule did not match any known site DocumentRoot; failing closed across sites"
                ),
            );
        }
        doc.set_source_file(prev_file);
    }

    // R4-MIG-4 & R5-MIG-5: Resolve every `<VirtualHost *:port>` strictly against global `Listen`
    // entries matching THAT port ONLY, and fail closed if `Include ports.conf` was unread and a
    // wildcard `<VirtualHost *:port>` has NO visible `Listen` for that port!
    for (bind, port) in &redirect_raw_binds {
        if bind.starts_with(':') {
            let matching: Vec<&String> = global_binds
                .iter()
                .filter(|(_, gp)| *gp == *port)
                .map(|(gb, _)| gb)
                .collect();
            if matching.is_empty() {
                doc.add_http_bind(bind.clone());
            } else {
                for gb in matching {
                    doc.add_http_bind(gb.clone());
                }
            }
        } else {
            doc.add_http_bind(bind.clone());
        }
    }

    let mut doc_binds_to_add: Vec<(bool, String)> = Vec::new();
    let mut deferred_downgrades: Vec<(Option<usize>, &'static str, String)> = Vec::new();
    let mut deferred_notes: Vec<(Option<usize>, &'static str, String)> = Vec::new();
    let mut ports_conf_downgrade_emitted = false;
    for (site, (raw_binds, vhost_ssl)) in doc.sites.iter_mut().zip(site_raw_binds.iter()) {
        if raw_binds.is_empty() {
            for (gb, gp) in &global_binds {
                let is_https = *vhost_ssl || *gp == 443 || global_https_ports.contains(gp);
                if is_https {
                    site.add_https_bind(gb.clone());
                    doc_binds_to_add.push((false, gb.clone()));
                } else {
                    site.add_http_bind(gb.clone());
                    doc_binds_to_add.push((true, gb.clone()));
                }
            }
            continue;
        }
        for (bind, port) in raw_binds {
            let is_https = *vhost_ssl || *port == 443 || global_https_ports.contains(port);
            if bind.starts_with(':') {
                let matching: Vec<&String> = global_binds
                    .iter()
                    .filter(|(_, gp)| *gp == *port)
                    .map(|(gb, _)| gb)
                    .collect();
                if matching.is_empty() {
                    if let Some((p_line, p_target)) = &unread_ports_conf {
                        // R5-MIG-5: `ports.conf` was included but not read and this port has no
                        // visible `Listen` -> could be loopback-scoped in `ports.conf`! Fail closed.
                        site.block_site(Some(*p_line), &format!("Include {p_target}"));
                        if !ports_conf_downgrade_emitted {
                            ports_conf_downgrade_emitted = true;
                            deferred_downgrades.push((
                                Some(*p_line),
                                "Include",
                                format!(
                                    "Apache config includes `{p_target}` which was not read, and `<VirtualHost *:{port}>` has no visible `Listen` directive for port {port} (may be loopback-scoped in ports.conf); import from disk with sibling ports.conf or inline Listen directives"
                                ),
                            ));
                        }
                    }
                    if is_https {
                        site.add_https_bind(bind.clone());
                        doc_binds_to_add.push((false, bind.clone()));
                    } else {
                        if *port != 80 && !is_scoped_bind(bind) {
                            deferred_notes.push((
                                None,
                                "VirtualHost",
                                format!(
                                    "Plain HTTP Apache `<VirtualHost *:{port}>` mapped to HTTP->HTTPS redirect; TLS terminates on ':443'"
                                ),
                            ));
                        }
                        site.add_http_bind(bind.clone());
                        doc_binds_to_add.push((true, bind.clone()));
                    }
                } else {
                    for gb in matching {
                        if is_https {
                            site.add_https_bind(gb.clone());
                            doc_binds_to_add.push((false, gb.clone()));
                        } else {
                            site.add_http_bind(gb.clone());
                            doc_binds_to_add.push((true, gb.clone()));
                        }
                    }
                }
            } else if is_https {
                site.add_https_bind(bind.clone());
                doc_binds_to_add.push((false, bind.clone()));
            } else {
                site.add_http_bind(bind.clone());
                doc_binds_to_add.push((true, bind.clone()));
            }
        }
    }
    for (line, dir, msg) in deferred_downgrades {
        doc.push_security_downgrade(line, dir, msg);
    }
    for (line, dir, msg) in deferred_notes {
        doc.push_note(line, dir, msg);
    }
    for (is_http, bind) in doc_binds_to_add {
        if is_http {
            doc.add_http_bind(bind);
        } else {
            doc.add_https_bind(bind);
        }
    }

    doc
}

type GlobalDirRestriction = (String, bool, Option<String>, usize, String, String);

#[allow(clippy::too_many_arguments)]
fn record_global_dir_or_site_block(
    global_dir_scope: Option<&GlobalDirScope>,
    global_files_scope: Option<&str>,
    source_file: Option<&str>,
    line_no: usize,
    directive: &str,
    rule_text: &str,
    global_dir_restrictions: &mut Vec<GlobalDirRestriction>,
    global_block_reasons: &mut Vec<(usize, String)>,
    doc: &mut MigratedDoc,
) {
    match global_dir_scope {
        Some(GlobalDirScope::Literal(dir_path)) if global_files_scope.is_none() => {
            global_dir_restrictions.push((
                dir_path.clone(),
                false,
                source_file.map(str::to_owned),
                line_no,
                directive.to_owned(),
                format!(
                    "Global Apache `<Directory {dir_path}>` security rule `{rule_text}` applies to overlapping site DocumentRoot and cannot be auto-translated"
                ),
            ));
        }
        Some(GlobalDirScope::GlobPrefix { prefix, pattern }) if global_files_scope.is_none() => {
            let is_userdir_glob = pattern.eq_ignore_ascii_case("/home/*/public_html");
            global_dir_restrictions.push((
                prefix.clone(),
                is_userdir_glob,
                source_file.map(str::to_owned),
                line_no,
                directive.to_owned(),
                format!(
                    "Global Apache `<Directory {pattern}>` security rule `{rule_text}` applies to overlapping site DocumentRoot and cannot be auto-translated"
                ),
            ));
        }
        Some(GlobalDirScope::NonLiteral(raw_pat)) => {
            global_block_reasons.push((line_no, directive.to_owned()));
            doc.push_security_downgrade(
                Some(line_no),
                directive,
                format!(
                    "Global Apache regex/wildcard/unparseable directory rule `<Directory {raw_pat}> {rule_text}` cannot be scoped safely; sites withheld"
                ),
            );
        }
        _ => {
            global_block_reasons.push((line_no, directive.to_owned()));
            doc.push_security_downgrade(
                Some(line_no),
                directive,
                format!(
                    "Global Apache access control `{rule_text}` outside `<VirtualHost>` cannot be auto-translated; sites withheld"
                ),
            );
        }
    }
}

fn apply_scope_block_to_site(
    scope: &ApacheScope,
    site: &mut MigratedSite,
    vhost_dir_blocks: &mut Vec<(String, bool, usize, String)>,
    line_no: usize,
    directive: &str,
) {
    match scope {
        ApacheScope::Directory {
            path, is_literal, ..
        } => {
            if !*is_literal
                || path == "/"
                || site
                    .root
                    .as_deref()
                    .is_some_and(|r| dir_paths_overlap(path, r))
            {
                site.block_site(Some(line_no), directive);
            } else {
                vhost_dir_blocks.push((path.clone(), *is_literal, line_no, directive.to_owned()));
            }
        }
        ApacheScope::Location { path, is_regex, .. } => {
            // R5-MIG-4: Record blocked location prefix on the site so separate `ProxyPass`
            // directives AND static `root` fallback overlapping this path are also caught!
            if *is_regex || path == "/" {
                site.block_site(Some(line_no), directive);
            } else {
                site.add_blocked_location(normalize_route_pattern(path), Some(line_no), directive);
            }
        }
        ApacheScope::Files {
            pattern, is_regex, ..
        } => match resolve_apache_files_pattern(pattern, *is_regex) {
            Ok(pats) if !pats.is_empty() => {
                for pat in pats {
                    site.add_blocked_location(pat, Some(line_no), directive);
                }
            }
            _ => {
                site.add_blocked_location("/*".to_owned(), Some(line_no), directive);
            }
        },
        ApacheScope::Limit { .. } | ApacheScope::Other { .. } => {
            site.block_site(Some(line_no), directive);
        }
    }
}

/// Apache containers whose content applies unconditionally for translation purposes: a positive
/// `<IfModule mod_x.c>` (the module is assumed loaded, as it was for the running source server)
/// and grouping containers whose own directives (`Require`, `ProxySet`, ...) are each classified
/// when reached. Everything else is conditional or unknown (`R8-MIG-2`).
fn is_transparent_apache_container(tag: &str, raw_arg: &str) -> bool {
    match tag {
        "ifmodule" => !raw_arg.trim().trim_matches('"').starts_with('!'),
        "proxy" | "proxymatch" | "requireall" | "requireany" | "requirenone" => true,
        _ => false,
    }
}

/// Apache directives that only tune logging, MIME metadata, compression, caching, connection
/// handling or TLS session behaviour. Dropping one never changes WHO may reach a path or WHAT a
/// path serves (`R8-MIG-1`). Anything not listed here and not explicitly translated blocks.
const APACHE_INERT_DIRECTIVES: &[&str] = &[
    "logformat",
    "serversignature",
    "servertokens",
    "usecanonicalname",
    "usecanonicalphysicalport",
    "hostnamelookups",
    "keepalive",
    "keepalivetimeout",
    "maxkeepaliverequests",
    "timeout",
    "adddefaultcharset",
    "addcharset",
    "addencoding",
    "addlanguage",
    "defaultlanguage",
    "languagepriority",
    "forcelanguagepriority",
    "typesconfig",
    "adddescription",
    "indexoptions",
    "indexignore",
    "addicon",
    "addiconbytype",
    "addiconbyencoding",
    "defaulticon",
    "readmename",
    "headername",
    "expiresactive",
    "expiresbytype",
    "expiresdefault",
    "addoutputfilterbytype",
    "deflatecompressionlevel",
    "enablesendfile",
    "enablemmap",
    "fileetag",
    "limitrequestbody",
    "limitrequestfields",
    "limitrequestfieldsize",
    "limitrequestline",
    "proxytimeout",
    "proxyrequests",
    "proxyvia",
    "proxyerroroverride",
    "proxybadheader",
    "proxyiobuffersize",
    "proxyreceivebuffersize",
    "proxyaddheaders",
    "proxypassreversecookiedomain",
    "proxypassreversecookiepath",
    "sslcertificatechainfile",
    "sslsessioncache",
    "sslsessioncachetimeout",
    "sslsessiontickets",
    "sslusestapling",
    "sslstaplingcache",
    "sslstaplingresponsertimeout",
    "sslstaplingreturnrespondererrors",
    "sslcompression",
    "sslopensslconfcmd",
    "sslrandomseed",
    "sslproxyengine",
    "protocols",
    "protocolshonororder",
    "h2direct",
    "h2push",
    "h2upgrade",
    "setenv",
    "setenvif",
    "setenvifnocase",
    "passenv",
    "unsetenv",
    "errordocument",
    "rewritebase",
    "rewriteoptions",
    "serverpath",
    "acceptpathinfo",
    "tracenable",
];

/// Returns `true` when dropping this Apache directive cannot widen access or change served content
/// (see [`APACHE_INERT_DIRECTIVES`]). A `RequestHeader` rule is inert only for the forwarding
/// headers MiraServe's reverse proxy manages itself.
fn is_apache_inert_directive(lower: &str, args: &[String]) -> bool {
    if APACHE_INERT_DIRECTIVES.contains(&lower) {
        return true;
    }
    if lower == "requestheader" {
        // A request-header rule is inert only when MiraServe's proxy sends that exact result:
        // - `set X-Forwarded-Proto "https"` (or the request scheme): the proxy always sets the
        //   client scheme, and it only proxies HTTPS requests;
        // - `unset Forwarded`: the proxy always removes it.
        // Everything else is a blocker, including rules on forwarding headers whose result
        // differs (`unset X-Forwarded-Host` while the proxy adds it, `set X-Forwarded-Port`
        // which the proxy never sends) and every identity header the upstream may trust.
        let action = args.first().map(|a| a.to_ascii_lowercase());
        let header = args.get(1).map(|h| h.to_ascii_lowercase());
        let value = args.get(2).map_or("", |v| v.trim_matches(['"', '\'']));
        return match (action.as_deref(), header.as_deref()) {
            (Some("set" | "setifempty"), Some("x-forwarded-proto")) => {
                value.eq_ignore_ascii_case("https")
                    || value.eq_ignore_ascii_case("%{REQUEST_SCHEME}s")
                    || value.eq_ignore_ascii_case("%{REQUEST_SCHEME}e")
            }
            (Some("unset"), Some("forwarded")) => true,
            _ => false,
        };
    }
    false
}

fn mark_enclosing_scope_blocked(
    scopes: &mut [ApacheScope],
    site: &mut MigratedSite,
    vhost_dir_blocks: &mut Vec<(String, bool, usize, String)>,
    line_no: usize,
    directive: &str,
) {
    if let Some(last) = scopes.last_mut() {
        match last {
            ApacheScope::Directory { blocked, .. }
            | ApacheScope::Location { blocked, .. }
            | ApacheScope::Files { blocked, .. } => {
                *blocked = true;
            }
            ApacheScope::Limit { .. } | ApacheScope::Other { .. } => {}
        }
        apply_scope_block_to_site(last, site, vhost_dir_blocks, line_no, directive);
    } else {
        site.block_site(Some(line_no), directive);
    }
}

fn current_scope_is_blocked(scopes: &[ApacheScope]) -> bool {
    scopes.iter().any(|s| match s {
        ApacheScope::Directory { blocked, .. }
        | ApacheScope::Location { blocked, .. }
        | ApacheScope::Files { blocked, .. } => *blocked,
        ApacheScope::Limit { .. } => true,
        ApacheScope::Other { .. } => false,
    })
}

fn current_location_path(scopes: &[ApacheScope]) -> Option<&str> {
    scopes.iter().rev().find_map(|s| match s {
        ApacheScope::Location { path, .. } => Some(path.as_str()),
        _ => None,
    })
}

fn describe_single_scope(scope: &ApacheScope) -> String {
    match scope {
        ApacheScope::Directory { path, .. } => format!("<Directory {path}>"),
        ApacheScope::Location { path, .. } => format!("<Location {path}>"),
        ApacheScope::Files { pattern, .. } => format!("<Files {pattern}>"),
        ApacheScope::Limit { .. } => "<Limit>".to_owned(),
        ApacheScope::Other { .. } => "<VirtualHost>".to_owned(),
    }
}

fn describe_scope(scopes: &[ApacheScope]) -> String {
    scopes
        .last()
        .map_or_else(|| "<VirtualHost>".to_owned(), describe_single_scope)
}

//! OpenLiteSpeed (`vhconf.conf` / `httpd_config.conf`) -> MiraServe KDL importer.
//!
//! Uses a full nested block stack (`MIG-6`), deterministic `BTreeMap` iteration (`MIG-7`),
//! accurate `$VH_ROOT` & `uds://` absolute path expansion (`MIG-7`, failing closed on undefined
//! `$VH_ROOT`, `R6-MIG-11`), bounded local `configFile` expansion when importing `httpd_config.conf`
//! from disk (`R6-MIG-8`), accurate `listener { address ...; secure 0|1; map ... }` classification
//! (`R6-MIG-8`), default-deny `extraHeaders` inspection for both single-line and `<<<END` heredocs
//! (`R6-MIG-5`), PHP/LSAPI fail-closed protection (`R2-MIG-4`, `R5-MIG-1`), context `statusCode`
//! 4xx/5xx & `RewriteFile .htaccess` & `phpIniOverride` & case-insensitive bracketed rewrite flag
//! checks (`R5-MIG-6`, `R5-MIG-8`), stock `module cache` / zero `perClientConnLimit` /
//! `accessDenyDir` support (`R5-MIG-7`), and location-scoped overlap tracking (`R5-MIG-4`).

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use crate::includes::{BoundedIncludeResult, IncludeContext};
use crate::ir::{
    HeaderClassification, MigratedDoc, MigratedHandler, MigratedRoute, MigratedSite,
    classify_untranslated_security_header, has_blocking_rewrite_flag, is_routable_acme_email,
    normalize_bind_addr_with_default_port, normalize_fastcgi_target, normalize_route_pattern,
    normalize_upstream_url, sanitize_diagnostic_text, sanitize_untrusted_directive_token,
};

#[derive(Debug, Default)]
struct ExtProc {
    line: usize,
    kind: String,
    address: String,
}

#[derive(Debug, Default)]
struct OlsContext {
    line: usize,
    uri: String,
    kind: String,
    handler: String,
    blocked_by_security: bool,
    blocker_info: Option<(usize, String)>,
    /// `location` override of a static context (`R8-MIG-8`).
    location: Option<String>,
}

#[derive(Debug)]
struct OlsScriptHandlerEntry {
    line: usize,
    kind: String,
    handler_name: String,
    suffixes: Vec<String>,
}

#[derive(Debug, Default)]
struct OlsListener {
    addresses: Vec<(String, u16)>,
    /// `Some(true)` for `secure 1`, `Some(false)` for `secure 0`, `None` if omitted.
    secure: Option<bool>,
    mapped_domains: Vec<String>,
}

#[derive(Debug, Clone)]
enum OlsBlock {
    VirtualHost,
    Listener,
    ExtProcessor(String),
    Context,
    VhSsl,
    Rewrite,
    AccessControl,
    Realm,
    ScriptHandler,
    Index,
    PerClientConnLimit,
    AccessDenyDir,
    Other,
}

#[derive(Debug)]
enum OlsHeredoc {
    ExtraHeaders { end_marker: String },
    RewriteRules { end_marker: String },
}

impl OlsHeredoc {
    fn end_marker(&self) -> &str {
        match self {
            Self::ExtraHeaders { end_marker } | Self::RewriteRules { end_marker } => end_marker,
        }
    }
}

#[derive(Debug, Default)]
struct OlsParseState {
    site: MigratedSite,
    vhost_name: Option<String>,
    mapped_domains: Vec<String>,
    // MIG-7: BTreeMap ensures deterministic output order across runs.
    ext_procs: BTreeMap<String, ExtProc>,
    contexts: Vec<OlsContext>,
    vh_root: Option<String>,
    defined_realms: Vec<(usize, String)>,
    referenced_realms: HashSet<String>,
    php_indicator: Option<(usize, String)>,
    /// Parsed `scriptHandler { add <type:name> <suffixes...> }` mappings (`R7-MIG-10`).
    script_handlers: Vec<OlsScriptHandlerEntry>,
}

/// Strips an OLS `#` comment only when outside quotes and at start-of-line or after whitespace.
fn strip_ols_comment(raw: &str) -> &str {
    let mut in_quote: Option<char> = None;
    let mut prev_ws = true;
    for (idx, ch) in raw.char_indices() {
        if let Some(q) = in_quote {
            if ch == q {
                in_quote = None;
            }
            prev_ws = false;
            continue;
        }
        match ch {
            '"' | '\'' => {
                in_quote = Some(ch);
                prev_ws = false;
            }
            '#' if prev_ws => return raw.get(..idx).unwrap_or(raw).trim(),
            c if c.is_whitespace() => prev_ws = true,
            _ => prev_ws = false,
        }
    }
    raw.trim()
}

fn is_php_index_list(args: &[&str]) -> bool {
    args.iter().any(|tok| {
        tok.split([',', ' ']).any(|part| {
            Path::new(part.trim()).extension().is_some_and(|ext| {
                ext.eq_ignore_ascii_case("php")
                    || ext.eq_ignore_ascii_case("phtml")
                    || ext.eq_ignore_ascii_case("phar")
            })
        })
    })
}

fn is_stock_ols_access_deny_dir(path: &str) -> bool {
    matches!(
        path.trim(),
        "/" | "/etc/*" | "/dev/*" | "conf/*" | "admin/conf/*"
    )
}

/// Inspects a single OpenLiteSpeed `extraHeaders` line (`Name: Value`, `set Name Value`,
/// `add Name Value`, `append Name Value`, `unset Name`, etc.) against the response header
/// classifier (`R6-MIG-5`, `R7-MIG-12`).
fn inspect_ols_header_line(raw: &str) -> Option<(String, HeaderClassification)> {
    let trimmed = strip_ols_comment(raw).trim();
    if trimmed.is_empty() {
        return None;
    }
    let first_ws = trimmed.find(char::is_whitespace);
    if let Some(ws_idx) = first_ws {
        let first_tok = trimmed.get(..ws_idx).unwrap_or("");
        let rest = trimmed.get(ws_idx..).unwrap_or("").trim();
        let first_lower = first_tok.to_ascii_lowercase();
        if first_lower == "unset" {
            let hdr = rest.split_whitespace().next().unwrap_or("");
            if hdr.eq_ignore_ascii_case("server") || hdr.eq_ignore_ascii_case("x-powered-by") {
                return None;
            }
            return Some((
                sanitize_untrusted_directive_token(hdr),
                HeaderClassification::SecurityDowngrade(
                    "OpenLiteSpeed `extraHeaders unset` cannot be auto-translated",
                ),
            ));
        }
        if matches!(
            first_lower.as_str(),
            "set" | "add" | "append" | "merge" | "setifempty"
        ) {
            let (hdr_name, hdr_val) = match rest.find(char::is_whitespace) {
                Some(i) => (
                    rest.get(..i).unwrap_or("").trim_end_matches(':'),
                    rest.get(i..).unwrap_or("").trim(),
                ),
                None => (rest.trim_end_matches(':'), ""),
            };
            let class = classify_untranslated_security_header(hdr_name, hdr_val);
            return if class == HeaderClassification::CoveredByStrict {
                None
            } else {
                Some((sanitize_untrusted_directive_token(hdr_name), class))
            };
        }
    }

    if let Some((hdr_name, hdr_val)) = trimmed.split_once(':') {
        let clean_name = hdr_name.trim();
        let class = classify_untranslated_security_header(clean_name, hdr_val.trim());
        return if class == HeaderClassification::CoveredByStrict {
            None
        } else {
            Some((sanitize_untrusted_directive_token(clean_name), class))
        };
    }

    if let Some(ws_idx) = first_ws {
        let clean_name = trimmed.get(..ws_idx).unwrap_or("").trim();
        let hdr_val = trimmed.get(ws_idx..).unwrap_or("").trim();
        let class = classify_untranslated_security_header(clean_name, hdr_val);
        return if class == HeaderClassification::CoveredByStrict {
            None
        } else {
            Some((sanitize_untrusted_directive_token(clean_name), class))
        };
    }

    Some((
        sanitize_untrusted_directive_token(trimmed),
        HeaderClassification::SecurityDowngrade(
            "unrecognized OpenLiteSpeed `extraHeaders` rule cannot be auto-translated",
        ),
    ))
}

fn record_ols_header_downgrade(
    hdr_name: &str,
    class: HeaderClassification,
    line_no: usize,
    stack: &[OlsBlock],
    current_ctx: &mut OlsContext,
    site: &mut MigratedSite,
    doc: &mut MigratedDoc,
) {
    let reason = match class {
        HeaderClassification::CoveredByStrict => return,
        HeaderClassification::SafeToDropWithNote(reason) => {
            doc.push_note(
                Some(line_no),
                "extraHeaders",
                format!(
                    "OpenLiteSpeed `extraHeaders` setting `{hdr_name}` was not auto-translated ({reason})"
                ),
            );
            return;
        }
        HeaderClassification::SecurityDowngrade(reason) => reason,
    };
    doc.push_security_downgrade(
        Some(line_no),
        "extraHeaders",
        format!(
            "OpenLiteSpeed `extraHeaders` setting `{hdr_name}` cannot be auto-translated ({reason}); affected routes withheld"
        ),
    );
    if in_context(stack) {
        current_ctx.blocked_by_security = true;
        current_ctx.blocker_info = current_ctx
            .blocker_info
            .clone()
            .or_else(|| Some((line_no, format!("extraHeaders {hdr_name}"))));
    } else {
        site.block_site(Some(line_no), &format!("extraHeaders {hdr_name}"));
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_ols_rewrite_line(
    line: &str,
    line_no: usize,
    key_lower: &str,
    args: &[&str],
    rewrite_enabled: &mut bool,
    stack: &[OlsBlock],
    current_ctx: &mut OlsContext,
    state: &mut OlsParseState,
    doc: &mut MigratedDoc,
) {
    if key_lower == "autoloadhtaccess" {
        // R8-MIG-9: `.htaccess` files are read and enforced by the source server (deny rules,
        // `[F]` rewrites, auth). MiraServe does not read them, exactly as with Apache
        // `AllowOverride All`, which the Apache importer refuses.
        if args.first().copied().is_some_and(|v| v != "0") {
            doc.push_security_downgrade(
                Some(line_no),
                "autoLoadHtaccess",
                "OpenLiteSpeed `autoLoadHtaccess 1` loads per-directory `.htaccess` access and rewrite rules which MiraServe does not evaluate; audit and port those rules manually",
            );
            if in_context(stack) {
                current_ctx.blocked_by_security = true;
                current_ctx.blocker_info = current_ctx
                    .blocker_info
                    .clone()
                    .or_else(|| Some((line_no, "autoLoadHtaccess".to_owned())));
            } else {
                state.site.block_site(Some(line_no), "autoLoadHtaccess");
            }
        }
    } else if key_lower == "enable" {
        *rewrite_enabled = args.first().copied() != Some("0");
    } else if !*rewrite_enabled {
        // Rewrite engine is explicitly disabled (`enable 0`) in this block.
    } else if key_lower == "rewritefile" {
        // R5-MIG-6: `RewriteFile .htaccess` loads external `.htaccess` rules which
        // MiraServe does not interpret!
        doc.push_security_downgrade(
            Some(line_no),
            "RewriteFile",
            format!(
                "OpenLiteSpeed `{line}` loads external rewrite/access rules which MiraServe does not evaluate; audit and port rules manually"
            ),
        );
        if in_context(stack) {
            current_ctx.blocked_by_security = true;
            current_ctx.blocker_info = current_ctx
                .blocker_info
                .clone()
                .or_else(|| Some((line_no, "RewriteFile".to_owned())));
        } else {
            state.site.block_site(Some(line_no), "RewriteFile");
        }
    } else if has_blocking_rewrite_flag(line) {
        // R5-MIG-6: Case-insensitive bracketed flag parser catches `[L,R=403]`,
        // `[R=404,L]`, `[nc,f]`, `[L,R=405]`, `[G]`, etc.!
        doc.push_security_downgrade(
            Some(line_no),
            "rewrite",
            format!(
                "OpenLiteSpeed blocking rewrite rule '{line}' cannot be auto-translated; verify access control manually"
            ),
        );
        if in_context(stack) {
            current_ctx.blocked_by_security = true;
            current_ctx.blocker_info = current_ctx
                .blocker_info
                .clone()
                .or_else(|| Some((line_no, "rewrite".to_owned())));
        } else {
            state.site.block_site(Some(line_no), "rewrite");
        }
    } else if line.contains("index.php") {
        if state.php_indicator.is_none() {
            state.php_indicator = Some((line_no, line.to_owned()));
        }
        state.site.routes.push(MigratedRoute::new(
            "/*".to_owned(),
            MigratedHandler::TryFiles {
                candidates: vec![
                    "{path}".to_owned(),
                    "{path}/".to_owned(),
                    "/index.php?{query}".to_owned(),
                ],
            },
        ));
        doc.push_upgrade(
            "Converted OpenLiteSpeed front-controller rewrite rules into safe try-files route",
        );
    }
}

/// Parses an OpenLiteSpeed `vhconf.conf` or `httpd_config.conf` into an unfinalized
/// [`MigratedDoc`] (`lib.rs` runs `finalize_doc_with_options`), expanding bounded local
/// `configFile` includes when `source_path` is provided (`R6-MIG-8`, `R6-MIG-11`, `R7-MIG-13`).
#[allow(clippy::too_many_lines)]
pub(crate) fn parse_openlitespeed_raw_with_path(
    input: &str,
    source_path: Option<&Path>,
    source_root: Option<&Path>,
) -> MigratedDoc {
    let mut doc = MigratedDoc::new();
    let mut state = OlsParseState::default();
    let mut inc_ctx =
        source_path.and_then(|p| IncludeContext::from_source_path(p, true, source_root));

    parse_openlitespeed_stream(input, None, inc_ctx.as_mut(), &mut state, &mut doc);
    doc.set_source_file(None);

    // R6-MIG-11: Populate hosts from `listener { map ... }` if `vhDomain` was absent; only fall
    // back to internal `virtualHost` name when it looks like a real hostname (contains `.` or is
    // `localhost`), never emitting internal labels such as `Example`!
    if state.site.hosts.is_empty() {
        for domain in state.mapped_domains {
            if !state.site.hosts.contains(&domain) {
                state.site.hosts.push(domain);
            }
        }
    }
    if state.site.hosts.is_empty()
        && let Some(ref vh_name) = state.vhost_name
        && (vh_name.contains('.') || vh_name.eq_ignore_ascii_case("localhost"))
    {
        state.site.hosts.push(vh_name.clone());
    }

    // R4-MIG-3: Unused top-level `realm` definitions (such as default `SampleProtectedArea`) are
    // informational notes ONLY and do NOT block an otherwise clean OpenLiteSpeed vhost!
    for (realm_line, realm_name) in state.defined_realms {
        if !state.referenced_realms.contains(&realm_name) {
            doc.push_note(
                Some(realm_line),
                "realm",
                format!(
                    "Unused OpenLiteSpeed realm definition '{realm_name}' is not referenced by any context and was skipped"
                ),
            );
        }
    }

    // Map OpenLiteSpeed contexts (proxy; fail closed on scoped fcgi/lsapi/cgi/appserver contexts,
    // `R7-MIG-10`!).
    let mut context_bound_procs: HashSet<String> = HashSet::new();
    for ctx in state.contexts {
        if ctx.blocked_by_security {
            continue;
        }
        if ctx.kind == "proxy" {
            let target = state
                .ext_procs
                .get(&ctx.handler)
                .map_or_else(|| ctx.handler.clone(), |p| p.address.clone());
            if !target.is_empty() {
                state.site.routes.push(MigratedRoute::new(
                    normalize_route_pattern(&ctx.uri),
                    MigratedHandler::ReverseProxy {
                        upstreams: vec![normalize_upstream_url(&target)],
                        preserve_host: false,
                        allow_upgrades: false,
                    },
                ));
            }
        } else if matches!(ctx.kind.as_str(), "fcgi" | "lsapi" | "cgi" | "appserver") {
            // R7-MIG-10: Never drop a scoped FastCGI/dynamic context (e.g. `context /app/ { type
            // fcgi; handler py_app; }`) or map its processor to site-wide `*.php`!
            context_bound_procs.insert(ctx.handler.clone());
            let pat = normalize_route_pattern(&ctx.uri);
            let ctx_line = if ctx.line > 0 { Some(ctx.line) } else { None };
            state
                .site
                .add_blocked_location(pat, ctx_line, &format!("context ({})", ctx.kind));
            doc.push_security_downgrade(
                ctx_line,
                "context",
                format!(
                    "OpenLiteSpeed context '{}' uses dynamic handler type '{}' ('{}') which cannot be faithfully scoped without changing script execution or exposing source; configure explicit routes manually",
                    ctx.uri, ctx.kind, ctx.handler
                ),
            );
        } else {
            // R8-MIG-7 & R8-MIG-8: every other context kind. A plain static context that keeps
            // the document-root mapping needs nothing. A `redirect` context, or a static context
            // whose `location` points somewhere else, answers differently from the document
            // root, so its prefix is closed. An unknown kind is a blocker.
            let is_static = matches!(ctx.kind.as_str(), "" | "null" | "static");
            let remapped = ctx
                .location
                .as_deref()
                .map(str::trim)
                .is_some_and(|l| !l.is_empty());
            if is_static && !remapped {
                continue;
            }
            let pat = normalize_route_pattern(&ctx.uri);
            let ctx_line = if ctx.line > 0 { Some(ctx.line) } else { None };
            let label = if is_static {
                "context (location)".to_owned()
            } else {
                format!(
                    "context ({})",
                    sanitize_untrusted_directive_token(&ctx.kind)
                )
            };
            let closable = (is_static || ctx.kind == "redirect") && pat != "/*" && pat != "/";
            if closable {
                state.site.closed_prefixes.push((pat, ctx_line, label));
            } else {
                state.site.block_site(ctx_line, &label);
                doc.push_security_downgrade(
                    ctx_line,
                    "context",
                    format!(
                        "OpenLiteSpeed context '{}' ({label}) changes what the path serves and cannot be auto-translated; site withheld",
                        ctx.uri
                    ),
                );
            }
        }
    }

    // R7-MIG-10: Respect explicit `scriptHandler { add <type:name> <suffixes...> }` mappings so
    // non-PHP FastCGI processors (e.g. Python `.py`) NEVER get blindly mapped to `*.php`, and
    // multi-suffix PHP handlers emit one route per explicit suffix!
    let mut emitted_fcgi = false;
    let mut emitted_php_fcgi = false;
    let mut saw_lsapi = false;
    let mut handled_fcgi_procs: HashSet<String> = HashSet::new();
    for sh in &state.script_handlers {
        if sh.kind == "fcgi" {
            let Some(proc) = state.ext_procs.get(&sh.handler_name) else {
                state.site.block_site(Some(sh.line), "scriptHandler");
                doc.push_security_downgrade(
                    Some(sh.line),
                    "scriptHandler",
                    format!(
                        "OpenLiteSpeed `scriptHandler` references undefined FastCGI processor '{}'",
                        sh.handler_name
                    ),
                );
                continue;
            };
            if proc.kind != "fcgi" {
                continue;
            }
            handled_fcgi_procs.insert(sh.handler_name.clone());
            let target = normalize_fastcgi_target(&proc.address);
            for suffix in &sh.suffixes {
                let pat = format!("*.{suffix}");
                if suffix.starts_with("php") || matches!(suffix.as_str(), "phtml" | "phar" | "pht")
                {
                    emitted_php_fcgi = true;
                }
                state.site.routes.push(MigratedRoute::new(
                    pat,
                    MigratedHandler::FastCgi {
                        target: target.clone(),
                    },
                ));
                emitted_fcgi = true;
            }
            doc.push_upgrade(format!(
                "Migrated OpenLiteSpeed FastCGI scriptHandler '{}' ({}) to pure-Rust async FastCGI",
                sh.handler_name,
                sh.suffixes.join(", ")
            ));
        }
    }

    for (name, proc) in &state.ext_procs {
        if proc.kind == "fcgi" {
            if handled_fcgi_procs.contains(name) || context_bound_procs.contains(name) {
                continue;
            }
            let looks_php = state.php_indicator.is_some()
                || name.to_ascii_lowercase().contains("php")
                || proc.address.to_ascii_lowercase().contains("php");
            if looks_php && !emitted_fcgi {
                // MIG-7: `normalize_fastcgi_target` preserves leading `/` on `uds://tmp/...` -> `unix:/tmp/...`!
                let target = normalize_fastcgi_target(&proc.address);
                state.site.routes.push(MigratedRoute::new(
                    "*.php".to_owned(),
                    MigratedHandler::FastCgi { target },
                ));
                doc.push_upgrade(format!(
                    "Migrated OpenLiteSpeed FastCGI processor '{name}' to pure-Rust async FastCGI"
                ));
                emitted_fcgi = true;
                emitted_php_fcgi = true;
            } else {
                // R7-MIG-10: Never guess `*.php` for an unmapped non-PHP FastCGI processor!
                state.site.block_site(Some(proc.line), "extprocessor.fcgi");
                doc.push_security_downgrade(
                    Some(proc.line),
                    "extprocessor.fcgi",
                    format!(
                        "OpenLiteSpeed FastCGI processor '{name}' ({}) has no `scriptHandler` suffix mapping; refusing to guess `*.php` — configure explicit FastCGI routes manually",
                        proc.address
                    ),
                );
            }
        } else if proc.kind == "lsapi" {
            // R2-MIG-4 & R5-MIG-1: NEVER emit an LSAPI socket as `fastcgi-pass`, AND block the
            // site so fail-closed omits it and `--allow-insecure` tags it `// INSECURE:`!
            saw_lsapi = true;
            state.site.block_site(Some(proc.line), "extprocessor.lsapi");
            doc.push_security_downgrade(
                Some(proc.line),
                "extprocessor.lsapi",
                format!(
                    "OpenLiteSpeed LSAPI processor '{name}' ({}) speaks LiteSpeed LSAPI, NOT FastCGI, so no `fastcgi-pass` route was generated; site withheld until a real `php-fpm` FastCGI pool is configured",
                    proc.address
                ),
            );
        }
    }

    // R5-MIG-1: Fail closed if server/vhost indicates PHP (`scriptHandler` / `indexFiles` /
    // `index.php` rewrite) with NO emitted PHP FastCGI route!
    if !emitted_php_fcgi
        && !saw_lsapi
        && let Some((php_line, php_src)) = state.php_indicator
    {
        state.site.block_site(Some(php_line), "php");
        doc.push_security_downgrade(
            Some(php_line),
            "php",
            format!(
                "OpenLiteSpeed config indicates PHP execution ({php_src}) but no FastCGI route was emitted; configure `php-fpm` with `fastcgi-pass` manually"
            ),
        );
    }

    if !state.site.hosts.is_empty()
        || state.site.root.is_some()
        || !state.site.routes.is_empty()
        || state.site.site_wide_auth_blocked
        || state.vhost_name.is_some()
    {
        doc.sites.push(state.site);
    }

    doc
}

#[allow(clippy::too_many_lines)]
fn parse_openlitespeed_stream(
    input: &str,
    source_file: Option<&str>,
    mut inc_ctx: Option<&mut IncludeContext>,
    state: &mut OlsParseState,
    doc: &mut MigratedDoc,
) {
    let prev_file = doc.set_source_file(source_file.map(str::to_owned));
    let mut stack: Vec<OlsBlock> = Vec::new();
    let mut current_proc = ExtProc::default();
    let mut current_ctx = OlsContext::default();
    let mut current_listener = OlsListener::default();
    let mut rewrite_enabled = true;
    let mut per_client_limit_nonzero = false;
    let mut active_heredoc: Option<OlsHeredoc> = None;

    for (idx, raw_line) in input.lines().enumerate() {
        let line_no = idx.saturating_add(1);

        // Handle multiline OpenLiteSpeed heredocs (`extraHeaders <<<END ... END`, `rules <<<END ... END`).
        if let Some(ref heredoc) = active_heredoc {
            if raw_line.trim() == heredoc.end_marker() {
                active_heredoc = None;
                continue;
            }
            match heredoc {
                OlsHeredoc::ExtraHeaders { .. } => {
                    if let Some((hdr_name, reason)) = inspect_ols_header_line(raw_line) {
                        record_ols_header_downgrade(
                            &hdr_name,
                            reason,
                            line_no,
                            &stack,
                            &mut current_ctx,
                            &mut state.site,
                            doc,
                        );
                    }
                }
                OlsHeredoc::RewriteRules { .. } => {
                    let line = strip_ols_comment(raw_line);
                    if !line.is_empty() {
                        let toks: Vec<&str> = line.split_whitespace().collect();
                        let key_lower = toks
                            .first()
                            .map_or_else(String::new, |k| k.to_ascii_lowercase());
                        let args = toks.get(1..).unwrap_or(&[]);
                        handle_ols_rewrite_line(
                            line,
                            line_no,
                            &key_lower,
                            args,
                            &mut rewrite_enabled,
                            &stack,
                            &mut current_ctx,
                            state,
                            doc,
                        );
                    }
                }
            }
            continue;
        }

        let line = strip_ols_comment(raw_line);
        if line.is_empty() {
            continue;
        }

        if line == "}" {
            if let Some(popped) = stack.pop() {
                match popped {
                    OlsBlock::ExtProcessor(name) if !name.is_empty() => {
                        state
                            .ext_procs
                            .insert(name, std::mem::take(&mut current_proc));
                    }
                    OlsBlock::Listener => {
                        let listener = std::mem::take(&mut current_listener);
                        for (bind, port) in listener.addresses {
                            let is_https = listener.secure.unwrap_or(port == 443);
                            if is_https {
                                state.site.add_https_bind(bind.clone());
                                doc.add_https_bind(bind);
                            } else {
                                state.site.add_http_bind(bind.clone());
                                doc.add_http_bind(bind);
                            }
                        }
                        for domain in listener.mapped_domains {
                            if !state.mapped_domains.contains(&domain) {
                                state.mapped_domains.push(domain);
                            }
                        }
                    }
                    OlsBlock::Context if !current_ctx.uri.is_empty() => {
                        let ctx = std::mem::take(&mut current_ctx);
                        if ctx.blocked_by_security {
                            let (b_line, b_dir) = ctx
                                .blocker_info
                                .clone()
                                .unwrap_or((line_no, "context".to_owned()));
                            state.site.add_blocked_location(
                                normalize_route_pattern(&ctx.uri),
                                Some(b_line),
                                &b_dir,
                            );
                        }
                        state.contexts.push(ctx);
                    }
                    OlsBlock::PerClientConnLimit => {
                        if !per_client_limit_nonzero {
                            doc.push_upgrade(
                                "Preserved OpenLiteSpeed stock `perClientConnLimit` defaults via MiraServe per-IP connection caps",
                            );
                        }
                        per_client_limit_nonzero = false;
                    }
                    _ => {}
                }
            }
            continue;
        }

        let tokens: Vec<&str> = line.trim_end_matches('{').split_whitespace().collect();
        let Some(&key) = tokens.first() else {
            continue;
        };
        let args = tokens.get(1..).unwrap_or(&[]);
        let key_lower = key.to_ascii_lowercase();

        if line.ends_with('{') {
            match key_lower.as_str() {
                "virtualhost" => {
                    if let Some(&name) = args.first()
                        && state.vhost_name.is_none()
                    {
                        state.vhost_name = Some(name.to_owned());
                    }
                    stack.push(OlsBlock::VirtualHost);
                }
                "listener" => {
                    current_listener = OlsListener::default();
                    stack.push(OlsBlock::Listener);
                }
                "extprocessor" => {
                    let proc_name = args.first().copied().unwrap_or("").to_owned();
                    current_proc = ExtProc {
                        line: line_no,
                        ..ExtProc::default()
                    };
                    stack.push(OlsBlock::ExtProcessor(proc_name));
                }
                "context" => {
                    current_ctx = OlsContext {
                        line: line_no,
                        uri: args.first().copied().unwrap_or("/").to_owned(),
                        ..OlsContext::default()
                    };
                    stack.push(OlsBlock::Context);
                }
                "vhssl" => stack.push(OlsBlock::VhSsl),
                "rewrite" => {
                    rewrite_enabled = true;
                    stack.push(OlsBlock::Rewrite);
                }
                "accesscontrol" => {
                    stack.push(OlsBlock::AccessControl);
                }
                "scripthandler" => {
                    stack.push(OlsBlock::ScriptHandler);
                }
                "index" => {
                    stack.push(OlsBlock::Index);
                }
                "perclientconnlimit" => {
                    per_client_limit_nonzero = false;
                    stack.push(OlsBlock::PerClientConnLimit);
                }
                "accessdenydir" => {
                    stack.push(OlsBlock::AccessDenyDir);
                }
                "realm" => {
                    let realm_name = args.first().copied().unwrap_or("<unnamed>").to_owned();
                    if in_context(&stack) {
                        current_ctx.blocked_by_security = true;
                        current_ctx.blocker_info = current_ctx
                            .blocker_info
                            .clone()
                            .or_else(|| Some((line_no, "realm".to_owned())));
                        state.referenced_realms.insert(realm_name);
                        doc.push_security_downgrade(
                            Some(line_no),
                            "realm",
                            "OpenLiteSpeed `realm` authentication block inside context cannot be auto-translated",
                        );
                    } else {
                        state.defined_realms.push((line_no, realm_name));
                    }
                    stack.push(OlsBlock::Realm);
                }
                "module" => {
                    let mod_name = args.first().copied().unwrap_or("");
                    if mod_name.eq_ignore_ascii_case("cache")
                        || mod_name.eq_ignore_ascii_case("lscache")
                    {
                        doc.push_note(
                            Some(line_no),
                            "module",
                            format!(
                                "OpenLiteSpeed cache module `module {mod_name}` skipped (configure HTTP caching separately if needed)"
                            ),
                        );
                    } else {
                        doc.push_security_downgrade(
                            Some(line_no),
                            key,
                            format!(
                                "OpenLiteSpeed security/WAF block `{line}` cannot be auto-translated; site/route withheld"
                            ),
                        );
                        if in_context(&stack) {
                            current_ctx.blocked_by_security = true;
                            current_ctx.blocker_info = current_ctx
                                .blocker_info
                                .clone()
                                .or_else(|| Some((line_no, key.to_owned())));
                        } else {
                            state.site.block_site(Some(line_no), key);
                        }
                    }
                    stack.push(OlsBlock::Other);
                }
                "lsrecaptcha" | "accessdeny" | "security" | "phpinioverride" => {
                    doc.push_security_downgrade(
                        Some(line_no),
                        key,
                        format!(
                            "OpenLiteSpeed security/PHP-ini block `{line}` cannot be auto-translated; site/route withheld"
                        ),
                    );
                    if in_context(&stack) {
                        current_ctx.blocked_by_security = true;
                        current_ctx.blocker_info = current_ctx
                            .blocker_info
                            .clone()
                            .or_else(|| Some((line_no, key.to_owned())));
                    } else {
                        state.site.block_site(Some(line_no), key);
                    }
                    stack.push(OlsBlock::Other);
                }
                _ => stack.push(OlsBlock::Other),
            }
            continue;
        }

        // R6-MIG-5: Inspect `extraHeaders` in ANY scope (context, virtualHost, or top-level),
        // supporting both single-line values and `<<<END ... END` heredocs!
        if key_lower == "extraheaders" {
            let remainder = line.get(key.len()..).unwrap_or("").trim();
            if let Some(marker) = remainder.strip_prefix("<<<") {
                let end_marker = marker.trim().to_owned();
                if !end_marker.is_empty() {
                    active_heredoc = Some(OlsHeredoc::ExtraHeaders { end_marker });
                }
            } else if !remainder.is_empty()
                && let Some((hdr_name, reason)) = inspect_ols_header_line(remainder)
            {
                record_ols_header_downgrade(
                    &hdr_name,
                    reason,
                    line_no,
                    &stack,
                    &mut current_ctx,
                    &mut state.site,
                    doc,
                );
            }
            continue;
        }

        match stack.last() {
            Some(OlsBlock::Listener) => match key_lower.as_str() {
                "address" => {
                    if let Some(&addr_tok) = args.first() {
                        if let Some((bind, port)) =
                            normalize_bind_addr_with_default_port(addr_tok, 80)
                        {
                            current_listener.addresses.push((bind, port));
                        } else if addr_tok.contains('%') {
                            doc.push_note(
                                Some(line_no),
                                "address",
                                format!(
                                    "Skipped OpenLiteSpeed template placeholder listener address '{addr_tok}'"
                                ),
                            );
                        }
                    }
                }
                "secure" => {
                    if let Some(&val) = args.first() {
                        let is_tls = val != "0"
                            && !val.eq_ignore_ascii_case("no")
                            && !val.eq_ignore_ascii_case("false");
                        current_listener.secure = Some(is_tls);
                    }
                }
                "map" => {
                    // Format: `map <VHostName> <domain1, domain2, ...>`
                    for raw_d in args
                        .get(1..)
                        .unwrap_or(&[])
                        .join(" ")
                        .split([',', ' '])
                        .filter(|s| !s.is_empty())
                    {
                        let clean = raw_d.trim();
                        if clean != "*"
                            && !current_listener.mapped_domains.iter().any(|d| d == clean)
                        {
                            current_listener.mapped_domains.push(clean.to_owned());
                        }
                    }
                }
                "clientverify" => {
                    let val = args.first().copied().unwrap_or("0");
                    if val != "0" && !val.eq_ignore_ascii_case("none") {
                        state.site.block_site(Some(line_no), "clientVerify");
                        doc.push_security_downgrade(
                            Some(line_no),
                            "clientVerify",
                            format!(
                                "OpenLiteSpeed listener `clientVerify {val}` enforces client certificate auth; configure MiraServe `client-ca` manually"
                            ),
                        );
                    }
                }
                _ => {}
            },
            Some(OlsBlock::ExtProcessor(_)) => match key_lower.as_str() {
                "type" => {
                    current_proc.kind = args.first().copied().unwrap_or("").to_ascii_lowercase();
                }
                "address" => args
                    .first()
                    .copied()
                    .unwrap_or("")
                    .clone_into(&mut current_proc.address),
                _ => {}
            },
            Some(OlsBlock::ScriptHandler) => {
                if key_lower == "add" {
                    if let Some(&handler_spec) = args.first()
                        && let Some((kind_raw, handler_name)) = handler_spec.split_once(':')
                    {
                        let kind = kind_raw.trim().to_ascii_lowercase();
                        let mut suffixes: Vec<String> = Vec::new();
                        for tok in args.get(1..).unwrap_or(&[]) {
                            for raw_suf in tok.split(',') {
                                let clean =
                                    raw_suf.trim().trim_start_matches('.').to_ascii_lowercase();
                                if !clean.is_empty()
                                    && clean.len() <= 16
                                    && clean.bytes().all(|b| b.is_ascii_alphanumeric())
                                    && !suffixes.contains(&clean)
                                {
                                    suffixes.push(clean);
                                }
                            }
                        }
                        if !suffixes.is_empty() {
                            state.script_handlers.push(OlsScriptHandlerEntry {
                                line: line_no,
                                kind,
                                handler_name: handler_name.trim().to_owned(),
                                suffixes,
                            });
                        }
                    }
                    if args.iter().any(|a| a.to_ascii_lowercase().contains("php"))
                        && state.php_indicator.is_none()
                    {
                        state.php_indicator = Some((line_no, format!("scriptHandler `{line}`")));
                    }
                }
            }
            Some(OlsBlock::Index) => {
                if key_lower == "indexfiles"
                    && is_php_index_list(args)
                    && state.php_indicator.is_none()
                {
                    state.php_indicator = Some((line_no, format!("indexFiles {}", args.join(" "))));
                }
            }
            Some(OlsBlock::PerClientConnLimit) => {
                if matches!(
                    key_lower.as_str(),
                    "staticreqpersec" | "dynreqpersec" | "outbandwidth" | "inbandwidth"
                ) && let Some(&raw_val) = args.first()
                    && raw_val.parse::<u64>().is_ok_and(|n| n > 0)
                {
                    per_client_limit_nonzero = true;
                    state.site.block_site(Some(line_no), "perClientConnLimit");
                    doc.push_security_downgrade(
                        Some(line_no),
                        "perClientConnLimit",
                        format!(
                            "OpenLiteSpeed `perClientConnLimit` enforces active limit `{key} {raw_val}` which cannot be auto-translated; configure MiraServe `rate-limit` manually"
                        ),
                    );
                }
            }
            Some(OlsBlock::AccessDenyDir) => {
                if key_lower == "dir"
                    && let Some(&dir_path) = args.first()
                {
                    if is_stock_ols_access_deny_dir(dir_path) {
                        doc.push_upgrade(
                            "Preserved OpenLiteSpeed stock `accessDenyDir` system-path denials via MiraServe `cap-std` confinement",
                        );
                    } else {
                        state.site.block_site(Some(line_no), "accessDenyDir");
                        doc.push_security_downgrade(
                            Some(line_no),
                            "accessDenyDir",
                            format!(
                                "OpenLiteSpeed custom `accessDenyDir` entry `{dir_path}` cannot be auto-translated; site withheld"
                            ),
                        );
                    }
                }
            }
            Some(OlsBlock::Context) => match key_lower.as_str() {
                "type" => {
                    current_ctx.kind = args.first().copied().unwrap_or("").to_ascii_lowercase();
                }
                "handler" => args
                    .first()
                    .copied()
                    .unwrap_or("")
                    .clone_into(&mut current_ctx.handler),
                "statuscode" => {
                    if let Some(&raw_code) = args.first()
                        && let Ok(code) = raw_code.parse::<u16>()
                        && (400..=599).contains(&code)
                    {
                        current_ctx.blocked_by_security = true;
                        current_ctx.blocker_info = current_ctx
                            .blocker_info
                            .clone()
                            .or_else(|| Some((line_no, format!("statusCode {code}"))));
                        doc.push_security_downgrade(
                            Some(line_no),
                            "statusCode",
                            format!(
                                "OpenLiteSpeed context '{}' sets blocking `statusCode {code}`; route withheld to avoid exposing denied path",
                                current_ctx.uri
                            ),
                        );
                    }
                }
                "allowbrowse" if args.first().copied() == Some("0") => {
                    current_ctx.blocked_by_security = true;
                    current_ctx.blocker_info = current_ctx
                        .blocker_info
                        .clone()
                        .or_else(|| Some((line_no, "allowBrowse".to_owned())));
                    doc.push_security_downgrade(
                        Some(line_no),
                        "allowBrowse",
                        format!(
                            "OpenLiteSpeed context '{}' sets `allowBrowse 0` (access denied); route withheld to avoid exposing denied path",
                            current_ctx.uri
                        ),
                    );
                }
                "realm" | "authorizer" | "required" | "accessallowed" | "accessdenied" => {
                    if key_lower == "realm"
                        && let Some(&rname) = args.first()
                    {
                        state.referenced_realms.insert(rname.to_owned());
                    }
                    current_ctx.blocked_by_security = true;
                    current_ctx.blocker_info = current_ctx
                        .blocker_info
                        .clone()
                        .or_else(|| Some((line_no, key.to_owned())));
                    doc.push_security_downgrade(
                        Some(line_no),
                        key,
                        format!(
                            "OpenLiteSpeed context '{}' uses security directive '{key}'; route withheld to prevent open exposure",
                            current_ctx.uri
                        ),
                    );
                }
                "location" => {
                    current_ctx.location = Some(args.join(" "));
                }
                "allowbrowse" | "uri" | "note" | "adddefaultcharset" | "indexfiles"
                | "autoindex" | "enableexpires" | "expiresdefault" | "expiresbytype"
                | "enableipgeo" => {}
                other => {
                    // R8-MIG-1: fail closed on context options the importer does not know
                    // (`extraHeaders`, `addMIMEType`, `forceType`, module hooks, typos).
                    let safe_key = sanitize_untrusted_directive_token(other);
                    current_ctx.blocked_by_security = true;
                    current_ctx.blocker_info = current_ctx
                        .blocker_info
                        .clone()
                        .or_else(|| Some((line_no, safe_key.clone())));
                    doc.push_security_downgrade(
                        Some(line_no),
                        safe_key.clone(),
                        format!(
                            "OpenLiteSpeed context '{}' option '{safe_key}' is not translated and is not known to be inert; route withheld",
                            current_ctx.uri
                        ),
                    );
                }
            },
            Some(OlsBlock::AccessControl) => match key_lower.as_str() {
                "deny" => {
                    let val = args.join(" ");
                    if !val.is_empty() {
                        doc.push_security_downgrade(
                            Some(line_no),
                            "accessControl.deny",
                            format!(
                                "OpenLiteSpeed `accessControl {{ deny {val} }}` IP ACL cannot be auto-translated; affected routes withheld"
                            ),
                        );
                        if in_context(&stack) {
                            current_ctx.blocked_by_security = true;
                            current_ctx.blocker_info = current_ctx
                                .blocker_info
                                .clone()
                                .or_else(|| Some((line_no, "accessControl.deny".to_owned())));
                        } else {
                            state.site.block_site(Some(line_no), "accessControl.deny");
                        }
                    }
                }
                "allow" => {
                    let val = args.join(" ").trim().to_owned();
                    if !val.is_empty() && val != "*" && !val.eq_ignore_ascii_case("all") {
                        doc.push_security_downgrade(
                            Some(line_no),
                            "accessControl.allow",
                            format!(
                                "OpenLiteSpeed `accessControl {{ allow {val} }}` restricted IP allowlist cannot be auto-translated; affected routes withheld"
                            ),
                        );
                        if in_context(&stack) {
                            current_ctx.blocked_by_security = true;
                            current_ctx.blocker_info = current_ctx
                                .blocker_info
                                .clone()
                                .or_else(|| Some((line_no, "accessControl.allow".to_owned())));
                        } else {
                            state.site.block_site(Some(line_no), "accessControl.allow");
                        }
                    }
                }
                _ => {}
            },
            Some(OlsBlock::Realm | OlsBlock::Other) => {}
            Some(OlsBlock::VhSsl) => match key_lower.as_str() {
                "certfile" => {
                    if let Some(&c) = args.first() {
                        state.site.cert = Some(c.to_owned());
                    }
                }
                "keyfile" => {
                    if let Some(&k) = args.first() {
                        state.site.key = Some(k.to_owned());
                    }
                }
                "clientverify" => {
                    let val = args.first().copied().unwrap_or("0");
                    if val != "0" && !val.eq_ignore_ascii_case("none") {
                        state.site.block_site(Some(line_no), "clientVerify");
                        doc.push_security_downgrade(
                            Some(line_no),
                            "clientVerify",
                            format!(
                                "OpenLiteSpeed `clientVerify {val}` enforces client certificate auth; configure MiraServe `client-ca` manually"
                            ),
                        );
                    }
                }
                "sslprotocol" => {
                    doc.push_upgrade(
                        "Upgraded OpenLiteSpeed sslProtocol mask to MiraServe TLS 1.3 + X25519MLKEM768 PQC default",
                    );
                }
                _ => {}
            },
            Some(OlsBlock::Rewrite) => {
                if key_lower == "rules"
                    && let Some(&first_arg) = args.first()
                    && let Some(marker) = first_arg.strip_prefix("<<<")
                    && !marker.trim().is_empty()
                {
                    active_heredoc = Some(OlsHeredoc::RewriteRules {
                        end_marker: marker.trim().to_owned(),
                    });
                } else {
                    handle_ols_rewrite_line(
                        line,
                        line_no,
                        &key_lower,
                        args,
                        &mut rewrite_enabled,
                        &stack,
                        &mut current_ctx,
                        state,
                        doc,
                    );
                }
            }
            Some(OlsBlock::VirtualHost) | None => match key_lower.as_str() {
                "vhroot" => {
                    if let Some(&r) = args.first() {
                        let trimmed = r.trim_end_matches('/');
                        let abs = if trimmed.starts_with('/') {
                            trimmed.to_owned()
                        } else {
                            format!("/usr/local/lsws/{trimmed}")
                        };
                        state.vh_root = Some(abs);
                    }
                }
                "configfile" => {
                    if let Some(&cfg_target) = args.first()
                        && let Some(ctx) = inc_ctx.as_deref_mut()
                    {
                        let expanded = match ctx.expand(cfg_target, false) {
                            BoundedIncludeResult::Expanded(files) => Some(files),
                            BoundedIncludeResult::Unavailable => cfg_target
                                .strip_prefix("conf/")
                                .and_then(|rel| match ctx.expand(rel, false) {
                                    BoundedIncludeResult::Expanded(files) => Some(files),
                                    BoundedIncludeResult::Unavailable => None,
                                }),
                        };
                        if let Some(files) = expanded {
                            let safe_target = sanitize_diagnostic_text(cfg_target, 120);
                            doc.push_note(
                                Some(line_no),
                                "configFile",
                                format!(
                                    "Expanded OpenLiteSpeed `configFile {safe_target}` from local config tree ({} file(s))",
                                    files.len()
                                ),
                            );
                            for (canon_path, content) in files {
                                if !ctx.enter(canon_path.clone()) {
                                    continue;
                                }
                                let label =
                                    canon_path.file_name().and_then(|n| n.to_str()).map_or_else(
                                        || canon_path.display().to_string(),
                                        str::to_owned,
                                    );
                                parse_openlitespeed_stream(
                                    &content,
                                    Some(&label),
                                    Some(ctx),
                                    state,
                                    doc,
                                );
                                ctx.leave(&canon_path);
                            }
                        }
                    }
                }
                "vhdomain" | "vhaliases" => {
                    for raw_h in args.join(" ").split([',', ' ']).filter(|s| !s.is_empty()) {
                        let clean = raw_h.trim();
                        if clean != "*" {
                            state.site.hosts.push(clean.to_owned());
                        }
                    }
                }
                "docroot" => {
                    if let Some(&r) = args.first() {
                        let resolved = if r.contains("$VH_ROOT") {
                            if let Some(root_base) = &state.vh_root {
                                Some(r.replace("$VH_ROOT", root_base))
                            } else {
                                // R6-MIG-11: Never silently invent `/var/www` when `$VH_ROOT` is undefined!
                                state.site.block_site(Some(line_no), "docRoot");
                                doc.push_security_downgrade(
                                    Some(line_no),
                                    "docRoot",
                                    format!(
                                        "OpenLiteSpeed `docRoot '{r}'` references undefined `$VH_ROOT` (import via `httpd_config.conf` or set a concrete path); site withheld rather than guessing `/var/www`"
                                    ),
                                );
                                None
                            }
                        } else {
                            Some(r.to_owned())
                        };
                        if let Some(resolved_path) = resolved {
                            if resolved_path.to_ascii_lowercase().contains("wordpress") {
                                state.site.wordpress = true;
                                doc.push_upgrade(
                                    "Detected OpenLiteSpeed WordPress docRoot — enabled preset \"wordpress-hardened\"",
                                );
                            }
                            state.site.root = Some(resolved_path);
                        }
                    }
                }
                "indexfiles" => {
                    if is_php_index_list(args) && state.php_indicator.is_none() {
                        state.php_indicator =
                            Some((line_no, format!("indexFiles {}", args.join(" "))));
                    }
                }
                "adminemails" => {
                    if let Some(&e) = args.first() {
                        if is_routable_acme_email(e) {
                            doc.acme_email = Some(e.to_owned());
                        } else {
                            doc.push_note(
                                Some(line_no),
                                "adminEmails",
                                format!("Skipped non-routable OpenLiteSpeed adminEmails '{e}'"),
                            );
                        }
                    }
                }
                "realm" => {
                    if let Some(&rname) = args.first() {
                        state.referenced_realms.insert(rname.to_owned());
                    }
                    state.site.block_site(Some(line_no), "realm");
                    doc.push_security_downgrade(
                        Some(line_no),
                        "realm",
                        "OpenLiteSpeed vhost-level `realm` authentication directive cannot be auto-translated; site withheld",
                    );
                }
                "vhname"
                | "allowsymbollink"
                | "enablescript"
                | "restrained"
                | "setuidmode"
                | "enablegzip"
                | "enablebr"
                | "cgroups"
                | "servername"
                | "user"
                | "group"
                | "priority"
                | "autorestart"
                | "chrootpath"
                | "enablechroot"
                | "inmembufsize"
                | "swappingdir"
                | "autofix503"
                | "gracefulrestarttimeout"
                | "mime"
                | "showversionnumber"
                | "disablewebadmin"
                | "chrootmode"
                | "maxkeepalivereq"
                | "smartkeepalive" => {}
                other => {
                    let safe_dir = sanitize_untrusted_directive_token(other);
                    doc.push_note(
                        Some(line_no),
                        safe_dir.clone(),
                        format!("OpenLiteSpeed directive '{safe_dir}' requires manual review"),
                    );
                }
            },
        }
    }

    doc.set_source_file(prev_file);
}

fn in_context(stack: &[OlsBlock]) -> bool {
    stack.iter().any(|b| matches!(b, OlsBlock::Context))
}

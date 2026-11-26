//! Caddy (`Caddyfile`) -> MiraServe KDL importer.
//!
//! Handles same-file Caddy snippet expansion (`(name) { ... }` + `import name`, `R6-MIG-9`),
//! named matchers (`@internal`, `MIG-5`, `R5-MIG-4`), `reverse_proxy` / `php_fastcgi` sub-blocks
//! (including `split .php .php5`, `R5-MIG-7`, `R6-MIG-3`), single-line and block `header`
//! default-deny inspection (`R5-MIG-3`, `R6-MIG-5`), `uri strip_prefix` and `handle_path`
//! path-rewriting downgrades (`MIG-6`), PHP-without-FastCGI detection (`R5-MIG-1`),
//! auth/ACL/WAF/rate-limit/mTLS downgrades (`MIG-3`), and explicit bind/plain-HTTP port
//! preservation (`MIG-4`, `R5-MIG-7`, `R6-MIG-8`).

use std::collections::{BTreeMap, HashSet};

use crate::ir::{
    HeaderClassification, MigratedDoc, MigratedHandler, MigratedRoute, MigratedSite,
    classify_untranslated_security_header, is_routable_acme_email,
    normalize_bind_addr_with_default_port, normalize_fastcgi_target, normalize_route_pattern,
    normalize_upstream_url, sanitize_untrusted_directive_token,
};

#[derive(Debug)]
struct HandleScope {
    pattern: String,
    is_named_matcher: bool,
    blocked_by_security: bool,
    pending_routes: Vec<MigratedRoute>,
}

#[derive(Debug)]
enum CaddySubBlock {
    ReverseProxy {
        depth: usize,
        pattern: String,
        has_upstreams: bool,
        line: usize,
        /// Explicit `header_up Host ...`: `Some(true)` = the client's host, `Some(false)` = the
        /// upstream's own host. `None` = Caddy's default, which depends on the upstream scheme.
        host_mode: Option<bool>,
        /// At least one upstream is HTTPS.
        has_https: bool,
    },
    PhpFastCgi {
        depth: usize,
        target: Option<String>,
        emitted_fcgi: bool,
    },
}

impl CaddySubBlock {
    const fn depth(&self) -> usize {
        match self {
            Self::ReverseProxy { depth, .. } | Self::PhpFastCgi { depth, .. } => *depth,
        }
    }
}

const MAX_CADDY_SNIPPET_DEPTH: usize = 8;
const MAX_CADDY_EXPANDED_LINES: usize = 65_536;
const MAX_CADDY_SNIPPET_EXPANSIONS: usize = 256;
const MAX_CADDY_SNIPPET_NOTES: usize = 32;

struct CaddySnippetExpansion {
    lines: NumberedLines,
    notes: Vec<(usize, String)>,
    overflow_error: Option<String>,
}

type NumberedLines = Vec<(usize, String)>;

/// Extracts top-level `(snippet_name) { ... }` definitions from a Caddyfile and expands bounded
/// same-file `import <snippet_name> [args...]` invocations (`R6-MIG-9`).
///
/// Unknown, external-file, cyclic, or depth-exceeded `import` lines are left untouched so the
/// parser's fail-closed `import` guard rejects them with a security downgrade.
fn expand_caddy_snippets(input: &str) -> CaddySnippetExpansion {
    let mut snippets: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut main_lines: Vec<(usize, String)> = Vec::new();
    let mut brace_depth: usize = 0;
    let mut cur_snippet: Option<(String, Vec<String>)> = None;

    for (idx, raw_line) in input.lines().enumerate() {
        let line_no = idx.saturating_add(1);
        let stripped = strip_caddy_comment(raw_line);
        if stripped.is_empty() {
            continue;
        }
        let (opens, closes) = count_unquoted_braces(stripped);

        if let Some((ref name, ref mut body)) = cur_snippet {
            if stripped == "}" && brace_depth == 1 {
                let completed_name = name.clone();
                let completed_body = std::mem::take(body);
                snippets.insert(completed_name, completed_body);
                cur_snippet = None;
                brace_depth = 0;
            } else {
                body.push(raw_line.to_owned());
                brace_depth = brace_depth.saturating_add(opens).saturating_sub(closes);
            }
            continue;
        }

        if brace_depth == 0
            && stripped.ends_with('{')
            && let Some(header) = stripped.strip_suffix('{').map(str::trim)
            && let Some(inner_name) = header.strip_prefix('(').and_then(|s| s.strip_suffix(')'))
            && !inner_name.is_empty()
            && !inner_name.chars().any(char::is_whitespace)
        {
            cur_snippet = Some((inner_name.to_owned(), Vec::new()));
            brace_depth = 1;
            continue;
        }

        main_lines.push((line_no, raw_line.to_owned()));
        brace_depth = brace_depth.saturating_add(opens).saturating_sub(closes);
    }

    if snippets.is_empty() {
        return CaddySnippetExpansion {
            lines: main_lines,
            notes: Vec::new(),
            overflow_error: None,
        };
    }

    let mut out = Vec::with_capacity(main_lines.len());
    let mut active = HashSet::new();
    let mut expanded_notes = Vec::new();
    let mut noted_snippets = HashSet::new();
    let mut total_expansions = 0_usize;
    let mut overflow_error: Option<String> = None;
    expand_caddy_snippet_lines(
        &main_lines,
        &snippets,
        &mut active,
        0,
        &mut total_expansions,
        &mut out,
        &mut expanded_notes,
        &mut noted_snippets,
        &mut overflow_error,
    );
    CaddySnippetExpansion {
        lines: out,
        notes: expanded_notes,
        overflow_error,
    }
}

fn substitute_caddy_snippet_args(line: &str, args: &[String]) -> String {
    if !line.contains("{args") {
        return line.to_owned();
    }
    let mut replaced = line
        .replace("{args.*}", &args.join(" "))
        .replace("{args[0:]}", &args.join(" "));
    for (idx, arg) in args.iter().enumerate() {
        replaced = replaced
            .replace(&format!("{{args[{idx}]}}"), arg)
            .replace(&format!("{{args.{idx}}}"), arg);
    }
    replaced
}

#[allow(clippy::too_many_arguments)]
fn expand_caddy_snippet_lines(
    lines: &[(usize, String)],
    snippets: &BTreeMap<String, Vec<String>>,
    active: &mut HashSet<String>,
    depth: usize,
    total_expansions: &mut usize,
    out: &mut Vec<(usize, String)>,
    expanded_notes: &mut Vec<(usize, String)>,
    noted_snippets: &mut HashSet<String>,
    overflow_error: &mut Option<String>,
) {
    for (line_no, raw_line) in lines {
        if overflow_error.is_some() {
            return;
        }
        let stripped = strip_caddy_comment(raw_line);
        let toks = tokenize_caddy_line(stripped);
        if toks
            .first()
            .is_some_and(|d| d.eq_ignore_ascii_case("import"))
            && let Some(snippet_name) = toks.get(1)
            && let Some(body) = snippets.get(snippet_name)
        {
            if active.contains(snippet_name) {
                *overflow_error = Some(format!(
                    "Caddyfile line {line_no}: recursive snippet import cycle on '({snippet_name})'"
                ));
                return;
            }
            if depth >= MAX_CADDY_SNIPPET_DEPTH {
                *overflow_error = Some(format!(
                    "Caddyfile line {line_no}: snippet nesting exceeded safety limit of {MAX_CADDY_SNIPPET_DEPTH} levels"
                ));
                return;
            }
            if *total_expansions >= MAX_CADDY_SNIPPET_EXPANSIONS {
                *overflow_error = Some(format!(
                    "Caddyfile line {line_no}: snippet expansion count exceeded safety limit of {MAX_CADDY_SNIPPET_EXPANSIONS} expansions (R7-MIG-8)"
                ));
                return;
            }
            if out.len().saturating_add(body.len()) > MAX_CADDY_EXPANDED_LINES {
                *overflow_error = Some(format!(
                    "Caddyfile line {line_no}: expanded Caddyfile exceeded safety limit of {MAX_CADDY_EXPANDED_LINES} lines (R7-MIG-17)"
                ));
                return;
            }
            *total_expansions = total_expansions.saturating_add(1);
            let call_args = toks.get(2..).unwrap_or(&[]);
            let substituted: Vec<(usize, String)> = body
                .iter()
                .map(|b| (*line_no, substitute_caddy_snippet_args(b, call_args)))
                .collect();
            active.insert(snippet_name.clone());
            if expanded_notes.len() < MAX_CADDY_SNIPPET_NOTES
                && noted_snippets.insert(snippet_name.clone())
            {
                expanded_notes.push((*line_no, snippet_name.clone()));
            }
            expand_caddy_snippet_lines(
                &substituted,
                snippets,
                active,
                depth.saturating_add(1),
                total_expansions,
                out,
                expanded_notes,
                noted_snippets,
                overflow_error,
            );
            active.remove(snippet_name);
            continue;
        }
        if out.len() >= MAX_CADDY_EXPANDED_LINES {
            *overflow_error = Some(format!(
                "Caddyfile line {line_no}: expanded Caddyfile exceeded safety limit of {MAX_CADDY_EXPANDED_LINES} lines (R7-MIG-17)"
            ));
            return;
        }
        out.push((*line_no, raw_line.clone()));
    }
}

fn parse_clean_caddy_extension(raw: &str) -> Option<String> {
    let clean = raw.trim().trim_matches('"').trim_matches('\'');
    let ext = clean.strip_prefix('.')?;
    if !ext.is_empty() && ext.len() <= 16 && ext.bytes().all(|b| b.is_ascii_alphanumeric()) {
        Some(format!("*.{}", ext.to_ascii_lowercase()))
    } else {
        None
    }
}

/// Strips a Caddy `#` comment ONLY when `#` is outside quotes and either at the start of the
/// line or preceded by whitespace (matching official Caddyfile lexer rules).
fn strip_caddy_comment(raw: &str) -> &str {
    let mut in_quote: Option<char> = None;
    let mut prev_ws = true;
    let mut escaped = false;
    for (idx, ch) in raw.char_indices() {
        if escaped {
            escaped = false;
            prev_ws = false;
            continue;
        }
        if let Some(q) = in_quote {
            if ch == '\\' && q == '"' {
                escaped = true;
            } else if ch == q {
                in_quote = None;
            }
            prev_ws = false;
            continue;
        }
        match ch {
            '"' | '`' => {
                in_quote = Some(ch);
                prev_ws = false;
            }
            '#' if prev_ws => {
                return raw.get(..idx).unwrap_or(raw).trim();
            }
            c if c.is_whitespace() => {
                prev_ws = true;
            }
            _ => {
                prev_ws = false;
            }
        }
    }
    raw.trim()
}

/// Quote-aware Caddyfile token splitter (handles `"..."`, `` `...` ``, and bare words).
fn tokenize_caddy_line(line: &str) -> Vec<String> {
    let stripped = line.trim().trim_end_matches('{').trim();
    let mut tokens = Vec::new();
    let mut chars = stripped.chars().peekable();
    while let Some(&ch) = chars.peek() {
        if ch.is_whitespace() {
            chars.next();
            continue;
        }
        if ch == '"' || ch == '`' {
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

/// Counts unquoted `{` and `}` characters so placeholders or quoted strings never skew brace depth.
fn count_unquoted_braces(line: &str) -> (usize, usize) {
    let mut opens = 0_usize;
    let mut closes = 0_usize;
    let mut in_quote: Option<char> = None;
    let mut escaped = false;
    let chars: Vec<char> = line.chars().collect();
    for (idx, &ch) in chars.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if let Some(q) = in_quote {
            if ch == '\\' && q == '"' {
                escaped = true;
            } else if ch == q {
                in_quote = None;
            }
            continue;
        }
        match ch {
            '"' | '`' => in_quote = Some(ch),
            '{' => {
                // Ignore Caddy placeholders like `{path}`, `{query}`, `{$DOMAIN}` (closed on same word).
                let is_placeholder = chars.get(idx.saturating_add(1)..).is_some_and(|rest| {
                    rest.iter()
                        .take_while(|&&c| !c.is_whitespace())
                        .any(|&c| c == '}')
                });
                if !is_placeholder {
                    opens = opens.saturating_add(1);
                }
            }
            '}' => {
                let is_placeholder = idx > 0
                    && chars.get(..idx).is_some_and(|prev| {
                        prev.iter()
                            .rev()
                            .take_while(|&&c| !c.is_whitespace())
                            .any(|&c| c == '{')
                    });
                if !is_placeholder {
                    closes = closes.saturating_add(1);
                }
            }
            _ => {}
        }
    }
    (opens, closes)
}

fn is_blocking_caddy_status(arg: &str) -> bool {
    arg.parse::<u16>()
        .is_ok_and(|status| (400..=599).contains(&status))
}

/// Parses a Caddyfile into an unfinalized [`MigratedDoc`] (`lib.rs` runs `finalize_doc_with_options`).
#[allow(clippy::too_many_lines)]
pub(crate) fn parse_caddy_raw(input: &str) -> MigratedDoc {
    let mut doc = MigratedDoc::new();
    let expansion = expand_caddy_snippets(input);
    if let Some(err_msg) = expansion.overflow_error {
        doc.fatal_error = Some(err_msg);
        return doc;
    }
    let expanded_lines = expansion.lines;
    for (line_no, snippet_name) in expansion.notes {
        doc.push_note(
            Some(line_no),
            "import",
            format!("Expanded same-file Caddy snippet '({snippet_name})'"),
        );
    }

    let mut in_global = false;
    let mut in_snippet = false;
    let mut in_site = false;
    let mut brace_depth: usize = 0;
    let mut current_site = MigratedSite::default();
    let mut current_handle: Option<HandleScope> = None;
    let mut in_tls_block = false;
    let mut in_header_block: Option<(usize, Option<String>)> = None;
    let mut in_proxy_block: Option<CaddySubBlock> = None;
    let mut skip_block_depth: Option<usize> = None;
    // R8-MIG-5: depth of an open `file_server { ... }` block whose sub-directives are inspected
    // (rather than skipped) so `hide`, `root` and unknown options are never dropped silently.
    let mut file_server_block: Option<(usize, Option<String>)> = None;
    let mut global_default_bind: Option<String> = None;
    let mut site_bind_host: Option<String> = None;
    let mut site_ports: Vec<(Option<String>, u16, bool)> = Vec::new();
    let mut site_php_indicator: Option<(usize, String)> = None;

    for (line_no, raw_line) in expanded_lines {
        let line = strip_caddy_comment(&raw_line);
        if line.is_empty() {
            continue;
        }

        let (opens, closes) = count_unquoted_braces(line);

        if !in_global && !in_site && !in_snippet {
            if line == "{" {
                in_global = true;
                brace_depth = 1;
                continue;
            }
            if line.ends_with('{') {
                let header = line.trim_end_matches('{').trim();
                // Unclosed / nested snippet fallback guard
                if header.starts_with('(') && header.ends_with(')') {
                    in_snippet = true;
                    brace_depth = 1;
                    continue;
                }

                current_site = MigratedSite::default();
                site_bind_host = None;
                site_ports.clear();
                site_php_indicator = None;
                for token in header.split([',', ' ']).filter(|t| !t.is_empty()) {
                    let explicit_http = token.starts_with("http://");
                    let explicit_https = token.starts_with("https://");
                    let default_port = if explicit_http { 80 } else { 443 };
                    let clean = token
                        .trim_start_matches("https://")
                        .trim_start_matches("http://");
                    // Preserve explicit IP/loopback bind address if present (`MIG-4`, `R3-MIG-8`, `R5-MIG-7`, `R6-MIG-8`).
                    if let Some((bind, port)) =
                        normalize_bind_addr_with_default_port(clean, default_port)
                    {
                        // R6-MIG-8: In Caddy, bare port `:8080 {` (no `https://`, no hostname)
                        // and `http://127.0.0.1:8081` are PLAIN HTTP, NOT TLS!
                        let is_bare_port = clean.starts_with(':');
                        let is_https =
                            explicit_https || (!explicit_http && !is_bare_port && port != 80);
                        site_ports.push((Some(bind), port, is_https));
                        if clean.eq_ignore_ascii_case("localhost") {
                            current_site.hosts.push("localhost".to_owned());
                        } else if let Some(ip_host) = extract_host_from_addr(clean) {
                            current_site.hosts.push(ip_host);
                        }
                    } else if let Some((host, port_str)) = clean.rsplit_once(':')
                        && let Ok(port) = port_str.parse::<u16>()
                        && port > 0
                    {
                        if !host.is_empty() {
                            current_site.hosts.push(host.to_owned());
                        }
                        let is_https = explicit_https || (!explicit_http && port != 80);
                        site_ports.push((None, port, is_https));
                    } else if !clean.is_empty() {
                        current_site.hosts.push(clean.to_owned());
                    }
                }
                in_site = true;
                brace_depth = 1;
            }
            continue;
        }

        if line == "}" {
            brace_depth = brace_depth.saturating_sub(1);
            if skip_block_depth.is_some_and(|d| brace_depth < d) {
                skip_block_depth = None;
            }
            if file_server_block
                .as_ref()
                .is_some_and(|(d, _)| brace_depth < *d)
            {
                file_server_block = None;
            }
            if in_header_block
                .as_ref()
                .is_some_and(|(d, _)| brace_depth < *d)
            {
                in_header_block = None;
            }
            if in_proxy_block
                .as_ref()
                .is_some_and(|b| brace_depth < b.depth())
                && let Some(closed_block) = in_proxy_block.take()
            {
                match closed_block {
                    CaddySubBlock::PhpFastCgi {
                        target: Some(fcgi_target),
                        emitted_fcgi: false,
                        ..
                    } => {
                        push_caddy_route(
                            &mut current_handle,
                            &mut current_site,
                            MigratedRoute::new(
                                "*.php".to_owned(),
                                MigratedHandler::FastCgi {
                                    target: fcgi_target,
                                },
                            ),
                        );
                    }
                    CaddySubBlock::ReverseProxy {
                        pattern,
                        line,
                        host_mode: None,
                        has_https: true,
                        ..
                    } => {
                        block_caddy_https_default_host(
                            &mut current_handle,
                            &mut current_site,
                            &mut doc,
                            &pattern,
                            line,
                        );
                    }
                    _ => {}
                }
            }
            if in_snippet {
                if brace_depth == 0 {
                    in_snippet = false;
                }
            } else if in_global && brace_depth == 0 {
                in_global = false;
            } else if in_site {
                if brace_depth == 1 {
                    in_tls_block = false;
                    if let Some(handle) = current_handle.take() {
                        flush_caddy_handle(handle, &mut current_site, &mut doc);
                    }
                } else if brace_depth == 0 {
                    if let Some(handle) = current_handle.take() {
                        flush_caddy_handle(handle, &mut current_site, &mut doc);
                    }
                    // R5-MIG-1: Fail closed if this site indicates PHP usage with no emitted FastCGI route!
                    if let Some((php_line, php_src)) = site_php_indicator.take()
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
                                "Caddy site indicates PHP execution ({php_src}) but no FastCGI route was emitted; configure `fastcgi-pass` manually"
                            ),
                        );
                    }
                    let effective_bind =
                        site_bind_host.as_deref().or(global_default_bind.as_deref());
                    flush_site_binds(effective_bind, &site_ports, &mut current_site, &mut doc);
                    in_site = false;
                    in_tls_block = false;
                    in_header_block = None;
                    in_proxy_block = None;
                    doc.sites.push(std::mem::take(&mut current_site));
                }
            }
            continue;
        }

        if in_snippet {
            brace_depth = brace_depth.saturating_add(opens).saturating_sub(closes);
            continue;
        }

        let tokens = tokenize_caddy_line(line);
        let Some(directive_owned) = tokens.first() else {
            brace_depth = brace_depth.saturating_add(opens).saturating_sub(closes);
            continue;
        };
        let directive = directive_owned.as_str();
        let args: Vec<&str> = tokens.iter().skip(1).map(String::as_str).collect();

        if in_global {
            match directive {
                "email" => {
                    if let Some(&email) = args.first() {
                        if is_routable_acme_email(email) {
                            doc.acme_email = Some(email.to_owned());
                        } else {
                            doc.push_note(
                                Some(line_no),
                                "email",
                                format!("Skipped non-routable Caddy ACME email '{email}'"),
                            );
                        }
                    }
                }
                "default_bind" => {
                    // R3-MIG-7: Honor Caddy global `{ default_bind 127.0.0.1 }` so internal sites
                    // never get silently exposed on public `:443`!
                    if let Some(&host) = args.first() {
                        let clean = if host.eq_ignore_ascii_case("localhost") {
                            "127.0.0.1".to_owned()
                        } else {
                            host.to_owned()
                        };
                        global_default_bind = Some(clean);
                    }
                }
                _ => {
                    let safe_dir = sanitize_untrusted_directive_token(directive);
                    doc.push_note(
                        Some(line_no),
                        safe_dir.clone(),
                        format!("Caddy global option '{safe_dir}' requires manual review"),
                    );
                }
            }
            brace_depth = brace_depth.saturating_add(opens).saturating_sub(closes);
            continue;
        }

        // R8-MIG-5: inspect `file_server { ... }` options instead of skipping them.
        if let Some((_, fs_pattern)) = file_server_block.as_ref() {
            let sub_lower = directive.to_ascii_lowercase();
            let hides_only_dotfiles = sub_lower == "hide"
                && !args.is_empty()
                && args.iter().all(|a| is_literal_dotfile_hide_entry(a));
            let inert = matches!(
                sub_lower.as_str(),
                "precompressed"
                    | "index"
                    | "browse"
                    | "disable_canonical_uris"
                    | "etag_file_extensions"
            ) || hides_only_dotfiles;
            if !inert {
                let safe_sub = sanitize_untrusted_directive_token(&sub_lower);
                let label = format!("file_server {safe_sub}");
                doc.push_security_downgrade(
                    Some(line_no),
                    label.clone(),
                    format!(
                        "Caddy `file_server {{ {safe_sub} ... }}` changes which files are served (for example `hide` withholds listed files) and cannot be auto-translated; affected routes withheld"
                    ),
                );
                match fs_pattern {
                    Some(pat) => {
                        current_site.add_blocked_location(pat.clone(), Some(line_no), &label);
                    }
                    None => current_site.block_site(Some(line_no), &label),
                }
            }
            brace_depth = brace_depth.saturating_add(opens).saturating_sub(closes);
            continue;
        }

        // Skip lines inside a previously skipped security/matcher/harmless block.
        if skip_block_depth.is_some() {
            brace_depth = brace_depth.saturating_add(opens).saturating_sub(closes);
            continue;
        }

        // R5-MIG-3 & R7-MIG-12: Inspect lines inside `header [matcher] { ... }` blocks!
        if let Some((_, ref hdr_matcher)) = in_header_block {
            let hdr_val = args.join(" ");
            match classify_untranslated_security_header(directive, &hdr_val) {
                HeaderClassification::CoveredByStrict => {}
                HeaderClassification::SafeToDropWithNote(reason) => {
                    doc.push_note(
                        Some(line_no),
                        "header",
                        format!("Caddy `header` setting `{directive}` was not auto-translated ({reason})"),
                    );
                }
                HeaderClassification::SecurityDowngrade(reason) => {
                    doc.push_security_downgrade(
                        Some(line_no),
                        "header",
                        format!(
                            "Caddy `header` setting `{directive}` cannot be auto-translated ({reason}); affected routes withheld"
                        ),
                    );
                    if let Some(handle) = current_handle.as_mut() {
                        handle.blocked_by_security = true;
                        current_site.add_blocked_location(
                            handle.pattern.clone(),
                            Some(line_no),
                            &format!("header {directive}"),
                        );
                    } else if let Some(m) = hdr_matcher {
                        current_site.add_blocked_location(
                            m.clone(),
                            Some(line_no),
                            &format!("header {directive}"),
                        );
                    } else {
                        current_site.block_site(Some(line_no), &format!("header {directive}"));
                    }
                }
            }
            brace_depth = brace_depth.saturating_add(opens).saturating_sub(closes);
            continue;
        }

        // R5-MIG-7, R6-MIG-3 & R7-MIG-7: Handle `reverse_proxy ... { ... }` and
        // `php_fastcgi ... { split ... }` sub-blocks with default-deny on untranslated security
        // sub-directives (`header_down`, `header_up`, `transport`, unknown sub-directives).
        if let Some(ref mut sub_block) = in_proxy_block {
            let sub_lower = directive.to_ascii_lowercase();
            match sub_block {
                CaddySubBlock::ReverseProxy {
                    pattern: proxy_pat,
                    has_upstreams,
                    host_mode,
                    has_https,
                    ..
                } => {
                    if sub_lower == "to" && !*has_upstreams {
                        match caddy_upstream_urls(&args) {
                            Some(ups) if !ups.is_empty() => {
                                *has_upstreams = true;
                                *has_https |= ups.iter().any(|u| u.starts_with("https://"));
                                push_caddy_route(
                                    &mut current_handle,
                                    &mut current_site,
                                    MigratedRoute::new(
                                        proxy_pat.clone(),
                                        MigratedHandler::ReverseProxy {
                                            upstreams: ups,
                                            preserve_host: host_mode.unwrap_or(true),
                                            allow_upgrades: true,
                                        },
                                    ),
                                );
                            }
                            Some(_) => {}
                            None => block_caddy_unsupported_upstream(
                                &mut current_handle,
                                &mut current_site,
                                &mut doc,
                                proxy_pat,
                                line_no,
                            ),
                        }
                    } else if sub_lower == "header_up"
                        && args.first().is_some_and(|h| h.eq_ignore_ascii_case("host"))
                        && let Some(mode) = args.get(1).and_then(|v| caddy_host_value_mode(v))
                        && args.len() == 2
                    {
                        // An explicit `Host` removes the scheme/version ambiguity of the default.
                        *host_mode = Some(mode);
                        set_caddy_proxy_preserve_host(
                            &mut current_handle,
                            &mut current_site,
                            proxy_pat,
                            mode,
                        );
                    } else if sub_lower == "header_down" {
                        let hdr_name = args.first().copied().unwrap_or("");
                        let hdr_val = args.get(1..).map_or_else(String::new, |s| s.join(" "));
                        match classify_untranslated_security_header(hdr_name, &hdr_val) {
                            HeaderClassification::CoveredByStrict => {}
                            HeaderClassification::SafeToDropWithNote(reason) => {
                                doc.push_note(
                                    Some(line_no),
                                    "reverse_proxy.header_down",
                                    format!(
                                        "Caddy `reverse_proxy {{ header_down {hdr_name} }}` was not auto-translated ({reason})"
                                    ),
                                );
                            }
                            HeaderClassification::SecurityDowngrade(reason) => {
                                doc.push_security_downgrade(
                                    Some(line_no),
                                    "reverse_proxy.header_down",
                                    format!(
                                        "Caddy `reverse_proxy {{ header_down {hdr_name} }}` cannot be auto-translated ({reason}); affected route withheld"
                                    ),
                                );
                                if let Some(handle) = current_handle.as_mut() {
                                    handle.blocked_by_security = true;
                                    current_site.add_blocked_location(
                                        handle.pattern.clone(),
                                        Some(line_no),
                                        &format!("header_down {hdr_name}"),
                                    );
                                } else {
                                    current_site.add_blocked_location(
                                        proxy_pat.clone(),
                                        Some(line_no),
                                        &format!("header_down {hdr_name}"),
                                    );
                                }
                            }
                        }
                    } else if sub_lower == "transport" {
                        // R7-MIG-7: Step INTO `transport http { ... }` so benign transport tuning
                        // (`versions`, timeouts, keepalive) gets a note while `tls_trusted_ca_certs`,
                        // `tls_client_auth`, `tls_insecure_skip_verify`, `tls_server_name`, and
                        // non-`http` transports fail closed with a security downgrade!
                        let proto = args.first().copied().unwrap_or("");
                        if !proto.eq_ignore_ascii_case("http") {
                            doc.push_security_downgrade(
                                Some(line_no),
                                "reverse_proxy.transport",
                                format!(
                                    "Caddy `reverse_proxy {{ transport {proto} }}` cannot be auto-translated safely; affected route withheld"
                                ),
                            );
                            if let Some(handle) = current_handle.as_mut() {
                                handle.blocked_by_security = true;
                                current_site.add_blocked_location(
                                    handle.pattern.clone(),
                                    Some(line_no),
                                    "reverse_proxy.transport",
                                );
                            } else {
                                current_site.add_blocked_location(
                                    proxy_pat.clone(),
                                    Some(line_no),
                                    "reverse_proxy.transport",
                                );
                            }
                            if opens > closes {
                                skip_block_depth = Some(brace_depth.saturating_add(1));
                            }
                        }
                    } else if matches!(
                        sub_lower.as_str(),
                        "lb_policy"
                            | "lb_retries"
                            | "lb_try_duration"
                            | "lb_try_interval"
                            | "health_uri"
                            | "health_interval"
                            | "health_timeout"
                            | "health_status"
                            | "fail_duration"
                            | "max_fails"
                            | "unhealthy_status"
                            | "unhealthy_latency"
                            | "unhealthy_request_count"
                            | "flush_interval"
                            | "buffer_requests"
                            | "buffer_responses"
                            | "versions"
                            | "dial_timeout"
                            | "response_header_timeout"
                            | "read_timeout"
                            | "write_timeout"
                            | "keepalive"
                            | "keepalive_idle_conns"
                            | "keepalive_idle_conns_per_host"
                            | "max_conns_per_host"
                            | "compression"
                            | "read_buffer"
                            | "write_buffer"
                            | "max_response_header"
                    ) {
                        doc.push_note(
                            Some(line_no),
                            format!("reverse_proxy.{sub_lower}"),
                            format!(
                                "Caddy `reverse_proxy` tuning option `{sub_lower}` requires manual review"
                            ),
                        );
                        if opens > closes {
                            skip_block_depth = Some(brace_depth.saturating_add(1));
                        }
                    } else {
                        // R7-MIG-7: Refuse `header_up`, `transport` (TLS trust/client auth),
                        // `tls_insecure_skip_verify`, `trusted_proxies`, and any unknown
                        // `reverse_proxy` sub-directive!
                        let safe_sub = sanitize_untrusted_directive_token(directive);
                        doc.push_security_downgrade(
                            Some(line_no),
                            format!("reverse_proxy.{safe_sub}"),
                            format!(
                                "Caddy `reverse_proxy` sub-directive `{safe_sub}` cannot be auto-translated safely; affected route withheld"
                            ),
                        );
                        if let Some(handle) = current_handle.as_mut() {
                            handle.blocked_by_security = true;
                            current_site.add_blocked_location(
                                handle.pattern.clone(),
                                Some(line_no),
                                &format!("reverse_proxy.{safe_sub}"),
                            );
                        } else {
                            current_site.add_blocked_location(
                                proxy_pat.clone(),
                                Some(line_no),
                                &format!("reverse_proxy.{safe_sub}"),
                            );
                        }
                        if opens > closes {
                            skip_block_depth = Some(brace_depth.saturating_add(1));
                        }
                    }
                }
                CaddySubBlock::PhpFastCgi {
                    target,
                    emitted_fcgi,
                    ..
                } => {
                    if sub_lower == "to"
                        && target.is_none()
                        && let Some(&first_up) = args.iter().find(|u| !u.starts_with('@'))
                    {
                        *target = Some(normalize_fastcgi_target(first_up));
                    } else if sub_lower == "split" {
                        let mut patterns = Vec::new();
                        let mut all_valid = !args.is_empty();
                        for ext_arg in &args {
                            if let Some(pat) = parse_clean_caddy_extension(ext_arg) {
                                if !patterns.contains(&pat) {
                                    patterns.push(pat);
                                }
                            } else {
                                all_valid = false;
                                break;
                            }
                        }
                        if all_valid && let Some(fcgi_target) = target.clone() {
                            *emitted_fcgi = true;
                            for pat in patterns {
                                push_caddy_route(
                                    &mut current_handle,
                                    &mut current_site,
                                    MigratedRoute::new(
                                        pat,
                                        MigratedHandler::FastCgi {
                                            target: fcgi_target.clone(),
                                        },
                                    ),
                                );
                            }
                        } else {
                            *emitted_fcgi = true;
                            doc.push_security_downgrade(
                                Some(line_no),
                                "php_fastcgi.split",
                                format!(
                                    "Caddy `php_fastcgi {{ split {} }}` uses an unsupported split pattern; affected routes withheld to prevent serving PHP source",
                                    args.join(" ")
                                ),
                            );
                            if let Some(handle) = current_handle.as_mut() {
                                handle.blocked_by_security = true;
                                current_site.add_blocked_location(
                                    handle.pattern.clone(),
                                    Some(line_no),
                                    "php_fastcgi.split",
                                );
                            } else {
                                current_site.block_site(Some(line_no), "php_fastcgi.split");
                            }
                        }
                    } else if matches!(
                        sub_lower.as_str(),
                        "index"
                            | "try_files"
                            | "resolve_root_symlink"
                            | "dial_timeout"
                            | "read_timeout"
                            | "write_timeout"
                            | "root"
                    ) {
                        doc.push_note(
                            Some(line_no),
                            format!("php_fastcgi.{sub_lower}"),
                            format!(
                                "Caddy `php_fastcgi` option `{sub_lower}` requires manual review"
                            ),
                        );
                        if opens > closes {
                            skip_block_depth = Some(brace_depth.saturating_add(1));
                        }
                    } else {
                        // R7-MIG-7: Fail closed on `header_down`, `header_up`, `transport`,
                        // `tls_insecure_skip_verify`, `env`, or any unknown `php_fastcgi` sub-directive.
                        let safe_sub = sanitize_untrusted_directive_token(directive);
                        doc.push_security_downgrade(
                            Some(line_no),
                            format!("php_fastcgi.{safe_sub}"),
                            format!(
                                "Caddy `php_fastcgi` sub-directive `{safe_sub}` cannot be auto-translated safely; affected routes withheld"
                            ),
                        );
                        if let Some(handle) = current_handle.as_mut() {
                            handle.blocked_by_security = true;
                            current_site.add_blocked_location(
                                handle.pattern.clone(),
                                Some(line_no),
                                &format!("php_fastcgi.{safe_sub}"),
                            );
                        } else {
                            current_site
                                .block_site(Some(line_no), &format!("php_fastcgi.{safe_sub}"));
                        }
                        if opens > closes {
                            skip_block_depth = Some(brace_depth.saturating_add(1));
                        }
                    }
                }
            }
            brace_depth = brace_depth.saturating_add(opens).saturating_sub(closes);
            continue;
        }

        // Handle directives inside `tls { ... }` block (`client_auth` -> mTLS downgrade).
        if in_tls_block {
            if directive.eq_ignore_ascii_case("client_auth") {
                current_site.block_site(Some(line_no), "tls.client_auth");
                doc.push_security_downgrade(
                    Some(line_no),
                    "tls.client_auth",
                    "Caddy `tls { client_auth ... }` enforces mTLS; configure MiraServe `client-ca` manually before exposing this site",
                );
            }
            brace_depth = brace_depth.saturating_add(opens).saturating_sub(closes);
            continue;
        }

        // Named matcher definition (`@internal remote_ip 10.0.0.0/8` or `@internal { ... }`, `MIG-5`).
        if directive.starts_with('@') {
            doc.push_note(
                Some(line_no),
                directive,
                format!(
                    "Caddy named matcher '{directive}' cannot be auto-translated; routes referencing it will be withheld"
                ),
            );
            if opens > closes {
                skip_block_depth = Some(brace_depth.saturating_add(1));
            }
            brace_depth = brace_depth.saturating_add(opens).saturating_sub(closes);
            continue;
        }

        // R3-MIG-2 & R5-MIG-4: Universal named-matcher guard — ANY directive (block or single-line,
        // including `route @internal { ... }`, `respond @notlocal 403`, `redir @m ...`,
        // `rewrite @m ...`, `handle @m { ... }`, `reverse_proxy @m ...`) whose first argument
        // starts with `@` MUST emit a security downgrade, block the enclosing handle (or site),
        // record the blocked location pattern, and skip its entire block!
        if let Some(&first_arg) = args.first()
            && first_arg.starts_with('@')
        {
            if directive == "php_fastcgi" && site_php_indicator.is_none() {
                site_php_indicator = Some((line_no, format!("php_fastcgi {first_arg}")));
            }
            doc.push_security_downgrade(
                Some(line_no),
                directive,
                format!(
                    "Caddy `{directive} {first_arg}` relies on named matcher '{first_arg}'; route/block withheld to avoid widening access"
                ),
            );
            if let Some(handle) = current_handle.as_mut() {
                handle.blocked_by_security = true;
                current_site.add_blocked_location(handle.pattern.clone(), Some(line_no), directive);
            } else {
                current_site.block_site(Some(line_no), &format!("{directive} {first_arg}"));
            }
            if opens > closes {
                skip_block_depth = Some(brace_depth.saturating_add(1));
            }
            brace_depth = brace_depth.saturating_add(opens).saturating_sub(closes);
            continue;
        }

        if matches!(directive, "handle" | "handle_path" | "route") && line.ends_with('{') {
            let pat_raw = args.first().copied().unwrap_or("/*");
            if directive == "handle_path" {
                // MIG-6: Prefix stripping changes upstream path semantics (can break auth/routing);
                // record as a security downgrade so `miraserve import` does not exit 0 silently.
                doc.push_security_downgrade(
                    Some(line_no),
                    "handle_path",
                    format!(
                        "Caddy `handle_path {pat_raw}` strips its prefix before forwarding; MiraServe forwards the original path unchanged — verify upstream routing before deploying"
                    ),
                );
            }
            // A Caddy path matcher without `*` is EXACT: `handle /` is the homepage only, not
            // the whole site. Patterns that are neither exact nor `/prefix/*` cannot be
            // expressed and withhold the block.
            let translated = caddy_path_pattern(pat_raw);
            if translated.is_none() {
                doc.push_security_downgrade(
                    Some(line_no),
                    directive,
                    "Caddy path matcher is neither an exact path nor a `/prefix/*` pattern and cannot be translated without widening it; block withheld",
                );
                current_site.add_blocked_location(
                    normalize_route_pattern(pat_raw),
                    Some(line_no),
                    directive,
                );
            }
            current_handle = Some(HandleScope {
                pattern: translated
                    .clone()
                    .unwrap_or_else(|| normalize_route_pattern(pat_raw)),
                is_named_matcher: false,
                blocked_by_security: translated.is_none(),
                pending_routes: Vec::new(),
            });
            brace_depth = brace_depth.saturating_add(opens).saturating_sub(closes);
            continue;
        }

        // MIG-3 / R2-MIG-1 / R2-MIG-2 / R4-MIG-6 / R5-MIG-4: Detect authentication, WAF, ACL,
        // abort, rate-limit, and unexpanded import directives (both bare single-line and blocks)!
        let dir_lower = directive.to_ascii_lowercase();
        if matches!(
            dir_lower.as_str(),
            "basicauth"
                | "basic_auth"
                | "forward_auth"
                | "abort"
                | "rate_limit"
                | "ratelimit"
                | "import"
                | "authorize"
                | "authenticate"
                | "jwtauth"
                | "jwt"
                | "ipfilter"
                | "geofence"
                | "crowdsec"
                | "coraza_waf"
                | "coraza"
                | "waf"
                | "security"
                | "auth"
        ) {
            let matcher_arg = args.first().copied().unwrap_or("*");
            doc.push_security_downgrade(
                Some(line_no),
                directive,
                format!(
                    "Caddy directive `{directive} {matcher_arg}` may enforce authentication/WAF/access control and cannot be auto-translated; affected routes withheld"
                ),
            );
            if let Some(handle) = current_handle.as_mut() {
                handle.blocked_by_security = true;
                current_site.add_blocked_location(handle.pattern.clone(), Some(line_no), directive);
            } else if matcher_arg.starts_with('/') {
                current_site.add_blocked_location(
                    normalize_route_pattern(matcher_arg),
                    Some(line_no),
                    directive,
                );
            } else {
                current_site.block_site(Some(line_no), directive);
            }
            if opens > closes {
                skip_block_depth = Some(brace_depth.saturating_add(1));
            }
            brace_depth = brace_depth.saturating_add(opens).saturating_sub(closes);
            continue;
        }

        if matches!(directive, "respond" | "error")
            && args.iter().any(|a| is_blocking_caddy_status(a))
        {
            doc.push_security_downgrade(
                Some(line_no),
                directive,
                format!(
                    "Caddy blocking directive `{line}` cannot be auto-translated; affected routes withheld"
                ),
            );
            if let Some(handle) = current_handle.as_mut() {
                handle.blocked_by_security = true;
                current_site.add_blocked_location(handle.pattern.clone(), Some(line_no), directive);
            } else if args.first().is_some_and(|a| a.starts_with('/'))
                && let Some(&m) = args.first()
            {
                current_site.add_blocked_location(
                    normalize_route_pattern(m),
                    Some(line_no),
                    directive,
                );
            } else {
                current_site.block_site(Some(line_no), directive);
            }
            brace_depth = brace_depth.saturating_add(opens).saturating_sub(closes);
            continue;
        }

        match directive {
            "bind" => {
                // MIG-4: Preserve explicit Caddy `bind 127.0.0.1` / `bind ::1`.
                if let Some(&host) = args.first() {
                    let clean = if host == "localhost" {
                        "127.0.0.1".to_owned()
                    } else {
                        host.to_owned()
                    };
                    site_bind_host = Some(clean);
                }
            }
            "root"
                if (args.len() >= 2 && args.first() != Some(&"*"))
                    || current_handle.as_ref().is_some_and(|h| h.pattern != "/*") =>
            {
                // `root <matcher> <dir>` and a `root` inside a path-scoped `handle` set the
                // document root for PART of the site. MiraServe has one root per site, so
                // adopting it would serve that directory on unrelated paths (for example through
                // a fallback `file_server` that used Caddy's default root).
                doc.push_security_downgrade(
                    Some(line_no),
                    "root",
                    "Caddy `root` scoped to part of the site (a path matcher or a path-scoped `handle`) cannot be represented by one MiraServe site root; site withheld",
                );
                current_site.block_site(Some(line_no), "root (scoped)");
            }
            "root" => {
                let path = if args.first() == Some(&"*") {
                    args.get(1).copied()
                } else {
                    args.first().copied()
                };
                if let Some(p) = path {
                    if current_site.root.as_deref().is_some_and(|prev| prev != p) {
                        // Two `root` directives (typically in different `handle` blocks) map
                        // different paths to different directories; one site root cannot.
                        current_site.block_site(Some(line_no), "root (conflicting roots)");
                        doc.push_security_downgrade(
                            Some(line_no),
                            "root",
                            "Caddy site sets more than one document root; one MiraServe site root cannot represent both, so the site is withheld",
                        );
                    }
                    current_site.root = Some(p.to_owned());
                    // In Caddy `root` alone serves nothing; only `file_server`/`php_fastcgi` do.
                    current_site.static_fallback_must_be_confirmed = true;
                }
            }
            "reverse_proxy" => {
                let mut pattern = current_handle
                    .as_ref()
                    .map_or_else(|| "/*".to_owned(), |h| h.pattern.clone());
                let mut start_idx = 0_usize;
                let mut untranslatable_matcher = false;
                let mut unreachable_matcher = false;
                if let Some(&first) = args.first()
                    && (first.starts_with('/') || first == "*")
                {
                    if let Some(p) = caddy_path_pattern(first) {
                        // Inside a `handle`, the request already had to match the handle's
                        // matcher. The route must satisfy BOTH: an inner matcher broader than
                        // the handle must not widen it.
                        let scope = current_handle.as_ref().map(|h| h.pattern.as_str());
                        if let Some(both) =
                            scope.map_or_else(|| Some(p.clone()), |h| caddy_intersect(h, &p))
                        {
                            pattern = both;
                        } else {
                            // The two matchers share no path: Caddy never proxies here.
                            unreachable_matcher = true;
                            pattern = p;
                        }
                    } else {
                        untranslatable_matcher = true;
                        pattern = normalize_route_pattern(first);
                    }
                    start_idx = 1;
                }
                let upstream_args: Vec<&str> = args.get(start_idx..).unwrap_or(&[]).to_vec();
                let parsed = caddy_upstream_urls(&upstream_args);
                let upstreams = parsed.clone().unwrap_or_default();
                let has_https = upstreams.iter().any(|u| u.starts_with("https://"));
                let mut emitted_now = false;
                if untranslatable_matcher {
                    doc.push_security_downgrade(
                        Some(line_no),
                        "reverse_proxy",
                        "Caddy `reverse_proxy` path matcher is neither an exact path nor a `/prefix/*` pattern and cannot be translated without widening it; affected routes withheld",
                    );
                    current_site.add_blocked_location(
                        pattern.clone(),
                        Some(line_no),
                        "reverse_proxy (matcher)",
                    );
                } else if unreachable_matcher {
                    doc.push_note(
                        Some(line_no),
                        "reverse_proxy",
                        "Caddy `reverse_proxy` matcher shares no path with its enclosing `handle`, so it never matches; no route was emitted for it",
                    );
                } else if parsed.is_none() {
                    block_caddy_unsupported_upstream(
                        &mut current_handle,
                        &mut current_site,
                        &mut doc,
                        &pattern,
                        line_no,
                    );
                } else if !upstreams.is_empty() {
                    emitted_now = true;
                    let route = MigratedRoute::new(
                        pattern.clone(),
                        // Caddy forwards the client's `Host` to plain-HTTP upstreams. For HTTPS
                        // upstreams the default depends on the Caddy version, so it must be
                        // stated with `header_up Host ...` (checked when the block closes).
                        MigratedHandler::ReverseProxy {
                            upstreams,
                            preserve_host: true,
                            allow_upgrades: true,
                        },
                    );
                    push_caddy_route(&mut current_handle, &mut current_site, route);
                    if has_https && opens <= closes {
                        block_caddy_https_default_host(
                            &mut current_handle,
                            &mut current_site,
                            &mut doc,
                            &pattern,
                            line_no,
                        );
                    }
                }
                if opens > closes {
                    in_proxy_block = Some(CaddySubBlock::ReverseProxy {
                        depth: brace_depth.saturating_add(1),
                        pattern,
                        has_upstreams: emitted_now,
                        line: line_no,
                        host_mode: None,
                        has_https,
                    });
                }
            }
            "php_fastcgi" => {
                // `php_fastcgi` rewrites and proxies `.php`; it does not serve static files. Its
                // translation contains a `try-files` route that would, so a site-wide
                // `file_server` must be present too (checked in `finalize_doc_with_options`).
                current_site
                    .file_content_needs_file_server
                    .get_or_insert(line_no);
                // R7-MIG-5 & R7-MIG-11: Parse Caddy's optional leading matcher
                // (`php_fastcgi [<matcher>] <upstreams...>`) AND refuse any non-root matcher or
                // non-root enclosing `handle`/`handle_path`/`route` so `php_fastcgi` never widens
                // to site-wide `*.php` or parses `/blog/*` as `tcp:///blog/*`!
                let (matcher_opt, target_raw) = match args.first().copied() {
                    Some(first)
                        if first == "*" || first.starts_with('/') || first.starts_with('@') =>
                    {
                        (Some(first), args.get(1).copied())
                    }
                    other => (None, other),
                };
                let has_non_root_matcher = matcher_opt.is_some_and(|m| m != "*" && m != "/*");
                let in_non_root_handle = current_handle
                    .as_ref()
                    .is_some_and(|h| h.is_named_matcher || h.pattern != "/*");
                if has_non_root_matcher || in_non_root_handle {
                    let scope_desc = matcher_opt.map_or_else(
                        || {
                            current_handle
                                .as_ref()
                                .map_or_else(|| "scoped handle".to_owned(), |h| h.pattern.clone())
                        },
                        str::to_owned,
                    );
                    doc.push_security_downgrade(
                        Some(line_no),
                        "php_fastcgi",
                        format!(
                            "Caddy `php_fastcgi` scoped to '{scope_desc}' cannot be faithfully translated to site-wide `*.php` without widening PHP execution; affected routes withheld"
                        ),
                    );
                    if let Some(handle) = current_handle.as_mut() {
                        handle.blocked_by_security = true;
                        current_site.add_blocked_location(
                            handle.pattern.clone(),
                            Some(line_no),
                            "php_fastcgi (scoped)",
                        );
                    } else if let Some(m) = matcher_opt
                        && m.starts_with('/')
                    {
                        current_site.add_blocked_location(
                            normalize_route_pattern(m),
                            Some(line_no),
                            "php_fastcgi (scoped)",
                        );
                    } else {
                        current_site.block_site(Some(line_no), "php_fastcgi (scoped)");
                    }
                    if opens > closes {
                        skip_block_depth = Some(brace_depth.saturating_add(1));
                    }
                    brace_depth = brace_depth.saturating_add(opens).saturating_sub(closes);
                    continue;
                }
                let normalized_target = target_raw.map(normalize_fastcgi_target);
                if let Some(ref fcgi_target) = normalized_target {
                    if opens <= closes {
                        push_caddy_route(
                            &mut current_handle,
                            &mut current_site,
                            MigratedRoute::new(
                                "*.php".to_owned(),
                                MigratedHandler::FastCgi {
                                    target: fcgi_target.clone(),
                                },
                            ),
                        );
                    }
                    push_caddy_route(
                        &mut current_handle,
                        &mut current_site,
                        MigratedRoute::new(
                            "/*".to_owned(),
                            MigratedHandler::TryFiles {
                                candidates: vec![
                                    "{path}".to_owned(),
                                    "{path}/".to_owned(),
                                    "/index.php?{query}".to_owned(),
                                ],
                            },
                        ),
                    );
                    if current_site
                        .root
                        .as_deref()
                        .is_some_and(|r| r.to_ascii_lowercase().contains("wordpress"))
                    {
                        current_site.wordpress = true;
                        doc.push_upgrade(
                            "Detected WordPress php_fastcgi setup — enabled preset \"wordpress-hardened\"",
                        );
                    }
                }
                if opens > closes {
                    in_proxy_block = Some(CaddySubBlock::PhpFastCgi {
                        depth: brace_depth.saturating_add(1),
                        target: normalized_target,
                        emitted_fcgi: false,
                    });
                }
            }
            "file_server"
                if current_handle.is_none()
                    && args
                        .first()
                        .is_some_and(|a| a.starts_with('/') || a.starts_with('@')) =>
            {
                // `file_server /public/*` (or a named matcher) serves files ONLY for matching
                // requests. MiraServe serves every unmatched path from the document root, so
                // importing this as a plain site would expose the rest of the root.
                doc.push_security_downgrade(
                    Some(line_no),
                    "file_server",
                    "Caddy `file_server` with a request matcher serves only the matched paths; MiraServe's document-root fallback would serve everything, so the site is withheld",
                );
                current_site.block_site(Some(line_no), "file_server (matcher)");
                if opens > closes {
                    skip_block_depth = Some(brace_depth.saturating_add(1));
                }
            }
            "file_server" => {
                let has_matcher = args
                    .first()
                    .is_some_and(|a| a.starts_with('/') || a.starts_with('@'));
                if let Some(handle) = current_handle.as_mut() {
                    if has_matcher {
                        // `handle /a/* { file_server /a/public/* }` narrows the scope again.
                        // Emitting a static route for the whole handle would widen it.
                        handle.blocked_by_security = true;
                        current_site.add_blocked_location(
                            handle.pattern.clone(),
                            Some(line_no),
                            "file_server (matcher)",
                        );
                        doc.push_security_downgrade(
                            Some(line_no),
                            "file_server",
                            "Caddy `file_server` with its own request matcher inside a `handle` block serves only part of that block; the block is withheld",
                        );
                    } else {
                        if handle.pattern == "/*" {
                            // A catch-all `handle { file_server }` is a site-wide file server.
                            current_site.static_fallback_confirmed = true;
                        }
                        handle.pending_routes.push(MigratedRoute::new(
                            handle.pattern.clone(),
                            MigratedHandler::Static,
                        ));
                    }
                } else {
                    // Site-wide file server: the document-root fallback is what the source does.
                    current_site.static_fallback_confirmed = true;
                }
                if opens > closes {
                    file_server_block = Some((
                        brace_depth.saturating_add(1),
                        current_handle.as_ref().map(|h| h.pattern.clone()),
                    ));
                }
            }
            "try_files" => {
                let candidates: Vec<String> = args.iter().map(|tok| (*tok).to_owned()).collect();
                if !candidates.is_empty() {
                    if candidates
                        .iter()
                        .any(|c| c.to_ascii_lowercase().contains(".php"))
                        && site_php_indicator.is_none()
                    {
                        site_php_indicator =
                            Some((line_no, format!("try_files {}", args.join(" "))));
                    }
                    let pat = current_handle
                        .as_ref()
                        .map_or_else(|| "/*".to_owned(), |h| h.pattern.clone());
                    if pat == "/*" {
                        // A site-wide `try_files` only rewrites; see `php_fastcgi` above.
                        current_site
                            .file_content_needs_file_server
                            .get_or_insert(line_no);
                    }
                    push_caddy_route(
                        &mut current_handle,
                        &mut current_site,
                        MigratedRoute::new(pat, MigratedHandler::TryFiles { candidates }),
                    );
                }
            }
            "uri" => {
                // MIG-6: Flag `uri strip_prefix` / `strip_suffix` / `replace` as a security downgrade!
                if args.first().is_some_and(|sub| {
                    matches!(
                        sub.to_ascii_lowercase().as_str(),
                        "strip_prefix" | "strip_suffix" | "replace"
                    )
                }) {
                    doc.push_security_downgrade(
                        Some(line_no),
                        "uri",
                        format!(
                            "Caddy `uri {}` rewrites/strips request paths before routing; MiraServe forwards original request paths unchanged — verify upstream routing before cutover",
                            args.join(" ")
                        ),
                    );
                } else {
                    doc.push_note(
                        Some(line_no),
                        "uri",
                        format!(
                            "Caddy directive `uri {}` requires manual review",
                            args.join(" ")
                        ),
                    );
                }
            }
            "header" => {
                // R5-MIG-3: Inspect both single-line `header` and block `header { ... }` for
                // security headers not emitted by `security-headers "strict"` (CSP, COEP, etc.)!
                if opens > closes {
                    let path_matcher = args
                        .first()
                        .copied()
                        .filter(|a| a.starts_with('/'))
                        .map(normalize_route_pattern);
                    in_header_block = Some((brace_depth.saturating_add(1), path_matcher));
                } else {
                    let (matcher_opt, hdr_name_opt, hdr_val) = if args
                        .first()
                        .is_some_and(|a| a.starts_with('/') || *a == "*")
                    {
                        let m = args
                            .first()
                            .copied()
                            .filter(|a| a.starts_with('/'))
                            .map(normalize_route_pattern);
                        let name = args.get(1).copied();
                        let val = args.get(2..).map_or_else(String::new, |s| s.join(" "));
                        (m, name, val)
                    } else {
                        let name = args.first().copied();
                        let val = args.get(1..).map_or_else(String::new, |s| s.join(" "));
                        (None, name, val)
                    };
                    if let Some(hdr_name) = hdr_name_opt {
                        match classify_untranslated_security_header(hdr_name, &hdr_val) {
                            HeaderClassification::CoveredByStrict => {}
                            HeaderClassification::SafeToDropWithNote(reason) => {
                                doc.push_note(
                                    Some(line_no),
                                    "header",
                                    format!(
                                        "Caddy `header {hdr_name}` was not auto-translated ({reason})"
                                    ),
                                );
                            }
                            HeaderClassification::SecurityDowngrade(reason) => {
                                doc.push_security_downgrade(
                                    Some(line_no),
                                    "header",
                                    format!(
                                        "Caddy `header {hdr_name}` cannot be auto-translated ({reason}); affected routes withheld"
                                    ),
                                );
                                if let Some(handle) = current_handle.as_mut() {
                                    handle.blocked_by_security = true;
                                    current_site.add_blocked_location(
                                        handle.pattern.clone(),
                                        Some(line_no),
                                        &format!("header {hdr_name}"),
                                    );
                                } else if let Some(m) = matcher_opt {
                                    current_site.add_blocked_location(
                                        m,
                                        Some(line_no),
                                        &format!("header {hdr_name}"),
                                    );
                                } else {
                                    current_site
                                        .block_site(Some(line_no), &format!("header {hdr_name}"));
                                }
                            }
                        }
                    }
                }
            }
            "tls" => {
                if line.ends_with('{') {
                    in_tls_block = true;
                } else if args.len() == 1
                    && let Some(&email) = args.first()
                    && email.contains('@')
                {
                    if is_routable_acme_email(email) {
                        doc.acme_email = Some(email.to_owned());
                    } else {
                        doc.push_note(
                            Some(line_no),
                            "tls",
                            format!("Skipped non-routable Caddy TLS email '{email}'"),
                        );
                    }
                } else if args.len() >= 2
                    && let (Some(&c), Some(&k)) = (args.first(), args.get(1))
                {
                    current_site.cert = Some(c.to_owned());
                    current_site.key = Some(k.to_owned());
                }
            }
            "encode" | "log" => {
                if opens > closes {
                    skip_block_depth = Some(brace_depth.saturating_add(1));
                }
            }
            "redir" | "rewrite" if opens <= closes => {
                // R8-MIG-7: a redirect or rewrite decides what its path answers. Dropping it lets
                // the path fall through to the file server or a proxy.
                let first = args.first().copied().unwrap_or("");
                let has_target =
                    args.len() >= 2 && args.get(1).is_none_or(|a| a.parse::<u16>().is_err());
                if let Some(handle) = current_handle.as_mut() {
                    handle.blocked_by_security = true;
                    current_site.add_blocked_location(
                        handle.pattern.clone(),
                        Some(line_no),
                        directive,
                    );
                    doc.push_security_downgrade(
                        Some(line_no),
                        directive,
                        format!(
                            "Caddy `{directive}` inside a `handle` block changes what that block serves and cannot be auto-translated; block withheld"
                        ),
                    );
                } else if first.starts_with('/') && has_target {
                    // A Caddy path matcher without `*` is an exact match.
                    let pattern = if first.contains('*') {
                        normalize_route_pattern(first)
                    } else {
                        first.to_owned()
                    };
                    current_site.closed_prefixes.push((
                        pattern,
                        Some(line_no),
                        directive.to_owned(),
                    ));
                } else if first.starts_with('@') || (first == "*" && directive == "rewrite") {
                    current_site.block_site(Some(line_no), directive);
                    doc.push_security_downgrade(
                        Some(line_no),
                        directive,
                        format!(
                            "Caddy `{directive}` with a named or catch-all matcher changes what the site serves and cannot be auto-translated; site withheld"
                        ),
                    );
                } else if directive == "rewrite" {
                    current_site.block_site(Some(line_no), directive);
                    doc.push_security_downgrade(
                        Some(line_no),
                        directive,
                        "Caddy `rewrite` without a path matcher rewrites every request and cannot be auto-translated; site withheld",
                    );
                } else {
                    current_site.whole_site_redirect = Some((Some(line_no), directive.to_owned()));
                }
            }
            other if opens <= closes && is_caddy_inert_directive(other) => {}
            other => {
                if opens > closes {
                    // R3-MIG-2 & R5-MIG-4: Default-deny unknown Caddy block directives so directives
                    // inside unknown conditional/auth/plugin blocks are NEVER parsed as open routes!
                    doc.push_security_downgrade(
                        Some(line_no),
                        other,
                        format!(
                            "Unknown Caddy block directive '{other} {{ ... }}' may guard access/routing and cannot be auto-translated; block withheld"
                        ),
                    );
                    if let Some(handle) = current_handle.as_mut() {
                        handle.blocked_by_security = true;
                        current_site.add_blocked_location(
                            handle.pattern.clone(),
                            Some(line_no),
                            other,
                        );
                    } else {
                        current_site.block_site(Some(line_no), other);
                    }
                    skip_block_depth = Some(brace_depth.saturating_add(1));
                } else {
                    // R8-MIG-1: fail closed on single-line directives too. One that is neither
                    // translated nor known to be inert (`respond`, `templates`, `invoke`, a
                    // plugin, a typo) may decide what its path serves or to whom.
                    let safe_dir = sanitize_untrusted_directive_token(other);
                    doc.push_security_downgrade(
                        Some(line_no),
                        safe_dir.clone(),
                        format!(
                            "Caddy directive '{safe_dir}' is not translated and is not known to be inert; affected routes withheld because it may change what is served or who may reach it"
                        ),
                    );
                    if let Some(handle) = current_handle.as_mut() {
                        handle.blocked_by_security = true;
                        current_site.add_blocked_location(
                            handle.pattern.clone(),
                            Some(line_no),
                            &safe_dir,
                        );
                    } else if let Some(m) = args.first().filter(|a| a.starts_with('/')) {
                        current_site.add_blocked_location(
                            normalize_route_pattern(m),
                            Some(line_no),
                            &safe_dir,
                        );
                    } else {
                        current_site.block_site(Some(line_no), &safe_dir);
                    }
                }
            }
        }

        brace_depth = brace_depth.saturating_add(opens).saturating_sub(closes);
    }

    doc
}

/// Translates a Caddy path matcher into a MiraServe route pattern without widening it.
///
/// Caddy matches a path without `*` EXACTLY, so `/` is the homepage only and `/admin` is that
/// one path. `/prefix/*` is a prefix. Other glob shapes (`/foo*`, `*.php`, `/a/*/b`) have no
/// MiraServe equivalent and return `None`.
fn caddy_path_pattern(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_matches('"');
    if trimmed == "*" || trimmed == "/*" {
        return Some("/*".to_owned());
    }
    if !trimmed.starts_with('/') {
        return None;
    }
    if !trimmed.contains('*') {
        return Some(trimmed.to_owned());
    }
    let prefix = trimmed.strip_suffix("/*")?;
    (!prefix.contains('*') && !prefix.is_empty()).then(|| trimmed.to_owned())
}

/// Returns the pattern matching exactly the requests that match BOTH an enclosing `handle`
/// pattern and an inner matcher, or `None` when no request can match both. Patterns are the
/// output of [`caddy_path_pattern`]: `/*`, an exact path, or `/prefix/*`.
fn caddy_intersect(outer: &str, inner: &str) -> Option<String> {
    if outer == "/*" || outer == inner {
        return Some(inner.to_owned());
    }
    if inner == "/*" {
        return Some(outer.to_owned());
    }
    // `/prefix/*` covers a path when that path starts with `/prefix/`.
    let covers = |pattern: &str, path: &str| {
        pattern
            .strip_suffix('*')
            .is_some_and(|prefix| path.starts_with(prefix))
    };
    if covers(outer, inner) {
        Some(inner.to_owned())
    } else if covers(inner, outer) {
        Some(outer.to_owned())
    } else {
        None
    }
}

/// Converts Caddy upstream addresses to MiraServe upstream URLs, keeping the transport Caddy
/// would use: `https://` is TLS, `http://` and scheme-less addresses are plaintext. Returns
/// `None` when the transport cannot be determined or reproduced: a scheme other than
/// `http`/`https` (`h2c://`, `srv+http://`, `unix/`, ...), a placeholder, or a scheme-less
/// address on port 443.
fn caddy_upstream_urls(args: &[&str]) -> Option<Vec<String>> {
    let mut urls = Vec::new();
    for raw in args.iter().filter(|u| !u.starts_with('@')) {
        let trimmed = raw.trim().trim_matches('"');
        if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            urls.push(trimmed.to_owned());
        } else if trimmed.contains("://") || trimmed.starts_with("unix/") || trimmed.contains('{') {
            return None;
        } else if trimmed
            .rsplit_once(':')
            .is_some_and(|(_, port)| port == "443")
        {
            // A scheme-less address on port 443 is ambiguous: whether Caddy speaks TLS to it
            // depends on the transport configuration, not the port. Guessing HTTPS could break
            // a plaintext backend; guessing HTTP could send traffic in clear. The scheme must
            // be written out.
            return None;
        } else {
            urls.push(normalize_upstream_url(trimmed));
        }
    }
    Some(urls)
}

/// Classifies the value of `header_up Host <value>`: `Some(true)` when the backend gets the
/// client's host, `Some(false)` when it gets the upstream's own host, `None` otherwise.
fn caddy_host_value_mode(value: &str) -> Option<bool> {
    match value.trim_matches('"') {
        "{host}" | "{hostport}" | "{http.request.host}" | "{http.request.hostport}" => Some(true),
        "{upstream_hostport}" | "{http.reverse_proxy.upstream.hostport}" => Some(false),
        _ => None,
    }
}

/// Applies an explicit `header_up Host` decision to the proxy route already emitted for
/// `pattern` in the current scope.
fn set_caddy_proxy_preserve_host(
    current_handle: &mut Option<HandleScope>,
    site: &mut MigratedSite,
    pattern: &str,
    preserve: bool,
) {
    let routes = current_handle
        .as_mut()
        .map_or(&mut site.routes, |h| &mut h.pending_routes);
    for route in routes.iter_mut().rev() {
        if route.pattern == pattern
            && let MigratedHandler::ReverseProxy { preserve_host, .. } = &mut route.handler
        {
            *preserve_host = preserve;
            break;
        }
    }
}

/// Withholds a proxy route whose upstream is HTTPS and whose `Host` is left to Caddy's default.
/// Before Caddy 2.11 the backend received the client's host; from 2.11 it receives the upstream
/// host. The importer cannot know which, and picking wrong selects another virtual host.
fn block_caddy_https_default_host(
    current_handle: &mut Option<HandleScope>,
    site: &mut MigratedSite,
    doc: &mut MigratedDoc,
    pattern: &str,
    line_no: usize,
) {
    doc.push_security_downgrade(
        Some(line_no),
        "reverse_proxy",
        "Caddy `reverse_proxy` to an HTTPS upstream relies on a default `Host` that changed between Caddy versions; state it explicitly with `header_up Host {upstream_hostport}` or `header_up Host {host}`. Affected route withheld",
    );
    if let Some(handle) = current_handle.as_mut() {
        handle.blocked_by_security = true;
        site.add_blocked_location(
            handle.pattern.clone(),
            Some(line_no),
            "reverse_proxy (HTTPS upstream, default Host)",
        );
    } else {
        site.add_blocked_location(
            pattern.to_owned(),
            Some(line_no),
            "reverse_proxy (HTTPS upstream, default Host)",
        );
    }
}

/// Withholds a proxy route whose upstream address uses a transport MiraServe cannot reproduce.
fn block_caddy_unsupported_upstream(
    current_handle: &mut Option<HandleScope>,
    site: &mut MigratedSite,
    doc: &mut MigratedDoc,
    pattern: &str,
    line_no: usize,
) {
    doc.push_security_downgrade(
        Some(line_no),
        "reverse_proxy",
        "Caddy `reverse_proxy` upstream cannot be translated: it uses a scheme or placeholder other than `http://`/`https://`, or it is a scheme-less address on port 443 (write `https://` or `http://` explicitly). Affected route withheld",
    );
    if let Some(handle) = current_handle.as_mut() {
        handle.blocked_by_security = true;
        site.add_blocked_location(
            handle.pattern.clone(),
            Some(line_no),
            "reverse_proxy (upstream scheme)",
        );
    } else {
        site.add_blocked_location(
            pattern.to_owned(),
            Some(line_no),
            "reverse_proxy (upstream scheme)",
        );
    }
}

/// Moves a closed `handle` block's routes to the site, unless the block is withheld.
///
/// A `try_files` inside a `handle` only rewrites. Its translation returns file contents, so the
/// same block must also contain a `file_server`; otherwise the block is withheld.
fn flush_caddy_handle(handle: HandleScope, site: &mut MigratedSite, doc: &mut MigratedDoc) {
    if handle.blocked_by_security || handle.is_named_matcher {
        return;
    }
    let has_try_files = handle
        .pending_routes
        .iter()
        .any(|r| matches!(r.handler, MigratedHandler::TryFiles { .. }));
    let has_file_server = handle
        .pending_routes
        .iter()
        .any(|r| matches!(r.handler, MigratedHandler::Static));
    if has_try_files && !has_file_server && handle.pattern != "/*" {
        doc.push_security_downgrade(
            None,
            "try_files",
            "Caddy `try_files` inside a `handle` block without a `file_server` only rewrites; its translation would return file contents. Block withheld",
        );
        // The routes are still handed over: without `--allow-insecure` the blocked location
        // removes them again, and with it they are emitted tagged `// INSECURE:`.
        site.add_blocked_location(
            handle.pattern.clone(),
            None,
            "try_files without file_server",
        );
    }
    site.routes.extend(handle.pending_routes);
}

/// Returns `true` when a Caddy `hide` entry is a plain literal name that MiraServe's default
/// dotfile rule already denies.
///
/// Caddy treats `hide` entries as glob patterns matched against paths and path components, and
/// MiraServe deliberately serves ordinary files under `.well-known`. So the entry is accepted
/// only when it contains nothing but literal name characters (no `*`, `?`, `[`, `]`, `{`, `}`,
/// `\\` or placeholders), its last component starts with `.`, and no component is `.well-known`.
/// A pattern such as `.well-know?` or `.[w]ell-known` is not provably covered and blocks.
fn is_literal_dotfile_hide_entry(entry: &str) -> bool {
    let literal = !entry.is_empty()
        && entry
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'));
    let leaf = entry.rsplit('/').next().unwrap_or(entry);
    literal
        && leaf.starts_with('.')
        && leaf.len() > 1
        && leaf != ".."
        && !entry
            .split('/')
            .any(|part| part.eq_ignore_ascii_case(".well-known"))
}

/// Caddy site directives that only affect logging, compression, tracing or request metadata.
/// Dropping one never changes WHO may reach a path or WHAT a path serves (`R8-MIG-1`).
fn is_caddy_inert_directive(lower: &str) -> bool {
    matches!(
        lower,
        "encode"
            | "log"
            | "log_skip"
            | "skip_log"
            | "log_append"
            | "log_name"
            | "tracing"
            | "push"
            | "request_body"
            | "vars"
    )
}

fn push_caddy_route(
    current_handle: &mut Option<HandleScope>,
    site: &mut MigratedSite,
    route: MigratedRoute,
) {
    if let Some(handle) = current_handle.as_mut() {
        handle.pending_routes.push(route);
    } else {
        site.routes.push(route);
    }
}

fn flush_site_binds(
    bind_host: Option<&str>,
    site_ports: &[(Option<String>, u16, bool)],
    site: &mut MigratedSite,
    doc: &mut MigratedDoc,
) {
    if !site_ports.is_empty() {
        for (explicit_bind, port, is_https) in site_ports {
            let bind_str = if let Some(b) = explicit_bind {
                b.clone()
            } else if let Some(h) = bind_host {
                if h.contains(':') && !h.starts_with('[') {
                    format!("[{h}]:{port}")
                } else {
                    format!("{h}:{port}")
                }
            } else {
                format!(":{port}")
            };
            if *is_https {
                site.add_https_bind(bind_str.clone());
                doc.add_https_bind(bind_str);
            } else {
                site.add_http_bind(bind_str.clone());
                doc.add_http_bind(bind_str);
            }
        }
    } else if let Some(h) = bind_host {
        let bind_str = if h.contains(':') && !h.starts_with('[') {
            format!("[{h}]:443")
        } else {
            format!("{h}:443")
        };
        site.add_https_bind(bind_str.clone());
        doc.add_https_bind(bind_str);
    } else {
        // R3-MIG-4 & R3-MIG-8: Public Caddy sites with no explicit bind listen on `:443`.
        site.add_https_bind(":443".to_owned());
        doc.add_https_bind(":443".to_owned());
    }
}

fn extract_host_from_addr(raw: &str) -> Option<String> {
    if raw.starts_with('[') {
        raw.split(']')
            .next()
            .map(|s| s.trim_start_matches('[').to_owned())
            .filter(|s| !s.is_empty() && s != "::")
    } else {
        raw.rsplit_once(':')
            .map(|(h, _)| h.to_owned())
            .filter(|h| !h.is_empty() && h != "*" && h != "0.0.0.0")
    }
}

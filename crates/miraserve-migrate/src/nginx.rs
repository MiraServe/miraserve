//! Nginx (`nginx.conf` / `sites-enabled/*.conf`) -> MiraServe KDL importer.
//!
//! Uses a proper `;`/`{`/`}` tokenizer and recursive AST parser (bounded nesting depth) so
//! one-line locations (`location ~ /\.ht { deny all; }`, `MIG-1`), nested `if`/`limit_except`
//! blocks (`MIG-6`), `upstream` pools (`MIG-6`), exact/regex locations (`MIG-7`), explicit
//! bind addresses (`MIG-4`), and security controls (`MIG-3`) are handled accurately.

use std::collections::BTreeMap;
use std::path::Path;

use crate::includes::{BoundedIncludeResult, IncludeContext};
use crate::ir::{
    HeaderClassification, MigratedDoc, MigratedHandler, MigratedRoute, MigratedSite,
    PhpLocationPattern, classify_php_regex_pattern, classify_untranslated_security_header,
    is_scoped_bind, normalize_bind_addr_with_default_port, normalize_fastcgi_target,
    normalize_route_pattern_with_mode, normalize_upstream_url, sanitize_diagnostic_text,
};

/// Maximum block nesting depth accepted by the Nginx AST parser (prevents stack overflow on hostile input).
const MAX_BLOCK_DEPTH: usize = 32;

/// Security directives that cannot be auto-translated safely without widening access (`MIG-3`, `R2-MIG-2`, `R6-MIG-5`).
const NGINX_SECURITY_DIRECTIVES: &[&str] = &[
    "auth_basic",
    "auth_basic_user_file",
    "auth_request",
    "auth_jwt",
    "allow",
    "deny",
    "limit_req",
    "limit_conn",
    "ssl_verify_client",
    "ssl_client_certificate",
    "satisfy",
    "internal",
    "secure_link",
    "secure_link_secret",
    "secure_link_md5",
    "proxy_cookie_flags",
    "proxy_cookie_path",
    "proxy_cookie_domain",
];

fn is_safe_nginx_directive_name(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= 48
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// Nginx directives that only tune performance, buffering, logging, compression, caching or TLS
/// session behaviour. Dropping one never changes WHO may reach a path or WHAT content a path
/// serves, so they are the only directives the importer may leave untranslated (`R8-MIG-1`).
///
/// Everything not listed here and not explicitly translated is treated as a blocker: an importer
/// that does not understand a directive cannot know it is harmless.
const NGINX_INERT_DIRECTIVES: &[&str] = &[
    "access_log",
    "error_log",
    "log_not_found",
    "log_subrequest",
    "open_log_file_cache",
    "expires",
    "etag",
    "if_modified_since",
    "gunzip",
    "sendfile",
    "sendfile_max_chunk",
    "tcp_nopush",
    "tcp_nodelay",
    "aio",
    "directio",
    "output_buffers",
    "postpone_output",
    "read_ahead",
    "keepalive_timeout",
    "keepalive_requests",
    "keepalive_time",
    "send_timeout",
    "client_body_timeout",
    "client_header_timeout",
    "client_body_buffer_size",
    "client_header_buffer_size",
    "client_body_temp_path",
    "client_body_in_file_only",
    "large_client_header_buffers",
    "reset_timedout_connection",
    "lingering_close",
    "lingering_time",
    "lingering_timeout",
    "server_tokens",
    "charset",
    "source_charset",
    "override_charset",
    "default_type",
    "index",
    "error_page",
    "recursive_error_pages",
    "autoindex",
    "autoindex_exact_size",
    "autoindex_localtime",
    "limit_rate",
    "limit_rate_after",
    "max_ranges",
    "chunked_transfer_encoding",
    "msie_padding",
    "msie_refresh",
    "port_in_redirect",
    "absolute_redirect",
    "server_name_in_redirect",
    "types_hash_max_size",
    "types_hash_bucket_size",
    "server_names_hash_max_size",
    "server_names_hash_bucket_size",
    "variables_hash_max_size",
    "variables_hash_bucket_size",
    "resolver",
    "resolver_timeout",
    "http2",
    "http3",
    "http2_push_preload",
    "ssl_ciphers",
    "ssl_prefer_server_ciphers",
    "ssl_dhparam",
    "ssl_ecdh_curve",
    "ssl_session_cache",
    "ssl_session_timeout",
    "ssl_session_tickets",
    "ssl_buffer_size",
    "ssl_stapling",
    "ssl_stapling_verify",
    "ssl_trusted_certificate",
    "ssl_early_data",
    "proxy_http_version",
    "proxy_buffering",
    "proxy_buffers",
    "proxy_buffer_size",
    "proxy_busy_buffers_size",
    "proxy_max_temp_file_size",
    "proxy_temp_file_write_size",
    "proxy_read_timeout",
    "proxy_connect_timeout",
    "proxy_send_timeout",
    "proxy_request_buffering",
    "proxy_redirect",
    "proxy_intercept_errors",
    "proxy_ignore_client_abort",
    "proxy_socket_keepalive",
    "proxy_next_upstream",
    "proxy_next_upstream_tries",
    "proxy_next_upstream_timeout",
    "proxy_no_cache",
    "proxy_cache_bypass",
    "fastcgi_intercept_errors",
    "fastcgi_split_path_info",
    "fastcgi_index",
    "fastcgi_buffers",
    "fastcgi_buffer_size",
    "fastcgi_busy_buffers_size",
    "fastcgi_temp_file_write_size",
    "fastcgi_read_timeout",
    "fastcgi_send_timeout",
    "fastcgi_connect_timeout",
    "fastcgi_keep_conn",
    "fastcgi_request_buffering",
    "fastcgi_ignore_client_abort",
    "fastcgi_no_cache",
    "fastcgi_cache_bypass",
];

/// Returns `true` when `fastcgi_param NAME VALUE` restates a parameter exactly as MiraServe's own
/// FastCGI client derives it, so dropping the directive changes nothing the application sees.
///
/// The VALUE is checked, not just the name. `fastcgi_param SCRIPT_FILENAME /srv/app/index.php;`
/// pins every request to one front controller; MiraServe derives the script from the request
/// path, so accepting that line by name would make every other `.php` file under the root
/// directly executable. Any name or value not listed here is a blocker.
fn is_reproduced_fastcgi_param(args: &[String]) -> bool {
    let Some(name) = args.first().map(|n| n.to_ascii_uppercase()) else {
        return false;
    };
    let value = args.get(1).map_or("", |v| v.trim_matches(['"', '\'']));
    match name.as_str() {
        "SCRIPT_FILENAME" => matches!(
            value,
            "$document_root$fastcgi_script_name"
                | "$realpath_root$fastcgi_script_name"
                | "$request_filename"
        ),
        "SCRIPT_NAME" => value == "$fastcgi_script_name",
        "QUERY_STRING" => value == "$query_string",
        "REQUEST_METHOD" => value == "$request_method",
        "CONTENT_TYPE" => value == "$content_type",
        "CONTENT_LENGTH" => value == "$content_length",
        "REQUEST_URI" => value == "$request_uri",
        "DOCUMENT_URI" => value == "$document_uri",
        "DOCUMENT_ROOT" => matches!(value, "$document_root" | "$realpath_root"),
        "SERVER_PROTOCOL" => value == "$server_protocol",
        "REQUEST_SCHEME" => value == "$scheme",
        "HTTPS" => matches!(value, "$https" | "on"),
        "GATEWAY_INTERFACE" => value == "CGI/1.1",
        "SERVER_SOFTWARE" => value.starts_with("nginx"),
        "REMOTE_ADDR" => value == "$remote_addr",
        "REMOTE_PORT" => value == "$remote_port",
        "SERVER_ADDR" => value == "$server_addr",
        "SERVER_PORT" => value == "$server_port",
        "SERVER_NAME" => matches!(value, "$server_name" | "$host"),
        "REDIRECT_STATUS" => value == "200",
        // `$path_info` is the variable the stock Debian `snippets/fastcgi-php.conf` copies
        // `$fastcgi_path_info` into (see `is_stock_path_info_set`).
        "PATH_INFO" => matches!(value, "$fastcgi_path_info" | "$path_info"),
        // Nginx fills `$remote_user` only from its own `auth_basic`, which is a blocker by
        // itself. Without it the value is empty, which is what MiraServe sends.
        "REMOTE_USER" => value == "$remote_user",
        "PATH_TRANSLATED" => value == "$document_root$fastcgi_path_info",
        "HTTP_PROXY" => value.is_empty(),
        _ => false,
    }
}

/// The one `set` the importer accepts: `set $path_info $fastcgi_path_info;` from the stock
/// Debian/Ubuntu `snippets/fastcgi-php.conf`. It only carries `PATH_INFO` across `try_files`.
fn is_stock_path_info_set(args: &[String]) -> bool {
    args.len() == 2
        && args.first().map(String::as_str) == Some("$path_info")
        && args.get(1).map(String::as_str) == Some("$fastcgi_path_info")
}

/// `proxy_set_header` directives of one configuration level: `(line, [name, value])`.
type ProxyHeaderRules = Vec<(usize, Vec<String>)>;

/// The four rules of the stock Debian/Ubuntu `/etc/nginx/proxy_params` file, used when that
/// include is recognised but not read from disk.
const STOCK_PROXY_PARAMS: &[(&str, &str)] = &[
    ("Host", "$http_host"),
    ("X-Real-IP", "$remote_addr"),
    ("X-Forwarded-For", "$proxy_add_x_forwarded_for"),
    ("X-Forwarded-Proto", "$scheme"),
];

/// Collects the `proxy_set_header` directives written directly at this level.
fn direct_proxy_header_rules(items: &[NginxItem]) -> ProxyHeaderRules {
    let mut rules = ProxyHeaderRules::new();
    for item in items {
        let NginxItem::Directive {
            line, name, args, ..
        } = item
        else {
            continue;
        };
        if name.eq_ignore_ascii_case("proxy_set_header") {
            rules.push((*line, args.clone()));
        } else if name.eq_ignore_ascii_case("include")
            && args.first().is_some_and(|t| {
                is_safe_nginx_include_target(t)
                    && t.trim_matches(['"', '\'']).rsplit('/').next() == Some("proxy_params")
            })
        {
            for (header, value) in STOCK_PROXY_PARAMS {
                rules.push((*line, vec![(*header).to_owned(), (*value).to_owned()]));
            }
        }
    }
    rules
}

/// What the `proxy_set_header` rules in effect for a proxied location ask of the proxy.
#[derive(Debug, Clone, Copy, Default)]
struct ProxyHeaderOutcome {
    /// The backend must see the client's own `Host` (`preserve-host #true`). `false` is Nginx's
    /// default, `$proxy_host`: the host written in `proxy_pass`.
    preserve_host: bool,
    /// The location forwards WebSocket upgrades. Nginx does not pass the hop-by-hop `Upgrade`
    /// and `Connection` headers to the backend unless the configuration sets BOTH explicitly, so
    /// without that pair the source never opened a WebSocket tunnel on this location.
    allow_upgrades: bool,
}

/// Decides whether the `proxy_set_header` rules in effect for a proxied location are reproduced
/// by MiraServe's reverse proxy, checking the VALUE each header would carry to the backend.
///
/// Returns the outcome when every rule is reproduced, or `Err((line, label))` naming the first
/// rule that is not. What the runtime sends (`miraserve-proxy`, `apply_forwarded_headers`):
/// - `Host`: the upstream's own authority, or the client's host with `preserve-host #true`;
/// - `X-Forwarded-For` and `X-Real-IP`: the client address;
/// - `X-Forwarded-Proto`: the client scheme; `X-Forwarded-Host`: the client's host;
/// - `Forwarded` and `X-Forwarded-Port`: removed, never sent;
/// - the WebSocket `Upgrade`/`Connection` pair on a valid upgrade, unless `allow-upgrades #false`.
///
/// Anything else, including an identity header the source blanks or overwrites and a `Host`
/// pinned to a fixed name, cannot be reproduced and withholds the location.
fn evaluate_proxy_header_rules(
    rules: &ProxyHeaderRules,
    connection_upgrade_is_stock: bool,
) -> Result<ProxyHeaderOutcome, (usize, String)> {
    let mut preserve_host = false;
    let mut forwards_upgrade = false;
    let mut connection_upgrades = false;
    for (line, args) in rules {
        let name = args
            .first()
            .map(|n| n.to_ascii_lowercase())
            .unwrap_or_default();
        let value = args.get(1).map_or("", |v| v.trim_matches(['"', '\'']));
        let reproduced = match name.as_str() {
            "host" => match value {
                "$host" | "$http_host" => {
                    preserve_host = true;
                    true
                }
                "$proxy_host" => {
                    preserve_host = false;
                    true
                }
                _ => false,
            },
            "x-forwarded-for" => matches!(value, "$proxy_add_x_forwarded_for" | "$remote_addr"),
            "x-real-ip" => value == "$remote_addr",
            "x-forwarded-proto" => matches!(value, "$scheme" | "https"),
            "x-forwarded-host" => matches!(value, "$host" | "$http_host"),
            "forwarded" => value.is_empty(),
            "upgrade" => {
                forwards_upgrade = value == "$http_upgrade";
                forwards_upgrade
            }
            "connection" => {
                // `$connection_upgrade` is a user-defined `map` variable, not an Nginx built-in.
                // Its name proves nothing: only the stock map (`default upgrade; '' close;` on
                // `$http_upgrade`) means "upgrade when the client asks". Any other definition,
                // or none that the importer could read, makes the rule not reproducible.
                connection_upgrades = value.eq_ignore_ascii_case("upgrade")
                    || (value == "$connection_upgrade" && connection_upgrade_is_stock);
                // An empty value (upstream keep-alive) is the no-upgrade default.
                connection_upgrades || value.is_empty()
            }
            _ => false,
        };
        if !reproduced {
            let safe_name = if is_safe_nginx_directive_name(&name) {
                name
            } else {
                "header".to_owned()
            };
            return Err((
                *line,
                format!("proxy_set_header {safe_name} (not reproduced)"),
            ));
        }
    }
    Ok(ProxyHeaderOutcome {
        preserve_host,
        allow_upgrades: forwards_upgrade && connection_upgrades,
    })
}

/// Returns the named `upstream { ... }` pool a location's `proxy_pass` points at, if any.
fn proxy_pass_pool_name<'u>(body: &[NginxItem], upstreams: &'u NginxUpstreams) -> Option<&'u str> {
    body.iter().find_map(|item| {
        let NginxItem::Directive { name, args, .. } = item else {
            return None;
        };
        if !name.eq_ignore_ascii_case("proxy_pass") {
            return None;
        }
        let target = args.first()?;
        let after_scheme = target
            .strip_prefix("https://")
            .or_else(|| target.strip_prefix("http://"))
            .unwrap_or(target);
        let host = after_scheme.split('/').next().unwrap_or(after_scheme);
        upstreams.http.get_key_value(host).map(|(k, _)| k.as_str())
    })
}

/// Returns `true` when dropping this Nginx directive cannot widen access or change served content
/// (see [`NGINX_INERT_DIRECTIVES`]). `gzip*`, `brotli*`, `open_file_cache*`, `proxy_cache*` and
/// `fastcgi_cache*` families are inert as a whole.
fn is_nginx_inert_directive(lower: &str) -> bool {
    NGINX_INERT_DIRECTIVES.contains(&lower)
        || lower == "gzip"
        || lower.starts_with("gzip_")
        || lower == "brotli"
        || lower.starts_with("brotli_")
        || lower.starts_with("open_file_cache")
        || lower.starts_with("proxy_cache")
        || lower.starts_with("fastcgi_cache")
        || lower.starts_with("quic_")
}

fn is_nginx_security_directive(lower: &str) -> bool {
    NGINX_SECURITY_DIRECTIVES.contains(&lower)
        || lower.starts_with("auth_")
        || lower.starts_with("access_by_lua")
        || lower.starts_with("rewrite_by_lua")
        || lower.starts_with("header_filter_by_lua")
        || lower.starts_with("modsecurity")
        || lower == "naxsi"
        || lower == "limit_except"
}

fn is_blocking_return_code(code: &str) -> bool {
    code.parse::<u16>()
        .is_ok_and(|status| (400..=599).contains(&status))
}

fn canonicalize_nginx_include_path(raw: &str) -> Option<String> {
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
    // R4-MIG-5: Preserve case so `/etc/nginx/Proxy_Params` is never matched against `proxy_params`.
    let joined = parts.join("/");
    if is_abs {
        Some(format!("/{joined}"))
    } else {
        Some(joined)
    }
}

/// Strictly canonical, case-sensitive non-ACL parameter/TLS/PHP/module snippets commonly included
/// in stock distro and Certbot Nginx configs (`R2-MIG-1`, `R3-MIG-3`, `R4-MIG-5`). Arbitrary paths
/// and `conf.d/*.conf` / `sites-enabled/*` globs are NEVER assumed safe without reading them!
fn is_safe_nginx_include_target(target: &str) -> bool {
    let Some(canon) = canonicalize_nginx_include_path(target) else {
        return false;
    };
    matches!(
        canon.as_str(),
        "mime.types"
            | "/etc/nginx/mime.types"
            | "fastcgi_params"
            | "/etc/nginx/fastcgi_params"
            | "fastcgi.conf"
            | "/etc/nginx/fastcgi.conf"
            | "proxy_params"
            | "/etc/nginx/proxy_params"
            | "uwsgi_params"
            | "/etc/nginx/uwsgi_params"
            | "scgi_params"
            | "/etc/nginx/scgi_params"
            | "snippets/fastcgi-php.conf"
            | "/etc/nginx/snippets/fastcgi-php.conf"
            | "snippets/snakeoil.conf"
            | "/etc/nginx/snippets/snakeoil.conf"
            | "snippets/ssl-params.conf"
            | "/etc/nginx/snippets/ssl-params.conf"
            | "modules-enabled/*.conf"
            | "/etc/nginx/modules-enabled/*.conf"
            | "/etc/letsencrypt/options-ssl-nginx.conf"
    )
}

fn items_contain_deny(items: &[NginxItem]) -> bool {
    items.iter().any(|item| match item {
        NginxItem::Directive { name, .. } => name.eq_ignore_ascii_case("deny"),
        NginxItem::Block { body, .. } => items_contain_deny(body),
    })
}

/// R4-MIG-6: Strictly verifies a Certbot `if ($host = example.com)` redirect condition (never
/// treating access checks like `if ($remote_addr != 10.0.0.1)` as a Certbot redirect!).
fn is_certbot_host_if_condition(args: &[String]) -> bool {
    let joined = args.join(" ");
    let trimmed = joined.trim();
    let Some(inner) = trimmed.strip_prefix('(').and_then(|s| s.strip_suffix(')')) else {
        return false;
    };
    let parts: Vec<&str> = inner.split_whitespace().collect();
    matches!(
        parts.as_slice(),
        [lhs, "=", rhs] if (*lhs == "$host" || *lhs == "$http_host") && !rhs.is_empty()
    )
}

/// R4-MIG-6: Strict dotfile-only location pattern classifier (rejecting alternations like
/// `/\.|/(vendor|storage)/` so non-dotfile denials are NEVER misclassified as dotfile-only!).
fn is_strict_dotfile_only_pattern(raw_pat: &str) -> bool {
    let trimmed = raw_pat.trim();
    if trimmed.contains('|') {
        return false;
    }
    let no_anchor = trimmed
        .strip_prefix('^')
        .unwrap_or(trimmed)
        .strip_suffix('$')
        .unwrap_or(trimmed.strip_prefix('^').unwrap_or(trimmed));
    matches!(
        no_anchor,
        "/\\."
            | "/\\..*"
            | "/\\.(?!well-known)"
            | "/\\.(?!well-known).*"
            | "/\\.ht"
            | "/\\.ht.*"
            | "/\\.htaccess"
            | "/\\.htpasswd"
            | "\\.ht"
            | "\\.ht.*"
            | "/\\.git"
            | "/\\.git.*"
            | "/\\.svn"
            | "/\\.svn.*"
            | "/\\.hg"
            | "/\\.env"
            | "/.ht"
            | "/.git"
    )
}

/// R5-MIG-2: Strictly recognizes ONLY the exact WordPress deny patterns actually enforced by
/// `preset "wordpress-hardened"` (`xmlrpc.php`, `wp-config.php`, `wp-content/uploads/.*\.php`,
/// and `wp-includes/.*\.php`). Generic `/uploads/.*\.php$` or `/(?:uploads|files)/.*\.php$`
/// patterns are NEVER mapped to the preset because the preset does not block them!
fn is_wordpress_preset_deny_pattern(raw_pat: &str) -> bool {
    let lower = raw_pat.trim().to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "/xmlrpc.php"
            | "^/xmlrpc\\.php$"
            | "/xmlrpc\\.php$"
            | "xmlrpc\\.php$"
            | "/wp-config.php"
            | "^/wp-config\\.php$"
            | "/wp-config\\.php$"
            | "wp-config\\.php$"
    ) {
        return true;
    }
    if lower.contains('|') {
        return false;
    }
    (lower.contains("wp-content/uploads") || lower.contains("wp-includes"))
        && lower.contains(".php")
}

/// Returns `true` when a path/pattern carries genuine WordPress indicators (`R5-MIG-2`).
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

#[derive(Debug, Clone)]
enum TokenKind {
    Word(String),
    Semicolon,
    LBrace,
    RBrace,
}

#[derive(Debug, Clone)]
struct Token {
    line: usize,
    kind: TokenKind,
}

#[derive(Debug)]
enum NginxItem {
    Directive {
        file: Option<String>,
        line: usize,
        name: String,
        args: Vec<String>,
    },
    Block {
        file: Option<String>,
        line: usize,
        name: String,
        args: Vec<String>,
        body: Vec<NginxItem>,
    },
}

fn tag_nginx_items_file(items: &mut [NginxItem], file_name: &str) {
    for item in items {
        match item {
            NginxItem::Directive { file, .. } => {
                if file.is_none() {
                    *file = Some(file_name.to_owned());
                }
            }
            NginxItem::Block { file, body, .. } => {
                if file.is_none() {
                    *file = Some(file_name.to_owned());
                }
                tag_nginx_items_file(body, file_name);
            }
        }
    }
}

fn tokenize_nginx(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    let mut line: usize = 1;

    while let Some(&ch) = chars.peek() {
        match ch {
            '\n' => {
                line = line.saturating_add(1);
                chars.next();
            }
            c if c.is_whitespace() => {
                chars.next();
            }
            '#' => {
                // Comment to end of line
                for c in chars.by_ref() {
                    if c == '\n' {
                        line = line.saturating_add(1);
                        break;
                    }
                }
            }
            ';' => {
                tokens.push(Token {
                    line,
                    kind: TokenKind::Semicolon,
                });
                chars.next();
            }
            '{' => {
                tokens.push(Token {
                    line,
                    kind: TokenKind::LBrace,
                });
                chars.next();
            }
            '}' => {
                tokens.push(Token {
                    line,
                    kind: TokenKind::RBrace,
                });
                chars.next();
            }
            '"' | '\'' => {
                let quote = ch;
                let start_line = line;
                chars.next();
                let mut word = String::new();
                while let Some(c) = chars.next() {
                    if c == '\n' {
                        line = line.saturating_add(1);
                    }
                    if c == '\\' {
                        if let Some(esc) = chars.next() {
                            if esc == '\n' {
                                line = line.saturating_add(1);
                            }
                            word.push(esc);
                        }
                        continue;
                    }
                    if c == quote {
                        break;
                    }
                    word.push(c);
                }
                tokens.push(Token {
                    line: start_line,
                    kind: TokenKind::Word(word),
                });
            }
            _ => {
                let start_line = line;
                let mut word = String::new();
                while let Some(&c) = chars.peek() {
                    // R5-MIG-6: In Nginx, `#` starts a comment ONLY at the start of a token,
                    // never inside an unquoted word such as `https://a.example.com/#denied;`.
                    if c.is_whitespace() || matches!(c, ';' | '{' | '}') {
                        break;
                    }
                    word.push(c);
                    chars.next();
                }
                if !word.is_empty() {
                    tokens.push(Token {
                        line: start_line,
                        kind: TokenKind::Word(word),
                    });
                }
            }
        }
    }
    tokens
}

fn parse_items(
    tokens: &[Token],
    pos: &mut usize,
    depth: usize,
    depth_exceeded: &mut Option<usize>,
) -> Vec<NginxItem> {
    let mut items = Vec::new();
    if depth >= MAX_BLOCK_DEPTH {
        // R5-MIG-8: Record nesting overflow and consume balanced `{`/`}` blocks so callers fail closed.
        let overflow_line = tokens.get(*pos).map_or(1, |t| t.line);
        if depth_exceeded.is_none() {
            *depth_exceeded = Some(overflow_line);
        }
        let mut skip_depth: usize = 1;
        while let Some(tok) = tokens.get(*pos) {
            *pos = pos.saturating_add(1);
            match tok.kind {
                TokenKind::LBrace => skip_depth = skip_depth.saturating_add(1),
                TokenKind::RBrace => {
                    skip_depth = skip_depth.saturating_sub(1);
                    if skip_depth == 0 {
                        break;
                    }
                }
                TokenKind::Word(_) | TokenKind::Semicolon => {}
            }
        }
        return items;
    }

    let mut cur_words: Vec<(usize, String)> = Vec::new();

    while let Some(tok) = tokens.get(*pos) {
        *pos = pos.saturating_add(1);
        match &tok.kind {
            TokenKind::Word(w) => {
                cur_words.push((tok.line, w.clone()));
            }
            TokenKind::Semicolon => {
                if let Some((line, name)) = cur_words.first().cloned() {
                    let args = cur_words.into_iter().skip(1).map(|(_, w)| w).collect();
                    items.push(NginxItem::Directive {
                        file: None,
                        line,
                        name,
                        args,
                    });
                    cur_words = Vec::new();
                }
            }
            TokenKind::LBrace => {
                let body = parse_items(tokens, pos, depth.saturating_add(1), depth_exceeded);
                if let Some((line, name)) = cur_words.first().cloned() {
                    let args = cur_words.into_iter().skip(1).map(|(_, w)| w).collect();
                    items.push(NginxItem::Block {
                        file: None,
                        line,
                        name,
                        args,
                        body,
                    });
                }
                cur_words = Vec::new();
            }
            TokenKind::RBrace => {
                if let Some((line, name)) = cur_words.first().cloned() {
                    let args = cur_words.into_iter().skip(1).map(|(_, w)| w).collect();
                    items.push(NginxItem::Directive {
                        file: None,
                        line,
                        name,
                        args,
                    });
                }
                return items;
            }
        }
    }

    if let Some((line, name)) = cur_words.first().cloned() {
        let args = cur_words.into_iter().skip(1).map(|(_, w)| w).collect();
        items.push(NginxItem::Directive {
            file: None,
            line,
            name,
            args,
        });
    }
    items
}

#[derive(Debug, Default)]
struct NginxUpstreams {
    http: BTreeMap<String, Vec<String>>,
    fastcgi: BTreeMap<String, Vec<String>>,
    /// Number of `map ... $connection_upgrade { ... }` blocks seen, and whether every one of
    /// them is the stock WebSocket map (see `is_stock_connection_upgrade_map`).
    connection_upgrade_maps: usize,
    connection_upgrade_maps_all_stock: bool,
}

impl NginxUpstreams {
    /// `$connection_upgrade` may be treated as "upgrade when the client asks for one" only when
    /// exactly one map defines it and that map is the stock one. A map keyed on the host or any
    /// other request property makes the upgrade conditional in a way a route cannot express.
    fn connection_upgrade_is_stock(&self) -> bool {
        self.connection_upgrade_maps == 1 && self.connection_upgrade_maps_all_stock
    }
}

/// Returns `true` for the documented WebSocket map and nothing else:
/// `map $http_upgrade $connection_upgrade { default upgrade; '' close; }`.
fn is_stock_connection_upgrade_map(args: &[String], body: &[NginxItem]) -> bool {
    if args.first().map(String::as_str) != Some("$http_upgrade") {
        return false;
    }
    let mut has_default_upgrade = false;
    for item in body {
        let NginxItem::Directive { name, args, .. } = item else {
            return false;
        };
        let value = match args.as_slice() {
            [v] => v.trim_matches(['"', '\'']),
            _ => return false,
        };
        match name.trim_matches(['"', '\'']) {
            "default" if value.eq_ignore_ascii_case("upgrade") => has_default_upgrade = true,
            "" if value.eq_ignore_ascii_case("close") || value.is_empty() => {}
            _ => return false,
        }
    }
    has_default_upgrade
}

fn expand_nginx_includes(
    items: Vec<NginxItem>,
    inc_ctx: &mut IncludeContext,
    doc: &mut MigratedDoc,
    depth_exceeded: &mut Option<usize>,
) -> Vec<NginxItem> {
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        match item {
            NginxItem::Directive {
                file,
                line,
                name,
                args,
            } if name.eq_ignore_ascii_case("include") => {
                let target = args.first().map_or("", String::as_str);
                match inc_ctx.expand(target, true) {
                    BoundedIncludeResult::Expanded(files) => {
                        let prev_file = doc.set_source_file(file.clone());
                        let safe_target = sanitize_diagnostic_text(target, 120);
                        doc.push_note(
                            Some(line),
                            "include",
                            format!(
                                "Expanded Nginx `include {safe_target}` from local config tree ({} file(s))",
                                files.len()
                            ),
                        );
                        doc.set_source_file(prev_file);
                        for (canon_path, content) in files {
                            if !inc_ctx.enter(canon_path.clone()) {
                                out.push(NginxItem::Directive {
                                    file: file.clone(),
                                    line,
                                    name: name.clone(),
                                    args: args.clone(),
                                });
                                continue;
                            }
                            let label = canon_path
                                .file_name()
                                .and_then(|n| n.to_str())
                                .map_or_else(|| canon_path.display().to_string(), str::to_owned);
                            let toks = tokenize_nginx(&content);
                            let mut sub_pos = 0_usize;
                            let mut sub_ast = parse_items(&toks, &mut sub_pos, 0, depth_exceeded);
                            tag_nginx_items_file(&mut sub_ast, &label);
                            let expanded =
                                expand_nginx_includes(sub_ast, inc_ctx, doc, depth_exceeded);
                            out.extend(expanded);
                            inc_ctx.leave(&canon_path);
                        }
                    }
                    BoundedIncludeResult::Unavailable => {
                        out.push(NginxItem::Directive {
                            file,
                            line,
                            name,
                            args,
                        });
                    }
                }
            }
            NginxItem::Block {
                file,
                line,
                name,
                args,
                body,
            } => {
                let expanded_body = expand_nginx_includes(body, inc_ctx, doc, depth_exceeded);
                out.push(NginxItem::Block {
                    file,
                    line,
                    name,
                    args,
                    body: expanded_body,
                });
            }
            other @ NginxItem::Directive { .. } => out.push(other),
        }
    }
    out
}

/// Parses Nginx `server { ... }` (and `http { ... }`, `upstream { ... }`) blocks into an
/// unfinalized [`MigratedDoc`] (`lib.rs` runs `finalize_doc_with_options`), expanding bounded
/// local `include` directives when `source_path` is provided (`R4-MIG-5`, `R5-MIG-6`, `R7-MIG-13`).
pub(crate) fn parse_nginx_raw_with_path(
    input: &str,
    source_path: Option<&Path>,
    source_root: Option<&Path>,
) -> MigratedDoc {
    let mut doc = MigratedDoc::new();
    let tokens = tokenize_nginx(input);
    let mut pos = 0_usize;
    let mut depth_exceeded: Option<usize> = None;
    let mut ast = parse_items(&tokens, &mut pos, 0, &mut depth_exceeded);

    if let Some(path) = source_path
        && let Some(mut inc_ctx) = IncludeContext::from_source_path(path, false, source_root)
    {
        ast = expand_nginx_includes(ast, &mut inc_ctx, &mut doc, &mut depth_exceeded);
    }

    let mut inherited_blockers: Vec<(usize, String)> = Vec::new();
    if let Some(overflow_line) = depth_exceeded {
        inherited_blockers.push((overflow_line, "nesting".to_owned()));
        doc.push_security_downgrade(
            Some(overflow_line),
            "nesting",
            format!(
                "Nginx block nesting exceeded parser limit ({MAX_BLOCK_DEPTH}); deeper blocks could not be verified and sites were withheld"
            ),
        );
    }

    let mut upstreams = NginxUpstreams::default();
    collect_upstreams(&ast, &mut upstreams);
    collect_servers(
        &ast,
        &upstreams,
        &mut doc,
        &inherited_blockers,
        &ProxyHeaderRules::new(),
    );

    doc
}

fn collect_upstreams(items: &[NginxItem], upstreams: &mut NginxUpstreams) {
    for item in items {
        if let NginxItem::Block {
            name, args, body, ..
        } = item
        {
            if name.eq_ignore_ascii_case("map")
                && args.get(1).map(String::as_str) == Some("$connection_upgrade")
            {
                if upstreams.connection_upgrade_maps == 0 {
                    upstreams.connection_upgrade_maps_all_stock = true;
                }
                upstreams.connection_upgrade_maps =
                    upstreams.connection_upgrade_maps.saturating_add(1);
                upstreams.connection_upgrade_maps_all_stock &=
                    is_stock_connection_upgrade_map(args, body);
            } else if name.eq_ignore_ascii_case("upstream") {
                if let Some(pool_name) = args.first() {
                    let mut http_servers = Vec::new();
                    let mut fcgi_servers = Vec::new();
                    for sub in body {
                        if let NginxItem::Directive {
                            name: sub_name,
                            args: sub_args,
                            ..
                        } = sub
                            && sub_name.eq_ignore_ascii_case("server")
                            && let Some(target) = sub_args.first()
                        {
                            fcgi_servers.push(normalize_fastcgi_target(target));
                            if !target.starts_with("unix:") {
                                http_servers.push(normalize_upstream_url(target));
                            }
                        }
                    }
                    if !http_servers.is_empty() {
                        upstreams.http.insert(pool_name.clone(), http_servers);
                    }
                    if !fcgi_servers.is_empty() {
                        upstreams.fastcgi.insert(pool_name.clone(), fcgi_servers);
                    }
                }
            } else if name.eq_ignore_ascii_case("http") {
                collect_upstreams(body, upstreams);
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
fn collect_servers(
    items: &[NginxItem],
    upstreams: &NginxUpstreams,
    doc: &mut MigratedDoc,
    inherited_blockers: &[(usize, String)],
    inherited_proxy_headers: &ProxyHeaderRules,
) {
    // Nginx inherits `proxy_set_header` from the enclosing level only when the current level
    // defines none of its own.
    let own_proxy_headers = direct_proxy_header_rules(items);
    let scope_proxy_headers = if own_proxy_headers.is_empty() {
        inherited_proxy_headers
    } else {
        &own_proxy_headers
    };
    // R2-MIG-1, R3-MIG-1, R4-MIG-5, R5-MIG-3, R5-MIG-6: Scan `http`/top-level directives AND
    // security blocks FIRST so inherited `allow`/`deny`/`auth_*`/`modsecurity`/CSP `add_header`/
    // `access_by_lua_block` or unverified `include` files (including `conf.d/*.conf` and
    // `sites-enabled/*` when not expanded from disk) are NEVER dropped!
    let mut scope_blockers: Vec<(usize, String)> = inherited_blockers.to_vec();
    let scope_has_deny = items_contain_deny(items);
    for item in items {
        match item {
            NginxItem::Directive {
                file,
                line,
                name,
                args,
            } => {
                let prev_file = doc.set_source_file(file.clone());
                let lower = name.to_ascii_lowercase();
                if is_nginx_security_directive(&lower) {
                    let is_off = (lower == "auth_basic" || lower == "modsecurity")
                        && args.first().is_some_and(|v| v.eq_ignore_ascii_case("off"));
                    let is_noop_allow_all = lower == "allow"
                        && !scope_has_deny
                        && args.first().is_some_and(|v| v.eq_ignore_ascii_case("all"));
                    if !is_off && !is_noop_allow_all {
                        scope_blockers.push((*line, name.clone()));
                        doc.push_security_downgrade(
                            Some(*line),
                            name.clone(),
                            format!(
                                "Inherited Nginx `{name}` directive outside `server {{}}` cannot be auto-translated; server routes withheld"
                            ),
                        );
                    }
                } else if lower == "proxy_set_header" {
                    // Collected above (`direct_proxy_header_rules`) and evaluated at each
                    // proxied location that inherits it.
                } else if (lower == "fastcgi_param" && !is_reproduced_fastcgi_param(args))
                    || (!matches!(lower.as_str(), "fastcgi_param" | "proxy_hide_header")
                        && !lower.ends_with("_hide_header")
                        && ["proxy_", "fastcgi_", "uwsgi_", "scgi_", "grpc_"]
                            .iter()
                            .any(|family| lower.starts_with(family))
                        && !is_nginx_inert_directive(&lower))
                {
                    // Request-handling directives are inherited by every server and location
                    // below. One that is neither reproduced nor known to be inert (a custom
                    // `fastcgi_param`, `proxy_pass_header`, `proxy_ssl_*`, `proxy_cookie_*`, ...)
                    // must not vanish just because it was written at `http` level.
                    scope_blockers.push((*line, format!("{lower} (inherited, untranslated)")));
                    doc.push_security_downgrade(
                        Some(*line),
                        lower.clone(),
                        format!(
                            "Inherited Nginx `{lower}` outside `server {{}}` is not reproduced by MiraServe and is not known to be inert; server routes withheld"
                        ),
                    );
                } else if matches!(
                    lower.as_str(),
                    "add_header" | "more_set_headers" | "more_clear_headers"
                ) || lower.ends_with("_hide_header")
                {
                    let classify_as = if lower.ends_with("_hide_header") {
                        "proxy_hide_header"
                    } else {
                        lower.as_str()
                    };
                    for (hdr_label, class) in inspect_nginx_header_directive(classify_as, args) {
                        match class {
                            HeaderClassification::CoveredByStrict => {}
                            HeaderClassification::SafeToDropWithNote(reason) => {
                                doc.push_note(
                                    Some(*line),
                                    lower.clone(),
                                    format!(
                                        "Inherited Nginx `{lower} {hdr_label}` was not auto-translated ({reason})"
                                    ),
                                );
                            }
                            HeaderClassification::SecurityDowngrade(reason) => {
                                scope_blockers.push((*line, format!("{lower} {hdr_label}")));
                                doc.push_security_downgrade(
                                    Some(*line),
                                    lower.clone(),
                                    format!(
                                        "Inherited Nginx `{lower} {hdr_label}` cannot be auto-translated ({reason}); server routes withheld"
                                    ),
                                );
                            }
                        }
                    }
                } else if lower == "include" {
                    let target = args.first().map_or("", String::as_str);
                    let safe_target = sanitize_diagnostic_text(target, 120);
                    if is_safe_nginx_include_target(target) {
                        doc.push_note(
                            Some(*line),
                            "include",
                            format!(
                                "Nginx include `{safe_target}` matched known stock non-ACL path (assumed safe, not read)"
                            ),
                        );
                    } else {
                        scope_blockers.push((*line, "include".to_owned()));
                        doc.push_security_downgrade(
                            Some(*line),
                            "include",
                            format!(
                                "Unexpanded Nginx `include {safe_target}` may contain inherited access/auth controls and cannot be safely imported without reading it"
                            ),
                        );
                    }
                }
                doc.set_source_file(prev_file);
            }
            NginxItem::Block {
                file, line, name, ..
            } => {
                let prev_file = doc.set_source_file(file.clone());
                let lower = name.to_ascii_lowercase();
                if is_nginx_security_directive(&lower) {
                    scope_blockers.push((*line, name.clone()));
                    doc.push_security_downgrade(
                        Some(*line),
                        name.clone(),
                        format!(
                            "Inherited Nginx security block `{name} {{ ... }}` outside `server {{}}` cannot be auto-translated; server routes withheld"
                        ),
                    );
                }
                doc.set_source_file(prev_file);
            }
        }
    }

    for item in items {
        if let NginxItem::Block {
            file, name, body, ..
        } = item
        {
            let prev_file = doc.set_source_file(file.clone());
            if name.eq_ignore_ascii_case("http") {
                collect_servers(body, upstreams, doc, &scope_blockers, scope_proxy_headers);
            } else if name.eq_ignore_ascii_case("server") {
                process_server_block(body, upstreams, doc, &scope_blockers, scope_proxy_headers);
            }
            doc.set_source_file(prev_file);
        }
    }
}

#[allow(clippy::too_many_lines)]
fn process_server_block(
    body: &[NginxItem],
    upstreams: &NginxUpstreams,
    doc: &mut MigratedDoc,
    inherited_blockers: &[(usize, String)],
    inherited_proxy_headers: &ProxyHeaderRules,
) {
    let own_proxy_headers = direct_proxy_header_rules(body);
    let server_proxy_headers = if own_proxy_headers.is_empty() {
        inherited_proxy_headers
    } else {
        &own_proxy_headers
    };
    let mut site = MigratedSite::default();
    for (line, dir) in inherited_blockers {
        site.block_site(Some(*line), dir);
    }
    let mut has_https_return = false;
    let mut has_non_redirect_content = false;
    let mut has_legacy_ssl_on = false;
    let mut php_indicator: Option<(usize, String)> = None;
    let mut server_listens: Vec<(String, u16, bool)> = Vec::new();
    let mut dotfile_deny_locations: Vec<(usize, String)> = Vec::new();
    let mut wp_covered_deny_locations: Vec<(usize, String)> = Vec::new();
    let mut is_drop_only_default_server = false;
    let mut deferred_404_return: Option<(usize, String)> = None;
    let server_has_deny = items_contain_deny(body);

    for item in body {
        match item {
            NginxItem::Directive {
                file,
                line,
                name,
                args,
            } => {
                let prev_file = doc.set_source_file(file.clone());
                let lower = name.to_ascii_lowercase();
                if is_nginx_security_directive(&lower) {
                    let is_off = (lower == "auth_basic" || lower == "modsecurity")
                        && args.first().is_some_and(|v| v.eq_ignore_ascii_case("off"));
                    let is_noop_allow_all = lower == "allow"
                        && !server_has_deny
                        && args.first().is_some_and(|v| v.eq_ignore_ascii_case("all"));
                    if !is_off && !is_noop_allow_all {
                        site.block_site(Some(*line), name);
                        doc.push_security_downgrade(
                            Some(*line),
                            name.clone(),
                            format!(
                                "Server-level Nginx security directive '{name}' cannot be auto-translated; site routes withheld to avoid exposing protected resources"
                            ),
                        );
                    }
                    doc.set_source_file(prev_file);
                    continue;
                }
                if lower == "include" {
                    let target = args.first().map_or("", String::as_str);
                    let safe_target = sanitize_diagnostic_text(target, 120);
                    if is_safe_nginx_include_target(target) {
                        doc.push_note(
                            Some(*line),
                            "include",
                            format!(
                                "Nginx include `{safe_target}` matched known stock non-ACL path (assumed safe, not read)"
                            ),
                        );
                    } else {
                        // R6-MIG-1: Never echo raw untrusted include targets into KDL comments!
                        site.block_site(Some(*line), "include");
                        doc.push_security_downgrade(
                            Some(*line),
                            "include",
                            format!(
                                "Unexpanded server-level Nginx `include {safe_target}` may enforce auth/ACLs; site routes withheld"
                            ),
                        );
                    }
                    doc.set_source_file(prev_file);
                    continue;
                }

                match lower.as_str() {
                    "listen" => {
                        if let Some(first) = args.first() {
                            if first.starts_with("unix:") {
                                site.block_site(Some(*line), "listen");
                                doc.push_security_downgrade(
                                    Some(*line),
                                    "listen",
                                    format!(
                                        "Nginx Unix-socket listener `listen {first}` cannot be mapped to a public TCP listener safely; configure explicitly"
                                    ),
                                );
                            } else {
                                let has_ssl = args.iter().any(|a| a.eq_ignore_ascii_case("ssl"));
                                let default_port = if has_ssl { 443 } else { 80 };
                                if let Some((bind, port)) =
                                    normalize_bind_addr_with_default_port(first, default_port)
                                {
                                    let is_ssl = has_ssl || port == 443;
                                    server_listens.push((bind, port, is_ssl));
                                } else {
                                    // R4-MIG-6: Never silently drop `listen hostname:port` and fall
                                    // back to public `:443`!
                                    site.block_site(Some(*line), "listen");
                                    doc.push_security_downgrade(
                                        Some(*line),
                                        "listen",
                                        format!(
                                            "Nginx listener `listen {first}` uses a hostname or unsupported bind syntax that cannot be resolved safely; site withheld to prevent unintended public exposure"
                                        ),
                                    );
                                }
                            }
                        }
                    }
                    "server_name" => {
                        for host in args {
                            if host == "_" {
                                continue;
                            }
                            // R5-MIG-7: Nginx `.example.com` matches both `example.com` and `*.example.com`.
                            if let Some(apex) = host.strip_prefix('.')
                                && !apex.is_empty()
                                && !apex.starts_with('.')
                            {
                                site.hosts.push(apex.to_owned());
                                site.hosts.push(format!("*.{apex}"));
                            } else {
                                site.hosts.push(host.clone());
                            }
                        }
                    }
                    "root" => {
                        if let Some(r) = args.first() {
                            has_non_redirect_content = true;
                            let trimmed_r = r.trim();
                            if trimmed_r == "." || trimmed_r == "./" {
                                site.block_site(Some(*line), "root");
                            }
                            let resolved = normalize_nginx_root(r, *line, doc);
                            if site.root.as_deref().is_some_and(|prev| prev != resolved) {
                                // R8-MIG-8: a `location / { root ...; }` seen earlier disagrees.
                                site.block_site(Some(*line), "root (conflicting roots)");
                                doc.push_security_downgrade(
                                    Some(*line),
                                    "root",
                                    "Nginx server-level `root` differs from a location-level `root`; site withheld because one MiraServe site root cannot represent both",
                                );
                            }
                            if is_wordpress_indicator_path(&resolved) {
                                site.wordpress = true;
                                doc.push_upgrade(
                                    "Detected WordPress document root — enabled preset \"wordpress-hardened\"",
                                );
                            }
                            site.root = Some(resolved);
                        }
                    }
                    "ssl" => {
                        if args.first().is_some_and(|v| v.eq_ignore_ascii_case("on")) {
                            has_legacy_ssl_on = true;
                        }
                    }
                    "ssl_certificate" => {
                        if let Some(c) = args.first() {
                            site.cert = Some(c.clone());
                        }
                    }
                    "ssl_certificate_key" => {
                        if let Some(k) = args.first() {
                            site.key = Some(k.clone());
                        }
                    }
                    "ssl_protocols" => {
                        if args.iter().any(|p| p.eq_ignore_ascii_case("TLSv1.2"))
                            && !args.iter().all(|p| p.eq_ignore_ascii_case("TLSv1.3"))
                        {
                            doc.push_upgrade(
                                "Upgraded legacy Nginx ssl_protocols to TLS 1.3 + X25519MLKEM768 PQC default",
                            );
                        }
                    }
                    "index" => {
                        // R5-MIG-1: Track PHP index files so sites without a FastCGI route fail closed.
                        if args.iter().any(|a| is_php_filename(a)) && php_indicator.is_none() {
                            php_indicator = Some((*line, format!("index {}", args.join(" "))));
                        }
                    }
                    _ if lower.ends_with("_hide_header") => {
                        // R7-MIG-7 & R8-MIG-6: `proxy_`, `fastcgi_`, `uwsgi_`, `scgi_` and
                        // `grpc_hide_header` all stop an upstream header reaching the client.
                        for (hdr_label, class) in
                            inspect_nginx_header_directive("proxy_hide_header", args)
                        {
                            match class {
                                HeaderClassification::CoveredByStrict => {}
                                HeaderClassification::SafeToDropWithNote(reason) => {
                                    doc.push_note(
                                        Some(*line),
                                        lower.clone(),
                                        format!(
                                            "Server-level Nginx `{lower} {hdr_label}` was not auto-translated ({reason})"
                                        ),
                                    );
                                }
                                HeaderClassification::SecurityDowngrade(reason) => {
                                    site.block_site(Some(*line), &format!("{lower} {hdr_label}"));
                                    doc.push_security_downgrade(
                                        Some(*line),
                                        lower.clone(),
                                        format!(
                                            "Server-level Nginx `{lower} {hdr_label}` cannot be auto-translated ({reason}); site routes withheld"
                                        ),
                                    );
                                }
                            }
                        }
                    }
                    "add_header" | "more_set_headers" | "more_clear_headers" => {
                        // R5-MIG-3, R6-MIG-5, R7-MIG-7 & R7-MIG-12: Default-deny untranslated
                        // security/response headers while allowing benign caching/diagnostic
                        // headers with an informational note.
                        for (hdr_label, class) in inspect_nginx_header_directive(&lower, args) {
                            match class {
                                HeaderClassification::CoveredByStrict => {}
                                HeaderClassification::SafeToDropWithNote(reason) => {
                                    doc.push_note(
                                        Some(*line),
                                        lower.clone(),
                                        format!(
                                            "Server-level Nginx `{lower} {hdr_label}` was not auto-translated ({reason})"
                                        ),
                                    );
                                }
                                HeaderClassification::SecurityDowngrade(reason) => {
                                    site.block_site(Some(*line), &format!("{lower} {hdr_label}"));
                                    doc.push_security_downgrade(
                                        Some(*line),
                                        lower.clone(),
                                        format!(
                                            "Server-level Nginx `{lower} {hdr_label}` cannot be auto-translated ({reason}); site routes withheld"
                                        ),
                                    );
                                }
                            }
                        }
                    }
                    "client_max_body_size" => {
                        // R6-MIG-11: Surface client_max_body_size rather than ignoring silently.
                        let val = args.first().map_or("", String::as_str);
                        doc.push_note(
                            Some(*line),
                            "client_max_body_size",
                            format!(
                                "Nginx `client_max_body_size {val}` is not auto-translated; configure `server.limits.max-body-size` in MiraServe KDL if you need a non-default upload limit"
                            ),
                        );
                    }
                    "return" => {
                        if args.iter().any(|a| a.starts_with("https://")) {
                            has_https_return = true;
                        } else if args
                            .first()
                            .is_some_and(|code| is_blocking_return_code(code))
                        {
                            if args.first().map(String::as_str) == Some("444") {
                                is_drop_only_default_server = true;
                            } else if args.first().map(String::as_str) == Some("404") {
                                deferred_404_return = Some((*line, args.join(" ")));
                            } else {
                                site.block_site(Some(*line), "return");
                                doc.push_security_downgrade(
                                    Some(*line),
                                    "return",
                                    format!(
                                        "Server-level access denial 'return {}' cannot be auto-translated; site withheld",
                                        args.join(" ")
                                    ),
                                );
                            }
                        }
                    }
                    "access_log"
                    | "error_log"
                    | "ssl_ciphers"
                    | "ssl_prefer_server_ciphers"
                    | "ssl_dhparam"
                    | "ssl_session_cache"
                    | "ssl_session_timeout"
                    | "ssl_stapling"
                    | "ssl_stapling_verify"
                    | "resolver"
                    | "server_tokens"
                    | "gzip"
                    | "keepalive_timeout"
                    | "charset"
                    // `proxy_set_header` is evaluated per proxied location against the rules
                    // actually in effect there (`evaluate_proxy_header_rules`), with inheritance.
                    | "proxy_set_header" => {}
                    "fastcgi_param" if is_reproduced_fastcgi_param(args) => {}
                    _ if is_nginx_inert_directive(&lower) => {}
                    _ => {
                        // R8-MIG-1: fail closed. A server-level directive the importer neither
                        // translates nor knows to be inert (`rewrite`, `uwsgi_pass`, `set`, `alias`,
                        // a typo, a third-party module) may decide what the site serves or to whom.
                        // R6-MIG-10: Never echo raw non-identifier content (e.g. shadow hashes)!
                        let label = if is_safe_nginx_directive_name(name) {
                            name.clone()
                        } else {
                            "unknown".to_owned()
                        };
                        site.block_site(Some(*line), &label);
                        doc.push_security_downgrade(
                            Some(*line),
                            label.clone(),
                            format!(
                                "Server-level Nginx directive '{label}' is not translated and is not known to be inert; site withheld because it may change what is served or who may reach it"
                            ),
                        );
                    }
                }
                doc.set_source_file(prev_file);
            }
            NginxItem::Block {
                file,
                line,
                name,
                args,
                body: sub_body,
            } => {
                let prev_file = doc.set_source_file(file.clone());
                let lower_block = name.to_ascii_lowercase();
                if lower_block == "location" {
                    if args.len() == 1
                        && args.first().map(String::as_str) == Some("/")
                        && is_https_redirect_only_block(sub_body)
                    {
                        has_https_return = true;
                        doc.set_source_file(prev_file);
                        continue;
                    }
                    has_non_redirect_content = true;
                    process_location_block(
                        *line,
                        args,
                        sub_body,
                        upstreams,
                        &mut site,
                        &mut php_indicator,
                        &mut dotfile_deny_locations,
                        &mut wp_covered_deny_locations,
                        server_proxy_headers,
                        doc,
                    );
                } else if lower_block == "if"
                    && is_certbot_host_if_condition(args)
                    && is_https_redirect_only_block(sub_body)
                {
                    // R3-MIG-3 & R4-MIG-6: Strictly recognize Certbot's
                    // `if ($host = example.com) { return 301 https://...; }` ONLY!
                    has_https_return = true;
                } else if is_nginx_security_directive(&lower_block)
                    || block_contains_security_controls(sub_body)
                    || (lower_block == "if" && block_contains_redirect_return(sub_body))
                {
                    // R3-MIG-1 & R4-MIG-6: Catch `access_by_lua_block`, non-Certbot access `if`
                    // redirects (`if ($remote_addr != 10.0.0.1) { return 301 ...; }`), etc.!
                    site.block_site(Some(*line), name);
                    doc.push_security_downgrade(
                        Some(*line),
                        name.clone(),
                        format!(
                            "Server-level Nginx block '{name}' enforces access/security controls that cannot be auto-translated"
                        ),
                    );
                } else if lower_block == "types" {
                    // MIME map only; never affects access.
                } else {
                    // R8-MIG-1: fail closed on any other server-level block (`if` with a
                    // rewrite/proxy body, third-party module blocks, non-Nginx text).
                    let label = if is_safe_nginx_directive_name(name) {
                        name.clone()
                    } else {
                        "unknown".to_owned()
                    };
                    site.block_site(Some(*line), &label);
                    doc.push_security_downgrade(
                        Some(*line),
                        label.clone(),
                        format!(
                            "Server-level Nginx block '{label}' is not translated and is not known to be inert; site withheld because it may change what is served or who may reach it"
                        ),
                    );
                }
                doc.set_source_file(prev_file);
            }
        }
    }

    // R3-MIG-6 & R5-MIG-7: `location ~ /\. { deny all; }` is natively protected on static routes
    // AND on FastCGI routes backed by `site.root` (`StaticServer::exists_regular_file` enforces
    // `DotfilesPolicy::Deny` before invoking FastCGI). Only reverse-proxy routes (or root-less
    // FastCGI) are unprotected!
    let has_unprotected_dynamic_route = site.routes.iter().any(|r| {
        matches!(r.handler, MigratedHandler::ReverseProxy { .. })
            || (matches!(r.handler, MigratedHandler::FastCgi { .. }) && site.root.is_none())
    });
    for (loc_line, raw_pat) in dotfile_deny_locations {
        if has_unprotected_dynamic_route {
            site.block_site(Some(loc_line), "deny");
            doc.push_security_downgrade(
                Some(loc_line),
                "deny",
                format!(
                    "Nginx dotfile deny block '{raw_pat}' is NOT enforced automatically on reverse-proxy routes; block dotfile paths explicitly or restrict upstream"
                ),
            );
        } else {
            doc.push_upgrade(format!(
                "Replaced Nginx dotfile deny block '{raw_pat}' with native MiraServe dotfile denial protection"
            ));
        }
    }

    // R4-MIG-3 & R5-MIG-2: WordPress-specific deny blocks (`xmlrpc.php`, `wp-config.php`,
    // `wp-content/uploads/.*.php`, `wp-includes/.*.php`) are natively covered ONLY when
    // `preset "wordpress-hardened"` is active on this site!
    for (loc_line, raw_pat) in wp_covered_deny_locations {
        if site.wordpress {
            doc.push_upgrade(format!(
                "Replaced Nginx WordPress deny block '{raw_pat}' with native preset \"wordpress-hardened\""
            ));
        } else {
            site.block_site(Some(loc_line), "deny");
            doc.push_security_downgrade(
                Some(loc_line),
                "deny",
                format!(
                    "Nginx deny location '{raw_pat}' cannot be auto-translated without preset \"wordpress-hardened\"; site routes withheld"
                ),
            );
        }
    }

    // R6-MIG-11: Do NOT silently drop `server { server_name _; return 444; }` — MiraServe serves
    // its built-in Welcome page on unmatched HTTP hosts rather than closing the TCP connection.
    if is_drop_only_default_server {
        site.block_site(None, "return 444");
        doc.push_security_downgrade(
            None,
            "return",
            "Nginx `return 444` silent connection drop cannot be auto-translated (MiraServe serves a default response on unmatched Host headers instead of resetting TCP); review host filtering manually",
        );
        if site.hosts.is_empty() && !has_non_redirect_content && site.root.is_none() {
            return;
        }
    }

    // R3-MIG-3: Certbot managed port-80 redirect block (`if ($host = ...) { return 301 https://...; } return 404;`).
    let is_redirect_only = has_https_return && !has_non_redirect_content;
    if let Some((ret_line, ret_args)) = deferred_404_return {
        let all_non_ssl =
            !has_legacy_ssl_on && server_listens.iter().all(|(_, _, is_ssl)| !*is_ssl);
        if is_redirect_only && all_non_ssl {
            doc.push_upgrade(
                "Replaced Certbot HTTP->HTTPS redirect server (`if ($host = ...) return 301 https://...; return 404;`) with MiraServe native 308 redirect listener",
            );
        } else {
            site.block_site(Some(ret_line), "return");
            doc.push_security_downgrade(
                Some(ret_line),
                "return",
                format!(
                    "Server-level access denial 'return {ret_args}' cannot be auto-translated; site withheld"
                ),
            );
        }
    }

    // R5-MIG-1: Fail closed if this site shows PHP usage (e.g. `index index.php`, `try_files`
    // targeting `index.php`, or an untranslated PHP regex `fastcgi_pass`) with NO `*.php`
    // FastCGI route emitted!
    if !is_redirect_only
        && let Some((php_line, php_src)) = php_indicator
        && !site
            .routes
            .iter()
            .any(|r| matches!(r.handler, MigratedHandler::FastCgi { .. }))
    {
        site.block_site(Some(php_line), "php");
        doc.push_security_downgrade(
            Some(php_line),
            "php",
            format!(
                "Nginx server indicates PHP execution ({php_src}) but no `*.php` FastCGI route was emitted; configure `fastcgi-pass` manually before deploying"
            ),
        );
    }

    if is_redirect_only {
        doc.redirect_http = true;
        for (bind, _port, is_ssl) in server_listens {
            if !is_ssl && !has_legacy_ssl_on {
                doc.add_http_bind(bind);
            }
        }
    } else {
        for (bind, port, is_ssl) in server_listens {
            if is_ssl || has_legacy_ssl_on {
                site.add_https_bind(bind.clone());
                doc.add_https_bind(bind);
            } else {
                // R5-MIG-7: Plain HTTP listeners (`listen 80;`, `listen 8080;` without `ssl`)
                // are recorded as HTTP binds — never TLS `h3,h2,h1` on a plain HTTP port!
                if port != 80 && !is_scoped_bind(&bind) {
                    doc.push_note(
                        None,
                        "listen",
                        format!(
                            "Plain HTTP Nginx listener '{bind}' (no `ssl` flag) mapped to HTTP->HTTPS redirect; TLS terminates on ':443'"
                        ),
                    );
                }
                site.add_http_bind(bind.clone());
                doc.add_http_bind(bind);
            }
        }
        doc.sites.push(site);
    }
}

/// Returns `true` when an `if (...) { ... }` block contains solely an HTTP->HTTPS redirect
/// (`return 301/302/307/308 https://...;`), such as Certbot's managed port-80 redirect stanza.
fn is_https_redirect_only_block(items: &[NginxItem]) -> bool {
    !items.is_empty()
        && items.iter().all(|item| match item {
            NginxItem::Directive { name, args, .. } => {
                name.eq_ignore_ascii_case("return")
                    && args
                        .first()
                        .is_some_and(|c| matches!(c.as_str(), "301" | "302" | "307" | "308"))
                    && args.iter().any(|a| a.starts_with("https://"))
            }
            NginxItem::Block { .. } => false,
        })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn process_location_block(
    line: usize,
    args: &[String],
    body: &[NginxItem],
    upstreams: &NginxUpstreams,
    site: &mut MigratedSite,
    php_indicator: &mut Option<(usize, String)>,
    dotfile_deny_locations: &mut Vec<(usize, String)>,
    wp_covered_deny_locations: &mut Vec<(usize, String)>,
    inherited_proxy_headers: &ProxyHeaderRules,
    doc: &mut MigratedDoc,
) {
    let (modifier, raw_pat) = split_nginx_location_modifier(args);
    // R3-MIG-8: Named internal Nginx locations (`location @fallback { ... }`) are internal
    // jump targets and must NEVER be emitted as public `/@fallback/*` routes!
    if raw_pat.starts_with('@') {
        doc.push_note(
            Some(line),
            "location",
            format!(
                "Named internal Nginx location '{raw_pat}' cannot be mapped to a public route and was skipped"
            ),
        );
        return;
    }
    let is_exact = modifier == Some("=");
    let is_regex = matches!(modifier, Some("~" | "~*"));
    let is_preferential_prefix = modifier == Some("^~");

    // R5-MIG-2: Recognize genuine WordPress indicators in location paths (`wp-content`,
    // `wp-includes`, `wp-config.php`, `xmlrpc.php`, `wp-login.php`, `wp-admin`).
    if is_wordpress_indicator_path(raw_pat) {
        site.wordpress = true;
    }

    let mut proxy_targets: Option<Vec<String>> = None;
    let mut fastcgi_pass: Option<String> = None;
    let mut try_files: Option<Vec<String>> = None;
    let mut security_blockers: Vec<(usize, String)> = Vec::new();
    let mut has_deny_or_block_return = false;
    let loc_has_deny = items_contain_deny(body);

    collect_location_directives(
        body,
        raw_pat,
        upstreams,
        php_indicator,
        doc,
        &mut proxy_targets,
        &mut fastcgi_pass,
        &mut try_files,
        &mut security_blockers,
        &mut has_deny_or_block_return,
        loc_has_deny,
        0,
    );

    // R8-MIG-8: a per-location `root` normally changes which directory the path serves, so it is
    // a blocker. It is harmless in exactly two cases: it repeats the server-level root, or it is
    // the stock `location / { root <dir>; }` form on a server that declares no root of its own
    // (then it IS the site root). A later conflicting server-level `root` withholds the site.
    let location_root = body.iter().find_map(|item| match item {
        NginxItem::Directive { name, args, .. } if name.eq_ignore_ascii_case("root") => {
            args.first().map(|r| r.trim().to_owned())
        }
        _ => None,
    });
    if let Some(loc_root) = location_root.filter(|r| r.starts_with('/')) {
        let reconciled = match site.root.as_deref() {
            Some(existing) => existing == loc_root,
            None if !is_regex && raw_pat == "/" => {
                site.root = Some(loc_root);
                true
            }
            None => false,
        };
        if reconciled {
            security_blockers.retain(|(_, d)| d != "root (untranslated)");
        }
    }

    // For a proxied location, check the `proxy_set_header` rules actually in effect: the
    // location's own if it defines any, otherwise the ones it inherits from `server`/`http`.
    let mut proxy_headers = ProxyHeaderOutcome::default();
    if proxy_targets.is_some() {
        let own_rules = direct_proxy_header_rules(body);
        let effective_rules = if own_rules.is_empty() {
            inherited_proxy_headers
        } else {
            &own_rules
        };
        match evaluate_proxy_header_rules(effective_rules, upstreams.connection_upgrade_is_stock())
        {
            Ok(outcome) => proxy_headers = outcome,
            Err((rule_line, label)) => security_blockers.push((rule_line, label)),
        }
        // With a named `upstream` pool Nginx's default `Host` is the POOL NAME (`$proxy_host`),
        // which MiraServe cannot send: it sends the address of the member it picked. A backend
        // that selects a virtual host by name would switch tenants.
        if !proxy_headers.preserve_host
            && let Some(pool) = proxy_pass_pool_name(body, upstreams)
        {
            let safe_pool = sanitize_diagnostic_text(pool, 60);
            security_blockers.push((
                line,
                format!(
                    "proxy_pass to upstream pool '{safe_pool}' with default Host (not reproduced)"
                ),
            ));
        }
    }

    if fastcgi_pass.is_some() && php_indicator.is_none() {
        *php_indicator = Some((line, format!("fastcgi_pass in location '{raw_pat}'")));
    }

    let only_deny_blockers = !security_blockers.is_empty()
        && security_blockers.iter().all(|(_, d)| {
            let dl = d.to_ascii_lowercase();
            dl == "deny" || dl.starts_with("return 403") || dl.starts_with("return 404")
        });

    // R4-MIG-6: Strict dotfile-only pattern classifier (never matching `/\.|/(vendor|storage)/`!).
    let is_dotfile_deny_only = proxy_targets.is_none()
        && fastcgi_pass.is_none()
        && try_files.is_none()
        && has_deny_or_block_return
        && only_deny_blockers
        && is_strict_dotfile_only_pattern(raw_pat);
    if is_dotfile_deny_only {
        dotfile_deny_locations.push((line, raw_pat.to_owned()));
        return;
    }

    // R4-MIG-3 & R5-MIG-2: Defer ONLY exact `wordpress-hardened` deny locations (`xmlrpc.php`,
    // `wp-config.php`, `wp-content/uploads/.*.php`, `wp-includes/.*.php`)!
    let is_wp_deny_only = proxy_targets.is_none()
        && fastcgi_pass.is_none()
        && try_files.is_none()
        && has_deny_or_block_return
        && only_deny_blockers
        && is_wordpress_preset_deny_pattern(raw_pat);
    if is_wp_deny_only {
        wp_covered_deny_locations.push((line, raw_pat.to_owned()));
        return;
    }

    // MIG-3 & R5-MIG-4: If this location had auth/ACL/rate-limit/deny/security-header/PHP-ini
    // directives (or a nested `location` block, `R6-MIG-4`), omit the route AND record the blocked
    // location pattern on the site so any overlapping catch-all route (`/*`) or static `root`
    // fallback is also withheld (or tagged `// INSECURE:` under `--allow-insecure`)!
    if !security_blockers.is_empty() {
        let blocked_pat = if is_regex {
            match classify_php_regex_pattern(raw_pat) {
                PhpLocationPattern::Extensions(exts) if exts.len() == 1 => {
                    exts.into_iter().next().unwrap_or_else(|| "/*".to_owned())
                }
                _ => "/*".to_owned(),
            }
        } else {
            normalize_route_pattern_with_mode(raw_pat, is_exact)
        };
        for (sec_line, directive) in security_blockers {
            site.add_blocked_location(blocked_pat.clone(), Some(sec_line), &directive);
            doc.push_security_downgrade(
                Some(sec_line),
                directive.clone(),
                format!(
                    "Nginx location '{raw_pat}' uses '{directive}' which cannot be auto-translated; route omitted to avoid exposing protected endpoint"
                ),
            );
        }
        return;
    }

    // R6-MIG-2 & R6-MIG-3: Strictly classify regex PHP locations so allow-lists like
    // `^/(index|wp-login|wp-cron)\.php$` emit exact routes (NEVER widened to `*.php`), multi-
    // extension regexes like `\.(php|phtml|php5)$` emit one FastCGI route per extension, and
    // untranslatable PHP regexes fail closed with a security downgrade!
    let patterns: Vec<String> = if is_regex {
        match classify_php_regex_pattern(raw_pat) {
            PhpLocationPattern::Extensions(exts) => exts,
            PhpLocationPattern::ExactPaths(paths) => paths,
            PhpLocationPattern::Untranslatable => {
                if fastcgi_pass.is_some() || raw_pat.to_ascii_lowercase().contains(".php") {
                    site.add_blocked_location("/*".to_owned(), Some(line), "location (PHP regex)");
                    doc.push_security_downgrade(
                        Some(line),
                        "location",
                        format!(
                            "Nginx PHP regex location '{raw_pat}' cannot be represented faithfully without widening or narrowing PHP execution; configure explicit routes manually"
                        ),
                    );
                } else if proxy_targets.is_some() || try_files.is_some() {
                    doc.push_note(
                        Some(line),
                        "location",
                        format!(
                            "Nginx regex location '{raw_pat}' cannot be represented as a MiraServe prefix/extension route; configure manually"
                        ),
                    );
                }
                return;
            }
        }
    } else {
        vec![normalize_route_pattern_with_mode(raw_pat, is_exact)]
    };

    if let Some(ups) = proxy_targets {
        for pattern in patterns {
            site.routes.push(
                MigratedRoute::new(
                    pattern,
                    MigratedHandler::ReverseProxy {
                        upstreams: ups.clone(),
                        preserve_host: proxy_headers.preserve_host,
                        allow_upgrades: proxy_headers.allow_upgrades,
                    },
                )
                .with_preferential_prefix(is_preferential_prefix),
            );
        }
    } else if let Some(fcgi) = fastcgi_pass {
        doc.push_upgrade("Isolated PHP execution over pure-Rust async FastCGI");
        for pattern in patterns {
            site.routes.push(
                MigratedRoute::new(
                    pattern,
                    MigratedHandler::FastCgi {
                        target: fcgi.clone(),
                    },
                )
                .with_preferential_prefix(is_preferential_prefix),
            );
        }
    } else if let Some(candidates) = try_files {
        for pattern in patterns {
            site.routes.push(
                MigratedRoute::new(
                    pattern,
                    MigratedHandler::TryFiles {
                        candidates: candidates.clone(),
                    },
                )
                .with_preferential_prefix(is_preferential_prefix),
            );
        }
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn collect_location_directives(
    body: &[NginxItem],
    raw_loc: &str,
    upstreams: &NginxUpstreams,
    php_indicator: &mut Option<(usize, String)>,
    doc: &mut MigratedDoc,
    proxy_targets: &mut Option<Vec<String>>,
    fastcgi_pass: &mut Option<String>,
    try_files: &mut Option<Vec<String>>,
    security_blockers: &mut Vec<(usize, String)>,
    has_deny_or_block_return: &mut bool,
    loc_has_deny: bool,
    depth: usize,
) {
    if depth >= MAX_BLOCK_DEPTH {
        return;
    }
    for item in body {
        match item {
            NginxItem::Directive {
                file,
                line,
                name,
                args,
            } => {
                let prev_file = doc.set_source_file(file.clone());
                let lower = name.to_ascii_lowercase();
                if is_nginx_security_directive(&lower) {
                    let is_off = (lower == "auth_basic" || lower == "modsecurity")
                        && args.first().is_some_and(|v| v.eq_ignore_ascii_case("off"));
                    // R4-MIG-3: `allow all;` without any `deny` in the location is a no-op (e.g.
                    // `location = /robots.txt { allow all; log_not_found off; access_log off; }`).
                    let is_noop_allow_all = lower == "allow"
                        && !loc_has_deny
                        && args.first().is_some_and(|v| v.eq_ignore_ascii_case("all"));
                    if !is_off && !is_noop_allow_all {
                        if lower == "deny" {
                            *has_deny_or_block_return = true;
                        }
                        security_blockers.push((*line, name.clone()));
                    }
                    doc.set_source_file(prev_file);
                    continue;
                }
                if lower == "include" {
                    let target = args.first().map_or("", String::as_str);
                    let safe_target = sanitize_diagnostic_text(target, 120);
                    if is_safe_nginx_include_target(target) {
                        doc.push_note(
                            Some(*line),
                            "include",
                            format!(
                                "Nginx include `{safe_target}` matched known stock non-ACL path (assumed safe, not read)"
                            ),
                        );
                    } else {
                        security_blockers.push((*line, "include".to_owned()));
                    }
                    doc.set_source_file(prev_file);
                    continue;
                }

                match lower.as_str() {
                    "proxy_pass" => {
                        if let Some(target) = args.first() {
                            let resolved =
                                resolve_nginx_proxy_target(target, raw_loc, upstreams, *line, doc);
                            *proxy_targets = Some(resolved);
                        }
                    }
                    "fastcgi_pass" => {
                        if let Some(target) = args.first() {
                            let resolved =
                                resolve_nginx_fastcgi_target(target, upstreams, *line, doc);
                            *fastcgi_pass = Some(resolved);
                        }
                    }
                    "try_files" => {
                        let candidates: Vec<String> = args
                            .iter()
                            .map(|tok| convert_nginx_try_files_token(tok))
                            .collect();
                        // R5-MIG-1 & R5-MIG-2: Track PHP front-controller usage WITHOUT assuming
                        // every `try_files ... index.php` app (e.g. Laravel) is WordPress!
                        if candidates
                            .iter()
                            .any(|c| c.to_ascii_lowercase().contains(".php"))
                            && php_indicator.is_none()
                        {
                            *php_indicator = Some((*line, format!("try_files {}", args.join(" "))));
                        }
                        *try_files = Some(candidates);
                    }
                    "add_header" | "more_set_headers" | "more_clear_headers" => {
                        // R5-MIG-3, R6-MIG-5, R7-MIG-7 & R7-MIG-12: Default-deny untranslated
                        // security headers at location level while allowing benign caching headers
                        // with an informational note so static asset locations do not fail closed.
                        for (hdr_label, class) in inspect_nginx_header_directive(&lower, args) {
                            match class {
                                HeaderClassification::CoveredByStrict => {}
                                HeaderClassification::SafeToDropWithNote(reason) => {
                                    doc.push_note(
                                        Some(*line),
                                        lower.clone(),
                                        format!(
                                            "Nginx location `{lower} {hdr_label}` was not auto-translated ({reason})"
                                        ),
                                    );
                                }
                                HeaderClassification::SecurityDowngrade(_) => {
                                    security_blockers.push((*line, format!("{lower} {hdr_label}")));
                                }
                            }
                        }
                    }
                    "client_max_body_size" => {
                        let val = args.first().map_or("", String::as_str);
                        doc.push_note(
                            Some(*line),
                            "client_max_body_size",
                            format!(
                                "Nginx location `client_max_body_size {val}` is not auto-translated; configure `server.limits.max-body-size` in MiraServe KDL if needed"
                            ),
                        );
                    }
                    "fastcgi_param" => {
                        // R5-MIG-6: Never silently drop PHP_ADMIN_VALUE / PHP_VALUE security overrides
                        // such as `open_basedir` or `disable_functions`.
                        if let Some(param_name) = args.first()
                            && (param_name.eq_ignore_ascii_case("PHP_ADMIN_VALUE")
                                || param_name.eq_ignore_ascii_case("PHP_VALUE"))
                        {
                            security_blockers.push((*line, format!("fastcgi_param {param_name}")));
                        } else if !is_reproduced_fastcgi_param(args) {
                            // Same class as `proxy_set_header`: a non-standard parameter such as
                            // `fastcgi_param HTTP_X_REMOTE_USER "";` or `REMOTE_USER $remote_user`
                            // sets or blanks something the application may trust. Dropping it
                            // would let a client-supplied header take its place.
                            security_blockers
                                .push((*line, "fastcgi_param (untranslated)".to_owned()));
                        }
                    }
                    "return" => {
                        // R7-MIG-9: ANY `return` inside a location (4xx/5xx deny, 3xx redirect such
                        // as `location /backup/ { return 302 /; }`, or body override) changes what
                        // that location serves; silently dropping it would expose the path via `/*`!
                        *has_deny_or_block_return = true;
                        security_blockers.push((*line, format!("return {}", args.join(" "))));
                    }
                    _ if lower.ends_with("_hide_header") => {
                        // R7-MIG-7 & R8-MIG-6: every `*_hide_header` family member.
                        for (hdr_label, class) in
                            inspect_nginx_header_directive("proxy_hide_header", args)
                        {
                            match class {
                                HeaderClassification::CoveredByStrict => {}
                                HeaderClassification::SafeToDropWithNote(reason) => {
                                    doc.push_note(
                                        Some(*line),
                                        lower.clone(),
                                        format!(
                                            "Nginx location `{lower} {hdr_label}` was not auto-translated ({reason})"
                                        ),
                                    );
                                }
                                HeaderClassification::SecurityDowngrade(_) => {
                                    security_blockers.push((*line, format!("{lower} {hdr_label}")));
                                }
                            }
                        }
                    }
                    // Evaluated in `process_location_block` with inheritance.
                    "proxy_set_header" => {}
                    "set" if is_stock_path_info_set(args) => {}
                    _ if is_nginx_inert_directive(&lower) => {}
                    _ => {
                        // R8-MIG-1, R8-MIG-7 & R8-MIG-8: fail closed. A location directive that is
                        // neither translated nor known to be inert (`uwsgi_pass`, `scgi_pass`,
                        // `grpc_pass`, `content_by_lua*`, `js_content`, `rewrite`, `alias`, a
                        // per-location `root`, `internal`, `set`, a typo, a third-party module)
                        // may be the thing that decides what this path serves. Dropping it would
                        // let the path fall through to `/*` or the static document root.
                        let label = if is_safe_nginx_directive_name(name) {
                            name.clone()
                        } else {
                            "unknown".to_owned()
                        };
                        security_blockers.push((*line, format!("{label} (untranslated)")));
                    }
                }
                doc.set_source_file(prev_file);
            }
            NginxItem::Block {
                file,
                line,
                name,
                body: nested,
                ..
            } => {
                let prev_file = doc.set_source_file(file.clone());
                let lower = name.to_ascii_lowercase();
                if lower == "location" {
                    // R6-MIG-4: NEVER merge nested `location` blocks (e.g. `location /app/ { location ~ \.php$ { fastcgi_pass ... } }`)
                    // into the parent location — that would widen FastCGI/proxy to every file under `/app/`!
                    security_blockers.push((*line, "nested location".to_owned()));
                } else if is_nginx_security_directive(&lower) {
                    security_blockers.push((*line, name.clone()));
                } else if lower == "if" {
                    if block_contains_security_controls(nested)
                        || block_contains_redirect_return(nested)
                    {
                        security_blockers.push((*line, "if (access control)".to_owned()));
                    } else {
                        // R8-MIG-1: an `if` body can rewrite, proxy or return; without evaluating
                        // the condition the importer cannot keep its meaning. There is no
                        // exception for "harmless-looking" bodies: `if (...) { return 204; }`
                        // answers the matching requests itself and stops, so dropping it turns
                        // them into real backend calls (for example a write the source refused).
                        security_blockers.push((*line, "if (untranslated)".to_owned()));
                    }
                } else if lower == "types" {
                    // MIME map only; never affects access.
                } else {
                    collect_location_directives(
                        nested,
                        raw_loc,
                        upstreams,
                        php_indicator,
                        doc,
                        proxy_targets,
                        fastcgi_pass,
                        try_files,
                        security_blockers,
                        has_deny_or_block_return,
                        loc_has_deny,
                        depth.saturating_add(1),
                    );
                }
                doc.set_source_file(prev_file);
            }
        }
    }
}

fn block_contains_redirect_return(items: &[NginxItem]) -> bool {
    items.iter().any(|item| match item {
        NginxItem::Directive { name, args, .. } => {
            name.eq_ignore_ascii_case("return")
                && args
                    .first()
                    .is_some_and(|c| matches!(c.as_str(), "301" | "302" | "303" | "307" | "308"))
        }
        NginxItem::Block { body, .. } => block_contains_redirect_return(body),
    })
}

fn block_contains_security_controls(items: &[NginxItem]) -> bool {
    for item in items {
        match item {
            NginxItem::Directive { name, args, .. } => {
                let lower = name.to_ascii_lowercase();
                if is_nginx_security_directive(&lower) {
                    return true;
                }
                if lower == "include"
                    && args
                        .first()
                        .is_some_and(|t| !is_safe_nginx_include_target(t))
                {
                    return true;
                }
                if lower == "return" && args.first().is_some_and(|c| is_blocking_return_code(c)) {
                    return true;
                }
            }
            NginxItem::Block { name, body, .. } => {
                let lower = name.to_ascii_lowercase();
                if is_nginx_security_directive(&lower) || block_contains_security_controls(body) {
                    return true;
                }
            }
        }
    }
    false
}

/// Resolves a named Nginx `upstream` pool (e.g. `upstream php { server unix:...; }` in the
/// official wordpress.org recipe, `R5-MIG-7`) or direct `fastcgi_pass` target.
fn resolve_nginx_fastcgi_target(
    raw: &str,
    upstreams: &NginxUpstreams,
    line: usize,
    doc: &mut MigratedDoc,
) -> String {
    let trimmed = raw.trim().trim_end_matches(';').trim_matches('"');
    let pool_key = trimmed.strip_prefix("fastcgi://").unwrap_or(trimmed);
    if let Some(pool) = upstreams.fastcgi.get(pool_key)
        && let Some(primary) = pool.first()
    {
        if pool.len() > 1 {
            doc.push_note(
                Some(line),
                "fastcgi_pass",
                format!(
                    "Nginx FastCGI upstream pool '{pool_key}' had {} backend(s); mapped primary target '{primary}'",
                    pool.len()
                ),
            );
        }
        return primary.clone();
    }
    normalize_fastcgi_target(trimmed)
}

fn resolve_nginx_proxy_target(
    raw: &str,
    raw_loc: &str,
    upstreams: &NginxUpstreams,
    line: usize,
    doc: &mut MigratedDoc,
) -> Vec<String> {
    let normalized = normalize_upstream_url(raw);
    let after_scheme = normalized
        .strip_prefix("https://")
        .or_else(|| normalized.strip_prefix("http://"))
        .unwrap_or(&normalized);

    // Check if `proxy_pass` includes a URI path suffix (Nginx prefix-stripping behavior, `MIG-6`).
    // R5-MIG-7: `location / { proxy_pass http://127.0.0.1:3000/; }` maps `/` -> `/` unchanged
    // and is NOT prefix-stripping!
    let (host_part, path_part) = match after_scheme.split_once('/') {
        Some((h, rest)) => (h, Some(format!("/{rest}"))),
        None => (after_scheme, None),
    };
    if let Some(suffix) = path_part.as_deref()
        && !suffix.is_empty()
        && !(raw_loc == "/" && suffix == "/")
    {
        // MIG-6: Prefix-stripping `proxy_pass http://backend/;` on a non-root location or `/v1/`
        // changes upstream path routing (and can break path-based auth/ACLs). Record as a security
        // downgrade so `miraserve import` does NOT exit 0 silently!
        doc.push_security_downgrade(
            Some(line),
            "proxy_pass",
            format!(
                "Nginx `proxy_pass {raw}` rewrites/strips the matched location prefix '{raw_loc}' with URI path '{suffix}'; MiraServe forwards the original request path unchanged — adjust upstream routing before cutover"
            ),
        );
    }

    // Resolve named Nginx `upstream <name> { ... }` pool if defined (`MIG-6`). Pool members are
    // collected without a scheme, so the scheme comes from THIS `proxy_pass`: an
    // `https://pool` must never be emitted as plaintext `http://member`.
    if let Some(pool) = upstreams.http.get(host_part) {
        let scheme = if normalized.starts_with("https://") {
            "https://"
        } else {
            "http://"
        };
        return pool
            .iter()
            .map(|member| {
                let bare = member
                    .strip_prefix("https://")
                    .or_else(|| member.strip_prefix("http://"))
                    .unwrap_or(member);
                format!("{scheme}{bare}")
            })
            .collect();
    }

    // Strip any trailing path for MiraServe `upstream` URL (which is scheme://host[:port]).
    let scheme = if normalized.starts_with("https://") {
        "https://"
    } else {
        "http://"
    };
    vec![format!("{scheme}{host_part}")]
}

fn normalize_nginx_root(raw: &str, line: usize, doc: &mut MigratedDoc) -> String {
    let trimmed = raw.trim();
    if trimmed.starts_with('/') {
        return trimmed.to_owned();
    }
    let bytes = trimmed.as_bytes();
    let is_windows_abs = bytes.len() >= 3
        && bytes.first().is_some_and(u8::is_ascii_alphabetic)
        && bytes.get(1) == Some(&b':')
        && matches!(bytes.get(2), Some(b'/' | b'\\'));
    if is_windows_abs {
        return trimmed.to_owned();
    }
    if trimmed.contains('$') {
        doc.push_security_downgrade(
            Some(line),
            "root",
            "Nginx `root` uses dynamic runtime variables; replace with a static absolute document root before deployment",
        );
        return "/var/www/html".to_owned();
    }
    if trimmed.split(['/', '\\']).any(|seg| seg == "..") {
        doc.push_security_downgrade(
            Some(line),
            "root",
            "Nginx `root` contains forbidden '..' parent traversal; replace with an absolute document root before deployment",
        );
        return "/var/www/html".to_owned();
    }
    let rel = trimmed.trim_start_matches("./").trim_start_matches('/');
    if rel.is_empty() || rel == "." {
        // R7-CFG-2: `root .;` in Nginx resolves to the Nginx `--prefix` directory itself (often
        // `/etc/nginx`), NOT `/usr/share/nginx/html`; fail closed so config files are never served.
        doc.push_security_downgrade(
            Some(line),
            "root",
            "Nginx `root .;` resolves to the Nginx build --prefix directory (often containing config files); replace with an explicit absolute document root before deployment",
        );
        return "/var/www/html".to_owned();
    }
    let resolved = format!("/usr/share/nginx/{rel}");
    doc.push_note(
        Some(line),
        "root",
        format!(
            "Resolved relative Nginx `root` against the standard Nginx prefix -> '{resolved}' (adjust if your Nginx build uses a different --prefix)"
        ),
    );
    resolved
}

/// Parses an Nginx `location` modifier and pattern, supporting BOTH separate-token forms
/// (`location ~ \.php$`) and attached forms without whitespace (`location ~^/(index)\.php$`,
/// `location =/health`, `location ^~/files/`, `location ~*\.php$`) (`R7-MIG-2`).
fn split_nginx_location_modifier(args: &[String]) -> (Option<&str>, &str) {
    match args {
        [m, p, ..] if matches!(m.as_str(), "=" | "~" | "~*" | "^~") => {
            (Some(m.as_str()), p.as_str())
        }
        [first, ..] => {
            for prefix in ["~*", "^~", "~", "="] {
                if let Some(rest) = first.strip_prefix(prefix)
                    && !rest.is_empty()
                {
                    return (Some(prefix), rest);
                }
            }
            (None, first.as_str())
        }
        [] => (None, "/"),
    }
}

/// Classifies Nginx response header mutation directives (`add_header`, `proxy_hide_header`,
/// `more_set_headers`, `more_clear_headers`) (`R7-MIG-7`, `R7-MIG-12`).
fn inspect_nginx_header_directive(
    lower: &str,
    args: &[String],
) -> Vec<(String, HeaderClassification)> {
    match lower {
        "add_header" => {
            let Some(hdr_name) = args.first() else {
                return Vec::new();
            };
            let hdr_val = args.get(1).map_or("", String::as_str);
            vec![(
                hdr_name.clone(),
                classify_untranslated_security_header(hdr_name, hdr_val),
            )]
        }
        "proxy_hide_header" => {
            let Some(hdr_name) = args.first() else {
                return Vec::new();
            };
            let removed = format!("-{hdr_name}");
            vec![(
                hdr_name.clone(),
                classify_untranslated_security_header(&removed, ""),
            )]
        }
        "more_set_headers" | "more_clear_headers" => {
            let is_clear = lower == "more_clear_headers";
            let mut out = Vec::new();
            let mut idx = 0_usize;
            while let Some(tok) = args.get(idx) {
                if matches!(tok.as_str(), "-s" | "-t") {
                    idx = idx.saturating_add(2);
                    continue;
                }
                if tok.starts_with('-') {
                    idx = idx.saturating_add(1);
                    continue;
                }
                let trimmed = tok.trim().trim_matches('"').trim_matches('\'');
                if !trimmed.is_empty() {
                    if is_clear {
                        let name = trimmed.split_once(':').map_or(trimmed, |(n, _)| n).trim();
                        let removed = format!("-{name}");
                        out.push((
                            name.to_owned(),
                            classify_untranslated_security_header(&removed, ""),
                        ));
                    } else if let Some((name, val)) = trimmed.split_once(':') {
                        out.push((
                            name.trim().to_owned(),
                            classify_untranslated_security_header(name.trim(), val.trim()),
                        ));
                    } else {
                        out.push((
                            trimmed.to_owned(),
                            classify_untranslated_security_header(trimmed, ""),
                        ));
                    }
                }
                idx = idx.saturating_add(1);
            }
            out
        }
        _ => Vec::new(),
    }
}

fn convert_nginx_try_files_token(tok: &str) -> String {
    tok.replace("$is_args$args", "?{query}")
        .replace("$is_args$query_string", "?{query}")
        .replace("$is_args", "?")
        .replace("$uri", "{path}")
        .replace("$args", "{query}")
        .replace("$query_string", "{query}")
}

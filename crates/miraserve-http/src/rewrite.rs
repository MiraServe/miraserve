//! Per-site rewrite rules (`rewrite { rule "<regex>" ... }`).
//!
//! Rules run once per request, before the site's guards and route matching; the first rule
//! whose pattern and conditions match is applied and its result is never fed back into the
//! rules, so they cannot loop. Patterns use the `regex` crate, which matches in time linear in
//! the input. Text captured from the request is percent-encoded before it is placed into a
//! target, so it cannot add path segments' special meaning (`..`), a query separator, or a host.

use http::header::HeaderName;
use http::{HeaderMap, Method, StatusCode};
use std::net::IpAddr;

use miraserve_config::{
    IpCidr, RewriteAction, RewriteConditionKind, RewriteRule, compile_rewrite_regex,
};
use miraserve_static::StaticServer;
use regex::{Captures, Regex};

use crate::HttpError;

#[derive(Debug)]
enum CompiledAction {
    Internal {
        to: String,
        keep_query: bool,
    },
    Redirect {
        to: String,
        status: StatusCode,
        keep_query: bool,
    },
    Deny(StatusCode),
    Pass,
}

#[derive(Debug)]
enum ConditionSubject {
    Host(Regex),
    Query(Regex),
    Header(HeaderName, Regex),
    ClientIp(IpCidr),
}

#[derive(Debug)]
struct CompiledCondition {
    subject: ConditionSubject,
    negate: bool,
}

#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)] // one flag per configured file test
struct CompiledRule {
    pattern: Regex,
    action: CompiledAction,
    if_not_file: bool,
    host: Option<String>,
    method: Option<Method>,
    query: Option<Regex>,
    header: Option<(HeaderName, Regex)>,
    if_not_regular_file: bool,
    if_file: bool,
    if_regular_file: bool,
    conditions: Vec<CompiledCondition>,
}

/// A site's compiled rewrite rules.
#[derive(Debug, Default)]
pub(crate) struct CompiledRewrites {
    rules: Vec<CompiledRule>,
    /// Some rule tests the visitor address: answers then depend on who asks.
    uses_client_ip: bool,
    /// Some rule can refuse a request (a `deny`, or a rule on the visitor address).
    may_refuse: bool,
    /// Some rule tests filesystem existence (`if-file`, `if-not-file`, `if-regular-file`,
    /// `if-not-regular-file`).
    uses_filesystem: bool,
}

/// Result of applying a site's rewrite rules to one request.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RewriteOutcome {
    /// No rule matched.
    Unchanged,
    /// Serve this path (and query) instead; percent-encoded, starts with `/`.
    Internal(String),
    /// Answer with a redirect.
    Redirect {
        status: StatusCode,
        location: String,
    },
    /// Refuse with this status.
    Deny(StatusCode),
}

impl CompiledRewrites {
    /// Whether some rule tests the visitor address.
    pub(crate) fn uses_client_ip(&self) -> bool {
        self.uses_client_ip
    }

    /// Whether some rule tests a request header (written as a condition or inline on the rule)
    /// or the client's address: what it decides then differs between visitors in a way a
    /// shared cache does not see (host and query are part of what a cache stores under).
    pub(crate) fn uses_request_headers(&self) -> bool {
        self.rules.iter().any(|rule| {
            rule.header.is_some()
                || rule.conditions.iter().any(|cond| {
                    matches!(
                        cond.subject,
                        ConditionSubject::Header(..) | ConditionSubject::ClientIp(_)
                    )
                })
        })
    }

    /// Whether some rule can refuse a request.
    pub(crate) fn may_refuse(&self) -> bool {
        self.may_refuse
    }

    /// Whether some rule probes the filesystem (`if-file`, `if-not-file`, `if-regular-file`,
    /// `if-not-regular-file`).
    pub(crate) const fn uses_filesystem(&self) -> bool {
        self.uses_filesystem
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn compile(rules: &[RewriteRule]) -> Result<Self, HttpError> {
        let regex = |pattern: &str| {
            compile_rewrite_regex(pattern).map_err(|err| {
                HttpError::Router(format!("invalid rewrite pattern '{pattern}': {err}"))
            })
        };
        let status = |code: u16| {
            StatusCode::from_u16(code)
                .map_err(|_| HttpError::Router(format!("invalid rewrite status {code}")))
        };
        let mut compiled = Vec::with_capacity(rules.len());
        for rule in rules {
            let action = match &rule.action {
                RewriteAction::Internal { to, keep_query } => CompiledAction::Internal {
                    to: to.clone(),
                    keep_query: *keep_query,
                },
                RewriteAction::Redirect {
                    to,
                    status: code,
                    keep_query,
                } => CompiledAction::Redirect {
                    to: to.clone(),
                    status: status(*code)?,
                    keep_query: *keep_query,
                },
                RewriteAction::Deny(code) => CompiledAction::Deny(status(*code)?),
                RewriteAction::Pass => CompiledAction::Pass,
            };
            let mut conditions = Vec::with_capacity(rule.conditions.len());
            for cond in &rule.conditions {
                let subject = match &cond.kind {
                    RewriteConditionKind::Host => ConditionSubject::Host(regex(&cond.pattern)?),
                    RewriteConditionKind::Query => ConditionSubject::Query(regex(&cond.pattern)?),
                    RewriteConditionKind::Header(name) => ConditionSubject::Header(
                        HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                            HttpError::Router(format!("invalid rewrite header name '{name}'"))
                        })?,
                        regex(&cond.pattern)?,
                    ),
                    RewriteConditionKind::ClientIp => {
                        ConditionSubject::ClientIp(IpCidr::parse(&cond.pattern).map_err(|_| {
                            HttpError::Router(format!(
                                "invalid rewrite client-ip '{}'",
                                cond.pattern
                            ))
                        })?)
                    }
                };
                conditions.push(CompiledCondition {
                    subject,
                    negate: cond.negate,
                });
            }
            let header = match &rule.header {
                Some((name, value)) => Some((
                    HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                        HttpError::Router(format!("invalid rewrite header name '{name}'"))
                    })?,
                    regex(value)?,
                )),
                None => None,
            };
            let method = match &rule.method {
                Some(m) => Some(
                    Method::from_bytes(m.as_bytes())
                        .map_err(|_| HttpError::Router(format!("invalid rewrite method '{m}'")))?,
                ),
                None => None,
            };
            compiled.push(CompiledRule {
                pattern: regex(&rule.pattern)?,
                action,
                if_not_file: rule.if_not_file,
                host: rule.host.clone(),
                method,
                query: rule.query.as_deref().map(regex).transpose()?,
                header,
                if_not_regular_file: rule.if_not_regular_file,
                if_file: rule.if_file,
                if_regular_file: rule.if_regular_file,
                conditions,
            });
        }
        let uses_client_ip = rules.iter().any(|rule| {
            rule.conditions
                .iter()
                .any(|cond| matches!(cond.kind, RewriteConditionKind::ClientIp))
        });
        let may_refuse = uses_client_ip
            || compiled
                .iter()
                .any(|rule| matches!(rule.action, CompiledAction::Deny(_)));
        let uses_filesystem = compiled.iter().any(|rule| {
            rule.if_file || rule.if_not_file || rule.if_regular_file || rule.if_not_regular_file
        });
        Ok(Self {
            rules: compiled,
            uses_client_ip,
            may_refuse,
            uses_filesystem,
        })
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Finds the first rule that matches a request whose normalised path is `canonical_path`.
    #[allow(clippy::too_many_arguments)]
    async fn first_match<'r, 'p>(
        &'r self,
        canonical_path: &'p str,
        query: &str,
        host: &str,
        method: &Method,
        headers: &HeaderMap,
        client_ip: Option<IpAddr>,
        site_root: Option<&StaticServer>,
    ) -> Option<(&'r CompiledRule, Captures<'p>, bool)> {
        // The two file lookups are the same for every rule of one request; ask at most once.
        let mut is_regular_file: Option<bool> = None;
        let mut path_exists: Option<bool> = None;
        for rule in &self.rules {
            if rule
                .host
                .as_deref()
                .is_some_and(|h| !h.eq_ignore_ascii_case(host))
                || rule.method.as_ref().is_some_and(|m| m != method)
                || rule.query.as_ref().is_some_and(|q| !q.is_match(query))
            {
                continue;
            }
            if let Some((name, value)) = &rule.header {
                let matches = headers
                    .get_all(name)
                    .iter()
                    .any(|v| value.is_match(&header_text(v)));
                if !matches {
                    continue;
                }
            }
            // The visitor's address is unknown (a trusted proxy did not name a client): a rule
            // that tests it cannot be decided. Its address tests are treated as holding; if the
            // rest of the rule matches, the caller refuses the request (a `deny` rule keeps its
            // own status) instead of guessing which branch applies.
            let ip_unknown = client_ip.is_none()
                && rule
                    .conditions
                    .iter()
                    .any(|cond| matches!(cond.subject, ConditionSubject::ClientIp(_)));
            let conditions_hold = rule.conditions.iter().all(|cond| {
                if ip_unknown && matches!(cond.subject, ConditionSubject::ClientIp(_)) {
                    return true;
                }
                let matched = match &cond.subject {
                    ConditionSubject::Host(pattern) => pattern.is_match(host),
                    ConditionSubject::Query(pattern) => pattern.is_match(query),
                    ConditionSubject::Header(name, pattern) => headers
                        .get_all(name)
                        .iter()
                        .any(|v| pattern.is_match(&header_text(v))),
                    ConditionSubject::ClientIp(cidr) => {
                        client_ip.is_some_and(|ip| cidr.contains(ip))
                    }
                };
                matched != cond.negate
            });
            if !conditions_hold {
                continue;
            }
            let Some(caps) = rule.pattern.captures(canonical_path) else {
                continue;
            };
            if rule.if_not_regular_file || rule.if_regular_file {
                let is_file = match (is_regular_file, site_root) {
                    (Some(known), _) => known,
                    (None, Some(root)) => root.regular_file_exists(canonical_path).await,
                    (None, None) => false,
                };
                is_regular_file = Some(is_file);
                if (rule.if_not_regular_file && is_file) || (rule.if_regular_file && !is_file) {
                    continue;
                }
            }
            if rule.if_not_file || rule.if_file {
                let exists = match (path_exists, site_root) {
                    (Some(known), _) => known,
                    (None, Some(root)) => root.path_exists(canonical_path).await,
                    (None, None) => false,
                };
                path_exists = Some(exists);
                if (rule.if_not_file && exists) || (rule.if_file && !exists) {
                    continue;
                }
            }
            return Some((rule, caps, ip_unknown));
        }
        None
    }

    /// Applies the first matching rule to a request whose normalised path is `canonical_path`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn apply(
        &self,
        canonical_path: &str,
        query: Option<&str>,
        host: &str,
        method: &Method,
        headers: &HeaderMap,
        client_ip: Option<IpAddr>,
        site_root: Option<&StaticServer>,
    ) -> RewriteOutcome {
        let query = query.unwrap_or("");
        let Some((rule, caps, ip_unknown)) = self
            .first_match(
                canonical_path,
                query,
                host,
                method,
                headers,
                client_ip,
                site_root,
            )
            .await
        else {
            return RewriteOutcome::Unchanged;
        };
        if ip_unknown && !matches!(rule.action, CompiledAction::Deny(_)) {
            return RewriteOutcome::Deny(StatusCode::FORBIDDEN);
        }
        match &rule.action {
            CompiledAction::Deny(status) => RewriteOutcome::Deny(*status),
            CompiledAction::Pass => RewriteOutcome::Unchanged,
            CompiledAction::Internal { to, keep_query } => {
                match expand_target(to, &caps, query, *keep_query) {
                    Some(target) => RewriteOutcome::Internal(target),
                    None => RewriteOutcome::Deny(StatusCode::URI_TOO_LONG),
                }
            }
            CompiledAction::Redirect {
                to,
                status,
                keep_query,
            } => match expand_target(to, &caps, query, *keep_query) {
                Some(location) if redirect_has_dot_segment(&location) => {
                    RewriteOutcome::Deny(StatusCode::BAD_REQUEST)
                }
                Some(location) => RewriteOutcome::Redirect {
                    status: *status,
                    location,
                },
                None => RewriteOutcome::Deny(StatusCode::URI_TOO_LONG),
            },
        }
    }

    /// Returns the status of the `deny` rule a **direct** request for `canonical_path` would
    /// hit, if any.
    ///
    /// Used on the result of an internal rewrite: a `deny` rule protects a path, not one of its
    /// names, so a public alias must not serve what a direct request is refused. Only `deny`
    /// counts here; if the first matching rule is anything else the request goes on unchanged
    /// (a second transformation is never applied).
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn denied_status(
        &self,
        canonical_path: &str,
        query: Option<&str>,
        host: &str,
        method: &Method,
        headers: &HeaderMap,
        client_ip: Option<IpAddr>,
        site_root: Option<&StaticServer>,
    ) -> Option<StatusCode> {
        let query = query.unwrap_or("");
        match self
            .first_match(
                canonical_path,
                query,
                host,
                method,
                headers,
                client_ip,
                site_root,
            )
            .await
        {
            Some((rule, _, ip_unknown)) => match &rule.action {
                CompiledAction::Deny(status) => Some(*status),
                _ if ip_unknown => Some(StatusCode::FORBIDDEN),
                _ => None,
            },
            None => None,
        }
    }
}

/// A header value as text for matching. A value with bytes that are not UTF-8 (allowed in HTTP
/// field values) is still a value that is present: its odd bytes become U+FFFD instead of the
/// whole value disappearing, so "header present" and negated conditions see it.
fn header_text(value: &http::HeaderValue) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(value.as_bytes())
}

/// A rewritten target is held to the limit a client's own request target has.
const MAX_REWRITE_TARGET_BYTES: usize = 8_192;

/// Substitutes `$0`..`$9` in `template` and optionally appends the request's query string.
/// Returns `None` when the result would be longer than [`MAX_REWRITE_TARGET_BYTES`] (a template
/// may repeat a capture, so the request-target limit alone does not bound the result).
///
/// Captured text is percent-encoded: in the path part everything except unreserved characters
/// and `/`, in the query part everything except unreserved characters. The literal parts of the
/// template are copied as written (config validation restricts them).
fn expand_target(
    template: &str,
    caps: &Captures<'_>,
    request_query: &str,
    keep_query: bool,
) -> Option<String> {
    // The fragment of the template (a redirect may have one) goes last, after the query the
    // request contributes: `/help#intro` with `?lang=lo` is `/help?lang=lo#intro`.
    let (template, fragment) = match template.split_once('#') {
        Some((main, fragment)) => (main, Some(fragment)),
        None => (template, None),
    };
    let mut out = String::with_capacity(
        template
            .len()
            .saturating_add(32)
            .min(MAX_REWRITE_TARGET_BYTES),
    );
    let mut in_query = false;
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if out.len() > MAX_REWRITE_TARGET_BYTES {
            return None;
        }
        if c == '$'
            && let Some(d) = chars.peek().and_then(|n| n.to_digit(10))
        {
            chars.next();
            let captured = usize::try_from(d)
                .ok()
                .and_then(|i| caps.get(i))
                .map_or("", |m| m.as_str());
            if captured.len() > MAX_REWRITE_TARGET_BYTES {
                return None;
            }
            encode_into(captured, in_query, &mut out);
            continue;
        }
        if c == '?' {
            in_query = true;
        }
        out.push(c);
    }
    if keep_query && !request_query.is_empty() {
        out.push(if in_query { '&' } else { '?' });
        // The request's own query is already valid URI text; keep it as sent, minus anything
        // that could end the query or the header value.
        for b in request_query.bytes() {
            if b.is_ascii_graphic() && !matches!(b, b'#' | b'<' | b'>' | b'"') {
                out.push(char::from(b));
            } else {
                push_percent(b, &mut out);
            }
        }
    }
    if let Some(fragment) = fragment {
        out.push('#');
        let mut chars = fragment.chars().peekable();
        while let Some(c) = chars.next() {
            if out.len() > MAX_REWRITE_TARGET_BYTES {
                return None;
            }
            if c == '$'
                && let Some(d) = chars.peek().and_then(|n| n.to_digit(10))
            {
                chars.next();
                let captured = usize::try_from(d)
                    .ok()
                    .and_then(|i| caps.get(i))
                    .map_or("", |m| m.as_str());
                if captured.len() > MAX_REWRITE_TARGET_BYTES {
                    return None;
                }
                encode_into(captured, true, &mut out);
                continue;
            }
            out.push(c);
        }
    }
    (out.len() <= MAX_REWRITE_TARGET_BYTES).then_some(out)
}

/// Whether the path of an expanded redirect target has a segment a browser treats as `.` or
/// `..` (also written `%2e`, and with matrix parameters such as `..;x`).
///
/// A capture is placed between literal text, so a capture of `..` between two `/` would make
/// the browser leave the prefix the rule wrote. Internal rewrites are checked by the request
/// target validator; a redirect is only a header value, so it is checked here.
fn redirect_has_dot_segment(location: &str) -> bool {
    let without_scheme = location
        .strip_prefix("https://")
        .or_else(|| location.strip_prefix("http://"));
    let path_and_rest = match without_scheme {
        Some(rest) => rest
            .find(['/', '?', '#'])
            .map_or("", |i| rest.get(i..).unwrap_or("")),
        None => location,
    };
    let path = path_and_rest
        .split(['?', '#'])
        .next()
        .unwrap_or(path_and_rest);
    path.split('/').any(|segment| {
        let mut decoded = Vec::with_capacity(segment.len());
        let bytes = segment.as_bytes();
        let mut i = 0_usize;
        while let Some(&b) = bytes.get(i) {
            if b == b'%'
                && bytes.get(i.saturating_add(1)) == Some(&b'2')
                && matches!(bytes.get(i.saturating_add(2)), Some(b'e' | b'E'))
            {
                decoded.push(b'.');
                i = i.saturating_add(3);
            } else {
                decoded.push(b);
                i = i.saturating_add(1);
            }
        }
        miraserve_security::is_dot_segment_bytes(&decoded)
    })
}

fn encode_into(text: &str, in_query: bool, out: &mut String) {
    for b in text.bytes() {
        let keep = b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'.' | b'_' | b'~')
            || (!in_query && b == b'/');
        if keep {
            out.push(char::from(b));
        } else {
            push_percent(b, out);
        }
    }
}

fn push_percent(b: u8, out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    out.push('%');
    out.push(char::from(*HEX.get(usize::from(b >> 4)).unwrap_or(&b'0')));
    out.push(char::from(*HEX.get(usize::from(b & 0x0F)).unwrap_or(&b'0')));
}

//! HTTP security headers middleware and authoritative `Alt-Svc` HTTP/3 advertisement.

use std::sync::OnceLock;

use http::header::{
    ALT_SVC, HeaderName, HeaderValue, LOCATION, REFERRER_POLICY, SERVER, STRICT_TRANSPORT_SECURITY,
    X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use http::{HeaderMap, Version};
use miraserve_config::SecurityHeadersPolicy;

const CROSS_ORIGIN_OPENER_POLICY: HeaderName =
    HeaderName::from_static("cross-origin-opener-policy");
const PERMISSIONS_POLICY: HeaderName = HeaderName::from_static("permissions-policy");

const SERVER_VALUE: HeaderValue = HeaderValue::from_static("MiraServe");
// No `includeSubDomains`: on shared hosting one customer's site must not pin HTTPS for every
// other name under the same parent domain. `strict` keeps it for operators who own the whole
// domain.
const HSTS_STANDARD: HeaderValue = HeaderValue::from_static("max-age=31536000");
const HSTS_STRICT: HeaderValue = HeaderValue::from_static("max-age=63072000; includeSubDomains");
const NOSNIFF: HeaderValue = HeaderValue::from_static("nosniff");
const REFERRER_POLICY_VAL: HeaderValue =
    HeaderValue::from_static("strict-origin-when-cross-origin");
const XFO_SAMEORIGIN: HeaderValue = HeaderValue::from_static("SAMEORIGIN");
const XFO_DENY: HeaderValue = HeaderValue::from_static("DENY");
const COOP_SAME_ORIGIN: HeaderValue = HeaderValue::from_static("same-origin");
const PERMISSIONS_POLICY_VAL: HeaderValue =
    HeaderValue::from_static("geolocation=(), microphone=(), camera=()");
const EMPTY_VALUE: HeaderValue = HeaderValue::from_static("");

static OFF_HEADERS: [(HeaderName, HeaderValue); 0] = [];
static STANDARD_HTTP_HEADERS: [(HeaderName, HeaderValue); 3] = [
    (X_CONTENT_TYPE_OPTIONS, NOSNIFF),
    (REFERRER_POLICY, REFERRER_POLICY_VAL),
    (X_FRAME_OPTIONS, XFO_SAMEORIGIN),
];
static STANDARD_HTTPS_HEADERS: [(HeaderName, HeaderValue); 4] = [
    (STRICT_TRANSPORT_SECURITY, HSTS_STANDARD),
    (X_CONTENT_TYPE_OPTIONS, NOSNIFF),
    (REFERRER_POLICY, REFERRER_POLICY_VAL),
    (X_FRAME_OPTIONS, XFO_SAMEORIGIN),
];
static STRICT_HTTP_HEADERS: [(HeaderName, HeaderValue); 5] = [
    (X_CONTENT_TYPE_OPTIONS, NOSNIFF),
    (REFERRER_POLICY, REFERRER_POLICY_VAL),
    (X_FRAME_OPTIONS, XFO_DENY),
    (CROSS_ORIGIN_OPENER_POLICY, COOP_SAME_ORIGIN),
    (PERMISSIONS_POLICY, PERMISSIONS_POLICY_VAL),
];
static STRICT_HTTPS_HEADERS: [(HeaderName, HeaderValue); 6] = [
    (STRICT_TRANSPORT_SECURITY, HSTS_STRICT),
    (X_CONTENT_TYPE_OPTIONS, NOSNIFF),
    (REFERRER_POLICY, REFERRER_POLICY_VAL),
    (X_FRAME_OPTIONS, XFO_DENY),
    (CROSS_ORIGIN_OPENER_POLICY, COOP_SAME_ORIGIN),
    (PERMISSIONS_POLICY, PERMISSIONS_POLICY_VAL),
];

fn policy_headers(
    policy: SecurityHeadersPolicy,
    is_https: bool,
) -> &'static [(HeaderName, HeaderValue)] {
    match (policy, is_https) {
        (SecurityHeadersPolicy::Off, _) => &OFF_HEADERS,
        (SecurityHeadersPolicy::Standard, false) => &STANDARD_HTTP_HEADERS,
        (SecurityHeadersPolicy::Standard, true) => &STANDARD_HTTPS_HEADERS,
        (SecurityHeadersPolicy::Strict, false) => &STRICT_HTTP_HEADERS,
        (SecurityHeadersPolicy::Strict, true) => &STRICT_HTTPS_HEADERS,
    }
}

const fn template_index(policy: SecurityHeadersPolicy, is_https: bool) -> usize {
    let base = match policy {
        SecurityHeadersPolicy::Off => 0,
        SecurityHeadersPolicy::Standard => 2,
        SecurityHeadersPolicy::Strict => 4,
    };
    base + if is_https { 1 } else { 0 }
}

/// Prebuilt `HeaderMap` templates for each `(SecurityHeadersPolicy, is_https)` pair when no
/// `Alt-Svc` header is emitted.
struct PolicyTemplates {
    /// `[server, ...policy_headers]` in exact wire order.
    empty: [HeaderMap; 6],
    /// `[location(""), server, ...policy_headers]` in exact wire order; callers replace
    /// `LOCATION` in place so slot 0 stays first without rehashing or growing.
    redirect: [HeaderMap; 6],
}

fn build_template(policy: SecurityHeadersPolicy, is_https: bool, with_location: bool) -> HeaderMap {
    let extra = policy_headers(policy, is_https);
    let mut map = HeaderMap::with_capacity(usize::from(with_location) + 1 + extra.len());
    if with_location {
        map.insert(LOCATION, EMPTY_VALUE);
    }
    map.insert(SERVER, SERVER_VALUE);
    for (name, value) in extra {
        map.insert(name.clone(), value.clone());
    }
    map
}

fn templates() -> &'static PolicyTemplates {
    static TEMPLATES: OnceLock<PolicyTemplates> = OnceLock::new();
    TEMPLATES.get_or_init(|| {
        let pairs = [
            (SecurityHeadersPolicy::Off, false),
            (SecurityHeadersPolicy::Off, true),
            (SecurityHeadersPolicy::Standard, false),
            (SecurityHeadersPolicy::Standard, true),
            (SecurityHeadersPolicy::Strict, false),
            (SecurityHeadersPolicy::Strict, true),
        ];
        PolicyTemplates {
            empty: pairs.map(|(p, https)| build_template(p, https, false)),
            redirect: pairs.map(|(p, https)| build_template(p, https, true)),
        }
    })
}

/// Builds the authoritative `Alt-Svc` header value advertised for an HTTP/3 UDP listener port.
#[must_use]
pub(crate) fn alt_svc_header_value(port: u16) -> Option<HeaderValue> {
    HeaderValue::from_str(&format!("h3=\":{port}\"; ma=86400")).ok()
}

/// Worst-case number of distinct response header keys [`apply_security_headers`] can add
/// (`server`, optional `alt-svc`, and the HTTPS security headers of `policy`).
///
/// Includes `alt-svc` unconditionally so dynamically enabling HTTP/3 advertisement via
/// `HttpEngine::set_alt_svc_h3_port` never forces a `HeaderMap` regrow; for all default policies
/// (`Off`, `Standard`, `Strict`), `+1` stays in the same power-of-two `HeaderMap` bucket on
/// standard 200 and 304 static responses.
#[must_use]
pub(crate) const fn security_header_slot_budget(policy: SecurityHeadersPolicy) -> usize {
    let policy_count = match policy {
        SecurityHeadersPolicy::Off => 0,
        SecurityHeadersPolicy::Standard => 4,
        SecurityHeadersPolicy::Strict => 6,
    };
    2 + policy_count
}

/// Builds the complete `HeaderMap` for a MiraServe redirect response (`location`, `server`,
/// optional `alt-svc`, and configured security headers) in the exact same wire order as
/// inserting `LOCATION` followed by [`apply_security_headers`].
#[must_use]
pub(crate) fn redirect_headers(
    location: HeaderValue,
    policy: SecurityHeadersPolicy,
    is_https: bool,
    alt_svc: Option<&HeaderValue>,
    version: Version,
) -> HeaderMap {
    let emit_alt_svc = if is_https && version != Version::HTTP_3 {
        alt_svc
    } else {
        None
    };
    if emit_alt_svc.is_none()
        && let Some(template) = templates().redirect.get(template_index(policy, is_https))
    {
        let mut map = template.clone();
        map.insert(LOCATION, location);
        return map;
    }
    let extra = policy_headers(policy, is_https);
    let mut map = HeaderMap::with_capacity(2 + usize::from(emit_alt_svc.is_some()) + extra.len());
    map.insert(LOCATION, location);
    map.insert(SERVER, SERVER_VALUE);
    if let Some(alt) = emit_alt_svc {
        map.insert(ALT_SVC, alt.clone());
    }
    for (name, value) in extra {
        map.insert(name.clone(), value.clone());
    }
    map
}

/// Applies MiraServe's configured security headers and authoritative `Alt-Svc` HTTP/3 header.
///
/// - Always strips any upstream/plugin `Alt-Svc` before emitting MiraServe's own H3 port.
/// - Under [`SecurityHeadersPolicy::Strict`] or when `force_overwrite` is `true` (e.g. for
///   sandboxed WASM plugins), unconditionally overwrites operator-managed security headers
///   so untrusted plugins or weakened upstreams cannot downgrade protection.
pub(crate) fn apply_security_headers(
    headers: &mut HeaderMap,
    policy: SecurityHeadersPolicy,
    is_https: bool,
    alt_svc: Option<&HeaderValue>,
    version: Version,
    force_overwrite: bool,
) {
    let emit_alt_svc = if is_https && version != Version::HTTP_3 {
        alt_svc
    } else {
        None
    };
    if headers.is_empty()
        && emit_alt_svc.is_none()
        && let Some(template) = templates().empty.get(template_index(policy, is_https))
    {
        *headers = template.clone();
        return;
    }

    let extra = policy_headers(policy, is_https);
    let max_new = 1 + usize::from(emit_alt_svc.is_some()) + extra.len();
    if headers.capacity() < headers.keys_len().saturating_add(max_new) {
        let _ = headers.try_reserve(max_new);
    }

    headers.entry(SERVER).or_insert(SERVER_VALUE);

    // Unconditionally strip upstream/plugin Alt-Svc before advertising MiraServe's H3 port.
    headers.remove(ALT_SVC);
    // Plain-HTTP responses must never carry `Strict-Transport-Security` (RFC 6797 §7.2).
    if !is_https {
        headers.remove(STRICT_TRANSPORT_SECURITY);
    }
    if let Some(val) = emit_alt_svc {
        headers.insert(ALT_SVC, val.clone());
    }

    let overwrite = force_overwrite || policy == SecurityHeadersPolicy::Strict;
    for (name, value) in extra {
        set_header(headers, name.clone(), value.clone(), overwrite);
    }
}

fn set_header(headers: &mut HeaderMap, name: HeaderName, value: HeaderValue, overwrite: bool) {
    if overwrite {
        headers.insert(name, value);
    } else {
        headers.entry(name).or_insert(value);
    }
}

#[cfg(test)]
mod tests {
    use super::{alt_svc_header_value, apply_security_headers, redirect_headers};
    use http::header::{ALT_SVC, HeaderName, HeaderValue, LOCATION, SERVER};
    use http::{HeaderMap, Version};
    use miraserve_config::SecurityHeadersPolicy;

    fn ordered_pairs(map: &HeaderMap) -> Vec<(&str, &str)> {
        map.iter()
            .map(|(k, v)| (k.as_str(), v.to_str().unwrap_or("")))
            .collect()
    }

    #[test]
    fn redirect_headers_match_insert_plus_apply_in_exact_order() {
        let alt = alt_svc_header_value(8443);
        for policy in [
            SecurityHeadersPolicy::Off,
            SecurityHeadersPolicy::Standard,
            SecurityHeadersPolicy::Strict,
        ] {
            for is_https in [false, true] {
                for alt_opt in [None, alt.as_ref()] {
                    for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
                        let loc = HeaderValue::from_static("https://shop.example/next");
                        let fast =
                            redirect_headers(loc.clone(), policy, is_https, alt_opt, version);
                        let mut slow = HeaderMap::new();
                        slow.insert(LOCATION, loc);
                        apply_security_headers(
                            &mut slow, policy, is_https, alt_opt, version, false,
                        );
                        assert_eq!(
                            ordered_pairs(&fast),
                            ordered_pairs(&slow),
                            "policy={policy:?} is_https={is_https} alt={alt_opt:?} version={version:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn apply_security_headers_preserves_existing_order_and_strips_upstream_alt_svc() {
        let mut map = HeaderMap::new();
        map.insert(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("custom"),
        );
        map.insert(ALT_SVC, HeaderValue::from_static("h3=\":9999\""));
        map.insert(SERVER, HeaderValue::from_static("Upstream"));
        let alt = alt_svc_header_value(443);

        apply_security_headers(
            &mut map,
            SecurityHeadersPolicy::Standard,
            true,
            alt.as_ref(),
            Version::HTTP_2,
            false,
        );
        assert_eq!(
            ordered_pairs(&map),
            vec![
                ("x-content-type-options", "custom"),
                ("server", "Upstream"),
                ("alt-svc", "h3=\":443\"; ma=86400"),
                ("strict-transport-security", "max-age=31536000"),
                ("referrer-policy", "strict-origin-when-cross-origin"),
                ("x-frame-options", "SAMEORIGIN"),
            ]
        );
    }
}

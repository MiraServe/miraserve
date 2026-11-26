//! Deterministic edge WAF and site hardening presets (`wordpress-hardened`,
//! `static-strict`, `api-gateway`) enforcing Threat Model T5.

use std::net::IpAddr;
use std::time::Duration;

use http::{HeaderMap, Method, StatusCode};
use miraserve_config::SitePreset;

use crate::gcra::GcraRateLimiter;

/// Outcome of evaluating a site's deterministic security preset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresetVerdict {
    /// Request permitted to proceed to route dispatch.
    Allow,
    /// Request blocked by a deterministic security rule.
    Block {
        /// HTTP status code (`403`, `404`, `405`, `400`).
        status: StatusCode,
        /// Stable rule identifier for audit logs.
        rule: &'static str,
        /// Human-readable reason.
        reason: &'static str,
    },
    /// Request throttled by a preset-specific rate limiter (e.g., `wp-login.php`).
    RateLimited {
        /// Stable rule identifier.
        rule: &'static str,
        /// Recommended `Retry-After` seconds.
        retry_after_secs: u64,
    },
}

/// Compiled runtime guard for a [`SitePreset`].
#[derive(Debug)]
pub struct SitePresetGuard {
    preset: SitePreset,
    /// Dedicated GCRA brute-force limiter for `wp-login.php` under `wordpress-hardened`.
    wp_login_limiter: Option<GcraRateLimiter>,
}

impl SitePresetGuard {
    /// Compiles a runtime guard for `preset`.
    #[must_use]
    pub fn new(preset: SitePreset) -> Self {
        let wp_login_limiter = match preset {
            // Threat Model T5: strict brute-force protection on wp-login.php (10 req/min, burst 5).
            SitePreset::WordpressHardened => {
                Some(GcraRateLimiter::per_ip(10, Duration::from_secs(60), 5))
            }
            SitePreset::StaticStrict | SitePreset::ApiGateway => None,
        };
        Self {
            preset,
            wp_login_limiter,
        }
    }

    /// Evaluates an incoming request against the active site preset.
    #[must_use]
    pub fn evaluate(
        &self,
        method: &Method,
        raw_path: &str,
        headers: &HeaderMap,
        client_ip: Option<IpAddr>,
    ) -> PresetVerdict {
        self.evaluate_inner(method, raw_path, headers, client_ip, true)
    }

    /// [`Self::evaluate`] for another path of a request that has been evaluated already (a
    /// file served in the place of the one asked for): the same rules, but nothing is counted
    /// against a rate limit a second time.
    #[must_use]
    pub fn evaluate_uncounted(
        &self,
        method: &Method,
        raw_path: &str,
        headers: &HeaderMap,
        client_ip: Option<IpAddr>,
    ) -> PresetVerdict {
        self.evaluate_inner(method, raw_path, headers, client_ip, false)
    }

    fn evaluate_inner(
        &self,
        method: &Method,
        raw_path: &str,
        headers: &HeaderMap,
        client_ip: Option<IpAddr>,
        count: bool,
    ) -> PresetVerdict {
        match self.preset {
            SitePreset::WordpressHardened => {
                self.eval_wordpress_hardened(raw_path, headers, client_ip, count)
            }
            SitePreset::StaticStrict => eval_static_strict(method, raw_path),
            SitePreset::ApiGateway => eval_api_gateway(raw_path),
        }
    }

    fn eval_wordpress_hardened(
        &self,
        raw_path: &str,
        headers: &HeaderMap,
        client_ip: Option<IpAddr>,
        count: bool,
    ) -> PresetVerdict {
        let decoded = decode_slash_lower(raw_path);
        // 1. Block traversal / dot-segments / NUL bytes anywhere before collapsing.
        if has_traversal_or_nul(&decoded) {
            return PresetVerdict::Block {
                status: StatusCode::BAD_REQUEST,
                rule: "WP_PATH_TRAVERSAL",
                reason: "path traversal rejected",
            };
        }
        let segments = canonical_segments(&decoded);

        // 2. Deny dotfiles (.env, .git, .htaccess, .DS_Store, /.well-known/.env, etc.).
        if has_dotfile_segment(&segments) {
            return PresetVerdict::Block {
                status: StatusCode::NOT_FOUND,
                rule: "WP_DENY_DOTFILES",
                reason: "dotfile access denied",
            };
        }

        // 3. Block xmlrpc.php on ANY segment (blocking /xmlrpc.php, /xmlrpc.php/, /xmlrpc.php/a.php).
        if segments.contains(&"xmlrpc.php") {
            return PresetVerdict::Block {
                status: StatusCode::FORBIDDEN,
                rule: "WP_BLOCK_XMLRPC",
                reason: "xmlrpc.php is blocked by wordpress-hardened preset",
            };
        }

        // 4. Block sensitive WordPress config/backup/disclosure files on ANY path segment
        //    (defeating trailing-slash and PATH_INFO bypasses such as /wp-config.php/ or /dump.sql/).
        if segments.iter().any(|seg| is_sensitive_wp_segment(seg)) {
            return PresetVerdict::Block {
                status: StatusCode::NOT_FOUND,
                rule: "WP_BLOCK_SENSITIVE_FILES",
                reason: "sensitive WordPress file blocked",
            };
        }

        // 5. Block PHP execution inside writable upload & includes directories (webshell defense),
        //    even with duplicate slashes (//wp-content/uploads/...), subdirectory WordPress installs
        //    (/blog/wp-content/uploads/...), or trailing PATH_INFO.
        let in_uploads_or_includes = segments
            .windows(2)
            .any(|pair| pair == ["wp-content", "uploads"])
            || segments.contains(&"wp-includes");
        if in_uploads_or_includes && segments.iter().any(|seg| is_php_script(seg)) {
            return PresetVerdict::Block {
                status: StatusCode::FORBIDDEN,
                rule: "WP_BLOCK_UPLOADS_PHP",
                reason: "PHP execution in uploads/includes is forbidden",
            };
        }

        // 6. Apply GCRA brute-force rate limit to wp-login.php on ANY segment
        //    (blocking /wp-login.php/, /wp-login.php/a.php, //wp-login.php).
        if count
            && segments.contains(&"wp-login.php")
            && let Some(limiter) = &self.wp_login_limiter
        {
            let decision = limiter.check_request(client_ip, headers, None);
            if !decision.allowed {
                return PresetVerdict::RateLimited {
                    rule: "WP_LOGIN_RATE_LIMIT",
                    retry_after_secs: decision.retry_after_secs,
                };
            }
        }

        PresetVerdict::Allow
    }
}

fn eval_static_strict(method: &Method, raw_path: &str) -> PresetVerdict {
    if !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return PresetVerdict::Block {
            status: StatusCode::METHOD_NOT_ALLOWED,
            rule: "STATIC_READ_ONLY_METHODS",
            reason: "only GET, HEAD, and OPTIONS are allowed by static-strict preset",
        };
    }

    let decoded = decode_slash_lower(raw_path);
    if has_traversal_or_nul(&decoded) {
        return PresetVerdict::Block {
            status: StatusCode::BAD_REQUEST,
            rule: "STATIC_PATH_TRAVERSAL",
            reason: "path traversal rejected",
        };
    }
    let segments = canonical_segments(&decoded);
    if has_dotfile_segment(&segments) {
        return PresetVerdict::Block {
            status: StatusCode::NOT_FOUND,
            rule: "STATIC_DENY_DOTFILES",
            reason: "dotfile access denied",
        };
    }
    if segments.iter().any(|seg| has_backup_extension(seg)) {
        return PresetVerdict::Block {
            status: StatusCode::NOT_FOUND,
            rule: "STATIC_BLOCK_BACKUPS",
            reason: "backup file access denied",
        };
    }

    PresetVerdict::Allow
}

fn eval_api_gateway(raw_path: &str) -> PresetVerdict {
    let decoded = decode_slash_lower(raw_path);
    if has_traversal_or_nul(&decoded) {
        return PresetVerdict::Block {
            status: StatusCode::BAD_REQUEST,
            rule: "API_PATH_TRAVERSAL",
            reason: "suspicious path traversal rejected",
        };
    }
    let segments = canonical_segments(&decoded);
    // Allow ONLY root `.well-known` segment; block `/.well-known/.env` or any other dotfile!
    if has_dotfile_segment(&segments) {
        return PresetVerdict::Block {
            status: StatusCode::NOT_FOUND,
            rule: "API_DENY_DOTFILES",
            reason: "dotfile access denied",
        };
    }
    PresetVerdict::Allow
}

fn decode_slash_lower(raw_path: &str) -> String {
    let decoded = percent_decode_lossy(raw_path);
    decoded.replace('\\', "/").to_ascii_lowercase()
}

fn canonical_segments(decoded: &str) -> Vec<&str> {
    decoded.split('/').filter(|seg| !seg.is_empty()).collect()
}

fn percent_decode_lossy(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0_usize;
    while let Some(&b) = bytes.get(i) {
        if b == b'%'
            && let Some(hi) = bytes.get(i.saturating_add(1)).and_then(|&x| hex(x))
            && let Some(lo) = bytes.get(i.saturating_add(2)).and_then(|&x| hex(x))
        {
            out.push((hi << 4) | lo);
            i = i.saturating_add(3);
            continue;
        }
        out.push(b);
        i = i.saturating_add(1);
    }
    String::from_utf8_lossy(&out).into_owned()
}

const fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn has_traversal_or_nul(decoded: &str) -> bool {
    decoded.contains('\0') || decoded.split('/').any(|seg| seg == ".." || seg == ".")
}

/// Denies any dotfile segment except an exact root `/.well-known/...` prefix segment.
fn has_dotfile_segment(segments: &[&str]) -> bool {
    segments.iter().enumerate().any(|(idx, seg)| {
        if !seg.starts_with('.') {
            return false;
        }
        !(idx == 0 && *seg == ".well-known")
    })
}

fn is_sensitive_wp_segment(seg: &str) -> bool {
    seg.starts_with("wp-config.php")
        || matches!(
            seg,
            "readme.html" | "license.txt" | "wp-config-sample.php" | "debug.log"
        )
        || has_backup_extension(seg)
}

fn is_php_script(segment: &str) -> bool {
    std::path::Path::new(segment)
        .extension()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|ext| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "php" | "phtml" | "phar" | "php5" | "php7" | "php8"
            )
        })
}

fn has_backup_extension(segment: &str) -> bool {
    segment.ends_with('~')
        || std::path::Path::new(segment)
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|ext| {
                matches!(
                    ext.to_ascii_lowercase().as_str(),
                    "bak" | "old" | "orig" | "swp" | "sql"
                )
            })
}

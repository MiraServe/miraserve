#![forbid(unsafe_code)]
//! Edge security defenses for MiraServe:
//! - Strict RFC 9110 / RFC 9112 anti-smuggling request validator ([`validate_request_framing`])
//! - Bounded-memory sharded GCRA rate limiter ([`GcraRateLimiter`])
//! - HTTP/2 & HTTP/3 flood guard and Slowloris minimum body-rate wrapper ([`ConnectionFloodGuard`], [`BoundedBody`])
//! - Deterministic site hardening presets (`wordpress-hardened`, `static-strict`, `api-gateway`)

pub mod flood;
pub mod gcra;
pub mod presets;
pub mod smuggling;

pub use flood::{BodyGuardError, BoundedBody, ConnectionFloodGuard};
pub use gcra::{GcraRateLimiter, RateLimitDecision};
pub use presets::{PresetVerdict, SitePresetGuard};
pub use smuggling::{
    SmugglingRejection, contains_overlong_or_surrogate_utf8, is_dot_segment_bytes,
    is_valid_rfc3986_host_port, validate_host_consistency, validate_request_framing,
    validate_request_target,
};

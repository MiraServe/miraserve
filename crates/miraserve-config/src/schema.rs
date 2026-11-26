//! Strongly-typed MiraServe configuration model.
//!
//! All types in this module represent validated, normalized configuration values
//! ready to be shared lock-free across worker threads via [`crate::ConfigStore`].

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::Serialize;

use crate::units::{
    BindAddr, ByteSize, IpCidr, Protocol, serialize_duration_ms, serialize_opt_duration_ms,
};

/// Root MiraServe configuration document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Config {
    /// Global server listeners, TLS defaults, sandboxing, timeouts, and protocol limits.
    pub server: ServerConfig,
    /// Virtual host / site definitions.
    pub sites: Vec<SiteConfig>,
}

/// Global `server { ... }` block.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ServerConfig {
    /// Network listeners (`listen ":443" ...`).
    pub listeners: Vec<ListenConfig>,
    /// Global TLS & ACME configuration.
    pub tls: TlsConfig,
    /// OS process sandboxing and privilege drop configuration.
    pub sandbox: SandboxConfig,
    /// Connection & request timeouts (Threat Model T4).
    pub timeouts: TimeoutsConfig,
    /// Protocol-level anti-DoS limits (Threat Model T4).
    pub limits: LimitsConfig,
    /// Observability: Prometheus metrics, OTLP export, and secret-redacted logging.
    pub telemetry: TelemetryConfig,
    /// Explicit opt-in exceptions permitting HTTP document roots under default-denied trees
    /// (`/var/lib`, `/var/log`, `/run`, Section 5). Cannot override unconditionally forbidden
    /// OS or MiraServe state directories (`/etc`, `/var/lib/miraserve`, `/run/secrets`, etc.).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_docroots: Vec<String>,
    /// Server-owned directory an external ACME client (certbot, lego) writes HTTP-01 tokens
    /// into (`acme-webroot "/path"`): MiraServe answers `/.well-known/acme-challenge/<token>`
    /// from it for every configured host, before sites and routes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acme_webroot: Option<String>,
    /// How connections are run (`workers "shared"`, `workers "auto"` or `workers <N>`).
    #[serde(default, skip_serializing_if = "Workers::is_shared")]
    pub workers: Workers,
}

/// How HTTPS connections over TCP are run (`workers` in `server`).
///
/// `Shared` is one multi-thread runtime whose threads pass connections between them. The
/// other two run one event loop per worker thread, each with its own listening socket
/// (`SO_REUSEPORT`); a connection stays on the thread that accepted it, so one core does not
/// wake another for it. That is Linux only; other systems use `Shared` whatever is set. A
/// change takes effect when the server is restarted, not on reload.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Workers {
    /// One shared runtime (the default).
    #[default]
    Shared,
    /// One event loop per available core.
    Auto,
    /// This many event loops (1 to 256).
    Count(u32),
}

impl Workers {
    /// Whether this is the shared runtime.
    #[must_use]
    pub const fn is_shared(&self) -> bool {
        matches!(self, Self::Shared)
    }
}

/// Single `listen` directive inside `server`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListenConfig {
    /// IP/port bind address (`:443`, `0.0.0.0:443`, `[::]:443`).
    pub addr: BindAddr,
    /// Enabled HTTP protocol versions (e.g. `[H3, H2, H1]`).
    pub protocols: Vec<Protocol>,
    /// If `true`, redirect incoming plaintext HTTP requests to HTTPS (`308`).
    pub redirect_https: bool,
}

/// Minimum supported TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum TlsVersion {
    /// TLS 1.3 (recommended and default).
    #[serde(rename = "1.3")]
    V1_3,
    /// TLS 1.2 (legacy compatibility only).
    #[serde(rename = "1.2")]
    V1_2,
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V1_3 => f.write_str("1.3"),
            Self::V1_2 => f.write_str("1.2"),
        }
    }
}

/// TLS private key isolation architecture (Threat Model T2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyIsolation {
    /// TLS keys held in-process (cross-platform default).
    InProcess,
    /// Split-privilege `miraserve-keyd` signing daemon outside worker address space.
    SplitDaemon,
}

/// Global `server.tls { ... }` configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsConfig {
    /// Minimum TLS protocol version (defaults to TLS 1.3).
    pub min_version: TlsVersion,
    /// Prioritize post-quantum hybrid key exchange (`X25519MLKEM768` / RFC 10024).
    pub pqc_hybrid: bool,
    /// Private key isolation mode (`in-process` or `split-daemon`).
    pub key_isolation: KeyIsolation,
    /// Optional IPC socket path for `split-daemon` mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyd_socket: Option<String>,
    /// Enable Encrypted Client Hello (ECH / RFC 9849) support.
    pub ech: bool,
    /// Public outer SNI name advertised in RFC 9849 `ECHConfig` records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ech_public_name: Option<String>,
    /// Automatic ECH HPKE key rotation cadence (defaults to 1 hour).
    #[serde(
        rename = "ech_rotate_interval_ms",
        serialize_with = "serialize_duration_ms"
    )]
    pub ech_rotate_interval: Duration,
    /// Optional static TLS certificate path (PEM).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert: Option<String>,
    /// Optional static TLS private key path (PEM).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Optional trusted CA certificate bundle (PEM) for verifying mTLS client certificates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ca: Option<String>,
    /// Automatic ACME v2 certificate management configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acme: Option<AcmeConfig>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            min_version: TlsVersion::V1_3,
            pqc_hybrid: true,
            key_isolation: KeyIsolation::InProcess,
            keyd_socket: None,
            ech: false,
            ech_public_name: None,
            ech_rotate_interval: Duration::from_hours(1),
            cert: None,
            key: None,
            client_ca: None,
            acme: None,
        }
    }
}

/// ACME validation challenge method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AcmeChallenge {
    /// TLS-ALPN-01 (RFC 8737).
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
    /// HTTP-01 (RFC 8555).
    #[serde(rename = "http-01")]
    Http01,
    /// DNS-01 (RFC 8555).
    #[serde(rename = "dns-01")]
    Dns01,
}

/// `server.tls.acme { ... }` configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AcmeConfig {
    /// Contact email address for ACME account registration.
    pub email: String,
    /// ACME domain validation challenge type.
    pub challenge: AcmeChallenge,
    /// Prefer short-lived leaf certificates (6-day profile).
    pub short_lived: bool,
    /// Enable RFC 9773 ACME Renewal Information (ARI).
    pub ari: bool,
    /// Optional custom HTTPS ACME directory URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub directory: Option<String>,
}

/// Linux seccomp-bpf syscall filtering mode (dangerous-syscall denylist + set-ID mode-bit filter).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SeccompMode {
    /// Strict dangerous-syscall denylist (blocks `execve`, `ptrace`, `mount`, `bpf`, `io_uring`,
    /// `keyctl`, etc.) plus the in-process `S_ISUID` / `S_ISGID` mode-bit filter.
    Strict,
    /// Standard dangerous-syscall denylist (including `io_uring`, blocked as part of the set-ID
    /// policy) for broader plugin compatibility plus the in-process `S_ISUID` / `S_ISGID`
    /// mode-bit filter.
    Standard,
    /// Disable seccomp-bpf filtering completely (emits warning `W003`; neither the syscall
    /// denylist nor the in-process `S_ISUID` / `S_ISGID` filter is installed).
    Off,
}

/// `server.sandbox { ... }` OS confinement configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SandboxConfig {
    /// Unprivileged OS user to drop privileges to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Optional unprivileged OS group to drop privileges to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Enable Linux Landlock LSM filesystem confinement.
    pub landlock: bool,
    /// Linux seccomp-bpf profile.
    pub seccomp: SeccompMode,
    /// Directory trees the worker may READ under Landlock in addition to the paths derived from
    /// the config (`read-tree "/home" "/var/www"`).
    ///
    /// Landlock rules cannot be extended after startup, so a site added by a reload whose
    /// document root is not already inside a granted tree is unreadable until a restart. A
    /// hosting panel that adds sites continuously lists the parent of all its document roots
    /// here once. Ordinary Unix permissions still decide which files the worker user can open.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_trees: Vec<String>,
    /// Directory trees whose Unix sockets the worker may CONNECT to under Landlock
    /// (`socket-tree "/run/php"`), for FastCGI pools created after startup.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub socket_trees: Vec<String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            user: None,
            group: None,
            landlock: true,
            seccomp: SeccompMode::Strict,
            read_trees: Vec::new(),
            socket_trees: Vec::new(),
        }
    }
}

/// Mandatory server timeouts defending against Slowloris and idle connection exhaustion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TimeoutsConfig {
    /// Maximum duration for completing a TLS handshake.
    #[serde(rename = "tls_handshake_ms", serialize_with = "serialize_duration_ms")]
    pub tls_handshake: Duration,
    /// Maximum duration for receiving request headers.
    #[serde(rename = "header_read_ms", serialize_with = "serialize_duration_ms")]
    pub header_read: Duration,
    /// Maximum idle keep-alive duration between requests.
    #[serde(rename = "idle_keepalive_ms", serialize_with = "serialize_duration_ms")]
    pub idle_keepalive: Duration,
    /// Maximum graceful drain duration during reload/shutdown.
    #[serde(rename = "graceful_drain_ms", serialize_with = "serialize_duration_ms")]
    pub graceful_drain: Duration,
    /// Maximum idle gap permitted between request body chunks before Slowloris abort (`R3-HTTP-1`).
    #[serde(
        rename = "body_idle_timeout_ms",
        serialize_with = "serialize_duration_ms"
    )]
    pub body_idle_timeout: Duration,
    /// Absolute maximum wall-clock duration permitted to stream a request body from first poll
    /// (always enforced even when `min_body_rate_bps == 0`, `R5-HTTP-2`).
    #[serde(
        rename = "max_body_duration_ms",
        serialize_with = "serialize_duration_ms"
    )]
    pub max_body_duration: Duration,
    /// Minimum request body transfer rate in bytes/sec (`0` disables rate enforcement while keeping
    /// `body-idle-timeout` and `max-body-duration` active, `R3-HTTP-1` / `R4-HTTP-1` / `R5-HTTP-2`).
    pub min_body_rate_bps: u64,
    /// Dedicated TCP/TLS connect timeout for reverse-proxy and MCP upstreams (`R2-PRX-2`).
    #[serde(
        rename = "upstream_connect_ms",
        serialize_with = "serialize_duration_ms"
    )]
    pub upstream_connect: Duration,
    /// Dedicated timeout awaiting upstream response headers after request upload completes (`R2-PRX-2`).
    #[serde(
        rename = "upstream_response_ms",
        serialize_with = "serialize_duration_ms"
    )]
    pub upstream_response: Duration,
    /// Dedicated maximum idle gap between upstream response body chunks before abort (`DOS-7`).
    #[serde(
        rename = "upstream_body_idle_ms",
        serialize_with = "serialize_duration_ms"
    )]
    pub upstream_body_idle: Duration,
    /// Maximum backpressure stall duration when writing responses to a slow client (`R7-DOS-1`).
    #[serde(
        rename = "response_write_idle_ms",
        serialize_with = "serialize_duration_ms"
    )]
    pub response_write_idle: Duration,
    /// Minimum client response send rate in bytes/sec enforced while socket writes are
    /// back-pressured (`0` disables rate enforcement while keeping `response-write-idle` active,
    /// `R7-DOS-1`).
    pub min_response_rate_bps: u64,
}

impl Default for TimeoutsConfig {
    fn default() -> Self {
        Self {
            tls_handshake: Duration::from_secs(10),
            header_read: Duration::from_secs(10),
            idle_keepalive: Duration::from_secs(60),
            graceful_drain: Duration::from_secs(30),
            body_idle_timeout: Duration::from_secs(30),
            max_body_duration: Duration::from_hours(1),
            min_body_rate_bps: 1_024,
            upstream_connect: Duration::from_secs(10),
            upstream_response: Duration::from_secs(60),
            upstream_body_idle: Duration::from_secs(60),
            response_write_idle: Duration::from_secs(30),
            min_response_rate_bps: 1_024,
        }
    }
}

/// Hard protocol caps defending against HTTP/2 Rapid Reset, header floods, and OOM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LimitsConfig {
    /// Maximum total size of HTTP request headers.
    pub max_header_bytes: ByteSize,
    /// Maximum default request body size.
    pub max_body_bytes: ByteSize,
    /// Maximum concurrent streams per HTTP/2 or HTTP/3 connection.
    pub max_concurrent_streams: u32,
    /// Maximum HTTP/2 `RST_STREAM` frames per second per connection (CVE-2023-44487 defense).
    pub max_h2_rst_stream_per_sec: u32,
    /// Global maximum concurrent active connections across all listeners (`R5-DOS-1`).
    pub max_connections: u32,
    /// Maximum concurrent active connections permitted from a single client IP (or IPv6 `/64`,
    /// `DOS-1` / `R5-DOS-1`).
    pub max_connections_per_ip: u32,
    /// Multiplier applied to `max-connections-per-ip` for aggregate IPv6 `/48` connection caps
    /// (defaults to `4`; raise for large institutional `/48` NAT/campus networks, `R6-DOS-2`).
    pub ipv6_prefix_conn_multiplier: u32,
    /// How many FastCGI answers larger than the buffer (32 MiB) may be streamed to one client
    /// IP (or IPv6 `/64`) at once. Each holds a backend worker for the length of the download.
    #[serde(default = "default_max_streamed_answers_per_ip")]
    pub max_streamed_answers_per_ip: u32,
    /// How many such answers may be streamed from one FastCGI backend at once, for all clients
    /// together. Keep it below the backend's number of workers (PHP-FPM `pm.max_children`), so
    /// that ordinary requests still find one.
    #[serde(default = "default_max_streamed_answers_per_backend")]
    pub max_streamed_answers_per_backend: u32,
    /// Trusted upstream proxy/load-balancer IPs or CIDRs exempt from per-IP connection caps
    /// (`R5-DOS-1`) and trusted to supply client IP via `X-Forwarded-For` (`R5-RL-1`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_proxies: Vec<IpCidr>,
    /// Process-wide memory budget for the opt-in static file cache (`limits.file-cache-bytes`,
    /// default `64MiB`; `0` disables the file cache globally across all sites and workers).
    #[serde(
        default = "default_file_cache_bytes",
        skip_serializing_if = "is_default_file_cache_bytes"
    )]
    pub file_cache_bytes: ByteSize,
}

/// Minimum allowed site `file-cache` validity window (`100ms`).
pub const MIN_FILE_CACHE_WINDOW: Duration = Duration::from_millis(100);

/// Maximum allowed site `file-cache` validity window (`60s`).
pub const MAX_FILE_CACHE_WINDOW: Duration = Duration::from_secs(60);

/// Default process-wide static file-cache byte budget (`64MiB`).
pub const DEFAULT_FILE_CACHE_BYTES: u64 = 64 * ByteSize::MIB;

/// Maximum permitted `limits.file-cache-bytes` budget (`1GiB`).
pub const MAX_FILE_CACHE_BYTES: u64 = 1_024 * ByteSize::MIB;

const fn default_file_cache_bytes() -> ByteSize {
    ByteSize::from_bytes(DEFAULT_FILE_CACHE_BYTES)
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde skip_serializing_if passes &T"
)]
const fn is_default_file_cache_bytes(value: &ByteSize) -> bool {
    value.as_bytes() == DEFAULT_FILE_CACHE_BYTES
}

const fn default_max_streamed_answers_per_ip() -> u32 {
    8
}

const fn default_max_streamed_answers_per_backend() -> u32 {
    4
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_header_bytes: ByteSize::from_bytes(16 * ByteSize::KIB),
            max_body_bytes: ByteSize::from_bytes(10 * ByteSize::MIB),
            max_concurrent_streams: 128,
            max_h2_rst_stream_per_sec: 50,
            max_connections: 16_384,
            max_connections_per_ip: 128,
            ipv6_prefix_conn_multiplier: 4,
            max_streamed_answers_per_ip: default_max_streamed_answers_per_ip(),
            max_streamed_answers_per_backend: default_max_streamed_answers_per_backend(),
            trusted_proxies: Vec::new(),
            file_cache_bytes: default_file_cache_bytes(),
        }
    }
}

/// Global `server.telemetry { ... }` observability and redaction configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TelemetryConfig {
    /// Optional dedicated Prometheus scrape listener (loopback strongly recommended, e.g. `"127.0.0.1:9090"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics_listen: Option<BindAddr>,
    /// HTTP path serving Prometheus exposition text format (defaults to `"/metrics"`).
    pub metrics_path: String,
    /// Optional OTLP/HTTP JSON collector base URL (e.g. `"https://otel.internal:4318"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub otlp_endpoint: Option<String>,
    /// Logical OpenTelemetry `service.name` resource attribute.
    pub service_name: String,
    /// Automatically redact `Authorization`, `Cookie`, API keys, and query secrets from logs.
    pub redact_logs: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            metrics_listen: None,
            metrics_path: "/metrics".to_owned(),
            otlp_endpoint: None,
            service_name: "miraserve".to_owned(),
            redact_logs: true,
        }
    }
}

/// Built-in site hardening presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SitePreset {
    /// Denies dotfiles, blocks `xmlrpc.php`, blocks `.php` execution in uploads,
    /// and rate-limits `wp-login.php` (Threat Model T5).
    WordpressHardened,
    /// Strict static site hardening preset with CSP and dotfile denial.
    StaticStrict,
    /// Hardened JSON/API gateway preset.
    ApiGateway,
}

/// HTTP security headers policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityHeadersPolicy {
    /// Strict HSTS, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, frame protection, COOP.
    Strict,
    /// Baseline security headers compatible with embedded legacy apps.
    Standard,
    /// Do not inject default security headers (emits a security warning).
    Off,
}

/// Key selector for GCRA rate limiting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "kebab-case")]
pub enum RateLimitKey {
    /// Partition limits by client IP address.
    ClientIp,
    /// Partition limits by verified RFC 9421 agent identity.
    AgentId,
    /// Partition limits by an HTTP header name.
    Header(String),
}

/// GCRA rate limit configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RateLimitConfig {
    /// Allowed number of requests per period.
    pub requests: u32,
    /// Replenishment window duration.
    #[serde(rename = "per_ms", serialize_with = "serialize_duration_ms")]
    pub per: Duration,
    /// Burst allowance above the steady rate.
    pub burst: u32,
    /// Keying dimension for rate limit buckets.
    pub key: RateLimitKey,
    /// Optional per-IP aggregate ceiling multiplier for `RateLimitKey::Header(_)` (default `10`,
    /// `R5-RL-1`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_ceiling_multiplier: Option<u32>,
    /// Optional maximum distinct simultaneously-active header keys per IP for
    /// `RateLimitKey::Header(_)` (default `64`, `R5-RL-1`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_keys_per_ip: Option<u32>,
}

/// Per-site TLS override block (`site.tls { ... }`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SiteTlsConfig {
    /// Opt-in legacy TLS 1.2 compatibility for this site only.
    pub compat_tls_1_2: bool,
    /// Optional per-site override for post-quantum hybrid key exchange.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pqc_hybrid: Option<bool>,
    /// Optional per-site certificate PEM path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert: Option<String>,
    /// Optional per-site private key PEM path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Optional per-site trusted CA bundle (PEM) for client certificate mTLS verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ca: Option<String>,
}

/// Policy for requests carrying an AI bot `User-Agent` without valid RFC 9421 auth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnverifiedBotAction {
    /// Allow request normally.
    Allow,
    /// Apply stricter rate limiting.
    Throttle,
    /// Issue a verification challenge.
    Challenge,
    /// Reject with `403 Forbidden`.
    Block,
}

/// Allowed verified AI agent rule under `bot-auth`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AllowedAgentConfig {
    /// Agent group name or cryptographic agent identifier.
    pub name: String,
    /// Automatically negotiate/serve Markdown (`text/markdown`) for this agent.
    pub serve_markdown: bool,
}

/// Configured Ed25519 Web Bot Auth agent verification key (`bot-auth { agent-key ... }`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BotAgentKeyConfig {
    /// RFC 9421 `keyid` parameter identifying this key.
    pub key_id: String,
    /// Logical agent identity recorded in audit logs and rate limits.
    pub agent_id: String,
    /// Agent group matched against `allow-agent`.
    pub group: String,
    /// Base64-encoded 32-byte Ed25519 public key (or `miraserve-ed25519-pub:<base64>`).
    pub ed25519_b64: String,
}

/// RFC 9421 / Web Bot Auth configuration (`site.bot-auth { ... }`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BotAuthConfig {
    /// Verify RFC 9421 HTTP Message Signatures for declared AI agents.
    pub verify_rfc9421: bool,
    /// Explicitly allowed verified agents or agent groups.
    pub allow_agents: Vec<AllowedAgentConfig>,
    /// Policy for unverified AI user agents.
    pub on_unverified_ai_ua: UnverifiedBotAction,
    /// Inline Ed25519 public keys registered for RFC 9421 agent verification.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_keys: Vec<BotAgentKeyConfig>,
    /// Optional path to a JSON file defining trusted RFC 9421 agent public keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_keys_file: Option<String>,
}

impl Default for BotAuthConfig {
    fn default() -> Self {
        Self {
            verify_rfc9421: true,
            allow_agents: Vec::new(),
            on_unverified_ai_ua: UnverifiedBotAction::Throttle,
            agent_keys: Vec::new(),
            agent_keys_file: None,
        }
    }
}

/// Cryptographic signature algorithm for `ai-publish` bundles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SignatureAlgorithm {
    /// Ed25519 signature verification.
    Ed25519,
}

/// Required deployment bundle signature (`ed25519:/path/to/key.pub`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignatureRequirement {
    /// Signature verification algorithm.
    pub algorithm: SignatureAlgorithm,
    /// Path to the public verification key file.
    pub public_key_path: String,
}

/// Pre-flight safety checks executed before atomic site bundle activation (Threat Model T6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "check", content = "value", rename_all = "kebab-case")]
pub enum PreflightCheck {
    /// Scan bundle contents for leaked credentials, API keys, and private keys.
    NoSecrets,
    /// Validate Content-Security-Policy compliance.
    CspValid,
    /// Reject inline `<script>` tags in HTML assets.
    NoInlineScripts,
    /// Reject bundles exceeding the configured total size.
    MaxSize(ByteSize),
    /// Reject bundles exceeding the configured file count.
    MaxFiles(u32),
}

/// Authentication mechanism for the `ai-publish` MCP publishing endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PublishAuthMode {
    /// Scoped OAuth 2.1 JWT bearer token.
    #[serde(rename = "oauth-jwt")]
    OAuthJwt,
    /// Client certificate mutual TLS.
    #[serde(rename = "mtls")]
    Mtls,
    /// Per-request Ed25519 signature authentication.
    #[serde(rename = "ed25519")]
    Ed25519,
}

/// MCP publishing endpoint configuration inside `ai-publish`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct McpPublishEndpoint {
    /// URL path where the MCP publish endpoint is mounted (e.g. `"/_miraserve/publish"`).
    pub path: String,
    /// Required authentication mode for publishing operations.
    pub auth: PublishAuthMode,
}

/// Atomic self-updating AI website publisher (`site.ai-publish { ... }`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AiPublishConfig {
    /// Directory storing immutable versioned release bundles.
    pub storage: String,
    /// Optional explicit, immutable site identifier used to bind `miraserve-bundle-v3`
    /// signatures, publish JWT `aud`, and Ed25519 request signatures independently of host list
    /// ordering or wildcard hosts (`R4-PUB-3`). Falls back to the site's first host when omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_id: Option<String>,
    /// Number of historical releases retained for instant rollback.
    pub keep_versions: u32,
    /// Optional Ed25519 signature requirement for deployment bundles.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_signature: Option<SignatureRequirement>,
    /// Optional dedicated Ed25519 public key (`ed25519:/path/to/jwt.pub` or
    /// `miraserve-ed25519-pub:<b64>`) for verifying `auth="oauth-jwt"` publish Bearer tokens
    /// separately from the bundle signing key (§4 Q4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt_public_key: Option<String>,
    /// Optional expected JWT `iss` (issuer) claim enforced in `auth="oauth-jwt"` mode (§4 Q4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt_issuer: Option<String>,
    /// Optional explicit allowlist of verified mTLS client certificate subject DNs or RDN entries
    /// (e.g. `"CN=deploy-bot"`) authorized in `auth="mtls"` mode (§4 Q4, `R2-PUB-4`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_subjects: Vec<String>,
    /// Mandatory pre-flight safety checks run before atomic swap.
    pub preflight_checks: Vec<PreflightCheck>,
    /// Optional authenticated MCP endpoint for agent-driven publishing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_endpoint: Option<McpPublishEndpoint>,
}

/// Per-site custom error page overrides and `401` sign-in URL (`site.error-pages { ... }`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ErrorPagesConfig {
    /// Optional sign-in URL rendered in the built-in `401 Unauthorized` page's Sign in action
    /// (must be a safe site-relative path such as `"/login"` or an `https://` URL).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_url: Option<String>,
    /// Optional map of HTTP error status codes (`400..=599`) to replacement page file paths.
    /// Relative paths are confined inside the site's `cap-std` document `root`; absolute paths
    /// are loaded at compile/reload time.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pages: BTreeMap<u16, String>,
}

/// Virtual host / site definition (`site "example.com" { ... }`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SiteConfig {
    /// Primary hostname and optional host aliases for SNI / `Host` routing.
    pub hosts: Vec<String>,
    /// Optional security hardening preset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preset: Option<SitePreset>,
    /// HTTP security headers policy (defaults to `strict`).
    pub security_headers: SecurityHeadersPolicy,
    /// Behaviour on a plain-HTTP `redirect-https=#true` listener (defaults to `redirect`).
    #[serde(default, skip_serializing_if = "SiteHttpMode::is_redirect")]
    pub http: SiteHttpMode,
    /// Explicit opt-in allowing `basic-auth` credentials over plain HTTP
    /// (`http "serve" credentials=#true`). Defaults to `false`; only valid with `http "serve"`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub http_credentials: bool,
    /// Optional site-wide GCRA rate limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitConfig>,
    /// Optional per-site TLS overrides.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<SiteTlsConfig>,
    /// Optional document root for static files (confined via `cap-std`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    /// Optional ordered directory index filenames (e.g. `["index.php", "index.html"]`) used by
    /// the site's default static handler, `try-files` routes, and `static` routes that do not
    /// specify their own `index` list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<Vec<String>>,
    /// Policy for probing ready-made `.zst`/`.br`/`.gz` pre-compressed sibling files on static
    /// routes (defaults to `off`; on-the-fly compression is unaffected).
    #[serde(default, skip_serializing_if = "PrecompressedPolicy::is_off")]
    pub precompressed: PrecompressedPolicy,
    /// Optional RFC 9421 Web Bot Auth configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bot_auth: Option<BotAuthConfig>,
    /// Optional atomic AI website publishing configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_publish: Option<AiPublishConfig>,
    /// Optional custom per-site error pages and `401` sign-in URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_pages: Option<ErrorPagesConfig>,
    /// Ordered route table for this site.
    pub routes: Vec<RouteConfig>,
    /// Ordered rewrite rules (`rewrite { rule ... }`), applied once before route matching; the
    /// first rule that matches wins.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rewrites: Vec<RewriteRule>,
    /// Response header changes for every response of this site (`headers { set ...; add ...;
    /// remove ... }`), applied after the security headers and before a route's own changes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<HeaderRule>,
    /// Visitor address allow/deny list for the whole site (`access { allow ...; deny ... }`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub access: Vec<AccessRule>,
    /// Password protection for the whole site (`basic-auth "/path/htpasswd" realm="..."`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basic_auth: Option<BasicAuthConfig>,
    /// The account directory that owns this site (`owner-dir "/home/user"`): every document root
    /// of the site must really be inside it once opened (links inside it are fine); otherwise
    /// the site answers 503 and the rest of the server is unaffected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_dir: Option<String>,
    /// Opt-in time-bounded in-memory cache window for qualifying static files (`file-cache "1s"`,
    /// `100ms` to `60s`; `None` or `"off"` disables caching so every filesystem change shows on
    /// the very next request).
    #[serde(
        default,
        rename = "file_cache_ms",
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_opt_duration_ms"
    )]
    pub file_cache: Option<Duration>,
    /// Set by the server, never by the configuration: why this site is unavailable (an unsafe
    /// document root found when loading). The site then answers 503 and its roots are ignored.
    #[serde(skip)]
    pub quarantine: Option<String>,
    /// Set with `quarantine` when one field caused it: the key below the site (`root`,
    /// `route[2].root`, `tls`), for diagnostics that point at that field.
    #[serde(skip)]
    pub quarantine_field: Option<String>,
}

/// Plain-HTTP serving policy for a site (`site { http "redirect" | "serve" }`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SiteHttpMode {
    /// Redirect plain-HTTP requests to HTTPS with `308 Permanent Redirect` (default).
    #[default]
    Redirect,
    /// Serve the site directly over plain HTTP on `redirect-https=#true` listeners.
    Serve,
}

impl SiteHttpMode {
    /// Returns `true` when this mode is the default ([`Self::Redirect`]).
    #[must_use]
    pub const fn is_redirect(&self) -> bool {
        matches!(self, Self::Redirect)
    }
}

impl SiteConfig {
    /// Returns the first route in [`Self::routes`] matching `canonical_path` using the exact
    /// same first-match semantics as `miraserve-http`'s `CompiledRouter`.
    #[must_use]
    pub fn match_route(&self, canonical_path: &str) -> Option<&RouteConfig> {
        self.routes.iter().find(|r| {
            if matches!(r.handler, RouteHandler::FastCgi(_))
                && let Some(ext) = r.pattern.strip_prefix("*.")
            {
                let ext_with_dot = format!(".{}", ext.to_ascii_lowercase());
                return split_extension_path_info(canonical_path, &ext_with_dot).is_some();
            }
            route_pattern_matches(&r.pattern, canonical_path)
        })
    }
}

/// Splits a canonical request path into `(script_name, path_info)` at the first path segment
/// ending with ASCII-lowercased `ext_with_dot` (e.g. `".php"`).
///
/// Mirrors Nginx `fastcgi_split_path_info ^(.+?\.php)(/.*)$`:
/// - `"/info.php"` -> `Some(("/info.php", ""))`
/// - `"/info.php/extra/path"` -> `Some(("/info.php", "/extra/path"))`
/// - `"/info.php/"` -> `Some(("/info.php", "/"))`
/// - `"/.php"` (bare dotfile) -> `None`
#[must_use]
pub fn split_extension_path_info<'a>(
    canonical_path: &'a str,
    ext_with_dot: &str,
) -> Option<(&'a str, &'a str)> {
    if !canonical_path.starts_with('/') || ext_with_dot.is_empty() {
        return None;
    }
    let bytes = canonical_path.as_bytes();
    let mut seg_start = 1_usize;
    while seg_start < bytes.len() {
        let seg_end = bytes
            .get(seg_start..)
            .and_then(|rest| rest.iter().position(|&b| b == b'/'))
            .map_or(bytes.len(), |rel| seg_start.saturating_add(rel));
        if let Some(seg) = canonical_path.get(seg_start..seg_end)
            && seg.len() > ext_with_dot.len()
            && !seg.starts_with('.')
            && seg
                .as_bytes()
                .get(seg.len() - ext_with_dot.len()..)
                .is_some_and(|tail| {
                    tail.iter()
                        .zip(ext_with_dot.as_bytes())
                        .all(|(&h, &e)| h.to_ascii_lowercase() == e)
                })
        {
            let script = canonical_path.get(..seg_end)?;
            let path_info = canonical_path.get(seg_end..).unwrap_or("");
            return Some((script, path_info));
        }
        seg_start = seg_end.saturating_add(1);
    }
    None
}

/// Evaluates whether a MiraServe route `pattern` (`"/*"`, `"*.ext"`, `"/prefix/*"`, or exact
/// path) matches `canonical_path`, mirroring `miraserve-http`'s `RouteMatcher::matches`.
#[must_use]
pub fn route_pattern_matches(pattern: &str, canonical_path: &str) -> bool {
    if pattern == "/*" {
        true
    } else if let Some(ext) = pattern.strip_prefix("*.") {
        let trimmed = canonical_path.trim_end_matches('/');
        let t = trimmed.as_bytes();
        let e = ext.as_bytes();
        !t.is_empty()
            && t.len()
                .checked_sub(e.len().saturating_add(1))
                .is_some_and(|dot_pos| {
                    t.get(dot_pos) == Some(&b'.')
                        && t.get(dot_pos.saturating_add(1)..)
                            .is_some_and(|tail| tail.eq_ignore_ascii_case(e))
                })
    } else if let Some(prefix) = pattern.strip_suffix("/*") {
        canonical_path == prefix
            || canonical_path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
    } else {
        canonical_path == pattern
    }
}

/// Single `route "<pattern>" { ... }` rule inside a site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RouteConfig {
    /// Route match pattern (e.g. `"/*"`, `"/mcp/*"`, `"*.php"`).
    pub pattern: String,
    /// Optional route-specific document root override.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    /// Optional route-specific rate limit override.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitConfig>,
    /// Optional route-specific security headers override.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_headers: Option<SecurityHeadersPolicy>,
    /// Terminal handler invoked when this route matches.
    pub handler: RouteHandler,
    /// Response header changes for this route, applied after the site's.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<HeaderRule>,
    /// Visitor address allow/deny list for this route, checked after the site's.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub access: Vec<AccessRule>,
    /// Password protection for this route, checked after the site's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basic_auth: Option<BasicAuthConfig>,
}

/// `basic-auth "/abs/path/htpasswd" realm="..."`: HTTP Basic authentication against an
/// htpasswd file with bcrypt hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BasicAuthConfig {
    /// Absolute path of the htpasswd file (`user:hash` per line).
    pub users_file: String,
    /// Realm shown by the browser's sign-in dialog.
    pub realm: String,
}

/// Largest htpasswd file read.
pub const MAX_HTPASSWD_BYTES: u64 = 1024 * 1024;

/// Parses an htpasswd file: `user:hash` per line, `#` comments and blank lines ignored. Only
/// bcrypt hashes (`$2y$`, `$2b$`, `$2a$`) are accepted.
///
/// # Errors
/// Returns `"line N: reason"` for the first line that is not acceptable. The hash itself is
/// never included in the message.
pub fn parse_htpasswd(text: &str) -> Result<Vec<(String, String)>, String> {
    let mut users: Vec<(String, String)> = Vec::new();
    let mut area_cost: Option<u32> = None;
    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((user, hash)) = line.split_once(':') else {
            return Err(format!("line {line_no}: not 'user:hash'"));
        };
        if user.is_empty() || user.bytes().any(|b| b.is_ascii_control()) {
            return Err(format!("line {line_no}: invalid user name"));
        }
        if users.iter().any(|(existing, _)| existing == user) {
            return Err(format!(
                "line {line_no}: user '{user}' appears more than once (an old entry would decide)"
            ));
        }
        let hash = hash.trim();
        let cost = bcrypt_record_rejection(hash)
            .map_err(|reason| format!("line {line_no}: user '{user}': {reason}"))?;
        // One cost per file, so a wrong password takes as long as an unknown user name.
        match area_cost {
            None => area_cost = Some(cost),
            Some(first) if first != cost => {
                return Err(format!(
                    "line {line_no}: user '{user}' has bcrypt cost {cost}, other users {first}; \
                     use one cost for every user of the file (htpasswd -B -C {first})"
                ));
            }
            Some(_) => {}
        }
        users.push((user.to_owned(), hash.to_owned()));
    }
    Ok(users)
}

/// Lowest and highest bcrypt cost accepted in a users file. Higher costs make every check of
/// that account occupy a worker for a long time (cost 12 is about a quarter second; each step
/// doubles it).
pub const BCRYPT_COST_RANGE: std::ops::RangeInclusive<u32> = 4..=12;

/// Checks a complete bcrypt record: `$2y$` (or `$2b$`, `$2a$`), a two-digit cost in
/// [`BCRYPT_COST_RANGE`], `$`, and 53 characters of the bcrypt alphabet (22 of salt, 31 of
/// digest). Never echoes the record.
fn bcrypt_record_rejection(hash: &str) -> Result<u32, String> {
    let not_bcrypt = || {
        "the password hash is not a bcrypt hash (one starting with $2y$, $2b$ or $2a$); re-enter the password with htpasswd -B".to_owned()
    };
    let rest = ["$2y$", "$2b$", "$2a$"]
        .iter()
        .find_map(|prefix| hash.strip_prefix(prefix))
        .ok_or_else(not_bcrypt)?;
    let (cost, encoded) = rest.split_once('$').ok_or_else(not_bcrypt)?;
    if cost.len() != 2 || !cost.bytes().all(|b| b.is_ascii_digit()) {
        return Err("the bcrypt record is damaged (cost)".to_owned());
    }
    let cost: u32 = cost
        .parse()
        .map_err(|_| "the bcrypt record is damaged (cost)".to_owned())?;
    if encoded.len() != 53
        || !encoded
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'/')
    {
        return Err("the bcrypt record is damaged (salt or digest)".to_owned());
    }
    // The same decoder the password check uses: catches invalid trailing bits that the
    // alphabet check above lets through.
    if hash.parse::<bcrypt::HashParts>().is_err() {
        return Err("the bcrypt record is damaged (salt or digest)".to_owned());
    }
    if !BCRYPT_COST_RANGE.contains(&cost) {
        return Err(format!(
            "bcrypt cost {cost} is outside {}..={}; re-enter the password (htpasswd -B -C 10)",
            BCRYPT_COST_RANGE.start(),
            BCRYPT_COST_RANGE.end()
        ));
    }
    Ok(cost)
}

/// One line of an `access` block: `allow "10.0.0.0/8"`, `deny "all"`. The first line that
/// matches the visitor's address decides; when none matches, the request is allowed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccessRule {
    /// `true` for `allow`, `false` for `deny`.
    pub allow: bool,
    /// `"all"`, an IP address or a CIDR range.
    pub source: String,
}

/// Most lines in one `access` block.
pub const MAX_ACCESS_RULES: usize = 256;

/// What a [`HeaderRule`] does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HeaderAction {
    /// Replace every value of the header with this one (Apache `Header set`).
    Set,
    /// Add this value, keeping existing ones (Apache `Header append`/`add`).
    Add,
    /// Remove the header (Apache `Header unset`).
    Remove,
}

/// Maximum number of status codes/classes in a single header rule's `status="..."` condition.
pub const MAX_HEADER_STATUS_ENTRIES: usize = 64;

/// One status code (`200`–`599`) or status class (`2xx`, `3xx`, `4xx`, `5xx`) in a
/// [`HeaderRule::status`] condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HeaderStatusMatcher {
    /// Exact final HTTP status code (`200..=599`).
    Code(u16),
    /// Status class digit (`2`, `3`, `4`, or `5` representing `2xx`–`5xx`).
    Class(u8),
}

impl HeaderStatusMatcher {
    /// Returns `true` when HTTP response `status_code` matches this condition.
    #[must_use]
    pub fn matches(self, status_code: u16) -> bool {
        match self {
            Self::Code(code) => status_code == code,
            Self::Class(class) => status_code / 100 == u16::from(class),
        }
    }

    /// Formats this matcher in its canonical token form (e.g. `"200"` or `"2xx"`).
    #[must_use]
    pub fn as_token(self) -> String {
        match self {
            Self::Code(code) => code.to_string(),
            Self::Class(class) => format!("{class}xx"),
        }
    }
}

impl Serialize for HeaderStatusMatcher {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.as_token())
    }
}

/// Parses a space-separated list of HTTP status codes (`200`–`599`) and/or classes (`2xx`, `3xx`,
/// `4xx`, `5xx`) for a header rule's `status="..."` property.
///
/// # Errors
/// Returns a human-readable rejection message if the list is empty, contains invalid whitespace,
/// unknown tokens, out-of-range status codes, duplicates, or more than
/// [`MAX_HEADER_STATUS_ENTRIES`] entries.
pub fn parse_header_status_list(raw: &str) -> Result<Vec<HeaderStatusMatcher>, String> {
    if raw
        .bytes()
        .any(|b| b.is_ascii_control() || (b.is_ascii_whitespace() && b != b' '))
    {
        return Err(
            "status condition must be a space-separated list of codes (200-599) or classes (2xx, 3xx, 4xx, 5xx)"
                .to_owned(),
        );
    }
    let mut matchers = Vec::new();
    for token in raw.split(' ').filter(|part| !part.is_empty()) {
        if matchers.len() >= MAX_HEADER_STATUS_ENTRIES {
            return Err(format!(
                "status condition has more than {MAX_HEADER_STATUS_ENTRIES} entries"
            ));
        }
        let matcher = match token {
            "2xx" => HeaderStatusMatcher::Class(2),
            "3xx" => HeaderStatusMatcher::Class(3),
            "4xx" => HeaderStatusMatcher::Class(4),
            "5xx" => HeaderStatusMatcher::Class(5),
            _ if token.len() == 3 && token.bytes().all(|b| b.is_ascii_digit()) => {
                let code = token.parse::<u16>().map_err(|_| {
                    format!("'{token}' is not a valid status code (200-599) or class (2xx-5xx)")
                })?;
                if !(200..=599).contains(&code) {
                    return Err(format!("status code '{token}' must be between 200 and 599"));
                }
                HeaderStatusMatcher::Code(code)
            }
            _ => {
                return Err(format!(
                    "'{token}' is not a valid status code (200-599) or class (2xx, 3xx, 4xx, 5xx)"
                ));
            }
        };
        if matchers.contains(&matcher) {
            return Err(format!("duplicate status condition '{token}'"));
        }
        matchers.push(matcher);
    }
    if matchers.is_empty() {
        return Err(
            "status condition must list at least one status code (200-599) or class (2xx, 3xx, 4xx, 5xx)"
                .to_owned(),
        );
    }
    Ok(matchers)
}

/// One response header change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HeaderRule {
    /// What to do.
    pub action: HeaderAction,
    /// Header name, lower case.
    pub name: String,
    /// Value for `set` and `add`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Optional status condition (`status="200 206 304"` or classes `2xx`–`5xx`).
    /// Empty means the rule applies to every response status (default).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub status: Vec<HeaderStatusMatcher>,
}

/// Most header changes in one `headers` block.
pub const MAX_HEADER_RULES: usize = 64;

/// Longest value a header change may set.
pub const MAX_HEADER_RULE_VALUE_BYTES: usize = 4_096;

/// Headers a configuration may not change: they describe the message framing or the connection,
/// and a wrong value breaks the response or lets it be read as a different message.
const PROTECTED_RESPONSE_HEADERS: &[&str] = &[
    "connection",
    "content-encoding",
    "content-length",
    "content-range",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Returns why a header change is not acceptable, or `None`.
#[must_use]
pub fn header_rule_rejection(rule: &HeaderRule) -> Option<String> {
    let name = rule.name.as_str();
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
    {
        return Some(format!("'{name}' is not a valid header name"));
    }
    if PROTECTED_RESPONSE_HEADERS.contains(&name) {
        return Some(format!(
            "'{name}' describes message framing or the connection and cannot be changed"
        ));
    }
    if rule.status.len() > MAX_HEADER_STATUS_ENTRIES {
        return Some(format!(
            "status condition has more than {MAX_HEADER_STATUS_ENTRIES} entries"
        ));
    }
    for (idx, matcher) in rule.status.iter().enumerate() {
        match *matcher {
            HeaderStatusMatcher::Code(code) if !(200..=599).contains(&code) => {
                return Some(format!("status code '{code}' must be between 200 and 599"));
            }
            HeaderStatusMatcher::Class(class) if !(2..=5).contains(&class) => {
                return Some(format!(
                    "status class '{class}xx' must be one of 2xx, 3xx, 4xx, 5xx"
                ));
            }
            _ => {}
        }
        if rule
            .status
            .get(..idx)
            .is_some_and(|prev| prev.contains(matcher))
        {
            return Some(format!(
                "duplicate status condition '{}'",
                matcher.as_token()
            ));
        }
    }
    match (rule.action, rule.value.as_deref()) {
        (HeaderAction::Remove, None) => None,
        (HeaderAction::Remove, Some(_)) => Some("remove takes only a header name".to_owned()),
        (_, None) => Some("set and add need a value".to_owned()),
        (_, Some(value)) => {
            if value.len() > MAX_HEADER_RULE_VALUE_BYTES {
                Some(format!(
                    "the value is longer than {MAX_HEADER_RULE_VALUE_BYTES} bytes"
                ))
            } else if value.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f) {
                Some("the value contains a control character".to_owned())
            } else {
                None
            }
        }
    }
}

/// Terminal handler configured on a [`RouteConfig`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", content = "config", rename_all = "kebab-case")]
pub enum RouteHandler {
    /// Forward request to an isolated FastCGI backend (e.g. PHP-FPM).
    #[serde(rename = "fastcgi")]
    FastCgi(FastCgiConfig),
    /// Resolve static files in order with fallback URI/status (`try-files`).
    TryFiles(TryFilesConfig),
    /// Model Context Protocol security gateway with OAuth & tool RBAC.
    McpGateway(McpGatewayConfig),
    /// Reverse proxy pool with health checks and streaming controls.
    ReverseProxy(ReverseProxyConfig),
    /// Dedicated `cap-std` confined static file server.
    Static(StaticConfig),
    /// Sandboxed WebAssembly (`wasmtime` + `wasi:http`) plugin handler (Threat Model T7).
    WasmPlugin(WasmPluginConfig),
    /// Answer with an HTTP redirect (`redirect "https://example.com{uri}" status=301`).
    Redirect(RedirectConfig),
    /// Answer every request with a fixed status and the site's error page for it
    /// (`respond 503`), for example a suspended or maintenance site.
    Respond(u16),
}

/// Configuration for a `try-files` route handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TryFilesConfig {
    /// Candidate paths or `=status` codes tried in order.
    pub candidates: Vec<String>,
    /// When `true`, skip the final candidate if the normalised request path (without query string)
    /// ends with a dot followed by 1 to 8 ASCII letters or digits (`\.[A-Za-z0-9]{1,8}$`).
    pub fallback_unless_extension: bool,
}

impl Serialize for TryFilesConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Preserve 0.1.5 `--dump-normalized` JSON output byte-for-byte when the default
        // (`fallback-unless-extension=#false`) is used: serialize as a plain array of candidates.
        // When `#true`, serialize as an object carrying both fields.
        if self.fallback_unless_extension {
            use serde::ser::SerializeStruct as _;
            let mut state = serializer.serialize_struct("TryFilesConfig", 2)?;
            state.serialize_field("candidates", &self.candidates)?;
            state.serialize_field("fallback_unless_extension", &self.fallback_unless_extension)?;
            state.end()
        } else {
            self.candidates.serialize(serializer)
        }
    }
}

/// HTTP redirect handler (`redirect "<target>" status=301`).
///
/// `target` is either an absolute `http://` / `https://` URL whose host is written out in full,
/// or a path starting with a single `/`. After the host (or the literal path prefix) it may use
/// `{path}` (the request path), `{query}` (the query string without `?`) and `{uri}` (the path
/// plus `?query` when there is one). On a prefix route (`"/old/*"`) it may also use `{rest}`, the
/// part of the request path after that prefix without its leading `/`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RedirectConfig {
    /// Redirect target template.
    pub target: String,
    /// Status code: 301, 302, 307 or 308 (defaults to 301).
    pub status: u16,
}

/// Returns why `target` is not a safe redirect target template, or `None`.
///
/// The destination host must never depend on the request: an absolute target needs a literal
/// host followed by `/`, `{path}`, `{uri}` or nothing; a relative target needs `/` followed by a
/// literal character that is not `/` or `\\` (so the result can never be read as `//host`).
#[must_use]
pub fn redirect_target_rejection(target: &str) -> Option<&'static str> {
    if target.is_empty() {
        return Some("it is empty");
    }
    if target.len() > MAX_TARGET_TEMPLATE_BYTES {
        return Some("it is longer than 2048 bytes");
    }
    if target
        .bytes()
        .any(|b| b.is_ascii_control() || b == b' ' || b == b'\\' || !b.is_ascii())
    {
        return Some(
            "it contains a space, backslash, control or non-ASCII character (percent-encode it)",
        );
    }
    // Every `{...}` must be a known placeholder.
    let mut rest = target;
    while let Some(open) = rest.find('{') {
        let after = rest.get(open..).unwrap_or("");
        if !["{path}", "{query}", "{uri}", "{rest}"]
            .iter()
            .any(|ph| after.starts_with(ph))
        {
            return Some(
                "it uses an unknown placeholder (allowed: {path}, {query}, {uri}, {rest})",
            );
        }
        rest = after.get(1..).unwrap_or("");
    }
    if target.contains('}') && !target.contains('{') {
        return Some("it contains an unmatched '}'");
    }
    // `{query}` is query text; before the first '?' it would be read as part of the host or path.
    if let Some(pos) = target.find("{query}")
        && !target.get(..pos).unwrap_or("").contains('?')
    {
        return Some("{query} must come after a '?'");
    }
    let after_scheme = target
        .strip_prefix("https://")
        .or_else(|| target.strip_prefix("http://"));
    if let Some(rest) = after_scheme {
        let host_end = rest.find(['/', '{', '?', '#']).unwrap_or(rest.len());
        let host = rest.get(..host_end).unwrap_or("");
        if host.is_empty() || host.contains('@') {
            return Some("an absolute target needs a literal host name without user info");
        }
        let tail = rest.get(host_end..).unwrap_or("");
        if !(tail.is_empty()
            || tail.starts_with('/')
            || tail.starts_with("{path}")
            || tail.starts_with("{uri}"))
        {
            return Some("the host must be followed by '/', {path} or {uri}");
        }
        return None;
    }
    let mut chars = target.chars();
    if chars.next() != Some('/') {
        return Some("it must start with http://, https:// or a single '/'");
    }
    match chars.next() {
        Some('/' | '{') => Some(
            "a relative target must start with '/' and a literal path character, not '//' or a placeholder",
        ),
        _ => None,
    }
}

/// Sandboxed WebAssembly plugin handler (`wasm-plugin "/path/to/mod.wasm" ...`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WasmPluginConfig {
    /// Path to the WebAssembly component or core module (`.wasm` or `.wat`).
    pub module_path: String,
    /// Hard linear memory ceiling per plugin invocation (defaults to `16 MiB`).
    pub max_memory: ByteSize,
    /// Deterministic CPU instruction fuel budget per request (defaults to `5_000_000`).
    pub max_fuel: u64,
    /// Wall-clock execution timeout per request (defaults to `100ms`).
    #[serde(rename = "timeout_ms", serialize_with = "serialize_duration_ms")]
    pub timeout: Duration,
    /// Explicit outbound HTTP host allowlist (empty by default = zero ambient network access).
    pub allow_outbound_hosts: Vec<String>,
}

impl Default for WasmPluginConfig {
    fn default() -> Self {
        Self {
            module_path: String::new(),
            max_memory: ByteSize::from_bytes(16 * ByteSize::MIB),
            max_fuel: 5_000_000,
            timeout: Duration::from_millis(100),
            allow_outbound_hosts: Vec::new(),
        }
    }
}

/// FastCGI backend transport target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "transport", rename_all = "lowercase")]
pub enum FastCgiTarget {
    /// Unix domain socket path (`unix:/run/php/php8.3-fpm.sock`).
    Unix {
        /// Filesystem path to the Unix domain socket.
        path: String,
    },
    /// TCP host and port (`tcp://127.0.0.1:9000` or `127.0.0.1:9000`).
    Tcp {
        /// Backend host or IP address.
        host: String,
        /// Backend TCP port.
        port: u16,
    },
}

/// Pure-Rust FastCGI upstream configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FastCgiConfig {
    /// Backend FastCGI endpoint.
    pub target: FastCgiTarget,
    /// Request/response timeout for FastCGI execution (defaults to `30s`).
    #[serde(rename = "timeout_ms", serialize_with = "serialize_duration_ms")]
    pub timeout: Duration,
    /// Send a `GET`, `HEAD` or `OPTIONS` request to the backend a second time when the
    /// connection is lost after the request was handed over (`replay-safe-methods=#true`).
    /// Off by default: the backend may already have run the request. A connection that could
    /// not be made at all is always tried once more, for every method.
    pub replay_safe_methods: bool,
    /// How many answers larger than the buffer this backend may have streaming at once
    /// (`max-streamed-answers=N`), instead of `limits.max-streamed-answers-per-backend`. For
    /// a pool whose number of workers differs from the others'.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_streamed_answers: Option<u32>,
}

/// Audit logging mode for the MCP security gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditLogMode {
    /// Secret-redacted structured JSON audit records.
    StructuredJson,
    /// Secret-redacted human-readable log lines.
    RedactedText,
    /// Disable MCP audit logging (emits a security warning).
    Off,
}

/// MCP security gateway configuration (`mcp-gateway upstream="..." { ... }`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct McpGatewayConfig {
    /// Upstream MCP server URL (`https://...` recommended).
    pub upstream: String,
    /// Serve OAuth 2.1 Protected Resource Metadata (`RFC 9728`) and require verified Bearer JWTs.
    pub oauth_resource_metadata: bool,
    /// Optional Ed25519 public key (`ed25519:/path/to/key.pub` or `miraserve-ed25519-pub:<b64>`)
    /// used to cryptographically verify OAuth 2.1 `EdDSA` Bearer JWTs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt_public_key: Option<String>,
    /// Optional HTTPS JWKS endpoint URL (`RFC 7517`) publishing Ed25519 OKP verifying keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_url: Option<String>,
    /// Optional expected JWT `iss` (issuer) claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt_issuer: Option<String>,
    /// Optional expected JWT `aud` (audience) claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt_audience: Option<String>,
    /// Optional required OAuth 2.1 `scope` token inside the verified JWT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_scope: Option<String>,
    /// JSON-RPC tool allowlist patterns (default-deny when empty).
    pub allow_tools: Vec<String>,
    /// JSON-RPC tool denylist patterns (always takes precedence over allowlist).
    pub deny_tools: Vec<String>,
    /// Audit logging output mode.
    pub audit_log: AuditLogMode,
    /// Maximum permitted JSON nesting depth in MCP JSON-RPC payloads.
    pub max_json_depth: u32,
    /// Maximum permitted MCP JSON-RPC request body size.
    pub max_request_bytes: ByteSize,
    /// Optional per-route override for upstream TCP/TLS connect timeout (`R5-PRX-3`).
    #[serde(
        rename = "upstream_connect_timeout_ms",
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_opt_duration_ms"
    )]
    pub upstream_connect_timeout: Option<Duration>,
    /// Optional per-route override for upstream response-header timeout (`R5-PRX-3`).
    #[serde(
        rename = "upstream_response_timeout_ms",
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_opt_duration_ms"
    )]
    pub upstream_response_timeout: Option<Duration>,
    /// Optional per-route override for upstream response-body idle timeout (e.g. long-lived MCP
    /// Streamable HTTP SSE streams, `R5-PRX-3`).
    #[serde(
        rename = "upstream_body_idle_timeout_ms",
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_opt_duration_ms"
    )]
    pub upstream_body_idle_timeout: Option<Duration>,
}

/// Streaming response flush policy for reverse proxies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StreamingFlushMode {
    /// Flush chunks immediately (zero-buffer SSE / LLM token streaming).
    Immediate,
    /// Standard buffered forwarding.
    Buffered,
}

/// Reverse proxy load balancing algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoadBalancePolicy {
    /// Weighted round-robin across healthy upstreams.
    RoundRobin,
    /// Route to upstream with fewest active in-flight requests.
    LeastConn,
    /// Uniform random selection across healthy upstreams.
    Random,
}

/// Single upstream backend inside `reverse-proxy`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpstreamConfig {
    /// Upstream URL (`https://10.0.1.30:8000`, `http://127.0.0.1:8080`, etc.).
    pub url: String,
    /// Relative load-balancing weight (defaults to `1`).
    pub weight: u32,
}

/// Active upstream health-check configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HealthCheckConfig {
    /// HTTP probe path (must start with `/`).
    pub path: String,
    /// Interval between consecutive probes.
    #[serde(rename = "interval_ms", serialize_with = "serialize_duration_ms")]
    pub interval: Duration,
    /// Optional per-probe timeout (must be strictly less than `interval`).
    #[serde(
        rename = "timeout_ms",
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_opt_duration_ms"
    )]
    pub timeout: Option<Duration>,
    /// Consecutive failures before marking an upstream unhealthy.
    pub unhealthy_threshold: u32,
    /// `Host` header sent with each probe (`host="example.com"`). Required when the route uses
    /// `preserve-host #true`: real requests then reach the upstream with the visitor's host, so
    /// a probe sent with the upstream's own name could test a different virtual host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

/// Optional upstream TLS / mTLS configuration for backend connections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpstreamTlsConfig {
    /// Custom CA bundle PEM path for verifying upstream certificates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_cert: Option<String>,
    /// Client certificate PEM path for upstream mTLS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_cert: Option<String>,
    /// Client private key PEM path for upstream mTLS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_key: Option<String>,
}

/// Reverse proxy pool configuration (`reverse-proxy { ... }`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReverseProxyConfig {
    /// Backend upstream servers (at least one required).
    pub upstreams: Vec<UpstreamConfig>,
    /// Response body flush policy (`immediate` for LLM SSE streaming).
    pub streaming_flush: StreamingFlushMode,
    /// Load-balancing strategy across healthy upstreams.
    pub lb_policy: LoadBalancePolicy,
    /// Optional active HTTP health check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_check: Option<HealthCheckConfig>,
    /// Optional upstream mTLS/CA configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_tls: Option<UpstreamTlsConfig>,
    /// Optional per-route override for upstream TCP/TLS connect timeout (`R5-PRX-3`).
    #[serde(
        rename = "upstream_connect_timeout_ms",
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_opt_duration_ms"
    )]
    pub upstream_connect_timeout: Option<Duration>,
    /// Optional per-route override for upstream response-header timeout (`R5-PRX-3`).
    #[serde(
        rename = "upstream_response_timeout_ms",
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_opt_duration_ms"
    )]
    pub upstream_response_timeout: Option<Duration>,
    /// Optional per-route override for upstream response-body idle timeout (e.g. long-lived SSE,
    /// `R5-PRX-3`).
    #[serde(
        rename = "upstream_body_idle_timeout_ms",
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_opt_duration_ms"
    )]
    pub upstream_body_idle_timeout: Option<Duration>,
    /// Forward the client's own `Host` header to the upstream instead of the upstream's
    /// authority (`preserve-host #true`). Off by default. Needed when the backend selects a
    /// virtual host or tenant by hostname, as Nginx `proxy_set_header Host $host`, Apache
    /// `ProxyPreserveHost On` and Caddy's default do. The forwarded value has already matched
    /// one of this site's configured hosts.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub preserve_host: bool,
    /// Tunnel RFC 6455 WebSocket upgrades to the upstream (`allow-upgrades`, default `#true`).
    /// Set `#false` for a backend that must never receive an upgraded connection; a client
    /// `Upgrade` request is then forwarded as an ordinary request without the upgrade headers.
    pub allow_upgrades: bool,
    /// Remove the route's prefix from the request path before forwarding
    /// (`strip-prefix #true` on `route "/tool/*"` forwards `/tool/a/b` as `/a/b`). Off by default.
    pub strip_prefix: bool,
}

/// Policy for serving hidden dotfiles (`.env`, `.git`, `.htaccess`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DotfilesPolicy {
    /// Deny access to dotfiles (default, Threat Model T5).
    Deny,
    /// Permit serving dotfiles (emits a security warning).
    Allow,
}

/// Policy controlling which ready-made pre-compressed sibling files (`.zst`, `.br`, `.gz`) are
/// probed when serving static content (`precompressed "off" | "all" | "zst" "br" "gz"`).
///
/// Defaults to [`Self::OFF`] (no sibling probes; on-the-fly compression is unaffected). When
/// specific encodings are enabled, probing still follows the server's negotiation order
/// (`zst` > `br` > `gz`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PrecompressedPolicy {
    /// Probe ready-made `.zst` sibling files.
    pub zst: bool,
    /// Probe ready-made `.br` sibling files.
    pub br: bool,
    /// Probe ready-made `.gz` sibling files.
    pub gz: bool,
}

impl PrecompressedPolicy {
    /// Never probe or serve pre-compressed siblings (default).
    pub const OFF: Self = Self {
        zst: false,
        br: false,
        gz: false,
    };

    /// Probe all supported pre-compressed siblings (`zst`, `br`, `gz`).
    pub const ALL: Self = Self {
        zst: true,
        br: true,
        gz: true,
    };

    /// Returns `true` when sibling lookup is completely disabled (`precompressed "off"`).
    #[must_use]
    pub const fn is_off(&self) -> bool {
        !self.zst && !self.br && !self.gz
    }

    /// Returns `true` when all supported encodings (`zst`, `br`, `gz`) are enabled.
    #[must_use]
    pub const fn is_all(&self) -> bool {
        self.zst && self.br && self.gz
    }

    /// Returns `true` when at least one sibling encoding is enabled.
    #[must_use]
    pub const fn any(&self) -> bool {
        !self.is_off()
    }

    /// Returns enabled encoding names in server negotiation order (`"zst"`, `"br"`, `"gz"`).
    #[must_use]
    pub fn enabled_names(&self) -> Vec<&'static str> {
        let mut names = Vec::with_capacity(3);
        if self.zst {
            names.push("zst");
        }
        if self.br {
            names.push("br");
        }
        if self.gz {
            names.push("gz");
        }
        names
    }

    /// Human-readable summary for CLI diagnostics (`"off"`, `"all"`, or comma-separated names).
    #[must_use]
    pub fn display_summary(&self) -> String {
        if self.is_off() {
            "off".to_owned()
        } else if self.is_all() {
            "all".to_owned()
        } else {
            self.enabled_names().join(", ")
        }
    }
}

impl Serialize for PrecompressedPolicy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.enabled_names().serialize(serializer)
    }
}

/// Static file handler configuration (`static { ... }`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticConfig {
    /// Directory index filenames tried in order.
    pub index: Vec<String>,
    /// Whether `index` was explicitly configured on this `static` route rather than using the
    /// default fallback (when `false`, the route inherits `site.index` if configured; Codex G9).
    pub index_explicit: bool,
    /// Dotfile serving policy (defaults to `deny`).
    pub dotfiles: DotfilesPolicy,
    /// Enable on-the-fly/precompressed `zstd`/`br`/`gzip` negotiation.
    pub compression: bool,
    /// Pre-compressed sibling lookup policy (defaults to `off`; inherits `site.precompressed`
    /// when omitted on a `static` route).
    pub precompressed: PrecompressedPolicy,
    /// Whether `precompressed` was explicitly configured on this `static` route rather than
    /// inheriting `site.precompressed`.
    pub precompressed_explicit: bool,
}

impl Serialize for StaticConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct as _;
        // Emit `precompressed` whenever explicitly set on the route (including explicit `"off"`,
        // which serializes as `[]`) so a route overriding a site-level policy never dumps
        // identically to a route inheriting it. Omitted (inherited) routes omit the field so
        // v0.1.2/v0.1.3 normalized goldens remain byte-identical.
        let emit_precompressed = self.precompressed_explicit || self.precompressed.any();
        let field_count = if emit_precompressed { 4 } else { 3 };
        let mut state = serializer.serialize_struct("StaticConfig", field_count)?;
        state.serialize_field("index", &self.index)?;
        state.serialize_field("dotfiles", &self.dotfiles)?;
        state.serialize_field("compression", &self.compression)?;
        if emit_precompressed {
            state.serialize_field("precompressed", &self.precompressed)?;
        }
        state.end()
    }
}

impl Default for StaticConfig {
    fn default() -> Self {
        Self {
            index: vec!["index.html".to_owned()],
            index_explicit: false,
            dotfiles: DotfilesPolicy::Deny,
            compression: true,
            precompressed: PrecompressedPolicy::OFF,
            precompressed_explicit: false,
        }
    }
}

/// Longest redirect or rewrite target template, in bytes. A template is expanded for every
/// matching request, so its size is bounded when the configuration is loaded.
pub const MAX_TARGET_TEMPLATE_BYTES: usize = 2_048;

/// Largest number of rewrite rules one site may define.
pub const MAX_REWRITE_RULES_PER_SITE: usize = 200;
/// Longest rewrite pattern, in bytes.
pub const MAX_REWRITE_PATTERN_BYTES: usize = 512;
/// Compiled-size limit for one rewrite pattern.
pub const REWRITE_REGEX_SIZE_LIMIT: usize = 256 * 1024;

/// One `rule "<regex>" ...` line of a site's `rewrite` block.
///
/// The pattern is matched against the request path after normalisation (the same form routes
/// match). The first rule whose pattern and conditions all match is applied, once; rules are
/// never re-run on their own result, so they cannot loop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[allow(clippy::struct_excessive_bools)] // independent per-rule flags, one per directive
pub struct RewriteRule {
    /// Regular expression matched against the normalised request path.
    pub pattern: String,
    /// What to do when the rule matches.
    pub action: RewriteAction,
    /// Only when no file or directory exists at the request path under the site root
    /// (`if-not-file=#true`, the `!-f` / `!-d` pair of a front controller).
    pub if_not_file: bool,
    /// Only for this exact hostname (`host="www.example.com"`).
    pub host: Option<String>,
    /// Only for this method (`method="GET"`).
    pub method: Option<String>,
    /// Only when the query string matches this regular expression.
    pub query: Option<String>,
    /// Only when a request header matches (`header="Name=regex"`).
    pub header: Option<(String, String)>,
    /// Only when no REGULAR FILE exists at the request path (`if-not-regular-file=#true`,
    /// Apache `!-f` on its own: a directory still counts as "not a file").
    pub if_not_regular_file: bool,
    /// Only when a file or directory exists at the request path (`if-file=#true`, Apache `-f`
    /// or `-d`; the opposite of `if-not-file`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub if_file: bool,
    /// Only when a REGULAR FILE exists at the request path (`if-regular-file=#true`, Apache
    /// `-f` on its own; the opposite of `if-not-regular-file`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub if_regular_file: bool,
    /// Further conditions from the rule's child block, all of which must hold.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<RewriteCondition>,
}

/// Largest number of child conditions on one rewrite rule.
pub const MAX_REWRITE_CONDITIONS_PER_RULE: usize = 16;

/// What a [`RewriteCondition`] tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum RewriteConditionKind {
    /// The site hostname the request was matched to.
    Host,
    /// The query string (without `?`).
    Query,
    /// A request header, by lower-case name.
    Header(String),
    /// The visitor's address (after trusted proxies); the pattern is an IP or CIDR, not a
    /// regular expression.
    ClientIp,
}

/// One condition line inside a rule's child block: `header "Referer" "<regex>"`,
/// `not-header "Referer" "<regex>"`, `query "<regex>"`, `not-query`, `host`, `not-host`.
///
/// A negated header condition holds when NO value of that header matches, which includes the
/// header being absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RewriteCondition {
    /// What is tested.
    pub kind: RewriteConditionKind,
    /// Regular expression.
    pub pattern: String,
    /// `not-` form: the condition holds when the pattern does not match.
    pub negate: bool,
}

/// Action of a [`RewriteRule`]. Targets may use `$0`..`$9` for the pattern's capture groups.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum RewriteAction {
    /// Serve another path of the same site; the visitor's address does not change
    /// (`to="/index.php?route=$1"`).
    Internal {
        /// Target path, optionally with a query string.
        to: String,
        /// Append the request's own query string (`keep-query`, default `#true`).
        keep_query: bool,
    },
    /// Answer with a redirect (`redirect="/new/$1" status=301`).
    Redirect {
        /// Target: a path starting with a single `/`, or an absolute `http(s)://` URL whose
        /// host is literal.
        to: String,
        /// 301, 302, 307 or 308.
        status: u16,
        /// Append the request's own query string (`keep-query`, default `#true`).
        keep_query: bool,
    },
    /// Refuse the request (`deny=403`; 403, 404 or 410).
    Deny(u16),
    /// Stop here and leave the request unchanged (`pass=#true`): later rules are not checked.
    Pass,
}

/// Compiles a rewrite regular expression with the limits every rule must respect. The engine
/// runs in time linear in the input, so a crafted address cannot make a pattern hang.
///
/// # Errors
/// Returns the compile error text.
pub fn compile_rewrite_regex(pattern: &str) -> Result<regex::Regex, String> {
    if pattern.len() > MAX_REWRITE_PATTERN_BYTES {
        return Err(format!(
            "pattern is longer than {MAX_REWRITE_PATTERN_BYTES} bytes"
        ));
    }
    regex::RegexBuilder::new(pattern)
        .size_limit(REWRITE_REGEX_SIZE_LIMIT)
        .dfa_size_limit(REWRITE_REGEX_SIZE_LIMIT)
        .build()
        .map_err(|err| err.to_string())
}

/// Highest capture group number (`$n`) a rewrite target refers to.
#[must_use]
pub fn highest_capture_reference(target: &str) -> usize {
    let bytes = target.as_bytes();
    let mut highest = 0;
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'$'
            && let Some(d) = bytes.get(i.saturating_add(1))
            && d.is_ascii_digit()
        {
            highest = highest.max(usize::from(d.saturating_sub(b'0')));
        }
    }
    highest
}

fn rewrite_target_rejection(to: &str, groups: usize, absolute_allowed: bool) -> Option<String> {
    if to.len() > MAX_TARGET_TEMPLATE_BYTES {
        return Some("target is longer than 2048 bytes".to_owned());
    }
    if to
        .bytes()
        .any(|b| b.is_ascii_control() || b == b' ' || b == b'\\' || !b.is_ascii())
    {
        return Some(
            "target contains a space, backslash, control or non-ASCII character".to_owned(),
        );
    }
    if highest_capture_reference(to) > groups {
        return Some(format!(
            "target refers to a capture group the pattern does not have ({groups} group(s))"
        ));
    }
    // An internal target becomes the request target, which has no fragment: the HTTP library
    // would drop everything from '#' while route matching would still see it.
    if !absolute_allowed && to.contains('#') {
        return Some("an internal target must not contain '#'".to_owned());
    }
    let after_scheme = to
        .strip_prefix("https://")
        .or_else(|| to.strip_prefix("http://"));
    if let Some(rest) = after_scheme {
        if !absolute_allowed {
            return Some("an internal target must be a path starting with '/'".to_owned());
        }
        let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let host = rest.get(..host_end).unwrap_or("");
        if host.is_empty() || host.contains('@') || host.contains('$') {
            return Some(
                "an absolute target needs a literal host name (no '$n', no user info)".to_owned(),
            );
        }
        return None;
    }
    let mut chars = to.chars();
    if chars.next() != Some('/') {
        return Some(
            "target must start with a single '/' (or http://, https:// for a redirect)".to_owned(),
        );
    }
    if matches!(chars.next(), Some('/' | '$')) {
        return Some(
            "target must start with '/' and a literal character, not '//' or '$n'".to_owned(),
        );
    }
    None
}

/// Returns why a rewrite rule is not acceptable, or `None`.
#[must_use]
pub fn rewrite_rule_rejection(rule: &RewriteRule) -> Option<String> {
    let regex = match compile_rewrite_regex(&rule.pattern) {
        Ok(regex) => regex,
        Err(err) => return Some(format!("invalid pattern: {err}")),
    };
    let groups = regex.captures_len().saturating_sub(1);
    match &rule.action {
        RewriteAction::Internal { to, .. } => {
            if let Some(reason) = rewrite_target_rejection(to, groups, false) {
                return Some(reason);
            }
        }
        RewriteAction::Redirect { to, status, .. } => {
            if !matches!(status, 301 | 302 | 303 | 307 | 308) {
                return Some(format!(
                    "redirect status {status} is not 301, 302, 303, 307 or 308"
                ));
            }
            if let Some(reason) = rewrite_target_rejection(to, groups, true) {
                return Some(reason);
            }
        }
        RewriteAction::Deny(status) => {
            if !matches!(status, 403 | 404 | 410) {
                return Some(format!("deny status {status} is not 403, 404 or 410"));
            }
        }
        RewriteAction::Pass => {}
    }
    if rule.conditions.len() > MAX_REWRITE_CONDITIONS_PER_RULE {
        return Some(format!(
            "more than {MAX_REWRITE_CONDITIONS_PER_RULE} conditions on one rule"
        ));
    }
    for cond in &rule.conditions {
        if let RewriteConditionKind::Header(name) = &cond.kind
            && (name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
        {
            return Some(format!("invalid header name '{name}' in a condition"));
        }
        if cond.kind == RewriteConditionKind::ClientIp {
            if crate::units::IpCidr::parse(&cond.pattern).is_err() {
                return Some(format!(
                    "'{}' is not an IP address or CIDR range",
                    cond.pattern
                ));
            }
            continue;
        }
        if let Err(err) = compile_rewrite_regex(&cond.pattern) {
            return Some(format!(
                "invalid condition pattern '{}': {err}",
                cond.pattern
            ));
        }
    }
    if let Some(query) = &rule.query
        && let Err(err) = compile_rewrite_regex(query)
    {
        return Some(format!("invalid query pattern: {err}"));
    }
    if let Some((name, value)) = &rule.header {
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Some("header condition needs a header name before '='".to_owned());
        }
        if let Err(err) = compile_rewrite_regex(value) {
            return Some(format!("invalid header pattern: {err}"));
        }
    }
    if let Some(method) = &rule.method
        && (method.is_empty() || !method.bytes().all(|b| b.is_ascii_uppercase()))
    {
        return Some("method must be an upper-case token such as GET".to_owned());
    }
    None
}

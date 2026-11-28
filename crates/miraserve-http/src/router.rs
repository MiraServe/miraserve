//! Virtual-host (`Host` / `:authority`) and route matcher compiling [`Config`] into
//! lock-free runtime handlers (`StaticServer`, `ReverseProxy`, `FastCgiClient`, `McpGateway`,
//! `ReleaseStore`, `BotAuthGuard`, GCRA rate limiters, and `SitePresetGuard` WAF presets).

use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use bytes::Bytes;
use http::header::{
    ACCEPT, ACCEPT_ENCODING, ALLOW, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE,
    CONTENT_TYPE, ETAG, HOST, HeaderMap, HeaderName, LOCATION, RETRY_AFTER, VARY,
};
use http::{HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt as _, Limited};
use miraserve_ai::{
    AgentKeyRegistry, BotAuthGuard, BotAuthOutcome, McpGateway, html_to_markdown,
    markdown_sibling_path, prefers_markdown,
};
use miraserve_config::{
    Config, IpCidr, LimitsConfig, PrecompressedPolicy, PublishAuthMode, RouteHandler,
    SecurityHeadersPolicy, SiteConfig, SiteHttpMode, StaticConfig, TlsVersion, normalize_site_host,
    split_extension_path_info,
};
use miraserve_fastcgi::{AnswerTail, FastCgiAnswer, FastCgiClient, FastCgiError, FastCgiRequest};
use miraserve_proxy::{ProxyBody, ProxyError, ProxyGeneratedError, ReverseProxy};
use miraserve_publish::{
    McpPublishAuthContext, ReleaseStore, handle_mcp_publish_http, precheck_mcp_publish_auth,
    try_claim_disk_sync,
};
use miraserve_security::{
    GcraRateLimiter, PresetVerdict, SitePresetGuard, contains_overlong_or_surrogate_utf8,
    is_valid_rfc3986_host_port, validate_host_consistency, validate_request_framing,
    validate_request_target,
};
use miraserve_static::compress::{
    ContentEncoding, MAX_ONTHEFLY_COMPRESS_BYTES, MIN_COMPRESS_BYTES, StreamCompressor,
    accepted_encodings, compress_bytes, is_compressible_mime,
};
use miraserve_static::{StaticServer, TryFilesOutcome};
use miraserve_telemetry::{SecurityBlockReason, TelemetryRegistry};
use miraserve_tls::{AcmeChallengeStore, ClientCertTrust};
use miraserve_wasm::WasmPluginRuntime;
use tokio::sync::Semaphore;
use tracing::warn;

use crate::headers::{alt_svc_header_value, apply_security_headers, redirect_headers};
use crate::pages::{
    CustomErrorPage, DEFAULT_RETRY_AFTER_SECS, ErrorPageContext, MAX_CUSTOM_ERROR_PAGE_BYTES,
    SiteErrorPages, WelcomePageContext, custom_page_content_type, format_http_protocol,
    format_tls_summary, generate_request_id_inline, render_error_response, render_welcome_response,
};
use crate::{
    HttpBody, HttpError, PipeReqBody, PipeRespBody, RequestContext, empty_http_body, full_http_body,
};

/// Prefix for RFC 8555 ACME HTTP-01 validation tokens.
const ACME_HTTP01_PREFIX: &str = "/.well-known/acme-challenge/";

/// Well-known path for OAuth 2.1 Protected Resource Metadata (RFC 9728).
const OAUTH_PROTECTED_RESOURCE_PATH: &str = "/.well-known/oauth-protected-resource";

/// Maximum HTML size converted on-the-fly to Markdown for `Accept: text/markdown` (1 MiB).
const MAX_MARKDOWN_HTML_BYTES: usize = 1024 * 1024;

/// Concurrency cap for blocking HTML->Markdown fallback conversions.
const MAX_CONCURRENT_MARKDOWN_CONVERSIONS: usize = 8;

/// Limits buffered compressions handed from worker loops to the blocking pool (each holds a
/// body of up to 4 MiB), process-wide.
fn worker_compress_semaphore() -> &'static Arc<Semaphore> {
    static SEM: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SEM.get_or_init(|| Arc::new(Semaphore::new(WORKER_LOOP_COMPRESS_JOBS)))
}

/// See [`worker_compress_semaphore`].
const WORKER_LOOP_COMPRESS_JOBS: usize = 8;

fn markdown_semaphore() -> &'static Arc<Semaphore> {
    static SEM: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SEM.get_or_init(|| Arc::new(Semaphore::new(MAX_CONCURRENT_MARKDOWN_CONVERSIONS)))
}

/// Compiled immutable routing table swapped atomically via `ArcSwap` during hot reload.
#[derive(Debug)]
pub struct CompiledRouter {
    sites: Vec<CompiledSite>,
    /// First-match-wins exact host index built at compile time (`normalized_host -> site_idx`).
    site_exact_hosts: HashMap<String, usize>,
    /// First-match-wins single-label wildcard index built at compile time
    /// (`suffix` for configured `"*.<suffix>"` -> `site_idx`).
    site_wildcard_hosts: HashMap<String, usize>,
    /// True if at least one compiled site sets `http "serve"`. When false, redirect-listener
    /// requests bypass the plain-HTTP attribution pass and run the unmodified v0.1.2 responder.
    has_http_serve_site: bool,
    /// True if at least one live site serves static files or inspects a document root (`site.root`,
    /// `ai-publish`, `static`, `try-files`, or `fastcgi` with a script root). Excludes
    /// `acme-webroot` (which uses `openat` off the event loop) and compile-time `error-pages`.
    has_static_work: bool,
    /// The `basic-auth` users files, held open for the life of this configuration: their
    /// identities (refused by static serving) cannot be reused by another file meanwhile, even
    /// after a password file is replaced.
    _credential_handles: Arc<[std::fs::File]>,
    /// The trusted proxies of the SAME configuration as these sites' visitor lists, so one
    /// request never judges a new allow list with an old proxy trust (or the reverse).
    trusted_proxies: Arc<[IpCidr]>,
    /// The sites of this configuration that answer 503 as a whole, as actually compiled.
    offline_sites: Vec<OfflineSite>,
    /// `server.acme-webroot`: an external ACME client's HTTP-01 token directory.
    acme_webroot: Option<std::path::PathBuf>,
    /// Token names of configured credential files in that challenge directory: never answered.
    acme_reserved: std::collections::HashSet<String>,
    /// Identities of the credential files nothing of this configuration ever serves.
    secret_files: Arc<[(u64, u64)]>,
    /// Generation-scoped opt-in static file cache (`None` when disabled everywhere or unused).
    file_cache: Option<Arc<miraserve_static::FileCache>>,
    /// Cached boolean mirror of `file_cache.is_some()` for O(1) ACME-probe gating.
    has_file_cache: bool,
}

/// Why a compiled site answers 503 as a whole, with its warning code: isolated before
/// compiling, failing the final owner-dir check, or a users file that cannot be loaded.
fn offline_reason(
    site: &miraserve_config::SiteConfig,
    compiled: &CompiledSite,
) -> Option<(&'static str, String)> {
    site.quarantine
        .clone()
        .or_else(|| compiled.unavailable.clone())
        .map(|reason| ("W026", reason))
        .or_else(|| {
            compiled
                .basic_auth
                .as_ref()
                .and_then(|auth| auth.load_error())
                .map(|reason| ("W024", reason.to_owned()))
        })
}

/// Users files, the open credential handles, and the identities static serving refuses.
type CredentialInventory = (
    Vec<std::path::PathBuf>,
    Vec<std::fs::File>,
    Arc<[(u64, u64)]>,
    Vec<std::path::PathBuf>,
);

#[derive(Default)]
struct SplitSigningKeys<'a> {
    paths: Vec<&'a str>,
    ids: Vec<(u64, u64)>,
    has_unidentifiable: bool,
}

impl<'a> SplitSigningKeys<'a> {
    fn metadata_id(path: &Path) -> Option<(u64, u64)> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            std::fs::metadata(path)
                .ok()
                .filter(std::fs::Metadata::is_file)
                .map(|m| (m.dev(), m.ino()))
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            None
        }
    }

    fn from_config(config: &'a Config) -> Self {
        let mut out = Self::default();
        if config.server.tls.key_isolation == miraserve_config::KeyIsolation::SplitDaemon {
            for (_, k) in miraserve_config::split_daemon_signing_keys(config) {
                out.paths.push(k);
                if let Some(id) = Self::metadata_id(Path::new(k)) {
                    out.ids.push(id);
                } else {
                    out.has_unidentifiable = true;
                }
            }
        }
        out
    }

    fn matches(&self, path: &Path) -> bool {
        !self.paths.is_empty()
            && (self.paths.iter().any(|k| Path::new(k) == path)
                || (!self.ids.is_empty()
                    && Self::metadata_id(path).is_some_and(|id| self.ids.contains(&id))))
    }
}

/// Every credential file path `config` names: users files, the server's and sites' private keys,
/// and upstream client keys. Returns path names only (it does not open files). The server uses
/// this list to refuse credentials in static responses and reserve their names in an ACME
/// challenge directory, and `check --fs` reports from it; opening and retaining handles happens
/// separately in the credential inventory (which skips configured signing keys and matching
/// entries in `split-daemon` mode and publishes [`miraserve_static::UNIDENTIFIED_CREDENTIAL`]
/// when there is a skipped signing-key match, an open error other than not-found, or a handle
/// whose identity cannot be read).
#[must_use]
pub fn configured_credential_paths(config: &Config) -> Vec<std::path::PathBuf> {
    let mut paths: Vec<std::path::PathBuf> = config
        .sites
        .iter()
        .filter_map(|site| site.basic_auth.as_ref())
        .map(|auth| std::path::PathBuf::from(&auth.users_file))
        .collect();
    paths.extend(config.server.tls.key.iter().map(std::path::PathBuf::from));
    for site in &config.sites {
        paths.extend(
            site.tls
                .as_ref()
                .and_then(|tls| tls.key.as_ref())
                .map(std::path::PathBuf::from),
        );
        for route in &site.routes {
            if let miraserve_config::RouteHandler::ReverseProxy(rp) = &route.handler
                && let Some(key) = rp.upstream_tls.as_ref().and_then(|t| t.client_key.as_ref())
            {
                paths.push(std::path::PathBuf::from(key));
            }
        }
    }
    paths
}

fn credential_inventory(
    config: &Config,
    sources: &CredentialSources,
    read_users_files: Vec<std::fs::File>,
    split_keys: &SplitSigningKeys<'_>,
) -> CredentialInventory {
    let users_files: Vec<std::path::PathBuf> = config
        .sites
        .iter()
        .filter_map(|site| site.basic_auth.as_ref())
        .map(|auth| std::path::PathBuf::from(&auth.users_file))
        .collect();
    let mut secret_paths = configured_credential_paths(config);
    // Credential files named only on the command line (the keyd shared secret) and the files
    // of credential directories (ACME account keys and certificate bundles).
    secret_paths.extend(sources.files.iter().cloned());
    for dir in &sources.dirs {
        collect_files(dir, 4, &mut secret_paths);
    }
    // Each credential is opened once and its handle kept, except configured signing keys (and
    // matching entries) skipped in `split-daemon` mode. One that exists but cannot be opened,
    // or whose identity cannot be read, is unidentified: static serving then refuses every
    // multi-linked file instead (it could be an alias).
    let mut unidentified = false;
    let mut split_skipped = false;
    // The users files as they were read are credentials too, even when replaced since.
    let mut credential_handles = read_users_files;
    for path in &secret_paths {
        if split_keys.matches(path) {
            split_skipped = true;
            continue;
        }
        match std::fs::File::open(path) {
            Ok(file) => credential_handles.push(file),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => unidentified = true,
        }
    }
    let mut secret_files = miraserve_static::handle_identities(&credential_handles);
    if secret_files.len() < credential_handles.len() {
        unidentified = true;
    }
    if unidentified {
        warn!(
            "a configured credential file cannot be opened by the server to learn its identity; \
             files with several hard links are not served until it can"
        );
    }
    if split_skipped {
        warn!(
            "in split-daemon mode the credential inventory skips signing keys; multi-linked \
             files are refused, the file cache is not used, and on Linux descriptor retention \
             falls back to a fresh lookup"
        );
        let mut all = secret_files.to_vec();
        all.extend(&split_keys.ids);
        all.push(miraserve_static::UNIDENTIFIED_CREDENTIAL);
        all.sort_unstable();
        all.dedup();
        secret_files = all.into();
    } else if unidentified {
        let mut with_marker = secret_files.to_vec();
        with_marker.push(miraserve_static::UNIDENTIFIED_CREDENTIAL);
        secret_files = with_marker.into();
    }
    (users_files, credential_handles, secret_files, secret_paths)
}

/// The external ACME webroot of `config` and the token names it must never answer (those of
/// configured credential files in its challenge directory, present or not).
fn acme_webroot_with_reserved(
    config: &Config,
    secret_paths: &[std::path::PathBuf],
) -> (
    Option<std::path::PathBuf>,
    std::collections::HashSet<String>,
) {
    let Some(webroot) = config
        .server
        .acme_webroot
        .as_ref()
        .map(std::path::PathBuf::from)
    else {
        return (None, std::collections::HashSet::new());
    };
    let reserved = miraserve_static::reserved_acme_tokens(
        &webroot.join(".well-known").join("acme-challenge"),
        secret_paths,
    );
    if !reserved.is_empty() {
        tracing::error!(
            acme_webroot = %webroot.display(),
            "configured credential files are named inside the acme-webroot challenge directory; those names are never answered (move the credentials elsewhere)"
        );
    }
    (Some(webroot), reserved)
}

/// Credential files a server knows besides its configuration: files named only on its command
/// line (the keyd shared secret) and directories whose files are all credentials (the ACME
/// state: account keys, certificate bundles). Static serving refuses them like configured
/// credentials. Kept per server (per [`crate::HttpEngine`]).
#[derive(Debug, Clone, Default)]
pub struct CredentialSources {
    /// Individual credential files.
    pub files: Vec<std::path::PathBuf>,
    /// Directories whose regular files (a few levels deep) are credentials.
    pub dirs: Vec<std::path::PathBuf>,
}

/// Regular files under `dir` (not following links), `depth` levels deep, at most 10 000.
fn collect_files(dir: &std::path::Path, depth: u32, out: &mut Vec<std::path::PathBuf>) {
    const MAX_FILES: usize = 10_000;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if out.len() >= MAX_FILES {
            return;
        }
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_file() {
            out.push(entry.path());
        } else if kind.is_dir() && depth > 0 {
            collect_files(&entry.path(), depth - 1, out);
        }
    }
}

/// A site that the active configuration serves as a 503 (isolated tenant site).
#[derive(Debug, Clone)]
pub struct OfflineSite {
    /// Position of the site in the configuration (`site[index]`).
    pub index: usize,
    /// The site's first host name.
    pub host: String,
    /// `W026` (isolated tenant site) or `W024` (its users file cannot be loaded).
    pub code: &'static str,
    /// Why it is offline.
    pub reason: String,
}

#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)] // independent compiled per-site capability/state flags
struct CompiledSite {
    hosts: Vec<String>,
    allows_tls_1_2: bool,
    security_headers: SecurityHeadersPolicy,
    http_mode: SiteHttpMode,
    http_credentials: bool,
    precompressed: PrecompressedPolicy,
    /// Shared with the next configuration when the preset stays (its login throttle counts on).
    preset_guard: Option<Arc<SitePresetGuard>>,
    preset: Option<miraserve_config::SitePreset>,
    bot_auth: Option<BotAuthGuard>,
    rate_limit: Option<Limiter>,
    default_static: Option<StaticServer>,
    /// Post-static response header key budget for `default_static` and `ai_publish` release servers.
    default_static_extra_headers: usize,
    /// True when `site.root` was configured but could not be opened on disk (e.g. deleted or
    /// unreadable tenant directory); isolates ONLY this site to `503` without failing start/reload.
    default_static_unavailable: bool,
    ai_publish: Option<CompiledAiPublish>,
    /// Per-site strict mTLS client-certificate trust verifier (bound strictly to THIS site's
    /// `site.tls.client-ca`, falling back to global `server.tls.client-ca` only when unset).
    client_cert_trust: Option<ClientCertTrust>,
    /// Lowercased file extensions (e.g. `".php"`) refused by static handlers as defense-in-depth
    /// (`PATH-1`), always including default PHP extensions plus any site FastCGI extensions.
    fastcgi_extensions: Vec<String>,
    /// Lowercased file extensions actively handled by at least one `FastCgi` route on this site
    /// (empty on static-only sites so directory indexes never treat PHP files as live scripts).
    routed_fastcgi_extensions: Vec<String>,
    /// True when `site.default_static`'s index list includes an actively routed FastCGI script
    /// extension (e.g. `index.php` with `route "*.php"`), so directory/extensionless paths on the
    /// default root are classified `StreamExec::Spawn`.
    default_static_has_script_index: bool,
    /// Whether a FastCGI route runs a path (for the index of a directory under `try-files`).
    runs_script: RunsScript,
    /// Per-site custom error page overrides and optional `401` sign-in URL.
    error_pages: SiteErrorPages,
    /// `rewrite { rule ... }` rules, applied once before the site's guards and routes.
    rewrites: crate::rewrite::CompiledRewrites,
    /// `headers { ... }` of the site, applied to every response of the site.
    headers: Arc<[CompiledHeaderRule]>,
    /// `access { ... }` of the site: visitor address allow/deny, first match decides.
    access: Arc<[AccessLine]>,
    /// `basic-auth` of the site.
    basic_auth: Option<Arc<crate::basic_auth::CompiledBasicAuth>>,
    /// Why this site answers 503 to everything: an unsafe document root found when loading, or
    /// a root that is not really inside the site's `owner-dir`.
    unavailable: Option<String>,
    /// Identities of the credential files no static server of this site ever serves.
    secret_files: Arc<[(u64, u64)]>,
    /// Whether any route of this site defines configurable `headers { ... }` rules.
    /// When `false`, static `try-files` fallback header-owner lookup is skipped completely.
    has_route_headers: bool,
    /// Counts static `try-files` fallback header-owner lookups on this site (tests only).
    #[cfg(test)]
    fallback_header_lookups: std::sync::atomic::AtomicUsize,
    /// Generation-scoped opt-in file cache attached to this site (`None` when off for this site).
    file_cache: Option<Arc<miraserve_static::FileCache>>,
    /// Cached boolean mirror of `file_cache.is_some()`, tested once per request at site dispatch.
    has_file_cache: bool,
    routes: Vec<CompiledRoute>,
}

/// Pre-first-filesystem-access snapshot carried across router stages and internal rewrites for
/// cache-enabled sites (never inserted on sites without `file-cache`).
#[derive(Clone, Copy)]
struct CarriedFillStart(miraserve_static::FillStart);

/// Marks a request on a cache-enabled site that must bypass both file-cache hits and admissions
/// (for example, because the original request carried `Range` or `If-Range`, or because an
/// earlier filesystem probe could not carry its timestamp). Never inserted when `file-cache` is
/// off.
#[derive(Clone, Copy)]
struct RequestCacheBypass;

/// Marks a request on a cache-enabled site that made a filesystem access before a fill timestamp
/// was sampled (for example, an ACME webroot lookup that missed and fell through to the site):
/// fresh cache hits remain unaffected, while misses serve live from disk and MUST NOT admit.
/// Never inserted when `file-cache` is off.
#[derive(Clone, Copy)]
struct RequestCacheNoAdmit;

#[cfg(test)]
use std::sync::atomic::Ordering;

#[cfg(test)]
type RouterHostTestHook = Arc<dyn Fn(&str) + Send + Sync>;

#[cfg(test)]
static ACME_WEBROOT_PROBE_TEST_HOOK: std::sync::RwLock<Option<RouterHostTestHook>> =
    std::sync::RwLock::new(None);

#[cfg(test)]
static AFTER_REWRITES_TEST_HOOK: std::sync::RwLock<Option<RouterHostTestHook>> =
    std::sync::RwLock::new(None);

#[cfg(test)]
static ROUTER_CACHE_SITE_BRANCH_HITS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
static ROUTER_CACHE_LOOKUP_OR_ADMIT_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
static ROUTER_ACME_PROBED_FS_SET: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Lightweight per-request metadata snapshot used to render content-negotiated MiraServe
/// error pages even after the full `Request<HttpBody>` has been moved into a handler.
#[derive(Debug, Clone)]
/// Lightweight snapshot of the request's `Accept` header(s) that avoids allocating a `HeaderMap`
/// on every request when no error or welcome page is rendered.
enum AcceptHeaders {
    None,
    Single(HeaderValue),
    Many(Vec<HeaderValue>),
}

impl AcceptHeaders {
    fn from_headers(headers: &HeaderMap) -> Self {
        let mut iter = headers.get_all(ACCEPT).iter();
        let Some(first) = iter.next() else {
            return Self::None;
        };
        let Some(second) = iter.next() else {
            return Self::Single(first.clone());
        };
        let mut all = Vec::with_capacity(4);
        all.push(first.clone());
        all.push(second.clone());
        for val in iter {
            all.push(val.clone());
        }
        Self::Many(all)
    }

    fn to_header_map(&self) -> HeaderMap {
        match self {
            Self::None => HeaderMap::new(),
            Self::Single(val) => {
                let mut map = HeaderMap::with_capacity(1);
                map.insert(ACCEPT, val.clone());
                map
            }
            Self::Many(vals) => {
                // All duplicate `Accept` values share one HeaderMap key slot; reserving by
                // `vals.len()` would reserve key slots and panic above `HeaderMap`'s key cap.
                let mut map = HeaderMap::with_capacity(1);
                for val in vals {
                    map.append(ACCEPT, val.clone());
                }
                map
            }
        }
    }
}

struct ErrorMeta<'a> {
    method: Method,
    path: &'a str,
    host: Option<Cow<'a, str>>,
    accept_headers: AcceptHeaders,
    request_id: &'a str,
}

impl<'a> ErrorMeta<'a> {
    fn from_request<B>(
        req: &Request<B>,
        path: &'a str,
        host: Option<Cow<'a, str>>,
        request_id: &'a str,
    ) -> Self {
        Self {
            method: req.method().clone(),
            path,
            host,
            accept_headers: AcceptHeaders::from_headers(req.headers()),
            request_id,
        }
    }

    fn render_error(
        &self,
        status: StatusCode,
        retry_after_secs: Option<u64>,
        site_pages: Option<&SiteErrorPages>,
    ) -> Response<PipeRespBody> {
        let accept = self.accept_headers.to_header_map();
        render_error_response(
            &accept,
            &ErrorPageContext {
                status,
                method: &self.method,
                path: self.path,
                host: self.host.as_deref(),
                request_id: self.request_id,
                retry_after_secs,
                site_pages,
            },
        )
        .map(PipeRespBody::Boxed)
    }

    fn framing_error(&self, status: StatusCode) -> Response<PipeRespBody> {
        let mut resp = self.render_error(status, None, None);
        resp.extensions_mut().insert(crate::ServerFramingRejection);
        resp
    }

    fn rate_limit_error(
        &self,
        retry_after_secs: u64,
        limit: u32,
        remaining: u32,
        site_pages: Option<&SiteErrorPages>,
    ) -> Response<PipeRespBody> {
        let secs = retry_after_secs.max(1);
        let mut resp = self.render_error(StatusCode::TOO_MANY_REQUESTS, Some(secs), site_pages);
        resp.extensions_mut().insert(ServerThrottle);
        if let Ok(v) = HeaderValue::from_str(&limit.to_string()) {
            resp.headers_mut()
                .insert(HeaderName::from_static("x-ratelimit-limit"), v);
        }
        if let Ok(v) = HeaderValue::from_str(&remaining.to_string()) {
            resp.headers_mut()
                .insert(HeaderName::from_static("x-ratelimit-remaining"), v);
        }
        resp
    }

    /// Replaces a MiraServe-generated static or proxy error response (`4xx`/`5xx`) with a full
    /// content-negotiated built-in (or site-custom) error page while preserving protocol headers
    /// such as `Allow`, `Content-Range`, and `Retry-After`.
    fn upgrade_generated_error(
        &self,
        resp: Response<PipeRespBody>,
        site_pages: Option<&SiteErrorPages>,
    ) -> Response<PipeRespBody> {
        let status = resp.status();
        if !(status.is_client_error() || status.is_server_error()) {
            return resp;
        }
        let allow = resp.headers().get(ALLOW).cloned();
        let content_range = resp.headers().get(CONTENT_RANGE).cloned();
        let retry_after = resp
            .headers()
            .get(RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok());

        let mut rendered = self.render_error(status, retry_after, site_pages);
        if let Some(val) = allow {
            rendered.headers_mut().insert(ALLOW, val);
        }
        if let Some(val) = content_range {
            rendered.headers_mut().insert(CONTENT_RANGE, val);
        }
        rendered
    }
}

impl CompiledSite {
    /// Verifies a TLS/QUIC peer certificate chain strictly against THIS site's `client-ca`
    /// trust verifier (preventing cross-site mTLS CA confusion on both TCP and QUIC/HTTP/3).
    fn verify_mtls_peer(&self, tls: Option<&crate::TlsConnectionInfo>) -> Option<String> {
        let trust = self.client_cert_trust.as_ref()?;
        let chain = tls?.peer_cert_chain_der.as_deref()?;
        trust.verify_peer_chain(chain)
    }
}

#[derive(Debug)]
struct CompiledAiPublish {
    store: Arc<ReleaseStore>,
    mcp_endpoint: Option<(String, PublishAuthMode)>,
}

/// A rate limiter and the settings it was made from. A reload that leaves the settings of a
/// site's or route's limit unchanged keeps the limiter, so a visitor who is throttled is not
/// let in again by an unrelated configuration change.
#[derive(Debug)]
struct Limiter {
    config: miraserve_config::RateLimitConfig,
    inner: Arc<GcraRateLimiter>,
}

impl Limiter {
    fn from_config(config: &miraserve_config::RateLimitConfig) -> Self {
        Self {
            config: config.clone(),
            inner: Arc::new(GcraRateLimiter::from_config(config)),
        }
    }

    /// Takes over `previous`'s counts when both have the same settings.
    fn inherit(limit: &mut Option<Self>, previous: Option<&Self>) {
        if let (Some(limit), Some(previous)) = (limit, previous)
            && limit.config == previous.config
        {
            limit.inner = Arc::clone(&previous.inner);
        }
    }
}

impl std::ops::Deref for Limiter {
    type Target = GcraRateLimiter;
    fn deref(&self) -> &GcraRateLimiter {
        &self.inner
    }
}

#[derive(Debug)]
struct CompiledRoute {
    matcher: RouteMatcher,
    /// The pattern as configured (what tells routes apart across a reload).
    pattern: String,
    security_headers: Option<SecurityHeadersPolicy>,
    rate_limit: Option<Limiter>,
    handler: CompiledHandler,
    /// For a `reverse-proxy { strip-prefix #true }` route: the literal prefix (`"/tool"` for
    /// `"/tool/*"`) removed from the request path before forwarding.
    proxy_strip_prefix: Option<String>,
    /// `headers { ... }` of the route, applied after the site's.
    headers: Arc<[CompiledHeaderRule]>,
    /// Cached boolean indicating whether this route's handler has an attached opt-in file cache.
    has_file_cache: bool,
}

/// Decides whether `basic-auth` and OAuth/JWT `mcp-gateway` routes may challenge for and
/// evaluate credentials on this transport.
///
/// Always allowed over HTTPS (`is_https == true`). Over plain HTTP (`is_https == false`),
/// MiraServe refuses the request with `403 Forbidden` (no `WWW-Authenticate`, no credential or
/// token evaluation) unless the site explicitly opted in via `http "serve" credentials=#true`.
/// Centralized in this one function; nothing else branches on plain-HTTP credential policy.
const fn allow_credentials_on_transport(is_https: bool, site: &CompiledSite) -> bool {
    is_https || (matches!(site.http_mode, SiteHttpMode::Serve) && site.http_credentials)
}

/// Checks a `basic-auth` area. `None` when the request may continue; otherwise the answer:
/// 403 over plain HTTP unless the site opted in via `http "serve" credentials=#true`, 401 with
/// the challenge, 429 after too many failures, or 503 when the area cannot check.
/// Protected answers are never stored by shared caches.
async fn basic_auth_refusal<B>(
    auth: &crate::basic_auth::CompiledBasicAuth,
    req: &Request<B>,
    client_ip: Option<std::net::IpAddr>,
    err_meta: &ErrorMeta<'_>,
    site: &CompiledSite,
    is_https: bool,
) -> Option<Response<PipeRespBody>> {
    use crate::basic_auth::AuthDecision;
    // The built-in page: a configured error page is site content the visitor has not been
    // allowed to see yet.
    let _ = &site.error_pages;
    if !allow_credentials_on_transport(is_https, site) {
        let mut resp = err_meta.render_error(StatusCode::FORBIDDEN, None, None);
        resp.headers_mut().insert(
            http::header::CACHE_CONTROL,
            http::HeaderValue::from_static("no-store"),
        );
        resp.extensions_mut().insert(ProtectedResponse);
        resp.extensions_mut().insert(StripWwwAuthenticate);
        return Some(resp);
    }
    let credentials = credentials_of(req);
    let status = match auth.check(&credentials, client_ip).await {
        AuthDecision::Allowed => return None,
        AuthDecision::Denied => StatusCode::UNAUTHORIZED,
        AuthDecision::Throttled => StatusCode::TOO_MANY_REQUESTS,
        AuthDecision::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
    };
    // A throttled address waits until its counted failures are dropped.
    let retry_after =
        (status == StatusCode::TOO_MANY_REQUESTS).then(|| auth.retry_after_secs(client_ip));
    let mut resp = err_meta.render_error(status, retry_after, None);
    if status == StatusCode::UNAUTHORIZED {
        resp.headers_mut()
            .insert(http::header::WWW_AUTHENTICATE, auth.challenge());
    }
    resp.headers_mut().insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    resp.extensions_mut().insert(ProtectedResponse);
    if status == StatusCode::TOO_MANY_REQUESTS {
        resp.extensions_mut().insert(ServerThrottle);
    }
    Some(resp)
}

/// Marks a 429 produced by MiraServe's own throttles (login attempts, rate limits): its
/// `Retry-After` is the server's and survives configured header rules. Upstream responses
/// never carry it, so operator rules keep controlling theirs.
#[derive(Debug, Clone, Copy)]
struct ServerThrottle;

/// The `Authorization` values MiraServe checked for a `basic-auth` area, kept here after the
/// header itself is removed so the password never reaches PHP, a proxied application or a
/// WebAssembly component.
#[derive(Debug, Clone)]
struct ServerAuthCredentials(Vec<http::HeaderValue>);

/// The credentials a request carries for MiraServe's own `basic-auth` checks.
fn credentials_of<B>(req: &Request<B>) -> Vec<http::HeaderValue> {
    match req.extensions().get::<ServerAuthCredentials>() {
        Some(kept) => kept.0.clone(),
        None => crate::basic_auth::authorization_values(req.headers()),
    }
}

/// Records that a `basic-auth` area consumed the request's credentials. The header stays for
/// MiraServe's own later checks (rewrite conditions, bot signatures, limiters) and is removed by
/// [`strip_consumed_credentials`] when the request is handed to PHP, a proxy or WebAssembly.
fn consume_server_credentials<B>(req: &mut Request<B>) {
    if req.extensions().get::<ServerAuthCredentials>().is_none() {
        let kept = crate::basic_auth::authorization_values(req.headers());
        req.extensions_mut().insert(ServerAuthCredentials(kept));
    }
}

/// Removes credentials a `basic-auth` area consumed, at the hand-off to an application.
fn strip_consumed_credentials<B>(req: &mut Request<B>) {
    if req.extensions().get::<ServerAuthCredentials>().is_some() {
        req.headers_mut().remove(http::header::AUTHORIZATION);
    }
}

/// Marks a response produced inside an access-controlled area: it must not be stored by shared
/// caches (see the finalizer).
#[derive(Debug, Clone, Copy)]
struct ProtectedResponse;

/// Marks a plaintext credential refusal (`403`) that must never carry `WWW-Authenticate`,
/// whatever site or route `headers` rules add (stripped in the finalizer).
#[derive(Debug, Clone, Copy)]
struct StripWwwAuthenticate;

/// A response of an access-controlled area may be kept by the visitor's browser but never by a
/// shared cache: `public` and `s-maxage` are dropped and `private` added.
fn make_private(headers: &mut http::HeaderMap) {
    let existing = headers
        .get_all(http::header::CACHE_CONTROL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|d| {
            let name = d
                .split('=')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            !d.is_empty() && name != "public" && name != "s-maxage" && name != "private"
        })
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let mut value = String::from("private");
    for directive in existing {
        value.push_str(", ");
        value.push_str(&directive);
    }
    if let Ok(value) = http::HeaderValue::from_str(&value) {
        headers.insert(http::header::CACHE_CONTROL, value);
    }
}

/// Request extension carrying [`policy_client_ip`] to the handlers.
#[derive(Debug, Clone, Copy)]
struct PolicyClientIp(Option<IpAddr>);

/// The [`PolicyClientIp`] of a request (unknown when absent).
fn policy_ip_of<B>(req: &Request<B>) -> Option<IpAddr> {
    req.extensions().get::<PolicyClientIp>().and_then(|p| p.0)
}

/// The visitor address used for allow/deny decisions (see
/// [`miraserve_proxy::resolve_established_client_ip`]): unknown, never a proxy's own address or
/// one beyond an unnamed hop, when the forwarding chain does not establish it.
fn policy_client_ip(
    peer: Option<IpAddr>,
    trusted_proxies: &[IpCidr],
    headers: &http::HeaderMap,
) -> Option<IpAddr> {
    miraserve_proxy::resolve_established_client_ip(peer, headers, trusted_proxies)
}

/// One `allow`/`deny` line; `None` is `"all"`.
#[derive(Debug, Clone, Copy)]
struct AccessLine {
    allow: bool,
    source: Option<IpCidr>,
}

fn compile_access(rules: &[miraserve_config::AccessRule]) -> Result<Arc<[AccessLine]>, HttpError> {
    let mut compiled = Vec::with_capacity(rules.len());
    for rule in rules {
        let source = if rule.source == "all" {
            None
        } else {
            Some(IpCidr::parse(&rule.source).map_err(|_| {
                HttpError::Router(format!("invalid access source '{}'", rule.source))
            })?)
        };
        compiled.push(AccessLine {
            allow: rule.allow,
            source,
        });
    }
    Ok(Arc::from(compiled))
}

/// Whether the visitor may proceed: the first line that matches decides, and a visitor no line
/// matches is allowed (as in Nginx). Without a known address only `all` lines can match.
fn access_allows(lines: &[AccessLine], ip: Option<IpAddr>) -> bool {
    for line in lines {
        let matches = match (line.source, ip) {
            (None, _) => true,
            (Some(cidr), Some(ip)) => cidr.contains(ip),
            // The visitor's address is not known (a trusted proxy sent no usable
            // X-Forwarded-For): a list that names addresses cannot be decided, so refuse.
            (Some(_), None) => return false,
        };
        if matches {
            return line.allow;
        }
    }
    true
}

/// Action of a compiled response header change.
#[derive(Debug, Clone)]
enum CompiledHeaderAction {
    Set(HeaderName, HeaderValue),
    Add(HeaderName, HeaderValue),
    Remove(HeaderName),
}

/// A response header change, ready to apply.
#[derive(Debug, Clone)]
struct CompiledHeaderRule {
    action: CompiledHeaderAction,
    /// Optional status condition; empty matches every response status.
    status: Box<[miraserve_config::HeaderStatusMatcher]>,
}

impl CompiledHeaderRule {
    fn matches_status(&self, status: StatusCode) -> bool {
        self.status.is_empty()
            || self
                .status
                .iter()
                .any(|matcher| matcher.matches(status.as_u16()))
    }
}

fn compile_header_rules(
    rules: &[miraserve_config::HeaderRule],
) -> Result<Arc<[CompiledHeaderRule]>, HttpError> {
    use miraserve_config::HeaderAction;

    let mut compiled = Vec::with_capacity(rules.len());
    for rule in rules {
        let name = HeaderName::from_bytes(rule.name.as_bytes())
            .map_err(|_| HttpError::Router(format!("invalid header name '{}'", rule.name)))?;
        let value = || {
            HeaderValue::from_str(rule.value.as_deref().unwrap_or(""))
                .map_err(|_| HttpError::Router(format!("invalid value for header '{}'", rule.name)))
        };
        let action = match rule.action {
            HeaderAction::Set => CompiledHeaderAction::Set(name, value()?),
            HeaderAction::Add => CompiledHeaderAction::Add(name, value()?),
            HeaderAction::Remove => CompiledHeaderAction::Remove(name),
        };
        compiled.push(CompiledHeaderRule {
            action,
            status: rule.status.clone().into_boxed_slice(),
        });
    }
    Ok(Arc::from(compiled))
}

fn apply_header_rules(headers: &mut HeaderMap, status: StatusCode, rules: &[CompiledHeaderRule]) {
    for rule in rules {
        if !rule.matches_status(status) {
            continue;
        }
        match &rule.action {
            CompiledHeaderAction::Set(name, value) => {
                headers.insert(name.clone(), value.clone());
            }
            CompiledHeaderAction::Add(name, value) => {
                headers.append(name.clone(), value.clone());
            }
            CompiledHeaderAction::Remove(name) => {
                headers.remove(name);
            }
        }
    }
}

/// Counts distinct response header names that `Set` / `Add` rules in `site_rules` and
/// `route_rules` can insert (excluding `server` and `alt-svc`, which are already accounted for in
/// [`crate::headers::security_header_slot_budget`]).
fn distinct_header_rule_keys(
    site_rules: &[CompiledHeaderRule],
    route_rules: &[CompiledHeaderRule],
) -> usize {
    let mut distinct_rule_keys: Vec<&HeaderName> =
        Vec::with_capacity(site_rules.len().saturating_add(route_rules.len()));
    for rule in site_rules.iter().chain(route_rules.iter()) {
        let name = match &rule.action {
            CompiledHeaderAction::Set(name, _) | CompiledHeaderAction::Add(name, _) => name,
            CompiledHeaderAction::Remove(_) => continue,
        };
        if *name == http::header::SERVER || *name == http::header::ALT_SVC {
            continue;
        }
        if !distinct_rule_keys.contains(&name) {
            distinct_rule_keys.push(name);
        }
    }
    distinct_rule_keys.len()
}

/// Compile-time upper bound on additional `HeaderMap` capacity needed after static response
/// construction so `apply_security_headers`, `apply_header_rules`, router server-owned header
/// restores (`Alt-Svc` re-insertion), and `make_private` (`Cache-Control`) never grow the map.
///
/// Includes `+ 1` headroom because pinned `http::HeaderMap::{insert, append, entry}` calls
/// `try_reserve_one()` BEFORE resolving whether the key is already occupied; without `+ 1`, a map
/// filled to exact capacity (such as a routed HTTPS 200 with 6 file headers + Standard security +
/// Alt-Svc = 12 keys, or a repeated `add` at exact capacity) would grow on the subsequent restore
/// or append.
const fn extra_static_response_header_budget_with_rules(
    policy: SecurityHeadersPolicy,
    distinct_rule_keys: usize,
    may_add_cache_control: bool,
) -> usize {
    crate::headers::security_header_slot_budget(policy)
        .saturating_add(distinct_rule_keys)
        .saturating_add(if may_add_cache_control { 1 } else { 0 })
        .saturating_add(1)
}

#[cfg(test)]
fn extra_static_response_header_budget(
    policy: SecurityHeadersPolicy,
    site_rules: &[CompiledHeaderRule],
    route_rules: &[CompiledHeaderRule],
    may_add_cache_control: bool,
) -> usize {
    extra_static_response_header_budget_with_rules(
        policy,
        distinct_header_rule_keys(site_rules, route_rules),
        may_add_cache_control,
    )
}

/// Response extension: the header changes of the route that produced the response (`None` when
/// answered by no route or by a route with no `headers` rules, avoiding an empty `Arc` allocation),
/// applied after the site's in [`CompiledRouter::dispatch_with_request_id`]. A marker holding
/// `None` is still a marker: the step that restores the fields the server owns runs for it.
#[derive(Clone)]
struct RouteHeaderRules(Option<Arc<[CompiledHeaderRule]>>);

impl CompiledRoute {
    fn matches_path(&self, canonical_path: &str) -> bool {
        let runs_scripts = matches!(self.handler, CompiledHandler::FastCgi { .. });
        route_matches(&self.matcher, runs_scripts, canonical_path)
    }

    fn split_fastcgi_script_and_path_info<'a>(
        &self,
        canonical_path: &'a str,
    ) -> Option<(&'a str, &'a str)> {
        if let RouteMatcher::Extension(ext) = &self.matcher {
            split_extension_path_info(canonical_path, ext)
        } else if canonical_path.ends_with('/') {
            None
        } else {
            Some((canonical_path, ""))
        }
    }
}

/// Whether a route with `matcher` (one that runs scripts or not) takes `canonical_path`.
fn route_matches(matcher: &RouteMatcher, runs_scripts: bool, canonical_path: &str) -> bool {
    if runs_scripts && let RouteMatcher::Extension(ext) = matcher {
        return split_extension_path_info(canonical_path, ext).is_some();
    }
    matcher.matches(canonical_path)
}

/// The routes of a site, to decide whose a directory's script index is
/// ([`miraserve_static::ScriptOwner`]): each with whether it is FastCGI, which decides how
/// its pattern matches a script's path.
struct RunsScript(Arc<Vec<(RouteMatcher, bool)>>);

impl std::fmt::Debug for RunsScript {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RunsScript")
    }
}

impl RunsScript {
    /// Whether a script index is handed on, asked by the route at `asking` (its place among
    /// the site's routes). As in v0.1.0 it goes to the route that takes its path, whatever
    /// that route answers (FastCGI runs it, a file route refuses it with 404). It is skipped,
    /// and the next index served, only when nothing else takes it: no route does, or the very
    /// `try-files` route that is looking for the index (the leftover `index.php` of the
    /// audit, which v0.1.0 turned into a 404 for the whole directory).
    fn asked_by(&self, asking: Option<usize>) -> miraserve_static::ScriptOwner {
        let routes = Arc::clone(&self.0);
        Arc::new(move |path: &str| {
            let owner = routes
                .iter()
                .position(|(matcher, fastcgi)| route_matches(matcher, *fastcgi, path));
            owner.is_some() && owner != asking
        })
    }
}

#[derive(Debug)]
enum CompiledHandler {
    Static {
        static_server: StaticServer,
        /// True when this static route's effective index list includes an actively routed FastCGI
        /// script extension (e.g. `index.php` on a site with a `*.php` FastCGI route).
        has_script_index: bool,
    },
    TryFiles {
        static_server: StaticServer,
        candidates: Vec<String>,
        /// True when the `try-files` fallback target (or directory script index) can dispatch to a
        /// waiting handler (`FastCgi`, `ReverseProxy`, `WasmPlugin`, `McpGateway`, or publish
        /// endpoint). Computed once at router compile time so WordPress-style front controllers
        /// keep extensioned static assets in-task while spawning extensionless/non-read requests.
        fallback_spawns: bool,
    },
    FastCgi {
        client: FastCgiClient,
        /// Optional `cap-std` docroot used to verify the script file exists before invoking PHP-FPM (`PATH-6`).
        script_root: Option<StaticServer>,
    },
    ReverseProxy(Arc<ReverseProxy>),
    McpGateway(Arc<McpGateway>),
    WasmPlugin(Arc<WasmPluginRuntime>),
    /// Fixed status answered with the site's error page for it (`respond 503`).
    Respond(StatusCode),
    Redirect {
        status: StatusCode,
        target: String,
        /// Literal prefix of the route pattern (`"/old"` for `"/old/*"`, empty for `"/*"`),
        /// used to compute `{rest}`.
        route_prefix: String,
    },
    /// Tenant-owned route file or directory (root or WASM module) could not be opened on disk;
    /// serves `503 Service Unavailable` for this route only without failing startup/reload for
    /// healthy sibling routes or sites (`HANDOVER §5 #9`).
    Unavailable,
}

/// Returns `true` when the last path segment looks like a filename with an extension (e.g.
/// `/assets/app.css`, `/img/hero.webp`), and `false` for directories (`/`, `/about/`),
/// extensionless routes (`/about`, `/wp-json/wp/v2/posts`), hidden dotfiles (`/.env`), or trailing
/// dots (`/foo.`). Pure byte scan, zero allocation.
#[inline]
fn path_has_file_extension(canonical_path: &str) -> bool {
    if canonical_path.ends_with('/') {
        return false;
    }
    let last_seg = match canonical_path.rsplit_once('/') {
        Some((_, seg)) => seg,
        None => canonical_path,
    };
    match last_seg.rfind('.') {
        Some(dot) => dot > 0 && dot + 1 < last_seg.len(),
        None => false,
    }
}

/// Returns whether a compiled handler always waits on another task / upstream / runtime and must
/// run as its own spawned Tokio task (`StreamExec::Spawn`).
///
/// Exhaustive over [`CompiledHandler`] with NO wildcard arm so adding a new handler fails to
/// compile until its HTTP/2 execution class is decided.
const fn handler_always_spawns(handler: &CompiledHandler) -> bool {
    match handler {
        CompiledHandler::ReverseProxy(_)
        | CompiledHandler::FastCgi { .. }
        | CompiledHandler::WasmPlugin(_)
        | CompiledHandler::McpGateway(_) => true,
        CompiledHandler::Static { .. }
        | CompiledHandler::TryFiles { .. }
        | CompiledHandler::Respond(_)
        | CompiledHandler::Redirect { .. }
        | CompiledHandler::Unavailable => false,
    }
}

/// Statically decides at router compile time whether the fallback (last candidate) of a
/// `try-files` route at `route_idx` can dispatch to a waiting handler (`FastCgi`, `ReverseProxy`,
/// `WasmPlugin`, `McpGateway`, or `ai-publish.mcp-endpoint`).
///
/// Exhaustive over [`CompiledHandler`] with NO wildcard arm.
fn try_files_last_candidate_spawns(
    route_idx: usize,
    candidates: &[String],
    routes: &[CompiledRoute],
    ai_publish: Option<&CompiledAiPublish>,
    site_has_waiting_handler: bool,
) -> bool {
    let Some(last) = candidates.last() else {
        return false;
    };
    if last.starts_with('=') {
        return false;
    }
    let last_path = last.split_once('?').map_or(last.as_str(), |(p, _)| p);
    if last_path.contains('{') {
        // Dynamic fallback template (e.g. `{path}`): cannot resolve target route statically; fall
        // back to the safe side whenever the site has any waiting handler.
        return site_has_waiting_handler;
    }
    let Some((canonical_last, _)) = canonicalize_request_path_with_flags(last_path) else {
        return false;
    };
    let target = canonical_last.as_ref();
    if ai_publish
        .and_then(|p| p.mcp_endpoint.as_ref())
        .is_some_and(|(ep, _)| ep == target)
    {
        return true;
    }
    match routes
        .iter()
        .enumerate()
        .find(|(_, r)| r.matches_path(target))
    {
        None => false,
        // Originating `try-files` route serves its own fallback terminally as a static file.
        Some((owner_idx, _)) if owner_idx == route_idx => false,
        Some((_, owner)) => match &owner.handler {
            CompiledHandler::ReverseProxy(_)
            | CompiledHandler::FastCgi { .. }
            | CompiledHandler::WasmPlugin(_)
            | CompiledHandler::McpGateway(_) => true,
            CompiledHandler::TryFiles { .. } => site_has_waiting_handler,
            CompiledHandler::Static { .. }
            | CompiledHandler::Respond(_)
            | CompiledHandler::Redirect { .. }
            | CompiledHandler::Unavailable => false,
        },
    }
}

/// `REQUEST_URI` for FastCGI. After an internal rewrite it is still what the visitor asked for
/// (as Apache and Nginx do); applications such as WordPress route on it.
fn fastcgi_request_uri(parts: &http::request::Parts) -> &str {
    parts.extensions.get::<OriginalRequestTarget>().map_or_else(
        || {
            parts
                .uri
                .path_and_query()
                .map_or("/", http::uri::PathAndQuery::as_str)
        },
        |original| original.0.as_str(),
    )
}

/// The request target as the visitor sent it, kept across an internal rewrite.
#[derive(Debug, Clone)]
struct OriginalRequestTarget(String);

/// Turns the result of an internal rewrite rule into the request's new URI and normalised path.
///
/// The target is parsed **once** into a URI, and the path, its flags and the query that every
/// later step uses are all read from that one parsed URI, so route matching and the handler
/// can never see different paths. The target has to pass the rules a client's own request
/// target passes ([`validate_request_target`]: length, control bytes, backslashes, raw and
/// decoded dot-segments including matrix parameters), must not carry a fragment (the HTTP
/// library would drop it silently), and goes through the same normalisation as every request.
///
/// The strict-path flags of the visitor's original path are kept in addition to the target's
/// own: an encoded `/` or invalid UTF-8 that a filesystem route would refuse directly is still
/// refused when it arrives through an alias.
///
/// Returns `None` (answered with 400) when any of this fails.
fn rewritten_request_target(
    current: &http::Uri,
    target: &str,
    original_flags: PathFlags,
) -> Option<(http::Uri, String, PathFlags)> {
    if target.contains('#') || validate_request_target(target).is_err() {
        return None;
    }
    let mut parts = current.clone().into_parts();
    parts.path_and_query = Some(target.parse().ok()?);
    let uri = http::Uri::from_parts(parts).ok()?;
    if !uri.path().starts_with('/') {
        return None;
    }
    let (canonical, flags) = canonicalize_request_path_with_flags(uri.path())?;
    let canonical = canonical.into_owned();
    let merged = PathFlags {
        has_encoded_slash: flags.has_encoded_slash || original_flags.has_encoded_slash,
        has_malformed_percent: flags.has_malformed_percent || original_flags.has_malformed_percent,
        has_invalid_utf8: flags.has_invalid_utf8 || original_flags.has_invalid_utf8,
    };
    Some((uri, canonical, merged))
}

/// Removes a route's literal `prefix` from a request URI for `strip-prefix` reverse-proxy routes:
/// `/tool/a/b?x=1` with prefix `/tool` becomes `/a/b?x=1`, and `/tool` becomes `/`. The result
/// always starts with exactly one `/`. Returns `None` when the path as sent does not start with
/// the prefix at a segment boundary.
fn strip_route_prefix(uri: &http::Uri, prefix: &str) -> Option<http::Uri> {
    let rest = uri.path().strip_prefix(prefix)?;
    if !(rest.is_empty() || rest.starts_with('/')) {
        return None;
    }
    let mut path_and_query = format!("/{}", rest.trim_start_matches('/'));
    if let Some(query) = uri.query() {
        path_and_query.push('?');
        path_and_query.push_str(query);
    }
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(path_and_query.parse().ok()?);
    http::Uri::from_parts(parts).ok()
}

/// Upper bound for a generated `Location` value. Inputs are bounded by the request-target
/// limit, but a template may repeat a placeholder; the result is checked as it is built.
const MAX_REDIRECT_LOCATION_BYTES: usize = 8_192;

/// Appends `text` to `out` unless that would pass [`MAX_REDIRECT_LOCATION_BYTES`].
fn push_bounded(out: &mut String, text: &str) -> Option<()> {
    if out.len().saturating_add(text.len()) > MAX_REDIRECT_LOCATION_BYTES {
        return None;
    }
    out.push_str(text);
    Some(())
}

/// Appends `text` percent-encoded so it stays one opaque value inside a query string or
/// fragment: everything except unreserved characters and `/` is encoded.
fn push_bounded_encoded(out: &mut String, text: &str) -> Option<()> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for b in text.bytes() {
        if out.len().saturating_add(3) > MAX_REDIRECT_LOCATION_BYTES {
            return None;
        }
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'/') {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(*HEX.get(usize::from(b >> 4)).unwrap_or(&b'0')));
            out.push(char::from(*HEX.get(usize::from(b & 0x0F)).unwrap_or(&b'0')));
        }
    }
    Some(())
}

/// What the request contributes to a `redirect` target.
struct RedirectInputs<'a> {
    path: &'a str,
    rest: &'a str,
    query: &'a str,
}

/// One piece of a `redirect` template.
enum RedirectToken<'a> {
    Literal(&'a str),
    Path,
    Rest,
    Uri,
    Query,
}

/// Splits a template into literal text and placeholders. The template is read exactly once, so
/// placeholder-shaped text inside a substituted value is never interpreted.
fn redirect_tokens(template: &str) -> Vec<RedirectToken<'_>> {
    let mut tokens = Vec::new();
    let mut rest = template;
    while !rest.is_empty() {
        let Some(open) = rest.find('{') else {
            tokens.push(RedirectToken::Literal(rest));
            break;
        };
        let (literal, tail) = rest.split_at(open);
        if !literal.is_empty() {
            tokens.push(RedirectToken::Literal(literal));
        }
        let (token, after) = if let Some(after) = tail.strip_prefix("{path}") {
            (RedirectToken::Path, after)
        } else if let Some(after) = tail.strip_prefix("{rest}") {
            (RedirectToken::Rest, after)
        } else if let Some(after) = tail.strip_prefix("{uri}") {
            (RedirectToken::Uri, after)
        } else if let Some(after) = tail.strip_prefix("{query}") {
            (RedirectToken::Query, after)
        } else {
            // Not a placeholder (config validation refuses this): keep the brace as text.
            let (brace, after) = tail.split_at(1);
            (RedirectToken::Literal(brace), after)
        };
        tokens.push(token);
        rest = after;
    }
    tokens
}

/// Builds the `Location` value for a `redirect` route, or `None` when it would be longer than
/// [`MAX_REDIRECT_LOCATION_BYTES`].
///
/// The template is split into its path, query and fragment parts **before** anything from the
/// request is inserted, and each part is expanded on its own:
///
/// - path part: `{path}`, `{rest}` and `{uri}` insert the raw request path (already valid URI
///   text). A path that does not start with `/` (`OPTIONS *`) is replaced by `/`, and `{rest}`
///   has its leading `/` removed, so neither can extend the host or start a `//host` form.
///   `{uri}` also carries the request's query into the query part.
/// - query part: `{query}` inserts the request's query as sent; an item that is only `{query}`
///   disappears together with its separator when the query is empty. `{path}`, `{rest}` and
///   `{uri}` are percent-encoded so they stay one value.
/// - fragment: copied, with placeholders percent-encoded.
///
/// Config validation guarantees that a host in the template is literal and followed by `/`,
/// `{path}` or `{uri}`, and that a relative template starts with `/` and a literal character.
fn expand_redirect_target(
    template: &str,
    route_prefix: &str,
    raw_path: &str,
    raw_query: Option<&str>,
) -> Option<String> {
    let path = if raw_path.starts_with('/') {
        raw_path
    } else {
        "/"
    };
    // `{rest}`: what follows the route's literal prefix, with every leading `/` removed. If the
    // raw path does not literally start with the prefix (the route matched a normalised form),
    // `{rest}` is empty.
    let rest = path
        .strip_prefix(route_prefix)
        .filter(|r| r.is_empty() || r.starts_with('/'))
        .map_or("", |r| r.trim_start_matches('/'));
    expand_redirect_with_rest(template, path, rest, raw_query)
}

/// [`expand_redirect_target`] with `{rest}` already worked out by the caller.
fn expand_redirect_with_rest(
    template: &str,
    raw_path: &str,
    rest: &str,
    raw_query: Option<&str>,
) -> Option<String> {
    let path = if raw_path.starts_with('/') {
        raw_path
    } else {
        "/"
    };
    let inputs = RedirectInputs {
        path,
        rest,
        query: raw_query.unwrap_or(""),
    };

    let (main, fragment) = match template.split_once('#') {
        Some((main, fragment)) => (main, Some(fragment)),
        None => (template, None),
    };
    let (path_tpl, query_tpl) = match main.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (main, None),
    };

    let mut out = String::with_capacity(
        template
            .len()
            .saturating_add(path.len())
            .min(MAX_REDIRECT_LOCATION_BYTES),
    );
    let mut uri_query = false;
    for token in redirect_tokens(path_tpl) {
        match token {
            RedirectToken::Literal(text) => push_bounded(&mut out, text)?,
            RedirectToken::Path => push_bounded(&mut out, inputs.path)?,
            RedirectToken::Rest => push_bounded(&mut out, inputs.rest)?,
            RedirectToken::Uri => {
                push_bounded(&mut out, inputs.path)?;
                uri_query = true;
            }
            // Refused by config validation; encoded so it can only ever be path text.
            RedirectToken::Query => push_bounded_encoded(&mut out, inputs.query)?,
        }
    }

    let mut first_item = true;
    let mut start_item = |out: &mut String| {
        let sep = if first_item { "?" } else { "&" };
        first_item = false;
        push_bounded(out, sep)
    };
    if uri_query && !inputs.query.is_empty() {
        start_item(&mut out)?;
        push_bounded(&mut out, inputs.query)?;
    }
    for item in query_tpl.into_iter().flat_map(|q| q.split('&')) {
        if item.is_empty() || (item == "{query}" && inputs.query.is_empty()) {
            continue;
        }
        start_item(&mut out)?;
        expand_redirect_value(&mut out, item, &inputs)?;
    }
    if let Some(fragment) = fragment {
        push_bounded(&mut out, "#")?;
        expand_redirect_value(&mut out, fragment, &inputs)?;
    }
    Some(out)
}

/// Turns an expanded redirect target into a response: `414` when the target was too long to
/// build, `400` when it is not a valid header value.
fn redirect_response(
    location: Option<String>,
    status: StatusCode,
    err_meta: &ErrorMeta<'_>,
    error_pages: &SiteErrorPages,
) -> Response<PipeRespBody> {
    let Some(location) = location else {
        return err_meta.render_error(StatusCode::URI_TOO_LONG, None, Some(error_pages));
    };
    match HeaderValue::from_str(&location) {
        Ok(value) => {
            let mut resp = Response::new(PipeRespBody::empty());
            *resp.status_mut() = status;
            resp.headers_mut().reserve(8);
            resp.headers_mut().insert(http::header::LOCATION, value);
            resp
        }
        Err(_) => err_meta.render_error(StatusCode::BAD_REQUEST, None, Some(error_pages)),
    }
}

/// Like [`redirect_response`], building the response directly from the prebuilt redirect
/// `HeaderMap` template (including `Server`, optional `Alt-Svc`, and security headers in exact
/// wire order) so `apply_security_headers` does not have to re-probe each header.
#[allow(clippy::too_many_arguments)]
fn redirect_response_with_security(
    location: Option<String>,
    status: StatusCode,
    policy: SecurityHeadersPolicy,
    is_https: bool,
    alt_svc: Option<&HeaderValue>,
    version: http::Version,
    err_meta: &ErrorMeta<'_>,
    error_pages: &SiteErrorPages,
) -> (Response<PipeRespBody>, bool) {
    let Some(location) = location else {
        return (
            err_meta.render_error(StatusCode::URI_TOO_LONG, None, Some(error_pages)),
            false,
        );
    };
    match HeaderValue::from_str(&location) {
        Ok(value) => {
            let mut resp = Response::new(PipeRespBody::empty());
            *resp.status_mut() = status;
            *resp.headers_mut() = redirect_headers(value, policy, is_https, alt_svc, version);
            (resp, true)
        }
        Err(_) => (
            err_meta.render_error(StatusCode::BAD_REQUEST, None, Some(error_pages)),
            false,
        ),
    }
}

/// How [`CompiledRouter::dispatch_with_request_id`] should finish security headers after a route
/// handler returns.
#[derive(Debug, Clone, Copy)]
enum SecurityStep {
    /// Apply the route/site's default policy.
    Default,
    /// Apply a specific policy chosen by an internal rewrite target.
    Override(SecurityHeadersPolicy),
    /// The handler already built the exact policy `HeaderMap` from a prebuilt template.
    AlreadyApplied,
}

/// Expands one query item or the fragment of a `redirect` template.
fn expand_redirect_value(
    out: &mut String,
    template: &str,
    inputs: &RedirectInputs<'_>,
) -> Option<()> {
    for token in redirect_tokens(template) {
        match token {
            RedirectToken::Literal(text) => push_bounded(out, text)?,
            RedirectToken::Query => push_bounded(out, inputs.query)?,
            RedirectToken::Path => push_bounded_encoded(out, inputs.path)?,
            RedirectToken::Rest => push_bounded_encoded(out, inputs.rest)?,
            RedirectToken::Uri => {
                push_bounded_encoded(out, inputs.path)?;
                if !inputs.query.is_empty() {
                    push_bounded_encoded(out, "?")?;
                    push_bounded_encoded(out, inputs.query)?;
                }
            }
        }
    }
    Some(())
}

#[derive(Debug, Clone)]
enum RouteMatcher {
    CatchAll,
    Prefix(String),
    Extension(String),
    Exact(String),
}

impl RouteMatcher {
    fn compile(pattern: &str) -> Self {
        if pattern == "/*" {
            Self::CatchAll
        } else if let Some(ext) = pattern.strip_prefix("*.") {
            Self::Extension(format!(".{}", ext.to_ascii_lowercase()))
        } else if let Some(prefix) = pattern.strip_suffix("/*") {
            Self::Prefix(prefix.to_owned())
        } else {
            Self::Exact(pattern.to_owned())
        }
    }

    fn matches(&self, canonical_path: &str) -> bool {
        match self {
            Self::CatchAll => true,
            Self::Prefix(prefix) => {
                canonical_path == prefix
                    || canonical_path
                        .strip_prefix(prefix.as_str())
                        .is_some_and(|rest| rest.starts_with('/'))
            }
            Self::Extension(ext) => {
                // Match extension against the canonical path without allocating (and ignore
                // trailing slash only so `*.php` never falls through to StaticServer on
                // `/file.php/`).
                let trimmed = canonical_path.trim_end_matches('/');
                !trimmed.is_empty() && ends_with_ascii_lower(trimmed, ext)
            }
            Self::Exact(exact) => canonical_path == exact,
        }
    }
}

impl CompiledRouter {
    /// Compiles a validated [`Config`] into live runtime handlers for server startup.
    ///
    /// # Errors
    /// Returns [`HttpError`] if a configured static root, release store, reverse-proxy pool,
    /// or MCP gateway fails initialization.
    pub fn compile(config: &Config, agent_keys: &Arc<AgentKeyRegistry>) -> Result<Self, HttpError> {
        Self::compile_standalone(config, agent_keys, false, &CredentialSources::default())
    }

    /// Takes over the rate-limit counts of `previous` (the configuration this one replaces)
    /// wherever a site, one of its routes or its preset has the same limit as before. Sites are
    /// matched by their host names, routes by their pattern.
    pub(crate) fn inherit_limits(&mut self, previous: &Self) {
        for site in &mut self.sites {
            // The same names in any order (a panel may write aliases in another order).
            let same_names = |before: &&CompiledSite| {
                before.hosts.len() == site.hosts.len()
                    && before.hosts.iter().all(|host| site.hosts.contains(host))
            };
            let Some(before) = previous.sites.iter().find(same_names) else {
                continue;
            };
            Limiter::inherit(&mut site.rate_limit, before.rate_limit.as_ref());
            if site.preset == before.preset
                && let Some(guard) = &before.preset_guard
            {
                site.preset_guard = Some(Arc::clone(guard));
            }
            for route in &mut site.routes {
                let same = before.routes.iter().find(|r| r.pattern == route.pattern);
                Limiter::inherit(
                    &mut route.rate_limit,
                    same.and_then(|r| r.rate_limit.as_ref()),
                );
            }
        }
    }

    /// [`Self::compile`] (or, with `is_reload`, [`Self::compile_for_reload`]) that also refuses
    /// the server's `credentials` beyond those the configuration names.
    ///
    /// # Errors
    /// As [`Self::compile`].
    pub fn compile_with_credentials(
        config: &Config,
        agent_keys: &Arc<AgentKeyRegistry>,
        is_reload: bool,
        credentials: &CredentialSources,
    ) -> Result<Self, HttpError> {
        Self::compile_standalone(config, agent_keys, is_reload, credentials)
    }

    /// Compiles a validated [`Config`] into live runtime handlers for a live reload (`SIGHUP` /
    /// `miraserve reload`), strictly enforcing `ai-publish` preflight with NO startup upgrade
    /// grace (`R7-PUB-1`).
    ///
    /// # Errors
    /// Returns [`HttpError`] if a configured static root, release store, reverse-proxy pool,
    /// or MCP gateway fails initialization.
    pub fn compile_for_reload(
        config: &Config,
        agent_keys: &Arc<AgentKeyRegistry>,
    ) -> Result<Self, HttpError> {
        Self::compile_standalone(config, agent_keys, true, &CredentialSources::default())
    }

    /// Compiles a router wired to a shared process-wide [`miraserve_static::FileCacheBudget`]
    /// and [`miraserve_static::FileCacheCounters`].
    pub(crate) fn compile_with_file_cache(
        config: &Config,
        agent_keys: &Arc<AgentKeyRegistry>,
        is_reload: bool,
        credentials: &CredentialSources,
        budget: &Arc<miraserve_static::FileCacheBudget>,
        counters: miraserve_static::FileCacheCounters,
        clock: &miraserve_static::CacheClock,
    ) -> Result<Self, HttpError> {
        let needs_cache = config.server.limits.file_cache_bytes.as_bytes() > 0
            && config.sites.iter().any(|s| {
                s.file_cache.is_some() && s.quarantine.is_none() && s.ai_publish.is_none()
            });
        let file_cache = needs_cache.then(|| {
            miraserve_static::FileCache::with_clock(Arc::clone(budget), counters, clock.clone())
        });
        Self::compile_inner(config, agent_keys, is_reload, credentials, file_cache)
    }

    fn compile_standalone(
        config: &Config,
        agent_keys: &Arc<AgentKeyRegistry>,
        is_reload: bool,
        credentials: &CredentialSources,
    ) -> Result<Self, HttpError> {
        let budget_limit =
            usize::try_from(config.server.limits.file_cache_bytes.as_bytes()).unwrap_or(usize::MAX);
        let budget = Arc::new(miraserve_static::FileCacheBudget::new(budget_limit));
        Self::compile_with_file_cache(
            config,
            agent_keys,
            is_reload,
            credentials,
            &budget,
            miraserve_static::FileCacheCounters::new(),
            &miraserve_static::CacheClock::System,
        )
    }

    /// Sweeps expired entries from this generation's file cache.
    pub(crate) fn sweep_expired_file_cache(&self) -> usize {
        self.file_cache.as_ref().map_or(0, |c| c.sweep_expired())
    }

    #[allow(clippy::too_many_lines)]
    fn compile_inner(
        config: &Config,
        agent_keys: &Arc<AgentKeyRegistry>,
        is_reload: bool,
        credentials: &CredentialSources,
        file_cache: Option<Arc<miraserve_static::FileCache>>,
    ) -> Result<Self, HttpError> {
        let global_allows_tls12 = config.server.tls.min_version == TlsVersion::V1_2;
        let global_client_ca = config.server.tls.client_ca.as_deref();
        let global_pqc = config.server.tls.pqc_hybrid;
        let upstream_timeouts = (
            config.server.timeouts.upstream_connect,
            config.server.timeouts.upstream_response,
            config.server.timeouts.upstream_body_idle,
        );
        let trusted_proxies = &config.server.limits.trusted_proxies;
        let served_roots = served_document_roots(&config.sites);
        let is_split =
            config.server.tls.key_isolation == miraserve_config::KeyIsolation::SplitDaemon;
        let split_keys = SplitSigningKeys::from_config(config);
        // The server's users files are never served as static content, under any name or link
        // that reaches them (identity checked when a file is opened).
        let (areas, read_users_files) = crate::basic_auth::LoadedAreas::load(
            config
                .sites
                .iter()
                // An isolated site answers 503 without its area (kept while it matters).
                .filter(|site| site.quarantine.is_none())
                .filter_map(|site| site.basic_auth.as_ref())
                .filter(|auth| !split_keys.matches(Path::new(&auth.users_file))),
            &served_roots,
        );
        let (users_files, credential_handles, secret_files, secret_paths) =
            credential_inventory(config, credentials, read_users_files, &split_keys);
        miraserve_static::publish_secret_files(&secret_files);
        let (acme_webroot, acme_reserved) = acme_webroot_with_reserved(config, &secret_paths);
        let uses_workers = config.server.workers != miraserve_config::Workers::Shared && !is_split;
        let proxy_worker_pools = proxy_worker_pool_count(config);
        let uses_h2 =
            config.server.listeners.iter().any(|l| {
                !l.redirect_https && l.protocols.contains(&miraserve_config::Protocol::H2)
            });
        let probe_root_policy = (uses_workers && miraserve_static::kernel_supports_nowait_read())
            || (uses_h2 && miraserve_static::kernel_supports_h2_intask_static());
        let mut sites = Vec::with_capacity(config.sites.len());
        let mut offline_sites: Vec<OfflineSite> = Vec::new();
        for site in &config.sites {
            let compile = |site: &SiteConfig| {
                compile_site(
                    &users_files,
                    &served_roots,
                    &areas,
                    &secret_files,
                    site,
                    global_allows_tls12,
                    global_client_ca,
                    global_pqc,
                    upstream_timeouts,
                    proxy_worker_pools,
                    trusted_proxies,
                    agent_keys,
                    is_reload,
                    probe_root_policy,
                    is_split.then_some(&split_keys),
                    file_cache.as_ref(),
                )
            };
            let host = site.hosts.first().cloned().unwrap_or_default();
            match compile(site) {
                // Recorded from the compiled site, so every way a site ends up answering 503 as
                // a whole is reported: isolation before compiling, the final owner-dir check,
                // and a users file that cannot be loaded.
                Ok(compiled) => {
                    let reason = offline_reason(site, &compiled);
                    if let Some((code, reason)) = reason {
                        offline_sites.push(OfflineSite {
                            index: sites.len(),
                            host: host.clone(),
                            code,
                            reason,
                        });
                    }
                    sites.push(compiled);
                }
                // A tenant site (owner-dir) that cannot be compiled answers 503 on its own; the
                // rest of the configuration loads. Other sites fail the configuration as before.
                Err(err) if site.owner_dir.is_some() && site.quarantine.is_none() => {
                    warn!(
                        site = %site.hosts.first().map_or("<site>", String::as_str),
                        error = %err,
                        "tenant site cannot be loaded; it answers 503, the other sites load normally"
                    );
                    let reason = format!("cannot be loaded: {err}");
                    offline_sites.push(OfflineSite {
                        index: sites.len(),
                        host,
                        code: "W026",
                        reason: reason.clone(),
                    });
                    let mut quarantined = site.clone();
                    quarantined.quarantine = Some(reason);
                    sites.push(compile(&quarantined)?);
                }
                Err(err) => return Err(err),
            }
        }
        let has_http_serve_site = sites
            .iter()
            .any(|site| site.http_mode == SiteHttpMode::Serve);
        let has_static_work = sites.iter().any(|site| {
            site.unavailable.is_none()
                && (site.default_static.is_some()
                    || site.ai_publish.is_some()
                    || site.routes.iter().any(|route| {
                        matches!(
                            route.handler,
                            CompiledHandler::Static { .. }
                                | CompiledHandler::TryFiles { .. }
                                | CompiledHandler::FastCgi {
                                    script_root: Some(_),
                                    ..
                                }
                        )
                    }))
        });
        let mut site_exact_hosts = HashMap::new();
        let mut site_wildcard_hosts = HashMap::new();
        for (idx, site) in sites.iter().enumerate() {
            for host in &site.hosts {
                site_exact_hosts.entry(host.clone()).or_insert(idx);
                if let Some(suffix) = host.strip_prefix("*.") {
                    site_wildcard_hosts.entry(suffix.to_owned()).or_insert(idx);
                }
            }
        }
        let has_file_cache = file_cache.is_some();
        Ok(Self {
            sites,
            site_exact_hosts,
            site_wildcard_hosts,
            has_http_serve_site,
            has_static_work,
            _credential_handles: credential_handles.into(),
            trusted_proxies: config.server.limits.trusted_proxies.clone().into(),
            offline_sites,
            secret_files: Arc::clone(&secret_files),
            acme_webroot,
            acme_reserved,
            file_cache,
            has_file_cache,
        })
    }

    /// Returns `true` when at least one site in this compiled router sets `http "serve"`.
    /// When `false`, redirect-listener requests skip the plain-HTTP attribution pass and go
    /// straight to the unmodified v0.1.2 redirect responder.
    #[must_use]
    pub const fn has_http_serve_site(&self) -> bool {
        self.has_http_serve_site
    }

    /// Returns `true` when at least one live site in this compiled router performs static file
    /// work (`site.root`, `ai-publish`, `static`, `try-files`, or `fastcgi` with a script root).
    #[must_use]
    pub const fn has_static_work(&self) -> bool {
        self.has_static_work
    }

    /// Synchronously classifies an incoming HTTP/2 request at `service.call` time (no filesystem
    /// I/O, zero allocation on canonical lowercase requests) to decide whether its stream future
    /// runs inside the connection's own task ([`crate::h2_intask::StreamExec::InTask`]) or as its
    /// own spawned Tokio task ([`crate::h2_intask::StreamExec::Spawn`], v0.1.4's model).
    ///
    /// - **Spawned (`StreamExec::Spawn`):** reverse proxy, FastCGI/PHP, WASM plugins, MCP/AI
    ///   gateway, `ai-publish` MCP publish endpoints, upgrades (`CONNECT`, extended `CONNECT`
    ///   `:protocol`, `Upgrade`), authenticated `basic-auth` requests (which await `bcrypt` on the
    ///   blocking pool), `try-files` routes whose fallback targets a waiting handler on
    ///   extensionless or non-`GET`/`HEAD` paths, static/default roots with a routed script index
    ///   (e.g. `index.php`) on extensionless paths, and overlong request targets (`> 8 KiB`,
    ///   measuring the full target including query, scheme, and authority identically to framing).
    /// - **In-task (`StreamExec::InTask`):** static files and directory listings, static `try-files`
    ///   (and extensioned `GET`/`HEAD` assets under front-controller `try-files`), redirects,
    ///   fixed `respond` answers, immediate errors decided without I/O, and ACME HTTP-01 requests
    ///   that the responder will actually answer immediately without I/O (non-`GET`/`HEAD` `405`
    ///   or a token currently present in the lock-free in-memory `acme_challenges` store; missing
    ///   or malformed tokens and `acme-webroot` lookups classify by site/auth/route like any other
    ///   request).
    ///
    /// The handler match is exhaustive with NO wildcard arm so adding a new [`CompiledHandler`]
    /// fails to compile until classified.
    #[must_use]
    pub(crate) fn classify_h2_stream_exec<B>(
        &self,
        req: &Request<B>,
        acme_challenges: &AcmeChallengeStore,
    ) -> crate::h2_intask::StreamExec {
        use crate::h2_intask::StreamExec;

        // Plain CONNECT, RFC 8441 extended CONNECT (`:protocol`), or any Upgrade header always
        // run on their own spawned task.
        if req.method() == Method::CONNECT
            || req.extensions().get::<hyper::ext::Protocol>().is_some()
            || req.headers().contains_key(http::header::UPGRADE)
        {
            return StreamExec::Spawn;
        }

        // Measure the full request target (`[scheme "://"][authority]path["?" query]`), matching
        // `miraserve_security::smuggling::validate_uri_ref`'s 8 KiB `414` limit so overlong
        // targets (including short path + long query) consistently spawn without double-decoding.
        let uri = req.uri();
        let target_len = uri
            .scheme_str()
            .map_or(0, |s| s.len().saturating_add(3))
            .saturating_add(uri.authority().map_or(0, |a| a.as_str().len()))
            .saturating_add(uri.path().len())
            .saturating_add(uri.query().map_or(0, |q| q.len().saturating_add(1)));
        if target_len > 8_192 {
            return StreamExec::Spawn;
        }
        let raw_path = uri.path();

        // Invalid paths (NUL, `\`, `.`, `..`, `%uXXXX`, overlong UTF-8) are rejected with 400
        // immediately without I/O.
        let Some((canonical_path, path_flags)) = canonicalize_request_path_with_flags(raw_path)
        else {
            return StreamExec::InTask;
        };
        let path = canonical_path.as_ref();
        let req_host = extract_request_host_ref(req);

        // RFC 8555 ACME HTTP-01 challenge responder: classify in-task ONLY when the responder will
        // genuinely answer without I/O (non-GET/HEAD -> immediate 405, or a token currently present
        // in the lock-free `ArcSwap` in-memory `AcmeChallengeStore`, checked via `has_http01_token`
        // without cloning the key authorization or allocating for canonical lowercase hosts).
        // Missing or malformed (`..`) tokens and `acme-webroot` disk lookups fall through to normal
        // site/auth/route classification so a client cannot steer a catch-all proxy or basic-auth
        // request in-task.
        if !path_flags.has_strict_fs_violation()
            && let Some(token) = path.strip_prefix(ACME_HTTP01_PREFIX)
            && !token.is_empty()
            && !token.contains('/')
            && !token.contains("..")
            && (!matches!(*req.method(), Method::GET | Method::HEAD)
                || req_host.is_some_and(|h| acme_challenges.has_http01_token(h, token)))
        {
            return StreamExec::InTask;
        }

        let Some((_, site)) = self.match_site_indexed(req_host) else {
            // Unmatched host -> immediate 421 Misdirected Request or Welcome/405 without I/O.
            return StreamExec::InTask;
        };

        // Unavailable / quarantined site -> immediate 503 without I/O.
        if site.unavailable.is_some() {
            return StreamExec::InTask;
        }

        // Requests carrying `Authorization` on a `basic-auth` site await `spawn_blocking(bcrypt)`;
        // unauthenticated requests return 401 immediately without I/O.
        if site.basic_auth.is_some() && req.headers().contains_key(http::header::AUTHORIZATION) {
            return StreamExec::Spawn;
        }

        // Built-in authenticated MCP publishing endpoint (`ai-publish.mcp-endpoint`).
        if let Some(ai_pub) = &site.ai_publish
            && let Some((ep_path, _)) = &ai_pub.mcp_endpoint
            && path == ep_path.as_str()
        {
            return StreamExec::Spawn;
        }

        // Exhaustive match on `CompiledHandler` (no wildcard arm).
        if let Some(route) = site.routes.iter().find(|r| r.matches_path(path)) {
            return match &route.handler {
                CompiledHandler::ReverseProxy(_)
                | CompiledHandler::FastCgi { .. }
                | CompiledHandler::WasmPlugin(_)
                | CompiledHandler::McpGateway(_) => StreamExec::Spawn,
                CompiledHandler::Static {
                    has_script_index, ..
                } => {
                    if *has_script_index && !path_has_file_extension(path) {
                        StreamExec::Spawn
                    } else {
                        StreamExec::InTask
                    }
                }
                CompiledHandler::TryFiles {
                    fallback_spawns, ..
                } => {
                    if *fallback_spawns
                        && (!matches!(*req.method(), Method::GET | Method::HEAD)
                            || !path_has_file_extension(path))
                    {
                        StreamExec::Spawn
                    } else {
                        StreamExec::InTask
                    }
                }
                CompiledHandler::Respond(_)
                | CompiledHandler::Redirect { .. }
                | CompiledHandler::Unavailable => StreamExec::InTask,
            };
        }

        // Unmatched site path: `ai-publish` active release static files, `site.default_static`,
        // or immediate 503/404 without I/O.
        if site.default_static.is_some()
            && site.default_static_has_script_index
            && !path_has_file_extension(path)
        {
            return StreamExec::Spawn;
        }
        StreamExec::InTask
    }

    /// The HTTP-01 key authorization an external ACME client wrote for `token` into
    /// `server.acme-webroot`, for a configured host: the token is RFC 8555 base64url only, the
    /// file a small regular file reached without links, and the file and its directory are
    /// owned by root or the MiraServe user and not writable by group or others.
    fn acme_webroot_token(&self, host: &str, token: &str, probed_fs: &mut bool) -> Option<Vec<u8>> {
        let path = self.prepare_acme_webroot_path(host, token, probed_fs)?;
        read_acme_webroot_token_file(&path, token, &self.secret_files)
    }

    /// Async counterpart to [`Self::acme_webroot_token`]: when [`inline_work_must_not_block`] is
    /// active (dedicated worker loops and in-task HTTP/2 streams), runs the filesystem ownership
    /// check and 4 KiB read on the blocking pool so it cannot park sibling connections or streams.
    async fn acme_webroot_token_async(
        &self,
        host: &str,
        token: &str,
        probed_fs: &mut bool,
    ) -> Option<Vec<u8>> {
        let path = self.prepare_acme_webroot_path(host, token, probed_fs)?;
        if miraserve_static::inline_work_must_not_block() {
            let token_owned = token.to_owned();
            let secret_files = Arc::clone(&self.secret_files);
            return Box::pin(async move {
                tokio::task::spawn_blocking(move || {
                    read_acme_webroot_token_file(&path, &token_owned, &secret_files)
                })
                .await
                .ok()
                .flatten()
            })
            .await;
        }
        read_acme_webroot_token_file(&path, token, &self.secret_files)
    }

    fn prepare_acme_webroot_path(
        &self,
        host: &str,
        token: &str,
        probed_fs: &mut bool,
    ) -> Option<std::path::PathBuf> {
        let dir = self.acme_webroot.as_deref()?;
        if !miraserve_static::is_acme_token(token)
            || !self.matches_configured_host(host)
            || self.acme_reserved.contains(token)
        {
            return None;
        }
        // Filesystem access begins here: if this lookup misses and falls through to the site,
        // the request must not admit to any site's file cache. Test the router's cached boolean
        // first so an all-off server never even writes the flag.
        if self.has_file_cache {
            *probed_fs = true;
            #[cfg(test)]
            ROUTER_ACME_PROBED_FS_SET.fetch_add(1, Ordering::Relaxed);
        }
        #[cfg(test)]
        if let Some(hook) = ACME_WEBROOT_PROBE_TEST_HOOK
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        {
            hook(host);
        }
        // Only the challenge subtree certbot and lego write (`<webroot>/.well-known/acme-
        // challenge/<token>`): nothing else under the webroot is ever answered here.
        Some(dir.join(".well-known").join("acme-challenge").join(token))
    }

    /// The sites this configuration serves as a 503 as a whole.
    #[must_use]
    pub fn offline_sites(&self) -> &[OfflineSite] {
        &self.offline_sites
    }

    /// Dispatches an incoming HTTP request through anti-smuggling validation, single-decode
    /// path canonicalization, TLS SNI/Host & TLS 1.3 binding, site/preset WAF guards,
    /// RFC 9421 Web Bot Auth, GCRA rate limiting, and route execution.
    pub async fn dispatch(
        &self,
        req: Request<HttpBody>,
        ctx: &RequestContext,
        limits: &LimitsConfig,
        acme_challenges: &AcmeChallengeStore,
        alt_svc_h3_port: Option<u16>,
        telemetry: &TelemetryRegistry,
    ) -> Response<HttpBody> {
        let request_id = generate_request_id_inline();
        let alt_svc = alt_svc_h3_port.and_then(alt_svc_header_value);
        let mut req_slot = Some(req.map(PipeReqBody::from_http_body));
        self.dispatch_with_request_id(
            &mut req_slot,
            ctx,
            limits,
            acme_challenges,
            alt_svc.as_ref(),
            telemetry,
            request_id.as_str(),
            "Not enabled",
        )
        .await
        .map(PipeRespBody::into_http_body)
    }

    /// Dispatches an incoming HTTP request using an explicit server-generated `request_id`
    /// (matching `miraserve::access` logs) and worker `sandbox_state` summary.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn dispatch_with_request_id(
        &self,
        req_slot: &mut Option<Request<PipeReqBody>>,
        ctx: &RequestContext,
        limits: &LimitsConfig,
        acme_challenges: &AcmeChallengeStore,
        alt_svc_h3_port: Option<&HeaderValue>,
        telemetry: &TelemetryRegistry,
        request_id: &str,
        sandbox_state: &str,
    ) -> Response<PipeRespBody> {
        let Some(req_ref) = req_slot.as_ref() else {
            let mut r = Response::new(PipeRespBody::empty());
            *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            return r;
        };
        let req_version = req_ref.version();
        let req_uri = req_ref.uri().clone();
        let host_hdr = req_ref.headers().get(HOST).cloned();
        let req_host = extract_host_from_parts(host_hdr.as_ref(), &req_uri);

        // 1. Strict RFC 9110/9112/9113/9114 anti-smuggling normalizer (Threat Model T4)
        if let Err(rejection) = validate_request_framing(req_ref, limits) {
            telemetry.record_security_block(SecurityBlockReason::AntiSmuggling);
            warn!(
                request_id = %request_id,
                rule = rejection.rule,
                client_ip = %display_opt_ip(ctx.client_ip),
                "rejected request by anti-smuggling normalizer"
            );
            let meta = ErrorMeta::from_request(
                req_ref,
                req_uri.path(),
                req_host.map(Cow::Borrowed),
                request_id,
            );
            return meta.framing_error(rejection.status);
        }

        // 2. Single-decode canonical request path ONCE so PresetGuard, RouteMatcher, and
        //    StaticServer ALWAYS agree on the exact same path (no double-decode / PHP leak!).
        //    R2-HTTP-3: Preserve `path_flags` so filesystem/static/FastCGI/publish routes still
        //    strictly reject `%2F`, malformed `%`, and non-UTF-8 escapes while reverse-proxy,
        //    WASM, and MCP routes can forward encoded API identifiers (e.g. GitLab/npm).
        let Some((orig_canonical_path, path_flags)) =
            canonicalize_request_path_with_flags(req_uri.path())
        else {
            telemetry.record_security_block(SecurityBlockReason::AntiSmuggling);
            warn!(
                request_id = %request_id,
                client_ip = %display_opt_ip(ctx.client_ip),
                "rejected request with invalid path"
            );
            let meta = ErrorMeta::from_request(
                req_ref,
                req_uri.path(),
                req_host.map(Cow::Borrowed),
                request_id,
            );
            return meta.framing_error(StatusCode::BAD_REQUEST);
        };

        let mut err_meta = ErrorMeta::from_request(
            req_ref,
            orig_canonical_path.as_ref(),
            req_host.map(Cow::Borrowed),
            request_id,
        );

        // 3. Domain-scoped, method-restricted RFC 8555 ACME HTTP-01 challenge responder.
        //    Fast path: guard with the static prefix so non-ACME requests never enter (or include
        //    in `pipeline_tracked`'s inline state) the async webroot lookup future.
        let mut acme_probed_fs = false;
        if !path_flags.has_strict_fs_violation()
            && orig_canonical_path.starts_with(ACME_HTTP01_PREFIX)
            && let Some(req_ref) = req_slot.as_ref()
            && let Some(resp) = Box::pin(maybe_serve_acme_http01_async(
                req_ref,
                orig_canonical_path.as_ref(),
                acme_challenges,
                self,
                &err_meta,
                &mut acme_probed_fs,
            ))
            .await
        {
            return resp;
        }

        let Some((site_idx, site)) = self.match_site_indexed(req_host) else {
            // If TLS SNI matched a configured site OR differs from HTTP Host, fail closed
            // with 421 Misdirected Request to block HTTP/2 connection-coalescing attacks.
            if ctx.is_https
                && let Some(tls) = &ctx.tls
                && let Some(sni) = tls.sni.as_deref()
            {
                let host_matches_sni = req_host.is_some_and(|h| sni.eq_ignore_ascii_case(h));
                let host_differs_from_sni = req_host.is_some() && !host_matches_sni;
                // When SNI equals Host (ASCII case-insensitively), `normalize_site_host` yields
                // the same value and `match_site_indexed` just returned `None`, so reuse that miss.
                let sni_matches_configured = !host_matches_sni
                    && !host_differs_from_sni
                    && self.match_site_indexed(Some(sni)).is_some();
                if sni_matches_configured || host_differs_from_sni {
                    telemetry.record_security_block(SecurityBlockReason::AntiSmuggling);
                    warn!(
                        request_id = %request_id,
                        client_ip = %display_opt_ip(ctx.client_ip),
                        "rejected request with 421 Misdirected Request (SNI/Host mismatch)"
                    );
                    let mut resp =
                        err_meta.render_error(StatusCode::MISDIRECTED_REQUEST, None, None);
                    apply_security_headers(
                        resp.headers_mut(),
                        SecurityHeadersPolicy::Strict,
                        ctx.is_https,
                        alt_svc_h3_port,
                        req_version,
                        true,
                    );
                    return resp;
                }
            }

            // A server that hosts sites must not answer for names it does not serve, and must
            // not describe itself (TLS, sandbox state) to whoever points a hostname at it: 421.
            // The built-in Welcome page is only for a fresh install with no site configured.
            if !self.sites.is_empty() {
                let mut resp = err_meta.render_error(StatusCode::MISDIRECTED_REQUEST, None, None);
                apply_security_headers(
                    resp.headers_mut(),
                    SecurityHeadersPolicy::Strict,
                    ctx.is_https,
                    alt_svc_h3_port,
                    req_version,
                    true,
                );
                return resp;
            }

            // No site is configured at all: serve the built-in Welcome page on GET/HEAD, or
            // 405 Method Not Allowed on write methods.
            let mut resp = if matches!(err_meta.method, Method::GET | Method::HEAD) {
                let accept = err_meta.accept_headers.to_header_map();
                render_welcome_response(
                    &accept,
                    &WelcomePageContext {
                        method: &err_meta.method,
                        host: err_meta.host.as_deref(),
                        tls_summary: format_tls_summary(ctx.is_https, ctx.tls.as_ref()),
                        protocol: format_http_protocol(req_version),
                        sandbox_state,
                        request_id,
                    },
                )
                .map(PipeRespBody::Boxed)
            } else {
                let mut r = err_meta.render_error(StatusCode::METHOD_NOT_ALLOWED, None, None);
                r.headers_mut()
                    .insert(ALLOW, HeaderValue::from_static("GET, HEAD"));
                r
            };
            apply_security_headers(
                resp.headers_mut(),
                SecurityHeadersPolicy::Strict,
                ctx.is_https,
                alt_svc_h3_port,
                req_version,
                true,
            );
            return resp;
        };

        // 4. Enforce TLS SNI/Host binding & per-site TLS 1.3 policy (defeats HTTP/2 coalescing downgrade).
        if ctx.is_https
            && let Some(tls) = &ctx.tls
        {
            if let Some(sni) = tls.sni.as_deref() {
                // ASCII case-insensitive equality implies identical `normalize_site_host` output
                // and therefore the same matched site index as `req_host`.
                let sni_site_idx = if req_host.is_some_and(|h| sni.eq_ignore_ascii_case(h)) {
                    Some(site_idx)
                } else {
                    self.match_site_indexed(Some(sni)).map(|(i, _)| i)
                };
                if sni_site_idx != Some(site_idx) {
                    telemetry.record_security_block(SecurityBlockReason::AntiSmuggling);
                    warn!(
                        request_id = %request_id,
                        client_ip = %display_opt_ip(ctx.client_ip),
                        "rejected request with 421 Misdirected Request (Host/SNI site mismatch)"
                    );
                    let mut resp =
                        err_meta.render_error(StatusCode::MISDIRECTED_REQUEST, None, None);
                    apply_security_headers(
                        resp.headers_mut(),
                        SecurityHeadersPolicy::Strict,
                        ctx.is_https,
                        alt_svc_h3_port,
                        req_version,
                        true,
                    );
                    return resp;
                }
            }
            if !tls.is_tls13 && !site.allows_tls_1_2 {
                telemetry.record_security_block(SecurityBlockReason::AntiSmuggling);
                warn!(
                    request_id = %request_id,
                    client_ip = %display_opt_ip(ctx.client_ip),
                    "rejected request with 421 Misdirected Request (site requires TLS 1.3)"
                );
                let mut resp = err_meta.render_error(StatusCode::MISDIRECTED_REQUEST, None, None);
                apply_security_headers(
                    resp.headers_mut(),
                    SecurityHeadersPolicy::Strict,
                    ctx.is_https,
                    alt_svc_h3_port,
                    req_version,
                    true,
                );
                return resp;
            }
        }

        err_meta.host = Some(canonical_host_for_site(site, req_host));
        let host_for_site = err_meta.host.as_deref().unwrap_or("localhost");
        // Everything below answers for this site; its `headers { ... }` (and the matched
        // route's) apply to whatever it returns, error responses included.
        // Flattened labeled block avoids a nested `async { ... }.await` state machine and its
        // by-value `Request` / `Response` moves.
        let mut resp: Response<PipeRespBody> = 'site: {
            // R5-RL-1: Derive effective client IP from `X-Forwarded-For` ONLY when the socket peer
            // matches `server.limits.trusted-proxies` (right-to-left peeling of trusted proxies),
            // keeping untrusted peers bound strictly to the socket IP.
            let (effective_client_ip, policy_ip, peer_migrated) = {
                let Some(req_ref) = req_slot.as_ref() else {
                    break 'site err_meta.render_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        None,
                        Some(&site.error_pages),
                    );
                };
                let effective = resolve_effective_client_ip(
                    ctx.client_ip,
                    req_ref.headers(),
                    &self.trusted_proxies,
                );
                // Allow/deny lists, `client-ip` conditions and login throttling use an address only
                // when it is established; rate limits and logs keep the resolved one.
                // Only sites that decide by visitor address need the stricter policy address.
                let policy = if !site.access.is_empty()
                    || site.basic_auth.is_some()
                    || site.rewrites.uses_client_ip()
                {
                    policy_client_ip(ctx.client_ip, &self.trusted_proxies, req_ref.headers())
                } else {
                    effective
                };
                let migrated = req_ref.extensions().get::<crate::PeerMigrated>().is_some();
                (effective, policy, migrated)
            };
            // Only sites whose handlers re-check visitor policy need the address carried along
            // (an extension costs an allocation per request).
            if site.rewrites.uses_client_ip()
                && let Some(req_mut) = req_slot.as_mut()
            {
                req_mut.extensions_mut().insert(PolicyClientIp(policy_ip));
            }

            // 4a. A site whose document root is unsafe or outside its owner directory serves
            //     nothing (other sites are unaffected).
            if site.unavailable.is_some() {
                let mut resp = err_meta.render_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    Some(DEFAULT_RETRY_AFTER_SECS),
                    None,
                );
                apply_security_headers(
                    resp.headers_mut(),
                    site.security_headers,
                    ctx.is_https,
                    alt_svc_h3_port,
                    req_version,
                    false,
                );
                break 'site resp;
            }

            // 4a'. A site that decides by visitor address trusts only the address an HTTP/3
            //      handshake validated: after the connection moved, ask for a new connection
            //      (browsers retry a 421 on a fresh one).
            if (!site.access.is_empty() || site.rewrites.uses_client_ip()) && peer_migrated {
                let mut resp = err_meta.render_error(StatusCode::MISDIRECTED_REQUEST, None, None);
                resp.headers_mut().insert(
                    http::header::CACHE_CONTROL,
                    http::HeaderValue::from_static("no-store"),
                );
                break 'site resp;
            }

            // 4c. Site visitor allow/deny list, before anything else looks at the request.
            if !site.access.is_empty() && !access_allows(&site.access, policy_ip) {
                telemetry.record_security_block(SecurityBlockReason::SitePreset);
                // Built-in page: the site's own error pages are content this visitor may not see.
                let mut resp = err_meta.render_error(StatusCode::FORBIDDEN, None, None);
                resp.extensions_mut().insert(ProtectedResponse);
                apply_security_headers(
                    resp.headers_mut(),
                    site.security_headers,
                    ctx.is_https,
                    alt_svc_h3_port,
                    req_version,
                    false,
                );
                break 'site resp;
            }

            if let Some(auth) = &site.basic_auth
                && let Some(req_ref) = req_slot.as_ref()
                && let Some(mut resp) = Box::pin(basic_auth_refusal(
                    auth,
                    req_ref,
                    policy_ip,
                    &err_meta,
                    site,
                    ctx.is_https,
                ))
                .await
            {
                apply_security_headers(
                    resp.headers_mut(),
                    site.security_headers,
                    ctx.is_https,
                    alt_svc_h3_port,
                    req_version,
                    false,
                );
                break 'site resp;
            }

            if site.basic_auth.is_some()
                && let Some(req_mut) = req_slot.as_mut()
            {
                consume_server_credentials(req_mut);
            }

            // 5. Site-level deterministic security preset (e.g., wordpress-hardened)
            if let Some(req_ref) = req_slot.as_ref()
                && let Some(resp) = preset_guard_response(
                    site,
                    req_ref.method(),
                    orig_canonical_path.as_ref(),
                    req_ref.headers(),
                    effective_client_ip,
                    telemetry,
                    request_id,
                    &err_meta,
                    ctx,
                    alt_svc_h3_port,
                    req_version,
                )
            {
                break 'site resp;
            }

            // 6. RFC 9421 Web Bot Auth & unverified AI User-Agent policy
            let mut verified_agent_id: Option<String> = None;
            let mut agent_serve_markdown = false;
            if let Some(bot_auth) = &site.bot_auth
                && let Some(req_ref) = req_slot.as_ref()
            {
                match bot_auth.evaluate_with_scheme(
                    req_ref.method(),
                    req_ref.uri(),
                    req_ref.headers(),
                    effective_client_ip,
                    ctx.scheme(),
                ) {
                    BotAuthOutcome::Pass { serve_markdown } => {
                        agent_serve_markdown = serve_markdown;
                    }
                    BotAuthOutcome::Verified {
                        agent,
                        serve_markdown,
                    } => {
                        verified_agent_id = Some(agent.agent_id);
                        agent_serve_markdown = serve_markdown;
                    }
                    BotAuthOutcome::Throttle { retry_after_secs } => {
                        telemetry.record_security_block(SecurityBlockReason::BotAuth);
                        let mut resp = err_meta.rate_limit_error(
                            retry_after_secs,
                            10,
                            0,
                            Some(&site.error_pages),
                        );
                        apply_security_headers(
                            resp.headers_mut(),
                            site.security_headers,
                            ctx.is_https,
                            alt_svc_h3_port,
                            req_version,
                            false,
                        );
                        break 'site resp;
                    }
                    BotAuthOutcome::Reject {
                        status, challenge, ..
                    } => {
                        telemetry.record_security_block(SecurityBlockReason::BotAuth);
                        let mut resp = err_meta.render_error(status, None, Some(&site.error_pages));
                        if challenge {
                            resp.headers_mut().insert(
                                HeaderName::from_static("x-miraserve-bot-challenge"),
                                HeaderValue::from_static("rfc9421-required"),
                            );
                        }
                        apply_security_headers(
                            resp.headers_mut(),
                            site.security_headers,
                            ctx.is_https,
                            alt_svc_h3_port,
                            req_version,
                            false,
                        );
                        break 'site resp;
                    }
                }
            }

            // 7. Site-level GCRA rate limit (ALWAYS executes BEFORE OAuth metadata and ai-publish!)
            if let Some(limiter) = &site.rate_limit
                && let Some(req_ref) = req_slot.as_ref()
            {
                let decision = limiter.check_request(
                    effective_client_ip,
                    req_ref.headers(),
                    verified_agent_id.as_deref(),
                );
                if !decision.allowed {
                    telemetry.record_security_block(SecurityBlockReason::RateLimit);
                    let mut resp = err_meta.rate_limit_error(
                        decision.retry_after_secs,
                        decision.limit,
                        decision.remaining,
                        Some(&site.error_pages),
                    );
                    apply_security_headers(
                        resp.headers_mut(),
                        site.security_headers,
                        ctx.is_https,
                        alt_svc_h3_port,
                        req_version,
                        false,
                    );
                    break 'site resp;
                }
            }

            // Test `site.has_file_cache` ONCE per request: cache-enabled sites branch into the
            // boxed cached path, while sites without `file-cache` continue inline below with zero
            // further cache checks and no extra nested coroutine frame.
            if site.has_file_cache {
                let Some(req) = req_slot.take() else {
                    break 'site err_meta.render_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        None,
                        Some(&site.error_pages),
                    );
                };
                break 'site Box::pin(self.dispatch_site_cached(
                    site,
                    req,
                    orig_canonical_path.as_ref(),
                    path_flags,
                    &req_uri,
                    host_for_site,
                    ctx,
                    alt_svc_h3_port,
                    req_version,
                    effective_client_ip,
                    policy_ip,
                    verified_agent_id.as_deref(),
                    agent_serve_markdown,
                    acme_probed_fs,
                    limits,
                    telemetry,
                    request_id,
                    &err_meta,
                ))
                .await;
            }

            // 7b. Site rewrite rules (uncached inline path).
            let mut canonical_path: Cow<'_, str> = Cow::Borrowed(orig_canonical_path.as_ref());
            let mut path_flags = path_flags;
            let mut rewritten_uri: Option<http::Uri> = None;
            if !site.rewrites.is_empty() {
                let outcome = {
                    let Some(req_ref) = req_slot.as_ref() else {
                        break 'site err_meta.render_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            None,
                            Some(&site.error_pages),
                        );
                    };
                    Box::pin(site.rewrites.apply(
                        &canonical_path,
                        req_ref.uri().query(),
                        host_for_site,
                        req_ref.method(),
                        req_ref.headers(),
                        policy_ip,
                        site.default_static.as_ref(),
                    ))
                    .await
                };
                #[cfg(test)]
                if let Some(hook) = AFTER_REWRITES_TEST_HOOK
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
                {
                    hook(host_for_site);
                }
                let early = match outcome {
                    crate::rewrite::RewriteOutcome::Unchanged => None,
                    crate::rewrite::RewriteOutcome::Deny(status) => Some((
                        err_meta.render_error(status, None, Some(&site.error_pages)),
                        false,
                    )),
                    crate::rewrite::RewriteOutcome::Redirect { status, location } => {
                        Some(redirect_response_with_security(
                            Some(location),
                            status,
                            site.security_headers,
                            ctx.is_https,
                            alt_svc_h3_port,
                            req_version,
                            &err_meta,
                            &site.error_pages,
                        ))
                    }
                    crate::rewrite::RewriteOutcome::Internal(target) => {
                        let rewritten = req_slot.as_ref().and_then(|req_ref| {
                            rewritten_request_target(req_ref.uri(), &target, path_flags)
                        });
                        match rewritten {
                            Some((uri, new_path, new_flags)) => {
                                let path_changed = new_path != canonical_path.as_ref();
                                if let Some(req_mut) = req_slot.as_mut() {
                                    let original = req_mut.uri().path_and_query().map_or_else(
                                        || "/".to_owned(),
                                        |pq| pq.as_str().to_owned(),
                                    );
                                    *req_mut.uri_mut() = uri.clone();
                                    req_mut
                                        .extensions_mut()
                                        .insert(OriginalRequestTarget(original));
                                }
                                rewritten_uri = Some(uri);
                                canonical_path = Cow::Owned(new_path);
                                path_flags = new_flags;
                                let denied = {
                                    let Some(req_ref) = req_slot.as_ref() else {
                                        break 'site err_meta.render_error(
                                            StatusCode::INTERNAL_SERVER_ERROR,
                                            None,
                                            Some(&site.error_pages),
                                        );
                                    };
                                    Box::pin(site.rewrites.denied_status(
                                        &canonical_path,
                                        req_ref.uri().query(),
                                        host_for_site,
                                        req_ref.method(),
                                        req_ref.headers(),
                                        policy_ip,
                                        site.default_static.as_ref(),
                                    ))
                                    .await
                                };
                                if let Some(status) = denied {
                                    Some((
                                        err_meta.render_error(
                                            status,
                                            None,
                                            Some(&site.error_pages),
                                        ),
                                        false,
                                    ))
                                } else if path_changed
                                    && let Some(req_ref) = req_slot.as_ref()
                                    && let Some(resp) = preset_guard_response(
                                        site,
                                        req_ref.method(),
                                        &canonical_path,
                                        req_ref.headers(),
                                        effective_client_ip,
                                        telemetry,
                                        request_id,
                                        &err_meta,
                                        ctx,
                                        alt_svc_h3_port,
                                        req_version,
                                    )
                                {
                                    break 'site resp;
                                } else {
                                    None
                                }
                            }
                            None => Some((err_meta.framing_error(StatusCode::BAD_REQUEST), false)),
                        }
                    }
                };
                if let Some((mut resp, security_applied)) = early {
                    if !security_applied {
                        apply_security_headers(
                            resp.headers_mut(),
                            site.security_headers,
                            ctx.is_https,
                            alt_svc_h3_port,
                            req_version,
                            false,
                        );
                    }
                    break 'site resp;
                }
            }
            let query = rewritten_uri.as_ref().unwrap_or(&req_uri).query();

            // 8. OAuth 2.1 RFC 9728 Protected Resource Metadata (exact path, GET/HEAD, canonical host)
            if !path_flags.has_strict_fs_violation()
                && canonical_path.as_ref() == OAUTH_PROTECTED_RESOURCE_PATH
                && let Some(req_ref) = req_slot.as_ref()
                && matches!(*req_ref.method(), Method::GET | Method::HEAD)
                && let Some(gw) = site.first_oauth_mcp_gateway()
            {
                let resource_url = if ctx.is_https {
                    format!("{}://{host_for_site}", ctx.scheme())
                } else {
                    let resource_host = format_host_for_url(host_for_site);
                    match extract_request_port(req_ref) {
                        Some(port) if port != 80 => {
                            format!("{}://{resource_host}:{port}", ctx.scheme())
                        }
                        _ => format!("{}://{resource_host}", ctx.scheme()),
                    }
                };
                let mut resp = gw
                    .oauth_protected_resource_metadata(&resource_url)
                    .map(map_proxy_body_pipe);
                if *req_ref.method() == Method::HEAD {
                    let (parts, _) = resp.into_parts();
                    resp = Response::from_parts(parts, PipeRespBody::empty());
                }
                apply_security_headers(
                    resp.headers_mut(),
                    site.security_headers,
                    ctx.is_https,
                    alt_svc_h3_port,
                    req_version,
                    false,
                );
                break 'site resp;
            }

            // 9. Built-in authenticated MCP publishing endpoint (`ai-publish.mcp-endpoint`)
            if let Some(ai_pub) = &site.ai_publish
                && let Some((ep_path, auth_mode)) = &ai_pub.mcp_endpoint
                && canonical_path.as_ref() == ep_path.as_str()
            {
                if path_flags.has_strict_fs_violation() {
                    telemetry.record_security_block(SecurityBlockReason::AntiSmuggling);
                    break 'site err_meta.framing_error(StatusCode::BAD_REQUEST);
                }
                let Some(req) = req_slot.take() else {
                    break 'site err_meta.render_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        None,
                        Some(&site.error_pages),
                    );
                };
                let verified_dn = site.verify_mtls_peer(ctx.tls.as_ref());
                let publish_site_id = canonical_publish_site_id(site);
                let mut resp = Box::pin(handle_ai_publish_mcp(
                    Arc::clone(&ai_pub.store),
                    *auth_mode,
                    ep_path.clone(),
                    publish_site_id,
                    ctx.is_https,
                    verified_dn,
                    req,
                    limits.max_body_bytes.as_bytes(),
                    &err_meta,
                    &site.error_pages,
                ))
                .await;
                apply_security_headers(
                    resp.headers_mut(),
                    site.security_headers,
                    ctx.is_https,
                    alt_svc_h3_port,
                    req_version,
                    false,
                );
                break 'site resp;
            }

            let want_md = req_slot
                .as_ref()
                .is_some_and(|r| prefers_markdown(r.headers(), agent_serve_markdown));

            // 10. Route matching + route-level rate limit + handler dispatch
            let (mut resp, sec_step, force_sec_overwrite) =
                if let Some(route) = site.routes.iter().find(|r| r.matches_path(&canonical_path)) {
                    if path_flags.has_strict_fs_violation()
                        && matches!(
                            route.handler,
                            CompiledHandler::Static { .. }
                                | CompiledHandler::TryFiles { .. }
                                | CompiledHandler::FastCgi { .. }
                        )
                    {
                        telemetry.record_security_block(SecurityBlockReason::AntiSmuggling);
                        break 'site err_meta.framing_error(StatusCode::BAD_REQUEST);
                    }
                    let sec = route.security_headers.unwrap_or(site.security_headers);
                    let is_wasm = matches!(route.handler, CompiledHandler::WasmPlugin(_));
                    let throttled = route.rate_limit.as_ref().and_then(|rl| {
                        let req_ref = req_slot.as_ref()?;
                        let decision = rl.check_request(
                            effective_client_ip,
                            req_ref.headers(),
                            verified_agent_id.as_deref(),
                        );
                        (!decision.allowed).then(|| {
                            telemetry.record_security_block(SecurityBlockReason::RateLimit);
                            err_meta.rate_limit_error(
                                decision.retry_after_secs,
                                decision.limit,
                                decision.remaining,
                                Some(&site.error_pages),
                            )
                        })
                    });
                    if let Some(mut r) = throttled {
                        if !route.headers.is_empty() {
                            r.extensions_mut()
                                .insert(RouteHeaderRules(Some(Arc::clone(&route.headers))));
                        }
                        (r, SecurityStep::Override(sec), is_wasm)
                    } else {
                        let is_trusted_peer = ctx.client_ip.is_some_and(|ip| {
                            self.trusted_proxies
                                .iter()
                                .any(|cidr| cidr.contains(ip.to_canonical()))
                        });
                        let (r, route_sec_step) = execute_route::<false>(
                            site,
                            route,
                            req_slot,
                            &canonical_path,
                            query,
                            host_for_site,
                            ctx,
                            alt_svc_h3_port,
                            effective_client_ip,
                            is_trusted_peer,
                            verified_agent_id.as_deref(),
                            limits.max_body_bytes.as_bytes(),
                            want_md,
                            agent_serve_markdown,
                            telemetry,
                            &err_meta,
                        )
                        .await;
                        let mut r = r;
                        if !route.headers.is_empty()
                            && r.extensions().get::<RouteHeaderRules>().is_none()
                        {
                            r.extensions_mut()
                                .insert(RouteHeaderRules(Some(Arc::clone(&route.headers))));
                        }
                        let final_step = match route_sec_step {
                            SecurityStep::Default => SecurityStep::Override(sec),
                            other => other,
                        };
                        (r, final_step, is_wasm)
                    }
                } else if let Some(pub_site) = site.ai_publish.as_ref() {
                    if path_flags.has_strict_fs_violation() {
                        telemetry.record_security_block(SecurityBlockReason::AntiSmuggling);
                        break 'site err_meta.framing_error(StatusCode::BAD_REQUEST);
                    }
                    if let Some(sync_guard) = try_claim_disk_sync(&pub_site.store) {
                        tokio::task::spawn_blocking(move || {
                            sync_guard.sync_now();
                        });
                    }
                    if let Some(mut active_srv) = pub_site.store.active_static_server()
                        && let Some(req_ref) = req_slot.as_ref()
                    {
                        active_srv.set_secret_files(Arc::clone(&site.secret_files));
                        active_srv.set_precompressed(site.precompressed);
                        active_srv.set_extra_response_headers(site.default_static_extra_headers);
                        let r = Box::pin(serve_static_with_markdown::<false>(
                            &active_srv,
                            &SiblingPolicy {
                                site,
                                owner: None,
                                host: host_for_site,
                                effective_client_ip,
                            },
                            req_ref,
                            &canonical_path,
                            want_md,
                            agent_serve_markdown,
                            true,
                            &site.fastcgi_extensions,
                            &err_meta,
                            &site.error_pages,
                            StaticLookup::direct(),
                        ))
                        .await;
                        (r, SecurityStep::Override(site.security_headers), false)
                    } else if let Some(static_srv) = &site.default_static
                        && let Some(req_ref) = req_slot.as_ref()
                    {
                        let r = Box::pin(serve_static_with_markdown::<false>(
                            static_srv,
                            &SiblingPolicy {
                                site,
                                owner: None,
                                host: host_for_site,
                                effective_client_ip,
                            },
                            req_ref,
                            &canonical_path,
                            want_md,
                            agent_serve_markdown,
                            true,
                            &site.fastcgi_extensions,
                            &err_meta,
                            &site.error_pages,
                            StaticLookup::direct(),
                        ))
                        .await;
                        (r, SecurityStep::Override(site.security_headers), false)
                    } else {
                        (
                            err_meta.render_error(
                                StatusCode::SERVICE_UNAVAILABLE,
                                Some(DEFAULT_RETRY_AFTER_SECS),
                                Some(&site.error_pages),
                            ),
                            SecurityStep::Override(site.security_headers),
                            false,
                        )
                    }
                } else if let Some(static_srv) = &site.default_static {
                    if path_flags.has_strict_fs_violation() {
                        telemetry.record_security_block(SecurityBlockReason::AntiSmuggling);
                        break 'site err_meta.framing_error(StatusCode::BAD_REQUEST);
                    }
                    let Some(req) = req_slot.take() else {
                        break 'site err_meta.render_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            None,
                            Some(&site.error_pages),
                        );
                    };
                    let is_trusted_peer = ctx.client_ip.is_some_and(|ip| {
                        self.trusted_proxies
                            .iter()
                            .any(|cidr| cidr.contains(ip.to_canonical()))
                    });
                    let (r, override_sec) = serve_static_or_script_index::<false>(
                        site,
                        None,
                        static_srv,
                        req,
                        &canonical_path,
                        query,
                        host_for_site,
                        ctx,
                        effective_client_ip,
                        is_trusted_peer,
                        verified_agent_id.as_deref(),
                        limits.max_body_bytes.as_bytes(),
                        want_md,
                        agent_serve_markdown,
                        telemetry,
                        &err_meta,
                    )
                    .await;
                    (
                        r,
                        SecurityStep::Override(override_sec.unwrap_or(site.security_headers)),
                        false,
                    )
                } else if site.ai_publish.is_some() || site.default_static_unavailable {
                    (
                        err_meta.render_error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            Some(DEFAULT_RETRY_AFTER_SECS),
                            Some(&site.error_pages),
                        ),
                        SecurityStep::Override(site.security_headers),
                        false,
                    )
                } else {
                    (
                        err_meta.render_error(StatusCode::NOT_FOUND, None, Some(&site.error_pages)),
                        SecurityStep::Override(site.security_headers),
                        false,
                    )
                };

            let force_sec_overwrite =
                force_sec_overwrite || resp.extensions_mut().remove::<WasmResponse>().is_some();
            match sec_step {
                SecurityStep::AlreadyApplied if !force_sec_overwrite => {}
                SecurityStep::Override(effective_sec_headers) => {
                    apply_security_headers(
                        resp.headers_mut(),
                        effective_sec_headers,
                        ctx.is_https,
                        alt_svc_h3_port,
                        req_version,
                        force_sec_overwrite,
                    );
                }
                SecurityStep::Default | SecurityStep::AlreadyApplied => {
                    apply_security_headers(
                        resp.headers_mut(),
                        site.security_headers,
                        ctx.is_https,
                        alt_svc_h3_port,
                        req_version,
                        force_sec_overwrite,
                    );
                }
            }
            resp
        };
        let strip_www_authenticate = resp
            .extensions_mut()
            .remove::<StripWwwAuthenticate>()
            .is_some();
        // The marker's PRESENCE decides whether this step runs (as in v0.1.3, where a route
        // without rules still left its marker); the rules inside it are optional.
        let route_marker = resp.extensions_mut().remove::<RouteHeaderRules>();
        if !site.headers.is_empty() || route_marker.is_some() {
            // Fields the server owns survive configured header rules: the login challenge of a
            // 401 and the advertised HTTP/3 endpoint.
            let challenge = resp.headers().get(http::header::WWW_AUTHENTICATE).cloned();
            let alt_svc = resp.headers().get(http::header::ALT_SVC).cloned();
            let retry_after = resp
                .extensions()
                .get::<ServerThrottle>()
                .and_then(|_| resp.headers().get(http::header::RETRY_AFTER).cloned());
            let status = resp.status();
            if !site.headers.is_empty() {
                apply_header_rules(resp.headers_mut(), status, &site.headers);
            }
            if let Some(RouteHeaderRules(Some(rules))) = route_marker {
                apply_header_rules(resp.headers_mut(), status, &rules);
            }
            if resp.status() == StatusCode::UNAUTHORIZED
                && let Some(challenge) = challenge
            {
                resp.headers_mut()
                    .insert(http::header::WWW_AUTHENTICATE, challenge);
            }
            if let Some(alt_svc) = alt_svc {
                resp.headers_mut().insert(http::header::ALT_SVC, alt_svc);
            }
            // The retry interval of MiraServe's own throttle (login attempts, rate limits) stays.
            if let Some(retry_after) = retry_after {
                resp.headers_mut()
                    .insert(http::header::RETRY_AFTER, retry_after);
            }
            if !ctx.is_https {
                resp.headers_mut()
                    .remove(http::header::STRICT_TRANSPORT_SECURITY);
                resp.headers_mut().remove(http::header::ALT_SVC);
            }
        }
        if strip_www_authenticate {
            resp.headers_mut().remove(http::header::WWW_AUTHENTICATE);
        }
        let marked = resp
            .extensions_mut()
            .remove::<ProtectedResponse>()
            .is_some();
        // Answers of a site whose content depends on who asks (visitor list, password, rules on
        // the visitor address) stay out of shared caches.
        let site_protected =
            !site.access.is_empty() || site.basic_auth.is_some() || site.rewrites.uses_client_ip();
        if marked || site_protected {
            // Caches in front of the server may obey their own fields before Cache-Control.
            // (`CDN-Cache-Control`, vendor `*-CDN-Cache-Control`, `Surrogate-Control`).
            let targeted: Vec<http::HeaderName> = resp
                .headers()
                .keys()
                .filter(|name| {
                    let name = name.as_str();
                    name == "surrogate-control" || name.ends_with("cdn-cache-control")
                })
                .cloned()
                .collect();
            for field in targeted {
                resp.headers_mut().remove(field);
            }
            if resp.status().is_client_error() || resp.status().is_server_error() {
                // A refusal is never stored, whatever a header rule set.
                resp.headers_mut().insert(
                    http::header::CACHE_CONTROL,
                    http::HeaderValue::from_static("no-store"),
                );
            } else {
                make_private(resp.headers_mut());
            }
        }
        resp
    }

    /// Boxed post-guards site dispatch for sites with `site.has_file_cache == true` (never
    /// entered on cache-off, quarantined, or `ai-publish` sites).
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        clippy::fn_params_excessive_bools
    )]
    async fn dispatch_site_cached(
        &self,
        site: &CompiledSite,
        mut req: Request<PipeReqBody>,
        orig_canonical_path: &str,
        mut path_flags: PathFlags,
        req_uri: &http::Uri,
        host_for_site: &str,
        ctx: &RequestContext,
        alt_svc_h3_port: Option<&HeaderValue>,
        req_version: http::Version,
        effective_client_ip: Option<IpAddr>,
        policy_ip: Option<IpAddr>,
        verified_agent_id: Option<&str>,
        agent_serve_markdown: bool,
        acme_probed_fs: bool,
        limits: &LimitsConfig,
        telemetry: &TelemetryRegistry,
        request_id: &str,
        err_meta: &ErrorMeta<'_>,
    ) -> Response<PipeRespBody> {
        // 7b. Site rewrite rules + pre-first-filesystem-access cache markers.
        let mut canonical_path: Cow<'_, str> = Cow::Borrowed(orig_canonical_path);
        let mut rewritten_uri: Option<http::Uri> = None;
        if let Some(fc) = site.file_cache.as_ref() {
            #[cfg(test)]
            ROUTER_CACHE_SITE_BRANCH_HITS.fetch_add(1, Ordering::Relaxed);
            if req.headers().contains_key(http::header::RANGE)
                || req.headers().contains_key(http::header::IF_RANGE)
            {
                req.extensions_mut().insert(RequestCacheBypass);
            } else if acme_probed_fs {
                req.extensions_mut().insert(RequestCacheNoAdmit);
            } else if !site.rewrites.is_empty() && site.rewrites.uses_filesystem() {
                req.extensions_mut()
                    .insert(CarriedFillStart(fc.sample_fill_start()));
            }
        }
        if !site.rewrites.is_empty() {
            let outcome = site
                .rewrites
                .apply(
                    &canonical_path,
                    req.uri().query(),
                    host_for_site,
                    req.method(),
                    req.headers(),
                    policy_ip,
                    site.default_static.as_ref(),
                )
                .await;
            #[cfg(test)]
            if let Some(hook) = AFTER_REWRITES_TEST_HOOK
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
            {
                hook(host_for_site);
            }
            let early = match outcome {
                crate::rewrite::RewriteOutcome::Unchanged => None,
                crate::rewrite::RewriteOutcome::Deny(status) => Some((
                    err_meta.render_error(status, None, Some(&site.error_pages)),
                    false,
                )),
                crate::rewrite::RewriteOutcome::Redirect { status, location } => {
                    Some(redirect_response_with_security(
                        Some(location),
                        status,
                        site.security_headers,
                        ctx.is_https,
                        alt_svc_h3_port,
                        req_version,
                        err_meta,
                        &site.error_pages,
                    ))
                }
                crate::rewrite::RewriteOutcome::Internal(target) => {
                    match rewritten_request_target(req.uri(), &target, path_flags) {
                        Some((uri, new_path, new_flags)) => {
                            let original = req
                                .uri()
                                .path_and_query()
                                .map_or_else(|| "/".to_owned(), |pq| pq.as_str().to_owned());
                            let path_changed = new_path != canonical_path.as_ref();
                            *req.uri_mut() = uri.clone();
                            rewritten_uri = Some(uri);
                            req.extensions_mut().insert(OriginalRequestTarget(original));
                            canonical_path = Cow::Owned(new_path);
                            path_flags = new_flags;
                            let denied = site
                                .rewrites
                                .denied_status(
                                    &canonical_path,
                                    req.uri().query(),
                                    host_for_site,
                                    req.method(),
                                    req.headers(),
                                    policy_ip,
                                    site.default_static.as_ref(),
                                )
                                .await;
                            if let Some(status) = denied {
                                Some((
                                    err_meta.render_error(status, None, Some(&site.error_pages)),
                                    false,
                                ))
                            } else if path_changed
                                && let Some(resp) = preset_guard_response(
                                    site,
                                    req.method(),
                                    &canonical_path,
                                    req.headers(),
                                    effective_client_ip,
                                    telemetry,
                                    request_id,
                                    err_meta,
                                    ctx,
                                    alt_svc_h3_port,
                                    req_version,
                                )
                            {
                                return resp;
                            } else {
                                None
                            }
                        }
                        None => Some((err_meta.framing_error(StatusCode::BAD_REQUEST), false)),
                    }
                }
            };
            if let Some((mut resp, security_applied)) = early {
                if !security_applied {
                    apply_security_headers(
                        resp.headers_mut(),
                        site.security_headers,
                        ctx.is_https,
                        alt_svc_h3_port,
                        req_version,
                        false,
                    );
                }
                return resp;
            }
        }
        let query = rewritten_uri.as_ref().unwrap_or(req_uri).query();

        // 8. OAuth 2.1 RFC 9728 Protected Resource Metadata (exact path, GET/HEAD, canonical host)
        if !path_flags.has_strict_fs_violation()
            && canonical_path.as_ref() == OAUTH_PROTECTED_RESOURCE_PATH
            && matches!(*req.method(), Method::GET | Method::HEAD)
            && let Some(gw) = site.first_oauth_mcp_gateway()
        {
            let resource_url = if ctx.is_https {
                format!("{}://{host_for_site}", ctx.scheme())
            } else {
                let resource_host = format_host_for_url(host_for_site);
                match extract_request_port(&req) {
                    Some(port) if port != 80 => {
                        format!("{}://{resource_host}:{port}", ctx.scheme())
                    }
                    _ => format!("{}://{resource_host}", ctx.scheme()),
                }
            };
            let mut resp = gw
                .oauth_protected_resource_metadata(&resource_url)
                .map(map_proxy_body_pipe);
            if *req.method() == Method::HEAD {
                let (parts, _) = resp.into_parts();
                resp = Response::from_parts(parts, PipeRespBody::empty());
            }
            apply_security_headers(
                resp.headers_mut(),
                site.security_headers,
                ctx.is_https,
                alt_svc_h3_port,
                req_version,
                false,
            );
            return resp;
        }

        let want_md = prefers_markdown(req.headers(), agent_serve_markdown);

        // 10. Route matching + route-level rate limit + handler dispatch (`site.ai_publish` is
        //     always `None` when `site.has_file_cache` is `true`).
        let (mut resp, sec_step, force_sec_overwrite) = if let Some(route) =
            site.routes.iter().find(|r| r.matches_path(&canonical_path))
        {
            if path_flags.has_strict_fs_violation()
                && matches!(
                    route.handler,
                    CompiledHandler::Static { .. }
                        | CompiledHandler::TryFiles { .. }
                        | CompiledHandler::FastCgi { .. }
                )
            {
                telemetry.record_security_block(SecurityBlockReason::AntiSmuggling);
                return err_meta.framing_error(StatusCode::BAD_REQUEST);
            }
            let sec = route.security_headers.unwrap_or(site.security_headers);
            let is_wasm = matches!(route.handler, CompiledHandler::WasmPlugin(_));
            let throttled = route.rate_limit.as_ref().and_then(|rl| {
                let decision =
                    rl.check_request(effective_client_ip, req.headers(), verified_agent_id);
                (!decision.allowed).then(|| {
                    telemetry.record_security_block(SecurityBlockReason::RateLimit);
                    err_meta.rate_limit_error(
                        decision.retry_after_secs,
                        decision.limit,
                        decision.remaining,
                        Some(&site.error_pages),
                    )
                })
            });
            if let Some(mut r) = throttled {
                if !route.headers.is_empty() {
                    r.extensions_mut()
                        .insert(RouteHeaderRules(Some(Arc::clone(&route.headers))));
                }
                (r, SecurityStep::Override(sec), is_wasm)
            } else {
                let is_trusted_peer = ctx.client_ip.is_some_and(|ip| {
                    self.trusted_proxies
                        .iter()
                        .any(|cidr| cidr.contains(ip.to_canonical()))
                });
                let mut req_slot = Some(req);
                let (r, route_sec_step) = execute_route::<true>(
                    site,
                    route,
                    &mut req_slot,
                    &canonical_path,
                    query,
                    host_for_site,
                    ctx,
                    alt_svc_h3_port,
                    effective_client_ip,
                    is_trusted_peer,
                    verified_agent_id,
                    limits.max_body_bytes.as_bytes(),
                    want_md,
                    agent_serve_markdown,
                    telemetry,
                    err_meta,
                )
                .await;
                let mut r = r;
                if !route.headers.is_empty() && r.extensions().get::<RouteHeaderRules>().is_none() {
                    r.extensions_mut()
                        .insert(RouteHeaderRules(Some(Arc::clone(&route.headers))));
                }
                let final_step = match route_sec_step {
                    SecurityStep::Default => SecurityStep::Override(sec),
                    other => other,
                };
                (r, final_step, is_wasm)
            }
        } else if let Some(static_srv) = &site.default_static {
            if path_flags.has_strict_fs_violation() {
                telemetry.record_security_block(SecurityBlockReason::AntiSmuggling);
                return err_meta.framing_error(StatusCode::BAD_REQUEST);
            }
            let is_trusted_peer = ctx.client_ip.is_some_and(|ip| {
                self.trusted_proxies
                    .iter()
                    .any(|cidr| cidr.contains(ip.to_canonical()))
            });
            let (r, override_sec) = serve_static_or_script_index::<true>(
                site,
                None,
                static_srv,
                req,
                &canonical_path,
                query,
                host_for_site,
                ctx,
                effective_client_ip,
                is_trusted_peer,
                verified_agent_id,
                limits.max_body_bytes.as_bytes(),
                want_md,
                agent_serve_markdown,
                telemetry,
                err_meta,
            )
            .await;
            (
                r,
                SecurityStep::Override(override_sec.unwrap_or(site.security_headers)),
                false,
            )
        } else if site.default_static_unavailable {
            (
                err_meta.render_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    Some(DEFAULT_RETRY_AFTER_SECS),
                    Some(&site.error_pages),
                ),
                SecurityStep::Override(site.security_headers),
                false,
            )
        } else {
            (
                err_meta.render_error(StatusCode::NOT_FOUND, None, Some(&site.error_pages)),
                SecurityStep::Override(site.security_headers),
                false,
            )
        };

        let force_sec_overwrite =
            force_sec_overwrite || resp.extensions_mut().remove::<WasmResponse>().is_some();
        match sec_step {
            SecurityStep::AlreadyApplied if !force_sec_overwrite => {}
            SecurityStep::Override(effective_sec_headers) => {
                apply_security_headers(
                    resp.headers_mut(),
                    effective_sec_headers,
                    ctx.is_https,
                    alt_svc_h3_port,
                    req_version,
                    force_sec_overwrite,
                );
            }
            SecurityStep::Default | SecurityStep::AlreadyApplied => {
                apply_security_headers(
                    resp.headers_mut(),
                    site.security_headers,
                    ctx.is_https,
                    alt_svc_h3_port,
                    req_version,
                    force_sec_overwrite,
                );
            }
        }
        resp
    }

    /// Returns `true` if `host` matches a configured site in this router.
    #[must_use]
    pub fn matches_configured_host(&self, host: &str) -> bool {
        self.match_site_indexed(Some(host)).is_some()
    }

    fn match_site_indexed(&self, host: Option<&str>) -> Option<(usize, &CompiledSite)> {
        if let Some(raw_host) = host {
            let lower = normalize_site_host(raw_host);
            if let Some(&idx) = self.site_exact_hosts.get(lower.as_ref()) {
                return self.sites.get(idx).map(|s| (idx, s));
            }
            if !self.site_wildcard_hosts.is_empty()
                && let Some((_, suffix)) = lower.split_once('.')
                && let Some(&idx) = self.site_wildcard_hosts.get(suffix)
            {
                return self.sites.get(idx).map(|s| (idx, s));
            }
            if self.sites.len() == 1
                && (lower == "localhost" || lower == "127.0.0.1" || lower == "::1")
            {
                return self.sites.first().map(|s| (0, s));
            }
            return None;
        }

        if self.sites.len() == 1 {
            self.sites.first().map(|s| (0, s))
        } else {
            None
        }
    }

    #[cfg(test)]
    fn match_site_indexed_linear(&self, host: Option<&str>) -> Option<(usize, &CompiledSite)> {
        if let Some(raw_host) = host {
            let lower = normalize_site_host(raw_host);
            if let Some(found) = self
                .sites
                .iter()
                .enumerate()
                .find(|(_, s)| s.hosts.iter().any(|h| h == lower.as_ref()))
            {
                return Some(found);
            }
            if let Some((_, suffix)) = lower.split_once('.') {
                let wild = format!("*.{suffix}");
                if let Some(found) = self
                    .sites
                    .iter()
                    .enumerate()
                    .find(|(_, s)| s.hosts.iter().any(|h| h == &wild))
                {
                    return Some(found);
                }
            }
            if self.sites.len() == 1
                && (lower == "localhost" || lower == "127.0.0.1" || lower == "::1")
            {
                return self.sites.first().map(|s| (0, s));
            }
            return None;
        }

        if self.sites.len() == 1 {
            self.sites.first().map(|s| (0, s))
        } else {
            None
        }
    }
}

impl CompiledSite {
    fn first_oauth_mcp_gateway(&self) -> Option<&Arc<McpGateway>> {
        self.routes.iter().find_map(|r| match &r.handler {
            CompiledHandler::McpGateway(gw) if gw.config().oauth_resource_metadata => Some(gw),
            _ => None,
        })
    }
}

/// Evaluates the site's security preset for `canonical_path` and returns the finished error
/// response when the preset blocks or rate-limits the request.
#[allow(clippy::too_many_arguments)]
fn preset_guard_response(
    site: &CompiledSite,
    method: &Method,
    canonical_path: &str,
    headers: &HeaderMap,
    effective_client_ip: Option<IpAddr>,
    telemetry: &TelemetryRegistry,
    request_id: &str,
    err_meta: &ErrorMeta<'_>,
    ctx: &RequestContext,
    alt_svc_h3_port: Option<&HeaderValue>,
    req_version: http::Version,
) -> Option<Response<PipeRespBody>> {
    let preset_guard = site.preset_guard.as_ref()?;
    let mut resp = match preset_guard.evaluate(method, canonical_path, headers, effective_client_ip)
    {
        PresetVerdict::Allow => return None,
        PresetVerdict::Block { status, rule, .. } => {
            telemetry.record_security_block(SecurityBlockReason::SitePreset);
            warn!(
                request_id = %request_id,
                rule,
                path = %canonical_path,
                client_ip = %display_opt_ip(effective_client_ip),
                "blocked request by site preset"
            );
            err_meta.render_error(status, None, Some(&site.error_pages))
        }
        PresetVerdict::RateLimited {
            rule,
            retry_after_secs,
        } => {
            telemetry.record_security_block(SecurityBlockReason::RateLimit);
            warn!(
                request_id = %request_id,
                rule,
                path = %canonical_path,
                client_ip = %display_opt_ip(effective_client_ip),
                "rate-limited request by site preset"
            );
            err_meta.rate_limit_error(retry_after_secs, 10, 0, Some(&site.error_pages))
        }
    };
    apply_security_headers(
        resp.headers_mut(),
        site.security_headers,
        ctx.is_https,
        alt_svc_h3_port,
        req_version,
        false,
    );
    Some(resp)
}

/// Returns the immutable configured site identifier (`ai-publish.site-id` when explicitly set,
/// otherwise the first configured hostname lowercased) used to bind publish JWT `aud`, Ed25519
/// request signatures, and signed release manifests — NEVER reflecting the client-supplied `Host`
/// header (`R3-PUB-4`, `R3-PUB-5`, `R4-PUB-3`).
fn canonical_publish_site_id(site: &CompiledSite) -> String {
    if let Some(ai_pub) = &site.ai_publish
        && let Some(explicit) = ai_pub.store.expected_site_id()
    {
        return explicit.to_owned();
    }
    site.hosts
        .first()
        .map_or_else(|| "localhost".to_owned(), |h| h.to_ascii_lowercase())
}

/// Computes the canonical hostname for a matched site: uses the exact configured non-wildcard
/// host whenever matched, or strictly validates wildcard-matched hosts.
fn canonical_host_for_site<'a>(site: &'a CompiledSite, req_host: Option<&'a str>) -> Cow<'a, str> {
    if let Some(raw) = req_host {
        if let Some(exact) = site.hosts.iter().find(|h| h.eq_ignore_ascii_case(raw)) {
            return Cow::Borrowed(exact.as_str());
        }
        // Only reflect wildcard-matched host if it passes strict RFC 3986 validation.
        if raw.bytes().any(|b| b.is_ascii_uppercase()) {
            let lower = raw.to_ascii_lowercase();
            if is_valid_rfc3986_host_port(&lower) {
                return Cow::Owned(lower);
            }
        } else if is_valid_rfc3986_host_port(raw) {
            return Cow::Borrowed(raw);
        }
    }
    site.hosts
        .first()
        .map_or(Cow::Borrowed("localhost"), |h| Cow::Borrowed(h.as_str()))
}

/// Flags recorded during single-decode request path canonicalization (`R2-HTTP-3`, `R5-HTTP-3`)
/// so filesystem/static/FastCGI/publish routes can strictly reject `%2F`, malformed `%`, and
/// non-UTF-8 byte escapes while reverse-proxy, MCP, and WASM routes preserve them (overlong
/// UTF-8, UTF-16 surrogates, and IIS `%uXXXX` escapes are rejected globally per `R4-PRX-1` /
/// `R5-HTTP-3`).
#[derive(Debug, Clone, Copy, Default)]
struct PathFlags {
    has_encoded_slash: bool,
    has_malformed_percent: bool,
    has_invalid_utf8: bool,
}

impl PathFlags {
    const fn has_strict_fs_violation(self) -> bool {
        self.has_encoded_slash || self.has_malformed_percent || self.has_invalid_utf8
    }
}

/// Decodes valid percent-escapes ONCE, rejects NUL / `\` / `.` / `..` / `%uXXXX` / overlong or
/// surrogate UTF-8 globally, collapses consecutive slashes, preserves a trailing `/` (so
/// `StaticServer::serve_canonical` returns 404 on `/wp-config.php/`), and returns [`PathFlags`]
/// for handler-specific strictness (`R2-HTTP-3`, `R5-HTTP-3`).
///
/// Borrows `raw_path` without allocating when it needs no percent-decoding and is already
/// canonical, and builds canonicalized paths in a single pass without intermediate segment `Vec`s.
fn canonicalize_request_path_with_flags(raw_path: &str) -> Option<(Cow<'_, str>, PathFlags)> {
    let bytes = raw_path.as_bytes();
    if !bytes.contains(&b'%') {
        if bytes.contains(&0x00) || bytes.contains(&b'\\') {
            return None;
        }
        return canonicalize_decoded_str(Cow::Borrowed(raw_path), PathFlags::default());
    }

    let mut decoded_bytes = Vec::with_capacity(bytes.len());
    let mut flags = PathFlags::default();
    let mut i = 0_usize;
    while let Some(&b) = bytes.get(i) {
        if b == b'%' {
            // R4-PRX-1: Reject IIS `%uXXXX`/`%UXXXX` Unicode escapes on ALL routes!
            if matches!(bytes.get(i.saturating_add(1)), Some(b'u' | b'U'))
                && bytes
                    .get(i.saturating_add(2)..i.saturating_add(6))
                    .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
            {
                return None;
            }
            if let (Some(&h1), Some(&h2)) = (
                bytes.get(i.saturating_add(1)),
                bytes.get(i.saturating_add(2)),
            ) && let (Some(hi), Some(lo)) = (hex_digit(h1), hex_digit(h2))
            {
                let ch = (hi << 4) | lo;
                if ch == b'/' {
                    flags.has_encoded_slash = true;
                }
                decoded_bytes.push(ch);
                i = i.saturating_add(3);
            } else {
                flags.has_malformed_percent = true;
                decoded_bytes.push(b);
                i = i.saturating_add(1);
            }
        } else {
            decoded_bytes.push(b);
            i = i.saturating_add(1);
        }
    }
    // R4-PRX-1 & R5-HTTP-3: Reject overlong UTF-8 and UTF-16 surrogates globally while permitting
    // legacy non-UTF-8 byte escapes (e.g. `/fichier%E9.pdf`) to reach reverse-proxy routes!
    if contains_overlong_or_surrogate_utf8(&decoded_bytes) {
        return None;
    }
    if decoded_bytes.contains(&0x00)
        || decoded_bytes.contains(&b'\\')
        || decoded_bytes
            .split(|&b| b == b'/')
            .any(|seg| seg == b"." || seg == b"..")
    {
        return None;
    }
    let decoded = match String::from_utf8(decoded_bytes) {
        Ok(s) => s,
        Err(err) => {
            flags.has_invalid_utf8 = true;
            String::from_utf8_lossy(err.as_bytes()).into_owned()
        }
    };

    canonicalize_decoded_str(Cow::Owned(decoded), flags)
}

fn canonicalize_decoded_str(
    decoded: Cow<'_, str>,
    flags: PathFlags,
) -> Option<(Cow<'_, str>, PathFlags)> {
    let mut has_segment = false;
    for seg in decoded.split('/') {
        if seg.is_empty() {
            continue;
        }
        if seg == "." || seg == ".." {
            return None;
        }
        has_segment = true;
    }
    if !has_segment {
        return Some((Cow::Borrowed("/"), flags));
    }
    if decoded.starts_with('/') && !decoded.contains("//") {
        return Some((decoded, flags));
    }
    let trailing_slash = decoded.ends_with('/');
    let mut out = String::with_capacity(decoded.len().saturating_add(1));
    for seg in decoded.split('/') {
        if seg.is_empty() {
            continue;
        }
        out.push('/');
        out.push_str(seg);
    }
    if trailing_slash {
        out.push('/');
    }
    Some((Cow::Owned(out), flags))
}

/// Derives the effective client IP from `X-Forwarded-For` using byte-wise right-to-left peeling of
/// `server.limits.trusted-proxies` (`R5-RL-1`, `R6-XFF-1`). Untrusted peers ALWAYS keep their socket IP.
pub(crate) fn resolve_effective_client_ip(
    peer_ip: Option<IpAddr>,
    headers: &HeaderMap,
    trusted_proxies: &[IpCidr],
) -> Option<IpAddr> {
    miraserve_proxy::resolve_effective_client_ip(peer_ip, headers, trusted_proxies)
}

const fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Handles plaintext HTTP `redirect-https=true` listeners:
/// - Runs full RFC 9110/9112 anti-smuggling validation first.
/// - Serves active domain-scoped RFC 8555 ACME HTTP-01 challenges under `/.well-known/acme-challenge/`.
/// - Rejects unconfigured hosts (`421 Misdirected Request`) to defeat open-redirect abuse.
/// - Redirects configured hosts to `https://` with `308 Permanent Redirect`.
#[must_use]
pub fn serve_https_redirect(
    req: &Request<HttpBody>,
    https_port: u16,
    limits: &LimitsConfig,
    router: &CompiledRouter,
    acme_challenges: &AcmeChallengeStore,
) -> Response<HttpBody> {
    let request_id = generate_request_id_inline();
    serve_https_redirect_with_request_id(
        req,
        https_port,
        limits,
        router,
        acme_challenges,
        request_id.as_str(),
    )
}

/// Returns `true` when a request arriving on a `redirect-https=#true` listener should be
/// dispatched through the normal request pipeline as plain HTTP instead of the v0.1.2 redirect
/// responder.
///
/// Only HTTP/1.0 and HTTP/1.1 requests with an unambiguous, syntactically valid `Host` matching
/// a configured `http "serve"` site qualify; HTTP/2 (`h2c`), bad/missing/ambiguous `Host`,
/// unknown hosts, `http "redirect"` sites, and configurations without any `http "serve"` site
/// all return `false` and run the unmodified v0.1.2 redirect responder.
///
/// Deliberately does not decode the request path or look up ACME tokens: the normal pipeline
/// performs framing (rejecting overlength paths with `414` before decoding), path
/// canonicalization, and ACME HTTP-01 lookup once, identically to HTTPS.
#[must_use]
pub(crate) fn should_serve_plain_http<B>(req: &Request<B>, router: &CompiledRouter) -> bool {
    if !router.has_http_serve_site()
        || !matches!(
            req.version(),
            http::Version::HTTP_10 | http::Version::HTTP_11
        )
        || validate_host_consistency(req).is_err()
    {
        return false;
    }
    let Some(host) = extract_request_host_ref(req) else {
        return false;
    };
    let Some((_, site)) = router.match_site_indexed(Some(host)) else {
        return false;
    };
    site.http_mode == SiteHttpMode::Serve
}

pub(crate) async fn serve_https_redirect_with_request_id_async<B>(
    req: &Request<B>,
    https_port: u16,
    limits: &LimitsConfig,
    router: &CompiledRouter,
    acme_challenges: &AcmeChallengeStore,
    request_id: &str,
) -> Response<HttpBody> {
    let raw_host = extract_request_host_ref(req);
    if let Err(rejection) = validate_request_framing(req, limits) {
        let meta = ErrorMeta::from_request(
            req,
            req.uri().path(),
            raw_host.map(Cow::Borrowed),
            request_id,
        );
        return meta
            .framing_error(rejection.status)
            .map(PipeRespBody::into_http_body);
    }

    let Some((canonical_path, path_flags)) = canonicalize_request_path_with_flags(req.uri().path())
    else {
        let meta = ErrorMeta::from_request(
            req,
            req.uri().path(),
            raw_host.map(Cow::Borrowed),
            request_id,
        );
        return meta
            .framing_error(StatusCode::BAD_REQUEST)
            .map(PipeRespBody::into_http_body);
    };

    let err_meta = ErrorMeta::from_request(
        req,
        canonical_path.as_ref(),
        raw_host.map(Cow::Borrowed),
        request_id,
    );

    if !path_flags.has_strict_fs_violation()
        && let Some(resp) = maybe_serve_acme_http01_async(
            req,
            canonical_path.as_ref(),
            acme_challenges,
            router,
            &err_meta,
            &mut false,
        )
        .await
    {
        return resp.map(PipeRespBody::into_http_body);
    }

    finish_https_redirect(req, raw_host, https_port, router, &err_meta)
}

pub(crate) fn serve_https_redirect_with_request_id<B>(
    req: &Request<B>,
    https_port: u16,
    limits: &LimitsConfig,
    router: &CompiledRouter,
    acme_challenges: &AcmeChallengeStore,
    request_id: &str,
) -> Response<HttpBody> {
    let raw_host = extract_request_host_ref(req);
    if let Err(rejection) = validate_request_framing(req, limits) {
        let meta = ErrorMeta::from_request(
            req,
            req.uri().path(),
            raw_host.map(Cow::Borrowed),
            request_id,
        );
        return meta
            .framing_error(rejection.status)
            .map(PipeRespBody::into_http_body);
    }

    let Some((canonical_path, path_flags)) = canonicalize_request_path_with_flags(req.uri().path())
    else {
        let meta = ErrorMeta::from_request(
            req,
            req.uri().path(),
            raw_host.map(Cow::Borrowed),
            request_id,
        );
        return meta
            .framing_error(StatusCode::BAD_REQUEST)
            .map(PipeRespBody::into_http_body);
    };

    let err_meta = ErrorMeta::from_request(
        req,
        canonical_path.as_ref(),
        raw_host.map(Cow::Borrowed),
        request_id,
    );

    if !path_flags.has_strict_fs_violation()
        && let Some(resp) = maybe_serve_acme_http01(
            req,
            canonical_path.as_ref(),
            acme_challenges,
            router,
            &err_meta,
            &mut false,
        )
    {
        return resp.map(PipeRespBody::into_http_body);
    }

    finish_https_redirect(req, raw_host, https_port, router, &err_meta)
}

fn finish_https_redirect<B>(
    req: &Request<B>,
    raw_host: Option<&str>,
    https_port: u16,
    router: &CompiledRouter,
    err_meta: &ErrorMeta<'_>,
) -> Response<HttpBody> {
    let Some(host) = raw_host else {
        return err_meta
            .framing_error(StatusCode::BAD_REQUEST)
            .map(PipeRespBody::into_http_body);
    };

    if !is_valid_rfc3986_host_port(host) {
        return err_meta
            .framing_error(StatusCode::BAD_REQUEST)
            .map(PipeRespBody::into_http_body);
    }

    // Only redirect hosts configured in MiraServe to prevent open-redirect abuse!
    if !router.matches_configured_host(host) {
        return err_meta
            .render_error(StatusCode::MISDIRECTED_REQUEST, None, None)
            .map(PipeRespBody::into_http_body);
    }

    let authority = if https_port == 443 {
        format_host_for_url(host)
    } else {
        format!("{}:{https_port}", format_host_for_url(host))
    };

    // Preserve safe relative path & query (never allow protocol-relative `//evil.com`).
    let raw_pq = req
        .uri()
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str);
    let safe_pq = if raw_pq.starts_with("//") {
        let trimmed = raw_pq.trim_start_matches('/');
        format!("/{trimmed}")
    } else if raw_pq.starts_with('/') {
        raw_pq.to_owned()
    } else {
        format!("/{raw_pq}")
    };

    let location = format!("https://{authority}{safe_pq}");
    let Ok(loc_val) = HeaderValue::from_str(&location) else {
        return err_meta
            .render_error(StatusCode::BAD_REQUEST, None, None)
            .map(PipeRespBody::into_http_body);
    };

    Response::builder()
        .status(StatusCode::PERMANENT_REDIRECT)
        .header(LOCATION, loc_val)
        .header(http::header::SERVER, "MiraServe")
        .header(HeaderName::from_static("x-content-type-options"), "nosniff")
        .body(empty_http_body())
        .unwrap_or_else(|_| {
            err_meta
                .render_error(StatusCode::BAD_REQUEST, None, None)
                .map(PipeRespBody::into_http_body)
        })
}

/// The policy a Markdown sibling (`page.md` served for `page.html`) has to pass as if it had
/// been requested itself: the site's rewrite `deny` rules and preset, and the same route.
struct SiblingPolicy<'a> {
    site: &'a CompiledSite,
    /// The route serving the request (`None`: the site's default static files).
    owner: Option<&'a CompiledRoute>,
    host: &'a str,
    effective_client_ip: Option<IpAddr>,
}

impl SiblingPolicy<'_> {
    async fn allows<B>(&self, md_path: &str, req: &Request<B>) -> bool {
        let route = self.site.routes.iter().find(|r| r.matches_path(md_path));
        let same_owner = match (route, self.owner) {
            (None, None) => true,
            (Some(route), Some(owner)) => std::ptr::eq(route, owner),
            _ => false,
        };
        if !same_owner {
            return false;
        }
        // A rule that would refuse, redirect or rewrite the sibling's own path decides what
        // that path is: it is not served in the page's place.
        let untouched = self.site.rewrites.is_empty()
            || matches!(
                self.site
                    .rewrites
                    .apply(
                        md_path,
                        req.uri().query(),
                        self.host,
                        req.method(),
                        req.headers(),
                        policy_ip_of(req),
                        self.site.default_static.as_ref(),
                    )
                    .await,
                crate::rewrite::RewriteOutcome::Unchanged
            );
        untouched
            && self.site.preset_guard.as_ref().is_none_or(|guard| {
                // The request itself has been evaluated (and counted) already.
                matches!(
                    guard.evaluate_uncounted(
                        req.method(),
                        md_path,
                        req.headers(),
                        self.effective_client_ip
                    ),
                    PresetVerdict::Allow
                )
            })
    }
}

/// Whether `path` names an HTML page by the server's own type table (also a directory or an
/// extensionless path, whose index is one): its answers vary with `Accept` while Markdown
/// negotiation is on.
fn names_html_page(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or("");
    !name.contains('.') || miraserve_static::is_html_path(Path::new(name))
}

/// Whether a script-index probe ran before calling [`serve_static_with_markdown`].
struct StaticLookup {
    /// Optional public `Lookup` returned by a prior script-index probe.
    lookup: Option<miraserve_static::Lookup>,
    /// True when a script-index probe already ran: even when `lookup` is `None` (because the
    /// probe ran on the blocking pool), serving calls [`StaticServer::serve_canonical_looked_up`]
    /// so the late decision-time status read stays. False for plain static / published sites so
    /// [`StaticServer::serve_canonical_with_query`] keeps Linux `(1, 1)` single-status fusion.
    after_script_probe: bool,
}

impl StaticLookup {
    const fn direct() -> Self {
        Self {
            lookup: None,
            after_script_probe: false,
        }
    }

    const fn after_script_probe(lookup: Option<miraserve_static::Lookup>) -> Self {
        Self {
            lookup,
            after_script_probe: true,
        }
    }
}

/// Serves a static request with automatic `Accept: text/markdown` / verified AI agent
/// Markdown content negotiation (bounded to 1 MiB and semaphore-throttled offloaded conversion),
/// `Vary: Accept` caching hygiene (`BOT-4`), and FastCGI extension source-disclosure defense (`PATH-1`).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn serve_static_with_markdown<const CACHE_ATTACHED: bool>(
    static_srv: &StaticServer,
    sibling_policy: &SiblingPolicy<'_>,
    req: &Request<PipeReqBody>,
    canonical_path: &str,
    want_markdown: bool,
    agent_selected: bool,
    markdown_negotiation_enabled: bool,
    forbidden_extensions: &[String],
    err_meta: &ErrorMeta<'_>,
    site_pages: &SiteErrorPages,
    lookup: StaticLookup,
) -> Response<PipeRespBody> {
    let mut resp = if is_forbidden_static_extension(canonical_path, forbidden_extensions) {
        err_meta.render_error(StatusCode::NOT_FOUND, None, Some(site_pages))
    } else if !want_markdown || !matches!(*req.method(), Method::GET | Method::HEAD) {
        // The file the index check opened is used only here, where nothing is awaited between
        // that check and serving. Below, the sibling's access check can wait; the file is then
        // opened afresh, so its validators are read after the wait, as in v0.1.1.
        serve_static_as_is::<CACHE_ATTACHED>(
            static_srv,
            req,
            canonical_path,
            markdown_negotiation_enabled,
            err_meta,
            site_pages,
            lookup,
        )
        .await
    } else {
        Box::pin(markdown_or_file(
            static_srv,
            sibling_policy,
            req,
            canonical_path,
            agent_selected,
            markdown_negotiation_enabled,
            err_meta,
            site_pages,
        ))
        .await
    };
    // Which answer a Markdown request gets can depend on rules on request headers (whether a
    // sibling may be served): a shared cache would give one visitor the answer chosen for
    // another, so none of them is stored there.
    if want_markdown && sibling_policy.site.rewrites.uses_request_headers() {
        resp.extensions_mut().insert(ProtectedResponse);
    }
    resp
}

#[cfg(test)]
thread_local! {
    /// Captures the raw `HeaderMap::capacity()` returned by `StaticServer` right before router
    /// Markdown/security/rule/restore mutations run, so real-path capacity tests can assert zero
    /// `HeaderMap` regrowth end-to-end.
    static LAST_STATIC_RESPONSE_INITIAL_CAP: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

/// [`serve_static_with_markdown`] for `GET`/`HEAD` requests with Markdown negotiation active,
/// without the final cache-protection marker.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn markdown_or_file(
    static_srv: &StaticServer,
    sibling_policy: &SiblingPolicy<'_>,
    req: &Request<PipeReqBody>,
    canonical_path: &str,
    agent_selected: bool,
    markdown_negotiation_enabled: bool,
    err_meta: &ErrorMeta<'_>,
    site_pages: &SiteErrorPages,
) -> Response<PipeRespBody> {
    // The order below is fixed: first WHICH representation this request gets (an authored
    // sibling, the page converted, or the file as it is), then that representation's own
    // preconditions. HEAD answers for the whole of it, so a range does not apply.
    let mut headers = req.headers().clone();
    if *req.method() == Method::HEAD {
        headers.remove(http::header::RANGE);
        headers.remove(http::header::IF_RANGE);
    }
    let vary = HeaderValue::from_static("Accept, Accept-Encoding");

    // 1. An authored sibling, when it could be requested itself. Whatever it answers for
    //    itself (also a range of it) is the answer. Authored Markdown siblings always bypass
    //    the opt-in file cache directly via `serve_canonical_unfused_with_extra_headers`.
    //    Reserve +1 extra header slot for `Content-Type` (new key when the sibling answers `304
    //    Not Modified`) and +1 more when `agent_selected` adds `Cache-Control: private, no-transform`,
    //    keeping ordinary non-Markdown `304` responses in their smaller 16-slot bucket.
    if let Some(md_path) = markdown_sibling_path(canonical_path)
        && sibling_policy.allows(&md_path, req).await
    {
        let md_extra_headers = 1 + usize::from(agent_selected);
        let md_resp = static_srv
            .serve_canonical_unfused_with_extra_headers(
                req.method(),
                &md_path,
                &headers,
                md_extra_headers,
            )
            .await;
        if matches!(
            md_resp.status(),
            StatusCode::OK
                | StatusCode::NOT_MODIFIED
                | StatusCode::PARTIAL_CONTENT
                | StatusCode::RANGE_NOT_SATISFIABLE
        ) {
            let mut mapped = md_resp.map(map_static_body);
            if mapped.status() == StatusCode::RANGE_NOT_SATISFIABLE {
                // The sibling's refusal, with the site's page for it like any other
                // refusal (its `Content-Range` is kept, and its own cache rule).
                mapped = err_meta.upgrade_generated_error(mapped, Some(site_pages));
                mapped.headers_mut().insert(VARY, vary);
                return mapped;
            }
            #[cfg(test)]
            LAST_STATIC_RESPONSE_INITIAL_CAP
                .with(|cell| cell.set(Some(mapped.headers().capacity())));
            mapped.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("text/markdown; charset=utf-8"),
            );
            mapped.headers_mut().insert(VARY, vary);
            if agent_selected {
                mapped.headers_mut().insert(
                    CACHE_CONTROL,
                    HeaderValue::from_static("private, no-transform"),
                );
            }
            return mapped;
        }
    }

    // 2. The page converted: when it is HTML within the limit AND a conversion slot is free;
    //    otherwise the file is sent as it is, by the request's own validators and ranges.
    //    The file is looked up and opened once, and that one file is either converted or
    //    sent: a tenant replacing it meanwhile cannot make the two disagree.
    let mut bare = headers.clone();
    for name in [
        http::header::ACCEPT_ENCODING,
        http::header::IF_NONE_MATCH,
        http::header::IF_MODIFIED_SINCE,
        http::header::IF_MATCH,
        http::header::IF_UNMODIFIED_SINCE,
        http::header::IF_RANGE,
        http::header::RANGE,
    ] {
        bare.remove(name);
    }
    // The slot is taken when the static server finds a page to convert, at most once.
    let slot = Arc::new(std::sync::Mutex::new(None));
    let taken = Arc::new(std::sync::OnceLock::new());
    let conversion = miraserve_static::Conversion {
        bare,
        max_len: MAX_MARKDOWN_HTML_BYTES as u64,
        take: {
            let (slot, taken) = (Arc::clone(&slot), Arc::clone(&taken));
            Arc::new(move || {
                *taken.get_or_init(|| {
                    let permit = Arc::clone(markdown_semaphore()).try_acquire_owned().ok();
                    let got = permit.is_some();
                    *slot
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = permit;
                    got
                })
            })
        },
    };
    let found = static_srv
        .serve_canonical_choosing(
            req.method(),
            canonical_path,
            req.uri().query(),
            &headers,
            &conversion,
        )
        .await;
    if found
        .extensions()
        .get::<miraserve_static::ToConvert>()
        .is_none()
        || found.status() != StatusCode::OK
    {
        return finish_static_as_is(
            found,
            canonical_path,
            markdown_negotiation_enabled,
            err_meta,
            site_pages,
        );
    }
    // Held until the conversion is done.
    let _slot = slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    // The Markdown made from the page has no validator of its own (no entity tag, and no date:
    // whether a request gets it also depends on a free slot). A specific `If-Match` cannot be
    // met and a specific `If-None-Match` matches nothing; `*` stands for any representation.
    let condition = |name| {
        headers
            .get(name)
            .map(|value: &HeaderValue| value.as_bytes().trim_ascii() == b"*")
    };
    let bodiless = |status: StatusCode| {
        let mut resp = Response::new(PipeRespBody::empty());
        *resp.status_mut() = status;
        resp.headers_mut().insert(VARY, vary.clone());
        resp
    };
    if condition(http::header::IF_MATCH) == Some(false) {
        return bodiless(StatusCode::PRECONDITION_FAILED);
    }
    if condition(http::header::IF_NONE_MATCH) == Some(true) {
        return bodiless(StatusCode::NOT_MODIFIED);
    }
    let html_resp = found.map(map_static_body);
    let (mut parts, body) = html_resp.into_parts();
    // Strip strong HTML ETag & Accept-Ranges because converted Markdown bytes differ (`BOT-4`).
    parts.headers.remove(http::header::ETAG);
    parts.headers.remove(http::header::LAST_MODIFIED);
    parts.headers.remove(http::header::ACCEPT_RANGES);
    parts.headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/markdown; charset=utf-8"),
    );
    parts.headers.insert(VARY, vary);
    if agent_selected {
        parts.headers.insert(
            CACHE_CONTROL,
            HeaderValue::from_static("private, no-transform"),
        );
    }
    if *req.method() == Method::HEAD {
        parts.headers.remove(CONTENT_LENGTH);
        return Response::from_parts(parts, PipeRespBody::empty());
    }
    match Limited::new(body, MAX_MARKDOWN_HTML_BYTES).collect().await {
        Ok(collected) => {
            let html_bytes = collected.to_bytes();
            let converted = tokio::task::spawn_blocking(move || {
                html_to_markdown(&String::from_utf8_lossy(&html_bytes))
            })
            .await;
            let Ok(md) = converted else {
                return err_meta.render_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    None,
                    Some(site_pages),
                );
            };
            let md_bytes = Bytes::from(md.into_bytes());
            if let Ok(len_val) = HeaderValue::from_str(&md_bytes.len().to_string()) {
                parts.headers.insert(CONTENT_LENGTH, len_val);
            }
            Response::from_parts(parts, PipeRespBody::full(md_bytes))
        }
        Err(_) => err_meta.render_error(StatusCode::INTERNAL_SERVER_ERROR, None, Some(site_pages)),
    }
}

/// The file as it is, with the request's own validators and ranges; an HTML page says that its
/// answer varies with `Accept` while Markdown negotiation is on.
async fn serve_static_as_is<const CACHE_ATTACHED: bool>(
    static_srv: &StaticServer,
    req: &Request<PipeReqBody>,
    canonical_path: &str,
    markdown_negotiation_enabled: bool,
    err_meta: &ErrorMeta<'_>,
    site_pages: &SiteErrorPages,
    lookup: StaticLookup,
) -> Response<PipeRespBody> {
    // A range is for GET: HEAD answers for the whole file (RFC 9110 section 14.2).
    let whole;
    let headers =
        if *req.method() == Method::HEAD && req.headers().contains_key(http::header::RANGE) {
            let mut without_range = req.headers().clone();
            without_range.remove(http::header::RANGE);
            without_range.remove(http::header::IF_RANGE);
            whole = without_range;
            &whole
        } else {
            req.headers()
        };
    let raw_resp = if CACHE_ATTACHED {
        Box::pin(serve_static_as_is_cached(
            static_srv,
            req,
            canonical_path,
            headers,
            lookup,
        ))
        .await
    } else if lookup.after_script_probe {
        static_srv
            .serve_canonical_looked_up_no_cache(
                req.method(),
                canonical_path,
                req.uri().query(),
                headers,
                lookup.lookup,
            )
            .await
    } else {
        static_srv
            .serve_canonical_with_query_no_cache(
                req.method(),
                canonical_path,
                req.uri().query(),
                headers,
            )
            .await
    };
    finish_static_as_is(
        raw_resp,
        canonical_path,
        markdown_negotiation_enabled,
        err_meta,
        site_pages,
    )
}

async fn serve_static_as_is_cached(
    static_srv: &StaticServer,
    req: &Request<PipeReqBody>,
    canonical_path: &str,
    headers: &HeaderMap,
    lookup: StaticLookup,
) -> Response<miraserve_static::StaticBody> {
    #[cfg(test)]
    ROUTER_CACHE_LOOKUP_OR_ADMIT_CALLS.fetch_add(1, Ordering::Relaxed);
    let bypass = req.extensions().get::<RequestCacheBypass>().is_some()
        || req.headers().contains_key(http::header::RANGE)
        || req.headers().contains_key(http::header::IF_RANGE);
    let no_admit = req.extensions().get::<RequestCacheNoAdmit>().is_some();
    let carried = req.extensions().get::<CarriedFillStart>().map(|c| c.0);
    if lookup.after_script_probe {
        if bypass {
            static_srv
                .serve_canonical_looked_up_uncached(
                    req.method(),
                    canonical_path,
                    req.uri().query(),
                    headers,
                    lookup.lookup,
                )
                .await
        } else if no_admit {
            static_srv
                .serve_canonical_looked_up_no_admit(
                    req.method(),
                    canonical_path,
                    req.uri().query(),
                    headers,
                    lookup.lookup,
                )
                .await
        } else if let Some(carried) = carried {
            static_srv
                .serve_canonical_looked_up_with_start(
                    req.method(),
                    canonical_path,
                    req.uri().query(),
                    headers,
                    lookup.lookup,
                    carried,
                )
                .await
        } else {
            static_srv
                .serve_canonical_looked_up(
                    req.method(),
                    canonical_path,
                    req.uri().query(),
                    headers,
                    lookup.lookup,
                )
                .await
        }
    } else if bypass {
        static_srv
            .serve_canonical_with_query_uncached(
                req.method(),
                canonical_path,
                req.uri().query(),
                headers,
            )
            .await
    } else if no_admit {
        static_srv
            .serve_canonical_with_query_no_admit(
                req.method(),
                canonical_path,
                req.uri().query(),
                headers,
            )
            .await
    } else if let Some(carried) = carried {
        static_srv
            .serve_canonical_with_query_with_start(
                req.method(),
                canonical_path,
                req.uri().query(),
                headers,
                carried,
            )
            .await
    } else {
        static_srv
            .serve_canonical_with_query(req.method(), canonical_path, req.uri().query(), headers)
            .await
    }
}

/// The static server's answer for a file as it is, as the site sends it.
fn finish_static_as_is(
    raw_resp: Response<miraserve_static::StaticBody>,
    canonical_path: &str,
    markdown_negotiation_enabled: bool,
    err_meta: &ErrorMeta<'_>,
    site_pages: &SiteErrorPages,
) -> Response<PipeRespBody> {
    #[cfg(test)]
    if !(raw_resp.status().is_client_error() || raw_resp.status().is_server_error()) {
        LAST_STATIC_RESPONSE_INITIAL_CAP.with(|cell| cell.set(Some(raw_resp.headers().capacity())));
    }
    let raw_resp = raw_resp.map(map_static_body);
    let mut resp = err_meta.upgrade_generated_error(raw_resp, Some(site_pages));
    // BOT-4: Always advertise `Vary: Accept` on HTML responses whenever Markdown negotiation is active.
    let is_html = resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("text/html"));
    // Another `Accept` can get other bytes for this URL when it is a page, or when it may have
    // a Markdown sibling (an extensionless file too). A 304 carries no type: it varies like
    // the 200 of the same URL.
    let negotiable = is_html
        || names_html_page(canonical_path)
        || markdown_sibling_path(canonical_path).is_some();
    // Also a redirect (a directory without its slash): a Markdown request for the same URL
    // may get a sibling instead.
    let answers_for_the_file = resp.status().is_success() || resp.status().is_redirection();
    if markdown_negotiation_enabled && answers_for_the_file && negotiable {
        resp.headers_mut()
            .insert(VARY, HeaderValue::from_static("Accept, Accept-Encoding"));
    }
    resp
}

/// Returns `true` iff `haystack.to_ascii_lowercase().ends_with(lower_suffix)` without allocating.
#[inline]
fn ends_with_ascii_lower(haystack: &str, lower_suffix: &str) -> bool {
    haystack.len() >= lower_suffix.len()
        && haystack
            .as_bytes()
            .get(haystack.len() - lower_suffix.len()..)
            .is_some_and(|tail| {
                tail.iter()
                    .zip(lower_suffix.as_bytes())
                    .all(|(&h, &s)| h.to_ascii_lowercase() == s)
            })
}

fn is_forbidden_static_extension(canonical_path: &str, forbidden_extensions: &[String]) -> bool {
    if forbidden_extensions.is_empty() {
        return false;
    }
    let check_part = |part: &str| {
        let trimmed = part.trim_end_matches('/');
        forbidden_extensions
            .iter()
            .any(|ext| ends_with_ascii_lower(trimmed, ext))
    };
    if check_part(canonical_path) {
        return true;
    }
    if let Some((before_q, _)) = canonical_path.split_once('?')
        && check_part(before_q)
    {
        return true;
    }
    false
}

#[allow(clippy::too_many_arguments)]
async fn handle_ai_publish_mcp(
    store: Arc<ReleaseStore>,
    auth_mode: PublishAuthMode,
    endpoint_path: String,
    site_host: String,
    is_https: bool,
    verified_client_cert_dn: Option<String>,
    req: Request<PipeReqBody>,
    max_body_bytes: u64,
    err_meta: &ErrorMeta<'_>,
    site_pages: &SiteErrorPages,
) -> Response<PipeRespBody> {
    if *req.method() != Method::POST {
        let mut resp =
            err_meta.render_error(StatusCode::METHOD_NOT_ALLOWED, None, Some(site_pages));
        resp.headers_mut()
            .insert(ALLOW, HeaderValue::from_static("POST"));
        return resp;
    }

    // Fast header-level authentication precheck BEFORE buffering request body!
    {
        let auth_ctx = McpPublishAuthContext {
            endpoint_path: &endpoint_path,
            site_host: &site_host,
            is_https,
            verified_client_cert_dn: verified_client_cert_dn.as_deref(),
        };
        if let Some(unauth_resp) =
            precheck_mcp_publish_auth(&store, auth_mode, req.headers(), &auth_ctx)
        {
            return unauth_resp.map(|bytes| PipeRespBody::full(Bytes::from(bytes)));
        }
    }

    let (parts, mut body) = req.into_parts();
    let mut raw = Vec::new();
    while let Some(frame_res) = body.frame().await {
        match frame_res {
            Ok(frame) => {
                if let Ok(data) = frame.into_data() {
                    if (raw.len() as u64).saturating_add(data.len() as u64) > max_body_bytes {
                        return err_meta.render_error(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            None,
                            Some(site_pages),
                        );
                    }
                    raw.extend_from_slice(&data);
                }
            }
            Err(HttpError::PayloadTooLarge(_)) => {
                return err_meta.render_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    None,
                    Some(site_pages),
                );
            }
            Err(HttpError::SlowBodyRate(min_rate_bps)) => {
                warn!(
                    request_id = %err_meta.request_id,
                    host = %site_host,
                    min_rate_bps,
                    "closing slow publish request body upload (Slowloris guard)"
                );
                return err_meta.render_error(StatusCode::REQUEST_TIMEOUT, None, Some(site_pages));
            }
            Err(_) => {
                return err_meta.render_error(StatusCode::BAD_REQUEST, None, Some(site_pages));
            }
        }
    }

    // Offload synchronous Ed25519 verification + staging filesystem writes to blocking pool.
    let headers = parts.headers;
    match tokio::task::spawn_blocking(move || {
        let auth_ctx = McpPublishAuthContext {
            endpoint_path: &endpoint_path,
            site_host: &site_host,
            is_https,
            verified_client_cert_dn: verified_client_cert_dn.as_deref(),
        };
        handle_mcp_publish_http(&store, auth_mode, &headers, &raw, &auth_ctx)
    })
    .await
    {
        Ok(resp) => resp.map(|bytes| PipeRespBody::full(Bytes::from(bytes))),
        Err(_) => err_meta.render_error(StatusCode::INTERNAL_SERVER_ERROR, None, Some(site_pages)),
    }
}

fn format_host_for_url(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

fn read_acme_webroot_token_file(
    path: &Path,
    token: &str,
    secret_files: &[(u64, u64)],
) -> Option<Vec<u8>> {
    if let Some(problem) = miraserve_static::credential_file_problem(path) {
        if path.exists() {
            warn!(
                token_file = %path.display(),
                problem = %problem,
                "acme-webroot token not served: the file and its directory must belong to root or the MiraServe user"
            );
        }
        return None;
    }
    let raw = miraserve_static::read_no_symlink_file_excluding(path, 4096, secret_files).ok()?;
    // Only an HTTP-01 key authorization for this very token is ever answered:
    // `<token>.<base64url SHA-256 account key thumbprint>` (43 characters), optionally
    // followed by a newline. Whatever else the file holds (a key, a password file, any
    // other content) is never returned, whatever its name or how it got there.
    let body = raw
        .strip_suffix(b"\r\n")
        .or_else(|| raw.strip_suffix(b"\n"))
        .unwrap_or(&raw);
    is_key_authorization(body, token).then(|| body.to_vec())
}

fn finish_acme_http01_response<B>(
    req: &Request<B>,
    key_auth: Vec<u8>,
    err_meta: &ErrorMeta<'_>,
) -> Response<PipeRespBody> {
    let body = if *req.method() == Method::HEAD {
        PipeRespBody::empty()
    } else {
        PipeRespBody::full(Bytes::from(key_auth))
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(HeaderName::from_static("x-content-type-options"), "nosniff")
        .header(CACHE_CONTROL, "no-store")
        .body(body)
        .unwrap_or_else(|_| err_meta.render_error(StatusCode::INTERNAL_SERVER_ERROR, None, None))
}

fn maybe_serve_acme_http01<B>(
    req: &Request<B>,
    canonical_path: &str,
    acme_challenges: &AcmeChallengeStore,
    router: &CompiledRouter,
    err_meta: &ErrorMeta<'_>,
    probed_fs: &mut bool,
) -> Option<Response<PipeRespBody>> {
    let token = canonical_path.strip_prefix(ACME_HTTP01_PREFIX)?;
    if token.is_empty() || token.contains('/') || token.contains("..") {
        return None;
    }
    if !matches!(*req.method(), Method::GET | Method::HEAD) {
        let mut resp = err_meta.render_error(StatusCode::METHOD_NOT_ALLOWED, None, None);
        resp.headers_mut()
            .insert(ALLOW, HeaderValue::from_static("GET, HEAD"));
        return Some(resp);
    }
    let host = extract_request_host_ref(req)?;
    // MiraServe's own challenges first, then a token an external ACME client wrote into the
    // configured webroot (for configured hosts only).
    let key_auth = acme_challenges
        .get_http01_token(host, token)
        .map(String::into_bytes)
        .or_else(|| router.acme_webroot_token(host, token, probed_fs))?;
    Some(finish_acme_http01_response(req, key_auth, err_meta))
}

async fn maybe_serve_acme_http01_async<B>(
    req: &Request<B>,
    canonical_path: &str,
    acme_challenges: &AcmeChallengeStore,
    router: &CompiledRouter,
    err_meta: &ErrorMeta<'_>,
    probed_fs: &mut bool,
) -> Option<Response<PipeRespBody>> {
    let token = canonical_path.strip_prefix(ACME_HTTP01_PREFIX)?;
    if token.is_empty() || token.contains('/') || token.contains("..") {
        return None;
    }
    if !matches!(*req.method(), Method::GET | Method::HEAD) {
        let mut resp = err_meta.render_error(StatusCode::METHOD_NOT_ALLOWED, None, None);
        resp.headers_mut()
            .insert(ALLOW, HeaderValue::from_static("GET, HEAD"));
        return Some(resp);
    }
    let host = extract_request_host_ref(req)?;
    let key_auth = match acme_challenges
        .get_http01_token(host, token)
        .map(String::into_bytes)
    {
        Some(found) => found,
        None => {
            router
                .acme_webroot_token_async(host, token, probed_fs)
                .await?
        }
    };
    Some(finish_acme_http01_response(req, key_auth, err_meta))
}

fn push_unique_extension(list: &mut Vec<String>, ext: &str) {
    let trimmed = ext.trim().to_ascii_lowercase();
    if trimmed.is_empty() || trimmed == "." {
        return;
    }
    let dot_ext = if trimmed.starts_with('.') {
        trimmed
    } else {
        format!(".{trimmed}")
    };
    if !list.contains(&dot_ext) {
        list.push(dot_ext);
    }
}

/// Why a site with `owner-dir` cannot be served: one of the document roots it opened is not really
/// inside that directory (checked on the opened handles, so links inside the owner directory are
/// fine and nothing can change between the check and serving). `None` when all are inside, or
/// when the site has no `owner-dir`.
fn owner_dir_violation(
    site: &SiteConfig,
    default_static: Option<&StaticServer>,
    routes: &[CompiledRoute],
) -> Option<String> {
    let owner = site.owner_dir.as_ref()?;
    let Ok(owner_real) = std::fs::canonicalize(owner) else {
        return Some(format!("owner-dir '{owner}' cannot be resolved"));
    };
    let servers = default_static
        .into_iter()
        .chain(routes.iter().filter_map(|route| match &route.handler {
            CompiledHandler::Static { static_server, .. }
            | CompiledHandler::TryFiles { static_server, .. } => Some(static_server),
            CompiledHandler::FastCgi { script_root, .. } => script_root.as_ref(),
            _ => None,
        }));
    for server in servers {
        match server.opened_root_path() {
            Some(real) if real.starts_with(&owner_real) => {}
            Some(real) => {
                return Some(format!(
                    "document root '{}' is outside owner-dir '{owner}'",
                    real.display()
                ));
            }
            None => return Some("the document root's location cannot be verified".to_owned()),
        }
    }
    None
}

/// Opens a static server that never serves `secret_files`.
fn open_static(
    secret_files: &Arc<[(u64, u64)]>,
    root: impl AsRef<std::path::Path>,
    options: StaticConfig,
    probe_root_policy: bool,
) -> Result<StaticServer, miraserve_static::StaticError> {
    StaticServer::open_with_nowait_policy_probe(root, options, probe_root_policy).map(
        |mut server| {
            server.set_secret_files(Arc::clone(secret_files));
            server
        },
    )
}

/// Every document root any site or route serves from (a `basic-auth` users file must not be
/// inside one of them).
fn served_document_roots(sites: &[SiteConfig]) -> Vec<std::path::PathBuf> {
    sites
        .iter()
        .flat_map(|site| {
            site.root
                .iter()
                .chain(site.routes.iter().filter_map(|route| route.root.as_ref()))
        })
        .map(std::path::PathBuf::from)
        .collect()
}

/// Computes how many per-worker upstream connection pools each [`ReverseProxy`] should allocate
/// for `config`, matching `miraserve-core`'s worker event-loop count (`0` in default `"shared"`
/// mode, under `key-isolation "split-daemon"`, and on non-Linux platforms).
fn proxy_worker_pool_count(config: &Config) -> usize {
    if !cfg!(target_os = "linux")
        || config.server.tls.key_isolation == miraserve_config::KeyIsolation::SplitDaemon
    {
        return 0;
    }
    match config.server.workers {
        miraserve_config::Workers::Shared => 0,
        miraserve_config::Workers::Auto => {
            std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
        }
        miraserve_config::Workers::Count(count) => usize::try_from(count).unwrap_or(1).max(1),
    }
}

#[allow(
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::fn_params_excessive_bools
)]
fn compile_site(
    credential_files: &[std::path::PathBuf],
    served_roots: &[std::path::PathBuf],
    areas: &crate::basic_auth::LoadedAreas,
    secret_files: &Arc<[(u64, u64)]>,
    site: &SiteConfig,
    global_allows_tls12: bool,
    global_client_ca: Option<&str>,
    global_pqc: bool,
    upstream_timeouts: (
        std::time::Duration,
        std::time::Duration,
        std::time::Duration,
    ),
    proxy_worker_pools: usize,
    trusted_proxies: &[IpCidr],
    runtime_agent_keys: &Arc<AgentKeyRegistry>,
    is_reload: bool,
    probe_root_policy: bool,
    split_keys: Option<&SplitSigningKeys<'_>>,
    file_cache: Option<&Arc<miraserve_static::FileCache>>,
) -> Result<CompiledSite, HttpError> {
    // A quarantined site answers 503 and nothing else: it is compiled from a copy without
    // anything that would be opened or loaded (routes, publishing, bot keys, client CA,
    // password check, error pages, rules). The configuration itself keeps those entries, so
    // every server-wide protection list (users files, publish stores, keys) still sees them.
    let sanitized;
    let site = if site.quarantine.is_some() {
        sanitized = SiteConfig {
            root: None,
            routes: Vec::new(),
            ai_publish: None,
            bot_auth: None,
            basic_auth: None,
            error_pages: None,
            rewrites: Vec::new(),
            headers: Vec::new(),
            access: Vec::new(),
            file_cache: None,
            tls: site.tls.clone().map(|mut tls| {
                tls.client_ca = None;
                tls
            }),
            ..site.clone()
        };
        &sanitized
    } else {
        site
    };
    // A tenant site whose own certificate pair cannot be loaded is not served under some other
    // certificate: the error makes the caller compile it as a quarantined 503 site.
    if split_keys.is_some()
        && site.owner_dir.is_some()
        && site.quarantine.is_none()
        && let Some(t) = &site.tls
        && (t.cert.is_some() || t.key.is_some())
    {
        return Err(HttpError::Router(format!(
            "site '{}' uses 'owner-dir' with its own TLS pair, unsupported with split-daemon",
            site.hosts.first().map_or("<site>", String::as_str)
        )));
    }
    if split_keys.is_none()
        && site.owner_dir.is_some()
        && site.quarantine.is_none()
        && let Some(tls) = &site.tls
        && let (Some(cert), Some(key)) = (&tls.cert, &tls.key)
        && let Err(err) = miraserve_tls::load_certified_key_from_files(
            cert,
            key,
            &miraserve_tls::build_crypto_provider(global_pqc),
        )
    {
        return Err(HttpError::Router(format!(
            "site certificate ('{cert}', '{key}') cannot be loaded: {err}"
        )));
    }
    // A password database placed inside a served document root (as configured) could be
    // downloaded: refuse the configuration (`check --fs` reports it first).
    if let Some(auth) = &site.basic_auth
        && let Some(problem) = crate::basic_auth::users_file_problem(
            std::path::Path::new(&auth.users_file),
            served_roots,
        )
    {
        return Err(HttpError::Router(format!(
            "basic-auth users file '{}': {problem}",
            auth.users_file
        )));
    }

    // PATH-1 & R5-MIG-1 defense-in-depth: ALWAYS refuse PHP script extensions as static files
    // on EVERY site (even when no FastCGI route is configured!), plus any extra script extensions
    // claimed by FastCGI routes so default root, static routes, directory index (`index.php`),
    // try-files, and symlinks never leak server-side script source code.
    let mut fastcgi_extensions = Vec::new();
    let mut routed_fastcgi_extensions = Vec::new();
    for ext in ["php", "phtml", "phar", "phps"] {
        push_unique_extension(&mut fastcgi_extensions, ext);
    }
    // A quarantined site compiles to a plain 503: its routes (whose roots were dropped) are
    // not built, so they cannot fail the whole configuration.
    for route in site.routes.iter().filter(|_| site.quarantine.is_none()) {
        if matches!(route.handler, RouteHandler::FastCgi(_)) {
            if let Some(ext) = route.pattern.strip_prefix("*.") {
                push_unique_extension(&mut fastcgi_extensions, ext);
                push_unique_extension(&mut routed_fastcgi_extensions, ext);
            } else if let Some((_, tail)) = route.pattern.rsplit_once('.')
                && !tail.is_empty()
                && tail.chars().all(|c| c.is_ascii_alphanumeric())
            {
                push_unique_extension(&mut fastcgi_extensions, tail);
                push_unique_extension(&mut routed_fastcgi_extensions, tail);
            }
        }
    }

    let site_label = site.hosts.first().map_or("<site>", String::as_str);

    let site_static_cfg = StaticConfig {
        index: site
            .index
            .clone()
            .unwrap_or_else(|| StaticConfig::default().index),
        precompressed: site.precompressed,
        ..StaticConfig::default()
    };

    // Opt-in file cache for this site's static and try-files handlers only (never for
    // quarantined sites, ai-publish sites, or FastCGI script_root).
    let site_cache = if site.quarantine.is_none() && site.ai_publish.is_none() {
        site.file_cache
            .and_then(|window| file_cache.map(|cache| (Arc::clone(cache), window)))
    } else {
        None
    };

    // HANDOVER §5 #9: A tenant-owned `site.root` that is deleted, chmod-000'd, or broken on disk
    // must NEVER prevent startup or hot reload for healthy sibling sites. Degrade ONLY this site's
    // static root to `503 Service Unavailable` and log a clear site-identifying warning.
    let (mut default_static, default_static_unavailable) = match &site.root {
        Some(root) => match open_static(
            secret_files,
            root,
            site_static_cfg.clone(),
            probe_root_policy,
        ) {
            Ok(srv) => {
                let mut srv = srv.with_forbidden_extensions(fastcgi_extensions.clone());
                if let Some((cache, window)) = &site_cache {
                    srv = srv.with_file_cache(Arc::clone(cache), *window);
                }
                (Some(srv), false)
            }
            Err(err) => {
                warn!(
                    site = %site_label,
                    root = %root,
                    error = %err,
                    "site root could not be opened; this site will return 503 Service Unavailable while other sites continue serving"
                );
                (None, true)
            }
        },
        None => (None, false),
    };

    let ai_publish = match &site.ai_publish {
        Some(pub_cfg) => {
            // R3-PUB-5 & R4-PUB-3: Bind the release store to the explicit `ai-publish.site-id`
            // when configured, falling back to `site.hosts[0]` lowercased.
            let site_id = pub_cfg
                .site_id
                .as_deref()
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .or_else(|| site.hosts.first().map(|h| h.to_ascii_lowercase()));
            let store = Arc::new(
                if is_reload {
                    ReleaseStore::open_for_site_reload(pub_cfg.clone(), site_id)
                } else {
                    ReleaseStore::open_for_site(pub_cfg.clone(), site_id)
                }
                .map_err(|err| {
                    HttpError::Router(format!("site '{site_label}' ai-publish: {err}"))
                })?,
            );
            let mcp_endpoint = pub_cfg
                .mcp_endpoint
                .as_ref()
                .map(|ep| (ep.path.clone(), ep.auth));
            Some(CompiledAiPublish {
                store,
                mcp_endpoint,
            })
        }
        None => None,
    };

    // Build an isolated per-site mTLS client CA verifier bound strictly to THIS site's
    // `site.tls.client-ca` (inheriting global `server.tls.client-ca` only when site override is None).
    let effective_client_ca = site
        .tls
        .as_ref()
        .and_then(|t| t.client_ca.as_deref())
        .or(global_client_ca);
    let site_pqc = site
        .tls
        .as_ref()
        .and_then(|t| t.pqc_hybrid)
        .unwrap_or(global_pqc);
    let client_cert_trust = effective_client_ca
        .map(|ca| {
            ClientCertTrust::from_pem_file(ca, site_pqc).map_err(|err| {
                HttpError::Router(format!("site '{site_label}' tls.client-ca '{ca}': {err}"))
            })
        })
        .transpose()?;

    let allows_tls_1_2 = global_allows_tls12 || site.tls.as_ref().is_some_and(|t| t.compat_tls_1_2);
    let preset_guard = site
        .preset
        .map(|preset| Arc::new(SitePresetGuard::new(preset)));
    let bot_auth = match &site.bot_auth {
        Some(ba) => {
            // BOT-1 + atomic reload isolation: build a FRESH per-site AgentKeyRegistry from KDL
            // so removed keys vanish immediately upon reload commit, failed reloads never mutate
            // live registries, and Site A's KDL keys never bleed into Site B!
            let site_keys = Arc::new(AgentKeyRegistry::new());
            site_keys
                .load_from_bot_auth_config(ba)
                .map_err(|err| HttpError::Router(format!("site '{site_label}' bot-auth: {err}")))?;
            Some(BotAuthGuard::new_with_fallback(
                ba.clone(),
                site_keys,
                Some(Arc::clone(runtime_agent_keys)),
            ))
        }
        None => None,
    };
    let rate_limit = site.rate_limit.as_ref().map(Limiter::from_config);

    let mut routes = Vec::with_capacity(site.routes.len());
    // A quarantined site compiles to a plain 503: its routes (whose roots were dropped) are
    // not built, so they cannot fail the whole configuration.
    for route in site.routes.iter().filter(|_| site.quarantine.is_none()) {
        let handler = match &route.handler {
            RouteHandler::Static(static_cfg) => {
                let root = route
                    .root
                    .as_deref()
                    .or(site.root.as_deref())
                    .ok_or_else(|| {
                        HttpError::Router(format!(
                            "site '{site_label}' static route '{}' has no configured root directory",
                            route.pattern
                        ))
                    })?;
                // Codex G9: Inherit site-level `index` order whenever an explicit `static` route
                // omits its own `index` directive, while preserving explicit route overrides.
                let mut effective_static_cfg = static_cfg.clone();
                if !effective_static_cfg.index_explicit
                    && let Some(site_index) = &site.index
                {
                    effective_static_cfg.index.clone_from(site_index);
                }
                if !effective_static_cfg.precompressed_explicit {
                    effective_static_cfg.precompressed = site.precompressed;
                }
                let has_script_index = !routed_fastcgi_extensions.is_empty()
                    && effective_static_cfg
                        .index
                        .iter()
                        .any(|idx| is_forbidden_static_extension(idx, &routed_fastcgi_extensions));
                match open_static(secret_files, root, effective_static_cfg, probe_root_policy) {
                    Ok(srv) => {
                        let mut srv = srv.with_forbidden_extensions(fastcgi_extensions.clone());
                        if let Some((cache, window)) = &site_cache {
                            srv = srv.with_file_cache(Arc::clone(cache), *window);
                        }
                        CompiledHandler::Static {
                            static_server: srv,
                            has_script_index,
                        }
                    }
                    Err(err) => {
                        warn!(
                            site = %site_label,
                            route = %route.pattern,
                            root = %root,
                            error = %err,
                            "static route root could not be opened; route will return 503 Service Unavailable"
                        );
                        CompiledHandler::Unavailable
                    }
                }
            }
            RouteHandler::TryFiles(tf) => {
                let candidates = &tf.candidates;
                let root = route
                    .root
                    .as_deref()
                    .or(site.root.as_deref())
                    .ok_or_else(|| {
                        HttpError::Router(format!(
                            "site '{site_label}' try-files route '{}' has no configured root directory",
                            route.pattern
                        ))
                    })?;
                match open_static(
                    secret_files,
                    root,
                    site_static_cfg.clone(),
                    probe_root_policy,
                ) {
                    Ok(srv) => {
                        let mut srv = srv.with_forbidden_extensions(fastcgi_extensions.clone());
                        if let Some((cache, window)) = &site_cache {
                            srv = srv
                                .with_file_cache(Arc::clone(cache), *window)
                                .with_try_files_candidates(candidates.clone())
                                .with_try_files_script_extensions(fastcgi_extensions.clone());
                        }
                        if tf.fallback_unless_extension {
                            srv = srv.with_try_files_fallback_unless_extension(true);
                        }
                        CompiledHandler::TryFiles {
                            static_server: srv,
                            candidates: candidates.clone(),
                            // Populated below once all routes of this site are compiled.
                            fallback_spawns: false,
                        }
                    }
                    Err(err) => {
                        warn!(
                            site = %site_label,
                            route = %route.pattern,
                            root = %root,
                            error = %err,
                            "try-files route root could not be opened; route will return 503 Service Unavailable"
                        );
                        CompiledHandler::Unavailable
                    }
                }
            }
            RouteHandler::FastCgi(fcgi) => {
                let root_opt = route.root.as_deref().or(site.root.as_deref());
                let doc_root = root_opt.map_or_else(|| PathBuf::from("."), PathBuf::from);
                match root_opt {
                    Some(r) => match open_static(
                        secret_files,
                        r,
                        StaticConfig::default(),
                        probe_root_policy,
                    ) {
                        Ok(srv) => CompiledHandler::FastCgi {
                            // On an `owner-dir` site, PHP is told the real location of the
                            // directory MiraServe opened and checked (the script it verified),
                            // not the configured name a link could later point elsewhere.
                            client: FastCgiClient::new(
                                fcgi.target.clone(),
                                site.owner_dir
                                    .as_ref()
                                    .and(srv.opened_root_path())
                                    .unwrap_or(doc_root),
                            )
                            .with_timeout(fcgi.timeout)
                            .with_replay_safe_methods(fcgi.replay_safe_methods)
                            .with_max_streamed_answers(fcgi.max_streamed_answers),
                            script_root: Some(srv),
                        },
                        Err(err) => {
                            // PATH-6: Never fall back to `script_root: None` when a root was configured;
                            // isolate this route to 503 without failing other sites!
                            warn!(
                                site = %site_label,
                                route = %route.pattern,
                                root = %r,
                                error = %err,
                                "FastCGI route root could not be opened; route will return 503 Service Unavailable"
                            );
                            CompiledHandler::Unavailable
                        }
                    },
                    None => CompiledHandler::FastCgi {
                        client: FastCgiClient::new(fcgi.target.clone(), doc_root)
                            .with_timeout(fcgi.timeout)
                            .with_replay_safe_methods(fcgi.replay_safe_methods)
                            .with_max_streamed_answers(fcgi.max_streamed_answers),
                        script_root: None,
                    },
                }
            }
            RouteHandler::ReverseProxy(rp_cfg) => {
                // R5-PRX-3: Honor optional per-route upstream timeout overrides (falling back to
                // global `server.timeouts.*`) so SSE routes can configure longer idle gaps cleanly.
                let connect_tmo = rp_cfg
                    .upstream_connect_timeout
                    .unwrap_or(upstream_timeouts.0);
                let response_tmo = rp_cfg
                    .upstream_response_timeout
                    .unwrap_or(upstream_timeouts.1);
                let body_idle_tmo = rp_cfg
                    .upstream_body_idle_timeout
                    .unwrap_or(upstream_timeouts.2);
                CompiledHandler::ReverseProxy(Arc::new(
                    ReverseProxy::new_with_timeouts_and_workers(
                        rp_cfg,
                        connect_tmo,
                        response_tmo,
                        body_idle_tmo,
                        proxy_worker_pools,
                    )
                    .map_err(|err| {
                        HttpError::Router(format!(
                            "site '{site_label}' route '{}' reverse-proxy: {err}",
                            route.pattern
                        ))
                    })?
                    .with_trusted_proxy_cidrs(trusted_proxies.to_vec()),
                ))
            }
            RouteHandler::McpGateway(mcp_cfg) => {
                let connect_tmo = mcp_cfg
                    .upstream_connect_timeout
                    .unwrap_or(upstream_timeouts.0);
                let response_tmo = mcp_cfg
                    .upstream_response_timeout
                    .unwrap_or(upstream_timeouts.1);
                let body_idle_tmo = mcp_cfg
                    .upstream_body_idle_timeout
                    .unwrap_or(upstream_timeouts.2);
                CompiledHandler::McpGateway(Arc::new(
                    McpGateway::new_with_timeouts(
                        mcp_cfg.clone(),
                        connect_tmo,
                        response_tmo,
                        body_idle_tmo,
                    )
                    .map_err(|err| {
                        HttpError::Router(format!(
                            "site '{site_label}' route '{}' mcp-gateway: {err}",
                            route.pattern
                        ))
                    })?,
                ))
            }
            RouteHandler::WasmPlugin(wasm_cfg) => {
                match WasmPluginRuntime::from_config(wasm_cfg.clone()) {
                    Ok(rt) => CompiledHandler::WasmPlugin(Arc::new(rt)),
                    Err(err) => {
                        // HANDOVER §5 #9: A tenant-owned `.wasm` plugin file that is deleted, unreadable,
                        // or corrupted must isolate ONLY this route to `503 Service Unavailable`.
                        warn!(
                            site = %site_label,
                            route = %route.pattern,
                            module_path = %wasm_cfg.module_path,
                            error = %err,
                            "WASM plugin could not be loaded; route will return 503 Service Unavailable"
                        );
                        CompiledHandler::Unavailable
                    }
                }
            }
            RouteHandler::Respond(status) => CompiledHandler::Respond(
                StatusCode::from_u16(*status)
                    .map_err(|_| HttpError::Router(format!("invalid respond status {status}")))?,
            ),
            RouteHandler::Redirect(redirect) => CompiledHandler::Redirect {
                status: StatusCode::from_u16(redirect.status).map_err(|_| {
                    HttpError::Router(format!(
                        "site '{site_label}' route '{}' invalid redirect status {}",
                        route.pattern, redirect.status
                    ))
                })?,
                target: redirect.target.clone(),
                route_prefix: route
                    .pattern
                    .strip_suffix("/*")
                    .unwrap_or_default()
                    .to_owned(),
            },
        };

        let has_file_cache = matches!(
            &handler,
            CompiledHandler::Static {
                static_server: srv,
                ..
            }
            | CompiledHandler::TryFiles {
                static_server: srv,
                ..
            } if srv.has_file_cache()
        );
        routes.push(CompiledRoute {
            matcher: RouteMatcher::compile(&route.pattern),
            pattern: route.pattern.clone(),
            security_headers: route.security_headers,
            rate_limit: route.rate_limit.as_ref().map(Limiter::from_config),
            handler,
            proxy_strip_prefix: match &route.handler {
                RouteHandler::ReverseProxy(rp) if rp.strip_prefix => route
                    .pattern
                    .strip_suffix("/*")
                    .filter(|p| !p.is_empty())
                    .map(str::to_owned),
                _ => None,
            },
            headers: compile_header_rules(&route.headers)?,
            has_file_cache,
        });
    }

    let unavailable = site
        .quarantine
        .clone()
        .or_else(|| owner_dir_violation(site, default_static.as_ref(), &routes));
    if let Some(reason) = &unavailable {
        tracing::warn!(
            site = %site.hosts.first().map_or("<site>", String::as_str),
            reason = %reason,
            "site unavailable (503); see the reason for what to fix (reload, or restart when the reason says so)"
        );
    }
    let error_pages = load_site_error_pages(
        site,
        default_static.as_ref(),
        credential_files,
        secret_files,
        split_keys,
    );

    let default_static_has_script_index = !routed_fastcgi_extensions.is_empty()
        && site_static_cfg
            .index
            .iter()
            .any(|idx| is_forbidden_static_extension(idx, &routed_fastcgi_extensions));
    let site_has_waiting_handler = routes.iter().any(|r| handler_always_spawns(&r.handler))
        || ai_publish
            .as_ref()
            .is_some_and(|p| p.mcp_endpoint.is_some());
    let try_files_fallback_spawns: Vec<(usize, bool)> = routes
        .iter()
        .enumerate()
        .filter_map(|(route_idx, route)| {
            let CompiledHandler::TryFiles { candidates, .. } = &route.handler else {
                return None;
            };
            let spawns = default_static_has_script_index
                || try_files_last_candidate_spawns(
                    route_idx,
                    candidates,
                    &routes,
                    ai_publish.as_ref(),
                    site_has_waiting_handler,
                );
            Some((route_idx, spawns))
        })
        .collect();
    for (route_idx, spawns) in try_files_fallback_spawns {
        if let Some(route) = routes.get_mut(route_idx)
            && let CompiledHandler::TryFiles {
                fallback_spawns, ..
            } = &mut route.handler
        {
            *fallback_spawns = spawns;
        }
    }

    let has_route_headers = routes.iter().any(|r| !r.headers.is_empty());
    let runs_script = RunsScript(Arc::new(
        routes
            .iter()
            .map(|route: &CompiledRoute| {
                let fastcgi = matches!(route.handler, CompiledHandler::FastCgi { .. });
                (route.matcher.clone(), fastcgi)
            })
            .collect(),
    ));
    if site_cache.is_some() {
        for (idx, route) in routes.iter_mut().enumerate() {
            if let CompiledHandler::TryFiles { static_server, .. } = &mut route.handler
                && static_server.has_file_cache()
            {
                let owned = std::mem::replace(
                    static_server,
                    // Temporarily clone while rebinding the compile-time ScriptOwner.
                    static_server.clone(),
                );
                *static_server = owned.with_try_files_script_owner(runs_script.asked_by(Some(idx)));
            }
        }
    }

    let site_rewrites = crate::rewrite::CompiledRewrites::compile(&site.rewrites)?;
    let site_headers = compile_header_rules(&site.headers)?;
    let site_access = compile_access(&site.access)?;

    let site_may_add_cache_control = !site.access.is_empty()
        || site.basic_auth.is_some()
        || site_rewrites.uses_client_ip()
        || site_rewrites.uses_request_headers()
        || client_cert_trust.is_some();
    let site_only_rule_keys = distinct_header_rule_keys(&site_headers, &[]);
    let default_static_extra_headers = extra_static_response_header_budget_with_rules(
        site.security_headers,
        site_only_rule_keys,
        site_may_add_cache_control,
    );
    if let Some(srv) = default_static.as_mut() {
        srv.set_extra_response_headers(default_static_extra_headers);
    }
    // Compute the site-wide maximum rule-key contribution ONCE (O(routes) instead of recomputing
    // across all routes inside every `try-files` route) and combine with each route's policy.
    let max_try_files_rule_keys = if routes
        .iter()
        .any(|r| matches!(r.handler, CompiledHandler::TryFiles { .. }))
    {
        routes
            .iter()
            .map(|r| distinct_header_rule_keys(&site_headers, &r.headers))
            .max()
            .unwrap_or(site_only_rule_keys)
    } else {
        0
    };
    for route in &mut routes {
        let effective_policy = route.security_headers.unwrap_or(site.security_headers);
        match &mut route.handler {
            CompiledHandler::Static { static_server, .. } => {
                let rule_keys = distinct_header_rule_keys(&site_headers, &route.headers);
                let budget = extra_static_response_header_budget_with_rules(
                    effective_policy,
                    rule_keys,
                    site_may_add_cache_control,
                );
                static_server.set_extra_response_headers(budget);
            }
            CompiledHandler::TryFiles { static_server, .. } => {
                let budget = extra_static_response_header_budget_with_rules(
                    effective_policy,
                    max_try_files_rule_keys,
                    site_may_add_cache_control,
                );
                static_server.set_extra_response_headers(budget);
            }
            _ => {}
        }
    }

    Ok(CompiledSite {
        hosts: site
            .hosts
            .iter()
            .map(|h| normalize_site_host(h).into_owned())
            .collect(),
        allows_tls_1_2,
        security_headers: site.security_headers,
        http_mode: site.http,
        http_credentials: site.http_credentials,
        precompressed: site.precompressed,
        preset_guard,
        preset: site.preset,
        bot_auth,
        rate_limit,
        default_static,
        default_static_extra_headers,
        default_static_unavailable,
        ai_publish,
        client_cert_trust,
        runs_script,
        fastcgi_extensions,
        routed_fastcgi_extensions,
        default_static_has_script_index,
        error_pages,
        rewrites: site_rewrites,
        headers: site_headers,
        access: site_access,
        // The area keeps its state across reloads (keyed by its users file: host-name edits keep
        // the throttle and the bcrypt slots, which the router generations of a reload share).
        basic_auth: site
            .basic_auth
            .as_ref()
            .map(|auth| crate::basic_auth::CompiledBasicAuth::load(auth, areas)),
        unavailable,
        secret_files: Arc::clone(secret_files),
        has_route_headers,
        #[cfg(test)]
        fallback_header_lookups: std::sync::atomic::AtomicUsize::new(0),
        has_file_cache: site_cache.is_some(),
        file_cache: site_cache.map(|(cache, _)| cache),
        routes,
    })
}

fn load_site_error_pages(
    site: &SiteConfig,
    default_static: Option<&StaticServer>,
    credential_files: &[std::path::PathBuf],
    secret_files: &[(u64, u64)],
    split_keys: Option<&SplitSigningKeys<'_>>,
) -> SiteErrorPages {
    let mut compiled = SiteErrorPages::default();
    let Some(cfg) = &site.error_pages else {
        return compiled;
    };
    compiled.login_url = cfg.login_url.as_ref().map(|u| u.trim().to_owned());

    for (&status, raw_path) in &cfg.pages {
        let p = Path::new(raw_path);
        // An absolute page inside the site root is read through the confined reader, like a
        // relative one. Anywhere else EVERY path component from root down to the leaf must not
        // be a symlink (HANDOVER §5 #10): an intermediate directory may sit inside a tenant-owned
        // tree, and symlinking that directory to another account's directory would otherwise serve
        // another tenant's files as the error body.
        let inside_root = site
            .root
            .as_deref()
            .and_then(|root| p.strip_prefix(root).ok())
            .and_then(Path::to_str)
            .filter(|rel| !rel.is_empty());
        let loaded: Result<Vec<u8>, String> = if let (true, Some(rel), Some(static_srv)) =
            (p.is_absolute(), inside_root, default_static)
        {
            static_srv
                .read_confined_file(&format!("/{rel}"), MAX_CUSTOM_ERROR_PAGE_BYTES)
                .map_err(|err| {
                    format!(
                        "failed to load confined error page '{raw_path}' for status {status}: {err}"
                    )
                })
        } else if p.is_absolute()
            && credential_files
                .iter()
                .any(|users| p == users.as_path() || p.parent() == users.parent())
        {
            // A password database (or its directory) is never an error page: this site uses
            // the built-in page for this status; nothing else is affected.
            Err(format!(
                "error page '{raw_path}' for status {status} is a basic-auth users file or in its directory"
            ))
        } else if p.is_absolute() {
            // On an `owner-dir` site the page must belong to that account: its directory must
            // really be inside owner-dir (the page itself is read without following links).
            let outside_owner = site.owner_dir.as_ref().is_some_and(|owner| {
                let owner_real = std::fs::canonicalize(owner).ok();
                let page_dir = p.parent().and_then(|d| std::fs::canonicalize(d).ok());
                !matches!((owner_real, page_dir), (Some(o), Some(d)) if d.starts_with(&o))
            });
            if split_keys.is_some_and(|sk| sk.has_unidentifiable) {
                Err(format!(
                    "error page '{raw_path}' for status {status} outside site root is refused in split-daemon mode while a configured signing key cannot be identified"
                ))
            } else if split_keys.is_some_and(|sk| sk.matches(p)) {
                Err(format!(
                    "error page '{raw_path}' for status {status} matches a split-daemon signing key"
                ))
            } else if outside_owner {
                Err(format!(
                    "error page '{raw_path}' for status {status} is outside the site's owner-dir"
                ))
            } else {
                // A credential file under another name is refused by identity.
                miraserve_static::read_no_symlink_file_excluding(
                    p,
                    MAX_CUSTOM_ERROR_PAGE_BYTES,
                    secret_files,
                )
            }
        } else if let Some(static_srv) = default_static {
            static_srv
                .read_confined_file(raw_path, MAX_CUSTOM_ERROR_PAGE_BYTES)
                .map_err(|err| {
                    format!(
                        "failed to load confined error page '{raw_path}' for status {status}: {err}"
                    )
                })
        } else {
            Err(format!(
                "relative error page '{raw_path}' for status {status} requires an available site root"
            ))
        };
        // The page file belongs to the site owner, who can delete it, empty it or replace any
        // component with a symlink at any time. That must never stop the server or a reload for
        // every other site: use the built-in page for this status and say so.
        let bytes = match loaded {
            Ok(bytes) => bytes,
            Err(err) => {
                warn!(
                    site = site.hosts.first().map_or("", String::as_str),
                    status,
                    page = %raw_path,
                    error = %err,
                    "custom error page could not be loaded; using the built-in page for this status"
                );
                continue;
            }
        };
        compiled.pages.insert(
            status,
            CustomErrorPage {
                body: Bytes::from(bytes),
                content_type: custom_page_content_type(raw_path),
            },
        );
    }
    compiled
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
async fn serve_canonical_or_script_index_cached_step(
    static_srv: &StaticServer,
    req: &mut Request<PipeReqBody>,
    canonical_path: &str,
    query: Option<&str>,
    routed_fastcgi_extensions: &[String],
    path_is_forbidden_script: bool,
) -> miraserve_static::ScriptOrStaticOutcome {
    #[cfg(test)]
    ROUTER_CACHE_LOOKUP_OR_ADMIT_CALLS.fetch_add(1, Ordering::Relaxed);
    let whole;
    let headers =
        if *req.method() == Method::HEAD && req.headers().contains_key(http::header::RANGE) {
            let mut without_range = req.headers().clone();
            without_range.remove(http::header::RANGE);
            without_range.remove(http::header::IF_RANGE);
            whole = without_range;
            &whole
        } else {
            req.headers()
        };
    let bypass_cache = req.extensions().get::<RequestCacheBypass>().is_some()
        || req.headers().contains_key(http::header::RANGE)
        || req.headers().contains_key(http::header::IF_RANGE);
    let no_admit = req.extensions().get::<RequestCacheNoAdmit>().is_some();
    let carried = req.extensions().get::<CarriedFillStart>().map(|c| c.0);
    let mut sampled = None;
    let out = static_srv
        .serve_canonical_or_script_index_cached(
            req.method(),
            canonical_path,
            query,
            headers,
            routed_fastcgi_extensions,
            path_is_forbidden_script,
            bypass_cache,
            no_admit,
            carried,
            &mut sampled,
        )
        .await;
    if matches!(
        out,
        miraserve_static::ScriptOrStaticOutcome::ScriptRewrite(_)
    ) && req.extensions().get::<RequestCacheBypass>().is_none()
        && req.extensions().get::<RequestCacheNoAdmit>().is_none()
    {
        if let Some(fs) = sampled {
            req.extensions_mut().insert(CarriedFillStart(fs));
        } else if req.extensions().get::<CarriedFillStart>().is_none() {
            req.extensions_mut().insert(RequestCacheBypass);
        }
    }
    out
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn serve_static_or_script_index<const CACHE_ATTACHED: bool>(
    site: &CompiledSite,
    origin: Option<&CompiledRoute>,
    static_srv: &StaticServer,
    mut req: Request<PipeReqBody>,
    canonical_path: &str,
    query: Option<&str>,
    server_name: &str,
    ctx: &RequestContext,
    effective_client_ip: Option<IpAddr>,
    is_trusted_peer: bool,
    verified_agent_id: Option<&str>,
    max_body_bytes: u64,
    want_markdown: bool,
    agent_selected_markdown: bool,
    telemetry: &TelemetryRegistry,
    err_meta: &ErrorMeta<'_>,
) -> (Response<PipeRespBody>, Option<SecurityHeadersPolicy>) {
    #[cfg(target_os = "linux")]
    if !want_markdown
        && matches!(*req.method(), Method::GET | Method::HEAD)
        && !site.routed_fastcgi_extensions.is_empty()
    {
        let path_is_forbidden_script =
            is_forbidden_static_extension(canonical_path, &site.fastcgi_extensions);
        let outcome = if CACHE_ATTACHED {
            Box::pin(serve_canonical_or_script_index_cached_step(
                static_srv,
                &mut req,
                canonical_path,
                query,
                &site.routed_fastcgi_extensions,
                path_is_forbidden_script,
            ))
            .await
        } else {
            // A range is for GET: HEAD answers for the whole file (RFC 9110 section 14.2).
            let whole;
            let headers = if *req.method() == Method::HEAD
                && req.headers().contains_key(http::header::RANGE)
            {
                let mut without_range = req.headers().clone();
                without_range.remove(http::header::RANGE);
                without_range.remove(http::header::IF_RANGE);
                whole = without_range;
                &whole
            } else {
                req.headers()
            };
            Box::pin(static_srv.serve_canonical_or_script_index_no_cache(
                req.method(),
                canonical_path,
                query,
                headers,
                &site.routed_fastcgi_extensions,
                path_is_forbidden_script,
            ))
            .await
        };
        match outcome {
            miraserve_static::ScriptOrStaticOutcome::Static(raw_resp) => {
                return (
                    finish_static_as_is(
                        *raw_resp,
                        canonical_path,
                        true,
                        err_meta,
                        &site.error_pages,
                    ),
                    None,
                );
            }
            miraserve_static::ScriptOrStaticOutcome::ScriptRedirect(resp) => {
                let mapped = (*resp).map(map_static_body);
                return (
                    err_meta.upgrade_generated_error(mapped, Some(&site.error_pages)),
                    None,
                );
            }
            miraserve_static::ScriptOrStaticOutcome::ScriptRewrite(target) => {
                return Box::pin(dispatch_internal_rewrite::<CACHE_ATTACHED>(
                    site,
                    origin,
                    (want_markdown, agent_selected_markdown),
                    static_srv,
                    req,
                    &target,
                    query,
                    server_name,
                    ctx,
                    effective_client_ip,
                    is_trusted_peer,
                    verified_agent_id,
                    max_body_bytes,
                    telemetry,
                    err_meta,
                ))
                .await;
            }
        }
    }

    // Markdown (deferred), non-Linux, and non-GET/HEAD requests keep the two-step script-index
    // path; Markdown never carries a static descriptor across sibling policy checks.
    let mut lookup = None;
    if !site.routed_fastcgi_extensions.is_empty() {
        // Opt-in file-cache fast path ahead of the FastCGI script directory-index disk probe:
        // compiled out entirely when `CACHE_ATTACHED` is false. Hits remain unaffected by
        // `RequestCacheNoAdmit`.
        if CACHE_ATTACHED {
            #[cfg(test)]
            ROUTER_CACHE_LOOKUP_OR_ADMIT_CALLS.fetch_add(1, Ordering::Relaxed);
            if !want_markdown
                && req.extensions().get::<RequestCacheBypass>().is_none()
                && let Some(cached) =
                    static_srv.try_serve_cached(req.method(), canonical_path, req.headers())
            {
                return (
                    finish_static_as_is(cached, canonical_path, true, err_meta, &site.error_pages),
                    None,
                );
            }
        }
        let outcome = if want_markdown {
            Box::pin(static_srv.resolve_script_directory_index(
                req.method(),
                canonical_path,
                query,
                &site.routed_fastcgi_extensions,
            ))
            .await
        } else if CACHE_ATTACHED {
            Box::pin(static_srv.resolve_script_directory_index_keeping(
                req.method(),
                canonical_path,
                query,
                &site.routed_fastcgi_extensions,
                &mut lookup,
            ))
            .await
        } else {
            Box::pin(static_srv.resolve_script_directory_index_keeping_no_cache(
                req.method(),
                canonical_path,
                query,
                &site.routed_fastcgi_extensions,
                &mut lookup,
            ))
            .await
        };
        if let Some(outcome) = outcome {
            match outcome {
                TryFilesOutcome::Response(resp)
                | TryFilesOutcome::FallbackResponse { response: resp, .. } => {
                    let mapped = (*resp).map(map_static_body);
                    return (
                        err_meta.upgrade_generated_error(mapped, Some(&site.error_pages)),
                        None,
                    );
                }
                TryFilesOutcome::InternalRewrite(target) => {
                    if CACHE_ATTACHED
                        && req.extensions().get::<RequestCacheBypass>().is_none()
                        && req.extensions().get::<RequestCacheNoAdmit>().is_none()
                        && req.extensions().get::<CarriedFillStart>().is_none()
                    {
                        if let Some(fs) = lookup
                            .as_ref()
                            .and_then(miraserve_static::Lookup::fill_start)
                        {
                            req.extensions_mut().insert(CarriedFillStart(fs));
                        } else {
                            req.extensions_mut().insert(RequestCacheBypass);
                        }
                    }
                    return Box::pin(dispatch_internal_rewrite::<CACHE_ATTACHED>(
                        site,
                        origin,
                        (want_markdown, agent_selected_markdown),
                        static_srv,
                        req,
                        &target,
                        query,
                        server_name,
                        ctx,
                        effective_client_ip,
                        is_trusted_peer,
                        verified_agent_id,
                        max_body_bytes,
                        telemetry,
                        err_meta,
                    ))
                    .await;
                }
            }
        }
    }

    let static_lookup = if site.routed_fastcgi_extensions.is_empty() {
        StaticLookup::direct()
    } else {
        StaticLookup::after_script_probe(lookup)
    };
    (
        serve_static_with_markdown::<CACHE_ATTACHED>(
            static_srv,
            &SiblingPolicy {
                site,
                owner: origin,
                host: server_name,
                effective_client_ip,
            },
            &req,
            canonical_path,
            want_markdown,
            agent_selected_markdown,
            true,
            &site.fastcgi_extensions,
            err_meta,
            &site.error_pages,
            static_lookup,
        )
        .await,
        None,
    )
}

/// Unified FastCGI target ownership, rate-limit, security-header, and execution helper shared
/// between direct FastCGI route dispatch and internal rewrites (directory indexes / `try-files`).
///
/// Enforces two G4 invariants uniformly:
/// 1. Exact routes preserve exact URL matching (only general routes such as `*.php` match
///    `PATH_INFO` suffixes), so anchored PHP allowlists are never widened.
/// 2. Whenever a matched FastCGI route resolves a `script_path` (either directly or via
///    `PATH_INFO`), the first route owning `script_path` governs rate limits, security headers,
///    and whether FastCGI execution is permitted at all.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn dispatch_fastcgi_route(
    site: &CompiledSite,
    route: &CompiledRoute,
    client: &FastCgiClient,
    script_root: Option<&StaticServer>,
    route_rate_limit_checked: bool,
    req: Request<PipeReqBody>,
    canonical_path: &str,
    query: &str,
    server_name: &str,
    ctx: &RequestContext,
    effective_client_ip: Option<IpAddr>,
    is_trusted_peer: bool,
    verified_agent_id: Option<&str>,
    max_body_bytes: u64,
    telemetry: &TelemetryRegistry,
    err_meta: &ErrorMeta<'_>,
) -> (Response<PipeRespBody>, Option<SecurityHeadersPolicy>) {
    let Some((script_path, path_info)) = route.split_fastcgi_script_and_path_info(canonical_path)
    else {
        return (
            err_meta.render_error(StatusCode::NOT_FOUND, None, Some(&site.error_pages)),
            route.security_headers,
        );
    };

    let mut effective_client = client;
    let mut effective_root = script_root;
    let mut override_sec = route.security_headers;

    // A rewrite `deny` aimed at the script applies when it is reached with PATH_INFO too,
    // evaluated with the same file view as a direct request (the site's root).
    if !path_info.is_empty()
        && site.rewrites.may_refuse()
        && let Some(status) = site
            .rewrites
            .denied_status(
                script_path,
                Some(query),
                server_name,
                req.method(),
                req.headers(),
                policy_ip_of(&req),
                site.default_static.as_ref(),
            )
            .await
    {
        return (
            err_meta.render_error(status, None, Some(&site.error_pages)),
            route.security_headers,
        );
    }

    // Codex Round-3 P2 #1 (G4): Enforce the matched FastCGI route's rate limit independently
    // BEFORE checking any earlier `script_owner` for `PATH_INFO`, so internal rewrites (where
    // `route_rate_limit_checked == false`) match direct requests identically and never skip the
    // wildcard route's rate limit when `script_owner` is a distinct route.
    if !route_rate_limit_checked && let Some(rl) = &route.rate_limit {
        let decision = rl.check_request(effective_client_ip, req.headers(), verified_agent_id);
        if !decision.allowed {
            telemetry.record_security_block(SecurityBlockReason::RateLimit);
            return (
                err_meta.rate_limit_error(
                    decision.retry_after_secs,
                    decision.limit,
                    decision.remaining,
                    Some(&site.error_pages),
                ),
                override_sec,
            );
        }
    }

    let mut header_owner = route;
    // When `PATH_INFO` is non-empty, check whether an earlier route owns `script_path` directly.
    if !path_info.is_empty()
        && let Some(script_owner) = site.routes.iter().find(|r| r.matcher.matches(script_path))
        && !std::ptr::eq(script_owner, route)
    {
        // The owner's effective policy (its own, or the site's it inherits): never "none",
        // which would let the enclosing route substitute its own.
        override_sec = Some(effective_security(script_owner, site));
        // The route that owns the script governs the answer, its header rules included.
        header_owner = script_owner;
        if let Some(rl) = &script_owner.rate_limit {
            let decision = rl.check_request(effective_client_ip, req.headers(), verified_agent_id);
            if !decision.allowed {
                telemetry.record_security_block(SecurityBlockReason::RateLimit);
                return (
                    with_route_headers(
                        err_meta.rate_limit_error(
                            decision.retry_after_secs,
                            decision.limit,
                            decision.remaining,
                            Some(&site.error_pages),
                        ),
                        header_owner,
                    ),
                    override_sec,
                );
            }
        }
        if let CompiledHandler::FastCgi {
            client: owner_client,
            script_root: owner_root,
        } = &script_owner.handler
        {
            effective_client = owner_client;
            effective_root = owner_root.as_ref();
        } else {
            return (
                with_route_headers(
                    err_meta.render_error(StatusCode::NOT_FOUND, None, Some(&site.error_pages)),
                    header_owner,
                ),
                override_sec,
            );
        }
    }

    // PATH-6: Verify the resolved script file exists inside the confined cap-std root BEFORE
    // invoking PHP-FPM (blocks `/uploads/a.jpg/x.php` and missing scripts while permitting valid
    // `/script.php/extra` PATH_INFO requests).
    if let Some(root_srv) = effective_root
        && !root_srv.exists_regular_file_async(script_path).await
    {
        return (
            with_route_headers(
                err_meta.render_error(StatusCode::NOT_FOUND, None, Some(&site.error_pages)),
                header_owner,
            ),
            override_sec,
        );
    }

    let resp = execute_fastcgi(
        effective_client,
        req,
        script_path,
        path_info,
        query,
        server_name,
        ctx,
        effective_client_ip,
        is_trusted_peer,
        max_body_bytes,
        err_meta,
        &site.error_pages,
    )
    .await;
    (with_route_headers(resp, header_owner), override_sec)
}

/// How many internal rewrites a request has gone through (a rewrite to a route that itself
/// rewrites again).
#[derive(Debug, Clone, Copy)]
struct RewriteDepth(u8);

/// The request as the destination of an internal rewrite sees it: the rewritten target as its
/// URI (a proxy forwards it), the visitor's original target kept for FastCGI `REQUEST_URI`,
/// and one more rewrite level counted.
fn retarget<B>(
    mut req: Request<B>,
    target_path: &str,
    target_query: &str,
    depth: u8,
) -> Option<Request<B>> {
    // The decoded path is percent-encoded again; the query keeps its encoding (only bytes a
    // URI cannot carry are encoded). Scheme and authority (`:authority` on HTTP/2) stay.
    let mut path_and_query = percent_encode_target(target_path, false);
    if !target_query.is_empty() {
        path_and_query.push('?');
        path_and_query.push_str(&percent_encode_target(target_query, true));
    }
    let pq = http::uri::PathAndQuery::from_maybe_shared(path_and_query).ok()?;
    let mut parts = req.uri().clone().into_parts();
    parts.path_and_query = Some(pq);
    let uri = http::Uri::from_parts(parts).ok()?;
    if req.extensions().get::<OriginalRequestTarget>().is_none() {
        let original = req
            .uri()
            .path_and_query()
            .map_or_else(|| "/".to_owned(), |pq| pq.as_str().to_owned());
        req.extensions_mut().insert(OriginalRequestTarget(original));
    }
    req.extensions_mut().insert(RewriteDepth(depth + 1));
    *req.uri_mut() = uri;
    Some(req)
}

/// What follows the part of `raw` (a request path as sent) that percent-decodes to `prefix`,
/// after the separator there (`/` or `%2F`) and any further `/`; `None` when `raw` does not
/// start with an encoding of `prefix` followed by a separator or its end.
fn raw_rest_after_prefix<'a>(raw: &'a str, prefix: &str) -> Option<&'a str> {
    let raw_bytes = raw.as_bytes();
    let mut at = 0;
    for &want in prefix.as_bytes() {
        let (got, used) = match raw_bytes.get(at..at + 3) {
            Some([b'%', hi, lo]) => {
                let hex = |c: u8| char::from(c).to_digit(16);
                match (hex(*hi), hex(*lo)) {
                    (Some(h), Some(l)) => (u8::try_from(h * 16 + l).ok()?, 3),
                    _ => (b'%', 1),
                }
            }
            _ => (*raw_bytes.get(at)?, 1),
        };
        if got != want {
            return None;
        }
        at += used;
        // Route matching decodes `%2F` and then collapses repeated slashes: so does this walk.
        if want == b'/' {
            loop {
                if raw_bytes.get(at) == Some(&b'/') {
                    at += 1;
                } else if raw
                    .get(at..at + 3)
                    .is_some_and(|sep| sep.eq_ignore_ascii_case("%2f"))
                {
                    at += 3;
                } else {
                    break;
                }
            }
        }
    }
    let rest = raw.get(at..)?;
    if rest.is_empty() {
        return Some("");
    }
    // At least one separator (`/` or `%2F`), then every further one, as routing collapses them.
    let mut after = rest.strip_prefix('/').or_else(|| {
        rest.get(..3)
            .filter(|sep| sep.eq_ignore_ascii_case("%2f"))
            .and_then(|_| rest.get(3..))
    })?;
    loop {
        if let Some(next) = after.strip_prefix('/') {
            after = next;
        } else if let Some(next) = after
            .get(..3)
            .filter(|sep| sep.eq_ignore_ascii_case("%2f"))
            .and_then(|_| after.get(3..))
        {
            after = next;
        } else {
            break;
        }
    }
    Some(after)
}

/// Percent-encodes every byte a request target cannot carry as is. In a path (`query` false)
/// `%` is encoded too (the path is decoded); in a query existing `%XX` escapes are kept.
fn percent_encode_target(text: &str, query: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for &b in text.as_bytes() {
        let plain = b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
                    | b'/'
            )
            || (query && matches!(b, b'?' | b'%'));
        if plain {
            out.push(char::from(b));
        } else {
            use std::fmt::Write as _;
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Marks `resp` as answered by no route (the site's own default handling): enclosing routes
/// add no header rules of their own. Uses `None` rather than allocating an empty `Arc`.
fn without_route_headers<B>(mut resp: Response<B>) -> Response<B> {
    if resp.extensions().get::<RouteHeaderRules>().is_none() {
        resp.extensions_mut().insert(RouteHeaderRules(None));
    }
    resp
}

/// Marks an answer produced by a WebAssembly route reached through an internal rewrite: its
/// security headers are enforced as for a direct WebAssembly route.
#[derive(Debug, Clone, Copy)]
struct WasmResponse;

/// Most nested internal rewrites per request.
const MAX_INTERNAL_REWRITES: u8 = 4;

/// The security-header policy that applies to answers of `route`: its own, or the site's.
fn effective_security(route: &CompiledRoute, site: &CompiledSite) -> SecurityHeadersPolicy {
    route.security_headers.unwrap_or(site.security_headers)
}

/// Whether `body` is an RFC 8555 HTTP-01 key authorization for `token`: the token, a dot, and
/// the 43-character base64url SHA-256 thumbprint of the account key.
fn is_key_authorization(body: &[u8], token: &str) -> bool {
    body.strip_prefix(token.as_bytes())
        .and_then(|rest| rest.strip_prefix(b"."))
        .is_some_and(|thumbprint| {
            thumbprint.len() == 43
                && thumbprint
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
        })
}

/// Records `route` as the route whose header rules apply to `resp` (also when it has none, so an
/// enclosing route never adds its own), unless a more specific route already did.
fn with_route_headers<B>(mut resp: Response<B>, route: &CompiledRoute) -> Response<B> {
    if resp.extensions().get::<RouteHeaderRules>().is_none() {
        let rules = (!route.headers.is_empty()).then(|| Arc::clone(&route.headers));
        resp.extensions_mut().insert(RouteHeaderRules(rules));
    }
    resp
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn dispatch_internal_rewrite<const CACHE_ATTACHED: bool>(
    site: &CompiledSite,
    origin: Option<&CompiledRoute>,
    markdown: (bool, bool),
    static_server: &StaticServer,
    req: Request<PipeReqBody>,
    target: &str,
    fallback_query: Option<&str>,
    server_name: &str,
    ctx: &RequestContext,
    effective_client_ip: Option<IpAddr>,
    is_trusted_peer: bool,
    verified_agent_id: Option<&str>,
    max_body_bytes: u64,
    telemetry: &TelemetryRegistry,
    err_meta: &ErrorMeta<'_>,
) -> (Response<PipeRespBody>, Option<SecurityHeadersPolicy>) {
    // The first `?` separates path and query (the path part escapes its own `?`, `#`, `%`).
    let (encoded_path, target_query) = match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target, fallback_query.unwrap_or("")),
    };
    let decoded_path = miraserve_static::decode_rewrite_path(encoded_path);
    let target_path = decoded_path.as_str();
    // The site's rewrite `deny` rules protect a path under every name, including the name the
    // server itself selects: a directory index (`/dir/` -> `/dir/index.php`) or a `try-files`
    // fallback. A direct request for the selected path would be refused, so this one is too,
    // before any backend is contacted. Only `deny` is applied; the target is not transformed.
    if !site.rewrites.is_empty()
        && let Some(status) = site
            .rewrites
            .denied_status(
                target_path,
                Some(target_query),
                server_name,
                req.method(),
                req.headers(),
                policy_ip_of(&req),
                site.default_static.as_ref(),
            )
            .await
    {
        return (
            err_meta.render_error(status, None, Some(&site.error_pages)),
            None,
        );
    }
    // Re-evaluate site preset on rewritten target path.
    if let Some(preset_guard) = &site.preset_guard {
        match preset_guard.evaluate(
            req.method(),
            target_path,
            req.headers(),
            effective_client_ip,
        ) {
            PresetVerdict::Allow => {}
            PresetVerdict::Block { status, .. } => {
                telemetry.record_security_block(SecurityBlockReason::SitePreset);
                return (
                    err_meta.render_error(status, None, Some(&site.error_pages)),
                    None,
                );
            }
            PresetVerdict::RateLimited {
                retry_after_secs, ..
            } => {
                telemetry.record_security_block(SecurityBlockReason::RateLimit);
                return (
                    err_meta.rate_limit_error(retry_after_secs, 10, 0, Some(&site.error_pages)),
                    None,
                );
            }
        }
    }
    // Codex G4 (internal rewrites): Match against ALL routes in order (NEVER filtering only to
    // FastCGI routes!) so an earlier exact static, redirect, or denying route protecting a script
    // (e.g. `/admin/index.php`) is enforced identically for direct URLs, directory indexes, and
    // `try-files` rewrites!
    if let Some(owner_route) = site.routes.iter().find(|r| r.matches_path(target_path)) {
        match &owner_route.handler {
            CompiledHandler::FastCgi {
                client,
                script_root,
            } => {
                let (resp, sec) = dispatch_fastcgi_route(
                    site,
                    owner_route,
                    client,
                    script_root.as_ref(),
                    false,
                    req,
                    target_path,
                    target_query,
                    server_name,
                    ctx,
                    effective_client_ip,
                    is_trusted_peer,
                    verified_agent_id,
                    max_body_bytes,
                    telemetry,
                    err_meta,
                )
                .await;
                // The script's own route header rules apply, not those of the route that
                // rewrote to it (or those of the route owning the script itself, if attached).
                return (
                    with_route_headers(resp, owner_route),
                    sec.or(Some(effective_security(owner_route, site))),
                );
            }
            // The route that owns the selected path decides, as for a direct request: a redirect
            // route redirects whatever the target's extension.
            CompiledHandler::Redirect {
                status,
                target,
                route_prefix,
            } => {
                if let Some(rl) = &owner_route.rate_limit {
                    let decision =
                        rl.check_request(effective_client_ip, req.headers(), verified_agent_id);
                    if !decision.allowed {
                        telemetry.record_security_block(SecurityBlockReason::RateLimit);
                        return (
                            with_route_headers(
                                err_meta.rate_limit_error(
                                    decision.retry_after_secs,
                                    decision.limit,
                                    decision.remaining,
                                    Some(&site.error_pages),
                                ),
                                owner_route,
                            ),
                            Some(effective_security(owner_route, site)),
                        );
                    }
                }
                let loc = expand_redirect_target(
                    target,
                    // Both encoded the same way, so the prefix still matches (`/café/*`).
                    &percent_encode_target(route_prefix, false),
                    &percent_encode_target(target_path, false),
                    (!target_query.is_empty()).then_some(target_query),
                );
                let resp = redirect_response(loc, *status, err_meta, &site.error_pages);
                return (
                    with_route_headers(resp, owner_route),
                    Some(effective_security(owner_route, site)),
                );
            }
            // A static route never serves a script's source.
            CompiledHandler::Static { .. }
                if is_forbidden_static_extension(target_path, &site.fastcgi_extensions) =>
            {
                if let Some(rl) = &owner_route.rate_limit {
                    let decision =
                        rl.check_request(effective_client_ip, req.headers(), verified_agent_id);
                    if !decision.allowed {
                        telemetry.record_security_block(SecurityBlockReason::RateLimit);
                        return (
                            with_route_headers(
                                err_meta.rate_limit_error(
                                    decision.retry_after_secs,
                                    decision.limit,
                                    decision.remaining,
                                    Some(&site.error_pages),
                                ),
                                owner_route,
                            ),
                            Some(effective_security(owner_route, site)),
                        );
                    }
                }
                return (
                    with_route_headers(
                        err_meta.render_error(StatusCode::NOT_FOUND, None, Some(&site.error_pages)),
                        owner_route,
                    ),
                    Some(effective_security(owner_route, site)),
                );
            }
            // The originating route itself (its own `try-files` fallback, or its static root):
            // served below, terminally, as before.
            _ if origin.is_some_and(|origin| std::ptr::eq(owner_route, origin)) => {}
            CompiledHandler::Static {
                static_server: owner_static,
                ..
            } if std::ptr::eq(owner_static, static_server) => {}
            // Any other route that owns the selected path answers as it does for a direct
            // request (its own handler, rate limit, header rules and security headers). Internal
            // rewrites nest at most a few levels.
            _ => {
                if let Some(rl) = &owner_route.rate_limit {
                    let decision =
                        rl.check_request(effective_client_ip, req.headers(), verified_agent_id);
                    if !decision.allowed {
                        telemetry.record_security_block(SecurityBlockReason::RateLimit);
                        return (
                            with_route_headers(
                                err_meta.rate_limit_error(
                                    decision.retry_after_secs,
                                    decision.limit,
                                    decision.remaining,
                                    Some(&site.error_pages),
                                ),
                                owner_route,
                            ),
                            Some(effective_security(owner_route, site)),
                        );
                    }
                }
                let depth = req.extensions().get::<RewriteDepth>().map_or(0, |d| d.0);
                if depth >= MAX_INTERNAL_REWRITES {
                    return (
                        err_meta.render_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            None,
                            Some(&site.error_pages),
                        ),
                        None,
                    );
                }
                let Some(req) = retarget(req, target_path, target_query, depth) else {
                    return (
                        err_meta.render_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            None,
                            Some(&site.error_pages),
                        ),
                        None,
                    );
                };
                let is_wasm = matches!(owner_route.handler, CompiledHandler::WasmPlugin(_));
                let mut req_slot = Some(req);
                let (resp, sec) = Box::pin(execute_route::<CACHE_ATTACHED>(
                    site,
                    owner_route,
                    &mut req_slot,
                    target_path,
                    (!target_query.is_empty()).then_some(target_query),
                    server_name,
                    ctx,
                    None,
                    effective_client_ip,
                    is_trusted_peer,
                    verified_agent_id,
                    max_body_bytes,
                    markdown.0,
                    markdown.1,
                    telemetry,
                    err_meta,
                ))
                .await;
                let mut resp = with_route_headers(resp, owner_route);
                if is_wasm {
                    // A WebAssembly destination's security headers are always enforced.
                    resp.extensions_mut().insert(WasmResponse);
                }
                let sec_override = match sec {
                    SecurityStep::Override(policy) => Some(policy),
                    SecurityStep::Default | SecurityStep::AlreadyApplied => {
                        Some(effective_security(owner_route, site))
                    }
                };
                return (resp, sec_override);
            }
        }
    }
    // No route owns the selected path: it is answered as a direct request for it would be (the
    // site's default root, or 503 / 404 without one), with the site's own header policy, never
    // from the root of the route that rewrote.
    if origin.is_some() && !site.routes.iter().any(|r| r.matches_path(target_path)) {
        let Some(default_srv) = site.default_static.as_ref() else {
            let status = if site.ai_publish.is_some() || site.default_static_unavailable {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::NOT_FOUND
            };
            let retry =
                (status == StatusCode::SERVICE_UNAVAILABLE).then_some(DEFAULT_RETRY_AFTER_SECS);
            return (
                without_route_headers(err_meta.render_error(
                    status,
                    retry,
                    Some(&site.error_pages),
                )),
                Some(site.security_headers),
            );
        };
        let depth = req.extensions().get::<RewriteDepth>().map_or(0, |d| d.0);
        let retargeted = if depth >= MAX_INTERNAL_REWRITES {
            None
        } else {
            retarget(req, target_path, target_query, depth)
        };
        let Some(req) = retargeted else {
            return (
                err_meta.render_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    None,
                    Some(&site.error_pages),
                ),
                None,
            );
        };
        let (resp, sec) = Box::pin(serve_static_or_script_index::<CACHE_ATTACHED>(
            site,
            None,
            default_srv,
            req,
            target_path,
            (!target_query.is_empty()).then_some(target_query),
            server_name,
            ctx,
            effective_client_ip,
            is_trusted_peer,
            verified_agent_id,
            max_body_bytes,
            markdown.0,
            markdown.1,
            telemetry,
            err_meta,
        ))
        .await;
        return (
            without_route_headers(resp),
            sec.or(Some(site.security_headers)),
        );
    }
    if is_forbidden_static_extension(target_path, &site.fastcgi_extensions) {
        return (
            err_meta.render_error(StatusCode::NOT_FOUND, None, Some(&site.error_pages)),
            None,
        );
    }
    let raw = if CACHE_ATTACHED {
        Box::pin(serve_terminal_rewrite_cached(
            static_server,
            &req,
            target_path,
            target_query,
        ))
        .await
    } else {
        static_server
            .serve_canonical_with_query_no_cache(
                req.method(),
                target_path,
                Some(target_query),
                req.headers(),
            )
            .await
    }
    .map(map_static_body);
    (
        err_meta.upgrade_generated_error(raw, Some(&site.error_pages)),
        None,
    )
}

async fn serve_terminal_rewrite_cached(
    static_server: &StaticServer,
    req: &Request<PipeReqBody>,
    target_path: &str,
    target_query: &str,
) -> Response<miraserve_static::StaticBody> {
    #[cfg(test)]
    ROUTER_CACHE_LOOKUP_OR_ADMIT_CALLS.fetch_add(1, Ordering::Relaxed);
    if req.extensions().get::<RequestCacheBypass>().is_some() {
        static_server
            .serve_canonical_with_query_uncached(
                req.method(),
                target_path,
                Some(target_query),
                req.headers(),
            )
            .await
    } else if req.extensions().get::<RequestCacheNoAdmit>().is_some() {
        static_server
            .serve_canonical_with_query_no_admit(
                req.method(),
                target_path,
                Some(target_query),
                req.headers(),
            )
            .await
    } else if let Some(&CarriedFillStart(carried)) = req.extensions().get::<CarriedFillStart>() {
        static_server
            .serve_canonical_with_query_with_start(
                req.method(),
                target_path,
                Some(target_query),
                req.headers(),
                carried,
            )
            .await
    } else {
        static_server
            .serve_canonical_with_query_uncached(
                req.method(),
                target_path,
                Some(target_query),
                req.headers(),
            )
            .await
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute_try_files_cached(
    site: &CompiledSite,
    route: &CompiledRoute,
    static_server: &StaticServer,
    req: &mut Request<PipeReqBody>,
    canonical_path: &str,
    query: Option<&str>,
    candidates: &[String],
) -> TryFilesOutcome {
    #[cfg(test)]
    ROUTER_CACHE_LOOKUP_OR_ADMIT_CALLS.fetch_add(1, Ordering::Relaxed);
    let mut sampled = None;
    let bound_owner = static_server.bound_try_files_script_owner();
    let fallback_owner;
    let runs_script = if let Some(bound) = bound_owner {
        bound
    } else {
        let asking = site.routes.iter().position(|r| std::ptr::eq(r, route));
        fallback_owner = site.runs_script.asked_by(asking);
        &fallback_owner
    };
    let outcome = if req.extensions().get::<RequestCacheBypass>().is_some() {
        static_server
            .serve_try_files_canonical_routed_uncached(
                req.method(),
                canonical_path,
                query,
                req.headers(),
                candidates,
                &site.fastcgi_extensions,
                runs_script,
            )
            .await
    } else if req.extensions().get::<RequestCacheNoAdmit>().is_some() {
        static_server
            .serve_try_files_canonical_routed_no_admit(
                req.method(),
                canonical_path,
                query,
                req.headers(),
                candidates,
                &site.fastcgi_extensions,
                runs_script,
            )
            .await
    } else {
        let carried = req.extensions().get::<CarriedFillStart>().map(|c| c.0);
        static_server
            .serve_try_files_canonical_routed_with_start(
                req.method(),
                canonical_path,
                query,
                req.headers(),
                candidates,
                &site.fastcgi_extensions,
                runs_script,
                carried,
                &mut sampled,
            )
            .await
    };
    if matches!(outcome, TryFilesOutcome::InternalRewrite(_))
        && req.extensions().get::<RequestCacheBypass>().is_none()
        && req.extensions().get::<RequestCacheNoAdmit>().is_none()
    {
        if let Some(fs) = sampled {
            req.extensions_mut().insert(CarriedFillStart(fs));
        } else if req.extensions().get::<CarriedFillStart>().is_none() {
            req.extensions_mut().insert(RequestCacheBypass);
        }
    }
    outcome
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
async fn execute_route<const CACHE_ATTACHED: bool>(
    site: &CompiledSite,
    route: &CompiledRoute,
    req_slot: &mut Option<Request<PipeReqBody>>,
    canonical_path: &str,
    query: Option<&str>,
    server_name: &str,
    ctx: &RequestContext,
    alt_svc: Option<&HeaderValue>,
    effective_client_ip: Option<IpAddr>,
    is_trusted_peer: bool,
    verified_agent_id: Option<&str>,
    max_body_bytes: u64,
    want_markdown: bool,
    agent_selected_markdown: bool,
    telemetry: &TelemetryRegistry,
    err_meta: &ErrorMeta<'_>,
) -> (Response<PipeRespBody>, SecurityStep) {
    let to_step = |override_sec: Option<SecurityHeadersPolicy>| match override_sec {
        Some(policy) => SecurityStep::Override(policy),
        None => SecurityStep::Default,
    };
    match &route.handler {
        CompiledHandler::Static {
            static_server: srv, ..
        } => {
            let Some(req) = req_slot.take() else {
                return (
                    err_meta.render_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        None,
                        Some(&site.error_pages),
                    ),
                    SecurityStep::Default,
                );
            };
            // Codex G9: Use the single unified directory-index resolver with the route's effective
            // index order (whether inherited from `site.index` or overridden explicitly on the
            // `static` route), subject to `dispatch_internal_rewrite`'s script-owner route policy.
            let (resp, override_sec) = serve_static_or_script_index::<CACHE_ATTACHED>(
                site,
                Some(route),
                srv,
                req,
                canonical_path,
                query,
                server_name,
                ctx,
                effective_client_ip,
                is_trusted_peer,
                verified_agent_id,
                max_body_bytes,
                want_markdown,
                agent_selected_markdown,
                telemetry,
                err_meta,
            )
            .await;
            (resp, to_step(override_sec))
        }
        CompiledHandler::TryFiles {
            static_server,
            candidates,
            ..
        } => {
            if is_forbidden_static_extension(canonical_path, &site.fastcgi_extensions) {
                return (
                    err_meta.render_error(StatusCode::NOT_FOUND, None, Some(&site.error_pages)),
                    SecurityStep::Default,
                );
            }
            let Some(mut req) = req_slot.take() else {
                return (
                    err_meta.render_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        None,
                        Some(&site.error_pages),
                    ),
                    SecurityStep::Default,
                );
            };
            let outcome = if CACHE_ATTACHED && route.has_file_cache {
                Box::pin(execute_try_files_cached(
                    site,
                    route,
                    static_server,
                    &mut req,
                    canonical_path,
                    query,
                    candidates,
                ))
                .await
            } else {
                // A directory's index that is a script is handed on if the route that takes that
                // very path answers for it (see `RunsScript`): a leftover `index.php` nothing
                // answers for is skipped and the next index is served.
                let asking = site.routes.iter().position(|r| std::ptr::eq(r, route));
                let runs_script = site.runs_script.asked_by(asking);
                Box::pin(static_server.serve_try_files_canonical_routed_no_cache(
                    req.method(),
                    canonical_path,
                    query,
                    req.headers(),
                    candidates,
                    &site.fastcgi_extensions,
                    &runs_script,
                ))
                .await
            };
            match outcome {
                TryFilesOutcome::Response(resp) => {
                    let mapped = (*resp).map(map_static_body);
                    (
                        err_meta.upgrade_generated_error(mapped, Some(&site.error_pages)),
                        SecurityStep::Default,
                    )
                }
                TryFilesOutcome::FallbackResponse {
                    response,
                    candidate_path,
                } => {
                    let mapped = (*response).map(map_static_body);
                    let upgraded =
                        err_meta.upgrade_generated_error(mapped, Some(&site.error_pages));
                    // Rule (b) without a second dispatch: the static handler produced the exact
                    // v0.1.3 response; select configurable `headers` rules by pure path lookup
                    // against the static-normalized fallback candidate path (no handler runs, no
                    // limiter is consulted, and `security-headers` stays unchanged as in v0.1.3).
                    // Skip the lookup completely when no route of this site defines `headers`.
                    let resp = if site.has_route_headers {
                        #[cfg(test)]
                        site.fallback_header_lookups
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        match miraserve_static::normalize_static_lookup_path(&candidate_path) {
                            // A candidate the static handler refused (`..`, NUL, backslash)
                            // selected no file: its error answer is the originating route's,
                            // with that route's rules, exactly as in v0.1.3.
                            None => upgraded,
                            Some(lookup_path) => {
                                match site.routes.iter().find(|r| r.matches_path(&lookup_path)) {
                                    Some(owner) if !owner.headers.is_empty() => {
                                        with_route_headers(upgraded, owner)
                                    }
                                    _ if !route.headers.is_empty() => {
                                        without_route_headers(upgraded)
                                    }
                                    _ => upgraded,
                                }
                            }
                        }
                    } else {
                        upgraded
                    };
                    (resp, SecurityStep::Default)
                }
                TryFilesOutcome::InternalRewrite(target) => {
                    let (resp, override_sec) =
                        Box::pin(dispatch_internal_rewrite::<CACHE_ATTACHED>(
                            site,
                            Some(route),
                            (want_markdown, agent_selected_markdown),
                            static_server,
                            req,
                            &target,
                            query,
                            server_name,
                            ctx,
                            effective_client_ip,
                            is_trusted_peer,
                            verified_agent_id,
                            max_body_bytes,
                            telemetry,
                            err_meta,
                        ))
                        .await;
                    (resp, to_step(override_sec))
                }
            }
        }
        CompiledHandler::FastCgi {
            client,
            script_root,
        } => {
            let Some(req) = req_slot.take() else {
                return (
                    err_meta.render_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        None,
                        Some(&site.error_pages),
                    ),
                    SecurityStep::Default,
                );
            };
            let (resp, override_sec) = Box::pin(dispatch_fastcgi_route(
                site,
                route,
                client,
                script_root.as_ref(),
                true,
                req,
                canonical_path,
                query.unwrap_or(""),
                server_name,
                ctx,
                effective_client_ip,
                is_trusted_peer,
                verified_agent_id,
                max_body_bytes,
                telemetry,
                err_meta,
            ))
            .await;
            (resp, to_step(override_sec))
        }
        CompiledHandler::Respond(status) => (
            err_meta.render_error(*status, None, Some(&site.error_pages)),
            SecurityStep::Default,
        ),
        CompiledHandler::ReverseProxy(proxy) => {
            let Some(req_mut) = req_slot.as_mut() else {
                return (
                    err_meta.render_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        None,
                        Some(&site.error_pages),
                    ),
                    SecurityStep::Default,
                );
            };
            strip_consumed_credentials(req_mut);
            if let Some(prefix) = &route.proxy_strip_prefix {
                match strip_route_prefix(req_mut.uri(), prefix) {
                    Some(stripped) => *req_mut.uri_mut() = stripped,
                    None => {
                        // The route matched a normalised form of the path, but the path as
                        // sent does not literally start with the prefix: refuse it instead of
                        // forwarding something the backend would read differently.
                        return (
                            err_meta.render_error(
                                StatusCode::BAD_REQUEST,
                                None,
                                Some(&site.error_pages),
                            ),
                            SecurityStep::Default,
                        );
                    }
                }
            }
            let req_method = req_mut.method().clone();
            let req_accept_encoding = combined_accept_encoding(req_mut.headers());
            let upgrade_lifecycle = req_mut
                .extensions_mut()
                .remove::<miraserve_proxy::UpgradeLifecycle>();
            let Some(req) = req_slot.take() else {
                return (
                    err_meta.render_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        None,
                        Some(&site.error_pages),
                    ),
                    SecurityStep::Default,
                );
            };
            let (parts, body) = req.into_parts();
            let resp = proxy
                .forward_parts(
                    parts,
                    body.into_proxy_body(),
                    ctx.client_ip,
                    ctx.scheme(),
                    upgrade_lifecycle,
                )
                .await
                .map(PipeRespBody::Proxy);
            // ONLY replace MiraServe-synthesized proxy gateway failures (`ProxyGeneratedError`),
            // never overwriting real upstream HTTP error responses!
            let final_resp = if resp.extensions().get::<ProxyGeneratedError>().is_some() {
                err_meta.upgrade_generated_error(resp, Some(&site.error_pages))
            } else {
                match try_compress_proxied_response_sync(
                    req_accept_encoding.as_deref(),
                    &req_method,
                    resp,
                ) {
                    std::ops::ControlFlow::Break(done) => done,
                    std::ops::ControlFlow::Continue((resp, decision, buffered_enc)) => {
                        Box::pin(buffer_and_compress_proxied_response(
                            resp,
                            decision,
                            buffered_enc,
                        ))
                        .await
                    }
                }
            };
            (final_resp, SecurityStep::Default)
        }
        CompiledHandler::McpGateway(gateway) => {
            // A Basic credential MiraServe consumed never reaches the MCP upstream (its own
            // bearer-token check never accepts a Basic value anyway).
            let Some(mut req) = req_slot.take() else {
                return (
                    err_meta.render_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        None,
                        Some(&site.error_pages),
                    ),
                    SecurityStep::Default,
                );
            };
            strip_consumed_credentials(&mut req);
            let proxy_req: Request<ProxyBody> = req.map(|body| {
                body.into_http_body()
                    .map_err(map_http_err_to_proxy_err)
                    .boxed()
            });
            let allow_plaintext_credentials = allow_credentials_on_transport(ctx.is_https, site);
            // R6-XFF-3: Pass the resolved effective client IP into MCP gateway audit/forwarding
            // so clients behind a trusted front proxy do not collapse onto the proxy IP.
            let (resp, blocked_by_gateway) = Box::pin(gateway.handle_with_outcome_for_transport(
                proxy_req,
                effective_client_ip,
                ctx.scheme(),
                allow_plaintext_credentials,
            ))
            .await;
            // MCP-4: Only record `mcp_rbac` security blocks originated by the gateway itself!
            if blocked_by_gateway {
                telemetry.record_security_block(SecurityBlockReason::McpRbac);
            }
            let mut resp = resp.map(map_proxy_body_pipe);
            if gateway.requires_jwt() && !allow_plaintext_credentials {
                resp.extensions_mut().insert(ProtectedResponse);
                resp.extensions_mut().insert(StripWwwAuthenticate);
            }
            (resp, SecurityStep::Default)
        }
        CompiledHandler::Redirect {
            status,
            target,
            route_prefix,
        } => {
            let Some(req_ref) = req_slot.as_ref() else {
                return (
                    err_meta.render_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        None,
                        Some(&site.error_pages),
                    ),
                    SecurityStep::Default,
                );
            };
            // `{path}` and `{uri}` are the visitor's path as sent. `{rest}` is what follows the
            // part of that path which decodes to the route prefix (the route matched the
            // decoded form: `/café/*`, `/old%2Farticle`), kept in its original encoding.
            let raw_path = req_ref.uri().path();
            let rest = raw_rest_after_prefix(raw_path, route_prefix).map_or_else(
                || {
                    canonical_path
                        .strip_prefix(route_prefix.as_str())
                        .map(|r| percent_encode_target(r.trim_start_matches('/'), false))
                        .unwrap_or_default()
                },
                str::to_owned,
            );
            let location =
                expand_redirect_with_rest(target, raw_path, &rest, req_ref.uri().query());
            let (redirect_resp, applied) = redirect_response_with_security(
                location,
                *status,
                route.security_headers.unwrap_or(site.security_headers),
                ctx.is_https,
                alt_svc,
                req_ref.version(),
                err_meta,
                &site.error_pages,
            );
            (
                redirect_resp,
                if applied {
                    SecurityStep::AlreadyApplied
                } else {
                    SecurityStep::Default
                },
            )
        }
        CompiledHandler::WasmPlugin(runtime) => {
            let Some(req) = req_slot.take() else {
                return (
                    err_meta.render_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        None,
                        Some(&site.error_pages),
                    ),
                    SecurityStep::Default,
                );
            };
            (
                Box::pin(execute_wasm_plugin(
                    runtime,
                    req,
                    ctx,
                    max_body_bytes,
                    telemetry,
                    err_meta,
                    &site.error_pages,
                ))
                .await,
                SecurityStep::Default,
            )
        }
        CompiledHandler::Unavailable => (
            err_meta.render_error(
                StatusCode::SERVICE_UNAVAILABLE,
                Some(DEFAULT_RETRY_AFTER_SECS),
                Some(&site.error_pages),
            ),
            SecurityStep::Default,
        ),
    }
}

#[cfg(any(test, feature = "test-h2-hooks"))]
static TEST_WASM_SPAWNED_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Returns how many WASM plugin invocations were spawned onto their own Tokio task for in-task
/// HTTP/2 streams since process start.
#[cfg(any(test, feature = "test-h2-hooks"))]
#[doc(hidden)]
#[must_use]
pub fn test_wasm_spawned_count() -> usize {
    TEST_WASM_SPAWNED_COUNT.load(std::sync::atomic::Ordering::Acquire)
}

/// Aborts a spawned task if its awaiting request future is dropped (e.g. client `RST_STREAM`,
/// connection drop, or drain timeout).
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Runs a WASM plugin invocation on its own Tokio task (boxed out of the inline request future)
/// so concurrent plugin invocations on one in-task HTTP/2 connection do not serialize on a single
/// core. Note that Wasmtime's execution timeout starts at the spawned task's first poll.
async fn execute_wasm_spawned(
    runtime: Arc<WasmPluginRuntime>,
    buffered_req: Request<Bytes>,
    is_https: bool,
    slot: tokio::sync::OwnedSemaphorePermit,
) -> Result<miraserve_wasm::WasmExecutionResult, miraserve_wasm::WasmError> {
    #[cfg(any(test, feature = "test-h2-hooks"))]
    TEST_WASM_SPAWNED_COUNT.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    let mut task = AbortOnDrop(tokio::spawn(async move {
        let _slot = slot;
        #[cfg(any(test, feature = "test-h2-hooks"))]
        let hold_gate = {
            let path = buffered_req.uri().path();
            TEST_WASM_HOLD_GATE
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .filter(|g| path.starts_with(g.path_prefix.as_str()))
                .map(|g| (Arc::clone(&g.entered), Arc::clone(&g.release)))
        };
        let res = runtime.execute(buffered_req, is_https).await;
        #[cfg(any(test, feature = "test-h2-hooks"))]
        if let Some((entered, release)) = hold_gate {
            entered.notify_one();
            release.notified().await;
        }
        res
    }));
    match (&mut task.0).await {
        Ok(res) => res,
        Err(join_err) if join_err.is_panic() => std::panic::resume_unwind(join_err.into_panic()),
        Err(_) => Err(miraserve_wasm::WasmError::Trap(
            "WASM plugin task cancelled".to_owned(),
        )),
    }
}

async fn execute_wasm_plugin(
    runtime: &Arc<WasmPluginRuntime>,
    mut req: Request<PipeReqBody>,
    ctx: &RequestContext,
    max_body_bytes: u64,
    telemetry: &TelemetryRegistry,
    err_meta: &ErrorMeta<'_>,
    site_pages: &SiteErrorPages,
) -> Response<PipeRespBody> {
    strip_consumed_credentials(&mut req);
    let (parts, mut body) = req.into_parts();
    let Ok(slot) = wasm_slots().try_acquire_owned() else {
        return no_room_to_buffer(err_meta, site_pages);
    };
    let mut held = crate::buffered::Buffered::for_address(ctx.client_ip, max_body_bytes);
    let mut raw = Vec::new();
    while let Some(frame_res) = body.frame().await {
        match frame_res {
            Ok(frame) => {
                if let Ok(data) = frame.into_data() {
                    if (raw.len() as u64).saturating_add(data.len() as u64) > max_body_bytes {
                        return err_meta.render_error(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            None,
                            Some(site_pages),
                        );
                    }
                    if !held.grow(data.len()) {
                        return no_room_to_buffer(err_meta, site_pages);
                    }
                    raw.extend_from_slice(&data);
                }
            }
            Err(HttpError::PayloadTooLarge(_)) => {
                return err_meta.render_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    None,
                    Some(site_pages),
                );
            }
            Err(HttpError::SlowBodyRate(min_rate_bps)) => {
                warn!(
                    request_id = %err_meta.request_id,
                    client_ip = %display_opt_ip(ctx.client_ip),
                    min_rate_bps,
                    "closing slow client request body upload (Slowloris guard)"
                );
                return err_meta.render_error(StatusCode::REQUEST_TIMEOUT, None, Some(site_pages));
            }
            Err(_) => {
                return err_meta.render_error(StatusCode::BAD_REQUEST, None, Some(site_pages));
            }
        }
    }

    let buffered_req = Request::from_parts(parts, Bytes::from(raw));
    let exec_res = if miraserve_static::in_nonblocking_inline_context() {
        Box::pin(execute_wasm_spawned(
            Arc::clone(runtime),
            buffered_req,
            ctx.is_https,
            slot,
        ))
        .await
    } else {
        let _slot = slot;
        runtime.execute(buffered_req, ctx.is_https).await
    };
    match exec_res {
        Ok(res) => {
            telemetry.record_wasm_invocation("ok", res.fuel_consumed);
            res.response.map(PipeRespBody::full)
        }
        Err(err) => {
            let (status, label) = err.http_status_and_label();
            // WASM-4: Record full fuel budget only on actual fuel exhaustion; never leak raw
            // Wasmtime internals to clients or misclassify guest traps as security blocks.
            let fuel_charged = if matches!(err, miraserve_wasm::WasmError::FuelExhausted { .. }) {
                runtime.config().max_fuel
            } else {
                0
            };
            telemetry.record_wasm_invocation(label, fuel_charged);
            if err.is_security_violation() {
                telemetry.record_security_block(SecurityBlockReason::WasmSandbox);
            }
            warn!(
                request_id = %err_meta.request_id,
                error = %err,
                outcome = label,
                "WASM plugin execution rejected"
            );
            err_meta.render_error(status, None, Some(site_pages))
        }
    }
}

/// 503 for a request whose body or answer cannot be buffered now (see `buffered`).
fn no_room_to_buffer(
    err_meta: &ErrorMeta<'_>,
    site_pages: &SiteErrorPages,
) -> Response<PipeRespBody> {
    warn!(
        request_id = %err_meta.request_id,
        "no room to buffer a request or its answer: too much is held for this address or in all"
    );
    err_meta.render_error(
        StatusCode::SERVICE_UNAVAILABLE,
        Some(DEFAULT_RETRY_AFTER_SECS),
        Some(site_pages),
    )
}

/// A buffered answer handed over in pieces, counted until the last piece has been taken (or it
/// is dropped). As one frame, hyper would take all of it at once and the count would end while
/// the bytes still wait in the connection's write buffer for a slow client.
struct HeldBody {
    bytes: Bytes,
    held: Option<crate::buffered::Buffered>,
}

/// The size of one piece of a [`HeldBody`].
const HELD_PIECE: usize = 64 * 1024;

impl http_body::Body for HeldBody {
    type Data = Bytes;
    type Error = HttpError;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, HttpError>>> {
        if self.bytes.is_empty() {
            self.bytes = Bytes::new();
            self.held = None;
            return std::task::Poll::Ready(None);
        }
        let piece = self.bytes.len().min(HELD_PIECE);
        // Each piece is a copy of its own: a slice would keep the whole answer alive for as
        // long as hyper holds the last one, after the count has been given back. So the
        // answer is freed, and its count ends, when the last piece has been taken; what hyper
        // still holds then is one piece.
        let data = Bytes::copy_from_slice(self.bytes.get(..piece).unwrap_or_default());
        bytes::Buf::advance(&mut self.bytes, piece);
        std::task::Poll::Ready(Some(Ok(http_body::Frame::data(data))))
    }

    fn is_end_stream(&self) -> bool {
        self.bytes.is_empty()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        http_body::SizeHint::with_exact(self.bytes.len() as u64)
    }
}

/// The rest of a streamed answer, as it comes from the backend.
type AnswerRest =
    Pin<Box<dyn futures_util::Stream<Item = Result<Bytes, FastCgiError>> + Send + Sync>>;

/// An answer larger than what is buffered: the buffered part (handed over and counted like a
/// [`HeldBody`]), then the rest as the backend sends it, one record at a time and only as fast
/// as the client takes it. If the backend fails on the way, the body ends with an error, so
/// the client sees a broken transfer and not a short answer that looks whole.
struct StreamedBody {
    first: Bytes,
    /// What is left of a declared length. At zero the body has ended: a transport that knows
    /// the length stops asking then, and must find the body complete.
    declared_left: Option<u64>,
    held: Option<crate::buffered::Buffered>,
    rest: Option<AnswerRest>,
    slot: Option<crate::buffered::Streamed>,
    request_id: String,
}

impl http_body::Body for StreamedBody {
    type Data = Bytes;
    type Error = HttpError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, HttpError>>> {
        if !self.first.is_empty() {
            let piece = self.first.len().min(HELD_PIECE);
            // A copy of its own, for the reason given in `HeldBody`.
            let data = Bytes::copy_from_slice(self.first.get(..piece).unwrap_or_default());
            bytes::Buf::advance(&mut self.first, piece);
            if self.first.is_empty() {
                self.first = Bytes::new();
                self.held = None;
            }
            self.count_declared(data.len());
            return Poll::Ready(Some(Ok(http_body::Frame::data(data))));
        }
        // The buffered part has been handed over (it can be empty when a declared length
        // sent the answer on at once): nothing is held any more.
        self.held = None;
        let Some(rest) = self.rest.as_mut() else {
            return Poll::Ready(None);
        };
        match futures_util::Stream::poll_next(rest.as_mut(), cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(part))) => {
                self.count_declared(part.len());
                Poll::Ready(Some(Ok(http_body::Frame::data(part))))
            }
            Poll::Ready(None) => {
                self.rest = None;
                self.slot = None;
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(err))) => {
                self.rest = None;
                self.slot = None;
                warn!(
                    request_id = %self.request_id,
                    error = %err,
                    "FastCGI answer ended early while it was being streamed"
                );
                Poll::Ready(Some(Err(HttpError::Body(format!(
                    "FastCGI answer ended early: {err}"
                )))))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.first.is_empty() && self.rest.is_none()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.declared_left.map_or_else(
            http_body::SizeHint::default,
            http_body::SizeHint::with_exact,
        )
    }
}

impl StreamedBody {
    /// Counts `bytes` against a declared length; with its last byte the answer is complete
    /// and the backend is let go.
    fn count_declared(&mut self, bytes: usize) {
        if let Some(left) = self.declared_left.as_mut() {
            *left = left.saturating_sub(bytes as u64);
            if *left == 0 && self.first.is_empty() {
                self.rest = None;
                self.slot = None;
            }
        }
    }
}

fn held_pipe_body(bytes: Bytes, held: crate::buffered::Buffered) -> PipeRespBody {
    PipeRespBody::Boxed(
        HeldBody {
            bytes,
            held: Some(held),
        }
        .boxed(),
    )
}

/// WASM executions at once, for the whole server (each has a store of its own).
const MAX_CONCURRENT_WASM: usize = 64;

#[cfg(any(test, feature = "test-h2-hooks"))]
static TEST_WASM_SLOTS_OVERRIDE: std::sync::Mutex<Option<Arc<Semaphore>>> =
    std::sync::Mutex::new(None);

/// Integration-test RAII guard overriding the process-wide WASM concurrency semaphore (e.g. to 1
/// slot to verify cancelled invocations release their slot deterministically).
#[cfg(any(test, feature = "test-h2-hooks"))]
#[doc(hidden)]
pub struct TestWasmSlotsOverrideGuard {
    prev: Option<Arc<Semaphore>>,
}

#[cfg(any(test, feature = "test-h2-hooks"))]
impl Drop for TestWasmSlotsOverrideGuard {
    fn drop(&mut self) {
        *TEST_WASM_SLOTS_OVERRIDE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = self.prev.take();
    }
}

/// Integration-test helper setting the active WASM slot semaphore to `slots` permits until drop.
#[cfg(any(test, feature = "test-h2-hooks"))]
#[doc(hidden)]
#[must_use]
pub fn test_wasm_slots_override_guard(slots: usize) -> TestWasmSlotsOverrideGuard {
    let prev = TEST_WASM_SLOTS_OVERRIDE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .replace(Arc::new(Semaphore::new(slots)));
    TestWasmSlotsOverrideGuard { prev }
}

#[cfg(any(test, feature = "test-h2-hooks"))]
struct WasmHoldGate {
    path_prefix: String,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

#[cfg(any(test, feature = "test-h2-hooks"))]
static TEST_WASM_HOLD_GATE: std::sync::Mutex<Option<WasmHoldGate>> = std::sync::Mutex::new(None);

/// Integration-test RAII guard holding matching spawned WASM tasks inside their task (while
/// still owning their `wasm_slots` permit) until released or cancelled.
#[cfg(any(test, feature = "test-h2-hooks"))]
#[doc(hidden)]
pub struct TestWasmHoldGateGuard {
    prev: Option<WasmHoldGate>,
}

#[cfg(any(test, feature = "test-h2-hooks"))]
impl Drop for TestWasmHoldGateGuard {
    fn drop(&mut self) {
        *TEST_WASM_HOLD_GATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = self.prev.take();
    }
}

/// Integration-test helper pausing spawned WASM tasks matching `path_prefix` while they still own
/// their `wasm_slots` permit, signaling `entered` and waiting on `release` until cancelled.
#[cfg(any(test, feature = "test-h2-hooks"))]
#[doc(hidden)]
#[must_use]
pub fn test_wasm_hold_path_guard(
    path_prefix: impl Into<String>,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
) -> TestWasmHoldGateGuard {
    let prev = TEST_WASM_HOLD_GATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .replace(WasmHoldGate {
            path_prefix: path_prefix.into(),
            entered,
            release,
        });
    TestWasmHoldGateGuard { prev }
}

/// Returns the number of currently available WASM execution slots on the active semaphore.
#[cfg(any(test, feature = "test-h2-hooks"))]
#[doc(hidden)]
#[must_use]
pub fn test_wasm_available_slots() -> usize {
    wasm_slots().available_permits()
}

fn wasm_slots() -> Arc<Semaphore> {
    static SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    #[cfg(any(test, feature = "test-h2-hooks"))]
    if let Some(sem) = TEST_WASM_SLOTS_OVERRIDE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
    {
        return sem;
    }
    Arc::clone(SLOTS.get_or_init(|| Arc::new(Semaphore::new(MAX_CONCURRENT_WASM))))
}

/// A HEAD answer has no body, whatever the script wrote (hyper drops it for HTTP/1.1 only;
/// HTTP/2 and HTTP/3 would send it). Its length is that of the body a GET would get: kept when
/// the script wrote one, left out when it did not (PHP writes none for HEAD, and "0" would be a
/// wrong length).
fn headless(resp: Response<Bytes>) -> Response<PipeRespBody> {
    let (mut head, body) = resp.into_parts();
    if body.is_empty() {
        head.headers.remove(CONTENT_LENGTH);
    }
    Response::from_parts(head, PipeRespBody::Empty)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn execute_fastcgi(
    client: &FastCgiClient,
    mut req: Request<PipeReqBody>,
    script_name: &str,
    path_info: &str,
    query_string: &str,
    server_name: &str,
    ctx: &RequestContext,
    effective_client_ip: Option<IpAddr>,
    is_trusted_peer: bool,
    max_body_bytes: u64,
    err_meta: &ErrorMeta<'_>,
    site_pages: &SiteErrorPages,
) -> Response<PipeRespBody> {
    strip_consumed_credentials(&mut req);
    let (mut parts, mut body) = req.into_parts();
    // R7-XFF-3: Match reverse-proxy forwarding header hygiene on FastCGI routes!
    // Untrusted peers must NEVER smuggle spoofed `X-Forwarded-*`, `X-Real-IP`, or `Forwarded`
    // headers into PHP/WordPress as `$_SERVER['HTTP_X_FORWARDED_*']`. Trusted peers have
    // `Forwarded` stripped and `X-Real-IP` overwritten with the resolved effective client IP.
    parts.headers.remove("forwarded");
    if !is_trusted_peer {
        parts.headers.remove("x-forwarded-for");
        parts.headers.remove("x-real-ip");
        parts.headers.remove("x-forwarded-proto");
        parts.headers.remove("x-forwarded-host");
        parts.headers.remove("x-forwarded-port");
    } else if let Some(ip) = effective_client_ip
        && let Ok(val) = HeaderValue::from_str(&ip.to_string())
    {
        parts
            .headers
            .insert(HeaderName::from_static("x-real-ip"), val);
    }
    let request_uri = fastcgi_request_uri(&parts);

    // The request and the answer are held whole in memory: counted against what the visitor's
    // address and the server may hold (see `buffered`).
    let mut held = crate::buffered::Buffered::for_address(effective_client_ip, max_body_bytes);
    let mut body_bytes = Vec::new();
    while let Some(frame_res) = body.frame().await {
        match frame_res {
            Ok(frame) => {
                if let Ok(data) = frame.into_data() {
                    if (body_bytes.len() as u64).saturating_add(data.len() as u64) > max_body_bytes
                    {
                        return err_meta.render_error(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            None,
                            Some(site_pages),
                        );
                    }
                    if !held.grow(data.len()) {
                        return no_room_to_buffer(err_meta, site_pages);
                    }
                    body_bytes.extend_from_slice(&data);
                }
            }
            Err(HttpError::PayloadTooLarge(_)) => {
                return err_meta.render_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    None,
                    Some(site_pages),
                );
            }
            Err(HttpError::SlowBodyRate(min_rate_bps)) => {
                warn!(
                    request_id = %err_meta.request_id,
                    client_ip = %display_opt_ip(ctx.client_ip),
                    min_rate_bps,
                    "closing slow client request body upload (Slowloris guard)"
                );
                return err_meta.render_error(StatusCode::REQUEST_TIMEOUT, None, Some(site_pages));
            }
            Err(err) => {
                warn!(
                    request_id = %err_meta.request_id,
                    error = %err,
                    "error reading request body for FastCGI"
                );
                return err_meta.render_error(StatusCode::BAD_REQUEST, None, Some(site_pages));
            }
        }
    }

    let fcgi_req = FastCgiRequest {
        method: &parts.method,
        version: parts.version,
        script_name,
        path_info,
        request_uri,
        query_string,
        server_name,
        server_addr: ctx.server_addr,
        server_port: ctx.server_port,
        // R6-XFF-3: Report the trusted-proxy-peeled effective client IP as FastCGI `REMOTE_ADDR`.
        client_ip: effective_client_ip,
        remote_port: ctx.remote_port,
        is_https: ctx.is_https,
        headers: &parts.headers,
        body: &body_bytes,
    };

    let answer = client
        .execute_streaming(&fcgi_req, &mut |bytes, take| {
            if take {
                held.grow(bytes)
            } else {
                held.shrink(bytes);
                true
            }
        })
        .await;
    // The request is done with; the answer stays counted until it has been sent.
    held.shrink(body_bytes.len());
    drop(body_bytes);
    match answer {
        Ok(FastCgiAnswer::Whole(resp)) if parts.method == Method::HEAD => headless(resp),
        Ok(FastCgiAnswer::Whole(resp)) => resp.map(|body| held_pipe_body(body, held)),
        // An answer larger than what is buffered. For HEAD the rest is not read: dropping the
        // tail closes the connection to the backend.
        Ok(FastCgiAnswer::Streamed(resp, _)) if parts.method == Method::HEAD => {
            let (response_head, _) = resp.into_parts();
            Response::from_parts(response_head, PipeRespBody::Empty)
        }
        Ok(FastCgiAnswer::Streamed(resp, tail)) => {
            // It holds a backend worker while the visitor downloads it: an address gets a few
            // of these at once.
            let slot = match crate::buffered::Streamed::start(
                effective_client_ip,
                &client.backend_key(),
                client.max_streamed_answers(),
            ) {
                Ok(slot) => slot,
                Err(refusal) => {
                    let setting = match refusal {
                        crate::buffered::StreamedRefusal::Address => {
                            "limits.max-streamed-answers-per-ip"
                        }
                        crate::buffered::StreamedRefusal::Backend
                            if client.max_streamed_answers().is_some() =>
                        {
                            "fastcgi-pass max-streamed-answers"
                        }
                        crate::buffered::StreamedRefusal::Backend => {
                            "limits.max-streamed-answers-per-backend"
                        }
                    };
                    warn!(
                        request_id = %err_meta.request_id,
                        script = script_name,
                        client_ip = %display_opt_ip(effective_client_ip),
                        setting,
                        "refusing a large FastCGI answer: as many are being streamed as the setting allows"
                    );
                    // What v0.1.0 and v0.1.1 answer for every answer of this size: 502. The
                    // script has run, so not a 503, whose page always carries `Retry-After`
                    // and would invite a client to send a request with side effects again.
                    return err_meta.render_error(StatusCode::BAD_GATEWAY, None, Some(site_pages));
                }
            };
            let request_id = err_meta.request_id.to_owned();
            // The length the answer declares, when it declares one (see `AnswerTail`).
            let declared_left = resp
                .headers()
                .get(CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok());
            resp.map(|first| {
                PipeRespBody::Boxed(
                    StreamedBody {
                        first,
                        declared_left,
                        held: Some(held),
                        rest: Some(Box::pin(futures_util::stream::try_unfold(
                            tail,
                            |mut tail: AnswerTail| async move {
                                Ok(tail.next().await?.map(|part| (part, tail)))
                            },
                        ))),
                        slot: Some(slot),
                        request_id,
                    }
                    .boxed(),
                )
            })
        }
        Err(FastCgiError::NoRoom) => no_room_to_buffer(err_meta, site_pages),
        Err(FastCgiError::Timeout) => {
            warn!(
                request_id = %err_meta.request_id,
                script = script_name,
                "FastCGI execution timed out"
            );
            err_meta.render_error(StatusCode::GATEWAY_TIMEOUT, None, Some(site_pages))
        }
        Err(err) => {
            warn!(
                request_id = %err_meta.request_id,
                script = script_name,
                error = %err,
                "FastCGI execution failed"
            );
            err_meta.render_error(StatusCode::BAD_GATEWAY, None, Some(site_pages))
        }
    }
}

fn display_opt_ip(ip: Option<IpAddr>) -> String {
    ip.map_or_else(|| "-".to_owned(), |v| v.to_string())
}

fn map_static_body(body: miraserve_static::StaticBody) -> PipeRespBody {
    match body.into_single_chunk() {
        Ok(None) => PipeRespBody::Empty,
        Ok(Some(bytes)) => PipeRespBody::full(bytes),
        Err(stream) => PipeRespBody::Boxed(
            stream
                .map_err(|err| HttpError::Body(err.to_string()))
                .boxed(),
        ),
    }
}

fn map_proxy_body_pipe(body: ProxyBody) -> PipeRespBody {
    PipeRespBody::Boxed(body.map_err(|err| HttpError::Body(err.to_string())).boxed())
}

fn map_http_err_to_proxy_err(err: HttpError) -> ProxyError {
    match err {
        HttpError::PayloadTooLarge(max) => ProxyError::PayloadTooLarge(max),
        other => ProxyError::Body(other.to_string()),
    }
}

fn extract_host_from_parts<'a>(
    host_header: Option<&'a HeaderValue>,
    uri: &'a http::Uri,
) -> Option<&'a str> {
    if let Some(host_hdr) = host_header.and_then(|v| v.to_str().ok()) {
        return Some(strip_port_from_host(host_hdr.trim()));
    }
    uri.host()
        .map(|h| h.trim_start_matches('[').trim_end_matches(']'))
}

fn extract_request_host_ref<B>(req: &Request<B>) -> Option<&str> {
    extract_host_from_parts(req.headers().get(HOST), req.uri())
}

#[cfg(test)]
fn extract_request_host<B>(req: &Request<B>) -> Option<String> {
    extract_request_host_ref(req).map(str::to_owned)
}

fn strip_port_from_host(raw: &str) -> &str {
    if let Some(rest) = raw.strip_prefix('[') {
        if let Some((v6, _)) = rest.split_once(']') {
            return v6;
        }
        return raw;
    }
    match raw.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && port.chars().all(|c| c.is_ascii_digit()) => {
            host
        }
        _ => raw,
    }
}

fn extract_request_port<B>(req: &Request<B>) -> Option<u16> {
    if let Some(host_hdr) = req.headers().get(HOST).and_then(|v| v.to_str().ok()) {
        return parse_port_from_authority(host_hdr.trim());
    }
    req.uri().port_u16()
}

fn parse_port_from_authority(raw: &str) -> Option<u16> {
    if let Some(rest) = raw.strip_prefix('[') {
        let (_, after) = rest.split_once(']')?;
        let port = after.strip_prefix(':')?;
        return (!port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))
            .then(|| port.parse::<u16>().ok())
            .flatten();
    }
    let (host, port) = raw.rsplit_once(':')?;
    if host.contains(':') || port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    port.parse::<u16>().ok()
}

/// Streaming fallback body that replays already-buffered prefix chunks (and optional trailers/error)
/// before continuing to stream the remaining upstream frames uncompressed when a chunked proxied
/// response exceeds [`MAX_ONTHEFLY_COMPRESS_BYTES`] mid-stream.
struct PrefixStreamBody {
    prefix: VecDeque<http_body::Frame<Bytes>>,
    pending_error: Option<HttpError>,
    rest: Option<HttpBody>,
}

impl http_body::Body for PrefixStreamBody {
    type Data = Bytes;
    type Error = HttpError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        if let Some(frame) = self.prefix.pop_front() {
            return Poll::Ready(Some(Ok(frame)));
        }
        if let Some(err) = self.pending_error.take() {
            return Poll::Ready(Some(Err(err)));
        }
        if let Some(rest) = self.rest.as_mut() {
            let poll = Pin::new(rest).poll_frame(cx);
            if matches!(poll, Poll::Ready(None)) {
                self.rest = None;
            }
            return poll;
        }
        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        self.prefix.is_empty()
            && self.pending_error.is_none()
            && self
                .rest
                .as_ref()
                .is_none_or(http_body::Body::is_end_stream)
    }
}

fn cache_control_has_no_transform(headers: &HeaderMap) -> bool {
    headers.get_all(CACHE_CONTROL).iter().any(|v| {
        v.to_str().is_ok_and(|s| {
            s.split(',')
                .any(|d| d.trim().eq_ignore_ascii_case("no-transform"))
        })
    })
}

fn append_vary_accept_encoding(headers: &mut HeaderMap) {
    let already = headers.get_all(VARY).iter().any(|v| {
        v.to_str().is_ok_and(|s| {
            s.split(',').any(|tok| {
                let t = tok.trim();
                t == "*" || t.eq_ignore_ascii_case("accept-encoding")
            })
        })
    });
    if !already {
        // Codex G6 (P1): Use `append` instead of `insert` so repeated upstream `Vary` header
        // lines (e.g. `Vary: Origin` + `Vary: Cookie`) are ALL preserved!
        headers.append(VARY, HeaderValue::from_static("Accept-Encoding"));
    }
}

fn weaken_etag_if_strong(headers: &mut HeaderMap) {
    if let Some(etag) = headers
        .get(ETAG)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .map(str::to_owned)
        && etag.starts_with('"')
        && let Ok(weak) = HeaderValue::from_str(&format!("W/{etag}"))
    {
        headers.insert(ETAG, weak);
    }
}

/// Maximum bytes compressed inline per poll on a dedicated worker event loop (64 KiB).
/// Buffered bodies larger than this are compressed on the blocking pool; streamed bodies compress
/// in pieces of at most this size and yield between pieces.
const WORKER_LOOP_COMPRESS_CHUNK_BYTES: usize = 64 * 1024;

/// Incremental chunk-by-chunk compressed body wrapper for unknown-length proxied responses on the
/// shared runtime so response headers and early chunks flush immediately while the upstream
/// remains open (Codex G6). Keeps the exact 0.1.4 field layout without worker-loop yield fields.
struct StreamingCompressedBody {
    inner: HttpBody,
    compressor: StreamCompressor,
    pending: VecDeque<http_body::Frame<Bytes>>,
    finished: bool,
}

impl StreamingCompressedBody {
    const fn new(inner: HttpBody, compressor: StreamCompressor) -> Self {
        Self {
            inner,
            compressor,
            pending: VecDeque::new(),
            finished: false,
        }
    }
}

impl http_body::Body for StreamingCompressedBody {
    type Data = Bytes;
    type Error = HttpError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        if let Some(frame) = self.pending.pop_front() {
            return Poll::Ready(Some(Ok(frame)));
        }
        if self.finished {
            return Poll::Ready(None);
        }
        loop {
            match Pin::new(&mut self.inner).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(err))) => {
                    self.finished = true;
                    return Poll::Ready(Some(Err(err)));
                }
                Poll::Ready(Some(Ok(frame))) => {
                    if frame.is_data() {
                        if let Some(data) = frame.data_ref() {
                            if data.is_empty() {
                                continue;
                            }
                            match self.compressor.push_chunk(data) {
                                Ok(out) if !out.is_empty() => {
                                    return Poll::Ready(Some(Ok(http_body::Frame::data(
                                        Bytes::from(out),
                                    ))));
                                }
                                Ok(_) => {}
                                Err(err) => {
                                    self.finished = true;
                                    return Poll::Ready(Some(Err(HttpError::Router(format!(
                                        "streaming compression failed: {err}"
                                    )))));
                                }
                            }
                        }
                    } else {
                        self.finished = true;
                        let mut frame = frame;
                        let keep_frame = if let Some(trailers) = frame.trailers_mut() {
                            trailers.remove("content-digest");
                            trailers.remove("repr-digest");
                            trailers.remove("digest");
                            !trailers.is_empty()
                        } else {
                            true
                        };
                        match self.compressor.finish() {
                            Ok(tail) if !tail.is_empty() => {
                                if keep_frame {
                                    self.pending.push_back(frame);
                                }
                                return Poll::Ready(Some(Ok(http_body::Frame::data(Bytes::from(
                                    tail,
                                )))));
                            }
                            Ok(_) => {
                                if keep_frame {
                                    return Poll::Ready(Some(Ok(frame)));
                                }
                                return Poll::Ready(None);
                            }
                            Err(err) => {
                                return Poll::Ready(Some(Err(HttpError::Router(format!(
                                    "streaming compression finalization failed: {err}"
                                )))));
                            }
                        }
                    }
                }
                Poll::Ready(None) => {
                    self.finished = true;
                    return match self.compressor.finish() {
                        Ok(tail) if !tail.is_empty() => {
                            Poll::Ready(Some(Ok(http_body::Frame::data(Bytes::from(tail)))))
                        }
                        Ok(_) => Poll::Ready(None),
                        Err(err) => Poll::Ready(Some(Err(HttpError::Router(format!(
                            "streaming compression finalization failed: {err}"
                        ))))),
                    };
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished && self.pending.is_empty()
    }
}

/// Worker-loop counterpart of [`StreamingCompressedBody`]: bounds inline compression to
/// [`WORKER_LOOP_COMPRESS_CHUNK_BYTES`] (64 KiB) per poll and yields between pieces so one
/// stream cannot starve other connections sharing the same single-thread worker event loop.
struct YieldingStreamingCompressedBody {
    inner: HttpBody,
    compressor: StreamCompressor,
    in_progress: Option<Bytes>,
    bytes_since_yield: usize,
    pending: VecDeque<http_body::Frame<Bytes>>,
    finished: bool,
}

impl YieldingStreamingCompressedBody {
    const fn new(inner: HttpBody, compressor: StreamCompressor) -> Self {
        Self {
            inner,
            compressor,
            in_progress: None,
            bytes_since_yield: 0,
            pending: VecDeque::new(),
            finished: false,
        }
    }
}

impl http_body::Body for YieldingStreamingCompressedBody {
    type Data = Bytes;
    type Error = HttpError;

    #[allow(clippy::too_many_lines)]
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        if let Some(frame) = self.pending.pop_front() {
            return Poll::Ready(Some(Ok(frame)));
        }
        if self.finished {
            return Poll::Ready(None);
        }
        loop {
            if self.bytes_since_yield >= WORKER_LOOP_COMPRESS_CHUNK_BYTES {
                self.bytes_since_yield = 0;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            if let Some(mut remaining) = self.in_progress.take() {
                let budget = WORKER_LOOP_COMPRESS_CHUNK_BYTES - self.bytes_since_yield;
                let take = remaining.len().min(budget);
                let piece = remaining.split_to(take);
                let is_last = remaining.is_empty();
                if !is_last {
                    self.in_progress = Some(remaining);
                }
                self.bytes_since_yield = self.bytes_since_yield.saturating_add(piece.len());
                match self.compressor.push_piece(&piece, is_last) {
                    Ok(out) if !out.is_empty() => {
                        return Poll::Ready(Some(Ok(http_body::Frame::data(Bytes::from(out)))));
                    }
                    Ok(_) => continue,
                    Err(err) => {
                        self.finished = true;
                        self.in_progress = None;
                        return Poll::Ready(Some(Err(HttpError::Router(format!(
                            "streaming compression failed: {err}"
                        )))));
                    }
                }
            }
            match Pin::new(&mut self.inner).poll_frame(cx) {
                Poll::Pending => {
                    self.bytes_since_yield = 0;
                    return Poll::Pending;
                }
                Poll::Ready(Some(Err(err))) => {
                    self.finished = true;
                    return Poll::Ready(Some(Err(err)));
                }
                Poll::Ready(Some(Ok(frame))) => {
                    if frame.is_data() {
                        let Ok(data) = frame.into_data() else {
                            continue;
                        };
                        if data.is_empty() {
                            continue;
                        }
                        self.in_progress = Some(data);
                        continue;
                    }
                    self.finished = true;
                    let mut frame = frame;
                    let keep_frame = if let Some(trailers) = frame.trailers_mut() {
                        trailers.remove("content-digest");
                        trailers.remove("repr-digest");
                        trailers.remove("digest");
                        !trailers.is_empty()
                    } else {
                        true
                    };
                    match self.compressor.finish() {
                        Ok(tail) if !tail.is_empty() => {
                            if keep_frame {
                                self.pending.push_back(frame);
                            }
                            return Poll::Ready(Some(Ok(http_body::Frame::data(Bytes::from(
                                tail,
                            )))));
                        }
                        Ok(_) => {
                            if keep_frame {
                                return Poll::Ready(Some(Ok(frame)));
                            }
                            return Poll::Ready(None);
                        }
                        Err(err) => {
                            return Poll::Ready(Some(Err(HttpError::Router(format!(
                                "streaming compression finalization failed: {err}"
                            )))));
                        }
                    }
                }
                Poll::Ready(None) => {
                    self.finished = true;
                    return match self.compressor.finish() {
                        Ok(tail) if !tail.is_empty() => {
                            Poll::Ready(Some(Ok(http_body::Frame::data(Bytes::from(tail)))))
                        }
                        Ok(_) => Poll::Ready(None),
                        Err(err) => Poll::Ready(Some(Err(HttpError::Router(format!(
                            "streaming compression finalization failed: {err}"
                        ))))),
                    };
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished && self.pending.is_empty() && self.in_progress.is_none()
    }
}

#[cfg(any(test, feature = "test-h2-hooks"))]
static TEST_PROXY_COMPRESS_POOL_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(any(test, feature = "test-h2-hooks"))]
static TEST_YIELDING_STREAM_COMPRESS_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(any(test, feature = "test-h2-hooks"))]
type ProxyCompressPoolHook = Arc<dyn Fn() + Send + Sync>;

#[cfg(any(test, feature = "test-h2-hooks"))]
static TEST_PROXY_COMPRESS_POOL_HOOK: std::sync::Mutex<Option<ProxyCompressPoolHook>> =
    std::sync::Mutex::new(None);

/// Integration-test RAII guard installing a hook inside `compress_buffered_on_worker_pool`'s
/// blocking-pool closure.
#[cfg(any(test, feature = "test-h2-hooks"))]
#[doc(hidden)]
pub struct TestProxyCompressPoolHookGuard {
    prev: Option<ProxyCompressPoolHook>,
}

#[cfg(any(test, feature = "test-h2-hooks"))]
impl Drop for TestProxyCompressPoolHookGuard {
    fn drop(&mut self) {
        *TEST_PROXY_COMPRESS_POOL_HOOK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = self.prev.take();
    }
}

/// Integration-test helper installing `hook` inside the proxied buffered compression blocking-pool
/// task until the returned guard drops.
#[cfg(any(test, feature = "test-h2-hooks"))]
#[doc(hidden)]
#[must_use]
pub fn test_proxy_compress_pool_hook_guard(
    hook: Arc<dyn Fn() + Send + Sync>,
) -> TestProxyCompressPoolHookGuard {
    let prev = TEST_PROXY_COMPRESS_POOL_HOOK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .replace(hook);
    TestProxyCompressPoolHookGuard { prev }
}

/// Returns `(buffered_pool_offloads, yielding_stream_wrappers)` recorded since process start.
#[cfg(any(test, feature = "test-h2-hooks"))]
#[doc(hidden)]
#[must_use]
pub fn test_proxy_compress_stats() -> (usize, usize) {
    (
        TEST_PROXY_COMPRESS_POOL_COUNT.load(std::sync::atomic::Ordering::Acquire),
        TEST_YIELDING_STREAM_COMPRESS_COUNT.load(std::sync::atomic::Ordering::Acquire),
    )
}

/// Process-wide byte budget for buffered proxied responses waiting for one of the
/// [`WORKER_LOOP_COMPRESS_JOBS`] (8) blocking-pool compression permits (32 MiB; combined with at
/// most 8 × 4 MiB active jobs, total buffered compression memory stays capped at 64 MiB). When
/// saturated, new waiting requests skip the wait and return the response uncompressed immediately
/// (with `Vary: Accept-Encoding`).
const WORKER_LOOP_COMPRESS_WAITER_BUDGET_BYTES: usize = 32 * 1024 * 1024;

static WORKER_LOOP_COMPRESS_WAITER_BYTES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(any(test, feature = "test-h2-hooks"))]
static TEST_COMPRESS_WAITER_BUDGET_OVERRIDE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(any(test, feature = "test-h2-hooks"))]
static TEST_COMPRESS_WAITER_REJECTED_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Integration-test RAII guard overriding the buffered compression waiter byte budget (`0`
/// restores the 32 MiB default).
#[cfg(any(test, feature = "test-h2-hooks"))]
#[doc(hidden)]
pub struct TestCompressWaiterBudgetGuard {
    prev: usize,
}

#[cfg(any(test, feature = "test-h2-hooks"))]
impl Drop for TestCompressWaiterBudgetGuard {
    fn drop(&mut self) {
        TEST_COMPRESS_WAITER_BUDGET_OVERRIDE.store(self.prev, std::sync::atomic::Ordering::Release);
    }
}

/// Integration-test helper overriding [`WORKER_LOOP_COMPRESS_WAITER_BUDGET_BYTES`] until drop.
#[cfg(any(test, feature = "test-h2-hooks"))]
#[doc(hidden)]
#[must_use]
pub fn test_compress_waiter_budget_override_guard(
    limit_bytes: usize,
) -> TestCompressWaiterBudgetGuard {
    let prev =
        TEST_COMPRESS_WAITER_BUDGET_OVERRIDE.swap(limit_bytes, std::sync::atomic::Ordering::AcqRel);
    TestCompressWaiterBudgetGuard { prev }
}

/// Returns `(current_waiter_bytes, rejected_by_budget_count)` for buffered compression waiters.
#[cfg(any(test, feature = "test-h2-hooks"))]
#[doc(hidden)]
#[must_use]
pub fn test_compress_waiter_stats() -> (usize, usize) {
    (
        WORKER_LOOP_COMPRESS_WAITER_BYTES.load(std::sync::atomic::Ordering::Acquire),
        TEST_COMPRESS_WAITER_REJECTED_COUNT.load(std::sync::atomic::Ordering::Acquire),
    )
}

/// Process-wide test hook forcing buffered proxy compression to take the failure path.
/// Serialized by `worker_compression_tests::COMPRESS_POOL_TEST_LOCK`; every unit test in this
/// module that depends on buffered proxy compression succeeding must hold that lock.
#[cfg(test)]
static TEST_FORCE_BUFFERED_COMPRESS_FAIL: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
struct TestForceBufferedCompressFailGuard {
    prev: bool,
}

#[cfg(test)]
impl Drop for TestForceBufferedCompressFailGuard {
    fn drop(&mut self) {
        TEST_FORCE_BUFFERED_COMPRESS_FAIL.store(self.prev, std::sync::atomic::Ordering::Release);
    }
}

#[cfg(test)]
fn test_force_buffered_compress_fail_guard(force_fail: bool) -> TestForceBufferedCompressFailGuard {
    let prev =
        TEST_FORCE_BUFFERED_COMPRESS_FAIL.swap(force_fail, std::sync::atomic::Ordering::AcqRel);
    TestForceBufferedCompressFailGuard { prev }
}

fn active_compress_waiter_budget_bytes() -> usize {
    #[cfg(any(test, feature = "test-h2-hooks"))]
    {
        let override_limit =
            TEST_COMPRESS_WAITER_BUDGET_OVERRIDE.load(std::sync::atomic::Ordering::Acquire);
        if override_limit > 0 {
            return override_limit;
        }
    }
    WORKER_LOOP_COMPRESS_WAITER_BUDGET_BYTES
}

/// RAII reservation against [`WORKER_LOOP_COMPRESS_WAITER_BYTES`], released as soon as the waiter
/// acquires a compression permit OR its future is dropped/cancelled.
struct WaiterByteReservation {
    bytes: usize,
}

impl WaiterByteReservation {
    fn try_reserve(bytes: usize) -> Option<Self> {
        let limit = active_compress_waiter_budget_bytes();
        let mut cur = WORKER_LOOP_COMPRESS_WAITER_BYTES.load(std::sync::atomic::Ordering::Acquire);
        loop {
            let next = cur.checked_add(bytes)?;
            if next > limit {
                return None;
            }
            match WORKER_LOOP_COMPRESS_WAITER_BYTES.compare_exchange_weak(
                cur,
                next,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            ) {
                Ok(_) => return Some(Self { bytes }),
                Err(observed) => cur = observed,
            }
        }
    }
}

impl Drop for WaiterByteReservation {
    fn drop(&mut self) {
        WORKER_LOOP_COMPRESS_WAITER_BYTES
            .fetch_sub(self.bytes, std::sync::atomic::Ordering::AcqRel);
    }
}

enum BufferedCompressOutcome {
    Compressed(Vec<u8>),
    /// Waiter byte budget was saturated while permits were busy; return uncompressed immediately
    /// with `Vary: Accept-Encoding`.
    BackpressureUncompressed,
    /// Compression failed or semaphore closed; return uncompressed as-is.
    Failed,
}

/// Non-blocking buffered compression offload (kept in its own boxed future so the shared-runtime
/// `maybe_compress_proxied_response` future does not carry semaphore/blocking-join state). Used
/// both on dedicated worker loops and inside in-task HTTP/2 streams.
async fn compress_buffered_on_worker_pool(
    enc: ContentEncoding,
    raw: Bytes,
) -> BufferedCompressOutcome {
    // Try an immediately available permit first (zero waiter-budget charge). If all permits are
    // busy, charge `raw.len()` against the process-wide 32 MiB waiter byte budget and release the
    // charge as soon as a permit is acquired or the waiting future is dropped. When the waiter
    // budget is full, return uncompressed immediately rather than letting idle waiters accumulate
    // unbounded heap buffers across concurrent HTTP/2 streams.
    let sem = worker_compress_semaphore();
    let permit = if let Ok(permit) = Arc::clone(sem).try_acquire_owned() {
        permit
    } else {
        let Some(waiter_reservation) = WaiterByteReservation::try_reserve(raw.len()) else {
            #[cfg(any(test, feature = "test-h2-hooks"))]
            TEST_COMPRESS_WAITER_REJECTED_COUNT.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            return BufferedCompressOutcome::BackpressureUncompressed;
        };
        let Ok(acquired) = Arc::clone(sem).acquire_owned().await else {
            return BufferedCompressOutcome::Failed;
        };
        drop(waiter_reservation);
        acquired
    };
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        #[cfg(any(test, feature = "test-h2-hooks"))]
        {
            TEST_PROXY_COMPRESS_POOL_COUNT.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            let hook = TEST_PROXY_COMPRESS_POOL_HOOK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if let Some(hook) = hook {
                hook();
            }
        }
        compress_bytes(enc, &raw)
    })
    .await
    .ok()
    .and_then(Result::ok)
    {
        Some(bytes) => BufferedCompressOutcome::Compressed(bytes),
        None => BufferedCompressOutcome::Failed,
    }
}

fn has_integrity_digest_headers(headers: &HeaderMap) -> bool {
    if headers.contains_key("content-digest")
        || headers.contains_key("repr-digest")
        || headers.contains_key("digest")
    {
        return true;
    }
    headers.get_all(http::header::TRAILER).iter().any(|v| {
        v.to_str().is_ok_and(|s| {
            s.split(',').any(|tok| {
                let t = tok.trim();
                t.eq_ignore_ascii_case("content-digest")
                    || t.eq_ignore_ascii_case("repr-digest")
                    || t.eq_ignore_ascii_case("digest")
            })
        })
    })
}

/// Owned `Accept-Encoding` value combined per RFC 9110 §5.2 without constructing a `String` for
/// the common single-header-line case (cloning the `Bytes`-backed `HeaderValue` directly; a first
/// clone of uniquely backed `Bytes` may still allocate reference-count metadata).
#[derive(Debug, Clone)]
enum CombinedAcceptEncoding {
    Single(HeaderValue),
    Joined(String),
}

impl std::ops::Deref for CombinedAcceptEncoding {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Single(val) => val.to_str().unwrap_or(""),
            Self::Joined(s) => s.as_str(),
        }
    }
}

/// Combines all valid UTF-8 `Accept-Encoding` field lines in order separated by `", "`
/// (RFC 9110 §5.2), avoiding constructing a `String` in the common zero- or single-header case.
fn combined_accept_encoding(headers: &HeaderMap) -> Option<CombinedAcceptEncoding> {
    let mut iter = headers
        .get_all(ACCEPT_ENCODING)
        .iter()
        .filter_map(|v| v.to_str().ok().map(|s| (v, s)));
    let (first_val, first_str) = iter.next()?;
    let Some((_, second_str)) = iter.next() else {
        return Some(CombinedAcceptEncoding::Single(first_val.clone()));
    };
    let mut combined = String::with_capacity(first_str.len() + 2 + second_str.len());
    combined.push_str(first_str);
    combined.push_str(", ");
    combined.push_str(second_str);
    for (_, next) in iter {
        combined.push_str(", ");
        combined.push_str(next);
    }
    Some(CombinedAcceptEncoding::Joined(combined))
}

/// Parses an RFC 9110 §12.4.2 `qvalue` into exact milliquality (`0..=1000`):
/// `qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )`.
///
/// Any value outside `0..=1`, with more than 3 fractional digits, or containing non-digit
/// characters returns `None` so the caller rejects that member per RFC 9110 §12.4.2 / §12.5.3.
fn parse_rfc9110_qvalue(q_str: &str) -> Option<u16> {
    if q_str == "0" || q_str == "0." {
        return Some(0);
    }
    if q_str == "1" || q_str == "1." {
        return Some(1_000);
    }
    if let Some(frac) = q_str.strip_prefix("0.") {
        if frac.len() > 3 || !frac.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let mut scale = 100_u16;
        let mut val = 0_u16;
        for b in frac.bytes() {
            val += u16::from(b - b'0') * scale;
            scale /= 10;
        }
        return Some(val);
    }
    if let Some(frac) = q_str.strip_prefix("1.") {
        if frac.len() > 3 || !frac.bytes().all(|b| b == b'0') {
            return None;
        }
        return Some(1_000);
    }
    None
}

/// Result of RFC 9110 §12.5.3 / §12.4.2 `Accept-Encoding` negotiation over a combined field value.
///
/// Server preference order for equal quality weights is **`zstd > br > gzip`**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NegotiatedAcceptEncoding {
    /// `true` iff unencoded (`identity`) representation is acceptable under RFC 9110 §12.5.3.
    identity_acceptable: bool,
    /// Acceptable codings among `{zstd, br, gzip}` ordered by descending RFC 9110 §12.4.2 weight,
    /// breaking ties in server preference order (`zstd > br > gzip`). Only `..self.len` is live.
    codings: [ContentEncoding; 3],
    len: usize,
}

impl NegotiatedAcceptEncoding {
    fn acceptable_codings(&self) -> &[ContentEncoding] {
        self.codings.get(..self.len).unwrap_or(&self.codings)
    }
}

#[derive(Default, Clone, Copy)]
struct EncodingTokenState {
    max_pos_q: Option<u16>,
    excluded: bool,
}

impl EncodingTokenState {
    fn record(&mut self, q: u16) {
        if q == 0 {
            self.excluded = true;
        } else {
            self.max_pos_q = Some(self.max_pos_q.map_or(q, |prev| prev.max(q)));
        }
    }

    const fn is_listed(self) -> bool {
        self.excluded || self.max_pos_q.is_some()
    }

    const fn effective_q(self, wildcard: Self) -> Option<u16> {
        if self.excluded {
            None
        } else if let Some(q) = self.max_pos_q {
            Some(q)
        } else if wildcard.excluded {
            None
        } else {
            wildcard.max_pos_q
        }
    }
}

/// Parses a combined `Accept-Encoding` field value per RFC 9110 §12.5.3 and §12.4.2 in one pass.
///
/// Rules:
/// - Empty list elements (RFC 9110 §5.6.1.2) are ignored.
/// - Each member is `coding [ OWS ";" OWS "q=" qvalue ]` (case-insensitive coding and `q`; per
///   RFC 9110 §12.4.2 `OWS` is permitted around `;` but forbidden around `=`).
/// - Per RFC 9110 §8.4.1.3 & §18.6 (IANA HTTP Content Coding Registry), `x-gzip` is treated as
///   strictly equivalent to `gzip` (sharing the same `EncodingTokenState`: multiple positive
///   weights keep the maximum `q`, any `q=0` on either spelling excludes `gzip` fail-closed and
///   prevents `*` from re-enabling it, and the response is emitted as canonical
///   `Content-Encoding: gzip`). `x-gzip` is the sole registered alias for any coding MiraServe
///   produces (`br` [RFC 7932] and `zstd` [RFC 8878] have none; `x-compress` aliases `compress`,
///   which MiraServe does not produce).
/// - Any member with a malformed parameter, duplicate `q=`, non-`q` parameter, or out-of-range
///   `qvalue` (outside `0..=1` or more than 3 fractional digits) is rejected completely (treated as
///   not listed).
/// - A member with `q=0` excludes that token; if a token appears with both `q>0` and `q=0`, `q=0`
///   wins (fail-closed); multiple valid positive listings for the same token keep the maximum `q`.
/// - `*` applies only to codings (and `identity`) that have NO valid explicit listing.
/// - `identity` is acceptable by default unless explicitly excluded (`identity;q=0`) or excluded via
///   `*;q=0` without a valid explicit `identity` listing (RFC 9110 §12.5.3).
/// - Acceptable codings among `{zstd, br, gzip}` are ordered by descending quality weight, breaking
///   ties by server preference: **`zstd > br > gzip`**.
fn negotiate_proxy_accept_encoding(header_val: &str) -> NegotiatedAcceptEncoding {
    let mut zstd = EncodingTokenState::default();
    let mut br = EncodingTokenState::default();
    let mut gzip = EncodingTokenState::default();
    let mut identity = EncodingTokenState::default();
    let mut wildcard = EncodingTokenState::default();

    for raw_part in header_val.split(',') {
        let mut segments = raw_part.trim_matches([' ', '\t']).split(';');
        let Some(token_raw) = segments.next() else {
            continue;
        };
        let token = token_raw.trim_matches([' ', '\t']);
        if token.is_empty() {
            continue;
        }

        let mut parsed_q: Option<u16> = None;
        let mut invalid_member = false;
        for param in segments {
            let p = param.trim_matches([' ', '\t']);
            if p.is_empty() {
                invalid_member = true;
                break;
            }
            if let Some(q_str) = p.strip_prefix("q=").or_else(|| p.strip_prefix("Q=")) {
                if parsed_q.is_some() {
                    invalid_member = true;
                    break;
                }
                if let Some(q) = parse_rfc9110_qvalue(q_str) {
                    parsed_q = Some(q);
                } else {
                    invalid_member = true;
                    break;
                }
            } else {
                // RFC 9110 §12.5.3 allows only `[ weight ]` parameters on Accept-Encoding members.
                invalid_member = true;
                break;
            }
        }
        if invalid_member {
            continue;
        }
        let q = parsed_q.unwrap_or(1_000);

        if token.eq_ignore_ascii_case("zstd") {
            zstd.record(q);
        } else if token.eq_ignore_ascii_case("br") {
            br.record(q);
        } else if token.eq_ignore_ascii_case("gzip") || token.eq_ignore_ascii_case("x-gzip") {
            gzip.record(q);
        } else if token.eq_ignore_ascii_case("identity") {
            identity.record(q);
        } else if token == "*" {
            wildcard.record(q);
        }
    }

    // RFC 9110 §12.5.3: identity is acceptable unless explicitly excluded (`identity;q=0`) or
    // excluded via `*;q=0` without a valid explicit listing for `identity`.
    let identity_acceptable = if identity.is_listed() {
        !identity.excluded
    } else {
        !wildcard.excluded
    };

    // Collect acceptable codings in server preference order (`zstd > br > gzip`), then stable-sort
    // by descending quality weight so ties strictly preserve `zstd > br > gzip`.
    let mut weighted: [(ContentEncoding, u16); 3] = [(ContentEncoding::Zstd, 0); 3];
    let mut len = 0_usize;
    for (enc, q_opt) in [
        (ContentEncoding::Zstd, zstd.effective_q(wildcard)),
        (ContentEncoding::Brotli, br.effective_q(wildcard)),
        (ContentEncoding::Gzip, gzip.effective_q(wildcard)),
    ] {
        if let Some(q) = q_opt
            && let Some(slot) = weighted.get_mut(len)
        {
            *slot = (enc, q);
            len += 1;
        }
    }
    if let Some(active) = weighted.get_mut(..len) {
        active.sort_by_key(|a| std::cmp::Reverse(a.1));
    }

    let mut codings = [ContentEncoding::Zstd; 3];
    for i in 0..len {
        if let (Some(dst), Some(&(enc, _))) = (codings.get_mut(i), weighted.get(i)) {
            *dst = enc;
        }
    }

    NegotiatedAcceptEncoding {
        identity_acceptable,
        codings,
        len,
    }
}

/// Which proxy compression path is choosing an encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxyCompressPath {
    /// Known-length buffered path outside saturation: can produce `{zstd, br, gzip}`.
    BufferedUnsaturated,
    /// Unknown-length incremental streaming path (`StreamCompressor`): can produce `{br, gzip}`.
    Streamed,
    /// Known-length path at blocking-pool saturation (permits and waiter byte budget full):
    /// sheds compression when `identity` is acceptable; otherwise falls back to incremental
    /// `YieldingStreamingCompressedBody` over `{br, gzip}`.
    Saturated,
}

/// Single proxy `Accept-Encoding` decision across all three compression paths, enforcing the
/// proxy invariant in one place:
///
/// - **(a) `identity` acceptable:** preserves **exact v0.1.4 selection** (`accepted_encodings`, so
///   a bare `*` still gets identity and ordinary clients are unchanged; at saturation, sheds
///   compression and sends uncompressed with `Vary: Accept-Encoding`).
/// - **(b) `identity` NOT acceptable:** selects the highest-ranked coding from
///   [`negotiate_proxy_accept_encoding`] restricted to what the path at hand can produce:
///   - `BufferedUnsaturated`: `{zstd, br, gzip}`
///   - `Streamed` and `Saturated`: `{br, gzip}`
///
/// If and only if that intersection is empty (streamed or saturated with only `zstd` acceptable,
/// or no supported coding acceptable), the upstream response goes out uncompressed with
/// `Vary: Accept-Encoding` (the documented residual).
///
/// Therefore, `"identity excluded and a coding this path can produce is acceptable => never
/// identity"` holds for every header by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProxyEncodingDecision {
    identity_acceptable: bool,
    buffered_unsaturated: Option<ContentEncoding>,
    streamed: Option<ContentEncoding>,
    saturated: Option<ContentEncoding>,
}

impl ProxyEncodingDecision {
    fn from_header(header_val: Option<&str>) -> Self {
        let Some(val) = header_val else {
            return Self {
                identity_acceptable: true,
                buffered_unsaturated: None,
                streamed: None,
                saturated: None,
            };
        };

        let is_streamable =
            |e: &ContentEncoding| matches!(e, ContentEncoding::Brotli | ContentEncoding::Gzip);
        let negotiated = negotiate_proxy_accept_encoding(val);
        if negotiated.identity_acceptable {
            // Case (a): identity acceptable -> exact v0.1.4 selection.
            let v014 = accepted_encodings(val);
            Self {
                identity_acceptable: true,
                buffered_unsaturated: v014.first().copied(),
                streamed: v014.iter().copied().find(is_streamable),
                saturated: None,
            }
        } else {
            // Case (b): identity NOT acceptable -> RFC 9110 ordered list restricted to producible.
            let list = negotiated.acceptable_codings();
            let streamable = list.iter().copied().find(is_streamable);
            Self {
                identity_acceptable: false,
                buffered_unsaturated: list.first().copied(),
                streamed: streamable,
                saturated: streamable,
            }
        }
    }

    const fn encoding_for(self, path: ProxyCompressPath) -> Option<ContentEncoding> {
        match path {
            ProxyCompressPath::BufferedUnsaturated => self.buffered_unsaturated,
            ProxyCompressPath::Streamed => self.streamed,
            ProxyCompressPath::Saturated => self.saturated,
        }
    }
}

/// Categorical classification for a proxied response before instance guards and compression:
/// - [`Self::BypassUntouched`]: MiraServe never transforms this response and must leave upstream
///   headers untouched (no `Vary: Accept-Encoding` added).
/// - [`Self::VaryOnly`]: Cache-updating bodiless response (`304 Not Modified` per RFC 9111 §4.3.4,
///   or `HEAD` passing every non-method categorical guard with missing `Content-Type` allowed per
///   RFC 9111 §4.3.5) — if the upstream response already has a `Vary` field, merge
///   `Accept-Encoding` into it at the single append site (because a cache updating a stored `200`
///   replaces its `Vary` with the received `Vary`, RFC 9111 §3.2); if the upstream response has NO
///   `Vary` field, leave the response untouched (matching v0.1.4, so the cache keeps the stored
///   `200`'s existing `Vary` intact, RFC 9110 §9.3.2 / RFC 9111 §3.2). In both cases return
///   immediately without touching the body.
/// - [`Self::Eligible`]: Passes all categorical guards — append `Vary: Accept-Encoding` and
///   proceed to instance guards and compression negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxyCategoricalOutcome {
    BypassUntouched,
    VaryOnly,
    Eligible,
}

/// Categorical proxy-compression classification: separates responses MiraServe NEVER transforms
/// (`1xx`, `204`, `206`, an existing `Content-Encoding` or `Content-Range`, a visible digest
/// header or an advertised digest trailer, `Cache-Control: no-transform`, or a
/// non-compressible/missing media type including SSE — returning with upstream headers untouched)
/// from the two cache-updating bodiless response kinds (`304 Not Modified` unconditionally, and
/// `HEAD` whenever it passes every non-method categorical guard with missing `Content-Type`
/// treated as transformable — merging `Accept-Encoding` into an existing upstream `Vary` only,
/// leaving responses with no `Vary` untouched, and never touching the body) and from categorically
/// eligible responses.
fn classify_proxied_response_categorical<B>(
    req_method: &Method,
    resp: &Response<B>,
) -> ProxyCategoricalOutcome {
    let status = resp.status();

    // RFC 9111 §4.3.4 / §3.2: a validating `304 Not Modified` (for GET or HEAD) that carries a
    // `Vary` header replaces a stored compressed `200`'s `Vary` (so `Accept-Encoding` must be
    // merged into it), whereas a `304` omitting `Vary` leaves the stored `Vary` intact (so absence
    // must be preserved). Handled uniformly with eligible `HEAD` via `VaryOnly` without ever
    // touching the body.
    if status == StatusCode::NOT_MODIFIED {
        return ProxyCategoricalOutcome::VaryOnly;
    }

    let is_head = *req_method == Method::HEAD;

    if status.is_informational()
        || matches!(status, StatusCode::NO_CONTENT | StatusCode::PARTIAL_CONTENT)
    {
        return ProxyCategoricalOutcome::BypassUntouched;
    }

    let headers = resp.headers();
    if headers.contains_key(CONTENT_ENCODING)
        || headers.contains_key(CONTENT_RANGE)
        || has_integrity_digest_headers(headers)
        || cache_control_has_no_transform(headers)
    {
        return ProxyCategoricalOutcome::BypassUntouched;
    }

    let compressible = match headers.get(CONTENT_TYPE) {
        Some(ct) => {
            let mime_essence = ct
                .to_str()
                .ok()
                .and_then(|s| s.split(';').next())
                .map(str::trim)
                .unwrap_or_default();
            if mime_essence.bytes().any(|b| b.is_ascii_uppercase()) {
                is_compressible_mime(&mime_essence.to_ascii_lowercase())
            } else {
                is_compressible_mime(mime_essence)
            }
        }
        // RFC 9111 §4.3.5: a `HEAD` response with no `Content-Type` can still update a stored
        // compressed `GET` representation and counts as transformable; non-`HEAD` responses
        // without `Content-Type` stay untouched.
        None => is_head,
    };
    if !compressible {
        return ProxyCategoricalOutcome::BypassUntouched;
    }

    if is_head {
        ProxyCategoricalOutcome::VaryOnly
    } else {
        ProxyCategoricalOutcome::Eligible
    }
}

/// Instance proxy-compression guards (header/metadata stage): this particular response instance is
/// not transformed, even though another response for the same resource (e.g. different framing or
/// size) could be (`Body::is_end_stream`, the `UpstreamHasDigestTrailer` extension recorded after
/// hop-by-hop `Trailer` header stripping, `X-Accel-Buffering: no`, or a declared `Content-Length`
/// outside `MIN_COMPRESS_BYTES..=MAX_ONTHEFLY_COMPRESS_BYTES`).
///
/// Runs AFTER the single `Vary: Accept-Encoding` append site so caches still key on
/// `Accept-Encoding` (matching and strictly superseding v0.1.4's empty-accepted-list behaviour).
/// Body-stage instance guards (actual data over the cap, under the minimum, trailers, or a body
/// error) run later during buffering and likewise inherit `Vary: Accept-Encoding`.
fn proxied_response_fails_instance_guards<B: http_body::Body>(
    resp: &Response<B>,
    content_length: Option<u64>,
) -> bool {
    if http_body::Body::is_end_stream(resp.body())
        || resp
            .extensions()
            .get::<miraserve_proxy::UpstreamHasDigestTrailer>()
            .is_some()
        || resp
            .headers()
            .get("x-accel-buffering")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("no"))
    {
        return true;
    }

    content_length
        .is_some_and(|cl| !(MIN_COMPRESS_BYTES..=MAX_ONTHEFLY_COMPRESS_BYTES).contains(&cl))
}

/// Compresses eligible proxied text/JSON/JS/CSS/SVG/XML responses on the fly using `zstd`, `br`,
/// or `gzip` (`HANDOVER §5 #11`) while strictly preserving zero-buffer SSE/streaming routes,
/// `no-transform`, integrity-protected responses (`Content-Digest` / `Repr-Digest` / `Digest`,
/// RFC 9530 §2), pre-compressed upstreams, partial content, `HEAD`, and live unknown-length
/// text streams (Codex G6: unknown-length streams compress incrementally chunk-by-chunk without
/// delaying headers for EOF).
/// Synchronous header-stage half of proxied-response compression: handles categorical guards,
/// `Vary: Accept-Encoding`, instance guards, encoding negotiation, and unknown-length incremental
/// streaming without awaiting, returning `ControlFlow::Continue` only when a known-length body
/// must be buffered and compressed asynchronously (so bypassed/streaming responses pay zero async
/// future state inside `execute_route` and zero boxing).
#[allow(clippy::too_many_lines)]
fn try_compress_proxied_response_sync(
    req_accept_encoding: Option<&str>,
    req_method: &Method,
    mut resp: Response<PipeRespBody>,
) -> std::ops::ControlFlow<
    Response<PipeRespBody>,
    (
        Response<PipeRespBody>,
        ProxyEncodingDecision,
        ContentEncoding,
    ),
> {
    // 1. CATEGORICAL guards + cache-updating `304` / `HEAD` classification:
    //    - `BypassUntouched`: MiraServe never transforms such a response whatever its body turns
    //      out to be; return with upstream headers untouched (no `Vary: Accept-Encoding` added).
    //    - `VaryOnly`: `304 Not Modified` (RFC 9111 §4.3.4) or eligible `HEAD` (RFC 9111 §4.3.5):
    //      * When the upstream response has NO `Vary` field, leave it untouched (exact v0.1.4
    //        behaviour): RFC 9110 §9.3.2 permits a `HEAD` to omit `Vary`, whereas RFC 9110
    //        §15.4.5 requires an origin to send `Vary` on a `304` if it would on the `200`;
    //        preserving absence protects the stored `200`'s existing `Vary` field intact
    //        (RFC 9111 §3.2, §4.3.4, §4.3.5) when an origin omits it anyway. Synthesizing
    //        `Vary: Accept-Encoding` here would instead cause the cache to replace the stored
    //        `Vary` and erase upstream dimensions such as `Accept-Language`.
    //      * When the upstream response HAS a `Vary` field, fall through to the single append site
    //        below to merge `Accept-Encoding` into it (leaving `*` untouched, checking all field
    //        lines, avoiding duplicates) because the cache replaces the stored `Vary` with the
    //        received `Vary` on update; then return immediately without touching the body.
    //    - `Eligible`: append `Vary: Accept-Encoding` and proceed to instance guards & compression.
    let categorical = classify_proxied_response_categorical(req_method, &resp);
    match categorical {
        ProxyCategoricalOutcome::BypassUntouched => return std::ops::ControlFlow::Break(resp),
        ProxyCategoricalOutcome::VaryOnly if !resp.headers().contains_key(VARY) => {
            return std::ops::ControlFlow::Break(resp);
        }
        ProxyCategoricalOutcome::VaryOnly | ProxyCategoricalOutcome::Eligible => {}
    }

    // 2. THE ONE `Vary: Accept-Encoding` append site: sits after categorical guards and before
    //    instance guards, for EVERY request whatever `Accept-Encoding` it carried or lacked.
    //    Reached by `VaryOnly` (`304`/`HEAD`) ONLY when the upstream response already carries a
    //    `Vary` field (merging `Accept-Encoding` so the cache's replacement keeps it, then
    //    returning immediately below without touching the body), and by all categorically eligible
    //    responses (`Eligible`), where every instance guard exit, late body-stage exit,
    //    identity-by-choice exit, expanded-therefore-identity exit, saturation/failure fallback,
    //    and compressed arm structurally inherits this header from here (strict superset of
    //    v0.1.4; zero per-arm appends).
    append_vary_accept_encoding(resp.headers_mut());

    if categorical == ProxyCategoricalOutcome::VaryOnly {
        return std::ops::ControlFlow::Break(resp);
    }

    // 3. INSTANCE guards (header/metadata stage): this particular response is not transformed,
    //    though another response for the same resource could be (`Vary` already appended above).
    let content_length = resp
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok());
    if proxied_response_fails_instance_guards(&resp, content_length) {
        return std::ops::ControlFlow::Break(resp);
    }

    // 4. Consult the single encoding decision (`Vary: Accept-Encoding` is already set above).
    let decision = ProxyEncodingDecision::from_header(req_accept_encoding);

    // `Streamed` and `Saturated` producible codings (`{br, gzip}`) are a strict subset of
    // `BufferedUnsaturated` (`{zstd, br, gzip}`), so `buffered_enc == None` guarantees no path
    // can compress this request.
    let Some(buffered_enc) = decision.encoding_for(ProxyCompressPath::BufferedUnsaturated) else {
        return std::ops::ControlFlow::Break(resp);
    };

    if content_length.is_none() {
        // Codex G6: Unknown-length response (e.g. chunked plain-text log or NDJSON stream).
        // NEVER buffer waiting for EOF before returning headers! Compress incrementally with a
        // flush-capable encoder (`br`/`gzip`), or pass through uncompressed (`Vary` already set
        // above) if only `zstd` is accepted so headers and the first chunk reach the client
        // immediately.
        let Some(stream_enc) = decision.encoding_for(ProxyCompressPath::Streamed) else {
            return std::ops::ControlFlow::Break(resp);
        };
        let Some(compressor) = StreamCompressor::new(stream_enc) else {
            return std::ops::ControlFlow::Break(resp);
        };
        let (mut parts, body) = resp.into_parts();
        parts.headers.insert(
            CONTENT_ENCODING,
            HeaderValue::from_static(stream_enc.header_value()),
        );
        parts.headers.remove(CONTENT_LENGTH);
        weaken_etag_if_strong(&mut parts.headers);
        let boxed_body = if miraserve_static::inline_work_must_not_block() {
            #[cfg(any(test, feature = "test-h2-hooks"))]
            TEST_YIELDING_STREAM_COMPRESS_COUNT.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            PipeRespBody::Boxed(
                YieldingStreamingCompressedBody::new(body.into_http_body(), compressor).boxed(),
            )
        } else {
            PipeRespBody::Boxed(
                StreamingCompressedBody::new(body.into_http_body(), compressor).boxed(),
            )
        };
        return std::ops::ControlFlow::Break(Response::from_parts(parts, boxed_body));
    }

    std::ops::ControlFlow::Continue((resp, decision, buffered_enc))
}

/// Async buffering + compression half of proxied-response compression, boxed out of
/// `execute_route` so bypassed and streaming responses add zero state to `pipeline_tracked`.
#[allow(clippy::too_many_lines)]
async fn buffer_and_compress_proxied_response(
    resp: Response<PipeRespBody>,
    decision: ProxyEncodingDecision,
    buffered_enc: ContentEncoding,
) -> Response<PipeRespBody> {
    let disallow_identity = !decision.identity_acceptable;
    let (mut parts, mut body) = resp.into_parts();
    let max_bytes = usize::try_from(MAX_ONTHEFLY_COMPRESS_BYTES).unwrap_or(4 * 1024 * 1024);
    let min_bytes = usize::try_from(MIN_COMPRESS_BYTES).unwrap_or(1_024);

    let mut frames: VecDeque<http_body::Frame<Bytes>> = VecDeque::new();
    let mut total_data_bytes: usize = 0;

    // Buffering stage: late INSTANCE guards (actual data over the 4 MiB cap, body error, actual
    // data under 1,024 bytes, or trailers) return uncompressed while preserving the
    // `Vary: Accept-Encoding` appended after categorical guards above.
    while let Some(next_res) = body.frame().await {
        match next_res {
            Ok(frame) => {
                if let Some(data) = frame.data_ref() {
                    total_data_bytes = total_data_bytes.saturating_add(data.len());
                }
                frames.push_back(frame);
                if total_data_bytes > max_bytes {
                    // Exceeded on-the-fly compression cap mid-stream: stream seamlessly uncompressed!
                    let passthrough = PrefixStreamBody {
                        prefix: frames,
                        pending_error: None,
                        rest: Some(body.into_http_body()),
                    };
                    return Response::from_parts(parts, PipeRespBody::Boxed(passthrough.boxed()));
                }
            }
            Err(err) => {
                let passthrough = PrefixStreamBody {
                    prefix: frames,
                    pending_error: Some(err),
                    rest: None,
                };
                return Response::from_parts(parts, PipeRespBody::Boxed(passthrough.boxed()));
            }
        }
    }

    // Separate trailers (if any) from data chunks; preserve uncompressed if tiny or trailers present.
    let has_trailers = frames.iter().any(http_body::Frame::is_trailers);
    if total_data_bytes < min_bytes || has_trailers {
        let passthrough = PrefixStreamBody {
            prefix: frames,
            pending_error: None,
            rest: None,
        };
        return Response::from_parts(parts, PipeRespBody::Boxed(passthrough.boxed()));
    }

    // Consume `frames` completely BEFORE any `.await` so no duplicate copy is held across the
    // compression permit wait. Single-frame bodies avoid copying altogether.
    let raw_bytes: Bytes =
        if frames.len() == 1 && frames.front().is_some_and(http_body::Frame::is_data) {
            frames
                .pop_front()
                .and_then(|f| f.into_data().ok())
                .unwrap_or_default()
        } else {
            let mut raw = Vec::with_capacity(total_data_bytes);
            while let Some(frame) = frames.pop_front() {
                if let Ok(data) = frame.into_data() {
                    raw.extend_from_slice(&data);
                }
            }
            Bytes::from(raw)
        };
    drop(frames);

    let raw_len = raw_bytes.len();
    let outcome = {
        #[cfg(test)]
        let force_fail =
            TEST_FORCE_BUFFERED_COMPRESS_FAIL.load(std::sync::atomic::Ordering::Acquire);
        #[cfg(not(test))]
        let force_fail = false;
        if force_fail {
            BufferedCompressOutcome::Failed
        } else if miraserve_static::inline_work_must_not_block()
            && raw_len > WORKER_LOOP_COMPRESS_CHUNK_BYTES
        {
            Box::pin(compress_buffered_on_worker_pool(
                buffered_enc,
                raw_bytes.clone(),
            ))
            .await
        } else {
            match compress_bytes(buffered_enc, &raw_bytes) {
                Ok(bytes) => BufferedCompressOutcome::Compressed(bytes),
                Err(_) => BufferedCompressOutcome::Failed,
            }
        }
    };

    match outcome {
        BufferedCompressOutcome::Compressed(compressed)
            if compressed.len() < raw_len || disallow_identity =>
        {
            parts.headers.insert(
                CONTENT_ENCODING,
                HeaderValue::from_static(buffered_enc.header_value()),
            );
            if let Ok(len_val) = HeaderValue::from_str(&compressed.len().to_string()) {
                parts.headers.insert(CONTENT_LENGTH, len_val);
            } else {
                parts.headers.remove(CONTENT_LENGTH);
            }
            weaken_etag_if_strong(&mut parts.headers);
            return Response::from_parts(parts, PipeRespBody::full(Bytes::from(compressed)));
        }
        BufferedCompressOutcome::BackpressureUncompressed => {
            if let Some(stream_enc) = decision.encoding_for(ProxyCompressPath::Saturated)
                && let Some(compressor) = StreamCompressor::new(stream_enc)
            {
                parts.headers.insert(
                    CONTENT_ENCODING,
                    HeaderValue::from_static(stream_enc.header_value()),
                );
                parts.headers.remove(CONTENT_LENGTH);
                weaken_etag_if_strong(&mut parts.headers);
                #[cfg(any(test, feature = "test-h2-hooks"))]
                TEST_YIELDING_STREAM_COMPRESS_COUNT
                    .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                return Response::from_parts(
                    parts,
                    PipeRespBody::Boxed(
                        YieldingStreamingCompressedBody::new(full_http_body(raw_bytes), compressor)
                            .boxed(),
                    ),
                );
            }
            // When identity is allowed, OR when identity is excluded but no incremental
            // streamable coding can be produced (e.g. zstd-only at saturation), preserve the
            // upstream response and send it uncompressed rather than replacing it with 406
            // (RFC 9110 §12.5.3 recommendation with exception, matching v0.1.4's streamed-path
            // fallback). `Vary: Accept-Encoding` is already set above.
        }
        BufferedCompressOutcome::Failed | BufferedCompressOutcome::Compressed(_) => {
            // Failed compression or expanded output with identity acceptable: return original
            // bytes uncompressed (`Vary: Accept-Encoding` is already set above).
        }
    }

    Response::from_parts(parts, PipeRespBody::full(raw_bytes))
}

#[cfg(test)]
async fn maybe_compress_proxied_response(
    req_accept_encoding: Option<&str>,
    req_method: &Method,
    resp: Response<HttpBody>,
) -> Response<HttpBody> {
    let out = match try_compress_proxied_response_sync(
        req_accept_encoding,
        req_method,
        resp.map(PipeRespBody::Boxed),
    ) {
        std::ops::ControlFlow::Break(done) => done,
        std::ops::ControlFlow::Continue((resp, decision, buffered_enc)) => {
            buffer_and_compress_proxied_response(resp, decision, buffered_enc).await
        }
    };
    out.map(PipeRespBody::into_http_body)
}

#[cfg(test)]
mod rewritten_target_tests {
    use super::{PathFlags, expand_redirect_target, rewritten_request_target};

    fn current() -> http::Uri {
        http::Uri::from_static("/alias?x=1")
    }

    /// Review 12, finding 1: the path and query every later step sees come from one parsed URI.
    #[test]
    fn path_and_query_come_from_the_parsed_target() {
        let rewritten =
            rewritten_request_target(&current(), "/staff/list?page=2", PathFlags::default());
        let Some((uri, canonical, flags)) = rewritten else {
            panic_free_fail("a plain target must be accepted");
            return;
        };
        assert_eq!(uri.path(), "/staff/list");
        assert_eq!(uri.query(), Some("page=2"));
        assert_eq!(canonical, uri.path());
        assert!(!flags.has_strict_fs_violation());
    }

    #[test]
    fn fragment_is_refused_instead_of_being_dropped() {
        assert!(
            rewritten_request_target(&current(), "/staff#overview", PathFlags::default()).is_none()
        );
    }

    /// The limits and traversal checks of a direct request apply to a rewritten one.
    #[test]
    fn direct_request_rules_apply() {
        let too_long = format!("/a/{}", "b".repeat(8_200));
        for bad in [
            too_long.as_str(),
            "/a/../b",
            "/a/..;x=1/b",
            "/a/%2e%2e/b",
            "/a/%2e%2e%3Bx/b",
            "/a\\b",
            "/a/%00",
            "relative",
        ] {
            assert!(
                rewritten_request_target(&current(), bad, PathFlags::default()).is_none(),
                "'{bad}' must be refused"
            );
        }
    }

    /// Review 12, finding 13: what was wrong with the visitor's own path stays wrong.
    #[test]
    fn strict_flags_of_the_original_path_are_kept() {
        let original = PathFlags {
            has_encoded_slash: true,
            has_malformed_percent: false,
            has_invalid_utf8: false,
        };
        let rewritten = rewritten_request_target(&current(), "/public/sub/n.txt", original);
        assert!(rewritten.is_some_and(|(_, _, flags)| flags.has_strict_fs_violation()));
    }

    /// Review 12, finding 4: one pass over the template, bounded output.
    #[test]
    fn redirect_expansion_is_single_pass_and_bounded() {
        assert_eq!(
            expand_redirect_target(
                "https://h.test/{rest}?{query}",
                "/s",
                "/s/{query}",
                Some("a={path}")
            ),
            Some("https://h.test/{query}?a={path}".to_owned())
        );
        assert_eq!(
            expand_redirect_target("/new/{rest}?{query}", "/old", "/old/a", None),
            Some("/new/a".to_owned())
        );
        assert_eq!(
            expand_redirect_target("https://h.test{uri}", "/", "/a/b", Some("x=1")),
            Some("https://h.test/a/b?x=1".to_owned())
        );
        let long = format!("/{}", "a".repeat(5_000));
        assert_eq!(
            expand_redirect_target("/x{path}{path}", "/", &long, None),
            None
        );
    }

    fn panic_free_fail(message: &str) {
        assert!(message.is_empty(), "{message}");
    }
}

#[cfg(test)]
mod rewrite_redirect_tests {
    use super::{expand_redirect_target, percent_encode_target};

    /// Codex review 36: an internal rewrite into a redirect route with a non-ASCII prefix keeps
    /// `{rest}` and an encoded Location.
    #[test]
    fn encoded_prefix_and_path_keep_the_redirect_suffix() {
        let loc = expand_redirect_target(
            "/new/{rest}",
            &percent_encode_target("/café", false),
            &percent_encode_target("/café/article one", false),
            None,
        );
        assert_eq!(loc.as_deref(), Some("/new/article%20one"));
    }
}

#[cfg(test)]
mod http80_router_tests {
    use std::sync::Arc;

    use http::header::HOST;
    use http::{Method, Request, StatusCode};
    use http_body_util::BodyExt as _;
    use miraserve_ai::AgentKeyRegistry;
    use miraserve_config::{LimitsConfig, parse_kdl};
    use miraserve_telemetry::TelemetryRegistry;
    use miraserve_tls::AcmeChallengeStore;

    use super::{CompiledRouter, empty_http_body};
    use crate::RequestContext;

    #[tokio::test]
    async fn has_http_serve_flag_and_oauth_resource_url_preserve_v012_over_https()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = Arc::new(AgentKeyRegistry::new());
        let (redir_cfg, _) = parse_kdl(
            "redir.kdl",
            r#"
server {
    listen "127.0.0.1:8443" protocols="h1"
    listen "127.0.0.1:8080" redirect-https=#true
}
site "panel.example" {
    route "/mcp/*" {
        mcp-gateway upstream="http://127.0.0.1:9" {
            oauth-resource-metadata #true
            jwks-url "https://auth.example.test/.well-known/jwks.json"
            jwt-issuer "https://auth.example.test"
            jwt-audience "https://panel.example"
            allow-tools "docs_search"
            audit-log "off"
        }
    }
}
site "::1" {
    route "/mcp/*" {
        mcp-gateway upstream="http://127.0.0.1:9" {
            oauth-resource-metadata #true
            jwks-url "https://auth.example.test/.well-known/jwks.json"
            jwt-issuer "https://auth.example.test"
            jwt-audience "https://::1"
            allow-tools "docs_search"
            audit-log "off"
        }
    }
}
"#,
        )?;
        let redir_router = CompiledRouter::compile(&redir_cfg, &registry)?;
        assert!(
            !redir_router.has_http_serve_site(),
            "all-redirect configuration must set has_http_serve_site = false"
        );

        let (serve_cfg, _) = parse_kdl(
            "serve.kdl",
            r#"
server {
    listen "127.0.0.1:8443" protocols="h1"
    listen "127.0.0.1:8080" redirect-https=#true
}
site "panel.example" {
    http "serve"
    route "/mcp/*" {
        mcp-gateway upstream="http://127.0.0.1:9" {
            oauth-resource-metadata #true
            jwks-url "https://auth.example.test/.well-known/jwks.json"
            jwt-issuer "https://auth.example.test"
            jwt-audience "https://panel.example"
            allow-tools "docs_search"
            audit-log "off"
        }
    }
}
site "::1" {
    http "serve"
    route "/mcp/*" {
        mcp-gateway upstream="http://127.0.0.1:9" {
            oauth-resource-metadata #true
            jwks-url "https://auth.example.test/.well-known/jwks.json"
            jwt-issuer "https://auth.example.test"
            jwt-audience "https://::1"
            allow-tools "docs_search"
            audit-log "off"
        }
    }
}
"#,
        )?;
        let serve_router = CompiledRouter::compile(&serve_cfg, &registry)?;
        assert!(
            serve_router.has_http_serve_site(),
            "configuration with http \"serve\" must set has_http_serve_site = true"
        );

        let limits = LimitsConfig::default();
        let acme = AcmeChallengeStore::new();
        let telemetry = TelemetryRegistry::new();

        // HTTPS: exact v0.1.2 `resource` URL (omits non-default port and does not bracket IPv6).
        let https_ctx = RequestContext {
            client_ip: None,
            remote_port: None,
            server_addr: None,
            server_port: 8443,
            is_https: true,
            tls: None,
        };
        for (host_hdr, expected_resource) in [
            (
                "panel.example:8443",
                "\"resource\":\"https://panel.example\"",
            ),
            ("[::1]:8443", "\"resource\":\"https://::1\""),
        ] {
            let req = Request::builder()
                .method(Method::GET)
                .uri("/.well-known/oauth-protected-resource")
                .header(HOST, host_hdr)
                .body(empty_http_body())?;
            let resp = serve_router
                .dispatch(req, &https_ctx, &limits, &acme, None, &telemetry)
                .await;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = resp.into_body().collect().await?.to_bytes();
            let text = std::str::from_utf8(&body)?;
            assert!(
                text.contains(expected_resource),
                "HTTPS host {host_hdr}: expected {expected_resource} in {text}"
            );
        }

        // Plain HTTP: keeps non-default port and brackets IPv6 literals; omits default port 80.
        let http_ctx = RequestContext {
            client_ip: None,
            remote_port: None,
            server_addr: None,
            server_port: 8080,
            is_https: false,
            tls: None,
        };
        for (host_hdr, expected_resource) in [
            (
                "panel.example:8080",
                "\"resource\":\"http://panel.example:8080\"",
            ),
            ("panel.example:80", "\"resource\":\"http://panel.example\""),
            ("[::1]:8080", "\"resource\":\"http://[::1]:8080\""),
            ("[::1]:80", "\"resource\":\"http://[::1]\""),
        ] {
            let req = Request::builder()
                .method(Method::GET)
                .uri("/.well-known/oauth-protected-resource")
                .header(HOST, host_hdr)
                .body(empty_http_body())?;
            let resp = serve_router
                .dispatch(req, &http_ctx, &limits, &acme, None, &telemetry)
                .await;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = resp.into_body().collect().await?.to_bytes();
            let text = std::str::from_utf8(&body)?;
            assert!(
                text.contains(expected_resource),
                "plain HTTP host {host_hdr}: expected {expected_resource} in {text}"
            );
        }

        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn site_lookup_map_matches_linear_scan_on_generated_set()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::borrow::Cow;
        use std::str::FromStr as _;

        use miraserve_config::normalize_site_host;

        use super::{canonical_host_for_site, extract_request_host};

        fn legacy_normalize_site_host(host: &str) -> String {
            let trimmed = host.trim();
            let unbracketed = trimmed
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .unwrap_or(trimmed);
            if let Ok(v6) = std::net::Ipv6Addr::from_str(unbracketed) {
                return v6.to_string();
            }
            trimmed.to_ascii_lowercase()
        }

        fn legacy_canonical_host_for_site(
            site: &super::CompiledSite,
            req_host: Option<&str>,
        ) -> String {
            if let Some(raw) = req_host {
                let lower = raw.to_ascii_lowercase();
                if let Some(exact) = site.hosts.iter().find(|h| **h == lower) {
                    return exact.clone();
                }
                if miraserve_security::is_valid_rfc3986_host_port(&lower) {
                    return lower;
                }
            }
            site.hosts
                .first()
                .map_or_else(|| "localhost".to_owned(), Clone::clone)
        }

        fn build_router(
            registry: &Arc<AgentKeyRegistry>,
            site_host_lists: &[Vec<String>],
        ) -> Result<CompiledRouter, Box<dyn std::error::Error>> {
            let (mut cfg, _) = parse_kdl(
                "template.kdl",
                r#"
server {
    listen "127.0.0.1:8443"
}
site "template.example" {
    route "/" {
        redirect "https://example.com/"
    }
}
"#,
            )?;
            let template = cfg
                .sites
                .pop()
                .ok_or_else(|| std::io::Error::other("missing template site"))?;
            for hosts in site_host_lists {
                let mut site = template.clone();
                site.hosts.clone_from(hosts);
                cfg.sites.push(site);
            }
            Ok(CompiledRouter::compile(&cfg, registry)?)
        }

        let registry = Arc::new(AgentKeyRegistry::new());

        // Build configs covering: 0 sites, 1 site (loopback fallback), and multi-site with
        // duplicates across sites (first wins), wildcards before/after exact, IPv6 literals,
        // and generated aliases.
        let mut multi_sites: Vec<Vec<String>> = vec![
            vec![
                "*.example.com".to_owned(),
                "First.Example.ORG".to_owned(),
                "dup.test".to_owned(),
            ],
            vec![
                "api.example.com".to_owned(),
                "dup.test".to_owned(),
                "*.example.com".to_owned(),
            ],
            vec![
                "[2001:DB8:0:0::1]".to_owned(),
                "::1".to_owned(),
                "127.0.0.2".to_owned(),
                "*.sub.example.com".to_owned(),
            ],
            vec![
                "2001:db8::1".to_owned(),
                "*.sub.example.com".to_owned(),
                "a.sub.example.com".to_owned(),
            ],
            vec![
                "*.dup-wild.test".to_owned(),
                "exact-late.dup-wild.test".to_owned(),
            ],
            vec![
                "*.dup-wild.test".to_owned(),
                "exact-late.dup-wild.test".to_owned(),
            ],
        ];
        for i in 0..16_u32 {
            multi_sites.push(vec![format!("s{i}.gen.test"), format!("*.w{i}.gen.test")]);
        }

        let configs: Vec<Vec<Vec<String>>> = vec![
            vec![],
            vec![vec!["solo.example.com".to_owned()]],
            vec![vec!["*.solo.example.com".to_owned()]],
            vec![vec!["[2001:db8::9]".to_owned()]],
            multi_sites,
        ];

        // Candidate raw hosts and HTTP Host header values (including ports, IPv6, mixed case,
        // wildcards, duplicates, whitespace, malformed, and deterministic PRNG-generated names).
        let mut raw_queries: Vec<Option<String>> = vec![
            None,
            Some(String::new()),
            Some("localhost".to_owned()),
            Some("LOCALHOST".to_owned()),
            Some(" 127.0.0.1 ".to_owned()),
            Some("::1".to_owned()),
            Some("[::1]".to_owned()),
            Some("[0:0:0:0:0:0:0:1]".to_owned()),
            Some("2001:db8::1".to_owned()),
            Some("[2001:DB8:0:0::1]".to_owned()),
            Some("2001:0db8:0000:0000::1".to_owned()),
            Some("[::ffff:192.0.2.128]".to_owned()),
            Some("[::ffff:c000:0280]".to_owned()),
            Some("solo.example.com".to_owned()),
            Some("SOLO.Example.COM".to_owned()),
            Some("sub.solo.example.com".to_owned()),
            Some("a.b.solo.example.com".to_owned()),
            Some("api.example.com".to_owned()),
            Some("API.EXAMPLE.COM".to_owned()),
            Some("other.example.com".to_owned()),
            Some("OTHER.example.com".to_owned()),
            Some("a.b.example.com".to_owned()),
            Some("a.sub.example.com".to_owned()),
            Some("z.sub.example.com".to_owned()),
            Some("*.example.com".to_owned()),
            Some("*.EXAMPLE.COM".to_owned()),
            Some(".example.com".to_owned()),
            Some("dup.test".to_owned()),
            Some("DUP.TEST".to_owned()),
            Some("first.example.org".to_owned()),
            Some("  FIRST.EXAMPLE.ORG  ".to_owned()),
            Some("x.dup-wild.test".to_owned()),
            Some("exact-late.dup-wild.test".to_owned()),
            Some("example.com:8443".to_owned()),
            Some("api.example.com:443".to_owned()),
            Some("[::1]:8443".to_owned()),
            Some("unknown.test".to_owned()),
            Some("[not-an-ip]".to_owned()),
            Some("[NOT-AN-IP]".to_owned()),
        ];

        // Deterministic xorshift64 generator for extra subdomains, ports, and case permutations.
        let mut seed: u64 = 0x5EED_CAFE_1234_5678;
        let mut next_u64 = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let bases = [
            "example.com",
            "sub.example.com",
            "dup.test",
            "dup-wild.test",
            "w0.gen.test",
            "w7.gen.test",
            "w15.gen.test",
            "gen.test",
            "unknown.invalid",
        ];
        for _ in 0..200 {
            let label_idx = next_u64() % 24;
            let base = bases
                .get(usize::try_from(next_u64() % (bases.len() as u64))?)
                .copied()
                .unwrap_or("example.com");
            let mut candidate = match next_u64() % 4 {
                0 => format!("s{label_idx}.{base}"),
                1 => format!("sub{label_idx}.{base}"),
                2 => format!("a.b{label_idx}.{base}"),
                _ => format!("s{label_idx}.{base}:8443"),
            };
            if next_u64() % 2 == 0 {
                candidate = candidate.to_ascii_uppercase();
            }
            raw_queries.push(Some(candidate));
        }

        // Also exercise HTTP Host headers with ports and IPv6 literals via `extract_request_host`.
        for host_hdr in [
            "api.example.com:8443",
            "API.EXAMPLE.COM:443",
            "sub.example.com:8080",
            "[2001:DB8::1]:8443",
            "[::1]:80",
            "localhost:8443",
            "127.0.0.1:443",
            "dup.test:8443",
        ] {
            let req = Request::builder()
                .method(Method::GET)
                .uri("/")
                .header(HOST, host_hdr)
                .body(empty_http_body())?;
            raw_queries.push(extract_request_host(&req));
        }

        // Verify `normalize_site_host` matches legacy on every input and borrows canonical forms.
        for query in raw_queries.iter().flatten() {
            let got = normalize_site_host(query);
            let want = legacy_normalize_site_host(query);
            assert_eq!(
                got.as_ref(),
                want,
                "normalize_site_host mismatch for {query:?}"
            );
        }
        assert!(matches!(
            normalize_site_host("example.com"),
            Cow::Borrowed("example.com")
        ));
        assert!(matches!(
            normalize_site_host("  example.com "),
            Cow::Borrowed("example.com")
        ));
        assert!(matches!(normalize_site_host("::1"), Cow::Borrowed("::1")));
        assert!(matches!(normalize_site_host("[::1]"), Cow::Borrowed("::1")));
        assert!(matches!(
            normalize_site_host("2001:db8::1"),
            Cow::Borrowed("2001:db8::1")
        ));
        assert!(matches!(normalize_site_host("Example.COM"), Cow::Owned(_)));
        assert!(matches!(
            normalize_site_host("[2001:DB8:0:0::1]"),
            Cow::Owned(_)
        ));

        // Verify map lookup == linear scan across every config and every query.
        for sites in &configs {
            let router = build_router(&registry, sites)?;
            for query in &raw_queries {
                let map_res = router.match_site_indexed(query.as_deref()).map(|(i, _)| i);
                let lin_res = router
                    .match_site_indexed_linear(query.as_deref())
                    .map(|(i, _)| i);
                assert_eq!(
                    map_res,
                    lin_res,
                    "map vs linear mismatch for query={query:?} with {} sites",
                    router.sites.len()
                );
                if let Some((idx, site)) = router.match_site_indexed(query.as_deref()) {
                    assert_eq!(Some(idx), lin_res);
                    let got_canon = canonical_host_for_site(site, query.as_deref());
                    let want_canon = legacy_canonical_host_for_site(site, query.as_deref());
                    assert_eq!(
                        got_canon.as_ref(),
                        want_canon,
                        "canonical_host_for_site mismatch for query={query:?}"
                    );
                }
            }
            // Spot-check Cow::Borrowed vs Cow::Owned on `canonical_host_for_site`.
            if let Some(site) = router.sites.first() {
                let first_host = site.hosts.first().map(String::as_str);
                if let Some(h) = first_host {
                    assert!(matches!(
                        canonical_host_for_site(site, Some(h)),
                        Cow::Borrowed(_)
                    ));
                    assert!(matches!(
                        canonical_host_for_site(site, Some(&h.to_ascii_uppercase())),
                        Cow::Borrowed(_)
                    ));
                }
                assert!(matches!(
                    canonical_host_for_site(site, None),
                    Cow::Borrowed(_)
                ));
                assert!(matches!(
                    canonical_host_for_site(site, Some("sub.example.com")),
                    Cow::Borrowed("sub.example.com")
                ));
                assert!(matches!(
                    canonical_host_for_site(site, Some("SUB.EXAMPLE.COM")),
                    Cow::Owned(ref s) if s == "sub.example.com"
                ));
            }
        }

        // Verify explicit first-match-wins on duplicates & exact-over-wildcard.
        let dup_router = build_router(
            &registry,
            &[
                vec!["*.example.com".to_owned(), "dup.example".to_owned()],
                vec![
                    "api.example.com".to_owned(),
                    "dup.example".to_owned(),
                    "*.example.com".to_owned(),
                ],
            ],
        )?;
        assert_eq!(
            dup_router
                .match_site_indexed(Some("dup.example"))
                .map(|(i, _)| i),
            Some(0)
        );
        assert_eq!(
            dup_router
                .match_site_indexed(Some("api.example.com"))
                .map(|(i, _)| i),
            Some(1)
        );
        assert_eq!(
            dup_router
                .match_site_indexed(Some("foo.example.com"))
                .map(|(i, _)| i),
            Some(0)
        );

        Ok(())
    }

    #[tokio::test]
    async fn sni_host_reuse_preserves_421_and_same_site_matching()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = Arc::new(AgentKeyRegistry::new());
        let (cfg, _) = parse_kdl(
            "sni.kdl",
            r#"
server {
    listen "127.0.0.1:8443"
}
site "a.example" "alias.example" {
    route "/ok" {
        redirect "https://a.example/dest"
    }
}
site "b.example" {
    route "/ok" {
        redirect "https://b.example/dest"
    }
}
"#,
        )?;
        let router = CompiledRouter::compile(&cfg, &registry)?;
        let limits = LimitsConfig::default();
        let acme = AcmeChallengeStore::new();
        let telemetry = TelemetryRegistry::new();

        let make_ctx = |sni: Option<&str>| RequestContext {
            client_ip: None,
            remote_port: None,
            server_addr: None,
            server_port: 443,
            is_https: true,
            tls: Some(crate::TlsConnectionInfo {
                sni: sni.map(Arc::from),
                is_tls13: true,
                is_pqc: false,
                verified_client_cert_dn: None,
                peer_cert_chain_der: None,
            }),
        };

        // Matching Host and SNI (exact, case-variant, alias) reach site 0 (404, not 421).
        for (host, sni) in [
            ("a.example", "a.example"),
            ("A.EXAMPLE", "a.example"),
            ("a.example", "ALIAS.EXAMPLE"),
        ] {
            let req = Request::builder()
                .method(Method::GET)
                .uri("/")
                .header(HOST, host)
                .body(empty_http_body())?;
            let resp = router
                .dispatch(req, &make_ctx(Some(sni)), &limits, &acme, None, &telemetry)
                .await;
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "host={host} sni={sni}"
            );
        }

        // Cross-site SNI/Host mismatch returns 421.
        let req = Request::builder()
            .method(Method::GET)
            .uri("/")
            .header(HOST, "a.example")
            .body(empty_http_body())?;
        let resp = router
            .dispatch(
                req,
                &make_ctx(Some("b.example")),
                &limits,
                &acme,
                None,
                &telemetry,
            )
            .await;
        assert_eq!(resp.status(), StatusCode::MISDIRECTED_REQUEST);

        // Unmatched Host with matching or mismatched SNI both return 421.
        for sni in ["unknown.example", "a.example"] {
            let req = Request::builder()
                .method(Method::GET)
                .uri("/")
                .header(HOST, "unknown.example")
                .body(empty_http_body())?;
            let resp = router
                .dispatch(req, &make_ctx(Some(sni)), &limits, &acme, None, &telemetry)
                .await;
            assert_eq!(resp.status(), StatusCode::MISDIRECTED_REQUEST, "sni={sni}");
        }

        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn canonicalize_request_path_borrows_clean_paths_and_matches_legacy_reference() {
        use super::{
            PathFlags, canonicalize_request_path_with_flags, contains_overlong_or_surrogate_utf8,
            hex_digit,
        };
        use std::borrow::Cow;

        fn legacy_canonicalize(raw_path: &str) -> Option<(String, PathFlags)> {
            let bytes = raw_path.as_bytes();
            let mut decoded_bytes = Vec::with_capacity(bytes.len());
            let mut flags = PathFlags::default();
            let mut i = 0_usize;
            while let Some(&b) = bytes.get(i) {
                if b == b'%' {
                    if matches!(bytes.get(i.saturating_add(1)), Some(b'u' | b'U'))
                        && bytes
                            .get(i.saturating_add(2)..i.saturating_add(6))
                            .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
                    {
                        return None;
                    }
                    if let (Some(&h1), Some(&h2)) = (
                        bytes.get(i.saturating_add(1)),
                        bytes.get(i.saturating_add(2)),
                    ) && let (Some(hi), Some(lo)) = (hex_digit(h1), hex_digit(h2))
                    {
                        let ch = (hi << 4) | lo;
                        if ch == b'/' {
                            flags.has_encoded_slash = true;
                        }
                        decoded_bytes.push(ch);
                        i = i.saturating_add(3);
                    } else {
                        flags.has_malformed_percent = true;
                        decoded_bytes.push(b);
                        i = i.saturating_add(1);
                    }
                } else {
                    decoded_bytes.push(b);
                    i = i.saturating_add(1);
                }
            }
            if contains_overlong_or_surrogate_utf8(&decoded_bytes) {
                return None;
            }
            if decoded_bytes.contains(&0x00)
                || decoded_bytes.contains(&b'\\')
                || decoded_bytes
                    .split(|&b| b == b'/')
                    .any(|seg| seg == b"." || seg == b"..")
            {
                return None;
            }
            let decoded = match String::from_utf8(decoded_bytes) {
                Ok(s) => s,
                Err(err) => {
                    flags.has_invalid_utf8 = true;
                    String::from_utf8_lossy(err.as_bytes()).into_owned()
                }
            };
            let trailing_slash = decoded.ends_with('/');
            let mut parts: Vec<&str> = Vec::new();
            for seg in decoded.split('/') {
                if seg.is_empty() {
                    continue;
                }
                if seg == "." || seg == ".." {
                    return None;
                }
                parts.push(seg);
            }
            if parts.is_empty() {
                return Some(("/".to_owned(), flags));
            }
            let mut out = String::with_capacity(decoded.len() + 1);
            for seg in parts {
                out.push('/');
                out.push_str(seg);
            }
            if trailing_slash {
                out.push('/');
            }
            Some((out, flags))
        }

        let cases = [
            "",
            "/",
            "//",
            "///",
            "/1k.txt",
            "/a/b/c",
            "/a/b/c/",
            "/.well-known/acme-challenge/abc123",
            "relative/path",
            "relative/path/",
            "/a//b///c",
            "//a/b//",
            "/hello%20world.txt",
            "/hello%20world//sub/",
            "/pkg%2Fname",
            "/pkg%2F%2Fname",
            "/bad%ZZpercent",
            "/trailing%",
            "/fichier%E9.pdf",
            "/caf\u{e9}/page.html",
            "/.",
            "/..",
            "/a/./b",
            "/a/../b",
            ".",
            "..",
            "/%2e/a",
            "/%2e%2e/a",
            "/%u002e%u002e/a",
            "/%U002F/a",
            "/a\\b",
            "/a%5cb",
            "/a\0b",
            "/a%00b",
            "/%C0%AF",
            "/%E0%80%AE",
            "/%ED%A0%80",
            "/%F0%80%80%AE",
        ];

        for raw in cases {
            let expected = legacy_canonicalize(raw);
            let actual = canonicalize_request_path_with_flags(raw);
            assert_eq!(
                actual.as_ref().map(|(p, f)| (
                    p.as_ref().to_owned(),
                    f.has_encoded_slash,
                    f.has_malformed_percent,
                    f.has_invalid_utf8
                )),
                expected.as_ref().map(|(p, f)| (
                    p.clone(),
                    f.has_encoded_slash,
                    f.has_malformed_percent,
                    f.has_invalid_utf8
                )),
                "mismatch for raw path {raw:?}"
            );
        }

        // Clean canonical paths and empty/root-only paths borrow without allocating.
        for clean in ["/", "/1k.txt", "/a/b/c/", "/.hidden/file.txt", "", "///"] {
            let res = canonicalize_request_path_with_flags(clean);
            assert!(
                matches!(res, Some((Cow::Borrowed(_), _))),
                "expected Cow::Borrowed for {clean:?}"
            );
        }
        for owned in ["/a//b", "rel/path", "/hello%20world.txt", "/pkg%2Fname"] {
            let res = canonicalize_request_path_with_flags(owned);
            assert!(
                matches!(res, Some((Cow::Owned(_), _))),
                "expected Cow::Owned for {owned:?}"
            );
        }
    }

    #[test]
    fn extension_matching_without_lowercasing_matches_legacy_reference() {
        use super::{RouteMatcher, is_forbidden_static_extension};
        use miraserve_config::{route_pattern_matches, split_extension_path_info};

        fn legacy_route_pattern_matches(pattern: &str, canonical_path: &str) -> bool {
            if pattern == "/*" {
                true
            } else if let Some(ext) = pattern.strip_prefix("*.") {
                let trimmed = canonical_path.trim_end_matches('/');
                !trimmed.is_empty()
                    && trimmed
                        .to_ascii_lowercase()
                        .ends_with(&format!(".{}", ext.to_ascii_lowercase()))
            } else if let Some(prefix) = pattern.strip_suffix("/*") {
                canonical_path == prefix
                    || canonical_path
                        .strip_prefix(prefix)
                        .is_some_and(|rest| rest.starts_with('/'))
            } else {
                canonical_path == pattern
            }
        }

        let paths = [
            "/",
            "/index.php",
            "/index.PHP",
            "/index.PhP/",
            "/index.PHP///",
            "/wp-admin/index.PHP/extra/path",
            "/.php",
            "/.PHP/info",
            "/php",
            "/caf\u{e9}.PHP",
            "/script.php?foo=bar",
            "/script.PHP/?foo=bar",
            "/app.phtml",
            "/style.css",
            "/dir/",
        ];
        let patterns = [
            "/*",
            "*.php",
            "*.PHP",
            "*.phtml",
            "*.css",
            "/wp-admin/*",
            "/index.php",
        ];
        for pat in patterns {
            let matcher = RouteMatcher::compile(pat);
            for path in paths {
                let expected = legacy_route_pattern_matches(pat, path);
                assert_eq!(
                    matcher.matches(path),
                    expected,
                    "RouteMatcher pat={pat} path={path}"
                );
                assert_eq!(
                    route_pattern_matches(pat, path),
                    expected,
                    "route_pattern_matches pat={pat} path={path}"
                );
            }
        }

        let forbidden = vec![".php".to_owned(), ".phtml".to_owned()];
        for path in paths {
            let legacy = {
                let check = |p: &str| {
                    let t = p.trim_end_matches('/').to_ascii_lowercase();
                    forbidden.iter().any(|ext| t.ends_with(ext))
                };
                check(path) || path.split_once('?').is_some_and(|(b, _)| check(b))
            };
            assert_eq!(
                is_forbidden_static_extension(path, &forbidden),
                legacy,
                "is_forbidden_static_extension path={path}"
            );
        }

        for ext in [".php", ".PHP", ".phtml", ""] {
            for path in paths {
                let legacy = if !path.starts_with('/') || ext.is_empty() {
                    None
                } else {
                    let mut out = None;
                    let bytes = path.as_bytes();
                    let mut seg_start = 1_usize;
                    while seg_start < bytes.len() {
                        let seg_end = bytes
                            .get(seg_start..)
                            .and_then(|r| r.iter().position(|&b| b == b'/'))
                            .map_or(bytes.len(), |rel| seg_start.saturating_add(rel));
                        if let Some(seg) = path.get(seg_start..seg_end)
                            && seg.len() > ext.len()
                            && !seg.starts_with('.')
                            && seg.to_ascii_lowercase().ends_with(ext)
                        {
                            out = path
                                .get(..seg_end)
                                .map(|s| (s, path.get(seg_end..).unwrap_or("")));
                            break;
                        }
                        seg_start = seg_end.saturating_add(1);
                    }
                    out
                };
                assert_eq!(
                    split_extension_path_info(path, ext),
                    legacy,
                    "split_extension_path_info path={path} ext={ext}"
                );
            }
        }
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn framing_and_path_rejections_preserve_status_and_strike_marker()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::CompiledRouter;
        use crate::{RequestContext, ServerFramingRejection, empty_http_body};
        use http::{
            Method, Request, StatusCode, Version,
            header::{CONTENT_LENGTH, HOST, TRANSFER_ENCODING},
        };
        use miraserve_ai::AgentKeyRegistry;
        use miraserve_config::{LimitsConfig, parse_kdl};
        use miraserve_telemetry::TelemetryRegistry;
        use miraserve_tls::AcmeChallengeStore;
        use std::sync::Arc;

        let dir =
            std::env::temp_dir().join(format!("miraserve-diet2-framing-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("ok.txt"), b"hello")?;
        let root_kdl = dir.display().to_string().replace('\\', "/");
        let kdl = format!(
            r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "example.test" {{
    root "{root_kdl}"
}}
"#
        );
        let (cfg, _) = parse_kdl("framing.kdl", &kdl)?;
        let router = CompiledRouter::compile(&cfg, &Arc::new(AgentKeyRegistry::default()))?;
        let limits = LimitsConfig::default();
        let acme = AcmeChallengeStore::new();
        let telemetry = TelemetryRegistry::new();
        let ctx = RequestContext {
            client_ip: Some("127.0.0.1".parse()?),
            remote_port: Some(45_000),
            server_addr: Some("127.0.0.1".parse()?),
            server_port: 8443,
            is_https: true,
            tls: None,
        };

        let overlong = format!("/{}", "a".repeat(8_192));
        let bad_cases: Vec<(Request<crate::HttpBody>, StatusCode, &str)> = vec![
            (
                Request::builder()
                    .method(Method::GET)
                    .uri(overlong.as_str())
                    .header(HOST, "example.test")
                    .body(empty_http_body())?,
                StatusCode::URI_TOO_LONG,
                "uri_too_long",
            ),
            (
                Request::builder()
                    .method(Method::GET)
                    .uri("/a/../b")
                    .header(HOST, "example.test")
                    .body(empty_http_body())?,
                StatusCode::BAD_REQUEST,
                "dot_segment",
            ),
            (
                Request::builder()
                    .method(Method::GET)
                    .uri("/%2e%2e/secret")
                    .header(HOST, "example.test")
                    .body(empty_http_body())?,
                StatusCode::BAD_REQUEST,
                "encoded_dot_segment",
            ),
            (
                Request::builder()
                    .method(Method::GET)
                    .uri("/%u002e%u002e/secret")
                    .header(HOST, "example.test")
                    .body(empty_http_body())?,
                StatusCode::BAD_REQUEST,
                "iis_unicode",
            ),
            (
                Request::builder()
                    .method(Method::GET)
                    .uri("/%C0%AF/overlong")
                    .header(HOST, "example.test")
                    .body(empty_http_body())?,
                StatusCode::BAD_REQUEST,
                "overlong_utf8",
            ),
            (
                Request::builder()
                    .method(Method::GET)
                    .uri("/pkg%2Fname")
                    .header(HOST, "example.test")
                    .body(empty_http_body())?,
                StatusCode::BAD_REQUEST,
                "encoded_slash_on_static",
            ),
            (
                Request::builder()
                    .method(Method::POST)
                    .uri("/ok.txt")
                    .header(HOST, "example.test")
                    .header(CONTENT_LENGTH, "5")
                    .header(TRANSFER_ENCODING, "chunked")
                    .body(empty_http_body())?,
                StatusCode::BAD_REQUEST,
                "cl_te_smuggle",
            ),
            (
                Request::builder()
                    .method(Method::POST)
                    .uri("/ok.txt")
                    .header(HOST, "example.test")
                    .header(CONTENT_LENGTH, "5")
                    .header(CONTENT_LENGTH, "5")
                    .body(empty_http_body())?,
                StatusCode::BAD_REQUEST,
                "duplicate_cl",
            ),
            (
                Request::builder()
                    .version(Version::HTTP_2)
                    .method(Method::POST)
                    .uri("https://example.test/ok.txt")
                    .header(TRANSFER_ENCODING, "chunked")
                    .body(empty_http_body())?,
                StatusCode::BAD_REQUEST,
                "h2_transfer_encoding",
            ),
        ];

        for (req, expected_status, label) in bad_cases {
            let resp = router
                .dispatch(req, &ctx, &limits, &acme, None, &telemetry)
                .await;
            assert_eq!(resp.status(), expected_status, "case={label}");
            assert!(
                resp.extensions().get::<ServerFramingRejection>().is_some(),
                "case={label} must carry ServerFramingRejection strike marker"
            );
        }

        // Valid request with query string succeeds via borrowed path/host/query path.
        let ok_req = Request::builder()
            .method(Method::GET)
            .uri("/ok.txt?v=1")
            .header(HOST, "EXAMPLE.TEST:8443")
            .body(empty_http_body())?;
        let ok_resp = router
            .dispatch(ok_req, &ctx, &limits, &acme, None, &telemetry)
            .await;
        assert_eq!(ok_resp.status(), StatusCode::OK);
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn fallback_header_lookup_skips_sites_without_route_headers_and_normalizes_dot_segments()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::{RouteMatcher, split_extension_path_info};
        use std::sync::atomic::Ordering;

        let base = std::env::temp_dir().join(format!(
            "miraserve-router-fb-lookup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        std::fs::create_dir_all(&base)?;
        std::fs::write(base.join("index.html"), b"<html>SHELL</html>")?;
        std::fs::write(base.join("version.json"), br#"{"v":1}"#)?;

        let root_str = base.to_string_lossy().replace('\\', "/");
        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:8443" protocols="h1"
}}
site "no-route-hdrs.example" {{
    root "{root_str}"
    headers {{
        set "x-site" "plain"
    }}
    route "*.php" {{
        fastcgi-pass "tcp://127.0.0.1:9"
    }}
    route "*.js" {{
        static
    }}
    route "/app/*" {{
        try-files "{{path}}" "/index.html"
    }}
}}
site "with-route-hdrs.example" {{
    root "{root_str}"
    headers {{
        set "x-site" "always"
    }}
    route "*.php" {{
        fastcgi-pass "tcp://127.0.0.1:9"
    }}
    route "*.css" {{
        static
    }}
    route "/version.json" {{
        static
        headers {{
            set "x-version" "matched"
        }}
    }}
    route "/app/*" {{
        try-files "{{path}}" "/./version.json"
        headers {{
            set "x-app" "must-not-leak"
        }}
    }}
}}
"#
        );
        let (cfg, _) = parse_kdl("fb_lookup.kdl", &kdl)?;
        let registry = Arc::new(AgentKeyRegistry::new());
        let router = CompiledRouter::compile(&cfg, &registry)?;
        assert!(
            !router.sites.first().is_some_and(|s| s.has_route_headers),
            "site without route headers must set has_route_headers = false"
        );
        assert!(
            router.sites.get(1).is_some_and(|s| s.has_route_headers),
            "site with route headers must set has_route_headers = true"
        );

        let limits = LimitsConfig::default();
        let acme = AcmeChallengeStore::new();
        let telemetry = TelemetryRegistry::new();
        let ctx = RequestContext {
            client_ip: None,
            remote_port: None,
            server_addr: None,
            server_port: 8443,
            is_https: true,
            tls: None,
        };

        // 1. Site with NO route headers: fallback runs zero header-owner lookups and still applies
        //    site-level headers.
        let req1 = Request::builder()
            .method(Method::GET)
            .uri("/app/missing")
            .header(HOST, "no-route-hdrs.example")
            .body(empty_http_body())?;
        let resp1 = router
            .dispatch(req1, &ctx, &limits, &acme, None, &telemetry)
            .await;
        assert_eq!(resp1.status(), StatusCode::OK);
        assert_eq!(
            resp1.headers().get("x-site").and_then(|v| v.to_str().ok()),
            Some("plain")
        );
        assert_eq!(
            router
                .sites
                .first()
                .map(|s| s.fallback_header_lookups.load(Ordering::Relaxed)),
            Some(0),
            "no fallback header lookup may run when no route of the site has headers rules"
        );

        // 2. Site WITH route headers: `/./version.json` normalizes identically to static resolution
        //    and finds `route "/version.json"`, applying its headers instead of `/app/*`'s.
        let req2 = Request::builder()
            .method(Method::GET)
            .uri("/app/missing")
            .header(HOST, "with-route-hdrs.example")
            .body(empty_http_body())?;
        let resp2 = router
            .dispatch(req2, &ctx, &limits, &acme, None, &telemetry)
            .await;
        assert_eq!(resp2.status(), StatusCode::OK);
        assert_eq!(
            resp2.headers().get("x-site").and_then(|v| v.to_str().ok()),
            Some("always")
        );
        assert_eq!(
            resp2
                .headers()
                .get("x-version")
                .and_then(|v| v.to_str().ok()),
            Some("matched")
        );
        assert!(resp2.headers().get("x-app").is_none());
        assert_eq!(
            router
                .sites
                .get(1)
                .map(|s| s.fallback_header_lookups.load(Ordering::Relaxed)),
            Some(1),
            "expected exactly one fallback header lookup when a route defines headers"
        );

        // 3. Case-insensitive extension matcher parity (without allocating).
        let ext_matcher = RouteMatcher::compile("*.JSON");
        assert!(ext_matcher.matches("/version.json"));
        assert!(ext_matcher.matches("/VERSION.JSON"));
        assert!(ext_matcher.matches("/dir/File.Json/"));
        assert!(!ext_matcher.matches("/version.jsonp"));
        assert_eq!(
            split_extension_path_info("/SUB/INDEX.PHP/info", ".php"),
            Some(("/SUB/INDEX.PHP", "/info"))
        );

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    #[tokio::test]
    async fn markdown_exhausted_conversion_slots_falls_back_to_html_with_request_headers()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::{CompiledRouter, markdown_semaphore};
        use crate::{RequestContext, empty_http_body};
        use http::{
            Method, Request, StatusCode,
            header::{ACCEPT, CONTENT_RANGE, CONTENT_TYPE, HOST, RANGE, VARY},
        };
        use http_body_util::BodyExt as _;
        use miraserve_ai::AgentKeyRegistry;
        use miraserve_config::{LimitsConfig, parse_kdl};
        use miraserve_telemetry::TelemetryRegistry;
        use miraserve_tls::AcmeChallengeStore;
        use std::sync::Arc;

        let dir = std::env::temp_dir().join(format!(
            "miraserve-md-slots-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("page.html"), b"<h1>Exhausted Slots</h1>")?;

        let root_str = dir.to_string_lossy().replace('\\', "/");
        let kdl = format!(
            r#"
server {{
    listen ":8443"
}}
site "md-slots.example" {{
    root "{root_str}"
}}
"#
        );
        let (cfg, _) = parse_kdl("md_slots.kdl", &kdl)?;
        let router = CompiledRouter::compile(&cfg, &Arc::new(AgentKeyRegistry::default()))?;
        let limits = LimitsConfig::default();
        let acme = AcmeChallengeStore::new();
        let telemetry = TelemetryRegistry::new();
        let ctx = RequestContext {
            client_ip: None,
            remote_port: None,
            server_addr: None,
            server_port: 8443,
            is_https: true,
            tls: None,
        };

        // Drain all conversion permits so the Markdown conversion slot check fails and static
        // serving falls back to the HTML file using the request's own headers (including Range).
        let sem = markdown_semaphore();
        let mut held = Vec::new();
        while let Ok(permit) = Arc::clone(sem).try_acquire_owned() {
            held.push(permit);
        }

        let req = Request::builder()
            .method(Method::GET)
            .uri("/page.html")
            .header(HOST, "md-slots.example")
            .header(ACCEPT, "text/markdown")
            .header(RANGE, "bytes=0-7")
            .body(empty_http_body())?;
        let resp = router
            .dispatch(req, &ctx, &limits, &acme, None, &telemetry)
            .await;
        drop(held);

        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
        assert_eq!(
            resp.headers()
                .get(CONTENT_RANGE)
                .and_then(|v| v.to_str().ok()),
            Some("bytes 0-7/24")
        );
        assert_eq!(
            resp.headers().get(VARY).and_then(|v| v.to_str().ok()),
            Some("Accept, Accept-Encoding")
        );
        let body = resp.into_body().collect().await?.to_bytes();
        assert_eq!(body.as_ref(), b"<h1>Exha");

        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// Finding 2: A non-read request carrying a Markdown preference (`POST /page.html` with
    /// `Accept: text/markdown`) on a site with a header-testing rewrite and a `CDN-Cache-Control`
    /// header rule MUST still pass through the shared `ProtectedResponse` post-processing:
    /// `405` with `Cache-Control: no-store` and no `CDN-Cache-Control` header (and likewise `404`
    /// for a forbidden static extension), matching the base boxed path on all platforms.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn markdown_preference_on_non_read_method_preserves_cache_protection()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::CompiledRouter;
        use crate::{RequestContext, empty_http_body};
        use http::{
            Method, Request, StatusCode,
            header::{ACCEPT, CACHE_CONTROL, HOST},
        };
        use miraserve_ai::AgentKeyRegistry;
        use miraserve_config::{LimitsConfig, parse_kdl};
        use miraserve_telemetry::TelemetryRegistry;
        use miraserve_tls::AcmeChallengeStore;
        use std::sync::Arc;

        let dir = std::env::temp_dir().join(format!(
            "miraserve-md-post-prot-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("page.html"), b"<h1>Page</h1>")?;

        let root_str = dir.to_string_lossy().replace('\\', "/");
        let kdl = format!(
            r#"
server {{
    listen ":8443"
}}
site "md-prot.example" {{
    root "{root_str}"
    rewrite {{
        rule "\\.md$" deny=403 header="X-Preview=^blocked$"
    }}
    headers {{
        set "Cache-Control" "public, max-age=300"
        set "CDN-Cache-Control" "public, max-age=300"
    }}
}}
"#
        );
        let (cfg, _) = parse_kdl("md_prot.kdl", &kdl)?;
        let router = CompiledRouter::compile(&cfg, &Arc::new(AgentKeyRegistry::default()))?;
        let limits = LimitsConfig::default();
        let acme = AcmeChallengeStore::new();
        let telemetry = TelemetryRegistry::new();
        let ctx = RequestContext {
            client_ip: None,
            remote_port: None,
            server_addr: None,
            server_port: 8443,
            is_https: true,
            tls: None,
        };

        // Control: POST /page.html WITHOUT Accept: text/markdown is not Markdown-negotiated,
        // so the site has no independent protection and CDN-Cache-Control stays.
        let ctrl_req = Request::builder()
            .method(Method::POST)
            .uri("/page.html")
            .header(HOST, "md-prot.example")
            .body(empty_http_body())?;
        let ctrl_resp = router
            .dispatch(ctrl_req, &ctx, &limits, &acme, None, &telemetry)
            .await;
        assert_eq!(ctrl_resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            ctrl_resp
                .headers()
                .get("cdn-cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("public, max-age=300"),
            "control without Markdown preference should retain CDN-Cache-Control"
        );

        // Regression case: POST /page.html WITH Accept: text/markdown must be marked
        // ProtectedResponse -> 405 with Cache-Control: no-store and CDN-Cache-Control stripped.
        let post_req = Request::builder()
            .method(Method::POST)
            .uri("/page.html")
            .header(HOST, "md-prot.example")
            .header(ACCEPT, "text/markdown")
            .body(empty_http_body())?;
        let post_resp = router
            .dispatch(post_req, &ctx, &limits, &acme, None, &telemetry)
            .await;
        assert_eq!(post_resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            post_resp
                .headers()
                .get(CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store"),
            "POST with Accept: text/markdown must enforce Cache-Control: no-store"
        );
        assert!(
            post_resp.headers().get("cdn-cache-control").is_none(),
            "POST with Accept: text/markdown must strip CDN-Cache-Control"
        );

        // Also verify forbidden static extension path goes through the exact same post-processing.
        let forb_req = Request::builder()
            .method(Method::POST)
            .uri("/secret.php")
            .header(HOST, "md-prot.example")
            .header(ACCEPT, "text/markdown")
            .body(empty_http_body())?;
        let forb_resp = router
            .dispatch(forb_req, &ctx, &limits, &acme, None, &telemetry)
            .await;
        assert_eq!(forb_resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            forb_resp
                .headers()
                .get(CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
        assert!(forb_resp.headers().get("cdn-cache-control").is_none());

        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}

// Linux and Android only: the file cache admits a response only when its file was selected by the
// link-free lookup, which exists on those platforms alone (see `miraserve-static`).
#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod file_cache_p1_3_tests {
    use super::{
        ACME_WEBROOT_PROBE_TEST_HOOK, AFTER_REWRITES_TEST_HOOK, ROUTER_ACME_PROBED_FS_SET,
        ROUTER_CACHE_LOOKUP_OR_ADMIT_CALLS, ROUTER_CACHE_SITE_BRANCH_HITS,
    };
    use crate::{CredentialSources, HttpEngine, RequestContext, empty_http_body};
    use http::header::HOST;
    use http::{Method, Request, StatusCode};
    use http_body_util::BodyExt as _;
    use miraserve_config::parse_kdl;
    use miraserve_static::ManualClock;
    use miraserve_tls::AcmeChallengeStore;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    static ROUTER_HOOK_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    static TEST_SEQ: AtomicU64 = AtomicU64::new(1);

    fn temp_dir(label: &str) -> Result<PathBuf, std::io::Error> {
        let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!(
            "miraserve-router-fc-{label}-{}-{seq}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    fn kdl_path(path: &Path) -> String {
        let raw = path.to_string_lossy();
        let stripped = raw.strip_prefix(r"\\?\").unwrap_or(&raw);
        stripped.replace('\\', "/")
    }

    fn req_ctx() -> RequestContext {
        RequestContext {
            client_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42))),
            remote_port: Some(50_000),
            server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            server_port: 8443,
            is_https: true,
            tls: None,
        }
    }

    struct ClearHooksGuard;
    impl Drop for ClearHooksGuard {
        fn drop(&mut self) {
            *ACME_WEBROOT_PROBE_TEST_HOOK
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
            *AFTER_REWRITES_TEST_HOOK
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        }
    }

    async fn fetch(
        engine: &HttpEngine,
        host: &str,
        uri: &str,
    ) -> Result<(StatusCode, Vec<u8>), Box<dyn std::error::Error>> {
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(HOST, host)
            .body(empty_http_body())?;
        let resp = engine.handle_request(req, &req_ctx()).await;
        let status = resp.status();
        let body = resp.into_body().collect().await?.to_bytes().to_vec();
        Ok((status, body))
    }

    /// Review round 2, P1-3: An ACME-token-shaped path whose delayed webroot probe runs
    /// (starting at 0 ms, returning at 120 ms on a 100 ms site) and misses before falling through
    /// to a static file or `try-files` fallback MUST NOT admit into the cache, while hits on
    /// already-cached entries remain unaffected and a newly installed ACME webroot token still
    /// takes precedence over static dispatch.
    #[cfg(unix)]
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn p1_3_acme_webroot_delayed_probe_miss_declines_admission_while_hits_and_acme_unaffected()
    -> TestResult {
        use std::os::unix::fs::PermissionsExt as _;

        let _lock = ROUTER_HOOK_TEST_LOCK.lock().await;
        let _clear = ClearHooksGuard;

        let base = temp_dir("p1-3-acme")?;
        let webroot = base.join("acme-webroot");
        let challenges = webroot.join(".well-known").join("acme-challenge");
        std::fs::create_dir_all(&challenges)?;
        std::fs::set_permissions(&challenges, std::fs::Permissions::from_mode(0o755))?;

        let root_static = base.join("static");
        let static_acme_dir = root_static.join(".well-known").join("acme-challenge");
        std::fs::create_dir_all(&static_acme_dir)?;
        let tok_miss = "TokMiss_01";
        let tok_warm = "TokWarm_02";
        std::fs::write(static_acme_dir.join(tok_miss), b"static-v1")?;
        std::fs::write(static_acme_dir.join(tok_warm), b"warm-v1")?;

        let root_tf = base.join("tryfiles");
        std::fs::create_dir_all(&root_tf)?;
        std::fs::write(root_tf.join("fallback.html"), b"tf-fallback-v1")?;

        let kdl = format!(
            r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
    acme-webroot "{webroot}"
}}
site "acme-static.example.test" {{
    root "{root_static}"
    file-cache "100ms"
    rewrite {{
        rule "^/warm-alias$" to="/.well-known/acme-challenge/{tok_warm}"
    }}
}}
site "acme-tf.example.test" {{
    root "{root_tf}"
    file-cache "100ms"
    route "/*" {{
        try-files "{{path}}" "/fallback.html"
    }}
}}
"#,
            webroot = kdl_path(&webroot),
            root_static = kdl_path(&root_static),
            root_tf = kdl_path(&root_tf),
        );
        let (cfg, _) = parse_kdl("acme-p1-3.kdl", &kdl)?;
        let clock = ManualClock::new();
        let engine = HttpEngine::from_config_with_file_cache_clock(
            &cfg,
            Arc::new(AcmeChallengeStore::new()),
            None,
            8443,
            CredentialSources::default(),
            clock.cache_clock(),
        )?;

        // Delay the ACME webroot probe by 120 ms (> 100 ms site window) so on b978f1c the
        // fallback would sample at 120 ms and admit until 220 ms.
        let delay_clock = clock.clone();
        *ACME_WEBROOT_PROBE_TEST_HOOK
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(move |host| {
            if host == "acme-static.example.test" {
                delay_clock.advance(Duration::from_millis(120));
            }
        }));

        // 1. Direct static fallthrough after delayed ACME webroot miss: serves 200 OK, MUST NOT
        //    admit!
        let uri_miss = format!("/.well-known/acme-challenge/{tok_miss}");
        let (st1, body1) = fetch(&engine, "acme-static.example.test", &uri_miss).await?;
        assert_eq!(st1, StatusCode::OK);
        assert_eq!(body1, b"static-v1");
        assert_eq!(
            engine.telemetry().file_cache_counts().2,
            0,
            "P1-3: direct static fallthrough after ACME webroot probe must NOT admit"
        );
        assert_eq!(engine.file_cache_budget_used(), 0);

        // Mutate disk at t=120ms and re-request (on b978f1c, a cached entry valid until 220ms
        // would serve stale "static-v1"): must see "static-v2" immediately!
        *ACME_WEBROOT_PROBE_TEST_HOOK
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        std::fs::write(static_acme_dir.join(tok_miss), b"static-v2")?;
        let (st2, body2) = fetch(&engine, "acme-static.example.test", &uri_miss).await?;
        assert_eq!(st2, StatusCode::OK);
        assert_eq!(body2, b"static-v2");
        assert_eq!(engine.telemetry().file_cache_counts().2, 0);

        // 2. Try-files fallthrough after delayed ACME webroot miss: serves 200 OK, MUST NOT admit!
        let delay_clock2 = clock.clone();
        *ACME_WEBROOT_PROBE_TEST_HOOK
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(move |host| {
            if host == "acme-tf.example.test" {
                delay_clock2.advance(Duration::from_millis(120));
            }
        }));
        let (st_tf, body_tf) = fetch(&engine, "acme-tf.example.test", &uri_miss).await?;
        assert_eq!(st_tf, StatusCode::OK);
        assert_eq!(body_tf, b"tf-fallback-v1");
        assert_eq!(
            engine.telemetry().file_cache_counts().2,
            0,
            "P1-3: try-files fallthrough after ACME webroot probe must NOT admit"
        );
        *ACME_WEBROOT_PROBE_TEST_HOOK
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;

        // 3. Hits remain unaffected: warm `/.well-known/acme-challenge/TokWarm_02` via a non-ACME
        //    internal rewrite (`/warm-alias`), mutate disk, then request the ACME path directly
        //    (webroot misses -> falls through -> MUST still hit the fresh cached entry!).
        let (st_warm, body_warm) =
            fetch(&engine, "acme-static.example.test", "/warm-alias").await?;
        assert_eq!(st_warm, StatusCode::OK);
        assert_eq!(body_warm, b"warm-v1");
        assert_eq!(engine.telemetry().file_cache_counts().2, 1);

        std::fs::write(static_acme_dir.join(tok_warm), b"warm-v2")?;
        clock.advance(Duration::from_millis(10));
        let uri_warm = format!("/.well-known/acme-challenge/{tok_warm}");
        let (st_hit, body_hit) = fetch(&engine, "acme-static.example.test", &uri_warm).await?;
        assert_eq!(st_hit, StatusCode::OK);
        assert_eq!(
            body_hit, b"warm-v1",
            "P1-3: ACME webroot miss must leave fresh cache hits unaffected"
        );
        assert_eq!(engine.telemetry().file_cache_counts().0, 1);

        // 4. Installing a real ACME token file in the webroot still wins before static dispatch!
        let key_auth = format!("{tok_warm}.AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdE");
        let tok_file = challenges.join(tok_warm);
        std::fs::write(&tok_file, format!("{key_auth}\n"))?;
        std::fs::set_permissions(&tok_file, std::fs::Permissions::from_mode(0o644))?;
        let (st_acme, body_acme) = fetch(&engine, "acme-static.example.test", &uri_warm).await?;
        assert_eq!(st_acme, StatusCode::OK);
        assert_eq!(
            body_acme,
            key_auth.as_bytes(),
            "P1-3: newly installed ACME webroot token must still answer before static dispatch"
        );

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    /// Guard test (this precedence invariant already held on `b978f1c`, while the
    /// `b978f1c`-failing regression test for P1-3 is
    /// `p1_3_acme_webroot_delayed_probe_miss_declines_admission_while_hits_and_acme_unaffected`):
    /// where two fill timestamps exist (a site with BOTH filesystem rewrites AND a FastCGI index
    /// probe), the earlier pre-rewrite sample MUST win over the later index-probe sample.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn p1_3_filesystem_rewrite_plus_fastcgi_index_probe_keeps_earlier_sample() -> TestResult {
        let _lock = ROUTER_HOOK_TEST_LOCK.lock().await;
        let _clear = ClearHooksGuard;

        let base = temp_dir("p1-3-rw-fcgi")?;
        let root = base.join("root");
        let sub = root.join("sub");
        std::fs::create_dir_all(&sub)?;
        std::fs::write(sub.join("index.html"), b"index-v1")?;

        let kdl = format!(
            r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "rw-fcgi.example.test" {{
    root "{root}"
    index "index.php" "index.html"
    file-cache "100ms"
    rewrite {{
        rule "^/go$" to="/sub/" if-not-file=#true
    }}
    route "*.php" {{
        fastcgi-pass "127.0.0.1:9000"
    }}
}}
"#,
            root = kdl_path(&root)
        );
        let (cfg, _) = parse_kdl("rw-fcgi.kdl", &kdl)?;
        let clock = ManualClock::new();
        let engine = HttpEngine::from_config_with_file_cache_clock(
            &cfg,
            Arc::new(AcmeChallengeStore::new()),
            None,
            8443,
            CredentialSources::default(),
            clock.cache_clock(),
        )?;

        // Part 1: Rewrite samples at t = 0 ms (deadline = 100 ms), then advance clock by 60 ms
        // before FastCGI index probe runs at t = 60 ms (whose second sample would expire at
        // 160 ms if it replaced the first!).
        let hook_clock = clock.clone();
        *AFTER_REWRITES_TEST_HOOK
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(move |host| {
            if host == "rw-fcgi.example.test" {
                hook_clock.advance(Duration::from_millis(60));
            }
        }));

        let (st1, body1) = fetch(&engine, "rw-fcgi.example.test", "/go").await?;
        assert_eq!(st1, StatusCode::OK);
        assert_eq!(body1, b"index-v1");
        assert_eq!(engine.telemetry().file_cache_counts().2, 1);

        // Clear hook and mutate `/sub/index.html` to "index-v2".
        *AFTER_REWRITES_TEST_HOOK
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        std::fs::write(sub.join("index.html"), b"index-v2")?;

        // At t = 99 ms (39 ms after t = 60 ms): still inside the 0 ms + 100 ms = 100 ms deadline.
        clock.advance(Duration::from_millis(39));
        let (st_hit, body_hit) = fetch(&engine, "rw-fcgi.example.test", "/sub/").await?;
        assert_eq!(st_hit, StatusCode::OK);
        assert_eq!(body_hit, b"index-v1");
        assert_eq!(engine.telemetry().file_cache_counts().0, 1);

        // At t = 100 ms (NOT 160 ms!): entry MUST be expired and serve "index-v2"!
        clock.advance(Duration::from_millis(1));
        let (st_exp, body_exp) = fetch(&engine, "rw-fcgi.example.test", "/sub/").await?;
        assert_eq!(st_exp, StatusCode::OK);
        assert_eq!(
            body_exp, b"index-v2",
            "P1-3: earlier pre-rewrite sample (0ms -> 100ms) must win over later FastCGI index sample (60ms -> 160ms)"
        );

        // Part 2: Rewrite takes 120 ms (> 100 ms window) before FastCGI index probe -> MUST NOT
        // admit even though the later FastCGI probe would sample at t = 220 ms!
        clock.advance(Duration::from_millis(100)); // t = 200 ms (expire /sub/ refill)
        let fills_before = engine.telemetry().file_cache_counts().2;
        let slow_clock = clock.clone();
        *AFTER_REWRITES_TEST_HOOK
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(move |host| {
            if host == "rw-fcgi.example.test" {
                slow_clock.advance(Duration::from_millis(120));
            }
        }));
        let (st_slow, _) = fetch(&engine, "rw-fcgi.example.test", "/go").await?;
        assert_eq!(st_slow, StatusCode::OK);
        assert_eq!(
            engine.telemetry().file_cache_counts().2,
            fills_before,
            "P1-3: when earlier pre-rewrite sample already expired, later index probe must NOT admit"
        );

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    /// Review round 3, Cache-off rule: running a request set (static file, FastCGI site static
    /// hit, `try-files` route, and an ACME-shaped path that misses the configured webroot)
    /// against a cache-less server MUST record ZERO cache-clock reads and ZERO calls into cache
    /// lookup or admission, both on an all-off engine and on a cache-less site sharing a mixed
    /// engine with a cache-enabled site.
    #[cfg(unix)]
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn r3_cache_off_request_set_zero_clock_reads_and_zero_cache_calls() -> TestResult {
        use std::os::unix::fs::PermissionsExt as _;
        use std::sync::atomic::AtomicUsize;

        let _lock = ROUTER_HOOK_TEST_LOCK.lock().await;
        let _clear = ClearHooksGuard;

        let base = temp_dir("r3-cache-off-zero")?;
        let webroot = base.join("acme-webroot");
        let challenges = webroot.join(".well-known").join("acme-challenge");
        std::fs::create_dir_all(&challenges)?;
        std::fs::set_permissions(&challenges, std::fs::Permissions::from_mode(0o755))?;

        let off_root = base.join("off-root");
        let off_sub = off_root.join("sub");
        let off_spa = off_root.join("spa_root");
        let off_acme_dir = off_root.join(".well-known").join("acme-challenge");
        std::fs::create_dir_all(&off_sub)?;
        std::fs::create_dir_all(&off_spa)?;
        std::fs::create_dir_all(&off_acme_dir)?;

        let tok_miss = "TokOffMiss_0123456789abcdef";
        std::fs::write(off_root.join("plain.txt"), b"plain-off-body")?;
        std::fs::write(off_root.join("style.css"), b"body { color: black; }")?;
        std::fs::write(off_sub.join("index.html"), b"<h1>sub-index-off</h1>")?;
        std::fs::write(off_spa.join("index.html"), b"<h1>spa-fallback-off</h1>")?;
        std::fs::write(off_acme_dir.join(tok_miss), b"acme-fallthrough-off")?;

        let on_root = base.join("on-root");
        std::fs::create_dir_all(&on_root)?;
        std::fs::write(on_root.join("cached.txt"), b"cached-on-body")?;

        let acme_probe_runs = Arc::new(AtomicUsize::new(0));
        let acme_probe_runs_hook = Arc::clone(&acme_probe_runs);
        *ACME_WEBROOT_PROBE_TEST_HOOK
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(move |host| {
            if host == "off-plain.example.test" || host == "off-mixed.example.test" {
                acme_probe_runs_hook.fetch_add(1, Ordering::Relaxed);
            }
        }));

        // 1. All-off server (no site uses `file-cache`, `acme-webroot` configured).
        let kdl_all_off = format!(
            r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
    acme-webroot "{webroot}"
}}
site "off-plain.example.test" {{
    root "{off_root}"
}}
site "off-fcgi.example.test" {{
    root "{off_root}"
    index "index.php" "index.html"
    route "*.php" {{
        fastcgi-pass "127.0.0.1:9000"
    }}
    route "/spa/*" {{
        try-files "{{path}}" "/spa_root/index.html"
    }}
}}
"#,
            webroot = kdl_path(&webroot),
            off_root = kdl_path(&off_root),
        );
        let (cfg_off, _) = parse_kdl("r3-all-off.kdl", &kdl_all_off)?;
        let clock_off = ManualClock::new();
        let engine_off = HttpEngine::from_config_with_file_cache_clock(
            &cfg_off,
            Arc::new(AcmeChallengeStore::new()),
            None,
            8443,
            CredentialSources::default(),
            clock_off.cache_clock(),
        )?;

        ROUTER_CACHE_SITE_BRANCH_HITS.store(0, Ordering::Relaxed);
        ROUTER_CACHE_LOOKUP_OR_ADMIT_CALLS.store(0, Ordering::Relaxed);
        ROUTER_ACME_PROBED_FS_SET.store(0, Ordering::Relaxed);
        acme_probe_runs.store(0, Ordering::Relaxed);
        #[cfg(debug_assertions)]
        let sys_clock_reads_off_before = miraserve_static::CacheClock::system_read_count();

        let acme_uri = format!("/.well-known/acme-challenge/{tok_miss}");
        // (a) Static file
        let (st, body) = fetch(&engine_off, "off-plain.example.test", "/plain.txt").await?;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body, b"plain-off-body");
        // (b) FastCGI site static hit (direct file + directory index)
        let (st, body) = fetch(&engine_off, "off-fcgi.example.test", "/style.css").await?;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body, b"body { color: black; }");
        let (st, body) = fetch(&engine_off, "off-fcgi.example.test", "/sub/").await?;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body, b"<h1>sub-index-off</h1>");
        // (c) try-files route
        let (st, body) = fetch(&engine_off, "off-fcgi.example.test", "/spa/dashboard").await?;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body, b"<h1>spa-fallback-off</h1>");
        // (d) ACME-shaped path that probes and misses the configured webroot
        let (st, body) = fetch(&engine_off, "off-plain.example.test", &acme_uri).await?;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body, b"acme-fallthrough-off");
        assert_eq!(
            acme_probe_runs.load(Ordering::Relaxed),
            1,
            "test setup must genuinely probe and miss acme-webroot"
        );

        assert_eq!(
            clock_off.read_count(),
            0,
            "cache-off all-off server must perform zero cache-clock reads"
        );
        #[cfg(debug_assertions)]
        assert_eq!(
            miraserve_static::CacheClock::system_read_count(),
            sys_clock_reads_off_before,
            "cache-off all-off server (including router ACME path) must perform zero CacheClock::System reads"
        );
        assert_eq!(
            ROUTER_CACHE_SITE_BRANCH_HITS.load(Ordering::Relaxed),
            0,
            "cache-off all-off server must never enter site file-cache branch"
        );
        assert_eq!(
            ROUTER_CACHE_LOOKUP_OR_ADMIT_CALLS.load(Ordering::Relaxed),
            0,
            "cache-off all-off server must perform zero cache lookup/admission calls"
        );
        assert_eq!(
            ROUTER_ACME_PROBED_FS_SET.load(Ordering::Relaxed),
            0,
            "all-off router must not even set acme_probed_fs when router.file_cache is None"
        );
        assert_eq!(engine_off.telemetry().file_cache_counts(), (0, 0, 0, 0));
        assert_eq!(engine_off.file_cache_budget_used(), 0);

        // 1b. Also exercise an all-off server built with the default `CacheClock::System`
        //     production clock on the ACME webroot miss + plain static request, verifying zero
        //     `CacheClock::System` reads on the router's ACME and static paths.
        let engine_off_sys = HttpEngine::from_config_with_credentials(
            &cfg_off,
            Arc::new(AcmeChallengeStore::new()),
            None,
            8443,
            CredentialSources::default(),
        )?;
        acme_probe_runs.store(0, Ordering::Relaxed);
        #[cfg(debug_assertions)]
        let sys_clock_reads_default_before = miraserve_static::CacheClock::system_read_count();
        let (st, body) = fetch(&engine_off_sys, "off-plain.example.test", &acme_uri).await?;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body, b"acme-fallthrough-off");
        assert_eq!(acme_probe_runs.load(Ordering::Relaxed), 1);
        let (st, body) = fetch(&engine_off_sys, "off-plain.example.test", "/plain.txt").await?;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body, b"plain-off-body");
        #[cfg(debug_assertions)]
        assert_eq!(
            miraserve_static::CacheClock::system_read_count(),
            sys_clock_reads_default_before,
            "default-clock all-off server (including router ACME path) must perform zero CacheClock::System reads"
        );

        // 2. Mixed server (one site enables `file-cache`, another site leaves it off): the same
        //    request set against the cache-less site STILL performs zero cache-clock reads and
        //    zero cache lookup/admission calls, while a request to the cache-enabled site DOES
        //    increment the counters (proving the instrumentation is live).
        let kdl_mixed = format!(
            r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
    acme-webroot "{webroot}"
}}
site "off-mixed.example.test" {{
    root "{off_root}"
    index "index.php" "index.html"
    route "*.php" {{
        fastcgi-pass "127.0.0.1:9000"
    }}
    route "/spa/*" {{
        try-files "{{path}}" "/spa_root/index.html"
    }}
}}
site "on-mixed.example.test" {{
    root "{on_root}"
    file-cache "60s"
}}
"#,
            webroot = kdl_path(&webroot),
            off_root = kdl_path(&off_root),
            on_root = kdl_path(&on_root),
        );
        let (cfg_mixed, _) = parse_kdl("r3-mixed.kdl", &kdl_mixed)?;
        let clock_mixed = ManualClock::new();
        let engine_mixed = HttpEngine::from_config_with_file_cache_clock(
            &cfg_mixed,
            Arc::new(AcmeChallengeStore::new()),
            None,
            8443,
            CredentialSources::default(),
            clock_mixed.cache_clock(),
        )?;

        ROUTER_CACHE_SITE_BRANCH_HITS.store(0, Ordering::Relaxed);
        ROUTER_CACHE_LOOKUP_OR_ADMIT_CALLS.store(0, Ordering::Relaxed);
        acme_probe_runs.store(0, Ordering::Relaxed);
        #[cfg(debug_assertions)]
        let sys_clock_reads_mixed_before = miraserve_static::CacheClock::system_read_count();

        let (st, _) = fetch(&engine_mixed, "off-mixed.example.test", "/plain.txt").await?;
        assert_eq!(st, StatusCode::OK);
        let (st, _) = fetch(&engine_mixed, "off-mixed.example.test", "/style.css").await?;
        assert_eq!(st, StatusCode::OK);
        let (st, _) = fetch(&engine_mixed, "off-mixed.example.test", "/sub/").await?;
        assert_eq!(st, StatusCode::OK);
        let (st, _) = fetch(&engine_mixed, "off-mixed.example.test", "/spa/dashboard").await?;
        assert_eq!(st, StatusCode::OK);
        let (st, _) = fetch(&engine_mixed, "off-mixed.example.test", &acme_uri).await?;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(acme_probe_runs.load(Ordering::Relaxed), 1);

        assert_eq!(
            clock_mixed.read_count(),
            0,
            "cache-less site on mixed server must perform zero cache-clock reads"
        );
        #[cfg(debug_assertions)]
        assert_eq!(
            miraserve_static::CacheClock::system_read_count(),
            sys_clock_reads_mixed_before,
            "cache-less site on mixed server (including router ACME path) must perform zero CacheClock::System reads"
        );
        assert_eq!(ROUTER_CACHE_SITE_BRANCH_HITS.load(Ordering::Relaxed), 0);
        assert_eq!(
            ROUTER_CACHE_LOOKUP_OR_ADMIT_CALLS.load(Ordering::Relaxed),
            0
        );
        assert_eq!(engine_mixed.telemetry().file_cache_counts(), (0, 0, 0, 0));
        assert_eq!(engine_mixed.file_cache_budget_used(), 0);

        // Positive control: one request to the cache-enabled site increments every counter, and a
        // direct / default-clock `CacheClock::System` read increments `system_read_count()` too.
        let (st_on, body_on) = fetch(&engine_mixed, "on-mixed.example.test", "/cached.txt").await?;
        assert_eq!(st_on, StatusCode::OK);
        assert_eq!(body_on, b"cached-on-body");
        assert!(clock_mixed.read_count() > 0);
        assert!(ROUTER_CACHE_SITE_BRANCH_HITS.load(Ordering::Relaxed) > 0);
        assert!(ROUTER_CACHE_LOOKUP_OR_ADMIT_CALLS.load(Ordering::Relaxed) > 0);
        assert_eq!(engine_mixed.telemetry().file_cache_counts().2, 1);

        #[cfg(debug_assertions)]
        {
            let before_direct = miraserve_static::CacheClock::system_read_count();
            let _ = miraserve_static::CacheClock::System.now_nanos();
            assert!(
                miraserve_static::CacheClock::system_read_count() > before_direct,
                "CacheClock::system_read_count() must detect direct CacheClock::System.now_nanos() reads"
            );
            let before_sys_site = miraserve_static::CacheClock::system_read_count();
            let engine_sys_on = HttpEngine::from_config_with_credentials(
                &cfg_mixed,
                Arc::new(AcmeChallengeStore::new()),
                None,
                8443,
                CredentialSources::default(),
            )?;
            let (st_sys_on, body_sys_on) =
                fetch(&engine_sys_on, "on-mixed.example.test", "/cached.txt").await?;
            assert_eq!(st_sys_on, StatusCode::OK);
            assert_eq!(body_sys_on, b"cached-on-body");
            assert!(
                miraserve_static::CacheClock::system_read_count() > before_sys_site,
                "default-clock cache-enabled site must increment CacheClock::system_read_count()"
            );
            drop(engine_sys_on);
        }

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    /// Review round 1, Item 4: `CompiledRouter`, `CompiledSite`, and `CompiledRoute` each cache
    /// their `has_file_cache` boolean accurately so cache-off sites/routes execute one boolean
    /// check at site dispatch and zero downstream cache-option checks.
    #[test]
    fn r1_item4_cached_has_file_cache_flags_on_router_site_and_route() -> TestResult {
        let base = temp_dir("r1-item4-flags")?;
        let off_root = base.join("off");
        let on_root = base.join("on");
        std::fs::create_dir_all(&off_root)?;
        std::fs::create_dir_all(&on_root)?;

        let kdl = format!(
            r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "off.example.test" {{
    root "{off}"
    route "/static/*" {{ static {{}} }}
    route "/spa/*" {{ try-files "{{path}}" "/index.html" }}
    route "/ping" {{ respond 410 }}
}}
site "on.example.test" {{
    root "{on}"
    file-cache "30s"
    route "/static/*" {{ static {{}} }}
    route "/spa/*" {{ try-files "{{path}}" "/index.html" }}
    route "*.php" {{ fastcgi-pass "127.0.0.1:9000" }}
    route "/ping" {{ respond 410 }}
}}
"#,
            off = kdl_path(&off_root),
            on = kdl_path(&on_root),
        );
        let (cfg, _) = parse_kdl("r1-item4-flags.kdl", &kdl)?;
        let router =
            super::CompiledRouter::compile(&cfg, &Arc::new(super::AgentKeyRegistry::new()))?;
        assert!(router.has_file_cache);
        let [off_site, on_site] = router.sites.as_slice() else {
            return Err("expected 2 compiled sites".into());
        };
        assert!(!off_site.has_file_cache);
        assert!(off_site.routes.iter().all(|r| !r.has_file_cache));

        assert!(on_site.has_file_cache);
        let [r_static, r_try, r_fcgi, r_resp] = on_site.routes.as_slice() else {
            return Err("expected 4 routes on cache-enabled site".into());
        };
        assert!(r_static.has_file_cache);
        assert!(r_try.has_file_cache);
        assert!(!r_fcgi.has_file_cache);
        assert!(!r_resp.has_file_cache);

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }
}

#[cfg(test)]
mod worker_compression_tests {
    use super::{
        StreamingCompressedBody, WORKER_LOOP_COMPRESS_CHUNK_BYTES, YieldingStreamingCompressedBody,
        full_http_body, maybe_compress_proxied_response,
    };
    use crate::{HttpBody, HttpError, empty_http_body};
    use bytes::Bytes;
    use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, ETAG, VARY};
    use http::{HeaderValue, Method, Response, StatusCode};
    use http_body::Body as _;
    use http_body_util::BodyExt as _;
    use miraserve_static::compress::{ContentEncoding, StreamCompressor};
    use miraserve_static::enter_worker_loop_thread;
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};

    struct VecFramesBody {
        frames: VecDeque<Bytes>,
    }

    impl http_body::Body for VecFramesBody {
        type Data = Bytes;
        type Error = HttpError;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
            match self.frames.pop_front() {
                Some(b) => Poll::Ready(Some(Ok(http_body::Frame::data(b)))),
                None => Poll::Ready(None),
            }
        }

        fn is_end_stream(&self) -> bool {
            self.frames.is_empty()
        }
    }

    fn sample_payload(size: usize) -> Bytes {
        let mut raw = Vec::with_capacity(size);
        for i in 0_u32.. {
            use std::io::Write as _;
            let _ = writeln!(raw, "{{\"row\":{i},\"data\":\"worker-loop-compress\"}}");
            if raw.len() >= size {
                break;
            }
        }
        raw.truncate(size);
        Bytes::from(raw)
    }

    fn buffered_response(payload: Bytes) -> Response<HttpBody> {
        let len = payload.len().to_string();
        let mut resp = Response::new(full_http_body(payload));
        *resp.status_mut() = StatusCode::OK;
        resp.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Ok(v) = HeaderValue::from_str(&len) {
            resp.headers_mut().insert(CONTENT_LENGTH, v);
        }
        resp.headers_mut()
            .insert(ETAG, HeaderValue::from_static("\"abc123\""));
        resp
    }

    static COMPRESS_POOL_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A buffered compression handed off a worker loop needs one of the process-wide permits
    /// BEFORE it is queued: with every permit taken nothing is queued and the request waits,
    /// a request dropped while it waits leaves nothing behind, and the next one is served once
    /// a permit is free.
    #[test]
    fn worker_loop_buffered_compression_waits_for_a_permit_and_can_be_dropped()
    -> Result<(), Box<dyn std::error::Error>> {
        let _serial = COMPRESS_POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let payload = sample_payload(256 * 1024);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let _worker_guard = enter_worker_loop_thread();
        let permits = u32::try_from(super::WORKER_LOOP_COMPRESS_JOBS)?;
        rt.block_on(async {
            let all = Arc::clone(super::worker_compress_semaphore())
                .acquire_many_owned(permits)
                .await?;
            let waiting = maybe_compress_proxied_response(
                Some("gzip"),
                &Method::GET,
                buffered_response(payload.clone()),
            );
            let waited = tokio::time::timeout(std::time::Duration::from_millis(150), waiting).await;
            assert!(
                waited.is_err(),
                "with every permit taken the compression must wait, not be queued"
            );
            // `waiting` was dropped by the timeout while it waited for a permit.
            drop(all);
            let resp = tokio::time::timeout(
                std::time::Duration::from_secs(20),
                maybe_compress_proxied_response(
                    Some("gzip"),
                    &Method::GET,
                    buffered_response(payload.clone()),
                ),
            )
            .await?;
            assert_eq!(
                resp.headers().get(CONTENT_ENCODING),
                Some(&HeaderValue::from_static("gzip")),
                "after the permits are free again the next response is compressed"
            );
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    }

    /// Buffered proxied compression > 64 KiB on a worker loop produces the exact same headers and
    /// compressed bytes as the shared runtime while offloading compression to the blocking pool.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn worker_loop_buffered_compression_matches_shared_runtime_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let _serial = COMPRESS_POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let payload = sample_payload(256 * 1024);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        for accept in ["zstd", "br", "gzip"] {
            let shared_resp = rt.block_on(maybe_compress_proxied_response(
                Some(accept),
                &Method::GET,
                buffered_response(payload.clone()),
            ));
            let shared_enc = shared_resp.headers().get(CONTENT_ENCODING).cloned();
            let shared_len = shared_resp.headers().get(CONTENT_LENGTH).cloned();
            let shared_etag = shared_resp.headers().get(ETAG).cloned();
            let shared_vary = shared_resp.headers().get(VARY).cloned();
            let shared_bytes = rt.block_on(shared_resp.into_body().collect())?.to_bytes();

            let worker_thread_id = std::thread::current().id();
            let job_entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let offloaded_to_other_thread = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let hook_saw_sibling_tick = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let sibling_ticked_gate =
                Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));

            let job_entered_hook = Arc::clone(&job_entered);
            let offloaded_hook = Arc::clone(&offloaded_to_other_thread);
            let hook_saw_tick_hook = Arc::clone(&hook_saw_sibling_tick);
            let gate_hook = Arc::clone(&sibling_ticked_gate);
            let pool_hook = super::test_proxy_compress_pool_hook_guard(Arc::new(move || {
                if std::thread::current().id() != worker_thread_id {
                    offloaded_hook.store(true, Ordering::Release);
                }
                job_entered_hook.store(true, Ordering::Release);
                let (lock, cvar) = &*gate_hook;
                let guard = lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let (guard, _) = cvar
                    .wait_timeout_while(guard, std::time::Duration::from_secs(5), |ready| !*ready)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if *guard {
                    hook_saw_tick_hook.store(true, Ordering::Release);
                }
            }));

            let worker_guard = enter_worker_loop_thread();
            let sibling_ticks = Arc::new(AtomicUsize::new(0));
            let ticks_while_on_pool = Arc::new(AtomicUsize::new(0));
            let ticks_c = Arc::clone(&sibling_ticks);
            let ticks_pool_c = Arc::clone(&ticks_while_on_pool);
            let job_entered_c = Arc::clone(&job_entered);
            let gate_c = Arc::clone(&sibling_ticked_gate);
            let (worker_resp, ticks_during_compress, pool_ticks) = rt.block_on(async {
                let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let done_c = Arc::clone(&done);
                let sibling = tokio::spawn(async move {
                    while !done_c.load(Ordering::Acquire) {
                        let on_pool = job_entered_c.load(Ordering::Acquire);
                        ticks_c.fetch_add(1, Ordering::AcqRel);
                        if on_pool {
                            ticks_pool_c.fetch_add(1, Ordering::AcqRel);
                            let (lock, cvar) = &*gate_c;
                            let mut ready = lock
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            if !*ready {
                                *ready = true;
                                cvar.notify_all();
                            }
                        }
                        tokio::task::yield_now().await;
                    }
                });
                let resp = maybe_compress_proxied_response(
                    Some(accept),
                    &Method::GET,
                    buffered_response(payload.clone()),
                )
                .await;
                let ticks = sibling_ticks.load(Ordering::Acquire);
                let on_pool_ticks = ticks_while_on_pool.load(Ordering::Acquire);
                done.store(true, Ordering::Release);
                // Defensively release the pool hook if compression somehow returned without waking it.
                {
                    let (lock, cvar) = &*sibling_ticked_gate;
                    let mut ready = lock
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    *ready = true;
                    cvar.notify_all();
                }
                let _ = sibling.await;
                (resp, ticks, on_pool_ticks)
            });
            drop(pool_hook);
            assert!(
                job_entered.load(Ordering::Acquire),
                "buffered > 64 KiB compression must run on the blocking pool ({accept})"
            );
            assert!(
                offloaded_to_other_thread.load(Ordering::Acquire),
                "buffered > 64 KiB compression must execute off the worker loop thread ({accept})"
            );
            assert!(
                hook_saw_sibling_tick.load(Ordering::Acquire),
                "blocking-pool compression job did not observe sibling progress on the worker loop ({accept})"
            );
            assert!(
                ticks_during_compress > 0 && pool_ticks > 0,
                "sibling task on the same worker loop must make progress while > 64 KiB buffered body compresses ({accept})"
            );
            let worker_enc = worker_resp.headers().get(CONTENT_ENCODING).cloned();
            let worker_len = worker_resp.headers().get(CONTENT_LENGTH).cloned();
            let worker_etag = worker_resp.headers().get(ETAG).cloned();
            let worker_vary = worker_resp.headers().get(VARY).cloned();
            let worker_bytes = rt.block_on(worker_resp.into_body().collect())?.to_bytes();
            drop(worker_guard);

            assert_eq!(
                worker_enc, shared_enc,
                "Content-Encoding mismatch ({accept})"
            );
            assert_eq!(worker_len, shared_len, "Content-Length mismatch ({accept})");
            assert_eq!(worker_etag, shared_etag, "ETag mismatch ({accept})");
            assert_eq!(worker_vary, shared_vary, "Vary mismatch ({accept})");
            assert_eq!(
                worker_bytes, shared_bytes,
                "compressed body bytes must be identical ({accept})"
            );
        }
        Ok(())
    }

    /// Streaming compression on a worker loop compresses in `<= 64 KiB` pieces, yields back to
    /// the event loop between pieces so sibling tasks make progress, and produces byte-identical
    /// compressed output to the shared runtime.
    #[test]
    fn worker_loop_streaming_compression_yields_between_pieces_and_matches_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let single_big = sample_payload(256 * 1024);
        let multi = vec![
            sample_payload(100 * 1024),
            sample_payload(100 * 1024),
            sample_payload(80 * 1024),
        ];
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        for enc in [ContentEncoding::Brotli, ContentEncoding::Gzip] {
            for frames in [vec![single_big.clone()], multi.clone()] {
                let total_input: usize = frames.iter().map(Bytes::len).sum();
                let shared_body = StreamingCompressedBody::new(
                    VecFramesBody {
                        frames: frames.iter().cloned().collect(),
                    }
                    .boxed(),
                    StreamCompressor::new(enc).ok_or("expected stream compressor")?,
                );
                let shared_bytes = rt.block_on(shared_body.collect())?.to_bytes();

                let sibling_ticks = Arc::new(AtomicUsize::new(0));
                let ticks_during_compress = Arc::new(AtomicUsize::new(0));
                let ticks_c = Arc::clone(&sibling_ticks);
                let during_c = Arc::clone(&ticks_during_compress);
                let worker_body = YieldingStreamingCompressedBody::new(
                    VecFramesBody {
                        frames: frames.into_iter().collect(),
                    }
                    .boxed(),
                    StreamCompressor::new(enc).ok_or("expected stream compressor")?,
                );

                let worker_bytes = rt.block_on(async move {
                    let _worker_guard = enter_worker_loop_thread();
                    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
                    let done_c = Arc::clone(&done);
                    let sibling = tokio::spawn(async move {
                        while !done_c.load(Ordering::Acquire) {
                            ticks_c.fetch_add(1, Ordering::AcqRel);
                            tokio::task::yield_now().await;
                        }
                    });
                    // Poll the streaming compressor directly with a real waker and count yields.
                    let mut body = std::pin::pin!(worker_body);
                    let mut out = Vec::new();
                    let mut yields = 0_usize;
                    while !body.is_end_stream() {
                        let res = std::future::poll_fn(|cx| match body.as_mut().poll_frame(cx) {
                            Poll::Pending => {
                                yields += 1;
                                Poll::Pending
                            }
                            Poll::Ready(item) => Poll::Ready(item),
                        })
                        .await;
                        match res {
                            Some(Ok(frame)) => {
                                if let Some(data) = frame.data_ref() {
                                    out.extend_from_slice(data);
                                }
                            }
                            Some(Err(err)) => return Err(err),
                            None => break,
                        }
                    }
                    during_c.store(sibling_ticks.load(Ordering::Acquire), Ordering::Release);
                    done.store(true, Ordering::Release);
                    let _ = sibling.await;
                    let expected_min_yields =
                        (total_input / WORKER_LOOP_COMPRESS_CHUNK_BYTES).saturating_sub(1);
                    assert!(
                        yields >= expected_min_yields,
                        "expected at least {expected_min_yields} yields for {total_input} bytes ({enc:?}), saw {yields}"
                    );
                    Ok::<_, HttpError>(Bytes::from(out))
                })?;

                assert!(
                    ticks_during_compress.load(Ordering::Acquire) > 0,
                    "sibling task on the same worker loop must run during streaming compression ({enc:?})"
                );
                assert_eq!(
                    worker_bytes, shared_bytes,
                    "worker streaming compression bytes must match shared runtime byte for byte ({enc:?})"
                );
            }
        }
        Ok(())
    }

    /// Review round 1, Item 4: on the shared runtime, `StreamingCompressedBody` must keep the
    /// compact 4-field 0.1.4 layout without worker-loop chunk-yield fields.
    #[test]
    fn shared_streaming_compressed_body_does_not_grow_for_worker_yield_fields() {
        let shared_size = std::mem::size_of::<StreamingCompressedBody>();
        let worker_size = std::mem::size_of::<YieldingStreamingCompressedBody>();
        assert!(
            shared_size < worker_size,
            "shared StreamingCompressedBody ({shared_size} B) must remain strictly smaller than worker YieldingStreamingCompressedBody ({worker_size} B)"
        );
    }

    /// In-task HTTP/2 non-blocking context (`enter_nonblocking_inline_context()`, WITHOUT
    /// `enter_worker_loop_thread()`) selects the exact same worker-mode compression paths
    /// (blocking pool for > 64 KiB buffered bodies; yielding wrapper for unknown-length streams)
    /// while leaving `is_worker_loop_thread() == false`.
    #[test]
    fn nonblocking_inline_context_uses_pool_and_yielding_proxy_compression()
    -> Result<(), Box<dyn std::error::Error>> {
        let _serial = COMPRESS_POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let payload = sample_payload(256 * 1024);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        let (pool_before, yielding_before) = super::test_proxy_compress_stats();
        let (buf_enc, stream_enc) = rt.block_on(async {
            let _ctx = miraserve_static::enter_nonblocking_inline_context();
            assert!(!miraserve_static::is_worker_loop_thread());
            assert!(miraserve_static::inline_work_must_not_block());

            let buf_resp = maybe_compress_proxied_response(
                Some("br"),
                &Method::GET,
                buffered_response(payload.clone()),
            )
            .await;
            let buf_enc = buf_resp.headers().get(CONTENT_ENCODING).cloned();

            let unknown_resp = Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/json")
                .body(
                    VecFramesBody {
                        frames: VecDeque::from([payload.clone()]),
                    }
                    .boxed(),
                )
                .unwrap_or_else(|_| Response::new(full_http_body(Bytes::new())));
            let stream_resp =
                maybe_compress_proxied_response(Some("br"), &Method::GET, unknown_resp).await;
            let stream_enc = stream_resp.headers().get(CONTENT_ENCODING).cloned();
            let _ = stream_resp.into_body().collect().await;
            (buf_enc, stream_enc)
        });
        let (pool_after, yielding_after) = super::test_proxy_compress_stats();
        assert_eq!(buf_enc, Some(HeaderValue::from_static("br")));
        assert_eq!(stream_enc, Some(HeaderValue::from_static("br")));
        assert!(
            pool_after > pool_before,
            "buffered > 64 KiB body under nonblocking inline context must offload to blocking pool"
        );
        assert!(
            yielding_after > yielding_before,
            "unknown-length body under nonblocking inline context must select YieldingStreamingCompressedBody"
        );
        Ok(())
    }

    /// ACME webroot 4 KiB token lookup offloads its filesystem check and read to the blocking
    /// pool under `enter_nonblocking_inline_context()` (and `enter_worker_loop_thread()`), and
    /// serves the exact key authorization while keeping HTTP/1.1 shared-runtime requests inline.
    #[test]
    fn acme_webroot_offloads_to_blocking_pool_in_nonblocking_context()
    -> Result<(), Box<dyn std::error::Error>> {
        use miraserve_config::parse_kdl;
        use miraserve_tls::AcmeChallengeStore;
        use std::sync::atomic::AtomicBool;

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let tmp =
            std::env::temp_dir().join(format!("miraserve-acme-nb-{}-{nanos}", std::process::id()));
        let challenge_dir = tmp.join(".well-known").join("acme-challenge");
        std::fs::create_dir_all(&challenge_dir)?;
        let token = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_";
        let thumbprint = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG";
        let key_auth = format!("{token}.{thumbprint}");
        std::fs::write(challenge_dir.join(token), format!("{key_auth}\n"))?;

        let kdl = format!(
            r#"
server {{
    listen ":8443"
    acme-webroot "{webroot}"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "acme.nb.test" {{
    route "/*" {{
        respond 404
    }}
}}
"#,
            webroot = tmp.to_string_lossy().replace('\\', "/"),
        );
        let (cfg, _) = parse_kdl("acme-nb.kdl", &kdl)?;
        let router = super::CompiledRouter::compile(
            &cfg,
            &Arc::new(miraserve_ai::AgentKeyRegistry::default()),
        )?;
        let acme = AcmeChallengeStore::new();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let body = rt.block_on(async {
            let _ctx = miraserve_static::enter_nonblocking_inline_context();
            let done = Arc::new(AtomicBool::new(false));
            let done_c = Arc::clone(&done);
            let sibling_ticks = Arc::new(AtomicUsize::new(0));
            let ticks_c = Arc::clone(&sibling_ticks);
            let sibling = tokio::spawn(async move {
                while !done_c.load(Ordering::Acquire) {
                    ticks_c.fetch_add(1, Ordering::AcqRel);
                    tokio::task::yield_now().await;
                }
            });
            let req = http::Request::builder()
                .uri(format!("/.well-known/acme-challenge/{token}"))
                .header(http::header::HOST, "acme.nb.test")
                .body(crate::empty_http_body())
                .map_err(|e| e.to_string())?;
            let req_ctx = crate::RequestContext {
                client_ip: None,
                remote_port: None,
                server_addr: None,
                server_port: 8443,
                is_https: true,
                tls: None,
            };
            let resp = router
                .dispatch(
                    req,
                    &req_ctx,
                    &cfg.server.limits,
                    &acme,
                    None,
                    &miraserve_telemetry::TelemetryRegistry::new(),
                )
                .await;
            done.store(true, Ordering::Release);
            let _ = sibling.await;
            assert_eq!(resp.status(), StatusCode::OK);
            let bytes = resp
                .into_body()
                .collect()
                .await
                .map_err(|e| e.to_string())?
                .to_bytes();
            Ok::<Bytes, String>(bytes)
        })?;
        assert_eq!(body.as_ref(), key_auth.as_bytes());

        let _ = std::fs::remove_dir_all(&tmp);
        Ok(())
    }

    /// P2-2: Buffered compression waiters consume frames before awaiting (no duplicate buffer),
    /// bound waiter bytes via the waiter byte budget, fall back immediately to uncompressed with
    /// `Vary: Accept-Encoding` when the waiter budget is saturated, and refund waiter bytes on
    /// cancellation/drop.
    #[test]
    fn p2_2_compression_waiter_drops_frames_and_bounds_waiter_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let _serial = COMPRESS_POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let _ctx = miraserve_static::enter_nonblocking_inline_context();
        let permits = u32::try_from(super::WORKER_LOOP_COMPRESS_JOBS)?;

        // Multi-frame 256 KiB payload (4 x 64 KiB) to exercise frame consumption before `.await`.
        let payload = sample_payload(256 * 1024);
        let make_multi_frame_resp = |data: &Bytes| -> Response<HttpBody> {
            let chunks: VecDeque<Bytes> = (0..4)
                .map(|i| data.slice(i * 64 * 1024..(i + 1) * 64 * 1024))
                .collect();
            let mut resp = Response::new(VecFramesBody { frames: chunks }.boxed());
            *resp.status_mut() = StatusCode::OK;
            resp.headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            if let Ok(len_val) = HeaderValue::from_str(&data.len().to_string()) {
                resp.headers_mut().insert(CONTENT_LENGTH, len_val);
            }
            resp
        };

        // Limit waiter bytes to 300 KiB: 1st 256 KiB waiter fits, 2nd 256 KiB waiter exceeds
        // budget and must immediately fall back to uncompressed with `Vary: Accept-Encoding`.
        let _budget_guard = super::test_compress_waiter_budget_override_guard(300 * 1024);
        rt.block_on(async {
            let all = Arc::clone(super::worker_compress_semaphore())
                .acquire_many_owned(permits)
                .await?;
            let (_, rejected_before) = super::test_compress_waiter_stats();

            let mut waiter_a = Box::pin(maybe_compress_proxied_response(
                Some("gzip"),
                &Method::GET,
                make_multi_frame_resp(&payload),
            ));
            // Drive waiter_a once so it buffers all 4 frames, drops `frames`, reserves 256 KiB
            // from the waiter budget, and parks on the semaphore.
            let poll_a =
                tokio::time::timeout(std::time::Duration::from_millis(50), waiter_a.as_mut()).await;
            assert!(poll_a.is_err(), "first 256 KiB waiter must wait for permit");
            let (in_use_after_a, _) = super::test_compress_waiter_stats();
            assert_eq!(
                in_use_after_a,
                256 * 1024,
                "waiter budget must hold exactly one 256 KiB buffer (no duplicate)"
            );

            // Second 256 KiB request while permits are saturated: 512 KiB > 300 KiB budget ->
            // must return immediately uncompressed with `Vary: Accept-Encoding`.
            let resp_b = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                maybe_compress_proxied_response(
                    Some("gzip"),
                    &Method::GET,
                    make_multi_frame_resp(&payload),
                ),
            )
            .await?;
            assert!(
                resp_b.headers().get(CONTENT_ENCODING).is_none(),
                "budget-saturated waiter must fall back to uncompressed"
            );
            assert!(
                resp_b
                    .headers()
                    .get_all(VARY)
                    .iter()
                    .any(|v| v.to_str().is_ok_and(|s| s.contains("Accept-Encoding"))),
                "uncompressed backpressure fallback must include Vary: Accept-Encoding"
            );
            let body_b = resp_b.into_body().collect().await?.to_bytes();
            assert_eq!(body_b, payload);
            let (_, rejected_after) = super::test_compress_waiter_stats();
            assert_eq!(rejected_after, rejected_before + 1);

            // Dropping waiter_a immediately refunds its 256 KiB waiter reservation.
            drop(waiter_a);
            let (in_use_after_drop, _) = super::test_compress_waiter_stats();
            assert_eq!(
                in_use_after_drop, 0,
                "dropping a waiting future must release its waiter byte reservation immediately"
            );

            drop(all);
            Ok::<_, Box<dyn std::error::Error>>(())
        })
    }

    /// P1-C: `CompiledRouter::has_static_work()` distinguishes static-free configs (proxy,
    /// respond, redirect, fastcgi-without-root, acme-webroot) from configs that serve or inspect
    /// static document roots (`site.root`, `static`, `try-files`, `fastcgi` with `root`).
    #[test]
    fn p1_c_compiled_router_has_static_work_inventory() -> Result<(), Box<dyn std::error::Error>> {
        use miraserve_config::parse_kdl;

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let tmp =
            std::env::temp_dir().join(format!("miraserve-p1c-inv-{}-{nanos}", std::process::id()));
        let webroot = tmp.join("acme");
        let docroot = tmp.join("www");
        std::fs::create_dir_all(&webroot)?;
        std::fs::create_dir_all(&docroot)?;
        let keys = Arc::new(miraserve_ai::AgentKeyRegistry::default());

        let no_static_kdl = format!(
            r#"
server {{
    listen ":8443"
    acme-webroot "{acme}"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "nostatic.test" {{
    route "/proxy/*" {{ reverse-proxy {{ upstream "http://127.0.0.1:9999" }} }}
    route "/redir/*" {{ redirect "https://example.com{{uri}}" status=301 }}
    route "/*" {{ respond 503 }}
}}
"#,
            acme = webroot.to_string_lossy().replace('\\', "/"),
        );
        let (cfg_no, _) = parse_kdl("no-static.kdl", &no_static_kdl)?;
        let router_no = super::CompiledRouter::compile(&cfg_no, &keys)?;
        assert!(
            !router_no.has_static_work(),
            "proxy + respond + redirect + acme-webroot must have has_static_work() == false"
        );

        let root_esc = docroot.to_string_lossy().replace('\\', "/");
        for (label, site_body) in [
            ("site-root", format!(r#"root "{root_esc}""#)),
            (
                "static-route",
                format!(r#"route "/files/*" {{ root "{root_esc}"; static {{}} }}"#),
            ),
            (
                "try-files",
                format!(r#"route "/*" {{ root "{root_esc}"; try-files "{{path}}" "=404" }}"#),
            ),
            (
                "fastcgi-with-root",
                format!(r#"route "*.php" {{ root "{root_esc}"; fastcgi-pass "127.0.0.1:9000" }}"#),
            ),
        ] {
            let kdl = format!(
                r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "yes.test" {{
    {site_body}
}}
"#
            );
            let (cfg, _) = parse_kdl(label, &kdl)?;
            let router = super::CompiledRouter::compile(&cfg, &keys)?;
            assert!(
                router.has_static_work(),
                "{label} must report has_static_work() == true"
            );
        }

        // P1-3: Shared HTTP/1.1-only static config must skip RootReadPolicy's fstatvfs/statx probe
        // even when the host kernel is in range.
        #[cfg(target_os = "linux")]
        {
            let _k = miraserve_static::test_nowait_kernel_in_range_override_guard(Some(true));
            let h1_kdl = format!(
                r#"
server {{
    listen ":8443" protocols="h1"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "h1only.test" {{
    root "{root_esc}"
}}
"#
            );
            let (h1_cfg, _) = parse_kdl("h1-only-static.kdl", &h1_kdl)?;
            let probes_before = miraserve_static::test_root_policy_probe_calls();
            let _h1_router = super::CompiledRouter::compile(&h1_cfg, &keys)?;
            assert_eq!(
                miraserve_static::test_root_policy_probe_calls(),
                probes_before,
                "shared H1-only static config must not probe RootReadPolicy at root open"
            );
        }

        let _ = std::fs::remove_dir_all(&tmp);
        Ok(())
    }

    /// Exhaustive proof of the proxy `Accept-Encoding` negotiation invariant over all
    /// `4^5 = 1024` combinations of `{br, gzip, zstd, *, identity}` × `{absent, q=0, q=0.5, q=1}`,
    /// checked against an INDEPENDENT plain RFC 9110 §12.5.3 / §12.4.2 oracle (not calling the
    /// production parser) across all three proxy paths (`BufferedUnsaturated`, `Streamed`,
    /// `Saturated`), plus member-order permutations, two-field-line splits, malformed/out-of-range
    /// weights, and duplicate contradictions.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn proxy_accept_encoding_exhaustive_oracle_proof() -> Result<(), Box<dyn std::error::Error>> {
        use std::cmp::Reverse;
        use std::collections::HashMap;

        use http::header::ACCEPT_ENCODING;
        use miraserve_static::compress::{ContentEncoding, accepted_encodings};

        use super::{ProxyCompressPath, ProxyEncodingDecision, negotiate_proxy_accept_encoding};

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum Weight {
            Absent,
            Zero,
            Half,
            One,
        }
        impl Weight {
            const ALL: [Self; 4] = [Self::Absent, Self::Zero, Self::Half, Self::One];
            fn format_member(self, name: &str) -> Option<String> {
                match self {
                    Self::Absent => None,
                    Self::Zero => Some(format!("{name};q=0")),
                    Self::Half => Some(format!("{name};q=0.5")),
                    Self::One => Some(format!("{name};q=1")),
                }
            }
            const fn millis(self) -> Option<u16> {
                match self {
                    Self::Absent => None,
                    Self::Zero => Some(0),
                    Self::Half => Some(500),
                    Self::One => Some(1_000),
                }
            }
        }

        // Independent, plain, slow RFC 9110 §12.4.2 / §12.5.3 string oracle — shares NO code with
        // `negotiate_proxy_accept_encoding` or `parse_rfc9110_qvalue`.
        fn oracle_parse_qvalue(raw: &str) -> Option<u16> {
            let bytes = raw.as_bytes();
            let first = *bytes.first()?;
            match first {
                b'0' => {
                    if bytes.len() == 1 {
                        return Some(0);
                    }
                    if bytes.get(1) != Some(&b'.') || bytes.len() > 5 {
                        return None;
                    }
                    let frac = bytes.get(2..)?;
                    if !frac.iter().all(u8::is_ascii_digit) {
                        return None;
                    }
                    let mut padded = [b'0'; 3];
                    for (dst, &src) in padded.iter_mut().zip(frac.iter()) {
                        *dst = src;
                    }
                    let s = std::str::from_utf8(&padded).ok()?;
                    s.parse::<u16>().ok()
                }
                b'1' => {
                    if bytes.len() == 1 {
                        return Some(1_000);
                    }
                    if bytes.get(1) != Some(&b'.') || bytes.len() > 5 {
                        return None;
                    }
                    let frac = bytes.get(2..)?;
                    if !frac.iter().all(|&b| b == b'0') {
                        return None;
                    }
                    Some(1_000)
                }
                _ => None,
            }
        }

        fn oracle_rfc9110(header: &str) -> (bool, Vec<ContentEncoding>) {
            let mut weights: HashMap<String, Vec<u16>> = HashMap::new();
            for item in header.split(',') {
                let trimmed = item.trim_matches([' ', '\t']);
                if trimmed.is_empty() {
                    continue;
                }
                let parts: Vec<&str> = trimmed.split(';').collect();
                let Some(token_raw) = parts.first() else {
                    continue;
                };
                let token = token_raw.trim_matches([' ', '\t']).to_ascii_lowercase();
                if token.is_empty() {
                    continue;
                }
                let q = match parts.len() {
                    1 => 1_000_u16,
                    2 => {
                        let Some(param_raw) = parts.get(1) else {
                            continue;
                        };
                        let param = param_raw.trim_matches([' ', '\t']);
                        let Some(q_val) = param
                            .strip_prefix("q=")
                            .or_else(|| param.strip_prefix("Q="))
                        else {
                            continue;
                        };
                        let Some(parsed) = oracle_parse_qvalue(q_val) else {
                            continue;
                        };
                        parsed
                    }
                    // Duplicate `q=` or extra/empty parameters reject the member.
                    _ => continue,
                };
                weights.entry(token).or_default().push(q);
            }

            let effective = |name: &str| -> Option<u16> {
                let resolve = |ws: &[u16]| -> u16 {
                    if ws.contains(&0) {
                        0
                    } else {
                        ws.iter().copied().max().unwrap_or(0)
                    }
                };
                // Independent RFC 9110 §8.4.1.3 alias handling (does not import production's
                // token mapping): `x-gzip` and `gzip` are equivalent, so combine both buckets
                // before applying `q=0` fail-closed / positive-max and wildcard fallback.
                if name == "gzip" {
                    let mut combined = Vec::new();
                    if let Some(ws) = weights.get("gzip") {
                        combined.extend_from_slice(ws);
                    }
                    if let Some(ws) = weights.get("x-gzip") {
                        combined.extend_from_slice(ws);
                    }
                    if !combined.is_empty() {
                        return Some(resolve(&combined));
                    }
                    return weights.get("*").map(|ws| resolve(ws));
                }
                if let Some(ws) = weights.get(name) {
                    Some(resolve(ws))
                } else {
                    weights.get("*").map(|ws| resolve(ws))
                }
            };

            // RFC 9110 §12.5.3: identity is acceptable by default unless explicitly excluded
            // (`identity;q=0`) or excluded by `*;q=0` without an explicit listing for `identity`.
            let identity_ok = effective("identity").is_none_or(|w| w > 0);

            let mut acceptable: Vec<(ContentEncoding, u16, u8)> = Vec::new();
            for (rank, enc) in [
                (0_u8, ContentEncoding::Zstd),
                (1_u8, ContentEncoding::Brotli),
                (2_u8, ContentEncoding::Gzip),
            ] {
                if let Some(w) = effective(enc.header_value())
                    && w > 0
                {
                    acceptable.push((enc, w, rank));
                }
            }
            acceptable.sort_by_key(|&(_, w, rank)| (Reverse(w), rank));
            let ordered = acceptable.into_iter().map(|(e, _, _)| e).collect();
            (identity_ok, ordered)
        }

        fn oracle_proxy_decision(
            header: &str,
            path: ProxyCompressPath,
        ) -> (bool, Option<ContentEncoding>) {
            let (identity_ok, rfc_list) = oracle_rfc9110(header);
            let is_streamable =
                |e: &ContentEncoding| matches!(e, ContentEncoding::Brotli | ContentEncoding::Gzip);
            let chosen = if identity_ok {
                let v014 = accepted_encodings(header);
                match path {
                    ProxyCompressPath::BufferedUnsaturated => v014.first().copied(),
                    ProxyCompressPath::Streamed => v014.iter().copied().find(is_streamable),
                    ProxyCompressPath::Saturated => None,
                }
            } else {
                match path {
                    ProxyCompressPath::BufferedUnsaturated => rfc_list.first().copied(),
                    ProxyCompressPath::Streamed | ProxyCompressPath::Saturated => {
                        rfc_list.iter().copied().find(is_streamable)
                    }
                }
            };
            (identity_ok, chosen)
        }

        fn permute<'a>(items: &[&'a str]) -> Vec<Vec<&'a str>> {
            if items.len() <= 1 {
                return vec![items.to_vec()];
            }
            let mut out = Vec::new();
            for i in 0..items.len() {
                let Some(&head) = items.get(i) else {
                    continue;
                };
                let mut rest = Vec::with_capacity(items.len() - 1);
                for (j, &item) in items.iter().enumerate() {
                    if j != i {
                        rest.push(item);
                    }
                }
                for mut sub in permute(&rest) {
                    let mut row = Vec::with_capacity(items.len());
                    row.push(head);
                    row.append(&mut sub);
                    out.push(row);
                }
            }
            out
        }

        type EdgeCase<'a> = (
            Option<&'a str>,
            bool,
            Option<ContentEncoding>,
            Option<ContentEncoding>,
            Option<ContentEncoding>,
        );

        // 1. Exhaustive 4^5 = 1024 combinations over {br, gzip, zstd, *, identity}.
        let mut total_cases = 0_usize;
        let mut identity_excluded_cases = 0_usize;
        for w_br in Weight::ALL {
            for w_gzip in Weight::ALL {
                for w_zstd in Weight::ALL {
                    for w_star in Weight::ALL {
                        for w_id in Weight::ALL {
                            total_cases += 1;
                            let members: Vec<String> = [
                                w_br.format_member("br"),
                                w_gzip.format_member("gzip"),
                                w_zstd.format_member("zstd"),
                                w_star.format_member("*"),
                                w_id.format_member("identity"),
                            ]
                            .into_iter()
                            .flatten()
                            .collect();
                            let header = members.join(", ");

                            // Cross-check the string oracle itself against a direct enum-level
                            // truth table (no string parsing at all).
                            let direct_eff = |w: Weight| -> Option<u16> {
                                w.millis().or_else(|| w_star.millis())
                            };
                            let direct_id_ok = direct_eff(w_id).is_none_or(|q| q > 0);
                            let (oracle_id_ok, oracle_list) = oracle_rfc9110(&header);
                            assert_eq!(
                                oracle_id_ok, direct_id_ok,
                                "oracle vs direct identity mismatch for {header:?}"
                            );

                            let negotiated = negotiate_proxy_accept_encoding(&header);
                            assert_eq!(
                                negotiated.identity_acceptable, oracle_id_ok,
                                "identity_acceptable mismatch for {header:?}"
                            );
                            assert_eq!(
                                negotiated.acceptable_codings(),
                                oracle_list.as_slice(),
                                "acceptable_codings mismatch for {header:?}"
                            );

                            let decision = ProxyEncodingDecision::from_header(Some(&header));
                            assert_eq!(decision.identity_acceptable, oracle_id_ok);

                            for path in [
                                ProxyCompressPath::BufferedUnsaturated,
                                ProxyCompressPath::Streamed,
                                ProxyCompressPath::Saturated,
                            ] {
                                let (_, expected) = oracle_proxy_decision(&header, path);
                                let actual = decision.encoding_for(path);
                                assert_eq!(
                                    actual, expected,
                                    "proxy decision mismatch for header={header:?} path={path:?}"
                                );
                            }

                            if oracle_id_ok {
                                // Case (a) invariant: EXACTLY v0.1.4 selection.
                                let v014 = accepted_encodings(&header);
                                assert_eq!(
                                    decision.encoding_for(ProxyCompressPath::BufferedUnsaturated),
                                    v014.first().copied(),
                                    "case (a) buffered must match v0.1.4 for {header:?}"
                                );
                                assert_eq!(
                                    decision.encoding_for(ProxyCompressPath::Streamed),
                                    v014.iter().copied().find(|e| matches!(
                                        e,
                                        ContentEncoding::Brotli | ContentEncoding::Gzip
                                    )),
                                    "case (a) streamed must match v0.1.4 for {header:?}"
                                );
                                assert_eq!(
                                    decision.encoding_for(ProxyCompressPath::Saturated),
                                    None,
                                    "case (a) saturated must shed compression for {header:?}"
                                );
                            } else {
                                identity_excluded_cases += 1;
                                // Case (b) invariant: if a producible coding is acceptable, NEVER identity.
                                let any_buffered = !oracle_list.is_empty();
                                let any_streamable = oracle_list.iter().any(|e| {
                                    matches!(e, ContentEncoding::Brotli | ContentEncoding::Gzip)
                                });
                                assert_eq!(
                                    decision
                                        .encoding_for(ProxyCompressPath::BufferedUnsaturated)
                                        .is_some(),
                                    any_buffered,
                                    "case (b) buffered sent identity despite acceptable coding for {header:?}"
                                );
                                assert_eq!(
                                    decision.encoding_for(ProxyCompressPath::Streamed).is_some(),
                                    any_streamable,
                                    "case (b) streamed sent identity despite acceptable streamable coding for {header:?}"
                                );
                                assert_eq!(
                                    decision
                                        .encoding_for(ProxyCompressPath::Saturated)
                                        .is_some(),
                                    any_streamable,
                                    "case (b) saturated sent identity despite acceptable streamable coding for {header:?}"
                                );
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(total_cases, 1_024);
        // `identity` is excluded iff `identity == q=0` (4^4 = 256) OR (`identity == absent` AND `* == q=0`, 4^3 = 64) => 320 cases.
        assert_eq!(identity_excluded_cases, 320);

        // 1b. Second exhaustive pass: all 4^6 = 4,096 combinations over
        //     {br, gzip, x-gzip, zstd, *, identity} x {absent, q=0, q=0.5, q=1}, proving
        //     RFC 9110 §8.4.1.3 `x-gzip` equivalence (including mixed `gzip` + `x-gzip` weights
        //     and `q=0` contradictions) against BOTH the independent string oracle AND a direct
        //     enum-level truth table with no string parsing at all.
        //
        // Coverage limitation (cannot be observed through `&str` inputs): a wire `Accept-Encoding`
        // field line containing any non-ASCII octet (`obs-text`, 0x80..=0xFF) is dropped whole by
        // `combined_accept_encoding` via `HeaderValue::to_str().ok()` before either parser sees
        // any valid ASCII siblings on that same line. Per RFC 9110 §5.5, generic `field-vchar`
        // allows `obs-text` as opaque data, whereas RFC 9110 §5.6.2 / §12.5.3 restricts
        // `Accept-Encoding` `token` to strictly US-ASCII `tchar`; dropping the whole line is
        // therefore coarser than member-granular recovery on malformed wire lines that mix
        // `obs-text` with valid siblings, though no conforming sender can emit `obs-text` in
        // `Accept-Encoding` (other ASCII-only `Accept-Encoding` lines remain preserved).
        let mut total_cases_6 = 0_usize;
        let mut identity_excluded_cases_6 = 0_usize;
        for w_br in Weight::ALL {
            for w_gzip in Weight::ALL {
                for w_xgzip in Weight::ALL {
                    for w_zstd in Weight::ALL {
                        for w_star in Weight::ALL {
                            for w_id in Weight::ALL {
                                total_cases_6 += 1;
                                let members: Vec<String> = [
                                    w_br.format_member("br"),
                                    w_gzip.format_member("gzip"),
                                    w_xgzip.format_member("x-gzip"),
                                    w_zstd.format_member("zstd"),
                                    w_star.format_member("*"),
                                    w_id.format_member("identity"),
                                ]
                                .into_iter()
                                .flatten()
                                .collect();
                                let header = members.join(", ");

                                // Direct enum-level truth table (zero string parsing) for BOTH
                                // identity acceptability AND the full ordered coding list, with
                                // `gzip` + `x-gzip` combined independently (fail-closed on q=0,
                                // max positive otherwise, wildcard fallback if both absent).
                                let direct_id_ok = w_id
                                    .millis()
                                    .or_else(|| w_star.millis())
                                    .is_none_or(|q| q > 0);
                                let direct_gzip_q = match (w_gzip.millis(), w_xgzip.millis()) {
                                    (Some(0), _) | (_, Some(0)) => Some(0),
                                    (Some(a), Some(b)) => Some(a.max(b)),
                                    (Some(a), None) | (None, Some(a)) => Some(a),
                                    (None, None) => w_star.millis(),
                                };
                                let mut direct_weighted: Vec<(ContentEncoding, u16, u8)> =
                                    Vec::new();
                                for (rank, enc, eff_q) in [
                                    (
                                        0_u8,
                                        ContentEncoding::Zstd,
                                        w_zstd.millis().or_else(|| w_star.millis()),
                                    ),
                                    (
                                        1_u8,
                                        ContentEncoding::Brotli,
                                        w_br.millis().or_else(|| w_star.millis()),
                                    ),
                                    (2_u8, ContentEncoding::Gzip, direct_gzip_q),
                                ] {
                                    if let Some(q) = eff_q
                                        && q > 0
                                    {
                                        direct_weighted.push((enc, q, rank));
                                    }
                                }
                                direct_weighted.sort_by_key(|&(_, q, rank)| (Reverse(q), rank));
                                let direct_list: Vec<ContentEncoding> =
                                    direct_weighted.into_iter().map(|(e, _, _)| e).collect();

                                let (oracle_id_ok, oracle_list) = oracle_rfc9110(&header);
                                assert_eq!(
                                    oracle_id_ok, direct_id_ok,
                                    "6-member oracle vs direct identity mismatch for {header:?}"
                                );
                                assert_eq!(
                                    oracle_list, direct_list,
                                    "6-member oracle vs direct list mismatch for {header:?}"
                                );

                                let negotiated = negotiate_proxy_accept_encoding(&header);
                                assert_eq!(
                                    negotiated.identity_acceptable, direct_id_ok,
                                    "6-member identity_acceptable mismatch for {header:?}"
                                );
                                assert_eq!(
                                    negotiated.acceptable_codings(),
                                    direct_list.as_slice(),
                                    "6-member acceptable_codings mismatch for {header:?}"
                                );

                                let decision = ProxyEncodingDecision::from_header(Some(&header));
                                assert_eq!(decision.identity_acceptable, direct_id_ok);
                                for path in [
                                    ProxyCompressPath::BufferedUnsaturated,
                                    ProxyCompressPath::Streamed,
                                    ProxyCompressPath::Saturated,
                                ] {
                                    let (_, expected) = oracle_proxy_decision(&header, path);
                                    assert_eq!(
                                        decision.encoding_for(path),
                                        expected,
                                        "6-member proxy decision mismatch for {header:?} path={path:?}"
                                    );
                                }
                                if !direct_id_ok {
                                    identity_excluded_cases_6 += 1;
                                    let any_buf = !direct_list.is_empty();
                                    let any_stream = direct_list.iter().any(|e| {
                                        matches!(e, ContentEncoding::Brotli | ContentEncoding::Gzip)
                                    });
                                    assert_eq!(
                                        decision
                                            .encoding_for(ProxyCompressPath::BufferedUnsaturated)
                                            .is_some(),
                                        any_buf
                                    );
                                    assert_eq!(
                                        decision
                                            .encoding_for(ProxyCompressPath::Streamed)
                                            .is_some(),
                                        any_stream
                                    );
                                    assert_eq!(
                                        decision
                                            .encoding_for(ProxyCompressPath::Saturated)
                                            .is_some(),
                                        any_stream
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(total_cases_6, 4_096);
        // `identity` excluded iff `identity == q=0` (4^5 = 1024) OR (`identity == absent` AND `* == q=0`, 4^4 = 256) => 1280.
        assert_eq!(identity_excluded_cases_6, 1_280);

        // 1c. Frozen independent table of v0.1.4's case-(a) answers (ZERO calls to
        //     `accepted_encodings` in expected values) so any later change to the legacy helper
        //     is caught immediately here.
        let frozen_v014_case_a: &[EdgeCase<'_>] = &[
            // Standard browser header
            (
                Some("gzip, deflate, br, zstd"),
                true,
                Some(ContentEncoding::Zstd),
                Some(ContentEncoding::Brotli),
                None,
            ),
            (
                Some("gzip"),
                true,
                Some(ContentEncoding::Gzip),
                Some(ContentEncoding::Gzip),
                None,
            ),
            (
                Some("br"),
                true,
                Some(ContentEncoding::Brotli),
                Some(ContentEncoding::Brotli),
                None,
            ),
            (Some("zstd"), true, Some(ContentEncoding::Zstd), None, None),
            (Some("*"), true, None, None, None),
            (None, true, None, None, None),
            (
                Some("gzip, br"),
                true,
                Some(ContentEncoding::Brotli),
                Some(ContentEncoding::Brotli),
                None,
            ),
            (
                Some("br, gzip"),
                true,
                Some(ContentEncoding::Brotli),
                Some(ContentEncoding::Brotli),
                None,
            ),
            (
                Some("gzip;q=0.5, br"),
                true,
                Some(ContentEncoding::Brotli),
                Some(ContentEncoding::Brotli),
                None,
            ),
            // v0.1.4 prefers server order across positive explicit weights in case (a)
            (
                Some("br;q=0.5, gzip"),
                true,
                Some(ContentEncoding::Brotli),
                Some(ContentEncoding::Brotli),
                None,
            ),
            // v0.1.4 legacy helper does not normalize `x-gzip` when identity is acceptable
            (Some("x-gzip"), true, None, None, None),
            (
                Some("zstd, gzip"),
                true,
                Some(ContentEncoding::Zstd),
                Some(ContentEncoding::Gzip),
                None,
            ),
        ];
        for &(hdr, exp_id_ok, exp_buf, exp_stream, exp_sat) in frozen_v014_case_a {
            let dec = ProxyEncodingDecision::from_header(hdr);
            assert_eq!(
                dec.identity_acceptable, exp_id_ok,
                "frozen v0.1.4 case (a) identity_acceptable mismatch for {hdr:?}"
            );
            assert_eq!(
                dec.encoding_for(ProxyCompressPath::BufferedUnsaturated),
                exp_buf,
                "frozen v0.1.4 case (a) buffered mismatch for {hdr:?}"
            );
            assert_eq!(
                dec.encoding_for(ProxyCompressPath::Streamed),
                exp_stream,
                "frozen v0.1.4 case (a) streamed mismatch for {hdr:?}"
            );
            assert_eq!(
                dec.encoding_for(ProxyCompressPath::Saturated),
                exp_sat,
                "frozen v0.1.4 case (a) saturated mismatch for {hdr:?}"
            );
        }

        // 2. Member-order permutations (all `k!` orders) and two-field-line splits across a sample
        //    including implicit-q=1 forms, explicit weights, wildcards, `x-gzip` alias combinations,
        //    and identity exclusions.
        let permutation_samples: &[&[&str]] = &[
            &["br;q=0", "gzip;q=0", "*;q=1", "identity;q=0"],
            &["gzip;q=0", "*;q=1", "identity;q=0"],
            &["*", "identity;q=0"],
            &["gzip;q=1", "*;q=0.1", "identity;q=0"],
            &["br;q=0.5", "*;q=1", "identity;q=0"],
            &["zstd", "gzip", "identity;q=0"],
            &["zstd", "br;q=0.5", "gzip;q=0.8", "identity;q=0"],
            &["identity;q=0.5", "*;q=0", "br;q=1"],
            &[
                "br;q=0.5",
                "gzip;q=1",
                "zstd;q=0.5",
                "*;q=0.5",
                "identity;q=0",
            ],
            &["x-gzip", "identity;q=0"],
            &["x-gzip;q=0.50", "gzip;q=0.80", "br;q=0.60", "identity;q=0"],
            &["x-gzip;q=0", "gzip;q=1", "identity;q=0"],
            &["x-gzip;q=0", "*;q=1", "identity;q=0"],
            &[
                "X-GZIP;Q=0.75",
                "br;q=0.50",
                "deflate;q=0.90",
                "identity;q=0",
            ],
        ];
        for sample in permutation_samples {
            let baseline_hdr = sample.join(", ");
            let baseline_dec = ProxyEncodingDecision::from_header(Some(&baseline_hdr));
            for perm in permute(sample) {
                let joined = perm.join(", ");
                let dec = ProxyEncodingDecision::from_header(Some(&joined));
                assert_eq!(
                    dec, baseline_dec,
                    "permutation {joined:?} differed from baseline {baseline_hdr:?}"
                );
                for path in [
                    ProxyCompressPath::BufferedUnsaturated,
                    ProxyCompressPath::Streamed,
                    ProxyCompressPath::Saturated,
                ] {
                    let (ok, expected) = oracle_proxy_decision(&joined, path);
                    assert_eq!(dec.identity_acceptable, ok);
                    assert_eq!(dec.encoding_for(path), expected);
                }

                // Every 2-field-line split of this permutation via `combined_accept_encoding`.
                for split_at in 1..perm.len() {
                    let (left, right) = perm.split_at(split_at);
                    let mut hdrs = http::HeaderMap::new();
                    hdrs.append(ACCEPT_ENCODING, HeaderValue::from_str(&left.join(", "))?);
                    hdrs.append(ACCEPT_ENCODING, HeaderValue::from_str(&right.join(", "))?);
                    let combined = super::combined_accept_encoding(&hdrs);
                    let split_dec = ProxyEncodingDecision::from_header(combined.as_deref());
                    assert_eq!(
                        split_dec, baseline_dec,
                        "2-line split ({left:?} | {right:?}) differed from {baseline_hdr:?}"
                    );
                }
            }
        }

        // 3. Malformed / out-of-range weights, parameter errors, case-insensitivity, empty/absent
        //    headers, and contradicting duplicate members.
        let edge_cases: &[EdgeCase<'_>] = &[
            // Absent and empty headers
            (None, true, None, None, None),
            (Some(""), true, None, None, None),
            (Some(" , , "), true, None, None, None),
            // Bare wildcard -> identity acceptable -> exact v0.1.4 (uncompressed)
            (Some("*"), true, None, None, None),
            (Some("*;q=1"), true, None, None, None),
            // Malformed weights reject ONLY that member
            (
                Some("gzip;q=2, br;q=0.5, identity;q=0"),
                false,
                Some(ContentEncoding::Brotli),
                Some(ContentEncoding::Brotli),
                Some(ContentEncoding::Brotli),
            ),
            (Some("*;q=2, identity;q=0"), false, None, None, None),
            (
                Some("gzip;q=0, *;q=2, identity;q=0"),
                false,
                None,
                None,
                None,
            ),
            (
                Some("br;q=-0.5, gzip;q=0.5, identity;q=0"),
                false,
                Some(ContentEncoding::Gzip),
                Some(ContentEncoding::Gzip),
                Some(ContentEncoding::Gzip),
            ),
            (
                Some("br;q=0.1234, gzip;q=0.5, identity;q=0"),
                false,
                Some(ContentEncoding::Gzip),
                Some(ContentEncoding::Gzip),
                Some(ContentEncoding::Gzip),
            ),
            (
                Some("br;q=1.0000, gzip;q=0.5, identity;q=0"),
                false,
                Some(ContentEncoding::Gzip),
                Some(ContentEncoding::Gzip),
                Some(ContentEncoding::Gzip),
            ),
            // Malformed `br;q=1.001` rejected -> `br` is NOT listed -> `*` applies to zstd, br, gzip!
            (
                Some("br;q=1.001, *;q=0.5, identity;q=0"),
                false,
                Some(ContentEncoding::Zstd),
                Some(ContentEncoding::Brotli),
                Some(ContentEncoding::Brotli),
            ),
            (
                Some("gzip;q=1;q=0.5, identity;q=0"),
                false,
                None,
                None,
                None,
            ),
            (Some("gzip;foo=1, identity;q=0"), false, None, None, None),
            (Some("gzip;q= 0.5, identity;q=0"), false, None, None, None),
            (Some("gzip;, identity;q=0"), false, None, None, None),
            (Some("identity;q=2, *;q=0"), false, None, None, None),
            (Some("identity;q=-1"), true, None, None, None),
            // Valid boundary qvalues (`0.`, `1.`, `0.000`, `1.000`, uppercase tokens & `Q=`)
            (
                Some("BR;Q=0.000, GZIP;q=0., *;Q=1., IDENTITY;Q=0."),
                false,
                Some(ContentEncoding::Zstd),
                None,
                None,
            ),
            (
                Some("br;q=1.000, gzip;q=0.999, identity;q=0"),
                false,
                Some(ContentEncoding::Brotli),
                Some(ContentEncoding::Brotli),
                Some(ContentEncoding::Brotli),
            ),
            // Contradicting duplicates fail closed (`q=0` wins), including across `gzip`/`x-gzip`
            (
                Some("gzip, gzip;q=0, identity;q=0"),
                false,
                None,
                None,
                None,
            ),
            (
                Some("gzip;q=1, x-gzip;q=0, identity;q=0"),
                false,
                None,
                None,
                None,
            ),
            (
                Some("x-gzip;q=1, gzip;q=0, identity;q=0"),
                false,
                None,
                None,
                None,
            ),
            // Positive `x-gzip` and `gzip` with different weights take max(q)
            (
                Some("x-gzip;q=0.85, gzip;q=0.40, br;q=0.70, identity;q=0"),
                false,
                Some(ContentEncoding::Gzip),
                Some(ContentEncoding::Gzip),
                Some(ContentEncoding::Gzip),
            ),
            (
                Some("x-gzip;q=0.40, gzip;q=0.85, br;q=0.70, identity;q=0"),
                false,
                Some(ContentEncoding::Gzip),
                Some(ContentEncoding::Gzip),
                Some(ContentEncoding::Gzip),
            ),
            // Explicit `x-gzip;q=0` blocks `*` from re-enabling gzip
            (
                Some("x-gzip;q=0, br;q=0, *;q=1, identity;q=0"),
                false,
                Some(ContentEncoding::Zstd),
                None,
                None,
            ),
            (
                Some("identity, identity;q=0, br"),
                false,
                Some(ContentEncoding::Brotli),
                Some(ContentEncoding::Brotli),
                Some(ContentEncoding::Brotli),
            ),
            (
                Some("*, *;q=0, gzip"),
                false,
                Some(ContentEncoding::Gzip),
                Some(ContentEncoding::Gzip),
                Some(ContentEncoding::Gzip),
            ),
            // Optional whitespace around `;` (allowed by RFC 9110 §12.4.2: `OWS ";" OWS "q=" qvalue`)
            (
                Some("br ; q=0.50 , x-gzip\t;\tq=0.75 , identity ; q=0"),
                false,
                Some(ContentEncoding::Gzip),
                Some(ContentEncoding::Gzip),
                Some(ContentEncoding::Gzip),
            ),
            (
                Some(" \t x-gzip \t ; \t Q=0.25 \t , \t br ;q=0.24 , identity\t;q=0 "),
                false,
                Some(ContentEncoding::Gzip),
                Some(ContentEncoding::Gzip),
                Some(ContentEncoding::Gzip),
            ),
            // Whitespace around `=` is FORBIDDEN by RFC 9110 §12.4.2 (`"q=" qvalue`) -> member rejected
            (Some("gzip;q =0.5, identity;q=0"), false, None, None, None),
            (Some("gzip;q = 0.5, identity;q=0"), false, None, None, None),
            (
                Some("x-gzip;Q\t=0.5, br;q=0.25, identity;q=0"),
                false,
                Some(ContentEncoding::Brotli),
                Some(ContentEncoding::Brotli),
                Some(ContentEncoding::Brotli),
            ),
            (
                Some("x-gzip;q=\t0.5, br;q=0.25, identity;q=0"),
                false,
                Some(ContentEncoding::Brotli),
                Some(ContentEncoding::Brotli),
                Some(ContentEncoding::Brotli),
            ),
            // Unknown codings beside known codings (and unregistered/unproduced aliases)
            (
                Some(
                    "deflate, compress, x-compress, lz4;q=1, foo-bar;q=0.95, x-gzip;q=0.40, identity;q=0",
                ),
                false,
                Some(ContentEncoding::Gzip),
                Some(ContentEncoding::Gzip),
                Some(ContentEncoding::Gzip),
            ),
            (
                Some("deflate;q=1, x-compress;q=1, identity;q=0"),
                false,
                None,
                None,
                None,
            ),
            (
                Some("deflate;q=0, *;q=0.50, identity;q=0"),
                false,
                Some(ContentEncoding::Zstd),
                Some(ContentEncoding::Brotli),
                Some(ContentEncoding::Brotli),
            ),
            (
                Some("unknown-coding;q=not-a-num, x-gzip;q=0.55, identity;q=0"),
                false,
                Some(ContentEncoding::Gzip),
                Some(ContentEncoding::Gzip),
                Some(ContentEncoding::Gzip),
            ),
            // Close unequal milliweights & two-decimal vs three-decimal ties
            (
                Some("br;q=0.500, gzip;q=0.501, identity;q=0"),
                false,
                Some(ContentEncoding::Gzip),
                Some(ContentEncoding::Gzip),
                Some(ContentEncoding::Gzip),
            ),
            (
                Some("zstd;q=0.998, br;q=0.999, identity;q=0"),
                false,
                Some(ContentEncoding::Brotli),
                Some(ContentEncoding::Brotli),
                Some(ContentEncoding::Brotli),
            ),
            (
                Some("gzip;q=0.001, zstd;q=0.000, identity;q=0"),
                false,
                Some(ContentEncoding::Gzip),
                Some(ContentEncoding::Gzip),
                Some(ContentEncoding::Gzip),
            ),
            (
                Some("br;q=0.12, x-gzip;q=0.120, identity;q=0"),
                false,
                Some(ContentEncoding::Brotli),
                Some(ContentEncoding::Brotli),
                Some(ContentEncoding::Brotli),
            ),
        ];

        for &(hdr, exp_id_ok, exp_buf, exp_stream, exp_sat) in edge_cases {
            let dec = ProxyEncodingDecision::from_header(hdr);
            assert_eq!(
                dec.identity_acceptable, exp_id_ok,
                "edge case identity_acceptable mismatch for {hdr:?}"
            );
            assert_eq!(
                dec.encoding_for(ProxyCompressPath::BufferedUnsaturated),
                exp_buf,
                "edge case buffered mismatch for {hdr:?}"
            );
            assert_eq!(
                dec.encoding_for(ProxyCompressPath::Streamed),
                exp_stream,
                "edge case streamed mismatch for {hdr:?}"
            );
            assert_eq!(
                dec.encoding_for(ProxyCompressPath::Saturated),
                exp_sat,
                "edge case saturated mismatch for {hdr:?}"
            );
            if let Some(s) = hdr {
                for path in [
                    ProxyCompressPath::BufferedUnsaturated,
                    ProxyCompressPath::Streamed,
                    ProxyCompressPath::Saturated,
                ] {
                    let (ok, expected) = oracle_proxy_decision(s, path);
                    assert_eq!(dec.identity_acceptable, ok, "oracle id mismatch for {s:?}");
                    assert_eq!(
                        dec.encoding_for(path),
                        expected,
                        "oracle path={path:?} mismatch for {s:?}"
                    );
                }
            }
        }

        // 4. Systematic two-decimal weights across all pairs from a 10-point grid
        //    (`0.00..=1.00`), comparing `br` vs `x-gzip` and `zstd` vs `gzip` with an unknown
        //    coding present alongside.
        let two_dec_weights: &[(&str, u16)] = &[
            ("0.00", 0),
            ("0.01", 10),
            ("0.09", 90),
            ("0.10", 100),
            ("0.25", 250),
            ("0.50", 500),
            ("0.51", 510),
            ("0.75", 750),
            ("0.99", 990),
            ("1.00", 1_000),
        ];
        for &(s_a, m_a) in two_dec_weights {
            for &(s_b, m_b) in two_dec_weights {
                let hdr_bx = format!("deflate;q=0.80, br;q={s_a}, x-gzip;q={s_b}, identity;q=0");
                let dec_bx = ProxyEncodingDecision::from_header(Some(&hdr_bx));
                let expected_bx = match (m_a > 0, m_b > 0) {
                    (false, false) => None,
                    (true, false) => Some(ContentEncoding::Brotli),
                    (false, true) => Some(ContentEncoding::Gzip),
                    // Server tie-break: br > gzip when weights are equal
                    (true, true) => Some(if m_a >= m_b {
                        ContentEncoding::Brotli
                    } else {
                        ContentEncoding::Gzip
                    }),
                };
                for path in [
                    ProxyCompressPath::BufferedUnsaturated,
                    ProxyCompressPath::Streamed,
                    ProxyCompressPath::Saturated,
                ] {
                    assert_eq!(
                        dec_bx.encoding_for(path),
                        expected_bx,
                        "two-decimal grid mismatch for {hdr_bx:?} path={path:?}"
                    );
                    let (ok, oracle_exp) = oracle_proxy_decision(&hdr_bx, path);
                    assert!(!ok);
                    assert_eq!(oracle_exp, expected_bx);
                }

                let hdr_zg = format!("zstd ; q={s_a} , gzip\t;\tq={s_b} , identity;q=0");
                let dec_zg = ProxyEncodingDecision::from_header(Some(&hdr_zg));
                let expected_buf = match (m_a > 0, m_b > 0) {
                    (false, false) => None,
                    (true, false) => Some(ContentEncoding::Zstd),
                    (false, true) => Some(ContentEncoding::Gzip),
                    // Server tie-break: zstd > gzip when weights are equal
                    (true, true) => Some(if m_a >= m_b {
                        ContentEncoding::Zstd
                    } else {
                        ContentEncoding::Gzip
                    }),
                };
                let expected_stream = (m_b > 0).then_some(ContentEncoding::Gzip);
                assert_eq!(
                    dec_zg.encoding_for(ProxyCompressPath::BufferedUnsaturated),
                    expected_buf,
                    "two-decimal OWS grid buffered mismatch for {hdr_zg:?}"
                );
                assert_eq!(
                    dec_zg.encoding_for(ProxyCompressPath::Streamed),
                    expected_stream,
                    "two-decimal OWS grid streamed mismatch for {hdr_zg:?}"
                );
                assert_eq!(
                    dec_zg.encoding_for(ProxyCompressPath::Saturated),
                    expected_stream,
                    "two-decimal OWS grid saturated mismatch for {hdr_zg:?}"
                );
                for path in [
                    ProxyCompressPath::BufferedUnsaturated,
                    ProxyCompressPath::Streamed,
                    ProxyCompressPath::Saturated,
                ] {
                    let (ok, oracle_exp) = oracle_proxy_decision(&hdr_zg, path);
                    assert!(!ok);
                    assert_eq!(dec_zg.encoding_for(path), oracle_exp);
                }
            }
        }

        Ok(())
    }

    /// At compression saturation (all permits busy AND waiter byte budget full):
    /// - When `identity` is excluded (`identity;q=0` or `*;q=0`) and `br`/`gzip` is accepted
    ///   (including across multiple `Accept-Encoding` field lines or via positive wildcard `*;q>0`),
    ///   MiraServe compresses via `YieldingStreamingCompressedBody` over the buffered body;
    /// - When `identity` is allowed, MiraServe falls back to uncompressed with `Vary: Accept-Encoding`;
    /// - When `identity` is excluded and no streamable coding can be produced (e.g. `zstd, identity;q=0`),
    ///   MiraServe NEVER replaces the upstream response with `406` — it preserves the upstream
    ///   status and sends the body uncompressed with `Vary: Accept-Encoding` (matching v0.1.4).
    /// - Outside saturation, a successful compression larger than the input is still sent when
    ///   `identity` is excluded.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn p2_2_compression_saturation_respects_identity_q0_and_wildcard_q0()
    -> Result<(), Box<dyn std::error::Error>> {
        use http::header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, VARY};
        use http_body_util::BodyExt as _;

        let _serial = COMPRESS_POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let nb_ctx = miraserve_static::enter_nonblocking_inline_context();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let permits = u32::try_from(super::WORKER_LOOP_COMPRESS_JOBS).unwrap_or(8);

        let payload = Bytes::from(vec![b'B'; 256 * 1024]);
        let make_resp_with_status = |status: StatusCode, body: &Bytes| {
            let mut resp = Response::new(full_http_body(body.clone()));
            *resp.status_mut() = status;
            resp.headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
            if let Ok(len_v) = HeaderValue::from_str(&body.len().to_string()) {
                resp.headers_mut().insert(CONTENT_LENGTH, len_v);
            }
            resp
        };
        let make_resp = |body: &Bytes| make_resp_with_status(StatusCode::OK, body);

        // Limit waiter bytes to 300 KiB: waiter_a holds 256 KiB; subsequent 256 KiB requests hit
        // saturation immediately.
        let _budget_guard = super::test_compress_waiter_budget_override_guard(300 * 1024);
        rt.block_on(async {
            let all = Arc::clone(super::worker_compress_semaphore())
                .acquire_many_owned(permits)
                .await?;

            let mut waiter_a = Box::pin(maybe_compress_proxied_response(
                Some("gzip"),
                &Method::GET,
                make_resp(&payload),
            ));
            let poll_a =
                tokio::time::timeout(std::time::Duration::from_millis(50), waiter_a.as_mut()).await;
            assert!(poll_a.is_err(), "waiter_a must park waiting for a permit");

            // 1. `Accept-Encoding: gzip, identity;q=0` -> MUST compress via yielding stream body.
            let (_, stream_before) = super::test_proxy_compress_stats();
            let resp_gzip_no_id = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                maybe_compress_proxied_response(
                    Some("gzip, identity;q=0"),
                    &Method::GET,
                    make_resp(&payload),
                ),
            )
            .await?;
            assert_eq!(resp_gzip_no_id.status(), StatusCode::OK);
            assert_eq!(
                resp_gzip_no_id
                    .headers()
                    .get(CONTENT_ENCODING)
                    .and_then(|v| v.to_str().ok()),
                Some("gzip"),
                "gzip with identity;q=0 at saturation must NOT send identity"
            );
            assert!(
                resp_gzip_no_id
                    .headers()
                    .get_all(VARY)
                    .iter()
                    .any(|v| v.to_str().is_ok_and(|s| s.contains("Accept-Encoding")))
            );
            let (_, stream_after) = super::test_proxy_compress_stats();
            assert_eq!(
                stream_after,
                stream_before + 1,
                "saturated identity;q=0 must use YieldingStreamingCompressedBody"
            );
            let compressed_body = resp_gzip_no_id.into_body().collect().await?.to_bytes();
            let decoded = miraserve_static::compress::decompress_gzip(&compressed_body)?;
            assert_eq!(decoded, payload.as_ref());

            // 2. `Accept-Encoding: gzip, *;q=0` -> identity excluded via wildcard -> MUST compress.
            let resp_star_q0 = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                maybe_compress_proxied_response(
                    Some("gzip, *;q=0"),
                    &Method::GET,
                    make_resp(&payload),
                ),
            )
            .await?;
            assert_eq!(resp_star_q0.status(), StatusCode::OK);
            assert_eq!(
                resp_star_q0
                    .headers()
                    .get(CONTENT_ENCODING)
                    .and_then(|v| v.to_str().ok()),
                Some("gzip"),
                "gzip with *;q=0 (no explicit identity) at saturation must NOT send identity"
            );
            let decoded_star = miraserve_static::compress::decompress_gzip(
                &resp_star_q0.into_body().collect().await?.to_bytes(),
            )?;
            assert_eq!(decoded_star, payload.as_ref());

            // 3. `Accept-Encoding: gzip, identity;q=0.5, *;q=0` -> explicit identity allowed ->
            //    uncompressed fallback with Vary: Accept-Encoding.
            let resp_explicit_id = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                maybe_compress_proxied_response(
                    Some("gzip, identity;q=0.5, *;q=0"),
                    &Method::GET,
                    make_resp(&payload),
                ),
            )
            .await?;
            assert_eq!(resp_explicit_id.status(), StatusCode::OK);
            assert!(resp_explicit_id.headers().get(CONTENT_ENCODING).is_none());
            assert_eq!(
                resp_explicit_id.into_body().collect().await?.to_bytes(),
                payload
            );

            // 4. `Accept-Encoding: zstd, identity;q=0` on a committed POST (`201 Created`):
            //    zstd has no incremental StreamCompressor; NEVER replace with 406 — preserve
            //    upstream status and send uncompressed with Vary: Accept-Encoding.
            let resp_zstd_no_id = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                maybe_compress_proxied_response(
                    Some("zstd, identity;q=0"),
                    &Method::POST,
                    make_resp_with_status(StatusCode::CREATED, &payload),
                ),
            )
            .await?;
            assert_eq!(resp_zstd_no_id.status(), StatusCode::CREATED);
            assert!(resp_zstd_no_id.headers().get(CONTENT_ENCODING).is_none());
            assert!(
                resp_zstd_no_id
                    .headers()
                    .get_all(VARY)
                    .iter()
                    .any(|v| v.to_str().is_ok_and(|s| s.contains("Accept-Encoding")))
            );
            assert_eq!(
                resp_zstd_no_id.into_body().collect().await?.to_bytes(),
                payload
            );

            // 5. Two `Accept-Encoding` field lines in both orders -> combined per RFC 9110 §5.2
            //    -> yielding gzip fallback (never uncompressed or 406).
            for pair in [
                ["zstd, identity;q=0", "gzip"],
                ["gzip", "zstd, identity;q=0"],
            ] {
                let mut hdrs = http::HeaderMap::new();
                for line in pair {
                    hdrs.append(ACCEPT_ENCODING, HeaderValue::from_str(line)?);
                }
                let combined = super::combined_accept_encoding(&hdrs);
                let resp_two = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    maybe_compress_proxied_response(
                        combined.as_deref(),
                        &Method::GET,
                        make_resp(&payload),
                    ),
                )
                .await?;
                assert_eq!(resp_two.status(), StatusCode::OK);
                assert_eq!(
                    resp_two
                        .headers()
                        .get(CONTENT_ENCODING)
                        .and_then(|v| v.to_str().ok()),
                    Some("gzip"),
                    "two Accept-Encoding lines {pair:?} must select yielding gzip at saturation"
                );
                let dec = miraserve_static::compress::decompress_gzip(
                    &resp_two.into_body().collect().await?.to_bytes(),
                )?;
                assert_eq!(dec, payload.as_ref());
            }

            // 6. Positive wildcard cases at saturation — BOTH with explicit `zstd` AND with
            //    empty `accepted_encodings` (Codex audit-5 acceptance test: upstream `201 Created`
            //    with 128 KiB compressible JSON, exact headers `gzip;q=0, *;q=1, identity;q=0`
            //    and `*;q=1, identity;q=0`, plus relative-weight `gzip;q=1, *;q=0.1, identity;q=0`).
            for hdr in [
                "zstd, *;q=1, identity;q=0",
                "zstd, gzip;q=0, *;q=1, identity;q=0",
            ] {
                let resp_wc = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    maybe_compress_proxied_response(Some(hdr), &Method::GET, make_resp(&payload)),
                )
                .await?;
                assert_eq!(resp_wc.status(), StatusCode::OK);
                assert_eq!(
                    resp_wc
                        .headers()
                        .get(CONTENT_ENCODING)
                        .and_then(|v| v.to_str().ok()),
                    Some("br"),
                    "wildcard Accept-Encoding {hdr:?} must select yielding Brotli at saturation"
                );
                let dec = miraserve_static::compress::decompress_brotli(
                    &resp_wc.into_body().collect().await?.to_bytes(),
                )?;
                assert_eq!(dec, payload.as_ref());
            }

            // Codex acceptance test: 128 KiB compressible JSON, upstream `201 Created`, at
            // saturation (all 8 permits busy and waiter byte budget exceeded: waiter_a holds
            // 256 KiB of the 300 KiB budget, so 128 KiB exceeds 300 KiB immediately).
            let mut json_128k = Vec::with_capacity(128 * 1024);
            while json_128k.len() < 128 * 1024 {
                json_128k.extend_from_slice(br#"{"status":"created","service":"miraserve"}"#);
                json_128k.push(b'\n');
            }
            json_128k.truncate(128 * 1024);
            let json_128k = Bytes::from(json_128k);
            let make_json_201 = |body: &Bytes| {
                let mut resp = Response::new(full_http_body(body.clone()));
                *resp.status_mut() = StatusCode::CREATED;
                resp.headers_mut()
                    .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                if let Ok(len_v) = HeaderValue::from_str(&body.len().to_string()) {
                    resp.headers_mut().insert(CONTENT_LENGTH, len_v);
                }
                resp
            };
            for hdr in ["gzip;q=0, *;q=1, identity;q=0", "*;q=1, identity;q=0"] {
                let (_, stream_before_wc) = super::test_proxy_compress_stats();
                let resp_wc = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    maybe_compress_proxied_response(
                        Some(hdr),
                        &Method::POST,
                        make_json_201(&json_128k),
                    ),
                )
                .await?;
                assert_eq!(resp_wc.status(), StatusCode::CREATED);
                assert_eq!(
                    resp_wc
                        .headers()
                        .get(CONTENT_ENCODING)
                        .and_then(|v| v.to_str().ok()),
                    Some("br"),
                    "wildcard Accept-Encoding {hdr:?} must NOT take early return at saturation"
                );
                assert!(
                    resp_wc
                        .headers()
                        .get_all(VARY)
                        .iter()
                        .any(|v| v.to_str().is_ok_and(|s| s.contains("Accept-Encoding")))
                );
                let (_, stream_after_wc) = super::test_proxy_compress_stats();
                assert_eq!(
                    stream_after_wc,
                    stream_before_wc + 1,
                    "saturated wildcard {hdr:?} must reach YieldingStreamingCompressedBody"
                );
                let dec = miraserve_static::compress::decompress_brotli(
                    &resp_wc.into_body().collect().await?.to_bytes(),
                )?;
                assert_eq!(dec, json_128k.as_ref());
            }

            // Relative weight at saturation: `gzip;q=1, *;q=0.1, identity;q=0` prefers gzip.
            let resp_weighted = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                maybe_compress_proxied_response(
                    Some("gzip;q=1, *;q=0.1, identity;q=0"),
                    &Method::POST,
                    make_json_201(&json_128k),
                ),
            )
            .await?;
            assert_eq!(resp_weighted.status(), StatusCode::CREATED);
            assert_eq!(
                resp_weighted
                    .headers()
                    .get(CONTENT_ENCODING)
                    .and_then(|v| v.to_str().ok()),
                Some("gzip"),
                "relative weight gzip;q=1 > *;q=0.1 must select gzip at saturation"
            );
            let dec_weighted = miraserve_static::compress::decompress_gzip(
                &resp_weighted.into_body().collect().await?.to_bytes(),
            )?;
            assert_eq!(dec_weighted, json_128k.as_ref());

            // Round 8 P1 (`x-gzip` alias, RFC 9110 §8.4.1.3): at saturation, `x-gzip, identity;q=0`
            // must compress incrementally as canonical `Content-Encoding: gzip` with `Vary`.
            let (_, stream_before_xgz) = super::test_proxy_compress_stats();
            let resp_sat_xgzip = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                maybe_compress_proxied_response(
                    Some("x-gzip, identity;q=0"),
                    &Method::POST,
                    make_json_201(&json_128k),
                ),
            )
            .await?;
            assert_eq!(resp_sat_xgzip.status(), StatusCode::CREATED);
            assert_eq!(
                resp_sat_xgzip
                    .headers()
                    .get(CONTENT_ENCODING)
                    .and_then(|v| v.to_str().ok()),
                Some("gzip"),
                "saturated x-gzip, identity;q=0 must emit canonical Content-Encoding: gzip"
            );
            assert!(
                resp_sat_xgzip
                    .headers()
                    .get_all(VARY)
                    .iter()
                    .any(|v| v.to_str().is_ok_and(|s| s.contains("Accept-Encoding")))
            );
            let (_, stream_after_xgz) = super::test_proxy_compress_stats();
            assert_eq!(stream_after_xgz, stream_before_xgz + 1);
            assert_eq!(
                miraserve_static::compress::decompress_gzip(
                    &resp_sat_xgzip.into_body().collect().await?.to_bytes(),
                )?,
                json_128k.as_ref()
            );

            // Normal eligibility guards MUST still apply when wildcard bypasses the early return.
            for (method, status, extra_hdr, body_bytes) in [
                (Method::HEAD, StatusCode::OK, None, json_128k.clone()),
                (Method::GET, StatusCode::NO_CONTENT, None, Bytes::new()),
                (Method::GET, StatusCode::NOT_MODIFIED, None, Bytes::new()),
                (
                    Method::GET,
                    StatusCode::PARTIAL_CONTENT,
                    None,
                    json_128k.clone(),
                ),
                (
                    Method::GET,
                    StatusCode::OK,
                    Some((CONTENT_ENCODING, "deflate")),
                    json_128k.clone(),
                ),
                (
                    Method::GET,
                    StatusCode::OK,
                    Some((http::header::CONTENT_RANGE, "bytes 0-99/200")),
                    json_128k.clone(),
                ),
                (
                    Method::GET,
                    StatusCode::OK,
                    None,
                    Bytes::from_static(b"tiny-below-min-compress-bytes"),
                ),
            ] {
                let mut r = make_resp_with_status(status, &body_bytes);
                if let Some((ref k, v)) = extra_hdr {
                    r.headers_mut()
                        .insert(k.clone(), HeaderValue::from_static(v));
                }
                let out = maybe_compress_proxied_response(
                    Some("gzip;q=0, *;q=1, identity;q=0"),
                    &method,
                    r,
                )
                .await;
                assert_eq!(out.status(), status);
                let expected_ce = extra_hdr
                    .as_ref()
                    .and_then(|(k, v)| (*k == CONTENT_ENCODING).then_some(*v));
                assert_eq!(
                    out.headers()
                        .get(CONTENT_ENCODING)
                        .and_then(|v| v.to_str().ok()),
                    expected_ce,
                    "eligibility guard must prevent wildcard compression for {method} {status} {extra_hdr:?}"
                );
            }

            drop(waiter_a);
            drop(all);

            // 7. Outside saturation:
            //    (a) Codex Round-6 acceptance test: `br;q=0, gzip;q=0, *;q=1, identity;q=0`,
            //        upstream `201 Created`, 128 KiB compressible JSON with `Content-Length`:
            //        assert `201`, `Content-Encoding: zstd`, `Vary: Accept-Encoding`, decoded bytes
            //        equal (and same server preference `zstd > br > gzip` for `gzip;q=0, *;q=1,
            //        identity;q=0` and `*;q=1, identity;q=0`, plus `zstd;q=0` -> `br`);
            //    (b) unknown-length streamed path with `br;q=0, gzip;q=0, *;q=1, identity;q=0`
            //        preserves `201` uncompressed with `Vary: Accept-Encoding` (residual) while
            //        `gzip;q=0, *;q=1, identity;q=0` streams `br`;
            //    (c) wildcard with identity allowed (`*`) keeps v0.1.4's uncompressed answer;
            //    (d) a successful compression larger than the input is still sent when `identity`
            //        is excluded (round-3 behavior preserved).
            for hdr in [
                "br;q=0, gzip;q=0, *;q=1, identity;q=0",
                "gzip;q=0, *;q=1, identity;q=0",
                "*;q=1, identity;q=0",
            ] {
                let resp_unsat = maybe_compress_proxied_response(
                    Some(hdr),
                    &Method::POST,
                    make_json_201(&json_128k),
                )
                .await;
                assert_eq!(resp_unsat.status(), StatusCode::CREATED);
                assert_eq!(
                    resp_unsat
                        .headers()
                        .get(CONTENT_ENCODING)
                        .and_then(|v| v.to_str().ok()),
                    Some("zstd"),
                    "outside saturation, {hdr:?} must compress with zstd (server preference zstd > br > gzip)"
                );
                assert!(
                    resp_unsat
                        .headers()
                        .get_all(VARY)
                        .iter()
                        .any(|v| v.to_str().is_ok_and(|s| s.contains("Accept-Encoding"))),
                    "outside saturation, {hdr:?} must emit Vary: Accept-Encoding"
                );
                let dec_unsat = miraserve_static::compress::decompress_zstd(
                    &resp_unsat.into_body().collect().await?.to_bytes(),
                )?;
                assert_eq!(dec_unsat, json_128k.as_ref());
            }

            // Streamed (unknown Content-Length) path with wildcard + identity excluded:
            // - `br;q=0, gzip;q=0, *;q=1, identity;q=0` -> only zstd acceptable (not streamable) ->
            //   documented residual: upstream 201 preserved uncompressed with Vary.
            let mut streamed_zstd_only = Response::new(full_http_body(json_128k.clone()));
            *streamed_zstd_only.status_mut() = StatusCode::CREATED;
            streamed_zstd_only
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            let out_stream_zstd = maybe_compress_proxied_response(
                Some("br;q=0, gzip;q=0, *;q=1, identity;q=0"),
                &Method::POST,
                streamed_zstd_only,
            )
            .await;
            assert_eq!(out_stream_zstd.status(), StatusCode::CREATED);
            assert!(out_stream_zstd.headers().get(CONTENT_ENCODING).is_none());
            assert!(
                out_stream_zstd
                    .headers()
                    .get_all(VARY)
                    .iter()
                    .any(|v| v.to_str().is_ok_and(|s| s.contains("Accept-Encoding")))
            );
            assert_eq!(
                out_stream_zstd.into_body().collect().await?.to_bytes(),
                json_128k
            );

            // - `gzip;q=0, *;q=1, identity;q=0` on unknown-length streamed path -> `br`.
            let mut streamed_br = Response::new(full_http_body(json_128k.clone()));
            *streamed_br.status_mut() = StatusCode::CREATED;
            streamed_br
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            let out_stream_br = maybe_compress_proxied_response(
                Some("gzip;q=0, *;q=1, identity;q=0"),
                &Method::POST,
                streamed_br,
            )
            .await;
            assert_eq!(out_stream_br.status(), StatusCode::CREATED);
            assert_eq!(
                out_stream_br
                    .headers()
                    .get(CONTENT_ENCODING)
                    .and_then(|v| v.to_str().ok()),
                Some("br")
            );
            assert_eq!(
                miraserve_static::compress::decompress_brotli(
                    &out_stream_br.into_body().collect().await?.to_bytes(),
                )?,
                json_128k.as_ref()
            );

            // Round 8 P1 (`x-gzip`, RFC 9110 §8.4.1.3): unsaturated (non-blocking context) and
            // streamed unknown-length with `x-gzip, identity;q=0` -> canonical `Content-Encoding: gzip`,
            // `Vary: Accept-Encoding`, decoded bytes equal.
            let resp_unsat_xgzip = maybe_compress_proxied_response(
                Some("x-gzip, identity;q=0"),
                &Method::POST,
                make_json_201(&json_128k),
            )
            .await;
            assert_eq!(resp_unsat_xgzip.status(), StatusCode::CREATED);
            assert_eq!(
                resp_unsat_xgzip
                    .headers()
                    .get(CONTENT_ENCODING)
                    .and_then(|v| v.to_str().ok()),
                Some("gzip"),
                "unsaturated non-blocking x-gzip, identity;q=0 must emit Content-Encoding: gzip"
            );
            assert!(
                resp_unsat_xgzip
                    .headers()
                    .get_all(VARY)
                    .iter()
                    .any(|v| v.to_str().is_ok_and(|s| s.contains("Accept-Encoding")))
            );
            assert_eq!(
                miraserve_static::compress::decompress_gzip(
                    &resp_unsat_xgzip.into_body().collect().await?.to_bytes(),
                )?,
                json_128k.as_ref()
            );

            let mut streamed_xgzip = Response::new(full_http_body(json_128k.clone()));
            *streamed_xgzip.status_mut() = StatusCode::CREATED;
            streamed_xgzip
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            let out_stream_xgzip = maybe_compress_proxied_response(
                Some("x-gzip, identity;q=0"),
                &Method::POST,
                streamed_xgzip,
            )
            .await;
            assert_eq!(out_stream_xgzip.status(), StatusCode::CREATED);
            assert_eq!(
                out_stream_xgzip
                    .headers()
                    .get(CONTENT_ENCODING)
                    .and_then(|v| v.to_str().ok()),
                Some("gzip"),
                "streamed x-gzip, identity;q=0 must emit Content-Encoding: gzip"
            );
            assert!(
                out_stream_xgzip
                    .headers()
                    .get_all(VARY)
                    .iter()
                    .any(|v| v.to_str().is_ok_and(|s| s.contains("Accept-Encoding")))
            );
            assert_eq!(
                miraserve_static::compress::decompress_gzip(
                    &out_stream_xgzip.into_body().collect().await?.to_bytes(),
                )?,
                json_128k.as_ref()
            );

            // Also verify Codex Round-6 & Round-8 acceptance tests on the ordinary shared-runtime
            // spawned path (NO non-blocking inline context active).
            drop(nb_ctx);
            let resp_shared_xgzip = maybe_compress_proxied_response(
                Some("x-gzip, identity;q=0"),
                &Method::POST,
                make_json_201(&json_128k),
            )
            .await;
            assert_eq!(resp_shared_xgzip.status(), StatusCode::CREATED);
            assert_eq!(
                resp_shared_xgzip
                    .headers()
                    .get(CONTENT_ENCODING)
                    .and_then(|v| v.to_str().ok()),
                Some("gzip"),
                "ordinary spawned shared-runtime x-gzip, identity;q=0 must emit Content-Encoding: gzip"
            );
            assert!(
                resp_shared_xgzip
                    .headers()
                    .get_all(VARY)
                    .iter()
                    .any(|v| v.to_str().is_ok_and(|s| s.contains("Accept-Encoding")))
            );
            assert_eq!(
                miraserve_static::compress::decompress_gzip(
                    &resp_shared_xgzip.into_body().collect().await?.to_bytes(),
                )?,
                json_128k.as_ref()
            );

            let resp_shared_zstd = maybe_compress_proxied_response(
                Some("br;q=0, gzip;q=0, *;q=1, identity;q=0"),
                &Method::POST,
                make_json_201(&json_128k),
            )
            .await;
            assert_eq!(resp_shared_zstd.status(), StatusCode::CREATED);
            assert_eq!(
                resp_shared_zstd
                    .headers()
                    .get(CONTENT_ENCODING)
                    .and_then(|v| v.to_str().ok()),
                Some("zstd"),
                "ordinary spawned shared-runtime path must compress br;q=0, gzip;q=0, *;q=1, identity;q=0 with zstd"
            );
            assert!(
                resp_shared_zstd
                    .headers()
                    .get_all(VARY)
                    .iter()
                    .any(|v| v.to_str().is_ok_and(|s| s.contains("Accept-Encoding")))
            );
            assert_eq!(
                miraserve_static::compress::decompress_zstd(
                    &resp_shared_zstd.into_body().collect().await?.to_bytes(),
                )?,
                json_128k.as_ref()
            );

            // Bare `x-gzip` (case (a), identity acceptable): stays v0.1.4 uncompressed with Vary.
            let resp_xgzip_only = maybe_compress_proxied_response(
                Some("x-gzip"),
                &Method::GET,
                make_json_201(&json_128k),
            )
            .await;
            assert_eq!(resp_xgzip_only.status(), StatusCode::CREATED);
            assert!(resp_xgzip_only.headers().get(CONTENT_ENCODING).is_none());
            assert!(
                resp_xgzip_only
                    .headers()
                    .get_all(VARY)
                    .iter()
                    .any(|v| v.to_str().is_ok_and(|s| s.contains("Accept-Encoding")))
            );
            assert_eq!(
                resp_xgzip_only.into_body().collect().await?.to_bytes(),
                json_128k
            );

            let resp_star_only =
                maybe_compress_proxied_response(Some("*"), &Method::GET, make_json_201(&json_128k))
                    .await;
            assert_eq!(resp_star_only.status(), StatusCode::CREATED);
            assert!(
                resp_star_only.headers().get(CONTENT_ENCODING).is_none(),
                "outside saturation with identity allowed (`*`), v0.1.4 uncompressed behavior holds"
            );
            assert!(
                resp_star_only
                    .headers()
                    .get_all(VARY)
                    .iter()
                    .any(|v| v.to_str().is_ok_and(|s| s.contains("Accept-Encoding")))
            );
            assert_eq!(
                resp_star_only.into_body().collect().await?.to_bytes(),
                json_128k
            );

            // Round 8 P1 (`Vary: Accept-Encoding` on expanded-therefore-identity):
            // Request `gzip` first (expanded -> identity MUST still carry `Vary: Accept-Encoding`
            // so a shared cache never hands it to a `gzip, identity;q=0` client), then request
            // `gzip, identity;q=0` (compressed `gzip`, also carrying `Vary: Accept-Encoding`).
            let mut incompressible = Vec::with_capacity(2048);
            let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
            for _ in 0..2048 {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                incompressible.push((state >> 56) as u8);
            }
            let incompressible = Bytes::from(incompressible);

            let resp_expanded_identity = maybe_compress_proxied_response(
                Some("gzip"),
                &Method::GET,
                make_resp(&incompressible),
            )
            .await;
            assert_eq!(resp_expanded_identity.status(), StatusCode::OK);
            assert!(
                resp_expanded_identity
                    .headers()
                    .get(CONTENT_ENCODING)
                    .is_none(),
                "expanded compressed output with identity allowed returns identity"
            );
            assert!(
                resp_expanded_identity
                    .headers()
                    .get_all(VARY)
                    .iter()
                    .any(|v| v.to_str().is_ok_and(|s| s.contains("Accept-Encoding"))),
                "expanded-therefore-identity response MUST still carry Vary: Accept-Encoding"
            );
            assert_eq!(
                resp_expanded_identity
                    .into_body()
                    .collect()
                    .await?
                    .to_bytes(),
                incompressible
            );

            let resp_larger = maybe_compress_proxied_response(
                Some("gzip, identity;q=0"),
                &Method::GET,
                make_resp(&incompressible),
            )
            .await;
            assert_eq!(resp_larger.status(), StatusCode::OK);
            assert_eq!(
                resp_larger
                    .headers()
                    .get(CONTENT_ENCODING)
                    .and_then(|v| v.to_str().ok()),
                Some("gzip"),
                "larger compressed output must still be sent when identity is excluded"
            );
            assert!(
                resp_larger
                    .headers()
                    .get_all(VARY)
                    .iter()
                    .any(|v| v.to_str().is_ok_and(|s| s.contains("Accept-Encoding"))),
                "incompressible gzip, identity;q=0 response MUST carry Vary: Accept-Encoding"
            );
            let dec_larger = miraserve_static::compress::decompress_gzip(
                &resp_larger.into_body().collect().await?.to_bytes(),
            )?;
            assert_eq!(dec_larger, incompressible.as_ref());

            Ok::<_, Box<dyn std::error::Error>>(())
        })
    }

    /// Round 8/9 P1: Structural `Vary: Accept-Encoding` invariant across EVERY outcome arm
    /// (buffered compressed, expanded-therefore-identity, expanded-identity-excluded, identity by
    /// choice, saturated uncompressed, saturated yielding-stream, saturated zstd-only residual,
    /// failed compression, streamed compressed, and streamed uncompressed residual) AND across the
    /// categorical vs. instance guard split:
    /// - Without upstream `Vary`: `Accept-Encoding` is present exactly once (on non-categorical).
    /// - With upstream `Vary: Origin`: both `Origin` and `Accept-Encoding` are present (once).
    /// - With upstream `Vary: *`: untouched (`["*"]`, no `Accept-Encoding` appended).
    /// - With upstream `Vary: Accept-Encoding`: still present exactly once (no duplicate).
    ///
    /// Categorical guards (`1xx`, `204`, `206`, existing `Content-Encoding` or `Content-Range`,
    /// visible digest headers `Content-Digest`/`Repr-Digest`/`Digest`, advertised digest trailers,
    /// `Cache-Control: no-transform`, non-compressible MIME / SSE / missing CT on non-`HEAD`)
    /// return with upstream headers untouched (no `Vary` added). Cache-updating bodiless responses
    /// (`304 Not Modified` per RFC 9111 §4.3.4, and `HEAD` passing every non-method categorical
    /// guard with missing `Content-Type` allowed per RFC 9111 §4.3.5) leave responses with NO
    /// upstream `Vary` untouched (matching v0.1.4 so the cache keeps the stored `200`'s `Vary`,
    /// RFC 9110 §9.3.2 / RFC 9111 §3.2) and merge `Accept-Encoding` ONLY when the upstream
    /// response already carries a `Vary` field (without touching the body).
    ///
    /// Instance guards (already-ended body, `UpstreamHasDigestTrailer` extension after trailer
    /// stripping, `X-Accel-Buffering: no`, declared `Content-Length` below 1,024 or above 4 MiB)
    /// and late body-stage instance exits (actual data over 4 MiB, under 1,024, trailers, or a
    /// body error) ALL carry `Vary: Accept-Encoding` for every request, pinned independently from
    /// the v0.1.4 source via a literal table (zero calls to production guard helpers).
    #[test]
    #[allow(clippy::too_many_lines)]
    fn round8_proxy_vary_structural_across_all_outcomes_and_guards()
    -> Result<(), Box<dyn std::error::Error>> {
        use http::header::{
            CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, TRAILER,
            VARY,
        };

        struct CustomFramesBody {
            frames: VecDeque<Result<http_body::Frame<Bytes>, HttpError>>,
        }

        impl http_body::Body for CustomFramesBody {
            type Data = Bytes;
            type Error = HttpError;

            fn poll_frame(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
                Poll::Ready(self.frames.pop_front())
            }

            fn is_end_stream(&self) -> bool {
                self.frames.is_empty()
            }
        }

        #[derive(Clone, Copy)]
        enum GuardFixture {
            // Categorical guards (v0.1.4: Vary absent; Round 10: still absent)
            Informational103,
            NoContent204,
            PartialContent206,
            ExistingContentEncoding,
            ExistingContentRange,
            VisibleContentDigest,
            VisibleReprDigest,
            VisibleDigest,
            AdvertisedTrailerContentDigest,
            AdvertisedTrailerReprDigest,
            AdvertisedTrailerDigest,
            CacheControlNoTransform,
            NonCompressibleMimePng,
            SseEventStream,
            MissingContentType,
            // HEAD categorical guards (non-method categorical guards still apply to HEAD)
            HeadInformational103,
            HeadNoContent204,
            HeadPartialContent206,
            HeadExistingContentEncoding,
            HeadExistingContentRange,
            HeadVisibleContentDigest,
            HeadAdvertisedTrailerDigest,
            HeadCacheControlNoTransform,
            HeadNonCompressibleMimePng,
            HeadSseEventStream,
            // Round 11 `VaryOnly` cache-updating bodiless responses (`304` and eligible `HEAD`):
            // absent upstream `Vary` stays untouched as in v0.1.4; present upstream `Vary` merges
            // `Accept-Encoding` (body never touched).
            NotModified304,
            NotModified304NoContentType,
            HeadNotModified304,
            Head,
            HeadMissingContentType,
            // Header/metadata instance guards (v0.1.4: Vary present for empty accepted list)
            AlreadyEndedBody,
            DigestTrailerExtension,
            XAccelBufferingNo,
            KnownLengthTooSmall512,
            KnownLengthTooLarge,
            // Late body-stage instance exits (v0.1.4: Vary present for empty accepted list)
            LateExitActualOverCap,
            LateExitActualUnderMin,
            LateExitBodyTrailers,
            LateExitBodyError,
        }

        #[derive(Clone, Copy)]
        enum UpstreamVaryScope {
            /// Applies across all upstream `Vary` modes (`None`, `Origin`, `*`, `Accept-Encoding`).
            Any,
            /// Upstream response has NO `Vary` header (`None`).
            Absent,
            /// Upstream response already has a `Vary` header (`Origin`, `*`, `Accept-Encoding`).
            Present,
        }

        type GuardPinRow<'a> = (
            &'a str,
            GuardFixture,
            UpstreamVaryScope,
            bool,
            bool,
            bool,
            Option<&'a str>,
        );

        fn vary_tokens(headers: &http::HeaderMap) -> Vec<String> {
            headers
                .get_all(VARY)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|s| s.split(','))
                .map(|t| t.trim().to_owned())
                .filter(|t| !t.is_empty())
                .collect()
        }

        fn assert_vary_behavior(
            label: &str,
            upstream_vary: Option<&str>,
            headers: &http::HeaderMap,
        ) {
            let tokens = vary_tokens(headers);
            let ae_count = tokens
                .iter()
                .filter(|t| t.eq_ignore_ascii_case("accept-encoding"))
                .count();
            match upstream_vary {
                None => {
                    assert_eq!(
                        ae_count, 1,
                        "{label} (no upstream Vary): expected Accept-Encoding once, got {tokens:?}"
                    );
                    assert_eq!(
                        tokens.len(),
                        1,
                        "{label} (no upstream Vary): unexpected extra Vary tokens {tokens:?}"
                    );
                }
                Some("Origin") => {
                    assert_eq!(
                        ae_count, 1,
                        "{label} (Vary: Origin): expected Accept-Encoding once, got {tokens:?}"
                    );
                    assert!(
                        tokens.iter().any(|t| t == "Origin"),
                        "{label} (Vary: Origin): upstream Origin lost, got {tokens:?}"
                    );
                    assert_eq!(
                        tokens.len(),
                        2,
                        "{label} (Vary: Origin): expected exactly Origin + Accept-Encoding, got {tokens:?}"
                    );
                }
                Some("*") => {
                    assert_eq!(
                        tokens,
                        vec!["*".to_owned()],
                        "{label} (Vary: *): wildcard Vary must remain untouched, got {tokens:?}"
                    );
                }
                Some("Accept-Encoding") => {
                    assert_eq!(
                        ae_count, 1,
                        "{label} (Vary: Accept-Encoding): must not duplicate Accept-Encoding, got {tokens:?}"
                    );
                    assert_eq!(tokens.len(), 1);
                }
                Some(other) => {
                    assert_eq!(
                        other, "",
                        "unexpected upstream Vary fixture {other:?} in {label}"
                    );
                }
            }
        }

        fn assert_vary_untouched(
            label: &str,
            upstream_vary: Option<&str>,
            headers: &http::HeaderMap,
        ) {
            let tokens = vary_tokens(headers);
            match upstream_vary {
                None => {
                    assert!(
                        headers.get(VARY).is_none(),
                        "{label} (no upstream Vary): must NOT add Vary header, got {:?}",
                        headers.get_all(VARY).iter().collect::<Vec<_>>()
                    );
                    assert!(
                        tokens.is_empty(),
                        "{label} (no upstream Vary): must NOT add Vary, got {tokens:?}"
                    );
                }
                Some(expected) => assert_eq!(
                    tokens,
                    vec![expected.to_owned()],
                    "{label} (Vary: {expected}): must keep upstream Vary untouched, got {tokens:?}"
                ),
            }
        }

        let _serial = COMPRESS_POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        let compressible_128k = sample_payload(128 * 1024);
        let payload_256k = Bytes::from(vec![b'V'; 256 * 1024]);
        let mut incompressible = Vec::with_capacity(2048);
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..2048 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            incompressible.push((state >> 56) as u8);
        }
        let incompressible = Bytes::from(incompressible);

        let make_eligible = |body: &Bytes, known_len: bool, upstream_vary: Option<&str>| {
            let mut resp = Response::new(full_http_body(body.clone()));
            *resp.status_mut() = StatusCode::OK;
            resp.headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
            if known_len && let Ok(len_v) = HeaderValue::from_str(&body.len().to_string()) {
                resp.headers_mut().insert(CONTENT_LENGTH, len_v);
            }
            if let Some(v) = upstream_vary
                && let Ok(hv) = HeaderValue::from_str(v)
            {
                resp.headers_mut().insert(VARY, hv);
            }
            resp
        };

        let upstream_vary_modes = [None, Some("Origin"), Some("*"), Some("Accept-Encoding")];

        rt.block_on(async {
            for upstream_vary in upstream_vary_modes {
                // 1. Buffered compressed
                let r = maybe_compress_proxied_response(
                    Some("gzip"),
                    &Method::GET,
                    make_eligible(&compressible_128k, true, upstream_vary),
                )
                .await;
                assert_eq!(
                    r.headers()
                        .get(CONTENT_ENCODING)
                        .and_then(|v| v.to_str().ok()),
                    Some("gzip")
                );
                assert_vary_behavior("buffered-compressed", upstream_vary, r.headers());

                // 2. Expanded-therefore-identity (`gzip` on incompressible body)
                let r = maybe_compress_proxied_response(
                    Some("gzip"),
                    &Method::GET,
                    make_eligible(&incompressible, true, upstream_vary),
                )
                .await;
                assert!(r.headers().get(CONTENT_ENCODING).is_none());
                assert_vary_behavior("expanded-therefore-identity", upstream_vary, r.headers());

                // 3. Expanded but identity excluded (`gzip, identity;q=0` on incompressible body)
                let r = maybe_compress_proxied_response(
                    Some("gzip, identity;q=0"),
                    &Method::GET,
                    make_eligible(&incompressible, true, upstream_vary),
                )
                .await;
                assert_eq!(
                    r.headers()
                        .get(CONTENT_ENCODING)
                        .and_then(|v| v.to_str().ok()),
                    Some("gzip")
                );
                assert_vary_behavior("expanded-identity-excluded", upstream_vary, r.headers());

                // 4. Identity by choice (absent, `identity`, `*`, `identity;q=0`)
                for ae in [None, Some("identity"), Some("*"), Some("identity;q=0")] {
                    let r = maybe_compress_proxied_response(
                        ae,
                        &Method::GET,
                        make_eligible(&compressible_128k, true, upstream_vary),
                    )
                    .await;
                    assert!(r.headers().get(CONTENT_ENCODING).is_none());
                    assert_vary_behavior(
                        &format!("identity-by-choice({ae:?})"),
                        upstream_vary,
                        r.headers(),
                    );
                }

                // 5. Failed buffered compression (`BufferedCompressOutcome::Failed`)
                {
                    let _fail = super::test_force_buffered_compress_fail_guard(true);
                    let r = maybe_compress_proxied_response(
                        Some("gzip"),
                        &Method::GET,
                        make_eligible(&compressible_128k, true, upstream_vary),
                    )
                    .await;
                    assert!(r.headers().get(CONTENT_ENCODING).is_none());
                    assert_vary_behavior("buffered-failed", upstream_vary, r.headers());
                }

                // 6. Streamed compressed (unknown Content-Length: `br` and `x-gzip, identity;q=0`)
                for (ae, exp_ce) in [("br", "br"), ("x-gzip, identity;q=0", "gzip")] {
                    let r = maybe_compress_proxied_response(
                        Some(ae),
                        &Method::GET,
                        make_eligible(&compressible_128k, false, upstream_vary),
                    )
                    .await;
                    assert_eq!(
                        r.headers()
                            .get(CONTENT_ENCODING)
                            .and_then(|v| v.to_str().ok()),
                        Some(exp_ce)
                    );
                    assert_vary_behavior(
                        &format!("streamed-compressed({ae})"),
                        upstream_vary,
                        r.headers(),
                    );
                }

                // 7. Streamed uncompressed residual (`zstd` and `zstd, identity;q=0`)
                for ae in ["zstd", "zstd, identity;q=0"] {
                    let r = maybe_compress_proxied_response(
                        Some(ae),
                        &Method::GET,
                        make_eligible(&compressible_128k, false, upstream_vary),
                    )
                    .await;
                    assert!(r.headers().get(CONTENT_ENCODING).is_none());
                    assert_vary_behavior(
                        &format!("streamed-uncompressed({ae})"),
                        upstream_vary,
                        r.headers(),
                    );
                }
            }

            // 8. Saturated arms (uncompressed fallback, yielding-stream compressed, zstd-only residual)
            let _nb_ctx = miraserve_static::enter_nonblocking_inline_context();
            let permits = u32::try_from(super::WORKER_LOOP_COMPRESS_JOBS).unwrap_or(8);
            let _budget_guard = super::test_compress_waiter_budget_override_guard(300 * 1024);
            let all = Arc::clone(super::worker_compress_semaphore())
                .acquire_many_owned(permits)
                .await?;
            let mut waiter_a = Box::pin(maybe_compress_proxied_response(
                Some("gzip"),
                &Method::GET,
                make_eligible(&payload_256k, true, None),
            ));
            let poll_a =
                tokio::time::timeout(std::time::Duration::from_millis(50), waiter_a.as_mut()).await;
            assert!(poll_a.is_err());

            for upstream_vary in upstream_vary_modes {
                // 8a. Saturated uncompressed fallback (identity acceptable)
                let r = maybe_compress_proxied_response(
                    Some("gzip"),
                    &Method::GET,
                    make_eligible(&payload_256k, true, upstream_vary),
                )
                .await;
                assert!(r.headers().get(CONTENT_ENCODING).is_none());
                assert_vary_behavior("saturated-uncompressed", upstream_vary, r.headers());

                // 8b. Saturated yielding stream (`gzip, identity;q=0`)
                let r = maybe_compress_proxied_response(
                    Some("gzip, identity;q=0"),
                    &Method::GET,
                    make_eligible(&payload_256k, true, upstream_vary),
                )
                .await;
                assert_eq!(
                    r.headers()
                        .get(CONTENT_ENCODING)
                        .and_then(|v| v.to_str().ok()),
                    Some("gzip")
                );
                assert_vary_behavior("saturated-yielding-stream", upstream_vary, r.headers());

                // 8c. Saturated zstd-only residual (`zstd, identity;q=0`)
                let r = maybe_compress_proxied_response(
                    Some("zstd, identity;q=0"),
                    &Method::GET,
                    make_eligible(&payload_256k, true, upstream_vary),
                )
                .await;
                assert!(r.headers().get(CONTENT_ENCODING).is_none());
                assert_vary_behavior("saturated-zstd-residual", upstream_vary, r.headers());
            }

            drop(waiter_a);
            drop(all);

            // 9. Independent literal guard × request-header truth table transcribed directly from
            //    `v0.1.4:crates/miraserve-http/src/router.rs:6215–6392`, the categorical vs.
            //    instance rule, and Round 11's RFC 9111 §4.3.4 / §4.3.5 / §3.2 merge-on-present
            //    rule (ZERO calls to production guard helpers).
            //    Columns:
            //      (label, fixture, upstream_vary_scope, v0.1.4_empty_ae_vary,
            //       v0.1.4_nonempty_ae_vary, expected_vary, intentional_addition_rfc)
            //    Invariants checked for every row:
            //      - Strict superset of v0.1.4: wherever v0.1.4 emitted `Vary` (empty or non-empty
            //        accepted list), `expected_vary` MUST be `true`.
            //      - Every row where `expected_vary` is `true` while v0.1.4 emitted no `Vary` for
            //        either list MUST carry an explicit intentional RFC 9111 addition tag (ONLY
            //        the `304` and eligible `HEAD` rows when upstream `Vary` is PRESENT; the
            //        absent-upstream-`Vary` rows for `304` and `HEAD` stay at v0.1.4's `false`).
            //      - Untouched rows (`expected_vary == false`): upstream `Vary` untouched (or
            //        remains absent) for EVERY request header in that row's scope.
            //      - `Vary`-merging rows (`expected_vary == true`): `Vary: Accept-Encoding`
            //        merged cleanly for EVERY request header in that row's scope (`*` untouched,
            //        no duplicate), with no transformation applied (`Content-Encoding` absent).
            let literal_guard_table: &[GuardPinRow<'_>] = &[
                // --- CATEGORICAL GUARDS (v0.1.4 empty=false, non-empty=false -> Round 11=false) ---
                (
                    "103-Early-Hints",
                    GuardFixture::Informational103,
                    UpstreamVaryScope::Any,
                    false,
                    false,
                    false,
                    None,
                ),
                (
                    "204-No-Content",
                    GuardFixture::NoContent204,
                    UpstreamVaryScope::Any,
                    false,
                    false,
                    false,
                    None,
                ),
                (
                    "206-Partial-Content",
                    GuardFixture::PartialContent206,
                    UpstreamVaryScope::Any,
                    false,
                    false,
                    false,
                    None,
                ),
                (
                    "existing-Content-Encoding",
                    GuardFixture::ExistingContentEncoding,
                    UpstreamVaryScope::Any,
                    false,
                    false,
                    false,
                    None,
                ),
                (
                    "existing-Content-Range",
                    GuardFixture::ExistingContentRange,
                    UpstreamVaryScope::Any,
                    false,
                    false,
                    false,
                    None,
                ),
                (
                    "Content-Digest",
                    GuardFixture::VisibleContentDigest,
                    UpstreamVaryScope::Any,
                    false,
                    false,
                    false,
                    None,
                ),
                (
                    "Repr-Digest",
                    GuardFixture::VisibleReprDigest,
                    UpstreamVaryScope::Any,
                    false,
                    false,
                    false,
                    None,
                ),
                (
                    "Digest",
                    GuardFixture::VisibleDigest,
                    UpstreamVaryScope::Any,
                    false,
                    false,
                    false,
                    None,
                ),
                (
                    "Trailer-Content-Digest",
                    GuardFixture::AdvertisedTrailerContentDigest,
                    UpstreamVaryScope::Any,
                    false,
                    false,
                    false,
                    None,
                ),
                (
                    "Trailer-Repr-Digest",
                    GuardFixture::AdvertisedTrailerReprDigest,
                    UpstreamVaryScope::Any,
                    false,
                    false,
                    false,
                    None,
                ),
                (
                    "Trailer-Digest",
                    GuardFixture::AdvertisedTrailerDigest,
                    UpstreamVaryScope::Any,
                    false,
                    false,
                    false,
                    None,
                ),
                (
                    "Cache-Control-no-transform",
                    GuardFixture::CacheControlNoTransform,
                    UpstreamVaryScope::Any,
                    false,
                    false,
                    false,
                    None,
                ),
                (
                    "non-compressible-MIME-png",
                    GuardFixture::NonCompressibleMimePng,
                    UpstreamVaryScope::Any,
                    false,
                    false,
                    false,
                    None,
                ),
                (
                    "non-compressible-MIME-SSE",
                    GuardFixture::SseEventStream,
                    UpstreamVaryScope::Any,
                    false,
                    false,
                    false,
                    None,
                ),
                (
                    "missing-Content-Type",
                    GuardFixture::MissingContentType,
                    UpstreamVaryScope::Any,
                    false,
                    false,
                    false,
                    None,
                ),
                // --- HEAD WITH NON-METHOD CATEGORICAL GUARDS (unchanged from v0.1.4: false) ---
                (
                    "HEAD-103-Early-Hints",
                    GuardFixture::HeadInformational103,
                    UpstreamVaryScope::Any,
                    false,
                    false,
                    false,
                    None,
                ),
                (
                    "HEAD-204-No-Content",
                    GuardFixture::HeadNoContent204,
                    UpstreamVaryScope::Any,
                    false,
                    false,
                    false,
                    None,
                ),
                (
                    "HEAD-206-Partial-Content",
                    GuardFixture::HeadPartialContent206,
                    UpstreamVaryScope::Any,
                    false,
                    false,
                    false,
                    None,
                ),
                (
                    "HEAD-existing-Content-Encoding",
                    GuardFixture::HeadExistingContentEncoding,
                    UpstreamVaryScope::Any,
                    false,
                    false,
                    false,
                    None,
                ),
                (
                    "HEAD-existing-Content-Range",
                    GuardFixture::HeadExistingContentRange,
                    UpstreamVaryScope::Any,
                    false,
                    false,
                    false,
                    None,
                ),
                (
                    "HEAD-Content-Digest",
                    GuardFixture::HeadVisibleContentDigest,
                    UpstreamVaryScope::Any,
                    false,
                    false,
                    false,
                    None,
                ),
                (
                    "HEAD-Trailer-Digest",
                    GuardFixture::HeadAdvertisedTrailerDigest,
                    UpstreamVaryScope::Any,
                    false,
                    false,
                    false,
                    None,
                ),
                (
                    "HEAD-Cache-Control-no-transform",
                    GuardFixture::HeadCacheControlNoTransform,
                    UpstreamVaryScope::Any,
                    false,
                    false,
                    false,
                    None,
                ),
                (
                    "HEAD-non-compressible-MIME-png",
                    GuardFixture::HeadNonCompressibleMimePng,
                    UpstreamVaryScope::Any,
                    false,
                    false,
                    false,
                    None,
                ),
                (
                    "HEAD-non-compressible-MIME-SSE",
                    GuardFixture::HeadSseEventStream,
                    UpstreamVaryScope::Any,
                    false,
                    false,
                    false,
                    None,
                ),
                // --- CACHE-UPDATING 304 & HEAD WITH ABSENT UPSTREAM `Vary` (v0.1.4=false -> Round 11=false) ---
                // Preserving absent `Vary` lets a downstream cache keep the stored `200`'s `Vary`
                // (e.g. `Accept-Language, Accept-Encoding`) intact (RFC 9110 §9.3.2, RFC 9111 §3.2).
                (
                    "304-Not-Modified-absent-Vary",
                    GuardFixture::NotModified304,
                    UpstreamVaryScope::Absent,
                    false,
                    false,
                    false,
                    None,
                ),
                (
                    "304-Not-Modified-no-Content-Type-absent-Vary",
                    GuardFixture::NotModified304NoContentType,
                    UpstreamVaryScope::Absent,
                    false,
                    false,
                    false,
                    None,
                ),
                (
                    "HEAD-304-Not-Modified-absent-Vary",
                    GuardFixture::HeadNotModified304,
                    UpstreamVaryScope::Absent,
                    false,
                    false,
                    false,
                    None,
                ),
                (
                    "HEAD-absent-Vary",
                    GuardFixture::Head,
                    UpstreamVaryScope::Absent,
                    false,
                    false,
                    false,
                    None,
                ),
                (
                    "HEAD-missing-Content-Type-absent-Vary",
                    GuardFixture::HeadMissingContentType,
                    UpstreamVaryScope::Absent,
                    false,
                    false,
                    false,
                    None,
                ),
                // --- INTENTIONAL ADDITIONS: cache-updating 304 & HEAD WITH PRESENT UPSTREAM `Vary` ---
                // A present upstream `Vary` replaces the stored `200`'s `Vary` on update (RFC 9111
                // §3.2, §4.3.4, §4.3.5), so `Accept-Encoding` must be merged into it.
                (
                    "304-Not-Modified-present-Vary",
                    GuardFixture::NotModified304,
                    UpstreamVaryScope::Present,
                    false,
                    false,
                    true,
                    Some("RFC 9111 §4.3.4"),
                ),
                (
                    "304-Not-Modified-no-Content-Type-present-Vary",
                    GuardFixture::NotModified304NoContentType,
                    UpstreamVaryScope::Present,
                    false,
                    false,
                    true,
                    Some("RFC 9111 §4.3.4"),
                ),
                (
                    "HEAD-304-Not-Modified-present-Vary",
                    GuardFixture::HeadNotModified304,
                    UpstreamVaryScope::Present,
                    false,
                    false,
                    true,
                    Some("RFC 9111 §4.3.4"),
                ),
                (
                    "HEAD-present-Vary",
                    GuardFixture::Head,
                    UpstreamVaryScope::Present,
                    false,
                    false,
                    true,
                    Some("RFC 9111 §4.3.5"),
                ),
                (
                    "HEAD-missing-Content-Type-present-Vary",
                    GuardFixture::HeadMissingContentType,
                    UpstreamVaryScope::Present,
                    false,
                    false,
                    true,
                    Some("RFC 9111 §4.3.5"),
                ),
                // --- INSTANCE GUARDS (v0.1.4 empty=true, non-empty=false -> Round 9/10/11=true) ---
                (
                    "already-ended-body",
                    GuardFixture::AlreadyEndedBody,
                    UpstreamVaryScope::Any,
                    true,
                    false,
                    true,
                    None,
                ),
                (
                    "UpstreamHasDigestTrailer",
                    GuardFixture::DigestTrailerExtension,
                    UpstreamVaryScope::Any,
                    true,
                    false,
                    true,
                    None,
                ),
                (
                    "X-Accel-Buffering-no",
                    GuardFixture::XAccelBufferingNo,
                    UpstreamVaryScope::Any,
                    true,
                    false,
                    true,
                    None,
                ),
                (
                    "known-CL-512-below-1024",
                    GuardFixture::KnownLengthTooSmall512,
                    UpstreamVaryScope::Any,
                    true,
                    false,
                    true,
                    None,
                ),
                (
                    "known-CL-above-4MiB",
                    GuardFixture::KnownLengthTooLarge,
                    UpstreamVaryScope::Any,
                    true,
                    false,
                    true,
                    None,
                ),
                // --- LATE BODY-STAGE INSTANCE EXITS (v0.1.4 empty=true, non-empty=false -> Round 9/10/11=true) ---
                (
                    "late-exit-actual-over-4MiB",
                    GuardFixture::LateExitActualOverCap,
                    UpstreamVaryScope::Any,
                    true,
                    false,
                    true,
                    None,
                ),
                (
                    "late-exit-actual-under-1024",
                    GuardFixture::LateExitActualUnderMin,
                    UpstreamVaryScope::Any,
                    true,
                    false,
                    true,
                    None,
                ),
                (
                    "late-exit-body-trailers",
                    GuardFixture::LateExitBodyTrailers,
                    UpstreamVaryScope::Any,
                    true,
                    false,
                    true,
                    None,
                ),
                (
                    "late-exit-body-error",
                    GuardFixture::LateExitBodyError,
                    UpstreamVaryScope::Any,
                    true,
                    false,
                    true,
                    None,
                ),
            ];

            let small_512 = Bytes::from(vec![b's'; 512]);
            let over_cap_bytes = Bytes::from(vec![b'B'; 4 * 1024 * 1024 + 1]);
            let big_cl = super::MAX_ONTHEFLY_COMPRESS_BYTES + 1;

            let build_fixture = |fixture: GuardFixture, upstream_vary: Option<&str>| {
                let mut method = Method::GET;
                let mut status = StatusCode::OK;
                let mut body: HttpBody = full_http_body(compressible_128k.clone());
                let mut ct: Option<&'static str> = Some("text/plain");
                let mut cl: Option<u64> = Some(compressible_128k.len() as u64);
                let mut extra_hdr: Option<(&'static str, &'static str)> = None;
                let mut digest_trailer_ext = false;

                match fixture {
                    GuardFixture::Head => {
                        method = Method::HEAD;
                        body = empty_http_body();
                    }
                    GuardFixture::HeadMissingContentType => {
                        method = Method::HEAD;
                        body = empty_http_body();
                        ct = None;
                    }
                    GuardFixture::HeadInformational103 => {
                        method = Method::HEAD;
                        status = StatusCode::EARLY_HINTS;
                        body = empty_http_body();
                    }
                    GuardFixture::HeadNoContent204 => {
                        method = Method::HEAD;
                        status = StatusCode::NO_CONTENT;
                        body = empty_http_body();
                        cl = None;
                    }
                    GuardFixture::HeadPartialContent206 => {
                        method = Method::HEAD;
                        status = StatusCode::PARTIAL_CONTENT;
                        body = empty_http_body();
                    }
                    GuardFixture::HeadNotModified304 => {
                        method = Method::HEAD;
                        status = StatusCode::NOT_MODIFIED;
                        body = empty_http_body();
                        ct = None;
                        cl = None;
                    }
                    GuardFixture::HeadExistingContentEncoding => {
                        method = Method::HEAD;
                        body = empty_http_body();
                        extra_hdr = Some((CONTENT_ENCODING.as_str(), "deflate"));
                    }
                    GuardFixture::HeadExistingContentRange => {
                        method = Method::HEAD;
                        body = empty_http_body();
                        extra_hdr = Some((CONTENT_RANGE.as_str(), "bytes 0-100/200"));
                    }
                    GuardFixture::HeadVisibleContentDigest => {
                        method = Method::HEAD;
                        body = empty_http_body();
                        extra_hdr = Some(("content-digest", "sha-256=:AAAA:"));
                    }
                    GuardFixture::HeadAdvertisedTrailerDigest => {
                        method = Method::HEAD;
                        body = empty_http_body();
                        extra_hdr = Some((TRAILER.as_str(), "Digest"));
                    }
                    GuardFixture::HeadCacheControlNoTransform => {
                        method = Method::HEAD;
                        body = empty_http_body();
                        extra_hdr = Some((CACHE_CONTROL.as_str(), "public, no-transform"));
                    }
                    GuardFixture::HeadNonCompressibleMimePng => {
                        method = Method::HEAD;
                        body = empty_http_body();
                        ct = Some("image/png");
                    }
                    GuardFixture::HeadSseEventStream => {
                        method = Method::HEAD;
                        body = empty_http_body();
                        ct = Some("text/event-stream");
                        cl = None;
                    }
                    GuardFixture::Informational103 => status = StatusCode::EARLY_HINTS,
                    GuardFixture::NoContent204 => {
                        status = StatusCode::NO_CONTENT;
                        body = empty_http_body();
                        cl = None;
                    }
                    GuardFixture::PartialContent206 => status = StatusCode::PARTIAL_CONTENT,
                    GuardFixture::NotModified304 => {
                        status = StatusCode::NOT_MODIFIED;
                        body = empty_http_body();
                        cl = None;
                    }
                    GuardFixture::NotModified304NoContentType => {
                        status = StatusCode::NOT_MODIFIED;
                        body = empty_http_body();
                        ct = None;
                        cl = None;
                    }
                    GuardFixture::ExistingContentEncoding => {
                        extra_hdr = Some((CONTENT_ENCODING.as_str(), "deflate"));
                    }
                    GuardFixture::ExistingContentRange => {
                        extra_hdr = Some((CONTENT_RANGE.as_str(), "bytes 0-100/200"));
                    }
                    GuardFixture::VisibleContentDigest => {
                        extra_hdr = Some(("content-digest", "sha-256=:AAAA:"));
                    }
                    GuardFixture::VisibleReprDigest => {
                        extra_hdr = Some(("repr-digest", "sha-256=:BBBB:"));
                    }
                    GuardFixture::VisibleDigest => {
                        extra_hdr = Some(("digest", "SHA-256=CCCC"));
                    }
                    GuardFixture::AdvertisedTrailerContentDigest => {
                        extra_hdr = Some((TRAILER.as_str(), "Content-Digest"));
                    }
                    GuardFixture::AdvertisedTrailerReprDigest => {
                        extra_hdr = Some((TRAILER.as_str(), "Repr-Digest"));
                    }
                    GuardFixture::AdvertisedTrailerDigest => {
                        extra_hdr = Some((TRAILER.as_str(), "Digest"));
                    }
                    GuardFixture::CacheControlNoTransform => {
                        extra_hdr = Some((CACHE_CONTROL.as_str(), "public, no-transform"));
                    }
                    GuardFixture::NonCompressibleMimePng => ct = Some("image/png"),
                    GuardFixture::SseEventStream => {
                        ct = Some("text/event-stream");
                        cl = None;
                    }
                    GuardFixture::MissingContentType => ct = None,
                    GuardFixture::AlreadyEndedBody => {
                        body = empty_http_body();
                        cl = Some(2048);
                    }
                    GuardFixture::DigestTrailerExtension => digest_trailer_ext = true,
                    GuardFixture::XAccelBufferingNo => {
                        extra_hdr = Some(("x-accel-buffering", "no"));
                    }
                    GuardFixture::KnownLengthTooSmall512 => {
                        body = full_http_body(small_512.clone());
                        cl = Some(512);
                    }
                    GuardFixture::KnownLengthTooLarge => cl = Some(big_cl),
                    GuardFixture::LateExitActualOverCap => {
                        body = full_http_body(over_cap_bytes.clone());
                        cl = Some(2048);
                    }
                    GuardFixture::LateExitActualUnderMin => {
                        body = full_http_body(small_512.clone());
                        cl = Some(2048);
                    }
                    GuardFixture::LateExitBodyTrailers => {
                        let mut trailers = http::HeaderMap::new();
                        trailers.insert(
                            http::HeaderName::from_static("x-checksum"),
                            HeaderValue::from_static("ok"),
                        );
                        let mut frames = VecDeque::new();
                        frames.push_back(Ok(http_body::Frame::data(Bytes::from(vec![b't'; 2048]))));
                        frames.push_back(Ok(http_body::Frame::trailers(trailers)));
                        body = CustomFramesBody { frames }.boxed();
                        cl = Some(2048);
                    }
                    GuardFixture::LateExitBodyError => {
                        let mut frames = VecDeque::new();
                        frames.push_back(Ok(http_body::Frame::data(Bytes::from(vec![b'e'; 1024]))));
                        frames.push_back(Err(HttpError::Router("upstream body reset".to_owned())));
                        body = CustomFramesBody { frames }.boxed();
                        cl = Some(2048);
                    }
                }

                let mut resp = Response::new(body);
                *resp.status_mut() = status;
                if let Some(ct_v) = ct {
                    resp.headers_mut()
                        .insert(CONTENT_TYPE, HeaderValue::from_static(ct_v));
                }
                if let Some(n) = cl
                    && let Ok(hv) = HeaderValue::from_str(&n.to_string())
                {
                    resp.headers_mut().insert(CONTENT_LENGTH, hv);
                }
                if let Some((k, v)) = extra_hdr
                    && let Ok(name) = http::HeaderName::from_bytes(k.as_bytes())
                {
                    resp.headers_mut().insert(name, HeaderValue::from_static(v));
                }
                if digest_trailer_ext {
                    resp.extensions_mut()
                        .insert(miraserve_proxy::UpstreamHasDigestTrailer);
                }
                if let Some(v) = upstream_vary
                    && let Ok(hv) = HeaderValue::from_str(v)
                {
                    resp.headers_mut().insert(VARY, hv);
                }
                (method, resp)
            };

            let req_ae_cases = [
                None,
                Some("identity"),
                Some("*"),
                Some("identity;q=0"),
                Some("gzip"),
                Some("gzip, identity;q=0"),
            ];

            for &(
                label,
                fixture,
                vary_scope,
                v014_empty_had_vary,
                v014_nonempty_had_vary,
                expected_vary_present,
                intentional_addition_rfc,
            ) in literal_guard_table
            {
                let v014_union = v014_empty_had_vary || v014_nonempty_had_vary;
                if v014_union {
                    assert!(
                        expected_vary_present,
                        "superset invariant violated in table for {label}"
                    );
                }
                assert_eq!(
                    expected_vary_present && !v014_union,
                    intentional_addition_rfc.is_some(),
                    "row {label} differs from v0.1.4 union without matching intentional RFC tag"
                );
                let row_vary_modes: &[Option<&str>] = match vary_scope {
                    UpstreamVaryScope::Any => &upstream_vary_modes,
                    UpstreamVaryScope::Absent => &[None],
                    UpstreamVaryScope::Present => {
                        &[Some("Origin"), Some("*"), Some("Accept-Encoding")]
                    }
                };
                for ae in req_ae_cases {
                    for &upstream_vary in row_vary_modes {
                        let (method, resp) = build_fixture(fixture, upstream_vary);
                        let out = maybe_compress_proxied_response(ae, &method, resp).await;

                        // Guarded responses must never be newly transformed.
                        if matches!(
                            fixture,
                            GuardFixture::ExistingContentEncoding
                                | GuardFixture::HeadExistingContentEncoding
                        ) {
                            assert_eq!(
                                out.headers()
                                    .get(CONTENT_ENCODING)
                                    .and_then(|v| v.to_str().ok()),
                                Some("deflate"),
                                "guard {label} (ae={ae:?}) must keep upstream Content-Encoding"
                            );
                        } else {
                            assert!(
                                out.headers().get(CONTENT_ENCODING).is_none(),
                                "guard {label} (ae={ae:?}) must remain uncompressed"
                            );
                        }

                        if expected_vary_present {
                            assert_vary_behavior(
                                &format!(
                                    "vary-present:{label}(rfc={intentional_addition_rfc:?},ae={ae:?})"
                                ),
                                upstream_vary,
                                out.headers(),
                            );
                        } else {
                            assert_vary_untouched(
                                &format!("categorical-guard:{label}(ae={ae:?})"),
                                upstream_vary,
                                out.headers(),
                            );
                        }

                        // Verify late-exit body passthrough integrity once per late-exit fixture.
                        if ae == Some("gzip") && upstream_vary.is_none() {
                            match fixture {
                                GuardFixture::LateExitActualOverCap => {
                                    let collected = out.into_body().collect().await?.to_bytes();
                                    assert_eq!(collected.len(), over_cap_bytes.len());
                                }
                                GuardFixture::LateExitActualUnderMin => {
                                    let collected = out.into_body().collect().await?.to_bytes();
                                    assert_eq!(collected, small_512);
                                }
                                GuardFixture::LateExitBodyTrailers => {
                                    let collected = out.into_body().collect().await?;
                                    assert_eq!(
                                        collected
                                            .trailers()
                                            .and_then(|t| t.get("x-checksum"))
                                            .and_then(|v| v.to_str().ok()),
                                        Some("ok")
                                    );
                                    assert_eq!(collected.to_bytes().len(), 2048);
                                }
                                GuardFixture::LateExitBodyError => {
                                    assert!(
                                        out.into_body().collect().await.is_err(),
                                        "body error late exit must preserve upstream error"
                                    );
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }

            Ok::<_, Box<dyn std::error::Error>>(())
        })
    }

    /// Round 9 P1 (Codex's two-request sequence):
    /// 1. Request 1 carries NO `Accept-Encoding`; upstream replies with a cacheable
    ///    `200 text/plain`, `Content-Length: 512`, and no `Vary`. Because `Content-Length: 512`
    ///    is an instance guard (after the single `Vary` append site), MiraServe returns identity
    ///    WITH `Vary: Accept-Encoding` (matching v0.1.4), preventing a shared cache from serving
    ///    this identity response to clients with different `Accept-Encoding`.
    /// 2. Request 2 carries `Accept-Encoding: gzip, identity;q=0` for the same 512-byte resource
    ///    when the upstream streams it without `Content-Length`; MiraServe compresses it as
    ///    `Content-Encoding: gzip` with `Vary: Accept-Encoding`.
    #[test]
    fn round9_codex_small_cl_then_chunked_identity_excluded_preserves_vary()
    -> Result<(), Box<dyn std::error::Error>> {
        use http::header::{CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, VARY};

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        let mut raw_512 = "The quick brown fox jumps over the lazy dog. 0123456789abcdef\n"
            .repeat(9)
            .into_bytes();
        raw_512.truncate(512);
        let body_512 = Bytes::from(raw_512);
        assert_eq!(body_512.len(), 512);

        rt.block_on(async {
            // Request 1: no `Accept-Encoding`, cacheable `200 text/plain`, `Content-Length: 512`, no `Vary`.
            let mut req1_resp = Response::new(full_http_body(body_512.clone()));
            *req1_resp.status_mut() = StatusCode::OK;
            req1_resp
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
            req1_resp
                .headers_mut()
                .insert(CONTENT_LENGTH, HeaderValue::from_static("512"));
            req1_resp.headers_mut().insert(
                CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=60"),
            );

            let out1 = maybe_compress_proxied_response(None, &Method::GET, req1_resp).await;
            assert_eq!(out1.status(), StatusCode::OK);
            assert!(
                out1.headers().get(CONTENT_ENCODING).is_none(),
                "512-byte Content-Length response without Accept-Encoding must stay uncompressed"
            );
            assert_eq!(
                out1.headers()
                    .get(CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok()),
                Some("512")
            );
            assert_eq!(
                out1.headers()
                    .get(CACHE_CONTROL)
                    .and_then(|v| v.to_str().ok()),
                Some("public, max-age=60")
            );
            let vary1: Vec<&str> = out1
                .headers()
                .get_all(VARY)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect();
            assert_eq!(
                vary1,
                vec!["Accept-Encoding"],
                "512-byte Content-Length response with no Accept-Encoding MUST carry Vary: Accept-Encoding"
            );
            assert_eq!(out1.into_body().collect().await?.to_bytes(), body_512);

            // Request 2: `gzip, identity;q=0`, same 512-byte payload streamed without Content-Length.
            let mut req2_resp = Response::new(full_http_body(body_512.clone()));
            *req2_resp.status_mut() = StatusCode::OK;
            req2_resp
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
            req2_resp.headers_mut().insert(
                CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=60"),
            );

            let out2 = maybe_compress_proxied_response(
                Some("gzip, identity;q=0"),
                &Method::GET,
                req2_resp,
            )
            .await;
            assert_eq!(out2.status(), StatusCode::OK);
            assert_eq!(
                out2.headers()
                    .get(CONTENT_ENCODING)
                    .and_then(|v| v.to_str().ok()),
                Some("gzip"),
                "unknown-length 512-byte stream with gzip, identity;q=0 must compress as gzip"
            );
            assert!(out2.headers().get(CONTENT_LENGTH).is_none());
            let vary2: Vec<&str> = out2
                .headers()
                .get_all(VARY)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect();
            assert_eq!(vary2, vec!["Accept-Encoding"]);
            let decoded2 = miraserve_static::compress::decompress_gzip(
                &out2.into_body().collect().await?.to_bytes(),
            )?;
            assert_eq!(decoded2, body_512.as_ref());

            Ok::<_, Box<dyn std::error::Error>>(())
        })
    }

    /// Round 10 P1 (Codex Audit 9, three-step `200` -> `304` revalidation sequence, RFC 9111 §4.3.4):
    /// 1. Client requests cacheable text with `Accept-Encoding: gzip`; upstream returns `200`,
    ///    `Vary: Origin`, weak `ETag` -> MiraServe returns gzip with `Vary` containing BOTH
    ///    `Origin` and `Accept-Encoding`.
    /// 2. Downstream cache revalidates; upstream returns `304`, same weak `ETag`, `Vary: Origin`,
    ///    fresh `max-age` (no `Content-Type`, and also with `Content-Type`) -> MiraServe merges
    ///    `Accept-Encoding` into `Vary` (preserving `Origin`, leaving `*` untouched, never
    ///    duplicating, never polling the body), whatever the request's `Accept-Encoding`.
    /// 3. Updating the stored `200`'s `Vary` from the `304`'s `Vary` (RFC 9111 §4.3.4) therefore
    ///    retains `Accept-Encoding`, so a later client with the same `Origin` and
    ///    `Accept-Encoding: identity, gzip;q=0` cannot match the cached gzip entry and receives
    ///    an uncompressed identity `200` on cache miss.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn round10_codex_200_then_304_with_vary_origin_preserves_accept_encoding()
    -> Result<(), Box<dyn std::error::Error>> {
        use http::header::{
            CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, ETAG, VARY,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct UntouchedBody {
            polls: Arc<AtomicUsize>,
        }

        impl http_body::Body for UntouchedBody {
            type Data = Bytes;
            type Error = HttpError;

            fn poll_frame(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
                self.polls.fetch_add(1, Ordering::SeqCst);
                Poll::Ready(None)
            }

            fn is_end_stream(&self) -> bool {
                false
            }
        }

        fn vary_tokens(headers: &http::HeaderMap) -> Vec<String> {
            headers
                .get_all(VARY)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|s| s.split(','))
                .map(|t| t.trim().to_owned())
                .filter(|t| !t.is_empty())
                .collect()
        }

        // Round 11 P2: hold `COMPRESS_POOL_TEST_LOCK` so Step 1's buffered gzip compression cannot
        // race `round8_proxy_vary_structural_across_all_outcomes_and_guards`'s forced-failure hook.
        let _serial = COMPRESS_POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let body_4k = sample_payload(4 * 1024);

        rt.block_on(async {
            // Step 1: initial GET with `Accept-Encoding: gzip`; upstream returns 200 + `Vary: Origin`.
            let mut resp_200 = Response::new(full_http_body(body_4k.clone()));
            *resp_200.status_mut() = StatusCode::OK;
            resp_200
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
            resp_200
                .headers_mut()
                .insert(CONTENT_LENGTH, HeaderValue::from(body_4k.len()));
            resp_200
                .headers_mut()
                .insert(VARY, HeaderValue::from_static("Origin"));
            resp_200
                .headers_mut()
                .insert(ETAG, HeaderValue::from_static("W/\"doc-v1\""));
            resp_200.headers_mut().insert(
                CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=60"),
            );

            let out_200 =
                maybe_compress_proxied_response(Some("gzip"), &Method::GET, resp_200).await;
            assert_eq!(out_200.status(), StatusCode::OK);
            assert_eq!(
                out_200
                    .headers()
                    .get(CONTENT_ENCODING)
                    .and_then(|v| v.to_str().ok()),
                Some("gzip")
            );
            assert_eq!(
                out_200.headers().get(ETAG).and_then(|v| v.to_str().ok()),
                Some("W/\"doc-v1\"")
            );
            let vary_200 = vary_tokens(out_200.headers());
            assert_eq!(vary_200, vec!["Origin", "Accept-Encoding"]);
            let decoded_200 = miraserve_static::compress::decompress_gzip(
                &out_200.into_body().collect().await?.to_bytes(),
            )?;
            assert_eq!(decoded_200, body_4k.as_ref());

            // Step 2: cache revalidates; upstream returns `304 Not Modified` with `Vary: Origin`
            // (both without and with `Content-Type`, across request `Accept-Encoding` values).
            for (ae, with_ct) in [
                (Some("gzip"), false),
                (Some("gzip"), true),
                (None, false),
                (Some("identity, gzip;q=0"), false),
            ] {
                let polls = Arc::new(AtomicUsize::new(0));
                let mut resp_304 = Response::new(
                    UntouchedBody {
                        polls: Arc::clone(&polls),
                    }
                    .boxed(),
                );
                *resp_304.status_mut() = StatusCode::NOT_MODIFIED;
                resp_304
                    .headers_mut()
                    .insert(ETAG, HeaderValue::from_static("W/\"doc-v1\""));
                resp_304
                    .headers_mut()
                    .insert(VARY, HeaderValue::from_static("Origin"));
                resp_304.headers_mut().insert(
                    CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=120"),
                );
                if with_ct {
                    resp_304
                        .headers_mut()
                        .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
                }

                let out_304 = maybe_compress_proxied_response(ae, &Method::GET, resp_304).await;
                assert_eq!(out_304.status(), StatusCode::NOT_MODIFIED);
                assert_eq!(
                    polls.load(Ordering::SeqCst),
                    0,
                    "304 body must never be polled/touched"
                );
                assert!(out_304.headers().get(CONTENT_ENCODING).is_none());
                assert_eq!(
                    out_304.headers().get(ETAG).and_then(|v| v.to_str().ok()),
                    Some("W/\"doc-v1\"")
                );
                assert_eq!(
                    out_304
                        .headers()
                        .get(CACHE_CONTROL)
                        .and_then(|v| v.to_str().ok()),
                    Some("public, max-age=120")
                );
                let vary_304 = vary_tokens(out_304.headers());
                assert_eq!(
                    vary_304,
                    vec!["Origin", "Accept-Encoding"],
                    "304 (ae={ae:?}, with_ct={with_ct}) must preserve Origin and append Accept-Encoding"
                );
            }

            // Also verify `304` and matching `HEAD` with `Vary: Origin`, multi-line `Vary`, `*`,
            // and existing `Accept-Encoding` (RFC 9111 §4.3.4, §4.3.5, §3.2):
            for (method, status) in [
                (Method::GET, StatusCode::NOT_MODIFIED),
                (Method::HEAD, StatusCode::NOT_MODIFIED),
                (Method::HEAD, StatusCode::OK),
            ] {
                for (up_lines, expected) in [
                    (&["Origin"][..], vec!["Origin", "Accept-Encoding"]),
                    (
                        &["Origin", "Cookie"][..],
                        vec!["Origin", "Cookie", "Accept-Encoding"],
                    ),
                    (&["*"][..], vec!["*"]),
                    (&["Origin", "*"][..], vec!["Origin", "*"]),
                    (
                        &["Origin, Accept-Encoding"][..],
                        vec!["Origin", "Accept-Encoding"],
                    ),
                    (
                        &["Origin", "Accept-Encoding"][..],
                        vec!["Origin", "Accept-Encoding"],
                    ),
                ] {
                    let polls = Arc::new(AtomicUsize::new(0));
                    let mut resp = Response::new(
                        UntouchedBody {
                            polls: Arc::clone(&polls),
                        }
                        .boxed(),
                    );
                    *resp.status_mut() = status;
                    if status == StatusCode::OK {
                        resp.headers_mut()
                            .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
                    }
                    for &line in up_lines {
                        resp.headers_mut()
                            .append(VARY, HeaderValue::from_static(line));
                    }
                    let out = maybe_compress_proxied_response(Some("gzip"), &method, resp).await;
                    assert_eq!(out.status(), status);
                    assert_eq!(polls.load(Ordering::SeqCst), 0);
                    assert_eq!(
                        vary_tokens(out.headers()),
                        expected,
                        "{method} {status} with upstream Vary {up_lines:?}"
                    );
                }
            }

            // Step 3: downstream client with `Accept-Encoding: identity, gzip;q=0` misses the
            // stored gzip entry (since the updated 304 `Vary` kept `Accept-Encoding`) and on its
            // fresh `200` receives identity uncompressed with `Vary: Origin, Accept-Encoding`.
            let mut resp_step3 = Response::new(full_http_body(body_4k.clone()));
            *resp_step3.status_mut() = StatusCode::OK;
            resp_step3
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
            resp_step3
                .headers_mut()
                .insert(CONTENT_LENGTH, HeaderValue::from(body_4k.len()));
            resp_step3
                .headers_mut()
                .insert(VARY, HeaderValue::from_static("Origin"));
            let out_step3 = maybe_compress_proxied_response(
                Some("identity, gzip;q=0"),
                &Method::GET,
                resp_step3,
            )
            .await;
            assert_eq!(out_step3.status(), StatusCode::OK);
            assert!(out_step3.headers().get(CONTENT_ENCODING).is_none());
            assert_eq!(
                vary_tokens(out_step3.headers()),
                vec!["Origin", "Accept-Encoding"]
            );
            assert_eq!(out_step3.into_body().collect().await?.to_bytes(), body_4k);

            Ok::<_, Box<dyn std::error::Error>>(())
        })
    }

    /// Round 11 P1 (Codex Audit 10 sequence, RFC 9110 §9.3.2 & RFC 9111 §3.2 / §4.3.4 / §4.3.5):
    /// 1. A downstream cache stores an English `GET 200` with weak `ETag` and upstream
    ///    `Vary: Accept-Language`. MiraServe compresses the body (`gzip`) and appends
    ///    `Accept-Encoding`, so the stored entry varies on BOTH `Accept-Language` and
    ///    `Accept-Encoding`.
    /// 2. The cache forwards a `HEAD` for the same resource; upstream replies `200 text/plain`
    ///    (or without `Content-Type`), the same weak `ETag`, fresh `Cache-Control`, and omits
    ///    both `Content-Length` and `Vary` (permitted by RFC 9110 §9.3.2). MiraServe MUST
    ///    forward that `HEAD` WITHOUT creating a `Vary` header (and without polling the body) so
    ///    the cache keeps the stored `Vary: Accept-Language, Accept-Encoding` intact instead of
    ///    replacing it with `Vary: Accept-Encoding` and dropping `Accept-Language`.
    /// 3. The same rule applies to a validating `304 Not Modified` without `Vary` (for `GET` or
    ///    `HEAD`, with or without `Content-Type`, across request `Accept-Encoding` values):
    ///    forwarded WITHOUT `Vary` and with zero body polls so the stored `Vary` survives.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn round11_codex_head_and_304_without_vary_preserve_stored_dimensions()
    -> Result<(), Box<dyn std::error::Error>> {
        use http::header::{
            CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, ETAG, VARY,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct UntouchedBody {
            polls: Arc<AtomicUsize>,
        }

        impl http_body::Body for UntouchedBody {
            type Data = Bytes;
            type Error = HttpError;

            fn poll_frame(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
                self.polls.fetch_add(1, Ordering::SeqCst);
                Poll::Ready(None)
            }

            fn is_end_stream(&self) -> bool {
                false
            }
        }

        fn vary_tokens(headers: &http::HeaderMap) -> Vec<String> {
            headers
                .get_all(VARY)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|s| s.split(','))
                .map(|t| t.trim().to_owned())
                .filter(|t| !t.is_empty())
                .collect()
        }

        // Hold `COMPRESS_POOL_TEST_LOCK` around the buffered gzip step so this test cannot race
        // `round8_proxy_vary_structural_across_all_outcomes_and_guards`'s forced-failure hook.
        let _serial = COMPRESS_POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let body_4k = sample_payload(4 * 1024);

        rt.block_on(async {
            // Step 1: initial English `GET 200` with upstream `Vary: Accept-Language`.
            let mut resp_get = Response::new(full_http_body(body_4k.clone()));
            *resp_get.status_mut() = StatusCode::OK;
            resp_get
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
            resp_get
                .headers_mut()
                .insert(CONTENT_LENGTH, HeaderValue::from(body_4k.len()));
            resp_get
                .headers_mut()
                .insert(ETAG, HeaderValue::from_static("W/\"en-v1\""));
            resp_get
                .headers_mut()
                .insert(VARY, HeaderValue::from_static("Accept-Language"));
            resp_get.headers_mut().insert(
                CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=60"),
            );

            let out_get =
                maybe_compress_proxied_response(Some("gzip"), &Method::GET, resp_get).await;
            assert_eq!(out_get.status(), StatusCode::OK);
            assert_eq!(
                out_get
                    .headers()
                    .get(CONTENT_ENCODING)
                    .and_then(|v| v.to_str().ok()),
                Some("gzip")
            );
            assert_eq!(
                out_get.headers().get(ETAG).and_then(|v| v.to_str().ok()),
                Some("W/\"en-v1\"")
            );
            assert_eq!(
                vary_tokens(out_get.headers()),
                vec!["Accept-Language", "Accept-Encoding"]
            );
            let decoded_get = miraserve_static::compress::decompress_gzip(
                &out_get.into_body().collect().await?.to_bytes(),
            )?;
            assert_eq!(decoded_get, body_4k.as_ref());

            // Step 2: matching `HEAD 200` with same weak ETag, fresh policy, NO `Content-Length`,
            // and NO `Vary` -> MUST be forwarded with NO `Vary` (stored `Accept-Language,
            // Accept-Encoding` survives in the cache).
            for ae in [Some("gzip"), None, Some("identity, gzip;q=0")] {
                for ct in [Some("text/plain"), None] {
                    let polls = Arc::new(AtomicUsize::new(0));
                    let mut resp_head = Response::new(
                        UntouchedBody {
                            polls: Arc::clone(&polls),
                        }
                        .boxed(),
                    );
                    *resp_head.status_mut() = StatusCode::OK;
                    if let Some(ct_v) = ct {
                        resp_head
                            .headers_mut()
                            .insert(CONTENT_TYPE, HeaderValue::from_static(ct_v));
                    }
                    resp_head
                        .headers_mut()
                        .insert(ETAG, HeaderValue::from_static("W/\"en-v1\""));
                    resp_head.headers_mut().insert(
                        CACHE_CONTROL,
                        HeaderValue::from_static("public, max-age=120"),
                    );

                    let out_head =
                        maybe_compress_proxied_response(ae, &Method::HEAD, resp_head).await;
                    assert_eq!(out_head.status(), StatusCode::OK);
                    assert_eq!(
                        polls.load(Ordering::SeqCst),
                        0,
                        "HEAD without Vary must never poll body"
                    );
                    assert!(out_head.headers().get(CONTENT_ENCODING).is_none());
                    assert!(out_head.headers().get(CONTENT_LENGTH).is_none());
                    assert!(
                        out_head.headers().get(VARY).is_none(),
                        "HEAD 200 without upstream Vary (ae={ae:?}, ct={ct:?}) MUST NOT synthesize Vary"
                    );
                    assert_eq!(
                        out_head.headers().get(ETAG).and_then(|v| v.to_str().ok()),
                        Some("W/\"en-v1\"")
                    );
                    assert_eq!(
                        out_head
                            .headers()
                            .get(CACHE_CONTROL)
                            .and_then(|v| v.to_str().ok()),
                        Some("public, max-age=120")
                    );
                }
            }

            // Step 3: same sequence for `304 Not Modified` without upstream `Vary` (`GET` and
            // `HEAD`, with and without `Content-Type`, across `Accept-Encoding` values) ->
            // forwarded WITHOUT `Vary` and with zero body polls.
            for method in [Method::GET, Method::HEAD] {
                for ae in [Some("gzip"), None, Some("identity, gzip;q=0")] {
                    for ct in [None, Some("text/plain")] {
                        let polls = Arc::new(AtomicUsize::new(0));
                        let mut resp_304 = Response::new(
                            UntouchedBody {
                                polls: Arc::clone(&polls),
                            }
                            .boxed(),
                        );
                        *resp_304.status_mut() = StatusCode::NOT_MODIFIED;
                        if let Some(ct_v) = ct {
                            resp_304
                                .headers_mut()
                                .insert(CONTENT_TYPE, HeaderValue::from_static(ct_v));
                        }
                        resp_304
                            .headers_mut()
                            .insert(ETAG, HeaderValue::from_static("W/\"en-v1\""));
                        resp_304.headers_mut().insert(
                            CACHE_CONTROL,
                            HeaderValue::from_static("public, max-age=120"),
                        );

                        let out_304 =
                            maybe_compress_proxied_response(ae, &method, resp_304).await;
                        assert_eq!(out_304.status(), StatusCode::NOT_MODIFIED);
                        assert_eq!(
                            polls.load(Ordering::SeqCst),
                            0,
                            "304 without Vary must never poll body"
                        );
                        assert!(out_304.headers().get(CONTENT_ENCODING).is_none());
                        assert!(
                            out_304.headers().get(VARY).is_none(),
                            "{method} 304 without upstream Vary (ae={ae:?}, ct={ct:?}) MUST NOT synthesize Vary"
                        );
                        assert_eq!(
                            out_304.headers().get(ETAG).and_then(|v| v.to_str().ok()),
                            Some("W/\"en-v1\"")
                        );
                        assert_eq!(
                            out_304
                                .headers()
                                .get(CACHE_CONTROL)
                                .and_then(|v| v.to_str().ok()),
                            Some("public, max-age=120")
                        );
                    }
                }
            }

            Ok::<_, Box<dyn std::error::Error>>(())
        })
    }

    /// Round 10/11 (RFC 9110 §9.3.2 & RFC 9111 §3.2 / §4.3.4 / §4.3.5): `HEAD` responses apply
    /// every categorical guard other than the method to the `HEAD` response's own status and
    /// headers (treating missing `Content-Type` on `HEAD` as transformable) and never touch the
    /// body:
    /// - Eligible `HEAD` (and `HEAD 304`) WITH an existing upstream `Vary` merges
    ///   `Accept-Encoding` into it (`*` untouched, no duplicate, all field lines considered).
    /// - Eligible `HEAD` (and `HEAD 304`) with NO upstream `Vary` stays completely untouched
    ///   (matching v0.1.4 so a cache leaves stored `Vary` dimensions intact).
    /// - `HEAD` failing any non-method categorical guard stays untouched even with upstream `Vary`.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn round10_proxy_head_vary_matches_get_categorical_guards()
    -> Result<(), Box<dyn std::error::Error>> {
        use http::header::{
            CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, TRAILER,
            VARY,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct UntouchedBody {
            polls: Arc<AtomicUsize>,
        }

        impl http_body::Body for UntouchedBody {
            type Data = Bytes;
            type Error = HttpError;

            fn poll_frame(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
                self.polls.fetch_add(1, Ordering::SeqCst);
                Poll::Ready(None)
            }

            fn is_end_stream(&self) -> bool {
                false
            }
        }

        fn vary_tokens(headers: &http::HeaderMap) -> Vec<String> {
            headers
                .get_all(VARY)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|s| s.split(','))
                .map(|t| t.trim().to_owned())
                .filter(|t| !t.is_empty())
                .collect()
        }

        type HeadUntouchedRow<'a> = (
            &'a str,
            StatusCode,
            Option<&'a str>,
            Option<(&'a str, &'a str)>,
        );

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        rt.block_on(async {
            let ae_cases = [None, Some("gzip"), Some("identity, gzip;q=0")];
            let vary_cases = [None, Some("Origin"), Some("*"), Some("Accept-Encoding")];

            // Cases where HEAD takes `VaryOnly` (body untouched): merges `Accept-Encoding` ONLY
            // when upstream already sent `Vary`; preserves absence when upstream omitted `Vary`.
            // 1. text with Content-Type (with parameters and Content-Length)
            // 2. no Content-Type ("could be transformed")
            // 3. HEAD 304 Not Modified (handled identically to GET 304 per RFC 9111 §4.3.4)
            let head_vary_only: &[(&str, StatusCode, Option<&str>)] = &[
                (
                    "HEAD-text-with-CT",
                    StatusCode::OK,
                    Some("text/plain; charset=utf-8"),
                ),
                ("HEAD-no-CT", StatusCode::OK, None),
                ("HEAD-304-no-CT", StatusCode::NOT_MODIFIED, None),
                (
                    "HEAD-304-image-CT",
                    StatusCode::NOT_MODIFIED,
                    Some("image/png"),
                ),
            ];

            for &(label, status, ct) in head_vary_only {
                for ae in ae_cases {
                    for up_vary in vary_cases {
                        let polls = Arc::new(AtomicUsize::new(0));
                        let mut resp = Response::new(
                            UntouchedBody {
                                polls: Arc::clone(&polls),
                            }
                            .boxed(),
                        );
                        *resp.status_mut() = status;
                        if let Some(ct_v) = ct {
                            resp.headers_mut()
                                .insert(CONTENT_TYPE, HeaderValue::from_static(ct_v));
                        }
                        if status == StatusCode::OK {
                            resp.headers_mut()
                                .insert(CONTENT_LENGTH, HeaderValue::from_static("4096"));
                        }
                        if let Some(v) = up_vary {
                            resp.headers_mut().insert(VARY, HeaderValue::from_static(v));
                        }

                        let out = maybe_compress_proxied_response(ae, &Method::HEAD, resp).await;
                        assert_eq!(out.status(), status);
                        assert_eq!(
                            polls.load(Ordering::SeqCst),
                            0,
                            "{label}: HEAD body must never be polled"
                        );
                        assert!(out.headers().get(CONTENT_ENCODING).is_none());
                        if status == StatusCode::OK {
                            assert_eq!(
                                out.headers()
                                    .get(CONTENT_LENGTH)
                                    .and_then(|v| v.to_str().ok()),
                                Some("4096"),
                                "{label}: HEAD Content-Length must remain untouched"
                            );
                        }
                        if up_vary.is_none() {
                            assert!(
                                out.headers().get(VARY).is_none(),
                                "{label} (ae={ae:?}, no upstream Vary): must NOT create Vary"
                            );
                        }
                        let tokens = vary_tokens(out.headers());
                        let expected: Vec<&str> = match up_vary {
                            None => Vec::new(),
                            Some("Accept-Encoding") => vec!["Accept-Encoding"],
                            Some("Origin") => vec!["Origin", "Accept-Encoding"],
                            Some("*") => vec!["*"],
                            Some(other) => vec![other],
                        };
                        assert_eq!(tokens, expected, "{label} (ae={ae:?}, up_vary={up_vary:?})");
                    }
                }
            }

            // Cases where HEAD MUST stay untouched (same categorical guards as GET):
            // - image (`image/png`)
            // - upstream-coded (`Content-Encoding: gzip`, both with text CT and with no CT)
            // - 103, 204, 206, Content-Range, Content-Digest, Trailer: Repr-Digest, no-transform, SSE
            let head_untouched: &[HeadUntouchedRow<'_>] = &[
                ("HEAD-image-png", StatusCode::OK, Some("image/png"), None),
                (
                    "HEAD-upstream-coded-text",
                    StatusCode::OK,
                    Some("text/plain"),
                    Some((CONTENT_ENCODING.as_str(), "gzip")),
                ),
                (
                    "HEAD-upstream-coded-no-CT",
                    StatusCode::OK,
                    None,
                    Some((CONTENT_ENCODING.as_str(), "gzip")),
                ),
                (
                    "HEAD-103",
                    StatusCode::EARLY_HINTS,
                    Some("text/plain"),
                    None,
                ),
                ("HEAD-204", StatusCode::NO_CONTENT, None, None),
                (
                    "HEAD-206",
                    StatusCode::PARTIAL_CONTENT,
                    Some("text/plain"),
                    None,
                ),
                (
                    "HEAD-Content-Range",
                    StatusCode::OK,
                    Some("text/plain"),
                    Some((CONTENT_RANGE.as_str(), "bytes 0-10/20")),
                ),
                (
                    "HEAD-Content-Digest",
                    StatusCode::OK,
                    Some("text/plain"),
                    Some(("content-digest", "sha-256=:AAAA:")),
                ),
                (
                    "HEAD-Trailer-Repr-Digest",
                    StatusCode::OK,
                    Some("text/plain"),
                    Some((TRAILER.as_str(), "Repr-Digest")),
                ),
                (
                    "HEAD-no-transform",
                    StatusCode::OK,
                    Some("text/plain"),
                    Some((CACHE_CONTROL.as_str(), "public, no-transform")),
                ),
                ("HEAD-SSE", StatusCode::OK, Some("text/event-stream"), None),
            ];

            for &(label, status, ct, extra) in head_untouched {
                for ae in ae_cases {
                    for up_vary in [None, Some("Origin")] {
                        let polls = Arc::new(AtomicUsize::new(0));
                        let mut resp = Response::new(
                            UntouchedBody {
                                polls: Arc::clone(&polls),
                            }
                            .boxed(),
                        );
                        *resp.status_mut() = status;
                        if let Some(ct_v) = ct {
                            resp.headers_mut()
                                .insert(CONTENT_TYPE, HeaderValue::from_static(ct_v));
                        }
                        if let Some((k, v)) = extra
                            && let Ok(name) = http::HeaderName::from_bytes(k.as_bytes())
                        {
                            resp.headers_mut().insert(name, HeaderValue::from_static(v));
                        }
                        if let Some(v) = up_vary {
                            resp.headers_mut().insert(VARY, HeaderValue::from_static(v));
                        }

                        let out = maybe_compress_proxied_response(ae, &Method::HEAD, resp).await;
                        assert_eq!(out.status(), status);
                        assert_eq!(
                            polls.load(Ordering::SeqCst),
                            0,
                            "{label}: HEAD body must never be polled"
                        );
                        let expected: Vec<&str> = up_vary.into_iter().collect();
                        assert_eq!(
                            vary_tokens(out.headers()),
                            expected,
                            "{label} (ae={ae:?}, up_vary={up_vary:?}) must keep Vary untouched"
                        );
                    }
                }
            }

            Ok::<_, Box<dyn std::error::Error>>(())
        })
    }

    /// Round 6: Exhaustive per-request HTTP/2 stream classification across every handler kind,
    /// WordPress/SPA/proxy `try-files` chains, script directory indexes, `ai-publish` endpoints,
    /// `basic-auth`, ACME, upgrades (`CONNECT` / extended `CONNECT` / `Upgrade`), and error paths.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn round6_classify_h2_stream_exec_all_handlers_and_edge_cases()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::h2_intask::StreamExec;
        use http::Request;
        use miraserve_config::parse_kdl;

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let tmp = std::env::temp_dir().join(format!(
            "miraserve-r6-classify-{}-{}",
            std::process::id(),
            nanos
        ));
        let www = tmp.join("www");
        let pub_dir = tmp.join("pub");
        let missing_dir = tmp.join("does-not-exist");
        let wat_path = tmp.join("noop.wat");
        let users_file = tmp.join("users.txt");
        let ed_pub_file = tmp.join("test-ed25519.pub");
        std::fs::create_dir_all(&www)?;
        std::fs::create_dir_all(&pub_dir)?;
        std::fs::write(
            &wat_path,
            r#"(module (func (export "miraserve_handle") (param i32 i32 i32 i32) (result i32) (i32.const 200)))"#,
        )?;
        // Minimal valid bcrypt users file for basic-auth site.
        std::fs::write(
            &users_file,
            "alice:$2b$04$012345678901234567890u8Y8z3N9xL6v2P5qR7sT1wX4yZ6aB8cD\n",
        )?;
        let ed_key = miraserve_publish::Ed25519SigningKey::generate()?;
        std::fs::write(&ed_pub_file, ed_key.verifying_key().to_encoded())?;

        let www_s = www.to_string_lossy().replace('\\', "/");
        let pub_s = pub_dir.to_string_lossy().replace('\\', "/");
        let missing_s = missing_dir.to_string_lossy().replace('\\', "/");
        let wat_s = wat_path.to_string_lossy().replace('\\', "/");
        let users_s = users_file.to_string_lossy().replace('\\', "/");
        let ed_pub_s = ed_pub_file.to_string_lossy().replace('\\', "/");

        let kdl = format!(
            r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "wp.test" {{
    root "{www_s}"
    index "index.php" "index.html"
    route "*.php" {{
        fastcgi-pass "127.0.0.1:9000"
    }}
    route "/api/*" {{
        reverse-proxy {{
            upstream "http://127.0.0.1:9001"
        }}
    }}
    route "/wasm/*" {{
        wasm-plugin "{wat_s}"
    }}
    route "/mcp" {{
        mcp-gateway upstream="http://127.0.0.1:9002" {{
            oauth-resource-metadata #true
            jwt-public-key "ed25519:{ed_pub_s}"
            jwt-issuer "https://auth.wp.test"
            jwt-audience "https://wp.test/mcp"
            allow-tools "docs_search"
        }}
    }}
    route "/static/*" {{
        root "{www_s}"
        static {{ index "index.html" }}
    }}
    route "/php-dir/*" {{
        root "{www_s}"
        static {{ index "index.php" "index.html" }}
    }}
    route "/redir/*" {{
        redirect "https://other.test{{uri}}" status=301
    }}
    route "/fixed" {{
        respond 503
    }}
    route "/broken/*" {{
        root "{missing_s}"
        static {{}}
    }}
    route "/*" {{
        try-files "{{path}}" "{{path}}/" "/index.php?{{query}}"
    }}
}}
site "spa.test" {{
    root "{www_s}"
    route "/proxy-tf/*" {{
        try-files "{{path}}" "/backend/entry"
    }}
    route "/backend/*" {{
        reverse-proxy {{
            upstream "http://127.0.0.1:9003"
        }}
    }}
    route "/status-tf/*" {{
        try-files "{{path}}" "=404"
    }}
    route "/*" {{
        try-files "{{path}}" "{{path}}/" "/index.html"
    }}
}}
site "default-php.test" {{
    root "{www_s}"
    index "index.php" "index.html"
    route "*.php" {{
        fastcgi-pass "127.0.0.1:9000"
    }}
}}
site "auth.test" {{
    root "{www_s}"
    basic-auth "{users_s}" realm="Admin"
}}
site "publish.test" {{
    ai-publish {{
        storage "{pub_s}"
        require-signature "ed25519:{ed_pub_s}"
        mcp-endpoint "/_miraserve/publish" auth="oauth-jwt"
    }}
}}
site "proxy-only.test" {{
    route "/*" {{
        reverse-proxy {{
            upstream "http://127.0.0.1:9004"
        }}
    }}
}}
"#
        );

        let (cfg, _) = parse_kdl("r6-classify.kdl", &kdl)?;
        let keys = Arc::new(miraserve_ai::AgentKeyRegistry::default());
        let router = super::CompiledRouter::compile(&cfg, &keys)?;
        let acme = miraserve_tls::AcmeChallengeStore::new();
        acme.set_http01_token(
            "proxy-only.test",
            "live_tok_123",
            "live_tok_123.thumb".to_owned(),
        );
        acme.set_http01_token("auth.test", "auth_tok_456", "auth_tok_456.thumb".to_owned());

        let req = |method: Method, host: &str, path: &str| -> Request<()> {
            Request::builder()
                .method(method)
                .uri(format!("https://{host}{path}"))
                .body(())
                .unwrap_or_else(|_| Request::new(()))
        };

        // Direct waiting handlers -> Spawn.
        assert_eq!(
            router.classify_h2_stream_exec(&req(Method::GET, "wp.test", "/api/v1/items"), &acme),
            StreamExec::Spawn
        );
        assert_eq!(
            router.classify_h2_stream_exec(&req(Method::GET, "wp.test", "/index.php"), &acme),
            StreamExec::Spawn
        );
        assert_eq!(
            router.classify_h2_stream_exec(&req(Method::GET, "wp.test", "/wasm/run"), &acme),
            StreamExec::Spawn
        );
        assert_eq!(
            router.classify_h2_stream_exec(&req(Method::POST, "wp.test", "/mcp"), &acme),
            StreamExec::Spawn
        );

        // Static, Redirect, Respond, Unavailable -> InTask.
        assert_eq!(
            router.classify_h2_stream_exec(&req(Method::GET, "wp.test", "/static/"), &acme),
            StreamExec::InTask
        );
        assert_eq!(
            router.classify_h2_stream_exec(&req(Method::GET, "wp.test", "/static/app.css"), &acme),
            StreamExec::InTask
        );
        assert_eq!(
            router.classify_h2_stream_exec(&req(Method::GET, "wp.test", "/redir/old"), &acme),
            StreamExec::InTask
        );
        assert_eq!(
            router.classify_h2_stream_exec(&req(Method::GET, "wp.test", "/fixed"), &acme),
            StreamExec::InTask
        );
        assert_eq!(
            router.classify_h2_stream_exec(&req(Method::GET, "wp.test", "/broken/file.txt"), &acme),
            StreamExec::InTask
        );

        // Static route with `index "index.php"` on a FastCGI site: extensionless -> Spawn,
        // extensioned -> InTask.
        assert_eq!(
            router.classify_h2_stream_exec(&req(Method::GET, "wp.test", "/php-dir/"), &acme),
            StreamExec::Spawn
        );
        assert_eq!(
            router
                .classify_h2_stream_exec(&req(Method::GET, "wp.test", "/php-dir/style.css"), &acme),
            StreamExec::InTask
        );

        // WordPress front-controller `try-files "{path}" "{path}/" "/index.php?{query}"`:
        // - GET/HEAD with file extension -> InTask (keeps static assets fast!)
        // - GET/HEAD without file extension or trailing slash -> Spawn
        // - POST/PUT/DELETE (even with extension) -> Spawn
        assert_eq!(
            router.classify_h2_stream_exec(
                &req(Method::GET, "wp.test", "/wp-content/themes/a/style.css"),
                &acme
            ),
            StreamExec::InTask
        );
        assert_eq!(
            router.classify_h2_stream_exec(&req(Method::HEAD, "wp.test", "/logo.webp"), &acme),
            StreamExec::InTask
        );
        assert_eq!(
            router.classify_h2_stream_exec(&req(Method::GET, "wp.test", "/"), &acme),
            StreamExec::Spawn
        );
        assert_eq!(
            router.classify_h2_stream_exec(&req(Method::GET, "wp.test", "/about"), &acme),
            StreamExec::Spawn
        );
        assert_eq!(
            router.classify_h2_stream_exec(&req(Method::GET, "wp.test", "/2026/11/post/"), &acme),
            StreamExec::Spawn
        );
        assert_eq!(
            router.classify_h2_stream_exec(&req(Method::GET, "wp.test", "/v1.0/users"), &acme),
            StreamExec::Spawn
        );
        assert_eq!(
            router.classify_h2_stream_exec(&req(Method::POST, "wp.test", "/submit.json"), &acme),
            StreamExec::Spawn
        );

        // SPA static `try-files` (`/index.html` fallback) and `=404` fallback -> ALWAYS InTask.
        assert_eq!(
            router.classify_h2_stream_exec(&req(Method::GET, "spa.test", "/"), &acme),
            StreamExec::InTask
        );
        assert_eq!(
            router.classify_h2_stream_exec(
                &req(Method::GET, "spa.test", "/dashboard/settings"),
                &acme
            ),
            StreamExec::InTask
        );
        assert_eq!(
            router.classify_h2_stream_exec(&req(Method::GET, "spa.test", "/bundle.js"), &acme),
            StreamExec::InTask
        );
        assert_eq!(
            router.classify_h2_stream_exec(
                &req(Method::GET, "spa.test", "/status-tf/missing"),
                &acme
            ),
            StreamExec::InTask
        );
        // `try-files` whose fallback targets a reverse-proxy route: extensioned -> InTask,
        // extensionless -> Spawn.
        assert_eq!(
            router
                .classify_h2_stream_exec(&req(Method::GET, "spa.test", "/proxy-tf/app.js"), &acme),
            StreamExec::InTask
        );
        assert_eq!(
            router.classify_h2_stream_exec(&req(Method::GET, "spa.test", "/proxy-tf/page"), &acme),
            StreamExec::Spawn
        );

        // `site.default_static` with `index "index.php"`: extensionless -> Spawn, asset -> InTask.
        assert_eq!(
            router.classify_h2_stream_exec(&req(Method::GET, "default-php.test", "/"), &acme),
            StreamExec::Spawn
        );
        assert_eq!(
            router
                .classify_h2_stream_exec(&req(Method::GET, "default-php.test", "/logo.png"), &acme),
            StreamExec::InTask
        );

        // `basic-auth`: unauthenticated (401 without I/O) -> InTask; with Authorization (bcrypt
        // on pool) -> Spawn.
        assert_eq!(
            router.classify_h2_stream_exec(&req(Method::GET, "auth.test", "/secret.html"), &acme),
            StreamExec::InTask
        );
        let mut authed = req(Method::GET, "auth.test", "/secret.html");
        authed.headers_mut().insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic YWxpY2U6cGFzcw=="),
        );
        assert_eq!(
            router.classify_h2_stream_exec(&authed, &acme),
            StreamExec::Spawn
        );

        // `ai-publish`: publish MCP endpoint -> Spawn; published static asset -> InTask.
        assert_eq!(
            router.classify_h2_stream_exec(
                &req(Method::POST, "publish.test", "/_miraserve/publish"),
                &acme
            ),
            StreamExec::Spawn
        );
        assert_eq!(
            router.classify_h2_stream_exec(&req(Method::GET, "publish.test", "/index.html"), &acme),
            StreamExec::InTask
        );

        // Upgrades: CONNECT, extended CONNECT (`:protocol`), Upgrade header -> Spawn.
        let connect_req = Request::builder()
            .method(Method::CONNECT)
            .uri("wp.test:443")
            .body(())?;
        assert_eq!(
            router.classify_h2_stream_exec(&connect_req, &acme),
            StreamExec::Spawn
        );
        let mut ext_connect = req(Method::GET, "wp.test", "/static/ws");
        ext_connect
            .extensions_mut()
            .insert(hyper::ext::Protocol::from_static("websocket"));
        assert_eq!(
            router.classify_h2_stream_exec(&ext_connect, &acme),
            StreamExec::Spawn
        );
        let mut upg_req = req(Method::GET, "wp.test", "/static/ws");
        upg_req
            .headers_mut()
            .insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
        assert_eq!(
            router.classify_h2_stream_exec(&upg_req, &acme),
            StreamExec::Spawn
        );

        // ACME HTTP-01:
        // - Present token in the in-memory store -> InTask (even on a catch-all proxy or basic-auth site).
        assert_eq!(
            router.classify_h2_stream_exec(
                &req(
                    Method::GET,
                    "proxy-only.test",
                    "/.well-known/acme-challenge/live_tok_123"
                ),
                &acme
            ),
            StreamExec::InTask
        );
        let mut authed_acme_hit = req(
            Method::GET,
            "auth.test",
            "/.well-known/acme-challenge/auth_tok_456",
        );
        authed_acme_hit.headers_mut().insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic YWxpY2U6cGFzcw=="),
        );
        assert_eq!(
            router.classify_h2_stream_exec(&authed_acme_hit, &acme),
            StreamExec::InTask
        );
        // - Non-GET/HEAD valid ACME path -> immediate 405 without I/O -> InTask.
        assert_eq!(
            router.classify_h2_stream_exec(
                &req(
                    Method::POST,
                    "proxy-only.test",
                    "/.well-known/acme-challenge/absent_tok"
                ),
                &acme
            ),
            StreamExec::InTask
        );
        // - Absent token or malformed (`..`) token falls through to normal site/auth/route
        //   classification: catch-all proxy -> Spawn, basic-auth + Authorization -> Spawn,
        //   static SPA site -> InTask.
        assert_eq!(
            router.classify_h2_stream_exec(
                &req(
                    Method::GET,
                    "proxy-only.test",
                    "/.well-known/acme-challenge/absent_tok"
                ),
                &acme
            ),
            StreamExec::Spawn
        );
        assert_eq!(
            router.classify_h2_stream_exec(
                &req(
                    Method::GET,
                    "proxy-only.test",
                    "/.well-known/acme-challenge/tok..bad"
                ),
                &acme
            ),
            StreamExec::Spawn
        );
        let mut authed_acme_miss = req(
            Method::GET,
            "auth.test",
            "/.well-known/acme-challenge/absent_tok",
        );
        authed_acme_miss.headers_mut().insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic YWxpY2U6cGFzcw=="),
        );
        assert_eq!(
            router.classify_h2_stream_exec(&authed_acme_miss, &acme),
            StreamExec::Spawn
        );
        assert_eq!(
            router.classify_h2_stream_exec(
                &req(
                    Method::GET,
                    "PROXY-ONLY.TEST",
                    "/.well-known/acme-challenge/live_tok_123"
                ),
                &acme
            ),
            StreamExec::InTask
        );
        acme.clear_http01_token("proxy-only.test", "live_tok_123");
        assert_eq!(
            router.classify_h2_stream_exec(
                &req(
                    Method::GET,
                    "proxy-only.test",
                    "/.well-known/acme-challenge/live_tok_123"
                ),
                &acme
            ),
            StreamExec::Spawn
        );
        assert_eq!(
            router.classify_h2_stream_exec(
                &req(
                    Method::GET,
                    "spa.test",
                    "/.well-known/acme-challenge/absent_tok"
                ),
                &acme
            ),
            StreamExec::InTask
        );

        // Unmatched host (421), invalid path (400) -> InTask.
        assert_eq!(
            router.classify_h2_stream_exec(&req(Method::GET, "unknown.test", "/api/items"), &acme),
            StreamExec::InTask
        );
        assert_eq!(
            router.classify_h2_stream_exec(&req(Method::GET, "wp.test", "/../etc/passwd"), &acme),
            StreamExec::InTask
        );

        // Overlong request targets (> 8 KiB full target, matching framing):
        // - Long path -> Spawn.
        // - Short static path + long query -> Spawn.
        // - Short static path + short query -> InTask.
        let huge_path = format!("/{}", "a".repeat(9_000));
        assert_eq!(
            router.classify_h2_stream_exec(&req(Method::GET, "wp.test", &huge_path), &acme),
            StreamExec::Spawn
        );
        let short_path_long_query = format!("/static/app.css?q={}", "a".repeat(8_200));
        assert_eq!(
            router.classify_h2_stream_exec(
                &req(Method::GET, "wp.test", &short_path_long_query),
                &acme
            ),
            StreamExec::Spawn
        );
        assert_eq!(
            router.classify_h2_stream_exec(
                &req(Method::GET, "wp.test", "/static/app.css?v=1"),
                &acme
            ),
            StreamExec::InTask
        );

        let _ = std::fs::remove_dir_all(&tmp);
        Ok(())
    }

    /// Round 6/7: Microbenchmark measuring per-request classifier latency across three paths:
    /// 1. Held `CompiledRouter::classify_h2_stream_exec` on canonical lowercase requests;
    /// 2. Full `HttpEngine::classify_h2_stream_exec` (`ArcSwap` router snapshot load + classify)
    ///    + `StreamHandoff::set` (and consume) on canonical lowercase requests;
    /// 3. Full `HttpEngine::classify_h2_stream_exec` + `StreamHandoff::set` (and consume) on
    ///    non-canonical requests (percent-encoded path + upper-case host).
    #[test]
    fn round6_classify_h2_stream_exec_cost_measurement() -> Result<(), Box<dyn std::error::Error>> {
        use crate::HttpEngine;
        use crate::h2_intask::{InTaskExec, StreamExec};
        use http::Request;
        use miraserve_config::parse_kdl;

        const ITERS: usize = 50_000;

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let tmp = std::env::temp_dir().join(format!(
            "miraserve-r6-bench-{}-{}",
            std::process::id(),
            nanos
        ));
        std::fs::create_dir_all(&tmp)?;
        let root_s = tmp.to_string_lossy().replace('\\', "/");
        let kdl = format!(
            r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "bench.test" {{
    root "{root_s}"
    route "/api/*" {{
        reverse-proxy {{
            upstream "http://127.0.0.1:9001"
        }}
    }}
    route "*.php" {{
        fastcgi-pass "127.0.0.1:9000"
    }}
    route "/*" {{
        try-files "{{path}}" "{{path}}/" "/index.php?{{query}}"
    }}
}}
"#
        );
        let (cfg, _) = parse_kdl("r6-bench.kdl", &kdl)?;
        let keys = Arc::new(miraserve_ai::AgentKeyRegistry::default());
        let acme = Arc::new(miraserve_tls::AcmeChallengeStore::new());
        let router = super::CompiledRouter::compile(&cfg, &keys)?;
        let engine = HttpEngine::from_config(&cfg, Arc::clone(&acme), None, 8443)?;
        let (_exec, handoff) = InTaskExec::with_handoff();

        let canonical_reqs = [
            Request::builder()
                .uri("https://bench.test/assets/style.css")
                .body(())?,
            Request::builder()
                .uri("https://bench.test/api/v1/users")
                .body(())?,
            Request::builder()
                .uri("https://bench.test/2026/11/hello-world")
                .body(())?,
        ];
        let noncanonical_reqs = [
            Request::builder()
                .uri("https://BENCH.TEST/assets/my%20style.css")
                .body(())?,
            Request::builder()
                .uri("https://BENCH.TEST/api/v1/user%20list")
                .body(())?,
            Request::builder()
                .uri("https://BENCH.TEST/2026/11/hello%20world")
                .body(())?,
        ];
        let total_calls = ITERS * 3;

        // 1. Held router, canonical requests.
        let t0 = std::time::Instant::now();
        let mut hits_held = 0_usize;
        for _ in 0..ITERS {
            for req in &canonical_reqs {
                if std::hint::black_box(
                    router.classify_h2_stream_exec(std::hint::black_box(req), &acme),
                ) == StreamExec::InTask
                {
                    hits_held += 1;
                }
            }
        }
        let held_ns = t0.elapsed().as_nanos();
        assert_eq!(hits_held, ITERS);

        // 2. Full engine (`ArcSwap::load` + classify) + `StreamHandoff::set` + consume, canonical.
        let t1 = std::time::Instant::now();
        let mut hits_eng_canon = 0_usize;
        for _ in 0..ITERS {
            for req in &canonical_reqs {
                let d = engine.classify_h2_stream_exec(std::hint::black_box(req));
                handoff.set(d);
                if std::hint::black_box(handoff.take_for_test()) == 1 {
                    hits_eng_canon += 1;
                }
            }
        }
        let eng_canon_ns = t1.elapsed().as_nanos();
        assert_eq!(hits_eng_canon, ITERS);

        // 3. Full engine + `StreamHandoff::set` + consume, non-canonical (percent-encoded + UPPER host).
        let t2 = std::time::Instant::now();
        let mut hits_eng_noncanon = 0_usize;
        for _ in 0..ITERS {
            for req in &noncanonical_reqs {
                let d = engine.classify_h2_stream_exec(std::hint::black_box(req));
                handoff.set(d);
                if std::hint::black_box(handoff.take_for_test()) == 1 {
                    hits_eng_noncanon += 1;
                }
            }
        }
        let eng_noncanon_ns = t2.elapsed().as_nanos();
        assert_eq!(hits_eng_noncanon, ITERS);

        eprintln!(
            "[round7 classify cost] held-router canonical: {total_calls} calls in {} us (~{} ns/call); \
             engine+handoff canonical: {} us (~{} ns/call); \
             engine+handoff non-canonical: {} us (~{} ns/call)",
            held_ns / 1_000,
            held_ns / (total_calls as u128),
            eng_canon_ns / 1_000,
            eng_canon_ns / (total_calls as u128),
            eng_noncanon_ns / 1_000,
            eng_noncanon_ns / (total_calls as u128),
        );

        let _ = std::fs::remove_dir_all(&tmp);
        Ok(())
    }

    /// Header-rule check: `add "Vary" "Cookie"` (at site level and at route level)
    /// and the reverse proxy's `Vary: Accept-Encoding` BOTH reach the client on a proxied
    /// compressible response — with gzip applied and with identity, and preserving an upstream
    /// `Vary: Origin` as well.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn proxy_add_vary_cookie_header_rule_preserves_proxy_and_upstream_vary()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::CompiledRouter;
        use crate::{RequestContext, empty_http_body};
        use http::Request;
        use http::header::{ACCEPT_ENCODING, CONTENT_ENCODING, HOST, VARY};
        use http_body_util::BodyExt as _;
        use miraserve_ai::AgentKeyRegistry;
        use miraserve_config::{LimitsConfig, parse_kdl};
        use miraserve_telemetry::TelemetryRegistry;
        use miraserve_tls::AcmeChallengeStore;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        fn vary_tokens(headers: &http::HeaderMap) -> Vec<String> {
            headers
                .get_all(VARY)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|s| s.split(','))
                .map(|t| t.trim().to_owned())
                .filter(|t| !t.is_empty())
                .collect()
        }

        let _serial = COMPRESS_POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        rt.block_on(async {
            let payload = sample_payload(4 * 1024);
            let payload_c = payload.clone();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let upstream_addr = listener.local_addr()?;
            let upstream_task = tokio::spawn(async move {
                while let Ok((mut sock, _)) = listener.accept().await {
                    let body = payload_c.clone();
                    tokio::spawn(async move {
                        let mut buf = [0_u8; 4096];
                        let Ok(n) = sock.read(&mut buf).await else {
                            return;
                        };
                        let head = String::from_utf8_lossy(buf.get(..n).unwrap_or(&[]));
                        let with_origin = head.contains("/with-origin");
                        let vary_line = if with_origin { "Vary: Origin\r\n" } else { "" };
                        let resp_head = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{vary_line}Connection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = sock.write_all(resp_head.as_bytes()).await;
                        let _ = sock.write_all(&body).await;
                        let _ = sock.shutdown().await;
                    });
                }
            });

            let kdl = format!(
                r#"
server {{
    listen "127.0.0.1:8443" protocols="h1"
}}
site "site-add-vary.example" {{
    headers {{
        add "Vary" "Cookie"
    }}
    route "/api/*" {{
        reverse-proxy {{
            upstream "http://{upstream_addr}"
        }}
    }}
}}
site "route-add-vary.example" {{
    route "/api/*" {{
        reverse-proxy {{
            upstream "http://{upstream_addr}"
        }}
        headers {{
            add "Vary" "Cookie"
        }}
    }}
}}
"#
            );
            let (cfg, _) = parse_kdl("proxy_add_vary.kdl", &kdl)?;
            let registry = Arc::new(AgentKeyRegistry::new());
            let router = CompiledRouter::compile(&cfg, &registry)?;
            let limits = LimitsConfig::default();
            let acme = AcmeChallengeStore::new();
            let telemetry = TelemetryRegistry::new();
            let ctx = RequestContext {
                client_ip: None,
                remote_port: None,
                server_addr: None,
                server_port: 8443,
                is_https: true,
                tls: None,
            };

            for host in ["site-add-vary.example", "route-add-vary.example"] {
                for (path, has_origin) in [("/api/plain", false), ("/api/with-origin", true)] {
                    for (ae, expect_gzip) in [(Some("gzip"), true), (None, false)] {
                        let mut builder = Request::builder()
                            .method(Method::GET)
                            .uri(path)
                            .header(HOST, host);
                        if let Some(ae_val) = ae {
                            builder = builder.header(ACCEPT_ENCODING, ae_val);
                        }
                        let req = builder.body(empty_http_body())?;
                        let resp = router
                            .dispatch(req, &ctx, &limits, &acme, None, &telemetry)
                            .await;
                        assert_eq!(resp.status(), StatusCode::OK);
                        if expect_gzip {
                            assert_eq!(
                                resp.headers()
                                    .get(CONTENT_ENCODING)
                                    .and_then(|v| v.to_str().ok()),
                                Some("gzip"),
                                "{host}{path} (ae={ae:?}) expected gzip"
                            );
                        } else {
                            assert!(
                                resp.headers().get(CONTENT_ENCODING).is_none(),
                                "{host}{path} (ae={ae:?}) expected identity"
                            );
                        }
                        let tokens = vary_tokens(resp.headers());
                        let expected = if has_origin {
                            vec!["Origin", "Accept-Encoding", "Cookie"]
                        } else {
                            vec!["Accept-Encoding", "Cookie"]
                        };
                        assert_eq!(
                            tokens, expected,
                            "{host}{path} (ae={ae:?}) must preserve all Vary values"
                        );
                        let raw = resp.into_body().collect().await?.to_bytes();
                        if expect_gzip {
                            let decoded = miraserve_static::compress::decompress_gzip(&raw)?;
                            assert_eq!(decoded, payload.as_ref());
                        } else {
                            assert_eq!(raw, payload);
                        }
                    }
                }
            }

            upstream_task.abort();
            Ok::<_, Box<dyn std::error::Error>>(())
        })
    }

    /// Header-rule pin: `set "Vary" "Cookie"` (site-level or route-level) replaces ALL
    /// `Vary` header lines — including the proxy's `Accept-Encoding` and any upstream `Vary` — as
    /// the operator's explicit override (unchanged from v0.1.4).
    #[test]
    #[allow(clippy::too_many_lines)]
    fn proxy_set_vary_cookie_header_rule_replaces_all_vary_lines()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::CompiledRouter;
        use crate::{RequestContext, empty_http_body};
        use http::Request;
        use http::header::{ACCEPT_ENCODING, CONTENT_ENCODING, HOST, VARY};
        use miraserve_ai::AgentKeyRegistry;
        use miraserve_config::{LimitsConfig, parse_kdl};
        use miraserve_telemetry::TelemetryRegistry;
        use miraserve_tls::AcmeChallengeStore;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        fn vary_tokens(headers: &http::HeaderMap) -> Vec<String> {
            headers
                .get_all(VARY)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|s| s.split(','))
                .map(|t| t.trim().to_owned())
                .filter(|t| !t.is_empty())
                .collect()
        }

        let _serial = COMPRESS_POOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        rt.block_on(async {
            let payload = sample_payload(4 * 1024);
            let payload_c = payload.clone();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let upstream_addr = listener.local_addr()?;
            let upstream_task = tokio::spawn(async move {
                while let Ok((mut sock, _)) = listener.accept().await {
                    let body = payload_c.clone();
                    tokio::spawn(async move {
                        let mut buf = [0_u8; 4096];
                        let Ok(n) = sock.read(&mut buf).await else {
                            return;
                        };
                        let head = String::from_utf8_lossy(buf.get(..n).unwrap_or(&[]));
                        let vary_lines = if head.contains("/with-origin") {
                            "Vary: Origin\r\nVary: Accept-Language\r\n"
                        } else {
                            ""
                        };
                        let resp_head = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{vary_lines}Connection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = sock.write_all(resp_head.as_bytes()).await;
                        let _ = sock.write_all(&body).await;
                        let _ = sock.shutdown().await;
                    });
                }
            });

            let kdl = format!(
                r#"
server {{
    listen "127.0.0.1:8443" protocols="h1"
}}
site "site-set-vary.example" {{
    headers {{
        set "Vary" "Cookie"
    }}
    route "/api/*" {{
        reverse-proxy {{
            upstream "http://{upstream_addr}"
        }}
    }}
}}
site "route-set-vary.example" {{
    route "/api/*" {{
        reverse-proxy {{
            upstream "http://{upstream_addr}"
        }}
        headers {{
            set "Vary" "Cookie"
        }}
    }}
}}
"#
            );
            let (cfg, _) = parse_kdl("proxy_set_vary.kdl", &kdl)?;
            let registry = Arc::new(AgentKeyRegistry::new());
            let router = CompiledRouter::compile(&cfg, &registry)?;
            let limits = LimitsConfig::default();
            let acme = AcmeChallengeStore::new();
            let telemetry = TelemetryRegistry::new();
            let ctx = RequestContext {
                client_ip: None,
                remote_port: None,
                server_addr: None,
                server_port: 8443,
                is_https: true,
                tls: None,
            };

            for host in ["site-set-vary.example", "route-set-vary.example"] {
                for path in ["/api/plain", "/api/with-origin"] {
                    for (ae, expect_gzip) in [(Some("gzip"), true), (None, false)] {
                        let mut builder = Request::builder()
                            .method(Method::GET)
                            .uri(path)
                            .header(HOST, host);
                        if let Some(ae_val) = ae {
                            builder = builder.header(ACCEPT_ENCODING, ae_val);
                        }
                        let req = builder.body(empty_http_body())?;
                        let resp = router
                            .dispatch(req, &ctx, &limits, &acme, None, &telemetry)
                            .await;
                        assert_eq!(resp.status(), StatusCode::OK);
                        if expect_gzip {
                            assert_eq!(
                                resp.headers()
                                    .get(CONTENT_ENCODING)
                                    .and_then(|v| v.to_str().ok()),
                                Some("gzip")
                            );
                        } else {
                            assert!(resp.headers().get(CONTENT_ENCODING).is_none());
                        }
                        assert_eq!(
                            resp.headers().get_all(VARY).iter().count(),
                            1,
                            "{host}{path} (ae={ae:?}) set Vary must collapse to one header line"
                        );
                        assert_eq!(
                            vary_tokens(resp.headers()),
                            vec!["Cookie"],
                            "{host}{path} (ae={ae:?}) set Vary must replace all Vary values"
                        );
                    }
                }
            }

            upstream_task.abort();
            Ok::<_, Box<dyn std::error::Error>>(())
        })
    }

    #[test]
    fn proxy_worker_pool_count_matches_event_loop_policy() -> Result<(), Box<dyn std::error::Error>>
    {
        use miraserve_config::parse_kdl;

        let (shared_cfg, _) = parse_kdl(
            "shared.kdl",
            r#"server { listen "127.0.0.1:8443" protocols="h1" }"#,
        )?;
        assert_eq!(super::proxy_worker_pool_count(&shared_cfg), 0);

        let (count_cfg, _) = parse_kdl(
            "count.kdl",
            r#"server { listen "127.0.0.1:8443" protocols="h1"
                workers 3 }"#,
        )?;
        if cfg!(target_os = "linux") {
            assert_eq!(super::proxy_worker_pool_count(&count_cfg), 3);
        } else {
            assert_eq!(super::proxy_worker_pool_count(&count_cfg), 0);
        }

        let (split_cfg, _) = parse_kdl(
            "split.kdl",
            r#"server { listen "127.0.0.1:8443" protocols="h1"
                workers 3
                tls { key-isolation "split-daemon"
                      keyd-socket "/run/miraserve-keyd/keyd.sock" } }"#,
        )?;
        assert_eq!(super::proxy_worker_pool_count(&split_cfg), 0);
        Ok(())
    }

    /// Capacity-independence and zero-regrow test (NOT a `416f01f` oracle — see
    /// `tests/static_header_order_oracle_tests.rs` for the independent `416f01f` wire-order
    /// oracle).
    ///
    /// Proves that sizing `StaticServer` with `extra_static_response_header_budget` prevents ANY
    /// `HeaderMap` capacity growth all the way through the real end of the router post-processing
    /// pipeline — including `apply_security_headers`, `apply_header_rules` (with repeated `add` at
    /// exact capacity), the router's `Alt-Svc` restore re-insertion (Codex Round-1 P2-3: 6 file
    /// headers + Standard security + Alt-Svc = 12 keys), plain-HTTP HSTS/Alt-Svc stripping, and
    /// `make_private` on protected sites — while confirming identical raw-byte header sequences
    /// compared to `extra_response_headers = 0`.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn static_single_shot_header_budget_capacity_independence_and_zero_regrow_after_router_restore()
    -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(unix)]
        use http::header::IF_NONE_MATCH;
        use http::header::{
            ACCEPT_ENCODING, ALT_SVC, HeaderName, RANGE, STRICT_TRANSPORT_SECURITY,
        };
        #[cfg(not(unix))]
        use http::header::{IF_MODIFIED_SINCE, LAST_MODIFIED};
        use http::{HeaderMap, Method, StatusCode, Version};
        use miraserve_config::{
            HeaderAction, HeaderRule, PrecompressedPolicy, SecurityHeadersPolicy, StaticConfig,
        };
        use miraserve_static::compress::{ContentEncoding, compress_bytes};
        use miraserve_static::{FileCache, FileCacheBudget, FileCacheCounters, StaticServer};

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(async {
            let dir = std::env::temp_dir().join(format!(
                "miraserve-static-hdr-cap-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir)?;
            let payload = "Static capacity-independence payload line.\n".repeat(48);
            std::fs::write(dir.join("a.txt"), payload.as_bytes())?;
            let gz = compress_bytes(ContentEncoding::Gzip, payload.as_bytes())?;
            std::fs::write(dir.join("a.txt.gz"), &gz)?;

            // Repeated `add` hitting exact 12-key boundary under Off + Alt-Svc (6 own + 2 sec + 4
            // distinct = 12 keys, followed by a 2nd `add` on `x-at12-4` and `Alt-Svc` restore).
            let exact_12_repeated_add = super::compile_header_rules(&[
                HeaderRule {
                    action: HeaderAction::Set,
                    name: "x-at12-1".to_owned(),
                    value: Some("1".to_owned()),
                    status: Vec::new(),
                },
                HeaderRule {
                    action: HeaderAction::Set,
                    name: "x-at12-2".to_owned(),
                    value: Some("2".to_owned()),
                    status: Vec::new(),
                },
                HeaderRule {
                    action: HeaderAction::Set,
                    name: "x-at12-3".to_owned(),
                    value: Some("3".to_owned()),
                    status: Vec::new(),
                },
                HeaderRule {
                    action: HeaderAction::Add,
                    name: "x-at12-4".to_owned(),
                    value: Some("a".to_owned()),
                    status: Vec::new(),
                },
                HeaderRule {
                    action: HeaderAction::Add,
                    name: "x-at12-4".to_owned(),
                    value: Some("b".to_owned()),
                    status: Vec::new(),
                },
            ])?;
            let site_rules = super::compile_header_rules(&[
                HeaderRule {
                    action: HeaderAction::Set,
                    name: "cache-control".to_owned(),
                    value: Some("public, max-age=60".to_owned()),
                    status: Vec::new(),
                },
                HeaderRule {
                    action: HeaderAction::Add,
                    name: "x-multi".to_owned(),
                    value: Some("a".to_owned()),
                    status: Vec::new(),
                },
                HeaderRule {
                    action: HeaderAction::Add,
                    name: "x-multi".to_owned(),
                    value: Some("b".to_owned()),
                    status: Vec::new(),
                },
                HeaderRule {
                    action: HeaderAction::Remove,
                    name: "x-content-type-options".to_owned(),
                    value: None,
                    status: Vec::new(),
                },
            ])?;
            let route_rules = super::compile_header_rules(&[
                HeaderRule {
                    action: HeaderAction::Set,
                    name: "x-r1".to_owned(),
                    value: Some("1".to_owned()),
                    status: Vec::new(),
                },
                HeaderRule {
                    action: HeaderAction::Set,
                    name: "x-r2".to_owned(),
                    value: Some("2".to_owned()),
                    status: Vec::new(),
                },
                HeaderRule {
                    action: HeaderAction::Set,
                    name: "x-r3".to_owned(),
                    value: Some("3".to_owned()),
                    status: Vec::new(),
                },
            ])?;

            let alt = crate::headers::alt_svc_header_value(8443);
            let opts = StaticConfig {
                precompressed: PrecompressedPolicy::ALL,
                ..StaticConfig::default()
            };
            let cache = Arc::new(FileCache::new(
                Arc::new(FileCacheBudget::new(1024 * 1024)),
                FileCacheCounters::new(),
            ));

            for policy in [
                SecurityHeadersPolicy::Off,
                SecurityHeadersPolicy::Standard,
                SecurityHeadersPolicy::Strict,
            ] {
                for (rule_case, sr, rr) in [
                    ("routed_no_rules_restore", &[][..], &[][..]),
                    ("exact_12_repeated_add", &exact_12_repeated_add[..], &[][..]),
                    ("site_and_route_rules", &site_rules[..], &route_rules[..]),
                ] {
                    for site_protected in [false, true] {
                        let budget = super::extra_static_response_header_budget(
                            policy,
                            sr,
                            rr,
                            site_protected,
                        );
                        for use_cache in [false, true] {
                            let mut sized = StaticServer::open(&dir, opts.clone())?
                                .with_extra_response_headers(budget);
                            let mut unhinted = StaticServer::open(&dir, opts.clone())?;
                            if use_cache {
                                sized = sized.with_file_cache(
                                    Arc::clone(&cache),
                                    std::time::Duration::from_secs(30),
                                );
                                unhinted = unhinted.with_file_cache(
                                    Arc::clone(&cache),
                                    std::time::Duration::from_secs(30),
                                );
                            }

                            let probe = sized
                                .serve_canonical(&Method::GET, "/a.txt", &HeaderMap::new())
                                .await;
                            let mut range_hdrs = HeaderMap::new();
                            range_hdrs.insert(RANGE, HeaderValue::from_static("bytes=0-63"));
                            let mut cond_304_hdrs = HeaderMap::new();
                            #[cfg(unix)]
                            {
                                let etag = probe
                                    .headers()
                                    .get(ETAG)
                                    .cloned()
                                    .ok_or("missing etag on unix")?;
                                cond_304_hdrs.insert(IF_NONE_MATCH, etag);
                            }
                            #[cfg(not(unix))]
                            {
                                // Non-Unix platforms deliberately emit no ETag (`format_etag` needs
                                // inode ctime); trigger 304 via `If-Modified-Since` instead.
                                assert!(
                                    probe.headers().get(ETAG).is_none(),
                                    "non-unix static response unexpectedly emitted ETag"
                                );
                                let lm = probe
                                    .headers()
                                    .get(LAST_MODIFIED)
                                    .cloned()
                                    .ok_or("missing last-modified")?;
                                cond_304_hdrs.insert(IF_MODIFIED_SINCE, lm);
                            }
                            let mut gz_hdrs = HeaderMap::new();
                            gz_hdrs.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip"));

                            let cases: &[(&str, Method, &HeaderMap, StatusCode)] = &[
                                ("200", Method::GET, &HeaderMap::new(), StatusCode::OK),
                                (
                                    "206",
                                    Method::GET,
                                    &range_hdrs,
                                    StatusCode::PARTIAL_CONTENT,
                                ),
                                (
                                    "304",
                                    Method::GET,
                                    &cond_304_hdrs,
                                    StatusCode::NOT_MODIFIED,
                                ),
                                ("HEAD", Method::HEAD, &HeaderMap::new(), StatusCode::OK),
                                ("gz", Method::GET, &gz_hdrs, StatusCode::OK),
                            ];

                            for &(case_name, ref method, req_hdrs, expected_status) in cases {
                                for is_https in [false, true] {
                                    for alt_opt in [None, alt.as_ref()] {
                                        let mut r_sized =
                                            sized.serve_canonical(method, "/a.txt", req_hdrs).await;
                                        let mut r_unhinted = unhinted
                                            .serve_canonical(method, "/a.txt", req_hdrs)
                                            .await;
                                        let cap_before = r_sized.headers().capacity();
                                        let status = r_sized.status();
                                        assert_eq!(
                                            status, expected_status,
                                            "case={case_name} returned {status}, expected {expected_status}"
                                        );
                                        assert_eq!(status, r_unhinted.status());
                                        if case_name == "gz" {
                                            assert_eq!(
                                                r_sized.headers().get(http::header::CONTENT_ENCODING),
                                                Some(&HeaderValue::from_static("gzip")),
                                                "gz case must emit Content-Encoding: gzip"
                                            );
                                        }

                                        // Run the FULL router post-processing sequence: security
                                        // headers, rules, server-owned `Alt-Svc` restore (which
                                        // runs on every routed response via `RouteHeaderRules`),
                                        // plain-HTTP HSTS/Alt-Svc strip, and `make_private`.
                                        for resp in [&mut r_sized, &mut r_unhinted] {
                                            crate::headers::apply_security_headers(
                                                resp.headers_mut(),
                                                policy,
                                                is_https,
                                                alt_opt,
                                                Version::HTTP_11,
                                                false,
                                            );
                                            let saved_alt_svc =
                                                resp.headers().get(ALT_SVC).cloned();
                                            if !sr.is_empty() {
                                                super::apply_header_rules(
                                                    resp.headers_mut(),
                                                    status,
                                                    sr,
                                                );
                                            }
                                            if !rr.is_empty() {
                                                super::apply_header_rules(
                                                    resp.headers_mut(),
                                                    status,
                                                    rr,
                                                );
                                            }
                                            if let Some(alt_svc) = saved_alt_svc {
                                                resp.headers_mut().insert(ALT_SVC, alt_svc);
                                            }
                                            if !is_https {
                                                resp.headers_mut()
                                                    .remove(STRICT_TRANSPORT_SECURITY);
                                                resp.headers_mut().remove(ALT_SVC);
                                            }
                                            if site_protected {
                                                super::make_private(resp.headers_mut());
                                            }
                                        }

                                        let cap_after = r_sized.headers().capacity();
                                        assert_eq!(
                                            cap_before, cap_after,
                                            "HeaderMap regrew ({cap_before} -> {cap_after}) after router restore for case={case_name} rules={rule_case} protected={site_protected} policy={policy:?} cache={use_cache} https={is_https} alt={alt_opt:?}"
                                        );
                                        let sized_seq: Vec<(HeaderName, Vec<u8>)> = r_sized
                                            .headers()
                                            .iter()
                                            .map(|(k, v)| (k.clone(), v.as_bytes().to_vec()))
                                            .collect();
                                        let unhinted_seq: Vec<(HeaderName, Vec<u8>)> = r_unhinted
                                            .headers()
                                            .iter()
                                            .map(|(k, v)| (k.clone(), v.as_bytes().to_vec()))
                                            .collect();
                                        assert_eq!(
                                            sized_seq, unhinted_seq,
                                            "capacity-independence check diverged for case={case_name} rules={rule_case} protected={site_protected} policy={policy:?} cache={use_cache} https={is_https} alt={alt_opt:?}"
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let _ = std::fs::remove_dir_all(&dir);
            Ok::<_, Box<dyn std::error::Error>>(())
        })
    }

    /// Real-path end-to-end capacity test through `HttpEngine::handle_request` ->
    /// `CompiledRouter::dispatch_with_request_id` -> `serve_static_with_markdown` ->
    /// `markdown_or_file` -> `apply_security_headers` -> `apply_header_rules` -> `Alt-Svc`
    /// restore -> `make_private` (NOT a hand replay).
    ///
    /// Covers Codex Round-2's negotiated authored Markdown sibling `304` case (`Vary`, `ETag`,
    /// `Last-Modified`, then `Content-Type` from Markdown negotiation, `Strict` HTTPS + `Alt-Svc`,
    /// and a site rule removing an absent field -> 12 keys + `Alt-Svc` restore), agent-selected
    /// Markdown adding `Cache-Control` earlier via `bot-auth`, header-dependent rewrites adding
    /// `ProtectedResponse` -> `make_private`, and confirms ordinary non-Markdown `304` responses
    /// remain in the smaller 12-key bucket.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn static_markdown_negotiation_real_path_never_regrows_header_map()
    -> Result<(), Box<dyn std::error::Error>> {
        use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
        use base64::Engine as _;
        #[cfg(unix)]
        use http::header::IF_NONE_MATCH;
        use http::header::{
            ACCEPT, ALT_SVC, CACHE_CONTROL, CONTENT_TYPE, ETAG, HOST, STRICT_TRANSPORT_SECURITY,
            USER_AGENT, VARY,
        };
        #[cfg(not(unix))]
        use http::header::{IF_MODIFIED_SINCE, LAST_MODIFIED};
        use http::{HeaderMap, Method, Request, StatusCode, Uri};
        use miraserve_ai::sign_rfc9421_headers;
        use miraserve_config::parse_kdl;
        use miraserve_tls::AcmeChallengeStore;
        use std::time::{SystemTime, UNIX_EPOCH};

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(async {
            let dir = std::env::temp_dir().join(format!(
                "miraserve-static-md-cap-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir)?;
            std::fs::write(dir.join("page.html"), b"<h1>Hello</h1>\n")?;
            std::fs::write(dir.join("page.md"), b"# Hello\n")?;
            std::fs::write(dir.join("plain.txt"), b"plain text payload\n")?;

            let root_kdl = format!(
                "\"{}\"",
                dir.to_string_lossy().replace('\\', "\\\\").replace('"', "\\\"")
            );
            let https_ctx = crate::RequestContext {
                client_ip: Some("198.51.100.40".parse()?),
                remote_port: Some(41000),
                server_addr: Some("127.0.0.1".parse()?),
                server_port: 8443,
                is_https: true,
                tls: None,
            };

            let take_initial_cap = || -> Result<usize, Box<dyn std::error::Error>> {
                super::LAST_STATIC_RESPONSE_INITIAL_CAP
                    .with(std::cell::Cell::take)
                    .ok_or_else(|| "expected static response initial capacity to be recorded".into())
            };

            // Build conditional 304 headers on Unix (ETag) or non-Unix (Last-Modified).
            let cond_304_header = |probe: &http::Response<crate::HttpBody>| -> Result<(http::HeaderName, HeaderValue), Box<dyn std::error::Error>> {
                #[cfg(unix)]
                {
                    let etag = probe
                        .headers()
                        .get(ETAG)
                        .cloned()
                        .ok_or("missing etag on unix")?;
                    Ok((IF_NONE_MATCH, etag))
                }
                #[cfg(not(unix))]
                {
                    assert!(
                        probe.headers().get(ETAG).is_none(),
                        "non-unix static response unexpectedly emitted ETag"
                    );
                    let lm = probe
                        .headers()
                        .get(LAST_MODIFIED)
                        .cloned()
                        .ok_or("missing last-modified")?;
                    Ok((IF_MODIFIED_SINCE, lm))
                }
            };

            // 1. Codex Round-2 exact case: negotiated authored Markdown sibling answering 304 under
            //    Strict HTTPS + Alt-Svc + site rule removing an absent field (12 keys + restore).
            {
                let kdl = format!(
                    r#"
server {{
    listen "127.0.0.1:8443" protocols="h1,h2,h3"
}}
site "md.test" {{
    root {root_kdl}
    security-headers "strict"
    headers {{
        remove "x-absent-field"
    }}
}}
"#
                );
                let (cfg, _) = parse_kdl("md-cap-1.kdl", &kdl)?;
                let engine = crate::HttpEngine::from_config(
                    &cfg,
                    Arc::new(AcmeChallengeStore::new()),
                    Some(8443),
                    8443,
                )?;

                // Probe authored Markdown sibling to obtain its validator.
                let probe_req = Request::builder()
                    .method(Method::GET)
                    .uri("/page.html")
                    .header(HOST, "md.test")
                    .header(ACCEPT, "text/markdown")
                    .body(crate::empty_http_body())?;
                super::LAST_STATIC_RESPONSE_INITIAL_CAP.with(|c| c.set(None));
                let probe = engine.handle_request(probe_req, &https_ctx).await;
                let probe_init_cap = take_initial_cap()?;
                assert_eq!(probe.status(), StatusCode::OK);
                assert_eq!(probe_init_cap, probe.headers().capacity());
                let (cond_name, cond_val) = cond_304_header(&probe)?;

                // Real negotiated 304 for authored Markdown sibling!
                let req_304 = Request::builder()
                    .method(Method::GET)
                    .uri("/page.html")
                    .header(HOST, "md.test")
                    .header(ACCEPT, "text/markdown")
                    .header(cond_name, cond_val)
                    .body(crate::empty_http_body())?;
                super::LAST_STATIC_RESPONSE_INITIAL_CAP.with(|c| c.set(None));
                let resp = engine.handle_request(req_304, &https_ctx).await;
                let cap_initial = take_initial_cap()?;
                assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
                assert_eq!(
                    resp.headers().get(CONTENT_TYPE),
                    Some(&HeaderValue::from_static("text/markdown; charset=utf-8"))
                );
                assert_eq!(
                    resp.headers().get(VARY),
                    Some(&HeaderValue::from_static("Accept, Accept-Encoding"))
                );
                assert!(resp.headers().contains_key(ALT_SVC));
                assert!(resp.headers().contains_key(STRICT_TRANSPORT_SECURITY));
                #[cfg(unix)]
                assert_eq!(
                    resp.headers().keys_len(),
                    12,
                    "expected exact 12 keys on Strict HTTPS + Alt-Svc Markdown sibling 304"
                );
                assert_eq!(
                    cap_initial,
                    resp.headers().capacity(),
                    "HeaderMap regrew ({cap_initial} -> {}) on negotiated authored Markdown sibling 304",
                    resp.headers().capacity()
                );
            }

            // 2. Agent-selected Markdown (`bot-auth` `serve-markdown=#true`) adding `Cache-Control`
            //    early on both 304 and 200 under Standard and Strict HTTPS + Alt-Svc + remove rule.
            {
                let key = Ed25519KeyPair::generate().map_err(|_| "key generation failed")?;
                let public_b64 =
                    base64::engine::general_purpose::STANDARD.encode(key.public_key().as_ref());
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());

                for (policy_name, extra_rule_kdl) in [
                    ("standard", "set \"x-one\" \"1\""),
                    ("strict", ""),
                ] {
                    let kdl = format!(
                        r#"
server {{
    listen "127.0.0.1:8443" protocols="h1,h2,h3"
}}
site "bot-md.test" {{
    root {root_kdl}
    security-headers "{policy_name}"
    bot-auth {{
        verify-rfc9421 #true
        allow-agent "verified-ai-agents" serve-markdown=#true
        agent-key "k1" agent-id="bot-k1" group="verified-ai-agents" ed25519="{public_b64}"
    }}
    headers {{
        {extra_rule_kdl}
        remove "x-absent-field"
    }}
}}
"#
                    );
                    let (cfg, _) = parse_kdl("md-cap-2.kdl", &kdl)?;
                    let engine = crate::HttpEngine::from_config(
                        &cfg,
                        Arc::new(AcmeChallengeStore::new()),
                        Some(8443),
                        8443,
                    )?;

                    let build_signed = |extra_hdr: Option<(http::HeaderName, HeaderValue)>| -> Result<Request<crate::HttpBody>, Box<dyn std::error::Error>> {
                        let uri: Uri = "/page.html".parse()?;
                        let mut hdrs = HeaderMap::new();
                        hdrs.insert(HOST, HeaderValue::from_static("bot-md.test"));
                        hdrs.insert(USER_AGENT, HeaderValue::from_static("GPTBot/1.0"));
                        if let Some((k, v)) = extra_hdr {
                            hdrs.insert(k, v);
                        }
                        sign_rfc9421_headers(
                            &Method::GET,
                            &uri,
                            &mut hdrs,
                            "k1",
                            &key,
                            now,
                            now.saturating_add(120),
                        )?;
                        let mut req = Request::builder()
                            .method(Method::GET)
                            .uri(uri)
                            .body(crate::empty_http_body())?;
                        *req.headers_mut() = hdrs;
                        Ok(req)
                    };

                    // 200 agent-selected Markdown
                    super::LAST_STATIC_RESPONSE_INITIAL_CAP.with(|c| c.set(None));
                    let resp_200 = engine
                        .handle_request(build_signed(None)?, &https_ctx)
                        .await;
                    let cap_200_init = take_initial_cap()?;
                    assert_eq!(resp_200.status(), StatusCode::OK);
                    assert_eq!(
                        resp_200.headers().get(CONTENT_TYPE),
                        Some(&HeaderValue::from_static("text/markdown; charset=utf-8"))
                    );
                    assert_eq!(
                        resp_200.headers().get(CACHE_CONTROL),
                        Some(&HeaderValue::from_static("private, no-transform"))
                    );
                    assert_eq!(
                        cap_200_init,
                        resp_200.headers().capacity(),
                        "HeaderMap regrew ({cap_200_init} -> {}) on agent-selected Markdown 200 (policy={policy_name})",
                        resp_200.headers().capacity()
                    );

                    // 304 agent-selected Markdown
                    let cond = cond_304_header(&resp_200)?;
                    super::LAST_STATIC_RESPONSE_INITIAL_CAP.with(|c| c.set(None));
                    let resp_304 = engine
                        .handle_request(build_signed(Some(cond))?, &https_ctx)
                        .await;
                    let cap_304_init = take_initial_cap()?;
                    assert_eq!(resp_304.status(), StatusCode::NOT_MODIFIED);
                    assert_eq!(
                        resp_304.headers().get(CONTENT_TYPE),
                        Some(&HeaderValue::from_static("text/markdown; charset=utf-8"))
                    );
                    assert_eq!(
                        resp_304.headers().get(CACHE_CONTROL),
                        Some(&HeaderValue::from_static("private, no-transform"))
                    );
                    assert!(resp_304.headers().contains_key(ALT_SVC));
                    assert_eq!(
                        cap_304_init,
                        resp_304.headers().capacity(),
                        "HeaderMap regrew ({cap_304_init} -> {}) on agent-selected Markdown 304 (policy={policy_name})",
                        resp_304.headers().capacity()
                    );
                }
            }

            // 3. Header-dependent rewrite (`uses_request_headers()`) with `Accept: text/markdown`
            //    setting `ProtectedResponse` -> `make_private` -> `Cache-Control` on BOTH a plain
            //    non-HTML fallback 304 and an authored Markdown sibling 304, pinned to the exact
            //    12 -> 13 slot boundary so removing `uses_request_headers()` from
            //    `site_may_add_cache_control` fails BOTH cases (`cap_init` drops from 24 to 12,
            //    consuming the `+1` restore headroom instead of sizing for `Cache-Control`).
            {
                // 3a. Plain fallback 304:
                //   Unix:     own(3) + Strict(8) + rules(0) + may_add_cc(1) + restore(1) = 13 -> 24
                //             (without `uses_request_headers()`: 12 -> 12).
                //   Non-Unix: own(2) + Strict(8) + rules(1) + may_add_cc(1) + restore(1) = 13 -> 24
                //             (without `uses_request_headers()`: 12 -> 12).
                #[cfg(unix)]
                let plain_pad_rule = "";
                #[cfg(not(unix))]
                let plain_pad_rule = "set \"x-non-unix-pad\" \"1\"";

                // 3b. Authored Markdown sibling 304:
                //   Unix:     own(3) + md_extra(1) + Standard(6) + rules(1) + may_add_cc(1) + restore(1) = 13 -> 24
                //             (without `uses_request_headers()`: 12 -> 12).
                //   Non-Unix: own(2) + md_extra(1) + Standard(6) + rules(2) + may_add_cc(1) + restore(1) = 13 -> 24
                //             (without `uses_request_headers()`: 12 -> 12).
                #[cfg(unix)]
                let authored_pad_rules = "set \"x-one\" \"1\"";
                #[cfg(not(unix))]
                let authored_pad_rules = "set \"x-one\" \"1\"\n        set \"x-two\" \"2\"";

                for (host, policy_name, pad_rules, uri_path) in [
                    ("rw-md-plain.test", "strict", plain_pad_rule, "/plain.txt"),
                    (
                        "rw-md-authored.test",
                        "standard",
                        authored_pad_rules,
                        "/page.html",
                    ),
                ] {
                    let kdl = format!(
                        r#"
server {{
    listen "127.0.0.1:8443" protocols="h1,h2,h3"
}}
site "{host}" {{
    root {root_kdl}
    security-headers "{policy_name}"
    rewrite {{
        rule "\\.md$" deny=403 header="X-Preview=^blocked$"
    }}
    headers {{
        {pad_rules}
        remove "x-absent-field"
    }}
}}
"#
                    );
                    let (cfg, _) = parse_kdl("md-cap-3.kdl", &kdl)?;
                    let engine = crate::HttpEngine::from_config(
                        &cfg,
                        Arc::new(AcmeChallengeStore::new()),
                        Some(8443),
                        8443,
                    )?;

                    let probe_req = Request::builder()
                        .method(Method::GET)
                        .uri(uri_path)
                        .header(HOST, host)
                        .header(ACCEPT, "text/markdown")
                        .body(crate::empty_http_body())?;
                    super::LAST_STATIC_RESPONSE_INITIAL_CAP.with(|c| c.set(None));
                    let probe = engine.handle_request(probe_req, &https_ctx).await;
                    let probe_init = take_initial_cap()?;
                    assert_eq!(probe.status(), StatusCode::OK);
                    assert_eq!(probe_init, probe.headers().capacity());
                    let (cond_name, cond_val) = cond_304_header(&probe)?;

                    let req_304 = Request::builder()
                        .method(Method::GET)
                        .uri(uri_path)
                        .header(HOST, host)
                        .header(ACCEPT, "text/markdown")
                        .header(cond_name, cond_val)
                        .body(crate::empty_http_body())?;
                    super::LAST_STATIC_RESPONSE_INITIAL_CAP.with(|c| c.set(None));
                    let resp = engine.handle_request(req_304, &https_ctx).await;
                    let cap_init = take_initial_cap()?;
                    assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
                    assert!(
                        resp.headers().contains_key(CACHE_CONTROL),
                        "expected make_private Cache-Control on header-rewrite Markdown {uri_path}"
                    );
                    assert_eq!(
                        resp.headers().keys_len(),
                        12,
                        "expected exact 12 keys (including Cache-Control) on boundary 304 for {host}{uri_path}"
                    );
                    assert_eq!(
                        cap_init, 24,
                        "expected `uses_request_headers()` to bump 12->13 slots into the 24-key bucket on {host}{uri_path} (got {cap_init})"
                    );
                    assert_eq!(
                        cap_init,
                        resp.headers().capacity(),
                        "HeaderMap regrew ({cap_init} -> {}) on header-rewrite Markdown 304 for {host}{uri_path}",
                        resp.headers().capacity()
                    );
                }
            }

            // 4. Ordinary non-Markdown 304 on default Strict HTTPS site stays in the 12-key bucket
            //    (zero extra bytes vs baseline) and does not regrow.
            {
                let kdl = format!(
                    r#"
server {{
    listen "127.0.0.1:8443" protocols="h1,h2,h3"
}}
site "plain304.test" {{
    root {root_kdl}
    security-headers "strict"
}}
"#
                );
                let (cfg, _) = parse_kdl("md-cap-4.kdl", &kdl)?;
                let engine = crate::HttpEngine::from_config(
                    &cfg,
                    Arc::new(AcmeChallengeStore::new()),
                    Some(8443),
                    8443,
                )?;
                let probe_req = Request::builder()
                    .method(Method::GET)
                    .uri("/plain.txt")
                    .header(HOST, "plain304.test")
                    .body(crate::empty_http_body())?;
                super::LAST_STATIC_RESPONSE_INITIAL_CAP.with(|c| c.set(None));
                let probe = engine.handle_request(probe_req, &https_ctx).await;
                let _ = take_initial_cap()?;
                let (cond_name, cond_val) = cond_304_header(&probe)?;

                let req_304 = Request::builder()
                    .method(Method::GET)
                    .uri("/plain.txt")
                    .header(HOST, "plain304.test")
                    .header(cond_name, cond_val)
                    .body(crate::empty_http_body())?;
                super::LAST_STATIC_RESPONSE_INITIAL_CAP.with(|c| c.set(None));
                let resp = engine.handle_request(req_304, &https_ctx).await;
                let cap_init = take_initial_cap()?;
                assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
                assert_eq!(cap_init, 12, "ordinary Strict 304 should keep 12-key bucket");
                assert_eq!(cap_init, resp.headers().capacity());
            }

            let _ = std::fs::remove_dir_all(&dir);
            Ok::<_, Box<dyn std::error::Error>>(())
        })
    }
}

//! Immutable versioned release store with atomic zero-downtime `ArcSwap` activation,
//! instant rollback, strict canonical release-ID validation, RAII staging cleanup, and
//! bounded retention garbage collection.

use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use miraserve_config::{AiPublishConfig, StaticConfig};
use miraserve_static::StaticServer;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::PublishError;
use crate::crypto::{Ed25519SigningKey, Ed25519VerifyingKey, SignedBundle};
use crate::preflight::run_preflight_checks;

fn load_jwt_verifying_key(spec: &str) -> Result<Ed25519VerifyingKey, PublishError> {
    if let Some(path) = spec.strip_prefix("ed25519:") {
        Ed25519VerifyingKey::from_file(path)
    } else {
        Ed25519VerifyingKey::from_encoded(spec)
    }
}

/// Validates that `id` strictly matches MiraServe's canonical immutable release identifier
/// grammar: `rel-<digits>-<4+digits>-<8+lowercase-hex>`.
#[must_use]
pub fn is_canonical_release_id(id: &str) -> bool {
    if id.len() > 80 {
        return false;
    }
    let Some(rest) = id.strip_prefix("rel-") else {
        return false;
    };
    let mut parts = rest.split('-');
    let Some(ts) = parts.next() else {
        return false;
    };
    let Some(seq) = parts.next() else {
        return false;
    };
    let Some(hash) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    !ts.is_empty()
        && ts.bytes().all(|b| b.is_ascii_digit())
        && seq.len() >= 4
        && seq.bytes().all(|b| b.is_ascii_digit())
        && hash.len() >= 8
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}

/// RAII cleanup guard ensuring failed staging directories (`.staging-*`) are always deleted
/// so repeated rejected publishes cannot leak disk space or bypass `keep_versions`.
struct StagingDirGuard {
    path: PathBuf,
    armed: bool,
}

impl StagingDirGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StagingDirGuard {
    fn drop(&mut self) {
        if self.armed && self.path.exists() {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

/// Maximum allowed future clock skew on signed bundle `created_at_unix` (5 minutes).
const MAX_BUNDLE_FUTURE_SKEW_SECS: u64 = 300;
/// Maximum blocking wait attempts (200 * 25ms = 5s) when another writer holds the OS lock.
const WRITER_LOCK_MAX_ATTEMPTS: u32 = 200;

/// OS kernel-backed cross-process exclusive lock coordinating CLI (`miraserve publish`) and live
/// server mutations (`PUB-10`).
///
/// Backed by [`std::fs::File::try_lock`] (`flock` on Unix, `LockFileEx` on Windows), which stays
/// held for the entire lifetime of the writer regardless of wall-clock duration (never expires by
/// file age) and is released automatically by the OS kernel if the writer process exits or crashes.
/// The underlying `.miraserve-store.lock` file is intentionally kept on disk (never unlinked on
/// drop) so concurrent processes always synchronize on the same inode.
struct StoreFileLock {
    file: fs::File,
}

impl StoreFileLock {
    /// Non-blocking single attempt to acquire the OS-backed cross-process exclusive store lock.
    /// Returns `Ok(None)` immediately if another live writer currently holds the kernel lock.
    fn try_acquire(storage_dir: &Path) -> Result<Option<Self>, PublishError> {
        let lock_path = storage_dir.join(".miraserve-store.lock");
        if let Ok(meta) = fs::symlink_metadata(&lock_path)
            && meta.file_type().is_symlink()
        {
            return Err(PublishError::Io {
                path: lock_path,
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "refusing to lock symlinked .miraserve-store.lock",
                ),
            });
        }
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let file = opts.open(&lock_path).map_err(|source| PublishError::Io {
            path: lock_path.clone(),
            source,
        })?;

        match file.try_lock() {
            Ok(()) => Ok(Some(Self { file })),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(source)) => Err(PublishError::Io {
                path: lock_path,
                source,
            }),
        }
    }

    fn acquire(storage_dir: &Path) -> Result<Self, PublishError> {
        let lock_path = storage_dir.join(".miraserve-store.lock");
        for attempt in 0..WRITER_LOCK_MAX_ATTEMPTS {
            if let Some(lock) = Self::try_acquire(storage_dir)? {
                return Ok(lock);
            }
            if attempt + 1 == WRITER_LOCK_MAX_ATTEMPTS {
                return Err(PublishError::Io {
                    path: lock_path,
                    source: std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "timed out waiting for release store lock",
                    ),
                });
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        Err(PublishError::Io {
            path: lock_path,
            source: std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "timed out waiting for release store lock",
            ),
        })
    }
}

/// Removes orphaned `.staging-*` directories ONLY while the caller holds [`StoreFileLock`],
/// guaranteeing concurrent `publish` operations are never interrupted (`PUB-10`).
fn sweep_orphaned_staging_dirs(releases_dir: &Path) {
    if let Ok(entries) = fs::read_dir(releases_dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str()
                && name.starts_with(".staging-")
                && entry.file_type().is_ok_and(|ft| ft.is_dir())
            {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
    }
}

impl Drop for StoreFileLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn current_unix_millis() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    u64::try_from(millis).unwrap_or(u64::MAX)
}

fn file_stamp_opt(path: &Path) -> Option<(Option<SystemTime>, u64)> {
    fs::metadata(path)
        .ok()
        .map(|m| (m.modified().ok(), m.len()))
}

fn file_stamp(path: &Path) -> (Option<SystemTime>, u64) {
    file_stamp_opt(path).unwrap_or((None, 0))
}

/// Writes a regular file atomically with `sync_all()` durability (`PUB-14`).
fn write_synced_file(path: &Path, data: &[u8]) -> Result<(), PublishError> {
    let mut f = fs::File::create(path).map_err(|source| PublishError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    f.write_all(data).map_err(|source| PublishError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    f.sync_all().map_err(|source| PublishError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// Metadata persisted for each immutable release in `<storage>/releases/<id>/release.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseMetadata {
    /// Monotonic, filesystem-safe release identifier (e.g. `"rel-1763541000-0001-deadbeef"`).
    pub release_id: String,
    /// Deterministic SHA-256 hex digest of the signed bundle manifest.
    pub manifest_sha256: String,
    /// Number of files stored in this immutable release.
    pub file_count: usize,
    /// Total uncompressed bytes stored in this release.
    pub total_bytes: u64,
    /// Unix epoch timestamp (seconds) when activated.
    pub published_at_unix: u64,
    /// Signed bundle creation timestamp (enforces monotonic anti-downgrade protection, `PUB-8`).
    #[serde(default)]
    pub bundle_created_at_unix: u64,
    /// Optional deployment note supplied by the publishing agent/operator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Whether an Ed25519 signature was cryptographically verified at publish time.
    pub signature_verified: bool,
    /// Base64-encoded Ed25519 signature over the release's canonical manifest (`miraserve-bundle-v2`/`v3`),
    /// cryptographically re-verified against the active `require-signature` key on restore/rollback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_b64: Option<String>,
    /// Canonical target site identifier bound into the signed bundle manifest (`R3-PUB-5`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site_id: Option<String>,
    /// Preflight scanner policy version that strictly verified this release at activation (`R7-PUB-1`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preflight_scanner_version: Option<u32>,
    /// Sorted canonical `preflight-checks` names verified when this release was published (`R7-PUB-1`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preflight_checks_passed: Vec<String>,
}

impl ReleaseMetadata {
    /// Returns a copy with `signature_b64` omitted for MCP API listings and status responses
    /// so read-only callers cannot harvest raw bundle signatures (`R3-PUB-5`).
    #[must_use]
    pub fn redacted_for_listing(&self) -> Self {
        let mut out = self.clone();
        out.signature_b64 = None;
        out
    }
}

/// RAII guard that releases a [`ReleaseStore`] background disk-sync slot even if `sync_from_disk`
/// unwinds (`R3-PUB-7`).
#[derive(Debug)]
pub struct DiskSyncGuard {
    store: Arc<ReleaseStore>,
}

impl DiskSyncGuard {
    /// Executes [`ReleaseStore::sync_from_disk`] while holding the claimed sync slot.
    pub fn sync_now(&self) {
        self.store.sync_from_disk();
    }
}

impl Drop for DiskSyncGuard {
    fn drop(&mut self) {
        self.store.release_disk_sync_slot();
    }
}

/// Claims a rate-limited background disk-sync slot protected by an RAII [`DiskSyncGuard`] (`R3-PUB-7`).
#[must_use]
pub fn try_claim_disk_sync(store: &Arc<ReleaseStore>) -> Option<DiskSyncGuard> {
    if store.claim_disk_sync_slot() {
        Some(DiskSyncGuard {
            store: Arc::clone(store),
        })
    } else {
        None
    }
}

/// Monotonically incremented whenever preflight checks tighten across releases (`R7-PUB-1`).
const CURRENT_PREFLIGHT_SCANNER_VERSION: u32 = 2;

/// Exact release digest and policy recorded at strict activation (`publish`/`rollback`).
///
/// It is informational only. It used to authorise a lenient cold-startup path (`R6-PUB-5`,
/// `R7-PUB-1`); that path was removed (`R8-PUB-2`) because this record lives in the same
/// writable directory as the releases and is therefore no proof of anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VerifiedActiveRelease {
    release_id: String,
    manifest_sha256: String,
    scanner_version: u32,
    preflight_checks: Vec<String>,
}

fn canonical_preflight_check_names(checks: &[miraserve_config::PreflightCheck]) -> Vec<String> {
    let mut names: Vec<String> = checks
        .iter()
        .map(|c| match c {
            miraserve_config::PreflightCheck::NoSecrets => "no-secrets".to_owned(),
            miraserve_config::PreflightCheck::CspValid => "csp-valid".to_owned(),
            miraserve_config::PreflightCheck::NoInlineScripts => "no-inline-scripts".to_owned(),
            miraserve_config::PreflightCheck::MaxSize(sz) => {
                format!("max-size:{}", sz.as_bytes())
            }
            miraserve_config::PreflightCheck::MaxFiles(n) => format!("max-files:{n}"),
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

fn parse_preflight_check_names(names: &[String]) -> Option<Vec<miraserve_config::PreflightCheck>> {
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        match name.as_str() {
            "no-secrets" => out.push(miraserve_config::PreflightCheck::NoSecrets),
            "csp-valid" => out.push(miraserve_config::PreflightCheck::CspValid),
            "no-inline-scripts" => out.push(miraserve_config::PreflightCheck::NoInlineScripts),
            other => {
                if let Some(bytes_str) = other.strip_prefix("max-size:") {
                    let bytes: u64 = bytes_str.parse().ok()?;
                    out.push(miraserve_config::PreflightCheck::MaxSize(
                        miraserve_config::ByteSize::from_bytes(bytes),
                    ));
                } else {
                    let n_str = other.strip_prefix("max-files:")?;
                    let n: u32 = n_str.parse().ok()?;
                    out.push(miraserve_config::PreflightCheck::MaxFiles(n));
                }
            }
        }
    }
    Some(out)
}

/// Outcome of [`ReleaseStore::check_and_record_replay`] distinguishing genuine replays (HTTP 401)
/// from replay-cache faults/saturation (HTTP 503, `R7-PUB-4`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplayCheckOutcome {
    /// Fresh request fingerprint accepted and persisted.
    Accepted,
    /// Duplicate request fingerprint rejected as replay (HTTP 401).
    Replayed,
    /// Replay cache unavailable, corrupt, oversized, locked, or saturated (HTTP 503).
    CacheFault(&'static str),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct StoreState {
    active_release_id: Option<String>,
    /// Ordered history of active release IDs (most recent last) for non-oscillating rollback.
    history: Vec<String>,
    /// Highest signed bundle `created_at_unix` accepted by this store (`PUB-8`).
    #[serde(default)]
    max_created_at_unix: u64,
    /// Exact release & policy record written at strict activation (`R7-PUB-1`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verified_active: Option<VerifiedActiveRelease>,
}

#[derive(Debug, Clone)]
struct ActiveRelease {
    meta: ReleaseMetadata,
    static_server: StaticServer,
}

/// Minimum interval (milliseconds) between background `active.json` disk sync checks (`R2-PUB-1`).
const DISK_SYNC_MIN_INTERVAL_MS: u64 = 1_000;

/// Cached metadata stamps preventing redundant `active.json` parses or repeated re-verification
/// of an unverified/failed release on disk (`R2-PUB-1`).
#[derive(Debug, Default)]
struct DiskSyncCache {
    last_active_stamp: Option<(Option<SystemTime>, u64)>,
    failed_release: Option<(String, Option<SystemTime>, u64)>,
}

/// Maximum bounded replay-cache entries tracked per [`ReleaseStore`] (`R2-PUB-2`).
const MAX_REPLAY_CACHE_ENTRIES: usize = 8_192;
/// Maximum TTL (12 minutes) clamped on loaded & newly recorded replay entries so corrupt/forged
/// `exp = u64::MAX` values can never permanently lock out publishes (`R7-PUB-4`).
const MAX_REPLAY_CACHE_TTL_SECS: u64 = 720;
/// Maximum accepted size (2 MiB) of `<storage>/replay-cache.json` (`R7-PUB-4`).
const MAX_REPLAY_CACHE_BYTES: u64 = 2 * 1024 * 1024;

/// Persisted pre-upgrade legacy-v2 release ID allowlist (`R5-PUB-4`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct LegacyV2Allowlist {
    allowed_release_ids: Vec<String>,
}

/// Persisted anti-replay fingerprint cache (`R5-PUB-7`): maps lowercase hex SHA-256 fingerprint
/// to Unix expiration timestamp so replay protection survives hot SIGHUP reloads and restarts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistedReplayCache {
    entries: HashMap<String, u64>,
}

/// Options controlling [`ReleaseStore::resign_release_with_options`] and
/// [`ReleaseStore::resign_all_with_options`] (`R2-PUB-7`, `R5-PUB-1`, `R5-PUB-6`, `R6-PUB-4`).
#[derive(Debug, Clone, Copy, Default)]
pub struct ResignOptions<'a> {
    /// Allow re-signing truly UNSIGNED releases (`signature_b64.is_none()`). Already-signed
    /// releases STILL strictly require `old_verifying_key` verification (`R5-PUB-6`).
    pub include_unsigned: bool,
    /// Previous Ed25519 public verifying key used to cryptographically verify each existing
    /// release signature BEFORE re-signing under the new key during rotation or site-id rebinding.
    pub old_verifying_key: Option<&'a Ed25519VerifyingKey>,
    /// When `Some(old_site_id)`, rebinds ONLY stored releases whose existing `site_id` matches
    /// `old_site_id` (case-insensitively) to the store's current `expected_site_id` AFTER
    /// verifying the existing signature (`R6-PUB-4`). Releases bound to any other foreign
    /// `site_id` are refused so a planted release from another site can never be adopted.
    pub rebind_from_site_id: Option<&'a str>,
}

/// Thread-safe, atomic immutable release publisher for an `ai-publish` site.
#[derive(Debug)]
pub struct ReleaseStore {
    config: AiPublishConfig,
    storage_dir: PathBuf,
    verifying_key: Option<Ed25519VerifyingKey>,
    /// Optional dedicated Ed25519 verifying key for `auth="oauth-jwt"` MCP publish Bearer tokens
    /// (`ai-publish.jwt-public-key`, §4 Q4), separating token verification from bundle signing.
    jwt_verifying_key: Option<Ed25519VerifyingKey>,
    /// Optional canonical site identifier (`ai-publish.site-id` or first configured hostname,
    /// lowercased) enforced on signed bundle publishes and activations (`R3-PUB-5`, `R4-PUB-3`).
    expected_site_id: Option<String>,
    /// Bounded pre-upgrade legacy-v2 release ID allowlist (`R5-PUB-4`). Only release IDs already
    /// present when the site upgraded to v3 `site_id` enforcement may use the legacy v2 path.
    legacy_v2_allowlist: Mutex<HashSet<String>>,
    /// Lock-free active release reader used on every HTTP request hot path.
    active: ArcSwap<Option<ActiveRelease>>,
    /// Serializes write mutations (publish / rollback / GC / disk-sync swap) cleanly.
    write_lock: Mutex<u64>,
    /// Caches `active.json` metadata and failed release IDs off the HTTP hot path (`R2-PUB-1`).
    sync_cache: Mutex<DiskSyncCache>,
    /// Unix epoch milliseconds of the last background sync attempt.
    last_sync_ms: AtomicU64,
    /// Prevents concurrent background disk-sync tasks from piling up.
    sync_in_flight: AtomicBool,
    /// Bounded TTL replay cache keyed by `SHA-256(signature)` -> `expires_at_unix` (`R2-PUB-2`, `R5-PUB-7`).
    seen_replays: Mutex<HashMap<[u8; 32], u64>>,
}

impl ReleaseStore {
    /// Opens or initializes an immutable [`ReleaseStore`] from an [`AiPublishConfig`].
    ///
    /// Restores the previously active release if `active.json` exists and passes cryptographic
    /// verification under the active signing policy. Orphaned `.staging-*` directories are swept
    /// ONLY if no concurrent writer currently holds `.miraserve-store.lock`.
    ///
    /// # Errors
    /// Returns [`PublishError`] if directories cannot be created or the configured
    /// Ed25519 public verification key cannot be loaded.
    pub fn open(config: AiPublishConfig) -> Result<Self, PublishError> {
        Self::open_for_site(config, None)
    }

    /// Opens or initializes an immutable [`ReleaseStore`] bound to a canonical `expected_site_id`
    /// (enforced on signed manifests so bundles signed for another site are rejected, `R3-PUB-5`).
    ///
    /// # Errors
    /// Returns [`PublishError`] if directories cannot be created or key loading fails.
    pub fn open_for_site(
        config: AiPublishConfig,
        expected_site_id: Option<String>,
    ) -> Result<Self, PublishError> {
        let storage_dir = PathBuf::from(&config.storage);
        let releases_dir = storage_dir.join("releases");
        fs::create_dir_all(&releases_dir).map_err(|source| PublishError::Io {
            path: releases_dir.clone(),
            source,
        })?;

        // Sweep orphaned `.staging-*` ONLY when we acquire the cross-process lock non-blockingly,
        // never deleting staging directories of a concurrent live publisher!
        if let Ok(Some(_file_lock)) = StoreFileLock::try_acquire(&storage_dir) {
            sweep_orphaned_staging_dirs(&releases_dir);
        }

        Self::open_loaded(
            config,
            storage_dir,
            expected_site_id.map(|s| s.trim().to_ascii_lowercase()),
            true,
            true,
        )
    }

    /// Opens or initializes an immutable [`ReleaseStore`] during a live configuration reload
    /// (`SIGHUP` / `miraserve reload`), strictly enforcing current preflight rules with NO
    /// startup upgrade grace (`R7-PUB-1`).
    ///
    /// # Errors
    /// Returns [`PublishError`] if directories cannot be created or key loading fails.
    pub fn open_for_site_reload(
        config: AiPublishConfig,
        expected_site_id: Option<String>,
    ) -> Result<Self, PublishError> {
        let storage_dir = PathBuf::from(&config.storage);
        let releases_dir = storage_dir.join("releases");
        fs::create_dir_all(&releases_dir).map_err(|source| PublishError::Io {
            path: releases_dir.clone(),
            source,
        })?;

        if let Ok(Some(_file_lock)) = StoreFileLock::try_acquire(&storage_dir) {
            sweep_orphaned_staging_dirs(&releases_dir);
        }

        Self::open_loaded(
            config,
            storage_dir,
            expected_site_id.map(|s| s.trim().to_ascii_lowercase()),
            true,
            false,
        )
    }

    /// Opens an ALREADY-EXISTING [`ReleaseStore`] without creating missing directories,
    /// acquiring locks, or deleting staging directories (100% side-effect free on open).
    ///
    /// # Errors
    /// Returns [`PublishError`] if the storage directory does not exist or key loading fails.
    pub fn open_existing(config: AiPublishConfig) -> Result<Self, PublishError> {
        Self::open_existing_for_site(config, None)
    }

    /// Opens an ALREADY-EXISTING [`ReleaseStore`] bound to `expected_site_id` without side effects.
    ///
    /// # Errors
    /// Returns [`PublishError`] if the storage directory does not exist or key loading fails.
    pub fn open_existing_for_site(
        config: AiPublishConfig,
        expected_site_id: Option<String>,
    ) -> Result<Self, PublishError> {
        let storage_dir = PathBuf::from(&config.storage);
        if !storage_dir.is_dir() {
            return Err(PublishError::Io {
                path: storage_dir,
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "release storage directory does not exist",
                ),
            });
        }
        Self::open_loaded(
            config,
            storage_dir,
            expected_site_id.map(|s| s.trim().to_ascii_lowercase()),
            false,
            true,
        )
    }

    /// Opens an ALREADY-EXISTING [`ReleaseStore`] strictly read-only with zero filesystem
    /// side effects (safe to run concurrently with active `publish` operations).
    ///
    /// # Errors
    /// Returns [`PublishError`] if the storage directory does not exist or key loading fails.
    pub fn open_read_only(config: AiPublishConfig) -> Result<Self, PublishError> {
        Self::open_existing(config)
    }

    #[allow(clippy::too_many_lines)]
    fn open_loaded(
        config: AiPublishConfig,
        storage_dir: PathBuf,
        expected_site_id: Option<String>,
        allow_init_writes: bool,
        allow_startup_preflight_fallback: bool,
    ) -> Result<Self, PublishError> {
        let verifying_key = match &config.require_signature {
            Some(req) => Some(Ed25519VerifyingKey::from_file(&req.public_key_path)?),
            None => None,
        };
        let jwt_verifying_key = match &config.jwt_public_key {
            Some(spec) => Some(load_jwt_verifying_key(spec)?),
            None => None,
        };
        let effective_site_id = config
            .site_id
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .or(expected_site_id);

        // R5-PUB-4: Initialize or load the bounded pre-upgrade legacy-v2 release ID allowlist.
        let legacy_v2_set = if effective_site_id.is_some() && verifying_key.is_some() {
            load_or_init_legacy_v2_allowlist(&storage_dir, allow_init_writes)
        } else {
            HashSet::new()
        };

        // R5-PUB-7 & R6-PUB-8: Reload persisted anti-replay cache entries so replay defense
        // survives hot SIGHUP reloads and full server restarts; log loud errors if corrupt
        // (runtime `check_and_record_replay` fails closed until repaired).
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let initial_replays = match load_persisted_replay_cache(&storage_dir, now_unix) {
            // R8-PUB-3: only plausible expiries are preloaded. An implausibly distant one is left
            // for `check_and_record_replay`, which gives it a bounded expiry once and rewrites
            // the file; preloading it raw would make it look like a trusted in-memory entry.
            Ok(mut entries) => {
                let plausible = now_unix
                    .saturating_add(MAX_REPLAY_CACHE_TTL_SECS)
                    .saturating_add(MAX_REPLAY_CACHE_TTL_SECS);
                entries.retain(|_, exp| *exp <= plausible);
                entries
            }
            Err(err) => {
                error!(
                    storage = %storage_dir.display(),
                    error = %err,
                    "persisted replay-cache.json is corrupt or unreadable (R6-PUB-8); publish requests will fail closed until repaired"
                );
                HashMap::new()
            }
        };

        let store = Self {
            config,
            storage_dir,
            verifying_key,
            jwt_verifying_key,
            expected_site_id: effective_site_id,
            legacy_v2_allowlist: Mutex::new(legacy_v2_set),
            active: ArcSwap::from_pointee(None),
            write_lock: Mutex::new(0),
            sync_cache: Mutex::new(DiskSyncCache::default()),
            last_sync_ms: AtomicU64::new(0),
            sync_in_flight: AtomicBool::new(false),
            seen_replays: Mutex::new(initial_replays),
        };

        // Restore previously active release if present on disk and cryptographically valid.
        match store.read_state() {
            Ok(state) => {
                if let Some(active_id) = state.active_release_id.as_deref() {
                    // R8-PUB-2/6/7: startup uses the SAME strict rule as a reload. The former
                    // "previously verified" leniency read its proof (`verified_active`) from the
                    // store directory itself, so whoever could write a release there could also
                    // forge the proof; and a release admitted that way went dark on the next
                    // SIGHUP. A release that no longer passes the current checks is not served;
                    // the newest older release that passes is, and the operator is told below.
                    let _ = allow_startup_preflight_fallback;
                    match store.load_release_runtime(active_id, None) {
                        Ok(rel) => {
                            info!(release_id = %active_id, "restored active ai-publish release");
                            store.active.store(Arc::new(Some(rel)));
                        }
                        Err(err) => {
                            error!(
                                release_id = %active_id,
                                error = %err,
                                "active ai-publish release failed verification with the current checks and is NOT served; using the newest older release that passes, if any. Publish a corrected release to restore the site (R5-PUB-1, R8-PUB-2)"
                            );
                            let rel_stamp = file_stamp(
                                &store
                                    .storage_dir
                                    .join("releases")
                                    .join(active_id)
                                    .join("release.json"),
                            );
                            if let Ok(mut cache) = store.sync_cache.lock() {
                                cache.failed_release =
                                    Some((active_id.to_owned(), rel_stamp.0, rel_stamp.1));
                            }
                            let mut tried = HashSet::new();
                            tried.insert(active_id.to_owned());
                            for candidate in state.history.iter().rev() {
                                if !tried.insert(candidate.clone()) {
                                    continue;
                                }
                                if let Ok(fallback) = store.load_release_runtime(candidate, None) {
                                    warn!(
                                        failed_active = %active_id,
                                        fallback_release_id = %candidate,
                                        "serving newest valid fallback ai-publish release at startup after active release failed verification (R5-PUB-1)"
                                    );
                                    store.active.store(Arc::new(Some(fallback)));
                                    break;
                                }
                            }
                        }
                    }
                }
                if let Ok(mut cache) = store.sync_cache.lock() {
                    cache.last_active_stamp = file_stamp_opt(&store.state_path());
                }
            }
            Err(err) => {
                warn!(
                    path = %store.state_path().display(),
                    error = %err,
                    "failed to parse active.json while opening release store (PUB-14); leaving active release unset"
                );
            }
        }

        Ok(store)
    }

    /// Returns the configured [`AiPublishConfig`].
    #[must_use]
    pub fn config(&self) -> &AiPublishConfig {
        &self.config
    }

    /// Returns the configured Ed25519 verifying key, if `require-signature` is enabled.
    #[must_use]
    pub const fn verifying_key(&self) -> Option<&Ed25519VerifyingKey> {
        self.verifying_key.as_ref()
    }

    /// Returns the Ed25519 verifying key used for `auth="oauth-jwt"` publish tokens: prefers the
    /// dedicated `jwt-public-key` (§4 Q4) when configured, falling back to `require-signature`.
    #[must_use]
    pub fn jwt_verifying_key(&self) -> Option<&Ed25519VerifyingKey> {
        self.jwt_verifying_key
            .as_ref()
            .or(self.verifying_key.as_ref())
    }

    /// Returns the canonical site identifier bound to this store, if configured (`R3-PUB-5`).
    #[must_use]
    pub fn expected_site_id(&self) -> Option<&str> {
        self.expected_site_id.as_deref()
    }

    /// Returns the highest signed bundle `created_at_unix` accepted by this store (`0` if empty).
    #[must_use]
    pub fn latest_created_at_unix(&self) -> u64 {
        self.read_state().map_or(0, |s| s.max_created_at_unix)
    }

    /// Checks whether `fingerprint` (e.g. SHA-256 of a verified Ed25519 signature) has already
    /// been seen within its validity window, recording it atomically both in memory AND on disk
    /// (`<storage>/replay-cache.json`) so replay protection survives hot SIGHUP reloads and full
    /// restarts (`R2-PUB-2`, `R5-PUB-7`, `R6-PUB-8`, `R7-PUB-4`).
    ///
    /// Returns [`ReplayCheckOutcome::Replayed`] (HTTP 401) only for genuine duplicate signatures
    /// and [`ReplayCheckOutcome::CacheFault`] (HTTP 503) on lock timeout, corrupt/oversized
    /// `replay-cache.json`, write/fsync failure, or active cache saturation.
    pub(crate) fn check_and_record_replay(
        &self,
        fingerprint: [u8; 32],
        now_unix: u64,
        ttl_secs: u64,
    ) -> ReplayCheckOutcome {
        let mut guard = match self.seen_replays.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let _file_lock = match StoreFileLock::acquire(&self.storage_dir) {
            Ok(lock) => lock,
            Err(err) => {
                error!(
                    storage = %self.storage_dir.display(),
                    error = %err,
                    "failed to acquire store lock for replay cache (R6-PUB-8/R7-PUB-4); failing closed with 503"
                );
                return ReplayCheckOutcome::CacheFault("replay cache lock timed out");
            }
        };
        let persisted = match load_persisted_replay_cache(&self.storage_dir, now_unix) {
            Ok(map) => map,
            Err(err) => {
                error!(
                    storage = %self.storage_dir.display(),
                    error = %err,
                    "replay-cache.json is corrupt, oversized, or unreadable (R6-PUB-8/R7-PUB-4); failing closed with 503"
                );
                return ReplayCheckOutcome::CacheFault(
                    "replay-cache.json is corrupt or unreadable",
                );
            }
        };
        // Merge any unexpired entries recorded by a sibling/previous store instance across reload
        // (`R7-PUB-4`, `R8-PUB-3`, `R8-PUB-4`).
        //
        // This code never writes an expiry later than `now + MAX_REPLAY_CACHE_TTL_SECS`, so a
        // persisted expiry far beyond that is corrupt or planted. Such an entry is given a fixed
        // expiry ONCE, the first time it is seen, and the cleaned file is written back. Clamping
        // it again relative to the current time on every call (as before) made it a moving
        // target that never expired: 8,192 planted entries locked publishing out for good.
        //
        // The "plausible" bound is twice the TTL so that a backwards clock step of up to one TTL
        // does not reclassify honest entries, and an entry already held in memory is never
        // shortened, so a clock step cannot re-open the replay window for a recent request.
        let max_expiry = now_unix.saturating_add(MAX_REPLAY_CACHE_TTL_SECS);
        let plausible_expiry = max_expiry.saturating_add(MAX_REPLAY_CACHE_TTL_SECS);
        let mut rewrite_cleaned_file = false;
        for (fp, exp) in persisted {
            if exp <= plausible_expiry {
                guard
                    .entry(fp)
                    .and_modify(|e| *e = (*e).max(exp))
                    .or_insert(exp);
            } else {
                // An expiry already held in memory was either recorded by this process or fixed
                // on an earlier call, so it is kept as is. Only an entry seen for the first time
                // gets the bounded expiry.
                guard.entry(fp).or_insert(max_expiry);
                rewrite_cleaned_file = true;
            }
        }
        guard.retain(|_, &mut expires_at| expires_at > now_unix);
        if rewrite_cleaned_file {
            warn!(
                storage = %self.storage_dir.display(),
                "replay-cache.json held entries with an implausibly distant expiry (R8-PUB-3); they now expire within the replay window"
            );
            if let Err(err) = persist_replay_cache(&self.storage_dir, &guard) {
                error!(
                    storage = %self.storage_dir.display(),
                    error = %err,
                    "failed to persist cleaned replay-cache.json (R8-PUB-3); failing closed with 503"
                );
                return ReplayCheckOutcome::CacheFault("failed to persist replay-cache.json");
            }
        }
        if guard
            .get(&fingerprint)
            .is_some_and(|&expires_at| expires_at > now_unix)
        {
            return ReplayCheckOutcome::Replayed;
        }
        if guard.len() >= MAX_REPLAY_CACHE_ENTRIES {
            // R7-PUB-4: Log loudly on saturation and return HTTP 503 (distinct from 401 replay).
            warn!(
                storage = %self.storage_dir.display(),
                active_entries = guard.len(),
                max_entries = MAX_REPLAY_CACHE_ENTRIES,
                "ai-publish replay cache saturated with unexpired entries (R7-PUB-4); failing closed with 503 until entries expire"
            );
            return ReplayCheckOutcome::CacheFault(
                "replay cache saturated; retry after replay window expires",
            );
        }
        let clamped_ttl = ttl_secs.min(MAX_REPLAY_CACHE_TTL_SECS);
        let expiry = now_unix.saturating_add(clamped_ttl);
        guard.insert(fingerprint, expiry);
        if let Err(err) = persist_replay_cache(&self.storage_dir, &guard) {
            guard.remove(&fingerprint);
            error!(
                storage = %self.storage_dir.display(),
                error = %err,
                "failed to persist replay-cache.json (R6-PUB-8/R7-PUB-4); failing closed with 503"
            );
            return ReplayCheckOutcome::CacheFault("failed to persist replay-cache.json");
        }
        ReplayCheckOutcome::Accepted
    }

    /// Claims a rate-limited background disk-sync slot (at most once per second and at most
    /// one concurrent sync task) so callers can run [`Self::sync_from_disk`] inside
    /// `spawn_blocking` off the HTTP request hot path (`R2-PUB-1`).
    #[must_use]
    pub fn claim_disk_sync_slot(&self) -> bool {
        let now_ms = current_unix_millis();
        let prev = self.last_sync_ms.load(Ordering::Acquire);
        if now_ms.saturating_sub(prev) < DISK_SYNC_MIN_INTERVAL_MS {
            return false;
        }
        if self
            .sync_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        self.last_sync_ms.store(now_ms, Ordering::Release);
        true
    }

    /// Releases a previously claimed background disk-sync slot.
    pub fn release_disk_sync_slot(&self) {
        self.sync_in_flight.store(false, Ordering::Release);
    }

    /// Reconciles the in-memory `ArcSwap` active pointer if an external process (e.g. CLI
    /// `miraserve publish deploy` / `rollback`) atomically updated `active.json` on disk (`PUB-10`).
    ///
    /// Intended to be invoked off the async HTTP hot path (e.g. from `spawn_blocking` after
    /// [`Self::claim_disk_sync_slot`]). Skips JSON parsing when `active.json` metadata is
    /// unchanged and caches failed release verification results so an invalid release is never
    /// repeatedly hashed (`R2-PUB-1`).
    pub fn sync_from_disk(&self) {
        let active_stamp = file_stamp_opt(&self.state_path());
        {
            let cache = match self.sync_cache.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            if cache.last_active_stamp == active_stamp {
                return;
            }
        }

        // R3-PUB-7: Hold `write_lock` across state read + `active.store(...)` swap so a concurrent
        // in-process `publish()` / `rollback()` can never be overwritten by a stale disk sync!
        let _write_guard = match self.write_lock.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let active_stamp = file_stamp_opt(&self.state_path());
        {
            let cache = match self.sync_cache.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            if cache.last_active_stamp == active_stamp {
                return;
            }
        }

        let Ok(state) = self.read_state() else {
            return;
        };
        let disk_id = state.active_release_id.as_deref();
        let mem_guard = self.active.load();
        let mem_id = mem_guard
            .as_ref()
            .as_ref()
            .map(|r| r.meta.release_id.as_str());

        if disk_id == mem_id {
            let mut cache = match self.sync_cache.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            cache.last_active_stamp = active_stamp;
            return;
        }

        if let Some(id) = disk_id {
            let rel_meta_path = self
                .storage_dir
                .join("releases")
                .join(id)
                .join("release.json");
            let (rel_mtime, rel_len) = file_stamp(&rel_meta_path);
            {
                let mut cache = match self.sync_cache.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                if let Some((ref failed_id, failed_mtime, failed_len)) = cache.failed_release
                    && failed_id == id
                    && failed_mtime == rel_mtime
                    && failed_len == rel_len
                {
                    cache.last_active_stamp = active_stamp;
                    return;
                }
            }
            match self.load_release_runtime(id, None) {
                Ok(runtime) => {
                    info!(release_id = %id, "reloaded updated active ai-publish release from disk");
                    self.active.store(Arc::new(Some(runtime)));
                    let mut cache = match self.sync_cache.lock() {
                        Ok(g) => g,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    cache.last_active_stamp = active_stamp;
                    cache.failed_release = None;
                }
                Err(err) => {
                    warn!(
                        release_id = %id,
                        error = %err,
                        "refusing to activate release from disk; caching failure until release.json or active.json changes"
                    );
                    let mut cache = match self.sync_cache.lock() {
                        Ok(g) => g,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    cache.last_active_stamp = active_stamp;
                    cache.failed_release = Some((id.to_owned(), rel_mtime, rel_len));
                }
            }
        } else {
            self.active.store(Arc::new(None));
            let mut cache = match self.sync_cache.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            cache.last_active_stamp = active_stamp;
            cache.failed_release = None;
        }
    }

    /// Returns the lock-free `cap-std` [`StaticServer`] for the currently active release
    /// without performing any filesystem I/O on the HTTP hot path (`R2-PUB-1`).
    #[must_use]
    pub fn active_static_server(&self) -> Option<StaticServer> {
        self.active
            .load()
            .as_ref()
            .as_ref()
            .map(|r| r.static_server.clone())
    }

    /// Returns metadata for the currently active release, if any (lock-free, no disk I/O).
    #[must_use]
    pub fn active_release(&self) -> Option<ReleaseMetadata> {
        self.active.load().as_ref().as_ref().map(|r| r.meta.clone())
    }

    /// Lists all valid canonical immutable releases currently stored on disk, newest first.
    ///
    /// Ignores symlinks, non-canonical directory names, and `release.json` entries whose
    /// `release_id` disagrees with the actual directory name.
    #[must_use]
    pub fn list_releases(&self) -> Vec<ReleaseMetadata> {
        let releases_dir = self.storage_dir.join("releases");
        let Ok(entries) = fs::read_dir(&releases_dir) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if !ft.is_dir() || ft.is_symlink() {
                continue;
            }
            let Some(dir_name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if !is_canonical_release_id(&dir_name) {
                continue;
            }
            let meta_path = entry.path().join("release.json");
            if let Ok(raw) = fs::read_to_string(&meta_path)
                && let Ok(meta) = serde_json::from_str::<ReleaseMetadata>(&raw)
                && meta.release_id == dir_name
            {
                out.push(meta);
            }
        }
        out.sort_by(|a, b| b.release_id.cmp(&a.release_id));
        out
    }

    /// Verifies signature & pre-flight checks, writes an immutable release directory,
    /// atomically swaps the live `cap-std` server, and garbage-collects old versions.
    ///
    /// # Errors
    /// Returns [`PublishError`] if signature verification, pre-flight safety checks,
    /// or atomic persistence fail. On any error, staging directories are cleaned up via RAII
    /// and the live site remains untouched.
    pub fn publish(&self, signed: &SignedBundle) -> Result<ReleaseMetadata, PublishError> {
        self.publish_with_options(signed, false)
    }

    /// Publishes a release bundle with explicit recovery control (`allow_timestamp_reset` permits
    /// an operator CLI deploy to recover after a host clock ran ahead or a future-stamped bundle
    /// was deployed, `R4-PUB-5`). Network MCP endpoints always call [`Self::publish`] with
    /// `allow_timestamp_reset = false`.
    ///
    /// # Errors
    /// Returns [`PublishError`] on signature, preflight, timestamp, or persistence failure.
    #[allow(clippy::too_many_lines)]
    pub fn publish_with_options(
        &self,
        signed: &SignedBundle,
        allow_timestamp_reset: bool,
    ) -> Result<ReleaseMetadata, PublishError> {
        // 1. Cryptographic Ed25519 signature & site-ID binding verification (Threat Model T6, R3-PUB-5)
        let (manifest_sha256, signature_verified) = if let Some(vk) = &self.verifying_key {
            if let Some(expected_site) = &self.expected_site_id {
                let actual_site = signed.bundle.site_id.as_deref().map(str::trim);
                if !actual_site.is_some_and(|s| s.eq_ignore_ascii_case(expected_site)) {
                    return Err(PublishError::InvalidSignature(format!(
                        "bundle site_id '{}' does not match target site '{expected_site}' (R3-PUB-5)",
                        actual_site.unwrap_or("<missing>")
                    )));
                }
            }
            (signed.verify(vk)?, true)
        } else {
            (signed.bundle.manifest_sha256_hex(), false)
        };

        // 2. Mandatory path safety & configured pre-flight safety checks
        let violations = run_preflight_checks(&signed.bundle, &self.config.preflight_checks);
        if !violations.is_empty() {
            return Err(PublishError::PreflightFailed(violations));
        }

        // 3. Serialize in-process & cross-process write mutations cleanly (PUB-10)
        let mut seq_guard = match self.write_lock.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let _file_lock = StoreFileLock::acquire(&self.storage_dir)?;
        *seq_guard = seq_guard.saturating_add(1);
        let seq = *seq_guard;

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        // PUB-8 & R3-PUB-5: Enforce strictly increasing timestamps (rejecting equal-timestamp
        // replays that could otherwise prune all rollback targets!) & anti-future-skew checks.
        if signed.bundle.created_at_unix == 0 {
            return Err(PublishError::InvalidSignature(
                "bundle created_at_unix must be a positive Unix timestamp".to_owned(),
            ));
        }
        if signed.bundle.created_at_unix > now_unix.saturating_add(MAX_BUNDLE_FUTURE_SKEW_SECS) {
            return Err(PublishError::InvalidSignature(
                "bundle created_at_unix is too far in the future".to_owned(),
            ));
        }

        // PUB-14: Fail closed if active.json is corrupt instead of silently wiping history!
        let mut state = self.read_state()?;
        if !allow_timestamp_reset
            && state.max_created_at_unix > 0
            && signed.bundle.created_at_unix <= state.max_created_at_unix
        {
            return Err(PublishError::InvalidSignature(format!(
                "refusing downgrade/replay: bundle created_at_unix {} must be strictly greater than latest published {} (pass --allow-timestamp-reset on CLI to recover from clock skew)",
                signed.bundle.created_at_unix, state.max_created_at_unix
            )));
        }

        let short_hash = manifest_sha256.get(..8).unwrap_or("00000000");
        let release_id = format!("rel-{now_unix}-{seq:04}-{short_hash}");

        let releases_dir = self.storage_dir.join("releases");
        // Clean up any orphaned `.staging-*` dirs left by crashed writers while holding the exclusive lock.
        sweep_orphaned_staging_dirs(&releases_dir);
        let staging_dir = releases_dir.join(format!(".staging-{release_id}"));
        let final_dir = releases_dir.join(&release_id);
        let content_dir = staging_dir.join("public");

        // Ensure any failed staging attempt cleans up `.staging-*` automatically on error.
        let mut staging_guard = StagingDirGuard::new(staging_dir.clone());

        fs::create_dir_all(&content_dir).map_err(|source| PublishError::Io {
            path: content_dir.clone(),
            source,
        })?;

        let mut total_bytes: u64 = 0;
        for (rel_path, bytes) in &signed.bundle.files {
            total_bytes = total_bytes.saturating_add(bytes.len() as u64);
            let dest = content_dir.join(rel_path);
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent).map_err(|source| PublishError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
            write_synced_file(&dest, bytes)?;
        }

        let passed_checks = canonical_preflight_check_names(&self.config.preflight_checks);
        let meta = ReleaseMetadata {
            release_id: release_id.clone(),
            manifest_sha256: manifest_sha256.clone(),
            file_count: signed.bundle.files.len(),
            total_bytes,
            published_at_unix: now_unix,
            bundle_created_at_unix: signed.bundle.created_at_unix,
            note: signed.bundle.note.clone(),
            signature_verified,
            signature_b64: signed.signature_b64.clone(),
            site_id: signed
                .bundle
                .site_id
                .as_deref()
                .map(|s| s.trim().to_ascii_lowercase()),
            preflight_scanner_version: Some(CURRENT_PREFLIGHT_SCANNER_VERSION),
            preflight_checks_passed: passed_checks.clone(),
        };
        let meta_json = serde_json::to_string_pretty(&meta)
            .map_err(|err| PublishError::Serialization(err.to_string()))?;
        let meta_path = staging_dir.join("release.json");
        write_synced_file(&meta_path, meta_json.as_bytes())?;

        // Atomic directory promotion from staging -> immutable release dir
        fs::rename(&staging_dir, &final_dir).map_err(|source| PublishError::Io {
            path: final_dir.clone(),
            source,
        })?;
        staging_guard.disarm();

        // Open confined cap-std static server BEFORE swapping live traffic!
        let static_server = StaticServer::open(final_dir.join("public"), StaticConfig::default())
            .map_err(|err| PublishError::StaticOpen(err.to_string()))?;

        // Persist updated active pointer, verified activation record (`R7-PUB-1`), & bounded history atomically (`R2-PUB-8`)
        state.active_release_id = Some(release_id.clone());
        state.verified_active = Some(VerifiedActiveRelease {
            release_id: release_id.clone(),
            manifest_sha256,
            scanner_version: CURRENT_PREFLIGHT_SCANNER_VERSION,
            preflight_checks: passed_checks,
        });
        state.history.push(release_id.clone());
        let max_history = usize::try_from(self.config.keep_versions.max(1))
            .unwrap_or(10)
            .saturating_mul(4)
            .max(64);
        if state.history.len() > max_history {
            let excess = state.history.len().saturating_sub(max_history);
            state.history.drain(..excess);
        }
        if allow_timestamp_reset {
            let prev_max = state.max_created_at_unix;
            state.max_created_at_unix = signed.bundle.created_at_unix;
            // R5-PUB-11: Record an explicit durable audit trail entry whenever `--allow-timestamp-reset`
            // lowers the anti-replay timestamp watermark so operators can detect or audit skew resets.
            if prev_max > 0 && signed.bundle.created_at_unix <= prev_max {
                warn!(
                    release_id = %release_id,
                    previous_max_created_at_unix = prev_max,
                    new_max_created_at_unix = signed.bundle.created_at_unix,
                    site_id = self.expected_site_id.as_deref().unwrap_or(""),
                    "ai-publish timestamp watermark reset via --allow-timestamp-reset (R5-PUB-11)"
                );
                let _ = append_audit_log_entry(
                    &self.storage_dir,
                    &serde_json::json!({
                        "event": "timestamp_watermark_reset",
                        "at_unix": now_unix,
                        "release_id": release_id,
                        "site_id": self.expected_site_id,
                        "previous_max_created_at_unix": prev_max,
                        "new_max_created_at_unix": signed.bundle.created_at_unix,
                    }),
                );
            }
        } else {
            state.max_created_at_unix =
                state.max_created_at_unix.max(signed.bundle.created_at_unix);
        }
        self.write_state(&state)?;

        // Zero-downtime atomic ArcSwap!
        self.active.store(Arc::new(Some(ActiveRelease {
            meta: meta.clone(),
            static_server,
        })));

        // Retain at most `keep_versions` immutable releases on disk (never pruning active).
        self.prune_old_releases(&release_id);
        info!(
            release_id = %meta.release_id,
            files = meta.file_count,
            bytes = meta.total_bytes,
            signed = meta.signature_verified,
            "published atomic AI site release"
        );
        Ok(meta)
    }

    /// Instantly rolls back to `target_release_id` (or the immediately previous release when `None`).
    ///
    /// Enforces strict canonical release-ID validation, requires `signature_verified == true`
    /// whenever `require_signature` is configured, and walks backward through `history` without
    /// oscillating (`[A, B, C]` -> rollback to `B` -> rollback to `A`, `PUB-11`).
    ///
    /// # Errors
    /// Returns [`PublishError::ReleaseNotFound`] or [`PublishError::InvalidSignature`].
    pub fn rollback(
        &self,
        target_release_id: Option<&str>,
    ) -> Result<ReleaseMetadata, PublishError> {
        let _guard = match self.write_lock.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let _file_lock = StoreFileLock::acquire(&self.storage_dir)?;

        let mut state = self.read_state()?;
        let chosen_id = if let Some(explicit) = target_release_id {
            if !is_canonical_release_id(explicit) {
                return Err(PublishError::ReleaseNotFound(explicit.to_owned()));
            }
            explicit.to_owned()
        } else {
            let current = state.active_release_id.as_deref();
            // PUB-11: Find the latest prior release in history strictly before current,
            // and truncate rolled-back tip entries so a second rollback walks further back
            // rather than oscillating back to the broken release!
            let chosen_pos = state
                .history
                .iter()
                .enumerate()
                .rev()
                .find(|(_, id)| Some(id.as_str()) != current && self.release_exists(id))
                .map(|(idx, _)| idx)
                .ok_or_else(|| {
                    PublishError::ReleaseNotFound(
                        "no previous immutable release available for rollback".to_owned(),
                    )
                })?;
            let id = state
                .history
                .get(chosen_pos)
                .cloned()
                .ok_or_else(|| PublishError::ReleaseNotFound("empty history".to_owned()))?;
            state.history.truncate(chosen_pos.saturating_add(1));
            id
        };

        let runtime = self.load_release_runtime(&chosen_id, None)?;
        let meta = runtime.meta.clone();

        state.active_release_id = Some(chosen_id.clone());
        state.verified_active = Some(VerifiedActiveRelease {
            release_id: chosen_id.clone(),
            manifest_sha256: meta.manifest_sha256.clone(),
            scanner_version: CURRENT_PREFLIGHT_SCANNER_VERSION,
            preflight_checks: canonical_preflight_check_names(&self.config.preflight_checks),
        });
        if target_release_id.is_some() {
            // PUB-11: If rolling back explicitly to an existing release in history, truncate
            // back to that point instead of pushing `[A, B, A]` (prevents oscillation on next default rollback!).
            if let Some(pos) = state.history.iter().rposition(|id| id == &chosen_id) {
                state.history.truncate(pos.saturating_add(1));
            } else {
                state.history.push(chosen_id.clone());
            }
        }
        self.write_state(&state)?;

        self.active.store(Arc::new(Some(runtime)));
        info!(release_id = %chosen_id, "rolled back AI site release atomically");
        Ok(meta)
    }

    /// Re-signs a single retained immutable release (refusing unsigned releases by default;
    /// verifies on-disk `manifest_sha256` before signing) and atomically updates `release.json`.
    ///
    /// # Errors
    /// Returns [`PublishError`] if the release does not exist, was stored unsigned, fails
    /// `manifest_sha256` integrity verification, or fails key verification.
    pub fn resign_release(
        &self,
        release_id: &str,
        signing_key: &Ed25519SigningKey,
    ) -> Result<ReleaseMetadata, PublishError> {
        self.resign_release_with_options(release_id, signing_key, ResignOptions::default())
    }

    /// Re-signs a single retained immutable release with explicit [`ResignOptions`] (`R2-PUB-7`).
    ///
    /// # Errors
    /// Returns [`PublishError`] if integrity, unsigned-policy, old-key, or active-key verification fails.
    pub fn resign_release_with_options(
        &self,
        release_id: &str,
        signing_key: &Ed25519SigningKey,
        options: ResignOptions<'_>,
    ) -> Result<ReleaseMetadata, PublishError> {
        let _guard = match self.write_lock.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let _file_lock = StoreFileLock::acquire(&self.storage_dir)?;
        let meta = self.resign_release_locked(release_id, signing_key, options)?;

        // Refresh in-memory active release & verified_active record if we just re-signed the active release ID.
        if let Ok(mut state) = self.read_state()
            && state.active_release_id.as_deref() == Some(release_id)
            && let Ok(runtime) = self.load_release_runtime(release_id, None)
        {
            state.verified_active = Some(VerifiedActiveRelease {
                release_id: release_id.to_owned(),
                manifest_sha256: runtime.meta.manifest_sha256.clone(),
                scanner_version: CURRENT_PREFLIGHT_SCANNER_VERSION,
                preflight_checks: canonical_preflight_check_names(&self.config.preflight_checks),
            });
            let _ = self.write_state(&state);
            self.active.store(Arc::new(Some(runtime)));
        }
        Ok(meta)
    }

    /// Re-signs all retained immutable releases in this store using default [`ResignOptions`]
    /// (refusing unsigned releases unless [`Self::resign_all_with_options`] opts in).
    ///
    /// # Errors
    /// Returns [`PublishError`] if any retained release fails integrity or key verification,
    /// or if the store contains no retained releases.
    pub fn resign_all(
        &self,
        signing_key: &Ed25519SigningKey,
    ) -> Result<Vec<ReleaseMetadata>, PublishError> {
        self.resign_all_with_options(signing_key, ResignOptions::default())
    }

    /// Re-signs all retained immutable releases in this store with explicit [`ResignOptions`] (`R2-PUB-7`).
    ///
    /// # Errors
    /// Returns [`PublishError`] if any retained release fails integrity, unsigned-policy, or key verification.
    pub fn resign_all_with_options(
        &self,
        signing_key: &Ed25519SigningKey,
        options: ResignOptions<'_>,
    ) -> Result<Vec<ReleaseMetadata>, PublishError> {
        let _guard = match self.write_lock.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let _file_lock = StoreFileLock::acquire(&self.storage_dir)?;

        // R8-PUB-1: adopting unsigned releases is a per-release decision. A bulk re-sign must
        // never sweep up whatever unsigned directory happens to be in `releases/`.
        if options.include_unsigned {
            return Err(PublishError::InvalidSignature(
                "--include-unsigned requires an explicit --release-id <ID>; a bulk re-sign never adopts unsigned releases (R8-PUB-1)".to_owned(),
            ));
        }

        let releases = self.list_releases();
        if releases.is_empty() {
            return Err(PublishError::ReleaseNotFound(
                "no immutable releases found in store to re-sign".to_owned(),
            ));
        }

        let mut updated = Vec::with_capacity(releases.len());
        for rel in &releases {
            updated.push(self.resign_release_locked(&rel.release_id, signing_key, options)?);
        }

        if let Ok(mut state) = self.read_state()
            && let Some(active_id) = state.active_release_id.clone()
            && let Ok(runtime) = self.load_release_runtime(&active_id, None)
        {
            state.verified_active = Some(VerifiedActiveRelease {
                release_id: active_id,
                manifest_sha256: runtime.meta.manifest_sha256.clone(),
                scanner_version: CURRENT_PREFLIGHT_SCANNER_VERSION,
                preflight_checks: canonical_preflight_check_names(&self.config.preflight_checks),
            });
            let _ = self.write_state(&state);
            self.active.store(Arc::new(Some(runtime)));
        }
        Ok(updated)
    }

    #[allow(clippy::too_many_lines)]
    fn resign_release_locked(
        &self,
        release_id: &str,
        signing_key: &Ed25519SigningKey,
        options: ResignOptions<'_>,
    ) -> Result<ReleaseMetadata, PublishError> {
        if !is_canonical_release_id(release_id) {
            return Err(PublishError::ReleaseNotFound(release_id.to_owned()));
        }
        let dir = self.storage_dir.join("releases").join(release_id);
        let dir_meta = fs::symlink_metadata(&dir)
            .map_err(|_| PublishError::ReleaseNotFound(release_id.to_owned()))?;
        if !dir_meta.is_dir() || dir_meta.file_type().is_symlink() {
            return Err(PublishError::ReleaseNotFound(release_id.to_owned()));
        }
        let meta_path = dir.join("release.json");
        let raw = fs::read_to_string(&meta_path).map_err(|source| PublishError::Io {
            path: meta_path.clone(),
            source,
        })?;
        let mut meta: ReleaseMetadata = serde_json::from_str(&raw)
            .map_err(|err| PublishError::Serialization(err.to_string()))?;
        if meta.release_id != release_id {
            return Err(PublishError::ReleaseNotFound(release_id.to_owned()));
        }

        let public_dir = dir.join("public");
        let mut files = std::collections::BTreeMap::new();
        collect_dir_files_strict(&public_dir, &public_dir, &mut files)?;
        let rebuilt = crate::crypto::SiteBundle {
            files,
            note: meta.note.clone(),
            created_at_unix: meta.bundle_created_at_unix,
            site_id: meta.site_id.clone(),
        };
        let actual_sha = rebuilt.manifest_sha256_hex();
        if actual_sha != meta.manifest_sha256 {
            return Err(PublishError::InvalidSignature(format!(
                "refusing to re-sign release '{release_id}': on-disk files do not match recorded manifest_sha256 (pre-v2 legacy releases must be republished from source)"
            )));
        }

        // R2-PUB-7 & R5-PUB-6: Always cryptographically verify already-signed releases
        // (`meta.signature_b64.is_some()`) against `--old-pubkey` (or the current active
        // verifying key when rebinding without rotating keys) — EVEN WHEN `--include-unsigned`
        // is passed! `--include-unsigned` ONLY permits truly unsigned releases (`signature_b64.is_none()`).
        if let Some(existing_sig) = &meta.signature_b64 {
            let Some(verify_vk) = options.old_verifying_key.or(self.verifying_key.as_ref()) else {
                return Err(PublishError::InvalidSignature(format!(
                    "release '{release_id}' is already signed and requires --old-pubkey for cryptographic verification even with --include-unsigned (R5-PUB-6)"
                )));
            };
            let prev = SignedBundle {
                bundle: rebuilt.clone(),
                signature_b64: Some(existing_sig.clone()),
            };
            prev.verify(verify_vk).map_err(|err| {
                PublishError::InvalidSignature(format!(
                    "release '{release_id}' failed cryptographic verification against previous verifying key: {err}"
                ))
            })?;
        } else if !options.include_unsigned {
            // R8-PUB-1: `signature_verified` in `release.json` is unauthenticated metadata that
            // anyone able to write the storage directory can set. A release with no persisted
            // signature is unsigned no matter what that flag says, and is only ever re-signed
            // when the operator names it explicitly (`--release-id <ID> --include-unsigned`).
            return Err(PublishError::InvalidSignature(format!(
                "refusing to re-sign release '{release_id}': it has no persisted Ed25519 signature to verify (R8-PUB-1); inspect its content, then name it explicitly with `--release-id {release_id} --include-unsigned`, or re-publish the site from source"
            )));
        }

        // R5-PUB-12: Re-run current preflight checks before issuing a fresh signature so releases
        // accepted by an older scanner cannot be promoted under stricter policy.
        let violations = run_preflight_checks(&rebuilt, &self.config.preflight_checks);
        if !violations.is_empty() {
            return Err(PublishError::PreflightFailed(violations));
        }

        // R3-PUB-5, R5-PUB-1, R6-PUB-4, R7-PUB-2 & R7-PUB-3: Bind pre-upgrade legacy v2 releases
        // ONLY when permitted by `legacy-v2-allowlist.json` (blocking planted foreign v2 releases!),
        // OR rebind an existing v3 release to a new `expected_site_id` ONLY when
        // `options.rebind_from_site_id` explicitly matches the release's stored `site_id` (after
        // existing-signature verification succeeded above!). Never echo the foreign site_id or a
        // copy-paste command in refusal errors (`R7-PUB-3`).
        let mut to_sign = rebuilt;
        if let Some(expected_site) = &self.expected_site_id {
            match to_sign.site_id.as_deref() {
                None => {
                    // R8-PUB-1: the allowlist gate covers every unbound release. The only other
                    // way in is an unsigned release the operator named explicitly above.
                    let explicitly_adopted_unsigned =
                        meta.signature_b64.is_none() && options.include_unsigned;
                    if self.verifying_key.is_some()
                        && !explicitly_adopted_unsigned
                        && !self.is_legacy_v2_allowed(release_id)
                    {
                        return Err(PublishError::InvalidSignature(format!(
                            "release '{release_id}' has no bound site_id and is not in the pre-upgrade legacy-v2 allowlist (R7-PUB-2)"
                        )));
                    }
                    to_sign.site_id = Some(expected_site.clone());
                }
                Some(existing) if existing.eq_ignore_ascii_case(expected_site) => {
                    to_sign.site_id = Some(expected_site.clone());
                }
                Some(existing) => {
                    if let Some(from_site_id) = options
                        .rebind_from_site_id
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                    {
                        if existing.eq_ignore_ascii_case(from_site_id) {
                            info!(
                                release_id = %release_id,
                                old_site_id = %existing,
                                new_site_id = %expected_site,
                                "rebinding release site_id via --rebind-site-id --from-site-id after verifying previous signature (R6-PUB-4)"
                            );
                            to_sign.site_id = Some(expected_site.clone());
                        } else {
                            return Err(PublishError::InvalidSignature(format!(
                                "refusing to rebind release '{release_id}': stored site_id does not match --from-site-id '{from_site_id}' (R6-PUB-4, R7-PUB-3)"
                            )));
                        }
                    } else {
                        return Err(PublishError::InvalidSignature(format!(
                            "release '{release_id}' is bound to a different site_id than target site '{expected_site}' (R6-PUB-4, R7-PUB-3); see docs/DEPLOYMENT.md for the documented site-id migration procedure"
                        )));
                    }
                }
            }
        }

        let signed = SignedBundle::sign(to_sign, signing_key);
        if let Some(vk) = &self.verifying_key {
            signed.verify(vk)?;
        }

        meta.manifest_sha256 = signed.bundle.manifest_sha256_hex();
        meta.site_id = signed.bundle.site_id;
        meta.signature_verified = true;
        meta.signature_b64 = signed.signature_b64;
        meta.preflight_scanner_version = Some(CURRENT_PREFLIGHT_SCANNER_VERSION);
        meta.preflight_checks_passed =
            canonical_preflight_check_names(&self.config.preflight_checks);
        let tmp_meta = dir.join("release.json.tmp");
        let meta_json = serde_json::to_string_pretty(&meta)
            .map_err(|err| PublishError::Serialization(err.to_string()))?;
        write_synced_file(&tmp_meta, meta_json.as_bytes())?;
        fs::rename(&tmp_meta, &meta_path).map_err(|source| PublishError::Io {
            path: meta_path,
            source,
        })?;

        // R5-PUB-4: Once re-signed to a v3 site-bound manifest, permanently remove this release ID
        // from the pre-upgrade legacy-v2 allowlist!
        if meta.site_id.is_some() {
            self.remove_from_legacy_v2_allowlist(release_id);
        }

        info!(release_id = %release_id, "re-signed immutable AI site release manifest");
        Ok(meta)
    }

    fn release_exists(&self, id: &str) -> bool {
        is_canonical_release_id(id)
            && self
                .storage_dir
                .join("releases")
                .join(id)
                .join("release.json")
                .is_file()
    }

    fn is_legacy_v2_allowed(&self, release_id: &str) -> bool {
        let guard = match self.legacy_v2_allowlist.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.contains(release_id)
    }

    fn remove_from_legacy_v2_allowlist(&self, release_id: &str) {
        let mut guard = match self.legacy_v2_allowlist.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.remove(release_id) {
            let _ = persist_legacy_v2_allowlist(&self.storage_dir, &guard);
        }
    }

    #[allow(clippy::too_many_lines)]
    fn load_release_runtime(
        &self,
        release_id: &str,
        startup_preflight_grace: Option<&VerifiedActiveRelease>,
    ) -> Result<ActiveRelease, PublishError> {
        if !is_canonical_release_id(release_id) {
            return Err(PublishError::ReleaseNotFound(release_id.to_owned()));
        }
        let dir = self.storage_dir.join("releases").join(release_id);
        let dir_meta = fs::symlink_metadata(&dir)
            .map_err(|_| PublishError::ReleaseNotFound(release_id.to_owned()))?;
        if !dir_meta.is_dir() || dir_meta.file_type().is_symlink() {
            return Err(PublishError::ReleaseNotFound(release_id.to_owned()));
        }
        let meta_path = dir.join("release.json");
        if !meta_path.is_file() {
            return Err(PublishError::ReleaseNotFound(release_id.to_owned()));
        }
        let raw = fs::read_to_string(&meta_path).map_err(|source| PublishError::Io {
            path: meta_path,
            source,
        })?;
        let meta: ReleaseMetadata = serde_json::from_str(&raw)
            .map_err(|err| PublishError::Serialization(err.to_string()))?;
        if meta.release_id != release_id {
            return Err(PublishError::ReleaseNotFound(release_id.to_owned()));
        }

        // R6-PUB-5: Run cheap metadata checks (`signature_verified`, `signature_b64`, `site_id`,
        // legacy-v2 allowlist) BEFORE reading every file under `public/` from disk!
        let mut is_legacy_unbound_v2 = false;
        let required_sig_b64: Option<&str> = if self.verifying_key.is_some() {
            if !meta.signature_verified {
                return Err(PublishError::InvalidSignature(format!(
                    "refusing to activate unsigned release '{release_id}' while require-signature is enabled"
                )));
            }
            let Some(sig_b64) = meta.signature_b64.as_deref() else {
                return Err(PublishError::InvalidSignature(format!(
                    "release '{release_id}' has no persisted Ed25519 signature to verify against the active signing key (legacy pre-manifest release); after inspecting its content run `miraserve publish resign --storage {} --key <SECRET_KEY> --release-id {release_id} --include-unsigned`, or re-publish the site",
                    self.storage_dir.display()
                )));
            };
            if let Some(expected_site) = &self.expected_site_id {
                match meta.site_id.as_deref() {
                    Some(actual) if actual.eq_ignore_ascii_case(expected_site) => {}
                    Some(_) => {
                        return Err(PublishError::InvalidSignature(format!(
                            "release '{release_id}' is bound to a different site_id than target site '{expected_site}' (R3-PUB-5, R7-PUB-3); see docs/DEPLOYMENT.md if this site was intentionally renamed"
                        )));
                    }
                    None => {
                        // R4-PUB-2 & R5-PUB-4: Bounded upgrade compatibility! Only legacy v2
                        // releases ALREADY present in `<storage>/legacy-v2-allowlist.json` at the
                        // time of upgrade may activate without a bound `site_id`, blocking any
                        // newly planted foreign v2 release!
                        if !self.is_legacy_v2_allowed(release_id) {
                            return Err(PublishError::InvalidSignature(format!(
                                "release '{release_id}' has no bound site_id and is not in the pre-upgrade legacy-v2 allowlist (R5-PUB-4)"
                            )));
                        }
                        is_legacy_unbound_v2 = true;
                    }
                }
            }
            Some(sig_b64)
        } else {
            None
        };

        let public_dir = dir.join("public");
        let mut files = std::collections::BTreeMap::new();
        collect_dir_files_strict(&public_dir, &public_dir, &mut files)?;
        let rebuilt = crate::crypto::SiteBundle {
            files,
            note: meta.note.clone(),
            created_at_unix: meta.bundle_created_at_unix,
            site_id: meta.site_id.clone(),
        };

        if let (Some(vk), Some(sig_b64)) = (&self.verifying_key, required_sig_b64) {
            // Cryptographically re-verify the immutable release files on disk against the CURRENTLY
            // ACTIVE verifying key so key rotation immediately invalidates old-key releases and
            // on-disk file tampering is rejected!
            let signed_rebuilt = SignedBundle {
                bundle: rebuilt.clone(),
                signature_b64: Some(sig_b64.to_owned()),
            };
            let verified_sha = signed_rebuilt.verify(vk).map_err(|err| {
                PublishError::InvalidSignature(format!(
                    "release '{release_id}' failed cryptographic verification against active require-signature key: {err}"
                ))
            })?;
            if verified_sha != meta.manifest_sha256 {
                return Err(PublishError::InvalidSignature(format!(
                    "release '{release_id}' manifest digest mismatch on activation"
                )));
            }
            if is_legacy_unbound_v2 {
                warn!(
                    release_id = %release_id,
                    site = self.expected_site_id.as_deref().unwrap_or(""),
                    "activating pre-upgrade legacy v2 signed release without bound site_id (R4-PUB-2/R5-PUB-4); run `miraserve publish resign --config <CONFIG> --site <SITE> --old-pubkey <PUBKEY> --key <SECRET_KEY>` to migrate stored releases to v3 site-bound manifests"
                );
            }
        }

        // R5-PUB-12, R6-PUB-5 & R7-PUB-1: Re-run current preflight checks on activation, rollback,
        // disk sync, live reload (`SIGHUP`), and resign. Cold startup permits preflight upgrade
        // grace ONLY when `startup_preflight_grace` (`active.json`'s `verified_active`) matches
        // THIS exact `(release_id, manifest_sha256)`, agrees with `release.json`, and proves that
        // either the scanner version or configured `preflight-checks` tightened since strict
        // activation! A planted release or `SIGHUP` reload NEVER receives lenient fallback.
        let violations = run_preflight_checks(&rebuilt, &self.config.preflight_checks);
        if !violations.is_empty() {
            let grace_authorized = startup_preflight_grace.is_some_and(|v| {
                let current_checks = canonical_preflight_check_names(&self.config.preflight_checks);
                let mut meta_checks = meta.preflight_checks_passed.clone();
                meta_checks.sort();
                meta_checks.dedup();
                let mut recorded_checks = v.preflight_checks.clone();
                recorded_checks.sort();
                recorded_checks.dedup();

                v.release_id == release_id
                    && v.manifest_sha256 == meta.manifest_sha256
                    && meta.preflight_scanner_version == Some(v.scanner_version)
                    && meta_checks == recorded_checks
                    && v.scanner_version >= 1
                    && v.scanner_version <= CURRENT_PREFLIGHT_SCANNER_VERSION
                    && (v.scanner_version < CURRENT_PREFLIGHT_SCANNER_VERSION
                        || (recorded_checks.len() < current_checks.len()
                            && recorded_checks.iter().all(|c| current_checks.contains(c))
                            && parse_preflight_check_names(&recorded_checks).is_some_and(|prev| {
                                run_preflight_checks(&rebuilt, &prev).is_empty()
                            })))
            });
            if !grace_authorized {
                return Err(PublishError::PreflightFailed(violations));
            }
            let sample = violations.first().map_or("", |v| v.detail.as_str());
            warn!(
                release_id = %release_id,
                violation_count = violations.len(),
                first_violation = %sample,
                "active ai-publish release failed stricter post-upgrade preflight checks at startup (R6-PUB-5/R7-PUB-1); continuing to serve exact previously strictly-verified release — republish a compliant release"
            );
        }

        let static_server = StaticServer::open(public_dir, StaticConfig::default())
            .map_err(|err| PublishError::StaticOpen(err.to_string()))?;
        Ok(ActiveRelease {
            meta,
            static_server,
        })
    }

    fn state_path(&self) -> PathBuf {
        self.storage_dir.join("active.json")
    }

    fn read_state(&self) -> Result<StoreState, PublishError> {
        let path = self.state_path();
        if !path.exists() {
            return Ok(StoreState::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| PublishError::Io { path, source })?;
        serde_json::from_str(&raw).map_err(|err| PublishError::Serialization(err.to_string()))
    }

    fn write_state(&self, state: &StoreState) -> Result<(), PublishError> {
        let tmp = self.storage_dir.join("active.json.tmp");
        let final_path = self.state_path();
        let json = serde_json::to_string_pretty(state)
            .map_err(|err| PublishError::Serialization(err.to_string()))?;
        write_synced_file(&tmp, json.as_bytes())?;
        fs::rename(&tmp, &final_path).map_err(|source| PublishError::Io {
            path: final_path,
            source,
        })
    }

    fn prune_old_releases(&self, active_id: &str) {
        let keep = usize::try_from(self.config.keep_versions.max(1)).unwrap_or(10);
        let disk_active = self.read_state().ok().and_then(|s| s.active_release_id);
        let all = self.list_releases();
        if all.len() <= keep {
            return;
        }
        let releases_dir = self.storage_dir.join("releases");
        for stale in all.into_iter().skip(keep) {
            if stale.release_id == active_id
                || disk_active.as_deref() == Some(stale.release_id.as_str())
                || !is_canonical_release_id(&stale.release_id)
            {
                continue;
            }
            let dir = releases_dir.join(&stale.release_id);
            let Ok(md) = fs::symlink_metadata(&dir) else {
                continue;
            };
            if !md.is_dir() || md.file_type().is_symlink() {
                continue;
            }
            if let Err(err) = fs::remove_dir_all(&dir) {
                warn!(release_id = %stale.release_id, error = %err, "failed to prune old release");
            }
        }
    }
}

/// Reads all files recursively from a local directory into a [`crate::crypto::SiteBundle`].
///
/// # Errors
/// Returns [`PublishError::Io`] on filesystem errors.
pub fn bundle_from_directory(
    dir: impl AsRef<Path>,
    note: Option<String>,
) -> Result<crate::crypto::SiteBundle, PublishError> {
    let root = dir.as_ref();
    let mut files = std::collections::BTreeMap::new();
    collect_dir_files(root, root, &mut files)?;
    let created_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    Ok(crate::crypto::SiteBundle {
        files,
        note,
        created_at_unix,
        site_id: None,
    })
}

fn collect_dir_files_strict(
    root: &Path,
    current: &Path,
    out: &mut std::collections::BTreeMap<String, Vec<u8>>,
) -> Result<(), PublishError> {
    let entries = fs::read_dir(current).map_err(|source| PublishError::Io {
        path: current.to_path_buf(),
        source,
    })?;
    for entry_res in entries {
        let entry = entry_res.map_err(|source| PublishError::Io {
            path: current.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| PublishError::Io {
            path: path.clone(),
            source,
        })?;
        if file_type.is_symlink() {
            return Err(PublishError::InvalidSignature(format!(
                "unexpected symlink '{}' inside immutable release directory",
                path.display()
            )));
        }
        if file_type.is_dir() {
            collect_dir_files_strict(root, &path, out)?;
        } else if file_type.is_file() {
            let rel = path.strip_prefix(root).map_err(|_| {
                PublishError::Serialization("failed to compute relative path".to_owned())
            })?;
            let rel_posix = rel.to_string_lossy().replace('\\', "/");
            let bytes = fs::read(&path).map_err(|source| PublishError::Io { path, source })?;
            out.insert(rel_posix, bytes);
        } else {
            return Err(PublishError::InvalidSignature(format!(
                "unexpected non-regular entry '{}' inside immutable release directory",
                path.display()
            )));
        }
    }
    Ok(())
}

fn collect_dir_files(
    root: &Path,
    current: &Path,
    out: &mut std::collections::BTreeMap<String, Vec<u8>>,
) -> Result<(), PublishError> {
    let entries = fs::read_dir(current).map_err(|source| PublishError::Io {
        path: current.to_path_buf(),
        source,
    })?;
    for entry_res in entries {
        let entry = entry_res.map_err(|source| PublishError::Io {
            path: current.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| PublishError::Io {
            path: path.clone(),
            source,
        })?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_dir_files(root, &path, out)?;
        } else if file_type.is_file() {
            let rel = path.strip_prefix(root).map_err(|_| {
                PublishError::Serialization("failed to compute relative path".to_owned())
            })?;
            let rel_posix = rel.to_string_lossy().replace('\\', "/");
            let bytes = fs::read(&path).map_err(|source| PublishError::Io { path, source })?;
            out.insert(rel_posix, bytes);
        }
    }
    Ok(())
}

/// Loads the persisted pre-upgrade legacy-v2 allowlist (`<storage>/legacy-v2-allowlist.json`), or
/// snapshots currently present unsigned-site-id v2 release IDs ONCE on first boot (`R5-PUB-4`).
///
/// If the store already contains ANY v3 site-bound release (`meta.site_id.is_some()`), a missing
/// `legacy-v2-allowlist.json` is NEVER re-seeded from `releases/` (failing closed to an empty set)
/// so deleting the allowlist file on a v3 store cannot adopt a newly planted foreign v2 release!
fn load_or_init_legacy_v2_allowlist(storage_dir: &Path, allow_write: bool) -> HashSet<String> {
    let path = storage_dir.join("legacy-v2-allowlist.json");
    if let Ok(md) = fs::symlink_metadata(&path) {
        if md.file_type().is_symlink() || !md.is_file() {
            warn!(
                path = %path.display(),
                "legacy-v2-allowlist.json is not a regular file; treating allowlist as empty"
            );
            return HashSet::new();
        }
        return fs::read_to_string(&path)
            .ok()
            .and_then(|raw| serde_json::from_str::<LegacyV2Allowlist>(&raw).ok())
            .map(|list| list.allowed_release_ids.into_iter().collect())
            .unwrap_or_default();
    }

    // First upgrade boot: scan `releases/` and check whether any v3 release already exists.
    let mut existing_v2 = HashSet::new();
    let mut saw_any_v3 = false;
    let releases_dir = storage_dir.join("releases");
    if let Ok(entries) = fs::read_dir(&releases_dir) {
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if !ft.is_dir() || ft.is_symlink() {
                continue;
            }
            let Some(dir_name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if !is_canonical_release_id(&dir_name) {
                continue;
            }
            let meta_path = entry.path().join("release.json");
            if let Ok(raw) = fs::read_to_string(&meta_path)
                && let Ok(meta) = serde_json::from_str::<ReleaseMetadata>(&raw)
                && meta.release_id == dir_name
            {
                if meta.site_id.is_some() {
                    saw_any_v3 = true;
                } else if meta.signature_verified && meta.signature_b64.is_some() {
                    existing_v2.insert(dir_name);
                }
            }
        }
    }

    if saw_any_v3 {
        if !existing_v2.is_empty() {
            warn!(
                storage = %storage_dir.display(),
                planted_v2_count = existing_v2.len(),
                "legacy-v2-allowlist.json is missing on a store that already contains v3 site-bound releases (R5-PUB-4); refusing to auto-seed unbound v2 releases"
            );
        }
        existing_v2.clear();
    }

    if allow_write && storage_dir.is_dir() {
        let _ = persist_legacy_v2_allowlist(storage_dir, &existing_v2);
    }
    existing_v2
}

fn persist_legacy_v2_allowlist(
    storage_dir: &Path,
    allowed: &HashSet<String>,
) -> Result<(), PublishError> {
    let mut ids: Vec<String> = allowed.iter().cloned().collect();
    ids.sort();
    let payload = LegacyV2Allowlist {
        allowed_release_ids: ids,
    };
    let json = serde_json::to_string_pretty(&payload)
        .map_err(|err| PublishError::Serialization(err.to_string()))?;
    let tmp = storage_dir.join("legacy-v2-allowlist.json.tmp");
    let dst = storage_dir.join("legacy-v2-allowlist.json");
    write_synced_file(&tmp, json.as_bytes())?;
    fs::rename(&tmp, &dst).map_err(|source| PublishError::Io { path: dst, source })
}

fn encode_hex_32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn decode_hex_32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let pair = hex.get(i * 2..i * 2 + 2)?;
        *slot = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

/// Loads unexpired entries from `<storage>/replay-cache.json`, failing CLOSED (`Err`) on
/// symlinks, oversized (>2 MiB) files, unreadable files, corrupt JSON, or malformed hex entries
/// (`R6-PUB-8`, `R7-PUB-4`). Clamps any abnormally distant expiry timestamp to
/// `now_unix + MAX_REPLAY_CACHE_TTL_SECS` so forged or corrupt `exp = u64::MAX` values can never
/// permanently lock out publishes.
/// Returns `Ok(empty)` ONLY when `replay-cache.json` does not exist yet (`NotFound`).
fn load_persisted_replay_cache(
    storage_dir: &Path,
    now_unix: u64,
) -> Result<HashMap<[u8; 32], u64>, PublishError> {
    let path = storage_dir.join("replay-cache.json");
    let md = match fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(source) => return Err(PublishError::Io { path, source }),
    };
    if md.file_type().is_symlink() || !md.is_file() {
        return Err(PublishError::Io {
            path,
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "replay-cache.json must be a regular file, not a symlink",
            ),
        });
    }
    if md.len() > MAX_REPLAY_CACHE_BYTES {
        return Err(PublishError::Io {
            path,
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "replay-cache.json exceeds maximum allowed size ({MAX_REPLAY_CACHE_BYTES} bytes, R7-PUB-4)"
                ),
            ),
        });
    }
    let file = fs::File::open(&path).map_err(|source| PublishError::Io {
        path: path.clone(),
        source,
    })?;
    let mut raw_bytes = Vec::new();
    file.take(MAX_REPLAY_CACHE_BYTES.saturating_add(1))
        .read_to_end(&mut raw_bytes)
        .map_err(|source| PublishError::Io {
            path: path.clone(),
            source,
        })?;
    if (raw_bytes.len() as u64) > MAX_REPLAY_CACHE_BYTES {
        return Err(PublishError::Io {
            path,
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "replay-cache.json exceeded maximum allowed size while reading ({MAX_REPLAY_CACHE_BYTES} bytes, R7-PUB-4)"
                ),
            ),
        });
    }
    let raw = String::from_utf8(raw_bytes).map_err(|err| {
        PublishError::Serialization(format!("replay-cache.json is not valid UTF-8: {err}"))
    })?;
    let parsed: PersistedReplayCache = serde_json::from_str(&raw)
        .map_err(|err| PublishError::Serialization(format!("corrupt replay-cache.json: {err}")))?;
    // Expiries are returned exactly as stored. Deciding what to do with an implausibly distant
    // one belongs to `check_and_record_replay`, which fixes it once and writes the file back
    // (`R8-PUB-3`); clamping here relative to the current time on every read made such entries
    // immortal.
    let mut map = HashMap::new();
    for (hex_fp, exp) in parsed.entries {
        let Some(fp) = decode_hex_32(&hex_fp) else {
            return Err(PublishError::Serialization(
                "corrupt replay-cache.json: invalid 64-hex fingerprint key".to_owned(),
            ));
        };
        if exp > now_unix {
            map.insert(fp, exp);
        }
    }
    Ok(map)
}

fn persist_replay_cache(
    storage_dir: &Path,
    entries: &HashMap<[u8; 32], u64>,
) -> Result<(), PublishError> {
    if !storage_dir.is_dir() {
        return Err(PublishError::Io {
            path: storage_dir.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "release storage directory is unavailable for replay-cache persistence",
            ),
        });
    }
    let dst = storage_dir.join("replay-cache.json");
    if let Ok(md) = fs::symlink_metadata(&dst)
        && md.file_type().is_symlink()
    {
        return Err(PublishError::Io {
            path: dst,
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "refusing to overwrite symlinked replay-cache.json",
            ),
        });
    }
    let mut serialized_entries = HashMap::with_capacity(entries.len());
    for (fp, &exp) in entries {
        serialized_entries.insert(encode_hex_32(fp), exp);
    }
    let payload = PersistedReplayCache {
        entries: serialized_entries,
    };
    let json = serde_json::to_string(&payload)
        .map_err(|err| PublishError::Serialization(err.to_string()))?;
    let tmp = storage_dir.join(format!("replay-cache.json.tmp-{}", std::process::id()));
    write_synced_file(&tmp, json.as_bytes())?;
    fs::rename(&tmp, &dst).map_err(|source| PublishError::Io { path: dst, source })
}

fn append_audit_log_entry(
    storage_dir: &Path,
    entry: &serde_json::Value,
) -> Result<(), PublishError> {
    let path = storage_dir.join("audit.log");
    if let Ok(md) = fs::symlink_metadata(&path)
        && md.file_type().is_symlink()
    {
        return Err(PublishError::Io {
            path,
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "refusing to append to symlinked audit.log",
            ),
        });
    }
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut file = opts.open(&path).map_err(|source| PublishError::Io {
        path: path.clone(),
        source,
    })?;
    let mut line =
        serde_json::to_string(entry).map_err(|err| PublishError::Serialization(err.to_string()))?;
    line.push('\n');
    file.write_all(line.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|source| PublishError::Io { path, source })
}

#[cfg(test)]
mod replay_cache_tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn open_store(tag: &str) -> Result<(ReleaseStore, PathBuf), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!(
            "miraserve-r8-replay-{tag}-{}-{}",
            std::process::id(),
            current_unix_millis()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("releases"))?;
        let store = ReleaseStore::open(AiPublishConfig {
            storage: dir.to_string_lossy().into_owned(),
            site_id: None,
            keep_versions: 5,
            require_signature: None,
            jwt_public_key: None,
            jwt_issuer: None,
            allowed_subjects: Vec::new(),
            preflight_checks: Vec::new(),
            mcp_endpoint: None,
        })?;
        Ok((store, dir))
    }

    fn fp(n: u64) -> [u8; 32] {
        let mut out = [0_u8; 32];
        if let Some(tail) = out.get_mut(24..) {
            tail.copy_from_slice(&n.to_be_bytes());
        }
        out
    }

    /// R8-PUB-3: a replay cache planted full of `u64::MAX` expiries must stop blocking publishes
    /// once one replay window has passed. Before the fix every call re-clamped those entries
    /// relative to the current time, so they never expired.
    #[test]
    fn r8_pub_3_planted_far_future_entries_expire_after_one_replay_window() -> TestResult {
        let (store, dir) = open_store("pub3")?;
        let mut entries = serde_json::Map::new();
        for n in 0..MAX_REPLAY_CACHE_ENTRIES {
            entries.insert(
                format!("{:064x}", n.saturating_add(1)),
                serde_json::Value::from(u64::MAX),
            );
        }
        fs::write(
            dir.join("replay-cache.json"),
            serde_json::to_vec(&serde_json::json!({ "entries": entries }))?,
        )?;

        let t0 = 1_800_000_000_u64;
        let probe = fp(u64::MAX);
        assert!(
            matches!(
                store.check_and_record_replay(probe, t0, 600),
                ReplayCheckOutcome::CacheFault(_)
            ),
            "a saturated cache fails closed while the planted entries are inside the window"
        );
        let on_disk = fs::read_to_string(dir.join("replay-cache.json"))?;
        assert!(
            !on_disk.contains(&u64::MAX.to_string()),
            "R8-PUB-3: the cleaned cache must be written back with bounded expiries"
        );
        // Still saturated just inside the window, on the same fixed deadline.
        assert!(matches!(
            store.check_and_record_replay(probe, t0 + MAX_REPLAY_CACHE_TTL_SECS - 1, 600),
            ReplayCheckOutcome::CacheFault(_)
        ));
        assert!(
            matches!(
                store.check_and_record_replay(probe, t0 + MAX_REPLAY_CACHE_TTL_SECS + 1, 600),
                ReplayCheckOutcome::Accepted
            ),
            "R8-PUB-3: publishing must recover one replay window after the first sighting"
        );

        // A fresh process (no in-memory state) reading the cleaned file recovers as well.
        let reopened = ReleaseStore::open(store.config.clone())?;
        assert!(matches!(
            reopened.check_and_record_replay(
                fp(u64::MAX - 1),
                t0 + MAX_REPLAY_CACHE_TTL_SECS + 2,
                600
            ),
            ReplayCheckOutcome::Accepted
        ));
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    /// R8-PUB-4: a backwards clock step must not shorten the expiry of a request that was
    /// already recorded, or that request could be replayed while its timestamp is still valid.
    #[test]
    fn r8_pub_4_backwards_clock_step_does_not_reopen_the_replay_window() -> TestResult {
        let (store, dir) = open_store("pub4")?;
        let t0 = 1_800_000_000_u64;
        let request = fp(7);
        assert!(matches!(
            store.check_and_record_replay(request, t0, 600),
            ReplayCheckOutcome::Accepted
        ));
        // The clock steps back 1,000 s and an unrelated request arrives.
        assert!(matches!(
            store.check_and_record_replay(fp(8), t0 - 1_000, 600),
            ReplayCheckOutcome::Accepted
        ));
        // 250 s before the original time the original timestamp is acceptable again; the
        // recorded entry must still be there.
        assert!(
            matches!(
                store.check_and_record_replay(request, t0 - 250, 600),
                ReplayCheckOutcome::Replayed
            ),
            "R8-PUB-4: the recorded request must still be recognised as a replay"
        );
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }
}

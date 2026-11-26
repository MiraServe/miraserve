//! Opt-in, time-bounded, memory-bounded in-memory cache for qualifying static file responses.
//!
//! # Guarantees
//! - **Off by default:** sites without `file-cache` never attach a [`FileCache`], so
//!   their static path takes a single branch (`None`) and runs the unchanged uncached path.
//! - **Fixed deadline from lookup:** every entry records `expires_at = lookup_started + window`
//!   anchored before the first filesystem access made for the request; hits never extend the
//!   deadline. Freshness is decided using a clock sample taken while holding the shard lock.
//! - **Suspend-aware clock on Linux:** [`CacheClock::System`] reads `CLOCK_BOOTTIME` via `rustix`
//!   on Linux (counting suspended time without `unsafe`), and [`std::time::Instant`] on other
//!   platforms (where the elapsed-time bound assumes the system does not suspend).
//! - **Credential epoch safety:** every publication of credential identities increments the
//!   process-wide credential epoch. Entries record the epoch read before lookup started; a hit
//!   requires the current epoch to equal it (one atomic load), and stale admissions are dropped.
//! - **Bounded exact memory across reloads and slow readers:** admission reserves exact body,
//!   body-owner, key, entry, header-storage, and shard hash-table growth bytes from the
//!   process-wide [`FileCacheBudget`] *before* copying or allocating cache structures. Admitted
//!   payloads are copied into an exact-capacity buffer (`capacity == len`) wrapped with
//!   [`Bytes::from_owner`] so body bytes stay charged until the very last clone (including
//!   in-flight slow-reader frames) is dropped, even after eviction or reload.
//! - **Read-mostly sharded concurrency & bounded pressure work:** 64 cache-line-aligned shards
//!   (`std::sync::RwLock`) with DoS-resistant keyed hashing, zero-allocation lookups on hits,
//!   per-thread cache-line-separated counters summed on scrape, and bounded pressure sweeps
//!   examining at most one shard and a fixed number of entries. No lock is ever held across an
//!   `.await` or filesystem I/O.

use std::borrow::Borrow;
use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher as _, Hash, Hasher};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
#[cfg(not(target_os = "linux"))]
use std::time::Instant;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use http::HeaderValue;

use crate::compress::ContentEncoding;
use crate::{ScriptOwner, current_credential_epoch, is_quiescent_credential_epoch};

/// Number of lock shards in a [`FileCache`] generation (power of two; fits in a `u64` bitmask).
const NUM_SHARDS: usize = 64;

/// Number of cache-line-separated per-thread stripes backing [`FileCacheCounters`].
const COUNTER_STRIPES: usize = 64;

/// Maximum canonical path length (in bytes) eligible for file-cache lookup or admission.
pub const MAX_CACHE_KEY_BYTES: usize = 4_096;

/// Maximum live entries per shard (`64 * 256 = 16_384` entries per generation).
const MAX_ENTRIES_PER_SHARD: usize = 256;

/// Maximum live entries across all shards of a single [`FileCache`] generation.
pub const MAX_CACHE_ENTRIES: usize = NUM_SHARDS * MAX_ENTRIES_PER_SHARD;

/// Maximum entries examined on a requesting worker thread during a synchronous budget-pressure
/// or shard-cap cleanup step (at most one shard is visited; broader reclamation belongs to the
/// periodic sweeper).
pub(crate) const PRESSURE_SWEEP_MAX_ENTRIES: usize = 32;

/// Interval between periodic bounded background sweeps for idle sites.
const BACKGROUND_SWEEP_INTERVAL: Duration = Duration::from_millis(500);

/// Maximum shards inspected per background sweep tick.
const BACKGROUND_SWEEP_SHARDS_PER_TICK: usize = 16;

/// Soft entry-scan budget per background sweep tick: once at least this many entries have been
/// inspected across visited shards in one tick, the sweeper stops until the next tick (always
/// finishing the current shard, whose capacity is bounded by [`MAX_ENTRIES_PER_SHARD`] = 256,
/// so no shard tail is ever starved).
const BACKGROUND_SWEEP_MAX_ENTRIES_PER_TICK: usize = 256;

/// Overhead of `bytes::Bytes`'s heap-allocated `Shared` control block (`buf`, `cap`, `ref_cnt`)
/// when a [`HeaderValue`]'s backing buffer is promoted on clone.
const BYTES_SHARED_OVERHEAD: usize = 3 * std::mem::size_of::<usize>();

/// Monotonic server identifier allocator so every compiled [`crate::StaticServer`] (and every
/// mutated clone whose resolution policy changes) gets a unique key namespace.
static NEXT_SERVER_ID: AtomicU64 = AtomicU64::new(1);

/// Monotonic cache-generation identifier allocator so a [`FillStart`] sampled from one
/// [`FileCache`] (and its clock domain) can never be accepted by another [`FileCache`].
static NEXT_CACHE_ID: AtomicU64 = AtomicU64::new(1);

#[cfg(test)]
pub(crate) static CACHE_CLOCK_READS: AtomicUsize = AtomicUsize::new(0);
#[cfg(any(test, debug_assertions))]
static SYSTEM_CLOCK_READS: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
pub(crate) static CACHE_LOOKUP_CALLS: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
pub(crate) static CACHE_ADMIT_CALLS: AtomicUsize = AtomicUsize::new(0);

/// Allocates a process-unique identifier for one [`crate::StaticServer`] namespace.
pub(crate) fn next_server_id() -> u64 {
    NEXT_SERVER_ID.fetch_add(1, Ordering::Relaxed)
}

/// Snapshot sampled once before the first filesystem access for a request: the owning cache's
/// identity, the monotonic cache timestamp anchoring the fixed expiry deadline, and the
/// process-wide credential epoch.
///
/// External crates cannot construct a `FillStart` directly and cannot transfer one across
/// different [`FileCache`] instances (or clock domains): a foreign `FillStart` is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FillStart {
    pub(crate) cache_id: u64,
    pub(crate) looked_up_at: u64,
    pub(crate) cred_epoch: u64,
    pub(crate) pressure: PressureBudget,
}

#[cfg(target_os = "linux")]
fn system_now_nanos() -> u64 {
    let ts = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let secs = u128::try_from(ts.tv_sec).unwrap_or(0);
    let nanos = u128::try_from(ts.tv_nsec).unwrap_or(0);
    let total = secs.saturating_mul(1_000_000_000).saturating_add(nanos);
    u64::try_from(total).unwrap_or(u64::MAX)
}

#[cfg(not(target_os = "linux"))]
fn system_now_nanos() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let origin = *EPOCH.get_or_init(Instant::now);
    u64::try_from(origin.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

#[derive(Debug, Default)]
struct ManualClockState {
    nanos: AtomicU64,
    reads: AtomicUsize,
}

/// Monotonic clock source for [`FileCache`] entry deadlines.
///
/// Production builds use [`CacheClock::System`] (`CLOCK_BOOTTIME` via `rustix` on Linux so
/// suspended time counts toward the expiry window; [`std::time::Instant`] on other systems,
/// where the bound assumes the host does not suspend). Tests can inject [`CacheClock::Manual`]
/// via [`ManualClock`] to advance deadlines deterministically without sleeping.
#[derive(Clone, Debug, Default)]
pub enum CacheClock {
    /// Real monotonic clock (`CLOCK_BOOTTIME` on Linux; `std::time::Instant` elsewhere).
    #[default]
    System,
    /// Deterministic test clock storing elapsed nanoseconds since an arbitrary test epoch.
    Manual(ManualClock),
}

impl CacheClock {
    /// Current monotonic timestamp in nanoseconds.
    #[must_use]
    pub fn now_nanos(&self) -> u64 {
        #[cfg(test)]
        CACHE_CLOCK_READS.fetch_add(1, Ordering::Relaxed);
        match self {
            Self::System => {
                #[cfg(any(test, debug_assertions))]
                SYSTEM_CLOCK_READS.fetch_add(1, Ordering::Relaxed);
                system_now_nanos()
            }
            Self::Manual(clock) => {
                clock.state.reads.fetch_add(1, Ordering::Relaxed);
                clock.state.nanos.load(Ordering::Acquire)
            }
        }
    }

    /// Returns how many times [`CacheClock::System`] has been read in this process (available in
    /// test and debug-assertion builds so downstream cache-off tests also detect direct
    /// `CacheClock::System.now_nanos()` calls, such as from the router's ACME path).
    #[cfg(any(test, debug_assertions))]
    #[doc(hidden)]
    #[must_use]
    pub fn system_read_count() -> usize {
        SYSTEM_CLOCK_READS.load(Ordering::Acquire)
    }

    /// Name of the underlying OS clock source used by [`CacheClock::System`] on this target.
    #[must_use]
    pub const fn system_clock_source() -> &'static str {
        #[cfg(target_os = "linux")]
        {
            "CLOCK_BOOTTIME"
        }
        #[cfg(not(target_os = "linux"))]
        {
            "std::time::Instant"
        }
    }

    const fn is_system(&self) -> bool {
        matches!(self, Self::System)
    }
}

/// Deterministic controllable clock for sleep-free file-cache tests.
#[derive(Clone, Debug, Default)]
pub struct ManualClock {
    state: Arc<ManualClockState>,
}

impl ManualClock {
    /// Creates a manual clock starting at `0`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(ManualClockState::default()),
        }
    }

    /// Advances the clock forward by `delta`.
    pub fn advance(&self, delta: Duration) {
        let add = duration_to_nanos(delta);
        self.state.nanos.fetch_add(add, Ordering::AcqRel);
    }

    /// Returns the current elapsed nanoseconds.
    #[must_use]
    pub fn now_nanos(&self) -> u64 {
        self.state.nanos.load(Ordering::Acquire)
    }

    /// Returns how many times [`CacheClock::now_nanos`] has read this manual clock.
    #[must_use]
    pub fn read_count(&self) -> usize {
        self.state.reads.load(Ordering::Acquire)
    }

    /// Returns a [`CacheClock`] handle backed by this manual clock.
    #[must_use]
    pub fn cache_clock(&self) -> CacheClock {
        CacheClock::Manual(self.clone())
    }
}

pub(crate) fn duration_to_nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

fn thread_counter_stripe() -> usize {
    static NEXT_STRIPE: AtomicUsize = AtomicUsize::new(0);
    thread_local! {
        static STRIPE: usize = NEXT_STRIPE.fetch_add(1, Ordering::Relaxed)
            & (COUNTER_STRIPES - 1);
    }
    STRIPE.with(|&s| s)
}

/// Shared lock-free striped telemetry counters for static file-cache events:
/// `[hits, misses, fills, not_cached_budget]`.
///
/// Each stripe occupies `128` bytes (`[AtomicU64; 16]`, using indices `0..4` with `96` bytes of
/// padding) and is indexed per OS thread so concurrent hits and misses on different cores do not
/// write one shared cache line. Totals are summed lazily on read/scrape.
#[derive(Debug, Clone)]
pub struct FileCacheCounters {
    raw: Arc<[[AtomicU64; 16]]>,
}

impl Default for FileCacheCounters {
    fn default() -> Self {
        Self::new()
    }
}

impl FileCacheCounters {
    /// Creates a fresh zero-initialized striped counter set.
    #[must_use]
    pub fn new() -> Self {
        let stripes: Vec<[AtomicU64; 16]> = (0..COUNTER_STRIPES)
            .map(|_| std::array::from_fn(|_| AtomicU64::new(0)))
            .collect();
        Self {
            raw: Arc::from(stripes),
        }
    }

    /// Wraps an existing striped `[hits, misses, fills, not_cached_budget, ..]` atomic table
    /// (for example, the table owned by `miraserve-telemetry`'s `TelemetryRegistry`).
    #[must_use]
    pub const fn from_raw(raw: Arc<[[AtomicU64; 16]]>) -> Self {
        Self { raw }
    }

    /// Total cache hits served from memory (summed across all stripes).
    #[must_use]
    pub fn hits(&self) -> u64 {
        self.snapshot().0
    }

    /// Total eligible cache lookups that missed (summed across all stripes).
    #[must_use]
    pub fn misses(&self) -> u64 {
        self.snapshot().1
    }

    /// Total qualifying responses admitted into the cache (summed across all stripes).
    #[must_use]
    pub fn fills(&self) -> u64 {
        self.snapshot().2
    }

    /// Total qualifying responses not cached because the byte budget was exhausted
    /// (summed across all stripes).
    #[must_use]
    pub fn not_cached_budget(&self) -> u64 {
        self.snapshot().3
    }

    /// Returns `(hits, misses, fills, not_cached_budget)` summed across all stripes.
    #[must_use]
    pub fn snapshot(&self) -> (u64, u64, u64, u64) {
        let (mut hits, mut misses, mut fills, mut budget) = (0_u64, 0_u64, 0_u64, 0_u64);
        for [h, m, f, b, ..] in &*self.raw {
            hits = hits.saturating_add(h.load(Ordering::Relaxed));
            misses = misses.saturating_add(m.load(Ordering::Relaxed));
            fills = fills.saturating_add(f.load(Ordering::Relaxed));
            budget = budget.saturating_add(b.load(Ordering::Relaxed));
        }
        (hits, misses, fills, budget)
    }

    fn record_slot(&self, counter_index: usize) {
        let len = self.raw.len();
        if len == 0 {
            return;
        }
        let stripe_idx = thread_counter_stripe();
        let slot = if len.is_power_of_two() {
            stripe_idx & (len - 1)
        } else {
            stripe_idx % len
        };
        if let Some(stripe) = self.raw.get(slot)
            && let Some(ctr) = stripe.get(counter_index)
        {
            ctr.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn record_hit(&self) {
        self.record_slot(0);
    }

    pub(crate) fn record_miss(&self) {
        self.record_slot(1);
    }

    pub(crate) fn record_fill(&self) {
        self.record_slot(2);
    }

    pub(crate) fn record_not_cached_budget(&self) {
        self.record_slot(3);
    }
}

/// Process-wide byte budget shared across all sites, worker loops, and reload generations.
///
/// Body bytes stay charged while any response still holds a clone of a cached body, even after
/// the entry is evicted or its configuration generation is replaced on reload.
pub struct FileCacheBudget {
    limit_bytes: AtomicUsize,
    used_bytes: AtomicUsize,
    #[cfg(test)]
    before_cas_hook: RwLock<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl std::fmt::Debug for FileCacheBudget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileCacheBudget")
            .field("limit_bytes", &self.limit_bytes.load(Ordering::Relaxed))
            .field("used_bytes", &self.used_bytes.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl FileCacheBudget {
    /// Creates a budget capped at `limit_bytes` (`0` disables caching globally).
    #[must_use]
    pub const fn new(limit_bytes: usize) -> Self {
        Self {
            limit_bytes: AtomicUsize::new(limit_bytes),
            used_bytes: AtomicUsize::new(0),
            #[cfg(test)]
            before_cas_hook: RwLock::new(None),
        }
    }

    /// Updates the budget ceiling on configuration reload commit.
    pub fn set_limit(&self, limit_bytes: usize) {
        self.limit_bytes.store(limit_bytes, Ordering::SeqCst);
    }

    /// Current configured byte limit (`0` means disabled).
    #[must_use]
    pub fn limit_bytes(&self) -> usize {
        self.limit_bytes.load(Ordering::SeqCst)
    }

    /// Live bytes currently charged across cached entries, shard tables, and in-flight responses.
    #[must_use]
    pub fn used_bytes(&self) -> usize {
        self.used_bytes.load(Ordering::Acquire)
    }

    #[cfg(test)]
    fn set_before_cas_hook(&self, hook: Option<Arc<dyn Fn() + Send + Sync>>) {
        let mut guard = self
            .before_cas_hook
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = hook;
    }

    #[cfg(test)]
    fn run_before_cas_hook(&self) {
        let hook = self
            .before_cas_hook
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(f) = hook {
            f();
        }
    }

    /// Atomically reserves `bytes` against the ceiling before allocating cache structures.
    ///
    /// Reads `limit_bytes` inside the CAS loop and re-checks it with `SeqCst` ordering after CAS
    /// success, immediately releasing the reservation if the ceiling was lowered concurrently.
    /// Lowering the limit to `0` disables new reservations at once.
    fn try_reserve(self: &Arc<Self>, bytes: usize) -> Option<BudgetReservation> {
        if bytes == 0 {
            if self.limit_bytes.load(Ordering::SeqCst) == 0 {
                return None;
            }
            return Some(BudgetReservation {
                budget: Arc::clone(self),
                bytes: 0,
            });
        }
        let mut current = self.used_bytes.load(Ordering::Acquire);
        loop {
            let limit = self.limit_bytes.load(Ordering::SeqCst);
            if limit == 0 {
                return None;
            }
            let next = current.checked_add(bytes)?;
            if next > limit {
                return None;
            }
            #[cfg(test)]
            self.run_before_cas_hook();
            match self.used_bytes.compare_exchange_weak(
                current,
                next,
                Ordering::SeqCst,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    let reservation = BudgetReservation {
                        budget: Arc::clone(self),
                        bytes,
                    };
                    let limit_after = self.limit_bytes.load(Ordering::SeqCst);
                    if limit_after == 0 || next > limit_after {
                        drop(reservation);
                        return None;
                    }
                    return Some(reservation);
                }
                Err(actual) => current = actual,
            }
        }
    }
}

/// RAII byte reservation against a [`FileCacheBudget`].
#[derive(Debug)]
struct BudgetReservation {
    budget: Arc<FileCacheBudget>,
    bytes: usize,
}

impl BudgetReservation {
    /// Splits this reservation into `(first_part, remainder)` without modifying the budget total.
    fn split(mut self, first: usize) -> (Self, Self) {
        let take = first.min(self.bytes);
        let rest = self.bytes.saturating_sub(take);
        self.bytes = 0;
        let a = Self {
            budget: Arc::clone(&self.budget),
            bytes: take,
        };
        let b = Self {
            budget: Arc::clone(&self.budget),
            bytes: rest,
        };
        (a, b)
    }
}

impl Drop for BudgetReservation {
    fn drop(&mut self) {
        if self.bytes > 0 {
            self.budget
                .used_bytes
                .fetch_sub(self.bytes, Ordering::AcqRel);
        }
    }
}

/// Exact-capacity body buffer (`data.capacity() == data.len()`) paired with its
/// [`BudgetReservation`], wrapped via [`Bytes::from_owner`] so that every [`Bytes`] clone or
/// slice keeps the body and owner box charged until the very last reference drops.
struct ChargedBody {
    data: Vec<u8>,
    _reservation: BudgetReservation,
}

impl AsRef<[u8]> for ChargedBody {
    fn as_ref(&self) -> &[u8] {
        self.data.as_slice()
    }
}

/// Real memory occupied by a `Bytes::from_owner(ChargedBody)` control box (excluding the payload
/// slice itself): `Owned<ChargedBody>` (`ref_cnt: AtomicUsize` + `ChargedBody`).
#[must_use]
pub const fn charged_body_owner_bytes() -> usize {
    std::mem::size_of::<(AtomicUsize, ChargedBody)>()
}

/// Real memory charged for a cached body of `len` bytes: `0` when empty (uses `Bytes::new()`),
/// otherwise exact `len` bytes plus [`charged_body_owner_bytes`].
#[must_use]
pub const fn charged_body_bytes(len: usize) -> usize {
    if len == 0 {
        0
    } else {
        len.saturating_add(charged_body_owner_bytes())
    }
}

/// Copies `src` into an exact-capacity `Vec<u8>` (`capacity() == len()`) via `Box<[u8]>`.
fn copy_exact_vec(src: &[u8]) -> Vec<u8> {
    let boxed: Box<[u8]> = Box::from(src);
    Vec::from(boxed)
}

/// Copies a [`HeaderValue`] into an exact-sized `Bytes`-backed [`HeaderValue`].
fn exact_header_value(val: &HeaderValue) -> HeaderValue {
    HeaderValue::from_bytes(val.as_bytes()).unwrap_or_else(|_| val.clone())
}

/// Disjoint lookup namespace separating direct static serves from `try-files` resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum LookupKind {
    /// Direct static file / directory-index serving (`serve_canonical*` / `serve`).
    Direct,
    /// `try-files` candidate evaluation (`serve_try_files*`).
    TryFiles,
}

/// Borrowed view of [`CacheKey`] enabling zero-allocation `HashMap` lookups with `std` only.
trait KeyParts {
    fn key_parts(&self) -> (u64, LookupKind, u8, &str);
}

impl PartialEq for dyn KeyParts + '_ {
    fn eq(&self, other: &Self) -> bool {
        self.key_parts() == other.key_parts()
    }
}

impl Eq for dyn KeyParts + '_ {}

impl Hash for dyn KeyParts + '_ {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key_parts().hash(state);
    }
}

#[derive(Debug, Clone)]
struct CacheKey {
    server_id: u64,
    kind: LookupKind,
    enc_mask: u8,
    path: Box<str>,
}

impl KeyParts for CacheKey {
    fn key_parts(&self) -> (u64, LookupKind, u8, &str) {
        (self.server_id, self.kind, self.enc_mask, &self.path)
    }
}

impl PartialEq for CacheKey {
    fn eq(&self, other: &Self) -> bool {
        self.key_parts() == other.key_parts()
    }
}

impl Eq for CacheKey {}

impl Hash for CacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key_parts().hash(state);
    }
}

impl<'a> Borrow<dyn KeyParts + 'a> for CacheKey {
    fn borrow(&self) -> &(dyn KeyParts + 'a) {
        self
    }
}

struct LookupKey<'a> {
    server_id: u64,
    kind: LookupKind,
    enc_mask: u8,
    path: &'a str,
}

impl KeyParts for LookupKey<'_> {
    fn key_parts(&self) -> (u64, LookupKind, u8, &str) {
        (self.server_id, self.kind, self.enc_mask, self.path)
    }
}

/// Cached immutable static representation valid strictly while `now < expires_at_nanos` and
/// `cred_epoch == current_credential_epoch()`.
#[derive(Debug)]
pub(crate) struct CacheEntry {
    pub(crate) expires_at_nanos: u64,
    pub(crate) cred_epoch: u64,
    pub(crate) content_type: HeaderValue,
    pub(crate) content_len: u64,
    pub(crate) etag: Option<HeaderValue>,
    pub(crate) modified: Option<SystemTime>,
    pub(crate) last_modified: Option<HeaderValue>,
    pub(crate) encoding: Option<ContentEncoding>,
    /// Expanded static fallback candidate path for `try-files` entries produced by a non-`{path}`
    /// fallback template (such as `"/index.html"`), so cache hits return
    /// [`crate::TryFilesOutcome::FallbackResponse`] and preserve route header ownership. `None`
    /// for direct static entries and `{path}` / `{path}/` matches.
    pub(crate) fallback_candidate_path: Option<Box<str>>,
    pub(crate) body: Bytes,
    #[cfg(test)]
    pub(crate) body_capacity: usize,
    _meta_reservation: BudgetReservation,
}

impl CacheEntry {
    pub(crate) fn etag_str(&self) -> &str {
        self.etag
            .as_ref()
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    }

    fn is_live(&self, now: u64, cur_epoch: u64) -> bool {
        is_quiescent_credential_epoch(cur_epoch)
            && self.cred_epoch == cur_epoch
            && now < self.expires_at_nanos
    }
}

/// Parameters for admitting a qualifying `200 OK` `GET` regular-file response into [`FileCache`].
pub(crate) struct AdmitParams<'a> {
    pub(crate) server_id: u64,
    pub(crate) kind: LookupKind,
    pub(crate) enc_mask: u8,
    pub(crate) path: &'a str,
    pub(crate) expires_at_nanos: u64,
    pub(crate) cred_epoch: u64,
    pub(crate) content_type: HeaderValue,
    pub(crate) content_len: u64,
    pub(crate) etag: Option<HeaderValue>,
    pub(crate) modified: Option<SystemTime>,
    pub(crate) last_modified: Option<HeaderValue>,
    pub(crate) encoding: Option<ContentEncoding>,
    pub(crate) fallback_candidate_path: Option<&'a str>,
    pub(crate) body: Bytes,
}

/// Per-request budget-pressure sweep allowance shared between pre-compression budget checks and
/// final admission so a single request visits at most one non-empty shard for reservation retries
/// and examines at most [`PRESSURE_SWEEP_MAX_ENTRIES`] (32) entries in total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PressureBudget {
    remaining_entries: usize,
    shard_swept: bool,
}

impl PressureBudget {
    pub(crate) const fn new() -> Self {
        Self {
            remaining_entries: PRESSURE_SWEEP_MAX_ENTRIES,
            shard_swept: false,
        }
    }
}

/// Result of checking whether [`FileCache`] has enough budget to admit even a minimal non-empty
/// entry (used before on-the-fly compression so budget-exhausted requests can keep using the
/// compression cache as in `7dcbd97` without ever admitting compression-cache bytes).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum MinBudgetStatus {
    /// Budget can fit at least the minimum non-empty entry overhead.
    Available,
    /// Caching is disabled globally (`file-cache-bytes == 0`).
    Disabled,
    /// Budget is full of live entries and cannot fit even the minimum entry overhead.
    Exhausted,
}

fn header_value_bytes(val: &HeaderValue) -> usize {
    val.len().saturating_add(BYTES_SHARED_OVERHEAD)
}

/// Real per-entry heap charge covering `ArcInner<CacheEntry>`, `CacheKey::path: Box<str>`, and
/// exact `HeaderValue` backing storage + `Bytes` shared control blocks.
///
/// The inline `(CacheKey, Arc<CacheEntry>)` hash-table slot itself is accounted separately in
/// `ShardMap::table_reservation` whenever the shard's `HashMap` allocates or grows its bucket
/// array.
fn entry_meta_bytes(
    path_len: usize,
    content_type: &HeaderValue,
    etag: Option<&HeaderValue>,
    last_modified: Option<&HeaderValue>,
    fallback_candidate_path: Option<&str>,
) -> usize {
    let arc_entry = 2_usize
        .saturating_mul(std::mem::size_of::<AtomicUsize>())
        .saturating_add(std::mem::size_of::<CacheEntry>());
    arc_entry
        .saturating_add(path_len)
        .saturating_add(header_value_bytes(content_type))
        .saturating_add(etag.map_or(0, header_value_bytes))
        .saturating_add(last_modified.map_or(0, header_value_bytes))
        .saturating_add(fallback_candidate_path.map_or(0, str::len))
}

#[allow(clippy::too_many_arguments)]
fn build_charged_entry(
    reservation: BudgetReservation,
    meta_charge: usize,
    expires_at_nanos: u64,
    cred_epoch: u64,
    content_type: &HeaderValue,
    content_len: u64,
    etag: Option<&HeaderValue>,
    modified: Option<SystemTime>,
    last_modified: Option<&HeaderValue>,
    encoding: Option<ContentEncoding>,
    fallback_candidate_path: Option<&str>,
    body: &[u8],
) -> (Arc<CacheEntry>, Bytes) {
    let (meta_res, body_res) = reservation.split(meta_charge);
    #[cfg(test)]
    let body_capacity;
    let charged_body = if body.is_empty() {
        drop(body_res);
        #[cfg(test)]
        {
            body_capacity = 0;
        }
        Bytes::new()
    } else {
        let exact = copy_exact_vec(body);
        debug_assert_eq!(exact.capacity(), exact.len());
        #[cfg(test)]
        {
            body_capacity = exact.capacity();
        }
        Bytes::from_owner(ChargedBody {
            data: exact,
            _reservation: body_res,
        })
    };
    let entry = Arc::new(CacheEntry {
        expires_at_nanos,
        cred_epoch,
        content_type: exact_header_value(content_type),
        content_len,
        etag: etag.map(exact_header_value),
        modified,
        last_modified: last_modified.map(exact_header_value),
        encoding,
        fallback_candidate_path: fallback_candidate_path.map(Box::from),
        body: charged_body.clone(),
        #[cfg(test)]
        body_capacity,
        _meta_reservation: meta_res,
    });
    (entry, charged_body)
}

/// Bucket count of `std::collections::HashMap` (hashbrown `SwissTable`, 7/8 load factor) for a
/// reported `capacity()`.
fn map_bucket_count(cap: usize) -> usize {
    if cap == 0 {
        0
    } else {
        let raw = cap.saturating_mul(8) / 7;
        raw.next_power_of_two().max(4)
    }
}

/// Initial bucket count allocated by `HashMap::<CacheKey, Arc<CacheEntry>>::reserve(1)` on this
/// standard library build (typically `4`), probed once and cached.
fn initial_map_buckets() -> usize {
    static INITIAL: OnceLock<usize> = OnceLock::new();
    *INITIAL.get_or_init(|| {
        let mut m: HashMap<CacheKey, Arc<CacheEntry>> = HashMap::new();
        m.reserve(1);
        map_bucket_count(m.capacity()).max(4)
    })
}

/// Real backing allocation size in bytes for `buckets` `SwissTable` slots (`(K, V)` + 1 control
/// byte per bucket + 16 SIMD padding control bytes).
fn map_table_bytes_for_buckets(buckets: usize) -> usize {
    if buckets == 0 {
        0
    } else {
        let per_bucket = std::mem::size_of::<(CacheKey, Arc<CacheEntry>)>().saturating_add(1);
        buckets.saturating_mul(per_bucket).saturating_add(16)
    }
}

#[derive(Debug)]
struct ShardMap {
    map: HashMap<CacheKey, Arc<CacheEntry>>,
    /// High-water bucket count of `map`'s currently allocated backing table.
    ///
    /// Never decremented on deletions (tombstones lower `map.capacity()` without freeing the
    /// backing bucket array); only reset to `0` when the shard becomes empty and `map` is
    /// replaced with a fresh unallocated `HashMap::new()`.
    allocated_buckets: usize,
    table_reservation: Option<BudgetReservation>,
}

impl ShardMap {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            allocated_buckets: 0,
            table_reservation: None,
        }
    }

    #[cfg(test)]
    fn reserved_table_bytes(&self) -> usize {
        self.table_reservation.as_ref().map_or(0, |r| r.bytes)
    }

    /// Bucket count that will be reserved before inserting a new key when `len >= capacity`.
    fn next_growth_buckets(&self) -> usize {
        if self.allocated_buckets == 0 {
            initial_map_buckets()
        } else {
            self.allocated_buckets.saturating_mul(2)
        }
    }

    /// Replaces an empty map with an unallocated `HashMap::new()` so the backing bucket array is
    /// guaranteed to be freed before refunding `table_reservation` outside the shard lock.
    fn clear_if_empty(&mut self) -> Option<BudgetReservation> {
        if self.map.is_empty() {
            self.map = HashMap::new();
            self.allocated_buckets = 0;
            self.table_reservation.take()
        } else {
            None
        }
    }
}

#[repr(align(64))]
#[derive(Debug)]
struct CacheShard {
    entries: RwLock<ShardMap>,
    len: AtomicUsize,
}

impl CacheShard {
    fn new() -> Self {
        Self {
            entries: RwLock::new(ShardMap::new()),
            len: AtomicUsize::new(0),
        }
    }
}

#[cfg(test)]
type FillStartHook = Arc<dyn Fn(FillStart) + Send + Sync>;

#[cfg(test)]
#[derive(Default)]
struct CacheTestHooks {
    before_read_lock: RwLock<Option<Arc<dyn Fn() + Send + Sync>>>,
    before_write_lock: RwLock<Option<Arc<dyn Fn() + Send + Sync>>>,
    before_admit_lock: RwLock<Option<Arc<dyn Fn() + Send + Sync>>>,
    on_sweeper_start: RwLock<Option<Arc<dyn Fn() + Send + Sync>>>,
    after_sample_fill_start: RwLock<Option<FillStartHook>>,
    pressure_shards_visited: AtomicUsize,
    pressure_entries_examined: AtomicUsize,
}

/// Generation-scoped sharded static file cache sharing a process-wide [`FileCacheBudget`] and
/// [`FileCacheCounters`].
///
/// A configuration reload creates a fresh empty [`FileCache`] linked to the same
/// [`FileCacheBudget`] and [`FileCacheCounters`] and drops the previous generation's instance.
pub struct FileCache {
    cache_id: u64,
    shards: Box<[CacheShard]>,
    hasher: RandomState,
    budget: Arc<FileCacheBudget>,
    counters: FileCacheCounters,
    clock: CacheClock,
    nonempty_shards: AtomicU64,
    sweep_cursor: AtomicUsize,
    sweeper_started: AtomicBool,
    /// Shared/control Tokio runtime handle captured when this generation was constructed off a
    /// worker loop thread, so background sweeps always run on the shared runtime rather than on a
    /// dedicated worker event loop.
    sweeper_handle: Option<tokio::runtime::Handle>,
    #[cfg(test)]
    hooks: CacheTestHooks,
}

impl std::fmt::Debug for FileCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileCache")
            .field("cache_id", &self.cache_id)
            .field("entry_count", &self.entry_count())
            .field("budget", &self.budget)
            .field("clock", &self.clock)
            .finish_non_exhaustive()
    }
}

impl FileCache {
    /// Creates a new empty cache generation using the system monotonic clock.
    #[must_use]
    pub fn new(budget: Arc<FileCacheBudget>, counters: FileCacheCounters) -> Arc<Self> {
        Self::with_clock(budget, counters, CacheClock::System)
    }

    /// Creates a new empty cache generation using an explicit [`CacheClock`].
    #[must_use]
    pub fn with_clock(
        budget: Arc<FileCacheBudget>,
        counters: FileCacheCounters,
        clock: CacheClock,
    ) -> Arc<Self> {
        let mut shards = Vec::with_capacity(NUM_SHARDS);
        for _ in 0..NUM_SHARDS {
            shards.push(CacheShard::new());
        }
        let sweeper_handle = (!crate::is_worker_loop_thread())
            .then(|| tokio::runtime::Handle::try_current().ok())
            .flatten();
        Arc::new(Self {
            cache_id: NEXT_CACHE_ID.fetch_add(1, Ordering::Relaxed),
            shards: shards.into_boxed_slice(),
            hasher: RandomState::new(),
            budget,
            counters,
            clock,
            nonempty_shards: AtomicU64::new(0),
            sweep_cursor: AtomicUsize::new(0),
            sweeper_started: AtomicBool::new(false),
            sweeper_handle,
            #[cfg(test)]
            hooks: CacheTestHooks::default(),
        })
    }

    /// Returns the shared process-wide byte budget.
    #[must_use]
    pub const fn budget(&self) -> &Arc<FileCacheBudget> {
        &self.budget
    }

    /// Returns the shared telemetry counters.
    #[must_use]
    pub const fn counters(&self) -> &FileCacheCounters {
        &self.counters
    }

    /// Returns whether the process-wide byte budget permits caching (`limit_bytes() > 0`).
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.budget.limit_bytes() > 0
    }

    /// Current monotonic timestamp in nanoseconds from this cache's clock.
    #[must_use]
    pub fn now_nanos(&self) -> u64 {
        self.clock.now_nanos()
    }

    /// Samples a [`FillStart`] bound to this cache's identity (credential epoch and monotonic
    /// timestamp) before a request's first filesystem access.
    #[must_use]
    pub fn sample_fill_start(&self) -> FillStart {
        let start = FillStart {
            cache_id: self.cache_id,
            cred_epoch: current_credential_epoch(),
            looked_up_at: self.clock.now_nanos(),
            pressure: PressureBudget::new(),
        };
        #[cfg(test)]
        {
            let hook = self
                .hooks
                .after_sample_fill_start
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if let Some(f) = hook {
                f(start);
            }
        }
        start
    }

    #[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
    #[cfg(test)]
    pub(crate) fn set_after_sample_fill_start(&self, hook: Option<FillStartHook>) {
        *self
            .hooks
            .after_sample_fill_start
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = hook;
    }

    #[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
    #[cfg(test)]
    pub(crate) fn reset_pressure_counters(&self) {
        self.hooks
            .pressure_shards_visited
            .store(0, Ordering::SeqCst);
        self.hooks
            .pressure_entries_examined
            .store(0, Ordering::SeqCst);
    }

    #[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
    #[cfg(test)]
    pub(crate) fn pressure_shards_visited(&self) -> usize {
        self.hooks.pressure_shards_visited.load(Ordering::SeqCst)
    }

    #[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
    #[cfg(test)]
    pub(crate) fn pressure_entries_examined(&self) -> usize {
        self.hooks.pressure_entries_examined.load(Ordering::SeqCst)
    }

    /// Returns whether `start` was sampled from this [`FileCache`] instance (and clock domain).
    #[must_use]
    pub(crate) const fn owns_fill_start(&self, start: FillStart) -> bool {
        start.cache_id == self.cache_id
    }

    /// Total entries currently held across all shards of this generation.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.len.load(Ordering::Relaxed))
            .sum()
    }

    fn shard_index(&self, server_id: u64, kind: LookupKind, enc_mask: u8, path: &str) -> usize {
        let hash = self.hasher.hash_one((server_id, kind, enc_mask, path));
        usize::try_from(hash & ((NUM_SHARDS as u64) - 1)).unwrap_or(0)
    }

    fn mark_shard_nonempty(&self, idx: usize) {
        self.nonempty_shards
            .fetch_or(1_u64 << idx, Ordering::Release);
    }

    fn mark_shard_empty(&self, idx: usize) {
        self.nonempty_shards
            .fetch_and(!(1_u64 << idx), Ordering::Release);
    }

    #[cfg(test)]
    fn run_hook(slot: &RwLock<Option<Arc<dyn Fn() + Send + Sync>>>) {
        let hook = slot
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(f) = hook {
            f();
        }
    }

    /// Looks up a fresh entry for `(server_id, kind, enc_mask, path)`.
    ///
    /// Samples both the clock and credential epoch *while holding the shard lock* (on both the
    /// read path and the expired/replacement write-lock path). Lazily removes an expired or
    /// superseded-epoch entry only if the slot still holds a stale entry under the write lock.
    pub(crate) fn get_if_fresh(
        &self,
        server_id: u64,
        kind: LookupKind,
        enc_mask: u8,
        path: &str,
    ) -> Option<Arc<CacheEntry>> {
        #[cfg(test)]
        CACHE_LOOKUP_CALLS.fetch_add(1, Ordering::Relaxed);
        if path.len() > MAX_CACHE_KEY_BYTES || self.budget.limit_bytes() == 0 {
            return None;
        }
        let idx = self.shard_index(server_id, kind, enc_mask, path);
        let shard = self.shards.get(idx)?;
        if shard.len.load(Ordering::Acquire) == 0 {
            return None;
        }
        let lookup_key = LookupKey {
            server_id,
            kind,
            enc_mask,
            path,
        };
        let lookup: &dyn KeyParts = &lookup_key;

        #[cfg(test)]
        Self::run_hook(&self.hooks.before_read_lock);

        let stale = {
            let guard = shard
                .entries
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match guard.map.get(lookup) {
                Some(entry) => {
                    let now = self.clock.now_nanos();
                    let cur_epoch = current_credential_epoch();
                    if entry.is_live(now, cur_epoch) {
                        return Some(Arc::clone(entry));
                    }
                    true
                }
                None => false,
            }
        };

        if stale {
            #[cfg(test)]
            Self::run_hook(&self.hooks.before_write_lock);

            let mut evicted = None;
            let mut released_table = None;
            let mut refreshed = None;
            {
                let mut guard = shard
                    .entries
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let now = self.clock.now_nanos();
                let cur_epoch = current_credential_epoch();
                match guard.map.get(lookup) {
                    Some(cur) if cur.is_live(now, cur_epoch) => {
                        // A concurrent fill refreshed this key while we waited for the write lock
                        // and it is still live at the time sampled under this lock.
                        refreshed = Some(Arc::clone(cur));
                    }
                    Some(_) => {
                        evicted = guard.map.remove(lookup);
                        let new_len = guard.map.len();
                        shard.len.store(new_len, Ordering::Release);
                        if new_len == 0 {
                            released_table = guard.clear_if_empty();
                            self.mark_shard_empty(idx);
                        }
                    }
                    None => {}
                }
            }
            drop(evicted);
            drop(released_table);
            if refreshed.is_some() {
                return refreshed;
            }
        }
        None
    }

    /// Minimum bytes required to admit any non-empty cached entry for `path_len` and headers
    /// (1 body byte + owner box + entry/header metadata).
    pub(crate) fn min_nonempty_entry_charge(
        path_len: usize,
        content_type: &HeaderValue,
        etag_len: usize,
        last_modified: Option<&HeaderValue>,
        fallback_path_len: usize,
    ) -> Option<usize> {
        let arc_entry = 2_usize
            .saturating_mul(std::mem::size_of::<AtomicUsize>())
            .saturating_add(std::mem::size_of::<CacheEntry>());
        let etag_bytes = if etag_len == 0 {
            0
        } else {
            etag_len.saturating_add(BYTES_SHARED_OVERHEAD)
        };
        let meta_charge = arc_entry
            .saturating_add(path_len)
            .saturating_add(header_value_bytes(content_type))
            .saturating_add(etag_bytes)
            .saturating_add(last_modified.map_or(0, header_value_bytes))
            .saturating_add(fallback_path_len);
        charged_body_bytes(1).checked_add(meta_charge)
    }

    /// Checks whether the shared byte budget can possibly admit an entry requiring at least
    /// `min_charge` bytes, running at most one bounded pressure sweep (sharing `pressure` with
    /// [`Self::admit_with_pressure`]) if the budget currently appears full.
    pub(crate) fn check_budget_for_min_entry(
        &self,
        min_charge: usize,
        pressure: &mut PressureBudget,
    ) -> MinBudgetStatus {
        let limit = self.budget.limit_bytes();
        if limit == 0 {
            return MinBudgetStatus::Disabled;
        }
        let used = self.budget.used_bytes();
        if used
            .checked_add(min_charge)
            .is_some_and(|next| next <= limit)
        {
            return MinBudgetStatus::Available;
        }
        if !pressure.shard_swept && pressure.remaining_entries > 0 {
            pressure.shard_swept = true;
            if let Some(res) =
                self.sweep_pressure_one_shard(min_charge, &mut pressure.remaining_entries)
            {
                drop(res);
                return MinBudgetStatus::Available;
            }
            if self.budget.limit_bytes() == 0 {
                return MinBudgetStatus::Disabled;
            }
        }
        MinBudgetStatus::Exhausted
    }

    /// Attempts to admit a qualifying response into the cache, returning the [`Bytes`] buffer to
    /// send to the caller (backed by an exact-capacity [`ChargedBody`] if admitted, or the
    /// original buffer unchanged if not admitted).
    ///
    /// Reserves body, owner, entry, key, header-storage, and map-growth bytes from
    /// [`FileCacheBudget`] *before* copying or allocating cache structures. On concurrent fills
    /// of the same key, the first live entry wins without blocking any request.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn admit(self: &Arc<Self>, params: AdmitParams<'_>) -> Bytes {
        let mut pressure = PressureBudget::new();
        self.admit_with_pressure(params, &mut pressure)
    }

    /// Like [`Self::admit`], sharing `pressure` with any earlier pre-compression budget check on
    /// the same request so total pressure work stays strictly bounded.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn admit_with_pressure(
        self: &Arc<Self>,
        params: AdmitParams<'_>,
        pressure: &mut PressureBudget,
    ) -> Bytes {
        #[cfg(test)]
        CACHE_ADMIT_CALLS.fetch_add(1, Ordering::Relaxed);
        let AdmitParams {
            server_id,
            kind,
            enc_mask,
            path,
            expires_at_nanos,
            cred_epoch,
            content_type,
            content_len,
            etag,
            modified,
            last_modified,
            encoding,
            fallback_candidate_path,
            body,
        } = params;

        if path.len() > MAX_CACHE_KEY_BYTES || self.budget.limit_bytes() == 0 {
            return body;
        }
        if !is_quiescent_credential_epoch(cred_epoch)
            || cred_epoch != current_credential_epoch()
            || self.clock.now_nanos() >= expires_at_nanos
        {
            return body;
        }

        let body_charge = charged_body_bytes(body.len());
        let meta_charge = entry_meta_bytes(
            path.len(),
            &content_type,
            etag.as_ref(),
            last_modified.as_ref(),
            fallback_candidate_path,
        );
        let Some(total_charge) = body_charge.checked_add(meta_charge) else {
            self.counters.record_not_cached_budget();
            return body;
        };

        // Reserve budget BEFORE copying the body or allocating cache entry/key structures.
        // One request examines at most `PRESSURE_SWEEP_MAX_ENTRIES` (32) entries in total across
        // the reservation retry (at most one shard) and the destination shard.
        let reservation = self.budget.try_reserve(total_charge).or_else(|| {
            if pressure.shard_swept {
                None
            } else {
                pressure.shard_swept = true;
                self.sweep_pressure_one_shard(total_charge, &mut pressure.remaining_entries)
            }
        });
        let Some(reservation) = reservation else {
            self.counters.record_not_cached_budget();
            return body;
        };

        let idx = self.shard_index(server_id, kind, enc_mask, path);
        let Some(shard) = self.shards.get(idx) else {
            return body;
        };

        let lookup_key = LookupKey {
            server_id,
            kind,
            enc_mask,
            path,
        };
        let lookup: &dyn KeyParts = &lookup_key;

        #[cfg(test)]
        Self::run_hook(&self.hooks.before_admit_lock);

        let mut evicted_batch: Vec<Arc<CacheEntry>> = Vec::new();
        let mut replaced: Option<Arc<CacheEntry>> = None;
        let mut released_table: Option<BudgetReservation> = None;
        let (result_body, admitted, budget_exhausted) = {
            let mut guard = shard
                .entries
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let now = self.clock.now_nanos();
            let cur_epoch = current_credential_epoch();
            if self.budget.limit_bytes() == 0
                || !is_quiescent_credential_epoch(cred_epoch)
                || cred_epoch != cur_epoch
                || now >= expires_at_nanos
            {
                (body, false, false)
            } else if let Some(slot) = guard.map.get_mut(lookup) {
                if slot.is_live(now, cur_epoch) {
                    // Concurrent fill already inserted a live entry: first writer wins.
                    (body, false, false)
                } else {
                    // Replace an existing expired/stale key strictly in place via `get_mut` so
                    // hashbrown NEVER reserves a slot or grows a full table on replacement.
                    let (entry, charged_body) = build_charged_entry(
                        reservation,
                        meta_charge,
                        expires_at_nanos,
                        cred_epoch,
                        &content_type,
                        content_len,
                        etag.as_ref(),
                        modified,
                        last_modified.as_ref(),
                        encoding,
                        fallback_candidate_path,
                        body.as_ref(),
                    );
                    replaced = Some(std::mem::replace(slot, entry));
                    shard.len.store(guard.map.len(), Ordering::Release);
                    self.mark_shard_nonempty(idx);
                    (charged_body, true, false)
                }
            } else {
                if guard.map.len() >= MAX_ENTRIES_PER_SHARD && pressure.remaining_entries > 0 {
                    // Bounded eviction of expired/stale entries within this shard, sharing the
                    // single 32-entry per-request budget with any reservation retry above.
                    let mut stale_keys: Vec<CacheKey> = Vec::new();
                    let mut examined = 0_usize;
                    for (k, entry) in guard.map.iter().take(pressure.remaining_entries) {
                        examined = examined.saturating_add(1);
                        if !entry.is_live(now, cur_epoch) {
                            stale_keys.push(k.clone());
                        }
                    }
                    pressure.remaining_entries =
                        pressure.remaining_entries.saturating_sub(examined);
                    #[cfg(test)]
                    self.hooks
                        .pressure_entries_examined
                        .fetch_add(examined, Ordering::Relaxed);
                    for k in stale_keys {
                        if let Some(e) = guard.map.remove(&k) {
                            evicted_batch.push(e);
                        }
                    }
                }
                if guard.map.len() >= MAX_ENTRIES_PER_SHARD {
                    shard.len.store(guard.map.len(), Ordering::Release);
                    (body, false, false)
                } else {
                    // Conservative table accounting: when inserting a new key may trigger table
                    // allocation or growth (`len >= capacity`), reserve the FULL new table BEFORE
                    // inserting while still holding the old table's reservation, and release the
                    // old (or unused) table reservation only AFTER inserting. Never insert if the
                    // reservation fails, and never refund based on `capacity()` after deletions.
                    let mut growth_failed = false;
                    let planned_growth = if guard.map.len() >= guard.map.capacity() {
                        let next_buckets = guard.next_growth_buckets();
                        let new_table_bytes = map_table_bytes_for_buckets(next_buckets);
                        if let Some(res) = self.budget.try_reserve(new_table_bytes) {
                            Some((next_buckets, res))
                        } else {
                            growth_failed = true;
                            None
                        }
                    } else {
                        None
                    };

                    if growth_failed {
                        shard.len.store(guard.map.len(), Ordering::Release);
                        (body, false, true)
                    } else {
                        let (entry, charged_body) = build_charged_entry(
                            reservation,
                            meta_charge,
                            expires_at_nanos,
                            cred_epoch,
                            &content_type,
                            content_len,
                            etag.as_ref(),
                            modified,
                            last_modified.as_ref(),
                            encoding,
                            fallback_candidate_path,
                            body.as_ref(),
                        );
                        let key = CacheKey {
                            server_id,
                            kind,
                            enc_mask,
                            path: Box::from(path),
                        };
                        replaced = guard.map.insert(key, entry);
                        if let Some((next_buckets, new_table_res)) = planned_growth {
                            let observed_buckets = map_bucket_count(guard.map.capacity());
                            if observed_buckets > guard.allocated_buckets {
                                // Table grew: keep the full new-table reservation and release
                                // the old table reservation only now (dropped outside the lock).
                                guard.allocated_buckets = next_buckets.max(observed_buckets);
                                released_table = guard.table_reservation.replace(new_table_res);
                            } else {
                                // In-place tombstone rehash kept the existing bucket array: keep
                                // the existing table reservation and release the temporary full
                                // new-table reservation outside the lock.
                                released_table = Some(new_table_res);
                            }
                        }
                        shard.len.store(guard.map.len(), Ordering::Release);
                        self.mark_shard_nonempty(idx);
                        (charged_body, true, false)
                    }
                }
            }
        };

        // Drop replaced/evicted entries and any released table reservation strictly outside the
        // shard lock so budget releases never contend while holding the shard write lock.
        drop(replaced);
        drop(evicted_batch);
        drop(released_table);

        if budget_exhausted {
            self.counters.record_not_cached_budget();
        } else if admitted {
            self.counters.record_fill();
            self.maybe_start_sweeper();
        }
        result_body
    }

    /// Removes expired and superseded-epoch entries across up to `max_shards` shards starting at
    /// the rotating sweep cursor. Returns the number of entries removed.
    pub fn sweep_step(&self, max_shards: usize) -> usize {
        let count = max_shards.min(NUM_SHARDS);
        let start = self.sweep_cursor.fetch_add(count, Ordering::Relaxed);
        let mut removed = 0_usize;
        for step in 0..count {
            let idx = start.wrapping_add(step) & (NUM_SHARDS - 1);
            let (shard_removed, _) = self.sweep_shard_counted(idx);
            removed = removed.saturating_add(shard_removed);
        }
        removed
    }

    /// Bounded background sweep tick: visits up to `BACKGROUND_SWEEP_SHARDS_PER_TICK` (16) shards
    /// advancing the rotating cursor by the exact number of shards visited, stopping early once
    /// `BACKGROUND_SWEEP_MAX_ENTRIES_PER_TICK` (256) entries have been scanned (after completing
    /// the current shard of at most `MAX_ENTRIES_PER_SHARD` (256) entries so no shard tail is
    /// starved). Returns `(entries_removed, entries_examined)`.
    pub fn sweep_background_tick(&self) -> (usize, usize) {
        let mut removed = 0_usize;
        let mut examined = 0_usize;
        for _ in 0..BACKGROUND_SWEEP_SHARDS_PER_TICK {
            let idx = self.sweep_cursor.fetch_add(1, Ordering::Relaxed) & (NUM_SHARDS - 1);
            let (shard_removed, shard_examined) = self.sweep_shard_counted(idx);
            removed = removed.saturating_add(shard_removed);
            examined = examined.saturating_add(shard_examined);
            if examined >= BACKGROUND_SWEEP_MAX_ENTRIES_PER_TICK {
                break;
            }
        }
        (removed, examined)
    }

    /// Removes all expired and superseded-epoch entries across every shard of this generation.
    pub fn sweep_expired(&self) -> usize {
        self.sweep_step(NUM_SHARDS)
    }

    fn sweep_shard_counted(&self, idx: usize) -> (usize, usize) {
        let Some(shard) = self.shards.get(idx) else {
            return (0, 0);
        };
        if shard.len.load(Ordering::Acquire) == 0 {
            return (0, 0);
        }
        let mut evicted: Vec<Arc<CacheEntry>> = Vec::new();
        let released_table;
        let examined;
        {
            let mut guard = shard
                .entries
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            examined = guard.map.len();
            let now = self.clock.now_nanos();
            let cur_epoch = current_credential_epoch();
            guard.map.retain(|_, entry| {
                if entry.is_live(now, cur_epoch) {
                    true
                } else {
                    evicted.push(Arc::clone(entry));
                    false
                }
            });
            let new_len = guard.map.len();
            shard.len.store(new_len, Ordering::Release);
            released_table = if new_len == 0 {
                self.mark_shard_empty(idx);
                guard.clear_if_empty()
            } else {
                None
            };
        }
        let removed = evicted.len();
        drop(evicted);
        drop(released_table);
        (removed, examined)
    }

    /// Bounded opportunistic sweep on budget pressure: inspects **at most one** non-empty shard
    /// (chosen in O(1) from the 64-bit occupancy mask) and **at most `*remaining`** entries
    /// within it, decrementing `*remaining` so the whole request examines at most
    /// [`PRESSURE_SWEEP_MAX_ENTRIES`] (32) entries in total.
    fn sweep_pressure_one_shard(
        &self,
        needed: usize,
        remaining: &mut usize,
    ) -> Option<BudgetReservation> {
        let limit = *remaining;
        if limit == 0 {
            return None;
        }
        let mask = self.nonempty_shards.load(Ordering::Acquire);
        if mask == 0 {
            return None;
        }
        let start = self.sweep_cursor.fetch_add(1, Ordering::Relaxed) & (NUM_SHARDS - 1);
        let shift = u32::try_from(start).unwrap_or(0);
        let offset = usize::try_from(mask.rotate_right(shift).trailing_zeros()).unwrap_or(0);
        let idx = (start + offset) & (NUM_SHARDS - 1);
        let shard = self.shards.get(idx)?;

        let mut evicted: Vec<Arc<CacheEntry>> = Vec::new();
        let released_table;
        {
            let mut guard = shard
                .entries
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            #[cfg(test)]
            self.hooks
                .pressure_shards_visited
                .fetch_add(1, Ordering::Relaxed);
            let now = self.clock.now_nanos();
            let cur_epoch = current_credential_epoch();
            let mut stale_keys: Vec<CacheKey> = Vec::new();
            let mut examined = 0_usize;
            for (k, entry) in guard.map.iter().take(limit) {
                examined = examined.saturating_add(1);
                if !entry.is_live(now, cur_epoch) {
                    stale_keys.push(k.clone());
                }
            }
            *remaining = remaining.saturating_sub(examined);
            #[cfg(test)]
            self.hooks
                .pressure_entries_examined
                .fetch_add(examined, Ordering::Relaxed);
            for k in stale_keys {
                if let Some(e) = guard.map.remove(&k) {
                    evicted.push(e);
                }
            }
            let new_len = guard.map.len();
            shard.len.store(new_len, Ordering::Release);
            released_table = if new_len == 0 {
                self.mark_shard_empty(idx);
                guard.clear_if_empty()
            } else {
                None
            };
        }
        let removed = evicted.len();
        drop(evicted);
        drop(released_table);

        if removed > 0 {
            self.budget.try_reserve(needed)
        } else {
            None
        }
    }

    /// Lazily spawns a lightweight bounded background sweeper holding only a `Weak<Self>` on the
    /// **shared** Tokio runtime (never on a dedicated worker event loop) when running on the real
    /// system clock, so idle sites release expired memory without delaying worker event loops and
    /// the task exits automatically once this generation is dropped.
    fn maybe_start_sweeper(self: &Arc<Self>) {
        if !self.clock.is_system() {
            return;
        }
        let handle = if let Some(shared) = self.sweeper_handle.as_ref() {
            shared.clone()
        } else if crate::is_worker_loop_thread() {
            // Never place whole-shard background sweeps onto a single-thread worker event loop.
            return;
        } else if let Ok(current) = tokio::runtime::Handle::try_current() {
            current
        } else {
            return;
        };
        if self.sweeper_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let weak = Arc::downgrade(self);
        handle.spawn(async move {
            #[cfg(test)]
            if let Some(cache) = weak.upgrade() {
                Self::run_hook(&cache.hooks.on_sweeper_start);
            }
            let mut tick = tokio::time::interval(BACKGROUND_SWEEP_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await;
            loop {
                tick.tick().await;
                let Some(cache) = weak.upgrade() else {
                    break;
                };
                let _ = cache.sweep_background_tick();
            }
        });
    }
}

/// Per-[`crate::StaticServer`] attachment binding it to a [`FileCache`] generation, unique
/// `server_id`, validity window, unidentified-credential suppression flag, and optional
/// `try-files` candidate list, script-extension list, and script predicate.
#[derive(Clone)]
pub(crate) struct SiteFileCache {
    pub(crate) cache: Arc<FileCache>,
    pub(crate) server_id: u64,
    pub(crate) window_nanos: u64,
    /// `true` while [`crate::UNIDENTIFIED_CREDENTIAL`] is present in the server's `secret_files`;
    /// disables all file-cache hits and admissions on this server. Stored here rather than on
    /// `StaticServer` so cache-less servers never scan `secret_files`.
    pub(crate) has_unidentified_credential: bool,
    pub(crate) try_files_candidates: Option<Arc<[String]>>,
    pub(crate) try_files_uses_query_in_path: bool,
    pub(crate) try_files_script_extensions: Arc<[String]>,
    pub(crate) try_files_script_owner: Option<ScriptOwner>,
}

impl std::fmt::Debug for SiteFileCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SiteFileCache")
            .field("server_id", &self.server_id)
            .field("window_nanos", &self.window_nanos)
            .field(
                "has_unidentified_credential",
                &self.has_unidentified_credential,
            )
            .field("try_files_candidates", &self.try_files_candidates)
            .field(
                "try_files_uses_query_in_path",
                &self.try_files_uses_query_in_path,
            )
            .field(
                "try_files_script_extensions",
                &self.try_files_script_extensions,
            )
            .field(
                "has_try_files_script_owner",
                &self.try_files_script_owner.is_some(),
            )
            .finish_non_exhaustive()
    }
}

impl SiteFileCache {
    pub(crate) fn new(
        cache: Arc<FileCache>,
        window: Duration,
        has_unidentified_credential: bool,
    ) -> Self {
        Self {
            cache,
            server_id: next_server_id(),
            window_nanos: duration_to_nanos(window),
            has_unidentified_credential,
            try_files_candidates: None,
            try_files_uses_query_in_path: false,
            try_files_script_extensions: Arc::from(Vec::new()),
            try_files_script_owner: None,
        }
    }

    pub(crate) fn refresh_namespace_id(&mut self) {
        self.server_id = next_server_id();
    }

    pub(crate) fn with_try_files_candidates(mut self, candidates: Vec<String>) -> Self {
        self.server_id = next_server_id();
        self.try_files_uses_query_in_path = candidates.iter().any(|tpl| {
            let tpl_path = tpl.split_once('?').map_or(tpl.as_str(), |(p, _)| p);
            tpl_path.contains("{query}")
        });
        self.try_files_candidates = Some(Arc::from(candidates));
        self
    }

    pub(crate) fn with_try_files_script_extensions(mut self, extensions: Vec<String>) -> Self {
        self.server_id = next_server_id();
        self.try_files_script_extensions = Arc::from(extensions);
        self
    }

    pub(crate) fn with_try_files_script_owner(mut self, runs_script: ScriptOwner) -> Self {
        self.server_id = next_server_id();
        self.try_files_script_owner = Some(runs_script);
        self
    }

    pub(crate) fn try_files_eligible(
        &self,
        candidates: &[String],
        script_extensions: &[String],
        runs_script: Option<&ScriptOwner>,
    ) -> bool {
        let candidates_ok = !self.try_files_uses_query_in_path
            && self
                .try_files_candidates
                .as_deref()
                .is_some_and(|bound| bound == candidates);
        if !candidates_ok {
            return false;
        }
        if &*self.try_files_script_extensions != script_extensions {
            return false;
        }
        match (&self.try_files_script_owner, runs_script) {
            (None, None) => true,
            (Some(bound), Some(actual)) => Arc::ptr_eq(bound, actual),
            _ => false,
        }
    }

    pub(crate) fn owns_fill_start(&self, start: FillStart) -> bool {
        self.cache.owns_fill_start(start)
    }

    pub(crate) const fn deadline_from(&self, lookup_started_nanos: u64) -> u64 {
        lookup_started_nanos.saturating_add(self.window_nanos)
    }

    pub(crate) fn sample_fill_start(&self) -> FillStart {
        self.cache.sample_fill_start()
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use std::sync::Barrier;

    fn sample_admit_params(
        server_id: u64,
        path: &str,
        expires_at_nanos: u64,
        body: Bytes,
    ) -> AdmitParams<'_> {
        AdmitParams {
            server_id,
            kind: LookupKind::Direct,
            enc_mask: 0,
            path,
            expires_at_nanos,
            cred_epoch: current_credential_epoch(),
            content_type: HeaderValue::from_static("text/plain; charset=utf-8"),
            content_len: body.len() as u64,
            etag: Some(HeaderValue::from_static("\"etag-1\"")),
            modified: None,
            last_modified: Some(HeaderValue::from_static("Tue, 14 Nov 2023 22:13:20 GMT")),
            encoding: None,
            fallback_candidate_path: None,
            body,
        }
    }

    /// P1-2: Clock must be sampled WHILE holding the shard lock on both the read-lock path
    /// and the expired-entry/replacement write-lock path.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn p1_2_clock_sampled_under_shard_lock_for_read_and_replacement() {
        let _epoch_guard = crate::CRED_EPOCH_TEST_LOCK.blocking_read();
        let clock = ManualClock::new();
        let budget = Arc::new(FileCacheBudget::new(1024 * 1024));
        let counters = FileCacheCounters::new();
        let cache = FileCache::with_clock(budget, counters, clock.cache_clock());
        let server_id = next_server_id();
        let path = "/lock-wait.txt";

        // Admit entry expiring at t = 100ms.
        let _ = cache.admit(sample_admit_params(
            server_id,
            path,
            duration_to_nanos(Duration::from_millis(100)),
            Bytes::from_static(b"entry-v1"),
        ));
        assert_eq!(cache.entry_count(), 1);

        // Part 1: Reader waits behind a shard write lock at t=99ms; writer advances clock to
        // t=101ms before releasing. Because `now` is sampled AFTER acquiring the read lock,
        // the reader must see the entry as expired and return None.
        clock.advance(Duration::from_millis(99));
        let idx = cache.shard_index(server_id, LookupKind::Direct, 0, path);
        let Some(shard) = cache.shards.get(idx) else {
            return;
        };

        let reached_hook = Arc::new(Barrier::new(2));
        let hook_bar = Arc::clone(&reached_hook);
        {
            let mut h = cache
                .hooks
                .before_read_lock
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *h = Some(Arc::new(move || {
                hook_bar.wait();
            }));
        }

        let write_guard = shard
            .entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let cache_reader = Arc::clone(&cache);
        let reader = std::thread::spawn(move || {
            cache_reader.get_if_fresh(server_id, LookupKind::Direct, 0, path)
        });

        // Wait until reader is about to block on `shard.entries.read()`.
        reached_hook.wait();
        // Give reader a brief yield to enter the lock wait, then advance past deadline before unlock.
        std::thread::yield_now();
        clock.advance(Duration::from_millis(2)); // t = 101ms > 100ms
        drop(write_guard);

        let res = reader.join().ok().flatten();
        assert!(
            res.is_none(),
            "P1-2: reader waiting past deadline behind shard lock must NOT receive expired entry"
        );
        assert_eq!(cache.entry_count(), 0);

        // Clear read hook for Part 2.
        {
            let mut h = cache
                .hooks
                .before_read_lock
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *h = None;
        }

        // Part 2: Expired-entry -> write-lock replacement path.
        // Insert entry A expiring at t = 200ms (clock currently at 101ms).
        let _ = cache.admit(sample_admit_params(
            server_id,
            path,
            duration_to_nanos(Duration::from_millis(200)),
            Bytes::from_static(b"entry-A"),
        ));
        // Advance clock to exactly 200ms (A is expired).
        clock.advance(Duration::from_millis(99));

        let at_write_hook = Arc::new(Barrier::new(2));
        let allow_write_proceed = Arc::new(Barrier::new(2));
        let b1 = Arc::clone(&at_write_hook);
        let b2 = Arc::clone(&allow_write_proceed);
        {
            let mut h = cache
                .hooks
                .before_write_lock
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *h = Some(Arc::new(move || {
                b1.wait();
                b2.wait();
            }));
        }

        let cache_reader2 = Arc::clone(&cache);
        let reader2 = std::thread::spawn(move || {
            cache_reader2.get_if_fresh(server_id, LookupKind::Direct, 0, path)
        });

        // Reader2 saw A expired at t=200ms and paused right before acquiring the write lock.
        at_write_hook.wait();

        // While reader2 waits, insert replacement entry B expiring at t=205ms, then advance
        // clock to t=210ms so B is ALSO expired before reader2 acquires the write lock!
        let _ = cache.admit(sample_admit_params(
            server_id,
            path,
            duration_to_nanos(Duration::from_millis(205)),
            Bytes::from_static(b"entry-B"),
        ));
        assert_eq!(cache.entry_count(), 1);
        clock.advance(Duration::from_millis(10)); // t = 210ms > 205ms

        allow_write_proceed.wait();
        let res2 = reader2.join().ok().flatten();
        assert!(
            res2.is_none(),
            "P1-2: expired-entry write-lock path must re-sample clock and reject expired replacement"
        );
        assert_eq!(
            cache.entry_count(),
            0,
            "expired replacement must be evicted under write lock"
        );
    }

    /// P1-5 & P2-b: Admitted buffer has exact capacity == len (dropping encoder spare capacity)
    /// and budget charges real sizes for body, owner, entry, key, headers, and map growth,
    /// returning to exact 0 once swept.
    #[test]
    fn p1_5_exact_capacity_copy_and_p2_b_real_accounting_with_map_growth() {
        let _epoch_guard = crate::CRED_EPOCH_TEST_LOCK.blocking_read();
        let clock = ManualClock::new();
        let budget = Arc::new(FileCacheBudget::new(1024 * 1024));
        let counters = FileCacheCounters::new();
        let cache = FileCache::with_clock(Arc::clone(&budget), counters, clock.cache_clock());
        let server_id = next_server_id();

        // Simulate Brotli/gzip encoder allocating 128 KiB capacity for a 96-byte compressed payload.
        let mut oversized = Vec::with_capacity(128 * 1024);
        oversized.extend_from_slice(&[b'x'; 96]);
        assert!(oversized.capacity() >= 128 * 1024);
        let input_bytes = Bytes::from(oversized);

        let path = "/compressed.css";
        let params = sample_admit_params(
            server_id,
            path,
            duration_to_nanos(Duration::from_secs(1)),
            input_bytes,
        );
        let expected_meta = entry_meta_bytes(
            path.len(),
            &params.content_type,
            params.etag.as_ref(),
            params.last_modified.as_ref(),
            None,
        );
        let expected_body = charged_body_bytes(96);
        let _ = cache.admit(params);

        let entry = cache.get_if_fresh(server_id, LookupKind::Direct, 0, path);
        let Some(entry) = entry else {
            assert_eq!(cache.entry_count(), 1);
            return;
        };
        assert_eq!(entry.body.len(), 96);
        assert_eq!(
            entry.body_capacity,
            entry.body.len(),
            "P1-5: cached buffer capacity must equal its length (not 128 KiB)"
        );

        let idx = cache.shard_index(server_id, LookupKind::Direct, 0, path);
        let map_cap = cache.shards.get(idx).map_or(0, |s| {
            s.entries
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .map
                .capacity()
        });
        let expected_table = map_table_bytes_for_buckets(map_bucket_count(map_cap));
        assert!(expected_table > 0, "first insert must charge map table");
        assert_eq!(
            budget.used_bytes(),
            expected_body + expected_meta + expected_table,
            "P1-5/P2-b: budget must equal exact body + owner + entry/key/headers + map table"
        );
        drop(entry);

        // Fill many distinct small files to trigger shard HashMap table growth, then expire and
        // sweep: map buckets must be charged while allocated and refunded on shrink_to_fit.
        for i in 0..200_u32 {
            let p = format!("/small-{i}.txt");
            let _ = cache.admit(sample_admit_params(
                server_id,
                &p,
                duration_to_nanos(Duration::from_secs(1)),
                Bytes::from_static(b"hi"),
            ));
        }
        assert_eq!(cache.entry_count(), 201);
        let total_table_bytes: usize = cache
            .shards
            .iter()
            .map(|s| {
                s.entries
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .reserved_table_bytes()
            })
            .sum();
        assert!(
            total_table_bytes > expected_table,
            "map growth across shards must be charged"
        );
        assert!(budget.used_bytes() > total_table_bytes);

        clock.advance(Duration::from_secs(1));
        assert_eq!(cache.sweep_expired(), 201);
        assert_eq!(cache.entry_count(), 0);
        assert_eq!(
            budget.used_bytes(),
            0,
            "sweeping empty shards must shrink maps and refund all table + entry + body bytes"
        );
    }

    /// P1-6: Lowering the budget ceiling between load and CAS (deterministic hook) must reject
    /// the reservation and leave `used_bytes == 0`; lowering to 0 disables admissions at once.
    #[test]
    fn p1_6_limit_lowered_between_load_and_cas_rejects_reservation_and_zero_disables_at_once() {
        let _epoch_guard = crate::CRED_EPOCH_TEST_LOCK.blocking_read();
        // Case 1: Limit lowered from 64 KiB to 1 KiB between load and CAS.
        let lowered_budget = Arc::new(FileCacheBudget::new(64 * 1024));
        let lower_trigger = Arc::clone(&lowered_budget);
        lowered_budget.set_before_cas_hook(Some(Arc::new(move || {
            lower_trigger.set_limit(1024);
        })));
        let res = lowered_budget.try_reserve(4096);
        assert!(
            res.is_none(),
            "P1-6: reservation must be rolled back when limit lowered between load and CAS"
        );
        assert_eq!(lowered_budget.used_bytes(), 0);

        // Case 2: Limit lowered to 0 between load and CAS.
        let zeroed_budget = Arc::new(FileCacheBudget::new(64 * 1024));
        let zero_trigger = Arc::clone(&zeroed_budget);
        zeroed_budget.set_before_cas_hook(Some(Arc::new(move || {
            zero_trigger.set_limit(0);
        })));
        let res2 = zeroed_budget.try_reserve(512);
        assert!(
            res2.is_none(),
            "P1-6: lowering limit to 0 between load and CAS must reject reservation"
        );
        assert_eq!(zeroed_budget.used_bytes(), 0);

        // Case 3: In-flight `admit` already reserved before `set_limit(0)` runs before shard lock.
        let clock = ManualClock::new();
        let admit_budget = Arc::new(FileCacheBudget::new(64 * 1024));
        let admit_counters = FileCacheCounters::new();
        let admit_cache = FileCache::with_clock(
            Arc::clone(&admit_budget),
            admit_counters.clone(),
            clock.cache_clock(),
        );
        let disable_trigger = Arc::clone(&admit_budget);
        {
            let mut h = admit_cache
                .hooks
                .before_admit_lock
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *h = Some(Arc::new(move || {
                disable_trigger.set_limit(0);
            }));
        }
        let _ = admit_cache.admit(sample_admit_params(
            next_server_id(),
            "/zero-race.txt",
            duration_to_nanos(Duration::from_secs(5)),
            Bytes::from_static(b"payload"),
        ));
        assert_eq!(
            admit_cache.entry_count(),
            0,
            "P1-6: lowering limit to 0 must disable in-flight admission publication at once"
        );
        assert_eq!(admit_counters.fills(), 0);
        assert_eq!(admit_budget.used_bytes(), 0);
    }

    /// P1-7: Linux system clock must read `CLOCK_BOOTTIME` directly (counting suspended time).
    #[test]
    fn p1_7_system_clock_source_and_monotonic_boottime() {
        let _epoch_guard = crate::CRED_EPOCH_TEST_LOCK.blocking_read();
        #[cfg(target_os = "linux")]
        {
            assert_eq!(CacheClock::system_clock_source(), "CLOCK_BOOTTIME");
            let read_bt = || -> u64 {
                let ts = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
                let secs = u128::try_from(ts.tv_sec).unwrap_or(0);
                let nanos = u128::try_from(ts.tv_nsec).unwrap_or(0);
                u64::try_from(secs.saturating_mul(1_000_000_000).saturating_add(nanos))
                    .unwrap_or(u64::MAX)
            };
            let before = read_bt();
            let got = CacheClock::System.now_nanos();
            let after = read_bt();
            assert!(
                got >= before && got <= after,
                "P1-7: Linux CacheClock::System must report CLOCK_BOOTTIME nanos (before={before}, got={got}, after={after})"
            );
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(CacheClock::system_clock_source(), "std::time::Instant");
            let t1 = CacheClock::System.now_nanos();
            let t2 = CacheClock::System.now_nanos();
            assert!(t2 >= t1);
        }
    }

    /// P2-a: Under budget pressure a requesting worker inspects at most 1 shard and at most
    /// `PRESSURE_SWEEP_MAX_ENTRIES` entries (never all 64 shards), and striped counters sum
    /// accurately across threads.
    #[test]
    fn p2_a_bounded_pressure_work_and_striped_counters() {
        let _epoch_guard = crate::CRED_EPOCH_TEST_LOCK.blocking_read();
        let clock = ManualClock::new();
        let budget = Arc::new(FileCacheBudget::new(4 * 1024 * 1024));
        let counters = FileCacheCounters::new();
        let cache =
            FileCache::with_clock(Arc::clone(&budget), counters.clone(), clock.cache_clock());
        let server_id = next_server_id();

        // Populate all 64 shards with > PRESSURE_SWEEP_MAX_ENTRIES live entries across shards
        // (including >= 48 entries in at least one shard).
        for i in 0..2_500_u32 {
            let p = format!("/live-{i}.txt");
            let _ = cache.admit(sample_admit_params(
                server_id,
                &p,
                duration_to_nanos(Duration::from_secs(60)),
                Bytes::from(vec![b'a'; 128]),
            ));
        }
        assert!(cache.entry_count() >= 2_000);
        // Clamp budget right at current usage so the next admit hits full budget pressure.
        budget.set_limit(budget.used_bytes());

        cache
            .hooks
            .pressure_shards_visited
            .store(0, Ordering::Relaxed);
        cache
            .hooks
            .pressure_entries_examined
            .store(0, Ordering::Relaxed);

        let _ = cache.admit(sample_admit_params(
            server_id,
            "/pressure-trigger.txt",
            duration_to_nanos(Duration::from_secs(60)),
            Bytes::from(vec![b'b'; 256]),
        ));

        let shards_visited = cache.hooks.pressure_shards_visited.load(Ordering::Relaxed);
        let entries_examined = cache
            .hooks
            .pressure_entries_examined
            .load(Ordering::Relaxed);
        assert_eq!(
            shards_visited, 1,
            "P2-a: pressure sweep must visit at most 1 shard (never all 64)"
        );
        assert!(
            entries_examined <= PRESSURE_SWEEP_MAX_ENTRIES,
            "P2-a: pressure sweep examined {entries_examined} > {PRESSURE_SWEEP_MAX_ENTRIES}"
        );
        assert_eq!(counters.not_cached_budget(), 1);

        // Multi-threaded striped counter summation.
        let mt_counters = FileCacheCounters::new();
        let mut threads = Vec::new();
        for _ in 0..8 {
            let c = mt_counters.clone();
            threads.push(std::thread::spawn(move || {
                for _ in 0..250 {
                    c.record_hit();
                    c.record_miss();
                }
            }));
        }
        for t in threads {
            let _ = t.join();
        }
        assert_eq!(mt_counters.hits(), 2_000);
        assert_eq!(mt_counters.misses(), 2_000);
    }

    /// Helper: generate `count` distinct paths that all hash into `target_shard`.
    fn paths_for_shard(
        cache: &FileCache,
        server_id: u64,
        target_shard: usize,
        prefix: &str,
        count: usize,
    ) -> Vec<String> {
        let mut out = Vec::with_capacity(count);
        let mut n = 0_u64;
        while out.len() < count {
            let p = format!("/{prefix}-{n}.txt");
            if cache.shard_index(server_id, LookupKind::Direct, 0, &p) == target_shard {
                out.push(p);
            }
            n = n.saturating_add(1);
        }
        out
    }

    /// P2-a: One request examines at most 32 entries in TOTAL across the reservation retry
    /// (shard A) AND the full destination shard (shard B).
    #[test]
    #[allow(clippy::too_many_lines)]
    fn p2_a_total_entries_examined_across_retry_and_destination_shard_at_most_32() {
        let _epoch_guard = crate::CRED_EPOCH_TEST_LOCK.blocking_read();
        let clock = ManualClock::new();
        let budget = Arc::new(FileCacheBudget::new(8 * 1024 * 1024));
        let counters = FileCacheCounters::new();
        let cache =
            FileCache::with_clock(Arc::clone(&budget), counters.clone(), clock.cache_clock());
        let server_id = next_server_id();

        let shard_a = 0_usize;
        let shard_b = 1_usize;

        // Fill shard A with 40 entries: 10 short-lived (10ms) + 30 long-lived (60s) so
        // `sweep_pressure_one_shard` examines 32 entries, reclaims enough expired bytes for the
        // retry reservation to succeed, and uses up the request's entire 32-entry budget.
        let paths_a = paths_for_shard(&cache, server_id, shard_a, "a", 40);
        for (i, p) in paths_a.iter().enumerate() {
            let exp = if i < 10 {
                duration_to_nanos(Duration::from_millis(10))
            } else {
                duration_to_nanos(Duration::from_secs(60))
            };
            let _ = cache.admit(sample_admit_params(
                server_id,
                p,
                exp,
                Bytes::from(vec![b'a'; 1024]),
            ));
        }

        // Fill destination shard B to MAX_ENTRIES_PER_SHARD (256) with 256 live entries.
        let paths_b = paths_for_shard(&cache, server_id, shard_b, "b", MAX_ENTRIES_PER_SHARD + 1);
        for p in paths_b.iter().take(MAX_ENTRIES_PER_SHARD) {
            let _ = cache.admit(sample_admit_params(
                server_id,
                p,
                duration_to_nanos(Duration::from_secs(60)),
                Bytes::from(vec![b'b'; 64]),
            ));
        }
        assert_eq!(
            cache
                .shards
                .get(shard_a)
                .map_or(0, |s| s.len.load(Ordering::Relaxed)),
            40
        );
        assert_eq!(
            cache
                .shards
                .get(shard_b)
                .map_or(0, |s| s.len.load(Ordering::Relaxed)),
            MAX_ENTRIES_PER_SHARD
        );

        // Expire shard A's 10 short-lived entries, clamp budget so initial reservation fails and
        // points `sweep_cursor` directly at shard A.
        clock.advance(Duration::from_millis(20));
        budget.set_limit(budget.used_bytes());
        cache.sweep_cursor.store(shard_a, Ordering::Relaxed);
        cache
            .hooks
            .pressure_entries_examined
            .store(0, Ordering::Relaxed);

        let Some(trigger_b) = paths_b.get(MAX_ENTRIES_PER_SHARD) else {
            return;
        };
        let _ = cache.admit(sample_admit_params(
            server_id,
            trigger_b,
            duration_to_nanos(Duration::from_secs(60)),
            Bytes::from(vec![b'c'; 256]),
        ));
        let examined_case1 = cache
            .hooks
            .pressure_entries_examined
            .load(Ordering::Relaxed);
        assert!(
            examined_case1 <= PRESSURE_SWEEP_MAX_ENTRIES,
            "P2-a case 1: total entries examined across retry + full dest shard was {examined_case1} > {PRESSURE_SWEEP_MAX_ENTRIES}"
        );

        // Case 2: Partial budget used in shard A (20 entries in shard A), remainder (12) in
        // full destination shard B -> combined total still <= 32!
        let clock2 = ManualClock::new();
        let budget2 = Arc::new(FileCacheBudget::new(8 * 1024 * 1024));
        let counters2 = FileCacheCounters::new();
        let cache2 = FileCache::with_clock(Arc::clone(&budget2), counters2, clock2.cache_clock());
        let paths_a2 = paths_for_shard(&cache2, server_id, shard_a, "a2", 20);
        for (i, p) in paths_a2.iter().enumerate() {
            let exp = if i < 5 {
                duration_to_nanos(Duration::from_millis(10))
            } else {
                duration_to_nanos(Duration::from_secs(60))
            };
            let _ = cache2.admit(sample_admit_params(
                server_id,
                p,
                exp,
                Bytes::from(vec![b'a'; 1024]),
            ));
        }
        let paths_b2 =
            paths_for_shard(&cache2, server_id, shard_b, "b2", MAX_ENTRIES_PER_SHARD + 1);
        for p in paths_b2.iter().take(MAX_ENTRIES_PER_SHARD) {
            let _ = cache2.admit(sample_admit_params(
                server_id,
                p,
                duration_to_nanos(Duration::from_secs(60)),
                Bytes::from(vec![b'b'; 64]),
            ));
        }
        clock2.advance(Duration::from_millis(20));
        budget2.set_limit(budget2.used_bytes());
        cache2.sweep_cursor.store(shard_a, Ordering::Relaxed);
        cache2
            .hooks
            .pressure_entries_examined
            .store(0, Ordering::Relaxed);

        let Some(trigger_b2) = paths_b2.get(MAX_ENTRIES_PER_SHARD) else {
            return;
        };
        let _ = cache2.admit(sample_admit_params(
            server_id,
            trigger_b2,
            duration_to_nanos(Duration::from_secs(60)),
            Bytes::from(vec![b'c'; 256]),
        ));
        let examined_case2 = cache2
            .hooks
            .pressure_entries_examined
            .load(Ordering::Relaxed);
        assert_eq!(
            examined_case2, PRESSURE_SWEEP_MAX_ENTRIES,
            "P2-a case 2: 20 entries in shard A + 12 remaining in shard B must cap at exactly 32"
        );
    }

    /// P2-b: Conservative table accounting:
    /// 1. During growth, the FULL new table must be reserved before inserting (while old table
    ///    stays reserved), and the old table is released only after inserting.
    /// 2. If the entry or table-share reservation fails, the entry is NOT inserted.
    /// 3. Deletions (tombstones lowering `capacity()`) NEVER refund table bytes until the shard
    ///    becomes empty and drops its backing table.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn p2_b_conservative_table_growth_peak_no_tombstone_refund_and_fail_closed_insert() {
        let _epoch_guard = crate::CRED_EPOCH_TEST_LOCK.blocking_read();
        // Part 3 needs deletions that leave tombstones behind and lower `HashMap::capacity()`
        // far enough to compute fewer buckets. Whether a removal leaves a tombstone depends on
        // where the randomly seeded hasher put the keys (and on the group width of the
        // platform: it failed about one run in three on x86-64), so the scenario is built
        // again, with a fresh cache and so a fresh seed, until it has that shape.
        let mut exercised = false;
        for _attempt in 0..64 {
            let clock = ManualClock::new();
            let budget = Arc::new(FileCacheBudget::new(4 * 1024 * 1024));
            let counters = FileCacheCounters::new();
            let cache =
                FileCache::with_clock(Arc::clone(&budget), counters.clone(), clock.cache_clock());
            let server_id = next_server_id();
            let shard_idx = 0_usize;

            let paths = paths_for_shard(&cache, server_id, shard_idx, "tbl", 32);

            // 1. Insert the first entry into an empty shard; test failing table reservation refuses
            //    insertion even when the entry itself fits!
            let p0 = paths.first().map_or("/tbl-0.txt", String::as_str);
            let probe_params = sample_admit_params(
                server_id,
                p0,
                duration_to_nanos(Duration::from_secs(60)),
                Bytes::from_static(b"hello"),
            );
            let entry_only = charged_body_bytes(5)
                + entry_meta_bytes(
                    p0.len(),
                    &probe_params.content_type,
                    probe_params.etag.as_ref(),
                    probe_params.last_modified.as_ref(),
                    None,
                );
            let initial_table = map_table_bytes_for_buckets(initial_map_buckets());
            // Allow entry_only + (initial_table - 1): entry reserves, table fails -> MUST NOT insert.
            budget.set_limit(entry_only + initial_table - 1);
            let _ = cache.admit(probe_params);
            assert_eq!(
                cache.entry_count(),
                0,
                "P2-b: failed initial table reservation must NOT insert entry"
            );
            assert_eq!(budget.used_bytes(), 0);
            assert_eq!(counters.not_cached_budget(), 1);

            // 2. Now raise budget and fill the shard right up to `capacity()` (initial bucket array).
            budget.set_limit(4 * 1024 * 1024);
            let mut inserted = 0_usize;
            while let Some(p) = paths.get(inserted) {
                let _ = cache.admit(sample_admit_params(
                    server_id,
                    p,
                    duration_to_nanos(Duration::from_secs(60)),
                    Bytes::from_static(b"val"),
                ));
                inserted += 1;
                let (len, cap) = cache.shards.get(shard_idx).map_or((0, 0), |s| {
                    let g = s
                        .entries
                        .read()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    (g.map.len(), g.map.capacity())
                });
                if len == cap {
                    break;
                }
            }
            let (old_buckets, old_table_bytes) = cache.shards.get(shard_idx).map_or((0, 0), |s| {
                let g = s
                    .entries
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                (g.allocated_buckets, g.reserved_table_bytes())
            });
            assert_eq!(old_table_bytes, map_table_bytes_for_buckets(old_buckets));
            let next_buckets = old_buckets * 2;
            let full_new_table_bytes = map_table_bytes_for_buckets(next_buckets);
            let delta_only = full_new_table_bytes - old_table_bytes;

            // Next insert triggers table growth from `old_buckets` -> `next_buckets`.
            // Set limit so `used + next_entry + delta_only` WOULD fit, but `used + next_entry +
            // full_new_table_bytes` does NOT fit: conservative peak accounting MUST refuse to insert!
            let Some(p_grow) = paths.get(inserted) else {
                return;
            };
            let grow_params = sample_admit_params(
                server_id,
                p_grow,
                duration_to_nanos(Duration::from_secs(60)),
                Bytes::from_static(b"val"),
            );
            let grow_entry_bytes = charged_body_bytes(3)
                + entry_meta_bytes(
                    p_grow.len(),
                    &grow_params.content_type,
                    grow_params.etag.as_ref(),
                    grow_params.last_modified.as_ref(),
                    None,
                );
            let used_before_grow = budget.used_bytes();
            // Enough for entry + delta, NOT enough for entry + full new table alongside old table.
            budget.set_limit(
                used_before_grow + grow_entry_bytes + delta_only + (old_table_bytes - 1),
            );
            let _ = cache.admit(grow_params);
            assert_eq!(
                cache.entry_count(),
                inserted,
                "P2-b: growth must reserve FULL new table before insert (delta-only must be refused)"
            );
            assert_eq!(budget.used_bytes(), used_before_grow);
            assert!(counters.not_cached_budget() >= 2);

            // Raising limit by 1 byte lets `used + entry + full_new_table` fit: insert succeeds,
            // old table is released AFTER insert, so final used == used_before + entry + delta!
            budget.set_limit(used_before_grow + grow_entry_bytes + full_new_table_bytes);
            let _ = cache.admit(sample_admit_params(
                server_id,
                p_grow,
                duration_to_nanos(Duration::from_secs(60)),
                Bytes::from_static(b"val"),
            ));
            inserted += 1;
            assert_eq!(cache.entry_count(), inserted);
            assert_eq!(
                budget.used_bytes(),
                used_before_grow + grow_entry_bytes + delta_only,
                "P2-b: old table reservation must be released after growth completes"
            );

            // 3. Tombstone deletion non-refund: populate shard2 to 128 buckets (112 entries:
            //    96 short-lived + 16 long-lived so tombstones are guaranteed across both 8-byte and
            //    16-byte SIMD group widths), expire and lazily remove the 96 short-lived entries,
            //    assert that `map.capacity()` REALLY dropped (and `map_bucket_count(cap)` dropped
            //    below `allocated_buckets`), and verify table bytes are NEVER refunded on a subsequent
            //    insert until the shard becomes empty!
            budget.set_limit(4 * 1024 * 1024);
            let shard2 = 2_usize;
            let paths2 = paths_for_shard(&cache, server_id, shard2, "tomb", 120);
            for (i, p) in paths2.iter().take(112).enumerate() {
                let exp = if i < 96 {
                    duration_to_nanos(Duration::from_millis(50))
                } else {
                    duration_to_nanos(Duration::from_secs(60))
                };
                let _ = cache.admit(sample_admit_params(
                    server_id,
                    p,
                    exp,
                    Bytes::from_static(b"val"),
                ));
            }
            let (cap_before_deletes, buckets_before_deletes, table_before_deletes) =
                cache.shards.get(shard2).map_or((0, 0, 0), |s| {
                    let g = s
                        .entries
                        .read()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    (
                        g.map.capacity(),
                        g.allocated_buckets,
                        g.reserved_table_bytes(),
                    )
                });
            assert!(buckets_before_deletes >= 128);
            assert_eq!(
                table_before_deletes,
                map_table_bytes_for_buckets(buckets_before_deletes)
            );

            // Expire the 96 short-lived entries and lazily remove them via `get_if_fresh`.
            clock.advance(Duration::from_millis(60));
            for p in paths2.iter().take(96) {
                assert!(
                    cache
                        .get_if_fresh(server_id, LookupKind::Direct, 0, p)
                        .is_none()
                );
            }
            let cap_after_deletes = cache.shards.get(shard2).map_or(0, |s| {
                s.entries
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .map
                    .capacity()
            });
            if cap_after_deletes >= cap_before_deletes
                || map_bucket_count(cap_after_deletes) >= buckets_before_deletes
            {
                continue;
            }

            // Insert another entry into shard2: table bytes MUST NOT be refunded based on
            // tombstone-lowered `capacity()`.
            if let Some(p_extra) = paths2.get(115) {
                let _ = cache.admit(sample_admit_params(
                    server_id,
                    p_extra,
                    duration_to_nanos(Duration::from_secs(60)),
                    Bytes::from_static(b"val"),
                ));
            }
            let table_after_deletes = cache.shards.get(shard2).map_or(0, |s| {
                s.entries
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .reserved_table_bytes()
            });
            assert!(
                table_after_deletes >= table_before_deletes,
                "P2-b: deletions creating tombstones must NOT refund table bytes ({table_after_deletes} < {table_before_deletes})"
            );

            // Once all entries expire and are swept, shards become empty and release 100% of bytes.
            clock.advance(Duration::from_secs(60));
            let _ = cache.sweep_expired();
            assert_eq!(cache.entry_count(), 0);
            assert_eq!(budget.used_bytes(), 0);
            exercised = true;
            break;
        }
        assert!(
            exercised,
            "P2-b: 64 fresh caches never produced tombstones that lower the computed bucket count"
        );
    }

    /// Review round 3, P2-a: Replacing an existing expired key at a 100% full shard table
    /// (`len == capacity`) MUST update the slot in place (`get_mut`) and NEVER grow the table or
    /// charge unaccounted growth.
    ///
    /// Reproduces Codex's exact two-GET race on a 100 ms site:
    /// - GET A starts at 0 ms (deadline 100 ms), GET B starts at 50 ms (deadline 150 ms).
    /// - GET A inserts at 60 ms and takes the last available slot (`len == capacity`).
    /// - GET B reaches admission at 110 ms (past A's deadline, before B's deadline).
    ///
    /// On `6d068dd`, `HashMap::insert` reserved a slot before checking for replacement and
    /// doubled `capacity()` without reserving the new table; in-place `get_mut` keeps `capacity()`
    /// and `allocated_buckets` strictly unchanged.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn p2_a_r3_replacing_expired_key_at_full_table_never_grows_table() -> Result<(), String> {
        let _epoch_guard = crate::CRED_EPOCH_TEST_LOCK.blocking_read();
        let clock = ManualClock::new();
        let budget = Arc::new(FileCacheBudget::new(4 * 1024 * 1024));
        let counters = FileCacheCounters::new();
        let cache =
            FileCache::with_clock(Arc::clone(&budget), counters.clone(), clock.cache_clock());
        let server_id = next_server_id();
        let shard_idx = 0_usize;

        let paths = paths_for_shard(&cache, server_id, shard_idx, "replace-full", 32);

        // Fill shard 0 until ONE slot remains before the table is full (with `cap >= 7`, i.e.,
        // >= 8 buckets, so the table is already non-trivial).
        let mut inserted = 0_usize;
        let mut reached_near_full = false;
        for p in &paths {
            let _ = cache.admit(sample_admit_params(
                server_id,
                p,
                duration_to_nanos(Duration::from_secs(60)),
                Bytes::from_static(b"filler"),
            ));
            inserted += 1;
            let (len, cap) = cache.shards.get(shard_idx).map_or((0, 0), |s| {
                let g = s
                    .entries
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                (g.map.len(), g.map.capacity())
            });
            if cap >= 7 && len + 1 == cap {
                reached_near_full = true;
                break;
            }
        }
        if !reached_near_full {
            return Err(format!(
                "setup did not reach a near-full shard table after inserting {inserted} entries"
            ));
        }
        let Some(target_path) = paths.get(inserted) else {
            return Err(format!(
                "exhausted {inserted}/{} setup paths before choosing replacement key",
                paths.len()
            ));
        };

        // GET A starts at t = 0 ms -> deadline = 100 ms.
        let exp_a = clock.now_nanos() + duration_to_nanos(Duration::from_millis(100));
        // GET B starts at t = 50 ms -> deadline = 150 ms.
        clock.advance(Duration::from_millis(50));
        let exp_b = clock.now_nanos() + duration_to_nanos(Duration::from_millis(100));

        // GET A admits at t = 60 ms, taking the VERY LAST slot (`len == capacity`).
        clock.advance(Duration::from_millis(10));
        let _ = cache.admit(sample_admit_params(
            server_id,
            target_path,
            exp_a,
            Bytes::from_static(b"from-A"),
        ));
        inserted += 1;

        let (len_full, cap_full, buckets_full, table_bytes_full) =
            cache.shards.get(shard_idx).map_or((0, 0, 0, 0), |s| {
                let g = s
                    .entries
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                (
                    g.map.len(),
                    g.map.capacity(),
                    g.allocated_buckets,
                    g.reserved_table_bytes(),
                )
            });
        assert_eq!(len_full, inserted);
        assert_eq!(
            len_full, cap_full,
            "precondition: shard table must be 100% full before expired-key replacement"
        );
        let used_before = budget.used_bytes();
        let fills_before = counters.fills();

        // Advance to t = 110 ms (past A's 100 ms deadline, still before B's 150 ms deadline).
        clock.advance(Duration::from_millis(50));

        // Case 1: With ample budget (so `HashMap::insert` on 6d068dd WOULD have silently doubled
        // the table), replacing the expired key MUST keep `capacity()` and `allocated_buckets`
        // strictly unchanged!
        let _ = cache.admit(sample_admit_params(
            server_id,
            target_path,
            exp_b,
            Bytes::from_static(b"from-B"),
        ));
        let (len_after1, cap_after1, buckets_after1, table_bytes_after1) =
            cache.shards.get(shard_idx).map_or((0, 0, 0, 0), |s| {
                let g = s
                    .entries
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                (
                    g.map.len(),
                    g.map.capacity(),
                    g.allocated_buckets,
                    g.reserved_table_bytes(),
                )
            });
        assert_eq!(counters.fills(), fills_before + 1);
        assert_eq!(len_after1, len_full);
        assert_eq!(
            cap_after1, cap_full,
            "P2-a: replacing an expired key at a full table MUST NOT grow HashMap::capacity() \
             (before={cap_full}, after={cap_after1})"
        );
        assert_eq!(buckets_after1, buckets_full);
        assert_eq!(table_bytes_after1, table_bytes_full);
        assert_eq!(budget.used_bytes(), used_before);
        let got_b = cache.get_if_fresh(server_id, LookupKind::Direct, 0, target_path);
        assert_eq!(
            got_b.as_ref().map(|e| e.body.as_ref()),
            Some(b"from-B".as_slice())
        );
        drop(got_b);

        // Case 2: Tight budget leaving room ONLY for the replacement entry (`body + meta`) and
        // ZERO bytes for table growth: expired replacement at the same full table STILL succeeds
        // in place and keeps `capacity()` and `used_bytes()` exact!
        let params_c = sample_admit_params(
            server_id,
            target_path,
            clock.now_nanos() + duration_to_nanos(Duration::from_millis(200)),
            Bytes::from_static(b"from-C"),
        );
        let c_entry_bytes = charged_body_bytes(6)
            + entry_meta_bytes(
                target_path.len(),
                &params_c.content_type,
                params_c.etag.as_ref(),
                params_c.last_modified.as_ref(),
                None,
            );
        clock.advance(Duration::from_millis(50)); // t = 160 ms > exp_b (150 ms)
        budget.set_limit(used_before + c_entry_bytes);
        let _ = cache.admit(params_c);

        let (len_after2, cap_after2, buckets_after2, table_bytes_after2) =
            cache.shards.get(shard_idx).map_or((0, 0, 0, 0), |s| {
                let g = s
                    .entries
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                (
                    g.map.len(),
                    g.map.capacity(),
                    g.allocated_buckets,
                    g.reserved_table_bytes(),
                )
            });
        assert_eq!(counters.fills(), fills_before + 2);
        assert_eq!(len_after2, len_full);
        assert_eq!(cap_after2, cap_full);
        assert_eq!(buckets_after2, buckets_full);
        assert_eq!(table_bytes_after2, table_bytes_full);
        assert_eq!(budget.used_bytes(), used_before);
        let got_c = cache.get_if_fresh(server_id, LookupKind::Direct, 0, target_path);
        assert_eq!(
            got_c.as_ref().map(|e| e.body.as_ref()),
            Some(b"from-C".as_slice())
        );
        drop(got_c);

        // Clean expiry releases 100% of bytes.
        clock.advance(Duration::from_secs(120));
        let _ = cache.sweep_expired();
        assert_eq!(cache.entry_count(), 0);
        assert_eq!(budget.used_bytes(), 0);
        Ok(())
    }

    /// Review round 1, Item 5 (P2): background sweeper must run on the shared runtime even when
    /// the very first cache admission happens on a dedicated worker event loop thread, and must
    /// refuse to spawn onto a worker loop if no shared runtime handle was captured.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn r1_item5_sweeper_placement_off_worker_loop_and_bounded_tick()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::atomic::AtomicBool;
        use std::thread::ThreadId;

        let _cred_lock = crate::PUBLISHED_TEST_LOCK.blocking_read();

        // 1. Construct `FileCache` (system clock) on a multi-thread shared runtime, then perform
        //    the FIRST admission from a separate worker loop OS thread (`current_thread` runtime +
        //    `enter_worker_loop_thread()`): the sweeper MUST spawn onto the shared runtime!
        let shared_rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let cache = shared_rt.block_on(async {
            FileCache::new(
                Arc::new(FileCacheBudget::new(4 * 1024 * 1024)),
                FileCacheCounters::new(),
            )
        });
        let (tx, rx) = std::sync::mpsc::channel::<(ThreadId, bool)>();
        let tx = Arc::new(std::sync::Mutex::new(Some(tx)));
        *cache
            .hooks
            .on_sweeper_start
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(move || {
            let is_worker = crate::is_worker_loop_thread();
            let tid = std::thread::current().id();
            if let Some(sender) = tx
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                let _ = sender.send((tid, is_worker));
            }
        }));

        let cache_for_worker = Arc::clone(&cache);
        let worker_tid = std::thread::spawn(move || -> Result<ThreadId, String> {
            let worker_rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            let _worker_guard = crate::enter_worker_loop_thread();
            let tid = std::thread::current().id();
            worker_rt.block_on(async {
                let exp = cache_for_worker
                    .now_nanos()
                    .saturating_add(duration_to_nanos(Duration::from_secs(60)));
                let _ = cache_for_worker.admit(sample_admit_params(
                    next_server_id(),
                    "/first-on-worker.txt",
                    exp,
                    Bytes::from_static(b"hello-worker"),
                ));
            });
            Ok(tid)
        })
        .join()
        .map_err(|_| "worker admission thread panicked")??;

        let (sweeper_tid, sweeper_on_worker) = rx
            .recv_timeout(Duration::from_secs(2))
            .map_err(|_| "sweeper did not start on shared runtime within 2s")?;
        assert!(
            !sweeper_on_worker,
            "file-cache sweeper must never run on a worker loop thread"
        );
        assert_ne!(
            sweeper_tid, worker_tid,
            "file-cache sweeper must run on the shared runtime, not the admitting worker loop thread"
        );
        drop(cache);
        shared_rt.shutdown_timeout(Duration::from_secs(2));

        // 2. Construct `FileCache` outside any runtime (`sweeper_handle == None`) and admit from a
        //    worker loop thread -> refuses to spawn the sweeper onto the worker loop!
        let detached_cache = FileCache::new(
            Arc::new(FileCacheBudget::new(4 * 1024 * 1024)),
            FileCacheCounters::new(),
        );
        let started_on_worker = Arc::new(AtomicBool::new(false));
        let started_flag = Arc::clone(&started_on_worker);
        *detached_cache
            .hooks
            .on_sweeper_start
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(move || {
            started_flag.store(true, Ordering::SeqCst);
        }));
        let detached_for_worker = Arc::clone(&detached_cache);
        std::thread::spawn(move || -> Result<(), String> {
            let worker_rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            let _worker_guard = crate::enter_worker_loop_thread();
            worker_rt.block_on(async {
                let exp = detached_for_worker
                    .now_nanos()
                    .saturating_add(duration_to_nanos(Duration::from_secs(60)));
                let _ = detached_for_worker.admit(sample_admit_params(
                    next_server_id(),
                    "/detached-worker.txt",
                    exp,
                    Bytes::from_static(b"no-worker-sweeper"),
                ));
                tokio::task::yield_now().await;
            });
            Ok(())
        })
        .join()
        .map_err(|_| "detached worker thread panicked")??;
        assert!(
            !detached_cache.sweeper_started.load(Ordering::Acquire),
            "sweeper must refuse to start on a worker loop when no shared runtime handle exists"
        );
        assert!(!started_on_worker.load(Ordering::SeqCst));

        // 3. Bounded work per background tick: populate 640 expired entries spread across shards
        //    and verify a single `sweep_background_tick` caps examined entries well below a full
        //    16-shard scan while rotating through all shards across consecutive ticks.
        let clock = ManualClock::new();
        let budget = Arc::new(FileCacheBudget::new(16 * 1024 * 1024));
        let cache_b = FileCache::with_clock(
            Arc::clone(&budget),
            FileCacheCounters::new(),
            clock.cache_clock(),
        );
        let sid = next_server_id();
        let exp = clock.now_nanos() + duration_to_nanos(Duration::from_secs(10));
        for i in 0..800_usize {
            let path = format!("/item-{i:04}.txt");
            let _ = cache_b.admit(sample_admit_params(
                sid,
                &path,
                exp,
                Bytes::from_static(b"payload"),
            ));
        }
        assert_eq!(cache_b.entry_count(), 800);
        clock.advance(Duration::from_secs(15));

        let (removed_first, examined_first) = cache_b.sweep_background_tick();
        assert!(examined_first > 0);
        assert!(
            examined_first < 800,
            "single background tick must be bounded instead of scanning the whole cache (examined={examined_first})"
        );
        assert!(
            examined_first <= BACKGROUND_SWEEP_MAX_ENTRIES_PER_TICK + MAX_ENTRIES_PER_SHARD,
            "single background tick examined {examined_first} entries exceeding bound"
        );
        assert_eq!(removed_first, examined_first);

        // Subsequent ticks advance the cursor and eventually reclaim 100% of expired entries.
        let mut total_removed = removed_first;
        for _ in 0..64 {
            let (r, _) = cache_b.sweep_background_tick();
            total_removed = total_removed.saturating_add(r);
            if cache_b.entry_count() == 0 {
                break;
            }
        }
        assert_eq!(total_removed, 800);
        assert_eq!(cache_b.entry_count(), 0);
        assert_eq!(budget.used_bytes(), 0);
        Ok(())
    }
}

//! Sharded, bounded-memory GCRA (Generic Cell Rate Algorithm) rate limiter.
//!
//! Uses per-instance keyed hashing (`RandomState`), fixed-width `u128` bucket digests,
//! IPv6 `/64` prefix masking, isolated verified-agent shard tables, and active-throttle
//! eviction protection to defend against memory amplification, shard-collision DoS, and
//! eviction-reset bypasses.

use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher as _, Hasher as _};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use http::HeaderMap;
use miraserve_config::{RateLimitConfig, RateLimitKey};

/// Number of independent lock shards for low-contention multi-core access.
const NUM_SHARDS: usize = 16;

/// Maximum tracked rate-limit keys per shard (`16 * 4096 = 65,536` total keys per table).
const MAX_KEYS_PER_SHARD: usize = 4_096;

/// Number of distinct IPv6 `/64` networks one `/48` may show inside [`PREFIX48_WINDOW_NS`] before
/// that `/48` is rate limited as a single client (`R7-RL-1`, `R8-RL-1`).
///
/// The decision is made per `/48`, from that `/48`'s own behaviour. One host that owns a `/48`
/// and rotates through its 65,536 `/64`s is collapsed after this many, so it cannot fill the
/// table or multiply a login limit; an unrelated `/48` (a campus, a company, an ISP pool) keeps
/// its per-`/64` buckets however busy the rest of the server is.
const PREFIX48_DISTINCT_LIMIT: usize = 128;

/// Sliding observation window for [`PREFIX48_DISTINCT_LIMIT`], and how long a `/48` stays
/// aggregated after it last exceeded the limit. Aggregation therefore ends by itself.
const PREFIX48_WINDOW_NS: u64 = 60_000_000_000;

/// Bound on tracked `/48` prefixes per shard (`16 * 256 = 4,096` prefixes, each remembering at
/// most [`PREFIX48_DISTINCT_LIMIT`] `/64` identifiers).
const MAX_TRACKED_PREFIX48_PER_SHARD: usize = 256;

/// Recent `/64` activity of one IPv6 `/48`.
#[derive(Debug, Default)]
struct Prefix48State {
    window_start_ns: u64,
    seen64: Vec<u64>,
    aggregated_until_ns: u64,
    last_seen_ns: u64,
}

/// Minimum interval between full expired-key sweeps per shard to prevent O(4096) CPU DoS.
const SWEEP_COOLDOWN_NS: u64 = 1_000_000_000;

/// Maximum entries sampled during bounded eviction lookup.
const EVICTION_SAMPLE_LIMIT: usize = 64;

/// Default per-IP ceiling multiplier applied unconditionally to `RateLimitKey::Header(_)` traffic
/// (`R4-RL-1` / `R5-RL-1`) so rotating header values across windows can never multiply quota
/// unboundedly while still permitting legitimate shared NAT / CDN / load-balancer tenants.
const DEFAULT_HEADER_IP_CEILING_MULTIPLIER: u32 = 10;

/// Default maximum distinct simultaneously-active header keys tracked per client IP (`R5-RL-1`).
const DEFAULT_MAX_ACTIVE_HEADER_KEYS_PER_IP: usize = 64;

/// Maximum IP entries retained per shard in the active-header-key tracker.
const MAX_IP_KEY_TRACKERS_PER_SHARD: usize = 1_024;

/// Decision returned by [`GcraRateLimiter::check_key`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitDecision {
    /// Whether the request is allowed.
    pub allowed: bool,
    /// Configured request limit per replenishment period.
    pub limit: u32,
    /// Approximate remaining burst requests available right now.
    pub remaining: u32,
    /// Seconds the client should wait before retrying (`0` if allowed).
    pub retry_after_secs: u64,
}

#[derive(Debug, Default)]
struct ShardState {
    entries: HashMap<u128, u64>,
    last_sweep_ns: u64,
}

/// Header bucket state retaining both GCRA theoretical arrival time (`tat_ns`), idle-retention
/// expiry (`idle_expires_ns`, `R5-RL-1`), and a fair-share virtual arrival time (`fair_tat_ns`,
/// `R6-RL-1`) enforced only when the shared IP's aggregate ceiling is congested.
#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_field_names)]
struct HeaderEntry {
    tat_ns: u64,
    idle_expires_ns: u64,
    fair_tat_ns: u64,
}

enum CeilingStatus {
    Uncongested,
    Congested,
    Exhausted(RateLimitDecision),
}

enum HeaderLookup {
    Throttled(RateLimitDecision),
    Active(HeaderEntry),
    MissingOrExpired,
}

#[derive(Debug, Default)]
struct HeaderShardState {
    entries: HashMap<u128, HeaderEntry>,
    last_sweep_ns: u64,
}

#[derive(Debug, Default)]
struct IpKeyTrackerShard {
    entries: HashMap<u128, Vec<(u128, u64)>>,
    last_sweep_ns: u64,
}

#[derive(Debug, Clone, Copy)]
struct GcraParams {
    emission_interval_ns: u64,
    delay_tolerance_ns: u64,
    limit: u32,
    burst: u32,
}

/// Sharded GCRA rate limiter backed by [`RateLimitConfig`].
#[derive(Debug)]
pub struct GcraRateLimiter {
    epoch: Instant,
    /// Primary bucket GCRA parameters.
    params: GcraParams,
    /// Unconditional larger per-IP ceiling parameters for `RateLimitKey::Header(_)` (`R4-RL-1`).
    ceiling_params: GcraParams,
    /// Idle retention duration (`cfg.per`) for recognized header keys (`R5-RL-1`).
    header_idle_ttl_ns: u64,
    /// Maximum distinct unexpired header keys permitted per client IP (`R5-RL-1`).
    max_active_header_keys_per_ip: usize,
    key_selector: RateLimitKey,
    /// Two independent per-instance randomized hash states producing a 128-bit keyed digest.
    hash_lo: RandomState,
    hash_hi: RandomState,
    /// Primary sharded table for IP / unauthenticated header-less fallback buckets.
    shards: [Mutex<ShardState>; NUM_SHARDS],
    /// Per-`/48` record of recently seen `/64` networks deciding IPv6 aggregation (`R8-RL-1`).
    prefix48_shards: [Mutex<HashMap<u64, Prefix48State>>; NUM_SHARDS],
    /// Dedicated isolated table for cryptographically verified `AgentId` principals so
    /// unauthenticated IP floods cannot evict verified agent buckets.
    agent_shards: [Mutex<ShardState>; NUM_SHARDS],
    /// Dedicated table for `RateLimitKey::Header(_)` buckets with idle retention (`R5-RL-1`).
    header_shards: Option<Box<[Mutex<HeaderShardState>; NUM_SHARDS]>>,
    /// Isolated per-IP admission table charged ONLY for brand-new or idle-expired header keys,
    /// separated from header-less fallback traffic in `shards` (`R5-RL-1`).
    new_key_admission_shards: Option<Box<[Mutex<ShardState>; NUM_SHARDS]>>,
    /// Unconditional per-IP ceiling table enforced on EVERY `RateLimitKey::Header(_)` request (`R4-RL-1`).
    ip_ceiling_shards: Option<Box<[Mutex<ShardState>; NUM_SHARDS]>>,
    /// Bounded per-IP active-header-key tracker capping distinct unexpired keys per IP atomically (`R5-RL-2`).
    ip_active_keys: Option<Box<[Mutex<IpKeyTrackerShard>; NUM_SHARDS]>>,
}

impl GcraRateLimiter {
    /// Creates a new [`GcraRateLimiter`] from a validated [`RateLimitConfig`].
    #[must_use]
    pub fn from_config(cfg: &RateLimitConfig) -> Self {
        let requests = cfg.requests.max(1);
        let burst = cfg.burst.max(1);
        let period_ns = u64::try_from(cfg.per.as_nanos()).unwrap_or(u64::MAX).max(1);
        let emission_interval_ns = (period_ns / u64::from(requests)).max(1);
        // Standard GCRA: burst B means B instantaneous arrivals are allowed, so tau = (B - 1) * T.
        let delay_tolerance_ns =
            emission_interval_ns.saturating_mul(u64::from(burst.saturating_sub(1)));

        let ceiling_mult = cfg
            .ip_ceiling_multiplier
            .unwrap_or(DEFAULT_HEADER_IP_CEILING_MULTIPLIER)
            .max(1);
        let max_active_header_keys_per_ip = cfg
            .max_keys_per_ip
            .map_or(DEFAULT_MAX_ACTIVE_HEADER_KEYS_PER_IP, |v| {
                usize::try_from(v.max(1)).unwrap_or(DEFAULT_MAX_ACTIVE_HEADER_KEYS_PER_IP)
            });

        let ceiling_limit = requests.saturating_mul(ceiling_mult);
        let ceiling_burst = burst.saturating_mul(ceiling_mult);
        let ceiling_emission_ns = (period_ns / u64::from(ceiling_limit.max(1))).max(1);
        let ceiling_delay_tol_ns =
            ceiling_emission_ns.saturating_mul(u64::from(ceiling_burst.saturating_sub(1)));

        let is_header = matches!(cfg.key, RateLimitKey::Header(_));
        let shards = std::array::from_fn(|_| Mutex::new(ShardState::default()));
        let agent_shards = std::array::from_fn(|_| Mutex::new(ShardState::default()));
        let header_shards = is_header.then(|| {
            Box::new(std::array::from_fn(|_| {
                Mutex::new(HeaderShardState::default())
            }))
        });
        let new_key_admission_shards =
            is_header.then(|| Box::new(std::array::from_fn(|_| Mutex::new(ShardState::default()))));
        let ip_ceiling_shards =
            is_header.then(|| Box::new(std::array::from_fn(|_| Mutex::new(ShardState::default()))));
        let ip_active_keys = is_header.then(|| {
            Box::new(std::array::from_fn(|_| {
                Mutex::new(IpKeyTrackerShard::default())
            }))
        });

        Self {
            epoch: Instant::now(),
            params: GcraParams {
                emission_interval_ns,
                delay_tolerance_ns,
                limit: requests,
                burst,
            },
            ceiling_params: GcraParams {
                emission_interval_ns: ceiling_emission_ns,
                delay_tolerance_ns: ceiling_delay_tol_ns,
                limit: ceiling_limit,
                burst: ceiling_burst,
            },
            header_idle_ttl_ns: period_ns,
            max_active_header_keys_per_ip,
            key_selector: cfg.key.clone(),
            hash_lo: RandomState::new(),
            hash_hi: RandomState::new(),
            shards,
            prefix48_shards: std::array::from_fn(|_| Mutex::new(HashMap::new())),
            agent_shards,
            header_shards,
            new_key_admission_shards,
            ip_ceiling_shards,
            ip_active_keys,
        }
    }

    /// Evaluates an incoming HTTP request using this limiter's configured [`RateLimitKey`].
    #[must_use]
    pub fn check_request(
        &self,
        client_ip: Option<IpAddr>,
        headers: &HeaderMap,
        verified_agent_id: Option<&str>,
    ) -> RateLimitDecision {
        self.check_request_at(client_ip, headers, verified_agent_id, Instant::now())
    }

    /// Deterministic clock variant of [`Self::check_request`] for testing.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn check_request_at(
        &self,
        client_ip: Option<IpAddr>,
        headers: &HeaderMap,
        verified_agent_id: Option<&str>,
        now: Instant,
    ) -> RateLimitDecision {
        if let RateLimitKey::Header(name) = &self.key_selector {
            let ip_digest = self.hash_ip(client_ip, now);
            if let (
                Some(header_table),
                Some(admission_table),
                Some(ceiling_table),
                Some(active_table),
                Some(hdr_digest),
            ) = (
                &self.header_shards,
                &self.new_key_admission_shards,
                &self.ip_ceiling_shards,
                &self.ip_active_keys,
                self.hash_header_opt(name, headers),
            ) {
                let now_ns = u64::try_from(now.saturating_duration_since(self.epoch).as_nanos())
                    .unwrap_or(u64::MAX);
                let idle_expires_ns = now_ns.saturating_add(self.header_idle_ttl_ns);

                // Layer 1 (R6-RL-1): Evaluate per-key state FIRST before touching the shared IP
                // ceiling or active-key LRU table so throttled keys NEVER drain the IP ceiling or
                // evict other users sharing the same NAT/CDN IP.
                match self.peek_existing_header_digest(header_table, hdr_digest, now_ns) {
                    HeaderLookup::Throttled(denied) => return denied,
                    HeaderLookup::Active(entry) => {
                        let active_keys =
                            Self::active_key_count_for_ip_digest(active_table, ip_digest, now_ns);
                        let fair_interval = self.fair_share_interval_ns(active_keys);
                        match self.inspect_ceiling(ceiling_table, ip_digest, now_ns) {
                            CeilingStatus::Exhausted(ceil_denied) => return ceil_denied,
                            CeilingStatus::Congested if now_ns < entry.fair_tat_ns => {
                                let wait_ns = entry.fair_tat_ns.saturating_sub(now_ns);
                                return RateLimitDecision {
                                    allowed: false,
                                    limit: self.params.limit,
                                    remaining: 0,
                                    retry_after_secs: wait_ns.div_ceil(1_000_000_000).max(1),
                                };
                            }
                            CeilingStatus::Uncongested | CeilingStatus::Congested => {}
                        }
                        // Commit per-key GCRA first; only charge the shared IP ceiling if the
                        // per-key bucket actually admits this request (`R6-RL-1`).
                        let Some(existing_decision) = self.commit_existing_header_digest(
                            header_table,
                            hdr_digest,
                            now_ns,
                            idle_expires_ns,
                            fair_interval,
                        ) else {
                            // Entry expired between peek and commit; fall through to new-key path.
                            return self.admit_new_header_key(
                                header_table,
                                admission_table,
                                ceiling_table,
                                active_table,
                                ip_digest,
                                hdr_digest,
                                now,
                                now_ns,
                                idle_expires_ns,
                            );
                        };
                        if !existing_decision.allowed {
                            return existing_decision;
                        }
                        let (ceil_dec, _) = self.check_digest_in_table_with_params(
                            ceiling_table,
                            ip_digest,
                            now,
                            self.ceiling_params,
                        );
                        if !ceil_dec.allowed {
                            return ceil_dec;
                        }
                        let (_, evicted) = self.claim_or_evict_ip_active_key(
                            active_table,
                            ip_digest,
                            hdr_digest,
                            idle_expires_ns,
                            now_ns,
                        );
                        if let Some(evicted_digest) = evicted {
                            Self::mark_header_key_evicted(header_table, evicted_digest, now_ns);
                        }
                        return existing_decision;
                    }
                    HeaderLookup::MissingOrExpired => {
                        return self.admit_new_header_key(
                            header_table,
                            admission_table,
                            ceiling_table,
                            active_table,
                            ip_digest,
                            hdr_digest,
                            now,
                            now_ns,
                            idle_expires_ns,
                        );
                    }
                }
            }
            // Header absent: use isolated per-IP fallback table (`self.shards`), never competing
            // with header-key admission or active header users.
            return self
                .check_digest_in_table_with_params(&self.shards, ip_digest, now, self.params)
                .0;
        }
        let (is_agent_table, digest) =
            self.hash_request_key(client_ip, headers, verified_agent_id, now);
        let table = if is_agent_table {
            &self.agent_shards
        } else {
            &self.shards
        };
        self.check_digest_in_table_with_params(table, digest, now, self.params)
            .0
    }

    /// Evaluates a rate-limit check for an explicit string key at the current time.
    #[must_use]
    pub fn check_key(&self, key: &str) -> RateLimitDecision {
        self.check_key_at(key, Instant::now())
    }

    /// Evaluates a rate-limit check for `key` at an explicit [`Instant`] (deterministic testing).
    #[must_use]
    pub fn check_key_at(&self, key: &str, now: Instant) -> RateLimitDecision {
        let digest = self.hash_slices(&[b"raw", key.as_bytes()]);
        self.check_digest_in_table_with_params(&self.shards, digest, now, self.params)
            .0
    }

    /// Returns the number of currently active (unexpired) tracked header keys for `client_ip`
    /// at `now` (`0` for non-header limiters). Useful for verifying atomic LRU cap bounds (`R5-RL-2`, `R6-RL-1`).
    #[must_use]
    pub fn tracked_active_key_count_for_ip(
        &self,
        client_ip: Option<IpAddr>,
        now: Instant,
    ) -> usize {
        let Some(active_table) = &self.ip_active_keys else {
            return 0;
        };
        let ip_digest = self.hash_ip(client_ip, now);
        let now_ns =
            u64::try_from(now.saturating_duration_since(self.epoch).as_nanos()).unwrap_or(u64::MAX);
        let shard_idx = usize::try_from((ip_digest >> 64) % (NUM_SHARDS as u128)).unwrap_or(0);
        let Some(shard_lock) = active_table.get(shard_idx) else {
            return 0;
        };
        let shard = match shard_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        shard.entries.get(&ip_digest).map_or(0, |keys| {
            keys.iter().filter(|(_, exp)| *exp > now_ns).count()
        })
    }

    /// Evaluates admission for a brand-new or idle-expired header key (`R2-RL-1`, `R5-RL-1`, `R6-RL-1`).
    #[allow(clippy::too_many_arguments)]
    fn admit_new_header_key(
        &self,
        header_table: &[Mutex<HeaderShardState>; NUM_SHARDS],
        admission_table: &[Mutex<ShardState>; NUM_SHARDS],
        ceiling_table: &[Mutex<ShardState>; NUM_SHARDS],
        active_table: &[Mutex<IpKeyTrackerShard>; NUM_SHARDS],
        ip_digest: u128,
        hdr_digest: u128,
        now: Instant,
        now_ns: u64,
        idle_expires_ns: u64,
    ) -> RateLimitDecision {
        // 1. Enforce isolated per-IP new-key admission FIRST so rejected rotation floods never
        //    charge the shared IP ceiling or evict active victims from `ip_active_keys`.
        let (admission_decision, _) =
            self.check_digest_in_table_with_params(admission_table, ip_digest, now, self.params);
        if !admission_decision.allowed {
            return admission_decision;
        }
        // 2. Enforce the shared IP ceiling before admitting the key.
        let (ceil_decision, _) = self.check_digest_in_table_with_params(
            ceiling_table,
            ip_digest,
            now,
            self.ceiling_params,
        );
        if !ceil_decision.allowed {
            return ceil_decision;
        }
        // 3. Atomically claim a slot in `ip_active_keys`, evicting the least-recently-used key
        //    when at capacity (`R6-RL-1`) instead of permanently denying new/returning users!
        let (active_count, evicted) = self.claim_or_evict_ip_active_key(
            active_table,
            ip_digest,
            hdr_digest,
            idle_expires_ns,
            now_ns,
        );
        if let Some(evicted_digest) = evicted {
            Self::mark_header_key_evicted(header_table, evicted_digest, now_ns);
        }
        let fair_interval = self.fair_share_interval_ns(active_count);
        let hdr_decision = self.check_and_insert_header_digest(
            header_table,
            hdr_digest,
            now_ns,
            idle_expires_ns,
            fair_interval,
        );
        if !hdr_decision.allowed {
            Self::release_ip_active_key(active_table, ip_digest, hdr_digest);
        }
        hdr_decision
    }

    /// Inspects the shared IP ceiling state without mutating it (`R6-RL-1`).
    fn inspect_ceiling(
        &self,
        table: &[Mutex<ShardState>; NUM_SHARDS],
        digest: u128,
        now_ns: u64,
    ) -> CeilingStatus {
        let shard_idx = usize::try_from((digest >> 64) % (NUM_SHARDS as u128)).unwrap_or(0);
        let Some(shard_lock) = table.get(shard_idx) else {
            return CeilingStatus::Uncongested;
        };
        let shard = match shard_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let Some(&prev_tat) = shard.entries.get(&digest) else {
            return CeilingStatus::Uncongested;
        };
        let allow_at = prev_tat.saturating_sub(self.ceiling_params.delay_tolerance_ns);
        if now_ns < allow_at {
            let wait_ns = allow_at.saturating_sub(now_ns);
            let retry_after_secs = wait_ns.div_ceil(1_000_000_000).max(1);
            return CeilingStatus::Exhausted(RateLimitDecision {
                allowed: false,
                limit: self.ceiling_params.limit,
                remaining: 0,
                retry_after_secs,
            });
        }
        let soft_tol_ns = (self.ceiling_params.delay_tolerance_ns / 4).saturating_mul(3);
        let soft_allow_at = prev_tat.saturating_sub(soft_tol_ns);
        if self.ceiling_params.delay_tolerance_ns > 0 && now_ns < soft_allow_at {
            return CeilingStatus::Congested;
        }
        CeilingStatus::Uncongested
    }

    /// Returns the fair-share per-key emission interval (`80% * ceiling / active_keys`) enforced
    /// only when the IP's shared ceiling enters soft congestion (`R6-RL-1`).
    fn fair_share_interval_ns(&self, active_keys: usize) -> u64 {
        let keys = u64::try_from(active_keys.max(2)).unwrap_or(2);
        self.ceiling_params
            .emission_interval_ns
            .saturating_mul(keys)
            .saturating_mul(5)
            / 4
    }

    fn active_key_count_for_ip_digest(
        table: &[Mutex<IpKeyTrackerShard>; NUM_SHARDS],
        ip_digest: u128,
        now_ns: u64,
    ) -> usize {
        let shard_idx = usize::try_from((ip_digest >> 64) % (NUM_SHARDS as u128)).unwrap_or(0);
        let Some(shard_lock) = table.get(shard_idx) else {
            return 1;
        };
        let shard = match shard_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        shard.entries.get(&ip_digest).map_or(1, |keys| {
            keys.iter().filter(|(_, exp)| *exp > now_ns).count().max(1)
        })
    }

    /// Atomically refreshes or claims a per-IP active-header-key slot under ONE shard lock
    /// (`R5-RL-2`, `R6-RL-1`). When the IP is already at `max_active_header_keys_per_ip`, evicts
    /// the least-recently-used key (earliest `expires_at_ns`) so a slot-hogging user can never
    /// starve new or returning users behind the same NAT/CDN IP.
    ///
    /// Returns `(active_key_count_after_update, evicted_header_digest)`.
    fn claim_or_evict_ip_active_key(
        &self,
        table: &[Mutex<IpKeyTrackerShard>; NUM_SHARDS],
        ip_digest: u128,
        hdr_digest: u128,
        expires_at_ns: u64,
        now_ns: u64,
    ) -> (usize, Option<u128>) {
        let shard_idx = usize::try_from((ip_digest >> 64) % (NUM_SHARDS as u128)).unwrap_or(0);
        let Some(shard_lock) = table.get(shard_idx) else {
            return (1, None);
        };
        let mut shard = match shard_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        if !shard.entries.contains_key(&ip_digest)
            && shard.entries.len() >= MAX_IP_KEY_TRACKERS_PER_SHARD
        {
            if now_ns.saturating_sub(shard.last_sweep_ns) >= SWEEP_COOLDOWN_NS {
                shard.entries.retain(|_, list| {
                    list.retain(|(_, exp)| *exp > now_ns);
                    !list.is_empty()
                });
                shard.last_sweep_ns = now_ns;
            }
            if shard.entries.len() >= MAX_IP_KEY_TRACKERS_PER_SHARD {
                let victim = shard
                    .entries
                    .iter()
                    .take(EVICTION_SAMPLE_LIMIT)
                    .min_by_key(|(_, list)| list.iter().map(|(_, exp)| *exp).max().unwrap_or(0))
                    .map(|(k, _)| *k);
                if let Some(evict_ip) = victim {
                    shard.entries.remove(&evict_ip);
                }
            }
        }

        let keys = shard.entries.entry(ip_digest).or_default();
        keys.retain(|(_, exp_ns)| *exp_ns > now_ns);
        if let Some((_, exp_slot)) = keys.iter_mut().find(|(k, _)| *k == hdr_digest) {
            *exp_slot = (*exp_slot).max(expires_at_ns);
            return (keys.len().max(1), None);
        }
        let mut evicted = None;
        if keys.len() >= self.max_active_header_keys_per_ip
            && let Some((lru_idx, _)) = keys
                .iter()
                .enumerate()
                .min_by_key(|(_, (_, exp_ns))| *exp_ns)
        {
            evicted = Some(keys.swap_remove(lru_idx).0);
        }
        keys.push((hdr_digest, expires_at_ns));
        (keys.len().max(1), evicted)
    }

    /// Cleans up a header key evicted from `ip_active_keys`: removes it from `header_shards` if
    /// unthrottled (preserving memory bounds), or clears its `idle_expires_ns` while retaining
    /// active `tat_ns` so LRU churn can never reset a throttled key's GCRA penalty.
    fn mark_header_key_evicted(
        table: &[Mutex<HeaderShardState>; NUM_SHARDS],
        digest: u128,
        now_ns: u64,
    ) {
        let shard_idx = usize::try_from((digest >> 64) % (NUM_SHARDS as u128)).unwrap_or(0);
        let Some(shard_lock) = table.get(shard_idx) else {
            return;
        };
        let mut shard = match shard_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(entry) = shard.entries.get_mut(&digest) {
            if entry.tat_ns <= now_ns {
                shard.entries.remove(&digest);
            } else {
                entry.idle_expires_ns = 0;
            }
        }
    }

    /// Releases a newly-claimed active-key slot when a subsequent check rejects the request.
    fn release_ip_active_key(
        table: &[Mutex<IpKeyTrackerShard>; NUM_SHARDS],
        ip_digest: u128,
        hdr_digest: u128,
    ) {
        let shard_idx = usize::try_from((ip_digest >> 64) % (NUM_SHARDS as u128)).unwrap_or(0);
        let Some(shard_lock) = table.get(shard_idx) else {
            return;
        };
        let mut shard = match shard_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(keys) = shard.entries.get_mut(&ip_digest) {
            keys.retain(|(k, _)| *k != hdr_digest);
            if keys.is_empty() {
                shard.entries.remove(&ip_digest);
            }
        }
    }

    /// Read-only inspection of `header_shards` before touching the shared IP ceiling (`R6-RL-1`).
    fn peek_existing_header_digest(
        &self,
        table: &[Mutex<HeaderShardState>; NUM_SHARDS],
        digest: u128,
        now_ns: u64,
    ) -> HeaderLookup {
        let shard_idx = usize::try_from((digest >> 64) % (NUM_SHARDS as u128)).unwrap_or(0);
        let Some(shard_lock) = table.get(shard_idx) else {
            return HeaderLookup::MissingOrExpired;
        };
        let mut shard = match shard_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let Some(&entry) = shard.entries.get(&digest) else {
            return HeaderLookup::MissingOrExpired;
        };
        let tat = entry.tat_ns.max(now_ns);
        let allow_at = tat.saturating_sub(self.params.delay_tolerance_ns);
        if now_ns < allow_at {
            let wait_ns = allow_at.saturating_sub(now_ns);
            let retry_after_secs = wait_ns.div_ceil(1_000_000_000).max(1);
            return HeaderLookup::Throttled(RateLimitDecision {
                allowed: false,
                limit: self.params.limit,
                remaining: 0,
                retry_after_secs,
            });
        }
        if entry.idle_expires_ns <= now_ns {
            if entry.tat_ns <= now_ns {
                shard.entries.remove(&digest);
            }
            return HeaderLookup::MissingOrExpired;
        }
        HeaderLookup::Active(entry)
    }

    /// Commits a per-key GCRA advance for an already-known header key within its idle-retention TTL
    /// (`R5-RL-1`, `R6-RL-1`).
    fn commit_existing_header_digest(
        &self,
        table: &[Mutex<HeaderShardState>; NUM_SHARDS],
        digest: u128,
        now_ns: u64,
        next_idle_expires_ns: u64,
        fair_interval_ns: u64,
    ) -> Option<RateLimitDecision> {
        let shard_idx = usize::try_from((digest >> 64) % (NUM_SHARDS as u128)).unwrap_or(0);
        let shard_lock = table.get(shard_idx)?;
        let mut shard = match shard_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let entry = *shard.entries.get(&digest)?;
        if entry.idle_expires_ns <= now_ns {
            if entry.tat_ns <= now_ns {
                shard.entries.remove(&digest);
            }
            return None;
        }

        let tat = entry.tat_ns.max(now_ns);
        let allow_at = tat.saturating_sub(self.params.delay_tolerance_ns);
        if now_ns < allow_at {
            let wait_ns = allow_at.saturating_sub(now_ns);
            let retry_after_secs = wait_ns.div_ceil(1_000_000_000).max(1);
            return Some(RateLimitDecision {
                allowed: false,
                limit: self.params.limit,
                remaining: 0,
                retry_after_secs,
            });
        }

        let new_tat = tat.saturating_add(self.params.emission_interval_ns);
        let max_fair_tat = now_ns.saturating_add(fair_interval_ns.saturating_mul(2));
        let next_fair_tat = entry
            .fair_tat_ns
            .max(now_ns)
            .saturating_add(fair_interval_ns)
            .min(max_fair_tat);
        shard.entries.insert(
            digest,
            HeaderEntry {
                tat_ns: new_tat,
                idle_expires_ns: entry.idle_expires_ns.max(next_idle_expires_ns),
                fair_tat_ns: next_fair_tat,
            },
        );

        let used_burst_ns = new_tat.saturating_sub(now_ns);
        let max_burst_ns = self
            .params
            .emission_interval_ns
            .saturating_mul(u64::from(self.params.burst));
        let remaining_ns = max_burst_ns.saturating_sub(used_burst_ns);
        let remaining = u32::try_from(remaining_ns / self.params.emission_interval_ns).unwrap_or(0);

        Some(RateLimitDecision {
            allowed: true,
            limit: self.params.limit,
            remaining,
            retry_after_secs: 0,
        })
    }

    /// Inserts or updates a header-keyed GCRA bucket with idle-retention expiry (`R5-RL-1`, `R6-RL-1`).
    fn check_and_insert_header_digest(
        &self,
        table: &[Mutex<HeaderShardState>; NUM_SHARDS],
        digest: u128,
        now_ns: u64,
        next_idle_expires_ns: u64,
        fair_interval_ns: u64,
    ) -> RateLimitDecision {
        let shard_idx = usize::try_from((digest >> 64) % (NUM_SHARDS as u128)).unwrap_or(0);
        let Some(shard_lock) = table.get(shard_idx) else {
            return RateLimitDecision {
                allowed: false,
                limit: self.params.limit,
                remaining: 0,
                retry_after_secs: 1,
            };
        };
        let mut shard = match shard_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        if !shard.entries.contains_key(&digest) && shard.entries.len() >= MAX_KEYS_PER_SHARD {
            if now_ns.saturating_sub(shard.last_sweep_ns) >= SWEEP_COOLDOWN_NS {
                shard
                    .entries
                    .retain(|_, entry| entry.idle_expires_ns > now_ns || entry.tat_ns > now_ns);
                shard.last_sweep_ns = now_ns;
            }
            if shard.entries.len() >= MAX_KEYS_PER_SHARD {
                let throttle_cutoff = now_ns.saturating_add(self.params.delay_tolerance_ns);
                // R7-RL-1: Prefer evicting an unthrottled entry first; if all sampled entries are
                // throttled under a shard-fill flood, evict the entry with the earliest `tat_ns`
                // instead of locking out every brand-new client for the entire period!
                let victim = shard
                    .entries
                    .iter()
                    .take(EVICTION_SAMPLE_LIMIT)
                    .filter(|(_, entry)| entry.tat_ns <= throttle_cutoff)
                    .min_by_key(|(_, entry)| entry.idle_expires_ns)
                    .or_else(|| {
                        shard
                            .entries
                            .iter()
                            .take(EVICTION_SAMPLE_LIMIT)
                            .min_by_key(|(_, entry)| entry.tat_ns)
                    })
                    .map(|(k, _)| *k);
                if let Some(evict_key) = victim {
                    shard.entries.remove(&evict_key);
                }
            }
        }

        let prev = shard.entries.get(&digest).copied();
        let tat = prev.map_or(now_ns, |e| e.tat_ns).max(now_ns);
        let allow_at = tat.saturating_sub(self.params.delay_tolerance_ns);
        if now_ns < allow_at {
            let wait_ns = allow_at.saturating_sub(now_ns);
            let retry_after_secs = wait_ns.div_ceil(1_000_000_000).max(1);
            return RateLimitDecision {
                allowed: false,
                limit: self.params.limit,
                remaining: 0,
                retry_after_secs,
            };
        }

        let new_tat = tat.saturating_add(self.params.emission_interval_ns);
        let idle_exp = prev
            .map_or(next_idle_expires_ns, |e| {
                e.idle_expires_ns.max(next_idle_expires_ns)
            })
            .max(new_tat);
        let max_fair_tat = now_ns.saturating_add(fair_interval_ns.saturating_mul(2));
        let next_fair_tat = prev
            .map_or(now_ns, |e| e.fair_tat_ns)
            .max(now_ns)
            .saturating_add(fair_interval_ns)
            .min(max_fair_tat);
        shard.entries.insert(
            digest,
            HeaderEntry {
                tat_ns: new_tat,
                idle_expires_ns: idle_exp,
                fair_tat_ns: next_fair_tat,
            },
        );

        let used_burst_ns = new_tat.saturating_sub(now_ns);
        let max_burst_ns = self
            .params
            .emission_interval_ns
            .saturating_mul(u64::from(self.params.burst));
        let remaining_ns = max_burst_ns.saturating_sub(used_burst_ns);
        let remaining = u32::try_from(remaining_ns / self.params.emission_interval_ns).unwrap_or(0);

        RateLimitDecision {
            allowed: true,
            limit: self.params.limit,
            remaining,
            retry_after_secs: 0,
        }
    }

    fn check_digest_in_table_with_params(
        &self,
        table: &[Mutex<ShardState>; NUM_SHARDS],
        digest: u128,
        now: Instant,
        params: GcraParams,
    ) -> (RateLimitDecision, Option<u64>) {
        let now_ns =
            u64::try_from(now.saturating_duration_since(self.epoch).as_nanos()).unwrap_or(u64::MAX);
        let shard_idx = usize::try_from((digest >> 64) % (NUM_SHARDS as u128)).unwrap_or(0);
        let Some(shard_lock) = table.get(shard_idx) else {
            return (
                RateLimitDecision {
                    allowed: false,
                    limit: params.limit,
                    remaining: 0,
                    retry_after_secs: 1,
                },
                None,
            );
        };

        let mut shard = match shard_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        // Bounded-memory management with active-throttle preference and overflow fallback (`R7-RL-1`).
        if !shard.entries.contains_key(&digest) && shard.entries.len() >= MAX_KEYS_PER_SHARD {
            if now_ns.saturating_sub(shard.last_sweep_ns) >= SWEEP_COOLDOWN_NS {
                shard.entries.retain(|_, tat| *tat > now_ns);
                shard.last_sweep_ns = now_ns;
            }
            if shard.entries.len() >= MAX_KEYS_PER_SHARD {
                let throttle_cutoff = now_ns.saturating_add(params.delay_tolerance_ns);
                // R7-RL-1: Prefer evicting an unthrottled entry first to avoid resetting active
                // throttles; if all sampled entries are throttled (table-fill flood), evict the
                // earliest-expiring sampled entry instead of globally denying all fresh clients!
                let victim = shard
                    .entries
                    .iter()
                    .take(EVICTION_SAMPLE_LIMIT)
                    .filter(|(_, tat)| **tat <= throttle_cutoff)
                    .min_by_key(|(_, tat)| **tat)
                    .or_else(|| {
                        shard
                            .entries
                            .iter()
                            .take(EVICTION_SAMPLE_LIMIT)
                            .min_by_key(|(_, tat)| **tat)
                    })
                    .map(|(k, _)| *k);
                if let Some(evict_key) = victim {
                    shard.entries.remove(&evict_key);
                }
            }
        }

        let tat = shard
            .entries
            .get(&digest)
            .copied()
            .unwrap_or(now_ns)
            .max(now_ns);
        let allow_at = tat.saturating_sub(params.delay_tolerance_ns);

        if now_ns < allow_at {
            let wait_ns = allow_at.saturating_sub(now_ns);
            let retry_after_secs = wait_ns.div_ceil(1_000_000_000).max(1);
            return (
                RateLimitDecision {
                    allowed: false,
                    limit: params.limit,
                    remaining: 0,
                    retry_after_secs,
                },
                None,
            );
        }

        let new_tat = tat.saturating_add(params.emission_interval_ns);
        shard.entries.insert(digest, new_tat);

        let used_burst_ns = new_tat.saturating_sub(now_ns);
        let max_burst_ns = params
            .emission_interval_ns
            .saturating_mul(u64::from(params.burst));
        let remaining_ns = max_burst_ns.saturating_sub(used_burst_ns);
        let remaining = u32::try_from(remaining_ns / params.emission_interval_ns).unwrap_or(0);

        (
            RateLimitDecision {
                allowed: true,
                limit: params.limit,
                remaining,
                retry_after_secs: 0,
            },
            Some(new_tat),
        )
    }

    fn hash_request_key(
        &self,
        client_ip: Option<IpAddr>,
        headers: &HeaderMap,
        verified_agent_id: Option<&str>,
        now: Instant,
    ) -> (bool, u128) {
        match &self.key_selector {
            RateLimitKey::ClientIp => (false, self.hash_ip(client_ip, now)),
            RateLimitKey::AgentId => {
                if let Some(agent_id) = verified_agent_id {
                    (true, self.hash_slices(&[b"agent", agent_id.as_bytes()]))
                } else {
                    (false, self.hash_ip(client_ip, now))
                }
            }
            RateLimitKey::Header(name) => {
                if let Some(digest) = self.hash_header_opt(name, headers) {
                    (false, digest)
                } else {
                    (false, self.hash_ip(client_ip, now))
                }
            }
        }
    }

    fn hash_header_opt(&self, name: &str, headers: &HeaderMap) -> Option<u128> {
        let mut h_lo = self.hash_lo.build_hasher();
        let mut h_hi = self.hash_hi.build_hasher();
        let mut count = 0_usize;
        for val in headers.get_all(name) {
            if count == 0 {
                feed_part(&mut h_lo, &mut h_hi, b"hdr");
                feed_part(&mut h_lo, &mut h_hi, name.as_bytes());
            }
            feed_part(&mut h_lo, &mut h_hi, val.as_bytes());
            count = count.saturating_add(1);
        }
        if count == 0 {
            None
        } else {
            Some((u128::from(h_hi.finish()) << 64) | u128::from(h_lo.finish()))
        }
    }

    /// Records that `prefix64` (the upper 64 bits of an IPv6 address) was seen at `now_ns` and
    /// returns `true` while its `/48` must be rate limited as one client (`R8-RL-1`).
    fn prefix48_is_aggregated(&self, prefix64: u64, now_ns: u64) -> bool {
        let prefix48 = prefix64 >> 16;
        let shard_hash = self.hash_slices(&[b"p48", &prefix48.to_be_bytes()]);
        let shard_idx = usize::try_from(shard_hash % (NUM_SHARDS as u128)).unwrap_or(0);
        let Some(lock) = self.prefix48_shards.get(shard_idx) else {
            return false;
        };
        let mut shard = match lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        if !shard.contains_key(&prefix48) && shard.len() >= MAX_TRACKED_PREFIX48_PER_SHARD {
            // Forget prefixes that are neither aggregated nor recently active; if every tracked
            // prefix is still live, drop the least recently seen one that is not aggregated.
            shard.retain(|_, st| {
                st.aggregated_until_ns > now_ns
                    || now_ns.saturating_sub(st.last_seen_ns) < PREFIX48_WINDOW_NS
            });
            if shard.len() >= MAX_TRACKED_PREFIX48_PER_SHARD {
                let victim = shard
                    .iter()
                    .filter(|(_, st)| st.aggregated_until_ns <= now_ns)
                    .min_by_key(|(_, st)| st.last_seen_ns)
                    .map(|(k, _)| *k);
                match victim {
                    Some(key) => {
                        shard.remove(&key);
                    }
                    // Every tracked /48 is an active rotator. A further unknown /48 arriving
                    // during such a flood is treated as one client rather than left untracked.
                    None => return true,
                }
            }
        }

        let state = shard.entry(prefix48).or_default();
        state.last_seen_ns = now_ns;
        if now_ns.saturating_sub(state.window_start_ns) >= PREFIX48_WINDOW_NS {
            state.window_start_ns = now_ns;
            state.seen64.clear();
        }
        if !state.seen64.contains(&prefix64) {
            if state.seen64.len() < PREFIX48_DISTINCT_LIMIT {
                state.seen64.push(prefix64);
            }
            if state.seen64.len() >= PREFIX48_DISTINCT_LIMIT {
                state.aggregated_until_ns = now_ns.saturating_add(PREFIX48_WINDOW_NS);
            }
        } else if state.seen64.len() >= PREFIX48_DISTINCT_LIMIT {
            // Still rotating through the full set: keep the aggregation alive.
            state.aggregated_until_ns = now_ns.saturating_add(PREFIX48_WINDOW_NS);
        }
        state.aggregated_until_ns > now_ns
    }

    fn hash_ip(&self, client_ip: Option<IpAddr>, now: Instant) -> u128 {
        match client_ip {
            None => self.hash_slices(&[b"ip", b"unknown"]),
            Some(IpAddr::V4(v4)) => self.hash_slices(&[b"ip4", &v4.octets()]),
            Some(IpAddr::V6(v6)) => {
                if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                    return self.hash_slices(&[b"ip4", &mapped_v4.octets()]);
                }
                // Mask IPv6 to /64 prefix to prevent trivial /128 address-rotation bypasses.
                let prefix_hi = u64::try_from(u128::from(v6) >> 64).unwrap_or(0);
                let now_ns = u64::try_from(now.saturating_duration_since(self.epoch).as_nanos())
                    .unwrap_or(u64::MAX);
                if self.prefix48_is_aggregated(prefix_hi, now_ns) {
                    // R7-RL-1 & R8-RL-1: this /48 is itself rotating through many /64s.
                    let prefix48 = prefix_hi >> 16;
                    self.hash_slices(&[b"ip6_48", &prefix48.to_be_bytes()])
                } else {
                    self.hash_slices(&[b"ip6_64", &prefix_hi.to_be_bytes()])
                }
            }
        }
    }

    fn hash_slices(&self, parts: &[&[u8]]) -> u128 {
        let mut h_lo = self.hash_lo.build_hasher();
        let mut h_hi = self.hash_hi.build_hasher();
        for part in parts {
            feed_part(&mut h_lo, &mut h_hi, part);
        }
        (u128::from(h_hi.finish()) << 64) | u128::from(h_lo.finish())
    }

    /// Creates a convenient IP-keyed GCRA limiter for built-in presets (e.g. `wp-login.php`).
    #[must_use]
    pub fn per_ip(requests: u32, per: Duration, burst: u32) -> Self {
        Self::from_config(&RateLimitConfig {
            requests,
            per,
            burst,
            key: RateLimitKey::ClientIp,
            ip_ceiling_multiplier: None,
            max_keys_per_ip: None,
        })
    }
}

fn feed_part<H: std::hash::Hasher>(h_lo: &mut H, h_hi: &mut H, bytes: &[u8]) {
    let len_le = (bytes.len() as u64).to_le_bytes();
    h_lo.write(&len_le);
    h_lo.write(bytes);
    h_hi.write(bytes);
    h_hi.write(&len_le);
}

//! Upstream backend pool, weighted load balancing (`round-robin`, `least-conn`, `random`),
//! RAII in-flight tracking, and active HTTP health state.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use http::HeaderValue;
use http::uri::{Authority, Scheme};
use miraserve_config::{LoadBalancePolicy, UpstreamConfig};
use url::Url;

use crate::ProxyError;

/// Runtime state for a single upstream backend server.
#[derive(Debug)]
pub struct Backend {
    /// Parsed base URL (`https://10.0.1.30:8000`).
    pub base_url: Url,
    /// Pre-validated HTTP `Scheme`.
    pub scheme: Scheme,
    /// Pre-validated HTTP `Authority` (`host` or `host:port`).
    pub authority: Authority,
    /// Precomputed upstream `Host` header value derived from `authority` once at pool build time.
    pub(crate) host_header: Option<HeaderValue>,
    /// Relative load-balancing weight (`>= 1`).
    pub weight: u32,
    /// Whether this backend is currently considered healthy.
    healthy: AtomicBool,
    /// Consecutive active health-check probe failures (`R3-PRX-2`).
    active_consecutive_failures: AtomicU32,
    /// Consecutive passive request transport/timeout failures (`R3-PRX-2`).
    passive_consecutive_failures: AtomicU32,
    /// Number of currently active in-flight requests/streams.
    in_flight: AtomicUsize,
    /// Number of currently in-progress TCP connect / TLS handshake attempts (`R5-PRX-1`).
    connecting_in_flight: AtomicUsize,
    /// Monotonic origin for passive connect-failure cooldown timestamps.
    epoch: Instant,
    /// Milliseconds since `epoch` until which this backend is passively cooled down after a
    /// connect failure (`0` = not in cooldown).
    passive_cooldown_until_ms: AtomicU64,
}

impl Backend {
    /// Builds a [`Backend`] from a validated [`UpstreamConfig`].
    ///
    /// # Errors
    /// Returns [`ProxyError::InvalidUpstream`] if the URL cannot be mapped to HTTP scheme/authority.
    pub fn from_config(cfg: &UpstreamConfig) -> Result<Self, ProxyError> {
        let base_url = Url::parse(&cfg.url)
            .map_err(|err| ProxyError::InvalidUpstream(format!("{}: {err}", cfg.url)))?;
        let scheme = Scheme::try_from(base_url.scheme())
            .map_err(|err| ProxyError::InvalidUpstream(format!("{}: {err}", cfg.url)))?;
        let host = base_url
            .host_str()
            .ok_or_else(|| ProxyError::InvalidUpstream(format!("{}: missing host", cfg.url)))?;
        let authority_str = match base_url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        };
        let authority = Authority::try_from(authority_str.as_str())
            .map_err(|err| ProxyError::InvalidUpstream(format!("{}: {err}", cfg.url)))?;
        let host_header = HeaderValue::from_str(authority.as_str()).ok();

        Ok(Self {
            base_url,
            scheme,
            authority,
            host_header,
            weight: cfg.weight.max(1),
            healthy: AtomicBool::new(true),
            active_consecutive_failures: AtomicU32::new(0),
            passive_consecutive_failures: AtomicU32::new(0),
            in_flight: AtomicUsize::new(0),
            connecting_in_flight: AtomicUsize::new(0),
            epoch: Instant::now(),
            passive_cooldown_until_ms: AtomicU64::new(0),
        })
    }

    fn now_epoch_ms(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Returns `true` if the backend is currently healthy (not marked down by health checks).
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }

    /// Returns `true` if the backend is temporarily cooled down after a passive connect failure.
    #[must_use]
    pub fn is_in_passive_cooldown(&self) -> bool {
        let until = self.passive_cooldown_until_ms.load(Ordering::Acquire);
        until != 0 && self.now_epoch_ms() < until
    }

    /// Returns `true` if the backend is both healthy and not in passive connect cooldown.
    #[must_use]
    pub fn is_available(&self) -> bool {
        self.is_healthy() && !self.is_in_passive_cooldown()
    }

    /// Temporarily cools down this backend for `cooldown` after a passive connect error so
    /// subsequent requests in a multi-backend pool skip it until the cooldown expires.
    pub fn record_passive_cooldown(&self, cooldown: Duration) {
        let add_ms = u64::try_from(cooldown.as_millis()).unwrap_or(u64::MAX);
        if add_ms == 0 {
            return;
        }
        let until = self.now_epoch_ms().saturating_add(add_ms).max(1);
        self.passive_cooldown_until_ms
            .store(until, Ordering::Release);
    }

    /// Clears any active passive connect cooldown on this backend.
    pub fn clear_passive_cooldown(&self) {
        self.passive_cooldown_until_ms.store(0, Ordering::Release);
    }

    /// Returns the number of currently active in-flight requests.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Acquire)
    }

    /// Returns the number of currently in-progress TCP connect / TLS handshake attempts (`R5-PRX-1`).
    #[must_use]
    pub fn connecting_in_flight(&self) -> usize {
        self.connecting_in_flight.load(Ordering::Acquire)
    }

    /// Acquires an RAII guard tracking an active TCP connect / TLS handshake attempt.
    pub(crate) fn begin_connect(self: &Arc<Self>) -> ConnectingGuard {
        self.connecting_in_flight.fetch_add(1, Ordering::AcqRel);
        ConnectingGuard {
            backend: Arc::clone(self),
        }
    }

    /// Marks an active health-check probe as successful, resetting both active and passive
    /// failure counters and restoring health.
    pub fn record_health_success(&self) {
        self.active_consecutive_failures.store(0, Ordering::Release);
        self.passive_consecutive_failures
            .store(0, Ordering::Release);
        self.passive_cooldown_until_ms.store(0, Ordering::Release);
        self.healthy.store(true, Ordering::Release);
    }

    /// Resets ONLY the passive consecutive failure counter and passive cooldown after a successful
    /// non-5xx forwarded response, never resetting active health-check probe failures (`R3-PRX-2`)
    /// or overriding an active health-check ejection (`R2-PRX-1`).
    pub fn reset_passive_failures(&self) {
        self.passive_consecutive_failures
            .store(0, Ordering::Release);
        self.passive_cooldown_until_ms.store(0, Ordering::Release);
    }

    /// Alias for [`Self::reset_passive_failures`].
    pub fn reset_consecutive_failures(&self) {
        self.reset_passive_failures();
    }

    /// Marks an active health-check probe as failed; flips unhealthy once `threshold` is reached.
    pub fn record_health_failure(&self, threshold: u32) -> bool {
        let failures = self
            .active_consecutive_failures
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        if failures >= threshold.max(1) {
            self.healthy.store(false, Ordering::Release);
            true
        } else {
            false
        }
    }

    /// Marks a passive forwarded request transport/timeout failure (`R3-PRX-2`); flips unhealthy
    /// once `threshold` consecutive passive failures occur without interfering with active probes.
    pub fn record_passive_health_failure(&self, threshold: u32) -> bool {
        let failures = self
            .passive_consecutive_failures
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        if failures >= threshold.max(1) {
            self.healthy.store(false, Ordering::Release);
            true
        } else {
            false
        }
    }
}

/// RAII guard tracking an active in-flight request/stream on a [`Backend`].
#[derive(Debug)]
pub struct InFlightGuard {
    backend: Arc<Backend>,
}

impl InFlightGuard {
    fn acquire(backend: Arc<Backend>) -> Self {
        backend.in_flight.fetch_add(1, Ordering::AcqRel);
        Self { backend }
    }

    /// Borrows the selected [`Backend`].
    #[must_use]
    pub fn backend(&self) -> &Backend {
        &self.backend
    }

    /// Clones the underlying `Arc<Backend>` handle (for retry exclusion lists).
    #[must_use]
    pub(crate) fn backend_arc(&self) -> Arc<Backend> {
        Arc::clone(&self.backend)
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.backend.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// RAII guard tracking an in-progress TCP connect / TLS handshake attempt on a [`Backend`].
#[derive(Debug)]
pub(crate) struct ConnectingGuard {
    backend: Arc<Backend>,
}

impl Drop for ConnectingGuard {
    fn drop(&mut self) {
        self.backend
            .connecting_in_flight
            .fetch_sub(1, Ordering::AcqRel);
    }
}

/// Weighted load-balancing pool across upstream [`Backend`] instances.
#[derive(Debug)]
pub struct BackendPool {
    backends: Vec<Arc<Backend>>,
    /// Weighted index schedule for O(1) weighted round-robin / random selection.
    weighted_slots: Vec<usize>,
    policy: LoadBalancePolicy,
    rr_cursor: AtomicUsize,
    rng_state: AtomicU64,
}

impl BackendPool {
    /// Creates a new [`BackendPool`] from configured upstreams.
    ///
    /// # Errors
    /// Returns [`ProxyError::InvalidUpstream`] if the upstream list is empty or malformed.
    pub fn new(
        upstreams: &[UpstreamConfig],
        policy: LoadBalancePolicy,
    ) -> Result<Self, ProxyError> {
        if upstreams.is_empty() {
            return Err(ProxyError::InvalidUpstream(
                "reverse-proxy pool requires at least one upstream".to_owned(),
            ));
        }

        let mut backends = Vec::with_capacity(upstreams.len());
        let mut weighted_slots = Vec::new();
        for (idx, cfg) in upstreams.iter().enumerate() {
            let backend = Arc::new(Backend::from_config(cfg)?);
            // Cap slot expansion per backend to 64 to keep memory strictly bounded.
            let slots = usize::try_from(backend.weight.min(64)).unwrap_or(1);
            for _ in 0..slots {
                weighted_slots.push(idx);
            }
            backends.push(backend);
        }

        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0x9E37_79B9_7F4A_7C15, |d| {
                u64::try_from(d.as_nanos() & u128::from(u64::MAX)).unwrap_or(1) | 1
            });

        Ok(Self {
            backends,
            weighted_slots,
            policy,
            rr_cursor: AtomicUsize::new(0),
            rng_state: AtomicU64::new(seed),
        })
    }

    /// Returns all backends in this pool (for health checks and status inspection).
    #[must_use]
    pub fn backends(&self) -> &[Arc<Backend>] {
        &self.backends
    }

    /// Looks up a backend by matching HTTP `Authority` (`host` or `host:port`, ASCII case-insensitive).
    #[must_use]
    pub(crate) fn find_by_authority(&self, authority: &str) -> Option<Arc<Backend>> {
        self.backends
            .iter()
            .find(|b| b.authority.as_str().eq_ignore_ascii_case(authority))
            .map(Arc::clone)
    }

    /// Selects the next available healthy backend according to [`LoadBalancePolicy`] and acquires
    /// an [`InFlightGuard`] that decrements automatically on drop.
    #[must_use]
    pub fn select(&self) -> Option<InFlightGuard> {
        self.select_excluding(&[])
    }

    /// Selects the next available healthy backend not present in `excluded`. If every non-excluded
    /// healthy backend is currently in passive connect cooldown (and not marked down by an active
    /// health check), falls back to the one whose cooldown expires soonest so a transient blip
    /// cannot lock out the entire pool.
    #[must_use]
    pub fn select_excluding(&self, excluded: &[Arc<Backend>]) -> Option<InFlightGuard> {
        let primary = match self.policy {
            LoadBalancePolicy::RoundRobin => self.select_round_robin(excluded),
            LoadBalancePolicy::LeastConn => self.select_least_conn(excluded),
            LoadBalancePolicy::Random => self.select_random(excluded),
        };
        if primary.is_some() {
            return primary;
        }
        self.backends
            .iter()
            .filter(|b| !is_excluded_backend(b, excluded) && b.is_healthy())
            .min_by_key(|b| b.passive_cooldown_until_ms.load(Ordering::Acquire))
            .map(|b| InFlightGuard::acquire(Arc::clone(b)))
    }

    fn select_round_robin(&self, excluded: &[Arc<Backend>]) -> Option<InFlightGuard> {
        let total = self.weighted_slots.len();
        if total == 0 {
            return None;
        }
        let start = self.rr_cursor.fetch_add(1, Ordering::Relaxed);
        for offset in 0..total {
            let slot_idx = start.wrapping_add(offset) % total;
            if let Some(&backend_idx) = self.weighted_slots.get(slot_idx)
                && let Some(backend) = self.backends.get(backend_idx)
                && !is_excluded_backend(backend, excluded)
                && backend.is_available()
            {
                return Some(InFlightGuard::acquire(Arc::clone(backend)));
            }
        }
        None
    }

    fn select_least_conn(&self, excluded: &[Arc<Backend>]) -> Option<InFlightGuard> {
        let max_weight = self
            .backends
            .iter()
            .map(|b| u64::from(b.weight))
            .max()
            .unwrap_or(1);

        let mut best: Option<&Arc<Backend>> = None;
        let mut best_score = u128::MAX;

        for backend in &self.backends {
            if is_excluded_backend(backend, excluded) || !backend.is_available() {
                continue;
            }
            let inflight = u128::try_from(backend.in_flight()).unwrap_or(u128::MAX);
            let score =
                inflight.saturating_mul(u128::from(max_weight)) / u128::from(backend.weight.max(1));
            if score < best_score {
                best_score = score;
                best = Some(backend);
            }
        }

        best.map(|b| InFlightGuard::acquire(Arc::clone(b)))
    }

    fn select_random(&self, excluded: &[Arc<Backend>]) -> Option<InFlightGuard> {
        let healthy_slots: Vec<usize> = self
            .weighted_slots
            .iter()
            .copied()
            .filter(|&idx| {
                self.backends
                    .get(idx)
                    .is_some_and(|b| !is_excluded_backend(b, excluded) && b.is_available())
            })
            .collect();
        if healthy_slots.is_empty() {
            return None;
        }
        let rand_val = self.next_rand();
        let chosen_pos = usize::try_from(rand_val % (healthy_slots.len() as u64)).unwrap_or(0);
        let backend_idx = *healthy_slots.get(chosen_pos)?;
        let backend = self.backends.get(backend_idx)?;
        Some(InFlightGuard::acquire(Arc::clone(backend)))
    }

    fn next_rand(&self) -> u64 {
        let mut prev = self.rng_state.load(Ordering::Relaxed);
        loop {
            let mut x = if prev == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                prev
            };
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            match self.rng_state.compare_exchange_weak(
                prev,
                x,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return x,
                Err(actual) => prev = actual,
            }
        }
    }
}

fn is_excluded_backend(candidate: &Arc<Backend>, excluded: &[Arc<Backend>]) -> bool {
    excluded.iter().any(|ex| Arc::ptr_eq(candidate, ex))
}

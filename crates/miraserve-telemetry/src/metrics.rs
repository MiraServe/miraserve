//! Lock-free atomic metrics registry supporting Prometheus text exposition (`0.0.4`)
//! and OpenTelemetry OTLP/HTTP v1 JSON export.

use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

/// Number of cache-line-separated stripes backing static file-cache counters.
const FILE_CACHE_COUNTER_STRIPES: usize = 64;

/// Cache-line-separated per-thread stripes (`128` bytes each: `[hit, miss, fill, not_cached_budget]`
/// plus padding) so concurrent cache hits and misses do not write one shared cache line.
#[derive(Debug)]
struct FileCacheCounterTable(Arc<[[AtomicU64; 16]]>);

impl Default for FileCacheCounterTable {
    fn default() -> Self {
        let stripes: Vec<[AtomicU64; 16]> = (0..FILE_CACHE_COUNTER_STRIPES)
            .map(|_| std::array::from_fn(|_| AtomicU64::new(0)))
            .collect();
        Self(Arc::from(stripes))
    }
}

fn thread_file_cache_stripe() -> usize {
    static NEXT_STRIPE: AtomicUsize = AtomicUsize::new(0);
    thread_local! {
        static STRIPE: usize = NEXT_STRIPE.fetch_add(1, Ordering::Relaxed)
            & (FILE_CACHE_COUNTER_STRIPES - 1);
    }
    STRIPE.with(|&s| s)
}

/// Histogram upper bounds in seconds (standard web-edge latency buckets).
const LATENCY_BUCKETS_SECS: [f64; 11] = [
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
];

/// Security block reason label for `miraserve_security_blocks_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityBlockReason {
    /// GCRA rate limiter returned `429`.
    RateLimit,
    /// RFC 9110/9112 anti-smuggling normalizer rejected request.
    AntiSmuggling,
    /// Site hardening preset (e.g. `wordpress-hardened`) blocked request.
    SitePreset,
    /// RFC 9421 Web Bot Auth rejected or throttled unverified AI crawler.
    BotAuth,
    /// MCP Security Gateway blocked forbidden tool or oversized/deep JSON.
    McpRbac,
    /// WASM plugin sandbox trapped (fuel, memory, or timeout).
    WasmSandbox,
}

/// Outcome label for `miraserve_file_cache_events_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileCacheOutcome {
    /// Request satisfied from the opt-in in-memory file cache.
    Hit,
    /// Eligible request missed the cache (absent or expired) and ran the disk path.
    Miss,
    /// Eligible response was admitted into the file cache.
    Fill,
    /// Eligible response was served normally without caching because the byte budget was full.
    NotCachedBudget,
}

/// Lock-free atomic telemetry registry shared across all MiraServe workers.
#[derive(Debug, Default)]
pub struct TelemetryRegistry {
    // HTTP requests by protocol x status class: [h1, h2, h3] x [1xx, 2xx, 3xx, 4xx, 5xx]
    req_h1_1xx: AtomicU64,
    req_h1_2xx: AtomicU64,
    req_h1_3xx: AtomicU64,
    req_h1_4xx: AtomicU64,
    req_h1_5xx: AtomicU64,
    req_h2_1xx: AtomicU64,
    req_h2_2xx: AtomicU64,
    req_h2_3xx: AtomicU64,
    req_h2_4xx: AtomicU64,
    req_h2_5xx: AtomicU64,
    req_h3_1xx: AtomicU64,
    req_h3_2xx: AtomicU64,
    req_h3_3xx: AtomicU64,
    req_h3_4xx: AtomicU64,
    req_h3_5xx: AtomicU64,

    // Latency histogram (11 finite buckets + total count + total microseconds)
    latency_buckets: [AtomicU64; 11],
    latency_count: AtomicU64,
    latency_sum_micros: AtomicU64,

    // Active connections gauge
    active_connections: AtomicI64,

    // TLS handshakes
    tls_pqc_in_process: AtomicU64,
    tls_pqc_split_keyd: AtomicU64,
    tls_classical_in_process: AtomicU64,
    tls_classical_split_keyd: AtomicU64,

    // Security blocks
    sec_rate_limit: AtomicU64,
    sec_anti_smuggling: AtomicU64,
    sec_site_preset: AtomicU64,
    sec_bot_auth: AtomicU64,
    sec_mcp_rbac: AtomicU64,
    sec_wasm_sandbox: AtomicU64,

    // WASM plugin invocations & fuel
    wasm_ok: AtomicU64,
    wasm_fuel_exhausted: AtomicU64,
    wasm_memory_limit: AtomicU64,
    wasm_timeout: AtomicU64,
    wasm_trap: AtomicU64,
    wasm_fuel_total: AtomicU64,

    // Static file cache: 64 cache-line-separated stripes of [hits, misses, fills, not_cached_budget]
    file_cache_counters: FileCacheCounterTable,
}

impl TelemetryRegistry {
    /// Creates a zero-initialized lock-free [`TelemetryRegistry`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a completed HTTP request with its protocol (`"h1"`, `"h2"`, or `"h3"`),
    /// numeric HTTP status code, and processing latency.
    pub fn record_http_request(&self, protocol: &str, status_code: u16, duration: Duration) {
        let counter = match (protocol, status_code / 100) {
            ("h3", 1) => &self.req_h3_1xx,
            ("h3", 2) => &self.req_h3_2xx,
            ("h3", 3) => &self.req_h3_3xx,
            ("h3", 4) => &self.req_h3_4xx,
            ("h3", _) => &self.req_h3_5xx,
            ("h2", 1) => &self.req_h2_1xx,
            ("h2", 2) => &self.req_h2_2xx,
            ("h2", 3) => &self.req_h2_3xx,
            ("h2", 4) => &self.req_h2_4xx,
            ("h2", _) => &self.req_h2_5xx,
            (_, 1) => &self.req_h1_1xx,
            (_, 2) => &self.req_h1_2xx,
            (_, 3) => &self.req_h1_3xx,
            (_, 4) => &self.req_h1_4xx,
            (_, _) => &self.req_h1_5xx,
        };
        counter.fetch_add(1, Ordering::Relaxed);

        let secs = duration.as_secs_f64();
        for (idx, &bound) in LATENCY_BUCKETS_SECS.iter().enumerate() {
            if secs <= bound
                && let Some(bucket) = self.latency_buckets.get(idx)
            {
                bucket.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.latency_count.fetch_add(1, Ordering::Relaxed);
        let micros = u64::try_from(duration.as_micros()).unwrap_or(u64::MAX);
        self.latency_sum_micros.fetch_add(micros, Ordering::Relaxed);
    }

    /// Increments the active connections gauge.
    pub fn inc_active_connections(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrements the active connections gauge.
    pub fn dec_active_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// Records a completed TLS handshake.
    pub fn record_tls_handshake(&self, pqc_hybrid: bool, split_keyd: bool) {
        let ctr = match (pqc_hybrid, split_keyd) {
            (true, false) => &self.tls_pqc_in_process,
            (true, true) => &self.tls_pqc_split_keyd,
            (false, false) => &self.tls_classical_in_process,
            (false, true) => &self.tls_classical_split_keyd,
        };
        ctr.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a security enforcement block/rejection.
    pub fn record_security_block(&self, reason: SecurityBlockReason) {
        let ctr = match reason {
            SecurityBlockReason::RateLimit => &self.sec_rate_limit,
            SecurityBlockReason::AntiSmuggling => &self.sec_anti_smuggling,
            SecurityBlockReason::SitePreset => &self.sec_site_preset,
            SecurityBlockReason::BotAuth => &self.sec_bot_auth,
            SecurityBlockReason::McpRbac => &self.sec_mcp_rbac,
            SecurityBlockReason::WasmSandbox => &self.sec_wasm_sandbox,
        };
        ctr.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a sandboxed WASM plugin invocation outcome and deterministic CPU fuel consumed.
    pub fn record_wasm_invocation(&self, outcome_label: &str, fuel_consumed: u64) {
        let ctr = match outcome_label {
            "ok" => &self.wasm_ok,
            "fuel_exhausted" => &self.wasm_fuel_exhausted,
            "memory_limit" => &self.wasm_memory_limit,
            "timeout" => &self.wasm_timeout,
            _ => &self.wasm_trap,
        };
        ctr.fetch_add(1, Ordering::Relaxed);
        self.wasm_fuel_total
            .fetch_add(fuel_consumed, Ordering::Relaxed);
    }

    /// Records a static file-cache lookup or admission outcome on this thread's counter stripe.
    pub fn record_file_cache_event(&self, outcome: FileCacheOutcome) {
        let stripes = &*self.file_cache_counters.0;
        let len = stripes.len();
        if len == 0 {
            return;
        }
        let idx = thread_file_cache_stripe();
        let slot = if len.is_power_of_two() {
            idx & (len - 1)
        } else {
            idx % len
        };
        if let Some([hits, misses, fills, not_cached_budget, ..]) = stripes.get(slot) {
            let ctr = match outcome {
                FileCacheOutcome::Hit => hits,
                FileCacheOutcome::Miss => misses,
                FileCacheOutcome::Fill => fills,
                FileCacheOutcome::NotCachedBudget => not_cached_budget,
            };
            ctr.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Returns a shared handle to the striped `[hits, misses, fills, not_cached_budget, ..]`
    /// atomic counter table so lower-layer caches can increment per-thread stripes without
    /// depending on `miraserve-telemetry`.
    #[must_use]
    pub fn file_cache_counters_raw(&self) -> Arc<[[AtomicU64; 16]]> {
        Arc::clone(&self.file_cache_counters.0)
    }

    /// Returns a snapshot of `(hits, misses, fills, not_cached_budget)` summed across all stripes.
    #[must_use]
    pub fn file_cache_counts(&self) -> (u64, u64, u64, u64) {
        let (mut hits, mut misses, mut fills, mut budget) = (0_u64, 0_u64, 0_u64, 0_u64);
        for [h, m, f, b, ..] in &*self.file_cache_counters.0 {
            hits = hits.saturating_add(h.load(Ordering::Relaxed));
            misses = misses.saturating_add(m.load(Ordering::Relaxed));
            fills = fills.saturating_add(f.load(Ordering::Relaxed));
            budget = budget.saturating_add(b.load(Ordering::Relaxed));
        }
        (hits, misses, fills, budget)
    }

    /// Returns total HTTP requests observed across all protocols.
    #[must_use]
    pub fn total_http_requests(&self) -> u64 {
        self.latency_count.load(Ordering::Relaxed)
    }

    /// Renders all metrics in Prometheus 0.0.4 text exposition format.
    #[allow(clippy::too_many_lines)]
    #[must_use]
    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(2048);

        let _ = writeln!(
            out,
            "# HELP miraserve_http_requests_total Total HTTP requests handled by protocol and status class."
        );
        let _ = writeln!(out, "# TYPE miraserve_http_requests_total counter");
        for (proto, cls, ctr) in [
            ("h1", "1xx", &self.req_h1_1xx),
            ("h1", "2xx", &self.req_h1_2xx),
            ("h1", "3xx", &self.req_h1_3xx),
            ("h1", "4xx", &self.req_h1_4xx),
            ("h1", "5xx", &self.req_h1_5xx),
            ("h2", "1xx", &self.req_h2_1xx),
            ("h2", "2xx", &self.req_h2_2xx),
            ("h2", "3xx", &self.req_h2_3xx),
            ("h2", "4xx", &self.req_h2_4xx),
            ("h2", "5xx", &self.req_h2_5xx),
            ("h3", "1xx", &self.req_h3_1xx),
            ("h3", "2xx", &self.req_h3_2xx),
            ("h3", "3xx", &self.req_h3_3xx),
            ("h3", "4xx", &self.req_h3_4xx),
            ("h3", "5xx", &self.req_h3_5xx),
        ] {
            let v = ctr.load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "miraserve_http_requests_total{{protocol=\"{proto}\",status_class=\"{cls}\"}} {v}"
            );
        }

        let _ = writeln!(
            out,
            "# HELP miraserve_http_request_duration_seconds HTTP request latency histogram."
        );
        let _ = writeln!(
            out,
            "# TYPE miraserve_http_request_duration_seconds histogram"
        );
        for (idx, &bound) in LATENCY_BUCKETS_SECS.iter().enumerate() {
            let count = self
                .latency_buckets
                .get(idx)
                .map_or(0, |b| b.load(Ordering::Relaxed));
            let _ = writeln!(
                out,
                "miraserve_http_request_duration_seconds_bucket{{le=\"{bound}\"}} {count}"
            );
        }
        let total_count = self.latency_count.load(Ordering::Relaxed);
        #[allow(clippy::cast_precision_loss)]
        let total_secs = (self.latency_sum_micros.load(Ordering::Relaxed) as f64) / 1_000_000.0;
        let _ = writeln!(
            out,
            "miraserve_http_request_duration_seconds_bucket{{le=\"+Inf\"}} {total_count}"
        );
        let _ = writeln!(
            out,
            "miraserve_http_request_duration_seconds_sum {total_secs:.6}"
        );
        let _ = writeln!(
            out,
            "miraserve_http_request_duration_seconds_count {total_count}"
        );

        let _ = writeln!(
            out,
            "# HELP miraserve_active_connections Currently open client connections."
        );
        let _ = writeln!(out, "# TYPE miraserve_active_connections gauge");
        let _ = writeln!(
            out,
            "miraserve_active_connections {}",
            self.active_connections.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP miraserve_tls_handshakes_total Completed TLS handshakes by PQC hybrid and key isolation mode."
        );
        let _ = writeln!(out, "# TYPE miraserve_tls_handshakes_total counter");
        for (pqc, iso, ctr) in [
            ("true", "in-process", &self.tls_pqc_in_process),
            ("true", "split-daemon", &self.tls_pqc_split_keyd),
            ("false", "in-process", &self.tls_classical_in_process),
            ("false", "split-daemon", &self.tls_classical_split_keyd),
        ] {
            let _ = writeln!(
                out,
                "miraserve_tls_handshakes_total{{pqc=\"{pqc}\",isolation=\"{iso}\"}} {}",
                ctr.load(Ordering::Relaxed)
            );
        }

        let _ = writeln!(
            out,
            "# HELP miraserve_security_blocks_total Requests rejected by MiraServe security controls."
        );
        let _ = writeln!(out, "# TYPE miraserve_security_blocks_total counter");
        for (reason, ctr) in [
            ("rate_limit", &self.sec_rate_limit),
            ("anti_smuggling", &self.sec_anti_smuggling),
            ("site_preset", &self.sec_site_preset),
            ("bot_auth", &self.sec_bot_auth),
            ("mcp_rbac", &self.sec_mcp_rbac),
            ("wasm_sandbox", &self.sec_wasm_sandbox),
        ] {
            let _ = writeln!(
                out,
                "miraserve_security_blocks_total{{reason=\"{reason}\"}} {}",
                ctr.load(Ordering::Relaxed)
            );
        }

        let _ = writeln!(
            out,
            "# HELP miraserve_wasm_invocations_total Sandboxed WASM plugin executions by outcome."
        );
        let _ = writeln!(out, "# TYPE miraserve_wasm_invocations_total counter");
        for (outcome, ctr) in [
            ("ok", &self.wasm_ok),
            ("fuel_exhausted", &self.wasm_fuel_exhausted),
            ("memory_limit", &self.wasm_memory_limit),
            ("timeout", &self.wasm_timeout),
            ("trap", &self.wasm_trap),
        ] {
            let _ = writeln!(
                out,
                "miraserve_wasm_invocations_total{{outcome=\"{outcome}\"}} {}",
                ctr.load(Ordering::Relaxed)
            );
        }

        let _ = writeln!(
            out,
            "# HELP miraserve_wasm_fuel_consumed_total Cumulative Wasmtime CPU fuel consumed across plugins."
        );
        let _ = writeln!(out, "# TYPE miraserve_wasm_fuel_consumed_total counter");
        let _ = writeln!(
            out,
            "miraserve_wasm_fuel_consumed_total {}",
            self.wasm_fuel_total.load(Ordering::Relaxed)
        );

        let (fc_hits, fc_misses, fc_fills, fc_budget) = self.file_cache_counts();
        let _ = writeln!(
            out,
            "# HELP miraserve_file_cache_events_total Static file cache lookups and admissions by outcome."
        );
        let _ = writeln!(out, "# TYPE miraserve_file_cache_events_total counter");
        for (outcome, val) in [
            ("hit", fc_hits),
            ("miss", fc_misses),
            ("fill", fc_fills),
            ("not_cached_budget", fc_budget),
        ] {
            let _ = writeln!(
                out,
                "miraserve_file_cache_events_total{{outcome=\"{outcome}\"}} {val}"
            );
        }

        out
    }

    /// Serializes a snapshot of current metrics into an OpenTelemetry OTLP v1
    /// `ExportMetricsServiceRequest` JSON payload ready for `POST /v1/metrics`.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn to_otlp_metrics_json(&self, service_name: &str) -> Value {
        let now_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0_u128, |d| d.as_nanos())
            .to_string();
        let (fc_hits, fc_misses, fc_fills, fc_budget) = self.file_cache_counts();

        json!({
            "resourceMetrics": [
                {
                    "resource": {
                        "attributes": [
                            { "key": "service.name", "value": { "stringValue": service_name } },
                            { "key": "service.version", "value": { "stringValue": env!("CARGO_PKG_VERSION") } }
                        ]
                    },
                    "scopeMetrics": [
                        {
                            "scope": {
                                "name": "miraserve-telemetry",
                                "version": env!("CARGO_PKG_VERSION")
                            },
                            "metrics": [
                                {
                                    "name": "miraserve.http.requests",
                                    "unit": "1",
                                    "sum": {
                                        "isMonotonic": true,
                                        "aggregationTemporality": 2,
                                        "dataPoints": [
                                            {
                                                "timeUnixNano": now_nanos,
                                                "asInt": self.total_http_requests().to_string()
                                            }
                                        ]
                                    }
                                },
                                {
                                    "name": "miraserve.active_connections",
                                    "unit": "1",
                                    "gauge": {
                                        "dataPoints": [
                                            {
                                                "timeUnixNano": now_nanos,
                                                "asInt": self.active_connections.load(Ordering::Relaxed).to_string()
                                            }
                                        ]
                                    }
                                },
                                {
                                    "name": "miraserve.wasm.fuel_consumed",
                                    "unit": "1",
                                    "sum": {
                                        "isMonotonic": true,
                                        "aggregationTemporality": 2,
                                        "dataPoints": [
                                            {
                                                "timeUnixNano": now_nanos,
                                                "asInt": self.wasm_fuel_total.load(Ordering::Relaxed).to_string()
                                            }
                                        ]
                                    }
                                },
                                {
                                    "name": "miraserve.file_cache.events",
                                    "unit": "1",
                                    "sum": {
                                        "isMonotonic": true,
                                        "aggregationTemporality": 2,
                                        "dataPoints": [
                                            {
                                                "timeUnixNano": now_nanos,
                                                "asInt": fc_hits.to_string(),
                                                "attributes": [{ "key": "outcome", "value": { "stringValue": "hit" } }]
                                            },
                                            {
                                                "timeUnixNano": now_nanos,
                                                "asInt": fc_misses.to_string(),
                                                "attributes": [{ "key": "outcome", "value": { "stringValue": "miss" } }]
                                            },
                                            {
                                                "timeUnixNano": now_nanos,
                                                "asInt": fc_fills.to_string(),
                                                "attributes": [{ "key": "outcome", "value": { "stringValue": "fill" } }]
                                            },
                                            {
                                                "timeUnixNano": now_nanos,
                                                "asInt": fc_budget.to_string(),
                                                "attributes": [{ "key": "outcome", "value": { "stringValue": "not_cached_budget" } }]
                                            }
                                        ]
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        })
    }
}

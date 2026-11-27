#![forbid(unsafe_code)]
//! MiraServe listener supervisor: TCP/TLS (HTTP/1.1 & HTTP/2 with per-SNI `LazyConfigAcceptor`),
//! UDP/QUIC (HTTP/3 via `quinn` + `h3` with stateless Retry validation and stream caps),
//! HTTP->HTTPS redirect listeners, global connection caps, 2-phase atomic hot reload
//! (`SIGHUP` + programmatic API preserving ACME certs), and graceful connection drain.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use miraserve_config::{
    BindAddr, Config, ConfigError, ConfigStore, KeyIsolation, ListenConfig, Protocol, Workers,
};
pub use miraserve_http::{
    AccessLogSink, DiagnosticLogSink, H2ExecMode, H2ExecSelection, OffloadDrainOutcome,
    OffloadLogDrainReport, enqueue_offloaded_diagnostic_log, find_symlink_component,
    flush_offloaded_access_logs, flush_offloaded_access_logs_blocking,
    flush_offloaded_access_logs_until, flush_offloaded_access_logs_until_blocking,
    flush_offloaded_diagnostic_logs, flush_offloaded_diagnostic_logs_blocking,
    flush_offloaded_diagnostic_logs_until, flush_offloaded_diagnostic_logs_until_blocking,
    flush_offloaded_logs, flush_offloaded_logs_until, flush_offloaded_logs_until_blocking,
    offloaded_access_log_dropped, offloaded_diagnostic_log_dropped, select_h2_exec_mode,
    set_access_log_sink, write_or_offload_diagnostic_line,
};
use miraserve_http::{
    ConnectionControl, ConnectionIdleState, HttpEngine, HttpError, TlsConnectionInfo,
    serve_h3_connection_with_control, warm_nowait_kernel_probe,
};
pub use miraserve_http::{
    NonblockingStaticSupport, configured_credential_paths, credential_file_problem,
    credential_file_problem_for, enter_nonblocking_inline_context, enter_worker_loop_thread,
    handle_identities, in_nonblocking_inline_context, inline_work_must_not_block,
    kernel_supports_h2_intask_static, kernel_supports_nowait_read, nonblocking_static_support,
    open_root_probe, probe_nonblocking_static_support, read_no_symlink_file,
    read_no_symlink_file_opened, reserved_acme_tokens, scan_precompressed_siblings_no_follow,
    users_file_alias_problem, with_nonblocking_inline_context,
};
#[cfg(target_os = "linux")]
pub use miraserve_sandbox::probe_landlock_availability;
pub use miraserve_sandbox::{LANDLOCK_MIN_REQUIRED_ABI_VERSION, LandlockProbe};
pub use miraserve_sandbox::{
    LANDLOCK_TARGET_ABI_VERSION, LandlockEnforcement, LogDirBinding, Openat2AdvisoryLevel,
    PinnedLogDir, PinnedWritableDir, SandboxPolicy, WritableGrant, apply_landlock_current_thread,
    apply_seccomp_current_thread, bind_log_file_dir, check_docroot_classification_resources,
    classify_landlock_enforcement, config_has_static_work, detect_seccomp_filter_active,
    find_docroot_acme_overlaps, find_docroot_log_overlaps, find_docroot_pinned_log_overlaps,
    find_unsafe_docroots, find_unsafe_docroots_with_secret_files,
    is_quarantined_publish_storage_candidate, is_quarantined_socket_candidate,
    is_resource_io_error, log_path_platform_rejection, openat2_refusal_advisory_level,
    openat2_refused_advisory, openat2_refused_advisory_for_runtime,
    openat2_refused_advisory_for_runtime_with_static_work, probe_landlock_enforcement,
    probe_openat2_refused, setid_filtered_syscalls_for_mode,
    validate_writable_candidates_for_inspection, warm_kernel_release,
};
use miraserve_sandbox::{SandboxError, SandboxReport, apply_sandbox};
use miraserve_telemetry::{
    MetricsServer, OtlpExporter, RunningMetricsServer, TelemetryError, TelemetryRegistry,
};
use miraserve_tls::{
    AcmeChallengeStore, AcmeManager, DynamicCertResolver, EchRotationManager, GeneratedCertPem,
    TlsConfigSet, TlsError, build_crypto_provider, populate_resolver_from_config_with_keyd_secret,
};
use quinn::crypto::rustls::QuicServerConfig;
use socket2::{Domain, Protocol as SocketProtocol, Socket, Type as SocketType};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::{Notify, Semaphore, watch};
use tokio::task::JoinHandle;
use tokio_rustls::LazyConfigAcceptor;
use tracing::{debug, error, info, warn};

/// Default global concurrent connection cap across all HTTPS, HTTP/3, and redirect listeners.
const DEFAULT_MAX_GLOBAL_CONNECTIONS: usize = 16_384;

/// Maximum concurrent unidirectional streams permitted per QUIC connection (H3 control + QPACK).
const MAX_H3_UNI_STREAMS: u32 = 3;
/// QUIC flow-control credit per stream and per connection (the HTTP/2 windows).
const QUIC_STREAM_WINDOW: u32 = 256 * 1024;
const QUIC_CONNECTION_WINDOW: u32 = 4 * 1024 * 1024;

/// Errors produced while starting, reloading, or shutting down MiraServe.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Failed to bind a TCP or UDP network socket.
    #[error("failed to bind listener on '{addr}': {source}")]
    Bind {
        /// Address that failed to bind.
        addr: String,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },
    /// The new configuration is valid but cannot take effect without a process restart.
    #[error("restart required: {0}")]
    RestartRequired(String),
    /// Configuration error during load or hot reload.
    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),
    /// TLS certificate or crypto provider error.
    #[error("TLS error: {0}")]
    Tls(#[from] TlsError),
    /// HTTP router or upstream initialization error.
    #[error("HTTP engine error: {0}")]
    Http(#[from] HttpError),
    /// QUIC / HTTP/3 server configuration error.
    #[error("QUIC configuration error: {0}")]
    Quic(String),
    /// OS confinement (`Landlock` / `seccomp-bpf`) installation failure.
    #[error("OS sandbox error: {0}")]
    Sandbox(#[from] SandboxError),
    /// Telemetry metrics server error.
    #[error("telemetry error: {0}")]
    Telemetry(#[from] TelemetryError),
    /// Document root confinement violation (symlink into forbidden dir or overlap with ACME/keys/config, `R7-SBX-1`/`R7-SBX-2`).
    #[error("unsafe document root configuration: {0}")]
    UnsafeDocroot(String),
}

/// Startup options for [`MiraServeServer`].
#[derive(Clone, Default)]
pub struct ServerOptions {
    /// Automatically generate a self-signed ECDSA P-256 development certificate when no
    /// manual certificates or ACME config are present.
    pub dev_tls: bool,
    /// Optional path to the KDL config file (enables `SIGHUP` hot reload from disk).
    pub config_path: Option<PathBuf>,
    /// Optional directory for ACME v2 account credentials and issued certificates.
    pub acme_state_dir: Option<PathBuf>,
    /// Apply OS worker confinement (`Landlock` + `seccomp-bpf` on Linux) after binding sockets
    /// and BEFORE accepting any network connections.
    pub apply_sandbox: bool,
    /// Optional explicit 32-byte HMAC-SHA256 IPC secret for authenticating with `miraserve-keyd`
    /// over `LoopbackTcp` (if `None`, `KeydClient` falls back to `MIRASERVE_KEYD_AUTH_SECRET`).
    pub keyd_auth_secret: Option<[u8; 32]>,
    /// Secret files named only on the command line (the `--keyd-auth-secret-file` path). They
    /// are checked against every document root at startup and on every reload (`R8-SBX-1`).
    pub secret_file_paths: Vec<PathBuf>,
    /// Optional already-opened writable status file paired with `--pid-file` (`<pid-file>.reload`)
    /// where SIGHUP reload outcomes are recorded so `miraserve reload` reports actual success or
    /// failure (`R4-SBX-1`).
    pub reload_status_file: Option<Arc<Mutex<std::fs::File>>>,
    /// Optional emergency shutdown signal triggered if a post-startup worker thread fails OS
    /// sandbox confinement (`R2-SBX-3`).
    pub abort_signal: Option<Arc<Notify>>,
    /// All active CLI log file paths (`--log-file` and `--access-log`) checked for document-root
    /// overlap at startup and on every reload (Codex G7).
    pub log_file_paths: Vec<PathBuf>,
    /// Log file paths with size-based rotation enabled (`--log-max-bytes > 0`) whose validated
    /// parent directories need Landlock RW access for `rename()` + reopen (Codex G7).
    pub log_rotation_paths: Vec<PathBuf>,
    /// Optional pre-built, handle-pinned [`SandboxPolicy`] shared with Tokio worker threads so
    /// main-thread and worker-thread Landlock rules bind to the exact same directory descriptors.
    pub startup_sandbox_policy: Option<Arc<SandboxPolicy>>,
    /// Startup association between each configured CLI log path and its pinned directory handle
    /// so reloads detect any moved log alias and refuse to expose the original log directory as a
    /// document root (Codex Round-4 P1 #3).
    pub pinned_log_dirs: Vec<PinnedLogDir>,
}

impl std::fmt::Debug for ServerOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerOptions")
            .field("dev_tls", &self.dev_tls)
            .field("config_path", &self.config_path)
            .field("acme_state_dir", &self.acme_state_dir)
            .field("apply_sandbox", &self.apply_sandbox)
            .field(
                "keyd_auth_secret",
                &self.keyd_auth_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("secret_file_paths", &self.secret_file_paths)
            .field(
                "reload_status_file",
                &self.reload_status_file.as_ref().map(|_| "<open-file>"),
            )
            .field(
                "abort_signal",
                &self.abort_signal.as_ref().map(|_| "<notify>"),
            )
            .field("log_file_paths", &self.log_file_paths)
            .field("log_rotation_paths", &self.log_rotation_paths)
            .field(
                "startup_sandbox_policy",
                &self.startup_sandbox_policy.is_some(),
            )
            .field("pinned_log_dirs", &self.pinned_log_dirs.len())
            .finish()
    }
}

/// Transport role of a bound network listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerKind {
    /// TLS-terminated TCP listener serving HTTP/1.1 and/or HTTP/2.
    HttpsTcp,
    /// QUIC/UDP listener serving HTTP/3 (`h3`).
    Http3Udp,
    /// Plaintext TCP listener redirecting HTTP requests to HTTPS (and serving ACME HTTP-01).
    HttpRedirect,
}

/// Metadata for an active bound network socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundListener {
    /// Transport role.
    pub kind: ListenerKind,
    /// Local OS-assigned or configured socket address.
    pub local_addr: SocketAddr,
}

#[derive(Debug, Default)]
struct ActiveTracker {
    count: AtomicUsize,
    zero_notify: Notify,
}

impl ActiveTracker {
    fn acquire(self: &Arc<Self>) -> ActiveGuard {
        self.count.fetch_add(1, Ordering::AcqRel);
        ActiveGuard {
            tracker: Arc::clone(self),
        }
    }

    fn current(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }

    async fn wait_until_zero(&self) {
        while self.current() > 0 {
            let notified = self.zero_notify.notified();
            if self.current() == 0 {
                break;
            }
            notified.await;
        }
    }
}

struct ActiveGuard {
    tracker: Arc<ActiveTracker>,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        if self.tracker.count.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.tracker.zero_notify.notify_waiters();
        }
    }
}

/// Number of lock shards for per-IP concurrent connection tracking (`DOS-1`, `R5-DOS-1`).
const PER_IP_CONN_SHARDS: usize = 16;

/// Reason a peer connection was rejected by MiraServe's connection caps (`R5-DOS-1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnCapReason {
    Global,
    PerIp,
    Ipv6Prefix48,
}

/// Canonical per-client key for connection caps (IPv4 `/32` or IPv6 `/64` prefix).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum IpConnKey {
    V4([u8; 4]),
    V6Prefix64(u64),
}

impl IpConnKey {
    fn from_ip(ip: IpAddr) -> (Self, Option<u64>) {
        match ip.to_canonical() {
            IpAddr::V4(v4) => (Self::V4(v4.octets()), None),
            IpAddr::V6(v6) => {
                let raw = u128::from(v6);
                let prefix64 = u64::try_from(raw >> 64).unwrap_or(0);
                // Top 48 bits of the IPv6 address for `/48` aggregate capping (`R5-DOS-1`).
                let prefix48 = u64::try_from(raw >> 80).unwrap_or(0);
                (Self::V6Prefix64(prefix64), Some(prefix48))
            }
        }
    }

    fn shard_index(self) -> usize {
        let mix = match self {
            Self::V4(b) => u64::from(u32::from_be_bytes(b)),
            Self::V6Prefix64(p) => p ^ (p >> 32),
        };
        usize::try_from(mix.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 60).unwrap_or(0)
            % PER_IP_CONN_SHARDS
    }
}

fn prefix48_shard_index(prefix48: u64) -> usize {
    let mix = prefix48 ^ (prefix48 >> 24);
    usize::try_from(mix.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 60).unwrap_or(0) % PER_IP_CONN_SHARDS
}

/// Per-connection slot tracked by [`PerIpConnTracker`] so an IP hitting
/// `limits.max-connections-per-ip` can evict its oldest idle keep-alive connection instead of
/// locking itself out across sites and port 80 while active/in-flight DoS still hits the cap.
#[derive(Debug)]
struct PerIpSlot {
    id: u64,
    idle_state: Arc<ConnectionIdleState>,
    evict_tx: watch::Sender<bool>,
    evicted: AtomicBool,
}

/// Sharded RAII per-IP and IPv6 `/48` aggregate concurrent connection tracker enforcing
/// `limits.max-connections-per-ip` (`DOS-1`, `R5-DOS-1`, zero `unsafe`) with oldest-idle
/// keep-alive eviction.
#[derive(Debug)]
struct PerIpConnTracker {
    next_id: AtomicU64,
    shards: [Mutex<std::collections::HashMap<IpConnKey, Vec<Arc<PerIpSlot>>>>; PER_IP_CONN_SHARDS],
    /// Evicted connections of an address that have not ended yet. An evicted connection gives
    /// its place to the new one at once but may live on (a request that arrived meanwhile, an
    /// upgraded tunnel): while as many of them as the address's limit are still around, nothing
    /// more of that address is evicted, so it never holds more than twice its limit.
    draining_shards: [Mutex<std::collections::HashMap<IpConnKey, u32>>; PER_IP_CONN_SHARDS],
    /// The same per IPv6 /48.
    draining48_shards: [Mutex<std::collections::HashMap<u64, u32>>; PER_IP_CONN_SHARDS],
    v6_prefix48_shards: [Mutex<std::collections::HashMap<u64, u32>>; PER_IP_CONN_SHARDS],
}

impl Default for PerIpConnTracker {
    fn default() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            shards: std::array::from_fn(|_| Mutex::new(std::collections::HashMap::new())),
            draining_shards: std::array::from_fn(|_| Mutex::new(std::collections::HashMap::new())),
            draining48_shards: std::array::from_fn(
                |_| Mutex::new(std::collections::HashMap::new()),
            ),
            v6_prefix48_shards: std::array::from_fn(|_| {
                Mutex::new(std::collections::HashMap::new())
            }),
        }
    }
}

struct PerIpConnLease {
    guard: PerIpConnGuard,
    idle_state: Arc<ConnectionIdleState>,
    evict_rx: watch::Receiver<bool>,
}

/// Picks the index of the oldest currently-idle keep-alive slot (`idle_since_ms > 0`), if any.
fn find_oldest_idle_slot(slots: &[Arc<PerIpSlot>]) -> Option<usize> {
    let mut best: Option<(usize, u64)> = None;
    for (idx, slot) in slots.iter().enumerate() {
        let ts = slot.idle_state.idle_since_ms();
        if ts > 0 && best.is_none_or(|(_, best_ts)| ts < best_ts) {
            best = Some((idx, ts));
        }
    }
    best.map(|(idx, _)| idx)
}

impl PerIpConnTracker {
    /// Counts one more evicted connection of `key` still around; `false` (nothing counted)
    /// when there are `limit` of them already, or as many of its IPv6 /48 as that may have
    /// connections (the evictions of many /64s of one /48 add up otherwise).
    fn start_draining(
        &self,
        shard_idx: usize,
        key: IpConnKey,
        limit: usize,
        prefix48: Option<(u64, u32)>,
    ) -> bool {
        let Some(lock) = self.draining_shards.get(shard_idx) else {
            return false;
        };
        let mut map = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Nothing is entered in either map unless both have room.
        let draining = map.get(&key).copied().unwrap_or(0);
        if usize::try_from(draining).unwrap_or(usize::MAX) >= limit {
            return false;
        }
        if let Some((prefix48, p48_limit)) = prefix48 {
            let Some(lock48) = self.draining48_shards.get(prefix48_shard_index(prefix48)) else {
                return false;
            };
            let mut map48 = lock48
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let draining48 = map48.get(&prefix48).copied().unwrap_or(0);
            if draining48 >= p48_limit {
                return false;
            }
            map48.insert(prefix48, draining48.saturating_add(1));
        }
        map.insert(key, draining.saturating_add(1));
        true
    }

    /// An evicted connection of `key` has ended.
    fn end_draining(&self, shard_idx: usize, key: IpConnKey, prefix48: Option<u64>) {
        if let Some(lock) = self.draining_shards.get(shard_idx) {
            let mut map = lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(draining) = map.get_mut(&key) {
                *draining = draining.saturating_sub(1);
                if *draining == 0 {
                    map.remove(&key);
                }
            }
        }
        if let Some(prefix48) = prefix48
            && let Some(lock48) = self.draining48_shards.get(prefix48_shard_index(prefix48))
        {
            let mut map48 = lock48
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(draining) = map48.get_mut(&prefix48) {
                *draining = draining.saturating_sub(1);
                if *draining == 0 {
                    map48.remove(&prefix48);
                }
            }
        }
    }

    fn try_acquire(
        self: &Arc<Self>,
        ip: IpAddr,
        max_per_ip: u32,
        ipv6_prefix_mult: u32,
    ) -> Result<PerIpConnLease, ConnCapReason> {
        let limit = usize::try_from(max_per_ip.max(1)).unwrap_or(1);
        let (key, maybe_prefix48) = IpConnKey::from_ip(ip);
        let shard_idx = key.shard_index();
        let Some(shard_lock) = self.shards.get(shard_idx) else {
            return Err(ConnCapReason::PerIp);
        };
        // An IPv6 /48 may have as many evicted connections still around as connections.
        let p48_limit = max_per_ip.max(1).saturating_mul(ipv6_prefix_mult.max(1));
        let draining48 = maybe_prefix48.map(|prefix48| (prefix48, p48_limit));

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let idle_state = Arc::new(ConnectionIdleState::new());
        let (evict_tx, evict_rx) = watch::channel(false);
        let slot = Arc::new(PerIpSlot {
            id,
            idle_state: Arc::clone(&idle_state),
            evict_tx,
            evicted: AtomicBool::new(false),
        });

        let mut evicted_victim: Option<Arc<PerIpSlot>> = None;
        {
            let mut map = match shard_lock.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            let slots = map.entry(key).or_default();
            if slots.len() >= limit {
                let Some(victim_idx) = find_oldest_idle_slot(slots) else {
                    return Err(ConnCapReason::PerIp);
                };
                if !self.start_draining(shard_idx, key, limit, draining48) {
                    return Err(ConnCapReason::PerIp);
                }
                let victim = slots.swap_remove(victim_idx);
                victim.evicted.store(true, Ordering::Release);
                slots.push(Arc::clone(&slot));
                evicted_victim = Some(victim);
            } else {
                slots.push(Arc::clone(&slot));
            }
        }

        // For non-IPv4-mapped IPv6 addresses, also enforce an aggregate `/48` cap
        // (`ipv6-prefix-conn-multiplier * max-connections-per-ip`, default `4x`, `R5-DOS-1`/`R6-DOS-2`).
        // If we already evicted a same-`/64` idle slot above, we inherit its `/48` slot directly.
        let v6_prefix48 = if let Some(prefix48) = maybe_prefix48 {
            let p48_shard_idx = prefix48_shard_index(prefix48);
            if evicted_victim.is_none() {
                let acquired_p48 = self.v6_prefix48_shards.get(p48_shard_idx).is_some_and(|l| {
                    let mut map = match l.lock() {
                        Ok(guard) => guard,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    let cur = map.get(&prefix48).copied().unwrap_or(0);
                    if cur >= p48_limit {
                        false
                    } else {
                        map.insert(prefix48, cur.saturating_add(1));
                        true
                    }
                });
                if !acquired_p48 {
                    // Before rejecting on `/48` aggregate cap, check if THIS `/64` has an idle
                    // keep-alive slot we can evict and inherit its `/48` slot cleanly.
                    let mut map = match shard_lock.lock() {
                        Ok(guard) => guard,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    let mut transferred = false;
                    if let Some(slots) = map.get_mut(&key) {
                        // Exclude the newly pushed `slot` (which is active, idle_since_ms == 0).
                        if let Some(victim_idx) = find_oldest_idle_slot(slots)
                            && self.start_draining(shard_idx, key, limit, draining48)
                        {
                            let victim = slots.swap_remove(victim_idx);
                            victim.evicted.store(true, Ordering::Release);
                            evicted_victim = Some(victim);
                            transferred = true;
                        } else {
                            slots.retain(|s| s.id != id);
                            if slots.is_empty() {
                                map.remove(&key);
                            }
                        }
                    }
                    if !transferred {
                        return Err(ConnCapReason::Ipv6Prefix48);
                    }
                }
            }
            Some((p48_shard_idx, prefix48))
        } else {
            None
        };

        if let Some(victim) = evicted_victim {
            let _ = victim.evict_tx.send(true);
        }

        Ok(PerIpConnLease {
            guard: PerIpConnGuard {
                tracker: Arc::clone(self),
                shard_idx,
                key,
                slot,
                v6_prefix48,
            },
            idle_state,
            evict_rx,
        })
    }
}

struct PerIpConnGuard {
    tracker: Arc<PerIpConnTracker>,
    shard_idx: usize,
    key: IpConnKey,
    slot: Arc<PerIpSlot>,
    v6_prefix48: Option<(usize, u64)>,
}

impl Drop for PerIpConnGuard {
    fn drop(&mut self) {
        let mut was_evicted = self.slot.evicted.load(Ordering::Acquire);
        if !was_evicted && let Some(shard_lock) = self.tracker.shards.get(self.shard_idx) {
            let mut map = match shard_lock.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            // Re-check `evicted` under the shard lock so we NEVER double-decrement `/48`
            // if a replacement connection just inherited our slot.
            was_evicted = self.slot.evicted.load(Ordering::Acquire);
            if !was_evicted && let Some(slots) = map.get_mut(&self.key) {
                slots.retain(|s| s.id != self.slot.id);
                if slots.is_empty() {
                    map.remove(&self.key);
                }
            }
        }
        if was_evicted {
            // Its place went to the connection that evicted it; now it is gone itself.
            self.tracker.end_draining(
                self.shard_idx,
                self.key,
                self.v6_prefix48.map(|(_, prefix48)| prefix48),
            );
        }
        if !was_evicted
            && let Some((p48_shard_idx, prefix48)) = self.v6_prefix48
            && let Some(shard_lock) = self.tracker.v6_prefix48_shards.get(p48_shard_idx)
        {
            let mut map = match shard_lock.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Some(count) = map.get_mut(&prefix48) {
                if *count <= 1 {
                    map.remove(&prefix48);
                } else {
                    *count -= 1;
                }
            }
        }
    }
}

/// Shared RAII connection lease kept alive across the HTTP connection AND any upgraded
/// WebSocket tunnel spawned from it so graceful shutdown counts/drains upgraded tunnels,
/// telemetry stays accurate, and global/per-IP connection caps remain exact.
struct ConnectionLease {
    _per_ip_guard: Option<PerIpConnGuard>,
    _permit: tokio::sync::OwnedSemaphorePermit,
    _active_guard: ActiveGuard,
    telemetry: Arc<TelemetryRegistry>,
    counted_in_telemetry: AtomicBool,
}

impl ConnectionLease {
    fn new(
        per_ip_guard: Option<PerIpConnGuard>,
        permit: tokio::sync::OwnedSemaphorePermit,
        active_guard: ActiveGuard,
        telemetry: Arc<TelemetryRegistry>,
    ) -> Self {
        Self {
            _per_ip_guard: per_ip_guard,
            _permit: permit,
            _active_guard: active_guard,
            telemetry,
            counted_in_telemetry: AtomicBool::new(false),
        }
    }

    fn mark_telemetry_active(&self) {
        if !self.counted_in_telemetry.swap(true, Ordering::AcqRel) {
            self.telemetry.inc_active_connections();
        }
    }
}

impl Drop for ConnectionLease {
    fn drop(&mut self) {
        if self.counted_in_telemetry.swap(false, Ordering::AcqRel) {
            self.telemetry.dec_active_connections();
        }
    }
}

/// Shared RAII connection lease for redirect-listener connections (`spawn_redirect_loop`),
/// kept alive across both the HTTP/1.1 connection and any upgraded WebSocket tunnel spawned
/// by an `http "serve"` site.
///
/// Field declaration order preserves the exact v0.1.2 LIFO release order of `spawn_redirect_loop`'s
/// local guards: `Drop::drop` decrements active-connection telemetry first, then `_active_guard`
/// (active/drain guard), then `_permit` (global semaphore permit), then `_per_ip_guard`
/// (per-address slot). Releasing a contended per-IP shard lock therefore never holds the global
/// permit or active/drain guard.
struct RedirectConnectionLease {
    _active_guard: ActiveGuard,
    _permit: tokio::sync::OwnedSemaphorePermit,
    _per_ip_guard: Option<PerIpConnGuard>,
    telemetry: Arc<TelemetryRegistry>,
    counted_in_telemetry: AtomicBool,
}

impl RedirectConnectionLease {
    fn new(
        active_guard: ActiveGuard,
        permit: tokio::sync::OwnedSemaphorePermit,
        per_ip_guard: Option<PerIpConnGuard>,
        telemetry: Arc<TelemetryRegistry>,
    ) -> Self {
        Self {
            _active_guard: active_guard,
            _permit: permit,
            _per_ip_guard: per_ip_guard,
            telemetry,
            counted_in_telemetry: AtomicBool::new(false),
        }
    }

    fn mark_telemetry_active(&self) {
        if !self.counted_in_telemetry.swap(true, Ordering::AcqRel) {
            self.telemetry.inc_active_connections();
        }
    }
}

impl Drop for RedirectConnectionLease {
    fn drop(&mut self) {
        if self.counted_in_telemetry.swap(false, Ordering::AcqRel) {
            self.telemetry.dec_active_connections();
        }
    }
}

enum PendingListener {
    Redirect(TcpListener, u16),
    /// The last field: one more socket on the same address for each event loop after the
    /// first (`workers`), bound with `SO_REUSEPORT` before the sandbox is applied.
    HttpsTcp(
        TcpListener,
        u16,
        Arc<TlsConfigSet>,
        Vec<std::net::TcpListener>,
    ),
    Http3Udp(quinn::Endpoint, u16),
}

/// Entrypoint for booting a MiraServe server instance.
pub struct MiraServeServer;

impl MiraServeServer {
    /// Binds all configured TCP/TLS, UDP/QUIC (HTTP/3), and redirect listeners, applies OS
    /// worker confinement BEFORE accepting any traffic, and spawns bounded accept loops.
    ///
    /// # Errors
    /// Returns [`CoreError`] if certificates, router handlers, QUIC configs, sandbox, or sockets fail.
    #[allow(clippy::too_many_lines)]
    pub async fn start(
        store: Arc<ConfigStore>,
        options: ServerOptions,
    ) -> Result<RunningServer, CoreError> {
        let mut initial_config = store.snapshot();
        // R6-SBX-1, R7-SBX-1, R7-SBX-2 & Section 5: Enforce uniform docroot confinement at
        // startup (blocking symlinks into forbidden dirs and overlaps with ACME/keys/config/publish).
        let effective_acme = effective_acme_dir_for_checks(&initial_config, &options);
        let startup_checks = |cfg: &Config| {
            let mut violations = find_unsafe_docroots_with_secret_files(
                cfg,
                options.config_path.as_deref(),
                effective_acme,
                &options.secret_file_paths,
            );
            violations.extend(find_docroot_log_overlaps(
                cfg,
                &options.log_file_paths,
                &options.log_rotation_paths,
            ));
            violations
        };
        let mut checked = (*initial_config).clone();
        quarantine_inaccessible_tenant_roots(&mut checked);
        let docroot_violations = quarantine_unsafe_sites(&mut checked, startup_checks);
        if !docroot_violations.is_empty() {
            return Err(CoreError::UnsafeDocroot(docroot_violations.join("; ")));
        }
        if checked.sites.iter().any(|site| site.quarantine.is_some()) {
            store.swap(checked);
            initial_config = store.snapshot();
        }
        // Tenant sites whose sandbox grants fail are quarantined NOW, before TLS and the HTTP
        // engine are built from the configuration, so everything serves the same configuration
        // (the policy built here is the one applied below).
        let mut early_policy = if options.apply_sandbox && options.startup_sandbox_policy.is_none()
        {
            let mut tenant_checked = (*initial_config).clone();
            let policy = prepare_startup_policy(&mut tenant_checked, &|cfg: &Config| {
                SandboxPolicy::from_config_with_file(
                    cfg,
                    options.config_path.as_deref(),
                    options.acme_state_dir.as_deref(),
                )
            });
            if tenant_checked != *initial_config {
                store.swap(tenant_checked);
                initial_config = store.snapshot();
            }
            Some(policy)
        } else {
            None
        };
        // Codex G7 & Round-5 P1 #1: validate rotating log directories with the EXACT same rule
        // as reload and keep each configured log associated with its validated directory handle.
        let startup_pinned_log_dirs =
            bind_startup_log_dirs(&initial_config, &options, effective_acme)?;

        let acme_store = Arc::new(AcmeChallengeStore::new());
        let resolver = Arc::new(DynamicCertResolver::new(Arc::clone(&acme_store)));

        let dev_cert = populate_resolver_from_config_with_keyd_secret(
            &resolver,
            &initial_config,
            options.dev_tls,
            options.keyd_auth_secret,
        )?;

        // Load any previously cached ACME certificates from disk if configured.
        load_cached_acme_certs_into(&resolver, &acme_store, &initial_config, &options);

        // Determine initial HTTPS target port and H3 Alt-Svc port from config.
        let https_port = initial_config
            .server
            .listeners
            .iter()
            .find(|l| !l.redirect_https)
            .map_or(443, |l| l.addr.port);
        let h3_port = initial_config
            .server
            .listeners
            .iter()
            .find(|l| !l.redirect_https && l.protocols.contains(&Protocol::H3))
            .map(|l| l.addr.port);

        // This server's credentials outside its configuration: command-line secrets (the keyd
        // shared secret). The ACME state is the server's own (written by its account, never
        // linkable by a tenant where `fs.protected_hardlinks` is on) and outside every root.
        warn_if_hardlinks_unprotected();
        if let Some(webroot) = &initial_config.server.acme_webroot
            && let Some(problem) = replaceable_ancestor(
                &std::path::Path::new(webroot)
                    .join(".well-known")
                    .join("acme-challenge")
                    .join("token"),
            )
        {
            warn!(
                acme_webroot = %webroot,
                problem = %problem,
                "an account other than root could replace the acme-webroot challenge directory; keep every parent directory root-owned and not group/other-writable"
            );
        }
        if let Some(webroot) = &initial_config.server.acme_webroot
            && !std::path::Path::new(webroot).is_dir()
        {
            warn!(
                acme_webroot = %webroot,
                "acme-webroot does not exist: the sandbox cannot grant it, so HTTP-01 tokens written there later are not served until MiraServe restarts; create it before starting"
            );
        }
        let credentials = miraserve_http::CredentialSources {
            files: options.secret_file_paths.clone(),
            dirs: Vec::new(),
        };
        let engine = Arc::new(HttpEngine::from_config_with_credentials(
            &initial_config,
            Arc::clone(&acme_store),
            h3_port,
            https_port,
            credentials,
        )?);

        // Initialize RFC 9849 ECH key-ring & rotation manager if enabled.
        let ech_manager = if initial_config.server.tls.ech {
            let public_name = initial_config
                .server
                .tls
                .ech_public_name
                .clone()
                .or_else(|| {
                    initial_config
                        .sites
                        .first()
                        .and_then(|s| s.hosts.first())
                        .cloned()
                })
                .unwrap_or_else(|| "localhost".to_owned());
            let mgr = Arc::new(EchRotationManager::new(
                public_name,
                initial_config.server.tls.ech_rotate_interval,
            )?);
            if let Ok(snap) = mgr.public_snapshot() {
                info!(
                    config_id = snap.active_config_id,
                    public_name = %snap.public_name,
                    dns_https = %snap.dns_https_record,
                    "initialized RFC 9849 ECH rotation manager"
                );
            }
            Some(mgr)
        } else {
            None
        };

        // Phase A: Bind all TCP/UDP sockets BEFORE installing sandbox confinement.
        // Bare `":port"` binds dual-stack (`0.0.0.0:port` + `[::]:port` with `IPV6_V6ONLY = true`),
        // falling back gracefully to IPv4-only if the host kernel has IPv6 disabled.
        let mut bound_listeners = Vec::new();
        // How many event loops serve HTTPS over TCP besides the shared runtime (`workers`).
        let event_loops = event_loop_count(
            initial_config.server.workers,
            initial_config.server.tls.key_isolation,
        );
        let mut pending_listeners = Vec::new();
        let mut quic_endpoints = Vec::new();

        for listen in &initial_config.server.listeners {
            let bind_targets = expand_bind_targets(&listen.addr);

            if listen.redirect_https {
                for (sock_addr, optional_v6) in bind_targets {
                    let tcp = match bind_tcp_socket(sock_addr, false) {
                        Ok(t) => t,
                        Err(err) if optional_v6 && is_ipv6_unavailable(&err) => {
                            warn!(
                                addr = %sock_addr,
                                error = %err,
                                "IPv6 unavailable on this host; HTTP redirect listener serving IPv4 only"
                            );
                            continue;
                        }
                        Err(source) => {
                            return Err(CoreError::Bind {
                                addr: sock_addr.to_string(),
                                source,
                            });
                        }
                    };
                    let local_addr = tcp.local_addr().map_err(|source| CoreError::Bind {
                        addr: sock_addr.to_string(),
                        source,
                    })?;
                    info!(addr = %local_addr, "bound HTTP -> HTTPS redirect listener");
                    bound_listeners.push(BoundListener {
                        kind: ListenerKind::HttpRedirect,
                        local_addr,
                    });
                    pending_listeners.push(PendingListener::Redirect(tcp, local_addr.port()));
                }
                continue;
            }

            let tls_set = Arc::new(TlsConfigSet::build_with_config(
                Arc::clone(&resolver),
                &listen.protocols,
                Some(&initial_config),
            )?);

            let wants_tcp = listen.protocols.contains(&Protocol::H1)
                || listen.protocols.contains(&Protocol::H2);
            let wants_h3 = listen.protocols.contains(&Protocol::H3);

            for (sock_addr, optional_v6) in bind_targets {
                if wants_tcp {
                    let tcp = match bind_tcp_socket(sock_addr, event_loops > 0) {
                        Ok(t) => t,
                        Err(err) if optional_v6 && is_ipv6_unavailable(&err) => {
                            warn!(
                                addr = %sock_addr,
                                error = %err,
                                "IPv6 unavailable on this host; HTTPS TCP listener serving IPv4 only"
                            );
                            continue;
                        }
                        Err(source) => {
                            return Err(CoreError::Bind {
                                addr: sock_addr.to_string(),
                                source,
                            });
                        }
                    };
                    let local_addr = tcp.local_addr().map_err(|source| CoreError::Bind {
                        addr: sock_addr.to_string(),
                        source,
                    })?;
                    info!(
                        addr = %local_addr,
                        protocols = ?listen.protocols,
                        "bound HTTPS TCP listener (TLS 1.3 + PQC)"
                    );
                    bound_listeners.push(BoundListener {
                        kind: ListenerKind::HttpsTcp,
                        local_addr,
                    });
                    // The other event loops' sockets, on the address that was bound (the
                    // port may have been chosen by the system).
                    let mut more = Vec::new();
                    for _ in 1..event_loops {
                        more.push(bind_reuseport_std(local_addr).map_err(|source| {
                            CoreError::Bind {
                                addr: local_addr.to_string(),
                                source,
                            }
                        })?);
                    }
                    pending_listeners.push(PendingListener::HttpsTcp(
                        tcp,
                        local_addr.port(),
                        Arc::clone(&tls_set),
                        more,
                    ));
                }

                if wants_h3 {
                    let quic_cfg = build_quinn_server_config(&tls_set, &initial_config)?;
                    let endpoint = match bind_udp_quinn_endpoint(quic_cfg, sock_addr) {
                        Ok(ep) => ep,
                        Err(err) if optional_v6 && is_ipv6_unavailable(&err) => {
                            warn!(
                                addr = %sock_addr,
                                error = %err,
                                "IPv6 unavailable on this host; HTTP/3 QUIC listener serving IPv4 only"
                            );
                            continue;
                        }
                        Err(source) => {
                            return Err(CoreError::Bind {
                                addr: format!("udp://{sock_addr}"),
                                source,
                            });
                        }
                    };
                    let local_addr = endpoint.local_addr().map_err(|source| CoreError::Bind {
                        addr: format!("udp://{sock_addr}"),
                        source,
                    })?;
                    info!(addr = %local_addr, "bound HTTP/3 QUIC UDP listener (TLS 1.3 + PQC)");
                    bound_listeners.push(BoundListener {
                        kind: ListenerKind::Http3Udp,
                        local_addr,
                    });
                    quic_endpoints.push(endpoint.clone());
                    pending_listeners.push(PendingListener::Http3Udp(endpoint, local_addr.port()));
                }
            }
        }

        // Update Alt-Svc and redirect ports to actual bound local ports (handles ephemeral ports).
        if let Some(first_https) = bound_listeners
            .iter()
            .find(|b| b.kind == ListenerKind::HttpsTcp)
        {
            engine.set_https_redirect_port(first_https.local_addr.port());
        }
        let actual_h3_port = bound_listeners
            .iter()
            .find(|b| b.kind == ListenerKind::Http3Udp)
            .map(|b| b.local_addr.port());
        engine.set_alt_svc_h3_port(actual_h3_port);

        // Start dedicated Prometheus scrape listener if configured (bind before sandbox).
        let metrics_server =
            if let Some(metrics_bind) = &initial_config.server.telemetry.metrics_listen {
                let sock = bind_addr_to_socket_addr(metrics_bind);
                Some(
                    MetricsServer::start(
                        sock,
                        initial_config.server.telemetry.metrics_path.clone(),
                        Arc::clone(engine.telemetry()),
                    )
                    .await?,
                )
            } else {
                None
            };

        // Initialize OTLP exporter TLS client BEFORE sandbox so system trust stores remain readable (`TEL-1`).
        let otlp_exporter = if let Some(endpoint) = &initial_config.server.telemetry.otlp_endpoint {
            Some(OtlpExporter::new(
                endpoint,
                initial_config.server.telemetry.service_name.clone(),
            )?)
        } else {
            None
        };

        // Sample whether an outer seccomp filter (e.g. systemd or container) is already attached
        // BEFORE Phase B installs MiraServe's own seccomp filter, so the startup `openat2` probe
        // can distinguish `ENOSYS` on a pre-5.6 kernel (`Seccomp: 0`) from an outer filter.
        let had_outer_seccomp = detect_seccomp_filter_active();
        // Warm `/proc/sys/kernel/osrelease` before Landlock restricts `/proc`, even when the
        // configuration has no static routes, so neither the startup HTTP/2 selection nor the
        // post-sandbox advisory re-reads `/proc` under Landlock.
        warm_nowait_kernel_probe();
        warm_kernel_release();

        // Phase B: Apply OS confinement STRICTLY AFTER binding sockets and BEFORE spawning
        // any network accept loops (closes pre-sandbox connection window!).
        // R3-SBX-1: Uses the exact same `SandboxPolicy::from_config_with_file` builder used by
        // worker `on_thread_start`, so main-thread SIGHUP reloads and worker threads share one policy.
        let (sandbox_report, startup_sandbox_policy) = if options.apply_sandbox {
            let policy = if let Some(pre_pinned) = &options.startup_sandbox_policy {
                (**pre_pinned).clone()
            } else {
                let mut built = early_policy.take().unwrap_or_else(|| {
                    SandboxPolicy::from_config_with_file(
                        &initial_config,
                        options.config_path.as_deref(),
                        options.acme_state_dir.as_deref(),
                    )
                });
                for log_path in &options.log_rotation_paths {
                    if let Err(reason) = built.allow_log_rotation_dir_with_context(
                        log_path,
                        &initial_config,
                        options.config_path.as_deref(),
                        effective_acme,
                        &options.secret_file_paths,
                    ) {
                        return Err(CoreError::UnsafeDocroot(reason));
                    }
                }
                built.finalize_grants()?;
                built
            };
            let report = apply_sandbox(&policy)?;
            (Some(report), Some(policy))
        } else {
            (None, None)
        };

        let sandbox_label = match &sandbox_report {
            Some(rep)
                if matches!(
                    rep.landlock,
                    miraserve_sandbox::EnforcementStatus::Enforced
                        | miraserve_sandbox::EnforcementStatus::PartiallyEnforced
                ) || matches!(
                    rep.seccomp,
                    miraserve_sandbox::EnforcementStatus::Enforced
                        | miraserve_sandbox::EnforcementStatus::PartiallyEnforced
                ) =>
            {
                "Enabled"
            }
            Some(rep)
                if matches!(
                    rep.landlock,
                    miraserve_sandbox::EnforcementStatus::UnsupportedPlatform
                ) =>
            {
                "Filesystem confined"
            }
            _ => "Not enabled",
        };
        engine.set_sandbox_state(sandbox_label);

        let h2_selection = engine.select_h2_exec_mode();
        info!(
            mode = %h2_selection.mode.as_str(),
            reason = %h2_selection.reason,
            "HTTP/2 stream execution mode selected"
        );

        if let Some(advisory) = openat2_refused_advisory_for_runtime_with_static_work(
            &initial_config,
            sandbox_report.as_ref(),
            had_outer_seccomp,
            engine.has_static_work(),
        ) {
            emit_openat2_refused_advisory(&initial_config, &advisory);
        }

        // Phase C: Spawn globally and per-IP connection-bounded accept loops and background supervisors.
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (upgrade_force_close_tx, upgrade_force_close_rx) = watch::channel(false);
        let tracker = Arc::new(ActiveTracker::default());
        let max_global_conns = usize::try_from(initial_config.server.limits.max_connections.max(1))
            .unwrap_or(DEFAULT_MAX_GLOBAL_CONNECTIONS);
        let conn_sem = Arc::new(Semaphore::new(max_global_conns));
        let per_ip_tracker = Arc::new(PerIpConnTracker::default());
        let mut listener_tasks = Vec::with_capacity(pending_listeners.len());
        let mut background_tasks = Vec::new();
        // With `workers`: what each event loop listens on, filled below.
        let mut loop_listeners: Vec<Vec<LoopListener>> =
            (0..event_loops).map(|_| Vec::new()).collect();
        let (workers_exit_tx, workers_exit_rx) = watch::channel(false);

        for listener in pending_listeners {
            match listener {
                PendingListener::Redirect(tcp, local_port) => {
                    listener_tasks.push(spawn_redirect_loop(
                        tcp,
                        local_port,
                        Arc::clone(&store),
                        Arc::clone(&engine),
                        Arc::clone(&tracker),
                        Arc::clone(&conn_sem),
                        Arc::clone(&per_ip_tracker),
                        shutdown_rx.clone(),
                        upgrade_force_close_rx.clone(),
                    ));
                }
                PendingListener::HttpsTcp(tcp, local_port, tls_set, more) if event_loops > 0 => {
                    let first = tcp.into_std().map_err(|source| CoreError::Bind {
                        addr: format!("port {local_port}"),
                        source,
                    })?;
                    for (slot, socket) in loop_listeners
                        .iter_mut()
                        .zip(std::iter::once(first).chain(more))
                    {
                        slot.push((socket, local_port, Arc::clone(&tls_set)));
                    }
                }
                PendingListener::HttpsTcp(tcp, local_port, tls_set, _) => {
                    listener_tasks.push(spawn_https_tcp_loop(
                        tcp,
                        local_port,
                        Arc::clone(&store),
                        tls_set,
                        Arc::clone(&engine),
                        Arc::clone(&tracker),
                        Arc::clone(&conn_sem),
                        Arc::clone(&per_ip_tracker),
                        shutdown_rx.clone(),
                        upgrade_force_close_rx.clone(),
                    ));
                }
                PendingListener::Http3Udp(endpoint, local_port) => {
                    listener_tasks.push(spawn_h3_udp_loop(
                        endpoint,
                        local_port,
                        Arc::clone(&store),
                        Arc::clone(&engine),
                        Arc::clone(&tracker),
                        Arc::clone(&conn_sem),
                        Arc::clone(&per_ip_tracker),
                        shutdown_rx.clone(),
                    ));
                }
            }
        }

        let mut worker_threads = Vec::new();
        if event_loops > 0 {
            info!(
                event_loops,
                "HTTPS over TCP is served by one event loop per worker thread (workers)"
            );
            let shared = LoopShared {
                store: Arc::clone(&store),
                engine: Arc::clone(&engine),
                tracker: Arc::clone(&tracker),
                conn_sem: Arc::clone(&conn_sem),
                per_ip_tracker: Arc::clone(&per_ip_tracker),
                shutdown: shutdown_rx.clone(),
                upgrade_force_close: upgrade_force_close_rx.clone(),
                exit: workers_exit_rx,
                landlock: startup_sandbox_policy
                    .as_ref()
                    .filter(|policy| policy.landlock)
                    .map(|policy| Arc::new(policy.clone())),
                worker_count: event_loops,
            };
            let mut spawned_workers = Vec::with_capacity(event_loops);
            let mut start_err: Option<CoreError> = None;
            for (index, listeners) in loop_listeners.into_iter().enumerate() {
                match spawn_event_loop_thread(index, listeners, shared.clone()) {
                    Ok(worker) => spawned_workers.push(worker),
                    Err(err) => {
                        start_err = Some(err);
                        break;
                    }
                }
            }
            worker_threads.reserve(spawned_workers.len());
            for worker in spawned_workers {
                if start_err.is_none() {
                    match worker.ready_rx.await {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => start_err = Some(err),
                        Err(_) => {
                            start_err = Some(CoreError::Bind {
                                addr: format!("worker event loop {}", worker.index),
                                source: io::Error::other(
                                    "worker event loop exited before acknowledging startup",
                                ),
                            });
                        }
                    }
                }
                listener_tasks.push(worker.stopped_task);
                worker_threads.push(WorkerThreadHandle {
                    exited: worker.exited_rx,
                    thread: worker.thread,
                });
            }
            if let Some(err) = start_err {
                let rollback_deadline = tokio::time::Instant::now() + WORKER_SHUTDOWN_JOIN_GRACE;
                let _ = shutdown_tx.send(true);
                let _ = upgrade_force_close_tx.send(true);
                let _ = workers_exit_tx.send(true);
                let _ = tokio::time::timeout_at(rollback_deadline, async {
                    for handle in listener_tasks {
                        let _ = handle.await;
                    }
                })
                .await;
                let _ = join_worker_threads_bounded(
                    worker_threads,
                    rollback_deadline,
                    "startup rollback",
                )
                .await;
                for ep in &quic_endpoints {
                    ep.close(0_u32.into(), b"server startup failed");
                }
                if let Some(metrics_srv) = metrics_server {
                    metrics_srv.shutdown().await;
                }
                return Err(err);
            }
        }

        // Wire live background ACME v2 issuance & ARI renewal supervisor (`ACME-1`, skip in
        // `split-daemon` `ACME-3`).
        // R2-ACME-4: Always spawn the lightweight standby supervisor so adding an `acme` block
        // via hot reload starts issuing immediately instead of requiring a full process restart!
        let acme_reload_notify = Arc::new(tokio::sync::Notify::new());
        {
            let state_dir = options
                .acme_state_dir
                .clone()
                .unwrap_or_else(|| PathBuf::from(".miraserve-acme"));
            let store_for_acme = Arc::clone(&store);
            let acme_store_bg = Arc::clone(&acme_store);
            let resolver_bg = Arc::clone(&resolver);
            let notify_for_acme = Arc::clone(&acme_reload_notify);
            let mut sd = shutdown_rx.clone();
            background_tasks.push(tokio::spawn(async move {
                loop {
                    if *sd.borrow() {
                        break;
                    }
                    let cfg = store_for_acme.current();
                    if let Some(acme_cfg) = cfg.server.tls.acme.clone()
                        && cfg.server.tls.key_isolation != KeyIsolation::SplitDaemon
                    {
                        let provider = build_crypto_provider(cfg.server.tls.pqc_hybrid);
                        let active_acme_cfg = acme_cfg.clone();
                        let active_pqc = cfg.server.tls.pqc_hybrid;
                        let manager = Arc::new(AcmeManager::new(
                            acme_cfg,
                            state_dir.clone(),
                            Arc::clone(&acme_store_bg),
                            Arc::clone(&resolver_bg),
                            provider,
                        ));
                        let store_inner = Arc::clone(&store_for_acme);
                        let store_for_change = Arc::clone(&store_for_acme);
                        // R5-ACME-4: Re-check `server.tls.acme` / `key_isolation` on every reload
                        // and rebuild `AcmeManager` immediately if staging/production directory,
                        // email, short-lived, or ARI settings changed!
                        manager
                            .run_renewal_loop_with_reload_check(
                                move || {
                                    let cur = store_inner.current();
                                    if cur.server.tls.acme.is_none()
                                        || cur.server.tls.key_isolation == KeyIsolation::SplitDaemon
                                    {
                                        return Vec::new();
                                    }
                                    cur.sites
                                        .iter()
                                        .filter(|s| {
                                            s.tls.as_ref().and_then(|t| t.cert.as_ref()).is_none()
                                        })
                                        .flat_map(|s| s.hosts.iter().cloned())
                                        .collect()
                                },
                                move || {
                                    let cur = store_for_change.current();
                                    cur.server.tls.key_isolation == KeyIsolation::SplitDaemon
                                        || cur.server.tls.acme.as_ref() != Some(&active_acme_cfg)
                                        || cur.server.tls.pqc_hybrid != active_pqc
                                },
                                Arc::clone(&notify_for_acme),
                                sd.clone(),
                            )
                            .await;
                        continue;
                    }
                    tokio::select! {
                        () = notify_for_acme.notified() => {}
                        changed = sd.changed() => {
                            if changed.is_err() || *sd.borrow() {
                                break;
                            }
                        }
                    }
                }
            }));
        }

        // Wire live periodic OTLP/HTTP JSON metrics exporter (`TEL-1`).
        if let Some(exporter) = otlp_exporter {
            let reg = Arc::clone(engine.telemetry());
            let sd = shutdown_rx.clone();
            background_tasks.push(tokio::spawn(async move {
                exporter
                    .run_export_loop(reg, Duration::from_secs(30), sd)
                    .await;
            }));
        }

        let startup_config = store.snapshot();
        let startup_client_cas = client_ca_digests(&startup_config);
        Ok(RunningServer {
            startup_config,
            startup_client_cas,
            restart_required: Mutex::new(Vec::new()),
            store,
            resolver,
            acme_store,
            acme_reload_notify,
            engine,
            ech_manager,
            metrics_server,
            options,
            dev_cert,
            sandbox_report,
            startup_sandbox_policy,
            startup_pinned_log_dirs,
            bound_listeners,
            shutdown_tx,
            upgrade_force_close_tx,
            workers_exit_tx,
            worker_threads,
            tracker,
            listener_tasks,
            background_tasks,
            quic_endpoints,
            reload_lock: Mutex::new(()),
        })
    }
}

/// Validates every configured CLI log destination with the startup/reload rule and returns each
/// configured log bound to its validated directory handle (Codex G7 & Round-5 P1 #1).
///
/// Associations supplied by the CLI (`ServerOptions::pinned_log_dirs`) are kept as-is so the
/// writer, startup and reload share one directory identity; embedders that start the server
/// directly get the association created here.
fn bind_startup_log_dirs(
    config: &Config,
    options: &ServerOptions,
    effective_acme: Option<&Path>,
) -> Result<Vec<PinnedLogDir>, CoreError> {
    let mut bound: Vec<PinnedLogDir> = options.pinned_log_dirs.clone();
    let is_bound =
        |b: &[PinnedLogDir], p: &Path| b.iter().any(|pl| pl.configured_path.as_path() == p);
    let mut check_policy = SandboxPolicy::from_config_with_file(
        config,
        options.config_path.as_deref(),
        options.acme_state_dir.as_deref(),
    );
    for log_path in &options.log_rotation_paths {
        let binding = check_policy
            .bind_log_rotation_dir(
                log_path,
                config,
                options.config_path.as_deref(),
                effective_acme,
                &options.secret_file_paths,
            )
            .map_err(CoreError::UnsafeDocroot)?;
        if !is_bound(&bound, log_path)
            && let Some(dir) = binding.pinned
        {
            bound.push(PinnedLogDir::new(log_path, dir, true).map_err(CoreError::UnsafeDocroot)?);
        }
    }
    for log_path in &options.log_file_paths {
        if is_bound(&bound, log_path) || options.log_rotation_paths.contains(log_path) {
            continue;
        }
        let binding = bind_log_file_dir(log_path, config).map_err(CoreError::UnsafeDocroot)?;
        if let Some(dir) = binding.pinned {
            bound.push(PinnedLogDir::new(log_path, dir, false).map_err(CoreError::UnsafeDocroot)?);
        }
    }
    let violations = find_docroot_pinned_log_overlaps(config, &bound);
    if !violations.is_empty() {
        return Err(CoreError::UnsafeDocroot(violations.join("; ")));
    }
    Ok(bound)
}

fn effective_acme_dir_for_checks<'a>(
    config: &Config,
    options: &'a ServerOptions,
) -> Option<&'a Path> {
    options.acme_state_dir.as_deref().or_else(|| {
        (config.server.tls.acme.is_some()
            && config.server.tls.key_isolation != KeyIsolation::SplitDaemon)
            .then_some(Path::new(".miraserve-acme"))
    })
}

fn load_cached_acme_certs_into(
    resolver: &Arc<DynamicCertResolver>,
    acme_store: &Arc<AcmeChallengeStore>,
    config: &Config,
    options: &ServerOptions,
) {
    // ACME-3: Never load ACME private keys directly into the worker under `split-daemon`.
    if config.server.tls.key_isolation == KeyIsolation::SplitDaemon {
        return;
    }
    if let Some(acme_cfg) = &config.server.tls.acme {
        let state_dir = options
            .acme_state_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from(".miraserve-acme"));
        let provider = build_crypto_provider(config.server.tls.pqc_hybrid);
        let manager = AcmeManager::new(
            acme_cfg.clone(),
            state_dir,
            Arc::clone(acme_store),
            Arc::clone(resolver),
            provider,
        );
        let domains: Vec<String> = config
            .sites
            .iter()
            .filter(|s| s.tls.as_ref().and_then(|t| t.cert.as_ref()).is_none())
            .flat_map(|s| s.hosts.iter().cloned())
            .collect();
        manager.load_cached_certificates(&domains);
    }
}

/// Handle to a running MiraServe server supporting 2-phase atomic hot reload and graceful drain.
pub struct RunningServer {
    store: Arc<ConfigStore>,
    resolver: Arc<DynamicCertResolver>,
    acme_store: Arc<AcmeChallengeStore>,
    acme_reload_notify: Arc<tokio::sync::Notify>,
    engine: Arc<HttpEngine>,
    ech_manager: Option<Arc<EchRotationManager>>,
    metrics_server: Option<RunningMetricsServer>,
    options: ServerOptions,
    dev_cert: Option<GeneratedCertPem>,
    sandbox_report: Option<SandboxReport>,
    startup_sandbox_policy: Option<SandboxPolicy>,
    startup_pinned_log_dirs: Vec<PinnedLogDir>,
    bound_listeners: Vec<BoundListener>,
    shutdown_tx: watch::Sender<bool>,
    upgrade_force_close_tx: watch::Sender<bool>,
    /// Ends the per-worker event loops (`workers`) once connections have drained.
    workers_exit_tx: watch::Sender<bool>,
    /// Native thread handles for per-worker event loops, joined during [`Self::shutdown`].
    worker_threads: Vec<WorkerThreadHandle>,
    tracker: Arc<ActiveTracker>,
    listener_tasks: Vec<JoinHandle<()>>,
    background_tasks: Vec<JoinHandle<()>>,
    quic_endpoints: Vec<quinn::Endpoint>,
    reload_lock: Mutex<()>,
    /// The configuration the process started with: settings a reload cannot change (listeners,
    /// sandbox, ...) stay as they were then.
    startup_config: Arc<Config>,
    /// Client CA contents the TLS listeners loaded at start-up (by path).
    startup_client_cas: std::collections::BTreeMap<String, Option<String>>,
    /// Settings of the active configuration that differ from the running process and need a
    /// restart to take effect (reported with every reload acknowledgement).
    restart_required: Mutex<Vec<&'static str>>,
}

impl RunningServer {
    /// Returns all currently bound network listeners and their resolved OS addresses.
    #[must_use]
    pub fn bound_listeners(&self) -> &[BoundListener] {
        &self.bound_listeners
    }

    /// Returns the OS confinement report if sandboxing was enabled at startup.
    #[must_use]
    pub fn sandbox_report(&self) -> Option<&SandboxReport> {
        self.sandbox_report.as_ref()
    }

    /// Returns the PEM of the auto-generated dev TLS certificate, if `--dev-tls` created one.
    #[must_use]
    pub fn dev_cert_pem(&self) -> Option<&str> {
        self.dev_cert.as_deref_cert()
    }

    /// Returns the lock-free [`ConfigStore`].
    #[must_use]
    pub fn config_store(&self) -> &Arc<ConfigStore> {
        &self.store
    }

    /// Returns the shared [`AcmeChallengeStore`].
    #[must_use]
    pub fn acme_store(&self) -> &Arc<AcmeChallengeStore> {
        &self.acme_store
    }

    /// Returns the shared RFC 9421 Web Bot Auth Ed25519 key registry.
    #[must_use]
    pub fn agent_keys(&self) -> &Arc<miraserve_http::BotAuthKeyRegistry> {
        self.engine.agent_keys()
    }

    /// Returns the shared lock-free Prometheus / OTLP [`TelemetryRegistry`].
    #[must_use]
    pub fn telemetry(&self) -> &Arc<TelemetryRegistry> {
        self.engine.telemetry()
    }

    /// Returns the RFC 9849 ECH rotation manager if `server.tls.ech` is enabled.
    #[must_use]
    pub fn ech_manager(&self) -> Option<&Arc<EchRotationManager>> {
        self.ech_manager.as_ref()
    }

    /// Returns the local socket address of the Prometheus metrics listener, if enabled.
    #[must_use]
    pub fn metrics_addr(&self) -> Option<SocketAddr> {
        self.metrics_server
            .as_ref()
            .map(RunningMetricsServer::local_addr)
    }

    /// Returns the settings of the active reloaded configuration that differ from the startup
    /// configuration and require a process restart to take effect.
    #[must_use]
    pub fn restart_required(&self) -> Vec<&'static str> {
        self.restart_required
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Atomically reloads configuration from an in-memory KDL string with zero downtime.
    ///
    /// Uses 2-phase staging (preparing both HTTP router and TLS certificate table before
    /// committing anything) and preserves live ACME certificates across reloads. Any error
    /// leaves live HTTP and TLS state completely untouched!
    ///
    /// # Errors
    /// Returns [`CoreError`] if parsing, validation, router compilation, or cert loading fails.
    pub fn reload_from_str(&self, source_name: &str, kdl: &str) -> Result<u64, CoreError> {
        let (next_cfg, report) = miraserve_config::parse_kdl(source_name, kdl)?;
        self.apply_reloaded_config(next_cfg, report.warnings.len())
    }

    /// Atomically reloads configuration from disk with zero downtime.
    ///
    /// # Errors
    /// Returns [`CoreError`] if reading, validation, router compilation, or cert loading fails.
    pub fn reload_from_file(&self, path: impl AsRef<Path>) -> Result<u64, CoreError> {
        self.reload_from_file_hashed(path).1
    }

    /// [`Self::reload_from_file`], with the SHA-256 of the very bytes that were loaded (what
    /// `miraserve reload --config` compares its own file with): the file is read once, so the
    /// digest cannot describe other content than the configuration that was applied or
    /// refused. `None` when the file could not be read.
    fn reload_from_file_hashed(
        &self,
        path: impl AsRef<Path>,
    ) -> (Option<String>, Result<u64, CoreError>) {
        match miraserve_config::load_file_detailed(path) {
            Ok(loaded) => {
                let digest = miraserve_tls::sha256_hex(loaded.source_text.as_bytes());
                let warnings = loaded.report.warnings.len();
                (
                    Some(digest),
                    self.apply_reloaded_config(loaded.config, warnings),
                )
            }
            Err(err) => {
                let digest = match &err {
                    ConfigError::Validation { source_text, .. } => {
                        Some(miraserve_tls::sha256_hex(source_text.as_bytes()))
                    }
                    _ => None,
                };
                (digest, Err(err.into()))
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn apply_reloaded_config(
        &self,
        mut next_cfg: Config,
        warnings: usize,
    ) -> Result<u64, CoreError> {
        // Serialize concurrent reloads cleanly.
        let _reload_guard = match self.reload_lock.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        let prev_cfg = self.store.snapshot();

        // R7-SBX-1 & R7-SBX-2 (Reload parity): Run the EXACT SAME docroot confinement checks on
        // reload as at startup — checking against both the previous and next effective ACME dirs,
        // the config directory, TLS keys, publish stores, and symlink targets!
        let effective_acme = effective_acme_dir_for_checks(&next_cfg, &self.options)
            .or_else(|| effective_acme_dir_for_checks(&prev_cfg, &self.options));
        let reload_checks = |cfg: &Config| {
            let mut violations = find_unsafe_docroots_with_secret_files(
                cfg,
                self.options.config_path.as_deref(),
                effective_acme,
                &self.options.secret_file_paths,
            );
            violations.extend(find_docroot_log_overlaps(
                cfg,
                &self.options.log_file_paths,
                &self.options.log_rotation_paths,
            ));
            // Codex Round-4 P1 #3: Verify EVERY configured log path still resolves to its exact
            // startup pinned directory identity AND no reloaded document root overlaps any
            // startup pinned log directory (blocking moved-alias reload exposure).
            violations.extend(find_docroot_pinned_log_overlaps(
                cfg,
                &self.startup_pinned_log_dirs,
            ));
            violations
        };
        // Same order as start-up: tenant roots that are unusable or leave their owner-dir are
        // isolated first, so the overlap checks below never expand them against every key.
        quarantine_inaccessible_tenant_roots(&mut next_cfg);
        let mut docroot_violations = lexical_log_overlaps(&next_cfg, &self.options.log_file_paths);
        if docroot_violations.is_empty() {
            docroot_violations = quarantine_unsafe_sites(&mut next_cfg, reload_checks);
        }
        if !docroot_violations.is_empty() {
            return Err(CoreError::UnsafeDocroot(docroot_violations.join("; ")));
        }
        // Codex G7 (P1 & P2): Validate rotating log directories against forbidden trees, secrets,
        // trust anchors, and docroots with the EXACT same rule at startup AND on reload (even when
        // running without Landlock / `--no-sandbox`).
        // Build the candidate sandbox policy and compare it with the startup policy. A grant
        // that fails, or a path outside the startup policy, whose ONLY consumers are tenant
        // sites (owner-dir) quarantines those sites (503) and the policy is rebuilt without
        // them: a tenant cannot hold back every other site's reload. A path the server itself
        // or a site without owner-dir needs keeps the previous behaviour (refusal / restart).
        let build_policy = |cfg: &Config| {
            let mut policy = SandboxPolicy::from_config_with_file(
                cfg,
                self.options.config_path.as_deref(),
                self.options.acme_state_dir.as_deref(),
            );
            let mut rotation_error = None;
            for log_path in &self.options.log_rotation_paths {
                if let Err(reason) = policy.allow_log_rotation_dir_with_context(
                    log_path,
                    cfg,
                    self.options.config_path.as_deref(),
                    effective_acme,
                    &self.options.secret_file_paths,
                ) {
                    rotation_error = Some(reason);
                }
            }
            (policy, rotation_error)
        };
        let policy_only = |cfg: &Config| build_policy(cfg).0;
        for _ in 0..=next_cfg.sites.len() {
            let (next_policy, rotation_error) = build_policy(&next_cfg);
            if let Some(reason) = rotation_error {
                return Err(CoreError::UnsafeDocroot(reason));
            }

            // Codex Round-11 P2: a candidate grant that startup would refuse must be refused
            // here too, even when an existing ancestor grant would make it look "covered".
            // Genuinely missing optional trees are not failures.
            let failed: Vec<WantedGrant> = next_policy
                .grant_failure_paths()
                .into_iter()
                .map(|path| (None, path))
                .collect();
            if !failed.is_empty() {
                match quarantine_sole_tenant_consumers(&mut next_cfg, &policy_only, &failed) {
                    Ok(true) => continue,
                    _ => {
                        return Err(CoreError::Sandbox(SandboxError::Landlock(format!(
                            "reload refused: sandbox grant(s) invalid in the new configuration: {}",
                            next_policy.grant_failures().join("; ")
                        ))));
                    }
                }
            }

            // R2-SBX-2: Check startup Landlock coverage BEFORE opening any newly-referenced
            // certs, keys, or roots so live Landlock returns a clear `RestartRequired` instead
            // of `EACCES`.
            let Some(active_policy) = self
                .startup_sandbox_policy
                .as_ref()
                .filter(|policy| policy.landlock)
            else {
                break;
            };
            let uncovered: Vec<WantedGrant> = active_policy
                .uncovered_grants_in(&next_policy)
                .into_iter()
                .map(|(class, path)| (Some(class), path))
                .collect();
            if uncovered.is_empty() {
                break;
            }
            if let Ok(true) =
                quarantine_sole_tenant_consumers(&mut next_cfg, &policy_only, &uncovered)
            {
                continue;
            }
            let listed = uncovered
                .iter()
                .map(|(_, p)| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            warn!(
                paths = %listed,
                "reload refused: config references path outside the startup Landlock policy; restart MiraServe to grant access"
            );
            return Err(CoreError::RestartRequired(format!(
                "path(s) outside the startup Landlock policy: {listed}; restart MiraServe, or list their parent under sandbox read-tree/socket-tree so later reloads are covered"
            )));
        }

        // Phase 1a (fallible, zero live mutation): compile new HTTP router.
        let prepared_http = self.engine.prepare_reload(&next_cfg)?;

        // Phase 1b (fallible, zero live mutation): build staged TLS certificate table
        // preserving existing dev certs and live/cached ACME certs across reloads!
        let staged_resolver = Arc::new(DynamicCertResolver::new(Arc::clone(&self.acme_store)));
        let has_manual_certs = next_cfg.server.tls.cert.is_some()
            || next_cfg
                .sites
                .iter()
                .any(|s| s.tls.as_ref().and_then(|t| t.cert.as_ref()).is_some());
        let is_split_daemon = next_cfg.server.tls.key_isolation == KeyIsolation::SplitDaemon;

        if has_manual_certs || is_split_daemon || self.dev_cert.is_none() {
            let _ = populate_resolver_from_config_with_keyd_secret(
                &staged_resolver,
                &next_cfg,
                self.options.dev_tls,
                self.options.keyd_auth_secret,
            )?;
        }

        // Reload any cached ACME certificates from disk and compute the exact set of hosts
        // still eligible for live ACME preservation (`R2-ACME-6`).
        load_cached_acme_certs_into(&staged_resolver, &self.acme_store, &next_cfg, &self.options);
        let keep_acme_hosts: std::collections::HashSet<String> =
            if next_cfg.server.tls.acme.is_some() && !is_split_daemon {
                next_cfg
                    .sites
                    .iter()
                    .filter(|s| s.tls.as_ref().and_then(|t| t.cert.as_ref()).is_none())
                    .flat_map(|s| s.hosts.iter().map(|h| h.to_ascii_lowercase()))
                    .collect()
            } else {
                std::collections::HashSet::new()
            };
        let keep_dev_default = !has_manual_certs && !is_split_daemon && self.dev_cert.is_some();

        // RLD-2: Warn explicitly whenever non-hot-reloadable process-level settings changed, and
        // remember which settings of the new configuration differ from the running process
        // (compared with the start-up configuration, so a later reload still reports them).
        warn_on_non_reloadable_changes(&prev_cfg, &next_cfg);
        let pending =
            restart_required_settings(&self.startup_config, &next_cfg, &self.startup_client_cas);
        *self
            .restart_required
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = pending;

        // Phase 2 (infallible atomic commit): swap TLS via RCU (never clobbering concurrent
        // ACME upserts and never keeping removed manual certs!), HTTP router, and ConfigStore.
        self.resolver.commit_reload_preserving_acme(
            &staged_resolver,
            &keep_acme_hosts,
            keep_dev_default,
        );
        self.engine.commit_reload(prepared_http);
        let generation = self.store.swap(next_cfg);
        self.acme_reload_notify.notify_one();

        info!(
            generation,
            warnings, "reloaded MiraServe configuration atomically (2-phase commit)"
        );
        Ok(generation)
    }

    /// Initiates graceful shutdown, draining active HTTP/1.1, HTTP/2, and HTTP/3 connections
    /// up to `server.timeouts.graceful_drain`, then draining offloaded log queues under one
    /// caller-measured 2 s deadline and returning the drain report.
    pub async fn shutdown_with_report(self) -> OffloadLogDrainReport {
        let drain_timeout = self.store.current().server.timeouts.graceful_drain;
        info!(
            active_connections = self.tracker.current(),
            drain_timeout_ms = drain_timeout.as_millis(),
            "initiating graceful drain"
        );

        let (connections_forced_closed, workers_join_timed_out) = if self.worker_threads.is_empty()
        {
            // 1. Signal accept loops, HTTP/1.1+2+3 connections, and background loops to stop.
            let _ = self.shutdown_tx.send(true);
            for handle in self.listener_tasks {
                let _ = handle.await;
            }

            // 2. Drain active connections (including upgraded WebSocket tunnels whose leases
            //    hold `ActiveGuard`) BEFORE closing QUIC endpoints (`RLD-3`), so HTTP/3 GOAWAY
            //    frames, in-flight streams, and active WebSockets finish cleanly up to `drain_timeout`.
            let forced = if tokio::time::timeout(drain_timeout, self.tracker.wait_until_zero())
                .await
                .is_err()
            {
                warn!(
                    remaining = self.tracker.current(),
                    "graceful drain timeout elapsed; forcing exit"
                );
                let _ = self.upgrade_force_close_tx.send(true);
                true
            } else {
                let _ = self.upgrade_force_close_tx.send(true);
                info!("all connections drained cleanly");
                false
            };

            let _ = self.workers_exit_tx.send(true);
            (forced, false)
        } else {
            // Start the drain deadline at the stop signal rather than after listener
            // acknowledgements, so a slow acknowledgement cannot push out shutdown.
            let drain_deadline = tokio::time::Instant::now() + drain_timeout;
            let _ = self.shutdown_tx.send(true);
            let _ = tokio::time::timeout_at(drain_deadline, async {
                for handle in self.listener_tasks {
                    let _ = handle.await;
                }
            })
            .await;

            let forced = if tokio::time::timeout_at(drain_deadline, self.tracker.wait_until_zero())
                .await
                .is_err()
            {
                warn!(
                    remaining = self.tracker.current(),
                    "graceful drain timeout elapsed; forcing exit"
                );
                let _ = self.upgrade_force_close_tx.send(true);
                true
            } else {
                let _ = self.upgrade_force_close_tx.send(true);
                info!("all connections drained cleanly");
                false
            };

            // Signal worker loops to exit and join every loop thread (bounded by
            // `drain_deadline + 2s`) before returning so all cancelled connections drop and emit
            // their final access-log records prior to the CLI's final log flush.
            let _ = self.workers_exit_tx.send(true);
            let join_deadline = drain_deadline + WORKER_SHUTDOWN_JOIN_GRACE;
            let unjoined =
                join_worker_threads_bounded(self.worker_threads, join_deadline, "shutdown").await;
            (forced, unjoined > 0)
        };

        for ep in &self.quic_endpoints {
            ep.close(0_u32.into(), b"server shutting down");
        }
        if let Some(metrics_srv) = self.metrics_server {
            metrics_srv.shutdown().await;
        }

        // 3. Join background supervisors (ACME / OTLP) with a bounded grace period.
        let bg_timeout = drain_timeout.min(Duration::from_secs(3));
        for mut handle in self.background_tasks {
            if tokio::time::timeout(bg_timeout, &mut handle).await.is_err() {
                handle.abort();
            }
        }

        // 4. Drain both offloaded log queues (interrupted HTTP/2 access records and runtime
        //    diagnostics) under ONE shared 2 s deadline measured from here before returning to
        //    the caller / CLI's final flush.
        let mut report = flush_offloaded_logs(Duration::from_secs(2)).await;
        report.connections_forced_closed = connections_forced_closed;
        report.workers_join_timed_out = workers_join_timed_out;
        if !report.is_clean() {
            warn_incomplete_offload_drain(report);
        }
        report
    }

    /// Gracefully stops accepting new connections, drains in-flight connections up to
    /// `server.timeouts.shutdown-drain`, and drains offloaded log queues under one 2 s deadline.
    pub async fn shutdown(self) {
        let _ = self.shutdown_with_report().await;
    }

    /// Blocks until `SIGINT`/`SIGTERM`, handling `SIGHUP` hot reloads on Unix, and returns the
    /// shutdown offloaded-log drain report so the CLI does not start a second drain deadline.
    #[allow(clippy::too_many_lines)]
    pub async fn run_until_signal_with_report(self) -> OffloadLogDrainReport {
        let abort_signal = self.options.abort_signal.clone();
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};

            let mut sigterm = signal(SignalKind::terminate()).ok();
            let mut sighup = signal(SignalKind::hangup()).ok();
            let mut reload_seq: u64 = 0;
            if sighup.is_some() {
                write_ready_status(self.options.reload_status_file.as_ref());
            } else {
                // Without a handler SIGHUP would terminate the server, so it never reports
                // "ready" and `miraserve reload` never signals it.
                error!("could not install the SIGHUP handler; reload is unavailable until restart");
            }

            loop {
                tokio::select! {
                    () = async {
                        if let Some(notify) = abort_signal.as_ref() {
                            notify.notified().await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {
                        error!("aborting server because a post-startup thread failed OS sandbox confinement");
                        break;
                    }
                    _ = tokio::signal::ctrl_c() => {
                        info!("received SIGINT");
                        break;
                    }
                    () = async {
                        if let Some(s) = sigterm.as_mut() {
                            s.recv().await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {
                        info!("received SIGTERM");
                        break;
                    }
                    () = async {
                        if let Some(s) = sighup.as_mut() {
                            s.recv().await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {
                        reload_seq = reload_seq.saturating_add(1);
                        if let Some(path) = &self.options.config_path {
                            let (config_digest, reloaded) = self.reload_from_file_hashed(path);
                            match reloaded {
                                Ok(generation) => {
                                    info!(generation, path = %path.display(), "SIGHUP reload succeeded");
                                    let offline = self.engine.offline_sites();
                                    let restart = self
                                        .restart_required
                                        .lock()
                                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                                        .clone();
                                    write_reload_status(
                                        self.options.reload_status_file.as_ref(),
                                        reload_seq,
                                        config_digest.as_deref(),
                                        Ok((generation, &offline, &restart)),
                                    );
                                }
                                Err(err) => {
                                    error!(error = %err, path = %path.display(), "SIGHUP reload failed; keeping previous active configuration");
                                    write_reload_status(
                                        self.options.reload_status_file.as_ref(),
                                        reload_seq,
                                        config_digest.as_deref(),
                                        Err(&err.to_string()),
                                    );
                                }
                            }
                        } else {
                            warn!("received SIGHUP but no config file path is configured");
                            write_reload_status(
                                self.options.reload_status_file.as_ref(),
                                reload_seq,
                                None,
                                Err("no config file path is configured"),
                            );
                        }
                    }
                }
            }
        }

        #[cfg(not(unix))]
        {
            tokio::select! {
                () = async {
                    if let Some(notify) = abort_signal.as_ref() {
                        notify.notified().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    error!("aborting server because a post-startup thread failed OS sandbox confinement");
                }
                res = tokio::signal::ctrl_c() => {
                    if res.is_ok() {
                        info!("received Ctrl-C shutdown signal");
                    }
                }
            }
        }

        self.shutdown_with_report().await
    }

    /// Blocks until `SIGINT`/`SIGTERM`, while transparently handling `SIGHUP` hot reloads on Unix.
    pub async fn run_until_signal(self) {
        let _ = self.run_until_signal_with_report().await;
    }
}

#[cfg(unix)]
/// Marks the reload status file "ready". Called once the signal handlers are installed: from
/// then on `SIGHUP` reloads instead of terminating the process. Until then
/// the file says "starting" and `miraserve reload` waits instead of signalling.
#[cfg(unix)]
fn write_ready_status(status_file: Option<&Arc<Mutex<std::fs::File>>>) {
    use std::io::{Seek as _, SeekFrom, Write as _};

    let Some(file_mutex) = status_file else {
        return;
    };
    let Ok(mut file) = file_mutex.lock() else {
        return;
    };
    if file.seek(SeekFrom::Start(0)).is_ok()
        && file.set_len(0).is_ok()
        && file
            .write_all(
                format!(
                    "format=2\npid={}\nseq=0\nstatus=ready\nend=1\n",
                    std::process::id()
                )
                .as_bytes(),
            )
            .is_ok()
    {
        let _ = file.sync_data();
    }
}

/// The last line of a status record. The file is rewritten in place while `miraserve reload`
/// polls it, so a reader can see the beginning of a record: one that starts with `format=2`
/// is complete only with this line.
#[cfg_attr(not(unix), allow(dead_code))]
const STATUS_END: &str = "end=1\n";

#[cfg_attr(not(unix), allow(dead_code))]
fn write_reload_status(
    status_file: Option<&Arc<Mutex<std::fs::File>>>,
    seq: u64,
    config_sha256: Option<&str>,
    outcome: Result<(u64, &[miraserve_http::OfflineSite], &[&str]), &str>,
) {
    use std::io::{Seek as _, SeekFrom, Write as _};

    let Some(file_mutex) = status_file else {
        return;
    };
    let Ok(mut file) = file_mutex.lock() else {
        return;
    };
    let digest_line = config_sha256
        .map(|d| format!("config_sha256={d}\n"))
        .unwrap_or_default();
    let one_line = |text: &str, max: usize| -> String {
        text.chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .take(max)
            .collect()
    };
    let payload = match outcome {
        // `ack=3` marks a server that reports its sites: `offline_count=` and then, per site
        // the committed configuration serves as a 503, `offline=<index>\t<host>\t<reason>` (the
        // record layout before `ack=`) and `offline_code=<index>\t<code>`. (`ack=2` was the
        // four-field `offline=<index>\t<code>\t<host>\t<reason>` layout.) `miraserve reload`
        // reports what the server did and can tell an empty list from an older server that
        // sends none, or a cut-off file.
        Ok((generation, offline, restart_required)) => {
            use std::fmt::Write as _;
            let mut text = format!(
                "format=2\npid={}\nseq={seq}\nstatus=ok\ngeneration={generation}\n{digest_line}ack=3\noffline_count={}\n",
                std::process::id(),
                offline.len()
            );
            // `restart_required=<setting>`: valid settings of the committed configuration that
            // the running process does not apply until it restarts (listeners, sandbox, ...).
            for setting in restart_required {
                let _ = writeln!(text, "restart_required={setting}");
            }
            for site in offline {
                let _ = writeln!(
                    text,
                    "offline={}\t{}\t{}\noffline_code={}\t{}",
                    site.index,
                    one_line(&site.host, 255),
                    one_line(&site.reason, 512),
                    site.index,
                    site.code
                );
            }
            text.push_str(STATUS_END);
            text
        }
        Err(msg) => {
            let clean: String = msg
                .chars()
                .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
                .take(512)
                .collect();
            format!(
                "format=2\npid={}\nseq={seq}\nstatus=err\n{digest_line}error={clean}\n{STATUS_END}",
                std::process::id()
            )
        }
    };
    if file.seek(SeekFrom::Start(0)).is_ok()
        && file.set_len(0).is_ok()
        && file.write_all(payload.as_bytes()).is_ok()
    {
        let _ = file.sync_data();
    }
}

trait DevCertExt {
    fn as_deref_cert(&self) -> Option<&str>;
}

impl DevCertExt for Option<GeneratedCertPem> {
    fn as_deref_cert(&self) -> Option<&str> {
        self.as_ref().map(|g| g.cert_pem.as_str())
    }
}

fn bind_addr_to_socket_addr(addr: &BindAddr) -> SocketAddr {
    let ip = addr.host.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    SocketAddr::new(ip, addr.port)
}

/// Expands a [`BindAddr`] into concrete `(SocketAddr, optional_ipv6_fallback)` bind targets.
///
/// Bare `":port"` (`host == None`) binds **dual-stack** (`0.0.0.0:port` + `[::]:port` with
/// `IPV6_V6ONLY = true`), allowing graceful IPv4-only fallback only if IPv6 is disabled on the host.
/// Explicit IPv4 or IPv6 addresses bind strictly as requested.
fn expand_bind_targets(addr: &BindAddr) -> Vec<(SocketAddr, bool)> {
    match addr.host {
        Some(ip) => vec![(SocketAddr::new(ip, addr.port), false)],
        None => vec![
            (
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), addr.port),
                false,
            ),
            (
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), addr.port),
                true,
            ),
        ],
    }
}

/// Binds a non-blocking TCP listener with `IPV6_V6ONLY = true` on IPv6 sockets so IPv4 and IPv6
/// listeners behave identically across Linux, macOS, and Windows without `EADDRINUSE` collisions.
///
/// With `reuse_port` the address can be bound again by this process's other event loops
/// (`workers`): the kernel then spreads new connections over those sockets. Only a process
/// with the same effective user as the first binder can join.
fn bind_tcp_socket(addr: SocketAddr, reuse_port: bool) -> io::Result<TcpListener> {
    TcpListener::from_std(bind_std_tcp_socket(addr, reuse_port)?)
}

fn bind_std_tcp_socket(addr: SocketAddr, reuse_port: bool) -> io::Result<std::net::TcpListener> {
    let socket = Socket::new(
        Domain::for_address(addr),
        SocketType::STREAM,
        Some(SocketProtocol::TCP),
    )?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    #[cfg(target_os = "linux")]
    if reuse_port {
        socket.set_reuse_port(true)?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = reuse_port;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    Ok(socket.into())
}

/// One more socket for an address already bound with `SO_REUSEPORT`.
fn bind_reuseport_std(addr: SocketAddr) -> io::Result<std::net::TcpListener> {
    bind_std_tcp_socket(addr, true)
}

/// How many event loops `workers` asks for; 0 for the shared runtime. Per-worker event loops
/// rely on `SO_REUSEPORT` spreading connections, which is Linux's behaviour: elsewhere the
/// shared runtime is used whatever is configured. Split-key signing (`key-isolation
/// "split-daemon"`) performs synchronous IPC to `miraserve-keyd` during TLS handshakes, so
/// `workers` is ignored with a warning and the shared runtime is used.
fn event_loop_count(workers: Workers, key_isolation: KeyIsolation) -> usize {
    let wanted = match workers {
        Workers::Shared => return 0,
        Workers::Auto => std::thread::available_parallelism().map_or(1, std::num::NonZero::get),
        Workers::Count(count) => usize::try_from(count).unwrap_or(1).max(1),
    };
    if key_isolation == KeyIsolation::SplitDaemon {
        warn!(
            "'workers' is ignored when key-isolation is \"split-daemon\"; using the shared runtime"
        );
        return 0;
    }
    if cfg!(target_os = "linux") {
        wanted
    } else {
        warn!("'workers' is supported on Linux only; using the shared runtime");
        0
    }
}

/// Total blocking-thread budget distributed across worker event loops (`workers`).
const WORKER_BLOCKING_THREAD_BUDGET: usize = 256;
/// Minimum blocking-pool ceiling for any individual worker event loop.
const MIN_WORKER_BLOCKING_THREADS: usize = 8;
/// Idle keep-alive for blocking threads spawned by worker event loops.
const WORKER_BLOCKING_THREAD_KEEP_ALIVE: Duration = Duration::from_secs(10);
/// Maximum time `shutdown()` waits past the drain deadline for worker loop threads to finish.
/// Grace period for worker event-loop thread joins after the drain deadline (or during startup
/// rollback after a worker initialization failure).
const WORKER_SHUTDOWN_JOIN_GRACE: Duration = Duration::from_secs(2);

/// Emits the shutdown warning for an incomplete offloaded log drain, a graceful connection
/// deadline expiry (where late force-closed connection teardown may still enqueue records after
/// the shutdown snapshot), or dedicated worker threads that failed to join in time (so a clean
/// shutdown could not be certified).
fn warn_incomplete_offload_drain(report: OffloadLogDrainReport) {
    let queues_clean = report.access_drained
        && report.access_remaining == 0
        && report.diagnostic_drained
        && report.diagnostic_remaining == 0;
    let shutdown_detail = match (
        report.connections_forced_closed,
        report.workers_join_timed_out,
    ) {
        (true, true) => {
            "graceful connection deadline elapsed and one or more dedicated worker threads did not join in time, so records of force-closed connections or unjoined workers may be missing"
        }
        (true, false) => {
            "graceful connection deadline elapsed, so records of force-closed connections may be missing"
        }
        (false, true) => {
            "one or more dedicated worker threads did not join before the shutdown grace deadline, so a clean shutdown could not be certified"
        }
        (false, false) => "",
    };
    if report.diagnostic_drained && report.diagnostic_remaining == 0 {
        if !queues_clean && !shutdown_detail.is_empty() {
            warn!(
                access_remaining = report.access_remaining,
                diagnostic_remaining = report.diagnostic_remaining,
                connections_forced_closed = report.connections_forced_closed,
                workers_join_timed_out = report.workers_join_timed_out,
                "offloaded log drain timed out during shutdown ({} access-log and {} diagnostic record(s) remaining); {shutdown_detail}",
                report.access_remaining,
                report.diagnostic_remaining
            );
        } else if !queues_clean {
            warn!(
                access_remaining = report.access_remaining,
                diagnostic_remaining = report.diagnostic_remaining,
                "offloaded log drain timed out during shutdown ({} access-log and {} diagnostic record(s) remaining); remaining record(s) may miss the final flush",
                report.access_remaining,
                report.diagnostic_remaining
            );
        } else {
            warn!(
                access_remaining = report.access_remaining,
                diagnostic_remaining = report.diagnostic_remaining,
                connections_forced_closed = report.connections_forced_closed,
                workers_join_timed_out = report.workers_join_timed_out,
                "clean shutdown could not be certified before offloaded log drain ({} access-log and {} diagnostic record(s) remaining at snapshot): {shutdown_detail}",
                report.access_remaining,
                report.diagnostic_remaining
            );
        }
    } else {
        // Diagnostic sink itself timed out: report directly to stderr so shutdown does not block
        // again on the stalled runtime log sink.
        use std::io::Write as _;
        let mut stderr = io::stderr().lock();
        if shutdown_detail.is_empty() {
            let _ = writeln!(
                stderr,
                "miraserve: warning: offloaded log drain timed out during shutdown ({} access-log and {} diagnostic record(s) remaining)",
                report.access_remaining, report.diagnostic_remaining
            );
        } else {
            let _ = writeln!(
                stderr,
                "miraserve: warning: offloaded log drain timed out during shutdown ({} access-log and {} diagnostic record(s) remaining); {shutdown_detail}",
                report.access_remaining, report.diagnostic_remaining
            );
        }
    }
}

/// Joins worker event-loop threads concurrently up to `join_deadline`, aborting any remaining
/// join wrappers once the deadline expires so neither shutdown nor startup rollback can hang on
/// a stuck worker thread. Returns the number of worker threads that had not joined in time.
async fn join_worker_threads_bounded(
    worker_threads: Vec<WorkerThreadHandle>,
    join_deadline: tokio::time::Instant,
    phase: &str,
) -> usize {
    let mut joins = tokio::task::JoinSet::new();
    for worker in worker_threads {
        joins.spawn(async move {
            let _ = worker.exited.await;
            let handle = worker.thread;
            let _ = tokio::task::spawn_blocking(move || {
                let _ = handle.join();
            })
            .await;
        });
    }
    while tokio::time::timeout_at(join_deadline, joins.join_next())
        .await
        .is_ok_and(|res| res.is_some())
    {}
    let remaining = joins.len();
    if remaining > 0 {
        warn!(
            phase,
            remaining, "worker event loop thread(s) did not finish within deadline"
        );
        joins.abort_all();
    }
    remaining
}
/// Upper bound a worker loop's Tokio runtime waits for blocking-pool tasks on shutdown, leaving
/// headroom inside [`WORKER_SHUTDOWN_JOIN_GRACE`] for async task drops and OS thread join.
const WORKER_RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(1_500);

/// Blocking-pool ceiling for each worker event loop: `max(8, 256 / workers)`.
const fn worker_max_blocking_threads(workers: usize) -> usize {
    let workers = if workers == 0 { 1 } else { workers };
    let share = WORKER_BLOCKING_THREAD_BUDGET / workers;
    if share < MIN_WORKER_BLOCKING_THREADS {
        MIN_WORKER_BLOCKING_THREADS
    } else {
        share
    }
}

/// A socket one event loop listens on: the socket, its port, and the TLS configuration.
type LoopListener = (std::net::TcpListener, u16, Arc<TlsConfigSet>);

/// What every event loop of `workers` shares with the rest of the server. Limits, budgets and
/// connection counts are the server's, not a worker's: 128 connections per address stays 128
/// however many event loops there are.
#[derive(Clone)]
struct LoopShared {
    store: Arc<ConfigStore>,
    engine: Arc<HttpEngine>,
    tracker: Arc<ActiveTracker>,
    conn_sem: Arc<Semaphore>,
    per_ip_tracker: Arc<PerIpConnTracker>,
    shutdown: watch::Receiver<bool>,
    upgrade_force_close: watch::Receiver<bool>,
    /// Set by `shutdown` after the drain: the loop's runtime ends.
    exit: watch::Receiver<bool>,
    /// The policy every thread of the loop confines itself with, when Landlock is on.
    landlock: Option<Arc<SandboxPolicy>>,
    /// Total number of worker event loops started (used to divide the blocking-thread budget).
    worker_count: usize,
}

/// Native thread handle and completion notification for a spawned worker event loop.
struct WorkerThreadHandle {
    exited: tokio::sync::oneshot::Receiver<()>,
    thread: std::thread::JoinHandle<()>,
}

/// Handles returned when spawning a per-worker event loop thread.
struct SpawnedWorkerLoop {
    index: usize,
    stopped_task: JoinHandle<()>,
    ready_rx: tokio::sync::oneshot::Receiver<Result<(), CoreError>>,
    exited_rx: tokio::sync::oneshot::Receiver<()>,
    thread: std::thread::JoinHandle<()>,
}

#[cfg(test)]
type WorkerStartTestHook = Arc<dyn Fn(usize) -> Option<CoreError> + Send + Sync>;

#[cfg(test)]
static WORKER_START_TEST_HOOK: Mutex<Option<WorkerStartTestHook>> = Mutex::new(None);

#[cfg(test)]
fn run_worker_start_test_hook(index: usize) -> Option<CoreError> {
    let hook = WORKER_START_TEST_HOOK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    hook.and_then(|f| f(index))
}

/// Starts one worker thread with a single-thread runtime that accepts on `listeners` and runs
/// every connection it accepts to its end, without handing it to another thread.
///
/// The worker sends its startup acknowledgement only after Landlock is applied on the loop
/// thread, its runtime is built, and every listener is registered. Its `stopped_task` ends when
/// the worker has stopped accepting, as the accept-loop tasks of the shared runtime do.
fn spawn_event_loop_thread(
    index: usize,
    listeners: Vec<LoopListener>,
    shared: LoopShared,
) -> Result<SpawnedWorkerLoop, CoreError> {
    let (stopped_tx, stopped_rx) = tokio::sync::oneshot::channel::<()>();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<Result<(), CoreError>>();
    let (exited_tx, exited_rx) = tokio::sync::oneshot::channel::<()>();
    let thread = std::thread::Builder::new()
        .name(format!("miraserve-loop-{index}"))
        .spawn(move || {
            run_worker_event_loop(index, listeners, shared, ready_tx, stopped_tx, exited_tx);
        })
        .map_err(|source| CoreError::Bind {
            addr: format!("worker event loop {index}"),
            source,
        })?;
    let stopped_task = tokio::spawn(async move {
        let _ = stopped_rx.await;
    });
    Ok(SpawnedWorkerLoop {
        index,
        stopped_task,
        ready_rx,
        exited_rx,
        thread,
    })
}

fn build_worker_runtime(
    index: usize,
    shared: &LoopShared,
) -> Result<tokio::runtime::Runtime, CoreError> {
    #[cfg(test)]
    if let Some(err) = run_worker_start_test_hook(index) {
        return Err(err);
    }
    let mut builder = tokio::runtime::Builder::new_current_thread();
    builder
        .enable_all()
        .max_blocking_threads(worker_max_blocking_threads(shared.worker_count))
        .thread_keep_alive(WORKER_BLOCKING_THREAD_KEEP_ALIVE);
    if let Some(policy) = shared.landlock.clone() {
        // Confine this loop thread before building its runtime or registering listeners;
        // a failure here aborts startup cleanly by returning an error to `start()`.
        if let Err(err) = apply_landlock_current_thread(&policy) {
            error!(
                worker = index,
                error = %err,
                "worker event loop failed Landlock LSM confinement during startup"
            );
            return Err(CoreError::Sandbox(err));
        }
        // Every blocking-pool thread this runtime lazily starts later must also be
        // confined; failure after startup aborts fail-closed.
        builder.on_thread_start(move || {
            if let Err(err) = apply_landlock_current_thread(&policy) {
                error!(
                    error = %err,
                    "terminating immediately: worker thread failed Landlock LSM confinement"
                );
                std::process::abort();
            }
        });
    }
    builder.build().map_err(|err| {
        error!(
            worker = index,
            error = %err,
            "worker event loop runtime could not be created"
        );
        CoreError::Bind {
            addr: format!("worker event loop {index}"),
            source: err,
        }
    })
}

fn run_worker_event_loop(
    index: usize,
    listeners: Vec<LoopListener>,
    shared: LoopShared,
    ready_tx: tokio::sync::oneshot::Sender<Result<(), CoreError>>,
    stopped_tx: tokio::sync::oneshot::Sender<()>,
    exited_tx: tokio::sync::oneshot::Sender<()>,
) {
    let runtime = match build_worker_runtime(index, &shared) {
        Ok(runtime) => runtime,
        Err(err) => {
            let _ = ready_tx.send(Err(err));
            let _ = exited_tx.send(());
            return;
        }
    };
    // Mark only this worker loop OS thread (never blocking-pool threads or the shared runtime)
    // so static serving and body compression avoid blocking operations inline here, and reverse
    // proxies keep upstream connections on this worker loop's own runtime and pool.
    let _worker_loop_guard = miraserve_http::enter_worker_loop_thread();
    let _proxy_worker_guard = miraserve_http::enter_worker_loop_index(index);
    runtime.block_on(async move {
        let mut accept_loops = Vec::with_capacity(listeners.len());
        for (socket, local_port, tls_set) in listeners {
            match TcpListener::from_std(socket) {
                Ok(listener) => accept_loops.push(spawn_https_tcp_loop(
                    listener,
                    local_port,
                    Arc::clone(&shared.store),
                    tls_set,
                    Arc::clone(&shared.engine),
                    Arc::clone(&shared.tracker),
                    Arc::clone(&shared.conn_sem),
                    Arc::clone(&shared.per_ip_tracker),
                    shared.shutdown.clone(),
                    shared.upgrade_force_close.clone(),
                )),
                Err(err) => {
                    error!(
                        worker = index,
                        port = local_port,
                        error = %err,
                        "worker event loop could not register its listener"
                    );
                    for accept_loop in accept_loops {
                        accept_loop.abort();
                    }
                    let _ = ready_tx.send(Err(CoreError::Bind {
                        addr: format!("port {local_port}"),
                        source: err,
                    }));
                    return;
                }
            }
        }
        // Let each spawned accept task poll once so its listener is actively accepting
        // before `start()` returns and `status=ready` can be reported.
        tokio::task::yield_now().await;
        let _ = ready_tx.send(Ok(()));
        let mut exit = shared.exit;
        let wait_exit = std::pin::pin!(async move {
            while !*exit.borrow() {
                if exit.changed().await.is_err() {
                    break;
                }
            }
        });
        let mut wait_exit = wait_exit;
        let accepts_done = tokio::select! {
            () = async {
                for accept_loop in &mut accept_loops {
                    let _ = accept_loop.await;
                }
            } => true,
            () = &mut wait_exit => false,
        };
        if !accepts_done {
            for accept_loop in accept_loops {
                accept_loop.abort();
            }
        }
        let _ = stopped_tx.send(());
        if accepts_done {
            wait_exit.await;
        }
    });
    // Shut down with a bounded blocking-pool wait: drops all remaining async tasks on this
    // loop (emitting final access-log records for open streams) before signalling thread exit.
    runtime.shutdown_timeout(WORKER_RUNTIME_SHUTDOWN_TIMEOUT);
    let _ = exited_tx.send(());
}

/// Binds a QUIC UDP `quinn::Endpoint` with `IPV6_V6ONLY = true` on IPv6 sockets.
fn bind_udp_quinn_endpoint(
    quic_cfg: quinn::ServerConfig,
    addr: SocketAddr,
) -> io::Result<quinn::Endpoint> {
    let socket = Socket::new(
        Domain::for_address(addr),
        SocketType::DGRAM,
        Some(SocketProtocol::UDP),
    )?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    let std_udp: std::net::UdpSocket = socket.into();
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(quic_cfg),
        std_udp,
        Arc::new(quinn::TokioRuntime),
    )
}

/// Returns `true` when an OS socket error indicates the host kernel has IPv6 disabled
/// (never masking real port conflicts like `AddrInUse` or `PermissionDenied`).
fn is_ipv6_unavailable(err: &io::Error) -> bool {
    #[cfg(target_os = "linux")]
    const IPV6_UNAVAIL_ERRNOS: &[i32] = &[97, 93, 99]; // EAFNOSUPPORT, EPROTONOSUPPORT, EADDRNOTAVAIL
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    const IPV6_UNAVAIL_ERRNOS: &[i32] = &[47, 43, 49]; // EAFNOSUPPORT, EPROTONOSUPPORT, EADDRNOTAVAIL
    #[cfg(windows)]
    const IPV6_UNAVAIL_ERRNOS: &[i32] = &[10047, 10043, 10049]; // WSAEAFNOSUPPORT, WSAEPROTONOSUPPORT, WSAEADDRNOTAVAIL
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        windows
    )))]
    const IPV6_UNAVAIL_ERRNOS: &[i32] = &[];

    if matches!(
        err.kind(),
        io::ErrorKind::AddrNotAvailable | io::ErrorKind::Unsupported
    ) {
        return true;
    }

    err.raw_os_error()
        .is_some_and(|code| IPV6_UNAVAIL_ERRNOS.contains(&code))
}

/// Normalizes IPv4-mapped IPv6 peer addresses (`::ffff:a.b.c.d`) to canonical IPv4 (`a.b.c.d`)
/// so rate limits, access logs, and FastCGI `REMOTE_ADDR` never split per-IP buckets.
#[must_use]
fn canonicalize_peer_addr(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

fn build_quinn_server_config(
    tls_set: &TlsConfigSet,
    config: &Config,
) -> Result<quinn::ServerConfig, CoreError> {
    let quic_crypto = QuicServerConfig::try_from(Arc::clone(&tls_set.quic_h3))
        .map_err(|err| CoreError::Quic(err.to_string()))?;

    let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(
        u64::from(config.server.limits.max_concurrent_streams)
            .try_into()
            .unwrap_or_else(|_| quinn::VarInt::from_u32(128)),
    );
    // HTTP/3 requires only 3 unidirectional streams (control + QPACK encoder + QPACK decoder).
    transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(MAX_H3_UNI_STREAMS));
    // Receive and send credit like HTTP/2's (256 KiB a stream, 4 MiB a connection): quinn's
    // defaults give a connection unlimited receive credit and 1.25 MB a stream, held in its
    // buffers before any body limit of ours sees a byte. No datagrams: nothing here reads them.
    transport.stream_receive_window(quinn::VarInt::from_u32(QUIC_STREAM_WINDOW));
    transport.receive_window(quinn::VarInt::from_u32(QUIC_CONNECTION_WINDOW));
    transport.send_window(u64::from(QUIC_CONNECTION_WINDOW));
    transport.datagram_receive_buffer_size(None);
    if let Ok(idle) = config.server.timeouts.idle_keepalive.try_into() {
        transport.max_idle_timeout(Some(idle));
    }
    server_cfg.transport_config(Arc::new(transport));
    Ok(server_cfg)
}

/// Runs the document-root safety checks. A tenant site (one with `owner-dir`) whose OWN roots
/// fail them is quarantined: it answers 503 and its roots are dropped before the sandbox policy
/// and router are built, so one tenant cannot hold back every other site's start or reload.
/// Each tenant site is checked with every other site's roots set aside but all of their keys
/// and protected paths kept, so a problem is attributed exactly. Sites without `owner-dir`
/// keep the previous behaviour: any problem refuses the configuration. Returns what still
/// fails after quarantine.
pub fn quarantine_unsafe_sites(
    cfg: &mut Config,
    checks: impl Fn(&Config) -> Vec<String>,
) -> Vec<String> {
    let violations = checks(cfg);
    if violations.is_empty() {
        return violations;
    }
    let tenant_sites: Vec<usize> = cfg
        .sites
        .iter()
        .enumerate()
        .filter(|(_, site)| site.owner_dir.is_some() && site.quarantine.is_none())
        .map(|(index, _)| index)
        .collect();
    // Every violation names its site first (`site '<host>' ...`): the tenant sites named that
    // way are checked on their own first (one lookup per violation); when something unsafe
    // remains that no message tied to a site, the other tenant sites are checked as well.
    let mut by_host: std::collections::HashMap<&str, Vec<usize>> = std::collections::HashMap::new();
    for &index in &tenant_sites {
        if let Some(host) = cfg.sites.get(index).and_then(|site| site.hosts.first()) {
            by_host.entry(host.as_str()).or_default().push(index);
        }
    }
    let named_set: std::collections::BTreeSet<usize> = violations
        .iter()
        .filter_map(|v| {
            v.strip_prefix("site '")
                .and_then(|rest| rest.split_once('\''))
        })
        .filter_map(|(host, _)| by_host.get(host))
        .flatten()
        .copied()
        .collect();
    let named: Vec<usize> = tenant_sites
        .iter()
        .copied()
        .filter(|index| named_set.contains(index))
        .collect();
    // Each named site is isolated with its own messages: the first pass already tied every
    // violation to its site, so no per-site check runs again (no further key resolution
    // under the reload lock).
    let mut by_site_messages: std::collections::HashMap<&str, Vec<&str>> =
        std::collections::HashMap::new();
    for v in &violations {
        if let Some((host, _)) = v
            .strip_prefix("site '")
            .and_then(|rest| rest.split_once('\''))
        {
            by_site_messages.entry(host).or_default().push(v.as_str());
        }
    }
    let reasons: Vec<(usize, String)> = named
        .iter()
        .filter_map(|&index| {
            let host = cfg.sites.get(index)?.hosts.first()?;
            // A bounded reason: the first few problems and how many more.
            let messages = by_site_messages.get(host.as_str())?;
            let mut reason = messages
                .iter()
                .take(3)
                .copied()
                .collect::<Vec<_>>()
                .join("; ");
            if messages.len() > 3 {
                use std::fmt::Write as _;
                let _ = write!(reason, "; and {} more", messages.len() - 3);
            }
            Some((index, reason))
        })
        .collect();
    for (index, reason) in reasons {
        if let Some(site) = cfg.sites.get_mut(index) {
            quarantine_site(site, reason);
        }
    }
    // Each check compares roots one by one, so isolating a site removes exactly its own
    // violations: what remains is the original list minus the isolated sites' messages (no
    // second whole-configuration pass). Violations of other sites or of the server stay.
    let isolated_hosts: std::collections::HashSet<&str> = cfg
        .sites
        .iter()
        .filter(|site| site.quarantine.is_some())
        .filter_map(|site| site.hosts.first().map(String::as_str))
        .collect();
    violations
        .into_iter()
        .filter(|v| {
            !v.strip_prefix("site '")
                .and_then(|rest| rest.split_once('\''))
                .is_some_and(|(host, _)| isolated_hosts.contains(host))
        })
        .collect()
}

/// Quarantines every tenant site (`owner-dir`) whose document root exists but cannot be used
/// as a directory (no permission on a component, a link loop, not a directory), so it never
/// becomes a sandbox grant failure that would stop the start or reload for everyone. A root that
/// does not exist keeps its usual handling (that site answers 503).
pub fn quarantine_inaccessible_tenant_roots(cfg: &mut Config) {
    let server_uid = server_account_uid(cfg);
    let server_account = server_account_ids(cfg);
    for site in cfg
        .sites
        .iter_mut()
        .filter(|site| site.owner_dir.is_some() && site.quarantine.is_none())
    {
        let owner_real = site
            .owner_dir
            .as_ref()
            .and_then(|owner| std::fs::canonicalize(owner).ok());
        // Each root with the configuration field it comes from.
        let roots: Vec<(String, String)> = site
            .root
            .iter()
            .map(|root| ("root".to_owned(), root.clone()))
            .chain(site.routes.iter().enumerate().filter_map(|(i, route)| {
                route
                    .root
                    .as_ref()
                    .map(|root| (format!("route[{i}].root"), root.clone()))
            }))
            .collect();
        let problem = roots
            .iter()
            .find_map(|(field, root)| {
                let root = root.as_str();
                let why = match std::fs::metadata(root) {
                // Opened exactly as the static server opens it (a directory with its
                // permissions removed still has metadata).
                Ok(meta) if meta.is_dir() => {
                    // Opened as the static server opens it, and entered (looking up a name inside
                    // needs search permission, which an O_PATH open does not).
                    if let Err(err) = open_root_probe(std::path::Path::new(root))
                        .and_then(|()| std::fs::metadata(std::path::Path::new(root).join(".")).map(|_| ()))
                    {
                        Some(format!(
                            "document root '{root}' cannot be opened: {err} (fix its permissions; if the directory is new since MiraServe started, restart MiraServe so the sandbox grants it)"
                        ))
                    } else if let Some(why) = server_account_cannot_read(root, server_account.as_ref()) {
                        // Running as root (check --fs, start before the privilege drop): root
                        // reads everything, so judge by the account the server will run as.
                        Some(format!("document root '{root}' cannot be read by the server account: {why}"))
                    } else {
                        // It must really be inside the account (the router checks the opened
                        // handle again; this catches it before preflight looks at its routes).
                        let root_real = std::fs::canonicalize(root).ok();
                        match (owner_real.as_ref(), root_real) {
                            (Some(owner), Some(real)) if real.starts_with(owner) => None,
                            _ => Some(format!("document root '{root}' is outside owner-dir")),
                        }
                    }
                }
                Ok(_) => Some(format!("document root '{root}' is not a directory")),
                // A tenant site without its root is offline as a whole (no other route of it
                // stays live while its files return 503).
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    Some(format!("document root '{root}' does not exist"))
                }
                Err(err) => Some(format!("document root '{root}' cannot be opened: {err}")),
                };
                why.map(|why| (field.clone(), why))
            });
        // Every credential file a tenant site names (its certificate, key and client CA, upstream
        // TLS files, bot key file) must be the server's, like the users files: owned by root or
        // the server, not writable by others, not a link. A tenant can then not point the
        // server at another account's key or make a sibling's file look like a secret.
        let problem = problem.or_else(|| {
            tenant_credential_paths(site)
                .into_iter()
                .find_map(|(field, path)| {
                    credential_file_problem_for(std::path::Path::new(&path), server_uid)
                        .map(|why| (field, format!("credential file '{path}': {why}")))
                })
        });
        if let Some((field, problem)) = problem {
            site.quarantine_field = Some(field);
            quarantine_site(site, problem);
        }
    }
}

/// Inspection-only variant of [`quarantine_inaccessible_tenant_roots`] for
/// `miraserve check --writable-set`: performs the identical tenant root and credential
/// classification, except any OS descriptor or memory exhaustion (`EMFILE`, `ENFILE`, `ENOMEM`)
/// fails the inspection command immediately instead of quarantining a healthy tenant.
///
/// Unreachable from `miraserve run`.
///
/// # Errors
/// Returns a diagnostic message if classification hits `EMFILE`, `ENFILE`, or `ENOMEM`.
#[allow(clippy::too_many_lines)]
pub fn quarantine_inaccessible_tenant_roots_for_inspection(cfg: &mut Config) -> Result<(), String> {
    if let Err(err) = std::fs::read_to_string("/etc/passwd")
        && is_resource_io_error(&err)
    {
        return Err(format!(
            "resource failure reading '/etc/passwd' during tenant classification: {err}"
        ));
    }
    #[cfg(unix)]
    if rustix::process::geteuid().as_raw() == 0
        && let Err(err) = std::fs::read_to_string("/etc/group")
        && is_resource_io_error(&err)
    {
        return Err(format!(
            "resource failure reading '/etc/group' during tenant classification: {err}"
        ));
    }
    let server_uid = server_account_uid(cfg);
    let server_account = server_account_ids(cfg);
    for site in cfg
        .sites
        .iter_mut()
        .filter(|site| site.owner_dir.is_some() && site.quarantine.is_none())
    {
        let owner_real = match site.owner_dir.as_ref() {
            Some(owner) => match std::fs::canonicalize(owner) {
                Ok(real) => Some(real),
                Err(err) if is_resource_io_error(&err) => {
                    return Err(format!(
                        "resource failure inspecting owner-dir '{owner}' during tenant classification: {err}"
                    ));
                }
                Err(_) => None,
            },
            None => None,
        };
        let roots: Vec<(String, String)> = site
            .root
            .iter()
            .map(|root| ("root".to_owned(), root.clone()))
            .chain(site.routes.iter().enumerate().filter_map(|(i, route)| {
                route
                    .root
                    .as_ref()
                    .map(|root| (format!("route[{i}].root"), root.clone()))
            }))
            .collect();
        let mut problem: Option<(String, String)> = None;
        for (field, root) in &roots {
            let root = root.as_str();
            let why = match std::fs::metadata(root) {
                Ok(meta) if meta.is_dir() => {
                    let probe = open_root_probe(std::path::Path::new(root)).and_then(|()| {
                        std::fs::metadata(std::path::Path::new(root).join(".")).map(|_| ())
                    });
                    match probe {
                        Err(err) if is_resource_io_error(&err) => {
                            return Err(format!(
                                "resource failure opening document root '{root}' during tenant classification: {err}"
                            ));
                        }
                        Err(err) => Some(format!(
                            "document root '{root}' cannot be opened: {err} (fix its permissions; if the directory is new since MiraServe started, restart MiraServe so the sandbox grants it)"
                        )),
                        Ok(()) => {
                            if let Some(why) =
                                server_account_cannot_read(root, server_account.as_ref())
                            {
                                Some(format!(
                                    "document root '{root}' cannot be read by the server account: {why}"
                                ))
                            } else {
                                let root_real = match std::fs::canonicalize(root) {
                                    Ok(real) => Some(real),
                                    Err(err) if is_resource_io_error(&err) => {
                                        return Err(format!(
                                            "resource failure resolving document root '{root}' during tenant classification: {err}"
                                        ));
                                    }
                                    Err(_) => None,
                                };
                                match (owner_real.as_ref(), root_real) {
                                    (Some(owner), Some(real)) if real.starts_with(owner) => None,
                                    _ => {
                                        Some(format!("document root '{root}' is outside owner-dir"))
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(_) => Some(format!("document root '{root}' is not a directory")),
                Err(err) if is_resource_io_error(&err) => {
                    return Err(format!(
                        "resource failure inspecting document root '{root}' during tenant classification: {err}"
                    ));
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    Some(format!("document root '{root}' does not exist"))
                }
                Err(err) => Some(format!("document root '{root}' cannot be opened: {err}")),
            };
            if let Some(why) = why {
                problem = Some((field.clone(), why));
                break;
            }
        }
        if problem.is_none() {
            for (field, path) in tenant_credential_paths(site) {
                let p = std::path::Path::new(&path);
                if let Some(parent) = p.parent()
                    && let Err(err) = std::fs::symlink_metadata(parent)
                    && is_resource_io_error(&err)
                {
                    return Err(format!(
                        "resource failure inspecting credential directory '{}' during tenant classification: {err}",
                        parent.display()
                    ));
                }
                if let Err(err) = std::fs::symlink_metadata(p)
                    && is_resource_io_error(&err)
                {
                    return Err(format!(
                        "resource failure inspecting credential file '{path}' during tenant classification: {err}"
                    ));
                }
                if let Some(why) = credential_file_problem_for(p, server_uid) {
                    problem = Some((field, format!("credential file '{path}': {why}")));
                    break;
                }
            }
        }
        if let Some((field, problem)) = problem {
            site.quarantine_field = Some(field);
            quarantine_site(site, problem);
        }
    }
    Ok(())
}

/// The uid of the account the server runs as (`sandbox { user }`, else `miraserve`), from
/// `/etc/passwd`: checks that run as root (startup, `check --fs`) accept files that account owns.
#[must_use]
pub fn server_account_uid(config: &Config) -> Option<u32> {
    let name = config.server.sandbox.user.as_deref().unwrap_or("miraserve");
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next()? == name)
            .then(|| fields.nth(1)?.parse().ok())
            .flatten()
    })
}

/// The server account's uid, primary gid and supplementary gids (from `/etc/passwd` and
/// `/etc/group`), when this process runs as root and so cannot test access by trying.
#[cfg(unix)]
fn server_account_ids(config: &Config) -> Option<(u32, Vec<u32>)> {
    if rustix::process::geteuid().as_raw() != 0 {
        return None;
    }
    let name = config.server.sandbox.user.as_deref().unwrap_or("miraserve");
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    let (uid, gid) = passwd.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        (fields.first()? == &name).then(|| {
            Some((
                fields.get(2)?.parse::<u32>().ok()?,
                fields.get(3)?.parse::<u32>().ok()?,
            ))
        })?
    })?;
    let mut gids = vec![gid];
    let service_group = config.server.sandbox.group.as_deref();
    if let Ok(groups) = std::fs::read_to_string("/etc/group") {
        for line in groups.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            let member = fields
                .get(3)
                .is_some_and(|members| members.split(',').any(|member| member == name));
            // The configured service group (sandbox { group }) counts too.
            let configured = service_group.is_some_and(|group| fields.first() == Some(&group));
            if (member || configured)
                && let Some(Ok(gid)) = fields.get(2).map(|gid| gid.parse::<u32>())
            {
                gids.push(gid);
            }
        }
    }
    Some((uid, gids))
}

#[cfg(not(unix))]
fn server_account_ids(_config: &Config) -> Option<(u32, Vec<u32>)> {
    None
}

/// Why the server account cannot enter `dir` (by POSIX access ACL on Linux when present,
/// otherwise by permission bits: search on the directory and on every ancestor of the path as
/// written, which is how the server reaches it), or `None` when it can, the account is unknown,
/// or an access ACL cannot be read or parsed (no verdict is given for that directory).
fn server_account_cannot_read(dir: &str, account: Option<&(u32, Vec<u32>)>) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let (uid, gids) = account?;
        let mut path = std::path::PathBuf::new();
        for component in std::path::Path::new(dir).components() {
            path.push(component);
        }
        // Every directory the service searches to reach the root, following links one step at
        // a time as the kernel does (a chain of links can pass through directories that are on
        // neither the written path nor the final location). Unresolvable: no verdict.
        let crossed = traversed_directories(&path)?;
        for step in crossed.iter().map(std::path::PathBuf::as_path) {
            if step.as_os_str().is_empty() {
                continue;
            }
            let Ok(meta) = std::fs::metadata(step) else {
                continue;
            };
            // On Linux, a POSIX access ACL replaces the group/other bits and can grant or deny
            // specific users and groups; evaluate it instead of relying on mode bits. If the
            // xattr exists but cannot be read or parsed, skip this directory (no verdict) and
            // keep checking the rest of the path.
            match access_acl_verdict(step, meta.uid(), meta.gid(), *uid, gids) {
                AclVerdict::Allow | AclVerdict::Indeterminate => continue,
                AclVerdict::Deny => {
                    return Some(format!("no search permission on '{}'", step.display()));
                }
                AclVerdict::Absent => {}
            }
            let mode = meta.mode();
            let bits = if meta.uid() == *uid {
                (mode >> 6) & 7
            } else if gids.contains(&meta.gid()) {
                (mode >> 3) & 7
            } else {
                mode & 7
            };
            if bits & 0o1 == 0 {
                return Some(format!("no search permission on '{}'", step.display()));
            }
        }
        None
    }
    #[cfg(not(unix))]
    {
        let _ = (dir, account);
        None
    }
}

/// The directories searched while resolving `path` (absolute), following each symbolic link
/// component by component like the kernel, plus the final directory itself. `None` when the
/// path cannot be resolved (missing component, too many links).
#[cfg(unix)]
fn traversed_directories(
    path: &std::path::Path,
) -> Option<std::collections::BTreeSet<std::path::PathBuf>> {
    use std::collections::{BTreeSet, VecDeque};
    use std::ffi::OsString;
    use std::path::{Component, PathBuf};
    fn parts_of(target: &std::path::Path) -> Vec<OsString> {
        target
            .components()
            .map(|c| match c {
                Component::RootDir => OsString::from("/"),
                other => other.as_os_str().to_os_string(),
            })
            .collect()
    }
    if !path.is_absolute() {
        return None;
    }
    let mut pending: VecDeque<OsString> = parts_of(path).into();
    let mut current = PathBuf::from("/");
    let mut searched = BTreeSet::new();
    let mut links = 0_u32;
    while let Some(part) = pending.pop_front() {
        if part == "/" {
            current = PathBuf::from("/");
        } else if part == ".." {
            // Leaving a directory still searches it first.
            searched.insert(current.clone());
            current.pop();
        } else if part != "." {
            searched.insert(current.clone());
            let next = current.join(&part);
            if std::fs::symlink_metadata(&next)
                .ok()?
                .file_type()
                .is_symlink()
            {
                links += 1;
                if links > 40 {
                    return None;
                }
                let target = std::fs::read_link(&next).ok()?;
                for item in parts_of(&target).into_iter().rev() {
                    pending.push_front(item);
                }
            } else {
                current = next;
            }
        }
    }
    searched.insert(current);
    Some(searched)
}

/// Linux `system.posix_acl_access` xattr binary format constants (`uapi/linux/posix_acl_xattr.h`).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const ACL_XATTR_VERSION: u32 = 2;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const ACL_USER_OBJ: u16 = 0x01;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const ACL_USER: u16 = 0x02;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const ACL_GROUP_OBJ: u16 = 0x04;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const ACL_GROUP: u16 = 0x08;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const ACL_MASK: u16 = 0x10;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const ACL_OTHER: u16 = 0x20;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const ACL_EXECUTE: u16 = 0x01;

/// Outcome of checking a directory's POSIX access ACL for search permission.
#[cfg(unix)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
enum AclVerdict {
    /// No POSIX access ACL on this directory (fall back to mode bits).
    Absent,
    /// POSIX access ACL grants search permission.
    Allow,
    /// POSIX access ACL denies search permission.
    Deny,
    /// An access ACL could not be read or parsed; give no verdict for this directory.
    Indeterminate,
}

/// Evaluates the POSIX access ACL on `path` (Linux), if one is present.
#[cfg(unix)]
fn access_acl_verdict(
    path: &std::path::Path,
    file_owner: u32,
    file_group: u32,
    uid: u32,
    gids: &[u32],
) -> AclVerdict {
    #[cfg(target_os = "linux")]
    {
        match read_access_acl(path) {
            RawAccessAcl::Absent => AclVerdict::Absent,
            RawAccessAcl::Unreadable => AclVerdict::Indeterminate,
            RawAccessAcl::Present(raw) => {
                match acl_allows_search(&raw, file_owner, file_group, uid, gids) {
                    Some(true) => AclVerdict::Allow,
                    Some(false) => AclVerdict::Deny,
                    None => AclVerdict::Indeterminate,
                }
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, file_owner, file_group, uid, gids);
        AclVerdict::Absent
    }
}

#[cfg(target_os = "linux")]
const MAX_ACL_XATTR_BYTES: usize = 64 * 1024;

#[cfg(target_os = "linux")]
enum RawAccessAcl {
    Absent,
    Present(Vec<u8>),
    Unreadable,
}

/// Reads the raw Linux `system.posix_acl_access` xattr value for `path` (capped at 64 KiB).
#[cfg(target_os = "linux")]
fn read_access_acl(path: &std::path::Path) -> RawAccessAcl {
    const ATTR: &str = "system.posix_acl_access";

    // Most directories have no access ACL (ENODATA/EOPNOTSUPP) and typical ACLs fit in 256 bytes,
    // so try a stack buffer first to avoid an extra size-query syscall and heap allocation.
    let mut small = [0_u8; 256];
    match rustix::fs::getxattr(path, ATTR, &mut small) {
        Ok(len) => {
            return small.get(..len).map_or(RawAccessAcl::Unreadable, |slice| {
                RawAccessAcl::Present(slice.to_vec())
            });
        }
        Err(err) if err == rustix::io::Errno::NODATA || err == rustix::io::Errno::OPNOTSUPP => {
            return RawAccessAcl::Absent;
        }
        Err(err) if err == rustix::io::Errno::RANGE => {}
        Err(_) => return RawAccessAcl::Unreadable,
    }

    // Larger ACL: ask the kernel for the current length, then read (growing up to the cap if
    // the attribute expands concurrently).
    let mut size = match rustix::fs::getxattr_query(path, ATTR) {
        Ok(len) => len,
        Err(err) if err == rustix::io::Errno::NODATA || err == rustix::io::Errno::OPNOTSUPP => {
            return RawAccessAcl::Absent;
        }
        Err(_) => return RawAccessAcl::Unreadable,
    };

    loop {
        if size == 0 || size > MAX_ACL_XATTR_BYTES {
            return RawAccessAcl::Unreadable;
        }
        let mut buf = vec![0_u8; size];
        match rustix::fs::getxattr(path, ATTR, buf.as_mut_slice()) {
            Ok(len) => {
                buf.truncate(len);
                return RawAccessAcl::Present(buf);
            }
            Err(err) if err == rustix::io::Errno::NODATA || err == rustix::io::Errno::OPNOTSUPP => {
                return RawAccessAcl::Absent;
            }
            Err(err) if err == rustix::io::Errno::RANGE => {
                if size == MAX_ACL_XATTR_BYTES {
                    return RawAccessAcl::Unreadable;
                }
                size = size.saturating_mul(2).min(MAX_ACL_XATTR_BYTES);
            }
            Err(_) => return RawAccessAcl::Unreadable,
        }
    }
}

/// Evaluates a raw Linux `system.posix_acl_access` xattr value for search (execute) permission
/// following the kernel's `acl(5)` access-check algorithm. Returns `None` when the xattr cannot
/// be parsed (unknown version, truncated, unknown tag, duplicate or missing required entries).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn acl_allows_search(
    acl: &[u8],
    file_owner: u32,
    file_group: u32,
    uid: u32,
    gids: &[u32],
) -> Option<bool> {
    let (header, rest) = acl.split_first_chunk::<4>()?;
    if u32::from_le_bytes(*header) != ACL_XATTR_VERSION {
        return None;
    }
    let (entries, remainder) = rest.as_chunks::<8>();
    if entries.is_empty() || !remainder.is_empty() {
        return None;
    }

    let mut user_obj: Option<u16> = None;
    let mut named_user: Option<u16> = None;
    let mut group_obj: Option<u16> = None;
    let mut mask: Option<u16> = None;
    let mut other: Option<u16> = None;
    let mut named_group_matched = false;
    let mut named_group_exec = false;

    for &[t0, t1, p0, p1, i0, i1, i2, i3] in entries {
        let tag = u16::from_le_bytes([t0, t1]);
        let perm = u16::from_le_bytes([p0, p1]);
        let id = u32::from_le_bytes([i0, i1, i2, i3]);
        match tag {
            ACL_USER_OBJ => {
                if user_obj.replace(perm).is_some() {
                    return None;
                }
            }
            ACL_USER => {
                if id == uid && named_user.is_none() {
                    named_user = Some(perm);
                }
            }
            ACL_GROUP_OBJ => {
                if group_obj.replace(perm).is_some() {
                    return None;
                }
            }
            ACL_GROUP => {
                if gids.contains(&id) {
                    named_group_matched = true;
                    if perm & ACL_EXECUTE != 0 {
                        named_group_exec = true;
                    }
                }
            }
            ACL_MASK => {
                if mask.replace(perm).is_some() {
                    return None;
                }
            }
            ACL_OTHER => {
                if other.replace(perm).is_some() {
                    return None;
                }
            }
            _ => return None,
        }
    }

    let (user_obj, group_obj, other) = (user_obj?, group_obj?, other?);
    let apply_mask = |perm: u16| mask.map_or(perm, |m| perm & m);

    // 1. File owner: ACL_USER_OBJ (never restricted by ACL_MASK).
    if uid == file_owner {
        return Some(user_obj & ACL_EXECUTE != 0);
    }
    // 2. Named user: matching ACL_USER entry, restricted by ACL_MASK if present.
    if let Some(perm) = named_user {
        return Some(apply_mask(perm) & ACL_EXECUTE != 0);
    }
    // 3. Owning group and named groups: granted if any matching entry (masked) has execute;
    //    if at least one group matched and none grants it, denied without falling through to other.
    let owning_group_matched = gids.contains(&file_group);
    if owning_group_matched || named_group_matched {
        let owning_group_exec = owning_group_matched && (apply_mask(group_obj) & ACL_EXECUTE != 0);
        let named_group_allowed = named_group_exec && (apply_mask(ACL_EXECUTE) != 0);
        return Some(owning_group_exec || named_group_allowed);
    }
    // 4. Everyone else: ACL_OTHER (never restricted by ACL_MASK).
    Some(other & ACL_EXECUTE != 0)
}

/// The credential files a site's configuration names (TLS, upstream TLS, bot keys).
fn tenant_credential_paths(site: &miraserve_config::SiteConfig) -> Vec<(String, String)> {
    let mut paths: Vec<(String, String)> = Vec::new();
    if let Some(tls) = &site.tls {
        for (field, value) in [
            ("tls.cert", &tls.cert),
            ("tls.key", &tls.key),
            ("tls.client-ca", &tls.client_ca),
        ] {
            if let Some(path) = value {
                paths.push((field.to_owned(), path.clone()));
            }
        }
    }
    if let Some(file) = site
        .bot_auth
        .as_ref()
        .and_then(|b| b.agent_keys_file.clone())
    {
        paths.push(("bot-auth.agent-keys-file".to_owned(), file));
    }
    for (index, route) in site.routes.iter().enumerate() {
        if let miraserve_config::RouteHandler::ReverseProxy(rp) = &route.handler
            && let Some(up) = &rp.upstream_tls
        {
            for (field, value) in [
                ("ca-cert", &up.ca_cert),
                ("client-cert", &up.client_cert),
                ("client-key", &up.client_key),
            ] {
                if let Some(path) = value {
                    paths.push((
                        format!("route[{index}].reverse-proxy.upstream-tls.{field}"),
                        path.clone(),
                    ));
                }
            }
        }
    }
    paths
}

/// A sandbox grant being attributed: its path and, when known, its access (`None`: any access,
/// e.g. a grant that failed to open, which hurts whoever asks for that path).
pub type WantedGrant = (Option<miraserve_sandbox::GrantClass>, std::path::PathBuf);

fn asks_for(
    grants: &std::collections::BTreeSet<(miraserve_sandbox::GrantClass, std::path::PathBuf)>,
    wanted: &WantedGrant,
) -> bool {
    match wanted {
        (Some(class), path) => grants.contains(&(*class, path.clone())),
        (None, path) => grants.iter().any(|(_, p)| p == path),
    }
}

/// For each wanted grant, the sites (indices) whose own configuration asks for it (with that
/// access), and whether the server itself does: the policy is built once without sites and once
/// per site, so a grant two sites share is attributed to both. Quarantined sites ask for nothing.
pub fn grant_consumers(
    cfg: &Config,
    build: &dyn Fn(&Config) -> SandboxPolicy,
    wanted: &[WantedGrant],
) -> Vec<(WantedGrant, Vec<usize>, bool)> {
    let mut no_sites = cfg.clone();
    no_sites.sites.clear();
    let server_grants = build(&no_sites).requested_grants();
    // One-site configurations are built from the site-less copy (no full clone per site).
    // Path -> (class, site index) of every one-site build's request, so each wanted grant is
    // a lookup instead of a scan over all sites.
    let mut requested_by: std::collections::HashMap<
        std::path::PathBuf,
        Vec<(miraserve_sandbox::GrantClass, usize)>,
    > = std::collections::HashMap::new();
    for (index, site) in cfg.sites.iter().enumerate() {
        let mut one = no_sites.clone();
        one.sites.push(site.clone());
        for (class, path) in build(&one).requested_grants() {
            requested_by.entry(path).or_default().push((class, index));
        }
    }
    wanted
        .iter()
        .map(|grant| {
            let mut consumers: Vec<usize> = requested_by
                .get(&grant.1)
                .map(|askers| {
                    let mut sites: Vec<usize> = askers
                        .iter()
                        .filter(|(class, _)| grant.0.is_none_or(|wanted| wanted == *class))
                        .map(|(_, index)| *index)
                        .collect();
                    sites.dedup();
                    sites
                })
                .unwrap_or_default();
            let server_needs = asks_for(&server_grants, grant);
            // The combined policy can grant a different shape than a one-site build (a file
            // instead of its directory when another site's key sits beside it). When no site
            // build asks for the path, attribute it to the sites whose configuration names it,
            // a file inside it, or a directory around it.
            if consumers.is_empty() && !server_needs {
                consumers = cfg
                    .sites
                    .iter()
                    .enumerate()
                    .filter(|(_, site)| {
                        site_referenced_paths(site).iter().any(|named| {
                            named == &grant.1
                                || named.starts_with(&grant.1)
                                || grant.1.starts_with(named)
                        })
                    })
                    .map(|(index, _)| index)
                    .collect();
            }
            (grant.clone(), consumers, server_needs)
        })
        .collect()
}

/// Every filesystem path a site's configuration names (roots, pages, TLS and upstream TLS
/// files, bot keys, users file, publish store, FastCGI sockets, WebAssembly modules), written
/// and resolved.
fn site_referenced_paths(site: &miraserve_config::SiteConfig) -> Vec<std::path::PathBuf> {
    let mut named: Vec<String> = Vec::new();
    named.extend(site.root.iter().cloned());
    named.extend(
        tenant_credential_paths(site)
            .into_iter()
            .map(|(_, path)| path),
    );
    if let Some(pages) = &site.error_pages {
        named.extend(pages.pages.values().cloned());
    }
    if let Some(auth) = &site.basic_auth {
        named.push(auth.users_file.clone());
    }
    if let Some(publish) = &site.ai_publish {
        named.push(publish.storage.clone());
    }
    for route in &site.routes {
        named.extend(route.root.iter().cloned());
        match &route.handler {
            miraserve_config::RouteHandler::FastCgi(fcgi) => {
                if let miraserve_config::FastCgiTarget::Unix { path } = &fcgi.target {
                    named.push(path.clone());
                }
            }
            miraserve_config::RouteHandler::WasmPlugin(wasm) => {
                named.push(wasm.module_path.clone());
            }
            _ => {}
        }
    }
    named
        .into_iter()
        .flat_map(|path| {
            let written = std::path::PathBuf::from(&path);
            let resolved = std::fs::canonicalize(&written).ok();
            std::iter::once(written).chain(resolved)
        })
        .collect()
}

/// Quarantines the tenant sites that are the ONLY consumers of a failing or uncovered sandbox
/// path. Returns `Err` with the paths that cannot be attributed that way (needed by the server
/// itself, by a site without `owner-dir`, or by nobody identifiable): those keep the previous
/// behaviour (refusal / restart). `Ok(true)` when sites were quarantined (rebuild the policy).
///
/// # Errors
/// The paths that cannot be attributed to tenant sites alone.
pub fn quarantine_sole_tenant_consumers(
    cfg: &mut Config,
    build: &dyn Fn(&Config) -> SandboxPolicy,
    wanted: &[WantedGrant],
) -> Result<bool, Vec<WantedGrant>> {
    let mut unattributable = Vec::new();
    let mut tenants: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    for (grant, consumers, server_needs) in grant_consumers(cfg, build, wanted) {
        let all_tenant = !consumers.is_empty()
            && consumers.iter().all(|index| {
                cfg.sites
                    .get(*index)
                    .is_some_and(|site| site.owner_dir.is_some())
            });
        if server_needs || !all_tenant {
            unattributable.push(grant);
        } else {
            tenants.extend(consumers);
        }
    }
    if !unattributable.is_empty() {
        return Err(unattributable);
    }
    for index in &tenants {
        if let Some(site) = cfg.sites.get_mut(*index) {
            quarantine_site(
                site,
                "a sandbox grant this site needs failed or is outside the startup policy; restart MiraServe after fixing it".to_owned(),
            );
        }
    }
    Ok(!tenants.is_empty())
}

/// Builds the startup sandbox policy for `cfg`: tenant sites that are the only consumers of a
/// failing grant are quarantined and the policy is rebuilt; the paths only tenant sites need are
/// recorded in the policy, so a late failure on one of them at finalization stays local. Grant
/// failures that remain are left in the returned policy for the caller to refuse.
pub fn prepare_startup_policy(
    cfg: &mut Config,
    build: &dyn Fn(&Config) -> SandboxPolicy,
) -> SandboxPolicy {
    let mut policy = build(cfg);
    for _ in 0..cfg.sites.len() {
        let failed: Vec<WantedGrant> = policy
            .grant_failure_paths()
            .into_iter()
            .map(|path| (None, path))
            .collect();
        if failed.is_empty()
            || !matches!(
                quarantine_sole_tenant_consumers(cfg, build, &failed),
                Ok(true)
            )
        {
            break;
        }
        policy = build(cfg);
    }
    if cfg.sites.iter().any(|site| site.owner_dir.is_some()) {
        // A path counts as tenant-only when, in whatever access it is asked for, only tenant
        // sites ask for it.
        let all: Vec<WantedGrant> = policy
            .requested_grants()
            .into_iter()
            .map(|(_, path)| (None, path))
            .collect();
        policy.tenant_only_paths = grant_consumers(cfg, build, &all)
            .into_iter()
            .filter(|(_, consumers, server_needs)| {
                !server_needs
                    && !consumers.is_empty()
                    && consumers.iter().all(|index| {
                        cfg.sites
                            .get(*index)
                            .is_some_and(|site| site.owner_dir.is_some())
                    })
            })
            .map(|((_, path), _, _)| path)
            .collect();
    }
    policy
}

/// Marks `site` unavailable (503) for `reason` and drops its document roots.
pub fn quarantine_site(site: &mut miraserve_config::SiteConfig, reason: String) {
    warn!(
        site = %site.hosts.first().map_or("<site>", String::as_str),
        problems = %reason,
        "unsafe or inaccessible document root: this site answers 503; the other sites load normally"
    );
    site.quarantine = Some(reason);
    drop_site_resources(site);
}

fn drop_roots(site: &mut miraserve_config::SiteConfig) {
    site.root = None;
    for route in &mut site.routes {
        route.root = None;
    }
}

/// A quarantined site answers 503 and serves nothing: its document roots are dropped (so they
/// are never opened or granted), and the router compiles the site from a copy without routes,
/// publishing, keys or pages. Everything else stays in the configuration so the server-wide
/// protection lists (users files, publish stores, TLS and upstream keys) keep seeing it.
fn drop_site_resources(site: &mut miraserve_config::SiteConfig) {
    drop_roots(site);
}

/// Log files that lie inside a configured document root AS WRITTEN (an operator mistake, never a
/// tenant's doing): these refuse the configuration outright instead of quarantining the site.
#[must_use]
pub fn lexical_log_overlaps(cfg: &Config, log_files: &[std::path::PathBuf]) -> Vec<String> {
    let mut found = Vec::new();
    for site in &cfg.sites {
        let roots = site
            .root
            .iter()
            .chain(site.routes.iter().filter_map(|route| route.root.as_ref()));
        for root in roots {
            let root_path = std::path::Path::new(root);
            if !root_path.is_absolute() {
                continue;
            }
            for log in log_files {
                if log.starts_with(root_path) {
                    found.push(format!(
                        "document root '{root}' overlaps log file '{}'",
                        log.display()
                    ));
                }
            }
        }
    }
    found
}

/// Why a directory holding server credentials (or the ACME webroot) could be replaced by an
/// account other than root: a directory from its parent up to `/` that is a link, is not owned
/// by root, or is writable by group or others without the sticky bit (whoever can write there
/// can rename the tree below away and put another in its place). `None` when every ancestor is
/// root's alone (or on platforms without these permission bits).
#[must_use]
pub fn replaceable_ancestor(path: &std::path::Path) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        for dir in path.ancestors().skip(1) {
            if dir.as_os_str().is_empty() {
                continue;
            }
            let Ok(meta) = std::fs::symlink_metadata(dir) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                return Some(format!("'{}' is a symbolic link", dir.display()));
            }
            if meta.uid() != 0 {
                return Some(format!(
                    "'{}' is owned by uid {}, not root",
                    dir.display(),
                    meta.uid()
                ));
            }
            let sticky = meta.mode() & 0o1000 != 0;
            if meta.mode() & 0o022 != 0 && !sticky {
                return Some(format!(
                    "'{}' is writable by group or others",
                    dir.display()
                ));
            }
        }
        None
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// Tenants cannot give a credential file a second name inside their document root only while
/// the kernel restricts hard links to a file's owner (`fs.protected_hardlinks = 1`, the default
/// on current Linux distributions): say so loudly when it is off.
fn warn_if_hardlinks_unprotected() {
    #[cfg(target_os = "linux")]
    if std::fs::read_to_string("/proc/sys/fs/protected_hardlinks").is_ok_and(|v| v.trim() == "0") {
        warn!(
            "fs.protected_hardlinks is 0: any local account can hard-link files it can read into \
             a document root; set it to 1 (sysctl -w fs.protected_hardlinks=1) on shared hosting"
        );
    }
}

/// A tenant site isolated (quarantined) in this configuration: TLS installs nothing for it.
fn isolated_tenant(site: &miraserve_config::SiteConfig) -> bool {
    site.owner_dir.is_some() && site.quarantine.is_some()
}

/// Content digest (`None` when unreadable) of every client CA file `cfg` installs, by path.
/// An isolated tenant site gets no verifier, so its CA is not counted (restoring the site is
/// then a change that needs a restart).
fn client_ca_digests(cfg: &Config) -> std::collections::BTreeMap<String, Option<String>> {
    cfg.server
        .tls
        .client_ca
        .iter()
        .chain(
            cfg.sites
                .iter()
                .filter(|site| !isolated_tenant(site))
                .filter_map(|site| site.tls.as_ref().and_then(|tls| tls.client_ca.as_ref())),
        )
        .map(|path| {
            let digest = std::fs::File::open(path).ok().and_then(|file| {
                use std::io::Read as _;
                let mut raw = Vec::new();
                file.take(16 * 1024 * 1024).read_to_end(&mut raw).ok()?;
                Some(miraserve_tls::sha256_hex(&raw))
            });
            (path.clone(), digest)
        })
        .collect()
}

/// The settings of `next` that differ from `running` (the start-up configuration) and that only
/// a restart applies.
fn restart_required_settings(
    running: &Config,
    next: &Config,
    running_cas: &std::collections::BTreeMap<String, Option<String>>,
) -> Vec<&'static str> {
    let mut settings = Vec::new();
    if running.server.listeners != next.server.listeners {
        settings.push("server.listen");
    }
    if running.server.sandbox != next.server.sandbox {
        settings.push("server.sandbox");
    }
    if running.server.telemetry.metrics_listen != next.server.telemetry.metrics_listen {
        settings.push("server.telemetry.metrics-listen");
    }
    if running.server.telemetry.metrics_path != next.server.telemetry.metrics_path {
        settings.push("server.telemetry.metrics-path");
    }
    if running.server.telemetry.otlp_endpoint != next.server.telemetry.otlp_endpoint {
        settings.push("server.telemetry.otlp-endpoint");
    }
    if running.server.telemetry.service_name != next.server.telemetry.service_name {
        settings.push("server.telemetry.service-name");
    }
    if running.server.tls.ech != next.server.tls.ech
        || running.server.tls.ech_public_name != next.server.tls.ech_public_name
        || running.server.tls.ech_rotate_interval != next.server.tls.ech_rotate_interval
    {
        settings.push("server.tls.ech");
    }
    if running.server.tls.key_isolation != next.server.tls.key_isolation
        || running.server.tls.keyd_socket != next.server.tls.keyd_socket
    {
        settings.push("server.tls.key-isolation");
    }
    let site_cas = |cfg: &Config| -> std::collections::BTreeSet<(Vec<String>, String)> {
        cfg.sites
            .iter()
            .filter(|s| !isolated_tenant(s))
            .filter_map(|s| {
                let ca = s.tls.as_ref().and_then(|t| t.client_ca.clone())?;
                Some((s.hosts.clone(), ca))
            })
            .collect()
    };
    // The TLS listeners verify client certificates with the CA contents loaded at start-up:
    // a different path, or new contents at the same path, needs a restart.
    if running.server.tls.client_ca != next.server.tls.client_ca
        || site_cas(running) != site_cas(next)
        || client_ca_digests(next) != *running_cas
    {
        settings.push("client-ca");
    }
    if running.server.limits.max_connections != next.server.limits.max_connections {
        settings.push("server.limits.max-connections");
    }
    if running.server.workers != next.server.workers {
        settings.push("server.workers");
    }
    settings
}

fn warn_on_non_reloadable_changes(prev: &Config, next: &Config) {
    if prev.server.listeners != next.server.listeners {
        warn!(
            "hot reload ignored changed `server.listen` bindings; restart MiraServe to rebind sockets"
        );
    }
    if prev.server.sandbox != next.server.sandbox {
        warn!(
            "hot reload ignored changed `server.sandbox` confinement; restart MiraServe to update OS sandbox"
        );
    }
    if prev.server.telemetry.metrics_listen != next.server.telemetry.metrics_listen
        || prev.server.telemetry.metrics_path != next.server.telemetry.metrics_path
    {
        warn!(
            "hot reload ignored changed `server.telemetry.metrics-listen`/`metrics-path`; restart required"
        );
    }
    if prev.server.telemetry.otlp_endpoint != next.server.telemetry.otlp_endpoint {
        warn!("hot reload ignored changed `server.telemetry.otlp-endpoint`; restart required");
    }
    if prev.server.tls.key_isolation != next.server.tls.key_isolation
        || prev.server.tls.keyd_socket != next.server.tls.keyd_socket
    {
        warn!(
            "hot reload ignored changed `server.tls.key-isolation`/`keyd-socket`; restart required"
        );
    }
    // Only sites that HAVE a `client-ca` count, keyed by their hosts: adding or removing a
    // site without one must not report changed trust roots.
    let site_cas = |cfg: &Config| -> std::collections::BTreeSet<(Vec<String>, String)> {
        cfg.sites
            .iter()
            .filter_map(|s| {
                let ca = s.tls.as_ref().and_then(|t| t.client_ca.clone())?;
                Some((s.hosts.clone(), ca))
            })
            .collect()
    };
    let prev_site_cas = site_cas(prev);
    let next_site_cas = site_cas(next);
    if prev.server.tls.client_ca != next.server.tls.client_ca || prev_site_cas != next_site_cas {
        warn!(
            "hot reload ignored changed TLS `client-ca` trust roots; restart required to rebuild mTLS verifier"
        );
    }
    if prev.server.tls.acme != next.server.tls.acme {
        info!(
            "hot reload updated `server.tls.acme` supervisor configuration; rebuilding ACME manager with directory-scoped state"
        );
    }
    if prev.server.limits.max_connections != next.server.limits.max_connections {
        warn!(
            "hot reload ignored changed `server.limits.max-connections`; restart required to resize global connection cap"
        );
    }
    if prev.server.workers != next.server.workers {
        warn!(
            "'workers' changed in the reloaded configuration; it takes effect when MiraServe is restarted"
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_https_tcp_loop(
    tcp: TcpListener,
    local_port: u16,
    store: Arc<ConfigStore>,
    tls_set: Arc<TlsConfigSet>,
    engine: Arc<HttpEngine>,
    tracker: Arc<ActiveTracker>,
    conn_sem: Arc<Semaphore>,
    per_ip_tracker: Arc<PerIpConnTracker>,
    mut shutdown: watch::Receiver<bool>,
    upgrade_force_close: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                accepted = tcp.accept() => {
                    match accepted {
                        Ok((stream, raw_peer)) => {
                            let peer_addr = canonicalize_peer_addr(raw_peer);
                            let Ok(permit) = Arc::clone(&conn_sem).try_acquire_owned() else {
                                log_throttled_conn_cap_drop(
                                    ConnCapReason::Global,
                                    "HTTPS TCP",
                                    peer_addr,
                                );
                                drop(stream);
                                continue;
                            };
                            let limits_snap = &store.snapshot().server.limits;
                            let is_trusted = limits_snap
                                .trusted_proxies
                                .iter()
                                .any(|cidr| cidr.contains(peer_addr.ip()));
                            let per_ip_lease = if is_trusted {
                                None
                            } else {
                                match per_ip_tracker.try_acquire(
                                    peer_addr.ip(),
                                    limits_snap.max_connections_per_ip,
                                    limits_snap.ipv6_prefix_conn_multiplier,
                                ) {
                                    Ok(lease) => Some(lease),
                                    Err(reason) => {
                                        log_throttled_conn_cap_drop(reason, "HTTPS TCP", peer_addr);
                                        drop(permit);
                                        drop(stream);
                                        continue;
                                    }
                                }
                            };
                            let _ = stream.set_nodelay(true);
                            let store_c = Arc::clone(&store);
                            let tls_c = Arc::clone(&tls_set);
                            let eng_c = Arc::clone(&engine);
                            let conn_guard = tracker.acquire();
                            let sd = shutdown.clone();
                            let force_close = upgrade_force_close.clone();
                            let (per_ip_guard, idle_state, evict_rx) = match per_ip_lease {
                                Some(l) => (Some(l.guard), Some(l.idle_state), Some(l.evict_rx)),
                                None => (None, None, None),
                            };
                            let lease = Arc::new(ConnectionLease::new(
                                per_ip_guard,
                                permit,
                                conn_guard,
                                Arc::clone(eng_c.telemetry()),
                            ));
                            tokio::spawn(async move {
                                handle_https_tcp_conn(
                                    stream,
                                    peer_addr,
                                    local_port,
                                    store_c,
                                    tls_c,
                                    eng_c,
                                    sd,
                                    lease,
                                    idle_state,
                                    evict_rx,
                                    force_close,
                                )
                                .await;
                            });
                        }
                        Err(err) => {
                            warn!(error = %err, "TCP accept error");
                            tokio::time::sleep(Duration::from_millis(25)).await;
                        }
                    }
                }
            }
        }
    })
}

#[allow(clippy::too_many_arguments)]
async fn handle_https_tcp_conn(
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    local_port: u16,
    store: Arc<ConfigStore>,
    tls_set: Arc<TlsConfigSet>,
    engine: Arc<HttpEngine>,
    shutdown: watch::Receiver<bool>,
    lease: Arc<ConnectionLease>,
    idle_state: Option<Arc<ConnectionIdleState>>,
    evict_rx: Option<watch::Receiver<bool>>,
    upgrade_force_close: watch::Receiver<bool>,
) {
    let cfg_snap = store.snapshot();
    let local_addr = stream
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], local_port)));
    // R5-DOS-1: Share ONE single combined TLS handshake deadline across both `LazyConfigAcceptor`
    // ClientHello reading AND `into_stream` handshake completion so peers cannot consume 2x timeout.
    let handshake_deadline = tokio::time::Instant::now() + cfg_snap.server.timeouts.tls_handshake;

    // R8-HTTP-1: slow-reader protection wraps the TCP socket itself, below TLS.
    let stream = miraserve_http::WriteGuardedIo::for_tcp_stream(
        stream,
        cfg_snap.server.timeouts.response_write_idle,
        cfg_snap.server.timeouts.min_response_rate_bps,
    );
    let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
    let start_handshake = match tokio::time::timeout_at(handshake_deadline, acceptor).await {
        Ok(Ok(hs)) => hs,
        Ok(Err(err)) => {
            debug!(peer = %peer_addr, error = %err, "TLS ClientHello read failed");
            return;
        }
        Err(_) => {
            warn!(peer = %peer_addr, "closing slow client: TLS handshake timed out reading ClientHello");
            return;
        }
    };

    let ch = start_handshake.client_hello();
    let sni = ch.server_name().map(str::to_owned);
    let alpns: Vec<Vec<u8>> = ch
        .alpn()
        .map(|iter| iter.map(<[u8]>::to_vec).collect())
        .unwrap_or_default();
    let alpn_refs: Vec<&[u8]> = alpns.iter().map(Vec::as_slice).collect();

    let selected_tls = tls_set.select_for_handshake(&cfg_snap, sni.as_deref(), &alpn_refs);
    let is_acme_alpn = Arc::ptr_eq(&selected_tls, &tls_set.acme_alpn);

    let tls_stream = match tokio::time::timeout_at(
        handshake_deadline,
        start_handshake.into_stream(selected_tls),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(err)) => {
            debug!(peer = %peer_addr, sni = sni.as_deref().unwrap_or("-"), error = %err, "TLS handshake failed");
            return;
        }
        Err(_) => {
            warn!(peer = %peer_addr, sni = sni.as_deref().unwrap_or("-"), "closing slow client: TLS handshake timed out");
            return;
        }
    };

    // RFC 8737 ACME TLS-ALPN-01 closes cleanly right after handshake verification.
    if is_acme_alpn {
        debug!(peer = %peer_addr, sni = sni.as_deref().unwrap_or("-"), "completed ACME TLS-ALPN-01 validation handshake");
        return;
    }

    let server_conn = tls_stream.get_ref().1;
    let is_tls13 = server_conn.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3);
    let is_pqc = server_conn
        .negotiated_key_exchange_group()
        .is_some_and(|g| g.name() == rustls::NamedGroup::X25519MLKEM768);
    // PUB-2: Extract verified mTLS peer leaf Subject DN AND raw DER chain directly from rustls
    // so the router cryptographically binds mTLS authorization to the routed site's own `client-ca`.
    let peer_cert_chain_der =
        miraserve_tls::extract_peer_cert_chain_der(server_conn.peer_certificates());
    let verified_client_cert_dn =
        miraserve_tls::extract_verified_client_cert_dn(server_conn.peer_certificates())
            .map(Arc::<str>::from);
    let is_split = cfg_snap.server.tls.key_isolation == KeyIsolation::SplitDaemon;
    engine.telemetry().record_tls_handshake(is_pqc, is_split);
    lease.mark_telemetry_active();

    let tls_info = TlsConnectionInfo {
        sni: sni.map(Arc::<str>::from),
        is_tls13,
        is_pqc,
        verified_client_cert_dn,
        peer_cert_chain_der,
    };

    let control = ConnectionControl {
        lease: Some(lease),
        idle_state,
        evict_rx,
        upgrade_force_close: Some(upgrade_force_close),
    };

    engine
        .serve_hyper_connection_with_control(
            tls_stream,
            peer_addr,
            local_addr,
            true,
            false,
            Some(tls_info),
            shutdown,
            control,
        )
        .await;
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn spawn_redirect_loop(
    tcp: TcpListener,
    local_port: u16,
    store: Arc<ConfigStore>,
    engine: Arc<HttpEngine>,
    tracker: Arc<ActiveTracker>,
    conn_sem: Arc<Semaphore>,
    per_ip_tracker: Arc<PerIpConnTracker>,
    mut shutdown: watch::Receiver<bool>,
    upgrade_force_close: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                accepted = tcp.accept() => {
                    match accepted {
                        Ok((stream, raw_peer)) => {
                            let peer_addr = canonicalize_peer_addr(raw_peer);
                            let Ok(permit) = Arc::clone(&conn_sem).try_acquire_owned() else {
                                log_throttled_conn_cap_drop(
                                    ConnCapReason::Global,
                                    "HTTP redirect",
                                    peer_addr,
                                );
                                drop(stream);
                                continue;
                            };
                            let limits_snap = &store.snapshot().server.limits;
                            let is_trusted = limits_snap
                                .trusted_proxies
                                .iter()
                                .any(|cidr| cidr.contains(peer_addr.ip()));
                            let per_ip_lease = if is_trusted {
                                None
                            } else {
                                match per_ip_tracker.try_acquire(
                                    peer_addr.ip(),
                                    limits_snap.max_connections_per_ip,
                                    limits_snap.ipv6_prefix_conn_multiplier,
                                ) {
                                    Ok(lease) => Some(lease),
                                    Err(reason) => {
                                        log_throttled_conn_cap_drop(
                                            reason,
                                            "HTTP redirect",
                                            peer_addr,
                                        );
                                        drop(permit);
                                        drop(stream);
                                        continue;
                                    }
                                }
                            };
                            let _ = stream.set_nodelay(true);
                            let local_addr = stream
                                .local_addr()
                                .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], local_port)));
                            // R8-HTTP-1: same socket-level slow-reader guard as the TLS path.
                            let timeouts_snap = &store.snapshot().server.timeouts;
                            let guarded = miraserve_http::WriteGuardedIo::for_tcp_stream(
                                stream,
                                timeouts_snap.response_write_idle,
                                timeouts_snap.min_response_rate_bps,
                            );
                            let eng = Arc::clone(&engine);
                            let conn_guard = tracker.acquire();
                            let sd = shutdown.clone();
                            let force_close = upgrade_force_close.clone();
                            let (per_ip_guard, idle_state, evict_rx) = match per_ip_lease {
                                Some(l) => (Some(l.guard), Some(l.idle_state), Some(l.evict_rx)),
                                None => (None, None, None),
                            };
                            let lease = Arc::new(RedirectConnectionLease::new(
                                conn_guard,
                                permit,
                                per_ip_guard,
                                Arc::clone(eng.telemetry()),
                            ));
                            tokio::spawn(async move {
                                // Keep one handle across `serve_hyper_connection_with_control` so
                                // non-upgraded connections close the TCP socket before releasing
                                // telemetry, active/drain guard, global permit, and per-IP slot
                                // in the exact v0.1.2 order.
                                let _lease_hold = Arc::clone(&lease);
                                lease.mark_telemetry_active();
                                let control = ConnectionControl {
                                    lease: Some(lease),
                                    idle_state,
                                    evict_rx,
                                    upgrade_force_close: Some(force_close),
                                };
                                eng.serve_hyper_connection_with_control(
                                    guarded,
                                    peer_addr,
                                    local_addr,
                                    false,
                                    true,
                                    None,
                                    sd,
                                    control,
                                )
                                .await;
                            });
                        }
                        Err(err) => {
                            warn!(error = %err, "HTTP redirect TCP accept error");
                            tokio::time::sleep(Duration::from_millis(25)).await;
                        }
                    }
                }
            }
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn spawn_h3_udp_loop(
    endpoint: quinn::Endpoint,
    local_port: u16,
    store: Arc<ConfigStore>,
    engine: Arc<HttpEngine>,
    tracker: Arc<ActiveTracker>,
    conn_sem: Arc<Semaphore>,
    per_ip_tracker: Arc<PerIpConnTracker>,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                incoming_opt = endpoint.accept() => {
                    let Some(incoming) = incoming_opt else {
                        break;
                    };
                    // RFC 9000 stateless QUIC Retry address validation prevents UDP amplification.
                    if !incoming.remote_address_validated() {
                        let _ = incoming.retry();
                        continue;
                    }
                    let peer_addr = canonicalize_peer_addr(incoming.remote_address());
                    let Ok(permit) = Arc::clone(&conn_sem).try_acquire_owned() else {
                        log_throttled_conn_cap_drop(ConnCapReason::Global, "QUIC", peer_addr);
                        incoming.refuse();
                        continue;
                    };
                    let limits_snap = &store.snapshot().server.limits;
                    let is_trusted = limits_snap
                        .trusted_proxies
                        .iter()
                        .any(|cidr| cidr.contains(peer_addr.ip()));
                    let per_ip_lease = if is_trusted {
                        None
                    } else {
                        match per_ip_tracker.try_acquire(
                            peer_addr.ip(),
                            limits_snap.max_connections_per_ip,
                            limits_snap.ipv6_prefix_conn_multiplier,
                        ) {
                            Ok(lease) => Some(lease),
                            Err(reason) => {
                                log_throttled_conn_cap_drop(reason, "QUIC", peer_addr);
                                drop(permit);
                                incoming.refuse();
                                continue;
                            }
                        }
                    };
                    let store_c = Arc::clone(&store);
                    let eng = Arc::clone(&engine);
                    let conn_guard = tracker.acquire();
                    let sd = shutdown.clone();
                    let local_addr = endpoint
                        .local_addr()
                        .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], local_port)));
                    let (per_ip_guard, idle_state, evict_rx) = match per_ip_lease {
                        Some(l) => (Some(l.guard), Some(l.idle_state), Some(l.evict_rx)),
                        None => (None, None, None),
                    };
                    tokio::spawn(async move {
                        let _per_ip_guard = per_ip_guard;
                        let _permit = permit;
                        let _guard = conn_guard;
                        let cfg_snap = store_c.snapshot();
                        let handshake_timeout = cfg_snap.server.timeouts.tls_handshake;
                        let is_pqc = cfg_snap.server.tls.pqc_hybrid;
                        let is_split = cfg_snap.server.tls.key_isolation == KeyIsolation::SplitDaemon;
                        match tokio::time::timeout(handshake_timeout, incoming).await {
                            Ok(Ok(quinn_conn)) => {
                                let telemetry = Arc::clone(eng.telemetry());
                                telemetry.record_tls_handshake(is_pqc, is_split);
                                telemetry.inc_active_connections();
                                let control = ConnectionControl {
                                    lease: None,
                                    idle_state,
                                    evict_rx,
                                    upgrade_force_close: None,
                                };
                                serve_h3_connection_with_control(
                                    quinn_conn,
                                    peer_addr,
                                    local_addr,
                                    eng,
                                    sd,
                                    control,
                                )
                                .await;
                                telemetry.dec_active_connections();
                            }
                            Ok(Err(err)) => {
                                debug!(peer = %peer_addr, error = %err, "QUIC handshake failed");
                            }
                            Err(_) => {
                                warn!(peer = %peer_addr, "closing slow client: QUIC handshake timed out");
                            }
                        }
                    });
                }
            }
        }
    })
}

/// Logs connection-cap drops at most once every 10 seconds per rejection reason (`R2-KEYD-3`,
/// `R5-DOS-1`) with distinct log messages for global, per-IP, and IPv6 `/48` aggregate caps.
fn log_throttled_conn_cap_drop(
    reason: ConnCapReason,
    protocol: &'static str,
    peer_addr: SocketAddr,
) {
    use std::sync::atomic::AtomicU64;
    use std::time::{SystemTime, UNIX_EPOCH};

    static LAST_GLOBAL_SECS: AtomicU64 = AtomicU64::new(0);
    static SUPPRESSED_GLOBAL: AtomicU64 = AtomicU64::new(0);
    static LAST_PER_IP_SECS: AtomicU64 = AtomicU64::new(0);
    static SUPPRESSED_PER_IP: AtomicU64 = AtomicU64::new(0);
    static LAST_V6_48_SECS: AtomicU64 = AtomicU64::new(0);
    static SUPPRESSED_V6_48: AtomicU64 = AtomicU64::new(0);

    let (last_secs, suppressed, msg) = match reason {
        ConnCapReason::Global => (
            &LAST_GLOBAL_SECS,
            &SUPPRESSED_GLOBAL,
            "global connection cap reached; dropping peer",
        ),
        ConnCapReason::PerIp => (
            &LAST_PER_IP_SECS,
            &SUPPRESSED_PER_IP,
            "per-IP connection cap reached; dropping peer",
        ),
        ConnCapReason::Ipv6Prefix48 => (
            &LAST_V6_48_SECS,
            &SUPPRESSED_V6_48,
            "IPv6 /48 aggregate connection cap reached; dropping peer",
        ),
    };

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let prev = last_secs.load(Ordering::Acquire);
    if now_secs.saturating_sub(prev) >= 10
        && last_secs
            .compare_exchange(prev, now_secs, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    {
        let skipped = suppressed.swap(0, Ordering::AcqRel);
        warn!(
            protocol,
            peer = %peer_addr,
            suppressed_since_last_warn = skipped,
            "{msg}"
        );
    } else {
        suppressed.fetch_add(1, Ordering::Relaxed);
    }
}

/// Helper re-export to verify a listener config references valid protocols.
#[must_use]
pub fn listener_uses_tls(listen: &ListenConfig) -> bool {
    !listen.redirect_https
}

#[cfg(test)]
mod conn_cap_tests {
    use super::*;

    #[test]
    fn ipv6_prefix48_aggregate_cap_blocks_prefix60_subnet_rotation()
    -> Result<(), Box<dyn std::error::Error>> {
        let tracker = Arc::new(PerIpConnTracker::default());
        let max_per_ip = 2_u32;
        // IPv6 /48 aggregate cap = 4 * max_per_ip = 8 connections across all /64 subnets in 2001:db8:abcd::/48!
        let mut held = Vec::new();
        for subnet in 0..4_u16 {
            for host in 1..=2_u16 {
                let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0xabcd, subnet, 0, 0, 0, host));
                let guard = tracker
                    .try_acquire(ip, max_per_ip, 4)
                    .map_err(|r| format!("expected acquire within /64 and /48 caps, got {r:?}"))?;
                held.push(guard);
            }
        }
        // A 5th distinct /64 inside the SAME /48 (e.g. a /60 attacker!) MUST be rejected with Ipv6Prefix48!
        let attacker_next_subnet = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0xabcd, 4, 0, 0, 0, 1));
        assert_eq!(
            tracker
                .try_acquire(attacker_next_subnet, max_per_ip, 4)
                .err(),
            Some(ConnCapReason::Ipv6Prefix48)
        );
        // A completely different /48 allocation is unaffected.
        let other_v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x9999, 0, 0, 0, 0, 1));
        assert!(tracker.try_acquire(other_v6, max_per_ip, 4).is_ok());

        // Dropping one guard frees both its /64 and /48 slots cleanly.
        held.pop();
        assert!(
            tracker
                .try_acquire(attacker_next_subnet, max_per_ip, 4)
                .is_ok()
        );
        Ok(())
    }

    #[test]
    fn r6_dos_2_ipv6_prefix48_multiplier_is_configurable() -> Result<(), Box<dyn std::error::Error>>
    {
        let tracker = Arc::new(PerIpConnTracker::default());
        let max_per_ip = 2_u32;
        let custom_mult = 6_u32; // /48 aggregate cap = 12 connections
        let mut held = Vec::new();
        for subnet in 0..6_u16 {
            for host in 1..=2_u16 {
                let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0xcafe, subnet, 0, 0, 0, host));
                let guard = tracker
                    .try_acquire(ip, max_per_ip, custom_mult)
                    .map_err(|r| format!("expected acquire within custom 6x /48 cap, got {r:?}"))?;
                held.push(guard);
            }
        }
        // 13th connection across a 7th /64 inside the same /48 hits the configured 6x cap.
        let over_cap = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0xcafe, 6, 0, 0, 0, 1));
        assert_eq!(
            tracker.try_acquire(over_cap, max_per_ip, custom_mult).err(),
            Some(ConnCapReason::Ipv6Prefix48)
        );
        drop(held);
        Ok(())
    }

    /// Evicted connections that live on (a request arrived, or an upgraded tunnel) still
    /// count: an address cannot keep evicting and so hold more than twice its limit
    /// (Cloudflare-skills audit of v0.1.0, claim 7).
    /// Evictions in many /64 networks of one IPv6 /48 add up: the /48 has a limit for evicted
    /// connections still around, like for connections (Antigravity review 27 P1 3).
    #[test]
    fn evicted_connections_of_an_ipv6_48_add_up() -> Result<(), Box<dyn std::error::Error>> {
        let tracker = Arc::new(PerIpConnTracker::default());
        // One connection per address, two per /48: the /48 may have 2 evicted ones around.
        let (per_ip, mult) = (1, 2);
        let address = |subnet: u16| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 9, subnet, 0, 0, 0, 1));
        let acquire = |subnet: u16| {
            let lease = tracker.try_acquire(address(subnet), per_ip, mult)?;
            lease.idle_state.enter_request();
            lease.idle_state.exit_request();
            Ok::<_, ConnCapReason>(lease)
        };
        let mut held = Vec::new();
        for subnet in [1, 2] {
            held.push(acquire(subnet).map_err(|r| format!("first of {subnet}: {r:?}"))?);
        }
        // An eviction in each /64: both evicted connections are still around.
        for subnet in [1, 2] {
            held.push(acquire(subnet).map_err(|r| format!("eviction in {subnet}: {r:?}"))?);
        }
        // The /48's two are used up, although each /64 could evict once more; a refused
        // eviction leaves no entry behind (Codex 71 finding 4).
        assert!(acquire(1).is_err());
        let entries = |tracker: &PerIpConnTracker| -> usize {
            tracker
                .draining_shards
                .iter()
                .map(|shard| shard.lock().map_or(0, |map| map.len()))
                .sum()
        };
        assert_eq!(entries(&tracker), 2);
        let fresh = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 9, 3, 0, 0, 0, 1));
        assert!(tracker.try_acquire(fresh, per_ip, mult).is_err());
        assert_eq!(entries(&tracker), 2);
        // until an evicted connection has ended.
        drop(held.remove(0));
        held.push(acquire(1).map_err(|r| format!("after one ended: {r:?}"))?);
        assert!(acquire(2).is_err());
        Ok(())
    }

    #[test]
    fn evicted_connections_count_until_they_end() -> Result<(), Box<dyn std::error::Error>> {
        let tracker = Arc::new(PerIpConnTracker::default());
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
        let limit = 2;
        let acquire = || {
            let lease = tracker.try_acquire(ip, limit, 4)?;
            // Idle at once, so that it can be evicted.
            lease.idle_state.enter_request();
            lease.idle_state.exit_request();
            Ok::<_, ConnCapReason>(lease)
        };
        let mut held = Vec::new();
        // The limit itself, then as many evictions as the limit.
        for n in 0..4 {
            held.push(acquire().map_err(|r| format!("connection {n}: {r:?}"))?);
        }
        assert_eq!(acquire().err(), Some(ConnCapReason::PerIp));
        // One evicted connection ends: one more eviction is possible, and only one.
        drop(held.remove(0));
        held.push(acquire().map_err(|r| format!("after one ended: {r:?}"))?);
        assert_eq!(acquire().err(), Some(ConnCapReason::PerIp));
        drop(held);
        assert!(acquire().is_ok());
        Ok(())
    }

    #[test]
    fn per_ip_cap_evicts_oldest_idle_keepalive_and_keeps_active_and_upgraded_protected()
    -> Result<(), Box<dyn std::error::Error>> {
        let tracker = Arc::new(PerIpConnTracker::default());
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));

        let lease1 = tracker
            .try_acquire(ip, 3, 4)
            .map_err(|r| format!("lease1 failed: {r:?}"))?;
        let lease2 = tracker
            .try_acquire(ip, 3, 4)
            .map_err(|r| format!("lease2 failed: {r:?}"))?;
        let lease3 = tracker
            .try_acquire(ip, 3, 4)
            .map_err(|r| format!("lease3 failed: {r:?}"))?;

        // While all 3 are active (never finished a request), a 4th MUST be rejected.
        assert_eq!(
            tracker.try_acquire(ip, 3, 4).err(),
            Some(ConnCapReason::PerIp)
        );

        // Lease 1 completes a request and goes idle FIRST (oldest idle).
        lease1.idle_state.enter_request();
        lease1.idle_state.exit_request();
        std::thread::sleep(Duration::from_millis(5));

        // Lease 2 completes a request and goes idle SECOND (newer idle).
        lease2.idle_state.enter_request();
        lease2.idle_state.exit_request();

        // Lease 3 is an upgraded WebSocket — must NEVER be evicted.
        lease3.idle_state.enter_request();
        lease3.idle_state.mark_upgraded();
        lease3.idle_state.exit_request();

        // 4th connection evicts lease1 (the oldest idle), leaving lease2 and lease3 untouched!
        let lease4 = tracker
            .try_acquire(ip, 3, 4)
            .map_err(|r| format!("expected oldest idle eviction, got {r:?}"))?;
        assert!(
            *lease1.evict_rx.borrow(),
            "oldest idle lease1 must be evicted"
        );
        assert!(
            !*lease2.evict_rx.borrow(),
            "newer idle lease2 must NOT be evicted yet"
        );
        assert!(
            !*lease3.evict_rx.borrow(),
            "upgraded WebSocket lease3 must NEVER be evicted"
        );

        // 5th connection evicts lease2 (now the oldest remaining idle).
        let lease5 = tracker
            .try_acquire(ip, 3, 4)
            .map_err(|r| format!("expected second idle eviction, got {r:?}"))?;
        assert!(*lease2.evict_rx.borrow(), "lease2 must now be evicted");

        // Now lease3 (upgraded), lease4 (active), and lease5 (active) are all non-idle -> 6th MUST fail!
        assert_eq!(
            tracker.try_acquire(ip, 3, 4).err(),
            Some(ConnCapReason::PerIp)
        );

        // Dropping evicted leases must NOT over-decrement active slots (still 3 active -> 6th still fails).
        drop(lease1);
        drop(lease2);
        assert_eq!(
            tracker.try_acquire(ip, 3, 4).err(),
            Some(ConnCapReason::PerIp)
        );

        // Dropping a live lease frees a slot cleanly.
        drop(lease4);
        let _lease6 = tracker
            .try_acquire(ip, 3, 4)
            .map_err(|r| format!("expected free slot after drop, got {r:?}"))?;
        drop((lease3, lease5));
        Ok(())
    }
}

#[cfg(test)]
mod acl_tests {
    use super::*;

    const UNDEF_ID: u32 = u32::MAX;

    fn encode_acl(version: u32, entries: &[(u16, u16, u32)]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + entries.len() * 8);
        out.extend_from_slice(&version.to_le_bytes());
        for &(tag, perm, id) in entries {
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&perm.to_le_bytes());
            out.extend_from_slice(&id.to_le_bytes());
        }
        out
    }

    #[test]
    fn owner_uses_user_obj_without_mask_or_fallthrough() {
        // Owner search is granted by USER_OBJ even when MASK strips all bits.
        let allow_owner = encode_acl(
            ACL_XATTR_VERSION,
            &[
                (ACL_USER_OBJ, 0o5, UNDEF_ID),
                (ACL_GROUP_OBJ, 0o0, UNDEF_ID),
                (ACL_MASK, 0o0, UNDEF_ID),
                (ACL_OTHER, 0o0, UNDEF_ID),
            ],
        );
        assert_eq!(
            acl_allows_search(&allow_owner, 100, 200, 100, &[200]),
            Some(true)
        );

        // Owner search denied by USER_OBJ does not fall through to named user, group, or other.
        let deny_owner = encode_acl(
            ACL_XATTR_VERSION,
            &[
                (ACL_USER_OBJ, 0o6, UNDEF_ID),
                (ACL_USER, 0o7, 100),
                (ACL_GROUP_OBJ, 0o7, UNDEF_ID),
                (ACL_MASK, 0o7, UNDEF_ID),
                (ACL_OTHER, 0o7, UNDEF_ID),
            ],
        );
        assert_eq!(
            acl_allows_search(&deny_owner, 100, 200, 100, &[200]),
            Some(false)
        );
    }

    #[test]
    fn named_user_with_and_without_restrictive_mask() {
        // Named user granted when no MASK entry exists.
        let no_mask = encode_acl(
            ACL_XATTR_VERSION,
            &[
                (ACL_USER_OBJ, 0o7, UNDEF_ID),
                (ACL_USER, 0o1, 500),
                (ACL_GROUP_OBJ, 0o0, UNDEF_ID),
                (ACL_OTHER, 0o0, UNDEF_ID),
            ],
        );
        assert_eq!(
            acl_allows_search(&no_mask, 100, 200, 500, &[300]),
            Some(true)
        );

        // Named user granted when MASK preserves execute.
        let permissive_mask = encode_acl(
            ACL_XATTR_VERSION,
            &[
                (ACL_USER_OBJ, 0o7, UNDEF_ID),
                (ACL_USER, 0o5, 500),
                (ACL_GROUP_OBJ, 0o0, UNDEF_ID),
                (ACL_MASK, 0o5, UNDEF_ID),
                (ACL_OTHER, 0o0, UNDEF_ID),
            ],
        );
        assert_eq!(
            acl_allows_search(&permissive_mask, 100, 200, 500, &[300]),
            Some(true)
        );

        // Named user denied when MASK strips execute, even if OTHER has execute.
        let restrictive_mask = encode_acl(
            ACL_XATTR_VERSION,
            &[
                (ACL_USER_OBJ, 0o7, UNDEF_ID),
                (ACL_USER, 0o7, 500),
                (ACL_GROUP_OBJ, 0o7, UNDEF_ID),
                (ACL_MASK, 0o6, UNDEF_ID),
                (ACL_OTHER, 0o7, UNDEF_ID),
            ],
        );
        assert_eq!(
            acl_allows_search(&restrictive_mask, 100, 200, 500, &[200]),
            Some(false)
        );

        // Named user entry without execute denies access without falling through to group or other.
        let explicit_deny = encode_acl(
            ACL_XATTR_VERSION,
            &[
                (ACL_USER_OBJ, 0o7, UNDEF_ID),
                (ACL_USER, 0o4, 500),
                (ACL_GROUP_OBJ, 0o7, UNDEF_ID),
                (ACL_MASK, 0o7, UNDEF_ID),
                (ACL_OTHER, 0o7, UNDEF_ID),
            ],
        );
        assert_eq!(
            acl_allows_search(&explicit_deny, 100, 200, 500, &[200]),
            Some(false)
        );
    }

    #[test]
    fn owning_group_respects_mask() {
        let minimal = encode_acl(
            ACL_XATTR_VERSION,
            &[
                (ACL_USER_OBJ, 0o7, UNDEF_ID),
                (ACL_GROUP_OBJ, 0o5, UNDEF_ID),
                (ACL_OTHER, 0o0, UNDEF_ID),
            ],
        );
        assert_eq!(
            acl_allows_search(&minimal, 100, 200, 500, &[300, 200]),
            Some(true)
        );

        let masked_out = encode_acl(
            ACL_XATTR_VERSION,
            &[
                (ACL_USER_OBJ, 0o7, UNDEF_ID),
                (ACL_GROUP_OBJ, 0o5, UNDEF_ID),
                (ACL_MASK, 0o4, UNDEF_ID),
                (ACL_OTHER, 0o7, UNDEF_ID),
            ],
        );
        assert_eq!(
            acl_allows_search(&masked_out, 100, 200, 500, &[200]),
            Some(false)
        );
    }

    #[test]
    fn named_group_grants_if_any_matching_group_has_execute() {
        let acl = encode_acl(
            ACL_XATTR_VERSION,
            &[
                (ACL_USER_OBJ, 0o7, UNDEF_ID),
                (ACL_GROUP_OBJ, 0o4, UNDEF_ID),
                (ACL_GROUP, 0o4, 300),
                (ACL_GROUP, 0o1, 400),
                (ACL_MASK, 0o5, UNDEF_ID),
                (ACL_OTHER, 0o0, UNDEF_ID),
            ],
        );
        // Matches owning group (no x) and named group 400 (has x) -> allowed.
        assert_eq!(
            acl_allows_search(&acl, 100, 200, 500, &[200, 400]),
            Some(true)
        );
        // Matches named group 300 (no x) and named group 400 (has x) -> allowed.
        assert_eq!(
            acl_allows_search(&acl, 100, 200, 500, &[300, 400]),
            Some(true)
        );

        // Restrictive mask blocks named group even when the entry itself has execute.
        let masked = encode_acl(
            ACL_XATTR_VERSION,
            &[
                (ACL_USER_OBJ, 0o7, UNDEF_ID),
                (ACL_GROUP_OBJ, 0o0, UNDEF_ID),
                (ACL_GROUP, 0o7, 400),
                (ACL_MASK, 0o6, UNDEF_ID),
                (ACL_OTHER, 0o7, UNDEF_ID),
            ],
        );
        assert_eq!(
            acl_allows_search(&masked, 100, 200, 500, &[400]),
            Some(false)
        );
    }

    #[test]
    fn group_matched_without_execute_is_denied() {
        let acl = encode_acl(
            ACL_XATTR_VERSION,
            &[
                (ACL_USER_OBJ, 0o7, UNDEF_ID),
                (ACL_GROUP_OBJ, 0o4, UNDEF_ID),
                (ACL_GROUP, 0o6, 300),
                (ACL_MASK, 0o7, UNDEF_ID),
                (ACL_OTHER, 0o7, UNDEF_ID),
            ],
        );
        // Owning group matched with no execute -> denied (does not fall through to OTHER).
        assert_eq!(acl_allows_search(&acl, 100, 200, 500, &[200]), Some(false));
        // Named group matched with no execute -> denied (does not fall through to OTHER).
        assert_eq!(acl_allows_search(&acl, 100, 200, 500, &[300]), Some(false));
    }

    #[test]
    fn other_applies_when_no_user_or_group_matches() {
        // ACL_OTHER is never restricted by ACL_MASK.
        let allow_other = encode_acl(
            ACL_XATTR_VERSION,
            &[
                (ACL_USER_OBJ, 0o0, UNDEF_ID),
                (ACL_GROUP_OBJ, 0o0, UNDEF_ID),
                (ACL_MASK, 0o0, UNDEF_ID),
                (ACL_OTHER, 0o1, UNDEF_ID),
            ],
        );
        assert_eq!(
            acl_allows_search(&allow_other, 100, 200, 500, &[999]),
            Some(true)
        );

        let deny_other = encode_acl(
            ACL_XATTR_VERSION,
            &[
                (ACL_USER_OBJ, 0o7, UNDEF_ID),
                (ACL_GROUP_OBJ, 0o7, UNDEF_ID),
                (ACL_MASK, 0o7, UNDEF_ID),
                (ACL_OTHER, 0o6, UNDEF_ID),
            ],
        );
        assert_eq!(
            acl_allows_search(&deny_other, 100, 200, 500, &[999]),
            Some(false)
        );
    }

    #[test]
    fn unparseable_acl_returns_none() {
        let base_entries = [
            (ACL_USER_OBJ, 0o7, UNDEF_ID),
            (ACL_GROUP_OBJ, 0o5, UNDEF_ID),
            (ACL_OTHER, 0o5, UNDEF_ID),
        ];

        // Bad version.
        let v1 = encode_acl(1, &base_entries);
        assert_eq!(acl_allows_search(&v1, 100, 200, 500, &[300]), None);
        let v3 = encode_acl(3, &base_entries);
        assert_eq!(acl_allows_search(&v3, 100, 200, 500, &[300]), None);

        // Empty, short header, zero entries, and truncated entry.
        assert_eq!(acl_allows_search(&[], 100, 200, 500, &[300]), None);
        assert_eq!(acl_allows_search(&[2, 0, 0], 100, 200, 500, &[300]), None);
        assert_eq!(
            acl_allows_search(&encode_acl(ACL_XATTR_VERSION, &[]), 100, 200, 500, &[300]),
            None
        );
        let mut truncated = encode_acl(ACL_XATTR_VERSION, &base_entries);
        truncated.extend_from_slice(&[0_u8; 4]);
        assert_eq!(acl_allows_search(&truncated, 100, 200, 500, &[300]), None);

        // Unknown tag.
        let bad_tag = encode_acl(
            ACL_XATTR_VERSION,
            &[
                (ACL_USER_OBJ, 0o7, UNDEF_ID),
                (ACL_GROUP_OBJ, 0o5, UNDEF_ID),
                (0x40, 0o5, UNDEF_ID),
                (ACL_OTHER, 0o5, UNDEF_ID),
            ],
        );
        assert_eq!(acl_allows_search(&bad_tag, 100, 200, 500, &[300]), None);

        // Missing required base entry (ACL_OTHER).
        let missing_other = encode_acl(
            ACL_XATTR_VERSION,
            &[
                (ACL_USER_OBJ, 0o7, UNDEF_ID),
                (ACL_GROUP_OBJ, 0o5, UNDEF_ID),
            ],
        );
        assert_eq!(
            acl_allows_search(&missing_other, 100, 200, 500, &[300]),
            None
        );

        // Duplicate singleton entry (ACL_MASK).
        let dup_mask = encode_acl(
            ACL_XATTR_VERSION,
            &[
                (ACL_USER_OBJ, 0o7, UNDEF_ID),
                (ACL_GROUP_OBJ, 0o5, UNDEF_ID),
                (ACL_MASK, 0o5, UNDEF_ID),
                (ACL_MASK, 0o5, UNDEF_ID),
                (ACL_OTHER, 0o5, UNDEF_ID),
            ],
        );
        assert_eq!(acl_allows_search(&dup_mask, 100, 200, 500, &[300]), None);
    }
}

#[cfg(test)]
mod restart_required_tests {
    use super::restart_required_settings;

    fn config(
        listen: &str,
        root: &str,
    ) -> Result<miraserve_config::Config, Box<dyn std::error::Error>> {
        let kdl = format!(
            "server {{\n    listen \"{listen}\" protocols=\"h1\"\n}}\nsite \"a.test\" {{\n    root \"{root}\"\n}}\n"
        );
        Ok(miraserve_config::parse_kdl("restart.kdl", &kdl)?.0)
    }

    /// A reload that changes the listeners is reported as needing a restart (compared with the
    /// start-up configuration, so the next reload reports it too); a site change is not.
    #[test]
    fn listener_changes_are_reported_until_restart() -> Result<(), Box<dyn std::error::Error>> {
        let startup = config("127.0.0.1:8080", "/srv/a")?;
        let site_only = config("127.0.0.1:8080", "/srv/b")?;
        let new_listener = config("127.0.0.1:3080", "/srv/a")?;
        let cas = std::collections::BTreeMap::new();
        assert_eq!(
            restart_required_settings(&startup, &site_only, &cas),
            Vec::<&str>::new()
        );
        assert_eq!(
            restart_required_settings(&startup, &new_listener, &cas),
            vec!["server.listen"]
        );
        Ok(())
    }

    /// Changing `server.workers` reports `server.workers` in `restart_required` on the first
    /// reload and on repeated reloads (compared with startup), and reverting clears it.
    #[test]
    fn workers_change_repeat_and_revert_updates_restart_required()
    -> Result<(), Box<dyn std::error::Error>> {
        let with_workers = |workers_line: &str, root: &str| {
            let kdl = format!(
                "server {{\n    listen \"127.0.0.1:8080\" protocols=\"h1\"\n    workers {workers_line}\n}}\nsite \"a.test\" {{\n    root \"{root}\"\n}}\n"
            );
            Ok::<_, Box<dyn std::error::Error>>(miraserve_config::parse_kdl("workers.kdl", &kdl)?.0)
        };
        let startup = with_workers("2", "/srv/a")?;
        let changed = with_workers("4", "/srv/a")?;
        let repeated_with_site_change = with_workers("4", "/srv/b")?;
        let reverted = with_workers("2", "/srv/b")?;
        let cas = std::collections::BTreeMap::new();

        assert_eq!(
            restart_required_settings(&startup, &changed, &cas),
            vec!["server.workers"]
        );
        assert_eq!(
            restart_required_settings(&startup, &repeated_with_site_change, &cas),
            vec!["server.workers"]
        );
        assert_eq!(
            restart_required_settings(&startup, &reverted, &cas),
            Vec::<&str>::new()
        );
        Ok(())
    }
}

#[cfg(test)]
mod worker_loop_tests {
    use super::{WORKER_BLOCKING_THREAD_KEEP_ALIVE, event_loop_count, worker_max_blocking_threads};
    use miraserve_config::{KeyIsolation, Workers};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[test]
    fn split_daemon_forces_shared_runtime_regardless_of_workers() {
        assert_eq!(
            event_loop_count(Workers::Shared, KeyIsolation::InProcess),
            0
        );
        assert_eq!(
            event_loop_count(Workers::Shared, KeyIsolation::SplitDaemon),
            0
        );
        assert_eq!(
            event_loop_count(Workers::Count(4), KeyIsolation::SplitDaemon),
            0
        );
        assert_eq!(
            event_loop_count(Workers::Auto, KeyIsolation::SplitDaemon),
            0
        );
        #[cfg(target_os = "linux")]
        assert_eq!(
            event_loop_count(Workers::Count(4), KeyIsolation::InProcess),
            4
        );
        #[cfg(not(target_os = "linux"))]
        assert_eq!(
            event_loop_count(Workers::Count(4), KeyIsolation::InProcess),
            0
        );
    }

    #[test]
    fn worker_blocking_thread_budget_divides_and_floors_at_eight() {
        assert_eq!(worker_max_blocking_threads(1), 256);
        assert_eq!(worker_max_blocking_threads(2), 128);
        assert_eq!(worker_max_blocking_threads(4), 64);
        assert_eq!(worker_max_blocking_threads(8), 32);
        assert_eq!(worker_max_blocking_threads(32), 8);
        assert_eq!(worker_max_blocking_threads(64), 8);
        assert_eq!(worker_max_blocking_threads(256), 8);
        assert_eq!(WORKER_BLOCKING_THREAD_KEEP_ALIVE, Duration::from_secs(10));
    }

    /// A worker runtime built with `worker_max_blocking_threads(32)` (cap = 8) never executes
    /// more than 8 blocking tasks concurrently even when 24 are queued at once.
    #[test]
    fn worker_runtime_enforces_blocking_thread_cap() -> Result<(), Box<dyn std::error::Error>> {
        let cap = worker_max_blocking_threads(32);
        assert_eq!(cap, 8);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(cap)
            .thread_keep_alive(WORKER_BLOCKING_THREAD_KEEP_ALIVE)
            .build()?;

        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(std::sync::Barrier::new(cap));

        runtime.block_on(async {
            let mut handles = Vec::new();
            for i in 0..(cap * 3) {
                let active = Arc::clone(&active);
                let peak = Arc::clone(&peak);
                let gate = Arc::clone(&gate);
                handles.push(tokio::task::spawn_blocking(move || {
                    let cur = active.fetch_add(1, Ordering::AcqRel) + 1;
                    peak.fetch_max(cur, Ordering::AcqRel);
                    if i < cap {
                        // Hold the first `cap` slots until all `cap` threads are active together,
                        // proving concurrency reaches `cap` and cannot exceed it while queued tasks wait.
                        gate.wait();
                    } else {
                        std::thread::yield_now();
                    }
                    active.fetch_sub(1, Ordering::AcqRel);
                }));
            }
            for handle in handles {
                let _ = handle.await;
            }
        });
        assert_eq!(peak.load(Ordering::Acquire), cap);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn hook_test_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    #[cfg(target_os = "linux")]
    struct ResetStartHook;

    #[cfg(target_os = "linux")]
    impl Drop for ResetStartHook {
        fn drop(&mut self) {
            *super::WORKER_START_TEST_HOOK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        }
    }

    #[cfg(target_os = "linux")]
    fn worker_test_config(
        workers: u16,
        tag: &str,
    ) -> Result<(miraserve_config::Config, std::path::PathBuf), Box<dyn std::error::Error>> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!(
            "miraserve-worker-start-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("index.html"), b"ready-ok")?;
        let sock = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = sock.local_addr()?.port();
        drop(sock);
        let kdl = format!(
            "server {{\n    listen \"127.0.0.1:{port}\" protocols=\"h2,h1\"\n    workers {workers}\n}}\nsite \"ready.test\" {{\n    root \"{}\"\n}}\n",
            dir.to_string_lossy().replace('\\', "/")
        );
        let (cfg, _) = miraserve_config::parse_kdl("worker-start.kdl", &kdl)?;
        Ok((cfg, dir))
    }

    /// `MiraServeServer::start()` does not return (so `status=ready` cannot be reported) until
    /// every worker event loop has completed initialization and registered its listeners.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn start_waits_until_every_worker_loop_acknowledges_readiness()
    -> Result<(), Box<dyn std::error::Error>> {
        let _serial = hook_test_lock().lock().await;
        let _reset = ResetStartHook;
        let (cfg, dir) = worker_test_config(2, "wait")?;

        let worker1_entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker1_gate = Arc::new(std::sync::Barrier::new(2));
        let entered_c = Arc::clone(&worker1_entered);
        let gate_c = Arc::clone(&worker1_gate);
        *super::WORKER_START_TEST_HOOK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(move |idx| {
            if idx == 1 {
                entered_c.store(true, Ordering::Release);
                gate_c.wait();
            }
            None
        }));

        let store = Arc::new(miraserve_config::ConfigStore::new(cfg));
        let mut start_task = tokio::spawn(super::MiraServeServer::start(
            store,
            super::ServerOptions {
                dev_tls: true,
                ..super::ServerOptions::default()
            },
        ));

        // Wait until worker 1 has started initializing and is parked at the barrier.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !worker1_entered.load(Ordering::Acquire) {
            assert!(
                std::time::Instant::now() < deadline,
                "worker 1 did not enter startup hook"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // `start()` MUST still be pending while worker 1 has not finished initializing.
        assert!(
            tokio::time::timeout(Duration::from_millis(80), &mut start_task)
                .await
                .is_err(),
            "start() must not return before all worker loops acknowledge readiness"
        );

        // Release worker 1; `start()` must now finish cleanly.
        let gate_release = Arc::clone(&worker1_gate);
        let release_task = tokio::task::spawn_blocking(move || {
            gate_release.wait();
        });
        let server = tokio::time::timeout(Duration::from_secs(5), start_task).await???;
        let _ = release_task.await;
        server.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// If any worker event loop fails during initialization (e.g. Landlock failure), `start()`
    /// fails cleanly and rolls back already-started worker loops instead of reporting ready.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn start_fails_and_rolls_back_when_worker_loop_init_fails()
    -> Result<(), Box<dyn std::error::Error>> {
        let _serial = hook_test_lock().lock().await;
        let _reset = ResetStartHook;
        let (cfg, dir) = worker_test_config(2, "fail")?;

        *super::WORKER_START_TEST_HOOK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(move |idx| {
            (idx == 1).then(|| {
                super::CoreError::Sandbox(miraserve_sandbox::SandboxError::Landlock(
                    "injected worker confinement failure".to_owned(),
                ))
            })
        }));

        let store = Arc::new(miraserve_config::ConfigStore::new(cfg));
        let res = super::MiraServeServer::start(
            store,
            super::ServerOptions {
                dev_tls: true,
                ..super::ServerOptions::default()
            },
        )
        .await;
        assert!(
            matches!(res, Err(super::CoreError::Sandbox(_))),
            "expected CoreError::Sandbox when worker 1 fails init"
        );

        // Worker 0 must have been rolled back and joined before `start()` returned `Err`.
        // Poll briefly for Linux `release_task()` to unlink the already-joined TID from
        // `/proc/self/task` after `pthread_join` wakes on `CLONE_CHILD_CLEARTID`.
        let reap_deadline = std::time::Instant::now() + Duration::from_millis(250);
        let remaining_loops = loop {
            let count = std::fs::read_dir("/proc/self/task")?
                .filter_map(Result::ok)
                .filter_map(|task| std::fs::read_to_string(task.path().join("comm")).ok())
                .filter(|name| name.starts_with("miraserve-loop-"))
                .count();
            if count == 0 || std::time::Instant::now() >= reap_deadline {
                break count;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        assert_eq!(
            remaining_loops, 0,
            "failed start() must roll back all already-started worker loops"
        );
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// M015 Intersection 9: With `workers` absent (the default), the configuration parses to
    /// `Workers::Shared`, omits `"workers"` from normalized JSON dumps (byte-identical to 0.1.4),
    /// requests 0 worker event loops on every platform (including Linux), spawns 0
    /// `miraserve-loop-*` threads on `MiraServeServer::start()`, keeps
    /// `is_worker_loop_thread() == false`, and shuts down cleanly via the exact 0.1.4 shared
    /// runtime path.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn m015_intersection_9_workers_absent_preserves_014_shared_runtime()
    -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(target_os = "linux")]
        let _serial = hook_test_lock().lock().await;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!(
            "miraserve-m015-i9-default-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("index.html"), b"shared-014-ok")?;

        let sock = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = sock.local_addr()?.port();
        drop(sock);

        let kdl = format!(
            "server {{\n    listen \"127.0.0.1:{port}\" protocols=\"h2,h1\"\n}}\nsite \"shared-default.test\" {{\n    root \"{}\"\n}}\n",
            dir.to_string_lossy().replace('\\', "/")
        );
        let (cfg, _) = miraserve_config::parse_kdl("i9-default.kdl", &kdl)?;
        assert_eq!(cfg.server.workers, Workers::Shared);
        assert!(cfg.server.workers.is_shared());

        // Default `workers` must be omitted from `--dump-normalized` JSON output.
        let normalized_json = serde_json::to_string_pretty(&cfg)?;
        assert!(
            !normalized_json.contains("\"workers\""),
            "default Workers::Shared must be omitted from normalized JSON: {normalized_json}"
        );

        // Zero dedicated worker event loops on every platform (including Linux).
        assert_eq!(
            event_loop_count(cfg.server.workers, cfg.server.tls.key_isolation),
            0,
            "omitted workers must resolve to 0 worker loops"
        );
        assert!(
            !miraserve_http::is_worker_loop_thread(),
            "shared runtime thread must not be marked as a worker loop"
        );

        // Start a real server with `workers` omitted and confirm zero worker threads spawned.
        let store = Arc::new(miraserve_config::ConfigStore::new(cfg));
        let running = super::MiraServeServer::start(
            store,
            super::ServerOptions {
                dev_tls: true,
                ..super::ServerOptions::default()
            },
        )
        .await?;
        assert!(
            running.worker_threads.is_empty(),
            "omitted workers must spawn 0 worker event loop threads (0.1.4 shared runtime)"
        );
        assert_eq!(running.restart_required(), Vec::<&str>::new());

        #[cfg(target_os = "linux")]
        {
            let worker_os_threads = std::fs::read_dir("/proc/self/task")?
                .filter_map(Result::ok)
                .filter_map(|task| std::fs::read_to_string(task.path().join("comm")).ok())
                .filter(|name| name.starts_with("miraserve-loop-"))
                .count();
            assert_eq!(
                worker_os_threads, 0,
                "omitted workers must create 0 miraserve-loop-* OS threads on Linux"
            );
        }

        running.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// Review round 1, Item 5 (P2): startup rollback worker joins share the same bounded deadline
    /// helper as normal shutdown so a stuck worker thread cannot prevent startup from returning
    /// its error.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn r1_item5_bounded_worker_join_returns_within_deadline_when_worker_stuck()
    -> Result<(), Box<dyn std::error::Error>> {
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (exited_tx, exited_rx) = tokio::sync::oneshot::channel::<()>();
        let stuck_thread = std::thread::Builder::new()
            .name("miraserve-stuck-rollback-test".to_owned())
            .spawn(move || {
                let _ = release_rx.recv();
                let _ = exited_tx.send(());
            })?;

        let (fast_exited_tx, fast_exited_rx) = tokio::sync::oneshot::channel::<()>();
        let fast_thread = std::thread::Builder::new()
            .name("miraserve-fast-rollback-test".to_owned())
            .spawn(move || {
                let _ = fast_exited_tx.send(());
            })?;

        let workers = vec![
            super::WorkerThreadHandle {
                exited: fast_exited_rx,
                thread: fast_thread,
            },
            super::WorkerThreadHandle {
                exited: exited_rx,
                thread: stuck_thread,
            },
        ];

        let started = std::time::Instant::now();
        let bound = Duration::from_millis(120);
        let remaining = super::join_worker_threads_bounded(
            workers,
            tokio::time::Instant::now() + bound,
            "startup rollback",
        )
        .await;
        let elapsed = started.elapsed();

        // Release the stuck thread immediately after verifying bounded return so no thread leaks.
        let _ = release_tx.send(());

        assert_eq!(
            remaining, 1,
            "fast worker must join while stuck worker times out at the rollback bound"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "bounded rollback join must return promptly at deadline, took {elapsed:?}"
        );
        Ok(())
    }
}

#[cfg(test)]
mod redirect_lease_tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use miraserve_telemetry::TelemetryRegistry;
    use tokio::sync::Semaphore;

    use super::{
        ActiveTracker, ConnectionLease, IpConnKey, PerIpConnTracker, RedirectConnectionLease,
    };

    /// Pins v0.1.2 drop order for redirect-listener connections under per-IP shard contention:
    /// telemetry active-connection count, active/drain guard, and global semaphore permit MUST
    /// all be released BEFORE attempting to acquire the per-IP shard lock.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn redirect_lease_releases_active_guard_and_global_permit_before_per_ip_slot()
    -> Result<(), Box<dyn std::error::Error>> {
        let tracker = Arc::new(ActiveTracker::default());
        let conn_sem = Arc::new(Semaphore::new(1));
        let per_ip_tracker = Arc::new(PerIpConnTracker::default());
        let telemetry = Arc::new(TelemetryRegistry::new());
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let (key, _) = IpConnKey::from_ip(ip);
        let shard_idx = key.shard_index();

        let permit = Arc::clone(&conn_sem)
            .try_acquire_owned()
            .map_err(|_| "expected global permit")?;
        let per_ip_lease = per_ip_tracker
            .try_acquire(ip, 4, 4)
            .map_err(|_| "expected per-IP lease")?;
        let conn_guard = tracker.acquire();
        let lease = RedirectConnectionLease::new(
            conn_guard,
            permit,
            Some(per_ip_lease.guard),
            Arc::clone(&telemetry),
        );
        lease.mark_telemetry_active();
        assert_eq!(tracker.current(), 1);
        assert_eq!(conn_sem.available_permits(), 0);
        assert!(
            telemetry
                .render_prometheus()
                .contains("miraserve_active_connections 1\n")
        );

        // Hold the per-IP shard lock on this thread while another thread drops the redirect lease.
        let shard_guard = per_ip_tracker
            .shards
            .get(shard_idx)
            .ok_or("missing shard")?
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dropper = std::thread::spawn(move || drop(lease));

        let deadline = Instant::now() + Duration::from_secs(2);
        while (tracker.current() != 0 || conn_sem.available_permits() != 1)
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(2));
        }

        assert_eq!(
            tracker.current(),
            0,
            "redirect lease must release ActiveGuard before blocking on per-IP shard lock"
        );
        assert_eq!(
            conn_sem.available_permits(),
            1,
            "redirect lease must release global semaphore permit before blocking on per-IP shard lock"
        );
        assert!(
            telemetry
                .render_prometheus()
                .contains("miraserve_active_connections 0\n"),
            "redirect lease must decrement active connections before blocking on per-IP shard lock"
        );

        drop(shard_guard);
        dropper.join().map_err(|_| "drop thread panicked")?;

        // Control: verify `ConnectionLease` (HTTPS TCP) keeps its exact v0.1.2 field order
        // (telemetry decrement first, then per-IP slot before permit and active guard).
        let https_permit = Arc::clone(&conn_sem)
            .try_acquire_owned()
            .map_err(|_| "expected global permit for HTTPS control")?;
        let https_per_ip = per_ip_tracker
            .try_acquire(ip, 4, 4)
            .map_err(|_| "expected per-IP lease for HTTPS control")?;
        let https_guard = tracker.acquire();
        let https_lease = ConnectionLease::new(
            Some(https_per_ip.guard),
            https_permit,
            https_guard,
            Arc::clone(&telemetry),
        );
        https_lease.mark_telemetry_active();
        let shard_guard = per_ip_tracker
            .shards
            .get(shard_idx)
            .ok_or("missing shard")?
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let https_dropper = std::thread::spawn(move || drop(https_lease));
        let deadline = Instant::now() + Duration::from_secs(2);
        while !telemetry
            .render_prometheus()
            .contains("miraserve_active_connections 0\n")
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(
            conn_sem.available_permits(),
            0,
            "HTTPS ConnectionLease must keep v0.1.2 drop order (per-IP guard before permit)"
        );
        assert_eq!(
            tracker.current(),
            1,
            "HTTPS ConnectionLease must keep v0.1.2 drop order (per-IP guard before active guard)"
        );
        drop(shard_guard);
        https_dropper
            .join()
            .map_err(|_| "HTTPS drop thread panicked")?;
        assert_eq!(conn_sem.available_permits(), 1);
        assert_eq!(tracker.current(), 0);
        Ok(())
    }

    #[test]
    fn emit_openat2_refused_advisory_selects_info_vs_warn_with_identical_text()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::Mutex;

        struct MsgVisitor(String);
        impl tracing::field::Visit for MsgVisitor {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "message" {
                    self.0 = value.to_owned();
                }
            }
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = format!("{value:?}");
                }
            }
        }
        struct Capture(Arc<Mutex<Vec<(tracing::Level, String)>>>);
        impl tracing::Subscriber for Capture {
            fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
                true
            }
            fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                tracing::span::Id::from_u64(1)
            }
            fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
            fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
            fn event(&self, event: &tracing::Event<'_>) {
                let mut v = MsgVisitor(String::new());
                event.record(&mut v);
                if let Ok(mut g) = self.0.lock() {
                    g.push((*event.metadata().level(), v.0));
                }
            }
            fn enter(&self, _: &tracing::span::Id) {}
            fn exit(&self, _: &tracing::span::Id) {}
        }

        let tls = r#"tls { cert "/etc/miraserve/c.pem"; key "/etc/miraserve/k.pem" }"#;
        let (default_cfg, _) = miraserve_config::parse_kdl(
            "default.kdl",
            &format!(
                "server {{ listen \":443\"; {tls} }}\nsite \"a.test\" {{ root \"/var/www/a\" }}"
            ),
        )?;
        let (fc_cfg, _) = miraserve_config::parse_kdl(
            "fc.kdl",
            &format!(
                "server {{ listen \":443\"; {tls} }}\nsite \"a.test\" {{ root \"/var/www/a\"; file-cache \"2s\" }}"
            ),
        )?;
        let (workers_cfg, _) = miraserve_config::parse_kdl(
            "wk.kdl",
            &format!(
                "server {{ listen \":443\"; workers 2; {tls} }}\nsite \"a.test\" {{ root \"/var/www/a\" }}"
            ),
        )?;

        let captured = Arc::new(Mutex::new(Vec::new()));
        let msg = "openat2 is refused in this process (synthetic test)";
        tracing::subscriber::with_default(Capture(Arc::clone(&captured)), || {
            super::emit_openat2_refused_advisory(&default_cfg, msg);
            super::emit_openat2_refused_advisory(&fc_cfg, msg);
            super::emit_openat2_refused_advisory(&workers_cfg, msg);
        });

        let events = captured.lock().map_err(|_| "mutex poisoned")?.clone();
        assert_eq!(
            events,
            vec![
                (tracing::Level::INFO, msg.to_owned()),
                (tracing::Level::WARN, msg.to_owned()),
                (tracing::Level::WARN, msg.to_owned()),
            ]
        );
        Ok(())
    }
}

/// Logs a runtime `openat2(2)` refusal advisory at `WARN` when the loaded configuration asks for
/// a feature degraded by the refusal (`file-cache` with a non-zero budget or non-`"shared"`
/// `workers`), and at `INFO` otherwise (same message text).
fn emit_openat2_refused_advisory(config: &Config, advisory: &str) {
    match openat2_refusal_advisory_level(config) {
        Openat2AdvisoryLevel::Warn => warn!("{advisory}"),
        Openat2AdvisoryLevel::Info => info!("{advisory}"),
    }
}

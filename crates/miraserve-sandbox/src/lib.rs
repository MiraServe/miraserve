#![forbid(unsafe_code)]
//! Cross-platform OS confinement for MiraServe workers:
//! - Derives minimal filesystem & syscall confinement policies directly from [`Config`].
//! - On **Linux**: applies real kernel **Landlock LSM** filesystem restrictions and
//!   **seccomp-bpf** syscall filtering (`seccompiler`) across worker threads.
//! - On **macOS & Windows**: validates policy and reports OS confinement status clearly
//!   while `cap-std` document-root confinement remains active on every platform.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use miraserve_config::{
    Config, FastCgiTarget, KeyIsolation, Protocol, RouteHandler, SeccompMode, Workers,
};
use serde::Serialize;
use thiserror::Error;

mod pinned;

use pinned::validate_tenant_file;
pub use pinned::{
    LogDirBinding, PinnedLogDir, PinnedReadOnlyPath, PinnedWritableDir, bind_log_file_dir,
};
#[cfg(not(target_os = "linux"))]
use tracing::info;

/// Errors encountered while compiling or applying OS confinement.
#[derive(Debug, Error)]
pub enum SandboxError {
    /// Failed to construct or enforce Linux Landlock LSM rules.
    #[error("Landlock LSM confinement failed: {0}")]
    Landlock(String),
    /// Failed to compile or install the Linux seccomp-bpf filter.
    #[error("seccomp-bpf installation failed: {0}")]
    Seccomp(String),
    /// Worker process is still running with root privileges despite configured `sandbox.user`/`group`.
    #[error("privilege-drop requirement violated: {0}")]
    PrivilegeDrop(String),
}

/// Confinement enforcement outcome reported for each OS mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnforcementStatus {
    /// Enforced strictly by the OS kernel.
    Enforced,
    /// Enforced with partial/best-effort kernel ABI support.
    PartiallyEnforced,
    /// Explicitly disabled in configuration.
    Disabled,
    /// Not supported on this operating system (e.g. Linux LSM on macOS/Windows).
    UnsupportedPlatform,
}

/// Landlock ABI version targeted by MiraServe's ruleset (`ABI::V5`, Linux 6.10+).
///
/// Kernels supporting this ABI or newer enforce every requested right in full; kernels supporting
/// ABI 1..4 enforce with documented partial coverage; kernels without Landlock (or non-Linux
/// platforms) report Landlock as unavailable.
pub const LANDLOCK_TARGET_ABI_VERSION: u32 = 5;

/// Minimum Linux Landlock ABI required for `run` to start (`ABI::V1`).
pub const LANDLOCK_MIN_REQUIRED_ABI_VERSION: u32 = 1;

/// Outcome of a query-only Linux Landlock version query in the calling process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LandlockProbe {
    /// The version query succeeded and reported the given Landlock ABI version.
    Available(u32),
    /// The version query returned `EOPNOTSUPP` (Landlock disabled or query refused).
    Disabled,
    /// The version query failed without `EOPNOTSUPP` (Landlock not available or query refused).
    NotImplemented,
    /// Probing Landlock availability returned an unexpected error or ABI.
    ProbeError(String),
}

impl LandlockProbe {
    /// Returns the probed Landlock ABI version when available, or `None` otherwise.
    #[must_use]
    pub const fn available_abi(&self) -> Option<u32> {
        match *self {
            Self::Available(abi) => Some(abi),
            Self::Disabled | Self::NotImplemented | Self::ProbeError(_) => None,
        }
    }
}
#[cfg(target_os = "linux")]
pub use linux::probe_landlock_availability;

/// Effective Landlock enforcement level computed for a [`SandboxPolicy`] on the running host.
///
/// Shared by both `miraserve run` (when installing and reporting confinement) and
/// `miraserve check --writable-set` (without installing any ruleset).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LandlockEnforcement {
    /// Kernel supports Landlock at or above [`LANDLOCK_TARGET_ABI_VERSION`] and `run` enforces
    /// the policy in full.
    Enforced {
        /// Running kernel's Landlock ABI version.
        abi: u32,
    },
    /// Kernel supports Landlock below [`LANDLOCK_TARGET_ABI_VERSION`] and `run` enforces the
    /// documented partial coverage.
    Partial {
        /// Running kernel's Landlock ABI version.
        abi: u32,
    },
    /// Configuration disables Landlock (`sandbox { landlock #false }`).
    Disabled,
    /// Kernel does not support Landlock LSM, or the host platform is not Linux.
    Unavailable,
}

impl LandlockEnforcement {
    /// Formats the canonical first-line state record emitted by `miraserve check --writable-set`.
    #[must_use]
    pub fn state_line(self) -> String {
        match self {
            Self::Enforced { abi } => format!("landlock enforced abi={abi}"),
            Self::Partial { abi } => format!("landlock partial abi={abi}"),
            Self::Disabled => "landlock disabled".to_owned(),
            Self::Unavailable => "landlock unavailable".to_owned(),
        }
    }

    /// Returns `true` when Landlock would actively enforce rules (`Enforced` or `Partial`).
    #[must_use]
    pub const fn is_enforcing(self) -> bool {
        matches!(self, Self::Enforced { .. } | Self::Partial { .. })
    }
}

/// Classifies the effective [`LandlockEnforcement`] level from a policy's `landlock` switch and
/// the host kernel's probed Landlock ABI version (`None` on non-Linux or kernels without Landlock).
#[must_use]
pub const fn classify_landlock_enforcement(
    policy_landlock: bool,
    host_abi: Option<u32>,
) -> LandlockEnforcement {
    if !policy_landlock {
        return LandlockEnforcement::Disabled;
    }
    match host_abi {
        Some(abi) if abi >= LANDLOCK_TARGET_ABI_VERSION => LandlockEnforcement::Enforced { abi },
        Some(abi) if abi >= 1 => LandlockEnforcement::Partial { abi },
        _ => LandlockEnforcement::Unavailable,
    }
}

/// Probes the [`LandlockEnforcement`] level that `miraserve run` would apply for `policy` on the
/// current host, **without** installing any Landlock ruleset or setting `PR_SET_NO_NEW_PRIVS`.
///
/// - On non-Linux platforms, always returns [`LandlockEnforcement::Unavailable`] regardless of
///   `policy.landlock`.
/// - On Linux, returns [`LandlockEnforcement::Disabled`] immediately when `policy.landlock` is
///   `false`, without issuing any Landlock ABI probe syscall.
#[must_use]
pub fn probe_landlock_enforcement(policy: &SandboxPolicy) -> LandlockEnforcement {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = policy;
        LandlockEnforcement::Unavailable
    }
    #[cfg(target_os = "linux")]
    {
        if !policy.landlock {
            return LandlockEnforcement::Disabled;
        }
        let host_abi = linux::probe_host_landlock_abi();
        classify_landlock_enforcement(policy.landlock, host_abi)
    }
}

/// One writable Landlock candidate grant computed for a [`SandboxPolicy`].
///
/// Mirrors the narrowed policy-report contract for `miraserve check --writable-set`:
/// - Existing pinned grants carry the pinned object's verified path (point-in-time snapshot).
/// - Every candidate grant that does not exist or cannot be opened by the inspecting process is
///   reported as [`WritableGrant::Missing`] (never dropped silently).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WritableGrant {
    /// The granted filesystem object already exists and was pinned when the policy was built.
    /// On Linux, the path is derived from the pinned descriptor (`/proc/self/fd/<fd>`) and
    /// verified against the pinned `(st_dev, st_ino)` identity (never a blind second lookup).
    Installed(PathBuf),
    /// A candidate writable path that does not exist yet or could not be opened by the inspecting
    /// process; callers emit `writable-missing landlock <absolute lexical path>`.
    Missing(PathBuf),
}

/// Classifies why a [`GrantState::Failed`] entry failed so policy inspection
/// (`check --writable-set`) can distinguish unopenable candidates (`EACCES`, `ELOOP`, `ENOTDIR`)
/// from security/policy rejections and OS resource exhaustion (`EMFILE`, `ENFILE`, `ENOMEM`).
///
/// Unused by `miraserve run` and reload, which treat every [`GrantState::Failed`] identically to
/// `74a8243`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrantFailureKind {
    OpenError,
    PolicyRejection,
    ResourceExhausted,
}

/// Returns `true` when `err` represents OS descriptor or memory exhaustion (`EMFILE`, `ENFILE`, or
/// `ENOMEM`). Used exclusively by policy inspection (`check --writable-set`) so resource pressure
/// fails inspection cleanly rather than silently misclassifying a tenant as absent.
#[must_use]
pub fn is_resource_io_error(err: &std::io::Error) -> bool {
    if err.kind() == std::io::ErrorKind::OutOfMemory {
        return true;
    }
    #[cfg(unix)]
    {
        matches!(
            rustix::io::Errno::from_io_error(err),
            Some(rustix::io::Errno::MFILE | rustix::io::Errno::NFILE | rustix::io::Errno::NOMEM)
        )
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Whether a name-based Landlock rule existed (and was therefore finalized for installation) when
/// the startup policy was prepared, together with its Unix `(st_dev, st_ino)` identity and, on
/// Linux, the exact `O_PATH` descriptor installed on every thread (Codex Round-7/8/9 P2).
#[derive(Debug, Clone)]
enum GrantState {
    /// Path existed when grants were finalized; on Linux `fd` is the opened `O_PATH` descriptor
    /// from which `identity` was `fstat`-ed and from which EVERY worker thread installs its
    /// Landlock rule (zero pathname reopening).
    Installed {
        #[cfg(unix)]
        identity: (u64, u64),
        #[cfg(target_os = "linux")]
        fd: std::sync::Arc<std::os::fd::OwnedFd>,
        #[cfg(target_os = "linux")]
        is_dir: bool,
        #[cfg(target_os = "linux")]
        file_type: rustix::fs::FileType,
    },
    /// Path did not exist at startup so Landlock omitted it; it cannot cover paths that appear
    /// later unless another installed ancestor covers them.
    AbsentAtStartup,
    /// The path exists (or could not be proven absent) but opening, inspecting or validating it
    /// failed — e.g. `EMFILE`, `EACCES`, `ELOOP`, an I/O error, or a `read-tree`/`socket-tree`
    /// whose opened object resolves into a forbidden directory. Startup and reload refuse every
    /// [`Self::Failed`] entry (quarantining sole tenant consumers); policy inspection
    /// (`check --writable-set`) fails closed on [`GrantFailureKind::PolicyRejection`] and
    /// [`GrantFailureKind::ResourceExhausted`], and reports [`GrantFailureKind::OpenError`] on
    /// writable candidates as `writable-missing`.
    Failed {
        reason: String,
        kind: GrantFailureKind,
    },
}

#[cfg(target_os = "linux")]
const fn linux_file_type_label(ft: rustix::fs::FileType) -> &'static str {
    match ft {
        rustix::fs::FileType::Directory => "directory",
        rustix::fs::FileType::RegularFile => "regular file",
        rustix::fs::FileType::Fifo => "FIFO",
        rustix::fs::FileType::Symlink => "symbolic link",
        rustix::fs::FileType::CharacterDevice => "character device",
        rustix::fs::FileType::BlockDevice => "block device",
        rustix::fs::FileType::Socket => "socket",
        rustix::fs::FileType::Unknown => "unknown file type",
    }
}

impl PartialEq for GrantState {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::AbsentAtStartup, Self::AbsentAtStartup) => true,
            (
                Self::Failed {
                    reason: a,
                    kind: ak,
                },
                Self::Failed {
                    reason: b,
                    kind: bk,
                },
            ) => a == b && ak == bk,
            #[cfg(target_os = "linux")]
            (
                Self::Installed {
                    identity: a_id,
                    is_dir: a_dir,
                    file_type: a_ft,
                    ..
                },
                Self::Installed {
                    identity: b_id,
                    is_dir: b_dir,
                    file_type: b_ft,
                    ..
                },
            ) => a_id == b_id && a_dir == b_dir && a_ft == b_ft,
            #[cfg(all(unix, not(target_os = "linux")))]
            (Self::Installed { identity: a_id }, Self::Installed { identity: b_id }) => {
                a_id == b_id
            }
            #[cfg(not(unix))]
            (Self::Installed {}, Self::Installed {}) => true,
            _ => false,
        }
    }
}

impl Eq for GrantState {}

/// The access a sandbox grant gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GrantClass {
    /// Read-only files or directories.
    Read,
    /// Read-write directories.
    Write,
    /// Unix sockets to connect to.
    Socket,
}

/// Complete confinement plan derived from a validated [`Config`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SandboxPolicy {
    /// Enable Linux Landlock LSM filesystem confinement.
    pub landlock: bool,
    /// Linux seccomp-bpf filtering profile.
    pub seccomp: SeccompMode,
    /// Configured unprivileged OS user (if any).
    pub user: Option<String>,
    /// Configured unprivileged OS group (if any).
    pub group: Option<String>,
    /// Minimal set of read-only directories or exact files required by the worker.
    pub read_only_paths: Vec<PathBuf>,
    /// Minimal set of read-write directories required by the worker (no execute/device flags).
    pub read_write_paths: Vec<PathBuf>,
    /// Validated directory handles pinned during policy construction so Landlock binds directly
    /// to the validated inode on every worker thread without reopening by pathname (Codex G7 P1).
    #[serde(skip)]
    pub pinned_read_write_dirs: Vec<PinnedWritableDir>,
    /// Tenant-controlled read-only paths (absolute custom error pages, WASM modules) validated
    /// with the loaders' no-follow rule and pinned, so their Landlock rules are installed from
    /// the validated identity instead of re-resolving a pathname (Codex Round-5 P1 #2).
    #[serde(skip)]
    pub pinned_read_only_paths: Vec<PinnedReadOnlyPath>,
    /// Exact Unix domain socket paths granted minimal `ReadFile | WriteFile` connect access.
    ///
    /// On Linux, a non-socket path added to a supplied or edited policy gets no socket rule at
    /// Landlock rule installation unless the policy still carries its internal `socket-tree` mark
    /// (for a directory originally configured as a `socket-tree`) or a shadowed-class mark (where
    /// a directory keeps the 0.1.5 socket-class rule and any other type is reduced to `ReadFile`
    /// only). [`Self::finalize_grants`] clears shadowed-class marks for paths no longer in
    /// `socket_paths`, but does not prune `socket-tree` marks or shadowed-class marks whose path
    /// remained in `socket_paths` (for example after removing a rotating-log directory from
    /// `read_write_paths` only).
    pub socket_paths: Vec<PathBuf>,
    /// Paths that only tenant sites (`owner-dir`) ask for (set by the caller from a consumer
    /// analysis). Such a grant that first appears at finalization and cannot be opened is left
    /// absent (that tenant's site fails on its own) instead of failing the whole start.
    #[serde(skip)]
    pub tenant_only_paths: BTreeSet<PathBuf>,
    /// Reloadable file paths (config, TLS certs/keys, bot keys) whose parent directory could NOT
    /// be widened under Landlock (falling back to exact-file rules; atomic-rename edits will
    /// require a restart until moved to a dedicated subdirectory, `R4-SBX-1`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exact_file_fallbacks: Vec<PathBuf>,
    /// Warnings produced while compiling the sandbox policy (e.g. explicitly configured root
    /// directories refused as unsafe system roots, `R4-SBX-2`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Startup install state and `(st_dev, st_ino)` identity of every name-based grant
    /// (`read-tree`, `socket-tree`, docroots, RW dirs) so `uncovered_paths_in` detects both
    /// replaced directories AND directories that were absent at startup and created later
    /// (Codex Round-7 P2 #4, Round-8 P2 #4).
    #[serde(skip)]
    grant_states: BTreeMap<PathBuf, GrantState>,
    /// Operator-configured `read-tree` / `socket-tree` entries whose OPENED object must pass the
    /// config validator's forbidden-tree rule before its descriptor is retained (Codex Round-10).
    #[serde(skip)]
    tree_paths: BTreeSet<PathBuf>,
    /// Subset of `tree_paths` configured specifically as `socket-tree` (used only by the Linux
    /// Landlock socket type guard).
    #[serde(skip)]
    socket_tree_paths: BTreeSet<PathBuf>,
    /// Socket-class spellings that shadowed an entry in `ro` or `rw` during class precedence in
    /// [`Self::from_config_with_file`], or matched the canonical rotating-log directory bound by
    /// [`Self::bind_log_rotation_dir`]. Pruned by [`Self::finalize_grants`] whenever a spelling is
    /// no longer in [`Self::socket_paths`]. On Linux, a wrong-type non-`socket-tree` entry in this
    /// set keeps the 0.1.5 socket-class rule with a warning when its descriptor is a directory,
    /// and reduces its socket-class rule to `ReadFile` only with a warning for any other type.
    #[serde(skip)]
    socket_shadows_other_class: BTreeSet<PathBuf>,
}

/// Audit report returned after applying a [`SandboxPolicy`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SandboxReport {
    /// Target OS name (`linux`, `macos`, `windows`).
    pub platform: &'static str,
    /// Landlock LSM enforcement state.
    pub landlock: EnforcementStatus,
    /// Seccomp-bpf enforcement state.
    pub seccomp: EnforcementStatus,
    /// Number of read-only paths granted to the sandboxed worker.
    pub read_only_path_count: usize,
    /// Number of read-write paths granted to the sandboxed worker.
    pub read_write_path_count: usize,
    /// Number of exact Unix socket paths granted connect access.
    pub socket_path_count: usize,
    /// Informational advisories (e.g. non-Linux host).
    pub notes: Vec<String>,
}

impl SandboxPolicy {
    /// Derives a least-privilege [`SandboxPolicy`] from a validated MiraServe [`Config`]
    /// and optional ACME state directory.
    #[must_use]
    pub fn from_config(config: &Config, acme_state_dir: Option<&Path>) -> Self {
        Self::from_config_with_file(config, None, acme_state_dir)
    }

    /// Derives a single unified least-privilege [`SandboxPolicy`] applied identically to the
    /// main thread (which executes `SIGHUP` reloads) and all Tokio worker threads (`R3-SBX-1`).
    ///
    /// - Grants read-only parent directories for reloadable files (config, certs, keys in
    ///   in-process mode, bot keys, publish public keys) AND canonical symlink target parents
    ///   (such as certbot's `archive/<site>/`, `R3-SBX-2`), while refusing broad shared
    ///   directories (`R3-SBX-3`) and never widening over any excluded private-key ancestor in
    ///   `split-daemon` mode (`R3-PKG-2`).
    /// - Never grants worker threads read-write access to `--pid-file`'s parent directory
    ///   (`R3-SBX-3`).
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn from_config_with_file(
        config: &Config,
        config_file: Option<&Path>,
        acme_state_dir: Option<&Path>,
    ) -> Self {
        let mut ro: BTreeSet<PathBuf> = BTreeSet::new();
        let mut rw: BTreeSet<PathBuf> = BTreeSet::new();
        let mut socks: BTreeSet<PathBuf> = BTreeSet::new();
        let mut fallbacks: BTreeSet<PathBuf> = BTreeSet::new();
        let mut pinned_ro: Vec<PinnedReadOnlyPath> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();
        let mut tree_paths: BTreeSet<PathBuf> = BTreeSet::new();
        let mut socket_tree_paths: BTreeSet<PathBuf> = BTreeSet::new();

        // System TLS trust anchors & DNS resolver needed for outbound HTTPS/ACME/proxy.
        // R3-SBX-3: Grant only public certificate directories/files — NEVER `/etc/ssl` or
        // `/etc/pki/tls` wholesale (which would expose `/etc/ssl/private` or `/etc/pki/tls/private`).
        // Include distro CA symlink targets (`/usr/share/ca-certificates`, `/usr/local/share/ca-certificates`,
        // `/usr/share/pki/ca-trust-source`, `/usr/share/pki/trust`, `/var/lib/ca-certificates`) and
        // resolve regular-file symlinks (e.g. `/etc/resolv.conf` -> `/run/systemd/resolve/stub-resolv.conf`)
        // so Landlock permits outbound TLS verification & DNS on Debian/Ubuntu, RHEL/Fedora, and SUSE.
        #[cfg(target_os = "linux")]
        {
            for sys_ro in [
                "/etc/ssl/certs",
                "/etc/ssl/openssl.cnf",
                "/etc/ssl/cert.pem",
                "/etc/ca-certificates",
                "/etc/ca-certificates.conf",
                "/usr/share/ca-certificates",
                "/usr/local/share/ca-certificates",
                "/etc/pki/tls/certs",
                "/etc/pki/tls/cert.pem",
                "/etc/pki/ca-trust",
                "/usr/share/pki/ca-trust-source",
                "/usr/share/pki/trust",
                "/var/lib/ca-certificates",
                "/etc/resolv.conf",
                "/etc/hosts",
            ] {
                let p = PathBuf::from(sys_ro);
                if p.exists() {
                    if let Ok(canon) = std::fs::canonicalize(&p)
                        && canon != p
                        && canon.is_file()
                    {
                        ro.insert(canon);
                    }
                    ro.insert(p);
                }
            }
        }

        let is_split_daemon = config.server.tls.key_isolation == KeyIsolation::SplitDaemon;

        // R3-PKG-2, R3-SBX-3 & R4-SBX-1: Always protect `/etc/miraserve/keys` from incidental
        // parent-directory widening (unless in-process mode explicitly loads a key from inside it),
        // and in split-daemon mode exclude EVERY configured private key path too!
        let mut excluded_key_paths: Vec<PathBuf> = Vec::new();
        let in_process_uses_keys_dir = !is_split_daemon
            && (config
                .server
                .tls
                .key
                .as_deref()
                .is_some_and(|k| Path::new(k).starts_with("/etc/miraserve/keys"))
                || config.sites.iter().any(|s| {
                    s.tls
                        .as_ref()
                        .and_then(|t| t.key.as_deref())
                        .is_some_and(|k| Path::new(k).starts_with("/etc/miraserve/keys"))
                }));
        if is_split_daemon || !in_process_uses_keys_dir {
            excluded_key_paths.push(PathBuf::from("/etc/miraserve/keys"));
        }
        if is_split_daemon {
            if let Some(key) = &config.server.tls.key {
                push_excluded_key(&mut excluded_key_paths, Path::new(key));
            }
            for site in &config.sites {
                if let Some(tls) = &site.tls
                    && let Some(key) = &tls.key
                {
                    push_excluded_key(&mut excluded_key_paths, Path::new(key));
                }
            }
        }

        if let Some(cfg_path) = config_file {
            insert_reloadable_file_dir(&mut ro, &mut fallbacks, cfg_path, &excluded_key_paths);
        }

        // Global TLS certs (+ keys ONLY in in-process mode; omitted in split-daemon mode per R2-PKG-3).
        if let Some(cert) = &config.server.tls.cert {
            insert_reloadable_file_dir(
                &mut ro,
                &mut fallbacks,
                Path::new(cert),
                &excluded_key_paths,
            );
        }
        if !is_split_daemon && let Some(key) = &config.server.tls.key {
            insert_reloadable_file_dir(
                &mut ro,
                &mut fallbacks,
                Path::new(key),
                &excluded_key_paths,
            );
        }
        if let Some(sock) = &config.server.tls.keyd_socket
            && !sock.starts_with("tcp://")
        {
            let path_str = sock.strip_prefix("unix:").unwrap_or(sock);
            insert_exact_path(&mut socks, Path::new(path_str));
        }

        // R6-SBX-1: Track effective ACME state dir so no HTTP docroot overlapping it is granted RO.
        let effective_acme_dir: Option<PathBuf> = if let Some(acme_dir) = acme_state_dir {
            insert_exact_dir(
                &mut rw,
                &mut warnings,
                acme_dir,
                ExplicitDirRole::AcmeState,
                &config.server.allow_docroots,
            );
            Some(acme_dir.to_path_buf())
        } else if config.server.tls.acme.is_some() {
            // SBX-3: Include the default ACME state directory when ACME is enabled without --acme-dir.
            insert_exact_dir(
                &mut rw,
                &mut warnings,
                Path::new(".miraserve-acme"),
                ExplicitDirRole::AcmeState,
                &config.server.allow_docroots,
            );
            Some(PathBuf::from(".miraserve-acme"))
        } else {
            None
        };
        let overlapping_docroots: BTreeSet<PathBuf> = effective_acme_dir
            .as_deref()
            .map(|acme| {
                find_docroot_acme_overlaps(config, acme)
                    .into_iter()
                    .map(|(label, path)| {
                        warnings.push(format!(
                            "refused Landlock read-only grant for {label} '{}' because it overlaps ACME state directory '{}'",
                            path.display(),
                            acme.display()
                        ));
                        path
                    })
                    .collect()
            })
            .unwrap_or_default();

        // The documented directory of Basic-auth users files: granted read-only whenever it exists,
        // so the first protected site a panel adds later loads on reload (no restart), even when
        // no site used it at start-up.
        if Path::new(USERS_FILE_DIR).is_dir() {
            ro.insert(PathBuf::from(USERS_FILE_DIR));
        }

        // The external ACME client's webroot: read-only, whole directory (tokens come and go).
        if let Some(webroot) = &config.server.acme_webroot
            && Path::new(webroot).is_absolute()
            && Path::new(webroot).is_dir()
        {
            ro.insert(PathBuf::from(webroot));
        }

        // Also allow server/site mTLS client CA bundles and bot-auth key files read-only.
        if let Some(ca) = &config.server.tls.client_ca {
            insert_reloadable_file_dir(&mut ro, &mut fallbacks, Path::new(ca), &excluded_key_paths);
        }

        // Site roots, per-site TLS certs, ai-publish release stores, FastCGI sockets, upstream mTLS
        for site in &config.sites {
            // A quarantined site serves nothing, so it asks for no access (its keys and other
            // protected files are still collected above and below, for the other sites' checks).
            if site.quarantine.is_some() {
                continue;
            }
            if let Some(root) = &site.root {
                let rp = Path::new(root);
                if !overlapping_docroots.contains(rp) {
                    insert_exact_dir(
                        &mut ro,
                        &mut warnings,
                        rp,
                        ExplicitDirRole::Docroot,
                        &config.server.allow_docroots,
                    );
                }
            }
            if let Some(tls) = &site.tls {
                for p in [&tls.cert, &tls.client_ca].into_iter().flatten() {
                    insert_reloadable_file_dir(
                        &mut ro,
                        &mut fallbacks,
                        Path::new(p),
                        &excluded_key_paths,
                    );
                }
                if !is_split_daemon && let Some(key) = &tls.key {
                    insert_reloadable_file_dir(
                        &mut ro,
                        &mut fallbacks,
                        Path::new(key),
                        &excluded_key_paths,
                    );
                }
            }
            if let Some(bot) = &site.bot_auth
                && let Some(keys_file) = &bot.agent_keys_file
            {
                insert_reloadable_file_dir(
                    &mut ro,
                    &mut fallbacks,
                    Path::new(keys_file),
                    &excluded_key_paths,
                );
            }
            if let Some(publish) = &site.ai_publish {
                insert_exact_dir(
                    &mut rw,
                    &mut warnings,
                    Path::new(&publish.storage),
                    ExplicitDirRole::PublishStorage,
                    &config.server.allow_docroots,
                );
                if let Some(sig) = &publish.require_signature {
                    insert_reloadable_file_dir(
                        &mut ro,
                        &mut fallbacks,
                        Path::new(&sig.public_key_path),
                        &excluded_key_paths,
                    );
                }
                if let Some(pk) = &publish.jwt_public_key
                    && let Some(path) = pk.strip_prefix("ed25519:")
                {
                    insert_reloadable_file_dir(
                        &mut ro,
                        &mut fallbacks,
                        Path::new(path),
                        &excluded_key_paths,
                    );
                }
            }
            if let Some(error_pages) = &site.error_pages {
                for page_path in error_pages.pages.values() {
                    let p = Path::new(page_path);
                    // Codex Round-5 P1 #2: an error page the loader would refuse (symlink in ANY
                    // component, missing, non-regular) gets the built-in page instead, so it must
                    // never widen the policy; an accepted page is pinned by identity.
                    // On a tenant site (owner-dir) a page outside the account is discarded by
                    // the loader, so it must not ask for (or veto a reload over) a grant either.
                    let outside_owner = site.owner_dir.as_ref().is_some_and(|owner| {
                        let owner_real = std::fs::canonicalize(owner).ok();
                        let page_dir = p.parent().and_then(|d| std::fs::canonicalize(d).ok());
                        !matches!((owner_real, page_dir), (Some(o), Some(d)) if d.starts_with(&o))
                    });
                    if p.is_absolute() && !outside_owner {
                        insert_validated_tenant_file(
                            &mut ro,
                            &mut fallbacks,
                            &mut pinned_ro,
                            p,
                            &excluded_key_paths,
                        );
                    }
                }
            }
            // `basic-auth` users files are read at load and reload, like error pages: granted
            // read-only by identity, never through a link.
            for users_file in site
                .basic_auth
                .iter()
                .chain(site.routes.iter().filter_map(|r| r.basic_auth.as_ref()))
                .map(|auth| Path::new(&auth.users_file))
            {
                if !users_file.is_absolute() {
                    continue;
                }
                if users_file.exists() {
                    insert_validated_tenant_file(
                        &mut ro,
                        &mut fallbacks,
                        &mut pinned_ro,
                        users_file,
                        &excluded_key_paths,
                    );
                } else if let Some(parent) = users_file.parent()
                    && parent.is_dir()
                    && !is_forbidden_widened_parent(parent)
                    && !parent_covers_excluded_key(parent, excluded_key_paths.as_slice())
                {
                    // Not created yet: grant its directory now, so creating the file later
                    // needs no new sandbox coverage (a reload, not a restart).
                    ro.insert(parent.to_path_buf());
                }
            }
            for route in &site.routes {
                if let Some(r_root) = &route.root {
                    let rp = Path::new(r_root);
                    if !overlapping_docroots.contains(rp) {
                        insert_exact_dir(
                            &mut ro,
                            &mut warnings,
                            rp,
                            ExplicitDirRole::Docroot,
                            &config.server.allow_docroots,
                        );
                    }
                }
                match &route.handler {
                    RouteHandler::FastCgi(fcgi) => {
                        if let FastCgiTarget::Unix { path } = &fcgi.target {
                            insert_exact_path(&mut socks, Path::new(path));
                        }
                    }
                    RouteHandler::ReverseProxy(rp) => {
                        if let Some(utls) = &rp.upstream_tls {
                            for p in [&utls.ca_cert, &utls.client_cert, &utls.client_key]
                                .into_iter()
                                .flatten()
                            {
                                insert_reloadable_file_dir(
                                    &mut ro,
                                    &mut fallbacks,
                                    Path::new(p),
                                    &excluded_key_paths,
                                );
                            }
                        }
                    }
                    RouteHandler::WasmPlugin(wasm) => {
                        // Codex Round-5 P1 #3: tenant-owned module, same no-follow rule as the
                        // WASM loader (a refused module isolates only its route to 503).
                        insert_validated_tenant_file(
                            &mut ro,
                            &mut fallbacks,
                            &mut pinned_ro,
                            &make_abs_path(Path::new(&wasm.module_path)),
                            &excluded_key_paths,
                        );
                    }
                    RouteHandler::McpGateway(mcp) => {
                        if let Some(pk) = &mcp.jwt_public_key
                            && let Some(path) = pk.strip_prefix("ed25519:")
                        {
                            insert_reloadable_file_dir(
                                &mut ro,
                                &mut fallbacks,
                                Path::new(path),
                                &excluded_key_paths,
                            );
                        }
                    }
                    RouteHandler::TryFiles(_)
                    | RouteHandler::Static(_)
                    | RouteHandler::Redirect(_)
                    | RouteHandler::Respond(_) => {}
                }
            }
        }

        // Operator-granted directory trees (`sandbox { read-tree ...; socket-tree ... }`). They
        // exist so sites and FastCGI pools added by a later reload are already inside the
        // Landlock policy, which cannot be extended after startup. Config validation has
        // rejected trees that touch system, secret or MiraServe state directories; a tree that
        // fails that check here (a config built in code) is skipped with a warning.
        for (trees, set, kind, is_socket_tree) in [
            (
                &config.server.sandbox.read_trees,
                &mut ro,
                "read-tree",
                false,
            ),
            (
                &config.server.sandbox.socket_trees,
                &mut socks,
                "socket-tree",
                true,
            ),
        ] {
            for tree in trees {
                if let Some(reason) = miraserve_config::sandbox_tree_rejection(tree) {
                    warnings.push(format!("sandbox {kind} '{tree}' ignored: {reason}"));
                } else {
                    let tp = PathBuf::from(tree.trim_end_matches('/'));
                    tree_paths.insert(tp.clone());
                    if is_socket_tree {
                        socket_tree_paths.insert(tp.clone());
                    }
                    set.insert(tp);
                }
            }
        }

        // Paths granted RW do not need duplicate RO entries.
        for p in &rw {
            ro.remove(p);
        }
        let mut socket_shadows_other_class: BTreeSet<PathBuf> = BTreeSet::new();
        for p in &socks {
            let removed_readonly = ro.remove(p);
            let removed_writable = rw.remove(p);
            if removed_readonly || removed_writable {
                socket_shadows_other_class.insert(p.clone());
            }
        }
        // Keep one pin per granted read-only path (a path granted RW or as a socket needs none).
        let mut seen_pins: BTreeSet<(PathBuf, bool)> = BTreeSet::new();
        pinned_ro.retain(|pin| {
            ro.contains(&pin.path) && seen_pins.insert((pin.path.clone(), pin.is_dir))
        });

        let read_only_paths: Vec<PathBuf> = ro.into_iter().collect();
        let read_write_paths: Vec<PathBuf> = rw.into_iter().collect();
        let socket_paths: Vec<PathBuf> = socks.into_iter().collect();
        let mut grant_states = BTreeMap::new();
        for p in read_only_paths
            .iter()
            .chain(read_write_paths.iter())
            .chain(socket_paths.iter())
        {
            grant_states.insert(p.clone(), open_grant(p, tree_paths.contains(p)));
        }

        Self {
            tenant_only_paths: BTreeSet::new(),
            landlock: config.server.sandbox.landlock,
            seccomp: config.server.sandbox.seccomp,
            user: config.server.sandbox.user.clone(),
            group: config.server.sandbox.group.clone(),
            read_only_paths,
            read_write_paths,
            pinned_read_write_dirs: Vec::new(),
            pinned_read_only_paths: pinned_ro,
            socket_paths,
            exact_file_fallbacks: fallbacks.into_iter().collect(),
            warnings,
            grant_states,
            tree_paths,
            socket_tree_paths,
            socket_shadows_other_class,
        }
    }

    /// Returns every directory or file path that this Landlock policy grants WRITE access to
    /// (matching the write-bearing rule classes installed by `apply_landlock`: `read_write_paths`,
    /// `pinned_read_write_dirs`, and `socket_paths` which carry `AccessFs::WriteFile`), sorted and
    /// deduplicated.
    #[must_use]
    pub fn landlock_writable_paths(&self) -> Vec<PathBuf> {
        let mut paths: BTreeSet<PathBuf> = BTreeSet::new();
        for p in &self.read_write_paths {
            paths.insert(p.clone());
        }
        for pinned in &self.pinned_read_write_dirs {
            paths.insert(pinned.path.clone());
        }
        for p in &self.socket_paths {
            paths.insert(p.clone());
        }
        paths.into_iter().collect()
    }

    /// Computes the writable Landlock candidate grants for `miraserve check --writable-set` under
    /// the superset policy-report contract:
    ///
    /// - Fails closed on any unfinalized grant, orphan pin, policy rejection (forbidden tree or
    ///   publish-store target, swap during validation), or identity mismatch / unlink on a pinned
    ///   descriptor.
    /// - Existing pinned grants (`pinned_read_write_dirs`, existing `read_write_paths`, existing
    ///   `socket_paths`) are derived from the pinned descriptor on Linux (`/proc/self/fd/<fd>`)
    ///   and verified against the pinned `(st_dev, st_ino)` identity (snapshot at inspection time).
    /// - Every candidate writable grant (`read_write_paths` AND `socket_paths`, including absent
    ///   `socket-tree` directories, absent Unix sockets, and absent or unopenable tenant-only
    ///   directories) that does not exist or cannot be opened by the inspecting process is emitted
    ///   as [`WritableGrant::Missing`]. No candidate is ever dropped silently, and no permission
    ///   inference (`accessat`) is performed.
    ///
    /// # Errors
    /// Returns [`SandboxError::Landlock`] if any grant failed policy validation, is unfinalized,
    /// or has an orphan or mismatched/unlinked pin.
    #[allow(clippy::too_many_lines)]
    pub fn writable_policy_grants(&self) -> Result<Vec<WritableGrant>, SandboxError> {
        self.verify_pinned_writable_dirs()?;

        let pinned_rw_paths: BTreeSet<&Path> = self
            .pinned_read_write_dirs
            .iter()
            .map(|d| d.path.as_path())
            .collect();
        let tenant_pinned_paths: BTreeSet<&Path> = self
            .pinned_read_only_paths
            .iter()
            .map(|p| p.path.as_path())
            .collect();

        let mut unfinalized: Vec<String> = Vec::new();
        let mut policy_rejected: Vec<String> = Vec::new();
        let mut resource_failed: Vec<String> = Vec::new();
        for p in self
            .read_only_paths
            .iter()
            .chain(self.read_write_paths.iter())
            .chain(self.socket_paths.iter())
        {
            if pinned_rw_paths.contains(p.as_path()) || tenant_pinned_paths.contains(p.as_path()) {
                continue;
            }
            match self.grant_states.get(p) {
                None => unfinalized.push(sanitize_path_for_display(p)),
                Some(GrantState::Failed {
                    reason,
                    kind: GrantFailureKind::PolicyRejection,
                }) => {
                    policy_rejected.push(format!("'{}': {reason}", sanitize_path_for_display(p)));
                }
                Some(GrantState::Failed {
                    reason,
                    kind: GrantFailureKind::ResourceExhausted,
                }) => {
                    resource_failed.push(format!("'{}': {reason}", sanitize_path_for_display(p)));
                }
                Some(_) => {}
            }
        }
        if !resource_failed.is_empty() {
            return Err(SandboxError::Landlock(format!(
                "sandbox policy inspection hit OS resource limit: {}",
                resource_failed.join("; ")
            )));
        }
        if !unfinalized.is_empty() {
            return Err(SandboxError::Landlock(format!(
                "sandbox policy path(s) were added after construction without finalization: {}; call SandboxPolicy::finalize_grants() before inspecting the policy",
                unfinalized.join(", ")
            )));
        }
        let orphan_pins: Vec<String> = self
            .pinned_read_write_dirs
            .iter()
            .filter(|pin| {
                !self
                    .read_write_paths
                    .iter()
                    .any(|p| normalized_paths_equal(p, &pin.path))
            })
            .map(|pin| format!("{} (read-write)", sanitize_path_for_display(&pin.path)))
            .chain(
                self.pinned_read_only_paths
                    .iter()
                    .filter(|pin| !self.read_only_paths.iter().any(|p| p == &pin.path))
                    .map(|pin| format!("{} (read-only)", sanitize_path_for_display(&pin.path))),
            )
            .collect();
        if !orphan_pins.is_empty() {
            return Err(SandboxError::Landlock(format!(
                "pinned sandbox grant(s) no longer requested by the policy path lists: {}; call SandboxPolicy::finalize_grants() after editing the lists",
                orphan_pins.join(", ")
            )));
        }
        if !policy_rejected.is_empty() {
            return Err(SandboxError::Landlock(format!(
                "sandbox grant(s) failed validation: {}",
                policy_rejected.join("; ")
            )));
        }

        let mut grants = Vec::new();

        // 1. Pinned rotating-log / writable directory handles.
        for pinned in &self.pinned_read_write_dirs {
            #[cfg(target_os = "linux")]
            let path = derive_and_verify_pinned_path(
                &pinned.path,
                &*pinned.file,
                pinned.inode_identity(),
            )?;
            #[cfg(not(target_os = "linux"))]
            let path = pinned.path.clone();
            grants.push(WritableGrant::Installed(path));
        }

        // 2. Remaining `read_write_paths` not already covered by `pinned_read_write_dirs`.
        for p in &self.read_write_paths {
            if self
                .pinned_read_write_dirs
                .iter()
                .any(|pin| normalized_paths_equal(p, &pin.path))
            {
                continue;
            }
            match self.grant_states.get(p) {
                Some(GrantState::Installed {
                    #[cfg(unix)]
                    identity,
                    #[cfg(target_os = "linux")]
                    fd,
                    ..
                }) => {
                    #[cfg(target_os = "linux")]
                    let path = derive_and_verify_pinned_path(p, fd.as_ref(), *identity)?;
                    #[cfg(all(unix, not(target_os = "linux")))]
                    let (path, _) = verify_canonical_identity(p, *identity)?;
                    #[cfg(not(unix))]
                    let path = p.clone();
                    grants.push(WritableGrant::Installed(path));
                }
                Some(
                    GrantState::AbsentAtStartup
                    | GrantState::Failed {
                        kind: GrantFailureKind::OpenError,
                        ..
                    },
                ) => {
                    grants.push(WritableGrant::Missing(p.clone()));
                }
                Some(GrantState::Failed {
                    reason,
                    kind: GrantFailureKind::ResourceExhausted,
                }) => {
                    return Err(SandboxError::Landlock(format!(
                        "sandbox grant '{}' hit OS resource limit: {reason}",
                        sanitize_path_for_display(p)
                    )));
                }
                Some(GrantState::Failed {
                    reason,
                    kind: GrantFailureKind::PolicyRejection,
                }) => {
                    return Err(SandboxError::Landlock(format!(
                        "sandbox grant '{}' failed validation: {reason}",
                        sanitize_path_for_display(p)
                    )));
                }
                None => {
                    return Err(SandboxError::Landlock(format!(
                        "sandbox grant '{}' is unfinalized",
                        sanitize_path_for_display(p)
                    )));
                }
            }
        }

        // 3. `socket_paths` (including `socket-tree` directories and exact Unix socket paths):
        //    existing entries print the pinned object's name; absent or unopenable entries are
        //    emitted as `WritableGrant::Missing` so no candidate grant (including a directory
        //    startup itself creates before `finalize_grants()`) is ever omitted silently.
        for p in &self.socket_paths {
            match self.grant_states.get(p) {
                Some(GrantState::Installed {
                    #[cfg(unix)]
                    identity,
                    #[cfg(target_os = "linux")]
                    fd,
                    ..
                }) => {
                    #[cfg(target_os = "linux")]
                    let path = derive_and_verify_pinned_path(p, fd.as_ref(), *identity)?;
                    #[cfg(all(unix, not(target_os = "linux")))]
                    let (path, _) = verify_canonical_identity(p, *identity)?;
                    #[cfg(not(unix))]
                    let path = p.clone();
                    grants.push(WritableGrant::Installed(path));
                }
                Some(
                    GrantState::AbsentAtStartup
                    | GrantState::Failed {
                        kind: GrantFailureKind::OpenError,
                        ..
                    },
                ) => {
                    grants.push(WritableGrant::Missing(p.clone()));
                }
                Some(GrantState::Failed {
                    reason,
                    kind: GrantFailureKind::ResourceExhausted,
                }) => {
                    return Err(SandboxError::Landlock(format!(
                        "sandbox socket grant '{}' hit OS resource limit: {reason}",
                        sanitize_path_for_display(p)
                    )));
                }
                Some(GrantState::Failed {
                    reason,
                    kind: GrantFailureKind::PolicyRejection,
                }) => {
                    return Err(SandboxError::Landlock(format!(
                        "sandbox socket grant '{}' failed validation: {reason}",
                        sanitize_path_for_display(p)
                    )));
                }
                None => {
                    return Err(SandboxError::Landlock(format!(
                        "sandbox socket grant '{}' is unfinalized",
                        sanitize_path_for_display(p)
                    )));
                }
            }
        }

        Ok(grants)
    }

    /// Finalizes the grant descriptors before the policy is shared with worker threads
    /// (Codex Round-9/10). Must be called after any direct edit of [`Self::read_only_paths`],
    /// [`Self::read_write_paths`] or [`Self::socket_paths`] and after startup has created the
    /// configured writable directories.
    ///
    /// - A grant whose descriptor was already opened and validated keeps that exact handle, so a
    ///   path component changing afterwards can never redirect the worker's rule.
    /// - A grant that was absent (or failed) is opened now; a `read-tree`/`socket-tree` that
    ///   first appears here passes the same forbidden-tree check on the opened object.
    /// - Only a genuinely absent entry (`ENOENT`) may remain absent; every other open, inspect or
    ///   validation failure is returned instead of silently omitting the grant.
    /// - Pinned rotating-log and tenant-file handles are reconciled with the public lists: a pin
    ///   whose path is no longer requested with its access class is dropped (Codex Round-11 P2).
    ///
    /// # Errors
    /// Returns [`SandboxError::Landlock`] listing every grant that could not be opened or whose
    /// opened object failed validation.
    pub fn finalize_grants(&mut self) -> Result<(), SandboxError> {
        // Codex Round-11 P2: the public path lists are the source of truth for access class.
        // A rotating-log pin whose directory is no longer requested read-write, or a tenant pin
        // no longer requested read-only, is dropped so installation can never grant its
        // original (wider) permission.
        let writable_list = &self.read_write_paths;
        self.pinned_read_write_dirs.retain(|pin| {
            writable_list
                .iter()
                .any(|p| normalized_paths_equal(p, &pin.path))
        });
        let readonly_list = &self.read_only_paths;
        self.pinned_read_only_paths
            .retain(|pin| readonly_list.iter().any(|p| p == &pin.path));

        let wanted: BTreeSet<PathBuf> = self
            .read_only_paths
            .iter()
            .chain(self.read_write_paths.iter())
            .chain(self.socket_paths.iter())
            .cloned()
            .collect();
        self.grant_states.retain(|p, _| wanted.contains(p));
        let mut dropped_tenant_grants: Vec<PathBuf> = Vec::new();
        for p in &wanted {
            let previous = self.grant_states.get(p);
            let keep = matches!(previous, Some(GrantState::Installed { .. }));
            if !keep {
                let was_absent = matches!(previous, Some(GrantState::AbsentAtStartup));
                #[cfg(target_os = "linux")]
                let mut state = match self
                    .pinned_read_write_dirs
                    .iter()
                    .find(|pin| normalized_paths_equal(p, &pin.path))
                {
                    Some(pin) if self.socket_paths.iter().any(|s| s == p) => {
                        grant_state_from_pinned_dir(pin)
                    }
                    _ => open_grant(p, self.tree_paths.contains(p)),
                };
                #[cfg(not(target_os = "linux"))]
                let mut state = open_grant(p, self.tree_paths.contains(p));
                // A grant only tenant sites need that did not exist when the policy was built and
                // cannot be opened now is treated as still absent: that tenant's site fails on
                // its own instead of the whole start. Anything the server or another site needs
                // still fails the start.
                if was_absent
                    && self.tenant_only_paths.contains(p)
                    && matches!(state, GrantState::Failed { .. })
                {
                    tracing::warn!(
                        path = %p.display(),
                        "read-only grant appeared but cannot be opened; left out of the sandbox (what needs it answers 503)"
                    );
                    state = GrantState::AbsentAtStartup;
                    dropped_tenant_grants.push(p.clone());
                }
                self.grant_states.insert(p.clone(), state);
            }
        }
        // An absent writable or socket grant cannot be installed at all; a tenant-only one that
        // failed late is left out entirely (that tenant's site fails on its own).
        for p in &dropped_tenant_grants {
            self.read_write_paths.retain(|x| x != p);
            self.socket_paths.retain(|x| x != p);
            if !self.read_only_paths.contains(p) {
                self.grant_states.remove(p);
            }
        }
        // Keep shadowed-class provenance aligned with `socket_paths`: if a spelling was removed
        // (and pruned from `grant_states`) or dropped above, re-adding it by hand later must treat
        // it as a plain exact socket entry rather than a shadowed grant.
        self.socket_shadows_other_class
            .retain(|p| self.socket_paths.iter().any(|s| s == p));
        let failures = self.grant_failures();
        if failures.is_empty() {
            Ok(())
        } else {
            Err(SandboxError::Landlock(format!(
                "cannot finalize sandbox grants: {}",
                failures.join("; ")
            )))
        }
    }

    /// Paths present in the public path lists that have no finalized grant state, i.e. entries
    /// appended after construction without calling [`Self::finalize_grants`] (Codex Round-10 P2).
    #[must_use]
    pub fn unfinalized_grant_paths(&self) -> Vec<PathBuf> {
        self.read_only_paths
            .iter()
            .chain(self.read_write_paths.iter())
            .chain(self.socket_paths.iter())
            .filter(|p| !self.grant_states.contains_key(p.as_path()))
            .cloned()
            .collect()
    }

    /// `(st_dev, st_ino)` of the finalized descriptor/object retained for `path`, if installed.
    #[cfg(unix)]
    #[must_use]
    pub fn granted_identity(&self, path: &Path) -> Option<(u64, u64)> {
        match self.grant_states.get(path) {
            Some(GrantState::Installed { identity, .. }) => Some(*identity),
            _ => None,
        }
    }

    /// The paths whose grant failed (the same entries as [`Self::grant_failures`]), for
    /// attributing a failure to whoever owns the path without parsing messages.
    #[must_use]
    pub fn grant_failure_paths(&self) -> Vec<PathBuf> {
        self.grant_states
            .iter()
            .filter(|(_, st)| matches!(st, GrantState::Failed { .. }))
            .map(|(p, _)| p.clone())
            .collect()
    }

    /// Grants that could not be opened, inspected or validated (e.g. a `read-tree` that is a
    /// regular file or resolves into a forbidden directory), as `'path': reason` strings. A policy
    /// with any entry here is refused by startup and must also be refused by reload
    /// (Codex Round-11 P2).
    #[must_use]
    pub fn grant_failures(&self) -> Vec<String> {
        self.grant_states
            .iter()
            .filter_map(|(p, st)| match st {
                GrantState::Failed { reason, .. } => Some(format!("'{}': {reason}", p.display())),
                _ => None,
            })
            .collect()
    }

    /// Returns only the grant failures caused by security/policy rejections (e.g. a forbidden
    /// `read-tree`/`socket-tree` target or swap during validation), excluding OS open/stat
    /// failures (`EACCES`, `ELOOP`, `ENOTDIR`) so `check --writable-set` can fail closed on
    /// policy rejections while reporting unopenable candidates as `writable-missing`.
    #[must_use]
    pub fn policy_rejection_failures(&self) -> Vec<String> {
        self.grant_states
            .iter()
            .filter_map(|(p, st)| match st {
                GrantState::Failed {
                    reason,
                    kind: GrantFailureKind::PolicyRejection,
                } => Some(format!("'{}': {reason}", sanitize_path_for_display(p))),
                _ => None,
            })
            .collect()
    }

    /// Returns grant failures caused by OS descriptor or memory exhaustion (`EMFILE`, `ENFILE`,
    /// `ENOMEM`). Used exclusively by `check --writable-set` so resource pressure always fails
    /// inspection instead of turning into a tenant quarantine or omission.
    #[must_use]
    pub fn resource_failure_grants(&self) -> Vec<String> {
        self.grant_states
            .iter()
            .filter_map(|(p, st)| match st {
                GrantState::Failed {
                    reason,
                    kind: GrantFailureKind::ResourceExhausted,
                } => Some(format!("'{}': {reason}", sanitize_path_for_display(p))),
                _ => None,
            })
            .collect()
    }

    /// Grants read-only access to the containing directory of a reloadable file (e.g. KDL config)
    /// without ever widening to a broad shared directory (`R2-SBX-2`, `R3-SBX-3`).
    pub fn allow_reloadable_file(&mut self, path: &Path) {
        let mut set: BTreeSet<PathBuf> = self.read_only_paths.iter().cloned().collect();
        let mut fb: BTreeSet<PathBuf> = self.exact_file_fallbacks.iter().cloned().collect();
        insert_reloadable_file_dir(&mut set, &mut fb, path, &[]);
        self.read_only_paths = set.into_iter().collect();
        self.exact_file_fallbacks = fb.into_iter().collect();
        for p in &self.read_only_paths {
            if !self.grant_states.contains_key(p) {
                let state = open_grant(p, self.tree_paths.contains(p));
                self.grant_states.insert(p.clone(), state);
            }
        }
    }

    /// Grants read-write access to the validated canonical parent directory of a rotating log file
    /// (`--log-file` or `--access-log` when `--log-max-bytes > 0`) so `rename()` + reopen succeed
    /// under Landlock (Codex G7), while refusing broad/system/secret directories, symlinked
    /// directories escaping into excluded trees, custom private-key/secret directories, and any
    /// directory overlapping configured HTTP document roots.
    ///
    /// # Errors
    /// Returns a descriptive reason if the log parent directory cannot be safely granted RW access.
    pub fn allow_log_rotation_dir(
        &mut self,
        log_path: &Path,
        config: &Config,
    ) -> Result<(), String> {
        self.allow_log_rotation_dir_with_context(log_path, config, None, None, &[])
    }

    /// Context-aware variant of [`Self::allow_log_rotation_dir`] that also protects the config
    /// file directory, effective ACME state directory, and CLI-supplied secret files
    /// (`--keyd-auth-secret-file`).
    ///
    /// # Errors
    /// Returns a descriptive reason if the log parent directory resolves into a forbidden system
    /// directory, any configured secret/key/state directory, or any served document root.
    pub fn allow_log_rotation_dir_with_context(
        &mut self,
        log_path: &Path,
        config: &Config,
        config_path: Option<&Path>,
        effective_acme_dir: Option<&Path>,
        extra_secret_files: &[PathBuf],
    ) -> Result<(), String> {
        self.bind_log_rotation_dir(
            log_path,
            config,
            config_path,
            effective_acme_dir,
            extra_secret_files,
        )
        .map(|_| ())
    }

    /// Validates a rotating log destination exactly like
    /// [`Self::allow_log_rotation_dir_with_context`] and returns the canonical directory that was
    /// validated together with the pinned handle the writer and Landlock must use (when the
    /// directory exists), so callers never re-resolve the configured pathname (Codex Round-5 P1 #1).
    ///
    /// # Errors
    /// Returns a descriptive reason if the log parent directory resolves into a forbidden system
    /// directory, any configured secret/key/state directory, or any served document root.
    #[allow(clippy::too_many_lines)]
    pub fn bind_log_rotation_dir(
        &mut self,
        log_path: &Path,
        config: &Config,
        config_path: Option<&Path>,
        effective_acme_dir: Option<&Path>,
        extra_secret_files: &[PathBuf],
    ) -> Result<LogDirBinding, String> {
        if let Some(reason) = log_path_platform_rejection(log_path) {
            self.warnings.push(reason.clone());
            return Err(reason);
        }
        let abs_log = if log_path.is_absolute() {
            log_path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|err| format!("cannot resolve working directory for log path: {err}"))?
                .join(log_path)
        };
        let parent = abs_log
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| format!("log path '{}' has no parent directory", log_path.display()))?;
        let real_parent = normalize_overlap_path(parent);

        // Codex G7 (P1 & Round-4 P2 Windows): Validate BOTH the configured spelling AND the
        // canonical real destination against the platform-appropriate forbidden system/secret/state
        // deny list so a symlinked log directory cannot grant RW access to an excluded tree (e.g.
        // `/etc`, `/etc/miraserve/keys` on Unix; drive roots / `C:\Windows` on Windows), without
        // blocking ordinary drive-qualified Windows paths containing backslashes.
        for (label, candidate) in [
            ("log rotation directory", parent),
            ("resolved log rotation directory", real_parent.as_path()),
        ] {
            if let Some(reason) = platform_log_dir_rejection(candidate) {
                let msg = format!(
                    "{label} '{}' not granted RW under Landlock: {reason}",
                    candidate.display()
                );
                self.warnings.push(msg.clone());
                return Err(msg);
            }
        }

        // Protect all sensitive/secret/state/trust-anchor paths — separating:
        // 1. `protected_trees` (whole directory trees such as `/etc/miraserve/keys`, ACME state,
        //    and `ai-publish` storage): bidirectional overlap is refused because writing anywhere
        //    inside or above the tree contaminates protected state.
        // 2. `protected_file_dirs` (containing directories of specific config/secret/trust/key/
        //    module files): refused whenever `file_dir` lies at or beneath `real_parent` (meaning
        //    RW on `real_parent/**` would grant write/replace access to that file).
        //    Codex Round-4 P2 #1: Push BOTH the configured entry's parent directory (without
        //    dereferencing a symlink at the leaf filename) AND the resolved target's parent
        //    directory, so an outward-pointing trust-file symlink inside the log directory cannot
        //    be unlinked or swapped by the worker!
        //    A dedicated sibling/child `logs/` subdirectory next to a regular file (e.g.
        //    `/opt/app/logs` beside `/opt/app/server.pem`) remains allowed.
        let push_protected_file_dir =
            |out: &mut Vec<(&'static str, PathBuf)>, label: &'static str, file_path: &Path| {
                let abs = make_abs_path(file_path);
                let configured_parent = abs
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .map(normalize_overlap_path);
                if let Some(ref cfg_parent) = configured_parent {
                    out.push((label, cfg_parent.clone()));
                }
                let norm = normalize_overlap_path(&abs);
                if let Some(target_parent) = norm.parent().filter(|p| !p.as_os_str().is_empty())
                    && configured_parent
                        .as_deref()
                        .is_none_or(|cp| !normalized_paths_equal(cp, target_parent))
                {
                    out.push((label, target_parent.to_path_buf()));
                }
            };
        let mut protected_trees: Vec<(&'static str, PathBuf)> = Vec::new();
        #[cfg(unix)]
        protected_trees.push((
            "private-key vault",
            normalize_overlap_path(Path::new("/etc/miraserve/keys")),
        ));
        let mut protected_file_dirs: Vec<(&'static str, PathBuf)> = Vec::new();
        if let Some(cfg_p) = config_path {
            push_protected_file_dir(&mut protected_file_dirs, "config directory", cfg_p);
        }
        if let Some(acme_p) = effective_acme_dir {
            protected_trees.push(("ACME state directory", normalize_overlap_path(acme_p)));
        }
        if let Some(cert) = &config.server.tls.cert {
            push_protected_file_dir(
                &mut protected_file_dirs,
                "server.tls.cert directory",
                Path::new(cert),
            );
        }
        if let Some(key) = &config.server.tls.key {
            push_protected_file_dir(
                &mut protected_file_dirs,
                "server.tls.key directory",
                Path::new(key),
            );
        }
        if let Some(ca) = &config.server.tls.client_ca {
            push_protected_file_dir(
                &mut protected_file_dirs,
                "server.tls.client-ca trust directory",
                Path::new(ca),
            );
        }
        if let Some(sock) = &config.server.tls.keyd_socket
            && !sock.starts_with("tcp://")
        {
            let sock_str = sock.strip_prefix("unix:").unwrap_or(sock);
            push_protected_file_dir(
                &mut protected_file_dirs,
                "server.tls.keyd-socket directory",
                Path::new(sock_str),
            );
        }
        for site in &config.sites {
            // A quarantined site's references are not used, so they cannot veto log rotation.
            if site.quarantine.is_some() {
                continue;
            }
            if let Some(tls) = &site.tls {
                if let Some(cert) = &tls.cert {
                    push_protected_file_dir(
                        &mut protected_file_dirs,
                        "site.tls.cert directory",
                        Path::new(cert),
                    );
                }
                if let Some(key) = &tls.key {
                    push_protected_file_dir(
                        &mut protected_file_dirs,
                        "site.tls.key directory",
                        Path::new(key),
                    );
                }
                if let Some(ca) = &tls.client_ca {
                    push_protected_file_dir(
                        &mut protected_file_dirs,
                        "site.tls.client-ca trust directory",
                        Path::new(ca),
                    );
                }
            }
            if let Some(bot) = &site.bot_auth
                && let Some(keys_file) = &bot.agent_keys_file
            {
                push_protected_file_dir(
                    &mut protected_file_dirs,
                    "bot-auth agent-keys directory",
                    Path::new(keys_file),
                );
            }
            if let Some(publish) = &site.ai_publish {
                protected_trees.push((
                    "ai-publish storage directory",
                    normalize_overlap_path(Path::new(&publish.storage)),
                ));
                if let Some(sig) = &publish.require_signature {
                    push_protected_file_dir(
                        &mut protected_file_dirs,
                        "ai-publish require-signature public-key directory",
                        Path::new(&sig.public_key_path),
                    );
                }
                if let Some(pk) = &publish.jwt_public_key
                    && let Some(path) = pk.strip_prefix("ed25519:")
                {
                    push_protected_file_dir(
                        &mut protected_file_dirs,
                        "ai-publish jwt-public-key directory",
                        Path::new(path),
                    );
                }
            }
            // Codex Round-4 P1 #1: Apply the tenant-file fallback policy consistently to custom
            // error pages! If a tenant's absolute error page is a symlink, FIFO, or missing file
            // that `read_no_symlink_file` would reject and fall back to the built-in page, it MUST
            // NOT contribute a resolved symlink target to the global trust-file list and DoS
            // startup or reload for healthy sibling sites.
            if let Some(error_pages) = &site.error_pages {
                for page_path in error_pages.pages.values() {
                    let p = Path::new(page_path);
                    if p.is_absolute()
                        && let Some(valid) = validate_tenant_file(p)
                    {
                        protected_file_dirs
                            .push(("site error-pages directory", valid.canonical_parent));
                    }
                }
            }
            for users_file in site
                .basic_auth
                .iter()
                .chain(site.routes.iter().filter_map(|r| r.basic_auth.as_ref()))
                .map(|auth| Path::new(&auth.users_file))
            {
                if users_file.is_absolute()
                    && let Some(valid) = validate_tenant_file(users_file)
                {
                    protected_file_dirs.push((
                        "site basic-auth users file directory",
                        valid.canonical_parent,
                    ));
                }
            }
            for route in &site.routes {
                match &route.handler {
                    RouteHandler::ReverseProxy(rp) => {
                        if let Some(utls) = &rp.upstream_tls {
                            for (label, p_opt) in [
                                ("upstream-tls ca-cert directory", &utls.ca_cert),
                                ("upstream-tls client-cert directory", &utls.client_cert),
                                ("upstream-tls client-key directory", &utls.client_key),
                            ] {
                                if let Some(p) = p_opt {
                                    push_protected_file_dir(
                                        &mut protected_file_dirs,
                                        label,
                                        Path::new(p),
                                    );
                                }
                            }
                        }
                    }
                    // Codex Round-5 P1 #3: a tenant-owned module is protected only when the WASM
                    // loader would accept it; a refused module (symlink in any component, missing,
                    // non-regular) is isolated to its route's 503 instead of blocking every site.
                    RouteHandler::WasmPlugin(wasm) => {
                        if let Some(valid) =
                            validate_tenant_file(&make_abs_path(Path::new(&wasm.module_path)))
                        {
                            protected_file_dirs
                                .push(("wasm-plugin module directory", valid.canonical_parent));
                        }
                    }
                    _ => {}
                }
            }
        }
        for secret in extra_secret_files {
            push_protected_file_dir(
                &mut protected_file_dirs,
                "keyd auth secret directory",
                secret,
            );
        }

        for (label, protected) in &protected_trees {
            if normalized_paths_overlap(&real_parent, protected) {
                let msg = format!(
                    "resolved log rotation directory '{}' overlaps {label} '{}' and cannot be granted RW under Landlock",
                    real_parent.display(),
                    protected.display()
                );
                self.warnings.push(msg.clone());
                return Err(msg);
            }
        }
        for (label, file_dir) in &protected_file_dirs {
            if normalized_path_starts_with(file_dir, &real_parent) {
                let msg = format!(
                    "resolved log rotation directory '{}' covers {label} '{}' and cannot be granted RW under Landlock",
                    real_parent.display(),
                    file_dir.display()
                );
                self.warnings.push(msg.clone());
                return Err(msg);
            }
        }

        for site in &config.sites {
            let roots = site
                .root
                .iter()
                .chain(site.routes.iter().filter_map(|r| r.root.as_ref()));
            for root_str in roots {
                let root_path = Path::new(root_str);
                let real_root = normalize_overlap_path(root_path);
                if normalized_paths_overlap(parent, root_path)
                    || normalized_paths_overlap(&real_parent, &real_root)
                {
                    let msg = format!(
                        "log rotation directory '{}' (resolved '{}') overlaps document root '{}' and cannot be granted RW under Landlock",
                        parent.display(),
                        real_parent.display(),
                        root_str
                    );
                    self.warnings.push(msg.clone());
                    return Err(msg);
                }
            }
        }

        // Bind the Landlock RW rule to the validated canonical directory and pin its directory
        // descriptor immediately if it already exists on disk. Look for an existing pin BEFORE
        // `is_dir()` so a second bind of the same directory reuses and verifies the first pin and
        // never falls back to a by-name open while a pin is retained (Codex G7 P1).
        let pinned = if let Some(existing) = self
            .pinned_read_write_dirs
            .iter()
            .find(|d| normalized_paths_equal(&d.path, &real_parent))
            .cloned()
        {
            existing.verify_identity().map_err(|err| {
                let msg = err.to_string();
                self.warnings.push(msg.clone());
                msg
            })?;
            Some(existing)
        } else if real_parent.is_dir() {
            let fresh = PinnedWritableDir::open_validated(&real_parent).map_err(|err| {
                let msg = err.to_string();
                self.warnings.push(msg.clone());
                msg
            })?;
            self.pinned_read_write_dirs.push(fresh.clone());
            Some(fresh)
        } else {
            None
        };
        let mut rw: BTreeSet<PathBuf> = self.read_write_paths.iter().cloned().collect();
        rw.insert(real_parent.clone());
        self.read_write_paths = rw.into_iter().collect();
        #[cfg(target_os = "linux")]
        let rp_state = match pinned.as_ref() {
            Some(pin) if self.socket_paths.iter().any(|p| p == &real_parent) => {
                grant_state_from_pinned_dir(pin)
            }
            _ => open_grant(&real_parent, false),
        };
        #[cfg(not(target_os = "linux"))]
        let rp_state = open_grant(&real_parent, false);
        self.grant_states.insert(real_parent.clone(), rp_state);
        // Log binding adds the canonical RW path and replaces its grant state after initial class
        // precedence. If the same path key is in `socket_paths`, record the socket list's spelling
        // so the Linux installer emits the shadow WARN instead of skipping it: when `real_parent`
        // is a directory it keeps the 0.1.5 socket-class rule on the replacement descriptor
        // (followed by the pinned RW rule); when the log parent is a regular file (or other
        // non-directory) there is no directory pin and the socket rule is reduced to read access
        // (`AccessFs::ReadFile` only).
        for sock_path in &self.socket_paths {
            if sock_path == &real_parent {
                self.socket_shadows_other_class.insert(sock_path.clone());
            }
        }
        self.read_only_paths.retain(|p| {
            !normalized_paths_equal(p, &real_parent) && !normalized_paths_equal(p, parent)
        });
        self.pinned_read_only_paths.retain(|pin| {
            !normalized_paths_equal(&pin.path, &real_parent)
                && !normalized_paths_equal(&pin.path, parent)
        });
        Ok(LogDirBinding {
            real_parent,
            pinned,
        })
    }

    /// Returns a cloned handle to the pinned writable directory for `dir` (if already pinned).
    #[must_use]
    pub fn pinned_dir_for(&self, dir: &Path) -> Option<PinnedWritableDir> {
        let norm = normalize_overlap_path(dir);
        self.pinned_read_write_dirs
            .iter()
            .find(|d| normalized_paths_equal(&d.path, &norm))
            .cloned()
    }

    /// Pins an already-validated writable directory handle (e.g. immediately after creating a
    /// previously missing log directory at startup) so main and worker threads share one inode fd.
    ///
    /// # Errors
    /// Returns [`SandboxError::Landlock`] if the directory cannot be opened without following
    /// symlinks or is not a directory.
    pub fn pin_writable_dir(&mut self, dir: &Path) -> Result<(), SandboxError> {
        let canonical = normalize_overlap_path(dir);
        let pinned = PinnedWritableDir::open_validated(&canonical)?;
        self.pinned_read_write_dirs
            .retain(|d| d.path != pinned.path);
        self.pinned_read_write_dirs.push(pinned);
        Ok(())
    }

    /// Verifies that every pinned writable directory handle still matches the directory on disk
    /// (detecting any directory identity swap between policy construction and rule installation).
    ///
    /// # Errors
    /// Returns [`SandboxError::Landlock`] if any pinned directory changed identity or became a symlink.
    pub fn verify_pinned_writable_dirs(&self) -> Result<(), SandboxError> {
        for pinned in &self.pinned_read_write_dirs {
            pinned.verify_identity()?;
        }
        Ok(())
    }

    /// Returns any paths required by `next` (after a live `SIGHUP` reload) that are not covered
    /// by this startup Landlock policy (`R2-SBX-2`). On Linux, Landlock rules are immutable after
    /// thread startup, so newly introduced uncovered paths require a service restart.
    #[must_use]
    pub fn uncovered_paths_in(&self, next: &Self) -> Vec<PathBuf> {
        self.uncovered_grants_in(next)
            .into_iter()
            .map(|(_, path)| path)
            .collect()
    }

    /// [`Self::uncovered_paths_in`] with the access each uncovered path needs.
    #[must_use]
    pub fn uncovered_grants_in(&self, next: &Self) -> Vec<(GrantClass, PathBuf)> {
        let mut uncovered = Vec::new();
        // Codex Round-6 P1 #4: rules installed from a pinned identity cover a candidate only if
        // the candidate still IS that object; name comparison would accept a directory or file
        // replaced at the same name. Independently covering name-based grants still count.
        let pinned_names: BTreeSet<&Path> = self
            .pinned_read_only_paths
            .iter()
            .map(|pin| pin.path.as_path())
            .collect();
        let name_rules: Vec<PathBuf> = self
            .read_only_paths
            .iter()
            .filter(|p| !pinned_names.contains(p.as_path()))
            .cloned()
            .collect();
        for p in &next.read_only_paths {
            // The users-file directory pre-grant is optional: when the directory appears only
            // after start-up it is not a reason to refuse a reload (a site needing a users file
            // there is handled as that site's own missing grant).
            if p.as_path() == Path::new(USERS_FILE_DIR) {
                continue;
            }
            if !is_path_covered_by(p, &name_rules, &self.grant_states)
                && !is_path_covered_by(p, &self.read_write_paths, &self.grant_states)
                && !self
                    .pinned_read_only_paths
                    .iter()
                    .any(|pin| pin.covers_by_identity(p))
            {
                uncovered.push((GrantClass::Read, p.clone()));
            }
        }
        for p in &next.read_write_paths {
            if !is_path_covered_by(p, &self.read_write_paths, &self.grant_states) {
                uncovered.push((GrantClass::Write, p.clone()));
            }
        }
        for p in &next.socket_paths {
            if !is_path_covered_by(p, &self.socket_paths, &self.grant_states)
                && !is_path_covered_by(p, &self.read_write_paths, &self.grant_states)
            {
                uncovered.push((GrantClass::Socket, p.clone()));
            }
        }
        uncovered
    }

    /// Every grant this policy asks for, with its access.
    #[must_use]
    pub fn requested_grants(&self) -> BTreeSet<(GrantClass, PathBuf)> {
        self.read_only_paths
            .iter()
            .map(|p| (GrantClass::Read, p.clone()))
            .chain(
                self.read_write_paths
                    .iter()
                    .map(|p| (GrantClass::Write, p.clone())),
            )
            .chain(
                self.socket_paths
                    .iter()
                    .map(|p| (GrantClass::Socket, p.clone())),
            )
            .collect()
    }
}

#[cfg(unix)]
fn current_path_identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata(path).ok().map(|md| (md.dev(), md.ino()))
}

/// Formats `path` for diagnostics, escaping any ASCII/Unicode control characters so raw control
/// bytes (newlines, BEL, ESC, etc.) never reach stderr or warnings, while keeping ordinary
/// printable paths byte-identical to `path.display()`.
fn sanitize_path_for_display(path: &Path) -> String {
    let s = path.to_string_lossy();
    if !s.chars().any(char::is_control) {
        return s.into_owned();
    }
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_control() {
            for esc in ch.escape_default() {
                out.push(esc);
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Derives the canonical path of an already-pinned Linux descriptor directly via
/// `/proc/self/fd/<fd>` (never performing an unverified second pathname lookup) and confirms that
/// the derived path is live, non-symlink, and matches the pinned `(st_dev, st_ino)` identity.
/// This is a point-in-time snapshot; a rename after the call returns is outside the contract.
#[cfg(target_os = "linux")]
fn derive_and_verify_pinned_path(
    raw_path: &Path,
    fd: &impl std::os::fd::AsRawFd,
    expected_identity: (u64, u64),
) -> Result<PathBuf, SandboxError> {
    use std::os::unix::fs::MetadataExt as _;

    let fd_path = PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()));
    let proc_target = std::fs::read_link(&fd_path).map_err(|err| {
        SandboxError::Landlock(format!(
            "cannot derive canonical path of pinned grant '{}' from '{}': {err}",
            sanitize_path_for_display(raw_path),
            fd_path.display()
        ))
    })?;
    let meta = std::fs::symlink_metadata(&proc_target).map_err(|err| {
        SandboxError::Landlock(format!(
            "pinned grant '{}' resolved to '{}', which is no longer reachable: {err}",
            sanitize_path_for_display(raw_path),
            sanitize_path_for_display(&proc_target)
        ))
    })?;
    if meta.file_type().is_symlink() {
        return Err(SandboxError::Landlock(format!(
            "pinned grant '{}' resolved to symbolic link '{}'",
            sanitize_path_for_display(raw_path),
            sanitize_path_for_display(&proc_target)
        )));
    }
    let current_identity = (meta.dev(), meta.ino());
    if current_identity != expected_identity {
        return Err(SandboxError::Landlock(format!(
            "pinned grant '{}' changed identity at '{}' (pinned dev={}, ino={} vs current dev={}, ino={})",
            sanitize_path_for_display(raw_path),
            sanitize_path_for_display(&proc_target),
            expected_identity.0,
            expected_identity.1,
            current_identity.0,
            current_identity.1
        )));
    }
    Ok(proc_target)
}

/// Canonicalizes `raw_path` on non-Linux Unix and verifies its `(st_dev, st_ino)` matches the
/// identity pinned during policy construction, failing on any mismatch.
#[cfg(all(unix, not(target_os = "linux")))]
fn verify_canonical_identity(
    raw_path: &Path,
    expected_identity: (u64, u64),
) -> Result<(PathBuf, bool), SandboxError> {
    use std::os::unix::fs::MetadataExt as _;

    let canon = std::fs::canonicalize(raw_path).map_err(|err| {
        SandboxError::Landlock(format!(
            "cannot canonicalize pinned grant '{}': {err}",
            sanitize_path_for_display(raw_path)
        ))
    })?;
    let meta = std::fs::symlink_metadata(&canon).map_err(|err| {
        SandboxError::Landlock(format!(
            "cannot inspect canonical path '{}' for pinned grant '{}': {err}",
            sanitize_path_for_display(&canon),
            sanitize_path_for_display(raw_path)
        ))
    })?;
    if meta.file_type().is_symlink() {
        return Err(SandboxError::Landlock(format!(
            "canonical path '{}' for pinned grant '{}' is a symbolic link",
            sanitize_path_for_display(&canon),
            sanitize_path_for_display(raw_path)
        )));
    }
    let current_identity = (meta.dev(), meta.ino());
    if current_identity != expected_identity {
        return Err(SandboxError::Landlock(format!(
            "pinned grant '{}' changed identity at '{}' (pinned dev={}, ino={} vs current dev={}, ino={})",
            sanitize_path_for_display(raw_path),
            sanitize_path_for_display(&canon),
            expected_identity.0,
            expected_identity.1,
            current_identity.0,
            current_identity.1
        )));
    }
    Ok((canon, meta.is_dir()))
}

/// Inspection-only validation of explicit writable directories (`--acme-dir` and active sites'
/// `ai-publish.storage`) for `miraserve check --writable-set`.
///
/// Catches documented hard rejections that `insert_exact_dir` would otherwise drop with only a
/// `W017` warning (such as `--acme-dir /etc` or a cleanly spelled publish-store symlink pointing
/// to `/etc`), checks non-tenant publish stores are not existing non-directories, and propagates
/// OS resource exhaustion (`EMFILE`, `ENFILE`, `ENOMEM`) as an inspection error.
///
/// Unreachable from `miraserve run`.
///
/// # Errors
/// Returns [`SandboxError::Landlock`] on a forbidden explicit directory, non-directory non-tenant
/// publish store, or OS resource exhaustion.
pub fn validate_writable_candidates_for_inspection(
    config: &Config,
    effective_acme_dir: Option<&Path>,
) -> Result<(), SandboxError> {
    if let Some(acme_dir) = effective_acme_dir {
        if acme_dir.as_os_str().is_empty()
            || is_forbidden_explicit_dir(
                acme_dir,
                ExplicitDirRole::AcmeState,
                &config.server.allow_docroots,
            )
        {
            return Err(SandboxError::Landlock(format!(
                "refused unsafe configured --acme-dir '{}'; move state out of system directories and use an absolute path",
                sanitize_path_for_display(acme_dir)
            )));
        }
        match std::fs::canonicalize(acme_dir) {
            Ok(canon)
                if is_forbidden_explicit_dir(
                    &canon,
                    ExplicitDirRole::AcmeState,
                    &config.server.allow_docroots,
                ) =>
            {
                return Err(SandboxError::Landlock(format!(
                    "refused configured --acme-dir '{}' because its canonical target '{}' points to a forbidden system directory",
                    sanitize_path_for_display(acme_dir),
                    sanitize_path_for_display(&canon)
                )));
            }
            Err(err) if is_resource_io_error(&err) => {
                return Err(SandboxError::Landlock(format!(
                    "resource failure inspecting --acme-dir '{}': {err}",
                    sanitize_path_for_display(acme_dir)
                )));
            }
            _ => {}
        }
    }

    for site in &config.sites {
        if site.quarantine.is_some() {
            continue;
        }
        let Some(publish) = &site.ai_publish else {
            continue;
        };
        let storage = Path::new(&publish.storage);
        if storage.as_os_str().is_empty()
            || is_forbidden_explicit_dir(
                storage,
                ExplicitDirRole::PublishStorage,
                &config.server.allow_docroots,
            )
        {
            return Err(SandboxError::Landlock(format!(
                "refused unsafe configured ai-publish.storage '{}'; move publish storage out of system directories and use an absolute path",
                sanitize_path_for_display(storage)
            )));
        }
        match std::fs::canonicalize(storage) {
            Ok(canon)
                if is_forbidden_explicit_dir(
                    &canon,
                    ExplicitDirRole::PublishStorage,
                    &config.server.allow_docroots,
                ) =>
            {
                return Err(SandboxError::Landlock(format!(
                    "refused configured ai-publish.storage '{}' because its canonical target '{}' points to a forbidden system directory",
                    sanitize_path_for_display(storage),
                    sanitize_path_for_display(&canon)
                )));
            }
            Err(err) if is_resource_io_error(&err) => {
                return Err(SandboxError::Landlock(format!(
                    "resource failure inspecting ai-publish.storage '{}': {err}",
                    sanitize_path_for_display(storage)
                )));
            }
            _ => {}
        }
        if site.owner_dir.is_none() {
            match std::fs::metadata(storage) {
                Ok(md) if !md.is_dir() => {
                    return Err(SandboxError::Landlock(format!(
                        "ai-publish.storage '{}' exists and is not a directory",
                        sanitize_path_for_display(storage)
                    )));
                }
                Err(err) if is_resource_io_error(&err) => {
                    return Err(SandboxError::Landlock(format!(
                        "resource failure inspecting ai-publish.storage '{}': {err}",
                        sanitize_path_for_display(storage)
                    )));
                }
                _ => {}
            }
        }
    }
    Ok(())
}

/// Inspection-only check for whether a quarantined site's `ai-publish.storage` is a valid
/// candidate writable path (i.e. not refused by `is_forbidden_explicit_dir`) without opening any
/// long-lived file descriptors.
///
/// Unreachable from `miraserve run`.
///
/// # Errors
/// Returns [`SandboxError::Landlock`] if canonicalization hits OS resource exhaustion (`EMFILE`,
/// `ENFILE`, `ENOMEM`).
pub fn is_quarantined_publish_storage_candidate(
    path: &Path,
    allow_docroots: &[String],
) -> Result<bool, SandboxError> {
    if path.as_os_str().is_empty()
        || is_forbidden_explicit_dir(path, ExplicitDirRole::PublishStorage, allow_docroots)
    {
        return Ok(false);
    }
    match std::fs::canonicalize(path) {
        Ok(canon)
            if is_forbidden_explicit_dir(
                &canon,
                ExplicitDirRole::PublishStorage,
                allow_docroots,
            ) =>
        {
            Ok(false)
        }
        Err(err) if is_resource_io_error(&err) => Err(SandboxError::Landlock(format!(
            "resource failure inspecting quarantined ai-publish.storage '{}': {err}",
            sanitize_path_for_display(path)
        ))),
        _ => Ok(true),
    }
}

/// Inspection-only check for whether a quarantined site's Unix FastCGI socket path is a valid
/// candidate writable socket grant (matching `insert_exact_path`).
///
/// Unreachable from `miraserve run`.
#[must_use]
pub fn is_quarantined_socket_candidate(path: &Path) -> bool {
    !path.as_os_str().is_empty() && !is_forbidden_file_or_socket_path(path)
}

/// Inspection-only check propagating OS resource exhaustion (`EMFILE`, `ENFILE`, `ENOMEM`) when
/// resolving paths consulted by docroot/overlap classification, without holding open descriptors.
///
/// Unreachable from `miraserve run`.
///
/// # Errors
/// Returns [`SandboxError::Landlock`] if any lookup hits `EMFILE`, `ENFILE`, or `ENOMEM`.
pub fn check_docroot_classification_resources(
    config: &Config,
    config_path: Option<&Path>,
    effective_acme_dir: Option<&Path>,
    log_file_paths: &[PathBuf],
    extra_secret_files: &[PathBuf],
) -> Result<(), SandboxError> {
    let check_path = |label: &str, path: &Path| -> Result<(), SandboxError> {
        if let Err(err) = std::fs::canonicalize(path)
            && is_resource_io_error(&err)
        {
            return Err(SandboxError::Landlock(format!(
                "resource failure inspecting {label} '{}': {err}",
                sanitize_path_for_display(path)
            )));
        }
        Ok(())
    };

    if let Some(cfg_path) = config_path {
        check_path("config path", cfg_path)?;
    }
    if let Some(acme) = effective_acme_dir {
        check_path("--acme-dir", acme)?;
    }
    for log_path in log_file_paths {
        check_path("log path", log_path)?;
        if let Some(parent) = log_path.parent().filter(|p| !p.as_os_str().is_empty()) {
            check_path("log directory", parent)?;
        }
    }
    for secret in extra_secret_files {
        check_path("secret file", secret)?;
    }
    for tree in config
        .server
        .sandbox
        .read_trees
        .iter()
        .chain(config.server.sandbox.socket_trees.iter())
    {
        check_path("sandbox tree", Path::new(tree))?;
    }
    for site in &config.sites {
        if let Some(owner) = &site.owner_dir {
            check_path("site owner-dir", Path::new(owner))?;
        }
        if let Some(root) = &site.root {
            check_path("site root", Path::new(root))?;
        }
        if let Some(publish) = &site.ai_publish {
            check_path("ai-publish.storage", Path::new(&publish.storage))?;
        }
        for route in &site.routes {
            if let Some(r_root) = &route.root {
                check_path("route root", Path::new(r_root))?;
            }
        }
    }
    Ok(())
}

/// Derives a Linux [`GrantState`] directly from a validated [`PinnedWritableDir`] via
/// `F_DUPFD_CLOEXEC` (minimum 0) and `fstat` on the duplicate (no path lookup).
#[cfg(target_os = "linux")]
fn grant_state_from_pinned_dir(pinned: &PinnedWritableDir) -> GrantState {
    use rustix::fs::{FileType, fstat};
    use rustix::io::{Errno, fcntl_dupfd_cloexec};

    let failed = |prefix: &str, err: Errno| GrantState::Failed {
        reason: format!("{prefix}: {}", std::io::Error::from(err)),
        kind: if matches!(err, Errno::MFILE | Errno::NFILE | Errno::NOMEM) {
            GrantFailureKind::ResourceExhausted
        } else {
            GrantFailureKind::OpenError
        },
    };
    let fd = match fcntl_dupfd_cloexec(&*pinned.file, 0) {
        Ok(fd) => fd,
        Err(err) => return failed("cannot duplicate pinned grant target", err),
    };
    let st = match fstat(&fd) {
        Ok(st) => st,
        Err(err) => return failed("cannot inspect grant target", err),
    };
    #[allow(clippy::useless_conversion)]
    let identity = (u64::from(st.st_dev), u64::from(st.st_ino));
    let file_type = FileType::from_raw_mode(st.st_mode);
    let is_dir = file_type == FileType::Directory;
    if !is_dir || identity != pinned.inode_identity() {
        return GrantState::Failed {
            reason: "pinned writable directory changed identity during descriptor duplication"
                .to_owned(),
            kind: GrantFailureKind::PolicyRejection,
        };
    }
    GrantState::Installed {
        identity,
        fd: std::sync::Arc::new(fd),
        is_dir,
        file_type,
    }
}

/// Opens (and, for operator trees, validates) one grant target, returning the state that both
/// reload coverage and Landlock installation will use (Codex Round-9/10/11).
///
/// - Only `ENOENT` (Linux) / `NotFound` is treated as a genuinely absent optional entry; every
///   other error becomes [`GrantState::Failed`] carrying the path's error.
/// - A `read-tree`/`socket-tree` is handled by [`open_validated_tree`]: the configured alias is
///   resolved to a candidate location, the tree policy is applied to that location, and the
///   descriptor that is retained and installed is opened at that location without following any
///   link, so the granted object is exactly the object at the validated location.
fn open_grant(path: &Path, is_tree: bool) -> GrantState {
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{CWD, FileType, Mode, OFlags, fstat, openat};
        use rustix::io::Errno;
        let fd = match openat(CWD, path, OFlags::PATH | OFlags::CLOEXEC, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return GrantState::AbsentAtStartup,
            Err(err) => {
                let kind = if matches!(err, Errno::MFILE | Errno::NFILE | Errno::NOMEM) {
                    GrantFailureKind::ResourceExhausted
                } else {
                    GrantFailureKind::OpenError
                };
                return GrantState::Failed {
                    reason: format!("cannot open grant target: {}", std::io::Error::from(err)),
                    kind,
                };
            }
        };
        let st = match fstat(&fd) {
            Ok(st) => st,
            Err(err) => {
                let kind = if matches!(err, Errno::MFILE | Errno::NFILE | Errno::NOMEM) {
                    GrantFailureKind::ResourceExhausted
                } else {
                    GrantFailureKind::OpenError
                };
                return GrantState::Failed {
                    reason: format!("cannot inspect grant target: {}", std::io::Error::from(err)),
                    kind,
                };
            }
        };
        #[allow(clippy::useless_conversion)]
        let identity = (u64::from(st.st_dev), u64::from(st.st_ino));
        let file_type = FileType::from_raw_mode(st.st_mode);
        let is_dir = file_type == FileType::Directory;
        if is_tree {
            return open_validated_tree(path, identity, is_dir, |p: &Path| {
                std::fs::canonicalize(p)
            });
        }
        GrantState::Installed {
            identity,
            fd: std::sync::Arc::new(fd),
            is_dir,
            file_type,
        }
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        use std::os::unix::fs::MetadataExt as _;
        match std::fs::metadata(path) {
            Ok(md) => {
                let identity = (md.dev(), md.ino());
                if is_tree {
                    return open_validated_tree(path, identity, md.is_dir(), |p: &Path| {
                        std::fs::canonicalize(p)
                    });
                }
                GrantState::Installed { identity }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => GrantState::AbsentAtStartup,
            Err(err) => {
                let kind = if is_resource_io_error(&err) {
                    GrantFailureKind::ResourceExhausted
                } else {
                    GrantFailureKind::OpenError
                };
                GrantState::Failed {
                    reason: format!("cannot inspect grant target: {err}"),
                    kind,
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = is_tree;
        match std::fs::metadata(path) {
            Ok(_) => GrantState::Installed {},
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => GrantState::AbsentAtStartup,
            Err(err) => {
                let kind = if is_resource_io_error(&err) {
                    GrantFailureKind::ResourceExhausted
                } else {
                    GrantFailureKind::OpenError
                };
                GrantState::Failed {
                    reason: format!("cannot inspect grant target: {err}"),
                    kind,
                }
            }
        }
    }
}

/// Validates and opens an operator `read-tree`/`socket-tree` (Codex Round-10/11 P1).
///
/// 1. `resolve` maps the configured alias to a candidate location (normally `canonicalize`).
/// 2. The tree policy ([`miraserve_config::sandbox_tree_rejection`]) is applied to that location.
/// 3. That exact location is opened component by component WITHOUT following any link
///    ([`pinned::open_dir_no_follow`]); the resulting descriptor is the one retained and installed.
/// 4. Its `(st_dev, st_ino)` must equal `first_identity` (what the configured alias named when it
///    was first opened); any difference means a component changed during validation and the grant
///    is refused.
///
/// No step re-resolves a mutable pathname after the policy check: the installed object is reached
/// only through the validated, link-free location.
#[cfg(unix)]
fn open_validated_tree(
    path: &Path,
    first_identity: (u64, u64),
    first_is_dir: bool,
    resolve: impl FnOnce(&Path) -> std::io::Result<PathBuf>,
) -> GrantState {
    let fail = |reason: String| GrantState::Failed {
        reason,
        kind: GrantFailureKind::PolicyRejection,
    };
    if !first_is_dir {
        return fail("sandbox tree is not a directory".to_owned());
    }
    let candidate = match resolve(path) {
        Ok(c) => c,
        Err(err) => {
            let kind = if is_resource_io_error(&err) {
                GrantFailureKind::ResourceExhausted
            } else {
                GrantFailureKind::PolicyRejection
            };
            return GrantState::Failed {
                reason: format!("cannot resolve sandbox tree location: {err}"),
                kind,
            };
        }
    };
    if let Some(reason) = miraserve_config::sandbox_tree_rejection(&candidate.to_string_lossy()) {
        return fail(format!(
            "sandbox tree resolves to '{}', which is not allowed: {reason}",
            candidate.display()
        ));
    }
    let (file, dev, ino) = match pinned::open_dir_no_follow(&candidate) {
        Ok(opened) => opened,
        Err(err) => {
            return fail(format!(
                "sandbox tree location '{}' changed or cannot be opened without following links: {err}",
                candidate.display()
            ));
        }
    };
    if (dev, ino) != first_identity {
        return fail(format!(
            "sandbox tree changed while it was being validated (validated location '{}' is a different directory)",
            candidate.display()
        ));
    }
    #[cfg(target_os = "linux")]
    {
        GrantState::Installed {
            identity: (dev, ino),
            fd: std::sync::Arc::new(std::os::fd::OwnedFd::from(file)),
            is_dir: true,
            file_type: rustix::fs::FileType::Directory,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        drop(file);
        GrantState::Installed {
            identity: (dev, ino),
        }
    }
}

/// Returns `true` iff `rule` existed at startup (so a kernel grant was installed) AND still
/// resolves to the exact same filesystem object on Unix.
fn rule_installed_and_unchanged(rule: &Path, grant_states: &BTreeMap<PathBuf, GrantState>) -> bool {
    match grant_states.get(rule) {
        #[cfg(unix)]
        Some(GrantState::Installed { identity, .. }) => {
            current_path_identity(rule) == Some(*identity)
        }
        #[cfg(not(unix))]
        Some(GrantState::Installed {}) => std::fs::metadata(rule).is_ok(),
        Some(GrantState::AbsentAtStartup | GrantState::Failed { .. }) | None => false,
    }
}

/// Whether `candidate` lies inside one of the `granted` trees whose startup grant still covers it.
///
/// Landlock rules attach to the REAL directory inode behind each granted path at startup:
/// 1. When `candidate` exists on disk, it MUST be covered by a rule that was actually installed at
///    startup (not `AbsentAtStartup`) and still resolves to the exact same Unix `(st_dev, st_ino)`
///    — so neither a replaced `read-tree` nor a missing `read-tree` created later can produce a
///    false successful reload (Codex Round-7 P2 #4, Round-8 P2 #4).
/// 2. When `candidate` does NOT exist on disk (e.g. an absent and unused `read-tree` on an
///    unchanged reload), an unchanged installed rule or matching absent rule still covers it so
///    absent unused rules do not spuriously force restarts.
fn is_path_covered_by(
    candidate: &Path,
    granted: &[PathBuf],
    grant_states: &BTreeMap<PathBuf, GrantState>,
) -> bool {
    let within = |c: &Path, rule: &Path| c == rule || c.starts_with(rule);
    match std::fs::canonicalize(candidate) {
        Ok(real) => granted.iter().any(|rule| {
            if !rule_installed_and_unchanged(rule, grant_states) {
                return false;
            }
            let real_rule = std::fs::canonicalize(rule).unwrap_or_else(|_| rule.clone());
            within(&real, &real_rule)
        }),
        Err(_) => granted.iter().any(|rule| {
            let ok = match grant_states.get(rule) {
                Some(GrantState::Installed { .. }) => {
                    rule_installed_and_unchanged(rule, grant_states)
                }
                Some(GrantState::AbsentAtStartup) | None => true,
                Some(GrantState::Failed { .. }) => false,
            };
            ok && within(candidate, rule)
        }),
    }
}

fn push_excluded_key(excluded: &mut Vec<PathBuf>, path: &Path) {
    if !path.as_os_str().is_empty() {
        excluded.push(path.to_path_buf());
        if let Ok(canon) = std::fs::canonicalize(path)
            && canon != path
        {
            excluded.push(canon);
        }
    }
}

fn parent_covers_excluded_key(parent: &Path, excluded_key_paths: &[PathBuf]) -> bool {
    excluded_key_paths
        .iter()
        .any(|excl| excl == parent || excl.starts_with(parent))
}

/// Grants the containing directory read-only so atomic rename replacements (certbot renewals,
/// config edits before SIGHUP) remain readable under Linux Landlock (`R2-SBX-2`, `R3-SBX-2`).
/// Also follows symlinks (e.g. certbot `live/<site>/fullchain.pem` -> `archive/<site>/...`)
/// and grants the canonical target's parent directory when safe.
/// Refuses to widen to broad shared directories (`R3-SBX-3`) or any ancestor of an excluded
/// private key (`R3-PKG-2`), recording any exact-file fallback in `fallbacks` (`R4-SBX-1`).
fn insert_reloadable_file_dir(
    set: &mut BTreeSet<PathBuf>,
    fallbacks: &mut BTreeSet<PathBuf>,
    path: &Path,
    excluded_key_paths: &[PathBuf],
) {
    insert_single_reloadable_target(set, fallbacks, path, excluded_key_paths);
    // R3-SBX-2: If `path` is a symlink (such as certbot's `live/<site>/fullchain.pem` ->
    // `../../archive/<site>/fullchain1.pem`), also cover the canonical target's directory.
    if let Ok(canon) = std::fs::canonicalize(path)
        && canon != path
    {
        insert_single_reloadable_target(set, fallbacks, &canon, excluded_key_paths);
    }
}

fn insert_single_reloadable_target(
    set: &mut BTreeSet<PathBuf>,
    fallbacks: &mut BTreeSet<PathBuf>,
    path: &Path,
    excluded_key_paths: &[PathBuf],
) {
    if path.as_os_str().is_empty() || is_forbidden_file_or_socket_path(path) {
        return;
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && !is_forbidden_widened_parent(parent)
        && !parent_covers_excluded_key(parent, excluded_key_paths)
    {
        set.insert(parent.to_path_buf());
    } else {
        set.insert(path.to_path_buf());
        fallbacks.insert(path.to_path_buf());
    }
}

/// Inserts an exact file or socket path (never widening to its parent directory)
/// and refuses granting broad access to `/` or kernel pseudo-filesystems.
fn insert_exact_path(set: &mut BTreeSet<PathBuf>, path: &Path) {
    if !path.as_os_str().is_empty() && !is_forbidden_file_or_socket_path(path) {
        set.insert(path.to_path_buf());
    }
}

/// Grants read access to a tenant-controlled file (absolute custom error page or WASM module)
/// ONLY when it passes the loaders' no-follow rule, and pins the grant to the validated identity
/// (Codex Round-5 P1 #2 & #3). A refused file contributes nothing, so a tenant symlink in any
/// component can neither widen the worker's read access nor force a restart on reload.
fn insert_validated_tenant_file(
    set: &mut BTreeSet<PathBuf>,
    fallbacks: &mut BTreeSet<PathBuf>,
    pinned: &mut Vec<PinnedReadOnlyPath>,
    file: &Path,
    excluded_key_paths: &[PathBuf],
) {
    if file.as_os_str().is_empty() || is_forbidden_file_or_socket_path(file) {
        return;
    }
    let Some(valid) = validate_tenant_file(file) else {
        return;
    };
    if let Some(parent) = file.parent()
        && !parent.as_os_str().is_empty()
        && !is_forbidden_widened_parent(parent)
        && !parent_covers_excluded_key(parent, excluded_key_paths)
    {
        set.insert(parent.to_path_buf());
        pinned.push(valid.into_parent_pin(parent));
    } else {
        set.insert(file.to_path_buf());
        fallbacks.insert(file.to_path_buf());
        pinned.push(valid.into_file_pin(file));
    }
}

/// Returns `true` if a file or Unix socket path itself is unsafe (empty, `/`, `..`, or kernel
/// pseudo-filesystems `/proc`, `/sys`, `/dev`, `/boot`). Dedicated config/cert paths under
/// `/etc/miraserve/...` or `/etc/letsencrypt/...` are permitted here; parent widening is guarded
/// separately by [`is_forbidden_widened_parent`].
fn is_forbidden_file_or_socket_path(path: &Path) -> bool {
    use std::path::Component;

    let mut has_root = false;
    let mut normals: Vec<&str> = Vec::new();
    for comp in path.components() {
        match comp {
            Component::RootDir | Component::Prefix(_) => has_root = true,
            Component::CurDir => {}
            Component::ParentDir => return true,
            Component::Normal(seg) => normals.push(seg.to_str().unwrap_or("")),
        }
    }
    if normals.is_empty() {
        return true;
    }
    if !has_root {
        return false;
    }
    let first = normals.first().copied().unwrap_or("");
    matches!(first, "proc" | "sys" | "dev" | "boot")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExplicitDirRole {
    Docroot,
    PublishStorage,
    AcmeState,
}

/// Inserts an explicitly configured directory path (docroot, release store, ACME state dir).
///
/// R4-SBX-2, R5-SBX-1 & Section 5: Rejects relative paths (except default `.miraserve-acme`),
/// canonicalizes existing symlinks before checking unified `miraserve_config::is_forbidden_dir_path`
/// boundaries, and blocks top-level directories, sensitive OS/MiraServe trees, and default-denied
/// `/var/lib`, `/var/log`, `/run` subtrees unless exempted via `server.allow-docroot`.
fn insert_exact_dir(
    set: &mut BTreeSet<PathBuf>,
    warnings: &mut Vec<String>,
    path: &Path,
    role: ExplicitDirRole,
    allow_docroots: &[String],
) {
    if path.as_os_str().is_empty() {
        return;
    }
    if is_forbidden_explicit_dir(path, role, allow_docroots) {
        warnings.push(format!(
            "Landlock policy refused unsafe configured directory '{}'; move site roots/state out of system directories and use an absolute path",
            path.display()
        ));
        return;
    }
    if let Ok(canon) = std::fs::canonicalize(path)
        && is_forbidden_explicit_dir(&canon, role, allow_docroots)
    {
        warnings.push(format!(
            "Landlock policy refused configured directory '{}' because its canonical target '{}' points to a forbidden system directory",
            path.display(),
            canon.display()
        ));
        return;
    }
    set.insert(path.to_path_buf());
}

/// Returns `true` if `path` is unsafe for `role` (`R4-SBX-2`, `R3-SBX-3`, `R5-SBX-1`, Section 5).
fn is_forbidden_explicit_dir(
    path: &Path,
    role: ExplicitDirRole,
    allow_docroots: &[String],
) -> bool {
    use std::path::Component;

    let mut has_root = false;
    let mut normals: Vec<&str> = Vec::new();
    for comp in path.components() {
        match comp {
            Component::RootDir | Component::Prefix(_) => has_root = true,
            Component::CurDir => {}
            Component::ParentDir => return true,
            Component::Normal(seg) => normals.push(seg.to_str().unwrap_or("")),
        }
    }

    if normals.is_empty() {
        return true;
    }

    let first = normals.first().copied().unwrap_or("");
    if !has_root {
        return !(role == ExplicitDirRole::AcmeState
            && normals.len() == 1
            && first == ".miraserve-acme");
    }

    match role {
        ExplicitDirRole::Docroot => {
            miraserve_config::is_forbidden_dir_path(&path.to_string_lossy(), true, allow_docroots)
        }
        ExplicitDirRole::PublishStorage => {
            miraserve_config::is_forbidden_dir_path(&path.to_string_lossy(), false, &[])
        }
        ExplicitDirRole::AcmeState => {
            // ACME state legitimately lives in `/var/lib/miraserve/acme`,
            // `/opt/homebrew/var/lib/miraserve/acme`, or a custom directory, but must NEVER be
            // `/`, a single-segment top-level directory, `/etc`, `/root`, `/proc`, `/sys`, `/dev`,
            // `/boot`, or a broad shared root like `/var/lib`.
            if normals.len() == 1 {
                return true;
            }
            if matches!(
                first.to_ascii_lowercase().as_str(),
                "etc" | "root" | "proc" | "sys" | "dev" | "boot" | "system"
            ) {
                return true;
            }
            let lower = path
                .to_string_lossy()
                .replace('\\', "/")
                .to_ascii_lowercase();
            let trimmed = lower.trim_end_matches('/');
            if trimmed.starts_with("/private/etc")
                || trimmed.starts_with("/usr/local/etc")
                || trimmed.starts_with("/opt/homebrew/etc")
            {
                return true;
            }
            matches!(
                trimmed,
                "/var/lib"
                    | "/var/log"
                    | "/var/run"
                    | "/var/tmp"
                    | "/var/cache"
                    | "/private/var"
                    | "/private/tmp"
                    | "/usr/local"
                    | "/opt/homebrew"
            )
        }
    }
}

/// Returns `true` if `path` is too broad/shared to receive a recursive Landlock directory rule
/// via automatic parent-directory widening (`R3-SBX-3`, `R4-SBX-2`). Rejects `/`, `.`, `..`,
/// ALL single-component top-level directories (`/etc`, `/opt`, `/srv`, `/var`, `/home`, `/tmp`,
/// ...), shared 2-level system roots (`/var/lib`, `/var/www`, `/etc/ssl`, `/etc/letsencrypt`, ...),
/// and user home roots (`/home/<user>`, `/Users/<user>`).
fn is_forbidden_widened_parent(path: &Path) -> bool {
    use std::path::Component;

    let mut has_root = false;
    let mut normals: Vec<&str> = Vec::new();
    for comp in path.components() {
        match comp {
            Component::RootDir | Component::Prefix(_) => has_root = true,
            Component::CurDir => {}
            Component::ParentDir => return true,
            Component::Normal(seg) => normals.push(seg.to_str().unwrap_or("")),
        }
    }

    if normals.is_empty() {
        return true;
    }
    if !has_root {
        // Never widen a relative parent directory (e.g. `etc/miraserve.kdl` -> `etc`).
        return true;
    }

    // Never widen a single file to ANY top-level directory (`/etc`, `/opt`, `/srv`, `/var`, `/tmp`, ...).
    if normals.len() == 1 {
        return true;
    }

    let first = normals.first().copied().unwrap_or("");
    let second = normals.get(1).copied().unwrap_or("");
    let third = normals.get(2).copied().unwrap_or("");

    if matches!(first, "root" | "proc" | "sys" | "dev" | "boot") {
        return true;
    }

    if normals.len() == 2
        && matches!(
            (first, second),
            ("home" | "Users", _)
                | ("var", "lib" | "run" | "tmp" | "www" | "log" | "cache")
                | ("usr", "local" | "share" | "lib" | "bin" | "sbin")
                | ("etc", "miraserve" | "ssl" | "pki" | "letsencrypt")
                | ("private", "etc" | "var" | "tmp")
        )
    {
        return true;
    }

    if normals.len() == 3
        && matches!(
            (first, second, third),
            ("etc", "ssl", "private")
                | ("etc", "pki", "tls")
                | ("etc", "letsencrypt", "live" | "archive")
                | ("etc", "miraserve", "keys")
                | ("usr", "local", "etc" | "var" | "share")
                | ("private", "var", "tmp" | "run" | "lib")
                | (
                    "private",
                    "etc",
                    "miraserve" | "ssl" | "pki" | "letsencrypt"
                )
        )
    {
        return true;
    }

    false
}

/// Validates that the process is not running as root (UID 0 / GID 0) whenever
/// `policy.user` or `policy.group` requests unprivileged execution.
///
/// MiraServe enforces `#![forbid(unsafe_code)]` across every shipped crate and therefore does not call
/// raw `setuid`/`setgid` FFI in-process; instead, it fails closed if still running as root
/// so operators must launch via systemd (`User=`/`Group=` + `AmbientCapabilities=CAP_NET_BIND_SERVICE`)
/// or an unprivileged container UID.
///
/// # Errors
/// Returns [`SandboxError::PrivilegeDrop`] if a root identity is requested or active.
pub fn verify_privilege_state(
    policy: &SandboxPolicy,
    user_id: Option<u32>,
    group_id: Option<u32>,
) -> Result<Option<String>, SandboxError> {
    let expected_user = policy
        .user
        .as_deref()
        .and_then(|u| u.trim().parse::<u32>().ok());
    let expected_group = policy
        .group
        .as_deref()
        .and_then(|g| g.trim().parse::<u32>().ok());
    verify_privilege_state_with_expected(policy, user_id, group_id, expected_user, expected_group)
}

/// Validates privilege-drop state against both non-root invariants AND explicitly resolved
/// expected UID/GID values (`R2-SBX-3`).
///
/// # Errors
/// Returns [`SandboxError::PrivilegeDrop`] if root is active/requested, current UID/GID is
/// unreadable, or the running UID/GID does not match `expected_user` / `expected_group`.
pub fn verify_privilege_state_with_expected(
    policy: &SandboxPolicy,
    user_id: Option<u32>,
    group_id: Option<u32>,
    expected_user: Option<u32>,
    expected_group: Option<u32>,
) -> Result<Option<String>, SandboxError> {
    if let Some(ref u) = policy.user {
        let trimmed = u.trim();
        if trimmed.eq_ignore_ascii_case("root") || trimmed.parse::<u32>().ok() == Some(0) {
            return Err(SandboxError::PrivilegeDrop(format!(
                "sandbox.user '{u}' resolves to root (UID 0)"
            )));
        }
    }
    if let Some(ref g) = policy.group {
        let trimmed = g.trim();
        if trimmed.eq_ignore_ascii_case("root") || trimmed.parse::<u32>().ok() == Some(0) {
            return Err(SandboxError::PrivilegeDrop(format!(
                "sandbox.group '{g}' resolves to root (GID 0)"
            )));
        }
    }

    if policy.user.is_none() && policy.group.is_none() {
        return Ok(None);
    }

    // R3-PKG-3: Non-Unix platforms (Windows) do not have POSIX UID/GID identities; service
    // account isolation (e.g. `NT AUTHORITY\LOCAL SERVICE`) is managed by the OS scheduler.
    #[cfg(not(unix))]
    {
        let _ = (user_id, group_id, expected_user, expected_group);
        Ok(Some(
            "non-Unix platform: sandbox.user/group is enforced by the OS service principal rather than POSIX UID/GID"
                .to_owned(),
        ))
    }

    #[cfg(unix)]
    {
        let (Some(actual_user), Some(actual_group)) = (user_id, group_id) else {
            return Err(SandboxError::PrivilegeDrop(
                "unable to determine current process UID/GID while sandbox.user/group is configured \
                 (refusing to start unverified, R2-SBX-3)"
                    .to_owned(),
            ));
        };

        if actual_user == 0 || actual_group == 0 {
            return Err(SandboxError::PrivilegeDrop(
                "process is running as UID/GID 0 while sandbox.user/group is configured; \
                 MiraServe forbids unsafe FFI setuid/setgid — launch the worker as the configured \
                 unprivileged user via systemd (User=/Group= + CAP_NET_BIND_SERVICE) or container UID"
                    .to_owned(),
            ));
        }

        // R2-SBX-3: Compare actual running UID/GID against configured `sandbox.user`/`group`!
        if let Some(exp_u) = expected_user
            && actual_user != exp_u
        {
            let cfg_u = policy.user.as_deref().unwrap_or("");
            return Err(SandboxError::PrivilegeDrop(format!(
                "process is running as UID {actual_user}, but sandbox.user '{cfg_u}' requires UID {exp_u}"
            )));
        }
        if let Some(exp_g) = expected_group
            && actual_group != exp_g
        {
            let cfg_g = policy.group.as_deref().unwrap_or("");
            return Err(SandboxError::PrivilegeDrop(format!(
                "process is running as GID {actual_group}, but sandbox.group '{cfg_g}' requires GID {exp_g}"
            )));
        }

        Ok(Some(format!(
            "running unprivileged (UID {actual_user}, GID {actual_group}); OS user/group isolation verified",
        )))
    }
}

/// Maximum time permitted for an NSS helper subprocess (`/usr/bin/id` or `/usr/bin/getent`)
/// before killing it so a hung LDAP/SSSD daemon can never stall startup (`R5-SBX-3`).
#[cfg(unix)]
const NSS_SUBPROCESS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Maximum stdout bytes read from an NSS helper subprocess (`R5-SBX-3`).
const MAX_NSS_STDOUT_BYTES: u64 = 4_096;

pub(crate) fn make_abs_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else if let Ok(cwd) = std::env::current_dir() {
        cwd.join(path)
    } else {
        path.to_path_buf()
    }
}

/// Returns `true` for Windows path spellings outside the local drive namespace: network shares
/// (`\\server\share`, `\\?\UNC\server\share`, `//server/share`), device paths
/// (`\\.\device`) and every verbatim namespace other than a drive letter (for example
/// `\\?\Volume{GUID}\` or `\\?\GLOBALROOT\`). Only `\\?\X:\...` is accepted among
/// verbatim paths (Codex Round-6 Windows note).
#[cfg_attr(not(windows), allow(dead_code))]
fn is_windows_network_or_device_path(s: &str) -> bool {
    let norm = s.replace('/', "\\");
    if let Some(rest) = norm.strip_prefix("\\\\?\\") {
        return !is_drive_qualified(rest);
    }
    norm.starts_with("\\\\")
}

/// `X:` or `X:\...` with an ASCII drive letter.
#[cfg_attr(not(windows), allow(dead_code))]
fn is_drive_qualified(s: &str) -> bool {
    let b = s.as_bytes();
    b.first().is_some_and(u8::is_ascii_alphabetic)
        && b.get(1) == Some(&b':')
        && b.get(2).is_none_or(|c| *c == b'\\')
}

/// Rejects log destinations this platform cannot pin safely, BEFORE any directory is created or
/// any file is opened (Codex Round-5 P2): on Windows, network shares and device paths (their
/// rename/lock semantics are not verified); on every platform, a log path that is itself a
/// symbolic link.
#[must_use]
pub fn log_path_platform_rejection(log_path: &Path) -> Option<String> {
    #[cfg(windows)]
    {
        let configured = log_path.to_string_lossy();
        if is_windows_network_or_device_path(&configured) {
            return Some(format!(
                "log path '{}' is on a network share or device path; MiraServe only writes logs to local drive-qualified directories",
                log_path.display()
            ));
        }
        let normalized = normalize_overlap_path(log_path);
        if is_windows_network_or_device_path(&normalized.to_string_lossy()) {
            return Some(format!(
                "log path '{}' is on a network share or device path; MiraServe only writes logs to local drive-qualified directories",
                log_path.display()
            ));
        }
    }
    if std::fs::symlink_metadata(make_abs_path(log_path))
        .is_ok_and(|md| md.file_type().is_symlink())
    {
        return Some(format!(
            "log path '{}' is a symbolic link; configure the real log file path",
            log_path.display()
        ));
    }
    None
}

/// Platform-appropriate forbidden directory check for rotating log directories (Codex Round-4 P2).
///
/// On Unix, applies the full Linux Landlock deny list (`sandbox_tree_rejection`). On Windows,
/// blocks drive roots, OS system directories (`\Windows`, `\Program Files`, etc.) and network
/// shares using native path semantics so normal drive-qualified log directories are allowed.
fn platform_log_dir_rejection(candidate: &Path) -> Option<String> {
    #[cfg(unix)]
    {
        let candidate_str = candidate.to_string_lossy();
        miraserve_config::sandbox_tree_rejection(&candidate_str).map(str::to_owned)
    }
    #[cfg(not(unix))]
    {
        if is_windows_network_or_device_path(&candidate.to_string_lossy()) {
            return Some(format!(
                "refusing network share or device path '{}' for rotating log directory",
                candidate.display()
            ));
        }
        let norm = normalize_overlap_path(candidate);
        let s = norm.to_string_lossy();
        if is_windows_network_or_device_path(&s) {
            return Some(format!(
                "refusing network share or device path '{}' for rotating log directory",
                candidate.display()
            ));
        }
        let trimmed = s.trim_end_matches(['\\', '/']);
        if trimmed.is_empty() || (trimmed.len() == 2 && trimmed.as_bytes().get(1) == Some(&b':')) {
            return Some(format!(
                "refusing broad filesystem root '{}' for rotating log directory",
                candidate.display()
            ));
        }
        let lower = trimmed.to_ascii_lowercase().replace('/', "\\");
        let after_drive = lower.get(2..).unwrap_or(&lower);
        for forbidden in [
            "\\windows",
            "\\program files",
            "\\program files (x86)",
            "\\programdata\\microsoft",
            "\\system volume information",
        ] {
            if after_drive == forbidden || after_drive.starts_with(&format!("{forbidden}\\")) {
                return Some(format!(
                    "refusing system directory '{}' for rotating log directory",
                    candidate.display()
                ));
            }
        }
        None
    }
}

/// Strips the Windows verbatim prefix only where the result stays absolute and equivalent:
/// `\\?\C:\x` -> `C:\x` and `\\?\UNC\server\share\x` -> `\\server\share\x`. Every other
/// verbatim namespace (e.g. `\\?\Volume{GUID}\`) is left unchanged so it never becomes a
/// relative path; such paths are rejected for logs before any filesystem access (Codex Round-6).
#[cfg(windows)]
fn strip_windows_verbatim(s: &str) -> String {
    if let Some(rest) = s.strip_prefix("\\\\?\\") {
        if rest.len() >= 4
            && rest
                .get(..4)
                .is_some_and(|p| p.eq_ignore_ascii_case("UNC\\"))
        {
            return format!("\\\\{}", rest.get(4..).unwrap_or_default());
        }
        if is_drive_qualified(rest) {
            return rest.to_owned();
        }
    }
    s.to_owned()
}

#[cfg(windows)]
fn canonical_compare_key(p: &Path) -> PathBuf {
    PathBuf::from(strip_windows_verbatim(&p.to_string_lossy()).to_ascii_lowercase())
}

pub(crate) fn normalized_paths_equal(a: &Path, b: &Path) -> bool {
    #[cfg(windows)]
    {
        canonical_compare_key(a) == canonical_compare_key(b)
    }
    #[cfg(not(windows))]
    {
        a == b
    }
}

pub(crate) fn normalized_path_starts_with(path: &Path, prefix: &Path) -> bool {
    #[cfg(windows)]
    {
        canonical_compare_key(path).starts_with(canonical_compare_key(prefix))
    }
    #[cfg(not(windows))]
    {
        path.starts_with(prefix)
    }
}

pub(crate) fn normalized_paths_overlap(a: &Path, b: &Path) -> bool {
    normalized_paths_equal(a, b)
        || normalized_path_starts_with(a, b)
        || normalized_path_starts_with(b, a)
}

/// Resolves `path` to a normalized absolute path key (canonicalizing the deepest existing
/// ancestor so symlinks and relative paths such as `.miraserve-acme` compare accurately).
/// Where a secret path named by `site` is located for the overlap checks. A path inside the
/// site's own `owner-dir` is under the tenant's control: it is checked as written, and also at
/// its resolved location when that stays inside the account (a genuine key reached through an
/// in-account link stays protected), but never at a location outside the account (a link there
/// must not make another site's file count as this secret). Other paths are resolved as usual.
fn secret_overlap_paths(site: &miraserve_config::SiteConfig, path: &Path) -> Vec<PathBuf> {
    let Some(owner) = site.owner_dir.as_ref() else {
        return vec![normalize_overlap_path(path)];
    };
    let owner_abs = make_abs_path(Path::new(owner));
    if !make_abs_path(path).starts_with(&owner_abs) {
        return vec![normalize_overlap_path(path)];
    }
    let mut written = PathBuf::new();
    for component in make_abs_path(path).components() {
        match component {
            std::path::Component::ParentDir => {
                written.pop();
            }
            std::path::Component::CurDir => {}
            other => written.push(other),
        }
    }
    let mut paths = vec![written];
    let owner_real = std::fs::canonicalize(&owner_abs).unwrap_or(owner_abs);
    let resolved = normalize_overlap_path(path);
    if resolved.starts_with(&owner_real) {
        paths.push(resolved);
    }
    paths
}

pub(crate) fn normalize_overlap_path(path: &Path) -> PathBuf {
    let abs = make_abs_path(path);
    let mut cur = abs.as_path();
    let mut suffix: Vec<std::ffi::OsString> = Vec::new();
    let resolved = loop {
        if let Ok(canon) = std::fs::canonicalize(cur) {
            let mut full = canon;
            for part in suffix.iter().rev() {
                full.push(part);
            }
            break full;
        }
        let Some(parent) = cur.parent() else {
            break abs;
        };
        if let Some(name) = cur.file_name() {
            suffix.push(name.to_os_string());
        }
        if parent == cur {
            break abs;
        }
        cur = parent;
    };
    // Strip the Windows verbatim prefix (keeping any UNC root) so canonicalized and
    // non-canonicalized paths compare uniformly on Windows.
    #[cfg(windows)]
    let resolved = PathBuf::from(strip_windows_verbatim(&resolved.to_string_lossy()));
    // Clean `.` components lexically.
    let mut cleaned = PathBuf::new();
    for comp in resolved.components() {
        if !matches!(comp, std::path::Component::CurDir) {
            cleaned.push(comp.as_os_str());
        }
    }
    cleaned
}

fn paths_overlap_canonical(a: &Path, b: &Path) -> bool {
    let na = normalize_overlap_path(a);
    let nb = normalize_overlap_path(b);
    normalized_paths_overlap(&na, &nb)
}

/// Returns every HTTP document root (`site.root` or `route.root`) that equals, lies inside, or is
/// an ancestor of `acme_dir` (`R6-SBX-1`).
#[must_use]
pub fn find_docroot_acme_overlaps(config: &Config, acme_dir: &Path) -> Vec<(String, PathBuf)> {
    let mut overlaps = Vec::new();
    for site in &config.sites {
        let host = site.hosts.first().map_or("<site>", String::as_str);
        if let Some(root) = &site.root {
            let rp = PathBuf::from(root);
            if paths_overlap_canonical(&rp, acme_dir) {
                overlaps.push((format!("site '{host}' root"), rp));
            }
        }
        for route in &site.routes {
            if let Some(r_root) = &route.root {
                let rp = PathBuf::from(r_root);
                if paths_overlap_canonical(&rp, acme_dir) {
                    overlaps.push((format!("site '{host}' route '{}' root", route.pattern), rp));
                }
            }
        }
    }
    overlaps
}

/// Inspects every HTTP document root (`site.root`, `route.root`) against:
/// 1. Symlink resolution into any forbidden or default-denied directory (`R7-SBX-2`, Section 5)
/// 2. Overlap with the running process's effective ACME state directory (`R6-SBX-1`, `R7-SBX-1`)
/// 3. Containment of the loaded configuration file's directory (`R7-CFG-1`)
/// 4. Overlap with any configured `ai-publish.storage` directory (Section 5)
/// 5. Containment of any configured TLS private key or `keyd` socket path (Section 5)
///
/// Called uniformly by `miraserve check --fs`, `miraserve run` startup, and `RunningServer`
/// live reloads (`SIGHUP` / `miraserve reload`) so startup and reload enforce identical docroot
/// confinement!
#[must_use]
pub fn find_unsafe_docroots(
    config: &Config,
    config_path: Option<&Path>,
    effective_acme_dir: Option<&Path>,
) -> Vec<String> {
    find_unsafe_docroots_with_secret_files(config, config_path, effective_acme_dir, &[])
}

/// Checks whether any configured HTTP document root overlaps an active CLI log file or rotating
/// log directory (Codex G7 P1).
///
/// Refuses BOTH:
/// - Any log file (`--log-file` or `--access-log`) whose canonical location lies inside a served
///   document root (so startup never opens a log file inside a served directory, and reloads can
///   never expose an existing log file).
/// - Any rotating log's parent directory overlapping a served document root (so an existing
///   Landlock RW grant for log rotation can never satisfy a newly reloaded docroot's read access).
#[must_use]
pub fn find_docroot_log_overlaps(
    config: &Config,
    log_file_paths: &[PathBuf],
    rotating_log_paths: &[PathBuf],
) -> Vec<String> {
    let mut violations = Vec::new();
    if log_file_paths.is_empty() && rotating_log_paths.is_empty() {
        return violations;
    }

    let mut docroots: Vec<(String, PathBuf)> = Vec::new();
    for site in &config.sites {
        let host = site.hosts.first().map_or("<site>", String::as_str);
        if let Some(root) = &site.root {
            docroots.push((
                format!("site '{host}' root '{root}'"),
                normalize_overlap_path(Path::new(root)),
            ));
        }
        for route in &site.routes {
            if let Some(r_root) = &route.root {
                docroots.push((
                    format!("site '{host}' route '{}' root '{r_root}'", route.pattern),
                    normalize_overlap_path(Path::new(r_root)),
                ));
            }
        }
    }

    for log_path in log_file_paths {
        let real_log = normalize_overlap_path(log_path);
        for (doc_label, real_root) in &docroots {
            if normalized_paths_equal(&real_log, real_root)
                || normalized_path_starts_with(&real_log, real_root)
            {
                violations.push(format!(
                    "{doc_label} overlaps log file '{}'",
                    log_path.display()
                ));
            }
        }
    }

    for rot_path in rotating_log_paths {
        let real_rot = normalize_overlap_path(rot_path);
        if let Some(real_parent) = real_rot.parent().filter(|p| !p.as_os_str().is_empty()) {
            for (doc_label, real_root) in &docroots {
                if normalized_paths_overlap(real_parent, real_root) {
                    violations.push(format!(
                        "{doc_label} overlaps rotating log directory '{}'",
                        real_parent.display()
                    ));
                }
            }
        }
    }

    violations
}

/// Reload check verifying EVERY startup pinned log directory retains its original destination AND
/// no reloaded document root overlaps any startup pinned log directory (by canonical path or Unix
/// inode) — closing the moved-alias reload attack where a CLI log alias moves between two already-
/// granted directories while the live writer still holds the original directory (Codex Round-4 P1 #3).
#[must_use]
pub fn find_docroot_pinned_log_overlaps(
    config: &Config,
    pinned_log_dirs: &[PinnedLogDir],
) -> Vec<String> {
    let mut violations = Vec::new();
    if pinned_log_dirs.is_empty() {
        return violations;
    }

    for pinned_log in pinned_log_dirs {
        if let Err(reason) = pinned_log.verify_configured_destination() {
            violations.push(reason);
        }
    }

    for site in &config.sites {
        let host = site.hosts.first().map_or("<site>", String::as_str);
        let roots = site
            .root
            .iter()
            .map(|r| (format!("site '{host}' root '{r}'"), Path::new(r.as_str())))
            .chain(site.routes.iter().filter_map(|rt| {
                rt.root.as_deref().map(|r| {
                    (
                        format!("site '{host}' route '{}' root '{r}'", rt.pattern),
                        Path::new(r),
                    )
                })
            }));
        for (doc_label, root_path) in roots {
            for pinned_log in pinned_log_dirs {
                if pinned_log.conflicts_with_docroot(root_path) {
                    let what = if pinned_log.rotating {
                        "rotating log directory"
                    } else {
                        "log file in directory"
                    };
                    violations.push(format!(
                        "{doc_label} overlaps startup pinned {what} '{}'",
                        pinned_log.dir.path.display()
                    ));
                }
            }
        }
    }

    violations
}

/// Where the deployment guide keeps Basic-auth users files (`/etc/miraserve/auth/<site>.htpasswd`).
pub const USERS_FILE_DIR: &str = "/etc/miraserve/auth";

/// [`find_unsafe_docroots`] plus secret files that exist only on the command line, such as the
/// `keyd` HMAC secret passed via `--keyd-auth-secret-file` (`R8-SBX-1`). Every caller that knows
/// such a path (`check --fs`, startup, reload) must pass it so the three stay in agreement.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn find_unsafe_docroots_with_secret_files(
    config: &Config,
    config_path: Option<&Path>,
    effective_acme_dir: Option<&Path>,
    extra_secret_files: &[PathBuf],
) -> Vec<String> {
    let mut violations = Vec::new();
    // Both the directory of the path as written and the directory of the real file (when the
    // configuration file name is a link): either one inside a served root exposes the file.
    let mut cfg_dirs: Vec<PathBuf> = config_path
        .and_then(Path::parent)
        .filter(|p| !p.as_os_str().is_empty())
        .map(normalize_overlap_path)
        .into_iter()
        .collect();
    if let Some(real_dir) = config_path
        .and_then(|p| std::fs::canonicalize(p).ok())
        .and_then(|real| real.parent().map(Path::to_path_buf))
        && !cfg_dirs.contains(&real_dir)
    {
        cfg_dirs.push(real_dir);
    }

    let mut key_or_sock_paths: Vec<(&str, PathBuf)> = Vec::new();
    if let Some(key) = &config.server.tls.key {
        key_or_sock_paths.push(("server.tls.key", normalize_overlap_path(Path::new(key))));
    }
    if let Some(sock) = &config.server.tls.keyd_socket
        && !sock.starts_with("tcp://")
    {
        key_or_sock_paths.push((
            "server.tls.keyd-socket",
            normalize_overlap_path(Path::new(sock)),
        ));
    }
    for site in &config.sites {
        if let Some(tls) = &site.tls
            && let Some(key) = &tls.key
        {
            for located in secret_overlap_paths(site, Path::new(key)) {
                key_or_sock_paths.push(("site.tls.key", located));
            }
        }
    }

    // R8-SBX-1: every other secret-bearing path. The upstream mTLS client key lets its holder
    // impersonate this proxy to the backend; the keyd HMAC secret lets any local process use
    // keyd as a signing oracle. Neither has a `.key`/`.pem` name the static deny rule would catch.
    for site in &config.sites {
        for route in &site.routes {
            if let RouteHandler::ReverseProxy(rp) = &route.handler
                && let Some(key) = rp.upstream_tls.as_ref().and_then(|t| t.client_key.as_ref())
            {
                for located in secret_overlap_paths(site, Path::new(key)) {
                    key_or_sock_paths.push(("reverse-proxy upstream-tls client-key", located));
                }
            }
        }
    }
    for secret in extra_secret_files {
        key_or_sock_paths.push(("keyd auth secret file", normalize_overlap_path(secret)));
    }

    let publish_stores: Vec<PathBuf> = config
        .sites
        .iter()
        .filter_map(|s| s.ai_publish.as_ref().map(|p| PathBuf::from(&p.storage)))
        .collect();

    let mut docroots: Vec<(String, PathBuf)> = Vec::new();
    for site in &config.sites {
        let host = site.hosts.first().map_or("<site>", String::as_str);
        if let Some(root) = &site.root {
            docroots.push((format!("site '{host}' root"), PathBuf::from(root)));
        }
        for route in &site.routes {
            if let Some(r_root) = &route.root {
                docroots.push((
                    format!("site '{host}' route '{}' root", route.pattern),
                    PathBuf::from(r_root),
                ));
            }
        }
    }

    // A `read-tree` / `socket-tree` is granted to the worker process, not served over HTTP, so
    // the document-root overlap checks do not apply to it: in the default key mode the worker
    // already reads its config, certificates and keys, and a panel will list the directory of
    // its certificate files here so renewed and new certificates load on reload. What must hold
    // is the config validator's rule on the REAL location: a tree that is a symlink into a
    // system, secret or MiraServe state directory is refused.
    let sandbox_trees = config
        .server
        .sandbox
        .read_trees
        .iter()
        .map(|t| ("read-tree", t))
        .chain(
            config
                .server
                .sandbox
                .socket_trees
                .iter()
                .map(|t| ("socket-tree", t)),
        );
    for (kind, tree) in sandbox_trees {
        let tp = PathBuf::from(tree);
        if let Ok(canon) = std::fs::canonicalize(&tp)
            && let Some(reason) = miraserve_config::sandbox_tree_rejection(&canon.to_string_lossy())
        {
            violations.push(format!(
                "sandbox {kind} '{}' resolves to '{}', which is not allowed: {reason}",
                tp.display(),
                canon.display()
            ));
        }
    }

    for (label, rp) in docroots {
        // 1. Symlink / canonical target check against Section 5 forbidden/default-denied trees (`R7-SBX-2`)
        if let Ok(canon) = std::fs::canonicalize(&rp) {
            let canon_str = canon.to_string_lossy();
            if miraserve_config::is_forbidden_dir_path(
                &canon_str,
                true,
                &config.server.allow_docroots,
            ) {
                violations.push(format!(
                    "{label} '{}' resolves to forbidden directory '{}' (R7-SBX-2)",
                    rp.display(),
                    canon.display()
                ));
            }
        }

        // 2. Effective ACME state directory overlap (`R6-SBX-1`, `R7-SBX-1`)
        if let Some(acme) = effective_acme_dir
            && paths_overlap_canonical(&rp, acme)
        {
            violations.push(format!(
                "{label} '{}' overlaps effective ACME state directory '{}' and would expose ACME account/certificate private keys (R7-SBX-1)",
                rp.display(),
                acme.display()
            ));
        }

        let rp_norm = normalize_overlap_path(&rp);

        // 3. Loaded config file directory containment (`R7-CFG-1`)
        for cfg_dir in cfg_dirs
            .iter()
            .filter(|cfg_dir| *cfg_dir == &rp_norm || cfg_dir.starts_with(&rp_norm))
        {
            violations.push(format!(
                "{label} '{}' contains the configuration directory '{}' and would expose the config file over HTTP (R7-CFG-1)",
                rp.display(),
                cfg_dir.display()
            ));
        }

        // 4. `ai-publish.storage` overlap (Section 5)
        for store in &publish_stores {
            if paths_overlap_canonical(&rp, store) {
                violations.push(format!(
                    "{label} '{}' overlaps ai-publish.storage '{}' and would expose publish metadata/releases",
                    rp.display(),
                    store.display()
                ));
            }
        }

        // 5. Configured TLS private key / keyd socket containment (Section 5)
        for (secret_label, secret_norm) in &key_or_sock_paths {
            if secret_norm == &rp_norm || secret_norm.starts_with(&rp_norm) {
                violations.push(format!(
                    "{label} '{}' contains {secret_label} '{}' and would expose private key or signing socket material over HTTP",
                    rp.display(),
                    secret_norm.display()
                ));
            }
        }
    }

    violations
}

/// Runs an external helper command with a strict wall-clock timeout, killing and reaping the
/// child process if it hangs (e.g. a wedged LDAP/SSSD lookup, `R5-SBX-3`).
///
/// Returns `Some(stdout_string)` only if the process exits with status `0` within `timeout`.
#[must_use]
pub fn run_command_stdout_with_timeout(
    program: &str,
    args: &[&str],
    timeout: std::time::Duration,
) -> Option<String> {
    use std::io::Read as _;
    use std::process::{Command, Stdio};
    use std::time::Instant;

    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return None;
                }
                let mut buf = Vec::new();
                if let Some(stdout) = child.stdout.take() {
                    let _ = stdout.take(MAX_NSS_STDOUT_BYTES).read_to_end(&mut buf);
                }
                return String::from_utf8(buf).ok();
            }
            Ok(None) => {
                let now = Instant::now();
                if now >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                let pause = std::time::Duration::from_millis(10)
                    .min(deadline.saturating_duration_since(now));
                std::thread::sleep(pause);
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

#[cfg(unix)]
fn is_safe_nss_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

#[cfg(unix)]
fn resolve_unix_user_uid_from_passwd(spec: &str) -> Result<u32, SandboxError> {
    let trimmed = spec.trim();
    if let Ok(uid) = trimmed.parse::<u32>() {
        return Ok(uid);
    }
    if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
        for line in content.lines() {
            let mut parts = line.split(':');
            if let (Some(name), Some(_), Some(uid_str)) = (parts.next(), parts.next(), parts.next())
                && name == trimmed
                && let Ok(uid) = uid_str.parse::<u32>()
            {
                return Ok(uid);
            }
        }
    }
    // R5-SBX-3: Fall back to `/usr/bin/id -u <user>` with a bounded timeout for NSS / LDAP / SSSD
    // accounts not present in local `/etc/passwd`.
    if is_safe_nss_name(trimmed)
        && let Some(stdout) =
            run_command_stdout_with_timeout("/usr/bin/id", &["-u", trimmed], NSS_SUBPROCESS_TIMEOUT)
        && let Ok(uid) = stdout.trim().parse::<u32>()
    {
        return Ok(uid);
    }
    Err(SandboxError::PrivilegeDrop(format!(
        "configured sandbox.user '{trimmed}' was not found in /etc/passwd or NSS (/usr/bin/id)"
    )))
}

#[cfg(unix)]
fn resolve_unix_group_gid_from_etc_group(spec: &str) -> Result<u32, SandboxError> {
    let trimmed = spec.trim();
    if let Ok(gid) = trimmed.parse::<u32>() {
        return Ok(gid);
    }
    if let Ok(content) = std::fs::read_to_string("/etc/group") {
        for line in content.lines() {
            let mut parts = line.split(':');
            if let (Some(name), Some(_), Some(gid_str)) = (parts.next(), parts.next(), parts.next())
                && name == trimmed
                && let Ok(gid) = gid_str.parse::<u32>()
            {
                return Ok(gid);
            }
        }
    }
    // R5-SBX-3: Fall back to `/usr/bin/getent group <group>` with a bounded timeout for NSS/LDAP.
    if is_safe_nss_name(trimmed)
        && let Some(stdout) = run_command_stdout_with_timeout(
            "/usr/bin/getent",
            &["group", trimmed],
            NSS_SUBPROCESS_TIMEOUT,
        )
        && let Some(first_line) = stdout.lines().next()
    {
        let mut parts = first_line.split(':');
        if let (Some(name), Some(_), Some(gid_str)) = (parts.next(), parts.next(), parts.next())
            && name == trimmed
            && let Ok(gid) = gid_str.parse::<u32>()
        {
            return Ok(gid);
        }
    }
    Err(SandboxError::PrivilegeDrop(format!(
        "configured sandbox.group '{trimmed}' was not found in /etc/group or NSS (/usr/bin/getent)"
    )))
}

/// Detects the current process effective UID/GID without `unsafe` code.
#[must_use]
fn detect_current_uid_gid() -> (Option<u32>, Option<u32>) {
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            let mut uid = None;
            let mut gid = None;
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("Uid:") {
                    // Format: Real Effective Saved Filesystem; fail closed if any is 0
                    let ids: Vec<u32> = rest
                        .split_whitespace()
                        .filter_map(|t| t.parse::<u32>().ok())
                        .collect();
                    if ids.contains(&0) {
                        uid = Some(0);
                    } else if let Some(&euid) = ids.get(1).or_else(|| ids.first()) {
                        uid = Some(euid);
                    }
                } else if let Some(rest) = line.strip_prefix("Gid:") {
                    let ids: Vec<u32> = rest
                        .split_whitespace()
                        .filter_map(|t| t.parse::<u32>().ok())
                        .collect();
                    if ids.contains(&0) {
                        gid = Some(0);
                    } else if let Some(&egid) = ids.get(1).or_else(|| ids.first()) {
                        gid = Some(egid);
                    }
                }
            }
            return (uid, gid);
        }
        (None, None)
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    {
        let uid = run_command_stdout_with_timeout("/usr/bin/id", &["-u"], NSS_SUBPROCESS_TIMEOUT)
            .and_then(|s| s.trim().parse::<u32>().ok());
        let gid = run_command_stdout_with_timeout("/usr/bin/id", &["-g"], NSS_SUBPROCESS_TIMEOUT)
            .and_then(|s| s.trim().parse::<u32>().ok());
        (uid, gid)
    }

    #[cfg(not(unix))]
    {
        (None, None)
    }
}

/// Applies Linux Landlock LSM confinement to the **calling thread** (safe to invoke from
/// Tokio's `Builder::on_thread_start` so every worker thread is individually confined).
///
/// On non-Linux hosts, returns `Ok(EnforcementStatus::UnsupportedPlatform)` or
/// `Ok(EnforcementStatus::Disabled)`.
///
/// # Errors
/// Returns [`SandboxError::Landlock`] if Landlock enforcement fails on Linux.
pub fn apply_landlock_current_thread(
    policy: &SandboxPolicy,
) -> Result<EnforcementStatus, SandboxError> {
    if !policy.landlock {
        return Ok(EnforcementStatus::Disabled);
    }
    policy.verify_pinned_writable_dirs()?;
    #[cfg(target_os = "linux")]
    {
        let mut notes = Vec::new();
        linux::apply_landlock(policy, &mut notes)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(EnforcementStatus::UnsupportedPlatform)
    }
}

/// Applies Linux seccomp-bpf confinement (dangerous-syscall denylist plus set-ID mode-bit filter)
/// to the **calling thread only** (without `SECCOMP_FILTER_FLAG_TSYNC`).
///
/// Production startup installs the identical filter across all threads in [`apply_sandbox`]; this
/// per-thread helper exists for symmetry with [`apply_landlock_current_thread`] and isolated
/// per-thread verification.
///
/// When `mode` is [`SeccompMode::Off`], no seccomp filter is installed at all (neither the
/// dangerous-syscall denylist nor the set-ID mode-bit filter) and
/// [`EnforcementStatus::Disabled`] is returned.
///
/// # Errors
/// Returns [`SandboxError::Seccomp`] if compiling or installing the seccomp-bpf filter fails on
/// Linux.
pub fn apply_seccomp_current_thread(mode: SeccompMode) -> Result<EnforcementStatus, SandboxError> {
    if mode == SeccompMode::Off {
        return Ok(EnforcementStatus::Disabled);
    }
    #[cfg(target_os = "linux")]
    {
        linux::apply_seccomp_current_thread(mode)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(EnforcementStatus::UnsupportedPlatform)
    }
}

/// Compiles MiraServe's seccomp-bpf program for the host Linux architecture and returns its raw
/// `struct sock_filter` instruction bytes (used by live-kernel integration tests to install the
/// exact `SeccompMode::Strict` program inside an isolated child process where `execve` is denied).
///
/// # Errors
/// Returns [`SandboxError::Seccomp`] if compiling the seccomp-bpf program fails.
#[doc(hidden)]
#[cfg(target_os = "linux")]
pub fn compile_seccomp_bpf_bytes_for_host(mode: SeccompMode) -> Result<Vec<u8>, SandboxError> {
    if mode == SeccompMode::Off {
        return Ok(Vec::new());
    }
    linux::compile_seccomp_bpf_bytes_host(mode)
}

/// Reason why `openat2(2)` was refused by the current process environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    not(any(target_os = "linux", target_os = "android", test)),
    allow(dead_code)
)]
enum Openat2RefusalKind {
    NoSys,
    Perm,
    Access,
}

/// Returns whether a seccomp filter is currently active on the **calling (probing) thread** by
/// inspecting `/proc/thread-self/status` (`Seccomp:` field: `0` -> `Some(false)`, `1` or `2` ->
/// `Some(true)`).
///
/// Inspects `/proc/thread-self/status` rather than `/proc/self/status` (which describes the
/// thread-group leader and can differ from the probing thread when filters are installed
/// per-thread). Returns `None` on non-Linux platforms or when `/proc/thread-self/status` cannot be
/// read or parsed. Calling this before installing MiraServe's own seccomp filter distinguishes an
/// outer filter (systemd or container) from an unfiltered thread on a kernel older than Linux 5.6.
#[must_use]
pub fn detect_seccomp_filter_active() -> Option<bool> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let status = std::fs::read_to_string("/proc/thread-self/status").ok()?;
        parse_proc_status_seccomp_active(&status)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        None
    }
}

#[cfg(any(target_os = "linux", target_os = "android", test))]
fn parse_proc_status_seccomp_active(status: &str) -> Option<bool> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Seccomp:") {
            return match rest.trim() {
                "0" => Some(false),
                "1" | "2" => Some(true),
                _ => None,
            };
        }
    }
    None
}

fn probe_openat2_refusal_detail() -> Option<(Openat2RefusalKind, String)> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, openat2};
        use rustix::io::Errno;

        match openat2(
            CWD,
            "",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::empty(),
        ) {
            Err(Errno::NOSYS) => Some((
                Openat2RefusalKind::NoSys,
                std::io::Error::from(Errno::NOSYS).to_string(),
            )),
            Err(Errno::PERM) => Some((
                Openat2RefusalKind::Perm,
                std::io::Error::from(Errno::PERM).to_string(),
            )),
            Err(Errno::ACCESS) => Some((
                Openat2RefusalKind::Access,
                std::io::Error::from(Errno::ACCESS).to_string(),
            )),
            _ => None,
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        None
    }
}

/// Probes whether the Linux `openat2(2)` system call is refused with a recognised errno in the
/// current thread.
///
/// Issues `openat2(AT_FDCWD, "", O_RDONLY | O_CLOEXEC, 0, 0)`, which is side-effect free: when
/// `openat2` is supported and allowed, the kernel rejects the empty pathname immediately with
/// `ENOENT` without creating or opening a descriptor or consulting Landlock. When the kernel is
/// older than Linux 5.6 or a system-call filter (such as systemd's `RestrictSUIDSGID=yes` or an
/// outer container seccomp profile) blocks `openat2` with a recognised errno action, the call
/// returns `ENOSYS`, `EPERM`, or `EACCES` before entering `sys_openat2`, and this function returns
/// `Some(error_description)`.
///
/// # Caveats
/// - **Silence means only "no recognised refusal":** returning `None` does **not** prove `openat2`
///   is unfiltered or usable — any unrecognised errno (for example an outer filter returning
///   `EINVAL`) also produces `None` and emits no advisory.
/// - **Kill-action filters (`KILL_PROCESS` vs `KILL_THREAD`):** if an outer seccomp policy denies
///   `openat2` with `SECCOMP_RET_KILL_PROCESS`, invoking this probe terminates the entire process
///   with `SIGSYS` (including `miraserve check` or `miraserve run`). With `SECCOMP_RET_KILL_THREAD`
///   (or legacy `SECCOMP_RET_KILL`), the kernel terminates only the probing thread with `SIGSYS`,
///   which can leave other startup threads alive in a multi-threaded process.
/// - **`RESOLVE_CACHED` (Linux 5.6–5.11):** because this probe passes `ResolveFlags::empty()`,
///   returning `None` proves only that no recognised refusal occurred for plain `openat2(2)`; it
///   says nothing about whether the kernel supports `RESOLVE_CACHED` (introduced in Linux 5.12).
///   On Linux 5.6–5.11 `openat2` succeeds (so `file-cache` works), while `openat2(RESOLVE_CACHED)`
///   returns `EINVAL` and worker loops fall back to their blocking pool.
///
/// Always returns `None` on non-Linux platforms (where `openat2` does not exist).
#[must_use]
pub fn probe_openat2_refused() -> Option<String> {
    probe_openat2_refusal_detail().map(|(_, err)| err)
}

/// Caller context for formatting an `openat2` refusal advisory.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(
    not(any(target_os = "linux", target_os = "android", test)),
    allow(dead_code)
)]
enum Openat2AdvisoryContext<'a> {
    /// Standalone `miraserve check`: no sandbox is installed and `check` cannot see whether
    /// `ExecStart` passes `--no-sandbox` or an embedder overrides `SandboxPolicy`.
    StandaloneCheck,
    /// Live runtime startup after Phase B `apply_sandbox`: uses the actually installed
    /// [`SandboxReport`] (`None` when sandboxing was skipped via `--no-sandbox`).
    Runtime(Option<&'a SandboxReport>),
}

/// Probes whether `openat2(RESOLVE_CACHED)` is rejected with `EINVAL` in the current thread
/// (Linux 5.6–5.11, where `openat2` itself works but `RESOLVE_CACHED` does not exist yet).
#[cfg(any(target_os = "linux", target_os = "android"))]
fn probe_openat2_resolve_cached_unsupported() -> bool {
    use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, openat2};
    use rustix::io::Errno;

    matches!(
        openat2(
            CWD,
            "",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::CACHED,
        ),
        Err(Errno::INVAL)
    )
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
const fn probe_openat2_resolve_cached_unsupported() -> bool {
    false
}

#[cfg(target_os = "linux")]
static CACHED_KERNEL_RELEASE: std::sync::OnceLock<Option<(u32, u32)>> = std::sync::OnceLock::new();

/// Reads and caches `/proc/sys/kernel/osrelease` before OS sandboxing (Landlock) is installed,
/// so post-sandbox startup advisories never re-read `/proc` under Landlock.
pub fn warm_kernel_release() {
    #[cfg(target_os = "linux")]
    {
        let _ = cached_kernel_release();
    }
}

#[cfg(target_os = "linux")]
fn cached_kernel_release() -> Option<(u32, u32)> {
    *CACHED_KERNEL_RELEASE.get_or_init(|| {
        let bytes = std::fs::read("/proc/sys/kernel/osrelease").ok()?;
        parse_kernel_release_major_minor(&bytes)
    })
}

#[cfg(all(any(test, feature = "test-h2-hooks"), target_os = "linux"))]
static TEST_ADVISORY_KERNEL_IN_RANGE_OVERRIDE: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(0);

/// Integration-test RAII guard overriding the Linux 5.12–6.11 kernel-range check inside
/// [`openat2_refused_advisory`] and [`openat2_refused_advisory_for_runtime_with_static_work`].
#[cfg(all(any(test, feature = "test-h2-hooks"), target_os = "linux"))]
#[doc(hidden)]
pub struct TestAdvisoryKernelOverrideGuard {
    prev: u8,
}

#[cfg(all(any(test, feature = "test-h2-hooks"), target_os = "linux"))]
impl Drop for TestAdvisoryKernelOverrideGuard {
    fn drop(&mut self) {
        TEST_ADVISORY_KERNEL_IN_RANGE_OVERRIDE
            .store(self.prev, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Integration-test helper overriding [`host_kernel_in_h2_intask_range`] until drop.
#[cfg(all(any(test, feature = "test-h2-hooks"), target_os = "linux"))]
#[doc(hidden)]
#[must_use]
pub fn test_advisory_kernel_in_range_override_guard(
    in_range: Option<bool>,
) -> TestAdvisoryKernelOverrideGuard {
    let val = match in_range {
        Some(true) => 1,
        Some(false) => 2,
        None => 0,
    };
    let prev =
        TEST_ADVISORY_KERNEL_IN_RANGE_OVERRIDE.swap(val, std::sync::atomic::Ordering::Relaxed);
    TestAdvisoryKernelOverrideGuard { prev }
}

/// Conservative check for whether this host's Linux kernel release is in 5.12–6.11 (where BOTH
/// `openat2(RESOLVE_CACHED)` (5.12+) and I/O-free buffered `preadv2(RWF_NOWAIT)` (5.9–6.11) are
/// supported, matching `miraserve-static`'s `kernel_supports_h2_intask_static` gate).
#[cfg(target_os = "linux")]
fn host_kernel_in_h2_intask_range() -> bool {
    #[cfg(any(test, feature = "test-h2-hooks"))]
    match TEST_ADVISORY_KERNEL_IN_RANGE_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    cached_kernel_release().is_some_and(|v| ((5, 12)..(6, 12)).contains(&v))
}

#[cfg(not(target_os = "linux"))]
const fn host_kernel_in_h2_intask_range() -> bool {
    false
}

#[cfg(any(target_os = "linux", test))]
fn parse_kernel_release_major_minor(release: &[u8]) -> Option<(u32, u32)> {
    fn number(bytes: &[u8]) -> Option<(u32, &[u8])> {
        let digits = bytes.iter().take_while(|b| b.is_ascii_digit()).count();
        if digits == 0 || digits > 6 {
            return None;
        }
        let (head, rest) = bytes.split_at(digits);
        let value = std::str::from_utf8(head).ok()?.parse::<u32>().ok()?;
        Some((value, rest))
    }
    let (got_major, rest) = number(release)?;
    let rest = rest.strip_prefix(b".")?;
    let (got_minor, _) = number(rest)?;
    Some((got_major, got_minor))
}

#[cfg(test)]
fn kernel_release_in_range(
    release: &[u8],
    min_inclusive: (u32, u32),
    max_exclusive: (u32, u32),
) -> bool {
    parse_kernel_release_major_minor(release)
        .is_some_and(|v| (min_inclusive..max_exclusive).contains(&v))
}

/// Returns a single plain operator advisory when `config` enables `file-cache` (with a non-zero
/// `server.limits.file-cache-bytes` budget), non-`"shared"` `workers`, or an HTTP/2 listener with
/// static file work on a Linux 5.12–6.11 kernel, AND `openat2(2)` is refused with a recognised
/// errno (`ENOSYS`, `EPERM`, or `EACCES`) on this thread (or `RESOLVE_CACHED` is unsupported with
/// `EINVAL` on Linux 5.6–5.11 when `workers` would otherwise use it).
///
/// Used by standalone `miraserve check` (which installs no sandbox and cannot observe an
/// `ExecStart ... --no-sandbox` override in the systemd unit; any regeneration advice therefore
/// reminds the operator to confirm the effective worker command). Note that `miraserve check` run
/// from an interactive shell observes the shell's seccomp policy, whereas `ExecStartPre` observes
/// the systemd unit's policy.
///
/// Returns `None` when no affected feature is enabled, when no recognised refusal occurred
/// (including unrecognised filter errnos such as `EINVAL` on plain `openat2`), or on non-Linux
/// platforms.
#[must_use]
pub fn openat2_refused_advisory(config: &Config) -> Option<String> {
    let in_h2_intask_range = host_kernel_in_h2_intask_range();
    let has_static_work = config_has_static_work(config);
    if !config_needs_openat2(config, in_h2_intask_range, has_static_work) {
        return None;
    }
    let had_outer_seccomp = detect_seccomp_filter_active();
    if let Some((kind, err)) = probe_openat2_refusal_detail() {
        return format_openat2_refused_advisory_with_static_work(
            config,
            kind,
            &err,
            Openat2AdvisoryContext::StandaloneCheck,
            had_outer_seccomp,
            in_h2_intask_range,
            has_static_work,
        );
    }
    if probe_openat2_resolve_cached_unsupported() {
        return format_resolve_cached_unsupported_advisory_with_static_work(
            config,
            in_h2_intask_range,
            has_static_work,
        );
    }
    None
}

/// Runtime variant of [`openat2_refused_advisory`] that inspects the **actually installed**
/// [`SandboxReport`] (`None` when sandboxing was skipped via `--no-sandbox` /
/// `apply_sandbox: false`, or `Some(report)` after [`apply_sandbox`]) — rather than assuming
/// `config.server.sandbox.seccomp`, since an embedder can supply a prebuilt [`SandboxPolicy`] —
/// and whether an outer seccomp filter was already active on the probing thread *before*
/// MiraServe installed its own seccomp filter (`had_outer_seccomp`, captured via
/// [`detect_seccomp_filter_active`] before [`apply_sandbox`]).
///
/// Uses the kernel release cached before Landlock (via [`warm_kernel_release`]) rather than
/// re-reading `/proc` after sandboxing. Never recommends removing `RestrictSUIDSGID=yes` when the
/// kernel itself lacks `openat2` (`ENOSYS` with no outer filter attached), when the host kernel
/// is outside Linux 5.12–6.11 for HTTP/2 alone, when only `RESOLVE_CACHED` is missing (Linux
/// 5.6–5.11), or when MiraServe's in-process seccomp filter is not active (warning explicitly of
/// the disabled policy in both cases, including `ENOSYS` with no filter on a disabled policy).
#[must_use]
pub fn openat2_refused_advisory_for_runtime(
    config: &Config,
    sandbox_report: Option<&SandboxReport>,
    had_outer_seccomp: Option<bool>,
) -> Option<String> {
    openat2_refused_advisory_for_runtime_with_static_work(
        config,
        sandbox_report,
        had_outer_seccomp,
        config_has_static_work(config),
    )
}

/// Like [`openat2_refused_advisory_for_runtime`], using the caller's effective serving static-work
/// inventory (`has_static_work`, e.g. from `CompiledRouter::has_static_work()`) for the HTTP/2
/// condition so a quarantined tenant site whose static routes were excluded by the compiled router
/// never triggers an unnecessary `openat2(2)` probe at startup.
///
/// The independent `file-cache` and `workers` advisory conditions are unchanged.
#[must_use]
pub fn openat2_refused_advisory_for_runtime_with_static_work(
    config: &Config,
    sandbox_report: Option<&SandboxReport>,
    had_outer_seccomp: Option<bool>,
    has_static_work: bool,
) -> Option<String> {
    let in_h2_intask_range = host_kernel_in_h2_intask_range();
    if !config_needs_openat2(config, in_h2_intask_range, has_static_work) {
        return None;
    }
    if let Some((kind, err)) = probe_openat2_refusal_detail() {
        return format_openat2_refused_advisory_with_static_work(
            config,
            kind,
            &err,
            Openat2AdvisoryContext::Runtime(sandbox_report),
            had_outer_seccomp,
            in_h2_intask_range,
            has_static_work,
        );
    }
    if probe_openat2_resolve_cached_unsupported() {
        return format_resolve_cached_unsupported_advisory_with_static_work(
            config,
            in_h2_intask_range,
            has_static_work,
        );
    }
    None
}

fn config_uses_h2(config: &Config) -> bool {
    config
        .server
        .listeners
        .iter()
        .any(|l| !l.redirect_https && l.protocols.contains(&Protocol::H2))
}

/// Returns `true` when any non-quarantined configured site performs static file work (site
/// `root`, `ai-publish`, `static`, `try-files`, or `fastcgi` with a script `root`), excluding
/// quarantined tenant sites, `acme-webroot` (which uses `openat` off the event loop), and
/// compile-time `error-pages`.
#[must_use]
pub fn config_has_static_work(config: &Config) -> bool {
    config.sites.iter().any(|site| {
        site.quarantine.is_none()
            && (site.root.is_some()
                || site.ai_publish.is_some()
                || site.routes.iter().any(|route| {
                    matches!(
                        route.handler,
                        RouteHandler::Static(_) | RouteHandler::TryFiles(_)
                    ) || (matches!(route.handler, RouteHandler::FastCgi(_)) && route.root.is_some())
                }))
    })
}

fn config_needs_openat2(
    config: &Config,
    kernel_in_h2_intask_range: bool,
    has_static_work: bool,
) -> bool {
    let uses_file_cache = config.server.limits.file_cache_bytes.as_bytes() > 0
        && config.sites.iter().any(|s| s.file_cache.is_some());
    let uses_workers = config.server.workers != Workers::Shared;
    let uses_h2_intask = kernel_in_h2_intask_range && config_uses_h2(config) && has_static_work;
    uses_file_cache || uses_workers || uses_h2_intask
}

/// Severity for a runtime `openat2(2)` refusal startup advisory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Openat2AdvisoryLevel {
    /// No explicitly requested feature (`file-cache` with a non-zero budget, or non-`"shared"`
    /// `workers`) is degraded; only the opportunistic Linux 5.12–6.11 in-task HTTP/2 mode falls
    /// back to spawned streams.
    Info,
    /// An explicitly requested feature (`file-cache` with a non-zero budget, or non-`"shared"`
    /// `workers`) is degraded by the `openat2(2)` refusal.
    Warn,
}

/// Returns the runtime startup log level for an `openat2(2)` refusal advisory on `config`:
/// [`Openat2AdvisoryLevel::Warn`] when the loaded configuration asks for a feature degraded by
/// the refusal (any site with `file-cache` other than `"off"` while `server.limits.file-cache-bytes`
/// is non-zero, or `server.workers` other than `"shared"`), and [`Openat2AdvisoryLevel::Info`]
/// otherwise.
#[must_use]
pub fn openat2_refusal_advisory_level(config: &Config) -> Openat2AdvisoryLevel {
    let uses_file_cache = config.server.limits.file_cache_bytes.as_bytes() > 0
        && config.sites.iter().any(|s| s.file_cache.is_some());
    let uses_workers = config.server.workers != Workers::Shared;
    if uses_file_cache || uses_workers {
        Openat2AdvisoryLevel::Warn
    } else {
        Openat2AdvisoryLevel::Info
    }
}

#[cfg(test)]
fn format_resolve_cached_unsupported_advisory(
    config: &Config,
    kernel_in_h2_intask_range: bool,
) -> Option<String> {
    format_resolve_cached_unsupported_advisory_with_static_work(
        config,
        kernel_in_h2_intask_range,
        config_has_static_work(config),
    )
}

fn format_resolve_cached_unsupported_advisory_with_static_work(
    config: &Config,
    kernel_in_h2_intask_range: bool,
    has_static_work: bool,
) -> Option<String> {
    let uses_workers = config.server.workers != Workers::Shared;
    let uses_h2_intask = kernel_in_h2_intask_range && config_uses_h2(config) && has_static_work;
    let impact = match (uses_workers, uses_h2_intask) {
        (true, true) => {
            "worker loops will not look up static files inline and static HTTP/2 streams will run \
             as separate tasks instead of in-task"
        }
        (true, false) => "worker loops will not look up static files inline",
        (false, true) => "static HTTP/2 streams will run as separate tasks instead of in-task",
        (false, false) => return None,
    };
    Some(format!(
        "openat2 RESOLVE_CACHED is not supported by this kernel (requires Linux 5.12+): {impact}; \
         upgrade the host kernel to Linux 5.12+ — regenerating the systemd unit cannot help"
    ))
}

fn disabled_seccomp_reason(
    config: &Config,
    ctx: Openat2AdvisoryContext<'_>,
) -> Option<&'static str> {
    match ctx {
        Openat2AdvisoryContext::StandaloneCheck => (config.server.sandbox.seccomp
            == SeccompMode::Off)
            .then_some("server.sandbox.seccomp \"off\""),
        Openat2AdvisoryContext::Runtime(None) => {
            if config.server.sandbox.seccomp == SeccompMode::Off {
                Some("--no-sandbox and server.sandbox.seccomp \"off\"")
            } else {
                Some("--no-sandbox")
            }
        }
        Openat2AdvisoryContext::Runtime(Some(report)) => {
            if matches!(
                report.seccomp,
                EnforcementStatus::Enforced | EnforcementStatus::PartiallyEnforced
            ) {
                None
            } else if config.server.sandbox.seccomp == SeccompMode::Off {
                Some("server.sandbox.seccomp \"off\"")
            } else {
                Some("the installed sandbox policy (seccomp disabled)")
            }
        }
    }
}

#[cfg(test)]
fn format_openat2_refused_advisory(
    config: &Config,
    kind: Openat2RefusalKind,
    err: &str,
    ctx: Openat2AdvisoryContext<'_>,
    had_outer_seccomp: Option<bool>,
    kernel_in_h2_intask_range: bool,
) -> Option<String> {
    format_openat2_refused_advisory_with_static_work(
        config,
        kind,
        err,
        ctx,
        had_outer_seccomp,
        kernel_in_h2_intask_range,
        config_has_static_work(config),
    )
}

fn format_openat2_refused_advisory_with_static_work(
    config: &Config,
    kind: Openat2RefusalKind,
    err: &str,
    ctx: Openat2AdvisoryContext<'_>,
    had_outer_seccomp: Option<bool>,
    kernel_in_h2_intask_range: bool,
    has_static_work: bool,
) -> Option<String> {
    let uses_file_cache = config.server.limits.file_cache_bytes.as_bytes() > 0
        && config.sites.iter().any(|s| s.file_cache.is_some());
    let uses_workers = config.server.workers != Workers::Shared;
    let uses_h2_intask = kernel_in_h2_intask_range && config_uses_h2(config) && has_static_work;
    let impact = match (uses_file_cache, uses_workers, uses_h2_intask) {
        (true, true, true) => {
            "file-cache will store nothing, worker loops will not look up static files inline, \
             and static HTTP/2 streams will run as separate tasks instead of in-task"
        }
        (true, true, false) => {
            "file-cache will store nothing and worker loops will not look up static files inline"
        }
        (true, false, true) => {
            "file-cache will store nothing and static HTTP/2 streams will run as separate tasks \
             instead of in-task"
        }
        (true, false, false) => "file-cache will store nothing",
        (false, true, true) => {
            "worker loops will not look up static files inline and static HTTP/2 streams will run \
             as separate tasks instead of in-task"
        }
        (false, true, false) => "worker loops will not look up static files inline",
        (false, false, true) => {
            "static HTTP/2 streams will run as separate tasks instead of in-task"
        }
        (false, false, false) => return None,
    };

    let disabled_by = disabled_seccomp_reason(config, ctx);
    let kernel_lacks_openat2 =
        kind == Openat2RefusalKind::NoSys && had_outer_seccomp == Some(false);

    if let Some(disabled_by) = disabled_by {
        if kernel_lacks_openat2 {
            return Some(format!(
                "openat2 is not supported by this kernel ({err}; no seccomp filter is attached \
                 to this thread, so the host kernel is older than Linux 5.6): {impact}; upgrade \
                 the host kernel to Linux 5.6+ (5.12+ for inline worker lookups) — regenerating \
                 the systemd unit cannot help; additionally, do NOT remove RestrictSUIDSGID=yes \
                 while {disabled_by} is in effect, because the unit without that line would have \
                 NO set-ID protection — re-enable seccomp \"strict\" or \"standard\" (and remove \
                 --no-sandbox) before ever allowing openat2"
            ));
        }
        let cause = match kind {
            Openat2RefusalKind::NoSys => {
                "a system-call filter such as systemd RestrictSUIDSGID=yes / \
                 DefaultRestrictSUIDSGID=yes, an outer container seccomp profile, or a kernel \
                 older than 5.6"
            }
            Openat2RefusalKind::Perm | Openat2RefusalKind::Access => {
                "an outer system-call filter such as a container seccomp profile or custom policy"
            }
        };
        return Some(format!(
            "openat2 is refused in this process ({err}; {cause}): {impact}; do NOT remove \
             RestrictSUIDSGID=yes while {disabled_by} is in effect, because the unit without that \
             line would have NO set-ID protection — re-enable seccomp \"strict\" or \"standard\" \
             (and remove --no-sandbox) before allowing openat2 in systemd or an outer container \
             seccomp profile (or upgrade to Linux 5.6+ if the kernel lacks openat2)"
        ));
    }

    // ENOSYS with confirmed `Seccomp: 0` on the probing thread: the kernel itself lacks `openat2`
    // (< Linux 5.6). Regenerating the systemd unit cannot help.
    if kernel_lacks_openat2 {
        return Some(format!(
            "openat2 is not supported by this kernel ({err}; no seccomp filter is attached to \
             this thread, so the host kernel is older than Linux 5.6): {impact}; upgrade the \
             host kernel to Linux 5.6+ (5.12+ for inline worker lookups) — regenerating the \
             systemd unit cannot help"
        ));
    }

    let check_confirm = match ctx {
        Openat2AdvisoryContext::StandaloneCheck => {
            " after confirming the effective worker ExecStart command does not pass --no-sandbox \
             and keeps in-process seccomp active"
        }
        Openat2AdvisoryContext::Runtime(_) => "",
    };

    match kind {
        Openat2RefusalKind::NoSys => Some(format!(
            "openat2 is refused in this process ({err}; either a system-call filter such as \
             systemd RestrictSUIDSGID=yes / DefaultRestrictSUIDSGID=yes or an outer container \
             seccomp profile, or a kernel older than 5.6): {impact}; if blocked by systemd \
             RestrictSUIDSGID=yes, regenerate the worker unit with `miraserve service generate \
             --target systemd --allow-openat2`{check_confirm} (or set `RestrictSUIDSGID=no` if \
             systemd 258+ enables `DefaultRestrictSUIDSGID=yes`); if blocked by a container or \
             outer seccomp profile, allow openat2 there; if the host kernel is older than 5.6, \
             upgrade the kernel (regenerating the unit cannot help)"
        )),
        Openat2RefusalKind::Perm | Openat2RefusalKind::Access => Some(format!(
            "openat2 is refused in this process ({err}; blocked by an outer system-call filter \
             such as a container seccomp profile or custom policy): {impact}; allow openat2 in \
             the outer seccomp profile (if running under systemd RestrictSUIDSGID=yes, regenerate \
             the worker unit with `miraserve service generate --target systemd --allow-openat2`\
             {check_confirm})"
        )),
    }
}

/// Applies the derived OS confinement policy to the current worker process.
///
/// # Errors
/// Returns [`SandboxError`] if root privileges remain active when `sandbox.user`/`group` is
/// configured, or if Linux kernel confinement fails when explicitly enabled.
pub fn apply_sandbox(policy: &SandboxPolicy) -> Result<SandboxReport, SandboxError> {
    let mut notes = Vec::new();
    let (uid, gid) = if policy.user.is_some() || policy.group.is_some() {
        detect_current_uid_gid()
    } else {
        (None, None)
    };
    #[cfg(unix)]
    let expected_user = match &policy.user {
        Some(u) => Some(resolve_unix_user_uid_from_passwd(u)?),
        None => None,
    };
    #[cfg(not(unix))]
    let expected_user: Option<u32> = None;

    #[cfg(unix)]
    let expected_group = match &policy.group {
        Some(g) => Some(resolve_unix_group_gid_from_etc_group(g)?),
        None => None,
    };
    #[cfg(not(unix))]
    let expected_group: Option<u32> = None;

    if let Some(priv_note) =
        verify_privilege_state_with_expected(policy, uid, gid, expected_user, expected_group)?
    {
        notes.push(priv_note);
    }

    // R4-SBX-1 & R4-SBX-2: Always surface policy warnings and exact-file Landlock fallbacks!
    for w in &policy.warnings {
        notes.push(w.clone());
    }
    if policy.landlock {
        for fb in &policy.exact_file_fallbacks {
            notes.push(format!(
                "Landlock granted exact-file access to '{}' (parent directory could not be safely widened); \
                 atomic-rename updates before SIGHUP reload require moving this file into a dedicated subdirectory (e.g. /etc/miraserve/conf/) or restarting",
                fb.display()
            ));
        }
    }

    #[cfg(target_os = "linux")]
    {
        linux::apply_linux_sandbox(policy, notes)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let landlock = if policy.landlock {
            notes.push(format!(
                "Landlock LSM is Linux-only (running on {}); cap-std document-root confinement remains active",
                std::env::consts::OS
            ));
            EnforcementStatus::UnsupportedPlatform
        } else {
            EnforcementStatus::Disabled
        };

        let seccomp = match policy.seccomp {
            SeccompMode::Off => EnforcementStatus::Disabled,
            SeccompMode::Strict | SeccompMode::Standard => {
                notes.push(format!(
                    "seccomp-bpf is Linux-only (running on {})",
                    std::env::consts::OS
                ));
                EnforcementStatus::UnsupportedPlatform
            }
        };

        info!(
            platform = std::env::consts::OS,
            ro_paths = policy.read_only_paths.len(),
            rw_paths = policy.read_write_paths.len(),
            socket_paths = policy.socket_paths.len(),
            "sandbox policy evaluated (non-Linux host)"
        );

        Ok(SandboxReport {
            platform: std::env::consts::OS,
            landlock,
            seccomp,
            read_only_path_count: policy.read_only_paths.len(),
            read_write_path_count: policy.read_write_paths.len(),
            socket_path_count: policy.socket_paths.len(),
            notes,
        })
    }
}

/// Returns the list of dangerous Linux syscall names blocked by each [`SeccompMode`]
/// (available cross-platform for documentation, auditing, and testing).
#[must_use]
pub fn blocked_syscalls_for_mode(mode: SeccompMode) -> &'static [&'static str] {
    match mode {
        SeccompMode::Off => &[],
        SeccompMode::Standard => &[
            "ptrace",
            "mount",
            "umount2",
            "pivot_root",
            "chroot",
            "kexec_load",
            "init_module",
            "finit_module",
            "delete_module",
            "reboot",
            "bpf",
            // Denied in Standard as well as Strict as part of the set-ID policy: io_uring
            // operations (IORING_OP_OPENAT, IORING_OP_OPENAT2, IORING_OP_MKDIRAT) run inside
            // the kernel past every scalar seccomp rule, and MiraServe's standing policy keeps
            // io_uring blocked.
            "io_uring_setup",
            "io_uring_enter",
            "io_uring_register",
        ],
        SeccompMode::Strict => &[
            "execve",
            "execveat",
            "ptrace",
            "mount",
            "umount2",
            "pivot_root",
            "chroot",
            "kexec_load",
            "kexec_file_load",
            "init_module",
            "finit_module",
            "delete_module",
            "reboot",
            "bpf",
            "swapon",
            "swapoff",
            "perf_event_open",
            "userfaultfd",
            "unshare",
            "setns",
            "process_vm_readv",
            "process_vm_writev",
            "add_key",
            "request_key",
            "keyctl",
            "io_uring_setup",
            "io_uring_enter",
            "io_uring_register",
            "open_tree",
            "move_mount",
            "fsopen",
            "fsconfig",
            "fsmount",
            "fspick",
        ],
    }
}

/// Returns the list of Linux syscall names conditionally filtered against `S_ISUID` (`0o4000`)
/// and `S_ISGID` (`0o2000`) mode bits by each [`SeccompMode`] (available cross-platform for
/// documentation, auditing, and testing).
///
/// Legacy non-`*at` syscalls (`chmod`, `mkdir`, `mknod`, `creat`, `open`) are installed on
/// architectures whose kernel ABI provides them (`x86_64`, including `x32` aliases) and omitted on
/// `asm-generic` architectures (`aarch64`, `riscv64`) where those syscall numbers do not exist.
///
/// [`SeccompMode::Off`] installs no seccomp-bpf filter at all (neither the unconditional denylist
/// nor these set-ID rules).
#[must_use]
pub fn setid_filtered_syscalls_for_mode(mode: SeccompMode) -> &'static [&'static str] {
    match mode {
        SeccompMode::Off => &[],
        SeccompMode::Standard | SeccompMode::Strict => &[
            "chmod",
            "fchmod",
            "fchmodat",
            "fchmodat2",
            "mkdir",
            "mkdirat",
            "mknod",
            "mknodat",
            "creat",
            "open",
            "openat",
            "mq_open",
        ],
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::{BTreeMap, BTreeSet};

    use landlock::{
        ABI, Access as _, AccessFs, BitFlags, LandlockStatus, PathBeneath, RestrictSelf, Ruleset,
        RulesetAttr as _, RulesetCreated, RulesetCreatedAttr as _, RulesetStatus,
    };
    use miraserve_config::SeccompMode;
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule, TargetArch,
    };
    use tracing::{info, warn};

    use crate::{
        EnforcementStatus, LANDLOCK_TARGET_ABI_VERSION, SandboxError, SandboxPolicy, SandboxReport,
    };

    /// Landlock ABI targeted by [`apply_landlock`]; must stay aligned with
    /// [`LANDLOCK_TARGET_ABI_VERSION`].
    const LANDLOCK_TARGET_ABI: ABI = ABI::V5;
    const _: () = assert!(LANDLOCK_TARGET_ABI as u32 == LANDLOCK_TARGET_ABI_VERSION);

    /// Query-only Landlock availability probe (no ruleset, no `PR_SET_NO_NEW_PRIVS`).
    #[must_use]
    pub fn probe_landlock_availability() -> crate::LandlockProbe {
        use crate::LandlockProbe as P;
        match RestrictSelf::default().no_new_privs(false).apply() {
            Err(e) => P::ProbeError(e.to_string()),
            Ok(s) => match s.landlock {
                LandlockStatus::NotEnabled => P::Disabled,
                LandlockStatus::NotImplemented => P::NotImplemented,
                LandlockStatus::Available {
                    effective_abi: e,
                    kernel_abi: k,
                } => match k.unwrap_or(e as i32) {
                    v if v >= 1 => P::Available(v.cast_unsigned()),
                    v => P::ProbeError(format!("unexpected Landlock ABI {v}")),
                },
            },
        }
    }

    pub(crate) fn probe_host_landlock_abi() -> Option<u32> {
        probe_landlock_availability().available_abi()
    }

    const LINUX_EPERM: u32 = 1;
    /// POSIX set-user-ID bit (`S_ISUID = 0o4000`, bit 11 in `umode_t`).
    const LINUX_S_ISUID: u64 = 0o4000;
    /// POSIX set-group-ID bit (`S_ISGID = 0o2000`, bit 10 in `umode_t`).
    const LINUX_S_ISGID: u64 = 0o2000;
    /// Linux `O_CREAT` (`0o100` on `x86_64`, `aarch64`, and `riscv64`).
    const LINUX_O_CREAT: u64 = 0o100;
    /// Linux `O_PATH` (`0o10000000` / `0x200000` on `x86_64`, `aarch64`, and `riscv64`).
    ///
    /// When `O_PATH` is set on `open(2)` or `openat(2)`, Linux `build_open_flags()` discards all
    /// creation flags (`O_CREAT`, `O_TMPFILE`) and never creates an inode, so `O_PATH` opens are
    /// excluded from the `open`/`openat` set-ID creation rules to avoid false positives.
    const LINUX_O_PATH: u64 = 0o1000_0000;
    /// Linux `__O_TMPFILE` (`0o20000000` on `x86_64`, `aarch64`, and `riscv64`).
    const LINUX_INTERNAL_O_TMPFILE: u64 = 0o2000_0000;
    /// `x32` ABI syscall bit on `x86_64` (`__X32_SYSCALL_BIT`).
    const X32_SYSCALL_BIT: i64 = 0x4000_0000;
    /// `io_uring_setup` (425), `io_uring_enter` (426), and `io_uring_register` (427) — identical
    /// syscall numbers on `x86_64` (common/`x32`), `aarch64`, and `riscv64`.
    ///
    /// These belong to the set-ID policy in BOTH `Standard` and `Strict` modes: a ring can submit
    /// `IORING_OP_OPENAT`, `IORING_OP_OPENAT2`, and `IORING_OP_MKDIRAT` inside the kernel past
    /// every scalar seccomp argument check, even when direct `openat2` is filtered separately.
    /// MiraServe's standing policy keeps `io_uring` blocked, and neither MiraServe nor its
    /// dependencies (`tokio` without `io-uring`, `wasmtime`, `rustls`, `hyper`, `quinn`) use it.
    const SETID_IO_URING_SYSCALLS: &[i64] = &[425, 426, 427];

    /// Returns the architecture-specific `O_TMPFILE = __O_TMPFILE | O_DIRECTORY` value.
    ///
    /// On Linux, `O_DIRECTORY` is `0o200000` (`0x10000`) on `x86_64` and `riscv64`, but `0o40000`
    /// (`0x4000`) on `aarch64`. The kernel rejects bare `__O_TMPFILE` without `O_DIRECTORY` with
    /// `EINVAL`, so matching `O_TMPFILE` matches every valid temporary-file creation while never
    /// matching ordinary `O_DIRECTORY` opens.
    const fn o_tmpfile_for_arch(arch: TargetArch) -> u64 {
        let o_directory = match arch {
            TargetArch::x86_64 | TargetArch::riscv64 => 0o20_0000,
            TargetArch::aarch64 => 0o4_0000,
        };
        LINUX_INTERNAL_O_TMPFILE | o_directory
    }

    #[derive(Clone, Copy)]
    enum SetIdRuleKind {
        /// Unconditionally inspect `mode_arg` (`umode_t` in low 32 bits) for `S_ISUID` or `S_ISGID`.
        Mode { mode_arg: u8 },
        /// Inspect `mode_arg` when `flags_arg` has `O_CREAT` set (`mq_open`).
        CreateMode { flags_arg: u8, mode_arg: u8 },
        /// Inspect `mode_arg` when `flags_arg` has `O_CREAT` or `O_TMPFILE` set (`open`, `openat`).
        OpenCreateMode { flags_arg: u8, mode_arg: u8 },
    }

    #[derive(Clone, Copy)]
    struct SetIdSyscallSpec {
        nr: i64,
        kind: SetIdRuleKind,
    }

    pub(crate) fn apply_linux_sandbox(
        policy: &SandboxPolicy,
        mut notes: Vec<String>,
    ) -> Result<SandboxReport, SandboxError> {
        let landlock_status = if policy.landlock {
            apply_landlock(policy, &mut notes)?
        } else {
            EnforcementStatus::Disabled
        };

        let seccomp_status = match policy.seccomp {
            SeccompMode::Off => EnforcementStatus::Disabled,
            mode => apply_seccomp(mode)?,
        };

        info!(
            landlock = ?landlock_status,
            seccomp = ?seccomp_status,
            ro_paths = policy.read_only_paths.len(),
            rw_paths = policy.read_write_paths.len(),
            socket_paths = policy.socket_paths.len(),
            "Linux kernel sandbox applied"
        );

        Ok(SandboxReport {
            platform: "linux",
            landlock: landlock_status,
            seccomp: seccomp_status,
            read_only_path_count: policy.read_only_paths.len(),
            read_write_path_count: policy.read_write_paths.len(),
            socket_path_count: policy.socket_paths.len(),
            notes,
        })
    }

    /// Whether `path` lies strictly inside a directory of `list` whose grant is installed.
    fn covered_by_installed_tree(
        policy: &SandboxPolicy,
        path: &std::path::Path,
        list: &[std::path::PathBuf],
    ) -> bool {
        list.iter().any(|tree| {
            tree != path
                && path.starts_with(tree)
                && matches!(
                    policy.grant_states.get(tree),
                    Some(super::GrantState::Installed { is_dir: true, .. })
                )
        })
    }

    /// Every worker thread installs the same policy; report each missing-path notice once per
    /// process instead of once per thread.
    pub(super) fn first_time_reported(key: &str) -> bool {
        static REPORTED: std::sync::Mutex<std::collections::BTreeSet<String>> =
            std::sync::Mutex::new(std::collections::BTreeSet::new());
        REPORTED
            .lock()
            .map_or(true, |mut seen| seen.insert(key.to_owned()))
    }

    pub(super) struct AssembledLandlockRules<'a> {
        pub(super) all_abi: BitFlags<AccessFs>,
        pub(super) read_only_access: BitFlags<AccessFs>,
        pub(super) read_write_access: BitFlags<AccessFs>,
        pub(super) readonly_rules: Vec<(&'a std::os::fd::OwnedFd, BitFlags<AccessFs>)>,
        pub(super) writable_rules: Vec<(&'a std::os::fd::OwnedFd, BitFlags<AccessFs>)>,
        pub(super) sock_rules: Vec<(&'a std::os::fd::OwnedFd, BitFlags<AccessFs>)>,
    }

    #[allow(clippy::too_many_lines)]
    pub(super) fn assemble_landlock_rules<'a>(
        policy: &'a SandboxPolicy,
        notes: &mut Vec<String>,
    ) -> Result<AssembledLandlockRules<'a>, SandboxError> {
        let abi = LANDLOCK_TARGET_ABI;
        let all_abi = AccessFs::from_all(abi);
        // Strip Execute and device/FIFO/symlink-creation rights from data and socket rules.
        let read_only_access = (AccessFs::ReadFile | AccessFs::ReadDir) & all_abi;
        let read_file_access = read_only_access & AccessFs::ReadFile;
        let read_write_access = (AccessFs::ReadFile
            | AccessFs::ReadDir
            | AccessFs::WriteFile
            | AccessFs::Truncate
            | AccessFs::MakeReg
            | AccessFs::MakeDir
            | AccessFs::RemoveFile
            | AccessFs::RemoveDir
            | AccessFs::Refer)
            & all_abi;
        let read_write_file_access =
            read_write_access & (AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::Truncate);
        let sock_access = (AccessFs::ReadFile | AccessFs::WriteFile) & all_abi;

        policy.verify_pinned_writable_dirs()?;

        let pinned_rw_paths: BTreeSet<&std::path::Path> = policy
            .pinned_read_write_dirs
            .iter()
            .map(|d| d.path.as_path())
            .collect();
        let tenant_pinned_paths: BTreeSet<&std::path::Path> = policy
            .pinned_read_only_paths
            .iter()
            .map(|p| p.path.as_path())
            .collect();

        // Codex Round-10 P2: refuse a policy whose public path lists were edited without
        // `finalize_grants()` or whose grant could not be opened/validated, instead of silently
        // omitting the grant from the installed ruleset.
        let mut unfinalized: Vec<String> = Vec::new();
        let mut failed: Vec<String> = Vec::new();
        for p in policy
            .read_only_paths
            .iter()
            .chain(policy.read_write_paths.iter())
            .chain(policy.socket_paths.iter())
        {
            if pinned_rw_paths.contains(p.as_path()) || tenant_pinned_paths.contains(p.as_path()) {
                continue;
            }
            match policy.grant_states.get(p) {
                None => unfinalized.push(p.display().to_string()),
                Some(super::GrantState::Failed { reason, .. }) => {
                    failed.push(format!("'{}': {reason}", p.display()));
                }
                Some(_) => {}
            }
        }
        if !unfinalized.is_empty() {
            return Err(SandboxError::Landlock(format!(
                "sandbox policy path(s) were added after construction without finalization: {}; call SandboxPolicy::finalize_grants() before installing the policy",
                unfinalized.join(", ")
            )));
        }
        // Codex Round-11 P2: a pinned handle must still be requested with its access class;
        // otherwise installing the pin would grant a permission the public lists no longer ask
        // for (e.g. a rotating-log directory removed from, or downgraded out of, the RW list).
        let orphan_pins: Vec<String> = policy
            .pinned_read_write_dirs
            .iter()
            .filter(|pin| {
                !policy
                    .read_write_paths
                    .iter()
                    .any(|p| super::normalized_paths_equal(p, &pin.path))
            })
            .map(|pin| format!("{} (read-write)", pin.path.display()))
            .chain(
                policy
                    .pinned_read_only_paths
                    .iter()
                    .filter(|pin| !policy.read_only_paths.iter().any(|p| p == &pin.path))
                    .map(|pin| format!("{} (read-only)", pin.path.display())),
            )
            .collect();
        if !orphan_pins.is_empty() {
            return Err(SandboxError::Landlock(format!(
                "pinned sandbox grant(s) no longer requested by the policy path lists: {}; call SandboxPolicy::finalize_grants() after editing the lists",
                orphan_pins.join(", ")
            )));
        }
        if !failed.is_empty() {
            return Err(SandboxError::Landlock(format!(
                "sandbox grant(s) could not be opened or validated: {}",
                failed.join("; ")
            )));
        }

        // Codex Round-9 P2: install EVERY grant directly from the `O_PATH` descriptor finalized
        // into `policy.grant_states` (from which reload identities were `fstat`-ed), never
        // reopening pathnames per thread or letting `path_beneath_rules` silently skip errors.
        let mut writable_rules: Vec<(&std::os::fd::OwnedFd, BitFlags<AccessFs>)> =
            Vec::with_capacity(policy.read_write_paths.len());
        let mut missing_writable: Vec<String> = Vec::new();
        for p in &policy.read_write_paths {
            if pinned_rw_paths.contains(p.as_path()) {
                continue;
            }
            match policy.grant_states.get(p) {
                Some(super::GrantState::Installed { fd, is_dir, .. }) => {
                    let access = if *is_dir {
                        read_write_access
                    } else {
                        read_write_file_access
                    };
                    writable_rules.push((fd.as_ref(), access));
                }
                Some(super::GrantState::AbsentAtStartup | super::GrantState::Failed { .. })
                | None => {
                    missing_writable.push(p.display().to_string());
                }
            }
        }
        if !missing_writable.is_empty() {
            return Err(SandboxError::Landlock(format!(
                "required read-write Landlock directory does not exist at thread start: {} (R2-SBX-1)",
                missing_writable.join(", ")
            )));
        }

        let mut readonly_rules: Vec<(&std::os::fd::OwnedFd, BitFlags<AccessFs>)> =
            Vec::with_capacity(policy.read_only_paths.len());
        let mut missing_readonly: Vec<String> = Vec::new();
        for p in &policy.read_only_paths {
            if tenant_pinned_paths.contains(p.as_path()) {
                // Codex Round-5 P1 #2: installed below from the validated handle.
                continue;
            }
            match policy.grant_states.get(p) {
                Some(super::GrantState::Installed { fd, is_dir, .. }) => {
                    let access = if *is_dir {
                        read_only_access
                    } else {
                        read_file_access
                    };
                    readonly_rules.push((fd.as_ref(), access));
                }
                Some(super::GrantState::AbsentAtStartup | super::GrantState::Failed { .. })
                | None => {
                    if !covered_by_installed_tree(policy, p, &policy.read_only_paths) {
                        missing_readonly.push(p.display().to_string());
                    }
                }
            }
        }
        if !missing_readonly.is_empty() {
            let joined = missing_readonly.join(", ");
            if first_time_reported(&format!("ro:{joined}")) {
                warn!(
                    missing_ro = %joined,
                    "configured Landlock read-only path(s) do not exist at startup and cannot be granted until restart"
                );
            }
            notes.push(format!(
                "missing Landlock read-only path(s) omitted at startup (restart after creating): {joined}"
            ));
        }

        let mut sock_rules: Vec<(&std::os::fd::OwnedFd, BitFlags<AccessFs>)> =
            Vec::with_capacity(policy.socket_paths.len());
        let mut missing_socks: Vec<String> = Vec::new();
        for p in &policy.socket_paths {
            match policy.grant_states.get(p) {
                Some(super::GrantState::Installed { fd, file_type, .. }) => {
                    if *file_type == rustix::fs::FileType::Socket
                        || (*file_type == rustix::fs::FileType::Directory
                            && policy.socket_tree_paths.contains(p))
                    {
                        sock_rules.push((fd.as_ref(), sock_access));
                    } else if policy.socket_shadows_other_class.contains(p) {
                        let display_path = super::sanitize_path_for_display(p);
                        let found = super::linux_file_type_label(*file_type);
                        if *file_type == rustix::fs::FileType::Directory {
                            sock_rules.push((fd.as_ref(), sock_access));
                            if first_time_reported(&format!(
                                "sock-shadow-not-socket:{}",
                                p.display()
                            )) {
                                warn!(
                                    path = %display_path,
                                    found,
                                    "unix socket path '{display_path}' is not a socket (found {found}) and the same path is also configured as a directory grant: the 0.1.5 access rule is kept; give the socket its own path"
                                );
                            }
                        } else {
                            sock_rules.push((fd.as_ref(), read_file_access));
                            if first_time_reported(&format!(
                                "sock-shadow-not-socket:{}",
                                p.display()
                            )) {
                                warn!(
                                    path = %display_path,
                                    found,
                                    "unix socket path '{display_path}' is not a socket (found {found}) and the same path is configured for another use: its socket rule is reduced to read access; give the socket its own path"
                                );
                            }
                        }
                    } else {
                        let display_path = super::sanitize_path_for_display(p);
                        let found = super::linux_file_type_label(*file_type);
                        if first_time_reported(&format!("sock-not-socket:{}", p.display())) {
                            warn!(
                                path = %display_path,
                                found,
                                "exact unix socket path '{display_path}' is not a socket (found {found}): no socket rule installed for it; FastCGI or keyd requests to it fail while it is not a socket"
                            );
                        }
                    }
                }
                Some(super::GrantState::AbsentAtStartup | super::GrantState::Failed { .. })
                | None => {
                    // A socket that does not exist yet but lies inside an installed tree (a
                    // `socket-tree`) is reachable as soon as it is created: nothing to warn about.
                    if !covered_by_installed_tree(policy, p, &policy.socket_paths) {
                        missing_socks.push(p.display().to_string());
                    }
                }
            }
        }
        if !missing_socks.is_empty() {
            let joined = missing_socks.join(", ");
            if first_time_reported(&format!("sock:{joined}")) {
                warn!(
                    missing_sockets = %joined,
                    "configured Landlock Unix socket path(s) do not exist at startup and cannot be granted until restart"
                );
            }
            notes.push(format!(
                "missing Landlock Unix socket path(s) omitted at startup (restart after creating): {joined}"
            ));
        }

        Ok(AssembledLandlockRules {
            all_abi,
            read_only_access,
            read_write_access,
            readonly_rules,
            writable_rules,
            sock_rules,
        })
    }

    pub(crate) fn apply_landlock(
        policy: &SandboxPolicy,
        notes: &mut Vec<String>,
    ) -> Result<EnforcementStatus, SandboxError> {
        let AssembledLandlockRules {
            all_abi,
            read_only_access,
            read_write_access,
            readonly_rules,
            writable_rules,
            sock_rules,
        } = assemble_landlock_rules(policy, notes)?;

        let mut ruleset = Ruleset::default()
            .handle_access(all_abi)
            .map_err(|err| SandboxError::Landlock(err.to_string()))?
            .create()
            .map_err(|err| SandboxError::Landlock(err.to_string()))?;
        for (fd, access) in readonly_rules
            .into_iter()
            .chain(writable_rules)
            .chain(sock_rules)
        {
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, access))
                .map_err(|err| SandboxError::Landlock(err.to_string()))?;
        }

        let ruleset = add_pinned_rules(ruleset, policy, read_write_access, read_only_access)?;

        let status = ruleset
            .restrict_self()
            .map_err(|err| SandboxError::Landlock(err.to_string()))?;

        match status.ruleset {
            RulesetStatus::FullyEnforced => Ok(EnforcementStatus::Enforced),
            RulesetStatus::PartiallyEnforced => {
                notes.push(
                    "Landlock partially enforced: this kernel is older than Landlock ABI 5 (Linux 6.10). \
                     On ABI 1 (Linux 5.13-5.18), cross-directory rename/link is denied (ABI 2 added Refer \
                     to allow it) and file truncation is not restricted; on ABI 2 (Linux 5.19-6.1), file \
                     truncation is not restricted; on ABI 3-4 (Linux 6.2-6.9), all file \
                     read/write/truncate/execute rules are enforced and only device ioctl (ABI 5) is not"
                        .to_owned(),
                );
                Ok(EnforcementStatus::PartiallyEnforced)
            }
            RulesetStatus::NotEnforced => Err(SandboxError::Landlock(
                "kernel does not support Landlock LSM while sandbox.landlock=true (disable via 'landlock false' or --no-sandbox to run unconfined)".to_owned(),
            )),
        }
    }

    /// Installs Landlock rules for pinned handles directly from their validated descriptors
    /// (`AsFd`) instead of reopening pathnames: rotating-log directories (Codex G7 P1) and tenant
    /// files validated with the loaders' no-follow rule (Codex Round-5 P1 #2), so a later symlink
    /// swap cannot redirect a grant to an unrelated directory.
    fn add_pinned_rules(
        mut ruleset: RulesetCreated,
        policy: &SandboxPolicy,
        read_write_access: BitFlags<AccessFs>,
        read_only_access: BitFlags<AccessFs>,
    ) -> Result<RulesetCreated, SandboxError> {
        for pinned in &policy.pinned_read_write_dirs {
            ruleset = ruleset
                .add_rule(PathBeneath::new(&*pinned.file, read_write_access))
                .map_err(|err| SandboxError::Landlock(err.to_string()))?;
        }
        let read_file_access = read_only_access & AccessFs::ReadFile;
        for pinned in &policy.pinned_read_only_paths {
            let access = if pinned.is_dir {
                read_only_access
            } else {
                read_file_access
            };
            ruleset = ruleset
                .add_rule(PathBeneath::new(&*pinned.file, access))
                .map_err(|err| SandboxError::Landlock(err.to_string()))?;
        }
        Ok(ruleset)
    }

    fn apply_seccomp(mode: SeccompMode) -> Result<EnforcementStatus, SandboxError> {
        let bpf = compile_seccomp_bpf_host(mode)?;
        seccompiler::apply_filter_all_threads(&bpf)
            .map_err(|err| SandboxError::Seccomp(err.to_string()))?;
        Ok(EnforcementStatus::Enforced)
    }

    pub(crate) fn apply_seccomp_current_thread(
        mode: SeccompMode,
    ) -> Result<EnforcementStatus, SandboxError> {
        let bpf = compile_seccomp_bpf_host(mode)?;
        seccompiler::apply_filter(&bpf).map_err(|err| SandboxError::Seccomp(err.to_string()))?;
        Ok(EnforcementStatus::Enforced)
    }

    pub(crate) fn compile_seccomp_bpf_bytes_host(
        mode: SeccompMode,
    ) -> Result<Vec<u8>, SandboxError> {
        let bpf = compile_seccomp_bpf_host(mode)?;
        let mut out = Vec::with_capacity(bpf.len() * 8);
        for insn in bpf {
            out.extend_from_slice(&insn.code.to_ne_bytes());
            out.push(insn.jt);
            out.push(insn.jf);
            out.extend_from_slice(&insn.k.to_ne_bytes());
        }
        Ok(out)
    }

    fn compile_seccomp_bpf_host(mode: SeccompMode) -> Result<BpfProgram, SandboxError> {
        let Ok(arch) = TargetArch::try_from(std::env::consts::ARCH) else {
            return Err(SandboxError::Seccomp(format!(
                "seccomp-bpf target architecture '{}' is not supported (set seccomp \"off\" to bypass)",
                std::env::consts::ARCH
            )));
        };
        compile_seccomp_bpf(mode, arch)
    }

    /// Compiles MiraServe's seccomp-bpf program for `mode` and `arch`.
    ///
    /// In every active mode (`SeccompMode::Standard` and `SeccompMode::Strict`), the filter combines:
    /// 1. The mode's unconditional dangerous-syscall denylist (returning `EPERM`).
    /// 2. MiraServe's own set-ID policy (returning `EPERM`):
    ///    - Conditional mode-bit rules whenever `S_ISUID` or `S_ISGID` is requested on any syscall
    ///      whose mode and creation flags are scalar arguments (`chmod`, `fchmod`, `fchmodat`,
    ///      `fchmodat2`, `mkdir`, `mkdirat`, `mknod`, `mknodat`, `creat`, `open`, `openat` for
    ///      `O_CREAT` or arch-specific `O_TMPFILE` without `O_PATH`, and `mq_open` for `O_CREAT`).
    ///    - Unconditional denial of `io_uring_setup`, `io_uring_enter`, and `io_uring_register` in
    ///      both `Standard` and `Strict` modes, because ring operations (`IORING_OP_OPENAT`,
    ///      `IORING_OP_OPENAT2`, `IORING_OP_MKDIRAT`) execute inside the kernel past scalar rules.
    ///
    /// Compared with systemd's `seccomp_restrict_suid_sgid` (`src/shared/seccomp-util.c`,
    /// checked against upstream commit `94bb07689802a769d33b8c023ee0255fff511db3`):
    /// - Covers `mq_open` (`O_CREAT`) and full `O_TMPFILE`, and excludes `O_PATH` on `open`/`openat`
    ///   (since Linux `build_open_flags()` discards creation flags when `O_PATH` is set).
    /// - Intentionally omits `msgget`, `semget`, and `shmget`: Linux masks System V IPC modes to
    ///   `S_IRWXUGO` (`0o777`), while `0o2000` (`IPC_EXCL`) and `0o4000` (`IPC_NOWAIT` /
    ///   `SHM_HUGETLB`) are valid IPC flags.
    /// - Intentionally allows `openat2(2)` (syscall 437): classic seccomp-bpf cannot dereference
    ///   its `struct open_how __user *` argument (`arg2`), which carries both `flags` and `mode`.
    ///   Because the worker owns its state/log directories and Landlock does not mediate `chmod`,
    ///   service-owned directory modes are NOT a control against a compromised worker; durable
    ///   controls for the `openat2` residual are a host-level `nosuid` mount or a non-searchable
    ///   ancestor owned by an identity the worker cannot act as (documented in `docs/SPEC.md` and
    ///   the `--allow-openat2` unit comment).
    pub(super) fn compile_seccomp_bpf(
        mode: SeccompMode,
        arch: TargetArch,
    ) -> Result<BpfProgram, SandboxError> {
        let denied = denied_syscall_numbers(mode, arch);
        if mode != SeccompMode::Off && denied.is_empty() {
            return Err(SandboxError::Seccomp(format!(
                "no seccomp syscall denylist defined for architecture '{arch:?}' under mode {mode:?}"
            )));
        }

        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        for nr in denied {
            rules.insert(*nr, Vec::new());
            if arch == TargetArch::x86_64 {
                rules.insert(*nr | X32_SYSCALL_BIT, Vec::new());
            }
        }
        if arch == TargetArch::x86_64 && mode == SeccompMode::Strict {
            // x32-specific high syscall numbers: execve(520), ptrace(521), kexec_load(528),
            // process_vm_readv(539), process_vm_writev(540), execveat(545).
            for x32_nr in [520_i64, 521, 528, 539, 540, 545] {
                rules.insert(x32_nr | X32_SYSCALL_BIT, Vec::new());
            }
        }

        if mode != SeccompMode::Off {
            // Part of the set-ID policy in BOTH Standard and Strict modes: deny io_uring so no
            // ring operation can create a set-ID file past the scalar syscall rules below.
            for &nr in SETID_IO_URING_SYSCALLS {
                rules.insert(nr, Vec::new());
                if arch == TargetArch::x86_64 {
                    rules.insert(nr | X32_SYSCALL_BIT, Vec::new());
                }
            }
            let o_tmpfile = o_tmpfile_for_arch(arch);
            for spec in setid_syscall_specs(arch) {
                let cond_rules = build_setid_rules(spec.kind, o_tmpfile)?;
                rules.insert(spec.nr, cond_rules.clone());
                if arch == TargetArch::x86_64 {
                    rules.insert(spec.nr | X32_SYSCALL_BIT, cond_rules);
                }
            }
        }

        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(LINUX_EPERM),
            arch,
        )
        .map_err(|err| SandboxError::Seccomp(err.to_string()))?;

        filter
            .try_into()
            .map_err(|err: seccompiler::BackendError| SandboxError::Seccomp(err.to_string()))
    }

    fn build_setid_rules(
        kind: SetIdRuleKind,
        o_tmpfile: u64,
    ) -> Result<Vec<SeccompRule>, SandboxError> {
        let map_err = |err: seccompiler::BackendError| SandboxError::Seccomp(err.to_string());
        let mode_cond = |arg: u8, bit: u64| {
            SeccompCondition::new(
                arg,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::MaskedEq(bit),
                bit,
            )
            .map_err(map_err)
        };
        let flag_cond = |arg: u8, flag: u64| {
            SeccompCondition::new(
                arg,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::MaskedEq(flag),
                flag,
            )
            .map_err(map_err)
        };
        let not_flag_cond = |arg: u8, flag: u64| {
            SeccompCondition::new(
                arg,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::MaskedEq(flag),
                0,
            )
            .map_err(map_err)
        };
        let mut out = Vec::new();
        match kind {
            SetIdRuleKind::Mode { mode_arg } => {
                for bit in [LINUX_S_ISUID, LINUX_S_ISGID] {
                    out.push(SeccompRule::new(vec![mode_cond(mode_arg, bit)?]).map_err(map_err)?);
                }
            }
            SetIdRuleKind::CreateMode {
                flags_arg,
                mode_arg,
            } => {
                for bit in [LINUX_S_ISUID, LINUX_S_ISGID] {
                    out.push(
                        SeccompRule::new(vec![
                            flag_cond(flags_arg, LINUX_O_CREAT)?,
                            mode_cond(mode_arg, bit)?,
                        ])
                        .map_err(map_err)?,
                    );
                }
            }
            SetIdRuleKind::OpenCreateMode {
                flags_arg,
                mode_arg,
            } => {
                for create_flag in [LINUX_O_CREAT, o_tmpfile] {
                    for bit in [LINUX_S_ISUID, LINUX_S_ISGID] {
                        out.push(
                            SeccompRule::new(vec![
                                not_flag_cond(flags_arg, LINUX_O_PATH)?,
                                flag_cond(flags_arg, create_flag)?,
                                mode_cond(mode_arg, bit)?,
                            ])
                            .map_err(map_err)?,
                        );
                    }
                }
            }
        }
        Ok(out)
    }

    fn setid_syscall_specs(arch: TargetArch) -> &'static [SetIdSyscallSpec] {
        match arch {
            TargetArch::x86_64 => &[
                // open(filename, flags, mode) = 2
                SetIdSyscallSpec {
                    nr: 2,
                    kind: SetIdRuleKind::OpenCreateMode {
                        flags_arg: 1,
                        mode_arg: 2,
                    },
                },
                // mkdir(pathname, mode) = 83
                SetIdSyscallSpec {
                    nr: 83,
                    kind: SetIdRuleKind::Mode { mode_arg: 1 },
                },
                // creat(pathname, mode) = 85
                SetIdSyscallSpec {
                    nr: 85,
                    kind: SetIdRuleKind::Mode { mode_arg: 1 },
                },
                // chmod(filename, mode) = 90
                SetIdSyscallSpec {
                    nr: 90,
                    kind: SetIdRuleKind::Mode { mode_arg: 1 },
                },
                // fchmod(fd, mode) = 91
                SetIdSyscallSpec {
                    nr: 91,
                    kind: SetIdRuleKind::Mode { mode_arg: 1 },
                },
                // mknod(filename, mode, dev) = 133
                SetIdSyscallSpec {
                    nr: 133,
                    kind: SetIdRuleKind::Mode { mode_arg: 1 },
                },
                // mq_open(u_name, oflag, mode, u_attr) = 240
                SetIdSyscallSpec {
                    nr: 240,
                    kind: SetIdRuleKind::CreateMode {
                        flags_arg: 1,
                        mode_arg: 2,
                    },
                },
                // openat(dfd, filename, flags, mode) = 257
                SetIdSyscallSpec {
                    nr: 257,
                    kind: SetIdRuleKind::OpenCreateMode {
                        flags_arg: 2,
                        mode_arg: 3,
                    },
                },
                // mkdirat(dfd, pathname, mode) = 258
                SetIdSyscallSpec {
                    nr: 258,
                    kind: SetIdRuleKind::Mode { mode_arg: 2 },
                },
                // mknodat(dfd, filename, mode, dev) = 259
                SetIdSyscallSpec {
                    nr: 259,
                    kind: SetIdRuleKind::Mode { mode_arg: 2 },
                },
                // fchmodat(dfd, filename, mode) = 268
                SetIdSyscallSpec {
                    nr: 268,
                    kind: SetIdRuleKind::Mode { mode_arg: 2 },
                },
                // fchmodat2(dfd, filename, mode, flags) = 452
                SetIdSyscallSpec {
                    nr: 452,
                    kind: SetIdRuleKind::Mode { mode_arg: 2 },
                },
            ],
            TargetArch::aarch64 | TargetArch::riscv64 => &[
                // Linux asm-generic/unistd.h (no legacy open/creat/chmod/mkdir/mknod):
                // mknodat(dfd, filename, mode, dev) = 33
                SetIdSyscallSpec {
                    nr: 33,
                    kind: SetIdRuleKind::Mode { mode_arg: 2 },
                },
                // mkdirat(dfd, pathname, mode) = 34
                SetIdSyscallSpec {
                    nr: 34,
                    kind: SetIdRuleKind::Mode { mode_arg: 2 },
                },
                // fchmod(fd, mode) = 52
                SetIdSyscallSpec {
                    nr: 52,
                    kind: SetIdRuleKind::Mode { mode_arg: 1 },
                },
                // fchmodat(dfd, filename, mode) = 53
                SetIdSyscallSpec {
                    nr: 53,
                    kind: SetIdRuleKind::Mode { mode_arg: 2 },
                },
                // openat(dfd, filename, flags, mode) = 56
                SetIdSyscallSpec {
                    nr: 56,
                    kind: SetIdRuleKind::OpenCreateMode {
                        flags_arg: 2,
                        mode_arg: 3,
                    },
                },
                // mq_open(u_name, oflag, mode, u_attr) = 180
                SetIdSyscallSpec {
                    nr: 180,
                    kind: SetIdRuleKind::CreateMode {
                        flags_arg: 1,
                        mode_arg: 2,
                    },
                },
                // fchmodat2(dfd, filename, mode, flags) = 452
                SetIdSyscallSpec {
                    nr: 452,
                    kind: SetIdRuleKind::Mode { mode_arg: 2 },
                },
            ],
        }
    }

    fn denied_syscall_numbers(mode: SeccompMode, arch: TargetArch) -> &'static [i64] {
        match arch {
            TargetArch::x86_64 => match mode {
                SeccompMode::Off => &[],
                // ptrace(101), mount(165), umount2(166), pivot_root(155), chroot(161),
                // kexec_load(246), init_module(175), finit_module(313), delete_module(176),
                // reboot(169), bpf(321)
                SeccompMode::Standard => &[101, 155, 161, 165, 166, 169, 175, 176, 246, 313, 321],
                // Standard + execve(59), swapon(167), swapoff(168), add_key(248), request_key(249),
                // keyctl(250), unshare(272), perf_event_open(298), setns(308), process_vm_readv(310),
                // process_vm_writev(311), kexec_file_load(320), execveat(322), userfaultfd(323),
                // io_uring_setup(425), io_uring_enter(426), io_uring_register(427),
                // open_tree(428), move_mount(429), fsopen(430), fsconfig(431), fsmount(432), fspick(433)
                SeccompMode::Strict => &[
                    59, 101, 155, 161, 165, 166, 167, 168, 169, 175, 176, 246, 248, 249, 250, 272,
                    298, 308, 310, 311, 313, 320, 321, 322, 323, 425, 426, 427, 428, 429, 430, 431,
                    432, 433,
                ],
            },
            TargetArch::aarch64 | TargetArch::riscv64 => match mode {
                SeccompMode::Off => &[],
                // Linux asm-generic/unistd.h (shared by aarch64 and riscv64):
                // umount2(39), mount(40), pivot_root(41), chroot(51), kexec_load(104),
                // init_module(105), delete_module(106), ptrace(117), reboot(142),
                // finit_module(273), bpf(280)
                SeccompMode::Standard => &[39, 40, 41, 51, 104, 105, 106, 117, 142, 273, 280],
                // Standard + unshare(97), add_key(217), request_key(218), keyctl(219), execve(221),
                // swapon(224), swapoff(225), perf_event_open(241), setns(268), process_vm_readv(270),
                // process_vm_writev(271), execveat(281), userfaultfd(282), kexec_file_load(294),
                // io_uring_*(425..427), open_tree..fspick(428..433)
                SeccompMode::Strict => &[
                    39, 40, 41, 51, 97, 104, 105, 106, 117, 142, 217, 218, 219, 221, 224, 225, 241,
                    268, 270, 271, 273, 280, 281, 282, 294, 425, 426, 427, 428, 429, 430, 431, 432,
                    433,
                ],
            },
        }
    }
}

/// Codex Round-11 P1: tree validation must hold even when a path component changes DURING
/// validation (between resolving the candidate location and opening it). `open_validated_tree`
/// takes the resolver as a parameter so these tests can mutate the tree inside that interval.
#[cfg(all(test, unix))]
mod tree_validation_tests {
    use super::{GrantState, open_validated_tree};
    use std::os::unix::fs::MetadataExt as _;
    use std::path::{Path, PathBuf};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn temp_base(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let base = std::fs::canonicalize(std::env::temp_dir())?.join(format!(
            "miraserve-r11-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&base)?;
        Ok(base)
    }

    fn identity(p: &Path) -> std::io::Result<(u64, u64)> {
        let md = std::fs::metadata(p)?;
        Ok((md.dev(), md.ino()))
    }

    fn installed_identity(state: &GrantState) -> Option<(u64, u64)> {
        match state {
            GrantState::Installed { identity, .. } => Some(*identity),
            _ => None,
        }
    }

    /// An ancestor of the validated location is replaced by a link to the SAME directory while
    /// validating: the object's device/inode still matches through the link, but the no-follow
    /// open of the validated location refuses the link (the previous name-based `metadata` check
    /// accepted this).
    #[test]
    fn ancestor_relinked_during_validation_is_refused() -> TestResult {
        let base = temp_base("ancestor")?;
        let parent = base.join("a");
        let tree = parent.join("tree");
        std::fs::create_dir_all(&tree)?;
        let first = identity(&tree)?;
        let state = open_validated_tree(&tree, first, true, |p: &Path| {
            let canon = std::fs::canonicalize(p)?;
            std::fs::rename(&parent, base.join("a-moved"))?;
            std::os::unix::fs::symlink(base.join("a-moved"), &parent)?;
            Ok(canon)
        });
        assert!(
            matches!(state, GrantState::Failed { .. }),
            "a link introduced into the validated location must be refused, got {state:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    /// The validated leaf itself is replaced by a link into `/etc` while validating: refused.
    #[test]
    fn leaf_replaced_by_forbidden_link_during_validation_is_refused() -> TestResult {
        let base = temp_base("leaf-link")?;
        let tree = base.join("tree");
        std::fs::create_dir_all(&tree)?;
        let first = identity(&tree)?;
        let state = open_validated_tree(&tree, first, true, |p: &Path| {
            let canon = std::fs::canonicalize(p)?;
            std::fs::rename(&tree, base.join("tree-moved"))?;
            std::os::unix::fs::symlink("/etc", &tree)?;
            Ok(canon)
        });
        assert!(matches!(state, GrantState::Failed { .. }), "got {state:?}");
        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    /// The validated location is replaced by a different directory while validating: the
    /// identity no longer matches the alias's first open, so the grant is refused.
    #[test]
    fn directory_replaced_during_validation_is_refused() -> TestResult {
        let base = temp_base("replaced")?;
        let tree = base.join("tree");
        std::fs::create_dir_all(&tree)?;
        let first = identity(&tree)?;
        let state = open_validated_tree(&tree, first, true, |p: &Path| {
            let canon = std::fs::canonicalize(p)?;
            std::fs::rename(&tree, base.join("tree-old"))?;
            std::fs::create_dir_all(&tree)?;
            Ok(canon)
        });
        assert!(matches!(state, GrantState::Failed { .. }), "got {state:?}");
        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    /// The configured alias is swapped to `/etc` after it was resolved: the installed descriptor
    /// is the directory at the validated location (the original tree), never `/etc`.
    #[test]
    fn alias_swapped_during_validation_installs_validated_object() -> TestResult {
        let base = temp_base("alias")?;
        if let Some(reason) = miraserve_config::sandbox_tree_rejection(&base.to_string_lossy()) {
            eprintln!(
                "skipping alias_swapped_during_validation_installs_validated_object: temp path '{}' rejected by sandbox tree validator ({reason})",
                base.display()
            );
            let _ = std::fs::remove_dir_all(&base);
            return Ok(());
        }
        let real = base.join("real-tree");
        let alias = base.join("alias");
        std::fs::create_dir_all(&real)?;
        std::os::unix::fs::symlink(&real, &alias)?;
        let first = identity(&alias)?;
        let state = open_validated_tree(&alias, first, true, |p: &Path| {
            let canon = std::fs::canonicalize(p)?;
            std::fs::remove_file(&alias)?;
            std::os::unix::fs::symlink("/etc", &alias)?;
            Ok(canon)
        });
        assert_eq!(installed_identity(&state), Some(identity(&real)?));
        assert_ne!(
            installed_identity(&state),
            Some(identity(Path::new("/etc"))?)
        );
        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    /// The tree policy is applied to the resolved candidate location, and a stable allowed alias
    /// keeps working.
    #[test]
    fn policy_applies_to_candidate_and_stable_alias_is_accepted() -> TestResult {
        let base = temp_base("policy")?;
        if let Some(reason) = miraserve_config::sandbox_tree_rejection(&base.to_string_lossy()) {
            eprintln!(
                "skipping policy_applies_to_candidate_and_stable_alias_is_accepted: temp path '{}' rejected by sandbox tree validator ({reason})",
                base.display()
            );
            let _ = std::fs::remove_dir_all(&base);
            return Ok(());
        }
        let real = base.join("real-tree");
        let alias = base.join("alias");
        std::fs::create_dir_all(&real)?;
        std::os::unix::fs::symlink(&real, &alias)?;
        let first = identity(&alias)?;
        let ok = open_validated_tree(&alias, first, true, |p: &Path| std::fs::canonicalize(p));
        assert_eq!(installed_identity(&ok), Some(identity(&real)?));

        let refused =
            open_validated_tree(&alias, first, true, |_: &Path| Ok(PathBuf::from("/etc")));
        match refused {
            GrantState::Failed { reason, .. } => {
                assert!(reason.contains("not allowed"), "{reason}");
            }
            other => return Err(format!("expected policy refusal, got {other:?}").into()),
        }
        let not_dir =
            open_validated_tree(&alias, first, false, |p: &Path| std::fs::canonicalize(p));
        assert!(matches!(not_dir, GrantState::Failed { .. }));
        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }
}

#[cfg(test)]
mod openat2_advisory_tests {
    use super::{
        EnforcementStatus, Openat2AdvisoryContext, Openat2RefusalKind, SandboxReport,
        blocked_syscalls_for_mode, format_openat2_refused_advisory,
        format_resolve_cached_unsupported_advisory, kernel_release_in_range,
        parse_proc_status_seccomp_active, setid_filtered_syscalls_for_mode,
    };
    use miraserve_config::{SeccompMode, parse_kdl};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn mock_report(seccomp: EnforcementStatus) -> SandboxReport {
        SandboxReport {
            platform: "linux",
            landlock: EnforcementStatus::Enforced,
            seccomp,
            read_only_path_count: 0,
            read_write_path_count: 0,
            socket_path_count: 0,
            notes: Vec::new(),
        }
    }

    fn parse_advisory_cfg(
        name: &str,
        server_extra: &str,
        site_extra: &str,
    ) -> Result<miraserve_config::Config, Box<dyn std::error::Error>> {
        let base_tls =
            r#"tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }"#;
        let (cfg, _) = parse_kdl(
            name,
            &format!(
                "server {{ listen \":443\"; {base_tls}; {server_extra} }}\n\
                 site \"a.test\" {{ root \"/var/www/a\"; {site_extra} }}\n"
            ),
        )?;
        Ok(cfg)
    }

    #[test]
    fn setid_filtered_syscalls_and_io_uring_reported_for_active_modes_only() {
        assert_eq!(
            setid_filtered_syscalls_for_mode(SeccompMode::Off),
            <&[&str]>::default()
        );
        assert_eq!(
            blocked_syscalls_for_mode(SeccompMode::Off),
            <&[&str]>::default()
        );
        for mode in [SeccompMode::Standard, SeccompMode::Strict] {
            let calls = setid_filtered_syscalls_for_mode(mode);
            for expected in [
                "chmod",
                "fchmod",
                "fchmodat",
                "fchmodat2",
                "mkdir",
                "mkdirat",
                "mknod",
                "mknodat",
                "creat",
                "open",
                "openat",
                "mq_open",
            ] {
                assert!(
                    calls.contains(&expected),
                    "mode {mode:?} missing {expected} in {calls:?}"
                );
            }
            for omitted in ["openat2", "msgget", "semget", "shmget"] {
                assert!(
                    !calls.contains(&omitted),
                    "mode {mode:?} should not list {omitted} in {calls:?}"
                );
            }
            let blocked = blocked_syscalls_for_mode(mode);
            for ring_call in ["io_uring_setup", "io_uring_enter", "io_uring_register"] {
                assert!(
                    blocked.contains(&ring_call),
                    "mode {mode:?} must unconditionally deny {ring_call}: {blocked:?}"
                );
            }
        }
    }

    #[test]
    fn proc_status_seccomp_parser_distinguishes_disabled_active_and_missing() {
        assert_eq!(
            parse_proc_status_seccomp_active("Name:\tmiraserve\nSeccomp:\t0\n"),
            Some(false)
        );
        assert_eq!(
            parse_proc_status_seccomp_active(
                "Name:\tmiraserve\nSeccomp:\t2\nSeccomp_filters:\t1\n"
            ),
            Some(true)
        );
        assert_eq!(
            parse_proc_status_seccomp_active("Seccomp:\t1\n"),
            Some(true)
        );
        assert_eq!(parse_proc_status_seccomp_active("Name:\tmiraserve\n"), None);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn advisory_covers_file_cache_workers_h2_and_neither() -> TestResult {
        let enforced = mock_report(EnforcementStatus::Enforced);
        let rt_enforced = Openat2AdvisoryContext::Runtime(Some(&enforced));

        // Plain default `:443` serves HTTP/2: on Linux 5.9-6.11 (`kernel_in_nowait_range = true`)
        // openat2 refusal forces HTTP/2 onto separate tasks, so an advisory IS emitted; on kernels
        // outside 5.9-6.11 (`false`) allowing openat2 would not enable in-task HTTP/2, so no
        // advisory is emitted.
        let plain = parse_advisory_cfg("plain.kdl", "", "")?;
        assert_eq!(
            format_openat2_refused_advisory(
                &plain,
                Openat2RefusalKind::NoSys,
                "Function not implemented",
                rt_enforced,
                Some(true),
                false,
            ),
            None
        );
        let plain_h2_msg = format_openat2_refused_advisory(
            &plain,
            Openat2RefusalKind::NoSys,
            "Function not implemented",
            rt_enforced,
            Some(true),
            true,
        )
        .ok_or("expected advisory for plain HTTP/2 config on 5.9-6.11 kernel")?;
        assert!(
            plain_h2_msg.contains("static HTTP/2 streams will run as separate tasks")
                && !plain_h2_msg.contains("file-cache")
                && !plain_h2_msg.contains("worker loops")
                && plain_h2_msg.contains("--allow-openat2"),
            "{plain_h2_msg}"
        );

        // HTTP/1.1-only without file-cache or workers: never emits an advisory on any kernel.
        let (h1_only, _) = parse_kdl(
            "h1-only.kdl",
            r#"server { listen ":443" protocols="h1"; tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" } }
site "a.test" { root "/var/www/a" }"#,
        )?;
        assert_eq!(
            format_openat2_refused_advisory(
                &h1_only,
                Openat2RefusalKind::NoSys,
                "Function not implemented",
                rt_enforced,
                Some(true),
                true,
            ),
            None
        );

        let cache_zero = parse_advisory_cfg(
            "zero.kdl",
            r#"limits { file-cache-bytes "0" }"#,
            r#"file-cache "1s""#,
        )?;
        assert_eq!(
            format_openat2_refused_advisory(
                &cache_zero,
                Openat2RefusalKind::NoSys,
                "Function not implemented",
                rt_enforced,
                Some(true),
                false,
            ),
            None
        );

        let cache_only = parse_advisory_cfg("cache.kdl", "", r#"file-cache "1s""#)?;
        let msg = format_openat2_refused_advisory(
            &cache_only,
            Openat2RefusalKind::NoSys,
            "Function not implemented",
            rt_enforced,
            Some(true),
            false,
        )
        .ok_or("expected advisory for file-cache")?;
        assert!(msg.contains("file-cache will store nothing"), "{msg}");
        assert!(!msg.contains("worker loops"), "{msg}");
        assert!(!msg.contains("HTTP/2 streams"), "{msg}");
        assert!(msg.contains("--allow-openat2"), "{msg}");
        assert!(msg.contains("DefaultRestrictSUIDSGID=yes"), "{msg}");
        assert!(!msg.contains("confirming the effective worker"), "{msg}");

        let msg_cache_h2 = format_openat2_refused_advisory(
            &cache_only,
            Openat2RefusalKind::NoSys,
            "Function not implemented",
            rt_enforced,
            Some(true),
            true,
        )
        .ok_or("expected advisory for file-cache + h2")?;
        assert!(
            msg_cache_h2.contains("file-cache will store nothing")
                && msg_cache_h2.contains("HTTP/2 streams will run as separate tasks")
                && !msg_cache_h2.contains("worker loops"),
            "{msg_cache_h2}"
        );

        let workers_only = parse_advisory_cfg("workers.kdl", r#"workers "auto""#, "")?;
        let msg = format_openat2_refused_advisory(
            &workers_only,
            Openat2RefusalKind::NoSys,
            "Function not implemented",
            Openat2AdvisoryContext::StandaloneCheck,
            Some(true),
            false,
        )
        .ok_or("expected advisory for workers")?;
        assert!(msg.contains("worker loops will not look up"), "{msg}");
        assert!(!msg.contains("file-cache"), "{msg}");
        assert!(msg.contains("--allow-openat2"), "{msg}");
        assert!(
            msg.contains(
                "confirming the effective worker ExecStart command does not pass --no-sandbox"
            ),
            "standalone check must remind operator to verify effective ExecStart: {msg}"
        );

        let both = parse_advisory_cfg("both.kdl", "workers 2", r#"file-cache "2s""#)?;
        let msg = format_openat2_refused_advisory(
            &both,
            Openat2RefusalKind::NoSys,
            "Function not implemented",
            rt_enforced,
            Some(true),
            true,
        )
        .ok_or("expected advisory for all three")?;
        assert!(
            msg.contains("file-cache will store nothing")
                && msg.contains("worker loops will not look up")
                && msg.contains("HTTP/2 streams will run as separate tasks")
                && msg.contains("--allow-openat2"),
            "{msg}"
        );

        // Linux 5.6-5.11 RESOLVE_CACHED unsupported notice never suggests --allow-openat2.
        // On 5.6-5.11 `kernel_in_h2_intask_range` is false, so only `workers` is mentioned;
        // on 5.12-6.11 (`true`, synthetic) both are mentioned.
        let rc_msg_5_11 = format_resolve_cached_unsupported_advisory(&both, false)
            .ok_or("expected RESOLVE_CACHED advisory for workers on 5.11")?;
        assert!(
            rc_msg_5_11.contains("RESOLVE_CACHED")
                && rc_msg_5_11.contains("worker loops will not look up")
                && !rc_msg_5_11.contains("HTTP/2 streams")
                && !rc_msg_5_11.contains("--allow-openat2"),
            "{rc_msg_5_11}"
        );
        let rc_msg = format_resolve_cached_unsupported_advisory(&both, true)
            .ok_or("expected RESOLVE_CACHED advisory")?;
        assert!(
            rc_msg.contains("RESOLVE_CACHED")
                && rc_msg.contains("worker loops will not look up")
                && rc_msg.contains("HTTP/2 streams will run as separate tasks")
                && rc_msg.contains("regenerating the systemd unit cannot help")
                && !rc_msg.contains("--allow-openat2"),
            "{rc_msg}"
        );
        assert_eq!(
            format_resolve_cached_unsupported_advisory(&h1_only, true),
            None
        );

        // P1-C & P2-4: H2 reverse-proxy-only config (no static file work) never needs openat2
        // and never emits an advisory even on Linux 5.12-6.11.
        let (h2_proxy_only, _) = parse_kdl(
            "h2-proxy-only.kdl",
            r#"server { listen ":443"; tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" } }
site "proxy.test" { route "/*" { reverse-proxy { upstream "http://127.0.0.1:9000" } } }"#,
        )?;
        assert!(!super::config_has_static_work(&h2_proxy_only));
        assert_eq!(
            format_openat2_refused_advisory(
                &h2_proxy_only,
                Openat2RefusalKind::NoSys,
                "Function not implemented",
                rt_enforced,
                Some(true),
                true,
            ),
            None
        );
        assert_eq!(
            format_resolve_cached_unsupported_advisory(&h2_proxy_only, true),
            None
        );

        // P2-4: HTTP/2 in-task range is Linux 5.12-6.11 (NOT 5.9-5.11, since RESOLVE_CACHED
        // requires 5.12+).
        assert!(!kernel_release_in_range(b"5.9.0\n", (5, 12), (6, 12)));
        assert!(!kernel_release_in_range(b"5.11.22\n", (5, 12), (6, 12)));
        assert!(kernel_release_in_range(b"5.12.0\n", (5, 12), (6, 12)));
        assert!(kernel_release_in_range(
            b"6.8.0-142-generic\n",
            (5, 12),
            (6, 12)
        ));
        assert!(kernel_release_in_range(b"6.11.9\n", (5, 12), (6, 12)));
        assert!(!kernel_release_in_range(b"6.12.0\n", (5, 12), (6, 12)));
        assert!(!kernel_release_in_range(
            b"7.2.12-orbstack\n",
            (5, 12),
            (6, 12)
        ));
        assert!(!kernel_release_in_range(b"5.4.0\n", (5, 12), (6, 12)));
        Ok(())
    }

    #[test]
    fn advisory_respects_unfiltered_kernel_and_outer_filter() -> TestResult {
        let strict_cfg = parse_advisory_cfg("strict.kdl", "workers 2", r#"file-cache "1s""#)?;
        let off_cfg = parse_advisory_cfg(
            "off.kdl",
            r#"workers 2; sandbox { seccomp "off" }"#,
            r#"file-cache "1s""#,
        )?;
        let enforced_rep = mock_report(EnforcementStatus::Enforced);
        let disabled_rep = mock_report(EnforcementStatus::Disabled);

        let old_kernel = format_openat2_refused_advisory(
            &strict_cfg,
            Openat2RefusalKind::NoSys,
            "Function not implemented",
            Openat2AdvisoryContext::Runtime(Some(&enforced_rep)),
            Some(false),
            false,
        )
        .ok_or("expected advisory for pre-5.6 kernel")?;
        assert!(
            old_kernel.contains("regenerating the systemd unit cannot help")
                && !old_kernel.contains("--allow-openat2")
                && !old_kernel.contains("NO set-ID protection"),
            "pre-5.6 kernel notice must not recommend regenerating unit: {old_kernel}"
        );

        // ENOSYS + Seccomp=0 with disabled policy must emit BOTH pre-5.6 AND NO set-ID warning.
        for (label, cfg, ctx) in [
            (
                "check seccomp off",
                &off_cfg,
                Openat2AdvisoryContext::StandaloneCheck,
            ),
            (
                "runtime --no-sandbox",
                &strict_cfg,
                Openat2AdvisoryContext::Runtime(None),
            ),
            (
                "runtime prebuilt disabled policy",
                &strict_cfg,
                Openat2AdvisoryContext::Runtime(Some(&disabled_rep)),
            ),
        ] {
            let msg = format_openat2_refused_advisory(
                cfg,
                Openat2RefusalKind::NoSys,
                "Function not implemented",
                ctx,
                Some(false),
                false,
            )
            .ok_or("expected combined pre-5.6 + disabled-seccomp advisory")?;
            assert!(
                msg.contains("regenerating the systemd unit cannot help")
                    && msg.contains("NO set-ID protection")
                    && msg.contains("do NOT remove RestrictSUIDSGID=yes")
                    && !msg.contains("--allow-openat2"),
                "{label}: ENOSYS+Seccomp=0 with disabled policy must include both warnings: {msg}"
            );
        }

        for (kind, err) in [
            (Openat2RefusalKind::Access, "Permission denied"),
            (Openat2RefusalKind::Perm, "Operation not permitted"),
        ] {
            let outer_check = format_openat2_refused_advisory(
                &strict_cfg,
                kind,
                err,
                Openat2AdvisoryContext::StandaloneCheck,
                Some(true),
                true,
            )
            .ok_or("expected outer-filter advisory")?;
            assert!(
                outer_check.contains("outer system-call filter")
                    && outer_check.contains("allow openat2 in the outer seccomp profile")
                    && outer_check.contains("confirming the effective worker ExecStart command"),
                "unexpected standalone-check outer-filter notice: {outer_check}"
            );
        }
        Ok(())
    }

    #[test]
    fn advisory_respects_installed_report_and_disabled_seccomp() -> TestResult {
        let strict_cfg = parse_advisory_cfg("strict.kdl", "workers 2", r#"file-cache "1s""#)?;
        let off_cfg = parse_advisory_cfg(
            "off.kdl",
            r#"workers 2; sandbox { seccomp "off" }"#,
            r#"file-cache "1s""#,
        )?;
        let enforced_rep = mock_report(EnforcementStatus::Enforced);
        let disabled_rep = mock_report(EnforcementStatus::Disabled);

        let embedder_disabled = format_openat2_refused_advisory(
            &strict_cfg,
            Openat2RefusalKind::NoSys,
            "Function not implemented",
            Openat2AdvisoryContext::Runtime(Some(&disabled_rep)),
            Some(true),
            true,
        )
        .ok_or("expected advisory for embedder-disabled policy")?;
        assert!(
            embedder_disabled.contains("the installed sandbox policy (seccomp disabled)")
                && embedder_disabled.contains("NO set-ID protection")
                && !embedder_disabled.contains("--allow-openat2"),
            "embedder disabled report must override strict config: {embedder_disabled}"
        );

        let embedder_enforced = format_openat2_refused_advisory(
            &off_cfg,
            Openat2RefusalKind::NoSys,
            "Function not implemented",
            Openat2AdvisoryContext::Runtime(Some(&enforced_rep)),
            Some(true),
            true,
        )
        .ok_or("expected advisory for embedder-enforced policy")?;
        assert!(
            embedder_enforced.contains("--allow-openat2")
                && !embedder_enforced.contains("NO set-ID protection"),
            "embedder enforced report must override off config: {embedder_enforced}"
        );

        for (label, cfg, ctx) in [
            (
                "seccomp off (check)",
                &off_cfg,
                Openat2AdvisoryContext::StandaloneCheck,
            ),
            (
                "--no-sandbox",
                &strict_cfg,
                Openat2AdvisoryContext::Runtime(None),
            ),
            ("both off", &off_cfg, Openat2AdvisoryContext::Runtime(None)),
        ] {
            let msg = format_openat2_refused_advisory(
                cfg,
                Openat2RefusalKind::NoSys,
                "Function not implemented",
                ctx,
                Some(true),
                true,
            )
            .ok_or("expected disabled-seccomp advisory")?;
            assert!(
                msg.contains("NO set-ID protection")
                    && msg.contains("do NOT remove RestrictSUIDSGID=yes")
                    && !msg.contains("--allow-openat2"),
                "{label}: advisory must warn of NO set-ID protection without steering into --allow-openat2: {msg}"
            );
        }
        Ok(())
    }

    /// P1-3: `config_has_static_work` and the runtime HTTP/2 advisory must exclude quarantined
    /// tenant sites (whose `routes` retain `RouteHandler::Static` declarations while their roots
    /// were cleared) without altering independent `workers` and `file-cache` advisory conditions.
    #[test]
    fn p1_3_advisory_ignores_quarantined_static_tenant_and_uses_effective_inventory()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::{
            config_has_static_work, config_needs_openat2,
            format_openat2_refused_advisory_with_static_work,
        };

        let kdl = r#"
server {
    listen "127.0.0.1:8443" protocols="h2,h1"
    tls { cert "/etc/miraserve/c.pem"; key "/etc/miraserve/k.pem" }
}
site "live-proxy.test" {
    route "/*" {
        reverse-proxy {
            upstream "http://127.0.0.1:8080"
        }
    }
}
site "tenant-static.test" {
    owner-dir "/var/www/tenant"
    route "/files/*" {
        root "/var/www/tenant/public"
        static {}
    }
}
"#;
        let (mut cfg, _) = miraserve_config::parse_kdl("p13-quarantine.kdl", kdl)?;
        assert!(
            config_has_static_work(&cfg),
            "unquarantined static tenant must count as static work"
        );

        // Simulate preflight missing-root quarantine (clears root paths, retains route declarations).
        if let Some(tenant) = cfg.sites.get_mut(1) {
            tenant.quarantine = Some("document root does not exist".to_owned());
            tenant.root = None;
            for r in &mut tenant.routes {
                r.root = None;
            }
        }
        assert!(
            !config_has_static_work(&cfg),
            "quarantined static tenant must not count as static work in classified config"
        );
        assert!(
            !config_needs_openat2(&cfg, true, config_has_static_work(&cfg)),
            "classified config with only a quarantined static tenant must not probe openat2"
        );
        assert!(
            format_openat2_refused_advisory_with_static_work(
                &cfg,
                Openat2RefusalKind::NoSys,
                "Function not implemented",
                Openat2AdvisoryContext::Runtime(None),
                Some(true),
                true,
                false,
            )
            .is_none(),
            "runtime advisory with effective has_static_work=false must emit None"
        );

        // Independent `workers` and `file-cache` conditions remain unaffected even when
        // `has_static_work == false`.
        let mut workers_cfg = cfg.clone();
        workers_cfg.server.workers = miraserve_config::Workers::Count(2);
        assert!(
            config_needs_openat2(&workers_cfg, true, false),
            "workers advisory condition must remain independent of H2 static work"
        );
        let mut fc_cfg = cfg;
        if let Some(site) = fc_cfg.sites.first_mut() {
            site.file_cache = Some(std::time::Duration::from_secs(5));
        }
        assert!(
            config_needs_openat2(&fc_cfg, true, false),
            "file-cache advisory condition must remain independent of H2 static work"
        );
        Ok(())
    }

    #[test]
    fn openat2_refusal_advisory_level_warns_only_when_configured_feature_degraded()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::{Openat2AdvisoryLevel, openat2_refusal_advisory_level};

        let tls = r#"tls { cert "/etc/miraserve/c.pem"; key "/etc/miraserve/k.pem" }"#;
        let cases = [
            (
                "default H2 static",
                format!(
                    "server {{ listen \":443\"; {tls} }}\nsite \"a.test\" {{ root \"/var/www/a\" }}"
                ),
                Openat2AdvisoryLevel::Info,
            ),
            (
                "explicit file-cache off",
                format!(
                    "server {{ listen \":443\"; {tls} }}\nsite \"a.test\" {{ root \"/var/www/a\"; file-cache \"off\" }}"
                ),
                Openat2AdvisoryLevel::Info,
            ),
            (
                "file-cache with zero global budget",
                format!(
                    "server {{ listen \":443\"; {tls}; limits {{ file-cache-bytes \"0\" }} }}\nsite \"a.test\" {{ root \"/var/www/a\"; file-cache \"5s\" }}"
                ),
                Openat2AdvisoryLevel::Info,
            ),
            (
                "explicit shared workers",
                format!(
                    "server {{ listen \":443\"; workers \"shared\"; {tls} }}\nsite \"a.test\" {{ root \"/var/www/a\" }}"
                ),
                Openat2AdvisoryLevel::Info,
            ),
            (
                "file-cache enabled",
                format!(
                    "server {{ listen \":443\"; {tls} }}\nsite \"a.test\" {{ root \"/var/www/a\"; file-cache \"5s\" }}"
                ),
                Openat2AdvisoryLevel::Warn,
            ),
            (
                "workers count",
                format!(
                    "server {{ listen \":443\"; workers 2; {tls} }}\nsite \"a.test\" {{ root \"/var/www/a\" }}"
                ),
                Openat2AdvisoryLevel::Warn,
            ),
            (
                "workers auto",
                format!(
                    "server {{ listen \":443\"; workers \"auto\"; {tls} }}\nsite \"a.test\" {{ root \"/var/www/a\" }}"
                ),
                Openat2AdvisoryLevel::Warn,
            ),
        ];

        for (label, kdl, expected) in cases {
            let (cfg, _) = miraserve_config::parse_kdl("level.kdl", &kdl)?;
            assert_eq!(
                openat2_refusal_advisory_level(&cfg),
                expected,
                "case '{label}' produced unexpected advisory level"
            );
        }
        Ok(())
    }
}

/// Pure-Rust safe cBPF evaluator verifying the compiled seccomp-bpf programs for every supported
/// Linux architecture (`x86_64` including `x32`, `aarch64`, and `riscv64`) across every syscall
/// and argument combination in both `Standard` and `Strict` modes.
#[cfg(all(test, target_os = "linux"))]
mod seccomp_bpf_vm_tests {
    use super::linux::compile_seccomp_bpf;
    use miraserve_config::SeccompMode;
    use seccompiler::{TargetArch, sock_filter};

    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_EPERM: u32 = 0x0005_0001;

    const AUDIT_ARCH_X86_64: u32 = 0x003e | 0x8000_0000 | 0x4000_0000;
    const AUDIT_ARCH_AARCH64: u32 = 0x00b7 | 0x8000_0000 | 0x4000_0000;
    const AUDIT_ARCH_RISCV64: u32 = 0x00f3 | 0x8000_0000 | 0x4000_0000;
    const AUDIT_ARCH_I386: u32 = 0x0003 | 0x4000_0000;

    const X32_BIT: u32 = 0x4000_0000;
    const fn x32(nr: u32) -> u32 {
        nr | X32_BIT
    }
    const O_CREAT: u64 = 0o100;
    const O_PATH: u64 = 0o1000_0000;
    const O_RDONLY: u64 = 0;

    fn encode_seccomp_data(nr: u32, arch: u32, args: [u64; 6]) -> [u8; 64] {
        let mut buf = [0_u8; 64];
        if let Some(slot) = buf.get_mut(0..4) {
            slot.copy_from_slice(&nr.to_le_bytes());
        }
        if let Some(slot) = buf.get_mut(4..8) {
            slot.copy_from_slice(&arch.to_le_bytes());
        }
        for (idx, val) in args.iter().enumerate() {
            let off = 16 + idx * 8;
            if let Some(slot) = buf.get_mut(off..off + 8) {
                slot.copy_from_slice(&val.to_le_bytes());
            }
        }
        buf
    }

    fn eval_bpf(prog: &[sock_filter], data: &[u8; 64]) -> Result<u32, String> {
        let mut pc: usize = 0;
        let mut acc: u32 = 0;
        for _ in 0..8192 {
            let insn = prog
                .get(pc)
                .ok_or_else(|| format!("pc {pc} out of bounds (len={})", prog.len()))?;
            match insn.code {
                // BPF_LD | BPF_W | BPF_ABS
                0x20 => {
                    let off = usize::try_from(insn.k).map_err(|e| e.to_string())?;
                    let bytes: [u8; 4] = data
                        .get(off..off + 4)
                        .and_then(|s| s.try_into().ok())
                        .ok_or_else(|| format!("data load out of bounds at {off}"))?;
                    acc = u32::from_le_bytes(bytes);
                    pc += 1;
                }
                // BPF_ALU | BPF_AND | BPF_K
                0x54 => {
                    acc &= insn.k;
                    pc += 1;
                }
                // BPF_JMP | BPF_JA
                0x05 => {
                    let delta = usize::try_from(insn.k).map_err(|e| e.to_string())?;
                    pc += 1 + delta;
                }
                // BPF_JMP | BPF_JEQ | BPF_K
                0x15 => {
                    pc += 1 + usize::from(if acc == insn.k { insn.jt } else { insn.jf });
                }
                // BPF_JMP | BPF_JGT | BPF_K
                0x25 => {
                    pc += 1 + usize::from(if acc > insn.k { insn.jt } else { insn.jf });
                }
                // BPF_JMP | BPF_JGE | BPF_K
                0x35 => {
                    pc += 1 + usize::from(if acc >= insn.k { insn.jt } else { insn.jf });
                }
                // BPF_RET | BPF_K
                0x06 => return Ok(insn.k),
                other => return Err(format!("unsupported BPF opcode 0x{other:x} at pc {pc}")),
            }
        }
        Err("BPF evaluation step budget exceeded".to_owned())
    }

    fn audit_arch_for(arch: TargetArch) -> u32 {
        match arch {
            TargetArch::x86_64 => AUDIT_ARCH_X86_64,
            TargetArch::aarch64 => AUDIT_ARCH_AARCH64,
            TargetArch::riscv64 => AUDIT_ARCH_RISCV64,
        }
    }

    /// Mirrors Linux `kernel/seccomp.c`'s `seccomp_check_filter` static verifier constraints:
    /// non-empty, `<= BPF_MAXINSNS` (4096), 4-byte aligned in-bounds `seccomp_data` loads,
    /// in-bounds forward jumps, and terminating `BPF_RET`.
    fn validate_kernel_seccomp_bpf(prog: &[sock_filter]) -> Result<(), String> {
        const BPF_MAXINSNS: usize = 4096;
        if prog.is_empty() || prog.len() > BPF_MAXINSNS {
            return Err(format!(
                "BPF length {} outside 1..={BPF_MAXINSNS}",
                prog.len()
            ));
        }
        if prog.last().map(|i| i.code) != Some(0x06) {
            return Err("BPF program does not terminate with BPF_RET|BPF_K".to_owned());
        }
        for (pc, insn) in prog.iter().enumerate() {
            match insn.code {
                0x20 => {
                    if insn.k >= 64 || !insn.k.is_multiple_of(4) {
                        return Err(format!(
                            "invalid seccomp_data load offset {} at pc {pc}",
                            insn.k
                        ));
                    }
                }
                0x54 | 0x06 => {}
                0x05 => {
                    let delta = usize::try_from(insn.k).map_err(|e| e.to_string())?;
                    if pc.checked_add(1).and_then(|n| n.checked_add(delta)) >= Some(prog.len()) {
                        return Err(format!("BPF_JA out of bounds at pc {pc}"));
                    }
                }
                0x15 | 0x25 | 0x35 => {
                    let t = pc + 1 + usize::from(insn.jt);
                    let f = pc + 1 + usize::from(insn.jf);
                    if t >= prog.len() || f >= prog.len() {
                        return Err(format!("conditional jump out of bounds at pc {pc}"));
                    }
                }
                other => return Err(format!("unexpected BPF opcode 0x{other:x} at pc {pc}")),
            }
        }
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn compiled_bpf_enforces_setid_rules_across_all_architectures()
    -> Result<(), Box<dyn std::error::Error>> {
        let poison_hi = 0xdead_beef_0000_0000_u64;

        for mode in [SeccompMode::Standard, SeccompMode::Strict] {
            for arch in [TargetArch::x86_64, TargetArch::aarch64, TargetArch::riscv64] {
                let prog = compile_seccomp_bpf(mode, arch)?;
                validate_kernel_seccomp_bpf(&prog)?;
                let audit = audit_arch_for(arch);
                let run = |nr: u32, args: [u64; 6]| -> Result<u32, String> {
                    eval_bpf(&prog, &encode_seccomp_data(nr, audit, args))
                };

                // Wrong architecture (e.g. 32-bit i386 compat) is killed immediately.
                assert_eq!(
                    eval_bpf(&prog, &encode_seccomp_data(0, AUDIT_ARCH_I386, [0; 6]))?,
                    SECCOMP_RET_KILL_PROCESS
                );

                // `openat2` (437 on all three architectures) is allowed.
                assert_eq!(run(437, [0; 6])?, SECCOMP_RET_ALLOW);

                // `io_uring_setup` (425), `io_uring_enter` (426), and `io_uring_register` (427)
                // are denied with EPERM in BOTH Standard and Strict modes on every architecture
                // (including x32 aliases on x86_64) as part of the set-ID policy.
                for ring_nr in [425_u32, 426, 427] {
                    assert_eq!(
                        run(ring_nr, [0; 6])?,
                        SECCOMP_RET_EPERM,
                        "mode={mode:?} arch={arch:?} io_uring nr={ring_nr}"
                    );
                    if arch == TargetArch::x86_64 {
                        assert_eq!(
                            run(x32(ring_nr), [0; 6])?,
                            SECCOMP_RET_EPERM,
                            "mode={mode:?} arch={arch:?} x32 io_uring nr={ring_nr}"
                        );
                    }
                }

                let (o_dir, o_tmpfile, other_o_tmpfile, mode_calls, open_calls, mq_nr, ipc_nrs) =
                    match arch {
                        TargetArch::x86_64 => (
                            0o20_0000_u64,
                            0o2020_0000_u64,
                            0o2004_0000_u64,
                            vec![
                                (83_u32, 1_usize), // mkdir
                                (85, 1),           // creat
                                (90, 1),           // chmod
                                (91, 1),           // fchmod
                                (133, 1),          // mknod
                                (258, 2),          // mkdirat
                                (259, 2),          // mknodat
                                (268, 2),          // fchmodat
                                (452, 2),          // fchmodat2
                                (x32(83), 1),      // x32 mkdir
                                (x32(85), 1),      // x32 creat
                                (x32(90), 1),      // x32 chmod
                                (x32(91), 1),      // x32 fchmod
                                (x32(133), 1),     // x32 mknod
                                (x32(258), 2),     // x32 mkdirat
                                (x32(259), 2),     // x32 mknodat
                                (x32(268), 2),     // x32 fchmodat
                                (x32(452), 2),     // x32 fchmodat2
                            ],
                            vec![
                                (2_u32, 1_usize, 2_usize), // open
                                (257, 2, 3),               // openat
                                (x32(2), 1, 2),            // x32 open
                                (x32(257), 2, 3),          // x32 openat
                            ],
                            vec![240_u32, x32(240)],
                            vec![(68_u32, 1_usize), (64, 2), (29, 2)], // msgget, semget, shmget
                        ),
                        TargetArch::aarch64 => (
                            0o4_0000_u64,
                            0o2004_0000_u64,
                            0o2020_0000_u64,
                            vec![
                                (33_u32, 2_usize), // mknodat
                                (34, 2),           // mkdirat
                                (52, 1),           // fchmod
                                (53, 2),           // fchmodat
                                (452, 2),          // fchmodat2
                            ],
                            vec![(56_u32, 2_usize, 3_usize)], // openat
                            vec![180_u32],
                            vec![(186_u32, 1_usize), (190, 2), (194, 2)],
                        ),
                        TargetArch::riscv64 => (
                            0o20_0000_u64,
                            0o2020_0000_u64,
                            0o2004_0000_u64,
                            vec![(33_u32, 2_usize), (34, 2), (52, 1), (53, 2), (452, 2)],
                            vec![(56_u32, 2_usize, 3_usize)],
                            vec![180_u32],
                            vec![(186_u32, 1_usize), (190, 2), (194, 2)],
                        ),
                    };

                // 1. Unconditional-mode calls: ordinary modes pass; S_ISUID/S_ISGID (incl. high-32 garbage) -> EPERM.
                for (nr, mode_arg) in mode_calls {
                    for ok_mode in [0_u64, 0o600, 0o644, 0o755, 0o1777] {
                        let mut args = [0_u64; 6];
                        if let Some(slot) = args.get_mut(mode_arg) {
                            *slot = ok_mode;
                        }
                        assert_eq!(
                            run(nr, args)?,
                            SECCOMP_RET_ALLOW,
                            "arch={arch:?} nr={nr} mode={ok_mode:#o}"
                        );
                    }
                    for bad_mode in [
                        0o4000_u64,
                        0o2000,
                        0o4755,
                        0o2755,
                        0o6755,
                        poison_hi | 0o4755,
                        poison_hi | 0o2755,
                    ] {
                        let mut args = [0_u64; 6];
                        if let Some(slot) = args.get_mut(mode_arg) {
                            *slot = bad_mode;
                        }
                        assert_eq!(
                            run(nr, args)?,
                            SECCOMP_RET_EPERM,
                            "arch={arch:?} nr={nr} mode={bad_mode:#o}"
                        );
                    }
                }

                // 2. open / openat: only O_CREAT or arch-specific O_TMPFILE inspect mode.
                for (nr, flags_arg, mode_arg) in open_calls {
                    // Non-creating opens (O_RDONLY, O_DIRECTORY alone, wrong-arch O_TMPFILE, or
                    // O_PATH combined with O_CREAT/O_TMPFILE where Linux discards creation flags)
                    // allow stale or arbitrary mode bits without false positives.
                    for non_create_flags in [
                        O_RDONLY,
                        o_dir,
                        other_o_tmpfile,
                        O_PATH,
                        O_PATH | O_CREAT,
                        O_PATH | o_tmpfile,
                        poison_hi | O_PATH | O_CREAT,
                    ] {
                        let mut args = [0_u64; 6];
                        if let Some(s) = args.get_mut(flags_arg) {
                            *s = non_create_flags;
                        }
                        if let Some(s) = args.get_mut(mode_arg) {
                            *s = 0o6755;
                        }
                        assert_eq!(
                            run(nr, args)?,
                            SECCOMP_RET_ALLOW,
                            "arch={arch:?} nr={nr} non_create_flags={non_create_flags:#o}"
                        );
                    }
                    // Creating opens (O_CREAT or arch O_TMPFILE): ordinary mode allowed, SUID/SGID -> EPERM.
                    for create_flags in [O_CREAT, O_CREAT | 2, o_tmpfile, o_tmpfile | 2] {
                        let mut ok_args = [0_u64; 6];
                        if let Some(s) = ok_args.get_mut(flags_arg) {
                            *s = create_flags;
                        }
                        if let Some(s) = ok_args.get_mut(mode_arg) {
                            *s = 0o644;
                        }
                        assert_eq!(run(nr, ok_args)?, SECCOMP_RET_ALLOW);

                        for bad_mode in [0o4755_u64, 0o2755, 0o6755, poison_hi | 0o4000] {
                            let mut bad_args = [0_u64; 6];
                            if let Some(s) = bad_args.get_mut(flags_arg) {
                                *s = create_flags;
                            }
                            if let Some(s) = bad_args.get_mut(mode_arg) {
                                *s = bad_mode;
                            }
                            assert_eq!(
                                run(nr, bad_args)?,
                                SECCOMP_RET_EPERM,
                                "arch={arch:?} nr={nr} flags={create_flags:#o} mode={bad_mode:#o}"
                            );
                        }
                    }
                }

                // 3. mq_open: only O_CREAT inspects mode (arg2).
                for nr in mq_nr {
                    assert_eq!(run(nr, [0, O_RDONLY, 0o6755, 0, 0, 0])?, SECCOMP_RET_ALLOW);
                    assert_eq!(run(nr, [0, O_CREAT, 0o600, 0, 0, 0])?, SECCOMP_RET_ALLOW);
                    assert_eq!(run(nr, [0, O_CREAT, 0o4600, 0, 0, 0])?, SECCOMP_RET_EPERM);
                    assert_eq!(run(nr, [0, O_CREAT, 0o2600, 0, 0, 0])?, SECCOMP_RET_EPERM);
                    assert_eq!(
                        run(nr, [0, O_CREAT, poison_hi | 0o2000, 0, 0, 0])?,
                        SECCOMP_RET_EPERM
                    );
                }

                // 4. SysV IPC (msgget/semget/shmget): NOT blocked even when IPC_EXCL (0o2000) or
                //    IPC_NOWAIT / SHM_HUGETLB (0o4000) is set alongside IPC_CREAT (0o1000).
                for (nr, flg_arg) in ipc_nrs {
                    let mut args = [0_u64; 6];
                    if let Some(s) = args.get_mut(flg_arg) {
                        *s = 0o1000 | 0o2000 | 0o4000 | 0o600;
                    }
                    assert_eq!(
                        run(nr, args)?,
                        SECCOMP_RET_ALLOW,
                        "arch={arch:?} ipc nr={nr}"
                    );
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod landlock_enforcement_tests {
    #[test]
    fn classify_landlock_enforcement_covers_all_states() {
        assert_eq!(
            crate::classify_landlock_enforcement(false, Some(7)),
            crate::LandlockEnforcement::Disabled
        );
        assert_eq!(
            crate::classify_landlock_enforcement(false, None).state_line(),
            "landlock disabled"
        );
        assert!(!crate::classify_landlock_enforcement(false, Some(7)).is_enforcing());

        assert_eq!(
            crate::classify_landlock_enforcement(true, None),
            crate::LandlockEnforcement::Unavailable
        );
        assert_eq!(
            crate::classify_landlock_enforcement(true, Some(0)),
            crate::LandlockEnforcement::Unavailable
        );
        assert_eq!(
            crate::classify_landlock_enforcement(true, None).state_line(),
            "landlock unavailable"
        );
        assert!(!crate::classify_landlock_enforcement(true, None).is_enforcing());

        for abi in 1..crate::LANDLOCK_TARGET_ABI_VERSION {
            let state = crate::classify_landlock_enforcement(true, Some(abi));
            assert_eq!(state, crate::LandlockEnforcement::Partial { abi });
            assert_eq!(state.state_line(), format!("landlock partial abi={abi}"));
            assert!(state.is_enforcing());
        }

        for abi in crate::LANDLOCK_TARGET_ABI_VERSION..=9 {
            let state = crate::classify_landlock_enforcement(true, Some(abi));
            assert_eq!(state, crate::LandlockEnforcement::Enforced { abi });
            assert_eq!(state.state_line(), format!("landlock enforced abi={abi}"));
            assert!(state.is_enforcing());
        }
    }

    #[test]
    fn landlock_writable_paths_matches_rw_and_socket_grants_only()
    -> Result<(), Box<dyn std::error::Error>> {
        let (cfg, _) = miraserve_config::parse_kdl(
            "writable-paths.kdl",
            r#"
server {
    listen ":443"
    tls {
        acme { email "ops@example.com" }
    }
    sandbox {
        read-tree "/srv/sites"
        socket-tree "/run/custom-fpm"
    }
}
site "app.example.com" {
    root "/var/www/app"
    ai-publish {
        storage "/var/lib/miraserve/releases/app"
        require-signature "ed25519:/etc/miraserve/deploy.pub"
    }
    route "*.php" {
        fastcgi-pass "unix:/run/php/php8.3-fpm.sock"
    }
}
"#,
        )?;
        let policy = crate::SandboxPolicy::from_config_with_file(
            &cfg,
            None,
            Some(std::path::Path::new("/var/lib/miraserve/acme")),
        );
        let writable = policy.landlock_writable_paths();
        assert!(writable.contains(&std::path::PathBuf::from("/var/lib/miraserve/acme")));
        assert!(writable.contains(&std::path::PathBuf::from("/var/lib/miraserve/releases/app")));
        assert!(writable.contains(&std::path::PathBuf::from("/run/custom-fpm")));
        assert!(writable.contains(&std::path::PathBuf::from("/run/php/php8.3-fpm.sock")));
        assert!(
            !writable.contains(&std::path::PathBuf::from("/var/www/app")),
            "read-only docroot must not appear in landlock_writable_paths"
        );
        assert!(
            !writable.contains(&std::path::PathBuf::from("/srv/sites")),
            "read-only read-tree must not appear in landlock_writable_paths"
        );
        Ok(())
    }

    #[test]
    fn probe_landlock_enforcement_is_non_installing_and_matches_apply()
    -> Result<(), Box<dyn std::error::Error>> {
        let (cfg_on, _) = miraserve_config::parse_kdl(
            "probe-on.kdl",
            r#"server { listen "127.0.0.1:8443"; sandbox { landlock #true; seccomp "off" } }"#,
        )?;
        let (cfg_off, _) = miraserve_config::parse_kdl(
            "probe-off.kdl",
            r#"server { listen "127.0.0.1:8443"; sandbox { landlock #false; seccomp "off" } }"#,
        )?;
        let policy_on = crate::SandboxPolicy::from_config_with_file(&cfg_on, None, None);
        let policy_off = crate::SandboxPolicy::from_config_with_file(&cfg_off, None, None);

        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(
                crate::probe_landlock_enforcement(&policy_off),
                crate::LandlockEnforcement::Unavailable,
                "non-Linux must always report landlock unavailable even when landlock #false"
            );
            assert_eq!(
                crate::probe_landlock_enforcement(&policy_on),
                crate::LandlockEnforcement::Unavailable
            );
        }

        #[cfg(target_os = "linux")]
        {
            fn read_no_new_privs() -> Result<String, Box<dyn std::error::Error>> {
                let status = std::fs::read_to_string("/proc/thread-self/status")?;
                let val = status
                    .lines()
                    .find_map(|line| line.strip_prefix("NoNewPrivs:"))
                    .map(str::trim)
                    .ok_or("missing NoNewPrivs line in /proc/thread-self/status")?;
                Ok(val.to_owned())
            }

            // Run probe checks on a fresh thread so any sibling test's state does not interfere.
            let nnp_before = read_no_new_privs()?;
            assert_eq!(
                crate::probe_landlock_enforcement(&policy_off),
                crate::LandlockEnforcement::Disabled
            );
            let probed = crate::probe_landlock_enforcement(&policy_on);
            // Verify probing installed NO Landlock ruleset AND did not flip NoNewPrivs:
            // perform REAL file reads (not `metadata`, which Landlock does not restrict).
            let nnp_after = read_no_new_privs()?;
            assert_eq!(
                nnp_after, nnp_before,
                "probe_landlock_enforcement must not modify NoNewPrivs"
            );
            assert!(
                std::fs::read_to_string("/proc/sys/kernel/osrelease").is_ok(),
                "probe_landlock_enforcement must not restrict real file reads on the calling thread"
            );

            // Verify probing agrees with actual `apply_landlock_current_thread` on a disposable
            // thread AND confirm that real file reads DO fail once `apply_landlock_current_thread`
            // installs `policy_on` (proving our real-read assertion catches confinement).
            let (apply_outcome, read_blocked_after_apply) = std::thread::spawn(move || {
                let mut p = policy_on;
                let res = p
                    .finalize_grants()
                    .and_then(|()| crate::apply_landlock_current_thread(&p));
                let blocked = std::fs::read_to_string("/proc/thread-self/status").is_err();
                (res, blocked)
            })
            .join()
            .map_err(|_| "apply_landlock_current_thread thread panicked")?;
            match (probed, apply_outcome) {
                (
                    crate::LandlockEnforcement::Enforced { abi },
                    Ok(crate::EnforcementStatus::Enforced),
                ) => {
                    assert!(abi >= crate::LANDLOCK_TARGET_ABI_VERSION);
                    assert!(
                        read_blocked_after_apply,
                        "expected real file read of /proc/thread-self/status to fail under enforcing Landlock"
                    );
                }
                (
                    crate::LandlockEnforcement::Partial { abi },
                    Ok(crate::EnforcementStatus::PartiallyEnforced),
                ) => {
                    assert!((1..crate::LANDLOCK_TARGET_ABI_VERSION).contains(&abi));
                    assert!(
                        read_blocked_after_apply,
                        "expected real file read of /proc/thread-self/status to fail under partial Landlock"
                    );
                }
                (
                    crate::LandlockEnforcement::Unavailable,
                    Err(crate::SandboxError::Landlock(_)),
                ) => {}
                (other_probe, other_apply) => {
                    return Err(format!(
                        "probe_landlock_enforcement ({other_probe:?}) disagreed with apply_landlock_current_thread ({other_apply:?})"
                    )
                    .into());
                }
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn writable_policy_grants_reports_pinned_object_and_never_omits_absent_candidates()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let base = std::env::temp_dir().join(format!(
            "miraserve-sbx-pinned-grant-{}-{nanos}",
            std::process::id()
        ));
        if let Some(reason) = miraserve_config::sandbox_tree_rejection(&base.to_string_lossy()) {
            eprintln!(
                "skipping writable_policy_grants_reports_pinned_object_and_never_omits_absent_candidates: temp path '{}' rejected by sandbox tree validator ({reason})",
                base.display()
            );
            return Ok(());
        }
        let dir_a = base.join("release-a");
        let dir_b = base.join("release-b");
        let link = base.join("acme-link");
        let existing_sock_tree = base.join("live-fpm");
        let absent_sock_tree = base.join("absent-pool");
        let missing_publish = base.join("future-publish");
        std::fs::create_dir_all(&dir_a)?;
        std::fs::create_dir_all(&dir_b)?;
        std::fs::create_dir_all(&existing_sock_tree)?;
        symlink(&dir_a, &link)?;

        let canon_a = std::fs::canonicalize(&dir_a)?;
        let canon_b = std::fs::canonicalize(&dir_b)?;
        let canon_sock_tree = std::fs::canonicalize(&existing_sock_tree)?;

        let kdl = format!(
            r#"
server {{
    listen ":443"
    tls {{ acme {{ email "ops@example.com" }} }}
    sandbox {{
        socket-tree "{}" "{}"
    }}
}}
site "app.example.com" {{
    root "/var/www/app"
    ai-publish {{
        storage "{}"
        require-signature "ed25519:/etc/miraserve/deploy.pub"
    }}
    route "*.php" {{
        fastcgi-pass "unix:/run/nonexistent-miraserve-test/absent.sock"
    }}
}}
"#,
            kdl_escape_test_path(&existing_sock_tree),
            kdl_escape_test_path(&absent_sock_tree),
            kdl_escape_test_path(&missing_publish)
        );
        let (cfg, _) = miraserve_config::parse_kdl("pinned-grant.kdl", &kdl)?;
        let policy = crate::SandboxPolicy::from_config_with_file(&cfg, None, Some(&link));

        // Before swapping `link`, verify the superset policy-report contract:
        // - `link` resolves to `canon_a` (`Installed`),
        // - `existing_sock_tree` resolves to `canon_sock_tree` (`Installed`),
        // - `missing_publish` is `Missing`,
        // - absent `socket-tree` and absent FastCGI socket are BOTH `Missing` (never omitted!).
        let before = policy.writable_policy_grants()?;
        assert!(
            before
                .iter()
                .any(|g| matches!(g, crate::WritableGrant::Installed(path) if path == &canon_a)),
            "expected pinned dir_a in grants: {before:?}"
        );
        assert!(
            before.iter().any(
                |g| matches!(g, crate::WritableGrant::Installed(path) if path == &canon_sock_tree)
            ),
            "expected existing socket-tree in grants: {before:?}"
        );
        assert!(
            before
                .iter()
                .any(|g| matches!(g, crate::WritableGrant::Missing(p) if p == &missing_publish)),
            "expected missing publish storage as Missing: {before:?}"
        );
        assert!(
            before
                .iter()
                .any(|g| matches!(g, crate::WritableGrant::Missing(p) if p == &absent_sock_tree)),
            "absent socket-tree must be reported as Missing (superset rule): {before:?}"
        );
        assert!(
            before.iter().any(|g| matches!(
                g,
                crate::WritableGrant::Missing(p)
                    if p == std::path::Path::new("/run/nonexistent-miraserve-test/absent.sock")
            )),
            "absent Unix socket must be reported as Missing (superset rule): {before:?}"
        );

        // Now atomically swap `link` from `dir_a` to `dir_b` AFTER policy construction!
        std::fs::remove_file(&link)?;
        symlink(&dir_b, &link)?;

        let after = policy.writable_policy_grants();
        #[cfg(target_os = "linux")]
        {
            // On Linux, `writable_policy_grants` derives directly from the pinned O_PATH fd
            // (`/proc/self/fd/<fd>`) and therefore still reports `canon_a`, NEVER `canon_b`.
            let after_grants = after?;
            assert!(
                after_grants.iter().any(
                    |g| matches!(g, crate::WritableGrant::Installed(path) if path == &canon_a)
                ),
                "Linux must report the pinned object (dir_a), got: {after_grants:?}"
            );
            assert!(
                after_grants.iter().all(|g| match g {
                    crate::WritableGrant::Installed(path) | crate::WritableGrant::Missing(path) => {
                        path != &canon_b
                    }
                }),
                "Linux must never report swapped target dir_b: {after_grants:?}"
            );
            // Deleting `dir_a` itself makes the pinned fd unlinked -> must fail closed.
            std::fs::remove_dir(&dir_a)?;
            assert!(
                policy.writable_policy_grants().is_err(),
                "unlinked pinned grant must fail closed"
            );
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = canon_b;
            // On non-Linux Unix, canonicalizing `link` sees `dir_b`'s identity != pinned `dir_a`'s
            // identity and MUST fail closed rather than printing `dir_b`.
            assert!(
                after.is_err(),
                "swapped symlink alias must fail identity check instead of reporting dir_b: {after:?}"
            );
        }

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn writable_policy_grants_reports_uncreatable_and_unopenable_candidates_as_missing()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        if rustix::process::geteuid().is_root() {
            return Ok(());
        }
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let base = std::env::temp_dir().join(format!(
            "miraserve-sbx-tenant-superset-{}-{nanos}",
            std::process::id()
        ));
        if let Some(reason) = miraserve_config::sandbox_tree_rejection(&base.to_string_lossy()) {
            eprintln!(
                "skipping writable_policy_grants_reports_uncreatable_and_unopenable_candidates_as_missing: temp path '{}' rejected by sandbox tree validator ({reason})",
                base.display()
            );
            return Ok(());
        }
        let ro_parent = base.join("ro-parent");
        let locked_parent = base.join("locked-000");
        let missing_tenant_store = ro_parent.join("releases");
        let unopenable_sock_tree = locked_parent.join("pool");
        std::fs::create_dir_all(&ro_parent)?;
        std::fs::create_dir_all(&unopenable_sock_tree)?;
        std::fs::set_permissions(&ro_parent, std::fs::Permissions::from_mode(0o555))?;
        std::fs::set_permissions(&locked_parent, std::fs::Permissions::from_mode(0o000))?;

        let kdl = format!(
            r#"
server {{
    listen ":443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }}
    sandbox {{
        socket-tree "{}"
    }}
}}
site "tenant.example.com" {{
    root "/var/www/tenant"
    ai-publish {{
        storage "{}"
        require-signature "ed25519:/etc/miraserve/deploy.pub"
    }}
}}
"#,
            kdl_escape_test_path(&unopenable_sock_tree),
            kdl_escape_test_path(&missing_tenant_store)
        );
        let (cfg, _) = miraserve_config::parse_kdl("tenant-superset.kdl", &kdl)?;
        let mut policy = crate::SandboxPolicy::from_config_with_file(&cfg, None, None);
        policy
            .tenant_only_paths
            .insert(missing_tenant_store.clone());

        let grants = policy.writable_policy_grants()?;
        assert!(
            grants.contains(&crate::WritableGrant::Missing(missing_tenant_store)),
            "missing tenant-only publish store under unwritable parent must still be emitted as Missing (no accessat heuristic), got: {grants:?}"
        );
        assert!(
            grants.contains(&crate::WritableGrant::Missing(unopenable_sock_tree)),
            "EACCES-unopenable socket-tree must be emitted as Missing, got: {grants:?}"
        );

        let _ = std::fs::set_permissions(&ro_parent, std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::set_permissions(&locked_parent, std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    /// Pins exact `74a8243` runtime parity for `apply_sandbox` and `apply_landlock_current_thread`
    /// when Landlock is disabled (`landlock #false`, `seccomp "off"`), and pins the derived
    /// requested policy path vectors for a fixed configuration (Codex Round-2 P1 #10 & Round-3 item 4).
    #[test]
    #[allow(clippy::too_many_lines)]
    fn runtime_sandbox_disabled_and_requested_policy_paths_match_74a8243()
    -> Result<(), Box<dyn std::error::Error>> {
        let (cfg_off, _) = miraserve_config::parse_kdl(
            "disabled-parity.kdl",
            r#"server { listen "127.0.0.1:8443"; sandbox { landlock #false; seccomp "off" } }"#,
        )?;
        let policy_off = crate::SandboxPolicy::from_config_with_file(&cfg_off, None, None);
        let report_off = crate::apply_sandbox(&policy_off)?;
        assert_eq!(
            report_off.landlock,
            crate::EnforcementStatus::Disabled,
            "apply_sandbox with landlock #false must return Disabled on every platform (74a8243 parity)"
        );
        assert_eq!(report_off.seccomp, crate::EnforcementStatus::Disabled);
        assert_eq!(
            crate::apply_landlock_current_thread(&policy_off)?,
            crate::EnforcementStatus::Disabled,
            "apply_landlock_current_thread with landlock #false must return Disabled immediately"
        );

        let (cfg_fixed, _) = miraserve_config::parse_kdl(
            "fixed-ruleset.kdl",
            r#"
server {
    listen ":443"
    tls { acme { email "ops@example.com" } }
    sandbox {
        landlock #true
        seccomp "strict"
        read-tree "/srv/sites"
        socket-tree "/run/custom-fpm"
    }
}
site "app.example.com" {
    root "/var/www/app"
    ai-publish {
        storage "/var/lib/miraserve/releases/app"
        require-signature "ed25519:/etc/miraserve/deploy.pub"
    }
    route "*.php" {
        fastcgi-pass "unix:/run/php/php8.3-fpm.sock"
    }
}
"#,
        )?;
        let policy_fixed = crate::SandboxPolicy::from_config_with_file(
            &cfg_fixed,
            Some(std::path::Path::new("/etc/miraserve/conf/miraserve.kdl")),
            Some(std::path::Path::new("/var/lib/miraserve/acme")),
        );
        assert!(policy_fixed.landlock);
        assert_eq!(policy_fixed.seccomp, miraserve_config::SeccompMode::Strict);
        assert_eq!(
            policy_fixed.read_write_paths,
            vec![
                std::path::PathBuf::from("/var/lib/miraserve/acme"),
                std::path::PathBuf::from("/var/lib/miraserve/releases/app"),
            ]
        );
        assert_eq!(
            policy_fixed.socket_paths,
            vec![
                std::path::PathBuf::from("/run/custom-fpm"),
                std::path::PathBuf::from("/run/php/php8.3-fpm.sock"),
            ]
        );
        assert!(
            policy_fixed
                .read_only_paths
                .contains(&std::path::PathBuf::from("/etc/miraserve/conf"))
        );
        assert!(
            policy_fixed
                .read_only_paths
                .contains(&std::path::PathBuf::from("/etc/miraserve/deploy.pub"))
        );
        assert!(
            !policy_fixed
                .read_only_paths
                .contains(&std::path::PathBuf::from("/etc/miraserve"))
        );
        assert!(
            policy_fixed
                .read_only_paths
                .contains(&std::path::PathBuf::from("/var/www/app"))
        );
        assert!(
            policy_fixed
                .read_only_paths
                .contains(&std::path::PathBuf::from("/srv/sites"))
        );
        #[cfg(not(target_os = "linux"))]
        {
            let rep_on = crate::apply_sandbox(&policy_fixed)?;
            assert_eq!(
                rep_on.landlock,
                crate::EnforcementStatus::UnsupportedPlatform
            );
            assert_eq!(
                rep_on.seccomp,
                crate::EnforcementStatus::UnsupportedPlatform
            );
        }
        Ok(())
    }

    #[cfg(unix)]
    mod kdl_test_util {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../miraserve-config/tests/common/mod.rs"
        ));
    }

    #[cfg(unix)]
    use kdl_test_util::kdl_escape_path as kdl_escape_test_path;

    #[cfg(target_os = "linux")]
    use kdl_test_util::kdl_escape_str as kdl_escape_test_str;

    #[cfg(target_os = "linux")]
    fn short_socket_test_dir(tag: &str) -> Result<std::path::PathBuf, std::io::Error> {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};

        static SEQ: AtomicU64 = AtomicU64::new(0);
        let default_tmp = std::env::temp_dir();
        let resolved = std::fs::canonicalize(&default_tmp).unwrap_or_else(|_| default_tmp.clone());
        let root = if default_tmp.as_os_str().len() <= 52 && resolved.as_os_str().len() <= 52 {
            default_tmp
        } else {
            std::path::PathBuf::from("/tmp")
        };
        let pid = std::process::id();
        let salt = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::from(d.subsec_nanos()) & 0xffff);
        loop {
            let seq = SEQ.fetch_add(1, Ordering::Relaxed);
            let raw = root.join(format!("ms-u-{tag}-{pid}-{salt:x}-{seq}"));
            match std::fs::create_dir(&raw) {
                Ok(()) => return std::fs::canonicalize(&raw),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(err),
            }
        }
    }

    /// White-box companion to Test 4 (PARITY): calls `linux::assemble_landlock_rules` directly on
    /// a fixture with a `socket-tree`, one real exact socket, one absent exact socket, and two
    /// `read-tree`s, and asserts the exact ordered `(canonical_path, AccessFs)` rule list against
    /// an independently constructed expected sequence (never derived from `policy`), plus verifies
    /// that a directory at an exact FastCGI path is omitted from `sock_rules`.
    #[cfg(target_os = "linux")]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn assembled_landlock_rule_list_and_masks_match_015_and_omit_non_socket_exact_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::collections::BTreeSet;
        use std::os::fd::AsRawFd as _;
        use std::os::unix::net::UnixListener;
        use std::path::{Path, PathBuf};

        use landlock::{ABI, Access as _, AccessFs};

        let base = short_socket_test_dir("rl")?;
        if let Some(reason) = miraserve_config::sandbox_tree_rejection(&base.to_string_lossy()) {
            eprintln!(
                "skipping assembled_landlock_rule_list_and_masks_match_015_and_omit_non_socket_exact_paths: temp path '{}' rejected by tree validator ({reason})",
                base.display()
            );
            let _ = std::fs::remove_dir_all(&base);
            return Ok(());
        }
        let rt1 = base.join("a_rt1");
        let docroot = base.join("b_docroot");
        let rt2 = base.join("c_rt2");
        let absent_sock = base.join("d_absent.sock");
        let real_sock = base.join("e_real.sock");
        let sock_tree = base.join("f_stree");
        std::fs::create_dir_all(&rt1)?;
        std::fs::create_dir_all(&docroot)?;
        std::fs::create_dir_all(&rt2)?;
        std::fs::create_dir_all(&sock_tree)?;
        let _listener = UnixListener::bind(&real_sock)?;

        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:8443"
    sandbox {{
        landlock #true
        seccomp "off"
        read-tree "{rt1}" "{rt2}"
        socket-tree "{sock_tree}"
    }}
}}
site "masks.example.test" {{
    root "{docroot}"
    route "/real.php" {{
        fastcgi-pass "unix:{real_sock}"
    }}
    route "/absent.php" {{
        fastcgi-pass "unix:{absent_sock}"
    }}
}}
"#,
            rt1 = kdl_escape_test_path(&rt1),
            rt2 = kdl_escape_test_path(&rt2),
            sock_tree = kdl_escape_test_path(&sock_tree),
            docroot = kdl_escape_test_path(&docroot),
            real_sock = kdl_escape_test_path(&real_sock),
            absent_sock = kdl_escape_test_path(&absent_sock),
        );
        let (cfg, _) = miraserve_config::parse_kdl("masks.kdl", &kdl)?;
        let mut policy = crate::SandboxPolicy::from_config_with_file(&cfg, None, None);
        policy.finalize_grants()?;

        let all_abi = AccessFs::from_all(ABI::V5);
        let ro_dir_mask = (AccessFs::ReadFile | AccessFs::ReadDir) & all_abi;
        let ro_file_mask = ro_dir_mask & AccessFs::ReadFile;
        let sock_mask = (AccessFs::ReadFile | AccessFs::WriteFile) & all_abi;

        // Independently construct the exact expected ordered `(canonical_path, mask)` rule list.
        let mut expected_ro_paths = BTreeSet::new();
        for sys_ro in [
            "/etc/ssl/certs",
            "/etc/ssl/openssl.cnf",
            "/etc/ssl/cert.pem",
            "/etc/ca-certificates",
            "/etc/ca-certificates.conf",
            "/usr/share/ca-certificates",
            "/usr/local/share/ca-certificates",
            "/etc/pki/tls/certs",
            "/etc/pki/tls/cert.pem",
            "/etc/pki/ca-trust",
            "/usr/share/pki/ca-trust-source",
            "/usr/share/pki/trust",
            "/var/lib/ca-certificates",
            "/etc/resolv.conf",
            "/etc/hosts",
        ] {
            let p = PathBuf::from(sys_ro);
            if p.exists() {
                if let Ok(canon) = std::fs::canonicalize(&p)
                    && canon != p
                    && canon.is_file()
                {
                    expected_ro_paths.insert(canon);
                }
                expected_ro_paths.insert(p);
            }
        }
        if Path::new("/etc/miraserve/auth").is_dir() {
            expected_ro_paths.insert(PathBuf::from("/etc/miraserve/auth"));
        }
        expected_ro_paths.insert(rt1.clone());
        expected_ro_paths.insert(docroot.clone());
        expected_ro_paths.insert(rt2.clone());

        let mut expected_rules: Vec<(PathBuf, landlock::BitFlags<AccessFs>)> = Vec::new();
        for p in &expected_ro_paths {
            let canon = std::fs::canonicalize(p)?;
            let mask = if std::fs::metadata(p)?.is_dir() {
                ro_dir_mask
            } else {
                ro_file_mask
            };
            expected_rules.push((canon, mask));
        }
        expected_rules.push((std::fs::canonicalize(&real_sock)?, sock_mask));
        expected_rules.push((std::fs::canonicalize(&sock_tree)?, sock_mask));

        let mut notes = Vec::new();
        let assembled = crate::linux::assemble_landlock_rules(&policy, &mut notes)?;
        let actual_rules: Vec<(PathBuf, landlock::BitFlags<AccessFs>)> = assembled
            .readonly_rules
            .into_iter()
            .chain(assembled.writable_rules)
            .chain(assembled.sock_rules)
            .map(|(fd, mask)| {
                let target = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))?;
                Ok((target, mask))
            })
            .collect::<Result<Vec<_>, std::io::Error>>()?;

        assert_eq!(
            actual_rules, expected_rules,
            "assembled Landlock rule list with masks in order must match 0.1.5 exactly"
        );
        assert_eq!(
            notes,
            vec![format!(
                "missing Landlock Unix socket path(s) omitted at startup (restart after creating): {}",
                absent_sock.display()
            )]
        );

        // Also confirm a directory used ONLY as an exact FastCGI path is omitted from `sock_rules`.
        let bad_dir = base.join("g_bad_dir");
        std::fs::create_dir_all(&bad_dir)?;
        let bad_kdl = format!(
            r#"
server {{
    listen "127.0.0.1:8443"
    sandbox {{ landlock #true; seccomp "off" }}
}}
site "bad.example.test" {{
    root "{docroot}"
    route "/bad.php" {{
        fastcgi-pass "unix:{bad_dir}"
    }}
}}
"#,
            docroot = kdl_escape_test_path(&docroot),
            bad_dir = kdl_escape_test_path(&bad_dir),
        );
        let (bad_cfg, _) = miraserve_config::parse_kdl("bad.kdl", &bad_kdl)?;
        let mut bad_policy = crate::SandboxPolicy::from_config_with_file(&bad_cfg, None, None);
        bad_policy.finalize_grants()?;
        let mut bad_notes = Vec::new();
        let bad_assembled = crate::linux::assemble_landlock_rules(&bad_policy, &mut bad_notes)?;
        assert!(
            bad_assembled.sock_rules.is_empty(),
            "exact directory socket entry with no other role must produce zero sock_rules"
        );

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    /// White-box rename/identity oracle: a real Unix socket is prepared, then renamed aside and
    /// replaced by a directory at the same pathname before rule assembly. Asserts directly via
    /// `fstat` on the descriptor inside `assembled.sock_rules` that its `(st_dev, st_ino)`
    /// identity, `FileType::Socket`, and `sock_mask` stay pinned to the original socket inode
    /// (never the replacement directory).
    #[cfg(target_os = "linux")]
    #[test]
    fn real_socket_replaced_by_directory_assembled_rule_keeps_original_inode_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::MetadataExt as _;
        use std::os::unix::net::UnixListener;

        use landlock::{ABI, Access as _, AccessFs};
        use rustix::fs::{FileType, fstat};

        let base = short_socket_test_dir("rid")?;
        let docroot = base.join("www");
        let ep_sock = base.join("ep.sock");
        let moved_sock = base.join("ep-m.sock");
        std::fs::create_dir_all(&docroot)?;
        let _listener = UnixListener::bind(&ep_sock)?;

        let orig_md = std::fs::metadata(&ep_sock)?;
        let original_id = (orig_md.dev(), orig_md.ino());

        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:8443"
    sandbox {{ landlock #true; seccomp "off" }}
}}
site "rid.example.test" {{
    root "{docroot}"
    route "/app.php" {{
        fastcgi-pass "unix:{ep_sock}"
    }}
}}
"#,
            docroot = kdl_escape_test_path(&docroot),
            ep_sock = kdl_escape_test_path(&ep_sock),
        );
        let (cfg, _) = miraserve_config::parse_kdl("rid.kdl", &kdl)?;
        let mut policy = crate::SandboxPolicy::from_config_with_file(&cfg, None, None);
        policy.finalize_grants()?;

        std::fs::rename(&ep_sock, &moved_sock)?;
        std::fs::create_dir_all(&ep_sock)?;
        let dir_md = std::fs::metadata(&ep_sock)?;
        let replacement_dir_id = (dir_md.dev(), dir_md.ino());
        assert_ne!(original_id, replacement_dir_id);

        let all_abi = AccessFs::from_all(ABI::V5);
        let expected_sock_mask = (AccessFs::ReadFile | AccessFs::WriteFile) & all_abi;

        let mut notes = Vec::new();
        let assembled = crate::linux::assemble_landlock_rules(&policy, &mut notes)?;
        assert_eq!(
            assembled.sock_rules.len(),
            1,
            "renamed real socket must keep its single assembled socket rule"
        );
        let (descriptor, rule_mask) = assembled
            .sock_rules
            .first()
            .copied()
            .ok_or("expected one assembled sock_rule")?;
        let st = fstat(descriptor)?;
        #[allow(clippy::useless_conversion)]
        let inode_identity = (u64::from(st.st_dev), u64::from(st.st_ino));
        let descriptor_type = FileType::from_raw_mode(st.st_mode);

        assert_eq!(
            inode_identity, original_id,
            "assembled sock_rule descriptor must identify original socket inode, not replacement dir"
        );
        assert_ne!(inode_identity, replacement_dir_id);
        assert_eq!(descriptor_type, FileType::Socket);
        assert_eq!(rule_mask, expected_sock_mask);
        assert!(notes.is_empty(), "expected no notes, got {notes:?}");

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    /// Test E (white-box): rule-list parity for the shadow case (Test A's configuration: config
    /// file in directory `D`, `D` also configured as `fastcgi-pass "unix:D"`, no other grant
    /// covers `D`). Asserts the assembled rules `(descriptor (dev, ino), AccessFs mask)` in exact
    /// order equal 0.1.5 byte-for-byte, and verifies that a wrong-type entry added manually to an
    /// edited policy (empty shadowed-class set) is still skipped.
    #[cfg(target_os = "linux")]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn assembled_landlock_rules_for_shadowed_config_dir_match_015_identity_mask_and_order()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::collections::BTreeSet;
        use std::os::unix::fs::MetadataExt as _;
        use std::path::{Path, PathBuf};

        use landlock::{ABI, Access as _, AccessFs};
        use rustix::fs::fstat;

        let base = short_socket_test_dir("shw")?;
        let conf_dir = base.join("conf");
        let cfg_file = conf_dir.join("miraserve.kdl");
        let docroot = base.join("www");
        std::fs::create_dir_all(&conf_dir)?;
        std::fs::create_dir_all(&docroot)?;

        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:8443"
    sandbox {{ landlock #true; seccomp "off" }}
}}
site "shadow.example.test" {{
    root "{docroot}"
    route "/app.php" {{
        fastcgi-pass "unix:{conf_dir}"
    }}
}}
"#,
            docroot = kdl_escape_test_path(&docroot),
            conf_dir = kdl_escape_test_path(&conf_dir),
        );
        std::fs::write(&cfg_file, &kdl)?;

        let (cfg, _) = miraserve_config::parse_kdl("miraserve.kdl", &kdl)?;
        let mut policy = crate::SandboxPolicy::from_config_with_file(&cfg, Some(&cfg_file), None);
        policy.finalize_grants()?;

        let all_abi = AccessFs::from_all(ABI::V5);
        let ro_dir_mask = (AccessFs::ReadFile | AccessFs::ReadDir) & all_abi;
        let ro_file_mask = ro_dir_mask & AccessFs::ReadFile;
        let sock_mask = (AccessFs::ReadFile | AccessFs::WriteFile) & all_abi;

        // Independently construct the exact 0.1.5 ordered `((dev, ino), mask)` sequence for Test A.
        let mut expected_ro_paths = BTreeSet::new();
        for sys_ro in [
            "/etc/ssl/certs",
            "/etc/ssl/openssl.cnf",
            "/etc/ssl/cert.pem",
            "/etc/ca-certificates",
            "/etc/ca-certificates.conf",
            "/usr/share/ca-certificates",
            "/usr/local/share/ca-certificates",
            "/etc/pki/tls/certs",
            "/etc/pki/tls/cert.pem",
            "/etc/pki/ca-trust",
            "/usr/share/pki/ca-trust-source",
            "/usr/share/pki/trust",
            "/var/lib/ca-certificates",
            "/etc/resolv.conf",
            "/etc/hosts",
        ] {
            let p = PathBuf::from(sys_ro);
            if p.exists() {
                if let Ok(canon) = std::fs::canonicalize(&p)
                    && canon != p
                    && canon.is_file()
                {
                    expected_ro_paths.insert(canon);
                }
                expected_ro_paths.insert(p);
            }
        }
        if Path::new("/etc/miraserve/auth").is_dir() {
            expected_ro_paths.insert(PathBuf::from("/etc/miraserve/auth"));
        }
        expected_ro_paths.insert(docroot.clone());
        // Note: `conf_dir` was removed from `ro` by socket precedence and sits in `socket_paths`.

        let mut expected_rules: Vec<((u64, u64), landlock::BitFlags<AccessFs>)> = Vec::new();
        for p in &expected_ro_paths {
            let md = std::fs::metadata(p)?;
            let mask = if md.is_dir() {
                ro_dir_mask
            } else {
                ro_file_mask
            };
            expected_rules.push(((md.dev(), md.ino()), mask));
        }
        let conf_md = std::fs::metadata(&conf_dir)?;
        expected_rules.push(((conf_md.dev(), conf_md.ino()), sock_mask));

        let mut notes = Vec::new();
        let assembled = crate::linux::assemble_landlock_rules(&policy, &mut notes)?;
        let actual_rules: Vec<((u64, u64), landlock::BitFlags<AccessFs>)> = assembled
            .readonly_rules
            .into_iter()
            .chain(assembled.writable_rules)
            .chain(assembled.sock_rules)
            .map(|(fd, mask)| {
                let st = fstat(fd)?;
                #[allow(clippy::useless_conversion)]
                Ok(((u64::from(st.st_dev), u64::from(st.st_ino)), mask))
            })
            .collect::<Result<Vec<_>, rustix::io::Errno>>()?;

        assert_eq!(
            actual_rules, expected_rules,
            "assembled Landlock rules (identity, mask, order) for shadowed config dir must equal 0.1.5"
        );
        assert!(notes.is_empty(), "expected no notes, got {notes:?}");

        // An embedder-edited policy has an empty shadowed-class set for manually added entries,
        // so a wrong-type directory pushed directly into `socket_paths` is skipped.
        let manual_dir = base.join("manual-dir");
        std::fs::create_dir_all(&manual_dir)?;
        let clean_kdl = format!(
            r#"
server {{
    listen "127.0.0.1:8443"
    sandbox {{ landlock #true; seccomp "off" }}
}}
site "clean.example.test" {{
    root "{docroot}"
}}
"#,
            docroot = kdl_escape_test_path(&docroot),
        );
        let (clean_cfg, _) = miraserve_config::parse_kdl("clean.kdl", &clean_kdl)?;
        let mut edited_policy = crate::SandboxPolicy::from_config_with_file(&clean_cfg, None, None);
        edited_policy.socket_paths.push(manual_dir.clone());
        edited_policy.finalize_grants()?;
        let mut edited_notes = Vec::new();
        let edited_assembled =
            crate::linux::assemble_landlock_rules(&edited_policy, &mut edited_notes)?;
        assert!(
            edited_assembled.sock_rules.is_empty(),
            "manually added wrong-type exact socket entry on edited policy must be skipped"
        );

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    struct TestCapturedEvent {
        level: tracing::Level,
        message: String,
        fields: std::collections::BTreeMap<String, String>,
    }

    #[cfg(target_os = "linux")]
    type TestEventSink = std::sync::Arc<std::sync::Mutex<Vec<TestCapturedEvent>>>;

    #[cfg(target_os = "linux")]
    std::thread_local! {
        static TEST_EVENT_SINK: std::cell::RefCell<Option<TestEventSink>> =
            const { std::cell::RefCell::new(None) };
    }

    #[cfg(target_os = "linux")]
    struct TestFieldVisitor {
        message: String,
        fields: std::collections::BTreeMap<String, String>,
    }

    #[cfg(target_os = "linux")]
    impl tracing::field::Visit for TestFieldVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            let rendered = format!("{value:?}");
            if field.name() == "message" {
                self.message = rendered;
            } else {
                self.fields.insert(field.name().to_owned(), rendered);
            }
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            if field.name() == "message" {
                self.message = value.to_owned();
            } else {
                self.fields
                    .insert(field.name().to_owned(), value.to_owned());
            }
        }
    }

    /// Single global test tracing router so parallel unit tests never race on `tracing-core`'s
    /// `set_default` / `has_just_one` callsite interest cache (where an unsubscribed parallel test
    /// thread can register a callsite with `Interest::never()` while only one scoped subscriber
    /// exists on another thread).
    #[cfg(target_os = "linux")]
    struct TestGlobalEventRouter;

    #[cfg(target_os = "linux")]
    impl tracing::Subscriber for TestGlobalEventRouter {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn register_callsite(
            &self,
            _metadata: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::always()
        }
        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            TEST_EVENT_SINK.with(|slot| {
                if let Some(sink) = slot.borrow().as_ref() {
                    let mut visitor = TestFieldVisitor {
                        message: String::new(),
                        fields: std::collections::BTreeMap::new(),
                    };
                    event.record(&mut visitor);
                    if let Ok(mut guard) = sink.lock() {
                        guard.push(TestCapturedEvent {
                            level: *event.metadata().level(),
                            message: visitor.message,
                            fields: visitor.fields,
                        });
                    }
                }
            });
        }
        fn enter(&self, _span: &tracing::span::Id) {}
        fn exit(&self, _span: &tracing::span::Id) {}
    }

    #[cfg(target_os = "linux")]
    struct TestEventCaptureGuard {
        previous: Option<TestEventSink>,
    }

    #[cfg(target_os = "linux")]
    impl Drop for TestEventCaptureGuard {
        fn drop(&mut self) {
            let prev = self.previous.take();
            let _ = TEST_EVENT_SINK.try_with(|slot| {
                *slot.borrow_mut() = prev;
            });
        }
    }

    #[cfg(target_os = "linux")]
    fn capture_test_events(sink: TestEventSink) -> TestEventCaptureGuard {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let _ = tracing::subscriber::set_global_default(TestGlobalEventRouter);
        });
        let previous = TEST_EVENT_SINK.with(|slot| slot.borrow_mut().replace(sink));
        TestEventCaptureGuard { previous }
    }

    #[cfg(target_os = "linux")]
    fn expected_linux_system_ro_paths_for_test() -> std::collections::BTreeSet<std::path::PathBuf> {
        use std::collections::BTreeSet;
        use std::path::{Path, PathBuf};

        let mut ro_paths = BTreeSet::new();
        for sys_ro in [
            "/etc/ssl/certs",
            "/etc/ssl/openssl.cnf",
            "/etc/ssl/cert.pem",
            "/etc/ca-certificates",
            "/etc/ca-certificates.conf",
            "/usr/share/ca-certificates",
            "/usr/local/share/ca-certificates",
            "/etc/pki/tls/certs",
            "/etc/pki/tls/cert.pem",
            "/etc/pki/ca-trust",
            "/usr/share/pki/ca-trust-source",
            "/usr/share/pki/trust",
            "/var/lib/ca-certificates",
            "/etc/resolv.conf",
            "/etc/hosts",
        ] {
            let p = PathBuf::from(sys_ro);
            if p.exists() {
                if let Ok(canon) = std::fs::canonicalize(&p)
                    && canon != p
                    && canon.is_file()
                {
                    ro_paths.insert(canon);
                }
                ro_paths.insert(p);
            }
        }
        if Path::new("/etc/miraserve/auth").is_dir() {
            ro_paths.insert(PathBuf::from("/etc/miraserve/auth"));
        }
        ro_paths
    }

    /// Audit 3 P1 #1 (white-box): existing directory `L`, `fastcgi-pass "unix:L"`, rotating log
    /// file `L/server.log` bound via `bind_log_rotation_dir`, no `socket-tree`. Asserts exact
    /// 0.1.5 rule-list parity against independent literals (socket-class rule on `L`'s replacement
    /// descriptor followed by the pinned RW rule on `L`), plus exactly one shadow WARN and zero
    /// skip WARNs across two installations (also tested with a trailing-slash spelling `unix:L/`).
    #[cfg(target_os = "linux")]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn assembled_landlock_rules_for_rotating_log_parent_as_exact_socket_match_015_and_warn()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::MetadataExt as _;
        use std::sync::{Arc, Mutex};

        use landlock::{ABI, Access as _, AccessFs};
        use rustix::fs::fstat;

        let all_abi = AccessFs::from_all(ABI::V5);
        let ro_dir_mask = (AccessFs::ReadFile | AccessFs::ReadDir) & all_abi;
        let ro_file_mask = ro_dir_mask & AccessFs::ReadFile;
        let writable_dir_mask = (AccessFs::ReadFile
            | AccessFs::ReadDir
            | AccessFs::WriteFile
            | AccessFs::Truncate
            | AccessFs::MakeReg
            | AccessFs::MakeDir
            | AccessFs::RemoveFile
            | AccessFs::RemoveDir
            | AccessFs::Refer)
            & all_abi;
        let sock_mask = (AccessFs::ReadFile | AccessFs::WriteFile) & all_abi;

        for (tag, trailing_slash) in [("rlog", false), ("rlogs", true)] {
            let base = short_socket_test_dir(tag)?;
            if let Some(reason) = miraserve_config::sandbox_tree_rejection(&base.to_string_lossy())
            {
                eprintln!(
                    "skipping assembled_landlock_rules_for_rotating_log_parent_as_exact_socket_match_015_and_warn ({tag}): temp path '{}' rejected by rotating-log dir validator ({reason})",
                    base.display()
                );
                let _ = std::fs::remove_dir_all(&base);
                continue;
            }
            let docroot = base.join("www");
            let log_dir = base.join("logs");
            let log_file = log_dir.join("server.log");
            std::fs::create_dir_all(&docroot)?;
            std::fs::create_dir_all(&log_dir)?;

            let sock_ep_str = if trailing_slash {
                format!("{}/", log_dir.display())
            } else {
                log_dir.display().to_string()
            };
            let kdl = format!(
                r#"
server {{
    listen "127.0.0.1:8443"
    sandbox {{ landlock #true; seccomp "off" }}
}}
site "rlog.example.test" {{
    root "{docroot}"
    route "/app.php" {{
        fastcgi-pass "unix:{sock_ep}"
    }}
}}
"#,
                docroot = kdl_escape_test_path(&docroot),
                sock_ep = kdl_escape_test_str(&sock_ep_str),
            );
            let (cfg, _) = miraserve_config::parse_kdl("rlog.kdl", &kdl)?;
            // Exact CLI order: build initial policy first, then bind rotating log dir, then finalize.
            let mut policy = crate::SandboxPolicy::from_config_with_file(&cfg, None, None);
            policy.bind_log_rotation_dir(&log_file, &cfg, None, None, &[])?;
            policy.finalize_grants()?;

            // Independently construct the exact 0.1.5 ordered rule list:
            // readonly_rules ++ writable_rules (empty because L is pinned) ++ sock_rules (L) ++
            // pinned_read_write_dirs (L).
            let mut expected_ro_paths = expected_linux_system_ro_paths_for_test();
            expected_ro_paths.insert(docroot.clone());

            let mut expected_rules: Vec<((u64, u64), landlock::BitFlags<AccessFs>)> = Vec::new();
            for p in &expected_ro_paths {
                let md = std::fs::metadata(p)?;
                let mask = if md.is_dir() {
                    ro_dir_mask
                } else {
                    ro_file_mask
                };
                expected_rules.push(((md.dev(), md.ino()), mask));
            }
            let log_md = std::fs::metadata(&log_dir)?;
            let log_inode = (log_md.dev(), log_md.ino());
            expected_rules.push((log_inode, sock_mask));
            expected_rules.push((log_inode, writable_dir_mask));

            let events = Arc::new(Mutex::new(Vec::<TestCapturedEvent>::new()));
            for _ in 0..2 {
                let _sub = capture_test_events(Arc::clone(&events));
                let mut notes = Vec::new();
                let assembled = crate::linux::assemble_landlock_rules(&policy, &mut notes)?;
                assert!(
                    assembled.writable_rules.is_empty(),
                    "rotating-log dir L is pinned so writable_rules must be empty"
                );
                assert_eq!(
                    assembled.sock_rules.len(),
                    1,
                    "rotating-log dir L used as exact endpoint must keep its 0.1.5 socket-class rule"
                );
                assert_eq!(
                    policy.pinned_read_write_dirs.len(),
                    1,
                    "rotating-log dir L must remain pinned"
                );
                let (sock_fd, _) = assembled
                    .sock_rules
                    .first()
                    .copied()
                    .ok_or("expected one sock_rule")?;
                let pinned_rw = policy
                    .pinned_read_write_dirs
                    .first()
                    .ok_or("expected one pinned_read_write_dir")?;
                assert_ne!(
                    sock_fd.as_raw_fd(),
                    pinned_rw.file.as_raw_fd(),
                    "socket-class rule must use the replacement grant_states descriptor, followed by the separate pinned handle"
                );

                let mut actual_rules: Vec<((u64, u64), landlock::BitFlags<AccessFs>)> = assembled
                    .readonly_rules
                    .into_iter()
                    .chain(assembled.writable_rules)
                    .chain(assembled.sock_rules)
                    .map(|(fd, mask)| {
                        let st = fstat(fd)?;
                        #[allow(clippy::useless_conversion)]
                        Ok(((u64::from(st.st_dev), u64::from(st.st_ino)), mask))
                    })
                    .collect::<Result<Vec<_>, rustix::io::Errno>>()?;
                for pinned in &policy.pinned_read_write_dirs {
                    let st = fstat(&*pinned.file)?;
                    #[allow(clippy::useless_conversion)]
                    actual_rules.push((
                        (u64::from(st.st_dev), u64::from(st.st_ino)),
                        writable_dir_mask,
                    ));
                }
                for pinned in &policy.pinned_read_only_paths {
                    let st = fstat(&*pinned.file)?;
                    let mask = if pinned.is_dir {
                        ro_dir_mask
                    } else {
                        ro_file_mask
                    };
                    #[allow(clippy::useless_conversion)]
                    actual_rules.push(((u64::from(st.st_dev), u64::from(st.st_ino)), mask));
                }

                assert_eq!(
                    actual_rules, expected_rules,
                    "assembled + pinned Landlock rules for rotating-log parent L must match 0.1.5"
                );
                assert!(notes.is_empty(), "expected no notes, got {notes:?}");
            }

            let expected_warn = format!(
                "unix socket path '{sock_ep_str}' is not a socket (found directory) and the same path is also configured as a directory grant: the 0.1.5 access rule is kept; give the socket its own path"
            );
            let captured = events.lock().map_err(|_| "event capture lock poisoned")?;
            let shadow_warns: Vec<&String> = captured
                .iter()
                .filter(|e| e.level == tracing::Level::WARN && e.message == expected_warn)
                .map(|e| &e.message)
                .collect();
            assert_eq!(
                shadow_warns.len(),
                1,
                "expected exactly 1 shadow WARN `{expected_warn}` across two calls, got {shadow_warns:?} (all: {:?})",
                captured
                    .iter()
                    .map(|e| (&e.level, &e.message))
                    .collect::<Vec<_>>()
            );
            assert!(
                captured
                    .iter()
                    .all(|e| !e.message.contains("no socket rule installed")
                        && !e.message.contains("no Landlock rule installed")),
                "rotating-log parent must emit shadow WARN, never skip WARN"
            );

            let _ = std::fs::remove_dir_all(&base);
        }
        Ok(())
    }

    /// Audit 3 P1 #2 (intended behaviour): regular certificate file `C` configured as a TLS
    /// certificate (whose parent directory is granted read-only) and also used as
    /// `fastcgi-pass "unix:C"` gets NO leaf socket rule, keeps its parent's read-only rule, stays
    /// readable (and not writable) under enforcing Landlock, and emits the skip WARN once.
    #[cfg(target_os = "linux")]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn cert_file_used_as_exact_socket_gets_no_leaf_rule_stays_readable_and_warns_once()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::fs::OpenOptions;
        use std::io::ErrorKind;
        use std::os::unix::fs::MetadataExt as _;
        use std::sync::{Arc, Mutex};

        use landlock::{ABI, Access as _, AccessFs};
        use rustix::fs::fstat;

        let base = short_socket_test_dir("crt")?;
        let docroot = base.join("www");
        let cert_dir = base.join("tls").join("public");
        let key_dir = base.join("tls").join("private");
        let outside = base.join("outside");
        let cert_file = cert_dir.join("site.pem");
        let key_file = key_dir.join("site.key");
        let outside_marker = outside.join("secret.txt");
        std::fs::create_dir_all(&docroot)?;
        std::fs::create_dir_all(&cert_dir)?;
        std::fs::create_dir_all(&key_dir)?;
        std::fs::create_dir_all(&outside)?;
        std::fs::write(&cert_file, "CERT-PEM-PAYLOAD")?;
        std::fs::write(&key_file, "KEY-PEM-PAYLOAD")?;
        std::fs::write(&outside_marker, "OUTSIDE-SECRET")?;

        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:8443"
    sandbox {{ landlock #true; seccomp "off" }}
}}
site "cert.example.test" {{
    root "{docroot}"
    tls {{
        cert "{cert_file}"
        key "{key_file}"
    }}
    route "/app.php" {{
        fastcgi-pass "unix:{cert_file}"
    }}
}}
"#,
            docroot = kdl_escape_test_path(&docroot),
            cert_file = kdl_escape_test_path(&cert_file),
            key_file = kdl_escape_test_path(&key_file),
        );
        let (cfg, _) = miraserve_config::parse_kdl("cert-ep.kdl", &kdl)?;
        let mut policy = crate::SandboxPolicy::from_config_with_file(&cfg, None, None);
        policy.finalize_grants()?;

        assert!(
            policy.read_only_paths.contains(&cert_dir),
            "certificate parent dir must be granted read-only"
        );
        assert!(
            policy.socket_paths.contains(&cert_file),
            "certificate path must sit in socket_paths"
        );

        let all_abi = AccessFs::from_all(ABI::V5);
        let ro_dir_mask = (AccessFs::ReadFile | AccessFs::ReadDir) & all_abi;
        let cert_dir_md = std::fs::metadata(&cert_dir)?;
        let cert_dir_inode = (cert_dir_md.dev(), cert_dir_md.ino());

        let events = Arc::new(Mutex::new(Vec::<TestCapturedEvent>::new()));
        {
            let _sub = capture_test_events(Arc::clone(&events));
            let mut notes = Vec::new();
            let assembled = crate::linux::assemble_landlock_rules(&policy, &mut notes)?;
            assert!(
                assembled.sock_rules.is_empty(),
                "regular certificate file C used as exact socket must get NO leaf socket rule"
            );
            let mut found_parent_ro = false;
            for (fd, mask) in &assembled.readonly_rules {
                let st = fstat(fd)?;
                #[allow(clippy::useless_conversion)]
                let id = (u64::from(st.st_dev), u64::from(st.st_ino));
                if id == cert_dir_inode && *mask == ro_dir_mask {
                    found_parent_ro = true;
                    break;
                }
            }
            assert!(
                found_parent_ro,
                "parent directory read-only rule must be present in assembled readonly_rules"
            );
            assert!(notes.is_empty(), "expected no notes, got {notes:?}");
        }

        // Enforce Landlock on two threads (both capturing WARNs): verify C stays readable via its
        // parent's read-only rule, is NOT writable (no leaf socket WriteFile rule), outside is
        // denied, and the skip WARN stays emitted once across all calls.
        if crate::linux::probe_host_landlock_abi().is_some() {
            for idx in 1..=2 {
                let p = policy.clone();
                let ev = Arc::clone(&events);
                let cf = cert_file.clone();
                let cd = cert_dir.clone();
                let out = outside_marker.clone();
                std::thread::spawn(move || -> Result<(), String> {
                    let _sub = capture_test_events(ev);
                    let status = crate::apply_landlock_current_thread(&p)
                        .map_err(|e| format!("thread {idx} apply_landlock: {e}"))?;
                    if !matches!(
                        status,
                        crate::EnforcementStatus::Enforced
                            | crate::EnforcementStatus::PartiallyEnforced
                    ) {
                        return Err(format!("thread {idx} expected enforcing Landlock: {status:?}"));
                    }
                    let got = std::fs::read_to_string(&cf)
                        .map_err(|e| format!("thread {idx} reading cert C failed: {e}"))?;
                    if got != "CERT-PEM-PAYLOAD" {
                        return Err(format!("thread {idx} unexpected cert contents: {got:?}"));
                    }
                    std::fs::read_dir(&cd)
                        .map_err(|e| format!("thread {idx} ReadDir on cert parent failed: {e}"))?;
                    let write_err = OpenOptions::new().write(true).open(&cf).err().ok_or_else(
                        || format!("thread {idx} cert C must NOT be writable under Landlock"),
                    )?;
                    if write_err.kind() != ErrorKind::PermissionDenied {
                        return Err(format!(
                            "thread {idx} expected PermissionDenied writing cert C, got {write_err:?}"
                        ));
                    }
                    let out_err = std::fs::read_to_string(&out).err().ok_or_else(|| {
                        format!("thread {idx} outside marker must be denied under Landlock")
                    })?;
                    if out_err.kind() != ErrorKind::PermissionDenied {
                        return Err(format!(
                            "thread {idx} expected PermissionDenied on outside marker, got {out_err:?}"
                        ));
                    }
                    Ok(())
                })
                .join()
                .map_err(|_| "cert enforcement thread panicked")??;
            }
        }

        let expected_warn = format!(
            "exact unix socket path '{}' is not a socket (found regular file): no socket rule installed for it; FastCGI or keyd requests to it fail while it is not a socket",
            cert_file.display()
        );
        let captured = events.lock().map_err(|_| "event capture lock poisoned")?;
        let skip_warns: Vec<&String> = captured
            .iter()
            .filter(|e| e.level == tracing::Level::WARN && e.message == expected_warn)
            .map(|e| &e.message)
            .collect();
        assert_eq!(
            skip_warns.len(),
            1,
            "expected exactly 1 skip WARN `{expected_warn}`, got {skip_warns:?} (all: {:?})",
            captured
                .iter()
                .map(|e| (&e.level, &e.message))
                .collect::<Vec<_>>()
        );
        assert!(
            captured
                .iter()
                .all(|e| !e.message.contains("0.1.5 access rule is kept")),
            "regular cert file C must not emit shadow WARN"
        );

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    /// Audit 3 P2 (shadow set hygiene): when `finalize_grants` prunes a spelling from
    /// `grant_states` because it was removed from every path list, it removes that spelling from
    /// `socket_shadows_other_class` too; re-adding the directory by hand afterwards treats it as
    /// a plain exact entry (skipped, skip WARN emitted instead of shadow WARN).
    #[cfg(target_os = "linux")]
    #[test]
    fn finalize_grants_prunes_shadow_set_when_socket_entry_removed_and_readded()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::{Arc, Mutex};

        let base = short_socket_test_dir("shh")?;
        let dir_d = base.join("shared");
        std::fs::create_dir_all(&dir_d)?;

        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:8443"
    sandbox {{ landlock #true; seccomp "off" }}
}}
site "hygiene.example.test" {{
    root "{dir_d}"
    route "/app.php" {{
        fastcgi-pass "unix:{dir_d}"
    }}
}}
"#,
            dir_d = kdl_escape_test_path(&dir_d),
        );
        let (cfg, _) = miraserve_config::parse_kdl("hygiene.kdl", &kdl)?;
        let mut policy = crate::SandboxPolicy::from_config_with_file(&cfg, None, None);
        policy.finalize_grants()?;

        assert!(
            policy.socket_shadows_other_class.contains(&dir_d),
            "initial policy must record D in socket_shadows_other_class"
        );
        assert!(
            !policy.read_only_paths.contains(&dir_d) && !policy.read_write_paths.contains(&dir_d),
            "socket precedence must have removed D from RO/RW"
        );

        // Remove D from socket_paths and finalize: grant_states and shadow set must both drop D.
        policy.socket_paths.retain(|p| p != &dir_d);
        policy.finalize_grants()?;
        assert!(
            !policy.grant_states.contains_key(&dir_d),
            "finalize_grants must prune D from grant_states"
        );
        assert!(
            !policy.socket_shadows_other_class.contains(&dir_d),
            "finalize_grants must prune D from socket_shadows_other_class"
        );

        // Re-add D by hand as a plain exact socket entry and finalize again.
        policy.socket_paths.push(dir_d.clone());
        policy.finalize_grants()?;
        assert!(
            !policy.socket_shadows_other_class.contains(&dir_d),
            "re-added D must not regain shadowed-class provenance"
        );

        let events = Arc::new(Mutex::new(Vec::<TestCapturedEvent>::new()));
        {
            let _sub = capture_test_events(Arc::clone(&events));
            let mut notes = Vec::new();
            let assembled = crate::linux::assemble_landlock_rules(&policy, &mut notes)?;
            assert!(
                assembled.sock_rules.is_empty(),
                "re-added directory D must be treated as a plain exact entry with zero sock_rules"
            );
            assert!(notes.is_empty(), "expected no notes, got {notes:?}");
        }

        let expected_skip_warn = format!(
            "exact unix socket path '{}' is not a socket (found directory): no socket rule installed for it; FastCGI or keyd requests to it fail while it is not a socket",
            dir_d.display()
        );
        let captured = events.lock().map_err(|_| "event capture lock poisoned")?;
        let skip_warns: Vec<&String> = captured
            .iter()
            .filter(|e| e.level == tracing::Level::WARN && e.message == expected_skip_warn)
            .map(|e| &e.message)
            .collect();
        assert_eq!(
            skip_warns.len(),
            1,
            "expected 1 skip WARN for re-added D, got {skip_warns:?} (all: {:?})",
            captured
                .iter()
                .map(|e| (&e.level, &e.message))
                .collect::<Vec<_>>()
        );
        assert!(
            captured
                .iter()
                .all(|e| !e.message.contains("0.1.5 access rule is kept")),
            "re-added D must not emit shadow WARN"
        );

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    /// Audit 3 P2 (Test D companion): verifies directly via crate-internal `first_time_reported`
    /// that the missing-socket notice uses the exact literal deduplication key prefix `sock:`
    /// (`sock:{z.sock}`), proving both directions (recorded after assembly AND suppressed when
    /// pre-seeded with `sock:{z2.sock}`).
    #[cfg(target_os = "linux")]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn missing_socket_notice_uses_literal_sock_deduplication_key_prefix()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::{Arc, Mutex};

        let base = short_socket_test_dir("ddk")?;
        let docroot = base.join("www");
        let bad_dir = base.join("pools").join("bad");
        let late_child = bad_dir.join("late.sock");
        let z1_sock = base.join("z1.sock");
        let z2_sock = base.join("z2.sock");
        std::fs::create_dir_all(&docroot)?;
        std::fs::create_dir_all(&bad_dir)?;

        let expected_warn_msg = "configured Landlock Unix socket path(s) do not exist at startup and cannot be granted until restart";

        // Direction 1: assembling with `pools/bad` (dir), `pools/bad/late.sock` (absent), and
        // `z1.sock` (absent) emits the WARN for ONLY `z1.sock` and records exact key `sock:{z1}`.
        let kdl1 = format!(
            r#"
server {{
    listen "127.0.0.1:8443"
    sandbox {{ landlock #true; seccomp "off" }}
}}
site "ddk1.example.test" {{
    root "{docroot}"
    route "/bad.php" {{ fastcgi-pass "unix:{bad_dir}" }}
    route "/late.php" {{ fastcgi-pass "unix:{late_child}" }}
    route "/z.php" {{ fastcgi-pass "unix:{z1_sock}" }}
}}
"#,
            docroot = kdl_escape_test_path(&docroot),
            bad_dir = kdl_escape_test_path(&bad_dir),
            late_child = kdl_escape_test_path(&late_child),
            z1_sock = kdl_escape_test_path(&z1_sock),
        );
        let (cfg1, _) = miraserve_config::parse_kdl("ddk1.kdl", &kdl1)?;
        let mut policy1 = crate::SandboxPolicy::from_config_with_file(&cfg1, None, None);
        policy1.finalize_grants()?;

        let events1 = Arc::new(Mutex::new(Vec::<TestCapturedEvent>::new()));
        let mut notes1 = Vec::new();
        {
            let _sub = capture_test_events(Arc::clone(&events1));
            let _assembled = crate::linux::assemble_landlock_rules(&policy1, &mut notes1)?;
        }
        let expected_note1 = format!(
            "missing Landlock Unix socket path(s) omitted at startup (restart after creating): {}",
            z1_sock.display()
        );
        assert_eq!(notes1, vec![expected_note1]);
        {
            let captured1 = events1.lock().map_err(|_| "event capture lock poisoned")?;
            let warns1: Vec<&TestCapturedEvent> = captured1
                .iter()
                .filter(|e| e.level == tracing::Level::WARN && e.message == expected_warn_msg)
                .collect();
            assert_eq!(warns1.len(), 1, "expected 1 missing-socket WARN for z1");
            let first1 = warns1.first().ok_or("expected missing-socket WARN")?;
            assert_eq!(
                first1.fields.get("missing_sockets").map(String::as_str),
                Some(z1_sock.to_string_lossy().as_ref()),
                "missing_sockets field must name ONLY z1.sock"
            );
        }
        assert!(
            !crate::linux::first_time_reported(&format!("sock:{}", z1_sock.display())),
            "assembly must have recorded exact literal deduplication key `sock:<z1.sock>`"
        );
        assert!(
            crate::linux::first_time_reported(&format!(
                "sock:{}, {}",
                late_child.display(),
                z1_sock.display()
            )),
            "wrong 2-path key must NOT have been recorded"
        );
        assert!(
            crate::linux::first_time_reported(&format!("missing:{}", z1_sock.display())),
            "alternate prefix `missing:` must NOT have been recorded"
        );

        // Direction 2: pre-seeding exact literal key `sock:{z2}` suppresses the missing-socket
        // WARN on assembly while leaving the report note intact.
        assert!(
            crate::linux::first_time_reported(&format!("sock:{}", z2_sock.display())),
            "fresh z2 key must not be pre-existing"
        );
        let kdl2 = format!(
            r#"
server {{
    listen "127.0.0.1:8443"
    sandbox {{ landlock #true; seccomp "off" }}
}}
site "ddk2.example.test" {{
    root "{docroot}"
    route "/bad.php" {{ fastcgi-pass "unix:{bad_dir}" }}
    route "/late.php" {{ fastcgi-pass "unix:{late_child}" }}
    route "/z.php" {{ fastcgi-pass "unix:{z2_sock}" }}
}}
"#,
            docroot = kdl_escape_test_path(&docroot),
            bad_dir = kdl_escape_test_path(&bad_dir),
            late_child = kdl_escape_test_path(&late_child),
            z2_sock = kdl_escape_test_path(&z2_sock),
        );
        let (cfg2, _) = miraserve_config::parse_kdl("ddk2.kdl", &kdl2)?;
        let mut policy2 = crate::SandboxPolicy::from_config_with_file(&cfg2, None, None);
        policy2.finalize_grants()?;

        let events2 = Arc::new(Mutex::new(Vec::<TestCapturedEvent>::new()));
        let mut notes2 = Vec::new();
        {
            let _sub = capture_test_events(Arc::clone(&events2));
            let _assembled = crate::linux::assemble_landlock_rules(&policy2, &mut notes2)?;
        }
        let expected_note2 = format!(
            "missing Landlock Unix socket path(s) omitted at startup (restart after creating): {}",
            z2_sock.display()
        );
        assert_eq!(notes2, vec![expected_note2]);
        {
            let captured2 = events2.lock().map_err(|_| "event capture lock poisoned")?;
            assert!(
                captured2
                    .iter()
                    .all(|e| !(e.level == tracing::Level::WARN && e.message == expected_warn_msg)),
                "pre-seeding exact `sock:<z2.sock>` key must suppress the missing-socket WARN"
            );
        }

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    /// Audit 4 P1 #1 (exact-file fallback regular file and FIFO shadowed by exact socket path):
    /// Split-daemon mode places `cert` and `key` in one temp directory so the parent is refused
    /// (`parent_covers_excluded_key`), forcing the exact-file read-only fallback. When the same
    /// file path is also configured as `fastcgi-pass "unix:<file>"`, socket precedence removes it
    /// from `read_only_paths` and marks it in `socket_shadows_other_class`. The installer keeps a
    /// socket-class rule on the SAME descriptor at the SAME position with mask `ReadFile` ONLY (no
    /// `WriteFile`), emits the reduced-to-read-access WARN once per path per process, and under
    /// enforcing Landlock (where no other class grants write) the file opens for reading and NOT
    /// for writing.
    #[cfg(target_os = "linux")]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn exact_file_fallback_non_dir_as_exact_socket_gets_read_only_rule_and_warns_once()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::fs::OpenOptions;
        use std::io::ErrorKind;
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::MetadataExt as _;
        use std::os::unix::net::{UnixListener, UnixStream};
        use std::sync::{Arc, Mutex};

        use landlock::{ABI, Access as _, AccessFs};
        use rustix::fs::{CWD, FileType, Mode, OFlags, fstat, mknodat, openat};

        let all_abi = AccessFs::from_all(ABI::V5);
        let read_file_mask = all_abi & AccessFs::ReadFile;
        let sock_mask = (AccessFs::ReadFile | AccessFs::WriteFile) & all_abi;

        for (tag, is_fifo, expected_type_label) in
            [("exfb", false, "regular file"), ("exff", true, "FIFO")]
        {
            let base = short_socket_test_dir(tag)?;
            let docroot = base.join("www");
            let tls_dir = base.join("tls");
            let outside = base.join("outside");
            let cert_file = tls_dir.join(if is_fifo { "site.fifo" } else { "site.pem" });
            let key_file = tls_dir.join("site.key");
            let real_sock = base.join("z_real.sock");
            let outside_marker = outside.join("secret.txt");
            std::fs::create_dir_all(&docroot)?;
            std::fs::create_dir_all(&tls_dir)?;
            std::fs::create_dir_all(&outside)?;
            if is_fifo {
                mknodat(CWD, &cert_file, FileType::Fifo, Mode::RUSR | Mode::WUSR, 0)?;
            } else {
                std::fs::write(&cert_file, "CERT-FALLBACK-PAYLOAD")?;
            }
            std::fs::write(&key_file, "PRIVATE-KEY-SECRET")?;
            std::fs::write(&outside_marker, "OUTSIDE-SECRET")?;
            let _real_listener = UnixListener::bind(&real_sock)?;

            let kdl = format!(
                r#"
server {{
    listen "127.0.0.1:8443"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "tcp://127.0.0.1:9443"
        cert "{cert_file}"
        key "{key_file}"
    }}
    sandbox {{ landlock #true; seccomp "off" }}
}}
site "exfb.example.test" {{
    root "{docroot}"
    route "/app.php" {{
        fastcgi-pass "unix:{cert_file}"
    }}
    route "/real.php" {{
        fastcgi-pass "unix:{real_sock}"
    }}
}}
"#,
                docroot = kdl_escape_test_path(&docroot),
                cert_file = kdl_escape_test_path(&cert_file),
                key_file = kdl_escape_test_path(&key_file),
                real_sock = kdl_escape_test_path(&real_sock),
            );
            let (cfg, _) = miraserve_config::parse_kdl("exfb.kdl", &kdl)?;
            let mut policy = crate::SandboxPolicy::from_config_with_file(&cfg, None, None);
            policy.finalize_grants()?;

            assert!(
                policy.exact_file_fallbacks.contains(&cert_file),
                "case {tag}: cert beside split-daemon key must use exact-file fallback"
            );
            assert!(
                !policy.read_only_paths.contains(&tls_dir),
                "case {tag}: parent directory holding split-daemon key must NOT be granted RO"
            );
            assert!(
                !policy.read_only_paths.contains(&cert_file),
                "case {tag}: socket precedence must have removed cert from read_only_paths"
            );
            assert!(
                !policy.read_write_paths.contains(&cert_file),
                "case {tag}: cert must not be in read_write_paths"
            );
            assert_eq!(
                policy.socket_paths,
                vec![cert_file.clone(), real_sock.clone()],
                "case {tag}: socket_paths must contain shadowed cert followed by second real socket"
            );
            assert!(
                policy.socket_shadows_other_class.contains(&cert_file),
                "case {tag}: shadowed exact-file fallback must be in socket_shadows_other_class"
            );
            assert!(
                !policy.socket_shadows_other_class.contains(&real_sock),
                "case {tag}: real socket must not be marked shadowed"
            );

            let cert_md = std::fs::metadata(&cert_file)?;
            let cert_inode = (cert_md.dev(), cert_md.ino());
            let expected_cert_fd = match policy.grant_states.get(&cert_file) {
                Some(crate::GrantState::Installed { fd, .. }) => fd.as_raw_fd(),
                other => {
                    return Err(format!(
                        "case {tag}: expected Installed grant_state for cert, got {other:?}"
                    )
                    .into());
                }
            };
            let real_md = std::fs::metadata(&real_sock)?;
            let real_inode = (real_md.dev(), real_md.ino());
            let expected_real_fd = match policy.grant_states.get(&real_sock) {
                Some(crate::GrantState::Installed { fd, .. }) => fd.as_raw_fd(),
                other => {
                    return Err(format!(
                        "case {tag}: expected Installed grant_state for real socket, got {other:?}"
                    )
                    .into());
                }
            };

            let events = Arc::new(Mutex::new(Vec::<TestCapturedEvent>::new()));
            {
                let _sub = capture_test_events(Arc::clone(&events));
                let mut notes = Vec::new();
                let assembled = crate::linux::assemble_landlock_rules(&policy, &mut notes)?;
                // Verify exact order, descriptor reuse, inode identity, and mask across BOTH
                // socket entries so any reordering relative to `z_real.sock` is detected.
                let actual_sock_rules: Vec<(i32, (u64, u64), landlock::BitFlags<AccessFs>)> =
                    assembled
                        .sock_rules
                        .iter()
                        .map(|(fd, mask)| {
                            let st = fstat(fd)?;
                            #[allow(clippy::useless_conversion)]
                            Ok((
                                fd.as_raw_fd(),
                                (u64::from(st.st_dev), u64::from(st.st_ino)),
                                *mask,
                            ))
                        })
                        .collect::<Result<Vec<_>, rustix::io::Errno>>()?;
                assert_eq!(
                    actual_sock_rules,
                    vec![
                        (expected_cert_fd, cert_inode, read_file_mask),
                        (expected_real_fd, real_inode, sock_mask),
                    ],
                    "case {tag}: shadowed non-directory must keep its exact position before real socket with ReadFile-only mask"
                );
                for (fd, _) in assembled
                    .readonly_rules
                    .iter()
                    .chain(assembled.writable_rules.iter())
                {
                    let other_st = fstat(fd)?;
                    #[allow(clippy::useless_conversion)]
                    let other_inode = (u64::from(other_st.st_dev), u64::from(other_st.st_ino));
                    assert_ne!(
                        other_inode, cert_inode,
                        "case {tag}: no other rule class may cover cert in this fixture"
                    );
                }
                assert!(
                    notes.is_empty(),
                    "case {tag}: expected no notes, got {notes:?}"
                );
            }

            if crate::linux::probe_host_landlock_abi().is_some() {
                for idx in 1..=2 {
                    let p = policy.clone();
                    let ev = Arc::clone(&events);
                    let cf = cert_file.clone();
                    let kf = key_file.clone();
                    let rs = real_sock.clone();
                    let out = outside_marker.clone();
                    std::thread::spawn(move || -> Result<(), String> {
                        let _sub = capture_test_events(ev);
                        let status = crate::apply_landlock_current_thread(&p)
                            .map_err(|e| format!("case {tag} thread {idx} apply_landlock: {e}"))?;
                        if !matches!(
                            status,
                            crate::EnforcementStatus::Enforced
                                | crate::EnforcementStatus::PartiallyEnforced
                        ) {
                            return Err(format!(
                                "case {tag} thread {idx} expected enforcing Landlock: {status:?}"
                            ));
                        }
                        UnixStream::connect(&rs).map_err(|e| {
                            format!("case {tag} thread {idx} real socket connect failed: {e}")
                        })?;
                        if is_fifo {
                            let _rd = openat(
                                CWD,
                                &cf,
                                OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
                                Mode::empty(),
                            )
                            .map_err(|e| {
                                format!("case {tag} thread {idx} reading FIFO failed: {e}")
                            })?;
                            let wr_err = openat(
                                CWD,
                                &cf,
                                OFlags::WRONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
                                Mode::empty(),
                            )
                            .err()
                            .ok_or_else(|| {
                                format!(
                                    "case {tag} thread {idx} FIFO must NOT open for writing under Landlock"
                                )
                            })?;
                            if wr_err != rustix::io::Errno::ACCESS {
                                return Err(format!(
                                    "case {tag} thread {idx} expected EACCES writing FIFO, got {wr_err:?}"
                                ));
                            }
                        } else {
                            let got = std::fs::read_to_string(&cf).map_err(|e| {
                                format!("case {tag} thread {idx} reading cert failed: {e}")
                            })?;
                            if got != "CERT-FALLBACK-PAYLOAD" {
                                return Err(format!(
                                    "case {tag} thread {idx} unexpected cert contents: {got:?}"
                                ));
                            }
                            let write_err =
                                OpenOptions::new().write(true).open(&cf).err().ok_or_else(
                                    || {
                                        format!(
                                            "case {tag} thread {idx} cert must NOT open for writing under Landlock"
                                        )
                                    },
                                )?;
                            if write_err.kind() != ErrorKind::PermissionDenied {
                                return Err(format!(
                                    "case {tag} thread {idx} expected PermissionDenied writing cert, got {write_err:?}"
                                ));
                            }
                        }
                        let key_err = std::fs::read_to_string(&kf).err().ok_or_else(|| {
                            format!("case {tag} thread {idx} sibling private key must be denied")
                        })?;
                        if key_err.kind() != ErrorKind::PermissionDenied {
                            return Err(format!(
                                "case {tag} thread {idx} expected PermissionDenied on sibling key, got {key_err:?}"
                            ));
                        }
                        let out_err = std::fs::read_to_string(&out).err().ok_or_else(|| {
                            format!("case {tag} thread {idx} outside marker must be denied")
                        })?;
                        if out_err.kind() != ErrorKind::PermissionDenied {
                            return Err(format!(
                                "case {tag} thread {idx} expected PermissionDenied on outside marker, got {out_err:?}"
                            ));
                        }
                        Ok(())
                    })
                    .join()
                    .map_err(|_| "exact-file fallback enforcement thread panicked")??;
                }
            }

            let expected_warn = format!(
                "unix socket path '{}' is not a socket (found {expected_type_label}) and the same path is configured for another use: its socket rule is reduced to read access; give the socket its own path",
                cert_file.display()
            );
            let captured = events.lock().map_err(|_| "event capture lock poisoned")?;
            let matching_warns: Vec<&String> = captured
                .iter()
                .filter(|e| e.level == tracing::Level::WARN && e.message == expected_warn)
                .map(|e| &e.message)
                .collect();
            assert_eq!(
                matching_warns.len(),
                1,
                "case {tag}: expected exactly 1 reduced-to-read WARN `{expected_warn}`, got {matching_warns:?} (all: {:?})",
                captured
                    .iter()
                    .map(|e| (&e.level, &e.message))
                    .collect::<Vec<_>>()
            );
            assert!(
                captured.iter().all(|e| {
                    !e.message.contains("also configured as a directory grant")
                        && !e.message.contains("no socket rule installed")
                }),
                "case {tag}: shadowed non-directory must emit only the reduced-to-read WARN"
            );

            let _ = std::fs::remove_dir_all(&base);
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn snapshot_open_fds_for_test()
    -> Result<std::collections::BTreeMap<i32, std::path::PathBuf>, std::io::Error> {
        use std::mem::MaybeUninit;
        use std::os::fd::AsRawFd as _;

        use rustix::fs::{CWD, Mode, OFlags, RawDir, openat};

        let dir_fd = openat(
            CWD,
            "/proc/self/fd",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)?;
        let self_fd = dir_fd.as_raw_fd();
        let mut out = std::collections::BTreeMap::new();
        let mut buf = [MaybeUninit::uninit(); 4096];
        let mut iter = RawDir::new(&dir_fd, &mut buf);
        while let Some(entry) = iter.next() {
            let entry = entry.map_err(std::io::Error::from)?;
            let Ok(name) = entry.file_name().to_str() else {
                continue;
            };
            let Ok(fd) = name.parse::<i32>() else {
                continue;
            };
            if fd == self_fd {
                continue;
            }
            if let Ok(target) = std::fs::read_link(format!("/proc/self/fd/{fd}")) {
                out.insert(fd, target);
            }
        }
        Ok(out)
    }

    #[cfg(target_os = "linux")]
    fn plug_fd_gaps_from(
        min_fd: i32,
    ) -> Result<(Vec<std::os::fd::OwnedFd>, i32), Box<dyn std::error::Error>> {
        use std::os::fd::AsRawFd as _;

        use rustix::fs::{CWD, Mode, OFlags, openat};
        use rustix::io::fcntl_dupfd_cloexec;

        let open_before = snapshot_open_fds_for_test()?;
        let max_open = open_before.keys().copied().max().unwrap_or(min_fd);
        let seed_raw_fd = openat(
            CWD,
            "/dev/null",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let seed = if seed_raw_fd.as_raw_fd() < min_fd {
            let moved = fcntl_dupfd_cloexec(&seed_raw_fd, min_fd)?;
            drop(seed_raw_fd);
            moved
        } else {
            seed_raw_fd
        };
        let dense_max = max_open.max(seed.as_raw_fd());
        let mut plugs = vec![seed];
        let cur = snapshot_open_fds_for_test()?;
        for fd in min_fd..=dense_max {
            if !cur.contains_key(&fd) {
                let seed_ref = plugs.first().ok_or("missing plug seed")?;
                let dup = fcntl_dupfd_cloexec(seed_ref, fd)?;
                assert_eq!(
                    dup.as_raw_fd(),
                    fd,
                    "expected plug to fill FD gap {fd}, got {}",
                    dup.as_raw_fd()
                );
                plugs.push(dup);
            }
        }
        let final_open = snapshot_open_fds_for_test()?;
        let top_fd = final_open.keys().copied().max().unwrap_or(dense_max);
        Ok((plugs, top_fd))
    }

    #[cfg(target_os = "linux")]
    fn proc_fdinfo_flags_octal(raw_fd: i32) -> Result<u32, Box<dyn std::error::Error>> {
        let body = std::fs::read_to_string(format!("/proc/self/fdinfo/{raw_fd}"))?;
        for line in body.lines() {
            if let Some(rest) = line.strip_prefix("flags:") {
                let parsed = u32::from_str_radix(rest.trim(), 8)?;
                return Ok(parsed);
            }
        }
        Err(format!("missing flags line in /proc/self/fdinfo/{raw_fd}: {body:?}").into())
    }

    #[cfg(target_os = "linux")]
    fn compile_block_by_name_reopen_bpf() -> Result<seccompiler::BpfProgram, String> {
        use std::collections::BTreeMap;

        use rustix::fs::OFlags;
        use seccompiler::{
            SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
            SeccompRule, TargetArch,
        };

        let arch = TargetArch::try_from(std::env::consts::ARCH)
            .map_err(|e| format!("unsupported arch {}: {e:?}", std::env::consts::ARCH))?;
        let (sys_openat, sys_openat2, sys_open): (i64, i64, Option<i64>) = match arch {
            TargetArch::x86_64 => (257, 437, Some(2)),
            TargetArch::aarch64 | TargetArch::riscv64 => (56, 437, None),
        };
        let o_directory = u64::from(OFlags::DIRECTORY.bits());
        let o_nofollow = u64::from(OFlags::NOFOLLOW.bits());
        let at_fdcwd = u64::from((-100_i32).cast_unsigned());

        let no_o_dir_rule = SeccompRule::new(vec![
            SeccompCondition::new(
                2,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::MaskedEq(o_directory),
                0,
            )
            .map_err(|e| e.to_string())?,
        ])
        .map_err(|e| e.to_string())?;
        let cwd_nofollow_rule = SeccompRule::new(vec![
            SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, at_fdcwd)
                .map_err(|e| e.to_string())?,
            SeccompCondition::new(
                2,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::MaskedEq(o_nofollow),
                o_nofollow,
            )
            .map_err(|e| e.to_string())?,
        ])
        .map_err(|e| e.to_string())?;

        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        rules.insert(sys_openat, vec![no_o_dir_rule, cwd_nofollow_rule]);
        rules.insert(sys_openat2, Vec::new());
        if let Some(nr) = sys_open {
            rules.insert(nr, Vec::new());
        }

        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(1), // EPERM
            arch,
        )
        .map_err(|e| e.to_string())?;
        filter
            .try_into()
            .map_err(|e: seccompiler::BackendError| e.to_string())
    }

    #[cfg(target_os = "linux")]
    fn compile_fcntl_dupfd_cloexec_bpf(
        errno_code: u32,
        only_nonzero_min: bool,
    ) -> Result<seccompiler::BpfProgram, String> {
        use std::collections::BTreeMap;

        use seccompiler::{
            SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
            SeccompRule, TargetArch,
        };

        const F_DUPFD_CLOEXEC: u64 = 1030;

        let arch = TargetArch::try_from(std::env::consts::ARCH)
            .map_err(|e| format!("unsupported arch {}: {e:?}", std::env::consts::ARCH))?;
        let sys_fcntl: i64 = match arch {
            TargetArch::x86_64 => 72,
            TargetArch::aarch64 | TargetArch::riscv64 => 25,
        };
        let mut conds = vec![
            SeccompCondition::new(
                1,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                F_DUPFD_CLOEXEC,
            )
            .map_err(|e| e.to_string())?,
        ];
        if only_nonzero_min {
            conds.push(
                SeccompCondition::new(2, SeccompCmpArgLen::Dword, SeccompCmpOp::Ne, 0)
                    .map_err(|e| e.to_string())?,
            );
        }
        let rule = SeccompRule::new(conds).map_err(|e| e.to_string())?;
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        rules.insert(sys_fcntl, vec![rule]);
        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(errno_code),
            arch,
        )
        .map_err(|e| e.to_string())?;
        filter
            .try_into()
            .map_err(|e: seccompiler::BackendError| e.to_string())
    }

    #[cfg(target_os = "linux")]
    fn run_unit_test_child(
        test_name: &str,
        env_key: &str,
        scenario: &str,
        base_env_key: &str,
        base: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let exe = std::env::current_exe()?;
        let output = std::process::Command::new(exe)
            .args(["--exact", test_name, "--nocapture"])
            .env(env_key, scenario)
            .env(base_env_key, base)
            .output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !output.status.success() || !stdout.contains("1 passed; 0 failed") {
            return Err(format!(
                "child '{scenario}' failed or did not execute exactly 1 test (status={}):\nstdout:\n{stdout}\nstderr:\n{stderr}",
                output.status,
            )
            .into());
        }
        Ok(())
    }

    /// Stage "log pin" Test P (PARITY — must pass on `origin/main` `c4ae997` AND on this branch):
    /// Exercises BOTH (1) a rotating log whose parent directory is also a configured `socket-tree`
    /// and (2) a rotating log whose parent directory is distinct from the configured `socket-tree`.
    /// Runs in an isolated single-threaded child process to verify exact public path lists, exact
    /// retained descriptor count (compared numerically via `/proc/self/fd`), exact assembled
    /// Landlock rule list (`(dev, ino)` from independent `std::fs::metadata`, ABI 5 masks, order),
    /// notices/warnings, and real kernel Landlock enforcement.
    #[cfg(target_os = "linux")]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn parity_rotating_log_parent_socket_tree_overlap_and_disjoint_rules_fds_and_notices()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::fs::OpenOptions;
        use std::io::ErrorKind;
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::MetadataExt as _;
        use std::path::PathBuf;
        use std::sync::{Arc, Mutex};

        use landlock::{ABI, Access as _, AccessFs};
        use rustix::fs::{FileType, fstat};

        const CHILD_ENV: &str = "MIRASERVE_LOGPIN_PARITY_CHILD";
        const BASE_ENV: &str = "MIRASERVE_LOGPIN_PARITY_BASE";

        if let Ok(scenario) = std::env::var(CHILD_ENV) {
            let base = PathBuf::from(std::env::var(BASE_ENV)?);
            let docroot = base.join("www");
            let log_dir = base.join("logs");
            let log_file = log_dir.join("server.log");
            let disjoint_sock_tree = base.join("socks");
            let outside = base.join("outside");
            let is_overlap = match scenario.as_str() {
                "overlap" => true,
                "disjoint" => false,
                other => return Err(format!("unknown parity scenario: {other}").into()),
            };
            let configured_sock_tree = if is_overlap {
                log_dir.clone()
            } else {
                disjoint_sock_tree.clone()
            };

            let kdl = format!(
                r#"
server {{
    listen "127.0.0.1:8443"
    sandbox {{
        landlock #true
        seccomp "off"
        socket-tree "{sock_tree}"
    }}
}}
site "logpin-parity.example.test" {{
    root "{docroot}"
}}
"#,
                sock_tree = kdl_escape_test_path(&configured_sock_tree),
                docroot = kdl_escape_test_path(&docroot),
            );
            let (cfg, _) = miraserve_config::parse_kdl("logpin-parity.kdl", &kdl)?;

            let mut expected_ro_set = expected_linux_system_ro_paths_for_test();
            expected_ro_set.insert(docroot.clone());
            let expected_read_only: Vec<PathBuf> = expected_ro_set.into_iter().collect();
            let expected_read_write: Vec<PathBuf> = vec![log_dir.clone()];
            let expected_socks: Vec<PathBuf> = vec![configured_sock_tree.clone()];

            // Snapshot open FDs immediately before policy preparation (single-threaded child).
            let pre_fd_map = snapshot_open_fds_for_test()?;
            let pre_count = pre_fd_map.len();
            let pre_fds: std::collections::BTreeSet<i32> = pre_fd_map.keys().copied().collect();

            let mut policy = crate::SandboxPolicy::from_config_with_file(&cfg, None, None);
            let binding = policy.bind_log_rotation_dir(&log_file, &cfg, None, None, &[])?;
            policy.finalize_grants()?;

            let post_fd_map = snapshot_open_fds_for_test()?;
            let post_count = post_fd_map.len();
            let new_fds: std::collections::BTreeMap<i32, PathBuf> = post_fd_map
                .into_iter()
                .filter(|(fd, _)| !pre_fds.contains(fd))
                .collect();

            // 1. Public path lists and binding identity.
            assert_eq!(policy.read_only_paths, expected_read_only);
            assert_eq!(policy.read_write_paths, expected_read_write);
            assert_eq!(policy.socket_paths, expected_socks);
            assert_eq!(binding.real_parent, log_dir);
            assert!(binding.pinned.is_some());
            assert_eq!(policy.pinned_read_write_dirs.len(), 1);

            // 2. Exact descriptor count after preparation (compare numbers, never discard).
            //    - Overlap: each RO grant (1 FD) + log_dir grant_state (1 FD) + log_dir pin (1 FD).
            //    - Disjoint: each RO grant (1 FD) + sock_tree grant_state (1 FD) + log_dir
            //      grant_state (1 FD) + log_dir pin (1 FD).
            let expected_fd_delta = if is_overlap {
                expected_read_only.len() + 2
            } else {
                expected_read_only.len() + 3
            };
            assert_eq!(
                post_count.saturating_sub(pre_count),
                expected_fd_delta,
                "scenario {scenario}: retained descriptor count mismatch (pre={pre_count}, post={post_count}, new_fds={new_fds:?})"
            );
            assert_eq!(
                new_fds.len(),
                expected_fd_delta,
                "scenario {scenario}: new FD map length mismatch: {new_fds:?}"
            );
            let log_dir_fd_count = new_fds.values().filter(|t| *t == &log_dir).count();
            assert_eq!(
                log_dir_fd_count, 2,
                "scenario {scenario}: expected exactly 2 retained FDs for log_dir (grant_state + pin), got {log_dir_fd_count} ({new_fds:?})"
            );
            // Verify the first `expected_read_only.len()` retained FDs match the sorted RO open
            // sequence verbatim, followed by the socket-tree / log-dir descriptors.
            let expected_ro_targets: Vec<PathBuf> = expected_read_only
                .iter()
                .map(|p| std::fs::canonicalize(p).unwrap_or_else(|_| p.clone()))
                .collect();
            let actual_fd_targets: Vec<PathBuf> = new_fds.values().cloned().collect();
            assert_eq!(
                actual_fd_targets.get(..expected_ro_targets.len()),
                Some(expected_ro_targets.as_slice()),
                "scenario {scenario}: retained RO FD open sequence mismatch (new_fds={new_fds:?})"
            );
            if !is_overlap {
                let sock_tree_fd_count = new_fds
                    .values()
                    .filter(|t| *t == &disjoint_sock_tree)
                    .count();
                assert_eq!(
                    sock_tree_fd_count, 1,
                    "scenario {scenario}: expected exactly 1 retained FD for disjoint socket-tree, got {sock_tree_fd_count}"
                );
            }

            // 3. Exact assembled rule list (device+inode from independent std::fs::metadata,
            //    ABI 5 AccessFs masks, exact installation order) and notices.
            let all_abi = AccessFs::from_all(ABI::V5);
            let ro_dir_mask = (AccessFs::ReadFile | AccessFs::ReadDir) & all_abi;
            let ro_file_mask = ro_dir_mask & AccessFs::ReadFile;
            let writable_dir_mask = (AccessFs::ReadFile
                | AccessFs::ReadDir
                | AccessFs::WriteFile
                | AccessFs::Truncate
                | AccessFs::MakeReg
                | AccessFs::MakeDir
                | AccessFs::RemoveFile
                | AccessFs::RemoveDir
                | AccessFs::Refer)
                & all_abi;
            let sock_mask = (AccessFs::ReadFile | AccessFs::WriteFile) & all_abi;

            let mut expected_rules: Vec<((u64, u64), landlock::BitFlags<AccessFs>)> = Vec::new();
            for p in &expected_read_only {
                let md = std::fs::metadata(p)?;
                let mask = if md.is_dir() {
                    ro_dir_mask
                } else {
                    ro_file_mask
                };
                expected_rules.push(((md.dev(), md.ino()), mask));
            }
            let sock_meta = std::fs::metadata(&configured_sock_tree)?;
            let sock_inode = (sock_meta.dev(), sock_meta.ino());
            let log_md = std::fs::metadata(&log_dir)?;
            let log_inode = (log_md.dev(), log_md.ino());
            expected_rules.push((sock_inode, sock_mask));
            expected_rules.push((log_inode, writable_dir_mask));

            let events = Arc::new(Mutex::new(Vec::<TestCapturedEvent>::new()));
            for _ in 0..2 {
                let _sub = capture_test_events(Arc::clone(&events));
                let mut notes = Vec::new();
                let assembled = crate::linux::assemble_landlock_rules(&policy, &mut notes)?;
                assert!(
                    assembled.writable_rules.is_empty(),
                    "scenario {scenario}: pinned rotating-log dir must not also appear in writable_rules"
                );
                assert_eq!(assembled.sock_rules.len(), 1);
                let (sock_fd, _) = assembled
                    .sock_rules
                    .first()
                    .copied()
                    .ok_or("expected one sock_rule")?;
                let pinned_rw = policy
                    .pinned_read_write_dirs
                    .first()
                    .ok_or("expected one pinned_read_write_dir")?;
                let sock_st = fstat(sock_fd)?;
                let pin_st = fstat(&*pinned_rw.file)?;
                #[allow(clippy::useless_conversion)]
                let sock_rule_id = (u64::from(sock_st.st_dev), u64::from(sock_st.st_ino));
                #[allow(clippy::useless_conversion)]
                let pin_rule_id = (u64::from(pin_st.st_dev), u64::from(pin_st.st_ino));
                assert_eq!(sock_rule_id, sock_inode);
                assert_eq!(pin_rule_id, log_inode);
                assert_eq!(
                    FileType::from_raw_mode(sock_st.st_mode),
                    FileType::Directory
                );
                assert_eq!(FileType::from_raw_mode(pin_st.st_mode), FileType::Directory);
                assert_ne!(
                    sock_fd.as_raw_fd(),
                    pinned_rw.file.as_raw_fd(),
                    "scenario {scenario}: socket rule descriptor and pinned handle must be distinct FDs"
                );
                assert_eq!(policy.granted_identity(&log_dir), Some(log_inode));
                assert_eq!(pinned_rw.inode_identity(), log_inode);

                assert_eq!(
                    assembled.read_only_access, ro_dir_mask,
                    "scenario {scenario}: production read_only_access mask mismatch"
                );
                assert_eq!(
                    assembled.read_write_access, writable_dir_mask,
                    "scenario {scenario}: production read_write_access mask mismatch"
                );
                let prod_pinned_rw_mask = assembled.read_write_access;
                let mut actual_rules: Vec<((u64, u64), landlock::BitFlags<AccessFs>)> = assembled
                    .readonly_rules
                    .into_iter()
                    .chain(assembled.writable_rules)
                    .chain(assembled.sock_rules)
                    .map(|(fd, mask)| {
                        let st = fstat(fd)?;
                        #[allow(clippy::useless_conversion)]
                        Ok(((u64::from(st.st_dev), u64::from(st.st_ino)), mask))
                    })
                    .collect::<Result<Vec<_>, rustix::io::Errno>>()?;
                for pinned in &policy.pinned_read_write_dirs {
                    let st = fstat(&*pinned.file)?;
                    #[allow(clippy::useless_conversion)]
                    actual_rules.push((
                        (u64::from(st.st_dev), u64::from(st.st_ino)),
                        prod_pinned_rw_mask,
                    ));
                }
                assert_eq!(
                    actual_rules, expected_rules,
                    "scenario {scenario}: assembled + pinned rule list mismatch"
                );
                assert!(
                    notes.is_empty(),
                    "scenario {scenario}: expected no notices, got {notes:?}"
                );
            }
            let captured = events.lock().map_err(|_| "event capture lock poisoned")?;
            let warns: Vec<&String> = captured
                .iter()
                .filter(|e| e.level == tracing::Level::WARN)
                .map(|e| &e.message)
                .collect();
            assert!(
                warns.is_empty(),
                "scenario {scenario}: valid socket-tree + rotating log must emit zero WARNs, got {warns:?}"
            );

            // 4. Real kernel Landlock enforcement check.
            if crate::linux::probe_host_landlock_abi().is_some() {
                let p = policy.clone();
                let ld = log_dir.clone();
                let dr = docroot.clone();
                let dst = disjoint_sock_tree.clone();
                let out = outside.clone();
                std::thread::spawn(move || -> Result<(), String> {
                    let status = crate::apply_landlock_current_thread(&p)
                        .map_err(|e| format!("apply_landlock: {e}"))?;
                    if !matches!(
                        status,
                        crate::EnforcementStatus::Enforced
                            | crate::EnforcementStatus::PartiallyEnforced
                    ) {
                        return Err(format!("expected enforcing Landlock, got {status:?}"));
                    }
                    let rotated = ld.join("server.log.1");
                    std::fs::write(&rotated, b"PARITY-ROTATED")
                        .map_err(|e| format!("write in log_dir: {e}"))?;
                    std::fs::read_to_string(&rotated)
                        .map_err(|e| format!("read in log_dir: {e}"))?;
                    std::fs::read_dir(&ld).map_err(|e| format!("readdir in log_dir: {e}"))?;
                    std::fs::remove_file(&rotated)
                        .map_err(|e| format!("remove in log_dir: {e}"))?;
                    // Cross-subdirectory rename inside `log_dir` exercises `AccessFs::Refer` on
                    // Landlock ABI >= 2 (would fail with EXDEV if `Refer` were missing from the
                    // production pinned RW mask).
                    let sub_a = ld.join("sub_a");
                    let sub_b = ld.join("sub_b");
                    std::fs::create_dir_all(&sub_a)
                        .map_err(|e| format!("create sub_a in log_dir: {e}"))?;
                    std::fs::create_dir_all(&sub_b)
                        .map_err(|e| format!("create sub_b in log_dir: {e}"))?;
                    let src = sub_a.join("moved.log");
                    let dst_moved = sub_b.join("moved.log");
                    std::fs::write(&src, b"REFER-OK")
                        .map_err(|e| format!("write sub_a/moved.log: {e}"))?;
                    std::fs::rename(&src, &dst_moved)
                        .map_err(|e| format!("cross-subdir rename (Refer) in log_dir: {e}"))?;
                    std::fs::remove_file(&dst_moved)
                        .map_err(|e| format!("remove sub_b/moved.log: {e}"))?;
                    std::fs::remove_dir(&sub_a)
                        .map_err(|e| format!("remove sub_a in log_dir: {e}"))?;
                    std::fs::remove_dir(&sub_b)
                        .map_err(|e| format!("remove sub_b in log_dir: {e}"))?;
                    std::fs::read_to_string(dr.join("index.html"))
                        .map_err(|e| format!("read docroot: {e}"))?;
                    if OpenOptions::new()
                        .write(true)
                        .open(dr.join("index.html"))
                        .err()
                        .map(|e| e.kind())
                        != Some(ErrorKind::PermissionDenied)
                    {
                        return Err("docroot must deny WriteFile".to_owned());
                    }
                    if !is_overlap {
                        std::fs::read_to_string(dst.join("existing.txt"))
                            .map_err(|e| format!("read disjoint sock_tree: {e}"))?;
                        OpenOptions::new()
                            .write(true)
                            .open(dst.join("existing.txt"))
                            .map_err(|e| format!("write disjoint sock_tree: {e}"))?;
                        if std::fs::read_dir(&dst).err().map(|e| e.kind())
                            != Some(ErrorKind::PermissionDenied)
                        {
                            return Err("disjoint sock_tree must deny ReadDir".to_owned());
                        }
                    }
                    if std::fs::read_to_string(out.join("secret.txt"))
                        .err()
                        .map(|e| e.kind())
                        != Some(ErrorKind::PermissionDenied)
                    {
                        return Err("outside dir must deny ReadFile".to_owned());
                    }
                    Ok(())
                })
                .join()
                .map_err(|_| "log-pin parity enforcement thread panicked")??;
            }
            return Ok(());
        }

        for scenario in ["overlap", "disjoint"] {
            let base = short_socket_test_dir(if scenario == "overlap" { "lpo" } else { "lpd" })?;
            if let Some(reason) = miraserve_config::sandbox_tree_rejection(&base.to_string_lossy())
            {
                let _ = std::fs::remove_dir_all(&base);
                return Err(format!(
                    "parity_rotating_log_parent_socket_tree_overlap_and_disjoint_rules_fds_and_notices ({scenario}): temp path '{}' rejected ({reason})",
                    base.display()
                )
                .into());
            }
            std::fs::create_dir_all(base.join("www"))?;
            std::fs::create_dir_all(base.join("logs"))?;
            std::fs::create_dir_all(base.join("socks"))?;
            std::fs::create_dir_all(base.join("outside"))?;
            std::fs::write(base.join("www").join("index.html"), "DOCROOT-OK")?;
            std::fs::write(base.join("logs").join("existing.txt"), "LOG-EXISTING")?;
            std::fs::write(base.join("socks").join("existing.txt"), "SOCK-EXISTING")?;
            std::fs::write(base.join("outside").join("secret.txt"), "OUTSIDE-SECRET")?;

            let res = run_unit_test_child(
                "landlock_enforcement_tests::parity_rotating_log_parent_socket_tree_overlap_and_disjoint_rules_fds_and_notices",
                CHILD_ENV,
                scenario,
                BASE_ENV,
                &base,
            );
            let _ = std::fs::remove_dir_all(&base);
            res?;
        }
        Ok(())
    }

    /// Stage "log pin" Test S1 (SECURITY — MUST FAIL on `origin/main` `c4ae997`, MUST PASS on this
    /// branch, zero sleeps, zero races, zero production hooks, real Linux kernel):
    ///
    /// Proves directly against the Linux kernel that `bind_log_rotation_dir` populates the
    /// overlapping socket-class grant state from the validated `PinnedWritableDir` handle itself
    /// WITHOUT performing any by-name path lookup (`open_grant`), across:
    ///   - `"sock-tree"`: rotating log parent is also a configured `socket-tree` (fresh pin),
    ///   - `"exact-sock"`: rotating log parent is also an exact `fastcgi-pass "unix:..."` (fresh),
    ///   - `"double-bind"`: second rotating log in the same `socket-tree` dir (reused `existing` pin).
    ///
    /// In an isolated child process, before calling `bind_log_rotation_dir`:
    ///   1. Plugs any FD gaps and lowers `RLIMIT_NOFILE` to leave ONLY 2 free FD slots — enough
    ///      for `open_dir_no_follow` (which needs 2 transient slots and keeps 1) plus 1 slot for
    ///      `try_clone_to_owned()`, and mathematically too tight for a second 2-slot component walk.
    ///   2. Installs a thread-local Linux `seccomp-bpf` filter (`seccompiler::apply_filter`) on a
    ///      scoped thread that rejects with `EPERM`:
    ///      - any `openat` without `O_DIRECTORY` (catching `open_grant(&real_parent, false)`),
    ///      - any `openat(AT_FDCWD, ..., O_NOFOLLOW)`,
    ///      - any `openat2` or legacy `open`.
    ///
    /// On `origin/main` (`c4ae997`), `bind_log_rotation_dir` calls `open_grant(&real_parent, false)`
    /// (`openat(AT_FDCWD, path, O_PATH | O_CLOEXEC)` without `O_DIRECTORY`), which the kernel
    /// seccomp filter deterministically blocks with `EPERM`, recording `GrantState::Failed` and
    /// failing `grant_failures()`, `granted_identity()`, `finalize_grants()`, and
    /// `assemble_landlock_rules()`. Independently, `/proc/self/fdinfo/<fd>` also verifies that the
    /// socket-class grant descriptor carries `O_PATH | O_DIRECTORY` (matching `pinned.file`, unlike
    /// `open_grant`) and `FD_CLOEXEC`. Finally, with all released identity guards
    /// (`verify_pinned_writable_dirs()`) active, verifies `fstat` identity equality on the assembled
    /// rule descriptors and real enforcing Landlock behavior (positive + negative controls).
    #[cfg(target_os = "linux")]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn security_rotating_log_bind_derives_socket_grant_from_pin_without_path_lookup()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::io::ErrorKind;
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::MetadataExt as _;
        use std::path::PathBuf;

        use rustix::fs::{FileType, OFlags, fstat};
        use rustix::io::{FdFlags, fcntl_getfd};
        use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

        const CHILD_ENV: &str = "MIRASERVE_LOGPIN_SEC1_CHILD";
        const BASE_ENV: &str = "MIRASERVE_LOGPIN_SEC1_BASE";

        if let Ok(scenario) = std::env::var(CHILD_ENV) {
            let base = PathBuf::from(std::env::var(BASE_ENV)?);
            let docroot = base.join("www");
            let log_dir = base.join("logs");
            let log_file = log_dir.join("server.log");
            let access_log_file = log_dir.join("access.log");
            let outside = base.join("outside");

            let kdl = match scenario.as_str() {
                "sock-tree" | "double-bind" | "absent-then-created" => format!(
                    r#"
server {{
    listen "127.0.0.1:8443"
    sandbox {{
        landlock #true
        seccomp "off"
        socket-tree "{log_dir}"
    }}
}}
site "sec-logpin.example.test" {{
    root "{docroot}"
}}
"#,
                    log_dir = kdl_escape_test_path(&log_dir),
                    docroot = kdl_escape_test_path(&docroot),
                ),
                "exact-sock" => format!(
                    r#"
server {{
    listen "127.0.0.1:8443"
    sandbox {{
        landlock #true
        seccomp "off"
    }}
}}
site "sec-logpin.example.test" {{
    root "{docroot}"
    route "/app.php" {{
        fastcgi-pass "unix:{log_dir}"
    }}
}}
"#,
                    log_dir = kdl_escape_test_path(&log_dir),
                    docroot = kdl_escape_test_path(&docroot),
                ),
                other => return Err(format!("unknown security scenario: {other}").into()),
            };

            let (cfg, _) = miraserve_config::parse_kdl("sec-logpin.kdl", &kdl)?;
            let mut policy = crate::SandboxPolicy::from_config_with_file(&cfg, None, None);

            // - "double-bind": bind the first rotating log normally so `log_dir` is already in
            //   `pinned_read_write_dirs`, then exercise the `existing` pin branch under seccomp.
            // - "absent-then-created": `log_dir` is absent at initial policy build and first
            //   `bind_log_rotation_dir` (`pinned == None`, `AbsentAtStartup`), then created on
            //   disk and rebound under seccomp (matching CLI `prebind_cli_logs` -> `create_dir_all`
            //   -> `finalize_cli_logs`).
            let target_log_file = if scenario == "double-bind" {
                policy.bind_log_rotation_dir(&log_file, &cfg, None, None, &[])?;
                &access_log_file
            } else if scenario == "absent-then-created" {
                assert_eq!(policy.granted_identity(&log_dir), None);
                let pre = policy.bind_log_rotation_dir(&log_file, &cfg, None, None, &[])?;
                assert!(pre.pinned.is_none());
                std::fs::create_dir_all(&log_dir)?;
                &log_file
            } else {
                &log_file
            };

            let log_md = std::fs::metadata(&log_dir)?;
            let expected_log_id = (log_md.dev(), log_md.ino());
            if scenario != "absent-then-created" {
                assert_eq!(policy.granted_identity(&log_dir), Some(expected_log_id));
            }

            // Plug every gap below `top_fd` so `RLIMIT_NOFILE = top_fd + 1 + 2` leaves
            // EXACTLY 2 free FD slots: enough for `open_dir_no_follow` (2 transient slots -> 1
            // retained) + `fcntl_dupfd_cloexec(..., 0)` (uses the 1 remaining slot), and impossible
            // for a second 2-slot component walk.
            let orig_rlim = getrlimit(Resource::Nofile);
            let (plugs, top_fd) = plug_fd_gaps_from(0)?;
            let tight_soft = u64::try_from(top_fd + 1 + 2)?;
            let tight_rlim = Rlimit {
                current: Some(tight_soft),
                maximum: orig_rlim.maximum,
            };

            let bpf = compile_block_by_name_reopen_bpf()?;
            let bind_res: Result<crate::LogDirBinding, String> = std::thread::scope(|scope| {
                let handle = scope.spawn(|| -> Result<crate::LogDirBinding, String> {
                    setrlimit(Resource::Nofile, tight_rlim)
                        .map_err(|e| format!("setrlimit tight failed: {e}"))?;
                    seccompiler::apply_filter(&bpf)
                        .map_err(|e| format!("apply seccomp filter failed: {e}"))?;
                    policy.bind_log_rotation_dir(target_log_file, &cfg, None, None, &[])
                });
                handle
                    .join()
                    .map_err(|_| "seccomp log-bind thread panicked".to_owned())?
            });
            // Restore original soft limit and drop plugs before post-bind inspections.
            setrlimit(Resource::Nofile, orig_rlim)?;
            drop(plugs);

            let binding = bind_res.map_err(|e| format!("scenario {scenario}: bind failed: {e}"))?;
            assert_eq!(binding.real_parent, log_dir);
            assert!(binding.pinned.is_some());

            // On `origin/main` (`c4ae997`), `open_grant(&real_parent, false)` was blocked with
            // EPERM by the kernel seccomp filter, leaving `GrantState::Failed` in `grant_states`.
            assert!(
                policy.grant_failures().is_empty(),
                "scenario {scenario}: bind_log_rotation_dir must NOT invoke a by-name open_grant; got grant_failures={:?}",
                policy.grant_failures()
            );
            assert_eq!(
                policy.granted_identity(&log_dir),
                Some(expected_log_id),
                "scenario {scenario}: socket-class grant state must hold validated log dir identity"
            );

            policy.finalize_grants()?;

            // Assemble Landlock rules with ALL released identity guards (`verify_pinned_writable_dirs`)
            // active, and verify descriptor identity, type, flags (`O_PATH | O_DIRECTORY`,
            // `FD_CLOEXEC`), and distinctness.
            let mut notes = Vec::new();
            let assembled = crate::linux::assemble_landlock_rules(&policy, &mut notes)?;
            assert!(
                notes.is_empty(),
                "scenario {scenario}: unexpected notes {notes:?}"
            );
            assert_eq!(assembled.sock_rules.len(), 1);
            assert_eq!(policy.pinned_read_write_dirs.len(), 1);
            let (sock_fd, _) = assembled
                .sock_rules
                .first()
                .copied()
                .ok_or("expected one sock_rule")?;
            let pinned_rw = policy
                .pinned_read_write_dirs
                .first()
                .ok_or("expected one pinned_read_write_dir")?;

            let sock_st = fstat(sock_fd)?;
            let pin_st = fstat(&*pinned_rw.file)?;
            #[allow(clippy::useless_conversion)]
            let sock_dev_ino = (u64::from(sock_st.st_dev), u64::from(sock_st.st_ino));
            #[allow(clippy::useless_conversion)]
            let pin_dev_ino = (u64::from(pin_st.st_dev), u64::from(pin_st.st_ino));
            assert_eq!(sock_dev_ino, expected_log_id);
            assert_eq!(pin_dev_ino, expected_log_id);
            assert_eq!(sock_dev_ino, pin_dev_ino);
            assert_eq!(
                FileType::from_raw_mode(sock_st.st_mode),
                FileType::Directory
            );
            assert_ne!(sock_fd.as_raw_fd(), pinned_rw.file.as_raw_fd());

            // Verify both FDs share the `O_PATH | O_DIRECTORY` open file description flags
            // (`open_grant` omits `O_DIRECTORY`) and carry `FD_CLOEXEC`.
            let sock_flags = proc_fdinfo_flags_octal(sock_fd.as_raw_fd())?;
            let pin_flags = proc_fdinfo_flags_octal(pinned_rw.file.as_raw_fd())?;
            let o_path_dir = OFlags::PATH.bits() | OFlags::DIRECTORY.bits();
            assert_eq!(
                sock_flags & o_path_dir,
                o_path_dir,
                "scenario {scenario}: sock grant FD must carry O_PATH|O_DIRECTORY from duplicated pin (flags={sock_flags:#o}, pin_flags={pin_flags:#o})"
            );
            assert_eq!(
                pin_flags & o_path_dir,
                o_path_dir,
                "scenario {scenario}: pinned FD must carry O_PATH|O_DIRECTORY (flags={pin_flags:#o})"
            );
            assert!(
                fcntl_getfd(sock_fd)?.contains(FdFlags::CLOEXEC),
                "scenario {scenario}: duplicated socket grant FD must set FD_CLOEXEC"
            );

            // Real enforcing Landlock check: positive controls succeed, outside denied.
            if crate::linux::probe_host_landlock_abi().is_some() {
                let p = policy.clone();
                let ld = log_dir.clone();
                let dr = docroot.clone();
                let out = outside.clone();
                std::thread::spawn(move || -> Result<(), String> {
                    let status = crate::apply_landlock_current_thread(&p)
                        .map_err(|e| format!("apply_landlock: {e}"))?;
                    if !matches!(
                        status,
                        crate::EnforcementStatus::Enforced
                            | crate::EnforcementStatus::PartiallyEnforced
                    ) {
                        return Err(format!("expected enforcing Landlock, got {status:?}"));
                    }
                    let probe = ld.join("ok.log");
                    std::fs::write(&probe, b"SEC-OK")
                        .map_err(|e| format!("write in log_dir: {e}"))?;
                    std::fs::remove_file(&probe).map_err(|e| format!("remove in log_dir: {e}"))?;
                    std::fs::read_to_string(dr.join("index.html"))
                        .map_err(|e| format!("read docroot: {e}"))?;
                    if std::fs::read_to_string(out.join("secret.txt"))
                        .err()
                        .map(|e| e.kind())
                        != Some(ErrorKind::PermissionDenied)
                    {
                        return Err(
                            "outside dir must be denied under enforcing Landlock".to_owned()
                        );
                    }
                    Ok(())
                })
                .join()
                .map_err(|_| "log-pin security enforcement thread panicked")??;
            }
            return Ok(());
        }

        for scenario in [
            "sock-tree",
            "exact-sock",
            "double-bind",
            "absent-then-created",
        ] {
            let base = short_socket_test_dir(match scenario {
                "sock-tree" => "ls1",
                "exact-sock" => "ls2",
                "double-bind" => "ls3",
                _ => "ls4",
            })?;
            if let Some(reason) = miraserve_config::sandbox_tree_rejection(&base.to_string_lossy())
            {
                let _ = std::fs::remove_dir_all(&base);
                return Err(format!(
                    "security_rotating_log_bind_derives_socket_grant_from_pin_without_path_lookup ({scenario}): temp path '{}' rejected ({reason})",
                    base.display()
                )
                .into());
            }
            std::fs::create_dir_all(base.join("www"))?;
            if scenario != "absent-then-created" {
                std::fs::create_dir_all(base.join("logs"))?;
            }
            std::fs::create_dir_all(base.join("outside"))?;
            std::fs::write(base.join("www").join("index.html"), "DOCROOT-OK")?;
            std::fs::write(base.join("outside").join("secret.txt"), "OUTSIDE-SECRET")?;

            let res = run_unit_test_child(
                "landlock_enforcement_tests::security_rotating_log_bind_derives_socket_grant_from_pin_without_path_lookup",
                CHILD_ENV,
                scenario,
                BASE_ENV,
                &base,
            );
            let _ = std::fs::remove_dir_all(&base);
            res?;
        }
        Ok(())
    }

    /// Stage "log pin" Test S2 (white-box deterministic rename-swap + restore oracle and `EMFILE`
    /// failure path, real Linux kernel, zero timing):
    ///
    /// - Part A (swap-and-restore with all released identity guards active): validates and pins
    ///   `slot` (`dir_a`), renames `slot` away and moves `decoy` (`dir_b`, containing `marker.txt`)
    ///   into `slot` before calling `grant_state_from_pinned_dir(&pinned)`, confirms `open_grant`
    ///   would have captured `dir_b` while `grant_state_from_pinned_dir` captures `dir_a`, then
    ///   restores `dir_a` back to `slot` (leaving `dir_b` at `decoy`) so `verify_pinned_writable_dirs()`
    ///   passes on assembly and real enforcing Landlock denies `decoy/marker.txt` with
    ///   `PermissionDenied` while allowing `slot/ok.txt`.
    /// - Part B (`EMFILE` duplication failure path in an isolated child process): with 0 free FD
    ///   slots, `grant_state_from_pinned_dir` fails with `SandboxError::Landlock` (no new error
    ///   kind), and `bind_log_rotation_dir` under FD exhaustion returns `Err(msg)`, appends to
    ///   `policy.warnings`, and leaves `policy` uncorrupted.
    #[cfg(target_os = "linux")]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn security_grant_state_from_pinned_dir_ignores_renamed_pathname_and_fails_cleanly_on_emfile()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::io::ErrorKind;
        use std::os::unix::fs::MetadataExt as _;
        use std::path::PathBuf;

        use rustix::fs::{FileType, fstat};
        use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

        const CHILD_ENV: &str = "MIRASERVE_LOGPIN_SEC2_CHILD";
        const BASE_ENV: &str = "MIRASERVE_LOGPIN_SEC2_BASE";

        if let Ok(scenario) = std::env::var(CHILD_ENV) {
            assert_eq!(scenario, "emfile");
            let base = PathBuf::from(std::env::var(BASE_ENV)?);
            let docroot = base.join("www");
            let slot = base.join("logs");
            let log_file = slot.join("server.log");
            let kdl = format!(
                r#"
server {{
    listen "127.0.0.1:8443"
    sandbox {{
        landlock #true
        seccomp "off"
        socket-tree "{slot}"
    }}
}}
site "emfile.example.test" {{
    root "{docroot}"
}}
"#,
                slot = kdl_escape_test_path(&slot),
                docroot = kdl_escape_test_path(&docroot),
            );
            let (cfg, _) = miraserve_config::parse_kdl("emfile.kdl", &kdl)?;
            let mut policy = crate::SandboxPolicy::from_config_with_file(&cfg, None, None);
            let slot_meta = std::fs::metadata(&slot)?;
            let slot_dev_ino = (slot_meta.dev(), slot_meta.ino());
            let pinned = crate::PinnedWritableDir::open_validated(&slot)?;

            // Plug every FD gap and cap RLIMIT_NOFILE at 0 free slots.
            let orig_rlim = getrlimit(Resource::Nofile);
            let (plugs, top_fd) = plug_fd_gaps_from(0)?;

            // 1. Direct `grant_state_from_pinned_dir` with 0 free slots -> `Failed(ResourceExhausted)`.
            setrlimit(
                Resource::Nofile,
                Rlimit {
                    current: Some(u64::try_from(top_fd + 1)?),
                    maximum: orig_rlim.maximum,
                },
            )?;
            let dup_state = crate::grant_state_from_pinned_dir(&pinned);
            match &dup_state {
                crate::GrantState::Failed {
                    reason,
                    kind: crate::GrantFailureKind::ResourceExhausted,
                } => {
                    assert!(
                        reason.contains("cannot duplicate pinned grant target"),
                        "unexpected dup failure reason: {reason}"
                    );
                }
                other => {
                    setrlimit(Resource::Nofile, orig_rlim)?;
                    drop(plugs);
                    return Err(format!(
                        "expected GrantState::Failed(ResourceExhausted) with 0 free slots, got {other:?}"
                    )
                    .into());
                }
            }

            // 2. `bind_log_rotation_dir` with 1 free slot (insufficient for the 2-slot pin walk
            //    `open_dir_no_follow`) takes the pin-validation error path without mutating policy.
            setrlimit(
                Resource::Nofile,
                Rlimit {
                    current: Some(u64::try_from(top_fd + 2)?),
                    maximum: orig_rlim.maximum,
                },
            )?;
            let warnings_before = policy.warnings.len();
            let bind_err = policy
                .bind_log_rotation_dir(&log_file, &cfg, None, None, &[])
                .err()
                .ok_or(
                    "expected bind_log_rotation_dir pin-walk failure under 1-slot RLIMIT_NOFILE",
                )?;
            setrlimit(Resource::Nofile, orig_rlim)?;
            drop(plugs);

            assert_eq!(policy.warnings.len(), warnings_before + 1);
            assert_eq!(
                policy.warnings.last().map(String::as_str),
                Some(bind_err.as_str())
            );
            assert_eq!(policy.pinned_read_write_dirs, Vec::new());
            assert_eq!(policy.read_write_paths, Vec::<PathBuf>::new());
            assert_eq!(policy.granted_identity(&slot), Some(slot_dev_ino));
            return Ok(());
        }

        // Part A: real swap-and-restore oracle with released identity guards active.
        let base = short_socket_test_dir("swp")?;
        if let Some(reason) = miraserve_config::sandbox_tree_rejection(&base.to_string_lossy()) {
            let _ = std::fs::remove_dir_all(&base);
            return Err(format!(
                "security_grant_state_from_pinned_dir_ignores_renamed_pathname_and_fails_cleanly_on_emfile: temp path '{}' rejected ({reason})",
                base.display()
            )
            .into());
        }
        let docroot = base.join("www");
        let slot = base.join("logs");
        let aside = base.join("logs_aside");
        let decoy = base.join("decoy");
        std::fs::create_dir_all(&docroot)?;
        std::fs::create_dir_all(&slot)?;
        std::fs::create_dir_all(&decoy)?;
        std::fs::write(docroot.join("index.html"), "DOCROOT-OK")?;
        std::fs::write(slot.join("ok.txt"), "DIR-A-OK")?;
        std::fs::write(decoy.join("marker.txt"), "DIR-B-ATTACKER")?;

        let md_a = std::fs::metadata(&slot)?;
        let md_b = std::fs::metadata(&decoy)?;
        let id_a = (md_a.dev(), md_a.ino());
        let id_b = (md_b.dev(), md_b.ino());
        assert_ne!(id_a, id_b);

        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:8443"
    sandbox {{
        landlock #true
        seccomp "off"
        socket-tree "{slot}"
    }}
}}
site "swap-logpin.example.test" {{
    root "{docroot}"
}}
"#,
            slot = kdl_escape_test_path(&slot),
            docroot = kdl_escape_test_path(&docroot),
        );
        let (cfg, _) = miraserve_config::parse_kdl("swap-logpin.kdl", &kdl)?;
        let mut policy = crate::SandboxPolicy::from_config_with_file(&cfg, None, None);

        // Pin `slot` (dir A), then deterministically swap `slot` -> dir B on disk.
        let pinned = crate::PinnedWritableDir::open_validated(&slot)?;
        assert_eq!(pinned.inode_identity(), id_a);
        std::fs::rename(&slot, &aside)?;
        std::fs::rename(&decoy, &slot)?;

        // Control: by-name `open_grant(&slot, false)` lands on attacker dir B!
        let by_name_state = crate::open_grant(&slot, false);
        match &by_name_state {
            crate::GrantState::Installed { identity, .. } => assert_eq!(*identity, id_b),
            other => return Err(format!("expected Installed control state, got {other:?}").into()),
        }

        // Fixed derivation: `grant_state_from_pinned_dir(&pinned)` stays pinned to dir A!
        let pin_derived_state = crate::grant_state_from_pinned_dir(&pinned);
        match &pin_derived_state {
            crate::GrantState::Installed {
                identity,
                is_dir,
                file_type,
                ..
            } => {
                assert_eq!(*identity, id_a);
                assert_ne!(*identity, id_b);
                assert!(*is_dir);
                assert_eq!(*file_type, FileType::Directory);
            }
            other => return Err(format!("expected Installed pin state, got {other:?}").into()),
        }

        // Restore dir A back to `slot` and move dir B back to `decoy` so `verify_pinned_writable_dirs`
        // passes (matching a transient race where the attacker restores the name before install).
        std::fs::rename(&slot, &decoy)?;
        std::fs::rename(&aside, &slot)?;

        // Negative control on the old by-name behavior: even with `verify_pinned_writable_dirs()`
        // active and passing, installing `by_name_state` puts attacker dir B (`id_b`) into
        // `sock_rules` and lets an enforcing Landlock worker read `decoy/marker.txt`!
        let mut by_name_policy = policy.clone();
        by_name_policy.pinned_read_write_dirs.push(pinned.clone());
        by_name_policy.read_write_paths.push(slot.clone());
        by_name_policy
            .grant_states
            .insert(slot.clone(), by_name_state);
        by_name_policy.finalize_grants()?;
        let mut by_name_notes = Vec::new();
        let by_name_assembled =
            crate::linux::assemble_landlock_rules(&by_name_policy, &mut by_name_notes)?;
        let (by_name_sock_fd, _) = by_name_assembled
            .sock_rules
            .first()
            .copied()
            .ok_or("expected one control sock_rule")?;
        let by_name_st = fstat(by_name_sock_fd)?;
        #[allow(clippy::useless_conversion)]
        let by_name_dev_ino = (u64::from(by_name_st.st_dev), u64::from(by_name_st.st_ino));
        assert_eq!(
            by_name_dev_ino, id_b,
            "control: by-name open_grant during swap installs attacker dir B even with verify_pinned_writable_dirs active"
        );

        policy.pinned_read_write_dirs.push(pinned);
        policy.read_write_paths.push(slot.clone());
        policy.grant_states.insert(slot.clone(), pin_derived_state);
        policy.finalize_grants()?;

        let mut notes = Vec::new();
        let assembled = crate::linux::assemble_landlock_rules(&policy, &mut notes)?;
        assert!(notes.is_empty(), "expected no notes, got {notes:?}");
        assert_eq!(assembled.sock_rules.len(), 1);
        let (sock_fd, _) = assembled
            .sock_rules
            .first()
            .copied()
            .ok_or("expected one sock_rule")?;
        let sock_st = fstat(sock_fd)?;
        #[allow(clippy::useless_conversion)]
        let sock_dev_ino = (u64::from(sock_st.st_dev), u64::from(sock_st.st_ino));
        assert_eq!(sock_dev_ino, id_a);
        assert_ne!(sock_dev_ino, id_b);
        assert_eq!(
            FileType::from_raw_mode(sock_st.st_mode),
            FileType::Directory
        );

        if crate::linux::probe_host_landlock_abi().is_some() {
            // Confirm under the real enforcing kernel that the old by-name state actually exposes
            // `decoy/marker.txt` even though `verify_pinned_writable_dirs()` passed.
            let bp = by_name_policy.clone();
            let bd = decoy.clone();
            std::thread::spawn(move || -> Result<(), String> {
                let status = crate::apply_landlock_current_thread(&bp)
                    .map_err(|e| format!("control apply_landlock: {e}"))?;
                if !matches!(
                    status,
                    crate::EnforcementStatus::Enforced
                        | crate::EnforcementStatus::PartiallyEnforced
                ) {
                    return Err(format!(
                        "control expected enforcing Landlock, got {status:?}"
                    ));
                }
                let leaked = std::fs::read_to_string(bd.join("marker.txt"))
                    .map_err(|e| format!("control expected by-name grant to expose dir B: {e}"))?;
                if leaked != "DIR-B-ATTACKER" {
                    return Err(format!("unexpected control marker body: {leaked:?}"));
                }
                Ok(())
            })
            .join()
            .map_err(|_| "control enforcement thread panicked")??;

            // Confirm under the real enforcing kernel that the pin-derived state denies
            // `decoy/marker.txt` while allowing authorized access to `slot` (`dir A`) and `docroot`.
            let p = policy.clone();
            let s = slot.clone();
            let d = decoy.clone();
            let dr = docroot.clone();
            std::thread::spawn(move || -> Result<(), String> {
                let status = crate::apply_landlock_current_thread(&p)
                    .map_err(|e| format!("apply_landlock: {e}"))?;
                if !matches!(
                    status,
                    crate::EnforcementStatus::Enforced | crate::EnforcementStatus::PartiallyEnforced
                ) {
                    return Err(format!("expected enforcing Landlock, got {status:?}"));
                }
                // Positive controls: dir A (`slot`) and docroot allowed.
                let body = std::fs::read_to_string(s.join("ok.txt"))
                    .map_err(|e| format!("read dir A failed: {e}"))?;
                if body != "DIR-A-OK" {
                    return Err(format!("unexpected dir A body: {body:?}"));
                }
                let created = s.join("rotated.log");
                std::fs::write(&created, b"OK").map_err(|e| format!("write dir A failed: {e}"))?;
                std::fs::remove_file(&created)
                    .map_err(|e| format!("remove dir A failed: {e}"))?;
                std::fs::read_to_string(dr.join("index.html"))
                    .map_err(|e| format!("read docroot failed: {e}"))?;
                // Negative control: dir B (`decoy`) must be DENIED under enforcing Landlock.
                if std::fs::read_to_string(d.join("marker.txt"))
                    .err()
                    .map(|e| e.kind())
                    != Some(ErrorKind::PermissionDenied)
                {
                    return Err("attacker dir B (`decoy/marker.txt`) must be denied under enforcing Landlock".to_owned());
                }
                Ok(())
            })
            .join()
            .map_err(|_| "swap-restore enforcement thread panicked")??;
        }

        // Part B: run EMFILE failure checks in an isolated child process.
        let emfile_res = run_unit_test_child(
            "landlock_enforcement_tests::security_grant_state_from_pinned_dir_ignores_renamed_pathname_and_fails_cleanly_on_emfile",
            CHILD_ENV,
            "emfile",
            BASE_ENV,
            &base,
        );
        let _ = std::fs::remove_dir_all(&base);
        emfile_res
    }

    /// Fix round 1, Test C1 (Correction 1 — MUST FAIL on `c2f4fc8`, MUST PASS after fix):
    /// Proves that when a rotating log's canonical parent already has a retained pin in
    /// `pinned_read_write_dirs`, a second `bind_log_rotation_dir` while the pathname is ABSENT or
    /// replaced by a REGULAR FILE fails closed (via `existing.verify_identity()`) before touching
    /// `grant_states`, never overwrites the socket-class grant with `AbsentAtStartup` or a by-name
    /// file grant alongside the retained pin, and a subsequent `finalize_grants()` while directory
    /// B occupies the pathname never opens B by name. Also confirms a genuinely unpinned absent
    /// parent preserves the original fallback (`pinned == None`, `AbsentAtStartup`).
    #[cfg(target_os = "linux")]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn fix1_second_bind_absent_or_regular_file_preserves_pin_and_blocks_by_name_retry()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::io::ErrorKind;
        use std::os::unix::fs::MetadataExt as _;

        use rustix::fs::{FileType, fstat};

        for mode in ["absent", "regular-file"] {
            let base = short_socket_test_dir(if mode == "absent" { "f1a" } else { "f1f" })?;
            if let Some(reason) = miraserve_config::sandbox_tree_rejection(&base.to_string_lossy())
            {
                let _ = std::fs::remove_dir_all(&base);
                return Err(format!("temp path '{}' rejected: {reason}", base.display()).into());
            }
            let docroot = base.join("www");
            let log_dir = base.join("logs");
            let aside = base.join("logs_aside");
            let decoy = base.join("decoy");
            let unpinned_dir = base.join("unpinned_logs");
            std::fs::create_dir_all(&docroot)?;
            std::fs::create_dir_all(&log_dir)?;
            std::fs::create_dir_all(&decoy)?;
            std::fs::write(docroot.join("index.html"), "DOCROOT-OK")?;
            std::fs::write(log_dir.join("ok.txt"), "DIR-A-OK")?;
            std::fs::write(decoy.join("marker.txt"), "DIR-B-ATTACKER")?;

            let md_a = std::fs::metadata(&log_dir)?;
            let md_b = std::fs::metadata(&decoy)?;
            let id_a = (md_a.dev(), md_a.ino());
            let id_b = (md_b.dev(), md_b.ino());
            assert_ne!(id_a, id_b);

            let kdl = format!(
                r#"
server {{
    listen "127.0.0.1:8443"
    sandbox {{
        landlock #true
        seccomp "off"
        socket-tree "{log_dir}"
    }}
}}
site "fix1.example.test" {{
    root "{docroot}"
}}
"#,
                log_dir = kdl_escape_test_path(&log_dir),
                docroot = kdl_escape_test_path(&docroot),
            );
            let (cfg, _) = miraserve_config::parse_kdl("fix1.kdl", &kdl)?;
            let mut policy = crate::SandboxPolicy::from_config_with_file(&cfg, None, None);

            // First bind pins directory A and ties socket-class `grant_states[log_dir]` to A.
            let first =
                policy.bind_log_rotation_dir(&log_dir.join("server.log"), &cfg, None, None, &[])?;
            assert!(first.pinned.is_some());
            assert_eq!(policy.pinned_read_write_dirs.len(), 1);
            assert_eq!(policy.granted_identity(&log_dir), Some(id_a));

            // Move directory A aside so `log_dir` is either absent or a regular file.
            std::fs::rename(&log_dir, &aside)?;
            let regular_file_id = if mode == "regular-file" {
                std::fs::write(&log_dir, b"NOT-A-DIR")?;
                let rf_md = std::fs::metadata(&log_dir)?;
                Some((rf_md.dev(), rf_md.ino()))
            } else {
                None
            };

            // Second bind of the same canonical parent while a pin is retained MUST fail closed
            // without replacing `grant_states[log_dir]` with `AbsentAtStartup` or a file grant.
            let warnings_before = policy.warnings.len();
            let second_res =
                policy.bind_log_rotation_dir(&log_dir.join("access.log"), &cfg, None, None, &[]);
            let second_err = match second_res {
                Err(err) => err,
                Ok(binding) => {
                    let _ = std::fs::remove_dir_all(&base);
                    return Err(format!(
                        "mode {mode}: second bind while pin retained must fail closed instead of falling back to open_grant; got Ok(pinned={:?}), granted_identity={:?}",
                        binding.pinned.is_some(),
                        policy.granted_identity(&log_dir),
                    )
                    .into());
                }
            };
            assert_eq!(policy.warnings.len(), warnings_before + 1);
            assert_eq!(
                policy.warnings.last().map(String::as_str),
                Some(second_err.as_str())
            );
            assert_eq!(policy.pinned_read_write_dirs.len(), 1);
            assert_eq!(
                policy.granted_identity(&log_dir),
                Some(id_a),
                "mode {mode}: grant_states[log_dir] must stay tied to pin A (never AbsentAtStartup or file {regular_file_id:?})"
            );

            // Put attacker dir B at `log_dir` and finalize: must keep pin A, never open dir B.
            if mode == "regular-file" {
                std::fs::remove_file(&log_dir)?;
            }
            std::fs::rename(&decoy, &log_dir)?;
            policy.finalize_grants()?;
            assert_eq!(
                policy.granted_identity(&log_dir),
                Some(id_a),
                "mode {mode}: finalize_grants must never open decoy dir B while pin A is retained"
            );

            // While dir B sits at `log_dir`, assembly fails closed via `verify_pinned_writable_dirs`.
            let mut bad_notes = Vec::new();
            assert!(
                crate::linux::assemble_landlock_rules(&policy, &mut bad_notes).is_err(),
                "mode {mode}: assemble_landlock_rules must refuse while decoy dir B sits at log_dir"
            );

            // Restore dir A to `log_dir` and dir B to `decoy`: assembly and enforcing Landlock
            // both bind solely to dir A (never dir B).
            std::fs::rename(&log_dir, &decoy)?;
            std::fs::rename(&aside, &log_dir)?;
            let mut notes = Vec::new();
            let assembled = crate::linux::assemble_landlock_rules(&policy, &mut notes)?;
            assert!(notes.is_empty(), "mode {mode}: unexpected notes {notes:?}");
            let (sock_fd, _) = assembled
                .sock_rules
                .first()
                .copied()
                .ok_or("expected one sock_rule")?;
            let sock_st = fstat(sock_fd)?;
            #[allow(clippy::useless_conversion)]
            let sock_dev_ino = (u64::from(sock_st.st_dev), u64::from(sock_st.st_ino));
            assert_eq!(sock_dev_ino, id_a);
            assert_ne!(sock_dev_ino, id_b);
            assert_eq!(
                FileType::from_raw_mode(sock_st.st_mode),
                FileType::Directory
            );

            if crate::linux::probe_host_landlock_abi().is_some() {
                let p = policy.clone();
                let ld = log_dir.clone();
                let d = decoy.clone();
                std::thread::spawn(move || -> Result<(), String> {
                    crate::apply_landlock_current_thread(&p)
                        .map_err(|e| format!("apply_landlock: {e}"))?;
                    std::fs::read_to_string(ld.join("ok.txt"))
                        .map_err(|e| format!("read dir A: {e}"))?;
                    if std::fs::read_to_string(d.join("marker.txt"))
                        .err()
                        .map(|e| e.kind())
                        != Some(ErrorKind::PermissionDenied)
                    {
                        return Err(
                            "decoy dir B must be denied under enforcing Landlock".to_owned()
                        );
                    }
                    Ok(())
                })
                .join()
                .map_err(|_| "fix1 enforcement thread panicked")??;
            }

            // Genuinely unpinned absent parent keeps the old fallback (`pinned == None`, `AbsentAtStartup`).
            let unpinned = policy.bind_log_rotation_dir(
                &unpinned_dir.join("server.log"),
                &cfg,
                None,
                None,
                &[],
            )?;
            assert!(unpinned.pinned.is_none());
            assert_eq!(policy.granted_identity(&unpinned_dir), None);

            let _ = std::fs::remove_dir_all(&base);
        }
        Ok(())
    }

    /// Fix round 1, Test C2 (Correction 2 — MUST FAIL on `c2f4fc8`, MUST PASS after fix):
    /// Rust's Unix runtime (`sanitize_standard_fds`) reopens closed descriptors 0–2 to `/dev/null`
    /// before `main()`, and `#![forbid(unsafe_code)]` forbids closing raw fds 0–2 afterwards, so
    /// leaving only fds `< 3` free cannot be arranged portably inside a safe Rust test binary.
    /// Instead, this test verifies the exact Linux kernel syscall argument directly via a stacked
    /// thread-local seccomp-bpf filter that:
    ///   1. Rejects `SYS_fcntl(fd, F_DUPFD_CLOEXEC, min)` with `EPERM` whenever `min != 0`
    ///      (catching `BorrowedFd::try_clone_to_owned()`, which passes `min = 3`), and
    ///   2. Rejects by-name `open_grant` (`openat` without `O_DIRECTORY`).
    ///
    /// Also runs a negative control on the same confined thread confirming `try_clone_to_owned()`
    /// fails with `PermissionDenied` (`EPERM`) while `bind_log_rotation_dir` succeeds with zero
    /// grant failures and `FD_CLOEXEC` set.
    #[cfg(target_os = "linux")]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn fix2_duplicate_uses_explicit_min_fd_zero_under_seccomp_abi_check()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::io::ErrorKind;
        use std::os::fd::{AsFd as _, AsRawFd as _};
        use std::os::unix::fs::MetadataExt as _;
        use std::path::PathBuf;

        use rustix::fs::{OFlags, fstat};
        use rustix::io::{FdFlags, fcntl_getfd};

        const CHILD_ENV: &str = "MIRASERVE_LOGPIN_FIX2_CHILD";
        const BASE_ENV: &str = "MIRASERVE_LOGPIN_FIX2_BASE";

        if let Ok(scenario) = std::env::var(CHILD_ENV) {
            assert_eq!(scenario, "min-zero");
            let base = PathBuf::from(std::env::var(BASE_ENV)?);
            let docroot = base.join("www");
            let log_dir = base.join("logs");
            let log_file = log_dir.join("server.log");

            let kdl = format!(
                r#"
server {{
    listen "127.0.0.1:8443"
    sandbox {{
        landlock #true
        seccomp "off"
        socket-tree "{log_dir}"
    }}
}}
site "fix2.example.test" {{
    root "{docroot}"
}}
"#,
                log_dir = kdl_escape_test_path(&log_dir),
                docroot = kdl_escape_test_path(&docroot),
            );
            let (cfg, _) = miraserve_config::parse_kdl("fix2.kdl", &kdl)?;
            let mut policy = crate::SandboxPolicy::from_config_with_file(&cfg, None, None);
            let log_md = std::fs::metadata(&log_dir)?;
            let expected_id = (log_md.dev(), log_md.ino());

            let min0_bpf = compile_fcntl_dupfd_cloexec_bpf(1, true)?;
            let no_by_name_bpf = compile_block_by_name_reopen_bpf()?;
            let policy_ref = &mut policy;
            let cfg_ref = &cfg;
            let log_file_ref = &log_file;
            let bind_res: Result<(crate::LogDirBinding, ErrorKind), String> = std::thread::scope(
                |scope| {
                    let handle = scope.spawn(move || -> Result<(crate::LogDirBinding, ErrorKind), String> {
                        seccompiler::apply_filter(&min0_bpf)
                            .map_err(|e| format!("apply min-0 seccomp filter failed: {e}"))?;
                        seccompiler::apply_filter(&no_by_name_bpf)
                            .map_err(|e| format!("apply no-by-name seccomp filter failed: {e}"))?;
                        // Positive control for the seccomp filter itself: stdlib
                        // `try_clone_to_owned()` passes `min = 3`, which MUST be rejected with
                        // `EPERM` (`PermissionDenied`).
                        let stdlib_err_kind = std::io::stdin()
                            .as_fd()
                            .try_clone_to_owned()
                            .err()
                            .ok_or_else(|| {
                                "expected try_clone_to_owned (min=3) to be blocked by seccomp"
                                    .to_owned()
                            })?
                            .kind();
                        let binding = policy_ref
                            .bind_log_rotation_dir(log_file_ref, cfg_ref, None, None, &[])?;
                        // Also unit-test `grant_state_from_pinned_dir` directly under the same
                        // `min != 0` seccomp filter.
                        let pin_for_helper = binding
                            .pinned
                            .as_ref()
                            .ok_or_else(|| "expected pinned dir from bind".to_owned())?;
                        match crate::grant_state_from_pinned_dir(pin_for_helper) {
                            crate::GrantState::Installed { fd, .. } => {
                                if !fcntl_getfd(&fd)
                                    .map_err(|e| format!("fcntl_getfd helper fd failed: {e}"))?
                                    .contains(FdFlags::CLOEXEC)
                                {
                                    return Err(
                                        "helper duplicated fd missing FD_CLOEXEC".to_owned()
                                    );
                                }
                            }
                            other => {
                                return Err(format!(
                                    "grant_state_from_pinned_dir must succeed under min=0 seccomp filter, got {other:?}"
                                ));
                            }
                        }
                        Ok((binding, stdlib_err_kind))
                    });
                    handle
                        .join()
                        .map_err(|_| "fix2 bind thread panicked".to_owned())?
                },
            );

            let (binding, stdlib_err_kind) = bind_res.map_err(|e| {
                format!(
                    "bind_log_rotation_dir must duplicate via F_DUPFD_CLOEXEC with min=0 (not try_clone_to_owned min=3): {e}"
                )
            })?;
            assert_eq!(stdlib_err_kind, ErrorKind::PermissionDenied);
            assert!(binding.pinned.is_some());
            assert!(
                policy.grant_failures().is_empty(),
                "expected no grant failures when dup uses min=0; got {:?}",
                policy.grant_failures()
            );
            assert_eq!(policy.granted_identity(&log_dir), Some(expected_id));

            policy.finalize_grants()?;
            let mut notes = Vec::new();
            let assembled = crate::linux::assemble_landlock_rules(&policy, &mut notes)?;
            let (sock_fd, _) = assembled
                .sock_rules
                .first()
                .copied()
                .ok_or("expected one sock_rule")?;
            let pinned_rw = policy
                .pinned_read_write_dirs
                .first()
                .ok_or("expected one pinned_read_write_dir")?;
            assert_ne!(sock_fd.as_raw_fd(), pinned_rw.file.as_raw_fd());
            assert!(
                fcntl_getfd(sock_fd)?.contains(FdFlags::CLOEXEC),
                "duplicated descriptor must carry FD_CLOEXEC"
            );
            let sock_flags = proc_fdinfo_flags_octal(sock_fd.as_raw_fd())?;
            let o_pin_flags =
                OFlags::PATH.bits() | OFlags::DIRECTORY.bits() | OFlags::NOFOLLOW.bits();
            assert_eq!(sock_flags & o_pin_flags, o_pin_flags);
            let sock_st = fstat(sock_fd)?;
            #[allow(clippy::useless_conversion)]
            let sock_dev_ino = (u64::from(sock_st.st_dev), u64::from(sock_st.st_ino));
            assert_eq!(sock_dev_ino, expected_id);
            return Ok(());
        }

        let base = short_socket_test_dir("f2m")?;
        if let Some(reason) = miraserve_config::sandbox_tree_rejection(&base.to_string_lossy()) {
            let _ = std::fs::remove_dir_all(&base);
            return Err(format!("temp path '{}' rejected: {reason}", base.display()).into());
        }
        std::fs::create_dir_all(base.join("www"))?;
        std::fs::create_dir_all(base.join("logs"))?;
        std::fs::write(base.join("www").join("index.html"), "DOCROOT-OK")?;

        let res = run_unit_test_child(
            "landlock_enforcement_tests::fix2_duplicate_uses_explicit_min_fd_zero_under_seccomp_abi_check",
            CHILD_ENV,
            "min-zero",
            BASE_ENV,
            &base,
        );
        let _ = std::fs::remove_dir_all(&base);
        res
    }

    /// Fix round 1, Test C3 (Correction 3 — MUST FAIL on `c2f4fc8`, MUST PASS after fix):
    /// For a rotating log whose parent is NOT in the socket class (`socket-tree` is a disjoint
    /// directory):
    ///   1. Under a seccomp filter rejecting ALL `fcntl(F_DUPFD_CLOEXEC)` with `EPERM`, both
    ///      first and second `bind_log_rotation_dir` and `finalize_grants` succeed with zero
    ///      `F_DUPFD_CLOEXEC` calls, and the stored `grant_states[log_dir]` descriptor carries
    ///      `O_PATH | O_CLOEXEC` WITHOUT `O_DIRECTORY` (byte-for-byte `c4ae997`).
    ///   2. Under a seccomp filter rejecting by-name `openat` without `O_DIRECTORY` (`EPERM`)
    ///      while allowing `F_DUPFD_CLOEXEC`, `bind_log_rotation_dir` triggers that `openat` and
    ///      records `"cannot open grant target: Operation not permitted"` (proving the by-name
    ///      `open_grant` path WAS taken, matching `c4ae997`).
    #[cfg(target_os = "linux")]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn fix3_disjoint_rotating_log_calls_by_name_open_and_never_dups()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::MetadataExt as _;
        use std::path::PathBuf;

        use rustix::fs::OFlags;
        use rustix::io::{FdFlags, fcntl_getfd};

        const CHILD_ENV: &str = "MIRASERVE_LOGPIN_FIX3_CHILD";
        const BASE_ENV: &str = "MIRASERVE_LOGPIN_FIX3_BASE";

        if let Ok(scenario) = std::env::var(CHILD_ENV) {
            let base = PathBuf::from(std::env::var(BASE_ENV)?);
            let docroot = base.join("www");
            let log_dir = base.join("logs");
            let socks_dir = base.join("socks");
            let log_file = log_dir.join("server.log");
            let access_log_file = log_dir.join("access.log");

            let kdl = format!(
                r#"
server {{
    listen "127.0.0.1:8443"
    sandbox {{
        landlock #true
        seccomp "off"
        socket-tree "{socks_dir}"
    }}
}}
site "fix3.example.test" {{
    root "{docroot}"
}}
"#,
                socks_dir = kdl_escape_test_path(&socks_dir),
                docroot = kdl_escape_test_path(&docroot),
            );
            let (cfg, _) = miraserve_config::parse_kdl("fix3.kdl", &kdl)?;
            let log_md = std::fs::metadata(&log_dir)?;
            let expected_log_id = (log_md.dev(), log_md.ino());

            match scenario.as_str() {
                "no-dup" => {
                    let mut policy = crate::SandboxPolicy::from_config_with_file(&cfg, None, None);
                    let deny_dup_bpf = compile_fcntl_dupfd_cloexec_bpf(1, false)?;
                    let res: Result<(), String> = std::thread::scope(|scope| {
                        let handle = scope.spawn(|| -> Result<(), String> {
                            seccompiler::apply_filter(&deny_dup_bpf)
                                .map_err(|e| format!("apply deny-dup seccomp failed: {e}"))?;
                            policy.bind_log_rotation_dir(&log_file, &cfg, None, None, &[])?;
                            policy.bind_log_rotation_dir(
                                &access_log_file,
                                &cfg,
                                None,
                                None,
                                &[],
                            )?;
                            policy.finalize_grants().map_err(|e| e.to_string())?;
                            Ok(())
                        });
                        handle
                            .join()
                            .map_err(|_| "fix3 no-dup thread panicked".to_owned())?
                    });
                    res.map_err(|e| {
                        format!("disjoint rotating log must NOT call F_DUPFD_CLOEXEC: {e}")
                    })?;
                    assert!(
                        policy.grant_failures().is_empty(),
                        "disjoint rotating log unexpected grant_failures: {:?}",
                        policy.grant_failures()
                    );
                    assert_eq!(policy.granted_identity(&log_dir), Some(expected_log_id));
                    match policy.grant_states.get(&log_dir) {
                        Some(crate::GrantState::Installed { fd, .. }) => {
                            let flags = proc_fdinfo_flags_octal(fd.as_raw_fd())?;
                            assert_ne!(
                                flags & OFlags::PATH.bits(),
                                0,
                                "disjoint grant FD must carry O_PATH (flags={flags:#o})"
                            );
                            assert_eq!(
                                flags & (OFlags::DIRECTORY.bits() | OFlags::NOFOLLOW.bits()),
                                0,
                                "disjoint grant FD must match c4ae997 open_grant (O_PATH|O_CLOEXEC without O_DIRECTORY|O_NOFOLLOW; flags={flags:#o})"
                            );
                            assert!(
                                fcntl_getfd(fd)?.contains(FdFlags::CLOEXEC),
                                "disjoint grant FD must set FD_CLOEXEC"
                            );
                        }
                        other => {
                            return Err(format!(
                                "expected Installed grant_state for disjoint log_dir, got {other:?}"
                            )
                            .into());
                        }
                    }
                }
                "uses-by-name-open" => {
                    let mut policy = crate::SandboxPolicy::from_config_with_file(&cfg, None, None);
                    let deny_by_name_bpf = compile_block_by_name_reopen_bpf()?;
                    let bind_res: Result<crate::LogDirBinding, String> =
                        std::thread::scope(|scope| {
                            let handle = scope.spawn(|| -> Result<crate::LogDirBinding, String> {
                                seccompiler::apply_filter(&deny_by_name_bpf).map_err(|e| {
                                    format!("apply deny-openat seccomp failed: {e}")
                                })?;
                                policy.bind_log_rotation_dir(&log_file, &cfg, None, None, &[])
                            });
                            handle
                                .join()
                                .map_err(|_| "fix3 by-name thread panicked".to_owned())?
                        });
                    let binding = bind_res.map_err(|e| {
                        format!(
                            "disjoint bind should return Ok even when open_grant hits EPERM: {e}"
                        )
                    })?;
                    assert!(binding.pinned.is_some());
                    let failures = policy.grant_failures();
                    assert!(
                        failures.iter().any(
                            |f| f.contains("cannot open grant target: Operation not permitted")
                        ),
                        "disjoint rotating log MUST execute by-name open_grant (expected EPERM failure); got failures={failures:?}"
                    );
                }
                other => return Err(format!("unknown fix3 scenario: {other}").into()),
            }
            return Ok(());
        }

        for scenario in ["no-dup", "uses-by-name-open"] {
            let base = short_socket_test_dir(if scenario == "no-dup" { "f3n" } else { "f3o" })?;
            if let Some(reason) = miraserve_config::sandbox_tree_rejection(&base.to_string_lossy())
            {
                let _ = std::fs::remove_dir_all(&base);
                return Err(format!("temp path '{}' rejected: {reason}", base.display()).into());
            }
            std::fs::create_dir_all(base.join("www"))?;
            std::fs::create_dir_all(base.join("logs"))?;
            std::fs::create_dir_all(base.join("socks"))?;
            std::fs::write(base.join("www").join("index.html"), "DOCROOT-OK")?;

            let res = run_unit_test_child(
                "landlock_enforcement_tests::fix3_disjoint_rotating_log_calls_by_name_open_and_never_dups",
                CHILD_ENV,
                scenario,
                BASE_ENV,
                &base,
            );
            let _ = std::fs::remove_dir_all(&base);
            res?;
        }
        Ok(())
    }

    /// Fix round 1, Test C4 (Correction 4 — MUST FAIL on `c2f4fc8`, MUST PASS after fix):
    /// Exercises a genuine binder-level `EMFILE` on descriptor duplication AFTER `open_validated`
    /// succeeds (via a scoped-thread seccomp filter returning `EMFILE` on `F_DUPFD_CLOEXEC`).
    /// Asserts the released failure contract:
    ///   - `bind_log_rotation_dir` returns `Ok(binding)` with the pin retained,
    ///   - `read_write_paths` and `socket_shadows_other_class` are updated as on `c4ae997`,
    ///   - zero warnings are appended,
    ///   - `grant_states[log_dir]` is `Failed { kind: ResourceExhausted }` (`resource_failure_grants`
    ///     non-empty, `writable_policy_grants` returns the OS resource-limit error),
    ///   - a later `finalize_grants()` retry after swapping `log_dir` -> dir B (and with by-name
    ///     `openat` blocked by seccomp) derives the grant state from the retained pin (dir A, NEVER
    ///     dir B), and after restoring dir A, assembly + enforcing Landlock allow dir A and deny
    ///     dir B.
    #[cfg(target_os = "linux")]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn fix4_duplicate_failure_keeps_released_contract_and_finalization_derives_from_pin()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::io::ErrorKind;
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::MetadataExt as _;
        use std::path::PathBuf;

        use rustix::fs::{FileType, OFlags, fstat};
        use rustix::io::{FdFlags, fcntl_getfd};

        const CHILD_ENV: &str = "MIRASERVE_LOGPIN_FIX4_CHILD";
        const BASE_ENV: &str = "MIRASERVE_LOGPIN_FIX4_BASE";

        if let Ok(scenario) = std::env::var(CHILD_ENV) {
            assert_eq!(scenario, "dup-emfile-and-retry");
            let base = PathBuf::from(std::env::var(BASE_ENV)?);
            let docroot = base.join("www");
            let log_dir = base.join("logs");
            let aside = base.join("logs_aside");
            let decoy = base.join("decoy");
            let log_file = log_dir.join("server.log");

            let md_a = std::fs::metadata(&log_dir)?;
            let md_b = std::fs::metadata(&decoy)?;
            let id_a = (md_a.dev(), md_a.ino());
            let id_b = (md_b.dev(), md_b.ino());
            assert_ne!(id_a, id_b);

            let kdl = format!(
                r#"
server {{
    listen "127.0.0.1:8443"
    sandbox {{
        landlock #true
        seccomp "off"
        socket-tree "{log_dir}"
    }}
}}
site "fix4.example.test" {{
    root "{docroot}"
}}
"#,
                log_dir = kdl_escape_test_path(&log_dir),
                docroot = kdl_escape_test_path(&docroot),
            );
            let (cfg, _) = miraserve_config::parse_kdl("fix4.kdl", &kdl)?;
            let mut policy = crate::SandboxPolicy::from_config_with_file(&cfg, None, None);

            // Phase 1: Pin succeeds via `open_dir_no_follow`, then `F_DUPFD_CLOEXEC` returns EMFILE (24).
            let dup_emfile_bpf = compile_fcntl_dupfd_cloexec_bpf(24, false)?;
            let warnings_before = policy.warnings.len();
            let bind_res: Result<crate::LogDirBinding, String> = std::thread::scope(|scope| {
                let handle = scope.spawn(|| -> Result<crate::LogDirBinding, String> {
                    seccompiler::apply_filter(&dup_emfile_bpf)
                        .map_err(|e| format!("apply dup-emfile seccomp failed: {e}"))?;
                    policy.bind_log_rotation_dir(&log_file, &cfg, None, None, &[])
                });
                handle
                    .join()
                    .map_err(|_| "fix4 bind thread panicked".to_owned())?
            });

            let binding = bind_res.map_err(|e| {
                format!(
                    "duplication EMFILE must keep released contract (return Ok with Failed state and retained pin); got Err({e})"
                )
            })?;
            assert_eq!(binding.real_parent, log_dir);
            assert!(binding.pinned.is_some());
            assert_eq!(policy.warnings.len(), warnings_before);
            assert_eq!(policy.pinned_read_write_dirs.len(), 1);
            assert_eq!(
                policy
                    .pinned_read_write_dirs
                    .first()
                    .map(crate::PinnedWritableDir::inode_identity),
                Some(id_a)
            );
            assert!(policy.read_write_paths.contains(&log_dir));
            assert!(policy.socket_shadows_other_class.contains(&log_dir));
            assert_eq!(policy.granted_identity(&log_dir), None);
            assert_eq!(policy.grant_failures().len(), 1);
            assert_eq!(policy.resource_failure_grants().len(), 1);
            assert_eq!(policy.policy_rejection_failures(), Vec::<String>::new());
            let inspect_err = policy
                .writable_policy_grants()
                .err()
                .ok_or("writable_policy_grants must fail closed on ResourceExhausted")?;
            assert!(
                inspect_err.to_string().contains("OS resource limit"),
                "expected OS resource limit diagnostic, got: {inspect_err}"
            );

            // Phase 2: Swap `log_dir` -> dir B on disk and retry `finalize_grants()` with by-name
            // `openat` blocked by seccomp: finalization MUST derive the grant state from the
            // retained pin (dir A) and NEVER open dir B by name.
            std::fs::rename(&log_dir, &aside)?;
            std::fs::rename(&decoy, &log_dir)?;
            let block_open_bpf = compile_block_by_name_reopen_bpf()?;
            let fin_res: Result<(), String> = std::thread::scope(|scope| {
                let handle = scope.spawn(|| -> Result<(), String> {
                    seccompiler::apply_filter(&block_open_bpf)
                        .map_err(|e| format!("apply block-open seccomp failed: {e}"))?;
                    policy.finalize_grants().map_err(|e| e.to_string())
                });
                handle
                    .join()
                    .map_err(|_| "fix4 finalize thread panicked".to_owned())?
            });
            fin_res.map_err(|e| {
                format!(
                    "finalize_grants retry for pinned overlap entry must derive from retained pin without by-name open: {e}"
                )
            })?;
            assert_eq!(policy.grant_failures(), Vec::<String>::new());
            assert_eq!(policy.resource_failure_grants(), Vec::<String>::new());
            assert_eq!(
                policy.granted_identity(&log_dir),
                Some(id_a),
                "finalize_grants retry must install dir A from retained pin, never decoy dir B ({id_b:?})"
            );

            // While dir B is still at `log_dir`, assembly fails closed via `verify_pinned_writable_dirs`.
            let mut bad_notes = Vec::new();
            assert!(
                crate::linux::assemble_landlock_rules(&policy, &mut bad_notes).is_err(),
                "assemble_landlock_rules must refuse while decoy dir B sits at log_dir"
            );

            // Restore dir A to `log_dir` and dir B to `decoy`: assembly + enforcing Landlock
            // install dir A only and deny `decoy/marker.txt`.
            std::fs::rename(&log_dir, &decoy)?;
            std::fs::rename(&aside, &log_dir)?;
            let mut notes = Vec::new();
            let assembled = crate::linux::assemble_landlock_rules(&policy, &mut notes)?;
            assert!(notes.is_empty(), "unexpected notes: {notes:?}");
            let (sock_fd, _) = assembled
                .sock_rules
                .first()
                .copied()
                .ok_or("expected one sock_rule")?;
            let sock_st = fstat(sock_fd)?;
            #[allow(clippy::useless_conversion)]
            let sock_dev_ino = (u64::from(sock_st.st_dev), u64::from(sock_st.st_ino));
            assert_eq!(sock_dev_ino, id_a);
            assert_ne!(sock_dev_ino, id_b);
            assert_eq!(
                FileType::from_raw_mode(sock_st.st_mode),
                FileType::Directory
            );
            let sock_flags = proc_fdinfo_flags_octal(sock_fd.as_raw_fd())?;
            let o_pin_flags =
                OFlags::PATH.bits() | OFlags::DIRECTORY.bits() | OFlags::NOFOLLOW.bits();
            assert_eq!(sock_flags & o_pin_flags, o_pin_flags);
            assert!(fcntl_getfd(sock_fd)?.contains(FdFlags::CLOEXEC));

            if crate::linux::probe_host_landlock_abi().is_some() {
                let p = policy.clone();
                let ld = log_dir.clone();
                let d = decoy.clone();
                std::thread::spawn(move || -> Result<(), String> {
                    crate::apply_landlock_current_thread(&p)
                        .map_err(|e| format!("apply_landlock: {e}"))?;
                    std::fs::read_to_string(ld.join("ok.txt"))
                        .map_err(|e| format!("read dir A: {e}"))?;
                    if std::fs::read_to_string(d.join("marker.txt"))
                        .err()
                        .map(|e| e.kind())
                        != Some(ErrorKind::PermissionDenied)
                    {
                        return Err(
                            "decoy dir B must be denied under enforcing Landlock".to_owned()
                        );
                    }
                    Ok(())
                })
                .join()
                .map_err(|_| "fix4 enforcement thread panicked")??;
            }
            return Ok(());
        }

        let base = short_socket_test_dir("f4e")?;
        if let Some(reason) = miraserve_config::sandbox_tree_rejection(&base.to_string_lossy()) {
            let _ = std::fs::remove_dir_all(&base);
            return Err(format!("temp path '{}' rejected: {reason}", base.display()).into());
        }
        std::fs::create_dir_all(base.join("www"))?;
        std::fs::create_dir_all(base.join("logs"))?;
        std::fs::create_dir_all(base.join("decoy"))?;
        std::fs::write(base.join("www").join("index.html"), "DOCROOT-OK")?;
        std::fs::write(base.join("logs").join("ok.txt"), "DIR-A-OK")?;
        std::fs::write(base.join("decoy").join("marker.txt"), "DIR-B-ATTACKER")?;

        let res = run_unit_test_child(
            "landlock_enforcement_tests::fix4_duplicate_failure_keeps_released_contract_and_finalization_derives_from_pin",
            CHILD_ENV,
            "dup-emfile-and-retry",
            BASE_ENV,
            &base,
        );
        let _ = std::fs::remove_dir_all(&base);
        res
    }
}

//! Implementation of `miraserve run` and `miraserve reload`.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::Args;
use miraserve_config::{Config, ConfigStore, load_file_detailed};
use miraserve_core::{
    LogDirBinding, MiraServeServer, PinnedLogDir, PinnedWritableDir, SandboxPolicy, ServerOptions,
    apply_landlock_current_thread, bind_log_file_dir, log_path_platform_rejection,
};
use miraserve_tls::load_keyd_auth_secret_file;
use serde::Serialize;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::check::{OutputFormat, QuarantinedSiteReport};

/// Maximum bytes read from a PID file (prevents OOM or blocking on FIFOs/devices).
const MAX_PID_FILE_BYTES: usize = 64;

/// Maximum safe POSIX PID (avoids `0`, `1` init, and `> i32::MAX` negative process-group wrap).
const MAX_SAFE_PID: u32 = 2_147_483_647;

/// CLI arguments for `miraserve run`.
#[derive(Debug, Args)]
pub(crate) struct RunArgs {
    /// Path to the MiraServe KDL configuration file.
    #[arg(value_name = "CONFIG", default_value = "miraserve.kdl")]
    pub(crate) config: PathBuf,

    /// Auto-generate an in-memory self-signed ECDSA P-256 development TLS certificate
    /// when no manual cert/key or ACME certificates are configured.
    #[arg(long)]
    pub(crate) dev_tls: bool,

    /// Optional PID file path written on startup and removed on clean shutdown.
    #[arg(long)]
    pub(crate) pid_file: Option<PathBuf>,

    /// Directory for storing ACME v2 account credentials and issued certificates.
    #[arg(long)]
    pub(crate) acme_dir: Option<PathBuf>,

    /// Log level filter (e.g. `"info"`, `"debug"`, `"warn"`, or `RUST_LOG` expression).
    #[arg(long, default_value = "info")]
    pub(crate) log_level: String,

    /// Optional log file path to append structured runtime logs to (useful for Windows
    /// Scheduled Tasks and daemonized deployments where stdout/stderr are detached).
    #[arg(long)]
    pub(crate) log_file: Option<PathBuf>,

    /// Optional dedicated file path for `miraserve::access` HTTP access log lines, keeping
    /// access logs separate from runtime/error logs.
    #[arg(long)]
    pub(crate) access_log: Option<PathBuf>,

    /// Optional maximum size in bytes for `--log-file` and `--access-log` before size-based
    /// rotation (`0` disables built-in rotation).
    #[arg(long, default_value_t = 0)]
    pub(crate) log_max_bytes: u64,

    /// Number of rotated log backups (`.1` .. `.N`) to keep when `--log-max-bytes` > 0.
    #[arg(long, default_value_t = 5)]
    pub(crate) log_keep: u32,

    /// Skip OS worker sandboxing (`Landlock` / `seccomp-bpf`) at startup (debugging only).
    #[arg(long)]
    pub(crate) no_sandbox: bool,

    /// Optional path to a 32-byte (Base64 or 64-hex) shared HMAC-SHA256 secret file for
    /// authenticating with `miraserve-keyd` over `LoopbackTcp`.
    #[arg(long)]
    pub(crate) keyd_auth_secret_file: Option<PathBuf>,
}

/// CLI arguments for `miraserve reload`.
#[derive(Debug, Args)]
pub(crate) struct ReloadArgs {
    /// Path to the running server's PID file.
    #[arg(long, default_value = "miraserve.pid")]
    pub(crate) pid_file: PathBuf,

    /// Optional KDL configuration file to pre-validate (including `--fs` checks) before signaling reload.
    #[arg(long)]
    pub(crate) config: Option<PathBuf>,

    /// Optional ACME state directory used during `--config` filesystem preflight checks.
    #[arg(long)]
    pub(crate) acme_dir: Option<PathBuf>,

    /// Optional 32-byte HMAC-SHA256 secret file used when probing `miraserve-keyd` over TCP.
    #[arg(long)]
    pub(crate) keyd_auth_secret_file: Option<PathBuf>,

    /// Output format (`text` or `json`).
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub(crate) format: OutputFormat,

    /// Run preflight checks and quarantine classification without signaling the running server
    /// (for hosting panels and tests).
    #[arg(long)]
    pub(crate) dry_run: bool,
}

#[derive(Debug, Serialize)]
struct ReloadJsonReport {
    /// `true` committed, `false` refused, `null` signal sent but not acknowledged in time (the
    /// server may still commit it: check its status or logs), or a dry run.
    reloaded: Option<bool>,
    /// What happened, without reading error text: `committed`, `committed_running_config` (the
    /// server committed its own configuration file, whose content differs from `--config`),
    /// `refused`, `unknown` (no acknowledgement in time), `dry_run_passed`, `dry_run_refused`.
    outcome: ReloadOutcome,
    /// Where `quarantined` comes from: `server` (the sites the committed configuration actually
    /// serves as a 503) or `preflight` (a prediction from `--config`).
    quarantined_source: &'static str,
    /// Whether this is a preflight prediction (`--dry-run`) rather than a reload outcome.
    dry_run: bool,
    /// Every per-site warning of the preflight (W024 users file, W026 isolated site, ...): each
    /// can make that site answer 503 although the reload succeeds.
    warnings: Vec<ReloadWarning>,
    quarantined: Vec<QuarantinedSiteReport>,
    /// Settings of the committed configuration (`server.listen`, `server.sandbox`, ...) that
    /// the running process applies only after a restart: restart MiraServe when non-empty.
    restart_required: Vec<String>,
    errors: Vec<String>,
}

/// The outcome of `miraserve reload`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReloadOutcome {
    Committed,
    CommittedRunningConfig,
    Refused,
    Unknown,
    DryRunPassed,
    DryRunRefused,
}

/// A reload the server acknowledged as committed (Unix only: Windows has no reload signal).
#[derive(Debug)]
#[cfg_attr(not(unix), allow(dead_code))]
struct ReloadAck {
    message: String,
    /// The server committed its own configuration file, whose content differs from `--config`.
    running_config: bool,
    /// The sites the committed configuration serves as a 503, as reported by the server.
    offline: Vec<QuarantinedSiteReport>,
    /// `server` (complete list), `server_incomplete` (fewer lines than announced), or `None`
    /// when the server is too old to report its sites.
    offline_source: Option<&'static str>,
    /// Settings of the committed configuration that need a process restart to take effect.
    restart_required: Vec<String>,
}

/// A reload that was refused, or whose outcome is not known.
#[derive(Debug)]
struct ReloadFailure {
    message: String,
    unknown: bool,
}

impl ReloadFailure {
    fn refused(message: String) -> Self {
        Self {
            message,
            unknown: false,
        }
    }
}

/// One preflight warning in the JSON report.
#[derive(Debug, Serialize)]
struct ReloadWarning {
    code: String,
    /// The configuration key it refers to (`site[3].basic-auth`, ...), when known.
    path: Option<String>,
    message: String,
}

fn write_reload_json_report(report: &ReloadJsonReport) {
    let mut stdout = io::stdout().lock();
    if let Ok(json) = serde_json::to_string_pretty(report) {
        let _ = writeln!(stdout, "{json}");
    }
}

/// Runs the MiraServe server until `SIGINT` / `SIGTERM`, handling `SIGHUP` hot reload.
#[allow(clippy::too_many_lines)]
pub(crate) fn run_server(args: &RunArgs) -> ExitCode {
    // Load and validate config + docroot/log-path overlaps BEFORE opening `--log-file` or
    // `--access-log` so an overlapping log path is rejected without creating a file inside a
    // served document root (Codex G7 P1).
    let mut loaded = match load_file_detailed(&args.config) {
        Ok(loaded) => loaded,
        Err(err) => {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(stderr, "error: {err}");
            for issue in err.validation_errors() {
                let _ = writeln!(stderr, "  - {issue}");
            }
            return ExitCode::FAILURE;
        }
    };

    let inputs = StartupPolicyInputs {
        config_path: Some(args.config.as_path()),
        acme_dir: args.acme_dir.as_deref(),
        log_file: args.log_file.as_deref(),
        access_log: args.access_log.as_deref(),
        log_max_bytes: args.log_max_bytes,
        keyd_auth_secret_file: args.keyd_auth_secret_file.as_deref(),
        no_sandbox: args.no_sandbox,
    };
    let prepared = match prepare_runtime_startup_policy(&mut loaded.config, &inputs) {
        Ok(prepared) => prepared,
        Err(violations) => {
            let mut stderr = io::stderr().lock();
            for violation in violations {
                let _ = writeln!(stderr, "error: refusing to start: {violation}");
            }
            return ExitCode::FAILURE;
        }
    };
    let mut worker_sandbox_policy = prepared.policy;
    let prebound = prepared.prebound;
    let log_specs = prepared.log_specs;
    let log_file_paths = prepared.log_file_paths;
    let log_rotation_paths = prepared.log_rotation_paths;
    let secret_file_paths = prepared.secret_file_paths;
    let acme_path_ref = prepared.effective_acme_dir.as_deref();
    let bind_ctx = LogBindContext {
        config: &loaded.config,
        config_path: Some(args.config.as_path()),
        acme_dir: acme_path_ref,
        secret_files: &secret_file_paths,
    };

    // R2-SBX-1 & R3-PKG-4: Pre-create all configured read-write state directories (including the
    // validated canonical rotating-log directories) and missing non-rotating log parents.
    let mut uncreatable_tenant_dirs: Vec<PathBuf> = Vec::new();
    for rw_dir in &worker_sandbox_policy.read_write_paths {
        let create_res = if acme_path_ref.is_some_and(|p| p == rw_dir.as_path()) {
            miraserve_tls::create_private_dir_all(rw_dir)
                .map_err(|err| io::Error::other(err.to_string()))
        } else {
            fs::create_dir_all(rw_dir)
        };
        if let Err(err) = create_res {
            // A directory only tenant sites need (a tenant publish store) that cannot be
            // created is left out of the sandbox: that tenant's feature fails on its own.
            if worker_sandbox_policy.tenant_only_paths.contains(rw_dir) {
                let mut stderr = io::stderr().lock();
                let _ = writeln!(
                    stderr,
                    "warning: cannot create tenant writable directory '{}': {err}; left out of the sandbox",
                    rw_dir.display()
                );
                uncreatable_tenant_dirs.push(rw_dir.clone());
                continue;
            }
            let mut stderr = io::stderr().lock();
            let _ = writeln!(
                stderr,
                "error: failed to create required writable directory '{}': {err}",
                rw_dir.display()
            );
            return ExitCode::FAILURE;
        }
    }
    for binding in &prebound {
        if binding.pinned.is_none()
            && let Err(err) = fs::create_dir_all(&binding.validated.real_parent)
        {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(
                stderr,
                "error: failed to create log directory '{}': {err}",
                binding.validated.real_parent.display()
            );
            return ExitCode::FAILURE;
        }
    }
    worker_sandbox_policy
        .read_write_paths
        .retain(|dir| !uncreatable_tenant_dirs.contains(dir));

    // Codex Round-5 P1 #1: Bind every log to its validated handle. A log whose directory existed
    // at validation keeps that handle; any destination change since then fails startup here,
    // before the writer creates or opens any file.
    let pinned_log_dirs =
        match finalize_cli_logs(&mut worker_sandbox_policy, &log_specs, prebound, &bind_ctx) {
            Ok(bound) => bound,
            Err(reason) => {
                let mut stderr = io::stderr().lock();
                let _ = writeln!(stderr, "error: refusing to start: {reason}");
                return ExitCode::FAILURE;
            }
        };

    // Codex Round-8/10: Finalize grant descriptors once, after startup created the writable
    // directories and log binding added its grants, and before the policy is shared with any
    // thread. Already validated descriptors (read-trees, socket-trees) are kept; trees that
    // first appear now are validated on the opened object; any non-absence failure stops
    // startup instead of silently omitting a grant.
    if let Err(err) = worker_sandbox_policy.finalize_grants() {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(stderr, "error: refusing to start: {err}");
        return ExitCode::FAILURE;
    }
    let find_bound = |path: Option<&PathBuf>| {
        path.and_then(|p| {
            pinned_log_dirs
                .iter()
                .find(|pl| &pl.configured_path == p)
                .cloned()
        })
    };
    let pinned_runtime_log = find_bound(args.log_file.as_ref());
    let pinned_access_log = find_bound(args.access_log.as_ref());

    if let Err(err) = init_tracing(
        &args.log_level,
        pinned_runtime_log,
        pinned_access_log,
        args.log_max_bytes,
        args.log_keep,
    ) {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(stderr, "error: failed to initialize logging: {err}");
        return ExitCode::FAILURE;
    }

    for warn_issue in &loaded.report.warnings {
        if args.dev_tls && warn_issue.code == "W015" {
            continue;
        }
        warn!(code = %warn_issue.code, "{}", warn_issue.message);
    }

    let keyd_auth_secret = match &args.keyd_auth_secret_file {
        Some(path) => match load_keyd_auth_secret_file(path) {
            Ok(secret) => Some(*secret),
            Err(err) => {
                let mut stderr = io::stderr().lock();
                let _ = writeln!(
                    stderr,
                    "error: failed to load --keyd-auth-secret-file '{}': {err}",
                    path.display()
                );
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };

    // R2-RUN-1: Acquire an OS-backed exclusive lock on `--pid-file` BEFORE spawning worker threads
    // or binding ports so a duplicate instance fails immediately without overwriting or deleting a
    // live server's PID file!
    let pid_guard = match args.pid_file.as_ref() {
        Some(path) => match PidFileGuard::create(path) {
            Ok(guard) => Some(guard),
            Err(err) => {
                error!(path = %path.display(), error = %err, "failed to acquire PID file lock");
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };

    let store = Arc::new(ConfigStore::new(loaded.config));
    let reload_status_file = pid_guard
        .as_ref()
        .and_then(|g| g.clone_reload_status_file().ok());
    let worker_landlock_failed = Arc::new(AtomicBool::new(false));
    let abort_signal = Arc::new(tokio::sync::Notify::new());
    let policy_arc = Arc::new(worker_sandbox_policy);

    let options = ServerOptions {
        dev_tls: args.dev_tls,
        config_path: Some(args.config.clone()),
        acme_state_dir: args.acme_dir.clone(),
        apply_sandbox: !args.no_sandbox,
        keyd_auth_secret,
        secret_file_paths,
        reload_status_file,
        abort_signal: Some(Arc::clone(&abort_signal)),
        log_file_paths,
        log_rotation_paths,
        startup_sandbox_policy: Some(Arc::clone(&policy_arc)),
        pinned_log_dirs,
    };

    // Enforce Linux Landlock LSM on EVERY Tokio worker thread at thread start (in addition to
    // main-thread Landlock + process-wide seccomp-bpf TSYNC installed in `MiraServeServer::start`).
    // R2-SBX-3 & R5-SBX-2: Abort unconditionally if ANY worker or blocking thread fails Landlock
    // confinement (including during startup, eliminating the pre-startup window).
    let mut rt_builder = tokio::runtime::Builder::new_multi_thread();
    rt_builder.enable_all();
    if !args.no_sandbox && policy_arc.landlock {
        let worker_policy = Arc::clone(&policy_arc);
        let failed_flag = Arc::clone(&worker_landlock_failed);
        let notify = Arc::clone(&abort_signal);
        rt_builder.on_thread_start(move || {
            if let Err(err) = apply_landlock_current_thread(&worker_policy) {
                error!(error = %err, "terminating immediately: worker thread failed Landlock LSM confinement");
                failed_flag.store(true, Ordering::Release);
                notify.notify_waiters();
                std::process::abort();
            }
        });
    }

    let rt = match rt_builder.build() {
        Ok(rt) => rt,
        Err(err) => {
            error!(error = %err, "failed to create Tokio runtime");
            return ExitCode::FAILURE;
        }
    };

    let exit_code = rt.block_on(async move {
        if worker_landlock_failed.load(Ordering::Acquire) {
            error!("aborting startup because worker-thread Landlock LSM enforcement failed");
            return ExitCode::FAILURE;
        }

        match MiraServeServer::start(store, options).await {
            Ok(running) => {
                if worker_landlock_failed.load(Ordering::Acquire) {
                    error!("aborting because worker-thread Landlock LSM failed during startup");
                    running.shutdown().await;
                    return ExitCode::FAILURE;
                }
                if let Some(report) = running.sandbox_report() {
                    info!(
                        platform = report.platform,
                        landlock = ?report.landlock,
                        seccomp = ?report.seccomp,
                        read_only_paths = report.read_only_path_count,
                        read_write_paths = report.read_write_path_count,
                        socket_paths = report.socket_path_count,
                        "OS worker sandbox status"
                    );
                    for note in &report.notes {
                        warn!(sandbox_note = %note, "sandbox advisory");
                    }
                } else {
                    warn!(
                        "OS worker sandboxing skipped via --no-sandbox (Landlock and seccomp-bpf, including MiraServe's in-process set-ID protection, are disabled)"
                    );
                }
                for bound in running.bound_listeners() {
                    info!(kind = ?bound.kind, addr = %bound.local_addr, "MiraServe listening");
                }
                // The access log is written in batches; this keeps a quiet server's last
                // lines from waiting in memory.
                let access_flusher = tokio::spawn(async {
                    let mut tick = tokio::time::interval(ACCESS_LOG_FLUSH_INTERVAL);
                    loop {
                        tick.tick().await;
                        flush_access_log();
                    }
                });
                running.run_until_signal().await;
                access_flusher.abort();
                if worker_landlock_failed.load(Ordering::Acquire) {
                    ExitCode::FAILURE
                } else {
                    ExitCode::SUCCESS
                }
            }
            Err(err) => {
                error!(error = %err, "failed to start MiraServe");
                ExitCode::FAILURE
            }
        }
    });
    // `shutdown_with_report` already drained both offloaded queues under one 2 s deadline and
    // emitted the warning with any remaining counts or force-closed connection notice. Exit
    // status is decided solely by the final access-log flush, matching v0.1.4 (so `SIGTERM`
    // under load does not trigger `Restart=on-failure`).
    let exit_code = if final_access_log_flush() {
        exit_code
    } else {
        ExitCode::FAILURE
    };

    drop(pid_guard);
    exit_code
}

/// Validates an optional config file (syntax, schema, and `--fs` filesystem checks) and signals
/// a running MiraServe process to reload.
#[allow(clippy::too_many_lines)]
pub(crate) fn run_reload(args: &ReloadArgs) -> ExitCode {
    let mut quarantined: Vec<QuarantinedSiteReport> = Vec::new();
    let mut warnings: Vec<ReloadWarning> = Vec::new();
    // The digest of the very bytes that were validated (not of a second read of the file).
    let mut expected_config_sha256: Option<String> = None;
    if args.dry_run && args.config.is_none() {
        let message = "--dry-run needs --config <file> to check";
        match args.format {
            OutputFormat::Text => {
                let mut stderr = io::stderr().lock();
                let _ = writeln!(stderr, "error: {message}");
            }
            OutputFormat::Json => write_reload_json_report(&ReloadJsonReport {
                reloaded: None,
                outcome: ReloadOutcome::DryRunRefused,
                quarantined_source: "preflight",
                dry_run: true,
                warnings: Vec::new(),
                quarantined: Vec::new(),
                restart_required: Vec::new(),
                errors: vec![message.to_owned()],
            }),
        }
        return ExitCode::FAILURE;
    }

    if let Some(cfg_path) = &args.config {
        let loaded = match load_file_detailed(cfg_path) {
            Ok(loaded) => loaded,
            Err(err) => {
                match args.format {
                    OutputFormat::Text => {
                        let mut stderr = io::stderr().lock();
                        let _ = writeln!(
                            stderr,
                            "error: refusing to signal reload because '{}' is invalid: {err}",
                            cfg_path.display()
                        );
                        for issue in err.validation_errors() {
                            let _ = writeln!(stderr, "  - {issue}");
                        }
                    }
                    OutputFormat::Json => {
                        let mut errors = vec![format!(
                            "refusing to signal reload because '{}' is invalid: {err}",
                            cfg_path.display()
                        )];
                        for issue in err.validation_errors() {
                            errors.push(issue.to_string());
                        }
                        write_reload_json_report(&ReloadJsonReport {
                            reloaded: (!args.dry_run).then_some(false),
                            outcome: if args.dry_run {
                                ReloadOutcome::DryRunRefused
                            } else {
                                ReloadOutcome::Refused
                            },
                            quarantined_source: "preflight",
                            dry_run: args.dry_run,
                            warnings: std::mem::take(&mut warnings),
                            quarantined,
                            restart_required: Vec::new(),
                            errors,
                        });
                    }
                }
                return ExitCode::FAILURE;
            }
        };

        // HANDOVER §5 #8: Run the exact same `--fs` checks and quarantine classification as
        // `miraserve check --fs` before signaling SIGHUP so missing certs/keys, bad keyd sockets,
        // or unsafe docroots fail upfront with clear site-identifying diagnostics.
        expected_config_sha256 = Some(miraserve_tls::sha256_hex(loaded.source_text.as_bytes()));
        let (fs_issues, site_quarantines) = crate::check::collect_filesystem_issues_and_quarantined(
            &loaded,
            Some(cfg_path.as_path()),
            args.acme_dir.as_deref(),
            args.keyd_auth_secret_file.as_deref(),
        );
        quarantined = site_quarantines;
        let (fs_errors, fs_warnings): (Vec<_>, Vec<_>) = fs_issues
            .into_iter()
            .partition(|i| i.severity == miraserve_config::Severity::Error);
        // The same warnings `check --fs` shows: configuration validation, sandbox policy, and
        // filesystem checks.
        // From the configuration with unusable tenant roots isolated, as `check` and the
        // server build it.
        let mut policy_config = loaded.config.clone();
        miraserve_core::quarantine_inaccessible_tenant_roots(&mut policy_config);
        let sandbox_warnings = miraserve_core::SandboxPolicy::from_config_with_file(
            &policy_config,
            Some(cfg_path.as_path()),
            args.acme_dir.as_deref(),
        )
        .warnings;
        warnings = loaded
            .report
            .warnings
            .iter()
            .chain(fs_warnings.iter())
            .map(|w| ReloadWarning {
                code: w.code.clone(),
                path: w.path.clone(),
                message: w.message.clone(),
            })
            .chain(sandbox_warnings.into_iter().map(|message| ReloadWarning {
                code: "W017".to_owned(),
                path: None,
                message,
            }))
            .collect();
        // Sites the later checks (certificates, dependencies) predict as offline are reported
        // too, not only those the root classification found.
        let mut listed: std::collections::HashSet<usize> =
            quarantined.iter().map(|q| q.index).collect();
        // W026 (isolated site) and W024 (users file that cannot be loaded) both make the whole
        // site answer 503, as the server will report them after the reload.
        for w in fs_warnings
            .iter()
            .filter(|w| matches!(w.code.as_str(), "W026" | "W024"))
        {
            let Some(index) = w
                .path
                .as_deref()
                .and_then(|key| key.strip_prefix("site["))
                .and_then(|rest| rest.split(']').next())
                .and_then(|index| index.parse::<usize>().ok())
            else {
                continue;
            };
            if !listed.insert(index) {
                continue;
            }
            let site = loaded
                .config
                .sites
                .get(index)
                .and_then(|site| site.hosts.first())
                .cloned()
                .unwrap_or_default();
            quarantined.push(QuarantinedSiteReport {
                site,
                index,
                code: w.code.clone(),
                reason: w.message.clone(),
            });
        }

        if args.format == OutputFormat::Text {
            let mut stderr = io::stderr().lock();
            // Every warning is printed (W026 also covers tenant dependency problems that are not
            // in the quarantine list below).
            for w in &fs_warnings {
                let _ = writeln!(stderr, "warning[{}]: {}", w.code, w.message);
            }
            for q in &quarantined {
                let _ = writeln!(
                    stderr,
                    "quarantined: site '{}' (site[{}]): {}",
                    q.site, q.index, q.reason
                );
            }
        }
        if !fs_errors.is_empty() {
            match args.format {
                OutputFormat::Text => {
                    let mut stderr = io::stderr().lock();
                    for e in &fs_errors {
                        let _ = writeln!(stderr, "error[{}]: {}", e.code, e.message);
                    }
                    let _ = writeln!(
                        stderr,
                        "error: refusing to signal reload because '{}' failed --fs check with {} error(s)",
                        cfg_path.display(),
                        fs_errors.len()
                    );
                }
                OutputFormat::Json => {
                    let mut errors: Vec<String> = fs_errors
                        .iter()
                        .map(|e| format!("error[{}]: {}", e.code, e.message))
                        .collect();
                    errors.push(format!(
                        "refusing to signal reload because '{}' failed --fs check with {} error(s)",
                        cfg_path.display(),
                        fs_errors.len()
                    ));
                    write_reload_json_report(&ReloadJsonReport {
                        reloaded: (!args.dry_run).then_some(false),
                        outcome: if args.dry_run {
                            ReloadOutcome::DryRunRefused
                        } else {
                            ReloadOutcome::Refused
                        },
                        quarantined_source: "preflight",
                        dry_run: args.dry_run,
                        warnings: std::mem::take(&mut warnings),
                        quarantined,
                        restart_required: Vec::new(),
                        errors,
                    });
                }
            }
            return ExitCode::FAILURE;
        }
    }

    if args.dry_run {
        match args.format {
            OutputFormat::Text => {
                let mut stdout = io::stdout().lock();
                let _ = writeln!(stdout, "OK: dry run passed (no signal sent)");
            }
            OutputFormat::Json => {
                write_reload_json_report(&ReloadJsonReport {
                    reloaded: None,
                    outcome: ReloadOutcome::DryRunPassed,
                    quarantined_source: "preflight",
                    dry_run: true,
                    warnings: std::mem::take(&mut warnings),
                    quarantined,
                    restart_required: Vec::new(),
                    errors: Vec::new(),
                });
            }
        }
        return ExitCode::SUCCESS;
    }

    // During a restart the old process has released the PID file and the new one has not taken
    // it yet: for a moment the file is missing, empty or unlocked. That is a server about to
    // start, not a stopped one, so wait briefly before reporting it.
    let pid_deadline = Instant::now() + Duration::from_secs(5);
    let pid = loop {
        match read_validated_pid_file(&args.pid_file) {
            Ok(pid) => break pid,
            Err(msg) if Instant::now() >= pid_deadline => {
                let err_msg = format!("{msg} (waited 5 s for a server to start)");
                match args.format {
                    OutputFormat::Text => {
                        let mut stderr = io::stderr().lock();
                        let _ = writeln!(stderr, "error: {err_msg}");
                    }
                    OutputFormat::Json => {
                        write_reload_json_report(&ReloadJsonReport {
                            reloaded: (!args.dry_run).then_some(false),
                            outcome: if args.dry_run {
                                ReloadOutcome::DryRunRefused
                            } else {
                                ReloadOutcome::Refused
                            },
                            quarantined_source: "preflight",
                            dry_run: args.dry_run,
                            warnings: std::mem::take(&mut warnings),
                            quarantined,
                            restart_required: Vec::new(),
                            errors: vec![err_msg],
                        });
                    }
                }
                return ExitCode::FAILURE;
            }
            Err(_) => std::thread::sleep(Duration::from_millis(25)),
        }
    };

    match send_reload_signal(pid, &args.pid_file, expected_config_sha256.as_deref()) {
        Ok(ack) => {
            match args.format {
                OutputFormat::Text => {
                    let mut stdout = io::stdout().lock();
                    let _ = writeln!(stdout, "{}", ack.message);
                    for site in &ack.offline {
                        let _ = writeln!(
                            stdout,
                            "offline: site[{}] '{}' answers 503: {}",
                            site.index, site.site, site.reason
                        );
                    }
                    if !ack.restart_required.is_empty() {
                        let _ = writeln!(
                            stdout,
                            "restart required: {} changed; the running server keeps the previous \
                             value until MiraServe restarts",
                            ack.restart_required.join(", ")
                        );
                    }
                }
                OutputFormat::Json => {
                    // What the server did when it says so; an older server reports no sites,
                    // and then the preflight prediction is all there is.
                    let (quarantined_source, quarantined) = match ack.offline_source {
                        Some(source) => (source, ack.offline),
                        None if args.config.is_some() => ("preflight", quarantined),
                        None => ("unknown", Vec::new()),
                    };
                    write_reload_json_report(&ReloadJsonReport {
                        reloaded: Some(true),
                        outcome: if ack.running_config {
                            ReloadOutcome::CommittedRunningConfig
                        } else {
                            ReloadOutcome::Committed
                        },
                        quarantined_source,
                        dry_run: false,
                        warnings: std::mem::take(&mut warnings),
                        quarantined,
                        restart_required: ack.restart_required,
                        errors: if ack.running_config {
                            vec![ack.message]
                        } else {
                            Vec::new()
                        },
                    });
                }
            }
            // Committing another file than the one given is not the requested change.
            if ack.running_config {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(failure) => {
            match args.format {
                OutputFormat::Text => {
                    let mut stderr = io::stderr().lock();
                    let _ = writeln!(stderr, "error: {}", failure.message);
                }
                OutputFormat::Json => {
                    write_reload_json_report(&ReloadJsonReport {
                        reloaded: (!failure.unknown).then_some(false),
                        outcome: if failure.unknown {
                            ReloadOutcome::Unknown
                        } else {
                            ReloadOutcome::Refused
                        },
                        quarantined_source: "preflight",
                        dry_run: false,
                        warnings,
                        quarantined,
                        restart_required: Vec::new(),
                        errors: vec![failure.message],
                    });
                }
            }
            ExitCode::FAILURE
        }
    }
}

fn read_validated_pid_file(path: &Path) -> Result<u32, String> {
    let link_meta = fs::symlink_metadata(path)
        .map_err(|err| format!("failed to stat PID file '{}': {err}", path.display()))?;
    if link_meta.file_type().is_symlink() {
        return Err(format!(
            "refusing to follow symlink PID file '{}'",
            path.display()
        ));
    }
    if !link_meta.file_type().is_file() {
        return Err(format!(
            "PID file '{}' is not a regular file",
            path.display()
        ));
    }

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .or_else(|_| File::open(path))
        .map_err(|err| format!("failed to open PID file '{}': {err}", path.display()))?;
    let meta = file
        .metadata()
        .map_err(|err| format!("failed to inspect PID file '{}': {err}", path.display()))?;
    if !meta.is_file() {
        return Err(format!(
            "PID file '{}' is not a regular file",
            path.display()
        ));
    }

    // R3-RUN-1: Verify the OS kernel-backed PID lock is actually HELD by a live `miraserve run`
    // instance! If `try_lock()` succeeds, the PID file is stale (e.g. left behind after SIGKILL)
    // and its PID may have been reused by an unrelated process.
    if file.try_lock().is_ok() {
        let _ = file.unlock();
        return Err(format!(
            "PID file '{}' is not locked by a running MiraServe server (stale PID after crash/SIGKILL); refusing to send SIGHUP",
            path.display()
        ));
    }

    let mut buf = Vec::with_capacity(MAX_PID_FILE_BYTES);
    file.take((MAX_PID_FILE_BYTES + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(|err| format!("failed to read PID file '{}': {err}", path.display()))?;
    if buf.len() > MAX_PID_FILE_BYTES {
        return Err(format!(
            "PID file '{}' exceeds maximum allowed size ({MAX_PID_FILE_BYTES} bytes)",
            path.display()
        ));
    }

    let raw_pid = String::from_utf8(buf)
        .map_err(|_| format!("PID file '{}' is not valid UTF-8", path.display()))?;
    let pid = raw_pid.trim().parse::<u32>().map_err(|_| {
        format!(
            "PID file '{}' does not contain a valid numeric PID",
            path.display()
        )
    })?;

    if !(2..=MAX_SAFE_PID).contains(&pid) {
        return Err(format!(
            "PID {pid} in '{}' is out of safe range (must be 2..={MAX_SAFE_PID})",
            path.display()
        ));
    }

    #[cfg(target_os = "linux")]
    verify_linux_miraserve_process(pid)?;

    Ok(pid)
}

#[cfg(target_os = "linux")]
fn verify_linux_miraserve_process(pid: u32) -> Result<(), String> {
    let comm_path = PathBuf::from(format!("/proc/{pid}/comm"));
    if let Ok(file) = File::open(&comm_path) {
        let mut buf = Vec::with_capacity(64);
        if file.take(64).read_to_end(&mut buf).is_ok()
            && let Ok(comm) = String::from_utf8(buf)
        {
            let name = comm.trim();
            if !name.is_empty() && !name.starts_with("miraserve") {
                return Err(format!(
                    "refusing to signal PID {pid}: process comm is '{name}', expected 'miraserve'"
                ));
            }
        }
    }
    // R3-RUN-1: Also verify `/proc/{pid}/cmdline` is `miraserve run` (never `miraserve keyd`,
    // which has no SIGHUP handler and would terminate on SIGHUP!).
    let cmdline_path = PathBuf::from(format!("/proc/{pid}/cmdline"));
    if let Ok(file) = File::open(&cmdline_path) {
        let mut buf = Vec::with_capacity(512);
        if file.take(512).read_to_end(&mut buf).is_ok() && !buf.is_empty() {
            let args: Vec<&str> = buf
                .split(|&b| b == 0)
                .filter_map(|s| std::str::from_utf8(s).ok())
                .filter(|s| !s.is_empty())
                .collect();
            if args.contains(&"keyd") || !args.contains(&"run") {
                return Err(format!(
                    "refusing to signal PID {pid}: process command line is not 'miraserve run'"
                ));
            }
        }
    }
    Ok(())
}

fn reload_status_path_for(pid_file: &Path) -> PathBuf {
    let mut os = pid_file.as_os_str().to_os_string();
    os.push(".reload");
    PathBuf::from(os)
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReloadStatus {
    /// PID of the server that wrote the status; absent in files written by older servers.
    pid: Option<u32>,
    seq: u64,
    status: String,
    generation: Option<u64>,
    config_sha256: Option<String>,
    error: Option<String>,
    /// `offline=<index>\t<code>\t<host>\t<reason>` lines: sites the committed configuration
    /// serves as a 503.
    offline: Vec<QuarantinedSiteReport>,
    /// `ack=` version: 2 and later report `offline_count` and the offline sites.
    ack: Option<u32>,
    /// How many `offline=` lines the server wrote.
    offline_count: Option<usize>,
    /// `restart_required=` settings: valid but not applied until the process restarts.
    restart_required: Vec<String>,
}

/// The offline-site records of a reload acknowledgement, by layout version.
#[cfg(unix)]
fn parse_offline_records(
    ack: Option<u32>,
    raw_offline: &[&str],
    codes: Vec<(usize, String)>,
) -> Vec<QuarantinedSiteReport> {
    let mut offline = Vec::new();
    // `ack=2`: `<index>\t<code>\t<host>\t<reason>`. Otherwise (no `ack`, or `ack=3`):
    // `<index>\t<host>\t<reason>`, with codes on `offline_code=` lines.
    for &record in raw_offline {
        // Two development builds wrote `ack=2`: one with the code as the second field, one with
        // the three-field record and `offline_code=` lines. A warning code (`W` + 3 digits) in
        // the second field tells them apart.
        let four_fields = ack == Some(2)
            && record.split('\t').nth(1).is_some_and(|field| {
                field.len() == 4
                    && field.starts_with('W')
                    && field.bytes().skip(1).all(|b| b.is_ascii_digit())
            });
        let parsed = if four_fields {
            let mut parts = record.splitn(4, '\t');
            match (parts.next(), parts.next(), parts.next(), parts.next()) {
                (Some(index), Some(code), Some(host), Some(reason)) => index
                    .parse::<usize>()
                    .ok()
                    .map(|index| (index, code, host, reason)),
                _ => None,
            }
        } else {
            let mut parts = record.splitn(3, '\t');
            match (parts.next(), parts.next(), parts.next()) {
                (Some(index), Some(host), Some(reason)) => index
                    .parse::<usize>()
                    .ok()
                    .map(|index| (index, "W026", host, reason)),
                _ => None,
            }
        };
        if let Some((index, code, host, reason)) = parsed {
            offline.push(QuarantinedSiteReport {
                site: host.to_owned(),
                index,
                code: code.to_owned(),
                reason: reason.to_owned(),
            });
        }
    }
    let mut codes: std::collections::HashMap<usize, String> = codes.into_iter().collect();
    for site in &mut offline {
        if let Some(code) = codes.remove(&site.index) {
            site.code = code;
        }
    }
    offline
}

/// Largest reload status file read (sites beyond it are reported as incomplete).
#[cfg(unix)]
const MAX_STATUS_BYTES: u64 = 16 * 1024 * 1024;

/// The status file as it is when two readings in a row agree: the server rewrites it in place,
/// so one reading can hold the beginning of one record and the end of the next.
#[cfg(unix)]
fn read_reload_status(path: &Path) -> Option<ReloadStatus> {
    let first = read_status_bytes(path)?;
    let again = read_status_bytes(path)?;
    (first == again)
        .then(|| parse_reload_status(first))
        .flatten()
}

#[cfg(unix)]
fn read_status_bytes(path: &Path) -> Option<Vec<u8>> {
    let md = fs::symlink_metadata(path).ok()?;
    if md.file_type().is_symlink() || !md.file_type().is_file() {
        return None;
    }
    let file = File::open(path).ok()?;
    let mut buf = Vec::with_capacity(1024);
    file.take(MAX_STATUS_BYTES + 1).read_to_end(&mut buf).ok()?;
    Some(buf)
}

#[cfg(unix)]
#[allow(clippy::too_many_lines)]
fn parse_reload_status(mut buf: Vec<u8>) -> Option<ReloadStatus> {
    // Only complete lines are read; a file cut at the limit still yields its complete records
    // (and is then reported as incomplete).
    let truncated = buf.len() as u64 > MAX_STATUS_BYTES;
    if truncated {
        let end = buf.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
        buf.truncate(end);
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let mut pid = None;
    let mut seq = None;
    let mut status = None;
    let mut generation = None;
    let mut config_sha256 = None;
    let mut error = None;
    let mut ack = None;
    let mut format = None;
    let mut complete = false;
    let mut offline_count = None;
    let mut codes: Vec<(usize, String)> = Vec::new();
    let mut raw_offline: Vec<&str> = Vec::new();
    let mut restart_required: Vec<String> = Vec::new();
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("offline=") {
            // Parsed once the acknowledgement version is known (the layout depends on it).
            raw_offline.push(v);
            continue;
        }
        if let Some(v) = line.strip_prefix("offline_code=") {
            if let Some((index, code)) = v.split_once('\t')
                && let Ok(index) = index.parse::<usize>()
            {
                codes.push((index, code.trim().to_owned()));
            }
            continue;
        }
        if let Some(v) = line.strip_prefix("restart_required=") {
            restart_required.push(v.trim().to_owned());
            continue;
        }
        if let Some(v) = line.strip_prefix("ack=") {
            ack = v.trim().parse::<u32>().ok();
            continue;
        }
        if let Some(v) = line.strip_prefix("format=") {
            format = v.trim().parse::<u32>().ok();
            continue;
        }
        if line == "end=1" {
            complete = true;
            continue;
        }
        if let Some(v) = line.strip_prefix("offline_count=") {
            offline_count = v.trim().parse::<usize>().ok();
            continue;
        }
        if let Some(v) = line.strip_prefix("pid=") {
            pid = v.trim().parse::<u32>().ok();
        } else if let Some(v) = line.strip_prefix("seq=") {
            seq = v.trim().parse::<u64>().ok();
        } else if let Some(v) = line.strip_prefix("status=") {
            status = Some(v.trim().to_owned());
        } else if let Some(v) = line.strip_prefix("generation=") {
            generation = v.trim().parse::<u64>().ok();
        } else if let Some(v) = line.strip_prefix("config_sha256=") {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                config_sha256 = Some(trimmed.to_owned());
            }
        } else if let Some(v) = line.strip_prefix("error=") {
            error = Some(v.trim().to_owned());
        }
    }
    // The server rewrites the file in place: a record of the current format is only used
    // whole (its last line is there). Older servers wrote no such line.
    if format.is_some_and(|format| format >= 2) && !complete {
        return None;
    }
    Some(ReloadStatus {
        pid,
        seq: seq?,
        status: status?,
        generation,
        config_sha256,
        error,
        offline: parse_offline_records(ack, &raw_offline, codes),
        ack,
        restart_required,
        // A cut-off file cannot be complete.
        offline_count: offline_count
            .map(|n: usize| if truncated { n.saturating_add(1) } else { n }),
    })
}

/// Decides whether SIGHUP may be sent to `pid`, and returns the reload sequence number to
/// wait past. `None` means: not yet. The status must be complete, written by `pid` itself, and
/// say that start-up is over ("ready", or the outcome of an earlier reload).
#[cfg(unix)]
fn reload_baseline(status: Option<&ReloadStatus>, pid: u32) -> Option<u64> {
    let status = status?;
    if status.pid != Some(pid) {
        return None;
    }
    matches!(status.status.as_str(), "ready" | "ok" | "err").then_some(status.seq)
}

/// Why no matching acknowledgement arrived.
#[cfg(unix)]
#[derive(Debug)]
enum ReloadWaitError {
    /// No acknowledgement in time: the reload may still complete.
    Timeout(String),
    /// The server committed its own file, whose content differs from `--config`.
    OtherConfigCommitted(Box<ReloadStatus>, String),
    /// The server refused its own file.
    Refused(String),
}

#[cfg(unix)]
impl std::fmt::Display for ReloadWaitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout(msg) | Self::OtherConfigCommitted(_, msg) | Self::Refused(msg) => {
                f.write_str(msg)
            }
        }
    }
}

#[cfg(unix)]
const RUNNING_CONFIG_COMMITTED: &str = "the server reloaded successfully, but from its own configuration file, whose content differs from the file given with --config (superseded or unknown digest). The server always reloads the file it was started with; --config only pre-validates a file. Put the new content at the running path and reload again";

#[cfg(unix)]
fn wait_for_reload_status(
    status_path: &Path,
    pid: u32,
    prev_seq: u64,
    expected_config_sha256: Option<&str>,
    timeout: Duration,
) -> Result<ReloadStatus, ReloadWaitError> {
    let deadline = Instant::now() + timeout;
    let mut mismatched_reload: Option<ReloadStatus> = None;
    loop {
        if let Some(cur) = read_reload_status(status_path)
            && cur.seq > prev_seq
            // Written by the process that was signalled (a server started meanwhile writes
            // its own records to the same file).
            && cur.pid.is_none_or(|writer| writer == pid)
        {
            let digest_matches = match (expected_config_sha256, cur.config_sha256.as_deref()) {
                (Some(exp), Some(got)) => exp == got,
                (Some(_), None) => false,
                (None, _) => true,
            };
            if digest_matches {
                return Ok(cur);
            }
            // If the live server reported an explicit reload ERROR (e.g. its own on-disk config is
            // broken while `reload --config other.kdl` pre-validated another file), surface that
            // error immediately instead of waiting 20s and reporting "superseded"!
            if cur.status != "ok" {
                return Err(ReloadWaitError::Refused(format!(
                    "server reload failed on its own on-disk config (differs from --config): {}",
                    cur.error.unwrap_or(cur.status)
                )));
            }
            if Instant::now() >= deadline {
                return Err(ReloadWaitError::OtherConfigCommitted(
                    Box::new(cur),
                    RUNNING_CONFIG_COMMITTED.to_owned(),
                ));
            }
            mismatched_reload = Some(cur);
            std::thread::sleep(Duration::from_millis(25));
            continue;
        }
        if Instant::now() >= deadline {
            if let Some(cur) = mismatched_reload {
                return Err(ReloadWaitError::OtherConfigCommitted(
                    Box::new(cur),
                    RUNNING_CONFIG_COMMITTED.to_owned(),
                ));
            }
            return Err(ReloadWaitError::Timeout(
                "timed out after 20 s waiting for the server to report the reload; the signal was sent, so the reload may still complete (check server logs and run `miraserve reload` again to confirm)"
                    .to_owned(),
            ));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Whether an acknowledgement carries the server's complete list of offline sites.
#[cfg(unix)]
fn offline_source(status: &ReloadStatus) -> Option<&'static str> {
    match (status.ack, status.offline_count) {
        (Some(version), Some(count)) if version >= 2 => Some(if count == status.offline.len() {
            "server"
        } else {
            "server_incomplete"
        }),
        // A server that lists sites without the acknowledgement version knows only some of the
        // ways a site goes offline.
        _ if !status.offline.is_empty() => Some("server_incomplete"),
        _ => None,
    }
}

#[allow(clippy::too_many_lines)]
fn send_reload_signal(
    pid: u32,
    pid_file: &Path,
    expected_config_sha256: Option<&str>,
) -> Result<ReloadAck, ReloadFailure> {
    #[cfg(unix)]
    {
        let status_path = reload_status_path_for(pid_file);
        // SIGHUP terminates a process that has not installed a handler for it, so the signal
        // is sent only on affirmative evidence that THIS process has: a complete status file,
        // written by the PID about to be signalled, that says it is past start-up. A missing,
        // partial or stale file, or one from another process, means wait; if it stays that
        // way nothing is sent.
        let startup_deadline = Instant::now() + Duration::from_secs(30);
        let before_seq = loop {
            let status = read_reload_status(&status_path);
            if let Some(seq) = reload_baseline(status.as_ref(), pid) {
                break seq;
            }
            // A complete status without a writer PID comes from a server started by an older
            // MiraServe. It will never add the PID, so say what to do instead of waiting.
            if status.as_ref().is_some_and(|s| {
                s.pid.is_none() && matches!(s.status.as_str(), "ready" | "ok" | "err")
            }) {
                return Err(ReloadFailure::refused(format!(
                    "the running server (PID {pid}) was started by an older MiraServe and cannot be reloaded by this version; restart it (for example: systemctl restart miraserve). No signal was sent"
                )));
            }
            if Instant::now() >= startup_deadline {
                return Err(ReloadFailure::refused(format!(
                    "MiraServe PID {pid} has not reported that it is ready to reload (status file '{}'); no signal was sent, try again",
                    status_path.display()
                )));
            }
            std::thread::sleep(Duration::from_millis(25));
        };

        // Use an absolute-path POSIX `kill` binary (never PATH-resolved) to remain `#![forbid(unsafe_code)]`.
        let kill_bin = ["/bin/kill", "/usr/bin/kill"]
            .into_iter()
            .find(|p| Path::new(p).is_file())
            .unwrap_or("/bin/kill");

        match std::process::Command::new(kill_bin)
            .args(["-HUP", &pid.to_string()])
            .status()
        {
            Ok(status) if status.success() => {
                // R4-SBX-1, R5-RUN-1 & R6-RUN-1: Wait up to 20s for the server's SIGHUP handler
                // to report the outcome matching `expected_config_sha256`; NEVER print another
                // reload's `"OK"` if the deadline expires with a mismatched digest!
                match wait_for_reload_status(
                    &status_path,
                    pid,
                    before_seq,
                    expected_config_sha256,
                    Duration::from_secs(20),
                ) {
                    Ok(cur) if cur.status == "ok" => {
                        let gen_note = cur
                            .generation
                            .map(|g| format!(" (generation {g})"))
                            .unwrap_or_default();
                        let offline_source = offline_source(&cur);
                        Ok(ReloadAck {
                            message: format!(
                                "OK: MiraServe PID {pid} reloaded successfully{gen_note}"
                            ),
                            running_config: false,
                            offline: cur.offline,
                            offline_source,
                            restart_required: cur.restart_required,
                        })
                    }
                    Ok(cur) => {
                        let err_msg = cur
                            .error
                            .as_deref()
                            .unwrap_or("unknown reload error (check server logs)");
                        Err(ReloadFailure::refused(format!(
                            "MiraServe PID {pid} reload failed: {err_msg}"
                        )))
                    }
                    Err(ReloadWaitError::Timeout(err_msg)) => Err(ReloadFailure {
                        message: format!("MiraServe PID {pid}: outcome unknown: {err_msg}"),
                        unknown: true,
                    }),
                    Err(ReloadWaitError::OtherConfigCommitted(cur, err_msg)) => {
                        let offline_source = offline_source(&cur);
                        Ok(ReloadAck {
                            message: format!("MiraServe PID {pid}: {err_msg}"),
                            running_config: true,
                            offline: cur.offline,
                            offline_source,
                            restart_required: cur.restart_required,
                        })
                    }
                    Err(ReloadWaitError::Refused(err_msg)) => Err(ReloadFailure::refused(format!(
                        "MiraServe PID {pid}: {err_msg}"
                    ))),
                }
            }
            Ok(status) => Err(ReloadFailure::refused(format!(
                "failed to signal PID {pid} ({kill_bin} exited with {status})"
            ))),
            Err(err) => Err(ReloadFailure::refused(format!(
                "failed to invoke {kill_bin} for PID {pid}: {err}"
            ))),
        }
    }

    #[cfg(not(unix))]
    {
        let _ = (pid_file, expected_config_sha256);
        Err(ReloadFailure::refused(format!(
            "POSIX SIGHUP reload signaling for PID {pid} is only supported on Unix; restart the service on Windows"
        )))
    }
}

/// Inputs that determine startup quarantine, `SandboxPolicy` grants, and CLI log bindings for
/// both `miraserve run` and `miraserve check --writable-set`.
pub(crate) struct StartupPolicyInputs<'a> {
    pub(crate) config_path: Option<&'a Path>,
    pub(crate) acme_dir: Option<&'a Path>,
    pub(crate) log_file: Option<&'a Path>,
    pub(crate) access_log: Option<&'a Path>,
    pub(crate) log_max_bytes: u64,
    pub(crate) keyd_auth_secret_file: Option<&'a Path>,
    pub(crate) no_sandbox: bool,
}

/// Output of the side-effect-free startup quarantine, policy derivation, and CLI log pre-binding
/// pass shared by `miraserve run` and `miraserve check --writable-set`.
pub(crate) struct PreparedStartupPolicy {
    pub(crate) policy: SandboxPolicy,
    pub(crate) prebound: Vec<PreboundLog>,
    pub(crate) log_specs: Vec<CliLogSpec>,
    pub(crate) log_file_paths: Vec<PathBuf>,
    pub(crate) log_rotation_paths: Vec<PathBuf>,
    pub(crate) secret_file_paths: Vec<PathBuf>,
    pub(crate) effective_acme_dir: Option<PathBuf>,
}

/// Executes the exact side-effect-free startup classification and sandbox policy preparation used
/// by `miraserve run`:
/// 1. Isolates inaccessible/escaping tenant roots and runs full docroot/ACME/secret/log overlap
///    checks (quarantining sole tenant offenders and refusing non-tenant violations).
/// 2. Builds the startup [`SandboxPolicy`] via [`miraserve_core::prepare_startup_policy`].
/// 3. Validates and pre-binds `--log-file` and `--access-log` (adding and pinning rotating log
///    directories when `log_max_bytes > 0`) without creating directories or opening log files.
///
/// Shared directly by `miraserve run` and `miraserve check --writable-set` so both commands always
/// derive the exact same policy from the same CLI flags.
pub(crate) fn prepare_runtime_startup_policy(
    config: &mut Config,
    inputs: &StartupPolicyInputs<'_>,
) -> Result<PreparedStartupPolicy, Vec<String>> {
    let effective_acme_dir: Option<PathBuf> =
        inputs.acme_dir.map(Path::to_path_buf).or_else(|| {
            config
                .server
                .tls
                .acme
                .as_ref()
                .map(|_| PathBuf::from(".miraserve-acme"))
        });
    let acme_path_ref = effective_acme_dir.as_deref();
    let secret_file_paths: Vec<PathBuf> = inputs
        .keyd_auth_secret_file
        .map(Path::to_path_buf)
        .into_iter()
        .collect();
    let log_file_paths: Vec<PathBuf> = [inputs.log_file, inputs.access_log]
        .into_iter()
        .flatten()
        .map(Path::to_path_buf)
        .collect();
    let log_rotation_paths: Vec<PathBuf> = if inputs.log_max_bytes > 0 {
        log_file_paths.clone()
    } else {
        Vec::new()
    };

    // R6-SBX-1, R7-SBX-1, R7-SBX-2 & Codex G7: Refuse startup if any HTTP document root resolves
    // via symlink into a forbidden directory or overlaps the effective ACME dir, config dir,
    // TLS private keys, publish stores, or active CLI log files/rotation directories.
    let startup_checks = |cfg: &Config| {
        let mut violations = miraserve_core::find_unsafe_docroots_with_secret_files(
            cfg,
            inputs.config_path,
            acme_path_ref,
            &secret_file_paths,
        );
        violations.extend(miraserve_core::find_docroot_log_overlaps(
            cfg,
            &log_file_paths,
            &log_rotation_paths,
        ));
        violations
    };
    miraserve_core::quarantine_inaccessible_tenant_roots(config);
    let mut docroot_violations = miraserve_core::lexical_log_overlaps(config, &log_file_paths);
    if docroot_violations.is_empty() {
        docroot_violations = miraserve_core::quarantine_unsafe_sites(config, startup_checks);
    }
    if !docroot_violations.is_empty() {
        return Err(docroot_violations);
    }

    let config_path_opt = inputs.config_path;
    let acme_arg_opt = inputs.acme_dir;
    let mut worker_sandbox_policy =
        miraserve_core::prepare_startup_policy(config, &|cfg: &Config| {
            SandboxPolicy::from_config_with_file(cfg, config_path_opt, acme_arg_opt)
        });
    if inputs.no_sandbox {
        worker_sandbox_policy.landlock = false;
    }

    let log_specs: Vec<CliLogSpec> = log_file_paths
        .iter()
        .map(|path| CliLogSpec {
            path: path.clone(),
            rotating: inputs.log_max_bytes > 0,
        })
        .collect();
    let bind_ctx = LogBindContext {
        config,
        config_path: inputs.config_path,
        acme_dir: acme_path_ref,
        secret_files: &secret_file_paths,
    };
    let prebound = prebind_cli_logs(&mut worker_sandbox_policy, &log_specs, &bind_ctx)
        .map_err(|reason| vec![reason])?;

    Ok(PreparedStartupPolicy {
        policy: worker_sandbox_policy,
        prebound,
        log_specs,
        log_file_paths,
        log_rotation_paths,
        secret_file_paths,
        effective_acme_dir,
    })
}

/// Inspection-only counterpart to [`prepare_runtime_startup_policy`] used by
/// `miraserve check --writable-set`: runs the identical startup classification, quarantine,
/// policy derivation, and CLI log pre-binding sequence while failing immediately on any OS
/// resource exhaustion (`EMFILE`, `ENFILE`, `ENOMEM`) during classification or any policy build
/// pass (including before tenant quarantine could discard the failing grant).
#[allow(clippy::too_many_lines)]
pub(crate) fn prepare_runtime_startup_policy_for_inspection(
    config: &mut Config,
    inputs: &StartupPolicyInputs<'_>,
) -> Result<PreparedStartupPolicy, Vec<String>> {
    let effective_acme_dir: Option<PathBuf> =
        inputs.acme_dir.map(Path::to_path_buf).or_else(|| {
            config
                .server
                .tls
                .acme
                .as_ref()
                .map(|_| PathBuf::from(".miraserve-acme"))
        });
    let acme_path_ref = effective_acme_dir.as_deref();
    let secret_file_paths: Vec<PathBuf> = inputs
        .keyd_auth_secret_file
        .map(Path::to_path_buf)
        .into_iter()
        .collect();
    let log_file_paths: Vec<PathBuf> = [inputs.log_file, inputs.access_log]
        .into_iter()
        .flatten()
        .map(Path::to_path_buf)
        .collect();
    let log_rotation_paths: Vec<PathBuf> = if inputs.log_max_bytes > 0 {
        log_file_paths.clone()
    } else {
        Vec::new()
    };

    miraserve_core::quarantine_inaccessible_tenant_roots_for_inspection(config)
        .map_err(|err| vec![err])?;
    miraserve_core::check_docroot_classification_resources(
        config,
        inputs.config_path,
        acme_path_ref,
        &log_file_paths,
        &secret_file_paths,
    )
    .map_err(|err| vec![err.to_string()])?;

    let startup_checks = |cfg: &Config| {
        let mut violations = miraserve_core::find_unsafe_docroots_with_secret_files(
            cfg,
            inputs.config_path,
            acme_path_ref,
            &secret_file_paths,
        );
        violations.extend(miraserve_core::find_docroot_log_overlaps(
            cfg,
            &log_file_paths,
            &log_rotation_paths,
        ));
        violations
    };
    let mut docroot_violations = miraserve_core::lexical_log_overlaps(config, &log_file_paths);
    if docroot_violations.is_empty() {
        docroot_violations = miraserve_core::quarantine_unsafe_sites(config, startup_checks);
    }
    if !docroot_violations.is_empty() {
        return Err(docroot_violations);
    }

    let config_path_opt = inputs.config_path;
    let acme_arg_opt = inputs.acme_dir;
    let resource_err: std::cell::RefCell<Option<String>> = std::cell::RefCell::new(None);
    let mut worker_sandbox_policy =
        miraserve_core::prepare_startup_policy(config, &|cfg: &Config| {
            let policy = SandboxPolicy::from_config_with_file(cfg, config_path_opt, acme_arg_opt);
            if resource_err.borrow().is_none()
                && let Some(first) = policy.resource_failure_grants().into_iter().next()
            {
                *resource_err.borrow_mut() = Some(first);
            }
            policy
        });
    if let Some(err) = resource_err.into_inner() {
        return Err(vec![format!(
            "sandbox policy inspection hit OS resource limit: {err}"
        )]);
    }
    if inputs.no_sandbox {
        worker_sandbox_policy.landlock = false;
    }

    let log_specs: Vec<CliLogSpec> = log_file_paths
        .iter()
        .map(|path| CliLogSpec {
            path: path.clone(),
            rotating: inputs.log_max_bytes > 0,
        })
        .collect();
    let bind_ctx = LogBindContext {
        config,
        config_path: inputs.config_path,
        acme_dir: acme_path_ref,
        secret_files: &secret_file_paths,
    };
    let prebound = prebind_cli_logs(&mut worker_sandbox_policy, &log_specs, &bind_ctx)
        .map_err(|reason| vec![reason])?;

    Ok(PreparedStartupPolicy {
        policy: worker_sandbox_policy,
        prebound,
        log_specs,
        log_file_paths,
        log_rotation_paths,
        secret_file_paths,
        effective_acme_dir,
    })
}

/// One configured CLI log destination (`--log-file` / `--access-log`).
pub(crate) struct CliLogSpec {
    path: PathBuf,
    rotating: bool,
}

/// Inputs shared by every log destination check.
struct LogBindContext<'a> {
    config: &'a Config,
    config_path: Option<&'a Path>,
    acme_dir: Option<&'a Path>,
    secret_files: &'a [PathBuf],
}

/// Result of the pre-creation validation pass for one configured log.
pub(crate) struct PreboundLog {
    validated: LogDirBinding,
    pinned: Option<PinnedLogDir>,
}

fn bind_cli_log(
    policy: &mut SandboxPolicy,
    spec: &CliLogSpec,
    ctx: &LogBindContext<'_>,
) -> Result<LogDirBinding, String> {
    if spec.rotating {
        policy.bind_log_rotation_dir(
            &spec.path,
            ctx.config,
            ctx.config_path,
            ctx.acme_dir,
            ctx.secret_files,
        )
    } else {
        bind_log_file_dir(&spec.path, ctx.config)
    }
}

/// Validates every configured log destination BEFORE any directory is created or file opened,
/// pinning each destination directory that already exists (Codex Round-5 P1 #1).
fn prebind_cli_logs(
    policy: &mut SandboxPolicy,
    specs: &[CliLogSpec],
    ctx: &LogBindContext<'_>,
) -> Result<Vec<PreboundLog>, String> {
    specs
        .iter()
        .map(|spec| {
            if let Some(reason) = log_path_platform_rejection(&spec.path) {
                return Err(reason);
            }
            let validated = bind_cli_log(policy, spec, ctx)?;
            let pinned = validated
                .pinned
                .clone()
                .map(|dir| PinnedLogDir::new(&spec.path, dir, spec.rotating))
                .transpose()?;
            Ok(PreboundLog { validated, pinned })
        })
        .collect()
}

/// Produces the final configured-log -> validated-handle association used by the writer and by
/// every reload. A destination pinned during [`prebind_cli_logs`] keeps that handle and must
/// still be what its configured path resolves to; a destination created since must re-validate
/// to the SAME canonical directory. Any change fails before a log file is created or opened.
fn finalize_cli_logs(
    policy: &mut SandboxPolicy,
    specs: &[CliLogSpec],
    prebound: Vec<PreboundLog>,
    ctx: &LogBindContext<'_>,
) -> Result<Vec<PinnedLogDir>, String> {
    let mut bound = Vec::with_capacity(specs.len());
    for (spec, pre) in specs.iter().zip(prebound) {
        let pinned_log = if let Some(existing) = pre.pinned {
            existing
        } else {
            let rebound = bind_cli_log(policy, spec, ctx)?;
            let dir = rebound.pinned.ok_or_else(|| {
                format!(
                    "log directory '{}' for '{}' does not exist",
                    rebound.real_parent.display(),
                    spec.path.display()
                )
            })?;
            if dir.path != pre.validated.real_parent {
                return Err(format!(
                    "log path '{}' changed destination during startup (validated '{}', now '{}')",
                    spec.path.display(),
                    pre.validated.real_parent.display(),
                    dir.path.display()
                ));
            }
            PinnedLogDir::new(&spec.path, dir, spec.rotating)?
        };
        pinned_log.verify_configured_destination()?;
        bound.push(pinned_log);
    }
    policy
        .verify_pinned_writable_dirs()
        .map_err(|err| format!("pinned writable directory changed identity: {err}"))?;
    Ok(bound)
}

struct RotatingLogInner {
    dir: PinnedWritableDir,
    file_name: OsString,
    path: PathBuf,
    file: File,
    written: u64,
    max_bytes: u64,
    keep: u32,
    rotation_error_reported: bool,
    /// Set when a previous rotation moved `self.file_name` away and both reopening and rolling it
    /// back failed; subsequent retries recreate `self.file_name` directly without double-shifting.
    active_file_detached: bool,
    /// `Some` for the access log: lines are collected here and written in batches (see
    /// [`ACCESS_LOG_FLUSH_BYTES`] and [`flush_access_log`]) instead of one `write` per request.
    buffer: Option<Vec<u8>>,
    /// Access-log lines dropped because the file could not be written (see
    /// [`MAX_UNWRITTEN_ACCESS_LOG_BYTES`]), not yet reported.
    dropped_lines: u64,
    /// When a failed write was last reported on stderr.
    last_failure_report: Option<std::time::Instant>,
    /// Bytes at the front of the buffer that finish a line already partly written to the
    /// current file. They go to that same file, before anything else, without rotation, and
    /// are never dropped.
    partial_tail: usize,
    /// While the file cannot be written: no new attempt before this time (see
    /// [`RotatingLogInner::flush_buffer`]).
    retry_at: Option<std::time::Instant>,
    /// Wait before the next attempt after another failure (doubles up to 5 s).
    retry_delay: Duration,
}

/// First wait after a failed access-log write; it doubles with each further failure.
const LOG_RETRY_INITIAL: Duration = Duration::from_millis(100);

/// Longest wait between two attempts to write a failing access log.
const LOG_RETRY_MAX: Duration = Duration::from_secs(5);

/// What the access log keeps in memory while its file cannot be written (a full disk, a
/// quota). Beyond this the oldest lines are dropped and counted.
const MAX_UNWRITTEN_ACCESS_LOG_BYTES: usize = 1024 * 1024;

/// A failing log file is reported on stderr at most this often.
const LOG_FAILURE_REPORT_INTERVAL: Duration = Duration::from_secs(60);

/// The access log's buffer is written out when it reaches this size...
const ACCESS_LOG_FLUSH_BYTES: usize = 64 * 1024;

/// ...and at this interval by a task on the runtime, so a quiet server's last lines are on
/// disk within a moment. Lines newer than this can be lost if the process is killed outright
/// (`SIGKILL`, power loss); a normal stop flushes them.
const ACCESS_LOG_FLUSH_INTERVAL: Duration = Duration::from_millis(100);

/// The access log writer, for [`flush_access_log`].
static ACCESS_LOG_WRITER: std::sync::OnceLock<std::sync::Arc<std::sync::Mutex<RotatingLogInner>>> =
    std::sync::OnceLock::new();

/// Writes out whatever the access log has buffered, unless the file is failing and the next
/// attempt is not due yet. Called by the timer.
pub(crate) fn flush_access_log() {
    if let Some(writer) = ACCESS_LOG_WRITER.get()
        && let Ok(mut inner) = writer.lock()
    {
        let _ = inner.flush_buffer(false);
    }
}

/// The last write of the access log before the process exits: one attempt whatever the retry
/// schedule says. Returns `false`, after saying on stderr exactly what is lost, when buffered
/// lines could not be written; the caller then exits with a failure status.
pub(crate) fn final_access_log_flush() -> bool {
    let Some(writer) = ACCESS_LOG_WRITER.get() else {
        return true;
    };
    let Ok(mut inner) = writer.lock() else {
        let _ = writeln!(
            io::stderr(),
            "miraserve: access log writer is unusable at exit; buffered lines are lost"
        );
        return false;
    };
    let (bytes, lines) = inner.flush_buffer(true);
    if bytes == 0 {
        return true;
    }
    let _ = writeln!(
        io::stderr(),
        "miraserve: stopping with {bytes} bytes ({lines} line(s), the first possibly incomplete) of the access log '{}' not written; they are lost ({} older line(s) were dropped during the outage)",
        inner.path.display(),
        inner.dropped_lines
    );
    false
}

/// The last byte of an open log file, `None` when it is empty. Reads through the handle the
/// server appends to, so a rename of the file in between cannot select another file. Fails on a
/// handle opened write-only.
fn last_byte_of(file: &File) -> io::Result<Option<u8>> {
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(None);
    }
    let mut byte = [0_u8; 1];
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt as _;
        file.read_exact_at(&mut byte, len - 1)?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt as _;
        if file.seek_read(&mut byte, len - 1)? != 1 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        return Err(io::Error::from(io::ErrorKind::Unsupported));
    }
    Ok(Some(byte[0]))
}

/// Number of complete lines in `bytes` (a final line without a newline counts too).
fn count_lines(bytes: &[u8]) -> usize {
    let newlines = bytes.split(|&b| b == b'\n').count().saturating_sub(1);
    if bytes.last().is_some_and(|&b| b != b'\n') {
        newlines.saturating_add(1)
    } else {
        newlines
    }
}

impl RotatingLogInner {
    /// Rotates if needed, then writes `bytes` to the file. Rotation failures are reported once
    /// on stderr (never through `tracing`, which may be the caller) and the bytes are still
    /// written to the current file. On a write error, returns how many bytes were written.
    fn write_through(&mut self, bytes: &[u8]) -> Result<(), (usize, io::Error)> {
        self.rotate_reporting_errors(bytes.len() as u64);
        self.write_raw(bytes)
    }

    fn rotate_reporting_errors(&mut self, incoming: u64) {
        match self.rotate_if_needed(incoming) {
            Ok(true) => self.rotation_error_reported = false,
            Ok(false) => {}
            Err(err) => {
                if !self.rotation_error_reported {
                    self.rotation_error_reported = true;
                    let _ = writeln!(
                        io::stderr(),
                        "miraserve: log rotation failed for '{}': {err} (check directory permissions and sandbox policy)",
                        self.path.display()
                    );
                }
            }
        }
    }

    /// Writes `bytes` to the current file without rotating. On an error, returns how many bytes
    /// were written.
    fn write_raw(&mut self, bytes: &[u8]) -> Result<(), (usize, io::Error)> {
        let mut done = 0_usize;
        while let Some(rest) = bytes.get(done..).filter(|r| !r.is_empty()) {
            match self.file.write(rest) {
                Ok(0) => {
                    return Err((
                        done,
                        io::Error::new(io::ErrorKind::WriteZero, "log file accepted no bytes"),
                    ));
                }
                Ok(n) => {
                    done = done.saturating_add(n);
                    self.written = self.written.saturating_add(n as u64);
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => return Err((done, err)),
            }
        }
        Ok(())
    }

    /// A previous run can have stopped in the middle of a line (the file system was full at
    /// exit). The first new line would then be glued to it, so the old line is terminated
    /// first. A file that ends with a newline, or is empty, is left as it is.
    fn finish_unterminated_line(&mut self) {
        let needs_separator = match last_byte_of(&self.file) {
            Ok(last) => last.is_some_and(|b| b != b'\n'),
            // The file cannot be read (a write-only log): when it is not empty, assume the worst
            // and start on a new line. A complete log then gets one blank line.
            Err(_) => self.file.metadata().is_ok_and(|m| m.len() > 0),
        };
        if !needs_separator {
            return;
        }
        if let Some(pending) = self.buffer.as_mut() {
            pending.insert(0, b'\n');
            self.partial_tail = self.partial_tail.saturating_add(1);
        } else {
            let _ = self.write_raw(b"\n");
        }
    }

    /// Writes the buffered access-log lines; returns the bytes and lines still buffered.
    ///
    /// Lines are written in groups that fit the current file, so rotation happens between
    /// complete lines and the file stays within `max_bytes` (a single line longer than that is
    /// written alone into a fresh file). If a write stops inside a line, the rest of that line
    /// is written first next time, to the same file and without rotation, so no line is split
    /// across files or joined to another.
    ///
    /// While the file cannot be written, attempts are spaced out (100 ms doubling to 5 s) unless
    /// `force` is set, so requests never pay for retries; the unwritten lines are kept up to
    /// [`MAX_UNWRITTEN_ACCESS_LOG_BYTES`], older whole lines beyond that are dropped and counted,
    /// and the failure is reported on stderr.
    fn flush_buffer(&mut self, force: bool) -> (usize, usize) {
        let Some(mut pending) = self.buffer.take() else {
            return (0, 0);
        };
        let due = force
            || self
                .retry_at
                .is_none_or(|at| std::time::Instant::now() >= at);
        if pending.is_empty() || !due {
            let left = (pending.len(), count_lines(&pending));
            self.buffer = Some(pending);
            return left;
        }
        let mut start = 0_usize;
        let mut failure = None;
        if self.partial_tail > 0 {
            let tail_end = self.partial_tail.min(pending.len());
            match self.write_raw(pending.get(..tail_end).unwrap_or(&[])) {
                Ok(()) => {
                    start = tail_end;
                    self.partial_tail = 0;
                }
                Err((done, err)) => {
                    start = done;
                    self.partial_tail = self.partial_tail.saturating_sub(done);
                    failure = Some(err);
                }
            }
        }
        while failure.is_none() && start < pending.len() {
            let chunk_end = self.next_chunk_end(&pending, start);
            match self.write_through(pending.get(start..chunk_end).unwrap_or(&[])) {
                Ok(()) => start = chunk_end,
                Err((done, err)) => {
                    let stop = start.saturating_add(done);
                    if done > 0 && pending.get(stop.saturating_sub(1)) != Some(&b'\n') {
                        let line_end = pending
                            .get(stop..)
                            .and_then(|rest| rest.iter().position(|&b| b == b'\n'))
                            .map_or(pending.len(), |i| stop.saturating_add(i).saturating_add(1));
                        self.partial_tail = line_end.saturating_sub(stop);
                    }
                    start = stop;
                    failure = Some(err);
                }
            }
        }
        pending.drain(..start.min(pending.len()));
        if let Some(err) = failure {
            self.drop_oldest_lines(&mut pending);
            self.retry_at = Some(std::time::Instant::now() + self.retry_delay);
            self.retry_delay = self.retry_delay.saturating_mul(2).min(LOG_RETRY_MAX);
            self.report_failure(&err, pending.len());
        } else {
            self.retry_at = None;
            self.retry_delay = LOG_RETRY_INITIAL;
            self.report_recovery();
        }
        let left = (pending.len(), count_lines(&pending));
        self.buffer = Some(pending);
        left
    }

    /// End of the next group of complete lines from `start` that fits the current file.
    fn next_chunk_end(&self, pending: &[u8], start: usize) -> usize {
        if self.max_bytes == 0 {
            // No rotation: everything goes in one write, no scan needed.
            return pending.len();
        }
        let room = self.max_bytes.saturating_sub(self.written);
        let mut end = start;
        let mut pos = start;
        while pos < pending.len() {
            let line_end = pending
                .get(pos..)
                .and_then(|rest| rest.iter().position(|&b| b == b'\n'))
                .map_or(pending.len(), |i| pos.saturating_add(i).saturating_add(1));
            let size = u64::try_from(line_end.saturating_sub(start)).unwrap_or(u64::MAX);
            if size > room && end > start {
                break;
            }
            end = line_end;
            pos = line_end;
            if size > room {
                // One line that does not fit even an empty file: it goes alone.
                break;
            }
        }
        end
    }

    /// Keeps the buffer within [`MAX_UNWRITTEN_ACCESS_LOG_BYTES`] by dropping the oldest whole
    /// lines that have not been started. When it acts it brings the buffer down to three
    /// quarters of the limit, so a long outage does not shift the buffer on every new line.
    fn drop_oldest_lines(&mut self, pending: &mut Vec<u8>) {
        if pending.len() <= MAX_UNWRITTEN_ACCESS_LOG_BYTES {
            return;
        }
        let keep = MAX_UNWRITTEN_ACCESS_LOG_BYTES / 4 * 3;
        let from = self.partial_tail.min(pending.len());
        let excess = pending.len().saturating_sub(keep);
        let search_from = from.saturating_add(excess);
        let cut = pending
            .get(search_from..)
            .and_then(|rest| rest.iter().position(|&b| b == b'\n'))
            .map_or(pending.len(), |i| {
                search_from.saturating_add(i).saturating_add(1)
            });
        if cut <= from {
            return;
        }
        let dropped = pending.get(from..cut).map_or(0, count_lines);
        self.dropped_lines = self
            .dropped_lines
            .saturating_add(u64::try_from(dropped).unwrap_or(u64::MAX));
        pending.drain(from..cut);
    }

    fn report_failure(&mut self, err: &io::Error, kept: usize) {
        let due = self
            .last_failure_report
            .is_none_or(|at| at.elapsed() >= LOG_FAILURE_REPORT_INTERVAL);
        if due {
            self.last_failure_report = Some(std::time::Instant::now());
            let _ = writeln!(
                io::stderr(),
                "miraserve: cannot write access log '{}': {err}; {kept} bytes kept for retry, {} line(s) dropped so far",
                self.path.display(),
                self.dropped_lines
            );
        }
    }

    fn report_recovery(&mut self) {
        if self.last_failure_report.take().is_some() {
            let _ = writeln!(
                io::stderr(),
                "miraserve: access log '{}' is writable again; {} line(s) were dropped while it was not",
                self.path.display(),
                self.dropped_lines
            );
            self.dropped_lines = 0;
        }
    }

    /// Opens a log file directly relative to its validated [`PinnedLogDir`] handle (no-follow
    /// leaf, regular-file check on the opened handle — Codex Round-4 P1 #2).
    fn open_pinned(target: PinnedLogDir, max_bytes: u64, keep: u32) -> io::Result<Self> {
        let file = target.dir.open_append_regular(&target.file_name)?;
        let written = file.metadata().map_or(0, |m| m.len());
        Ok(Self {
            dir: target.dir,
            file_name: target.file_name,
            path: target.configured_path,
            file,
            written,
            max_bytes,
            keep: keep.max(1),
            rotation_error_reported: false,
            active_file_detached: false,
            buffer: None,
            dropped_lines: 0,
            last_failure_report: None,
            partial_tail: 0,
            retry_at: None,
            retry_delay: LOG_RETRY_INITIAL,
        })
    }

    #[cfg(test)]
    fn open(path: &Path, max_bytes: u64, keep: u32) -> io::Result<Self> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "log path has no parent"))?;
        let canon_parent = fs::canonicalize(parent)?;
        let dir = PinnedWritableDir::open_validated(&canon_parent)
            .map_err(|err| io::Error::new(io::ErrorKind::PermissionDenied, err.to_string()))?;
        let target = PinnedLogDir::new(path, dir, max_bytes > 0)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        Self::open_pinned(target, max_bytes, keep)
    }

    /// Rotates the active log file relative to the pinned directory handle once
    /// `written + incoming > max_bytes`, propagating any symlink refusal, rename failure, or
    /// reopen failure so rotation errors are never silently discarded (Codex G7 & Round-4 P1 #2).
    fn rotate_if_needed(&mut self, incoming: u64) -> io::Result<bool> {
        self.rotate_with_opener(incoming, |dir, file_name| {
            dir.open_append_regular(file_name)
        })
    }

    fn rotate_with_opener<F>(&mut self, incoming: u64, open_fresh: F) -> io::Result<bool>
    where
        F: FnOnce(&PinnedWritableDir, &OsStr) -> io::Result<File>,
    {
        if self.max_bytes == 0 {
            return Ok(false);
        }
        if self.active_file_detached {
            // Codex G7: Previous rotation detached `self.file_name`; recover cleanly by reopening
            // relative to `self.dir` without shifting backups `.1 -> .2` again.
            if self.dir.is_symlink_entry(&self.file_name)? {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "refusing to recover log to symbolic link '{}'",
                        self.path.display()
                    ),
                ));
            }
            let _ = self.file.flush();
            let fresh = open_fresh(&self.dir, &self.file_name)?;
            self.file = fresh;
            self.written = 0;
            self.active_file_detached = false;
            return Ok(true);
        }
        // An empty file is never rotated away: that would only leave an empty backup.
        if self.written == 0 || self.written.saturating_add(incoming) <= self.max_bytes {
            return Ok(false);
        }
        let _ = self.file.flush();
        if self.dir.is_symlink_entry(&self.file_name)? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("refusing to rotate symbolic link '{}'", self.path.display()),
            ));
        }
        for idx in (1..self.keep).rev() {
            let src = rotated_file_name(&self.file_name, idx);
            let dst = rotated_file_name(&self.file_name, idx + 1);
            if self.dir.is_symlink_entry(&src)? || self.dir.is_symlink_entry(&dst)? {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "refusing to rotate through symbolic link backup '{}' -> '{}'",
                        src.to_string_lossy(),
                        dst.to_string_lossy()
                    ),
                ));
            }
            if self.dir.entry_exists(&src)? {
                self.dir.rename_entry(&src, &dst)?;
            }
        }
        let first_backup = rotated_file_name(&self.file_name, 1);
        if self.dir.is_symlink_entry(&first_backup)? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to overwrite symbolic link backup '{}'",
                    first_backup.to_string_lossy()
                ),
            ));
        }
        self.dir.rename_entry(&self.file_name, &first_backup)?;
        match open_fresh(&self.dir, &self.file_name) {
            Ok(fresh) => {
                self.file = fresh;
                self.written = 0;
                self.active_file_detached = false;
                Ok(true)
            }
            Err(err) => {
                // Codex G7: Restore `first_backup -> self.file_name` inside the pinned directory
                // so the active name stays recoverable; if rollback fails, mark detached so the
                // next retry reopens directly without shifting backups again.
                if self
                    .dir
                    .rename_entry(&first_backup, &self.file_name)
                    .is_err()
                {
                    self.active_file_detached = true;
                }
                Err(err)
            }
        }
    }
}

fn rotated_file_name(base: &OsStr, idx: u32) -> OsString {
    let mut os = base.to_os_string();
    os.push(format!(".{idx}"));
    os
}

#[cfg(test)]
fn rotated_log_path(base: &Path, idx: u32) -> PathBuf {
    let mut os = base.as_os_str().to_os_string();
    os.push(format!(".{idx}"));
    PathBuf::from(os)
}

#[derive(Clone)]
struct RotatingMakeWriter {
    inner: std::sync::Arc<std::sync::Mutex<RotatingLogInner>>,
}

struct RotatingWriterGuard<'a> {
    inner: &'a std::sync::Mutex<RotatingLogInner>,
}

impl io::Write for RotatingWriterGuard<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let Ok(mut guard) = self.inner.lock() else {
            return Err(io::Error::other("log writer lock poisoned"));
        };
        if let Some(mut pending) = guard.buffer.take() {
            pending.extend_from_slice(buf);
            // Bounded and cheap while the file is failing: trim, and leave retries to the timer.
            guard.drop_oldest_lines(&mut pending);
            let size_due = pending.len() >= ACCESS_LOG_FLUSH_BYTES && guard.retry_at.is_none();
            guard.buffer = Some(pending);
            if size_due {
                let _ = guard.flush_buffer(false);
            }
            return Ok(buf.len());
        }
        guard.write_through(buf).map_err(|(_, err)| err)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let Ok(mut guard) = self.inner.lock() else {
            return Err(io::Error::other("log writer lock poisoned"));
        };
        // A buffered log is flushed by size and by the runtime's timer, not per event: the
        // formatter calls `flush` after every line.
        if guard.buffer.is_some() {
            return Ok(());
        }
        guard.file.flush()
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for RotatingMakeWriter {
    type Writer = RotatingWriterGuard<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        RotatingWriterGuard { inner: &self.inner }
    }
}

/// Wraps any runtime tracing [`tracing_subscriber::fmt::MakeWriter`] (`--log-file` rotating
/// writer, `stderr`, or `stdout`) so events emitted inside a non-blocking context (in-task
/// HTTP/2 stream poll/drop or dedicated worker event loops, where
/// [`miraserve_core::inline_work_must_not_block`] is `true`) are buffered per event and enqueued
/// onto the bounded off-thread diagnostic queue instead of locking or writing through on the
/// connection/worker thread. Outside non-blocking contexts (default spawned mode, HTTP/1.1,
/// startup, shutdown, panics) it delegates directly and synchronously to `W` exactly as in v0.1.4.
#[derive(Clone)]
struct NonBlockingRuntimeMakeWriter<W> {
    inner: Arc<W>,
    sink: miraserve_core::DiagnosticLogSink,
}

impl<W> NonBlockingRuntimeMakeWriter<W>
where
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
{
    fn new(inner: W) -> Self {
        let inner = Arc::new(inner);
        let sink_inner = Arc::clone(&inner);
        let sink: miraserve_core::DiagnosticLogSink = Arc::new(move |bytes: &[u8]| {
            let mut w = sink_inner.make_writer();
            let _ = io::Write::write_all(&mut w, bytes);
            let _ = io::Write::flush(&mut w);
        });
        Self { inner, sink }
    }
}

enum NonBlockingRuntimeWriter<W> {
    Sync(W),
    Offload {
        buf: Vec<u8>,
        sink: miraserve_core::DiagnosticLogSink,
    },
}

impl<W: io::Write> io::Write for NonBlockingRuntimeWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        match self {
            Self::Sync(w) => w.write(data),
            Self::Offload { buf, .. } => {
                buf.extend_from_slice(data);
                Ok(data.len())
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Sync(w) => w.flush(),
            Self::Offload { .. } => Ok(()),
        }
    }
}

impl<W> Drop for NonBlockingRuntimeWriter<W> {
    fn drop(&mut self) {
        if let Self::Offload { buf, sink } = self
            && !buf.is_empty()
        {
            miraserve_core::enqueue_offloaded_diagnostic_log(std::mem::take(buf), Arc::clone(sink));
        }
    }
}

impl<'a, W> tracing_subscriber::fmt::MakeWriter<'a> for NonBlockingRuntimeMakeWriter<W>
where
    W: for<'b> tracing_subscriber::fmt::MakeWriter<'b> + Send + Sync + 'static,
{
    type Writer = NonBlockingRuntimeWriter<<W as tracing_subscriber::fmt::MakeWriter<'a>>::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        if miraserve_core::inline_work_must_not_block() {
            NonBlockingRuntimeWriter::Offload {
                buf: Vec::with_capacity(256),
                sink: Arc::clone(&self.sink),
            }
        } else {
            NonBlockingRuntimeWriter::Sync(self.inner.make_writer())
        }
    }

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        if miraserve_core::inline_work_must_not_block() {
            NonBlockingRuntimeWriter::Offload {
                buf: Vec::with_capacity(256),
                sink: Arc::clone(&self.sink),
            }
        } else {
            NonBlockingRuntimeWriter::Sync(self.inner.make_writer_for(meta))
        }
    }
}

fn init_tracing(
    default_level: &str,
    log_file: Option<PinnedLogDir>,
    access_log: Option<PinnedLogDir>,
    log_max_bytes: u64,
    log_keep: u32,
) -> io::Result<()> {
    use std::io::IsTerminal as _;
    use tracing_subscriber::Layer as _;
    use tracing_subscriber::filter::filter_fn;
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
    let use_ansi = io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none();

    if let Some(access_target) = access_log {
        let mut access_inner =
            RotatingLogInner::open_pinned(access_target, log_max_bytes, log_keep)?;
        access_inner.buffer = Some(Vec::with_capacity(ACCESS_LOG_FLUSH_BYTES));
        access_inner.finish_unterminated_line();
        let access_writer = RotatingMakeWriter {
            inner: std::sync::Arc::new(std::sync::Mutex::new(access_inner)),
        };
        let _ = ACCESS_LOG_WRITER.set(std::sync::Arc::clone(&access_writer.inner));
        // Access lines are formatted by the HTTP engine itself (same text) and appended here,
        // bypassing the general log formatter.
        let sink_target = std::sync::Arc::clone(&access_writer.inner);
        let _ = miraserve_core::set_access_log_sink(Box::new(move |line: &[u8]| {
            let mut guard = RotatingWriterGuard {
                inner: &sink_target,
            };
            let _ = io::Write::write_all(&mut guard, line);
        }));

        if let Some(runtime_target) = log_file {
            let runtime_writer =
                NonBlockingRuntimeMakeWriter::new(RotatingMakeWriter {
                    inner: std::sync::Arc::new(std::sync::Mutex::new(
                        RotatingLogInner::open_pinned(runtime_target, log_max_bytes, log_keep)?,
                    )),
                });
            let runtime_layer = tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_ansi(false)
                .with_writer(runtime_writer)
                .with_filter(filter_fn(|meta| meta.target() != "miraserve::access"));
            let access_layer = tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_ansi(false)
                .with_writer(access_writer)
                .with_filter(filter_fn(|meta| meta.target() == "miraserve::access"));
            let _ = tracing_subscriber::registry()
                .with(filter)
                .with(runtime_layer)
                .with(access_layer)
                .try_init();
        } else {
            let runtime_layer = tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_ansi(use_ansi)
                .with_writer(NonBlockingRuntimeMakeWriter::new(io::stderr))
                .with_filter(filter_fn(|meta| meta.target() != "miraserve::access"));
            let access_layer = tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_ansi(false)
                .with_writer(access_writer)
                .with_filter(filter_fn(|meta| meta.target() == "miraserve::access"));
            let _ = tracing_subscriber::registry()
                .with(filter)
                .with(runtime_layer)
                .with(access_layer)
                .try_init();
        }
    } else if let Some(runtime_target) = log_file {
        let writer = NonBlockingRuntimeMakeWriter::new(RotatingMakeWriter {
            inner: std::sync::Arc::new(std::sync::Mutex::new(RotatingLogInner::open_pinned(
                runtime_target,
                log_max_bytes,
                log_keep,
            )?)),
        });
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_ansi(false)
            .with_writer(writer)
            .try_init();
    } else {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_ansi(use_ansi)
            .with_writer(NonBlockingRuntimeMakeWriter::new(io::stdout))
            .try_init();
    }
    Ok(())
}

struct PidFileGuard {
    /// OS kernel-backed exclusive lock held on the open file descriptor for the entire server
    /// lifetime (`R2-RUN-1`, `R3-RUN-1`). Never unlinked on shutdown (truncated to 0 bytes while
    /// locked, then unlocked), eliminating unlink/inode lock races and avoiding Landlock RW grants
    /// on the PID parent directory (`R3-SBX-3`).
    lock_file: File,
    /// Pre-opened companion `<pid-file>.reload` handle (`R4-SBX-1`) so SIGHUP reload results can
    /// be written without needing directory write access under Landlock.
    reload_status: File,
}

impl PidFileGuard {
    fn create(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        if let Ok(md) = fs::symlink_metadata(path) {
            if md.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "refusing to open symlink PID file",
                ));
            }
            if !md.file_type().is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "refusing to open non-regular PID file",
                ));
            }
        }

        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o644);
        }

        let mut lock_file = opts.open(path)?;
        match lock_file.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "PID file '{}' is already locked by another running MiraServe instance",
                        path.display()
                    ),
                ));
            }
            Err(fs::TryLockError::Error(err)) => return Err(err),
        }

        // The status file is initialised BEFORE the PID is published: once `miraserve reload`
        // can read this process's PID, it must also find this process's "starting" status,
        // never a missing file or the status a previous process left behind.
        let pid = std::process::id();
        let status_path = reload_status_path_for(path);
        if let Ok(md) = fs::symlink_metadata(&status_path)
            && (md.file_type().is_symlink() || !md.file_type().is_file())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing to open symlink or non-regular reload status file",
            ));
        }
        let mut status_opts = OpenOptions::new();
        status_opts
            .read(true)
            .write(true)
            .create(true)
            .truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            status_opts.mode(0o644);
        }
        let mut reload_status = status_opts.open(&status_path)?;
        reload_status.set_len(0)?;
        reload_status.seek(SeekFrom::Start(0))?;
        // "starting" until the server has installed its signal handlers and writes "ready":
        // `miraserve reload` must not send SIGHUP before that, the default action of SIGHUP
        // is to terminate the process.
        writeln!(reload_status, "pid={pid}\nseq=0\nstatus=starting")?;
        reload_status.sync_data()?;

        lock_file.set_len(0)?;
        lock_file.seek(SeekFrom::Start(0))?;
        writeln!(lock_file, "{pid}")?;
        lock_file.sync_all()?;

        Ok(Self {
            lock_file,
            reload_status,
        })
    }

    fn clone_reload_status_file(&self) -> io::Result<Arc<Mutex<File>>> {
        Ok(Arc::new(Mutex::new(self.reload_status.try_clone()?)))
    }
}

impl Drop for PidFileGuard {
    fn drop(&mut self) {
        // R3-RUN-1 & R3-SBX-3: Truncate the already-open locked FD instead of unlinking by path.
        // Works cleanly under strict Landlock without granting RW on `/run/miraserve` and
        // eliminates the unlink-before-unlock inode race.
        let _ = self.reload_status.set_len(0);
        let _ = self.reload_status.sync_data();
        let _ = self.lock_file.set_len(0);
        let _ = self.lock_file.sync_all();
        let _ = self.lock_file.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The PID the reload was sent to in these tests.
    #[cfg(unix)]
    const TEST_PID: u32 = 4242;

    /// A status record being rewritten is not read as a result; one from another process is
    /// not this reload's (Cloudflare-skills audit of v0.1.0, claim 16).
    #[cfg(unix)]
    #[test]
    fn a_partial_or_foreign_status_record_is_not_an_acknowledgement()
    -> Result<(), Box<dyn std::error::Error>> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "miraserve-status-{}-{nanos}.reload-status",
            std::process::id()
        ));
        let whole = format!(
            "format=2\npid={TEST_PID}\nseq=2\nstatus=ok\ngeneration=2\nconfig_sha256=aa\nack=3\noffline_count=1\noffline=0\ta.test\tgone\noffline_code=0\tW026\nend=1\n"
        );
        // Every beginning of the record (what a reader sees while it is written) is no record.
        for cut in 0..whole.len() - 1 {
            if !whole.is_char_boundary(cut) {
                continue;
            }
            fs::write(&path, &whole[..cut])?;
            assert!(read_reload_status(&path).is_none(), "cut at {cut}");
        }
        fs::write(&path, &whole)?;
        let read = read_reload_status(&path).ok_or("a whole record")?;
        assert_eq!((read.seq, read.offline.len()), (2, 1));
        let wait =
            |pid| wait_for_reload_status(&path, pid, 1, Some("aa"), Duration::from_millis(80));
        assert!(wait(TEST_PID).is_ok());
        assert!(matches!(
            wait(TEST_PID + 1),
            Err(ReloadWaitError::Timeout(_))
        ));
        // A record of an older server (no format line) is read as before.
        fs::write(&path, "pid=7\nseq=3\nstatus=ok\n")?;
        assert!(read_reload_status(&path).is_some());
        let _ = fs::remove_file(&path);
        Ok(())
    }

    /// R6-BLD-1: Ensures `send_reload_signal` keeps one cross-platform 3-parameter signature
    /// across Unix and non-Unix (Windows) targets so platform stubs cannot drift out of sync.
    #[test]
    fn r6_bld_1_send_reload_signal_has_unified_cross_platform_signature() {
        let sig_pin: fn(u32, &Path, Option<&str>) -> Result<ReloadAck, ReloadFailure> =
            send_reload_signal;
        let _ = sig_pin;
    }

    /// R6-RUN-1: When another reload completes with a different `config_sha256`,
    /// `wait_for_reload_status` MUST fail with "superseded or unknown" after the deadline rather
    /// than falling through and printing another reload's `"OK"`.
    #[cfg(unix)]
    #[test]
    fn r6_run_1_wait_for_reload_status_fails_when_superseded_by_different_digest()
    -> Result<(), Box<dyn std::error::Error>> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let status_path = std::env::temp_dir().join(format!(
            "miraserve-r6-run-1-{}-{nanos}.reload-status",
            std::process::id()
        ));

        // Another reload finished (`seq=2`, `status=ok`), but its config digest does NOT match!
        fs::write(
            &status_path,
            "seq=2\nstatus=ok\ngeneration=2\nconfig_sha256=bbbbbbbbbbbbbbbb\n",
        )?;
        let res = wait_for_reload_status(
            &status_path,
            TEST_PID,
            1,
            Some("aaaaaaaaaaaaaaaa"),
            Duration::from_millis(80),
        );
        let err = res
            .err()
            .ok_or("R6-RUN-1: mismatched digest MUST NOT succeed after deadline")?;
        // Committed, but from the server's own file: reported as such, never as this reload.
        assert!(
            matches!(
                &err,
                ReloadWaitError::OtherConfigCommitted(_, msg) if msg.contains("superseded or unknown")
            ),
            "expected 'superseded or unknown' diagnostic, got: {err:?}"
        );

        // Matching digest succeeds immediately!
        fs::write(
            &status_path,
            "seq=3\nstatus=ok\ngeneration=3\nconfig_sha256=aaaaaaaaaaaaaaaa\n",
        )?;
        let ok = wait_for_reload_status(
            &status_path,
            TEST_PID,
            2,
            Some("aaaaaaaaaaaaaaaa"),
            Duration::from_millis(200),
        )
        .map_err(|e| format!("expected matching digest to succeed, got: {e}"))?;
        assert_eq!(ok.status, "ok");
        assert_eq!(ok.generation, Some(3));

        // LOW reload --config: If the server reports `status=error` on its own broken on-disk
        // config (different digest from `--config other.kdl`), surface that error IMMEDIATELY
        // instead of waiting for the full timeout and reporting "superseded"!
        fs::write(
            &status_path,
            "seq=4\nstatus=error\nconfig_sha256=cccccccccccccccc\nerror=broken on-disk KDL\n",
        )?;
        let started = Instant::now();
        let broken_res = wait_for_reload_status(
            &status_path,
            TEST_PID,
            3,
            Some("aaaaaaaaaaaaaaaa"),
            Duration::from_secs(5),
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "must surface server reload error immediately without waiting timeout"
        );
        let broken_err = broken_res
            .err()
            .ok_or("expected immediate error on server status=error")?;
        assert!(
            broken_err.to_string().contains("broken on-disk KDL"),
            "expected server validation error message, got: {broken_err}"
        );

        let _ = fs::remove_file(&status_path);
        Ok(())
    }

    /// Review after 17ec17b: a batched access log rotates between complete lines, keeps each
    /// file within the limit, and never leaves an empty backup.
    #[test]
    fn batched_access_log_rotates_on_line_boundaries_within_the_limit()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write as _;

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "miraserve-log-batch-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir)?;
        let log_path = dir.join("access.log");
        let mut inner = RotatingLogInner::open(&log_path, 2_048, 3)?;
        inner.buffer = Some(Vec::new());
        let writer = RotatingMakeWriter {
            inner: std::sync::Arc::new(std::sync::Mutex::new(inner)),
        };
        // 21 lines of 337 bytes: 7,077 bytes, written as one batch.
        let line = format!("{}\n", "x".repeat(336));
        for _ in 0..21 {
            let mut guard = RotatingWriterGuard {
                inner: &writer.inner,
            };
            guard.write_all(line.as_bytes())?;
        }
        if let Ok(mut inner) = writer.inner.lock() {
            let _ = inner.flush_buffer(true);
        }
        let mut total = 0_usize;
        // 6 lines fit a file: backups .3, .2, .1 hold 6 each, the active file the last 3.
        for path in [
            log_path.clone(),
            rotated_log_path(&log_path, 1),
            rotated_log_path(&log_path, 2),
            rotated_log_path(&log_path, 3),
        ] {
            let content = fs::read(&path)?;
            assert!(!content.is_empty(), "{} must not be empty", path.display());
            assert!(
                content.len() <= 2_048,
                "{} has {} bytes, over the 2,048 limit",
                path.display(),
                content.len()
            );
            assert!(
                content.len() % line.len() == 0,
                "{} must hold complete lines",
                path.display()
            );
            total += content.len();
        }
        assert_eq!(total, 21 * line.len(), "no line lost");
        assert_eq!(fs::read(&log_path)?.len(), 3 * line.len());
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    /// Review after 17ec17b: while the access log cannot be written, the unwritten lines are
    /// kept up to a bound and the oldest whole lines beyond it are dropped and counted.
    #[test]
    fn unwritable_access_log_keeps_a_bounded_tail_of_whole_lines()
    -> Result<(), Box<dyn std::error::Error>> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("miraserve-log-keep-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir)?;
        let mut inner = RotatingLogInner::open(&dir.join("access.log"), 0, 1)?;
        let line = format!("{}\n", "z".repeat(99));
        let count = MAX_UNWRITTEN_ACCESS_LOG_BYTES / line.len() + 500;
        let mut pending = line.repeat(count).into_bytes();
        inner.drop_oldest_lines(&mut pending);
        assert!(pending.len() <= MAX_UNWRITTEN_ACCESS_LOG_BYTES);
        assert_eq!(pending.len() % line.len(), 0, "only whole lines are kept");
        assert_eq!(
            inner.dropped_lines,
            u64::try_from(count - pending.len() / line.len())?
        );
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    /// Review of section 4c: the rest of a line a failed write left half on disk goes to the
    /// same file first, without rotation, and is never dropped to make room.
    #[test]
    fn interrupted_access_log_line_is_finished_in_the_same_file()
    -> Result<(), Box<dyn std::error::Error>> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("miraserve-log-tail-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir)?;
        let log_path = dir.join("access.log");
        let mut inner = RotatingLogInner::open(&log_path, 100, 2)?;
        // 95 bytes on disk, the last line unfinished ("head-" of "head-tail\n").
        let mut on_disk = "a".repeat(89);
        on_disk.push('\n');
        on_disk.push_str("head-");
        inner
            .write_through(on_disk.as_bytes())
            .map_err(|(_, err)| err)?;
        inner.partial_tail = 5;
        let mut pending = b"tail\n".to_vec();
        // A huge backlog behind it: trimming must not touch the unfinished line.
        let filler = format!("{}\n", "f".repeat(99));
        pending.extend(
            filler
                .repeat(MAX_UNWRITTEN_ACCESS_LOG_BYTES / 100 + 50)
                .bytes(),
        );
        inner.drop_oldest_lines(&mut pending);
        assert!(
            pending.starts_with(b"tail\n"),
            "the unfinished line survives trimming"
        );
        assert!(pending.len() <= MAX_UNWRITTEN_ACCESS_LOG_BYTES);
        pending.truncate(5);
        pending.extend_from_slice(b"next line\n");
        inner.buffer = Some(pending);

        let (left, _) = inner.flush_buffer(true);
        assert_eq!(left, 0);
        // The tail went into the first file although it is now over the limit by 0 bytes, and
        // the next line started a new one.
        let first = fs::read_to_string(rotated_log_path(&log_path, 1))?;
        assert!(first.ends_with("head-tail\n"), "got {first:?}");
        assert_eq!(fs::read_to_string(&log_path)?, "next line\n");
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    /// Review of section 4c: while the file cannot be written, attempts wait for the retry time
    /// (requests do not retry), a forced attempt still happens, and lines are not lost.
    #[test]
    fn failing_access_log_retries_on_a_schedule_and_recovers()
    -> Result<(), Box<dyn std::error::Error>> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "miraserve-log-retry-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir)?;
        let log_path = dir.join("access.log");
        let mut inner = RotatingLogInner::open(&log_path, 0, 1)?;
        let writable = std::mem::replace(&mut inner.file, File::open(&log_path)?);
        inner.buffer = Some(b"one\ntwo\n".to_vec());

        assert_eq!(
            inner.flush_buffer(false),
            (8, 2),
            "read-only handle: nothing written"
        );
        assert!(inner.retry_at.is_some());
        if let Some(buffer) = inner.buffer.as_mut() {
            buffer.extend_from_slice(b"three\n");
        }
        assert_eq!(
            inner.flush_buffer(false),
            (14, 3),
            "not due yet: no attempt, nothing lost"
        );
        inner.file = writable;
        assert_eq!(
            inner.flush_buffer(true),
            (0, 0),
            "a forced attempt writes everything"
        );
        assert!(inner.retry_at.is_none());
        assert_eq!(fs::read_to_string(&log_path)?, "one\ntwo\nthree\n");
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    /// Review of section 4d: after a run that stopped mid-line, the first new line starts on a
    /// line of its own; a complete log is left untouched.
    #[test]
    fn restart_after_an_unfinished_line_starts_a_new_line() -> Result<(), Box<dyn std::error::Error>>
    {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "miraserve-log-restart-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir)?;
        let broken = dir.join("broken.log");
        fs::write(&broken, b"complete\nhalf a li")?;
        let mut inner = RotatingLogInner::open(&broken, 0, 1)?;
        inner.buffer = Some(Vec::new());
        inner.finish_unterminated_line();
        if let Some(buffer) = inner.buffer.as_mut() {
            buffer.extend_from_slice(b"new\n");
        }
        let _ = inner.flush_buffer(true);
        assert_eq!(fs::read(&broken)?, b"complete\nhalf a li\nnew\n");

        // A write-only log cannot be read: a separator is written to be safe.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let write_only = dir.join("write-only.log");
            fs::write(&write_only, b"half a li")?;
            fs::set_permissions(&write_only, fs::Permissions::from_mode(0o200))?;
            let mut inner = RotatingLogInner::open(&write_only, 0, 1)?;
            inner.buffer = Some(Vec::new());
            inner.finish_unterminated_line();
            if let Some(buffer) = inner.buffer.as_mut() {
                buffer.extend_from_slice(b"new\n");
            }
            let _ = inner.flush_buffer(true);
            fs::set_permissions(&write_only, fs::Permissions::from_mode(0o600))?;
            assert_eq!(fs::read(&write_only)?, b"half a li\nnew\n");
        }

        let whole = dir.join("whole.log");
        fs::write(&whole, b"complete\n")?;
        let mut inner = RotatingLogInner::open(&whole, 0, 1)?;
        inner.buffer = Some(Vec::new());
        inner.finish_unterminated_line();
        if let Some(buffer) = inner.buffer.as_mut() {
            buffer.extend_from_slice(b"new\n");
        }
        let _ = inner.flush_buffer(true);
        assert_eq!(fs::read(&whole)?, b"complete\nnew\n");
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    /// Review after 17ec17b: a line longer than the limit goes alone into a fresh file.
    #[test]
    fn oversized_access_log_line_is_written_alone() -> Result<(), Box<dyn std::error::Error>> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("miraserve-log-big-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir)?;
        let log_path = dir.join("access.log");
        let mut inner = RotatingLogInner::open(&log_path, 100, 2)?;
        let mut batch = b"short\n".to_vec();
        batch.extend(std::iter::repeat_n(b'y', 300));
        batch.push(b'\n');
        batch.extend_from_slice(b"after\n");
        inner.buffer = Some(batch);
        let _ = inner.flush_buffer(true);
        assert_eq!(fs::read(rotated_log_path(&log_path, 1))?.len(), 301);
        assert_eq!(fs::read(&log_path)?, b"after\n");
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn rotating_log_writer_rotates_on_size_limit_and_refuses_symlinks()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write as _;

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "miraserve-log-rotate-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir)?;
        let log_path = dir.join("access.log");

        let writer = RotatingMakeWriter {
            inner: std::sync::Arc::new(std::sync::Mutex::new(RotatingLogInner::open(
                &log_path, 32, 2,
            )?)),
        };
        for idx in 0..4 {
            let mut guard = RotatingWriterGuard {
                inner: &writer.inner,
            };
            writeln!(guard, "line-{idx}-0123456789abcdef")?;
        }
        assert!(log_path.is_file(), "active log file must exist");
        assert!(
            rotated_log_path(&log_path, 1).is_file(),
            "rotated .1 backup must exist"
        );
        assert!(
            rotated_log_path(&log_path, 2).is_file(),
            "rotated .2 backup must exist"
        );
        assert!(
            !rotated_log_path(&log_path, 3).exists(),
            "backups beyond keep=2 must not be created"
        );

        #[cfg(unix)]
        {
            let target = dir.join("real.txt");
            fs::write(&target, b"keep")?;
            let link = dir.join("sym.log");
            std::os::unix::fs::symlink(&target, &link)?;
            assert!(
                RotatingLogInner::open(&link, 0, 1).is_err(),
                "rotating log writer must refuse symlink targets"
            );

            // Codex G7: Rotation failure (e.g. symlinked `.1` backup) MUST return an explicit
            // `Err` from `rotate_if_needed` rather than silently discarding the failure.
            let fail_log = dir.join("fail-rotate.log");
            let mut inner = RotatingLogInner::open(&fail_log, 16, 2)?;
            // Something to rotate: an empty file is never rotated.
            inner.write_through(b"0123456789").map_err(|(_, err)| err)?;
            let sym_backup = rotated_log_path(&fail_log, 1);
            std::os::unix::fs::symlink(&target, &sym_backup)?;
            let rot_err = inner
                .rotate_if_needed(32)
                .err()
                .ok_or("expected symlinked backup to fail rotation")?;
            assert_eq!(rot_err.kind(), io::ErrorKind::PermissionDenied);
        }

        // Codex G7: Temporary reopen failure after `rename(active -> .1)` rolls back cleanly so
        // the active file stays recoverable once the temporary error clears (without double-
        // shifting backups), AND detached recovery recreates the missing active file cleanly!
        let rec_log = dir.join("recover.log");
        let mut rec = RotatingLogInner::open(&rec_log, 16, 2)?;
        rec.file.write_all(b"initial-20-bytes-log")?;
        rec.written = 20;
        let temp_err = rec
            .rotate_with_opener(10, |_, _| {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "temporary EMFILE/EACCES",
                ))
            })
            .err()
            .ok_or("expected temporary reopen error")?;
        assert_eq!(temp_err.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            rec_log.is_file(),
            "rollback must restore active log file after reopen failure"
        );
        assert!(
            !rotated_log_path(&rec_log, 1).exists(),
            "rollback must move .1 back to active so backup slots are not double-shifted"
        );
        // Once the temporary error clears, rotation succeeds normally!
        assert!(rec.rotate_if_needed(10)?);
        assert!(rec_log.is_file());
        assert!(rotated_log_path(&rec_log, 1).is_file());
        assert!(
            !rotated_log_path(&rec_log, 2).exists(),
            "only one backup should exist after clean recovery"
        );

        // Also test detached recovery path (e.g. active path removed while backup `.1` exists).
        fs::remove_file(&rec_log)?;
        rec.active_file_detached = true;
        assert!(rec.rotate_if_needed(4)?);
        assert!(
            rec_log.is_file(),
            "detached recovery must recreate active file"
        );
        assert!(
            !rotated_log_path(&rec_log, 2).exists(),
            "detached recovery must not shift .1 into .2 again"
        );

        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    /// Codex Round-4 P1 #2 (G7): `RotatingLogInner::open_pinned` and rotation MUST operate
    /// strictly relative to the validated pinned directory descriptor. If an alias symlink in the
    /// configured log path is swapped to another directory (e.g. a served docroot) between
    /// validation and open (or before rotation), all writes and rotated backups MUST stay strictly
    /// inside the originally validated directory and ZERO files may be created in the swapped
    /// target.
    #[cfg(unix)]
    #[test]
    fn g7_r4_p1_pinned_log_writer_ignores_alias_swap_between_validation_and_open()
    -> Result<(), Box<dyn std::error::Error>> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "miraserve-g7-r4-pinned-writer-{}-{nanos}",
            std::process::id()
        ));
        let orig_logs = base.join("orig-logs");
        let docroot = base.join("docroot");
        let alias = base.join("log-alias");
        fs::create_dir_all(&orig_logs)?;
        fs::create_dir_all(&docroot)?;
        std::os::unix::fs::symlink(&orig_logs, &alias)?;

        // 1. Validate & pin the directory via the alias at startup validation time.
        let alias_log_path = alias.join("access.log");
        let canon_orig = fs::canonicalize(&orig_logs)?;
        let pinned = PinnedWritableDir::open_validated(&canon_orig)?;

        // 2. Attacker swaps the alias symlink to point into the served `docroot` BEFORE the log
        //    writer opens or rotates the file!
        fs::remove_file(&alias)?;
        std::os::unix::fs::symlink(&docroot, &alias)?;

        // 3. Open and write/rotate through the pinned handle.
        let mut inner = RotatingLogInner::open_pinned(
            PinnedLogDir::new(&alias_log_path, pinned, true)?,
            24,
            2,
        )?;
        inner.file.write_all(b"secret-log-entry-00000001\n")?;
        inner.written = 26;
        assert!(inner.rotate_if_needed(16)?);
        inner.file.write_all(b"secret-log-entry-00000002\n")?;
        inner.file.flush()?;

        // 4. All active & rotated files MUST live in `orig_logs`; `docroot` MUST remain untouched!
        assert!(orig_logs.join("access.log").is_file());
        assert!(orig_logs.join("access.log.1").is_file());
        assert!(
            !docroot.join("access.log").exists() && !docroot.join("access.log.1").exists(),
            "swapping alias between validation and open MUST NOT redirect log writes into docroot"
        );

        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    struct R5Fixture {
        base: PathBuf,
        #[cfg_attr(not(unix), allow(dead_code))]
        www: PathBuf,
        orig_logs: PathBuf,
        cfg_dir: PathBuf,
        cfg: Config,
    }

    fn kdl_escape_path(path: &Path) -> String {
        path.to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    }

    fn r5_cli_fixture(tag: &str) -> Result<R5Fixture, Box<dyn std::error::Error>> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let base = fs::canonicalize(std::env::temp_dir())?.join(format!(
            "miraserve-r5-cli-{tag}-{}-{nanos}",
            std::process::id()
        ));
        let www = base.join("www");
        let orig_logs = base.join("orig-logs");
        let cfg_dir = base.join("cfg");
        fs::create_dir_all(&www)?;
        fs::create_dir_all(&orig_logs)?;
        fs::create_dir_all(&cfg_dir)?;
        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:8443"
}}
site "app.example.test" {{
    root "{}"
}}
"#,
            kdl_escape_path(&www)
        );
        let (cfg, _) = miraserve_config::parse_kdl("r5-cli.kdl", &kdl)?;
        Ok(R5Fixture {
            base,
            www,
            orig_logs,
            cfg_dir,
            cfg,
        })
    }

    /// Codex Round-5 P1 #1 (G7): the CLI must bind each configured log to the handle produced by
    /// validation. If a configured alias moves after validation (here: into the served
    /// document root), startup must fail in the CLI binding step itself — before the writer
    /// creates or opens any file in the new destination — for both rotating and non-rotating
    /// logs.
    #[cfg(unix)]
    #[test]
    fn g7_r5_p1_cli_binding_fails_when_alias_moves_after_validation()
    -> Result<(), Box<dyn std::error::Error>> {
        for rotating in [true, false] {
            let R5Fixture {
                base,
                www,
                orig_logs,
                cfg_dir,
                cfg,
            } = r5_cli_fixture(if rotating { "rot" } else { "plain" })?;
            let alias = base.join("log-alias");
            std::os::unix::fs::symlink(&orig_logs, &alias)?;
            let cfg_path = cfg_dir.join("miraserve.kdl");
            let ctx = LogBindContext {
                config: &cfg,
                config_path: Some(&cfg_path),
                acme_dir: None,
                secret_files: &[],
            };
            let specs = vec![CliLogSpec {
                path: alias.join("access.log"),
                rotating,
            }];
            let mut policy = SandboxPolicy::from_config_with_file(&cfg, Some(&cfg_path), None);
            let prebound = prebind_cli_logs(&mut policy, &specs, &ctx)?;
            assert!(
                prebound.first().is_some_and(|p| p.pinned.is_some()),
                "existing validated log directory must be pinned during validation"
            );

            // The alias moves into the served document root after validation.
            fs::remove_file(&alias)?;
            std::os::unix::fs::symlink(&www, &alias)?;

            let err = finalize_cli_logs(&mut policy, &specs, prebound, &ctx)
                .err()
                .ok_or("alias moved after validation: CLI binding must fail")?;
            assert!(
                err.contains("changed directory"),
                "expected a destination-change refusal, got: {err}"
            );
            assert!(
                fs::read_dir(&www)?.next().is_none(),
                "no file may be created in the new destination (rotating={rotating})"
            );
            assert!(
                !orig_logs.join("access.log").exists(),
                "binding must fail before the writer opens any log file (rotating={rotating})"
            );
            let _ = fs::remove_dir_all(&base);
        }
        Ok(())
    }

    /// Codex Round-5 P1 #1 (G7): a log directory created between validation and binding must
    /// re-validate to the SAME canonical directory; an alias redirected in that window fails.
    #[cfg(unix)]
    #[test]
    fn g7_r5_p1_cli_binding_fails_when_new_directory_alias_is_redirected()
    -> Result<(), Box<dyn std::error::Error>> {
        let R5Fixture {
            base,
            orig_logs,
            cfg_dir,
            cfg,
            ..
        } = r5_cli_fixture("created")?;
        let elsewhere = base.join("elsewhere");
        fs::create_dir_all(&elsewhere)?;
        let alias = base.join("log-alias");
        let not_yet = orig_logs.join("new-sub");
        std::os::unix::fs::symlink(&not_yet, &alias)?;
        let cfg_path = cfg_dir.join("miraserve.kdl");
        let ctx = LogBindContext {
            config: &cfg,
            config_path: Some(&cfg_path),
            acme_dir: None,
            secret_files: &[],
        };
        let specs = vec![CliLogSpec {
            path: alias.join("access.log"),
            rotating: true,
        }];
        let mut policy = SandboxPolicy::from_config_with_file(&cfg, Some(&cfg_path), None);
        let prebound = prebind_cli_logs(&mut policy, &specs, &ctx)?;
        assert!(prebound.first().is_some_and(|p| p.pinned.is_none()));

        // Directory gets created (as startup does) but the alias is redirected meanwhile.
        fs::create_dir_all(&not_yet)?;
        fs::remove_file(&alias)?;
        std::os::unix::fs::symlink(&elsewhere, &alias)?;

        let err = finalize_cli_logs(&mut policy, &specs, prebound, &ctx)
            .err()
            .ok_or("redirected alias for a newly created log directory must fail")?;
        assert!(
            err.contains("changed destination during startup"),
            "expected destination-change refusal, got: {err}"
        );
        assert!(fs::read_dir(&elsewhere)?.next().is_none());
        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    /// Codex Round-5 P2: a NON-rotating log beside (not inside) the site root is accepted by the
    /// CLI binding, while the same layout with rotation (directory-wide write grant) is refused.
    #[test]
    fn g7_r5_p2_non_rotating_log_beside_docroot_binds_but_rotating_is_refused()
    -> Result<(), Box<dyn std::error::Error>> {
        let R5Fixture {
            base, cfg_dir, cfg, ..
        } = r5_cli_fixture("beside")?;
        let cfg_path = cfg_dir.join("miraserve.kdl");
        let ctx = LogBindContext {
            config: &cfg,
            config_path: Some(&cfg_path),
            acme_dir: None,
            secret_files: &[],
        };
        let log = base.join("access.log");

        let plain = vec![CliLogSpec {
            path: log.clone(),
            rotating: false,
        }];
        let mut policy = SandboxPolicy::from_config_with_file(&cfg, Some(&cfg_path), None);
        let prebound = prebind_cli_logs(&mut policy, &plain, &ctx)?;
        let bound = finalize_cli_logs(&mut policy, &plain, prebound, &ctx)?;
        assert_eq!(bound.len(), 1);
        assert!(
            miraserve_core::find_docroot_pinned_log_overlaps(&cfg, &bound).is_empty(),
            "a private non-rotating log beside www/ must not conflict with the site root"
        );

        let rotating = vec![CliLogSpec {
            path: log,
            rotating: true,
        }];
        let mut policy = SandboxPolicy::from_config_with_file(&cfg, Some(&cfg_path), None);
        assert!(
            prebind_cli_logs(&mut policy, &rotating, &ctx).is_err(),
            "a rotating log whose directory contains the site root must be refused"
        );
        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    /// Codex Round-6 P1 #1 (Windows): CLI binding pins the log directory and its ancestors with a
    /// share-participating access right without `FILE_SHARE_DELETE` and NTFS file IDs, so:
    /// 1. real writer rotation creates `.1`/`.2` backups cleanly inside the pinned directory,
    /// 2. renaming the pinned directory or its ancestor is rejected by NTFS while bound, and
    /// 3. unchanged reload verification (`find_docroot_pinned_log_overlaps`) succeeds.
    #[cfg(windows)]
    #[test]
    fn g7_r6_p1_windows_pinned_writer_rotates_locks_ancestors_and_verifies_reload()
    -> Result<(), Box<dyn std::error::Error>> {
        let R5Fixture {
            base,
            orig_logs,
            cfg_dir,
            cfg,
            ..
        } = r5_cli_fixture("win-rot")?;
        let nested = orig_logs.join("sub");
        fs::create_dir_all(&nested)?;
        let log_path = nested.join("access.log");
        let cfg_path = cfg_dir.join("miraserve.kdl");
        let ctx = LogBindContext {
            config: &cfg,
            config_path: Some(&cfg_path),
            acme_dir: None,
            secret_files: &[],
        };
        let specs = vec![CliLogSpec {
            path: log_path.clone(),
            rotating: true,
        }];
        let mut policy = SandboxPolicy::from_config_with_file(&cfg, Some(&cfg_path), None);
        let prebound = prebind_cli_logs(&mut policy, &specs, &ctx)?;
        let bound = finalize_cli_logs(&mut policy, &specs, prebound, &ctx)?;
        let pinned_log = bound
            .first()
            .cloned()
            .ok_or("expected one bound rotating log")?;

        let mut writer = RotatingLogInner::open_pinned(pinned_log, 24, 2)?;
        for idx in 0..3 {
            writer
                .file
                .write_all(format!("win-log-entry-{idx:02}-0123456789\n").as_bytes())?;
            writer.written = 32;
            assert!(writer.rotate_if_needed(16)?);
        }
        assert!(log_path.is_file());
        assert!(rotated_log_path(&log_path, 1).is_file());
        assert!(rotated_log_path(&log_path, 2).is_file());

        // Ancestor and leaf renames MUST fail while the pinned handle is open.
        assert!(
            fs::rename(&orig_logs, base.join("orig-logs-moved")).is_err(),
            "NTFS must block renaming a locked ancestor of the pinned log directory"
        );
        assert!(
            fs::rename(&nested, orig_logs.join("sub-moved")).is_err(),
            "NTFS must block renaming the pinned log directory itself"
        );

        // Unchanged reload check passes (file IDs match).
        assert!(
            miraserve_core::find_docroot_pinned_log_overlaps(&cfg, &bound).is_empty(),
            "unchanged reload must succeed when pinned NTFS file IDs still match"
        );

        drop(writer);
        drop(bound);
        drop(policy);
        let _ = fs::remove_dir_all(&base);
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod reload_gate_tests {
    use super::{ReloadStatus, reload_baseline};

    fn status(pid: Option<u32>, seq: u64, state: &str) -> ReloadStatus {
        ReloadStatus {
            pid,
            seq,
            status: state.to_owned(),
            generation: None,
            config_sha256: None,
            error: None,
            offline: Vec::new(),
            ack: None,
            offline_count: None,
            restart_required: Vec::new(),
        }
    }

    /// Review 13, P1: SIGHUP is sent only to a process that has itself reported that it is past
    /// start-up. Every other state means "not yet".
    #[test]
    fn signal_needs_a_ready_status_from_the_same_process() {
        assert_eq!(reload_baseline(None, 100), None, "no status file");
        assert_eq!(
            reload_baseline(Some(&status(Some(100), 0, "starting")), 100),
            None
        );
        assert_eq!(
            reload_baseline(Some(&status(Some(99), 4, "ok")), 100),
            None,
            "a status left behind by a previous process"
        );
        assert_eq!(
            reload_baseline(Some(&status(None, 0, "ready")), 100),
            None,
            "a status that does not say which process wrote it"
        );
        assert_eq!(
            reload_baseline(Some(&status(Some(100), 0, "unknown")), 100),
            None
        );
        assert_eq!(
            reload_baseline(Some(&status(Some(100), 0, "ready")), 100),
            Some(0)
        );
        assert_eq!(
            reload_baseline(Some(&status(Some(100), 7, "ok")), 100),
            Some(7)
        );
        assert_eq!(
            reload_baseline(Some(&status(Some(100), 8, "err")), 100),
            Some(8)
        );
    }
}

#[cfg(all(test, unix))]
mod ack_layout_tests {
    use super::parse_offline_records;

    /// Review 24: `ack=2` daemons wrote four-field records, `ack=3` (and pre-`ack`) daemons
    /// write three-field records with codes on `offline_code=` lines; each is read by its own
    /// layout, never one as the other.
    #[test]
    fn offline_records_are_parsed_by_acknowledgement_version() {
        let fields =
            |records: Vec<super::QuarantinedSiteReport>| -> Vec<(usize, String, String, String)> {
                records
                    .into_iter()
                    .map(|r| (r.index, r.code, r.site, r.reason))
                    .collect()
            };
        let site = |index: usize, code: &str, host: &str, reason: &str| {
            (index, code.to_owned(), host.to_owned(), reason.to_owned())
        };
        assert_eq!(
            fields(parse_offline_records(
                Some(2),
                &["3\tW024\tshop.test\tusers file broken"],
                vec![]
            )),
            vec![site(3, "W024", "shop.test", "users file broken")]
        );
        assert_eq!(
            fields(parse_offline_records(
                Some(3),
                &["4\tblog.test\troot missing"],
                vec![(4, "W024".to_owned())]
            )),
            vec![site(4, "W024", "blog.test", "root missing")]
        );
        assert_eq!(
            fields(parse_offline_records(None, &["5\told.test\twhy"], vec![])),
            vec![site(5, "W026", "old.test", "why")]
        );
        // The other `ack=2` writer: three fields plus `offline_code=`.
        assert_eq!(
            fields(parse_offline_records(
                Some(2),
                &["6\tnew.test\tusers file broken"],
                vec![(6, "W024".to_owned())]
            )),
            vec![site(6, "W024", "new.test", "users file broken")]
        );
    }
}

#[cfg(test)]
mod nonblocking_runtime_writer_tests {
    use std::io;
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::{Duration, Instant};

    use tracing_subscriber::layer::SubscriberExt as _;

    use super::NonBlockingRuntimeMakeWriter;

    #[derive(Clone)]
    struct BlockingTestMakeWriter {
        lines: Arc<Mutex<Vec<String>>>,
        block_substring: &'static str,
        entered: Arc<Mutex<Option<std::sync::mpsc::Sender<()>>>>,
        release: Arc<Mutex<Option<std::sync::mpsc::Receiver<()>>>>,
    }

    struct BlockingTestWriter<'a>(&'a BlockingTestMakeWriter);

    impl io::Write for BlockingTestWriter<'_> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let text = String::from_utf8_lossy(buf).into_owned();
            if text.contains(self.0.block_substring) {
                if let Some(tx) = self
                    .0
                    .entered
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take()
                {
                    let _ = tx.send(());
                }
                if let Some(rx) = self
                    .0
                    .release
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take()
                {
                    let _ = rx.recv_timeout(Duration::from_secs(10));
                }
            }
            self.0
                .lines
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(text);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BlockingTestMakeWriter {
        type Writer = BlockingTestWriter<'a>;

        fn make_writer(&'a self) -> Self::Writer {
            BlockingTestWriter(self)
        }
    }

    /// P1-1: `NonBlockingRuntimeMakeWriter` offloads formatted tracing events when
    /// `inline_work_must_not_block()` is true (both in-task HTTP/2 context AND dedicated worker
    /// loops) so a blocked sink never blocks the emitter, while writing synchronously when false.
    #[test]
    fn p1_1_nonblocking_runtime_make_writer_offloads_in_context_and_syncs_outside()
    -> Result<(), Box<dyn std::error::Error>> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;

        let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let raw_writer = BlockingTestMakeWriter {
            lines: Arc::clone(&lines),
            block_substring: "blocked-in-h2-stream",
            entered: Arc::new(Mutex::new(Some(entered_tx))),
            release: Arc::new(Mutex::new(Some(release_rx))),
        };
        let nb_writer = NonBlockingRuntimeMakeWriter::new(raw_writer);
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_ansi(false)
                .with_writer(nb_writer),
        );

        rt.block_on(async {
            tracing::subscriber::with_default(subscriber, || -> Result<(), Box<dyn std::error::Error>> {
                // 1. Inside in-task HTTP/2 non-blocking context: returns immediately even though
                //    the underlying writer blocks on `"blocked-in-h2-stream"`.
                let t0 = Instant::now();
                miraserve_core::with_nonblocking_inline_context(|| {
                    tracing::warn!("blocked-in-h2-stream");
                });
                assert!(
                    t0.elapsed() < Duration::from_secs(1),
                    "diagnostic emission in nonblocking context must not wait for blocked sink"
                );
                entered_rx
                    .recv_timeout(Duration::from_secs(5))
                    .map_err(|_| "offloaded diagnostic drainer never entered blocked sink")?;

                // 2. Inside a dedicated worker-loop thread: also offloads without blocking.
                {
                    let _worker = miraserve_core::enter_worker_loop_thread();
                    let t1 = Instant::now();
                    tracing::warn!("queued-from-worker-loop");
                    assert!(
                        t1.elapsed() < Duration::from_secs(1),
                        "diagnostic emission on worker loop must offload without blocking"
                    );
                }

                // 3. Outside non-blocking context: writes synchronously BEFORE warn! returns
                //    (preserving default spawned/startup/shutdown/panic behavior).
                tracing::warn!("sync-outside-context");
                assert!(
                    lines
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .iter()
                        .any(|l| l.contains("sync-outside-context")),
                    "outside nonblocking context, diagnostic line must write synchronously"
                );

                // While the offloaded sink is still blocked, shutdown drain reports incomplete
                // with both offloaded lines counted as outstanding.
                let mid = miraserve_core::flush_offloaded_diagnostic_logs_blocking(
                    Duration::from_millis(25),
                );
                assert!(!mid.drained);
                assert!(
                    mid.remaining >= 2,
                    "both blocked in-flight line and queued worker line must count as outstanding (got {})",
                    mid.remaining
                );
                Ok(())
            })?;

            // Release the blocked sink and confirm both offloaded lines drain cleanly with timestamps.
            let _ = release_tx.send(());
            let done = miraserve_core::flush_offloaded_diagnostic_logs(Duration::from_secs(5)).await;
            assert!(done.drained && done.remaining == 0);
            let got = lines
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            assert!(
                got.iter().any(|l| l.contains("blocked-in-h2-stream")),
                "expected offloaded H2 diagnostic line, got: {got:?}"
            );
            assert!(
                got.iter().any(|l| l.contains("queued-from-worker-loop")),
                "expected offloaded worker-loop diagnostic line, got: {got:?}"
            );
            Ok::<_, Box<dyn std::error::Error>>(())
        })
    }
}

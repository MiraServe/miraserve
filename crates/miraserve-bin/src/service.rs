//! Implementation of `miraserve service` — generates hardened OS service definitions
//! for Linux `systemd` (`miraserve.service` + split-privilege `miraserve-keyd.service`),
//! macOS `launchd` (`app.miraserve.server.plist`), and Windows boot-time Scheduled Task installers.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Subcommand, ValueEnum};

use crate::check::{SanitizingLineWriter, validate_path_no_control, write_writable_set_lines};

/// Supported OS service managers for `miraserve service generate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum ServiceTarget {
    /// Hardened Linux `systemd` unit for the unprivileged HTTP/QUIC worker (`miraserve.service`).
    Systemd,
    /// Hardened Linux `systemd` unit for the split-privilege TLS key vault (`miraserve-keyd.service`).
    #[value(name = "systemd-keyd")]
    SystemdKeyd,
    /// macOS `launchd` `LaunchDaemon` property list (`app.miraserve.server.plist`).
    Launchd,
    /// Windows hardened boot-time Scheduled Task PowerShell installer (`install-miraserve-service.ps1`).
    Windows,
}

/// CLI arguments for `miraserve service`.
#[derive(Debug, Args)]
pub(crate) struct ServiceArgs {
    #[command(subcommand)]
    pub(crate) action: ServiceCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ServiceCommand {
    /// Generate a hardened OS service unit/installer for systemd, launchd, or Windows.
    Generate {
        /// Target OS service manager (`systemd`, `systemd-keyd`, `launchd`, `windows`).
        #[arg(long, value_enum)]
        target: ServiceTarget,

        /// Path to the installed `miraserve` executable (defaults per target platform).
        #[arg(long)]
        binary: Option<String>,

        /// Path to the MiraServe KDL configuration file.
        #[arg(long)]
        config: Option<String>,

        /// Unprivileged OS user for the service (defaults to `miraserve` for `systemd`,
        /// `miraserve-keyd` for `systemd-keyd`, `_www` for `launchd`).
        #[arg(long)]
        user: Option<String>,

        /// Unprivileged OS group for the service (defaults to `miraserve` on Linux, `_www` on macOS).
        #[arg(long)]
        group: Option<String>,

        /// Directory for ACME v2 state and issued certificates (defaults per target platform).
        #[arg(long)]
        acme_dir: Option<String>,

        /// Directory for stdout/stderr log files (used by `launchd`; defaults from `--binary` prefix).
        #[arg(long)]
        log_dir: Option<String>,

        /// Unix socket path or loopback TCP endpoint for `miraserve-keyd` IPC (used by `systemd-keyd`).
        #[arg(long, default_value = "/run/miraserve-keyd/keyd.sock")]
        keyd_socket: String,

        /// Worker OS user/group authorized to connect to `miraserve-keyd` over Unix socket
        /// (`--allow-peer-user` and `tmpfiles.d` socket directory group, used by `systemd-keyd`).
        #[arg(long, default_value = "miraserve")]
        peer_user: String,

        /// Optional path to write the companion `systemd-tmpfiles` `.conf` rule for `systemd-keyd`
        /// (e.g. `/etc/tmpfiles.d/miraserve-keyd.conf`). When omitted and `--output` is set for a
        /// Unix-socket `systemd-keyd` unit, writes `<stem>.tmpfiles.conf` alongside `--output`.
        #[arg(long, value_name = "FILE")]
        tmpfiles_output: Option<PathBuf>,

        /// Optional HMAC-SHA256 auth secret file passed to `miraserve keyd --auth-secret-file`
        /// (for `systemd-keyd` loopback TCP mode) or `miraserve run --keyd-auth-secret-file`
        /// (when paired with `--split-keyd` on `systemd`).
        #[arg(long)]
        auth_secret_file: Option<String>,

        /// Enable split-privilege `miraserve-keyd` unit ordering on `systemd`
        /// (`Wants=miraserve-keyd.service`). Note: `InaccessiblePaths=-/etc/miraserve/keys` is
        /// always enforced on `systemd` (store in-process/starter certs under `/etc/miraserve/certs`).
        #[arg(long)]
        split_keyd: bool,

        /// Tighten `systemd` with `MemoryDenyWriteExecute=yes` when Wasmtime JIT plugins are unused.
        #[arg(long)]
        no_wasm: bool,

        /// Pass `--dev-tls` in generated `launchd` `ProgramArguments` (for local development daemons).
        #[arg(long)]
        dev_tls: bool,

        /// Emit `ProtectHome=read-only` instead of `ProtectHome=yes` in the `systemd` worker unit,
        /// so document roots under `/home` (the usual hosting-panel layout,
        /// `/home/<user>/public_html/...`) are visible to the service. Set automatically when
        /// `--config` exists on disk and names a site root or sandbox `read-tree` under `/home`.
        /// Homes stay read-only to the service; ordinary Unix permissions still apply.
        #[arg(long)]
        home_docroots: bool,

        /// Omit `RestrictSUIDSGID=yes` from the `systemd` worker unit so Linux `openat2(2)` is not
        /// answered with `ENOSYS` (enabling single-call whole-path lookups, `file-cache` admission,
        /// and inline `workers` lookups). MiraServe installs its own in-process seccomp-bpf set-ID
        /// filter in `seccomp "strict"` and `"standard"` modes (not in `"off"` or `--no-sandbox`);
        /// see the comment in the generated unit and `docs/SPEC.md` for the `openat2` residual.
        #[arg(long)]
        allow_openat2: bool,

        /// Configured `server.timeouts.graceful-drain` duration in seconds used to derive
        /// `TimeoutStopSec` (`systemd`) / `ExitTimeOut` (`launchd`) as `drain + 15s`.
        /// If omitted and `--config` exists on disk, read automatically from the config; otherwise 30s.
        #[arg(long)]
        graceful_drain: Option<u64>,

        /// Optional output file path (prints to stdout if omitted).
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Overwrite an existing `--output` file instead of refusing.
        #[arg(long)]
        force: bool,

        /// Instead of the unit file, print the writable-path directives the rendered systemd unit
        /// contains (derived from the same spec that renders the unit; no host filesystem scanning):
        /// `writable unit <path>` plus `writable unit-private-tmp /tmp` and
        /// `writable unit-private-tmp /var/tmp` when `PrivateTmp=yes`. Supported for
        /// `--target systemd` and `--target systemd-keyd`. Refuses path spellings it cannot
        /// represent exactly (including some systemd would normalise, such as a trailing slash);
        /// plain generation without `--print-writable-set` is unaffected.
        #[arg(long, conflicts_with_all = ["output", "tmpfiles_output"])]
        print_writable_set: bool,
    },
}

/// Dispatches `miraserve service` subcommands.
pub(crate) fn run_service(args: &ServiceArgs) -> ExitCode {
    match &args.action {
        ServiceCommand::Generate {
            target,
            binary,
            config,
            user,
            group,
            acme_dir,
            log_dir,
            keyd_socket,
            peer_user,
            tmpfiles_output,
            auth_secret_file,
            split_keyd,
            no_wasm,
            dev_tls,
            home_docroots,
            allow_openat2,
            graceful_drain,
            output,
            force,
            print_writable_set,
        } => {
            if *print_writable_set {
                return run_generate_print_writable_set(
                    *target,
                    binary.as_deref(),
                    config.as_deref(),
                    user.as_deref(),
                    group.as_deref(),
                    acme_dir.as_deref(),
                    log_dir.as_deref(),
                    keyd_socket,
                    peer_user,
                    auth_secret_file.as_deref(),
                );
            }
            run_generate(
                *target,
                binary.as_deref(),
                config.as_deref(),
                user.as_deref(),
                group.as_deref(),
                acme_dir.as_deref(),
                log_dir.as_deref(),
                keyd_socket,
                peer_user,
                tmpfiles_output.as_ref(),
                auth_secret_file.as_deref(),
                *split_keyd,
                *no_wasm,
                *dev_tls,
                *home_docroots,
                *allow_openat2,
                *graceful_drain,
                output.as_ref(),
                *force,
            )
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_generate_print_writable_set(
    target: ServiceTarget,
    binary_opt: Option<&str>,
    config_opt: Option<&str>,
    user_opt: Option<&str>,
    group_opt: Option<&str>,
    acme_dir_opt: Option<&str>,
    log_dir_opt: Option<&str>,
    keyd_socket: &str,
    peer_user: &str,
    auth_secret_file: Option<&str>,
) -> ExitCode {
    if !matches!(target, ServiceTarget::Systemd | ServiceTarget::SystemdKeyd) {
        let mut stderr = SanitizingLineWriter::new(io::stderr().lock());
        let _ = stderr.write_line(
            "error: --print-writable-set is only supported for --target systemd and --target systemd-keyd",
        );
        return ExitCode::FAILURE;
    }

    let binary = binary_opt.unwrap_or("/usr/bin/miraserve");
    let config = config_opt.unwrap_or("/etc/miraserve/conf/miraserve.kdl");
    let user = user_opt.unwrap_or(match target {
        ServiceTarget::SystemdKeyd => "miraserve-keyd",
        ServiceTarget::Systemd | ServiceTarget::Launchd | ServiceTarget::Windows => "miraserve",
    });
    let group = group_opt.unwrap_or(match target {
        ServiceTarget::SystemdKeyd => "miraserve-keyd",
        ServiceTarget::Systemd | ServiceTarget::Launchd | ServiceTarget::Windows => "miraserve",
    });
    let acme_dir = acme_dir_opt.unwrap_or("/var/lib/miraserve/acme");
    let default_log_dir = if binary.starts_with("/opt/homebrew/") {
        "/opt/homebrew/var/log"
    } else if binary.starts_with("/usr/local/") {
        "/usr/local/var/log"
    } else {
        "/var/log/miraserve"
    };
    let log_dir = log_dir_opt.unwrap_or(default_log_dir).trim_end_matches('/');

    // Report mode (`--print-writable-set`) enforces strict path-spelling validation before
    // emitting machine-readable records, and runs BEFORE any `--config` read so a FIFO config
    // cannot block it. Plain `service generate` never enters this function.
    let validated_keyd_dir = match validate_safe_service_value("binary", binary)
        .and_then(|()| validate_safe_service_value("config", config))
        .and_then(|()| validate_unprivileged_account("user", user))
        .and_then(|()| validate_unprivileged_account("group", group))
        .and_then(|()| validate_unprivileged_account("peer-user", peer_user))
        .and_then(|()| validate_safe_service_value("acme-dir", acme_dir))
        .and_then(|()| validate_safe_service_value("log-dir", log_dir))
        .and_then(|()| validate_safe_service_value("keyd-socket", keyd_socket))
        .and_then(|()| match auth_secret_file {
            Some(p) => validate_safe_service_value("auth-secret-file", p),
            None => Ok(()),
        })
        .and_then(|()| match target {
            ServiceTarget::Systemd => {
                validate_systemd_quoted_abs_path("acme-dir", acme_dir).map(|()| None)
            }
            ServiceTarget::SystemdKeyd => validate_systemd_keyd_socket(keyd_socket).map(Some),
            ServiceTarget::Launchd | ServiceTarget::Windows => Ok(None),
        }) {
        Ok(dir) => dir,
        Err(msg) => {
            let mut stderr = SanitizingLineWriter::new(io::stderr().lock());
            let _ = stderr.write_line(&format!("error: {msg}"));
            return ExitCode::FAILURE;
        }
    };

    let fs_spec = match target {
        ServiceTarget::Systemd => systemd_worker_fs_spec(acme_dir),
        ServiceTarget::SystemdKeyd => {
            let Some(rw_dir) = validated_keyd_dir else {
                return ExitCode::FAILURE;
            };
            systemd_keyd_fs_spec(rw_dir)
        }
        ServiceTarget::Launchd | ServiceTarget::Windows => return ExitCode::FAILURE,
    };

    match fs_spec.format_writable_set_lines() {
        Ok(lines) => {
            if let Err(err) = write_writable_set_lines(io::stdout().lock(), &lines) {
                let mut stderr = SanitizingLineWriter::new(io::stderr().lock());
                let _ = stderr.write_line(&format!(
                    "error: failed to write writable-set output: {err}"
                ));
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(msg) => {
            let mut stderr = SanitizingLineWriter::new(io::stderr().lock());
            let _ = stderr.write_line(&format!("error: {msg}"));
            ExitCode::FAILURE
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::fn_params_excessive_bools
)]
fn run_generate(
    target: ServiceTarget,
    binary_opt: Option<&str>,
    config_opt: Option<&str>,
    user_opt: Option<&str>,
    group_opt: Option<&str>,
    acme_dir_opt: Option<&str>,
    log_dir_opt: Option<&str>,
    keyd_socket: &str,
    peer_user: &str,
    tmpfiles_output: Option<&PathBuf>,
    auth_secret_file: Option<&str>,
    split_keyd: bool,
    no_wasm: bool,
    dev_tls: bool,
    home_docroots: bool,
    allow_openat2: bool,
    graceful_drain_opt: Option<u64>,
    output: Option<&PathBuf>,
    force: bool,
) -> ExitCode {
    if let Some(out_path) = output
        && !force
        && out_path.exists()
    {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(
            stderr,
            "error: refusing to overwrite existing file '{}' (pass --force to overwrite)",
            out_path.display()
        );
        return ExitCode::FAILURE;
    }

    let binary = binary_opt.unwrap_or(match target {
        ServiceTarget::Systemd | ServiceTarget::SystemdKeyd => "/usr/bin/miraserve",
        ServiceTarget::Launchd => "/opt/homebrew/bin/miraserve",
        ServiceTarget::Windows => r"C:\Program Files\MiraServe\miraserve.exe",
    });
    let config = config_opt.unwrap_or(match target {
        ServiceTarget::Systemd | ServiceTarget::SystemdKeyd => "/etc/miraserve/conf/miraserve.kdl",
        ServiceTarget::Launchd => "/opt/homebrew/etc/miraserve/miraserve.kdl",
        ServiceTarget::Windows => r"C:\ProgramData\MiraServe\miraserve.kdl",
    });
    let user = user_opt.unwrap_or(match target {
        ServiceTarget::SystemdKeyd => "miraserve-keyd",
        ServiceTarget::Launchd => "_www",
        ServiceTarget::Systemd | ServiceTarget::Windows => "miraserve",
    });
    let group = group_opt.unwrap_or(match target {
        ServiceTarget::SystemdKeyd => "miraserve-keyd",
        ServiceTarget::Launchd => "_www",
        ServiceTarget::Systemd | ServiceTarget::Windows => "miraserve",
    });
    let acme_dir = acme_dir_opt.unwrap_or(match target {
        ServiceTarget::Launchd => "/opt/homebrew/var/lib/miraserve/acme",
        _ => "/var/lib/miraserve/acme",
    });
    let default_log_dir = if binary.starts_with("/opt/homebrew/") {
        "/opt/homebrew/var/log"
    } else if binary.starts_with("/usr/local/") {
        "/usr/local/var/log"
    } else {
        "/var/log/miraserve"
    };
    let log_dir = log_dir_opt.unwrap_or(default_log_dir).trim_end_matches('/');

    let drain_secs = graceful_drain_opt.unwrap_or_else(|| {
        config_opt
            .and_then(|p| miraserve_config::load_file(p).ok())
            .map_or(30, |(cfg, _)| cfg.server.timeouts.graceful_drain.as_secs())
    });
    let stop_timeout_secs = drain_secs.saturating_add(15).max(15);
    // `ProtectHome=yes` hides `/home` from the service entirely. A config whose sites live there
    // would start and then answer 404 for every file, so the unit is relaxed to read-only when
    // asked, or when the config on disk shows it is needed.
    let protect_home = if home_docroots
        || config_opt
            .and_then(|p| miraserve_config::load_file(p).ok())
            .is_some_and(|(cfg, _)| config_uses_home(&cfg))
    {
        "read-only"
    } else {
        "yes"
    };

    if let Err(msg) = validate_safe_service_value("binary", binary)
        .and_then(|()| validate_safe_service_value("config", config))
        .and_then(|()| validate_unprivileged_account("user", user))
        .and_then(|()| validate_unprivileged_account("group", group))
        .and_then(|()| validate_unprivileged_account("peer-user", peer_user))
        .and_then(|()| validate_safe_service_value("acme-dir", acme_dir))
        .and_then(|()| validate_safe_service_value("log-dir", log_dir))
        .and_then(|()| validate_safe_service_value("keyd-socket", keyd_socket))
        .and_then(|()| match auth_secret_file {
            Some(p) => validate_safe_service_value("auth-secret-file", p),
            None => Ok(()),
        })
    {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(stderr, "error: {msg}");
        return ExitCode::FAILURE;
    }

    let rendered = match target {
        ServiceTarget::Systemd => render_systemd_worker(
            binary,
            config,
            user,
            group,
            acme_dir,
            auth_secret_file,
            split_keyd,
            no_wasm,
            allow_openat2,
            stop_timeout_secs,
            protect_home,
        ),
        ServiceTarget::SystemdKeyd => render_systemd_keyd(
            binary,
            config,
            user,
            group,
            peer_user,
            keyd_socket,
            auth_secret_file,
        ),
        ServiceTarget::Launchd => render_launchd_plist(
            binary,
            config,
            user,
            group,
            acme_dir,
            log_dir,
            dev_tls,
            stop_timeout_secs,
        ),
        ServiceTarget::Windows => render_windows_ps1(binary, config),
    };

    // R6-PKG-1: Emit a matching `systemd-tmpfiles` snippet alongside generated Unix-socket
    // `systemd-keyd` units so source installs and custom `--keyd-socket` / `--user` / `--peer-user`
    // setups never depend on a hardcoded packaged `/usr/lib/tmpfiles.d/miraserve.conf`.
    let companion_tmpfiles: Option<(PathBuf, String)> =
        if target == ServiceTarget::SystemdKeyd && !keyd_socket.starts_with("tcp://") {
            let sock_dir = keyd_socket_runtime_dir(keyd_socket);
            let snippet = render_systemd_keyd_tmpfiles(&sock_dir, user, peer_user);
            if let Some(explicit) = tmpfiles_output {
                Some((explicit.clone(), snippet))
            } else {
                output.map(|out_path| {
                    let stem = out_path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("miraserve-keyd");
                    let sidecar = out_path.with_file_name(format!("{stem}.tmpfiles.conf"));
                    (sidecar, snippet)
                })
            }
        } else {
            None
        };

    if let Some((ref tf_path, _)) = companion_tmpfiles
        && !force
        && tf_path.exists()
    {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(
            stderr,
            "error: refusing to overwrite existing tmpfiles file '{}' (pass --force to overwrite)",
            tf_path.display()
        );
        return ExitCode::FAILURE;
    }

    if let Some(out_path) = output {
        if let Some(parent) = out_path.parent()
            && !parent.as_os_str().is_empty()
            && let Err(err) = fs::create_dir_all(parent)
        {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(
                stderr,
                "error: failed to create parent directory '{}': {err}",
                parent.display()
            );
            return ExitCode::FAILURE;
        }
        if let Err(err) = fs::write(out_path, rendered.as_bytes()) {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(
                stderr,
                "error: failed to write '{}': {err}",
                out_path.display()
            );
            return ExitCode::FAILURE;
        }
        let mut stderr = io::stderr().lock();
        let _ = writeln!(
            stderr,
            "OK: wrote hardened {target:?} service definition to '{}'",
            out_path.display()
        );
    } else {
        let mut stdout = io::stdout().lock();
        let _ = write!(stdout, "{rendered}");
        if target == ServiceTarget::SystemdKeyd
            && !keyd_socket.starts_with("tcp://")
            && companion_tmpfiles.is_none()
        {
            let sock_dir = keyd_socket_runtime_dir(keyd_socket);
            let mut stderr = io::stderr().lock();
            let _ = writeln!(
                stderr,
                "note: install the companion tmpfiles.d rule into /etc/tmpfiles.d/miraserve-keyd.conf \
                 (or pass --tmpfiles-output <path>): d {sock_dir} 2750 {user} {peer_user} -"
            );
        }
    }

    if let Some((tf_path, tf_body)) = companion_tmpfiles {
        if let Some(parent) = tf_path.parent()
            && !parent.as_os_str().is_empty()
            && let Err(err) = fs::create_dir_all(parent)
        {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(
                stderr,
                "error: failed to create tmpfiles parent directory '{}': {err}",
                parent.display()
            );
            return ExitCode::FAILURE;
        }
        if let Err(err) = fs::write(&tf_path, tf_body.as_bytes()) {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(
                stderr,
                "error: failed to write tmpfiles snippet '{}': {err}",
                tf_path.display()
            );
            return ExitCode::FAILURE;
        }
        let mut stderr = io::stderr().lock();
        let _ = writeln!(
            stderr,
            "OK: wrote matching systemd-tmpfiles rule to '{}' (install to /etc/tmpfiles.d/miraserve-keyd.conf)",
            tf_path.display()
        );
    }

    ExitCode::SUCCESS
}

fn validate_safe_service_value(field: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("--{field} must not be empty"));
    }
    // Reject control chars, shell metacharacters, systemd specifiers (`%`), and Unicode smart
    // quotes (which terminate PowerShell single-quoted strings, `R2-PKG-5`).
    if value.chars().any(|c| {
        c.is_control()
            || matches!(
                c,
                '\0' | '\r'
                    | '\n'
                    | ';'
                    | '|'
                    | '&'
                    | '`'
                    | '$'
                    | '%'
                    | '\u{2018}'
                    | '\u{2019}'
                    | '\u{201A}'
                    | '\u{201B}'
                    | '\u{201C}'
                    | '\u{201D}'
                    | '\u{2032}'
                    | '\u{2033}'
            )
    }) {
        return Err(format!(
            "--{field} contains forbidden control, specifier, quote, or shell/unit-injection characters"
        ));
    }
    Ok(())
}

/// Report-mode (`--print-writable-set` only) validator for a quoted systemd path directive
/// (`--acme-dir` on `--target systemd`). Plain `service generate` never calls this function.
///
/// Refuses path spellings the report cannot represent exactly, including some systemd would
/// normalise (such as a trailing slash, `//`, or `.`/`..` segments), while keeping spaces,
/// quotes, backslashes, and glob characters accepted:
/// - must pass [`validate_safe_service_value`]
/// - must be an absolute Unix path starting with `/` (never relative, never `/`)
/// - normalized: no `//`, no trailing `/`, and no `.` or `..` segments.
fn validate_systemd_quoted_abs_path(field: &str, value: &str) -> Result<(), String> {
    validate_safe_service_value(field, value)?;
    if !value.starts_with('/') {
        return Err(format!(
            "--{field} must be an absolute path for systemd targets (relative path refused): \"{}\"",
            value.escape_debug()
        ));
    }
    if value == "/" {
        return Err(format!(
            "--{field} cannot be the filesystem root '/' for systemd targets"
        ));
    }
    if value.ends_with('/') || value.contains("//") {
        return Err(format!(
            "--{field} must be a normalized path without trailing or duplicate slashes for systemd targets: \"{}\"",
            value.escape_debug()
        ));
    }
    if value.split('/').any(|seg| seg == "." || seg == "..") {
        return Err(format!(
            "--{field} must be a normalized path without '.' or '..' segments for systemd targets: \"{}\"",
            value.escape_debug()
        ));
    }
    Ok(())
}

/// Report-mode (`--print-writable-set` only) validator for a filesystem path written into unquoted
/// systemd unit / `tmpfiles.d` directives (`ReadWritePaths=-{dir}`,
/// `systemd-tmpfiles --prefix={dir}`, and `tmpfiles.d` lines). Plain `service generate` never
/// calls this function.
///
/// Refuses path spellings the report cannot represent unambiguously, including some systemd would
/// accept or normalise (trailing slash, `//`, `.`/`..`, lone `]`, non-ASCII whitespace):
/// - must satisfy [`validate_systemd_quoted_abs_path`] (absolute, normalized, not `/`, safe value)
/// - no whitespace, quotes (`"`, `'`), backslashes (`\`), or glob metacharacters (`*`, `?`,
///   `[`, `]`).
fn validate_systemd_unquoted_path(field: &str, value: &str) -> Result<(), String> {
    validate_systemd_quoted_abs_path(field, value)?;
    if value
        .chars()
        .any(|c| c.is_whitespace() || matches!(c, '"' | '\'' | '\\' | '*' | '?' | '[' | ']'))
    {
        return Err(format!(
            "--{field} contains whitespace, quote, escape, or glob characters that unquoted systemd ReadWritePaths/tmpfiles directives cannot carry faithfully: \"{}\"",
            value.escape_debug()
        ));
    }
    Ok(())
}

/// Report-mode (`--print-writable-set` only) validator for `--keyd-socket` on
/// `--target systemd-keyd`. Plain `service generate` never calls this function.
///
/// Returns the exact writable directory reported by `--print-writable-set`. The quoted-argument
/// grammar ([`validate_safe_service_value`]) applies to the full endpoint rendered through
/// `systemd_quote` in `ExecStart=`, while the strict unquoted path grammar
/// ([`validate_systemd_unquoted_path`]) applies ONLY to the parent directory. Refuses path
/// spellings the report cannot represent unambiguously (including some systemd or `miraserve keyd`
/// would normalise/trim, such as `//`, lone `]`, U+00A0, or trailing space on `tcp://...`), as
/// well as Unix sockets whose parent is `/`, `/run`, or `/var/run`. The operator must dedicate the
/// chosen parent directory to `miraserve-keyd` because `tmpfiles.d` sets `2750` and keyd ownership
/// on it.
fn validate_systemd_keyd_socket(keyd_socket: &str) -> Result<String, String> {
    validate_safe_service_value("keyd-socket", keyd_socket)?;
    if keyd_socket.starts_with("tcp://") {
        if keyd_socket
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '"' | '\'' | '\\'))
        {
            return Err(format!(
                "--keyd-socket contains whitespace, quote, or escape characters not permitted in systemd units: \"{}\"",
                keyd_socket.escape_debug()
            ));
        }
        miraserve_tls::KeydEndpoint::parse(keyd_socket)
            .map_err(|err| format!("invalid --keyd-socket: {err}"))?;
        return Ok("/run/miraserve-keyd".to_owned());
    }
    let stripped = keyd_socket.strip_prefix("unix:").unwrap_or(keyd_socket);
    if !stripped.starts_with('/') {
        return Err(format!(
            "--keyd-socket must be an absolute path for systemd targets (relative path refused): \"{}\"",
            keyd_socket.escape_debug()
        ));
    }
    if stripped.ends_with('/') {
        return Err(format!(
            "--keyd-socket must name a socket file inside a subdirectory you dedicate to miraserve-keyd: \"{}\"",
            keyd_socket.escape_debug()
        ));
    }
    let Some((raw_parent, file_name)) = stripped.rsplit_once('/') else {
        return Err(format!(
            "--keyd-socket must name a socket file inside a subdirectory you dedicate to miraserve-keyd: \"{}\"",
            keyd_socket.escape_debug()
        ));
    };
    if file_name.is_empty() || file_name == "." || file_name == ".." {
        return Err(format!(
            "--keyd-socket must name a socket file inside a subdirectory you dedicate to miraserve-keyd: \"{}\"",
            keyd_socket.escape_debug()
        ));
    }
    if raw_parent.is_empty() || raw_parent == "/run" || raw_parent == "/var/run" {
        return Err(format!(
            "--keyd-socket '{}' must live inside a subdirectory you dedicate to miraserve-keyd (not directly in '/', '/run', or '/var/run'), e.g. '/run/miraserve-keyd/keyd.sock'",
            keyd_socket.escape_debug()
        ));
    }
    validate_systemd_unquoted_path("keyd-socket parent directory", raw_parent)?;
    Ok(raw_parent.to_owned())
}

fn validate_unprivileged_account(field: &str, account: &str) -> Result<(), String> {
    validate_safe_service_value(field, account)?;
    let lower = account.trim().to_ascii_lowercase();
    if lower.parse::<u32>().ok() == Some(0)
        || matches!(
            lower.as_str(),
            "root" | "wheel" | "admin" | "administrator" | "system" | "nt authority\\system"
        )
    {
        return Err(format!(
            "refusing to generate service running as privileged {field} '{account}' (Threat Model T2/T5)"
        ));
    }
    if !account
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err(format!(
            "--{field} '{account}' contains invalid OS account characters"
        ));
    }
    Ok(())
}

fn systemd_quote(arg: &str) -> String {
    let escaped = arg.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

fn ps_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Returns `true` when any site root, route root or sandbox `read-tree` lies under `/home`.
fn config_uses_home(cfg: &miraserve_config::Config) -> bool {
    let under_home = |p: &str| p == "/home" || p.starts_with("/home/");
    cfg.server.sandbox.read_trees.iter().any(|t| under_home(t))
        || cfg.sites.iter().any(|site| {
            site.root.as_deref().is_some_and(under_home)
                || site
                    .routes
                    .iter()
                    .any(|r| r.root.as_deref().is_some_and(under_home))
        })
}

const SYSTEMD_ALLOW_OPENAT2_COMMENT: &str = "\
# RestrictSUIDSGID omitted (--allow-openat2): systemd's filter answers ENOSYS to every\n\
# openat2(), disabling whole-path lookups, file-cache admission, and inline worker lookups.\n\
# Replaced in-process by MiraServe's seccomp-bpf set-ID policy (active under seccomp\n\
# \"strict\" and \"standard\", NOT under seccomp \"off\" or --no-sandbox), which rejects\n\
# S_ISUID/S_ISGID with EPERM on chmod/fchmod/fchmodat/fchmodat2/mkdir/mkdirat/mknod/\n\
# mknodat/creat/open/openat/mq_open and denies io_uring_{setup,enter,register} in both\n\
# modes. Note: on systemd 258+ with DefaultRestrictSUIDSGID=yes in systemd-system.conf,\n\
# omitting this line still inherits yes (add a drop-in with RestrictSUIDSGID=no).\n\
# Residual (why this is opt-in): seccomp cannot read openat2()'s struct open_how, so a\n\
# compromised worker can create a service-owned set-ID inode (group: effective group, or\n\
# the parent's on a set-GID parent) via openat2 with O_CREAT or O_TMPFILE where its\n\
# effective filesystem policy permits it, and chmod service-owned dirs to be searchable\n\
# (Landlock does not mediate chmod). With enforcing Landlock, named regular-file creation\n\
# (MakeReg) is limited to: --acme-dir (packaged /var/lib/miraserve/acme under /var/lib/\n\
# miraserve, both miraserve:miraserve), ai-publish.storage if set (packaged /var/lib/\n\
# miraserve/releases, miraserve:miraserve), and any rotating-log parent if --log-max-bytes\n\
# > 0 (packaged /var/log/miraserve, miraserve:miraserve). Unnamed O_TMPFILE creation is\n\
# checked by Landlock as a file open (WriteFile, not MakeReg), so configured socket-tree\n\
# dirs can also admit an unnamed inode where the effective mount is writable (a tree\n\
# outside this unit's writable paths is read-only; one under /var/log/miraserve is not)\n\
# and the filesystem and Unix permissions allow. Naming it (linkat) is a separate\n\
# operation that needs MakeReg at the destination (and Refer cross-dir, or fails EXDEV on\n\
# ABI v1): a socket-tree grant ALONE gives no such right, but the grants of one Landlock\n\
# ruleset add up, so a socket-tree beneath a writable grant (e.g. a rotating-log parent)\n\
# can be named in. Without Landlock, whatever the unit and permissions leave writable is\n\
# reachable. NoNewPrivileges=yes and Strict's exec denial protect the worker only; modes\n\
# on service-owned dirs (0700/0750) do NOT bound a compromised worker. No CAP_CHOWN (never\n\
# root-owned); ordinary unprivileged writes can clear set-ID bits. If a usable marked\n\
# executable survives, another local process that EXECUTES it may gain the file owner's\n\
# UID (from S_ISUID) and/or its group (from S_ISGID with group-execute) independently,\n\
# and so reach files accessible to that UID or GID (including worker-owned certs/keys and\n\
# ACME account material; split miraserve-keyd isolates only its own signing keys, disables\n\
# built-in ACME issuance, and leaves existing worker-owned ACME account material in\n\
# place). A root-controlled, non-searchable ancestor is a pathname control only (it does\n\
# not stop a process handed an open fd via a Unix socket); what suppresses the credential\n\
# change is nosuid on every mount through which the inode can be executed.";

/// One entry in a systemd `ReadWritePaths=` directive.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SystemdReadWriteEntry {
    path: String,
    optional: bool,
    quote: bool,
}

/// Single source of truth for the writable filesystem directives of a generated systemd unit.
///
/// Both unit rendering (`RuntimeDirectory=`, `StateDirectory=`, `LogsDirectory=`, `PrivateTmp=`,
/// `ReadWritePaths=`) and `--print-writable-set` read directly from this struct so they can never
/// drift apart.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SystemdUnitFsSpec {
    runtime_directories: Vec<String>,
    state_directories: Vec<String>,
    logs_directories: Vec<String>,
    read_write_paths: Vec<SystemdReadWriteEntry>,
    private_tmp: bool,
}

impl SystemdUnitFsSpec {
    fn render_read_write_paths(&self) -> String {
        self.read_write_paths
            .iter()
            .map(|entry| {
                let prefix = if entry.optional { "-" } else { "" };
                if entry.quote {
                    format!("{prefix}{}", systemd_quote(&entry.path))
                } else {
                    format!("{prefix}{}", entry.path)
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    const fn render_private_tmp(&self) -> &'static str {
        if self.private_tmp { "yes" } else { "no" }
    }

    /// Formats the rendered unit's writable directives directly from this struct without touching
    /// the host filesystem (no canonicalization, existence checks, or mount scanning).
    fn format_writable_set_lines(&self) -> Result<Vec<String>, String> {
        let mut unit_paths: BTreeSet<String> = BTreeSet::new();
        let mut record_path = |raw: String, label: &str| -> Result<(), String> {
            let clean = validate_path_no_control(Path::new(&raw), label)?;
            unit_paths.insert(clean);
            Ok(())
        };

        for dir in &self.runtime_directories {
            record_path(format!("/run/{dir}"), "RuntimeDirectory")?;
        }
        for dir in &self.state_directories {
            record_path(format!("/var/lib/{dir}"), "StateDirectory")?;
        }
        for dir in &self.logs_directories {
            record_path(format!("/var/log/{dir}"), "LogsDirectory")?;
        }
        for entry in &self.read_write_paths {
            record_path(entry.path.clone(), "ReadWritePaths")?;
        }

        let mut lines: Vec<String> = Vec::with_capacity(unit_paths.len() + 2);
        for path in unit_paths {
            lines.push(format!("writable unit {path}"));
        }
        if self.private_tmp {
            // `PrivateTmp=yes` gives the service private `/tmp` and `/var/tmp` directories inside
            // its mount namespace (normally bind-mounted service-private directories, not host
            // `/tmp` or `/var/tmp`).
            lines.push("writable unit-private-tmp /tmp".to_owned());
            lines.push("writable unit-private-tmp /var/tmp".to_owned());
        }
        Ok(lines)
    }
}

fn systemd_worker_fs_spec(acme_dir: &str) -> SystemdUnitFsSpec {
    let mut read_write_paths = vec![
        SystemdReadWriteEntry {
            path: "/var/lib/miraserve".to_owned(),
            optional: false,
            quote: false,
        },
        SystemdReadWriteEntry {
            path: "/run/miraserve".to_owned(),
            optional: false,
            quote: false,
        },
    ];
    if acme_dir != "/var/lib/miraserve/acme" {
        read_write_paths.push(SystemdReadWriteEntry {
            path: acme_dir.to_owned(),
            optional: true,
            quote: true,
        });
    }
    SystemdUnitFsSpec {
        runtime_directories: vec!["miraserve".to_owned()],
        state_directories: vec!["miraserve".to_owned()],
        logs_directories: vec!["miraserve".to_owned()],
        read_write_paths,
        private_tmp: true,
    }
}

fn systemd_keyd_fs_spec(rw_socket_dir: String) -> SystemdUnitFsSpec {
    SystemdUnitFsSpec {
        runtime_directories: Vec::new(),
        state_directories: Vec::new(),
        logs_directories: Vec::new(),
        read_write_paths: vec![SystemdReadWriteEntry {
            path: rw_socket_dir,
            optional: true,
            quote: false,
        }],
        private_tmp: true,
    }
}

#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
fn render_systemd_worker(
    binary: &str,
    config: &str,
    user: &str,
    group: &str,
    acme_dir: &str,
    auth_secret_file: Option<&str>,
    split_keyd: bool,
    no_wasm: bool,
    allow_openat2: bool,
    stop_timeout_secs: u64,
    protect_home: &str,
) -> String {
    let fs_spec = systemd_worker_fs_spec(acme_dir);
    let mdwe = if no_wasm { "yes" } else { "no" };
    let restrict_suid_sgid = if allow_openat2 {
        SYSTEMD_ALLOW_OPENAT2_COMMENT
    } else {
        "RestrictSUIDSGID=yes"
    };
    let bin_q = systemd_quote(binary);
    let cfg_q = systemd_quote(config);
    let acme_q = systemd_quote(acme_dir);
    let keyd_unit_deps = if split_keyd {
        "After=network-online.target miraserve-keyd.service\nWants=network-online.target miraserve-keyd.service"
    } else {
        "After=network-online.target\nWants=network-online.target"
    };
    let secret_arg = match auth_secret_file {
        Some(p) => format!(" --keyd-auth-secret-file {}", systemd_quote(p)),
        None => String::new(),
    };
    let runtime_dir = fs_spec.runtime_directories.join(" ");
    let state_dir = fs_spec.state_directories.join(" ");
    let logs_dir = fs_spec.logs_directories.join(" ");
    let private_tmp = fs_spec.render_private_tmp();
    let rw_paths = fs_spec.render_read_write_paths();
    format!(
        r"# Generated by `miraserve service generate --target systemd`
# Hardened unprivileged systemd unit for MiraServe (Linux Landlock + seccomp-bpf + CAP_NET_BIND_SERVICE)

[Unit]
Description=MiraServe Memory-Safe Post-Quantum HTTPS & AI Edge Server
Documentation=https://github.com/miraserve/miraserve
{keyd_unit_deps}

[Service]
Type=simple
User={user}
Group={group}
ExecStartPre={bin_q} check --fs --acme-dir {acme_q}{secret_arg} {cfg_q}
ExecStart={bin_q} run {cfg_q} --acme-dir {acme_q} --pid-file /run/miraserve/miraserve.pid{secret_arg}
ExecReload={bin_q} reload --pid-file /run/miraserve/miraserve.pid --acme-dir {acme_q}{secret_arg} --config {cfg_q}
KillSignal=SIGTERM
# Derived from `server.timeouts.graceful-drain` + 15s grace (override with `--graceful-drain <secs>`).
TimeoutStopSec={stop_timeout_secs}s
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576

# Privilege separation: bind :80/:443 without ever running as UID 0 (Threat Model T2/T5)
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes

# Filesystem & kernel confinement (layered beneath MiraServe's in-process Landlock + seccomp-bpf)
RuntimeDirectory={runtime_dir}
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=yes
StateDirectory={state_dir}
StateDirectoryMode=0750
# File logs (`--log-file`, `--access-log`) and their rotation go to /var/log/miraserve.
LogsDirectory={logs_dir}
LogsDirectoryMode=0750
ProtectSystem=strict
ProtectHome={protect_home}
PrivateTmp={private_tmp}
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
{restrict_suid_sgid}
LockPersonality=yes
# Set MemoryDenyWriteExecute=yes (via --no-wasm) if Wasmtime JIT plugins are not used.
MemoryDenyWriteExecute={mdwe}
SystemCallArchitectures=native
# Unconditionally block worker access to the isolated `miraserve-keyd` private-key vault.
# Starter/in-process TLS certificates live under `/etc/miraserve/certs/` instead.
InaccessiblePaths=-/etc/miraserve/keys
ReadWritePaths={rw_paths}
UMask=0027

[Install]
WantedBy=multi-user.target
"
    )
}

fn keyd_socket_runtime_dir(keyd_socket: &str) -> String {
    let stripped = keyd_socket.strip_prefix("unix:").unwrap_or(keyd_socket);
    std::path::Path::new(stripped)
        .parent()
        .and_then(|p| p.to_str())
        .filter(|s| !s.is_empty() && *s != "/" && *s != "/run" && *s != "/var/run")
        .unwrap_or("/run/miraserve-keyd")
        .to_owned()
}

fn render_systemd_keyd_tmpfiles(socket_dir: &str, user: &str, peer_group: &str) -> String {
    format!(
        "# Generated by `miraserve service generate --target systemd-keyd`\n\
         # Install to /etc/tmpfiles.d/miraserve-keyd.conf (or run `systemd-tmpfiles --create`)\n\
         d {socket_dir} 2750 {user} {peer_group} -\n"
    )
}

#[allow(clippy::too_many_arguments)]
fn render_systemd_keyd(
    binary: &str,
    config: &str,
    user: &str,
    group: &str,
    peer_user: &str,
    keyd_socket: &str,
    auth_secret_file: Option<&str>,
) -> String {
    let bin_q = systemd_quote(binary);
    let cfg_q = systemd_quote(config);
    let sock_q = systemd_quote(keyd_socket);
    let secret_arg = match auth_secret_file {
        Some(p) => format!(" --auth-secret-file {}", systemd_quote(p)),
        None => String::new(),
    };
    let is_loopback_tcp = keyd_socket.starts_with("tcp://");
    // R4-KEYD-1 & R7-PKG-1: Run keyd under its own primary UID/GID (`miraserve-keyd`), grant
    // `SupplementaryGroups={peer_user}` ONLY so keyd can traverse `0750 root:{peer_user}`
    // `/etc/miraserve`, `/etc/miraserve/conf`, and `/etc/miraserve/certs` (to read `miraserve.kdl`
    // and public certs and reach `0700 miraserve-keyd:miraserve-keyd` `/etc/miraserve/keys`), while
    // `/var/lib/miraserve/acme` and `starter.key` remain `0700`/`0600 miraserve:miraserve`!
    let peer_user_arg = if is_loopback_tcp {
        String::new()
    } else {
        format!(" --allow-peer-user {peer_user}")
    };
    // R8-PKG-1: the group is needed in BOTH socket modes. In loopback-TCP mode keyd still has to
    // traverse `0750 root:{peer_user}` `/etc/miraserve` and `/etc/miraserve/conf` to read its
    // config, and to read the `0640 root:{peer_user}` shared HMAC secret file.
    let supp_group_line = format!("\nSupplementaryGroups={peer_user}");
    let umask = if is_loopback_tcp { "0077" } else { "0027" };
    let rw_socket_dir = if is_loopback_tcp {
        "/run/miraserve-keyd".to_owned()
    } else {
        keyd_socket_runtime_dir(keyd_socket)
    };
    let fs_spec = systemd_keyd_fs_spec(rw_socket_dir);
    let rw_socket_dir = fs_spec
        .read_write_paths
        .first()
        .map_or("/run/miraserve-keyd", |e| e.path.as_str());
    let private_tmp = fs_spec.render_private_tmp();
    let rw_paths = fs_spec.render_read_write_paths();
    let net_block = if is_loopback_tcp {
        "# Loopback TCP mode: pair with --auth-secret-file and --keyd-auth-secret-file (HMAC-SHA256).\n\
         PrivateNetwork=no\n\
         RestrictAddressFamilies=AF_INET AF_INET6"
            .to_owned()
    } else {
        format!(
            "# Zero network access: communicates ONLY over the 0660 + exact-UID SO_PEERCRED Unix socket\n\
             # inside {rw_socket_dir} (2750 setgid {user}:{peer_user}; only UID `{peer_user}` authorized).\n\
             PrivateNetwork=yes\n\
             RestrictAddressFamilies=AF_UNIX"
        )
    };
    let tmpfiles_pre_line = if is_loopback_tcp {
        String::new()
    } else {
        format!(
            "\n# R5-PKG-3 & R6-PKG-1: Provision {rw_socket_dir} via systemd-tmpfiles (2750 {user}:{peer_user})\n\
             # instead of RuntimeDirectory=, searching /etc/tmpfiles.d and /usr/lib/tmpfiles.d.\n\
             # Companion tmpfiles.d rule: d {rw_socket_dir} 2750 {user} {peer_user} -\n\
             ExecStartPre=+/usr/bin/systemd-tmpfiles --create --prefix={rw_socket_dir}"
        )
    };
    format!(
        r"# Generated by `miraserve service generate --target systemd-keyd`
# Split-privilege TLS signing vault (Threat Model T2: distinct UID/GID `{user}`;
# private keys under /etc/miraserve/keys (0700 {user}:{group}) never enter worker memory)

[Unit]
Description=MiraServe Split-Privilege TLS Signing Vault (miraserve-keyd)
Documentation=https://github.com/miraserve/miraserve
Before=miraserve.service

[Service]
Type=simple
User={user}
Group={group}{supp_group_line}{tmpfiles_pre_line}
ExecStart={bin_q} keyd --socket {sock_q} --config {cfg_q}{peer_user_arg}{secret_arg}
KillSignal=SIGTERM
TimeoutStopSec=15s
Restart=on-failure
RestartSec=2s

# Zero capabilities (Threat Model T2)
CapabilityBoundingSet=
AmbientCapabilities=
NoNewPrivileges=yes
{net_block}

# Strict filesystem & memory isolation ({rw_socket_dir} is managed by tmpfiles.d)
ProtectSystem=strict
ProtectHome=yes
PrivateTmp={private_tmp}
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
ReadOnlyPaths=/etc/miraserve
ReadWritePaths={rw_paths}
UMask={umask}

[Install]
WantedBy=multi-user.target
"
    )
}

#[allow(clippy::too_many_arguments)]
fn render_launchd_plist(
    binary: &str,
    config: &str,
    user: &str,
    group: &str,
    acme_dir: &str,
    log_dir: &str,
    dev_tls: bool,
    stop_timeout_secs: u64,
) -> String {
    let bin_x = xml_escape(binary);
    let cfg_x = xml_escape(config);
    let user_x = xml_escape(user);
    let group_x = xml_escape(group);
    let acme_x = xml_escape(acme_dir);
    let log_x = xml_escape(log_dir);
    let dev_tls_entry = if dev_tls {
        "\n        <string>--dev-tls</string>"
    } else {
        ""
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Generated by `miraserve service generate --target launchd` -->
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>app.miraserve.server</string>

    <key>UserName</key>
    <string>{user_x}</string>
    <key>GroupName</key>
    <string>{group_x}</string>

    <key>ProgramArguments</key>
    <array>
        <string>{bin_x}</string>
        <string>run</string>
        <string>{cfg_x}</string>
        <string>--acme-dir</string>
        <string>{acme_x}</string>{dev_tls_entry}
    </array>

    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ExitTimeOut</key>
    <integer>{stop_timeout_secs}</integer>

    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>65536</integer>
    </dict>
    <key>HardResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>262144</integer>
    </dict>

    <key>StandardOutPath</key>
    <string>{log_x}/miraserve.out.log</string>
    <key>StandardErrorPath</key>
    <string>{log_x}/miraserve.err.log</string>
</dict>
</plist>
"#
    )
}

fn render_windows_ps1(binary: &str, config: &str) -> String {
    let bin_ps = ps_single_quote(binary);
    let cfg_ps = ps_single_quote(config);
    format!(
        r#"# Generated by `miraserve service generate --target windows`
# Development / non-production Windows boot-time Scheduled Task running under
# NT AUTHORITY\LOCAL SERVICE (NOTE: Scheduled Task stop performs hard termination rather
# than graceful Win32 SCM drain; do not rely on graceful stop in production on Windows).
#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$TaskName   = 'MiraServe'
$BinaryPath = {bin_ps}
$ConfigPath = {cfg_ps}
$StateDir   = 'C:\ProgramData\MiraServe'

if (-not (Test-Path -LiteralPath $BinaryPath)) {{
    throw "MiraServe binary not found at $BinaryPath"
}}
if (-not (Test-Path -LiteralPath $ConfigPath)) {{
    throw "MiraServe config not found at $ConfigPath"
}}

# 1. Pre-validate KDL configuration before registering or starting the task
& $BinaryPath check $ConfigPath
if ($LASTEXITCODE -ne 0) {{
    throw "Configuration validation failed; aborting installation"
}}

# 2. Remove any legacy Win32 SCM service from pre-task installs to avoid port conflicts
$LegacySvc = Get-Service -Name $TaskName -ErrorAction SilentlyContinue
if ($null -ne $LegacySvc) {{
    Stop-Service -Name $TaskName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $TaskName | Out-Null
}}

# 3. Ensure state/ACME/log directories exist with restricted ACLs for NT AUTHORITY\LOCAL SERVICE (*S-1-5-19)
New-Item -ItemType Directory -Force -Path "$StateDir\acme", "$StateDir\releases", "$StateDir\logs" | Out-Null
& icacls $StateDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-19:(OI)(CI)M' | Out-Null
if ($LASTEXITCODE -ne 0) {{
    throw "Failed to apply restricted ACLs on $StateDir"
}}

# 4. Register a boot-time Scheduled Task under NT AUTHORITY\LOCAL SERVICE with restart-on-failure & log persistence
$Arguments = "run `"$ConfigPath`" --acme-dir `"$StateDir\acme`" --log-file `"$StateDir\logs\miraserve.log`""
$Action    = New-ScheduledTaskAction -Execute $BinaryPath -Argument $Arguments
$Trigger   = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\LOCAL SERVICE' -LogonType ServiceAccount -RunLevel Limited
$Settings  = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Write-Host "OK: MiraServe boot task installed and started under NT AUTHORITY\LOCAL SERVICE (logs: $StateDir\logs\miraserve.log)."
"#
    )
}

#[cfg(test)]
mod systemd_path_validation_tests {
    use super::{
        render_systemd_keyd, render_systemd_worker, validate_safe_service_value,
        validate_systemd_keyd_socket, validate_systemd_quoted_abs_path,
        validate_systemd_unquoted_path,
    };

    #[test]
    fn systemd_unquoted_path_refuses_whitespace_quotes_globs_relative_and_unnormalized() {
        for ok in [
            "/var/lib/miraserve/acme",
            "/var/lib/custom-acme_1.0/state",
            "/run/miraserve-keyd/keyd.sock",
        ] {
            assert!(
                validate_systemd_unquoted_path("keyd-socket parent directory", ok).is_ok(),
                "report-mode validator should accept {ok}"
            );
        }
        for bad in [
            "state/acme",
            "./state/acme",
            "/",
            "/var/lib/custom acme/state",
            "/run/keyd\u{00a0}dir",
            "/run/keyd]",
            "/var/lib/acme\tdir",
            "/var/lib/acme\ninj",
            "/var/lib/acme\"q",
            "/var/lib/acme'q",
            "/var/lib/acme\\b",
            "/var/lib/acme*",
            "/var/lib/acme?",
            "/var/lib/acme[0]",
            "/var/lib/acme/",
            "/var/lib//acme",
            "/var/lib/./acme",
            "/var/lib/a/../b",
            "/var/lib/%i/acme",
            "/var/lib/$HOME/acme",
        ] {
            assert!(
                validate_systemd_unquoted_path("keyd-socket parent directory", bad).is_err(),
                "report-mode validator must refuse {bad:?}"
            );
        }
    }

    #[test]
    fn systemd_quoted_acme_dir_report_validator_accepts_spaces_and_refuses_unnormalized() {
        for ok in [
            "/var/lib/miraserve/acme",
            "/var/lib/custom acme/state",
            "/var/lib/acme's/state",
            "/var/lib/acme*1/state",
            "/var/lib/acme\"q",
            "/var/lib/acme\\b",
        ] {
            assert!(
                validate_systemd_quoted_abs_path("acme-dir", ok).is_ok(),
                "report-mode quoted --acme-dir should accept {ok}"
            );
        }
        for bad in [
            "state/acme",
            "./state/acme",
            "/",
            "/var/lib/acme\tdir",
            "/var/lib/acme\ninj",
            "/var/lib/acme/",
            "/var/lib//acme",
            "/var/lib/./acme",
            "/var/lib/a/../b",
            "/var/lib/%i/acme",
            "/var/lib/$HOME/acme",
        ] {
            assert!(
                validate_systemd_quoted_abs_path("acme-dir", bad).is_err(),
                "report-mode quoted --acme-dir must refuse {bad:?}"
            );
        }

        let acme = "/var/lib/custom acme/state";
        let unit = render_systemd_worker(
            "/usr/bin/miraserve",
            "/etc/miraserve/conf/miraserve.kdl",
            "miraserve",
            "miraserve",
            acme,
            None,
            false,
            false,
            false,
            45,
            "yes",
        );
        assert!(unit.contains(
            "ExecStartPre=\"/usr/bin/miraserve\" check --fs --acme-dir \"/var/lib/custom acme/state\" \"/etc/miraserve/conf/miraserve.kdl\"\n"
        ));
        assert!(unit.contains(
            "ExecStart=\"/usr/bin/miraserve\" run \"/etc/miraserve/conf/miraserve.kdl\" --acme-dir \"/var/lib/custom acme/state\" --pid-file /run/miraserve/miraserve.pid\n"
        ));
        assert!(unit.contains(
            "ExecReload=\"/usr/bin/miraserve\" reload --pid-file /run/miraserve/miraserve.pid --acme-dir \"/var/lib/custom acme/state\" --config \"/etc/miraserve/conf/miraserve.kdl\"\n"
        ));
        assert!(unit.contains(
            "ReadWritePaths=/var/lib/miraserve /run/miraserve -\"/var/lib/custom acme/state\"\n"
        ));
    }

    #[test]
    fn systemd_quoted_exec_fields_keep_accepting_spaces_as_in_v014() {
        let bin = "/opt/my bin/miraserve";
        let cfg = "/etc/miraserve/conf/site A.kdl";
        let secret = "/etc/miraserve/my secret.key";
        assert!(validate_safe_service_value("binary", bin).is_ok());
        assert!(validate_safe_service_value("config", cfg).is_ok());
        assert!(validate_safe_service_value("auth-secret-file", secret).is_ok());
        let unit = render_systemd_worker(
            bin,
            cfg,
            "miraserve",
            "miraserve",
            "/var/lib/miraserve/acme",
            Some(secret),
            false,
            false,
            false,
            45,
            "yes",
        );
        assert!(unit.contains(
            "ExecStartPre=\"/opt/my bin/miraserve\" check --fs --acme-dir \"/var/lib/miraserve/acme\" --keyd-auth-secret-file \"/etc/miraserve/my secret.key\" \"/etc/miraserve/conf/site A.kdl\""
        ));
        assert!(unit.contains(
            "ExecStart=\"/opt/my bin/miraserve\" run \"/etc/miraserve/conf/site A.kdl\" --acme-dir \"/var/lib/miraserve/acme\" --pid-file /run/miraserve/miraserve.pid --keyd-auth-secret-file \"/etc/miraserve/my secret.key\""
        ));
    }

    #[test]
    fn systemd_keyd_socket_report_validator_requires_clean_parent_or_loopback_tcp() {
        assert_eq!(
            validate_systemd_keyd_socket("/run/miraserve-keyd/keyd.sock").ok(),
            Some("/run/miraserve-keyd".to_owned())
        );
        // Report mode accepts spaces confined to the socket filename under a clean parent.
        assert_eq!(
            validate_systemd_keyd_socket("/run/miraserve-keyd/signer A.sock").ok(),
            Some("/run/miraserve-keyd".to_owned())
        );
        assert_eq!(
            validate_systemd_keyd_socket("unix:/run/miraserve-keyd/signer A.sock").ok(),
            Some("/run/miraserve-keyd".to_owned())
        );
        assert_eq!(
            validate_systemd_keyd_socket("unix:/run/custom-keyd/signer.sock").ok(),
            Some("/run/custom-keyd".to_owned())
        );
        assert_eq!(
            validate_systemd_keyd_socket("tcp://127.0.0.1:9443").ok(),
            Some("/run/miraserve-keyd".to_owned())
        );
        for bad in [
            "/run/signing vault/keyd.sock",
            "/run/keyd]/signer.sock",
            "/run/keyd\u{00a0}dir/signer.sock",
            "/run/keyd.sock",
            "/var/run/keyd.sock",
            "/keyd.sock",
            "run/miraserve-keyd/keyd.sock",
            "/run/miraserve-keyd/../keyd.sock",
            "/run/miraserve-keyd//keyd.sock",
            "/run/miraserve-keyd/.",
            "/run/miraserve-keyd/..",
            "/run/miraserve-keyd/",
            "tcp://127.0.0.1:9443 ",
            "tcp://0.0.0.0:9443",
            "tcp://127.0.0.1:9443\ninjected",
        ] {
            assert!(
                validate_systemd_keyd_socket(bad).is_err(),
                "report-mode validator must refuse keyd socket {bad:?}"
            );
        }
    }

    #[test]
    fn systemd_keyd_spaced_socket_filename_matches_74a8243_bytes() -> Result<(), String> {
        let rw_dir = validate_systemd_keyd_socket("/run/miraserve-keyd/signer A.sock")?;
        assert_eq!(rw_dir, "/run/miraserve-keyd");
        let rendered = render_systemd_keyd(
            "/usr/bin/miraserve",
            "/etc/miraserve/conf/miraserve.kdl",
            "miraserve-keyd",
            "miraserve-keyd",
            "miraserve",
            "/run/miraserve-keyd/signer A.sock",
            None,
        );
        let expected_74a8243 = concat!(
            "# Generated by `miraserve service generate --target systemd-keyd`\n",
            "# Split-privilege TLS signing vault (Threat Model T2: distinct UID/GID `miraserve-keyd`;\n",
            "# private keys under /etc/miraserve/keys (0700 miraserve-keyd:miraserve-keyd) never enter worker memory)\n",
            "\n",
            "[Unit]\n",
            "Description=MiraServe Split-Privilege TLS Signing Vault (miraserve-keyd)\n",
            "Documentation=https://github.com/miraserve/miraserve\n",
            "Before=miraserve.service\n",
            "\n",
            "[Service]\n",
            "Type=simple\n",
            "User=miraserve-keyd\n",
            "Group=miraserve-keyd\n",
            "SupplementaryGroups=miraserve\n",
            "# R5-PKG-3 & R6-PKG-1: Provision /run/miraserve-keyd via systemd-tmpfiles (2750 miraserve-keyd:miraserve)\n",
            "# instead of RuntimeDirectory=, searching /etc/tmpfiles.d and /usr/lib/tmpfiles.d.\n",
            "# Companion tmpfiles.d rule: d /run/miraserve-keyd 2750 miraserve-keyd miraserve -\n",
            "ExecStartPre=+/usr/bin/systemd-tmpfiles --create --prefix=/run/miraserve-keyd\n",
            "ExecStart=\"/usr/bin/miraserve\" keyd --socket \"/run/miraserve-keyd/signer A.sock\" --config \"/etc/miraserve/conf/miraserve.kdl\" --allow-peer-user miraserve\n",
            "KillSignal=SIGTERM\n",
            "TimeoutStopSec=15s\n",
            "Restart=on-failure\n",
            "RestartSec=2s\n",
            "\n",
            "# Zero capabilities (Threat Model T2)\n",
            "CapabilityBoundingSet=\n",
            "AmbientCapabilities=\n",
            "NoNewPrivileges=yes\n",
            "# Zero network access: communicates ONLY over the 0660 + exact-UID SO_PEERCRED Unix socket\n",
            "# inside /run/miraserve-keyd (2750 setgid miraserve-keyd:miraserve; only UID `miraserve` authorized).\n",
            "PrivateNetwork=yes\n",
            "RestrictAddressFamilies=AF_UNIX\n",
            "\n",
            "# Strict filesystem & memory isolation (/run/miraserve-keyd is managed by tmpfiles.d)\n",
            "ProtectSystem=strict\n",
            "ProtectHome=yes\n",
            "PrivateTmp=yes\n",
            "PrivateDevices=yes\n",
            "ProtectKernelTunables=yes\n",
            "ProtectKernelModules=yes\n",
            "ProtectKernelLogs=yes\n",
            "ProtectControlGroups=yes\n",
            "ProtectClock=yes\n",
            "ProtectHostname=yes\n",
            "RestrictNamespaces=yes\n",
            "RestrictRealtime=yes\n",
            "RestrictSUIDSGID=yes\n",
            "LockPersonality=yes\n",
            "MemoryDenyWriteExecute=yes\n",
            "SystemCallArchitectures=native\n",
            "ReadOnlyPaths=/etc/miraserve\n",
            "ReadWritePaths=-/run/miraserve-keyd\n",
            "UMask=0027\n",
            "\n",
            "[Install]\n",
            "WantedBy=multi-user.target\n",
        );
        assert_eq!(rendered, expected_74a8243);
        Ok(())
    }
}

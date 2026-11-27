//! Implementation of the `miraserve check` configuration validation command.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, ValueEnum};
use miette::{GraphicalReportHandler, GraphicalTheme};
use miraserve_config::{
    Config, ConfigError, ConfigIssue, FastCgiTarget, KeyIsolation, LoadedConfig,
    MAX_CONFIG_FILE_BYTES, RewriteAction, RouteConfig, RouteHandler, Severity, SiteConfig,
    SiteHttpMode, load_file_detailed, parse_kdl_detailed, route_pattern_matches,
};
use miraserve_core::{SandboxPolicy, WritableGrant};
use serde::Serialize;

/// Output format for `miraserve check` and `miraserve reload`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum OutputFormat {
    /// Human-readable summary with source-highlighted diagnostics.
    Text,
    /// Machine-readable structured JSON report.
    Json,
}

/// The W027 diagnostic: a valid users file without users.
const EMPTY_USERS_FILE: &str = "the users file has no users; the site asks everyone for a password (401) and nobody can sign in";

/// One tenant site (`owner-dir`) quarantined during filesystem preflight classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct QuarantinedSiteReport {
    pub(crate) site: String,
    pub(crate) index: usize,
    pub(crate) code: String,
    pub(crate) reason: String,
}

/// CLI arguments for `miraserve check`.
#[derive(Debug, Args)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct CheckArgs {
    /// Path to the KDL configuration file, or '-' to read from standard input.
    #[arg(value_name = "CONFIG", default_value = "miraserve.kdl")]
    pub(crate) config: PathBuf,

    /// Fail validation (exit code 1) if any security warnings are emitted.
    #[arg(long)]
    pub(crate) strict: bool,

    /// With `--strict`, do not fail on this warning code (repeatable, e.g.
    /// `--allow-warning W002 --allow-warning W022`). The warning is still reported.
    #[arg(long, value_name = "CODE")]
    pub(crate) allow_warning: Vec<String>,

    /// Diagnostic output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub(crate) format: OutputFormat,

    /// Include the fully resolved, normalized configuration (with defaults applied).
    #[arg(long)]
    pub(crate) dump_normalized: bool,

    /// Suppress the success summary line in text mode (errors and warnings are still shown).
    #[arg(short, long)]
    pub(crate) quiet: bool,

    /// Acknowledge that the server will be started with `--dev-tls` (suppresses warning `W015`
    /// when no static certificate, ACME block, or `keyd` daemon is configured).
    #[arg(long)]
    pub(crate) dev_tls: bool,

    /// Verify on-disk existence, readability, and cryptographic validity of configured TLS
    /// certs/keys, CA bundles, keyd socket, publish storage, ACME dir, site roots, WASM modules,
    /// bot-auth key files, and publish verifying keys (`CFG-6`, `R4-PKG-2`, `R5-CHK-1`).
    #[arg(long)]
    pub(crate) fs: bool,

    /// Opt-in Linux-only check (requires `--fs`); its only warning code is `W034`; it also prints
    /// notes. It does not change what the server does (without it, the processing of a
    /// configuration is the same as in 0.1.6; with it, existing `--fs` probes still run). Walks the
    /// directories on the way to five kinds of configured paths and stops at the first component it
    /// reports or does not find: `socket-tree` roots, exact `fastcgi-pass` Unix sockets,
    /// `keyd-socket` (path of the endpoint the server connects to), ACME dir (`--acme-dir` or
    /// `.miraserve-acme`), and rotating log parents (`--log-file`/`--access-log` when
    /// `--log-max-bytes > 0`); other configured paths, including `ai-publish` storage, are not
    /// looked at yet. For each path it considers untrusted or cannot verify, it reports `W034`
    /// giving the component (when reported), its owner and mode (when known), and the reason. A
    /// warning means the check found something to fix on that path, or could not verify it; the
    /// reason in the warning says which, and the usual fixes are to correct the ownership, mode or
    /// type of the named component, or to move the path. No warning is not a guarantee. Sees
    /// checker's view; assumes same root/mount view (unit isolates `/tmp`, restricts `/home`),
    /// ordinary local filesystems (no idmap, stacking, name-hiding encryption, or other writable
    /// view), stable mounts, no shared service account. Run as the service account or as root with
    /// `server.sandbox.user` set; when no service account is configured, the check trusts the
    /// account that runs it (only root when run as root), so run it as the service account. Can
    /// wait on unresponsive filesystems; writes nothing to configured paths, reads no contents
    /// (symlink read can update atime; reads uid/symlink system files and account db).
    #[arg(long)]
    pub(crate) trusted_paths: bool,

    /// ACME state directory to verify when `--fs` and `server.tls.acme` are enabled (`R5-CHK-1`).
    #[arg(long, value_name = "DIR")]
    pub(crate) acme_dir: Option<PathBuf>,

    /// Path to the 32-byte HMAC-SHA256 shared secret file used to authenticate `--fs` keyd probes
    /// in split-daemon loopback TCP (or authenticated Unix) mode (`R7-CHK-1`).
    #[arg(long, value_name = "FILE")]
    pub(crate) keyd_auth_secret_file: Option<PathBuf>,

    /// Runtime log file path matching `miraserve run --log-file` (used with `--writable-set` and
    /// `--log-max-bytes` to include the validated rotating-log directory grant).
    #[arg(long, value_name = "FILE")]
    pub(crate) log_file: Option<PathBuf>,

    /// Access log file path matching `miraserve run --access-log` (used with `--writable-set` and
    /// `--log-max-bytes` to include the validated rotating-log directory grant).
    #[arg(long, value_name = "FILE")]
    pub(crate) access_log: Option<PathBuf>,

    /// Maximum log file size in bytes before built-in rotation, matching
    /// `miraserve run --log-max-bytes` (`0` disables built-in rotation).
    #[arg(long, default_value_t = 0)]
    pub(crate) log_max_bytes: u64,

    /// Match `miraserve run --no-sandbox` when inspecting `--writable-set` (reports Landlock as
    /// disabled on Linux / unavailable on non-Linux with zero writable Landlock grants).
    #[arg(long)]
    pub(crate) no_sandbox: bool,

    /// After validating the configuration (preserving exit status and stderr diagnostics), print
    /// a policy report: the predicted Landlock state (`landlock <state>`) followed by one
    /// `writable landlock <path>` (existing pinned object snapshot; fails if `/proc/self/fd` name
    /// lookup is unavailable) or `writable-missing landlock <absolute lexical path>` (absent or
    /// unopenable candidate, or candidate of a quarantined tenant site) per path `run` would ask
    /// Landlock to make writable. Pass the same grant-affecting flags, working directory, and user
    /// as the service's `ExecStart` (`--acme-dir`, `--log-file`, `--access-log`,
    /// `--log-max-bytes`, `--keyd-auth-secret-file`, `--no-sandbox`).
    #[arg(long, conflicts_with = "dump_normalized")]
    pub(crate) writable_set: bool,
}

#[derive(Debug, Serialize)]
struct CheckSummary {
    listeners: usize,
    sites: usize,
    routes: usize,
    tls_min_version: String,
    pqc_hybrid: bool,
    warnings: usize,
    errors: usize,
}

#[derive(Debug, Serialize)]
struct JsonCheckReport<'a> {
    valid: bool,
    strict: bool,
    source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<CheckSummary>,
    errors: Vec<ConfigIssue>,
    warnings: Vec<ConfigIssue>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    notes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    io_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    config: Option<&'a Config>,
}

fn format_duration_short(d: std::time::Duration) -> String {
    let ms = d.as_millis();
    if ms > 0 && ms.is_multiple_of(1_000) {
        format!("{}s", ms / 1_000)
    } else {
        format!("{ms}ms")
    }
}

fn format_byte_size_short(bytes: u64) -> String {
    const KIB: u64 = 1_024;
    const MIB: u64 = 1_024 * 1_024;
    const GIB: u64 = 1_024 * 1_024 * 1_024;
    if bytes == 0 {
        "0B".to_owned()
    } else if bytes.is_multiple_of(GIB) {
        format!("{}GiB", bytes / GIB)
    } else if bytes.is_multiple_of(MIB) {
        format!("{}MiB", bytes / MIB)
    } else if bytes.is_multiple_of(KIB) {
        format!("{}KiB", bytes / KIB)
    } else {
        format!("{bytes}B")
    }
}

fn collect_file_cache_notes(config: &Config) -> Vec<String> {
    let cached_sites: Vec<String> = config
        .sites
        .iter()
        .filter_map(|site| {
            let window = site.file_cache?;
            let host = site.hosts.first().map_or("<site>", String::as_str);
            Some(format!("'{host}' ({})", format_duration_short(window)))
        })
        .collect();
    if cached_sites.is_empty() {
        return Vec::new();
    }
    let listed = cached_sites.join(", ");
    let budget = config.server.limits.file_cache_bytes.as_bytes();
    if budget == 0 {
        vec![format!(
            "file-cache configured on {listed} (disabled globally: server.limits.file-cache-bytes is 0)"
        )]
    } else {
        vec![format!(
            "file-cache enabled on {listed} (changes visible within each site's window; shared budget {})",
            format_byte_size_short(budget)
        )]
    }
}

/// Executes `miraserve check` and returns the appropriate process [`ExitCode`].
pub(crate) fn run_check(args: &CheckArgs) -> ExitCode {
    if args.writable_set && args.format == OutputFormat::Json {
        let mut stderr = SanitizingLineWriter::new(io::stderr().lock());
        let _ = stderr.write_line("error: --writable-set cannot be combined with --format json");
        return ExitCode::FAILURE;
    }

    if args.trusted_paths && !args.fs {
        let mut stderr = SanitizingLineWriter::new(io::stderr().lock());
        let _ = stderr.write_line("error: --trusted-paths requires --fs");
        return ExitCode::FAILURE;
    }

    if args.writable_set
        && let Err(msg) = validate_writable_set_cli_inputs(args)
    {
        let mut stderr = SanitizingLineWriter::new(io::stderr().lock());
        let _ = stderr.write_line(&format!("error: {msg}"));
        return ExitCode::FAILURE;
    }

    let loaded = load_from_arg(&args.config);

    match loaded {
        Ok(loaded) => handle_valid(&loaded, args),
        Err(err) => handle_error(&err, args),
    }
}

/// Returns `true` for every C0 (`U+0000..=U+001F`), DEL (`U+007F`), and C1 (`U+0080..=U+009F`)
/// control character.
pub(crate) const fn is_c0_del_c1(ch: char) -> bool {
    matches!(ch as u32, 0x00..=0x1F | 0x7F..=0x9F)
}

/// Escapes every C0 (`0x00..=0x1F`), DEL (`0x7F`), and C1 (`0x80..=0x9F`) control character in
/// `s`, leaving ordinary printable text unchanged.
pub(crate) fn sanitize_control_chars(s: &str) -> String {
    if !s.chars().any(is_c0_del_c1) {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if is_c0_del_c1(ch) {
            for esc in ch.escape_default() {
                out.push(esc);
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Single sanitizing line writer used for EVERY stdout and stderr line emitted in writable-set
/// mode (`check --writable-set` and `service generate --print-writable-set`) so no C0, DEL, or C1
/// control character from any field or diagnostic can ever reach a terminal or pipe raw.
pub(crate) struct SanitizingLineWriter<W: io::Write> {
    inner: W,
}

impl<W: io::Write> SanitizingLineWriter<W> {
    pub(crate) fn new(inner: W) -> Self {
        Self { inner }
    }

    /// Writes a single logical line with every C0 (including embedded `\n`, `\r`, `\t`), DEL, and
    /// C1 character escaped, terminated by one `\n`.
    pub(crate) fn write_line(&mut self, line: &str) -> io::Result<()> {
        let clean = sanitize_control_chars(line);
        writeln!(self.inner, "{clean}")
    }

    /// Writes a pre-formatted multi-line diagnostic (such as a miette report), preserving `\n`
    /// line boundaries while escaping every C0, DEL, and C1 character within each line.
    pub(crate) fn write_multiline(&mut self, text: &str) -> io::Result<()> {
        for line in text.split('\n') {
            self.write_line(line)?;
        }
        Ok(())
    }

    pub(crate) fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Validates that `raw` is valid UTF-8 and contains no C0, DEL, or C1 control character, escaping
/// any rejected value so raw control bytes are never printed to stderr or stdout.
pub(crate) fn validate_path_no_control(raw: &Path, label: &str) -> Result<String, String> {
    let Some(raw_str) = raw.to_str() else {
        return Err(format!(
            "{label} contains non-UTF-8 bytes and cannot be emitted safely: \"{}\"",
            raw.to_string_lossy().escape_debug()
        ));
    };
    if raw_str.chars().any(is_c0_del_c1) {
        return Err(format!(
            "{label} contains a control character and is refused: \"{}\"",
            raw_str.escape_debug()
        ));
    }
    Ok(raw_str.to_owned())
}

fn validate_writable_set_cli_inputs(args: &CheckArgs) -> Result<(), String> {
    if args.config.as_os_str() != "-" {
        validate_path_no_control(&args.config, "config path")?;
    }
    for (opt, label) in [
        (&args.acme_dir, "--acme-dir"),
        (&args.log_file, "--log-file"),
        (&args.access_log, "--access-log"),
        (&args.keyd_auth_secret_file, "--keyd-auth-secret-file"),
    ] {
        if let Some(path) = opt {
            validate_path_no_control(path, label)?;
        }
    }
    Ok(())
}

/// Rejects control characters in any config path that feeds policy construction or diagnostics
/// BEFORE policy filtering or warning emission can interpolate raw characters onto stderr.
fn validate_writable_set_config_inputs(config: &Config) -> Result<(), String> {
    if let Some(sock) = &config.server.tls.keyd_socket {
        validate_path_no_control(Path::new(sock), "server.tls.keyd-socket")?;
    }
    if let Some(webroot) = &config.server.acme_webroot {
        validate_path_no_control(Path::new(webroot), "server.acme-webroot")?;
    }
    for tree in &config.server.sandbox.read_trees {
        validate_path_no_control(Path::new(tree), "server.sandbox.read-tree")?;
    }
    for tree in &config.server.sandbox.socket_trees {
        validate_path_no_control(Path::new(tree), "server.sandbox.socket-tree")?;
    }
    for site in &config.sites {
        if let Some(root) = &site.root {
            validate_path_no_control(Path::new(root), "site.root")?;
        }
        if let Some(owner) = &site.owner_dir {
            validate_path_no_control(Path::new(owner), "site.owner-dir")?;
        }
        if let Some(publish) = &site.ai_publish {
            validate_path_no_control(Path::new(&publish.storage), "site.ai-publish.storage")?;
        }
        for route in &site.routes {
            if let Some(root) = &route.root {
                validate_path_no_control(Path::new(root), "route.root")?;
            }
            if let RouteHandler::FastCgi(fcgi) = &route.handler
                && let FastCgiTarget::Unix { path } = &fcgi.target
            {
                validate_path_no_control(Path::new(path), "route.fastcgi-pass")?;
            }
        }
    }
    Ok(())
}

/// Writes every machine-readable writable-set record line through [`SanitizingLineWriter`] and
/// flushes `out`, propagating both write and flush errors so truncated output can never report
/// exit code 0.
pub(crate) fn write_writable_set_lines<W: io::Write>(out: W, lines: &[String]) -> io::Result<()> {
    let mut writer = SanitizingLineWriter::new(out);
    for line in lines {
        writer.write_line(line)?;
    }
    writer.flush()
}

/// Strips the Windows `\\?\` verbatim drive prefix produced by `std::fs::canonicalize` when it
/// wraps an ordinary drive path (`\\?\C:\...` -> `C:\...`).
#[cfg(windows)]
fn strip_windows_verbatim_prefix(path: &Path) -> PathBuf {
    if let Some(s) = path.to_str()
        && let Some(rest) = s.strip_prefix(r"\\?\")
        && !rest.starts_with("UNC\\")
    {
        return PathBuf::from(rest);
    }
    path.to_path_buf()
}

/// Normalizes a candidate writable path into a clean absolute lexical path without probing the
/// host filesystem (aside from reading `current_dir()` for relative paths). Refuses any control
/// character or non-UTF-8 bytes so machine-readable lines stay unambiguous.
pub(crate) fn lexical_absolute_writable_path(raw: &Path, label: &str) -> Result<String, String> {
    let _ = validate_path_no_control(raw, label)?;
    let abs = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        let cwd = std::env::current_dir().map_err(|err| {
            format!("cannot resolve relative {label} without a current working directory: {err}")
        })?;
        let _ = validate_path_no_control(&cwd, "current working directory")?;
        cwd.join(raw)
    };

    let mut norm = PathBuf::new();
    for comp in abs.components() {
        match comp {
            Component::Prefix(p) => norm.push(p.as_os_str()),
            Component::RootDir => norm.push(std::path::MAIN_SEPARATOR_STR),
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(norm.components().next_back(), Some(Component::Normal(_))) {
                    norm.pop();
                }
            }
            Component::Normal(seg) => norm.push(seg),
        }
    }

    #[cfg(windows)]
    let norm = strip_windows_verbatim_prefix(&norm);

    let clean = validate_path_no_control(&norm, label)?;
    if !Path::new(&clean).is_absolute() {
        return Err(format!(
            "resolved {label} is not an absolute path: \"{}\"",
            clean.escape_debug()
        ));
    }
    Ok(clean)
}

fn load_from_arg(path: &PathBuf) -> Result<LoadedConfig, ConfigError> {
    if path.as_os_str() == "-" {
        let mut raw = Vec::new();
        let mut limited = io::stdin().take(MAX_CONFIG_FILE_BYTES.saturating_add(1));
        limited
            .read_to_end(&mut raw)
            .map_err(|source| ConfigError::Io {
                path: PathBuf::from("<stdin>"),
                source,
            })?;
        if (raw.len() as u64) > MAX_CONFIG_FILE_BYTES {
            return Err(ConfigError::FileTooLarge {
                path: PathBuf::from("<stdin>"),
                actual_bytes: raw.len() as u64,
                max_bytes: MAX_CONFIG_FILE_BYTES,
            });
        }
        let text = String::from_utf8(raw).map_err(|utf8_err| ConfigError::Io {
            path: PathBuf::from("<stdin>"),
            source: io::Error::new(io::ErrorKind::InvalidData, utf8_err),
        })?;
        parse_kdl_detailed("<stdin>", &text)
    } else {
        load_file_detailed(path)
    }
}

#[allow(clippy::too_many_lines)]
fn handle_valid(loaded: &LoadedConfig, args: &CheckArgs) -> ExitCode {
    if args.writable_set
        && let Err(msg) = validate_writable_set_config_inputs(&loaded.config)
    {
        let mut stderr = SanitizingLineWriter::new(io::stderr().lock());
        let _ = stderr.write_line(&format!("error: {msg}"));
        return ExitCode::FAILURE;
    }

    let mut filtered_warnings: Vec<ConfigIssue> = loaded
        .report
        .warnings
        .iter()
        .filter(|w| !(args.dev_tls && w.code == "W015"))
        .cloned()
        .collect();

    // R4-SBX-2: Surface sandbox policy warnings (such as refused unsafe roots) during `check` too!
    let cfg_path_opt = if args.config.as_os_str() == "-" {
        None
    } else {
        Some(args.config.as_path())
    };
    // Built from the configuration with unusable or escaping tenant roots already isolated (as
    // the server builds it), so one account's roots do not each produce a warning here; those
    // sites are reported once each by the `--fs` checks.
    let mut policy_config = loaded.config.clone();
    if args.writable_set {
        if let Err(err) =
            miraserve_core::quarantine_inaccessible_tenant_roots_for_inspection(&mut policy_config)
        {
            let mut stderr = SanitizingLineWriter::new(io::stderr().lock());
            let _ = stderr.write_line(&format!("error: {err}"));
            return ExitCode::FAILURE;
        }
    } else {
        miraserve_core::quarantine_inaccessible_tenant_roots(&mut policy_config);
    }
    // Without `--fs` (whose checks report them), each site isolated here is still reported, so
    // `--strict` never passes a configuration whose server would isolate a site.
    if !args.fs {
        for (index, site) in policy_config.sites.iter().enumerate() {
            if let Some(reason) = &site.quarantine {
                // The field the classification recorded (never guessed from the text).
                let key_path = site.quarantine_field.as_ref().map_or_else(
                    || format!("site[{index}]"),
                    |field| format!("site[{index}].{field}"),
                );
                let host = site.hosts.first().map_or("<site>", String::as_str);
                filtered_warnings.push(ConfigIssue {
                    code: "W026".to_owned(),
                    severity: Severity::Warning,
                    message: format!("tenant site '{host}' will answer 503: {reason}"),
                    path: Some(key_path.clone()),
                    help: None,
                    label: None,
                    location: loaded.location_for(&key_path),
                });
            }
        }
    }
    // Drop the preliminary policy (and every descriptor it opened) immediately after reading its
    // warnings so later `--fs` checks and the `--writable-set` startup pass hold no extra file
    // descriptors compared to `miraserve run` (Codex Round-3 P1 #1).
    let sbx_warnings = {
        let sbx_policy = SandboxPolicy::from_config_with_file(
            &policy_config,
            cfg_path_opt,
            args.acme_dir.as_deref(),
        );
        sbx_policy.warnings
    };
    for (n, w) in sbx_warnings.into_iter().enumerate() {
        // The configuration key is looked up for the first warnings only (bounded work).
        let key_path = (n < 64)
            .then(|| docroot_key_for_message(&loaded.config, &w))
            .flatten()
            .unwrap_or_else(|| "server.sandbox".to_owned());
        filtered_warnings.push(ConfigIssue {
            code: "W017".to_owned(),
            severity: Severity::Warning,
            message: w,
            path: Some(key_path.clone()),
            help: Some(
                "configure site roots and state directories outside restricted system roots"
                    .to_owned(),
            ),
            label: None,
            location: loaded.location_for(&key_path),
        });
    }

    // CFG-6, R4-PKG-2, R5-CHK-1, R7-CHK-1 & R7-SBX-2: Optional `--fs` disk readability,
    // symlink/overlap docroot confinement (`E301`), & PEM/pair/keyd verification.
    let (fs_errors, classified_for_notes, socket_access_status): (
        Vec<ConfigIssue>,
        Option<Config>,
        FastCgiSocketAccessNotes,
    ) = if args.fs {
        let (issues, _, classified, sock_notes) = collect_filesystem_issues_classified(
            loaded,
            cfg_path_opt,
            args.acme_dir.as_deref(),
            args.keyd_auth_secret_file.as_deref(),
        );
        (issues, Some(classified), sock_notes)
    } else {
        (Vec::new(), None, FastCgiSocketAccessNotes::default())
    };

    // `--fs` findings that the server tolerates at runtime are warnings, not errors.
    let (fs_errors, fs_warnings): (Vec<ConfigIssue>, Vec<ConfigIssue>) = fs_errors
        .into_iter()
        .partition(|issue| issue.severity == Severity::Error);
    filtered_warnings.extend(fs_warnings);

    #[cfg(target_os = "linux")]
    if args.fs && loaded.config.server.sandbox.landlock && !args.no_sandbox {
        let probe = miraserve_core::probe_landlock_availability();
        let req = miraserve_core::LANDLOCK_MIN_REQUIRED_ABI_VERSION;
        filtered_warnings.extend(landlock_availability_warning(&probe, req, loaded));
    }

    let trusted_path_notes = if args.trusted_paths {
        #[cfg(target_os = "linux")]
        {
            crate::trusted_paths::check(&mut filtered_warnings, loaded, args)
        }
        #[cfg(not(target_os = "linux"))]
        vec!["--trusted-paths is Linux-only; no paths were verified".into()]
    } else {
        Vec::new()
    };

    let warning_count = filtered_warnings.len();
    let error_count = fs_errors.len();
    // Warnings that count against `--strict`: all except the explicitly allowed codes.
    let blocking_warning_count = filtered_warnings
        .iter()
        .filter(|w| {
            !args
                .allow_warning
                .iter()
                .any(|code| code.eq_ignore_ascii_case(&w.code))
        })
        .count();
    let failed = error_count > 0 || (args.strict && blocking_warning_count > 0);
    let route_count: usize = loaded.config.sites.iter().map(|s| s.routes.len()).sum();

    let summary = CheckSummary {
        listeners: loaded.config.server.listeners.len(),
        sites: loaded.config.sites.len(),
        routes: route_count,
        tls_min_version: loaded.config.server.tls.min_version.to_string(),
        pqc_hybrid: loaded.config.server.tls.pqc_hybrid,
        warnings: warning_count,
        errors: error_count,
    };

    let mut notes: Vec<String> = trusted_path_notes.clone();
    let has_http_listener = loaded
        .config
        .server
        .listeners
        .iter()
        .any(|l| l.redirect_https);
    if has_http_listener {
        let plain_http_hosts: Vec<&str> = loaded
            .config
            .sites
            .iter()
            .filter(|s| s.http == SiteHttpMode::Serve)
            .flat_map(|s| s.hosts.iter().map(String::as_str))
            .collect();
        if !plain_http_hosts.is_empty() {
            notes.push(format!(
                "sites served over plain HTTP: {}",
                plain_http_hosts.join(", ")
            ));
        }
    }
    if let Some(note) = precompressed_enabled_note(&loaded.config) {
        notes.push(note);
    }
    if let Some(classified) = &classified_for_notes {
        notes.extend(collect_precompressed_fs_notes(classified));
    }
    notes.extend(collect_file_cache_notes(&loaded.config));
    let socket_access_notes = socket_access_status.into_note_lines();
    notes.extend(socket_access_notes.iter().cloned());
    let config_for_advisory = classified_for_notes.as_ref().unwrap_or(&loaded.config);
    if let Some(note) = miraserve_core::openat2_refused_advisory(config_for_advisory) {
        notes.push(note);
    }

    match args.format {
        OutputFormat::Json => {
            let report = JsonCheckReport {
                valid: !failed,
                strict: args.strict,
                source: loaded.source_name.clone(),
                summary: Some(summary),
                errors: fs_errors,
                warnings: filtered_warnings,
                notes,
                io_error: None,
                config: if args.dump_normalized {
                    Some(&loaded.config)
                } else {
                    None
                },
            };
            write_json_report(&report);
        }
        OutputFormat::Text => {
            let handler = make_report_handler();
            {
                let mut stderr = io::stderr().lock();
                for (issue, diag) in loaded
                    .report
                    .warnings
                    .iter()
                    .zip(loaded.warning_diagnostics())
                {
                    if args.dev_tls && issue.code == "W015" {
                        continue;
                    }
                    let mut buf = String::new();
                    if handler.render_report(&mut buf, &diag).is_ok() {
                        if args.writable_set {
                            let _ = SanitizingLineWriter::new(&mut stderr).write_multiline(&buf);
                        } else {
                            let _ = writeln!(stderr, "{buf}");
                        }
                    } else if args.writable_set {
                        let _ = SanitizingLineWriter::new(&mut stderr)
                            .write_line(&format!("warning: {diag}"));
                    } else {
                        let _ = writeln!(stderr, "warning: {diag}");
                    }
                }
                for extra_warn in filtered_warnings.iter().filter(|w| {
                    matches!(
                        w.code.as_str(),
                        "W017"
                            | "W023"
                            | "W024"
                            | "W026"
                            | "W027"
                            | "W028"
                            | "W029"
                            | "W030"
                            | "W033"
                            | "W034"
                            | "W035"
                    )
                }) {
                    let san =
                        args.writable_set || matches!(extra_warn.code.as_str(), "W034" | "W035");
                    if san {
                        let _ = SanitizingLineWriter::new(&mut stderr).write_line(&format!(
                            "warning[{}]: {}",
                            extra_warn.code, extra_warn.message
                        ));
                    } else {
                        let _ = writeln!(
                            stderr,
                            "warning[{}]: {}",
                            extra_warn.code, extra_warn.message
                        );
                    }
                    if matches!(extra_warn.code.as_str(), "W033" | "W034" | "W035")
                        && let Some(help) = &extra_warn.help
                    {
                        if san {
                            let _ = SanitizingLineWriter::new(&mut stderr)
                                .write_line(&format!("  help: {help}"));
                        } else {
                            let _ = writeln!(stderr, "  help: {help}");
                        }
                    }
                }
                // P2 #6: Print the root / indeterminate FastCGI socket access notes in text mode
                // on failed runs too, once each, after the warnings.
                if failed || args.writable_set || args.quiet {
                    write_tp_notes(&mut stderr, &trusted_path_notes);
                }
                if failed {
                    for note in &socket_access_notes {
                        if args.writable_set {
                            let _ = SanitizingLineWriter::new(&mut stderr)
                                .write_line(&format!("note: {note}"));
                        } else {
                            let _ = writeln!(stderr, "note: {note}");
                        }
                    }
                }
                for fs_err in &fs_errors {
                    if args.writable_set {
                        let _ = SanitizingLineWriter::new(&mut stderr)
                            .write_line(&format!("error[{}]: {}", fs_err.code, fs_err.message));
                    } else {
                        let _ = writeln!(stderr, "error[{}]: {}", fs_err.code, fs_err.message);
                    }
                }
            }

            if error_count > 0 {
                let msg = format!(
                    "FAILED: '{}' failed --fs check with {error_count} filesystem error(s) and {warning_count} warning(s)",
                    loaded.source_name
                );
                if args.writable_set {
                    let mut stderr = SanitizingLineWriter::new(io::stderr().lock());
                    let _ = stderr.write_line(&msg);
                } else {
                    let mut stderr = io::stderr().lock();
                    let _ = writeln!(stderr, "{msg}");
                }
            } else if args.strict && blocking_warning_count > 0 {
                let msg = format!(
                    "error: configuration '{}' failed --strict check due to {blocking_warning_count} security warning(s) not covered by --allow-warning",
                    loaded.source_name
                );
                if args.writable_set {
                    let mut stderr = SanitizingLineWriter::new(io::stderr().lock());
                    let _ = stderr.write_line(&msg);
                } else {
                    let mut stderr = io::stderr().lock();
                    let _ = writeln!(stderr, "{msg}");
                }
            } else if args.writable_set {
                // Build the startup SandboxPolicy through the exact same quarantine, policy, and
                // CLI log-binding pipeline `miraserve run` executes, without creating directories,
                // opening log files, or installing any Landlock ruleset, while failing cleanly on
                // OS resource exhaustion (`EMFILE`, `ENFILE`, `ENOMEM`).
                let mut startup_cfg = loaded.config.clone();
                let startup_inputs = crate::run::StartupPolicyInputs {
                    config_path: cfg_path_opt,
                    acme_dir: args.acme_dir.as_deref(),
                    log_file: args.log_file.as_deref(),
                    access_log: args.access_log.as_deref(),
                    log_max_bytes: args.log_max_bytes,
                    keyd_auth_secret_file: args.keyd_auth_secret_file.as_deref(),
                    no_sandbox: args.no_sandbox,
                };
                let prepared = match crate::run::prepare_runtime_startup_policy_for_inspection(
                    &mut startup_cfg,
                    &startup_inputs,
                ) {
                    Ok(prepared) => prepared,
                    Err(violations) => {
                        let mut stderr = SanitizingLineWriter::new(io::stderr().lock());
                        for violation in violations {
                            let _ = stderr.write_line(&format!("error: {violation}"));
                        }
                        return ExitCode::FAILURE;
                    }
                };
                // Enforce documented hard rejections for explicit writable directories (including
                // forbidden `--acme-dir` such as `/etc` and cleanly spelled `ai-publish.storage`
                // symlinks pointing to forbidden directories that `insert_exact_dir` otherwise
                // filters with only a W017 warning).
                if let Err(err) = miraserve_core::validate_writable_candidates_for_inspection(
                    &startup_cfg,
                    prepared.effective_acme_dir.as_deref(),
                ) {
                    let mut stderr = SanitizingLineWriter::new(io::stderr().lock());
                    let _ = stderr.write_line(&format!("error: {err}"));
                    return ExitCode::FAILURE;
                }
                // Codex Round-2/3 P2 (ACME): validate the effective ACME directory unconditionally
                // with the exact side-effect-free no-follow, ancestor-safety, and ownership check
                // `run` uses (even if `insert_exact_dir` filtered it out).
                if let Some(acme_dir) = prepared.effective_acme_dir.as_deref()
                    && let Err(err) = miraserve_tls::validate_private_dir_read_only(acme_dir)
                {
                    let mut stderr = SanitizingLineWriter::new(io::stderr().lock());
                    let _ = stderr.write_line(&format!(
                        "error: failed to validate required writable directory '{}': {err}",
                        acme_dir.display()
                    ));
                    return ExitCode::FAILURE;
                }
                let resource_failures = prepared.policy.resource_failure_grants();
                if !resource_failures.is_empty() {
                    let mut stderr = SanitizingLineWriter::new(io::stderr().lock());
                    let _ = stderr.write_line(&format!(
                        "error: sandbox policy inspection hit OS resource limit: {}",
                        resource_failures.join("; ")
                    ));
                    return ExitCode::FAILURE;
                }
                let policy_rejections = prepared.policy.policy_rejection_failures();
                if !policy_rejections.is_empty() {
                    let mut stderr = SanitizingLineWriter::new(io::stderr().lock());
                    let _ = stderr.write_line(&format!(
                        "error: cannot validate sandbox grants: {}",
                        policy_rejections.join("; ")
                    ));
                    return ExitCode::FAILURE;
                }
                let enforcement = miraserve_core::probe_landlock_enforcement(&prepared.policy);
                let mut lines: Vec<String> = vec![enforcement.state_line()];
                if enforcement.is_enforcing() {
                    let grants = match prepared.policy.writable_policy_grants() {
                        Ok(grants) => grants,
                        Err(err) => {
                            let mut stderr = SanitizingLineWriter::new(io::stderr().lock());
                            let _ = stderr.write_line(&format!("error: {err}"));
                            return ExitCode::FAILURE;
                        }
                    };
                    let mut existing_paths: BTreeSet<String> = BTreeSet::new();
                    let mut missing_paths: BTreeSet<String> = BTreeSet::new();
                    for grant in grants {
                        match grant {
                            WritableGrant::Installed(path) => {
                                match validate_path_no_control(&path, "Landlock writable path") {
                                    Ok(clean) => {
                                        existing_paths.insert(clean);
                                    }
                                    Err(msg) => {
                                        let mut stderr =
                                            SanitizingLineWriter::new(io::stderr().lock());
                                        let _ = stderr.write_line(&format!("error: {msg}"));
                                        return ExitCode::FAILURE;
                                    }
                                }
                            }
                            WritableGrant::Missing(raw_path) => {
                                match lexical_absolute_writable_path(
                                    &raw_path,
                                    "Landlock writable path",
                                ) {
                                    Ok(clean) => {
                                        missing_paths.insert(clean);
                                    }
                                    Err(msg) => {
                                        let mut stderr =
                                            SanitizingLineWriter::new(io::stderr().lock());
                                        let _ = stderr.write_line(&format!("error: {msg}"));
                                        return ExitCode::FAILURE;
                                    }
                                }
                            }
                        }
                    }
                    // Superset rule (Codex Round-3 P1 #1 / Round-4 item 3c): ANY site that
                    // classification quarantined must still have its candidate writable paths
                    // reported (as `writable-missing landlock <path>` if not already installed),
                    // because `run` on a healthier moment may grant them. Evaluated without
                    // opening any extra grant descriptors.
                    for site in startup_cfg
                        .sites
                        .iter()
                        .filter(|site| site.quarantine.is_some())
                    {
                        if let Some(publish) = &site.ai_publish {
                            let p = Path::new(&publish.storage);
                            match miraserve_core::is_quarantined_publish_storage_candidate(
                                p,
                                &loaded.config.server.allow_docroots,
                            ) {
                                Ok(true) => {
                                    match lexical_absolute_writable_path(
                                        p,
                                        "Landlock writable path",
                                    ) {
                                        Ok(clean) => {
                                            missing_paths.insert(clean);
                                        }
                                        Err(msg) => {
                                            let mut stderr =
                                                SanitizingLineWriter::new(io::stderr().lock());
                                            let _ = stderr.write_line(&format!("error: {msg}"));
                                            return ExitCode::FAILURE;
                                        }
                                    }
                                }
                                Ok(false) => {}
                                Err(err) => {
                                    let mut stderr = SanitizingLineWriter::new(io::stderr().lock());
                                    let _ = stderr.write_line(&format!("error: {err}"));
                                    return ExitCode::FAILURE;
                                }
                            }
                        }
                        for route in &site.routes {
                            if let RouteHandler::FastCgi(fcgi) = &route.handler
                                && let FastCgiTarget::Unix { path } = &fcgi.target
                            {
                                let p = Path::new(path);
                                if miraserve_core::is_quarantined_socket_candidate(p) {
                                    match lexical_absolute_writable_path(
                                        p,
                                        "Landlock writable path",
                                    ) {
                                        Ok(clean) => {
                                            missing_paths.insert(clean);
                                        }
                                        Err(msg) => {
                                            let mut stderr =
                                                SanitizingLineWriter::new(io::stderr().lock());
                                            let _ = stderr.write_line(&format!("error: {msg}"));
                                            return ExitCode::FAILURE;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    missing_paths.retain(|p| !existing_paths.contains(p));
                    for path in existing_paths {
                        lines.push(format!("writable landlock {path}"));
                    }
                    for path in missing_paths {
                        lines.push(format!("writable-missing landlock {path}"));
                    }
                }
                if let Err(err) = write_writable_set_lines(io::stdout().lock(), &lines) {
                    let mut stderr = SanitizingLineWriter::new(io::stderr().lock());
                    let _ = stderr.write_line(&format!(
                        "error: failed to write writable-set output: {err}"
                    ));
                    return ExitCode::FAILURE;
                }
            } else if !args.quiet {
                let mut stdout = io::stdout().lock();
                let pqc_label = if summary.pqc_hybrid {
                    "X25519MLKEM768 enabled"
                } else {
                    "disabled"
                };
                let _ = writeln!(
                    stdout,
                    "OK: '{}' is valid ({} listener(s), {} site(s), {} route(s), TLS >= {}, PQC: {}, {} warning(s))",
                    loaded.source_name,
                    summary.listeners,
                    summary.sites,
                    summary.routes,
                    summary.tls_min_version,
                    pqc_label,
                    summary.warnings,
                );
                write_tp_notes(&mut stdout, &trusted_path_notes);
                for note in notes.iter().skip(trusted_path_notes.len()) {
                    let _ = writeln!(stdout, "note: {note}");
                }
            }

            if args.dump_normalized
                && !failed
                && let Ok(pretty) = serde_json::to_string_pretty(&loaded.config)
            {
                let mut stdout = io::stdout().lock();
                let _ = writeln!(stdout, "{pretty}");
            }
        }
    }

    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Maximum directory entries inspected per site in total during `check --fs` sibling detection.
const MAX_PRECOMPRESSED_SCAN_ENTRIES: usize = 2_000;

/// Bounds for the informational enabled-sites note so output stays `O(1)` even on huge configs.
const MAX_ENABLED_NOTE_SITES: usize = 32;
const MAX_ENABLED_NOTE_ALIASES: usize = 3;
const MAX_ENABLED_NOTE_ROUTES: usize = 8;
const MAX_ENABLED_NOTE_BYTES: usize = 2_048;
const ENABLED_NOTE_PREFIX: &str = "sites that configure `precompressed`: ";
const MAX_FS_NOTE_PATTERN_BYTES: usize = 128;

/// Truncates `s` to at most `max_bytes` UTF-8 bytes, appending `"..."` when truncated and
/// `max_bytes >= 3`.
fn truncate_utf8_with_ellipsis(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_owned();
    }
    if max_bytes < 3 {
        let mut end = max_bytes;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        return s.get(..end).unwrap_or("").to_owned();
    }
    let mut end = max_bytes - 3;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::with_capacity(end + 3);
    out.push_str(s.get(..end).unwrap_or(""));
    out.push_str("...");
    out
}

fn omitted_sites_suffix(omitted: usize) -> String {
    if omitted > 0 {
        format!(", +{omitted} more site(s)")
    } else {
        String::new()
    }
}

fn format_grouped_site_hosts(hosts: &[String]) -> String {
    let Some((primary, aliases)) = hosts.split_first() else {
        return "<site>".to_owned();
    };
    if aliases.is_empty() {
        return primary.clone();
    }
    let shown: Vec<&str> = aliases
        .iter()
        .take(MAX_ENABLED_NOTE_ALIASES)
        .map(String::as_str)
        .collect();
    let hidden = aliases.len().saturating_sub(shown.len());
    if hidden > 0 {
        format!("{primary} [aliases: {}, +{hidden} more]", shown.join(", "))
    } else {
        format!("{primary} [aliases: {}]", shown.join(", "))
    }
}

/// Builds the informational note listing each site whose configuration turns `precompressed` on
/// (a summary of the configuration, not a statement that some request will probe a sibling)
/// once (grouping host aliases and strictly bounding the complete note — prefix, entries,
/// separators, and omission suffix — to [`MAX_ENABLED_NOTE_BYTES`]), or `None` when none enable
/// it.
fn precompressed_enabled_note(config: &Config) -> Option<String> {
    let mut raw_entries: Vec<String> = Vec::new();
    let mut total_enabled_sites = 0_usize;

    for site in &config.sites {
        let summary = if site.precompressed.any() {
            Some(site.precompressed.display_summary())
        } else {
            let mut route_summaries: Vec<String> = Vec::new();
            let mut total_routes = 0_usize;
            for route in &site.routes {
                // A route with compression off never probes a sibling, whatever its policy says.
                if let RouteHandler::Static(st) = &route.handler
                    && st.compression
                    && st.precompressed.any()
                {
                    total_routes += 1;
                    if route_summaries.len() < MAX_ENABLED_NOTE_ROUTES {
                        route_summaries.push(format!(
                            "{}: {}",
                            route.pattern,
                            st.precompressed.display_summary()
                        ));
                    }
                }
            }
            if total_routes == 0 {
                None
            } else {
                let hidden = total_routes.saturating_sub(route_summaries.len());
                if hidden > 0 {
                    route_summaries.push(format!("+{hidden} more"));
                }
                Some(route_summaries.join("; "))
            }
        };

        let Some(summary) = summary else {
            continue;
        };
        total_enabled_sites += 1;
        if raw_entries.len() < MAX_ENABLED_NOTE_SITES {
            let host_label = format_grouped_site_hosts(&site.hosts);
            raw_entries.push(format!("{host_label} ({summary})"));
        }
    }

    if total_enabled_sites == 0 {
        return None;
    }

    let mut included: Vec<String> = Vec::new();
    let mut body_bytes = 0_usize;
    for (idx, entry) in raw_entries.into_iter().enumerate() {
        let omitted_after = total_enabled_sites.saturating_sub(idx.saturating_add(1));
        let suffix_len = omitted_sites_suffix(omitted_after).len();
        if idx == 0 {
            let max_first = MAX_ENABLED_NOTE_BYTES
                .saturating_sub(ENABLED_NOTE_PREFIX.len())
                .saturating_sub(suffix_len);
            let fitted = truncate_utf8_with_ellipsis(&entry, max_first);
            body_bytes = fitted.len();
            included.push(fitted);
        } else {
            let needed = ENABLED_NOTE_PREFIX
                .len()
                .saturating_add(body_bytes)
                .saturating_add(2)
                .saturating_add(entry.len())
                .saturating_add(suffix_len);
            if needed > MAX_ENABLED_NOTE_BYTES {
                break;
            }
            body_bytes = body_bytes.saturating_add(2).saturating_add(entry.len());
            included.push(entry);
        }
    }

    let omitted = total_enabled_sites.saturating_sub(included.len());
    let suffix = omitted_sites_suffix(omitted);
    let note = format!("{ENABLED_NOTE_PREFIX}{}{suffix}", included.join(", "));
    debug_assert!(note.len() <= MAX_ENABLED_NOTE_BYTES);
    Some(note)
}

fn normalize_root_key(root: &str) -> &str {
    let trimmed = root.trim_end_matches(['/', '\\']);
    if trimmed.is_empty() { root } else { trimmed }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OffLocation {
    /// The site block itself (`site.root`).
    Site,
    /// A `static` route (`site.routes[idx]`).
    Route(usize),
}

/// Evaluates the simple determinate rule for a candidate file URL under `root_key`:
/// - Only the site block itself and `RouteHandler::Static` routes are considered.
/// - Routes with `try-files`, fixed status (`respond`), `redirect`, `reverse-proxy`,
///   `mcp-gateway`, `wasm-plugin`, or `fastcgi-pass` are NOT inferred about and do NOT suppress
///   the note for the site's own root.
/// - A matching `static` route with `compression #false`, an enabled `precompressed` policy, or a
///   different effective root suppresses the note for URLs it matches; otherwise it reports
///   `OffLocation::Route(idx)`.
/// - When exact and ASCII case-insensitive static-route matches disagree, returns `None`.
fn direct_url_off_location(site: &SiteConfig, root_key: &str, url: &str) -> Option<OffLocation> {
    let classify = |matched: Option<(usize, &RouteConfig)>| -> Option<OffLocation> {
        match matched {
            Some((idx, route)) => {
                let RouteHandler::Static(st) = &route.handler else {
                    return None;
                };
                let eff_root = route
                    .root
                    .as_deref()
                    .or(site.root.as_deref())
                    .map(normalize_root_key);
                if eff_root != Some(root_key) || !st.compression {
                    return None;
                }
                let policy = if st.precompressed_explicit {
                    st.precompressed
                } else {
                    site.precompressed
                };
                policy.is_off().then_some(OffLocation::Route(idx))
            }
            None => {
                if site.ai_publish.is_none()
                    && site.root.as_deref().map(normalize_root_key) == Some(root_key)
                    && site.precompressed.is_off()
                {
                    Some(OffLocation::Site)
                } else {
                    None
                }
            }
        }
    };

    let exact = classify(
        site.routes
            .iter()
            .enumerate()
            .filter(|(_, r)| matches!(r.handler, RouteHandler::Static(_)))
            .find(|(_, r)| route_pattern_matches(&r.pattern, url)),
    )?;
    let lower_url = url.to_ascii_lowercase();
    let ci = classify(
        site.routes
            .iter()
            .enumerate()
            .filter(|(_, r)| matches!(r.handler, RouteHandler::Static(_)))
            .find(|(_, r)| route_pattern_matches(&r.pattern.to_ascii_lowercase(), &lower_url)),
    )?;
    (exact == ci).then_some(exact)
}

/// Scans non-quarantined sites for `.zst`/`.br`/`.gz` sibling files in the top two directory
/// levels of determinate static locations where `precompressed` is off (`check --fs` only),
/// bounded to [`MAX_PRECOMPRESSED_SCAN_ENTRIES`] entries per site in total.
///
/// Emits a factual note stating only what exists on disk and which location has `precompressed`
/// off — never advising that enabling `precompressed` would serve the sibling.
#[allow(clippy::too_many_lines)]
fn collect_precompressed_fs_notes(classified: &Config) -> Vec<String> {
    let mut notes = Vec::new();

    for site in &classified.sites {
        if site.quarantine.is_some() {
            continue;
        }
        let host = site.hosts.first().map_or("<site>", String::as_str);

        // Determine whether this site has determinate static locations with `precompressed` off
        // (and whether any determinate static location enables `precompressed`).
        let mut any_off =
            site.root.is_some() && site.ai_publish.is_none() && site.precompressed.is_off();
        let mut any_on =
            site.root.is_some() && site.ai_publish.is_none() && site.precompressed.any();
        for route in &site.routes {
            if let RouteHandler::Static(st) = &route.handler
                && st.compression
            {
                let eff_policy = if st.precompressed_explicit {
                    st.precompressed
                } else {
                    site.precompressed
                };
                if eff_policy.is_off() {
                    any_off = true;
                } else {
                    any_on = true;
                }
            }
        }
        if !any_off {
            continue;
        }

        // If internal rewrite rules can dynamically transform paths between static locations with
        // different effective `precompressed` policies, emit no note for this site.
        let has_internal_rewrite = site
            .rewrites
            .iter()
            .any(|rule| matches!(rule.action, RewriteAction::Internal { .. }));
        if has_internal_rewrite && any_on {
            continue;
        }

        // Collect every distinct static root serving at least one determinate `"off"` location.
        let mut roots_to_scan: Vec<&str> = Vec::new();
        let mut seen_keys: Vec<&str> = Vec::new();
        if site.precompressed.is_off()
            && site.ai_publish.is_none()
            && let Some(root) = site.root.as_deref()
        {
            let key = normalize_root_key(root);
            if !seen_keys.contains(&key) {
                seen_keys.push(key);
                roots_to_scan.push(root);
            }
        }
        for route in &site.routes {
            if let RouteHandler::Static(st) = &route.handler
                && st.compression
            {
                let route_off = if st.precompressed_explicit {
                    st.precompressed.is_off()
                } else {
                    site.precompressed.is_off()
                };
                if route_off && let Some(root) = route.root.as_deref().or(site.root.as_deref()) {
                    let key = normalize_root_key(root);
                    if !seen_keys.contains(&key) {
                        seen_keys.push(key);
                        roots_to_scan.push(root);
                    }
                }
            }
        }

        let mut remaining = MAX_PRECOMPRESSED_SCAN_ENTRIES;
        for root in roots_to_scan {
            if remaining == 0 {
                break;
            }
            let root_key = normalize_root_key(root);
            let mut site_found = [false; 3];
            let mut route_found: Vec<(usize, [bool; 3])> = Vec::new();

            miraserve_core::scan_precompressed_siblings_no_follow(
                Path::new(root),
                &mut remaining,
                |url, ext_idx| {
                    let Some(loc) = direct_url_off_location(site, root_key, url) else {
                        return;
                    };
                    match loc {
                        OffLocation::Site => {
                            if let Some(slot) = site_found.get_mut(ext_idx) {
                                *slot = true;
                            }
                        }
                        OffLocation::Route(route_idx) => {
                            if let Some((_, arr)) =
                                route_found.iter_mut().find(|(i, _)| *i == route_idx)
                            {
                                if let Some(slot) = arr.get_mut(ext_idx) {
                                    *slot = true;
                                }
                            } else {
                                let mut arr = [false; 3];
                                if let Some(slot) = arr.get_mut(ext_idx) {
                                    *slot = true;
                                }
                                route_found.push((route_idx, arr));
                            }
                        }
                    }
                },
            );

            let site_exts = format_found_extensions(site_found);
            if !site_exts.is_empty() {
                notes.push(format!(
                    "site '{host}': files with {} siblings exist under '{root}' and \
                     `precompressed` is off for the site",
                    site_exts.join("/")
                ));
            }
            route_found.sort_by_key(|(route_idx, _)| *route_idx);
            for (route_idx, arr) in route_found {
                let exts = format_found_extensions(arr);
                if !exts.is_empty()
                    && let Some(route) = site.routes.get(route_idx)
                {
                    let pat =
                        truncate_utf8_with_ellipsis(&route.pattern, MAX_FS_NOTE_PATTERN_BYTES);
                    // An abbreviated pattern is not a name: say so and give the route's position,
                    // so that it cannot be read as another route whose pattern it happens to spell.
                    let label = if pat.len() == route.pattern.len() {
                        format!("route '{pat}'")
                    } else {
                        format!(
                            "route #{} of the site (pattern abbreviated: '{pat}')",
                            route_idx.saturating_add(1)
                        )
                    };
                    notes.push(format!(
                        "site '{host}': files with {} siblings exist under '{root}' and \
                         `precompressed` is off for {label}",
                        exts.join("/")
                    ));
                }
            }
        }
    }

    notes
}

fn format_found_extensions(found: [bool; 3]) -> Vec<&'static str> {
    let [zst, br, gz] = found;
    let mut out = Vec::with_capacity(3);
    if zst {
        out.push(".zst");
    }
    if br {
        out.push(".br");
    }
    if gz {
        out.push(".gz");
    }
    out
}

fn docroot_key_for_site(site: &miraserve_config::SiteConfig, site_idx: usize, msg: &str) -> String {
    for (route_idx, route) in site.routes.iter().enumerate() {
        if let Some(root) = &route.root
            && msg.contains(&format!("'{root}'"))
        {
            return format!("site[{site_idx}].route[{route_idx}].root");
        }
    }
    if site.root.is_some() {
        format!("site[{site_idx}].root")
    } else {
        format!("site[{site_idx}]")
    }
}

fn docroot_key_for_message(config: &Config, msg: &str) -> Option<String> {
    for (site_idx, site) in config.sites.iter().enumerate() {
        for (route_idx, route) in site.routes.iter().enumerate() {
            if let Some(root) = &route.root
                && msg.contains(&format!("'{root}'"))
            {
                return Some(format!("site[{site_idx}].route[{route_idx}].root"));
            }
        }
        if let Some(root) = &site.root
            && msg.contains(&format!("'{root}'"))
        {
            return Some(format!("site[{site_idx}].root"));
        }
    }
    None
}

fn push_fs_error(
    errors: &mut Vec<ConfigIssue>,
    loaded: &LoadedConfig,
    key_path: &str,
    message: String,
) {
    errors.push(ConfigIssue {
        code: "E301".to_owned(),
        severity: Severity::Error,
        message,
        path: Some(key_path.to_owned()),
        help: None,
        label: None,
        location: loaded.location_for(key_path),
    });
}

fn check_readable_file(
    errors: &mut Vec<ConfigIssue>,
    loaded: &LoadedConfig,
    key_path: &str,
    label: &str,
    path_str: &str,
) {
    let p = Path::new(path_str);
    // Never block: a FIFO or device at this path would stall the check (and with it service
    // start or reload). Look at the type first, then open without blocking.
    let opened = std::fs::metadata(p).and_then(|md| {
        if !md.is_file() {
            return Ok(md);
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(rustix::fs::OFlags::NONBLOCK.bits().cast_signed());
        }
        options.open(p).and_then(|f| f.metadata())
    });
    match opened {
        Ok(md) if md.is_file() && md.len() > 0 => {}
        Ok(md) if md.is_file() => {
            push_fs_error(
                errors,
                loaded,
                key_path,
                format!("{label} '{path_str}' is empty (0 bytes)"),
            );
        }
        Ok(_) => push_fs_error(
            errors,
            loaded,
            key_path,
            format!("{label} '{path_str}' is not a regular file"),
        ),
        Err(err) => push_fs_error(
            errors,
            loaded,
            key_path,
            format!("{label} '{path_str}' is missing or unreadable: {err}"),
        ),
    }
}

fn check_readable_dir(
    errors: &mut Vec<ConfigIssue>,
    loaded: &LoadedConfig,
    key_path: &str,
    label: &str,
    path_str: &str,
) {
    let p = Path::new(path_str);
    // The same test the server applies when it opens a root: open the directory and enter it
    // (search permission). Listing it is not needed, so a search-only root passes.
    if let Err(err) =
        miraserve_core::open_root_probe(p).and_then(|()| fs::metadata(p.join(".")).map(|_| ()))
    {
        push_fs_error(
            errors,
            loaded,
            key_path,
            format!("{label} directory '{path_str}' is missing or unreadable: {err}"),
        );
    }
}

fn check_writable_dir(
    errors: &mut Vec<ConfigIssue>,
    loaded: &LoadedConfig,
    key_path: &str,
    label: &str,
    path: &Path,
) {
    // R6-CHK-1: A bare relative path like `.miraserve-acme` has `parent() == Some("")`, which
    // means the current working directory (`.`), NOT a missing parent!
    let target = if path.exists() {
        path
    } else if let Some(parent) = path.parent() {
        let resolved_parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        if resolved_parent.exists() {
            resolved_parent
        } else {
            push_fs_error(
                errors,
                loaded,
                key_path,
                format!(
                    "{label} directory '{}' does not exist and its parent is missing",
                    path.display()
                ),
            );
            return;
        }
    } else {
        push_fs_error(
            errors,
            loaded,
            key_path,
            format!(
                "{label} directory '{}' does not exist and its parent is missing",
                path.display()
            ),
        );
        return;
    };

    let probe = target.join(format!(".miraserve-check-fs-probe-{}", std::process::id()));
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(f) => {
            drop(f);
            let _ = fs::remove_file(&probe);
        }
        Err(err) => push_fs_error(
            errors,
            loaded,
            key_path,
            format!(
                "{label} directory '{}' is not writable by the current user: {err}",
                path.display()
            ),
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn check_tls_cert_and_key(
    errors: &mut Vec<ConfigIssue>,
    loaded: &LoadedConfig,
    key_prefix: &str,
    label: &str,
    cert_opt: Option<&str>,
    key_opt: Option<&str>,
    is_split: bool,
    provider: &miraserve_tls::CryptoProvider,
) {
    let cert_key = format!("{key_prefix}.cert");
    let key_key = format!("{key_prefix}.key");
    match (cert_opt, key_opt) {
        (Some(cert), Some(key)) if !is_split => {
            check_readable_file(errors, loaded, &cert_key, &format!("{label}.cert"), cert);
            check_readable_file(errors, loaded, &key_key, &format!("{label}.key"), key);
            if let Err(err) = miraserve_tls::load_certified_key_from_files(cert, key, provider) {
                push_fs_error(
                    errors,
                    loaded,
                    key_prefix,
                    format!(
                        "{label} certificate/key pair ('{cert}', '{key}') is invalid or mismatched: {err}"
                    ),
                );
            }
        }
        (Some(cert), _) => {
            check_readable_file(errors, loaded, &cert_key, &format!("{label}.cert"), cert);
            if let Err(err) = miraserve_tls::inspect_cert_file(cert) {
                push_fs_error(
                    errors,
                    loaded,
                    &cert_key,
                    format!("{label}.cert '{cert}' failed X.509 PEM parsing: {err}"),
                );
            }
        }
        (None, Some(key)) if !is_split => {
            check_readable_file(errors, loaded, &key_key, &format!("{label}.key"), key);
        }
        _ => {}
    }
}

fn check_client_ca_bundle(
    errors: &mut Vec<ConfigIssue>,
    loaded: &LoadedConfig,
    key_path: &str,
    label: &str,
    ca_path: &str,
    pqc: bool,
) {
    check_readable_file(errors, loaded, key_path, label, ca_path);
    if let Err(err) = miraserve_tls::ClientCertTrust::from_pem_file(ca_path, pqc) {
        push_fs_error(
            errors,
            loaded,
            key_path,
            format!("{label} '{ca_path}' failed CA PEM parsing: {err}"),
        );
    }
}

fn check_keyd_socket_accessible(
    errors: &mut Vec<ConfigIssue>,
    loaded: &LoadedConfig,
    socket_spec: &str,
    auth_secret_file: Option<&Path>,
) {
    let key_path = "server.tls.keyd-socket";
    let endpoint = match miraserve_tls::KeydEndpoint::parse(socket_spec) {
        Ok(ep) => ep,
        Err(err) => {
            push_fs_error(
                errors,
                loaded,
                key_path,
                format!("server.tls.keyd-socket '{socket_spec}' is invalid: {err}"),
            );
            return;
        }
    };
    #[cfg(unix)]
    if let miraserve_tls::KeydEndpoint::Unix(ref sock_path) = endpoint {
        use std::os::unix::fs::FileTypeExt as _;
        match fs::metadata(sock_path) {
            Ok(md) if md.file_type().is_socket() => {}
            Ok(_) => {
                push_fs_error(
                    errors,
                    loaded,
                    key_path,
                    format!(
                        "server.tls.keyd-socket '{}' is not a Unix domain socket",
                        sock_path.display()
                    ),
                );
                return;
            }
            Err(err) => {
                push_fs_error(
                    errors,
                    loaded,
                    key_path,
                    format!(
                        "server.tls.keyd-socket '{}' is missing or inaccessible: {err}",
                        sock_path.display()
                    ),
                );
                return;
            }
        }
    }
    // R6-CHK-1 & R7-CHK-1: Perform a real bounded `ListCerts` protocol probe instead of a bare
    // `connect()`, honoring `--keyd-auth-secret-file` (matching `miraserve run`) before env fallback.
    let client_res = if let Some(secret_path) = auth_secret_file {
        miraserve_tls::load_keyd_auth_secret_file(secret_path)
            .map(|secret| miraserve_tls::KeydClient::with_auth_secret(endpoint, *secret))
    } else {
        miraserve_tls::KeydClient::from_env(endpoint)
    };
    let client = match client_res {
        Ok(c) => c.with_io_timeout(std::time::Duration::from_secs(2)),
        Err(err) => {
            push_fs_error(
                errors,
                loaded,
                key_path,
                format!("server.tls.keyd-socket '{socket_spec}' auth configuration failed: {err}"),
            );
            return;
        }
    };
    if let Err(err) = client.probe_access() {
        push_fs_error(
            errors,
            loaded,
            key_path,
            format!(
                "server.tls.keyd-socket '{socket_spec}' failed keyd protocol/peer authorization probe: {err}"
            ),
        );
    }
}

/// Classifies document roots on a clone of `config` using the same quarantine sequence as the
/// server (`quarantine_inaccessible_tenant_roots`, then `quarantine_unsafe_sites`), returning the
/// classified configuration and any remaining non-quarantined docroot violations.
pub(crate) fn classify_docroots(
    config: &Config,
    config_path: Option<&Path>,
    acme_dir: Option<&Path>,
    keyd_auth_secret_file: Option<&Path>,
) -> (Config, Vec<String>) {
    let is_split = config.server.tls.key_isolation == KeyIsolation::SplitDaemon;
    let effective_acme = acme_dir.or_else(|| {
        (config.server.tls.acme.is_some() && !is_split).then_some(Path::new(".miraserve-acme"))
    });
    let secret_file_paths: Vec<PathBuf> = keyd_auth_secret_file
        .map(Path::to_path_buf)
        .into_iter()
        .collect();
    // Classify exactly as the server does: tenant sites (owner-dir) whose own roots fail are
    // quarantined (W026, the service still starts); everything else refuses it (E301).
    let docroot_checks = |cfg: &Config| {
        miraserve_core::find_unsafe_docroots_with_secret_files(
            cfg,
            config_path,
            effective_acme,
            &secret_file_paths,
        )
    };
    let mut classified = config.clone();
    miraserve_core::quarantine_inaccessible_tenant_roots(&mut classified);
    let remaining = miraserve_core::quarantine_unsafe_sites(&mut classified, docroot_checks);
    (classified, remaining)
}

/// Extracts a machine-readable report of every quarantined tenant site in `classified`.
pub(crate) fn quarantined_site_reports(classified: &Config) -> Vec<QuarantinedSiteReport> {
    classified
        .sites
        .iter()
        .enumerate()
        .filter_map(|(index, site)| {
            let reason = site.quarantine.as_ref()?;
            let first_host = site
                .hosts
                .first()
                .map_or("<site>", String::as_str)
                .to_owned();
            Some(QuarantinedSiteReport {
                site: first_host,
                index,
                code: "W026".to_owned(),
                reason: reason.clone(),
            })
        })
        .collect()
}

/// Plain informational notes recorded while checking FastCGI Unix socket access (`check --fs`).
#[derive(Debug, Default)]
struct FastCgiSocketAccessNotes {
    #[cfg(unix)]
    skipped_as_root: bool,
    #[cfg(unix)]
    skipped_ids_differ: bool,
    #[cfg(unix)]
    indeterminate_errors: BTreeSet<String>,
}

impl FastCgiSocketAccessNotes {
    #[cfg(unix)]
    fn into_note_lines(self) -> Vec<String> {
        let mut lines = Vec::new();
        if self.skipped_as_root {
            lines.push(
                "FastCGI Unix socket access for the service account was not tested because the \
                 check runs as root (euid 0)"
                    .to_owned(),
            );
        }
        if self.skipped_ids_differ {
            lines.push(
                "FastCGI Unix socket access could not be tested because the real and effective \
                 ids of the checking process differ"
                    .to_owned(),
            );
        }
        for err_desc in self.indeterminate_errors {
            lines.push(format!(
                "FastCGI Unix socket access could not be tested: {err_desc}"
            ));
        }
        lines
    }

    #[cfg(not(unix))]
    const fn into_note_lines(self) -> Vec<String> {
        Vec::new()
    }
}

#[cfg(unix)]
fn format_access_errno(err: rustix::io::Errno) -> String {
    let sym = match err {
        rustix::io::Errno::PERM => Some("EPERM"),
        rustix::io::Errno::NOSYS => Some("ENOSYS"),
        rustix::io::Errno::INVAL => Some("EINVAL"),
        rustix::io::Errno::ROFS => Some("EROFS"),
        rustix::io::Errno::LOOP => Some("ELOOP"),
        rustix::io::Errno::NOENT => Some("ENOENT"),
        rustix::io::Errno::NOTDIR => Some("ENOTDIR"),
        rustix::io::Errno::OPNOTSUPP => Some("EOPNOTSUPP"),
        _ => None,
    };
    match sym {
        Some(name) => format!("faccessat failed with {name} ({err})"),
        None => format!("faccessat failed ({err})"),
    }
}

/// Checks whether an existing exact FastCGI Unix socket is reachable and grants read + write
/// permission to the account running the check without calling `connect()` (`W033`).
///
/// Uses the classic `faccessat(..., R_OK | W_OK, 0)` call (never `AT_EACCESS` / `faccessat2`)
/// when real and effective UID and GID are equal. When real and effective IDs differ, when
/// running as root (`euid 0`), or when `faccessat` returns any error other than `EACCES`, emits
/// no `W033` and records a plain informational note in `notes` instead.
#[cfg(unix)]
fn check_fastcgi_unix_socket_accessible(
    errors: &mut Vec<ConfigIssue>,
    notes: &mut FastCgiSocketAccessNotes,
    loaded: &LoadedConfig,
    key_path: &str,
    site_host: &str,
    sock_path: &str,
) {
    check_fastcgi_unix_socket_accessible_with(
        errors,
        notes,
        loaded,
        key_path,
        site_host,
        sock_path,
        rustix::process::getuid().as_raw(),
        rustix::process::geteuid().as_raw(),
        rustix::process::getgid().as_raw(),
        rustix::process::getegid().as_raw(),
        |p| {
            rustix::fs::accessat(
                rustix::fs::CWD,
                p,
                rustix::fs::Access::READ_OK | rustix::fs::Access::WRITE_OK,
                rustix::fs::AtFlags::empty(),
            )
        },
    );
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn check_fastcgi_unix_socket_accessible_with<F>(
    errors: &mut Vec<ConfigIssue>,
    notes: &mut FastCgiSocketAccessNotes,
    loaded: &LoadedConfig,
    key_path: &str,
    site_host: &str,
    sock_path: &str,
    real_uid: u32,
    effective_uid: u32,
    real_group: u32,
    effective_group: u32,
    probe: F,
) where
    F: FnOnce(&Path) -> Result<(), rustix::io::Errno>,
{
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

    let p = Path::new(sock_path);
    let md = match fs::metadata(p) {
        Ok(md) => md,
        Err(io_err) => {
            // `EACCES` on `metadata` means a parent directory cannot be searched by the checking
            // account, so the socket path cannot be reached at all (type and owner unknown).
            // `ENOENT` and every other error keep 0.1.5 behaviour (no output).
            if io_err.raw_os_error() == Some(rustix::io::Errno::ACCESS.raw_os_error()) {
                errors.push(ConfigIssue {
                    code: "W033".to_owned(),
                    severity: Severity::Warning,
                    message: format!(
                        "site '{site_host}' FastCGI Unix socket '{sock_path}' could not be \
                         reached (type and owner unknown); the socket must be reachable (search \
                         permission on its parent directories) and requires read and write \
                         permission on the socket for the account running the check \
                         (uid/gid {effective_uid}/{effective_group}): {io_err}",
                    ),
                    path: Some(key_path.to_owned()),
                    help: Some(
                        "grant search permission on parent directories of the socket, set \
                         `listen.group` of the pool to the server's group, or add the server \
                         account to the socket's group"
                            .to_owned(),
                    ),
                    label: None,
                    location: loaded.location_for(key_path),
                });
            }
            return;
        }
    };
    if !md.file_type().is_socket() {
        // Existing non-socket path: no new output here.
        return;
    }
    if real_uid != effective_uid || real_group != effective_group {
        notes.skipped_ids_differ = true;
        return;
    }
    if effective_uid == 0 {
        notes.skipped_as_root = true;
        return;
    }
    match probe(p) {
        Ok(()) => {}
        Err(err @ rustix::io::Errno::ACCESS) => {
            let owner_uid = md.uid();
            let owner_group = md.gid();
            let sock_mode = md.mode() & 0o7777;
            errors.push(ConfigIssue {
                code: "W033".to_owned(),
                severity: Severity::Warning,
                message: format!(
                    "site '{site_host}' FastCGI Unix socket '{sock_path}' \
                     (owner {owner_uid}:{owner_group}, mode {sock_mode:04o}) requires read and \
                     write permission on the socket for the account running the check \
                     (uid/gid {effective_uid}/{effective_group}): {err}",
                ),
                path: Some(key_path.to_owned()),
                help: Some(
                    "set `listen.group` of the pool to the server's group, or add the server \
                     account to the socket's group"
                        .to_owned(),
                ),
                label: None,
                location: loaded.location_for(key_path),
            });
        }
        Err(other) => {
            notes
                .indeterminate_errors
                .insert(format_access_errno(other));
        }
    }
}

#[cfg(not(unix))]
const fn check_fastcgi_unix_socket_accessible(
    _errors: &mut Vec<ConfigIssue>,
    _notes: &mut FastCgiSocketAccessNotes,
    _loaded: &LoadedConfig,
    _key_path: &str,
    _site_host: &str,
    _sock_path: &str,
) {
}

pub(crate) fn collect_filesystem_issues_and_quarantined(
    loaded: &LoadedConfig,
    config_path: Option<&Path>,
    acme_dir: Option<&Path>,
    keyd_auth_secret_file: Option<&Path>,
) -> (Vec<ConfigIssue>, Vec<QuarantinedSiteReport>) {
    let (issues, quarantined, _, _) =
        collect_filesystem_issues_classified(loaded, config_path, acme_dir, keyd_auth_secret_file);
    (issues, quarantined)
}

#[allow(clippy::too_many_lines)]
fn collect_filesystem_issues_classified(
    loaded: &LoadedConfig,
    config_path: Option<&Path>,
    acme_dir: Option<&Path>,
    keyd_auth_secret_file: Option<&Path>,
) -> (
    Vec<ConfigIssue>,
    Vec<QuarantinedSiteReport>,
    Config,
    FastCgiSocketAccessNotes,
) {
    let config = &loaded.config;
    let mut errors = Vec::new();
    let mut socket_access_notes = FastCgiSocketAccessNotes::default();
    let is_split = config.server.tls.key_isolation == KeyIsolation::SplitDaemon;
    let provider = miraserve_tls::build_crypto_provider(config.server.tls.pqc_hybrid);

    check_tls_cert_and_key(
        &mut errors,
        loaded,
        "server.tls",
        "server.tls",
        config.server.tls.cert.as_deref(),
        config.server.tls.key.as_deref(),
        is_split,
        &provider,
    );
    if let Some(ca) = &config.server.tls.client_ca {
        check_client_ca_bundle(
            &mut errors,
            loaded,
            "server.tls.client-ca",
            "server.tls.client-ca",
            ca,
            config.server.tls.pqc_hybrid,
        );
    }
    if is_split {
        let sock = config
            .server
            .tls
            .keyd_socket
            .as_deref()
            .unwrap_or("/run/miraserve-keyd/keyd.sock");
        check_keyd_socket_accessible(&mut errors, loaded, sock, keyd_auth_secret_file);
    }
    if config.server.tls.acme.is_some() && !is_split {
        let state_dir = acme_dir.unwrap_or_else(|| Path::new(".miraserve-acme"));
        check_writable_dir(
            &mut errors,
            loaded,
            "server.tls.acme",
            "server.tls.acme state",
            state_dir,
        );
    }
    // Directories holding credentials, and the ACME challenge directory, must not be
    // replaceable by an account other than root through a writable parent directory.
    {
        let mut guarded: Vec<(String, std::path::PathBuf)> = Vec::new();
        if let Some(webroot) = &config.server.acme_webroot {
            guarded.push((
                "server.acme-webroot".to_owned(),
                // A token inside it: the check covers the challenge directory and every parent.
                Path::new(webroot)
                    .join(".well-known")
                    .join("acme-challenge")
                    .join("token"),
            ));
        }
        for (i, site) in config.sites.iter().enumerate() {
            if let Some(auth) = &site.basic_auth {
                guarded.push((
                    format!("site[{i}].basic-auth"),
                    PathBuf::from(&auth.users_file),
                ));
            }
        }
        let mut seen = std::collections::HashSet::new();
        for (key, path) in guarded {
            let Some(parent) = path.parent().map(Path::to_path_buf) else {
                continue;
            };
            if !seen.insert(parent) {
                continue;
            }
            if let Some(problem) = miraserve_core::replaceable_ancestor(&path) {
                let mut issues = Vec::new();
                push_fs_error(
                    &mut issues,
                    loaded,
                    &key,
                    format!(
                        "'{}' could be replaced by an account other than root: {problem}; keep \
                         every parent directory root-owned and not group/other-writable",
                        path.display()
                    ),
                );
                for mut issue in issues {
                    "W029".clone_into(&mut issue.code);
                    issue.severity = Severity::Warning;
                    errors.push(issue);
                }
            }
        }
    }
    // Credential files whose names sit in the challenge directory are never answered there
    // (the same rule the server applies); say so, they are probably misplaced.
    if let Some(webroot) = &config.server.acme_webroot {
        // The same credential list the server uses, plus the command-line secret.
        let mut credentials = miraserve_core::configured_credential_paths(config);
        credentials.extend(keyd_auth_secret_file.map(Path::to_path_buf));
        let reserved = miraserve_core::reserved_acme_tokens(
            &Path::new(webroot)
                .join(".well-known")
                .join("acme-challenge"),
            &credentials,
        );
        if !reserved.is_empty() {
            let mut names: Vec<&String> = reserved.iter().collect();
            names.sort();
            let mut issues = Vec::new();
            push_fs_error(
                &mut issues,
                loaded,
                "server.acme-webroot",
                format!(
                    "credential files are named inside the acme-webroot challenge directory \
                     ({}); those names are never answered there, move the credentials elsewhere",
                    names
                        .iter()
                        .map(|n| n.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            );
            for mut issue in issues {
                "W030".clone_into(&mut issue.code);
                issue.severity = Severity::Warning;
                errors.push(issue);
            }
        }
    }
    // The external ACME client's webroot must exist before start-up: the sandbox grants only
    // what exists then, and tokens written into a later-created directory cannot be read.
    if let Some(webroot) = &config.server.acme_webroot
        && !Path::new(webroot).is_dir()
    {
        let mut issues = Vec::new();
        push_fs_error(
            &mut issues,
            loaded,
            "server.acme-webroot",
            format!(
                "acme-webroot '{webroot}' does not exist; create it (and its \
                 .well-known/acme-challenge directory, owned by root) before starting MiraServe, \
                 or HTTP-01 tokens written there cannot be served until a restart"
            ),
        );
        for mut issue in issues {
            "W028".clone_into(&mut issue.code);
            issue.severity = Severity::Warning;
            errors.push(issue);
        }
    }
    // R6-SBX-1, R7-SBX-1, R7-SBX-2 & Section 5: Refuse as hard E301 errors any HTTP document
    // root that resolves via symlink into a forbidden/default-denied directory (e.g. `/etc`)
    // OR overlaps the effective ACME state dir, config dir, TLS private keys, or publish stores!
    let (classified, remaining) =
        classify_docroots(config, config_path, acme_dir, keyd_auth_secret_file);
    let quarantined = quarantined_site_reports(&classified);
    for (site_idx, site) in classified.sites.iter().enumerate() {
        if let Some(reason) = &site.quarantine {
            // The field the classification recorded; for isolation found by the overlap checks
            // (no recorded field), the root the message names.
            let key_path = site.quarantine_field.as_ref().map_or_else(
                || {
                    config.sites.get(site_idx).map_or_else(
                        || format!("site[{site_idx}]"),
                        |orig| docroot_key_for_site(orig, site_idx, reason),
                    )
                },
                |field| format!("site[{site_idx}].{field}"),
            );
            let mut issues = Vec::new();
            push_fs_error(
                &mut issues,
                loaded,
                &key_path,
                format!("{reason}; that site will return 503 Service Unavailable"),
            );
            for mut issue in issues {
                "W026".clone_into(&mut issue.code);
                issue.severity = Severity::Warning;
                errors.push(issue);
            }
        }
    }
    // What remains after quarantine refuses the configuration on the server, so it stays an
    // error here whatever site its text mentions (added after the tenant downgrade below).
    let mut server_wide_errors = Vec::new();
    for violation in remaining {
        let key_path =
            docroot_key_for_message(config, &violation).unwrap_or_else(|| "server".to_owned());
        push_fs_error(&mut server_wide_errors, loaded, &key_path, violation);
    }

    let mut users_files: std::collections::HashMap<(u64, u64), PathBuf> =
        std::collections::HashMap::new();
    for (site_idx, site) in classified.sites.iter().enumerate() {
        // A quarantined site serves nothing: its routes and files are not checked (the server
        // does not use them), so they cannot stop the service for everyone.
        if site.quarantine.is_some() {
            continue;
        }
        let site_prefix = format!("site[{site_idx}]");
        let host = site.hosts.first().map_or("<site>", String::as_str);
        if let Some(root) = &site.root {
            // HANDOVER §5 #9: Missing or unreadable tenant-owned site roots isolate ONLY that site
            // to 503 at runtime (unsafe symlink/overlap violations are still hard E301 above).
            let mut root_issues = Vec::new();
            let root_key = format!("{site_prefix}.root");
            check_readable_dir(
                &mut root_issues,
                loaded,
                &root_key,
                &format!("site '{host}' root"),
                root,
            );
            for mut issue in root_issues {
                "W023".clone_into(&mut issue.code);
                issue.severity = Severity::Warning;
                issue.message.push_str(
                    "; that site's requests fail until it is fixed (503 when the directory \
                         cannot be opened, otherwise 404 for each file that cannot be read)",
                );
                errors.push(issue);
            }
        }
        if let Some(tls) = &site.tls {
            let site_pqc = tls.pqc_hybrid.unwrap_or(config.server.tls.pqc_hybrid);
            let site_provider = miraserve_tls::build_crypto_provider(site_pqc);
            let tls_key = format!("{site_prefix}.tls");
            check_tls_cert_and_key(
                &mut errors,
                loaded,
                &tls_key,
                &format!("site '{host}' tls"),
                tls.cert.as_deref(),
                tls.key.as_deref(),
                is_split,
                &site_provider,
            );
            if let Some(ca) = &tls.client_ca {
                check_client_ca_bundle(
                    &mut errors,
                    loaded,
                    &format!("{tls_key}.client-ca"),
                    &format!("site '{host}' tls.client-ca"),
                    ca,
                    site_pqc,
                );
            }
        }
        if let Some(bot) = &site.bot_auth
            && let Some(kf) = &bot.agent_keys_file
        {
            check_readable_file(
                &mut errors,
                loaded,
                &format!("{site_prefix}.bot-auth.agent-keys-file"),
                &format!("site '{host}' agent-keys-file"),
                kf,
            );
        }
        if let Some(pub_cfg) = &site.ai_publish {
            check_writable_dir(
                &mut errors,
                loaded,
                &format!("{site_prefix}.ai-publish.storage"),
                &format!("site '{host}' ai-publish.storage"),
                Path::new(&pub_cfg.storage),
            );
            if let Some(sig) = &pub_cfg.require_signature {
                check_readable_file(
                    &mut errors,
                    loaded,
                    &format!("{site_prefix}.ai-publish.require-signature"),
                    &format!("site '{host}' ai-publish.require-signature"),
                    &sig.public_key_path,
                );
            }
            if let Some(pk) = &pub_cfg.jwt_public_key
                && let Some(path) = pk.strip_prefix("ed25519:")
            {
                check_readable_file(
                    &mut errors,
                    loaded,
                    &format!("{site_prefix}.ai-publish.jwt-public-key"),
                    &format!("site '{host}' ai-publish.jwt-public-key"),
                    path,
                );
            }
        }
        // `basic-auth` users files: the server refuses to load a configuration whose file is
        // missing, unreadable or holds a hash it cannot check, so say so here first, with the
        // file and line (never the hash).
        let auth_areas = site
            .basic_auth
            .iter()
            .map(|auth| (format!("{site_prefix}.basic-auth"), auth))
            .chain(site.routes.iter().enumerate().filter_map(|(idx, route)| {
                route
                    .basic_auth
                    .as_ref()
                    .map(|auth| (format!("{site_prefix}.route[{idx}].basic-auth"), auth))
            }));
        for (key, auth) in auth_areas {
            let path = PathBuf::from(&auth.users_file);
            // As the server loads it: the place first, then the file, one name per file.
            let problem = miraserve_core::credential_file_problem_for(
                &path,
                miraserve_core::server_account_uid(config),
            )
            .or_else(|| {
                let (raw, file) = match miraserve_core::read_no_symlink_file_opened(
                    &path,
                    miraserve_config::MAX_HTPASSWD_BYTES,
                    &[],
                ) {
                    Ok(opened) => opened,
                    Err(err) => return Some(err),
                };
                let identities = miraserve_core::handle_identities(std::slice::from_ref(&file));
                let Some(identity) = identities.first() else {
                    return Some("its identity cannot be read".to_owned());
                };
                let first = users_files.entry(*identity).or_insert_with(|| path.clone());
                if *first != path {
                    return Some(miraserve_core::users_file_alias_problem(first));
                }
                match String::from_utf8(raw) {
                    Err(_) => Some("not UTF-8 text".to_owned()),
                    Ok(text) => match miraserve_config::parse_htpasswd(&text) {
                        Err(err) => Some(err),
                        // A valid but empty file locks everyone out of the site.
                        Ok(users) => users.is_empty().then(|| EMPTY_USERS_FILE.to_owned()),
                    },
                }
            });
            // As configured, no link followed: an operator mistake, refused everywhere.
            let inside_served_root = config
                .sites
                .iter()
                .flat_map(|s| {
                    s.root
                        .iter()
                        .chain(s.routes.iter().filter_map(|r| r.root.as_ref()))
                })
                .any(|root| {
                    let root = Path::new(root);
                    let users = Path::new(&auth.users_file);
                    users.starts_with(root)
                });
            if inside_served_root {
                push_fs_error(
                    &mut errors,
                    loaded,
                    &key,
                    format!(
                        "site '{host}' basic-auth users file '{}' is inside a served document \
                         root and could be downloaded; move it outside every site root",
                        auth.users_file
                    ),
                );
                continue;
            }
            if let Some(problem) = problem {
                // Only this area is affected (it answers 503), so service start and reload go
                // ahead for every other site; `check --strict` still fails on it.
                let mut issues = Vec::new();
                push_fs_error(
                    &mut issues,
                    loaded,
                    &key,
                    if problem == EMPTY_USERS_FILE {
                        // A valid empty file loads: everyone gets the 401 challenge.
                        format!(
                            "site '{host}' basic-auth users file '{}': {problem}",
                            auth.users_file
                        )
                    } else {
                        format!(
                            "site '{host}' basic-auth users file '{}': {problem}; that protected \
                             area will return 503 Service Unavailable",
                            auth.users_file
                        )
                    },
                );
                for mut issue in issues {
                    // W024: the site answers 503 (the file cannot be loaded). W027: a valid
                    // empty file loads and everyone gets the 401 challenge.
                    if problem == EMPTY_USERS_FILE {
                        "W027"
                    } else {
                        "W024"
                    }
                    .clone_into(&mut issue.code);
                    issue.severity = Severity::Warning;
                    errors.push(issue);
                }
            }
        }
        if let Some(ep) = &site.error_pages {
            for (&status, page_path) in &ep.pages {
                let resolved = if Path::new(page_path).is_absolute() {
                    PathBuf::from(page_path)
                } else if let Some(root) = &site.root {
                    Path::new(root).join(page_path)
                } else {
                    PathBuf::from(page_path)
                };
                // Not an error: the server falls back to its built-in page (the file belongs
                // to the site owner and may disappear at any time). Reported as a warning.
                let ep_key = format!("{site_prefix}.error-pages.page.{status}");
                let label = format!("site '{host}' error-pages.{status}");
                let mut page_issues = Vec::new();
                check_readable_file(
                    &mut page_issues,
                    loaded,
                    &ep_key,
                    &label,
                    &resolved.display().to_string(),
                );
                // HANDOVER §5 #10: For an absolute page outside the site root, check EVERY path
                // component from root down to the leaf for symlinks (not only the final component).
                let abs_inside_root = Path::new(page_path).is_absolute()
                    && site
                        .root
                        .as_deref()
                        .and_then(|root| resolved.strip_prefix(root).ok())
                        .is_some();
                if page_issues.is_empty()
                    && Path::new(page_path).is_absolute()
                    && !abs_inside_root
                    && let Some(sym) = miraserve_core::find_symlink_component(&resolved)
                {
                    push_fs_error(
                        &mut page_issues,
                        loaded,
                        &ep_key,
                        format!(
                            "{label} '{}' traverses symbolic link '{}'",
                            resolved.display(),
                            sym.display()
                        ),
                    );
                }
                if page_issues.is_empty()
                    && (!Path::new(page_path).is_absolute() || abs_inside_root)
                    && let Some(root) = &site.root
                    && let (Ok(real_root), Ok(real_page)) =
                        (fs::canonicalize(root), fs::canonicalize(&resolved))
                    && !real_page.starts_with(&real_root)
                {
                    push_fs_error(
                        &mut page_issues,
                        loaded,
                        &ep_key,
                        format!(
                            "{label} '{}' is a symlink that leaves the site root (resolves to '{}')",
                            resolved.display(),
                            real_page.display()
                        ),
                    );
                }
                for mut issue in page_issues {
                    "W023".clone_into(&mut issue.code);
                    issue.severity = Severity::Warning;
                    issue
                        .message
                        .push_str("; the built-in error page will be used");
                    errors.push(issue);
                }
            }
        }
        for (route_idx, route) in site.routes.iter().enumerate() {
            let route_prefix = format!("{site_prefix}.route[{route_idx}]");
            if let Some(r_root) = &route.root {
                let mut route_root_issues = Vec::new();
                check_readable_dir(
                    &mut route_root_issues,
                    loaded,
                    &format!("{route_prefix}.root"),
                    &format!("site '{host}' route '{}' root", route.pattern),
                    r_root,
                );
                for mut issue in route_root_issues {
                    "W023".clone_into(&mut issue.code);
                    issue.severity = Severity::Warning;
                    issue.message.push_str(
                        "; that route's requests fail until it is fixed (503 when the \
                             directory cannot be opened, otherwise 404 for each file that cannot \
                             be read)",
                    );
                    errors.push(issue);
                }
            }
            match &route.handler {
                RouteHandler::WasmPlugin(w) => {
                    let mut wasm_issues = Vec::new();
                    check_readable_file(
                        &mut wasm_issues,
                        loaded,
                        &format!("{route_prefix}.wasm-plugin"),
                        &format!("site '{host}' route '{}' wasm-plugin", route.pattern),
                        &w.module_path,
                    );
                    for mut issue in wasm_issues {
                        "W023".clone_into(&mut issue.code);
                        issue.severity = Severity::Warning;
                        issue.message.push_str(
                            "; that route's requests fail until it is fixed (503 when the \
                             directory cannot be opened, otherwise 404 for each file that cannot \
                             be read)",
                        );
                        errors.push(issue);
                    }
                }
                RouteHandler::ReverseProxy(rp) => {
                    if let Some(utls) = &rp.upstream_tls {
                        if let Some(p) = &utls.ca_cert {
                            check_readable_file(
                                &mut errors,
                                loaded,
                                &format!("{route_prefix}.reverse-proxy.upstream-tls.ca-cert"),
                                &format!(
                                    "site '{host}' route '{}' upstream-tls.ca-cert",
                                    route.pattern
                                ),
                                p,
                            );
                        }
                        if let Some(p) = &utls.client_cert {
                            check_readable_file(
                                &mut errors,
                                loaded,
                                &format!("{route_prefix}.reverse-proxy.upstream-tls.client-cert"),
                                &format!(
                                    "site '{host}' route '{}' upstream-tls.client-cert",
                                    route.pattern
                                ),
                                p,
                            );
                        }
                        if let Some(p) = &utls.client_key {
                            check_readable_file(
                                &mut errors,
                                loaded,
                                &format!("{route_prefix}.reverse-proxy.upstream-tls.client-key"),
                                &format!(
                                    "site '{host}' route '{}' upstream-tls.client-key",
                                    route.pattern
                                ),
                                p,
                            );
                        }
                    }
                }
                RouteHandler::McpGateway(mcp) => {
                    if let Some(pk) = &mcp.jwt_public_key
                        && let Some(path) = pk.strip_prefix("ed25519:")
                    {
                        check_readable_file(
                            &mut errors,
                            loaded,
                            &format!("{route_prefix}.mcp-gateway.jwt-public-key"),
                            &format!(
                                "site '{host}' route '{}' mcp-gateway.jwt-public-key",
                                route.pattern
                            ),
                            path,
                        );
                    }
                }
                RouteHandler::FastCgi(fcgi) => {
                    if let FastCgiTarget::Unix { path } = &fcgi.target {
                        check_fastcgi_unix_socket_accessible(
                            &mut errors,
                            &mut socket_access_notes,
                            loaded,
                            &format!("{route_prefix}.fastcgi-pass"),
                            host,
                            path,
                        );
                    }
                }
                RouteHandler::Static(_)
                | RouteHandler::TryFiles(_)
                | RouteHandler::Redirect(_)
                | RouteHandler::Respond(_) => {}
            }
        }
    }

    // A tenant site's (owner-dir) own dependency problems isolate that site at runtime (it
    // answers 503, the rest loads), so they do not stop the service here either: report them as
    // W026 (still an error with `--strict`). Other sites' problems stay errors.
    for issue in &mut errors {
        let tenant = issue
            .path
            .as_deref()
            .and_then(|key| key.strip_prefix("site["))
            .and_then(|rest| rest.split(']').next())
            .and_then(|index| index.parse::<usize>().ok())
            .and_then(|index| config.sites.get(index))
            .is_some_and(|site| site.owner_dir.is_some());
        if tenant && issue.severity == Severity::Error {
            "W026".clone_into(&mut issue.code);
            issue.severity = Severity::Warning;
            issue
                .message
                .push_str("; that site will return 503 Service Unavailable");
        }
    }
    errors.extend(server_wide_errors);
    (errors, quarantined, classified, socket_access_notes)
}

fn handle_error(err: &ConfigError, args: &CheckArgs) -> ExitCode {
    let err_notes: Vec<String> = if !args.trusted_paths {
        Vec::new()
    } else if cfg!(target_os = "linux") {
        let m = "configuration could not be loaded or is invalid; no paths were verified";
        vec![format!("trusted-paths: {m}")]
    } else {
        vec!["--trusted-paths is Linux-only; no paths were verified".into()]
    };
    match args.format {
        OutputFormat::Json => {
            let (source, io_error) = match err {
                ConfigError::Validation { source_name, .. } => (source_name.clone(), None),
                ConfigError::Io { path, .. } | ConfigError::FileTooLarge { path, .. } => {
                    (path.display().to_string(), Some(err.to_string()))
                }
            };
            let report = JsonCheckReport {
                valid: false,
                strict: args.strict,
                source,
                summary: None,
                errors: err.validation_errors().to_vec(),
                warnings: err.validation_warnings().to_vec(),
                notes: err_notes,
                io_error,
                config: None,
            };
            write_json_report(&report);
        }
        OutputFormat::Text => {
            let mut stderr = io::stderr().lock();
            match err {
                ConfigError::Io { .. } | ConfigError::FileTooLarge { .. } => {
                    if args.writable_set {
                        let _ = SanitizingLineWriter::new(&mut stderr)
                            .write_line(&format!("error: {err}"));
                    } else {
                        let _ = writeln!(stderr, "error: {err}");
                    }
                }
                ConfigError::Validation {
                    source_name,
                    errors,
                    warnings,
                    ..
                } => {
                    let handler = make_report_handler();
                    for diag in err.diagnostics() {
                        let mut buf = String::new();
                        if handler.render_report(&mut buf, &diag).is_ok() {
                            if args.writable_set {
                                let _ =
                                    SanitizingLineWriter::new(&mut stderr).write_multiline(&buf);
                            } else {
                                let _ = writeln!(stderr, "{buf}");
                            }
                        } else if args.writable_set {
                            let _ = SanitizingLineWriter::new(&mut stderr)
                                .write_line(&format!("error: {diag}"));
                        } else {
                            let _ = writeln!(stderr, "error: {diag}");
                        }
                    }
                    let summary = format!(
                        "FAILED: '{}' has {} error(s) and {} warning(s)",
                        source_name,
                        errors.len(),
                        warnings.len(),
                    );
                    if args.writable_set {
                        let _ = SanitizingLineWriter::new(&mut stderr).write_line(&summary);
                    } else {
                        let _ = writeln!(stderr, "{summary}");
                    }
                }
            }
            write_tp_notes(&mut stderr, &err_notes);
        }
    }

    ExitCode::FAILURE
}

fn write_tp_notes(w: impl io::Write, notes: &[String]) {
    let mut san = SanitizingLineWriter::new(w);
    for note in notes {
        let _ = san.write_line(&format!("note: {note}"));
    }
}

fn write_json_report(report: &JsonCheckReport<'_>) {
    let mut stdout = io::stdout().lock();
    if let Ok(json) = serde_json::to_string_pretty(report) {
        let _ = writeln!(stdout, "{json}");
    }
}

fn make_report_handler() -> GraphicalReportHandler {
    GraphicalReportHandler::new_themed(GraphicalTheme::unicode_nocolor())
}

#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
fn landlock_availability_warning(
    probe: &miraserve_core::LandlockProbe,
    req: u32,
    loaded: &LoadedConfig,
) -> Option<ConfigIssue> {
    use miraserve_core::LandlockProbe as P;
    const L: &str = "Linux Landlock";
    const R: &str = "`miraserve run` will refuse to start on this kernel";
    const K: &str = "server.sandbox.landlock";
    const H: &str = "run on a Landlock-enabled Linux kernel, or disable via `sandbox { landlock #false }` or `--no-sandbox`";
    let message = match probe {
        P::Available(a) if *a >= req && *a >= 1 => return None,
        P::Available(a) => format!("{L} ABI {a} found, ABI {req} required; {R}"),
        P::Disabled => format!("{L} LSM not available (disabled in LSM list); {R}"),
        P::NotImplemented => format!("{L} LSM not available on this kernel; {R}"),
        P::ProbeError(e) => format!("{L} probe failed ({e}); {R} if unavailable"),
    };
    Some(ConfigIssue {
        code: "W035".into(),
        severity: Severity::Warning,
        message,
        path: Some(K.into()),
        help: Some(H.into()),
        label: None,
        location: loaded.location_for(K),
    })
}

#[cfg(test)]
mod writable_set_unit_tests {
    use super::*;

    mod kdl_test_util {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../miraserve-config/tests/common/mod.rs"
        ));
    }

    struct FailWriteWriter;
    impl io::Write for FailWriteWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "simulated write failure",
            ))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FailFlushWriter {
        written: Vec<u8>,
    }
    impl io::Write for FailFlushWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "simulated flush failure",
            ))
        }
    }

    #[test]
    fn write_writable_set_lines_propagates_write_and_flush_errors()
    -> Result<(), Box<dyn std::error::Error>> {
        let lines = vec!["landlock unavailable".to_owned()];
        let err = write_writable_set_lines(FailWriteWriter, &lines)
            .err()
            .ok_or("write failure must propagate")?;
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);

        let mut flush_writer = FailFlushWriter {
            written: Vec::new(),
        };
        let err = write_writable_set_lines(&mut flush_writer, &lines)
            .err()
            .ok_or("flush failure must propagate")?;
        assert_eq!(err.kind(), io::ErrorKind::WriteZero);
        assert_eq!(flush_writer.written, b"landlock unavailable\n");
        Ok(())
    }

    #[test]
    fn lexical_absolute_writable_path_normalizes_and_refuses_controls()
    -> Result<(), Box<dyn std::error::Error>> {
        let abs = lexical_absolute_writable_path(Path::new("/var/lib/miraserve/./a/../acme"), "t")?;
        assert_eq!(abs, "/var/lib/miraserve/acme");

        let spaces = lexical_absolute_writable_path(Path::new("/var/lib/with space/dir"), "t")?;
        assert_eq!(spaces, "/var/lib/with space/dir");

        let rel = lexical_absolute_writable_path(Path::new(".miraserve-acme"), "t")?;
        assert!(Path::new(&rel).is_absolute());
        assert!(rel.ends_with(".miraserve-acme"), "got: {rel}");

        let ctrl_err = lexical_absolute_writable_path(Path::new("/tmp/a\nb"), "t")
            .err()
            .ok_or("control char must fail")?;
        assert!(!ctrl_err.contains('\n'), "raw newline leaked: {ctrl_err:?}");
        Ok(())
    }

    #[test]
    fn sanitizing_line_writer_escapes_all_c0_del_and_c1_control_characters()
    -> Result<(), Box<dyn std::error::Error>> {
        // Every C0 (0x00..=0x1F), DEL (0x7F), and C1 (0x80..=0x9F) code point must be escaped.
        for code in (0x00_u32..=0x1F)
            .chain(std::iter::once(0x7F))
            .chain(0x80..=0x9F)
        {
            let ch = char::from_u32(code).ok_or("valid scalar")?;
            let mut buf = Vec::new();
            let mut writer = SanitizingLineWriter::new(&mut buf);
            writer.write_line(&format!("prefix-{ch}-suffix"))?;
            writer.flush()?;
            let rendered = String::from_utf8(buf)?;
            assert!(
                rendered.ends_with('\n'),
                "line must end with newline for U+{code:04X}"
            );
            let body = rendered
                .strip_suffix('\n')
                .ok_or("missing trailing newline")?;
            assert!(
                !body.chars().any(is_c0_del_c1),
                "raw control U+{code:04X} leaked into sanitized line: {body:?}"
            );
            assert!(
                body.starts_with("prefix-") && body.ends_with("-suffix"),
                "unexpected sanitized body for U+{code:04X}: {body:?}"
            );
        }

        // Ordinary printable UTF-8 passes through unchanged; write_multiline preserves '\n'
        // boundaries while escaping C0/DEL/C1 inside each line.
        let mut multi = Vec::new();
        let mut writer = SanitizingLineWriter::new(&mut multi);
        writer.write_multiline("line1 /srv/café dir\nline2 \x07\x1b\x7f\u{009b} end")?;
        writer.flush()?;
        let multi_str = String::from_utf8(multi)?;
        let lines: Vec<&str> = multi_str.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines.first().copied(), Some("line1 /srv/café dir"));
        let second = lines.get(1).copied().unwrap_or("");
        assert!(!second.chars().any(is_c0_del_c1));
        assert!(second.starts_with("line2 ") && second.ends_with(" end"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn fastcgi_socket_probe_handles_ids_differ_root_eacces_and_indeterminate_errors()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt as _;
        use std::os::unix::net::UnixListener;

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let base = PathBuf::from(format!("/tmp/ms-w033-unit-{}-{nanos}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base)?;
        let sock_path = base.join("pool.sock");
        let _listener = UnixListener::bind(&sock_path)?;
        fs::set_permissions(&sock_path, fs::Permissions::from_mode(0o660))?;
        let sock_str = sock_path.to_string_lossy().into_owned();

        let kdl = format!(
            "server {{ listen \":443\"; tls {{ cert \"/c.pem\"; key \"/k.pem\" }} }}\n\
             site \"unit.example\" {{ root \"/var/www\"; route \"*.php\" {{ fastcgi-pass \"unix:{}\" }} }}\n",
            kdl_test_util::kdl_escape_str(&sock_str),
        );
        let cfg_path = base.join("unit.kdl");
        fs::write(&cfg_path, &kdl)?;
        let loaded = miraserve_config::load_file_detailed(&cfg_path)?;

        // 1. Real UID != effective UID (and real GID != effective GID, including uid = euid = 0
        //    with differing real/effective GIDs): INDETERMINATE ids-differ note wins (never the
        //    root note), zero W033, and the probe closure is never invoked.
        for (ruid, euid, rgid, egid) in [
            (1000, 33, 1000, 1000),
            (1000, 1000, 1000, 33),
            (0, 33, 0, 33),
            (1000, 0, 1000, 0),
            (0, 0, 0, 33),
        ] {
            let mut issues = Vec::new();
            let mut notes = FastCgiSocketAccessNotes::default();
            let mut probe_called = false;
            check_fastcgi_unix_socket_accessible_with(
                &mut issues,
                &mut notes,
                &loaded,
                "site[0].route[0].fastcgi-pass",
                "unit.example",
                &sock_str,
                ruid,
                euid,
                rgid,
                egid,
                |_| {
                    probe_called = true;
                    Err(rustix::io::Errno::ACCESS)
                },
            );
            assert!(
                !probe_called,
                "probe must not run when real and effective IDs differ"
            );
            assert!(
                issues.is_empty(),
                "must not emit W033 when IDs differ: {issues:?}"
            );
            let lines = notes.into_note_lines();
            assert_eq!(lines.len(), 1);
            assert!(
                lines.first().is_some_and(
                    |l| l.contains("real and effective ids of the checking process differ")
                ),
                "unexpected ids-differ note: {lines:?}"
            );
        }

        // 2. Root (ruid == euid == 0): root note, zero W033, probe never invoked.
        {
            let mut issues = Vec::new();
            let mut notes = FastCgiSocketAccessNotes::default();
            let mut probe_called = false;
            check_fastcgi_unix_socket_accessible_with(
                &mut issues,
                &mut notes,
                &loaded,
                "site[0].route[0].fastcgi-pass",
                "unit.example",
                &sock_str,
                0,
                0,
                0,
                0,
                |_| {
                    probe_called = true;
                    Err(rustix::io::Errno::ACCESS)
                },
            );
            assert!(!probe_called);
            assert!(issues.is_empty(), "root must emit no issues: {issues:?}");
            let lines = notes.into_note_lines();
            assert_eq!(lines.len(), 1);
            assert!(lines.first().is_some_and(|l| l.contains("root (euid 0)")));
        }

        // 3. EACCES -> W033 with required wording (NOT "cannot be opened").
        {
            let mut issues = Vec::new();
            let mut notes = FastCgiSocketAccessNotes::default();
            check_fastcgi_unix_socket_accessible_with(
                &mut issues,
                &mut notes,
                &loaded,
                "site[0].route[0].fastcgi-pass",
                "unit.example",
                &sock_str,
                1000,
                1000,
                1000,
                1000,
                |_| Err(rustix::io::Errno::ACCESS),
            );
            assert_eq!(issues.len(), 1);
            let issue = issues.first().ok_or("missing W033 issue")?;
            assert_eq!(issue.code, "W033");
            assert!(
                issue.message.contains(
                    "requires read and write permission on the socket for the account running the check (uid/gid 1000/1000)"
                ),
                "unexpected W033 message: {}",
                issue.message
            );
            assert!(!issue.message.contains("cannot be opened"));
            let note_lines = notes.into_note_lines();
            assert!(
                note_lines.is_empty(),
                "EACCES must emit no indeterminate note: {note_lines:?}"
            );
        }

        // 4. Non-EACCES errors (EPERM, ENOSYS, EINVAL) -> INDETERMINATE note naming the error, NO W033.
        for (errno, tag) in [
            (rustix::io::Errno::PERM, "EPERM"),
            (rustix::io::Errno::NOSYS, "ENOSYS"),
            (rustix::io::Errno::INVAL, "EINVAL"),
        ] {
            let mut issues = Vec::new();
            let mut notes = FastCgiSocketAccessNotes::default();
            check_fastcgi_unix_socket_accessible_with(
                &mut issues,
                &mut notes,
                &loaded,
                "site[0].route[0].fastcgi-pass",
                "unit.example",
                &sock_str,
                1000,
                1000,
                1000,
                1000,
                |_| Err(errno),
            );
            assert!(
                issues.is_empty(),
                "{tag} must be indeterminate and never emit W033: {issues:?}"
            );
            let lines = notes.into_note_lines();
            assert_eq!(lines.len(), 1);
            assert!(
                lines.first().is_some_and(|l| l.contains(tag)),
                "indeterminate note must name {tag}: {lines:?}"
            );
        }

        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn landlock_availability_warning_covers_every_probe_branch_and_location()
    -> Result<(), Box<dyn std::error::Error>> {
        use miraserve_core::LandlockProbe;
        const EXPECTED_HELP: &str = "run on a Landlock-enabled Linux kernel, or disable via \
            `sandbox { landlock #false }` or `--no-sandbox`";

        let explicit = parse_kdl_detailed(
            "explicit.kdl",
            r#"
server {
    listen ":443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }
    sandbox { landlock #true; seccomp "strict" }
}
site "a.example" { root "/var/www/a" }
"#,
        )?;
        let block_only = parse_kdl_detailed(
            "block.kdl",
            r#"
server {
    listen ":443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }
    sandbox { user "miraserve" }
}
site "a.example" { root "/var/www/a" }
"#,
        )?;
        let omitted = parse_kdl_detailed(
            "omitted.kdl",
            r#"
server {
    listen ":443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }
}
site "a.example" { root "/var/www/a" }
"#,
        )?;

        // 1. Available at or above required ABI -> None (no warning).
        assert_eq!(
            landlock_availability_warning(&LandlockProbe::Available(1), 1, &explicit),
            None
        );
        assert_eq!(
            landlock_availability_warning(&LandlockProbe::Available(5), 1, &explicit),
            None
        );
        assert_eq!(
            landlock_availability_warning(&LandlockProbe::Available(5), 5, &explicit),
            None
        );

        // 2. Available below required ABI (and zero ABI) -> W035 naming ABI found vs required.
        let low = landlock_availability_warning(&LandlockProbe::Available(2), 5, &explicit)
            .ok_or("expected W035 for ABI 2 < 5")?;
        assert_eq!(low.code, "W035");
        assert_eq!(low.severity, Severity::Warning);
        assert_eq!(low.path.as_deref(), Some("server.sandbox.landlock"));
        assert_eq!(
            low.message,
            "Linux Landlock ABI 2 found, ABI 5 required; `miraserve run` will refuse to start on this kernel"
        );
        assert_eq!(low.help.as_deref(), Some(EXPECTED_HELP));
        assert_eq!(
            low.location,
            explicit.location_for("server.sandbox.landlock")
        );
        assert!(low.location.is_some());

        let zero = landlock_availability_warning(&LandlockProbe::Available(0), 1, &explicit)
            .ok_or("expected W035 for ABI 0 < 1")?;
        assert_eq!(zero.code, "W035");
        assert_eq!(zero.path.as_deref(), Some("server.sandbox.landlock"));
        assert_eq!(
            zero.message,
            "Linux Landlock ABI 0 found, ABI 1 required; `miraserve run` will refuse to start on this kernel"
        );

        // 3. Disabled in kernel LSM list (EOPNOTSUPP) -> W035.
        let disabled = landlock_availability_warning(&LandlockProbe::Disabled, 1, &block_only)
            .ok_or("expected W035 for Disabled")?;
        assert_eq!(disabled.code, "W035");
        assert_eq!(disabled.severity, Severity::Warning);
        assert_eq!(disabled.path.as_deref(), Some("server.sandbox.landlock"));
        assert_eq!(
            disabled.message,
            "Linux Landlock LSM not available (disabled in LSM list); `miraserve run` will refuse to start on this kernel"
        );
        assert_eq!(disabled.help.as_deref(), Some(EXPECTED_HELP));
        assert_eq!(disabled.location, block_only.location_for("server.sandbox"));
        assert!(disabled.location.is_some());

        // 4. Not implemented in kernel (ENOSYS / filtered) -> W035.
        let not_impl = landlock_availability_warning(&LandlockProbe::NotImplemented, 1, &omitted)
            .ok_or("expected W035 for NotImplemented")?;
        assert_eq!(not_impl.code, "W035");
        assert_eq!(not_impl.severity, Severity::Warning);
        assert_eq!(not_impl.path.as_deref(), Some("server.sandbox.landlock"));
        assert_eq!(
            not_impl.message,
            "Linux Landlock LSM not available on this kernel; `miraserve run` will refuse to start on this kernel"
        );
        assert_eq!(not_impl.help.as_deref(), Some(EXPECTED_HELP));
        assert_eq!(not_impl.location, omitted.location_for("server"));
        assert!(not_impl.location.is_some());

        // 5. Probe error -> W035 stating probe failure, never silent, never Error severity.
        let err_issue = landlock_availability_warning(
            &LandlockProbe::ProbeError("unexpected Landlock ABI 0".to_owned()),
            1,
            &explicit,
        )
        .ok_or("expected W035 for ProbeError")?;
        assert_eq!(err_issue.code, "W035");
        assert_eq!(err_issue.severity, Severity::Warning);
        assert_eq!(err_issue.path.as_deref(), Some("server.sandbox.landlock"));
        assert_eq!(
            err_issue.message,
            "Linux Landlock probe failed (unexpected Landlock ABI 0); `miraserve run` will refuse to start on this kernel if unavailable"
        );
        assert_eq!(err_issue.help.as_deref(), Some(EXPECTED_HELP));
        Ok(())
    }
}

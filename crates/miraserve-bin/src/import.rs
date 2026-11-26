//! Implementation of `miraserve import` (Nginx, Caddy, Apache, OpenLiteSpeed -> KDL).

use std::fs;
use std::io::{self, Read as _, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, ValueEnum};
use miraserve_migrate::{
    MigrateError, MigrateOptions, SourceFormat, migrate_file_with_options, migrate_str_with_options,
};

/// Source format selector for `miraserve import`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum ImportFrom {
    /// Auto-detect Nginx, Caddy, Apache, or OpenLiteSpeed syntax.
    Auto,
    /// Nginx `nginx.conf` / `sites-enabled/*.conf`.
    Nginx,
    /// Caddy `Caddyfile`.
    Caddy,
    /// Apache HTTP Server `<VirtualHost>` config.
    Apache,
    /// OpenLiteSpeed `vhconf.conf` / `httpd_config.conf`.
    #[value(name = "openlitespeed", alias = "ols")]
    OpenLiteSpeed,
}

impl From<ImportFrom> for SourceFormat {
    fn from(value: ImportFrom) -> Self {
        match value {
            ImportFrom::Auto => Self::Auto,
            ImportFrom::Nginx => Self::Nginx,
            ImportFrom::Caddy => Self::Caddy,
            ImportFrom::Apache => Self::Apache,
            ImportFrom::OpenLiteSpeed => Self::OpenLiteSpeed,
        }
    }
}

/// Output mode for `miraserve import`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum ImportOutputFormat {
    /// Emit generated MiraServe KDL to stdout (or `--output`) and migration notes to stderr.
    Kdl,
    /// Emit full structured JSON migration report (including generated KDL, upgrades, and notes).
    Json,
}

/// CLI arguments for `miraserve import`.
#[derive(Debug, Args)]
pub(crate) struct ImportArgs {
    /// Path to legacy server config file, or '-' to read from standard input.
    #[arg(value_name = "INPUT")]
    pub(crate) input: PathBuf,

    /// Legacy server config format (defaults to automatic detection).
    #[arg(long, value_enum, default_value_t = ImportFrom::Auto)]
    pub(crate) from: ImportFrom,

    /// Optional destination file to write the generated MiraServe KDL config.
    #[arg(short, long, value_name = "FILE")]
    pub(crate) output: Option<PathBuf>,

    /// Output format (`kdl` or `json`).
    #[arg(long, value_enum, default_value_t = ImportOutputFormat::Kdl)]
    pub(crate) format: ImportOutputFormat,

    /// Emit blocked sites/routes and exit 0 even when source security controls
    /// (authentication, ACLs, rate limits, mTLS) could not be translated; emitted blocked sites
    /// are tagged with `// INSECURE:` comments and must NEVER be deployed as-is (`R4-MIG-2`).
    #[arg(long)]
    pub(crate) allow_insecure: bool,

    /// Overwrite an existing `--output` file instead of refusing (`CFG-7`).
    #[arg(long)]
    pub(crate) force: bool,

    /// Local directory root of a copied/uploaded config tree (`R7-MIG-13`), used to remap
    /// absolute `include` directives (e.g. `/etc/nginx/conf.d/*.conf`) strictly within that root.
    #[arg(long, value_name = "DIR")]
    pub(crate) source_root: Option<PathBuf>,
}

/// Writes `bytes` to `out_path` without following symlinks (existing OR dangling, `R7-MIG-17`).
fn write_output_file_nofollow(
    out_path: &std::path::Path,
    bytes: &[u8],
    force: bool,
) -> io::Result<()> {
    if let Ok(md) = fs::symlink_metadata(out_path) {
        if md.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "refusing to write output through a symlink (existing or dangling)",
            ));
        }
        if !force {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "refusing to overwrite existing file without --force",
            ));
        }
    }
    let mut opts = fs::OpenOptions::new();
    opts.write(true);
    if force {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        #[cfg(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        ))]
        const O_NOFOLLOW: i32 = 0x0100;
        #[cfg(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "arm")))]
        const O_NOFOLLOW: i32 = 0x8000;
        #[cfg(all(
            target_os = "linux",
            not(any(target_arch = "aarch64", target_arch = "arm"))
        ))]
        const O_NOFOLLOW: i32 = 0x20000;
        #[cfg(not(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly",
            target_os = "linux"
        )))]
        const O_NOFOLLOW: i32 = 0;
        if O_NOFOLLOW != 0 {
            opts.custom_flags(O_NOFOLLOW);
        }
    }
    let mut file = opts.open(out_path)?;
    file.write_all(bytes)?;
    Ok(())
}

/// Executes `miraserve import` and prints or writes validated MiraServe KDL.
#[allow(clippy::too_many_lines)]
pub(crate) fn run_import(args: &ImportArgs) -> ExitCode {
    let source_format: SourceFormat = args.from.into();

    if let Some(out_path) = &args.output
        && let Ok(md) = fs::symlink_metadata(out_path)
    {
        if md.file_type().is_symlink() {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(
                stderr,
                "error: refusing to write output through symlink '{}'",
                out_path.display()
            );
            return ExitCode::FAILURE;
        }
        if !args.force {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(
                stderr,
                "error: refusing to overwrite existing file '{}' (pass --force to overwrite)",
                out_path.display()
            );
            return ExitCode::FAILURE;
        }
    }

    let migrate_opts = MigrateOptions {
        allow_insecure: args.allow_insecure,
        source_root: args.source_root.clone(),
    };
    let report = if args.input.as_os_str() == "-" {
        const MAX_STDIN_IMPORT_BYTES: u64 = 10 * 1024 * 1024;
        let mut buf = String::new();
        if let Err(err) = io::stdin()
            .take(MAX_STDIN_IMPORT_BYTES.saturating_add(1))
            .read_to_string(&mut buf)
        {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(stderr, "error: failed to read stdin: {err}");
            return ExitCode::FAILURE;
        }
        if (buf.len() as u64) > MAX_STDIN_IMPORT_BYTES {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(
                stderr,
                "error: stdin config exceeds maximum import safety limit of {MAX_STDIN_IMPORT_BYTES} bytes"
            );
            return ExitCode::FAILURE;
        }
        migrate_str_with_options(&buf, source_format, migrate_opts)
    } else {
        migrate_file_with_options(&args.input, source_format, migrate_opts)
    };

    let report = match report {
        Ok(r) => r,
        Err(MigrateError::AllRoutesBlockedBySecurity { format, downgrades }) => {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(
                stderr,
                "SECURITY ERROR: refused to emit open routes from {format} config ({} untranslatable security control(s)):",
                downgrades.len()
            );
            for d in &downgrades {
                let loc = format_note_location(d);
                let _ = writeln!(stderr, "  ! {loc}({}): {}", d.directive, d.message);
            }
            return ExitCode::FAILURE;
        }
        Err(err) => {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(stderr, "error: {err}");
            return ExitCode::FAILURE;
        }
    };

    // MIG-3: Fail closed when any security controls were dropped unless `--allow-insecure` is passed!
    let has_security_downgrades = !report.security_downgrades.is_empty();
    if has_security_downgrades && !args.allow_insecure {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(
            stderr,
            "SECURITY ERROR: {} security directive(s) in {} config could not be auto-translated (affected routes were omitted):",
            report.security_downgrades.len(),
            report.source_format
        );
        for d in &report.security_downgrades {
            let loc = format_note_location(d);
            let _ = writeln!(stderr, "  ! {loc}({}): {}", d.directive, d.message);
        }
        let _ = writeln!(
            stderr,
            "Refusing to exit 0 or write output file. Re-implement the listed access controls manually, or re-run with --allow-insecure to export an INSECURE draft (including blocked sites tagged '// INSECURE:') for offline review only."
        );
        return ExitCode::FAILURE;
    }

    if let Some(out_path) = &args.output
        && let Err(err) = write_output_file_nofollow(out_path, report.kdl.as_bytes(), args.force)
    {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(
            stderr,
            "error: failed to write '{}': {err}",
            out_path.display()
        );
        return ExitCode::FAILURE;
    }

    match args.format {
        ImportOutputFormat::Json => {
            let mut stdout = io::stdout().lock();
            if let Ok(json) = serde_json::to_string_pretty(&report) {
                let _ = writeln!(stdout, "{json}");
            }
        }
        ImportOutputFormat::Kdl => {
            if args.output.is_none() {
                let mut stdout = io::stdout().lock();
                let _ = write!(stdout, "{}", report.kdl);
            }
            let mut stderr = io::stderr().lock();
            let _ = writeln!(
                stderr,
                "Migrated {} site(s) and {} route(s) from {} configuration.",
                report.migrated_sites, report.migrated_routes, report.source_format
            );
            if let Some(out_path) = &args.output {
                let _ = writeln!(
                    stderr,
                    "Wrote validated MiraServe KDL to '{}'.",
                    out_path.display()
                );
            }
            if !report.security_downgrades.is_empty() {
                if report.insecure_sites_emitted.is_empty() {
                    let _ = writeln!(
                        stderr,
                        "SECURITY WARNING (--allow-insecure): {} security directive(s) were NOT auto-translated (affected individual routes were omitted):",
                        report.security_downgrades.len()
                    );
                } else {
                    let _ = writeln!(
                        stderr,
                        "SECURITY WARNING (--allow-insecure): {} security directive(s) were NOT translated and {} blocked site(s) ({}) were EMITTED INSECURELY without those controls:",
                        report.security_downgrades.len(),
                        report.insecure_sites_emitted.len(),
                        report.insecure_sites_emitted.join("; ")
                    );
                }
                for d in &report.security_downgrades {
                    let loc = format_note_location(d);
                    let _ = writeln!(stderr, "  ! {loc}({}): {}", d.directive, d.message);
                }
            }
            if !report.security_upgrades.is_empty() {
                let _ = writeln!(stderr, "Security upgrades applied:");
                for up in &report.security_upgrades {
                    let _ = writeln!(stderr, "  + {up}");
                }
            }
            if !report.notes.is_empty() {
                let _ = writeln!(stderr, "Manual review notes ({}):", report.notes.len());
                for note in &report.notes {
                    let loc = format_note_location(note);
                    let _ = writeln!(stderr, "  - {loc}({}): {}", note.directive, note.message);
                }
            }
        }
    }

    ExitCode::SUCCESS
}

fn format_note_location(note: &miraserve_migrate::MigrationNote) -> String {
    match (note.file.as_deref(), note.line) {
        (Some(file), Some(line)) => format!("{file}:{line} "),
        (Some(file), None) => format!("{file} "),
        (None, Some(line)) => format!("line {line} "),
        (None, None) => String::new(),
    }
}

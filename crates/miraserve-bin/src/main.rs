#![forbid(unsafe_code)]
//! MiraServe CLI binary entrypoint.

mod cert;
mod check;
mod import;
mod keyd;
mod publish;
mod run;
mod service;

use std::io::{self, Write as _};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::cert::{CertArgs, run_cert};
use crate::check::{CheckArgs, run_check};
use crate::import::{ImportArgs, run_import};
use crate::keyd::{KeydArgs, run_keyd};
use crate::publish::{PublishArgs, run_publish};
use crate::run::{ReloadArgs, RunArgs, run_reload, run_server};
use crate::service::{ServiceArgs, run_service};

/// Web server and edge gateway in memory-safe Rust with post-quantum HTTPS.
#[derive(Debug, Parser)]
#[command(
    name = "miraserve",
    version,
    about = "Web server and edge gateway in memory-safe Rust with post-quantum HTTPS",
    long_about = None,
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Start the MiraServe HTTPS (HTTP/1.1, HTTP/2, HTTP/3 + PQC TLS 1.3) server.
    Run(RunArgs),

    /// Validate a MiraServe KDL configuration file against schema and threat-model rules.
    Check(CheckArgs),

    /// Gracefully hot-reload configuration in a running MiraServe instance via SIGHUP.
    Reload(ReloadArgs),

    /// Inspect PEM certificates or generate self-signed development TLS certificates.
    Cert(CertArgs),

    /// Display detailed version, build target, and security defaults.
    Version,

    /// Convert Nginx, Caddy, Apache, or OpenLiteSpeed configs to validated MiraServe KDL.
    Import(ImportArgs),

    /// Sign, verify, publish, list, or roll back atomic AI website bundles.
    Publish(PublishArgs),

    /// Run the split-privilege TLS signing daemon (`miraserve-keyd`, Threat Model T2).
    Keyd(KeydArgs),

    /// Generate hardened systemd, launchd, or Windows Service deployment units.
    Service(ServiceArgs),
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run(args) => run_server(&args),
        Commands::Check(args) => run_check(&args),
        Commands::Reload(args) => run_reload(&args),
        Commands::Cert(args) => run_cert(&args),
        Commands::Version => print_version(),
        Commands::Import(args) => run_import(&args),
        Commands::Publish(args) => run_publish(&args),
        Commands::Keyd(args) => run_keyd(&args),
        Commands::Service(args) => run_service(&args),
    }
}

fn print_version() -> ExitCode {
    let mut stdout = io::stdout().lock();
    let _ = writeln!(stdout, "miraserve {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(
        stdout,
        "platform: {}-{}",
        std::env::consts::ARCH,
        std::env::consts::OS
    );
    let _ = writeln!(
        stdout,
        "defaults: TLS 1.3 only, X25519MLKEM768 PQC hybrid, H3/H2/H1, dual-stack IPv4+IPv6, cap-std, forbid(unsafe_code)"
    );
    let _ = writeln!(
        stdout,
        "features: precompressed, header-rule-status, service-allow-openat2, writable-set, try-files-extensionless"
    );
    ExitCode::SUCCESS
}

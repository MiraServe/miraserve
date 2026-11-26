//! Implementation of `miraserve cert` (`inspect` and `generate-dev`).

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Subcommand};
use miraserve_tls::{generate_dev_cert_pem, inspect_cert_file, write_secret_file};

use crate::check::OutputFormat;

/// CLI arguments for `miraserve cert`.
#[derive(Debug, Args)]
pub(crate) struct CertArgs {
    #[command(subcommand)]
    pub(crate) action: CertCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum CertCommand {
    /// Inspect an X.509 PEM certificate chain and print SANs, issuer, and validity window.
    Inspect {
        /// Path to the PEM certificate file.
        #[arg(value_name = "CERT_PEM")]
        path: PathBuf,

        /// Output format (`text` or `json`).
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },

    /// Generate a self-signed ECDSA P-256 development TLS certificate and private key (no OpenSSL).
    GenerateDev {
        /// Comma-separated hostnames or IPs to include as SANs (`localhost`, `127.0.0.1`, `::1` always added).
        #[arg(long, value_delimiter = ',', default_value = "localhost")]
        hosts: Vec<String>,

        /// Output path for the PEM certificate file.
        #[arg(long, default_value = "dev-cert.pem")]
        cert: PathBuf,

        /// Output path for the PEM private key file.
        #[arg(long, default_value = "dev-key.pem")]
        key: PathBuf,

        /// Overwrite existing certificate or private key files.
        #[arg(long)]
        force: bool,
    },

    /// Generate an RFC 9849 Encrypted Client Hello (ECH) X25519 HPKE config and DNS HTTPS record.
    EchGenerate {
        /// Public outer SNI DNS hostname advertised in the RFC 9849 `ECHConfig` (e.g. `edge.example.com`).
        #[arg(long, default_value = "edge.example.com")]
        public_name: String,

        /// Automatic key rotation cadence in seconds (defaults to 3600s / 1h).
        #[arg(long, default_value_t = 3600)]
        rotate_secs: u64,

        /// Output format (`text` or `json`).
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
}

/// Dispatches `miraserve cert` subcommands.
pub(crate) fn run_cert(args: &CertArgs) -> ExitCode {
    match &args.action {
        CertCommand::Inspect { path, format } => run_inspect(path, *format),
        CertCommand::GenerateDev {
            hosts,
            cert,
            key,
            force,
        } => run_generate_dev(hosts, cert, key, *force),
        CertCommand::EchGenerate {
            public_name,
            rotate_secs,
            format,
        } => run_ech_generate(public_name, *rotate_secs, *format),
    }
}

fn run_inspect(path: &Path, format: OutputFormat) -> ExitCode {
    match inspect_cert_file(path) {
        Ok(info) => {
            let mut stdout = io::stdout().lock();
            match format {
                OutputFormat::Json => {
                    if let Ok(json) = serde_json::to_string_pretty(&info) {
                        let _ = writeln!(stdout, "{json}");
                    }
                }
                OutputFormat::Text => {
                    let _ = writeln!(stdout, "Certificate: {}", path.display());
                    let _ = writeln!(stdout, "  Subject:    {}", info.subject);
                    let _ = writeln!(stdout, "  Issuer:     {}", info.issuer);
                    let _ = writeln!(stdout, "  Serial:     {}", info.serial_hex);
                    let _ = writeln!(stdout, "  SANs:       {}", info.sans.join(", "));
                    let _ = writeln!(stdout, "  Not Before: {}", info.not_before);
                    let _ = writeln!(
                        stdout,
                        "  Not After:  {} ({} days)",
                        info.not_after, info.validity_days
                    );
                    let _ = writeln!(stdout, "  Signature:  {}", info.signature_algorithm);
                    let _ = writeln!(stdout, "  Chain Len:  {}", info.chain_len);
                }
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(stderr, "error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run_generate_dev(hosts: &[String], cert_path: &Path, key_path: &Path, force: bool) -> ExitCode {
    if !force {
        for existing in [cert_path, key_path] {
            if existing.exists() {
                let mut stderr = io::stderr().lock();
                let _ = writeln!(
                    stderr,
                    "error: refusing to overwrite existing file '{}' (pass --force to overwrite)",
                    existing.display()
                );
                return ExitCode::FAILURE;
            }
        }
    }
    let generated = match generate_dev_cert_pem(hosts) {
        Ok(g) => g,
        Err(err) => {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(stderr, "error: {err}");
            return ExitCode::FAILURE;
        }
    };

    // R4-PKG-2: Write the private key FIRST (`0600` atomic temp+rename) and then atomically write
    // the certificate via a sibling temp file + rename (rolling back the key on failure) so a
    // failed run never leaves a half-written cert without its matching private key!
    if let Err(err) = write_secret_file(key_path, generated.key_pem.as_bytes()) {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(
            stderr,
            "error: failed to write private key '{}': {err}",
            key_path.display()
        );
        return ExitCode::FAILURE;
    }

    let tmp_cert = cert_path.with_file_name(format!(
        ".{}.tmp-{}",
        cert_path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or("cert"),
        std::process::id()
    ));
    if let Some(parent) = cert_path.parent()
        && !parent.as_os_str().is_empty()
        && let Err(err) = fs::create_dir_all(parent)
    {
        let _ = fs::remove_file(key_path);
        let mut stderr = io::stderr().lock();
        let _ = writeln!(
            stderr,
            "error: failed to create certificate directory '{}': {err}",
            parent.display()
        );
        return ExitCode::FAILURE;
    }
    if let Err(err) = fs::write(&tmp_cert, generated.cert_pem.as_bytes())
        .and_then(|()| fs::rename(&tmp_cert, cert_path))
    {
        let _ = fs::remove_file(&tmp_cert);
        let _ = fs::remove_file(key_path);
        let mut stderr = io::stderr().lock();
        let _ = writeln!(
            stderr,
            "error: failed to write certificate '{}': {err}",
            cert_path.display()
        );
        return ExitCode::FAILURE;
    }

    let mut stdout = io::stdout().lock();
    let _ = writeln!(
        stdout,
        "OK: generated self-signed ECDSA P-256 dev certificate '{}' and key '{}'",
        cert_path.display(),
        key_path.display()
    );
    ExitCode::SUCCESS
}

fn run_ech_generate(public_name: &str, rotate_secs: u64, format: OutputFormat) -> ExitCode {
    let _ = (public_name, rotate_secs, format);
    // ECH-1 (Round-4 Q6): Refuse to emit a publishable DNS HTTPS ECH record while server-side ECH
    // decryption is unavailable in rustls 0.23, so operators can never publish undecryptable DNS.
    let mut stderr = io::stderr().lock();
    let _ = writeln!(
        stderr,
        "error: `miraserve cert ech-generate` is disabled because server-side ECH decryption is \
         not yet supported by rustls 0.23; refusing to print a DNS HTTPS ECH record that the \
         server cannot decrypt"
    );
    ExitCode::FAILURE
}

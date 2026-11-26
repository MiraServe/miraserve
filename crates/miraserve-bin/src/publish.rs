//! Implementation of `miraserve publish` (`keygen`, `sign`, `verify`, `deploy`, `rollback`, `list`).

use std::fs::{self, File};
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Subcommand};
use miraserve_config::{
    AiPublishConfig, PreflightCheck, SignatureAlgorithm, SignatureRequirement, load_file,
};
use miraserve_publish::{
    Ed25519SigningKey, Ed25519VerifyingKey, PublishError, ReleaseStore, ResignOptions,
    SignedBundle, bundle_from_directory,
};
use miraserve_tls::write_secret_file;
use serde::Serialize;

/// Maximum signed bundle JSON file size accepted by `miraserve publish verify` (64 MiB).
const MAX_BUNDLE_JSON_BYTES: u64 = 64 * 1024 * 1024;

use crate::check::OutputFormat;

/// CLI arguments for `miraserve publish`.
#[derive(Debug, Args)]
pub(crate) struct PublishArgs {
    #[command(subcommand)]
    pub(crate) action: PublishCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum PublishCommand {
    /// Generate an Ed25519 signing/verifying key pair for atomic AI website publishing.
    Keygen {
        /// Output path for the Ed25519 private signing key (permissions set to 0600 on Unix).
        #[arg(long, default_value = "publisher.key")]
        secret: PathBuf,

        /// Output path for the Ed25519 public verification key (referenced by `require-signature`).
        #[arg(long, default_value = "publisher.pub")]
        public: PathBuf,

        /// Overwrite existing secret or public key files.
        #[arg(long)]
        force: bool,
    },

    /// Pack and Ed25519-sign a local site directory into a verifiable JSON bundle.
    Sign {
        /// Directory containing static site files (`index.html`, `llms.txt`, assets, etc.).
        #[arg(value_name = "SITE_DIR")]
        dir: PathBuf,

        /// Path to the Ed25519 signing secret key created by `miraserve publish keygen`.
        #[arg(long)]
        key: PathBuf,

        /// Destination path for the signed JSON bundle.
        #[arg(long, short = 'o')]
        output: PathBuf,

        /// Optional release note recorded in the signed bundle manifest.
        #[arg(long)]
        note: Option<String>,

        /// Target site ID bound into the v3 signed bundle manifest (`R4-PUB-3`, mandatory per `R5-PUB-4`).
        #[arg(long)]
        site_id: String,

        /// Overwrite existing output bundle file.
        #[arg(long)]
        force: bool,
    },

    /// Cryptographically verify an Ed25519-signed bundle against a public key.
    Verify {
        /// Path to the signed JSON bundle produced by `miraserve publish sign`.
        #[arg(value_name = "BUNDLE_JSON")]
        bundle: PathBuf,

        /// Path to the Ed25519 public verifying key.
        #[arg(long)]
        pubkey: PathBuf,
    },

    /// Run pre-flight safety checks and atomically publish a directory into an immutable release store.
    Deploy {
        /// Directory containing static site files to publish atomically.
        #[arg(value_name = "SITE_DIR")]
        dir: PathBuf,

        /// MiraServe KDL config file loading the site's exact `ai-publish` policy (required by
        /// default unless `--allow-unconfigured-policy` is explicitly passed, §4 Q4 / `R2-PUB-6`).
        #[arg(long)]
        config: Option<PathBuf>,

        /// Target site hostname or `site-id` inside `--config` (required when `--config` defines
        /// multiple `ai-publish` sites).
        #[arg(long)]
        site: Option<String>,

        /// Release store storage directory (required with `--allow-unconfigured-policy`; overrides
        /// config storage when combined with `--config`).
        #[arg(long)]
        storage: Option<PathBuf>,

        /// Optional Ed25519 signing secret key to sign the bundle before deployment.
        #[arg(long)]
        key: Option<PathBuf>,

        /// Optional Ed25519 public verifying key required to verify the bundle signature.
        #[arg(long)]
        pubkey: Option<PathBuf>,

        /// Optional deployment note persisted in `release.json`.
        #[arg(long)]
        note: Option<String>,

        /// Number of historical releases to keep for instant rollback (used only with
        /// `--allow-unconfigured-policy`).
        #[arg(long, default_value_t = 10)]
        keep_versions: u32,

        /// Also enforce the `no-inline-scripts` HTML XSS pre-flight check.
        #[arg(long)]
        no_inline_scripts: bool,

        /// Explicitly allow deploying without `--config` (bypasses KDL site policy; standalone/dev only).
        #[arg(long)]
        allow_unconfigured_policy: bool,

        /// Explicitly reset the stored monotonic timestamp watermark to recover after a host clock
        /// ran ahead or a future-stamped deploy blocked later publishes (`R4-PUB-5`).
        #[arg(long)]
        allow_timestamp_reset: bool,

        /// Output format (`text` or `json`).
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },

    /// Instantly roll back an immutable release store to the previous (or specified) release.
    Rollback {
        /// Optional MiraServe KDL config file to load exact site `ai-publish` policy from (`R2-PUB-6`).
        #[arg(long)]
        config: Option<PathBuf>,

        /// Target site hostname inside `--config`.
        #[arg(long)]
        site: Option<String>,

        /// Release store storage directory (required unless `--config` supplies it).
        #[arg(long)]
        storage: Option<PathBuf>,

        /// Explicit release ID to activate (defaults to the immediately previous release).
        #[arg(long)]
        release_id: Option<String>,

        /// Optional Ed25519 public verifying key enforcing `signature_verified` on rollback.
        #[arg(long)]
        pubkey: Option<PathBuf>,

        /// Output format (`text` or `json`).
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },

    /// List retained immutable releases and show the currently active release.
    List {
        /// Release store storage directory.
        #[arg(long)]
        storage: PathBuf,

        /// Output format (`text` or `json`).
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },

    /// Re-sign retained immutable release manifests (verifying on-disk `manifest_sha256` first)
    /// for planned Ed25519 key rotation (`R2-PUB-7`). Pre-v2 releases must be republished from source.
    Resign {
        /// Optional MiraServe KDL config file to load exact site `ai-publish` policy from (`R2-PUB-6`).
        #[arg(long)]
        config: Option<PathBuf>,

        /// Target site hostname inside `--config`.
        #[arg(long)]
        site: Option<String>,

        /// Release store storage directory (required unless `--config` supplies it).
        #[arg(long)]
        storage: Option<PathBuf>,

        /// Path to the active Ed25519 private signing key.
        #[arg(long)]
        key: PathBuf,

        /// Optional Ed25519 public verifying key to cross-check generated signatures against.
        #[arg(long)]
        pubkey: Option<PathBuf>,

        /// Optional previous Ed25519 public key to cryptographically verify existing signatures before rotation.
        #[arg(long)]
        old_pubkey: Option<PathBuf>,

        /// Explicitly opt in to re-signing truly unsigned releases (`signature_b64` absent, `R2-PUB-7`, `R5-PUB-6`).
        #[arg(long)]
        include_unsigned: bool,

        /// Explicitly rebind stored releases from `--from-site-id` to the site's current
        /// `site-id` AFTER cryptographically verifying existing signatures (`R5-PUB-1`, `R6-PUB-4`).
        #[arg(long)]
        rebind_site_id: bool,

        /// Required alongside `--rebind-site-id`: exact previous `site-id` to migrate from so
        /// releases belonging to another site sharing the same key are never adopted (`R6-PUB-4`).
        #[arg(long)]
        from_site_id: Option<String>,

        /// Optional single release ID to re-sign (defaults to all retained releases in the store).
        #[arg(long)]
        release_id: Option<String>,

        /// Output format (`text` or `json`).
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
}

/// Dispatches `miraserve publish` subcommands.
pub(crate) fn run_publish(args: &PublishArgs) -> ExitCode {
    match &args.action {
        PublishCommand::Keygen {
            secret,
            public,
            force,
        } => run_keygen(secret, public, *force),
        PublishCommand::Sign {
            dir,
            key,
            output,
            note,
            site_id,
            force,
        } => run_sign(dir, key, output, note.as_deref(), site_id, *force),
        PublishCommand::Verify { bundle, pubkey } => run_verify(bundle, pubkey),
        PublishCommand::Deploy {
            dir,
            config,
            site,
            storage,
            key,
            pubkey,
            note,
            keep_versions,
            no_inline_scripts,
            allow_unconfigured_policy,
            allow_timestamp_reset,
            format,
        } => run_deploy(
            dir,
            config.as_deref(),
            site.as_deref(),
            storage.as_deref(),
            key.as_deref(),
            pubkey.as_deref(),
            note.as_deref(),
            *keep_versions,
            *no_inline_scripts,
            *allow_unconfigured_policy,
            *allow_timestamp_reset,
            *format,
        ),
        PublishCommand::Rollback {
            config,
            site,
            storage,
            release_id,
            pubkey,
            format,
        } => run_rollback(
            config.as_deref(),
            site.as_deref(),
            storage.as_deref(),
            release_id.as_deref(),
            pubkey.as_deref(),
            *format,
        ),
        PublishCommand::List { storage, format } => run_list(storage, *format),
        PublishCommand::Resign {
            config,
            site,
            storage,
            key,
            pubkey,
            old_pubkey,
            include_unsigned,
            rebind_site_id,
            from_site_id,
            release_id,
            format,
        } => run_resign(
            config.as_deref(),
            site.as_deref(),
            storage.as_deref(),
            key,
            pubkey.as_deref(),
            old_pubkey.as_deref(),
            *include_unsigned,
            *rebind_site_id,
            from_site_id.as_deref(),
            release_id.as_deref(),
            *format,
        ),
    }
}

fn run_keygen(secret_path: &Path, public_path: &Path, force: bool) -> ExitCode {
    if !force {
        for existing in [secret_path, public_path] {
            if existing.exists() {
                let mut stderr = io::stderr().lock();
                let _ = writeln!(
                    stderr,
                    "error: refusing to overwrite existing key file '{}' (pass --force to overwrite)",
                    existing.display()
                );
                return ExitCode::FAILURE;
            }
        }
    }
    let key = match Ed25519SigningKey::generate() {
        Ok(k) => k,
        Err(err) => return print_publish_error(&err),
    };
    let pub_encoded = key.verifying_key().to_encoded();
    let sec_encoded = key.to_encoded();

    if let Err(code) =
        write_file_creating_parents(public_path, format!("{pub_encoded}\n").as_bytes())
    {
        return code;
    }
    if let Err(err) = write_secret_file(secret_path, format!("{}\n", *sec_encoded).as_bytes()) {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(
            stderr,
            "error: failed to write secret key '{}': {err}",
            secret_path.display()
        );
        return ExitCode::FAILURE;
    }

    let mut stdout = io::stdout().lock();
    let _ = writeln!(
        stdout,
        "OK: generated Ed25519 publishing key pair (public: '{}', secret: '{}')",
        public_path.display(),
        secret_path.display()
    );
    ExitCode::SUCCESS
}

fn run_sign(
    dir: &Path,
    key_path: &Path,
    output: &Path,
    note: Option<&str>,
    site_id: &str,
    force: bool,
) -> ExitCode {
    let normalized_site_id = site_id.trim().to_ascii_lowercase();
    if normalized_site_id.is_empty()
        || normalized_site_id.len() > 255
        || normalized_site_id
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '/' | '\\'))
    {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(
            stderr,
            "error: --site-id '{site_id}' must be a non-empty identifier without whitespace or slashes (R5-PUB-4)"
        );
        return ExitCode::FAILURE;
    }
    if !force && output.exists() {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(
            stderr,
            "error: refusing to overwrite existing bundle '{}' (pass --force to overwrite)",
            output.display()
        );
        return ExitCode::FAILURE;
    }
    let signing_key = match Ed25519SigningKey::from_file(key_path) {
        Ok(k) => k,
        Err(err) => return print_publish_error(&err),
    };
    let mut bundle = match bundle_from_directory(dir, note.map(str::to_owned)) {
        Ok(b) => b,
        Err(err) => return print_publish_error(&err),
    };
    bundle.site_id = Some(normalized_site_id);
    let file_count = bundle.files.len();
    let manifest_sha = bundle.manifest_sha256_hex();
    let signed = SignedBundle::sign(bundle, &signing_key);

    let json = match serde_json::to_string_pretty(&signed) {
        Ok(j) => j,
        Err(err) => {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(stderr, "error: failed to serialize signed bundle: {err}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(code) = write_file_creating_parents(output, json.as_bytes()) {
        return code;
    }

    let mut stdout = io::stdout().lock();
    let _ = writeln!(
        stdout,
        "OK: signed {file_count} file(s) (manifest sha256: {manifest_sha}) -> '{}'",
        output.display()
    );
    ExitCode::SUCCESS
}

fn run_verify(bundle_path: &Path, pubkey_path: &Path) -> ExitCode {
    let file = match File::open(bundle_path) {
        Ok(f) => f,
        Err(err) => {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(
                stderr,
                "error: failed to open bundle '{}': {err}",
                bundle_path.display()
            );
            return ExitCode::FAILURE;
        }
    };
    if !file.metadata().is_ok_and(|m| m.is_file()) {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(
            stderr,
            "error: bundle '{}' is not a regular file",
            bundle_path.display()
        );
        return ExitCode::FAILURE;
    }
    let mut raw = String::new();
    if let Err(err) = file
        .take(MAX_BUNDLE_JSON_BYTES.saturating_add(1))
        .read_to_string(&mut raw)
    {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(
            stderr,
            "error: failed to read bundle '{}': {err}",
            bundle_path.display()
        );
        return ExitCode::FAILURE;
    }
    if (raw.len() as u64) > MAX_BUNDLE_JSON_BYTES {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(
            stderr,
            "error: bundle '{}' exceeds maximum verification size of {MAX_BUNDLE_JSON_BYTES} bytes",
            bundle_path.display()
        );
        return ExitCode::FAILURE;
    }
    let signed: SignedBundle = match serde_json::from_str(&raw) {
        Ok(b) => b,
        Err(err) => {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(stderr, "error: invalid signed bundle JSON: {err}");
            return ExitCode::FAILURE;
        }
    };
    let vk = match Ed25519VerifyingKey::from_file(pubkey_path) {
        Ok(k) => k,
        Err(err) => return print_publish_error(&err),
    };
    match signed.verify(&vk) {
        Ok(manifest_sha) => {
            let mut stdout = io::stdout().lock();
            let _ = writeln!(
                stdout,
                "OK: valid Ed25519 signature (files: {}, manifest sha256: {manifest_sha})",
                signed.bundle.files.len()
            );
            ExitCode::SUCCESS
        }
        Err(err) => print_publish_error(&err),
    }
}

#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
fn run_deploy(
    dir: &Path,
    config_path: Option<&Path>,
    site_host: Option<&str>,
    storage: Option<&Path>,
    key_path: Option<&Path>,
    pubkey_path: Option<&Path>,
    note: Option<&str>,
    keep_versions: u32,
    no_inline_scripts: bool,
    allow_unconfigured_policy: bool,
    allow_timestamp_reset: bool,
    format: OutputFormat,
) -> ExitCode {
    // §4 Q4 (`R2-PUB-6`): Require `--config` (and `--site` when multiple sites exist) by default
    // so CLI deploys never bypass site signing or preflight rules unless explicitly opted out!
    if config_path.is_none() && !allow_unconfigured_policy {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(
            stderr,
            "error: `miraserve publish deploy` requires --config <KDL> (and --site <SITE> when multiple sites exist) so site signing and preflight policies are enforced; pass --allow-unconfigured-policy only for standalone/dev storage"
        );
        return ExitCode::FAILURE;
    }

    let (cfg, canonical_site_id) = match resolve_publish_config(
        config_path,
        site_host,
        storage,
        pubkey_path,
        keep_versions,
        no_inline_scripts,
    ) {
        Ok(c) => c,
        Err(msg) => {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(stderr, "error: {msg}");
            return ExitCode::FAILURE;
        }
    };

    let store = match ReleaseStore::open_for_site(cfg, canonical_site_id.clone()) {
        Ok(s) => s,
        Err(err) => return print_publish_error(&err),
    };

    let mut bundle = match bundle_from_directory(dir, note.map(str::to_owned)) {
        Ok(b) => b,
        Err(err) => return print_publish_error(&err),
    };
    bundle.site_id = canonical_site_id;
    // Ensure consecutive CLI deploys invoked within the same wall-clock second receive a
    // strictly monotonic timestamp before signing (`R3-PUB-5`), unless resetting clock skew.
    if !allow_timestamp_reset {
        let prev_ts = store.latest_created_at_unix();
        if prev_ts >= bundle.created_at_unix && prev_ts.saturating_sub(bundle.created_at_unix) < 60
        {
            bundle.created_at_unix = prev_ts.saturating_add(1);
        }
    }

    let signed = if let Some(kp) = key_path {
        let sk = match Ed25519SigningKey::from_file(kp) {
            Ok(k) => k,
            Err(err) => return print_publish_error(&err),
        };
        SignedBundle::sign(bundle, &sk)
    } else {
        SignedBundle {
            bundle,
            signature_b64: None,
        }
    };

    match store.publish_with_options(&signed, allow_timestamp_reset) {
        Ok(meta) => {
            let mut stdout = io::stdout().lock();
            match format {
                OutputFormat::Json => {
                    if let Ok(json) = serde_json::to_string_pretty(&meta) {
                        let _ = writeln!(stdout, "{json}");
                    }
                }
                OutputFormat::Text => {
                    let _ = writeln!(
                        stdout,
                        "OK: published release {} ({} file(s), {} bytes, signed={}, sha256={})",
                        meta.release_id,
                        meta.file_count,
                        meta.total_bytes,
                        meta.signature_verified,
                        meta.manifest_sha256
                    );
                }
            }
            ExitCode::SUCCESS
        }
        Err(err) => print_publish_error(&err),
    }
}

fn run_rollback(
    config_path: Option<&Path>,
    site_host: Option<&str>,
    storage: Option<&Path>,
    release_id: Option<&str>,
    pubkey_path: Option<&Path>,
    format: OutputFormat,
) -> ExitCode {
    let (cfg, canonical_site_id) =
        match resolve_publish_config(config_path, site_host, storage, pubkey_path, 10, false) {
            Ok(c) => c,
            Err(msg) => {
                let mut stderr = io::stderr().lock();
                let _ = writeln!(stderr, "error: {msg}");
                return ExitCode::FAILURE;
            }
        };
    let store = match ReleaseStore::open_existing_for_site(cfg, canonical_site_id) {
        Ok(s) => s,
        Err(err) => return print_publish_error(&err),
    };
    match store.rollback(release_id) {
        Ok(meta) => {
            let mut stdout = io::stdout().lock();
            match format {
                OutputFormat::Json => {
                    if let Ok(json) = serde_json::to_string_pretty(&meta) {
                        let _ = writeln!(stdout, "{json}");
                    }
                }
                OutputFormat::Text => {
                    let _ = writeln!(
                        stdout,
                        "OK: rolled back active release to {} (sha256={})",
                        meta.release_id, meta.manifest_sha256
                    );
                }
            }
            ExitCode::SUCCESS
        }
        Err(err) => print_publish_error(&err),
    }
}

#[derive(Debug, Serialize)]
struct ReleaseListReport {
    active_release_id: Option<String>,
    releases: Vec<miraserve_publish::ReleaseMetadata>,
}

fn run_list(storage: &Path, format: OutputFormat) -> ExitCode {
    let store = match open_store_read_only(storage) {
        Ok(s) => s,
        Err(err) => return print_publish_error(&err),
    };
    let active_id = store.active_release().map(|r| r.release_id);
    let releases = store.list_releases();

    let mut stdout = io::stdout().lock();
    match format {
        OutputFormat::Json => {
            let report = ReleaseListReport {
                active_release_id: active_id,
                releases,
            };
            if let Ok(json) = serde_json::to_string_pretty(&report) {
                let _ = writeln!(stdout, "{json}");
            }
        }
        OutputFormat::Text => {
            if releases.is_empty() {
                let _ = writeln!(stdout, "No releases published in '{}'.", storage.display());
            } else {
                for rel in &releases {
                    let marker = if active_id.as_deref() == Some(rel.release_id.as_str()) {
                        "*"
                    } else {
                        " "
                    };
                    let note = rel.note.as_deref().unwrap_or("-");
                    let _ = writeln!(
                        stdout,
                        "{marker} {}  files={}  bytes={}  signed={}  note={note}",
                        rel.release_id, rel.file_count, rel.total_bytes, rel.signature_verified
                    );
                }
            }
        }
    }
    ExitCode::SUCCESS
}

#[allow(clippy::too_many_arguments)]
fn run_resign(
    config_path: Option<&Path>,
    site_host: Option<&str>,
    storage: Option<&Path>,
    key_path: &Path,
    pubkey_path: Option<&Path>,
    old_pubkey_path: Option<&Path>,
    include_unsigned: bool,
    rebind_site_id: bool,
    from_site_id: Option<&str>,
    release_id: Option<&str>,
    format: OutputFormat,
) -> ExitCode {
    // §4 Q4 (`R2-PUB-7`): Require `--old-pubkey` by default during key rotation/resign so
    // existing signatures are cryptographically verified before re-signing under the new key!
    if old_pubkey_path.is_none() && !include_unsigned {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(
            stderr,
            "error: `miraserve publish resign` requires --old-pubkey <PUBKEY> to cryptographically verify existing signatures before re-signing (or pass --include-unsigned explicitly when migrating unsigned/pre-manifest releases)"
        );
        return ExitCode::FAILURE;
    }

    // R6-PUB-4: `--rebind-site-id` MUST name `--from-site-id <OLD_SITE_ID>` so planted releases
    // from another site sharing the same Ed25519 signing key can never be adopted!
    let rebind_from_site_id = if rebind_site_id {
        let Some(from_id) = from_site_id.map(str::trim).filter(|s| !s.is_empty()) else {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(
                stderr,
                "error: --rebind-site-id requires --from-site-id <OLD_SITE_ID> so only releases bound to the expected prior site-id are migrated (R6-PUB-4)"
            );
            return ExitCode::FAILURE;
        };
        Some(from_id)
    } else if from_site_id.is_some() {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(stderr, "error: --from-site-id requires --rebind-site-id");
        return ExitCode::FAILURE;
    } else {
        None
    };

    let signing_key = match Ed25519SigningKey::from_file(key_path) {
        Ok(k) => k,
        Err(err) => return print_publish_error(&err),
    };
    let old_verifying_key = match old_pubkey_path {
        Some(p) => match Ed25519VerifyingKey::from_file(p) {
            Ok(vk) => Some(vk),
            Err(err) => return print_publish_error(&err),
        },
        None => None,
    };
    let (cfg, canonical_site_id) =
        match resolve_publish_config(config_path, site_host, storage, pubkey_path, 10, false) {
            Ok(c) => c,
            Err(msg) => {
                let mut stderr = io::stderr().lock();
                let _ = writeln!(stderr, "error: {msg}");
                return ExitCode::FAILURE;
            }
        };
    let store = match ReleaseStore::open_existing_for_site(cfg, canonical_site_id) {
        Ok(s) => s,
        Err(err) => return print_publish_error(&err),
    };
    let options = ResignOptions {
        include_unsigned,
        old_verifying_key: old_verifying_key.as_ref(),
        rebind_from_site_id,
    };

    let updated = match release_id {
        Some(id) => match store.resign_release_with_options(id, &signing_key, options) {
            Ok(meta) => vec![meta],
            Err(err) => return print_publish_error(&err),
        },
        None => match store.resign_all_with_options(&signing_key, options) {
            Ok(metas) => metas,
            Err(err) => return print_publish_error(&err),
        },
    };

    let mut stdout = io::stdout().lock();
    match format {
        OutputFormat::Json => {
            if let Ok(json) = serde_json::to_string_pretty(&updated) {
                let _ = writeln!(stdout, "{json}");
            }
        }
        OutputFormat::Text => {
            for meta in &updated {
                let _ = writeln!(
                    stdout,
                    "OK: re-signed release {} (sha256={})",
                    meta.release_id, meta.manifest_sha256
                );
            }
        }
    }
    ExitCode::SUCCESS
}

/// Resolves an [`AiPublishConfig`] either from `--config` (+ optional `--site`) so CLI commands
/// strictly honor the site's configured `keep-versions`, `require-signature`, and preflight rules
/// (`R2-PUB-6`), or from explicit CLI flags when `--config` is omitted.
fn resolve_publish_config(
    config_path: Option<&Path>,
    site_host: Option<&str>,
    storage: Option<&Path>,
    pubkey_path: Option<&Path>,
    keep_versions: u32,
    no_inline_scripts: bool,
) -> Result<(AiPublishConfig, Option<String>), String> {
    if let Some(cfg_path) = config_path {
        let (parsed, _report) = load_file(cfg_path)
            .map_err(|err| format!("failed to load config '{}': {err}", cfg_path.display()))?;
        let pub_sites: Vec<_> = parsed
            .sites
            .iter()
            .filter_map(|s| s.ai_publish.as_ref().map(|p| (s, p)))
            .collect();
        let (site_cfg, chosen) = if let Some(host) = site_host {
            let host_lower = host.to_ascii_lowercase();
            pub_sites
                .into_iter()
                .find(|(s, p)| {
                    p.site_id
                        .as_deref()
                        .is_some_and(|sid| sid.eq_ignore_ascii_case(&host_lower))
                        || s.hosts.iter().any(|h| h.eq_ignore_ascii_case(&host_lower))
                })
                .ok_or_else(|| {
                    format!(
                        "no ai-publish site matching --site '{host}' found in '{}'",
                        cfg_path.display()
                    )
                })?
        } else if pub_sites.len() == 1 {
            pub_sites
                .into_iter()
                .next()
                .ok_or_else(|| "missing ai-publish site".to_owned())?
        } else if pub_sites.is_empty() {
            return Err(format!(
                "no site with `ai-publish` block found in '{}'",
                cfg_path.display()
            ));
        } else {
            return Err(format!(
                "config '{}' defines multiple `ai-publish` sites; specify --site <HOST_OR_SITE_ID>",
                cfg_path.display()
            ));
        };

        let mut cfg = chosen.clone();
        if let Some(st) = storage {
            cfg.storage = st.to_string_lossy().into_owned();
        }
        if let Some(pk) = pubkey_path {
            cfg.require_signature = Some(SignatureRequirement {
                algorithm: SignatureAlgorithm::Ed25519,
                public_key_path: pk.to_string_lossy().into_owned(),
            });
        }
        if no_inline_scripts
            && !cfg
                .preflight_checks
                .contains(&PreflightCheck::NoInlineScripts)
        {
            cfg.preflight_checks.push(PreflightCheck::NoInlineScripts);
        }
        let canonical_site_id = cfg
            .site_id
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .or_else(|| site_cfg.hosts.first().map(|h| h.to_ascii_lowercase()));
        return Ok((cfg, canonical_site_id));
    }

    let Some(storage_dir) = storage else {
        return Err("either --storage <DIR> or --config <KDL> must be specified".to_owned());
    };
    let mut preflight_checks = vec![PreflightCheck::NoSecrets, PreflightCheck::CspValid];
    if no_inline_scripts {
        preflight_checks.push(PreflightCheck::NoInlineScripts);
    }
    Ok((
        AiPublishConfig {
            storage: storage_dir.to_string_lossy().into_owned(),
            site_id: site_host.map(str::to_ascii_lowercase),
            keep_versions: keep_versions.max(1),
            require_signature: pubkey_path.map(|p| SignatureRequirement {
                algorithm: SignatureAlgorithm::Ed25519,
                public_key_path: p.to_string_lossy().into_owned(),
            }),
            jwt_public_key: None,
            jwt_issuer: None,
            allowed_subjects: Vec::new(),
            preflight_checks,
            mcp_endpoint: None,
        },
        site_host.map(str::to_ascii_lowercase),
    ))
}

fn open_store_read_only(storage: &Path) -> Result<ReleaseStore, PublishError> {
    let cfg = AiPublishConfig {
        storage: storage.to_string_lossy().into_owned(),
        site_id: None,
        keep_versions: 10,
        require_signature: None,
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        preflight_checks: Vec::new(),
        mcp_endpoint: None,
    };
    ReleaseStore::open_read_only(cfg)
}

fn write_file_creating_parents(path: &Path, bytes: &[u8]) -> Result<(), ExitCode> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && let Err(err) = fs::create_dir_all(parent)
    {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(
            stderr,
            "error: failed to create directory '{}': {err}",
            parent.display()
        );
        return Err(ExitCode::FAILURE);
    }
    if let Err(err) = fs::write(path, bytes) {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(stderr, "error: failed to write '{}': {err}", path.display());
        return Err(ExitCode::FAILURE);
    }
    Ok(())
}

fn print_publish_error(err: &PublishError) -> ExitCode {
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "error: {err}");
    if let PublishError::PreflightFailed(violations) = err {
        for v in violations {
            let _ = writeln!(stderr, "  - [{}] {}: {}", v.rule, v.path, v.detail);
        }
    }
    ExitCode::FAILURE
}

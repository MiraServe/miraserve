//! Implementation of `miraserve keyd` — the split-privilege TLS signing daemon
//! (Threat Model T2: the inbound resolver delegates signing to keyd).

use std::io::{self, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;
use miraserve_config::{TlsVersion, load_file};
use miraserve_tls::{
    KEYD_AUTH_SECRET_ENV, KeydEndpoint, KeydKeyStore, KeydServer, KeydUnixPeerPolicy,
    build_crypto_provider, generate_dev_certificate, load_keyd_auth_secret_file,
    load_keyd_auth_secret_from_env, resolve_unix_user_uid,
};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

/// CLI arguments for `miraserve keyd`.
#[derive(Debug, Args)]
pub(crate) struct KeydArgs {
    /// IPC socket path (`"/run/miraserve-keyd/keyd.sock"`) or loopback TCP (`"tcp://127.0.0.1:9444"`).
    #[arg(long, default_value = default_socket())]
    pub(crate) socket: String,

    /// Optional MiraServe KDL config file whose global and per-site cert/key pairs should be loaded.
    #[arg(long)]
    pub(crate) config: Option<PathBuf>,

    /// Direct PEM certificate chain file to load into the isolated key vault.
    #[arg(long)]
    pub(crate) cert: Option<PathBuf>,

    /// Direct PEM private key file matching `--cert`.
    #[arg(long)]
    pub(crate) key: Option<PathBuf>,

    /// Comma-separated SNI hostnames bound to `--cert`/`--key`.
    #[arg(long, value_delimiter = ',')]
    pub(crate) hosts: Vec<String>,

    /// Generate an ephemeral ECDSA P-256 dev certificate inside `keyd` when no PEM files are given.
    #[arg(long)]
    pub(crate) dev_tls: bool,

    /// Opt in to signing legacy TLS 1.2 ECDHE `ServerKeyExchange` messages for all keys
    /// (by default, TLS 1.2 signing is permitted ONLY on keys whose config explicitly enables
    /// `compat-tls-1-2` or `min-version "1.2"`).
    #[arg(long)]
    pub(crate) allow_tls12: bool,

    /// Path to a 32-byte (Base64 or 64-hex) shared HMAC-SHA256 IPC auth secret file
    /// (recommended for `tcp://127.0.0.1:<port>` listeners; falls back to
    /// `MIRASERVE_KEYD_AUTH_SECRET` or ephemeral CSPRNG secret).
    #[arg(long)]
    pub(crate) auth_secret_file: Option<PathBuf>,

    /// Authorize a specific unprivileged worker Unix user (username or numeric UID, e.g.
    /// `miraserve`) over a `0660` Unix socket via exact kernel `SO_PEERCRED` UID matching
    /// (`R4-KEYD-1`: `cred.uid() == keyd_uid || cred.uid() == worker_uid`, never authorizing
    /// unrelated processes sharing the worker's group).
    #[arg(long, value_name = "USER_OR_UID")]
    pub(crate) allow_peer_user: Option<String>,

    /// Deprecated: allow Unix socket peers matching `keyd`'s primary GID (`0660` socket).
    /// Prefer `--allow-peer-user <user>` to restrict signing to the exact worker UID (`R4-KEYD-1`).
    #[arg(long)]
    pub(crate) allow_group_peers: bool,

    /// Log level filter (e.g. `"info"`, `"debug"`, `"warn"`, or `RUST_LOG` expression).
    #[arg(long, default_value = "info")]
    pub(crate) log_level: String,
}

#[cfg(unix)]
const fn default_socket() -> &'static str {
    "/run/miraserve-keyd/keyd.sock"
}

#[cfg(not(unix))]
const fn default_socket() -> &'static str {
    "tcp://127.0.0.1:9444"
}

/// Runs the isolated `miraserve-keyd` TLS signing daemon until `SIGINT`/`SIGTERM`.
#[allow(clippy::too_many_lines)]
pub(crate) fn run_keyd(args: &KeydArgs) -> ExitCode {
    use std::io::IsTerminal as _;

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(args.log_level.as_str()));
    let use_ansi = io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_ansi(use_ansi)
        .try_init();

    let endpoint = match KeydEndpoint::parse(&args.socket) {
        Ok(ep) => ep,
        Err(err) => {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(stderr, "error: {err}");
            return ExitCode::FAILURE;
        }
    };

    let explicit_secret = match &args.auth_secret_file {
        Some(path) => match load_keyd_auth_secret_file(path) {
            Ok(secret) => Some(secret),
            Err(err) => {
                let mut stderr = io::stderr().lock();
                let _ = writeln!(
                    stderr,
                    "error: failed to load --auth-secret-file '{}': {err}",
                    path.display()
                );
                return ExitCode::FAILURE;
            }
        },
        None => match load_keyd_auth_secret_from_env() {
            Ok(secret) => secret,
            Err(err) => {
                let mut stderr = io::stderr().lock();
                let _ = writeln!(stderr, "error: {err}");
                return ExitCode::FAILURE;
            }
        },
    };

    if matches!(endpoint, KeydEndpoint::LoopbackTcp(_)) && explicit_secret.is_none() {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(
            stderr,
            "error: loopback TCP keyd listeners require an explicit shared HMAC-SHA256 secret \
             via --auth-secret-file <path> or {KEYD_AUTH_SECRET_ENV} so workers can authenticate"
        );
        return ExitCode::FAILURE;
    }

    let mut store = KeydKeyStore::new();

    if let Some(cfg_path) = &args.config {
        let (cfg, _report) = match load_file(cfg_path) {
            Ok(loaded) => loaded,
            Err(err) => {
                let mut stderr = io::stderr().lock();
                let _ = writeln!(stderr, "error: failed to load config: {err}");
                return ExitCode::FAILURE;
            }
        };
        if let Some(cfg_sock) = &cfg.server.tls.keyd_socket
            && cfg_sock != &args.socket
        {
            warn!(
                cli_socket = %args.socket,
                config_keyd_socket = %cfg_sock,
                "CLI --socket differs from config server.tls.keyd-socket"
            );
        }
        let server_allow_tls12 = args.allow_tls12 || cfg.server.tls.min_version == TlsVersion::V1_2;
        if let (Some(cert), Some(key)) = (&cfg.server.tls.cert, &cfg.server.tls.key)
            && let Err(err) = store.load_pem_pair_with_policy(
                "server-default",
                Vec::new(),
                true,
                cert,
                key,
                server_allow_tls12,
            )
        {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(stderr, "error: failed to load server cert/key: {err}");
            return ExitCode::FAILURE;
        }
        for (idx, site) in cfg.sites.iter().enumerate() {
            if let Some(stls) = &site.tls
                && let (Some(cert), Some(key)) = (&stls.cert, &stls.key)
                && let Err(err) = store.load_pem_pair_with_policy(
                    format!("site-{idx}"),
                    site.hosts.clone(),
                    store.is_empty(),
                    cert,
                    key,
                    args.allow_tls12 || stls.compat_tls_1_2,
                )
            {
                let mut stderr = io::stderr().lock();
                let _ = writeln!(stderr, "error: failed to load site[{idx}] cert/key: {err}");
                return ExitCode::FAILURE;
            }
        }
    }

    match (&args.cert, &args.key) {
        (Some(cert), Some(key)) => {
            if let Err(err) = store.load_pem_pair_with_policy(
                "cli-default",
                args.hosts.clone(),
                true,
                cert,
                key,
                args.allow_tls12,
            ) {
                let mut stderr = io::stderr().lock();
                let _ = writeln!(stderr, "error: failed to load --cert/--key: {err}");
                return ExitCode::FAILURE;
            }
        }
        (Some(_), None) | (None, Some(_)) => {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(stderr, "error: --cert and --key must be provided together");
            return ExitCode::FAILURE;
        }
        (None, None) => {}
    }

    if store.is_empty() && args.dev_tls {
        let provider = build_crypto_provider(true);
        let hosts = if args.hosts.is_empty() {
            vec!["localhost".to_owned()]
        } else {
            args.hosts.clone()
        };
        match generate_dev_certificate(&hosts, &provider) {
            Ok((ck, _pem)) => {
                if let Err(err) = store.insert_certified_key_with_policy(
                    "dev-default",
                    hosts,
                    true,
                    ck,
                    args.allow_tls12,
                ) {
                    let mut stderr = io::stderr().lock();
                    let _ = writeln!(stderr, "error: {err}");
                    return ExitCode::FAILURE;
                }
            }
            Err(err) => {
                let mut stderr = io::stderr().lock();
                let _ = writeln!(stderr, "error: failed to generate dev cert: {err}");
                return ExitCode::FAILURE;
            }
        }
    }

    if store.is_empty() {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(
            stderr,
            "error: no certificates loaded into keyd (pass --cert/--key, --config, or --dev-tls)"
        );
        return ExitCode::FAILURE;
    }

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(err) => {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(stderr, "error: failed to build Tokio runtime: {err}");
            return ExitCode::FAILURE;
        }
    };

    let allow_tls12 = args.allow_tls12;
    let unix_peer_policy = if let Some(peer_user) = &args.allow_peer_user {
        match resolve_unix_user_uid(peer_user) {
            Ok(peer_uid) => KeydUnixPeerPolicy::SameUidOrPeerUid(peer_uid),
            Err(err) => {
                let mut stderr = io::stderr().lock();
                let _ = writeln!(
                    stderr,
                    "error: invalid --allow-peer-user '{peer_user}': {err}"
                );
                return ExitCode::FAILURE;
            }
        }
    } else if args.allow_group_peers {
        warn!(
            "--allow-group-peers is deprecated; prefer --allow-peer-user <worker-user> so only the exact worker UID is authorized (R4-KEYD-1)"
        );
        KeydUnixPeerPolicy::SameUidOrGroup
    } else {
        KeydUnixPeerPolicy::SameUidOnly
    };
    rt.block_on(async move {
        let start_res = KeydServer::start_with_options(
            endpoint,
            store,
            allow_tls12,
            explicit_secret,
            unix_peer_policy,
        )
        .await;

        let running = match start_res {
            Ok(r) => r,
            Err(err) => {
                error!(error = %err, "failed to start miraserve-keyd");
                let mut stderr = io::stderr().lock();
                let _ = writeln!(stderr, "error: {err}");
                return ExitCode::FAILURE;
            }
        };

        info!(
            endpoint = %running.endpoint().to_socket_string(),
            allow_tls12,
            authenticated = running.auth_secret().is_some(),
            "miraserve-keyd ready; awaiting worker signing IPC"
        );

        wait_for_shutdown_signal().await;
        info!(
            signatures_served = running.signatures_served(),
            "shutting down miraserve-keyd"
        );
        running.shutdown().await;
        ExitCode::SUCCESS
    })
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm = signal(SignalKind::terminate()).ok();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("miraserve-keyd received SIGINT");
            }
            () = async {
                if let Some(s) = sigterm.as_mut() {
                    s.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                info!("miraserve-keyd received SIGTERM");
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

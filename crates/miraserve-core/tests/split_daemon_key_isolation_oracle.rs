//! Real-kernel Linux security oracles for `key-isolation "split-daemon"`.
//!
//! Spawns a dedicated worker process (separate from the in-test `KeydServer` and parent observer),
//! synchronizes strictly on readiness and reload barriers with zero timing assumptions, and
//! verifies retained descriptors via `/proc/<worker_pid>/fd` (including a known open control
//! descriptor of the worker so an empty or failed inspection can never pass):
//! 1. Startup and reload under enforcing Linux Landlock LSM: the worker holds no descriptor for
//!    any configured inbound signing key inode after start-up and after reload even when
//!    DAC-readable (`0600`), confined worker `File::open` returns `PermissionDenied`, and fresh
//!    non-resumed TLS 1.3 handshakes succeed via `keyd`.
//! 2. Unsearchable `0000` hidden vault (non-root, verified no DAC override): worker cannot stat or
//!    open the key through the unsearchable vault even before Landlock, serves HTTPS 200 via
//!    `keyd`, holds no descriptor for the signing key after start-up, refuses multi-link static
//!    files (`404`), and fails closed on outside-root custom error pages.
//! 3. Quarantined site whose `basic-auth` users file is a hard link of the server signing key:
//!    the worker's credential inventory skips the aliased entry by metadata `(dev, ino)` and the
//!    worker holds no descriptor for the key inode after start-up while serving the healthy site
//!    via `keyd` and `503` on the quarantined site.

#![cfg(target_os = "linux")]
#![allow(clippy::too_many_lines, clippy::too_many_arguments)]

use std::fs::{self, File};
use std::io::{BufRead as _, BufReader, ErrorKind, Read as _, Write as _};
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[path = "../../miraserve-config/tests/common/mod.rs"]
mod kdl_test_util;
use kdl_test_util::kdl_escape_path;

use bytes::Bytes;
use http::header::HOST;
use http::{Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper_util::rt::TokioIo;
use miraserve_config::{ConfigStore, load_file, parse_kdl};
use miraserve_core::{
    ListenerKind, MiraServeServer, SandboxPolicy, ServerOptions, apply_landlock_current_thread,
};
use miraserve_sandbox::{EnforcementStatus, SandboxError};
use miraserve_tls::{
    KeydEndpoint, KeydKeyStore, KeydServer, build_crypto_provider, generate_dev_certificate,
};
use rustls::client::Resumption;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const CHILD_ENV: &str = "MIRASERVE_SPLITKEY_ORACLE_CHILD";
const BASE_ENV: &str = "MIRASERVE_SPLITKEY_ORACLE_BASE";
const CONTROL_FILE_NAME: &str = "observer-control.fd";

const BARRIER_TIMEOUT: Duration = Duration::from_secs(30);
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const CHILD_EXIT_TIMEOUT: Duration = Duration::from_secs(30);

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn short_socket_temp_root() -> PathBuf {
    let default_tmp = std::env::temp_dir();
    let resolved = fs::canonicalize(&default_tmp).unwrap_or_else(|_| default_tmp.clone());
    if default_tmp.as_os_str().len() <= 52 && resolved.as_os_str().len() <= 52 {
        default_tmp
    } else {
        PathBuf::from("/tmp")
    }
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Result<Self, std::io::Error> {
        let root = short_socket_temp_root();
        let pid = std::process::id();
        let salt = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::from(d.subsec_nanos()) & 0xffff);
        loop {
            let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
            let path = root.join(format!("ms-sk-{tag}-{pid}-{salt:x}-{seq}"));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(err) if err.kind() == ErrorKind::AlreadyExists => {}
                Err(err) => return Err(err),
            }
        }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct RestorePerm(PathBuf);

impl Drop for RestorePerm {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
    }
}

fn kernel_enforces_landlock() -> Result<bool, String> {
    std::thread::spawn(|| -> Result<bool, String> {
        let (cfg, _) = parse_kdl(
            "ll-probe.kdl",
            r#"server { listen "127.0.0.1:8443"; sandbox { landlock #true; seccomp "off" } }"#,
        )
        .map_err(|e| e.to_string())?;
        let mut policy = SandboxPolicy::from_config_with_file(&cfg, None, None);
        policy.finalize_grants().map_err(|e| e.to_string())?;
        match apply_landlock_current_thread(&policy) {
            Ok(EnforcementStatus::Enforced | EnforcementStatus::PartiallyEnforced) => Ok(true),
            Ok(other) => Err(format!("unexpected Landlock probe status: {other:?}")),
            Err(SandboxError::Landlock(msg))
                if msg.contains("kernel does not support Landlock LSM") =>
            {
                Ok(false)
            }
            Err(err) => Err(format!("Landlock kernel probe failed: {err}")),
        }
    })
    .join()
    .map_err(|_| "Landlock probe thread panicked".to_owned())?
}

fn file_identity(path: &Path) -> Result<(u64, u64), std::io::Error> {
    let md = fs::metadata(path)?;
    Ok((md.dev(), md.ino()))
}

fn create_control_file(base: &Path) -> Result<(u64, u64), std::io::Error> {
    let path = base.join(CONTROL_FILE_NAME);
    fs::write(&path, b"worker-observer-control")?;
    file_identity(&path)
}

/// Inspects every descriptor in `/proc/<pid>/fd`.
///
/// Fails on any directory/stat error other than a genuinely vanished fd (`NotFound`), and fails
/// if the worker's known `control_id` descriptor is not observed (so an empty or unreadable procfs
/// inspection can never pass).
fn inspect_worker_fds(
    pid: u32,
    control_id: (u64, u64),
    key_ids: &[(&str, (u64, u64))],
) -> Result<Vec<String>, String> {
    let fd_dir = PathBuf::from(format!("/proc/{pid}/fd"));
    let entries = fs::read_dir(&fd_dir)
        .map_err(|err| format!("failed to read '{}': {err}", fd_dir.display()))?;
    let mut saw_control = false;
    let mut leaked = Vec::new();
    for entry_res in entries {
        let entry = entry_res
            .map_err(|err| format!("failed to read entry in '{}': {err}", fd_dir.display()))?;
        let fd_path = entry.path();
        let md = match fs::metadata(&fd_path) {
            Ok(md) => md,
            Err(err) if err.kind() == ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(format!("failed to stat '{}': {err}", fd_path.display()));
            }
        };
        let id = (md.dev(), md.ino());
        if id == control_id {
            saw_control = true;
        }
        for (label, target_id) in key_ids {
            if id == *target_id {
                let link_target = match fs::read_link(&fd_path) {
                    Ok(p) => p.display().to_string(),
                    Err(err) if err.kind() == ErrorKind::NotFound => "<vanished>".to_owned(),
                    Err(err) => {
                        return Err(format!("failed to readlink '{}': {err}", fd_path.display()));
                    }
                };
                leaked.push(format!(
                    "worker pid {pid} holds open fd {} -> '{}' matching {label} (dev={}, ino={})",
                    entry.file_name().to_string_lossy(),
                    link_target,
                    id.0,
                    id.1
                ));
            }
        }
    }
    if !saw_control {
        return Err(format!(
            "observer did not find known worker control fd (dev={}, ino={}) in '{}'",
            control_id.0,
            control_id.1,
            fd_dir.display()
        ));
    }
    Ok(leaked)
}

fn parse_first_cert_der(pem: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let first = CertificateDer::pem_slice_iter(pem.as_bytes())
        .next()
        .ok_or("no certificate in PEM")??;
    Ok(first.as_ref().to_vec())
}

fn build_non_resuming_tls_connector(
    cert_pems: &[&str],
) -> Result<TlsConnector, Box<dyn std::error::Error>> {
    let provider = build_crypto_provider(true);
    let mut roots = RootCertStore::empty();
    for pem in cert_pems {
        for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            roots.add(cert?)?;
        }
    }
    let mut client_cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    client_cfg.resumption = Resumption::disabled();
    Ok(TlsConnector::from(Arc::new(client_cfg)))
}

async fn https_get_with_peer_cert(
    addr: SocketAddr,
    host: &str,
    path: &str,
    connector: &TlsConnector,
) -> Result<(StatusCode, Option<String>, String, Vec<u8>), Box<dyn std::error::Error>> {
    tokio::time::timeout(HTTP_TIMEOUT, async {
        let tcp = TcpStream::connect(addr).await?;
        let server_name = ServerName::try_from(host.to_owned())?;
        let tls = connector.connect(server_name, tcp).await?;
        let peer_leaf = tls
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(|c| c.as_ref().to_vec())
            .ok_or("missing peer certificate")?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = Request::builder()
            .uri(path)
            .header(HOST, host)
            .body(Empty::<Bytes>::new())?;
        let resp = sender.send_request(req).await?;
        let status = resp.status();
        let gen_hdr = resp
            .headers()
            .get("x-split-gen")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = resp.into_body().collect().await?.to_bytes();
        Ok((
            status,
            gen_hdr,
            String::from_utf8_lossy(&body).into_owned(),
            peer_leaf,
        ))
    })
    .await
    .map_err(|_| format!("timed out after {HTTP_TIMEOUT:?} on HTTPS GET {host}{path}"))?
}

fn write_split_config(
    cfg_path: &Path,
    keyd_sock: &Path,
    server_cert: &Path,
    server_key: &Path,
    ordinary_cert: &Path,
    ordinary_key: &Path,
    server_root: &Path,
    ordinary_root: &Path,
    owner_dir: &Path,
    tenant_root: &Path,
    gen_tag: &str,
) -> std::io::Result<()> {
    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443" protocols="h1"
    tls {{
        min-version "1.3"
        pqc-hybrid #true
        key-isolation "split-daemon"
        keyd-socket "{keyd_sock}"
        cert "{server_cert}"
        key "{server_key}"
    }}
    sandbox {{
        landlock #true
        seccomp "strict"
    }}
}}
site "server.split.test" {{
    root "{server_root}"
    headers {{ set "X-Split-Gen" "{gen_tag}" }}
}}
site "ordinary.split.test" {{
    root "{ordinary_root}"
    tls {{
        cert "{ordinary_cert}"
        key "{ordinary_key}"
    }}
    headers {{ set "X-Split-Gen" "{gen_tag}" }}
}}
site "tenant.split.test" {{
    owner-dir "{owner_dir}"
    root "{tenant_root}"
    headers {{ set "X-Split-Gen" "{gen_tag}" }}
}}
"#,
        keyd_sock = kdl_escape_path(keyd_sock),
        server_cert = kdl_escape_path(server_cert),
        server_key = kdl_escape_path(server_key),
        ordinary_cert = kdl_escape_path(ordinary_cert),
        ordinary_key = kdl_escape_path(ordinary_key),
        server_root = kdl_escape_path(server_root),
        ordinary_root = kdl_escape_path(ordinary_root),
        owner_dir = kdl_escape_path(owner_dir),
        tenant_root = kdl_escape_path(tenant_root),
    );
    let tmp_path = cfg_path.with_extension("kdl.tmp");
    fs::write(&tmp_path, kdl)?;
    fs::rename(&tmp_path, cfg_path)
}

fn recv_line_bounded(
    rx: &mpsc::Receiver<String>,
    label: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    rx.recv_timeout(BARRIER_TIMEOUT)
        .map_err(|err| format!("timed out waiting for worker '{label}': {err}").into())
}

fn wait_child_bounded(
    child: &mut Child,
    timeout: Duration,
) -> Result<Option<ExitStatus>, std::io::Error> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        std::thread::sleep(remaining.min(Duration::from_millis(10)));
    }
}

fn run_confined_worker_child(base: &Path) -> TestResult {
    let control_fd = File::open(base.join(CONTROL_FILE_NAME))?;
    let cfg_path = base.join("conf").join("miraserve.kdl");
    let vault_dir = base.join("vault");
    let server_key = vault_dir.join("server.key");
    let ordinary_key = vault_dir.join("ordinary.key");

    let (mut cfg, _) = load_file(&cfg_path)?;
    if let Some(listener) = cfg.server.listeners.first_mut() {
        listener.addr.port = 0;
    }
    let mut policy = SandboxPolicy::from_config_with_file(&cfg, Some(&cfg_path), None);
    policy.finalize_grants()?;
    let policy_arc = Arc::new(policy);

    let worker_policy = Arc::clone(&policy_arc);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .on_thread_start(move || {
            if let Err(err) = apply_landlock_current_thread(&worker_policy) {
                eprintln!("worker thread Landlock failed: {err}");
                std::process::abort();
            }
        })
        .build()?;

    let store = Arc::new(ConfigStore::new(cfg));
    let options = ServerOptions {
        dev_tls: false,
        config_path: Some(cfg_path.clone()),
        apply_sandbox: true,
        startup_sandbox_policy: Some(Arc::clone(&policy_arc)),
        ..ServerOptions::default()
    };

    rt.block_on(async move {
        let server = MiraServeServer::start(store, options).await?;
        let report = server
            .sandbox_report()
            .ok_or("expected active SandboxReport in confined worker")?;
        if !matches!(
            report.landlock,
            EnforcementStatus::Enforced | EnforcementStatus::PartiallyEnforced
        ) {
            return Err(format!("Landlock not enforced in worker: {:?}", report.landlock).into());
        }
        let https_port = server
            .bound_listeners()
            .iter()
            .find(|b| b.kind == ListenerKind::HttpsTcp)
            .ok_or("missing HTTPS listener")?
            .local_addr
            .port();

        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "READY {https_port}")?;
        stdout.flush()?;

        let stdin = std::io::stdin();
        let lines = BufReader::new(stdin.lock()).lines();
        for line_res in lines {
            let cmd = line_res?;
            match cmd.trim() {
                "PROBE_OPEN" => {
                    for (label, path) in [
                        ("server.tls.key", &server_key),
                        ("site[1].tls.key", &ordinary_key),
                    ] {
                        match File::open(path) {
                            Ok(_) => {
                                writeln!(
                                    stdout,
                                    "PROBE_OPEN_ERR confined worker opened {label} '{}'",
                                    path.display()
                                )?;
                                stdout.flush()?;
                                return Err(format!(
                                    "confined worker unexpectedly opened {label} '{}'",
                                    path.display()
                                )
                                .into());
                            }
                            Err(err) if err.kind() == ErrorKind::PermissionDenied => {}
                            Err(err) => {
                                writeln!(
                                    stdout,
                                    "PROBE_OPEN_ERR unexpected open error on {label}: {err}"
                                )?;
                                stdout.flush()?;
                                return Err(format!(
                                    "expected PermissionDenied opening {label}, got: {err}"
                                )
                                .into());
                            }
                        }
                    }
                    writeln!(stdout, "PROBE_OPEN_OK")?;
                    stdout.flush()?;
                }
                "RELOAD" => {
                    let generation = server.reload_from_file(&cfg_path)?;
                    writeln!(stdout, "RELOADED {generation}")?;
                    stdout.flush()?;
                }
                "QUIT" => {
                    break;
                }
                other => {
                    return Err(format!("unknown oracle command: {other:?}").into());
                }
            }
        }
        drop(stdout);
        server.shutdown().await;
        drop(control_fd);
        Ok(())
    })
}

/// Real-kernel Linux security oracle:
/// - Must FAIL on `dd19b94` (worker retains open descriptors to DAC-readable `server.key` and
///   `ordinary.key` in `_credential_handles`).
/// - Must PASS on `work/018-splitkey` (observer confirms worker control fd and observes that the
///   worker holds no descriptor for any configured signing key after start-up and after reload,
///   confined worker `File::open` fails with `PermissionDenied` under Landlock, and
///   server-default, ordinary-site, and `owner-dir` tenant-using-server-pair sites all serve HTTP
///   200 over fresh non-resumed TLS 1.3 signed by `miraserve-keyd`).
#[ignore = "requires Linux kernel enforcing Landlock LSM"]
#[allow(clippy::too_many_lines)]
#[test]
fn split_daemon_worker_holds_no_signing_key_fd_after_startup_and_reload() -> TestResult {
    if std::env::var(CHILD_ENV).as_deref() == Ok("worker") {
        let base =
            PathBuf::from(std::env::var_os(BASE_ENV).ok_or("missing BASE_ENV in worker child")?);
        return run_confined_worker_child(&base);
    }

    assert!(
        kernel_enforces_landlock()?,
        "this ignored security oracle requires a Linux kernel actively enforcing Landlock LSM"
    );

    let tmp = TempDir::new("iso")?;
    let base = &tmp.path;
    let control_id = create_control_file(base)?;
    let certs_dir = base.join("certs");
    let vault_dir = base.join("vault");
    let conf_dir = base.join("conf");
    let keyd_dir = base.join("keyd");
    let server_root = base.join("site-server");
    let ordinary_root = base.join("site-ordinary");
    let owner_dir = base.join("owner-tenant");
    let tenant_root = owner_dir.join("public_html");
    for d in [
        &certs_dir,
        &vault_dir,
        &conf_dir,
        &keyd_dir,
        &server_root,
        &ordinary_root,
        &tenant_root,
    ] {
        fs::create_dir_all(d)?;
    }

    fs::write(server_root.join("index.html"), b"server-ok")?;
    fs::write(ordinary_root.join("index.html"), b"ordinary-ok")?;
    fs::write(tenant_root.join("index.html"), b"tenant-server-pair-ok")?;

    let provider = build_crypto_provider(true);
    let (server_ck, server_pem) = generate_dev_certificate(
        &[
            "server.split.test".to_owned(),
            "tenant.split.test".to_owned(),
        ],
        &provider,
    )?;
    let (ordinary_ck, ordinary_pem) =
        generate_dev_certificate(&["ordinary.split.test".to_owned()], &provider)?;

    let server_cert = certs_dir.join("server.pem");
    let ordinary_cert = certs_dir.join("ordinary.pem");
    let server_key = vault_dir.join("server.key");
    let ordinary_key = vault_dir.join("ordinary.key");
    fs::write(&server_cert, &server_pem.cert_pem)?;
    fs::write(&ordinary_cert, &ordinary_pem.cert_pem)?;
    // Explicitly worker-DAC-readable (0600 owned by test UID) outside every read grant so OS DAC
    // alone cannot make the isolation test pass.
    fs::write(&server_key, server_pem.key_pem.as_str())?;
    fs::write(&ordinary_key, ordinary_pem.key_pem.as_str())?;
    fs::set_permissions(&server_key, fs::Permissions::from_mode(0o600))?;
    fs::set_permissions(&ordinary_key, fs::Permissions::from_mode(0o600))?;

    let server_key_id = file_identity(&server_key)?;
    let ordinary_key_id = file_identity(&ordinary_key)?;
    let key_ids = [
        ("server.tls.key", server_key_id),
        ("site[1].tls.key", ordinary_key_id),
    ];

    let server_leaf_der = parse_first_cert_der(&server_pem.cert_pem)?;
    let ordinary_leaf_der = parse_first_cert_der(&ordinary_pem.cert_pem)?;
    let connector =
        build_non_resuming_tls_connector(&[&server_pem.cert_pem, &ordinary_pem.cert_pem])?;

    let keyd_sock = keyd_dir.join("keyd.sock");
    let cfg_path = conf_dir.join("miraserve.kdl");
    write_split_config(
        &cfg_path,
        &keyd_sock,
        &server_cert,
        &server_key,
        &ordinary_cert,
        &ordinary_key,
        &server_root,
        &ordinary_root,
        &owner_dir,
        &tenant_root,
        "gen1",
    )?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;

    let mut store = KeydKeyStore::new();
    store.insert_certified_key("server-default", Vec::new(), true, server_ck)?;
    store.insert_certified_key(
        "site-ordinary",
        vec!["ordinary.split.test".to_owned()],
        false,
        ordinary_ck,
    )?;
    let keyd = rt.block_on(async {
        KeydServer::start(KeydEndpoint::Unix(keyd_sock.clone()), store, false).await
    })?;

    let exe = std::env::current_exe()?;
    let mut child = Command::new(exe)
        .args([
            "--exact",
            "split_daemon_worker_holds_no_signing_key_fd_after_startup_and_reload",
            "--ignored",
            "--nocapture",
        ])
        .env(CHILD_ENV, "worker")
        .env(BASE_ENV, base)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let child_pid = child.id();
    let mut child_stdin = child.stdin.take().ok_or("missing child stdin")?;
    let child_stdout = child.stdout.take().ok_or("missing child stdout")?;
    let child_stderr = child.stderr.take().ok_or("missing child stderr")?;

    let (line_tx, line_rx) = mpsc::channel::<String>();
    let stdout_reader = std::thread::spawn(move || {
        for line in BufReader::new(child_stdout).lines().map_while(Result::ok) {
            if line.starts_with("READY ")
                || line.starts_with("PROBE_OPEN_")
                || line.starts_with("RELOADED ")
            {
                let _ = line_tx.send(line);
            }
        }
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut buf = String::new();
        let mut err = child_stderr;
        let _ = err.read_to_string(&mut buf);
        buf
    });

    let run_result: TestResult = (|| {
        // Barrier 1: startup readiness.
        let ready = recv_line_bounded(&line_rx, "READY")?;
        let https_port: u16 = ready
            .strip_prefix("READY ")
            .ok_or_else(|| format!("unexpected ready line: {ready:?}"))?
            .trim()
            .parse()?;
        let https_addr = SocketAddr::from(([127, 0, 0, 1], https_port));

        // 1a. Observer checks /proc/<worker_pid>/fd: control fd seen, ZERO key descriptors.
        let leaked_startup = inspect_worker_fds(child_pid, control_id, &key_ids)?;
        assert!(
            leaked_startup.is_empty(),
            "worker holds open private-key descriptor(s) after startup:\n{}",
            leaked_startup.join("\n")
        );

        // 1b. Confined worker attempts File::open on both key paths and must get PermissionDenied.
        writeln!(child_stdin, "PROBE_OPEN")?;
        child_stdin.flush()?;
        let probe1 = recv_line_bounded(&line_rx, "PROBE_OPEN startup")?;
        assert_eq!(probe1, "PROBE_OPEN_OK");

        // 1c. Fresh non-resumed TLS 1.3 requests to server, ordinary, and owner-dir tenant site.
        rt.block_on(async {
            let (s1, g1, b1, c1) =
                https_get_with_peer_cert(https_addr, "server.split.test", "/", &connector).await?;
            assert_eq!(s1, StatusCode::OK);
            assert_eq!(g1.as_deref(), Some("gen1"));
            assert_eq!(b1, "server-ok");
            assert_eq!(c1, server_leaf_der);

            let (s2, g2, b2, c2) =
                https_get_with_peer_cert(https_addr, "ordinary.split.test", "/", &connector)
                    .await?;
            assert_eq!(s2, StatusCode::OK);
            assert_eq!(g2.as_deref(), Some("gen1"));
            assert_eq!(b2, "ordinary-ok");
            assert_eq!(c2, ordinary_leaf_der);

            let (s3, g3, b3, c3) =
                https_get_with_peer_cert(https_addr, "tenant.split.test", "/", &connector).await?;
            assert_eq!(s3, StatusCode::OK);
            assert_eq!(g3.as_deref(), Some("gen1"));
            assert_eq!(b3, "tenant-server-pair-ok");
            assert_eq!(c3, server_leaf_der);
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;
        assert_eq!(
            keyd.signatures_served(),
            3,
            "all three startup handshakes must be signed remotely by keyd"
        );

        // Barrier 2: live config reload.
        write_split_config(
            &cfg_path,
            &keyd_sock,
            &server_cert,
            &server_key,
            &ordinary_cert,
            &ordinary_key,
            &server_root,
            &ordinary_root,
            &owner_dir,
            &tenant_root,
            "gen2",
        )?;
        writeln!(child_stdin, "RELOAD")?;
        child_stdin.flush()?;
        let reloaded = recv_line_bounded(&line_rx, "RELOADED")?;
        assert!(
            reloaded.starts_with("RELOADED "),
            "expected RELOADED acknowledgement, got: {reloaded:?}"
        );

        // 2a. Observer checks /proc/<worker_pid>/fd after reload: control fd seen, ZERO key fds.
        let leaked_reload = inspect_worker_fds(child_pid, control_id, &key_ids)?;
        assert!(
            leaked_reload.is_empty(),
            "worker holds open private-key descriptor(s) after reload:\n{}",
            leaked_reload.join("\n")
        );

        // 2b. Confined worker open probe after reload still fails with PermissionDenied.
        writeln!(child_stdin, "PROBE_OPEN")?;
        child_stdin.flush()?;
        let probe2 = recv_line_bounded(&line_rx, "PROBE_OPEN reload")?;
        assert_eq!(probe2, "PROBE_OPEN_OK");

        // 2c. Fresh non-resumed TLS 1.3 requests after reload serve gen2 and keep using keyd.
        rt.block_on(async {
            let (s1, g1, b1, c1) =
                https_get_with_peer_cert(https_addr, "server.split.test", "/", &connector).await?;
            assert_eq!(s1, StatusCode::OK);
            assert_eq!(g1.as_deref(), Some("gen2"));
            assert_eq!(b1, "server-ok");
            assert_eq!(c1, server_leaf_der);

            let (s2, g2, b2, c2) =
                https_get_with_peer_cert(https_addr, "ordinary.split.test", "/", &connector)
                    .await?;
            assert_eq!(s2, StatusCode::OK);
            assert_eq!(g2.as_deref(), Some("gen2"));
            assert_eq!(b2, "ordinary-ok");
            assert_eq!(c2, ordinary_leaf_der);

            let (s3, g3, b3, c3) =
                https_get_with_peer_cert(https_addr, "tenant.split.test", "/", &connector).await?;
            assert_eq!(s3, StatusCode::OK);
            assert_eq!(g3.as_deref(), Some("gen2"));
            assert_eq!(b3, "tenant-server-pair-ok");
            assert_eq!(c3, server_leaf_der);
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;
        assert_eq!(
            keyd.signatures_served(),
            6,
            "all three post-reload handshakes must be signed remotely by keyd"
        );

        writeln!(child_stdin, "QUIT")?;
        child_stdin.flush()?;
        Ok(())
    })();

    drop(child_stdin);
    let exit_res = wait_child_bounded(&mut child, CHILD_EXIT_TIMEOUT);
    if matches!(exit_res, Ok(None)) {
        let _ = child.kill();
        let _ = child.wait();
    }
    let _ = stdout_reader.join();
    let stderr_text = stderr_reader.join().unwrap_or_default();
    rt.block_on(async {
        keyd.shutdown().await;
    });

    if let Err(err) = run_result {
        return Err(format!("{err}\n--- worker stderr ---\n{stderr_text}").into());
    }
    let status = exit_res?.ok_or("worker child timed out on exit")?;
    assert!(
        status.success(),
        "worker child exited with {status}:\n--- worker stderr ---\n{stderr_text}"
    );
    Ok(())
}

/// Real-kernel Linux security oracle covering an unsearchable `0000` key vault (non-root,
/// verified no `CAP_DAC_OVERRIDE` / `CAP_DAC_READ_SEARCH` before Landlock so the worker cannot
/// stat or open the key through the unsearchable vault): serves fresh non-resumed TLS 1.3 HTTPS
/// 200 via `miraserve-keyd`, holds no descriptor for the signing key after start-up (control fd
/// verified), refuses worker `File::open`, refuses multi-link static files (`404`), and fails
/// closed on outside-root custom error pages.
#[ignore = "requires non-root Linux kernel enforcing Landlock LSM without DAC override (ignored as root)"]
#[allow(clippy::too_many_lines)]
#[test]
fn split_daemon_hidden_vault_serves_and_fails_closed() -> TestResult {
    const CHILD2_ENV: &str = "MIRASERVE_SPLITKEY_ORACLE2_CHILD";

    if std::env::var(CHILD2_ENV).as_deref() == Ok("worker2") {
        let base = PathBuf::from(std::env::var_os(BASE_ENV).ok_or("missing BASE_ENV in worker2")?);
        let control_fd = File::open(base.join(CONTROL_FILE_NAME))?;
        let cfg_path = base.join("conf").join("miraserve.kdl");
        let hidden_key = base.join("vault").join("server.key");

        // Verify BEFORE Landlock that this worker cannot stat or open the key through the
        // unsearchable vault (rules out uid 0, CAP_DAC_OVERRIDE, and CAP_DAC_READ_SEARCH).
        if rustix::process::geteuid().as_raw() == 0 {
            return Err(
                "hidden-vault oracle requires non-root worker (uid 0 bypasses 0000 vault)".into(),
            );
        }
        match fs::metadata(&hidden_key) {
            Err(err) if err.kind() == ErrorKind::PermissionDenied => {}
            other => {
                return Err(format!(
                    "worker cannot stat or open the key through the unsearchable vault: expected DAC stat PermissionDenied before Landlock (no DAC override), got: {other:?}"
                )
                .into());
            }
        }
        match File::open(&hidden_key) {
            Err(err) if err.kind() == ErrorKind::PermissionDenied => {}
            other => {
                return Err(format!(
                    "worker cannot stat or open the key through the unsearchable vault: expected DAC open PermissionDenied before Landlock (no DAC override), got: {other:?}"
                )
                .into());
            }
        }

        let (mut cfg, _) = load_file(&cfg_path)?;
        if let Some(l) = cfg.server.listeners.first_mut() {
            l.addr.port = 0;
        }
        let mut policy = SandboxPolicy::from_config_with_file(&cfg, Some(&cfg_path), None);
        policy.finalize_grants()?;
        let policy_arc = Arc::new(policy);

        let worker_policy = Arc::clone(&policy_arc);
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .on_thread_start(move || {
                if let Err(err) = apply_landlock_current_thread(&worker_policy) {
                    eprintln!("worker2 Landlock failed: {err}");
                    std::process::abort();
                }
            })
            .build()?;

        let store = Arc::new(ConfigStore::new(cfg));
        let options = ServerOptions {
            dev_tls: false,
            config_path: Some(cfg_path),
            apply_sandbox: true,
            startup_sandbox_policy: Some(Arc::clone(&policy_arc)),
            ..ServerOptions::default()
        };

        return rt.block_on(async move {
            let server = MiraServeServer::start(store, options).await?;
            let report = server
                .sandbox_report()
                .ok_or("expected active SandboxReport in worker2")?;
            if !matches!(
                report.landlock,
                EnforcementStatus::Enforced | EnforcementStatus::PartiallyEnforced
            ) {
                return Err(
                    format!("Landlock not enforced in worker2: {:?}", report.landlock).into(),
                );
            }
            let https_port = server
                .bound_listeners()
                .iter()
                .find(|b| b.kind == ListenerKind::HttpsTcp)
                .ok_or("missing HTTPS listener")?
                .local_addr
                .port();

            let mut stdout = std::io::stdout().lock();
            writeln!(stdout, "READY {https_port}")?;
            stdout.flush()?;

            let stdin = std::io::stdin();
            let lines = BufReader::new(stdin.lock()).lines();
            for line_res in lines {
                match line_res?.trim() {
                    "PROBE_OPEN" => {
                        match File::open(&hidden_key) {
                            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                                writeln!(stdout, "PROBE_OPEN_OK")?;
                            }
                            other => {
                                return Err(format!(
                                    "expected PermissionDenied on hidden key, got: {other:?}"
                                )
                                .into());
                            }
                        }
                        stdout.flush()?;
                    }
                    "QUIT" => break,
                    other => return Err(format!("unknown cmd: {other:?}").into()),
                }
            }
            drop(stdout);
            server.shutdown().await;
            drop(control_fd);
            Ok(())
        });
    }

    assert_ne!(
        rustix::process::geteuid().as_raw(),
        0,
        "hidden-vault oracle requires non-root UID without CAP_DAC_OVERRIDE (ignored as root)"
    );
    assert!(
        kernel_enforces_landlock()?,
        "this ignored security oracle requires a Linux kernel actively enforcing Landlock LSM"
    );

    let tmp = TempDir::new("iso2")?;
    let base = &tmp.path;
    let control_id = create_control_file(base)?;
    let certs_dir = base.join("certs");
    let vault_dir = base.join("vault");
    let conf_dir = base.join("conf");
    let keyd_dir = base.join("keyd");
    let site_root = base.join("site");
    let err_dir = base.join("errpages");
    for d in [
        &certs_dir, &vault_dir, &conf_dir, &keyd_dir, &site_root, &err_dir,
    ] {
        fs::create_dir_all(d)?;
    }
    fs::write(site_root.join("index.html"), "hidden-vault-ok")?;
    fs::write(site_root.join("linked.txt"), "multi-link")?;
    fs::hard_link(site_root.join("linked.txt"), base.join("linked-second"))?;
    let outside_404 = err_dir.join("404.html");
    fs::write(&outside_404, "OUTSIDE-CUSTOM-404")?;

    let provider = build_crypto_provider(true);
    let (srv_ck, srv_pem) = generate_dev_certificate(&["hv.split.test".to_owned()], &provider)?;
    let srv_cert = certs_dir.join("server.pem");
    let srv_key = vault_dir.join("server.key");
    fs::write(&srv_cert, &srv_pem.cert_pem)?;
    fs::write(&srv_key, srv_pem.key_pem.as_str())?;
    let key_id = file_identity(&srv_key)?;
    let connector = build_non_resuming_tls_connector(&[&srv_pem.cert_pem])?;

    let keyd_sock = keyd_dir.join("keyd.sock");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let mut kstore = KeydKeyStore::new();
    kstore.insert_certified_key("srv", Vec::new(), true, srv_ck)?;
    let keyd = rt.block_on(async {
        KeydServer::start(KeydEndpoint::Unix(keyd_sock.clone()), kstore, false).await
    })?;

    // Lock vault to 0o000 before spawning worker and verify DAC denies stat on the key through
    // the unsearchable vault.
    fs::set_permissions(&vault_dir, fs::Permissions::from_mode(0o000))?;
    let _restore = RestorePerm(vault_dir);
    match fs::metadata(&srv_key) {
        Err(err) if err.kind() == ErrorKind::PermissionDenied => {}
        other => {
            return Err(format!(
                "test environment bypassed 0000 vault permissions (DAC override active): {other:?}"
            )
            .into());
        }
    }

    let cfg_path = conf_dir.join("miraserve.kdl");
    fs::write(
        &cfg_path,
        format!(
            r#"server {{
    listen "127.0.0.1:8443" protocols="h1"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "{}"
        cert "{}"
        key "{}"
    }}
    sandbox {{
        landlock #true
        seccomp "strict"
    }}
}}
site "hv.split.test" {{
    root "{}"
    error-pages {{ page 404 "{}" }}
}}
"#,
            kdl_escape_path(&keyd_sock),
            kdl_escape_path(&srv_cert),
            kdl_escape_path(&srv_key),
            kdl_escape_path(&site_root),
            kdl_escape_path(&outside_404),
        ),
    )?;

    let exe = std::env::current_exe()?;
    let mut child = Command::new(exe)
        .args([
            "--exact",
            "split_daemon_hidden_vault_serves_and_fails_closed",
            "--ignored",
            "--nocapture",
        ])
        .env(CHILD2_ENV, "worker2")
        .env(BASE_ENV, base)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let child_pid = child.id();
    let mut child_stdin = child.stdin.take().ok_or("missing stdin")?;
    let child_stdout = child.stdout.take().ok_or("missing stdout")?;
    let child_stderr = child.stderr.take().ok_or("missing stderr")?;

    let (tx, rx) = mpsc::channel::<String>();
    let out_reader = std::thread::spawn(move || {
        for line in BufReader::new(child_stdout).lines().map_while(Result::ok) {
            if line.starts_with("READY ") || line.starts_with("PROBE_OPEN_") {
                let _ = tx.send(line);
            }
        }
    });
    let err_reader = std::thread::spawn(move || {
        let mut buf = String::new();
        let mut err = child_stderr;
        let _ = err.read_to_string(&mut buf);
        buf
    });

    let res: TestResult = (|| {
        let ready = recv_line_bounded(&rx, "READY")?;
        let port: u16 = ready
            .strip_prefix("READY ")
            .ok_or("bad READY")?
            .trim()
            .parse()?;
        let addr = SocketAddr::from(([127, 0, 0, 1], port));

        let leaked = inspect_worker_fds(child_pid, control_id, &[("server.tls.key", key_id)])?;
        assert!(leaked.is_empty(), "leaked fds: {leaked:?}");

        writeln!(child_stdin, "PROBE_OPEN")?;
        child_stdin.flush()?;
        assert_eq!(recv_line_bounded(&rx, "PROBE_OPEN")?, "PROBE_OPEN_OK");

        rt.block_on(async {
            let (st, _, body, _) =
                https_get_with_peer_cert(addr, "hv.split.test", "/", &connector).await?;
            assert_eq!(st, StatusCode::OK);
            assert_eq!(body, "hidden-vault-ok");

            let (st, _, _, _) =
                https_get_with_peer_cert(addr, "hv.split.test", "/linked.txt", &connector).await?;
            assert_eq!(st, StatusCode::NOT_FOUND);

            let (st, _, body, _) =
                https_get_with_peer_cert(addr, "hv.split.test", "/missing-page", &connector)
                    .await?;
            assert_eq!(st, StatusCode::NOT_FOUND);
            assert!(
                !body.contains("OUTSIDE-CUSTOM-404"),
                "outside-root custom error page must fail closed on hidden vault: {body}"
            );
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;

        writeln!(child_stdin, "QUIT")?;
        child_stdin.flush()?;
        Ok(())
    })();

    drop(child_stdin);
    let exit_res = wait_child_bounded(&mut child, CHILD_EXIT_TIMEOUT);
    if matches!(exit_res, Ok(None)) {
        let _ = child.kill();
        let _ = child.wait();
    }
    let _ = out_reader.join();
    let stderr_text = err_reader.join().unwrap_or_default();
    rt.block_on(async {
        keyd.shutdown().await;
    });
    if let Err(err) = res {
        return Err(format!("{err}\n--- worker2 stderr ---\n{stderr_text}").into());
    }
    let status = exit_res?.ok_or("worker2 timed out")?;
    assert!(
        status.success(),
        "worker2 exited with {status}:\n--- worker2 stderr ---\n{stderr_text}"
    );
    Ok(())
}

/// Real-kernel Linux oracle for aliased credential-inventory entries:
/// a quarantined `owner-dir` site whose `basic-auth` users file is a hard link of the server
/// signing key.
/// - On `90149ce`, `credential_inventory` opens the hard-linked users file of the quarantined site
///   and the worker retains an open descriptor to the server key inode in `/proc/<pid>/fd`.
/// - On the fixed tip, `credential_inventory` skips the aliased inventory entry by `(dev, ino)`
///   metadata, so the observer sees the worker's control fd and the worker holds no descriptor for
///   the server signing key inode after start-up.
#[allow(clippy::too_many_lines)]
#[test]
fn split_daemon_quarantined_site_hardlinked_users_file_holds_no_key_fd() -> TestResult {
    const CHILD3_ENV: &str = "MIRASERVE_SPLITKEY_ORACLE3_CHILD";

    if std::env::var(CHILD3_ENV).as_deref() == Ok("worker3") {
        let base = PathBuf::from(std::env::var_os(BASE_ENV).ok_or("missing BASE_ENV in worker3")?);
        let control_fd = File::open(base.join(CONTROL_FILE_NAME))?;
        let cfg_path = base.join("conf").join("miraserve.kdl");

        let (mut cfg, _) = load_file(&cfg_path)?;
        if let Some(l) = cfg.server.listeners.first_mut() {
            l.addr.port = 0;
        }
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let store = Arc::new(ConfigStore::new(cfg));
        let options = ServerOptions {
            dev_tls: false,
            config_path: Some(cfg_path),
            apply_sandbox: false,
            ..ServerOptions::default()
        };

        return rt.block_on(async move {
            let server = MiraServeServer::start(store, options).await?;
            let https_port = server
                .bound_listeners()
                .iter()
                .find(|b| b.kind == ListenerKind::HttpsTcp)
                .ok_or("missing HTTPS listener")?
                .local_addr
                .port();

            let mut stdout = std::io::stdout().lock();
            writeln!(stdout, "READY {https_port}")?;
            stdout.flush()?;

            let stdin = std::io::stdin();
            let mut lines = BufReader::new(stdin.lock()).lines();
            if let Some(line_res) = lines.next() {
                match line_res?.trim() {
                    "QUIT" => {}
                    other => return Err(format!("unknown cmd: {other:?}").into()),
                }
            }
            drop(stdout);
            server.shutdown().await;
            drop(control_fd);
            Ok(())
        });
    }

    let tmp = TempDir::new("iso3")?;
    let base = &tmp.path;
    let control_id = create_control_file(base)?;
    let certs_dir = base.join("certs");
    let vault_dir = base.join("vault");
    let conf_dir = base.join("conf");
    let keyd_dir = base.join("keyd");
    let server_root = base.join("site-server");
    let owner_dir = base.join("owner-quarantined");
    for d in [
        &certs_dir,
        &vault_dir,
        &conf_dir,
        &keyd_dir,
        &server_root,
        &owner_dir,
    ] {
        fs::create_dir_all(d)?;
    }
    fs::write(server_root.join("index.html"), b"server-ok")?;

    let provider = build_crypto_provider(true);
    let (srv_ck, srv_pem) = generate_dev_certificate(
        &[
            "server.split.test".to_owned(),
            "quarantined.split.test".to_owned(),
        ],
        &provider,
    )?;
    let srv_cert = certs_dir.join("server.pem");
    let srv_key = vault_dir.join("server.key");
    fs::write(&srv_cert, &srv_pem.cert_pem)?;
    fs::write(&srv_key, srv_pem.key_pem.as_str())?;
    fs::set_permissions(&srv_key, fs::Permissions::from_mode(0o600))?;

    // Hard link of the server signing key configured as a quarantined site's basic-auth users file.
    let q_users = certs_dir.join("q_users.htpasswd");
    fs::hard_link(&srv_key, &q_users)?;
    let key_id = file_identity(&srv_key)?;
    assert_eq!(
        file_identity(&q_users)?,
        key_id,
        "quarantined users file must share inode with server.tls.key"
    );

    let connector = build_non_resuming_tls_connector(&[&srv_pem.cert_pem])?;
    let keyd_sock = keyd_dir.join("keyd.sock");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let mut kstore = KeydKeyStore::new();
    kstore.insert_certified_key("srv", Vec::new(), true, srv_ck)?;
    let keyd = rt.block_on(async {
        KeydServer::start(KeydEndpoint::Unix(keyd_sock.clone()), kstore, false).await
    })?;

    // Missing root inside owner_dir quarantines `quarantined.split.test` automatically at startup.
    let missing_tenant_root = owner_dir.join("missing-public-html");
    let cfg_path = conf_dir.join("miraserve.kdl");
    fs::write(
        &cfg_path,
        format!(
            r#"server {{
    listen "127.0.0.1:8443" protocols="h1"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "{}"
        cert "{}"
        key "{}"
    }}
    sandbox {{
        landlock #false
        seccomp "off"
    }}
}}
site "server.split.test" {{
    root "{}"
}}
site "quarantined.split.test" {{
    owner-dir "{}"
    root "{}"
    basic-auth "{}" realm="Quarantined"
}}
"#,
            kdl_escape_path(&keyd_sock),
            kdl_escape_path(&srv_cert),
            kdl_escape_path(&srv_key),
            kdl_escape_path(&server_root),
            kdl_escape_path(&owner_dir),
            kdl_escape_path(&missing_tenant_root),
            kdl_escape_path(&q_users),
        ),
    )?;

    let exe = std::env::current_exe()?;
    let mut child = Command::new(exe)
        .args([
            "--exact",
            "split_daemon_quarantined_site_hardlinked_users_file_holds_no_key_fd",
            "--nocapture",
        ])
        .env(CHILD3_ENV, "worker3")
        .env(BASE_ENV, base)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let child_pid = child.id();
    let mut child_stdin = child.stdin.take().ok_or("missing stdin")?;
    let child_stdout = child.stdout.take().ok_or("missing stdout")?;
    let child_stderr = child.stderr.take().ok_or("missing stderr")?;

    let (tx, rx) = mpsc::channel::<String>();
    let out_reader = std::thread::spawn(move || {
        for line in BufReader::new(child_stdout).lines().map_while(Result::ok) {
            if line.starts_with("READY ") {
                let _ = tx.send(line);
            }
        }
    });
    let err_reader = std::thread::spawn(move || {
        let mut buf = String::new();
        let mut err = child_stderr;
        let _ = err.read_to_string(&mut buf);
        buf
    });

    let res: TestResult = (|| {
        let ready = recv_line_bounded(&rx, "READY")?;
        let port: u16 = ready
            .strip_prefix("READY ")
            .ok_or("bad READY")?
            .trim()
            .parse()?;
        let addr = SocketAddr::from(([127, 0, 0, 1], port));

        let leaked = inspect_worker_fds(child_pid, control_id, &[("server.tls.key", key_id)])?;
        assert!(
            leaked.is_empty(),
            "worker holds open descriptor to server key inode via quarantined site's hard-linked users file:\n{}",
            leaked.join("\n")
        );

        rt.block_on(async {
            let (st1, _, body1, _) =
                https_get_with_peer_cert(addr, "server.split.test", "/", &connector).await?;
            assert_eq!(st1, StatusCode::OK);
            assert_eq!(body1, "server-ok");

            let (st2, _, _, _) =
                https_get_with_peer_cert(addr, "quarantined.split.test", "/", &connector).await?;
            assert_eq!(
                st2,
                StatusCode::SERVICE_UNAVAILABLE,
                "quarantined site must answer 503"
            );
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;
        assert_eq!(
            keyd.signatures_served(),
            2,
            "both handshakes must be signed remotely by keyd"
        );

        writeln!(child_stdin, "QUIT")?;
        child_stdin.flush()?;
        Ok(())
    })();

    drop(child_stdin);
    let exit_res = wait_child_bounded(&mut child, CHILD_EXIT_TIMEOUT);
    if matches!(exit_res, Ok(None)) {
        let _ = child.kill();
        let _ = child.wait();
    }
    let _ = out_reader.join();
    let stderr_text = err_reader.join().unwrap_or_default();
    rt.block_on(async {
        keyd.shutdown().await;
    });
    if let Err(err) = res {
        return Err(format!("{err}\n--- worker3 stderr ---\n{stderr_text}").into());
    }
    let status = exit_res?.ok_or("worker3 timed out")?;
    assert!(
        status.success(),
        "worker3 exited with {status}:\n--- worker3 stderr ---\n{stderr_text}"
    );
    Ok(())
}

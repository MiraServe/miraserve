//! Enforced Linux Landlock end-to-end tests for installer-only Unix socket typing (0.1.6):
//! 1. Exact FastCGI path pointing at a directory containing a DAC-readable marker outside every
//!    other grant: marker is NOT readable under enforcing Landlock, the site still answers static
//!    requests with 200, a sibling site answers 200, FastCGI to that route fails cleanly (502),
//!    the process stays alive, and exactly one WARN naming path and type is emitted. Also checks
//!    that a `read-tree` sharing the same spelling as an exact FastCGI path gets no socket rule.
//! 2. Same for a symlink to such a directory, a regular file, and a FIFO (must not block).
//! 3. A configured `socket-tree` directory keeps its rule: a late-bound Unix FastCGI socket
//!    created inside it after Landlock confinement works as in 0.1.5.

#![cfg(target_os = "linux")]

use std::fs::{self, OpenOptions};
use std::io::{BufRead as _, BufReader, ErrorKind, Write as _};
use std::net::SocketAddr;
use std::os::unix::fs::{OpenOptionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::header::HOST;
use http::{Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper_util::rt::TokioIo;
use miraserve_config::{ConfigStore, parse_kdl};
use miraserve_core::{
    ListenerKind, MiraServeServer, SandboxPolicy, ServerOptions, apply_landlock_current_thread,
};
use miraserve_fastcgi::protocol::{
    EndRequestBody, RecordType, read_record, write_record, write_stream_records,
};
use miraserve_sandbox::{EnforcementStatus, SandboxError};
use miraserve_tls::build_crypto_provider;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::{TcpStream, UnixListener};
use tokio_rustls::TlsConnector;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const CHILD_ENV: &str = "MIRASERVE_SOCKET_TYPING_E2E_CHILD";
const BASE_ENV: &str = "MIRASERVE_SOCKET_TYPING_E2E_BASE";

fn kdl_escape_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Result<Self, std::io::Error> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "miraserve-socktype-e2e-{tag}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Probes whether the running Linux kernel enforces Landlock LSM by installing a minimal policy on
/// a disposable OS thread (leaving the calling thread unaffected).
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

#[derive(Default)]
struct MsgVisitor {
    message: String,
}

impl tracing::field::Visit for MsgVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            value.clone_into(&mut self.message);
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        }
    }
}

struct WarnCapture(Arc<Mutex<Vec<(tracing::Level, String)>>>);

impl tracing::Subscriber for WarnCapture {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = MsgVisitor::default();
        event.record(&mut visitor);
        if let Ok(mut guard) = self.0.lock() {
            guard.push((*event.metadata().level(), visitor.message));
        }
    }

    fn enter(&self, _span: &tracing::span::Id) {}
    fn exit(&self, _span: &tracing::span::Id) {}
}

fn build_tls_connector(cert_pem: &str) -> Result<TlsConnector, Box<dyn std::error::Error>> {
    let provider = build_crypto_provider(false);
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(cert_pem.as_bytes()) {
        roots.add(cert?)?;
    }
    let client_cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(client_cfg)))
}

async fn https_get(
    addr: SocketAddr,
    host: &str,
    path: &str,
    connector: &TlsConnector,
) -> Result<(StatusCode, String), Box<dyn std::error::Error>> {
    let tcp = TcpStream::connect(addr).await?;
    let server_name = ServerName::try_from(host.to_owned())?;
    let tls = connector.connect(server_name, tcp).await?;
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
    let body = resp.into_body().collect().await?.to_bytes();
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

fn run_child_scenario(test_name: &str, scenario: &str, base: &Path) -> TestResult {
    let exe = std::env::current_exe()?;
    let output = Command::new(exe)
        .args(["--exact", test_name, "--nocapture"])
        .env(CHILD_ENV, scenario)
        .env(BASE_ENV, base)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "child scenario '{scenario}' failed (status={}):\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
        .into());
    }
    Ok(())
}

/// Runs a real confined `MiraServeServer` (ephemeral port 0, no port reservation) with `bad_ep`
/// configured as an exact FastCGI Unix path, checks that Landlock is enforcing, verifies the
/// caller-supplied `verify_denied` closure proves no Landlock rule was granted to `bad_ep`, checks
/// that static requests to both the misconfigured site and a sibling site return 200, checks that
/// FastCGI to the misconfigured route returns 502 without killing the server, and verifies the
/// exact WARN message is emitted ONCE across two Landlock installations.
#[allow(clippy::too_many_lines)]
fn child_run_non_socket_case<F>(
    base: &Path,
    bad_ep: &Path,
    extra_read_tree: Option<&Path>,
    expected_type_label: &str,
    verify_denied: F,
) -> TestResult
where
    F: FnOnce() -> Result<(), String>,
{
    let site_a = base.join("site-a");
    let site_b = base.join("site-b");
    fs::create_dir_all(&site_a)?;
    fs::create_dir_all(&site_b)?;
    fs::write(site_a.join("index.html"), "SITE-A-STATIC-OK")?;
    fs::write(site_a.join("app.php"), "<?php echo 'x'; ?>")?;
    fs::write(site_b.join("index.html"), "SITE-B-SIBLING-OK")?;

    let read_tree_line = extra_read_tree.map_or_else(String::new, |rt| {
        format!("        read-tree \"{}\"\n", kdl_escape_path(rt))
    });
    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443" protocols="h1"
    sandbox {{
        landlock #true
        seccomp "off"
{read_tree_line}    }}
}}
site "a.example.test" {{
    root "{site_a}"
    route "/app.php" {{
        fastcgi-pass "unix:{bad_ep}"
    }}
    route "/*" {{
        static
    }}
}}
site "b.example.test" {{
    root "{site_b}"
    route "/*" {{
        static
    }}
}}
"#,
        site_a = kdl_escape_path(&site_a),
        site_b = kdl_escape_path(&site_b),
        bad_ep = kdl_escape_path(bad_ep),
    );
    let (mut cfg, _) = parse_kdl("socktype.kdl", &kdl)?;
    // Bind ephemeral port 0 directly — no reserve-and-release port race.
    cfg.server
        .listeners
        .first_mut()
        .ok_or("expected listener in fixture")?
        .addr
        .port = 0;

    let events: Arc<Mutex<Vec<(tracing::Level, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let _sub_guard = tracing::subscriber::set_default(WarnCapture(Arc::clone(&events)));

    let policy_for_second_thread = SandboxPolicy::from_config(&cfg, None);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let store = Arc::new(ConfigStore::new(cfg));
        let server = MiraServeServer::start(
            store,
            ServerOptions {
                dev_tls: true,
                apply_sandbox: true,
                ..ServerOptions::default()
            },
        )
        .await?;

        let report = server
            .sandbox_report()
            .ok_or("expected sandbox report when apply_sandbox=true")?;
        if !matches!(
            report.landlock,
            EnforcementStatus::Enforced | EnforcementStatus::PartiallyEnforced
        ) {
            return Err(format!("expected enforcing Landlock, got {:?}", report.landlock).into());
        }

        // Install the same policy on a second thread to verify the WARN is emitted only once per
        // path per process and that per-thread installation reaches the same decision.
        let mut p2 = policy_for_second_thread;
        p2.finalize_grants()?;
        let t2_res = std::thread::spawn(move || -> Result<(), String> {
            let status = apply_landlock_current_thread(&p2).map_err(|e| e.to_string())?;
            if !matches!(
                status,
                EnforcementStatus::Enforced | EnforcementStatus::PartiallyEnforced
            ) {
                return Err(format!(
                    "thread 2 expected enforcing Landlock, got {status:?}"
                ));
            }
            Ok(())
        })
        .join()
        .map_err(|_| "second Landlock thread panicked")?;
        t2_res?;

        // Core security oracle: under enforcing Landlock, no rule was installed for `bad_ep`.
        verify_denied()?;

        let addr = server
            .bound_listeners()
            .iter()
            .find(|l| l.kind == ListenerKind::HttpsTcp)
            .map(|l| l.local_addr)
            .ok_or("expected bound HTTPS listener")?;
        let cert_pem = server
            .dev_cert_pem()
            .ok_or("expected dev TLS certificate PEM")?;
        let connector = build_tls_connector(cert_pem)?;

        // Site with misconfigured FastCGI still answers static requests with 200.
        let (st_a, body_a) = https_get(addr, "a.example.test", "/index.html", &connector).await?;
        assert_eq!(st_a, StatusCode::OK);
        assert_eq!(body_a, "SITE-A-STATIC-OK");

        // Sibling site answers 200.
        let (st_b, body_b) = https_get(addr, "b.example.test", "/index.html", &connector).await?;
        assert_eq!(st_b, StatusCode::OK);
        assert_eq!(body_b, "SITE-B-SIBLING-OK");

        // FastCGI route to non-socket fails cleanly (502) without exiting the process.
        let (st_php, _) = https_get(addr, "a.example.test", "/app.php", &connector).await?;
        assert_eq!(st_php, StatusCode::BAD_GATEWAY);

        // Both sites continue answering 200 after the failed FastCGI attempt.
        let (after_a_status, _) =
            https_get(addr, "a.example.test", "/index.html", &connector).await?;
        assert_eq!(after_a_status, StatusCode::OK);
        let (after_sibling_status, _) =
            https_get(addr, "b.example.test", "/index.html", &connector).await?;
        assert_eq!(after_sibling_status, StatusCode::OK);

        server.shutdown().await;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;

    let expected_warn = format!(
        "exact unix socket path '{}' is not a socket (found {expected_type_label}): no Landlock rule installed for it; FastCGI or keyd requests to it will fail",
        bad_ep.display()
    );
    let captured = events
        .lock()
        .map_err(|_| "warn capture lock poisoned")?
        .clone();
    let matching: Vec<&String> = captured
        .iter()
        .filter(|(lvl, msg)| *lvl == tracing::Level::WARN && msg == &expected_warn)
        .map(|(_, msg)| msg)
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "expected exactly 1 WARN matching `{expected_warn}` across two installations, got {matching:?} (all captured: {captured:?})"
    );
    Ok(())
}

/// Test 1: Exact FastCGI path is a directory containing a DAC-readable marker outside every other
/// grant (plus same check when a `read-tree` shares the exact spelling).
#[test]
fn enforced_landlock_denies_directory_at_exact_fastcgi_path() -> TestResult {
    if let Ok(scenario) = std::env::var(CHILD_ENV) {
        let base = PathBuf::from(std::env::var(BASE_ENV)?);
        let secret_dir = base.join("secret-dir");
        let marker = secret_dir.join("marker.txt");
        return match scenario.as_str() {
            "dir" => child_run_non_socket_case(&base, &secret_dir, None, "directory", || {
                let err = fs::read_to_string(&marker).err().ok_or_else(|| {
                    "SECURITY FAILURE: marker inside exact FastCGI directory was readable under Landlock"
                        .to_owned()
                })?;
                if err.kind() != ErrorKind::PermissionDenied {
                    return Err(format!(
                        "expected PermissionDenied reading marker, got {err:?}"
                    ));
                }
                Ok(())
            }),
            "dir-also-read-tree" => child_run_non_socket_case(
                &base,
                &secret_dir,
                Some(&secret_dir),
                "directory",
                || {
                    let err = fs::read_to_string(&marker).err().ok_or_else(|| {
                        "SECURITY FAILURE: marker inside read-tree sharing exact FastCGI spelling was readable under Landlock"
                            .to_owned()
                    })?;
                    if err.kind() != ErrorKind::PermissionDenied {
                        return Err(format!(
                            "expected PermissionDenied reading marker, got {err:?}"
                        ));
                    }
                    Ok(())
                },
            ),
            other => Err(format!("unknown scenario: {other}").into()),
        };
    }

    if !kernel_enforces_landlock()? {
        eprintln!(
            "skipping enforced_landlock_denies_directory_at_exact_fastcgi_path: host kernel lacks Landlock LSM"
        );
        return Ok(());
    }

    for scenario in ["dir", "dir-also-read-tree"] {
        let tmp = TempDir::new(scenario)?;
        let secret_dir = tmp.path.join("secret-dir");
        fs::create_dir_all(&secret_dir)?;
        let marker = secret_dir.join("marker.txt");
        fs::write(&marker, "SECRET-OUTSIDE-GRANTS")?;
        // Prove the marker is genuinely DAC-readable before confinement.
        assert_eq!(fs::read_to_string(&marker)?, "SECRET-OUTSIDE-GRANTS");

        run_child_scenario(
            "enforced_landlock_denies_directory_at_exact_fastcgi_path",
            scenario,
            &tmp.path,
        )?;
    }
    Ok(())
}

/// Test 2: Exact FastCGI path is a symlink to a directory with a DAC-readable marker, a regular
/// file, or a FIFO (must not block).
#[test]
#[allow(clippy::too_many_lines)]
fn enforced_landlock_denies_symlink_dir_regular_file_and_fifo() -> TestResult {
    if let Ok(scenario) = std::env::var(CHILD_ENV) {
        let base = PathBuf::from(std::env::var(BASE_ENV)?);
        return match scenario.as_str() {
            "symlink-dir" => {
                let link_ep = base.join("link-to-secret");
                let real_marker = base.join("real-secret-dir").join("marker.txt");
                let link_marker = link_ep.join("marker.txt");
                child_run_non_socket_case(&base, &link_ep, None, "directory", || {
                    for p in [&real_marker, &link_marker] {
                        let err = fs::read_to_string(p).err().ok_or_else(|| {
                            format!(
                                "SECURITY FAILURE: marker '{}' was readable through symlinked FastCGI dir",
                                p.display()
                            )
                        })?;
                        if err.kind() != ErrorKind::PermissionDenied {
                            return Err(format!(
                                "expected PermissionDenied reading '{}', got {err:?}",
                                p.display()
                            ));
                        }
                    }
                    Ok(())
                })
            }
            "regular-file" => {
                let secret_file = base.join("secret.txt");
                child_run_non_socket_case(&base, &secret_file, None, "regular file", || {
                    let err = fs::read_to_string(&secret_file).err().ok_or_else(|| {
                        "SECURITY FAILURE: regular file at exact FastCGI path was readable under Landlock"
                            .to_owned()
                    })?;
                    if err.kind() != ErrorKind::PermissionDenied {
                        return Err(format!(
                            "expected PermissionDenied reading regular file, got {err:?}"
                        ));
                    }
                    Ok(())
                })
            }
            "fifo" => {
                let fifo_path = base.join("pipe.fifo");
                child_run_non_socket_case(&base, &fifo_path, None, "FIFO", || {
                    // O_NONBLOCK read open on a FIFO succeeds with no writer when permitted by
                    // Landlock, and fails immediately with EACCES when denied by Landlock.
                    let res = OpenOptions::new()
                        .read(true)
                        .custom_flags(0o4000) // O_NONBLOCK on Linux (x86_64 & aarch64)
                        .open(&fifo_path);
                    let err = res.err().ok_or_else(|| {
                        "SECURITY FAILURE: FIFO at exact FastCGI path was openable under Landlock"
                            .to_owned()
                    })?;
                    if err.kind() != ErrorKind::PermissionDenied {
                        return Err(format!(
                            "expected PermissionDenied opening FIFO, got {err:?}"
                        ));
                    }
                    Ok(())
                })
            }
            other => Err(format!("unknown scenario: {other}").into()),
        };
    }

    if !kernel_enforces_landlock()? {
        eprintln!(
            "skipping enforced_landlock_denies_symlink_dir_regular_file_and_fifo: host kernel lacks Landlock LSM"
        );
        return Ok(());
    }

    // 2a. Symlink to a directory containing a DAC-readable marker.
    {
        let tmp = TempDir::new("symlink-dir")?;
        let real_dir = tmp.path.join("real-secret-dir");
        fs::create_dir_all(&real_dir)?;
        let marker = real_dir.join("marker.txt");
        fs::write(&marker, "SECRET-VIA-SYMLINK")?;
        symlink(&real_dir, tmp.path.join("link-to-secret"))?;
        assert_eq!(fs::read_to_string(&marker)?, "SECRET-VIA-SYMLINK");
        run_child_scenario(
            "enforced_landlock_denies_symlink_dir_regular_file_and_fifo",
            "symlink-dir",
            &tmp.path,
        )?;
    }

    // 2b. Regular file.
    {
        let tmp = TempDir::new("regular-file")?;
        let secret_file = tmp.path.join("secret.txt");
        fs::write(&secret_file, "SECRET-REGULAR-FILE")?;
        assert_eq!(fs::read_to_string(&secret_file)?, "SECRET-REGULAR-FILE");
        run_child_scenario(
            "enforced_landlock_denies_symlink_dir_regular_file_and_fifo",
            "regular-file",
            &tmp.path,
        )?;
    }

    // 2c. FIFO (must not block at open/fstat/install; O_NONBLOCK read open succeeds unconfined).
    {
        let tmp = TempDir::new("fifo")?;
        let fifo_path = tmp.path.join("pipe.fifo");
        let status = Command::new("mkfifo").arg(&fifo_path).status()?;
        assert!(status.success(), "mkfifo failed: {status}");
        let _unconfined = OpenOptions::new()
            .read(true)
            .custom_flags(0o4000)
            .open(&fifo_path)?;
        run_child_scenario(
            "enforced_landlock_denies_symlink_dir_regular_file_and_fifo",
            "fifo",
            &tmp.path,
        )?;
    }

    Ok(())
}

/// Test 3: A configured `socket-tree` directory keeps its Landlock rule: a late-bound Unix FastCGI
/// socket created inside it after confinement works as in 0.1.5.
#[test]
#[allow(clippy::too_many_lines)]
fn enforced_landlock_socket_tree_keeps_rule_for_late_bound_socket() -> TestResult {
    if let Ok(scenario) = std::env::var(CHILD_ENV) {
        assert_eq!(scenario, "socket-tree-late");
        let base = PathBuf::from(std::env::var(BASE_ENV)?);
        let site_root = base.join("www");
        let sock_tree = base.join("php-pools");
        let late_sock = sock_tree.join("late.sock");
        let ungranted = base.join("outside").join("marker.txt");

        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:8443" protocols="h1"
    sandbox {{
        landlock #true
        seccomp "off"
        socket-tree "{sock_tree}"
    }}
}}
site "late.example.test" {{
    root "{site_root}"
    route "/late.php" {{
        fastcgi-pass "unix:{late_sock}"
    }}
}}
"#,
            sock_tree = kdl_escape_path(&sock_tree),
            site_root = kdl_escape_path(&site_root),
            late_sock = kdl_escape_path(&late_sock),
        );
        let (mut cfg, _) = parse_kdl("socket-tree-late.kdl", &kdl)?;
        cfg.server
            .listeners
            .first_mut()
            .ok_or("expected listener in fixture")?
            .addr
            .port = 0;

        let events: Arc<Mutex<Vec<(tracing::Level, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let _sub_guard = tracing::subscriber::set_default(WarnCapture(Arc::clone(&events)));

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(async move {
            let store = Arc::new(ConfigStore::new(cfg));
            let server = MiraServeServer::start(
                store,
                ServerOptions {
                    dev_tls: true,
                    apply_sandbox: true,
                    ..ServerOptions::default()
                },
            )
            .await?;

            let report = server
                .sandbox_report()
                .ok_or("expected sandbox report when apply_sandbox=true")?;
            assert!(
                matches!(
                    report.landlock,
                    EnforcementStatus::Enforced | EnforcementStatus::PartiallyEnforced
                ),
                "expected enforcing Landlock, got {:?}",
                report.landlock
            );
            // Prove Landlock is genuinely enforcing by reading an ungranted marker.
            let ungranted_err = fs::read_to_string(&ungranted)
                .err()
                .ok_or("expected ungranted marker to be denied under Landlock")?;
            assert_eq!(ungranted_err.kind(), ErrorKind::PermissionDenied);

            // Tell unconfined parent that Landlock is now active; wait for parent to bind socket.
            println!("READY");
            std::io::stdout().flush()?;
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            assert_eq!(line.trim(), "BOUND");

            let addr = server
                .bound_listeners()
                .iter()
                .find(|l| l.kind == ListenerKind::HttpsTcp)
                .map(|l| l.local_addr)
                .ok_or("expected bound HTTPS listener")?;
            let cert_pem = server
                .dev_cert_pem()
                .ok_or("expected dev TLS certificate PEM")?;
            let connector = build_tls_connector(cert_pem)?;

            let (status, body) =
                https_get(addr, "late.example.test", "/late.php", &connector).await?;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body, "LATE-SOCKET-OK");

            server.shutdown().await;
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;

        let captured = events
            .lock()
            .map_err(|_| "warn capture lock poisoned")?
            .clone();
        assert!(
            captured
                .iter()
                .all(|(_, msg)| !msg.contains("is not a socket") && !msg.contains("do not exist")),
            "socket-tree + covered absent child must emit no wrong-type or missing-socket warning: {captured:?}"
        );
        return Ok(());
    }

    if !kernel_enforces_landlock()? {
        eprintln!(
            "skipping enforced_landlock_socket_tree_keeps_rule_for_late_bound_socket: host kernel lacks Landlock LSM"
        );
        return Ok(());
    }

    let tmp = TempDir::new("socket-tree-late")?;
    let site_root = tmp.path.join("www");
    let sock_tree = tmp.path.join("php-pools");
    let outside = tmp.path.join("outside");
    fs::create_dir_all(&site_root)?;
    fs::create_dir_all(&sock_tree)?;
    fs::create_dir_all(&outside)?;
    fs::write(site_root.join("late.php"), "<?php echo 'late'; ?>")?;
    fs::write(outside.join("marker.txt"), "OUTSIDE-MARKER")?;
    let late_sock = sock_tree.join("late.sock");
    assert!(!late_sock.exists());

    let exe = std::env::current_exe()?;
    let mut child = Command::new(exe)
        .args([
            "--exact",
            "enforced_landlock_socket_tree_keeps_rule_for_late_bound_socket",
            "--nocapture",
        ])
        .env(CHILD_ENV, "socket-tree-late")
        .env(BASE_ENV, &tmp.path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let child_stdout = child.stdout.take().ok_or("missing child stdout")?;
    let mut child_stdin = child.stdin.take().ok_or("missing child stdin")?;
    let mut reader = BufReader::new(child_stdout);

    // Wait until the confined child signals Landlock is active (no sleep).
    let mut ready_line = String::new();
    loop {
        ready_line.clear();
        let n = reader.read_line(&mut ready_line)?;
        if n == 0 {
            let out = child.wait_with_output()?;
            return Err(format!(
                "child exited before READY (status={}): stderr={}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            )
            .into());
        }
        if ready_line.trim() == "READY" {
            break;
        }
    }

    // Now bind the late FastCGI responder inside `socket-tree` from the unconfined parent.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let responder_handle = rt.block_on(async {
        let listener = UnixListener::bind(&late_sock)?;
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let req_id = loop {
                let rec = read_record(&mut stream).await?;
                if rec.record_type == RecordType::Stdin && rec.content.is_empty() {
                    break rec.request_id;
                }
            };
            let payload = b"Status: 200 OK\r\nContent-Type: text/plain\r\n\r\nLATE-SOCKET-OK";
            write_stream_records(&mut stream, RecordType::Stdout, req_id, payload, true).await?;
            let end = EndRequestBody {
                app_status: 0,
                protocol_status: 0,
            };
            write_record(&mut stream, RecordType::EndRequest, req_id, &end.encode()).await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });
        // Notify confined child that `late.sock` is bound and listening.
        writeln!(child_stdin, "BOUND")?;
        child_stdin.flush()?;
        drop(child_stdin);
        let res = handle.await;
        Ok::<_, Box<dyn std::error::Error>>(res)
    })?;

    let status = child.wait()?;
    let mut err_buf = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        std::io::Read::read_to_string(&mut stderr, &mut err_buf)?;
    }
    if !status.success() {
        return Err(format!("child failed (status={status}): stderr={err_buf}").into());
    }
    responder_handle?.map_err(|e| format!("responder failed: {e}"))?;
    Ok(())
}

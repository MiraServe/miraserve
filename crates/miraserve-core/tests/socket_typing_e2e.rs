//! End-to-end oracle and parity tests for MiraServe 0.1.6 `socket-typing`:
//! - Enforced-Landlock child-process oracle (tenant FastCGI directory & symlink to directory).
//! - Server-level `keyd-socket` directory startup failure (no ruleset installed).
//! - Same-spelling overlap with `read-tree` / sibling `root` / `socket-tree`.
//! - Live reload with wrong-type tenant vs non-tenant exact endpoint (including under `socket-tree`).
//! - Parity: late-bound socket with and without `socket-tree`, relative `unix:pool.sock`, disabled modes.

#![allow(clippy::too_many_lines)]

use std::fs;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use http::header::HOST;
use http::{Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper_util::rt::TokioIo;
use miraserve_config::{ConfigStore, parse_kdl};
#[cfg(target_os = "linux")]
use miraserve_core::CoreError;
use miraserve_core::{ListenerKind, MiraServeServer, ServerOptions};
use miraserve_tls::build_crypto_provider;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn temp_dir(tag: &str) -> Result<PathBuf, std::io::Error> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let path = std::env::temp_dir().join(format!(
        "miraserve-socktype-e2e-{tag}-{}-{nanos}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn reserve_free_port() -> Result<u16, std::io::Error> {
    let sock = StdTcpListener::bind("127.0.0.1:0")?;
    Ok(sock.local_addr()?.port())
}

fn generate_cert(
    dir: &Path,
    hosts: &[&str],
) -> Result<(PathBuf, PathBuf, String), Box<dyn std::error::Error>> {
    fs::create_dir_all(dir)?;
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    let owned_hosts: Vec<String> = hosts.iter().map(|h| (*h).to_owned()).collect();
    let (_, dev_pem) =
        miraserve_tls::generate_dev_certificate(&owned_hosts, &build_crypto_provider(false))?;
    fs::write(&cert_path, &dev_pem.cert_pem)?;
    fs::write(&key_path, &dev_pem.key_pem)?;
    Ok((cert_path, key_path, dev_pem.cert_pem))
}

fn build_h1_tls_connector(cert_pem: &str) -> Result<TlsConnector, Box<dyn std::error::Error>> {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(cert_pem.as_bytes()) {
        roots.add(cert?)?;
    }
    let mut cfg = ClientConfig::builder_with_provider(build_crypto_provider(false))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsConnector::from(Arc::new(cfg)))
}

async fn https_get(
    addr: SocketAddr,
    connector: &TlsConnector,
    host: &str,
    path: &str,
) -> Result<(StatusCode, String), Box<dyn std::error::Error>> {
    let tcp = TcpStream::connect(addr).await?;
    let server_name = ServerName::try_from(host.to_owned())?;
    let tls = connector.connect(server_name, tcp).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
    let conn_task = tokio::spawn(conn);
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .header(HOST, host)
        .body(Empty::<bytes::Bytes>::new())?;
    let resp = sender.send_request(req).await?;
    let status = resp.status();
    let body = resp.into_body().collect().await?.to_bytes();
    drop(sender);
    let _ = conn_task.await;
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

#[cfg(target_os = "linux")]
fn kernel_enforces_landlock() -> Result<bool, String> {
    std::thread::spawn(|| -> Result<bool, String> {
        let (cfg, _) = parse_kdl(
            "ll-probe.kdl",
            r#"server { listen "127.0.0.1:8443"; sandbox { landlock #true; seccomp "off" } }"#,
        )
        .map_err(|e| e.to_string())?;
        let mut policy = miraserve_core::SandboxPolicy::from_config_with_file(&cfg, None, None);
        policy.finalize_grants().map_err(|e| e.to_string())?;
        match miraserve_core::apply_landlock_current_thread(&policy) {
            Ok(
                miraserve_sandbox::EnforcementStatus::Enforced
                | miraserve_sandbox::EnforcementStatus::PartiallyEnforced,
            ) => Ok(true),
            Ok(other) => Err(format!("unexpected Landlock probe status: {other:?}")),
            Err(miraserve_sandbox::SandboxError::Landlock(msg))
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

/// Spawns a tiny minimal FastCGI responder on a Unix domain socket that returns `200 OK` with
/// `response_body` for one request (used to test late-bound sockets and relative `unix:pool.sock`).
#[cfg(target_os = "linux")]
fn spawn_single_shot_fastcgi_unix_server(
    sock_path: &Path,
    response_body: &'static str,
) -> Result<std::thread::JoinHandle<Result<(), String>>, std::io::Error> {
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::UnixListener;

    let listener = UnixListener::bind(sock_path)?;
    Ok(std::thread::spawn(move || -> Result<(), String> {
        let (mut stream, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| format!("set_read_timeout: {e}"))?;
        let mut req_id;
        // Read FastCGI records until empty FCGI_STDIN (type 5, len 0).
        loop {
            let mut hdr = [0_u8; 8];
            stream
                .read_exact(&mut hdr)
                .map_err(|e| format!("read header: {e}"))?;
            let rec_type = hdr[1];
            req_id = u16::from_be_bytes([hdr[2], hdr[3]]);
            let content_len = u16::from_be_bytes([hdr[4], hdr[5]]) as usize;
            let padding_len = hdr[6] as usize;
            let mut payload = vec![0_u8; content_len + padding_len];
            if !payload.is_empty() {
                stream
                    .read_exact(&mut payload)
                    .map_err(|e| format!("read payload: {e}"))?;
            }
            if rec_type == 5 && content_len == 0 {
                break;
            }
        }
        let body = format!("Status: 200 OK\r\nContent-Type: text/plain\r\n\r\n{response_body}");
        let body_bytes = body.as_bytes();
        let [req_hi, req_lo] = req_id.to_be_bytes();
        let [len_hi, len_lo] = u16::try_from(body_bytes.len())
            .map_err(|e| e.to_string())?
            .to_be_bytes();
        let mut out = Vec::new();
        // FCGI_STDOUT (type 6)
        out.extend_from_slice(&[1, 6, req_hi, req_lo, len_hi, len_lo, 0, 0]);
        out.extend_from_slice(body_bytes);
        // Empty FCGI_STDOUT
        out.extend_from_slice(&[1, 6, req_hi, req_lo, 0, 0, 0, 0]);
        // FCGI_END_REQUEST (type 3, 8 bytes payload)
        out.extend_from_slice(&[1, 3, req_hi, req_lo, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        stream
            .write_all(&out)
            .map_err(|e| format!("write response: {e}"))?;
        stream.flush().map_err(|e| format!("flush: {e}"))?;
        Ok(())
    }))
}

#[cfg(target_os = "linux")]
const CHILD_MODE_ENV: &str = "MIRASERVE_SOCKET_TYPING_CHILD_MODE";

/// Oracle (Linux, unprivileged, real kernel Landlock enforcement in a child process):
/// A tenant (`owner-dir`) site whose exact FastCGI path is a directory (or a symlink to a
/// directory) containing a DAC-readable marker file outside every other grant:
/// - On 0.1.5: site is NOT quarantined, Landlock installs a recursive `ReadFile | WriteFile` rule
///   on the directory, and the confined worker CAN read the marker file (test FAILS).
/// - After `socket-typing`: tenant site is quarantined (`503`), healthy sibling serves `200`, and
///   the marker file is NOT readable (`PermissionDenied`) under kernel Landlock enforcement!
#[cfg(target_os = "linux")]
#[test]
fn enforced_landlock_tenant_fastcgi_directory_and_symlink_quarantined_and_marker_denied()
-> TestResult {
    if let Ok(mode) = std::env::var(CHILD_MODE_ENV) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        return rt.block_on(run_enforced_child(&mode));
    }

    if !kernel_enforces_landlock().map_err(|e| -> Box<dyn std::error::Error> { e.into() })? {
        eprintln!("SKIP: host kernel does not enforce Landlock LSM");
        return Ok(());
    }

    let exe = std::env::current_exe()?;
    for mode in [
        "direct_dir",
        "symlink_dir",
        "overlap_read_tree",
        "overlap_sibling_root",
        "overlap_socket_tree",
    ] {
        let out = std::process::Command::new(&exe)
            .args([
                "--exact",
                "enforced_landlock_tenant_fastcgi_directory_and_symlink_quarantined_and_marker_denied",
                "--nocapture",
            ])
            .env(CHILD_MODE_ENV, mode)
            .output()?;
        assert!(
            out.status.success(),
            "enforced Landlock child mode '{mode}' failed (status={:?}):\nstdout:\n{}\nstderr:\n{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn run_enforced_child(mode: &str) -> TestResult {
    use std::os::unix::fs::symlink;

    let base = temp_dir(&format!("child-{mode}"))?;
    let good_root = base.join("good-www");
    let tenant_home = base.join("tenant-home");
    let tenant_root = tenant_home.join("public_html");
    let secret_dir = base.join("outside-secret-dir");
    let marker = secret_dir.join("marker.txt");
    fs::create_dir_all(&good_root)?;
    fs::create_dir_all(&tenant_root)?;
    fs::create_dir_all(&secret_dir)?;
    fs::write(good_root.join("index.html"), b"SIBLING-HEALTHY")?;
    fs::write(tenant_root.join("index.html"), b"TENANT-SHOULD-BE-503")?;
    fs::write(&marker, b"OUTSIDE-MARKER-VALUE")?;

    let (fcgi_path, good_root_for_kdl, extra_sandbox) = match mode {
        "direct_dir" => (secret_dir.clone(), good_root.clone(), String::new()),
        "symlink_dir" => {
            let link = base.join("fcgi-link-to-dir");
            symlink(&secret_dir, &link)?;
            (link, good_root.clone(), String::new())
        }
        "overlap_read_tree" => (
            secret_dir.clone(),
            good_root.clone(),
            format!("read-tree \"{}\"\n", secret_dir.display()),
        ),
        "overlap_sibling_root" => {
            fs::write(secret_dir.join("index.html"), b"SIBLING-HEALTHY")?;
            (secret_dir.clone(), secret_dir.clone(), String::new())
        }
        "overlap_socket_tree" => (
            secret_dir.clone(),
            good_root.clone(),
            format!("socket-tree \"{}\"\n", secret_dir.display()),
        ),
        other => return Err(format!("unknown child mode: {other}").into()),
    };

    let (cert, key, cert_pem) = generate_cert(
        &base.join("tls"),
        &["good.example.test", "evil.example.test"],
    )?;
    let port = reserve_free_port()?;
    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:{port}" protocols="h1"
    tls {{
        cert "{cert}"
        key "{key}"
    }}
    sandbox {{
        landlock #true
        seccomp "off"
        {extra_sandbox}
    }}
}}
site "good.example.test" {{
    root "{good_root}"
}}
site "evil.example.test" {{
    owner-dir "{tenant_home}"
    root "{tenant_root}"
    route "*.php" {{
        fastcgi-pass "unix:{fcgi_path}"
    }}
}}
"#,
        cert = cert.display(),
        key = key.display(),
        good_root = good_root_for_kdl.display(),
        tenant_home = tenant_home.display(),
        tenant_root = tenant_root.display(),
        fcgi_path = fcgi_path.display(),
    );
    let (cfg, _) = parse_kdl("enforced.kdl", &kdl)?;
    let store = Arc::new(ConfigStore::new(cfg));
    let server = MiraServeServer::start(
        Arc::clone(&store),
        ServerOptions {
            apply_sandbox: true,
            ..ServerOptions::default()
        },
    )
    .await?;

    // Confirm Landlock is actually enforced on this process.
    let report = server
        .sandbox_report()
        .ok_or("expected sandbox_report when apply_sandbox=true")?;
    assert!(
        matches!(
            report.landlock,
            miraserve_sandbox::EnforcementStatus::Enforced
                | miraserve_sandbox::EnforcementStatus::PartiallyEnforced
        ),
        "expected enforced Landlock, got: {:?}",
        report.landlock
    );

    // 1. Healthy sibling keeps serving 200; tenant site is quarantined and returns 503.
    let addr = server
        .bound_listeners()
        .iter()
        .find(|l| l.kind == ListenerKind::HttpsTcp)
        .map(|l| l.local_addr)
        .ok_or("missing HTTPS listener")?;
    let connector = build_h1_tls_connector(&cert_pem)?;

    let (good_status, good_body) = https_get(addr, &connector, "good.example.test", "/").await?;
    assert_eq!(good_status, StatusCode::OK);
    assert_eq!(good_body, "SIBLING-HEALTHY");

    let (evil_status, _) = https_get(addr, &connector, "evil.example.test", "/").await?;
    assert_eq!(
        evil_status,
        StatusCode::SERVICE_UNAVAILABLE,
        "tenant site with wrong-type exact FastCGI path must be quarantined (503)"
    );

    // 2. Kernel Landlock enforcement check on the marker file:
    match mode {
        "direct_dir" | "symlink_dir" => {
            let read_err = fs::read_to_string(&marker).err().ok_or(
                "marker inside wrong-type FastCGI directory MUST NOT be readable under Landlock",
            )?;
            assert_eq!(
                read_err.kind(),
                std::io::ErrorKind::PermissionDenied,
                "expected PermissionDenied reading marker, got: {read_err}"
            );
        }
        "overlap_read_tree" | "overlap_sibling_root" => {
            // `read-tree` / sibling docroot kept its RO rule (`ReadFile | ReadDir`): reading and
            // `read_dir` succeed, while writing (`O_WRONLY` / `O_RDWR`) is denied by Landlock (no
            // `WriteFile` leaked from the rejected endpoint role!).
            assert_eq!(fs::read_to_string(&marker)?, "OUTSIDE-MARKER-VALUE");
            let entries: Vec<_> = fs::read_dir(&secret_dir)?.collect();
            assert!(!entries.is_empty(), "RO role must retain ReadDir");
            let write_err = fs::OpenOptions::new()
                .write(true)
                .open(&marker)
                .err()
                .ok_or("overlap RO role must NOT receive WriteFile from rejected FastCGI role")?;
            assert_eq!(write_err.kind(), std::io::ErrorKind::PermissionDenied);
        }
        "overlap_socket_tree" => {
            // `socket-tree` kept its exact 0.1.5 rule (`ReadFile | WriteFile`, without `ReadDir`):
            // reading/writing an existing file succeeds, `read_dir` is denied!
            assert_eq!(fs::read_to_string(&marker)?, "OUTSIDE-MARKER-VALUE");
            let dir_err = fs::read_dir(&secret_dir)
                .err()
                .ok_or("socket-tree must NOT receive ReadDir")?;
            assert_eq!(dir_err.kind(), std::io::ErrorKind::PermissionDenied);
        }
        _ => unreachable!(),
    }

    server.shutdown().await;
    // Cleanup happens outside Landlock? We are confined now, so cleanup best-effort (parent doesn't
    // care; /tmp entries cleaned up on next reboot or if permitted).
    Ok(())
}

/// Oracle (Linux): server-level `keyd-socket` pointing to a directory fails `MiraServeServer::start`
/// with the typed reason and installs NO Landlock ruleset.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_server_keyd_socket_directory_fails_startup_with_typed_reason_and_no_ruleset()
-> TestResult {
    let base = temp_dir("keyd-dir")?;
    let www = base.join("www");
    let keyd_dir = base.join("keyd-is-a-dir");
    let probe_file = base.join("probe.txt");
    fs::create_dir_all(&www)?;
    fs::create_dir_all(&keyd_dir)?;
    fs::write(&probe_file, b"UNCONFINED")?;

    let (cert, key, _) = generate_cert(&base.join("tls"), &["keyd.example.test"])?;
    let port = reserve_free_port()?;
    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:{port}" protocols="h1"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "{keyd_dir}"
        cert "{cert}"
        key "{key}"
    }}
    sandbox {{
        landlock #true
        seccomp "off"
    }}
}}
site "keyd.example.test" {{
    root "{www}"
}}
"#,
        keyd_dir = keyd_dir.display(),
        cert = cert.display(),
        key = key.display(),
        www = www.display(),
    );
    let (cfg, _) = parse_kdl("keyd-dir.kdl", &kdl)?;
    // Run on a disposable thread to verify NoNewPrivs and unconfined reads are completely untouched.
    let probe_clone = probe_file.clone();
    let expected = format!(
        "exact unix endpoint '{}' is not a socket (found directory)",
        keyd_dir.display()
    );
    let res = std::thread::spawn(move || -> Result<(), String> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        let status_before =
            fs::read_to_string("/proc/thread-self/status").map_err(|e| e.to_string())?;
        let nnp_before = status_before
            .lines()
            .find_map(|l| l.strip_prefix("NoNewPrivs:"))
            .map(str::trim)
            .ok_or("missing NoNewPrivs")?
            .to_owned();

        // Notice: `populate_resolver` happens at core/lib.rs:775 BEFORE `finalize_grants` at 1087
        // unless keyd is checked earlier or `from_config_with_file` / `finalize_grants` runs.
        // Here `server.tls.keyd_socket` in `early_policy` fails `open_grant` at core/lib.rs:752
        // (left in `early_policy`), and for `key-isolation "split-daemon"` `populate_resolver`
        // may try to connect to keyd BEFORE line 1087. So ALSO test a non-tenant FastCGI
        // server/site failure that reaches `finalize_grants` at line 1087 directly, AND verify
        // `keyd-socket` via `SandboxPolicy::from_config` + `finalize_grants`!
        let start_res = rt.block_on(MiraServeServer::start(
            Arc::new(ConfigStore::new(cfg)),
            ServerOptions {
                apply_sandbox: true,
                ..ServerOptions::default()
            },
        ));
        let err = start_res
            .err()
            .ok_or("MiraServeServer::start must fail when keyd-socket is a directory")?;
        // Check: does it fail with SandboxError containing `expected`?
        match err {
            CoreError::Sandbox(sbx_err) if sbx_err.to_string().contains(&expected) => {}
            other => {
                return Err(format!(
                    "expected CoreError::Sandbox containing '{expected}', got: {other}"
                ));
            }
        }
        let status_after =
            fs::read_to_string("/proc/thread-self/status").map_err(|e| e.to_string())?;
        let nnp_after = status_after
            .lines()
            .find_map(|l| l.strip_prefix("NoNewPrivs:"))
            .map(str::trim)
            .ok_or("missing NoNewPrivs")?
            .to_owned();
        if nnp_before != nnp_after {
            return Err(format!(
                "NoNewPrivs changed from {nnp_before} to {nnp_after} on failed start"
            ));
        }
        let content = fs::read_to_string(&probe_clone)
            .map_err(|e| format!("process became confined after failed start: {e}"))?;
        if content != "UNCONFINED" {
            return Err(format!("unexpected probe content: {content:?}"));
        }
        Ok(())
    })
    .join()
    .map_err(|_| "keyd startup thread panicked")?;

    let _ = fs::remove_dir_all(&base);
    res.map_err(|msg| -> Box<dyn std::error::Error> { msg.into() })?;
    Ok(())
}

/// Oracle (Linux): reload with a wrong-type exact FastCGI endpoint:
/// 1. Non-tenant site (even beneath an installed `socket-tree`!) -> reload refused with typed
///    reason, previous generation keeps serving.
/// 2. Tenant (`owner-dir`) site -> reload succeeds, only the tenant site is quarantined (`503`),
///    healthy sibling serves updated content.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_reload_with_wrong_type_exact_endpoint_refuses_non_tenant_and_quarantines_tenant()
-> TestResult {
    let base = temp_dir("reload")?;
    let good_root = base.join("good");
    let tenant_home = base.join("tenant-home");
    let tenant_root = tenant_home.join("public_html");
    let sock_tree = base.join("sock-tree");
    let bad_dir_under_tree = sock_tree.join("actually-a-dir");
    fs::create_dir_all(&good_root)?;
    fs::create_dir_all(&tenant_root)?;
    fs::create_dir_all(&bad_dir_under_tree)?;
    fs::write(good_root.join("index.html"), b"GEN-1")?;
    fs::write(tenant_root.join("index.html"), b"TENANT-OK")?;

    let (cert, key, cert_pem) = generate_cert(
        &base.join("tls"),
        &["good.example.test", "bad.example.test"],
    )?;
    let port = reserve_free_port()?;
    let header = format!(
        r#"
server {{
    listen "127.0.0.1:{port}" protocols="h1"
    tls {{
        cert "{cert}"
        key "{key}"
    }}
    sandbox {{
        landlock #true
        seccomp "off"
        socket-tree "{sock_tree}"
    }}
}}
"#,
        cert = cert.display(),
        key = key.display(),
        sock_tree = sock_tree.display(),
    );
    let kdl_v1 = format!(
        "{header}site \"good.example.test\" {{ root \"{}\" }}\n",
        good_root.display()
    );
    let (cfg_v1, _) = parse_kdl("reload-v1.kdl", &kdl_v1)?;
    let server = MiraServeServer::start(
        Arc::new(ConfigStore::new(cfg_v1)),
        ServerOptions {
            apply_sandbox: false,
            ..ServerOptions::default()
        },
    )
    .await?;
    let addr = server
        .bound_listeners()
        .iter()
        .find(|l| l.kind == ListenerKind::HttpsTcp)
        .map(|l| l.local_addr)
        .ok_or("missing HTTPS listener")?;
    let connector = build_h1_tls_connector(&cert_pem)?;

    let (s1, b1) = https_get(addr, &connector, "good.example.test", "/").await?;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(b1, "GEN-1");

    // 1. Non-tenant site with directory under `socket-tree` -> reload REFUSED with typed reason.
    let kdl_non_tenant = format!(
        r#"{header}
site "good.example.test" {{ root "{}" }}
site "bad.example.test" {{
    root "{}"
    route "*.php" {{ fastcgi-pass "unix:{}" }}
}}
"#,
        good_root.display(),
        tenant_root.display(),
        bad_dir_under_tree.display(),
    );
    let refused = server.reload_from_str("reload-non-tenant.kdl", &kdl_non_tenant);
    let expected = format!(
        "exact unix endpoint '{}' is not a socket (found directory)",
        bad_dir_under_tree.display()
    );
    match refused {
        Err(CoreError::Sandbox(err)) => assert!(
            err.to_string().contains(&expected),
            "expected '{expected}', got: {err}"
        ),
        other => return Err(format!("expected CoreError::Sandbox, got: {other:?}").into()),
    }
    // Previous generation still serves (and `bad.example.test` was never published).
    let (s_still, b_still) = https_get(addr, &connector, "good.example.test", "/").await?;
    assert_eq!(s_still, StatusCode::OK);
    assert_eq!(b_still, "GEN-1");

    // 2. Tenant (`owner-dir`) site with the same directory -> reload SUCCEEDS, quarantining ONLY
    //    the tenant site (`503`) while healthy sibling serves updated content (`GEN-2`).
    fs::write(good_root.join("index.html"), b"GEN-2")?;
    let kdl_tenant = format!(
        r#"{header}
site "good.example.test" {{ root "{}" }}
site "bad.example.test" {{
    owner-dir "{}"
    root "{}"
    route "*.php" {{ fastcgi-pass "unix:{}" }}
}}
"#,
        good_root.display(),
        tenant_home.display(),
        tenant_root.display(),
        bad_dir_under_tree.display(),
    );
    server.reload_from_str("reload-tenant.kdl", &kdl_tenant)?;
    let (s_good, b_good) = https_get(addr, &connector, "good.example.test", "/").await?;
    assert_eq!(s_good, StatusCode::OK);
    assert_eq!(b_good, "GEN-2");
    let (s_bad, _) = https_get(addr, &connector, "bad.example.test", "/").await?;
    assert_eq!(s_bad, StatusCode::SERVICE_UNAVAILABLE);

    server.shutdown().await;
    let _ = fs::remove_dir_all(&base);
    Ok(())
}

/// Parity (Linux enforcing Landlock in child): a late-bound Unix FastCGI socket works BOTH with
/// and without a `socket-tree`, and a relative `unix:pool.sock` uses process working directory for
/// both the Landlock grant and the FastCGI client.
#[cfg(target_os = "linux")]
#[test]
fn parity_late_bound_socket_with_and_without_socket_tree_and_relative_unix_socket() -> TestResult {
    const PARITY_CHILD_ENV: &str = "MIRASERVE_SOCKET_PARITY_CHILD_MODE";
    if let Ok(mode) = std::env::var(PARITY_CHILD_ENV) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        return rt.block_on(run_parity_child(&mode));
    }

    if !kernel_enforces_landlock().map_err(|e| -> Box<dyn std::error::Error> { e.into() })? {
        eprintln!("SKIP: host kernel does not enforce Landlock LSM");
        return Ok(());
    }

    let exe = std::env::current_exe()?;
    for mode in ["late_with_tree", "late_without_tree", "relative_cwd"] {
        let out = std::process::Command::new(&exe)
            .args([
                "--exact",
                "parity_late_bound_socket_with_and_without_socket_tree_and_relative_unix_socket",
                "--nocapture",
            ])
            .env(PARITY_CHILD_ENV, mode)
            .output()?;
        assert!(
            out.status.success(),
            "parity child mode '{mode}' failed (status={:?}):\nstdout:\n{}\nstderr:\n{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn run_parity_child(mode: &str) -> TestResult {
    let base = temp_dir(&format!("parity-{mode}"))?;
    let www = base.join("www");
    let sock_dir = base.join("fpm");
    fs::create_dir_all(&www)?;
    fs::create_dir_all(&sock_dir)?;
    fs::write(www.join("index.php"), b"<?php echo 'ok'; ?>")?;

    let (cert, key, cert_pem) = generate_cert(&base.join("tls"), &["php.example.test"])?;
    let port = reserve_free_port()?;

    let (fcgi_spec, sock_file_path, sandbox_extra, bind_before_start) = match mode {
        "late_with_tree" => {
            let p = sock_dir.join("late.sock");
            (
                format!("unix:{}", p.display()),
                p,
                format!("socket-tree \"{}\"\n", sock_dir.display()),
                false,
            )
        }
        "late_without_tree" => {
            let p = sock_dir.join("late-notree.sock");
            (format!("unix:{}", p.display()), p, String::new(), false)
        }
        "relative_cwd" => {
            std::env::set_current_dir(&sock_dir)?;
            (
                "unix:pool.sock".to_owned(),
                sock_dir.join("pool.sock"),
                String::new(),
                true,
            )
        }
        other => return Err(format!("unknown parity mode: {other}").into()),
    };

    let mut fcgi_thread = if bind_before_start {
        Some(spawn_single_shot_fastcgi_unix_server(
            &sock_file_path,
            "FASTCGI-PARITY-OK",
        )?)
    } else {
        None
    };

    // For late-bound socket tests, spawn an UNCONFINED helper thread BEFORE `MiraServeServer::start`
    // applies Landlock on the main thread, so it can `bind()` the Unix socket after Landlock is
    // enforced (simulating PHP-FPM starting after MiraServe).
    let (late_trigger_tx, late_ready_rx, late_handle) = if bind_before_start {
        (None, None, None)
    } else {
        let (trig_tx, trig_rx) = std::sync::mpsc::channel::<()>();
        let (rdy_tx, rdy_rx) = std::sync::mpsc::channel::<Result<(), String>>();
        let late_path = sock_file_path.clone();
        let h = std::thread::spawn(move || -> Result<(), String> {
            trig_rx.recv().map_err(|e| format!("trigger recv: {e}"))?;
            let inner = match spawn_single_shot_fastcgi_unix_server(&late_path, "FASTCGI-PARITY-OK")
            {
                Ok(inner) => {
                    let _ = rdy_tx.send(Ok(()));
                    inner
                }
                Err(err) => {
                    let msg = format!("late bind failed: {err}");
                    let _ = rdy_tx.send(Err(msg.clone()));
                    return Err(msg);
                }
            };
            inner
                .join()
                .map_err(|_| "late inner fcgi thread panicked".to_owned())?
        });
        (Some(trig_tx), Some(rdy_rx), Some(h))
    };

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:{port}" protocols="h1"
    tls {{
        cert "{cert}"
        key "{key}"
    }}
    sandbox {{
        landlock #true
        seccomp "off"
        {sandbox_extra}
    }}
}}
site "php.example.test" {{
    root "{www}"
    route "*.php" {{
        fastcgi-pass "{fcgi_spec}"
    }}
}}
"#,
        cert = cert.display(),
        key = key.display(),
        www = www.display(),
    );
    let (cfg, _) = parse_kdl("parity-fcgi.kdl", &kdl)?;
    let server = MiraServeServer::start(
        Arc::new(ConfigStore::new(cfg)),
        ServerOptions {
            apply_sandbox: true,
            ..ServerOptions::default()
        },
    )
    .await?;

    let report = server
        .sandbox_report()
        .ok_or("expected sandbox_report when apply_sandbox=true")?;
    assert!(
        matches!(
            report.landlock,
            miraserve_sandbox::EnforcementStatus::Enforced
                | miraserve_sandbox::EnforcementStatus::PartiallyEnforced
        ),
        "expected enforced Landlock in parity mode '{mode}', got: {:?}",
        report.landlock
    );

    if let (Some(tx), Some(rx)) = (late_trigger_tx, late_ready_rx) {
        tx.send(())?;
        rx.recv()?
            .map_err(|msg| -> Box<dyn std::error::Error> { msg.into() })?;
    }

    let addr = server
        .bound_listeners()
        .iter()
        .find(|l| l.kind == ListenerKind::HttpsTcp)
        .map(|l| l.local_addr)
        .ok_or("missing HTTPS listener")?;
    let connector = build_h1_tls_connector(&cert_pem)?;

    let (status, body) = https_get(addr, &connector, "php.example.test", "/index.php").await?;
    assert_eq!(status, StatusCode::OK, "mode={mode} body={body:?}");
    assert_eq!(body, "FASTCGI-PARITY-OK");

    if let Some(handle) = fcgi_thread.take() {
        handle
            .join()
            .map_err(|_| "fcgi responder thread panicked")?
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    }
    if let Some(handle) = late_handle {
        handle
            .join()
            .map_err(|_| "late fcgi helper thread panicked")?
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    }
    server.shutdown().await;
    Ok(())
}

/// Oracle + disabled-mode verification (Linux):
/// 1. Non-tenant FastCGI directory fails `MiraServeServer::start` (`apply_sandbox: true`) with
///    the typed reason and installs no Landlock ruleset — including when `landlock #false` (same
///    0.1.5 `finalize_grants` failure path).
/// 2. Direct embedder with `apply_sandbox: false` does NOT take the startup sandbox failure path
///    (0.1.5 parity).
#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_non_tenant_fastcgi_dir_and_disabled_modes_behaviour() -> TestResult {
    let base = temp_dir("disabled-modes")?;
    let www = base.join("www");
    let bad_dir = base.join("fcgi-is-a-dir");
    fs::create_dir_all(&www)?;
    fs::create_dir_all(&bad_dir)?;
    fs::write(www.join("index.html"), b"OK")?;

    let (cert, key, _) = generate_cert(&base.join("tls"), &["mode.example.test"])?;
    let expected = format!(
        "exact unix endpoint '{}' is not a socket (found directory)",
        bad_dir.display()
    );

    // 1. `apply_sandbox: true` with `landlock #false`: still runs `prepare_startup_policy` +
    //    `finalize_grants`, so non-tenant wrong-type endpoint fails with typed reason.
    let port1 = reserve_free_port()?;
    let kdl_ll_off = format!(
        r#"
server {{
    listen "127.0.0.1:{port1}" protocols="h1"
    tls {{ cert "{cert}"; key "{key}" }}
    sandbox {{ landlock #false; seccomp "off" }}
}}
site "mode.example.test" {{
    root "{www}"
    route "*.php" {{ fastcgi-pass "unix:{bad_dir}" }}
}}
"#,
        cert = cert.display(),
        key = key.display(),
        www = www.display(),
        bad_dir = bad_dir.display(),
    );
    let (cfg_off, _) = parse_kdl("ll-off.kdl", &kdl_ll_off)?;
    let err = MiraServeServer::start(
        Arc::new(ConfigStore::new(cfg_off)),
        ServerOptions {
            apply_sandbox: true,
            ..ServerOptions::default()
        },
    )
    .await
    .err()
    .ok_or("apply_sandbox=true with landlock=#false must still refuse wrong-type endpoint")?;
    match err {
        CoreError::Sandbox(sbx) => assert!(
            sbx.to_string().contains(&expected),
            "expected '{expected}', got: {sbx}"
        ),
        other => return Err(format!("expected CoreError::Sandbox, got: {other}").into()),
    }

    // 2. Direct embedder `apply_sandbox: false`: startup does NOT build a SandboxPolicy (0.1.5
    //    parity — starts normally).
    let port2 = reserve_free_port()?;
    let kdl_nosbx = kdl_ll_off.replace(&port1.to_string(), &port2.to_string());
    let (cfg_nosbx, _) = parse_kdl("apply-false.kdl", &kdl_nosbx)?;
    let server = MiraServeServer::start(
        Arc::new(ConfigStore::new(cfg_nosbx)),
        ServerOptions {
            apply_sandbox: false,
            ..ServerOptions::default()
        },
    )
    .await?;
    assert!(server.sandbox_report().is_none());
    server.shutdown().await;

    let _ = fs::remove_dir_all(&base);
    Ok(())
}

/// Parity (non-Linux): macOS/Windows keeps 0.1.5 behaviour byte-for-byte — a directory at a
/// FastCGI unix path neither fails startup nor quarantines a tenant site.
#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn parity_non_linux_server_start_keeps_015_behaviour_for_non_socket_fastcgi() -> TestResult {
    let base = temp_dir("nonlinux-parity")?;
    let tenant_home = base.join("tenant-home");
    let tenant_root = tenant_home.join("public_html");
    let bad_dir = base.join("fcgi-is-a-dir");
    fs::create_dir_all(&tenant_root)?;
    fs::create_dir_all(&bad_dir)?;
    fs::write(tenant_root.join("index.html"), b"NON-LINUX-UNQUARANTINED")?;

    let (cert, key, cert_pem) = generate_cert(&base.join("tls"), &["tenant.example.test"])?;
    let port = reserve_free_port()?;
    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:{port}" protocols="h1"
    tls {{ cert "{cert}"; key "{key}" }}
    sandbox {{ landlock #true; seccomp "off" }}
}}
site "tenant.example.test" {{
    owner-dir "{tenant_home}"
    root "{tenant_root}"
    route "*.php" {{ fastcgi-pass "unix:{bad_dir}" }}
}}
"#,
        cert = cert.display(),
        key = key.display(),
        tenant_home = tenant_home.display(),
        tenant_root = tenant_root.display(),
        bad_dir = bad_dir.display(),
    );
    let (cfg, _) = parse_kdl("nonlinux.kdl", &kdl)?;
    let server = MiraServeServer::start(
        Arc::new(ConfigStore::new(cfg)),
        ServerOptions {
            apply_sandbox: true,
            ..ServerOptions::default()
        },
    )
    .await?;
    let addr = server
        .bound_listeners()
        .iter()
        .find(|l| l.kind == ListenerKind::HttpsTcp)
        .map(|l| l.local_addr)
        .ok_or("missing HTTPS listener")?;
    let connector = build_h1_tls_connector(&cert_pem)?;
    let (status, body) = https_get(addr, &connector, "tenant.example.test", "/").await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "NON-LINUX-UNQUARANTINED");

    server.shutdown().await;
    let _ = fs::remove_dir_all(&base);
    Ok(())
}

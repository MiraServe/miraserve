//! End-to-end Linux seccomp + Landlock tests comparing a systemd-like filter
//! (`RestrictSUIDSGID=yes`, answering `ENOSYS` to `openat2`) against MiraServe's own set-ID
//! seccomp-bpf filter (which allows `openat2`):
//! - Runs with enforcing Landlock whenever the host kernel supports Landlock LSM (and verifies
//!   an ungranted directory stays unreadable); falls back to seccomp-only with an explicit note
//!   only when the container/host kernel lacks Landlock LSM.
//! - Pre-warms a worker blocking-pool thread via a symlink lookup (failing if quiescence times
//!   out) and counts exact entries into `miraserve-static`'s blocking-pool fallback closure for
//!   the measured `HEAD` requests (not scheduler context switches), so reusing an already-existing
//!   blocking-pool thread cannot falsely pass the inline assertion.
//! - Under the systemd-like `ENOSYS` filter, `file-cache` stores nothing and every sequential
//!   `HEAD` enters the static blocking closure (`delta == 5`).
//! - Under MiraServe's own `SeccompMode::Strict` set-ID filter, `file-cache` admits and serves
//!   hits, worker event loops answer warmed `HEAD` lookups inline with `0` blocking-closure
//!   entries and `0` new blocking threads, and set-ID creation via `openat` is denied with `EPERM`.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::fs;
use std::net::TcpListener as StdTcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::header::HOST;
use http::{Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper_util::rt::TokioIo;
use miraserve_config::{ConfigStore, parse_kdl};
use miraserve_core::{
    ListenerKind, MiraServeServer, RunningServer, SandboxPolicy, ServerOptions,
    apply_landlock_current_thread, openat2_refused_advisory, probe_openat2_refused,
};
use miraserve_sandbox::{EnforcementStatus, SandboxError};
use miraserve_tls::build_crypto_provider;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const CHILD_MODE_ENV: &str = "MIRASERVE_E2E_OPENAT2_SECCOMP_CHILD";
const LINUX_ENOSYS: u32 = 38;
const SYS_OPENAT2: i64 = 437;

fn make_temp_dir(tag: &str) -> Result<PathBuf, std::io::Error> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let path = std::env::temp_dir().join(format!(
        "miraserve-openat2-e2e-{tag}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn reserve_free_port() -> Result<u16, std::io::Error> {
    let sock = StdTcpListener::bind("127.0.0.1:0")?;
    Ok(sock.local_addr()?.port())
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

#[derive(Debug, Clone, Copy)]
struct BlockingPoolSnapshot {
    threads: usize,
    all_sleeping: bool,
}

fn read_blocking_pool_snapshot() -> Result<BlockingPoolSnapshot, std::io::Error> {
    let mut threads = 0_usize;
    let mut all_sleeping = true;
    for task in fs::read_dir("/proc/self/task")?.flatten() {
        let comm = fs::read_to_string(task.path().join("comm")).unwrap_or_default();
        if comm.trim() != "tokio-rt-worker" {
            continue;
        }
        threads += 1;
        let status = fs::read_to_string(task.path().join("status")).unwrap_or_default();
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("State:")
                && !rest.trim().starts_with('S')
            {
                all_sleeping = false;
            }
        }
    }
    Ok(BlockingPoolSnapshot {
        threads,
        all_sleeping,
    })
}

fn wait_blocking_pool_quiescent() -> Result<BlockingPoolSnapshot, std::io::Error> {
    let mut snap = read_blocking_pool_snapshot()?;
    for _ in 0..100 {
        if snap.threads > 0 && snap.all_sleeping {
            return Ok(snap);
        }
        std::thread::sleep(Duration::from_millis(10));
        snap = read_blocking_pool_snapshot()?;
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("worker blocking pool did not reach quiescence within 1s: {snap:?}"),
    ))
}

/// Commands executed on a pre-sandbox helper thread (which has no Landlock confinement, mirroring
/// an external deployment/monitoring process on the host while the server threads stay Landlock-
/// confined).
enum HelperCmd {
    SnapshotQuiescent(mpsc::Sender<Result<BlockingPoolSnapshot, String>>),
    WriteFile(PathBuf, Vec<u8>, mpsc::Sender<Result<(), String>>),
    RemoveDirAll(PathBuf, mpsc::Sender<()>),
    Quit,
}

fn spawn_unconfined_helper() -> (mpsc::Sender<HelperCmd>, std::thread::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel::<HelperCmd>();
    let handle = std::thread::spawn(move || {
        while let Ok(cmd) = rx.recv() {
            match cmd {
                HelperCmd::SnapshotQuiescent(reply) => {
                    let _ = reply.send(wait_blocking_pool_quiescent().map_err(|e| e.to_string()));
                }
                HelperCmd::WriteFile(path, bytes, reply) => {
                    let _ = reply.send(fs::write(&path, &bytes).map_err(|e| e.to_string()));
                }
                HelperCmd::RemoveDirAll(path, reply) => {
                    let _ = fs::remove_dir_all(&path);
                    let _ = reply.send(());
                }
                HelperCmd::Quit => break,
            }
        }
    });
    (tx, handle)
}

fn helper_snapshot(tx: &mpsc::Sender<HelperCmd>) -> Result<BlockingPoolSnapshot, String> {
    let (rtx, rrx) = mpsc::channel();
    tx.send(HelperCmd::SnapshotQuiescent(rtx))
        .map_err(|e| e.to_string())?;
    rrx.recv().map_err(|e| e.to_string())?
}

fn helper_write(tx: &mpsc::Sender<HelperCmd>, path: &Path, bytes: &[u8]) -> Result<(), String> {
    let (rtx, rrx) = mpsc::channel();
    tx.send(HelperCmd::WriteFile(
        path.to_path_buf(),
        bytes.to_vec(),
        rtx,
    ))
    .map_err(|e| e.to_string())?;
    rrx.recv().map_err(|e| e.to_string())?
}

fn compile_systemd_enosys_openat2_filter() -> Result<BpfProgram, Box<dyn std::error::Error>> {
    let arch = TargetArch::try_from(std::env::consts::ARCH)?;
    let mut rules = BTreeMap::new();
    rules.insert(SYS_OPENAT2, Vec::new());
    if arch == TargetArch::x86_64 {
        rules.insert(SYS_OPENAT2 | 0x4000_0000, Vec::new());
    }
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(LINUX_ENOSYS),
        arch,
    )?;
    Ok(filter.try_into()?)
}

fn metric_value(prom: &str, metric_line_prefix: &str) -> Option<u64> {
    prom.lines()
        .find(|line| line.starts_with(metric_line_prefix))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|val| val.parse::<u64>().ok())
}

async fn https_request(
    sender: &mut hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
    method: http::Method,
    host: &str,
    path: &str,
) -> Result<(StatusCode, Bytes), Box<dyn std::error::Error>> {
    sender.ready().await?;
    let resp = sender
        .send_request(
            Request::builder()
                .method(method)
                .uri(path)
                .header(HOST, host)
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    let status = resp.status();
    let body = resp.into_body().collect().await?.to_bytes();
    Ok((status, body))
}

fn build_tls_client(cert_pem: &str) -> Result<Arc<ClientConfig>, Box<dyn std::error::Error>> {
    let mut roots = RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert_pem.as_bytes()).collect::<Result<_, _>>()?;
    roots.add_parsable_certificates(certs);
    let mut cli_tls = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cli_tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cli_tls))
}

async fn connect_h1(
    addr: std::net::SocketAddr,
    cli_tls: &Arc<ClientConfig>,
    sni: &'static str,
) -> Result<
    (
        hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
        tokio::task::JoinHandle<Result<(), hyper::Error>>,
    ),
    Box<dyn std::error::Error>,
> {
    let tcp = TcpStream::connect(addr).await?;
    let tls = TlsConnector::from(Arc::clone(cli_tls))
        .connect(ServerName::try_from(sni)?, tcp)
        .await?;
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
    Ok((sender, tokio::spawn(conn)))
}

async fn verify_inline_vs_pool_reuse(
    plain_sender: &mut hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
    helper_tx: &mpsc::Sender<HelperCmd>,
    expect_openat2_allowed: bool,
) -> TestResult {
    const INLINE_PROBES: u64 = 5;

    // 1. Pre-warm the worker's blocking pool with a symlink request (`sym.txt -> inline.txt`).
    //    `openat2(RESOLVE_NO_SYMLINKS)` returns ELOOP so BOTH scenarios take the full resolver on
    //    the worker blocking pool, ensuring >= 1 idle `tokio-rt-worker` thread ALREADY exists
    //    before we test inline `HEAD /inline.txt` (and proving the blocking-closure counter fires).
    let warmup_before = miraserve_static::static_blocking_pool_entries();
    let (st_sym, body_sym) = https_request(
        plain_sender,
        http::Method::GET,
        "plain.openat2.test",
        "/sym.txt",
    )
    .await?;
    assert_eq!(st_sym, StatusCode::OK);
    assert_eq!(body_sym.as_ref(), b"inline-v1");
    let warmup_entries =
        miraserve_static::static_blocking_pool_entries().saturating_sub(warmup_before);
    assert!(
        warmup_entries >= 1,
        "symlink warm-up must enter the static blocking closure at least once (got {warmup_entries})"
    );

    let before = helper_snapshot(helper_tx).map_err(std::io::Error::other)?;
    assert!(
        before.threads >= 1,
        "symlink warm-up must have created at least one worker blocking-pool thread: {before:?}"
    );

    // 2. Issue 5 sequential `HEAD /inline.txt` requests and count exact entries into the static
    //    blocking-pool fallback closure for these measured requests.
    let before_entries = miraserve_static::static_blocking_pool_entries();
    for _ in 0..INLINE_PROBES {
        let (st, body) = https_request(
            plain_sender,
            http::Method::HEAD,
            "plain.openat2.test",
            "/inline.txt",
        )
        .await?;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body.as_ref(), b"");
    }
    let after_entries = miraserve_static::static_blocking_pool_entries();
    let after = helper_snapshot(helper_tx).map_err(std::io::Error::other)?;
    let pool_entries = after_entries.saturating_sub(before_entries);

    if expect_openat2_allowed {
        assert_eq!(
            after.threads, before.threads,
            "with openat2 allowed, worker loop must not spawn blocking threads: before={before:?} after={after:?}"
        );
        assert_eq!(
            pool_entries, 0,
            "with openat2 allowed, worker loop must run HEAD lookups inline with 0 blocking-closure entries (got {pool_entries}): before={before:?} after={after:?}"
        );
    } else {
        assert_eq!(
            pool_entries, INLINE_PROBES,
            "with openat2 refused (ENOSYS), every sequential HEAD must enter the static blocking closure (expected {INLINE_PROBES}, got {pool_entries}): before={before:?} after={after:?}"
        );
    }

    let (st_get, body_get) = https_request(
        plain_sender,
        http::Method::GET,
        "plain.openat2.test",
        "/inline.txt",
    )
    .await?;
    assert_eq!(st_get, StatusCode::OK);
    assert_eq!(body_get.as_ref(), b"inline-v1");
    Ok(())
}

async fn verify_file_cache_behavior(
    cached_sender: &mut hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
    helper_tx: &mpsc::Sender<HelperCmd>,
    cached_file: &Path,
    server: &RunningServer,
    expect_openat2_allowed: bool,
) -> TestResult {
    let (st1, body1) = https_request(
        cached_sender,
        http::Method::GET,
        "cached.openat2.test",
        "/hello.txt",
    )
    .await?;
    assert_eq!(st1, StatusCode::OK);
    assert_eq!(body1.as_ref(), b"cached-v1");

    let (st2, body2) = https_request(
        cached_sender,
        http::Method::GET,
        "cached.openat2.test",
        "/hello.txt",
    )
    .await?;
    assert_eq!(st2, StatusCode::OK);
    assert_eq!(body2.as_ref(), b"cached-v1");

    // Mutate file on disk from the unconfined helper thread (external writer) inside the 60s window.
    helper_write(helper_tx, cached_file, b"cached-v2").map_err(std::io::Error::other)?;
    let (st3, body3) = https_request(
        cached_sender,
        http::Method::GET,
        "cached.openat2.test",
        "/hello.txt",
    )
    .await?;
    assert_eq!(st3, StatusCode::OK);

    let prom = server.telemetry().render_prometheus();
    let fills = metric_value(&prom, "miraserve_file_cache_events_total{outcome=\"fill\"}")
        .ok_or("missing file_cache fill metric")?;
    let hits = metric_value(&prom, "miraserve_file_cache_events_total{outcome=\"hit\"}")
        .ok_or("missing file_cache hit metric")?;

    if expect_openat2_allowed {
        assert!(
            fills >= 1 && hits >= 2,
            "expected fills >= 1 and hits >= 2 when openat2 is allowed, got fills={fills} hits={hits}\n{prom}"
        );
        assert_eq!(body3.as_ref(), b"cached-v1");
    } else {
        assert_eq!(
            fills, 0,
            "file-cache must store nothing under ENOSYS\n{prom}"
        );
        assert_eq!(hits, 0, "file-cache must have 0 hits under ENOSYS\n{prom}");
        assert_eq!(body3.as_ref(), b"cached-v2");
    }
    Ok(())
}

fn verify_sandbox_report_and_setid_filter(
    server: &RunningServer,
    use_landlock: bool,
    ungranted_dir: &Path,
    tmp_path: &Path,
) -> TestResult {
    let report = server.sandbox_report().ok_or("missing sandbox report")?;
    assert_eq!(report.seccomp, EnforcementStatus::Enforced);
    if use_landlock {
        assert!(
            matches!(
                report.landlock,
                EnforcementStatus::Enforced | EnforcementStatus::PartiallyEnforced
            ),
            "expected enforcing Landlock, got {:?}",
            report.landlock
        );
        assert!(
            fs::read(ungranted_dir.join("secret.txt")).is_err(),
            "Landlock must block reading an ungranted directory"
        );
    }

    let suid_attempt = rustix::fs::openat(
        rustix::fs::CWD,
        tmp_path.join("should-fail-suid"),
        rustix::fs::OFlags::CREATE | rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::from_raw_mode(0o4644),
    );
    assert_eq!(suid_attempt.err(), Some(rustix::io::Errno::PERM));
    Ok(())
}

async fn run_child_scenario(expect_openat2_allowed: bool) -> TestResult {
    let tmp_path = make_temp_dir(if expect_openat2_allowed {
        "allowed"
    } else {
        "enosys"
    })?;
    let cached_root = tmp_path.join("cached");
    let plain_root = tmp_path.join("plain");
    let ungranted_dir = tmp_path.join("ungranted");
    fs::create_dir_all(&cached_root)?;
    fs::create_dir_all(&plain_root)?;
    fs::create_dir_all(&ungranted_dir)?;
    let cached_file = cached_root.join("hello.txt");
    let plain_file = plain_root.join("inline.txt");
    fs::write(&cached_file, b"cached-v1")?;
    fs::write(&plain_file, b"inline-v1")?;
    fs::write(ungranted_dir.join("secret.txt"), b"outside-landlock")?;
    std::os::unix::fs::symlink("inline.txt", plain_root.join("sym.txt"))?;

    let use_landlock = kernel_enforces_landlock().map_err(std::io::Error::other)?;
    if !use_landlock {
        eprintln!(
            "note: host kernel does not enable Landlock LSM; running e2e_openat2_seccomp with seccomp only"
        );
    }

    let (helper_tx, helper_handle) = spawn_unconfined_helper();
    let tls_port = reserve_free_port()?;
    let kdl = format!(
        "server {{\n    listen \"127.0.0.1:{tls_port}\" protocols=\"h1\"\n    workers 1\n    sandbox {{ landlock #{use_landlock}; seccomp \"strict\" }}\n}}\n\
         site \"cached.openat2.test\" {{\n    root \"{}\"\n    file-cache \"60s\"\n}}\n\
         site \"plain.openat2.test\" {{\n    root \"{}\"\n}}\n",
        cached_root.display(),
        plain_root.display(),
    );
    let (cfg, _) = parse_kdl("openat2-seccomp.kdl", &kdl)?;

    if expect_openat2_allowed {
        assert!(probe_openat2_refused().is_none());
        assert!(openat2_refused_advisory(&cfg).is_none());
    } else {
        assert!(probe_openat2_refused().is_some());
        let advisory = openat2_refused_advisory(&cfg)
            .ok_or("expected openat2 refusal advisory under systemd-like filter")?;
        assert!(
            advisory.contains("--allow-openat2")
                && advisory.contains("file-cache will store nothing")
                && advisory.contains("worker loops will not look up"),
            "unexpected advisory: {advisory}"
        );
    }

    let server = MiraServeServer::start(
        Arc::new(ConfigStore::new(cfg)),
        ServerOptions {
            dev_tls: true,
            apply_sandbox: true,
            ..ServerOptions::default()
        },
    )
    .await?;
    verify_sandbox_report_and_setid_filter(&server, use_landlock, &ungranted_dir, &tmp_path)?;

    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::HttpsTcp)
        .ok_or("missing HttpsTcp listener")?
        .local_addr;
    let cert_pem = server.dev_cert_pem().ok_or("missing dev cert PEM")?;
    let cli_tls = build_tls_client(cert_pem)?;
    let (mut plain_sender, plain_conn) =
        connect_h1(https_addr, &cli_tls, "plain.openat2.test").await?;
    let (mut cached_sender, cached_conn) =
        connect_h1(https_addr, &cli_tls, "cached.openat2.test").await?;

    let _ = fs::read(&plain_file)?;
    let _ = fs::read(&cached_file)?;
    verify_inline_vs_pool_reuse(&mut plain_sender, &helper_tx, expect_openat2_allowed).await?;
    verify_file_cache_behavior(
        &mut cached_sender,
        &helper_tx,
        &cached_file,
        &server,
        expect_openat2_allowed,
    )
    .await?;

    drop(plain_sender);
    drop(cached_sender);
    let _ = plain_conn.await;
    let _ = cached_conn.await;
    server.shutdown().await;

    let (clean_tx, clean_rx) = mpsc::channel();
    let _ = helper_tx.send(HelperCmd::RemoveDirAll(tmp_path, clean_tx));
    let _ = clean_rx.recv();
    let _ = helper_tx.send(HelperCmd::Quit);
    let _ = helper_handle.join();
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn e2e_systemd_enosys_vs_miraserve_setid_filter_for_file_cache_and_workers() -> TestResult {
    if let Ok(mode) = std::env::var(CHILD_MODE_ENV) {
        return match mode.as_str() {
            "enosys" => run_child_scenario(false).await,
            "allowed" => run_child_scenario(true).await,
            other => Err(format!("unknown child mode: {other}").into()),
        };
    }

    let exe = std::env::current_exe()?;
    let test_name = "e2e_systemd_enosys_vs_miraserve_setid_filter_for_file_cache_and_workers";

    let exe1 = exe.clone();
    let enosys_out = std::thread::spawn(move || -> Result<std::process::Output, String> {
        let bpf = compile_systemd_enosys_openat2_filter().map_err(|e| e.to_string())?;
        seccompiler::apply_filter(&bpf).map_err(|e| e.to_string())?;
        Command::new(&exe1)
            .args(["--exact", test_name, "--nocapture"])
            .env(CHILD_MODE_ENV, "enosys")
            .output()
            .map_err(|e| e.to_string())
    })
    .join()
    .map_err(|_| "enosys helper thread panicked")?
    .map_err(|msg| -> Box<dyn std::error::Error> { msg.into() })?;

    assert!(
        enosys_out.status.success(),
        "ENOSYS child failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&enosys_out.stdout),
        String::from_utf8_lossy(&enosys_out.stderr),
    );

    let allowed_out = Command::new(&exe)
        .args(["--exact", test_name, "--nocapture"])
        .env(CHILD_MODE_ENV, "allowed")
        .output()?;

    assert!(
        allowed_out.status.success(),
        "allowed child failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&allowed_out.stdout),
        String::from_utf8_lossy(&allowed_out.stderr),
    );

    Ok(())
}

const KILL_CHILD_MODE_ENV: &str = "MIRASERVE_E2E_OPENAT2_KILL_CHILD";

fn compile_kill_openat2_filter() -> Result<BpfProgram, Box<dyn std::error::Error>> {
    let arch = TargetArch::try_from(std::env::consts::ARCH)?;
    let mut rules = BTreeMap::new();
    rules.insert(SYS_OPENAT2, Vec::new());
    if arch == TargetArch::x86_64 {
        rules.insert(SYS_OPENAT2 | 0x4000_0000, Vec::new());
    }
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::KillProcess,
        arch,
    )?;
    Ok(filter.try_into()?)
}

async fn run_kill_openat2_proxy_child(
    use_h2: bool,
    force_kernel_in_range: bool,
    with_quarantined_static_tenant: bool,
) -> TestResult {
    use http_body_util::Full;
    use hyper::body::Incoming;
    use hyper::client::conn::http2 as h2_client;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioExecutor;
    use std::convert::Infallible;
    use tokio::net::TcpListener;

    let _kernel_guard = force_kernel_in_range
        .then(|| miraserve_static::test_nowait_kernel_in_range_override_guard(Some(true)));
    let _advisory_kernel_guard = force_kernel_in_range
        .then(|| miraserve_sandbox::test_advisory_kernel_in_range_override_guard(Some(true)));

    let up_listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_port = up_listener.local_addr()?.port();
    let up_task = tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = up_listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(tcp),
                        service_fn(|_req: Request<Incoming>| async {
                            Ok::<_, Infallible>(http::Response::new(Full::new(Bytes::from_static(
                                b"proxy-kill-ok",
                            ))))
                        }),
                    )
                    .await;
            });
        }
    });

    let tls_port = reserve_free_port()?;
    let protocols = if use_h2 { "h2,h1" } else { "h1" };
    let tenant_dir = if with_quarantined_static_tenant {
        let dir = make_temp_dir("kill-openat2-tenant")?;
        let owner_dir = dir.join("tenant-owner");
        std::fs::create_dir_all(&owner_dir)?;
        Some((dir, owner_dir))
    } else {
        None
    };
    let tenant_block = if let Some((_, owner_dir)) = &tenant_dir {
        let owner = owner_dir.to_string_lossy().replace('\\', "/");
        let missing_root = owner_dir
            .join("missing-docroot")
            .to_string_lossy()
            .replace('\\', "/");
        format!(
            r#"
site "quarantined-tenant.test" {{
    owner-dir "{owner}"
    route "/files/*" {{
        root "{missing_root}"
        static {{}}
    }}
}}
"#
        )
    } else {
        String::new()
    };
    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="{protocols}"
    sandbox {{ landlock #false; seccomp "strict" }}
}}
site "kill-openat2.test" {{
    route "/*" {{
        reverse-proxy {{
            upstream "http://127.0.0.1:{up_port}"
        }}
    }}
}}
{tenant_block}
"#
    );
    let (mut cfg, _) = parse_kdl("kill-openat2-proxy.kdl", &kdl)?;
    if with_quarantined_static_tenant {
        // Preflight quarantines the missing-root tenant (clearing its root paths while retaining
        // its `static` route declaration). Both `check --fs`'s classified advisory and runtime
        // startup MUST skip probing `openat2(2)`!
        miraserve_core::quarantine_inaccessible_tenant_roots(&mut cfg);
        assert!(
            cfg.sites
                .get(1)
                .is_some_and(|s| s.quarantine.is_some() && !s.routes.is_empty()),
            "expected quarantined tenant to retain route declarations after preflight"
        );
    }
    // Advisory must also skip probing openat2 for H1-only, H2-proxy-only, and classified
    // quarantined-static-tenant configs!
    assert!(openat2_refused_advisory(&cfg).is_none());

    let server = MiraServeServer::start(
        Arc::new(ConfigStore::new(cfg)),
        ServerOptions {
            dev_tls: true,
            apply_sandbox: true,
            ..ServerOptions::default()
        },
    )
    .await?;

    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::HttpsTcp)
        .ok_or("missing HttpsTcp listener")?
        .local_addr;
    let cert_pem = server.dev_cert_pem().ok_or("missing dev cert PEM")?;

    if use_h2 {
        let mut roots = RootCertStore::empty();
        let certs: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(cert_pem.as_bytes()).collect::<Result<_, _>>()?;
        roots.add_parsable_certificates(certs);
        let mut cli_tls = ClientConfig::builder_with_provider(build_crypto_provider(true))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth();
        cli_tls.alpn_protocols = vec![b"h2".to_vec()];
        let tcp = TcpStream::connect(https_addr).await?;
        let tls = TlsConnector::from(Arc::new(cli_tls))
            .connect(ServerName::try_from("kill-openat2.test")?, tcp)
            .await?;
        let (mut sender, conn) =
            h2_client::handshake::<_, _, Empty<Bytes>>(TokioExecutor::new(), TokioIo::new(tls))
                .await?;
        let conn_task = tokio::spawn(conn);
        let (in_before, sp_before) = miraserve_http::test_h2_exec_stream_counts();
        for _ in 0..2 {
            sender.ready().await?;
            let resp = sender
                .send_request(
                    Request::builder()
                        .uri("https://kill-openat2.test/hello")
                        .body(Empty::new())?,
                )
                .await?;
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(
                resp.into_body().collect().await?.to_bytes().as_ref(),
                b"proxy-kill-ok"
            );
        }
        let (in_after, sp_after) = miraserve_http::test_h2_exec_stream_counts();
        assert_eq!(
            (in_after - in_before, sp_after - sp_before),
            (0, 2),
            "H2 proxy-only (no static work) must select Spawned (TokioExecutor) without calling openat2"
        );
        drop(sender);
        let _ = conn_task.await;
    } else {
        let cli_tls = build_tls_client(cert_pem)?;
        let (mut sender, conn) = connect_h1(https_addr, &cli_tls, "kill-openat2.test").await?;
        for _ in 0..2 {
            let (st, body) = https_request(
                &mut sender,
                http::Method::GET,
                "kill-openat2.test",
                "/hello",
            )
            .await?;
            assert_eq!(st, StatusCode::OK);
            assert_eq!(body.as_ref(), b"proxy-kill-ok");
        }
        drop(sender);
        let _ = conn.await;
    }

    up_task.abort();
    server.shutdown().await;
    if let Some((dir, _)) = tenant_dir {
        let _ = fs::remove_dir_all(&dir);
    }
    Ok(())
}

/// P1-C: Under an outer seccomp policy that KILLS the process (`SECCOMP_RET_KILL_PROCESS`) on
/// `openat2`, BOTH an HTTP/1.1-only reverse proxy AND an HTTP/2 reverse proxy (without static
/// file work) start, serve traffic, and shut down cleanly without ever issuing `openat2(2)`.
#[tokio::test(flavor = "current_thread")]
async fn e2e_openat2_kill_filter_allows_h1_and_h2_proxy_only_without_probing() -> TestResult {
    if let Ok(mode) = std::env::var(KILL_CHILD_MODE_ENV) {
        return match mode.as_str() {
            "h1_proxy" => run_kill_openat2_proxy_child(false, false, false).await,
            "h2_proxy" => run_kill_openat2_proxy_child(true, false, false).await,
            "h2_proxy_in_range" => run_kill_openat2_proxy_child(true, true, false).await,
            "h2_proxy_quarantined_static_tenant" => {
                run_kill_openat2_proxy_child(true, true, true).await
            }
            other => Err(format!("unknown kill child mode: {other}").into()),
        };
    }

    let exe = std::env::current_exe()?;
    let test_name = "e2e_openat2_kill_filter_allows_h1_and_h2_proxy_only_without_probing";
    for mode in [
        "h1_proxy",
        "h2_proxy",
        "h2_proxy_in_range",
        "h2_proxy_quarantined_static_tenant",
    ] {
        let exe_c = exe.clone();
        let out = std::thread::spawn(move || -> Result<std::process::Output, String> {
            let bpf = compile_kill_openat2_filter().map_err(|e| e.to_string())?;
            seccompiler::apply_filter(&bpf).map_err(|e| e.to_string())?;
            Command::new(&exe_c)
                .args(["--exact", test_name, "--nocapture"])
                .env(KILL_CHILD_MODE_ENV, mode)
                .output()
                .map_err(|e| e.to_string())
        })
        .join()
        .map_err(|_| "kill-openat2 helper thread panicked")?
        .map_err(|msg| -> Box<dyn std::error::Error> { msg.into() })?;

        assert!(
            out.status.success(),
            "SECCOMP_RET_KILL_PROCESS(openat2) child ({mode}) died or failed (status={:?}):\nstdout:\n{}\nstderr:\n{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }

    Ok(())
}

const LEVEL_CHILD_MODE_ENV: &str = "MIRASERVE_E2E_OPENAT2_LEVEL_CHILD";

struct MessageVisitor {
    message: String,
}

impl tracing::field::Visit for MessageVisitor {
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

struct CapturingSubscriber {
    events: Arc<std::sync::Mutex<Vec<(tracing::Level, String)>>>,
}

impl tracing::Subscriber for CapturingSubscriber {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = MessageVisitor {
            message: String::new(),
        };
        event.record(&mut visitor);
        if let Ok(mut guard) = self.events.lock() {
            guard.push((*event.metadata().level(), visitor.message));
        }
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

async fn run_openat2_level_child(mode: &str) -> TestResult {
    let _kernel_guard = miraserve_sandbox::test_advisory_kernel_in_range_override_guard(Some(true));
    let events = Arc::new(std::sync::Mutex::new(Vec::<(tracing::Level, String)>::new()));
    let _ = tracing::subscriber::set_global_default(CapturingSubscriber {
        events: Arc::clone(&events),
    });

    let tmp_path = make_temp_dir(&format!("level-{mode}"))?;
    let www = tmp_path.join("www");
    fs::create_dir_all(&www)?;
    fs::write(www.join("index.html"), b"ok")?;
    let tls_port = reserve_free_port()?;

    let (kdl, expected_level) = match mode {
        "default_h2_static" => (
            format!(
                "server {{\n    listen \"127.0.0.1:{tls_port}\"\n    sandbox {{ landlock #false; seccomp \"strict\" }}\n}}\n\
                 site \"level.openat2.test\" {{\n    root \"{}\"\n}}\n",
                www.display()
            ),
            tracing::Level::INFO,
        ),
        "file_cache_zero_budget" => (
            format!(
                "server {{\n    listen \"127.0.0.1:{tls_port}\"\n    limits {{ file-cache-bytes \"0\" }}\n    sandbox {{ landlock #false; seccomp \"strict\" }}\n}}\n\
                 site \"level.openat2.test\" {{\n    root \"{}\"\n    file-cache \"5s\"\n}}\n",
                www.display()
            ),
            tracing::Level::INFO,
        ),
        "file_cache_enabled" => (
            format!(
                "server {{\n    listen \"127.0.0.1:{tls_port}\"\n    sandbox {{ landlock #false; seccomp \"strict\" }}\n}}\n\
                 site \"level.openat2.test\" {{\n    root \"{}\"\n    file-cache \"5s\"\n}}\n",
                www.display()
            ),
            tracing::Level::WARN,
        ),
        "workers_non_shared" => (
            format!(
                "server {{\n    listen \"127.0.0.1:{tls_port}\"\n    workers 1\n    sandbox {{ landlock #false; seccomp \"strict\" }}\n}}\n\
                 site \"level.openat2.test\" {{\n    root \"{}\"\n}}\n",
                www.display()
            ),
            tracing::Level::WARN,
        ),
        other => return Err(format!("unknown level child mode: {other}").into()),
    };

    let (cfg, _) = parse_kdl("openat2-level.kdl", &kdl)?;
    let server = MiraServeServer::start(
        Arc::new(ConfigStore::new(cfg.clone())),
        ServerOptions {
            dev_tls: true,
            apply_sandbox: true,
            ..ServerOptions::default()
        },
    )
    .await?;
    let expected_text = miraserve_core::openat2_refused_advisory_for_runtime_with_static_work(
        &cfg,
        server.sandbox_report(),
        Some(true),
        true,
    )
    .ok_or("expected openat2 refusal advisory text")?;

    let captured = events.lock().map_err(|_| "events mutex poisoned")?.clone();
    let openat2_events: Vec<&(tracing::Level, String)> = captured
        .iter()
        .filter(|(_, msg)| msg.contains("openat2 is refused in this process"))
        .collect();
    assert_eq!(
        openat2_events.len(),
        1,
        "mode={mode}: expected exactly one openat2 refusal event, got: {openat2_events:?}"
    );
    let (actual_level, actual_msg) = openat2_events
        .first()
        .copied()
        .ok_or("missing openat2 event")?;
    assert_eq!(
        *actual_level, expected_level,
        "mode={mode}: expected level {expected_level}, got {actual_level} for message: {actual_msg}"
    );
    assert_eq!(
        actual_msg, &expected_text,
        "mode={mode}: message text must stay identical"
    );
    assert!(
        captured.iter().any(|(lvl, msg)| {
            *lvl == tracing::Level::INFO && msg.contains("HTTP/2 stream execution mode selected")
        }),
        "mode={mode}: expected HTTP/2 execution-mode INFO line, got: {captured:?}"
    );

    server.shutdown().await;
    let _ = fs::remove_dir_all(&tmp_path);
    Ok(())
}

/// Oracle for 0.1.6 Item 1: under an `ENOSYS` `openat2` filter (default systemd unit with
/// `RestrictSUIDSGID=yes`), startup logs `"openat2 is refused in this process"` at `INFO` unless
/// the loaded config asks for `file-cache` (with non-zero budget) or non-`"shared"` `workers`, in
/// which case the identical text is logged at `WARN`. The HTTP/2 execution-mode `INFO` line stays.
#[tokio::test(flavor = "current_thread")]
async fn e2e_openat2_refusal_startup_log_level_info_unless_degraded() -> TestResult {
    if let Ok(mode) = std::env::var(LEVEL_CHILD_MODE_ENV) {
        return run_openat2_level_child(&mode).await;
    }

    let exe = std::env::current_exe()?;
    let test_name = "e2e_openat2_refusal_startup_log_level_info_unless_degraded";
    for mode in [
        "default_h2_static",
        "file_cache_zero_budget",
        "file_cache_enabled",
        "workers_non_shared",
    ] {
        let exe_c = exe.clone();
        let out = std::thread::spawn(move || -> Result<std::process::Output, String> {
            let bpf = compile_systemd_enosys_openat2_filter().map_err(|e| e.to_string())?;
            seccompiler::apply_filter(&bpf).map_err(|e| e.to_string())?;
            Command::new(&exe_c)
                .args(["--exact", test_name, "--nocapture"])
                .env(LEVEL_CHILD_MODE_ENV, mode)
                .output()
                .map_err(|e| e.to_string())
        })
        .join()
        .map_err(|_| "openat2-level helper thread panicked")?
        .map_err(|msg| -> Box<dyn std::error::Error> { msg.into() })?;

        assert!(
            out.status.success(),
            "openat2 level child ({mode}) failed (status={:?}):\nstdout:\n{}\nstderr:\n{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }

    Ok(())
}

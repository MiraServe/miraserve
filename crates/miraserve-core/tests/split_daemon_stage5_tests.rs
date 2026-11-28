//! Runtime integration tests for `split-daemon` key isolation.
//!
//! Guarded with `cfg(unix)` because these tests use Unix-domain `miraserve-keyd` sockets, POSIX
//! permissions (`0600` / `0000`), symlinks, and hard links.
//!
//! Covers:
//! 1. An `owner-dir` tenant site using the server certificate pair serves HTTP 200 over fresh
//!    non-resumed TLS 1.3 signed by `miraserve-keyd` at both startup and reload.
//! 2. Reloading a `server.tls.key-isolation` mode transition (`split-daemon <-> in-process`) is
//!    refused with `CoreError::RestartRequired` BEFORE candidate compilation while the prior
//!    generation continues serving.
//! 3. Conservative credential protection in `split-daemon` mode: visible-key positive control
//!    serves a benign outside-root custom error page while readable (`0600`) signing-key and
//!    hard-link outside-root error pages fall back to built-in 404 (not serving key bytes),
//!    unidentifiable signing keys fail closed on outside-root custom error pages, non-quarantined
//!    `basic-auth` referencing a signing-key hard link fails closed with 503, `acme-webroot`
//!    reserves configured split signing-key names even after replacing the token file post-compile
//!    with a fresh single-link file, and multi-link static files return 404.
//! 4. Split-daemon compile logs its own warning once per compile ("in split-daemon mode the
//!    credential inventory skips signing keys; ...") instead of the "cannot be opened ... until
//!    it can" sentence (which remains for genuine unopenable files).
//! 5. Keyd failures remain closed on startup (even with `dev_tls: true`) and on reload (preserving
//!    the committed serving generation), returning the exact `CoreError::Tls(TlsError::KeyLoad)`
//!    keyd connection error.

#![cfg(unix)]
#![allow(clippy::too_many_lines)]

use std::cell::RefCell;
use std::fmt;
use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Once};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[path = "../../miraserve-config/tests/common/mod.rs"]
mod kdl_test_util;
use kdl_test_util::kdl_escape_path;

use bytes::Bytes;
use http::header::HOST;
use http::{Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper_util::rt::TokioIo;
use miraserve_ai::AgentKeyRegistry;
use miraserve_config::{ConfigStore, load_file, parse_kdl};
use miraserve_core::{CoreError, ListenerKind, MiraServeServer, ServerOptions};
use miraserve_http::RequestContext;
use miraserve_http::router::{CompiledRouter, CredentialSources};
use miraserve_telemetry::TelemetryRegistry;
use miraserve_tls::{
    AcmeChallengeStore, KeydEndpoint, KeydKeyStore, KeydServer, TlsError, build_crypto_provider,
    generate_dev_certificate,
};
use rustls::client::Resumption;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

type TestResult = Result<(), Box<dyn std::error::Error>>;

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Result<Self, std::io::Error> {
        let root = PathBuf::from("/tmp");
        let pid = std::process::id();
        let salt = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::from(d.subsec_nanos()) & 0xffff);
        loop {
            let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
            let path = root.join(format!("ms-s5-{tag}-{pid}-{salt:x}-{seq}"));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
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

fn parse_first_cert_der(pem: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let first = CertificateDer::pem_slice_iter(pem.as_bytes())
        .next()
        .ok_or("no certificate in PEM")??;
    Ok(first.as_ref().to_vec())
}

fn build_non_resuming_connector(
    cert_pems: &[&str],
) -> Result<TlsConnector, Box<dyn std::error::Error>> {
    let provider = build_crypto_provider(true);
    let mut roots = RootCertStore::empty();
    for pem in cert_pems {
        for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            roots.add(cert?)?;
        }
    }
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    cfg.resumption = Resumption::disabled();
    Ok(TlsConnector::from(Arc::new(cfg)))
}

async fn https_get(
    addr: SocketAddr,
    host: &str,
    path: &str,
    connector: &TlsConnector,
) -> Result<(StatusCode, String, Vec<u8>, Option<String>), Box<dyn std::error::Error>> {
    tokio::time::timeout(HTTP_TIMEOUT, async {
        let tcp = TcpStream::connect(addr).await?;
        let tls = connector
            .connect(ServerName::try_from(host.to_owned())?, tcp)
            .await?;
        let peer_leaf = tls
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|c| c.first())
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
        let x_gen = resp
            .headers()
            .get("x-gen")
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);
        let body = resp.into_body().collect().await?.to_bytes();
        Ok((
            status,
            String::from_utf8_lossy(&body).into_owned(),
            peer_leaf,
            x_gen,
        ))
    })
    .await
    .map_err(|_| format!("HTTPS GET {host}{path} timed out"))?
}

fn load_ephemeral(cfg_path: &Path) -> Result<miraserve_config::Config, Box<dyn std::error::Error>> {
    let (mut cfg, _) = load_file(cfg_path)?;
    if let Some(l) = cfg.server.listeners.first_mut() {
        l.addr.port = 0;
    }
    Ok(cfg)
}

#[derive(Default)]
struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            value.clone_into(&mut self.0);
        }
    }
}

thread_local! {
    static CAPTURED_WARNS: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
}

struct ThreadLocalWarnCapture;

impl tracing::Subscriber for ThreadLocalWarnCapture {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        *metadata.level() <= tracing::Level::WARN
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        if *event.metadata().level() != tracing::Level::WARN {
            return;
        }
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        CAPTURED_WARNS.with(|slot| {
            if let Some(buf) = slot.borrow_mut().as_mut() {
                buf.push(visitor.0);
            }
        });
    }

    fn enter(&self, _span: &tracing::span::Id) {}
    fn exit(&self, _span: &tracing::span::Id) {}
}

fn capture_warns<T, F: FnOnce() -> T>(f: F) -> (T, Vec<String>) {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = tracing::subscriber::set_global_default(ThreadLocalWarnCapture);
    });
    CAPTURED_WARNS.with(|slot| *slot.borrow_mut() = Some(Vec::new()));
    let result = f();
    let warns = CAPTURED_WARNS.with(|slot| slot.borrow_mut().take().unwrap_or_default());
    (result, warns)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tenant_site_using_server_pair_serves_under_split_daemon_startup_and_reload() -> TestResult
{
    let tmp = TempDir::new("ten")?;
    let base = &tmp.path;
    let certs = base.join("certs");
    let vault = base.join("vault");
    let srv_root = base.join("srv");
    let ord_root = base.join("ord");
    let owner_dir = base.join("owner");
    let ten_root = owner_dir.join("public_html");
    for d in [&certs, &vault, &srv_root, &ord_root, &ten_root] {
        fs::create_dir_all(d)?;
    }
    fs::write(srv_root.join("index.html"), "srv-body")?;
    fs::write(ord_root.join("index.html"), "ord-body")?;
    fs::write(ten_root.join("index.html"), "tenant-server-pair-v1")?;

    let provider = build_crypto_provider(true);
    let (srv_ck, srv_pem) = generate_dev_certificate(
        &["srv.s5.test".to_owned(), "ten.s5.test".to_owned()],
        &provider,
    )?;
    let (ord_ck, ord_pem) = generate_dev_certificate(&["ord.s5.test".to_owned()], &provider)?;
    let srv_cert = certs.join("server.pem");
    let srv_key = vault.join("server.key");
    let ord_cert = certs.join("ord.pem");
    let ord_key = vault.join("ord.key");
    fs::write(&srv_cert, &srv_pem.cert_pem)?;
    fs::write(&srv_key, srv_pem.key_pem.as_str())?;
    fs::write(&ord_cert, &ord_pem.cert_pem)?;
    fs::write(&ord_key, ord_pem.key_pem.as_str())?;
    fs::set_permissions(&srv_key, fs::Permissions::from_mode(0o600))?;
    fs::set_permissions(&ord_key, fs::Permissions::from_mode(0o600))?;

    let srv_der = parse_first_cert_der(&srv_pem.cert_pem)?;
    let ord_der = parse_first_cert_der(&ord_pem.cert_pem)?;
    let connector = build_non_resuming_connector(&[&srv_pem.cert_pem, &ord_pem.cert_pem])?;

    let keyd_sock = base.join("keyd.sock");
    let mut kstore = KeydKeyStore::new();
    kstore.insert_certified_key("srv", Vec::new(), true, srv_ck)?;
    kstore.insert_certified_key("ord", vec!["ord.s5.test".to_owned()], false, ord_ck)?;
    let keyd = KeydServer::start(KeydEndpoint::Unix(keyd_sock.clone()), kstore, false).await?;

    let cfg_path = base.join("miraserve.kdl");
    let write_cfg = |gen_hdr: &str| -> std::io::Result<()> {
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
}}
site "srv.s5.test" {{ root "{}"; headers {{ set "X-Gen" "{gen_hdr}" }} }}
site "ord.s5.test" {{
    root "{}"
    tls {{ cert "{}"; key "{}" }}
    headers {{ set "X-Gen" "{gen_hdr}" }}
}}
site "ten.s5.test" {{
    owner-dir "{}"
    root "{}"
    headers {{ set "X-Gen" "{gen_hdr}" }}
}}
"#,
                kdl_escape_path(&keyd_sock),
                kdl_escape_path(&srv_cert),
                kdl_escape_path(&srv_key),
                kdl_escape_path(&srv_root),
                kdl_escape_path(&ord_root),
                kdl_escape_path(&ord_cert),
                kdl_escape_path(&ord_key),
                kdl_escape_path(&owner_dir),
                kdl_escape_path(&ten_root),
            ),
        )
    };
    write_cfg("g1")?;

    let server = MiraServeServer::start(
        Arc::new(ConfigStore::new(load_ephemeral(&cfg_path)?)),
        ServerOptions {
            config_path: Some(cfg_path.clone()),
            apply_sandbox: false,
            ..ServerOptions::default()
        },
    )
    .await?;
    let addr = server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::HttpsTcp)
        .ok_or("missing HTTPS listener")?
        .local_addr;

    let (st, body, der, gen_hdr) = https_get(addr, "ten.s5.test", "/", &connector).await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, "tenant-server-pair-v1");
    assert_eq!(der, srv_der);
    assert_eq!(gen_hdr.as_deref(), Some("g1"));

    let (st, body, der, gen_hdr) = https_get(addr, "ord.s5.test", "/", &connector).await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, "ord-body");
    assert_eq!(der, ord_der);
    assert_eq!(gen_hdr.as_deref(), Some("g1"));
    assert_eq!(keyd.signatures_served(), 2);

    // Live reload keeps owner-dir tenant using server pair serving via keyd.
    fs::write(ten_root.join("index.html"), "tenant-server-pair-v2")?;
    write_cfg("g2")?;
    let _gen = server.reload_from_file(&cfg_path)?;

    let (st, body, der, gen_hdr) = https_get(addr, "ten.s5.test", "/", &connector).await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, "tenant-server-pair-v2");
    assert_eq!(der, srv_der);
    assert_eq!(gen_hdr.as_deref(), Some("g2"));
    assert_eq!(keyd.signatures_served(), 3);

    server.shutdown().await;
    keyd.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_mode_transition_refused_before_candidate_compilation() -> TestResult {
    let tmp = TempDir::new("mode")?;
    let base = &tmp.path;
    let certs = base.join("certs");
    let vault = base.join("vault");
    let srv_root = base.join("srv");
    for d in [&certs, &vault, &srv_root] {
        fs::create_dir_all(d)?;
    }
    fs::write(srv_root.join("index.html"), "mode-ok")?;

    let provider = build_crypto_provider(true);
    let (srv_ck, srv_pem) = generate_dev_certificate(&["mode.s5.test".to_owned()], &provider)?;
    let srv_cert = certs.join("server.pem");
    let srv_key = vault.join("server.key");
    fs::write(&srv_cert, &srv_pem.cert_pem)?;
    fs::write(&srv_key, srv_pem.key_pem.as_str())?;
    let connector = build_non_resuming_connector(&[&srv_pem.cert_pem])?;

    let keyd_sock = base.join("keyd.sock");
    let mut kstore = KeydKeyStore::new();
    kstore.insert_certified_key("srv", Vec::new(), true, srv_ck)?;
    let keyd = KeydServer::start(KeydEndpoint::Unix(keyd_sock.clone()), kstore, false).await?;

    // Direction A: split-daemon -> in-process (even with missing key path, refused BEFORE compile).
    let split_kdl = format!(
        r#"server {{
    listen "127.0.0.1:8443" protocols="h1"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "{}"
        cert "{}"
        key "{}"
    }}
}}
site "mode.s5.test" {{ root "{}" }}
"#,
        kdl_escape_path(&keyd_sock),
        kdl_escape_path(&srv_cert),
        kdl_escape_path(&srv_key),
        kdl_escape_path(&srv_root),
    );
    let split_cfg_path = base.join("split.kdl");
    fs::write(&split_cfg_path, &split_kdl)?;
    let server = MiraServeServer::start(
        Arc::new(ConfigStore::new(load_ephemeral(&split_cfg_path)?)),
        ServerOptions {
            config_path: Some(split_cfg_path.clone()),
            apply_sandbox: false,
            ..ServerOptions::default()
        },
    )
    .await?;
    let addr = server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::HttpsTcp)
        .ok_or("missing HTTPS listener")?
        .local_addr;

    let inproc_kdl = format!(
        r#"server {{
    listen "127.0.0.1:8443" protocols="h1"
    tls {{
        key-isolation "in-process"
        cert "{}"
        key "{}"
    }}
}}
site "mode.s5.test" {{ root "{}" }}
"#,
        kdl_escape_path(&srv_cert),
        kdl_escape_path(&vault.join("nonexistent-would-fail-compile.key")),
        kdl_escape_path(&srv_root),
    );
    let inproc_bad_path = base.join("inproc_bad.kdl");
    fs::write(&inproc_bad_path, &inproc_kdl)?;
    match server.reload_from_file(&inproc_bad_path) {
        Err(CoreError::RestartRequired(msg)) => {
            assert_eq!(
                msg,
                "server.tls.key-isolation changed; restart MiraServe to switch key isolation mode"
            );
        }
        other => {
            return Err(format!(
                "expected RestartRequired before compile on split->in-process, got: {other:?}"
            )
            .into());
        }
    }
    let (st, body, _, _) = https_get(addr, "mode.s5.test", "/", &connector).await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, "mode-ok");
    server.shutdown().await;

    // Direction B: in-process -> split-daemon.
    let inproc_valid_kdl = format!(
        r#"server {{
    listen "127.0.0.1:8443" protocols="h1"
    tls {{
        key-isolation "in-process"
        cert "{}"
        key "{}"
    }}
}}
site "mode.s5.test" {{ root "{}" }}
"#,
        kdl_escape_path(&srv_cert),
        kdl_escape_path(&srv_key),
        kdl_escape_path(&srv_root),
    );
    let inproc_cfg_path = base.join("inproc.kdl");
    fs::write(&inproc_cfg_path, &inproc_valid_kdl)?;
    let server2 = MiraServeServer::start(
        Arc::new(ConfigStore::new(load_ephemeral(&inproc_cfg_path)?)),
        ServerOptions {
            config_path: Some(inproc_cfg_path.clone()),
            apply_sandbox: false,
            ..ServerOptions::default()
        },
    )
    .await?;
    let addr2 = server2
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::HttpsTcp)
        .ok_or("missing HTTPS listener")?
        .local_addr;

    match server2.reload_from_file(&split_cfg_path) {
        Err(CoreError::RestartRequired(msg)) => {
            assert_eq!(
                msg,
                "server.tls.key-isolation changed; restart MiraServe to switch key isolation mode"
            );
        }
        other => {
            return Err(
                format!("expected RestartRequired on in-process->split, got: {other:?}").into(),
            );
        }
    }
    let (st, body, _, _) = https_get(addr2, "mode.s5.test", "/", &connector).await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, "mode-ok");
    server2.shutdown().await;
    keyd.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn split_daemon_preserves_conservative_credential_protection_and_acme_reservation()
-> TestResult {
    let tmp = TempDir::new("cons")?;
    let base = &tmp.path;
    let certs = base.join("certs");
    let vault = base.join("vault");
    let srv_root = base.join("srv");
    let err_dir = base.join("errpages");
    let extra_dir = base.join("extra-creds");
    let acme_wr = base.join("acme-wr");
    let acme_chal = acme_wr.join(".well-known").join("acme-challenge");
    for d in [&certs, &vault, &srv_root, &err_dir, &extra_dir, &acme_chal] {
        fs::create_dir_all(d)?;
    }
    fs::set_permissions(&acme_chal, fs::Permissions::from_mode(0o755))?;

    // Benign multi-link static file in docroot (nlink == 2) -> refused (404) because
    // UNIDENTIFIED_CREDENTIAL stays published when split signing keys are configured.
    fs::write(srv_root.join("single.txt"), "single-ok")?;
    fs::write(srv_root.join("linked.txt"), "linked-body")?;
    fs::hard_link(srv_root.join("linked.txt"), base.join("linked-second"))?;

    let outside_404 = err_dir.join("404.html");
    fs::write(&outside_404, "OUTSIDE-CUSTOM-404-BODY")?;

    let provider = build_crypto_provider(true);
    let (srv_ck, srv_pem) = generate_dev_certificate(&["cons.s5.test".to_owned()], &provider)?;
    let srv_cert = certs.join("server.pem");
    let reserved_token = "SplitKeyReservedToken12345";
    let srv_key = vault.join(reserved_token);
    fs::write(&srv_cert, &srv_pem.cert_pem)?;
    fs::write(&srv_key, srv_pem.key_pem.as_str())?;

    let thumb = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG";
    let normal_token = "NormalAcmeToken12345";
    fs::write(
        acme_chal.join(reserved_token),
        format!("{reserved_token}.{thumb}"),
    )?;
    fs::set_permissions(
        acme_chal.join(reserved_token),
        fs::Permissions::from_mode(0o644),
    )?;
    fs::write(
        acme_chal.join(normal_token),
        format!("{normal_token}.{thumb}"),
    )?;
    fs::set_permissions(
        acme_chal.join(normal_token),
        fs::Permissions::from_mode(0o644),
    )?;

    let agent_keys = Arc::new(AgentKeyRegistry::new());
    let acme_store = AcmeChallengeStore::new();
    let telemetry = TelemetryRegistry::new();
    let https_ctx = RequestContext {
        client_ip: None,
        remote_port: None,
        server_addr: None,
        server_port: 8443,
        is_https: true,
        tls: None,
    };

    let make_get = |uri: &str| -> Result<
        Request<http_body_util::combinators::BoxBody<Bytes, miraserve_http::HttpError>>,
        http::Error,
    > {
        Request::builder()
            .uri(uri)
            .header(HOST, "cons.s5.test")
            .body(
                Empty::<Bytes>::new()
                    .map_err(|never| match never {})
                    .boxed(),
            )
    };

    // 1a. Visible-key positive control: when all split signing keys are stat-visible, a benign
    //     outside-root custom error page IS served.
    let vis_benign_kdl = format!(
        r#"server {{
    listen "127.0.0.1:8443" protocols="h1"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "{}"
        cert "{}"
        key "{}"
    }}
}}
site "cons.s5.test" {{
    root "{}"
    error-pages {{ page 404 "{}" }}
}}
"#,
        kdl_escape_path(&base.join("keyd.sock")),
        kdl_escape_path(&srv_cert),
        kdl_escape_path(&srv_key),
        kdl_escape_path(&srv_root),
        kdl_escape_path(&outside_404),
    );
    let (vis_benign_cfg, _) = parse_kdl("vis_benign.kdl", &vis_benign_kdl)?;
    let vis_benign_router = CompiledRouter::compile(&vis_benign_cfg, &agent_keys)?;
    let resp = vis_benign_router
        .dispatch(
            make_get("/does-not-exist")?,
            &https_ctx,
            &vis_benign_cfg.server.limits,
            &acme_store,
            None,
            &telemetry,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = String::from_utf8_lossy(&resp.into_body().collect().await?.to_bytes()).into_owned();
    assert_eq!(
        body, "OUTSIDE-CUSTOM-404-BODY",
        "visible-key control must serve the benign outside-root custom 404 page"
    );

    // 1b. Visible-key refusal on readable (`0600`) key and hard link: outside-root custom error
    //     pages pointing to the signing key or a hard link fall back to the built-in 404 page
    //     without serving key bytes, and `basic-auth` referencing the hard link fails closed with
    //     503 (observed HTTP responses; retained descriptors in `credential_inventory` are
    //     verified separately via `/proc/<pid>/fd` in `split_daemon_key_isolation_oracle`).
    fs::set_permissions(&srv_key, fs::Permissions::from_mode(0o600))?;
    let hl_key = extra_dir.join("hl-key.pem");
    fs::hard_link(&srv_key, &hl_key)?;

    for (label, target) in [("direct-key", &srv_key), ("hardlink-key", &hl_key)] {
        let kdl = format!(
            r#"server {{
    listen "127.0.0.1:8443" protocols="h1"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "{}"
        cert "{}"
        key "{}"
    }}
}}
site "cons.s5.test" {{
    root "{}"
    basic-auth "{}" realm="Aliased"
    error-pages {{ page 404 "{}" }}
}}
"#,
            kdl_escape_path(&base.join("keyd.sock")),
            kdl_escape_path(&srv_cert),
            kdl_escape_path(&srv_key),
            kdl_escape_path(&srv_root),
            kdl_escape_path(&hl_key),
            kdl_escape_path(target),
        );
        let (cfg, _) = parse_kdl("vis_refuse.kdl", &kdl)?;
        let creds = CredentialSources {
            files: vec![hl_key.clone()],
            dirs: vec![extra_dir.clone()],
        };
        let router = CompiledRouter::compile_with_credentials(&cfg, &agent_keys, false, &creds)?;
        // Site has basic-auth pointing to a hard link of the signing key -> fails closed with 503.
        let resp_auth = router
            .dispatch(
                make_get("/single.txt")?,
                &https_ctx,
                &cfg.server.limits,
                &acme_store,
                None,
                &telemetry,
            )
            .await;
        assert_eq!(
            resp_auth.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{label}: aliased basic-auth users file must fail closed with 503"
        );

        // Without basic-auth, verify custom error page pointing to readable key or hard link falls
        // back to built-in 404 without serving key bytes.
        let kdl_no_auth = format!(
            r#"server {{
    listen "127.0.0.1:8443" protocols="h1"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "{}"
        cert "{}"
        key "{}"
    }}
}}
site "cons.s5.test" {{
    root "{}"
    error-pages {{ page 404 "{}" }}
}}
"#,
            kdl_escape_path(&base.join("keyd.sock")),
            kdl_escape_path(&srv_cert),
            kdl_escape_path(&srv_key),
            kdl_escape_path(&srv_root),
            kdl_escape_path(target),
        );
        let (cfg_na, _) = parse_kdl("vis_na.kdl", &kdl_no_auth)?;
        let router_na =
            CompiledRouter::compile_with_credentials(&cfg_na, &agent_keys, false, &creds)?;
        let resp_404 = router_na
            .dispatch(
                make_get("/does-not-exist")?,
                &https_ctx,
                &cfg_na.server.limits,
                &acme_store,
                None,
                &telemetry,
            )
            .await;
        assert_eq!(resp_404.status(), StatusCode::NOT_FOUND);
        let body_s =
            String::from_utf8_lossy(&resp_404.into_body().collect().await?.to_bytes()).into_owned();
        assert!(
            !body_s.contains("PRIVATE KEY") && body_s.contains("404"),
            "{label}: expected built-in 404 without key bytes, got: {body_s}"
        );
    }

    // 2. Unidentifiable signing key (absent/unstatable) causes outside-root custom error page to
    //    fail closed to the built-in 404 page (contrast with 1a above).
    let missing_key = vault.join("unstatable-missing.key");
    let unid_kdl = format!(
        r#"server {{
    listen "127.0.0.1:8443" protocols="h1"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "{}"
        cert "{}"
        key "{}"
    }}
}}
site "cons.s5.test" {{
    root "{}"
    error-pages {{ page 404 "{}" }}
}}
"#,
        kdl_escape_path(&base.join("keyd.sock")),
        kdl_escape_path(&srv_cert),
        kdl_escape_path(&missing_key),
        kdl_escape_path(&srv_root),
        kdl_escape_path(&outside_404),
    );
    let (unid_cfg, _) = parse_kdl("unid.kdl", &unid_kdl)?;
    let unid_router = CompiledRouter::compile(&unid_cfg, &agent_keys)?;
    let resp = unid_router
        .dispatch(
            make_get("/does-not-exist")?,
            &https_ctx,
            &unid_cfg.server.limits,
            &acme_store,
            None,
            &telemetry,
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body_s =
        String::from_utf8_lossy(&resp.into_body().collect().await?.to_bytes()).into_owned();
    assert!(
        !body_s.contains("OUTSIDE-CUSTOM-404-BODY") && body_s.contains("404"),
        "outside-root custom error page must fail closed while signing key is unidentifiable: {body_s}"
    );

    // 3. `acme-webroot` token reservation still reserves configured split signing-key names while
    //    serving normal tokens. After compiling the router, replace the reserved token file with a
    //    fresh single-link file holding a valid authorization for that token so only the name
    //    reservation can explain the refusal.
    let reserved_path = acme_chal.join(reserved_token);
    let orig_meta = fs::metadata(&reserved_path)?;
    let orig_inode = (orig_meta.dev(), orig_meta.ino());
    let key_link_into_chal = vault.join("link-to-chal-token");
    symlink(&reserved_path, &key_link_into_chal)?;
    let acme_res_kdl = format!(
        r#"server {{
    listen "127.0.0.1:8443" protocols="h1"
    acme-webroot "{}"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "{}"
        cert "{}"
        key "{}"
    }}
}}
site "cons.s5.test" {{ root "{}" }}
"#,
        kdl_escape_path(&acme_wr),
        kdl_escape_path(&base.join("keyd.sock")),
        kdl_escape_path(&srv_cert),
        kdl_escape_path(&key_link_into_chal),
        kdl_escape_path(&srv_root),
    );
    let (acme_res_cfg, _) = parse_kdl("acme_res.kdl", &acme_res_kdl)?;
    let acme_router = CompiledRouter::compile(&acme_res_cfg, &agent_keys)?;
    let old_handle = fs::File::open(&reserved_path)?;
    let fresh_path = acme_chal.join(format!("{reserved_token}.fresh"));
    fs::write(&fresh_path, format!("{reserved_token}.{thumb}"))?;
    fs::set_permissions(&fresh_path, fs::Permissions::from_mode(0o644))?;
    fs::rename(&fresh_path, &reserved_path)?;
    drop(old_handle);
    let fresh_meta = fs::metadata(&reserved_path)?;
    assert_eq!(
        fresh_meta.nlink(),
        1,
        "replacement ACME token file must be single-link"
    );
    assert_ne!(
        (fresh_meta.dev(), fresh_meta.ino()),
        orig_inode,
        "replacement ACME token file must have a fresh inode distinct from the compile-time key"
    );
    let resp_norm = acme_router
        .dispatch(
            make_get(&format!("/.well-known/acme-challenge/{normal_token}"))?,
            &https_ctx,
            &acme_res_cfg.server.limits,
            &acme_store,
            None,
            &telemetry,
        )
        .await;
    assert_eq!(resp_norm.status(), StatusCode::OK);
    assert_eq!(
        String::from_utf8_lossy(&resp_norm.into_body().collect().await?.to_bytes()),
        format!("{normal_token}.{thumb}")
    );
    let resp_res = acme_router
        .dispatch(
            make_get(&format!("/.well-known/acme-challenge/{reserved_token}"))?,
            &https_ctx,
            &acme_res_cfg.server.limits,
            &acme_store,
            None,
            &telemetry,
        )
        .await;
    assert_eq!(
        resp_res.status(),
        StatusCode::NOT_FOUND,
        "acme-webroot must still refuse reserved token name after fresh single-link replacement"
    );

    // 4. Live split-daemon server: single-link static file returns 200 while multi-link returns 404.
    let keyd_sock = base.join("keyd.sock");
    let mut kstore = KeydKeyStore::new();
    kstore.insert_certified_key("srv", Vec::new(), true, srv_ck)?;
    let keyd = KeydServer::start(KeydEndpoint::Unix(keyd_sock.clone()), kstore, false).await?;
    let connector = build_non_resuming_connector(&[&srv_pem.cert_pem])?;

    let live_cfg_path = base.join("live.kdl");
    fs::write(
        &live_cfg_path,
        format!(
            r#"server {{
    listen "127.0.0.1:8443" protocols="h1"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "{}"
        cert "{}"
        key "{}"
    }}
}}
site "cons.s5.test" {{ root "{}" }}
"#,
            kdl_escape_path(&keyd_sock),
            kdl_escape_path(&srv_cert),
            kdl_escape_path(&srv_key),
            kdl_escape_path(&srv_root),
        ),
    )?;
    let server = MiraServeServer::start(
        Arc::new(ConfigStore::new(load_ephemeral(&live_cfg_path)?)),
        ServerOptions {
            config_path: Some(live_cfg_path),
            apply_sandbox: false,
            ..ServerOptions::default()
        },
    )
    .await?;
    let addr = server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::HttpsTcp)
        .ok_or("missing HTTPS listener")?
        .local_addr;

    let (st, body, _, _) = https_get(addr, "cons.s5.test", "/single.txt", &connector).await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, "single-ok");

    let (st, _, _, _) = https_get(addr, "cons.s5.test", "/linked.txt", &connector).await?;
    assert_eq!(
        st,
        StatusCode::NOT_FOUND,
        "multi-link static file must remain refused under UNIDENTIFIED_CREDENTIAL"
    );

    server.shutdown().await;
    keyd.shutdown().await;
    Ok(())
}

#[test]
fn split_daemon_logs_truthful_warning_once_and_preserves_genuine_unidentified_warning() -> TestResult
{
    let tmp = TempDir::new("warn")?;
    let base = &tmp.path;
    let certs = base.join("certs");
    let vault = base.join("vault");
    let srv_root = base.join("srv");
    for d in [&certs, &vault, &srv_root] {
        fs::create_dir_all(d)?;
    }
    let provider = build_crypto_provider(true);
    let (_, srv_pem) = generate_dev_certificate(&["warn.s5.test".to_owned()], &provider)?;
    let srv_cert = certs.join("server.pem");
    let srv_key = vault.join("server.key");
    fs::write(&srv_cert, &srv_pem.cert_pem)?;
    fs::write(&srv_key, srv_pem.key_pem.as_str())?;

    // Self-referencing symlink causes ELOOP on open even when running as root.
    let eloop_cred = base.join("loop-cred");
    symlink(&eloop_cred, &eloop_cred)?;

    let split_kdl = format!(
        r#"server {{
    listen "127.0.0.1:8443" protocols="h1"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "{}"
        cert "{}"
        key "{}"
    }}
}}
site "warn.s5.test" {{ root "{}" }}
"#,
        kdl_escape_path(&base.join("keyd.sock")),
        kdl_escape_path(&srv_cert),
        kdl_escape_path(&srv_key),
        kdl_escape_path(&srv_root),
    );
    let (split_cfg, _) = parse_kdl("split_warn.kdl", &split_kdl)?;
    let agent_keys = Arc::new(AgentKeyRegistry::new());

    let expected_split_msg = "in split-daemon mode the credential inventory skips signing keys; \
        multi-linked files are refused, the file cache is not used, and on Linux descriptor \
        retention falls back to a fresh lookup";
    let expected_unid_msg = "a configured credential file cannot be opened by the server to \
        learn its identity; files with several hard links are not served until it can";

    // 1. Clean split-daemon compile: logs ONLY the split-mode warning once, NOT the old sentence.
    let (res1, msgs1) = capture_warns(|| CompiledRouter::compile(&split_cfg, &agent_keys));
    res1?;
    assert_eq!(
        msgs1
            .iter()
            .filter(|m| m.as_str() == expected_split_msg)
            .count(),
        1,
        "expected exactly one split-mode warning, got: {msgs1:?}"
    );
    assert!(
        !msgs1.iter().any(|m| m.contains("cannot be opened")),
        "intentional split-daemon skip must not log the old 'cannot be opened' warning: {msgs1:?}"
    );

    // 2. Split-daemon compile WITH a genuine unopenable extra credential: logs BOTH warnings.
    let bad_creds = CredentialSources {
        files: vec![eloop_cred],
        dirs: Vec::new(),
    };
    let (res2, msgs2) = capture_warns(|| {
        CompiledRouter::compile_with_credentials(&split_cfg, &agent_keys, false, &bad_creds)
    });
    res2?;
    assert_eq!(
        msgs2
            .iter()
            .filter(|m| m.as_str() == expected_split_msg)
            .count(),
        1,
        "expected split-mode warning once, got: {msgs2:?}"
    );
    assert_eq!(
        msgs2
            .iter()
            .filter(|m| m.as_str() == expected_unid_msg)
            .count(),
        1,
        "expected genuine unidentified warning once, got: {msgs2:?}"
    );

    // 3. In-process compile with a genuine unopenable credential: logs ONLY the old sentence.
    let inproc_kdl = format!(
        r#"server {{
    listen "127.0.0.1:8443" protocols="h1"
    tls {{
        key-isolation "in-process"
        cert "{}"
        key "{}"
    }}
}}
site "warn.s5.test" {{ root "{}" }}
"#,
        kdl_escape_path(&srv_cert),
        kdl_escape_path(&srv_key),
        kdl_escape_path(&srv_root),
    );
    let (inproc_cfg, _) = parse_kdl("inproc_warn.kdl", &inproc_kdl)?;
    let (res3, msgs3) = capture_warns(|| {
        CompiledRouter::compile_with_credentials(&inproc_cfg, &agent_keys, false, &bad_creds)
    });
    res3?;
    assert_eq!(
        msgs3
            .iter()
            .filter(|m| m.as_str() == expected_unid_msg)
            .count(),
        1,
        "expected genuine unidentified warning once in in-process mode, got: {msgs3:?}"
    );
    assert!(
        !msgs3.iter().any(|m| m.contains("split-daemon")),
        "in-process mode must never log the split-daemon warning: {msgs3:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keyd_failure_remains_closed_on_startup_and_reload() -> TestResult {
    let tmp = TempDir::new("kfail")?;
    let base = &tmp.path;
    let certs = base.join("certs");
    let vault = base.join("vault");
    let srv_root = base.join("srv");
    for d in [&certs, &vault, &srv_root] {
        fs::create_dir_all(d)?;
    }
    fs::write(srv_root.join("index.html"), "kfail-ok")?;

    let provider = build_crypto_provider(true);
    let (srv_ck, srv_pem) = generate_dev_certificate(&["kf.s5.test".to_owned()], &provider)?;
    let srv_cert = certs.join("server.pem");
    let srv_key = vault.join("server.key");
    fs::write(&srv_cert, &srv_pem.cert_pem)?;
    fs::write(&srv_key, srv_pem.key_pem.as_str())?;

    let dead_sock = base.join("missing-keyd.sock");
    let dead_cfg_path = base.join("dead.kdl");
    fs::write(
        &dead_cfg_path,
        format!(
            r#"server {{
    listen "127.0.0.1:8443" protocols="h1"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "{}"
        cert "{}"
        key "{}"
    }}
}}
site "kf.s5.test" {{ root "{}" }}
"#,
            kdl_escape_path(&dead_sock),
            kdl_escape_path(&srv_cert),
            kdl_escape_path(&srv_key),
            kdl_escape_path(&srv_root),
        ),
    )?;

    // Startup with unavailable keyd MUST fail closed even when dev_tls: true, with exact keyd error.
    let start_res = MiraServeServer::start(
        Arc::new(ConfigStore::new(load_ephemeral(&dead_cfg_path)?)),
        ServerOptions {
            dev_tls: true,
            config_path: Some(dead_cfg_path),
            apply_sandbox: false,
            ..ServerOptions::default()
        },
    )
    .await;
    match start_res {
        Err(CoreError::Tls(TlsError::KeyLoad(msg))) => {
            let expected_prefix = format!(
                "failed to connect to keyd Unix socket '{}': ",
                dead_sock.display()
            );
            assert!(
                msg.starts_with(&expected_prefix),
                "expected exact keyd connect error starting with {expected_prefix:?}, got: {msg:?}"
            );
        }
        Ok(srv) => {
            srv.shutdown().await;
            return Err("split-daemon startup must fail closed when keyd is unavailable".into());
        }
        Err(other) => {
            return Err(format!(
                "expected CoreError::Tls(TlsError::KeyLoad) on startup keyd failure, got: {other:?}"
            )
            .into());
        }
    }

    // Start live server with real keyd, then shut down keyd: reload must fail closed with the
    // exact keyd connect error and preserve generation 1 intact.
    let live_sock = base.join("live-keyd.sock");
    let mut kstore = KeydKeyStore::new();
    kstore.insert_certified_key("srv", Vec::new(), true, srv_ck)?;
    let keyd = KeydServer::start(KeydEndpoint::Unix(live_sock.clone()), kstore, false).await?;

    let live_cfg_path = base.join("live.kdl");
    fs::write(
        &live_cfg_path,
        format!(
            r#"server {{
    listen "127.0.0.1:8443" protocols="h1"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "{}"
        cert "{}"
        key "{}"
    }}
}}
site "kf.s5.test" {{ root "{}" }}
"#,
            kdl_escape_path(&live_sock),
            kdl_escape_path(&srv_cert),
            kdl_escape_path(&srv_key),
            kdl_escape_path(&srv_root),
        ),
    )?;
    let store = Arc::new(ConfigStore::new(load_ephemeral(&live_cfg_path)?));
    let server = MiraServeServer::start(
        Arc::clone(&store),
        ServerOptions {
            dev_tls: true,
            config_path: Some(live_cfg_path.clone()),
            apply_sandbox: false,
            ..ServerOptions::default()
        },
    )
    .await?;

    let gen_before = store.generation();
    keyd.shutdown().await;
    match server.reload_from_file(&live_cfg_path) {
        Err(CoreError::Tls(TlsError::KeyLoad(msg))) => {
            let expected_prefix = format!(
                "failed to connect to keyd Unix socket '{}': ",
                live_sock.display()
            );
            assert!(
                msg.starts_with(&expected_prefix),
                "expected exact keyd connect error starting with {expected_prefix:?}, got: {msg:?}"
            );
        }
        other => {
            return Err(format!(
                "expected CoreError::Tls(TlsError::KeyLoad) on reload keyd loss, got: {other:?}"
            )
            .into());
        }
    }
    assert_eq!(
        store.generation(),
        gen_before,
        "failed reload must preserve the committed generation"
    );
    server.shutdown().await;
    Ok(())
}

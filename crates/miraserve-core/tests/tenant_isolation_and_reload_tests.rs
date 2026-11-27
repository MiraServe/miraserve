//! Wave 5 integration tests (HANDOVER §4 & §5 #8, #9, #10):
//! - Tenant-owned disk failures (missing `site.root`, missing `route.root`, missing `.wasm`
//!   plugin, missing relative error page) isolate ONLY the broken site/route to `503`/built-in
//!   error page and NEVER fail startup or hot reload for healthy sibling sites.
//! - Absolute error pages outside the site root check EVERY path component (including
//!   intermediate directories) for symlinks and fall back to the built-in error page.
//! - Reload introducing paths outside the startup Landlock policy is refused with
//!   `CoreError::RestartRequired` while the previous configuration continues serving live traffic.

use std::fs;
use std::net::TcpListener as StdTcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::header::{ACCEPT, HOST};
use http::{Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper_util::rt::TokioIo;
use miraserve_config::{ConfigStore, parse_kdl};
use miraserve_core::{CoreError, ListenerKind, MiraServeServer, ServerOptions};
use miraserve_tls::build_crypto_provider;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Result<Self, std::io::Error> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path =
            std::env::temp_dir().join(format!("miraserve-w5-{tag}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn reserve_free_port() -> Result<u16, std::io::Error> {
    let sock = StdTcpListener::bind("127.0.0.1:0")?;
    Ok(sock.local_addr()?.port())
}

/// Starts `MiraServeServer` on a freshly picked loopback port, retrying on `AddrInUse`.
async fn start_server_with_free_port<F>(
    source_name: &str,
    make_kdl: F,
    options: ServerOptions,
) -> Result<(miraserve_core::RunningServer, u16, String), Box<dyn std::error::Error>>
where
    F: FnMut(u16) -> String,
{
    start_server_with_free_port_inner(source_name, make_kdl, options, None, "").await
}

/// Like [`start_server_with_free_port`], bounding each `MiraServeServer::start` attempt by
/// `attempt_timeout`.
#[cfg(unix)]
async fn start_server_with_free_port_within<F>(
    source_name: &str,
    make_kdl: F,
    options: ServerOptions,
    attempt_timeout: std::time::Duration,
    timeout_msg: &'static str,
) -> Result<(miraserve_core::RunningServer, u16, String), Box<dyn std::error::Error>>
where
    F: FnMut(u16) -> String,
{
    start_server_with_free_port_inner(
        source_name,
        make_kdl,
        options,
        Some(attempt_timeout),
        timeout_msg,
    )
    .await
}

async fn start_server_with_free_port_inner<F>(
    source_name: &str,
    mut make_kdl: F,
    options: ServerOptions,
    attempt_timeout: Option<std::time::Duration>,
    timeout_msg: &'static str,
) -> Result<(miraserve_core::RunningServer, u16, String), Box<dyn std::error::Error>>
where
    F: FnMut(u16) -> String,
{
    let mut last_err: Option<CoreError> = None;
    for _ in 0..16 {
        let port = reserve_free_port()?;
        let kdl = make_kdl(port);
        let (cfg, _) = parse_kdl(source_name, &kdl)?;
        let start_fut = MiraServeServer::start(Arc::new(ConfigStore::new(cfg)), options.clone());
        let outcome = match attempt_timeout {
            Some(limit) => tokio::time::timeout(limit, start_fut)
                .await
                .map_err(|_| timeout_msg)?,
            None => start_fut.await,
        };
        match outcome {
            Ok(server) => return Ok((server, port, kdl)),
            Err(CoreError::Bind { source, addr })
                if source.kind() == std::io::ErrorKind::AddrInUse =>
            {
                last_err = Some(CoreError::Bind { addr, source });
            }
            Err(err) => return Err(err.into()),
        }
    }
    Err(last_err.map_or_else(|| "exhausted bind retries".into(), Into::into))
}

fn build_h1_tls_connector(cert_pem: &str) -> Result<TlsConnector, Box<dyn std::error::Error>> {
    let mut roots = RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert_pem.as_bytes()).collect::<Result<_, _>>()?;
    roots.add_parsable_certificates(certs);

    let mut client_cfg = ClientConfig::builder_with_provider(build_crypto_provider(false))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsConnector::from(Arc::new(client_cfg)))
}

async fn https_get(
    addr: std::net::SocketAddr,
    connector: &TlsConnector,
    host: &str,
    path: &str,
) -> Result<(StatusCode, String), Box<dyn std::error::Error>> {
    let tcp = TcpStream::connect(addr).await?;
    let tls = connector
        .connect(ServerName::try_from(host.to_owned())?, tcp)
        .await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .uri(path)
        .header(HOST, host)
        .header(ACCEPT, "text/html")
        .body(Empty::<Bytes>::new())?;
    let resp = sender.send_request(req).await?;
    let status = resp.status();
    let body = resp.into_body().collect().await?.to_bytes();
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn tenant_owned_missing_roots_wasm_and_intermediate_symlink_error_pages_never_break_other_sites()
-> TestResult {
    let tmp = TempDir::new("tenant-iso")?;
    let healthy_root = tmp.path.join("healthy");
    let broken_routes_root = tmp.path.join("broken-routes");
    let deleted_site_root = tmp.path.join("deleted-tenant-root"); // intentionally NOT created
    let deleted_route_root = tmp.path.join("deleted-route-root"); // intentionally NOT created
    let missing_wasm = tmp.path.join("missing-plugin.wasm");
    let secret_dir = tmp.path.join("other-tenant-secrets");
    let error_dir_symlink = tmp.path.join("tenant-errors-link");

    fs::create_dir_all(&healthy_root)?;
    fs::create_dir_all(&broken_routes_root)?;
    fs::create_dir_all(&secret_dir)?;
    fs::write(healthy_root.join("index.html"), b"healthy-site-ok")?;
    fs::write(
        broken_routes_root.join("index.html"),
        b"broken-routes-home-ok",
    )?;
    fs::write(secret_dir.join("404.html"), b"OTHER_TENANT_SECRET_LEAK")?;

    #[cfg(unix)]
    std::os::unix::fs::symlink(&secret_dir, &error_dir_symlink)?;
    let abs_symlinked_dir_404 = error_dir_symlink.join("404.html");

    let (server, tls_port, kdl) = start_server_with_free_port(
        "tenant-iso.kdl",
        |tls_port| {
            format!(
                r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
}}
site "healthy.example" {{
    root "{healthy}"
}}
site "deleted-root.example" {{
    root "{deleted_site}"
    error-pages {{
        page 404 "/errors/404.html"
    }}
    route "/go" {{
        redirect "https://healthy.example/landed" status=301
    }}
}}
site "broken-routes.example" {{
    root "{broken_routes}"
    error-pages {{
        page 404 "{abs_err_404}"
    }}
    route "/files/*" {{
        root "{deleted_route}"
        static
    }}
    route "/wasm/*" {{
        wasm-plugin "{missing_wasm}"
    }}
}}
"#,
                healthy = healthy_root.to_string_lossy().replace('\\', "/"),
                deleted_site = deleted_site_root.to_string_lossy().replace('\\', "/"),
                broken_routes = broken_routes_root.to_string_lossy().replace('\\', "/"),
                abs_err_404 = abs_symlinked_dir_404.to_string_lossy().replace('\\', "/"),
                deleted_route = deleted_route_root.to_string_lossy().replace('\\', "/"),
                missing_wasm = missing_wasm.to_string_lossy().replace('\\', "/"),
            )
        },
        ServerOptions {
            dev_tls: true,
            ..ServerOptions::default()
        },
    )
    .await?;
    let cert_pem = server
        .dev_cert_pem()
        .ok_or("expected dev TLS cert")?
        .to_owned();
    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|l| l.kind == ListenerKind::HttpsTcp)
        .map(|l| l.local_addr)
        .ok_or("expected HTTPS listener")?;
    let connector = build_h1_tls_connector(&cert_pem)?;

    // 1. Healthy sibling site serves 200 OK unaffected by broken tenants.
    let (status, body) = https_get(https_addr, &connector, "healthy.example", "/").await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "healthy-site-ok");

    // 2. Site whose tenant deleted `site.root` returns 503 on `/` while its `/go` redirect works!
    let (status, _) = https_get(https_addr, &connector, "deleted-root.example", "/").await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let (status, _) = https_get(https_addr, &connector, "deleted-root.example", "/go").await?;
    assert_eq!(status, StatusCode::MOVED_PERMANENTLY);

    // 3. Site with broken static route root + missing WASM plugin still serves `/` (200 OK),
    //    returns 503 ONLY on the broken routes, and refuses intermediate-dir symlink error page!
    let (status, body) = https_get(https_addr, &connector, "broken-routes.example", "/").await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "broken-routes-home-ok");

    let (status, _) = https_get(
        https_addr,
        &connector,
        "broken-routes.example",
        "/files/a.txt",
    )
    .await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    let (status, _) = https_get(
        https_addr,
        &connector,
        "broken-routes.example",
        "/wasm/test",
    )
    .await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    let (status, body_404) = https_get(
        https_addr,
        &connector,
        "broken-routes.example",
        "/missing-page",
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        !body_404.contains("OTHER_TENANT_SECRET_LEAK"),
        "absolute error page with symlinked intermediate directory MUST NOT read target file"
    );

    // 4. Reloading the same multi-tenant config ALSO succeeds cleanly despite broken tenant files!
    let generation = server.reload_from_str("tenant-iso-reload.kdl", &kdl)?;
    assert!(generation >= 1);

    // 5. Missing per-site TLS cert on reload STILL fails and explicitly names the offending site!
    let missing_cert = tmp.path.join("nope.pem");
    let missing_key = tmp.path.join("nope.key");
    let bad_tls_kdl = format!(
        r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
}}
site "bad-cert.example" {{
    root "{healthy}"
    tls {{
        cert "{cert}"
        key "{key}"
    }}
}}
"#,
        healthy = healthy_root.to_string_lossy().replace('\\', "/"),
        cert = missing_cert.to_string_lossy().replace('\\', "/"),
        key = missing_key.to_string_lossy().replace('\\', "/"),
    );
    let tls_err = server
        .reload_from_str("bad-tls.kdl", &bad_tls_kdl)
        .err()
        .ok_or("expected missing per-site TLS cert to fail reload")?;
    assert!(
        tls_err.to_string().contains("bad-cert.example"),
        "per-site TLS reload error must name the offending site, got: {tls_err}"
    );

    server.shutdown().await;
    Ok(())
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn reload_refuses_uncovered_sandbox_path_with_restart_required_and_keeps_old_config_serving()
-> TestResult {
    let tmp = TempDir::new("restart-req")?;
    let tree_a = tmp.path.join("tree-a");
    let site_a1 = tree_a.join("site-a1");
    let site_a2 = tree_a.join("site-a2");
    let tree_b = tmp.path.join("tree-b");
    let site_b = tree_b.join("site-b");
    fs::create_dir_all(&site_a1)?;
    fs::create_dir_all(&site_a2)?;
    fs::create_dir_all(&site_b)?;
    fs::write(site_a1.join("index.html"), b"tree-a1-v1")?;
    fs::write(site_a2.join("index.html"), b"tree-a2-v2")?;
    fs::write(site_b.join("index.html"), b"tree-b-uncovered")?;

    let cert_path = tree_a.join("server.pem");
    let key_path = tree_a.join("server.key");
    let (_, dev_pem) = miraserve_tls::generate_dev_certificate(
        &[
            "a1.example".to_owned(),
            "a2.example".to_owned(),
            "b.example".to_owned(),
        ],
        &build_crypto_provider(false),
    )?;
    fs::write(&cert_path, &dev_pem.cert_pem)?;
    fs::write(&key_path, &dev_pem.key_pem)?;

    let (server, tls_port, _) = start_server_with_free_port(
        "restart-req-v1.kdl",
        |tls_port| {
            format!(
                r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    tls {{
        cert "{cert}"
        key "{key}"
    }}
    sandbox {{
        landlock true
        seccomp "off"
        read-tree "{tree_a}"
    }}
}}
site "a1.example" {{
    root "{site_a1}"
}}
"#,
                cert = cert_path.to_string_lossy().replace('\\', "/"),
                key = key_path.to_string_lossy().replace('\\', "/"),
                tree_a = tree_a.to_string_lossy().replace('\\', "/"),
                site_a1 = site_a1.to_string_lossy().replace('\\', "/"),
            )
        },
        ServerOptions {
            apply_sandbox: true,
            ..ServerOptions::default()
        },
    )
    .await?;
    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|l| l.kind == ListenerKind::HttpsTcp)
        .map(|l| l.local_addr)
        .ok_or("expected HTTPS listener")?;
    let connector = build_h1_tls_connector(&dev_pem.cert_pem)?;

    let (status, body) = https_get(https_addr, &connector, "a1.example", "/").await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "tree-a1-v1");

    // 1. Reload introducing a site outside the startup `read-tree` MUST be refused with
    //    `CoreError::RestartRequired` and keep the previous config serving!
    let kdl_uncovered = format!(
        r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    tls {{
        cert "{cert}"
        key "{key}"
    }}
    sandbox {{
        landlock true
        seccomp "off"
        read-tree "{tree_a}"
    }}
}}
site "a1.example" {{
    root "{site_a1}"
}}
site "b.example" {{
    root "{site_b}"
}}
"#,
        cert = cert_path.to_string_lossy().replace('\\', "/"),
        key = key_path.to_string_lossy().replace('\\', "/"),
        tree_a = tree_a.to_string_lossy().replace('\\', "/"),
        site_a1 = site_a1.to_string_lossy().replace('\\', "/"),
        site_b = site_b.to_string_lossy().replace('\\', "/"),
    );
    let err = server
        .reload_from_str("restart-req-uncovered.kdl", &kdl_uncovered)
        .err()
        .ok_or("expected RestartRequired error for uncovered sandbox path")?;
    assert!(
        matches!(err, CoreError::RestartRequired(_)),
        "expected CoreError::RestartRequired, got: {err:?}"
    );
    assert!(
        err.to_string().contains("site-b"),
        "RestartRequired message should identify the uncovered path, got: {err}"
    );

    // Previous live config keeps serving `a1.example` and does NOT serve `b.example`!
    let (status_a1, body_a1) = https_get(https_addr, &connector, "a1.example", "/").await?;
    assert_eq!(status_a1, StatusCode::OK);
    assert_eq!(body_a1, "tree-a1-v1");
    let (status_b, _) = https_get(https_addr, &connector, "b.example", "/").await?;
    assert_eq!(status_b, StatusCode::MISDIRECTED_REQUEST);

    // 2. Reload adding a site INSIDE the startup `read-tree` succeeds cleanly without restart!
    let kdl_covered = format!(
        r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    tls {{
        cert "{cert}"
        key "{key}"
    }}
    sandbox {{
        landlock true
        seccomp "off"
        read-tree "{tree_a}"
    }}
}}
site "a1.example" {{
    root "{site_a1}"
}}
site "a2.example" {{
    root "{site_a2}"
}}
"#,
        cert = cert_path.to_string_lossy().replace('\\', "/"),
        key = key_path.to_string_lossy().replace('\\', "/"),
        tree_a = tree_a.to_string_lossy().replace('\\', "/"),
        site_a1 = site_a1.to_string_lossy().replace('\\', "/"),
        site_a2 = site_a2.to_string_lossy().replace('\\', "/"),
    );
    let generation = server.reload_from_str("restart-req-covered.kdl", &kdl_covered)?;
    assert!(generation >= 1);
    let (status_a2, body_a2) = https_get(https_addr, &connector, "a2.example", "/").await?;
    assert_eq!(status_a2, StatusCode::OK);
    assert_eq!(body_a2, "tree-a2-v2");

    server.shutdown().await;
    Ok(())
}

/// Codex G3: Tenant-owned FIFOs (`mkfifo`) configured as a confined relative error page, an
/// absolute error page, or a `.wasm` plugin MUST NOT block startup or reload; nonblocking Unix
/// opens immediately reject non-regular descriptors so broken sites fall back cleanly while
/// healthy sibling sites keep serving `200 OK`.
#[cfg(unix)]
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn g3_tenant_fifos_in_error_pages_and_wasm_never_stall_startup_or_sibling_sites() -> TestResult
{
    use std::process::Command;
    use std::time::Duration;

    let tmp = TempDir::new("g3-fifo")?;
    let healthy_root = tmp.path.join("healthy");
    let rel_fifo_root = tmp.path.join("rel-fifo");
    let abs_fifo_root = tmp.path.join("abs-fifo");
    let wasm_fifo_root = tmp.path.join("wasm-fifo");
    for d in [
        &healthy_root,
        &rel_fifo_root,
        &abs_fifo_root,
        &wasm_fifo_root,
    ] {
        fs::create_dir_all(d)?;
    }
    fs::write(healthy_root.join("index.html"), b"healthy-sibling-ok")?;

    let rel_fifo = rel_fifo_root.join("404.html");
    let abs_fifo = tmp.path.join("abs-404.fifo");
    let wasm_fifo = tmp.path.join("plugin.wasm");
    for fifo in [&rel_fifo, &abs_fifo, &wasm_fifo] {
        let status = Command::new("mkfifo").arg(fifo).status()?;
        assert!(status.success(), "mkfifo failed for {}", fifo.display());
    }

    let cert_path = tmp.path.join("server.pem");
    let key_path = tmp.path.join("server.key");
    let (_, dev_pem) = miraserve_tls::generate_dev_certificate(
        &[
            "healthy.example".to_owned(),
            "rel-fifo.example".to_owned(),
            "abs-fifo.example".to_owned(),
            "wasm-fifo.example".to_owned(),
        ],
        &build_crypto_provider(false),
    )?;
    fs::write(&cert_path, &dev_pem.cert_pem)?;
    fs::write(&key_path, &dev_pem.key_pem)?;

    let (server, _, kdl) = start_server_with_free_port_within(
        "g3-fifo.kdl",
        |tls_port| {
            format!(
                r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    tls {{
        cert "{cert}"
        key "{key}"
    }}
}}
site "healthy.example" {{
    root "{healthy_root}"
}}
site "rel-fifo.example" {{
    root "{rel_fifo_root}"
    error-pages {{
        page 404 "/404.html"
    }}
}}
site "abs-fifo.example" {{
    root "{abs_fifo_root}"
    error-pages {{
        page 404 "{abs_fifo}"
    }}
}}
site "wasm-fifo.example" {{
    root "{wasm_fifo_root}"
    route "/plugin/*" {{
        wasm-plugin "{wasm_fifo}"
    }}
}}
"#,
                cert = cert_path.to_string_lossy().replace('\\', "/"),
                key = key_path.to_string_lossy().replace('\\', "/"),
                healthy_root = healthy_root.to_string_lossy().replace('\\', "/"),
                rel_fifo_root = rel_fifo_root.to_string_lossy().replace('\\', "/"),
                abs_fifo_root = abs_fifo_root.to_string_lossy().replace('\\', "/"),
                abs_fifo = abs_fifo.to_string_lossy().replace('\\', "/"),
                wasm_fifo_root = wasm_fifo_root.to_string_lossy().replace('\\', "/"),
                wasm_fifo = wasm_fifo.to_string_lossy().replace('\\', "/"),
            )
        },
        ServerOptions {
            apply_sandbox: false,
            ..ServerOptions::default()
        },
        Duration::from_secs(5),
        "MiraServeServer::start timed out",
    )
    .await?;

    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|l| l.kind == ListenerKind::HttpsTcp)
        .map(|l| l.local_addr)
        .ok_or("expected HTTPS listener")?;
    let connector = build_h1_tls_connector(&dev_pem.cert_pem)?;

    // Healthy sibling serves 200 OK.
    let (s_ok, b_ok) = https_get(https_addr, &connector, "healthy.example", "/").await?;
    assert_eq!(s_ok, StatusCode::OK);
    assert_eq!(b_ok, "healthy-sibling-ok");

    // Both FIFO error-page sites return built-in 404 without stalling.
    for host in ["rel-fifo.example", "abs-fifo.example"] {
        let (s_404, b_404) = tokio::time::timeout(
            Duration::from_secs(3),
            https_get(https_addr, &connector, host, "/missing"),
        )
        .await
        .map_err(|_| format!("request to {host} stalled on FIFO"))??;
        assert_eq!(s_404, StatusCode::NOT_FOUND, "{host}");
        assert!(
            b_404.contains("404") || b_404.contains("Not Found"),
            "expected built-in 404 fallback on {host}, got: {b_404}"
        );
    }

    // Live request directly targeting the FIFO inside docroot ALSO returns 404 without stalling!
    let (s_direct, _) = tokio::time::timeout(
        Duration::from_secs(3),
        https_get(https_addr, &connector, "rel-fifo.example", "/404.html"),
    )
    .await
    .map_err(|_| "direct static request to FIFO stalled")??;
    assert_eq!(s_direct, StatusCode::NOT_FOUND);

    // FIFO WASM plugin route fails isolated with 503 Service Unavailable.
    let (s_wasm, _) = tokio::time::timeout(
        Duration::from_secs(3),
        https_get(https_addr, &connector, "wasm-fifo.example", "/plugin/run"),
    )
    .await
    .map_err(|_| "WASM FIFO route stalled")??;
    assert_eq!(s_wasm, StatusCode::SERVICE_UNAVAILABLE);

    // Reload with the exact same FIFO config MUST also finish promptly without blocking!
    let reload_handle = tokio::task::spawn_blocking(move || {
        let res = server.reload_from_str("g3-fifo-reload.kdl", &kdl);
        (server, res)
    });
    let (server, reload_res) = tokio::time::timeout(Duration::from_secs(5), reload_handle)
        .await
        .map_err(|_| "reload stalled on tenant FIFO")??;
    assert!(reload_res.is_ok(), "reload failed: {reload_res:?}");

    server.shutdown().await;
    Ok(())
}

/// Codex G7 (P1): A reload introducing a site whose document root overlaps the active rotating
/// log directory MUST be refused with `CoreError::UnsafeDocroot`, keeping the old configuration
/// serving and never exposing the private log directory as static HTTP content.
#[tokio::test]
async fn g7_p1_reload_refuses_docroot_overlapping_active_log_directory_and_keeps_old_config()
-> TestResult {
    let tmp = TempDir::new("g7-reload-log-conflict")?;
    let www = tmp.path.join("www");
    let logs = tmp.path.join("logs");
    fs::create_dir_all(&www)?;
    fs::create_dir_all(&logs)?;
    fs::write(www.join("index.html"), b"healthy-site-v1")?;
    fs::write(logs.join("access.log"), b"PRIVATE-ACCESS-LOG-ENTRY\n")?;

    let cert_path = tmp.path.join("server.pem");
    let key_path = tmp.path.join("server.key");
    let (_, dev_pem) = miraserve_tls::generate_dev_certificate(
        &["good.example".to_owned(), "evil.example".to_owned()],
        &build_crypto_provider(false),
    )?;
    fs::write(&cert_path, &dev_pem.cert_pem)?;
    fs::write(&key_path, &dev_pem.key_pem)?;

    let log_file = logs.join("access.log");
    let (server, tls_port, _) = start_server_with_free_port(
        "g7-v1.kdl",
        |tls_port| {
            format!(
                r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    tls {{
        cert "{cert}"
        key "{key}"
    }}
}}
site "good.example" {{
    root "{www}"
}}
"#,
                cert = cert_path.to_string_lossy().replace('\\', "/"),
                key = key_path.to_string_lossy().replace('\\', "/"),
                www = www.to_string_lossy().replace('\\', "/"),
            )
        },
        ServerOptions {
            apply_sandbox: false,
            log_file_paths: vec![log_file.clone()],
            log_rotation_paths: vec![log_file],
            ..ServerOptions::default()
        },
    )
    .await?;

    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|l| l.kind == ListenerKind::HttpsTcp)
        .map(|l| l.local_addr)
        .ok_or("expected HTTPS listener")?;
    let connector = build_h1_tls_connector(&dev_pem.cert_pem)?;

    let (s1, b1) = https_get(https_addr, &connector, "good.example", "/").await?;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(b1, "healthy-site-v1");

    // Reload attempting to expose the active log directory as a site's document root MUST fail!
    let kdl_conflict = format!(
        r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    tls {{
        cert "{cert}"
        key "{key}"
    }}
}}
site "good.example" {{
    root "{www}"
}}
site "evil.example" {{
    root "{logs}"
}}
"#,
        cert = cert_path.to_string_lossy().replace('\\', "/"),
        key = key_path.to_string_lossy().replace('\\', "/"),
        www = www.to_string_lossy().replace('\\', "/"),
        logs = logs.to_string_lossy().replace('\\', "/"),
    );
    let err = server
        .reload_from_str("g7-conflict.kdl", &kdl_conflict)
        .err()
        .ok_or("expected reload exposing active log directory to fail")?;
    assert!(
        matches!(err, CoreError::UnsafeDocroot(_)),
        "expected CoreError::UnsafeDocroot, got: {err:?}"
    );

    // Previous config stays live and `evil.example` is NOT served!
    let (s_good, b_good) = https_get(https_addr, &connector, "good.example", "/").await?;
    assert_eq!(s_good, StatusCode::OK);
    assert_eq!(b_good, "healthy-site-v1");
    let (s_evil, _) = https_get(https_addr, &connector, "evil.example", "/access.log").await?;
    assert_eq!(s_evil, StatusCode::MISDIRECTED_REQUEST);

    server.shutdown().await;
    Ok(())
}

/// Codex G2: An allowed external absolute custom error page outside the document root MUST load
/// via traversal-only directory descriptors (`O_PATH` on Linux) and serve its custom body both
/// before AND after a real live reload.
#[tokio::test]
async fn g2_external_absolute_custom_error_page_survives_live_reload() -> TestResult {
    let tmp = TempDir::new("g2-abs-err-reload")?;
    let www = tmp.path.join("www");
    let err_dir = tmp.path.join("shared-errors");
    fs::create_dir_all(&www)?;
    fs::create_dir_all(&err_dir)?;
    fs::write(www.join("index.html"), b"site-ok")?;
    let abs_404 = err_dir.join("404.html");
    fs::write(&abs_404, b"<html>CUSTOM-EXTERNAL-404-V1</html>")?;

    let cert_path = tmp.path.join("server.pem");
    let key_path = tmp.path.join("server.key");
    let (_, dev_pem) = miraserve_tls::generate_dev_certificate(
        &["errpage.example".to_owned()],
        &build_crypto_provider(false),
    )?;
    fs::write(&cert_path, &dev_pem.cert_pem)?;
    fs::write(&key_path, &dev_pem.key_pem)?;

    let (server, _, kdl) = start_server_with_free_port(
        "g2-err-v1.kdl",
        |tls_port| {
            format!(
                r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    tls {{
        cert "{cert}"
        key "{key}"
    }}
}}
site "errpage.example" {{
    root "{www}"
    error-pages {{
        page 404 "{abs_404}"
    }}
}}
"#,
                cert = cert_path.to_string_lossy().replace('\\', "/"),
                key = key_path.to_string_lossy().replace('\\', "/"),
                www = www.to_string_lossy().replace('\\', "/"),
                abs_404 = abs_404.to_string_lossy().replace('\\', "/"),
            )
        },
        ServerOptions {
            apply_sandbox: false,
            ..ServerOptions::default()
        },
    )
    .await?;

    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|l| l.kind == ListenerKind::HttpsTcp)
        .map(|l| l.local_addr)
        .ok_or("expected HTTPS listener")?;
    let connector = build_h1_tls_connector(&dev_pem.cert_pem)?;

    let (s1, b1) = https_get(https_addr, &connector, "errpage.example", "/missing").await?;
    assert_eq!(s1, StatusCode::NOT_FOUND);
    assert!(
        b1.contains("CUSTOM-EXTERNAL-404-V1"),
        "expected external custom 404 before reload, got: {b1}"
    );

    // Update the external error page and perform a real live reload.
    fs::write(&abs_404, b"<html>CUSTOM-EXTERNAL-404-V2</html>")?;
    let generation = server.reload_from_str("g2-err-v2.kdl", &kdl)?;
    assert!(generation >= 1);

    let (s2, b2) = https_get(https_addr, &connector, "errpage.example", "/missing").await?;
    assert_eq!(s2, StatusCode::NOT_FOUND);
    assert!(
        b2.contains("CUSTOM-EXTERNAL-404-V2"),
        "expected refreshed external custom 404 after reload, got: {b2}"
    );

    server.shutdown().await;
    Ok(())
}

/// Codex Round-3 P1 #2 & P2 #2 (G7):
/// 1. A valid startup config with a rotating log directory reloads unchanged cleanly (parity).
/// 2. Reloading a config that introduces a custom `client-ca` or `ai-publish` `require-signature`
///    verification key inside the active rotating log directory MUST fail closed with
///    `CoreError::UnsafeDocroot`, leaving the previous config serving uninterrupted.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn g7_r3_p1_p2_reload_parity_and_trust_anchor_under_rotating_log_dir() -> TestResult {
    let tmp = TempDir::new("g7-r3-reload-trust")?;
    let www = tmp.path.join("www");
    let logs = tmp.path.join("logs");
    let tls_dir = tmp.path.join("tls");
    let publish_store = tmp.path.join("publish-store");
    fs::create_dir_all(&www)?;
    fs::create_dir_all(&logs)?;
    fs::create_dir_all(&tls_dir)?;
    fs::create_dir_all(&publish_store)?;
    fs::write(www.join("index.html"), b"HELLO-G7-R3")?;

    let cert_path = tls_dir.join("server.pem");
    let key_path = tls_dir.join("server.key");
    let (_, dev_pem) = miraserve_tls::generate_dev_certificate(
        &["g7trust.example".to_owned()],
        &build_crypto_provider(false),
    )?;
    fs::write(&cert_path, &dev_pem.cert_pem)?;
    fs::write(&key_path, &dev_pem.key_pem)?;

    // Place a CA PEM and a publish signature pubkey inside the rotating log directory for the
    // malicious reload attempts.
    let ca_in_logs = logs.join("client-ca.pem");
    let sig_pub_in_logs = logs.join("publish.pub");
    fs::write(&ca_in_logs, &dev_pem.cert_pem)?;
    fs::write(&sig_pub_in_logs, b"00000000000000000000000000000000")?;

    let access_log = logs.join("access.log");
    let (server, tls_port, base_kdl) = start_server_with_free_port(
        "g7-r3-v1.kdl",
        |tls_port| {
            format!(
                r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    tls {{
        cert "{cert}"
        key "{key}"
    }}
}}
site "g7trust.example" {{
    root "{www}"
}}
"#,
                cert = cert_path.to_string_lossy().replace('\\', "/"),
                key = key_path.to_string_lossy().replace('\\', "/"),
                www = www.to_string_lossy().replace('\\', "/"),
            )
        },
        ServerOptions {
            apply_sandbox: false,
            log_file_paths: vec![access_log.clone()],
            log_rotation_paths: vec![access_log],
            ..ServerOptions::default()
        },
    )
    .await?;

    // 1. Unchanged config reloads cleanly (startup/reload parity).
    let generation = server.reload_from_str("g7-r3-same.kdl", &base_kdl)?;
    assert!(generation >= 1);

    // 2. Reload introducing custom `client-ca` inside the rotating log directory MUST fail closed.
    let ca_kdl = format!(
        r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    tls {{
        cert "{cert}"
        key "{key}"
        client-ca "{ca}"
    }}
}}
site "g7trust.example" {{
    root "{www}"
}}
"#,
        cert = cert_path.to_string_lossy().replace('\\', "/"),
        key = key_path.to_string_lossy().replace('\\', "/"),
        ca = ca_in_logs.to_string_lossy().replace('\\', "/"),
        www = www.to_string_lossy().replace('\\', "/"),
    );
    let ca_err = server.reload_from_str("g7-r3-ca.kdl", &ca_kdl);
    assert!(
        matches!(ca_err, Err(CoreError::UnsafeDocroot(_))),
        "reload introducing client-ca inside rotating log dir must fail closed, got: {ca_err:?}"
    );

    // 3. Reload introducing `ai-publish` `require-signature` key inside rotating log dir MUST fail.
    let pub_kdl = format!(
        r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    tls {{
        cert "{cert}"
        key "{key}"
    }}
}}
site "g7trust.example" {{
    root "{www}"
    ai-publish {{
        storage "{storage}"
        require-signature "ed25519:{sig_pub}"
    }}
}}
"#,
        cert = cert_path.to_string_lossy().replace('\\', "/"),
        key = key_path.to_string_lossy().replace('\\', "/"),
        www = www.to_string_lossy().replace('\\', "/"),
        storage = publish_store.to_string_lossy().replace('\\', "/"),
        sig_pub = sig_pub_in_logs.to_string_lossy().replace('\\', "/"),
    );
    let pub_err = server.reload_from_str("g7-r3-pub.kdl", &pub_kdl);
    assert!(
        matches!(pub_err, Err(CoreError::UnsafeDocroot(_))),
        "reload introducing publish signature key inside rotating log dir must fail closed, got: {pub_err:?}"
    );

    // Original config still serves cleanly after both refused reloads.
    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|l| l.kind == ListenerKind::HttpsTcp)
        .map(|l| l.local_addr)
        .ok_or("expected HTTPS listener")?;
    let connector = build_h1_tls_connector(&dev_pem.cert_pem)?;
    let (status, body) = https_get(https_addr, &connector, "g7trust.example", "/").await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "HELLO-G7-R3");

    server.shutdown().await;
    Ok(())
}

/// Codex Round-4 P1 #1 (G7): A tenant-controlled absolute custom error page that is replaced on
/// disk with a symlink pointing into the active rotating log directory MUST NOT refuse startup or
/// live reload for healthy sibling sites; the affected tenant must fall back to the built-in error
/// page and private log contents must remain completely inaccessible.
#[cfg(unix)]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn g7_r4_p1_tenant_symlink_error_page_into_log_dir_never_blocks_sibling_startup_or_reload()
-> TestResult {
    let tmp = TempDir::new("g7-r4-tenant-errpage")?;
    let bad_tenant_root = tmp.path.join("tenant-a");
    let sibling_root = tmp.path.join("tenant-b");
    let logs = tmp.path.join("logs");
    let tls_dir = tmp.path.join("tls");
    for d in [&bad_tenant_root, &sibling_root, &logs, &tls_dir] {
        fs::create_dir_all(d)?;
    }
    fs::write(bad_tenant_root.join("index.html"), b"TENANT-A")?;
    fs::write(sibling_root.join("index.html"), b"SIBLING-OK-V1")?;
    let private_log = logs.join("access.log");
    fs::write(&private_log, b"PRIVATE-LOG-SECRET-TOKEN=99999\n")?;

    // Tenant A replaces its configured absolute error page with a symlink pointing directly at the
    // private rotating log file!
    let evil_404 = bad_tenant_root.join("404.html");
    std::os::unix::fs::symlink(&private_log, &evil_404)?;

    let cert_path = tls_dir.join("server.pem");
    let key_path = tls_dir.join("server.key");
    let (_, dev_pem) = miraserve_tls::generate_dev_certificate(
        &[
            "bad-tenant.example".to_owned(),
            "good-sibling.example".to_owned(),
        ],
        &build_crypto_provider(false),
    )?;
    fs::write(&cert_path, &dev_pem.cert_pem)?;
    fs::write(&key_path, &dev_pem.key_pem)?;

    let (server, _, kdl) = start_server_with_free_port(
        "g7-r4-errpage.kdl",
        |tls_port| {
            format!(
                r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    tls {{
        cert "{cert}"
        key "{key}"
    }}
}}
site "bad-tenant.example" {{
    root "{root_a}"
    error-pages {{
        page 404 "{evil_404}"
    }}
}}
site "good-sibling.example" {{
    root "{root_b}"
}}
"#,
                cert = cert_path.to_string_lossy().replace('\\', "/"),
                key = key_path.to_string_lossy().replace('\\', "/"),
                root_a = bad_tenant_root.to_string_lossy().replace('\\', "/"),
                evil_404 = evil_404.to_string_lossy().replace('\\', "/"),
                root_b = sibling_root.to_string_lossy().replace('\\', "/"),
            )
        },
        ServerOptions {
            apply_sandbox: false,
            log_file_paths: vec![private_log.clone()],
            log_rotation_paths: vec![private_log],
            ..ServerOptions::default()
        },
    )
    .await?;

    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|l| l.kind == ListenerKind::HttpsTcp)
        .map(|l| l.local_addr)
        .ok_or("expected HTTPS listener")?;
    let connector = build_h1_tls_connector(&dev_pem.cert_pem)?;

    // 1. Healthy sibling serves normally at startup.
    let (sb1, bb1) = https_get(https_addr, &connector, "good-sibling.example", "/").await?;
    assert_eq!(sb1, StatusCode::OK);
    assert_eq!(bb1, "SIBLING-OK-V1");

    // 2. Bad tenant falls back to the built-in 404 page and NEVER leaks private log contents!
    let (sa, ba) = https_get(https_addr, &connector, "bad-tenant.example", "/missing").await?;
    assert_eq!(sa, StatusCode::NOT_FOUND);
    assert!(
        !ba.contains("PRIVATE-LOG-SECRET"),
        "bad tenant symlinked error page must NEVER expose private log contents: {ba}"
    );

    // 3. Healthy sibling can still accept a live reload while bad tenant's symlink exists!
    fs::write(sibling_root.join("index.html"), b"SIBLING-OK-V2")?;
    let generation = server.reload_from_str("g7-r4-errpage-reload.kdl", &kdl)?;
    assert!(generation >= 1);
    let (sb2, bb2) = https_get(https_addr, &connector, "good-sibling.example", "/").await?;
    assert_eq!(sb2, StatusCode::OK);
    assert_eq!(bb2, "SIBLING-OK-V2");

    server.shutdown().await;
    Ok(())
}

/// Codex Round-4 P1 #3 & P2 #1 (G7):
/// 1. When a configured log alias moves between two already-granted rotating log directories
///    (`alias: logs_a -> logs_b`) after startup, a live reload MUST be refused even if the reload
///    tries to expose the original `logs_a` directory as a new site document root — keeping the
///    old site serving and never exposing `logs_a`.
/// 2. Reload introducing an outward-pointing trust-file symlink (`logs/outward-ca.pem ->
///    external_trust/ca.pem`) inside an active rotating log directory MUST also be refused.
#[cfg(unix)]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn g7_r4_p1_p2_moved_log_alias_and_outward_trust_symlink_refused_on_reload() -> TestResult {
    let tmp = TempDir::new("g7-r4-moved-alias")?;
    let www = tmp.path.join("www");
    let logs_a = tmp.path.join("logs-a");
    let logs_b = tmp.path.join("logs-b");
    let tls_dir = tmp.path.join("tls");
    let external_trust = tmp.path.join("external-trust");
    for d in [&www, &logs_a, &logs_b, &tls_dir, &external_trust] {
        fs::create_dir_all(d)?;
    }
    fs::write(www.join("index.html"), b"ORIGINAL-SITE-OK")?;
    fs::write(logs_a.join("access.log"), b"SECRET-ACCESS-LOG-A\n")?;
    fs::write(logs_b.join("server.log"), b"SECRET-SERVER-LOG-B\n")?;

    let cert_path = tls_dir.join("server.pem");
    let key_path = tls_dir.join("server.key");
    let (_, dev_pem) = miraserve_tls::generate_dev_certificate(
        &["stable.example".to_owned(), "leak-logs.example".to_owned()],
        &build_crypto_provider(false),
    )?;
    fs::write(&cert_path, &dev_pem.cert_pem)?;
    fs::write(&key_path, &dev_pem.key_pem)?;

    let ext_ca = external_trust.join("ca.pem");
    fs::write(&ext_ca, &dev_pem.cert_pem)?;
    let outward_ca_in_logs_b = logs_b.join("outward-ca.pem");
    std::os::unix::fs::symlink(&ext_ca, &outward_ca_in_logs_b)?;

    // Startup alias points to `logs_a`; second rotating log uses `logs_b` so BOTH are granted!
    let alias = tmp.path.join("log-alias");
    std::os::unix::fs::symlink(&logs_a, &alias)?;
    let access_log_alias = alias.join("access.log");
    let server_log_b = logs_b.join("server.log");

    let (server, tls_port, _) = start_server_with_free_port(
        "g7-r4-alias-v1.kdl",
        |tls_port| {
            format!(
                r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    tls {{
        cert "{cert}"
        key "{key}"
    }}
}}
site "stable.example" {{
    root "{www}"
}}
"#,
                cert = cert_path.to_string_lossy().replace('\\', "/"),
                key = key_path.to_string_lossy().replace('\\', "/"),
                www = www.to_string_lossy().replace('\\', "/"),
            )
        },
        ServerOptions {
            apply_sandbox: false,
            log_file_paths: vec![access_log_alias.clone(), server_log_b.clone()],
            log_rotation_paths: vec![access_log_alias, server_log_b],
            ..ServerOptions::default()
        },
    )
    .await?;

    // 1. Before moving alias: reload introducing outward-pointing trust-file symlink inside
    //    `logs_b` MUST be refused with `UnsafeDocroot`!
    let outward_ca_kdl = format!(
        r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    tls {{
        cert "{cert}"
        key "{key}"
        client-ca "{ca}"
    }}
}}
site "stable.example" {{
    root "{www}"
}}
"#,
        cert = cert_path.to_string_lossy().replace('\\', "/"),
        key = key_path.to_string_lossy().replace('\\', "/"),
        ca = outward_ca_in_logs_b.to_string_lossy().replace('\\', "/"),
        www = www.to_string_lossy().replace('\\', "/"),
    );
    let sym_err = server.reload_from_str("g7-r4-outward-ca.kdl", &outward_ca_kdl);
    assert!(
        matches!(sym_err, Err(CoreError::UnsafeDocroot(_))),
        "reload introducing outward-pointing trust-file symlink in rotating log dir must fail, got: {sym_err:?}"
    );

    // 2. Flip `alias` from `logs_a` to `logs_b` (another already-granted rotation directory!),
    //    then try reloading a config that exposes `logs_a` as a new site's document root.
    fs::remove_file(&alias)?;
    std::os::unix::fs::symlink(&logs_b, &alias)?;

    let expose_logs_a_kdl = format!(
        r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    tls {{
        cert "{cert}"
        key "{key}"
    }}
}}
site "stable.example" {{
    root "{www}"
}}
site "leak-logs.example" {{
    root "{logs_a}"
}}
"#,
        cert = cert_path.to_string_lossy().replace('\\', "/"),
        key = key_path.to_string_lossy().replace('\\', "/"),
        www = www.to_string_lossy().replace('\\', "/"),
        logs_a = logs_a.to_string_lossy().replace('\\', "/"),
    );
    let moved_err = server.reload_from_str("g7-r4-expose-logs-a.kdl", &expose_logs_a_kdl);
    assert!(
        matches!(moved_err, Err(CoreError::UnsafeDocroot(_))),
        "reload after log alias moved to another granted dir MUST fail closed, got: {moved_err:?}"
    );

    // 3. Old site MUST keep serving and `leak-logs.example` MUST NOT serve `logs_a/access.log`!
    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|l| l.kind == ListenerKind::HttpsTcp)
        .map(|l| l.local_addr)
        .ok_or("expected HTTPS listener")?;
    let connector = build_h1_tls_connector(&dev_pem.cert_pem)?;
    let (s_ok, b_ok) = https_get(https_addr, &connector, "stable.example", "/").await?;
    assert_eq!(s_ok, StatusCode::OK);
    assert_eq!(b_ok, "ORIGINAL-SITE-OK");

    let (s_leak, b_leak) =
        https_get(https_addr, &connector, "leak-logs.example", "/access.log").await?;
    assert_ne!(s_leak, StatusCode::OK);
    assert!(!b_leak.contains("SECRET-ACCESS-LOG-A"));

    server.shutdown().await;
    Ok(())
}

/// Writes a dev certificate covering `hosts` into `dir` and returns `(cert, key, cert_pem)`.
fn r5_dev_cert(
    dir: &std::path::Path,
    hosts: &[&str],
) -> Result<(PathBuf, PathBuf, String), Box<dyn std::error::Error>> {
    fs::create_dir_all(dir)?;
    let cert_path = dir.join("server.pem");
    let key_path = dir.join("server.key");
    let (_, dev_pem) = miraserve_tls::generate_dev_certificate(
        &hosts.iter().map(|h| (*h).to_owned()).collect::<Vec<_>>(),
        &build_crypto_provider(false),
    )?;
    fs::write(&cert_path, &dev_pem.cert_pem)?;
    fs::write(&key_path, &dev_pem.key_pem)?;
    Ok((cert_path, key_path, dev_pem.cert_pem))
}

fn r5_https_addr(server: &miraserve_core::RunningServer) -> Result<std::net::SocketAddr, String> {
    server
        .bound_listeners()
        .iter()
        .find(|l| l.kind == ListenerKind::HttpsTcp)
        .map(|l| l.local_addr)
        .ok_or_else(|| "expected HTTPS listener".to_owned())
}

/// Codex Round-5 P1 #3 (G7): with file rotation enabled, a tenant-owned WASM module that is a
/// symlink into the rotating-log directory must NOT reject startup or reload for the whole
/// server. The module's route returns 503, an unrelated site serves, and a reload is accepted.
#[cfg(unix)]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn g7_r5_p1_tenant_wasm_symlink_into_log_dir_isolated_to_route_with_rotation() -> TestResult {
    let tmp = TempDir::new("r5-wasm-rot")?;
    let tenant_root = tmp.path.join("tenant");
    let sibling_root = tmp.path.join("sibling");
    let logs = tmp.path.join("logs");
    for d in [&tenant_root, &sibling_root, &logs] {
        fs::create_dir_all(d)?;
    }
    fs::write(tenant_root.join("index.html"), b"TENANT")?;
    fs::write(sibling_root.join("index.html"), b"SIBLING-V1")?;
    let access_log = logs.join("access.log");
    fs::write(&access_log, b"PRIVATE-LOG-LINE\n")?;
    let module = tenant_root.join("edge.wasm");
    std::os::unix::fs::symlink(&access_log, &module)?;

    let (cert, key, cert_pem) = r5_dev_cert(
        &tmp.path.join("tls"),
        &["tenant.example", "sibling.example"],
    )?;
    let (server, _, kdl) = start_server_with_free_port(
        "r5-wasm-rot.kdl",
        |tls_port| {
            format!(
                r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    tls {{
        cert "{cert}"
        key "{key}"
    }}
}}
site "tenant.example" {{
    root "{tenant}"
    route "/edge/*" {{
        wasm-plugin "{module}"
    }}
}}
site "sibling.example" {{
    root "{sibling}"
}}
"#,
                cert = cert.display(),
                key = key.display(),
                tenant = tenant_root.display(),
                module = module.display(),
                sibling = sibling_root.display(),
            )
        },
        ServerOptions {
            apply_sandbox: false,
            log_file_paths: vec![access_log.clone()],
            log_rotation_paths: vec![access_log],
            ..ServerOptions::default()
        },
    )
    .await?;
    let addr = r5_https_addr(&server)?;
    let connector = build_h1_tls_connector(&cert_pem)?;

    let (s_edge, b_edge) = https_get(addr, &connector, "tenant.example", "/edge/x").await?;
    assert_eq!(s_edge, StatusCode::SERVICE_UNAVAILABLE);
    assert!(!b_edge.contains("PRIVATE-LOG-LINE"));
    let (s_sib, b_sib) = https_get(addr, &connector, "sibling.example", "/").await?;
    assert_eq!(s_sib, StatusCode::OK);
    assert_eq!(b_sib, "SIBLING-V1");

    fs::write(sibling_root.join("index.html"), b"SIBLING-V2")?;
    let generation = server.reload_from_str("r5-wasm-rot-reload.kdl", &kdl)?;
    assert!(generation >= 1);
    let (s_sib2, b_sib2) = https_get(addr, &connector, "sibling.example", "/").await?;
    assert_eq!(s_sib2, StatusCode::OK);
    assert_eq!(b_sib2, "SIBLING-V2");

    server.shutdown().await;
    Ok(())
}

/// Codex Round-5 P1 #2 (G7), enforced where the kernel supports Landlock: an absolute error page
/// reached through a tenant-controlled INTERMEDIATE symlink yields the built-in page, a sibling
/// site stays healthy and accepts a reload, and (on Linux) the worker gains no read access to the
/// unrelated directory the symlink pointed at.
///
/// On Linux this needs an enforcing Landlock kernel, so it is ignored by default there and FAILS
/// when Landlock is unavailable; run it on a Landlock-capable Linux host with
/// `--ignored`. On macOS the sandbox reports an unsupported platform and the functional checks run.
#[cfg(unix)]
#[tokio::test]
#[cfg_attr(
    target_os = "linux",
    ignore = "requires an enforcing Landlock kernel; run with --ignored on the staging VM"
)]
#[allow(clippy::too_many_lines)]
async fn g7_r5_p1_intermediate_symlink_error_page_sandboxed_builtin_page_and_no_widening()
-> TestResult {
    let tmp = TempDir::new("r5-errpage-ll")?;
    let tenant_root = tmp.path.join("tenant");
    let sibling_root = tmp.path.join("sibling");
    let unrelated = tmp.path.join("unrelated");
    for d in [&tenant_root, &sibling_root, &unrelated] {
        fs::create_dir_all(d)?;
    }
    fs::write(tenant_root.join("index.html"), b"TENANT")?;
    fs::write(sibling_root.join("index.html"), b"SIBLING-V1")?;
    fs::write(unrelated.join("404.html"), b"UNRELATED-SECRET-PAGE")?;
    fs::write(unrelated.join("secret.txt"), b"UNRELATED-SECRET")?;
    let errors_link = tenant_root.join("errors");
    std::os::unix::fs::symlink(&unrelated, &errors_link)?;

    let (cert, key, cert_pem) = r5_dev_cert(
        &tmp.path.join("tls"),
        &["tenant.example", "sibling.example"],
    )?;
    let (server, _, kdl) = start_server_with_free_port(
        "r5-errpage-ll.kdl",
        |tls_port| {
            format!(
                r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    tls {{
        cert "{cert}"
        key "{key}"
    }}
    sandbox {{
        landlock true
        seccomp "off"
    }}
}}
site "tenant.example" {{
    root "{tenant}"
    error-pages {{
        page 404 "{page}"
    }}
}}
site "sibling.example" {{
    root "{sibling}"
}}
"#,
                cert = cert.display(),
                key = key.display(),
                tenant = tenant_root.display(),
                page = errors_link.join("404.html").display(),
                sibling = sibling_root.display(),
            )
        },
        ServerOptions {
            apply_sandbox: true,
            ..ServerOptions::default()
        },
    )
    .await?;
    let addr = r5_https_addr(&server)?;
    let connector = build_h1_tls_connector(&cert_pem)?;

    let (s404, b404) = https_get(addr, &connector, "tenant.example", "/missing").await?;
    assert_eq!(s404, StatusCode::NOT_FOUND);
    assert!(
        !b404.contains("UNRELATED-SECRET-PAGE"),
        "intermediate-symlink error page must fall back to the built-in page: {b404}"
    );
    let (s_sib, b_sib) = https_get(addr, &connector, "sibling.example", "/").await?;
    assert_eq!(s_sib, StatusCode::OK);
    assert_eq!(b_sib, "SIBLING-V1");

    // On Linux the server confined this (main) thread with Landlock: the unrelated directory
    // behind the tenant symlink must not have been granted.
    #[cfg(target_os = "linux")]
    assert!(
        fs::read(unrelated.join("secret.txt")).is_err(),
        "Landlock policy must not grant read access to the unrelated directory"
    );

    let generation = server.reload_from_str("r5-errpage-ll-reload.kdl", &kdl)?;
    assert!(generation >= 1);
    let (s_sib2, _) = https_get(addr, &connector, "sibling.example", "/").await?;
    assert_eq!(s_sib2, StatusCode::OK);

    server.shutdown().await;
    Ok(())
}

/// Codex Round-5 P2 (G7): a NON-rotating log placed beside (not inside) a site root starts and
/// reloads unchanged; the same placement with rotation (directory-wide write grant) is refused.
#[tokio::test]
async fn g7_r5_p2_non_rotating_log_beside_docroot_starts_and_reloads() -> TestResult {
    let tmp = TempDir::new("r5-plain-log")?;
    let www = tmp.path.join("www");
    fs::create_dir_all(&www)?;
    fs::write(www.join("index.html"), b"BESIDE-OK")?;
    let access_log = tmp.path.join("access.log");

    let (cert, key, cert_pem) = r5_dev_cert(&tmp.path.join("tls"), &["beside.example"])?;
    let make_kdl = |tls_port: u16| {
        format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    tls {{
        cert "{cert}"
        key "{key}"
    }}
}}
site "beside.example" {{
    root "{www}"
}}
"#,
            cert = cert.to_string_lossy().replace('\\', "/"),
            key = key.to_string_lossy().replace('\\', "/"),
            www = www.to_string_lossy().replace('\\', "/"),
        )
    };

    let (server, kdl) = {
        let mut last_err: Option<CoreError> = None;
        let mut started = None;
        for _ in 0..16 {
            let tls_port = reserve_free_port()?;
            let kdl = make_kdl(tls_port);

            let (cfg_rot, _) = parse_kdl("r5-plain-rot.kdl", &kdl)?;
            let refused = MiraServeServer::start(
                Arc::new(ConfigStore::new(cfg_rot)),
                ServerOptions {
                    apply_sandbox: false,
                    log_file_paths: vec![access_log.clone()],
                    log_rotation_paths: vec![access_log.clone()],
                    ..ServerOptions::default()
                },
            )
            .await;
            assert!(
                matches!(refused, Err(CoreError::UnsafeDocroot(_))),
                "a rotating log whose directory contains the site root must be refused"
            );

            let (cfg, _) = parse_kdl("r5-plain.kdl", &kdl)?;
            match MiraServeServer::start(
                Arc::new(ConfigStore::new(cfg)),
                ServerOptions {
                    apply_sandbox: false,
                    log_file_paths: vec![access_log.clone()],
                    ..ServerOptions::default()
                },
            )
            .await
            {
                Ok(server) => {
                    started = Some((server, kdl));
                    break;
                }
                Err(CoreError::Bind { source, addr })
                    if source.kind() == std::io::ErrorKind::AddrInUse =>
                {
                    last_err = Some(CoreError::Bind { addr, source });
                }
                Err(err) => return Err(err.into()),
            }
        }
        let Some(pair) = started else {
            return Err(last_err.map_or_else(|| "exhausted bind retries".into(), Into::into));
        };
        pair
    };
    let addr = r5_https_addr(&server)?;
    let connector = build_h1_tls_connector(&cert_pem)?;
    let (status, body) = https_get(addr, &connector, "beside.example", "/").await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "BESIDE-OK");
    let generation = server.reload_from_str("r5-plain-reload.kdl", &kdl)?;
    assert!(generation >= 1);

    server.shutdown().await;
    Ok(())
}

/// Spawns a protocol-capable HTTPS mock ACME v2 CA on its own unconfined background OS thread so
/// a Landlock-confined worker thread can exercise real TLS + directory + nonce + new-account +
/// credential-reuse flows concurrently without blocking the CA's runtime (Codex Round-8).
#[cfg(target_os = "linux")]
#[allow(clippy::type_complexity, clippy::too_many_lines)]
fn spawn_unconfined_mock_acme_ca(
    provider: &Arc<miraserve_tls::CryptoProvider>,
) -> Result<
    (
        String,
        String,
        Arc<std::sync::atomic::AtomicUsize>,
        Arc<std::sync::atomic::AtomicUsize>,
        tokio::sync::oneshot::Sender<()>,
        std::thread::JoinHandle<()>,
    ),
    Box<dyn std::error::Error>,
> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let (ck, pem) = miraserve_tls::generate_dev_certificate(
        &["127.0.0.1".to_owned(), "localhost".to_owned()],
        provider,
    )?;
    let resolver = Arc::new(miraserve_tls::DynamicCertResolver::new(Arc::new(
        miraserve_tls::AcmeChallengeStore::new(),
    )));
    resolver.set_default(ck);
    let mut server_cfg = rustls::ServerConfig::builder_with_provider(Arc::clone(provider))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    server_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

    let std_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    std_listener.set_nonblocking(true)?;
    let addr = std_listener.local_addr()?;
    let base_url = format!("https://{addr}");
    let directory_url = format!("{base_url}/directory");
    let directory_hits = Arc::new(AtomicUsize::new(0));
    let new_account_hits = Arc::new(AtomicUsize::new(0));
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();

    let dir_bg = Arc::clone(&directory_hits);
    let acct_bg = Arc::clone(&new_account_hits);
    let base_bg = base_url.clone();
    let handle = std::thread::spawn(move || {
        let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            return;
        };
        rt.block_on(async move {
            let Ok(listener) = tokio::net::TcpListener::from_std(std_listener) else {
                return;
            };
            let nonce_seq = Arc::new(AtomicUsize::new(1));
            loop {
                tokio::select! {
                    _ = &mut stop_rx => break,
                    accepted = listener.accept() => {
                        let Ok((tcp, _)) = accepted else { break; };
                        let acc = acceptor.clone();
                        let dh = Arc::clone(&dir_bg);
                        let ah = Arc::clone(&acct_bg);
                        let ns = Arc::clone(&nonce_seq);
                        let base_inner = base_bg.clone();
                        tokio::spawn(async move {
                            let Ok(mut tls) = acc.accept(tcp).await else { return; };
                            let mut req_buf = Vec::with_capacity(2048);
                            let mut chunk = [0_u8; 1024];
                            let header_end = loop {
                                let Ok(n) = tls.read(&mut chunk).await else { return; };
                                if n == 0 { return; }
                                if let Some(s) = chunk.get(..n) {
                                    req_buf.extend_from_slice(s);
                                }
                                if let Some(pos) = req_buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                    break pos + 4;
                                }
                                if req_buf.len() > 64 * 1024 { return; }
                            };
                            let header_text = String::from_utf8_lossy(
                                req_buf.get(..header_end).unwrap_or_default(),
                            )
                            .into_owned();
                            let content_len: usize = header_text
                                .lines()
                                .find_map(|line| {
                                    let (k, v) = line.split_once(':')?;
                                    k.eq_ignore_ascii_case("content-length")
                                        .then(|| v.trim().parse::<usize>().ok())
                                        .flatten()
                                })
                                .unwrap_or(0);
                            let mut have_body = req_buf.len().saturating_sub(header_end);
                            while have_body < content_len {
                                let Ok(n) = tls.read(&mut chunk).await else { return; };
                                if n == 0 { break; }
                                have_body = have_body.saturating_add(n);
                            }
                            let first_line = header_text.lines().next().unwrap_or_default();
                            let mut parts = first_line.split_whitespace();
                            let method = parts.next().unwrap_or_default();
                            let path = parts.next().unwrap_or_default();
                            let nonce = ns.fetch_add(1, Ordering::SeqCst);
                            let resp = match (method, path) {
                                ("GET", "/directory") => {
                                    dh.fetch_add(1, Ordering::SeqCst);
                                    let body = format!(
                                        r#"{{"newNonce":"{base_inner}/new-nonce","newAccount":"{base_inner}/new-account","newOrder":"{base_inner}/new-order"}}"#
                                    );
                                    format!(
                                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                        body.len()
                                    )
                                }
                                ("HEAD" | "GET", "/new-nonce") => format!(
                                    "HTTP/1.1 200 OK\r\nReplay-Nonce: test-nonce-{nonce}\r\nCache-Control: no-store\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                                ),
                                ("POST", "/new-account") => {
                                    let acct_num = ah.fetch_add(1, Ordering::SeqCst) + 1;
                                    let body = r#"{"status":"valid"}"#;
                                    format!(
                                        "HTTP/1.1 201 Created\r\nReplay-Nonce: test-nonce-{nonce}\r\nLocation: {base_inner}/acct/{acct_num}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                        body.len()
                                    )
                                }
                                _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
                            };
                            let _ = tls.write_all(resp.as_bytes()).await;
                            let _ = tls.shutdown().await;
                        });
                    }
                }
            }
        });
    });

    Ok((
        directory_url,
        pem.cert_pem,
        directory_hits,
        new_account_hits,
        stop_tx,
        handle,
    ))
}

/// Codex Round-7 P1 & Round-8 P1, enforced Linux only: under the normal worker Landlock policy
/// (which grants RW to the ACME state directory and grants NO directory-read access to `/` or
/// ungranted ancestors), `create_private_dir_all`, cached-certificate loading, initial ACME
/// account registration, AND fresh-manager account reuse MUST all succeed against a concurrent
/// protocol-capable local HTTPS mock CA without a second registration.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires an enforcing Landlock kernel; run with --ignored on the staging VM"]
#[allow(clippy::too_many_lines)]
async fn r7_p1_enforced_landlock_acme_loads_cached_cert_and_reaches_local_ca() -> TestResult {
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::Ordering;

    let tmp = TempDir::new("r7-acme-landlock")?;
    let www = tmp.path.join("www");
    let acme_state = tmp.path.join("nested-ungranted").join("acme-state");
    let cfg_dir = tmp.path.join("cfg");
    fs::create_dir_all(&www)?;
    fs::create_dir_all(&acme_state)?;
    fs::create_dir_all(&cfg_dir)?;
    fs::set_permissions(&acme_state, fs::Permissions::from_mode(0o755))?;
    // Every ancestor created here must be safe whatever the caller's umask is: with Ubuntu's
    // default `0002` they would be `0775`, which the private-state ancestor check refuses.
    fs::set_permissions(&tmp.path, fs::Permissions::from_mode(0o755))?;
    fs::set_permissions(
        tmp.path.join("nested-ungranted"),
        fs::Permissions::from_mode(0o755),
    )?;
    let cfg_path = cfg_dir.join("miraserve.kdl");

    let provider = miraserve_tls::build_crypto_provider(false);
    let (acme_dir_url, ca_cert_pem, dir_hits, acct_hits, ca_stop_tx, ca_thread) =
        spawn_unconfined_mock_acme_ca(&provider)?;
    // Place the local test CA root inside `cfg_dir`, which is already in the worker policy's
    // read-only paths as the config file's parent directory (no extra Landlock grants).
    let ca_cert_path = cfg_dir.join("local-ca.crt");
    fs::write(&ca_cert_path, &ca_cert_pem)?;

    let domain = "cached.example.test";
    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{
        acme {{
            email "ops@example.test"
            directory "{acme_dir_url}"
        }}
    }}
    sandbox {{
        landlock true
        seccomp "off"
    }}
}}
site "{domain}" {{
    root "{www}"
}}
"#,
        www = www.display(),
    );
    fs::write(&cfg_path, &kdl)?;
    let (cfg, _) = parse_kdl("r7-acme-ll.kdl", &kdl)?;
    let acme_cfg = cfg
        .server
        .tls
        .acme
        .clone()
        .ok_or("expected acme config in fixture")?;

    // Pre-seed a valid cached certificate before confinement and reset state dir mode to 0755 so
    // the confined worker exercises BOTH ancestor `O_PATH` traversal AND leaf `fchmod` tightening.
    let challenges = Arc::new(miraserve_tls::AcmeChallengeStore::new());
    let seed_resolver = Arc::new(miraserve_tls::DynamicCertResolver::new(Arc::clone(
        &challenges,
    )));
    let seed_mgr = miraserve_tls::AcmeManager::new(
        acme_cfg.clone(),
        acme_state.clone(),
        Arc::clone(&challenges),
        seed_resolver,
        Arc::clone(&provider),
    );
    let (_, cert_pem) = miraserve_tls::generate_dev_certificate(&[domain.to_owned()], &provider)?;
    seed_mgr.install_and_persist_certificate_pem(domain, &cert_pem.cert_pem, &cert_pem.key_pem)?;
    fs::set_permissions(&acme_state, fs::Permissions::from_mode(0o755))?;

    let policy = miraserve_sandbox::SandboxPolicy::from_config_with_file(
        &cfg,
        Some(&cfg_path),
        Some(&acme_state),
    );
    let tmp_cleanup = tmp.path.clone();
    let acct_hits_worker = Arc::clone(&acct_hits);
    // Run the confined ACME assertions on a dedicated thread so Landlock does not block test
    // cleanup on the main thread, while the mock CA runs independently on `ca_thread`.
    let worker_res = std::thread::spawn(move || -> Result<(), String> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| format!("rt build: {err}"))?;
        let status = miraserve_sandbox::apply_landlock_current_thread(&policy)
            .map_err(|err| format!("apply_landlock_current_thread: {err}"))?;
        if !matches!(
            status,
            miraserve_sandbox::EnforcementStatus::Enforced
                | miraserve_sandbox::EnforcementStatus::PartiallyEnforced
        ) {
            return Err(format!(
                "expected Landlock Enforced or PartiallyEnforced, got {status:?}"
            ));
        }
        // Confirm `/` is genuinely not readable under the worker policy.
        if fs::read_dir("/").is_ok() {
            return Err("expected read_dir(\"/\") to be denied under Landlock".to_owned());
        }
        // Production state helper must still succeed via O_PATH ancestors and tighten to 0700.
        miraserve_tls::create_private_dir_all(&acme_state)
            .map_err(|err| format!("create_private_dir_all under Landlock failed: {err}"))?;
        let mode = fs::symlink_metadata(&acme_state)
            .map_err(|err| format!("stat acme_state: {err}"))?
            .permissions()
            .mode()
            & 0o7777;
        if mode != 0o700 {
            return Err(format!("expected tightened mode 0700, got {mode:04o}"));
        }
        // Cached certificate must load cleanly under Landlock.
        let resolver1 = Arc::new(miraserve_tls::DynamicCertResolver::new(Arc::clone(
            &challenges,
        )));
        let mgr1 = miraserve_tls::AcmeManager::new(
            acme_cfg.clone(),
            acme_state.clone(),
            Arc::clone(&challenges),
            Arc::clone(&resolver1),
            Arc::clone(&provider),
        )
        .with_ca_root_pem(&ca_cert_path);
        mgr1.load_cached_certificates(&[domain.to_owned()]);
        if resolver1.lookup_host(domain).is_none() {
            return Err("cached ACME certificate failed to load under Landlock".to_owned());
        }
        // 1. First account registration succeeds against the local protocol-capable CA.
        let acc1 = rt.block_on(mgr1.load_or_create_account()).map_err(|err| {
            format!("initial load_or_create_account failed under Landlock: {err}")
        })?;
        if !acc1.id().ends_with("/acct/1") {
            return Err(format!("unexpected initial account id: {}", acc1.id()));
        }
        if acct_hits_worker.load(Ordering::SeqCst) != 1 {
            return Err(format!(
                "expected exactly 1 new-account registration, got {}",
                acct_hits_worker.load(Ordering::SeqCst)
            ));
        }
        let saved_bytes = fs::read(mgr1.account_path())
            .map_err(|err| format!("read saved account creds under Landlock: {err}"))?;

        // 2. Fresh manager under the same confined worker reuses the saved account without a
        //    second POST /new-account registration and leaves credentials unchanged.
        let resolver2 = Arc::new(miraserve_tls::DynamicCertResolver::new(Arc::clone(
            &challenges,
        )));
        let mgr2 =
            miraserve_tls::AcmeManager::new(acme_cfg, acme_state, challenges, resolver2, provider)
                .with_ca_root_pem(&ca_cert_path);
        let acc2 = rt.block_on(mgr2.load_or_create_account()).map_err(|err| {
            format!("reopened load_or_create_account failed under Landlock: {err}")
        })?;
        if acc2.id() != acc1.id() {
            return Err(format!(
                "reopened manager registered different account: {} vs {}",
                acc2.id(),
                acc1.id()
            ));
        }
        if acct_hits_worker.load(Ordering::SeqCst) != 1 {
            return Err(format!(
                "reopened manager sent unexpected extra registration: {}",
                acct_hits_worker.load(Ordering::SeqCst)
            ));
        }
        let after_bytes = fs::read(mgr2.account_path())
            .map_err(|err| format!("re-read saved account creds: {err}"))?;
        if after_bytes != saved_bytes {
            return Err("stored ACME credentials were overwritten on reuse".to_owned());
        }
        Ok(())
    })
    .join()
    .map_err(|_| "confined ACME worker thread panicked")?;

    let _ = ca_stop_tx.send(());
    let _ = ca_thread.join();
    worker_res.map_err(|msg| -> Box<dyn std::error::Error> { msg.into() })?;

    assert_eq!(acct_hits.load(Ordering::SeqCst), 1);
    assert!(
        dir_hits.load(Ordering::SeqCst) >= 2,
        "both initial registration and reopened manager must have contacted the CA directory"
    );
    let _ = fs::remove_dir_all(&tmp_cleanup);
    Ok(())
}

/// Enforced Linux regression test: after the external error-page
/// DIRECTORY is replaced at the same name, a reload must be refused with `RestartRequired` (the
/// installed Landlock rule refers to the old directory) and the old generation keeps serving its
/// page. Filesystem edits are performed by a separate unconfined fixture-owner thread spawned
/// BEFORE confinement so the server remains confined throughout.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires an enforcing Landlock kernel; run with --ignored on the staging VM"]
#[allow(clippy::too_many_lines)]
async fn g7_r6_enforced_replaced_error_page_dir_requires_restart_and_keeps_old_generation()
-> TestResult {
    enum FixtureOp {
        ReplaceChild,
        ReplaceDir,
        Cleanup,
    }

    let tmp = TempDir::new("r6-errdir-replaced")?;
    let www = tmp.path.join("www");
    let errors = tmp.path.join("errors");
    fs::create_dir_all(&www)?;
    fs::create_dir_all(&errors)?;
    fs::write(www.join("index.html"), b"SITE")?;
    fs::write(errors.join("404.html"), b"<h1>ORIGINAL-404</h1>")?;

    let (cert, key, cert_pem) = r5_dev_cert(&tmp.path.join("tls"), &["errdir.example"])?;
    let make_kdl = |tls_port: u16| {
        format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    tls {{
        cert "{cert}"
        key "{key}"
    }}
    sandbox {{
        landlock true
        seccomp "off"
    }}
}}
site "errdir.example" {{
    root "{www}"
    error-pages {{
        page 404 "{page}"
    }}
}}
"#,
            cert = cert.display(),
            key = key.display(),
            www = www.display(),
            page = errors.join("404.html").display(),
        )
    };

    // Spawn the unconfined fixture-owner thread BEFORE `MiraServeServer::start` confines this
    // thread and Tokio's worker threads under Landlock.
    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel::<FixtureOp>();
    let (ack_tx, ack_rx) = std::sync::mpsc::channel::<Result<(), String>>();
    let errors_owner = errors.clone();
    let root_owner = tmp.path.clone();
    let owner_thread = std::thread::spawn(move || {
        while let Ok(op) = cmd_rx.recv() {
            let res: Result<(), String> = match op {
                FixtureOp::ReplaceChild => {
                    fs::write(errors_owner.join("404.html.tmp"), b"<h1>UPDATED-404</h1>")
                        .and_then(|()| {
                            fs::rename(
                                errors_owner.join("404.html.tmp"),
                                errors_owner.join("404.html"),
                            )
                        })
                        .map_err(|err| err.to_string())
                }
                FixtureOp::ReplaceDir => fs::rename(&errors_owner, root_owner.join("errors-old"))
                    .and_then(|()| fs::create_dir_all(&errors_owner))
                    .and_then(|()| {
                        fs::write(errors_owner.join("404.html"), b"<h1>REPLACED-DIR-404</h1>")
                    })
                    .map_err(|err| err.to_string()),
                FixtureOp::Cleanup => {
                    let _ = fs::remove_dir_all(&root_owner);
                    let _ = ack_tx.send(Ok(()));
                    break;
                }
            };
            let _ = ack_tx.send(res);
        }
    });

    let (server, _, kdl) = start_server_with_free_port(
        "r6-errdir.kdl",
        make_kdl,
        ServerOptions {
            apply_sandbox: true,
            ..ServerOptions::default()
        },
    )
    .await?;
    let addr = r5_https_addr(&server)?;
    let connector = build_h1_tls_connector(&cert_pem)?;
    let (s1, b1) = https_get(addr, &connector, "errdir.example", "/missing").await?;
    assert_eq!(s1, StatusCode::NOT_FOUND);
    assert!(
        b1.contains("ORIGINAL-404"),
        "startup page expected, got: {b1}"
    );

    // 1. Atomic child replacement under the unchanged directory grant still reloads.
    cmd_tx.send(FixtureOp::ReplaceChild)?;
    ack_rx
        .recv()?
        .map_err(|msg| -> Box<dyn std::error::Error> { msg.into() })?;
    let generation = server.reload_from_str("r6-errdir-child.kdl", &kdl)?;
    assert!(generation >= 1);
    let (_, b2) = https_get(addr, &connector, "errdir.example", "/missing").await?;
    assert!(
        b2.contains("UPDATED-404"),
        "updated page expected, got: {b2}"
    );

    // 2. Replace the directory itself at the same name: restart required, old generation serves.
    cmd_tx.send(FixtureOp::ReplaceDir)?;
    ack_rx
        .recv()?
        .map_err(|msg| -> Box<dyn std::error::Error> { msg.into() })?;
    let refused = server.reload_from_str("r6-errdir-replaced.kdl", &kdl);
    assert!(
        matches!(refused, Err(CoreError::RestartRequired(_))),
        "a replaced error-page directory must require a restart, got: {refused:?}"
    );
    let (s3, b3) = https_get(addr, &connector, "errdir.example", "/missing").await?;
    assert_eq!(s3, StatusCode::NOT_FOUND);
    assert!(
        b3.contains("UPDATED-404"),
        "the previous generation must keep serving after the refused reload, got: {b3}"
    );

    server.shutdown().await;
    let _ = cmd_tx.send(FixtureOp::Cleanup);
    let _ = ack_rx.recv();
    let _ = owner_thread.join();
    Ok(())
}

/// Codex Round-11 P2: reload must refuse a candidate grant that startup would refuse. An optional
/// read-tree that is missing at startup is valid; if it later appears as a regular file, reload
/// is refused (the old generation keeps serving) even though nothing else changed, and once it is
/// a real directory the same reload succeeds.
#[tokio::test]
async fn g7_r11_p2_reload_refuses_candidate_grant_failure_but_accepts_missing_tree() -> TestResult {
    let tmp = TempDir::new("r11-reload-grant")?;
    let www = tmp.path.join("www");
    fs::create_dir_all(&www)?;
    fs::write(www.join("index.html"), b"GRANT-OK")?;
    let optional_tree = tmp.path.join("optional-tree");

    let (cert, key, cert_pem) = r5_dev_cert(&tmp.path.join("tls"), &["grant.example"])?;
    let (server, _, kdl) = start_server_with_free_port(
        "r11-grant.kdl",
        |tls_port| {
            format!(
                r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    tls {{
        cert "{cert}"
        key "{key}"
    }}
    sandbox {{
        read-tree "{tree}"
    }}
}}
site "grant.example" {{
    root "{www}"
}}
"#,
                cert = cert.to_string_lossy().replace('\\', "/"),
                key = key.to_string_lossy().replace('\\', "/"),
                tree = optional_tree.to_string_lossy().replace('\\', "/"),
                www = www.to_string_lossy().replace('\\', "/"),
            )
        },
        ServerOptions {
            apply_sandbox: false,
            ..ServerOptions::default()
        },
    )
    .await?;
    let addr = r5_https_addr(&server)?;
    let connector = build_h1_tls_connector(&cert_pem)?;

    // Missing optional tree: unchanged reload is fine.
    let g1 = server.reload_from_str("r11-grant-missing.kdl", &kdl)?;

    // Regular file at the tree path: refused, old generation still serves.
    fs::write(&optional_tree, b"not a directory")?;
    let refused = server.reload_from_str("r11-grant-file.kdl", &kdl);
    match &refused {
        Err(CoreError::Sandbox(err)) => assert!(
            err.to_string().contains("not a directory"),
            "unexpected refusal reason: {err}"
        ),
        other => return Err(format!("expected a sandbox grant refusal, got {other:?}").into()),
    }
    let (status, body) = https_get(addr, &connector, "grant.example", "/").await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "GRANT-OK");

    // Real directory: the same reload succeeds.
    fs::remove_file(&optional_tree)?;
    fs::create_dir_all(&optional_tree)?;
    let g2 = server.reload_from_str("r11-grant-dir.kdl", &kdl)?;
    assert!(g2 > g1, "a valid reload must publish a new generation");

    server.shutdown().await;
    Ok(())
}

/// A tenant site (owner-dir) whose root becomes unsafe (here: linked to the server's log
/// directory) is quarantined on reload: the reload applies for every other site, that site
/// answers 503 and the log directory is never served. A site without owner-dir keeps the old
/// behaviour (the g7 test above: the whole reload is refused).
#[tokio::test]
async fn tenant_site_with_an_unsafe_root_is_quarantined_and_the_reload_applies() -> TestResult {
    let tmp = TempDir::new("tenant-quarantine")?;
    let www = tmp.path.join("www");
    let home = tmp.path.join("home/evil");
    let logs = tmp.path.join("logs");
    fs::create_dir_all(&www)?;
    fs::create_dir_all(&home)?;
    fs::create_dir_all(&logs)?;
    fs::write(www.join("index.html"), b"good-v1")?;
    fs::write(logs.join("access.log"), b"PRIVATE-ACCESS-LOG-ENTRY\n")?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(&logs, home.join("public_html"))?;

    let cert_path = tmp.path.join("server.pem");
    let key_path = tmp.path.join("server.key");
    let (_, dev_pem) = miraserve_tls::generate_dev_certificate(
        &["good.example".to_owned(), "evil.example".to_owned()],
        &build_crypto_provider(false),
    )?;
    fs::write(&cert_path, &dev_pem.cert_pem)?;
    fs::write(&key_path, &dev_pem.key_pem)?;
    let make_header = |tls_port: u16| {
        format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    tls {{
        cert "{cert}"
        key "{key}"
    }}
}}
"#,
            cert = cert_path.to_string_lossy().replace('\\', "/"),
            key = key_path.to_string_lossy().replace('\\', "/"),
        )
    };
    let good = |body: &str| {
        format!(
            "site \"good.example\" {{\n    root \"{}\"\n}}\n{body}",
            www.to_string_lossy().replace('\\', "/")
        )
    };
    let log_file = logs.join("access.log");
    let (server, tls_port, _) = start_server_with_free_port(
        "tq-v1.kdl",
        |tls_port| format!("{}{}", make_header(tls_port), good("")),
        ServerOptions {
            apply_sandbox: false,
            log_file_paths: vec![log_file.clone()],
            log_rotation_paths: vec![log_file],
            ..ServerOptions::default()
        },
    )
    .await?;
    let header = make_header(tls_port);
    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|l| l.kind == ListenerKind::HttpsTcp)
        .map(|l| l.local_addr)
        .ok_or("expected HTTPS listener")?;
    let connector = build_h1_tls_connector(&dev_pem.cert_pem)?;

    fs::write(www.join("index.html"), b"good-v2")?;
    let evil = format!(
        "site \"evil.example\" {{\n    owner-dir \"{h}\"\n    root \"{h}/public_html\"\n}}\n",
        h = home.to_string_lossy().replace('\\', "/")
    );
    server
        .reload_from_str("tq-v2.kdl", &format!("{header}{}", good(&evil)))
        .map_err(|err| format!("reload with one unsafe tenant root should apply: {err:?}"))?;

    let (s_good, b_good) = https_get(https_addr, &connector, "good.example", "/").await?;
    assert_eq!(s_good, StatusCode::OK);
    assert_eq!(b_good, "good-v2", "the other site's change applied");
    let (s_evil, b_evil) = https_get(https_addr, &connector, "evil.example", "/access.log").await?;
    assert_eq!(s_evil, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        !b_evil.contains("PRIVATE"),
        "the log directory is never served"
    );

    server.shutdown().await;
    Ok(())
}

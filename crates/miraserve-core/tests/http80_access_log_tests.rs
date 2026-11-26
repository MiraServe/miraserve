//! Access-log scheme and rejection accounting verification over real plain-HTTP TCP and real
//! TLS HTTPS connections (`MiraServeServer::start`).

#![allow(unknown_lints, clippy::assert_is_empty)]

use std::collections::BTreeMap;
use std::net::TcpListener as StdTcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use miraserve_config::{Config, ConfigStore, parse_kdl};
use miraserve_core::{CoreError, ListenerKind, MiraServeServer, RunningServer, ServerOptions};
use miraserve_tls::build_crypto_provider;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::field::{Field, Visit};
use tracing::{Event, Metadata, Subscriber, span};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Default)]
struct FieldRecorder {
    fields: BTreeMap<String, String>,
}

impl Visit for FieldRecorder {
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields
            .insert(field.name().to_owned(), value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields
            .insert(field.name().to_owned(), value.to_string());
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.fields
            .insert(field.name().to_owned(), value.to_owned());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.fields
            .insert(field.name().to_owned(), format!("{value:?}"));
    }
}

#[derive(Clone, Default)]
struct AccessCapture {
    events: Arc<Mutex<Vec<BTreeMap<String, String>>>>,
}

impl AccessCapture {
    fn snapshot(&self) -> Vec<BTreeMap<String, String>> {
        self.events
            .lock()
            .map_or_else(|_| Vec::new(), |g| g.clone())
    }
}

impl Subscriber for AccessCapture {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }

    fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}

    fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        if event.metadata().target() != "miraserve::access" {
            return;
        }
        let mut rec = FieldRecorder::default();
        event.record(&mut rec);
        if let Ok(mut guard) = self.events.lock() {
            guard.push(rec.fields);
        }
    }

    fn enter(&self, _span: &span::Id) {}

    fn exit(&self, _span: &span::Id) {}
}

fn reserve_two_free_ports() -> Result<(u16, u16), std::io::Error> {
    let sock1 = StdTcpListener::bind("127.0.0.1:0")?;
    let sock2 = StdTcpListener::bind("127.0.0.1:0")?;
    Ok((sock1.local_addr()?.port(), sock2.local_addr()?.port()))
}

async fn start_dual_port_server_retrying<F>(
    build_cfg: F,
) -> Result<RunningServer, Box<dyn std::error::Error>>
where
    F: Fn(u16, u16) -> Result<Config, Box<dyn std::error::Error>>,
{
    let mut last_err: Option<Box<dyn std::error::Error>> = None;
    for _ in 0..8 {
        let (tls_port, http_port) = reserve_two_free_ports()?;
        let cfg = match build_cfg(tls_port, http_port) {
            Ok(cfg) => cfg,
            Err(err) => {
                if err
                    .downcast_ref::<miraserve_config::ConfigError>()
                    .is_some_and(|ce| ce.validation_errors().iter().any(|e| e.code == "E102"))
                {
                    last_err = Some(err);
                    continue;
                }
                return Err(err);
            }
        };
        match MiraServeServer::start(
            Arc::new(ConfigStore::new(cfg)),
            ServerOptions {
                dev_tls: true,
                ..ServerOptions::default()
            },
        )
        .await
        {
            Ok(server) => return Ok(server),
            Err(CoreError::Bind { source, .. })
                if source.kind() == std::io::ErrorKind::AddrInUse =>
            {
                last_err = Some(Box::new(source));
            }
            Err(err) => return Err(Box::new(err)),
        }
    }
    Err(last_err.unwrap_or_else(|| "exhausted dual-port bind retries".into()))
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

async fn send_plain_raw(
    addr: std::net::SocketAddr,
    raw_request: &[u8],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut client = TcpStream::connect(addr).await?;
    client.write_all(raw_request).await?;
    let mut resp = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut resp)).await??;
    Ok(String::from_utf8(resp)?)
}

async fn send_tls_raw(
    addr: std::net::SocketAddr,
    sni: &str,
    connector: &TlsConnector,
    raw_request: &[u8],
) -> Result<String, Box<dyn std::error::Error>> {
    let tcp = TcpStream::connect(addr).await?;
    let mut tls = connector
        .connect(ServerName::try_from(sni.to_owned())?, tcp)
        .await?;
    tls.write_all(raw_request).await?;
    let mut resp = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut resp)).await??;
    Ok(String::from_utf8(resp)?)
}

fn metric_value(server: &RunningServer, prefix: &str) -> u64 {
    let prom = server.telemetry().render_prometheus();
    prom.lines()
        .find_map(|line| {
            line.strip_prefix(prefix)
                .and_then(|rest| rest.trim().parse::<u64>().ok())
        })
        .unwrap_or(0)
}

async fn wait_for_events(
    capture: &AccessCapture,
    expected: usize,
) -> Vec<BTreeMap<String, String>> {
    for _ in 0..50 {
        let snap = capture.snapshot();
        if snap.len() >= expected {
            return snap;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    capture.snapshot()
}

#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "current_thread")]
async fn plain_http_access_log_records_scheme_http_while_redirect_and_real_tls_https_stay_unchanged()
-> TestResult {
    let capture = AccessCapture::default();
    let _guard = tracing::subscriber::set_default(capture.clone());

    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "miraserve-http80-access-log-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("index.txt"), b"ok-plain")?;

    let root_str = root.display().to_string().replace('\\', "/");
    let server = start_dual_port_server_retrying(|tls_port, http_port| {
        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    listen "127.0.0.1:{http_port}" redirect-https=#true
}}
site "plain.example.test" {{
    http "serve"
    root "{root_str}"
}}
site "redir.example.test" {{
    http "redirect"
    root "{root_str}"
}}
"#
        );
        let (cfg, _) = parse_kdl("http80-access.kdl", &kdl)?;
        Ok(cfg)
    })
    .await?;
    let tls_addr = server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::HttpsTcp)
        .ok_or("missing HttpsTcp listener")?
        .local_addr;
    let http_addr = server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::HttpRedirect)
        .ok_or("missing HttpRedirect listener")?
        .local_addr;
    let dev_pem = server.dev_cert_pem().ok_or("missing dev cert PEM")?;
    let tls_connector = build_h1_tls_connector(dev_pem)?;

    // 1. `http "redirect"` on plain-HTTP listener: 308 and NO access log event (v0.1.2 parity).
    let redir_wire = send_plain_raw(
        http_addr,
        b"GET /index.txt HTTP/1.1\r\nHost: redir.example.test\r\nConnection: close\r\n\r\n",
    )
    .await?;
    assert!(
        redir_wire.starts_with("HTTP/1.1 308 Permanent Redirect\r\n"),
        "wire: {redir_wire}"
    );
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        capture.snapshot().is_empty(),
        "http \"redirect\" must not emit a miraserve::access event, got: {:?}",
        capture.snapshot()
    );
    assert_eq!(server.telemetry().total_http_requests(), 0);

    // 2. `http "serve"` on plain-HTTP listener: 200 and access log carries `scheme="http"`.
    let plain_wire = send_plain_raw(
        http_addr,
        b"GET /index.txt HTTP/1.1\r\nHost: plain.example.test\r\nConnection: close\r\n\r\n",
    )
    .await?;
    assert!(
        plain_wire.starts_with("HTTP/1.1 200 OK\r\n"),
        "wire: {plain_wire}"
    );
    let events = wait_for_events(&capture, 1).await;
    assert_eq!(events.len(), 1, "expected 1 access log event: {events:?}");
    let plain_ev = events.first().ok_or("missing plain HTTP access event")?;
    assert_eq!(plain_ev.get("scheme").map(String::as_str), Some("http"));
    assert_eq!(plain_ev.get("proto").map(String::as_str), Some("h1"));
    assert_eq!(
        plain_ev.get("host").map(String::as_str),
        Some("plain.example.test")
    );
    assert_eq!(plain_ev.get("status").map(String::as_str), Some("200"));
    assert_eq!(plain_ev.get("completed").map(String::as_str), Some("true"));

    // 3. Real TLS HTTPS listener control: 200 and access log stays byte-compatible with v0.1.2
    //    (no `scheme` field).
    let https_wire = send_tls_raw(
        tls_addr,
        "plain.example.test",
        &tls_connector,
        b"GET /index.txt HTTP/1.1\r\nHost: plain.example.test\r\nConnection: close\r\n\r\n",
    )
    .await?;
    assert!(
        https_wire.starts_with("HTTP/1.1 200 OK\r\n"),
        "wire: {https_wire}"
    );
    let events = wait_for_events(&capture, 2).await;
    assert_eq!(events.len(), 2, "expected 2 access log events: {events:?}");
    let https_ev = events.get(1).ok_or("missing HTTPS access event")?;
    assert!(
        https_ev.get("scheme").is_none(),
        "HTTPS access log must remain v0.1.2-compatible without extra fields: {https_ev:?}"
    );
    assert_eq!(https_ev.get("status").map(String::as_str), Some("200"));
    assert_eq!(https_ev.get("completed").map(String::as_str), Some("true"));
    assert_eq!(
        metric_value(
            &server,
            "miraserve_http_requests_total{protocol=\"h1\",status_class=\"2xx\"} "
        ),
        2
    );

    server.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

/// Pins P1-2: a declared body over `max-body-bytes` (`413`), path traversal (`400`), and
/// oversized headers (`431`) on an `http "serve"` site all go through the normal pipeline so
/// they are recorded in the access log and telemetry over plain HTTP identically to real TLS HTTPS.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "current_thread")]
async fn plain_http_serve_site_413_and_framing_rejections_logged_and_counted_like_https()
-> TestResult {
    let capture = AccessCapture::default();
    let _guard = tracing::subscriber::set_default(capture.clone());

    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "miraserve-http80-413-accounting-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("index.txt"), b"ok")?;

    let root_str = root.display().to_string().replace('\\', "/");
    let server = start_dual_port_server_retrying(|tls_port, http_port| {
        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    listen "127.0.0.1:{http_port}" redirect-https=#true
    limits {{
        max-body-bytes "128B"
        max-header-bytes "1024B"
    }}
}}
site "plain.example.test" {{
    http "serve"
    root "{root_str}"
}}
site "redir.example.test" {{
    http "redirect"
    root "{root_str}"
}}
"#
        );
        let (cfg, _) = parse_kdl("http80-413.kdl", &kdl)?;
        Ok(cfg)
    })
    .await?;
    let tls_addr = server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::HttpsTcp)
        .ok_or("missing HttpsTcp listener")?
        .local_addr;
    let http_addr = server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::HttpRedirect)
        .ok_or("missing HttpRedirect listener")?
        .local_addr;
    let dev_pem = server.dev_cert_pem().ok_or("missing dev cert PEM")?;
    let tls_connector = build_h1_tls_connector(dev_pem)?;

    let body_129 = "x".repeat(129);
    let upload_req = format!(
        "POST /upload HTTP/1.1\r\nHost: plain.example.test\r\nContent-Length: 129\r\nConnection: close\r\n\r\n{body_129}"
    );
    let h1_4xx = "miraserve_http_requests_total{protocol=\"h1\",status_class=\"4xx\"} ";
    let anti_smuggle = "miraserve_security_blocks_total{reason=\"anti_smuggling\"} ";

    // 1. Plain HTTP `413` on `http "serve"` site: appears in access log (`scheme="http"`) and telemetry.
    let plain_413 = send_plain_raw(http_addr, upload_req.as_bytes()).await?;
    assert!(
        plain_413.starts_with("HTTP/1.1 413 Payload Too Large\r\n"),
        "expected 413 over plain HTTP, got: {plain_413}"
    );
    let events = wait_for_events(&capture, 1).await;
    assert_eq!(events.len(), 1, "expected 1 access log event: {events:?}");
    let ev1 = events.first().ok_or("missing plain 413 event")?;
    assert_eq!(ev1.get("status").map(String::as_str), Some("413"));
    assert_eq!(ev1.get("method").map(String::as_str), Some("POST"));
    assert_eq!(ev1.get("target").map(String::as_str), Some("/upload"));
    assert_eq!(
        ev1.get("host").map(String::as_str),
        Some("plain.example.test")
    );
    assert_eq!(ev1.get("scheme").map(String::as_str), Some("http"));
    assert_eq!(metric_value(&server, h1_4xx), 1);
    assert_eq!(metric_value(&server, anti_smuggle), 1);

    // 2. Real TLS HTTPS `413` control on the same site: identical telemetry, no `scheme` field.
    let https_413 = send_tls_raw(
        tls_addr,
        "plain.example.test",
        &tls_connector,
        upload_req.as_bytes(),
    )
    .await?;
    assert!(
        https_413.starts_with("HTTP/1.1 413 Payload Too Large\r\n"),
        "expected 413 over HTTPS, got: {https_413}"
    );
    let events = wait_for_events(&capture, 2).await;
    assert_eq!(events.len(), 2, "expected 2 access log events: {events:?}");
    let ev2 = events.get(1).ok_or("missing HTTPS 413 event")?;
    assert_eq!(ev2.get("status").map(String::as_str), Some("413"));
    assert_eq!(ev2.get("method").map(String::as_str), Some("POST"));
    assert_eq!(ev2.get("target").map(String::as_str), Some("/upload"));
    assert!(ev2.get("scheme").is_none());
    assert_eq!(metric_value(&server, h1_4xx), 2);
    assert_eq!(metric_value(&server, anti_smuggle), 2);

    // 3. Path traversal `400` and header-budget `431` on serve-mode site over plain HTTP are
    //    also logged and counted through the normal pipeline.
    let plain_400 = send_plain_raw(
        http_addr,
        b"GET /../bad HTTP/1.1\r\nHost: plain.example.test\r\nConnection: close\r\n\r\n",
    )
    .await?;
    assert!(
        plain_400.starts_with("HTTP/1.1 400 Bad Request\r\n"),
        "expected 400 for /../bad, got: {plain_400}"
    );
    let events = wait_for_events(&capture, 3).await;
    assert_eq!(events.len(), 3);
    let ev3 = events.get(2).ok_or("missing plain 400 event")?;
    assert_eq!(ev3.get("status").map(String::as_str), Some("400"));
    assert_eq!(ev3.get("scheme").map(String::as_str), Some("http"));
    assert_eq!(metric_value(&server, h1_4xx), 3);
    assert_eq!(metric_value(&server, anti_smuggle), 3);

    let big_pad = "a".repeat(1100);
    let big_hdr_req = format!(
        "GET /index.txt HTTP/1.1\r\nHost: plain.example.test\r\nX-Pad: {big_pad}\r\nConnection: close\r\n\r\n"
    );
    let plain_431 = send_plain_raw(http_addr, big_hdr_req.as_bytes()).await?;
    assert!(
        plain_431.starts_with("HTTP/1.1 431 Request Header Fields Too Large\r\n"),
        "expected 431 for oversized headers, got: {plain_431}"
    );
    let events = wait_for_events(&capture, 4).await;
    assert_eq!(events.len(), 4);
    let ev4 = events.get(3).ok_or("missing plain 431 event")?;
    assert_eq!(ev4.get("status").map(String::as_str), Some("431"));
    assert_eq!(ev4.get("scheme").map(String::as_str), Some("http"));
    assert_eq!(metric_value(&server, h1_4xx), 4);
    assert_eq!(metric_value(&server, anti_smuggle), 4);

    // 4. Control: `413` on `http "redirect"` site stays on the v0.1.2 redirect listener path
    //    (no access log event, no telemetry increment).
    let redir_upload_req = format!(
        "POST /upload HTTP/1.1\r\nHost: redir.example.test\r\nContent-Length: 129\r\nConnection: close\r\n\r\n{body_129}"
    );
    let redir_413 = send_plain_raw(http_addr, redir_upload_req.as_bytes()).await?;
    assert!(
        redir_413.starts_with("HTTP/1.1 413 Payload Too Large\r\n"),
        "expected 413 on redirect site, got: {redir_413}"
    );
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(
        capture.snapshot().len(),
        4,
        "redirect-mode 413 must not emit a miraserve::access event"
    );
    assert_eq!(metric_value(&server, h1_4xx), 4);
    assert_eq!(metric_value(&server, anti_smuggle), 4);

    server.shutdown().await;
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

/// Captures both `miraserve::access` events and tracing warning messages for single-lookup ACME
/// verification.
#[derive(Clone, Default)]
struct AccessAndWarnCapture {
    access: Arc<Mutex<Vec<BTreeMap<String, String>>>>,
    warnings: Arc<Mutex<Vec<String>>>,
}

impl AccessAndWarnCapture {
    fn access_snapshot(&self) -> Vec<BTreeMap<String, String>> {
        self.access
            .lock()
            .map_or_else(|_| Vec::new(), |g| g.clone())
    }

    fn warning_count(&self, needle: &str) -> usize {
        self.warnings
            .lock()
            .map_or(0, |g| g.iter().filter(|m| m.contains(needle)).count())
    }
}

impl Subscriber for AccessAndWarnCapture {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }

    fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}

    fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut rec = FieldRecorder::default();
        event.record(&mut rec);
        if event.metadata().target() == "miraserve::access" {
            if let Ok(mut guard) = self.access.lock() {
                guard.push(rec.fields);
            }
        } else if *event.metadata().level() == tracing::Level::WARN
            && let Some(msg) = rec.fields.get("message")
            && let Ok(mut guard) = self.warnings.lock()
        {
            guard.push(msg.clone());
        }
    }

    fn enter(&self, _span: &span::Id) {}

    fn exit(&self, _span: &span::Id) {}
}

/// Pins round-2 P2s on a serve-mode site:
/// 1. ACME HTTP-01 webroot lookup runs strictly ONCE per request (a bad-permission webroot token
///    file emits its warning once, not twice).
/// 2. An overlength path (> 8192 bytes, even containing invalid percent escapes) is rejected with
///    `414 URI Too Long` before path decoding, identically to HTTPS, and logged/counted.
#[cfg(unix)]
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "current_thread")]
async fn plain_http_serve_site_acme_lookup_runs_once_and_overlength_path_returns_414() -> TestResult
{
    use std::os::unix::fs::PermissionsExt as _;

    let capture = AccessAndWarnCapture::default();
    let _guard = tracing::subscriber::set_default(capture.clone());

    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let base = std::env::temp_dir().join(format!(
        "miraserve-http80-acme-414-{}-{nanos}",
        std::process::id()
    ));
    let root = base.join("root");
    let webroot = base.join("webroot");
    let challenge_dir = webroot.join(".well-known").join("acme-challenge");
    std::fs::create_dir_all(&root)?;
    std::fs::create_dir_all(&challenge_dir)?;
    std::fs::write(root.join("index.txt"), b"ok")?;

    // World-writable token file triggers `acme-webroot token not served` warning on lookup.
    let bad_token = "badperm_token_0123456789";
    let token_path = challenge_dir.join(bad_token);
    std::fs::write(&token_path, format!("{bad_token}.thumbprint"))?;
    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o666))?;

    let webroot_str = webroot.display().to_string().replace('\\', "/");
    let root_str = root.display().to_string().replace('\\', "/");
    let server = start_dual_port_server_retrying(|tls_port, http_port| {
        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
    listen "127.0.0.1:{http_port}" redirect-https=#true
    acme-webroot "{webroot_str}"
}}
site "plain.example.test" {{
    http "serve"
    root "{root_str}"
}}
"#
        );
        let (cfg, _) = parse_kdl("http80-acme-414.kdl", &kdl)?;
        Ok(cfg)
    })
    .await?;
    let tls_addr = server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::HttpsTcp)
        .ok_or("missing HttpsTcp listener")?
        .local_addr;
    let http_addr = server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::HttpRedirect)
        .ok_or("missing HttpRedirect listener")?
        .local_addr;
    let dev_pem = server.dev_cert_pem().ok_or("missing dev cert PEM")?;
    let tls_connector = build_h1_tls_connector(dev_pem)?;

    // 1. Single ACME lookup on serve-mode site: exactly 1 warning, 404 response.
    let acme_req = format!(
        "GET /.well-known/acme-challenge/{bad_token} HTTP/1.1\r\nHost: plain.example.test\r\nConnection: close\r\n\r\n"
    );
    let acme_resp = send_plain_raw(http_addr, acme_req.as_bytes()).await?;
    assert!(
        acme_resp.starts_with("HTTP/1.1 404 Not Found\r\n"),
        "expected 404 when webroot token fails permission check, got: {acme_resp}"
    );
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(
        capture.warning_count("acme-webroot token not served"),
        1,
        "ACME webroot lookup must run strictly once per request on a serve-mode site"
    );

    // 2. Overlength path (> 8192 bytes, with embedded traversal/overlong bytes that would trigger
    //    400 if decoded before length validation): must return 414 on both plain HTTP and HTTPS.
    let overlength_path = format!("/{}/%E0%80%AE", "a".repeat(8_300));
    let raw_414 = format!(
        "GET {overlength_path} HTTP/1.1\r\nHost: plain.example.test\r\nConnection: close\r\n\r\n"
    );
    let plain_414 = send_plain_raw(http_addr, raw_414.as_bytes()).await?;
    assert!(
        plain_414.starts_with("HTTP/1.1 414 URI Too Long\r\n"),
        "expected 414 over plain HTTP for overlength path, got: {plain_414}"
    );
    let https_414 = send_tls_raw(
        tls_addr,
        "plain.example.test",
        &tls_connector,
        raw_414.as_bytes(),
    )
    .await?;
    assert!(
        https_414.starts_with("HTTP/1.1 414 URI Too Long\r\n"),
        "expected 414 over HTTPS control for overlength path, got: {https_414}"
    );

    for _ in 0..50 {
        if capture.access_snapshot().len() >= 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let events = capture.access_snapshot();
    assert_eq!(events.len(), 3, "expected 3 access log events: {events:?}");
    let plain_414_ev = events.get(1).ok_or("missing plain 414 event")?;
    assert_eq!(plain_414_ev.get("status").map(String::as_str), Some("414"));
    assert_eq!(plain_414_ev.get("scheme").map(String::as_str), Some("http"));
    let https_414_ev = events.get(2).ok_or("missing HTTPS 414 event")?;
    assert_eq!(https_414_ev.get("status").map(String::as_str), Some("414"));
    assert!(https_414_ev.get("scheme").is_none());

    server.shutdown().await;
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

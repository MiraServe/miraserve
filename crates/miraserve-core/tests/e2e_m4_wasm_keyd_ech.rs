//! Full-stack Milestone 4 end-to-end test over live PQC TLS 1.3 (`X25519MLKEM768`):
//! - Split-privilege `miraserve-keyd` signing daemon (worker process never loads private keys)
//! - Sandboxed Wasmtime plugins (normal execution + infinite-loop fuel exhaustion DoS defense)
//! - RFC 9849 ECH key-ring initialization, `rustls::client::EchConfig` verification & rotation
//! - Live Prometheus metrics scraping verifying TLS PQC/split-key, HTTP, security & WASM counters

use std::fs;
use std::net::TcpListener as StdTcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::header::HOST;
use http::{Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper_util::rt::TokioIo;
use miraserve_config::{ConfigStore, parse_kdl};
use miraserve_core::{ListenerKind, MiraServeServer, ServerOptions};
use miraserve_tls::{
    KeydEndpoint, KeydKeyStore, KeydServer, build_crypto_provider, generate_dev_certificate,
};
use rustls::client::EchConfig;
use rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
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
        let path = std::env::temp_dir().join(format!(
            "miraserve-m4-e2e-{tag}-{}-{nanos}",
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

fn reserve_two_free_ports() -> Result<(u16, u16), std::io::Error> {
    let sock1 = StdTcpListener::bind("127.0.0.1:0")?;
    let sock2 = StdTcpListener::bind("127.0.0.1:0")?;
    Ok((sock1.local_addr()?.port(), sock2.local_addr()?.port()))
}

#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_split_keyd_pqc_wasm_ech_and_prometheus_telemetry() -> TestResult {
    let tmp = TempDir::new("stack")?;

    // 1. Write two sandboxed WebAssembly modules (valid edge handler + hostile infinite loop).
    let ok_wat_path = tmp.path.join("hello.wat");
    fs::write(
        &ok_wat_path,
        r#"
(module
  (import "miraserve" "set_response_body" (func $set_body (param i32 i32) (result i32)))
  (import "miraserve" "set_response_header" (func $set_hdr (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 1024) "hello from split-key WASM edge!")
  (data (i32.const 1100) "x-edge-wasm")
  (data (i32.const 1120) "sandbox-ok")
  (func (export "miraserve_handle") (param i32 i32 i32 i32) (result i32)
    (drop (call $set_hdr (i32.const 1100) (i32.const 11) (i32.const 1120) (i32.const 10)))
    (drop (call $set_body (i32.const 1024) (i32.const 31)))
    (i32.const 200)
  )
)
"#,
    )?;

    let dos_wat_path = tmp.path.join("spin.wat");
    fs::write(
        &dos_wat_path,
        r#"
(module
  (memory (export "memory") 1)
  (func (export "miraserve_handle") (param i32 i32 i32 i32) (result i32)
    (loop $spin (br $spin))
    (i32.const 200)
  )
)
"#,
    )?;

    // 2. Start isolated split-privilege `miraserve-keyd` holding the private TLS key!
    let provider = build_crypto_provider(true);
    let (real_ck, cert_pem) = generate_dev_certificate(&["edge.m4.test".to_owned()], &provider)?;
    let mut key_store = KeydKeyStore::new();
    key_store.insert_certified_key("m4-default", vec!["edge.m4.test".to_owned()], true, real_ck)?;
    let keyd = KeydServer::start(
        KeydEndpoint::LoopbackTcp("127.0.0.1:0".parse()?),
        key_store,
        false,
    )
    .await?;
    let keyd_sock_str = keyd.endpoint().to_socket_string();

    let (tls_port, metrics_port) = reserve_two_free_ports()?;
    let ok_path_str = ok_wat_path.to_string_lossy().replace('\\', "/");
    let dos_path_str = dos_wat_path.to_string_lossy().replace('\\', "/");

    // 3. Verify `tls.ech #true` is rejected fail-closed (`ECH-1`: rustls 0.23 has no server ECH decryption),
    //    then boot MiraServe worker with key-isolation="split-daemon", WASM routes, and Prometheus!
    let kdl_ech_rejected = format!(
        r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
    tls {{
        min-version "1.3"
        ech #true
    }}
}}
site "edge.m4.test" {{
    route "/ok/*" {{
        wasm-plugin "{ok_path_str}"
    }}
}}
"#
    );
    assert!(
        parse_kdl("ech-rejected.kdl", &kdl_ech_rejected).is_err(),
        "tls.ech #true must be rejected by config validation until server-side ECH decryption exists"
    );

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
    tls {{
        min-version "1.3"
        pqc-hybrid #true
        key-isolation "split-daemon"
        keyd-socket "{keyd_sock_str}"
        ech #false
    }}
    telemetry {{
        metrics-listen "127.0.0.1:{metrics_port}"
        metrics-path "/metrics"
        service-name "m4-e2e"
        redact-logs #true
    }}
}}

site "edge.m4.test" {{
    security-headers "strict"

    route "/ok/*" {{
        wasm-plugin "{ok_path_str}" max-memory="1MB" max-fuel=500000 timeout="1s"
    }}

    route "/dos/*" {{
        wasm-plugin "{dos_path_str}" max-memory="1MB" max-fuel=20000 timeout="1s"
    }}
}}
"#
    );

    let (cfg, report) = parse_kdl("m4-e2e.kdl", &kdl)?;
    assert!(
        report.is_clean(),
        "unexpected config warnings: {:?}",
        report.warnings
    );

    // Verify unauthenticated LoopbackTcp worker connection to keyd fails closed (Threat Model T2)!
    let unauth_start = MiraServeServer::start(
        Arc::new(ConfigStore::new(cfg.clone())),
        ServerOptions {
            dev_tls: false,
            keyd_auth_secret: None,
            ..ServerOptions::default()
        },
    )
    .await;
    assert!(
        unauth_start.is_err(),
        "unauthenticated LoopbackTcp worker MUST fail to connect to keyd"
    );

    let server = MiraServeServer::start(
        Arc::new(ConfigStore::new(cfg)),
        ServerOptions {
            dev_tls: false, // Notice: NO dev_tls and NO local key files! Only remote keyd!
            keyd_auth_secret: keyd.auth_secret(),
            ..ServerOptions::default()
        },
    )
    .await?;

    // 4. Verify offline RFC 9849 ECH config generation/rotation helper produces byte-for-byte valid rustls ECHConfig!
    assert!(server.ech_manager().is_none());
    let ech_mgr = miraserve_tls::EchRotationManager::new(
        "edge.m4.test",
        std::time::Duration::from_secs(3600),
    )?;
    let ech_wire = ech_mgr.active_ech_config_list()?;
    let _parsed_ech = EchConfig::new(ech_wire, ALL_SUPPORTED_SUITES)?;
    let rotated = ech_mgr.rotate()?;
    assert_eq!(rotated.active_config_id, 2);
    assert_eq!(rotated.retained_key_count, 2);

    // 5. Connect over live TLS 1.3 + X25519MLKEM768 signed remotely by `keyd`!
    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::HttpsTcp)
        .ok_or("missing HTTPS listener")?
        .local_addr;

    let mut roots = RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert_pem.cert_pem.as_bytes()).collect::<Result<_, _>>()?;
    let (added, _) = roots.add_parsable_certificates(certs);
    assert_eq!(added, 1);

    let mut cli_tls = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cli_tls.alpn_protocols = vec![b"http/1.1".to_vec()];

    let tcp = TcpStream::connect(https_addr).await?;
    let tls_stream = TlsConnector::from(Arc::new(cli_tls))
        .connect(ServerName::try_from("edge.m4.test")?, tcp)
        .await?;
    let negotiated_kex = tls_stream
        .get_ref()
        .1
        .negotiated_key_exchange_group()
        .ok_or("missing negotiated KEX")?
        .name();
    assert_eq!(negotiated_kex, rustls::NamedGroup::X25519MLKEM768);
    assert_eq!(
        keyd.signatures_served(),
        1,
        "TLS handshake must have been signed remotely by isolated keyd"
    );

    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_stream)).await?;
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    // 6a. Execute valid sandboxed WASM edge plugin
    let ok_resp = sender
        .send_request(
            Request::builder()
                .uri("/ok/hello")
                .header(HOST, "edge.m4.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(ok_resp.status(), StatusCode::OK);
    assert_eq!(
        ok_resp
            .headers()
            .get("x-edge-wasm")
            .and_then(|v| v.to_str().ok()),
        Some("sandbox-ok")
    );
    assert_eq!(
        ok_resp.into_body().collect().await?.to_bytes().as_ref(),
        b"hello from split-key WASM edge!"
    );

    // 6b. Trigger hostile infinite-loop WASM plugin -> deterministic 504 FuelExhausted!
    sender.ready().await?;
    let dos_resp = sender
        .send_request(
            Request::builder()
                .uri("/dos/spin")
                .header(HOST, "edge.m4.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(dos_resp.status(), StatusCode::GATEWAY_TIMEOUT);
    // Drain the 504 body and wait for the HTTP/1 connection to become ready before reusing it.
    let _ = dos_resp.into_body().collect().await?;
    sender.ready().await?;

    // 6c. Server remains 100% healthy and responsive right after hostile plugin trap!
    let after_resp = sender
        .send_request(
            Request::builder()
                .uri("/ok/after")
                .header(HOST, "edge.m4.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(after_resp.status(), StatusCode::OK);
    let _ = after_resp.into_body().collect().await?;

    // 7. Scrape live Prometheus metrics endpoint and verify all Milestone 4 telemetry counters!
    let metrics_addr = server
        .metrics_addr()
        .ok_or("expected active Prometheus metrics listener")?;
    // A request is counted when the server has seen its last bytes flushed, which can be a
    // moment after the client has read the response. Scrape until the last request is counted
    // (or give up after 5 s and let the assertions below report what is there).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let prom_text = loop {
        // One connection per scrape: the metrics listener answers one request per connection
        // (`keep_alive(false)`), so a second scrape on the same connection fails with
        // `ChannelClosed` whenever the first one arrived before the last request was counted.
        let m_tcp = TcpStream::connect(metrics_addr).await?;
        let (mut m_sender, m_conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(m_tcp)).await?;
        let m_task = tokio::spawn(async move {
            let _ = m_conn.await;
        });
        let metrics_resp = m_sender
            .send_request(
                Request::builder()
                    .uri("/metrics")
                    .header(HOST, "127.0.0.1")
                    .body(Empty::<Bytes>::new())?,
            )
            .await?;
        assert_eq!(metrics_resp.status(), StatusCode::OK);
        let text = String::from_utf8(
            metrics_resp
                .into_body()
                .collect()
                .await?
                .to_bytes()
                .to_vec(),
        )?;
        m_task.abort();
        let counted =
            text.contains("miraserve_http_requests_total{protocol=\"h1\",status_class=\"2xx\"} 2");
        if counted || std::time::Instant::now() >= deadline {
            break text;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    };
    assert!(
        prom_text
            .contains("miraserve_tls_handshakes_total{pqc=\"true\",isolation=\"split-daemon\"} 1"),
        "missing split-daemon PQC handshake metric:\n{prom_text}"
    );
    assert!(
        prom_text.contains("miraserve_http_requests_total{protocol=\"h1\",status_class=\"2xx\"} 2"),
        "missing 2xx request counter:\n{prom_text}"
    );
    assert!(
        prom_text.contains("miraserve_http_requests_total{protocol=\"h1\",status_class=\"5xx\"} 1"),
        "missing 5xx request counter:\n{prom_text}"
    );
    assert!(
        prom_text.contains("miraserve_wasm_invocations_total{outcome=\"ok\"} 2"),
        "missing wasm ok counter:\n{prom_text}"
    );
    assert!(
        prom_text.contains("miraserve_wasm_invocations_total{outcome=\"fuel_exhausted\"} 1"),
        "missing wasm fuel_exhausted counter:\n{prom_text}"
    );
    assert!(
        prom_text.contains("miraserve_security_blocks_total{reason=\"wasm_sandbox\"} 1"),
        "missing wasm_sandbox security block counter:\n{prom_text}"
    );

    conn_task.abort();
    server.shutdown().await;
    keyd.shutdown().await;
    Ok(())
}

//! Full-stack Milestone 3 end-to-end test over live PQC TLS 1.3 (`X25519MLKEM768`):
//! 1. Atomic AI site publishing (`/_miraserve/publish` MCP JSON-RPC + Ed25519 signature +
//!    pre-flight secret/XSS checks + zero-downtime live swap + instant rollback)
//! 2. RFC 9421 / Web Bot Auth cryptographic agent verification, unverified AI UA blocking,
//!    and automatic `text/markdown` + `llms.txt` negotiation
//! 3. MCP Security Gateway: RFC 9728 OAuth Protected Resource Metadata, `tools/list` RBAC
//!    filtering, `tools/call` allow/deny enforcement, and JSON nesting depth guard

use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use bytes::Bytes;
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HOST, USER_AGENT, VARY};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt as _, Full};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use miraserve_ai::{RegisteredAgent, sign_rfc9421_headers};
use miraserve_config::{ConfigStore, parse_kdl};
use miraserve_core::{CoreError, ListenerKind, MiraServeServer, ServerOptions};
use miraserve_publish::{Ed25519SigningKey, SignedBundle, SiteBundle};
use miraserve_tls::build_crypto_provider;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};
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
            "miraserve-ai-e2e-{tag}-{}-{nanos}",
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

/// Reserves an ephemeral loopback port that is simultaneously free on BOTH TCP and UDP.
fn reserve_free_port() -> Result<u16, std::io::Error> {
    for _ in 0..64 {
        let tcp = StdTcpListener::bind("127.0.0.1:0")?;
        let port = tcp.local_addr()?.port();
        if StdUdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return Ok(port);
        }
    }
    Err(std::io::Error::new(
        ErrorKind::AddrInUse,
        "failed to reserve a port free on both 127.0.0.1 TCP and UDP",
    ))
}

async fn spawn_mock_mcp_upstream(
    hits: Arc<AtomicUsize>,
) -> Result<(SocketAddr, tokio::task::AbortHandle), std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let hits_c = Arc::clone(&hits);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let hits_inner = Arc::clone(&hits_c);
                    async move {
                        hits_inner.fetch_add(1, Ordering::AcqRel);
                        let raw = req
                            .into_body()
                            .collect()
                            .await
                            .map(http_body_util::Collected::to_bytes)
                            .unwrap_or_default();
                        let parsed: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
                        let id = parsed.get("id").cloned().unwrap_or(Value::Null);
                        let method = parsed
                            .get("method")
                            .and_then(Value::as_str)
                            .unwrap_or_default();

                        let payload = if method == "tools/list" {
                            json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "tools": [
                                        { "name": "docs_search", "description": "Search docs" },
                                        { "name": "db_delete", "description": "Dangerous delete" }
                                    ]
                                }
                            })
                        } else {
                            let tool = parsed
                                .get("params")
                                .and_then(|p| p.get("name"))
                                .and_then(Value::as_str)
                                .unwrap_or("unknown");
                            json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "ok": true,
                                    "executed_tool": tool
                                }
                            })
                        };
                        let bytes = serde_json::to_vec(&payload).unwrap_or_default();
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header(CONTENT_TYPE, "application/json")
                                .body(Full::new(Bytes::from(bytes)))
                                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    Ok((addr, task.abort_handle()))
}

async fn connect_https(
    https_addr: SocketAddr,
    sni: &str,
    tls_cfg: Arc<ClientConfig>,
) -> Result<
    (
        hyper::client::conn::http1::SendRequest<Full<Bytes>>,
        tokio::task::JoinHandle<()>,
    ),
    Box<dyn std::error::Error>,
> {
    let tcp = TcpStream::connect(https_addr).await?;
    let tls_stream = TlsConnector::from(tls_cfg)
        .connect(ServerName::try_from(sni.to_owned())?, tcp)
        .await?;
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls_stream)).await?;
    let task = tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok((sender, task))
}

fn build_signed_publish_rpc(
    rpc_id: u64,
    site_id: &str,
    files: &BTreeMap<String, String>,
    note: &str,
    created_at_unix: u64,
    signing_key: &Ed25519SigningKey,
) -> Value {
    let bundle = SiteBundle {
        files: files
            .iter()
            .map(|(k, v)| (k.clone(), v.as_bytes().to_vec()))
            .collect(),
        note: Some(note.to_owned()),
        created_at_unix,
        site_id: Some(site_id.to_owned()),
    };
    let signed = SignedBundle::sign(bundle, signing_key);
    json!({
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": "tools/call",
        "params": {
            "name": "site_publish",
            "arguments": {
                "files": files,
                "note": note,
                "created_at_unix": created_at_unix,
                "signature_b64": signed.signature_b64,
                "site_id": site_id,
            }
        }
    })
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn live_ai_publish_rfc9421_markdown_and_mcp_gateway_end_to_end() -> TestResult {
    let tmp = TempDir::new("edge")?;
    let storage_dir = tmp.path.join("releases");
    let pubkey_path = tmp.path.join("deploy-agent.pub");
    let mcp_pubkey_path = tmp.path.join("mcp-oauth.pub");

    let deploy_key = Ed25519SigningKey::generate()?;
    fs::write(&pubkey_path, deploy_key.verifying_key().to_encoded())?;
    let mcp_oauth_kp = Ed25519KeyPair::generate()
        .map_err(|_| "failed to generate MCP OAuth test Ed25519 keypair")?;
    let mcp_pub_b64 = encode_std_base64(mcp_oauth_kp.public_key().as_ref());
    fs::write(
        &mcp_pubkey_path,
        format!("miraserve-ed25519-pub:{mcp_pub_b64}"),
    )?;

    let mcp_hits = Arc::new(AtomicUsize::new(0));
    let (mcp_upstream_addr, mcp_abort) = spawn_mock_mcp_upstream(Arc::clone(&mcp_hits)).await?;
    let tls_port = reserve_free_port()?;

    let storage_str = storage_dir.to_string_lossy().replace('\\', "/");
    let pubkey_str = pubkey_path.to_string_lossy().replace('\\', "/");
    let mcp_pubkey_str = mcp_pubkey_path.to_string_lossy().replace('\\', "/");

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
    tls {{
        min-version "1.3"
        pqc-hybrid #true
    }}
}}

site "future.example.test" {{
    security-headers "strict"

    bot-auth {{
        verify-rfc9421 #true
        allow-agent "verified-ai-agents" serve-markdown=#true
        on-unverified-ai-ua "block"
    }}

    ai-publish {{
        storage "{storage_str}"
        keep-versions 5
        require-signature "ed25519:{pubkey_str}"
        preflight-checks "no-secrets" "no-inline-scripts" "csp-valid"
        mcp-endpoint "/_miraserve/publish" auth="oauth-jwt"
    }}
}}

site "ai.example.test" {{
    security-headers "strict"

    route "/mcp/*" {{
        mcp-gateway upstream="http://127.0.0.1:{}" {{
            oauth-resource-metadata #true
            jwt-public-key "ed25519:{mcp_pubkey_str}"
            jwt-issuer "https://auth.example.test"
            jwt-audience "https://ai.example.test"
            allow-tools "docs_search"
            deny-tools "*_delete"
            audit-log "structured-json"
        }}
    }}
}}
"#,
        mcp_upstream_addr.port()
    );

    let (cfg, _report) = parse_kdl("ai-edge.kdl", &kdl)?;
    let server = MiraServeServer::start(
        Arc::new(ConfigStore::new(cfg)),
        ServerOptions {
            dev_tls: true,
            ..ServerOptions::default()
        },
    )
    .await?;

    // Register an Ed25519 AI agent in the live lock-free Web Bot Auth key registry.
    let agent_kp =
        Ed25519KeyPair::generate().map_err(|_| "failed to generate RFC 9421 test agent keypair")?;
    let mut agent_pub = [0_u8; 32];
    if let Some(raw) = agent_kp.public_key().as_ref().get(..32) {
        agent_pub.copy_from_slice(raw);
    }
    server.agent_keys().register(
        "agent-key-2026",
        RegisteredAgent {
            agent_id: "trusted-research-bot".to_owned(),
            group: "verified-ai-agents".to_owned(),
            public_key: agent_pub,
        },
    );

    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::HttpsTcp)
        .ok_or("missing HTTPS listener")?
        .local_addr;
    let dev_pem = server.dev_cert_pem().ok_or("missing dev cert PEM")?;

    let mut roots = RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(dev_pem.as_bytes()).collect::<Result<_, _>>()?;
    let (added, _) = roots.add_parsable_certificates(certs);
    assert_eq!(added, 1);

    let mut cli_tls = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cli_tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let cli_tls = Arc::new(cli_tls);

    // =========================================================================
    // PART 1: Site `future.example.test` (ai-publish + Web Bot Auth + Markdown)
    // =========================================================================
    let (mut future_tx, future_conn) =
        connect_https(https_addr, "future.example.test", Arc::clone(&cli_tls)).await?;

    // 1a. Before first release: 503 Service Unavailable
    let pre_resp = future_tx
        .send_request(
            Request::builder()
                .uri("/")
                .header(HOST, "future.example.test")
                .body(Full::new(Bytes::new()))?,
        )
        .await?;
    assert_eq!(pre_resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    // 1b. Unauthenticated publish attempt -> 401 Unauthorized
    let unauth = future_tx
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("/_miraserve/publish")
                .header(HOST, "future.example.test")
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(b"{}")))?,
        )
        .await?;
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

    // 1b-2. Forged/unsigned JWT MUST be rejected with 401 Unauthorized (cryptographic EdDSA check)
    let forged_jwt = "Bearer eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJkZXBsb3ktYWdlbnQifQ.sig";
    let forged_resp = future_tx
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("/_miraserve/publish")
                .header(HOST, "future.example.test")
                .header(AUTHORIZATION, forged_jwt)
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(b"{}")))?,
        )
        .await?;
    assert_eq!(forged_resp.status(), StatusCode::UNAUTHORIZED);

    let now_for_jwt = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let jwt_auth = format!(
        "Bearer {}",
        deploy_key.sign_oauth_jwt_with_audience(
            "deploy-agent",
            Some("future.example.test"),
            now_for_jwt.saturating_add(300),
            Some("publish")
        )
    );
    let jwt_auth = jwt_auth.as_str();

    // 1c. Publish signed V1 over live HTTPS MCP JSON-RPC endpoint
    let v1_files = BTreeMap::from([
        (
            "index.html".to_owned(),
            "<!doctype html><html><body><h1>MiraServe Future V1</h1><p>Zero-trust edge.</p></body></html>".to_owned(),
        ),
        (
            "llms.txt".to_owned(),
            "# Future Site\n> Atomic AI site hosted by MiraServe\n".to_owned(),
        ),
    ]);
    let pub_v1_rpc = build_signed_publish_rpc(
        1,
        "future.example.test",
        &v1_files,
        "release v1",
        now_for_jwt,
        &deploy_key,
    );
    let pub_v1_resp = future_tx
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("/_miraserve/publish")
                .header(HOST, "future.example.test")
                .header(AUTHORIZATION, jwt_auth)
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(serde_json::to_vec(&pub_v1_rpc)?)))?,
        )
        .await?;
    assert_eq!(pub_v1_resp.status(), StatusCode::OK);
    let pub_v1_json: Value =
        serde_json::from_slice(&pub_v1_resp.into_body().collect().await?.to_bytes())?;
    assert!(
        pub_v1_json.get("error").is_none(),
        "unexpected publish v1 error: {pub_v1_json}"
    );

    // 1d. Browser receives HTML 200 OK
    let html_resp = future_tx
        .send_request(
            Request::builder()
                .uri("/")
                .header(HOST, "future.example.test")
                .header(USER_AGENT, "Mozilla/5.0")
                .body(Full::new(Bytes::new()))?,
        )
        .await?;
    assert_eq!(html_resp.status(), StatusCode::OK);
    let html_ct = html_resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(html_ct.starts_with("text/html"), "ct: {html_ct}");
    // BOT-4: Negotiated HTML responses MUST include `Vary: Accept` so shared caches never cross-contaminate!
    let html_vary = html_resp
        .headers()
        .get(VARY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        html_vary.to_ascii_lowercase().contains("accept"),
        "expected Vary: Accept on negotiated HTML response, got: {html_vary:?}"
    );
    let html_body = String::from_utf8(html_resp.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(html_body.contains("MiraServe Future V1"));

    // 1e. Explicit `Accept: text/markdown` converts HTML to Markdown with Vary header
    let md_resp = future_tx
        .send_request(
            Request::builder()
                .uri("/")
                .header(HOST, "future.example.test")
                .header(ACCEPT, "text/markdown, text/html;q=0.5")
                .body(Full::new(Bytes::new()))?,
        )
        .await?;
    assert_eq!(md_resp.status(), StatusCode::OK);
    assert_eq!(
        md_resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/markdown; charset=utf-8")
    );
    assert!(md_resp.headers().contains_key(VARY));
    let md_body = String::from_utf8(md_resp.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(md_body.contains("# MiraServe Future V1"), "md: {md_body}");

    // 1f. `GET /llms.txt` works directly
    let llms_resp = future_tx
        .send_request(
            Request::builder()
                .uri("/llms.txt")
                .header(HOST, "future.example.test")
                .body(Full::new(Bytes::new()))?,
        )
        .await?;
    assert_eq!(llms_resp.status(), StatusCode::OK);
    let llms_body = String::from_utf8(llms_resp.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(llms_body.contains("Atomic AI site hosted by MiraServe"));

    // 1g. Unverified AI crawler UA is blocked with 403 Forbidden
    let unverified_bot = future_tx
        .send_request(
            Request::builder()
                .uri("/")
                .header(HOST, "future.example.test")
                .header(USER_AGENT, "GPTBot/1.0")
                .body(Full::new(Bytes::new()))?,
        )
        .await?;
    assert_eq!(unverified_bot.status(), StatusCode::FORBIDDEN);

    // 1h. RFC 9421 Ed25519 signed AI agent is verified and automatically served Markdown!
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut signed_headers = HeaderMap::new();
    signed_headers.insert(HOST, "future.example.test".parse()?);
    signed_headers.insert(USER_AGENT, "GPTBot/1.0".parse()?);
    let uri = Uri::from_static("/");
    sign_rfc9421_headers(
        &Method::GET,
        &uri,
        &mut signed_headers,
        "agent-key-2026",
        &agent_kp,
        now_secs,
        now_secs.saturating_add(120),
    )?;

    let mut req_builder = Request::builder().method(Method::GET).uri("/");
    for (k, v) in &signed_headers {
        req_builder = req_builder.header(k, v);
    }
    let verified_bot = future_tx
        .send_request(req_builder.body(Full::new(Bytes::new()))?)
        .await?;
    assert_eq!(verified_bot.status(), StatusCode::OK);
    assert_eq!(
        verified_bot
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/markdown; charset=utf-8")
    );
    let bot_body = String::from_utf8(
        verified_bot
            .into_body()
            .collect()
            .await?
            .to_bytes()
            .to_vec(),
    )?;
    assert!(bot_body.contains("# MiraServe Future V1"));

    // 1i. Publish V2 atomically, verify live swap, then invoke MCP `site_rollback` back to V1!
    let v2_files = BTreeMap::from([(
        "index.html".to_owned(),
        "<!doctype html><html><body><h1>MiraServe Future V2</h1></body></html>".to_owned(),
    )]);
    let pub_v2_rpc = build_signed_publish_rpc(
        2,
        "future.example.test",
        &v2_files,
        "release v2",
        now_for_jwt.saturating_add(1),
        &deploy_key,
    );
    let pub_v2_resp = future_tx
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("/_miraserve/publish")
                .header(HOST, "future.example.test")
                .header(AUTHORIZATION, jwt_auth)
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(serde_json::to_vec(&pub_v2_rpc)?)))?,
        )
        .await?;
    assert_eq!(pub_v2_resp.status(), StatusCode::OK);

    let v2_live = future_tx
        .send_request(
            Request::builder()
                .uri("/")
                .header(HOST, "future.example.test")
                .body(Full::new(Bytes::new()))?,
        )
        .await?;
    let v2_text = String::from_utf8(v2_live.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(v2_text.contains("MiraServe Future V2"));

    let rollback_rpc = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "site_rollback",
            "arguments": {}
        }
    });
    let rb_resp = future_tx
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("/_miraserve/publish")
                .header(HOST, "future.example.test")
                .header(AUTHORIZATION, jwt_auth)
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(serde_json::to_vec(&rollback_rpc)?)))?,
        )
        .await?;
    assert_eq!(rb_resp.status(), StatusCode::OK);

    let rolled_back_live = future_tx
        .send_request(
            Request::builder()
                .uri("/")
                .header(HOST, "future.example.test")
                .body(Full::new(Bytes::new()))?,
        )
        .await?;
    let rb_text = String::from_utf8(
        rolled_back_live
            .into_body()
            .collect()
            .await?
            .to_bytes()
            .to_vec(),
    )?;
    assert!(
        rb_text.contains("MiraServe Future V1"),
        "expected rollback to V1, got: {rb_text}"
    );
    future_conn.abort();

    // =========================================================================
    // PART 2: Site `ai.example.test` (MCP Security Gateway + OAuth RFC 9728)
    // =========================================================================
    let (mut ai_tx, ai_conn) =
        connect_https(https_addr, "ai.example.test", Arc::clone(&cli_tls)).await?;

    // 2a. RFC 9728 OAuth 2.1 Protected Resource Metadata
    let meta_resp = ai_tx
        .send_request(
            Request::builder()
                .uri("/.well-known/oauth-protected-resource")
                .header(HOST, "ai.example.test")
                .body(Full::new(Bytes::new()))?,
        )
        .await?;
    assert_eq!(meta_resp.status(), StatusCode::OK);
    let meta_json: Value =
        serde_json::from_slice(&meta_resp.into_body().collect().await?.to_bytes())?;
    assert_eq!(
        meta_json.get("resource").and_then(Value::as_str),
        Some("https://ai.example.test")
    );

    // 2a-2. Unauthenticated MCP request MUST fail closed with 401 + WWW-Authenticate
    let unauth_mcp = ai_tx
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp/rpc")
                .header(HOST, "ai.example.test")
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(
                    br#"{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{}}"#,
                )))?,
        )
        .await?;
    assert_eq!(unauth_mcp.status(), StatusCode::UNAUTHORIZED);
    assert!(unauth_mcp.headers().contains_key("www-authenticate"));
    assert_eq!(mcp_hits.load(Ordering::Acquire), 0);

    // 2a-3. Forged/opaque Bearer tokens MUST fail closed with 401 Unauthorized (`MCP-2`)!
    for bad_token in [
        "Bearer mcp-valid-oauth-token-2026",
        "Bearer eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJmYWtlIiwiZXhwIjo5OTk5OTk5OTk5fQ.ZmFrZQ",
    ] {
        let bad_resp = ai_tx
            .send_request(
                Request::builder()
                    .method(Method::POST)
                    .uri("/mcp/rpc")
                    .header(HOST, "ai.example.test")
                    .header(AUTHORIZATION, bad_token)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from_static(
                        br#"{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{}}"#,
                    )))?,
            )
            .await?;
        assert_eq!(bad_resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(mcp_hits.load(Ordering::Acquire), 0);
    }

    let mcp_bearer_str = format!(
        "Bearer {}",
        miraserve_ai::sign_mcp_oauth_jwt(
            &mcp_oauth_kp,
            "mcp-agent",
            now_for_jwt.saturating_add(300),
            Some("https://auth.example.test"),
            Some("https://ai.example.test"),
            None,
            None,
        )
    );
    let mcp_bearer = mcp_bearer_str.as_str();

    // 2b. `tools/list` filters out `db_delete` before returning to client
    let list_rpc = json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/list",
        "params": {}
    });
    let list_resp = ai_tx
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp/rpc")
                .header(HOST, "ai.example.test")
                .header(AUTHORIZATION, mcp_bearer)
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(serde_json::to_vec(&list_rpc)?)))?,
        )
        .await?;
    assert_eq!(list_resp.status(), StatusCode::OK);
    let list_json: Value =
        serde_json::from_slice(&list_resp.into_body().collect().await?.to_bytes())?;
    let tools = list_json
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(Value::as_array)
        .ok_or("missing filtered tools array")?;
    assert_eq!(tools.len(), 1);
    assert_eq!(
        tools
            .first()
            .and_then(|t| t.get("name"))
            .and_then(Value::as_str),
        Some("docs_search")
    );
    assert_eq!(mcp_hits.load(Ordering::Acquire), 1);

    // 2c. Allowed tool `docs_search` reaches upstream MCP server
    let allow_rpc = json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "tools/call",
        "params": {
            "name": "docs_search",
            "arguments": { "query": "post-quantum TLS" }
        }
    });
    let allow_resp = ai_tx
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp/rpc")
                .header(HOST, "ai.example.test")
                .header(AUTHORIZATION, mcp_bearer)
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(serde_json::to_vec(&allow_rpc)?)))?,
        )
        .await?;
    assert_eq!(allow_resp.status(), StatusCode::OK);
    let allow_json: Value =
        serde_json::from_slice(&allow_resp.into_body().collect().await?.to_bytes())?;
    assert_eq!(
        allow_json
            .get("result")
            .and_then(|r| r.get("executed_tool"))
            .and_then(Value::as_str),
        Some("docs_search")
    );
    assert_eq!(mcp_hits.load(Ordering::Acquire), 2);

    // 2d. Denied tool `db_delete` is blocked at gateway (403 + JSON-RPC -32003), upstream untouched!
    let deny_rpc = json!({
        "jsonrpc": "2.0",
        "id": 12,
        "method": "tools/call",
        "params": {
            "name": "db_delete",
            "arguments": { "table": "users" }
        }
    });
    let deny_resp = ai_tx
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp/rpc")
                .header(HOST, "ai.example.test")
                .header(AUTHORIZATION, mcp_bearer)
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(serde_json::to_vec(&deny_rpc)?)))?,
        )
        .await?;
    assert_eq!(deny_resp.status(), StatusCode::FORBIDDEN);
    let deny_json: Value =
        serde_json::from_slice(&deny_resp.into_body().collect().await?.to_bytes())?;
    assert_eq!(
        deny_json
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(Value::as_i64),
        Some(-32003)
    );
    assert_eq!(
        mcp_hits.load(Ordering::Acquire),
        2,
        "denied MCP tool must NEVER hit upstream server"
    );

    // 2d-2. JSON-RPC batch array smuggling attempt is rejected fail-closed with 400!
    let batch_rpc = json!([{
        "jsonrpc": "2.0",
        "id": 13,
        "method": "tools/call",
        "params": { "name": "db_delete", "arguments": {} }
    }]);
    let batch_resp = ai_tx
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp/rpc")
                .header(HOST, "ai.example.test")
                .header(AUTHORIZATION, mcp_bearer)
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(serde_json::to_vec(&batch_rpc)?)))?,
        )
        .await?;
    assert_eq!(batch_resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(mcp_hits.load(Ordering::Acquire), 2);

    // 2e. Deeply nested JSON DoS payload is rejected with 400 Bad Request, upstream untouched!
    let deep_nested = format!("{}0{}", "[".repeat(48), "]".repeat(48));
    let deep_resp = ai_tx
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp/rpc")
                .header(HOST, "ai.example.test")
                .header(AUTHORIZATION, mcp_bearer)
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(deep_nested)))?,
        )
        .await?;
    assert_eq!(deep_resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(mcp_hits.load(Ordering::Acquire), 2);

    ai_conn.abort();
    server.shutdown().await;
    mcp_abort.abort();
    Ok(())
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn live_mtls_publish_verifies_tls_peer_and_rejects_header_spoof() -> TestResult {
    let tmp = TempDir::new("mtls")?;
    let storage_dir = tmp.path.join("releases");
    let pubkey_path = tmp.path.join("deploy.pub");
    let client_ca_path = tmp.path.join("client-ca.pem");

    let deploy_key = Ed25519SigningKey::generate()?;
    fs::write(&pubkey_path, deploy_key.verifying_key().to_encoded())?;

    // Generate a self-signed ECDSA P-256 client cert and trust it as the mTLS client CA.
    let client_cert = miraserve_tls::generate_dev_cert_pem(&["deploy-client.internal".to_owned()])?;
    fs::write(&client_ca_path, client_cert.cert_pem.as_bytes())?;

    let tls_port = reserve_free_port()?;
    let storage_str = storage_dir.to_string_lossy().replace('\\', "/");
    let pubkey_str = pubkey_path.to_string_lossy().replace('\\', "/");
    let ca_str = client_ca_path.to_string_lossy().replace('\\', "/");

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
    tls {{
        min-version "1.3"
        pqc-hybrid #true
        client-ca "{ca_str}"
    }}
}}

site "mtls.example.test" {{
    security-headers "strict"
    ai-publish {{
        storage "{storage_str}"
        keep-versions 3
        require-signature "ed25519:{pubkey_str}"
        mcp-endpoint "/_miraserve/publish" auth="mtls"
    }}
}}
"#
    );

    let (cfg, _report) = parse_kdl("mtls.kdl", &kdl)?;
    let server = MiraServeServer::start(
        Arc::new(ConfigStore::new(cfg)),
        ServerOptions {
            dev_tls: true,
            ..ServerOptions::default()
        },
    )
    .await?;

    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::HttpsTcp)
        .ok_or("missing HTTPS listener")?
        .local_addr;
    let dev_pem = server.dev_cert_pem().ok_or("missing dev cert PEM")?;

    let mut roots = RootCertStore::empty();
    let srv_certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(dev_pem.as_bytes()).collect::<Result<_, _>>()?;
    let (added, _) = roots.add_parsable_certificates(srv_certs);
    assert_eq!(added, 1);

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let files = BTreeMap::from([(
        "index.html".to_owned(),
        "<!doctype html><html><body><h1>mTLS Live</h1></body></html>".to_owned(),
    )]);
    let rpc = build_signed_publish_rpc(
        1,
        "mtls.example.test",
        &files,
        "mtls v1",
        now_unix,
        &deploy_key,
    );
    let rpc_bytes = serde_json::to_vec(&rpc)?;

    // 1. Unauthenticated TLS client spoofing `X-SSL-Client-S-DN` MUST be rejected with 401 (`PUB-2`)!
    let mut no_auth_tls = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    no_auth_tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let (mut unauth_tx, unauth_conn) =
        connect_https(https_addr, "mtls.example.test", Arc::new(no_auth_tls)).await?;
    let spoof_resp = unauth_tx
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("/_miraserve/publish")
                .header(HOST, "mtls.example.test")
                .header("x-ssl-client-s-dn", "CN=spoofed-admin")
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(rpc_bytes.clone())))?,
        )
        .await?;
    assert_eq!(
        spoof_resp.status(),
        StatusCode::UNAUTHORIZED,
        "spoofed X-SSL-Client-S-DN without TLS client cert MUST fail closed with 401"
    );
    unauth_conn.abort();

    // 2. Real TLS mTLS client presenting trusted client cert succeeds (`PUB-2`)!
    let cli_chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(client_cert.cert_pem.as_bytes())
            .collect::<Result<_, _>>()?;
    let cli_key = rustls::pki_types::PrivateKeyDer::from_pem_slice(client_cert.key_pem.as_bytes())?;
    let mut mtls_cfg = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_client_auth_cert(cli_chain, cli_key)?;
    mtls_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let (mut mtls_tx, mtls_conn) =
        connect_https(https_addr, "mtls.example.test", Arc::new(mtls_cfg)).await?;
    let ok_resp = mtls_tx
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("/_miraserve/publish")
                .header(HOST, "mtls.example.test")
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(rpc_bytes)))?,
        )
        .await?;
    assert_eq!(ok_resp.status(), StatusCode::OK);
    let ok_json: Value = serde_json::from_slice(&ok_resp.into_body().collect().await?.to_bytes())?;
    assert!(
        ok_json.get("error").is_none(),
        "unexpected mTLS publish error: {ok_json}"
    );

    mtls_conn.abort();
    server.shutdown().await;
    Ok(())
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn live_cross_site_mtls_client_ca_isolation_tcp_and_quic() -> TestResult {
    let tmp = TempDir::new("cross-site-mtls")?;
    let storage_a = tmp.path.join("releases-a");
    let storage_b = tmp.path.join("releases-b");
    let pub_a_path = tmp.path.join("deploy-a.pub");
    let pub_b_path = tmp.path.join("deploy-b.pub");
    let ca_a_path = tmp.path.join("ca-a.pem");
    let ca_b_path = tmp.path.join("ca-b.pem");

    let deploy_key_a = Ed25519SigningKey::generate()?;
    let deploy_key_b = Ed25519SigningKey::generate()?;
    fs::write(&pub_a_path, deploy_key_a.verifying_key().to_encoded())?;
    fs::write(&pub_b_path, deploy_key_b.verifying_key().to_encoded())?;

    // Distinct self-signed client CAs for Site A and Site B!
    let client_a = miraserve_tls::generate_dev_cert_pem(&["client-a.internal".to_owned()])?;
    let client_b = miraserve_tls::generate_dev_cert_pem(&["client-b.internal".to_owned()])?;
    fs::write(&ca_a_path, client_a.cert_pem.as_bytes())?;
    fs::write(&ca_b_path, client_b.cert_pem.as_bytes())?;

    let mut last_bind_err: Option<CoreError> = None;
    let mut started_server = None;
    for _ in 0..16 {
        let tls_port = reserve_free_port()?;
        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h3,h2,h1"
    tls {{
        min-version "1.3"
        pqc-hybrid #true
    }}
}}

site "site-a.example.test" {{
    security-headers "strict"
    tls {{
        client-ca "{}"
    }}
    ai-publish {{
        storage "{}"
        keep-versions 3
        require-signature "ed25519:{}"
        mcp-endpoint "/_miraserve/publish" auth="mtls"
    }}
}}

site "site-b.example.test" {{
    security-headers "strict"
    tls {{
        client-ca "{}"
    }}
    ai-publish {{
        storage "{}"
        keep-versions 3
        require-signature "ed25519:{}"
        mcp-endpoint "/_miraserve/publish" auth="mtls"
    }}
}}
"#,
            ca_a_path.to_string_lossy().replace('\\', "/"),
            storage_a.to_string_lossy().replace('\\', "/"),
            pub_a_path.to_string_lossy().replace('\\', "/"),
            ca_b_path.to_string_lossy().replace('\\', "/"),
            storage_b.to_string_lossy().replace('\\', "/"),
            pub_b_path.to_string_lossy().replace('\\', "/"),
        );

        let (cfg, _) = parse_kdl("cross-site-mtls.kdl", &kdl)?;
        match MiraServeServer::start(
            Arc::new(ConfigStore::new(cfg)),
            ServerOptions {
                dev_tls: true,
                ..ServerOptions::default()
            },
        )
        .await
        {
            Ok(srv) => {
                started_server = Some(srv);
                break;
            }
            Err(CoreError::Bind { source, addr }) if source.kind() == ErrorKind::AddrInUse => {
                last_bind_err = Some(CoreError::Bind { addr, source });
            }
            Err(err) => return Err(err.into()),
        }
    }
    let Some(server) = started_server else {
        return Err(last_bind_err.map_or_else(|| "exhausted bind retries".into(), Into::into));
    };

    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::HttpsTcp)
        .ok_or("missing HTTPS listener")?
        .local_addr;
    let h3_addr = server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::Http3Udp)
        .ok_or("missing HTTP/3 listener")?
        .local_addr;
    let dev_pem = server.dev_cert_pem().ok_or("missing dev cert PEM")?;

    let mut roots = RootCertStore::empty();
    let srv_certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(dev_pem.as_bytes()).collect::<Result<_, _>>()?;
    roots.add_parsable_certificates(srv_certs);

    let build_client_tls = |pem: &miraserve_tls::GeneratedCertPem,
                            alpn: &[u8]|
     -> Result<ClientConfig, Box<dyn std::error::Error>> {
        let chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(pem.cert_pem.as_bytes()).collect::<Result<_, _>>()?;
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(pem.key_pem.as_bytes())?;
        let mut cfg = ClientConfig::builder_with_provider(build_crypto_provider(true))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots.clone())
            .with_client_auth_cert(chain, key)?;
        cfg.alpn_protocols = vec![alpn.to_vec()];
        Ok(cfg)
    };

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    // Publish V1 & V2 to Site B using Site B's own trusted client cert B!
    let (mut b_tx, b_conn) = connect_https(
        https_addr,
        "site-b.example.test",
        Arc::new(build_client_tls(&client_b, b"http/1.1")?),
    )
    .await?;
    for (id, html, ts) in [
        (1_u64, "<h1>Site B V1</h1>", now_unix),
        (2_u64, "<h1>Site B V2</h1>", now_unix.saturating_add(1)),
    ] {
        let files = BTreeMap::from([("index.html".to_owned(), html.to_owned())]);
        let rpc =
            build_signed_publish_rpc(id, "site-b.example.test", &files, "rel", ts, &deploy_key_b);
        let resp = b_tx
            .send_request(
                Request::builder()
                    .method(Method::POST)
                    .uri("/_miraserve/publish")
                    .header(HOST, "site-b.example.test")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from(serde_json::to_vec(&rpc)?)))?,
            )
            .await?;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    let rollback_bytes = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 99,
        "method": "tools/call",
        "params": { "name": "site_rollback", "arguments": {} }
    }))?;

    // ATTACK 1 (TCP direct SNI=site-b with Client A's cert):
    // Server selects Site B's isolated ServerConfig (trusting ONLY ca-b.pem) -> handshake fails
    // OR request fails closed with 401!
    let client_a_h1 = Arc::new(build_client_tls(&client_a, b"http/1.1")?);
    if let Ok((mut cross_tx, cross_conn)) =
        connect_https(https_addr, "site-b.example.test", Arc::clone(&client_a_h1)).await
    {
        let res = cross_tx
            .send_request(
                Request::builder()
                    .method(Method::POST)
                    .uri("/_miraserve/publish")
                    .header(HOST, "site-b.example.test")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from(rollback_bytes.clone())))?,
            )
            .await;
        if let Ok(resp) = res {
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "Client A cert must NEVER authorize Site B publish/rollback!"
            );
        }
        cross_conn.abort();
    }

    // ATTACK 2 (Coalesced TCP connection: SNI=site-a with Client A's cert, Host: site-b):
    // Even though TLS handshake succeeded on SNI=site-a, router MUST verify Client A's cert
    // strictly against Site B's CA and reject with 401!
    let (mut coal_tx, coal_conn) =
        connect_https(https_addr, "site-a.example.test", Arc::clone(&client_a_h1)).await?;
    let coal_resp = coal_tx
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("/_miraserve/publish")
                .header(HOST, "site-b.example.test")
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(rollback_bytes.clone())))?,
        )
        .await?;
    assert_eq!(
        coal_resp.status(),
        StatusCode::MISDIRECTED_REQUEST,
        "coalesced SNI=site-a request targeting Host=site-b MUST be rejected with 421 Misdirected Request"
    );
    coal_conn.abort();

    // ATTACK 3 (QUIC / HTTP/3 with Client A's cert targeting Site B):
    // QUIC shares one UDP ServerConfig, so router's per-site ClientCertTrust MUST reject Client A with 401!
    let h3_client_a_tls = build_client_tls(&client_a, b"h3")?;
    let quic_cli_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(h3_client_a_tls)?;
    let mut quic_ep = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    quic_ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_cli_crypto)));
    let quinn_conn = quic_ep.connect(h3_addr, "site-b.example.test")?.await?;
    let (mut h3_driver, mut h3_send) =
        h3::client::new(h3_quinn::Connection::new(quinn_conn)).await?;
    let h3_driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| h3_driver.poll_close(cx)).await;
    });
    let mut h3_stream = h3_send
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("https://site-b.example.test/_miraserve/publish")
                .header(CONTENT_TYPE, "application/json")
                .body(())?,
        )
        .await?;
    h3_stream
        .send_data(Bytes::from(rollback_bytes.clone()))
        .await?;
    h3_stream.finish().await?;
    let h3_resp = h3_stream.recv_response().await?;
    assert_eq!(
        h3_resp.status(),
        StatusCode::UNAUTHORIZED,
        "HTTP/3 Client A cert MUST be rejected by Site B with 401"
    );
    h3_driver_task.abort();
    quic_ep.close(0_u32.into(), b"done");

    // Verify Site B is STILL serving V2 (none of the cross-site attacks rolled it back!).
    let still_v2 = b_tx
        .send_request(
            Request::builder()
                .uri("/")
                .header(HOST, "site-b.example.test")
                .body(Full::new(Bytes::new()))?,
        )
        .await?;
    assert_eq!(still_v2.status(), StatusCode::OK);
    let still_v2_body =
        String::from_utf8(still_v2.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(still_v2_body.contains("Site B V2"));

    // Legitimate Client B CAN roll Site B back to V1!
    let ok_rb = b_tx
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("/_miraserve/publish")
                .header(HOST, "site-b.example.test")
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(rollback_bytes)))?,
        )
        .await?;
    assert_eq!(ok_rb.status(), StatusCode::OK);

    b_conn.abort();
    server.shutdown().await;
    Ok(())
}

fn encode_std_base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let lookup = |idx: u32| char::from(*TABLE.get(idx as usize).unwrap_or(&b'A'));
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(*chunk.first().unwrap_or(&0));
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(lookup((triple >> 18) & 0x3F));
        out.push(lookup((triple >> 12) & 0x3F));
        if chunk.len() > 1 {
            out.push(lookup((triple >> 6) & 0x3F));
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(lookup(triple & 0x3F));
        } else {
            out.push('=');
        }
    }
    out
}

async fn send_signed_bot_req(
    tx: &mut hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    key_id: &str,
    kp: &Ed25519KeyPair,
) -> Result<Response<hyper::body::Incoming>, Box<dyn std::error::Error>> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut hdrs = HeaderMap::new();
    hdrs.insert(HOST, "bot-reload.example.test".parse()?);
    hdrs.insert(USER_AGENT, HeaderValue::from_static("GPTBot/1.0"));
    let uri = Uri::from_static("/");
    sign_rfc9421_headers(
        &Method::GET,
        &uri,
        &mut hdrs,
        key_id,
        kp,
        now,
        now.saturating_add(120),
    )?;
    let mut rb = Request::builder().method(Method::GET).uri("/");
    for (k, v) in &hdrs {
        rb = rb.header(k, v);
    }
    let req = rb.body(Full::new(Bytes::new()))?;
    Ok(tx.send_request(req).await?)
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn live_bot_auth_reload_revokes_removed_kdl_key_atomically() -> TestResult {
    let tmp = TempDir::new("bot-reload")?;
    let root_dir = tmp.path.join("site");
    fs::create_dir_all(&root_dir)?;
    fs::write(
        root_dir.join("index.html"),
        "<!doctype html><html><body><h1>Bot Reload Test</h1></body></html>",
    )?;

    let kp1 = Ed25519KeyPair::generate().map_err(|_| "kp1 gen failed")?;
    let kp2 = Ed25519KeyPair::generate().map_err(|_| "kp2 gen failed")?;
    let pub1_b64 = encode_std_base64(kp1.public_key().as_ref());
    let pub2_b64 = encode_std_base64(kp2.public_key().as_ref());

    let tls_port = reserve_free_port()?;
    let root_str = root_dir.to_string_lossy().replace('\\', "/");

    let build_kdl = |key_id: &str, pub_b64: &str, bad_root: bool| -> String {
        let r = if bad_root {
            "/nonexistent-dir-for-failed-reload-test"
        } else {
            root_str.as_str()
        };
        format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
    tls {{
        min-version "1.3"
        pqc-hybrid #true
    }}
}}

site "bot-reload.example.test" {{
    security-headers "strict"
    root "{r}"
    bot-auth {{
        verify-rfc9421 #true
        allow-agent "verified-ai-agents" serve-markdown=#true
        on-unverified-ai-ua "block"
        agent-key "{key_id}" agent-id="bot-{key_id}" group="verified-ai-agents" ed25519="{pub_b64}"
    }}
}}
"#
        )
    };

    let (cfg1, _) = parse_kdl("bot-v1.kdl", &build_kdl("k1", &pub1_b64, false))?;
    let server = MiraServeServer::start(
        Arc::new(ConfigStore::new(cfg1)),
        ServerOptions {
            dev_tls: true,
            ..ServerOptions::default()
        },
    )
    .await?;

    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::HttpsTcp)
        .ok_or("missing HTTPS listener")?
        .local_addr;
    let dev_pem = server.dev_cert_pem().ok_or("missing dev cert PEM")?;
    let mut roots = RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(dev_pem.as_bytes()).collect::<Result<_, _>>()?;
    roots.add_parsable_certificates(certs);

    let mut cli_tls = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cli_tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let (mut tx, conn_task) =
        connect_https(https_addr, "bot-reload.example.test", Arc::new(cli_tls)).await?;

    // 1. Before reload: `k1` is trusted (200 OK), `k2` is untrusted (403 Forbidden).
    assert_eq!(
        send_signed_bot_req(&mut tx, "k1", &kp1).await?.status(),
        StatusCode::OK
    );
    assert_eq!(
        send_signed_bot_req(&mut tx, "k2", &kp2).await?.status(),
        StatusCode::FORBIDDEN
    );

    // 2. Failed reload referencing `k2` MUST NOT mutate live keys!
    assert!(
        server
            .reload_from_str("bot-bad.kdl", &build_kdl("k2", &pub2_b64, true))
            .is_err()
    );
    assert_eq!(
        send_signed_bot_req(&mut tx, "k1", &kp1).await?.status(),
        StatusCode::OK
    );
    assert_eq!(
        send_signed_bot_req(&mut tx, "k2", &kp2).await?.status(),
        StatusCode::FORBIDDEN
    );

    // 3. Valid reload replacing `k1` with `k2` MUST immediately revoke `k1` (403) and trust `k2` (200)!
    server.reload_from_str("bot-v2.kdl", &build_kdl("k2", &pub2_b64, false))?;
    assert_eq!(
        send_signed_bot_req(&mut tx, "k1", &kp1).await?.status(),
        StatusCode::FORBIDDEN,
        "removed KDL bot key k1 MUST be immediately revoked after reload"
    );
    assert_eq!(
        send_signed_bot_req(&mut tx, "k2", &kp2).await?.status(),
        StatusCode::OK
    );

    conn_task.abort();
    server.shutdown().await;
    Ok(())
}

/// R3-PUB-4: Publish JWT `aud` and Ed25519 request binding MUST use the immutable configured
/// canonical site identifier (`site.hosts[0]`), NEVER reflecting the client-controlled `Host`
/// header on wildcard (`*.example.test`) or single-site `localhost` fallback!
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn live_publish_wildcard_host_cannot_spoof_jwt_audience() -> TestResult {
    let tmp = TempDir::new("pub-aud-r3")?;
    let storage_dir = tmp.path.join("releases");
    let pubkey_path = tmp.path.join("deploy.pub");
    let deploy_key = Ed25519SigningKey::generate()?;
    fs::write(&pubkey_path, deploy_key.verifying_key().to_encoded())?;

    let tls_port = reserve_free_port()?;
    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
    tls {{
        min-version "1.3"
        pqc-hybrid #true
    }}
}}
site "*.example.test" {{
    ai-publish {{
        storage "{}"
        require-signature "ed25519:{}"
        mcp-endpoint "/_miraserve/publish" auth="oauth-jwt"
    }}
}}
"#,
        storage_dir.to_string_lossy().replace('\\', "/"),
        pubkey_path.to_string_lossy().replace('\\', "/"),
    );

    let (cfg, _) = parse_kdl("wild-pub.kdl", &kdl)?;
    let server = MiraServeServer::start(
        Arc::new(ConfigStore::new(cfg)),
        ServerOptions {
            dev_tls: true,
            ..ServerOptions::default()
        },
    )
    .await?;

    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|l| l.kind == ListenerKind::HttpsTcp)
        .ok_or("missing HTTPS listener")?
        .local_addr;
    let dev_pem = server
        .dev_cert_pem()
        .ok_or("missing dev cert PEM")?
        .to_owned();
    let mut roots = RootCertStore::empty();
    let srv_certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(dev_pem.as_bytes()).collect::<Result<_, _>>()?;
    let (added, _) = roots.add_parsable_certificates(srv_certs);
    assert_eq!(added, 1);
    let mut client_tls_cfg = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_tls_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let client_tls = Arc::new(client_tls_cfg);
    let (mut tx, conn_task) = connect_https(https_addr, "staging.example.test", client_tls).await?;

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let init_body = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize"
    }))?;

    // 1. Token issued for `staging.example.test` sent with `Host: staging.example.test` MUST fail (401)!
    let staging_tok = deploy_key.sign_oauth_jwt_with_audience(
        "ci",
        Some("staging.example.test"),
        now_unix + 300,
        Some("publish:read"),
    );
    let r_staging = tx
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("/_miraserve/publish")
                .header(HOST, "staging.example.test")
                .header(AUTHORIZATION, format!("Bearer {staging_tok}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(init_body.clone())))?,
        )
        .await?;
    assert_eq!(
        r_staging.status(),
        StatusCode::UNAUTHORIZED,
        "reflected wildcard Host must NOT satisfy JWT aud on *.example.test (R3-PUB-4)"
    );

    // 2. Token issued for `localhost` sent with `Host: localhost` (single-site fallback) MUST fail (401)!
    let local_tok = deploy_key.sign_oauth_jwt_with_audience(
        "ci",
        Some("localhost"),
        now_unix + 300,
        Some("publish:read"),
    );
    let r_local = tx
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("/_miraserve/publish")
                .header(HOST, "localhost")
                .header(AUTHORIZATION, format!("Bearer {local_tok}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(init_body.clone())))?,
        )
        .await?;
    assert_eq!(
        r_local.status(),
        StatusCode::UNAUTHORIZED,
        "single-site localhost Host fallback must NOT satisfy JWT aud (R3-PUB-4)"
    );

    // 3. Token issued for canonical configured site identifier `*.example.test` SUCCEEDS (200)!
    let canon_tok = deploy_key.sign_oauth_jwt_with_audience(
        "ci",
        Some("*.example.test"),
        now_unix + 300,
        Some("publish:read"),
    );
    let r_ok = tx
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("/_miraserve/publish")
                .header(HOST, "staging.example.test")
                .header(AUTHORIZATION, format!("Bearer {canon_tok}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(init_body)))?,
        )
        .await?;
    assert_eq!(r_ok.status(), StatusCode::OK);

    conn_task.abort();
    server.shutdown().await;
    Ok(())
}

/// Round 5 Wave 2 (`R5-PUB-2`) live TLS 1.3 mTLS end-to-end test using REAL CA-signed X.509
/// client certificates:
/// - A client cert with embedded comma `CN="laptop, CN=deploy-bot"` issued by the SAME `client-ca`
///   is REJECTED (`403 Forbidden`) on both `site_publish` and `site_rollback`!
/// - A legitimate client cert with full DN `O=Corp, CN=deploy-bot` SUCCEEDS (`200 OK`) on both
///   `site_publish` and `site_rollback`!
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn live_mtls_publish_enforces_rfc4514_full_dn_and_blocks_comma_spoof() -> TestResult {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    };
    use rustls::pki_types::PrivateKeyDer;

    let tmp = TempDir::new("mtls-r5-dn")?;
    let storage_dir = tmp.path.join("releases");
    let pubkey_path = tmp.path.join("deploy.pub");
    let ca_path = tmp.path.join("client-ca.pem");

    let deploy_key = Ed25519SigningKey::generate()?;
    fs::write(&pubkey_path, deploy_key.verifying_key().to_encoded())?;

    // Mint a real ECDSA CA certificate
    let mut ca_params = CertificateParams::new(Vec::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::OrganizationName, "Corp");
    ca_dn.push(DnType::CommonName, "Corp Client CA");
    ca_params.distinguished_name = ca_dn;
    let ca_key = KeyPair::generate()?;
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let ca_issuer = Issuer::new(ca_params, ca_key);
    fs::write(&ca_path, ca_cert.pem().as_bytes())?;

    // Mint spoofed client cert under the SAME CA: CN = "laptop, CN=deploy-bot"
    let mut spoof_params = CertificateParams::new(Vec::new())?;
    let mut spoof_dn = DistinguishedName::new();
    spoof_dn.push(DnType::OrganizationName, "Corp");
    spoof_dn.push(DnType::CommonName, "laptop, CN=deploy-bot");
    spoof_params.distinguished_name = spoof_dn;
    let spoof_key = KeyPair::generate()?;
    let spoof_cert = spoof_params.signed_by(&spoof_key, &ca_issuer)?;

    // Mint legitimate client cert under the SAME CA: O = "Corp", CN = "deploy-bot"
    let mut legit_params = CertificateParams::new(Vec::new())?;
    let mut legit_dn = DistinguishedName::new();
    legit_dn.push(DnType::OrganizationName, "Corp");
    legit_dn.push(DnType::CommonName, "deploy-bot");
    legit_params.distinguished_name = legit_dn;
    let legit_key = KeyPair::generate()?;
    let legit_cert = legit_params.signed_by(&legit_key, &ca_issuer)?;

    let tls_port = reserve_free_port()?;
    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
    tls {{
        min-version "1.3"
        pqc-hybrid #true
    }}
}}
site "dn-test.example.test" {{
    tls {{
        client-ca "{}"
    }}
    ai-publish {{
        storage "{}"
        site-id "dn-test.example.test"
        keep-versions 5
        require-signature "ed25519:{}"
        allowed-subjects "O=Corp, CN=deploy-bot"
        mcp-endpoint "/_miraserve/publish" auth="mtls"
    }}
}}
"#,
        ca_path.to_string_lossy().replace('\\', "/"),
        storage_dir.to_string_lossy().replace('\\', "/"),
        pubkey_path.to_string_lossy().replace('\\', "/"),
    );

    let (cfg, _) = parse_kdl("mtls-r5-dn.kdl", &kdl)?;
    let server = MiraServeServer::start(
        Arc::new(ConfigStore::new(cfg)),
        ServerOptions {
            dev_tls: true,
            ..ServerOptions::default()
        },
    )
    .await?;

    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::HttpsTcp)
        .ok_or("missing HTTPS listener")?
        .local_addr;
    let dev_pem = server.dev_cert_pem().ok_or("missing dev cert PEM")?;
    let mut srv_roots = RootCertStore::empty();
    let srv_certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(dev_pem.as_bytes()).collect::<Result<_, _>>()?;
    srv_roots.add_parsable_certificates(srv_certs);

    let make_mtls_client =
        |cert_pem: &str, key_pem: &str| -> Result<Arc<ClientConfig>, Box<dyn std::error::Error>> {
            let certs: Vec<CertificateDer<'static>> =
                CertificateDer::pem_slice_iter(cert_pem.as_bytes()).collect::<Result<_, _>>()?;
            let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())?;
            let mut cfg = ClientConfig::builder_with_provider(build_crypto_provider(true))
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_root_certificates(srv_roots.clone())
                .with_client_auth_cert(certs, key)?;
            cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
            Ok(Arc::new(cfg))
        };

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let make_publish_rpc = |html: &str, ts: u64| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let bundle = SiteBundle {
            files: BTreeMap::from([("index.html".to_owned(), html.as_bytes().to_vec())]),
            note: Some("mtls-test".to_owned()),
            created_at_unix: ts,
            site_id: Some("dn-test.example.test".to_owned()),
        };
        let signed = SignedBundle::sign(bundle, &deploy_key);
        Ok(serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "site_publish",
                "arguments": {
                    "files": { "index.html": html },
                    "note": "mtls-test",
                    "created_at_unix": ts,
                    "site_id": "dn-test.example.test",
                    "signature_b64": signed.signature_b64
                }
            }
        }))?)
    };
    let rollback_rpc = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": { "name": "site_rollback", "arguments": {} }
    }))?;

    // 1. Legitimate `O=Corp, CN=deploy-bot` publishes V1 and V2 cleanly!
    let legit_tls = make_mtls_client(&legit_cert.pem(), &legit_key.serialize_pem())?;
    let (mut legit_tx, legit_conn) =
        connect_https(https_addr, "dn-test.example.test", legit_tls).await?;
    for (html, ts) in [
        ("<h1>Live V1</h1>", now_unix - 10),
        ("<h1>Live V2</h1>", now_unix - 5),
    ] {
        let resp = legit_tx
            .send_request(
                Request::builder()
                    .method(Method::POST)
                    .uri("/_miraserve/publish")
                    .header(HOST, "dn-test.example.test")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from(make_publish_rpc(html, ts)?)))?,
            )
            .await?;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "legit mTLS cert must publish"
        );
    }

    // 2. Spoofed `CN="laptop, CN=deploy-bot"` under SAME CA is REJECTED (403) on BOTH publish and rollback!
    let spoof_tls = make_mtls_client(&spoof_cert.pem(), &spoof_key.serialize_pem())?;
    let (mut spoof_tx, spoof_conn) =
        connect_https(https_addr, "dn-test.example.test", spoof_tls).await?;
    let spoof_pub = spoof_tx
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("/_miraserve/publish")
                .header(HOST, "dn-test.example.test")
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(make_publish_rpc(
                    "<h1>PWNED</h1>",
                    now_unix - 1,
                )?)))?,
        )
        .await?;
    assert_eq!(
        spoof_pub.status(),
        StatusCode::FORBIDDEN,
        "comma-spoofed CN must be rejected with 403 on site_publish (R5-PUB-2)"
    );
    let spoof_rb = spoof_tx
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("/_miraserve/publish")
                .header(HOST, "dn-test.example.test")
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(rollback_rpc.clone())))?,
        )
        .await?;
    assert_eq!(
        spoof_rb.status(),
        StatusCode::FORBIDDEN,
        "comma-spoofed CN must be rejected with 403 on site_rollback (R5-PUB-2)"
    );
    spoof_conn.abort();

    // 3. Legitimate `O=Corp, CN=deploy-bot` rolls back V2 -> V1 cleanly (200 OK)!
    let legit_rb = legit_tx
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("/_miraserve/publish")
                .header(HOST, "dn-test.example.test")
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(rollback_rpc)))?,
        )
        .await?;
    assert_eq!(legit_rb.status(), StatusCode::OK);
    let live_get = legit_tx
        .send_request(
            Request::builder()
                .uri("/")
                .header(HOST, "dn-test.example.test")
                .body(Full::new(Bytes::new()))?,
        )
        .await?;
    let live_body = live_get.into_body().collect().await?.to_bytes();
    assert_eq!(live_body.as_ref(), b"<h1>Live V1</h1>");

    legit_conn.abort();
    server.shutdown().await;
    Ok(())
}

/// R7-SBX-1, R7-SBX-2 & R7-PUB-1 (Live reload parity):
/// 1. Reloading a site whose `root` now points at the running server's effective `--acme-dir`
///    MUST be rejected (`CoreError::UnsafeDocroot`) so ACME private keys are never served.
/// 2. Reloading a site whose `root` is a symlink to `/etc` MUST be rejected (`CoreError::UnsafeDocroot`).
/// 3. Planting a validly-signed preflight-rejected release (`<script>alert(1)</script>`) into an
///    `ai-publish` store's `releases/` and pointing `active.json` at it, then triggering a live
///    reload (`reload_from_str`, equivalent to `SIGHUP`), MUST refuse the planted release and keep
///    serving the prior compliant release!
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn r7_sbx_1_and_r7_pub_1_live_reload_enforces_acme_overlap_symlink_and_strict_preflight()
-> TestResult {
    let tmp = TempDir::new("r7-reload-parity")?;
    let www_dir = tmp.path.join("www");
    let acme_dir = tmp.path.join("acme-state");
    let pub_storage = tmp.path.join("pub-store");
    let ext_storage = tmp.path.join("ext-store");
    std::fs::create_dir_all(&www_dir)?;
    std::fs::create_dir_all(&acme_dir)?;
    std::fs::create_dir_all(&pub_storage)?;
    std::fs::write(www_dir.join("index.html"), b"<h1>Safe Root</h1>")?;
    std::fs::write(
        acme_dir.join("secret.bundle.pem"),
        b"-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----\n",
    )?;

    let deploy_key = Ed25519SigningKey::generate()?;
    let pubkey_path = tmp.path.join("deploy.pub");
    std::fs::write(&pubkey_path, deploy_key.verifying_key().to_encoded())?;

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let pub_cfg = miraserve_config::AiPublishConfig {
        storage: pub_storage.to_string_lossy().into_owned(),
        site_id: Some("pub-r7.example.test".to_owned()),
        keep_versions: 5,
        require_signature: Some(miraserve_config::SignatureRequirement {
            algorithm: miraserve_config::SignatureAlgorithm::Ed25519,
            public_key_path: pubkey_path.to_string_lossy().into_owned(),
        }),
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        preflight_checks: vec![
            miraserve_config::PreflightCheck::NoSecrets,
            miraserve_config::PreflightCheck::NoInlineScripts,
        ],
        mcp_endpoint: None,
    };
    let initial_store = miraserve_publish::ReleaseStore::open_for_site(
        pub_cfg,
        Some("pub-r7.example.test".to_owned()),
    )?;
    let good_bundle = SiteBundle {
        files: BTreeMap::from([(
            "index.html".to_owned(),
            b"<!doctype html><html><body><h1>Compliant Release</h1></body></html>".to_vec(),
        )]),
        note: Some("good".to_owned()),
        created_at_unix: now_unix.saturating_sub(10),
        site_id: Some("pub-r7.example.test".to_owned()),
    };
    let good_rel = initial_store.publish(&SignedBundle::sign(good_bundle, &deploy_key))?;

    let tls_port = reserve_free_port()?;
    let make_kdl = |static_root: &std::path::Path| -> String {
        format!(
            r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h1"
}}
site "static-r7.example.test" {{
    root "{}"
}}
site "pub-r7.example.test" {{
    ai-publish {{
        storage "{}"
        site-id "pub-r7.example.test"
        require-signature "ed25519:{}"
        preflight-checks "no-secrets" "no-inline-scripts"
    }}
}}
"#,
            static_root.to_string_lossy().replace('\\', "/"),
            pub_storage.to_string_lossy().replace('\\', "/"),
            pubkey_path.to_string_lossy().replace('\\', "/"),
        )
    };

    let initial_kdl = make_kdl(&www_dir);
    let (cfg, _) = parse_kdl("r7-initial.kdl", &initial_kdl)?;
    let server = MiraServeServer::start(
        Arc::new(ConfigStore::new(cfg)),
        ServerOptions {
            dev_tls: true,
            acme_state_dir: Some(acme_dir.clone()),
            ..ServerOptions::default()
        },
    )
    .await?;

    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|l| l.kind == ListenerKind::HttpsTcp)
        .ok_or("missing HTTPS listener")?
        .local_addr;
    let dev_pem = server
        .dev_cert_pem()
        .ok_or("missing dev cert PEM")?
        .to_owned();
    let mut roots = RootCertStore::empty();
    let srv_certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(dev_pem.as_bytes()).collect::<Result<_, _>>()?;
    let (added, _) = roots.add_parsable_certificates(srv_certs);
    assert_eq!(added, 1);
    let mut client_tls_cfg = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_tls_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let client_tls = Arc::new(client_tls_cfg);

    // 1. R7-SBX-1: Live reload pointing static site root at `--acme-dir` MUST BE REFUSED!
    let acme_overlap_kdl = make_kdl(&acme_dir);
    let reload_acme = server.reload_from_str("r7-acme-overlap.kdl", &acme_overlap_kdl);
    assert!(
        reload_acme.is_err(),
        "R7-SBX-1: reload overlapping effective --acme-dir MUST fail, got: {reload_acme:?}"
    );
    // Live server MUST continue serving original safe root, NOT ACME private keys!
    let (mut st_tx, st_conn) = connect_https(
        https_addr,
        "static-r7.example.test",
        Arc::clone(&client_tls),
    )
    .await?;
    let leak_probe = st_tx
        .send_request(
            Request::builder()
                .uri("/secret.bundle.pem")
                .header(HOST, "static-r7.example.test")
                .body(Full::new(Bytes::new()))?,
        )
        .await?;
    assert_eq!(
        leak_probe.status(),
        StatusCode::NOT_FOUND,
        "R7-SBX-1: ACME key must never be served after rejected reload"
    );
    st_conn.abort();

    // 2. R7-SBX-2: Live reload pointing static site root at symlink -> /etc MUST BE REFUSED!
    #[cfg(unix)]
    {
        let etc_link = tmp.path.join("etc-link");
        std::os::unix::fs::symlink("/etc", &etc_link)?;
        let sym_kdl = make_kdl(&etc_link);
        let reload_sym = server.reload_from_str("r7-sym-etc.kdl", &sym_kdl);
        assert!(
            reload_sym.is_err(),
            "R7-SBX-2: reload with symlink docroot -> /etc MUST fail, got: {reload_sym:?}"
        );
    }

    // 3. R7-PUB-1: Plant a validly-signed inline-script release into pub_storage/releases/ and
    //    point active.json at it, then trigger live reload (`SIGHUP` equivalent)!
    let ext_cfg = miraserve_config::AiPublishConfig {
        storage: ext_storage.to_string_lossy().into_owned(),
        site_id: Some("pub-r7.example.test".to_owned()),
        keep_versions: 3,
        require_signature: Some(miraserve_config::SignatureRequirement {
            algorithm: miraserve_config::SignatureAlgorithm::Ed25519,
            public_key_path: pubkey_path.to_string_lossy().into_owned(),
        }),
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        preflight_checks: vec![miraserve_config::PreflightCheck::NoSecrets],
        mcp_endpoint: None,
    };
    let ext_store = miraserve_publish::ReleaseStore::open_for_site(
        ext_cfg,
        Some("pub-r7.example.test".to_owned()),
    )?;
    let evil_bundle = SiteBundle {
        files: BTreeMap::from([(
            "index.html".to_owned(),
            b"<!doctype html><html><body><script>alert(1)</script></body></html>".to_vec(),
        )]),
        note: Some("evil".to_owned()),
        created_at_unix: now_unix.saturating_sub(5),
        site_id: Some("pub-r7.example.test".to_owned()),
    };
    let evil_rel = ext_store.publish(&SignedBundle::sign(evil_bundle, &deploy_key))?;
    let src = ext_storage.join("releases").join(&evil_rel.release_id);
    let dst = pub_storage.join("releases").join(&evil_rel.release_id);
    std::fs::create_dir_all(dst.join("public"))?;
    std::fs::copy(src.join("release.json"), dst.join("release.json"))?;
    std::fs::copy(src.join("public/index.html"), dst.join("public/index.html"))?;

    // Rewrite active.json to point at evil_rel (even forging an old scanner_version=1 in active.json!)
    let forged_active = json!({
        "active_release_id": evil_rel.release_id,
        "history": [good_rel.release_id, evil_rel.release_id],
        "max_created_at_unix": now_unix.saturating_sub(5),
        "verified_active": {
            "release_id": evil_rel.release_id,
            "manifest_sha256": evil_rel.manifest_sha256,
            "scanner_version": 1,
            "preflight_checks": ["no-secrets"]
        }
    });
    std::fs::write(
        pub_storage.join("active.json"),
        serde_json::to_vec_pretty(&forged_active)?,
    )?;

    // Reload (`SIGHUP` equivalent): MUST NEVER use lenient preflight, even with forged scanner_version=1!
    let _reload_gen = server.reload_from_str("r7-reload-pub.kdl", &initial_kdl)?;
    let (mut pub_tx, pub_conn) =
        connect_https(https_addr, "pub-r7.example.test", client_tls).await?;
    let pub_resp = pub_tx
        .send_request(
            Request::builder()
                .uri("/")
                .header(HOST, "pub-r7.example.test")
                .body(Full::new(Bytes::new()))?,
        )
        .await?;
    assert_eq!(pub_resp.status(), StatusCode::OK);
    let pub_body = String::from_utf8(pub_resp.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(
        pub_body.contains("Compliant Release") && !pub_body.contains("alert(1)"),
        "R7-PUB-1: live reload must reject planted preflight violation and serve compliant fallback, got: {pub_body}"
    );

    pub_conn.abort();
    server.shutdown().await;
    Ok(())
}

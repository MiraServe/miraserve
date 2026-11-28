//! Stage 2 (0.1.8) live-server reload security oracle.
//!
//! Proves that from a healthy running generation serving distinct sentinel content,
//! certificate, and signed active `ai-publish` release, submitting a candidate with
//! padded path values (trailing space or `app /.` resolved directory) via direct file
//! reload is refused with `E202` while preserving:
//! - the exact same config generation (`1`),
//! - the old HTTP static content,
//! - the old TLS leaf certificate DER bytes,
//! - the old active `ai-publish` content and `active.json`, and
//! - zero provisioning or activation of padded sibling directories.
//!
//! MUST fail on `441a58d` and pass on the 0.1.8 branch. Deterministic; no timing.

use std::fs;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::header::{ACCEPT, HOST};
use http::{Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper_util::rt::TokioIo;
use miraserve_config::{
    AiPublishConfig, ConfigError, ConfigStore, SignatureAlgorithm, SignatureRequirement,
    load_file_detailed,
};
use miraserve_core::{CoreError, ListenerKind, MiraServeServer, ServerOptions};
use miraserve_publish::{Ed25519SigningKey, ReleaseStore, SignedBundle, bundle_from_directory};
use miraserve_tls::build_crypto_provider;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const EXPECTED_HELP: &str = "verify which directory or file currently holds live data before editing the path; remove leading or trailing whitespace from the configured path";
const EXPECTED_RESOLVED_HELP: &str = "verify which directory or file currently holds live data before editing the path; remove trailing whitespace from the final directory component before any trailing slash or '.'";

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Result<Self, std::io::Error> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path =
            std::env::temp_dir().join(format!("ms-pws-core-{tag}-{}-{nanos}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
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

fn build_h1_tls_connector(cert_pems: &[&str]) -> Result<TlsConnector, Box<dyn std::error::Error>> {
    let mut roots = RootCertStore::empty();
    for cert_pem in cert_pems {
        let certs: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(cert_pem.as_bytes()).collect::<Result<_, _>>()?;
        roots.add_parsable_certificates(certs);
    }
    let mut client_cfg = ClientConfig::builder_with_provider(build_crypto_provider(false))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsConnector::from(Arc::new(client_cfg)))
}

async fn https_get_with_leaf_cert(
    addr: SocketAddr,
    connector: &TlsConnector,
    host: &str,
    path: &str,
) -> Result<(StatusCode, String, Vec<u8>), Box<dyn std::error::Error>> {
    let tcp = TcpStream::connect(addr).await?;
    let tls = connector
        .connect(ServerName::try_from(host.to_owned())?, tcp)
        .await?;
    let leaf_der = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|c| c.as_ref().to_vec())
        .ok_or("expected server peer certificate")?;
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
    Ok((
        status,
        String::from_utf8_lossy(&body).into_owned(),
        leaf_der,
    ))
}

fn kdl_esc(path: &std::path::Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn security_failed_padded_reload_keeps_old_generation_http_cert_and_publish_state()
-> TestResult {
    let tmp = TempDir::new("reload")?;
    let conf_dir = tmp.path.join("conf");
    let certs_dir = tmp.path.join("certs");
    let web_unpadded = tmp.path.join("web");
    let web_padded = tmp.path.join("web ");
    let store_unpadded = tmp.path.join("store");
    let store_padded = tmp.path.join("store ");
    let store_new_padded = tmp.path.join("store-new "); // intentionally NOT created
    let src_v1 = tmp.path.join("bundle-v1");
    let src_padded = tmp.path.join("bundle-padded");

    for d in [
        &conf_dir,
        &certs_dir,
        &web_unpadded,
        &store_unpadded,
        &src_v1,
        &src_padded,
    ] {
        fs::create_dir_all(d)?;
    }

    // Distinct harmless sentinel content in unpadded vs padded static roots.
    fs::write(web_unpadded.join("index.html"), b"OLD-STATIC-V1")?;
    #[cfg(unix)]
    {
        fs::create_dir_all(&web_padded)?;
        fs::create_dir_all(&store_padded)?;
        fs::write(web_padded.join("index.html"), b"PADDED-STATIC-SENTINEL")?;
    }

    // Distinct Ed25519 signing key + distinct signed releases in `store` vs `store `.
    let signing_key = Ed25519SigningKey::generate()?;
    let pub_key_path = certs_dir.join("deploy.pub");
    fs::write(&pub_key_path, signing_key.verifying_key().to_encoded())?;

    fs::write(src_v1.join("index.html"), b"OLD-PUBLISH-V1")?;
    fs::write(src_padded.join("index.html"), b"PADDED-PUBLISH-SENTINEL")?;

    let stores_to_seed: Vec<(&PathBuf, &PathBuf, &str)> = {
        #[cfg(unix)]
        {
            vec![
                (&store_unpadded, &src_v1, "v1-unpadded"),
                (&store_padded, &src_padded, "padded-sibling"),
            ]
        }
        #[cfg(not(unix))]
        {
            vec![(&store_unpadded, &src_v1, "v1-unpadded")]
        }
    };
    for (store_dir, src_dir, note) in stores_to_seed {
        let mut bundle = bundle_from_directory(src_dir, Some(note.to_owned()))?;
        bundle.site_id = Some("pub.example".to_owned());
        let signed = SignedBundle::sign(bundle, &signing_key);
        let pub_cfg = AiPublishConfig {
            storage: store_dir.to_string_lossy().into_owned(),
            site_id: Some("pub.example".to_owned()),
            keep_versions: 5,
            require_signature: Some(SignatureRequirement {
                algorithm: SignatureAlgorithm::Ed25519,
                public_key_path: pub_key_path.to_string_lossy().into_owned(),
            }),
            jwt_public_key: None,
            jwt_issuer: None,
            allowed_subjects: Vec::new(),
            preflight_checks: Vec::new(),
            mcp_endpoint: None,
        };
        let store = ReleaseStore::open_for_site(pub_cfg, Some("pub.example".to_owned()))?;
        store.publish(&signed)?;
    }

    let active_v1_before = fs::read(store_unpadded.join("active.json"))?;
    #[cfg(unix)]
    let active_padded_before = fs::read(store_padded.join("active.json"))?;

    // Two distinct TLS certificates (cert-1 for gen 0, cert-2 offered only by rejected candidates).
    let provider = build_crypto_provider(false);
    let (_, cert1_pem) = miraserve_tls::generate_dev_certificate(
        &["static.example".to_owned(), "pub.example".to_owned()],
        &provider,
    )?;
    let (_, cert2_pem) = miraserve_tls::generate_dev_certificate(
        &[
            "static.example".to_owned(),
            "pub.example".to_owned(),
            "candidate-only.example".to_owned(),
        ],
        &provider,
    )?;
    let cert1_path = certs_dir.join("cert1.pem");
    let key1_path = certs_dir.join("key1.pem");
    let cert2_path = certs_dir.join("cert2.pem");
    let key2_path = certs_dir.join("key2.pem");
    fs::write(&cert1_path, &cert1_pem.cert_pem)?;
    fs::write(&key1_path, &cert1_pem.key_pem)?;
    fs::write(&cert2_path, &cert2_pem.cert_pem)?;
    fs::write(&key2_path, &cert2_pem.key_pem)?;

    let expected_cert1_der = CertificateDer::pem_slice_iter(cert1_pem.cert_pem.as_bytes())
        .next()
        .ok_or("missing cert1 DER")??
        .as_ref()
        .to_vec();
    let cert2_der = CertificateDer::pem_slice_iter(cert2_pem.cert_pem.as_bytes())
        .next()
        .ok_or("missing cert2 DER")??
        .as_ref()
        .to_vec();
    assert_ne!(expected_cert1_der, cert2_der, "test certs must be distinct");

    let live_cfg_path = conf_dir.join("live.kdl");
    let mut started: Option<(miraserve_core::RunningServer, u16)> = None;
    for _ in 0..16 {
        let port = reserve_free_port()?;
        let live_kdl = format!(
            "server {{\n\
                 listen \"127.0.0.1:{port}\" protocols=\"h1\"\n\
                 tls {{\n\
                     cert \"{cert1}\"\n\
                     key \"{key1}\"\n\
                 }}\n\
             }}\n\
             site \"static.example\" {{\n\
                 root \"{web}\"\n\
             }}\n\
             site \"pub.example\" {{\n\
                 ai-publish {{\n\
                     storage \"{store}\"\n\
                     site-id \"pub.example\"\n\
                     require-signature \"ed25519:{pubk}\"\n\
                 }}\n\
             }}\n",
            cert1 = kdl_esc(&cert1_path),
            key1 = kdl_esc(&key1_path),
            web = kdl_esc(&web_unpadded),
            store = kdl_esc(&store_unpadded),
            pubk = kdl_esc(&pub_key_path),
        );
        fs::write(&live_cfg_path, &live_kdl)?;
        let loaded = load_file_detailed(&live_cfg_path)?;
        let opts = ServerOptions {
            config_path: Some(live_cfg_path.clone()),
            apply_sandbox: false,
            ..ServerOptions::default()
        };
        match MiraServeServer::start(Arc::new(ConfigStore::new(loaded.config)), opts).await {
            Ok(srv) => {
                started = Some((srv, port));
                break;
            }
            Err(CoreError::Bind { source, .. })
                if source.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(err) => return Err(err.into()),
        }
    }
    let (server, port) = started.ok_or("failed to bind live server")?;
    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|l| l.kind == ListenerKind::HttpsTcp)
        .map(|l| l.local_addr)
        .ok_or("expected HTTPS listener")?;
    let connector = build_h1_tls_connector(&[&cert1_pem.cert_pem, &cert2_pem.cert_pem])?;

    // Baseline check: generation 1 serves cert-1, OLD-STATIC-V1, and OLD-PUBLISH-V1.
    assert_eq!(server.config_store().generation(), 1);
    let (st1, body1, leaf1) =
        https_get_with_leaf_cert(https_addr, &connector, "static.example", "/").await?;
    assert_eq!(st1, StatusCode::OK);
    assert_eq!(body1, "OLD-STATIC-V1");
    assert_eq!(leaf1, expected_cert1_der);

    let (st2, body2, leaf2) =
        https_get_with_leaf_cert(https_addr, &connector, "pub.example", "/").await?;
    assert_eq!(st2, StatusCode::OK);
    assert_eq!(body2, "OLD-PUBLISH-V1");
    assert_eq!(leaf2, expected_cert1_der);

    // Candidate A: direct file reload switching to cert-2, padded static root, and padded store!
    let padded_cand_path = conf_dir.join("candidate-padded.kdl");
    let padded_cand_kdl = format!(
        "server {{\n\
             listen \"127.0.0.1:{port}\" protocols=\"h1\"\n\
             tls {{\n\
                 cert \"{cert2}\"\n\
                 key \"{key2}\"\n\
             }}\n\
         }}\n\
         site \"static.example\" {{\n\
             root \"{web_pad}\"\n\
         }}\n\
         site \"pub.example\" {{\n\
             ai-publish {{\n\
                 storage \"{store_pad}\"\n\
                 site-id \"pub.example\"\n\
                 require-signature \"ed25519:{pubk}\"\n\
             }}\n\
         }}\n",
        cert2 = kdl_esc(&cert2_path),
        key2 = kdl_esc(&key2_path),
        web_pad = kdl_esc(&web_padded),
        store_pad = kdl_esc(&store_padded),
        pubk = kdl_esc(&pub_key_path),
    );
    fs::write(&padded_cand_path, &padded_cand_kdl)?;

    let err_a = match server.reload_from_file(&padded_cand_path) {
        Ok(gen_id) => {
            server.shutdown().await;
            return Err(format!(
                "padded reload MUST be refused, but committed generation {gen_id}"
            )
            .into());
        }
        Err(e) => e,
    };
    match err_a {
        CoreError::Config(ConfigError::Validation { errors, .. }) => {
            let [e0, e1] = errors.as_slice() else {
                server.shutdown().await;
                return Err(format!("expected 2 E202 errors: {errors:#?}").into());
            };
            assert_eq!(e0.code, "E202");
            assert_eq!(e0.path.as_deref(), Some("site[0].root"));
            assert_eq!(
                e0.message,
                "site 'root' path on site 'static.example' ends with whitespace (U+0020)"
            );
            assert_eq!(e0.help.as_deref(), Some(EXPECTED_HELP));
            assert_eq!(e1.code, "E202");
            assert_eq!(e1.path.as_deref(), Some("site[1].ai-publish.storage"));
            assert_eq!(
                e1.message,
                "ai-publish 'storage' path on site 'pub.example' ends with whitespace (U+0020)"
            );
            assert_eq!(e1.help.as_deref(), Some(EXPECTED_HELP));
        }
        other => {
            server.shutdown().await;
            return Err(format!("expected CoreError::Config(Validation), got: {other:?}").into());
        }
    }

    // Candidate A2: string reload of the same padded candidate is likewise refused.
    match server.reload_from_str("candidate-padded.kdl", &padded_cand_kdl) {
        Ok(gen_id) => {
            server.shutdown().await;
            return Err(format!(
                "padded reload_from_str MUST be refused, but committed generation {gen_id}"
            )
            .into());
        }
        Err(CoreError::Config(ConfigError::Validation { errors, .. })) => {
            let [a0, a1] = errors.as_slice() else {
                server.shutdown().await;
                return Err(format!("expected 2 E202 errors: {errors:#?}").into());
            };
            assert_eq!(a0.code, "E202");
            assert_eq!(a1.code, "E202");
        }
        Err(other) => {
            server.shutdown().await;
            return Err(format!("expected CoreError::Config(Validation), got: {other:?}").into());
        }
    }

    // Candidate B: direct file reload with non-existent padded store AND relative `app /.`!
    let resolved_cand_path = conf_dir.join("candidate-resolved.kdl");
    let resolved_cand_kdl = format!(
        "server {{\n\
             listen \"127.0.0.1:{port}\" protocols=\"h1\"\n\
             tls {{\n\
                 cert \"{cert2}\"\n\
                 key \"{key2}\"\n\
             }}\n\
         }}\n\
         site \"static.example\" {{\n\
             root \"pub /.\"\n\
         }}\n\
         site \"pub.example\" {{\n\
             ai-publish {{\n\
                 storage \"{store_new}\"\n\
                 site-id \"pub.example\"\n\
                 require-signature \"ed25519:{pubk}\"\n\
             }}\n\
         }}\n",
        cert2 = kdl_esc(&cert2_path),
        key2 = kdl_esc(&key2_path),
        store_new = kdl_esc(&store_new_padded),
        pubk = kdl_esc(&pub_key_path),
    );
    fs::write(&resolved_cand_path, &resolved_cand_kdl)?;

    let err_b = match server.reload_from_file(&resolved_cand_path) {
        Ok(gen_id) => {
            server.shutdown().await;
            return Err(format!(
                "resolved-dir padded reload MUST be refused, but committed generation {gen_id}"
            )
            .into());
        }
        Err(e) => e,
    };
    match err_b {
        CoreError::Config(ConfigError::Validation { errors, .. }) => {
            // Parser emits source-value E202s before `resolve_relative_dir_paths` emits
            // resolved-directory E202s, so `site[1].ai-publish.storage` precedes `site[0].root`.
            let [e0, e1] = errors.as_slice() else {
                server.shutdown().await;
                return Err(format!("expected 2 E202 errors: {errors:#?}").into());
            };
            assert_eq!(e0.code, "E202");
            assert_eq!(e0.path.as_deref(), Some("site[1].ai-publish.storage"));
            assert_eq!(
                e0.message,
                "ai-publish 'storage' path on site 'pub.example' ends with whitespace (U+0020)"
            );
            assert_eq!(e0.help.as_deref(), Some(EXPECTED_HELP));
            assert!(e0.location.is_some());
            assert_eq!(e1.code, "E202");
            assert_eq!(e1.path.as_deref(), Some("site[0].root"));
            assert_eq!(
                e1.message,
                "site 'root' resolved directory name on site 'static.example' ends with whitespace (U+0020)"
            );
            assert_eq!(e1.help.as_deref(), Some(EXPECTED_RESOLVED_HELP));
            assert!(e1.location.is_some());
        }
        other => {
            server.shutdown().await;
            return Err(format!("expected CoreError::Config(Validation), got: {other:?}").into());
        }
    }

    // Verify generation is STILL 1, old static content, old TLS cert DER, old active publish
    // content/state, and neither `store-new ` nor `conf/pub ` was provisioned!
    assert_eq!(
        server.config_store().generation(),
        1,
        "failed reload must not increment config generation"
    );

    let (st3, body3, leaf3) =
        https_get_with_leaf_cert(https_addr, &connector, "static.example", "/").await?;
    assert_eq!(st3, StatusCode::OK);
    assert_eq!(body3, "OLD-STATIC-V1");
    assert_eq!(leaf3, expected_cert1_der);

    let (st4, body4, leaf4) =
        https_get_with_leaf_cert(https_addr, &connector, "pub.example", "/").await?;
    assert_eq!(st4, StatusCode::OK);
    assert_eq!(body4, "OLD-PUBLISH-V1");
    assert_eq!(leaf4, expected_cert1_der);

    assert_eq!(
        fs::read(store_unpadded.join("active.json"))?,
        active_v1_before
    );
    #[cfg(unix)]
    assert_eq!(
        fs::read(store_padded.join("active.json"))?,
        active_padded_before
    );
    #[cfg(unix)]
    {
        assert!(
            !store_new_padded.exists(),
            "rejected reload must not create '{}'",
            store_new_padded.display()
        );
        assert!(!conf_dir.join("pub ").exists());
    }

    server.shutdown().await;
    Ok(())
}

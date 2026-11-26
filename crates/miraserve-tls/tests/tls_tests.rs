//! Integration tests for `miraserve-tls`: live PQC TLS 1.3 (`X25519MLKEM768`) handshake,
//! TLS 1.2 rejection vs per-site `compat-tls-1-2`, SNI wildcard resolution, dev cert
//! inspection, and RFC 8737 TLS-ALPN-01 challenge routing.

// `assert_is_empty` is new in clippy 1.100 and unknown to 1.95 (the minimum toolchain).
// `assert!(x.is_empty())` says what these tests mean.
#![allow(unknown_lints, clippy::assert_is_empty)]

use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use miraserve_config::{Protocol, parse_kdl};
use miraserve_tls::{
    ACME_TLS_ALPN_PROTOCOL, AcmeChallengeStore, DynamicCertResolver, TlsConfigSet,
    build_crypto_provider, build_tls_alpn_01_cert, compute_ari_renewal_delay,
    generate_dev_certificate, inspect_cert_pem, populate_resolver_from_config,
};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, NamedGroup, ProtocolVersion, RootCertStore};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_rustls::{TlsAcceptor, TlsConnector};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn live_tls13_negotiates_x25519mlkem768_pqc_hybrid_and_rejects_tls12() -> TestResult {
    let provider = build_crypto_provider(true);
    let acme = Arc::new(AcmeChallengeStore::new());
    let resolver = Arc::new(DynamicCertResolver::new(acme));
    let (cert_key, dev_pem) =
        generate_dev_certificate(&["pqc.example.test".to_owned()], &provider)?;
    resolver.set_default(cert_key);

    let tls_set = TlsConfigSet::build(Arc::clone(&resolver), &[Protocol::H2, Protocol::H1])?;

    // Build root store trusting our self-signed dev cert.
    let mut roots = RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(dev_pem.cert_pem.as_bytes()).collect::<Result<_, _>>()?;
    let (added, _) = roots.add_parsable_certificates(certs);
    assert_eq!(added, 1);

    // 1. PQC-capable TLS 1.3 client MUST negotiate TLS 1.3 + X25519MLKEM768 + h2.
    let mut pqc_client = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    pqc_client.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let (client_io, server_io) = tokio::io::duplex(16 * 1024);
    let acceptor = TlsAcceptor::from(Arc::clone(&tls_set.tls13_pqc));
    let connector = TlsConnector::from(Arc::new(pqc_client));
    let sni = ServerName::try_from("pqc.example.test")?;

    let server_task = tokio::spawn(async move {
        let mut tls = acceptor.accept(server_io).await?;
        let mut buf = [0_u8; 4];
        tls.read_exact(&mut buf).await?;
        tls.write_all(b"pong").await?;
        tls.shutdown().await?;
        Ok::<_, std::io::Error>(buf)
    });

    let mut client_tls = connector.connect(sni.clone(), client_io).await?;
    let (_, conn) = client_tls.get_ref();
    assert_eq!(conn.protocol_version(), Some(ProtocolVersion::TLSv1_3));
    assert_eq!(conn.alpn_protocol(), Some(b"h2".as_slice()));
    let kx = conn
        .negotiated_key_exchange_group()
        .ok_or("missing negotiated key exchange group")?;
    assert_eq!(
        kx.name(),
        NamedGroup::X25519MLKEM768,
        "expected X25519MLKEM768 PQC hybrid key exchange, got {:?}",
        kx.name()
    );

    client_tls.write_all(b"ping").await?;
    let mut reply = [0_u8; 4];
    client_tls.read_exact(&mut reply).await?;
    assert_eq!(&reply, b"pong");
    assert_eq!(&server_task.await??, b"ping");

    // 2. TLS 1.2-only client MUST be rejected by tls13_pqc.
    let tls12_only_client = ClientConfig::builder_with_provider(build_crypto_provider(false))
        .with_protocol_versions(&[&rustls::version::TLS12])?
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    let (client_io_2, server_io_2) = tokio::io::duplex(16 * 1024);
    let acceptor_strict = TlsAcceptor::from(Arc::clone(&tls_set.tls13_pqc));
    let connector_12 = TlsConnector::from(Arc::new(tls12_only_client.clone()));
    let srv_reject = tokio::spawn(async move { acceptor_strict.accept(server_io_2).await });
    let cli_reject = connector_12.connect(sni.clone(), client_io_2).await;
    assert!(
        cli_reject.is_err(),
        "TLS 1.2 client must fail against tls13_pqc"
    );
    assert!(srv_reject.await?.is_err());

    // 3. TLS 1.2-only client MUST succeed against tls12_pqc (per-site compat-tls-1-2).
    let (client_io_3, server_io_3) = tokio::io::duplex(16 * 1024);
    let acceptor_compat = TlsAcceptor::from(Arc::clone(&tls_set.tls12_pqc));
    let connector_12_ok = TlsConnector::from(Arc::new(tls12_only_client));
    let srv_ok = tokio::spawn(async move { acceptor_compat.accept(server_io_3).await });
    let cli_ok = connector_12_ok.connect(sni, client_io_3).await?;
    assert_eq!(
        cli_ok.get_ref().1.protocol_version(),
        Some(ProtocolVersion::TLSv1_2)
    );
    assert!(srv_ok.await?.is_ok());

    Ok(())
}

#[test]
fn per_site_tls_selection_and_wildcard_sni_resolution() -> TestResult {
    let kdl = r#"
server {
    listen ":443" protocols="h3,h2,h1"
    tls {
        min-version "1.3"
        pqc-hybrid true
    }
}
site "strict.example.com" {
    root "/var/www/strict"
}
site "legacy.example.com" {
    tls {
        compat-tls-1-2 true
        pqc-hybrid false
    }
    root "/var/www/legacy"
}
"#;
    let (cfg, _) = parse_kdl("sni.kdl", kdl)?;
    let acme = Arc::new(AcmeChallengeStore::new());
    let resolver = Arc::new(DynamicCertResolver::new(Arc::clone(&acme)));
    let dev_pem = populate_resolver_from_config(&resolver, &cfg, true)?
        .ok_or("expected dev cert generation")?;

    // Verify cert inspection extracts SANs cleanly.
    let info = inspect_cert_pem(dev_pem.cert_pem.as_bytes())?;
    assert_eq!(info.chain_len, 1);
    assert!(info.sans.iter().any(|s| s == "strict.example.com"));
    assert!(info.sans.iter().any(|s| s == "legacy.example.com"));
    assert!(info.sans.iter().any(|s| s == "localhost"));

    // Verify per-site handshake selection.
    let tls_set = TlsConfigSet::build(Arc::clone(&resolver), &[Protocol::H2, Protocol::H1])?;
    let strict_cfg = tls_set.select_for_handshake(&cfg, Some("strict.example.com"), &[b"h2"]);
    assert!(Arc::ptr_eq(&strict_cfg, &tls_set.tls13_pqc));

    let legacy_cfg = tls_set.select_for_handshake(&cfg, Some("legacy.example.com"), &[b"http/1.1"]);
    assert!(Arc::ptr_eq(&legacy_cfg, &tls_set.tls12_classical));

    // Verify ACME TLS-ALPN-01 challenge cert generation and routing priority.
    let provider = build_crypto_provider(true);
    let challenge_cert = build_tls_alpn_01_cert("strict.example.com", &[0xAB_u8; 32], &provider)?;
    acme.set_alpn_cert("strict.example.com", challenge_cert);
    let alpn_cfg =
        tls_set.select_for_handshake(&cfg, Some("strict.example.com"), &[ACME_TLS_ALPN_PROTOCOL]);
    assert!(Arc::ptr_eq(&alpn_cfg, &tls_set.acme_alpn));

    // Wildcard lookup
    let (wild_cert, _) = generate_dev_certificate(&["*.wild.test".to_owned()], &provider)?;
    resolver.upsert_host("*.wild.test", Arc::clone(&wild_cert));
    let matched_cert = resolver
        .lookup_host("api.wild.test")
        .ok_or("expected wildcard cert match")?;
    assert!(Arc::ptr_eq(&matched_cert, &wild_cert));

    Ok(())
}

#[test]
fn ari_renewal_delay_targets_window_midpoint() -> TestResult {
    let json = r#"{
        "suggestedWindow": {
            "start": "2030-01-01T00:00:00Z",
            "end": "2030-01-03T00:00:00Z"
        }
    }"#;
    let info: instant_acme::RenewalInfo = serde_json::from_str(json)?;
    // Reference timestamp: 2029-12-31T00:00:00Z (525,936 hours since epoch)
    // Window midpoint: 2030-01-02T00:00:00Z -> delta = 48h
    let now = UNIX_EPOCH + Duration::from_hours(525_936);
    let delay = compute_ari_renewal_delay(&info, now);
    assert_eq!(delay, Duration::from_hours(48));

    // Past window midpoint -> immediate renewal (Duration::ZERO)
    let after = UNIX_EPOCH + Duration::from_hours(526_008);
    assert_eq!(compute_ari_renewal_delay(&info, after), Duration::ZERO);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn split_privilege_keyd_signs_live_pqc_tls13_handshake_and_blocks_oracle_abuse() -> TestResult
{
    use miraserve_tls::{KeydClient, KeydEndpoint, KeydKeyStore, KeydServer};
    use rustls::SignatureScheme;
    use rustls::pki_types::pem::PemObject as _;
    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::{ClientConfig, RootCertStore};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    let provider = build_crypto_provider(true);
    let (real_ck, pem) = generate_dev_certificate(&["split.example.test".to_owned()], &provider)?;

    // 1. Place the real private key ONLY inside the isolated keyd vault.
    let mut keyd_store = KeydKeyStore::new();
    keyd_store.insert_certified_key(
        "split-default",
        vec!["split.example.test".to_owned()],
        true,
        real_ck,
    )?;

    let keyd = KeydServer::start(
        KeydEndpoint::LoopbackTcp("127.0.0.1:0".parse()?),
        keyd_store,
        false,
    )
    .await?;

    // 2. Unauthenticated TCP client MUST be rejected by LoopbackTcp HMAC-SHA256 guard!
    let unauth_client = KeydClient::new(keyd.endpoint().clone());
    assert!(unauth_client.load_remote_certified_keys().is_err());

    let wrong_secret_client = KeydClient::with_auth_secret(keyd.endpoint().clone(), [0xEE_u8; 32]);
    assert!(wrong_secret_client.load_remote_certified_keys().is_err());

    // 2b. Authenticated worker connects via IPC and loads ONLY public certs + RemoteSigningKey handles.
    let secret = keyd
        .auth_secret()
        .ok_or("expected LoopbackTcp keyd to have an auth secret")?;
    let worker_client = KeydClient::with_auth_secret(keyd.endpoint().clone(), secret);
    let worker_resolver = Arc::new(DynamicCertResolver::new(Arc::new(
        miraserve_tls::AcmeChallengeStore::new(),
    )));
    let loaded = worker_client.populate_resolver(&worker_resolver)?;
    assert!(loaded >= 1);

    let tls_set = TlsConfigSet::build(worker_resolver, &[Protocol::H2, Protocol::H1])?;
    let acceptor = TlsAcceptor::from(Arc::clone(&tls_set.tls13_pqc));

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let srv_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        let mut tls = acceptor.accept(tcp).await?;
        tls.write_all(b"split-keyd-ok").await?;
        tls.shutdown().await?;
        Ok::<(), std::io::Error>(())
    });

    // 3. Client completes a real TLS 1.3 + X25519MLKEM768 handshake signed remotely by keyd!
    let mut roots = RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(pem.cert_pem.as_bytes()).collect::<Result<_, _>>()?;
    let (added, _) = roots.add_parsable_certificates(certs);
    assert_eq!(added, 1);

    let client_cfg = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_cfg));

    let tcp = TcpStream::connect(addr).await?;
    let client_res = connector
        .connect(ServerName::try_from("split.example.test")?, tcp)
        .await;
    let srv_res = srv_task.await?;
    srv_res.map_err(|e| format!("server accept failed: {e}"))?;
    let mut client_tls = client_res?;

    let (_, conn) = client_tls.get_ref();
    let kex = conn
        .negotiated_key_exchange_group()
        .ok_or("missing negotiated KEX group")?;
    assert_eq!(kex.name(), rustls::NamedGroup::X25519MLKEM768);

    let mut reply = Vec::new();
    client_tls.read_to_end(&mut reply).await?;
    assert_eq!(reply, b"split-keyd-ok");
    assert_eq!(keyd.signatures_served(), 1);

    // 4. Anti-oracle check (Threat Model T2): arbitrary non-TLS-1.3 payload MUST be refused!
    let oracle_attempt = worker_client.request_signature(
        "split-default",
        SignatureScheme::ECDSA_NISTP256_SHA256,
        b"rogue-worker-chosen-message",
    );
    assert!(oracle_attempt.is_err());
    assert_eq!(keyd.signatures_served(), 1);

    keyd.shutdown().await;
    Ok(())
}

#[test]
fn ech_rfc9849_config_is_accepted_by_rustls_and_supports_hpke_and_rotation() -> TestResult {
    use miraserve_tls::EchRotationManager;
    use rustls::client::EchConfig;
    use rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;

    let mgr = EchRotationManager::new("edge.example.com", Duration::from_hours(1))?;
    let snap1 = mgr.public_snapshot()?;
    assert_eq!(snap1.active_config_id, 1);
    assert_eq!(snap1.retained_key_count, 1);
    assert!(snap1.dns_https_record.contains("edge.example.com."));
    assert!(snap1.dns_https_record.contains("alpn=\"h3,h2\""));
    assert!(snap1.dns_https_record.contains("ech=\""));

    // Prove byte-for-byte RFC 9849 compliance directly with rustls's ECH parser!
    let wire_list = mgr.active_ech_config_list()?;
    let _parsed_by_rustls = EchConfig::new(wire_list, ALL_SUPPORTED_SUITES)?;

    // Verify RFC 9180 HPKE seal/open round-trip on the active key.
    let active_v1 = mgr.active_entry();
    let (enc, ct) =
        active_v1.hpke_seal(b"tls ech\0", b"outer-ch", b"inner-sni:secret.example.com")?;
    let pt = active_v1.hpke_open(&enc, b"tls ech\0", b"outer-ch", &ct)?;
    assert_eq!(pt, b"inner-sni:secret.example.com");

    // Rotate to config_id = 2; verify config_id = 1 remains decryptable during DNS TTL grace window!
    let snap2 = mgr.rotate()?;
    assert_eq!(snap2.active_config_id, 2);
    assert_eq!(snap2.retained_key_count, 2);
    assert_ne!(snap1.ech_config_list_b64, snap2.ech_config_list_b64);

    let grace_v1 = mgr.lookup_key(1).ok_or("expected grace ECH key id 1")?;
    let pt_grace = grace_v1.hpke_open(&enc, b"tls ech\0", b"outer-ch", &ct)?;
    assert_eq!(pt_grace, b"inner-sni:secret.example.com");

    let wire_list_v2 = mgr.active_ech_config_list()?;
    let _parsed_v2 = EchConfig::new(wire_list_v2, ALL_SUPPORTED_SUITES)?;
    Ok(())
}

#[test]
fn tls_audit_regressions_alpn_isolation_domain_http01_and_tls12_ecdhe_guard() -> TestResult {
    // 1. Multi-ALPN ["h3", "acme-tls/1"] MUST NOT select acme_alpn (RFC 8737 §3 isolation)
    let kdl = r#"
server {
    listen ":443" protocols="h3,h2,h1"
}
site "acme.example.com" {
    root "/var/www/acme"
}
"#;
    let (cfg, _) = parse_kdl("alpn.kdl", kdl)?;
    let acme = Arc::new(AcmeChallengeStore::new());
    let resolver = Arc::new(DynamicCertResolver::new(Arc::clone(&acme)));
    let provider = build_crypto_provider(true);
    let challenge_cert = build_tls_alpn_01_cert("acme.example.com", &[0x55_u8; 32], &provider)?;
    acme.set_alpn_cert("acme.example.com", challenge_cert);

    let tls_set = TlsConfigSet::build(Arc::clone(&resolver), &[Protocol::H2, Protocol::H1])?;
    let multi_alpn = tls_set.select_for_handshake(
        &cfg,
        Some("acme.example.com"),
        &[b"h3", ACME_TLS_ALPN_PROTOCOL],
    );
    assert!(
        Arc::ptr_eq(&multi_alpn, &tls_set.tls13_pqc),
        "mixed ALPN must NOT select acme_alpn"
    );
    let sole_alpn =
        tls_set.select_for_handshake(&cfg, Some("acme.example.com"), &[ACME_TLS_ALPN_PROTOCOL]);
    assert!(Arc::ptr_eq(&sole_alpn, &tls_set.acme_alpn));

    // 2. HTTP-01 tokens are strictly domain-scoped (borrowed `has_http01_token` + `get_http01_token`)
    assert!(!acme.has_http01_token("acme.example.com", "tok123"));
    assert_eq!(acme.get_http01_token("acme.example.com", "tok123"), None);
    acme.set_http01_token("acme.example.com", "tok123", "tok123.thumb".to_owned());
    assert!(acme.has_http01_token("acme.example.com", "tok123"));
    assert!(acme.has_http01_token("ACME.EXAMPLE.COM", "tok123"));
    assert!(!acme.has_http01_token("acme.example.com", "other_tok"));
    assert!(!acme.has_http01_token("evil.example.com", "tok123"));
    assert_eq!(
        acme.get_http01_token("acme.example.com", "tok123")
            .as_deref(),
        Some("tok123.thumb")
    );
    assert_eq!(
        acme.get_http01_token("ACME.EXAMPLE.COM", "tok123")
            .as_deref(),
        Some("tok123.thumb")
    );
    assert_eq!(acme.get_http01_token("evil.example.com", "tok123"), None);
    acme.clear_http01_token("ACME.EXAMPLE.COM", "tok123");
    assert!(!acme.has_http01_token("acme.example.com", "tok123"));
    assert_eq!(acme.get_http01_token("acme.example.com", "tok123"), None);

    // 3. TLS 1.2 anti-oracle helper accepts valid RFC 8422 ECDHE X25519 SKE and rejects arbitrary text
    let mut valid_ske = vec![0xAA_u8; 64]; // client_random + server_random
    valid_ske.extend_from_slice(&[0x03, 0x00, 0x1d, 32]); // named_curve X25519 len=32
    valid_ske.extend_from_slice(&[0xBB_u8; 32]);
    assert!(miraserve_tls::is_tls12_ecdhe_server_key_exchange(
        &valid_ske
    ));
    assert!(!miraserve_tls::is_tls12_ecdhe_server_key_exchange(
        b"arbitrary-oracle-payload"
    ));

    // 4. ECH rejects invalid DNS names with DNS zone-injection characters
    assert!(miraserve_tls::EchRotationManager::new("bad\"name", Duration::from_hours(1)).is_err());

    Ok(())
}

/// R2-KEYD-1: Unauthenticated stalled TCP connections must NOT starve authenticated workers
/// (pre-auth slots are strictly isolated from the 128-slot authenticated signing pool).
#[tokio::test]
async fn keyd_tcp_preauth_flood_does_not_starve_authenticated_workers() -> TestResult {
    let provider = build_crypto_provider(true);
    let (ck, _pem) = generate_dev_certificate(&["keyd-flood.example.test".to_owned()], &provider)?;
    let mut store = miraserve_tls::KeydKeyStore::new();
    store.insert_certified_key(
        "flood-key",
        vec!["keyd-flood.example.test".to_owned()],
        true,
        ck,
    )?;

    let secret = miraserve_tls::generate_keyd_auth_secret()?;
    let addr: std::net::SocketAddr = "127.0.0.1:0".parse()?;
    let running = miraserve_tls::KeydServer::start_with_auth(
        miraserve_tls::KeydEndpoint::LoopbackTcp(addr),
        store,
        false,
        Some(secret.clone()),
    )
    .await?;

    let bound_addr = match running.endpoint() {
        miraserve_tls::KeydEndpoint::LoopbackTcp(sa) => *sa,
        #[cfg(unix)]
        miraserve_tls::KeydEndpoint::Unix(_) => return Err("expected LoopbackTcp".into()),
    };

    // Open 15 stalled unauthenticated TCP peers that never reply to the HMAC challenge,
    // leaving 1 pre-auth slot free while verifying main pool isn't exhausted.
    let mut stalled = Vec::new();
    for _ in 0..15 {
        stalled.push(tokio::net::TcpStream::connect(bound_addr).await?);
    }

    // Authenticated worker connects cleanly and loads remote keys!
    let client = miraserve_tls::KeydClient::with_auth_secret(
        miraserve_tls::KeydEndpoint::LoopbackTcp(bound_addr),
        *secret,
    );
    let bundle = tokio::task::spawn_blocking(move || client.load_remote_certified_keys()).await??;
    assert!(bundle.default_cert.is_some());

    // Even if all 16 pre-auth slots are saturated, the 1s pre-auth deadline clears them rapidly
    // and an authenticated worker recovers within 2s (never blocked for 5s!).
    stalled.push(tokio::net::TcpStream::connect(bound_addr).await?);
    tokio::time::sleep(Duration::from_millis(1250)).await;
    let client2 = miraserve_tls::KeydClient::with_auth_secret(
        miraserve_tls::KeydEndpoint::LoopbackTcp(bound_addr),
        *secret,
    );
    let bundle2 =
        tokio::task::spawn_blocking(move || client2.load_remote_certified_keys()).await??;
    assert!(bundle2.default_cert.is_some());

    drop(stalled);
    running.shutdown().await;
    Ok(())
}

/// R2-ACME-6: Reloading certificates via `commit_reload_preserving_acme` MUST drop removed manual
/// certificates immediately while preserving live ACME-managed certificates still in config.
#[test]
fn resolver_commit_reload_drops_removed_manual_certs_and_preserves_acme_certs() -> TestResult {
    let provider = build_crypto_provider(true);
    let acme = Arc::new(AcmeChallengeStore::new());
    let live = DynamicCertResolver::new(Arc::clone(&acme));

    let (manual_cert, _) =
        generate_dev_certificate(&["manual.example.test".to_owned()], &provider)?;
    let (acme_cert, _) = generate_dev_certificate(&["acme.example.test".to_owned()], &provider)?;
    let (kept_cert, _) = generate_dev_certificate(&["kept.example.test".to_owned()], &provider)?;

    live.upsert_host("manual.example.test", manual_cert);
    live.upsert_acme_host("acme.example.test", acme_cert);
    live.upsert_host("kept.example.test", Arc::clone(&kept_cert));

    // Staged reload removes `manual.example.test`, keeps `kept.example.test`, and leaves
    // `acme.example.test` as an ACME-managed host.
    let staged = DynamicCertResolver::new(acme);
    staged.upsert_host("kept.example.test", kept_cert);

    let keep_acme = std::collections::HashSet::from(["acme.example.test".to_owned()]);
    live.commit_reload_preserving_acme(&staged, &keep_acme, false);

    assert!(
        live.lookup_host("manual.example.test").is_none(),
        "removed manual certificate must be dropped immediately on reload"
    );
    assert!(
        live.lookup_host("acme.example.test").is_some(),
        "live ACME-managed certificate still in config must be preserved across reload"
    );
    assert!(live.lookup_host("kept.example.test").is_some());

    Ok(())
}

/// R3-PKG-2: `KeydUnixPeerPolicy::SameUidOrGroup` creates a `0750` socket directory and `0660`
/// Unix socket enforcing `SO_PEERCRED` UID/GID verification for separate-UID systemd deployments.
#[cfg(unix)]
#[tokio::test]
async fn keyd_unix_group_peer_policy_sets_0660_socket_and_serves_signing() -> TestResult {
    use std::os::unix::fs::PermissionsExt as _;

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let sock_dir = std::env::temp_dir().join(format!("ms-keyd-grp-{}-{nanos}", std::process::id()));
    let sock_path = sock_dir.join("keyd.sock");

    let provider = build_crypto_provider(true);
    let (dev_ck, _) = generate_dev_certificate(&["split.example.test".to_owned()], &provider)?;
    let mut store = miraserve_tls::KeydKeyStore::new();
    store.insert_certified_key(
        "split-default",
        vec!["split.example.test".to_owned()],
        true,
        dev_ck,
    )?;

    let running = miraserve_tls::KeydServer::start_with_options(
        miraserve_tls::KeydEndpoint::Unix(sock_path.clone()),
        store,
        false,
        None,
        miraserve_tls::KeydUnixPeerPolicy::SameUidOrGroup,
    )
    .await?;

    let sock_mode = std::fs::metadata(&sock_path)?.permissions().mode() & 0o777;
    assert_eq!(
        sock_mode, 0o660,
        "SameUidOrGroup keyd socket must be 0660, got {sock_mode:04o}"
    );
    let dir_mode = std::fs::metadata(&sock_dir)?.permissions().mode() & 0o777;
    assert_eq!(
        dir_mode & 0o007,
        0,
        "SameUidOrGroup keyd socket directory must have zero world permissions, got {dir_mode:04o}"
    );

    let client = miraserve_tls::KeydClient::new(miraserve_tls::KeydEndpoint::Unix(sock_path));
    let bundle = tokio::task::spawn_blocking(move || client.load_remote_certified_keys()).await??;
    assert!(bundle.default_cert.is_some());

    running.shutdown().await;
    let _ = std::fs::remove_dir_all(&sock_dir);
    Ok(())
}

/// R3-ACME-1 (ARI zero-delay due + Retry-After floor), R2-ACME-1 (in-memory cert avoids re-order
/// on persist failure), R2-ACME-4 (reload notify wakes ACME loop immediately), and R3-KEYD-1
/// (burst of 32 concurrent TCP keyd handshakes + persistent connection reuse under pre-auth flood).
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn round3_acme_ari_in_memory_reload_wake_and_keyd_burst_pool() -> TestResult {
    // 1. R3-ACME-1: Zero ARI delay marks domain immediately due while honoring Retry-After as floor.
    let urgent = miraserve_tls::plan_ari_schedule(Duration::ZERO, Duration::from_secs(3600));
    assert!(
        urgent.renew_now,
        "zero ARI delay must mark domain due immediately"
    );
    assert_eq!(urgent.next_ari_poll_after, Duration::from_secs(3600));
    assert_eq!(urgent.wake_delay, Duration::ZERO);

    let deferred =
        miraserve_tls::plan_ari_schedule(Duration::from_secs(7200), Duration::from_secs(3600));
    assert!(!deferred.renew_now);
    assert_eq!(deferred.next_ari_poll_after, Duration::from_secs(3600));
    assert_eq!(deferred.wake_delay, Duration::from_secs(3600));

    let short_floor =
        miraserve_tls::plan_ari_schedule(Duration::from_secs(600), Duration::from_secs(10));
    assert_eq!(
        short_floor.next_ari_poll_after,
        Duration::from_secs(60),
        "Retry-After floor must be at least 60s"
    );

    // 2. R2-ACME-1 + R2-ACME-4: In-memory ACME cert prevents re-ordering when disk files vanish,
    //    and `reload_notify` wakes `run_renewal_loop_with_domains_and_notify` immediately!
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let acme_dir = std::env::temp_dir().join(format!("ms-r3-acme-{}-{nanos}", std::process::id()));
    let provider = build_crypto_provider(true);
    let acme_store = Arc::new(AcmeChallengeStore::new());
    let resolver = Arc::new(DynamicCertResolver::new(Arc::clone(&acme_store)));
    let manager = Arc::new(miraserve_tls::AcmeManager::new(
        miraserve_config::AcmeConfig {
            email: "ops@example.com".to_owned(),
            challenge: miraserve_config::AcmeChallenge::Http01,
            short_lived: false,
            ari: false,
            directory: None,
        },
        &acme_dir,
        acme_store,
        resolver,
        Arc::clone(&provider),
    ));

    // Seed a valid cert via `install_and_persist_certificate_pem` (exercising paired temp-file
    // persistence `R3-ACME-2` + live in-memory validity cache `R2-ACME-1`), verify `needs_renewal`
    // is false, then remove the disk `certs/` directory (simulating disk persistence failure) and
    // assert `needs_renewal` STILL returns false while the live in-memory cert is valid!
    let dev_pem = miraserve_tls::generate_dev_cert_pem(&["cached.example.com".to_owned()])?;
    let _ck = manager.install_and_persist_certificate_pem(
        "cached.example.com",
        &dev_pem.cert_pem,
        &dev_pem.key_pem,
    )?;
    assert!(
        !manager.needs_renewal("cached.example.com"),
        "freshly persisted ACME cert must not need immediate renewal"
    );
    std::fs::remove_dir_all(manager.certs_dir())?;
    assert!(
        !manager.needs_renewal("cached.example.com"),
        "R2-ACME-1: live in-memory ACME cert must prevent re-ordering when disk cache is missing"
    );
    let poll_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let poll_count_ref = Arc::clone(&poll_count);
    let reload_notify = Arc::new(tokio::sync::Notify::new());
    let (sd_tx, sd_rx) = tokio::sync::watch::channel(false);
    let loop_mgr = Arc::clone(&manager);
    let loop_notify = Arc::clone(&reload_notify);
    let loop_handle = tokio::spawn(async move {
        loop_mgr
            .run_renewal_loop_with_domains_and_notify(
                move || {
                    poll_count_ref.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                    Vec::new()
                },
                loop_notify,
                sd_rx,
            )
            .await;
    });
    // Wait briefly for initial iteration, then trigger reload_notify and verify immediate wakeup!
    for _ in 0..40 {
        if poll_count.load(std::sync::atomic::Ordering::Acquire) >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(poll_count.load(std::sync::atomic::Ordering::Acquire) >= 1);
    reload_notify.notify_one();
    for _ in 0..40 {
        if poll_count.load(std::sync::atomic::Ordering::Acquire) >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        poll_count.load(std::sync::atomic::Ordering::Acquire) >= 2,
        "ACME renewal loop must wake immediately on reload_notify instead of sleeping 6h"
    );
    let _ = sd_tx.send(true);
    let _ = loop_handle.await;
    let _ = std::fs::remove_dir_all(&acme_dir);

    // 3. R3-KEYD-1: Burst of 32 concurrent TCP keyd signing requests (exceeding old 16-slot drop
    //    cap!) AND persistent connection reuse surviving 20 silent local unauthenticated TCP peers!
    let (ck, _) = generate_dev_certificate(&["burst.example.test".to_owned()], &provider)?;
    let mut store = miraserve_tls::KeydKeyStore::new();
    store.insert_certified_key("burst", vec!["burst.example.test".to_owned()], true, ck)?;
    let secret = miraserve_tls::generate_keyd_auth_secret()?;
    let running = miraserve_tls::KeydServer::start_with_auth(
        miraserve_tls::KeydEndpoint::LoopbackTcp("127.0.0.1:0".parse()?),
        store,
        false,
        Some(secret.clone()),
    )
    .await?;
    let endpoint = running.endpoint().clone();
    let mira_addr = match &endpoint {
        miraserve_tls::KeydEndpoint::LoopbackTcp(a) => *a,
        #[cfg(unix)]
        miraserve_tls::KeydEndpoint::Unix(_) => return Err("expected loopback TCP endpoint".into()),
    };

    // Build a valid RFC 8446 TLS 1.3 CertificateVerify message (98-byte context + 32-byte hash).
    let mut cv_msg = Vec::with_capacity(130);
    cv_msg.extend_from_slice(&[b' '; 64]);
    cv_msg.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
    cv_msg.extend_from_slice(&[0xAB_u8; 32]);

    // 3a. Burst of 32 simultaneous fresh TCP clients (> old 16-slot preauth cap) MUST all succeed!
    let mut burst_handles = Vec::with_capacity(32);
    for _ in 0..32 {
        let ep = endpoint.clone();
        let sec = *secret;
        let msg = cv_msg.clone();
        burst_handles.push(tokio::task::spawn_blocking(move || {
            let c = miraserve_tls::KeydClient::with_auth_secret(ep, sec);
            c.request_signature(
                "burst",
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                &msg,
            )
        }));
    }
    for h in burst_handles {
        let sig = h.await??;
        assert!(!sig.is_empty());
    }

    // 3b. Warm pooled worker client keeps signing cleanly even while 20 silent unauthenticated
    //     local TCP peers occupy pre-auth slots!
    let warm_client = miraserve_tls::KeydClient::with_auth_secret(endpoint, *secret);
    let warm_c1 = warm_client.clone();
    let msg1 = cv_msg.clone();
    let first_sig = tokio::task::spawn_blocking(move || {
        warm_c1.request_signature(
            "burst",
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            &msg1,
        )
    })
    .await??;
    assert!(!first_sig.is_empty());

    let mut silent_peers = Vec::with_capacity(20);
    for _ in 0..20 {
        if let Ok(s) = tokio::net::TcpStream::connect(mira_addr).await {
            silent_peers.push(s);
        }
    }
    let warm_c2 = warm_client.clone();
    let msg2 = cv_msg.clone();
    let pooled_sig = tokio::task::spawn_blocking(move || {
        warm_c2.request_signature(
            "burst",
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            &msg2,
        )
    })
    .await??;
    assert!(!pooled_sig.is_empty());

    drop(silent_peers);
    running.shutdown().await;
    Ok(())
}

/// Wave-1 Round-4 TLS regressions:
/// - `R4-ACME-1` / `R2-ACME-1`: `cached_cert_ari_id` reads the installed in-memory cert ID even
///   when disk files are absent or stale
/// - `R3-ACME-2`: `persist_certificate` rolls back `.key` if renaming `.crt` fails
/// - `R3-PKG-4`: `create_private_dir_all` tightens an existing `0755` directory to `0700`
/// - `R4-KEYD-1` / `R2-KEYD-2`: `resolve_unix_user_uid` rejects `0`/`root`, `SameUidOrPeerUid`
///   authorizes exact peer UID on Unix sockets, and `KeydClient` fails cleanly on missing socket.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn tls_round4_wave1_acme_ari_rollback_dir_mode_and_keyd_peer_uid() -> TestResult {
    use_private_umask();
    let provider = build_crypto_provider(true);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base =
        std::env::temp_dir().join(format!("miraserve-r4w1-tls-{}-{nanos}", std::process::id()));

    // 1. R3-PKG-4: Existing 0755 directory is tightened to 0700 by `create_private_dir_all`
    let acme_dir = base.join("acme");
    std::fs::create_dir_all(&acme_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&acme_dir, std::fs::Permissions::from_mode(0o755))?;
    }
    miraserve_tls::create_private_dir_all(&acme_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&acme_dir)?.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "create_private_dir_all must tighten pre-existing 0755 dir to 0700 (R3-PKG-4)"
        );
    }

    // 2. R4-ACME-1 / R2-ACME-1: `cached_cert_ari_id` reads in-memory cert ID even after disk files vanish
    let challenges = Arc::new(miraserve_tls::AcmeChallengeStore::new());
    let resolver = Arc::new(DynamicCertResolver::new(Arc::clone(&challenges)));
    let mgr = miraserve_tls::AcmeManager::new(
        miraserve_config::AcmeConfig {
            email: "ops@example.com".to_owned(),
            challenge: miraserve_config::AcmeChallenge::Http01,
            ari: true,
            short_lived: false,
            directory: None,
        },
        acme_dir.clone(),
        Arc::clone(&challenges),
        Arc::clone(&resolver),
        Arc::clone(&provider),
    );
    let mut ca_params = rcgen::CertificateParams::new(Vec::new())?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate()?;
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let issuer = rcgen::Issuer::new(ca_params, ca_key);
    let mut leaf_params = rcgen::CertificateParams::new(vec!["ari-mem.example.test".to_owned()])?;
    leaf_params.use_authority_key_identifier_extension = true;
    let leaf_key = rcgen::KeyPair::generate()?;
    let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer)?;
    let leaf_chain_pem = format!("{}{}", leaf_cert.pem(), ca_cert.pem());
    mgr.install_and_persist_certificate_pem(
        "ari-mem.example.test",
        &leaf_chain_pem,
        &leaf_key.serialize_pem(),
    )?;
    let ari_before_delete = mgr.cached_cert_ari_id("ari-mem.example.test");
    assert!(
        ari_before_delete.is_some(),
        "expected ARI ID from installed CA-signed leaf cert"
    );
    // Delete on-disk cert/key: in-memory ARI ID must STILL be returned (no stale disk fallback!)
    let certs_dir = mgr.certs_dir();
    std::fs::remove_dir_all(&certs_dir)?;
    let ari_after_delete = mgr.cached_cert_ari_id("ari-mem.example.test");
    assert!(
        ari_after_delete.is_some(),
        "cached_cert_ari_id must read in-memory cert state even when disk persistence is missing (R4-ACME-1)"
    );

    // 3. R3-ACME-2: If `.crt` rename fails (e.g. a directory obstructs `.crt`), `.key` is rolled
    //    back to the previous valid key instead of leaving a mismatched key/cert pair on disk!
    std::fs::create_dir_all(&certs_dir)?;
    let (_, pem_old) = generate_dev_certificate(&["rollback.example.test".to_owned()], &provider)?;
    mgr.install_and_persist_certificate_pem(
        "rollback.example.test",
        &pem_old.cert_pem,
        &pem_old.key_pem,
    )?;
    let mut key_file = None;
    let mut crt_file = None;
    for entry in std::fs::read_dir(&certs_dir)? {
        let p = entry?.path();
        match p.extension().and_then(std::ffi::OsStr::to_str) {
            Some("key") => key_file = Some(p),
            Some("crt") => crt_file = Some(p),
            _ => {}
        }
    }
    let key_file = key_file.ok_or("expected persisted .key file")?;
    let crt_file = crt_file.ok_or("expected persisted .crt file")?;
    let old_key_bytes = std::fs::read(&key_file)?;
    // Obstruct `.crt` with a directory so renaming the new temp `.crt` over it fails
    std::fs::remove_file(&crt_file)?;
    std::fs::create_dir_all(&crt_file)?;
    let (_, pem_new) = generate_dev_certificate(&["rollback.example.test".to_owned()], &provider)?;
    let persist_res = mgr.install_and_persist_certificate_pem(
        "rollback.example.test",
        &pem_new.cert_pem,
        &pem_new.key_pem,
    );
    assert!(
        persist_res.is_ok(),
        "R5-ACME-3 residual: atomic .bundle.pem succeeded so legacy .crt obstruction must warn without failing persistence: {persist_res:?}"
    );
    assert_eq!(
        std::fs::read(&key_file)?,
        old_key_bytes,
        "prior .key must still be rolled back intact when legacy .crt rename fails (R3-ACME-2)"
    );

    // 4. R4-KEYD-1 & R2-KEYD-2: Unix peer-UID resolution & SameUidOrPeerUid policy
    #[cfg(unix)]
    {
        assert!(miraserve_tls::resolve_unix_user_uid("0").is_err());
        assert!(miraserve_tls::resolve_unix_user_uid("root").is_err());
        assert!(miraserve_tls::resolve_unix_user_uid("nonexistent-user-xyz-999999").is_err());
        assert_eq!(miraserve_tls::resolve_unix_user_uid("65534")?, 65534);

        let sock_path =
            std::path::PathBuf::from(format!("/tmp/ms-r4w1-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock_path);
        let (ck, _) = generate_dev_certificate(&["peer.example.test".to_owned()], &provider)?;
        let mut store = miraserve_tls::KeydKeyStore::new();
        store.insert_certified_key("peer", vec!["peer.example.test".to_owned()], true, ck)?;
        let running = miraserve_tls::KeydServer::start_with_options(
            miraserve_tls::KeydEndpoint::Unix(sock_path.clone()),
            store,
            false,
            None,
            miraserve_tls::KeydUnixPeerPolicy::SameUidOrPeerUid(65534),
        )
        .await?;
        let client =
            miraserve_tls::KeydClient::new(miraserve_tls::KeydEndpoint::Unix(sock_path.clone()));
        let keys =
            tokio::task::spawn_blocking(move || client.load_remote_certified_keys()).await??;
        assert_eq!(keys.host_certs.len(), 1);
        running.shutdown().await;
        let _ = std::fs::remove_file(&sock_path);

        // R2-KEYD-2: Missing socket fails cleanly via bounded connect_unix_with_timeout
        let missing_client = miraserve_tls::KeydClient::new(miraserve_tls::KeydEndpoint::Unix(
            std::path::PathBuf::from(format!("/tmp/ms-r4w1-miss-{}.sock", std::process::id())),
        ));
        let miss_res =
            tokio::task::spawn_blocking(move || missing_client.load_remote_certified_keys())
                .await?;
        assert!(miss_res.is_err());
    }

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Round 5 Wave 1 TLS/ACME/keyd regressions:
/// - `R5-PKG-2`: `write_secret_file` preserves an existing `0750` parent directory mode.
/// - `R5-ACME-3`: Crash-atomic `.bundle.pem` survives corrupted `.crt`/`.key` pairs on reload.
/// - `R5-ACME-1` & `R5-ACME-2` & `R5-ACME-4`: Runs the REAL `run_renewal_loop_with_reload_check`
///   supervisor proving (a) a fresh in-memory cert suppresses re-ordering over a stale disk cert,
///   (b) a fresher disk cert over an older in-memory cert does NOT spin at 100% CPU, and
///   (c) `reload_notify` + `config_changed_fn` cleanly wakes and exits the supervisor for rebuild.
/// - `R4-KEYD-1` / `R5-KEYD-1`: Live Unix `KeydServer` with `ExactPeerUid` rejects an unauthorized
///   UID via real kernel `SO_PEERCRED`/`LOCAL_PEERCRED` while admitting the exact authorized UID.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn tls_round5_wave1_acme_loop_bundle_atomicity_and_keyd_peer_rejection() -> TestResult {
    use_private_umask();
    let provider = build_crypto_provider(true);
    let base = std::env::temp_dir().join(format!(
        "miraserve-r5w1-tls-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_nanos()
    ));

    // 1. R5-PKG-2: `write_secret_file` must NEVER chmod a pre-existing `0750` parent directory!
    let shared_certs = base.join("shared-certs");
    std::fs::create_dir_all(&shared_certs)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&shared_certs, std::fs::Permissions::from_mode(0o750))?;
        let key_out = shared_certs.join("starter.key");
        miraserve_tls::write_secret_file(&key_out, b"dummy-secret-key\n")?;
        let dir_mode = std::fs::metadata(&shared_certs)?.permissions().mode() & 0o777;
        let file_mode = std::fs::metadata(&key_out)?.permissions().mode() & 0o777;
        assert_eq!(
            dir_mode, 0o750,
            "write_secret_file must not tighten pre-existing 0750 parent dir (R5-PKG-2)"
        );
        assert_eq!(file_mode, 0o600, "secret file itself must be 0600");
    }

    // 2. R5-ACME-3: Crash-atomic `.bundle.pem` recovers cleanly even if `.crt`/`.key` are corrupted.
    let acme_dir = base.join("acme-state");
    let challenges = Arc::new(AcmeChallengeStore::new());
    let resolver = Arc::new(DynamicCertResolver::new(Arc::clone(&challenges)));
    let acme_cfg = miraserve_config::AcmeConfig {
        email: "ops@example.test".to_owned(),
        challenge: miraserve_config::AcmeChallenge::Http01,
        directory: Some("https://127.0.0.1:1/acme/directory".to_owned()),
        short_lived: false,
        ari: false,
    };
    let mgr = Arc::new(miraserve_tls::AcmeManager::new(
        acme_cfg.clone(),
        acme_dir.clone(),
        Arc::clone(&challenges),
        Arc::clone(&resolver),
        Arc::clone(&provider),
    ));

    let make_cert = |domain: &str,
                     not_after_offset_secs: u64|
     -> Result<(String, String), Box<dyn std::error::Error>> {
        let mut params = rcgen::CertificateParams::new(vec![domain.to_owned()])?;
        let now = std::time::SystemTime::now();
        params.not_before = (now - Duration::from_hours(24)).into();
        params.not_after = (now + Duration::from_secs(not_after_offset_secs)).into();
        let key = rcgen::KeyPair::generate()?;
        let cert = params.self_signed(&key)?;
        Ok((cert.pem(), key.serialize_pem()))
    };

    let (fresh_cert_pem, fresh_key_pem) = make_cert("bundle.example.test", 80 * 86_400)?;
    mgr.install_and_persist_certificate_pem(
        "bundle.example.test",
        &fresh_cert_pem,
        &fresh_key_pem,
    )?;

    // Corrupt `.crt` and `.key` to simulate a mid-rename crash while `.bundle.pem` is intact.
    let certs_dir = mgr.certs_dir();
    let mut saw_bundle = false;
    for entry in std::fs::read_dir(&certs_dir)? {
        let p = entry?.path();
        let name = p
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or("");
        if name.ends_with(".bundle.pem") {
            saw_bundle = true;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                assert_eq!(std::fs::metadata(&p)?.permissions().mode() & 0o777, 0o600);
            }
        } else if p
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("crt") || e.eq_ignore_ascii_case("key"))
        {
            std::fs::write(&p, b"CORRUPTED-HALF-WRITE")?;
        }
    }
    assert!(
        saw_bundle,
        "expected crash-atomic .bundle.pem file (R5-ACME-3)"
    );

    // Fresh resolver + manager must recover the certificate solely from `.bundle.pem`!
    let challenges2 = Arc::new(AcmeChallengeStore::new());
    let resolver2 = Arc::new(DynamicCertResolver::new(Arc::clone(&challenges2)));
    let mgr2 = Arc::new(miraserve_tls::AcmeManager::new(
        acme_cfg.clone(),
        acme_dir.clone(),
        Arc::clone(&challenges2),
        Arc::clone(&resolver2),
        Arc::clone(&provider),
    ));
    mgr2.load_cached_certificates(&["bundle.example.test".to_owned()]);
    assert!(
        !mgr2.needs_renewal("bundle.example.test"),
        "fresh .bundle.pem must load cleanly despite corrupted .crt/.key (R5-ACME-3)"
    );

    // 3. R5-ACME-1: Stale expiring cert on disk + fresh in-memory cert (failed disk write) ->
    //    `needs_renewal` uses the fresher in-memory validity and returns `false`!
    let (stale_cert_pem, stale_key_pem) = make_cert("memfresh.example.test", 3600)?;
    mgr.install_and_persist_certificate_pem(
        "memfresh.example.test",
        &stale_cert_pem,
        &stale_key_pem,
    )?;
    assert!(
        mgr.needs_renewal("memfresh.example.test"),
        "expiring 1h cert should need renewal"
    );
    // Simulate a fresh cert installed in memory whose disk write failed by obstructing the
    // `.bundle.pem` target with a directory so `fs::rename` fails with EISDIR/EEXIST (works
    // portably and regardless of UID; `install_and_persist_certificate_pem` installs in-memory
    // BEFORE persisting to disk).
    let stale_bundle_path = std::fs::read_dir(&certs_dir)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|n| {
                    n.starts_with("memfresh.example.test") && n.ends_with(".bundle.pem")
                })
        })
        .ok_or("expected memfresh .bundle.pem")?;
    let saved_stale_bundle = std::fs::read(&stale_bundle_path)?;
    std::fs::remove_file(&stale_bundle_path)?;
    std::fs::create_dir_all(&stale_bundle_path)?;
    let (mem_fresh_cert, mem_fresh_key) = make_cert("memfresh.example.test", 80 * 86_400)?;
    let res = mgr.install_and_persist_certificate_pem(
        "memfresh.example.test",
        &mem_fresh_cert,
        &mem_fresh_key,
    );
    std::fs::remove_dir_all(&stale_bundle_path)?;
    // Restore the stale bundle on disk so disk is strictly older than memory!
    std::fs::write(&stale_bundle_path, &saved_stale_bundle)?;
    assert!(
        res.is_err(),
        "disk write should fail when .bundle.pem is obstructed by a directory"
    );
    assert!(
        !mgr.needs_renewal("memfresh.example.test"),
        "needs_renewal must honor fresher in-memory cert after failed disk write (R5-ACME-1)"
    );

    // 4. R5-ACME-2 & R5-ACME-4: Run the REAL `run_renewal_loop_with_reload_check` supervisor with
    //    both domains (one where memory is fresher than disk, one where disk is fresher than
    //    memory). Verify it does NOT spin at 100% CPU (domains_fn called at most twice over
    //    200ms) and exits cleanly when `reload_notify` fires with `config_changed_fn == true`!
    // Create a second domain where disk is fresher than memory:
    let (disk_fresh_cert, disk_fresh_key) = make_cert("diskfresh.example.test", 80 * 86_400)?;
    mgr.install_and_persist_certificate_pem(
        "diskfresh.example.test",
        &disk_fresh_cert,
        &disk_fresh_key,
    )?;
    let fresh_bundle_path = std::fs::read_dir(&certs_dir)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|n| {
                    n.starts_with("diskfresh.example.test") && n.ends_with(".bundle.pem")
                })
        })
        .ok_or("expected diskfresh .bundle.pem")?;
    let saved_fresh_bundle = std::fs::read(&fresh_bundle_path)?;
    std::fs::remove_file(&fresh_bundle_path)?;
    std::fs::create_dir_all(&fresh_bundle_path)?;
    let (old_mem_cert, old_mem_key) = make_cert("diskfresh.example.test", 3600)?;
    let _ = mgr.install_and_persist_certificate_pem(
        "diskfresh.example.test",
        &old_mem_cert,
        &old_mem_key,
    );
    std::fs::remove_dir_all(&fresh_bundle_path)?;
    std::fs::write(&fresh_bundle_path, &saved_fresh_bundle)?;
    assert!(
        !mgr.needs_renewal("diskfresh.example.test"),
        "fresher disk cert must satisfy needs_renewal (R5-ACME-2)"
    );

    let loop_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let loop_calls_c = Arc::clone(&loop_calls);
    let reload_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reload_flag_c = Arc::clone(&reload_flag);
    let reload_notify = Arc::new(tokio::sync::Notify::new());
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let loop_handle = tokio::spawn(Arc::clone(&mgr).run_renewal_loop_with_reload_check(
        move || {
            loop_calls_c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            vec![
                "memfresh.example.test".to_owned(),
                "diskfresh.example.test".to_owned(),
            ]
        },
        move || reload_flag_c.load(std::sync::atomic::Ordering::SeqCst),
        Arc::clone(&reload_notify),
        shutdown_rx,
    ));

    tokio::time::sleep(Duration::from_millis(200)).await;
    let calls_during_idle = loop_calls.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        calls_during_idle <= 2,
        "ACME supervisor loop spun excessively ({calls_during_idle} passes in 200ms) — R5-ACME-2 regression!"
    );

    // Trigger R5-ACME-4 config-changed reload: supervisor must wake and exit cleanly!
    reload_flag.store(true, std::sync::atomic::Ordering::SeqCst);
    reload_notify.notify_one();
    tokio::time::timeout(Duration::from_secs(2), loop_handle)
        .await
        .map_err(
            |_| "ACME supervisor did not exit promptly after ACME config reload (R5-ACME-4)",
        )??;
    drop(shutdown_tx);

    // 5. R4-KEYD-1 / R5-KEYD-1: Live Unix socket peer-UID rejection via real kernel peer_cred!
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let my_uid = std::fs::metadata(&base)?.uid();
        let other_uid = if my_uid == 65534 { 65533 } else { 65534 };

        let sock_reject =
            std::path::PathBuf::from(format!("/tmp/ms-r5w1-rej-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock_reject);
        let (ck, _) = generate_dev_certificate(&["uid.example.test".to_owned()], &provider)?;
        let mut store = miraserve_tls::KeydKeyStore::new();
        store.insert_certified_key("uid", vec!["uid.example.test".to_owned()], true, ck.clone())?;
        let running_rej = miraserve_tls::KeydServer::start_with_options(
            miraserve_tls::KeydEndpoint::Unix(sock_reject.clone()),
            store,
            false,
            None,
            miraserve_tls::KeydUnixPeerPolicy::ExactPeerUid(other_uid),
        )
        .await?;
        let client_rej =
            miraserve_tls::KeydClient::new(miraserve_tls::KeydEndpoint::Unix(sock_reject.clone()));
        let rej_res =
            tokio::task::spawn_blocking(move || client_rej.load_remote_certified_keys()).await?;
        assert!(
            rej_res.is_err(),
            "keyd ExactPeerUid({other_uid}) must reject connecting process UID {my_uid} via kernel peer_cred!"
        );
        running_rej.shutdown().await;
        let _ = std::fs::remove_file(&sock_reject);

        // Now authorize exact current UID -> must succeed!
        let sock_ok =
            std::path::PathBuf::from(format!("/tmp/ms-r5w1-ok-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock_ok);
        let mut store_ok = miraserve_tls::KeydKeyStore::new();
        store_ok.insert_certified_key("uid", vec!["uid.example.test".to_owned()], true, ck)?;
        let running_ok = miraserve_tls::KeydServer::start_with_options(
            miraserve_tls::KeydEndpoint::Unix(sock_ok.clone()),
            store_ok,
            false,
            None,
            miraserve_tls::KeydUnixPeerPolicy::ExactPeerUid(my_uid),
        )
        .await?;
        let client_ok =
            miraserve_tls::KeydClient::new(miraserve_tls::KeydEndpoint::Unix(sock_ok.clone()));
        let ok_bundle =
            tokio::task::spawn_blocking(move || client_ok.load_remote_certified_keys()).await??;
        assert_eq!(ok_bundle.host_certs.len(), 1);
        running_ok.shutdown().await;
        let _ = std::fs::remove_file(&sock_ok);
    }

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// R6-ACME-1: Switching ACME directory URL (staging -> production) or account email isolates
/// `account.json` and `certs/` under deterministic SHA-256 scoped subdirectories so staging certs
/// and credentials are NEVER reused after switching to production.
#[test]
fn r6_acme_1_directory_and_account_switches_isolate_state_and_certs() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let state_dir = std::env::temp_dir().join(format!(
        "miraserve-r6-acme-1-{}-{nanos}",
        std::process::id()
    ));
    let provider = build_crypto_provider(true);
    let challenges = Arc::new(AcmeChallengeStore::new());

    let staging_cfg = miraserve_config::AcmeConfig {
        email: "ops@example.com".to_owned(),
        challenge: miraserve_config::AcmeChallenge::TlsAlpn01,
        ari: false,
        short_lived: false,
        directory: Some("https://acme-staging-v02.api.letsencrypt.org/directory".to_owned()),
    };
    let prod_cfg = miraserve_config::AcmeConfig {
        email: "ops@example.com".to_owned(),
        challenge: miraserve_config::AcmeChallenge::TlsAlpn01,
        ari: false,
        short_lived: false,
        directory: None,
    };
    let other_email_cfg = miraserve_config::AcmeConfig {
        email: "secops@example.com".to_owned(),
        ..prod_cfg.clone()
    };

    let staging_mgr = miraserve_tls::AcmeManager::new(
        staging_cfg,
        state_dir.clone(),
        Arc::clone(&challenges),
        Arc::new(DynamicCertResolver::new(Arc::clone(&challenges))),
        Arc::clone(&provider),
    );
    let prod_mgr = miraserve_tls::AcmeManager::new(
        prod_cfg,
        state_dir.clone(),
        Arc::clone(&challenges),
        Arc::new(DynamicCertResolver::new(Arc::clone(&challenges))),
        Arc::clone(&provider),
    );
    let other_email_mgr = miraserve_tls::AcmeManager::new(
        other_email_cfg,
        state_dir.clone(),
        Arc::clone(&challenges),
        Arc::new(DynamicCertResolver::new(Arc::clone(&challenges))),
        Arc::clone(&provider),
    );

    assert_ne!(
        staging_mgr.scoped_state_dir(),
        prod_mgr.scoped_state_dir(),
        "staging and production ACME directories must use separate state directories"
    );
    assert_eq!(
        prod_mgr.scoped_state_dir(),
        other_email_mgr.scoped_state_dir(),
        "R7-ACME-1: changing contact email within the same ACME directory must keep the same cert cache directory"
    );
    assert_ne!(
        prod_mgr.account_path(),
        other_email_mgr.account_path(),
        "R7-ACME-1: distinct ACME account emails must use separate account credential files"
    );

    let (_, staging_pem) =
        generate_dev_certificate(&["switch.example.test".to_owned()], &provider)?;
    staging_mgr.install_and_persist_certificate_pem(
        "switch.example.test",
        &staging_pem.cert_pem,
        &staging_pem.key_pem,
    )?;
    assert!(!staging_mgr.needs_renewal("switch.example.test"));

    // Production manager MUST NOT load or trust the staging cert on disk!
    prod_mgr.load_cached_certificates(&["switch.example.test".to_owned()]);
    assert!(
        prod_mgr.needs_renewal("switch.example.test"),
        "R6-ACME-1: switching from staging to production MUST require a fresh production certificate"
    );

    let _ = std::fs::remove_dir_all(&state_dir);
    Ok(())
}

/// R7-ACME-1: Upgrading from the `4bd1f41` flat ACME layout (`<state>/account.json` +
/// `<state>/certs/`) seamlessly adopts matching-directory state on first access, refuses to adopt
/// mismatched-directory state (e.g. production certs into staging), and preserves valid cached
/// certificates across a contact-email change without re-issuing.
#[test]
#[allow(clippy::too_many_lines)]
fn r7_acme_1_migrates_legacy_4bd1f41_layout_and_preserves_certs_across_email_change() -> TestResult
{
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let base = std::env::temp_dir().join(format!(
        "miraserve-r7-acme-1-{}-{nanos}",
        std::process::id()
    ));
    let seed_state = base.join("seed");
    let legacy_state = base.join("legacy-upgrade");
    let provider = build_crypto_provider(true);
    let challenges = Arc::new(AcmeChallengeStore::new());

    let prod_cfg = miraserve_config::AcmeConfig {
        email: "ops@example.com".to_owned(),
        challenge: miraserve_config::AcmeChallenge::TlsAlpn01,
        ari: false,
        short_lived: false,
        directory: None,
    };
    let staging_cfg = miraserve_config::AcmeConfig {
        directory: Some("https://acme-staging-v02.api.letsencrypt.org/directory".to_owned()),
        ..prod_cfg.clone()
    };
    let new_email_prod_cfg = miraserve_config::AcmeConfig {
        email: "secops@example.com".to_owned(),
        ..prod_cfg.clone()
    };

    // 1. Seed a real `.bundle.pem` / `.crt` / `.key` file set, then place it into the exact
    //    `4bd1f41` flat layout (`<state>/account.json` + `<state>/certs/`).
    let seed_mgr = miraserve_tls::AcmeManager::new(
        prod_cfg.clone(),
        seed_state.clone(),
        Arc::clone(&challenges),
        Arc::new(DynamicCertResolver::new(Arc::clone(&challenges))),
        Arc::clone(&provider),
    );
    let (_, cert_pem) = generate_dev_certificate(&["upgrade.example.test".to_owned()], &provider)?;
    seed_mgr.install_and_persist_certificate_pem(
        "upgrade.example.test",
        &cert_pem.cert_pem,
        &cert_pem.key_pem,
    )?;

    let legacy_certs = legacy_state.join("certs");
    std::fs::create_dir_all(&legacy_certs)?;
    for entry in std::fs::read_dir(seed_mgr.certs_dir())? {
        let entry = entry?;
        std::fs::copy(entry.path(), legacy_certs.join(entry.file_name()))?;
    }
    std::fs::write(
        legacy_state.join("account.json"),
        r#"{"id":"https://acme-v02.api.letsencrypt.org/acme/acct/42","key_pkcs8":"AA==","directory":"https://acme-v02.api.letsencrypt.org/directory"}"#,
    )?;

    // 2. A staging manager MUST NOT adopt legacy production certs or account.json!
    let staging_resolver = Arc::new(DynamicCertResolver::new(Arc::clone(&challenges)));
    let staging_mgr = miraserve_tls::AcmeManager::new(
        staging_cfg,
        legacy_state.clone(),
        Arc::clone(&challenges),
        Arc::clone(&staging_resolver),
        Arc::clone(&provider),
    );
    staging_mgr.load_cached_certificates(&["upgrade.example.test".to_owned()]);
    assert!(
        staging_mgr.needs_renewal("upgrade.example.test"),
        "R7-ACME-1: staging manager must NOT adopt legacy production ACME certificates"
    );
    assert!(
        legacy_state.join("account.json").is_file(),
        "legacy production account.json must stay untouched when staging loads"
    );

    // 3. A production manager seamlessly migrates the `4bd1f41` layout on first load!
    let prod_resolver = Arc::new(DynamicCertResolver::new(Arc::clone(&challenges)));
    let prod_mgr = miraserve_tls::AcmeManager::new(
        prod_cfg,
        legacy_state.clone(),
        Arc::clone(&challenges),
        Arc::clone(&prod_resolver),
        Arc::clone(&provider),
    );
    prod_mgr.load_cached_certificates(&["upgrade.example.test".to_owned()]);
    assert!(
        !prod_mgr.needs_renewal("upgrade.example.test"),
        "R7-ACME-1: production manager must adopt legacy 4bd1f41 certs without re-issuing"
    );
    assert!(
        prod_mgr.account_path().is_file(),
        "R7-ACME-1: legacy account.json must be migrated to account_path()"
    );
    assert!(
        !legacy_state.join("account.json").exists(),
        "R7-ACME-1: legacy flat account.json must be moved (no stale secret copy left behind)"
    );

    // 4. Changing only the contact email MUST keep the cached certificate without re-issuing,
    //    while storing the new email's account credentials at a distinct account_path().
    let new_email_resolver = Arc::new(DynamicCertResolver::new(Arc::clone(&challenges)));
    let new_email_mgr = miraserve_tls::AcmeManager::new(
        new_email_prod_cfg,
        legacy_state.clone(),
        Arc::clone(&challenges),
        Arc::clone(&new_email_resolver),
        Arc::clone(&provider),
    );
    new_email_mgr.load_cached_certificates(&["upgrade.example.test".to_owned()]);
    assert!(
        !new_email_mgr.needs_renewal("upgrade.example.test"),
        "R7-ACME-1: changing contact email alone must preserve cached certs with zero re-issuance"
    );
    assert_ne!(
        prod_mgr.account_path(),
        new_email_mgr.account_path(),
        "R7-ACME-1: email change must isolate account credentials"
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// R5-ACME-5: ARI queries run concurrently up to `MAX_CONCURRENT_ARI_QUERIES` (8), enforce per-query
/// timeouts without head-of-line blocking, and back off exponentially from 15 min to 4 h cap.
#[tokio::test]
async fn r5_acme_5_ari_bounded_concurrency_timeout_and_exponential_backoff() -> TestResult {
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Codex Round-11: count live query futures with a drop guard so a query cancelled by the
    // per-query timeout is decremented too (a completion-only decrement leaked one count and
    // could report a phantom ninth query). Query 3 times out while 12 more are still queued.
    struct LiveGuard(Arc<AtomicUsize>);
    impl Drop for LiveGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    assert_eq!(miraserve_tls::MAX_CONCURRENT_ARI_QUERIES, 8);
    assert_eq!(miraserve_tls::ARI_QUERY_TIMEOUT, Duration::from_secs(10));

    let in_flight = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let targets: Vec<usize> = (0..20).collect();

    let in_flight_c = Arc::clone(&in_flight);
    let peak_c = Arc::clone(&peak);
    let started = std::time::Instant::now();
    let results = miraserve_tls::run_bounded_ari_queries(
        targets,
        miraserve_tls::MAX_CONCURRENT_ARI_QUERIES,
        Duration::from_millis(80),
        move |idx| {
            let cur = Arc::clone(&in_flight_c);
            let max_seen = Arc::clone(&peak_c);
            async move {
                let active = cur.fetch_add(1, Ordering::SeqCst) + 1;
                let _live = LiveGuard(Arc::clone(&cur));
                max_seen.fetch_max(active, Ordering::SeqCst);
                if idx == 3 {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                } else {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                idx
            }
        },
    )
    .await;

    assert!(
        started.elapsed() < Duration::from_secs(2),
        "bounded ARI batch should not hang on a single stalled query"
    );
    let observed_peak = peak.load(Ordering::SeqCst);
    assert!(
        (2..=miraserve_tls::MAX_CONCURRENT_ARI_QUERIES).contains(&observed_peak),
        "expected concurrent ARI queries bounded by 8 (got peak={observed_peak})"
    );
    assert_eq!(
        in_flight.load(Ordering::SeqCst),
        0,
        "every query future, including the timed-out one, must be dropped after the batch"
    );
    assert_eq!(results.len(), 20);
    assert_eq!(results.iter().filter(|(_, r)| r.is_err()).count(), 1);

    let mut streaks = std::collections::HashMap::new();
    for mins in [15_u64, 30, 60, 120, 240, 240, 240] {
        let d = miraserve_tls::next_ari_error_backoff(&mut streaks, "api.example.test");
        assert_eq!(d, Duration::from_mins(mins));
    }
    Ok(())
}

/// R6-KEYD-1 & R5-KEYD-1: Calling `KeydClient` Unix connect from a `current_thread` Tokio runtime
/// must NEVER panic with nested-runtime error, and a stalled keyd socket must fail cleanly within
/// the configured `io_timeout`.
#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn r6_keyd_1_current_thread_runtime_unix_connect_does_not_panic_and_enforces_timeout()
-> TestResult {
    let provider = build_crypto_provider(true);
    let (ck, _) = generate_dev_certificate(&["ct-keyd.example.test".to_owned()], &provider)?;
    // Codex Round-5 P2: the fixture owns its socket directory. It is made sticky + world-writable
    // like `/tmp` to prove keyd leaves a shared socket parent's mode untouched.
    let sock_dir = std::path::PathBuf::from(format!("/tmp/ms-r6-keyd-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&sock_dir);
    std::fs::create_dir_all(&sock_dir)?;
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&sock_dir, std::fs::Permissions::from_mode(0o1777))?;
    }
    let sock_ok = sock_dir.join("ok.sock");

    let mut store = miraserve_tls::KeydKeyStore::new();
    store.insert_certified_key("ct", vec!["ct-keyd.example.test".to_owned()], true, ck)?;
    let running = miraserve_tls::KeydServer::start(
        miraserve_tls::KeydEndpoint::Unix(sock_ok.clone()),
        store,
        false,
    )
    .await?;

    let sock_stall = sock_dir.join("stall.sock");
    let _ = std::fs::remove_file(&sock_stall);
    let stall_listener = std::os::unix::net::UnixListener::bind(&sock_stall)?;
    let client_stall =
        miraserve_tls::KeydClient::new(miraserve_tls::KeydEndpoint::Unix(sock_stall.clone()))
            .with_io_timeout(Duration::from_millis(120));

    // Exercises the exact `RuntimeFlavor::CurrentThread` branch directly without panicking!
    let started = std::time::Instant::now();
    let stall_res = client_stall.probe_access();
    assert!(
        stall_res.is_err(),
        "R5-KEYD-1/R6-KEYD-1: stalled keyd listener must fail within io_timeout"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "stalled keyd probe hung past io_timeout: {:?}",
        started.elapsed()
    );

    let client_ok =
        miraserve_tls::KeydClient::new(miraserve_tls::KeydEndpoint::Unix(sock_ok.clone()))
            .with_io_timeout(Duration::from_secs(2));
    let ok_count = tokio::task::spawn_blocking(move || client_ok.probe_access()).await??;
    assert_eq!(ok_count, 1);
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&sock_dir)?.permissions().mode() & 0o7777;
        assert_eq!(
            mode, 0o1777,
            "keyd must not chmod a pre-existing sticky shared socket parent, got {mode:04o}"
        );
    }

    drop(stall_listener);
    running.shutdown().await;
    let _ = std::fs::remove_dir_all(&sock_dir);
    Ok(())
}

/// Codex Round-5 P2: private ACME state must never stay in a directory other users can create
/// entries in. A pre-existing sticky world-writable (`1777`) ACME directory is tightened to
/// `0700` (and a legacy `0755` one too).
#[cfg(unix)]
#[test]
fn r5_acme_private_dir_tightens_sticky_and_legacy_modes_to_0700() -> TestResult {
    use std::os::unix::fs::PermissionsExt as _;
    use_private_umask();

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::env::temp_dir().join(format!(
        "miraserve-r5-acme-mode-{}-{nanos}",
        std::process::id()
    ));
    for (name, initial) in [("sticky", 0o1777_u32), ("legacy", 0o755)] {
        let dir = base.join(name);
        std::fs::create_dir_all(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(initial))?;
        miraserve_tls::create_private_dir_all(&dir)?;
        let mode = std::fs::metadata(&dir)?.permissions().mode() & 0o7777;
        assert_eq!(
            mode, 0o700,
            "ACME state dir with initial mode {initial:04o} must become 0700, got {mode:04o}"
        );
    }
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Codex Round-6 P1 #2: `create_private_dir_all` and `AcmeManager` must:
/// 1. tighten and migrate a dedicated legacy directory (mode `0755`),
/// 2. refuse a symlinked leaf (and symlinked intermediate component) BEFORE migration or
///    credential/certificate reads, leaving the target untouched, and
/// 3. return an explicit `Err` on metadata/open failure (`ENOTDIR`, `EACCES`).
#[cfg(unix)]
#[tokio::test]
async fn r6_acme_private_dir_rejects_symlink_leaf_metadata_failure_and_migrates_legacy()
-> TestResult {
    use std::os::unix::fs::PermissionsExt as _;
    use_private_umask();

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base =
        std::env::temp_dir().join(format!("miraserve-r6-acme-{}-{nanos}", std::process::id()));
    let provider = build_crypto_provider(true);
    let challenges = Arc::new(AcmeChallengeStore::new());
    let make_mgr = |state_dir: &std::path::Path| {
        let resolver = Arc::new(DynamicCertResolver::new(Arc::clone(&challenges)));
        let acme_cfg = miraserve_config::AcmeConfig {
            email: "ops@example.test".to_owned(),
            challenge: miraserve_config::AcmeChallenge::TlsAlpn01,
            directory: Some("https://acme-staging-v02.api.letsencrypt.org/directory".to_owned()),
            ari: false,
            short_lived: false,
        };
        miraserve_tls::AcmeManager::new(
            acme_cfg,
            state_dir.to_path_buf(),
            Arc::clone(&challenges),
            resolver,
            Arc::clone(&provider),
        )
    };
    let legacy_json = r#"{"id":"https://acme-staging-v02.api.letsencrypt.org/acme/acct/1","key_pkcs8":"AA==","directory":"https://acme-staging-v02.api.letsencrypt.org/directory"}"#;

    // 1. Dedicated legacy directory (mode 0755) is tightened to 0700 and migrates cleanly.
    let legacy_dir = base.join("legacy-0755");
    std::fs::create_dir_all(&legacy_dir)?;
    std::fs::set_permissions(&legacy_dir, std::fs::Permissions::from_mode(0o755))?;
    std::fs::write(legacy_dir.join("account.json"), legacy_json)?;
    let legacy_mgr = make_mgr(&legacy_dir);
    legacy_mgr.load_cached_certificates(&[]);
    assert_eq!(
        std::fs::symlink_metadata(&legacy_dir)?.permissions().mode() & 0o7777,
        0o700,
        "dedicated legacy ACME state dir must be tightened to 0700"
    );
    assert!(!legacy_dir.join("account.json").exists());
    assert!(legacy_mgr.account_path().is_file());

    // 2. Symlinked leaf pointing to a world-writable 0777 target MUST be refused BEFORE any
    //    chmod, migration, or credential read.
    let linked_target = base.join("world-writable-target");
    std::fs::create_dir_all(&linked_target)?;
    std::fs::set_permissions(&linked_target, std::fs::Permissions::from_mode(0o777))?;
    std::fs::write(linked_target.join("account.json"), legacy_json)?;
    let leaf_link = base.join("acme-leaf-link");
    std::os::unix::fs::symlink(&linked_target, &leaf_link)?;
    assert!(miraserve_tls::create_private_dir_all(&leaf_link).is_err());
    let link_mgr = make_mgr(&leaf_link);
    assert!(link_mgr.load_or_create_account().await.is_err());
    link_mgr.load_cached_certificates(&["example.test".to_owned()]);
    assert!(linked_target.join("account.json").is_file());
    assert_eq!(
        std::fs::symlink_metadata(&linked_target)?
            .permissions()
            .mode()
            & 0o7777,
        0o777,
        "symlinked target directory permissions must not be modified through the link"
    );
    assert!(miraserve_tls::create_private_dir_all(&leaf_link.join("nested-sub")).is_err());
    assert!(!linked_target.join("nested-sub").exists());

    // 3. Metadata/open failure (`ENOTDIR` under a regular file, and `EACCES` under a 0000 parent).
    let file_as_parent = base.join("not-a-dir");
    std::fs::write(&file_as_parent, b"regular file")?;
    assert!(miraserve_tls::create_private_dir_all(&file_as_parent.join("acme")).is_err());

    let locked_parent = base.join("locked-0000");
    std::fs::create_dir_all(&locked_parent)?;
    std::fs::set_permissions(&locked_parent, std::fs::Permissions::from_mode(0o000))?;
    let eacces_res = miraserve_tls::create_private_dir_all(&locked_parent.join("acme"));
    std::fs::set_permissions(&locked_parent, std::fs::Permissions::from_mode(0o700))?;
    let running_as_root = std::fs::read_to_string("/proc/self/status")
        .is_ok_and(|s| s.lines().any(|l| l.starts_with("Uid:\t0\t")));
    if !running_as_root {
        assert!(
            eacces_res.is_err(),
            "EACCES on an unreadable parent must return Err"
        );
    }

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Codex Round-6 P1 #3: a same-UID Unix keyd server in a trusted private runtime directory
/// tightens its parent directory to `0700` and serves clients after authenticating the daemon's
/// UID via `peer_cred`.
#[cfg(unix)]
#[tokio::test]
async fn r6_keyd_trusted_private_parent_tightens_to_0700_and_serves() -> TestResult {
    use std::os::unix::fs::PermissionsExt as _;

    let sock_dir = std::path::PathBuf::from(format!("/tmp/ms-r6-kp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&sock_dir);
    std::fs::create_dir_all(&sock_dir)?;
    std::fs::set_permissions(&sock_dir, std::fs::Permissions::from_mode(0o755))?;
    let sock_path = sock_dir.join("keyd.sock");

    let provider = build_crypto_provider(true);
    let (ck, _) = generate_dev_certificate(&["r6-keyd.example.test".to_owned()], &provider)?;
    let mut store = miraserve_tls::KeydKeyStore::new();
    store.insert_certified_key("priv", vec!["r6-keyd.example.test".to_owned()], true, ck)?;

    let endpoint = miraserve_tls::KeydEndpoint::Unix(sock_path.clone());
    let running = miraserve_tls::KeydServer::start(endpoint.clone(), store, false).await?;

    let mode = std::fs::symlink_metadata(&sock_dir)?.permissions().mode() & 0o7777;
    assert_eq!(
        mode, 0o700,
        "trusted private keyd runtime directory must be tightened to 0700, got {mode:04o}"
    );

    let client = miraserve_tls::KeydClient::new(endpoint);
    let resolver = Arc::new(DynamicCertResolver::new(
        Arc::new(AcmeChallengeStore::new()),
    ));
    let loaded = tokio::task::spawn_blocking(move || client.populate_resolver(&resolver)).await??;
    assert_eq!(
        loaded, 2,
        "same-UID client must authenticate daemon peer_cred and load host + default certs"
    );

    running.shutdown().await;
    let _ = std::fs::remove_dir_all(&sock_dir);
    Ok(())
}

/// Codex Round-7 P2 #2: ACME startup cache loading, `needs_renewal`, and `cached_cert_ari_id`
/// MUST refuse to read certificates when:
/// 1. the ACME state root fails verification (e.g. symlinked root), OR
/// 2. a nested cache entry (`.bundle.pem`, `.crt`, `.key`) is a symlink to external material.
///
/// Manual-TLS `load_certified_key_from_files` MUST continue to follow symlinks (e.g. certbot).
#[cfg(unix)]
#[test]
fn r7_acme_cache_reads_reject_unverified_root_and_nested_symlinks_while_manual_tls_works()
-> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::env::temp_dir().join(format!(
        "miraserve-r7-acme-cache-{}-{nanos}",
        std::process::id()
    ));
    let provider = build_crypto_provider(true);
    let challenges = Arc::new(AcmeChallengeStore::new());
    let domain = "r7-cache.example.test";
    let (_, cert_pem) = generate_dev_certificate(&[domain.to_owned()], &provider)?;

    let make_mgr = |state_dir: &std::path::Path| {
        let resolver = Arc::new(DynamicCertResolver::new(Arc::clone(&challenges)));
        let cfg = miraserve_config::AcmeConfig {
            email: "ops@example.test".to_owned(),
            challenge: miraserve_config::AcmeChallenge::TlsAlpn01,
            directory: Some("https://acme-staging-v02.api.letsencrypt.org/directory".to_owned()),
            ari: false,
            short_lived: false,
        };
        (
            miraserve_tls::AcmeManager::new(
                cfg,
                state_dir.to_path_buf(),
                Arc::clone(&challenges),
                Arc::clone(&resolver),
                Arc::clone(&provider),
            ),
            resolver,
        )
    };

    // 1. Valid cached cert in real state dir; symlinked state root pointing to it MUST be refused.
    let real_state = base.join("real-state");
    let (seed_mgr, _) = make_mgr(&real_state);
    seed_mgr.install_and_persist_certificate_pem(domain, &cert_pem.cert_pem, &cert_pem.key_pem)?;
    let link_root = base.join("link-state");
    std::os::unix::fs::symlink(&real_state, &link_root)?;

    let (rejected_mgr, rejected_resolver) = make_mgr(&link_root);
    rejected_mgr.load_cached_certificates(&[domain.to_owned()]);
    assert!(rejected_resolver.lookup_host(domain).is_none());
    assert!(rejected_mgr.needs_renewal(domain));
    assert!(rejected_mgr.cached_cert_ari_id(domain).is_none());

    // 2. Real state root, but nested `.bundle.pem`/`.crt`/`.key` are symlinks to external files.
    let external = base.join("external");
    std::fs::create_dir_all(&external)?;
    let ext_bundle = external.join("ext.bundle.pem");
    let ext_crt = external.join("ext.crt");
    let ext_key = external.join("ext.key");
    std::fs::write(
        &ext_bundle,
        format!("{}\n{}", cert_pem.key_pem.as_str(), cert_pem.cert_pem),
    )?;
    std::fs::write(&ext_crt, &cert_pem.cert_pem)?;
    std::fs::write(&ext_key, &cert_pem.key_pem)?;

    let nested_state = base.join("nested-symlink-state");
    let (nested_mgr, nested_resolver) = make_mgr(&nested_state);
    let certs_dir = nested_mgr.certs_dir();
    miraserve_tls::create_private_dir_all(&certs_dir)?;
    std::os::unix::fs::symlink(&ext_bundle, certs_dir.join(format!("{domain}.bundle.pem")))?;
    std::os::unix::fs::symlink(&ext_crt, certs_dir.join(format!("{domain}.crt")))?;
    std::os::unix::fs::symlink(&ext_key, certs_dir.join(format!("{domain}.key")))?;

    nested_mgr.load_cached_certificates(&[domain.to_owned()]);
    assert!(nested_resolver.lookup_host(domain).is_none());
    assert!(nested_mgr.needs_renewal(domain));
    assert!(nested_mgr.cached_cert_ari_id(domain).is_none());

    // 3. Manual TLS (`load_certified_key_from_files`) preserves symlink semantics (certbot).
    let certbot_crt = base.join("live-fullchain.pem");
    let certbot_key = base.join("live-privkey.pem");
    std::os::unix::fs::symlink(&ext_crt, &certbot_crt)?;
    std::os::unix::fs::symlink(&ext_key, &certbot_key)?;
    miraserve_tls::load_certified_key_from_files(&certbot_crt, &certbot_key, &provider)?;

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

struct MockAcmeCaHandle {
    directory_url: String,
    ca_cert_pem: String,
    directory_hits: Arc<std::sync::atomic::AtomicUsize>,
    new_account_hits: Arc<std::sync::atomic::AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

#[allow(clippy::too_many_lines)]
async fn spawn_local_mock_acme_ca(
    provider: &Arc<miraserve_tls::CryptoProvider>,
) -> Result<MockAcmeCaHandle, Box<dyn std::error::Error>> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let (ck, pem) =
        generate_dev_certificate(&["127.0.0.1".to_owned(), "localhost".to_owned()], provider)?;
    let resolver = Arc::new(DynamicCertResolver::new(
        Arc::new(AcmeChallengeStore::new()),
    ));
    resolver.set_default(ck);
    let mut server_cfg = rustls::ServerConfig::builder_with_provider(Arc::clone(provider))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    server_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let base_url = format!("https://{addr}");
    let directory_url = format!("{base_url}/directory");
    let directory_hits = Arc::new(AtomicUsize::new(0));
    let new_account_hits = Arc::new(AtomicUsize::new(0));
    let nonce_seq = Arc::new(AtomicUsize::new(1));

    let dir_hits_bg = Arc::clone(&directory_hits);
    let acct_hits_bg = Arc::clone(&new_account_hits);
    let base_bg = base_url.clone();
    let task = tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acc = acceptor.clone();
            let dh = Arc::clone(&dir_hits_bg);
            let ah = Arc::clone(&acct_hits_bg);
            let ns = Arc::clone(&nonce_seq);
            let base_inner = base_bg.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acc.accept(tcp).await else {
                    return;
                };
                let mut req_buf = Vec::with_capacity(2048);
                let mut chunk = [0_u8; 1024];
                let header_end = loop {
                    let Ok(n) = tls.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    if let Some(slice) = chunk.get(..n) {
                        req_buf.extend_from_slice(slice);
                    }
                    if let Some(pos) = req_buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos + 4;
                    }
                    if req_buf.len() > 64 * 1024 {
                        return;
                    }
                };
                let header_text =
                    String::from_utf8_lossy(req_buf.get(..header_end).unwrap_or_default())
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
                    let Ok(n) = tls.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        break;
                    }
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
                    ("HEAD" | "GET", "/new-nonce") => {
                        format!(
                            "HTTP/1.1 200 OK\r\nReplay-Nonce: test-nonce-{nonce}\r\nCache-Control: no-store\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                    }
                    ("POST", "/new-account") => {
                        let acct_num = ah.fetch_add(1, Ordering::SeqCst) + 1;
                        let body = r#"{"status":"valid"}"#;
                        format!(
                            "HTTP/1.1 201 Created\r\nReplay-Nonce: test-nonce-{nonce}\r\nLocation: {base_inner}/acct/{acct_num}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                    }
                    _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_owned(),
                };
                let _ = tls.write_all(resp.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });

    Ok(MockAcmeCaHandle {
        directory_url,
        ca_cert_pem: pem.cert_pem,
        directory_hits,
        new_account_hits,
        task,
    })
}

/// Codex Round-8 P1: ACME accounts written by first registration OR migrated from legacy flat
/// `account.json` MUST be reused by a fresh manager with the same state directory and email
/// (`account-<email hash>.json`), with ZERO second `POST /new-account` request and unchanged
/// credential bytes on disk.
#[tokio::test]
async fn r8_p1_acme_account_reuses_saved_and_migrated_credentials_without_reregistering()
-> TestResult {
    use std::sync::atomic::Ordering;
    use_private_umask();

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::env::temp_dir().join(format!(
        "miraserve-r8-acme-acct-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&base)?;

    let provider = build_crypto_provider(false);
    let ca = spawn_local_mock_acme_ca(&provider).await?;
    let ca_cert_path = base.join("ca.crt");
    std::fs::write(&ca_cert_path, &ca.ca_cert_pem)?;

    let challenges = Arc::new(AcmeChallengeStore::new());
    let make_mgr = |state_dir: &std::path::Path| {
        let resolver = Arc::new(DynamicCertResolver::new(Arc::clone(&challenges)));
        let cfg = miraserve_config::AcmeConfig {
            email: "ops@example.test".to_owned(),
            challenge: miraserve_config::AcmeChallenge::TlsAlpn01,
            directory: Some(ca.directory_url.clone()),
            ari: false,
            short_lived: false,
        };
        miraserve_tls::AcmeManager::new(
            cfg,
            state_dir.to_path_buf(),
            Arc::clone(&challenges),
            resolver,
            Arc::clone(&provider),
        )
        .with_ca_root_pem(&ca_cert_path)
    };

    // 1. First registration creates and persists `account-<email hash>.json`.
    let state_dir = base.join("state");
    let mgr1 = make_mgr(&state_dir);
    let acc1 = mgr1.load_or_create_account().await?;
    assert!(
        acc1.id().ends_with("/acct/1"),
        "expected first registration account URL, got: {}",
        acc1.id()
    );
    assert_eq!(ca.new_account_hits.load(Ordering::SeqCst), 1);
    let saved_bytes = std::fs::read(mgr1.account_path())?;

    // 2. Fresh manager (simulating restart) MUST reuse the saved account with NO second registration.
    let mgr2 = make_mgr(&state_dir);
    let acc2 = mgr2.load_or_create_account().await?;
    assert_eq!(
        acc2.id(),
        acc1.id(),
        "restart must reuse original account ID"
    );
    assert_eq!(
        ca.new_account_hits.load(Ordering::SeqCst),
        1,
        "restart must NOT send a second POST /new-account registration"
    );
    assert!(
        ca.directory_hits.load(Ordering::SeqCst) >= 2,
        "fresh manager must still load directory metadata from the CA"
    );
    assert_eq!(
        std::fs::read(mgr2.account_path())?,
        saved_bytes,
        "stored account credentials must remain unchanged across restart"
    );

    // 3. Legacy flat `account.json` migration MUST also reuse the original account without re-registering.
    let legacy_state = base.join("legacy-state");
    std::fs::create_dir_all(&legacy_state)?;
    std::fs::write(legacy_state.join("account.json"), &saved_bytes)?;
    let mgr3 = make_mgr(&legacy_state);
    let acc3 = mgr3.load_or_create_account().await?;
    assert_eq!(
        acc3.id(),
        acc1.id(),
        "migrated legacy account must reuse original account ID"
    );
    assert_eq!(
        ca.new_account_hits.load(Ordering::SeqCst),
        1,
        "migrated legacy account must NOT trigger a new registration"
    );
    assert!(
        !legacy_state.join("account.json").exists(),
        "legacy flat account.json must be migrated out of root"
    );
    assert_eq!(std::fs::read(mgr3.account_path())?, saved_bytes);

    ca.task.abort();
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Codex Round-8 P2 #2: `KeydClient::with_expected_server_uid` MUST NOT reuse pooled connections
/// authenticated under an earlier policy or share a pool with differently pinned clones.
#[cfg(unix)]
#[tokio::test]
async fn r8_p2_keyd_client_uid_pin_isolates_warm_pool_and_clones() -> TestResult {
    let sock_dir = std::path::PathBuf::from(format!("/tmp/ms-r8-kp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&sock_dir);
    std::fs::create_dir_all(&sock_dir)?;
    let sock_path = sock_dir.join("keyd.sock");

    let provider = build_crypto_provider(true);
    let (ck, _) = generate_dev_certificate(&["r8-pin.example.test".to_owned()], &provider)?;
    let mut store = miraserve_tls::KeydKeyStore::new();
    store.insert_certified_key("pin", vec!["r8-pin.example.test".to_owned()], true, ck)?;

    let endpoint = miraserve_tls::KeydEndpoint::Unix(sock_path.clone());
    let running = miraserve_tls::KeydServer::start(endpoint.clone(), store, false).await?;

    // Warm the default client's pool so it holds a live idle Unix connection.
    let warm_client =
        miraserve_tls::KeydClient::new(endpoint).with_io_timeout(Duration::from_secs(2));
    let warm_probe = warm_client.clone();
    let warm_count = tokio::task::spawn_blocking(move || warm_probe.probe_access()).await??;
    assert_eq!(warm_count, 1);

    let my_uid = std::fs::symlink_metadata(&sock_dir)?;
    let actual_uid = {
        use std::os::unix::fs::MetadataExt as _;
        my_uid.uid()
    };
    let wrong_uid = actual_uid.wrapping_add(12_345).max(1);

    // 1. A clone pinned to a wrong UID MUST NOT reuse `warm_client`'s warmed connection.
    let clone_wrong = warm_client.clone().with_expected_server_uid(wrong_uid);
    let clone_wrong_res = tokio::task::spawn_blocking(move || clone_wrong.probe_access()).await?;
    assert!(
        clone_wrong_res.is_err(),
        "cloned keyd client pinned to a different UID must reject and not reuse the warm pool"
    );

    // 2. Pinning the warmed client itself to a wrong UID MUST fail immediately.
    let self_wrong = warm_client.clone().with_expected_server_uid(wrong_uid);
    let self_wrong_res = tokio::task::spawn_blocking(move || self_wrong.probe_access()).await?;
    assert!(
        self_wrong_res.is_err(),
        "re-pinning a warmed keyd client to a different UID must not reuse its prior pool"
    );

    // 3. Independently pinned clones: matching UID succeeds while mismatched clone still fails.
    let clone_ok = warm_client.clone().with_expected_server_uid(actual_uid);
    let clone_bad = clone_ok.clone().with_expected_server_uid(wrong_uid);
    let ok_res = tokio::task::spawn_blocking(move || clone_ok.probe_access()).await??;
    assert_eq!(ok_res, 1);
    let bad_res = tokio::task::spawn_blocking(move || clone_bad.probe_access()).await?;
    assert!(
        bad_res.is_err(),
        "clone re-pinned away from an authenticated UID must fail"
    );

    running.shutdown().await;
    let _ = std::fs::remove_dir_all(&sock_dir);
    Ok(())
}

/// Codex Round-8 P2 #3: opening a stale FIFO in the ACME state or certs directory MUST NOT block
/// startup, cache lookup, or account loading; it is rejected promptly via `O_NONBLOCK` + `fstat`
/// while ordinary cached certificates continue to load.
#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)]
fn r8_p2_acme_cache_rejects_stale_fifo_promptly_while_loading_valid_cache() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::env::temp_dir().join(format!(
        "miraserve-r8-acme-fifo-{}-{nanos}",
        std::process::id()
    ));
    let provider = build_crypto_provider(false);
    let challenges = Arc::new(AcmeChallengeStore::new());
    let resolver = Arc::new(DynamicCertResolver::new(Arc::clone(&challenges)));
    let cfg = miraserve_config::AcmeConfig {
        email: "fifo@example.test".to_owned(),
        challenge: miraserve_config::AcmeChallenge::TlsAlpn01,
        directory: Some("https://acme-staging-v02.api.letsencrypt.org/directory".to_owned()),
        ari: false,
        short_lived: false,
    };
    let mgr = Arc::new(miraserve_tls::AcmeManager::new(
        cfg,
        base.clone(),
        Arc::clone(&challenges),
        Arc::clone(&resolver),
        Arc::clone(&provider),
    ));

    let good_domain = "good-fifo.example.test";
    let fifo_domain = "stale-fifo.example.test";
    let (_, good_pem) = generate_dev_certificate(&[good_domain.to_owned()], &provider)?;
    mgr.install_and_persist_certificate_pem(good_domain, &good_pem.cert_pem, &good_pem.key_pem)?;

    // Place a stale FIFO with NO writer at `<certs_dir>/<fifo_domain>.bundle.pem` AND at the
    // account credentials path.
    let fifo_bundle = mgr.certs_dir().join(format!("{fifo_domain}.bundle.pem"));
    let fifo_acct = mgr.account_path();
    for fifo_path in [&fifo_bundle, &fifo_acct] {
        let status = std::process::Command::new("mkfifo")
            .arg(fifo_path)
            .status()?;
        assert!(
            status.success(),
            "mkfifo failed for {}",
            fifo_path.display()
        );
    }

    // Codex Round-9 test reliability: arm an independent OS watchdog thread around each probe.
    // If a blocking `open(O_RDONLY)` is ever reintroduced, the watchdog fires after 2s, sets
    // `blocked = true`, and opens the FIFO write end with `O_WRONLY | O_NONBLOCK` to unblock the
    // stuck reader immediately so the test fails deterministically instead of hanging shutdown.
    let run_with_fifo_watchdog = |fifo: &std::path::Path, f: &mut dyn FnMut()| -> bool {
        use std::sync::atomic::{AtomicBool, Ordering};
        let blocked = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        let blocked_bg = Arc::clone(&blocked);
        let finished_bg = Arc::clone(&finished);
        let fifo_bg = fifo.to_path_buf();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let watchdog = std::thread::spawn(move || {
            if done_rx.recv_timeout(Duration::from_secs(2)).is_err() {
                blocked_bg.store(true, Ordering::SeqCst);
                while !finished_bg.load(Ordering::SeqCst) {
                    let _ = rustix::fs::openat(
                        rustix::fs::CWD,
                        &fifo_bg,
                        rustix::fs::OFlags::WRONLY
                            | rustix::fs::OFlags::NONBLOCK
                            | rustix::fs::OFlags::CLOEXEC,
                        rustix::fs::Mode::empty(),
                    );
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        });
        f();
        finished.store(true, Ordering::SeqCst);
        let _ = done_tx.send(());
        let _ = watchdog.join();
        blocked.load(Ordering::SeqCst)
    };

    let mut fifo_needs_renew = false;
    let mut fifo_ari = None;
    let cache_blocked = run_with_fifo_watchdog(&fifo_bundle, &mut || {
        mgr.load_cached_certificates(&[fifo_domain.to_owned(), good_domain.to_owned()]);
        fifo_needs_renew = mgr.needs_renewal(fifo_domain);
        fifo_ari = mgr.cached_cert_ari_id(fifo_domain);
    });
    assert!(
        !cache_blocked,
        "ACME cache reader blocked on stale FIFO until watchdog intervened"
    );
    assert!(
        fifo_needs_renew,
        "stale FIFO cert must be rejected as needing renewal"
    );
    assert!(fifo_ari.is_none(), "stale FIFO cert must yield no ARI id");
    assert!(
        resolver.lookup_host(fifo_domain).is_none(),
        "stale FIFO cert must not be loaded into the resolver"
    );
    assert!(
        resolver.lookup_host(good_domain).is_some(),
        "ordinary cached certificate must still load alongside a stale FIFO"
    );

    // Run `load_or_create_account` on a fresh runtime inside the watchdog-monitored closure so
    // even a synchronous pre-await blocking `open` is deterministically unblocked and caught.
    let mgr_acct = Arc::clone(&mgr);
    let mut acct_is_err = false;
    let acct_blocked = run_with_fifo_watchdog(&fifo_acct, &mut || {
        if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            acct_is_err = rt.block_on(mgr_acct.load_or_create_account()).is_err();
        }
    });
    assert!(
        !acct_blocked,
        "ACME account loader blocked on stale FIFO until watchdog intervened"
    );
    assert!(
        acct_is_err,
        "stale FIFO at account_path must be rejected promptly"
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Fixture directories must not depend on the caller's umask: with Ubuntu's default `0002`
/// they are created group-writable (`0775`), which the private-state ancestor check refuses by
/// design. The stricter value is process-wide and harmless to the other tests.
#[cfg(unix)]
fn use_private_umask() {
    let _ = rustix::process::umask(rustix::fs::Mode::from_bits_truncate(0o022));
}

#[cfg(not(unix))]
fn use_private_umask() {}

/// Review 22: a tenant site's wildcard certificate never answers for a name another site owns
/// (that site falls back to the default certificate), so the tenant's quarantine cannot take
/// a sibling's certificate away; names nobody else owns still use the wildcard.
#[test]
fn tenant_wildcard_skips_names_owned_by_other_sites() -> Result<(), Box<dyn std::error::Error>> {
    let provider = build_crypto_provider(true);
    let (wild_cert, _) = generate_dev_certificate(&["*.example.test".to_owned()], &provider)?;
    let (default_cert, _) = generate_dev_certificate(&["fallback.test".to_owned()], &provider)?;
    let resolver = DynamicCertResolver::new(Arc::new(AcmeChallengeStore::new()));
    let tenant_wildcards = std::collections::HashMap::from([("example.test".to_owned(), 1_usize)]);
    let owners = std::collections::HashMap::from([
        ("panel.example.test".to_owned(), 0_usize),
        ("shop.example.test".to_owned(), 1_usize),
    ]);
    resolver.replace_all_with_owners(
        [("*.example.test".to_owned(), Arc::clone(&wild_cert))],
        Some(Arc::clone(&default_cert)),
        tenant_wildcards,
        owners,
    );
    let panel = resolver
        .lookup_host("panel.example.test")
        .ok_or("panel cert")?;
    assert!(Arc::ptr_eq(&panel, &default_cert), "another site's name");
    let shop = resolver
        .lookup_host("shop.example.test")
        .ok_or("shop cert")?;
    assert!(Arc::ptr_eq(&shop, &wild_cert), "the tenant's own name");
    let other = resolver
        .lookup_host("any.example.test")
        .ok_or("unowned cert")?;
    assert!(Arc::ptr_eq(&other, &wild_cert), "a name no site owns");
    Ok(())
}

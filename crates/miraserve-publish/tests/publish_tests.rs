//! Integration tests for `miraserve-publish`: Ed25519 signing/verification, pre-flight
//! secret/XSS/CSP/quota checks, atomic publish & rollback, retention GC, and MCP JSON-RPC.

// `assert_is_empty` is new in clippy 1.100 and unknown to 1.95 (the minimum toolchain).
// `assert!(x.is_empty())` says what these tests mean.
#![allow(unknown_lints, clippy::assert_is_empty)]

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use http::header::{AUTHORIZATION, HeaderValue};
use http::{HeaderMap, Method, StatusCode};
use http_body_util::BodyExt as _;
use miraserve_config::{
    AiPublishConfig, ByteSize, McpPublishEndpoint, PreflightCheck, PublishAuthMode,
    SignatureAlgorithm, SignatureRequirement,
};
use miraserve_publish::{
    Ed25519SigningKey, McpPublishAuthContext, PublishError, ReleaseStore, SignedBundle, SiteBundle,
    handle_mcp_publish_http,
};
use serde_json::{Value, json};

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
            "miraserve-pub-{tag}-{}-{nanos}",
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

fn make_bundle(html: &str, note: &str, ts: u64) -> SiteBundle {
    let mut files = BTreeMap::new();
    files.insert("index.html".to_owned(), html.as_bytes().to_vec());
    SiteBundle {
        files,
        note: Some(note.to_owned()),
        created_at_unix: ts,
        site_id: None,
    }
}

#[tokio::test]
async fn signed_atomic_publish_rollback_retention_and_tamper_rejection() -> TestResult {
    let tmp = TempDir::new("store")?;
    let key = Ed25519SigningKey::generate()?;
    let pub_key_path = tmp.path.join("deploy-agent.pub");
    fs::write(&pub_key_path, key.verifying_key().to_encoded())?;

    let storage_dir = tmp.path.join("releases-root");
    let cfg = AiPublishConfig {
        storage: storage_dir.to_string_lossy().into_owned(),
        keep_versions: 2,
        site_id: None,
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        require_signature: Some(SignatureRequirement {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_path: pub_key_path.to_string_lossy().into_owned(),
        }),
        preflight_checks: vec![
            PreflightCheck::NoSecrets,
            PreflightCheck::NoInlineScripts,
            PreflightCheck::CspValid,
            PreflightCheck::MaxSize(ByteSize::from_bytes(1024 * 1024)),
            PreflightCheck::MaxFiles(50),
        ],
        mcp_endpoint: Some(McpPublishEndpoint {
            path: "/_miraserve/publish".to_owned(),
            auth: PublishAuthMode::OAuthJwt,
        }),
    };

    let store = ReleaseStore::open(cfg)?;

    // 1. Unsigned bundle rejected
    let unsigned = SignedBundle {
        bundle: make_bundle("<h1>Unsigned</h1>", "bad", 100),
        signature_b64: None,
    };
    assert!(matches!(
        store.publish(&unsigned),
        Err(PublishError::MissingSignature)
    ));

    // 2. Signed then tampered bundle rejected
    let mut tampered = SignedBundle::sign(make_bundle("<h1>Clean</h1>", "v1", 100), &key);
    tampered
        .bundle
        .files
        .insert("index.html".to_owned(), b"<h1>Tampered!</h1>".to_vec());
    assert!(matches!(
        store.publish(&tampered),
        Err(PublishError::InvalidSignature(_))
    ));

    // 3. Publish V1, V2, V3 (retention = 2 keeps V2 & V3, prunes V1)
    let b1 = SignedBundle::sign(make_bundle("<h1>Version 1</h1>", "v1", 101), &key);
    let r1 = store.publish(&b1)?;
    assert!(r1.signature_verified);

    let b2 = SignedBundle::sign(make_bundle("<h1>Version 2</h1>", "v2", 102), &key);
    let r2 = store.publish(&b2)?;

    let b3 = SignedBundle::sign(make_bundle("<h1>Version 3</h1>", "v3", 103), &key);
    let r3 = store.publish(&b3)?;
    assert_eq!(store.list_releases().len(), 2);
    assert_eq!(
        store.active_release().map(|r| r.release_id),
        Some(r3.release_id.clone())
    );

    // Active cap-std static server serves V3
    let srv_v3 = store
        .active_static_server()
        .ok_or("missing active static server")?;
    let resp_v3 = srv_v3.serve(&Method::GET, "/", &HeaderMap::new()).await;
    assert_eq!(
        resp_v3.into_body().collect().await?.to_bytes().as_ref(),
        b"<h1>Version 3</h1>"
    );

    // 4. Instant rollback restores V2 atomically!
    let rolled = store.rollback(None)?;
    assert_eq!(rolled.release_id, r2.release_id);
    let srv_v2 = store
        .active_static_server()
        .ok_or("missing active static server after rollback")?;
    let resp_v2 = srv_v2.serve(&Method::GET, "/", &HeaderMap::new()).await;
    assert_eq!(
        resp_v2.into_body().collect().await?.to_bytes().as_ref(),
        b"<h1>Version 2</h1>"
    );

    Ok(())
}

#[test]
fn preflight_blocks_leaked_secrets_inline_xss_and_unsafe_csp() -> TestResult {
    let tmp = TempDir::new("preflight")?;
    let key = Ed25519SigningKey::generate()?;
    let pub_key_path = tmp.path.join("agent.pub");
    fs::write(&pub_key_path, key.verifying_key().to_encoded())?;

    let store = ReleaseStore::open(AiPublishConfig {
        storage: tmp.path.join("store").to_string_lossy().into_owned(),
        keep_versions: 5,
        site_id: None,
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        require_signature: Some(SignatureRequirement {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_path: pub_key_path.to_string_lossy().into_owned(),
        }),
        preflight_checks: vec![
            PreflightCheck::NoSecrets,
            PreflightCheck::NoInlineScripts,
            PreflightCheck::CspValid,
            PreflightCheck::MaxSize(ByteSize::from_bytes(512)),
        ],
        mcp_endpoint: None,
    })?;

    // Secret leak (Anthropic key)
    let leaked = SignedBundle::sign(
        make_bundle(
            "<p>key=sk-ant-api03-1234567890abcdef1234567890</p>",
            "leak",
            1,
        ),
        &key,
    );
    let Err(PublishError::PreflightFailed(v)) = store.publish(&leaked) else {
        return Err("expected NO_SECRETS preflight rejection".into());
    };
    assert!(v.iter().any(|x| x.rule == "NO_SECRETS"));

    // Inline script XSS injection
    let xss = SignedBundle::sign(
        make_bundle(
            "<html><body><script>fetch('https://evil.test')</script></body></html>",
            "xss",
            2,
        ),
        &key,
    );
    let Err(PublishError::PreflightFailed(v)) = store.publish(&xss) else {
        return Err("expected NO_INLINE_SCRIPTS rejection".into());
    };
    assert!(v.iter().any(|x| x.rule == "NO_INLINE_SCRIPTS"));

    // Unsafe CSP downgrade
    let bad_csp = SignedBundle::sign(
        make_bundle(
            r#"<meta http-equiv="Content-Security-Policy" content="script-src 'unsafe-inline'">"#,
            "csp",
            3,
        ),
        &key,
    );
    let Err(PublishError::PreflightFailed(v)) = store.publish(&bad_csp) else {
        return Err("expected CSP_VALID rejection".into());
    };
    assert!(v.iter().any(|x| x.rule == "CSP_VALID"));

    // Oversize bundle
    let huge = SignedBundle::sign(make_bundle(&"A".repeat(1024), "big", 4), &key);
    let Err(PublishError::PreflightFailed(v)) = store.publish(&huge) else {
        return Err("expected MAX_SIZE rejection".into());
    };
    assert!(v.iter().any(|x| x.rule == "MAX_SIZE"));

    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn mcp_publish_endpoint_enforces_auth_and_executes_publish_and_rollback() -> TestResult {
    let tmp = TempDir::new("mcp")?;
    let key = Ed25519SigningKey::generate()?;
    let pub_key_path = tmp.path.join("agent.pub");
    fs::write(&pub_key_path, key.verifying_key().to_encoded())?;

    let store = ReleaseStore::open(AiPublishConfig {
        storage: tmp.path.join("store").to_string_lossy().into_owned(),
        keep_versions: 10,
        site_id: None,
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        require_signature: Some(SignatureRequirement {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_path: pub_key_path.to_string_lossy().into_owned(),
        }),
        preflight_checks: vec![PreflightCheck::NoSecrets],
        mcp_endpoint: Some(McpPublishEndpoint {
            path: "/_miraserve/publish".to_owned(),
            auth: PublishAuthMode::OAuthJwt,
        }),
    })?;

    let list_req = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    }))?;
    let ctx = McpPublishAuthContext {
        endpoint_path: "/_miraserve/publish",
        site_host: "site.example.test",
        is_https: true,
        verified_client_cert_dn: None,
    };

    // Missing Bearer JWT -> 401 Unauthorized
    let unauth = handle_mcp_publish_http(
        &store,
        PublishAuthMode::OAuthJwt,
        &HeaderMap::new(),
        &list_req,
        &ctx,
    );
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

    // Forged unsigned 3-segment JWT -> MUST be rejected (401)
    let mut forged_headers = HeaderMap::new();
    forged_headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJhZ2VudCJ9.c2ln"),
    );
    let forged_resp = handle_mcp_publish_http(
        &store,
        PublishAuthMode::OAuthJwt,
        &forged_headers,
        &list_req,
        &ctx,
    );
    assert_eq!(forged_resp.status(), StatusCode::UNAUTHORIZED);

    // Valid cryptographically signed EdDSA Bearer JWT -> tools/list succeeds
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let valid_jwt = key.sign_oauth_jwt_with_audience(
        "deploy-agent",
        Some("site.example.test"),
        now_unix + 300,
        Some("publish"),
    );
    let mut auth_headers = HeaderMap::new();
    auth_headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {valid_jwt}"))?,
    );
    let list_resp = handle_mcp_publish_http(
        &store,
        PublishAuthMode::OAuthJwt,
        &auth_headers,
        &list_req,
        &ctx,
    );
    assert_eq!(list_resp.status(), StatusCode::OK);
    let list_json: Value = serde_json::from_slice(list_resp.body())?;
    assert!(
        list_json
            .get("result")
            .and_then(|r| r.get("tools"))
            .is_some()
    );

    // Signed site_publish over MCP JSON-RPC
    let bundle = make_bundle("<h1>Published via MCP</h1>", "agent-deploy", 1_763_541_000);
    let signed = SignedBundle::sign(bundle, &key);
    let pub_req = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "site_publish",
            "arguments": {
                "files": { "index.html": "<h1>Published via MCP</h1>" },
                "note": "agent-deploy",
                "created_at_unix": 1_763_541_000_u64,
                "signature_b64": signed.signature_b64
            }
        }
    }))?;
    let pub_resp = handle_mcp_publish_http(
        &store,
        PublishAuthMode::OAuthJwt,
        &auth_headers,
        &pub_req,
        &ctx,
    );
    assert_eq!(pub_resp.status(), StatusCode::OK);
    let pub_json: Value = serde_json::from_slice(pub_resp.body())?;
    assert!(
        pub_json.get("error").is_none(),
        "unexpected MCP error: {pub_json}"
    );
    assert!(store.active_release().is_some());

    // mTLS mode MUST ignore spoofed `X-Client-Cert-DN` header when TLS context has None
    let mut spoof_mtls = HeaderMap::new();
    spoof_mtls.insert(
        http::header::HeaderName::from_static("x-client-cert-dn"),
        HeaderValue::from_static("CN=admin"),
    );
    let mtls_denied =
        handle_mcp_publish_http(&store, PublishAuthMode::Mtls, &spoof_mtls, &list_req, &ctx);
    assert_eq!(mtls_denied.status(), StatusCode::UNAUTHORIZED);

    // Out-of-band verified mTLS context succeeds
    let mtls_ok_ctx = McpPublishAuthContext {
        endpoint_path: "/_miraserve/publish",
        site_host: "site.example.test",
        is_https: true,
        verified_client_cert_dn: Some("CN=deploy-agent"),
    };
    let mtls_ok = handle_mcp_publish_http(
        &store,
        PublishAuthMode::Mtls,
        &HeaderMap::new(),
        &list_req,
        &mtls_ok_ctx,
    );
    assert_eq!(mtls_ok.status(), StatusCode::OK);

    // Ed25519 mode rejects unsigned tools/list and accepts cryptographically signed request
    let ed_denied = handle_mcp_publish_http(
        &store,
        PublishAuthMode::Ed25519,
        &HeaderMap::new(),
        &list_req,
        &ctx,
    );
    assert_eq!(ed_denied.status(), StatusCode::UNAUTHORIZED);

    let sig_b64 = key.sign_mcp_request(
        "site.example.test",
        "/_miraserve/publish",
        now_unix,
        Some("nonce-1"),
        &list_req,
    );
    let mut ed_headers = HeaderMap::new();
    ed_headers.insert(
        http::header::HeaderName::from_static("x-miraserve-timestamp"),
        HeaderValue::from_str(&now_unix.to_string())?,
    );
    ed_headers.insert(
        http::header::HeaderName::from_static("x-miraserve-nonce"),
        HeaderValue::from_static("nonce-1"),
    );
    ed_headers.insert(
        http::header::HeaderName::from_static("x-miraserve-signature"),
        HeaderValue::from_str(&sig_b64)?,
    );
    let ed_ok = handle_mcp_publish_http(
        &store,
        PublishAuthMode::Ed25519,
        &ed_headers,
        &list_req,
        &ctx,
    );
    assert_eq!(ed_ok.status(), StatusCode::OK);

    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn publish_audit_regressions_manifest_preflight_and_rollback_hardening() -> TestResult {
    // 1. Bijective manifest: note with embedded `file:` line cannot collide with real file entry
    let mut files_a = BTreeMap::new();
    files_a.insert("a.txt".to_owned(), b"1".to_vec());
    let b_note = SiteBundle {
        files: files_a.clone(),
        note: Some("x\nfile:b.txt\t1\t00".to_owned()),
        created_at_unix: 10,
        site_id: None,
    };
    let mut files_b = files_a;
    files_b.insert("b.txt".to_owned(), b"2".to_vec());
    let b_real = SiteBundle {
        files: files_b,
        note: Some("x".to_owned()),
        created_at_unix: 10,
        site_id: None,
    };
    assert_ne!(b_note.canonical_manifest(), b_real.canonical_manifest());

    // 2. Preflight blocks pre-compressed `.gz`, Windows drive `C:evil`, non-UTF-8 HTML,
    //    SVG inline `<script>`, `onfocus`, `srcdoc`, entity-encoded `javascript:`,
    //    `data-x="application/json"` spoof, reversed CSP meta attributes, and invalid-UTF-8 secrets
    let checks = vec![
        PreflightCheck::NoSecrets,
        PreflightCheck::NoInlineScripts,
        PreflightCheck::CspValid,
    ];
    for (name, bytes, expected_rule) in [
        ("index.html.gz", b"gz".as_slice(), "SAFE_PATH"),
        ("C:evil.txt", b"x".as_slice(), "SAFE_PATH"),
        ("bad.html", &[0xFF, 0xFE, b'<', b's'], "NO_INLINE_SCRIPTS"),
        (
            "icon.svg",
            b"<svg onload=\"alert(1)\"></svg>".as_slice(),
            "NO_INLINE_SCRIPTS",
        ),
        (
            "ev.html",
            b"<input onfocus = \"alert(1)\">".as_slice(),
            "NO_INLINE_SCRIPTS",
        ),
        (
            "frame.html",
            b"<iframe srcdoc=\"<script>x</script>\"></iframe>".as_slice(),
            "NO_INLINE_SCRIPTS",
        ),
        (
            "ent.html",
            b"<a href=\"&#x6a;avascript:alert(1)\">x</a>".as_slice(),
            "NO_INLINE_SCRIPTS",
        ),
        (
            "spoof.html",
            b"<script data-x=\"application/json\">alert(1)</script>".as_slice(),
            "NO_INLINE_SCRIPTS",
        ),
        (
            "csp.html",
            b"<meta content=\"default-src 'self' 'unsafe-eval'\" http-equiv=\"Content-Security-Policy\">".as_slice(),
            "CSP_VALID",
        ),
        (
            "secret.bin",
            b"\xffsk-ant-api03-1234567890abcdef1234567890".as_slice(),
            "NO_SECRETS",
        ),
    ] {
        let mut files = BTreeMap::new();
        files.insert(name.to_owned(), bytes.to_vec());
        let bundle = SiteBundle {
            files,
            note: None,
            created_at_unix: 1,
            site_id: None,
        };
        let v = miraserve_publish::run_preflight_checks(&bundle, &checks);
        assert!(
            v.iter().any(|x| x.rule == expected_rule),
            "expected {expected_rule} for {name}, got {v:?}"
        );
    }

    // 3. Rollback refuses unsigned releases when require_signature is enabled
    let tmp = TempDir::new("rollback-sig")?;
    let key = Ed25519SigningKey::generate()?;
    let pub_key_path = tmp.path.join("agent.pub");
    fs::write(&pub_key_path, key.verifying_key().to_encoded())?;
    let storage = tmp.path.join("store");

    // Publish an unsigned release while require_signature is None
    let unsigned_store = ReleaseStore::open(AiPublishConfig {
        storage: storage.to_string_lossy().into_owned(),
        keep_versions: 5,
        site_id: None,
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        require_signature: None,
        preflight_checks: vec![],
        mcp_endpoint: None,
    })?;
    let unsigned_rel = unsigned_store.publish(&SignedBundle {
        bundle: make_bundle("<h1>Unsigned</h1>", "u", 1),
        signature_b64: None,
    })?;
    assert!(!unsigned_rel.signature_verified);

    // Reopen with require_signature enabled -> rollback to unsigned release MUST fail closed!
    let signed_store = ReleaseStore::open(AiPublishConfig {
        storage: storage.to_string_lossy().into_owned(),
        keep_versions: 5,
        site_id: None,
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        require_signature: Some(SignatureRequirement {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_path: pub_key_path.to_string_lossy().into_owned(),
        }),
        preflight_checks: vec![],
        mcp_endpoint: None,
    })?;
    assert!(matches!(
        signed_store.rollback(Some(&unsigned_rel.release_id)),
        Err(PublishError::InvalidSignature(_))
    ));
    // Non-canonical release IDs rejected outright
    assert!(matches!(
        signed_store.rollback(Some("../active.json")),
        Err(PublishError::ReleaseNotFound(_))
    ));

    Ok(())
}

#[allow(clippy::too_many_lines)]
#[test]
fn key_rotation_invalidates_old_releases_and_readonly_open_preserves_concurrent_staging()
-> TestResult {
    let tmp = TempDir::new("rotate-and-staging")?;
    let old_key = Ed25519SigningKey::generate()?;
    let new_key = Ed25519SigningKey::generate()?;
    let old_pub_path = tmp.path.join("old.pub");
    let new_pub_path = tmp.path.join("new.pub");
    fs::write(&old_pub_path, old_key.verifying_key().to_encoded())?;
    fs::write(&new_pub_path, new_key.verifying_key().to_encoded())?;
    let storage = tmp.path.join("store");

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    // 1. Publish V1 signed with `old_key` under `old_pub_path`.
    let old_store = ReleaseStore::open(AiPublishConfig {
        storage: storage.to_string_lossy().into_owned(),
        keep_versions: 5,
        site_id: None,
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        require_signature: Some(SignatureRequirement {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_path: old_pub_path.to_string_lossy().into_owned(),
        }),
        preflight_checks: vec![],
        mcp_endpoint: None,
    })?;
    let v1_rel = old_store.publish(&SignedBundle::sign(
        make_bundle("<h1>Old Key V1</h1>", "v1", now_unix),
        &old_key,
    ))?;
    assert!(v1_rel.signature_verified);
    assert!(v1_rel.signature_b64.is_some());

    // 2. Codex Finding 5: Rotate signing key to `new_key` -> V1 MUST NOT be restored on startup
    //    AND rollback to V1 MUST be rejected with InvalidSignature!
    let rotated_store = ReleaseStore::open(AiPublishConfig {
        storage: storage.to_string_lossy().into_owned(),
        keep_versions: 5,
        site_id: None,
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        require_signature: Some(SignatureRequirement {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_path: new_pub_path.to_string_lossy().into_owned(),
        }),
        preflight_checks: vec![],
        mcp_endpoint: None,
    })?;
    assert!(
        rotated_store.active_release().is_none(),
        "old-key release must NOT be restored after key rotation"
    );
    assert!(matches!(
        rotated_store.rollback(Some(&v1_rel.release_id)),
        Err(PublishError::InvalidSignature(_))
    ));

    // Publishing V2 signed with `new_key` succeeds, and tampering on disk breaks restore!
    let v2_rel = rotated_store.publish(&SignedBundle::sign(
        make_bundle("<h1>New Key V2</h1>", "v2", now_unix.saturating_add(1)),
        &new_key,
    ))?;
    assert!(v2_rel.signature_verified);
    assert!(matches!(
        rotated_store.rollback(Some(&v1_rel.release_id)),
        Err(PublishError::InvalidSignature(_))
    ));

    // Tamper V2 content on disk -> reopening under `new_key` MUST fail cryptographic re-verification!
    let v2_index = storage
        .join("releases")
        .join(&v2_rel.release_id)
        .join("public")
        .join("index.html");
    fs::write(&v2_index, b"<h1>TAMPERED</h1>")?;
    let tampered_store = ReleaseStore::open(AiPublishConfig {
        storage: storage.to_string_lossy().into_owned(),
        keep_versions: 5,
        site_id: None,
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        require_signature: Some(SignatureRequirement {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_path: new_pub_path.to_string_lossy().into_owned(),
        }),
        preflight_checks: vec![],
        mcp_endpoint: None,
    })?;
    assert!(
        tampered_store.active_release().is_none(),
        "tampered release on disk must fail signature verification on activation"
    );

    // 2b. Codex Recheck Finding 5: Legacy pre-manifest release (signature_verified=true,
    //     signature_b64=None) fails closed with actionable `miraserve publish resign` hint;
    //     `resign_release` refuses tampered files and cleanly migrates valid releases!
    // Restore V2's clean index.html, strip signature_b64 to simulate a pre-manifest release.
    let v2_meta_path = storage
        .join("releases")
        .join(&v2_rel.release_id)
        .join("release.json");
    let v2_meta_orig = fs::read_to_string(&v2_meta_path)?;
    // First test tampered file refuses resign_release!
    let mut legacy_v2: serde_json::Value = serde_json::from_str(&v2_meta_orig)?;
    if let Some(obj) = legacy_v2.as_object_mut() {
        obj.remove("signature_b64");
    }
    fs::write(&v2_meta_path, serde_json::to_string_pretty(&legacy_v2)?)?;

    let legacy_store = ReleaseStore::open(AiPublishConfig {
        storage: storage.to_string_lossy().into_owned(),
        keep_versions: 5,
        site_id: None,
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        require_signature: Some(SignatureRequirement {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_path: new_pub_path.to_string_lossy().into_owned(),
        }),
        preflight_checks: vec![],
        mcp_endpoint: None,
    })?;
    assert!(legacy_store.active_release().is_none());
    let legacy_err = legacy_store.rollback(Some(&v2_rel.release_id));
    match legacy_err {
        Err(PublishError::InvalidSignature(msg)) => {
            assert!(
                msg.contains("miraserve publish resign"),
                "expected upgrade hint in error, got: {msg}"
            );
        }
        other => return Err(format!("expected InvalidSignature, got {other:?}").into()),
    }
    // Tampered file still on disk -> resign_release MUST refuse (manifest_sha256 mismatch)!
    assert!(matches!(
        legacy_store.resign_release(&v2_rel.release_id, &new_key),
        Err(PublishError::InvalidSignature(_))
    ));
    // Restore V2's untampered content -> resign_release succeeds and restores activation!
    fs::write(&v2_index, b"<h1>New Key V2</h1>")?;
    // R8-PUB-1: a release with no persisted signature is unsigned whatever its
    // `signature_verified` flag says, so migrating it needs the explicit per-release opt-in.
    assert!(
        legacy_store
            .resign_release(&v2_rel.release_id, &new_key)
            .is_err(),
        "pre-manifest release must not be re-signed without include_unsigned (R8-PUB-1)"
    );
    let resigned = legacy_store.resign_release_with_options(
        &v2_rel.release_id,
        &new_key,
        miraserve_publish::ResignOptions {
            include_unsigned: true,
            old_verifying_key: None,
            rebind_from_site_id: None,
        },
    )?;
    assert!(resigned.signature_b64.is_some());
    let restored = ReleaseStore::open(AiPublishConfig {
        storage: storage.to_string_lossy().into_owned(),
        keep_versions: 5,
        site_id: None,
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        require_signature: Some(SignatureRequirement {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_path: new_pub_path.to_string_lossy().into_owned(),
        }),
        preflight_checks: vec![],
        mcp_endpoint: None,
    })?;
    assert_eq!(
        restored.active_release().map(|r| r.release_id),
        Some(v2_rel.release_id.clone())
    );

    // 3. Codex Recheck Finding 6: OS kernel-backed exclusive lock (`File::try_lock`) MUST NEVER
    //    expire by wall-clock file age, even when a slow publish holds the lock longer than 60s!
    let lock_path = storage.join(".miraserve-store.lock");
    let lock_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;
    lock_file.try_lock()?;
    // Backdate mtime by 2 hours to prove file age is NEVER treated as stale while kernel lock is held!
    let two_hours_ago = SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(7200))
        .ok_or("clock underflow")?;
    lock_file.set_modified(two_hours_ago)?;

    let live_staging = storage.join("releases").join(".staging-live-slow-publish");
    fs::create_dir_all(live_staging.join("public"))?;
    let staged_file = live_staging.join("public").join("index.html");
    fs::write(&staged_file, b"in-flight-slow-publish")?;

    let ro = ReleaseStore::open_read_only(AiPublishConfig {
        storage: storage.to_string_lossy().into_owned(),
        keep_versions: 5,
        site_id: None,
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        require_signature: None,
        preflight_checks: vec![],
        mcp_endpoint: None,
    })?;
    let _ = ro.list_releases();
    assert!(
        staged_file.is_file(),
        "open_read_only/list must NEVER delete in-flight staging directories"
    );

    let _concurrent_open = ReleaseStore::open(AiPublishConfig {
        storage: storage.to_string_lossy().into_owned(),
        keep_versions: 5,
        site_id: None,
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        require_signature: None,
        preflight_checks: vec![],
        mcp_endpoint: None,
    })?;
    assert!(
        staged_file.is_file(),
        "open() during slow (>60s) publish holding OS lock must NOT steal lock or delete staging"
    );

    // Once the live writer drops its OS file handle (exit or crash), `open()` immediately sweeps orphans!
    drop(lock_file);
    let _after_unlock = ReleaseStore::open(AiPublishConfig {
        storage: storage.to_string_lossy().into_owned(),
        keep_versions: 5,
        site_id: None,
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        require_signature: None,
        preflight_checks: vec![],
        mcp_endpoint: None,
    })?;
    assert!(
        !live_staging.exists(),
        "orphaned staging directory should be swept immediately once OS lock is released"
    );

    // 4. Real multi-threaded concurrency test: a live running publisher publishing multi-file
    //    signed bundles while concurrent threads simulate startup/reload (`ReleaseStore::open`)
    //    and `publish list` (`ReleaseStore::open_read_only`) on the SAME storage directory!
    let conc_storage = tmp.path.join("concurrent-live-store");
    let conc_cfg = AiPublishConfig {
        storage: conc_storage.to_string_lossy().into_owned(),
        keep_versions: 10,
        site_id: None,
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        require_signature: Some(SignatureRequirement {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_path: new_pub_path.to_string_lossy().into_owned(),
        }),
        preflight_checks: vec![],
        mcp_endpoint: None,
    };
    let publisher = std::sync::Arc::new(ReleaseStore::open(conc_cfg.clone())?);
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Both readers report their first completed operation, and publishing starts only then:
    // on a loaded machine the publisher could otherwise finish before a reader ran at all,
    // and the test would fail without anything being wrong with concurrent access.
    let started = std::sync::Arc::new(std::sync::Barrier::new(3));

    let done_open = std::sync::Arc::clone(&done);
    let cfg_open = conc_cfg.clone();
    let started_open = std::sync::Arc::clone(&started);
    let reload_thread = std::thread::spawn(move || -> Result<usize, String> {
        let mut opens = 0_usize;
        loop {
            let store = ReleaseStore::open(cfg_open.clone()).map_err(|e| e.to_string());
            let store = match store {
                Ok(store) => store,
                Err(err) => {
                    if opens == 0 {
                        started_open.wait();
                    }
                    return Err(err);
                }
            };
            let _ = store.list_releases();
            opens = opens.saturating_add(1);
            if opens == 1 {
                started_open.wait();
            }
            if done_open.load(std::sync::atomic::Ordering::Acquire) {
                break;
            }
        }
        Ok(opens)
    });

    let done_list = std::sync::Arc::clone(&done);
    let cfg_list = conc_cfg.clone();
    let started_list = std::sync::Arc::clone(&started);
    let list_thread = std::thread::spawn(move || -> Result<usize, String> {
        let mut lists = 0_usize;
        loop {
            let store = ReleaseStore::open_read_only(cfg_list.clone()).map_err(|e| e.to_string());
            let store = match store {
                Ok(store) => store,
                Err(err) => {
                    if lists == 0 {
                        started_list.wait();
                    }
                    return Err(err);
                }
            };
            let _ = store.list_releases();
            lists = lists.saturating_add(1);
            if lists == 1 {
                started_list.wait();
            }
            if done_list.load(std::sync::atomic::Ordering::Acquire) {
                break;
            }
        }
        Ok(lists)
    });
    started.wait();

    let mut published_ids = Vec::new();
    for i in 0..8_u64 {
        let mut files = BTreeMap::new();
        files.insert(
            "index.html".to_owned(),
            format!("<h1>Concurrent Release {i}</h1>").into_bytes(),
        );
        for f_idx in 0..16_u32 {
            files.insert(
                format!("assets/chunk-{f_idx}.txt"),
                format!("release-{i}-chunk-{f_idx}").into_bytes(),
            );
        }
        let bundle = SiteBundle {
            files,
            note: Some(format!("conc-{i}")),
            created_at_unix: now_unix.saturating_add(100).saturating_add(i),
            site_id: None,
        };
        let rel = publisher.publish(&SignedBundle::sign(bundle, &new_key))?;
        published_ids.push(rel.release_id);
    }

    done.store(true, std::sync::atomic::Ordering::Release);
    let reload_opens = reload_thread
        .join()
        .map_err(|_| "reload thread panicked")?
        .map_err(|e| format!("reload thread failed: {e}"))?;
    let list_ops = list_thread
        .join()
        .map_err(|_| "list thread panicked")?
        .map_err(|e| format!("list thread failed: {e}"))?;
    assert!(
        reload_opens > 0,
        "expected concurrent ReleaseStore::open calls"
    );
    assert!(list_ops > 0, "expected concurrent open_read_only calls");
    assert_eq!(published_ids.len(), 8);
    assert_eq!(
        publisher.active_release().map(|r| r.release_id),
        published_ids.last().cloned()
    );

    // 5. R2-PUB-1: `claim_disk_sync_slot` rate-limits background syncs (only 1 slot per second)
    //    and `sync_from_disk` picks up external CLI updates off the hot path while caching failures!
    let observer = ReleaseStore::open(conc_cfg)?;
    assert_eq!(
        observer.active_release().map(|r| r.release_id),
        published_ids.last().cloned()
    );
    assert!(observer.claim_disk_sync_slot());
    assert!(
        !observer.claim_disk_sync_slot(),
        "second immediate claim_disk_sync_slot must be rate-limited"
    );
    observer.release_disk_sync_slot();
    assert!(
        !observer.claim_disk_sync_slot(),
        "claim_disk_sync_slot must stay throttled for >= 1s after release"
    );

    let extra_rel = publisher.publish(&SignedBundle::sign(
        make_bundle(
            "<h1>External CLI Push</h1>",
            "cli-push",
            now_unix.saturating_add(120),
        ),
        &new_key,
    ))?;
    // Pure lock-free hot path does NOT block on disk I/O until `sync_from_disk()` runs:
    assert_ne!(
        observer.active_release().map(|r| r.release_id),
        Some(extra_rel.release_id.clone())
    );
    observer.sync_from_disk();
    assert_eq!(
        observer.active_release().map(|r| r.release_id),
        Some(extra_rel.release_id)
    );

    Ok(())
}

/// R2-PUB-2, R2-PUB-3, R2-PUB-4, R2-PUB-5, R2-PUB-7, R2-PUB-8, PUB-6, PUB-14 regression tests.
#[test]
#[allow(clippy::too_many_lines)]
fn publish_wave2_auth_replay_preflight_resign_and_rollback_hardening() -> TestResult {
    let dir = TempDir::new("wave2-hardening")?;
    let key = Ed25519SigningKey::generate()?;
    let old_key = Ed25519SigningKey::generate()?;
    let pub_path = dir.path.join("pub.pem");
    fs::write(&pub_path, key.verifying_key().to_encoded())?;

    let store = ReleaseStore::open(AiPublishConfig {
        storage: dir.path.join("releases").to_string_lossy().into_owned(),
        keep_versions: 10,
        site_id: None,
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        require_signature: Some(SignatureRequirement {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_path: pub_path.to_string_lossy().into_owned(),
        }),
        preflight_checks: vec![PreflightCheck::NoInlineScripts],
        mcp_endpoint: Some(McpPublishEndpoint {
            path: "/_miraserve/publish".to_owned(),
            auth: PublishAuthMode::OAuthJwt,
        }),
    })?;

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    // 1. R2-PUB-5: All three `no-inline-scripts` bypasses MUST be rejected!
    for (label, html) in [
        ("abrupt-comment", "<!--><script>alert(1)</script>"),
        (
            "rawtext-style-breakout",
            "<style><a title=\"</style><script>alert(1)</script>\"></style>",
        ),
        (
            "semicolonless-numeric-entity",
            "<iframe src=\"&#106avascript:alert(1)\"></iframe>",
        ),
    ] {
        let bad = SignedBundle::sign(make_bundle(html, label, now_unix), &key);
        let res = store.publish(&bad);
        assert!(
            matches!(res, Err(PublishError::PreflightFailed(_))),
            "bypass payload '{label}' MUST fail NoInlineScripts preflight, got: {res:?}"
        );
    }

    // 2. PUB-6: Case-colliding paths, trailing space/dot, and COM0/LPT0 MUST be rejected!
    let mut case_files = BTreeMap::new();
    case_files.insert("Index.html".to_owned(), b"<h1>A</h1>".to_vec());
    case_files.insert("index.html".to_owned(), b"<h1>B</h1>".to_vec());
    let case_bundle = SignedBundle::sign(
        SiteBundle {
            files: case_files,
            note: Some("case-collide".to_owned()),
            created_at_unix: now_unix,
            site_id: None,
        },
        &key,
    );
    assert!(matches!(
        store.publish(&case_bundle),
        Err(PublishError::PreflightFailed(_))
    ));

    for bad_name in ["dir /index.html", "file. ", "COM0.txt", "LPT0"] {
        let mut f = BTreeMap::new();
        f.insert(bad_name.to_owned(), b"x".to_vec());
        let b = SignedBundle::sign(
            SiteBundle {
                files: f,
                note: None,
                created_at_unix: now_unix,
                site_id: None,
            },
            &key,
        );
        assert!(
            matches!(store.publish(&b), Err(PublishError::PreflightFailed(_))),
            "unsafe filename '{bad_name}' must be rejected"
        );
    }

    // 3. PUB-14: Explicit rollback [A, B] -> A must NOT oscillate back to B on next rollback(None)!
    let rel_a = store.publish(&SignedBundle::sign(
        make_bundle("<h1>A</h1>", "a", now_unix + 1),
        &key,
    ))?;
    let _rel_b = store.publish(&SignedBundle::sign(
        make_bundle("<h1>B</h1>", "b", now_unix + 2),
        &key,
    ))?;
    let rb_to_a = store.rollback(Some(&rel_a.release_id))?;
    assert_eq!(rb_to_a.release_id, rel_a.release_id);
    assert!(
        store.rollback(None).is_err(),
        "rollback(None) after rolling back to earliest release A must NOT bounce forward to B"
    );

    // 4. R2-PUB-2: Plaintext HTTP rejected; Ed25519 cross-host rejected; Ed25519 replay rejected!
    let list_req = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    }))?;
    let https_ctx = McpPublishAuthContext {
        endpoint_path: "/_miraserve/publish",
        site_host: "pub.example.test",
        is_https: true,
        verified_client_cert_dn: None,
    };
    let http_ctx = McpPublishAuthContext {
        is_https: false,
        ..https_ctx
    };
    let ed_sig = key.sign_mcp_request(
        "pub.example.test",
        "/_miraserve/publish",
        now_unix,
        Some("nonce-replay-1"),
        &list_req,
    );
    let mut ed_headers = HeaderMap::new();
    ed_headers.insert(
        http::header::HeaderName::from_static("x-miraserve-timestamp"),
        HeaderValue::from_str(&now_unix.to_string())?,
    );
    ed_headers.insert(
        http::header::HeaderName::from_static("x-miraserve-nonce"),
        HeaderValue::from_static("nonce-replay-1"),
    );
    ed_headers.insert(
        http::header::HeaderName::from_static("x-miraserve-signature"),
        HeaderValue::from_str(&ed_sig)?,
    );
    // Plaintext HTTP rejected (401)
    assert_eq!(
        handle_mcp_publish_http(
            &store,
            PublishAuthMode::Ed25519,
            &ed_headers,
            &list_req,
            &http_ctx
        )
        .status(),
        StatusCode::UNAUTHORIZED
    );
    // Cross-host rejected (401)
    let other_host_ctx = McpPublishAuthContext {
        site_host: "other.example.test",
        ..https_ctx
    };
    assert_eq!(
        handle_mcp_publish_http(
            &store,
            PublishAuthMode::Ed25519,
            &ed_headers,
            &list_req,
            &other_host_ctx
        )
        .status(),
        StatusCode::UNAUTHORIZED
    );
    // First HTTPS request succeeds (200)
    assert_eq!(
        handle_mcp_publish_http(
            &store,
            PublishAuthMode::Ed25519,
            &ed_headers,
            &list_req,
            &https_ctx
        )
        .status(),
        StatusCode::OK
    );
    // Exact replay of same Ed25519 signed request MUST be rejected (401)!
    assert_eq!(
        handle_mcp_publish_http(
            &store,
            PublishAuthMode::Ed25519,
            &ed_headers,
            &list_req,
            &https_ctx
        )
        .status(),
        StatusCode::UNAUTHORIZED
    );

    // 5. R2-PUB-3: OAuth JWT enforces `aud`, `<= 3600s` lifetime, and per-tool `scope`!
    let wrong_aud = key.sign_oauth_jwt_with_audience(
        "agent",
        Some("wrong.example.test"),
        now_unix + 300,
        Some("publish"),
    );
    let too_long = key.sign_oauth_jwt_with_audience(
        "agent",
        Some("pub.example.test"),
        now_unix + 7200,
        Some("publish"),
    );
    let no_scope =
        key.sign_oauth_jwt_with_audience("agent", Some("pub.example.test"), now_unix + 300, None);
    for tok in [wrong_aud, too_long, no_scope] {
        let mut h = HeaderMap::new();
        h.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {tok}"))?,
        );
        assert_eq!(
            handle_mcp_publish_http(&store, PublishAuthMode::OAuthJwt, &h, &list_req, &https_ctx)
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    // Read-only scope allows `tools/list` (200) but denies `site_rollback` (403)!
    let read_only_jwt = key.sign_oauth_jwt_with_audience(
        "reader",
        Some("pub.example.test"),
        now_unix + 300,
        Some("publish:read"),
    );
    let mut ro_hdrs = HeaderMap::new();
    ro_hdrs.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {read_only_jwt}"))?,
    );
    assert_eq!(
        handle_mcp_publish_http(
            &store,
            PublishAuthMode::OAuthJwt,
            &ro_hdrs,
            &list_req,
            &https_ctx
        )
        .status(),
        StatusCode::OK
    );
    let rb_call = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": { "name": "site_rollback", "arguments": {} }
    }))?;
    assert_eq!(
        handle_mcp_publish_http(
            &store,
            PublishAuthMode::OAuthJwt,
            &ro_hdrs,
            &rb_call,
            &https_ctx
        )
        .status(),
        StatusCode::FORBIDDEN
    );

    // 6. R2-PUB-8: `site_rollback` with unknown field `{"releaseId":"..."}` MUST fail as invalid params!
    let admin_jwt = key.sign_oauth_jwt_with_audience(
        "admin",
        Some("pub.example.test"),
        now_unix + 300,
        Some("publish:rollback"),
    );
    let mut admin_hdrs = HeaderMap::new();
    admin_hdrs.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {admin_jwt}"))?,
    );
    let typo_rb = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": { "name": "site_rollback", "arguments": { "releaseId": rel_a.release_id } }
    }))?;
    let typo_resp = handle_mcp_publish_http(
        &store,
        PublishAuthMode::OAuthJwt,
        &admin_hdrs,
        &typo_rb,
        &https_ctx,
    );
    let typo_json: Value = serde_json::from_slice(typo_resp.body())?;
    assert_eq!(
        typo_json
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(Value::as_i64),
        Some(-32602),
        "unknown field in site_rollback must return JSON-RPC -32602, got: {typo_json}"
    );

    // 7. R2-PUB-7: `resign_release_with_options` refuses unsigned releases unless `include_unsigned = true`
    //    and verifies `old_verifying_key` when provided!
    let unsigned_dir = TempDir::new("wave2-resign")?;
    let unsigned_store = ReleaseStore::open(AiPublishConfig {
        storage: unsigned_dir
            .path
            .join("releases")
            .to_string_lossy()
            .into_owned(),
        keep_versions: 5,
        site_id: None,
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        require_signature: None,
        preflight_checks: vec![],
        mcp_endpoint: None,
    })?;
    let unsigned_rel = unsigned_store.publish(&SignedBundle {
        bundle: make_bundle("<h1>Unsigned</h1>", "u1", now_unix),
        signature_b64: None,
    })?;
    let old_signed_rel = unsigned_store.publish(&SignedBundle::sign(
        make_bundle("<h1>OldKey</h1>", "s1", now_unix + 1),
        &old_key,
    ))?;

    // Unsigned release refused by default
    assert!(
        unsigned_store
            .resign_release_with_options(
                &unsigned_rel.release_id,
                &key,
                miraserve_publish::ResignOptions::default()
            )
            .is_err()
    );
    // Unsigned release succeeds only with `include_unsigned: true`
    unsigned_store.resign_release_with_options(
        &unsigned_rel.release_id,
        &key,
        miraserve_publish::ResignOptions {
            include_unsigned: true,
            old_verifying_key: None,
            rebind_from_site_id: None,
        },
    )?;
    // Old-signed release fails with wrong `old_verifying_key` and succeeds with matching `old_verifying_key`
    let wrong_old_vk = key.verifying_key();
    assert!(
        unsigned_store
            .resign_release_with_options(
                &old_signed_rel.release_id,
                &key,
                miraserve_publish::ResignOptions {
                    include_unsigned: false,
                    old_verifying_key: Some(&wrong_old_vk),
                    rebind_from_site_id: None,
                }
            )
            .is_err()
    );
    let right_old_vk = old_key.verifying_key();
    unsigned_store.resign_release_with_options(
        &old_signed_rel.release_id,
        &key,
        miraserve_publish::ResignOptions {
            include_unsigned: false,
            old_verifying_key: Some(&right_old_vk),
            rebind_from_site_id: None,
        },
    )?;

    Ok(())
}

/// R3-PUB-1, R3-PUB-2, R3-PUB-3, R3-PUB-5, R3-PUB-6, R3-PUB-7, R2-PUB-8 regressions:
/// - SVG/XML `<title><script>` and HTML `<svg><style><img onerror>` are rejected (`R3-PUB-1`)
/// - `<script type="application/json">` closing-tag breakout, `.hxt`/`.xsl`/`.rss` served MIME types,
///   `<script src="data:,alert(1)">`, DOCTYPE internal subsets, and BOM-less UTF-16 NUL bytes are
///   rejected (`R3-PUB-2`)
/// - Repeated unclosed `<style>` fails fast in linear O(N) time (`R3-PUB-6`)
/// - Unicode case-colliding filenames (`É.html` vs `é.html`) are rejected (`R2-PUB-8`)
/// - Bearer JWT with `jti` works across multi-step `initialize` -> `tools/list` -> `tools/call` (`R3-PUB-3`)
/// - Site-bound stores reject bundles signed for another site, reject equal-timestamp replays,
///   omit `signature_b64` from MCP `site_list_releases`/`site_status`, and reflect external CLI
///   deploys on `site_status` immediately (`R3-PUB-5`, `R3-PUB-7`).
#[test]
#[allow(clippy::too_many_lines)]
fn publish_round3_preflight_site_binding_jti_replay_and_sync_hardening() -> TestResult {
    use base64::Engine as _;

    let checks = vec![
        PreflightCheck::NoSecrets,
        PreflightCheck::NoInlineScripts,
        PreflightCheck::CspValid,
    ];

    // 1. R3-PUB-1 & R3-PUB-2: All reported markup/XML/MIME/encoding bypasses MUST fail preflight!
    let payloads: &[(&str, &[u8], &str)] = &[
        (
            "logo.svg",
            b"<svg xmlns=\"http://www.w3.org/2000/svg\"><title><script>alert(document.domain)</script></title></svg>",
            "NO_INLINE_SCRIPTS",
        ),
        (
            "foreign.html",
            b"<html><body><svg><style><img src=x onerror=alert(1)></style></svg></body></html>",
            "NO_INLINE_SCRIPTS",
        ),
        (
            "json-breakout.html",
            b"<script type=\"application/json\"><a title=\"</script><script>alert(1)</script>\"></script>",
            "NO_INLINE_SCRIPTS",
        ),
        (
            "x.hxt",
            b"<script>alert(1)</script>",
            "NO_INLINE_SCRIPTS",
        ),
        (
            "feed.rss",
            b"<rss><channel><script>alert(1)</script></channel></rss>",
            "NO_INLINE_SCRIPTS",
        ),
        (
            "style.xsl",
            b"<xsl:stylesheet xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"><script>alert(1)</script></xsl:stylesheet>",
            "NO_INLINE_SCRIPTS",
        ),
        (
            "csp.hxt",
            b"<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'unsafe-inline'\">",
            "CSP_VALID",
        ),
        (
            "data-src.html",
            b"<script src=\"data:,alert(1)\"></script>",
            "NO_INLINE_SCRIPTS",
        ),
        (
            "doctype-entity.xml",
            b"<!DOCTYPE x [<!ENTITY s \"<script>alert(1)</script>\">]><x>&s;</x>",
            "NO_INLINE_SCRIPTS",
        ),
        (
            "utf16-bomless.xml",
            b"<\0s\0c\0r\0i\0p\0t\0>\0a\0(\0)\0<\0/\0s\0c\0r\0i\0p\0t\0>\0",
            "NO_INLINE_SCRIPTS",
        ),
    ];
    for &(name, bytes, expected_rule) in payloads {
        let mut files = BTreeMap::new();
        files.insert(name.to_owned(), bytes.to_vec());
        let bundle = SiteBundle {
            files,
            note: None,
            created_at_unix: 1,
            site_id: None,
        };
        let v = miraserve_publish::run_preflight_checks(&bundle, &checks);
        assert!(
            v.iter().any(|x| x.rule == expected_rule),
            "R3-PUB-1/2 payload '{name}' must trigger {expected_rule}, got: {v:?}"
        );
    }

    // Legitimate HTML with safe JSON-LD + external script + clean SVG still passes!
    let clean_bundle = SiteBundle {
        files: BTreeMap::from([
            (
                "index.html".to_owned(),
                b"<!doctype html><html><head><title>Safe</title><style>body{color:#111}</style><script type=\"application/ld+json\">{\"@type\":\"WebSite\"}</script><script src=\"/app.js\"></script></head><body><svg><title>Logo</title><circle r=\"4\"/></svg></body></html>".to_vec(),
            ),
            (
                "logo.svg".to_owned(),
                b"<svg xmlns=\"http://www.w3.org/2000/svg\"><title>Icon</title><rect width=\"10\" height=\"10\"/></svg>".to_vec(),
            ),
        ]),
        note: None,
        created_at_unix: 1,
        site_id: None,
    };
    let clean_v = miraserve_publish::run_preflight_checks(&clean_bundle, &checks);
    assert!(
        clean_v.is_empty(),
        "legitimate markup should pass preflight: {clean_v:?}"
    );

    // 2. R3-PUB-6: 5,000 repeated unclosed `<style>` tags must reject within the 200 ms bound.
    let quad_payload = "<style>".repeat(5_000);
    let quad_bundle = SiteBundle {
        files: BTreeMap::from([("dos.html".to_owned(), quad_payload.into_bytes())]),
        note: None,
        created_at_unix: 1,
        site_id: None,
    };
    let t0 = std::time::Instant::now();
    let quad_v = miraserve_publish::run_preflight_checks(&quad_bundle, &checks);
    assert!(!quad_v.is_empty());
    assert!(
        t0.elapsed() < std::time::Duration::from_millis(200),
        "unclosed <style> scan took {:?} (expected O(N) fast fail)",
        t0.elapsed()
    );

    // 3. R2-PUB-8: Unicode case-colliding paths (`É.html` vs `é.html`) MUST be rejected!
    let unicode_case = SiteBundle {
        files: BTreeMap::from([
            ("\u{00C9}.html".to_owned(), b"<h1>A</h1>".to_vec()),
            ("\u{00E9}.html".to_owned(), b"<h1>B</h1>".to_vec()),
        ]),
        note: None,
        created_at_unix: 1,
        site_id: None,
    };
    let uv = miraserve_publish::run_preflight_checks(&unicode_case, &checks);
    assert!(uv.iter().any(|x| x.rule == "SAFE_PATH"));

    // 4. R3-PUB-5, R3-PUB-3, R3-PUB-7: Site-ID manifest binding, strictly increasing timestamps,
    //    redacted `signature_b64` in MCP responses, multi-request JWT with `jti`, and instant sync on `site_status`.
    let tmp = TempDir::new("r3-pub-store")?;
    let key = Ed25519SigningKey::generate()?;
    let pub_key_path = tmp.path.join("shared.pub");
    fs::write(&pub_key_path, key.verifying_key().to_encoded())?;

    let cfg_a = AiPublishConfig {
        storage: tmp.path.join("site-a").to_string_lossy().into_owned(),
        keep_versions: 3,
        site_id: None,
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        require_signature: Some(SignatureRequirement {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_path: pub_key_path.to_string_lossy().into_owned(),
        }),
        preflight_checks: checks,
        mcp_endpoint: None,
    };
    let store_a =
        ReleaseStore::open_for_site(cfg_a.clone(), Some("site-a.example.test".to_owned()))?;
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    // Bundle signed for `site-b.example.test` (or unbound `site_id: None`) MUST be rejected by `site-a`!
    let mut b_for_b = make_bundle("<h1>Site B</h1>", "b", now_unix);
    b_for_b.site_id = Some("site-b.example.test".to_owned());
    assert!(matches!(
        store_a.publish(&SignedBundle::sign(b_for_b, &key)),
        Err(PublishError::InvalidSignature(_))
    ));
    let b_unbound = make_bundle("<h1>Unbound</h1>", "u", now_unix);
    assert!(matches!(
        store_a.publish(&SignedBundle::sign(b_unbound, &key)),
        Err(PublishError::InvalidSignature(_))
    ));

    // Bundle signed for `site-a.example.test` succeeds; re-publishing with EQUAL timestamp fails (`R3-PUB-5`)!
    let mut b_a1 = make_bundle("<h1>Site A v1</h1>", "a1", now_unix);
    b_a1.site_id = Some("site-a.example.test".to_owned());
    let signed_a1 = SignedBundle::sign(b_a1, &key);
    let rel_a1 = store_a.publish(&signed_a1)?;
    assert!(rel_a1.signature_b64.is_some());
    assert!(
        matches!(
            store_a.publish(&signed_a1),
            Err(PublishError::InvalidSignature(_))
        ),
        "equal-timestamp bundle replay must be rejected (R3-PUB-5)"
    );

    // R3-PUB-3: Bearer JWT carrying a `jti` claim MUST work across `initialize`, `tools/list`, AND `tools/call`!
    let jwt_hdr =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
    let jwt_payload =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({
            "sub": "ci-agent",
            "aud": "site-a.example.test",
            "iat": now_unix,
            "exp": now_unix + 600,
            "jti": "session-token-12345",
            "scope": "publish:read"
        }))?);
    let jwt_sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(key.sign(format!("{jwt_hdr}.{jwt_payload}").as_bytes()));
    let jti_jwt = format!("{jwt_hdr}.{jwt_payload}.{jwt_sig}");

    let mut jwt_headers = HeaderMap::new();
    jwt_headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {jti_jwt}"))?,
    );
    let ctx = McpPublishAuthContext {
        endpoint_path: "/_miraserve/publish",
        site_host: "site-a.example.test",
        is_https: true,
        verified_client_cert_dn: None,
    };
    let init_body =
        serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize" }))?;
    let list_body = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": { "name": "site_list_releases", "arguments": {} }
    }))?;
    let status_body = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": { "name": "site_status", "arguments": {} }
    }))?;

    let r1 = handle_mcp_publish_http(
        &store_a,
        PublishAuthMode::OAuthJwt,
        &jwt_headers,
        &init_body,
        &ctx,
    );
    assert_eq!(
        r1.status(),
        StatusCode::OK,
        "initialize with jti JWT failed"
    );
    let r2 = handle_mcp_publish_http(
        &store_a,
        PublishAuthMode::OAuthJwt,
        &jwt_headers,
        &list_body,
        &ctx,
    );
    assert_eq!(
        r2.status(),
        StatusCode::OK,
        "second request with same jti JWT must succeed (R3-PUB-3)"
    );
    let r2_json: Value = serde_json::from_slice(r2.body())?;
    let listed = r2_json
        .get("result")
        .and_then(|v| v.get("structuredContent"))
        .and_then(|v| v.get("releases"))
        .and_then(Value::as_array)
        .ok_or("missing releases array")?;
    assert_eq!(listed.len(), 1);
    let first_listed = listed.first().ok_or("missing first release")?;
    // R3-PUB-5: `signature_b64` MUST be omitted from MCP `site_list_releases`!
    assert!(
        first_listed.get("signature_b64").is_none(),
        "site_list_releases must omit signature_b64, got: {first_listed}"
    );

    // R3-PUB-7: External CLI publish updates disk; `site_status` reflects it immediately without static traffic!
    let external_cli = ReleaseStore::open_for_site(cfg_a, Some("site-a.example.test".to_owned()))?;
    let mut b_a2 = make_bundle("<h1>Site A v2 (CLI)</h1>", "a2", now_unix + 1);
    b_a2.site_id = Some("site-a.example.test".to_owned());
    let rel_a2 = external_cli.publish(&SignedBundle::sign(b_a2, &key))?;

    let r3 = handle_mcp_publish_http(
        &store_a,
        PublishAuthMode::OAuthJwt,
        &jwt_headers,
        &status_body,
        &ctx,
    );
    assert_eq!(r3.status(), StatusCode::OK);
    let r3_json: Value = serde_json::from_slice(r3.body())?;
    let active_obj = r3_json
        .get("result")
        .and_then(|v| v.get("structuredContent"))
        .and_then(|v| v.get("active"))
        .ok_or("missing active object in site_status")?;
    assert_eq!(
        active_obj.get("release_id").and_then(Value::as_str),
        Some(rel_a2.release_id.as_str()),
        "site_status must immediately sync external CLI deploys from disk (R3-PUB-7)"
    );
    assert!(
        active_obj.get("signature_b64").is_none(),
        "site_status must omit signature_b64 (R3-PUB-5)"
    );

    Ok(())
}

/// R4-PUB-1, R4-PUB-4, R4-PUB-6: Real HTML5 (`html5ever`) + strict XML (`roxmltree`, DTD refused)
/// preflight scanner regressions covering all reported bypass families, safe passive data/importmap
/// pages, and O(N) linear-time behavior on adversarial unclosed tokens.
#[test]
#[allow(clippy::too_many_lines)]
fn publish_round4_html5ever_roxmltree_scanner_regressions() {
    let checks = vec![
        PreflightCheck::NoSecrets,
        PreflightCheck::NoInlineScripts,
        PreflightCheck::CspValid,
    ];

    // 1. R4-PUB-1: Every reported HTML5 / SVG / MathML / XML / SMIL bypass MUST fail preflight!
    let bypasses: &[(&str, &str)] = &[
        (
            "svg-close-math.html",
            r"<svg></math><style><img src=x onerror=alert(1)></style>",
        ),
        (
            "svg-foreignobject.html",
            r#"<svg><foreignObject><style><a title="</style><img src=x onerror=alert(1)>">"#,
        ),
        (
            "svg-desc.html",
            r#"<svg><desc><style><a title="</style><img src=x onerror=alert(1)>">"#,
        ),
        (
            "svg-title.html",
            r#"<svg><title><style><a title="</style><img src=x onerror=alert(1)>">"#,
        ),
        (
            "math-mtext.html",
            r#"<math><mtext><style><a title="</style><img src=x onerror=alert(1)>">"#,
        ),
        (
            "math-annotation-xml.html",
            r#"<math><annotation-xml encoding="text/html"><style><a title="</style><img src=x onerror=alert(1)>">"#,
        ),
        (
            "svg-p-breakout.html",
            r#"<svg><p><style><a title="</style><img src=x onerror=alert(1)>">"#,
        ),
        (
            "svg-prefixed.html",
            r#"<svg:svg><style><a title="</style><img src=x onerror=alert(1)>">"#,
        ),
        (
            "svg-dot.html",
            r#"<svg.x><style><a title="</style><img src=x onerror=alert(1)>">"#,
        ),
        (
            "script-double-escaped.html",
            r#"<script type="application/json"><!--<script></script><a title="</script><img src=x onerror=alert(1)>">"#,
        ),
        (
            "svg-json-script-html.html",
            r#"<svg><script type="application/json"><x y="</script><a title='"></x></script><img src=x onerror=alert(1)>'>"#,
        ),
        (
            "bogus-pi-html.html",
            r"<?x > <img src=x onerror=alert(1)> ?>",
        ),
        (
            "end-tag-quote.html",
            r#"</a title="><x y='"><img src=x onerror=alert(1)>'>"#,
        ),
        (
            "tag-name-quote.html",
            r"<p'x=' ><img src=x onerror=alert(1)>'>",
        ),
        (
            "doctype-system-gt.svg",
            r#"<!DOCTYPE svg SYSTEM "x><a b='" [<!ENTITY e "<script>alert(1)</script>"><!--'>-->]><svg xmlns="http://www.w3.org/2000/svg">&e;</svg>"#,
        ),
        (
            "doctype-system-gt.html",
            r#"<!DOCTYPE svg SYSTEM "x><a b='" [<!ENTITY e "<script>alert(1)</script>"><!--'>-->]><svg xmlns="http://www.w3.org/2000/svg">&e;</svg>"#,
        ),
        (
            "svg-json-xml-comment.svg",
            r#"<svg xmlns="http://www.w3.org/2000/svg"><script type="application/json"><!-- comment -->{}</script></svg>"#,
        ),
        (
            "smil-animate-values.svg",
            r#"<svg xmlns="http://www.w3.org/2000/svg"><a><animate attributeName="href" values="0;javascript:alert(1)"/></a></svg>"#,
        ),
        (
            "smil-animate-values.html",
            r#"<!doctype html><html><body><svg><a><animate attributeName="href" values="0;javascript:alert(1)"/></a></svg></body></html>"#,
        ),
        (
            "noscript-hidden-xss.html",
            r"<!doctype html><html><body><noscript><img src=x onerror=alert(1)></noscript></body></html>",
        ),
        (
            "template-script.html",
            r"<!doctype html><html><body><template><script>alert(1)</script></template></body></html>",
        ),
        (
            "active-anchor-svg-data.html",
            r#"<!doctype html><html><body><a href="data:image/svg+xml,<svg onload=alert(1)>">click</a></body></html>"#,
        ),
        (
            "active-iframe-svg-data.html",
            r#"<!doctype html><html><body><iframe src="data:image/svg+xml,<svg/>"></iframe></body></html>"#,
        ),
        (
            "evil-importmap.html",
            r#"<!doctype html><html><head><script type="importmap">{"imports":{"x":"data:text/javascript,alert(1)"}}</script></head><body></body></html>"#,
        ),
        (
            "xml-stylesheet-pi.xml",
            r#"<?xml-stylesheet type="text/xsl" href="evil.xsl"?><root/>"#,
        ),
    ];

    for &(name, payload) in bypasses {
        let bundle = SiteBundle {
            files: BTreeMap::from([(name.to_owned(), payload.as_bytes().to_vec())]),
            note: None,
            created_at_unix: 1,
            site_id: None,
        };
        let v = miraserve_publish::run_preflight_checks(&bundle, &checks);
        assert!(
            v.iter().any(|x| x.rule == "NO_INLINE_SCRIPTS"),
            "R4-PUB-1 payload '{name}' MUST fail NO_INLINE_SCRIPTS, got: {v:?}"
        );
    }

    // 2. R4-PUB-4: Ordinary safe pages using `<img src="data:image/svg+xml,...">`,
    //    `<link rel="icon" href="data:image/svg+xml,...">`, safe `importmap`, and safe
    //    `speculationrules` MUST PASS!
    let safe_html = concat!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Safe</title>",
        "<link rel=\"icon\" href=\"data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'/%3E\">",
        "<script type=\"importmap\">{\"imports\":{\"app\":\"/assets/app.js\"}}</script>",
        "<script type=\"speculationrules\">{\"prerender\":[{\"source\":\"list\",\"urls\":[\"/about\"]}]}</script>",
        "</head><body><img src=\"data:image/svg+xml;base64,PHN2Zy8+\" alt=\"logo\"></body></html>"
    );
    let safe_bundle = SiteBundle {
        files: BTreeMap::from([("index.html".to_owned(), safe_html.as_bytes().to_vec())]),
        note: None,
        created_at_unix: 1,
        site_id: None,
    };
    let safe_v = miraserve_publish::run_preflight_checks(&safe_bundle, &checks);
    assert!(
        safe_v.is_empty(),
        "R4-PUB-4 safe HTML page should pass preflight, got: {safe_v:?}"
    );

    // 3. R4-PUB-6: Repeated `<!--` and repeated `</script ` must fail in linear O(N) time (< 200ms)!
    for (name, content) in [
        ("comments.html", "<!--".repeat(5_000)),
        (
            "script-close.html",
            format!(
                "<script type=\"application/json\">{}",
                "</script ".repeat(5_000)
            ),
        ),
    ] {
        let dos_bundle = SiteBundle {
            files: BTreeMap::from([(name.to_owned(), content.into_bytes())]),
            note: None,
            created_at_unix: 1,
            site_id: None,
        };
        let t0 = std::time::Instant::now();
        let v = miraserve_publish::run_preflight_checks(&dos_bundle, &checks);
        assert!(!v.is_empty(), "R4-PUB-6 malformed '{name}' must fail");
        assert!(
            t0.elapsed() < std::time::Duration::from_millis(200),
            "R4-PUB-6 '{name}' took {:?} (expected linear O(N) time)",
            t0.elapsed()
        );
    }
}

/// R4-PUB-2, R4-PUB-3, R4-PUB-5 & §4 Q4 regressions:
/// - Stored legacy v2 signed releases (no `site_id`) remain activatable on startup and rollback
///   under a site-bound store (preventing 503 outage on upgrade, `R4-PUB-2`), while network
///   `publish()` still rejects unbound v2 bundles and cross-site v3 bundles!
/// - Explicit stable `site_id` overrides host order (`R4-PUB-3`).
/// - Dedicated `jwt_public_key` + `jwt_issuer` authenticates Bearer JWTs separately from bundle
///   `require-signature` key, and `allowed_subjects` restricts mTLS certificates (§4 Q4).
/// - `publish_with_options(..., allow_timestamp_reset = true)` recovers cleanly after a forward
///   clock-skew publish (`R4-PUB-5`).
#[test]
#[allow(clippy::too_many_lines)]
fn publish_round4_wave2b_v2_upgrade_site_id_auth_separation_and_timestamp_reset() -> TestResult {
    use base64::Engine as _;

    let tmp = TempDir::new("r4-w2b")?;
    let bundle_key = Ed25519SigningKey::generate()?;
    let jwt_key = Ed25519SigningKey::generate()?;
    let bundle_pub_path = tmp.path.join("bundle.pub");
    let jwt_pub_path = tmp.path.join("jwt.pub");
    fs::write(&bundle_pub_path, bundle_key.verifying_key().to_encoded())?;
    fs::write(&jwt_pub_path, jwt_key.verifying_key().to_encoded())?;

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    // 1. R4-PUB-2: Create a legacy v2 signed release (no site_id) on disk, then reopen the store
    //    with an explicit v3 `site_id` -> startup restore AND rollback MUST succeed without 503!
    let upgrade_storage = tmp.path.join("v2-upgrade");
    let v2_store = ReleaseStore::open(AiPublishConfig {
        storage: upgrade_storage.to_string_lossy().into_owned(),
        site_id: None,
        keep_versions: 5,
        require_signature: Some(SignatureRequirement {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_path: bundle_pub_path.to_string_lossy().into_owned(),
        }),
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        preflight_checks: vec![PreflightCheck::NoSecrets],
        mcp_endpoint: None,
    })?;
    let v2_r1 = v2_store.publish(&SignedBundle::sign(
        make_bundle("<h1>Legacy V2 Release 1</h1>", "v2-r1", now_unix - 10),
        &bundle_key,
    ))?;
    let v2_r2 = v2_store.publish(&SignedBundle::sign(
        make_bundle("<h1>Legacy V2 Release 2</h1>", "v2-r2", now_unix - 5),
        &bundle_key,
    ))?;

    // Upgrade to v3 with explicit stable `site_id = "prod-docs"`
    let v3_cfg = AiPublishConfig {
        storage: upgrade_storage.to_string_lossy().into_owned(),
        site_id: Some("prod-docs".to_owned()),
        keep_versions: 5,
        require_signature: Some(SignatureRequirement {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_path: bundle_pub_path.to_string_lossy().into_owned(),
        }),
        jwt_public_key: Some(format!("ed25519:{}", jwt_pub_path.display())),
        jwt_issuer: Some("https://idp.example.test".to_owned()),
        allowed_subjects: vec!["O=Corp, CN=deploy-bot".to_owned()],
        preflight_checks: vec![PreflightCheck::NoSecrets],
        mcp_endpoint: Some(McpPublishEndpoint {
            path: "/_miraserve/publish".to_owned(),
            auth: PublishAuthMode::OAuthJwt,
        }),
    };
    let v3_store = ReleaseStore::open_for_site(v3_cfg, Some("fallback-host.example".to_owned()))?;
    // Explicit config `site_id` overrides fallback host (`R4-PUB-3`)!
    assert_eq!(v3_store.expected_site_id(), Some("prod-docs"));
    // Startup restored legacy v2 active release cleanly (zero 503 outage, `R4-PUB-2`)!
    assert_eq!(
        v3_store.active_release().map(|r| r.release_id),
        Some(v2_r2.release_id)
    );
    // Rollback to earlier stored legacy v2 release ALSO succeeds cleanly!
    let rolled = v3_store.rollback(Some(&v2_r1.release_id))?;
    assert_eq!(rolled.release_id, v2_r1.release_id);
    // Network `publish()` STILL rejects an unscoped v2 bundle (`site_id: None`)!
    assert!(matches!(
        v3_store.publish(&SignedBundle::sign(
            make_bundle("<h1>Unbound</h1>", "u", now_unix),
            &bundle_key,
        )),
        Err(PublishError::InvalidSignature(_))
    ));

    // 2. §4 Q4: Dedicated `jwt_public_key` + `jwt_issuer` verifies Bearer JWTs separately from
    //    `require-signature` bundle key!
    let list_req = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    }))?;
    let ctx = McpPublishAuthContext {
        endpoint_path: "/_miraserve/publish",
        site_host: "prod-docs",
        is_https: true,
        verified_client_cert_dn: None,
    };
    let sign_jwt = |sk: &Ed25519SigningKey,
                    iss: Option<&str>,
                    aud: &str|
     -> Result<String, Box<dyn std::error::Error>> {
        let hdr = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
        let mut claims = json!({
            "sub": "ci-deployer",
            "aud": aud,
            "iat": now_unix,
            "exp": now_unix + 300,
            "scope": "publish:read"
        });
        if let Some(i) = iss
            && let Some(obj) = claims.as_object_mut()
        {
            obj.insert("iss".to_owned(), Value::String(i.to_owned()));
        }
        let payload =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sk.sign(format!("{hdr}.{payload}").as_bytes()));
        Ok(format!("{hdr}.{payload}.{sig}"))
    };
    // Token signed by bundle key (NOT dedicated jwt_key) -> MUST be rejected (401)!
    let wrong_key_tok = sign_jwt(&bundle_key, Some("https://idp.example.test"), "prod-docs")?;
    let mut h_wrong_key = HeaderMap::new();
    h_wrong_key.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {wrong_key_tok}"))?,
    );
    assert_eq!(
        handle_mcp_publish_http(
            &v3_store,
            PublishAuthMode::OAuthJwt,
            &h_wrong_key,
            &list_req,
            &ctx,
        )
        .status(),
        StatusCode::UNAUTHORIZED
    );
    // Token signed by jwt_key with WRONG `iss` -> MUST be rejected (401)!
    let wrong_iss_tok = sign_jwt(&jwt_key, Some("https://evil-idp.test"), "prod-docs")?;
    let mut h_wrong_iss = HeaderMap::new();
    h_wrong_iss.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {wrong_iss_tok}"))?,
    );
    assert_eq!(
        handle_mcp_publish_http(
            &v3_store,
            PublishAuthMode::OAuthJwt,
            &h_wrong_iss,
            &list_req,
            &ctx,
        )
        .status(),
        StatusCode::UNAUTHORIZED
    );
    // Token signed by dedicated jwt_key with matching `iss` and `aud="prod-docs"` -> 200 OK!
    let good_tok = sign_jwt(&jwt_key, Some("https://idp.example.test"), "prod-docs")?;
    let mut h_good = HeaderMap::new();
    h_good.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {good_tok}"))?,
    );
    assert_eq!(
        handle_mcp_publish_http(
            &v3_store,
            PublishAuthMode::OAuthJwt,
            &h_good,
            &list_req,
            &ctx,
        )
        .status(),
        StatusCode::OK
    );

    // 3. §4 Q4: mTLS `allowed_subjects` blocks unauthorized subject under same CA (`403`) and
    //    allows exact DN / RDN match (`200`)!
    let bad_subj_ctx = McpPublishAuthContext {
        verified_client_cert_dn: Some("O=Corp, CN=untrusted-laptop"),
        ..ctx
    };
    assert_eq!(
        handle_mcp_publish_http(
            &v3_store,
            PublishAuthMode::Mtls,
            &HeaderMap::new(),
            &list_req,
            &bad_subj_ctx,
        )
        .status(),
        StatusCode::FORBIDDEN
    );
    let ok_subj_ctx = McpPublishAuthContext {
        verified_client_cert_dn: Some("O=Corp, CN=deploy-bot"),
        ..ctx
    };
    assert_eq!(
        handle_mcp_publish_http(
            &v3_store,
            PublishAuthMode::Mtls,
            &HeaderMap::new(),
            &list_req,
            &ok_subj_ctx,
        )
        .status(),
        StatusCode::OK
    );

    // 4. R4-PUB-5: Recover from a future-skewed (+200s) publish watermark via `allow_timestamp_reset`!
    let mut skewed = make_bundle("<h1>Skewed</h1>", "skew", now_unix + 200);
    skewed.site_id = Some("prod-docs".to_owned());
    let _ = v3_store.publish(&SignedBundle::sign(skewed, &bundle_key))?;
    // Normal publish at `now_unix` is blocked by the +200s watermark
    let mut normal = make_bundle("<h1>Normal</h1>", "norm", now_unix);
    normal.site_id = Some("prod-docs".to_owned());
    let signed_normal = SignedBundle::sign(normal, &bundle_key);
    assert!(matches!(
        v3_store.publish(&signed_normal),
        Err(PublishError::InvalidSignature(_))
    ));
    // Explicit `allow_timestamp_reset = true` succeeds and resets the watermark so `now_unix + 1` works!
    let recovered = v3_store.publish_with_options(&signed_normal, true)?;
    assert_eq!(recovered.bundle_created_at_unix, now_unix);
    let mut next_b = make_bundle("<h1>Next</h1>", "next", now_unix + 1);
    next_b.site_id = Some("prod-docs".to_owned());
    let next_rel = v3_store.publish(&SignedBundle::sign(next_b, &bundle_key))?;
    assert_eq!(next_rel.bundle_created_at_unix, now_unix + 1);

    Ok(())
}

/// Round 5 Wave 2 publish security regressions (`R5-PUB-1, 2, 3, 4, 6, 7, 11, 12`):
/// - `R5-PUB-1`: Changing `site-id` with stored v3 releases fails resign without `--rebind-site-id`,
///   succeeds with `rebind_site_id: true` after verifying old signature; startup falls back to
///   newest valid release when `active_release_id` fails verification.
/// - `R5-PUB-2`: RFC 4514 escaped comma in CN (`CN=laptop\, CN\=deploy-bot`) and partial single-RDN
///   `O=Corp` do NOT spoof `allowed_subjects`.
/// - `R5-PUB-3`: `verify_oauth_jwt` rejects `oauth-jwt` calls when `require_signature` is absent.
/// - `R5-PUB-4`: Bounded pre-upgrade legacy-v2 allowlist accepts pre-existing v2 release until
///   re-signed, while rejecting a newly planted foreign v2 release signed by the same key.
/// - `R5-PUB-6`: `resign --include-unsigned` STILL refuses already-signed releases without
///   valid `old_verifying_key` verification.
/// - `R5-PUB-7`: Ed25519 request replay cache persists across `ReleaseStore` reopens (hot reloads).
/// - `R5-PUB-11`: `--allow-timestamp-reset` writes a structured JSON entry to `<storage>/audit.log`.
/// - `R5-PUB-12`: Preflight checks are re-run on activation/rollback and resign.
#[test]
#[allow(clippy::too_many_lines)]
fn publish_round5_wave2_site_id_rebind_x509_dn_v2_allowlist_replay_and_preflight() -> TestResult {
    let tmp = TempDir::new("r5w2-publish")?;
    let storage = tmp.path.join("releases");
    let pub_path = tmp.path.join("bundle.pub");
    let jwt_pub_path = tmp.path.join("jwt.pub");
    let bundle_key = Ed25519SigningKey::generate()?;
    let jwt_key = Ed25519SigningKey::generate()?;
    let new_bundle_key = Ed25519SigningKey::generate()?;
    let new_pub_path = tmp.path.join("new-bundle.pub");
    fs::write(&pub_path, bundle_key.verifying_key().to_encoded())?;
    fs::write(&jwt_pub_path, jwt_key.verifying_key().to_encoded())?;
    fs::write(&new_pub_path, new_bundle_key.verifying_key().to_encoded())?;

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    // 1. R5-PUB-1: Publish v3 release under old `site-id = "old-site.example"`, then switch config
    //    to `site-id = "new-site.example"`. Resign WITHOUT `rebind_site_id` MUST fail; resign
    //    WITH `rebind_site_id: true` + `old_verifying_key` migrates cleanly!
    let mut cfg = AiPublishConfig {
        storage: storage.to_string_lossy().into_owned(),
        site_id: Some("old-site.example".to_owned()),
        keep_versions: 5,
        require_signature: Some(SignatureRequirement {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_path: pub_path.to_string_lossy().into_owned(),
        }),
        jwt_public_key: Some(format!("ed25519:{}", jwt_pub_path.display())),
        jwt_issuer: None,
        allowed_subjects: vec!["O=Corp, CN=deploy-bot".to_owned()],
        preflight_checks: vec![PreflightCheck::NoSecrets, PreflightCheck::NoInlineScripts],
        mcp_endpoint: Some(McpPublishEndpoint {
            path: "/_miraserve/publish".to_owned(),
            auth: PublishAuthMode::Ed25519,
        }),
    };
    let old_store = ReleaseStore::open_for_site(cfg.clone(), Some("old-site.example".to_owned()))?;
    let mut b1 = make_bundle("<h1>Site V1</h1>", "v1", now_unix - 10);
    b1.site_id = Some("old-site.example".to_owned());
    let rel1 = old_store.publish(&SignedBundle::sign(b1, &bundle_key))?;

    // Switch site-id to "new-site.example": active release is bound to old-site.example -> fails open
    cfg.site_id = Some("new-site.example".to_owned());
    let new_store = ReleaseStore::open_for_site(cfg.clone(), Some("new-site.example".to_owned()))?;
    assert!(new_store.active_release().is_none());

    // Resign without `rebind_site_id` refuses cross-site rebinding!
    let old_vk = bundle_key.verifying_key();
    assert!(
        new_store
            .resign_all_with_options(
                &bundle_key,
                miraserve_publish::ResignOptions {
                    include_unsigned: false,
                    old_verifying_key: Some(&old_vk),
                    rebind_from_site_id: None,
                },
            )
            .is_err()
    );
    // Resign WITH `rebind_site_id: true` verifies old signature and migrates to new-site.example!
    let rebound = new_store.resign_all_with_options(
        &bundle_key,
        miraserve_publish::ResignOptions {
            include_unsigned: false,
            old_verifying_key: Some(&old_vk),
            rebind_from_site_id: Some("old-site.example"),
        },
    )?;
    assert_eq!(rebound.len(), 1);
    assert_eq!(
        rebound.first().and_then(|r| r.site_id.as_deref()),
        Some("new-site.example")
    );
    assert_eq!(
        new_store.active_release().map(|m| m.release_id),
        Some(rel1.release_id.clone())
    );

    // 1b. R5-PUB-1 startup fallback: publish valid V2, then corrupt V2's on-disk signature so active
    //     fails on open; fresh `open_for_site` MUST automatically fall back to valid V1!
    let mut b2 = make_bundle("<h1>Site V2</h1>", "v2", now_unix - 5);
    b2.site_id = Some("new-site.example".to_owned());
    let rel2 = new_store.publish(&SignedBundle::sign(b2, &bundle_key))?;
    let rel2_meta_path = storage
        .join("releases")
        .join(&rel2.release_id)
        .join("release.json");
    let mut rel2_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&rel2_meta_path)?)?;
    if let Some(obj) = rel2_json.as_object_mut() {
        obj.insert(
            "site_id".to_owned(),
            serde_json::Value::String("wrong-site.example".to_owned()),
        );
    }
    fs::write(&rel2_meta_path, serde_json::to_string_pretty(&rel2_json)?)?;
    let fallback_store =
        ReleaseStore::open_for_site(cfg.clone(), Some("new-site.example".to_owned()))?;
    assert_eq!(
        fallback_store.active_release().map(|m| m.release_id),
        Some(rel1.release_id.clone()),
        "startup must fall back to newest valid release when active fails (R5-PUB-1)"
    );

    // 2. R5-PUB-2: RFC 4514 escaped comma CN and partial single-RDN MUST be rejected (403)!
    let list_body = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": "site_list_releases", "arguments": {} }
    }))?;
    let base_ctx = McpPublishAuthContext {
        endpoint_path: "/_miraserve/publish",
        site_host: "new-site.example",
        is_https: true,
        verified_client_cert_dn: None,
    };
    for spoofed_dn in [
        r"CN=laptop\, CN\=deploy-bot",
        r"O=Corp, CN=laptop\, CN\=deploy-bot",
        "O=Corp",
        "CN=deploy-bot",
        "O=Corp, CN=attacker",
    ] {
        let spoof_ctx = McpPublishAuthContext {
            verified_client_cert_dn: Some(spoofed_dn),
            ..base_ctx
        };
        assert_eq!(
            handle_mcp_publish_http(
                &fallback_store,
                PublishAuthMode::Mtls,
                &HeaderMap::new(),
                &list_body,
                &spoof_ctx,
            )
            .status(),
            StatusCode::FORBIDDEN,
            "spoofed/partial DN '{spoofed_dn}' must be rejected with 403 (R5-PUB-2)"
        );
    }

    // 3. R5-PUB-3: `auth="oauth-jwt"` MUST reject calls when `require_signature` is absent!
    let mut no_sig_cfg = cfg.clone();
    no_sig_cfg.require_signature = None;
    let no_sig_store =
        ReleaseStore::open_for_site(no_sig_cfg, Some("new-site.example".to_owned()))?;
    let jwt = jwt_key.sign_oauth_jwt_with_audience(
        "agent",
        Some("new-site.example"),
        now_unix + 300,
        Some("publish:read"),
    );
    let mut jwt_hdrs = HeaderMap::new();
    jwt_hdrs.insert(AUTHORIZATION, format!("Bearer {jwt}").parse()?);
    assert_eq!(
        handle_mcp_publish_http(
            &no_sig_store,
            PublishAuthMode::OAuthJwt,
            &jwt_hdrs,
            &list_body,
            &base_ctx,
        )
        .status(),
        StatusCode::UNAUTHORIZED,
        "oauth-jwt must fail closed when require_signature is unset (R5-PUB-3)"
    );

    // 4. R5-PUB-7: Ed25519 replay cache persists across store reopen (simulating SIGHUP reload)!
    let mut ed_hdrs = HeaderMap::new();
    let ts_str = now_unix.to_string();
    let nonce = "r5-reload-nonce-001";
    let sig_b64 = bundle_key.sign_mcp_request(
        "new-site.example",
        "/_miraserve/publish",
        now_unix,
        Some(nonce),
        &list_body,
    );
    ed_hdrs.insert("x-miraserve-timestamp", ts_str.parse()?);
    ed_hdrs.insert("x-miraserve-nonce", nonce.parse()?);
    ed_hdrs.insert("x-miraserve-signature", sig_b64.parse()?);
    assert_eq!(
        handle_mcp_publish_http(
            &fallback_store,
            PublishAuthMode::Ed25519,
            &ed_hdrs,
            &list_body,
            &base_ctx,
        )
        .status(),
        StatusCode::OK
    );
    // Reopen a brand-new ReleaseStore (like Router::from_config on SIGHUP reload): replay MUST fail!
    let reloaded_store =
        ReleaseStore::open_for_site(cfg.clone(), Some("new-site.example".to_owned()))?;
    assert_eq!(
        handle_mcp_publish_http(
            &reloaded_store,
            PublishAuthMode::Ed25519,
            &ed_hdrs,
            &list_body,
            &base_ctx,
        )
        .status(),
        StatusCode::UNAUTHORIZED,
        "replayed Ed25519 request must STILL be rejected after hot reload (R5-PUB-7)"
    );

    // 5. R5-PUB-6: `resign --include-unsigned` with `old_verifying_key: None` MUST reject an
    //    already-signed release signed under an old key!
    let mut rotated_cfg = cfg.clone();
    rotated_cfg.require_signature = Some(SignatureRequirement {
        algorithm: SignatureAlgorithm::Ed25519,
        public_key_path: new_pub_path.to_string_lossy().into_owned(),
    });
    let rotated_store =
        ReleaseStore::open_for_site(rotated_cfg, Some("new-site.example".to_owned()))?;
    assert!(
        rotated_store
            .resign_release_with_options(
                &rel1.release_id,
                &new_bundle_key,
                miraserve_publish::ResignOptions {
                    include_unsigned: true,
                    old_verifying_key: None,
                    rebind_from_site_id: None,
                },
            )
            .is_err(),
        "resign --include-unsigned must NEVER skip old-key verification on already-signed releases (R5-PUB-6)"
    );

    // 6. R5-PUB-4: Bounded legacy-v2 allowlist accepts pre-upgrade v2 release and rejects planted v2!
    let v2_storage = tmp.path.join("v2-upgrade-store");
    let v2_cfg = AiPublishConfig {
        storage: v2_storage.to_string_lossy().into_owned(),
        site_id: None,
        keep_versions: 5,
        require_signature: Some(SignatureRequirement {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_path: pub_path.to_string_lossy().into_owned(),
        }),
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        preflight_checks: vec![PreflightCheck::NoSecrets],
        mcp_endpoint: None,
    };
    let legacy_open = ReleaseStore::open(v2_cfg.clone())?;
    let existing_v2 = legacy_open.publish(&SignedBundle::sign(
        make_bundle("<h1>Pre-Upgrade V2</h1>", "pre-v2", now_unix - 20),
        &bundle_key,
    ))?;
    // Upgrade to v3 site-bound store: snapshots `existing_v2` into `legacy-v2-allowlist.json`
    let v3_upgraded =
        ReleaseStore::open_for_site(v2_cfg.clone(), Some("upgraded.example".to_owned()))?;
    assert_eq!(
        v3_upgraded.active_release().map(|m| m.release_id),
        Some(existing_v2.release_id.clone())
    );
    // Simulate an attacker planting a second foreign v2 release (signed by same key!) into releases/
    let foreign_storage = tmp.path.join("foreign-v2");
    let mut foreign_cfg = v2_cfg.clone();
    foreign_cfg.storage = foreign_storage.to_string_lossy().into_owned();
    let foreign_store = ReleaseStore::open(foreign_cfg)?;
    let planted_v2 = foreign_store.publish(&SignedBundle::sign(
        make_bundle("<h1>Planted Foreign V2</h1>", "planted", now_unix - 15),
        &bundle_key,
    ))?;
    let src_dir = foreign_storage
        .join("releases")
        .join(&planted_v2.release_id);
    let dst_dir = v2_storage.join("releases").join(&planted_v2.release_id);
    fs::create_dir_all(dst_dir.join("public"))?;
    fs::copy(src_dir.join("release.json"), dst_dir.join("release.json"))?;
    fs::copy(
        src_dir.join("public/index.html"),
        dst_dir.join("public/index.html"),
    )?;
    assert!(
        v3_upgraded.rollback(Some(&planted_v2.release_id)).is_err(),
        "newly planted foreign v2 release NOT in legacy-v2-allowlist.json MUST be rejected (R5-PUB-4)"
    );
    // After resigning `existing_v2` to v3, its ID is removed from legacy-v2-allowlist.json!
    v3_upgraded.resign_release_with_options(
        &existing_v2.release_id,
        &bundle_key,
        miraserve_publish::ResignOptions {
            include_unsigned: false,
            old_verifying_key: Some(&old_vk),
            rebind_from_site_id: None,
        },
    )?;
    let allowlist_raw = fs::read_to_string(v2_storage.join("legacy-v2-allowlist.json"))?;
    assert!(
        !allowlist_raw.contains(&existing_v2.release_id),
        "re-signed v2 release must be removed from legacy-v2-allowlist.json: {allowlist_raw}"
    );

    // 7. R5-PUB-11: `--allow-timestamp-reset` writes an explicit audit entry to `audit.log`!
    let mut future_b = make_bundle("<h1>Future</h1>", "fut", now_unix + 180);
    future_b.site_id = Some("upgraded.example".to_owned());
    let _ = v3_upgraded.publish(&SignedBundle::sign(future_b, &bundle_key))?;
    let mut reset_b = make_bundle("<h1>Reset</h1>", "rst", now_unix);
    reset_b.site_id = Some("upgraded.example".to_owned());
    let _ = v3_upgraded.publish_with_options(&SignedBundle::sign(reset_b, &bundle_key), true)?;
    let audit_log = fs::read_to_string(v2_storage.join("audit.log"))?;
    assert!(
        audit_log.contains("timestamp_watermark_reset"),
        "expected audit.log entry for timestamp watermark reset (R5-PUB-11), got: {audit_log}"
    );

    // 8. R5-PUB-12: Re-running preflight on activation & resign blocks previously-published HTML
    //    with inline script once `NoInlineScripts` is enabled!
    let mut inline_b = make_bundle("<h1>Old</h1><script>alert(1)</script>", "xss", now_unix + 1);
    inline_b.site_id = Some("upgraded.example".to_owned());
    let inline_rel = v3_upgraded.publish(&SignedBundle::sign(inline_b, &bundle_key))?;
    let mut stricter_cfg = v2_cfg;
    stricter_cfg.preflight_checks =
        vec![PreflightCheck::NoSecrets, PreflightCheck::NoInlineScripts];
    let stricter_store =
        ReleaseStore::open_for_site(stricter_cfg, Some("upgraded.example".to_owned()))?;
    assert!(
        matches!(
            stricter_store.rollback(Some(&inline_rel.release_id)),
            Err(PublishError::PreflightFailed(_))
        ),
        "rollback/activation must re-run preflight checks (R5-PUB-12)"
    );
    assert!(
        matches!(
            stricter_store.resign_release_with_options(
                &inline_rel.release_id,
                &bundle_key,
                miraserve_publish::ResignOptions {
                    include_unsigned: false,
                    old_verifying_key: Some(&old_vk),
                    rebind_from_site_id: None,
                }
            ),
            Err(PublishError::PreflightFailed(_))
        ),
        "resign must re-run preflight checks (R5-PUB-12)"
    );

    Ok(())
}

/// Round 5 Wave 3 scanner regressions (`R5-PUB-8, 9, 10, 13, 14`):
/// - `R5-PUB-8`: nested `<div>` hits the depth cap within 5 s (best of 3), 50k
///   foster-parented `<table><i></i>` completes within 10 s, and `max-size` short-circuits
///   markup scanning.
/// - `R5-PUB-9`: Ordinary valid pages pass without false positives (XHTML 1.0 DOCTYPE, `a < b`,
///   `&nbsp`, `<div/>`, duplicate `class`, stray `</p>`, nested `<a>`, empty `.html`,
///   `data:image/svg+xml` in `srcset`/`poster`/SVG `<image>`, `<script type="text/template">`,
///   `img-src 'self' data:` + `style-src 'self' 'unsafe-inline'` CSP, and subset-less SVG PUBLIC
///   DOCTYPE); `script-src https: http: blob:` CSP is rejected; errors report line numbers.
/// - `R5-PUB-10`: Cross-origin `<script src>`, cross-origin `<base href>`, and cross-origin SVG
///   `<script href>` are rejected while same-origin relative `<script src="/app.js">` passes.
/// - `R5-PUB-13`: Spec-compliant `<meta http-equiv="refresh">` catches `url = javascript:` and
///   no-`URL=` / comma-delimited executable refresh URLs.
/// - `R5-PUB-14`: Namespaced XHTML `<script x:type="application/json">` is NOT mistaken for `type`.
#[test]
#[allow(clippy::too_many_lines)]
fn publish_round5_wave3_scanner_perf_false_positives_script_policy_and_refresh() {
    let checks = vec![
        PreflightCheck::NoSecrets,
        PreflightCheck::NoInlineScripts,
        PreflightCheck::CspValid,
    ];

    // 1. R5-PUB-8: deeply nested `<div>` must hit the depth cap within the 5 s bound.
    let nested_divs = "<div>".repeat(210_000);
    assert!(nested_divs.len() > 1_000_000);
    let div_bundle = SiteBundle {
        files: BTreeMap::from([("nested.html".to_owned(), nested_divs.into_bytes())]),
        note: None,
        created_at_unix: 1,
        site_id: None,
    };
    // Keep the functional assertion on every run, and check the wall-clock bound using the best
    // of three runs so a single scheduler stall on a loaded or emulated host cannot cause a
    // spurious timeout failure.
    let mut div_elapsed = std::time::Duration::MAX;
    for _ in 0..3 {
        let t0 = std::time::Instant::now();
        let div_v = miraserve_publish::run_preflight_checks(&div_bundle, &checks);
        div_elapsed = div_elapsed.min(t0.elapsed());
        assert!(
            div_v
                .iter()
                .any(|v| v.rule == "NO_INLINE_SCRIPTS" && v.detail.contains("depth")),
            "expected depth limit violation, got: {div_v:?}"
        );
    }
    // Best-of-3 wall-clock bound (5 s) to tolerate unoptimised builds on loaded hosts.
    assert!(
        div_elapsed < std::time::Duration::from_secs(5),
        "1 MB nested <div> took {div_elapsed:?} at best of 3 (expected well under 5 s, R5-PUB-8)"
    );

    // 1b. R5-PUB-8: Foster-parenting `<table>` + `<i></i>` x 50k completes within the 10 s bound.
    let foster = format!("<table>{}</table>", "<i></i>".repeat(50_000));
    let foster_bundle = SiteBundle {
        files: BTreeMap::from([("foster.html".to_owned(), foster.into_bytes())]),
        note: None,
        created_at_unix: 1,
        site_id: None,
    };
    let t1 = std::time::Instant::now();
    let _ = miraserve_publish::run_preflight_checks(&foster_bundle, &checks);
    let foster_elapsed = t1.elapsed();
    assert!(
        foster_elapsed < std::time::Duration::from_secs(10),
        "foster-parented table took {foster_elapsed:?} (expected O(N), R5-PUB-8)"
    );

    // 1c. R5-PUB-8: `max-size` failure short-circuits markup scanning!
    let mut checks_with_cap = checks.clone();
    checks_with_cap.push(PreflightCheck::MaxSize(
        miraserve_config::ByteSize::from_bytes(64),
    ));
    let oversize_xss = SiteBundle {
        files: BTreeMap::from([(
            "big.html".to_owned(),
            format!("<script>alert(1)</script>{}", "a".repeat(200)).into_bytes(),
        )]),
        note: None,
        created_at_unix: 1,
        site_id: None,
    };
    let cap_v = miraserve_publish::run_preflight_checks(&oversize_xss, &checks_with_cap);
    assert!(cap_v.iter().any(|v| v.rule == "MAX_SIZE"));
    assert!(
        !cap_v.iter().any(|v| v.rule == "NO_INLINE_SCRIPTS"),
        "markup scan should be skipped once max-size already failed (R5-PUB-8): {cap_v:?}"
    );

    // 2. R5-PUB-9: Ordinary valid real-world pages MUST PASS with ZERO false positives!
    let ordinary_cases: &[(&str, &str)] = &[
        ("empty.html", ""),
        (
            "xhtml1-transitional.html",
            r#"<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"><html><head><title>Legacy</title></head><body><p>a < b and x < 5 &nbsp</p><div/><i class="fa"/><div class="a" class="b">ok</div></p><a href="/1"><a href="/2">nested</a></a></body></html>"#,
        ),
        (
            "passive-svg-data-and-template.html",
            concat!(
                "<!doctype html><html><head>",
                "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:\">",
                "<base href=\"/docs/\">",
                "<script src=\"/assets/app.js\"></script>",
                "<script type=\"text/template\"><div class=\"card\">{{title}}</div></script>",
                "</head><body>",
                "<picture><source srcset=\"data:image/svg+xml;base64,PHN2Zy8+ 1x, /img/hero.webp 2x\"><img srcset=\"data:image/svg+xml,%3Csvg/%3E 1x\" src=\"/img/a.png\"></picture>",
                "<video poster=\"data:image/svg+xml;base64,PHN2Zy8+\"></video>",
                "<svg><image href=\"data:image/svg+xml;base64,PHN2Zy8+\"/></svg>",
                "<meta http-equiv=\"refresh\" content=\"5; url=/next\">",
                "</body></html>"
            ),
        ),
        (
            "w3c-public-doctype.svg",
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg"><image href="data:image/svg+xml;base64,PHN2Zy8+"/><circle r="10"/></svg>"#,
        ),
    ];
    for &(name, content) in ordinary_cases {
        let bundle = SiteBundle {
            files: BTreeMap::from([(name.to_owned(), content.as_bytes().to_vec())]),
            note: None,
            created_at_unix: 1,
            site_id: None,
        };
        let v = miraserve_publish::run_preflight_checks(&bundle, &checks);
        assert!(
            v.is_empty(),
            "R5-PUB-9 ordinary page '{name}' had false positive violations: {v:?}"
        );
    }

    // 2b. R5-PUB-9: Weakened `script-src https: http: blob:` CSP MUST be rejected!
    let weak_csp = SiteBundle {
        files: BTreeMap::from([(
            "csp.html".to_owned(),
            br#"<!doctype html><html><head><meta http-equiv="Content-Security-Policy" content="script-src https: http: blob:"></head><body></body></html>"#.to_vec(),
        )]),
        note: None,
        created_at_unix: 1,
        site_id: None,
    };
    let weak_csp_violations = miraserve_publish::run_preflight_checks(&weak_csp, &checks);
    assert!(
        weak_csp_violations
            .iter()
            .any(|v| v.rule == "CSP_VALID" && v.detail.contains("line ")),
        "expected CSP_VALID rejection with line number for script-src https: http: blob:, got: {weak_csp_violations:?}"
    );

    // 3. R5-PUB-10, R5-PUB-13, R5-PUB-14: Reject cross-origin scripts, cross-origin <base>,
    //    spec-tricky meta refresh, and namespaced XHTML `x:type`!
    let blocked_cases: &[(&str, &str)] = &[
        (
            "cross-origin-script.html",
            r#"<!doctype html><html><head><script src="https://evil.example/x.js"></script></head><body></body></html>"#,
        ),
        (
            "proto-rel-script.html",
            r#"<!doctype html><html><head><script src="//evil.example/x.js"></script></head><body></body></html>"#,
        ),
        (
            "cross-origin-base.html",
            r#"<!doctype html><html><head><base href="https://evil.example/"><script src="app.js"></script></head><body></body></html>"#,
        ),
        (
            "svg-cross-origin-script.svg",
            r#"<svg xmlns="http://www.w3.org/2000/svg"><script href="https://evil.example/x.js"/></svg>"#,
        ),
        (
            "refresh-spaced-url.html",
            r#"<!doctype html><html><head><meta http-equiv="refresh" content="0; url = javascript:alert(1)"></head><body></body></html>"#,
        ),
        (
            "refresh-no-url-keyword.html",
            r#"<!doctype html><html><head><meta http-equiv="refresh" content="0; javascript:alert(1)"></head><body></body></html>"#,
        ),
        (
            "refresh-comma-data.html",
            r#"<!doctype html><html><head><meta http-equiv="refresh" content="0, data:text/html,<script>alert(1)</script>"></head><body></body></html>"#,
        ),
        (
            "xhtml-namespaced-type.xhtml",
            r#"<html xmlns="http://www.w3.org/1999/xhtml" xmlns:x="http://evil.example/ns"><head><script x:type="application/json">{}</script></head><body/></html>"#,
        ),
    ];
    for &(name, payload) in blocked_cases {
        let bundle = SiteBundle {
            files: BTreeMap::from([(name.to_owned(), payload.as_bytes().to_vec())]),
            note: None,
            created_at_unix: 1,
            site_id: None,
        };
        let v = miraserve_publish::run_preflight_checks(&bundle, &checks);
        assert!(
            v.iter()
                .any(|x| x.rule == "NO_INLINE_SCRIPTS" && x.detail.contains("line ")),
            "Wave 3 payload '{name}' MUST fail NO_INLINE_SCRIPTS with line info, got: {v:?}"
        );
    }
}

/// R6-PUB-1: Backslash scheme-relative URLs (`\/host/x.js`), `<base href="\/host/">`, SVG
/// `<script href="\/host/x.js">`, and cross-origin `xml:base` are rejected using WHATWG URL
/// resolution against two distinct dummy origins.
#[test]
fn r6_pub_1_blocks_backslash_scheme_relative_urls_and_cross_origin_xml_base() {
    let checks = vec![PreflightCheck::NoInlineScripts];
    let cases: &[(&str, &str, &str)] = &[
        (
            "script-backslash.html",
            r#"<!doctype html><html><head><script src="\/127.0.0.1:8772/x.js"></script></head><body></body></html>"#,
            "same-origin relative path",
        ),
        (
            "base-backslash.html",
            r#"<!doctype html><html><head><base href="\/127.0.0.1:8772/"><script src="app.js"></script></head><body></body></html>"#,
            "<base href>",
        ),
        (
            "svg-in-html-backslash.html",
            r#"<!doctype html><html><body><svg><script href="\/127.0.0.1:8772/x.js"></script></svg></body></html>"#,
            "same-origin relative path",
        ),
        (
            "svg-xml-base.svg",
            r#"<svg xmlns="http://www.w3.org/2000/svg" xml:base="https://evil.example/"><script href="x.js"/></svg>"#,
            "xml:base",
        ),
        (
            "script-dummy-host.html",
            r#"<!doctype html><html><head><script src="https://origin-a.miraserve.invalid/x.js"></script></head><body></body></html>"#,
            "same-origin relative path",
        ),
    ];
    for &(name, payload, expected_reason) in cases {
        let bundle = SiteBundle {
            files: BTreeMap::from([(name.to_owned(), payload.as_bytes().to_vec())]),
            note: None,
            created_at_unix: 1,
            site_id: None,
        };
        let v = miraserve_publish::run_preflight_checks(&bundle, &checks);
        assert!(
            v.iter()
                .any(|x| x.rule == "NO_INLINE_SCRIPTS" && x.detail.contains(expected_reason)),
            "R6-PUB-1 '{name}' must fail with reason containing '{expected_reason}', got: {v:?}"
        );
    }

    // Positive control: relative same-origin script and base pass cleanly.
    let ok = SiteBundle {
        files: BTreeMap::from([(
            "ok.html".to_owned(),
            br#"<!doctype html><html><head><base href="/sub/"><script src="assets/app.js?v=1"></script></head><body></body></html>"#.to_vec(),
        )]),
        note: None,
        created_at_unix: 1,
        site_id: None,
    };
    assert!(miraserve_publish::run_preflight_checks(&ok, &checks).is_empty());
}

/// R6-PUB-2: Every `src`, `href`, and `xlink:href` attribute on every `<script>` (both inside
/// HTML `<svg>` and standalone `.svg`) is validated so a benign first attribute cannot mask a
/// cross-origin second attribute.
#[test]
fn r6_pub_2_checks_every_script_url_attribute_on_svg_and_html() {
    let checks = vec![PreflightCheck::NoInlineScripts];
    let cases: &[(&str, &str)] = &[
        (
            "svg-xlink-and-href.html",
            r#"<!doctype html><html><body><svg><script xlink:href="ok.js" href="https://evil.example/x.js"></script></svg></body></html>"#,
        ),
        (
            "svg-src-and-href.html",
            r#"<!doctype html><html><body><svg><script src="ok.js" href="https://evil.example/x.js"></script></svg></body></html>"#,
        ),
        (
            "standalone-svg-dual-href.svg",
            r#"<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><script xlink:href="ok.js" href="https://evil.example/x.js"/></svg>"#,
        ),
    ];
    for &(name, payload) in cases {
        let bundle = SiteBundle {
            files: BTreeMap::from([(name.to_owned(), payload.as_bytes().to_vec())]),
            note: None,
            created_at_unix: 1,
            site_id: None,
        };
        let v = miraserve_publish::run_preflight_checks(&bundle, &checks);
        assert!(
            v.iter()
                .any(|x| x.rule == "NO_INLINE_SCRIPTS"
                    && x.detail.contains("same-origin relative path")),
            "R6-PUB-2 '{name}' must fail with same-origin script violation, got: {v:?}"
        );
    }

    let ok_svg = SiteBundle {
        files: BTreeMap::from([(
            "ok.svg".to_owned(),
            br#"<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><script xlink:href="/ok.js" href="/ok.js"/></svg>"#.to_vec(),
        )]),
        note: None,
        created_at_unix: 1,
        site_id: None,
    };
    assert!(miraserve_publish::run_preflight_checks(&ok_svg, &checks).is_empty());
}

/// R6-PUB-3: `<script type="importmap">` and `<script type="speculationrules">` reject any
/// cross-origin target URLs while allowing strictly same-origin relative mappings.
#[test]
fn r6_pub_3_importmap_and_speculationrules_enforce_same_origin_targets() {
    let checks = vec![PreflightCheck::NoInlineScripts];
    let bad_cases: &[(&str, &str, &str)] = &[
        (
            "importmap-https.html",
            r#"<!doctype html><html><head><script type="importmap">{"imports":{"app":"https://evil.example/x.js"}}</script></head><body></body></html>"#,
            "importmap",
        ),
        (
            "importmap-backslash.html",
            r#"<!doctype html><html><head><script type="importmap">{"imports":{"app":"\\/evil.example/x.js"}}</script></head><body></body></html>"#,
            "importmap",
        ),
        (
            "importmap-scopes.html",
            r#"<!doctype html><html><head><script type="importmap">{"scopes":{"/app/":{"lib":"https://evil.example/lib.js"}}}</script></head><body></body></html>"#,
            "importmap",
        ),
        (
            "speculation-cross.html",
            r#"<!doctype html><html><head><script type="speculationrules">{"prerender":[{"source":"list","urls":["https://evil.example/next"]}]}</script></head><body></body></html>"#,
            "speculationrules",
        ),
    ];
    for &(name, payload, kind) in bad_cases {
        let bundle = SiteBundle {
            files: BTreeMap::from([(name.to_owned(), payload.as_bytes().to_vec())]),
            note: None,
            created_at_unix: 1,
            site_id: None,
        };
        let v = miraserve_publish::run_preflight_checks(&bundle, &checks);
        assert!(
            v.iter().any(|x| x.rule == "NO_INLINE_SCRIPTS"
                && x.detail.contains(kind)
                && x.detail.contains("same-origin")),
            "R6-PUB-3 '{name}' must fail with {kind} same-origin violation, got: {v:?}"
        );
    }

    let ok = SiteBundle {
        files: BTreeMap::from([(
            "ok.html".to_owned(),
            br#"<!doctype html><html><head><script type="importmap">{"imports":{"app":"/assets/app.js","lib":"./lib.js"},"scopes":{"/admin/":{"lib":"/admin/lib.js"}}}</script><script type="speculationrules">{"prefetch":[{"source":"list","urls":["/about","/docs/"]}]}</script></head><body></body></html>"#.to_vec(),
        )]),
        note: None,
        created_at_unix: 1,
        site_id: None,
    };
    assert!(miraserve_publish::run_preflight_checks(&ok, &checks).is_empty());
}

/// R6-PUB-6: Exercises all four scanner DoS protections:
/// 1. 180k-sibling SVG (< 2 MiB) — ratio check against a 45k-sibling SVG
/// 2. Deeply nested XML/SVG (>512 depth) — explicit depth cap
/// 3. HTML adoption-agency formatting-element attribute amplification (95 `<b>` × 20 × 900 B + 2,500 `<p>`)
/// 4. Excessive attributes on a single HTML or SVG element (>1024 attrs)
#[test]
#[allow(clippy::too_many_lines)]
fn r6_pub_6_eliminates_xml_quadratic_depth_attr_count_and_adoption_agency_dos() {
    let checks = vec![PreflightCheck::NoInlineScripts, PreflightCheck::CspValid];

    // 1. 180k sibling `<g a="1"/>` SVG (< 2 MiB) must scan cleanly without quadratic hang. The
    //    bound is a ratio against a quarter-size document scanned right before, so a loaded
    //    machine slows both alike: linear work gives about 4x, quadratic about 16x.
    let svg_with = |siblings: usize| {
        let mut svg = String::with_capacity(siblings * 10 + 64);
        svg.push_str(r#"<svg xmlns="http://www.w3.org/2000/svg">"#);
        for _ in 0..siblings {
            svg.push_str(r#"<g a="1"/>"#);
        }
        svg.push_str("</svg>");
        svg
    };
    let scan = |svg: String| {
        let t0 = std::time::Instant::now();
        let violations = miraserve_publish::run_preflight_checks(
            &SiteBundle {
                files: BTreeMap::from([("big.svg".to_owned(), svg.into_bytes())]),
                note: None,
                created_at_unix: 1,
                site_id: None,
            },
            &checks,
        );
        (violations, t0.elapsed())
    };
    assert!(svg_with(180_000).len() < 2 * 1024 * 1024);
    // The fastest of three runs of each size: load on the machine only ever adds time.
    let fastest = |siblings: usize| {
        let mut best = scan(svg_with(siblings));
        for _ in 0..2 {
            let run = scan(svg_with(siblings));
            if run.1 < best.1 {
                best = run;
            }
        }
        best
    };
    let (v_quarter, t_quarter) = fastest(45_000);
    assert!(
        v_quarter.is_empty(),
        "valid 45k-sibling SVG must pass: {v_quarter:?}"
    );
    let (v_big, t_big) = fastest(180_000);
    assert!(
        v_big.is_empty(),
        "valid 180k-sibling SVG must pass: {v_big:?}"
    );
    assert!(
        t_big < t_quarter * 10 + std::time::Duration::from_millis(50),
        "180k-sibling SVG took {t_big:?} against {t_quarter:?} for 45k (linear is ~4x); \
         O(N^2) text_pos_at regression?"
    );

    // 2. Nested 600-deep SVG must be rejected quickly on nesting depth.
    let mut deep_svg = String::from(r#"<svg xmlns="http://www.w3.org/2000/svg">"#);
    for _ in 0..600 {
        deep_svg.push_str("<g>");
    }
    for _ in 0..600 {
        deep_svg.push_str("</g>");
    }
    deep_svg.push_str("</svg>");
    let t1 = std::time::Instant::now();
    let v_deep = miraserve_publish::run_preflight_checks(
        &SiteBundle {
            files: BTreeMap::from([("deep.svg".to_owned(), deep_svg.into_bytes())]),
            note: None,
            created_at_unix: 1,
            site_id: None,
        },
        &checks,
    );
    assert!(
        v_deep.iter().any(|x| x.detail.contains("nesting depth")),
        "deeply nested SVG must fail on nesting depth, got: {v_deep:?}"
    );
    assert!(t1.elapsed() < std::time::Duration::from_secs(2));

    // 3. HTML5 adoption-agency attribute amplification bomb (`<p>` followed by 95 `<b>` × 20 × 900 B
    //    attributes, then 2,500 `<p>t`).
    //    Must abort cleanly on the
    //    4 MiB expanded attribute memory budget.
    let mut bomb = String::with_capacity(1_900_000);
    bomb.push_str("<!doctype html><html><body><p>");
    let big_val = "x".repeat(900);
    for i in 0..95 {
        bomb.push_str("<b");
        for j in 0..20 {
            use std::fmt::Write as _;
            let _ = write!(bomb, " data-k{i}-{j}=\"{big_val}\"");
        }
        bomb.push('>');
    }
    for _ in 0..2_500 {
        bomb.push_str("<p>t");
    }
    bomb.push_str("</body></html>");
    assert!(bomb.len() < 2 * 1024 * 1024);
    let t2 = std::time::Instant::now();
    let v_bomb = miraserve_publish::run_preflight_checks(
        &SiteBundle {
            files: BTreeMap::from([("bomb.html".to_owned(), bomb.into_bytes())]),
            note: None,
            created_at_unix: 1,
            site_id: None,
        },
        &checks,
    );
    assert!(
        v_bomb
            .iter()
            .any(|x| x.detail.contains("attribute memory budget")),
        "adoption-agency bomb must abort on attribute memory budget, got: {v_bomb:?}"
    );
    assert!(t2.elapsed() < std::time::Duration::from_secs(2));

    // 4. Excessive attributes on a single HTML or SVG element (>1,024) rejected before parse.
    let mut many_html = String::from("<!doctype html><html><body><div");
    for i in 0..1_500 {
        use std::fmt::Write as _;
        let _ = write!(many_html, " a{i}=\"1\"");
    }
    many_html.push_str("></div></body></html>");
    let v_many_html = miraserve_publish::run_preflight_checks(
        &SiteBundle {
            files: BTreeMap::from([("attrs.html".to_owned(), many_html.into_bytes())]),
            note: None,
            created_at_unix: 1,
            site_id: None,
        },
        &checks,
    );
    assert!(
        v_many_html
            .iter()
            .any(|x| x.detail.contains("maximum attribute count")),
        "HTML >1024 attrs must fail on maximum attribute count, got: {v_many_html:?}"
    );

    let mut many_svg = String::from(r#"<svg xmlns="http://www.w3.org/2000/svg"><g"#);
    for i in 0..1_500 {
        use std::fmt::Write as _;
        let _ = write!(many_svg, " a{i}=\"1\"");
    }
    many_svg.push_str("/></svg>");
    let v_many_svg = miraserve_publish::run_preflight_checks(
        &SiteBundle {
            files: BTreeMap::from([("attrs.svg".to_owned(), many_svg.into_bytes())]),
            note: None,
            created_at_unix: 1,
            site_id: None,
        },
        &checks,
    );
    assert!(
        v_many_svg
            .iter()
            .any(|x| x.detail.contains("maximum attribute count")),
        "SVG >1024 attrs must fail on maximum attribute count, got: {v_many_svg:?}"
    );
}

/// R6-PUB-7: Accepts real-world benign sloppy HTML/SVG constructs while still blocking XSS hidden
/// inside those exact constructs, and emits actionable guidance for >2 MiB markup files.
#[test]
fn r6_pub_7_accepts_benign_sloppy_html_and_still_blocks_hidden_xss() {
    let checks = vec![PreflightCheck::NoInlineScripts, PreflightCheck::CspValid];
    let benign: &[(&str, &str)] = &[
        (
            "fb-pixel.html",
            r#"<!doctype html><html><head><noscript><img height="1" width="1" src="https://www.facebook.com/tr?id=123&ev=PageView"/></noscript></head><body><p>ok</p></body></html>"#,
        ),
        (
            "missing-attr-space.html",
            r#"<!doctype html><html><body><a href="/x"class="y">go</a></body></html>"#,
        ),
        (
            "sloppy-body-table.html",
            r#"<!DOCTYPE html5><html><body><head></head><td>cell</td><body><table><form><input type="hidden" name="k" value="1"></form></table><p>&#169 2025</ p><!-- a --!></body></html>"#,
        ),
        (
            "template-mime-param.html",
            r#"<!doctype html><html><body><script type="text/template; x"><p>tpl</p></script><script type="application/json; charset=utf-8">{"ok":true}</script></body></html>"#,
        ),
        (
            "svg-feimage.svg",
            r#"<svg xmlns="http://www.w3.org/2000/svg"><filter id="f"><feImage href="data:image/svg+xml;base64,PHN2Zy8+"/></filter></svg>"#,
        ),
    ];
    for &(name, payload) in benign {
        let v = miraserve_publish::run_preflight_checks(
            &SiteBundle {
                files: BTreeMap::from([(name.to_owned(), payload.as_bytes().to_vec())]),
                note: None,
                created_at_unix: 1,
                site_id: None,
            },
            &checks,
        );
        assert!(
            v.is_empty(),
            "R6-PUB-7 benign markup '{name}' had false positives: {v:?}"
        );
    }

    // Security check: XSS hidden inside those exact sloppy constructs MUST still be blocked!
    let evil: &[(&str, &str, &str)] = &[
        (
            "dup-body-onload.html",
            r#"<!doctype html><html><body>ok<body onload="alert(1)"></body></html>"#,
            "inline event handler",
        ),
        (
            "head-noscript-onerror.html",
            r#"<!doctype html><html><head><noscript><img src="x" onerror="alert(1)"/></noscript></head><body></body></html>"#,
            "inline event handler",
        ),
        (
            "comment-bang-script.html",
            "<!doctype html><html><body><!-- a --!><script>alert(1)</script></body></html>",
            "inline <script>",
        ),
        (
            "nospace-onclick.html",
            r#"<!doctype html><html><body><a href="/x"onclick="alert(1)">x</a></body></html>"#,
            "inline event handler",
        ),
    ];
    for &(name, payload, expected_reason) in evil {
        let v = miraserve_publish::run_preflight_checks(
            &SiteBundle {
                files: BTreeMap::from([(name.to_owned(), payload.as_bytes().to_vec())]),
                note: None,
                created_at_unix: 1,
                site_id: None,
            },
            &checks,
        );
        assert!(
            v.iter()
                .any(|x| x.rule == "NO_INLINE_SCRIPTS" && x.detail.contains(expected_reason)),
            "R6-PUB-7 evil '{name}' must still fail with '{expected_reason}', got: {v:?}"
        );
    }

    // >2 MiB HTML emits actionable guidance telling the author what to change.
    let huge = vec![b'a'; 2 * 1024 * 1024 + 16];
    let v_huge = miraserve_publish::run_preflight_checks(
        &SiteBundle {
            files: BTreeMap::from([("huge.html".to_owned(), huge)]),
            note: None,
            created_at_unix: 1,
            site_id: None,
        },
        &checks,
    );
    assert!(
        v_huge
            .iter()
            .any(|x| x.detail.contains("2 MiB") && x.detail.contains("split")),
        "expected actionable 2 MiB guidance, got: {v_huge:?}"
    );
}

/// R6-PUB-9: Meta CSP validator rejects `https://*`, `http://*:80`, `ws://*`, `wss:`, and
/// `'unsafe-hashes'` on active script/object/frame/base directives while permitting scoped hosts.
#[test]
fn r6_pub_9_csp_meta_rejects_wildcard_scheme_hosts_and_unsafe_hashes() {
    let checks = vec![PreflightCheck::CspValid];
    for policy in [
        "script-src https://*",
        "script-src http://*:80",
        "default-src ws://*",
        "script-src wss:",
        "script-src 'unsafe-hashes'",
        "script-src-elem https://*/*",
    ] {
        let html = format!(
            r#"<!doctype html><html><head><meta http-equiv="Content-Security-Policy" content="{policy}"></head><body></body></html>"#
        );
        let v = miraserve_publish::run_preflight_checks(
            &SiteBundle {
                files: BTreeMap::from([("csp.html".to_owned(), html.into_bytes())]),
                note: None,
                created_at_unix: 1,
                site_id: None,
            },
            &checks,
        );
        assert!(
            v.iter()
                .any(|x| x.rule == "CSP_VALID" && x.detail.contains("unsafe source")),
            "R6-PUB-9 policy '{policy}' must fail CSP_VALID with unsafe source, got: {v:?}"
        );
    }

    let ok = SiteBundle {
        files: BTreeMap::from([(
            "ok-csp.html".to_owned(),
            br#"<!doctype html><html><head><meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' 'unsafe-inline'"></head><body></body></html>"#.to_vec(),
        )]),
        note: None,
        created_at_unix: 1,
        site_id: None,
    };
    assert!(miraserve_publish::run_preflight_checks(&ok, &checks).is_empty());
}

/// R6-PUB-4: `resign --rebind-site-id` MUST require `--from-site-id` and refuse to adopt a
/// planted release signed under the same Ed25519 key for a different site B.
#[test]
fn r6_pub_4_rebind_site_id_requires_matching_from_site_id_and_refuses_foreign_releases()
-> TestResult {
    let dir =
        std::env::temp_dir().join(format!("miraserve-r6-pub-4-rebind-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;
    let shared_key = Ed25519SigningKey::generate()?;
    let pub_path = dir.join("shared.pub");
    fs::write(&pub_path, shared_key.verifying_key().to_encoded())?;

    let make_cfg = |storage: PathBuf, site_id: &str| AiPublishConfig {
        storage: storage.to_string_lossy().into_owned(),
        site_id: Some(site_id.to_owned()),
        keep_versions: 5,
        require_signature: Some(SignatureRequirement {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_path: pub_path.to_string_lossy().into_owned(),
        }),
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        preflight_checks: vec![PreflightCheck::NoSecrets],
        mcp_endpoint: None,
    };

    let now_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let storage_a = dir.join("site-a");
    let storage_b = dir.join("site-b");
    let store_a_old = ReleaseStore::open_for_site(
        make_cfg(storage_a.clone(), "old-a.example"),
        Some("old-a.example".to_owned()),
    )?;
    let store_b = ReleaseStore::open_for_site(
        make_cfg(storage_b.clone(), "site-b.example"),
        Some("site-b.example".to_owned()),
    )?;

    let mut bundle_a = make_bundle("<h1>Site A</h1>", "a1", now_unix - 10);
    bundle_a.site_id = Some("old-a.example".to_owned());
    let rel_a = store_a_old.publish(&SignedBundle::sign(bundle_a, &shared_key))?;

    let mut bundle_b = make_bundle("<h1>Site B</h1>", "b1", now_unix - 5);
    bundle_b.site_id = Some("site-b.example".to_owned());
    let rel_b = store_b.publish(&SignedBundle::sign(bundle_b, &shared_key))?;

    // Attacker with storage write access copies site B's signed release into site A's releases/.
    let src_b = storage_b.join("releases").join(&rel_b.release_id);
    let dst_b = storage_a.join("releases").join(&rel_b.release_id);
    fs::create_dir_all(dst_b.join("public"))?;
    fs::copy(src_b.join("release.json"), dst_b.join("release.json"))?;
    fs::copy(
        src_b.join("public/index.html"),
        dst_b.join("public/index.html"),
    )?;

    // Site A switches site-id to `new-a.example`.
    let store_a_new = ReleaseStore::open_for_site(
        make_cfg(storage_a, "new-a.example"),
        Some("new-a.example".to_owned()),
    )?;
    let vk = shared_key.verifying_key();

    // Rebind targeting `--from-site-id old-a.example` MUST refuse the planted site-b release!
    let err_all = store_a_new.resign_all_with_options(
        &shared_key,
        miraserve_publish::ResignOptions {
            include_unsigned: false,
            old_verifying_key: Some(&vk),
            rebind_from_site_id: Some("old-a.example"),
        },
    );
    assert!(
        matches!(err_all, Err(PublishError::InvalidSignature(ref m)) if m.contains("from-site-id") && !m.contains("site-b.example")),
        "resign_all must refuse foreign site-b release without echoing the foreign site_id (R6-PUB-4, R7-PUB-3), got: {err_all:?}"
    );
    // Explicitly targeting the planted release with `--from-site-id old-a.example` also fails!
    assert!(
        store_a_new
            .resign_release_with_options(
                &rel_b.release_id,
                &shared_key,
                miraserve_publish::ResignOptions {
                    include_unsigned: false,
                    old_verifying_key: Some(&vk),
                    rebind_from_site_id: Some("old-a.example"),
                },
            )
            .is_err()
    );
    // Meanwhile, rebinding genuine release A with `--from-site-id old-a.example` succeeds!
    let rebound_a = store_a_new.resign_release_with_options(
        &rel_a.release_id,
        &shared_key,
        miraserve_publish::ResignOptions {
            include_unsigned: false,
            old_verifying_key: Some(&vk),
            rebind_from_site_id: Some("old-a.example"),
        },
    )?;
    assert_eq!(rebound_a.site_id.as_deref(), Some("new-a.example"));
    // Rollback to planted foreign release B remains strictly refused!
    assert!(store_a_new.rollback(Some(&rel_b.release_id)).is_err());

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// R8-PUB-2/6/7 (supersedes the R6-PUB-5 startup leniency): startup applies the SAME strict rule
/// as a reload. A live release that fails stricter post-upgrade preflight checks (e.g. a CDN
/// `<script src>` under `no-inline-scripts`) is not served after a restart, a forged
/// `verified_active` record changes nothing, rollback/resign enforce preflight strictly, and
/// cheap metadata checks (`site_id`, `signature_b64`) execute BEFORE reading `public/`.
#[test]
fn r8_pub_2_startup_is_as_strict_as_reload_and_checks_metadata_first() -> TestResult {
    let dir =
        std::env::temp_dir().join(format!("miraserve-r6-pub-5-startup-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;
    let key = Ed25519SigningKey::generate()?;
    let pub_path = dir.join("site.pub");
    fs::write(&pub_path, key.verifying_key().to_encoded())?;

    let storage = dir.join("releases-store");
    let mut cfg = AiPublishConfig {
        storage: storage.to_string_lossy().into_owned(),
        site_id: Some("live.example".to_owned()),
        keep_versions: 5,
        require_signature: Some(SignatureRequirement {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_path: pub_path.to_string_lossy().into_owned(),
        }),
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        preflight_checks: vec![PreflightCheck::NoSecrets],
        mcp_endpoint: None,
    };

    let now_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let store_v1 = ReleaseStore::open_for_site(cfg.clone(), Some("live.example".to_owned()))?;
    let mut b = make_bundle(
        r#"<!doctype html><html><head><script src="https://cdn.jsdelivr.net/npm/bootstrap@5/dist/js/bootstrap.bundle.min.js"></script></head><body><h1>Bootstrap Starter</h1></body></html>"#,
        "cdn-starter",
        now_unix,
    );
    b.site_id = Some("live.example".to_owned());
    let live_rel = store_v1.publish(&SignedBundle::sign(b, &key))?;

    // Upgrade config to enforce `NoInlineScripts` (which rejects third-party CDN scripts):
    // 1. Startup must NOT serve the release that no longer passes, exactly like a reload. The
    //    `verified_active` record written at activation lives in the same writable directory,
    //    so it is no proof and grants nothing.
    cfg.preflight_checks = vec![PreflightCheck::NoSecrets, PreflightCheck::NoInlineScripts];
    let restarted = ReleaseStore::open_for_site(cfg.clone(), Some("live.example".to_owned()))?;
    assert_eq!(
        restarted.active_release().map(|r| r.release_id),
        None,
        "R8-PUB-2: a release failing the current checks must not be served after a restart"
    );
    assert!(restarted.active_static_server().is_none());
    // A second restart gives the same answer (no flip-flop between restart and reload).
    let restarted_again =
        ReleaseStore::open_for_site(cfg.clone(), Some("live.example".to_owned()))?;
    assert!(restarted_again.active_release().is_none());

    // 2. Rollback & resign STILL enforce preflight strictly!
    assert!(matches!(
        restarted.rollback(Some(&live_rel.release_id)),
        Err(PublishError::PreflightFailed(_))
    ));
    let vk = key.verifying_key();
    assert!(matches!(
        restarted.resign_release_with_options(
            &live_rel.release_id,
            &key,
            miraserve_publish::ResignOptions {
                include_unsigned: false,
                old_verifying_key: Some(&vk),
                rebind_from_site_id: None,
            },
        ),
        Err(PublishError::PreflightFailed(_))
    ));

    // 3. Cheap metadata check runs BEFORE reading `public/`: delete `public/` of the release and
    //    open with a DIFFERENT `site_id` — must fail with `InvalidSignature("...site_id...")`,
    //    NOT an `Io` error reading the missing `public/` directory!
    fs::remove_dir_all(
        storage
            .join("releases")
            .join(&live_rel.release_id)
            .join("public"),
    )?;
    cfg.site_id = Some("other.example".to_owned());
    let wrong_site_store = ReleaseStore::open_for_site(cfg, Some("other.example".to_owned()))?;
    let err = wrong_site_store.rollback(Some(&live_rel.release_id));
    assert!(
        matches!(err, Err(PublishError::InvalidSignature(ref m)) if m.contains("site_id")),
        "R6-PUB-5: site_id check must run BEFORE reading public/ files, got: {err:?}"
    );

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// R6-PUB-8: Anti-replay cache fails CLOSED on corrupt `replay-cache.json` or malformed hex keys,
/// and evicts expired entries on load so expired floods never permanently lock out publishes.
#[test]
fn r6_pub_8_replay_cache_fails_closed_on_corrupt_json_bad_hex_and_recovers_after_expiry()
-> TestResult {
    let dir =
        std::env::temp_dir().join(format!("miraserve-r6-pub-8-replay-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;
    let key = Ed25519SigningKey::generate()?;
    let pub_path = dir.join("pub.key");
    fs::write(&pub_path, key.verifying_key().to_encoded())?;

    let storage = dir.join("store");
    let cfg = AiPublishConfig {
        storage: storage.to_string_lossy().into_owned(),
        site_id: Some("replay.example".to_owned()),
        keep_versions: 3,
        require_signature: Some(SignatureRequirement {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_path: pub_path.to_string_lossy().into_owned(),
        }),
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        preflight_checks: vec![PreflightCheck::NoSecrets],
        mcp_endpoint: Some(McpPublishEndpoint {
            path: "/_miraserve/publish".to_owned(),
            auth: PublishAuthMode::Ed25519,
        }),
    };
    let store = ReleaseStore::open_for_site(cfg.clone(), Some("replay.example".to_owned()))?;

    let fixed_now_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let send_list_req = |st: &ReleaseStore, nonce: &str| -> u16 {
        let now_unix = fixed_now_unix;
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;
        let ts = now_unix.to_string();
        let sig_b64 = key.sign_mcp_request(
            "replay.example",
            "/_miraserve/publish",
            now_unix,
            Some(nonce),
            body,
        );
        let mut hdrs = HeaderMap::new();
        if let Ok(v) = HeaderValue::from_str(&ts) {
            hdrs.insert("x-miraserve-timestamp", v);
        }
        if let Ok(v) = HeaderValue::from_str(nonce) {
            hdrs.insert("x-miraserve-nonce", v);
        }
        if let Ok(v) = HeaderValue::from_str(&sig_b64) {
            hdrs.insert("x-miraserve-signature", v);
        }
        let ctx = McpPublishAuthContext {
            endpoint_path: "/_miraserve/publish",
            site_host: "replay.example",
            is_https: true,
            verified_client_cert_dn: None,
        };
        handle_mcp_publish_http(st, PublishAuthMode::Ed25519, &hdrs, body, &ctx)
            .status()
            .as_u16()
    };

    // 1. Corrupt JSON in `replay-cache.json` -> MUST fail closed with 503 (distinct from 401 replay, R7-PUB-4)!
    fs::write(storage.join("replay-cache.json"), b"{not valid json!!!")?;
    assert_eq!(
        send_list_req(&store, "nonce-corrupt-1"),
        503,
        "R6-PUB-8/R7-PUB-4: corrupt replay-cache.json must fail closed with 503"
    );

    // 2. Malformed hex key in `replay-cache.json` -> MUST fail closed with 503 (R7-PUB-4)!
    fs::write(
        storage.join("replay-cache.json"),
        br#"{"entries":{"not-64-hex":9999999999}}"#,
    )?;
    assert_eq!(
        send_list_req(&store, "nonce-badhex-2"),
        503,
        "R6-PUB-8/R7-PUB-4: malformed hex entry in replay-cache.json must fail closed with 503"
    );

    // 3. Previously saturated cache with ONLY expired entries recovers cleanly after reload!
    let mut expired_entries = serde_json::Map::new();
    for i in 0..16_u32 {
        expired_entries.insert(format!("{i:064x}"), serde_json::Value::from(1_u64));
    }
    let expired_json = serde_json::json!({ "entries": expired_entries });
    fs::write(
        storage.join("replay-cache.json"),
        serde_json::to_vec(&expired_json)?,
    )?;
    let reopened = ReleaseStore::open_for_site(cfg, Some("replay.example".to_owned()))?;
    assert_eq!(
        send_list_req(&reopened, "nonce-fresh-3"),
        200,
        "R6-PUB-8: expired replay entries must be evicted cleanly on load"
    );
    // Exact replay of `nonce-fresh-3` is still rejected!
    assert_eq!(send_list_req(&reopened, "nonce-fresh-3"), 401);

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// R5-PUB-4: Deleting `legacy-v2-allowlist.json` on a v3 store and restarting MUST NOT re-seed
/// `releases/` into the allowlist or allow rollback to a newly planted foreign v2 release.
#[test]
fn r5_pub_4_deleting_legacy_v2_allowlist_on_v3_store_does_not_adopt_planted_v2_release()
-> TestResult {
    let dir = std::env::temp_dir().join(format!("miraserve-r5-pub-4-v2del-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;
    let key = Ed25519SigningKey::generate()?;
    let pub_path = dir.join("shared.pub");
    fs::write(&pub_path, key.verifying_key().to_encoded())?;

    let now_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let v3_storage = dir.join("v3-store");
    let v3_cfg = AiPublishConfig {
        storage: v3_storage.to_string_lossy().into_owned(),
        site_id: Some("prod.example".to_owned()),
        keep_versions: 5,
        require_signature: Some(SignatureRequirement {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_path: pub_path.to_string_lossy().into_owned(),
        }),
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        preflight_checks: vec![PreflightCheck::NoSecrets],
        mcp_endpoint: None,
    };
    let v3_store = ReleaseStore::open_for_site(v3_cfg.clone(), Some("prod.example".to_owned()))?;
    let mut b_v3 = make_bundle("<h1>Prod V3</h1>", "v3", now_unix - 10);
    b_v3.site_id = Some("prod.example".to_owned());
    let _ = v3_store.publish(&SignedBundle::sign(b_v3, &key))?;

    // Build an unbound v2 release in a separate store and plant it into v3-store/releases/.
    let foreign_storage = dir.join("foreign-v2");
    let mut foreign_cfg = v3_cfg.clone();
    foreign_cfg.storage = foreign_storage.to_string_lossy().into_owned();
    foreign_cfg.site_id = None;
    let foreign_store = ReleaseStore::open_for_site(foreign_cfg, None)?;
    let b_v2 = make_bundle("<h1>Planted V2</h1>", "planted", now_unix - 5);
    let planted = foreign_store.publish(&SignedBundle::sign(b_v2, &key))?;

    let src = foreign_storage.join("releases").join(&planted.release_id);
    let dst = v3_storage.join("releases").join(&planted.release_id);
    fs::create_dir_all(dst.join("public"))?;
    fs::copy(src.join("release.json"), dst.join("release.json"))?;
    fs::copy(src.join("public/index.html"), dst.join("public/index.html"))?;

    // Attacker deletes `legacy-v2-allowlist.json` and restarts the server!
    let _ = fs::remove_file(v3_storage.join("legacy-v2-allowlist.json"));
    let restarted = ReleaseStore::open_for_site(v3_cfg, Some("prod.example".to_owned()))?;
    assert!(
        matches!(
            restarted.rollback(Some(&planted.release_id)),
            Err(PublishError::InvalidSignature(ref m)) if m.contains("legacy-v2 allowlist")
        ),
        "R5-PUB-4: deleting legacy-v2-allowlist.json on a v3 store MUST NOT adopt planted v2 release"
    );

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// R5-PUB-2: `allowed-subjects` supports `emailAddress`/`E`/`1.2.840.113549.1.9.1` and `#hex`
/// case normalization while preserving strict full-DN ASN.1 RDN sequence comparison.
#[test]
fn r5_pub_2_mtls_allowed_subjects_supports_email_address_and_hex_case_normalization() -> TestResult
{
    let dir = std::env::temp_dir().join(format!("miraserve-r5-pub-2-dn-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;
    let key = Ed25519SigningKey::generate()?;
    let pub_path = dir.join("pub.key");
    fs::write(&pub_path, key.verifying_key().to_encoded())?;

    let cfg = AiPublishConfig {
        storage: dir.join("store").to_string_lossy().into_owned(),
        site_id: Some("mtls.example".to_owned()),
        keep_versions: 3,
        require_signature: Some(SignatureRequirement {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_path: pub_path.to_string_lossy().into_owned(),
        }),
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: vec![
            "O=Corp, CN=deploy-bot, emailAddress=ops@corp.example, 1.2.3.4=#0c0474657374"
                .to_owned(),
        ],
        preflight_checks: vec![PreflightCheck::NoSecrets],
        mcp_endpoint: Some(McpPublishEndpoint {
            path: "/_miraserve/publish".to_owned(),
            auth: PublishAuthMode::Mtls,
        }),
    };
    let store = ReleaseStore::open_for_site(cfg, Some("mtls.example".to_owned()))?;
    let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;
    let hdrs = HeaderMap::new();

    // Matching ASN.1 DN with `1.2.840.113549.1.9.1` OID and uppercase `#HEX` succeeds (200).
    let ctx_ok = McpPublishAuthContext {
        endpoint_path: "/_miraserve/publish",
        site_host: "mtls.example",
        is_https: true,
        verified_client_cert_dn: Some(
            "O=Corp, CN=deploy-bot, 1.2.840.113549.1.9.1=ops@corp.example, 1.2.3.4=#0C0474657374",
        ),
    };
    assert_eq!(
        handle_mcp_publish_http(&store, PublishAuthMode::Mtls, &hdrs, body, &ctx_ok)
            .status()
            .as_u16(),
        200
    );

    // Wrong email value fails closed (403).
    let ctx_bad = McpPublishAuthContext {
        endpoint_path: "/_miraserve/publish",
        site_host: "mtls.example",
        is_https: true,
        verified_client_cert_dn: Some(
            "O=Corp, CN=deploy-bot, emailAddress=attacker@corp.example, 1.2.3.4=#0C0474657374",
        ),
    };
    assert_eq!(
        handle_mcp_publish_http(&store, PublishAuthMode::Mtls, &hdrs, body, &ctx_bad)
            .status()
            .as_u16(),
        403
    );

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// R7-SCAN-1 & R7-SCAN-4: Scheme-prefixed relative-looking URLs (`https:evil/x.js`,
/// `https:/evil/x.js`, `HTTPS:evil`, ` https:evil`, `ht\ttps:evil`, `https:@evil`,
/// `https:evil:443`, `http:evil/x.js`) are rejected on `<script>`, `<base>`, `<svg><script>`,
/// and `xml:base` with exact distinct violation reasons, while genuine scheme-less relative
/// paths (including `./foo:bar.js`) pass.
#[test]
fn r7_scan_1_rejects_scheme_prefixed_urls_across_http_and_https_contexts() {
    let checks = vec![PreflightCheck::NoInlineScripts];
    let cases: &[(&str, &str, &str)] = &[
        (
            "https-noslash.html",
            r#"<!doctype html><html><head><script src="https:evil.example/x.js"></script></head><body></body></html>"#,
            "external <script> URL attribute must be a scheme-less same-origin relative path",
        ),
        (
            "https-oneslash.html",
            r#"<!doctype html><html><head><script src="https:/evil.example/x.js"></script></head><body></body></html>"#,
            "external <script> URL attribute must be a scheme-less same-origin relative path",
        ),
        (
            "https-upper.html",
            r#"<!doctype html><html><head><script src="HTTPS:evil.example/x.js"></script></head><body></body></html>"#,
            "external <script> URL attribute must be a scheme-less same-origin relative path",
        ),
        (
            "https-leadspace.html",
            r#"<!doctype html><html><head><script src=" https:evil.example/x.js"></script></head><body></body></html>"#,
            "external <script> URL attribute must be a scheme-less same-origin relative path",
        ),
        (
            "https-tab-obfuscated.html",
            "<!doctype html><html><head><script src=\"ht\ttps:evil.example/x.js\"></script></head><body></body></html>",
            "external <script> URL attribute must be a scheme-less same-origin relative path",
        ),
        (
            "https-userinfo.html",
            r#"<!doctype html><html><head><script src="https:@evil.example/x.js"></script></head><body></body></html>"#,
            "external <script> URL attribute must be a scheme-less same-origin relative path",
        ),
        (
            "https-port.html",
            r#"<!doctype html><html><head><script src="https:evil.example:443/x.js"></script></head><body></body></html>"#,
            "external <script> URL attribute must be a scheme-less same-origin relative path",
        ),
        (
            "http-noslash.html",
            r#"<!doctype html><html><head><script src="http:evil.example/x.js"></script></head><body></body></html>"#,
            "external <script> URL attribute must be a scheme-less same-origin relative path",
        ),
        (
            "base-https-noslash.html",
            r#"<!doctype html><html><head><base href="https:evil.example/"><script src="app.js"></script></head><body></body></html>"#,
            "<base href> must be a relative same-origin path",
        ),
        (
            "svg-https-oneslash.html",
            r#"<!doctype html><html><body><svg><script href="https:/evil.example/x.js"></script></svg></body></html>"#,
            "non-HTML <script> external URL must be a scheme-less same-origin relative path",
        ),
        (
            "svg-xml-base-https.svg",
            r#"<svg xmlns="http://www.w3.org/2000/svg" xml:base="https:evil.example/"><script href="app.js"/></svg>"#,
            "xml:base attribute must be a relative same-origin path",
        ),
    ];
    for &(name, html, exact_reason) in cases {
        let v = miraserve_publish::run_preflight_checks(
            &SiteBundle {
                files: BTreeMap::from([(name.to_owned(), html.as_bytes().to_vec())]),
                note: None,
                created_at_unix: 1,
                site_id: None,
            },
            &checks,
        );
        assert!(
            v.iter()
                .any(|x| x.rule == "NO_INLINE_SCRIPTS" && x.detail.contains(exact_reason)),
            "R7-SCAN-1 '{name}' must fail with '{exact_reason}', got: {v:?}"
        );
    }

    // Legitimate scheme-less relative script/base URLs still pass cleanly.
    let ok = SiteBundle {
        files: BTreeMap::from([(
            "ok.html".to_owned(),
            br#"<!doctype html><html><head><base href="/app/"><script src="/app.js"></script><script src="./a:b.js"></script><script src="../lib/mod.js?v=1"></script></head><body></body></html>"#.to_vec(),
        )]),
        note: None,
        created_at_unix: 1,
        site_id: None,
    };
    assert!(
        miraserve_publish::run_preflight_checks(&ok, &checks).is_empty(),
        "valid relative script URLs must pass"
    );
}

/// R7-SCAN-2 & R7-SCAN-4: `<script type="importmap">` enforces WHATWG §8.1.6.5 "parse a URL-like
/// import specifier" — every target in `"imports"` and `"scopes"` MUST literally begin with
/// `"/"` (not `"//"` or `"/\\"`), `"./"`, or `"../"` so `"https:evil.example/m.js"` and bare
/// targets can never resolve cross-origin on HTTPS or HTTP pages.
#[test]
fn r7_scan_2_importmap_enforces_url_like_relative_specifier_rule() {
    let checks = vec![PreflightCheck::NoInlineScripts];
    let bad_targets: &[(&str, &str)] = &[
        (
            "imports-https-noslash.html",
            r#"<!doctype html><html><head><script type="importmap">{"imports":{"app":"https:evil.example/m.js"}}</script></head><body></body></html>"#,
        ),
        (
            "imports-https-oneslash.html",
            r#"<!doctype html><html><head><script type="importmap">{"imports":{"app":"https:/evil.example/m.js"}}</script></head><body></body></html>"#,
        ),
        (
            "imports-space-prefixed.html",
            r#"<!doctype html><html><head><script type="importmap">{"imports":{"app":" /assets/app.js"}}</script></head><body></body></html>"#,
        ),
        (
            "imports-bare-relative.html",
            r#"<!doctype html><html><head><script type="importmap">{"imports":{"app":"assets/app.js"}}</script></head><body></body></html>"#,
        ),
        (
            "imports-slash-backslash.html",
            r#"<!doctype html><html><head><script type="importmap">{"imports":{"app":"/\\evil.example/m.js"}}</script></head><body></body></html>"#,
        ),
        (
            "imports-slash-tab-slash.html",
            r#"<!doctype html><html><head><script type="importmap">{"imports":{"app":"/\t/evil.example/m.js"}}</script></head><body></body></html>"#,
        ),
        (
            "scopes-https-noslash.html",
            r#"<!doctype html><html><head><script type="importmap">{"scopes":{"/app/":{"lib":"https:evil.example/m.js"}}}</script></head><body></body></html>"#,
        ),
    ];
    for &(name, html) in bad_targets {
        let v = miraserve_publish::run_preflight_checks(
            &SiteBundle {
                files: BTreeMap::from([(name.to_owned(), html.as_bytes().to_vec())]),
                note: None,
                created_at_unix: 1,
                site_id: None,
            },
            &checks,
        );
        assert!(
            v.iter().any(|x| {
                x.rule == "NO_INLINE_SCRIPTS" && x.detail.contains("URL-like relative specifier")
            }),
            "R7-SCAN-2 '{name}' must fail with distinct URL-like relative specifier reason, got: {v:?}"
        );
    }

    let ok = SiteBundle {
        files: BTreeMap::from([(
            "ok-importmap.html".to_owned(),
            br#"<!doctype html><html><head><script type="importmap">{"imports":{"a":"/js/a.js","b":"./b.js","c":"../c.js"},"scopes":{"/sub/":{"a":"/sub/a.js"}}}</script></head><body></body></html>"#.to_vec(),
        )]),
        note: None,
        created_at_unix: 1,
        site_id: None,
    };
    assert!(miraserve_publish::run_preflight_checks(&ok, &checks).is_empty());
}

/// R7-SCAN-3: `<title><!--</title><g a0 ...>`, `<textarea><!--</textarea><g a0 ...>`, and
/// `<svg><script><g a0 ...></script></svg>` with 250k attributes reject at the attribute cap
/// within 250 ms.
#[test]
fn r7_scan_3_prescan_rcdata_rawtext_and_svg_script_cannot_be_desynchronized() {
    use std::fmt::Write as _;

    let checks = vec![PreflightCheck::NoInlineScripts, PreflightCheck::CspValid];
    let mut big_attrs = String::with_capacity(2_000_000);
    for i in 0..250_000_usize {
        let _ = write!(big_attrs, " a{i}");
    }
    let payloads = [
        (
            "title-rcdata-desync.html",
            format!("<!doctype html><title><!--</title><g{big_attrs}>-->"),
        ),
        (
            "textarea-rcdata-desync.html",
            format!("<!doctype html><textarea><!--</textarea><g{big_attrs}>-->"),
        ),
        (
            "svg-script-desync.html",
            format!("<svg><script><g{big_attrs}></script></svg>"),
        ),
    ];

    for (name, html) in payloads {
        assert!(html.len() < 2 * 1024 * 1024);
        let t0 = std::time::Instant::now();
        let v = miraserve_publish::run_preflight_checks(
            &SiteBundle {
                files: BTreeMap::from([(name.to_owned(), html.into_bytes())]),
                note: None,
                created_at_unix: 1,
                site_id: None,
            },
            &checks,
        );
        let elapsed = t0.elapsed();
        assert!(
            v.iter()
                .any(|x| x.detail.contains("maximum attribute count")),
            "R7-SCAN-3 '{name}' must fail on maximum attribute count, got: {v:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(250),
            "R7-SCAN-3 '{name}' took {elapsed:?} (expected < 250ms)"
        );
    }

    // SVG `<title>` HTML-integration-point comment containing `<g ...>` with 2,000 attributes
    // completes within the 250 ms bound.
    let svg_title_comment = format!(
        "<!doctype html><html><body><svg><title><!--</title><g{}>--></title></svg></body></html>",
        " a=1".repeat(2_000)
    );
    let t1 = std::time::Instant::now();
    let _ = miraserve_publish::run_preflight_checks(
        &SiteBundle {
            files: BTreeMap::from([("svg-title.html".to_owned(), svg_title_comment.into_bytes())]),
            note: None,
            created_at_unix: 1,
            site_id: None,
        },
        &checks,
    );
    assert!(t1.elapsed() < std::time::Duration::from_millis(250));
}

/// R7-SCAN-5: Meta CSP validator rejects ALL wildcard host and port expressions on active
/// directives (`*.com`, `*.example`, `https://*.com`, `https://*.example.com`, `*:*`,
/// `https://cdn.example.com:*`) while permitting exact pinned hosts and hashes.
#[test]
fn r7_scan_5_csp_meta_rejects_all_wildcard_host_and_port_sources() {
    let checks = vec![PreflightCheck::CspValid];
    for policy in [
        "script-src *.com",
        "script-src *.example",
        "script-src https://*.com",
        "script-src https://*.example.com",
        "default-src https://*.example.com/js/",
        "script-src-elem //*.example.com",
        "script-src https://cdn.example.com:*",
        "script-src *:*",
    ] {
        let html = format!(
            r#"<!doctype html><html><head><meta http-equiv="Content-Security-Policy" content="{policy}"></head><body></body></html>"#
        );
        let v = miraserve_publish::run_preflight_checks(
            &SiteBundle {
                files: BTreeMap::from([("csp.html".to_owned(), html.into_bytes())]),
                note: None,
                created_at_unix: 1,
                site_id: None,
            },
            &checks,
        );
        assert!(
            v.iter()
                .any(|x| x.rule == "CSP_VALID" && x.detail.contains("unsafe source")),
            "R7-SCAN-5 policy '{policy}' must fail CSP_VALID with unsafe source, got: {v:?}"
        );
    }

    let ok = SiteBundle {
        files: BTreeMap::from([(
            "ok.html".to_owned(),
            br#"<!doctype html><html><head><meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' https://cdn.example.com:8443/app.js 'sha256-abc123='"></head><body></body></html>"#.to_vec(),
        )]),
        note: None,
        created_at_unix: 1,
        site_id: None,
    };
    assert!(miraserve_publish::run_preflight_checks(&ok, &checks).is_empty());
}

/// R7-SCAN-6: Whitespace after `/` in a self-closing start tag (`<img src=a.png / >`) is accepted
/// while `<img src=a.png / onerror=alert(1)>` and `<img src=a.png /onerror=alert(1)>` remain
/// strictly rejected.
#[test]
fn r7_scan_6_self_closing_whitespace_allowed_while_trailing_event_handler_rejected() {
    let checks = vec![PreflightCheck::NoInlineScripts, PreflightCheck::CspValid];

    let benign = SiteBundle {
        files: BTreeMap::from([(
            "ok.html".to_owned(),
            b"<!doctype html><html><body><img src=a.png / ></body></html>".to_vec(),
        )]),
        note: None,
        created_at_unix: 1,
        site_id: None,
    };
    let v_ok = miraserve_publish::run_preflight_checks(&benign, &checks);
    assert!(
        v_ok.is_empty(),
        "R7-SCAN-6 benign '<img src=a.png / >' must pass, got: {v_ok:?}"
    );

    let evil_space = SiteBundle {
        files: BTreeMap::from([(
            "evil-space.html".to_owned(),
            b"<!doctype html><html><body><img src=a.png / onerror=alert(1)></body></html>".to_vec(),
        )]),
        note: None,
        created_at_unix: 1,
        site_id: None,
    };
    let v_evil_space = miraserve_publish::run_preflight_checks(&evil_space, &checks);
    assert!(
        v_evil_space
            .iter()
            .any(|x| x.rule == "NO_INLINE_SCRIPTS" && x.detail.contains("inline event handler")),
        "R7-SCAN-6 '<img src=a.png / onerror=alert(1)>' must fail as inline event handler, got: {v_evil_space:?}"
    );

    let evil_nospace = SiteBundle {
        files: BTreeMap::from([(
            "evil-nospace.html".to_owned(),
            b"<!doctype html><html><body><img src=a.png /onerror=alert(1)></body></html>".to_vec(),
        )]),
        note: None,
        created_at_unix: 1,
        site_id: None,
    };
    let v_evil_nospace = miraserve_publish::run_preflight_checks(&evil_nospace, &checks);
    assert!(
        v_evil_nospace.iter().any(|x| x.rule == "NO_INLINE_SCRIPTS"),
        "R7-SCAN-6 '<img src=a.png /onerror=alert(1)>' must fail, got: {v_evil_nospace:?}"
    );
}

/// R7-PUB-1: A release rejected by preflight (signed elsewhere with the same key & `site_id`,
/// copied into `releases/`, and pointed to by `active.json`) MUST be rejected on BOTH
/// `open_for_site_reload` (`SIGHUP`) AND cold restart (`open_for_site`), falling back to the
/// previous compliant release rather than serving inline script.
#[test]
#[allow(clippy::too_many_lines)]
fn r7_pub_1_rejects_planted_preflight_violation_on_reload_and_cold_restart() -> TestResult {
    let dir = std::env::temp_dir().join(format!("miraserve-r7-pub-1-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;

    let key = Ed25519SigningKey::generate()?;
    let pub_path = dir.join("site.pub");
    fs::write(&pub_path, key.verifying_key().to_encoded())?;

    let storage = dir.join("prod-store");
    let external_storage = dir.join("external-store");
    let make_cfg = |st: &std::path::Path, checks: Vec<PreflightCheck>| AiPublishConfig {
        storage: st.to_string_lossy().into_owned(),
        site_id: Some("strict.example".to_owned()),
        keep_versions: 5,
        require_signature: Some(SignatureRequirement {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_path: pub_path.to_string_lossy().into_owned(),
        }),
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        preflight_checks: checks,
        mcp_endpoint: None,
    };

    let now_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let strict_cfg = make_cfg(
        &storage,
        vec![PreflightCheck::NoSecrets, PreflightCheck::NoInlineScripts],
    );
    let prod_store =
        ReleaseStore::open_for_site(strict_cfg.clone(), Some("strict.example".to_owned()))?;

    let mut good_bundle = make_bundle(
        "<!doctype html><html><body><h1>Good</h1></body></html>",
        "good",
        now_unix - 10,
    );
    good_bundle.site_id = Some("strict.example".to_owned());
    let good_rel = prod_store.publish(&SignedBundle::sign(good_bundle, &key))?;

    // Build a validly signed inline-script bundle (rejected by prod_store.publish!) in an external
    // permissive store and plant it into prod_store/releases/ + point active.json at it.
    let mut evil_bundle = make_bundle(
        "<!doctype html><html><body><script>alert(1)</script></body></html>",
        "evil",
        now_unix - 5,
    );
    evil_bundle.site_id = Some("strict.example".to_owned());
    let signed_evil = SignedBundle::sign(evil_bundle, &key);
    assert!(matches!(
        prod_store.publish(&signed_evil),
        Err(PublishError::PreflightFailed(_))
    ));

    let ext_cfg = make_cfg(&external_storage, vec![PreflightCheck::NoSecrets]);
    let ext_store = ReleaseStore::open_for_site(ext_cfg, Some("strict.example".to_owned()))?;
    let evil_rel = ext_store.publish(&signed_evil)?;

    let src = external_storage.join("releases").join(&evil_rel.release_id);
    let dst = storage.join("releases").join(&evil_rel.release_id);
    fs::create_dir_all(dst.join("public"))?;
    fs::copy(src.join("release.json"), dst.join("release.json"))?;
    fs::copy(src.join("public/index.html"), dst.join("public/index.html"))?;

    // Rewrite active.json so active_release_id points at evil_rel (preserving history with good_rel).
    let tampered_active = serde_json::json!({
        "active_release_id": evil_rel.release_id,
        "history": [good_rel.release_id, evil_rel.release_id],
        "max_created_at_unix": now_unix - 5,
        "verified_active": {
            "release_id": good_rel.release_id,
            "manifest_sha256": good_rel.manifest_sha256,
            "scanner_version": 2,
            "preflight_checks": ["no-inline-scripts", "no-secrets"]
        }
    });
    fs::write(
        storage.join("active.json"),
        serde_json::to_vec_pretty(&tampered_active)?,
    )?;

    // 1. Live reload (`open_for_site_reload`) MUST refuse evil_rel and fall back to good_rel!
    let reloaded =
        ReleaseStore::open_for_site_reload(strict_cfg.clone(), Some("strict.example".to_owned()))?;
    assert_eq!(
        reloaded.active_release().map(|r| r.release_id),
        Some(good_rel.release_id.clone()),
        "R7-PUB-1: SIGHUP reload must never serve planted preflight-rejected release"
    );

    // 2. Cold restart (`open_for_site`) MUST ALSO refuse evil_rel and fall back to good_rel!
    let restarted =
        ReleaseStore::open_for_site(strict_cfg.clone(), Some("strict.example".to_owned()))?;
    assert_eq!(
        restarted.active_release().map(|r| r.release_id),
        Some(good_rel.release_id.clone()),
        "R7-PUB-1: cold restart must refuse planted release whose verified_active does not match"
    );

    // 3. Even if attacker strips `verified_active` completely from active.json, BOTH reload and
    //    cold restart MUST still refuse evil_rel!
    let stripped_active = serde_json::json!({
        "active_release_id": evil_rel.release_id,
        "history": [good_rel.release_id, evil_rel.release_id],
        "max_created_at_unix": now_unix - 5
    });
    fs::write(
        storage.join("active.json"),
        serde_json::to_vec_pretty(&stripped_active)?,
    )?;
    let restarted_stripped =
        ReleaseStore::open_for_site(strict_cfg, Some("strict.example".to_owned()))?;
    assert_eq!(
        restarted_stripped.active_release().map(|r| r.release_id),
        Some(good_rel.release_id),
        "R7-PUB-1: stripped active.json without verified_active must not trigger lenient fallback"
    );

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// R7-PUB-2: `resign` MUST consult `legacy-v2-allowlist.json` before binding an unbound v2
/// release to the current site so a planted foreign v2 release signed with a shared old key
/// cannot be adopted via `resign` and then rolled back to.
#[test]
fn r7_pub_2_resign_refuses_planted_unbound_v2_release_not_in_allowlist() -> TestResult {
    let dir = std::env::temp_dir().join(format!("miraserve-r7-pub-2-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;

    let shared_key = Ed25519SigningKey::generate()?;
    let pub_path = dir.join("shared.pub");
    fs::write(&pub_path, shared_key.verifying_key().to_encoded())?;
    let now_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    let storage_a = dir.join("site-a");
    let cfg_a = AiPublishConfig {
        storage: storage_a.to_string_lossy().into_owned(),
        site_id: Some("a.local".to_owned()),
        keep_versions: 5,
        require_signature: Some(SignatureRequirement {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_path: pub_path.to_string_lossy().into_owned(),
        }),
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        preflight_checks: vec![PreflightCheck::NoSecrets],
        mcp_endpoint: None,
    };
    let store_a = ReleaseStore::open_for_site(cfg_a.clone(), Some("a.local".to_owned()))?;
    let mut b_a = make_bundle("<h1>Site A</h1>", "a", now_unix - 20);
    b_a.site_id = Some("a.local".to_owned());
    let _rel_a = store_a.publish(&SignedBundle::sign(b_a, &shared_key))?;

    // Create an unbound v2 release (site_id = None) signed by the same shared key.
    let foreign_storage = dir.join("foreign-v2");
    let mut foreign_cfg = cfg_a.clone();
    foreign_cfg.storage = foreign_storage.to_string_lossy().into_owned();
    foreign_cfg.site_id = None;
    let foreign_store = ReleaseStore::open(foreign_cfg)?;
    let planted_v2 = foreign_store.publish(&SignedBundle::sign(
        make_bundle("<h1>Planted Foreign V2</h1>", "planted", now_unix - 10),
        &shared_key,
    ))?;

    let src = foreign_storage
        .join("releases")
        .join(&planted_v2.release_id);
    let dst = storage_a.join("releases").join(&planted_v2.release_id);
    fs::create_dir_all(dst.join("public"))?;
    fs::copy(src.join("release.json"), dst.join("release.json"))?;
    fs::copy(src.join("public/index.html"), dst.join("public/index.html"))?;

    // Site A's legacy-v2-allowlist is empty (`[]`); rollback is refused (R5-PUB-4).
    assert!(store_a.rollback(Some(&planted_v2.release_id)).is_err());

    // R7-PUB-2: `resign` MUST ALSO refuse the planted unbound v2 release!
    let vk = shared_key.verifying_key();
    let resign_one = store_a.resign_release_with_options(
        &planted_v2.release_id,
        &shared_key,
        miraserve_publish::ResignOptions {
            include_unsigned: false,
            old_verifying_key: Some(&vk),
            rebind_from_site_id: None,
        },
    );
    assert!(
        matches!(resign_one, Err(PublishError::InvalidSignature(ref m)) if m.contains("legacy-v2 allowlist")),
        "R7-PUB-2: resign_release must refuse planted unbound v2 release, got: {resign_one:?}"
    );
    let resign_all = store_a.resign_all_with_options(
        &shared_key,
        miraserve_publish::ResignOptions {
            include_unsigned: false,
            old_verifying_key: Some(&vk),
            rebind_from_site_id: None,
        },
    );
    assert!(
        matches!(resign_all, Err(PublishError::InvalidSignature(ref m)) if m.contains("legacy-v2 allowlist")),
        "R7-PUB-2: resign_all must refuse planted unbound v2 release, got: {resign_all:?}"
    );
    // Rollback remains strictly refused!
    assert!(store_a.rollback(Some(&planted_v2.release_id)).is_err());

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// R8-PUB-1: a planted release with NO signature must never be signed by a routine `resign`,
/// even when its unauthenticated `release.json` claims `"signature_verified": true`, and a bulk
/// `resign` must never accept `include_unsigned`.
#[test]
fn r8_pub_1_resign_never_adopts_planted_unsigned_release_via_flag_or_bulk_include_unsigned()
-> TestResult {
    let dir = std::env::temp_dir().join(format!("miraserve-r8-pub-1-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;

    let key = Ed25519SigningKey::generate()?;
    let vk = key.verifying_key();
    let pub_path = dir.join("k.pub");
    fs::write(&pub_path, vk.to_encoded())?;
    let now_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    let storage_a = dir.join("site-a");
    let cfg_a = AiPublishConfig {
        storage: storage_a.to_string_lossy().into_owned(),
        site_id: Some("a.local".to_owned()),
        keep_versions: 5,
        require_signature: Some(SignatureRequirement {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_path: pub_path.to_string_lossy().into_owned(),
        }),
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        preflight_checks: vec![PreflightCheck::NoSecrets],
        mcp_endpoint: None,
    };
    let store_a = ReleaseStore::open_for_site(cfg_a.clone(), Some("a.local".to_owned()))?;
    let mut good = make_bundle("<h1>Good</h1>", "good", now_unix - 20);
    good.site_id = Some("a.local".to_owned());
    let good_rel = store_a.publish(&SignedBundle::sign(good, &key))?;

    // An attacker with storage write access (and NO signing key) creates an unsigned release in
    // a throwaway store and copies it in.
    let evil_storage = dir.join("evil");
    let mut evil_cfg = cfg_a.clone();
    evil_cfg.storage = evil_storage.to_string_lossy().into_owned();
    evil_cfg.site_id = None;
    evil_cfg.require_signature = None;
    let evil_store = ReleaseStore::open(evil_cfg)?;
    let planted = evil_store.publish(&SignedBundle {
        bundle: make_bundle("<h1>EVIL-UNSIGNED</h1>", "evil", now_unix - 10),
        signature_b64: None,
    })?;
    let src = evil_storage.join("releases").join(&planted.release_id);
    let dst = storage_a.join("releases").join(&planted.release_id);
    fs::create_dir_all(dst.join("public"))?;
    fs::copy(src.join("public/index.html"), dst.join("public/index.html"))?;
    let forged = fs::read_to_string(src.join("release.json"))?.replace(
        "\"signature_verified\": false",
        "\"signature_verified\": true",
    );
    assert!(
        forged.contains("\"signature_verified\": true"),
        "test setup: flag must be forged"
    );
    fs::write(dst.join("release.json"), forged)?;

    let rotate = miraserve_publish::ResignOptions {
        include_unsigned: false,
        old_verifying_key: Some(&vk),
        rebind_from_site_id: None,
    };
    // The documented key-rotation command (all releases) must refuse, not sign the plant.
    let bulk = store_a.resign_all_with_options(&key, rotate);
    assert!(
        matches!(bulk, Err(PublishError::InvalidSignature(ref m)) if m.contains("R8-PUB-1")),
        "R8-PUB-1: bulk resign must refuse a planted unsigned release whose flag is forged, got: {bulk:?}"
    );
    let single = store_a.resign_release_with_options(&planted.release_id, &key, rotate);
    assert!(
        matches!(single, Err(PublishError::InvalidSignature(ref m)) if m.contains("R8-PUB-1")),
        "R8-PUB-1: single resign without --include-unsigned must refuse, got: {single:?}"
    );
    // Bulk + include_unsigned is never allowed.
    let bulk_unsigned = store_a.resign_all_with_options(
        &key,
        miraserve_publish::ResignOptions {
            include_unsigned: true,
            old_verifying_key: Some(&vk),
            rebind_from_site_id: None,
        },
    );
    assert!(
        matches!(bulk_unsigned, Err(PublishError::InvalidSignature(ref m)) if m.contains("--release-id")),
        "R8-PUB-1: bulk resign with include_unsigned must demand an explicit release id, got: {bulk_unsigned:?}"
    );
    // The plant stays unsigned on disk and cannot be activated.
    let on_disk = fs::read_to_string(dst.join("release.json"))?;
    assert!(
        !on_disk.contains("signature_b64"),
        "R8-PUB-1: planted release must not have gained a signature: {on_disk}"
    );
    assert!(store_a.rollback(Some(&planted.release_id)).is_err());

    // The legitimate release is still re-signable on its own.
    store_a.resign_release_with_options(&good_rel.release_id, &key, rotate)?;

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// R7-PUB-3: Neither activation/rollback errors nor resign errors echo the foreign `site_id` or a
/// copy-paste `--rebind-site-id --from-site-id <foreign>` command.
#[test]
fn r7_pub_3_errors_do_not_echo_foreign_site_id_or_rebind_command() -> TestResult {
    let dir = std::env::temp_dir().join(format!("miraserve-r7-pub-3-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;

    let key = Ed25519SigningKey::generate()?;
    let pub_path = dir.join("key.pub");
    fs::write(&pub_path, key.verifying_key().to_encoded())?;
    let now_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    let make_cfg = |st: &std::path::Path, site_id: &str| AiPublishConfig {
        storage: st.to_string_lossy().into_owned(),
        site_id: Some(site_id.to_owned()),
        keep_versions: 3,
        require_signature: Some(SignatureRequirement {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_path: pub_path.to_string_lossy().into_owned(),
        }),
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        preflight_checks: vec![PreflightCheck::NoSecrets],
        mcp_endpoint: None,
    };

    let storage_a = dir.join("site-a");
    let storage_b = dir.join("site-b");
    let store_b = ReleaseStore::open_for_site(
        make_cfg(&storage_b, "secret-b.local"),
        Some("secret-b.local".to_owned()),
    )?;
    let mut b_b = make_bundle("<h1>B</h1>", "b", now_unix);
    b_b.site_id = Some("secret-b.local".to_owned());
    let rel_b = store_b.publish(&SignedBundle::sign(b_b, &key))?;

    let store_a =
        ReleaseStore::open_for_site(make_cfg(&storage_a, "a.local"), Some("a.local".to_owned()))?;
    let src = storage_b.join("releases").join(&rel_b.release_id);
    let dst = storage_a.join("releases").join(&rel_b.release_id);
    fs::create_dir_all(dst.join("public"))?;
    fs::copy(src.join("release.json"), dst.join("release.json"))?;
    fs::copy(src.join("public/index.html"), dst.join("public/index.html"))?;

    let rollback_err = store_a.rollback(Some(&rel_b.release_id));
    let rollback_msg = format!("{rollback_err:?}");
    assert!(
        rollback_err.is_err()
            && !rollback_msg.contains("secret-b.local")
            && !rollback_msg.contains("--rebind-site-id")
            && rollback_msg.contains("docs/DEPLOYMENT.md"),
        "R7-PUB-3: rollback error must not echo foreign site_id or copy-paste command: {rollback_msg}"
    );

    let vk = key.verifying_key();
    let resign_err = store_a.resign_release_with_options(
        &rel_b.release_id,
        &key,
        miraserve_publish::ResignOptions {
            include_unsigned: false,
            old_verifying_key: Some(&vk),
            rebind_from_site_id: None,
        },
    );
    let resign_msg = format!("{resign_err:?}");
    assert!(
        resign_err.is_err()
            && !resign_msg.contains("secret-b.local")
            && !resign_msg.contains("--rebind-site-id")
            && resign_msg.contains("docs/DEPLOYMENT.md"),
        "R7-PUB-3: resign error must not echo foreign site_id or copy-paste command: {resign_msg}"
    );

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// R7-PUB-4: Replay cache clamps abnormally distant expiry timestamps (`u64::MAX`) to
/// `now + MAX_REPLAY_CACHE_TTL_SECS`, rejects oversized (>2 MiB) `replay-cache.json` files with
/// HTTP 503, and returns HTTP 503 (distinct from 401 replay) when saturated.
#[test]
#[allow(clippy::too_many_lines)]
fn r7_pub_4_replay_cache_clamps_distant_expiry_caps_size_and_returns_503_on_faults() -> TestResult {
    let dir = std::env::temp_dir().join(format!("miraserve-r7-pub-4-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;

    let key = Ed25519SigningKey::generate()?;
    let pub_path = dir.join("pub.key");
    fs::write(&pub_path, key.verifying_key().to_encoded())?;
    let storage = dir.join("store");
    let cfg = AiPublishConfig {
        storage: storage.to_string_lossy().into_owned(),
        site_id: Some("replay7.example".to_owned()),
        keep_versions: 3,
        require_signature: Some(SignatureRequirement {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_path: pub_path.to_string_lossy().into_owned(),
        }),
        jwt_public_key: None,
        jwt_issuer: None,
        allowed_subjects: Vec::new(),
        preflight_checks: vec![PreflightCheck::NoSecrets],
        mcp_endpoint: Some(McpPublishEndpoint {
            path: "/_miraserve/publish".to_owned(),
            auth: PublishAuthMode::Ed25519,
        }),
    };

    let now_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let send_req = |st: &ReleaseStore, nonce: &str| -> u16 {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;
        let ts = now_unix.to_string();
        let sig_b64 = key.sign_mcp_request(
            "replay7.example",
            "/_miraserve/publish",
            now_unix,
            Some(nonce),
            body,
        );
        let mut hdrs = HeaderMap::new();
        if let Ok(v) = HeaderValue::from_str(&ts) {
            hdrs.insert("x-miraserve-timestamp", v);
        }
        if let Ok(v) = HeaderValue::from_str(nonce) {
            hdrs.insert("x-miraserve-nonce", v);
        }
        if let Ok(v) = HeaderValue::from_str(&sig_b64) {
            hdrs.insert("x-miraserve-signature", v);
        }
        let ctx = McpPublishAuthContext {
            endpoint_path: "/_miraserve/publish",
            site_host: "replay7.example",
            is_https: true,
            verified_client_cert_dn: None,
        };
        handle_mcp_publish_http(st, PublishAuthMode::Ed25519, &hdrs, body, &ctx)
            .status()
            .as_u16()
    };

    // 1. Entry with `exp = u64::MAX` is clamped on load and persisted back with `exp <= now + 720`!
    fs::create_dir_all(storage.join("releases"))?;
    let max_fp = format!("{:064x}", 1_u64);
    let planted_cache = serde_json::json!({
        "entries": {
            max_fp.clone(): u64::MAX
        }
    });
    fs::write(
        storage.join("replay-cache.json"),
        serde_json::to_vec(&planted_cache)?,
    )?;
    let store = ReleaseStore::open_for_site(cfg.clone(), Some("replay7.example".to_owned()))?;
    assert_eq!(send_req(&store, "r7-pub-4-fresh-1"), 200);
    // Verify persisted file now holds the clamped timestamp (never u64::MAX!)
    let persisted_raw = fs::read_to_string(storage.join("replay-cache.json"))?;
    let persisted_val: serde_json::Value = serde_json::from_str(&persisted_raw)?;
    let clamped_exp = persisted_val
        .get("entries")
        .and_then(|e| e.get(&max_fp))
        .and_then(serde_json::Value::as_u64)
        .ok_or("expected entry in persisted replay-cache.json")?;
    assert!(
        clamped_exp <= now_unix.saturating_add(730),
        "R7-PUB-4: u64::MAX expiry must be clamped to <= now + 720s, got {clamped_exp} (now={now_unix})"
    );
    // Exact replay of `r7-pub-4-fresh-1` returns 401 (distinct from 503 cache fault).
    assert_eq!(send_req(&store, "r7-pub-4-fresh-1"), 401);

    // 2. Saturated cache (8,192 unexpired entries) returns 503 Service Unavailable (NOT 401)!
    let mut full_entries = serde_json::Map::with_capacity(8_192);
    for i in 0..8_192_u32 {
        full_entries.insert(format!("{i:064x}"), serde_json::Value::from(u64::MAX));
    }
    fs::write(
        storage.join("replay-cache.json"),
        serde_json::to_vec(&serde_json::json!({ "entries": full_entries }))?,
    )?;
    let saturated_store =
        ReleaseStore::open_for_site(cfg.clone(), Some("replay7.example".to_owned()))?;
    assert_eq!(
        send_req(&saturated_store, "r7-pub-4-saturated"),
        503,
        "R7-PUB-4: saturated replay cache must return 503 (distinct from 401 replay)"
    );

    // 3. Oversized (> 2 MiB) replay-cache.json is rejected without unbounded read -> 503!
    let huge = vec![b' '; 2 * 1024 * 1024 + 64];
    fs::write(storage.join("replay-cache.json"), &huge)?;
    let huge_store = ReleaseStore::open_for_site(cfg, Some("replay7.example".to_owned()))?;
    assert_eq!(
        send_req(&huge_store, "r7-pub-4-oversized"),
        503,
        "R7-PUB-4: oversized >2 MiB replay-cache.json must fail closed with 503"
    );

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

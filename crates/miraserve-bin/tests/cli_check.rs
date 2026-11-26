//! End-to-end CLI integration tests for the `miraserve` binary.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn miraserve_bin() -> &'static str {
    env!("CARGO_BIN_EXE_miraserve")
}

fn example_config_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("examples")
        .join("miraserve.kdl")
}

#[test]
fn check_reference_example_succeeds_with_security_warning() -> TestResult {
    let output = Command::new(miraserve_bin())
        .args(["check", "--strict"])
        .arg(example_config_path())
        .output()?;

    assert!(
        output.status.success(),
        "examples/miraserve.kdl should pass check --strict cleanly, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("OK:"), "stdout: {stdout}");
    assert!(stdout.contains("3 site(s)"), "stdout: {stdout}");
    assert!(stdout.contains("X25519MLKEM768"), "stdout: {stdout}");
    Ok(())
}

#[test]
fn check_reference_example_strict_fails_on_warning() -> TestResult {
    let mut child = Command::new(miraserve_bin())
        .args(["check", "--strict", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(
            br#"
server {
    listen ":443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key"; }
}
site "legacy.example.com" {
    tls { compat-tls-1-2 #true; }
    root "/var/www/legacy"
}
"#,
        )?;
    }
    let output = child.wait_with_output()?;

    assert!(
        !output.status.success(),
        "expected --strict to fail on W002"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("W002") && stderr.contains("--strict"),
        "stderr: {stderr}"
    );
    Ok(())
}

#[test]
fn check_reference_example_json_output_is_well_formed() -> TestResult {
    let output = Command::new(miraserve_bin())
        .args(["check", "--format", "json", "--dump-normalized"])
        .arg(example_config_path())
        .output()?;

    assert!(output.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        parsed.get("valid").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        parsed
            .get("summary")
            .and_then(|s| s.get("sites"))
            .and_then(serde_json::Value::as_u64),
        Some(3)
    );
    assert!(parsed.get("config").is_some());
    assert_eq!(
        parsed
            .get("config")
            .and_then(|c| c.get("server"))
            .and_then(|s| s.get("tls"))
            .and_then(|t| t.get("acme"))
            .and_then(|a| a.get("challenge"))
            .and_then(serde_json::Value::as_str),
        Some("tls-alpn-01")
    );
    Ok(())
}

#[test]
fn check_clean_kdl_v2_from_stdin_passes_strict() -> TestResult {
    let clean_kdl = r#"
server {
    listen ":443" protocols="h3,h2,h1"
    tls {
        min-version "1.3"
        pqc-hybrid #true
        cert "/etc/miraserve/certs/starter.crt"
        key "/etc/miraserve/certs/starter.key"
    }
    sandbox {
        user "miraserve"
        landlock #true
        seccomp "strict"
    }
}
site "clean.example.com" {
    root "/var/www/clean"
}
"#;

    let mut child = Command::new(miraserve_bin())
        .args(["check", "-", "--strict", "--format", "json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(clean_kdl.as_bytes())?;
    }

    let output = child.wait_with_output()?;
    assert!(
        output.status.success(),
        "expected exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        parsed.get("valid").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        parsed
            .get("warnings")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    Ok(())
}

#[test]
fn check_invalid_config_from_stdin_exits_nonzero_with_json_errors() -> TestResult {
    let bad_kdl = r#"
server {
    listen ":443"
    tls { min-version "1.0" }
    sandbox { user "root" }
}
"#;

    let mut child = Command::new(miraserve_bin())
        .args(["check", "-", "--format", "json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(bad_kdl.as_bytes())?;
    }

    let output = child.wait_with_output()?;
    assert!(!output.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        parsed.get("valid").and_then(serde_json::Value::as_bool),
        Some(false)
    );
    let errors = parsed
        .get("errors")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing errors array")?;
    assert!(errors.len() >= 2);
    Ok(())
}

#[test]
fn check_missing_file_exits_nonzero() -> TestResult {
    let output = Command::new(miraserve_bin())
        .args(["check", "/nonexistent/path/to/miraserve.kdl"])
        .output()?;

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to read configuration file"),
        "stderr: {stderr}"
    );
    Ok(())
}

/// 0.1.5: `service generate --allow-openat2` is announced as an exact, comma-separated token, so
/// a panel can probe for it without parsing `--help`.
#[test]
fn version_lists_the_service_allow_openat2_token() -> TestResult {
    let version = Command::new(miraserve_bin()).arg("version").output()?;
    assert!(version.status.success());
    let stdout = String::from_utf8_lossy(&version.stdout);
    assert!(
        stdout.lines().any(|line| {
            line.strip_prefix("features:").is_some_and(|rest| {
                rest.split(',')
                    .any(|token| token.trim() == "service-allow-openat2")
            })
        }),
        "expected the `service-allow-openat2` token on the features line, got:\n{stdout}"
    );
    Ok(())
}

#[test]
fn version_and_planned_subcommands_behave_cleanly() -> TestResult {
    let version = Command::new(miraserve_bin()).arg("version").output()?;
    assert!(version.status.success());
    let stdout = String::from_utf8_lossy(&version.stdout);
    assert!(stdout.contains("miraserve "));
    assert!(stdout.contains("X25519MLKEM768"));
    assert!(
        stdout.lines().any(|line| {
            line.starts_with("features:")
                && line.contains("precompressed")
                && line.contains("header-rule-status")
        }),
        "expected features line with precompressed and header-rule-status in `miraserve version` output, got:\n{stdout}"
    );

    // Verify `miraserve service generate` produces hardened systemd, systemd-keyd, launchd, and Windows units
    // and rejects privileged root accounts or injection payloads fail-closed!
    for (target, expected_snippet) in [
        ("systemd", "AmbientCapabilities=CAP_NET_BIND_SERVICE"),
        ("systemd-keyd", "PrivateNetwork=yes"),
        ("launchd", "<string>app.miraserve.server</string>"),
        ("windows", "Register-ScheduledTask"),
    ] {
        let out = Command::new(miraserve_bin())
            .args(["service", "generate", "--target", target])
            .output()?;
        assert!(
            out.status.success(),
            "service generate --target {target} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let body = String::from_utf8_lossy(&out.stdout);
        assert!(
            body.contains(expected_snippet),
            "target {target} missing '{expected_snippet}':\n{body}"
        );
    }

    // Refuse privileged root users (including numeric `00`), systemd `%` specifiers,
    // newline/shell injection, and Unicode smart-quote PowerShell terminators (`R2-PKG-5`).
    for bad_args in [
        vec![
            "service", "generate", "--target", "systemd", "--user", "root",
        ],
        vec!["service", "generate", "--target", "systemd", "--user", "00"],
        vec![
            "service",
            "generate",
            "--target",
            "systemd",
            "--config",
            "/etc/miraserve.kdl\nExecStart=/bin/sh",
        ],
        vec![
            "service",
            "generate",
            "--target",
            "systemd",
            "--config",
            "/etc/%h/miraserve.kdl",
        ],
        vec![
            "service",
            "generate",
            "--target",
            "windows",
            "--config",
            "C:\\ProgramData\\MiraServe\u{2019};calc.exe",
        ],
    ] {
        let out = Command::new(miraserve_bin()).args(&bad_args).output()?;
        assert!(
            !out.status.success(),
            "expected service generate failure for {bad_args:?}"
        );
    }

    // ECH-1 (§4 Q6): `miraserve cert ech-generate` MUST refuse to print a publishable DNS HTTPS
    // record while server-side ECH decryption is not yet wired in rustls 0.23.
    let ech = Command::new(miraserve_bin())
        .args([
            "cert",
            "ech-generate",
            "--public-name",
            "edge.example.com",
            "--format",
            "json",
        ])
        .output()?;
    assert!(
        !ech.status.success(),
        "ech-generate must fail closed while server-side ECH decryption is unavailable (ECH-1)"
    );
    let ech_err = String::from_utf8_lossy(&ech.stderr);
    assert!(
        ech_err.contains("refusing to print a DNS HTTPS ECH record"),
        "expected explicit ECH refusal diagnostic, got: {ech_err}"
    );
    assert!(
        ech.stdout.is_empty(),
        "ech-generate must not print a DNS record to stdout when refusing"
    );

    // Verify `miraserve keyd --help` exposes the split-privilege TLS signing daemon CLI.
    let keyd_help = Command::new(miraserve_bin())
        .args(["keyd", "--help"])
        .output()?;
    assert!(keyd_help.status.success());
    assert!(String::from_utf8_lossy(&keyd_help.stdout).contains("--socket"));

    Ok(())
}

#[allow(clippy::too_many_lines)]
#[test]
fn publish_keygen_sign_verify_deploy_list_and_rollback_roundtrip() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base =
        std::env::temp_dir().join(format!("miraserve-cli-pub-{}-{nanos}", std::process::id()));
    let v1_dir = base.join("site-v1");
    let v2_dir = base.join("site-v2");
    let bad_dir = base.join("site-secret");
    let storage_dir = base.join("storage");
    let sec_path = base.join("publisher.key");
    let pub_path = base.join("publisher.pub");
    let bundle_path = base.join("v1.bundle.json");

    std::fs::create_dir_all(&v1_dir)?;
    std::fs::create_dir_all(&v2_dir)?;
    std::fs::create_dir_all(&bad_dir)?;
    std::fs::write(
        v1_dir.join("index.html"),
        "<!doctype html><html><body><h1>Version 1</h1></body></html>",
    )?;
    std::fs::write(v1_dir.join("llms.txt"), "# Site V1\n")?;
    std::fs::write(
        v2_dir.join("index.html"),
        "<!doctype html><html><body><h1>Version 2</h1></body></html>",
    )?;
    std::fs::write(
        bad_dir.join("index.html"),
        "<html><body>sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</body></html>",
    )?;

    // 1. Keygen
    let keygen = Command::new(miraserve_bin())
        .args(["publish", "keygen", "--secret"])
        .arg(&sec_path)
        .arg("--public")
        .arg(&pub_path)
        .output()?;
    assert!(
        keygen.status.success(),
        "keygen failed: {}",
        String::from_utf8_lossy(&keygen.stderr)
    );

    // 2. Sign + Verify (`--site-id` is mandatory per R5-PUB-4)
    let sign_no_site = Command::new(miraserve_bin())
        .args(["publish", "sign"])
        .arg(&v1_dir)
        .arg("--key")
        .arg(&sec_path)
        .arg("--output")
        .arg(&bundle_path)
        .output()?;
    assert!(
        !sign_no_site.status.success(),
        "publish sign without --site-id must fail (R5-PUB-4)"
    );

    let sign = Command::new(miraserve_bin())
        .args(["publish", "sign"])
        .arg(&v1_dir)
        .arg("--key")
        .arg(&sec_path)
        .arg("--output")
        .arg(&bundle_path)
        .args(["--site-id", "cli-test.example.com", "--note", "initial v1"])
        .output()?;
    assert!(
        sign.status.success(),
        "sign failed: {}",
        String::from_utf8_lossy(&sign.stderr)
    );

    let verify = Command::new(miraserve_bin())
        .args(["publish", "verify"])
        .arg(&bundle_path)
        .arg("--pubkey")
        .arg(&pub_path)
        .output()?;
    assert!(
        verify.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    assert!(String::from_utf8_lossy(&verify.stdout).contains("valid Ed25519 signature"));

    // 3. §4 Q4: `publish deploy` WITHOUT `--config` fails closed by default unless
    //    `--allow-unconfigured-policy` is explicitly passed!
    let dep1_refused = Command::new(miraserve_bin())
        .args(["publish", "deploy"])
        .arg(&v1_dir)
        .arg("--storage")
        .arg(&storage_dir)
        .arg("--key")
        .arg(&sec_path)
        .arg("--pubkey")
        .arg(&pub_path)
        .output()?;
    assert!(
        !dep1_refused.status.success(),
        "deploy without --config must fail closed unless --allow-unconfigured-policy is passed"
    );
    assert!(
        String::from_utf8_lossy(&dep1_refused.stderr).contains("--config"),
        "expected --config guidance, got: {}",
        String::from_utf8_lossy(&dep1_refused.stderr)
    );

    // 3b. Deploy V1 with explicit `--allow-unconfigured-policy`
    let dep1 = Command::new(miraserve_bin())
        .args(["publish", "deploy", "--allow-unconfigured-policy"])
        .arg(&v1_dir)
        .arg("--storage")
        .arg(&storage_dir)
        .arg("--key")
        .arg(&sec_path)
        .arg("--pubkey")
        .arg(&pub_path)
        .args(["--no-inline-scripts", "--note", "v1", "--format", "json"])
        .output()?;
    assert!(
        dep1.status.success(),
        "deploy v1 failed: {}",
        String::from_utf8_lossy(&dep1.stderr)
    );
    let rel1: serde_json::Value = serde_json::from_slice(&dep1.stdout)?;
    let rel1_id = rel1
        .get("release_id")
        .and_then(serde_json::Value::as_str)
        .ok_or("missing v1 release_id")?
        .to_owned();
    assert_eq!(
        rel1.get("signature_verified")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );

    // 4. Reject leaked secret in pre-flight check
    let dep_bad = Command::new(miraserve_bin())
        .args(["publish", "deploy", "--allow-unconfigured-policy"])
        .arg(&bad_dir)
        .arg("--storage")
        .arg(&storage_dir)
        .arg("--key")
        .arg(&sec_path)
        .arg("--pubkey")
        .arg(&pub_path)
        .output()?;
    assert!(!dep_bad.status.success());
    let bad_err = String::from_utf8_lossy(&dep_bad.stderr);
    assert!(
        bad_err.contains("NO_SECRETS"),
        "expected secret leak rejection, got: {bad_err}"
    );

    // 5. Deploy V2
    let dep2 = Command::new(miraserve_bin())
        .args(["publish", "deploy", "--allow-unconfigured-policy"])
        .arg(&v2_dir)
        .arg("--storage")
        .arg(&storage_dir)
        .arg("--key")
        .arg(&sec_path)
        .arg("--pubkey")
        .arg(&pub_path)
        .args(["--note", "v2", "--format", "json"])
        .output()?;
    assert!(
        dep2.status.success(),
        "deploy v2 failed: {}",
        String::from_utf8_lossy(&dep2.stderr)
    );
    let rel2: serde_json::Value = serde_json::from_slice(&dep2.stdout)?;
    let rel2_id = rel2
        .get("release_id")
        .and_then(serde_json::Value::as_str)
        .ok_or("missing v2 release_id")?
        .to_owned();
    assert_ne!(rel1_id, rel2_id);

    // 6. List releases
    let list = Command::new(miraserve_bin())
        .args(["publish", "list", "--storage"])
        .arg(&storage_dir)
        .args(["--format", "json"])
        .output()?;
    assert!(list.status.success());
    let list_json: serde_json::Value = serde_json::from_slice(&list.stdout)?;
    assert_eq!(
        list_json
            .get("active_release_id")
            .and_then(serde_json::Value::as_str),
        Some(rel2_id.as_str())
    );

    // 7. Rollback to V1
    let rb = Command::new(miraserve_bin())
        .args(["publish", "rollback", "--storage"])
        .arg(&storage_dir)
        .args(["--format", "json"])
        .output()?;
    assert!(
        rb.status.success(),
        "rollback failed: {}",
        String::from_utf8_lossy(&rb.stderr)
    );
    let rb_json: serde_json::Value = serde_json::from_slice(&rb.stdout)?;
    assert_eq!(
        rb_json
            .get("release_id")
            .and_then(serde_json::Value::as_str),
        Some(rel1_id.as_str())
    );

    // 8. Resign a legacy pre-manifest release (stripped signature_b64) via `miraserve publish resign`
    let rel2_meta_path = storage_dir
        .join("releases")
        .join(&rel2_id)
        .join("release.json");
    let mut legacy_meta: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&rel2_meta_path)?)?;
    if let Some(obj) = legacy_meta.as_object_mut() {
        obj.remove("signature_b64");
    }
    std::fs::write(&rel2_meta_path, serde_json::to_string_pretty(&legacy_meta)?)?;

    // Rollback to legacy release under --pubkey fails closed with upgrade guidance
    let rb_legacy_fail = Command::new(miraserve_bin())
        .args(["publish", "rollback", "--storage"])
        .arg(&storage_dir)
        .args(["--release-id", &rel2_id, "--pubkey"])
        .arg(&pub_path)
        .output()?;
    assert!(!rb_legacy_fail.status.success());
    assert!(
        String::from_utf8_lossy(&rb_legacy_fail.stderr).contains("miraserve publish resign"),
        "expected resign guidance, got: {}",
        String::from_utf8_lossy(&rb_legacy_fail.stderr)
    );

    // §4 Q4: `publish resign` WITHOUT `--old-pubkey` fails closed by default unless
    // `--include-unsigned` is explicitly passed for pre-manifest migration!
    let resign_refused = Command::new(miraserve_bin())
        .args(["publish", "resign", "--storage"])
        .arg(&storage_dir)
        .arg("--key")
        .arg(&sec_path)
        .arg("--pubkey")
        .arg(&pub_path)
        .args(["--release-id", &rel2_id])
        .output()?;
    assert!(
        !resign_refused.status.success(),
        "resign without --old-pubkey must fail closed unless --include-unsigned is passed"
    );
    assert!(
        String::from_utf8_lossy(&resign_refused.stderr).contains("--old-pubkey"),
        "expected --old-pubkey guidance, got: {}",
        String::from_utf8_lossy(&resign_refused.stderr)
    );

    // Run `miraserve publish resign --include-unsigned` -> rollback under --pubkey now succeeds!
    let resign_out = Command::new(miraserve_bin())
        .args(["publish", "resign", "--include-unsigned", "--storage"])
        .arg(&storage_dir)
        .arg("--key")
        .arg(&sec_path)
        .arg("--pubkey")
        .arg(&pub_path)
        .args(["--release-id", &rel2_id, "--format", "json"])
        .output()?;
    assert!(
        resign_out.status.success(),
        "resign failed: {}",
        String::from_utf8_lossy(&resign_out.stderr)
    );
    let rb_after_resign = Command::new(miraserve_bin())
        .args(["publish", "rollback", "--storage"])
        .arg(&storage_dir)
        .args(["--release-id", &rel2_id, "--pubkey"])
        .arg(&pub_path)
        .output()?;
    assert!(
        rb_after_resign.status.success(),
        "rollback after resign failed: {}",
        String::from_utf8_lossy(&rb_after_resign.stderr)
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

#[test]
fn import_nginx_config_and_validate_generated_kdl_end_to_end() -> TestResult {
    let nginx_cfg = r"
server {
    listen 443 ssl;
    server_name migrate-demo.example.com;
    root /var/www/wordpress;
    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    }
    location / {
        try_files $uri $uri/ /index.php?$args;
    }
}
";

    let mut import_child = Command::new(miraserve_bin())
        .args(["import", "-", "--from", "auto"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = import_child.stdin.take() {
        stdin.write_all(nginx_cfg.as_bytes())?;
    }
    let import_out = import_child.wait_with_output()?;
    assert!(
        import_out.status.success(),
        "miraserve import failed: {}",
        String::from_utf8_lossy(&import_out.stderr)
    );
    let generated_kdl = String::from_utf8(import_out.stdout)?;
    assert!(generated_kdl.contains("preset \"wordpress-hardened\""));

    // Pipe the imported KDL directly into `miraserve check - --strict --dev-tls`
    // (imported snippet had no ssl_certificate, so --dev-tls acknowledges W015).
    let mut check_child = Command::new(miraserve_bin())
        .args(["check", "-", "--strict", "--dev-tls"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = check_child.stdin.take() {
        stdin.write_all(generated_kdl.as_bytes())?;
    }
    let check_out = check_child.wait_with_output()?;
    assert!(
        check_out.status.success(),
        "imported KDL failed strict check: {}",
        String::from_utf8_lossy(&check_out.stderr)
    );
    Ok(())
}

#[test]
fn cert_generate_dev_and_inspect_roundtrip() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let dir =
        std::env::temp_dir().join(format!("miraserve-cli-cert-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let cert_path = dir.join("dev.crt");
    let key_path = dir.join("dev.key");

    let gen_out = Command::new(miraserve_bin())
        .args([
            "cert",
            "generate-dev",
            "--hosts",
            "local.example.test,api.example.test",
            "--cert",
        ])
        .arg(&cert_path)
        .arg("--key")
        .arg(&key_path)
        .output()?;
    assert!(
        gen_out.status.success(),
        "generate-dev failed: {}",
        String::from_utf8_lossy(&gen_out.stderr)
    );

    let inspect_out = Command::new(miraserve_bin())
        .args(["cert", "inspect", "--format", "json"])
        .arg(&cert_path)
        .output()?;
    assert!(
        inspect_out.status.success(),
        "cert inspect failed: {}",
        String::from_utf8_lossy(&inspect_out.stderr)
    );

    let info: serde_json::Value = serde_json::from_slice(&inspect_out.stdout)?;
    let sans = info
        .get("sans")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing sans array")?;
    assert!(
        sans.iter()
            .any(|v| v.as_str() == Some("local.example.test"))
    );
    assert!(sans.iter().any(|v| v.as_str() == Some("api.example.test")));
    assert!(sans.iter().any(|v| v.as_str() == Some("localhost")));

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn import_security_downgrade_fails_without_allow_insecure_and_force_guards_overwrites() -> TestResult
{
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let dir = std::env::temp_dir().join(format!(
        "miraserve-cli-guards-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;

    let nginx_path = dir.join("auth.conf");
    let out_kdl = dir.join("out.kdl");
    std::fs::write(
        &nginx_path,
        r#"
server {
    listen 443 ssl;
    server_name app.example.test;
    location /public/ {
        proxy_pass http://127.0.0.1:8080;
    }
    location /admin/ {
        auth_basic "Admin";
        proxy_pass http://127.0.0.1:9000;
    }
}
"#,
    )?;

    // 1. MIG-3: Without --allow-insecure, import MUST exit non-zero and NOT write output file!
    let blocked = Command::new(miraserve_bin())
        .args(["import"])
        .arg(&nginx_path)
        .arg("-o")
        .arg(&out_kdl)
        .output()?;
    assert!(!blocked.status.success());
    assert!(
        String::from_utf8_lossy(&blocked.stderr).contains("SECURITY ERROR"),
        "expected loud SECURITY ERROR, got: {}",
        String::from_utf8_lossy(&blocked.stderr)
    );
    assert!(
        !out_kdl.exists(),
        "output file must not be written when security downgrade blocks import"
    );

    // 2. With --allow-insecure, import succeeds and omits /admin/!
    let allowed = Command::new(miraserve_bin())
        .args(["import", "--allow-insecure"])
        .arg(&nginx_path)
        .arg("-o")
        .arg(&out_kdl)
        .output()?;
    assert!(
        allowed.status.success(),
        "import --allow-insecure failed: {}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    let generated = std::fs::read_to_string(&out_kdl)?;
    assert!(!generated.contains("/admin"));
    assert!(generated.contains("/public/*"));

    // 3. CFG-7: Re-running import -o to existing file without --force MUST fail!
    let no_force = Command::new(miraserve_bin())
        .args(["import", "--allow-insecure"])
        .arg(&nginx_path)
        .arg("-o")
        .arg(&out_kdl)
        .output()?;
    assert!(!no_force.status.success());
    assert!(String::from_utf8_lossy(&no_force.stderr).contains("--force"));

    // 3b. R4-MIG-2 & MIG-6: CLI `--allow-insecure --format json` reports `insecure_sites_emitted`
    //     and `// INSECURE:` per-site marker for blocked sites, and prefix-stripping `proxy_pass`
    //     exits non-zero without `--allow-insecure`!
    let locked_path = dir.join("locked.conf");
    std::fs::write(
        &locked_path,
        "server {\n    listen 443 ssl;\n    server_name locked.example.test;\n    auth_basic \"Restricted\";\n    root /var/www/locked;\n}\n",
    )?;
    let json_insecure = Command::new(miraserve_bin())
        .args(["import", "--allow-insecure", "--format", "json"])
        .arg(&locked_path)
        .output()?;
    assert!(
        json_insecure.status.success(),
        "import --allow-insecure --format json failed: {}",
        String::from_utf8_lossy(&json_insecure.stderr)
    );
    let json_val: serde_json::Value = serde_json::from_slice(&json_insecure.stdout)?;
    assert_eq!(
        json_val.get("insecure_sites_emitted"),
        Some(&serde_json::json!(["locked.example.test"]))
    );
    assert!(
        json_val
            .get("kdl")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|k| k.contains("// INSECURE: emitted despite auth_basic")),
        "KDL must carry per-site // INSECURE marker: {json_val}"
    );

    let strip_path = dir.join("strip.conf");
    std::fs::write(
        &strip_path,
        "server {\n    listen 443 ssl;\n    server_name strip.example.test;\n    location /api/ {\n        proxy_pass http://127.0.0.1:8080/;\n    }\n}\n",
    )?;
    let strip_out = Command::new(miraserve_bin())
        .args(["import"])
        .arg(&strip_path)
        .output()?;
    assert!(
        !strip_out.status.success(),
        "MIG-6: prefix-stripping proxy_pass must exit non-zero without --allow-insecure"
    );

    // 4. TLS-3: cert generate-dev refuses to overwrite existing key without --force!
    let cert_path = dir.join("c.pem");
    let key_path = dir.join("k.pem");
    assert!(
        Command::new(miraserve_bin())
            .args(["cert", "generate-dev", "--cert"])
            .arg(&cert_path)
            .arg("--key")
            .arg(&key_path)
            .output()?
            .status
            .success()
    );
    let second_cert = Command::new(miraserve_bin())
        .args(["cert", "generate-dev", "--cert"])
        .arg(&cert_path)
        .arg("--key")
        .arg(&key_path)
        .output()?;
    assert!(!second_cert.status.success());

    // 5. PUB-10: publish list on nonexistent --storage fails without creating directories!
    let ghost_storage = dir.join("does-not-exist-store");
    let list_missing = Command::new(miraserve_bin())
        .args(["publish", "list", "--storage"])
        .arg(&ghost_storage)
        .output()?;
    assert!(!list_missing.status.success());
    assert!(
        !ghost_storage.exists(),
        "publish list must not create missing storage directories"
    );

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn packaged_service_units_and_container_config_stay_in_sync() -> TestResult {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");

    for (target, rel_path) in [
        ("systemd", "packaging/systemd/miraserve.service"),
        ("systemd-keyd", "packaging/systemd/miraserve-keyd.service"),
        ("launchd", "packaging/launchd/app.miraserve.server.plist"),
        ("windows", "packaging/windows/install-miraserve-service.ps1"),
    ] {
        let out = Command::new(miraserve_bin())
            .args(["service", "generate", "--target", target])
            .output()?;
        assert!(
            out.status.success(),
            "service generate --target {target} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let generated = String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n");
        let packaged = std::fs::read_to_string(root.join(rel_path))?.replace("\r\n", "\n");
        assert_eq!(
            generated, packaged,
            "checked-in {rel_path} drifted from `miraserve service generate --target {target}`"
        );
    }

    // --no-wasm tightens systemd with MemoryDenyWriteExecute=yes; --split-keyd enables keyd isolation
    let no_wasm = Command::new(miraserve_bin())
        .args([
            "service",
            "generate",
            "--target",
            "systemd",
            "--no-wasm",
            "--split-keyd",
        ])
        .output()?;
    assert!(no_wasm.status.success());
    let no_wasm_unit = String::from_utf8_lossy(&no_wasm.stdout);
    assert!(no_wasm_unit.contains("MemoryDenyWriteExecute=yes"));
    assert!(no_wasm_unit.contains("InaccessiblePaths=-/etc/miraserve/keys"));
    assert!(no_wasm_unit.contains("Wants=network-online.target miraserve-keyd.service"));

    // R3-PKG-2, R4-KEYD-1, R4-SBX-1 & R5-PKG-1..4: Shipped systemd worker unit unconditionally
    // blocks `/etc/miraserve/keys`, uses `/etc/miraserve/conf/miraserve.kdl` + `check --fs --acme-dir`,
    // and `miraserve-keyd.service` avoids `RuntimeDirectory=` (R5-PKG-3) so systemd never re-owns
    // `/run/miraserve-keyd` away from `miraserve-keyd:miraserve`, invoking `systemd-tmpfiles` instead.
    let default_unit = std::fs::read_to_string(root.join("packaging/systemd/miraserve.service"))?;
    assert!(default_unit.contains("InaccessiblePaths=-/etc/miraserve/keys"));
    assert!(default_unit.contains("TimeoutStopSec=45s"));
    assert!(default_unit.contains(
        "check --fs --acme-dir \"/var/lib/miraserve/acme\" \"/etc/miraserve/conf/miraserve.kdl\""
    ));

    let keyd_unit = std::fs::read_to_string(root.join("packaging/systemd/miraserve-keyd.service"))?;
    assert!(keyd_unit.contains("User=miraserve-keyd"));
    assert!(keyd_unit.contains("Group=miraserve-keyd"));
    // R7-PKG-1: keyd needs group `miraserve` to traverse 0750 root:miraserve `/etc/miraserve`
    // and read `/etc/miraserve/conf/miraserve.kdl`; `/etc/miraserve/certs/starter.key` is 0600
    // `miraserve:miraserve` so keyd still cannot read the worker's in-process starter key.
    assert!(keyd_unit.contains("SupplementaryGroups=miraserve"));
    assert!(!keyd_unit.contains("RuntimeDirectory=miraserve-keyd"));
    assert!(!keyd_unit.contains("/usr/lib/tmpfiles.d/miraserve.conf"));
    assert!(
        keyd_unit.contains(
            "ExecStartPre=+/usr/bin/systemd-tmpfiles --create --prefix=/run/miraserve-keyd"
        )
    );
    assert!(keyd_unit.contains("ReadWritePaths=-/run/miraserve-keyd"));
    assert!(keyd_unit.contains("--socket \"/run/miraserve-keyd/keyd.sock\""));
    assert!(keyd_unit.contains("--allow-peer-user miraserve"));
    assert!(!keyd_unit.contains("--allow-group-peers"));

    // R5-PKG-4 residual: preremove.sh has no dead `purge` branch (Debian purge runs in postremove.sh).
    let preremove_sh = std::fs::read_to_string(root.join("packaging/systemd/preremove.sh"))?;
    assert!(!preremove_sh.contains("= \"purge\""));

    // R5-PKG-1 & R5-PKG-4: nfpm ships starter.kdl to /usr/share/miraserve/starter.kdl (never
    // overwriting /etc/miraserve/conf/miraserve.kdl before postinstall migrates legacy configs),
    // and registers postremove.sh for Debian purge cleanup.
    let nfpm_yaml = std::fs::read_to_string(root.join("packaging/nfpm/nfpm.yaml"))?;
    assert!(nfpm_yaml.contains("/usr/share/miraserve/starter.kdl"));
    assert!(!nfpm_yaml.contains("dst: \"/etc/miraserve/conf/miraserve.kdl\""));
    assert!(!nfpm_yaml.contains("dst: /etc/miraserve/conf/miraserve.kdl"));
    assert!(nfpm_yaml.contains("postremove: \"packaging/systemd/postremove.sh\""));
    let postremove_sh = std::fs::read_to_string(root.join("packaging/systemd/postremove.sh"))?;
    assert!(postremove_sh.contains("purge"));
    assert!(postremove_sh.contains("/etc/miraserve/certs/starter.key"));

    // R2-PKG-5 & R3-PKG-4: Custom --graceful-drain derives stop timeout; launchd accepts --log-dir/--dev-tls;
    // Windows installer removes legacy SCM service, persists logs, and sets RestartCount 999.
    let custom_drain = Command::new(miraserve_bin())
        .args([
            "service",
            "generate",
            "--target",
            "systemd",
            "--graceful-drain",
            "120",
        ])
        .output()?;
    assert!(custom_drain.status.success());
    assert!(String::from_utf8_lossy(&custom_drain.stdout).contains("TimeoutStopSec=135s"));

    let custom_launchd = Command::new(miraserve_bin())
        .args([
            "service",
            "generate",
            "--target",
            "launchd",
            "--log-dir",
            "/var/log/miraserve-custom",
            "--dev-tls",
            "--graceful-drain",
            "90",
        ])
        .output()?;
    assert!(custom_launchd.status.success());
    let launchd_out = String::from_utf8_lossy(&custom_launchd.stdout);
    assert!(launchd_out.contains("/var/log/miraserve-custom/miraserve.out.log"));
    assert!(launchd_out.contains("<string>--dev-tls</string>"));
    assert!(launchd_out.contains("<integer>105</integer>"));

    let win_ps1 =
        std::fs::read_to_string(root.join("packaging/windows/install-miraserve-service.ps1"))?;
    assert!(win_ps1.contains("sc.exe delete $TaskName"));
    assert!(win_ps1.contains("-RestartCount 999"));
    assert!(win_ps1.contains("--log-file"));

    // LoopbackTcp keyd allows separate-UID operation with AF_INET/AF_INET6 and --auth-secret-file
    let tcp_keyd = Command::new(miraserve_bin())
        .args([
            "service",
            "generate",
            "--target",
            "systemd-keyd",
            "--user",
            "miraserve-keyd",
            "--keyd-socket",
            "tcp://127.0.0.1:9444",
            "--auth-secret-file",
            "/etc/miraserve/keyd.hmac",
        ])
        .output()?;
    assert!(tcp_keyd.status.success());
    let tcp_unit = String::from_utf8_lossy(&tcp_keyd.stdout);
    assert!(tcp_unit.contains("User=miraserve-keyd"));
    assert!(tcp_unit.contains("Group=miraserve-keyd"));
    assert!(tcp_unit.contains("PrivateNetwork=no"));
    assert!(tcp_unit.contains("RestrictAddressFamilies=AF_INET AF_INET6"));
    assert!(tcp_unit.contains("--auth-secret-file \"/etc/miraserve/keyd.hmac\""));
    assert!(!tcp_unit.contains("--allow-group-peers"));
    assert!(!tcp_unit.contains("--allow-peer-user"));

    // R3-PKG-1: Linux nFPM starter KDL passes strict validation WITHOUT --dev-tls (has starter cert/key),
    // while rootless distroless container KDL (uses --dev-tls CMD) emits W015 without --dev-tls and passes with --dev-tls!
    let nfpm_check = Command::new(miraserve_bin())
        .args(["check", "--strict"])
        .arg(root.join("packaging/nfpm/miraserve.kdl"))
        .output()?;
    assert!(
        nfpm_check.status.success(),
        "packaging/nfpm/miraserve.kdl failed strict check: {}",
        String::from_utf8_lossy(&nfpm_check.stderr)
    );

    let ctr_no_dev = Command::new(miraserve_bin())
        .args(["check", "--strict"])
        .arg(root.join("packaging/container/miraserve.kdl"))
        .output()?;
    assert!(
        !ctr_no_dev.status.success(),
        "container starter KDL without certs should fail --strict unless --dev-tls is passed (W015)"
    );
    assert!(String::from_utf8_lossy(&ctr_no_dev.stderr).contains("W015"));

    let ctr_with_dev = Command::new(miraserve_bin())
        .args(["check", "--strict", "--dev-tls"])
        .arg(root.join("packaging/container/miraserve.kdl"))
        .output()?;
    assert!(
        ctr_with_dev.status.success(),
        "packaging/container/miraserve.kdl failed --strict --dev-tls check: {}",
        String::from_utf8_lossy(&ctr_with_dev.stderr)
    );

    Ok(())
}

/// R2-PUB-6, R2-PUB-7, R2-KEYD-3 CLI hardening tests:
/// - `publish deploy --config ... --site ...` enforces site preflight checks & signing policy
/// - `publish resign --old-pubkey ...` verifies old signatures before rotating
/// - `keyd --socket tcp://127.0.0.1:0` fails fast when no HMAC auth secret is configured.
#[test]
#[allow(clippy::too_many_lines)]
fn cli_wave2_publish_config_policy_resign_and_keyd_tcp_auth_required() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::env::temp_dir().join(format!(
        "miraserve-wave2-cli-{}-{nanos}",
        std::process::id()
    ));
    let storage_dir = base.join("releases");
    let site_dir = base.join("site");
    std::fs::create_dir_all(&site_dir)?;
    std::fs::write(
        site_dir.join("index.html"),
        "<script>alert('inline')</script>",
    )?;

    let sec1 = base.join("k1.sec");
    let pub1 = base.join("k1.pub");
    let sec2 = base.join("k2.sec");
    let pub2 = base.join("k2.pub");
    for (s, p) in [(&sec1, &pub1), (&sec2, &pub2)] {
        let out = Command::new(miraserve_bin())
            .args(["publish", "keygen", "--secret"])
            .arg(s)
            .arg("--public")
            .arg(p)
            .output()?;
        assert!(
            out.status.success(),
            "keygen failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let cfg_path = base.join("miraserve.kdl");
    let kdl = format!(
        r#"
server {{
    listen ":443"
}}
site "policy.example.test" {{
    ai-publish {{
        storage "{}"
        require-signature "ed25519:{}"
        preflight-checks "no-inline-scripts" "no-secrets"
    }}
}}
"#,
        storage_dir.display(),
        pub1.display()
    );
    std::fs::write(&cfg_path, kdl)?;

    // 1. R2-PUB-6: deploy via `--config --site` rejects inline script via site preflight checks!
    let bad_deploy = Command::new(miraserve_bin())
        .args(["publish", "deploy"])
        .arg(&site_dir)
        .arg("--config")
        .arg(&cfg_path)
        .args(["--site", "policy.example.test"])
        .arg("--key")
        .arg(&sec1)
        .output()?;
    assert!(
        !bad_deploy.status.success(),
        "deploy via --config must enforce site preflight-checks"
    );

    // Replace with clean HTML -> deploy succeeds!
    std::fs::write(site_dir.join("index.html"), "<h1>Clean</h1>")?;
    let ok_deploy = Command::new(miraserve_bin())
        .args(["publish", "deploy"])
        .arg(&site_dir)
        .arg("--config")
        .arg(&cfg_path)
        .args(["--site", "policy.example.test"])
        .arg("--key")
        .arg(&sec1)
        .output()?;
    assert!(
        ok_deploy.status.success(),
        "clean deploy failed: {}",
        String::from_utf8_lossy(&ok_deploy.stderr)
    );

    // 2. R2-PUB-7: `resign --old-pubkey` verifies old key (rejects wrong old pubkey, accepts k1.pub)
    let bad_resign = Command::new(miraserve_bin())
        .args(["publish", "resign", "--storage"])
        .arg(&storage_dir)
        .arg("--key")
        .arg(&sec2)
        .arg("--old-pubkey")
        .arg(&pub2)
        .output()?;
    assert!(
        !bad_resign.status.success(),
        "resign with mismatched --old-pubkey must fail"
    );

    let ok_resign = Command::new(miraserve_bin())
        .args(["publish", "resign", "--storage"])
        .arg(&storage_dir)
        .arg("--key")
        .arg(&sec2)
        .arg("--old-pubkey")
        .arg(&pub1)
        .output()?;
    assert!(
        ok_resign.status.success(),
        "resign with matching --old-pubkey failed: {}",
        String::from_utf8_lossy(&ok_resign.stderr)
    );

    // 3. R2-KEYD-3: `miraserve keyd --socket tcp://127.0.0.1:0 --dev-tls` without auth secret fails fast!
    let keyd_no_secret = Command::new(miraserve_bin())
        .env_remove("MIRASERVE_KEYD_AUTH_SECRET")
        .args(["keyd", "--socket", "tcp://127.0.0.1:0", "--dev-tls"])
        .output()?;
    assert!(
        !keyd_no_secret.status.success(),
        "keyd on LoopbackTcp without auth secret must fail fast"
    );
    let keyd_err = String::from_utf8_lossy(&keyd_no_secret.stderr);
    assert!(
        keyd_err.contains("--auth-secret-file") || keyd_err.contains("MIRASERVE_KEYD_AUTH_SECRET"),
        "expected actionable auth secret error, got: {keyd_err}"
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// R3-PKG-1 & R3-RUN-1:
/// - Starter certificate generated via `cert generate-dev` allows `miraserve run` (without `--dev-tls`)
///   to boot cleanly, write `--log-file`, and hold an exclusive OS lock on `--pid-file`.
/// - A concurrent second instance using the same `--pid-file` fails immediately.
/// - Clean shutdown truncates `--pid-file` to 0 bytes without unlinking it (eliminating the
///   unlink-before-unlock inode race and Landlock RW requirement on `/run/miraserve`).
#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)]
fn cli_round3_starter_cert_boot_pid_lock_truncate_and_log_file() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base =
        std::env::temp_dir().join(format!("miraserve-r3-run-{}-{nanos}", std::process::id()));
    let certs_dir = base.join("certs");
    let www_dir = base.join("www");
    let acme_dir = base.join("acme");
    let pid_file = base.join("run/miraserve.pid");
    let log_file = base.join("logs/miraserve.log");
    std::fs::create_dir_all(&certs_dir)?;
    std::fs::create_dir_all(&www_dir)?;
    // The ACME state directory lives under `base`; with a `0002` umask `base` would be
    // group-writable, which the private-state ancestor check refuses by design.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755))?;
    }
    std::fs::write(www_dir.join("index.html"), b"starter ok")?;

    let cert_path = certs_dir.join("starter.crt");
    let key_path = certs_dir.join("starter.key");
    let cert_gen = Command::new(miraserve_bin())
        .args(["cert", "generate-dev", "--hosts", "localhost", "--cert"])
        .arg(&cert_path)
        .arg("--key")
        .arg(&key_path)
        .output()?;
    assert!(
        cert_gen.status.success(),
        "cert generate-dev failed: {}",
        String::from_utf8_lossy(&cert_gen.stderr)
    );

    let probe = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = probe.local_addr()?.port();
    drop(probe);

    let cfg_path = base.join("miraserve.kdl");
    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:{port}" protocols="h2,h1"
    tls {{
        min-version "1.3"
        pqc-hybrid #true
        cert "{}"
        key "{}"
    }}
}}
site "localhost" {{
    root "{}"
}}
"#,
        cert_path.display(),
        key_path.display(),
        www_dir.display()
    );
    std::fs::write(&cfg_path, kdl)?;

    // Config passes strict check WITHOUT --dev-tls!
    let check_out = Command::new(miraserve_bin())
        .args(["check", "--strict"])
        .arg(&cfg_path)
        .output()?;
    assert!(
        check_out.status.success(),
        "starter cert config failed strict check: {}",
        String::from_utf8_lossy(&check_out.stderr)
    );

    // Start first live instance WITHOUT --dev-tls (and --no-sandbox for macOS/Linux portability)
    let mut first = Command::new(miraserve_bin())
        .args(["run"])
        .arg(&cfg_path)
        .arg("--acme-dir")
        .arg(&acme_dir)
        .arg("--pid-file")
        .arg(&pid_file)
        .arg("--log-file")
        .arg(&log_file)
        .arg("--no-sandbox")
        // The assertion below needs the info-level startup line, independent of the caller's
        // inherited `RUST_LOG` (Codex fifth review).
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;

    // Wait up to 5s for the PID file to be written with the child PID
    let expected_pid = first.id().to_string();
    let mut ready = false;
    for _ in 0..50 {
        if let Ok(content) = std::fs::read_to_string(&pid_file)
            && content.trim() == expected_pid
        {
            ready = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        ready,
        "first miraserve instance did not write its PID file in time"
    );

    // R3-PKG-4: ACME dir must be created with 0700 mode on Unix!
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&acme_dir)?.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "ACME state dir must be created 0700, got {mode:04o}"
        );
    }

    // Second concurrent instance with the same --pid-file MUST fail immediately
    let second = Command::new(miraserve_bin())
        .args(["run"])
        .arg(&cfg_path)
        .arg("--pid-file")
        .arg(&pid_file)
        .arg("--no-sandbox")
        .output()?;
    assert!(
        !second.status.success(),
        "second concurrent miraserve instance should fail on locked PID file"
    );

    // R4-SBX-1: Live `miraserve reload` reports actual SIGHUP reload success AND failure!
    let reload_ok = Command::new(miraserve_bin())
        .args(["reload", "--pid-file"])
        .arg(&pid_file)
        .args(["--config"])
        .arg(&cfg_path)
        .output()?;
    assert!(
        reload_ok.status.success(),
        "live reload on valid config failed: stdout={} stderr={}",
        String::from_utf8_lossy(&reload_ok.stdout),
        String::from_utf8_lossy(&reload_ok.stderr)
    );
    assert!(
        String::from_utf8_lossy(&reload_ok.stdout).contains("reloaded successfully"),
        "expected confirmed reload status, got: {}",
        String::from_utf8_lossy(&reload_ok.stdout)
    );
    // Corrupt the config on disk and reload WITHOUT `--config` pre-check so the running server
    // rejects it during SIGHUP — `miraserve reload` MUST now exit non-zero and surface the error!
    let saved_cfg = std::fs::read_to_string(&cfg_path)?;
    std::fs::write(&cfg_path, "this is not valid kdl {{{")?;
    let reload_fail = Command::new(miraserve_bin())
        .args(["reload", "--pid-file"])
        .arg(&pid_file)
        .output()?;
    assert!(
        !reload_fail.status.success(),
        "live reload must exit non-zero when server SIGHUP reload fails (R4-SBX-1)"
    );
    assert!(
        String::from_utf8_lossy(&reload_fail.stderr).contains("reload failed"),
        "expected server reload error in stderr, got: {}",
        String::from_utf8_lossy(&reload_fail.stderr)
    );
    std::fs::write(&cfg_path, saved_cfg)?;

    // Gracefully terminate first instance with SIGTERM (`kill -TERM <pid>`)
    let _ = Command::new("kill").args(["-TERM", &expected_pid]).status();
    let status = first.wait()?;
    assert!(
        status.success(),
        "first instance did not exit cleanly on SIGTERM: {status}"
    );

    // R3-RUN-1: PID file MUST still exist (never unlinked!) and be truncated to 0 bytes
    assert!(
        pid_file.exists(),
        "PID file must not be unlinked on shutdown (R3-RUN-1)"
    );
    assert_eq!(
        std::fs::metadata(&pid_file)?.len(),
        0,
        "PID file must be truncated to 0 bytes on clean shutdown"
    );
    // R3-PKG-4: Log file received structured runtime logs
    let log_text = std::fs::read_to_string(&log_file)?;
    assert!(
        log_text.contains("MiraServe listening"),
        "expected structured logs in --log-file, got: {log_text}"
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Wave-1 Round-4 CLI regressions:
/// - `CFG-6` / `R4-PKG-2`: `miraserve check --fs` verifies on-disk certs/keys/roots (`E301`) and
///   surfaces Landlock policy refusals (`W017`, `R4-SBX-2`)
/// - `R3-RUN-1`: `miraserve reload` refuses an unlocked stale PID file
/// - `R4-KEYD-1`: `miraserve keyd --allow-peer-user 0` / `root` rejected fail-closed.
#[test]
#[allow(clippy::too_many_lines)]
fn cli_round4_wave1_check_fs_stale_pid_and_keyd_peer_user() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base =
        std::env::temp_dir().join(format!("miraserve-r4w1-cli-{}-{nanos}", std::process::id()));
    let site_root = base.join("www");
    std::fs::create_dir_all(&site_root)?;

    let cert_path = base.join("starter.crt");
    let key_path = base.join("starter.key");
    let missing_cert = base.join("missing.crt");

    // 1. Missing cert passes syntax-only `check`, but FAILS `check --fs` with E301 (CFG-6 / R4-PKG-2)
    let missing_cfg = base.join("missing.kdl");
    std::fs::write(
        &missing_cfg,
        format!(
            r#"
server {{
    listen "127.0.0.1:8443"
    tls {{
        cert "{}"
        key "{}"
    }}
}}
site "localhost" {{
    root "{}"
}}
"#,
            missing_cert.display(),
            key_path.display(),
            site_root.display(),
        ),
    )?;
    let syntax_ok = Command::new(miraserve_bin())
        .args(["check"])
        .arg(&missing_cfg)
        .output()?;
    assert!(
        syntax_ok.status.success(),
        "syntax-only check should pass when cert files don't exist yet: {}",
        String::from_utf8_lossy(&syntax_ok.stderr)
    );
    let fs_fail = Command::new(miraserve_bin())
        .args(["check", "--fs"])
        .arg(&missing_cfg)
        .output()?;
    assert!(
        !fs_fail.status.success(),
        "check --fs must fail when cert/key files are missing"
    );
    assert!(
        String::from_utf8_lossy(&fs_fail.stderr).contains("E301"),
        "expected E301 from check --fs, got: {}",
        String::from_utf8_lossy(&fs_fail.stderr)
    );

    // 2. Generate dev cert/key (`cert generate-dev` writes key first then atomic cert) and re-run `check --fs`
    let gen_out = Command::new(miraserve_bin())
        .args(["cert", "generate-dev", "--hosts", "localhost", "--cert"])
        .arg(&cert_path)
        .arg("--key")
        .arg(&key_path)
        .output()?;
    assert!(
        gen_out.status.success(),
        "cert generate-dev failed: {}",
        String::from_utf8_lossy(&gen_out.stderr)
    );
    let ok_cfg = base.join("ok.kdl");
    std::fs::write(
        &ok_cfg,
        format!(
            r#"
server {{
    listen "127.0.0.1:8443"
    tls {{
        cert "{}"
        key "{}"
    }}
}}
site "localhost" {{
    root "{}"
}}
"#,
            cert_path.display(),
            key_path.display(),
            site_root.display(),
        ),
    )?;
    let fs_ok = Command::new(miraserve_bin())
        .args(["check", "--fs", "--strict"])
        .arg(&ok_cfg)
        .output()?;
    assert!(
        fs_ok.status.success(),
        "check --fs --strict should pass when cert/key/root exist: {}",
        String::from_utf8_lossy(&fs_ok.stderr)
    );

    // 3. Relative root without a config-file base dir (stdin `-`) and parent traversal `../etc`
    //    fail hard with E202 in `check` (`R5-SBX-1`, `R6-CFG-1`).
    let bad_root_kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{
        cert "{}"
        key "{}"
    }}
}}
site "localhost" {{
    root "etc"
}}
"#,
        cert_path.display(),
        key_path.display(),
    );
    let mut stdin_child = Command::new(miraserve_bin())
        .args(["check", "--strict", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = stdin_child.stdin.take() {
        stdin.write_all(bad_root_kdl.as_bytes())?;
    }
    let bad_root_out = stdin_child.wait_with_output()?;
    assert!(
        !bad_root_out.status.success(),
        "relative root \"etc\" on stdin must fail validation via E202 (R5-SBX-1)"
    );
    assert!(
        String::from_utf8_lossy(&bad_root_out.stderr).contains("E202"),
        "expected E202 for relative root \"etc\" on stdin, got: {}",
        String::from_utf8_lossy(&bad_root_out.stderr)
    );

    let bad_root_cfg = base.join("bad-root.kdl");
    std::fs::write(
        &bad_root_cfg,
        bad_root_kdl.replace(r#"root "etc""#, r#"root "../etc""#),
    )?;
    let trav_out = Command::new(miraserve_bin())
        .args(["check", "--strict"])
        .arg(&bad_root_cfg)
        .output()?;
    assert!(
        !trav_out.status.success(),
        "traversal root \"../etc\" must fail validation via E202 (R5-SBX-1)"
    );
    assert!(
        String::from_utf8_lossy(&trav_out.stderr).contains("E202"),
        "expected E202 for traversal root \"../etc\", got: {}",
        String::from_utf8_lossy(&trav_out.stderr)
    );

    // 4. R3-RUN-1: `miraserve reload` rejects an UNLOCKED stale PID file (e.g. after SIGKILL)
    let stale_pid = base.join("stale.pid");
    std::fs::write(&stale_pid, format!("{}\n", std::process::id()))?;
    let stale_reload = Command::new(miraserve_bin())
        .args(["reload", "--pid-file"])
        .arg(&stale_pid)
        .output()?;
    assert!(
        !stale_reload.status.success(),
        "reload must reject an unlocked stale PID file (R3-RUN-1)"
    );
    assert!(
        String::from_utf8_lossy(&stale_reload.stderr).contains("not locked"),
        "expected unlocked PID diagnostic, got: {}",
        String::from_utf8_lossy(&stale_reload.stderr)
    );

    // 5. R4-KEYD-1: `miraserve keyd --allow-peer-user 0` and `root` fail closed
    for bad_peer in ["0", "root"] {
        let out = Command::new(miraserve_bin())
            .args(["keyd", "--socket"])
            .arg(base.join("keyd.sock"))
            .args(["--config"])
            .arg(&ok_cfg)
            .args(["--allow-peer-user", bad_peer])
            .output()?;
        assert!(
            !out.status.success(),
            "keyd must reject --allow-peer-user {bad_peer}"
        );
    }

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Round 5 Wave 1 CLI regressions:
/// - `R5-PKG-2`: `cert generate-dev` preserves pre-existing `0750` parent directory permissions.
/// - `R5-CHK-1`: `check --fs` rejects 0-byte cert/key, mismatched cert/key pair, bad client-ca,
///   missing `keyd-socket`, and unwritable `--acme-dir` / `ai-publish.storage`.
/// - `R5-SBX-1`: Relative roots (`etc/miraserve`) and broad system roots (`/var/lib`, `/var/log`,
///   `/usr/local`) fail validation with `E202`.
#[test]
#[allow(clippy::too_many_lines)]
fn cli_round5_wave1_pkg_cert_dir_mode_check_fs_and_sandbox_roots() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base =
        std::env::temp_dir().join(format!("miraserve-r5w1-cli-{}-{nanos}", std::process::id()));
    let certs_dir = base.join("certs");
    let site_root = base.join("www");
    std::fs::create_dir_all(&certs_dir)?;
    std::fs::create_dir_all(&site_root)?;

    // 1. R5-PKG-2: Pre-existing 0750 certs directory must NOT be chmodded to 0700 by generate-dev.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&certs_dir, std::fs::Permissions::from_mode(0o750))?;
    }
    let cert_a = certs_dir.join("a.crt");
    let key_a = certs_dir.join("a.key");
    let gen_a = Command::new(miraserve_bin())
        .args(["cert", "generate-dev", "--hosts", "a.localhost", "--cert"])
        .arg(&cert_a)
        .arg("--key")
        .arg(&key_a)
        .output()?;
    assert!(gen_a.status.success());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let dir_mode = std::fs::metadata(&certs_dir)?.permissions().mode() & 0o777;
        assert_eq!(
            dir_mode, 0o750,
            "cert generate-dev must preserve existing 0750 certs dir permissions (R5-PKG-2)"
        );
        let key_mode = std::fs::metadata(&key_a)?.permissions().mode() & 0o777;
        assert_eq!(key_mode, 0o600, "generated private key must still be 0600");
    }

    // 2. R5-CHK-1a: Zero-byte cert/key files MUST fail `check --fs --strict`.
    let zero_cert = certs_dir.join("zero.crt");
    let zero_key = certs_dir.join("zero.key");
    std::fs::write(&zero_cert, b"")?;
    std::fs::write(&zero_key, b"")?;
    let zero_cfg = base.join("zero.kdl");
    std::fs::write(
        &zero_cfg,
        format!(
            "server {{\n    listen \"127.0.0.1:8443\"\n    tls {{ cert \"{}\"; key \"{}\" }}\n}}\nsite \"localhost\" {{ root \"{}\" }}\n",
            zero_cert.display(),
            zero_key.display(),
            site_root.display(),
        ),
    )?;
    let zero_out = Command::new(miraserve_bin())
        .args(["check", "--fs", "--strict"])
        .arg(&zero_cfg)
        .output()?;
    assert!(
        !zero_out.status.success(),
        "0-byte cert/key must fail check --fs (R5-CHK-1)"
    );
    let zero_err = String::from_utf8_lossy(&zero_out.stderr);
    assert!(zero_err.contains("E301"), "expected E301, got: {zero_err}");

    // 3. R5-CHK-1b: Mismatched cert/key pair MUST fail `check --fs --strict`.
    let cert_b = certs_dir.join("b.crt");
    let key_b = certs_dir.join("b.key");
    let gen_b = Command::new(miraserve_bin())
        .args(["cert", "generate-dev", "--hosts", "b.localhost", "--cert"])
        .arg(&cert_b)
        .arg("--key")
        .arg(&key_b)
        .output()?;
    assert!(gen_b.status.success());
    let mismatch_cfg = base.join("mismatch.kdl");
    std::fs::write(
        &mismatch_cfg,
        format!(
            "server {{\n    listen \"127.0.0.1:8443\"\n    tls {{ cert \"{}\"; key \"{}\" }}\n}}\nsite \"localhost\" {{ root \"{}\" }}\n",
            cert_a.display(),
            key_b.display(),
            site_root.display(),
        ),
    )?;
    let mismatch_out = Command::new(miraserve_bin())
        .args(["check", "--fs", "--strict"])
        .arg(&mismatch_cfg)
        .output()?;
    assert!(
        !mismatch_out.status.success(),
        "mismatched cert/key pair must fail check --fs (R5-CHK-1)"
    );
    let mismatch_err = String::from_utf8_lossy(&mismatch_out.stderr);
    assert!(
        mismatch_err.contains("mismatched") || mismatch_err.contains("E301"),
        "expected mismatch E301, got: {mismatch_err}"
    );

    // 4. R5-CHK-1c: Missing keyd-socket in split-daemon mode MUST fail `check --fs`.
    let missing_sock = base.join("missing-keyd.sock");
    let split_cfg = base.join("split.kdl");
    std::fs::write(
        &split_cfg,
        format!(
            "server {{\n    listen \"127.0.0.1:8443\"\n    tls {{ key-isolation \"split-daemon\"; keyd-socket \"{}\"; cert \"{}\"; key \"{}\" }}\n}}\nsite \"localhost\" {{ root \"{}\" }}\n",
            missing_sock.display(),
            cert_a.display(),
            key_a.display(),
            site_root.display(),
        ),
    )?;
    let split_out = Command::new(miraserve_bin())
        .args(["check", "--fs"])
        .arg(&split_cfg)
        .output()?;
    assert!(
        !split_out.status.success(),
        "missing keyd-socket must fail check --fs (R5-CHK-1)"
    );
    let split_err = String::from_utf8_lossy(&split_out.stderr);
    assert!(
        split_err.contains("keyd-socket") && split_err.contains("E301"),
        "expected keyd-socket E301, got: {split_err}"
    );

    // 5. R5-CHK-1d: Read-only `--acme-dir` when ACME is enabled MUST fail `check --fs`.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let ro_acme = base.join("ro-acme");
        std::fs::create_dir_all(&ro_acme)?;
        std::fs::set_permissions(&ro_acme, std::fs::Permissions::from_mode(0o555))?;
        let acme_cfg = base.join("acme.kdl");
        std::fs::write(
            &acme_cfg,
            format!(
                "server {{\n    listen \"127.0.0.1:8443\"\n    tls {{\n        acme {{ email \"ops@example.com\" }}\n    }}\n}}\nsite \"app.example.com\" {{ root \"{}\" }}\n",
                site_root.display(),
            ),
        )?;
        let acme_out = Command::new(miraserve_bin())
            .args(["check", "--fs", "--acme-dir"])
            .arg(&ro_acme)
            .arg(&acme_cfg)
            .output()?;
        std::fs::set_permissions(&ro_acme, std::fs::Permissions::from_mode(0o755))?;
        assert!(
            !acme_out.status.success(),
            "read-only --acme-dir must fail check --fs (R5-CHK-1)"
        );
        let acme_err = String::from_utf8_lossy(&acme_out.stderr);
        assert!(
            acme_err.contains("not writable") && acme_err.contains("E301"),
            "expected unwritable acme-dir E301, got: {acme_err}"
        );
    }

    // 6. R5-SBX-1: Broad shared system roots & `/etc/miraserve` fail validation with E202.
    for forbidden in ["/etc/miraserve", "/var/lib", "/var/log", "/usr/local"] {
        let cfg_path = base.join(format!("sbx-{}.kdl", forbidden.replace('/', "_")));
        std::fs::write(
            &cfg_path,
            format!(
                "server {{\n    listen \"127.0.0.1:8443\"\n    tls {{ cert \"{}\"; key \"{}\" }}\n}}\nsite \"localhost\" {{ root \"{forbidden}\" }}\n",
                cert_a.display(),
                key_a.display(),
            ),
        )?;
        let out = Command::new(miraserve_bin())
            .args(["check", "--strict"])
            .arg(&cfg_path)
            .output()?;
        assert!(
            !out.status.success(),
            "forbidden root '{forbidden}' must fail validation (R5-SBX-1)"
        );
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("E202"),
            "expected E202 for '{forbidden}', got: {err}"
        );
    }

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// R6-CFG-1: Verifies that the README / CI quickstart command
/// (`miraserve check --strict --dev-tls --fs examples/dev-local.kdl`) exits 0 AND that
/// importing a stock Nginx config with relative `root html;` produces a valid absolute path
/// (`/usr/share/nginx/html`) that passes `miraserve check`.
#[test]
fn r6_cfg_1_dev_local_quickstart_and_nginx_relative_root_pass_check() -> TestResult {
    let dev_local = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("examples")
        .join("dev-local.kdl");
    let check_out = Command::new(miraserve_bin())
        .args(["check", "--strict", "--dev-tls", "--fs"])
        .arg(&dev_local)
        .output()?;
    assert!(
        check_out.status.success(),
        "examples/dev-local.kdl quickstart check must succeed: stdout={} stderr={}",
        String::from_utf8_lossy(&check_out.stdout),
        String::from_utf8_lossy(&check_out.stderr)
    );

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base =
        std::env::temp_dir().join(format!("miraserve-r6cfg1-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&base)?;
    let nginx_conf = base.join("default.conf");
    std::fs::write(
        &nginx_conf,
        "server {\n    listen 80;\n    server_name example.com;\n    root html;\n}\n",
    )?;
    let out_kdl = base.join("miraserve.kdl");
    let imp_out = Command::new(miraserve_bin())
        .args(["import", "--from", "nginx", "--output"])
        .arg(&out_kdl)
        .arg(&nginx_conf)
        .output()?;
    assert!(
        imp_out.status.success(),
        "importing stock Nginx `root html;` must exit 0: stderr={}",
        String::from_utf8_lossy(&imp_out.stderr)
    );
    let generated = std::fs::read_to_string(&out_kdl)?;
    assert!(
        generated.contains("/usr/share/nginx/html"),
        "expected relative Nginx `root html;` to resolve to /usr/share/nginx/html, got:\n{generated}"
    );
    let imported_check = Command::new(miraserve_bin())
        .args(["check", "--dev-tls"])
        .arg(&out_kdl)
        .output()?;
    assert!(
        imported_check.status.success(),
        "generated KDL from Nginx `root html;` must pass `miraserve check`: stderr={}",
        String::from_utf8_lossy(&imported_check.stderr)
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// R6-CHK-1 & R6-SBX-1:
/// - `miraserve check --fs` WITHOUT `--acme-dir` succeeds in a writable CWD (treating the empty
///   parent of default `.miraserve-acme` as `.`).
/// - `miraserve check --fs` performs a real timed keyd protocol/peer-auth probe so a wedged or
///   rejecting Unix socket fails with `E301` instead of passing a bare `connect()`.
/// - `miraserve check --fs --acme-dir <dir>` rejects a `site.root` overlapping `<dir>`.
#[test]
#[allow(clippy::too_many_lines)]
fn r6_chk_1_check_fs_accepts_default_acme_dir_and_probes_keyd_peer_authorization() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base =
        std::env::temp_dir().join(format!("miraserve-r6-chk-1-{}-{nanos}", std::process::id()));
    let www = base.join("www");
    let custom_acme = base.join("acme-state");
    std::fs::create_dir_all(&www)?;
    std::fs::create_dir_all(&custom_acme)?;

    // 1. Default `.miraserve-acme` without `--acme-dir` succeeds when CWD is writable!
    let acme_cfg = base.join("acme.kdl");
    std::fs::write(
        &acme_cfg,
        format!(
            "server {{\n    listen \":443\"\n    tls {{ acme {{ email \"ops@example.com\" }} }}\n}}\nsite \"acme.example.com\" {{ root \"{}\" }}\n",
            www.display()
        ),
    )?;
    let acme_out = Command::new(miraserve_bin())
        .current_dir(&base)
        .args(["check", "--fs", "--strict"])
        .arg(&acme_cfg)
        .output()?;
    assert!(
        acme_out.status.success(),
        "R6-CHK-1: check --fs without --acme-dir must succeed in writable CWD; stderr={}",
        String::from_utf8_lossy(&acme_out.stderr)
    );

    // 2. R6-SBX-1: Docroot overlapping `--acme-dir` MUST fail `check --fs` with E301!
    //    Keep `overlap.kdl` in a separate `conf/` directory so `R7-CFG-1` (config-in-docroot)
    //    does not preempt the ACME overlap check.
    let conf_dir = base.join("conf");
    let leak_root = base.join("leak-root");
    let nested_acme = leak_root.join("acme-state");
    std::fs::create_dir_all(&conf_dir)?;
    std::fs::create_dir_all(&nested_acme)?;
    let overlap_cfg = conf_dir.join("overlap.kdl");
    std::fs::write(
        &overlap_cfg,
        format!(
            "server {{\n    listen \":443\"\n    tls {{ acme {{ email \"ops@example.com\" }} }}\n}}\nsite \"leak.example.com\" {{ root \"{}\" }}\n",
            leak_root.display()
        ),
    )?;
    let overlap_out = Command::new(miraserve_bin())
        .args(["check", "--fs", "--acme-dir"])
        .arg(&nested_acme)
        .arg(&overlap_cfg)
        .output()?;
    assert!(
        !overlap_out.status.success(),
        "R6-SBX-1: check --fs must reject site.root overlapping --acme-dir"
    );
    let overlap_err = String::from_utf8_lossy(&overlap_out.stderr);
    assert!(
        overlap_err.contains("overlaps ACME state directory") && overlap_err.contains("E301"),
        "expected ACME overlap E301, got: {overlap_err}"
    );

    // 3. R6-CHK-1: Keyd socket that accepts TCP/Unix connections and immediately drops or stalls
    //    (simulating peer-UID rejection or wedged keyd) MUST fail `check --fs` with E301!
    #[cfg(unix)]
    {
        let cert_path = base.join("leaf.crt");
        let key_path = base.join("leaf.key");
        let cert_gen = Command::new(miraserve_bin())
            .args([
                "cert",
                "generate-dev",
                "--hosts",
                "split.example.test",
                "--cert",
            ])
            .arg(&cert_path)
            .arg("--key")
            .arg(&key_path)
            .output()?;
        assert!(cert_gen.status.success());

        let sock_path =
            std::path::PathBuf::from(format!("/tmp/ms-r6-chk-rej-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock_path);
        let listener = std::os::unix::net::UnixListener::bind(&sock_path)?;
        // Spawn a background thread that accepts and immediately closes (exactly like keyd
        // rejecting an unauthorized SO_PEERCRED UID!).
        let rej_thread = std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                drop(stream);
            }
        });

        let split_cfg = base.join("split-rej.kdl");
        std::fs::write(
            &split_cfg,
            format!(
                "server {{\n    listen \"127.0.0.1:8443\"\n    tls {{ key-isolation \"split-daemon\"; keyd-socket \"{}\"; cert \"{}\"; key \"{}\" }}\n}}\nsite \"split.example.test\" {{ root \"{}\" }}\n",
                sock_path.display(),
                cert_path.display(),
                key_path.display(),
                www.display(),
            ),
        )?;
        let split_out = Command::new(miraserve_bin())
            .args(["check", "--fs"])
            .arg(&split_cfg)
            .output()?;
        let _ = rej_thread.join();
        let _ = std::fs::remove_file(&sock_path);
        assert!(
            !split_out.status.success(),
            "R6-CHK-1: check --fs must fail when keyd closes/rejects the peer during ListCerts probe"
        );
        let split_err = String::from_utf8_lossy(&split_out.stderr);
        assert!(
            split_err.contains("keyd protocol/peer authorization probe")
                && split_err.contains("E301"),
            "expected keyd probe failure E301, got: {split_err}"
        );
    }

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// R6-PKG-1 & R5-PKG-3: `miraserve service generate --target systemd-keyd` emits a companion
/// `tmpfiles.d` snippet matching custom `--keyd-socket` / `--user` / `--peer-user` without
/// hardcoding `/usr/lib/tmpfiles.d/miraserve.conf` or `SupplementaryGroups=miraserve`.
#[test]
fn r6_pkg_1_service_generate_systemd_keyd_emits_matching_tmpfiles_without_hardcoded_path()
-> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base =
        std::env::temp_dir().join(format!("miraserve-r6-pkg-1-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&base)?;
    let unit_path = base.join("custom-keyd.service");

    let out = Command::new(miraserve_bin())
        .args([
            "service",
            "generate",
            "--target",
            "systemd-keyd",
            "--user",
            "vault-user",
            "--group",
            "vault-group",
            "--peer-user",
            "edge-worker",
            "--keyd-socket",
            "/run/custom-keyd/vault.sock",
            "--output",
        ])
        .arg(&unit_path)
        .output()?;
    assert!(
        out.status.success(),
        "service generate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let unit_text = std::fs::read_to_string(&unit_path)?;
    assert!(!unit_text.contains("/usr/lib/tmpfiles.d/miraserve.conf"));
    assert!(
        unit_text.contains("SupplementaryGroups=edge-worker"),
        "R7-PKG-1: Unix-socket systemd-keyd unit must include SupplementaryGroups=<peer_user> to traverse 0750 config directories"
    );
    assert!(
        unit_text
            .contains("ExecStartPre=+/usr/bin/systemd-tmpfiles --create --prefix=/run/custom-keyd")
    );
    assert!(unit_text.contains("--allow-peer-user edge-worker"));
    assert!(unit_text.contains("ReadWritePaths=-/run/custom-keyd"));

    let sidecar_tmpfiles = base.join("custom-keyd.tmpfiles.conf");
    assert!(
        sidecar_tmpfiles.is_file(),
        "R6-PKG-1: expected companion tmpfiles.conf at {}",
        sidecar_tmpfiles.display()
    );
    let tf_text = std::fs::read_to_string(&sidecar_tmpfiles)?;
    assert!(
        tf_text.contains("d /run/custom-keyd 2750 vault-user edge-worker -"),
        "expected matching tmpfiles rule, got:\n{tf_text}"
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// R8-PKG-1: the loopback-TCP keyd unit needs `SupplementaryGroups=<peer_user>` exactly like the
/// Unix-socket unit, or keyd cannot traverse `0750 root:<peer_user>` `/etc/miraserve/conf` to read
/// its config.
#[test]
fn r8_pkg_1_loopback_tcp_keyd_unit_keeps_supplementary_group() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base =
        std::env::temp_dir().join(format!("miraserve-r8-pkg-1-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&base)?;
    let unit_path = base.join("tcp-keyd.service");

    let out = Command::new(miraserve_bin())
        .args([
            "service",
            "generate",
            "--target",
            "systemd-keyd",
            "--peer-user",
            "edge-worker",
            "--keyd-socket",
            "tcp://127.0.0.1:9555",
            "--auth-secret-file",
            "/etc/miraserve/keyd.secret",
            "--output",
        ])
        .arg(&unit_path)
        .output()?;
    assert!(
        out.status.success(),
        "service generate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let unit_text = std::fs::read_to_string(&unit_path)?;
    assert!(
        unit_text.contains("SupplementaryGroups=edge-worker"),
        "R8-PKG-1: loopback-TCP systemd-keyd unit must include SupplementaryGroups=<peer_user>, got:\n{unit_text}"
    );
    assert!(
        unit_text.contains("tcp://127.0.0.1:9555"),
        "expected the TCP socket in the unit, got:\n{unit_text}"
    );
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// R7-CHK-1: `miraserve check --fs --keyd-auth-secret-file <FILE>` passes against a real
/// authenticated TCP keyd (and fails without the secret), and `service generate --target systemd
/// --split-keyd --auth-secret-file <FILE>` emits `--keyd-auth-secret-file` in BOTH `ExecStartPre`
/// and `ExecStart`.
#[test]
#[allow(clippy::too_many_lines)]
fn r7_chk_1_check_fs_accepts_keyd_auth_secret_file_and_service_unit_emits_it_in_exec_start_pre()
-> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base =
        std::env::temp_dir().join(format!("miraserve-r7-chk-1-{}-{nanos}", std::process::id()));
    let www = base.join("www");
    std::fs::create_dir_all(&www)?;

    // 1. Verify `service generate --target systemd --split-keyd --auth-secret-file ...` emits
    //    `--keyd-auth-secret-file` in BOTH `ExecStartPre` and `ExecStart`.
    let secret_path = base.join("keyd.secret");
    std::fs::write(
        &secret_path,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))?;
    }
    let custom_acme = base.join("custom-acme");
    let gen_out = Command::new(miraserve_bin())
        .args([
            "service",
            "generate",
            "--target",
            "systemd",
            "--split-keyd",
            "--acme-dir",
        ])
        .arg(&custom_acme)
        .arg("--auth-secret-file")
        .arg(&secret_path)
        .output()?;
    assert!(
        gen_out.status.success(),
        "service generate failed: {}",
        String::from_utf8_lossy(&gen_out.stderr)
    );
    let unit_text = String::from_utf8_lossy(&gen_out.stdout);
    let exec_pre = unit_text
        .lines()
        .find(|l| l.starts_with("ExecStartPre="))
        .unwrap_or("");
    let exec_start = unit_text
        .lines()
        .find(|l| l.starts_with("ExecStart="))
        .unwrap_or("");
    let exec_reload = unit_text
        .lines()
        .find(|l| l.starts_with("ExecReload="))
        .unwrap_or("");
    let expected_acme_arg = format!("--acme-dir \"{}\"", custom_acme.display());
    let expected_secret_arg = format!("--keyd-auth-secret-file \"{}\"", secret_path.display());
    for (label, line) in [
        ("ExecStartPre", exec_pre),
        ("ExecStart", exec_start),
        ("ExecReload", exec_reload),
    ] {
        assert!(
            line.contains(&expected_acme_arg),
            "G5: {label} must include `{expected_acme_arg}`; got: {line}"
        );
        assert!(
            line.contains(&expected_secret_arg),
            "R7-CHK-1 / G5: {label} must include `{expected_secret_arg}`; got: {line}"
        );
    }

    // 2. Start a real TCP `miraserve keyd` with HMAC auth secret and verify `check --fs` fails
    //    without `--keyd-auth-secret-file` and succeeds with it!
    let cert_path = base.join("leaf.crt");
    let key_path = base.join("leaf.key");
    let cert_gen = Command::new(miraserve_bin())
        .args([
            "cert",
            "generate-dev",
            "--hosts",
            "tcp-keyd.example.test",
            "--cert",
        ])
        .arg(&cert_path)
        .arg("--key")
        .arg(&key_path)
        .output()?;
    assert!(cert_gen.status.success());

    let probe_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = probe_listener.local_addr()?.port();
    drop(probe_listener);
    let endpoint = format!("tcp://127.0.0.1:{port}");

    let cfg_path = base.join("split-tcp.kdl");
    std::fs::write(
        &cfg_path,
        format!(
            "server {{\n    listen \"127.0.0.1:8443\"\n    tls {{ key-isolation \"split-daemon\"; keyd-socket \"{endpoint}\"; cert \"{}\"; key \"{}\" }}\n}}\nsite \"tcp-keyd.example.test\" {{ root \"{}\" }}\n",
            cert_path.display(),
            key_path.display(),
            www.display(),
        ),
    )?;

    let mut keyd_child = Command::new(miraserve_bin())
        .args(["keyd", "--socket", &endpoint, "--config"])
        .arg(&cfg_path)
        .arg("--auth-secret-file")
        .arg(&secret_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    // Wait briefly for keyd TCP listener to come up.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    let missing_secret = Command::new(miraserve_bin())
        .args(["check", "--fs"])
        .arg(&cfg_path)
        .output()?;
    assert!(
        !missing_secret.status.success(),
        "R7-CHK-1: check --fs without --keyd-auth-secret-file must fail against authenticated TCP keyd"
    );

    let with_secret = Command::new(miraserve_bin())
        .args(["check", "--fs", "--keyd-auth-secret-file"])
        .arg(&secret_path)
        .arg(&cfg_path)
        .output()?;
    let _ = keyd_child.kill();
    let _ = keyd_child.wait();

    assert!(
        with_secret.status.success(),
        "R7-CHK-1: check --fs --keyd-auth-secret-file must succeed against authenticated TCP keyd; stderr={}",
        String::from_utf8_lossy(&with_secret.stderr)
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// R7-MIG-13 & R7-MIG-17: `miraserve import --source-root <DIR>` imports a relocated Nginx tree
/// cleanly, and `miraserve import -o <dangling-symlink>` refuses to follow or create the target
/// (both with and without `--force`).
#[test]
fn r7_mig_13_17_cli_source_root_and_refuse_dangling_symlink_output() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::env::temp_dir().join(format!(
        "miraserve-r7-mig-cli-{}-{nanos}",
        std::process::id()
    ));
    let tree = base.join("copied-nginx");
    std::fs::create_dir_all(tree.join("conf.d"))?;
    std::fs::write(
        tree.join("conf.d/app.conf"),
        "server {\n    listen 443 ssl;\n    server_name tree.example.com;\n    root /var/www/tree;\n}\n",
    )?;
    let main_conf = tree.join("nginx.conf");
    std::fs::write(
        &main_conf,
        "http {\n    include /etc/nginx/conf.d/*.conf;\n}\n",
    )?;

    // 1. R7-MIG-13: `--source-root` remaps `/etc/nginx/conf.d/*.conf` inside `tree` and exits 0!
    let ok_out = Command::new(miraserve_bin())
        .args(["import", "--from", "nginx", "--source-root"])
        .arg(&tree)
        .arg(&main_conf)
        .output()?;
    assert!(
        ok_out.status.success(),
        "R7-MIG-13: import --source-root failed: {}",
        String::from_utf8_lossy(&ok_out.stderr)
    );
    let kdl_text = String::from_utf8_lossy(&ok_out.stdout);
    assert!(kdl_text.contains("tree.example.com"));

    // 2. R7-MIG-17: `-o` pointing to a dangling symlink MUST fail and NEVER create its target!
    #[cfg(unix)]
    {
        let dangling_target = base.join("should-never-exist.kdl");
        let dangling_link = base.join("out-link.kdl");
        std::os::unix::fs::symlink(&dangling_target, &dangling_link)?;
        for extra in [Vec::<&str>::new(), vec!["--force"]] {
            let mut cmd = Command::new(miraserve_bin());
            cmd.args(["import", "--from", "nginx", "--source-root"])
                .arg(&tree)
                .arg("-o")
                .arg(&dangling_link);
            for flag in extra {
                cmd.arg(flag);
            }
            let res = cmd.arg(&main_conf).output()?;
            assert!(
                !res.status.success(),
                "R7-MIG-17: import -o <dangling-symlink> MUST refuse"
            );
            assert!(
                !dangling_target.exists(),
                "R7-MIG-17: import -o MUST NOT create dangling symlink target"
            );
        }
    }

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// R7-SBX-2: Non-strict `miraserve check --fs` MUST fail with hard error `E301` (exit code != 0)
/// when a site document root is a symlink resolving to `/etc`, instead of emitting only `W017`.
#[test]
#[cfg_attr(not(unix), allow(clippy::unnecessary_wraps))]
fn r7_sbx_2_check_fs_rejects_symlink_docroot_to_etc_with_hard_e301_error() -> TestResult {
    #[cfg(unix)]
    {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let base =
            std::env::temp_dir().join(format!("miraserve-r7-sbx-2-{}-{nanos}", std::process::id()));
        let conf_dir = base.join("conf");
        std::fs::create_dir_all(&conf_dir)?;
        let cert_path = base.join("cert.pem");
        let key_path = base.join("key.pem");
        let gen_cert = Command::new(miraserve_bin())
            .args(["cert", "generate-dev", "--hosts", "sym.local", "--cert"])
            .arg(&cert_path)
            .arg("--key")
            .arg(&key_path)
            .output()?;
        assert!(gen_cert.status.success());

        let sym_root = base.join("www-link");
        std::os::unix::fs::symlink("/etc", &sym_root)?;
        let cfg_path = conf_dir.join("sym.kdl");
        std::fs::write(
            &cfg_path,
            format!(
                r#"
server {{
    listen "127.0.0.1:8443"
    tls {{
        cert "{}"
        key "{}"
    }}
}}
site "sym.local" {{
    root "{}"
}}
"#,
                cert_path.display(),
                key_path.display(),
                sym_root.display(),
            ),
        )?;

        // Non-strict `check --fs` (as invoked by systemd `ExecStartPre`) MUST fail with E301!
        let out = Command::new(miraserve_bin())
            .args(["check", "--fs"])
            .arg(&cfg_path)
            .output()?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success() && stderr.contains("E301"),
            "R7-SBX-2: non-strict `check --fs` must fail with E301 for symlink -> /etc, got status={:?} stderr={stderr}",
            out.status
        );

        let _ = std::fs::remove_dir_all(&base);
    }
    Ok(())
}

/// Hosting-panel layout: `service generate` must not hide `/home` from a server whose sites live
/// there. `ProtectHome` is relaxed to read-only when the config on disk needs it or when
/// `--home-docroots` is passed, and stays `yes` otherwise.
#[test]
fn service_generate_relaxes_protect_home_only_when_sites_live_under_home() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::env::temp_dir().join(format!(
        "miraserve-protect-home-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&base)?;
    let home_cfg = base.join("home.kdl");
    std::fs::write(
        &home_cfg,
        r#"
server {
    listen ":443"
    tls { cert "/opt/panel/certs/a.pem"; key "/opt/panel/certs/a.key" }
    sandbox { read-tree "/home" }
}
site "a.example" { root "/home/usr_a/public_html/a.example" }
"#,
    )?;
    let www_cfg = base.join("www.kdl");
    std::fs::write(
        &www_cfg,
        r#"
server {
    listen ":443"
    tls { cert "/opt/panel/certs/a.pem"; key "/opt/panel/certs/a.key" }
}
site "a.example" { root "/var/www/a.example" }
"#,
    )?;
    let unit_for = |cfg: &std::path::Path, extra: &[&str]| -> Result<String, std::io::Error> {
        let out = Command::new(miraserve_bin())
            .args(["service", "generate", "--target", "systemd", "--config"])
            .arg(cfg)
            .args(extra)
            .output()?;
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    };

    let home_unit = unit_for(&home_cfg, &[])?;
    assert!(
        home_unit.contains("ProtectHome=read-only") && !home_unit.contains("ProtectHome=yes"),
        "sites under /home need ProtectHome=read-only, got:\n{home_unit}"
    );
    let www_unit = unit_for(&www_cfg, &[])?;
    assert!(
        www_unit.contains("ProtectHome=yes"),
        "a config with no /home paths must keep ProtectHome=yes, got:\n{www_unit}"
    );
    let forced = unit_for(&www_cfg, &["--home-docroots"])?;
    assert!(forced.contains("ProtectHome=read-only"), "{forced}");
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Staging findings M1 and M4: `check --fs` must agree with the server about custom error
/// pages. A missing page, or one that is a symlink leaving the site root, makes the server use
/// its built-in page, so `check --fs` reports a warning (`W023`) and still exits 0.
#[cfg(unix)]
#[test]
fn check_fs_reports_unloadable_error_pages_as_warnings_not_errors() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::env::temp_dir().join(format!(
        "miraserve-check-errpage-{}-{nanos}",
        std::process::id()
    ));
    let root = base.join("site");
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("index.html"), b"ok")?;
    std::fs::write(base.join("outside.html"), b"outside")?;
    std::os::unix::fs::symlink(base.join("outside.html"), root.join("errpage.html"))?;
    let cfg = base.join("c.kdl");
    std::fs::write(
        &cfg,
        format!(
            r#"
server {{
    listen "127.0.0.1:8080"
}}
site "a.example" {{
    root "{}"
    error-pages {{
        page 404 "errpage.html"
        page 503 "missing.html"
    }}
}}
"#,
            root.display()
        ),
    )?;
    let out = Command::new(miraserve_bin())
        .args(["check", "--fs"])
        .arg(&cfg)
        .output()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("W023") && text.contains("leaves the site root"),
        "the symlinked error page must be reported: {text}"
    );
    assert!(
        text.contains("missing.html") && !text.contains("E301"),
        "a missing error page is a warning, not E301: {text}"
    );
    assert!(
        out.status.success(),
        "warnings alone must not fail check: {text}"
    );
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// `--strict` with `--allow-warning <CODE>`: a hosting panel accepts some warnings on purpose
/// (TLS 1.2 on, published CDN ranges) and still needs a pass/fail gate for everything else.
#[test]
fn strict_check_passes_when_every_warning_is_explicitly_allowed() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::env::temp_dir().join(format!(
        "miraserve-allow-warning-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&base)?;
    let cfg = base.join("c.kdl");
    std::fs::write(
        &cfg,
        r#"
server {
    listen ":443"
    tls { min-version "1.2"; cert "/opt/panel/certs/a.pem"; key "/opt/panel/certs/a.key" }
}
site "a.example" { root "/var/www/a.example" }
"#,
    )?;
    let run = |extra: &[&str]| -> Result<(bool, String), std::io::Error> {
        let out = Command::new(miraserve_bin())
            .args(["check", "--strict"])
            .args(extra)
            .arg(&cfg)
            .output()?;
        Ok((
            out.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        ))
    };
    let (ok, text) = run(&[])?;
    assert!(
        !ok && text.contains("W002"),
        "strict must fail on W002: {text}"
    );
    let (ok, text) = run(&["--allow-warning", "W002"])?;
    assert!(ok, "W002 was allowed, strict must pass: {text}");
    assert!(
        text.contains("W002"),
        "an allowed warning is still reported: {text}"
    );
    let (ok, text) = run(&["--allow-warning", "W022"])?;
    assert!(!ok, "allowing a different code must not hide W002: {text}");
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Wave 5 (HANDOVER §5 #8, #9, #10):
/// - `miraserve reload --config` runs the same `--fs` checks as `check --fs` before signaling
///   SIGHUP, naming the exact offending site on failure.
/// - `miraserve check --fs` catches an intermediate-directory symlink on an absolute error page
///   outside the site root (`W023`) AND reports missing tenant-owned `site.root` as `W023`
///   matching runtime tenant isolation.
#[allow(clippy::too_many_lines)]
#[test]
fn wave5_reload_runs_fs_checks_and_check_fs_catches_intermediate_error_page_symlink() -> TestResult
{
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::env::temp_dir().join(format!(
        "miraserve-wave5-cli-{}-{nanos}",
        std::process::id()
    ));
    let good_root = base.join("good-site");
    // Used by the Unix-only part of this test.
    #[cfg_attr(not(unix), allow(unused_variables))]
    let deleted_root = base.join("deleted-tenant-root");
    let secret_dir = base.join("secret-dir");
    #[cfg_attr(not(unix), allow(unused_variables))]
    let link_dir = base.join("error-dir-symlink");
    std::fs::create_dir_all(&good_root)?;
    std::fs::create_dir_all(&secret_dir)?;
    std::fs::write(good_root.join("index.html"), b"ok")?;
    std::fs::write(secret_dir.join("404.html"), b"SECRET")?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(&secret_dir, &link_dir)?;

    // 1. `reload --config` must run `--fs` checks BEFORE touching PID file and name the site!
    let bad_cert_cfg = base.join("bad-cert-reload.kdl");
    std::fs::write(
        &bad_cert_cfg,
        format!(
            r#"
server {{
    listen "127.0.0.1:8443"
}}
site "shop.example" {{
    root "{}"
    tls {{
        cert "{}"
        key "{}"
    }}
}}
"#,
            good_root.display(),
            base.join("missing.pem").display(),
            base.join("missing.key").display(),
        ),
    )?;
    let reload_out = Command::new(miraserve_bin())
        .args(["reload", "--config"])
        .arg(&bad_cert_cfg)
        .args(["--pid-file"])
        .arg(base.join("nonexistent.pid"))
        .output()?;
    let reload_stderr = String::from_utf8_lossy(&reload_out.stderr);
    assert!(
        !reload_out.status.success(),
        "reload --config must fail when --fs detects missing site cert"
    );
    assert!(
        reload_stderr.contains("E301") && reload_stderr.contains("site 'shop.example'"),
        "reload --config must report E301 naming site 'shop.example' before PID check, got: {reload_stderr}"
    );
    assert!(
        !reload_stderr.contains("PID file"),
        "reload --config must stop on --fs failure BEFORE touching PID file, got: {reload_stderr}"
    );

    // 2. `check --fs` catches intermediate-dir symlink on absolute error page + deleted tenant root as W023.
    #[cfg(unix)]
    {
        let fs_cfg = base.join("tenant-fs.kdl");
        std::fs::write(
            &fs_cfg,
            format!(
                r#"
server {{
    listen "127.0.0.1:8443"
}}
site "sym.example" {{
    root "{}"
    error-pages {{
        page 404 "{}"
    }}
}}
site "deleted.example" {{
    root "{}"
}}
"#,
                good_root.display(),
                link_dir.join("404.html").display(),
                deleted_root.display(),
            ),
        )?;
        let check_out = Command::new(miraserve_bin())
            .args(["check", "--dev-tls", "--fs"])
            .arg(&fs_cfg)
            .output()?;
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&check_out.stdout),
            String::from_utf8_lossy(&check_out.stderr)
        );
        assert!(
            check_out.status.success(),
            "tenant-owned W023 warnings alone must not fail non-strict check --fs: {combined}"
        );
        assert!(
            combined.contains("W023")
                && combined.contains("sym.example")
                && combined.contains("traverses symbolic link"),
            "check --fs must report intermediate-directory symlink on absolute error page as W023: {combined}"
        );
        assert!(
            combined.contains("W023")
                && combined.contains("deleted.example")
                && combined.contains("503 when the directory cannot be opened"),
            "check --fs must report missing tenant site.root as W023 naming the site: {combined}"
        );
        assert!(
            !combined.contains("E301"),
            "tenant-owned missing root / error-page symlink must be W023, not E301: {combined}"
        );
    }

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Wave 6 (HANDOVER §5 #11): JSON `check --fs` report must include `path` (config key path)
/// on validation issues and warnings, AND `E301` filesystem errors must include BOTH `path`
/// AND exact `location` (`line`, `column`, `offset`, `length`).
#[test]
fn wave6_json_check_report_includes_config_key_path_and_e301_location() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::env::temp_dir().join(format!(
        "miraserve-wave6-json-{}-{nanos}",
        std::process::id()
    ));
    let root = base.join("www");
    std::fs::create_dir_all(&root)?;
    let cfg_path = base.join("check-json.kdl");
    let missing_cert = base.join("missing.pem");
    let missing_key = base.join("missing.key");
    std::fs::write(
        &cfg_path,
        format!(
            r#"server {{
    listen "127.0.0.1:8443"
    tls {{
        min-version "1.2"
        cert "{}"
        key "{}"
    }}
}}
site "json.example" {{
    root "{}"
}}
"#,
            missing_cert.display(),
            missing_key.display(),
            root.display(),
        ),
    )?;

    let out = Command::new(miraserve_bin())
        .args(["check", "--fs", "--format", "json"])
        .arg(&cfg_path)
        .output()?;
    assert!(!out.status.success(), "missing cert must fail check --fs");
    let json: serde_json::Value = serde_json::from_slice(&out.stdout)?;

    let errors = json
        .get("errors")
        .and_then(serde_json::Value::as_array)
        .ok_or("JSON report missing errors array")?;
    let cert_err = errors
        .iter()
        .find(|e| {
            e.get("code").and_then(serde_json::Value::as_str) == Some("E301")
                && e.get("path").and_then(serde_json::Value::as_str) == Some("server.tls.cert")
        })
        .ok_or_else(|| format!("expected E301 with path='server.tls.cert', got: {json}"))?;
    let loc = cert_err
        .get("location")
        .ok_or_else(|| format!("E301 missing location field: {cert_err}"))?;
    assert_eq!(
        loc.get("line").and_then(serde_json::Value::as_u64),
        Some(5),
        "E301 location must point to exact line 5 of server.tls.cert, got: {loc}"
    );

    let warnings = json
        .get("warnings")
        .and_then(serde_json::Value::as_array)
        .ok_or("JSON report missing warnings array")?;
    let w002 = warnings
        .iter()
        .find(|w| w.get("code").and_then(serde_json::Value::as_str) == Some("W002"))
        .ok_or_else(|| format!("expected W002 warning, got: {json}"))?;
    assert_eq!(
        w002.get("path").and_then(serde_json::Value::as_str),
        Some("server.tls.min-version"),
        "JSON check warning must carry config key path, got: {w002}"
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Codex G7 (P1): Startup with `--access-log` or `--log-file` overlapping a served document root
/// MUST fail before opening or creating the log file inside the served directory.
#[test]
fn g7_p1_startup_rejects_log_inside_docroot_before_creating_file() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::env::temp_dir().join(format!(
        "miraserve-g7-p1-startup-{}-{nanos}",
        std::process::id()
    ));
    let www = base.join("www");
    std::fs::create_dir_all(&www)?;
    let cfg_path = base.join("miraserve.kdl");
    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:18443" protocols="h1"
}}
site "app.example.test" {{
    root "{}"
}}
"#,
        www.to_string_lossy().replace('\\', "/")
    );
    std::fs::write(&cfg_path, &kdl)?;

    let forbidden_log = www.join("should-never-exist.log");
    let out = Command::new(miraserve_bin())
        .args(["run", "--dev-tls", "--no-sandbox"])
        .arg(&cfg_path)
        .arg("--access-log")
        .arg(&forbidden_log)
        .output()?;
    assert!(
        !out.status.success(),
        "startup with --access-log inside a docroot must fail"
    );
    assert!(
        !forbidden_log.exists(),
        "startup must reject the overlap BEFORE creating/opening the log file inside docroot"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("overlaps log file"),
        "expected clear overlap error on stderr, got: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Codex Round-3 P2 #2 (G7): Startup with a rotating log (`--log-max-bytes > 0`) placed inside an
/// excluded directory or a configured trust-anchor directory MUST be rejected BEFORE `init_tracing`
/// creates or opens the log file — matching live reload's exact fail-closed policy.
#[test]
fn g7_r3_p2_startup_rejects_rotating_log_in_trust_or_excluded_dir_before_creating_file()
-> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::env::temp_dir().join(format!(
        "miraserve-g7-r3-startup-{}-{nanos}",
        std::process::id()
    ));
    let www = base.join("www");
    let cfg_dir = base.join("cfg");
    let trust_dir = base.join("trust");
    std::fs::create_dir_all(&www)?;
    std::fs::create_dir_all(&cfg_dir)?;
    std::fs::create_dir_all(&trust_dir)?;
    let ca_file = trust_dir.join("client-ca.pem");
    std::fs::write(&ca_file, b"-----BEGIN CERTIFICATE-----\ndummy\n")?;

    let cfg_path = cfg_dir.join("miraserve.kdl");
    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:18444" protocols="h1"
    tls {{
        client-ca "{ca}"
    }}
}}
site "app.example.test" {{
    root "{www}"
}}
"#,
        ca = ca_file.to_string_lossy().replace('\\', "/"),
        www = www.to_string_lossy().replace('\\', "/"),
    );
    std::fs::write(&cfg_path, &kdl)?;

    // 1. Rotating log inside the `client-ca` trust-anchor directory must fail BEFORE creation.
    let forbidden_trust_log = trust_dir.join("access.log");
    let out = Command::new(miraserve_bin())
        .args([
            "run",
            "--dev-tls",
            "--no-sandbox",
            "--log-max-bytes",
            "1024",
        ])
        .arg(&cfg_path)
        .arg("--access-log")
        .arg(&forbidden_trust_log)
        .output()?;
    assert!(
        !out.status.success(),
        "startup with rotating --access-log inside client-ca dir must fail"
    );
    assert!(
        !forbidden_trust_log.exists(),
        "startup must reject rotating log in trust dir BEFORE creating/opening the log file"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to start") && stderr.contains("client-ca"),
        "expected clear refusal mentioning client-ca on stderr, got: {stderr}"
    );

    // 2. Rotating log inside a symlink pointing into `/etc` (excluded system dir) must fail too.
    #[cfg(unix)]
    {
        let sym_etc = base.join("sym-etc");
        std::os::unix::fs::symlink("/etc", &sym_etc)?;
        let out_etc = Command::new(miraserve_bin())
            .args([
                "run",
                "--dev-tls",
                "--no-sandbox",
                "--log-max-bytes",
                "1024",
            ])
            .arg(&cfg_path)
            .arg("--access-log")
            .arg(sym_etc.join("miraserve-never-open.log"))
            .output()?;
        assert!(
            !out_etc.status.success(),
            "startup with rotating --access-log resolving to /etc must fail"
        );
        let stderr_etc = String::from_utf8_lossy(&out_etc.stderr);
        assert!(
            stderr_etc.contains("refusing to start"),
            "expected refusing to start for excluded rotating log dir, got: {stderr_etc}"
        );
    }

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Codex Round-5 P2 (G7): with rotation disabled, `miraserve run` must start when the private
/// access log shares a parent directory with the site's `www/` root (the log FILE is outside the
/// served tree), and must still refuse the same layout once rotation is enabled.
#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)]
fn g7_r5_p2_run_accepts_non_rotating_log_beside_www_and_refuses_rotation() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::env::temp_dir().join(format!(
        "miraserve-r5-run-beside-{}-{nanos}",
        std::process::id()
    ));
    let www = base.join("www");
    let cfg_dir = base.join("cfg");
    std::fs::create_dir_all(&www)?;
    std::fs::create_dir_all(&cfg_dir)?;
    std::fs::write(www.join("index.html"), b"ok")?;
    let probe = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = probe.local_addr()?.port();
    drop(probe);
    let cfg_path = cfg_dir.join("miraserve.kdl");
    std::fs::write(
        &cfg_path,
        format!(
            r#"
server {{
    listen "127.0.0.1:{port}" protocols="h1"
}}
site "localhost" {{
    root "{}"
}}
"#,
            www.display()
        ),
    )?;
    let access_log = base.join("access.log");
    let pid_file = base.join("miraserve.pid");

    // Rotation enabled: the log directory contains the site root -> refused before any file.
    let refused = Command::new(miraserve_bin())
        .args([
            "run",
            "--dev-tls",
            "--no-sandbox",
            "--log-max-bytes",
            "1024",
        ])
        .arg(&cfg_path)
        .arg("--access-log")
        .arg(&access_log)
        .output()?;
    assert!(
        !refused.status.success(),
        "rotating log beside www must be refused"
    );
    assert!(!access_log.exists());

    // Rotation disabled: starts, writes the log, and shuts down cleanly.
    let mut child = Command::new(miraserve_bin())
        .args(["run", "--dev-tls", "--no-sandbox", "--log-max-bytes", "0"])
        .arg(&cfg_path)
        .arg("--access-log")
        .arg(&access_log)
        .arg("--pid-file")
        .arg(&pid_file)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let expected_pid = child.id().to_string();
    let mut ready = false;
    for _ in 0..50 {
        if std::fs::read_to_string(&pid_file).is_ok_and(|c| c.trim() == expected_pid) {
            ready = true;
            break;
        }
        if let Some(status) = child.try_wait()? {
            let mut stderr = String::new();
            if let Some(mut pipe) = child.stderr.take() {
                let _ = std::io::Read::read_to_string(&mut pipe, &mut stderr);
            }
            return Err(format!("run exited early ({status}): {stderr}").into());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        ready,
        "non-rotating log beside www/ must not prevent startup"
    );
    assert!(
        access_log.is_file(),
        "the access log must be created beside www/"
    );
    // Wait until the listener accepts connections (signal handlers are installed by then) so
    // SIGTERM exercises graceful shutdown rather than racing process startup.
    let mut listening = false;
    for _ in 0..50 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            listening = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        listening,
        "server never accepted connections on port {port}"
    );
    std::thread::sleep(std::time::Duration::from_millis(300));
    let _ = Command::new("kill").args(["-TERM", &expected_pid]).status();
    let out = child.wait_with_output()?;
    assert!(
        out.status.success(),
        "server did not exit cleanly: {} stderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Codex Round-7 staging fix: exercises the real CLI binary with a non-rotating access log in an
/// ungranted parent directory under Landlock, sends distinct HTTPS requests before and after a
/// live CLI `reload`, and asserts the access log contains BOTH distinct request paths.
#[cfg(unix)]
#[test]
#[cfg_attr(
    target_os = "linux",
    ignore = "requires an enforcing Landlock kernel; run with --ignored on the staging VM"
)]
#[allow(clippy::too_many_lines)]
fn g7_r7_enforced_cli_non_rotating_access_log_records_before_and_after_reload() -> TestResult {
    use rustls::pki_types::pem::PemObject as _;
    use std::io::{Read as _, Write as _};
    use std::sync::Arc;

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::fs::canonicalize(std::env::temp_dir())?.join(format!(
        "miraserve-r7-cli-log-{}-{nanos}",
        std::process::id()
    ));
    let www = base.join("www");
    let cfg_dir = base.join("cfg");
    let tls_dir = base.join("tls");
    let log_dir = base.join("ungranted-logs");
    let pid_dir = base.join("run");
    std::fs::create_dir_all(&www)?;
    std::fs::create_dir_all(&cfg_dir)?;
    std::fs::create_dir_all(&tls_dir)?;
    std::fs::create_dir_all(&log_dir)?;
    std::fs::create_dir_all(&pid_dir)?;
    std::fs::write(www.join("before-reload"), b"BEFORE-OK")?;
    std::fs::write(www.join("after-reload"), b"AFTER-OK")?;

    let cert_path = tls_dir.join("server.crt");
    let key_path = tls_dir.join("server.key");
    let cert_gen = Command::new(miraserve_bin())
        .args([
            "cert",
            "generate-dev",
            "--hosts",
            "logreload.example",
            "--cert",
        ])
        .arg(&cert_path)
        .arg("--key")
        .arg(&key_path)
        .output()?;
    assert!(
        cert_gen.status.success(),
        "cert generate-dev failed: {}",
        String::from_utf8_lossy(&cert_gen.stderr)
    );

    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);

    let cfg_path = cfg_dir.join("miraserve.kdl");
    std::fs::write(
        &cfg_path,
        format!(
            r#"
server {{
    listen "127.0.0.1:{port}" protocols="h1"
    tls {{
        cert "{cert}"
        key "{key}"
    }}
    sandbox {{
        landlock true
        seccomp "off"
    }}
}}
site "logreload.example" {{
    root "{www}"
}}
"#,
            cert = cert_path.display(),
            key = key_path.display(),
            www = www.display(),
        ),
    )?;
    let access_log = log_dir.join("access.log");
    let pid_file = pid_dir.join("miraserve.pid");

    let mut child = Command::new(miraserve_bin())
        .args(["run", "--log-max-bytes", "0"])
        .arg(&cfg_path)
        .arg("--access-log")
        .arg(&access_log)
        .arg("--pid-file")
        .arg(&pid_file)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let expected_pid = child.id().to_string();

    let mut ready = false;
    for _ in 0..80 {
        if std::fs::read_to_string(&pid_file).is_ok_and(|c| c.trim() == expected_pid)
            && std::net::TcpStream::connect(("127.0.0.1", port)).is_ok()
        {
            ready = true;
            break;
        }
        if let Some(status) = child.try_wait()? {
            let mut stderr = String::new();
            if let Some(mut pipe) = child.stderr.take() {
                let _ = pipe.read_to_string(&mut stderr);
            }
            return Err(format!("miraserve exited early ({status}): {stderr}").into());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(ready, "miraserve CLI never became ready on port {port}");

    let mut roots = rustls::RootCertStore::empty();
    let cert_pem = std::fs::read(&cert_path)?;
    for cert in rustls::pki_types::CertificateDer::pem_slice_iter(&cert_pem) {
        roots.add(cert?)?;
    }
    let client_cfg = Arc::new(
        rustls::ClientConfig::builder_with_provider(miraserve_tls::build_crypto_provider(false))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );

    let https_get = |req_path: &str| -> Result<String, Box<dyn std::error::Error>> {
        let server_name = rustls::pki_types::ServerName::try_from("logreload.example")?;
        let conn = rustls::ClientConnection::new(Arc::clone(&client_cfg), server_name)?;
        let tcp = std::net::TcpStream::connect(("127.0.0.1", port))?;
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        tcp.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
        let mut tls = rustls::StreamOwned::new(conn, tcp);
        write!(
            tls,
            "GET {req_path} HTTP/1.1\r\nHost: logreload.example\r\nConnection: close\r\n\r\n"
        )?;
        tls.flush()?;
        let mut resp = String::new();
        let _ = tls.read_to_string(&mut resp);
        Ok(resp)
    };

    let resp_before = https_get("/before-reload")?;
    assert!(
        resp_before.contains("200 OK") && resp_before.contains("BEFORE-OK"),
        "expected 200 BEFORE-OK, got: {resp_before}"
    );

    // Trigger a live CLI reload while the worker is confined and holds the open access-log fd.
    let reload_out = Command::new(miraserve_bin())
        .args(["reload", "--pid-file"])
        .arg(&pid_file)
        .arg("--config")
        .arg(&cfg_path)
        .output()?;
    assert!(
        reload_out.status.success(),
        "miraserve reload failed: stdout={} stderr={}",
        String::from_utf8_lossy(&reload_out.stdout),
        String::from_utf8_lossy(&reload_out.stderr),
    );

    let resp_after = https_get("/after-reload")?;
    assert!(
        resp_after.contains("200 OK") && resp_after.contains("AFTER-OK"),
        "expected 200 AFTER-OK, got: {resp_after}"
    );

    std::thread::sleep(std::time::Duration::from_millis(200));
    let _ = Command::new("kill").args(["-TERM", &expected_pid]).status();
    let out = child.wait_with_output()?;
    assert!(
        out.status.success(),
        "server did not exit cleanly after reload: {} stderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    let log_text = std::fs::read_to_string(&access_log)?;
    assert!(
        log_text.contains("/before-reload"),
        "access log missing pre-reload request: {log_text}"
    );
    assert!(
        log_text.contains("/after-reload"),
        "access log missing post-reload request: {log_text}"
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Quarantine reporting for hosting panels:
/// - `miraserve reload --dry-run --format json` reports quarantined tenant (`owner-dir`) sites
///   (symlink to `/etc` and inaccessible non-directory root) as `W026` entries with `reloaded: false`
///   and empty `errors`.
/// - `miraserve reload --dry-run --format text` (and default) prints one `quarantined:` line per
///   quarantined site on stderr.
/// - `miraserve check --fs --format json` includes every quarantined site as a `W026` warning with
///   its site key path.
/// - Sites without `owner-dir` keep the existing hard-error (`E301`) behaviour.
#[cfg(unix)]
#[allow(clippy::too_many_lines)]
#[test]
fn reload_quarantine_report_json_text_and_check_fs_json() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::env::temp_dir().join(format!(
        "miraserve-quarantine-report-{}-{nanos}",
        std::process::id()
    ));
    let conf_dir = base.join("conf");
    let bad_owner = base.join("tenants/bad");
    let good_owner = base.join("tenants/good");
    let good_root = good_owner.join("public_html");
    let file_owner = base.join("tenants/file");
    let file_root = file_owner.join("not-a-dir");

    std::fs::create_dir_all(&conf_dir)?;
    std::fs::create_dir_all(&bad_owner)?;
    std::fs::create_dir_all(&good_root)?;
    std::fs::create_dir_all(&file_owner)?;
    std::fs::write(good_root.join("index.html"), b"ok")?;
    std::fs::write(&file_root, b"not a directory")?;

    let bad_root = bad_owner.join("public_html");
    std::os::unix::fs::symlink("/etc", &bad_root)?;

    let cfg_path = conf_dir.join("miraserve.kdl");
    std::fs::write(
        &cfg_path,
        format!(
            r#"
server {{
    listen "127.0.0.1:8443"
}}
site "bad.example" {{
    owner-dir "{}"
    root "{}"
}}
site "good.example" {{
    owner-dir "{}"
    root "{}"
}}
site "file.example" {{
    owner-dir "{}"
    root "{}"
}}
"#,
            bad_owner.display(),
            bad_root.display(),
            good_owner.display(),
            good_root.display(),
            file_owner.display(),
            file_root.display(),
        ),
    )?;

    // 1. `reload --dry-run --format json`
    let json_out = Command::new(miraserve_bin())
        .args(["reload", "--dry-run", "--format", "json", "--config"])
        .arg(&cfg_path)
        .output()?;
    assert!(
        json_out.status.success(),
        "reload --dry-run --format json must succeed when only tenant sites are quarantined: stdout={} stderr={}",
        String::from_utf8_lossy(&json_out.stdout),
        String::from_utf8_lossy(&json_out.stderr),
    );
    assert!(
        json_out.stderr.is_empty(),
        "reload --format json must not write to stderr, got: {}",
        String::from_utf8_lossy(&json_out.stderr),
    );
    let parsed: serde_json::Value = serde_json::from_slice(&json_out.stdout)?;
    // A dry run sends no signal: no outcome, marked as a prediction.
    assert!(
        parsed
            .get("reloaded")
            .is_some_and(serde_json::Value::is_null),
        "dry run has no reload outcome: {parsed}"
    );
    assert_eq!(
        parsed.get("dry_run").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        parsed
            .get("errors")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    let quarantined = parsed
        .get("quarantined")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing quarantined array")?;
    assert_eq!(
        quarantined.len(),
        2,
        "expected exactly 2 quarantined sites, got: {parsed}"
    );
    let first_q = quarantined.first().ok_or("missing quarantined[0]")?;
    let second_q = quarantined.get(1).ok_or("missing quarantined[1]")?;
    assert_eq!(
        first_q.get("site").and_then(serde_json::Value::as_str),
        Some("bad.example")
    );
    assert_eq!(
        first_q.get("index").and_then(serde_json::Value::as_u64),
        Some(0)
    );
    assert_eq!(
        first_q.get("code").and_then(serde_json::Value::as_str),
        Some("W026")
    );
    assert!(
        first_q
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|r| !r.is_empty()),
        "expected non-empty quarantine reason for bad.example: {parsed}"
    );
    assert_eq!(
        second_q.get("site").and_then(serde_json::Value::as_str),
        Some("file.example")
    );
    assert_eq!(
        second_q.get("index").and_then(serde_json::Value::as_u64),
        Some(2)
    );
    assert_eq!(
        second_q.get("code").and_then(serde_json::Value::as_str),
        Some("W026")
    );
    assert!(
        second_q
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|r| r.contains("not a directory")),
        "expected 'not a directory' quarantine reason for file.example: {parsed}"
    );

    // 2. `reload --dry-run` (default text format) prints one `quarantined:` line per site on stderr
    let text_out = Command::new(miraserve_bin())
        .args(["reload", "--dry-run", "--config"])
        .arg(&cfg_path)
        .output()?;
    assert!(
        text_out.status.success(),
        "reload --dry-run text failed: stdout={} stderr={}",
        String::from_utf8_lossy(&text_out.stdout),
        String::from_utf8_lossy(&text_out.stderr),
    );
    let text_stderr = String::from_utf8_lossy(&text_out.stderr);
    assert!(
        text_stderr.contains("quarantined: site 'bad.example' (site[0]): "),
        "expected quarantined line for bad.example on stderr, got: {text_stderr}"
    );
    assert!(
        text_stderr.contains("quarantined: site 'file.example' (site[2]): "),
        "expected quarantined line for file.example on stderr, got: {text_stderr}"
    );
    assert!(
        !text_stderr.contains("good.example"),
        "good.example must not be quarantined, stderr: {text_stderr}"
    );

    // 3. `check --fs --format json` includes every quarantined site as W026 with its site key path
    let check_out = Command::new(miraserve_bin())
        .args(["check", "--fs", "--dev-tls", "--format", "json"])
        .arg(&cfg_path)
        .output()?;
    assert!(
        check_out.status.success(),
        "check --fs --format json failed: stdout={} stderr={}",
        String::from_utf8_lossy(&check_out.stdout),
        String::from_utf8_lossy(&check_out.stderr),
    );
    let check_json: serde_json::Value = serde_json::from_slice(&check_out.stdout)?;
    assert_eq!(
        check_json.get("valid").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    let w026: Vec<&serde_json::Value> = check_json
        .get("warnings")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing warnings array")?
        .iter()
        .filter(|w| w.get("code").and_then(serde_json::Value::as_str) == Some("W026"))
        .collect();
    assert_eq!(
        w026.len(),
        2,
        "expected 2 W026 warnings in check --fs --format json: {check_json}"
    );
    assert_eq!(
        w026.first()
            .and_then(|w| w.get("path"))
            .and_then(serde_json::Value::as_str),
        Some("site[0].root")
    );
    assert_eq!(
        w026.get(1)
            .and_then(|w| w.get("path"))
            .and_then(serde_json::Value::as_str),
        Some("site[2].root")
    );

    // 4. Non-tenant site (no `owner-dir`) with root symlink to `/etc` still fails hard with E301
    let non_tenant_cfg = conf_dir.join("non-tenant.kdl");
    std::fs::write(
        &non_tenant_cfg,
        format!(
            r#"
server {{
    listen "127.0.0.1:8443"
}}
site "unowned.example" {{
    root "{}"
}}
"#,
            bad_root.display(),
        ),
    )?;
    let non_tenant_out = Command::new(miraserve_bin())
        .args(["reload", "--dry-run", "--format", "json", "--config"])
        .arg(&non_tenant_cfg)
        .output()?;
    assert!(
        !non_tenant_out.status.success(),
        "reload must still refuse unsafe root on site without owner-dir"
    );
    let non_tenant_json: serde_json::Value = serde_json::from_slice(&non_tenant_out.stdout)?;
    // A dry run never reloads: `reloaded` is null, the outcome says it was refused.
    assert!(
        non_tenant_json
            .get("reloaded")
            .is_some_and(serde_json::Value::is_null),
        "dry run has no reload outcome: {non_tenant_json}"
    );
    assert_eq!(
        non_tenant_json
            .get("outcome")
            .and_then(serde_json::Value::as_str),
        Some("dry_run_refused")
    );
    assert_eq!(
        non_tenant_json
            .get("quarantined")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    let non_tenant_errors = non_tenant_json
        .get("errors")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing errors array")?;
    assert!(
        non_tenant_errors
            .iter()
            .any(|e| e.as_str().is_some_and(|s| s.contains("E301"))),
        "expected E301 in errors for non-tenant unsafe root, got: {non_tenant_json}"
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Live `miraserve reload --format json` against a running server reports `reloaded: true`
/// together with the quarantined tenant site list and empty `errors`.
#[cfg(unix)]
#[allow(clippy::too_many_lines)]
#[test]
fn reload_format_json_against_live_daemon_reports_reloaded_true() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::env::temp_dir().join(format!(
        "miraserve-live-quarantine-reload-{}-{nanos}",
        std::process::id()
    ));
    let conf_dir = base.join("conf");
    let bad_owner = base.join("tenants/bad");
    let good_owner = base.join("tenants/good");
    let good_root = good_owner.join("public_html");
    std::fs::create_dir_all(&conf_dir)?;
    std::fs::create_dir_all(&bad_owner)?;
    std::fs::create_dir_all(&good_root)?;
    std::fs::write(good_root.join("index.html"), b"ok")?;

    let bad_root = bad_owner.join("public_html");
    std::os::unix::fs::symlink("/etc", &bad_root)?;

    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);

    let pid_file = base.join("miraserve.pid");
    let cfg_path = conf_dir.join("miraserve.kdl");
    std::fs::write(
        &cfg_path,
        format!(
            r#"
server {{
    listen "127.0.0.1:{port}" protocols="h2,h1"
}}
site "bad.example" {{
    owner-dir "{}"
    root "{}"
}}
site "good.example" {{
    owner-dir "{}"
    root "{}"
}}
"#,
            bad_owner.display(),
            bad_root.display(),
            good_owner.display(),
            good_root.display(),
        ),
    )?;

    let mut child = Command::new(miraserve_bin())
        .args(["run", "--dev-tls", "--no-sandbox", "--pid-file"])
        .arg(&pid_file)
        .arg(&cfg_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;

    let expected_pid = child.id().to_string();
    let mut ready = false;
    for _ in 0..80 {
        if std::fs::read_to_string(&pid_file).is_ok_and(|c| c.trim() == expected_pid)
            && std::net::TcpStream::connect(("127.0.0.1", port)).is_ok()
        {
            ready = true;
            break;
        }
        if let Some(status) = child.try_wait()? {
            let mut stderr = String::new();
            if let Some(mut pipe) = child.stderr.take() {
                use std::io::Read as _;
                let _ = pipe.read_to_string(&mut stderr);
            }
            return Err(format!("miraserve exited early ({status}): {stderr}").into());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(ready, "miraserve never became ready on port {port}");

    let reload_out = Command::new(miraserve_bin())
        .args(["reload", "--format", "json", "--pid-file"])
        .arg(&pid_file)
        .args(["--config"])
        .arg(&cfg_path)
        .output()?;

    let _ = Command::new("kill").args(["-TERM", &expected_pid]).status();
    let _ = child.wait();

    assert!(
        reload_out.status.success(),
        "live reload --format json failed: stdout={} stderr={}",
        String::from_utf8_lossy(&reload_out.stdout),
        String::from_utf8_lossy(&reload_out.stderr),
    );
    assert!(
        reload_out.stderr.is_empty(),
        "live reload --format json must not write to stderr, got: {}",
        String::from_utf8_lossy(&reload_out.stderr),
    );
    let parsed: serde_json::Value = serde_json::from_slice(&reload_out.stdout)?;
    assert_eq!(
        parsed.get("reloaded").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        parsed
            .get("errors")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    let quarantined = parsed
        .get("quarantined")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing quarantined array")?;
    assert_eq!(quarantined.len(), 1);
    let first_q = quarantined.first().ok_or("missing quarantined[0]")?;
    assert_eq!(
        first_q.get("site").and_then(serde_json::Value::as_str),
        Some("bad.example")
    );
    assert_eq!(
        first_q.get("index").and_then(serde_json::Value::as_u64),
        Some(0)
    );
    assert_eq!(
        first_q.get("code").and_then(serde_json::Value::as_str),
        Some("W026")
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Review 33/34: a missing upstream TLS file on a tenant site is reported as W026 with the real
/// configuration path (`...reverse-proxy.upstream-tls.<directive>`) and the line of that very
/// directive, by both `check` and `check --fs`.
#[cfg(unix)]
#[test]
fn w026_names_the_failing_upstream_tls_directive_and_its_line() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base =
        std::env::temp_dir().join(format!("miraserve-w026-up-{}-{nanos}", std::process::id()));
    let owner = base.join("owner");
    std::fs::create_dir_all(owner.join("www"))?;
    std::fs::write(owner.join("present.pem"), b"present")?;
    // Fixed permissions (not the runner's umask): only the missing file decides the result.
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&owner, std::fs::Permissions::from_mode(0o755))?;
        std::fs::set_permissions(
            owner.join("present.pem"),
            std::fs::Permissions::from_mode(0o640),
        )?;
    }
    let missing = owner.join("missing.pem");
    let present = owner.join("present.pem");
    // (failing directive, its line, the upstream-tls body): exactly one file is missing.
    let cases = [
        (
            "ca-cert",
            12_u64,
            format!("ca-cert \"{}\"", missing.display()),
        ),
        (
            "client-cert",
            12,
            format!(
                "client-cert \"{}\"\n                client-key \"{}\"",
                missing.display(),
                present.display()
            ),
        ),
        (
            "client-key",
            13,
            format!(
                "client-cert \"{}\"\n                client-key \"{}\"",
                present.display(),
                missing.display()
            ),
        ),
    ];
    for (directive, line, body) in cases {
        let cfg_path = base.join(format!("{directive}.kdl"));
        std::fs::write(
            &cfg_path,
            format!(
                r#"server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "shop.example" {{
    owner-dir "{owner}"
    root "{owner}/www"
    route "/api/*" {{
        reverse-proxy {{
            upstream "https://127.0.0.1:9000"
            upstream-tls {{
                {body}
            }}
        }}
    }}
}}
"#,
                owner = owner.display()
            ),
        )?;
        for fs_flag in [false, true] {
            let mut cmd = Command::new(miraserve_bin());
            cmd.arg("check").arg("--format").arg("json");
            if fs_flag {
                cmd.arg("--fs");
            }
            let out = cmd.arg(&cfg_path).output()?;
            let report: serde_json::Value = serde_json::from_slice(&out.stdout)?;
            let issues: Vec<&serde_json::Value> = ["warnings", "errors"]
                .iter()
                .filter_map(|k| report.get(*k).and_then(serde_json::Value::as_array))
                .flatten()
                .filter(|w| w.get("code").and_then(serde_json::Value::as_str) == Some("W026"))
                .collect();
            let expected = format!("site[0].route[0].reverse-proxy.upstream-tls.{directive}");
            let found = issues.iter().find(|w| {
                w.get("path").and_then(serde_json::Value::as_str) == Some(expected.as_str())
            });
            let found = found.ok_or_else(|| {
                format!(
                    "no W026 at {expected} (--fs {fs_flag}): {}",
                    String::from_utf8_lossy(&out.stdout)
                )
            })?;
            assert_eq!(
                found
                    .get("location")
                    .and_then(|l| l.get("line"))
                    .and_then(serde_json::Value::as_u64),
                Some(line),
                "W026 location for {directive} (--fs {fs_flag})"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

#[test]
fn check_reports_plain_http_note_when_redirect_listener_exists() -> TestResult {
    let base = std::env::temp_dir().join(format!(
        "miraserve-check-http80-note-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(&base)?;

    let with_http_path = base.join("with-http.kdl");
    std::fs::write(
        &with_http_path,
        r#"server {
    listen ":443" protocols="h3,h2,h1"
    listen ":80" redirect-https=#true
    tls { cert "/etc/miraserve/c.pem"; key "/etc/miraserve/k.pem" }
    sandbox { user "miraserve"; landlock #true; seccomp "strict" }
}
site "plain.example.com" "www.plain.example.com" {
    http "serve"
    root "/var/www/plain"
}
site "secure.example.com" {
    root "/var/www/secure"
}
"#,
    )?;

    let text_out = Command::new(miraserve_bin())
        .args(["check", "--strict"])
        .arg(&with_http_path)
        .output()?;
    assert!(
        text_out.status.success(),
        "expected strict check to pass, stderr: {}",
        String::from_utf8_lossy(&text_out.stderr)
    );
    let stdout = String::from_utf8_lossy(&text_out.stdout);
    assert!(
        stdout.contains(
            "note: sites served over plain HTTP: plain.example.com, www.plain.example.com"
        ),
        "expected plain-HTTP note in stdout, got: {stdout}"
    );
    assert!(
        !stdout.contains("secure.example.com"),
        "redirect site must not appear in plain-HTTP note: {stdout}"
    );

    let json_out = Command::new(miraserve_bin())
        .args(["check", "--format", "json"])
        .arg(&with_http_path)
        .output()?;
    assert!(json_out.status.success());
    let json: serde_json::Value = serde_json::from_slice(&json_out.stdout)?;
    assert_eq!(
        json.get("valid").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    let notes = json
        .get("notes")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| format!("expected notes array in JSON: {json}"))?;
    assert!(
        notes.iter().any(|n| {
            n.as_str().is_some_and(|s| {
                s.contains("plain.example.com") && s.contains("www.plain.example.com")
            })
        }),
        "expected plain-HTTP note in JSON notes: {notes:?}"
    );

    // Default config (no `http "serve"`): JSON omits `notes`.
    let default_json = Command::new(miraserve_bin())
        .args(["check", "--format", "json"])
        .arg(example_config_path())
        .output()?;
    assert!(default_json.status.success());
    let default_report: serde_json::Value = serde_json::from_slice(&default_json.stdout)?;
    assert!(
        default_report.get("notes").is_none(),
        "default config must not include notes field: {default_report}"
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

#[test]
fn check_warns_w031_when_site_serves_http_without_redirect_listener() -> TestResult {
    let base = std::env::temp_dir().join(format!(
        "miraserve-check-http80-warn-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(&base)?;

    let without_http_path = base.join("without-http.kdl");
    std::fs::write(
        &without_http_path,
        r#"server {
    listen ":443" protocols="h3,h2,h1"
    tls { cert "/etc/miraserve/c.pem"; key "/etc/miraserve/k.pem" }
    sandbox { user "miraserve"; landlock #true; seccomp "strict" }
}
site "orphan.example.com" {
    http "serve"
    root "/var/www/orphan"
}
"#,
    )?;

    let warn_text = Command::new(miraserve_bin())
        .arg("check")
        .arg(&without_http_path)
        .output()?;
    assert!(
        warn_text.status.success(),
        "W031 must be a warning, not an error; stderr: {}",
        String::from_utf8_lossy(&warn_text.stderr)
    );
    let warn_stderr = String::from_utf8_lossy(&warn_text.stderr);
    assert!(
        warn_stderr.contains("W031"),
        "expected W031 on stderr, got: {warn_stderr}"
    );
    let warn_stdout = String::from_utf8_lossy(&warn_text.stdout);
    assert!(
        !warn_stdout.contains("note: sites served over plain HTTP"),
        "must not emit plain-HTTP note when no HTTP listener exists: {warn_stdout}"
    );

    let strict_fail = Command::new(miraserve_bin())
        .args(["check", "--strict"])
        .arg(&without_http_path)
        .output()?;
    assert!(
        !strict_fail.status.success(),
        "expected --strict to fail on W031"
    );

    let warn_json = Command::new(miraserve_bin())
        .args(["check", "--format", "json"])
        .arg(&without_http_path)
        .output()?;
    assert!(warn_json.status.success());
    let warn_report: serde_json::Value = serde_json::from_slice(&warn_json.stdout)?;
    let w031 = warn_report
        .get("warnings")
        .and_then(serde_json::Value::as_array)
        .and_then(|arr| {
            arr.iter()
                .find(|w| w.get("code").and_then(serde_json::Value::as_str) == Some("W031"))
        })
        .ok_or_else(|| format!("expected W031 in JSON warnings: {warn_report}"))?;
    assert_eq!(
        w031.get("path").and_then(serde_json::Value::as_str),
        Some("site[0].http")
    );
    assert_eq!(
        w031.get("location")
            .and_then(|l| l.get("line"))
            .and_then(serde_json::Value::as_u64),
        Some(7)
    );
    assert!(
        warn_report.get("notes").is_none(),
        "JSON report must omit empty notes field: {warn_report}"
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

#[allow(clippy::too_many_lines)]
#[test]
fn check_warns_w032_when_site_enables_plain_http_credentials() -> TestResult {
    let base = std::env::temp_dir().join(format!(
        "miraserve-check-http80-creds-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(&base)?;

    let creds_path = base.join("plain-creds.kdl");
    std::fs::write(
        &creds_path,
        r#"server {
    listen ":443" protocols="h3,h2,h1"
    listen ":80" redirect-https=#true
    tls { cert "/etc/miraserve/c.pem"; key "/etc/miraserve/k.pem" }
    sandbox { user "miraserve"; landlock #true; seccomp "strict" }
}
site "staging.example.com" {
    http "serve" credentials=#true
    root "/var/www/staging"
}
site "second.example.com" {
    http "serve" credentials=#true
    root "/var/www/second"
}
site "safe-plain.example.com" {
    http "serve" credentials=#false
    root "/var/www/safe"
}
"#,
    )?;

    // Non-strict check succeeds (warning, not error) and prints W032 naming each opted-in site.
    let text_out = Command::new(miraserve_bin())
        .arg("check")
        .arg(&creds_path)
        .output()?;
    assert!(
        text_out.status.success(),
        "W032 must be a warning, not an error; stderr: {}",
        String::from_utf8_lossy(&text_out.stderr)
    );
    let stderr = String::from_utf8_lossy(&text_out.stderr);
    assert!(stderr.contains("W032"), "expected W032 on stderr: {stderr}");
    for expected in [
        "passwords for staging.example.com travel unencrypted over plain HTTP (http \"serve\" credentials=#true)",
        "passwords for second.example.com travel unencrypted over plain HTTP (http \"serve\" credentials=#true)",
    ] {
        // Miette may wrap long lines at terminal width; normalize internal whitespace for text check.
        let collapsed: String = stderr.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            collapsed.contains(expected),
            "expected warning text `{expected}` in stderr:\n{stderr}"
        );
    }
    assert!(
        !stderr.contains("safe-plain.example.com"),
        "site with credentials=#false must not trigger W032: {stderr}"
    );

    // `--strict` fails unless `--allow-warning W032` is supplied.
    let strict_fail = Command::new(miraserve_bin())
        .args(["check", "--strict"])
        .arg(&creds_path)
        .output()?;
    assert!(
        !strict_fail.status.success(),
        "expected --strict to fail on W032"
    );

    let strict_allow = Command::new(miraserve_bin())
        .args(["check", "--strict", "--allow-warning", "W032"])
        .arg(&creds_path)
        .output()?;
    assert!(
        strict_allow.status.success(),
        "expected --strict --allow-warning W032 to succeed; stderr: {}",
        String::from_utf8_lossy(&strict_allow.stderr)
    );

    // JSON output carries exact un-wrapped message, path, and line number per site.
    let json_out = Command::new(miraserve_bin())
        .args(["check", "--format", "json"])
        .arg(&creds_path)
        .output()?;
    assert!(json_out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&json_out.stdout)?;
    let warnings = report
        .get("warnings")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| format!("expected warnings array in JSON: {report}"))?;
    let w032s: Vec<_> = warnings
        .iter()
        .filter(|w| w.get("code").and_then(serde_json::Value::as_str) == Some("W032"))
        .collect();
    assert_eq!(w032s.len(), 2, "expected 2 W032 warnings: {w032s:?}");
    assert_eq!(
        w032s
            .first()
            .and_then(|w| w.get("message"))
            .and_then(serde_json::Value::as_str),
        Some(
            "passwords for staging.example.com travel unencrypted over plain HTTP (http \"serve\" credentials=#true)"
        )
    );
    assert_eq!(
        w032s
            .first()
            .and_then(|w| w.get("path"))
            .and_then(serde_json::Value::as_str),
        Some("site[0].http")
    );
    assert_eq!(
        w032s
            .get(1)
            .and_then(|w| w.get("message"))
            .and_then(serde_json::Value::as_str),
        Some(
            "passwords for second.example.com travel unencrypted over plain HTTP (http \"serve\" credentials=#true)"
        )
    );
    assert_eq!(
        w032s
            .get(1)
            .and_then(|w| w.get("path"))
            .and_then(serde_json::Value::as_str),
        Some("site[1].http")
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Pins `miraserve check --dump-normalized` (both JSON and text formats) on the shipped
/// `examples/` configurations against byte-exact output captured from `v0.1.2`.
///
/// Provenance: captured on tag `v0.1.2` (commit `4d5891d`, tree identical to `main` `da07274`)
/// from the repository root with:
/// - `miraserve check --format json --dump-normalized examples/miraserve.kdl`
/// - `miraserve check --dump-normalized examples/miraserve.kdl`
/// - `miraserve check --dev-tls --format json --dump-normalized examples/dev-local.kdl`
/// - `miraserve check --dev-tls --dump-normalized examples/dev-local.kdl`
///
/// `examples/dev-local.kdl` sets a relative `root "www"`, which `miraserve check` resolves to
/// `<repo_root>/examples/www`; only that absolute checkout prefix is substituted below.
#[allow(clippy::too_many_lines)]
#[test]
fn check_dump_normalized_examples_byte_identical_to_v012() -> TestResult {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()?;
    let dev_www = repo_root
        .join("examples")
        .join("www")
        .to_string_lossy()
        .replace('\\', "/");

    let expected_miraserve_json = concat!(
        "{\n",
        "  \"valid\": true,\n",
        "  \"strict\": false,\n",
        "  \"source\": \"examples/miraserve.kdl\",\n",
        "  \"summary\": {\n",
        "    \"listeners\": 2,\n",
        "    \"sites\": 3,\n",
        "    \"routes\": 4,\n",
        "    \"tls_min_version\": \"1.3\",\n",
        "    \"pqc_hybrid\": true,\n",
        "    \"warnings\": 0,\n",
        "    \"errors\": 0\n",
        "  },\n",
        "  \"errors\": [],\n",
        "  \"warnings\": [],\n",
        "  \"config\": {\n",
        "    \"server\": {\n",
        "      \"listeners\": [\n",
        "        {\n",
        "          \"addr\": \":443\",\n",
        "          \"protocols\": [\n",
        "            \"h3\",\n",
        "            \"h2\",\n",
        "            \"h1\"\n",
        "          ],\n",
        "          \"redirect_https\": false\n",
        "        },\n",
        "        {\n",
        "          \"addr\": \":80\",\n",
        "          \"protocols\": [\n",
        "            \"h1\"\n",
        "          ],\n",
        "          \"redirect_https\": true\n",
        "        }\n",
        "      ],\n",
        "      \"tls\": {\n",
        "        \"min_version\": \"1.3\",\n",
        "        \"pqc_hybrid\": true,\n",
        "        \"key_isolation\": \"in-process\",\n",
        "        \"ech\": false,\n",
        "        \"ech_rotate_interval_ms\": 3600000,\n",
        "        \"acme\": {\n",
        "          \"email\": \"ops@example.com\",\n",
        "          \"challenge\": \"tls-alpn-01\",\n",
        "          \"short_lived\": true,\n",
        "          \"ari\": true\n",
        "        }\n",
        "      },\n",
        "      \"sandbox\": {\n",
        "        \"user\": \"miraserve\",\n",
        "        \"landlock\": true,\n",
        "        \"seccomp\": \"strict\"\n",
        "      },\n",
        "      \"timeouts\": {\n",
        "        \"tls_handshake_ms\": 10000,\n",
        "        \"header_read_ms\": 10000,\n",
        "        \"idle_keepalive_ms\": 60000,\n",
        "        \"graceful_drain_ms\": 30000,\n",
        "        \"body_idle_timeout_ms\": 30000,\n",
        "        \"max_body_duration_ms\": 3600000,\n",
        "        \"min_body_rate_bps\": 1024,\n",
        "        \"upstream_connect_ms\": 10000,\n",
        "        \"upstream_response_ms\": 60000,\n",
        "        \"upstream_body_idle_ms\": 60000,\n",
        "        \"response_write_idle_ms\": 30000,\n",
        "        \"min_response_rate_bps\": 1024\n",
        "      },\n",
        "      \"limits\": {\n",
        "        \"max_header_bytes\": 16384,\n",
        "        \"max_body_bytes\": 10485760,\n",
        "        \"max_concurrent_streams\": 128,\n",
        "        \"max_h2_rst_stream_per_sec\": 50,\n",
        "        \"max_connections\": 16384,\n",
        "        \"max_connections_per_ip\": 128,\n",
        "        \"ipv6_prefix_conn_multiplier\": 4,\n",
        "        \"max_streamed_answers_per_ip\": 8,\n",
        "        \"max_streamed_answers_per_backend\": 4\n",
        "      },\n",
        "      \"telemetry\": {\n",
        "        \"metrics_path\": \"/metrics\",\n",
        "        \"service_name\": \"miraserve\",\n",
        "        \"redact_logs\": true\n",
        "      }\n",
        "    },\n",
        "    \"sites\": [\n",
        "      {\n",
        "        \"hosts\": [\n",
        "          \"future.example.com\"\n",
        "        ],\n",
        "        \"security_headers\": \"strict\",\n",
        "        \"rate_limit\": {\n",
        "          \"requests\": 600,\n",
        "          \"per_ms\": 60000,\n",
        "          \"burst\": 150,\n",
        "          \"key\": {\n",
        "            \"type\": \"client-ip\"\n",
        "          }\n",
        "        },\n",
        "        \"bot_auth\": {\n",
        "          \"verify_rfc9421\": true,\n",
        "          \"allow_agents\": [\n",
        "            {\n",
        "              \"name\": \"verified-ai-agents\",\n",
        "              \"serve_markdown\": true\n",
        "            }\n",
        "          ],\n",
        "          \"on_unverified_ai_ua\": \"throttle\"\n",
        "        },\n",
        "        \"ai_publish\": {\n",
        "          \"storage\": \"/var/lib/miraserve/releases/future\",\n",
        "          \"site_id\": \"future.example.com\",\n",
        "          \"keep_versions\": 20,\n",
        "          \"require_signature\": {\n",
        "            \"algorithm\": \"ed25519\",\n",
        "            \"public_key_path\": \"/etc/miraserve/deploy-agent.pub\"\n",
        "          },\n",
        "          \"jwt_public_key\": \"ed25519:/etc/miraserve/publish-jwt.pub\",\n",
        "          \"jwt_issuer\": \"https://auth.example.com\",\n",
        "          \"preflight_checks\": [\n",
        "            {\n",
        "              \"check\": \"no-secrets\"\n",
        "            },\n",
        "            {\n",
        "              \"check\": \"csp-valid\"\n",
        "            },\n",
        "            {\n",
        "              \"check\": \"max-size\",\n",
        "              \"value\": 50000000\n",
        "            }\n",
        "          ],\n",
        "          \"mcp_endpoint\": {\n",
        "            \"path\": \"/_miraserve/publish\",\n",
        "            \"auth\": \"oauth-jwt\"\n",
        "          }\n",
        "        },\n",
        "        \"routes\": []\n",
        "      },\n",
        "      {\n",
        "        \"hosts\": [\n",
        "          \"legacy-blog.example.com\"\n",
        "        ],\n",
        "        \"preset\": \"wordpress-hardened\",\n",
        "        \"security_headers\": \"strict\",\n",
        "        \"root\": \"/var/www/wordpress\",\n",
        "        \"routes\": [\n",
        "          {\n",
        "            \"pattern\": \"*.php\",\n",
        "            \"handler\": {\n",
        "              \"type\": \"fastcgi\",\n",
        "              \"config\": {\n",
        "                \"target\": {\n",
        "                  \"transport\": \"unix\",\n",
        "                  \"path\": \"/run/php/php8.3-fpm.sock\"\n",
        "                },\n",
        "                \"timeout_ms\": 30000,\n",
        "                \"replay_safe_methods\": false\n",
        "              }\n",
        "            }\n",
        "          },\n",
        "          {\n",
        "            \"pattern\": \"/*\",\n",
        "            \"handler\": {\n",
        "              \"type\": \"try-files\",\n",
        "              \"config\": [\n",
        "                \"{path}\",\n",
        "                \"{path}/\",\n",
        "                \"/index.php?{query}\"\n",
        "              ]\n",
        "            }\n",
        "          }\n",
        "        ]\n",
        "      },\n",
        "      {\n",
        "        \"hosts\": [\n",
        "          \"ai.example.com\"\n",
        "        ],\n",
        "        \"security_headers\": \"strict\",\n",
        "        \"routes\": [\n",
        "          {\n",
        "            \"pattern\": \"/mcp/*\",\n",
        "            \"handler\": {\n",
        "              \"type\": \"mcp-gateway\",\n",
        "              \"config\": {\n",
        "                \"upstream\": \"https://10.0.1.20:8443\",\n",
        "                \"oauth_resource_metadata\": true,\n",
        "                \"jwt_public_key\": \"ed25519:/etc/miraserve/mcp-oauth.pub\",\n",
        "                \"jwt_issuer\": \"https://auth.example.com\",\n",
        "                \"jwt_audience\": \"https://ai.example.com\",\n",
        "                \"allow_tools\": [\n",
        "                  \"docs_search\",\n",
        "                  \"catalog_read\"\n",
        "                ],\n",
        "                \"deny_tools\": [\n",
        "                  \"*_delete\",\n",
        "                  \"*_exec\"\n",
        "                ],\n",
        "                \"audit_log\": \"structured-json\",\n",
        "                \"max_json_depth\": 32,\n",
        "                \"max_request_bytes\": 1000000\n",
        "              }\n",
        "            }\n",
        "          },\n",
        "          {\n",
        "            \"pattern\": \"/v1/*\",\n",
        "            \"handler\": {\n",
        "              \"type\": \"reverse-proxy\",\n",
        "              \"config\": {\n",
        "                \"upstreams\": [\n",
        "                  {\n",
        "                    \"url\": \"https://10.0.1.30:8000\",\n",
        "                    \"weight\": 1\n",
        "                  },\n",
        "                  {\n",
        "                    \"url\": \"https://10.0.1.31:8000\",\n",
        "                    \"weight\": 1\n",
        "                  }\n",
        "                ],\n",
        "                \"streaming_flush\": \"immediate\",\n",
        "                \"lb_policy\": \"round-robin\",\n",
        "                \"health_check\": {\n",
        "                  \"path\": \"/health\",\n",
        "                  \"interval_ms\": 5000,\n",
        "                  \"unhealthy_threshold\": 3\n",
        "                },\n",
        "                \"allow_upgrades\": true,\n",
        "                \"strip_prefix\": false\n",
        "              }\n",
        "            }\n",
        "          }\n",
        "        ]\n",
        "      }\n",
        "    ]\n",
        "  }\n",
        "}\n"
    );

    let expected_miraserve_text = concat!(
        "OK: 'examples/miraserve.kdl' is valid (2 listener(s), 3 site(s), 4 route(s), TLS >= 1.3, PQC: X25519MLKEM768 enabled, 0 warning(s))\n",
        "{\n",
        "  \"server\": {\n",
        "    \"listeners\": [\n",
        "      {\n",
        "        \"addr\": \":443\",\n",
        "        \"protocols\": [\n",
        "          \"h3\",\n",
        "          \"h2\",\n",
        "          \"h1\"\n",
        "        ],\n",
        "        \"redirect_https\": false\n",
        "      },\n",
        "      {\n",
        "        \"addr\": \":80\",\n",
        "        \"protocols\": [\n",
        "          \"h1\"\n",
        "        ],\n",
        "        \"redirect_https\": true\n",
        "      }\n",
        "    ],\n",
        "    \"tls\": {\n",
        "      \"min_version\": \"1.3\",\n",
        "      \"pqc_hybrid\": true,\n",
        "      \"key_isolation\": \"in-process\",\n",
        "      \"ech\": false,\n",
        "      \"ech_rotate_interval_ms\": 3600000,\n",
        "      \"acme\": {\n",
        "        \"email\": \"ops@example.com\",\n",
        "        \"challenge\": \"tls-alpn-01\",\n",
        "        \"short_lived\": true,\n",
        "        \"ari\": true\n",
        "      }\n",
        "    },\n",
        "    \"sandbox\": {\n",
        "      \"user\": \"miraserve\",\n",
        "      \"landlock\": true,\n",
        "      \"seccomp\": \"strict\"\n",
        "    },\n",
        "    \"timeouts\": {\n",
        "      \"tls_handshake_ms\": 10000,\n",
        "      \"header_read_ms\": 10000,\n",
        "      \"idle_keepalive_ms\": 60000,\n",
        "      \"graceful_drain_ms\": 30000,\n",
        "      \"body_idle_timeout_ms\": 30000,\n",
        "      \"max_body_duration_ms\": 3600000,\n",
        "      \"min_body_rate_bps\": 1024,\n",
        "      \"upstream_connect_ms\": 10000,\n",
        "      \"upstream_response_ms\": 60000,\n",
        "      \"upstream_body_idle_ms\": 60000,\n",
        "      \"response_write_idle_ms\": 30000,\n",
        "      \"min_response_rate_bps\": 1024\n",
        "    },\n",
        "    \"limits\": {\n",
        "      \"max_header_bytes\": 16384,\n",
        "      \"max_body_bytes\": 10485760,\n",
        "      \"max_concurrent_streams\": 128,\n",
        "      \"max_h2_rst_stream_per_sec\": 50,\n",
        "      \"max_connections\": 16384,\n",
        "      \"max_connections_per_ip\": 128,\n",
        "      \"ipv6_prefix_conn_multiplier\": 4,\n",
        "      \"max_streamed_answers_per_ip\": 8,\n",
        "      \"max_streamed_answers_per_backend\": 4\n",
        "    },\n",
        "    \"telemetry\": {\n",
        "      \"metrics_path\": \"/metrics\",\n",
        "      \"service_name\": \"miraserve\",\n",
        "      \"redact_logs\": true\n",
        "    }\n",
        "  },\n",
        "  \"sites\": [\n",
        "    {\n",
        "      \"hosts\": [\n",
        "        \"future.example.com\"\n",
        "      ],\n",
        "      \"security_headers\": \"strict\",\n",
        "      \"rate_limit\": {\n",
        "        \"requests\": 600,\n",
        "        \"per_ms\": 60000,\n",
        "        \"burst\": 150,\n",
        "        \"key\": {\n",
        "          \"type\": \"client-ip\"\n",
        "        }\n",
        "      },\n",
        "      \"bot_auth\": {\n",
        "        \"verify_rfc9421\": true,\n",
        "        \"allow_agents\": [\n",
        "          {\n",
        "            \"name\": \"verified-ai-agents\",\n",
        "            \"serve_markdown\": true\n",
        "          }\n",
        "        ],\n",
        "        \"on_unverified_ai_ua\": \"throttle\"\n",
        "      },\n",
        "      \"ai_publish\": {\n",
        "        \"storage\": \"/var/lib/miraserve/releases/future\",\n",
        "        \"site_id\": \"future.example.com\",\n",
        "        \"keep_versions\": 20,\n",
        "        \"require_signature\": {\n",
        "          \"algorithm\": \"ed25519\",\n",
        "          \"public_key_path\": \"/etc/miraserve/deploy-agent.pub\"\n",
        "        },\n",
        "        \"jwt_public_key\": \"ed25519:/etc/miraserve/publish-jwt.pub\",\n",
        "        \"jwt_issuer\": \"https://auth.example.com\",\n",
        "        \"preflight_checks\": [\n",
        "          {\n",
        "            \"check\": \"no-secrets\"\n",
        "          },\n",
        "          {\n",
        "            \"check\": \"csp-valid\"\n",
        "          },\n",
        "          {\n",
        "            \"check\": \"max-size\",\n",
        "            \"value\": 50000000\n",
        "          }\n",
        "        ],\n",
        "        \"mcp_endpoint\": {\n",
        "          \"path\": \"/_miraserve/publish\",\n",
        "          \"auth\": \"oauth-jwt\"\n",
        "        }\n",
        "      },\n",
        "      \"routes\": []\n",
        "    },\n",
        "    {\n",
        "      \"hosts\": [\n",
        "        \"legacy-blog.example.com\"\n",
        "      ],\n",
        "      \"preset\": \"wordpress-hardened\",\n",
        "      \"security_headers\": \"strict\",\n",
        "      \"root\": \"/var/www/wordpress\",\n",
        "      \"routes\": [\n",
        "        {\n",
        "          \"pattern\": \"*.php\",\n",
        "          \"handler\": {\n",
        "            \"type\": \"fastcgi\",\n",
        "            \"config\": {\n",
        "              \"target\": {\n",
        "                \"transport\": \"unix\",\n",
        "                \"path\": \"/run/php/php8.3-fpm.sock\"\n",
        "              },\n",
        "              \"timeout_ms\": 30000,\n",
        "              \"replay_safe_methods\": false\n",
        "            }\n",
        "          }\n",
        "        },\n",
        "        {\n",
        "          \"pattern\": \"/*\",\n",
        "          \"handler\": {\n",
        "            \"type\": \"try-files\",\n",
        "            \"config\": [\n",
        "              \"{path}\",\n",
        "              \"{path}/\",\n",
        "              \"/index.php?{query}\"\n",
        "            ]\n",
        "          }\n",
        "        }\n",
        "      ]\n",
        "    },\n",
        "    {\n",
        "      \"hosts\": [\n",
        "        \"ai.example.com\"\n",
        "      ],\n",
        "      \"security_headers\": \"strict\",\n",
        "      \"routes\": [\n",
        "        {\n",
        "          \"pattern\": \"/mcp/*\",\n",
        "          \"handler\": {\n",
        "            \"type\": \"mcp-gateway\",\n",
        "            \"config\": {\n",
        "              \"upstream\": \"https://10.0.1.20:8443\",\n",
        "              \"oauth_resource_metadata\": true,\n",
        "              \"jwt_public_key\": \"ed25519:/etc/miraserve/mcp-oauth.pub\",\n",
        "              \"jwt_issuer\": \"https://auth.example.com\",\n",
        "              \"jwt_audience\": \"https://ai.example.com\",\n",
        "              \"allow_tools\": [\n",
        "                \"docs_search\",\n",
        "                \"catalog_read\"\n",
        "              ],\n",
        "              \"deny_tools\": [\n",
        "                \"*_delete\",\n",
        "                \"*_exec\"\n",
        "              ],\n",
        "              \"audit_log\": \"structured-json\",\n",
        "              \"max_json_depth\": 32,\n",
        "              \"max_request_bytes\": 1000000\n",
        "            }\n",
        "          }\n",
        "        },\n",
        "        {\n",
        "          \"pattern\": \"/v1/*\",\n",
        "          \"handler\": {\n",
        "            \"type\": \"reverse-proxy\",\n",
        "            \"config\": {\n",
        "              \"upstreams\": [\n",
        "                {\n",
        "                  \"url\": \"https://10.0.1.30:8000\",\n",
        "                  \"weight\": 1\n",
        "                },\n",
        "                {\n",
        "                  \"url\": \"https://10.0.1.31:8000\",\n",
        "                  \"weight\": 1\n",
        "                }\n",
        "              ],\n",
        "              \"streaming_flush\": \"immediate\",\n",
        "              \"lb_policy\": \"round-robin\",\n",
        "              \"health_check\": {\n",
        "                \"path\": \"/health\",\n",
        "                \"interval_ms\": 5000,\n",
        "                \"unhealthy_threshold\": 3\n",
        "              },\n",
        "              \"allow_upgrades\": true,\n",
        "              \"strip_prefix\": false\n",
        "            }\n",
        "          }\n",
        "        }\n",
        "      ]\n",
        "    }\n",
        "  ]\n",
        "}\n"
    );

    let expected_dev_local_json = format!(
        concat!(
            "{{\n",
            "  \"valid\": true,\n",
            "  \"strict\": false,\n",
            "  \"source\": \"examples/dev-local.kdl\",\n",
            "  \"summary\": {{\n",
            "    \"listeners\": 2,\n",
            "    \"sites\": 1,\n",
            "    \"routes\": 0,\n",
            "    \"tls_min_version\": \"1.3\",\n",
            "    \"pqc_hybrid\": true,\n",
            "    \"warnings\": 0,\n",
            "    \"errors\": 0\n",
            "  }},\n",
            "  \"errors\": [],\n",
            "  \"warnings\": [],\n",
            "  \"config\": {{\n",
            "    \"server\": {{\n",
            "      \"listeners\": [\n",
            "        {{\n",
            "          \"addr\": \"127.0.0.1:8443\",\n",
            "          \"protocols\": [\n",
            "            \"h3\",\n",
            "            \"h2\",\n",
            "            \"h1\"\n",
            "          ],\n",
            "          \"redirect_https\": false\n",
            "        }},\n",
            "        {{\n",
            "          \"addr\": \"127.0.0.1:8080\",\n",
            "          \"protocols\": [\n",
            "            \"h1\"\n",
            "          ],\n",
            "          \"redirect_https\": true\n",
            "        }}\n",
            "      ],\n",
            "      \"tls\": {{\n",
            "        \"min_version\": \"1.3\",\n",
            "        \"pqc_hybrid\": true,\n",
            "        \"key_isolation\": \"in-process\",\n",
            "        \"ech\": false,\n",
            "        \"ech_rotate_interval_ms\": 3600000\n",
            "      }},\n",
            "      \"sandbox\": {{\n",
            "        \"landlock\": true,\n",
            "        \"seccomp\": \"strict\"\n",
            "      }},\n",
            "      \"timeouts\": {{\n",
            "        \"tls_handshake_ms\": 10000,\n",
            "        \"header_read_ms\": 10000,\n",
            "        \"idle_keepalive_ms\": 60000,\n",
            "        \"graceful_drain_ms\": 30000,\n",
            "        \"body_idle_timeout_ms\": 30000,\n",
            "        \"max_body_duration_ms\": 3600000,\n",
            "        \"min_body_rate_bps\": 1024,\n",
            "        \"upstream_connect_ms\": 10000,\n",
            "        \"upstream_response_ms\": 60000,\n",
            "        \"upstream_body_idle_ms\": 60000,\n",
            "        \"response_write_idle_ms\": 30000,\n",
            "        \"min_response_rate_bps\": 1024\n",
            "      }},\n",
            "      \"limits\": {{\n",
            "        \"max_header_bytes\": 16384,\n",
            "        \"max_body_bytes\": 10485760,\n",
            "        \"max_concurrent_streams\": 128,\n",
            "        \"max_h2_rst_stream_per_sec\": 50,\n",
            "        \"max_connections\": 16384,\n",
            "        \"max_connections_per_ip\": 128,\n",
            "        \"ipv6_prefix_conn_multiplier\": 4,\n",
            "        \"max_streamed_answers_per_ip\": 8,\n",
            "        \"max_streamed_answers_per_backend\": 4\n",
            "      }},\n",
            "      \"telemetry\": {{\n",
            "        \"metrics_path\": \"/metrics\",\n",
            "        \"service_name\": \"miraserve\",\n",
            "        \"redact_logs\": true\n",
            "      }}\n",
            "    }},\n",
            "    \"sites\": [\n",
            "      {{\n",
            "        \"hosts\": [\n",
            "          \"localhost\"\n",
            "        ],\n",
            "        \"security_headers\": \"strict\",\n",
            "        \"root\": \"{dev_www}\",\n",
            "        \"routes\": []\n",
            "      }}\n",
            "    ]\n",
            "  }}\n",
            "}}\n"
        ),
        dev_www = dev_www,
    );

    let expected_dev_local_text = format!(
        concat!(
            "OK: 'examples/dev-local.kdl' is valid (2 listener(s), 1 site(s), 0 route(s), TLS >= 1.3, PQC: X25519MLKEM768 enabled, 0 warning(s))\n",
            "{{\n",
            "  \"server\": {{\n",
            "    \"listeners\": [\n",
            "      {{\n",
            "        \"addr\": \"127.0.0.1:8443\",\n",
            "        \"protocols\": [\n",
            "          \"h3\",\n",
            "          \"h2\",\n",
            "          \"h1\"\n",
            "        ],\n",
            "        \"redirect_https\": false\n",
            "      }},\n",
            "      {{\n",
            "        \"addr\": \"127.0.0.1:8080\",\n",
            "        \"protocols\": [\n",
            "          \"h1\"\n",
            "        ],\n",
            "        \"redirect_https\": true\n",
            "      }}\n",
            "    ],\n",
            "    \"tls\": {{\n",
            "      \"min_version\": \"1.3\",\n",
            "      \"pqc_hybrid\": true,\n",
            "      \"key_isolation\": \"in-process\",\n",
            "      \"ech\": false,\n",
            "      \"ech_rotate_interval_ms\": 3600000\n",
            "    }},\n",
            "    \"sandbox\": {{\n",
            "      \"landlock\": true,\n",
            "      \"seccomp\": \"strict\"\n",
            "    }},\n",
            "    \"timeouts\": {{\n",
            "      \"tls_handshake_ms\": 10000,\n",
            "      \"header_read_ms\": 10000,\n",
            "      \"idle_keepalive_ms\": 60000,\n",
            "      \"graceful_drain_ms\": 30000,\n",
            "      \"body_idle_timeout_ms\": 30000,\n",
            "      \"max_body_duration_ms\": 3600000,\n",
            "      \"min_body_rate_bps\": 1024,\n",
            "      \"upstream_connect_ms\": 10000,\n",
            "      \"upstream_response_ms\": 60000,\n",
            "      \"upstream_body_idle_ms\": 60000,\n",
            "      \"response_write_idle_ms\": 30000,\n",
            "      \"min_response_rate_bps\": 1024\n",
            "    }},\n",
            "    \"limits\": {{\n",
            "      \"max_header_bytes\": 16384,\n",
            "      \"max_body_bytes\": 10485760,\n",
            "      \"max_concurrent_streams\": 128,\n",
            "      \"max_h2_rst_stream_per_sec\": 50,\n",
            "      \"max_connections\": 16384,\n",
            "      \"max_connections_per_ip\": 128,\n",
            "      \"ipv6_prefix_conn_multiplier\": 4,\n",
            "      \"max_streamed_answers_per_ip\": 8,\n",
            "      \"max_streamed_answers_per_backend\": 4\n",
            "    }},\n",
            "    \"telemetry\": {{\n",
            "      \"metrics_path\": \"/metrics\",\n",
            "      \"service_name\": \"miraserve\",\n",
            "      \"redact_logs\": true\n",
            "    }}\n",
            "  }},\n",
            "  \"sites\": [\n",
            "    {{\n",
            "      \"hosts\": [\n",
            "        \"localhost\"\n",
            "      ],\n",
            "      \"security_headers\": \"strict\",\n",
            "      \"root\": \"{dev_www}\",\n",
            "      \"routes\": []\n",
            "    }}\n",
            "  ]\n",
            "}}\n"
        ),
        dev_www = dev_www,
    );

    for (label, args, expected) in [
        (
            "miraserve.kdl JSON",
            vec![
                "check",
                "--format",
                "json",
                "--dump-normalized",
                "examples/miraserve.kdl",
            ],
            expected_miraserve_json,
        ),
        (
            "miraserve.kdl text",
            vec!["check", "--dump-normalized", "examples/miraserve.kdl"],
            expected_miraserve_text,
        ),
        (
            "dev-local.kdl JSON",
            vec![
                "check",
                "--dev-tls",
                "--format",
                "json",
                "--dump-normalized",
                "examples/dev-local.kdl",
            ],
            expected_dev_local_json.as_str(),
        ),
        (
            "dev-local.kdl text",
            vec![
                "check",
                "--dev-tls",
                "--dump-normalized",
                "examples/dev-local.kdl",
            ],
            expected_dev_local_text.as_str(),
        ),
    ] {
        let out = Command::new(miraserve_bin())
            .current_dir(&repo_root)
            .args(&args)
            .output()?;
        assert!(
            out.status.success(),
            "{label} failed: stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            out.stderr.is_empty(),
            "{label} unexpected stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8(out.stdout)?;
        assert_eq!(
            stdout, expected,
            "{label} must be byte-identical to v0.1.2 normalized output"
        );
    }

    // Non-default `http "serve"` and `http "serve" credentials=#true` DO serialize explicitly,
    // while explicit `http "redirect"` (the default) stays omitted.
    let mut child = Command::new(miraserve_bin())
        .args(["check", "-", "--format", "json", "--dump-normalized"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(
            br#"
server {
    listen ":443"
    listen ":80" redirect-https=#true
    tls { cert "/etc/miraserve/c.pem"; key "/etc/miraserve/k.pem" }
}
site "default-redir.example.com" {
    http "redirect"
    root "/var/www/redir"
}
site "serve-only.example.com" {
    http "serve"
    root "/var/www/serve"
}
site "serve-creds.example.com" {
    http "serve" credentials=#true
    root "/var/www/creds"
}
"#,
        )?;
    }
    let out = child.wait_with_output()?;
    assert!(out.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let sites = parsed
        .get("config")
        .and_then(|c| c.get("sites"))
        .and_then(serde_json::Value::as_array)
        .ok_or("missing config.sites")?;
    assert_eq!(sites.len(), 3);
    assert!(sites.first().and_then(|s| s.get("http")).is_none());
    assert!(
        sites
            .first()
            .and_then(|s| s.get("http_credentials"))
            .is_none()
    );
    assert_eq!(
        sites
            .get(1)
            .and_then(|s| s.get("http"))
            .and_then(serde_json::Value::as_str),
        Some("serve")
    );
    assert!(
        sites
            .get(1)
            .and_then(|s| s.get("http_credentials"))
            .is_none()
    );
    assert_eq!(
        sites
            .get(2)
            .and_then(|s| s.get("http"))
            .and_then(serde_json::Value::as_str),
        Some("serve")
    );
    assert_eq!(
        sites
            .get(2)
            .and_then(|s| s.get("http_credentials"))
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );

    Ok(())
}

#[allow(clippy::too_many_lines)]
#[test]
fn check_notes_report_precompressed_sites_and_fs_bounded_sibling_scan() -> TestResult {
    let base = std::env::temp_dir().join(format!(
        "miraserve-check-precomp-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let root_off_l1 = base.join("off-l1");
    let root_off_l2 = base.join("off-l2");
    let root_off_l3 = base.join("off-l3");
    let root_off_standalone = base.join("off-standalone");
    let root_off_symlink = base.join("off-symlink");
    let root_outside = base.join("outside");
    let root_enabled = base.join("enabled");
    let root_bounded = base.join("bounded");

    for dir in [
        root_off_l1.clone(),
        root_off_l2.join("assets"),
        root_off_l3.join("a/b"),
        root_off_standalone.clone(),
        root_off_symlink.clone(),
        root_outside.clone(),
        root_enabled.clone(),
        root_bounded.clone(),
    ] {
        std::fs::create_dir_all(dir)?;
    }

    // Level 1 sibling pair (root/app.js + root/app.js.br)
    std::fs::write(root_off_l1.join("app.js"), b"base")?;
    std::fs::write(root_off_l1.join("app.js.br"), b"br")?;

    // Level 2 sibling pair (root/assets/app.css + root/assets/app.css.gz)
    std::fs::write(root_off_l2.join("assets/app.css"), b"base")?;
    std::fs::write(root_off_l2.join("assets/app.css.gz"), b"gz")?;

    // Level 3 only (must NOT be flagged: scan stops at top two directory levels)
    std::fs::write(root_off_l3.join("a/b/deep.js"), b"base")?;
    std::fs::write(root_off_l3.join("a/b/deep.js.zst"), b"zst")?;

    // Standalone .tar.gz without matching .tar (must NOT be flagged)
    std::fs::write(root_off_standalone.join("release.tar.gz"), b"tarball")?;

    // Symlinked directory and symlinked sibling file (must NEVER be followed)
    std::fs::write(root_outside.join("ext.js"), b"ext")?;
    std::fs::write(root_outside.join("ext.js.gz"), b"ext-gz")?;
    std::fs::write(root_off_symlink.join("sym.js"), b"base")?;
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&root_outside, root_off_symlink.join("linked_dir"))?;
        std::os::unix::fs::symlink(
            root_outside.join("ext.js.gz"),
            root_off_symlink.join("sym.js.gz"),
        )?;
    }

    // Enabled site with siblings (must appear in "enabled" note, NOT in "lookup is off" note)
    std::fs::write(root_enabled.join("main.js"), b"base")?;
    std::fs::write(root_enabled.join("main.js.br"), b"br")?;

    // Bounded scan: > 2,050 plain entries in root + subdir with a sibling after the entry cap.
    std::fs::create_dir_all(root_bounded.join("sub"))?;
    for i in 0..2_050_usize {
        std::fs::write(root_bounded.join(format!("f{i:04}.txt")), b"x")?;
    }
    std::fs::write(root_bounded.join("sub/late.js"), b"late")?;
    std::fs::write(root_bounded.join("sub/late.js.gz"), b"late-gz")?;

    let cfg_path = base.join("precomp.kdl");
    std::fs::write(
        &cfg_path,
        format!(
            r#"server {{
    listen ":443" protocols="h2,h1"
    sandbox {{ user "miraserve"; landlock #true; seccomp "strict" }}
}}
site "l1.example.test" {{
    root "{l1}"
}}
site "l2.example.test" {{
    root "{l2}"
}}
site "l3.example.test" {{
    root "{l3}"
}}
site "tarball.example.test" {{
    root "{tar}"
}}
site "symlink.example.test" {{
    root "{sym}"
}}
site "enabled.example.test" {{
    precompressed "br" "gz"
    root "{en}"
}}
site "route-only.example.test" {{
    root "{tar}"
    route "/static/*" {{
        static {{
            precompressed "zst"
        }}
    }}
}}
site "bounded.example.test" {{
    root "{bnd}"
}}
"#,
            l1 = root_off_l1.display(),
            l2 = root_off_l2.display(),
            l3 = root_off_l3.display(),
            tar = root_off_standalone.display(),
            sym = root_off_symlink.display(),
            en = root_enabled.display(),
            bnd = root_bounded.display(),
        ),
    )?;

    // 1. Plain `miraserve check` (NO `--fs`): prints enabled note ONLY, never touches filesystem.
    let no_fs = Command::new(miraserve_bin())
        .args(["check", "--dev-tls", "--format", "json"])
        .arg(&cfg_path)
        .output()?;
    assert!(
        no_fs.status.success(),
        "check without --fs failed: {}",
        String::from_utf8_lossy(&no_fs.stderr)
    );
    let no_fs_json: serde_json::Value = serde_json::from_slice(&no_fs.stdout)?;
    let no_fs_notes = no_fs_json
        .get("notes")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| format!("expected notes array: {no_fs_json}"))?;
    assert_eq!(
        no_fs_notes.len(),
        1,
        "expected only enabled note without --fs: {no_fs_notes:?}"
    );
    let enabled_note = no_fs_notes
        .first()
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    assert!(
        enabled_note.contains("enabled.example.test (br, gz)")
            && enabled_note.contains("route-only.example.test (/static/*: zst)"),
        "unexpected enabled note: {enabled_note}"
    );
    assert!(
        !enabled_note.contains("l1.example.test"),
        "off sites must not appear in enabled note: {enabled_note}"
    );

    // 2. `miraserve check --fs` (both text and JSON): reports l1 and l2 siblings, skips l3,
    //    standalone tarball, symlinks, enabled site, and stops at the 2,000-entry bound.
    let fs_text = Command::new(miraserve_bin())
        .args(["check", "--dev-tls", "--fs"])
        .arg(&cfg_path)
        .output()?;
    assert!(
        fs_text.status.success(),
        "check --fs text failed: {}",
        String::from_utf8_lossy(&fs_text.stderr)
    );
    let fs_stdout = String::from_utf8_lossy(&fs_text.stdout);
    assert!(
        fs_stdout.contains("note: sites that configure `precompressed`:"),
        "expected enabled note in text stdout:\n{fs_stdout}"
    );
    assert!(
        fs_stdout.contains("note: site 'l1.example.test': files with .br siblings exist under")
            && fs_stdout.contains("and `precompressed` is off for the site"),
        "expected l1 factual sibling note in stdout:\n{fs_stdout}"
    );
    assert!(
        fs_stdout.contains("note: site 'l2.example.test': files with .gz siblings exist under"),
        "expected l2 factual sibling note in stdout:\n{fs_stdout}"
    );
    assert!(
        !fs_stdout.contains("to serve them"),
        "sibling notes must be purely factual without migration advice:\n{fs_stdout}"
    );
    for absent in [
        "site 'l3.example.test': files with",
        "site 'tarball.example.test': files with",
        "site 'symlink.example.test': files with",
        "site 'enabled.example.test': files with",
        "site 'bounded.example.test': files with",
    ] {
        assert!(
            !fs_stdout.contains(absent),
            "unexpected note `{absent}` in stdout:\n{fs_stdout}"
        );
    }

    let fs_json = Command::new(miraserve_bin())
        .args([
            "check",
            "--dev-tls",
            "--fs",
            "--format",
            "json",
            "--dump-normalized",
        ])
        .arg(&cfg_path)
        .output()?;
    assert!(fs_json.status.success());
    let report: serde_json::Value = serde_json::from_slice(&fs_json.stdout)?;
    let notes = report
        .get("notes")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| format!("expected notes in JSON: {report}"))?;
    assert!(notes.iter().any(|n| {
        n.as_str().is_some_and(|s| {
            s.contains("site 'l1.example.test': files with .br siblings exist under")
                && s.contains("`precompressed` is off for the site")
        })
    }));
    assert!(notes.iter().any(|n| {
        n.as_str().is_some_and(|s| {
            s.contains("site 'l2.example.test': files with .gz siblings exist under")
                && s.contains("`precompressed` is off for the site")
        })
    }));

    // Normalized dump omits `precompressed` when off and serializes enabled encodings in order.
    let sites = report
        .get("config")
        .and_then(|c| c.get("sites"))
        .and_then(serde_json::Value::as_array)
        .ok_or("missing config.sites")?;
    assert!(sites.first().and_then(|s| s.get("precompressed")).is_none());
    assert_eq!(
        sites.get(5).and_then(|s| s.get("precompressed")),
        Some(&serde_json::json!(["br", "gz"]))
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

#[test]
fn check_dump_normalized_omits_empty_header_status_and_emits_explicit_status() -> TestResult {
    let mut child = Command::new(miraserve_bin())
        .args(["check", "--format", "json", "--dump-normalized", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(
            br#"server {
    listen ":443"
    tls { cert "/etc/miraserve/c.pem"; key "/etc/miraserve/k.pem" }
}
site "hdr-norm.example.com" {
    root "/var/www/hdr"
    headers {
        set "cache-control" "no-cache"
    }
    route "/assets/*" {
        static
        headers {
            set "cache-control" "public, max-age=31536000, immutable" status="200 206 304"
            add "x-class" "1" status="2xx"
        }
    }
}
"#,
        )?;
    }
    let out = child.wait_with_output()?;
    assert!(
        out.status.success(),
        "check failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let site = parsed
        .get("config")
        .and_then(|c| c.get("sites"))
        .and_then(serde_json::Value::as_array)
        .and_then(|a| a.first())
        .ok_or("missing site[0]")?;
    let site_rule = site
        .get("headers")
        .and_then(serde_json::Value::as_array)
        .and_then(|a| a.first())
        .ok_or("missing site header rule")?;
    assert!(
        site_rule.get("status").is_none(),
        "unconditional header rule must omit status in normalized dump: {site_rule}"
    );
    let route_headers = site
        .get("routes")
        .and_then(serde_json::Value::as_array)
        .and_then(|a| a.first())
        .and_then(|r| r.get("headers"))
        .and_then(serde_json::Value::as_array)
        .ok_or("missing route headers")?;
    assert_eq!(
        route_headers.first().and_then(|r| r.get("status")),
        Some(&serde_json::json!(["200", "206", "304"]))
    );
    assert_eq!(
        route_headers.get(1).and_then(|r| r.get("status")),
        Some(&serde_json::json!(["2xx"]))
    );
    Ok(())
}

#[test]
fn check_dump_normalized_distinguishes_explicit_route_precompressed_override() -> TestResult {
    let mut child = Command::new(miraserve_bin())
        .args(["check", "--format", "json", "--dump-normalized", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(
            br#"server {
    listen ":443"
    tls { cert "/etc/miraserve/c.pem"; key "/etc/miraserve/k.pem" }
}
site "all-with-overrides.example.test" {
    precompressed "all"
    root "/var/www/all"
    route "/inherit/*" {
        static
    }
    route "/override-off/*" {
        static {
            precompressed "off"
        }
    }
    route "/override-br/*" {
        static {
            precompressed "br"
        }
    }
}
site "default-with-explicit-off.example.test" {
    root "/var/www/off"
    route "/inherit/*" {
        static
    }
    route "/explicit-off/*" {
        static {
            precompressed "off"
        }
    }
}
"#,
        )?;
    }
    let out = child.wait_with_output()?;
    assert!(
        out.status.success(),
        "check failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let sites = parsed
        .get("config")
        .and_then(|c| c.get("sites"))
        .and_then(serde_json::Value::as_array)
        .ok_or("missing config.sites")?;

    let s0_routes = sites
        .first()
        .and_then(|s| s.get("routes"))
        .and_then(serde_json::Value::as_array)
        .ok_or("missing site[0].routes")?;
    let inherit = s0_routes
        .first()
        .and_then(|r| r.get("handler"))
        .and_then(|h| h.get("config"))
        .ok_or("missing route[0]")?;
    let override_off = s0_routes
        .get(1)
        .and_then(|r| r.get("handler"))
        .and_then(|h| h.get("config"))
        .ok_or("missing route[1]")?;
    let override_br = s0_routes
        .get(2)
        .and_then(|r| r.get("handler"))
        .and_then(|h| h.get("config"))
        .ok_or("missing route[2]")?;
    assert!(inherit.get("precompressed").is_none());
    assert_eq!(
        override_off.get("precompressed"),
        Some(&serde_json::json!([]))
    );
    assert_eq!(
        override_br.get("precompressed"),
        Some(&serde_json::json!(["br"]))
    );
    assert_ne!(
        inherit, override_off,
        "inheriting route and explicit `precompressed \"off\"` route must not dump identically"
    );

    let s1_routes = sites
        .get(1)
        .and_then(|s| s.get("routes"))
        .and_then(serde_json::Value::as_array)
        .ok_or("missing site[1].routes")?;
    assert!(
        s1_routes
            .first()
            .and_then(|r| r.get("handler"))
            .and_then(|h| h.get("config"))
            .and_then(|st| st.get("precompressed"))
            .is_none()
    );
    assert_eq!(
        s1_routes
            .get(1)
            .and_then(|r| r.get("handler"))
            .and_then(|h| h.get("config"))
            .and_then(|st| st.get("precompressed")),
        Some(&serde_json::json!([]))
    );
    Ok(())
}

#[test]
fn check_enabled_note_groups_aliases_once_per_site_and_bounds_output() -> TestResult {
    use std::fmt::Write as _;
    let mut kdl = String::from(
        "server {\n    listen \":443\"\n    tls { cert \"/etc/miraserve/c.pem\"; key \"/etc/miraserve/k.pem\" }\n}\n",
    );
    // One site with 10 host aliases and 12 route overrides: must appear ONCE with grouped aliases
    // and capped route list.
    kdl.push_str("site \"primary.example.test\"");
    for i in 1..=10 {
        let _ = write!(kdl, " \"alias-{i}.example.test\"");
    }
    kdl.push_str(" {\n    root \"/var/www/primary\"\n");
    for i in 0..12 {
        let _ = write!(
            kdl,
            "    route \"/r{i}/*\" {{\n        static {{ precompressed \"br\" }}\n    }}\n"
        );
    }
    kdl.push_str("}\n");
    // Plus 40 additional enabled sites to exercise the site-count / byte bound.
    for i in 0..40 {
        let _ = write!(
            kdl,
            "site \"extra-{i}.example.test\" {{\n    precompressed \"gz\"\n    root \"/var/www/extra-{i}\"\n}}\n"
        );
    }

    let mut child = Command::new(miraserve_bin())
        .args(["check", "--format", "json", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(kdl.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    assert!(
        out.status.success(),
        "check failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let notes = parsed
        .get("notes")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing notes")?;
    let enabled_note = notes
        .iter()
        .filter_map(serde_json::Value::as_str)
        .find(|n| n.starts_with("sites that configure `precompressed`:"))
        .ok_or("missing enabled note")?;

    assert_eq!(
        enabled_note.matches("/r0/*: br").count(),
        1,
        "route summary must NOT be duplicated per host alias: {enabled_note}"
    );
    assert!(
        enabled_note.contains("primary.example.test [aliases: alias-1.example.test, alias-2.example.test, alias-3.example.test, +7 more]"),
        "expected grouped + bounded aliases in note: {enabled_note}"
    );
    assert!(
        enabled_note.contains("+4 more"),
        "expected bounded route summary in note: {enabled_note}"
    );
    assert!(
        enabled_note.contains("more site(s)"),
        "expected bounded total sites in note: {enabled_note}"
    );
    assert!(
        enabled_note.len() <= 2_048,
        "enabled note must stay strictly within 2,048-byte cap, got {} bytes",
        enabled_note.len()
    );
    Ok(())
}

/// Pins Review round 2 P2 #5: the enabled-sites note NEVER exceeds 2,048 bytes, including the
/// prefix, an over-long first entry (3,000-byte route pattern), and the omission suffix.
#[allow(clippy::too_many_lines)]
#[test]
fn check_enabled_note_enforces_2048_byte_cap_on_overlong_route_pattern() -> TestResult {
    let long_pattern = format!("/{}", "a".repeat(3_000));
    let utf8_pattern = format!("/{}", "é".repeat(1_500));

    for (label, kdl, expect_suffix) in [
        (
            "single-site-3000b-ascii",
            format!(
                r#"server {{
    listen ":443"
    tls {{ cert "/etc/miraserve/c.pem"; key "/etc/miraserve/k.pem" }}
}}
site "huge.example.test" {{
    root "/var/www/huge"
    route "{long_pattern}" {{
        static {{ precompressed "br" }}
    }}
}}
"#
            ),
            false,
        ),
        (
            "multi-site-3000b-with-omission-suffix",
            format!(
                r#"server {{
    listen ":443"
    tls {{ cert "/etc/miraserve/c.pem"; key "/etc/miraserve/k.pem" }}
}}
site "huge.example.test" {{
    root "/var/www/huge"
    route "{long_pattern}" {{
        static {{ precompressed "br" }}
    }}
}}
site "second.example.test" {{
    precompressed "gz"
    root "/var/www/second"
}}
site "third.example.test" {{
    precompressed "zst"
    root "/var/www/third"
}}
"#
            ),
            true,
        ),
        (
            "single-site-3000b-utf8",
            format!(
                r#"server {{
    listen ":443"
    tls {{ cert "/etc/miraserve/c.pem"; key "/etc/miraserve/k.pem" }}
}}
site "utf8.example.test" {{
    root "/var/www/utf8"
    route "{utf8_pattern}" {{
        static {{ precompressed "br" }}
    }}
}}
"#
            ),
            false,
        ),
    ] {
        let mut child = Command::new(miraserve_bin())
            .args(["check", "--format", "json", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(kdl.as_bytes())?;
        }
        let out = child.wait_with_output()?;
        assert!(
            out.status.success(),
            "{label}: check failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let parsed: serde_json::Value = serde_json::from_slice(&out.stdout)?;
        let notes = parsed
            .get("notes")
            .and_then(serde_json::Value::as_array)
            .ok_or("missing notes")?;
        let enabled_note = notes
            .iter()
            .filter_map(serde_json::Value::as_str)
            .find(|n| n.starts_with("sites that configure `precompressed`:"))
            .ok_or("missing enabled note")?;
        assert!(
            enabled_note.len() <= 2_048,
            "{label}: enabled note exceeded 2,048-byte cap ({} bytes)",
            enabled_note.len()
        );
        assert!(
            enabled_note.contains("..."),
            "{label}: over-long first entry should be truncated with ellipsis"
        );
        if expect_suffix {
            assert!(
                enabled_note.ends_with(", +2 more site(s)"),
                "{label}: expected omission suffix at end of capped note, got tail: {:?}",
                enabled_note.get(enabled_note.len().saturating_sub(40)..)
            );
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
#[test]
fn check_fs_sibling_scan_effective_policy_intermediate_symlink_and_site_budget() -> TestResult {
    let base = std::env::temp_dir().join(format!(
        "miraserve-check-precomp-r1-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let root_off_route_on = base.join("site-off-route-on");
    let root_on_route_off = base.join("site-on-route-off");
    let root_on_route_off_top_only = base.join("site-on-route-off-top-only");
    let root_ambiguous = base.join("ambiguous-rewrite");
    let root_budget_a = base.join("budget-a");
    let root_budget_b = base.join("budget-b");
    let real_release = base.join("real-release");
    let link_parent = base.join("current");

    for dir in [
        root_off_route_on.join("assets"),
        root_on_route_off.join("assets"),
        root_on_route_off_top_only.join("assets"),
        root_ambiguous.join("assets"),
        root_budget_a.clone(),
        root_budget_b.join("sub"),
        real_release.join("public"),
    ] {
        std::fs::create_dir_all(dir)?;
    }

    // 1. Site OFF, `/assets/*` inherits site root with explicit `precompressed "all"`, siblings
    //    ONLY under `assets/`: already served -> MUST NOT emit a note.
    std::fs::write(root_off_route_on.join("assets/app.js"), b"js")?;
    std::fs::write(root_off_route_on.join("assets/app.js.br"), b"br")?;

    // 2. Site ON (`"all"`), `/assets/*` inherits site root with explicit `precompressed "off"`,
    //    siblings at BOTH top-level (`index.html.br`, served) and `assets/app.js.br` (NOT served):
    //    MUST emit a note for `.br`.
    std::fs::write(root_on_route_off.join("index.html"), b"html")?;
    std::fs::write(root_on_route_off.join("index.html.gz"), b"gz")?;
    std::fs::write(root_on_route_off.join("assets/app.js"), b"js")?;
    std::fs::write(root_on_route_off.join("assets/app.js.br"), b"br")?;

    // 3. Site ON (`"all"`), `/assets/*` inherits site root with explicit `precompressed "off"`,
    //    siblings ONLY at top-level (NOT under `assets/`): top-level IS served -> NO note!
    std::fs::write(root_on_route_off_top_only.join("index.html"), b"html")?;
    std::fs::write(root_on_route_off_top_only.join("index.html.gz"), b"gz")?;

    // 4. Site with internal path-rewriting `rewrite` rule + mixed on/off static policies:
    //    effective policy is indeterminate -> NO note!
    std::fs::write(root_ambiguous.join("index.html"), b"html")?;
    std::fs::write(root_ambiguous.join("index.html.br"), b"br")?;

    // 5. Single site with TWO roots sharing the 2,000-entry total site budget:
    //    root_budget_a consumes 2,000 entries with plain files; root_budget_b has siblings that
    //    must NOT be scanned once the site's 2,000-entry budget is exhausted.
    for i in 0..2_000_usize {
        std::fs::write(root_budget_a.join(format!("p{i:04}.txt")), b"x")?;
    }
    std::fs::write(root_budget_b.join("sub/late.js"), b"js")?;
    std::fs::write(root_budget_b.join("sub/late.js.gz"), b"gz")?;

    // 6. Intermediate symlink component in configured root (`current/public` where `current` -> `real-release`):
    //    component-by-component no-follow open refuses `current` -> NO note!
    std::fs::write(real_release.join("public/app.js"), b"js")?;
    std::fs::write(real_release.join("public/app.js.br"), b"br")?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real_release, &link_parent)?;
    #[cfg(not(unix))]
    std::fs::create_dir_all(link_parent.join("public"))?;

    let link_root = link_parent.join("public");
    let cfg_path = base.join("r1.kdl");
    let p = |path: &std::path::Path| path.to_string_lossy().replace('\\', "/");
    std::fs::write(
        &cfg_path,
        format!(
            r#"server {{
    listen ":443" protocols="h2,h1"
    sandbox {{ user "miraserve"; landlock #true; seccomp "strict" }}
}}
site "off-route-on.example.test" {{
    root "{r1}"
    route "/assets/*" {{
        static {{
            precompressed "all"
        }}
    }}
}}
site "on-route-off.example.test" {{
    precompressed "all"
    root "{r2}"
    route "/assets/*" {{
        static {{
            precompressed "off"
        }}
    }}
}}
site "on-route-off-top-only.example.test" {{
    precompressed "all"
    root "{r3}"
    route "/assets/*" {{
        static {{
            precompressed "off"
        }}
    }}
}}
site "ambiguous.example.test" {{
    root "{r4}"
    rewrite {{
        rule "^/go/(.*)$" to="/assets/$1"
    }}
    route "/assets/*" {{
        static {{
            precompressed "all"
        }}
    }}
}}
site "site-budget.example.test" {{
    root "{r5a}"
    route "/sub/*" {{
        root "{r5b}"
        static
    }}
}}
site "inter-symlink.example.test" {{
    root "{r6}"
}}
"#,
            r1 = p(&root_off_route_on),
            r2 = p(&root_on_route_off),
            r3 = p(&root_on_route_off_top_only),
            r4 = p(&root_ambiguous),
            r5a = p(&root_budget_a),
            r5b = p(&root_budget_b),
            r6 = p(&link_root),
        ),
    )?;

    let out = Command::new(miraserve_bin())
        .args(["check", "--dev-tls", "--fs", "--format", "json"])
        .arg(&cfg_path)
        .output()?;
    assert!(
        out.status.success(),
        "check --fs failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let notes: Vec<&str> = report
        .get("notes")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing notes")?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();

    // Only `on-route-off.example.test` should produce a sibling note, and ONLY for `.br` at
    // `route '/assets/*'` (NOT `.gz` from the top-level served with site `"all"`!).
    assert!(
        notes.iter().any(|n| {
            n.contains("site 'on-route-off.example.test': files with .br siblings exist under")
                && n.contains("and `precompressed` is off for route '/assets/*'")
                && !n.contains(".gz")
                && !n.contains("to serve them")
        }),
        "expected factual `.br`-only note for on-route-off.example.test, got: {notes:?}"
    );
    for silent_site in [
        "off-route-on.example.test",
        "on-route-off-top-only.example.test",
        "ambiguous.example.test",
        "site-budget.example.test",
        "inter-symlink.example.test",
    ] {
        assert!(
            !notes
                .iter()
                .any(|n| n.contains(&format!("site '{silent_site}': files with"))),
            "expected NO sibling note for {silent_site}, got: {notes:?}"
        );
    }

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Pins Review round 2 P2 #3 (all three Codex cases + non-static route non-suppression):
/// 1. `route "/*" { try-files "=410"; }` over `version.json{,.br,.gz}`: states ONLY the fact for
///    the site block, never giving advice claiming enabling `precompressed` would serve the sibling.
/// 2. `route "/*" { static { compression #false; } }` (and exact `/version.json`) over
///    `version.json{,.br,.gz}`: emits NO note because `compression` is `#false`.
/// 3. Site `precompressed "all"` + `route "/version.json" { static { precompressed "off"; } }` +
///    unrelated `route "/app/*" { try-files "{path}" "=404"; }`: still reports `route '/version.json'`
///    without being suppressed by the `try-files` route, and ignores top-level `.zst`.
/// 4. Fixed status (`respond`), `redirect`, `reverse-proxy`, and `fastcgi-pass` routes neither
///    trigger inference nor suppress the site's own root note.
#[allow(clippy::too_many_lines)]
#[test]
fn check_fs_sibling_note_is_factual_and_fixes_codex_three_cases() -> TestResult {
    let base = std::env::temp_dir().join(format!(
        "miraserve-check-precomp-r2-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let root_case1 = base.join("case1-tryfiles-410");
    let root_case2_all = base.join("case2-comp-false-all");
    let root_case2_exact = base.join("case2-comp-false-exact");
    let root_case3 = base.join("case3-site-on-route-off-plus-tryfiles");
    let root_case4 = base.join("case4-non-static-routes");

    for dir in [
        &root_case1,
        &root_case2_all,
        &root_case2_exact,
        &root_case3,
        &root_case4,
    ] {
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join("version.json"), br#"{"v":1}"#)?;
        std::fs::write(dir.join("version.json.br"), b"br")?;
        std::fs::write(dir.join("version.json.gz"), b"gz")?;
    }
    // Extra top-level sibling in Case 3 that belongs to the `precompressed "all"` site (must NOT appear).
    std::fs::write(root_case3.join("index.html"), b"<html>hi</html>")?;
    std::fs::write(root_case3.join("index.html.zst"), b"zst")?;

    let p = |path: &std::path::Path| path.to_string_lossy().replace('\\', "/");
    let cfg_path = base.join("r2.kdl");
    std::fs::write(
        &cfg_path,
        format!(
            r#"server {{
    listen ":443" protocols="h2,h1"
    sandbox {{ user "miraserve"; landlock #true; seccomp "strict" }}
}}
site "case1-try410.example.test" {{
    root "{c1}"
    route "/*" {{
        try-files "=410"
    }}
}}
site "case2-comp-all.example.test" {{
    root "{c2a}"
    route "/*" {{
        static {{
            compression #false
        }}
    }}
}}
site "case2-comp-exact.example.test" {{
    root "{c2e}"
    route "/version.json" {{
        static {{
            compression #false
        }}
    }}
}}
site "case3-site-on.example.test" {{
    precompressed "all"
    root "{c3}"
    route "/version.json" {{
        static {{
            precompressed "off"
        }}
    }}
    route "/app/*" {{
        try-files "{{path}}" "=404"
    }}
}}
site "case4-other-handlers.example.test" {{
    root "{c4}"
    route "/gone" {{
        respond 410
    }}
    route "/old/*" {{
        redirect "/new" status=301
    }}
    route "/api/*" {{
        reverse-proxy {{
            upstream "http://127.0.0.1:8080"
        }}
    }}
    route "*.php" {{
        fastcgi-pass "tcp://127.0.0.1:9000"
    }}
}}
"#,
            c1 = p(&root_case1),
            c2a = p(&root_case2_all),
            c2e = p(&root_case2_exact),
            c3 = p(&root_case3),
            c4 = p(&root_case4),
        ),
    )?;

    let out = Command::new(miraserve_bin())
        .args(["check", "--dev-tls", "--fs", "--format", "json"])
        .arg(&cfg_path)
        .output()?;
    assert!(
        out.status.success(),
        "check --fs failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let notes: Vec<&str> = report
        .get("notes")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing notes")?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();

    // No note may ever give migration advice claiming enabling `precompressed` would serve siblings.
    for note in &notes {
        assert!(
            !note.contains("to serve them")
                && !note.contains("add `precompressed")
                && !note.contains("remove the route"),
            "check --fs note must state a plain fact with no request-dependent advice: {note}"
        );
    }

    // Case 1: factual note for the site block (not suppressed by `try-files`, no advice).
    assert!(
        notes.iter().any(|n| {
            n.contains("site 'case1-try410.example.test': files with .br/.gz siblings exist under")
                && n.contains("and `precompressed` is off for the site")
        }),
        "Case 1: expected factual site note without advice, got: {notes:?}"
    );

    // Case 2 (both catch-all and exact `static { compression #false; }`): NO note emitted.
    for silent in [
        "case2-comp-all.example.test",
        "case2-comp-exact.example.test",
    ] {
        assert!(
            !notes
                .iter()
                .any(|n| n.contains(&format!("site '{silent}': files with"))),
            "Case 2: expected NO note when matching static route has compression #false ({silent}), got: {notes:?}"
        );
    }

    // Case 3: exact route's explicit `off` IS reported despite unrelated `/app/*` `try-files`,
    // and top-level `.zst` (handled by site `precompressed "all"`) is NOT reported.
    assert!(
        notes.iter().any(|n| {
            n.contains("site 'case3-site-on.example.test': files with .br/.gz siblings exist under")
                && n.contains("and `precompressed` is off for route '/version.json'")
                && !n.contains(".zst")
        }),
        "Case 3: expected factual route note for /version.json, got: {notes:?}"
    );

    // Case 4: respond / redirect / reverse-proxy / fastcgi-pass do not suppress the site note.
    assert!(
        notes.iter().any(|n| {
            n.contains(
                "site 'case4-other-handlers.example.test': files with .br/.gz siblings exist under",
            ) && n.contains("and `precompressed` is off for the site")
        }),
        "Case 4: non-static handlers must not suppress the site note, got: {notes:?}"
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// The enabled-sites note names only locations that can probe a sibling: a `static` route with
/// compression off never does, whatever its `precompressed` policy says.
#[test]
fn check_enabled_note_ignores_routes_with_compression_off() -> TestResult {
    let kdl = "server {\n    listen \":443\"\n    tls { cert \"/etc/miraserve/c.pem\"; key \"/etc/miraserve/k.pem\" }\n}\n\
        site \"quiet.example.test\" {\n    root \"/var/www/quiet\"\n    route \"/raw/*\" {\n        static { compression #false; precompressed \"br\" }\n    }\n}\n\
        site \"mixed.example.test\" {\n    root \"/var/www/mixed\"\n    route \"/raw/*\" {\n        static { compression #false; precompressed \"br\" }\n    }\n    route \"/assets/*\" {\n        static { precompressed \"gz\" }\n    }\n}\n";
    let mut child = Command::new(miraserve_bin())
        .args(["check", "--format", "json", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(kdl.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    assert!(
        out.status.success(),
        "check failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let notes = parsed
        .get("notes")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing notes")?;
    let enabled_note = notes
        .iter()
        .filter_map(serde_json::Value::as_str)
        .find(|n| n.starts_with("sites that configure `precompressed`:"))
        .ok_or("missing enabled note")?;
    assert!(
        !enabled_note.contains("quiet.example.test"),
        "a site whose only policy sits on a compression-off route is not enabled: {enabled_note}"
    );
    assert!(
        enabled_note.contains("mixed.example.test (/assets/*: gz)"),
        "only the route that can probe is listed: {enabled_note}"
    );
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn check_lists_sites_with_file_cache_as_informational_note_and_passes_strict() -> TestResult {
    let kdl_with_cache = r#"
server {
    listen ":443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }
    limits {
        file-cache-bytes "32MiB"
    }
}
site "cached.example.com" {
    root "/var/www/cached"
    file-cache "1s"
}
site "fast.example.com" {
    root "/var/www/fast"
    file-cache "250ms"
}
site "plain.example.com" {
    root "/var/www/plain"
}
"#;

    // Text mode with --strict: succeeds (informational note is NOT a warning) and lists sites + windows.
    let mut child = Command::new(miraserve_bin())
        .args(["check", "--strict", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(kdl_with_cache.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    assert!(
        out.status.success(),
        "file-cache note must not fail --strict, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("note: file-cache enabled"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("'cached.example.com' (1s)"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("'fast.example.com' (250ms)"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("32MiB"), "stdout: {stdout}");
    assert!(!stdout.contains("plain.example.com"), "stdout: {stdout}");

    // JSON mode with --strict: reports notes array, zero warnings.
    let mut child = Command::new(miraserve_bin())
        .args(["check", "--strict", "--format", "json", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(kdl_with_cache.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    assert_eq!(
        report.get("valid").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        report
            .get("warnings")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    let notes = report
        .get("notes")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing notes array in JSON check report")?;
    assert_eq!(notes.len(), 1);
    let note_str = notes
        .first()
        .and_then(serde_json::Value::as_str)
        .ok_or("note is not a string")?;
    assert!(note_str.contains("'cached.example.com' (1s)"));
    assert!(note_str.contains("'fast.example.com' (250ms)"));

    // Globally disabled with limits.file-cache-bytes "0": note states disabled globally.
    let kdl_global_zero = r#"
server {
    listen ":443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }
    limits { file-cache-bytes "0" }
}
site "cached.example.com" {
    root "/var/www/cached"
    file-cache "1s"
}
"#;
    let mut child = Command::new(miraserve_bin())
        .args(["check", "--strict", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(kdl_global_zero.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("disabled globally") && stdout.contains("'cached.example.com' (1s)"),
        "stdout: {stdout}"
    );
    Ok(())
}

const EXPECTED_ALLOW_OPENAT2_REPLACEMENT: &str = concat!(
    "# RestrictSUIDSGID omitted (--allow-openat2): systemd's filter answers ENOSYS to every\n",
    "# openat2(), disabling whole-path lookups, file-cache admission, and inline worker lookups.\n",
    "# Replaced in-process by MiraServe's seccomp-bpf set-ID policy (active under seccomp\n",
    "# \"strict\" and \"standard\", NOT under seccomp \"off\" or --no-sandbox), which rejects\n",
    "# S_ISUID/S_ISGID with EPERM on chmod/fchmod/fchmodat/fchmodat2/mkdir/mkdirat/mknod/\n",
    "# mknodat/creat/open/openat/mq_open and denies io_uring_{setup,enter,register} in both\n",
    "# modes. Note: on systemd 258+ with DefaultRestrictSUIDSGID=yes in systemd-system.conf,\n",
    "# omitting this line still inherits yes (add a drop-in with RestrictSUIDSGID=no).\n",
    "# Residual (why this is opt-in): seccomp cannot read openat2()'s struct open_how, so a\n",
    "# compromised worker can create a service-owned set-ID inode (group: effective group, or\n",
    "# the parent's on a set-GID parent) via openat2 with O_CREAT or O_TMPFILE where its\n",
    "# effective filesystem policy permits it, and chmod service-owned dirs to be searchable\n",
    "# (Landlock does not mediate chmod). With enforcing Landlock, named regular-file creation\n",
    "# (MakeReg) is limited to: --acme-dir (packaged /var/lib/miraserve/acme under /var/lib/\n",
    "# miraserve, both miraserve:miraserve), ai-publish.storage if set (packaged /var/lib/\n",
    "# miraserve/releases, miraserve:miraserve), and any rotating-log parent if --log-max-bytes\n",
    "# > 0 (packaged /var/log/miraserve, miraserve:miraserve). Unnamed O_TMPFILE creation is\n",
    "# checked by Landlock as a file open (WriteFile, not MakeReg), so configured socket-tree\n",
    "# dirs can also admit an unnamed inode where the effective mount is writable (a tree\n",
    "# outside this unit's writable paths is read-only; one under /var/log/miraserve is not)\n",
    "# and the filesystem and Unix permissions allow. Naming it (linkat) is a separate\n",
    "# operation that needs MakeReg at the destination (and Refer cross-dir, or fails EXDEV on\n",
    "# ABI v1): a socket-tree grant ALONE gives no such right, but the grants of one Landlock\n",
    "# ruleset add up, so a socket-tree beneath a writable grant (e.g. a rotating-log parent)\n",
    "# can be named in. Without Landlock, whatever the unit and permissions leave writable is\n",
    "# reachable. NoNewPrivileges=yes and Strict's exec denial protect the worker only; modes\n",
    "# on service-owned dirs (0700/0750) do NOT bound a compromised worker. No CAP_CHOWN (never\n",
    "# root-owned); ordinary unprivileged writes can clear set-ID bits. If a usable marked\n",
    "# executable survives, another local process that EXECUTES it may gain the file owner's\n",
    "# UID (from S_ISUID) and/or its group (from S_ISGID with group-execute) independently,\n",
    "# and so reach files accessible to that UID or GID (including worker-owned certs/keys and\n",
    "# ACME account material; split miraserve-keyd isolates only its own signing keys, disables\n",
    "# built-in ACME issuance, and leaves existing worker-owned ACME account material in\n",
    "# place). A root-controlled, non-searchable ancestor is a pathname control only (it does\n",
    "# not stop a process handed an open fd via a Unix socket); what suppresses the credential\n",
    "# change is nosuid on every mount through which the inode can be executed.\n",
);

/// Golden test for `miraserve service generate --target systemd --allow-openat2`:
/// - Default `--target systemd` stays byte-for-byte identical to `packaging/systemd/miraserve.service`
///   (covered by `packaged_service_units_and_container_config_stay_in_sync` too).
/// - `--allow-openat2` replaces ONLY `RestrictSUIDSGID=yes` with the exact replacement/residual
///   comment block and leaves every other line identical.
/// - `--target systemd-keyd --allow-openat2` still retains `RestrictSUIDSGID=yes` on keyd.
#[test]
fn service_generate_allow_openat2_golden_and_combinations() -> TestResult {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let default_packaged =
        std::fs::read_to_string(root.join("packaging/systemd/miraserve.service"))?
            .replace("\r\n", "\n");
    assert!(default_packaged.contains("RestrictSUIDSGID=yes\n"));

    let expected_allow_openat2 =
        default_packaged.replace("RestrictSUIDSGID=yes\n", EXPECTED_ALLOW_OPENAT2_REPLACEMENT);

    let out = Command::new(miraserve_bin())
        .args([
            "service",
            "generate",
            "--target",
            "systemd",
            "--allow-openat2",
        ])
        .output()?;
    assert!(
        out.status.success(),
        "service generate --allow-openat2 failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let generated = String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n");
    assert_eq!(
        generated, expected_allow_openat2,
        "`service generate --target systemd --allow-openat2` drifted from golden"
    );
    assert!(
        !generated
            .lines()
            .any(|line| line.trim() == "RestrictSUIDSGID=yes"),
        "unit generated with --allow-openat2 must not set RestrictSUIDSGID=yes"
    );

    // Combinations with --no-wasm, --split-keyd, --home-docroots work cleanly.
    let combo = Command::new(miraserve_bin())
        .args([
            "service",
            "generate",
            "--target",
            "systemd",
            "--allow-openat2",
            "--no-wasm",
            "--split-keyd",
            "--home-docroots",
        ])
        .output()?;
    assert!(combo.status.success());
    let combo_unit = String::from_utf8_lossy(&combo.stdout);
    assert!(
        !combo_unit
            .lines()
            .any(|line| line.trim() == "RestrictSUIDSGID=yes")
    );
    assert!(combo_unit.contains("MemoryDenyWriteExecute=yes"));
    assert!(combo_unit.contains("ProtectHome=read-only"));
    assert!(combo_unit.contains("Wants=network-online.target miraserve-keyd.service"));

    // `miraserve-keyd` never serves static files and MUST keep RestrictSUIDSGID=yes even if
    // `--allow-openat2` is passed.
    let keyd = Command::new(miraserve_bin())
        .args([
            "service",
            "generate",
            "--target",
            "systemd-keyd",
            "--allow-openat2",
        ])
        .output()?;
    assert!(keyd.status.success());
    assert!(
        String::from_utf8_lossy(&keyd.stdout).contains("RestrictSUIDSGID=yes"),
        "systemd-keyd must always retain RestrictSUIDSGID=yes"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn compile_openat2_errno_filter(
    errno_val: u32,
) -> Result<seccompiler::BpfProgram, Box<dyn std::error::Error>> {
    use seccompiler::{SeccompAction, SeccompFilter, TargetArch};
    use std::collections::BTreeMap;

    const SYS_OPENAT2: i64 = 437;
    let arch = TargetArch::try_from(std::env::consts::ARCH)?;
    let mut rules = BTreeMap::new();
    rules.insert(SYS_OPENAT2, Vec::new());
    if arch == TargetArch::x86_64 {
        rules.insert(SYS_OPENAT2 | 0x4000_0000, Vec::new());
    }
    Ok(SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(errno_val),
        arch,
    )?
    .try_into()?)
}

#[cfg(target_os = "linux")]
fn run_check_stdin_cmd(kdl: &str, extra: &[&str]) -> Result<std::process::Output, String> {
    let mut child = Command::new(miraserve_bin())
        .arg("check")
        .args(extra)
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(kdl.as_bytes()).map_err(|e| e.to_string())?;
    }
    child.wait_with_output().map_err(|e| e.to_string())
}

#[cfg(target_os = "linux")]
fn run_miraserve_until_ready_and_read_log(
    cfg_path: &std::path::Path,
    pid_path: &std::path::Path,
    log_path: &std::path::Path,
    extra_args: &[&str],
) -> Result<String, String> {
    let mut child = Command::new(miraserve_bin())
        .arg("run")
        .arg("--dev-tls")
        .args(extra_args)
        .arg(cfg_path)
        .arg("--pid-file")
        .arg(pid_path)
        .arg("--log-file")
        .arg(log_path)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn miraserve run: {e}"))?;
    let expected_pid = child.id().to_string();
    let mut ready = false;
    for _ in 0..100 {
        if let Ok(log_text) = std::fs::read_to_string(log_path)
            && log_text.contains("MiraServe listening")
        {
            ready = true;
            break;
        }
        if child.try_wait().ok().flatten().is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = Command::new("kill").args(["-TERM", &expected_pid]).status();
    let _ = child.wait();
    let log_text = std::fs::read_to_string(log_path).unwrap_or_default();
    if !ready {
        return Err(format!(
            "miraserve run did not reach listening state in time; log:\n{log_text}"
        ));
    }
    Ok(log_text)
}

/// On Linux, verifies `miraserve check` (text, JSON, `--strict`, `seccomp "off"`, `EACCES`)
/// under real seccomp filters answering `ENOSYS` or `EACCES` to `openat2`.
#[cfg(target_os = "linux")]
#[test]
fn check_reports_openat2_refusal_for_enosys_eacces_and_seccomp_off() -> TestResult {
    const LINUX_EACCES: u32 = 13;
    const LINUX_ENOSYS: u32 = 38;

    let tls = r#"tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }"#;
    let kdl_cache = format!(
        "server {{ listen \":443\"; {tls} }}\nsite \"c.example.test\" {{ root \"/var/www/c\"; file-cache \"1s\" }}\n"
    );
    let kdl_workers = format!(
        "server {{ listen \":443\"; workers 2; {tls} }}\nsite \"w.example.test\" {{ root \"/var/www/w\" }}\n"
    );
    let kdl_both = format!(
        "server {{ listen \":443\"; workers 2; {tls} }}\nsite \"b.example.test\" {{ root \"/var/www/b\"; file-cache \"2s\" }}\n"
    );
    let kdl_off = format!(
        "server {{ listen \":443\"; workers 2; {tls}; sandbox {{ seccomp \"off\" }} }}\nsite \"o.example.test\" {{ root \"/var/www/o\"; file-cache \"1s\" }}\n"
    );
    let kdl_plain = format!(
        "server {{ listen \":443\" protocols=\"h1\"; {tls} }}\nsite \"p.example.test\" {{ root \"/var/www/p\" }}\n"
    );
    let kdl_h2_only = format!(
        "server {{ listen \":443\"; {tls} }}\nsite \"h2.example.test\" {{ root \"/var/www/h2\" }}\n"
    );
    let kdl_zero = format!(
        "server {{ listen \":443\" protocols=\"h1\"; {tls}; limits {{ file-cache-bytes \"0\" }} }}\nsite \"z.example.test\" {{ root \"/var/www/z\"; file-cache \"1s\" }}\n"
    );

    // 1. Without a refusing filter (`openat2` works): NO openat2 refusal note.
    let ok_both = run_check_stdin_cmd(&kdl_both, &["--strict", "--format", "json"])
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    assert!(ok_both.status.success());
    let ok_json: serde_json::Value = serde_json::from_slice(&ok_both.stdout)?;
    assert!(
        !ok_json
            .get("notes")
            .and_then(serde_json::Value::as_array)
            .ok_or("missing notes")?
            .iter()
            .filter_map(serde_json::Value::as_str)
            .any(|n| n.contains("openat2"))
    );

    // 2. Under EACCES filter: treated like ENOSYS/EPERM refusal.
    let eacces_bpf = compile_openat2_errno_filter(LINUX_EACCES)?;
    let kdl_cache_eacces = kdl_cache.clone();
    std::thread::spawn(move || -> Result<(), String> {
        seccompiler::apply_filter(&eacces_bpf).map_err(|e| e.to_string())?;
        let out = run_check_stdin_cmd(&kdl_cache_eacces, &["--strict", "--format", "json"])?;
        if !out.status.success() {
            return Err("EACCES check --strict failed".to_owned());
        }
        let j: serde_json::Value =
            serde_json::from_slice(&out.stdout).map_err(|e| e.to_string())?;
        let ok = j
            .get("notes")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|arr| {
                arr.iter().filter_map(serde_json::Value::as_str).any(|n| {
                    n.contains("openat2 is refused") && n.contains("outer system-call filter")
                })
            });
        if !ok {
            return Err(format!("EACCES filter did not emit openat2 note: {j}"));
        }
        Ok(())
    })
    .join()
    .map_err(|_| "EACCES check thread panicked")?
    .map_err(|msg| -> Box<dyn std::error::Error> { msg.into() })?;

    // 3. Under ENOSYS filter: verify file-cache, workers, both, seccomp off, plain, and zero.
    let bpf = compile_openat2_errno_filter(LINUX_ENOSYS)?;
    std::thread::spawn(move || -> Result<(), String> {
        seccompiler::apply_filter(&bpf).map_err(|e| e.to_string())?;
        assert_enosys_check_cases(
            &kdl_cache,
            &kdl_workers,
            &kdl_both,
            &kdl_off,
            &kdl_plain,
            &kdl_h2_only,
            &kdl_zero,
        )
    })
    .join()
    .map_err(|_| "ENOSYS check thread panicked")?
    .map_err(|msg| -> Box<dyn std::error::Error> { msg.into() })
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_lines)]
fn assert_enosys_check_cases(
    kdl_cache: &str,
    kdl_workers: &str,
    kdl_both: &str,
    kdl_off: &str,
    kdl_plain: &str,
    kdl_h2_only: &str,
    kdl_zero: &str,
) -> Result<(), String> {
    let out = run_check_stdin_cmd(kdl_cache, &["--strict"])?;
    if !out.status.success() {
        return Err(format!(
            "file-cache check failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = s.lines().filter(|l| l.contains("openat2")).collect();
    if lines.len() != 1
        || !lines.first().is_some_and(|l| {
            l.contains("file-cache will store nothing")
                && l.contains("--allow-openat2")
                && l.contains("confirming the effective worker ExecStart command")
        })
    {
        return Err(format!("unexpected file-cache check output:\n{s}"));
    }

    for (label, kdl, expect_fc, expect_wk) in [
        ("workers", kdl_workers, false, true),
        ("both", kdl_both, true, true),
    ] {
        let out = run_check_stdin_cmd(kdl, &["--strict", "--format", "json"])?;
        if !out.status.success() {
            return Err(format!("{label} check --strict failed"));
        }
        let j: serde_json::Value =
            serde_json::from_slice(&out.stdout).map_err(|e| e.to_string())?;
        let notes: Vec<&str> = j
            .get("notes")
            .and_then(serde_json::Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(serde_json::Value::as_str)
                    .filter(|n| n.contains("openat2"))
                    .collect()
            })
            .unwrap_or_default();
        if notes.len() != 1
            || !notes.first().is_some_and(|n| {
                n.contains("file-cache will store nothing") == expect_fc
                    && n.contains("worker loops will not look up") == expect_wk
                    && n.contains("--allow-openat2")
            })
        {
            return Err(format!("unexpected {label} notes: {notes:?}"));
        }
    }

    // seccomp "off": W003 names set-ID protection, and advisory MUST NOT steer into --allow-openat2.
    let out = run_check_stdin_cmd(kdl_off, &["--format", "json"])?;
    if !out.status.success() {
        return Err("seccomp off check failed".to_owned());
    }
    let j: serde_json::Value = serde_json::from_slice(&out.stdout).map_err(|e| e.to_string())?;
    let has_w003_setid = j
        .get("warnings")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|arr| {
            arr.iter().any(|w| {
                w.get("code").and_then(serde_json::Value::as_str) == Some("W003")
                    && w.get("message")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|m| m.contains("set-ID"))
            })
        });
    if !has_w003_setid {
        return Err(format!("missing set-ID wording in W003: {j}"));
    }
    let off_notes: Vec<&str> = j
        .get("notes")
        .and_then(serde_json::Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(serde_json::Value::as_str)
                .filter(|n| n.contains("openat2"))
                .collect()
        })
        .unwrap_or_default();
    if off_notes.len() != 1
        || !off_notes.first().is_some_and(|n| {
            n.contains("NO set-ID protection")
                && n.contains("do NOT remove RestrictSUIDSGID=yes")
                && !n.contains("--allow-openat2")
        })
    {
        return Err(format!("unexpected seccomp-off advisory: {off_notes:?}"));
    }

    for (label, kdl) in [("plain-h1", kdl_plain), ("zero-h1", kdl_zero)] {
        let out = run_check_stdin_cmd(kdl, &["--strict"])?;
        if !out.status.success() {
            return Err(format!("{label} check failed"));
        }
        if String::from_utf8_lossy(&out.stdout).contains("openat2") {
            return Err(format!("{label} config should not emit openat2 note"));
        }
    }

    // Plain default HTTP/2 static config (`listen ":443"`): on kernels in 5.12-6.11 where allowing
    // openat2 enables in-task HTTP/2, emits the openat2 notice naming HTTP/2 separate tasks; on
    // kernels outside 5.12-6.11 does not falsely advise `--allow-openat2`.
    let h2_out = run_check_stdin_cmd(kdl_h2_only, &["--strict"])?;
    if !h2_out.status.success() {
        return Err("h2-only check failed".to_owned());
    }
    let h2_stdout = String::from_utf8_lossy(&h2_out.stdout);
    let in_h2_intask_range = miraserve_core::kernel_supports_h2_intask_static();
    if in_h2_intask_range {
        if !h2_stdout.contains("static HTTP/2 streams will run as separate tasks")
            || !h2_stdout.contains("--allow-openat2")
        {
            return Err(format!(
                "expected H2-only openat2 notice on 5.12-6.11 kernel, got:\n{h2_stdout}"
            ));
        }
    } else if h2_stdout.contains("--allow-openat2") {
        return Err(format!(
            "H2-only config outside 5.12-6.11 must not recommend --allow-openat2:\n{h2_stdout}"
        ));
    }
    Ok(())
}

/// On Linux, verifies `miraserve run` startup probe under an `ENOSYS` `openat2` filter in both
/// active-seccomp mode (naming `--allow-openat2`) and `--no-sandbox` mode (warning of lost
/// set-ID protection and refusing to recommend removing `RestrictSUIDSGID=yes`).
#[cfg(target_os = "linux")]
#[test]
fn startup_reports_openat2_refusal_for_active_seccomp_and_no_sandbox() -> TestResult {
    const LINUX_ENOSYS: u32 = 38;

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::env::temp_dir().join(format!(
        "miraserve-cli-openat2-run-{}-{nanos}",
        std::process::id()
    ));
    let www = base.join("www");
    std::fs::create_dir_all(&www)?;
    std::fs::write(www.join("index.html"), b"hi")?;
    let probe = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = probe.local_addr()?.port();
    drop(probe);
    let run_cfg = base.join("run.kdl");
    std::fs::write(
        &run_cfg,
        format!(
            "server {{\n    listen \"127.0.0.1:{port}\" protocols=\"h1\"\n    workers 1\n    sandbox {{ landlock #false; seccomp \"strict\" }}\n}}\n\
             site \"localhost\" {{\n    root \"{}\"\n    file-cache \"5s\"\n}}\n",
            www.display()
        ),
    )?;

    let bpf = compile_openat2_errno_filter(LINUX_ENOSYS)?;
    let base_t = base.clone();
    let run_cfg_t = run_cfg.clone();
    let res = std::thread::spawn(move || -> Result<(), String> {
        seccompiler::apply_filter(&bpf).map_err(|e| e.to_string())?;

        let log_active = run_miraserve_until_ready_and_read_log(
            &run_cfg_t,
            &base_t.join("run-active/miraserve.pid"),
            &base_t.join("logs-active/miraserve.log"),
            &[],
        )?;
        let active_matches: Vec<&str> = log_active
            .lines()
            .filter(|l| l.contains("openat2 is refused in this process"))
            .collect();
        if active_matches.len() != 1
            || !active_matches.first().is_some_and(|l| {
                l.contains("file-cache will store nothing")
                    && l.contains("worker loops will not look up")
                    && l.contains("--allow-openat2")
            })
        {
            return Err(format!(
                "expected active-seccomp openat2 advisory once, got:\n{log_active}"
            ));
        }
        if !log_active.contains("HTTP/2 stream execution mode selected")
            || !log_active.contains("mode=spawned")
        {
            return Err(format!(
                "expected startup log line reporting spawned HTTP/2 mode under ENOSYS, got:\n{log_active}"
            ));
        }

        let log_nosbx = run_miraserve_until_ready_and_read_log(
            &run_cfg_t,
            &base_t.join("run-nosbx/miraserve.pid"),
            &base_t.join("logs-nosbx/miraserve.log"),
            &["--no-sandbox"],
        )?;
        if !log_nosbx.contains("OS worker sandboxing skipped via --no-sandbox")
            || !log_nosbx.contains("set-ID protection")
        {
            return Err(format!(
                "--no-sandbox warning must name lost set-ID protection:\n{log_nosbx}"
            ));
        }
        let nosbx_matches: Vec<&str> = log_nosbx
            .lines()
            .filter(|l| l.contains("openat2 is refused in this process"))
            .collect();
        if nosbx_matches.len() != 1
            || !nosbx_matches.first().is_some_and(|l| {
                l.contains("NO set-ID protection")
                    && l.contains("do NOT remove RestrictSUIDSGID=yes")
                    && !l.contains("--allow-openat2")
            })
        {
            return Err(format!(
                "expected --no-sandbox openat2 advisory warning of NO set-ID protection, got:\n{log_nosbx}"
            ));
        }
        Ok(())
    })
    .join()
    .map_err(|_| "startup openat2 thread panicked")?;

    let _ = std::fs::remove_dir_all(&base);
    res.map_err(|msg| -> Box<dyn std::error::Error> { msg.into() })
}

// =========================================================================
// Section A: writable-set (`check --writable-set`, `service generate
// --print-writable-set`, and `version` features token `writable-set`).
// =========================================================================

fn parse_systemd_unit_writable_records(unit_text: &str) -> Vec<String> {
    let mut unit_paths = std::collections::BTreeSet::new();
    let mut private_tmp = false;

    for raw_line in unit_text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(val) = line.strip_prefix("RuntimeDirectory=") {
            for item in val.split_whitespace() {
                unit_paths.insert(format!("/run/{item}"));
            }
        } else if let Some(val) = line.strip_prefix("StateDirectory=") {
            for item in val.split_whitespace() {
                unit_paths.insert(format!("/var/lib/{item}"));
            }
        } else if let Some(val) = line.strip_prefix("LogsDirectory=") {
            for item in val.split_whitespace() {
                unit_paths.insert(format!("/var/log/{item}"));
            }
        } else if let Some(val) = line.strip_prefix("PrivateTmp=") {
            private_tmp = val.trim() == "yes";
        } else if let Some(val) = line.strip_prefix("ReadWritePaths=") {
            // Tokenize systemd space-separated paths with optional `-` prefix and `"..."` quotes.
            let mut chars = val.chars().peekable();
            while let Some(&ch) = chars.peek() {
                if ch.is_whitespace() {
                    chars.next();
                    continue;
                }
                if ch == '-' {
                    chars.next();
                }
                let mut token = String::new();
                if chars.peek() == Some(&'"') {
                    chars.next();
                    while let Some(c) = chars.next() {
                        if c == '\\' {
                            if let Some(next) = chars.next() {
                                token.push(next);
                            }
                        } else if c == '"' {
                            break;
                        } else {
                            token.push(c);
                        }
                    }
                } else {
                    while let Some(&c) = chars.peek() {
                        if c.is_whitespace() {
                            break;
                        }
                        token.push(c);
                        chars.next();
                    }
                }
                if !token.is_empty() {
                    unit_paths.insert(token);
                }
            }
        }
    }

    let mut out: Vec<String> = unit_paths
        .into_iter()
        .map(|p| format!("writable unit {p}"))
        .collect();
    if private_tmp {
        out.push("writable unit-private-tmp /tmp".to_owned());
        out.push("writable unit-private-tmp /var/tmp".to_owned());
    }
    out
}

#[test]
fn version_features_line_appends_writable_set_in_order() -> TestResult {
    let output = Command::new(miraserve_bin()).arg("version").output()?;
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    let features_line = stdout
        .lines()
        .find(|line| line.starts_with("features:"))
        .ok_or("missing features line in `miraserve version`")?;
    assert_eq!(
        features_line,
        "features: precompressed, header-rule-status, service-allow-openat2, writable-set, try-files-extensionless",
        "features tokens must keep existing order and append try-files-extensionless"
    );
    Ok(())
}

#[test]
fn plain_check_and_service_generate_outputs_remain_byte_identical() -> TestResult {
    // 1. Plain `miraserve check` emits byte-for-byte identical FULL stdout and empty stderr.
    let example = example_config_path();
    let check_out = Command::new(miraserve_bin())
        .args(["check", "--strict"])
        .arg(&example)
        .output()?;
    assert!(
        check_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&check_out.stderr)
    );
    let expected_check_stdout = format!(
        "OK: '{}' is valid (2 listener(s), 3 site(s), 4 route(s), TLS >= 1.3, PQC: X25519MLKEM768 enabled, 0 warning(s))\n",
        example.display()
    );
    assert_eq!(
        check_out.stdout,
        expected_check_stdout.as_bytes(),
        "plain `check` full stdout must match pinned output byte-for-byte"
    );
    assert!(
        check_out.stderr.is_empty(),
        "examples/miraserve.kdl should emit zero stderr diagnostics on plain check"
    );

    // 2. Plain `miraserve service generate --target systemd` and `--target systemd-keyd`
    //    must match the committed packaged unit files byte-for-byte in their entirety.
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    for (target, rel_path) in [
        ("systemd", "packaging/systemd/miraserve.service"),
        ("systemd-keyd", "packaging/systemd/miraserve-keyd.service"),
    ] {
        let pinned_unit = std::fs::read(repo_root.join(rel_path))?;
        let unit_out = Command::new(miraserve_bin())
            .args(["service", "generate", "--target", target])
            .output()?;
        assert!(
            unit_out.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&unit_out.stderr)
        );
        assert_eq!(
            unit_out.stdout, pinned_unit,
            "plain `service generate --target {target}` must match `{rel_path}` byte-for-byte"
        );
        // Pin: neither generated unit ever mentions or grants /run/php.
        let unit_str = String::from_utf8(unit_out.stdout)?;
        assert!(
            !unit_str.contains("/run/php") && !unit_str.contains("php"),
            "generated {target} unit must not mention or grant /run/php"
        );
    }
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn service_generate_print_writable_set_matches_parsed_unit_and_pins_no_php_dir() -> TestResult {
    let base = std::env::temp_dir().join(format!("miraserve-svc-ws-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let existing_keyd_dir = base.join("existing-keyd");
    std::fs::create_dir_all(&existing_keyd_dir)?;
    let existing_keyd_sock = existing_keyd_dir.join("signer.sock");
    let existing_keyd_sock_str = std::fs::canonicalize(&existing_keyd_dir)?
        .join("signer.sock")
        .to_string_lossy()
        .into_owned();
    let _ = existing_keyd_sock;

    let example_cfg = std::fs::canonicalize(example_config_path())?;
    let example_str = example_cfg.to_string_lossy().to_string();
    let flag_sets: Vec<Vec<String>> = vec![
        vec!["--target".into(), "systemd".into()],
        vec![
            "--target".into(),
            "systemd".into(),
            "--home-docroots".into(),
        ],
        vec![
            "--target".into(),
            "systemd".into(),
            "--allow-openat2".into(),
        ],
        vec![
            "--target".into(),
            "systemd".into(),
            "--allow-openat2".into(),
            "--home-docroots".into(),
            "--config".into(),
            example_str,
        ],
        vec![
            "--target".into(),
            "systemd".into(),
            "--acme-dir".into(),
            "/var/lib/custom-acme".into(),
        ],
        vec![
            "--target".into(),
            "systemd".into(),
            "--log-dir".into(),
            "/var/log/ignored-on-systemd".into(),
        ],
        vec!["--target".into(), "systemd-keyd".into()],
        vec![
            "--target".into(),
            "systemd-keyd".into(),
            "--keyd-socket".into(),
            existing_keyd_sock_str,
        ],
        vec![
            "--target".into(),
            "systemd-keyd".into(),
            "--keyd-socket".into(),
            "/run/custom-keyd/signer.sock".into(),
        ],
        vec![
            "--target".into(),
            "systemd-keyd".into(),
            "--keyd-socket".into(),
            "unix:/run/custom-keyd-unix/signer.sock".into(),
        ],
        vec![
            "--target".into(),
            "systemd-keyd".into(),
            "--keyd-socket".into(),
            "tcp://127.0.0.1:9443".into(),
        ],
    ];

    for flags in &flag_sets {
        let unit_out = Command::new(miraserve_bin())
            .args(["service", "generate"])
            .args(flags)
            .output()?;
        assert!(
            unit_out.status.success(),
            "unit gen failed for {flags:?}: {}",
            String::from_utf8_lossy(&unit_out.stderr)
        );
        let unit_text = String::from_utf8(unit_out.stdout)?;
        let expected_records = parse_systemd_unit_writable_records(&unit_text);

        let ws_out = Command::new(miraserve_bin())
            .args(["service", "generate"])
            .args(flags)
            .arg("--print-writable-set")
            .output()?;
        assert!(
            ws_out.status.success(),
            "--print-writable-set failed for {flags:?}: {}",
            String::from_utf8_lossy(&ws_out.stderr)
        );
        let actual_all: Vec<String> = String::from_utf8(ws_out.stdout)?
            .lines()
            .map(str::to_owned)
            .collect();
        assert_eq!(
            actual_all, expected_records,
            "unit writable-set records diverged from parsed unit directives for {flags:?}"
        );
        assert!(
            actual_all.iter().all(
                |l| !l.starts_with("writable-submount ") && !l.starts_with("writable-missing ")
            ),
            "service --print-writable-set must emit directives only (no host scanning / submounts / missing): {actual_all:?}"
        );
        assert!(
            actual_all
                .iter()
                .any(|l| l == "writable unit-private-tmp /tmp")
                && actual_all
                    .iter()
                    .any(|l| l == "writable unit-private-tmp /var/tmp"),
            "PrivateTmp must emit two separate records (/tmp and /var/tmp) for {flags:?}: {actual_all:?}"
        );
        // Pin: no PHP socket directory is ever left writable by the unit.
        assert!(
            actual_all.iter().all(|l| !l.contains("/run/php")),
            "generated unit must never include /run/php: {actual_all:?}"
        );
        // Custom --log-dir is ignored by systemd (LogsDirectory=miraserve always uses /var/log/miraserve).
        assert!(
            actual_all
                .iter()
                .all(|l| !l.contains("/var/log/ignored-on-systemd")),
            "unused --log-dir must not appear in systemd writable-set: {actual_all:?}"
        );
    }

    // Codex Round-2 P1 #7 regression guard: fields rendered through `systemd_quote` (`--config`,
    // `--binary`, `--auth-secret-file`) MUST keep accepting spaces just as at 74a8243, AND
    // `--acme-dir /tmp/acme` must report the literal directive without scanning host `/tmp`.
    let spaced_unit = Command::new(miraserve_bin())
        .args([
            "service",
            "generate",
            "--target",
            "systemd",
            "--binary",
            "/opt/my bin/miraserve",
            "--config",
            "/etc/miraserve/conf/site A.kdl",
            "--auth-secret-file",
            "/etc/miraserve/my secret.key",
        ])
        .output()?;
    assert!(
        spaced_unit.status.success(),
        "quoted ExecStart fields with spaces must remain accepted (74a8243 parity): {}",
        String::from_utf8_lossy(&spaced_unit.stderr)
    );
    let spaced_text = String::from_utf8(spaced_unit.stdout)?;
    assert!(spaced_text.contains(
        "ExecStart=\"/opt/my bin/miraserve\" run \"/etc/miraserve/conf/site A.kdl\" --acme-dir \"/var/lib/miraserve/acme\" --pid-file /run/miraserve/miraserve.pid --keyd-auth-secret-file \"/etc/miraserve/my secret.key\""
    ));

    let tmp_acme_ws = Command::new(miraserve_bin())
        .args([
            "service",
            "generate",
            "--target",
            "systemd",
            "--acme-dir",
            "/tmp/acme",
            "--print-writable-set",
        ])
        .output()?;
    assert!(tmp_acme_ws.status.success());
    let tmp_acme_lines: Vec<String> = String::from_utf8(tmp_acme_ws.stdout)?
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        tmp_acme_lines,
        vec![
            "writable unit /run/miraserve",
            "writable unit /tmp/acme",
            "writable unit /var/lib/miraserve",
            "writable unit /var/log/miraserve",
            "writable unit-private-tmp /tmp",
            "writable unit-private-tmp /var/tmp",
        ],
        "service --print-writable-set must emit literal directives without touching host /tmp"
    );

    // Report mode (`--print-writable-set` ONLY) refuses every path spelling it cannot represent
    // exactly, including some systemd or `miraserve keyd` would normalise/trim (trailing slash,
    // `//`, `.`/`..`, lone `]`, non-ASCII whitespace U+00A0, trailing space on `tcp://...`).
    // Plain `service generate` without `--print-writable-set` is unaffected and tested for exact
    // 74a8243 byte-identity in `plain_service_generate_matches_74a8243_bytes_for_all_targets_and_codex_inputs`.
    let refused_flag_sets: Vec<Vec<&str>> = vec![
        vec![
            "--target",
            "systemd-keyd",
            "--keyd-socket",
            "/run/signing vault/keyd.sock",
        ],
        vec![
            "--target",
            "systemd-keyd",
            "--keyd-socket",
            "/run/keyd*glob/keyd.sock",
        ],
        vec![
            "--target",
            "systemd-keyd",
            "--keyd-socket",
            "/run/keyd\"q/keyd.sock",
        ],
        vec![
            "--target",
            "systemd-keyd",
            "--keyd-socket",
            "/run/keyd\\b/keyd.sock",
        ],
        vec![
            "--target",
            "systemd-keyd",
            "--keyd-socket",
            "/run/keyd]/signer.sock",
        ],
        vec![
            "--target",
            "systemd-keyd",
            "--keyd-socket",
            "/run/keyd\u{00a0}dir/signer.sock",
        ],
        vec![
            "--target",
            "systemd-keyd",
            "--keyd-socket",
            "/run/miraserve-keyd//signer.sock",
        ],
        vec![
            "--target",
            "systemd-keyd",
            "--keyd-socket",
            "tcp://127.0.0.1:9443 ",
            "--auth-secret-file",
            "/etc/miraserve/keyd.secret",
        ],
        vec![
            "--target",
            "systemd-keyd",
            "--keyd-socket",
            "/run/keyd.sock",
        ],
        vec![
            "--target",
            "systemd-keyd",
            "--keyd-socket",
            "/var/run/keyd.sock",
        ],
        vec!["--target", "systemd-keyd", "--keyd-socket", "/keyd.sock"],
        vec![
            "--target",
            "systemd-keyd",
            "--keyd-socket",
            "run/miraserve-keyd/keyd.sock",
        ],
        vec![
            "--target",
            "systemd-keyd",
            "--keyd-socket",
            "/run/miraserve-keyd/../keyd.sock",
        ],
        vec!["--target", "systemd", "--acme-dir", "state/acme"],
        vec!["--target", "systemd", "--acme-dir", "/"],
        vec![
            "--target",
            "systemd",
            "--acme-dir",
            "/var/lib/miraserve/a/../b/nonexistent",
        ],
        vec![
            "--target",
            "systemd",
            "--acme-dir",
            "/var/lib/miraserve/./acme",
        ],
        vec![
            "--target",
            "systemd",
            "--acme-dir",
            "/var/lib/miraserve/acme/",
        ],
        vec![
            "--target",
            "systemd",
            "--acme-dir",
            "/var/lib/miraserve//acme",
        ],
    ];
    for flags in &refused_flag_sets {
        let out = Command::new(miraserve_bin())
            .args(["service", "generate"])
            .args(flags)
            .arg("--print-writable-set")
            .output()?;
        assert!(
            !out.status.success(),
            "expected report-mode refusal for {flags:?}, stdout:\n{}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert_eq!(
            out.stdout,
            [] as [u8; 0],
            "refused service generate --print-writable-set must print empty stdout for {flags:?}"
        );
        assert!(
            !out.stderr.is_empty(),
            "refused service generate --print-writable-set must explain the refusal on stderr for {flags:?}"
        );
    }

    // Quoted `--acme-dir` containing spaces preserves v0.1.4 acceptance in BOTH plain unit
    // rendering (`ReadWritePaths=-"/var/lib/custom acme dir/state"` + quoted `ExecStart*`) and
    // `--print-writable-set` (`writable unit /var/lib/custom acme dir/state`).
    let spaced_acme = "/var/lib/custom acme dir/state";
    let spaced_unit = Command::new(miraserve_bin())
        .args([
            "service",
            "generate",
            "--target",
            "systemd",
            "--acme-dir",
            spaced_acme,
        ])
        .output()?;
    assert!(
        spaced_unit.status.success(),
        "spaced quoted --acme-dir must remain accepted as at 74a8243: {}",
        String::from_utf8_lossy(&spaced_unit.stderr)
    );
    let spaced_unit_text = String::from_utf8(spaced_unit.stdout)?;
    assert!(
        spaced_unit_text.contains(
            "ReadWritePaths=/var/lib/miraserve /run/miraserve -\"/var/lib/custom acme dir/state\"\n"
        ),
        "unexpected ReadWritePaths in spaced --acme-dir unit:\n{spaced_unit_text}"
    );
    assert!(
        spaced_unit_text.contains("--acme-dir \"/var/lib/custom acme dir/state\""),
        "expected quoted --acme-dir in ExecStart*:\n{spaced_unit_text}"
    );
    let spaced_ws = Command::new(miraserve_bin())
        .args([
            "service",
            "generate",
            "--target",
            "systemd",
            "--acme-dir",
            spaced_acme,
            "--print-writable-set",
        ])
        .output()?;
    assert!(
        spaced_ws.status.success(),
        "spaced quoted --acme-dir --print-writable-set failed: {}",
        String::from_utf8_lossy(&spaced_ws.stderr)
    );
    assert_eq!(
        String::from_utf8(spaced_ws.stdout)?,
        "writable unit /run/miraserve\n\
         writable unit /var/lib/custom acme dir/state\n\
         writable unit /var/lib/miraserve\n\
         writable unit /var/log/miraserve\n\
         writable unit-private-tmp /tmp\n\
         writable unit-private-tmp /var/tmp\n"
    );

    // Non-systemd targets refuse --print-writable-set cleanly.
    for target in ["launchd", "windows"] {
        let out = Command::new(miraserve_bin())
            .args([
                "service",
                "generate",
                "--target",
                target,
                "--print-writable-set",
            ])
            .output()?;
        assert!(
            !out.status.success(),
            "expected non-zero exit for --target {target} --print-writable-set"
        );
        assert_eq!(out.stdout, [] as [u8; 0]);
    }
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn check_writable_set_example_configs_and_unit_coverage() -> TestResult {
    let dev_local = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("examples")
        .join("dev-local.kdl");

    // 1. examples/dev-local.kdl: zero writable Landlock paths.
    let dev_out = Command::new(miraserve_bin())
        .args(["check", "--writable-set"])
        .arg(&dev_local)
        .output()?;
    assert!(
        dev_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&dev_out.stderr)
    );
    let dev_lines: Vec<String> = String::from_utf8(dev_out.stdout)?
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        dev_lines.len(),
        1,
        "dev-local.kdl should print only the landlock state line, got: {dev_lines:?}"
    );
    let state_line = dev_lines.first().map_or("", String::as_str);
    #[cfg(not(target_os = "linux"))]
    assert_eq!(state_line, "landlock unavailable");
    #[cfg(target_os = "linux")]
    assert!(
        state_line.starts_with("landlock enforced abi=")
            || state_line.starts_with("landlock partial abi=")
            || state_line == "landlock unavailable",
        "unexpected state line: {state_line}"
    );

    // 2. examples/miraserve.kdl with the default systemd unit's --acme-dir /var/lib/miraserve/acme.
    let ex_out = Command::new(miraserve_bin())
        .args([
            "check",
            "--writable-set",
            "--acme-dir",
            "/var/lib/miraserve/acme",
        ])
        .arg(example_config_path())
        .output()?;
    assert!(
        ex_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&ex_out.stderr)
    );
    let ex_lines: Vec<String> = String::from_utf8(ex_out.stdout)?
        .lines()
        .map(str::to_owned)
        .collect();
    let ex_state = ex_lines.first().map_or("", String::as_str);
    let ll_records: Vec<&str> = ex_lines.iter().skip(1).map(String::as_str).collect();

    // Fetch default systemd unit writable set and compare coverage.
    let unit_ws_out = Command::new(miraserve_bin())
        .args([
            "service",
            "generate",
            "--target",
            "systemd",
            "--print-writable-set",
        ])
        .output()?;
    assert!(unit_ws_out.status.success());
    let unit_ws_text = String::from_utf8(unit_ws_out.stdout)?;
    let unit_dirs: Vec<&str> = unit_ws_text
        .lines()
        .filter_map(|l| l.strip_prefix("writable unit "))
        .collect();

    #[cfg(not(target_os = "linux"))]
    {
        assert_eq!(ex_state, "landlock unavailable");
        assert!(
            ll_records.is_empty(),
            "non-Linux must emit no writable landlock lines: {ll_records:?}"
        );
    }

    #[cfg(target_os = "linux")]
    if ex_state.starts_with("landlock enforced abi=")
        || ex_state.starts_with("landlock partial abi=")
    {
        let mut expected_existing = std::collections::BTreeSet::new();
        let mut expected_missing = std::collections::BTreeSet::new();
        for path in [
            "/run/php/php8.3-fpm.sock",
            "/var/lib/miraserve/acme",
            "/var/lib/miraserve/releases/future",
        ] {
            if let Ok(canon) = std::fs::canonicalize(path) {
                expected_existing.insert(canon.to_string_lossy().into_owned());
            } else {
                expected_missing.insert(path.to_owned());
            }
        }
        let mut expected: Vec<String> = expected_existing
            .into_iter()
            .map(|p| format!("writable landlock {p}"))
            .collect();
        for p in expected_missing {
            expected.push(format!("writable-missing landlock {p}"));
        }
        let actual: Vec<String> = ll_records.iter().map(|s| (*s).to_owned()).collect();
        assert_eq!(
            actual, expected,
            "expected exact installed/missing Landlock candidate grants (no submounts) for examples/miraserve.kdl"
        );
        // Every non-socket writable path in examples/miraserve.kdl lies inside the default unit's
        // `/var/lib/miraserve` grant; `/run/php/php8.3-fpm.sock` is intentionally outside unit dirs.
        let uncovered: Vec<&str> = actual
            .iter()
            .filter_map(|l| {
                l.strip_prefix("writable landlock ")
                    .or_else(|| l.strip_prefix("writable-missing landlock "))
            })
            .filter(|p| {
                !unit_dirs
                    .iter()
                    .any(|u| std::path::Path::new(p).starts_with(std::path::Path::new(u)))
            })
            .collect();
        assert_eq!(uncovered, vec!["/run/php/php8.3-fpm.sock"]);
    }

    let _ = unit_dirs;
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn check_writable_set_all_writable_features_disabled_and_errors() -> TestResult {
    let base = std::env::temp_dir().join(format!("miraserve-ws-all-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let acme_existing = base.join("acme dir");
    let sock_tree_existing = base.join("custom fpm pool");
    let sock_parent = base.join("socks");
    std::fs::create_dir_all(&acme_existing)?;
    std::fs::create_dir_all(&sock_tree_existing)?;
    std::fs::create_dir_all(&sock_parent)?;

    let canon_base = std::fs::canonicalize(&base)?;
    let canon_acme = std::fs::canonicalize(&acme_existing)?;
    let canon_sock_tree = std::fs::canonicalize(&sock_tree_existing)?;
    let missing_publish = canon_base.join("releases/with space/app");

    #[cfg(unix)]
    let existing_fcgi_sock = sock_parent.join("live.sock");
    #[cfg(unix)]
    let _fcgi_listener = std::os::unix::net::UnixListener::bind(&existing_fcgi_sock)?;
    #[cfg(unix)]
    let canon_fcgi_sock = std::fs::canonicalize(&existing_fcgi_sock)?;
    #[cfg(unix)]
    let existing_keyd_sock = sock_parent.join("keyd.sock");
    #[cfg(unix)]
    let _keyd_listener = std::os::unix::net::UnixListener::bind(&existing_keyd_sock)?;
    #[cfg(unix)]
    let canon_keyd_sock = std::fs::canonicalize(&existing_keyd_sock)?;

    // 1. Disabled Landlock prints `landlock disabled` on Linux and `landlock unavailable` on
    //    non-Linux, with zero writable lines (Codex Round-1 P2 #5).
    let disabled_kdl = r#"
server {
    listen ":443"
    tls { acme { email "ops@example.com" } }
    sandbox { landlock #false }
}
site "off.example.com" {
    root "/var/www/off"
    ai-publish {
        storage "/var/lib/miraserve/releases/off"
        require-signature "ed25519:/etc/miraserve/deploy.pub"
    }
}
"#;
    let mut child = Command::new(miraserve_bin())
        .args([
            "check",
            "--writable-set",
            "--acme-dir",
            "/var/lib/miraserve/acme",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(disabled_kdl.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    #[cfg(target_os = "linux")]
    assert_eq!(String::from_utf8(out.stdout)?, "landlock disabled\n");
    #[cfg(not(target_os = "linux"))]
    assert_eq!(String::from_utf8(out.stdout)?, "landlock unavailable\n");

    // 1b. `--no-sandbox` disables Landlock even when the KDL config enables it.
    let enabled_kdl = r#"
server {
    listen ":443"
    tls { acme { email "ops@example.com" } }
    sandbox { landlock #true }
}
site "on.example.com" {
    root "/var/www/on"
}
"#;
    let mut child = Command::new(miraserve_bin())
        .args([
            "check",
            "--writable-set",
            "--no-sandbox",
            "--acme-dir",
            "/var/lib/miraserve/acme",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(enabled_kdl.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    #[cfg(target_os = "linux")]
    assert_eq!(String::from_utf8(out.stdout)?, "landlock disabled\n");
    #[cfg(not(target_os = "linux"))]
    assert_eq!(String::from_utf8(out.stdout)?, "landlock unavailable\n");

    // 2. All writable-producing features: existing ACME + missing ai-publish + existing FastCGI
    //    Unix socket + absent FastCGI Unix socket (reported as writable-missing!) + existing
    //    socket-tree + absent socket-tree with non-rotating access log (Codex Round-2 P1 #1) + spaces.
    #[cfg(unix)]
    {
        let absent_fcgi_sock = canon_base.join("socks/absent.sock");
        let absent_sock_tree = canon_base.join("absent-pool");
        let all_features_kdl = format!(
            r#"
server {{
    listen ":443"
    tls {{
        acme {{ email "ops@example.com" }}
    }}
    sandbox {{
        read-tree "/srv/readonly-sites"
        socket-tree "{}" "{}"
    }}
}}
site "all.example.com" {{
    root "/var/www/all"
    ai-publish {{
        storage "{}"
        require-signature "ed25519:/etc/miraserve/deploy.pub"
    }}
    route "/live/*" {{
        fastcgi-pass "unix:{}"
    }}
    route "/absent/*" {{
        fastcgi-pass "unix:{}"
    }}
}}
"#,
            sock_tree_existing.display(),
            absent_sock_tree.display(),
            missing_publish.display(),
            existing_fcgi_sock.display(),
            absent_fcgi_sock.display(),
        );
        let mut child = Command::new(miraserve_bin())
            .args([
                "check",
                "--writable-set",
                "--log-max-bytes",
                "0",
                "--access-log",
            ])
            .arg(absent_sock_tree.join("access.log"))
            .arg("--acme-dir")
            .arg(&acme_existing)
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(all_features_kdl.as_bytes())?;
        }
        let out = child.wait_with_output()?;
        assert!(
            out.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let lines: Vec<String> = String::from_utf8(out.stdout)?
            .lines()
            .map(str::to_owned)
            .collect();
        assert!(
            !lines.is_empty(),
            "expected at least the landlock state line"
        );
        #[cfg(target_os = "linux")]
        if lines.first().is_some_and(|l| {
            l.starts_with("landlock enforced ") || l.starts_with("landlock partial ")
        }) {
            let mut expected_installed = std::collections::BTreeSet::new();
            expected_installed.insert(canon_acme.to_string_lossy().into_owned());
            expected_installed.insert(canon_sock_tree.to_string_lossy().into_owned());
            expected_installed.insert(canon_fcgi_sock.to_string_lossy().into_owned());
            let mut expected_missing = std::collections::BTreeSet::new();
            expected_missing.insert(absent_sock_tree.to_string_lossy().into_owned());
            expected_missing.insert(missing_publish.to_string_lossy().into_owned());
            expected_missing.insert(absent_fcgi_sock.to_string_lossy().into_owned());
            let mut expected: Vec<String> = expected_installed
                .into_iter()
                .map(|p| format!("writable landlock {p}"))
                .collect();
            for p in expected_missing {
                expected.push(format!("writable-missing landlock {p}"));
            }
            let actual: Vec<String> = lines.iter().skip(1).cloned().collect();
            assert_eq!(
                actual, expected,
                "superset rule must report existing pinned grants AND absent socket-tree / absent sockets as writable-missing (no submounts)"
            );
            assert!(
                lines
                    .iter()
                    .all(|l| !l.contains("/var/www/all") && !l.contains("/srv/readonly-sites"))
            );
        }
        let _ = (canon_acme, canon_sock_tree, canon_fcgi_sock);

        // 3. Split-daemon keyd Unix socket: `writable landlock` when present, `writable-missing
        //    landlock` when absent (superset rule).
        let keyd_present_kdl = format!(
            r#"
server {{
    listen ":443"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "{}"
        cert "/etc/miraserve/certs/app.crt"
        key "/etc/miraserve/keys/app.key"
    }}
}}
site "split.example.com" {{
    root "/var/www/split"
}}
"#,
            existing_keyd_sock.display()
        );
        let mut child = Command::new(miraserve_bin())
            .args(["check", "--writable-set", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(keyd_present_kdl.as_bytes())?;
        }
        let out = child.wait_with_output()?;
        assert!(
            out.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let keyd_lines: Vec<String> = String::from_utf8(out.stdout)?
            .lines()
            .map(str::to_owned)
            .collect();
        assert!(
            keyd_lines
                .first()
                .is_some_and(|l| l.starts_with("landlock ")),
            "expected landlock state line: {keyd_lines:?}"
        );
        #[cfg(target_os = "linux")]
        if keyd_lines.first().is_some_and(|l| {
            l.starts_with("landlock enforced ") || l.starts_with("landlock partial ")
        }) {
            assert_eq!(
                keyd_lines.get(1..),
                Some(&[format!("writable landlock {}", canon_keyd_sock.display())][..])
            );
        }
        let _ = canon_keyd_sock;

        let absent_keyd_kdl = r#"
server {
    listen ":443"
    tls {
        key-isolation "split-daemon"
        keyd-socket "/run/miraserve-keyd/nonexistent-keyd.sock"
        cert "/etc/miraserve/certs/app.crt"
        key "/etc/miraserve/keys/app.key"
    }
}
site "split.example.com" {
    root "/var/www/split"
}
"#;
        let mut child = Command::new(miraserve_bin())
            .args(["check", "--writable-set", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(absent_keyd_kdl.as_bytes())?;
        }
        let out = child.wait_with_output()?;
        assert!(out.status.success());
        let absent_lines: Vec<String> = String::from_utf8(out.stdout)?
            .lines()
            .map(str::to_owned)
            .collect();
        #[cfg(target_os = "linux")]
        if absent_lines.first().is_some_and(|l| {
            l.starts_with("landlock enforced ") || l.starts_with("landlock partial ")
        }) {
            assert_eq!(
                absent_lines.get(1..),
                Some(
                    &[
                        "writable-missing landlock /run/miraserve-keyd/nonexistent-keyd.sock"
                            .to_owned()
                    ][..]
                ),
                "absent keyd socket must appear as writable-missing under superset rule: {absent_lines:?}"
            );
        }
        #[cfg(not(target_os = "linux"))]
        assert_eq!(absent_lines, vec!["landlock unavailable"]);
    }

    // 4. Validation failure under --strict prints identical stderr diagnostics and EMPTY stdout.
    let warn_kdl = r#"
server {
    listen ":443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key"; }
}
site "legacy.example.com" {
    tls { compat-tls-1-2 #true; }
    root "/var/www/legacy"
}
"#;
    let mut child = Command::new(miraserve_bin())
        .args(["check", "--strict", "--writable-set", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(warn_kdl.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    assert!(!out.status.success());
    assert!(
        out.stdout.is_empty(),
        "failed check --writable-set must print nothing to stdout"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("W002"));

    // 5. --writable-set with --format json is refused cleanly.
    let json_conflict = Command::new(miraserve_bin())
        .args(["check", "--writable-set", "--format", "json"])
        .arg(example_config_path())
        .output()?;
    assert!(!json_conflict.status.success());
    assert_eq!(json_conflict.stdout, [] as [u8; 0]);

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn writable_set_refuses_control_characters_and_resolves_symlinks() -> TestResult {
    let base = std::env::temp_dir().join(format!("miraserve-ws-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let real_acme = base.join("real-acme-dir");
    std::fs::create_dir_all(&real_acme)?;
    let canon_base = std::fs::canonicalize(&base)?;
    let canon_acme = std::fs::canonicalize(&real_acme)?;
    let canon_acme_str = canon_acme
        .to_str()
        .ok_or("non-utf8 canonical temp dir")?
        .to_owned();

    // 1. Symlink, ACME private-dir validation, unopenable candidates, and control-bearing targets.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let link_acme = canon_base.join("link-acme");
        std::os::unix::fs::symlink(&real_acme, &link_acme)?;
        let missing_under_link = link_acme.join("future-state");
        let real_publish = base.join("real-publish-dir");
        std::fs::create_dir_all(&real_publish)?;
        let canon_publish = std::fs::canonicalize(&real_publish)?;
        let canon_publish_str = canon_publish
            .to_str()
            .ok_or("non-utf8 canonical publish dir")?
            .to_owned();
        let link_publish = canon_base.join("link-publish");
        std::os::unix::fs::symlink(&real_publish, &link_publish)?;

        // 1a. `service generate --target systemd --acme-dir <path> --print-writable-set` emits the
        //     rendered unit directive ONLY — zero host scanning or symlink resolution (Contract D).
        let svc_out = Command::new(miraserve_bin())
            .args(["service", "generate", "--target", "systemd", "--acme-dir"])
            .arg(&link_acme)
            .arg("--print-writable-set")
            .output()?;
        assert!(
            svc_out.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&svc_out.stderr)
        );
        let svc_stdout = String::from_utf8(svc_out.stdout)?;
        let expected_unit_rec = format!("writable unit {}", link_acme.display());
        assert!(
            svc_stdout.lines().any(|l| l == expected_unit_rec),
            "expected unit directive `{expected_unit_rec}` without host scanning, got:\n{svc_stdout}"
        );

        // 1b. Codex Round-2 P2 (ACME): `check --writable-set` MUST REFUSE symlinked leaf,
        //     symlinked ancestor, unsafe world-writable non-sticky ancestor, and wrong leaf owner
        //     with `run`'s diagnostic (never reporting success for an --acme-dir `run` refuses).
        let acme_cfg_kdl = r#"
server {
    listen ":443"
    tls { acme { email "ops@example.com" } }
}
site "sym.example.com" {
    root "/var/www/sym"
}
"#;
        for (label, bad_acme_path, expected_diag) in [
            ("symlinked leaf", link_acme.clone(), "symbolic link"),
            (
                "symlinked ancestor",
                missing_under_link.clone(),
                "symbolic link",
            ),
        ] {
            let mut child = Command::new(miraserve_bin())
                .args(["check", "--writable-set", "--acme-dir"])
                .arg(&bad_acme_path)
                .arg("-")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(acme_cfg_kdl.as_bytes())?;
            }
            let chk_out = child.wait_with_output()?;
            assert!(
                !chk_out.status.success(),
                "check --writable-set must refuse {label} --acme-dir"
            );
            assert_eq!(chk_out.stdout, [] as [u8; 0]);
            let stderr = String::from_utf8_lossy(&chk_out.stderr);
            assert!(
                stderr.contains(expected_diag),
                "expected `{expected_diag}` diagnostic for {label}, got: {stderr:?}"
            );
        }

        // Unsafe world-writable non-sticky ancestor for --acme-dir MUST fail with run's diagnostic.
        let unsafe_anc = canon_base.join("world-writable");
        std::fs::create_dir_all(&unsafe_anc)?;
        std::fs::set_permissions(&unsafe_anc, std::fs::Permissions::from_mode(0o777))?;
        let mut unsafe_child = Command::new(miraserve_bin())
            .args(["check", "--writable-set", "--acme-dir"])
            .arg(unsafe_anc.join("acme"))
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(mut stdin) = unsafe_child.stdin.take() {
            stdin.write_all(acme_cfg_kdl.as_bytes())?;
        }
        let unsafe_out = unsafe_child.wait_with_output()?;
        let _ = std::fs::set_permissions(&unsafe_anc, std::fs::Permissions::from_mode(0o700));
        assert!(
            !unsafe_out.status.success(),
            "check --writable-set must refuse --acme-dir with world-writable non-sticky ancestor"
        );
        assert_eq!(unsafe_out.stdout, [] as [u8; 0]);
        assert!(
            String::from_utf8_lossy(&unsafe_out.stderr).contains("unsafe ancestor"),
            "stderr: {}",
            String::from_utf8_lossy(&unsafe_out.stderr)
        );

        let running_as_root = std::process::Command::new("id")
            .arg("-u")
            .output()
            .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "0");
        if !running_as_root && std::path::Path::new("/usr/share").is_dir() {
            let mut wrong_owner = Command::new(miraserve_bin())
                .args(["check", "--writable-set", "--acme-dir", "/usr/share", "-"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            if let Some(mut stdin) = wrong_owner.stdin.take() {
                stdin.write_all(acme_cfg_kdl.as_bytes())?;
            }
            let owner_out = wrong_owner.wait_with_output()?;
            assert!(
                !owner_out.status.success(),
                "check --writable-set must refuse --acme-dir owned by another uid"
            );
            assert_eq!(owner_out.stdout, [] as [u8; 0]);
            assert!(
                String::from_utf8_lossy(&owner_out.stderr).contains("owned by uid"),
                "stderr: {}",
                String::from_utf8_lossy(&owner_out.stderr)
            );
        }

        // 1c. Existing symlinked `ai-publish.storage` (which `run` DOES accept) prints the pinned
        //     object's canonical name on Linux (`writable landlock <canon_publish>`), never the
        //     symlink spelling.
        let pub_sym_kdl = format!(
            r#"
server {{
    listen ":443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/keys/a.key" }}
}}
site "pubsym.example.com" {{
    root "/var/www/pubsym"
    ai-publish {{
        storage "{}"
        require-signature "ed25519:/etc/miraserve/deploy.pub"
    }}
}}
"#,
            link_publish.display()
        );
        let mut pub_child = Command::new(miraserve_bin())
            .args(["check", "--writable-set", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(mut stdin) = pub_child.stdin.take() {
            stdin.write_all(pub_sym_kdl.as_bytes())?;
        }
        let pub_out = pub_child.wait_with_output()?;
        assert!(
            pub_out.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&pub_out.stderr)
        );
        let pub_stdout = String::from_utf8(pub_out.stdout)?;
        #[cfg(not(target_os = "linux"))]
        assert_eq!(pub_stdout, "landlock unavailable\n");
        #[cfg(target_os = "linux")]
        if pub_stdout.lines().next().is_some_and(|l| {
            l.starts_with("landlock enforced ") || l.starts_with("landlock partial ")
        }) {
            let expected_ll_rec = format!("writable landlock {canon_publish_str}");
            assert!(
                pub_stdout.lines().any(|l| l == expected_ll_rec),
                "expected pinned publish dir `{expected_ll_rec}`, got:\n{pub_stdout}"
            );
            assert!(
                !pub_stdout.contains("link-publish"),
                "symlink name must not appear in resolved output:\n{pub_stdout}"
            );
        }
        let _ = (canon_publish_str, canon_acme_str);

        // 1d. Unopenable / unresolvable candidate (`ELOOP`, `ENOTDIR`, `EACCES`) on a non-ACME
        //     writable candidate (`socket-tree`) is printed as `writable-missing landlock <abs
        //     lexical path>` under the superset rule (never silently omitted).
        let loop_a = canon_base.join("loop-a");
        let loop_b = canon_base.join("loop-b");
        std::os::unix::fs::symlink(&loop_b, &loop_a)?;
        std::os::unix::fs::symlink(&loop_a, &loop_b)?;
        let regular_file = canon_base.join("not-a-dir");
        std::fs::write(&regular_file, b"hello")?;
        let mut unopenable_paths = vec![loop_a.join("leaf"), regular_file.join("child")];
        let locked_dir = canon_base.join("locked-000");
        if !running_as_root {
            std::fs::create_dir_all(&locked_dir)?;
            std::fs::set_permissions(&locked_dir, std::fs::Permissions::from_mode(0o000))?;
            unopenable_paths.push(locked_dir.join("pool"));
        }
        #[cfg(target_os = "linux")]
        for unopenable in &unopenable_paths {
            let kdl = format!(
                r#"
server {{
    listen ":443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/keys/a.key" }}
    sandbox {{
        socket-tree "{}"
    }}
}}
site "unopen.example.com" {{
    root "/var/www/unopen"
}}
"#,
                unopenable.display()
            );
            let mut child = Command::new(miraserve_bin())
                .args(["check", "--writable-set", "-"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(kdl.as_bytes())?;
            }
            let chk_res = child.wait_with_output()?;
            assert!(
                chk_res.status.success(),
                "unopenable candidate '{}' should report writable-missing, stderr: {}",
                unopenable.display(),
                String::from_utf8_lossy(&chk_res.stderr)
            );
            let stdout = String::from_utf8(chk_res.stdout)?;
            if stdout.lines().next().is_some_and(|l| {
                l.starts_with("landlock enforced ") || l.starts_with("landlock partial ")
            }) {
                let expected = format!("writable-missing landlock {}", unopenable.display());
                assert!(
                    stdout.lines().any(|l| l == expected),
                    "expected `{expected}`, got:\n{stdout}"
                );
            }
        }
        let _ = &unopenable_paths;
        if locked_dir.exists() {
            let _ = std::fs::set_permissions(&locked_dir, std::fs::Permissions::from_mode(0o700));
        }

        // 1e. Symlink in `ai-publish.storage` whose resolved TARGET contains a control character
        //     (BEL \x07) is REFUSED on Linux with the expected diagnostic and NO raw BEL byte (and
        //     strictly NO BrokenPipe tolerance on stdin since CLI args are valid).
        let ctrl_target = canon_base.join("bad\x07dir");
        if std::fs::create_dir_all(&ctrl_target).is_ok() {
            let clean_link = canon_base.join("clean-link-to-ctrl");
            std::os::unix::fs::symlink(&ctrl_target, &clean_link)?;

            #[cfg(target_os = "linux")]
            {
                let ctrl_pub_kdl = format!(
                    r#"
server {{
    listen ":443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/keys/a.key" }}
}}
site "ctrltarget.example.com" {{
    root "/var/www/ctrltarget"
    ai-publish {{
        storage "{}"
        require-signature "ed25519:/etc/miraserve/deploy.pub"
    }}
}}
"#,
                    clean_link.display()
                );
                let mut chk_ctrl_child = Command::new(miraserve_bin())
                    .args(["check", "--writable-set", "-"])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()?;
                if let Some(mut stdin) = chk_ctrl_child.stdin.take() {
                    stdin.write_all(ctrl_pub_kdl.as_bytes())?;
                }
                let chk_ctrl = chk_ctrl_child.wait_with_output()?;
                assert!(
                    !chk_ctrl.status.success(),
                    "check --writable-set must refuse symlink to control-char target"
                );
                assert_eq!(chk_ctrl.stdout, [] as [u8; 0]);
                assert!(
                    !chk_ctrl.stderr.contains(&0x07),
                    "raw control byte must never be printed"
                );
                let ctrl_stderr = String::from_utf8_lossy(&chk_ctrl.stderr);
                assert!(
                    ctrl_stderr.contains("control character") && ctrl_stderr.contains("refused"),
                    "expected control-character refusal diagnostic, got: {ctrl_stderr:?}"
                );
            }
            let _ = clean_link;
        }
    }

    // 1f. Codex Round-2 P2 (Control characters): a nonexistent POSITIONAL config filename
    //     containing a newline MUST be rejected without printing the raw newline to stderr.
    let bad_cfg_out = Command::new(miraserve_bin())
        .args(["check", "--writable-set", "/tmp/nonexistent\ninjected.kdl"])
        .output()?;
    assert!(
        !bad_cfg_out.status.success(),
        "check --writable-set must reject positional config filename with control char"
    );
    assert_eq!(bad_cfg_out.stdout, [] as [u8; 0]);
    let bad_cfg_stderr = String::from_utf8_lossy(&bad_cfg_out.stderr);
    assert!(
        !bad_cfg_stderr.contains("nonexistent\ninjected.kdl"),
        "raw newline in positional config filename must never reach stderr: {bad_cfg_stderr:?}"
    );
    assert!(
        bad_cfg_stderr.contains("control character"),
        "expected control character diagnostic: {bad_cfg_stderr:?}"
    );

    // 2. Direct newline and other control characters — INCLUDING relative paths that would
    //    otherwise trigger W017 — are REFUSED BEFORE any diagnostic interpolates them (P2 #3).
    for bad_acme in [
        "/tmp/evil\ninjected",
        "rel\ninjected",
        "/tmp/evil\rbar",
        "/tmp/evil\x07bell",
        "/tmp/evil\tbar",
    ] {
        // service generate --print-writable-set
        let svc_bad = Command::new(miraserve_bin())
            .args([
                "service",
                "generate",
                "--target",
                "systemd",
                "--acme-dir",
                bad_acme,
                "--print-writable-set",
            ])
            .output()?;
        assert!(
            !svc_bad.status.success(),
            "service generate must refuse control char in {bad_acme:?}"
        );
        assert_eq!(svc_bad.stdout, [] as [u8; 0]);
        let svc_stderr = String::from_utf8_lossy(&svc_bad.stderr);
        assert!(!svc_stderr.contains("evil\ninjected") && !svc_stderr.contains("rel\ninjected"));

        // check --writable-set (NON-STRICT!) via --acme-dir
        let cfg_kdl = r#"
server {
    listen ":443"
    tls { acme { email "ops@example.com" } }
}
site "ctrl.example.com" {
    root "/var/www/ctrl"
}
"#;
        let mut child = Command::new(miraserve_bin())
            .args(["check", "--writable-set", "--acme-dir", bad_acme, "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take()
            && let Err(err) = stdin.write_all(cfg_kdl.as_bytes())
            && err.kind() != std::io::ErrorKind::BrokenPipe
        {
            return Err(err.into());
        }
        let chk_bad = child.wait_with_output()?;
        assert!(
            !chk_bad.status.success(),
            "check --writable-set must refuse control char in {bad_acme:?}"
        );
        assert_eq!(chk_bad.stdout, [] as [u8; 0]);
        let stderr_str = String::from_utf8_lossy(&chk_bad.stderr);
        assert!(
            !stderr_str.contains("evil\ninjected")
                && !stderr_str.contains("rel\ninjected")
                && !stderr_str.contains("W017"),
            "control char must be rejected before W017 interpolation: {stderr_str:?}"
        );
        assert!(!chk_bad.stderr.contains(&0x07));
    }

    // 3. Control char embedded inside KDL config `ai-publish.storage` is also refused before W017.
    let bad_kdl = "server {\n    listen \":443\"\n    tls { cert \"/etc/miraserve/certs/a.crt\"; key \"/etc/miraserve/certs/a.key\" }\n}\nsite \"bad.example.com\" {\n    ai-publish {\n        storage \"/var/lib/miraserve/releases/bad\\u{0007}store\"\n        require-signature \"ed25519:/etc/miraserve/deploy.pub\"\n    }\n}\n";
    let mut child = Command::new(miraserve_bin())
        .args(["check", "--writable-set", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(bad_kdl.as_bytes())?;
    }
    let bad_kdl_out = child.wait_with_output()?;
    assert!(!bad_kdl_out.status.success());
    assert_eq!(bad_kdl_out.stdout, [] as [u8; 0]);
    assert!(!bad_kdl_out.stderr.contains(&0x07));

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)]
fn check_writable_set_matches_run_flags_quarantine_and_uncreatable_tenant() -> TestResult {
    use std::os::unix::fs::PermissionsExt as _;

    let base = std::env::temp_dir().join(format!("miraserve-ws-parity-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let docroot = base.join("www");
    let existing_logs = base.join("logs-existing");
    let owner_good = base.join("tenants/good");
    let owner_bad = base.join("tenants/bad");
    let good_www = owner_good.join("public_html");
    let ro_parent = owner_good.join("readonly-parent");
    let bad_www_escape = owner_bad.join("public_html");
    let bad_publish = owner_bad.join("releases");
    std::fs::create_dir_all(&docroot)?;
    std::fs::create_dir_all(&existing_logs)?;
    std::fs::create_dir_all(&good_www)?;
    std::fs::create_dir_all(&ro_parent)?;
    std::fs::create_dir_all(&owner_bad)?;
    std::fs::create_dir_all(&bad_publish)?;
    // Tenant `bad` tries to escape `owner-dir` into `/etc`: startup quarantines it, yet under the
    // Round-4 superset rule (Codex Round-3 P1 #1c), ANY site quarantined during classification
    // must still have its candidate writable paths reported as `writable-missing landlock <path>`
    // because `run` on a healthier moment may grant them.
    std::os::unix::fs::symlink("/etc", &bad_www_escape)?;

    let canon_base = std::fs::canonicalize(&base)?;
    let canon_docroot = std::fs::canonicalize(&docroot)?;
    let canon_existing_logs = std::fs::canonicalize(&existing_logs)?;
    let missing_logs_dir = canon_base.join("logs-missing");
    let uncreatable_publish = std::fs::canonicalize(&ro_parent)?.join("uncreatable-store");

    let running_as_root = std::process::Command::new("id")
        .arg("-u")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "0");
    if !running_as_root {
        std::fs::set_permissions(&ro_parent, std::fs::Permissions::from_mode(0o555))?;
    }

    let kdl = format!(
        r#"
server {{
    listen ":443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/keys/a.key" }}
}}
site "main.example.com" {{
    root "{}"
}}
site "tenant-good.example.com" {{
    owner-dir "{}"
    root "{}"
    ai-publish {{
        storage "{}"
        require-signature "ed25519:/etc/miraserve/deploy.pub"
    }}
}}
site "tenant-bad.example.com" {{
    owner-dir "{}"
    root "{}"
    ai-publish {{
        storage "{}"
        require-signature "ed25519:/etc/miraserve/deploy.pub"
    }}
}}
"#,
        canon_docroot.display(),
        std::fs::canonicalize(&owner_good)?.display(),
        std::fs::canonicalize(&good_www)?.display(),
        uncreatable_publish.display(),
        std::fs::canonicalize(&owner_bad)?.display(),
        bad_www_escape.display(),
        std::fs::canonicalize(&bad_publish)?.display(),
    );

    // 1. Rotating --log-file (existing dir) + --access-log (missing dir) with --log-max-bytes > 0.
    let mut child = Command::new(miraserve_bin())
        .args([
            "check",
            "--writable-set",
            "--log-max-bytes",
            "1048576",
            "--log-file",
        ])
        .arg(canon_existing_logs.join("server.log"))
        .arg("--access-log")
        .arg(missing_logs_dir.join("access.log"))
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(kdl.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lines: Vec<String> = String::from_utf8(out.stdout)?
        .lines()
        .map(str::to_owned)
        .collect();
    assert!(
        lines.first().is_some_and(|l| l.starts_with("landlock ")),
        "expected landlock state line: {lines:?}"
    );
    #[cfg(target_os = "linux")]
    if lines
        .first()
        .is_some_and(|l| l.starts_with("landlock enforced ") || l.starts_with("landlock partial "))
    {
        assert!(
            lines
                .iter()
                .any(|l| l == &format!("writable landlock {}", canon_existing_logs.display())),
            "existing rotating log dir must appear: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l == &format!("writable-missing landlock {}", missing_logs_dir.display())),
            "missing rotating log dir must appear as writable-missing: {lines:?}"
        );
        // Round-4 item 3c superset rule: quarantined tenant site's candidate publish store MUST
        // still be reported as `writable-missing landlock <path>`.
        let canon_bad_publish = std::fs::canonicalize(&bad_publish)?;
        assert!(
            lines
                .iter()
                .any(|l| l == &format!("writable-missing landlock {}", canon_bad_publish.display())),
            "quarantined tenant site's publish store must be emitted as writable-missing under superset rule: {lines:?}"
        );
        // Codex Round-2 P1 #6: missing tenant-only publish store MUST appear as `writable-missing`
        // even when its parent is read-only (0555) to the inspecting user (no accessat heuristic).
        assert!(
            lines.iter().any(|l| {
                l == &format!(
                    "writable-missing landlock {}",
                    uncreatable_publish.display()
                )
            }),
            "missing tenant-only publish store must appear as writable-missing under superset rule: {lines:?}"
        );
    }

    // 2. With --log-max-bytes 0 (no rotation), log directories receive NO Landlock RW grant.
    let mut child = Command::new(miraserve_bin())
        .args([
            "check",
            "--writable-set",
            "--log-max-bytes",
            "0",
            "--log-file",
        ])
        .arg(canon_existing_logs.join("server.log"))
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(kdl.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    assert!(out.status.success());
    let no_rot_stdout = String::from_utf8(out.stdout)?;
    assert!(
        !no_rot_stdout.contains(&canon_existing_logs.to_string_lossy().into_owned()),
        "non-rotating log dir must not appear in writable-set: {no_rot_stdout}"
    );

    // 3. Rotating log overlapping docroot MUST FAIL `check --writable-set` (matching `run`).
    let mut child = Command::new(miraserve_bin())
        .args([
            "check",
            "--writable-set",
            "--log-max-bytes",
            "1048576",
            "--access-log",
        ])
        .arg(canon_docroot.join("access.log"))
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(kdl.as_bytes())?;
    }
    let overlap_out = child.wait_with_output()?;
    assert!(
        !overlap_out.status.success(),
        "rotating log inside docroot must fail check --writable-set just like `run`"
    );
    assert_eq!(overlap_out.stdout, [] as [u8; 0]);

    // 4. Non-tenant site with unsafe symlink docroot into `/etc` MUST FAIL `check --writable-set`.
    let unsafe_nontenant_kdl = format!(
        r#"
server {{
    listen ":443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/keys/a.key" }}
}}
site "unsafe.example.com" {{
    root "{}"
}}
"#,
        bad_www_escape.display()
    );
    let mut child = Command::new(miraserve_bin())
        .args(["check", "--writable-set", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(unsafe_nontenant_kdl.as_bytes())?;
    }
    let unsafe_out = child.wait_with_output()?;
    assert!(
        !unsafe_out.status.success(),
        "non-tenant unsafe docroot must fail check --writable-set just like `run`"
    );
    assert_eq!(unsafe_out.stdout, [] as [u8; 0]);

    let _ = std::fs::set_permissions(&ro_parent, std::fs::Permissions::from_mode(0o700));
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn writable_set_propagates_stdout_write_errors_on_dev_full() -> TestResult {
    let dev_full_check = std::fs::OpenOptions::new().write(true).open("/dev/full")?;
    let chk_status = Command::new(miraserve_bin())
        .args(["check", "--writable-set"])
        .arg(example_config_path())
        .stdout(Stdio::from(dev_full_check))
        .stderr(Stdio::piped())
        .status()?;
    assert!(
        !chk_status.success(),
        "check --writable-set must exit non-zero when writing to /dev/full fails"
    );

    let dev_full_svc = std::fs::OpenOptions::new().write(true).open("/dev/full")?;
    let svc_status = Command::new(miraserve_bin())
        .args([
            "service",
            "generate",
            "--target",
            "systemd",
            "--print-writable-set",
        ])
        .stdout(Stdio::from(dev_full_svc))
        .stderr(Stdio::piped())
        .status()?;
    assert!(
        !svc_status.success(),
        "service generate --print-writable-set must exit non-zero when writing to /dev/full fails"
    );
    Ok(())
}

/// Codex Round-3 P1 #3 & P2 (FIFO config):
/// 1. `--target systemd-keyd --keyd-socket "/run/miraserve-keyd/signer A.sock"` produces exact
///    `74a8243` bytes on stdout and exact tmpfiles note on stderr, and reports `/run/miraserve-keyd`
///    under `--print-writable-set`.
/// 2. `service generate --target systemd --print-writable-set --config <fifo>` never blocks on a
///    FIFO config with no writer because the report branch runs before config reads.
#[test]
#[allow(clippy::too_many_lines)]
fn service_generate_keyd_spaced_filename_matches_74a8243_and_fifo_config_does_not_block()
-> TestResult {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let pinned_default_keyd = String::from_utf8(std::fs::read(
        repo_root.join("packaging/systemd/miraserve-keyd.service"),
    )?)?;
    let expected_spaced_unit = pinned_default_keyd.replace(
        "--socket \"/run/miraserve-keyd/keyd.sock\"",
        "--socket \"/run/miraserve-keyd/signer A.sock\"",
    );
    assert_ne!(expected_spaced_unit, pinned_default_keyd);

    let out = Command::new(miraserve_bin())
        .args([
            "service",
            "generate",
            "--target",
            "systemd-keyd",
            "--keyd-socket",
            "/run/miraserve-keyd/signer A.sock",
        ])
        .output()?;
    assert!(
        out.status.success(),
        "spaced keyd socket filename must be accepted as at 74a8243, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8(out.stdout)?,
        expected_spaced_unit,
        "generated unit bytes must match 74a8243 byte-for-byte"
    );
    assert_eq!(
        String::from_utf8(out.stderr)?,
        "note: install the companion tmpfiles.d rule into /etc/tmpfiles.d/miraserve-keyd.conf (or pass --tmpfiles-output <path>): d /run/miraserve-keyd 2750 miraserve-keyd miraserve -\n"
    );

    let ws = Command::new(miraserve_bin())
        .args([
            "service",
            "generate",
            "--target",
            "systemd-keyd",
            "--keyd-socket",
            "/run/miraserve-keyd/signer A.sock",
            "--print-writable-set",
        ])
        .output()?;
    assert!(
        ws.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&ws.stderr)
    );
    let ws_lines: Vec<String> = String::from_utf8(ws.stdout)?
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        ws_lines,
        vec![
            "writable unit /run/miraserve-keyd",
            "writable unit-private-tmp /tmp",
            "writable unit-private-tmp /var/tmp",
        ]
    );

    #[cfg(unix)]
    {
        let base = std::env::temp_dir().join(format!("miraserve-svc-fifo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base)?;
        let fifo = base.join("config.fifo");
        let mkfifo_status = Command::new("mkfifo").arg(&fifo).status()?;
        assert!(mkfifo_status.success(), "mkfifo failed");

        let mut child = Command::new(miraserve_bin())
            .args([
                "service",
                "generate",
                "--target",
                "systemd",
                "--print-writable-set",
                "--config",
            ])
            .arg(&fifo)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let exited = loop {
            if let Some(status) = child.try_wait()? {
                break Some(status);
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        let status =
            exited.ok_or("service generate --print-writable-set blocked on FIFO --config")?;
        assert!(
            status.success(),
            "FIFO --config should succeed without reading it"
        );
        let mut stdout_str = String::new();
        if let Some(mut stdout) = child.stdout.take() {
            std::io::Read::read_to_string(&mut stdout, &mut stdout_str)?;
        }
        assert!(
            stdout_str.contains("writable unit /var/lib/miraserve"),
            "unexpected stdout: {stdout_str:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
    Ok(())
}

/// Codex Round-3 P2 #1 & #3:
/// 1. Hard rejections (`--acme-dir /etc`, `--acme-dir /etc/sub`, and a cleanly spelled
///    `ai-publish.storage` symlink to `/etc`) exit non-zero with empty stdout in non-strict
///    `check --writable-set`.
/// 2. Every line on stderr and stdout in writable-set mode escapes C0, DEL, and C1 control
///    characters — including fields outside writable-path validation such as an escaped KDL BEL,
///    ESC, DEL, and C1 CSI in `site.tls.cert` (W026) or KDL validation errors.
#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)]
fn writable_set_hard_rejections_and_c0_del_c1_sanitizer() -> TestResult {
    let base = std::env::temp_dir().join(format!("miraserve-ws-r4-p2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let tenant_home = base.join("tenants/alice");
    let tenant_root = tenant_home.join("public_html");
    std::fs::create_dir_all(&tenant_root)?;
    let canon_base = std::fs::canonicalize(&base)?;
    let canon_home = std::fs::canonicalize(&tenant_home)?;
    let canon_root = std::fs::canonicalize(&tenant_root)?;
    let link_to_etc = canon_base.join("clean-store-link");
    std::os::unix::fs::symlink("/etc", &link_to_etc)?;

    // 1. `--acme-dir /etc` and `--acme-dir /etc/acme-sub` must fail non-strict `check --writable-set`
    //    with empty stdout (even though `insert_exact_dir` filters them out of `read_write_paths`).
    let acme_kdl = r#"
server {
    listen ":443"
    tls { acme { email "ops@example.com" } }
}
site "acme.example.com" {
    root "/var/www/acme"
}
"#;
    for bad_acme in ["/etc", "/etc/acme-sub"] {
        let mut child = Command::new(miraserve_bin())
            .args(["check", "--writable-set", "--acme-dir", bad_acme, "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(acme_kdl.as_bytes())?;
        }
        let out = child.wait_with_output()?;
        assert!(
            !out.status.success(),
            "non-strict check --writable-set must refuse --acme-dir {bad_acme}, stdout={:?}, stderr={:?}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout, [] as [u8; 0]);
    }

    // 2. Cleanly spelled `ai-publish.storage` symlink to `/etc` must fail non-strict
    //    `check --writable-set` with empty stdout (never W017 + exit 0).
    let pub_etc_kdl = format!(
        r#"
server {{
    listen ":443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/keys/a.key" }}
}}
site "pubetc.example.com" {{
    root "/var/www/pubetc"
    ai-publish {{
        storage "{}"
        require-signature "ed25519:/etc/miraserve/deploy.pub"
    }}
}}
"#,
        link_to_etc.display()
    );
    let mut child = Command::new(miraserve_bin())
        .args(["check", "--writable-set", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(pub_etc_kdl.as_bytes())?;
    }
    let pub_out = child.wait_with_output()?;
    assert!(
        !pub_out.status.success(),
        "publish-store symlink to /etc must fail check --writable-set, stdout={:?}, stderr={:?}",
        String::from_utf8_lossy(&pub_out.stdout),
        String::from_utf8_lossy(&pub_out.stderr)
    );
    assert_eq!(pub_out.stdout, [] as [u8; 0]);

    // 3. Codex Round-3 P2 #3 exact counterexample: valid `owner-dir` site with missing
    //    `site.tls.cert` containing escaped KDL C0 BEL (\u{0007}), ESC (\u{001b}), DEL (\u{007f}),
    //    and C1 CSI (\u{009b}) produces W026 on stderr with ZERO raw C0/DEL/C1 chars anywhere.
    let has_raw_ctrl = |s: &str| {
        s.chars()
            .any(|ch| ch != '\n' && matches!(ch as u32, 0x00..=0x1F | 0x7F..=0x9F))
    };
    let cert_ctrl_kdl = format!(
        "server {{\n    listen \":443\"\n    tls {{ cert \"/etc/miraserve/certs/a.crt\"; key \"/etc/miraserve/keys/a.key\" }}\n}}\nsite \"alice.example.com\" {{\n    owner-dir \"{}\"\n    root \"{}\"\n    tls {{\n        cert \"/nonexistent/bad\\u{{0007}}\\u{{001b}}\\u{{007f}}\\u{{009b}}.crt\"\n        key \"/nonexistent/key.pem\"\n    }}\n}}\n",
        canon_home.display(),
        canon_root.display(),
    );
    let mut child = Command::new(miraserve_bin())
        .args(["check", "--writable-set", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(cert_ctrl_kdl.as_bytes())?;
    }
    let cert_out = child.wait_with_output()?;
    assert!(
        cert_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&cert_out.stderr)
    );
    let cert_stderr = String::from_utf8(cert_out.stderr)?;
    let cert_stdout = String::from_utf8(cert_out.stdout)?;
    assert!(
        cert_stderr.contains("W026"),
        "expected W026 for missing tenant cert, got: {cert_stderr:?}"
    );
    assert!(
        !has_raw_ctrl(&cert_stderr),
        "raw C0/DEL/C1 control char leaked to stderr: {cert_stderr:?}"
    );
    assert!(
        !has_raw_ctrl(&cert_stdout),
        "raw C0/DEL/C1 control char leaked to stdout: {cert_stdout:?}"
    );

    // 4. KDL validation error carrying raw C0/DEL/C1 chars in source also produces zero raw
    //    control chars on stderr and empty stdout.
    let bad_syntax_kdl = "server {\n    listen \"bad\x07\x1b\x7f\u{009b}:443\"\n}\n";
    let mut child = Command::new(miraserve_bin())
        .args(["check", "--writable-set", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(bad_syntax_kdl.as_bytes())?;
    }
    let syntax_out = child.wait_with_output()?;
    assert!(!syntax_out.status.success());
    assert_eq!(syntax_out.stdout, [] as [u8; 0]);
    let syntax_stderr = String::from_utf8(syntax_out.stderr)?;
    assert!(
        !has_raw_ctrl(&syntax_stderr),
        "raw C0/DEL/C1 control char leaked to stderr on validation error: {syntax_stderr:?}"
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Codex Round-3 P1 #1 (descriptor pressure under lowered `RLIMIT_NOFILE`):
/// 1. Dropping the preliminary warning-only policy before the startup pass ensures Site A
///    (300 existing FastCGI sockets whose root contains the config dir) is quarantined before
///    startup policy construction, so healthy Site B's publish store is still pinned and emitted
///    as `writable landlock` (and Site A's sockets appear as `writable-missing landlock` under
///    the quarantined-site superset rule).
/// 2. Genuine `EMFILE` during startup policy construction (a non-tenant site holding 180 existing
///    sockets under `RLIMIT_NOFILE=128` alongside healthy tenant Site B) fails inspection cleanly
///    (non-zero exit, empty stdout, clear resource-limit diagnostic) instead of misclassifying
///    Site B as absent.
#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)]
fn writable_set_under_lowered_rlimit_nofile_preserves_superset_and_fails_on_emfile() -> TestResult {
    use std::fmt::Write as _;

    // Keep socket paths short so Unix `sun_path` (~104 bytes on macOS) is never exceeded.
    let base = std::env::temp_dir().join(format!("ms-rl-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let overlap_home = base.join("a");
    let overlap_real_root = overlap_home.join("real");
    let overlap_root = overlap_home.join("w");
    let healthy_home = base.join("b");
    let healthy_root = healthy_home.join("w");
    let healthy_store = healthy_home.join("r");
    let socks_dir = base.join("s");
    std::fs::create_dir_all(&overlap_real_root)?;
    std::os::unix::fs::symlink(&overlap_real_root, &overlap_root)?;
    std::fs::create_dir_all(&healthy_root)?;
    std::fs::create_dir_all(&healthy_store)?;
    std::fs::create_dir_all(&socks_dir)?;

    let canon_overlap_home = std::fs::canonicalize(&overlap_home)?;
    let canon_overlap_real = std::fs::canonicalize(&overlap_real_root)?;
    let overlap_root_link = canon_overlap_home.join("w");
    let canon_healthy_home = std::fs::canonicalize(&healthy_home)?;
    let canon_healthy_root = std::fs::canonicalize(&healthy_root)?;
    let canon_healthy_store = std::fs::canonicalize(&healthy_store)?;
    let canon_socks = std::fs::canonicalize(&socks_dir)?;

    // Create 300 distinct existing socket paths (each bound and immediately closed in this test
    // process so the test process itself holds 0 extra fds).
    let mut sock_paths = Vec::with_capacity(300);
    for i in 0..300_usize {
        let p = canon_socks.join(format!("{i}.s"));
        let _listener = std::os::unix::net::UnixListener::bind(&p)?;
        sock_paths.push(p);
    }

    // Scenario A (Codex P1 #1 exact counterexample): Site A's root is a symlink inside its own
    // `owner-dir` (`a/w -> a/real`) while the config file lives in `a/real/cfg/miraserve.kdl`.
    // Lexical config parsing succeeds and `quarantine_inaccessible_tenant_roots` accepts Site A,
    // so the preliminary warning-only policy includes Site A's 300 sockets (the warning pass
    // extracts only `.warnings` and drops its descriptors before the reported startup policy is
    // built); then `quarantine_unsafe_sites` resolves the symlink, detects the config-dir overlap,
    // and quarantines Site A BEFORE `prepare_startup_policy` builds the reported policy.
    // Because the reported policy itself encounters no detected resource failure, Scenario A
    // succeeds with healthy Site B pinned and quarantined Site A's sockets reported as
    // `writable-missing` (no candidate omitted).
    let real_cfg_dir = canon_overlap_real.join("cfg");
    std::fs::create_dir_all(&real_cfg_dir)?;
    let cfg_inside_a = real_cfg_dir.join("miraserve.kdl");
    let mut kdl_a = String::from(
        "server {\n    listen \":443\"\n    tls { cert \"/etc/miraserve/certs/a.crt\"; key \"/etc/miraserve/keys/a.key\" }\n}\n",
    );
    let _ = writeln!(
        kdl_a,
        "site \"a.example.com\" {{\n    owner-dir \"{}\"\n    root \"{}\"",
        canon_overlap_home.display(),
        overlap_root_link.display()
    );
    for (i, sp) in sock_paths.iter().enumerate() {
        let _ = writeln!(
            kdl_a,
            "    route \"/r{i}/*\" {{ fastcgi-pass \"unix:{}\" }}",
            sp.display()
        );
    }
    kdl_a.push_str("}\n");
    let _ = writeln!(
        kdl_a,
        "site \"b.example.com\" {{\n    owner-dir \"{}\"\n    root \"{}\"\n    ai-publish {{\n        storage \"{}\"\n        require-signature \"ed25519:/etc/miraserve/deploy.pub\"\n    }}\n}}",
        canon_healthy_home.display(),
        canon_healthy_root.display(),
        canon_healthy_store.display()
    );
    std::fs::write(&cfg_inside_a, &kdl_a)?;

    let out_a = Command::new("/bin/sh")
        .args([
            "-c",
            "ulimit -S -n \"$1\" && shift && exec \"$@\"",
            "--",
            "256",
        ])
        .arg(miraserve_bin())
        .args(["check", "--writable-set"])
        .arg(&cfg_inside_a)
        .output()?;
    assert!(
        out_a.status.success(),
        "dropping preliminary policy fds must allow Site A quarantine + Site B pinning under RLIMIT_NOFILE=256, stderr: {}",
        String::from_utf8_lossy(&out_a.stderr)
    );
    let stdout_a = String::from_utf8(out_a.stdout)?;
    let lines_a: Vec<&str> = stdout_a.lines().collect();
    #[cfg(target_os = "linux")]
    if lines_a
        .first()
        .is_some_and(|l| l.starts_with("landlock enforced ") || l.starts_with("landlock partial "))
    {
        let expected_b = format!("writable landlock {}", canon_healthy_store.display());
        assert!(
            lines_a.iter().any(|l| *l == expected_b),
            "healthy tenant Site B's publish store must be pinned and reported under RLIMIT_NOFILE=256 (never silently omitted): {lines_a:?}"
        );
        let first_a_sock = format!(
            "writable-missing landlock {}",
            sock_paths.first().ok_or("missing sock")?.display()
        );
        assert!(
            lines_a.iter().any(|l| *l == first_a_sock),
            "quarantined Site A's candidate socket must appear as writable-missing under superset rule: {lines_a:?}"
        );
    }
    #[cfg(not(target_os = "linux"))]
    assert_eq!(lines_a, vec!["landlock unavailable"]);

    // Scenario B: genuine EMFILE during startup policy building (non-tenant site with 180 existing
    // sockets under RLIMIT_NOFILE=128 alongside healthy tenant Site B) MUST fail inspection with
    // non-zero exit, empty stdout, and a clear diagnostic (never exit 0 omitting Site B).
    let cfg_emfile = base.join("emfile.kdl");
    let mut kdl_b = String::from(
        "server {\n    listen \":443\"\n    tls { cert \"/etc/miraserve/certs/a.crt\"; key \"/etc/miraserve/keys/a.key\" }\n}\n",
    );
    let _ = writeln!(
        kdl_b,
        "site \"main.example.com\" {{\n    root \"{}\"",
        canon_overlap_real.display()
    );
    for (i, sp) in sock_paths.iter().take(180).enumerate() {
        let _ = writeln!(
            kdl_b,
            "    route \"/r{i}/*\" {{ fastcgi-pass \"unix:{}\" }}",
            sp.display()
        );
    }
    kdl_b.push_str("}\n");
    let _ = writeln!(
        kdl_b,
        "site \"b.example.com\" {{\n    owner-dir \"{}\"\n    root \"{}\"\n    ai-publish {{\n        storage \"{}\"\n        require-signature \"ed25519:/etc/miraserve/deploy.pub\"\n    }}\n}}",
        canon_healthy_home.display(),
        canon_healthy_root.display(),
        canon_healthy_store.display()
    );
    std::fs::write(&cfg_emfile, &kdl_b)?;

    #[cfg(target_os = "linux")]
    {
        let out_b = Command::new("/bin/sh")
            .args([
                "-c",
                "ulimit -S -n \"$1\" && shift && exec \"$@\"",
                "--",
                "128",
            ])
            .arg(miraserve_bin())
            .args(["check", "--writable-set"])
            .arg(&cfg_emfile)
            .output()?;
        assert!(
            !out_b.status.success(),
            "EMFILE during startup policy construction must fail check --writable-set, stdout={:?}, stderr={:?}",
            String::from_utf8_lossy(&out_b.stdout),
            String::from_utf8_lossy(&out_b.stderr)
        );
        assert_eq!(
            out_b.stdout,
            [] as [u8; 0],
            "EMFILE inspection failure must leave stdout empty"
        );
        let stderr_b = String::from_utf8_lossy(&out_b.stderr);
        assert!(
            stderr_b.contains("resource limit") || stderr_b.contains("Too many open files"),
            "expected clear EMFILE/resource diagnostic on stderr, got: {stderr_b:?}"
        );
    }

    let _ = &cfg_emfile;
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Round-5 structural compatibility proof (Codex Round-4 P1 #1, #2, #3):
/// Plain `miraserve service generate` (without `--print-writable-set`) accepts every input
/// `74a8243` accepted and renders the exact stdout and stderr bytes captured from the `74a8243`
/// binary across the default invocation of all four targets (`systemd`, `systemd-keyd`,
/// `launchd`, `windows`) and all nine Codex Round-4 inputs.
#[test]
#[allow(clippy::too_many_lines)]
fn plain_service_generate_matches_74a8243_bytes_for_all_targets_and_codex_inputs() -> TestResult {
    const EXPECTED_SYSTEMD_DEFAULT: &str = concat!(
        "# Generated by `miraserve service generate --target systemd`\n",
        "# Hardened unprivileged systemd unit for MiraServe (Linux Landlock + seccomp-bpf + CAP_NET_BIND_SERVICE)\n",
        "\n",
        "[Unit]\n",
        "Description=MiraServe Memory-Safe Post-Quantum HTTPS & AI Edge Server\n",
        "Documentation=https://github.com/miraserve/miraserve\n",
        "After=network-online.target\n",
        "Wants=network-online.target\n",
        "\n",
        "[Service]\n",
        "Type=simple\n",
        "User=miraserve\n",
        "Group=miraserve\n",
        "ExecStartPre=\"/usr/bin/miraserve\" check --fs --acme-dir \"/var/lib/miraserve/acme\" \"/etc/miraserve/conf/miraserve.kdl\"\n",
        "ExecStart=\"/usr/bin/miraserve\" run \"/etc/miraserve/conf/miraserve.kdl\" --acme-dir \"/var/lib/miraserve/acme\" --pid-file /run/miraserve/miraserve.pid\n",
        "ExecReload=\"/usr/bin/miraserve\" reload --pid-file /run/miraserve/miraserve.pid --acme-dir \"/var/lib/miraserve/acme\" --config \"/etc/miraserve/conf/miraserve.kdl\"\n",
        "KillSignal=SIGTERM\n",
        "# Derived from `server.timeouts.graceful-drain` + 15s grace (override with `--graceful-drain <secs>`).\n",
        "TimeoutStopSec=45s\n",
        "Restart=on-failure\n",
        "RestartSec=3s\n",
        "LimitNOFILE=1048576\n",
        "\n",
        "# Privilege separation: bind :80/:443 without ever running as UID 0 (Threat Model T2/T5)\n",
        "AmbientCapabilities=CAP_NET_BIND_SERVICE\n",
        "CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n",
        "NoNewPrivileges=yes\n",
        "\n",
        "# Filesystem & kernel confinement (layered beneath MiraServe's in-process Landlock + seccomp-bpf)\n",
        "RuntimeDirectory=miraserve\n",
        "RuntimeDirectoryMode=0750\n",
        "RuntimeDirectoryPreserve=yes\n",
        "StateDirectory=miraserve\n",
        "StateDirectoryMode=0750\n",
        "# File logs (`--log-file`, `--access-log`) and their rotation go to /var/log/miraserve.\n",
        "LogsDirectory=miraserve\n",
        "LogsDirectoryMode=0750\n",
        "ProtectSystem=strict\n",
        "ProtectHome=yes\n",
        "PrivateTmp=yes\n",
        "PrivateDevices=yes\n",
        "ProtectKernelTunables=yes\n",
        "ProtectKernelModules=yes\n",
        "ProtectKernelLogs=yes\n",
        "ProtectControlGroups=yes\n",
        "ProtectClock=yes\n",
        "ProtectHostname=yes\n",
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n",
        "RestrictNamespaces=yes\n",
        "RestrictRealtime=yes\n",
        "RestrictSUIDSGID=yes\n",
        "LockPersonality=yes\n",
        "# Set MemoryDenyWriteExecute=yes (via --no-wasm) if Wasmtime JIT plugins are not used.\n",
        "MemoryDenyWriteExecute=no\n",
        "SystemCallArchitectures=native\n",
        "# Unconditionally block worker access to the isolated `miraserve-keyd` private-key vault.\n",
        "# Starter/in-process TLS certificates live under `/etc/miraserve/certs/` instead.\n",
        "InaccessiblePaths=-/etc/miraserve/keys\n",
        "ReadWritePaths=/var/lib/miraserve /run/miraserve\n",
        "UMask=0027\n",
        "\n",
        "[Install]\n",
        "WantedBy=multi-user.target\n",
    );

    const EXPECTED_SYSTEMD_KEYD_DEFAULT: &str = concat!(
        "# Generated by `miraserve service generate --target systemd-keyd`\n",
        "# Split-privilege TLS signing vault (Threat Model T2: distinct UID/GID `miraserve-keyd`;\n",
        "# private keys under /etc/miraserve/keys (0700 miraserve-keyd:miraserve-keyd) never enter worker memory)\n",
        "\n",
        "[Unit]\n",
        "Description=MiraServe Split-Privilege TLS Signing Vault (miraserve-keyd)\n",
        "Documentation=https://github.com/miraserve/miraserve\n",
        "Before=miraserve.service\n",
        "\n",
        "[Service]\n",
        "Type=simple\n",
        "User=miraserve-keyd\n",
        "Group=miraserve-keyd\n",
        "SupplementaryGroups=miraserve\n",
        "# R5-PKG-3 & R6-PKG-1: Provision /run/miraserve-keyd via systemd-tmpfiles (2750 miraserve-keyd:miraserve)\n",
        "# instead of RuntimeDirectory=, searching /etc/tmpfiles.d and /usr/lib/tmpfiles.d.\n",
        "# Companion tmpfiles.d rule: d /run/miraserve-keyd 2750 miraserve-keyd miraserve -\n",
        "ExecStartPre=+/usr/bin/systemd-tmpfiles --create --prefix=/run/miraserve-keyd\n",
        "ExecStart=\"/usr/bin/miraserve\" keyd --socket \"/run/miraserve-keyd/keyd.sock\" --config \"/etc/miraserve/conf/miraserve.kdl\" --allow-peer-user miraserve\n",
        "KillSignal=SIGTERM\n",
        "TimeoutStopSec=15s\n",
        "Restart=on-failure\n",
        "RestartSec=2s\n",
        "\n",
        "# Zero capabilities (Threat Model T2)\n",
        "CapabilityBoundingSet=\n",
        "AmbientCapabilities=\n",
        "NoNewPrivileges=yes\n",
        "# Zero network access: communicates ONLY over the 0660 + exact-UID SO_PEERCRED Unix socket\n",
        "# inside /run/miraserve-keyd (2750 setgid miraserve-keyd:miraserve; only UID `miraserve` authorized).\n",
        "PrivateNetwork=yes\n",
        "RestrictAddressFamilies=AF_UNIX\n",
        "\n",
        "# Strict filesystem & memory isolation (/run/miraserve-keyd is managed by tmpfiles.d)\n",
        "ProtectSystem=strict\n",
        "ProtectHome=yes\n",
        "PrivateTmp=yes\n",
        "PrivateDevices=yes\n",
        "ProtectKernelTunables=yes\n",
        "ProtectKernelModules=yes\n",
        "ProtectKernelLogs=yes\n",
        "ProtectControlGroups=yes\n",
        "ProtectClock=yes\n",
        "ProtectHostname=yes\n",
        "RestrictNamespaces=yes\n",
        "RestrictRealtime=yes\n",
        "RestrictSUIDSGID=yes\n",
        "LockPersonality=yes\n",
        "MemoryDenyWriteExecute=yes\n",
        "SystemCallArchitectures=native\n",
        "ReadOnlyPaths=/etc/miraserve\n",
        "ReadWritePaths=-/run/miraserve-keyd\n",
        "UMask=0027\n",
        "\n",
        "[Install]\n",
        "WantedBy=multi-user.target\n",
    );

    const EXPECTED_LAUNCHD_DEFAULT: &str = concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
        "<!-- Generated by `miraserve service generate --target launchd` -->\n",
        "<plist version=\"1.0\">\n",
        "<dict>\n",
        "    <key>Label</key>\n",
        "    <string>app.miraserve.server</string>\n",
        "\n",
        "    <key>UserName</key>\n",
        "    <string>_www</string>\n",
        "    <key>GroupName</key>\n",
        "    <string>_www</string>\n",
        "\n",
        "    <key>ProgramArguments</key>\n",
        "    <array>\n",
        "        <string>/opt/homebrew/bin/miraserve</string>\n",
        "        <string>run</string>\n",
        "        <string>/opt/homebrew/etc/miraserve/miraserve.kdl</string>\n",
        "        <string>--acme-dir</string>\n",
        "        <string>/opt/homebrew/var/lib/miraserve/acme</string>\n",
        "    </array>\n",
        "\n",
        "    <key>RunAtLoad</key>\n",
        "    <true/>\n",
        "    <key>KeepAlive</key>\n",
        "    <dict>\n",
        "        <key>SuccessfulExit</key>\n",
        "        <false/>\n",
        "    </dict>\n",
        "    <key>ExitTimeOut</key>\n",
        "    <integer>45</integer>\n",
        "\n",
        "    <key>SoftResourceLimits</key>\n",
        "    <dict>\n",
        "        <key>NumberOfFiles</key>\n",
        "        <integer>65536</integer>\n",
        "    </dict>\n",
        "    <key>HardResourceLimits</key>\n",
        "    <dict>\n",
        "        <key>NumberOfFiles</key>\n",
        "        <integer>262144</integer>\n",
        "    </dict>\n",
        "\n",
        "    <key>StandardOutPath</key>\n",
        "    <string>/opt/homebrew/var/log/miraserve.out.log</string>\n",
        "    <key>StandardErrorPath</key>\n",
        "    <string>/opt/homebrew/var/log/miraserve.err.log</string>\n",
        "</dict>\n",
        "</plist>\n",
    );

    const EXPECTED_WINDOWS_DEFAULT: &str = concat!(
        "# Generated by `miraserve service generate --target windows`\n",
        "# Development / non-production Windows boot-time Scheduled Task running under\n",
        "# NT AUTHORITY\\LOCAL SERVICE (NOTE: Scheduled Task stop performs hard termination rather\n",
        "# than graceful Win32 SCM drain; do not rely on graceful stop in production on Windows).\n",
        "#Requires -RunAsAdministrator\n",
        "Set-StrictMode -Version Latest\n",
        "$ErrorActionPreference = 'Stop'\n",
        "\n",
        "$TaskName   = 'MiraServe'\n",
        "$BinaryPath = 'C:\\Program Files\\MiraServe\\miraserve.exe'\n",
        "$ConfigPath = 'C:\\ProgramData\\MiraServe\\miraserve.kdl'\n",
        "$StateDir   = 'C:\\ProgramData\\MiraServe'\n",
        "\n",
        "if (-not (Test-Path -LiteralPath $BinaryPath)) {\n",
        "    throw \"MiraServe binary not found at $BinaryPath\"\n",
        "}\n",
        "if (-not (Test-Path -LiteralPath $ConfigPath)) {\n",
        "    throw \"MiraServe config not found at $ConfigPath\"\n",
        "}\n",
        "\n",
        "# 1. Pre-validate KDL configuration before registering or starting the task\n",
        "& $BinaryPath check $ConfigPath\n",
        "if ($LASTEXITCODE -ne 0) {\n",
        "    throw \"Configuration validation failed; aborting installation\"\n",
        "}\n",
        "\n",
        "# 2. Remove any legacy Win32 SCM service from pre-task installs to avoid port conflicts\n",
        "$LegacySvc = Get-Service -Name $TaskName -ErrorAction SilentlyContinue\n",
        "if ($null -ne $LegacySvc) {\n",
        "    Stop-Service -Name $TaskName -Force -ErrorAction SilentlyContinue\n",
        "    & sc.exe delete $TaskName | Out-Null\n",
        "}\n",
        "\n",
        "# 3. Ensure state/ACME/log directories exist with restricted ACLs for NT AUTHORITY\\LOCAL SERVICE (*S-1-5-19)\n",
        "New-Item -ItemType Directory -Force -Path \"$StateDir\\acme\", \"$StateDir\\releases\", \"$StateDir\\logs\" | Out-Null\n",
        "& icacls $StateDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-19:(OI)(CI)M' | Out-Null\n",
        "if ($LASTEXITCODE -ne 0) {\n",
        "    throw \"Failed to apply restricted ACLs on $StateDir\"\n",
        "}\n",
        "\n",
        "# 4. Register a boot-time Scheduled Task under NT AUTHORITY\\LOCAL SERVICE with restart-on-failure & log persistence\n",
        "$Arguments = \"run `\"$ConfigPath`\" --acme-dir `\"$StateDir\\acme`\" --log-file `\"$StateDir\\logs\\miraserve.log`\"\"\n",
        "$Action    = New-ScheduledTaskAction -Execute $BinaryPath -Argument $Arguments\n",
        "$Trigger   = New-ScheduledTaskTrigger -AtStartup\n",
        "$Principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\\LOCAL SERVICE' -LogonType ServiceAccount -RunLevel Limited\n",
        "$Settings  = New-ScheduledTaskSettingsSet `\n",
        "    -AllowStartIfOnBatteries `\n",
        "    -DontStopIfGoingOnBatteries `\n",
        "    -ExecutionTimeLimit ([TimeSpan]::Zero) `\n",
        "    -RestartCount 999 `\n",
        "    -RestartInterval (New-TimeSpan -Minutes 1) `\n",
        "    -MultipleInstances IgnoreNew\n",
        "\n",
        "Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null\n",
        "Start-ScheduledTask -TaskName $TaskName\n",
        "Write-Host \"OK: MiraServe boot task installed and started under NT AUTHORITY\\LOCAL SERVICE (logs: $StateDir\\logs\\miraserve.log).\"\n",
    );

    const EXPECTED_KEYD_TCP_TRAILING_SPACE_WITH_SECRET: &str = concat!(
        "# Generated by `miraserve service generate --target systemd-keyd`\n",
        "# Split-privilege TLS signing vault (Threat Model T2: distinct UID/GID `miraserve-keyd`;\n",
        "# private keys under /etc/miraserve/keys (0700 miraserve-keyd:miraserve-keyd) never enter worker memory)\n",
        "\n",
        "[Unit]\n",
        "Description=MiraServe Split-Privilege TLS Signing Vault (miraserve-keyd)\n",
        "Documentation=https://github.com/miraserve/miraserve\n",
        "Before=miraserve.service\n",
        "\n",
        "[Service]\n",
        "Type=simple\n",
        "User=miraserve-keyd\n",
        "Group=miraserve-keyd\n",
        "SupplementaryGroups=miraserve\n",
        "ExecStart=\"/usr/bin/miraserve\" keyd --socket \"tcp://127.0.0.1:9443 \" --config \"/etc/miraserve/conf/miraserve.kdl\" --auth-secret-file \"/etc/miraserve/keyd.secret\"\n",
        "KillSignal=SIGTERM\n",
        "TimeoutStopSec=15s\n",
        "Restart=on-failure\n",
        "RestartSec=2s\n",
        "\n",
        "# Zero capabilities (Threat Model T2)\n",
        "CapabilityBoundingSet=\n",
        "AmbientCapabilities=\n",
        "NoNewPrivileges=yes\n",
        "# Loopback TCP mode: pair with --auth-secret-file and --keyd-auth-secret-file (HMAC-SHA256).\n",
        "PrivateNetwork=no\n",
        "RestrictAddressFamilies=AF_INET AF_INET6\n",
        "\n",
        "# Strict filesystem & memory isolation (/run/miraserve-keyd is managed by tmpfiles.d)\n",
        "ProtectSystem=strict\n",
        "ProtectHome=yes\n",
        "PrivateTmp=yes\n",
        "PrivateDevices=yes\n",
        "ProtectKernelTunables=yes\n",
        "ProtectKernelModules=yes\n",
        "ProtectKernelLogs=yes\n",
        "ProtectControlGroups=yes\n",
        "ProtectClock=yes\n",
        "ProtectHostname=yes\n",
        "RestrictNamespaces=yes\n",
        "RestrictRealtime=yes\n",
        "RestrictSUIDSGID=yes\n",
        "LockPersonality=yes\n",
        "MemoryDenyWriteExecute=yes\n",
        "SystemCallArchitectures=native\n",
        "ReadOnlyPaths=/etc/miraserve\n",
        "ReadWritePaths=-/run/miraserve-keyd\n",
        "UMask=0077\n",
        "\n",
        "[Install]\n",
        "WantedBy=multi-user.target\n",
    );

    const EXPECTED_KEYD_DEFAULT_STDERR: &str = "note: install the companion tmpfiles.d rule into /etc/tmpfiles.d/miraserve-keyd.conf (or pass --tmpfiles-output <path>): d /run/miraserve-keyd 2750 miraserve-keyd miraserve -\n";

    let systemd_with_acme = |acme: &str| -> String {
        EXPECTED_SYSTEMD_DEFAULT
            .replace(
                "--acme-dir \"/var/lib/miraserve/acme\"",
                &format!("--acme-dir \"{acme}\""),
            )
            .replace(
                "ReadWritePaths=/var/lib/miraserve /run/miraserve\n",
                &format!("ReadWritePaths=/var/lib/miraserve /run/miraserve -\"{acme}\"\n"),
            )
    };

    let keyd_with_socket = |socket: &str, dir: &str| -> (String, String) {
        let stdout = EXPECTED_SYSTEMD_KEYD_DEFAULT
            .replace(
                "--socket \"/run/miraserve-keyd/keyd.sock\"",
                &format!("--socket \"{socket}\""),
            )
            .replace("/run/miraserve-keyd", dir);
        // Restore the `--socket` argument if `dir` != `/run/miraserve-keyd` and `socket` started
        // with `/run/miraserve-keyd` (no-op when `dir == "/run/miraserve-keyd"`).
        let stderr = format!(
            "note: install the companion tmpfiles.d rule into /etc/tmpfiles.d/miraserve-keyd.conf (or pass --tmpfiles-output <path>): d {dir} 2750 miraserve-keyd miraserve -\n"
        );
        (stdout, stderr)
    };

    let (keyd_double_slash_out, keyd_double_slash_err) =
        keyd_with_socket("/run/miraserve-keyd//signer.sock", "/run/miraserve-keyd");
    let (keyd_spaced_out, keyd_spaced_err) =
        keyd_with_socket("/run/miraserve-keyd/signer A.sock", "/run/miraserve-keyd");
    let (keyd_bracket_out, keyd_bracket_err) =
        keyd_with_socket("/run/keyd]/signer.sock", "/run/keyd]");
    let (keyd_nbsp_out, keyd_nbsp_err) =
        keyd_with_socket("/run/keyd\u{00a0}dir/signer.sock", "/run/keyd\u{00a0}dir");

    let cases: Vec<(&str, Vec<&str>, String, String)> = vec![
        (
            "default systemd",
            vec!["--target", "systemd"],
            EXPECTED_SYSTEMD_DEFAULT.to_owned(),
            String::new(),
        ),
        (
            "default systemd-keyd",
            vec!["--target", "systemd-keyd"],
            EXPECTED_SYSTEMD_KEYD_DEFAULT.to_owned(),
            EXPECTED_KEYD_DEFAULT_STDERR.to_owned(),
        ),
        (
            "default launchd",
            vec!["--target", "launchd"],
            EXPECTED_LAUNCHD_DEFAULT.to_owned(),
            String::new(),
        ),
        (
            "default windows",
            vec!["--target", "windows"],
            EXPECTED_WINDOWS_DEFAULT.to_owned(),
            String::new(),
        ),
        (
            "systemd --acme-dir trailing slash",
            vec![
                "--target",
                "systemd",
                "--acme-dir",
                "/var/lib/miraserve/acme/",
            ],
            systemd_with_acme("/var/lib/miraserve/acme/"),
            String::new(),
        ),
        (
            "systemd --acme-dir /./ segment",
            vec![
                "--target",
                "systemd",
                "--acme-dir",
                "/var/lib/miraserve/./acme",
            ],
            systemd_with_acme("/var/lib/miraserve/./acme"),
            String::new(),
        ),
        (
            "systemd --acme-dir // segment",
            vec![
                "--target",
                "systemd",
                "--acme-dir",
                "/var/lib//miraserve/acme",
            ],
            systemd_with_acme("/var/lib//miraserve/acme"),
            String::new(),
        ),
        (
            "systemd --acme-dir spaced path",
            vec![
                "--target",
                "systemd",
                "--acme-dir",
                "/var/lib/custom acme/state",
            ],
            systemd_with_acme("/var/lib/custom acme/state"),
            String::new(),
        ),
        (
            "systemd-keyd --keyd-socket // parent",
            vec![
                "--target",
                "systemd-keyd",
                "--keyd-socket",
                "/run/miraserve-keyd//signer.sock",
            ],
            keyd_double_slash_out,
            keyd_double_slash_err,
        ),
        (
            "systemd-keyd --keyd-socket spaced filename",
            vec![
                "--target",
                "systemd-keyd",
                "--keyd-socket",
                "/run/miraserve-keyd/signer A.sock",
            ],
            keyd_spaced_out,
            keyd_spaced_err,
        ),
        (
            "systemd-keyd --keyd-socket literal ] parent",
            vec![
                "--target",
                "systemd-keyd",
                "--keyd-socket",
                "/run/keyd]/signer.sock",
            ],
            keyd_bracket_out,
            keyd_bracket_err,
        ),
        (
            "systemd-keyd --keyd-socket U+00A0 parent",
            vec![
                "--target",
                "systemd-keyd",
                "--keyd-socket",
                "/run/keyd\u{00a0}dir/signer.sock",
            ],
            keyd_nbsp_out,
            keyd_nbsp_err,
        ),
        (
            "systemd-keyd --keyd-socket loopback TCP with trailing space + auth-secret-file",
            vec![
                "--target",
                "systemd-keyd",
                "--keyd-socket",
                "tcp://127.0.0.1:9443 ",
                "--auth-secret-file",
                "/etc/miraserve/keyd.secret",
            ],
            EXPECTED_KEYD_TCP_TRAILING_SPACE_WITH_SECRET.to_owned(),
            String::new(),
        ),
    ];

    for (label, flags, expected_stdout, expected_stderr) in cases {
        let out = Command::new(miraserve_bin())
            .args(["service", "generate"])
            .args(&flags)
            .output()?;
        assert!(
            out.status.success(),
            "plain service generate ({label}) must succeed as at 74a8243, stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            out.stdout,
            expected_stdout.as_bytes(),
            "plain service generate ({label}) stdout diverged from 74a8243 bytes"
        );
        assert_eq!(
            out.stderr,
            expected_stderr.as_bytes(),
            "plain service generate ({label}) stderr diverged from 74a8243 bytes"
        );
    }

    Ok(())
}

/// Oracle for 0.1.6 Item 2: `miraserve check --fs` warns (`W033`) when an existing exact FastCGI
/// Unix socket cannot be opened (read+write) by the checking account's effective credentials, prints
/// one plain note (not a warning) when running as root with existing sockets, ignores absent paths,
/// non-sockets, and TCP targets, never calls `connect()`, and never makes `reload --config` fail.
#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)]
fn check_fs_fastcgi_unix_socket_access_w033_and_root_note() -> TestResult {
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    // Keep socket paths short for macOS 104-byte sun_path limit.
    let base = PathBuf::from(format!("/tmp/ms-w033-{}-{nanos}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let conf_dir = base.join("c");
    let www_dir = base.join("www");
    std::fs::create_dir_all(&conf_dir)?;
    std::fs::create_dir_all(&www_dir)?;

    let ok_sock = base.join("ok.sock");
    let bad_sock = base.join("bad.sock");
    let ro_sock = base.join("ro.sock");
    let absent_sock = base.join("absent.sock");
    let regular_file = base.join("not-a-sock");
    std::fs::write(&regular_file, b"plain")?;

    let ok_listener = UnixListener::bind(&ok_sock)?;
    ok_listener.set_nonblocking(true)?;
    std::fs::set_permissions(&ok_sock, std::fs::Permissions::from_mode(0o660))?;

    let _bad_listener = UnixListener::bind(&bad_sock)?;
    std::fs::set_permissions(&bad_sock, std::fs::Permissions::from_mode(0o000))?;

    let _ro_listener = UnixListener::bind(&ro_sock)?;
    std::fs::set_permissions(&ro_sock, std::fs::Permissions::from_mode(0o400))?;

    let bad_cfg = conf_dir.join("bad.kdl");
    std::fs::write(
        &bad_cfg,
        format!(
            r#"
server {{
    listen ":443"
}}
site "php-denied.example" {{
    root "{}"
    route "*.php" {{
        fastcgi-pass "unix:{}"
    }}
}}
"#,
            www_dir.display(),
            bad_sock.display()
        ),
    )?;

    let ro_cfg = conf_dir.join("ro.kdl");
    std::fs::write(
        &ro_cfg,
        format!(
            r#"
server {{
    listen ":443"
}}
site "php-ro.example" {{
    root "{}"
    route "*.php" {{
        fastcgi-pass "unix:{}"
    }}
}}
"#,
            www_dir.display(),
            ro_sock.display()
        ),
    )?;

    #[cfg(not(target_os = "linux"))]
    let non_socket_route = format!(
        "    route \"/file/*\" {{\n        fastcgi-pass \"unix:{}\"\n    }}\n",
        regular_file.display()
    );
    #[cfg(target_os = "linux")]
    let non_socket_route = String::new();

    let clean_cfg = conf_dir.join("clean.kdl");
    std::fs::write(
        &clean_cfg,
        format!(
            r#"
server {{
    listen ":443"
}}
site "php-clean.example" {{
    root "{}"
    route "/ok/*" {{
        fastcgi-pass "unix:{}"
    }}
    route "/absent/*" {{
        fastcgi-pass "unix:{}"
    }}
{non_socket_route}    route "/tcp/*" {{
        fastcgi-pass "tcp://127.0.0.1:9000"
    }}
}}
"#,
            www_dir.display(),
            ok_sock.display(),
            absent_sock.display(),
        ),
    )?;

    let no_existing_sock_cfg = conf_dir.join("no-existing.kdl");
    std::fs::write(
        &no_existing_sock_cfg,
        format!(
            r#"
server {{
    listen ":443"
}}
site "php-no-existing.example" {{
    root "{}"
    route "/absent/*" {{
        fastcgi-pass "unix:{}"
    }}
{non_socket_route}    route "/tcp/*" {{
        fastcgi-pass "tcp://127.0.0.1:9000"
    }}
}}
"#,
            www_dir.display(),
            absent_sock.display(),
        ),
    )?;

    let regular_file_cfg = conf_dir.join("regular-file.kdl");
    std::fs::write(
        &regular_file_cfg,
        format!(
            r#"
server {{
    listen ":443"
}}
site "php-file.example" {{
    root "{}"
    route "/file/*" {{
        fastcgi-pass "unix:{}"
    }}
}}
"#,
            www_dir.display(),
            regular_file.display(),
        ),
    )?;

    let multi_sock_cfg = conf_dir.join("multi.kdl");
    std::fs::write(
        &multi_sock_cfg,
        format!(
            r#"
server {{
    listen ":443"
}}
site "php-a.example" {{
    root "{}"
    route "*.php" {{
        fastcgi-pass "unix:{}"
    }}
}}
site "php-b.example" {{
    root "{}"
    route "*.php" {{
        fastcgi-pass "unix:{}"
    }}
}}
"#,
            www_dir.display(),
            ok_sock.display(),
            www_dir.display(),
            bad_sock.display()
        ),
    )?;

    // Without `--fs`: never emits W033 or the root note.
    let no_fs = Command::new(miraserve_bin())
        .args(["check", "--strict", "--dev-tls"])
        .arg(&bad_cfg)
        .output()?;
    assert!(
        no_fs.status.success(),
        "check without --fs must pass: stderr={}",
        String::from_utf8_lossy(&no_fs.stderr)
    );
    assert!(!String::from_utf8_lossy(&no_fs.stderr).contains("W033"));
    assert!(!String::from_utf8_lossy(&no_fs.stdout).contains("root"));

    // Absent socket, non-socket regular file, and TCP target produce zero warnings and no
    // FastCGI socket access notes (without demanding an empty `notes` array, since an independent
    // note such as the Linux openat2 advisory may exist).
    let no_existing = Command::new(miraserve_bin())
        .args(["check", "--fs", "--strict", "--dev-tls", "--format", "json"])
        .arg(&no_existing_sock_cfg)
        .output()?;
    assert!(
        no_existing.status.success(),
        "absent/non-socket/tcp check --fs --strict must pass: stdout={} stderr={}",
        String::from_utf8_lossy(&no_existing.stdout),
        String::from_utf8_lossy(&no_existing.stderr)
    );
    let no_existing_json: serde_json::Value = serde_json::from_slice(&no_existing.stdout)?;
    assert!(
        no_existing_json
            .get("warnings")
            .and_then(serde_json::Value::as_array)
            .is_some_and(Vec::is_empty),
        "absent/non-socket/tcp must emit no warnings: {no_existing_json}"
    );
    assert!(
        no_existing_json
            .get("notes")
            .and_then(serde_json::Value::as_array)
            .is_none_or(|arr| arr.iter().all(|n| !n
                .as_str()
                .is_some_and(|s| s.contains("FastCGI Unix socket access")))),
        "absent/non-socket/tcp must emit no FastCGI socket access note: {no_existing_json}"
    );

    // On Linux (`socket-typing`), an existing regular file at `fastcgi-pass "unix:..."` on a
    // non-tenant site is refused with `E301` (typed reason), NEVER `W033` and NEVER a FastCGI
    // socket access note.
    #[cfg(target_os = "linux")]
    {
        let reg_out = Command::new(miraserve_bin())
            .args(["check", "--fs", "--dev-tls", "--format", "json"])
            .arg(&regular_file_cfg)
            .output()?;
        assert!(!reg_out.status.success());
        let reg_json: serde_json::Value = serde_json::from_slice(&reg_out.stdout)?;
        assert!(
            reg_json
                .get("errors")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|arr| arr.iter().any(|e| {
                    e.get("code").and_then(serde_json::Value::as_str) == Some("E301")
                        && e.get("message")
                            .and_then(serde_json::Value::as_str)
                            .is_some_and(|m| m.contains("is not a socket (found regular file)"))
                })),
            "expected E301 typed rejection for regular file on Linux: {reg_json}"
        );
        assert!(
            reg_json
                .get("warnings")
                .and_then(serde_json::Value::as_array)
                .is_none_or(|arr| arr
                    .iter()
                    .all(|w| w.get("code").and_then(serde_json::Value::as_str) != Some("W033"))),
            "non-socket must not emit W033: {reg_json}"
        );
        assert!(
            reg_json
                .get("notes")
                .and_then(serde_json::Value::as_array)
                .is_none_or(|arr| arr.iter().all(|n| !n
                    .as_str()
                    .is_some_and(|s| s.contains("FastCGI Unix socket access")))),
            "non-socket must not emit FastCGI socket access note: {reg_json}"
        );
    }
    #[cfg(not(target_os = "linux"))]
    let _ = regular_file_cfg;

    let is_root = rustix::process::geteuid().is_root();
    if is_root {
        // Running as root (euid 0): do NOT warn, print ONE plain note per run even with 2 sockets,
        // and `--strict` succeeds.
        let root_text = Command::new(miraserve_bin())
            .args(["check", "--fs", "--strict", "--dev-tls"])
            .arg(&multi_sock_cfg)
            .output()?;
        assert!(
            root_text.status.success(),
            "check --fs --strict as root must pass: stdout={} stderr={}",
            String::from_utf8_lossy(&root_text.stdout),
            String::from_utf8_lossy(&root_text.stderr)
        );
        assert!(
            !String::from_utf8_lossy(&root_text.stderr).contains("W033"),
            "root must not emit W033"
        );
        let root_stdout = String::from_utf8_lossy(&root_text.stdout);
        let note_lines: Vec<&str> = root_stdout
            .lines()
            .filter(|l| l.starts_with("note:") && l.contains("root"))
            .collect();
        assert_eq!(
            note_lines.len(),
            1,
            "expected exactly ONE plain root note in text output, got:\n{root_stdout}"
        );

        let root_json_out = Command::new(miraserve_bin())
            .args(["check", "--fs", "--strict", "--dev-tls", "--format", "json"])
            .arg(&multi_sock_cfg)
            .output()?;
        assert!(root_json_out.status.success());
        let root_json: serde_json::Value = serde_json::from_slice(&root_json_out.stdout)?;
        assert_eq!(
            root_json.get("valid").and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert!(
            root_json
                .get("warnings")
                .and_then(serde_json::Value::as_array)
                .is_some_and(Vec::is_empty)
        );
        let json_notes: Vec<&str> = root_json
            .get("notes")
            .and_then(serde_json::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(serde_json::Value::as_str)
                    .filter(|n| n.contains("root"))
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(
            json_notes.len(),
            1,
            "expected exactly ONE root note in JSON output: {root_json}"
        );

        // P2 #6: On a FAILED text run as root (e.g., `--strict` failing on an unallowed W003),
        // the root note MUST still be printed once after the warnings.
        let root_fail_cfg = conf_dir.join("root-fail.kdl");
        std::fs::write(
            &root_fail_cfg,
            format!(
                r#"
server {{
    listen ":443"
    sandbox {{ seccomp "off" }}
}}
site "php-root-fail.example" {{
    root "{}"
    route "*.php" {{
        fastcgi-pass "unix:{}"
    }}
}}
"#,
                www_dir.display(),
                ok_sock.display()
            ),
        )?;
        let root_fail = Command::new(miraserve_bin())
            .args(["check", "--fs", "--strict", "--dev-tls"])
            .arg(&root_fail_cfg)
            .output()?;
        assert!(
            !root_fail.status.success(),
            "root check --fs --strict with seccomp off must fail"
        );
        let fail_stderr = String::from_utf8_lossy(&root_fail.stderr);
        let fail_notes: Vec<&str> = fail_stderr
            .lines()
            .filter(|l| l.starts_with("note:") && l.contains("root"))
            .collect();
        assert_eq!(
            fail_notes.len(),
            1,
            "expected root note once on failed text run stderr:\n{fail_stderr}"
        );
        let warn_pos = fail_stderr
            .find("W003")
            .ok_or("missing W003 warning on failed root run")?;
        let note_pos = fail_stderr
            .find("note: FastCGI Unix socket access")
            .ok_or("missing FastCGI socket note on failed root run")?;
        assert!(
            note_pos > warn_pos,
            "root note must appear after warnings on failed text run:\n{fail_stderr}"
        );
    } else {
        let effective_uid = rustix::process::geteuid().as_raw();
        let effective_group = rustix::process::getegid().as_raw();

        // 1. Accessible 0660 socket + absent + regular file + TCP: passes `--strict`, no W033,
        //    and NEVER connects to the listening socket.
        let clean_out = Command::new(miraserve_bin())
            .args(["check", "--fs", "--strict", "--dev-tls"])
            .arg(&clean_cfg)
            .output()?;
        assert!(
            clean_out.status.success(),
            "accessible socket check --fs --strict failed: stderr={}",
            String::from_utf8_lossy(&clean_out.stderr)
        );
        assert!(
            matches!(
                ok_listener.accept(),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
            ),
            "check --fs must not call connect() on the FastCGI unix socket"
        );

        // 2. Inaccessible 0000 socket: text mode without --strict exits 0 with W033 + details + help.
        let bad_text = Command::new(miraserve_bin())
            .args(["check", "--fs", "--dev-tls"])
            .arg(&bad_cfg)
            .output()?;
        assert!(
            bad_text.status.success(),
            "check --fs without --strict must exit 0 on warning: stderr={}",
            String::from_utf8_lossy(&bad_text.stderr)
        );
        let bad_stderr = String::from_utf8_lossy(&bad_text.stderr);
        let expected_uid_gid = format!("(uid/gid {effective_uid}/{effective_group})");
        assert!(
            bad_stderr.contains("warning[W033]:")
                && bad_stderr.contains("php-denied.example")
                && bad_stderr.contains(&bad_sock.display().to_string())
                && bad_stderr.contains("0000")
                && bad_stderr.contains(
                    "requires read and write permission on the socket for the account running the check"
                )
                && bad_stderr.contains(&expected_uid_gid)
                && !bad_stderr.contains("cannot be opened")
                && bad_stderr.contains("listen.group"),
            "unexpected W033 text diagnostic:\n{bad_stderr}"
        );

        // 2b (P2 #4): Unsearchable parent directory (`metadata` fails with EACCES): emits W033
        // reporting that the path could not be reached (type and owner unknown).
        let unsearchable_dir = base.join("nosearch");
        std::fs::create_dir_all(&unsearchable_dir)?;
        let hidden_sock = unsearchable_dir.join("pool.sock");
        let _hidden_listener = UnixListener::bind(&hidden_sock)?;
        std::fs::set_permissions(&hidden_sock, std::fs::Permissions::from_mode(0o660))?;
        std::fs::set_permissions(&unsearchable_dir, std::fs::Permissions::from_mode(0o000))?;
        let unreachable_cfg = conf_dir.join("unreachable.kdl");
        std::fs::write(
            &unreachable_cfg,
            format!(
                r#"
server {{
    listen ":443"
}}
site "php-unreachable.example" {{
    root "{}"
    route "*.php" {{
        fastcgi-pass "unix:{}"
    }}
}}
"#,
                www_dir.display(),
                hidden_sock.display()
            ),
        )?;
        let unreach_strict = Command::new(miraserve_bin())
            .args(["check", "--fs", "--strict", "--dev-tls"])
            .arg(&unreachable_cfg)
            .output()?;
        let unreach_allowed = Command::new(miraserve_bin())
            .args([
                "check",
                "--fs",
                "--strict",
                "--allow-warning",
                "W033",
                "--dev-tls",
            ])
            .arg(&unreachable_cfg)
            .output()?;
        let _ = std::fs::set_permissions(&unsearchable_dir, std::fs::Permissions::from_mode(0o700));
        assert!(
            !unreach_strict.status.success(),
            "unsearchable parent directory must fail check --fs --strict with W033"
        );
        let unreach_stderr = String::from_utf8_lossy(&unreach_strict.stderr);
        assert!(
            unreach_stderr.contains("warning[W033]:")
                && unreach_stderr.contains("could not be reached")
                && unreach_stderr.contains("type and owner unknown")
                && unreach_stderr.contains(&expected_uid_gid),
            "unexpected unreachable-socket W033 diagnostic:\n{unreach_stderr}"
        );
        assert!(
            unreach_allowed.status.success(),
            "unreachable-socket W033 must be allow-listable: stderr={}",
            String::from_utf8_lossy(&unreach_allowed.stderr)
        );

        // 3. Read-only (0400, missing write) socket also triggers W033.
        let ro_strict = Command::new(miraserve_bin())
            .args(["check", "--fs", "--strict", "--dev-tls"])
            .arg(&ro_cfg)
            .output()?;
        assert!(
            !ro_strict.status.success(),
            "read-only 0400 socket must fail check --fs --strict"
        );
        assert!(
            String::from_utf8_lossy(&ro_strict.stderr).contains("W033"),
            "expected W033 for 0400 socket: {}",
            String::from_utf8_lossy(&ro_strict.stderr)
        );

        // 4. `--strict` fails on W033; `--strict --allow-warning W033` passes.
        let bad_strict = Command::new(miraserve_bin())
            .args(["check", "--fs", "--strict", "--dev-tls"])
            .arg(&bad_cfg)
            .output()?;
        assert!(
            !bad_strict.status.success(),
            "check --fs --strict must fail on W033"
        );

        let bad_allowed = Command::new(miraserve_bin())
            .args([
                "check",
                "--fs",
                "--strict",
                "--allow-warning",
                "W033",
                "--dev-tls",
            ])
            .arg(&bad_cfg)
            .output()?;
        assert!(
            bad_allowed.status.success(),
            "check --fs --strict --allow-warning W033 must succeed: stderr={}",
            String::from_utf8_lossy(&bad_allowed.stderr)
        );
        assert!(String::from_utf8_lossy(&bad_allowed.stderr).contains("W033"));

        // 5. JSON output carries W033 with help text.
        let bad_json_out = Command::new(miraserve_bin())
            .args(["check", "--fs", "--dev-tls", "--format", "json"])
            .arg(&bad_cfg)
            .output()?;
        assert!(bad_json_out.status.success());
        let bad_json: serde_json::Value = serde_json::from_slice(&bad_json_out.stdout)?;
        let w033 = bad_json
            .get("warnings")
            .and_then(serde_json::Value::as_array)
            .and_then(|arr| {
                arr.iter()
                    .find(|w| w.get("code").and_then(serde_json::Value::as_str) == Some("W033"))
            })
            .ok_or("missing W033 in JSON warnings")?;
        assert_eq!(
            w033.get("severity").and_then(serde_json::Value::as_str),
            Some("warning")
        );
        assert!(
            w033.get("help")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|h| h.contains("listen.group")),
            "expected listen.group help in JSON W033: {w033}"
        );

        // 6. `reload --dry-run --config` MUST NOT fail on W033 (warning only, not error/quarantined).
        let reload_json_out = Command::new(miraserve_bin())
            .args(["reload", "--dry-run", "--format", "json", "--config"])
            .arg(&bad_cfg)
            .output()?;
        assert!(
            reload_json_out.status.success(),
            "reload --dry-run --config must NOT fail on W033: stdout={} stderr={}",
            String::from_utf8_lossy(&reload_json_out.stdout),
            String::from_utf8_lossy(&reload_json_out.stderr)
        );
        let reload_json: serde_json::Value = serde_json::from_slice(&reload_json_out.stdout)?;
        assert_eq!(
            reload_json
                .get("outcome")
                .and_then(serde_json::Value::as_str),
            Some("dry_run_passed")
        );
        assert!(
            reload_json
                .get("errors")
                .and_then(serde_json::Value::as_array)
                .is_some_and(Vec::is_empty)
        );
        assert!(
            reload_json
                .get("quarantined")
                .and_then(serde_json::Value::as_array)
                .is_some_and(Vec::is_empty)
        );
        assert!(
            reload_json
                .get("warnings")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|arr| {
                    arr.iter()
                        .any(|w| w.get("code").and_then(serde_json::Value::as_str) == Some("W033"))
                }),
            "expected W033 in reload warnings: {reload_json}"
        );
    }

    let _ = std::fs::set_permissions(&bad_sock, std::fs::Permissions::from_mode(0o600));
    let _ = std::fs::set_permissions(&ro_sock, std::fs::Permissions::from_mode(0o600));
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Oracle for 0.1.6 Round 2 (Codex P1 #3 & P2 #6):
/// 1. Under a seccomp filter that KILLS on `faccessat2` while permitting classic `faccessat`,
///    `miraserve check --fs --strict` succeeds cleanly on an accessible socket and emits W033 on
///    an inaccessible socket without ever invoking `faccessat2`.
/// 2. Under a seccomp filter returning `EPERM` or `ENOSYS` on `faccessat`, `check --fs --strict`
///    treats access as INDETERMINATE (no W033, passes `--strict`, emits one plain note naming the
///    error even across multiple sockets), and prints that note once after warnings on failed
///    text runs too.
#[cfg(target_os = "linux")]
#[test]
#[allow(clippy::too_many_lines)]
fn check_fs_fastcgi_unix_socket_never_calls_faccessat2_and_handles_indeterminate_seccomp()
-> TestResult {
    use seccompiler::{SeccompAction, SeccompFilter, TargetArch};
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;

    const SYS_FACCESSAT2: i64 = 439;
    const LINUX_EPERM: u32 = 1;
    const LINUX_ENOSYS: u32 = 38;

    if rustix::process::geteuid().is_root() {
        // Root skips faccessat and emits the root note (tested in the test above).
        return Ok(());
    }

    let arch = TargetArch::try_from(std::env::consts::ARCH)?;
    let sys_faccessat: i64 = match arch {
        TargetArch::x86_64 => 269,
        TargetArch::aarch64 | TargetArch::riscv64 => 48,
    };

    let compile_filter =
        |syscalls: &[i64], action: SeccompAction| -> Result<seccompiler::BpfProgram, String> {
            let mut rules = BTreeMap::new();
            for &nr in syscalls {
                rules.insert(nr, Vec::new());
                if arch == TargetArch::x86_64 {
                    rules.insert(nr | 0x4000_0000, Vec::new());
                }
            }
            SeccompFilter::new(rules, SeccompAction::Allow, action, arch)
                .map_err(|e| e.to_string())?
                .try_into()
                .map_err(|e: seccompiler::BackendError| e.to_string())
        };

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = PathBuf::from(format!("/tmp/ms-w033-sc-{}-{nanos}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let conf_dir = base.join("c");
    let www_dir = base.join("www");
    std::fs::create_dir_all(&conf_dir)?;
    std::fs::create_dir_all(&www_dir)?;

    let ok_sock = base.join("ok.sock");
    let second_sock = base.join("ok2.sock");
    let bad_sock = base.join("bad.sock");
    let _l1 = UnixListener::bind(&ok_sock)?;
    let _l2 = UnixListener::bind(&second_sock)?;
    let _l3 = UnixListener::bind(&bad_sock)?;
    std::fs::set_permissions(&ok_sock, std::fs::Permissions::from_mode(0o660))?;
    std::fs::set_permissions(&second_sock, std::fs::Permissions::from_mode(0o660))?;
    std::fs::set_permissions(&bad_sock, std::fs::Permissions::from_mode(0o000))?;

    let ok_cfg = conf_dir.join("ok.kdl");
    std::fs::write(
        &ok_cfg,
        format!(
            "server {{ listen \":443\" }}\n\
             site \"ok-a.example\" {{ root \"{}\"; route \"*.php\" {{ fastcgi-pass \"unix:{}\" }} }}\n\
             site \"ok-b.example\" {{ root \"{}\"; route \"*.php\" {{ fastcgi-pass \"unix:{}\" }} }}\n",
            www_dir.display(),
            ok_sock.display(),
            www_dir.display(),
            second_sock.display()
        ),
    )?;
    let bad_cfg = conf_dir.join("bad.kdl");
    std::fs::write(
        &bad_cfg,
        format!(
            "server {{ listen \":443\" }}\n\
             site \"bad.example\" {{ root \"{}\"; route \"*.php\" {{ fastcgi-pass \"unix:{}\" }} }}\n",
            www_dir.display(),
            bad_sock.display()
        ),
    )?;
    let fail_cfg = conf_dir.join("fail.kdl");
    std::fs::write(
        &fail_cfg,
        format!(
            "server {{ listen \":443\"; sandbox {{ seccomp \"off\" }} }}\n\
             site \"fail.example\" {{ root \"{}\"; route \"*.php\" {{ fastcgi-pass \"unix:{}\" }} }}\n",
            www_dir.display(),
            ok_sock.display()
        ),
    )?;

    // 1. KILL_PROCESS on `faccessat2`: `check --fs --strict` must survive and work cleanly.
    let kill_faccessat2 = compile_filter(&[SYS_FACCESSAT2], SeccompAction::KillProcess)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    let ok_cfg_c = ok_cfg.clone();
    let bad_cfg_c = bad_cfg.clone();
    std::thread::spawn(move || -> Result<(), String> {
        seccompiler::apply_filter(&kill_faccessat2).map_err(|e| e.to_string())?;
        let ok_out = Command::new(miraserve_bin())
            .args(["check", "--fs", "--strict", "--dev-tls"])
            .arg(&ok_cfg_c)
            .output()
            .map_err(|e| e.to_string())?;
        if !ok_out.status.success() {
            return Err(format!(
                "check --fs under KILL faccessat2 failed on accessible socket: status={:?} stderr={}",
                ok_out.status,
                String::from_utf8_lossy(&ok_out.stderr)
            ));
        }
        let bad_out = Command::new(miraserve_bin())
            .args(["check", "--fs", "--strict", "--dev-tls"])
            .arg(&bad_cfg_c)
            .output()
            .map_err(|e| e.to_string())?;
        if bad_out.status.code() != Some(1) {
            return Err(format!(
                "expected clean exit code 1 (not signal kill) for 0000 socket under KILL faccessat2, got {:?}",
                bad_out.status
            ));
        }
        let bad_err = String::from_utf8_lossy(&bad_out.stderr);
        if !bad_err.contains("warning[W033]:") {
            return Err(format!(
                "expected W033 under KILL faccessat2, got:\n{bad_err}"
            ));
        }
        Ok(())
    })
    .join()
    .map_err(|_| "kill-faccessat2 helper thread panicked")?
    .map_err(|msg| -> Box<dyn std::error::Error> { msg.into() })?;

    // 2. EPERM and ENOSYS on `faccessat`: INDETERMINATE (exit 0 with `--strict`, no W033,
    //    one plain note naming the error across 2 sockets, and printed once after warnings on a
    //    failed text run too).
    for (errno_val, tag) in [(LINUX_EPERM, "EPERM"), (LINUX_ENOSYS, "ENOSYS")] {
        let filter = compile_filter(
            &[sys_faccessat, SYS_FACCESSAT2],
            SeccompAction::Errno(errno_val),
        )
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        let ok_cfg_c = ok_cfg.clone();
        let fail_cfg_c = fail_cfg.clone();
        std::thread::spawn(move || -> Result<(), String> {
            seccompiler::apply_filter(&filter).map_err(|e| e.to_string())?;

            // Valid strict text run with 2 sockets -> exit 0, no W033, exactly ONE note on stdout.
            let text_out = Command::new(miraserve_bin())
                .args(["check", "--fs", "--strict", "--dev-tls"])
                .arg(&ok_cfg_c)
                .output()
                .map_err(|e| e.to_string())?;
            if !text_out.status.success() {
                return Err(format!(
                    "{tag} filter should be indeterminate and pass --strict, got stderr={}",
                    String::from_utf8_lossy(&text_out.stderr)
                ));
            }
            if String::from_utf8_lossy(&text_out.stderr).contains("W033") {
                return Err(format!("{tag} filter must never emit W033"));
            }
            let stdout = String::from_utf8_lossy(&text_out.stdout);
            let note_lines: Vec<&str> = stdout
                .lines()
                .filter(|l| l.starts_with("note: FastCGI Unix socket access") && l.contains(tag))
                .collect();
            if note_lines.len() != 1 {
                return Err(format!(
                    "{tag} filter expected exactly 1 indeterminate note on stdout, got:\n{stdout}"
                ));
            }

            // JSON run -> valid=true, no W033, exactly ONE indeterminate note in `notes`.
            let json_out = Command::new(miraserve_bin())
                .args(["check", "--fs", "--strict", "--dev-tls", "--format", "json"])
                .arg(&ok_cfg_c)
                .output()
                .map_err(|e| e.to_string())?;
            if !json_out.status.success() {
                return Err(format!("{tag} JSON check --fs --strict failed"));
            }
            let j: serde_json::Value =
                serde_json::from_slice(&json_out.stdout).map_err(|e| e.to_string())?;
            let json_notes =
                j.get("notes")
                    .and_then(serde_json::Value::as_array)
                    .map_or(0, |arr| {
                        arr.iter()
                            .filter_map(serde_json::Value::as_str)
                            .filter(|n| n.contains("FastCGI Unix socket access") && n.contains(tag))
                            .count()
                    });
            if json_notes != 1 {
                return Err(format!(
                    "{tag} JSON expected 1 indeterminate note, got: {j}"
                ));
            }

            // Failed text run (`--strict` failing on W003) -> note printed ONCE on stderr AFTER W003.
            let fail_out = Command::new(miraserve_bin())
                .args(["check", "--fs", "--strict", "--dev-tls"])
                .arg(&fail_cfg_c)
                .output()
                .map_err(|e| e.to_string())?;
            if fail_out.status.success() {
                return Err(format!("{tag} failed-run fixture unexpectedly succeeded"));
            }
            let fail_err = String::from_utf8_lossy(&fail_out.stderr);
            let fail_note_count = fail_err
                .lines()
                .filter(|l| l.starts_with("note: FastCGI Unix socket access") && l.contains(tag))
                .count();
            if fail_note_count != 1 {
                return Err(format!(
                    "{tag} failed text run expected 1 note on stderr, got:\n{fail_err}"
                ));
            }
            let warn_pos = fail_err
                .find("W003")
                .ok_or_else(|| format!("{tag} failed run missing W003:\n{fail_err}"))?;
            let note_pos = fail_err
                .find("note: FastCGI Unix socket access")
                .ok_or_else(|| format!("{tag} failed run missing note:\n{fail_err}"))?;
            if note_pos <= warn_pos {
                return Err(format!(
                    "{tag} failed text run note must appear after warnings:\n{fail_err}"
                ));
            }
            Ok(())
        })
        .join()
        .map_err(|_| "faccessat-errno helper thread panicked")?
        .map_err(|msg| -> Box<dyn std::error::Error> { msg.into() })?;
    }

    let _ = std::fs::set_permissions(&bad_sock, std::fs::Permissions::from_mode(0o600));
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// 0.1.6 Item 3: `miraserve check` validates `try-files ... fallback-unless-extension`, preserves
/// byte-identical 0.1.5 `--dump-normalized` JSON when omitted or `#false`, emits the object form
/// when `#true`, accepts single-candidate lists, and rejects bad types/unknown/duplicate attrs.
#[test]
#[allow(clippy::too_many_lines)]
fn check_validates_try_files_fallback_unless_extension_and_dump_normalized() -> TestResult {
    const EXPECTED_015_JSON_BYTES: &[u8] = concat!(
        "{\n",
        "  \"valid\": true,\n",
        "  \"strict\": true,\n",
        "  \"source\": \"<stdin>\",\n",
        "  \"summary\": {\n",
        "    \"listeners\": 1,\n",
        "    \"sites\": 1,\n",
        "    \"routes\": 1,\n",
        "    \"tls_min_version\": \"1.3\",\n",
        "    \"pqc_hybrid\": true,\n",
        "    \"warnings\": 0,\n",
        "    \"errors\": 0\n",
        "  },\n",
        "  \"errors\": [],\n",
        "  \"warnings\": [],\n",
        "  \"config\": {\n",
        "    \"server\": {\n",
        "      \"listeners\": [\n",
        "        {\n",
        "          \"addr\": \":443\",\n",
        "          \"protocols\": [\n",
        "            \"h1\"\n",
        "          ],\n",
        "          \"redirect_https\": false\n",
        "        }\n",
        "      ],\n",
        "      \"tls\": {\n",
        "        \"min_version\": \"1.3\",\n",
        "        \"pqc_hybrid\": true,\n",
        "        \"key_isolation\": \"in-process\",\n",
        "        \"ech\": false,\n",
        "        \"ech_rotate_interval_ms\": 3600000,\n",
        "        \"cert\": \"/etc/miraserve/certs/a.crt\",\n",
        "        \"key\": \"/etc/miraserve/certs/a.key\"\n",
        "      },\n",
        "      \"sandbox\": {\n",
        "        \"landlock\": true,\n",
        "        \"seccomp\": \"strict\"\n",
        "      },\n",
        "      \"timeouts\": {\n",
        "        \"tls_handshake_ms\": 10000,\n",
        "        \"header_read_ms\": 10000,\n",
        "        \"idle_keepalive_ms\": 60000,\n",
        "        \"graceful_drain_ms\": 30000,\n",
        "        \"body_idle_timeout_ms\": 30000,\n",
        "        \"max_body_duration_ms\": 3600000,\n",
        "        \"min_body_rate_bps\": 1024,\n",
        "        \"upstream_connect_ms\": 10000,\n",
        "        \"upstream_response_ms\": 60000,\n",
        "        \"upstream_body_idle_ms\": 60000,\n",
        "        \"response_write_idle_ms\": 30000,\n",
        "        \"min_response_rate_bps\": 1024\n",
        "      },\n",
        "      \"limits\": {\n",
        "        \"max_header_bytes\": 16384,\n",
        "        \"max_body_bytes\": 10485760,\n",
        "        \"max_concurrent_streams\": 128,\n",
        "        \"max_h2_rst_stream_per_sec\": 50,\n",
        "        \"max_connections\": 16384,\n",
        "        \"max_connections_per_ip\": 128,\n",
        "        \"ipv6_prefix_conn_multiplier\": 4,\n",
        "        \"max_streamed_answers_per_ip\": 8,\n",
        "        \"max_streamed_answers_per_backend\": 4\n",
        "      },\n",
        "      \"telemetry\": {\n",
        "        \"metrics_path\": \"/metrics\",\n",
        "        \"service_name\": \"miraserve\",\n",
        "        \"redact_logs\": true\n",
        "      }\n",
        "    },\n",
        "    \"sites\": [\n",
        "      {\n",
        "        \"hosts\": [\n",
        "          \"spa.example.test\"\n",
        "        ],\n",
        "        \"security_headers\": \"strict\",\n",
        "        \"root\": \"/var/www/spa\",\n",
        "        \"routes\": [\n",
        "          {\n",
        "            \"pattern\": \"/*\",\n",
        "            \"handler\": {\n",
        "              \"type\": \"try-files\",\n",
        "              \"config\": [\n",
        "                \"{path}\",\n",
        "                \"{path}/\",\n",
        "                \"/index.html\"\n",
        "              ]\n",
        "            }\n",
        "          }\n",
        "        ]\n",
        "      }\n",
        "    ]\n",
        "  }\n",
        "}\n"
    )
    .as_bytes();

    let run_stdin = |kdl: &str, extra: &[&str]| -> Result<std::process::Output, std::io::Error> {
        let mut child = Command::new(miraserve_bin())
            .arg("check")
            .args(extra)
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(kdl.as_bytes())?;
        }
        child.wait_with_output()
    };

    // 0. Exact byte-for-byte 0.1.5 serialization parity for a 0.1.5 configuration (omitted
    //    `fallback-unless-extension` vs explicit `#false` vs pinned literal 0.1.5 JSON bytes).
    //    Uses `protocols="h1"` so no kernel-dependent HTTP/2 openat2 note can alter the envelope.
    let kdl_015 = r#"
server {
    listen ":443" protocols="h1"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }
}
site "spa.example.test" {
    root "/var/www/spa"
    route "/*" {
        try-files "{path}" "{path}/" "/index.html"
    }
}
"#;
    let kdl_explicit_false = r#"
server {
    listen ":443" protocols="h1"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }
}
site "spa.example.test" {
    root "/var/www/spa"
    route "/*" {
        try-files "{path}" "{path}/" "/index.html" fallback-unless-extension=#false
    }
}
"#;
    let out_015 = run_stdin(
        kdl_015,
        &["--strict", "--format", "json", "--dump-normalized"],
    )?;
    assert!(
        out_015.status.success(),
        "0.1.5 try-files config must pass: stderr={}",
        String::from_utf8_lossy(&out_015.stderr)
    );
    assert_eq!(
        out_015.stdout.as_slice(),
        EXPECTED_015_JSON_BYTES,
        "0.1.5 try-files normalized JSON bytes diverged:\n{}",
        String::from_utf8_lossy(&out_015.stdout)
    );
    let out_false = run_stdin(
        kdl_explicit_false,
        &["--strict", "--format", "json", "--dump-normalized"],
    )?;
    assert!(out_false.status.success());
    assert_eq!(
        out_false.stdout.as_slice(),
        EXPECTED_015_JSON_BYTES,
        "explicit fallback-unless-extension=#false must serialize byte-for-byte identically to 0.1.5"
    );

    // 1. Valid `#true`, `#false`, and single-candidate list pass `--strict`.
    let valid_kdl = r#"
server {
    listen ":443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }
}
site "spa.example.test" {
    root "/var/www/spa"
    route "/single/*" {
        try-files "/index.html" fallback-unless-extension=#true
    }
    route "/default/*" {
        try-files "{path}" "{path}/" "/index.html" fallback-unless-extension=#false
    }
    route "/*" {
        try-files "{path}" "{path}/" "/index.html" fallback-unless-extension=#true
    }
}
"#;
    let ok = run_stdin(
        valid_kdl,
        &["--strict", "--format", "json", "--dump-normalized"],
    )?;
    assert!(
        ok.status.success(),
        "valid fallback-unless-extension config must pass --strict: stdout={} stderr={}",
        String::from_utf8_lossy(&ok.stdout),
        String::from_utf8_lossy(&ok.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&ok.stdout)?;
    let routes = parsed
        .pointer("/config/sites/0/routes")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing routes array in normalized dump")?;
    // Single-candidate `#true`: serialized as object with `fallback_unless_extension: true`.
    assert_eq!(
        routes
            .first()
            .and_then(|r| r.pointer("/handler/config/fallback_unless_extension"))
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    // Explicit `#false`: exact JSON serialization of the try-files candidate array in order.
    assert_eq!(
        serde_json::to_string(
            routes
                .get(1)
                .and_then(|r| r.pointer("/handler/config"))
                .ok_or("missing default route config")?
        )?,
        r#"["{path}","{path}/","/index.html"]"#,
        "fallback-unless-extension=#false must dump exact 0.1.5 candidate array bytes: {parsed}"
    );
    // Multi-candidate `#true`: serialized as object.
    assert_eq!(
        routes
            .get(2)
            .and_then(|r| r.pointer("/handler/config/fallback_unless_extension"))
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );

    // 1b. P2 #8: `examples/miraserve.kdl` passes unchanged, and uncommenting its standalone SPA
    //     `site` block also passes `miraserve check --strict` with 0 warnings and 4 sites.
    let example_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("examples/miraserve.kdl");
    let example_check = Command::new(miraserve_bin())
        .args(["check", "--strict"])
        .arg(&example_path)
        .output()?;
    assert!(
        example_check.status.success(),
        "examples/miraserve.kdl check --strict failed: {}",
        String::from_utf8_lossy(&example_check.stderr)
    );
    assert!(
        String::from_utf8_lossy(&example_check.stdout)
            .contains("(2 listener(s), 3 site(s), 4 route(s), TLS >= 1.3, PQC: X25519MLKEM768 enabled, 0 warning(s))"),
        "unexpected examples/miraserve.kdl summary: {}",
        String::from_utf8_lossy(&example_check.stdout)
    );
    let example_src = std::fs::read_to_string(&example_path)?;
    let spa_marker = "// site \"spa.example.com\" {";
    let spa_start = example_src
        .find(spa_marker)
        .ok_or("examples/miraserve.kdl missing commented standalone SPA site block")?;
    let mut uncommented = String::with_capacity(example_src.len());
    uncommented.push_str(&example_src[..spa_start]);
    for line in example_src[spa_start..].split_inclusive('\n') {
        if let Some(rest) = line.strip_prefix("// ") {
            uncommented.push_str(rest);
        } else if let Some(rest) = line.strip_prefix("//") {
            uncommented.push_str(rest);
        } else {
            uncommented.push_str(line);
        }
    }
    let spa_uncommented = run_stdin(&uncommented, &["--strict"])?;
    assert!(
        spa_uncommented.status.success(),
        "uncommenting the SPA site block in examples/miraserve.kdl must pass --strict: stdout={} stderr={}",
        String::from_utf8_lossy(&spa_uncommented.stdout),
        String::from_utf8_lossy(&spa_uncommented.stderr)
    );
    assert!(
        String::from_utf8_lossy(&spa_uncommented.stdout)
            .contains("(2 listener(s), 4 site(s), 5 route(s), TLS >= 1.3, PQC: X25519MLKEM768 enabled, 0 warning(s))"),
        "expected 4 sites / 5 routes / 0 warnings when SPA block is uncommented, got: {}",
        String::from_utf8_lossy(&spa_uncommented.stdout)
    );

    // 2. Non-boolean attribute rejected with E004.
    let bad_type = r#"
server { listen ":443"; tls { cert "/c.pem"; key "/k.pem" } }
site "bad.example.test" {
    root "/var/www/bad"
    route "/*" { try-files "{path}" "/index.html" fallback-unless-extension="yes" }
}
"#;
    let out_bad_type = run_stdin(bad_type, &["--format", "json"])?;
    assert!(!out_bad_type.status.success());
    let j_bad: serde_json::Value = serde_json::from_slice(&out_bad_type.stdout)?;
    assert!(
        j_bad
            .get("errors")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|arr| {
                arr.iter()
                    .any(|e| e.get("code").and_then(serde_json::Value::as_str) == Some("E004"))
            }),
        "expected E004 for non-bool fallback-unless-extension: {j_bad}"
    );

    // 3. Unknown attribute rejected with E003.
    let unknown_prop = r#"
server { listen ":443"; tls { cert "/c.pem"; key "/k.pem" } }
site "bad.example.test" {
    root "/var/www/bad"
    route "/*" { try-files "{path}" "/index.html" unknown-attr=#true }
}
"#;
    let out_unknown = run_stdin(unknown_prop, &["--format", "json"])?;
    assert!(!out_unknown.status.success());
    let j_unknown: serde_json::Value = serde_json::from_slice(&out_unknown.stdout)?;
    assert!(
        j_unknown
            .get("errors")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|arr| {
                arr.iter()
                    .any(|e| e.get("code").and_then(serde_json::Value::as_str) == Some("E003"))
            }),
        "expected E003 for unknown try-files property: {j_unknown}"
    );

    // 4. Duplicate attribute rejected with E005.
    let dup_prop = r#"
server { listen ":443"; tls { cert "/c.pem"; key "/k.pem" } }
site "bad.example.test" {
    root "/var/www/bad"
    route "/*" {
        try-files "{path}" "/index.html" fallback-unless-extension=#true fallback-unless-extension=#false
    }
}
"#;
    let out_dup = run_stdin(dup_prop, &["--format", "json"])?;
    assert!(!out_dup.status.success());
    let j_dup: serde_json::Value = serde_json::from_slice(&out_dup.stdout)?;
    assert!(
        j_dup
            .get("errors")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|arr| {
                arr.iter()
                    .any(|e| e.get("code").and_then(serde_json::Value::as_str) == Some("E005"))
            }),
        "expected E005 for duplicate fallback-unless-extension: {j_dup}"
    );

    Ok(())
}

/// Oracle for 0.1.6 Item 4: CLI `--help` and packaging descriptions omit the unsupported
/// "zero-trust" claim and use the agreed description wording.
#[test]
fn cli_help_and_packaging_descriptions_replace_zero_trust_wording() -> TestResult {
    const EXPECTED: &str =
        "Web server and edge gateway in memory-safe Rust with post-quantum HTTPS";

    let help = Command::new(miraserve_bin()).arg("--help").output()?;
    assert!(help.status.success());
    let help_stdout = String::from_utf8_lossy(&help.stdout);
    assert!(
        help_stdout.contains(EXPECTED),
        "expected `miraserve --help` to contain `{EXPECTED}`, got:\n{help_stdout}"
    );
    assert!(
        !help_stdout.to_ascii_lowercase().contains("zero-trust"),
        "`miraserve --help` must not contain zero-trust:\n{help_stdout}"
    );

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    for rel in [
        "crates/miraserve-bin/src/main.rs",
        "packaging/nfpm/nfpm.yaml",
        "packaging/homebrew/miraserve.rb",
        "packaging/windows/winget-manifest.yaml",
        "Containerfile",
    ] {
        let text = std::fs::read_to_string(root.join(rel))?;
        assert!(
            text.contains(EXPECTED),
            "expected `{rel}` to contain `{EXPECTED}`"
        );
        assert!(
            !text.to_ascii_lowercase().contains("zero-trust"),
            "`{rel}` must not contain zero-trust"
        );
    }
    Ok(())
}

/// Oracle for 0.1.6 Item 5: Debian `postremove.sh purge` removes empty `/etc/miraserve/*` and
/// `/etc/miraserve` via `rmdir` (never `rm -r`, never acting through symlinks), leaves non-empty
/// folders/mount points/symlinks/state/logs/accounts untouched, prints one stderr line naming
/// what was kept when present (without failing if stderr writes fail), keeps the RPM `0` branch
/// unchanged, and stays POSIX `sh` + `set -eu` safe.
#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)]
fn debian_postremove_purge_removes_only_empty_dirs_and_notes_kept_paths() -> TestResult {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let script_path = root.join("packaging/systemd/postremove.sh");
    let script_text = std::fs::read_to_string(&script_path)?;

    // Static safety checks on the real script.
    let syntax = Command::new("sh").arg("-n").arg(&script_path).output()?;
    assert!(
        syntax.status.success(),
        "postremove.sh failed POSIX sh -n syntax check: {}",
        String::from_utf8_lossy(&syntax.stderr)
    );
    assert!(
        !script_text.contains("rm -r") && !script_text.contains("rm -rf"),
        "postremove.sh must never use rm -r"
    );

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    // Include a space in the temp root name so the test proves robustness to a TMPDIR with spaces.
    let base =
        std::env::temp_dir().join(format!("miraserve postrm-{}-{nanos}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base)?;

    // Rewrite absolute system paths in `postremove.sh` to reference `"${TEST_ROOT}"` (when
    // unquoted) or `${TEST_ROOT}` (when already inside double quotes), passing the actual temp
    // root via the `TEST_ROOT` environment variable so spaces or shell metacharacters in `TMPDIR`
    // can never split arguments or alter shell syntax.
    let rewrite_script_for_test_root = |src: &str| -> String {
        const TARGETS: [&str; 4] = [
            "/etc/miraserve",
            "/var/lib/miraserve",
            "/var/log/miraserve",
            "/run/systemd/system",
        ];
        let mut out = String::with_capacity(src.len() + 256);
        for line in src.split_inclusive('\n') {
            if line.trim_start().starts_with('#') {
                out.push_str(line);
                continue;
            }
            let mut in_double = false;
            let mut in_single = false;
            let mut i = 0;
            while i < line.len() {
                let rest = &line[i..];
                if !in_single && let Some(&target) = TARGETS.iter().find(|&&t| rest.starts_with(t))
                {
                    if in_double {
                        out.push_str("${TEST_ROOT}");
                    } else {
                        out.push_str("\"${TEST_ROOT}\"");
                    }
                    out.push_str(target);
                    i += target.len();
                    continue;
                }
                let Some(ch) = rest.chars().next() else {
                    break;
                };
                match ch {
                    '"' if !in_single => in_double = !in_double,
                    '\'' if !in_double => in_single = !in_single,
                    _ => {}
                }
                out.push(ch);
                i += ch.len_utf8();
            }
        }
        out
    };
    let rewritten_script = base.join("postremove-test.sh");
    std::fs::write(
        &rewritten_script,
        rewrite_script_for_test_root(&script_text),
    )?;
    let rewritten_syntax = Command::new("sh")
        .arg("-n")
        .arg(&rewritten_script)
        .output()?;
    assert!(
        rewritten_syntax.status.success(),
        "rewritten postremove test script failed sh -n: {}",
        String::from_utf8_lossy(&rewritten_syntax.stderr)
    );

    // Stub `id` binary reporting both `miraserve` and `miraserve-keyd` as present.
    let fake_bin = base.join("fake bin");
    std::fs::create_dir_all(&fake_bin)?;
    let fake_id = fake_bin.join("id");
    std::fs::write(
        &fake_id,
        "#!/bin/sh\nif [ \"${1:-}\" = \"-u\" ] && { [ \"${2:-}\" = \"miraserve\" ] || [ \"${2:-}\" = \"miraserve-keyd\" ]; }; then echo 999; exit 0; fi\nexit 1\n",
    )?;
    std::fs::set_permissions(&fake_id, std::fs::Permissions::from_mode(0o755))?;
    let path_with_fake_id = format!(
        "{}:{}",
        fake_bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    // Case 1: Clean Debian `purge` under a root containing a space (only starter files + empty
    // dirs under /etc/miraserve; state, logs, and accounts present).
    let case1 = base.join("case1 clean");
    for rel in [
        "etc/miraserve/conf",
        "etc/miraserve/certs",
        "etc/miraserve/auth",
        "etc/miraserve/keys",
        "var/lib/miraserve/acme",
        "var/log/miraserve",
    ] {
        std::fs::create_dir_all(case1.join(rel))?;
    }
    std::fs::write(case1.join("etc/miraserve/certs/starter.crt"), b"crt")?;
    std::fs::write(case1.join("etc/miraserve/certs/starter.key"), b"key")?;
    std::fs::write(case1.join("etc/miraserve/conf/miraserve.kdl"), b"kdl")?;
    std::fs::write(case1.join("var/lib/miraserve/acme/account.json"), b"{}")?;
    std::fs::write(case1.join("var/log/miraserve/access.log"), b"log")?;
    let out1 = Command::new("sh")
        .arg(&rewritten_script)
        .arg("purge")
        .env("TEST_ROOT", &case1)
        .env("PATH", &path_with_fake_id)
        .output()?;
    assert!(
        out1.status.success(),
        "clean purge failed: stderr={}",
        String::from_utf8_lossy(&out1.stderr)
    );
    assert!(
        !case1.join("etc/miraserve").exists(),
        "empty /etc/miraserve tree must be removed on clean purge"
    );
    assert!(case1.join("var/lib/miraserve/acme/account.json").exists());
    assert!(case1.join("var/log/miraserve/access.log").exists());
    let err1 = String::from_utf8_lossy(&out1.stderr);
    let err1_lines: Vec<&str> = err1.lines().collect();
    assert_eq!(
        err1_lines.len(),
        1,
        "expected exactly one stderr line on purge, got:\n{err1}"
    );
    assert!(
        !err1.contains("etc/miraserve")
            && !err1.contains("non-empty")
            && err1.contains("var/lib/miraserve (certificates and ACME account)")
            && err1.contains("var/log/miraserve")
            && err1.contains("miraserve")
            && err1.contains("miraserve-keyd"),
        "unexpected clean-purge stderr line:\n{err1}"
    );

    // Case 2: Non-empty Debian `purge` (custom site config in /etc/miraserve/conf survives; empty
    // sibling dirs are removed; stderr reports /etc/miraserve as kept, not non-empty).
    let case2 = base.join("case2 nonempty");
    for rel in [
        "etc/miraserve/conf",
        "etc/miraserve/certs",
        "etc/miraserve/auth",
        "etc/miraserve/keys",
        "var/lib/miraserve",
    ] {
        std::fs::create_dir_all(case2.join(rel))?;
    }
    std::fs::write(case2.join("etc/miraserve/conf/miraserve.kdl"), b"starter")?;
    std::fs::write(case2.join("etc/miraserve/conf/custom.kdl"), b"operator")?;
    let out2 = Command::new("sh")
        .arg(&rewritten_script)
        .arg("purge")
        .env("TEST_ROOT", &case2)
        .env("PATH", &path_with_fake_id)
        .output()?;
    assert!(out2.status.success());
    assert!(!case2.join("etc/miraserve/conf/miraserve.kdl").exists());
    assert!(case2.join("etc/miraserve/conf/custom.kdl").exists());
    assert!(case2.join("etc/miraserve/conf").exists());
    assert!(case2.join("etc/miraserve").exists());
    assert!(!case2.join("etc/miraserve/certs").exists());
    assert!(!case2.join("etc/miraserve/auth").exists());
    assert!(!case2.join("etc/miraserve/keys").exists());
    let err2 = String::from_utf8_lossy(&out2.stderr);
    assert_eq!(err2.lines().count(), 1, "expected 1 stderr line:\n{err2}");
    assert!(
        err2.contains("etc/miraserve (kept)")
            && !err2.contains("non-empty")
            && err2.contains("var/lib/miraserve (certificates and ACME account)")
            && !err2.contains("var/log/miraserve"),
        "unexpected non-empty purge stderr line:\n{err2}"
    );

    // Case 3 (Codex P1 #1): Top-level `/etc/miraserve` is a symlink to an operator directory
    // containing an empty `auth` directory -> NOTHING behind the link is removed!
    let case3_sym = base.join("case3 symlink top");
    let external_top = case3_sym.join("operator-etc");
    std::fs::create_dir_all(external_top.join("auth"))?;
    std::fs::create_dir_all(external_top.join("conf"))?;
    std::fs::create_dir_all(case3_sym.join("etc"))?;
    symlink(&external_top, case3_sym.join("etc/miraserve"))?;
    let out3_sym = Command::new("sh")
        .arg(&rewritten_script)
        .arg("purge")
        .env("TEST_ROOT", &case3_sym)
        .env("PATH", &path_with_fake_id)
        .output()?;
    assert!(
        out3_sym.status.success(),
        "symlink top-dir purge failed: stderr={}",
        String::from_utf8_lossy(&out3_sym.stderr)
    );
    assert!(
        std::fs::symlink_metadata(case3_sym.join("etc/miraserve"))?
            .file_type()
            .is_symlink(),
        "/etc/miraserve symlink itself must remain"
    );
    assert!(
        external_top.join("auth").is_dir(),
        "empty auth directory behind /etc/miraserve symlink must NOT be removed"
    );
    assert!(
        external_top.join("conf").is_dir(),
        "empty conf directory behind /etc/miraserve symlink must NOT be removed"
    );
    let err3_sym = String::from_utf8_lossy(&out3_sym.stderr);
    assert!(
        err3_sym.contains("etc/miraserve (kept)") && !err3_sym.contains("non-empty"),
        "symlinked /etc/miraserve must be reported as kept: {err3_sym}"
    );

    // Case 4 (Codex P1 #1): Child `/etc/miraserve/auth` is a symlink to an external empty
    // directory -> external directory and child symlink survive; other real empty siblings go.
    let case4_child_sym = base.join("case4 symlink child");
    let external_auth = case4_child_sym.join("external-auth");
    std::fs::create_dir_all(&external_auth)?;
    for rel in [
        "etc/miraserve/conf",
        "etc/miraserve/certs",
        "etc/miraserve/keys",
    ] {
        std::fs::create_dir_all(case4_child_sym.join(rel))?;
    }
    symlink(&external_auth, case4_child_sym.join("etc/miraserve/auth"))?;
    let out4_sym = Command::new("sh")
        .arg(&rewritten_script)
        .arg("purge")
        .env("TEST_ROOT", &case4_child_sym)
        .env("PATH", &path_with_fake_id)
        .output()?;
    assert!(out4_sym.status.success());
    assert!(
        external_auth.is_dir(),
        "external directory behind child symlink must NOT be removed"
    );
    assert!(
        std::fs::symlink_metadata(case4_child_sym.join("etc/miraserve/auth"))?
            .file_type()
            .is_symlink(),
        "child auth symlink must NOT be removed"
    );
    assert!(!case4_child_sym.join("etc/miraserve/conf").exists());
    assert!(!case4_child_sym.join("etc/miraserve/certs").exists());
    assert!(!case4_child_sym.join("etc/miraserve/keys").exists());
    assert!(case4_child_sym.join("etc/miraserve").is_dir());

    // Case 5 (Codex P2 #7): Empty `/etc/miraserve` that cannot be removed by `rmdir` (simulating a
    // mount point via read-only parent `etc` for non-root): reported as "kept", NOT "non-empty".
    if !rustix::process::geteuid().is_root() {
        let case5_ro = base.join("case5 unremovable empty");
        std::fs::create_dir_all(case5_ro.join("etc/miraserve"))?;
        std::fs::set_permissions(case5_ro.join("etc"), std::fs::Permissions::from_mode(0o555))?;
        let out5_ro = Command::new("sh")
            .arg(&rewritten_script)
            .arg("purge")
            .env("TEST_ROOT", &case5_ro)
            .env("PATH", &path_with_fake_id)
            .output()?;
        let _ =
            std::fs::set_permissions(case5_ro.join("etc"), std::fs::Permissions::from_mode(0o755));
        assert!(out5_ro.status.success());
        assert!(case5_ro.join("etc/miraserve").is_dir());
        let err5 = String::from_utf8_lossy(&out5_ro.stderr);
        assert!(
            err5.contains("etc/miraserve (kept)") && !err5.contains("non-empty"),
            "empty surviving directory must be reported as kept, not non-empty: {err5}"
        );
    }

    // Case 6 (Codex P2 #7): Final informational `printf` failing on stderr (e.g. `/dev/full`)
    // must NOT fail the purge under `set -eu`.
    #[cfg(target_os = "linux")]
    if let Ok(dev_full) = std::fs::OpenOptions::new().write(true).open("/dev/full") {
        let case6_full = base.join("case6 devfull");
        std::fs::create_dir_all(case6_full.join("etc/miraserve"))?;
        let status_full = Command::new("sh")
            .arg(&rewritten_script)
            .arg("purge")
            .env("TEST_ROOT", &case6_full)
            .env("PATH", &path_with_fake_id)
            .stderr(Stdio::from(dev_full))
            .status()?;
        assert!(
            status_full.success(),
            "purge must not fail when stderr writes fail (/dev/full)"
        );
    }

    // Case 7: RPM full uninstall (`0`): removes only starter cert/key, keeps dirs and emits nothing.
    let case7_rpm = base.join("case7 rpm");
    for rel in ["etc/miraserve/conf", "etc/miraserve/certs"] {
        std::fs::create_dir_all(case7_rpm.join(rel))?;
    }
    std::fs::write(case7_rpm.join("etc/miraserve/certs/starter.crt"), b"crt")?;
    std::fs::write(case7_rpm.join("etc/miraserve/certs/starter.key"), b"key")?;
    std::fs::write(case7_rpm.join("etc/miraserve/conf/miraserve.kdl"), b"kdl")?;
    let out7 = Command::new("sh")
        .arg(&rewritten_script)
        .arg("0")
        .env("TEST_ROOT", &case7_rpm)
        .env("PATH", &path_with_fake_id)
        .output()?;
    assert!(out7.status.success());
    assert!(!case7_rpm.join("etc/miraserve/certs/starter.crt").exists());
    assert!(!case7_rpm.join("etc/miraserve/certs/starter.key").exists());
    assert!(case7_rpm.join("etc/miraserve/conf/miraserve.kdl").exists());
    assert!(case7_rpm.join("etc/miraserve/certs").exists());
    assert!(
        out7.stderr.is_empty(),
        "RPM branch must stay untouched with no Debian purge message: {}",
        String::from_utf8_lossy(&out7.stderr)
    );

    // Case 8: `purge` when nothing exists at all (`set -eu` safety, zero stderr when nothing kept).
    let case8_missing = base.join("case8 missing");
    std::fs::create_dir_all(&case8_missing)?;
    let fake_id_none = case8_missing.join("bin");
    std::fs::create_dir_all(&fake_id_none)?;
    std::fs::write(fake_id_none.join("id"), "#!/bin/sh\nexit 1\n")?;
    std::fs::set_permissions(
        fake_id_none.join("id"),
        std::fs::Permissions::from_mode(0o755),
    )?;
    let path_no_accts = format!(
        "{}:{}",
        fake_id_none.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out8 = Command::new("sh")
        .arg(&rewritten_script)
        .arg("purge")
        .env("TEST_ROOT", &case8_missing)
        .env("PATH", &path_no_accts)
        .output()?;
    assert!(
        out8.status.success(),
        "purge with absent paths must succeed under set -eu: {}",
        String::from_utf8_lossy(&out8.stderr)
    );
    assert!(
        out8.stderr.is_empty(),
        "purge with nothing kept must emit no stderr, got: {}",
        String::from_utf8_lossy(&out8.stderr)
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Oracle for 0.1.6 `socket-typing` inspection (Requirement 7):
/// Tests `check`, `check --fs`, and `check --writable-set` (non-root AND root) for:
/// 1. Tenant (`owner-dir`) site with a directory at its FastCGI path.
/// 2. Non-tenant site with a directory at its FastCGI path.
/// 3. Server-level `keyd-socket` path that is a directory.
///
/// Also verifies CLI `miraserve run --no-sandbox` and `miraserve run` refuse a server `keyd-socket`
/// directory with the typed reason on Linux, while non-Linux preserves 0.1.5 behaviour.
#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)]
fn socket_typing_check_fs_and_writable_set_inspection() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::env::temp_dir().join(format!(
        "miraserve-socktype-cli-{}-{nanos}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    let conf_dir = base.join("conf");
    let tenant_home = base.join("tenant");
    let tenant_root = tenant_home.join("public_html");
    let www = base.join("www");
    let bad_fcgi_dir = base.join("bad-fcgi-dir");
    let bad_keyd_dir = base.join("bad-keyd-dir");
    std::fs::create_dir_all(&conf_dir)?;
    std::fs::create_dir_all(&tenant_root)?;
    std::fs::create_dir_all(&www)?;
    std::fs::create_dir_all(&bad_fcgi_dir)?;
    std::fs::create_dir_all(&bad_keyd_dir)?;

    let canon_base = std::fs::canonicalize(&base)?;
    let canon_tenant_home = std::fs::canonicalize(&tenant_home)?;
    let canon_tenant_root = std::fs::canonicalize(&tenant_root)?;
    let canon_www = std::fs::canonicalize(&www)?;
    let canon_fcgi_dir = std::fs::canonicalize(&bad_fcgi_dir)?;
    let canon_keyd_dir = std::fs::canonicalize(&bad_keyd_dir)?;

    let cert_path = canon_base.join("tls/server.crt");
    let key_path = canon_base.join("tls/server.key");
    std::fs::create_dir_all(canon_base.join("tls"))?;
    let gen_cert = Command::new(miraserve_bin())
        .args([
            "cert",
            "generate-dev",
            "--hosts",
            "tenant.example.test,plain.example.test,keyd.example.test",
            "--cert",
        ])
        .arg(&cert_path)
        .arg("--key")
        .arg(&key_path)
        .output()?;
    assert!(
        gen_cert.status.success(),
        "generate-dev failed: {}",
        String::from_utf8_lossy(&gen_cert.stderr)
    );

    let tenant_cfg = conf_dir.join("tenant-fcgi-dir.kdl");
    std::fs::write(
        &tenant_cfg,
        format!(
            r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "{}"; key "{}" }}
}}
site "tenant.example.test" {{
    owner-dir "{}"
    root "{}"
    route "*.php" {{ fastcgi-pass "unix:{}" }}
}}
"#,
            cert_path.display(),
            key_path.display(),
            canon_tenant_home.display(),
            canon_tenant_root.display(),
            canon_fcgi_dir.display(),
        ),
    )?;

    let non_tenant_cfg = conf_dir.join("non-tenant-fcgi-dir.kdl");
    std::fs::write(
        &non_tenant_cfg,
        format!(
            r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "{}"; key "{}" }}
}}
site "plain.example.test" {{
    root "{}"
    route "*.php" {{ fastcgi-pass "unix:{}" }}
}}
"#,
            cert_path.display(),
            key_path.display(),
            canon_www.display(),
            canon_fcgi_dir.display(),
        ),
    )?;

    let keyd_cfg = conf_dir.join("keyd-dir.kdl");
    std::fs::write(
        &keyd_cfg,
        format!(
            r#"
server {{
    listen "127.0.0.1:8443"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "{}"
        cert "{}"
        key "{}"
    }}
}}
site "keyd.example.test" {{
    root "{}"
}}
"#,
            canon_keyd_dir.display(),
            cert_path.display(),
            key_path.display(),
            canon_www.display(),
        ),
    )?;

    #[cfg(target_os = "linux")]
    {
        let expected_fcgi = format!(
            "exact unix endpoint '{}' is not a socket (found directory)",
            canon_fcgi_dir.display()
        );
        let expected_keyd = format!(
            "exact unix endpoint '{}' is not a socket (found directory)",
            canon_keyd_dir.display()
        );

        // --- 1. Tenant site with a directory at its FastCGI path ---
        let t_plain = Command::new(miraserve_bin())
            .arg("check")
            .arg(&tenant_cfg)
            .output()?;
        assert!(
            t_plain.status.success(),
            "plain check on tenant dir should exit 0 (warning only): stderr={}",
            String::from_utf8_lossy(&t_plain.stderr)
        );
        let t_plain_err = String::from_utf8_lossy(&t_plain.stderr);
        assert!(
            t_plain_err.contains("warning[W017]:") && t_plain_err.contains(&expected_fcgi),
            "expected W017 with typed text in plain check, got:\n{t_plain_err}"
        );
        let t_plain_strict = Command::new(miraserve_bin())
            .args(["check", "--strict"])
            .arg(&tenant_cfg)
            .output()?;
        assert!(!t_plain_strict.status.success());

        let t_fs = Command::new(miraserve_bin())
            .args(["check", "--fs"])
            .arg(&tenant_cfg)
            .output()?;
        assert!(
            t_fs.status.success(),
            "check --fs on tenant dir should exit 0 (W026): stderr={}",
            String::from_utf8_lossy(&t_fs.stderr)
        );
        let t_fs_err = String::from_utf8_lossy(&t_fs.stderr);
        let t_fs_out = String::from_utf8_lossy(&t_fs.stdout);
        assert!(
            t_fs_err.contains("warning[W026]:")
                && t_fs_err.contains(&expected_fcgi)
                && t_fs_err.contains("503 Service Unavailable"),
            "expected W026 with typed text in check --fs, got:\n{t_fs_err}"
        );
        assert!(
            !t_fs_err.contains("W033") && !t_fs_err.contains("W017"),
            "check --fs should not emit W033 or duplicate W017, got:\n{t_fs_err}"
        );
        assert!(
            !t_fs_out.contains("not tested because the check runs as root"),
            "non-socket must not trigger W033 root note, got:\n{t_fs_out}"
        );
        let t_fs_strict = Command::new(miraserve_bin())
            .args(["check", "--fs", "--strict"])
            .arg(&tenant_cfg)
            .output()?;
        assert!(!t_fs_strict.status.success());

        let t_writable = Command::new(miraserve_bin())
            .args(["check", "--writable-set"])
            .arg(&tenant_cfg)
            .output()?;
        assert!(
            t_writable.status.success(),
            "check --writable-set on tenant dir should exit 0 (quarantined superset): stderr={}",
            String::from_utf8_lossy(&t_writable.stderr)
        );
        let t_writable_out = String::from_utf8(t_writable.stdout)?;
        assert!(
            !t_writable_out.contains(&format!("writable landlock {}", canon_fcgi_dir.display())),
            "wrong-type exact endpoint MUST NEVER be printed as `writable landlock`: {t_writable_out}"
        );
        if t_writable_out.lines().next().is_some_and(|l| {
            l.starts_with("landlock enforced ") || l.starts_with("landlock partial ")
        }) {
            assert!(
                t_writable_out
                    .lines()
                    .any(|l| l == format!("writable-missing landlock {}", canon_fcgi_dir.display())),
                "quarantined tenant socket candidate must appear as writable-missing: {t_writable_out}"
            );
        }

        // --- 2. Non-tenant site with a directory at its FastCGI path ---
        let nt_fs = Command::new(miraserve_bin())
            .args(["check", "--fs"])
            .arg(&non_tenant_cfg)
            .output()?;
        assert!(
            !nt_fs.status.success(),
            "check --fs on non-tenant FastCGI dir must fail with E301"
        );
        let nt_fs_err = String::from_utf8_lossy(&nt_fs.stderr);
        assert!(
            nt_fs_err.contains("error[E301]:") && nt_fs_err.contains(&expected_fcgi),
            "expected E301 with typed text for non-tenant FastCGI dir, got:\n{nt_fs_err}"
        );

        let nt_writable = Command::new(miraserve_bin())
            .args(["check", "--writable-set"])
            .arg(&non_tenant_cfg)
            .output()?;
        assert!(!nt_writable.status.success());
        assert_eq!(nt_writable.stdout, b"");
        assert!(String::from_utf8_lossy(&nt_writable.stderr).contains(&expected_fcgi));

        // --- 3. Server-level `keyd-socket` path that is a directory ---
        let k_plain = Command::new(miraserve_bin())
            .arg("check")
            .arg(&keyd_cfg)
            .output()?;
        assert!(
            k_plain.status.success(),
            "plain check on keyd dir should exit 0 (W017): stderr={}",
            String::from_utf8_lossy(&k_plain.stderr)
        );
        let k_plain_err = String::from_utf8_lossy(&k_plain.stderr);
        assert!(
            k_plain_err.contains("warning[W017]:") && k_plain_err.contains(&expected_keyd),
            "expected W017 with typed text for keyd dir, got:\n{k_plain_err}"
        );

        let k_fs = Command::new(miraserve_bin())
            .args(["check", "--fs"])
            .arg(&keyd_cfg)
            .output()?;
        assert!(
            !k_fs.status.success(),
            "check --fs on keyd dir must exit non-zero"
        );
        let k_fs_err = String::from_utf8_lossy(&k_fs.stderr);
        assert!(
            k_fs_err.contains("error[E301]:") && k_fs_err.contains(&expected_keyd),
            "expected E301 with typed text for keyd dir, got:\n{k_fs_err}"
        );

        let k_writable = Command::new(miraserve_bin())
            .args(["check", "--writable-set"])
            .arg(&keyd_cfg)
            .output()?;
        assert!(
            !k_writable.status.success(),
            "check --writable-set on keyd dir must fail"
        );
        assert!(
            k_writable.stdout.is_empty(),
            "failed check --writable-set must print empty stdout, got: {}",
            String::from_utf8_lossy(&k_writable.stdout)
        );
        let k_writable_err = String::from_utf8_lossy(&k_writable.stderr);
        assert!(
            k_writable_err.contains(&expected_keyd),
            "expected typed reason on stderr, got:\n{k_writable_err}"
        );

        for extra in [&[][..], &["--no-sandbox"][..]] {
            let run_out = Command::new(miraserve_bin())
                .arg("run")
                .args(extra)
                .arg(&keyd_cfg)
                .output()?;
            assert!(
                !run_out.status.success(),
                "miraserve run {extra:?} must refuse keyd directory"
            );
            let run_err = String::from_utf8_lossy(&run_out.stderr);
            assert!(
                run_err.contains(&expected_keyd),
                "miraserve run {extra:?} must emit typed reason, got:\n{run_err}"
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let t_plain = Command::new(miraserve_bin())
            .args(["check", "--strict"])
            .arg(&tenant_cfg)
            .output()?;
        assert!(
            t_plain.status.success(),
            "non-Linux plain check --strict must pass unchanged: stderr={}",
            String::from_utf8_lossy(&t_plain.stderr)
        );
        let t_fs = Command::new(miraserve_bin())
            .args(["check", "--fs", "--strict"])
            .arg(&tenant_cfg)
            .output()?;
        assert!(
            t_fs.status.success(),
            "non-Linux check --fs --strict on tenant FastCGI dir must pass unchanged: stderr={}",
            String::from_utf8_lossy(&t_fs.stderr)
        );
        let t_writable = Command::new(miraserve_bin())
            .args(["check", "--writable-set"])
            .arg(&tenant_cfg)
            .output()?;
        assert!(t_writable.status.success());
        assert_eq!(
            String::from_utf8(t_writable.stdout)?,
            "landlock unavailable\n"
        );
    }

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

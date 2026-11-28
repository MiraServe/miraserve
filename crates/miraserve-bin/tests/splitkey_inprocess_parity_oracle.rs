//! Split-daemon CLI parity and load-time rejection oracles:
//! 1. Byte-for-byte `in-process` parity against recorded `dd19b94` baseline fixtures (with distinct
//!    placeholders for configured vs canonical temp paths, exclusive temp directory creation, no
//!    optional reference binary env var, and no silent skips).
//! 2. Literal `E109` load-time checks (code, path, location, message) for `owner-dir` per-tenant
//!    TLS pairs under `split-daemon` and the early lexical diagnostics (read-bearing trees and
//!    collisions with `cert`, `client-ca`, `upstream-tls`, and `basic-auth`).
//! 3. Positive sibling-certificate `check --fs` acceptance against a live `miraserve-keyd`
//!    requiring exact exit code 0 and zero errors.

#![allow(clippy::too_many_lines)]

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "../../miraserve-config/tests/common/mod.rs"]
mod kdl_test_util;
use kdl_test_util::kdl_escape_path;

use serde_json::Value;

type TestResult = Result<(), Box<dyn std::error::Error>>;

static SEQ: AtomicU64 = AtomicU64::new(0);

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_miraserve")
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Exclusively creates a fixed 27-byte `/tmp/ms-skp-p-<pid:08x>-<seq:04x>` directory matching
    /// the recorded `dd19b94` fixtures so JSON `location.offset` and `location.length` remain
    /// byte-identical without ever removing a pre-existing directory.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn new_fixed_parity() -> Result<Self, std::io::Error> {
        let pid = std::process::id();
        for suffix in 1_u16..=u16::MAX {
            let path = PathBuf::from(format!("/tmp/ms-skp-p-{pid:08x}-{suffix:04x}"));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(err) if err.kind() == ErrorKind::AlreadyExists => {}
                Err(err) => return Err(err),
            }
        }
        Err(std::io::Error::new(
            ErrorKind::AlreadyExists,
            "exhausted exclusive fixed-length parity directory suffixes",
        ))
    }

    fn new(tag: &str) -> Result<Self, std::io::Error> {
        let root = if cfg!(unix) {
            PathBuf::from("/tmp")
        } else {
            std::env::temp_dir()
        };
        let pid = std::process::id();
        let salt = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::from(d.subsec_nanos()) & 0xffff);
        loop {
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let path = root.join(format!("ms-sk5-{tag}-{pid}-{salt:x}-{n}"));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(err) if err.kind() == ErrorKind::AlreadyExists => {}
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

/// Exclusive fixed-length symlink `/tmp/ms-skp-s-<pid:08x>-<suffix:04x>` pointing at the parity
/// temp directory so Linux exercises distinct `<RAW_TMPDIR>` and `<CANON_TMPDIR>` spellings.
#[cfg(target_os = "linux")]
struct SymlinkDir {
    path: PathBuf,
}

#[cfg(target_os = "linux")]
impl SymlinkDir {
    fn new_fixed_parity(target: &Path) -> Result<Self, std::io::Error> {
        let pid = std::process::id();
        for suffix in 1_u16..=u16::MAX {
            let path = PathBuf::from(format!("/tmp/ms-skp-s-{pid:08x}-{suffix:04x}"));
            match std::os::unix::fs::symlink(target, &path) {
                Ok(()) => return Ok(Self { path }),
                Err(err) if err.kind() == ErrorKind::AlreadyExists => {}
                Err(err) => return Err(err),
            }
        }
        Err(std::io::Error::new(
            ErrorKind::AlreadyExists,
            "exhausted exclusive fixed-length parity symlink suffixes",
        ))
    }
}

#[cfg(target_os = "linux")]
impl Drop for SymlinkDir {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn run_cli(args: &[&str]) -> Result<(i32, String, String), Box<dyn std::error::Error>> {
    let out = Command::new(bin_path()).args(args).output()?;
    Ok((
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stdout)?,
        String::from_utf8(out.stderr)?,
    ))
}

fn gen_dev_cert(host: &str, cert: &Path, key: &Path) -> TestResult {
    let (code, stdout, stderr) = run_cli(&[
        "cert",
        "generate-dev",
        "--hosts",
        host,
        "--cert",
        &cert.to_string_lossy(),
        "--key",
        &key.to_string_lossy(),
    ])?;
    assert_eq!(
        code, 0,
        "generate-dev failed: stdout={stdout}\nstderr={stderr}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(cert, fs::Permissions::from_mode(0o644))?;
        fs::set_permissions(key, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn normalize_text(text: &str, canon_base: &str, raw_base: &str, euid: u32) -> String {
    let mut s = text.to_owned();
    // Preserve distinct placeholders so a switch between configured and canonical paths fails parity.
    if !canon_base.is_empty() && canon_base != raw_base {
        s = s.replace(canon_base, "<CANON_TMPDIR>");
    }
    if !raw_base.is_empty() {
        s = s.replace(raw_base, "<RAW_TMPDIR>");
    }
    if euid != 0 {
        s = s.replace(&format!("uid {euid}"), "uid <EUID>");
    }
    s
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn write_in_process_parity_fixture(
    raw_base: &Path,
) -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error>> {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let certs = raw_base.join("certs");
    let roots_srv = raw_base.join("roots").join("srv");
    let roots_ord = raw_base.join("roots").join("ord");
    let owner_ok = raw_base.join("owner_ok");
    let owner_ok_pub = owner_ok.join("public_html");
    let owner_bad = raw_base.join("owner_bad");
    let owner_bad_pub = owner_bad.join("public_html");
    let owner_link = raw_base.join("owner_link");
    let owner_link_pub = owner_link.join("public_html");
    let errors_dir = raw_base.join("errors");
    let socks_dir = raw_base.join("socks");
    for d in [
        &certs,
        &roots_srv,
        &roots_ord,
        &owner_ok_pub,
        &owner_bad_pub,
        &owner_link_pub,
        &errors_dir,
        &socks_dir,
    ] {
        fs::create_dir_all(d)?;
        fs::set_permissions(d, fs::Permissions::from_mode(0o755))?;
    }
    fs::write(roots_srv.join("index.html"), "srv")?;
    fs::write(roots_ord.join("index.html"), "ord")?;
    fs::write(owner_ok_pub.join("index.html"), "tenant-ok")?;
    fs::write(owner_bad_pub.join("index.html"), "tenant-bad")?;
    fs::write(owner_link_pub.join("index.html"), "tenant-link")?;
    fs::write(errors_dir.join("404.html"), "custom-404")?;

    for (name, host) in [
        ("server", "srv.inproc.test"),
        ("ord", "ord.inproc.test"),
        ("tenant", "ten.inproc.test"),
    ] {
        gen_dev_cert(
            host,
            &certs.join(format!("{name}.crt")),
            &certs.join(format!("{name}.key")),
        )?;
    }

    fs::write(certs.join("bad.key"), "not-a-valid-pem-key\n")?;
    fs::set_permissions(certs.join("bad.key"), fs::Permissions::from_mode(0o600))?;
    symlink(certs.join("tenant.key"), certs.join("link.key"))?;
    fs::write(
        certs.join("users.htpasswd"),
        "alice:$2y$04$012345678901234567890uQ5nH1E3aZ2bC4dE5fG6hI7jK8lM9nO.\n",
    )?;
    fs::set_permissions(
        certs.join("users.htpasswd"),
        fs::Permissions::from_mode(0o600),
    )?;

    let valid_cfg = raw_base.join("valid.kdl");
    fs::write(
        &valid_cfg,
        format!(
            r#"server {{
    listen "127.0.0.1:8443" protocols="h2,h1"
    tls {{
        min-version "1.3"
        pqc-hybrid #true
        key-isolation "in-process"
        cert "{}"
        key "{}"
    }}
    sandbox {{
        landlock #false
        seccomp "strict"
        read-tree "{}" "{}"
        socket-tree "{}"
    }}
}}
site "srv.inproc.test" {{
    root "{}"
}}
site "ord.inproc.test" {{
    root "{}"
    tls {{
        cert "{}"
        key "{}"
    }}
    error-pages {{
        page 404 "{}"
    }}
}}
site "ten.inproc.test" {{
    owner-dir "{}"
    root "{}"
    tls {{
        cert "{}"
        key "{}"
    }}
}}
"#,
            kdl_escape_path(&certs.join("server.crt")),
            kdl_escape_path(&certs.join("server.key")),
            kdl_escape_path(&certs),
            kdl_escape_path(&owner_ok),
            kdl_escape_path(&socks_dir),
            kdl_escape_path(&roots_srv),
            kdl_escape_path(&roots_ord),
            kdl_escape_path(&certs.join("ord.crt")),
            kdl_escape_path(&certs.join("ord.key")),
            kdl_escape_path(&errors_dir.join("404.html")),
            kdl_escape_path(&owner_ok),
            kdl_escape_path(&owner_ok_pub),
            kdl_escape_path(&certs.join("tenant.crt")),
            kdl_escape_path(&certs.join("tenant.key")),
        ),
    )?;

    let broken_cfg = raw_base.join("broken.kdl");
    fs::write(
        &broken_cfg,
        format!(
            r#"server {{
    listen "127.0.0.1:8443" protocols="h2,h1"
    tls {{
        min-version "1.3"
        pqc-hybrid #true
        key-isolation "in-process"
        cert "{}"
        key "{}"
    }}
    sandbox {{
        landlock #false
        seccomp "strict"
    }}
}}
site "ord-bad.inproc.test" {{
    root "{}"
    tls {{
        cert "{}"
        key "{}"
    }}
}}
site "ten-bad.inproc.test" {{
    owner-dir "{}"
    root "{}"
    tls {{
        cert "{}"
        key "{}"
    }}
}}
site "ten-link.inproc.test" {{
    owner-dir "{}"
    root "{}"
    tls {{
        cert "{}"
        key "{}"
    }}
}}
"#,
            kdl_escape_path(&certs.join("server.crt")),
            kdl_escape_path(&certs.join("server.key")),
            kdl_escape_path(&roots_ord),
            kdl_escape_path(&certs.join("ord.crt")),
            kdl_escape_path(&certs.join("bad.key")),
            kdl_escape_path(&owner_bad),
            kdl_escape_path(&owner_bad_pub),
            kdl_escape_path(&certs.join("tenant.crt")),
            kdl_escape_path(&certs.join("bad.key")),
            kdl_escape_path(&owner_link),
            kdl_escape_path(&owner_link_pub),
            kdl_escape_path(&certs.join("tenant.crt")),
            kdl_escape_path(&certs.join("link.key")),
        ),
    )?;
    Ok((valid_cfg, broken_cfg))
}

// Guarded to macOS and Linux because the recorded `dd19b94` parity fixtures are captured on those
// OS profiles (POSIX permissions, symlinks, and EUID).
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn in_process_cli_parity_matches_dd19b94_recorded_baseline() -> TestResult {
    let tmp = TempDir::new_fixed_parity()?;
    let raw_base = tmp.path.display().to_string();
    let canon_base = fs::canonicalize(&tmp.path)?.display().to_string();
    let euid = rustix::process::geteuid().as_raw();
    let (valid_cfg, broken_cfg) = write_in_process_parity_fixture(&tmp.path)?;
    let valid_s = valid_cfg.display().to_string();
    let broken_s = broken_cfg.display().to_string();

    #[cfg(target_os = "linux")]
    let (sym_dir, sym_raw_base, sym_cfg_s) = {
        let sym = SymlinkDir::new_fixed_parity(&tmp.path)?;
        let sym_raw = sym.path.display().to_string();
        assert_ne!(
            sym_raw, canon_base,
            "Linux symlink parity spelling must differ from canonical temp directory"
        );
        let sym_certs = sym.path.join("certs");
        let sym_socks = sym.path.join("socks");
        let sym_cfg = sym.path.join("sym.kdl");
        fs::write(
            &sym_cfg,
            format!(
                r#"server {{
    listen "127.0.0.1:8443" protocols="h2,h1"
    tls {{
        min-version "1.3"
        pqc-hybrid #true
        key-isolation "in-process"
        cert "{}"
        key "{}"
    }}
    sandbox {{
        landlock #false
        seccomp "strict"
        read-tree "{}"
        socket-tree "{}"
    }}
}}
site "sym.inproc.test" {{
    root "roots/srv"
}}
"#,
                kdl_escape_path(&sym_certs.join("server.crt")),
                kdl_escape_path(&sym_certs.join("server.key")),
                kdl_escape_path(&sym_certs),
                kdl_escape_path(&sym_socks),
            ),
        )?;
        let sym_s = sym_cfg.display().to_string();
        (sym, sym_raw, sym_s)
    };
    #[cfg(target_os = "linux")]
    let _keep_sym_dir = &sym_dir;

    let profile = if cfg!(target_os = "macos") {
        "macos"
    } else if euid == 0 {
        "linux-root"
    } else {
        "linux-nonroot"
    };
    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("splitkey_inprocess_parity")
        .join(profile)
        .join("in_process_dd19b94.json");
    let baseline: Value = serde_json::from_str(&fs::read_to_string(&fixture_path)?)?;
    let commands = baseline
        .get("commands")
        .and_then(Value::as_object)
        .ok_or("fixture missing commands object")?;

    let cases: Vec<(&str, Vec<&str>, &str)> = vec![
        ("valid_check", vec!["check", &valid_s], raw_base.as_str()),
        (
            "valid_check_json",
            vec!["check", "--format", "json", &valid_s],
            raw_base.as_str(),
        ),
        (
            "valid_check_strict_fs",
            vec!["check", "--strict", "--fs", &valid_s],
            raw_base.as_str(),
        ),
        (
            "valid_check_strict_fs_json",
            vec!["check", "--strict", "--fs", "--format", "json", &valid_s],
            raw_base.as_str(),
        ),
        (
            "valid_dump_normalized",
            vec!["check", "--dump-normalized", &valid_s],
            raw_base.as_str(),
        ),
        (
            "valid_writable_set",
            vec!["check", "--writable-set", &valid_s],
            raw_base.as_str(),
        ),
        (
            "valid_reload_dry_run_json",
            vec![
                "reload",
                "--dry-run",
                "--config",
                &valid_s,
                "--format",
                "json",
            ],
            raw_base.as_str(),
        ),
        ("broken_check", vec!["check", &broken_s], raw_base.as_str()),
        (
            "broken_check_json",
            vec!["check", "--format", "json", &broken_s],
            raw_base.as_str(),
        ),
        (
            "broken_check_fs",
            vec!["check", "--fs", &broken_s],
            raw_base.as_str(),
        ),
        (
            "broken_check_fs_json",
            vec!["check", "--fs", "--format", "json", &broken_s],
            raw_base.as_str(),
        ),
        (
            "broken_reload_dry_run_json",
            vec![
                "reload",
                "--dry-run",
                "--config",
                &broken_s,
                "--format",
                "json",
            ],
            raw_base.as_str(),
        ),
        #[cfg(target_os = "linux")]
        (
            "valid_symlink_dump_normalized",
            vec!["check", "--dump-normalized", &sym_cfg_s],
            sym_raw_base.as_str(),
        ),
    ];
    assert_eq!(
        cases.len(),
        commands.len(),
        "recorded fixture command count mismatch for profile {profile}"
    );

    for (name, args, case_raw_base) in cases {
        let expected = commands
            .get(name)
            .ok_or_else(|| format!("missing recorded case '{name}'"))?;
        let exp_code = i32::try_from(
            expected
                .get("exit_code")
                .and_then(Value::as_i64)
                .ok_or("missing exit_code")?,
        )?;
        let exp_stdout = expected
            .get("stdout")
            .and_then(Value::as_str)
            .ok_or("missing stdout")?;
        let exp_stderr = expected
            .get("stderr")
            .and_then(Value::as_str)
            .ok_or("missing stderr")?;

        if name == "valid_symlink_dump_normalized" {
            assert!(
                exp_stdout.contains("<RAW_TMPDIR>") && exp_stdout.contains("<CANON_TMPDIR>"),
                "symlink parity fixture must contain both <RAW_TMPDIR> and <CANON_TMPDIR>"
            );
        }

        let (code, stdout, stderr) = run_cli(&args)?;
        let norm_stdout = normalize_text(&stdout, &canon_base, case_raw_base, euid);
        let norm_stderr = normalize_text(&stderr, &canon_base, case_raw_base, euid);

        assert_eq!(code, exp_code, "exit_code mismatch on {profile}/{name}");
        assert_eq!(
            norm_stdout, exp_stdout,
            "stdout mismatch on {profile}/{name}"
        );
        assert_eq!(
            norm_stderr, exp_stderr,
            "stderr mismatch on {profile}/{name}"
        );
    }
    Ok(())
}

#[test]
fn s2_owner_dir_with_site_tls_rejected_at_load_with_exact_fields() -> TestResult {
    let tmp = TempDir::new("s2")?;
    let base = &tmp.path;
    let owner = base.join("owner");
    let pub_dir = owner.join("public_html");
    let vault = base.join("vault");
    let certs = base.join("certs");
    for d in [&pub_dir, &vault, &certs] {
        fs::create_dir_all(d)?;
    }

    let kdl = format!(
        r#"server {{
    listen "127.0.0.1:8443" protocols="h1"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "tcp://127.0.0.1:9444"
        cert "{scert}"
        key "{skey}"
    }}
}}
site "tenant.example.test" {{
    owner-dir "{owner}"
    root "{pub_dir}"
    tls {{
        cert "{tcert}"
        key "{tkey}"
    }}
}}
"#,
        scert = kdl_escape_path(&certs.join("server.crt")),
        skey = kdl_escape_path(&vault.join("server.key")),
        owner = kdl_escape_path(&owner),
        pub_dir = kdl_escape_path(&pub_dir),
        tcert = kdl_escape_path(&certs.join("tenant.crt")),
        tkey = kdl_escape_path(&vault.join("tenant.key")),
    );
    let cfg = base.join("s2.kdl");
    fs::write(&cfg, &kdl)?;
    let cfg_s = cfg.display().to_string();

    let expected_msg = "site 'tenant.example.test' uses 'owner-dir' and declares its own TLS \
        certificate/key pair, which is not supported with key-isolation \"split-daemon\" in this release";

    // Text check.
    let (code, stdout, stderr) = run_cli(&["check", &cfg_s])?;
    assert_eq!(code, 1);
    assert!(stdout.is_empty(), "expected empty stdout, got: {stdout}");
    assert!(
        stderr.contains("miraserve::E109")
            && stderr.contains(expected_msg)
            && stderr
                .contains("help: remove site.tls cert/key for server pair, or use in-process mode"),
        "unexpected text stderr:\n{stderr}"
    );

    // JSON check with literal code, path, message, help, and location.
    let (code, stdout, stderr) = run_cli(&["check", "--format", "json", &cfg_s])?;
    assert_eq!(code, 1);
    assert!(stderr.is_empty(), "expected empty stderr, got: {stderr}");
    let json: Value = serde_json::from_str(&stdout)?;
    assert_eq!(json.get("valid"), Some(&Value::Bool(false)));
    let errs = json
        .get("errors")
        .and_then(Value::as_array)
        .ok_or("missing errors array")?;
    assert_eq!(errs.len(), 1, "expected 1 error, got: {errs:?}");
    let e0 = errs.first().ok_or("missing e0")?;
    assert_eq!(e0.get("code").and_then(Value::as_str), Some("E109"));
    assert_eq!(e0.get("severity").and_then(Value::as_str), Some("error"));
    assert_eq!(e0.get("path").and_then(Value::as_str), Some("site[0].tls"));
    assert_eq!(
        e0.get("message").and_then(Value::as_str),
        Some(expected_msg)
    );
    assert_eq!(
        e0.get("help").and_then(Value::as_str),
        Some("remove site.tls cert/key for server pair, or use in-process mode")
    );
    let loc = e0
        .get("location")
        .and_then(Value::as_object)
        .ok_or("missing location")?;
    assert_eq!(loc.get("line").and_then(Value::as_u64), Some(13));
    assert_eq!(loc.get("column").and_then(Value::as_u64), Some(5));

    // Reload dry-run JSON also refuses with E109.
    let (code, stdout, _) = run_cli(&[
        "reload",
        "--dry-run",
        "--config",
        &cfg_s,
        "--format",
        "json",
    ])?;
    assert_eq!(code, 1);
    let rjson: Value = serde_json::from_str(&stdout)?;
    assert_eq!(
        rjson.get("outcome").and_then(Value::as_str),
        Some("dry_run_refused")
    );
    let rerrs = rjson
        .get("errors")
        .and_then(Value::as_array)
        .ok_or("missing reload errors")?;
    assert!(
        rerrs.iter().any(|v| v
            .as_str()
            .is_some_and(|s| s.contains("E109") && s.contains(expected_msg))),
        "expected E109 in reload errors: {rerrs:?}"
    );

    // Cert-only site.tls on owner-dir under split-daemon is also rejected with E109.
    let cert_only = base.join("s2_cert_only.kdl");
    fs::write(
        &cert_only,
        format!(
            r#"server {{
    listen "127.0.0.1:8443" protocols="h1"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "tcp://127.0.0.1:9444"
        cert "{scert}"
        key "{skey}"
    }}
}}
site "tenant.example.test" {{
    owner-dir "{owner}"
    root "{pub_dir}"
    tls {{
        cert "{tcert}"
    }}
}}
"#,
            scert = kdl_escape_path(&certs.join("server.crt")),
            skey = kdl_escape_path(&vault.join("server.key")),
            owner = kdl_escape_path(&owner),
            pub_dir = kdl_escape_path(&pub_dir),
            tcert = kdl_escape_path(&certs.join("tenant.crt")),
        ),
    )?;
    let (code, stdout, _) = run_cli(&[
        "check",
        "--format",
        "json",
        &cert_only.display().to_string(),
    ])?;
    assert_eq!(code, 1);
    let co_json: Value = serde_json::from_str(&stdout)?;
    assert!(
        co_json
            .get("errors")
            .and_then(Value::as_array)
            .is_some_and(|arr| arr.iter().any(|e| {
                e.get("code").and_then(Value::as_str) == Some("E109")
                    && e.get("path").and_then(Value::as_str) == Some("site[0].tls")
            })),
        "expected E109 for cert-only owner-dir tls: {co_json}"
    );

    // Tenant site WITHOUT site.tls (using server pair) stays accepted.
    let server_pair_tenant = base.join("s2_ok_server_pair.kdl");
    fs::write(
        &server_pair_tenant,
        format!(
            r#"server {{
    listen "127.0.0.1:8443" protocols="h1"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "tcp://127.0.0.1:9444"
        cert "{scert}"
        key "{skey}"
    }}
}}
site "tenant.example.test" {{
    owner-dir "{owner}"
    root "{pub_dir}"
}}
"#,
            scert = kdl_escape_path(&certs.join("server.crt")),
            skey = kdl_escape_path(&vault.join("server.key")),
            owner = kdl_escape_path(&owner),
            pub_dir = kdl_escape_path(&pub_dir),
        ),
    )?;
    let (code, stdout, stderr) = run_cli(&[
        "check",
        "--format",
        "json",
        &server_pair_tenant.display().to_string(),
    ])?;
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let ok_json: Value = serde_json::from_str(&stdout)?;
    assert_eq!(ok_json.get("valid"), Some(&Value::Bool(true)));
    Ok(())
}

#[test]
fn s3_split_daemon_lexical_e109_and_sibling_cert_acceptance() -> TestResult {
    let tmp = TempDir::new("s3")?;
    let base = &tmp.path;
    let vault = base.join("vault");
    let certs = base.join("certs");
    let root_dir = base.join("site");
    for d in [&vault, &certs, &root_dir] {
        fs::create_dir_all(d)?;
    }
    fs::write(root_dir.join("index.html"), "ok")?;
    let server_cert = certs.join("server.crt");
    let server_key = vault.join("server.key");
    gen_dev_cert("s3.example.test", &server_cert, &server_key)?;

    // 1. Early lexical E109 diagnostics: read-tree and socket-tree use synthetic `/srv/...`
    //    tree and key spellings (so `sandbox_tree_rejection` does not emit E202 before E109 on
    //    Windows); `acme-webroot` and file-touching cases keep native, KDL-escaped paths.
    let syn_vault = "/srv/splitkey-vault";
    let syn_cert = "/srv/splitkey-certs/server.crt";
    let syn_key = "/srv/splitkey-vault/server.key";
    let syn_root = "/srv/splitkey-site";
    let vault_kdl = kdl_escape_path(&vault);
    let cert_kdl = kdl_escape_path(&server_cert);
    let key_kdl = kdl_escape_path(&server_key);
    let root_kdl = kdl_escape_path(&root_dir);
    let tree_cases: [(&str, &str, &str, &str, &str, String, String); 3] = [
        (
            "read-tree",
            "server.sandbox.read-tree",
            syn_cert,
            syn_key,
            syn_root,
            format!(r#"sandbox {{ read-tree "{syn_vault}" }}"#),
            format!(
                "split-daemon signing key server.tls.key '{syn_key}' lies inside read-bearing read-tree '{syn_vault}'"
            ),
        ),
        (
            "socket-tree",
            "server.sandbox.socket-tree",
            syn_cert,
            syn_key,
            syn_root,
            format!(r#"sandbox {{ socket-tree "{syn_vault}" }}"#),
            format!(
                "split-daemon signing key server.tls.key '{syn_key}' lies inside read-bearing socket-tree '{syn_vault}'"
            ),
        ),
        (
            "acme-webroot",
            "server.acme-webroot",
            &cert_kdl,
            &key_kdl,
            &root_kdl,
            format!(r#"acme-webroot "{vault_kdl}""#),
            format!(
                "split-daemon signing key server.tls.key '{}' lies inside read-bearing acme-webroot '{}'",
                server_key.display(),
                vault.display()
            ),
        ),
    ];

    for (label, exp_path, cfg_cert, cfg_key, cfg_root, snippet, exp_msg) in tree_cases {
        let cfg = base.join(format!("s3_{label}.kdl"));
        fs::write(
            &cfg,
            format!(
                r#"server {{
    listen "127.0.0.1:8443" protocols="h1"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "tcp://127.0.0.1:9444"
        cert "{cfg_cert}"
        key "{cfg_key}"
    }}
    {snippet}
}}
site "s3.example.test" {{
    root "{cfg_root}"
}}
"#
            ),
        )?;
        let (code, stdout, _) =
            run_cli(&["check", "--format", "json", &cfg.display().to_string()])?;
        assert_eq!(code, 1, "expected E109 for {label}, stdout={stdout}");
        let json: Value = serde_json::from_str(&stdout)?;
        let e0 = json
            .get("errors")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .ok_or("missing first error")?;
        assert_eq!(
            e0.get("code").and_then(Value::as_str),
            Some("E109"),
            "case {label}: {json}"
        );
        assert_eq!(
            e0.get("path").and_then(Value::as_str),
            Some(exp_path),
            "case {label}: {json}"
        );
        assert_eq!(
            e0.get("message").and_then(Value::as_str),
            Some(exp_msg.as_str()),
            "case {label}: {json}"
        );
        assert!(
            e0.get("location")
                .and_then(|l| l.get("line"))
                .and_then(Value::as_u64)
                .is_some(),
            "expected source location for {label}: {json}"
        );
    }

    // 2. Early lexical E109: exact lexical collisions with server/site cert, server/site
    //    client-ca, upstream-tls ca-cert/client-cert/client-key, and basic-auth users file.
    let site_key = vault.join("site.key");
    let site_key_kdl = kdl_escape_path(&site_key);
    let srv_col_msg = format!(
        "split-daemon signing key server.tls.key '{}' collides with worker-read input '{}'",
        server_key.display(),
        server_key.display()
    );
    let site_col_msg = format!(
        "split-daemon signing key site[0].tls.key '{}' collides with worker-read input '{}'",
        site_key.display(),
        site_key.display()
    );
    let collision_cases: [(&str, &str, u64, &str, String); 8] = [
        (
            "server_cert",
            "server.tls.key",
            7,
            &srv_col_msg,
            format!(
                r#"server {{
    listen "127.0.0.1:8443" protocols="h1"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "tcp://127.0.0.1:9444"
        cert "{key_kdl}"
        key "{key_kdl}"
    }}
}}
site "s3.example.test" {{ root "{root_kdl}" }}
"#
            ),
        ),
        (
            "site_cert",
            "site[0].tls.key",
            12,
            &site_col_msg,
            format!(
                r#"server {{
    listen "127.0.0.1:8443" protocols="h1"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "tcp://127.0.0.1:9444"
        cert "{cert_kdl}"
        key "{key_kdl}"
    }}
}}
site "s3.example.test" {{
    root "{root_kdl}"
    tls {{ cert "{site_key_kdl}"; key "{site_key_kdl}" }}
}}
"#
            ),
        ),
        (
            "server_client_ca",
            "server.tls.key",
            7,
            &srv_col_msg,
            format!(
                r#"server {{
    listen "127.0.0.1:8443" protocols="h1"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "tcp://127.0.0.1:9444"
        cert "{cert_kdl}"
        key "{key_kdl}"
        client-ca "{key_kdl}"
    }}
}}
site "s3.example.test" {{ root "{root_kdl}" }}
"#
            ),
        ),
        (
            "site_client_ca",
            "server.tls.key",
            7,
            &srv_col_msg,
            format!(
                r#"server {{
    listen "127.0.0.1:8443" protocols="h1"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "tcp://127.0.0.1:9444"
        cert "{cert_kdl}"
        key "{key_kdl}"
    }}
}}
site "s3.example.test" {{
    root "{root_kdl}"
    tls {{ client-ca "{key_kdl}" }}
}}
"#
            ),
        ),
        (
            "upstream_ca_cert",
            "server.tls.key",
            7,
            &srv_col_msg,
            format!(
                r#"server {{
    listen "127.0.0.1:8443" protocols="h1"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "tcp://127.0.0.1:9444"
        cert "{cert_kdl}"
        key "{key_kdl}"
    }}
}}
site "s3.example.test" {{
    route "/api/*" {{
        reverse-proxy {{
            upstream "https://127.0.0.1:9443"
            upstream-tls {{ ca-cert "{key_kdl}" }}
        }}
    }}
}}
"#
            ),
        ),
        (
            "upstream_client_cert",
            "server.tls.key",
            7,
            &srv_col_msg,
            format!(
                r#"server {{
    listen "127.0.0.1:8443" protocols="h1"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "tcp://127.0.0.1:9444"
        cert "{cert_kdl}"
        key "{key_kdl}"
    }}
}}
site "s3.example.test" {{
    route "/api/*" {{
        reverse-proxy {{
            upstream "https://127.0.0.1:9443"
            upstream-tls {{
                client-cert "{key_kdl}"
                client-key "{cert_kdl}"
            }}
        }}
    }}
}}
"#
            ),
        ),
        (
            "upstream_client_key",
            "server.tls.key",
            7,
            &srv_col_msg,
            format!(
                r#"server {{
    listen "127.0.0.1:8443" protocols="h1"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "tcp://127.0.0.1:9444"
        cert "{cert_kdl}"
        key "{key_kdl}"
    }}
}}
site "s3.example.test" {{
    route "/api/*" {{
        reverse-proxy {{
            upstream "https://127.0.0.1:9443"
            upstream-tls {{
                client-cert "{cert_kdl}"
                client-key "{key_kdl}"
            }}
        }}
    }}
}}
"#
            ),
        ),
        (
            "basic_auth_users_file",
            "server.tls.key",
            7,
            &srv_col_msg,
            format!(
                r#"server {{
    listen "127.0.0.1:8443" protocols="h1"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "tcp://127.0.0.1:9444"
        cert "{cert_kdl}"
        key "{key_kdl}"
    }}
}}
site "s3.example.test" {{
    root "{root_kdl}"
    basic-auth "{key_kdl}" realm="Members"
}}
"#
            ),
        ),
    ];

    for (label, exp_path, exp_line, exp_msg, kdl) in collision_cases {
        let cfg = base.join(format!("s3_col_{label}.kdl"));
        fs::write(&cfg, kdl)?;
        let (code, stdout, _) =
            run_cli(&["check", "--format", "json", &cfg.display().to_string()])?;
        assert_eq!(code, 1, "expected E109 for {label}, stdout={stdout}");
        let json: Value = serde_json::from_str(&stdout)?;
        let e0 = json
            .get("errors")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .ok_or("missing collision error")?;
        assert_eq!(
            e0.get("code").and_then(Value::as_str),
            Some("E109"),
            "case {label}: {json}"
        );
        assert_eq!(
            e0.get("path").and_then(Value::as_str),
            Some(exp_path),
            "case {label}: {json}"
        );
        assert_eq!(
            e0.get("message").and_then(Value::as_str),
            Some(exp_msg),
            "case {label}: {json}"
        );
        assert_eq!(
            e0.get("location")
                .and_then(|l| l.get("line"))
                .and_then(Value::as_u64),
            Some(exp_line),
            "expected source location line for {label}: {json}"
        );
        assert!(
            e0.get("location")
                .and_then(|l| l.get("column"))
                .and_then(Value::as_u64)
                .is_some(),
            "expected source location column for {label}: {json}"
        );
    }

    // Route-level `basic-auth` emits the existing E311 first, followed by E109 at the signing-key
    // path with location.
    let route_ba_cfg = base.join("s3_col_route_basic_auth.kdl");
    fs::write(
        &route_ba_cfg,
        format!(
            r#"server {{
    listen "127.0.0.1:8443" protocols="h1"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "tcp://127.0.0.1:9444"
        cert "{cert_kdl}"
        key "{key_kdl}"
    }}
}}
site "s3.example.test" {{
    root "{root_kdl}"
    route "/admin/*" {{
        basic-auth "{key_kdl}" realm="Admin"
        respond 404
    }}
}}
"#
        ),
    )?;
    let (code, stdout, _) = run_cli(&[
        "check",
        "--format",
        "json",
        &route_ba_cfg.display().to_string(),
    ])?;
    assert_eq!(
        code, 1,
        "expected E311 and E109 for route_basic_auth, stdout={stdout}"
    );
    let rba_json: Value = serde_json::from_str(&stdout)?;
    let rba_errs = rba_json
        .get("errors")
        .and_then(Value::as_array)
        .ok_or("missing route_basic_auth errors")?;
    assert_eq!(
        rba_errs.len(),
        2,
        "expected E311 and E109 for route_basic_auth: {rba_json}"
    );
    let rba_e0 = rba_errs.first().ok_or("missing E311")?;
    assert_eq!(
        rba_e0.get("code").and_then(Value::as_str),
        Some("E311"),
        "expected existing E311 first: {rba_json}"
    );
    assert_eq!(
        rba_e0.get("path").and_then(Value::as_str),
        Some("site[0].route[0]"),
        "expected E311 at site[0].route[0]: {rba_json}"
    );
    let rba_e1 = rba_errs.get(1).ok_or("missing E109")?;
    assert_eq!(
        rba_e1.get("code").and_then(Value::as_str),
        Some("E109"),
        "expected additional E109 second: {rba_json}"
    );
    assert_eq!(
        rba_e1.get("path").and_then(Value::as_str),
        Some("server.tls.key"),
        "expected E109 at server.tls.key: {rba_json}"
    );
    assert_eq!(
        rba_e1.get("message").and_then(Value::as_str),
        Some(srv_col_msg.as_str()),
        "expected E109 message for route_basic_auth: {rba_json}"
    );
    assert_eq!(
        rba_e1
            .get("location")
            .and_then(|l| l.get("line"))
            .and_then(Value::as_u64),
        Some(7),
        "expected E109 location line for route_basic_auth: {rba_json}"
    );
    assert!(
        rba_e1
            .get("location")
            .and_then(|l| l.get("column"))
            .and_then(Value::as_u64)
            .is_some(),
        "expected E109 location column for route_basic_auth: {rba_json}"
    );

    // Paths differing only in letter case (`C:\tls\Server.pem` vs `C:\tls\server.pem`) must not
    // collide with E109 on any platform.
    let case_cfg = base.join("s3_case_distinct.kdl");
    fs::write(
        &case_cfg,
        format!(
            r#"server {{
    listen "127.0.0.1:8443" protocols="h1"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "tcp://127.0.0.1:9444"
        cert "C:\\tls\\server.crt"
        key "C:\\tls\\Server.pem"
        client-ca "C:\\tls\\server.pem"
    }}
}}
site "s3.example.test" {{ root "{syn_root}" }}
"#
        ),
    )?;
    let (code, stdout, stderr) =
        run_cli(&["check", "--format", "json", &case_cfg.display().to_string()])?;
    assert_eq!(
        code, 0,
        "case-distinct key and client-ca must not trigger E109: stdout={stdout}\nstderr={stderr}"
    );
    let case_json: Value = serde_json::from_str(&stdout)?;
    assert_eq!(
        case_json.get("valid"),
        Some(&Value::Bool(true)),
        "expected valid=true: {case_json}"
    );
    assert_eq!(
        case_json
            .get("errors")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0),
        "expected zero errors (no E109): {case_json}"
    );

    // 3. Positive sibling-certificate check against a live Unix-socket `miraserve-keyd` requiring
    //    exact exit code 0 and zero errors. Guarded to Unix because `KeydEndpoint::Unix` and POSIX
    //    key permissions apply only on Unix platforms.
    #[cfg(unix)]
    {
        use miraserve_tls::{KeydEndpoint, KeydKeyStore, KeydServer};

        let shared = base.join("shared");
        fs::create_dir_all(&shared)?;
        let sib_cert = shared.join("server.crt");
        let sib_key = shared.join("server.key");
        gen_dev_cert("s3.example.test", &sib_cert, &sib_key)?;

        let keyd_sock = base.join("keyd.sock");
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let mut store = KeydKeyStore::new();
        store.load_pem_pair("srv", Vec::new(), true, &sib_cert, &sib_key)?;
        let keyd = rt.block_on(async {
            KeydServer::start(KeydEndpoint::Unix(keyd_sock.clone()), store, false).await
        })?;

        let sib_cfg = base.join("s3_sibling.kdl");
        fs::write(
            &sib_cfg,
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
site "s3.example.test" {{ root "{}" }}
"#,
                kdl_escape_path(&keyd_sock),
                kdl_escape_path(&sib_cert),
                kdl_escape_path(&sib_key),
                kdl_escape_path(&root_dir),
            ),
        )?;
        let cli_res = run_cli(&[
            "check",
            "--fs",
            "--format",
            "json",
            &sib_cfg.display().to_string(),
        ]);
        rt.block_on(async {
            keyd.shutdown().await;
        });
        let (code, stdout, stderr) = cli_res?;
        assert_eq!(
            code, 0,
            "sibling cert beside key with live keyd must pass check --fs with exit 0: stdout={stdout}\nstderr={stderr}"
        );
        assert!(stderr.is_empty(), "expected empty stderr, got: {stderr}");
        let json: Value = serde_json::from_str(&stdout)?;
        assert_eq!(
            json.get("valid"),
            Some(&Value::Bool(true)),
            "expected valid=true: {json}"
        );
        assert_eq!(
            json.get("errors").and_then(Value::as_array).map(Vec::len),
            Some(0),
            "expected zero errors: {json}"
        );
    }

    Ok(())
}

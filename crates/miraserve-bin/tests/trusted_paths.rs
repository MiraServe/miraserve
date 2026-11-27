//! Integration tests (Tests F and S) for `miraserve check --fs --trusted-paths` (`W034`, Stage 1a).
//!
//! Covers CLI flag validation, `--help` wording, non-Linux note, Linux real-filesystem walker
//! semantics, filesystem/mount guard, JSON/text output, `--strict` / `--allow-warning W034`,
//! `openat2` refusal, frozen `W029`, and root-only real multi-UID ownership + socket-producer cases.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "../../miraserve-config/tests/common/mod.rs"]
mod kdl_test_util;

use kdl_test_util::kdl_escape_path;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn miraserve_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_miraserve"))
}

fn make_temp_base(tag: &str) -> Result<PathBuf, std::io::Error> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = PathBuf::from(format!("/tmp/ms-tp-{tag}-{}-{nanos}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base)?;
    #[cfg(unix)]
    set_mode(&base, 0o750)?;
    Ok(base)
}

#[cfg(unix)]
fn set_mode(p: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(p, fs::Permissions::from_mode(mode))
}

fn gen_dev_cert(dir: &Path) -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error>> {
    let cert = dir.join("server.crt");
    let key = dir.join("server.key");
    let out = Command::new(miraserve_bin())
        .args(["cert", "generate-dev", "--hosts", "tp.example", "--cert"])
        .arg(&cert)
        .arg("--key")
        .arg(&key)
        .output()?;
    if !out.status.success() {
        return Err(format!(
            "cert generate-dev failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    #[cfg(unix)]
    {
        set_mode(&cert, 0o640)?;
        set_mode(&key, 0o600)?;
    }
    Ok((cert, key))
}

// ---------------------------------------------------------------------------
// Test F: CLI flag contract (cross-platform)
// ---------------------------------------------------------------------------

#[test]
fn flag_trusted_paths_without_fs_is_usage_error() -> TestResult {
    let base = make_temp_base("flag-no-fs")?;
    let cfg = base.join("min.kdl");
    fs::write(&cfg, "server { listen \":443\" }\n")?;

    let out = Command::new(miraserve_bin())
        .args(["check", "--trusted-paths"])
        .arg(&cfg)
        .output()?;
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(String::from_utf8(out.stdout)?, "");
    assert_eq!(
        String::from_utf8(out.stderr)?,
        "error: --trusted-paths requires --fs\n"
    );

    // Same exit status style as neighbouring `--writable-set --format json` error.
    let neighbor = Command::new(miraserve_bin())
        .args(["check", "--writable-set", "--format", "json"])
        .arg(&cfg)
        .output()?;
    assert_eq!(out.status.code(), neighbor.status.code());

    let _ = fs::remove_dir_all(&base);
    Ok(())
}

#[test]
fn check_help_documents_narrowed_scope_and_d3_without_overclaiming() -> TestResult {
    let out = Command::new(miraserve_bin())
        .args(["check", "--help"])
        .output()?;
    assert_eq!(out.status.code(), Some(0));
    let help = String::from_utf8(out.stdout)?;
    assert!(help.contains("--trusted-paths"), "help:\n{help}");
    assert!(help.contains("--fs"), "help:\n{help}");
    assert!(help.contains("W034"), "help:\n{help}");
    assert!(help.contains("Linux-only"), "help:\n{help}");
    assert!(help.contains("socket-tree"), "help:\n{help}");
    assert!(help.contains("fastcgi-pass"), "help:\n{help}");
    assert!(help.contains("keyd-socket"), "help:\n{help}");
    assert!(help.contains("ACME"), "help:\n{help}");
    assert!(help.contains("ai-publish"), "help:\n{help}");
    assert!(help.contains("rotating log"), "help:\n{help}");
    assert!(
        !help.to_ascii_lowercase().contains("race-free"),
        "help:\n{help}"
    );
    assert!(
        !help.to_ascii_lowercase().contains("secure layout"),
        "help:\n{help}"
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[test]
fn non_linux_trusted_paths_prints_plain_note_and_zero_w034() -> TestResult {
    let base = make_temp_base("nonlinux")?;
    let (cert, key) = gen_dev_cert(&base)?;
    let root = base.join("www");
    fs::create_dir_all(&root)?;
    let cfg = base.join("site.kdl");
    fs::write(
        &cfg,
        format!(
            "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }} }}\n\
             site \"tp.example\" {{ root \"{}\" }}\n",
            kdl_escape_path(&cert),
            kdl_escape_path(&key),
            kdl_escape_path(&root),
        ),
    )?;

    let text = Command::new(miraserve_bin())
        .args(["check", "--fs", "--strict", "--trusted-paths"])
        .arg(&cfg)
        .output()?;
    assert_eq!(text.status.code(), Some(0));
    let stdout = String::from_utf8(text.stdout)?;
    let stderr = String::from_utf8(text.stderr)?;
    assert!(
        stdout.contains("note: --trusted-paths is Linux-only; no paths were verified\n"),
        "stdout:\n{stdout}"
    );
    assert!(!stderr.contains("W034"), "stderr:\n{stderr}");

    let json_out = Command::new(miraserve_bin())
        .args([
            "check",
            "--fs",
            "--strict",
            "--trusted-paths",
            "--format",
            "json",
        ])
        .arg(&cfg)
        .output()?;
    assert_eq!(json_out.status.code(), Some(0));
    let val: serde_json::Value = serde_json::from_slice(&json_out.stdout)?;
    assert_eq!(val.get("valid"), Some(&serde_json::Value::Bool(true)));
    assert_eq!(
        val.get("warnings")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(0),
        "warnings: {val}"
    );
    assert_eq!(
        val.get("notes"),
        Some(&serde_json::json!([
            "--trusted-paths is Linux-only; no paths were verified"
        ]))
    );

    let _ = fs::remove_dir_all(&base);
    Ok(())
}

// ---------------------------------------------------------------------------
// Test S & Linux F: real Linux filesystem trees, zero timing, literal asserts
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux_tests {
    use std::os::unix::net::UnixListener;

    use super::*;

    const NARROWED_NOTE_LITERAL: &str = "trusted-paths (narrowed): does not yet inspect config file, \
        read-tree, site/route roots, owner-dir, TLS certs/keys/CAs, keyd-auth-secret-file, \
        acme-webroot, basic-auth, bot-auth, ai-publish keys, error-pages, upstream-tls, \
        mcp-gateway, wasm-plugin, or non-rotating log paths";

    fn make_pub_key(dir: &Path) -> Result<PathBuf, std::io::Error> {
        let p = dir.join("publish.pub");
        fs::write(&p, b"0123456789abcdef0123456789abcdef\n")?;
        set_mode(&p, 0o640)?;
        Ok(p)
    }

    fn expected_default_observer_note() -> String {
        let euid = rustix::process::geteuid().as_raw();
        if euid == 0 {
            "trusted-paths: running as root; service uid is unknown, so only uid 0 is trusted (server.sandbox.user is unset)".to_owned()
        } else {
            format!(
                "trusted-paths: trusting uid 0 and service uid {euid} (effective uid of this check)"
            )
        }
    }

    fn run_json(
        args: &[&str],
        cfg: &Path,
    ) -> Result<(Option<i32>, serde_json::Value), Box<dyn std::error::Error>> {
        run_json_in(args, cfg, None)
    }

    fn run_json_in(
        args: &[&str],
        cfg: &Path,
        cwd: Option<&Path>,
    ) -> Result<(Option<i32>, serde_json::Value), Box<dyn std::error::Error>> {
        let mut cmd = Command::new(miraserve_bin());
        cmd.arg("check")
            .args(args)
            .arg("--format")
            .arg("json")
            .arg(cfg);
        if let Some(dir) = cwd {
            cmd.current_dir(dir);
        }
        let out = cmd.output()?;
        let val: serde_json::Value = serde_json::from_slice(&out.stdout).map_err(|e| {
            format!(
                "invalid json ({e}); stdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
            )
        })?;
        Ok((out.status.code(), val))
    }

    fn jstr<'a>(val: &'a serde_json::Value, key: &str) -> Option<&'a str> {
        val.get(key).and_then(serde_json::Value::as_str)
    }

    fn w034s(val: &serde_json::Value) -> Vec<&serde_json::Value> {
        val.get("warnings")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter(|w| jstr(w, "code") == Some("W034"))
            .collect()
    }

    fn w029_of(val: &serde_json::Value) -> Vec<&serde_json::Value> {
        val.get("warnings")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter(|w| jstr(w, "code") == Some("W029"))
            .collect()
    }

    fn note_at(val: &serde_json::Value, idx: usize) -> Option<&str> {
        val.get("notes")
            .and_then(serde_json::Value::as_array)
            .and_then(|a| a.get(idx))
            .and_then(serde_json::Value::as_str)
    }

    #[test]
    fn linux_trusted_chain_all_six_classes_and_narrowed_exclusions() -> TestResult {
        let base = make_temp_base("clean")?;
        let (cert, key) = gen_dev_cert(&base)?;
        let pub_key = make_pub_key(&base)?;
        let sock_dir = base.join("php");
        let acme_dir = base.join("acme");
        let store_dir = base.join("store");
        let log_dir = base.join("logs");
        let uncov_bad = base.join("uncovered_bad");
        let docroot = uncov_bad.join("www");
        let read_tree = uncov_bad.join("rtree");
        for d in [
            &sock_dir, &acme_dir, &store_dir, &log_dir, &uncov_bad, &docroot, &read_tree,
        ] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o750)?;
        }
        set_mode(&acme_dir, 0o700)?;
        // Intentionally make a non-covered ancestor (`site.root`, `read-tree`) world-writable:
        // Stage 1a MUST NOT inspect them!
        set_mode(&uncov_bad, 0o777)?;

        let sock = sock_dir.join("pool.sock");
        let _listener = UnixListener::bind(&sock)?;
        set_mode(&sock, 0o660)?;

        let cfg = base.join("clean.kdl");
        fs::write(
            &cfg,
            format!(
                "server {{\n\
                     listen \":443\"\n\
                     tls {{ cert \"{}\"; key \"{}\" }}\n\
                     sandbox {{ read-tree \"{}\"; socket-tree \"{}\" }}\n\
                 }}\n\
                 site \"tp.example\" {{\n\
                     root \"{}\"\n\
                     ai-publish {{\n\
                         storage \"{}\"\n\
                         require-signature \"ed25519:{}\"\n\
                     }}\n\
                     route \"*.php\" {{ fastcgi-pass \"unix:{}\" }}\n\
                 }}\n",
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&read_tree),
                kdl_escape_path(&sock_dir),
                kdl_escape_path(&docroot),
                kdl_escape_path(&store_dir),
                kdl_escape_path(&pub_key),
                kdl_escape_path(&sock),
            ),
        )?;

        let log_f = log_dir.join("server.log");
        let acc_f = log_dir.join("access.log");
        let (code, val) = run_json(
            &[
                "--fs",
                "--strict",
                "--trusted-paths",
                "--acme-dir",
                &acme_dir.to_string_lossy(),
                "--log-file",
                &log_f.to_string_lossy(),
                "--access-log",
                &acc_f.to_string_lossy(),
                "--log-max-bytes",
                "1024",
            ],
            &cfg,
        )?;
        assert_eq!(code, Some(0), "clean json: {val}");
        assert_eq!(val.get("valid"), Some(&serde_json::Value::Bool(true)));
        assert!(w034s(&val).is_empty(), "expected 0 W034, got: {val}");
        assert_eq!(
            note_at(&val, 0),
            Some(expected_default_observer_note().as_str())
        );
        assert_eq!(note_at(&val, 1), Some(NARROWED_NOTE_LITERAL));

        // Clean keyd-socket (split-daemon, absent socket in trusted parent) emits 0 W034.
        let keyd_sock = sock_dir.join("keyd.sock");
        let keyd_cfg = base.join("keyd.kdl");
        fs::write(
            &keyd_cfg,
            format!(
                "server {{\n\
                     listen \":443\"\n\
                     tls {{ key-isolation \"split-daemon\"; keyd-socket \"{}\"; cert \"{}\"; key \"{}\" }}\n\
                 }}\n\
                 site \"tp.example\" {{ root \"{}\" }}\n",
                kdl_escape_path(&keyd_sock),
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&docroot),
            ),
        )?;
        let (_kcode, kval) = run_json(&["--fs", "--trusted-paths"], &keyd_cfg)?;
        assert!(
            w034s(&kval).is_empty(),
            "clean keyd must emit 0 W034: {kval}"
        );

        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    fn linux_group_and_other_writable_first_component_strict_allow_and_writable_set() -> TestResult
    {
        let base = make_temp_base("writable")?;
        let (cert, key) = gen_dev_cert(&base)?;
        let pub_key = make_pub_key(&base)?;
        let euid = rustix::process::geteuid().as_raw();
        let gw = base.join("gw");
        let ow = gw.join("ow");
        let store = ow.join("store");
        fs::create_dir_all(&store)?;
        set_mode(&gw, 0o775)?;
        set_mode(&ow, 0o777)?;
        set_mode(&store, 0o750)?;

        let cfg = base.join("gw.kdl");
        fs::write(
            &cfg,
            format!(
                "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }} }}\n\
                 site \"tp.example\" {{ ai-publish {{ storage \"{}\"; require-signature \"ed25519:{}\" }} }}\n",
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&store),
                kdl_escape_path(&pub_key),
            ),
        )?;

        // 1. `--strict` fails with exit 1, reporting FIRST untrusted component (`gw`, NOT `ow`!).
        let (code, val) = run_json(&["--fs", "--strict", "--trusted-paths"], &cfg)?;
        assert_eq!(code, Some(1), "strict must fail on W034: {val}");
        assert_eq!(val.get("valid"), Some(&serde_json::Value::Bool(false)));
        let ws = w034s(&val);
        assert_eq!(ws.len(), 1, "expected 1 W034: {val}");
        let w = ws.first().copied().ok_or("missing W034")?;
        assert_eq!(jstr(w, "path"), Some("site[0].ai-publish.storage"));
        assert_eq!(
            jstr(w, "message"),
            Some(
                format!(
                    "site 'tp.example' ai-publish storage '{}': first untrusted component '{}' \
                     (uid {euid}, mode 0775): group or other writable",
                    store.display(),
                    gw.display()
                )
                .as_str()
            )
        );

        // 2. `--allow-warning W034` passes `--strict` (exit 0) while STILL emitting W034!
        let (allow_code, allow_val) = run_json(
            &[
                "--fs",
                "--strict",
                "--trusted-paths",
                "--allow-warning",
                "W034",
            ],
            &cfg,
        )?;
        assert_eq!(
            allow_code,
            Some(0),
            "allow-warning W034 must pass: {allow_val}"
        );
        assert_eq!(allow_val.get("valid"), Some(&serde_json::Value::Bool(true)));
        assert_eq!(w034s(&allow_val).len(), 1);

        // 3. Text mode on failed `--strict` prints warning[W034], help, AND both notes on stderr.
        let txt = Command::new(miraserve_bin())
            .args(["check", "--fs", "--strict", "--trusted-paths"])
            .arg(&cfg)
            .output()?;
        assert_eq!(txt.status.code(), Some(1));
        assert_eq!(String::from_utf8(txt.stdout)?, "");
        let stderr = String::from_utf8(txt.stderr)?;
        let expected_warn = format!(
            "warning[W034]: site 'tp.example' ai-publish storage '{}': first untrusted component '{}' \
             (uid {euid}, mode 0775): group or other writable\n",
            store.display(),
            gw.display()
        );
        assert!(stderr.contains(&expected_warn), "stderr:\n{stderr}");
        assert!(
            stderr.contains("  help: keep every ancestor"),
            "stderr:\n{stderr}"
        );
        assert!(
            stderr.contains(&format!("note: {}\n", expected_default_observer_note())),
            "stderr:\n{stderr}"
        );
        assert!(
            stderr.contains(&format!("note: {NARROWED_NOTE_LITERAL}\n")),
            "stderr:\n{stderr}"
        );

        // 4. `--writable-set` keeps stdout strictly machine-readable (no `note:` lines on stdout).
        let ws_out = Command::new(miraserve_bin())
            .args(["check", "--fs", "--trusted-paths", "--writable-set"])
            .arg(&cfg)
            .output()?;
        assert_eq!(ws_out.status.code(), Some(0));
        let ws_stdout = String::from_utf8(ws_out.stdout)?;
        let ws_stderr = String::from_utf8(ws_out.stderr)?;
        assert!(ws_stdout.starts_with("landlock "), "stdout:\n{ws_stdout}");
        assert!(!ws_stdout.contains("note:"), "stdout:\n{ws_stdout}");
        assert!(ws_stderr.contains("warning[W034]:"), "stderr:\n{ws_stderr}");

        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn linux_sticky_directory_existing_trusted_missing_child_and_sticky_leaf() -> TestResult {
        let base = make_temp_base("sticky")?;
        let (cert, key) = gen_dev_cert(&base)?;
        let pub_key = make_pub_key(&base)?;
        let euid = rustix::process::geteuid().as_raw();
        let sticky = base.join("sticky");
        let existing_child = sticky.join("ok_store");
        fs::create_dir_all(&existing_child)?;
        set_mode(&sticky, 0o1777)?;
        set_mode(&existing_child, 0o750)?;

        // 1. Existing trusted child inside sticky dir -> ACCEPTED (0 W034).
        let ok_cfg = base.join("sticky_ok.kdl");
        fs::write(
            &ok_cfg,
            format!(
                "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }} }}\n\
                 site \"tp.example\" {{ ai-publish {{ storage \"{}\"; require-signature \"ed25519:{}\" }} }}\n",
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&existing_child),
                kdl_escape_path(&pub_key),
            ),
        )?;
        let (code, val) = run_json(&["--fs", "--strict", "--trusted-paths"], &ok_cfg)?;
        assert_eq!(
            code,
            Some(0),
            "existing child in sticky dir must pass: {val}"
        );
        assert!(w034s(&val).is_empty(), "val: {val}");

        // 2. Absent direct child, deeper absent child, AND sticky dir itself as leaf -> REPORTED!
        let missing_direct = sticky.join("absent_acme");
        let missing_deep = sticky.join("absent_mid/leaf_store");
        let miss_cfg = base.join("sticky_miss.kdl");
        fs::write(
            &miss_cfg,
            format!(
                "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }}; sandbox {{ socket-tree \"{}\" }} }}\n\
                 site \"tp.example\" {{ ai-publish {{ storage \"{}\"; require-signature \"ed25519:{}\" }} }}\n",
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&sticky),
                kdl_escape_path(&missing_deep),
                kdl_escape_path(&pub_key),
            ),
        )?;
        let (_code, mval) = run_json(
            &[
                "--fs",
                "--trusted-paths",
                "--acme-dir",
                &missing_direct.to_string_lossy(),
            ],
            &miss_cfg,
        )?;
        let ws = w034s(&mval);
        assert_eq!(ws.len(), 3, "expected 3 W034s: {mval}");
        assert_eq!(
            ws.first().and_then(|w| jstr(w, "path")),
            Some("server.sandbox.socket-tree")
        );
        assert_eq!(
            ws.first().and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "server.sandbox socket-tree root '{}': first untrusted component '{}' \
                     (uid {euid}, mode 1777): group or other writable",
                    sticky.display(),
                    sticky.display()
                )
                .as_str()
            )
        );
        assert_eq!(
            ws.get(1).and_then(|w| jstr(w, "path")),
            Some("site[0].ai-publish.storage")
        );
        assert_eq!(
            ws.get(1).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "site 'tp.example' ai-publish storage '{}': first untrusted component '{}' \
                     (uid {euid}, mode 1777): missing component under a parent where another account could create it",
                    missing_deep.display(),
                    sticky.display()
                )
                .as_str()
            )
        );
        assert_eq!(
            ws.get(2).and_then(|w| jstr(w, "path")),
            Some("server.tls.acme")
        );
        assert_eq!(
            ws.get(2).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "ACME directory '{}': first untrusted component '{}' \
                     (uid {euid}, mode 1777): missing component under a parent where another account could create it",
                    missing_direct.display(),
                    sticky.display()
                )
                .as_str()
            )
        );

        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn linux_symlinks_relative_acme_loop_and_non_lexical_dotdot() -> TestResult {
        use std::os::unix::fs::symlink;

        let base = make_temp_base("symlinks")?;
        let (cert, key) = gen_dev_cert(&base)?;
        let pub_key = make_pub_key(&base)?;
        let euid = rustix::process::geteuid().as_raw();

        let good_dir = base.join("good_dir");
        let good_target_a = base.join("good_target_a");
        let good_target_b = base.join("good_target_b");
        let good_sub = good_target_a.join("sub");
        let docroot = base.join("www");
        let bad_dir = base.join("bad_dir");
        let bad_target = bad_dir.join("inner");
        for d in [
            &good_dir,
            &good_target_a,
            &good_target_b,
            &good_sub,
            &docroot,
            &bad_dir,
            &bad_target,
        ] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o750)?;
        }
        set_mode(&bad_dir, 0o777)?;

        let abs_ok_link = good_dir.join("abs_ok");
        symlink(&good_target_a, &abs_ok_link)?;
        let rel_ok_link = good_dir.join("rel_ok");
        symlink("../good_target_b", &rel_ok_link)?;
        let sym_good_sub = good_dir.join("sym_sub");
        symlink(&good_sub, &sym_good_sub)?;
        let bad_tgt_link = good_dir.join("to_bad");
        symlink(&bad_target, &bad_tgt_link)?;
        let bad_dotdot_link = good_dir.join("to_bad_dotdot");
        symlink(bad_dir.join("../good_target_a"), &bad_dotdot_link)?;
        let bad_parent_link = bad_dir.join("to_good");
        symlink(&good_target_a, &bad_parent_link)?;
        let loop_a = good_dir.join("loop_a");
        let loop_b = good_dir.join("loop_b");
        symlink(&loop_b, &loop_a)?;
        symlink(&loop_a, &loop_b)?;

        // 1. Trusted absolute link, trusted relative link, and trusted `..` suffixes -> 0 W034!
        let ok_dotdot_log = good_dir.join("../good_target_a/server.log");
        let ok_sym_dotdot_acc = sym_good_sub.join("../access.log");
        let ok_cfg = base.join("sym_ok.kdl");
        fs::write(
            &ok_cfg,
            format!(
                "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }} }}\n\
                 site \"a.example\" {{ ai-publish {{ storage \"{}\"; require-signature \"ed25519:{}\" }} }}\n\
                 site \"b.example\" {{ ai-publish {{ storage \"{}\"; require-signature \"ed25519:{}\" }} }}\n",
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&abs_ok_link),
                kdl_escape_path(&pub_key),
                kdl_escape_path(&rel_ok_link),
                kdl_escape_path(&pub_key),
            ),
        )?;
        let (ok_code, ok_val) = run_json(
            &[
                "--fs",
                "--strict",
                "--trusted-paths",
                "--log-file",
                &ok_dotdot_log.to_string_lossy(),
                "--access-log",
                &ok_sym_dotdot_acc.to_string_lossy(),
                "--log-max-bytes",
                "1024",
            ],
            &ok_cfg,
        )?;
        assert_eq!(
            ok_code,
            Some(0),
            "trusted symlinks & .. must pass: {ok_val}"
        );
        assert!(w034s(&ok_val).is_empty(), "ok_val: {ok_val}");

        // 2. Untrusted target, untrusted parent of link, loop, `..` in symlink target,
        //    ACME symlink, and direct non-lexical `..` on rotating log paths!
        let bad_dotdot_log = bad_dir.join("../good_target_a/app.log");
        let bad_sym_dotdot_acc = bad_tgt_link.join("../acc.log");
        let bad_cfg = base.join("sym_bad.kdl");
        fs::write(
            &bad_cfg,
            format!(
                "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }} }}\n\
                 site \"t.example\" {{ root \"{}\"; route \"*.php\" {{ fastcgi-pass \"unix:{}/p.sock\" }} }}\n\
                 site \"p.example\" {{ root \"{}\"; route \"*.php\" {{ fastcgi-pass \"unix:{}/p.sock\" }} }}\n\
                 site \"l.example\" {{ root \"{}\"; route \"*.php\" {{ fastcgi-pass \"unix:{}/p.sock\" }} }}\n\
                 site \"d.example\" {{ root \"{}\"; route \"*.php\" {{ fastcgi-pass \"unix:{}/p.sock\" }} }}\n",
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&docroot),
                kdl_escape_path(&bad_tgt_link),
                kdl_escape_path(&docroot),
                kdl_escape_path(&bad_parent_link),
                kdl_escape_path(&docroot),
                kdl_escape_path(&loop_a),
                kdl_escape_path(&docroot),
                kdl_escape_path(&bad_dotdot_link),
            ),
        )?;
        let (_code, bval) = run_json(
            &[
                "--fs",
                "--trusted-paths",
                "--acme-dir",
                &abs_ok_link.to_string_lossy(),
                "--log-file",
                &bad_dotdot_log.to_string_lossy(),
                "--access-log",
                &bad_sym_dotdot_acc.to_string_lossy(),
                "--log-max-bytes",
                "1024",
            ],
            &bad_cfg,
        )?;
        let ws = w034s(&bval);
        assert_eq!(ws.len(), 7, "expected 7 W034s: {bval}");

        assert_eq!(
            ws.first().and_then(|w| jstr(w, "path")),
            Some("site[0].route[0].fastcgi-pass")
        );
        assert_eq!(
            ws.first().and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "site 't.example' FastCGI Unix socket '{}/p.sock': first untrusted component '{}' \
                     (uid {euid}, mode 0777): symbolic link whose own parent or target chain is untrusted \
                     (via '{}': group or other writable)",
                    bad_tgt_link.display(),
                    bad_dir.display(),
                    bad_tgt_link.display()
                )
                .as_str()
            )
        );
        assert_eq!(
            ws.get(1).and_then(|w| jstr(w, "path")),
            Some("site[1].route[0].fastcgi-pass")
        );
        assert_eq!(
            ws.get(1).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "site 'p.example' FastCGI Unix socket '{}/p.sock': first untrusted component '{}' \
                     (uid {euid}, mode 0777): group or other writable",
                    bad_parent_link.display(),
                    bad_dir.display()
                )
                .as_str()
            )
        );
        assert_eq!(
            ws.get(2).and_then(|w| jstr(w, "path")),
            Some("site[2].route[0].fastcgi-pass")
        );
        assert!(
            ws.get(2).and_then(|w| jstr(w, "message")).is_some_and(
                |m| m.contains("could not be inspected (Too many levels of symbolic links")
            ),
            "loop msg: {:?}",
            ws.get(2)
        );
        assert_eq!(
            ws.get(3).and_then(|w| jstr(w, "path")),
            Some("site[3].route[0].fastcgi-pass")
        );
        assert_eq!(
            ws.get(3).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "site 'd.example' FastCGI Unix socket '{}/p.sock': first untrusted component '{}' \
                     (uid {euid}, mode 0777): symbolic link whose own parent or target chain is untrusted \
                     (via '{}': group or other writable)",
                    bad_dotdot_link.display(),
                    bad_dir.display(),
                    bad_dotdot_link.display()
                )
                .as_str()
            )
        );
        assert_eq!(
            ws.get(4).and_then(|w| jstr(w, "path")),
            Some("server.tls.acme")
        );
        assert_eq!(
            ws.get(4).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "ACME directory '{}': first untrusted component '{}' \
                     (uid {euid}, mode 0777): symbolic link whose own parent or target chain is untrusted \
                     (symbolic links are not allowed for this role)",
                    abs_ok_link.display(),
                    abs_ok_link.display()
                )
                .as_str()
            )
        );
        assert_eq!(
            ws.get(5).and_then(|w| jstr(w, "path")),
            Some("server.log-file")
        );
        assert_eq!(
            ws.get(5).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "rotating --log-file parent directory '{}/../good_target_a': first untrusted component '{}' \
                     (uid {euid}, mode 0777): group or other writable",
                    bad_dir.display(),
                    bad_dir.display()
                )
                .as_str()
            )
        );
        assert_eq!(
            ws.get(6).and_then(|w| jstr(w, "path")),
            Some("server.access-log")
        );
        assert_eq!(
            ws.get(6).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "rotating --access-log parent directory '{}/..': first untrusted component '{}' \
                     (uid {euid}, mode 0777): symbolic link whose own parent or target chain is untrusted \
                     (via '{}': group or other writable)",
                    bad_tgt_link.display(),
                    bad_dir.display(),
                    bad_tgt_link.display()
                )
                .as_str()
            )
        );

        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    fn linux_relative_paths_walk_cwd_from_root() -> TestResult {
        let base = make_temp_base("relcwd")?;
        let docroot = base.join("www");
        let good_cwd = base.join("good_cwd");
        let good_acme = good_cwd.join(".miraserve-acme");
        let bad_cwd = base.join("bad_cwd");
        let bad_acme = bad_cwd.join(".miraserve-acme");
        let euid = rustix::process::geteuid().as_raw();
        for d in [&docroot, &good_cwd, &good_acme, &bad_cwd, &bad_acme] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o750)?;
        }
        set_mode(&good_acme, 0o700)?;
        set_mode(&bad_acme, 0o700)?;
        set_mode(&bad_cwd, 0o777)?;

        let cfg = base.join("rel.kdl");
        fs::write(
            &cfg,
            format!(
                "server {{\n\
                     listen \":443\"\n\
                     tls {{ acme {{ email \"ops@example.com\"; challenge \"tls-alpn-01\" }} }}\n\
                 }}\n\
                 site \"rel.example\" {{ root \"{}\" }}\n",
                kdl_escape_path(&docroot),
            ),
        )?;

        // Relative default `.miraserve-acme` and relative `--log-file app.log` (parent `.`)
        // under trusted `good_cwd` -> 0 W034!
        let (ok_code, ok_val) = run_json_in(
            &[
                "--fs",
                "--trusted-paths",
                "--log-file",
                "app.log",
                "--log-max-bytes",
                "1024",
            ],
            &cfg,
            Some(&good_cwd),
        )?;
        assert_eq!(ok_code, Some(0), "good cwd json: {ok_val}");
        assert!(
            w034s(&ok_val).is_empty(),
            "good cwd must emit 0 W034: {ok_val}"
        );

        // Same config under world-writable `bad_cwd` -> BOTH report `bad_cwd`!
        let (_bad_code, bad_val) = run_json_in(
            &[
                "--fs",
                "--trusted-paths",
                "--log-file",
                "app.log",
                "--log-max-bytes",
                "1024",
            ],
            &cfg,
            Some(&bad_cwd),
        )?;
        let ws = w034s(&bad_val);
        assert_eq!(ws.len(), 2, "expected 2 W034s for bad cwd: {bad_val}");
        assert_eq!(
            ws.first().and_then(|w| jstr(w, "path")),
            Some("server.tls.acme")
        );
        assert_eq!(
            ws.first().and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "ACME directory '.miraserve-acme': first untrusted component '{}' \
                     (uid {euid}, mode 0777): group or other writable",
                    bad_cwd.display()
                )
                .as_str()
            )
        );
        assert_eq!(
            ws.get(1).and_then(|w| jstr(w, "path")),
            Some("server.log-file")
        );
        assert_eq!(
            ws.get(1).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "rotating --log-file parent directory '.': first untrusted component '{}' \
                     (uid {euid}, mode 0777): group or other writable",
                    bad_cwd.display()
                )
                .as_str()
            )
        );

        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn linux_absent_uninspectable_fs_guard_two_sites_all_json_paths_and_w029_frozen() -> TestResult
    {
        use std::os::unix::fs::symlink;

        let base = make_temp_base("matrix")?;
        let (cert, key) = gen_dev_cert(&base)?;
        let pub_key = make_pub_key(&base)?;
        let euid = rustix::process::geteuid().as_raw();

        let good = base.join("good");
        let docroot = good.join("www");
        let bad = base.join("bad");
        let not_a_dir = base.join("regular_file");
        let no_search = base.join("no_search");
        let webroot = bad.join("webroot");
        let store0 = bad.join("store0");
        let store1 = bad.join("store1");
        for d in [
            &good, &docroot, &bad, &no_search, &webroot, &store0, &store1,
        ] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o750)?;
        }
        fs::write(&not_a_dir, b"x")?;
        let proc_link = good.join("proc_link");
        symlink("/proc/self", &proc_link)?;
        set_mode(&bad, 0o775)?;
        let keyd_sock = bad.join("keyd.sock");
        let shared_sock = bad.join("shared.sock");
        let absent_good = good.join("absent.sock");
        let bad_log = bad.join("app.log");
        let bad_acc = bad.join("acc.log");

        let cfg = base.join("matrix.kdl");
        fs::write(
            &cfg,
            format!(
                "server {{\n\
                     listen \":443\"\n\
                     acme-webroot \"{}\"\n\
                     tls {{ key-isolation \"split-daemon\"; keyd-socket \"{}\"; cert \"{}\"; key \"{}\" }}\n\
                     sandbox {{ socket-tree \"{}\" }}\n\
                 }}\n\
                 site \"s0.example\" {{\n\
                     root \"{}\"\n\
                     ai-publish {{ storage \"{}\"; require-signature \"ed25519:{}\" }}\n\
                     route \"/a/*\" {{ fastcgi-pass \"unix:{}\" }}\n\
                     route \"/ok/*\" {{ fastcgi-pass \"unix:{}\" }}\n\
                     route \"/proc/*\" {{ fastcgi-pass \"unix:{}/p.sock\" }}\n\
                 }}\n\
                 site \"s1.example\" {{\n\
                     root \"{}\"\n\
                     ai-publish {{ storage \"{}\"; require-signature \"ed25519:{}\" }}\n\
                     route \"/b/*\" {{ fastcgi-pass \"unix:{}\" }}\n\
                     route \"/nd/*\" {{ fastcgi-pass \"unix:{}/child.sock\" }}\n\
                 }}\n",
                kdl_escape_path(&webroot),
                kdl_escape_path(&keyd_sock),
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&bad),
                kdl_escape_path(&docroot),
                kdl_escape_path(&store0),
                kdl_escape_path(&pub_key),
                kdl_escape_path(&shared_sock),
                kdl_escape_path(&absent_good),
                kdl_escape_path(&proc_link),
                kdl_escape_path(&docroot),
                kdl_escape_path(&store1),
                kdl_escape_path(&pub_key),
                kdl_escape_path(&shared_sock),
                kdl_escape_path(&not_a_dir),
            ),
        )?;

        let acme_bad = bad.join("acme");
        let (_, val_without) = run_json(
            &[
                "--fs",
                "--acme-dir",
                &acme_bad.to_string_lossy(),
                "--log-file",
                &bad_log.to_string_lossy(),
                "--access-log",
                &bad_acc.to_string_lossy(),
                "--log-max-bytes",
                "1024",
            ],
            &cfg,
        )?;
        let (_, val_with) = run_json(
            &[
                "--fs",
                "--trusted-paths",
                "--acme-dir",
                &acme_bad.to_string_lossy(),
                "--log-file",
                &bad_log.to_string_lossy(),
                "--access-log",
                &bad_acc.to_string_lossy(),
                "--log-max-bytes",
                "1024",
            ],
            &cfg,
        )?;

        // D5: W029 warnings must be identical with and without `--trusted-paths`!
        let w029_without = w029_of(&val_without);
        let w029_with = w029_of(&val_with);
        assert!(
            !w029_without.is_empty(),
            "expected W029 on bad webroot: {val_without}"
        );
        assert_eq!(w029_with, w029_without, "W029 must remain frozen");

        // Verify all 11 expected W034 paths in exact deterministic order (absent_good must NOT warn!)
        let ws = w034s(&val_with);
        let paths: Vec<Option<&str>> = ws.iter().map(|w| jstr(w, "path")).collect();
        assert_eq!(
            paths,
            vec![
                Some("server.sandbox.socket-tree"),
                Some("site[0].route[0].fastcgi-pass"),
                Some("site[0].route[2].fastcgi-pass"),
                Some("site[0].ai-publish.storage"),
                Some("site[1].route[0].fastcgi-pass"),
                Some("site[1].route[1].fastcgi-pass"),
                Some("site[1].ai-publish.storage"),
                Some("server.tls.keyd-socket"),
                Some("server.tls.acme"),
                Some("server.log-file"),
                Some("server.access-log"),
            ],
            "unexpected W034 paths: {ws:#?}"
        );
        assert_eq!(
            ws.get(2).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "site 's0.example' FastCGI Unix socket '{}/p.sock': first untrusted component \
                     '/proc' (uid 0, mode 0555): could not be verified on this filesystem \
                     (filesystem 0x9fa0)",
                    proc_link.display()
                )
                .as_str()
            )
        );
        assert_eq!(
            ws.get(5).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "site 's1.example' FastCGI Unix socket '{}/child.sock': first untrusted component \
                     '{}' (uid unknown, mode unknown): could not be inspected \
                     (Not a directory (os error 20))",
                    not_a_dir.display(),
                    not_a_dir.display()
                )
                .as_str()
            )
        );

        // Non-root EACCES uninspectable component (`chmod 0000` on parent -> `openat` child fails!)
        if euid != 0 {
            let hidden = no_search.join("secret.sock");
            set_mode(&no_search, 0o000)?;
            let eacces_cfg = base.join("eacces.kdl");
            fs::write(
                &eacces_cfg,
                format!(
                    "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }} }}\n\
                     site \"x.example\" {{ root \"{}\"; route \"*.php\" {{ fastcgi-pass \"unix:{}\" }} }}\n",
                    kdl_escape_path(&cert),
                    kdl_escape_path(&key),
                    kdl_escape_path(&docroot),
                    kdl_escape_path(&hidden),
                ),
            )?;
            let (_c, eval) = run_json(&["--fs", "--trusted-paths"], &eacces_cfg)?;
            set_mode(&no_search, 0o750)?;
            let ews = w034s(&eval);
            assert_eq!(ews.len(), 1, "expected 1 W034 on EACCES: {eval}");
            assert_eq!(
                ews.first().and_then(|w| jstr(w, "message")),
                Some(
                    format!(
                        "site 'x.example' FastCGI Unix socket '{}': first untrusted component '{}' \
                         (uid unknown, mode unknown): could not be inspected \
                         (Permission denied (os error 13))",
                        hidden.display(),
                        hidden.display()
                    )
                    .as_str()
                )
            );
        }

        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    fn linux_cli_trusted_paths_succeeds_under_openat2_enosys_and_kill_process() -> TestResult {
        use seccompiler::{SeccompAction, SeccompFilter, TargetArch};
        use std::collections::BTreeMap;

        const SYS_OPENAT2: i64 = 437;
        let base = make_temp_base("openat2-cli")?;
        let (cert, key) = gen_dev_cert(&base)?;
        let pub_key = make_pub_key(&base)?;
        let sock_dir = base.join("socks");
        let store_dir = base.join("store");
        let docroot = base.join("www");
        for d in [&sock_dir, &store_dir, &docroot] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o750)?;
        }

        let cfg = base.join("o2.kdl");
        fs::write(
            &cfg,
            format!(
                "server {{\n\
                     listen \":443\"\n\
                     tls {{ cert \"{}\"; key \"{}\" }}\n\
                     sandbox {{ socket-tree \"{}\" }}\n\
                 }}\n\
                 site \"o2.example\" {{\n\
                     root \"{}\"\n\
                     ai-publish {{ storage \"{}\"; require-signature \"ed25519:{}\" }}\n\
                     route \"*.php\" {{ fastcgi-pass \"unix:{}/pool.sock\" }}\n\
                 }}\n",
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&sock_dir),
                kdl_escape_path(&docroot),
                kdl_escape_path(&store_dir),
                kdl_escape_path(&pub_key),
                kdl_escape_path(&sock_dir),
            ),
        )?;

        for action in [SeccompAction::Errno(38), SeccompAction::KillProcess] {
            let arch = TargetArch::try_from(std::env::consts::ARCH)?;
            let mut rules = BTreeMap::new();
            rules.insert(SYS_OPENAT2, Vec::new());
            if arch == TargetArch::x86_64 {
                rules.insert(SYS_OPENAT2 | 0x4000_0000, Vec::new());
            }
            let bpf: seccompiler::BpfProgram =
                SeccompFilter::new(rules, SeccompAction::Allow, action.clone(), arch)?
                    .try_into()?;
            let cfg_c = cfg.clone();
            let out = std::thread::spawn(move || -> Result<std::process::Output, String> {
                seccompiler::apply_filter(&bpf).map_err(|e| e.to_string())?;
                Command::new(miraserve_bin())
                    .args([
                        "check",
                        "--fs",
                        "--strict",
                        "--trusted-paths",
                        "--format",
                        "json",
                    ])
                    .arg(&cfg_c)
                    .output()
                    .map_err(|e| e.to_string())
            })
            .join()
            .map_err(|_| "seccomp thread panicked")?
            .map_err(|e| format!("seccomp child failed: {e}"))?;
            assert_eq!(
                out.status.code(),
                Some(0),
                "check --fs --trusted-paths failed under openat2 filter ({action:?}); stderr:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let val: serde_json::Value = serde_json::from_slice(&out.stdout)?;
            assert!(w034s(&val).is_empty(), "val: {val}");
        }

        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn linux_root_second_uid_ownership_socket_producer_and_sandbox_user() -> TestResult {
        use rustix::fs::{AtFlags, CWD, Gid, Uid, chown, chownat};
        use std::os::unix::fs::symlink;

        if !rustix::process::geteuid().is_root() {
            eprintln!(
                "skipping linux_root_second_uid_ownership_socket_producer_and_sandbox_user: requires root"
            );
            return Ok(());
        }

        let base = make_temp_base("root-multiuid")?;
        let (cert, key) = gen_dev_cert(&base)?;
        let pub_key = make_pub_key(&base)?;

        let docroot = base.join("www");
        let php_dir = base.join("php_producer");
        let root_sock_dir = base.join("root_socks");
        let keyd_dir = base.join("keyd_dir");
        let sticky_dir = base.join("sticky_root");
        let sticky_u1000 = sticky_dir.join("u1000_store");
        let sticky_sym_u1000 = sticky_dir.join("u1000_link");
        let u1000_store = base.join("u1000_store");
        let u1001_store = base.join("u1001_store");
        for d in [
            &docroot,
            &php_dir,
            &root_sock_dir,
            &keyd_dir,
            &sticky_dir,
            &sticky_u1000,
            &u1000_store,
            &u1001_store,
        ] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o755)?;
        }
        set_mode(&keyd_dir, 0o2750)?;
        set_mode(&sticky_dir, 0o1777)?;
        set_mode(&u1000_store, 0o750)?;
        set_mode(&u1001_store, 0o750)?;

        let php_sock = php_dir.join("pool.sock");
        let _l1 = UnixListener::bind(&php_sock)?;
        set_mode(&php_sock, 0o660)?;

        let root_parent_sock = root_sock_dir.join("pool.sock");
        let _l2 = UnixListener::bind(&root_parent_sock)?;
        set_mode(&root_parent_sock, 0o660)?;

        let keyd_sock = keyd_dir.join("keyd.sock");
        symlink(&root_sock_dir, &sticky_sym_u1000)?;

        let u1000 = Some(Uid::from_raw(1000));
        let g1000 = Some(Gid::from_raw(1000));
        let u1001 = Some(Uid::from_raw(1001));
        let g1001 = Some(Gid::from_raw(1001));
        chown(&php_dir, u1000, g1000)?;
        chown(&php_sock, u1000, g1000)?;
        chown(&root_parent_sock, u1000, g1000)?;
        chown(&keyd_dir, u1000, g1000)?;
        chown(&sticky_u1000, u1000, g1000)?;
        chownat(
            CWD,
            &sticky_sym_u1000,
            u1000,
            g1000,
            AtFlags::SYMLINK_NOFOLLOW,
        )?;
        chown(&u1000_store, u1000, g1000)?;
        chown(&u1001_store, u1001, g1001)?;

        // 1. Running as root with `server.sandbox.user` UNSET: only uid 0 is trusted!
        let cfg1 = base.join("root_unset.kdl");
        fs::write(
            &cfg1,
            format!(
                "server {{\n\
                     listen \":443\"\n\
                     tls {{ key-isolation \"split-daemon\"; keyd-socket \"{}\"; cert \"{}\"; key \"{}\" }}\n\
                     sandbox {{ socket-tree \"{}\" \"{}\" }}\n\
                 }}\n\
                 site \"r0.example\" {{\n\
                     root \"{}\"\n\
                     ai-publish {{ storage \"{}\"; require-signature \"ed25519:{}\" }}\n\
                     route \"/bad/*\" {{ fastcgi-pass \"unix:{}\" }}\n\
                     route \"/ok/*\" {{ fastcgi-pass \"unix:{}\" }}\n\
                 }}\n\
                 site \"r1.example\" {{\n\
                     root \"{}\"\n\
                     ai-publish {{ storage \"{}\"; require-signature \"ed25519:{}\" }}\n\
                     route \"/sym/*\" {{ fastcgi-pass \"unix:{}/pool.sock\" }}\n\
                 }}\n",
                kdl_escape_path(&keyd_sock),
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&php_dir),
                kdl_escape_path(&root_sock_dir),
                kdl_escape_path(&docroot),
                kdl_escape_path(&u1000_store),
                kdl_escape_path(&pub_key),
                kdl_escape_path(&php_sock),
                kdl_escape_path(&root_parent_sock),
                kdl_escape_path(&docroot),
                kdl_escape_path(&sticky_u1000),
                kdl_escape_path(&pub_key),
                kdl_escape_path(&sticky_sym_u1000),
            ),
        )?;
        let (_c1, val1) = run_json(&["--fs", "--trusted-paths"], &cfg1)?;
        assert_eq!(
            note_at(&val1, 0),
            Some(
                "trusted-paths: running as root; service uid is unknown, so only uid 0 is trusted (server.sandbox.user is unset)"
            )
        );
        let ws1 = w034s(&val1);
        assert_eq!(ws1.len(), 6, "expected 6 W034s: {ws1:#?}");

        assert_eq!(
            ws1.first().and_then(|w| jstr(w, "path")),
            Some("server.sandbox.socket-tree")
        );
        assert_eq!(
            ws1.first().and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "server.sandbox socket-tree root '{}': first untrusted component '{}' \
                     (uid 1000, mode 0755): directory is controlled by uid 1000 (the socket producer)",
                    php_dir.display(),
                    php_dir.display()
                )
                .as_str()
            )
        );
        assert_eq!(
            ws1.get(1).and_then(|w| jstr(w, "path")),
            Some("site[0].route[0].fastcgi-pass")
        );
        assert_eq!(
            ws1.get(1).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "site 'r0.example' FastCGI Unix socket '{}': first untrusted component '{}' \
                     (uid 1000, mode 0755): owner not trusted",
                    php_sock.display(),
                    php_dir.display()
                )
                .as_str()
            )
        );
        assert_eq!(
            ws1.get(2).and_then(|w| jstr(w, "path")),
            Some("site[0].ai-publish.storage")
        );
        assert_eq!(
            ws1.get(2).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "site 'r0.example' ai-publish storage '{}': first untrusted component '{}' \
                     (uid 1000, mode 0750): owner not trusted",
                    u1000_store.display(),
                    u1000_store.display()
                )
                .as_str()
            )
        );
        assert_eq!(
            ws1.get(3).and_then(|w| jstr(w, "path")),
            Some("site[1].route[0].fastcgi-pass")
        );
        assert_eq!(
            ws1.get(3).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "site 'r1.example' FastCGI Unix socket '{}/pool.sock': first untrusted component '{}' \
                     (uid 1000, mode 0777): symbolic link whose own parent or target chain is untrusted \
                     (owner not trusted in sticky directory)",
                    sticky_sym_u1000.display(),
                    sticky_sym_u1000.display()
                )
                .as_str()
            )
        );
        assert_eq!(
            ws1.get(4).and_then(|w| jstr(w, "path")),
            Some("site[1].ai-publish.storage")
        );
        assert_eq!(
            ws1.get(4).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "site 'r1.example' ai-publish storage '{}': first untrusted component '{}' \
                     (uid 1000, mode 0755): owner not trusted",
                    sticky_u1000.display(),
                    sticky_u1000.display()
                )
                .as_str()
            )
        );
        assert_eq!(
            ws1.get(5).and_then(|w| jstr(w, "path")),
            Some("server.tls.keyd-socket")
        );
        assert_eq!(
            ws1.get(5).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "server.tls.keyd-socket '{}': first untrusted component '{}' \
                     (uid 1000, mode 2750): owner not trusted",
                    keyd_sock.display(),
                    keyd_dir.display()
                )
                .as_str()
            )
        );

        // 2. Running as root WITH `server.sandbox.user "1000"`: uid 0 and 1000 trusted, 1001 fails!
        let cfg2 = base.join("root_user1000.kdl");
        fs::write(
            &cfg2,
            format!(
                "server {{\n\
                     listen \":443\"\n\
                     tls {{ cert \"{}\"; key \"{}\" }}\n\
                     sandbox {{ user \"1000\"; socket-tree \"{}\" }}\n\
                 }}\n\
                 site \"ok.example\" {{ ai-publish {{ storage \"{}\"; require-signature \"ed25519:{}\" }} }}\n\
                 site \"bad.example\" {{ ai-publish {{ storage \"{}\"; require-signature \"ed25519:{}\" }} }}\n",
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&php_dir),
                kdl_escape_path(&u1000_store),
                kdl_escape_path(&pub_key),
                kdl_escape_path(&u1001_store),
                kdl_escape_path(&pub_key),
            ),
        )?;
        let (_c2, val2) = run_json(&["--fs", "--trusted-paths"], &cfg2)?;
        assert_eq!(
            note_at(&val2, 0),
            Some(
                "trusted-paths: running as root; trusting uid 0 and service uid 1000 (from server.sandbox.user '1000')"
            )
        );
        let ws2 = w034s(&val2);
        assert_eq!(ws2.len(), 1, "only uid 1001 should fail: {ws2:#?}");
        assert_eq!(
            ws2.first().and_then(|w| jstr(w, "path")),
            Some("site[1].ai-publish.storage")
        );
        assert_eq!(
            ws2.first().and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "site 'bad.example' ai-publish storage '{}': first untrusted component '{}' \
                     (uid 1001, mode 0750): owner not trusted",
                    u1001_store.display(),
                    u1001_store.display()
                )
                .as_str()
            )
        );

        let _ = fs::remove_dir_all(&base);
        Ok(())
    }
}

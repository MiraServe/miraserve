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
fn check_help_lists_trusted_paths_scope_assumptions_and_limits() -> TestResult {
    let out = Command::new(miraserve_bin())
        .args(["check", "--help"])
        .output()?;
    assert_eq!(out.status.code(), Some(0));
    let help = String::from_utf8(out.stdout)?;
    let start = help
        .find("--trusted-paths")
        .ok_or("missing --trusted-paths in help")?;
    let rest = help.get(start..).unwrap_or("");
    let end = rest.find("  --acme-dir").unwrap_or(rest.len());
    let flag_help = rest.get(..end).unwrap_or(rest);
    let norm = flag_help.split_whitespace().collect::<Vec<_>>().join(" ");
    for req in [
        "--trusted-paths",
        "--fs",
        "W034",
        "Linux-only",
        "its only warning code is `W034`; it also prints notes",
        "Walks the directories on the way to five kinds of configured paths and stops at the first component it reports or does not find:",
        "socket-tree",
        "fastcgi-pass",
        "keyd-socket",
        "path of the endpoint the server connects to",
        "ACME",
        "rotating log",
        "other configured paths, including `ai-publish` storage, are not looked at yet",
        "For each path it considers untrusted or cannot verify, it reports `W034` giving the component (when reported), its owner and mode (when known), and the reason.",
        "A warning means the check found something to fix on that path, or could not verify it; the reason in the warning says which, and the usual fixes are to correct the ownership, mode or type of the named component, or to move the path.",
        "No warning is not a guarantee.",
        "/tmp",
        "/home",
        "idmap",
        "stacking",
        "encryption",
        "writable view",
        "Run as the service account or as root with `server.sandbox.user` set; when no service account is configured, the check trusts the account that runs it (only root when run as root), so run it as the service account.",
        "0.1.6",
        "unresponsive",
        "atime",
    ] {
        assert!(norm.contains(req), "missing '{req}' in help:\n{norm}");
    }
    let lower = norm.to_ascii_lowercase();
    for forbidden in [
        "never",
        "always",
        "every component",
        "cannot pass",
        "verified local filesystem",
        "established",
        "does not exist",
        "opens no file for reading",
        "absent prefixes",
        "race-free",
        "secure layout",
        "changes nothing",
        "looks at each directory on the way",
        "else not verified",
        "otherwise results are reported as not verified",
        "six kinds",
        "resolve against the config dir first",
        "an existing socket at an exact endpoint is accepted",
        "in a sticky directory owned by root",
        "owned by another account, group/other-writable",
        "when the configuration names a service account different",
        "may be able to replace that path while the server starts",
        "reports `w034` only",
    ] {
        assert!(
            !lower.contains(forbidden),
            "forbidden '{forbidden}' in help:\n{norm}"
        );
    }
    assert_eq!(
        lower.matches("guarantee").count(),
        1,
        "only the not-a-guarantee sentence may mention guarantee:\n{norm}"
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
    let note_line = "note: --trusted-paths is Linux-only; no paths were verified\n";

    let text = Command::new(miraserve_bin())
        .args(["check", "--fs", "--strict", "--trusted-paths"])
        .arg(&cfg)
        .output()?;
    assert_eq!(text.status.code(), Some(0));
    let stdout = String::from_utf8(text.stdout)?;
    let stderr = String::from_utf8(text.stderr)?;
    assert!(stdout.contains(note_line), "stdout:\n{stdout}");
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

    // P2-7: `--writable-set` keeps stdout machine-readable and prints the note on stderr.
    let ws = Command::new(miraserve_bin())
        .args(["check", "--fs", "--trusted-paths", "--writable-set"])
        .arg(&cfg)
        .output()?;
    assert_eq!(ws.status.code(), Some(0));
    let ws_out = String::from_utf8(ws.stdout)?;
    let ws_err = String::from_utf8(ws.stderr)?;
    assert!(ws_out.starts_with("landlock "), "stdout:\n{ws_out}");
    assert!(!ws_out.contains("note:"), "stdout:\n{ws_out}");
    assert_eq!(ws_err, note_line);

    // P2-7: `--quiet` keeps stdout empty and prints the note on stderr.
    let q = Command::new(miraserve_bin())
        .args(["check", "--fs", "--trusted-paths", "--quiet"])
        .arg(&cfg)
        .output()?;
    assert_eq!(q.status.code(), Some(0));
    assert_eq!(String::from_utf8(q.stdout)?, "");
    assert_eq!(String::from_utf8(q.stderr)?, note_line);

    // P2-7: invalid KDL with `--trusted-paths` still carries the Linux-only note.
    let bad_cfg = base.join("bad.kdl");
    fs::write(&bad_cfg, "not valid kdl {{{")?;
    let bad_json = Command::new(miraserve_bin())
        .args(["check", "--fs", "--trusted-paths", "--format", "json"])
        .arg(&bad_cfg)
        .output()?;
    assert_eq!(bad_json.status.code(), Some(1));
    let bad_val: serde_json::Value = serde_json::from_slice(&bad_json.stdout)?;
    assert_eq!(
        bad_val.get("notes"),
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
        acme-webroot, basic-auth, bot-auth, ai-publish storage and keys, error-pages, \
        upstream-tls, mcp-gateway, wasm-plugin, or non-rotating log paths";

    const TREE_WR_LITERAL: &str = "group or other writable (other accounts with search permission may be able to create or replace sockets)";

    fn fs_magic_of(path: &str) -> Result<u32, std::io::Error> {
        let fd = rustix::fs::openat(
            rustix::fs::CWD,
            path,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(std::io::Error::from)?;
        let sf = rustix::fs::fstatfs(&fd).map_err(std::io::Error::from)?;
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        Ok(sf.f_type as u32)
    }

    fn is_accepted_local_fs(m: u32) -> bool {
        matches!(
            m,
            0xEF53
                | 0x5846_5342
                | 0x9123_683E
                | 0x0102_1994
                | 0x2FC1_2FC1
                | 0xF2F5_2010
                | 0xCA45_1A4E
                | 0x8584_58F6
                | 0x7371_7368
                | 0xE0F5_E1E2
                | 0x3153_464A
                | 0x5265_4973
                | 0x0001_1954
        )
    }

    /// Returns `true` when both `/` and `/tmp` sit on an accepted non-stacking local POSIX
    /// filesystem (e.g. ext4/xfs/btrfs/tmpfs, not overlayfs). When running inside an overlayfs
    /// container, CLI tests that must traverse past `/` report the environment and return early.
    fn require_local_root_fs(test_name: &str) -> Result<bool, std::io::Error> {
        for p in ["/", "/tmp"] {
            let m = fs_magic_of(p)?;
            if !is_accepted_local_fs(m) {
                eprintln!(
                    "skipping {test_name}: {p} is on filesystem 0x{m:x} (not an accepted non-stacking local POSIX filesystem)"
                );
                return Ok(false);
            }
        }
        Ok(true)
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
    #[allow(clippy::too_many_lines)]
    fn linux_trusted_chain_all_five_classes_and_narrowed_exclusions() -> TestResult {
        if !require_local_root_fs("linux_trusted_chain_all_five_classes_and_narrowed_exclusions")? {
            return Ok(());
        }
        let base = make_temp_base("clean")?;
        let (cert, key) = gen_dev_cert(&base)?;
        let euid = rustix::process::geteuid().as_raw();
        let sock_dir = base.join("php");
        let acme_dir = base.join("acme");
        let log_dir = base.join("logs");
        let uncov_bad = base.join("uncovered_bad");
        let docroot = uncov_bad.join("www");
        let read_tree = uncov_bad.join("rtree");
        for d in [
            &sock_dir, &acme_dir, &log_dir, &uncov_bad, &docroot, &read_tree,
        ] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o750)?;
        }
        set_mode(&acme_dir, 0o700)?;
        // Intentionally make a non-covered ancestor (`site.root`, `read-tree`) world-writable:
        // Stage 1a MUST NOT inspect them!
        set_mode(&uncov_bad, 0o777)?;

        // When running as root, set `sandbox.user "1000"` and chown `acme_dir` to uid 1000
        // because ACME requires service-uid ownership (P1-5).
        let (sb_user_line, expected_obs) = if euid == 0 {
            rustix::fs::chown(
                &acme_dir,
                Some(rustix::fs::Uid::from_raw(1000)),
                Some(rustix::fs::Gid::from_raw(1000)),
            )?;
            (
                "user \"1000\"; ",
                "trusted-paths: running as root; trusting uid 0 and service uid 1000 (from server.sandbox.user '1000')".to_owned(),
            )
        } else {
            ("", expected_default_observer_note())
        };

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
                     sandbox {{ {sb_user_line}read-tree \"{}\"; socket-tree \"{}\" }}\n\
                 }}\n\
                 site \"tp.example\" {{\n\
                     root \"{}\"\n\
                     route \"*.php\" {{ fastcgi-pass \"unix:{}\" }}\n\
                 }}\n",
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&read_tree),
                kdl_escape_path(&sock_dir),
                kdl_escape_path(&docroot),
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
        assert_eq!(note_at(&val, 0), Some(expected_obs.as_str()));
        assert_eq!(note_at(&val, 1), Some(NARROWED_NOTE_LITERAL));

        // Clean keyd-socket (split-daemon, absent socket in trusted parent) emits 0 W034
        // AND emits the P2-1 verified-prefix note naming `sock_dir` and `keyd.sock`.
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
        assert_eq!(
            note_at(&kval, 2),
            Some(
                format!(
                    "trusted-paths: server.tls.keyd-socket '{}': inspected existing prefix '{}' \
                     (stopped at 'keyd.sock', not found by this lookup)",
                    keyd_sock.display(),
                    sock_dir.display()
                )
                .as_str()
            )
        );

        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn linux_group_and_other_writable_first_component_strict_allow_and_writable_set() -> TestResult
    {
        if !require_local_root_fs(
            "linux_group_and_other_writable_first_component_strict_allow_and_writable_set",
        )? {
            return Ok(());
        }
        let base = make_temp_base("writable")?;
        let (cert, key) = gen_dev_cert(&base)?;
        let euid = rustix::process::geteuid().as_raw();
        let docroot = base.join("www");
        let gw = base.join("gw");
        let ow = gw.join("ow");
        let sock_dir = ow.join("socks");
        fs::create_dir_all(&docroot)?;
        fs::create_dir_all(&sock_dir)?;
        set_mode(&docroot, 0o750)?;
        set_mode(&gw, 0o775)?;
        set_mode(&ow, 0o777)?;
        set_mode(&sock_dir, 0o750)?;
        let sock = sock_dir.join("pool.sock");

        let cfg = base.join("gw.kdl");
        fs::write(
            &cfg,
            format!(
                "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }} }}\n\
                 site \"tp.example\" {{ root \"{}\"; route \"*.php\" {{ fastcgi-pass \"unix:{}\" }} }}\n",
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&docroot),
                kdl_escape_path(&sock),
            ),
        )?;

        // 1. `--strict` fails with exit 1, reporting FIRST untrusted component (`gw`, NOT `ow`!).
        let (code, val) = run_json(&["--fs", "--strict", "--trusted-paths"], &cfg)?;
        assert_eq!(code, Some(1), "strict must fail on W034: {val}");
        assert_eq!(val.get("valid"), Some(&serde_json::Value::Bool(false)));
        let ws = w034s(&val);
        assert_eq!(ws.len(), 1, "expected 1 W034: {val}");
        let w = ws.first().copied().ok_or("missing W034")?;
        assert_eq!(jstr(w, "path"), Some("site[0].route[0].fastcgi-pass"));
        assert_eq!(
            jstr(w, "message"),
            Some(
                format!(
                    "site 'tp.example' FastCGI Unix socket '{}': first untrusted component '{}' \
                     (uid {euid}, mode 0775): group or other writable",
                    sock.display(),
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
            "warning[W034]: site 'tp.example' FastCGI Unix socket '{}': first untrusted component '{}' \
             (uid {euid}, mode 0775): group or other writable\n",
            sock.display(),
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

        // 4. `--writable-set` keeps stdout strictly machine-readable (no `note:` lines on stdout)
        //    and emits W034 + trusted-paths notes on stderr (P2-7).
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
        assert!(
            ws_stderr.contains(&format!("note: {}\n", expected_default_observer_note())),
            "stderr:\n{ws_stderr}"
        );

        // 5. `--quiet` keeps stdout empty and still emits W034 + trusted-paths notes on stderr (P2-7).
        let q_out = Command::new(miraserve_bin())
            .args(["check", "--fs", "--trusted-paths", "--quiet"])
            .arg(&cfg)
            .output()?;
        assert_eq!(q_out.status.code(), Some(0));
        assert_eq!(String::from_utf8(q_out.stdout)?, "");
        let q_stderr = String::from_utf8(q_out.stderr)?;
        assert!(
            q_stderr.contains(&format!("note: {}\n", expected_default_observer_note())),
            "stderr:\n{q_stderr}"
        );

        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn linux_sticky_directory_existing_trusted_missing_child_and_sticky_leaf() -> TestResult {
        if !require_local_root_fs(
            "linux_sticky_directory_existing_trusted_missing_child_and_sticky_leaf",
        )? {
            return Ok(());
        }
        let base = make_temp_base("sticky")?;
        let (cert, key) = gen_dev_cert(&base)?;
        let euid = rustix::process::geteuid().as_raw();
        let docroot = base.join("www");
        let sticky = base.join("sticky");
        let existing_child = sticky.join("ok_logs");
        fs::create_dir_all(&docroot)?;
        fs::create_dir_all(&existing_child)?;
        set_mode(&docroot, 0o750)?;
        set_mode(&sticky, 0o1777)?;
        set_mode(&existing_child, 0o750)?;

        // 1. Existing trusted child inside sticky dir -> ACCEPTED (0 W034).
        let ok_log = existing_child.join("server.log");
        let ok_cfg = base.join("sticky_ok.kdl");
        fs::write(
            &ok_cfg,
            format!(
                "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }} }}\n\
                 site \"tp.example\" {{ root \"{}\" }}\n",
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&docroot),
            ),
        )?;
        let (code, val) = run_json(
            &[
                "--fs",
                "--strict",
                "--trusted-paths",
                "--log-file",
                &ok_log.to_string_lossy(),
                "--log-max-bytes",
                "1024",
            ],
            &ok_cfg,
        )?;
        assert_eq!(
            code,
            Some(0),
            "existing child in sticky dir must pass: {val}"
        );
        assert!(w034s(&val).is_empty(), "val: {val}");

        // 2. Absent direct child, deeper absent child, AND sticky dir itself as leaf -> REPORTED!
        let missing_direct = sticky.join("absent_acme");
        let missing_deep_dir = sticky.join("absent_mid/leaf_logs");
        let missing_deep_log = missing_deep_dir.join("server.log");
        let miss_cfg = base.join("sticky_miss.kdl");
        fs::write(
            &miss_cfg,
            format!(
                "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }}; sandbox {{ socket-tree \"{}\" }} }}\n\
                 site \"tp.example\" {{ root \"{}\" }}\n",
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&sticky),
                kdl_escape_path(&docroot),
            ),
        )?;
        let (_code, mval) = run_json(
            &[
                "--fs",
                "--trusted-paths",
                "--acme-dir",
                &missing_direct.to_string_lossy(),
                "--log-file",
                &missing_deep_log.to_string_lossy(),
                "--log-max-bytes",
                "1024",
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
                     (uid {euid}, mode 1777): {TREE_WR_LITERAL}",
                    sticky.display(),
                    sticky.display()
                )
                .as_str()
            )
        );
        assert_eq!(
            ws.get(1).and_then(|w| jstr(w, "path")),
            Some("server.tls.acme")
        );
        assert_eq!(
            ws.get(1).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "ACME directory '{}': first untrusted component '{}' \
                     (uid {euid}, mode 1777): missing component 'absent_acme' under a parent where \
                     another account could create it, and if it is created later the permissions it \
                     would inherit are not verified",
                    missing_direct.display(),
                    sticky.display()
                )
                .as_str()
            )
        );
        assert_eq!(
            ws.get(2).and_then(|w| jstr(w, "path")),
            Some("server.log-file")
        );
        assert_eq!(
            ws.get(2).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "rotating --log-file parent directory '{}': first untrusted component '{}' \
                     (uid {euid}, mode 1777): missing component 'absent_mid' under a parent where \
                     another account could create it, and if it is created later the permissions it \
                     would inherit are not verified",
                    missing_deep_dir.display(),
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

        if !require_local_root_fs("linux_symlinks_relative_acme_loop_and_non_lexical_dotdot")? {
            return Ok(());
        }

        let base = make_temp_base("symlinks")?;
        let (cert, key) = gen_dev_cert(&base)?;
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
                "server {{\n\
                     listen \":443\"\n\
                     tls {{ cert \"{}\"; key \"{}\" }}\n\
                     sandbox {{ socket-tree \"{}\" \"{}\" }}\n\
                 }}\n\
                 site \"a.example\" {{ root \"{}\" }}\n",
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&abs_ok_link),
                kdl_escape_path(&rel_ok_link),
                kdl_escape_path(&docroot),
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
        assert_eq!(
            ws.get(2).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "site 'l.example' FastCGI Unix socket '{}/p.sock': first untrusted component '{}' \
                     (uid {euid}, mode 0777): could not be inspected \
                     (Too many levels of symbolic links (os error 40))",
                    loop_a.display(),
                    loop_a.display()
                )
                .as_str()
            )
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

        // P2-5: writable suffix AFTER a trusted symlink must NOT blame the symlink.
        let bad_later = good_target_a.join("bad_later");
        fs::create_dir_all(&bad_later)?;
        set_mode(&bad_later, 0o777)?;
        let suffix_cfg = base.join("sym_suffix.kdl");
        fs::write(
            &suffix_cfg,
            format!(
                "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }} }}\n\
                 site \"sf.example\" {{ root \"{}\"; route \"*.php\" {{ fastcgi-pass \"unix:{}/bad_later/p.sock\" }} }}\n",
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&docroot),
                kdl_escape_path(&abs_ok_link),
            ),
        )?;
        let (_sc, sval) = run_json(&["--fs", "--trusted-paths"], &suffix_cfg)?;
        let sws = w034s(&sval);
        assert_eq!(sws.len(), 1, "writable suffix must emit 1 W034: {sval}");
        assert_eq!(
            sws.first().and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "site 'sf.example' FastCGI Unix socket '{}/bad_later/p.sock': first untrusted \
                     component '{}' (uid {euid}, mode 0777): group or other writable",
                    abs_ok_link.display(),
                    bad_later.display()
                )
                .as_str()
            )
        );

        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    fn linux_p2_verified_prefix_newline_sanitization_and_invalid_kdl_note() -> TestResult {
        if !require_local_root_fs(
            "linux_p2_verified_prefix_newline_sanitization_and_invalid_kdl_note",
        )? {
            return Ok(());
        }
        let base = make_temp_base("p2-notes")?;
        let (cert, key) = gen_dev_cert(&base)?;
        let euid = rustix::process::geteuid().as_raw();
        let docroot = base.join("www");
        let trusted_parent = base.join("trusted_state");
        let nl_dir = base.join("nl\ndir");
        for d in [&docroot, &trusted_parent, &nl_dir] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o750)?;
        }
        set_mode(&nl_dir, 0o775)?;

        let cfg = base.join("p2.kdl");
        fs::write(
            &cfg,
            format!(
                "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }} }}\n\
                 site \"p2.example\" {{\n\
                     root \"{}\"\n\
                     route \"*.php\" {{ fastcgi-pass \"unix:{}/pool.sock\" }}\n\
                 }}\n",
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&docroot),
                kdl_escape_path(&trusted_parent),
            ),
        )?;

        // 1. P2-1: absent exact socket under existing trusted parent emits verified-prefix note.
        let (ok_code, ok_val) = run_json(&["--fs", "--strict", "--trusted-paths"], &cfg)?;
        assert_eq!(ok_code, Some(0), "absent under trusted must pass: {ok_val}");
        assert!(w034s(&ok_val).is_empty(), "ok_val: {ok_val}");
        assert_eq!(
            note_at(&ok_val, 2),
            Some(
                format!(
                    "trusted-paths: site 'p2.example' FastCGI Unix socket '{}/pool.sock': \
                     inspected existing prefix '{}' (stopped at 'pool.sock', not found by this lookup)",
                    trusted_parent.display(),
                    trusted_parent.display()
                )
                .as_str()
            )
        );

        // 2. P2-6: rotating log parent containing `\n` stays on ONE single sanitized line in ordinary text mode!
        let nl_log = nl_dir.join("server.log");
        let txt = Command::new(miraserve_bin())
            .args(["check", "--fs", "--trusted-paths", "--log-file"])
            .arg(&nl_log)
            .args(["--log-max-bytes", "1024"])
            .arg(&cfg)
            .output()?;
        let stderr = String::from_utf8(txt.stderr)?;
        let w_lines: Vec<&str> = stderr
            .lines()
            .filter(|l| l.starts_with("warning[W034]:"))
            .collect();
        assert_eq!(
            w_lines.len(),
            1,
            "expected 1 W034 line on stderr:\n{stderr}"
        );
        let expected_esc = format!(
            "warning[W034]: rotating --log-file parent directory '{}/nl\\ndir': first untrusted \
             component '{}/nl\\ndir' (uid {euid}, mode 0775): group or other writable",
            base.display(),
            base.display()
        );
        assert_eq!(w_lines.first().copied(), Some(expected_esc.as_str()));

        // 3. P2-7 + Additional 2: invalid KDL and missing config I/O error with
        // `--trusted-paths --format json` both emit the truthful load/validity diagnostic note.
        let bad_cfg = base.join("bad.kdl");
        fs::write(&bad_cfg, "broken {{{")?;
        let (bcode, bval) = run_json(&["--fs", "--trusted-paths"], &bad_cfg)?;
        assert_eq!(bcode, Some(1));
        assert_eq!(
            bval.get("notes"),
            Some(&serde_json::json!([
                "trusted-paths: configuration could not be loaded or is invalid; no paths were verified"
            ]))
        );
        let missing_cfg = base.join("does_not_exist.kdl");
        let (mcode, mval) = run_json(&["--fs", "--trusted-paths"], &missing_cfg)?;
        assert_eq!(mcode, Some(1));
        assert_eq!(
            mval.get("notes"),
            Some(&serde_json::json!([
                "trusted-paths: configuration could not be loaded or is invalid; no paths were verified"
            ]))
        );

        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn linux_absent_uninspectable_fs_guard_two_sites_all_json_paths_and_w029_frozen() -> TestResult
    {
        use std::os::unix::fs::symlink;

        if !require_local_root_fs(
            "linux_absent_uninspectable_fs_guard_two_sites_all_json_paths_and_w029_frozen",
        )? {
            return Ok(());
        }

        let base = make_temp_base("matrix")?;
        let (cert, key) = gen_dev_cert(&base)?;
        let euid = rustix::process::geteuid().as_raw();

        let good = base.join("good");
        let docroot = good.join("www");
        let bad = base.join("bad");
        let not_a_dir = base.join("regular_file");
        let no_search = base.join("no_search");
        let webroot = bad.join("webroot");
        for d in [&good, &docroot, &bad, &no_search, &webroot] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o750)?;
        }
        fs::write(&not_a_dir, b"x")?;
        set_mode(&not_a_dir, 0o644)?;
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
                     route \"/a/*\" {{ fastcgi-pass \"unix:{}\" }}\n\
                     route \"/ok/*\" {{ fastcgi-pass \"unix:{}\" }}\n\
                     route \"/proc/*\" {{ fastcgi-pass \"unix:{}/p.sock\" }}\n\
                 }}\n\
                 site \"s1.example\" {{\n\
                     root \"{}\"\n\
                     route \"/b/*\" {{ fastcgi-pass \"unix:{}\" }}\n\
                     route \"/nd/*\" {{ fastcgi-pass \"unix:{}/child.sock\" }}\n\
                 }}\n",
                kdl_escape_path(&webroot),
                kdl_escape_path(&keyd_sock),
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&bad),
                kdl_escape_path(&docroot),
                kdl_escape_path(&shared_sock),
                kdl_escape_path(&absent_good),
                kdl_escape_path(&proc_link),
                kdl_escape_path(&docroot),
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

        // Verify all 9 expected W034 paths in exact deterministic order (absent_good must NOT warn!)
        let ws = w034s(&val_with);
        let paths: Vec<Option<&str>> = ws.iter().map(|w| jstr(w, "path")).collect();
        assert_eq!(
            paths,
            vec![
                Some("server.sandbox.socket-tree"),
                Some("site[0].route[0].fastcgi-pass"),
                Some("site[0].route[2].fastcgi-pass"),
                Some("site[1].route[0].fastcgi-pass"),
                Some("site[1].route[1].fastcgi-pass"),
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
            ws.get(4).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "site 's1.example' FastCGI Unix socket '{}/child.sock': first untrusted component \
                     '{}' (uid {euid}, mode 0644): could not be inspected \
                     (Not a directory (os error 20))",
                    not_a_dir.display(),
                    not_a_dir.display()
                )
                .as_str()
            )
        );
        assert_eq!(
            note_at(&val_with, 2),
            Some(
                format!(
                    "trusted-paths: site 's0.example' FastCGI Unix socket '{}': inspected existing \
                     prefix '{}' (stopped at 'absent.sock', not found by this lookup)",
                    absent_good.display(),
                    good.display()
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

        if !require_local_root_fs(
            "linux_cli_trusted_paths_succeeds_under_openat2_enosys_and_kill_process",
        )? {
            return Ok(());
        }
        let base = make_temp_base("openat2-cli")?;
        let (cert, key) = gen_dev_cert(&base)?;
        let sock_dir = base.join("socks");
        let docroot = base.join("www");
        for d in [&sock_dir, &docroot] {
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
                     route \"*.php\" {{ fastcgi-pass \"unix:{}/pool.sock\" }}\n\
                 }}\n",
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&sock_dir),
                kdl_escape_path(&docroot),
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
        if !require_local_root_fs(
            "linux_root_second_uid_ownership_socket_producer_and_sandbox_user",
        )? {
            return Ok(());
        }

        let base = make_temp_base("root-multiuid")?;
        let (cert, key) = gen_dev_cert(&base)?;

        let docroot = base.join("www");
        let php_dir = base.join("php_producer");
        let root_sock_dir = base.join("root_socks");
        let keyd_dir = base.join("keyd_dir");
        let sticky_dir = base.join("sticky_root");
        let sticky_u1000 = sticky_dir.join("u1000_logs");
        let sticky_sym_u1000 = sticky_dir.join("u1000_link");
        let u1000_dir = base.join("u1000_logs");
        let u1001_dir = base.join("u1001_logs");
        for d in [
            &docroot,
            &php_dir,
            &root_sock_dir,
            &keyd_dir,
            &sticky_dir,
            &sticky_u1000,
            &u1000_dir,
            &u1001_dir,
        ] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o755)?;
        }
        set_mode(&keyd_dir, 0o2750)?;
        set_mode(&sticky_dir, 0o1777)?;
        set_mode(&u1000_dir, 0o750)?;
        set_mode(&u1001_dir, 0o750)?;

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
        chown(&u1000_dir, u1000, g1000)?;
        chown(&u1001_dir, u1001, g1001)?;

        // 1. Running as root with `server.sandbox.user` UNSET: only uid 0 is trusted!
        let u1000_log = u1000_dir.join("app.log");
        let sticky_u1000_acc = sticky_u1000.join("acc.log");
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
                     route \"/bad/*\" {{ fastcgi-pass \"unix:{}\" }}\n\
                     route \"/ok/*\" {{ fastcgi-pass \"unix:{}\" }}\n\
                 }}\n\
                 site \"r1.example\" {{\n\
                     root \"{}\"\n\
                     route \"/sym/*\" {{ fastcgi-pass \"unix:{}/pool.sock\" }}\n\
                 }}\n",
                kdl_escape_path(&keyd_sock),
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&php_dir),
                kdl_escape_path(&root_sock_dir),
                kdl_escape_path(&docroot),
                kdl_escape_path(&php_sock),
                kdl_escape_path(&root_parent_sock),
                kdl_escape_path(&docroot),
                kdl_escape_path(&sticky_sym_u1000),
            ),
        )?;
        let (_c1, val1) = run_json(
            &[
                "--fs",
                "--trusted-paths",
                "--log-file",
                &u1000_log.to_string_lossy(),
                "--access-log",
                &sticky_u1000_acc.to_string_lossy(),
                "--log-max-bytes",
                "1024",
            ],
            &cfg1,
        )?;
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
            ws1.first().and_then(|w| jstr(w, "help")),
            Some(
                "set the socket-tree directory owner to root or the service account, or \
                 pass --allow-warning W034 if you trust that socket producer (--allow-warning \
                 W034 applies to all W034 warnings under --strict)"
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
            Some("site[1].route[0].fastcgi-pass")
        );
        assert_eq!(
            ws1.get(2).and_then(|w| jstr(w, "message")),
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
            ws1.get(3).and_then(|w| jstr(w, "path")),
            Some("server.tls.keyd-socket")
        );
        assert_eq!(
            ws1.get(3).and_then(|w| jstr(w, "message")),
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
        assert_eq!(
            ws1.get(4).and_then(|w| jstr(w, "path")),
            Some("server.log-file")
        );
        assert_eq!(
            ws1.get(4).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "rotating --log-file parent directory '{}': first untrusted component '{}' \
                     (uid 1000, mode 0750): owner not trusted",
                    u1000_dir.display(),
                    u1000_dir.display()
                )
                .as_str()
            )
        );
        assert_eq!(
            ws1.get(5).and_then(|w| jstr(w, "path")),
            Some("server.access-log")
        );
        assert_eq!(
            ws1.get(5).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "rotating --access-log parent directory '{}': first untrusted component '{}' \
                     (uid 1000, mode 0755): owner not trusted",
                    sticky_u1000.display(),
                    sticky_u1000.display()
                )
                .as_str()
            )
        );

        // 2. Running as root WITH `server.sandbox.user " 1000 "` (P2-4 trimmed): uid 0 and 1000 trusted, 1001 fails!
        //    Also test P2-2: producer-owned 0775 socket-tree AND sticky-dir producer-owned socket-tree
        //    must not mask the producer note!
        let php_gw = base.join("php_gw_u1001");
        let sticky_php = sticky_dir.join("php_sticky_u1001");
        fs::create_dir_all(&php_gw)?;
        fs::create_dir_all(&sticky_php)?;
        set_mode(&php_gw, 0o775)?;
        set_mode(&sticky_php, 0o755)?;
        chown(&php_gw, u1001, g1001)?;
        chown(&sticky_php, u1001, g1001)?;

        let u1001_acc = u1001_dir.join("acc.log");
        let cfg2 = base.join("root_user1000.kdl");
        fs::write(
            &cfg2,
            format!(
                "server {{\n\
                     listen \":443\"\n\
                     tls {{ cert \"{}\"; key \"{}\" }}\n\
                     sandbox {{ user \" 1000 \"; socket-tree \"{}\" \"{}\" \"{}\" }}\n\
                 }}\n\
                 site \"ok.example\" {{ root \"{}\" }}\n",
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&php_dir),
                kdl_escape_path(&php_gw),
                kdl_escape_path(&sticky_php),
                kdl_escape_path(&docroot),
            ),
        )?;
        let (_c2, val2) = run_json(
            &[
                "--fs",
                "--trusted-paths",
                "--log-file",
                &u1000_log.to_string_lossy(),
                "--access-log",
                &u1001_acc.to_string_lossy(),
                "--log-max-bytes",
                "1024",
            ],
            &cfg2,
        )?;
        assert_eq!(
            note_at(&val2, 0),
            Some(
                "trusted-paths: running as root; trusting uid 0 and service uid 1000 (from server.sandbox.user '1000')"
            )
        );
        let ws2 = w034s(&val2);
        assert_eq!(
            ws2.len(),
            3,
            "expected 3 W034s (php_gw, sticky_php, u1001_dir): {ws2:#?}"
        );
        assert_eq!(
            ws2.first().and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "server.sandbox socket-tree root '{}': first untrusted component '{}' \
                     (uid 1001, mode 0775): {TREE_WR_LITERAL}; directory is controlled by uid 1001 \
                     (the socket producer)",
                    php_gw.display(),
                    php_gw.display()
                )
                .as_str()
            )
        );
        assert_eq!(
            ws2.get(1).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "server.sandbox socket-tree root '{}': first untrusted component '{}' \
                     (uid 1001, mode 0755): owner not trusted in sticky directory; directory is \
                     controlled by uid 1001 (the socket producer)",
                    sticky_php.display(),
                    sticky_php.display()
                )
                .as_str()
            )
        );
        assert_eq!(
            ws2.get(2).and_then(|w| jstr(w, "path")),
            Some("server.access-log")
        );
        assert_eq!(
            ws2.get(2).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "rotating --access-log parent directory '{}': first untrusted component '{}' \
                     (uid 1001, mode 0750): owner not trusted",
                    u1001_dir.display(),
                    u1001_dir.display()
                )
                .as_str()
            )
        );

        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    fn linux_p1_1_keyd_leading_space_walks_trimmed_endpoint() -> TestResult {
        // Since 0.1.8, leading or trailing whitespace in KDL `server.tls.keyd-socket` is
        // rejected at configuration load with E202 before `--trusted-paths` runs (runs on
        // all Linux filesystems, including overlayfs).
        let base = make_temp_base("p1-keyd-space")?;
        let (cert, key) = gen_dev_cert(&base)?;
        let docroot = base.join("www");
        let good_cwd = base.join("good_cwd");
        let bad_dir = base.join("bad_keyd_dir");
        for d in [&docroot, &good_cwd, &bad_dir] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o750)?;
        }
        set_mode(&bad_dir, 0o775)?;
        let keyd_sock = bad_dir.join("keyd.sock");

        let cfg = base.join("keyd_space.kdl");
        fs::write(
            &cfg,
            format!(
                "server {{\n\
                     listen \":443\"\n\
                     tls {{ key-isolation \"split-daemon\"; keyd-socket \" {}\"; cert \"{}\"; key \"{}\" }}\n\
                 }}\n\
                 site \"ks.example\" {{ root \"{}\" }}\n",
                kdl_escape_path(&keyd_sock),
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&docroot),
            ),
        )?;

        let (code, val) = run_json_in(&["--fs", "--trusted-paths"], &cfg, Some(&good_cwd))?;
        // The configuration now fails to load, so `check` exits non-zero.
        assert_eq!(
            code,
            Some(1),
            "leading-space keyd-socket must exit 1: {val}"
        );
        // The configuration now fails to load, so the report marks it invalid.
        assert_eq!(val.get("valid"), Some(&serde_json::Value::Bool(false)));
        // The configuration now fails to load, so `--trusted-paths` does not run.
        assert_eq!(w034s(&val).len(), 0, "expected zero W034 on E202: {val}");
        // The configuration now fails to load with a single E202 load error.
        assert_eq!(
            val.get("errors")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(1),
            "expected single E202 error: {val}"
        );
        // The configuration now fails to load with code E202.
        assert_eq!(
            val.pointer("/errors/0/code")
                .and_then(serde_json::Value::as_str),
            Some("E202")
        );
        // The configuration now fails to load on `server.tls.keyd-socket`.
        assert_eq!(
            val.pointer("/errors/0/path")
                .and_then(serde_json::Value::as_str),
            Some("server.tls.keyd-socket")
        );
        // The configuration now fails to load naming `keyd-socket` and its whitespace.
        assert_eq!(
            val.pointer("/errors/0/message")
                .and_then(serde_json::Value::as_str),
            Some("server.tls 'keyd-socket' path starts with whitespace (U+0020)")
        );

        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    fn linux_p1_3_overlayfs_root_reported_not_verified() -> TestResult {
        let fd = rustix::fs::openat(
            rustix::fs::CWD,
            "/",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        let sf = rustix::fs::fstatfs(&fd)?;
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let magic = sf.f_type as u32;
        if magic != 0x794C_7630 {
            eprintln!(
                "skipping linux_p1_3_overlayfs_root_reported_not_verified: / is 0x{magic:x}, not overlayfs"
            );
            return Ok(());
        }
        let base = make_temp_base("p1-overlay")?;
        let (cert, key) = gen_dev_cert(&base)?;
        let docroot = base.join("www");
        let socks = base.join("socks");
        for d in [&docroot, &socks] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o750)?;
        }
        let sock = socks.join("pool.sock");
        let cfg = base.join("ovl.kdl");
        fs::write(
            &cfg,
            format!(
                "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }} }}\n\
                 site \"ovl.example\" {{ root \"{}\"; route \"*.php\" {{ fastcgi-pass \"unix:{}\" }} }}\n",
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&docroot),
                kdl_escape_path(&sock),
            ),
        )?;
        let (_code, val) = run_json(&["--fs", "--trusted-paths"], &cfg)?;
        let ws = w034s(&val);
        assert_eq!(ws.len(), 1, "overlayfs root must emit W034: {val}");
        assert_eq!(
            ws.first().and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "site 'ovl.example' FastCGI Unix socket '{}': first untrusted component '/' \
                     (uid 0, mode 0755): could not be verified on this filesystem (filesystem 0x794c7630)",
                    sock.display()
                )
                .as_str()
            )
        );
        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    fn linux_p1_4_relative_paths_reported_not_verified() -> TestResult {
        let base = make_temp_base("p1-rel")?;
        let docroot = base.join("www");
        let good_cwd = base.join("good_cwd");
        let good_acme = good_cwd.join(".miraserve-acme");
        let sock_dir = good_cwd.join("sockets");
        for d in [&docroot, &good_cwd, &good_acme, &sock_dir] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o750)?;
        }
        set_mode(&good_acme, 0o700)?;

        let cfg = base.join("rel.kdl");
        fs::write(
            &cfg,
            format!(
                "server {{\n\
                     listen \":443\"\n\
                     tls {{ acme {{ email \"ops@example.com\"; challenge \"tls-alpn-01\" }} }}\n\
                 }}\n\
                 site \"rel.example\" {{\n\
                     root \"{}\"\n\
                     route \"*.php\" {{ fastcgi-pass \"unix:sockets/pool.sock\" }}\n\
                 }}\n",
                kdl_escape_path(&docroot),
            ),
        )?;

        let (_code, val) = run_json_in(
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
        let ws = w034s(&val);
        assert_eq!(ws.len(), 3, "all 3 relative paths must report W034: {val}");
        assert_eq!(
            ws.first().and_then(|w| jstr(w, "message")),
            Some(
                "site 'rel.example' FastCGI Unix socket 'sockets/pool.sock': first untrusted \
                 component 'sockets/pool.sock' (uid unknown, mode unknown): not verified: \
                 relative path depends on the working directory of the server"
            )
        );
        assert_eq!(
            ws.get(1).and_then(|w| jstr(w, "message")),
            Some(
                "ACME directory '.miraserve-acme': first untrusted component '.miraserve-acme' \
                 (uid unknown, mode unknown): not verified: relative path depends on the \
                 working directory of the server"
            )
        );
        assert_eq!(
            ws.get(2).and_then(|w| jstr(w, "message")),
            Some(
                "rotating --log-file parent directory 'app.log': first untrusted component \
                 'app.log' (uid unknown, mode unknown): not verified: relative path depends on \
                 the working directory of the server"
            )
        );

        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn linux_p1_5_wrong_leaf_types_reported_and_0660_socket_accepted() -> TestResult {
        if !require_local_root_fs("linux_p1_5_wrong_leaf_types_reported_and_0660_socket_accepted")?
        {
            return Ok(());
        }
        let base = make_temp_base("p1-leaves")?;
        let (cert, key) = gen_dev_cert(&base)?;
        let euid = rustix::process::geteuid().as_raw();
        let docroot = base.join("www");
        let good_dir = base.join("good_dir");
        for d in [&docroot, &good_dir] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o750)?;
        }
        let reg_tree = base.join("reg_tree");
        let reg_log_parent = base.join("reg_log_parent");
        let reg_acme = base.join("reg_acme");
        let reg_fcgi = base.join("reg_fcgi");
        let reg_keyd = base.join("reg_keyd");
        for f in [&reg_tree, &reg_log_parent, &reg_acme, &reg_fcgi, &reg_keyd] {
            fs::write(f, b"not-a-dir-or-sock")?;
            set_mode(f, 0o644)?;
        }
        let real_sock = good_dir.join("ok.sock");
        let _listener = UnixListener::bind(&real_sock)?;
        set_mode(&real_sock, 0o660)?;

        let cfg = base.join("leaves.kdl");
        fs::write(
            &cfg,
            format!(
                "server {{\n\
                     listen \":443\"\n\
                     tls {{ key-isolation \"split-daemon\"; keyd-socket \"{}\"; cert \"{}\"; key \"{}\" }}\n\
                     sandbox {{ socket-tree \"{}\" }}\n\
                 }}\n\
                 site \"lf.example\" {{\n\
                     root \"{}\"\n\
                     route \"/ok/*\" {{ fastcgi-pass \"unix:{}\" }}\n\
                     route \"/reg/*\" {{ fastcgi-pass \"unix:{}\" }}\n\
                     route \"/dir/*\" {{ fastcgi-pass \"unix:{}\" }}\n\
                 }}\n",
                kdl_escape_path(&reg_keyd),
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&reg_tree),
                kdl_escape_path(&docroot),
                kdl_escape_path(&real_sock),
                kdl_escape_path(&reg_fcgi),
                kdl_escape_path(&good_dir),
            ),
        )?;

        let log_under_reg = reg_log_parent.join("server.log");
        let (_code, val) = run_json(
            &[
                "--fs",
                "--trusted-paths",
                "--acme-dir",
                &reg_acme.to_string_lossy(),
                "--log-file",
                &log_under_reg.to_string_lossy(),
                "--log-max-bytes",
                "1024",
            ],
            &cfg,
        )?;
        let ws = w034s(&val);
        assert_eq!(
            ws.len(),
            6,
            "all 6 wrong leaves must fail, 0660 sock must pass: {val}"
        );
        assert_eq!(
            ws.first().and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "server.sandbox socket-tree root '{}': first untrusted component '{}' \
                     (uid {euid}, mode 0644): exists but is not a directory",
                    reg_tree.display(),
                    reg_tree.display()
                )
                .as_str()
            )
        );
        assert_eq!(
            ws.get(1).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "site 'lf.example' FastCGI Unix socket '{}': first untrusted component '{}' \
                     (uid {euid}, mode 0644): exists but is not a socket",
                    reg_fcgi.display(),
                    reg_fcgi.display()
                )
                .as_str()
            )
        );
        assert_eq!(
            ws.get(2).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "site 'lf.example' FastCGI Unix socket '{}': first untrusted component '{}' \
                     (uid {euid}, mode 0750): exists but is not a socket",
                    good_dir.display(),
                    good_dir.display()
                )
                .as_str()
            )
        );
        assert_eq!(
            ws.get(3).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "server.tls.keyd-socket '{}': first untrusted component '{}' \
                     (uid {euid}, mode 0644): exists but is not a socket",
                    reg_keyd.display(),
                    reg_keyd.display()
                )
                .as_str()
            )
        );
        assert_eq!(
            ws.get(4).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "ACME directory '{}': first untrusted component '{}' \
                     (uid {euid}, mode 0644): exists but is not a directory",
                    reg_acme.display(),
                    reg_acme.display()
                )
                .as_str()
            )
        );
        assert_eq!(
            ws.get(5).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "rotating --log-file parent directory '{}': first untrusted component '{}' \
                     (uid {euid}, mode 0644): exists but is not a directory",
                    reg_log_parent.display(),
                    reg_log_parent.display()
                )
                .as_str()
            )
        );

        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn linux_p1_5_acme_dotdot_and_owner_rules() -> TestResult {
        let base = make_temp_base("p1-acme")?;
        let (cert, key) = gen_dev_cert(&base)?;
        let docroot = base.join("www");
        let a_dir = base.join("a");
        let state_dir = base.join("state");
        for d in [&docroot, &a_dir, &state_dir] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o750)?;
        }
        set_mode(&state_dir, 0o700)?;

        let cfg = base.join("acme.kdl");
        fs::write(
            &cfg,
            format!(
                "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }} }}\n\
                 site \"ac.example\" {{ root \"{}\" }}\n",
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&docroot),
            ),
        )?;

        // 1. Trusted path containing `..` MUST be reported for ACME!
        let dotdot = a_dir.join("../state");
        let (_c, val) = run_json(
            &[
                "--fs",
                "--trusted-paths",
                "--acme-dir",
                &dotdot.to_string_lossy(),
            ],
            &cfg,
        )?;
        let ws = w034s(&val);
        assert_eq!(ws.len(), 1, "ACME path with .. must emit W034: {val}");
        assert_eq!(
            ws.first().and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "ACME directory '{}': first untrusted component '{}' \
                     (uid unknown, mode unknown): private state path must not contain '..'",
                    dotdot.display(),
                    dotdot.display()
                )
                .as_str()
            )
        );

        // 1b. Root `/` MUST be refused as ACME dir!
        let (_cr, val_r) = run_json(&["--fs", "--trusted-paths", "--acme-dir", "/"], &cfg)?;
        let wsr = w034s(&val_r);
        assert_eq!(wsr.len(), 1, "ACME / must emit W034: {val_r}");
        assert_eq!(
            wsr.first().and_then(|w| jstr(w, "message")),
            Some(
                "ACME directory '/': first untrusted component '/' (uid unknown, mode unknown): \
                 refusing filesystem root as private state path"
            )
        );

        // 2. Root-owned 0700 ACME dir MUST fail when service uid is 1000 (or unknown),
        //    and uid-1000-owned 0700 ACME dir MUST pass when service uid is 1000!
        if rustix::process::geteuid().is_root()
            && require_local_root_fs("linux_p1_5_acme_dotdot_and_owner_rules(owner)")?
        {
            let root_cfg = base.join("acme_u1000.kdl");
            fs::write(
                &root_cfg,
                format!(
                    "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }}; sandbox {{ user \"1000\" }} }}\n\
                     site \"ac.example\" {{ root \"{}\" }}\n",
                    kdl_escape_path(&cert),
                    kdl_escape_path(&key),
                    kdl_escape_path(&docroot),
                ),
            )?;
            let (_c2, val2) = run_json(
                &[
                    "--fs",
                    "--trusted-paths",
                    "--acme-dir",
                    &state_dir.to_string_lossy(),
                ],
                &root_cfg,
            )?;
            let ws2 = w034s(&val2);
            assert_eq!(
                ws2.len(),
                1,
                "root-owned ACME dir with service uid 1000 must emit W034: {val2}"
            );
            assert_eq!(
                ws2.first().and_then(|w| jstr(w, "message")),
                Some(
                    format!(
                        "ACME directory '{}': first untrusted component '{}' \
                         (uid 0, mode 0700): ACME directory must be owned by service uid 1000 (owned by uid 0)",
                        state_dir.display(),
                        state_dir.display()
                    )
                    .as_str()
                )
            );

            // Unknown service uid (root without sandbox.user) must also fail!
            let (_c3, val3) = run_json(
                &[
                    "--fs",
                    "--trusted-paths",
                    "--acme-dir",
                    &state_dir.to_string_lossy(),
                ],
                &cfg,
            )?;
            let ws3 = w034s(&val3);
            assert_eq!(
                ws3.len(),
                1,
                "ACME dir with unknown service uid must emit W034: {val3}"
            );
            assert_eq!(
                ws3.first().and_then(|w| jstr(w, "message")),
                Some(
                    format!(
                        "ACME directory '{}': first untrusted component '{}' \
                         (uid 0, mode 0700): not verified: service uid is unknown; cannot verify ACME directory owner",
                        state_dir.display(),
                        state_dir.display()
                    )
                    .as_str()
                )
            );

            // Service-uid-owned 0700 ACME dir MUST pass (0 W034)!
            rustix::fs::chown(
                &state_dir,
                Some(rustix::fs::Uid::from_raw(1000)),
                Some(rustix::fs::Gid::from_raw(1000)),
            )?;
            let (c4, val4) = run_json(
                &[
                    "--fs",
                    "--strict",
                    "--trusted-paths",
                    "--acme-dir",
                    &state_dir.to_string_lossy(),
                ],
                &root_cfg,
            )?;
            assert_eq!(
                c4,
                Some(0),
                "uid-1000 ACME dir with sandbox.user 1000 must pass: {val4}"
            );
            assert!(w034s(&val4).is_empty(), "val4: {val4}");
        }

        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn linux_p1_6_sticky_symlink_uses_service_uid_and_unknown_service_uid_fails() -> TestResult {
        use rustix::fs::{AtFlags, CWD, Gid, Uid, chown, chownat};
        use std::os::unix::fs::symlink;

        if !rustix::process::geteuid().is_root() {
            eprintln!(
                "skipping linux_p1_6_sticky_symlink_uses_service_uid_and_unknown_service_uid_fails: requires root"
            );
            return Ok(());
        }
        if !require_local_root_fs(
            "linux_p1_6_sticky_symlink_uses_service_uid_and_unknown_service_uid_fails",
        )? {
            return Ok(());
        }

        let base = make_temp_base("p1-sticky-sym")?;
        let (cert, key) = gen_dev_cert(&base)?;
        let docroot = base.join("www");
        let sock_dir = base.join("socks");
        let sticky_u1000 = base.join("sticky_u1000");
        let sticky_root = base.join("sticky_root");
        for d in [&docroot, &sock_dir, &sticky_u1000, &sticky_root] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o755)?;
        }
        set_mode(&sticky_u1000, 0o1777)?;
        set_mode(&sticky_root, 0o1777)?;

        let sock = sock_dir.join("pool.sock");
        let _listener = UnixListener::bind(&sock)?;
        set_mode(&sock, 0o660)?;

        // 1. 1000-owned sticky dir with root-owned symlink -> blocked for service uid 1000!
        let root_sym_in_u1000 = sticky_u1000.join("root_link");
        symlink(&sock, &root_sym_in_u1000)?;
        // 2. root-owned sticky dir with 1000-owned symlink -> ALLOWED for service uid 1000!
        let u1000_sym_in_root = sticky_root.join("u1000_link");
        symlink(&sock, &u1000_sym_in_root)?;
        // 3. root-owned sticky dir with root-owned symlink -> NOT VERIFIED when service uid unknown!
        let root_sym_in_root = sticky_root.join("root_link");
        symlink(&sock, &root_sym_in_root)?;

        let u1000 = Some(Uid::from_raw(1000));
        let g1000 = Some(Gid::from_raw(1000));
        chown(&sticky_u1000, u1000, g1000)?;
        chownat(
            CWD,
            &u1000_sym_in_root,
            u1000,
            g1000,
            AtFlags::SYMLINK_NOFOLLOW,
        )?;

        let named_cfg = base.join("named.kdl");
        fs::write(
            &named_cfg,
            format!(
                "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }}; sandbox {{ user \"1000\" }} }}\n\
                 site \"s.example\" {{\n\
                     root \"{}\"\n\
                     route \"/blocked/*\" {{ fastcgi-pass \"unix:{}\" }}\n\
                     route \"/allowed/*\" {{ fastcgi-pass \"unix:{}\" }}\n\
                 }}\n",
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&docroot),
                kdl_escape_path(&root_sym_in_u1000),
                kdl_escape_path(&u1000_sym_in_root),
            ),
        )?;
        let (_c1, val1) = run_json(&["--fs", "--trusted-paths"], &named_cfg)?;
        let ws1 = w034s(&val1);
        assert_eq!(
            ws1.len(),
            1,
            "only root_sym_in_u1000 must warn, u1000_sym_in_root must pass: {val1}"
        );
        assert_eq!(
            ws1.first().and_then(|w| jstr(w, "path")),
            Some("site[0].route[0].fastcgi-pass")
        );
        assert_eq!(
            ws1.first().and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "site 's.example' FastCGI Unix socket '{}': first untrusted component '{}' \
                     (uid 0, mode 0777): symbolic link whose own parent or target chain is untrusted \
                     (blocked by fs.protected_symlinks for service uid)",
                    root_sym_in_u1000.display(),
                    root_sym_in_u1000.display()
                )
                .as_str()
            )
        );

        let unknown_cfg = base.join("unknown.kdl");
        fs::write(
            &unknown_cfg,
            format!(
                "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }} }}\n\
                 site \"u.example\" {{\n\
                     root \"{}\"\n\
                     route \"/unk/*\" {{ fastcgi-pass \"unix:{}\" }}\n\
                 }}\n",
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&docroot),
                kdl_escape_path(&root_sym_in_root),
            ),
        )?;
        let (_c2, val2) = run_json(&["--fs", "--trusted-paths"], &unknown_cfg)?;
        let ws2 = w034s(&val2);
        assert_eq!(
            ws2.len(),
            1,
            "sticky symlink with unknown service uid must warn: {val2}"
        );
        assert_eq!(
            ws2.first().and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "site 'u.example' FastCGI Unix socket '{}': first untrusted component '{}' \
                     (uid 0, mode 0777): symbolic link whose own parent or target chain is untrusted \
                     (not verified: service uid is unknown in sticky world-writable directory)",
                    root_sym_in_root.display(),
                    root_sym_in_root.display()
                )
                .as_str()
            )
        );

        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn linux_c1_service_uid_mismatch_uses_configured_uid_and_reports_not_verified() -> TestResult {
        let euid = rustix::process::geteuid().as_raw();
        if euid == 0 {
            eprintln!(
                "skipping linux_c1_service_uid_mismatch_uses_configured_uid_and_reports_not_verified: requires non-root"
            );
            return Ok(());
        }
        if !require_local_root_fs(
            "linux_c1_service_uid_mismatch_uses_configured_uid_and_reports_not_verified",
        )? {
            return Ok(());
        }

        let other_uid = if euid == 1000 { 1001 } else { 1000 };
        let base = make_temp_base("c1-mismatch")?;
        let (cert, key) = gen_dev_cert(&base)?;
        let docroot = base.join("www");
        let pool_dir = base.join("pool");
        for d in [&docroot, &pool_dir] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o750)?;
        }
        let sock = pool_dir.join("app.sock");
        let _listener = UnixListener::bind(&sock)?;
        set_mode(&sock, 0o660)?;

        let cfg = base.join("c1.kdl");
        fs::write(
            &cfg,
            format!(
                "server {{\n\
                     listen \":443\"\n\
                     tls {{ cert \"{}\"; key \"{}\" }}\n\
                     sandbox {{ user \"{other_uid}\" }}\n\
                 }}\n\
                 site \"c1.example\" {{\n\
                     root \"{}\"\n\
                     route \"/owned/*\" {{ fastcgi-pass \"unix:{}\" }}\n\
                     route \"/root/*\" {{ fastcgi-pass \"unix:/ms-tp-c1-nonexistent.sock\" }}\n\
                 }}\n",
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&docroot),
                kdl_escape_path(&sock),
            ),
        )?;

        let (code, val) = run_json(&["--fs", "--strict", "--trusted-paths"], &cfg)?;
        let ws = w034s(&val);
        assert_eq!(
            ws.len(),
            3,
            "expected owner-not-trusted + two per-path not-verified W034s: {ws:#?}"
        );
        assert_eq!(
            code,
            Some(1),
            "mismatched service uid must fail --strict: {val}"
        );
        assert_eq!(
            note_at(&val, 0),
            Some(
                format!(
                    "trusted-paths: checked as uid {euid}, but server.sandbox.user '{other_uid}' \
                     resolves to uid {other_uid}; trusting uid 0 and service uid {other_uid}"
                )
                .as_str()
            )
        );
        assert_eq!(note_at(&val, 1), Some(NARROWED_NOTE_LITERAL));
        assert_eq!(
            note_at(&val, 2),
            None,
            "mismatched check must not emit an inspected-prefix pass note: {val}"
        );
        assert_eq!(
            ws.first().and_then(|w| jstr(w, "path")),
            Some("site[0].route[0].fastcgi-pass")
        );
        assert_eq!(
            ws.first().and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "site 'c1.example' FastCGI Unix socket '{}': first untrusted component '{}' \
                     (uid {euid}, mode 0750): owner not trusted",
                    sock.display(),
                    base.display()
                )
                .as_str()
            )
        );
        assert_eq!(
            ws.get(1).and_then(|w| jstr(w, "path")),
            Some("site[0].route[0].fastcgi-pass")
        );
        assert_eq!(
            ws.get(1).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "site 'c1.example' FastCGI Unix socket '{}': not verified: checked as uid {euid} \
                     but the configured service account is uid {other_uid}",
                    sock.display(),
                )
                .as_str()
            )
        );
        assert_eq!(
            ws.get(2).and_then(|w| jstr(w, "path")),
            Some("site[0].route[1].fastcgi-pass")
        );
        assert_eq!(
            ws.get(2).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "site 'c1.example' FastCGI Unix socket '/ms-tp-c1-nonexistent.sock': \
                     not verified: checked as uid {euid} but the configured service account is uid \
                     {other_uid}"
                )
                .as_str()
            )
        );

        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn linux_c2_cli_sourced_paths_have_no_kdl_location_and_documented_keys() -> TestResult {
        if !require_local_root_fs(
            "linux_c2_cli_sourced_paths_have_no_kdl_location_and_documented_keys",
        )? {
            return Ok(());
        }
        let base = make_temp_base("c2-cli-loc")?;
        let (cert, key) = gen_dev_cert(&base)?;
        let docroot = base.join("www");
        let bad = base.join("bad");
        for d in [&docroot, &bad] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o750)?;
        }
        set_mode(&bad, 0o775)?;
        let bad_sock = bad.join("pool.sock");

        // Explicit `server` and `server.tls` blocks exist in KDL; CLI-sourced warnings MUST NOT
        // inherit their source spans via `location_for` fallback.
        let cfg = base.join("c2.kdl");
        fs::write(
            &cfg,
            format!(
                "server {{\n\
                     listen \":443\"\n\
                     tls {{ cert \"{}\"; key \"{}\" }}\n\
                 }}\n\
                 site \"c2.example\" {{\n\
                     root \"{}\"\n\
                     route \"*.php\" {{ fastcgi-pass \"unix:{}\" }}\n\
                 }}\n",
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&docroot),
                kdl_escape_path(&bad_sock),
            ),
        )?;

        let acme_bad = bad.join("acme");
        let log_bad = bad.join("server.log");
        let acc_bad = bad.join("access.log");
        let (_code, val) = run_json(
            &[
                "--fs",
                "--trusted-paths",
                "--acme-dir",
                &acme_bad.to_string_lossy(),
                "--log-file",
                &log_bad.to_string_lossy(),
                "--access-log",
                &acc_bad.to_string_lossy(),
                "--log-max-bytes",
                "1024",
            ],
            &cfg,
        )?;
        let ws = w034s(&val);
        assert_eq!(ws.len(), 4, "expected 4 W034s: {ws:#?}");

        // KDL-sourced fastcgi-pass retains its KDL location.
        assert_eq!(
            ws.first().and_then(|w| jstr(w, "path")),
            Some("site[0].route[0].fastcgi-pass")
        );
        assert!(
            ws.first().and_then(|w| w.get("location")).is_some(),
            "KDL-sourced warning must retain location: {:?}",
            ws.first()
        );

        // CLI-sourced --acme-dir, --log-file, and --access-log use documented keys and omit `location`.
        for (idx, expected_key) in [
            (1_usize, "server.tls.acme"),
            (2, "server.log-file"),
            (3, "server.access-log"),
        ] {
            let w = ws.get(idx).copied().ok_or("missing CLI W034")?;
            assert_eq!(jstr(w, "path"), Some(expected_key), "w: {w}");
            assert!(
                w.get("location").is_none(),
                "CLI-sourced W034 '{expected_key}' must have no KDL location: {w}"
            );
        }

        // Even when KDL contains `server.tls.acme`, `--acme-dir` is CLI-sourced -> no location;
        // without `--acme-dir`, default `.miraserve-acme` is triggered by KDL -> has location.
        let acme_cfg = base.join("c2_acme.kdl");
        fs::write(
            &acme_cfg,
            format!(
                "server {{\n\
                     listen \":443\"\n\
                     tls {{ acme {{ email \"ops@example.com\"; challenge \"tls-alpn-01\" }} }}\n\
                 }}\n\
                 site \"c2a.example\" {{ root \"{}\" }}\n",
                kdl_escape_path(&docroot),
            ),
        )?;
        let (_c_cli, val_cli) = run_json(
            &[
                "--fs",
                "--trusted-paths",
                "--acme-dir",
                &acme_bad.to_string_lossy(),
            ],
            &acme_cfg,
        )?;
        let w_cli = w034s(&val_cli);
        assert_eq!(w_cli.len(), 1, "val_cli: {val_cli}");
        assert_eq!(
            w_cli.first().and_then(|w| jstr(w, "path")),
            Some("server.tls.acme")
        );
        assert!(
            w_cli.first().and_then(|w| w.get("location")).is_none(),
            "--acme-dir W034 must omit location even with KDL acme block: {val_cli}"
        );

        let (_c_kdl, val_kdl) = run_json(&["--fs", "--trusted-paths"], &acme_cfg)?;
        let w_kdl = w034s(&val_kdl);
        assert_eq!(w_kdl.len(), 1, "val_kdl: {val_kdl}");
        assert_eq!(
            w_kdl.first().and_then(|w| jstr(w, "path")),
            Some("server.tls.acme")
        );
        assert!(
            w_kdl.first().and_then(|w| w.get("location")).is_some(),
            "KDL-triggered default ACME W034 must carry location: {val_kdl}"
        );

        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    fn linux_point2_fastcgi_untrimmed_and_socket_tree_trailing_slash_match_runtime() -> TestResult {
        let base = make_temp_base("p2-runtime-match")?;
        let (cert, key) = gen_dev_cert(&base)?;
        let euid = rustix::process::geteuid().as_raw();
        let docroot = base.join("www");
        let sticky = base.join("sticky");
        let tree_ok = base.join("tree_ok");
        let tree_bad = base.join("tree_bad");
        for d in [&docroot, &sticky, &tree_ok, &tree_bad] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o750)?;
        }
        set_mode(&sticky, 0o1777)?;
        set_mode(&tree_bad, 0o775)?;

        let sock = sticky.join("pool.sock");
        let _listener = UnixListener::bind(&sock)?;
        set_mode(&sock, 0o660)?;

        // 1. Since 0.1.8, leading/trailing whitespace after `unix:` on `fastcgi-pass` is
        //    rejected at KDL load with E202 before `--trusted-paths` runs.
        let padded_cfg = base.join("rt-padded.kdl");
        fs::write(
            &padded_cfg,
            format!(
                "server {{\n\
                     listen \":443\"\n\
                     tls {{ cert \"{}\"; key \"{}\" }}\n\
                 }}\n\
                 site \"rt.example\" {{\n\
                     root \"{}\"\n\
                     route \"/lead/*\" {{ fastcgi-pass \"unix: {}\" }}\n\
                     route \"/trail/*\" {{ fastcgi-pass \"unix:{} \" }}\n\
                 }}\n",
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&docroot),
                kdl_escape_path(&sock),
                kdl_escape_path(&sock),
            ),
        )?;
        let (p_code, p_val) = run_json(&["--fs", "--trusted-paths"], &padded_cfg)?;
        // The configuration now fails to load, so `check` exits non-zero.
        assert_eq!(p_code, Some(1), "padded fastcgi-pass must exit 1: {p_val}");
        // The configuration now fails to load, so the report marks it invalid.
        assert_eq!(p_val.get("valid"), Some(&serde_json::Value::Bool(false)));
        // The configuration now fails to load, so `--trusted-paths` does not run.
        assert_eq!(w034s(&p_val).len(), 0, "expected 0 W034 on E202: {p_val}");
        // The configuration now fails to load with two E202 load errors.
        assert_eq!(
            p_val
                .get("errors")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(2),
            "expected 2 E202 errors: {p_val}"
        );
        // The configuration now fails to load with E202 on the leading-space route.
        assert_eq!(
            p_val
                .pointer("/errors/0/code")
                .and_then(serde_json::Value::as_str),
            Some("E202")
        );
        // The configuration now fails to load on `site[0].route[0].fastcgi-pass`.
        assert_eq!(
            p_val
                .pointer("/errors/0/path")
                .and_then(serde_json::Value::as_str),
            Some("site[0].route[0].fastcgi-pass")
        );
        // The configuration now fails to load naming `/lead/*` and its leading space.
        assert_eq!(
            p_val
                .pointer("/errors/0/message")
                .and_then(serde_json::Value::as_str),
            Some(
                "'fastcgi-pass' path on route '/lead/*' of site 'rt.example' starts with whitespace (U+0020)"
            )
        );
        // The configuration now fails to load with E202 on the trailing-space route.
        assert_eq!(
            p_val
                .pointer("/errors/1/code")
                .and_then(serde_json::Value::as_str),
            Some("E202")
        );
        // The configuration now fails to load on `site[0].route[1].fastcgi-pass`.
        assert_eq!(
            p_val
                .pointer("/errors/1/path")
                .and_then(serde_json::Value::as_str),
            Some("site[0].route[1].fastcgi-pass")
        );
        // The configuration now fails to load naming `/trail/*` and its trailing space.
        assert_eq!(
            p_val
                .pointer("/errors/1/message")
                .and_then(serde_json::Value::as_str),
            Some(
                "'fastcgi-pass' path on route '/trail/*' of site 'rt.example' ends with whitespace (U+0020)"
            )
        );

        // 2. Clean `socket-tree` trailing slash continues to load and match runtime normalization.
        if require_local_root_fs(
            "linux_point2_fastcgi_untrimmed_and_socket_tree_trailing_slash_match_runtime",
        )? {
            let cfg = base.join("rt.kdl");
            fs::write(
                &cfg,
                format!(
                    "server {{\n\
                         listen \":443\"\n\
                         tls {{ cert \"{}\"; key \"{}\" }}\n\
                         sandbox {{ socket-tree \"{}/\" \"{}/\" }}\n\
                     }}\n\
                     site \"rt.example\" {{\n\
                         root \"{}\"\n\
                     }}\n",
                    kdl_escape_path(&cert),
                    kdl_escape_path(&key),
                    kdl_escape_path(&tree_ok),
                    kdl_escape_path(&tree_bad),
                    kdl_escape_path(&docroot),
                ),
            )?;

            let (_code, val) = run_json(&["--fs", "--trusted-paths"], &cfg)?;
            let ws = w034s(&val);
            assert_eq!(ws.len(), 1, "expected 1 W034: {ws:#?}");
            assert_eq!(
                ws.first().and_then(|w| jstr(w, "path")),
                Some("server.sandbox.socket-tree")
            );
            assert_eq!(
                ws.first().and_then(|w| jstr(w, "message")),
                Some(
                    format!(
                        "server.sandbox socket-tree root '{}': first untrusted component '{}' \
                         (uid {euid}, mode 0775): {TREE_WR_LITERAL}",
                        tree_bad.display(),
                        tree_bad.display()
                    )
                    .as_str()
                )
            );
        }

        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn linux_small2_missing_created_dirs_and_non_utf8_components() -> TestResult {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;
        use std::os::unix::fs::symlink;

        if !require_local_root_fs("linux_small2_missing_created_dirs_and_non_utf8_components")? {
            return Ok(());
        }
        let base = make_temp_base("small2")?;
        let (cert, key) = gen_dev_cert(&base)?;
        let euid = rustix::process::geteuid().as_raw();
        let docroot = base.join("www");
        let trusted = base.join("trusted");
        for d in [&docroot, &trusted] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o750)?;
        }

        // 1. Missing directory components across all directory roles (socket-tree, rotating log
        //    parent, ACME dir) MUST give W034 with the exact reason; absent final exact sockets
        //    (fastcgi-pass, keyd-socket) under existing trusted parents keep verified-prefix notes.
        let miss_tree = trusted.join("future_tree");
        let miss_fcgi = trusted.join("future_fcgi.sock");
        let miss_keyd = trusted.join("future_keyd.sock");
        let miss_log_mid = trusted.join("new/logs/server.log");
        let miss_acc_leaf = trusted.join("absent_acc/access.log");
        let miss_acme_mid = trusted.join("new_acme/state");
        let miss_acme_leaf = trusted.join("absent_acme");

        let cfg = base.join("small2_missing.kdl");
        fs::write(
            &cfg,
            format!(
                "server {{\n\
                     listen \":443\"\n\
                     tls {{ key-isolation \"split-daemon\"; keyd-socket \"{}\"; cert \"{}\"; key \"{}\" }}\n\
                     sandbox {{ socket-tree \"{}\" }}\n\
                 }}\n\
                 site \"m.example\" {{\n\
                     root \"{}\"\n\
                     route \"*.php\" {{ fastcgi-pass \"unix:{}\" }}\n\
                 }}\n",
                kdl_escape_path(&miss_keyd),
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&miss_tree),
                kdl_escape_path(&docroot),
                kdl_escape_path(&miss_fcgi),
            ),
        )?;

        let reason =
            "not found; if it is created later the permissions it would inherit are not verified";
        let (_code, val) = run_json(
            &[
                "--fs",
                "--trusted-paths",
                "--acme-dir",
                &miss_acme_mid.to_string_lossy(),
                "--log-file",
                &miss_log_mid.to_string_lossy(),
                "--access-log",
                &miss_acc_leaf.to_string_lossy(),
                "--log-max-bytes",
                "1024",
            ],
            &cfg,
        )?;
        let ws = w034s(&val);
        assert_eq!(
            ws.len(),
            4,
            "expected 4 W034s (socket-tree, acme, log, access): {ws:#?}"
        );
        assert_eq!(
            ws.first().and_then(|w| jstr(w, "path")),
            Some("server.sandbox.socket-tree")
        );
        assert_eq!(
            ws.first().and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "server.sandbox socket-tree root '{}': first untrusted component '{}' \
                     (uid unknown, mode unknown): {reason}",
                    miss_tree.display(),
                    miss_tree.display(),
                )
                .as_str()
            )
        );
        assert_eq!(
            ws.get(1).and_then(|w| jstr(w, "path")),
            Some("server.tls.acme")
        );
        assert_eq!(
            ws.get(1).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "ACME directory '{}': first untrusted component '{}' \
                     (uid unknown, mode unknown): {reason}",
                    miss_acme_mid.display(),
                    trusted.join("new_acme").display(),
                )
                .as_str()
            )
        );
        assert_eq!(
            ws.get(2).and_then(|w| jstr(w, "path")),
            Some("server.log-file")
        );
        assert_eq!(
            ws.get(2).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "rotating --log-file parent directory '{}': first untrusted component '{}' \
                     (uid unknown, mode unknown): {reason}",
                    trusted.join("new/logs").display(),
                    trusted.join("new").display(),
                )
                .as_str()
            )
        );
        assert_eq!(
            ws.get(3).and_then(|w| jstr(w, "path")),
            Some("server.access-log")
        );
        assert_eq!(
            ws.get(3).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "rotating --access-log parent directory '{}': first untrusted component '{}' \
                     (uid unknown, mode unknown): {reason}",
                    trusted.join("absent_acc").display(),
                    trusted.join("absent_acc").display(),
                )
                .as_str()
            )
        );
        // Only absent exact sockets under an existing trusted parent keep verified-prefix notes.
        assert_eq!(
            note_at(&val, 2),
            Some(
                format!(
                    "trusted-paths: site 'm.example' FastCGI Unix socket '{}': inspected existing \
                     prefix '{}' (stopped at 'future_fcgi.sock', not found by this lookup)",
                    miss_fcgi.display(),
                    trusted.display()
                )
                .as_str()
            )
        );
        assert_eq!(
            note_at(&val, 3),
            Some(
                format!(
                    "trusted-paths: server.tls.keyd-socket '{}': inspected existing prefix '{}' \
                     (stopped at 'future_keyd.sock', not found by this lookup)",
                    miss_keyd.display(),
                    trusted.display()
                )
                .as_str()
            )
        );

        // Missing leaf ACME directory also emits W034 with the same exact reason.
        let (_c_leaf, val_leaf) = run_json(
            &[
                "--fs",
                "--trusted-paths",
                "--acme-dir",
                &miss_acme_leaf.to_string_lossy(),
            ],
            &cfg,
        )?;
        let ws_leaf = w034s(&val_leaf);
        assert_eq!(
            ws_leaf.len(),
            2,
            "expected 2 W034s (absent socket-tree and absent ACME leaf): {ws_leaf:#?}"
        );
        assert_eq!(
            ws_leaf.get(1).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "ACME directory '{}': first untrusted component '{}' \
                     (uid unknown, mode unknown): {reason}",
                    miss_acme_leaf.display(),
                    miss_acme_leaf.display(),
                )
                .as_str()
            )
        );

        // 2. Non-UTF-8 symlink target bytes vs U+FFFD vs literal `\xff`: four distinct byte
        //    strings MUST render to four distinct warning component names.
        let dir_high_ff = trusted.join(OsString::from_vec(b"bad_\xff".to_vec()));
        let dir_alt_fe = trusted.join(OsString::from_vec(b"bad_\xfe".to_vec()));
        let dir_fffd = trusted.join("bad_\u{FFFD}");
        let dir_esc = trusted.join("bad_\\xff");
        for d in [&dir_high_ff, &dir_alt_fe, &dir_fffd, &dir_esc] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o775)?;
        }
        let sym_high_ff = trusted.join("link_ff");
        let sym_alt_fe = trusted.join("link_fe");
        let sym_fffd = trusted.join("link_fffd");
        let sym_esc = trusted.join("link_esc");
        symlink(&dir_high_ff, &sym_high_ff)?;
        symlink(&dir_alt_fe, &sym_alt_fe)?;
        symlink(&dir_fffd, &sym_fffd)?;
        symlink(&dir_esc, &sym_esc)?;

        let ncfg = base.join("non_utf8.kdl");
        fs::write(
            &ncfg,
            format!(
                "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }} }}\n\
                 site \"u.example\" {{\n\
                     root \"{}\"\n\
                     route \"/a/*\" {{ fastcgi-pass \"unix:{}/p.sock\" }}\n\
                     route \"/b/*\" {{ fastcgi-pass \"unix:{}/p.sock\" }}\n\
                     route \"/c/*\" {{ fastcgi-pass \"unix:{}/p.sock\" }}\n\
                     route \"/d/*\" {{ fastcgi-pass \"unix:{}/p.sock\" }}\n\
                 }}\n",
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&docroot),
                kdl_escape_path(&sym_high_ff),
                kdl_escape_path(&sym_alt_fe),
                kdl_escape_path(&sym_fffd),
                kdl_escape_path(&sym_esc),
            ),
        )?;
        let (_nc, nval) = run_json(&["--fs", "--trusted-paths"], &ncfg)?;
        let nws = w034s(&nval);
        assert_eq!(
            nws.len(),
            4,
            "expected 4 W034s for distinct byte targets: {nws:#?}"
        );
        let expected_msgs = [
            (&sym_high_ff, format!("{}/bad_\\xff", trusted.display())),
            (&sym_alt_fe, format!("{}/bad_\\xfe", trusted.display())),
            (&sym_fffd, format!("{}/bad_\u{FFFD}", trusted.display())),
            (&sym_esc, format!("{}/bad_\\\\xff", trusted.display())),
        ];
        for (idx, (lnk, rendered_comp)) in expected_msgs.iter().enumerate() {
            assert_eq!(
                nws.get(idx).and_then(|w| jstr(w, "message")),
                Some(
                    format!(
                        "site 'u.example' FastCGI Unix socket '{}/p.sock': first untrusted \
                         component '{rendered_comp}' (uid {euid}, mode 0775): symbolic link \
                         whose own parent or target chain is untrusted (via '{}': group or other \
                         writable)",
                        lnk.display(),
                        lnk.display(),
                    )
                    .as_str()
                )
            );
        }

        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn linux_small3_missing_dirs_all_classes_and_sticky_reason() -> TestResult {
        if !require_local_root_fs("linux_small3_missing_dirs_all_classes_and_sticky_reason")? {
            return Ok(());
        }
        let base = make_temp_base("small3")?;
        let (cert, key) = gen_dev_cert(&base)?;
        let euid = rustix::process::geteuid().as_raw();
        let docroot = base.join("www");
        let trusted = base.join("trusted");
        let sticky = base.join("sticky");
        for d in [&docroot, &trusted, &sticky] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o750)?;
        }
        set_mode(&sticky, 0o1777)?;

        // 1. Fails on b6a2196: socket-tree with two missing components under a trusted prefix
        //    (including alongside a non-rotating --log-file) MUST give W034 at the FIRST missing
        //    component; missing intermediate dirs of fastcgi-pass and keyd-socket (and trailing /
        //    on an absent socket) MUST also give W034; ONLY an absent exact socket directly under
        //    an existing trusted parent gives no W034 (keeps verified-prefix note).
        let tree_two_miss = trusted.join("a/b");
        let nonrot_log = tree_two_miss.join("app.log");
        let fcgi_miss_mid = trusted.join("miss_fcgi/pool.sock");
        let fcgi_trailing_slash = format!("{}/trailing.sock/", trusted.display());
        let fcgi_unbound_ok = trusted.join("unbound.sock");
        let keyd_miss_mid = trusted.join("miss_keyd/keyd.sock");
        let sticky_miss_tree = sticky.join("miss_tree/sub");

        let cfg = base.join("small3.kdl");
        fs::write(
            &cfg,
            format!(
                "server {{\n\
                     listen \":443\"\n\
                     tls {{ key-isolation \"split-daemon\"; keyd-socket \"{}\"; cert \"{}\"; key \"{}\" }}\n\
                     sandbox {{ socket-tree \"{}\" \"{}\" }}\n\
                 }}\n\
                 site \"s3.example\" {{\n\
                     root \"{}\"\n\
                     route \"/mid/*\" {{ fastcgi-pass \"unix:{}\" }}\n\
                     route \"/slash/*\" {{ fastcgi-pass \"unix:{}\" }}\n\
                     route \"/ok/*\" {{ fastcgi-pass \"unix:{}\" }}\n\
                 }}\n",
                kdl_escape_path(&keyd_miss_mid),
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&tree_two_miss),
                kdl_escape_path(&sticky_miss_tree),
                kdl_escape_path(&docroot),
                kdl_escape_path(&fcgi_miss_mid),
                kdl_escape_path(Path::new(&fcgi_trailing_slash)),
                kdl_escape_path(&fcgi_unbound_ok),
            ),
        )?;

        let reason =
            "not found; if it is created later the permissions it would inherit are not verified";
        let (_code, val) = run_json(
            &[
                "--fs",
                "--trusted-paths",
                "--log-file",
                &nonrot_log.to_string_lossy(),
            ],
            &cfg,
        )?;
        let ws = w034s(&val);
        assert_eq!(ws.len(), 5, "expected 5 W034s: {ws:#?}");
        assert_eq!(
            ws.first().and_then(|w| jstr(w, "path")),
            Some("server.sandbox.socket-tree")
        );
        assert_eq!(
            ws.first().and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "server.sandbox socket-tree root '{}': first untrusted component '{}' \
                     (uid unknown, mode unknown): {reason}",
                    tree_two_miss.display(),
                    trusted.join("a").display(),
                )
                .as_str()
            )
        );
        assert_eq!(
            ws.get(1).and_then(|w| jstr(w, "path")),
            Some("server.sandbox.socket-tree")
        );
        assert_eq!(
            ws.get(1).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "server.sandbox socket-tree root '{}': first untrusted component '{}' \
                     (uid {euid}, mode 1777): missing component 'miss_tree' under a parent where \
                     another account could create it, and if it is created later the permissions it \
                     would inherit are not verified",
                    sticky_miss_tree.display(),
                    sticky.display(),
                )
                .as_str()
            )
        );
        assert_eq!(
            ws.get(2).and_then(|w| jstr(w, "path")),
            Some("site[0].route[0].fastcgi-pass")
        );
        assert_eq!(
            ws.get(2).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "site 's3.example' FastCGI Unix socket '{}': first untrusted component '{}' \
                     (uid unknown, mode unknown): {reason}",
                    fcgi_miss_mid.display(),
                    trusted.join("miss_fcgi").display(),
                )
                .as_str()
            )
        );
        assert_eq!(
            ws.get(3).and_then(|w| jstr(w, "path")),
            Some("site[0].route[1].fastcgi-pass")
        );
        assert_eq!(
            ws.get(3).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "site 's3.example' FastCGI Unix socket '{fcgi_trailing_slash}': first untrusted \
                     component '{}' (uid unknown, mode unknown): {reason}",
                    trusted.join("trailing.sock").display(),
                )
                .as_str()
            )
        );
        assert_eq!(
            ws.get(4).and_then(|w| jstr(w, "path")),
            Some("server.tls.keyd-socket")
        );
        assert_eq!(
            ws.get(4).and_then(|w| jstr(w, "message")),
            Some(
                format!(
                    "server.tls.keyd-socket '{}': first untrusted component '{}' \
                     (uid unknown, mode unknown): {reason}",
                    keyd_miss_mid.display(),
                    trusted.join("miss_keyd").display(),
                )
                .as_str()
            )
        );
        // The absent exact socket under existing trusted parent keeps its note and gets no W034.
        assert_eq!(
            note_at(&val, 2),
            Some(
                format!(
                    "trusted-paths: site 's3.example' FastCGI Unix socket '{}': inspected existing \
                     prefix '{}' (stopped at 'unbound.sock', not found by this lookup)",
                    fcgi_unbound_ok.display(),
                    trusted.display(),
                )
                .as_str()
            )
        );
        assert_eq!(note_at(&val, 3), None, "unexpected extra note: {val}");

        let _ = fs::remove_dir_all(&base);
        Ok(())
    }
}

//! Stage 2 (0.1.8) CLI parity and security oracle tests.
//!
//! - `parity_*`: MUST pass on both `441a58d` and the 0.1.8 branch. When `MIRASERVE_BASELINE_BIN`
//!   points to a `441a58d` or `bef6865` binary, asserts exact byte-for-byte equality of exit
//!   status, stdout, and stderr across all clean CLI modes (`check`, `--strict`,
//!   `--allow-warning`, `--fs`, `--format json`, `--writable-set`, `--dump-normalized`,
//!   `--trusted-paths`, stdin `-`, symlinked config, internal spaces, padded `index` basenames,
//!   and `service generate`), allowing on Linux `--trusted-paths` only the exact narrowed-note
//!   update and the single `site[1].ai-publish.storage` `W034` delta when a shared ancestor fails.
//! - `security_*`: MUST fail on `441a58d` and pass on the 0.1.8 branch. Proves that rejected
//!   padded candidates emit exact `E202` JSON fields, nonzero exit, empty `--writable-set` stdout,
//!   refused `reload --dry-run`, and NEVER provision or modify padded or unpadded sibling dirs.

use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[path = "../../miraserve-config/tests/common/mod.rs"]
mod kdl_test_util;

use kdl_test_util::kdl_escape_path;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type RunOutput = (Option<i32>, Vec<u8>, Vec<u8>);
type CliCase<'a> = (&'a str, Vec<&'a str>, Option<&'a [u8]>);

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
            std::env::temp_dir().join(format!("ms-pws-cli-{tag}-{}-{nanos}", std::process::id()));
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

fn current_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_miraserve"))
}

fn baseline_bin() -> Option<PathBuf> {
    std::env::var_os("MIRASERVE_BASELINE_BIN").map(PathBuf::from)
}

fn strip_windows_verbatim_prefix(path: &Path) -> String {
    let raw = path.to_string_lossy();
    if let Some(unc) = raw.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else if let Some(stripped) = raw.strip_prefix(r"\\?\") {
        stripped.to_owned()
    } else {
        raw.into_owned()
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

fn run_bin(
    bin: &Path,
    cwd: &Path,
    args: &[&str],
    stdin_bytes: Option<&[u8]>,
) -> Result<RunOutput, Box<dyn std::error::Error>> {
    let mut cmd = Command::new(bin);
    cmd.current_dir(cwd).args(args);
    if stdin_bytes.is_some() {
        cmd.stdin(Stdio::piped());
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    if let Some(input) = stdin_bytes
        && let Some(mut stdin) = child.stdin.take()
    {
        stdin.write_all(input)?;
    }
    let out = child.wait_with_output()?;
    Ok((out.status.code(), out.stdout, out.stderr))
}

fn run_bin_with_timeout(
    bin: &Path,
    cwd: &Path,
    args: &[&str],
    timeout: Duration,
) -> Result<RunOutput, Box<dyn std::error::Error>> {
    let mut cmd = Command::new(bin);
    cmd.current_dir(cwd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let out_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut r) = stdout_pipe {
            let _ = r.read_to_end(&mut buf);
        }
        buf
    });
    let err_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut r) = stderr_pipe {
            let _ = r.read_to_end(&mut buf);
        }
        buf
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break st;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = out_thread.join();
            let _ = err_thread.join();
            return Err(format!(
                "command {:?} did not exit within {}s",
                args,
                timeout.as_secs()
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let stdout = out_thread
        .join()
        .map_err(|_| "stdout reader thread panicked")?;
    let stderr = err_thread
        .join()
        .map_err(|_| "stderr reader thread panicked")?;
    Ok((status.code(), stdout, stderr))
}

#[test]
#[allow(clippy::too_many_lines)]
fn parity_clean_cli_modes_including_trusted_paths_and_service_generate() -> TestResult {
    let bin = current_bin();
    let tmp = TempDir::new("parity")?;
    let base = &tmp.path;

    let certs_dir = base.join("certs");
    let root_spaces = base.join("site root");
    let conf_dir = base.join("conf real");
    let link_dir = base.join("conf link");
    let rel_pub = conf_dir.join("public");
    let rel_store = conf_dir.join("releases");
    let acme_dir = base.join("acme state");
    for d in [
        &certs_dir,
        &root_spaces,
        &conf_dir,
        &link_dir,
        &rel_pub,
        &rel_store,
        &acme_dir,
    ] {
        fs::create_dir_all(d)?;
        set_mode(d, 0o750)?;
    }
    #[cfg(unix)]
    let sock_dir = {
        let raw_sock_dir = base.join("php socks");
        fs::create_dir_all(&raw_sock_dir)?;
        set_mode(&raw_sock_dir, 0o750)?;
        // Canonicalize so `socket-tree` shares the exact symlink-free ancestor chain that
        // `miraserve-config` resolves for relative `ai-publish.storage` (preventing a `TMPDIR`
        // symlink under sticky `/tmp` from flagging `socket-tree` as root when storage is clean).
        fs::canonicalize(&raw_sock_dir)?
    };
    set_mode(&acme_dir, 0o700)?;
    fs::write(root_spaces.join(" index.html"), b"padded-index-ok")?;
    fs::write(rel_pub.join("index.html"), b"rel-pub-ok")?;

    let cert_path = certs_dir.join("srv.crt");
    let key_path = certs_dir.join("srv.key");
    let (cert_code, _, cert_err) = run_bin(
        &bin,
        base,
        &[
            "cert",
            "generate-dev",
            "--hosts",
            "clean.example,rel.example",
            "--cert",
            cert_path.to_str().ok_or("non-utf8 cert path")?,
            "--key",
            key_path.to_str().ok_or("non-utf8 key path")?,
        ],
        None,
    )?;
    assert_eq!(
        cert_code,
        Some(0),
        "cert generate-dev failed: {}",
        String::from_utf8_lossy(&cert_err)
    );
    set_mode(&cert_path, 0o640)?;
    set_mode(&key_path, 0o600)?;

    let pub_key = certs_dir.join("deploy.pub");
    fs::write(&pub_key, b"0123456789abcdef0123456789abcdef\n")?;
    set_mode(&pub_key, 0o640)?;

    let cert_esc = kdl_escape_path(&cert_path);
    let key_esc = kdl_escape_path(&key_path);
    let pub_esc = kdl_escape_path(&pub_key);
    let root_esc = kdl_escape_path(&root_spaces);
    // `sandbox.socket-tree` requires a leading `/` and forbids backslashes (`sandbox_tree_rejection`),
    // so use the temp socket dir on Unix and a clean POSIX path with an internal space on Windows.
    #[cfg(unix)]
    let socket_tree_kdl = kdl_escape_path(&sock_dir);
    #[cfg(not(unix))]
    let socket_tree_kdl = "/run/php pools".to_owned();

    // File-backed config with internal spaces, relative root/storage, padded index basename,
    // and a clean warning (`min-version "1.2"` -> W002) to exercise `--strict` & `--allow-warning`.
    let clean_cfg = conf_dir.join("clean.kdl");
    let clean_kdl = format!(
        "server {{\n\
             listen \":443\"\n\
             tls {{\n\
                 min-version \"1.2\"\n\
                 cert \"{cert_esc}\"\n\
                 key \"{key_esc}\"\n\
             }}\n\
             sandbox {{\n\
                 socket-tree \"{socket_tree_kdl}\"\n\
             }}\n\
         }}\n\
         site \"clean.example\" {{\n\
             root \"{root_esc}\"\n\
             index \" index.html\" \"index.html\"\n\
         }}\n\
         site \"rel.example\" {{\n\
             root \"public\"\n\
             ai-publish {{\n\
                 storage \"releases\"\n\
                 require-signature \"ed25519:{pub_esc}\"\n\
             }}\n\
         }}\n"
    );
    fs::write(&clean_cfg, &clean_kdl)?;

    // Absolute stdin config (no relative dirs).
    let stdin_kdl = format!(
        "server {{\n\
             listen \":443\"\n\
             tls {{ cert \"{cert_esc}\"; key \"{key_esc}\" }}\n\
         }}\n\
         site \"stdin.example\" {{\n\
             root \"{root_esc}\"\n\
             index \" index.html\"\n\
         }}\n"
    );

    #[cfg(unix)]
    let link_cfg = {
        let p = link_dir.join("clean-link.kdl");
        std::os::unix::fs::symlink(&clean_cfg, &p)?;
        p
    };

    let clean_cfg_str = clean_cfg.to_str().ok_or("non-utf8 cfg")?;
    let acme_str = acme_dir.to_str().ok_or("non-utf8 acme")?;

    #[cfg(unix)]
    let link_cfg_str = link_cfg.to_str().ok_or("non-utf8 link cfg")?;
    #[cfg(unix)]
    let unix_cases: [CliCase<'_>; 1] = [(
        "check_symlink_dump",
        vec!["check", "--dump-normalized", link_cfg_str],
        None,
    )];
    #[cfg(not(unix))]
    let unix_cases: [CliCase<'_>; 0] = [];

    let invocations: Vec<CliCase<'_>> = [
        ("check", vec!["check", clean_cfg_str], None),
        (
            "check_strict",
            vec!["check", "--strict", clean_cfg_str],
            None,
        ),
        (
            "check_allow_w002",
            vec![
                "check",
                "--strict",
                "--allow-warning",
                "W002",
                clean_cfg_str,
            ],
            None,
        ),
        (
            "check_json",
            vec!["check", "--format", "json", clean_cfg_str],
            None,
        ),
        (
            "check_dump_norm",
            vec!["check", "--dump-normalized", clean_cfg_str],
            None,
        ),
        (
            "check_fs",
            vec!["check", "--fs", "--acme-dir", acme_str, clean_cfg_str],
            None,
        ),
        (
            "check_fs_json",
            vec![
                "check",
                "--fs",
                "--strict",
                "--allow-warning",
                "W002",
                "--format",
                "json",
                "--acme-dir",
                acme_str,
                clean_cfg_str,
            ],
            None,
        ),
        (
            "check_fs_trusted_paths",
            vec![
                "check",
                "--fs",
                "--trusted-paths",
                "--acme-dir",
                acme_str,
                clean_cfg_str,
            ],
            None,
        ),
        (
            "check_fs_trusted_paths_json",
            vec![
                "check",
                "--fs",
                "--trusted-paths",
                "--format",
                "json",
                "--acme-dir",
                acme_str,
                clean_cfg_str,
            ],
            None,
        ),
        (
            "check_writable_set",
            vec![
                "check",
                "--fs",
                "--writable-set",
                "--acme-dir",
                acme_str,
                clean_cfg_str,
            ],
            None,
        ),
        (
            "check_stdin_json",
            vec!["check", "--format", "json", "--dump-normalized", "-"],
            Some(stdin_kdl.as_bytes()),
        ),
        (
            "service_generate_systemd",
            vec![
                "service",
                "generate",
                "--target",
                "systemd",
                "--config",
                clean_cfg_str,
                "--acme-dir",
                acme_str,
            ],
            None,
        ),
    ]
    .into_iter()
    .chain(unix_cases)
    .collect();

    let canon_conf_dir = fs::canonicalize(&conf_dir)?;
    let expected_conf_base = PathBuf::from(strip_windows_verbatim_prefix(&canon_conf_dir));
    let expected_rel_pub = expected_conf_base
        .join("public")
        .to_string_lossy()
        .into_owned();
    let expected_rel_store = expected_conf_base
        .join("releases")
        .to_string_lossy()
        .into_owned();
    let expected_root_spaces = root_spaces.to_string_lossy().into_owned();

    let baseline = baseline_bin();
    let mut dump_norm_json: Option<serde_json::Value> = None;
    let mut fs_json_has_w035: Option<bool> = None;
    for (name, args, stdin_data) in &invocations {
        let (code, stdout, stderr) = run_bin(&bin, base, args, *stdin_data)?;

        // Always assert clean semantic invariants for every invocation (no wildcard fallthrough;
        // must pass on BOTH 441a58d and the 0.1.8 branch without assuming a Landlock-capable host).
        match *name {
            "check" | "check_allow_w002" => {
                assert_eq!(
                    code,
                    Some(0),
                    "case '{name}' failed unexpectedly: stderr={}",
                    String::from_utf8_lossy(&stderr)
                );
                let out_text = String::from_utf8_lossy(&stdout);
                assert!(
                    out_text.contains("OK:") && out_text.contains("2 site(s)"),
                    "case '{name}' stdout must contain OK summary for 2 sites: {out_text}"
                );
                assert!(
                    String::from_utf8_lossy(&stderr).contains("W002"),
                    "case '{name}' stderr must mention W002: {}",
                    String::from_utf8_lossy(&stderr)
                );
            }
            "check_dump_norm" | "check_symlink_dump" => {
                assert_eq!(
                    code,
                    Some(0),
                    "case '{name}' failed unexpectedly: stderr={}",
                    String::from_utf8_lossy(&stderr)
                );
                let out_text = String::from_utf8_lossy(&stdout);
                assert!(
                    out_text.contains("OK:") && out_text.contains("2 site(s)"),
                    "case '{name}' stdout must contain OK summary: {out_text}"
                );
                let json_start = out_text
                    .find('{')
                    .ok_or_else(|| format!("case '{name}' missing normalized JSON: {out_text}"))?;
                let cfg_val: serde_json::Value = serde_json::from_str(&out_text[json_start..])?;
                assert_eq!(
                    cfg_val
                        .get("sites")
                        .and_then(serde_json::Value::as_array)
                        .map(Vec::len),
                    Some(2),
                    "case '{name}' must dump 2 sites: {cfg_val}"
                );
                assert_eq!(
                    cfg_val
                        .pointer("/sites/0/root")
                        .and_then(serde_json::Value::as_str),
                    Some(expected_root_spaces.as_str()),
                    "case '{name}' must preserve internal-space site[0].root: {cfg_val}"
                );
                assert_eq!(
                    cfg_val.pointer("/sites/0/index"),
                    Some(&serde_json::json!([" index.html", "index.html"])),
                    "case '{name}' must preserve padded site[0].index: {cfg_val}"
                );
                assert_eq!(
                    cfg_val
                        .pointer("/sites/1/root")
                        .and_then(serde_json::Value::as_str),
                    Some(expected_rel_pub.as_str()),
                    "case '{name}' must resolve relative site[1].root against canonical config dir: {cfg_val}"
                );
                assert_eq!(
                    cfg_val
                        .pointer("/sites/1/ai_publish/storage")
                        .and_then(serde_json::Value::as_str),
                    Some(expected_rel_store.as_str()),
                    "case '{name}' must resolve relative site[1].ai_publish.storage against canonical config dir: {cfg_val}"
                );
                if *name == "check_dump_norm" {
                    dump_norm_json = Some(cfg_val);
                } else {
                    assert_eq!(
                        Some(&cfg_val),
                        dump_norm_json.as_ref(),
                        "symlinked config dump must match real config dump"
                    );
                }
            }
            "service_generate_systemd" => {
                assert_eq!(
                    code,
                    Some(0),
                    "case '{name}' failed unexpectedly: stderr={}",
                    String::from_utf8_lossy(&stderr)
                );
                let unit = String::from_utf8_lossy(&stdout);
                for required in [
                    "[Unit]",
                    "[Service]",
                    "ExecStart=",
                    "clean.kdl",
                    "acme state",
                    "TimeoutStopSec=45",
                    "ProtectHome=",
                    "ReadWritePaths=",
                ] {
                    assert!(
                        unit.contains(required),
                        "service_generate_systemd missing '{required}' in unit:\n{unit}"
                    );
                }
            }
            "check_strict" => {
                // W002 causes --strict to fail with exit 1.
                assert_eq!(code, Some(1), "case '{name}' must fail on W002");
                assert!(
                    String::from_utf8_lossy(&stderr).contains("W002"),
                    "case '{name}' stderr must mention W002: {}",
                    String::from_utf8_lossy(&stderr)
                );
            }
            "check_json" => {
                assert_eq!(code, Some(0));
                let val: serde_json::Value = serde_json::from_slice(&stdout)?;
                assert_eq!(
                    val.get("valid").and_then(serde_json::Value::as_bool),
                    Some(true)
                );
                assert_eq!(
                    val.get("errors")
                        .and_then(serde_json::Value::as_array)
                        .map(Vec::len),
                    Some(0)
                );
                assert_eq!(
                    val.pointer("/warnings/0/code")
                        .and_then(serde_json::Value::as_str),
                    Some("W002")
                );
            }
            "check_stdin_json" => {
                assert_eq!(code, Some(0));
                let val: serde_json::Value = serde_json::from_slice(&stdout)?;
                assert_eq!(
                    val.get("valid").and_then(serde_json::Value::as_bool),
                    Some(true)
                );
                assert_eq!(
                    val.get("errors")
                        .and_then(serde_json::Value::as_array)
                        .map(Vec::len),
                    Some(0)
                );
                assert_eq!(
                    val.pointer("/config/sites/0/root")
                        .and_then(serde_json::Value::as_str),
                    Some(expected_root_spaces.as_str()),
                    "check_stdin_json must include normalized site[0].root: {val}"
                );
                assert_eq!(
                    val.pointer("/config/sites/0/index"),
                    Some(&serde_json::json!([" index.html"])),
                    "check_stdin_json must preserve padded index basename: {val}"
                );
            }
            "check_fs" => {
                assert_eq!(
                    code,
                    Some(0),
                    "case '{name}' failed unexpectedly: stdout={}, stderr={}",
                    String::from_utf8_lossy(&stdout),
                    String::from_utf8_lossy(&stderr)
                );
                let out_text = String::from_utf8_lossy(&stdout);
                assert!(
                    out_text.contains("OK:") && out_text.contains("2 site(s)"),
                    "case '{name}' stdout must contain OK summary for 2 sites: {out_text}"
                );
            }
            "check_fs_trusted_paths" => {
                assert_eq!(
                    code,
                    Some(0),
                    "case '{name}' failed unexpectedly: stdout={}, stderr={}",
                    String::from_utf8_lossy(&stdout),
                    String::from_utf8_lossy(&stderr)
                );
                let out_text = String::from_utf8_lossy(&stdout);
                assert!(
                    out_text.contains("OK:") && out_text.contains("2 site(s)"),
                    "case '{name}' stdout must contain OK summary for 2 sites: {out_text}"
                );
                #[cfg(target_os = "linux")]
                assert!(
                    out_text.contains("note: trusted-paths:")
                        && out_text.contains("note: trusted-paths (narrowed):"),
                    "case '{name}' on Linux must emit trusted-paths notes: {out_text}"
                );
                #[cfg(not(target_os = "linux"))]
                assert!(
                    out_text
                        .contains("note: --trusted-paths is Linux-only; no paths were verified"),
                    "case '{name}' on non-Linux must emit Linux-only trusted-paths note: {out_text}"
                );
            }
            "check_fs_json" => {
                let val: serde_json::Value = serde_json::from_slice(&stdout)?;
                assert_eq!(
                    val.get("errors")
                        .and_then(serde_json::Value::as_array)
                        .map(Vec::len),
                    Some(0),
                    "case '{name}' must report zero errors: {val}"
                );
                let warnings = val
                    .get("warnings")
                    .and_then(serde_json::Value::as_array)
                    .ok_or("check_fs_json missing warnings array")?;
                let codes: Vec<&str> = warnings
                    .iter()
                    .filter_map(|w| w.get("code").and_then(serde_json::Value::as_str))
                    .collect();
                assert!(
                    codes.contains(&"W002"),
                    "case '{name}' must retain W002 warning: {val}"
                );
                let has_w035 = codes.contains(&"W035");
                fs_json_has_w035 = Some(has_w035);
                assert!(
                    codes
                        .iter()
                        .all(|&c| c == "W002" || (cfg!(target_os = "linux") && c == "W035")),
                    "case '{name}' had unexpected warnings {codes:?}: {val}"
                );
                // Do not assume a Landlock-capable Linux host: when the sandbox probe emits W035,
                // `--strict --allow-warning W002` rejects with exit 1 and valid=false on BOTH 441a58d
                // and the branch; otherwise it exits 0 with valid=true.
                if cfg!(target_os = "linux") && has_w035 {
                    assert_eq!(
                        code,
                        Some(1),
                        "case '{name}' with W035 under --strict must exit 1: {val}"
                    );
                    assert_eq!(
                        val.get("valid").and_then(serde_json::Value::as_bool),
                        Some(false),
                        "case '{name}' with W035 under --strict must report valid=false: {val}"
                    );
                } else {
                    assert_eq!(
                        code,
                        Some(0),
                        "case '{name}' failed unexpectedly: stdout={}, stderr={}",
                        String::from_utf8_lossy(&stdout),
                        String::from_utf8_lossy(&stderr)
                    );
                    assert_eq!(
                        val.get("valid").and_then(serde_json::Value::as_bool),
                        Some(true),
                        "case '{name}' must report valid=true: {val}"
                    );
                }
            }
            "check_fs_trusted_paths_json" => {
                assert_eq!(
                    code,
                    Some(0),
                    "case '{name}' failed unexpectedly: stdout={}, stderr={}",
                    String::from_utf8_lossy(&stdout),
                    String::from_utf8_lossy(&stderr)
                );
                let val: serde_json::Value = serde_json::from_slice(&stdout)?;
                assert_eq!(
                    val.get("valid").and_then(serde_json::Value::as_bool),
                    Some(true),
                    "case '{name}' must report valid=true: {val}"
                );
                assert_eq!(
                    val.get("errors")
                        .and_then(serde_json::Value::as_array)
                        .map(Vec::len),
                    Some(0),
                    "case '{name}' must report zero errors: {val}"
                );
                let warnings = val
                    .get("warnings")
                    .and_then(serde_json::Value::as_array)
                    .ok_or("check_fs_trusted_paths_json missing warnings array")?;
                let codes: Vec<&str> = warnings
                    .iter()
                    .filter_map(|w| w.get("code").and_then(serde_json::Value::as_str))
                    .collect();
                assert!(
                    codes.contains(&"W002"),
                    "case '{name}' must retain W002 warning: {val}"
                );
                assert_eq!(
                    codes.contains(&"W035"),
                    fs_json_has_w035.unwrap_or(false),
                    "case '{name}' W035 presence must match check_fs_json on the same host: {val}"
                );
                let notes = val
                    .get("notes")
                    .and_then(serde_json::Value::as_array)
                    .ok_or("check_fs_trusted_paths_json missing notes array")?;
                let note_strs: Vec<&str> =
                    notes.iter().filter_map(serde_json::Value::as_str).collect();
                #[cfg(target_os = "linux")]
                assert!(
                    note_strs.iter().any(|n| n.starts_with("trusted-paths:"))
                        && note_strs
                            .iter()
                            .any(|n| n.starts_with("trusted-paths (narrowed):")),
                    "case '{name}' on Linux must include trusted-paths notes: {note_strs:?}"
                );
                #[cfg(not(target_os = "linux"))]
                assert!(
                    note_strs.contains(&"--trusted-paths is Linux-only; no paths were verified"),
                    "case '{name}' on non-Linux must include Linux-only trusted-paths note: {note_strs:?}"
                );
            }
            "check_writable_set" => {
                assert_eq!(
                    code,
                    Some(0),
                    "case '{name}' failed unexpectedly: stderr={}",
                    String::from_utf8_lossy(&stderr)
                );
                let ws_text = String::from_utf8_lossy(&stdout);
                #[cfg(target_os = "linux")]
                if fs_json_has_w035 == Some(false) {
                    assert!(
                        ws_text.contains("releases") && ws_text.contains("acme state"),
                        "writable-set on Landlock-capable Linux must list publish store and acme state dir: {ws_text}"
                    );
                } else {
                    assert!(
                        ws_text.trim() == "landlock unavailable"
                            || (ws_text.starts_with("landlock partial abi=")
                                && ws_text.contains("releases")
                                && ws_text.contains("acme state")),
                        "writable-set on Linux with W035 must report landlock unavailable or partial ABI grants: {ws_text}"
                    );
                }
                #[cfg(not(target_os = "linux"))]
                assert_eq!(
                    ws_text.as_ref(),
                    "landlock unavailable\n",
                    "writable-set on non-Linux must report landlock unavailable"
                );
            }
            other => {
                return Err(format!("unhandled CLI parity case '{other}'").into());
            }
        }

        // If MIRASERVE_BASELINE_BIN is provided (e.g. a 441a58d or bef6865 binary), assert exact
        // byte-for-byte identity of exit code, stdout, and stderr for every flag-off case and
        // non-Linux flag-on case; on Linux for the two `--trusted-paths` cases, allow ONLY the
        // exact narrowed-note update and the single `site[1].ai-publish.storage` W034 delta.
        if let Some(base_bin) = &baseline {
            let (b_code, b_stdout, b_stderr) = run_bin(base_bin, base, args, *stdin_data)?;
            assert_eq!(
                code, b_code,
                "exit status mismatch vs baseline for case '{name}'"
            );
            #[cfg(target_os = "linux")]
            let handled_linux_tp = matches!(
                *name,
                "check_fs_trusted_paths" | "check_fs_trusted_paths_json"
            );
            #[cfg(not(target_os = "linux"))]
            let handled_linux_tp = false;

            if handled_linux_tp {
                #[cfg(target_os = "linux")]
                {
                    const OLD_NARROWED: &str = "trusted-paths (narrowed): does not yet inspect config file, read-tree, site/route roots, owner-dir, TLS certs/keys/CAs, keyd-auth-secret-file, acme-webroot, basic-auth, bot-auth, ai-publish storage and keys, error-pages, upstream-tls, mcp-gateway, wasm-plugin, or non-rotating log paths";
                    const NEW_NARROWED: &str = "trusted-paths (narrowed): does not yet inspect config file, read-tree, site/route roots, owner-dir, TLS certs/keys/CAs, keyd-auth-secret-file, acme-webroot, basic-auth, bot-auth, ai-publish keys, error-pages, upstream-tls, mcp-gateway, wasm-plugin, or non-rotating log paths";
                    const HELP_GEN: &str = "keep every ancestor (and exclusive state directory) owned by root or the service account, not group/other-writable, on an ordinary local POSIX filesystem; use absolute paths";

                    let sock_msg_prefix =
                        format!("server.sandbox socket-tree root '{}': ", sock_dir.display());
                    let storage_node = "storage \"releases\"";
                    let storage_offset = clean_kdl
                        .find(storage_node)
                        .ok_or("missing storage node in clean_kdl")?;
                    let storage_line = clean_kdl
                        .get(..storage_offset)
                        .ok_or("invalid storage offset")?
                        .chars()
                        .filter(|&c| c == '\n')
                        .count()
                        + 1;
                    assert_eq!(storage_line, 19, "unexpected line for storage node");

                    if *name == "check_fs_trusted_paths_json" {
                        assert_eq!(stderr, b_stderr, "stderr byte mismatch on '{name}'");
                        let b_str = String::from_utf8(b_stdout.clone())?;
                        assert_eq!(
                            b_str.matches(OLD_NARROWED).count(),
                            1,
                            "baseline JSON must contain OLD_NARROWED exactly once"
                        );
                        let mut expected_str = b_str.replacen(OLD_NARROWED, NEW_NARROWED, 1);

                        // Read-only inspection of baseline JSON to learn whether the shared
                        // canonical ancestor prefix up to `base` (e.g. overlayfs `/` or a writable
                        // non-sticky ancestor) already triggered a `server.sandbox.socket-tree`
                        // W034 (`sock_dir` is canonicalized and 0750 owned by euid, so it walks
                        // the exact same ancestor chain as canonical relative `ai-publish.storage`
                        // and fails iff a shared ancestor fails — unlike ACME, which as root also
                        // flags unknown service uid).
                        let b_val: serde_json::Value = serde_json::from_str(&b_str)?;
                        let shared_anc_tail: Option<String> = b_val
                            .get("warnings")
                            .and_then(serde_json::Value::as_array)
                            .and_then(|ws| {
                                ws.iter().find(|w| {
                                    w.get("code").and_then(serde_json::Value::as_str)
                                        == Some("W034")
                                        && w.get("path").and_then(serde_json::Value::as_str)
                                            == Some("server.sandbox.socket-tree")
                                })
                            })
                            .and_then(|w| w.get("message").and_then(serde_json::Value::as_str))
                            .and_then(|m| m.strip_prefix(&sock_msg_prefix))
                            .map(str::to_owned);

                        if let Some(failure_tail) = shared_anc_tail {
                            let b_warn_count = b_val
                                .pointer("/summary/warnings")
                                .and_then(serde_json::Value::as_u64)
                                .ok_or("baseline JSON missing summary.warnings")?;
                            let old_count_line = format!("    \"warnings\": {b_warn_count},\n");
                            let new_count_line =
                                format!("    \"warnings\": {},\n", b_warn_count + 1);
                            assert_eq!(
                                expected_str.matches(&old_count_line).count(),
                                1,
                                "baseline JSON must contain summary.warnings line once"
                            );
                            expected_str =
                                expected_str.replacen(&old_count_line, &new_count_line, 1);

                            let expected_msg = format!(
                                "site 'rel.example' ai-publish storage '{expected_rel_store}': {failure_tail}"
                            );
                            let expected_record = format!(
                                ",\n    {{\n      \"code\": \"W034\",\n      \"severity\": \"warning\",\n      \"message\": {},\n      \"path\": \"site[1].ai-publish.storage\",\n      \"help\": {},\n      \"location\": {{\n        \"line\": {storage_line},\n        \"column\": 1,\n        \"offset\": {storage_offset},\n        \"length\": {}\n      }}\n    }}",
                                serde_json::to_string(&expected_msg)?,
                                serde_json::to_string(HELP_GEN)?,
                                storage_node.len(),
                            );
                            let close_anchor = "\n  ],\n  \"notes\": [";
                            assert_eq!(
                                expected_str.matches(close_anchor).count(),
                                1,
                                "baseline JSON must contain warnings closing anchor once"
                            );
                            expected_str = expected_str.replacen(
                                close_anchor,
                                &format!("{expected_record}{close_anchor}"),
                                1,
                            );
                        }

                        assert_eq!(
                            stdout.as_slice(),
                            expected_str.as_bytes(),
                            "JSON stdout byte mismatch vs baseline on '{name}'\n--- EXPECTED ---\n{expected_str}\n--- ACTUAL ---\n{}",
                            String::from_utf8_lossy(&stdout),
                        );
                    } else {
                        let b_out = String::from_utf8(b_stdout.clone())?;
                        let b_err = String::from_utf8(b_stderr.clone())?;
                        assert_eq!(
                            b_out.matches(OLD_NARROWED).count(),
                            1,
                            "baseline text stdout must contain OLD_NARROWED exactly once"
                        );
                        let mut expected_out = b_out.replacen(OLD_NARROWED, NEW_NARROWED, 1);
                        let mut expected_err = b_stderr.clone();

                        let sock_warn_prefix = format!("warning[W034]: {sock_msg_prefix}");
                        let shared_anc_tail = b_err
                            .lines()
                            .find_map(|line| line.strip_prefix(&sock_warn_prefix));

                        if let Some(failure_tail) = shared_anc_tail {
                            let expected_extra_err = format!(
                                "warning[W034]: site 'rel.example' ai-publish storage '{expected_rel_store}': {failure_tail}\n  help: {HELP_GEN}\n"
                            );
                            expected_err.extend_from_slice(expected_extra_err.as_bytes());

                            let first_line = expected_out
                                .lines()
                                .next()
                                .ok_or("baseline text stdout missing summary line")?;
                            let warn_suffix = " warning(s))";
                            let end_idx = first_line
                                .find(warn_suffix)
                                .ok_or("baseline summary line missing warning(s) count")?;
                            let start_idx = first_line
                                .get(..end_idx)
                                .and_then(|s| s.rfind(", "))
                                .ok_or(
                                "baseline summary line missing comma before warning count",
                            )? + 2;
                            let b_warn_count: usize = first_line
                                .get(start_idx..end_idx)
                                .ok_or("invalid warning count slice")?
                                .parse()?;
                            let old_token = format!(", {b_warn_count}{warn_suffix}");
                            let new_token = format!(", {}{warn_suffix}", b_warn_count + 1);
                            assert_eq!(
                                expected_out.matches(&old_token).count(),
                                1,
                                "baseline text stdout must contain summary warning count once"
                            );
                            expected_out = expected_out.replacen(&old_token, &new_token, 1);
                        }

                        assert_eq!(
                            stdout.as_slice(),
                            expected_out.as_bytes(),
                            "text stdout byte mismatch vs baseline on '{name}'\n--- EXPECTED ---\n{expected_out}\n--- ACTUAL ---\n{}",
                            String::from_utf8_lossy(&stdout),
                        );
                        assert_eq!(
                            stderr.as_slice(),
                            expected_err.as_slice(),
                            "text stderr byte mismatch vs baseline on '{name}'\n--- EXPECTED ---\n{}\n--- ACTUAL ---\n{}",
                            String::from_utf8_lossy(&expected_err),
                            String::from_utf8_lossy(&stderr),
                        );
                    }
                }
            } else {
                assert_eq!(
                    stdout,
                    b_stdout,
                    "stdout byte mismatch vs baseline for case '{name}'\n--- BASELINE ---\n{}\n--- BRANCH ---\n{}",
                    String::from_utf8_lossy(&b_stdout),
                    String::from_utf8_lossy(&stdout),
                );
                assert_eq!(
                    stderr,
                    b_stderr,
                    "stderr byte mismatch vs baseline for case '{name}'\n--- BASELINE ---\n{}\n--- BRANCH ---\n{}",
                    String::from_utf8_lossy(&b_stderr),
                    String::from_utf8_lossy(&stderr),
                );
            }
        }
    }

    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn security_rejected_padded_publish_and_root_siblings_neither_provisioned_granted_or_selected()
-> TestResult {
    let bin = current_bin();
    let tmp = TempDir::new("sec-cli")?;
    let base = &tmp.path;

    let certs_dir = base.join("certs");
    let releases_dir = base.join("releases");
    let unpadded_store = releases_dir.join("app");
    #[cfg(unix)]
    let padded_store = releases_dir.join("app ");
    let unpadded_fresh = releases_dir.join("fresh");
    let padded_fresh = releases_dir.join("fresh "); // intentionally NOT created!
    let unpadded_root = base.join("web");
    let padded_root = base.join("web ");
    let conf_dir = base.join("conf");

    for d in [
        &certs_dir,
        &unpadded_store,
        &unpadded_fresh,
        &unpadded_root,
        &conf_dir,
    ] {
        fs::create_dir_all(d)?;
        set_mode(d, 0o750)?;
    }
    #[cfg(unix)]
    for d in [&padded_store, &padded_root] {
        fs::create_dir_all(d)?;
        set_mode(d, 0o750)?;
    }

    // Distinct harmless sentinel data in padded and unpadded siblings.
    fs::write(
        unpadded_store.join("sentinel.txt"),
        b"UNPADDED_STORE_SENTINEL",
    )?;
    fs::write(
        unpadded_fresh.join("sentinel.txt"),
        b"UNPADDED_FRESH_SENTINEL",
    )?;
    fs::write(unpadded_root.join("index.html"), b"UNPADDED_ROOT_SENTINEL")?;
    #[cfg(unix)]
    {
        fs::write(padded_store.join("sentinel.txt"), b"PADDED_STORE_SENTINEL")?;
        fs::write(padded_root.join("index.html"), b"PADDED_ROOT_SENTINEL")?;
    }

    let cert_path = certs_dir.join("srv.crt");
    let key_path = certs_dir.join("srv.key");
    let (cert_code, _, cert_err) = run_bin(
        &bin,
        base,
        &[
            "cert",
            "generate-dev",
            "--hosts",
            "pub.example,web.example",
            "--cert",
            cert_path.to_str().ok_or("non-utf8 cert")?,
            "--key",
            key_path.to_str().ok_or("non-utf8 key")?,
        ],
        None,
    )?;
    assert_eq!(
        cert_code,
        Some(0),
        "cert generate-dev failed: {}",
        String::from_utf8_lossy(&cert_err)
    );
    let pub_key = certs_dir.join("deploy.pub");
    fs::write(&pub_key, b"0123456789abcdef0123456789abcdef\n")?;

    let cert_esc = kdl_escape_path(&cert_path);
    let key_esc = kdl_escape_path(&key_path);
    let pub_esc = kdl_escape_path(&pub_key);
    let padded_fresh_esc = kdl_escape_path(&padded_fresh);
    let padded_root_esc = kdl_escape_path(&padded_root);

    // Candidate 1: trailing space on ai-publish.storage pointing at non-existent `fresh `
    // beside existing `fresh`.
    let cand_fresh = conf_dir.join("cand-fresh.kdl");
    fs::write(
        &cand_fresh,
        format!(
            "server {{\n\
                 listen \"127.0.0.1:18443\" protocols=\"h1\"\n\
                 tls {{ cert \"{cert_esc}\"; key \"{key_esc}\" }}\n\
             }}\n\
             site \"pub.example\" {{\n\
                 ai-publish {{\n\
                     storage \"{padded_fresh_esc}\"\n\
                     require-signature \"ed25519:{pub_esc}\"\n\
                 }}\n\
             }}\n"
        ),
    )?;
    let cand_fresh_str = cand_fresh.to_str().ok_or("non-utf8 path")?;

    // 1. `check --format json`: exact E202 code, semantic path, message, help, location, valid=false.
    let (code, stdout, _) = run_bin(
        &bin,
        base,
        &["check", "--format", "json", cand_fresh_str],
        None,
    )?;
    assert_eq!(code, Some(1), "padded storage must exit 1");
    let json: serde_json::Value = serde_json::from_slice(&stdout)?;
    assert_eq!(
        json.get("valid").and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        json.get("errors")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(1)
    );
    assert_eq!(
        json.pointer("/errors/0/code")
            .and_then(serde_json::Value::as_str),
        Some("E202")
    );
    assert_eq!(
        json.pointer("/errors/0/path")
            .and_then(serde_json::Value::as_str),
        Some("site[0].ai-publish.storage")
    );
    assert_eq!(
        json.pointer("/errors/0/message")
            .and_then(serde_json::Value::as_str),
        Some("ai-publish 'storage' path on site 'pub.example' ends with whitespace (U+0020)")
    );
    assert_eq!(
        json.pointer("/errors/0/help")
            .and_then(serde_json::Value::as_str),
        Some(EXPECTED_HELP)
    );
    assert_eq!(
        json.pointer("/errors/0/location/line")
            .and_then(serde_json::Value::as_u64),
        Some(7)
    );

    // 2. `check --fs --writable-set`: nonzero exit AND strictly EMPTY stdout!
    let (ws_code, ws_stdout, ws_stderr) = run_bin(
        &bin,
        base,
        &["check", "--fs", "--writable-set", cand_fresh_str],
        None,
    )?;
    assert_eq!(
        ws_code,
        Some(1),
        "writable-set must exit 1 on padded storage"
    );
    assert!(
        ws_stdout.is_empty(),
        "writable-set stdout MUST be empty on rejected config, got: {}",
        String::from_utf8_lossy(&ws_stdout)
    );
    let ws_err_text = String::from_utf8_lossy(&ws_stderr);
    assert!(
        ws_err_text.contains("E202")
            && ws_err_text.contains(
                "ai-publish 'storage' path on site 'pub.example' ends with whitespace (U+0020)"
            ),
        "writable-set stderr must report E202: {ws_err_text}"
    );

    // 3. `miraserve reload --dry-run --config <cand> --format json`: refused!
    let (rld_code, rld_stdout, _) = run_bin(
        &bin,
        base,
        &[
            "reload",
            "--dry-run",
            "--config",
            cand_fresh_str,
            "--format",
            "json",
        ],
        None,
    )?;
    assert_eq!(rld_code, Some(1), "reload --dry-run must exit 1");
    let rld_json: serde_json::Value = serde_json::from_slice(&rld_stdout)?;
    assert_eq!(
        rld_json.get("outcome").and_then(serde_json::Value::as_str),
        Some("dry_run_refused")
    );
    let rld_errors = rld_json
        .get("errors")
        .and_then(serde_json::Value::as_array)
        .ok_or("expected reload errors array")?;
    assert!(
        rld_errors
            .iter()
            .filter_map(serde_json::Value::as_str)
            .any(|s| s.contains(
                "[E202] ai-publish 'storage' path on site 'pub.example' ends with whitespace (U+0020)"
            )),
        "expected E202 in reload preflight errors, got: {rld_json}"
    );

    // 4. `miraserve run <cand>`: fails immediately at config load (bounded timeout so a
    //    regression that starts serving fails fast); NEVER creates `fresh `!
    let (run_code, _, run_stderr) = run_bin_with_timeout(
        &bin,
        base,
        &["run", "--no-sandbox", cand_fresh_str],
        Duration::from_secs(15),
    )?;
    assert_eq!(run_code, Some(1), "run must refuse padded storage");
    let run_err_text = String::from_utf8_lossy(&run_stderr);
    assert!(
        run_err_text.contains(
            "[E202] ai-publish 'storage' path on site 'pub.example' ends with whitespace (U+0020)"
        ),
        "run stderr must report E202: {run_err_text}"
    );
    #[cfg(unix)]
    assert!(
        !padded_fresh.exists(),
        "rejected candidate MUST NOT provision padded sibling '{}'",
        padded_fresh.display()
    );
    assert_eq!(
        fs::read(unpadded_fresh.join("sentinel.txt"))?,
        b"UNPADDED_FRESH_SENTINEL"
    );
    assert!(
        !unpadded_fresh.join("releases").exists(),
        "rejected candidate MUST NOT touch unpadded sibling '{}'",
        unpadded_fresh.display()
    );

    // 5. Candidate 2: trailing space on site.root + narrow `app /.` resolved directory exception.
    let cand_root = conf_dir.join("cand-root.kdl");
    fs::write(
        &cand_root,
        format!(
            "server {{\n\
                 listen \":443\"\n\
                 tls {{ cert \"{cert_esc}\"; key \"{key_esc}\" }}\n\
             }}\n\
             site \"web.example\" {{\n\
                 root \"{padded_root_esc}\"\n\
             }}\n\
             site \"rel-dot.example\" {{\n\
                 ai-publish {{\n\
                     storage \"app /.\"\n\
                     require-signature \"ed25519:{pub_esc}\"\n\
                 }}\n\
             }}\n"
        ),
    )?;
    let cand_root_str = cand_root.to_str().ok_or("non-utf8 path")?;
    let (c2_code, c2_stdout, _) = run_bin(
        &bin,
        base,
        &["check", "--format", "json", cand_root_str],
        None,
    )?;
    assert_eq!(c2_code, Some(1));
    let c2_json: serde_json::Value = serde_json::from_slice(&c2_stdout)?;
    assert_eq!(
        c2_json.get("valid").and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        c2_json
            .get("errors")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(2)
    );
    assert_eq!(
        c2_json
            .pointer("/errors/0/code")
            .and_then(serde_json::Value::as_str),
        Some("E202")
    );
    assert_eq!(
        c2_json
            .pointer("/errors/0/path")
            .and_then(serde_json::Value::as_str),
        Some("site[0].root")
    );
    assert_eq!(
        c2_json
            .pointer("/errors/0/message")
            .and_then(serde_json::Value::as_str),
        Some("site 'root' path on site 'web.example' ends with whitespace (U+0020)")
    );
    assert_eq!(
        c2_json
            .pointer("/errors/0/help")
            .and_then(serde_json::Value::as_str),
        Some(EXPECTED_HELP)
    );
    assert_eq!(
        c2_json
            .pointer("/errors/1/code")
            .and_then(serde_json::Value::as_str),
        Some("E202")
    );
    assert_eq!(
        c2_json
            .pointer("/errors/1/path")
            .and_then(serde_json::Value::as_str),
        Some("site[1].ai-publish.storage")
    );
    assert_eq!(
        c2_json
            .pointer("/errors/1/message")
            .and_then(serde_json::Value::as_str),
        Some(
            "ai-publish 'storage' resolved directory name on site 'rel-dot.example' ends with whitespace (U+0020)"
        )
    );
    assert_eq!(
        c2_json
            .pointer("/errors/1/help")
            .and_then(serde_json::Value::as_str),
        Some(EXPECTED_RESOLVED_HELP)
    );

    // Writable-set on cand-root also exits 1 with empty stdout.
    let (root_ws_code, root_ws_stdout, _) = run_bin(
        &bin,
        base,
        &["check", "--fs", "--writable-set", cand_root_str],
        None,
    )?;
    assert_eq!(root_ws_code, Some(1));
    assert_eq!(root_ws_stdout, b"");

    // Sentinels in both unpadded and padded siblings remain completely untouched.
    assert_eq!(
        fs::read(unpadded_store.join("sentinel.txt"))?,
        b"UNPADDED_STORE_SENTINEL"
    );
    assert_eq!(
        fs::read(unpadded_root.join("index.html"))?,
        b"UNPADDED_ROOT_SENTINEL"
    );
    #[cfg(unix)]
    {
        assert_eq!(
            fs::read(padded_store.join("sentinel.txt"))?,
            b"PADDED_STORE_SENTINEL"
        );
        assert_eq!(
            fs::read(padded_root.join("index.html"))?,
            b"PADDED_ROOT_SENTINEL"
        );
        assert!(!conf_dir.join("app ").exists());
    }
    assert!(!conf_dir.join("app").exists());

    Ok(())
}

#[test]
fn parity_reload_dry_run_json_for_other_load_error_pins_empty_warnings() -> TestResult {
    // Baseline behaviour at 441a58d: on ANY load failure (here unknown directive E002),
    // `reload --dry-run --format json` prints an empty `warnings` array even when the loader
    // produced load-time warnings (W002, W015), while `check --format json` shows them.
    let bin = current_bin();
    let tmp = TempDir::new("reload-other-err")?;
    let cfg = tmp.path.join("other-err.kdl");
    fs::write(
        &cfg,
        r#"server {
    listen ":443"
    tls { min-version "1.2" }
    bogus "x"
}
site "shop.example" {
    root "/srv/www/shop"
}
"#,
    )?;
    let cfg_str = cfg.to_str().ok_or("non-utf8 path")?;

    let (rld_code, rld_stdout, rld_stderr) = run_bin(
        &bin,
        &tmp.path,
        &[
            "reload",
            "--dry-run",
            "--format",
            "json",
            "--config",
            cfg_str,
        ],
        None,
    )?;
    assert_eq!(rld_code, Some(1));
    assert_eq!(rld_stderr, b"");
    let rld_json: serde_json::Value = serde_json::from_slice(&rld_stdout)?;
    assert_eq!(rld_json.get("reloaded"), Some(&serde_json::Value::Null));
    assert_eq!(
        rld_json.get("outcome").and_then(serde_json::Value::as_str),
        Some("dry_run_refused")
    );
    assert_eq!(
        rld_json
            .get("quarantined_source")
            .and_then(serde_json::Value::as_str),
        Some("preflight")
    );
    assert_eq!(
        rld_json.get("dry_run").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        rld_json.get("warnings"),
        Some(&serde_json::json!([])),
        "reload load-error JSON prints empty warnings for every load error: {rld_json}"
    );
    assert_eq!(rld_json.get("quarantined"), Some(&serde_json::json!([])));
    assert_eq!(
        rld_json.get("restart_required"),
        Some(&serde_json::json!([]))
    );
    let expected_errors = vec![
        format!(
            "refusing to signal reload because '{}' is invalid: configuration validation failed with 1 error(s)",
            cfg.display()
        ),
        "[E002] unknown directive 'bogus' inside 'server' (line 4, col 5)".to_owned(),
    ];
    let actual_errors: Vec<&str> = rld_json
        .get("errors")
        .and_then(serde_json::Value::as_array)
        .ok_or("expected errors array")?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert_eq!(actual_errors, expected_errors);

    if let Some(base_bin) = baseline_bin() {
        let (base_code, base_stdout, base_stderr) = run_bin(
            &base_bin,
            &tmp.path,
            &[
                "reload",
                "--dry-run",
                "--format",
                "json",
                "--config",
                cfg_str,
            ],
            None,
        )?;
        assert_eq!(rld_code, base_code);
        assert_eq!(rld_stdout, base_stdout);
        assert_eq!(rld_stderr, base_stderr);
    }

    Ok(())
}

#[test]
fn security_reload_dry_run_json_for_padded_input_pins_errors_and_warnings() -> TestResult {
    // Pins the exact `reload --dry-run --format json` output for a padded input that also carries
    // load-time warnings (W002, W015). Under G2, each command shows warnings for a failed load
    // exactly as it does for any other load error: `reload --dry-run --format json` emits an
    // empty `warnings` array (pinned here so any later change is visible), while `check --format json`
    // emits the load-time warnings alongside `E202`.
    let bin = current_bin();
    let tmp = TempDir::new("reload-padded-json")?;
    let cfg = tmp.path.join("padded-w002.kdl");
    fs::write(
        &cfg,
        r#"server {
    listen ":443"
    tls { min-version "1.2" }
}
site "shop.example" {
    root "/srv/www/shop "
}
"#,
    )?;
    let cfg_str = cfg.to_str().ok_or("non-utf8 path")?;

    let (rld_code, rld_stdout, _) = run_bin(
        &bin,
        &tmp.path,
        &[
            "reload",
            "--dry-run",
            "--format",
            "json",
            "--config",
            cfg_str,
        ],
        None,
    )?;
    assert_eq!(rld_code, Some(1), "reload --dry-run must exit 1");
    let rld_json: serde_json::Value = serde_json::from_slice(&rld_stdout)?;
    assert_eq!(rld_json.get("reloaded"), Some(&serde_json::Value::Null));
    assert_eq!(
        rld_json.get("outcome").and_then(serde_json::Value::as_str),
        Some("dry_run_refused")
    );
    assert_eq!(
        rld_json
            .get("quarantined_source")
            .and_then(serde_json::Value::as_str),
        Some("preflight")
    );
    assert_eq!(
        rld_json.get("dry_run").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        rld_json.get("warnings"),
        Some(&serde_json::json!([])),
        "reload load-error branch emits empty warnings for every load error (pinned): {rld_json}"
    );
    assert_eq!(rld_json.get("quarantined"), Some(&serde_json::json!([])));
    assert_eq!(
        rld_json.get("restart_required"),
        Some(&serde_json::json!([]))
    );
    let expected_errors = vec![
        format!(
            "refusing to signal reload because '{}' is invalid: configuration validation failed with 1 error(s)",
            cfg.display()
        ),
        "[E202] site 'root' path on site 'shop.example' ends with whitespace (U+0020) (line 6, col 10)"
            .to_owned(),
    ];
    let actual_errors: Vec<&str> = rld_json
        .get("errors")
        .and_then(serde_json::Value::as_array)
        .ok_or("expected reload errors array")?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert_eq!(actual_errors, expected_errors);

    // Cross-check `check --format json` on the identical file: `E202` plus ordered load-time
    // warnings [W002, W015] are preserved in `ConfigError::Validation`.
    let (chk_code, chk_stdout, _) = run_bin(
        &bin,
        &tmp.path,
        &["check", "--format", "json", cfg_str],
        None,
    )?;
    assert_eq!(chk_code, Some(1));
    let chk_json: serde_json::Value = serde_json::from_slice(&chk_stdout)?;
    assert_eq!(
        chk_json.get("valid").and_then(serde_json::Value::as_bool),
        Some(false)
    );
    let chk_err_codes: Vec<&str> = chk_json
        .get("errors")
        .and_then(serde_json::Value::as_array)
        .ok_or("expected check errors array")?
        .iter()
        .filter_map(|e| e.get("code").and_then(serde_json::Value::as_str))
        .collect();
    assert_eq!(chk_err_codes, vec!["E202"]);
    let chk_warn_codes: Vec<&str> = chk_json
        .get("warnings")
        .and_then(serde_json::Value::as_array)
        .ok_or("expected check warnings array")?
        .iter()
        .filter_map(|w| w.get("code").and_then(serde_json::Value::as_str))
        .collect();
    assert_eq!(chk_warn_codes, vec!["W002", "W015"]);

    Ok(())
}

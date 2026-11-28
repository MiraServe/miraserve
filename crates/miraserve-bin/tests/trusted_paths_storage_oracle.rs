//! Stage 3 (0.1.8) oracle tests for `site[N].ai-publish.storage` under
//! `miraserve check --fs --trusted-paths` (`W034`).
//!
//! Every test always invokes Cargo's candidate binary (`env!("CARGO_BIN_EXE_miraserve")`); no
//! environment variable can redirect verification to another executable or switch into a recording
//! mode. On macOS and Linux, parity tests compare unconditionally byte-for-byte against checked-in
//! fixtures under `tests/fixtures/tp_storage_parity/<profile>/` recorded from `bef6865` (and
//! `v0.1.7` = commit `48ab7fa` / tag `9836e8a7` for Linux flag-on parity). On all platforms
//! (including Windows), platform-independent exact stream literals and non-Linux flag-on vs
//! flag-off invariance are also verified unconditionally.
//!
//! Environment-dependent Linux tests (local POSIX filesystem at `/` and `/tmp`, `overlayfs` at
//! `/`, root vs non-root) are marked with `#[ignore]` and assert their preconditions when selected
//! so the test harness reports them as ignored rather than silently skipping them.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

#[cfg(any(target_os = "macos", target_os = "linux"))]
use serde::Deserialize;

#[path = "../../miraserve-config/tests/common/mod.rs"]
mod kdl_test_util;

use kdl_test_util::kdl_escape_path;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type RunOutput = (Option<i32>, Vec<u8>, Vec<u8>);
type CliCase<'a> = (&'a str, Vec<&'a str>, Option<&'a [u8]>);

static TEMP_SEQ: AtomicU32 = AtomicU32::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(any(target_os = "macos", target_os = "linux"), derive(Deserialize))]
struct CommandSnapshot {
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(any(target_os = "macos", target_os = "linux"), derive(Deserialize))]
struct CaseFixture {
    commands: BTreeMap<String, CommandSnapshot>,
}

fn miraserve_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_miraserve"))
}

fn loc_parts_of_occurrence(
    kdl: &str,
    needle: &str,
    occurrence: usize,
) -> Result<(usize, usize, usize, usize), Box<dyn std::error::Error>> {
    let mut start = 0_usize;
    let mut found = None;
    for _ in 0..=occurrence {
        let rel = kdl
            .get(start..)
            .and_then(|s| s.find(needle))
            .ok_or_else(|| format!("needle '{needle}' occurrence {occurrence} not found"))?;
        let abs = start + rel;
        found = Some(abs);
        start = abs + needle.len();
    }
    let offset = found.ok_or("offset missing")?;
    let prefix = kdl.get(..offset).ok_or("invalid offset")?;
    let mut line = 1_usize;
    let mut column = 1_usize;
    for ch in prefix.chars() {
        if ch == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    Ok((line, column, offset, needle.len()))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn fixture_profile() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "macos"
    }
    #[cfg(target_os = "linux")]
    {
        if rustix::process::geteuid().is_root() {
            "linux-root"
        } else {
            "linux-nonroot"
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn fixture_dir(profile: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("tp_storage_parity")
        .join(profile)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn normalize_output(raw_text: &str, canon_base: &str, raw_base: &str) -> String {
    let mut text = raw_text.to_owned();
    if !canon_base.is_empty() && canon_base != raw_base {
        text = text.replace(canon_base, "<TMPDIR>");
    }
    if !raw_base.is_empty() {
        text = text.replace(raw_base, "<TMPDIR>");
    }
    text
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Creates a temporary directory. On Unix this uses a fixed 27-byte path
    /// (`/tmp/ms-tps-<c>-<8hex>-<4hex>`) so generated KDL source offsets and span lengths stay
    /// invariant against the committed Unix parity fixtures; on non-Unix it uses the platform
    /// temporary directory.
    fn new_fixed(tag: char) -> Result<Self, std::io::Error> {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed) & 0xFFFF;
        #[cfg(unix)]
        let path = PathBuf::from(format!(
            "/tmp/ms-tps-{tag}-{:08x}-{seq:04x}",
            std::process::id(),
        ));
        #[cfg(not(unix))]
        let path = std::env::temp_dir()
            .join(format!("ms-tps-{tag}-{:08x}-{seq:04x}", std::process::id(),));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path)?;
        set_mode(&path, 0o750)?;
        Ok(Self { path })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(unix)]
fn set_mode(p: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(p, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_p: &Path, _mode: u32) -> std::io::Result<()> {
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

fn gen_dev_cert(
    bin: &Path,
    dir: &Path,
    hosts: &str,
) -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error>> {
    let cert = dir.join("server.crt");
    let key = dir.join("server.key");
    let (code, _, stderr) = run_bin(
        bin,
        dir,
        &[
            "cert",
            "generate-dev",
            "--hosts",
            hosts,
            "--cert",
            cert.to_str().ok_or("non-utf8 cert path")?,
            "--key",
            key.to_str().ok_or("non-utf8 key path")?,
        ],
        None,
    )?;
    if code != Some(0) {
        return Err(format!(
            "cert generate-dev failed: {}",
            String::from_utf8_lossy(&stderr)
        )
        .into());
    }
    set_mode(&cert, 0o640)?;
    set_mode(&key, 0o600)?;
    Ok((cert, key))
}

fn write_pubkey(dir: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let pub_key = dir.join("deploy.pub");
    fs::write(&pub_key, b"0123456789abcdef0123456789abcdef\n")?;
    set_mode(&pub_key, 0o640)?;
    Ok(pub_key)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn assert_fixture_byte_parity(
    actual: &CaseFixture,
    fixture_path: &Path,
    profile: &str,
) -> TestResult {
    let expected_raw = fs::read_to_string(fixture_path)
        .map_err(|err| format!("missing parity fixture '{}': {err}", fixture_path.display()))?;
    let expected: CaseFixture = serde_json::from_str(&expected_raw)?;
    assert_eq!(
        actual.commands.keys().collect::<Vec<_>>(),
        expected.commands.keys().collect::<Vec<_>>(),
        "command set mismatch for '{}' (profile={profile})",
        fixture_path.display()
    );
    for (mode_name, exp_snap) in &expected.commands {
        let act_snap = actual
            .commands
            .get(mode_name)
            .ok_or_else(|| format!("missing mode '{mode_name}' in actual output"))?;
        assert_eq!(
            act_snap.exit_code, exp_snap.exit_code,
            "exit status mismatch for mode '{mode_name}' (profile={profile})"
        );
        assert_eq!(
            act_snap.stdout.as_bytes(),
            exp_snap.stdout.as_bytes(),
            "stdout byte mismatch for mode '{mode_name}' (profile={profile})\n--- EXPECTED ---\n{}\n--- ACTUAL ---\n{}",
            exp_snap.stdout,
            act_snap.stdout,
        );
        assert_eq!(
            act_snap.stderr.as_bytes(),
            exp_snap.stderr.as_bytes(),
            "stderr byte mismatch for mode '{mode_name}' (profile={profile})\n--- EXPECTED ---\n{}\n--- ACTUAL ---\n{}",
            exp_snap.stderr,
            act_snap.stderr,
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 1. Flag-off parity against checked-in bef6865 fixtures and exact literals
// ---------------------------------------------------------------------------

struct FlagOffLiteralInputs<'a> {
    cfg_s: &'a str,
    miss_s: &'a str,
    padded_s: &'a str,
    miss_kdl: &'a str,
    padded_kdl: &'a str,
    missing_parent_store: &'a Path,
    bad_store: &'a Path,
}

#[allow(clippy::too_many_lines)]
fn assert_flag_off_exact_literals(
    raw: &CaseFixture,
    inputs: &FlagOffLiteralInputs<'_>,
) -> TestResult {
    let expected_keys = [
        "check_fs",
        "check_fs_json",
        "check_fs_missing_parent",
        "check_fs_quiet",
        "check_fs_rejected_padded",
        "check_fs_strict",
        "check_fs_strict_allow_w002",
        "check_fs_writable_set",
        "check_json",
        "check_quiet",
        "check_stdin_json",
        "check_text",
        "reload_dry_run_rejected",
        "reload_dry_run_valid",
    ];
    assert_eq!(
        raw.commands.keys().map(String::as_str).collect::<Vec<_>>(),
        expected_keys,
        "flag-off command key set mismatch"
    );

    let get = |k: &str| -> Result<&CommandSnapshot, Box<dyn std::error::Error>> {
        raw.commands
            .get(k)
            .ok_or_else(|| format!("missing flag-off snapshot '{k}'").into())
    };

    let w002_json = |source: &str, strict: bool| -> Result<String, Box<dyn std::error::Error>> {
        let src_json = serde_json::to_string(source)?;
        Ok(format!(
            "{{\n  \"valid\": true,\n  \"strict\": {strict},\n  \"source\": {src_json},\n  \
             \"summary\": {{\n    \"listeners\": 1,\n    \"sites\": 1,\n    \"routes\": 0,\n    \
             \"tls_min_version\": \"1.2\",\n    \"pqc_hybrid\": true,\n    \"warnings\": 1,\n    \
             \"errors\": 0\n  }},\n  \"errors\": [],\n  \"warnings\": [\n    {{\n      \
             \"code\": \"W002\",\n      \"severity\": \"warning\",\n      \
             \"message\": \"global TLS min-version is downgraded to 1.2\",\n      \
             \"path\": \"server.tls.min-version\",\n      \
             \"help\": \"keep global min-version \\\"1.3\\\" and opt in per legacy site via 'tls {{ compat-tls-1-2 true }}'\",\n      \
             \"location\": {{\n        \"line\": 3,\n        \"column\": 7,\n        \
             \"offset\": 29,\n        \"length\": 17\n      }}\n    }}\n  ]\n}}\n"
        ))
    };

    for (mode, source, strict) in [
        ("check_json", inputs.cfg_s, false),
        ("check_fs_json", inputs.cfg_s, false),
        ("check_fs_strict_allow_w002", inputs.cfg_s, true),
        ("check_stdin_json", "<stdin>", false),
    ] {
        let snap = get(mode)?;
        assert_eq!(snap.exit_code, Some(0), "{mode} exit code");
        assert_eq!(snap.stderr, "", "{mode} stderr must be empty");
        assert_eq!(
            snap.stdout.as_bytes(),
            w002_json(source, strict)?.as_bytes(),
            "{mode} exact JSON literal mismatch"
        );
    }

    let miss_node = format!(
        "storage \"{}\"",
        kdl_escape_path(inputs.missing_parent_store)
    );
    let (m_line, m_col, m_off, m_len) = loc_parts_of_occurrence(inputs.miss_kdl, &miss_node, 0)?;
    assert_eq!((m_line, m_col), (8, 1));
    let miss_msg = format!(
        "site 'miss.example' ai-publish.storage directory '{}' does not exist and its parent is missing",
        inputs.missing_parent_store.display()
    );
    let expected_miss_json = format!(
        "{{\n  \"valid\": false,\n  \"strict\": false,\n  \"source\": {},\n  \"summary\": {{\n    \
         \"listeners\": 1,\n    \"sites\": 1,\n    \"routes\": 0,\n    \
         \"tls_min_version\": \"1.3\",\n    \"pqc_hybrid\": true,\n    \"warnings\": 0,\n    \
         \"errors\": 1\n  }},\n  \"errors\": [\n    {{\n      \"code\": \"E301\",\n      \
         \"severity\": \"error\",\n      \"message\": {},\n      \
         \"path\": \"site[0].ai-publish.storage\",\n      \"location\": {{\n        \
         \"line\": {m_line},\n        \"column\": {m_col},\n        \"offset\": {m_off},\n        \
         \"length\": {m_len}\n      }}\n    }}\n  ],\n  \"warnings\": []\n}}\n",
        serde_json::to_string(inputs.miss_s)?,
        serde_json::to_string(&miss_msg)?,
    );
    let miss_snap = get("check_fs_missing_parent")?;
    assert_eq!(miss_snap.exit_code, Some(1));
    assert_eq!(miss_snap.stderr, "");
    assert_eq!(
        miss_snap.stdout.as_bytes(),
        expected_miss_json.as_bytes(),
        "check_fs_missing_parent exact JSON literal mismatch"
    );

    let padded_quoted = format!("\"{} \"", kdl_escape_path(inputs.bad_store));
    let (p_line, p_col, p_off, p_len) =
        loc_parts_of_occurrence(inputs.padded_kdl, &padded_quoted, 0)?;
    assert_eq!((p_line, p_col), (7, 9));
    let expected_padded_json = format!(
        "{{\n  \"valid\": false,\n  \"strict\": false,\n  \"source\": {},\n  \"errors\": [\n    \
         {{\n      \"code\": \"E202\",\n      \"severity\": \"error\",\n      \
         \"message\": \"ai-publish 'storage' path on site 'pub.example' ends with whitespace (U+0020)\",\n      \
         \"path\": \"site[0].ai-publish.storage\",\n      \
         \"help\": \"verify which directory or file currently holds live data before editing the path; remove leading or trailing whitespace from the configured path\",\n      \
         \"location\": {{\n        \"line\": {p_line},\n        \"column\": {p_col},\n        \
         \"offset\": {p_off},\n        \"length\": {p_len}\n      }}\n    }}\n  ],\n  \
         \"warnings\": []\n}}\n",
        serde_json::to_string(inputs.padded_s)?,
    );
    let padded_snap = get("check_fs_rejected_padded")?;
    assert_eq!(padded_snap.exit_code, Some(1));
    assert_eq!(padded_snap.stderr, "");
    assert_eq!(
        padded_snap.stdout.as_bytes(),
        expected_padded_json.as_bytes(),
        "check_fs_rejected_padded exact JSON literal mismatch"
    );

    let expected_reload_valid = "{\n  \"reloaded\": null,\n  \"outcome\": \"dry_run_passed\",\n  \
         \"quarantined_source\": \"preflight\",\n  \"dry_run\": true,\n  \"warnings\": [\n    \
         {\n      \"code\": \"W002\",\n      \"path\": \"server.tls.min-version\",\n      \
         \"message\": \"global TLS min-version is downgraded to 1.2\"\n    }\n  ],\n  \
         \"quarantined\": [],\n  \"restart_required\": [],\n  \"errors\": []\n}\n";
    let reload_ok = get("reload_dry_run_valid")?;
    assert_eq!(reload_ok.exit_code, Some(0));
    assert_eq!(reload_ok.stderr, "");
    assert_eq!(
        reload_ok.stdout.as_bytes(),
        expected_reload_valid.as_bytes(),
        "reload_dry_run_valid exact JSON literal mismatch"
    );

    let reload_refuse_line = format!(
        "refusing to signal reload because '{}' is invalid: configuration validation failed with 1 error(s)",
        inputs.padded_s
    );
    let expected_reload_refused = format!(
        "{{\n  \"reloaded\": null,\n  \"outcome\": \"dry_run_refused\",\n  \
         \"quarantined_source\": \"preflight\",\n  \"dry_run\": true,\n  \"warnings\": [],\n  \
         \"quarantined\": [],\n  \"restart_required\": [],\n  \"errors\": [\n    {},\n    \
         \"[E202] ai-publish 'storage' path on site 'pub.example' ends with whitespace (U+0020) (line 7, col 9)\"\n  ]\n}}\n",
        serde_json::to_string(&reload_refuse_line)?,
    );
    let reload_bad = get("reload_dry_run_rejected")?;
    assert_eq!(reload_bad.exit_code, Some(1));
    assert_eq!(reload_bad.stderr, "");
    assert_eq!(
        reload_bad.stdout.as_bytes(),
        expected_reload_refused.as_bytes(),
        "reload_dry_run_rejected exact JSON literal mismatch"
    );

    let expected_ok_stdout = format!(
        "OK: '{}' is valid (1 listener(s), 1 site(s), 0 route(s), TLS >= 1.2, PQC: X25519MLKEM768 enabled, 1 warning(s))\n",
        inputs.cfg_s
    );
    let check_text = get("check_text")?;
    assert_eq!(check_text.exit_code, Some(0));
    assert_eq!(check_text.stdout, expected_ok_stdout);
    assert!(
        check_text.stderr.contains("miraserve::W002")
            && check_text
                .stderr
                .contains("global TLS min-version is downgraded to 1.2")
            && check_text
                .stderr
                .contains("help: keep global min-version \"1.3\"")
            && !check_text.stderr.contains("W034"),
        "unexpected check_text stderr:\n{}",
        check_text.stderr
    );

    let check_fs = get("check_fs")?;
    assert_eq!(check_fs.exit_code, Some(0));
    assert_eq!(check_fs.stdout, expected_ok_stdout);
    assert_eq!(check_fs.stderr, check_text.stderr);

    for q_mode in ["check_quiet", "check_fs_quiet"] {
        let q = get(q_mode)?;
        assert_eq!(q.exit_code, Some(0));
        assert_eq!(q.stdout, "");
        assert_eq!(q.stderr, check_text.stderr);
    }

    let strict = get("check_fs_strict")?;
    assert_eq!(strict.exit_code, Some(1));
    assert_eq!(strict.stdout, "");
    let expected_strict_stderr = format!(
        "{}error: configuration '{}' failed --strict check due to 1 security warning(s) not covered by --allow-warning\n",
        check_text.stderr, inputs.cfg_s
    );
    assert_eq!(strict.stderr, expected_strict_stderr);

    let expected_ws_stdout = if cfg!(target_os = "linux") {
        "landlock disabled\n"
    } else {
        "landlock unavailable\n"
    };
    let ws = get("check_fs_writable_set")?;
    assert_eq!(ws.exit_code, Some(0));
    assert_eq!(ws.stdout, expected_ws_stdout);
    assert_eq!(ws.stderr, check_text.stderr);

    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn flag_off_bef6865_parity() -> TestResult {
    let bin = miraserve_bin();
    let tmp = TempDir::new_fixed('f')?;
    let base = &tmp.path;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let (canon_base_s, raw_base_s) = (
        fs::canonicalize(base)?.to_string_lossy().into_owned(),
        base.to_string_lossy().into_owned(),
    );

    let certs = base.join("certs");
    let docroot = base.join("www");
    let bad_store = base.join("store_bad");
    let missing_parent_store = base.join("absent_parent").join("store");
    let acme = base.join("acme");
    for d in [&certs, &docroot, &bad_store, &acme] {
        fs::create_dir_all(d)?;
        set_mode(d, 0o750)?;
    }
    set_mode(&bad_store, 0o777)?;
    set_mode(&acme, 0o700)?;

    let (cert, key) = gen_dev_cert(&bin, &certs, "pub.example,miss.example")?;
    let pub_key = write_pubkey(&certs)?;

    // Config WITH a 0777 ai-publish.storage AND W002 (min-version 1.2) to exercise all flag-off modes.
    let cfg = base.join("pub.kdl");
    let cfg_text = format!(
        "server {{\n\
             listen \":443\"\n\
             tls {{ min-version \"1.2\"; cert \"{}\"; key \"{}\" }}\n\
         }}\n\
         site \"pub.example\" {{\n\
             root \"{}\"\n\
             ai-publish {{\n\
                 storage \"{}\"\n\
                 require-signature \"ed25519:{}\"\n\
             }}\n\
         }}\n",
        kdl_escape_path(&cert),
        kdl_escape_path(&key),
        kdl_escape_path(&docroot),
        kdl_escape_path(&bad_store),
        kdl_escape_path(&pub_key),
    );
    fs::write(&cfg, &cfg_text)?;

    // Config WITH missing parent of ai-publish.storage (triggers --fs error, still zero W034 when flag off).
    let miss_cfg = base.join("miss.kdl");
    let miss_kdl = format!(
        "server {{\n\
             listen \":443\"\n\
             tls {{ cert \"{}\"; key \"{}\" }}\n\
         }}\n\
         site \"miss.example\" {{\n\
             root \"{}\"\n\
             ai-publish {{\n\
                 storage \"{}\"\n\
                 require-signature \"ed25519:{}\"\n\
             }}\n\
         }}\n",
        kdl_escape_path(&cert),
        kdl_escape_path(&key),
        kdl_escape_path(&docroot),
        kdl_escape_path(&missing_parent_store),
        kdl_escape_path(&pub_key),
    );
    fs::write(&miss_cfg, &miss_kdl)?;

    // Rejected config (trailing space on ai-publish.storage -> E202).
    let padded_cfg = base.join("padded.kdl");
    let padded_kdl = format!(
        "server {{\n\
             listen \":443\"\n\
             tls {{ cert \"{}\"; key \"{}\" }}\n\
         }}\n\
         site \"pub.example\" {{\n\
             ai-publish {{\n\
                 storage \"{} \"\n\
                 require-signature \"ed25519:{}\"\n\
             }}\n\
         }}\n",
        kdl_escape_path(&cert),
        kdl_escape_path(&key),
        kdl_escape_path(&bad_store),
        kdl_escape_path(&pub_key),
    );
    fs::write(&padded_cfg, &padded_kdl)?;

    let cfg_s = cfg.to_str().ok_or("non-utf8 cfg")?;
    let miss_s = miss_cfg.to_str().ok_or("non-utf8 miss cfg")?;
    let padded_s = padded_cfg.to_str().ok_or("non-utf8 padded cfg")?;
    let acme_s = acme.to_str().ok_or("non-utf8 acme")?;

    // Pass `--no-sandbox` on `--fs` invocations so flag-off parity is invariant across Linux
    // kernels with different Landlock ABIs or refused Landlock queries (zero W035 drift), while
    // every ordinary `--fs` check still runs in full.
    let cases: [CliCase<'_>; 14] = [
        ("check_text", vec!["check", cfg_s], None),
        ("check_json", vec!["check", "--format", "json", cfg_s], None),
        ("check_quiet", vec!["check", "--quiet", cfg_s], None),
        (
            "check_fs",
            vec!["check", "--fs", "--no-sandbox", "--acme-dir", acme_s, cfg_s],
            None,
        ),
        (
            "check_fs_json",
            vec![
                "check",
                "--fs",
                "--no-sandbox",
                "--format",
                "json",
                "--acme-dir",
                acme_s,
                cfg_s,
            ],
            None,
        ),
        (
            "check_fs_strict",
            vec![
                "check",
                "--fs",
                "--no-sandbox",
                "--strict",
                "--acme-dir",
                acme_s,
                cfg_s,
            ],
            None,
        ),
        (
            "check_fs_strict_allow_w002",
            vec![
                "check",
                "--fs",
                "--no-sandbox",
                "--strict",
                "--allow-warning",
                "W002",
                "--format",
                "json",
                "--acme-dir",
                acme_s,
                cfg_s,
            ],
            None,
        ),
        (
            "check_fs_quiet",
            vec![
                "check",
                "--fs",
                "--no-sandbox",
                "--quiet",
                "--acme-dir",
                acme_s,
                cfg_s,
            ],
            None,
        ),
        (
            "check_fs_writable_set",
            vec![
                "check",
                "--fs",
                "--no-sandbox",
                "--writable-set",
                "--acme-dir",
                acme_s,
                cfg_s,
            ],
            None,
        ),
        (
            "check_stdin_json",
            vec!["check", "--format", "json", "-"],
            Some(cfg_text.as_bytes()),
        ),
        (
            "check_fs_missing_parent",
            vec!["check", "--fs", "--no-sandbox", "--format", "json", miss_s],
            None,
        ),
        (
            "check_fs_rejected_padded",
            vec![
                "check",
                "--fs",
                "--no-sandbox",
                "--format",
                "json",
                padded_s,
            ],
            None,
        ),
        (
            "reload_dry_run_valid",
            vec!["reload", "--dry-run", "--format", "json", "--config", cfg_s],
            None,
        ),
        (
            "reload_dry_run_rejected",
            vec![
                "reload",
                "--dry-run",
                "--format",
                "json",
                "--config",
                padded_s,
            ],
            None,
        ),
    ];

    let mut raw_commands = BTreeMap::new();
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let mut normalized_commands = BTreeMap::new();

    for (name, args, stdin_bytes) in &cases {
        let (code, stdout, stderr) = run_bin(&bin, base, args, *stdin_bytes)?;
        let stdout_s = String::from_utf8(stdout)?;
        let stderr_s = String::from_utf8(stderr)?;
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        normalized_commands.insert(
            (*name).to_owned(),
            CommandSnapshot {
                exit_code: code,
                stdout: normalize_output(&stdout_s, &canon_base_s, &raw_base_s),
                stderr: normalize_output(&stderr_s, &canon_base_s, &raw_base_s),
            },
        );
        raw_commands.insert(
            (*name).to_owned(),
            CommandSnapshot {
                exit_code: code,
                stdout: stdout_s,
                stderr: stderr_s,
            },
        );
    }

    let raw_fixture = CaseFixture {
        commands: raw_commands,
    };
    assert_flag_off_exact_literals(
        &raw_fixture,
        &FlagOffLiteralInputs {
            cfg_s,
            miss_s,
            padded_s,
            miss_kdl: &miss_kdl,
            padded_kdl: &padded_kdl,
            missing_parent_store: &missing_parent_store,
            bad_store: &bad_store,
        },
    )?;

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let profile = fixture_profile();
        let actual = CaseFixture {
            commands: normalized_commands,
        };
        let fixture_path = fixture_dir(profile).join("flag_off_bef6865.json");
        assert_fixture_byte_parity(&actual, &fixture_path, profile)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 2. Non-Linux flag-on with storage parity against literals, flag-off, and
//    checked-in bef6865 fixture
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "linux"))]
fn assert_non_linux_exact_literals(raw: &CaseFixture, cfg_s: &str) -> TestResult {
    const NOTE_TEXT: &str = "--trusted-paths is Linux-only; no paths were verified";
    const NOTE_LINE: &str = "note: --trusted-paths is Linux-only; no paths were verified\n";

    let expected_keys = [
        "check_fs_strict_tp",
        "check_fs_strict_tp_json",
        "check_fs_tp_quiet",
        "check_fs_tp_writable_set",
    ];
    assert_eq!(
        raw.commands.keys().map(String::as_str).collect::<Vec<_>>(),
        expected_keys,
        "non-Linux command key set mismatch"
    );

    let get = |k: &str| -> Result<&CommandSnapshot, Box<dyn std::error::Error>> {
        raw.commands
            .get(k)
            .ok_or_else(|| format!("missing non-Linux snapshot '{k}'").into())
    };

    let txt = get("check_fs_strict_tp")?;
    assert_eq!(txt.exit_code, Some(0));
    assert_eq!(txt.stderr, "");
    let expected_txt_stdout = format!(
        "OK: '{cfg_s}' is valid (1 listener(s), 1 site(s), 0 route(s), TLS >= 1.3, PQC: X25519MLKEM768 enabled, 0 warning(s))\n{NOTE_LINE}"
    );
    assert_eq!(
        txt.stdout.as_bytes(),
        expected_txt_stdout.as_bytes(),
        "non-Linux check_fs_strict_tp stdout mismatch"
    );

    let json_snap = get("check_fs_strict_tp_json")?;
    assert_eq!(json_snap.exit_code, Some(0));
    assert_eq!(json_snap.stderr, "");
    let expected_json_stdout = format!(
        "{{\n  \"valid\": true,\n  \"strict\": true,\n  \"source\": {},\n  \"summary\": {{\n    \
         \"listeners\": 1,\n    \"sites\": 1,\n    \"routes\": 0,\n    \
         \"tls_min_version\": \"1.3\",\n    \"pqc_hybrid\": true,\n    \"warnings\": 0,\n    \
         \"errors\": 0\n  }},\n  \"errors\": [],\n  \"warnings\": [],\n  \"notes\": [\n    \
         \"{NOTE_TEXT}\"\n  ]\n}}\n",
        serde_json::to_string(cfg_s)?,
    );
    assert_eq!(
        json_snap.stdout.as_bytes(),
        expected_json_stdout.as_bytes(),
        "non-Linux check_fs_strict_tp_json stdout mismatch"
    );

    let quiet = get("check_fs_tp_quiet")?;
    assert_eq!(quiet.exit_code, Some(0));
    assert_eq!(quiet.stdout, "");
    assert_eq!(quiet.stderr, NOTE_LINE);

    let ws = get("check_fs_tp_writable_set")?;
    assert_eq!(ws.exit_code, Some(0));
    assert_eq!(ws.stdout, "landlock unavailable\n");
    assert_eq!(ws.stderr, NOTE_LINE);

    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[test]
#[allow(clippy::too_many_lines)]
fn non_linux_trusted_paths_with_storage_unchanged() -> TestResult {
    const NOTE_LINE: &str = "note: --trusted-paths is Linux-only; no paths were verified\n";
    const NOTE_JSON_BLOCK: &str =
        ",\n  \"notes\": [\n    \"--trusted-paths is Linux-only; no paths were verified\"\n  ]";

    let bin = miraserve_bin();
    let tmp = TempDir::new_fixed('n')?;
    let base = &tmp.path;
    #[cfg(target_os = "macos")]
    let (canon_base_s, raw_base_s) = (
        fs::canonicalize(base)?.to_string_lossy().into_owned(),
        base.to_string_lossy().into_owned(),
    );

    let certs = base.join("certs");
    let docroot = base.join("www");
    let bad_store = base.join("store_bad");
    for d in [&certs, &docroot, &bad_store] {
        fs::create_dir_all(d)?;
        set_mode(d, 0o750)?;
    }
    set_mode(&bad_store, 0o777)?;
    let (cert, key) = gen_dev_cert(&bin, &certs, "pub.example")?;
    let pub_key = write_pubkey(&certs)?;

    let cfg = base.join("pub.kdl");
    fs::write(
        &cfg,
        format!(
            "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }} }}\n\
             site \"pub.example\" {{\n\
                 root \"{}\"\n\
                 ai-publish {{\n\
                     storage \"{}\"\n\
                     require-signature \"ed25519:{}\"\n\
                 }}\n\
             }}\n",
            kdl_escape_path(&cert),
            kdl_escape_path(&key),
            kdl_escape_path(&docroot),
            kdl_escape_path(&bad_store),
            kdl_escape_path(&pub_key),
        ),
    )?;
    let cfg_s = cfg.to_str().ok_or("non-utf8 cfg")?;

    let cases: [(&str, Vec<&str>, Vec<&str>); 4] = [
        (
            "check_fs_strict_tp",
            vec!["check", "--fs", "--strict", "--trusted-paths", cfg_s],
            vec!["check", "--fs", "--strict", cfg_s],
        ),
        (
            "check_fs_strict_tp_json",
            vec![
                "check",
                "--fs",
                "--strict",
                "--trusted-paths",
                "--format",
                "json",
                cfg_s,
            ],
            vec!["check", "--fs", "--strict", "--format", "json", cfg_s],
        ),
        (
            "check_fs_tp_writable_set",
            vec!["check", "--fs", "--trusted-paths", "--writable-set", cfg_s],
            vec!["check", "--fs", "--writable-set", cfg_s],
        ),
        (
            "check_fs_tp_quiet",
            vec!["check", "--fs", "--trusted-paths", "--quiet", cfg_s],
            vec!["check", "--fs", "--quiet", cfg_s],
        ),
    ];

    let mut raw_commands = BTreeMap::new();
    #[cfg(target_os = "macos")]
    let mut normalized_commands = BTreeMap::new();

    for (name, on_args, off_args) in &cases {
        let (code, stdout, stderr) = run_bin(&bin, base, on_args, None)?;
        let (off_code, off_stdout, off_stderr) = run_bin(&bin, base, off_args, None)?;
        assert_eq!(code, Some(0), "non-linux case {name} failed");
        assert_eq!(code, off_code, "non-linux case {name} changed exit code");

        let on_out_s = String::from_utf8(stdout)?;
        let on_err_s = String::from_utf8(stderr)?;
        let off_out_s = String::from_utf8(off_stdout)?;
        let off_err_s = String::from_utf8(off_stderr)?;

        // Prove on every non-Linux target (macOS and Windows) that enabling `--trusted-paths`
        // adds ONLY the single plain Linux-only note and leaves all other stdout/stderr bytes
        // identical to running without `--trusted-paths`.
        match *name {
            "check_fs_strict_tp" => {
                assert_eq!(on_out_s, format!("{off_out_s}{NOTE_LINE}"));
                assert_eq!(on_err_s, off_err_s);
            }
            "check_fs_strict_tp_json" => {
                let off_body = off_out_s
                    .strip_suffix("\n}\n")
                    .ok_or("flag-off JSON missing closing brace")?;
                assert_eq!(on_out_s, format!("{off_body}{NOTE_JSON_BLOCK}\n}}\n"));
                assert_eq!(on_err_s, off_err_s);
            }
            "check_fs_tp_writable_set" | "check_fs_tp_quiet" => {
                assert_eq!(on_out_s, off_out_s);
                assert_eq!(on_err_s, format!("{off_err_s}{NOTE_LINE}"));
            }
            other => return Err(format!("unhandled non-linux case {other}").into()),
        }

        #[cfg(target_os = "macos")]
        normalized_commands.insert(
            (*name).to_owned(),
            CommandSnapshot {
                exit_code: code,
                stdout: normalize_output(&on_out_s, &canon_base_s, &raw_base_s),
                stderr: normalize_output(&on_err_s, &canon_base_s, &raw_base_s),
            },
        );
        raw_commands.insert(
            (*name).to_owned(),
            CommandSnapshot {
                exit_code: code,
                stdout: on_out_s,
                stderr: on_err_s,
            },
        );
    }

    let raw_fixture = CaseFixture {
        commands: raw_commands,
    };
    assert_non_linux_exact_literals(&raw_fixture, cfg_s)?;

    #[cfg(target_os = "macos")]
    {
        let profile = fixture_profile();
        let actual = CaseFixture {
            commands: normalized_commands,
        };
        let fixture_path = fixture_dir(profile).join("non_linux_trusted_paths.json");
        assert_fixture_byte_parity(&actual, &fixture_path, profile)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 3 & 4. Linux flag-on parity, storage diagnostics, and deployment effects
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux_storage_oracles {
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;

    use super::*;

    const OLD_NARROWED: &str = "trusted-paths (narrowed): does not yet inspect config file, \
        read-tree, site/route roots, owner-dir, TLS certs/keys/CAs, keyd-auth-secret-file, \
        acme-webroot, basic-auth, bot-auth, ai-publish storage and keys, error-pages, \
        upstream-tls, mcp-gateway, wasm-plugin, or non-rotating log paths";
    const NEW_NARROWED: &str = "trusted-paths (narrowed): does not yet inspect config file, \
        read-tree, site/route roots, owner-dir, TLS certs/keys/CAs, keyd-auth-secret-file, \
        acme-webroot, basic-auth, bot-auth, ai-publish keys, error-pages, \
        upstream-tls, mcp-gateway, wasm-plugin, or non-rotating log paths";
    const HELP_GEN: &str = "keep every ancestor (and exclusive state directory) owned by root or \
        the service account, not group/other-writable, on an ordinary local POSIX filesystem; \
        use absolute paths";
    const MISS_REASON: &str =
        "not found; if it is created later the permissions it would inherit are not verified";

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

    /// Asserts that both `/` and `/tmp` reside on an accepted non-stacking local POSIX filesystem.
    /// Never skips or returns `Ok(())` on an unsupported filesystem.
    fn assert_local_root_fs() -> TestResult {
        for p in ["/", "/tmp"] {
            let m = fs_magic_of(p)?;
            assert!(
                is_accepted_local_fs(m),
                "precondition failed: {p} is on filesystem 0x{m:x} \
                 (requires an accepted non-stacking local POSIX filesystem such as tmpfs/ext4)"
            );
        }
        Ok(())
    }

    fn normalize_euid(text: String, euid: u32) -> String {
        if euid == 0 {
            return text;
        }
        text.replace(&format!("service uid {euid} "), "service uid <EUID> ")
            .replace(&format!("(uid {euid}, "), "(uid <EUID>, ")
    }

    fn expected_default_observer_note() -> String {
        let euid = rustix::process::geteuid().as_raw();
        if euid == 0 {
            "trusted-paths: running as root; service uid is unknown, so only uid 0 is trusted \
             (server.sandbox.user is unset)"
                .to_owned()
        } else {
            format!(
                "trusted-paths: trusting uid 0 and service uid {euid} \
                 (effective uid of this check)"
            )
        }
    }

    type JsonRunOut = (Option<i32>, serde_json::Value, Vec<u8>, Vec<u8>);

    fn run_check_json(
        bin: &Path,
        cwd: &Path,
        args: &[&str],
        cfg: &Path,
    ) -> Result<JsonRunOut, Box<dyn std::error::Error>> {
        let cfg_s = cfg.to_str().ok_or("non-utf8 cfg")?;
        let mut full = vec!["check"];
        full.extend_from_slice(args);
        full.push("--format");
        full.push("json");
        full.push(cfg_s);
        let (code, stdout, stderr) = run_bin(bin, cwd, &full, None)?;
        let val: serde_json::Value = serde_json::from_slice(&stdout).map_err(|e| {
            format!(
                "invalid json ({e}); stdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr),
            )
        })?;
        Ok((code, val, stdout, stderr))
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

    fn notes_of(val: &serde_json::Value) -> Vec<&str> {
        val.get("notes")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .collect()
    }

    fn loc_of_occurrence(
        kdl: &str,
        needle: &str,
        occurrence: usize,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let (line, column, offset, length) = loc_parts_of_occurrence(kdl, needle, occurrence)?;
        Ok(serde_json::json!({
            "line": line,
            "column": column,
            "offset": offset,
            "length": length,
        }))
    }

    /// Asserts exact whole-object JSON equality for a `W034` issue, including exact `location`
    /// (`line`, `column`, `offset`, `length`), absent `label`, and zero extra fields.
    fn assert_w034_full(
        issue: &serde_json::Value,
        expected_path: &str,
        expected_message: &str,
        expected_help: &str,
        expected_loc: &serde_json::Value,
    ) {
        let expected = serde_json::json!({
            "code": "W034",
            "severity": "warning",
            "message": expected_message,
            "path": expected_path,
            "help": expected_help,
            "location": expected_loc,
        });
        assert_eq!(issue, &expected, "W034 full JSON mismatch");
    }

    fn format_storage_w034_json_entry(
        path: &str,
        message: &str,
        loc: (usize, usize, usize, usize),
    ) -> Result<String, Box<dyn std::error::Error>> {
        let (line, column, offset, length) = loc;
        Ok(format!(
            ",\n    {{\n      \"code\": \"W034\",\n      \"severity\": \"warning\",\n      \"message\": {},\n      \"path\": {},\n      \"help\": {},\n      \"location\": {{\n        \"line\": {line},\n        \"column\": {column},\n        \"offset\": {offset},\n        \"length\": {length}\n      }}\n    }}",
            serde_json::to_string(message)?,
            serde_json::to_string(path)?,
            serde_json::to_string(HELP_GEN)?,
        ))
    }

    // -----------------------------------------------------------------------
    // Always-run Linux rejection test (runs on ALL Linux filesystems, no skip)
    // -----------------------------------------------------------------------

    #[test]
    #[allow(clippy::too_many_lines)]
    fn linux_storage_padded_and_stdin_rejections_never_reach_w034() -> TestResult {
        let bin = miraserve_bin();
        let tmp = TempDir::new_fixed('r')?;
        let base = &tmp.path;

        let certs = base.join("certs");
        let real_cfg_dir = base.join("real_cfg_tree");
        let cwd_dir = base.join("cwd_tree");
        let real_pub = real_cfg_dir.join("www");
        let bad_padded_dir = base.join("padded_target");
        for d in [&certs, &real_cfg_dir, &cwd_dir, &real_pub, &bad_padded_dir] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o750)?;
        }
        set_mode(&bad_padded_dir, 0o777)?;

        let (cert, key) = gen_dev_cert(&bin, &certs, "rel.example")?;
        let pub_key = write_pubkey(&certs)?;

        for (tag, storage_val, expected_err_msg) in [
            (
                "abs_padded",
                format!("{} ", kdl_escape_path(&bad_padded_dir)),
                "ai-publish 'storage' path on site 'rel.example' ends with whitespace (U+0020)",
            ),
            (
                "rel_dot_padded",
                "app /.".to_owned(),
                "ai-publish 'storage' resolved directory name on site 'rel.example' ends with whitespace (U+0020)",
            ),
        ] {
            let padded_cfg = real_cfg_dir.join(format!("{tag}.kdl"));
            fs::write(
                &padded_cfg,
                format!(
                    "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }} }}\n\
                     site \"rel.example\" {{\n\
                         root \"www\"\n\
                         ai-publish {{\n\
                             storage \"{storage_val}\"\n\
                             require-signature \"ed25519:{}\"\n\
                         }}\n\
                     }}\n",
                    kdl_escape_path(&cert),
                    kdl_escape_path(&key),
                    kdl_escape_path(&pub_key),
                ),
            )?;
            let (p_code, p_val, _, _) =
                run_check_json(&bin, &cwd_dir, &["--fs", "--trusted-paths"], &padded_cfg)?;
            assert_eq!(p_code, Some(1), "{tag} must exit 1: {p_val}");
            assert_eq!(p_val.get("valid"), Some(&serde_json::Value::Bool(false)));
            assert!(w034s(&p_val).is_empty(), "{tag} must emit 0 W034: {p_val}");
            assert_eq!(
                p_val
                    .pointer("/errors/0/code")
                    .and_then(serde_json::Value::as_str),
                Some("E202")
            );
            assert_eq!(
                p_val
                    .pointer("/errors/0/path")
                    .and_then(serde_json::Value::as_str),
                Some("site[0].ai-publish.storage")
            );
            assert_eq!(
                p_val
                    .pointer("/errors/0/message")
                    .and_then(serde_json::Value::as_str),
                Some(expected_err_msg)
            );
            assert_eq!(
                notes_of(&p_val),
                vec![
                    "trusted-paths: configuration could not be loaded or is invalid; no paths were verified"
                ]
            );
        }

        let stdin_kdl = format!(
            "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }} }}\n\
             site \"rel.example\" {{\n\
                 root \"{}\"\n\
                 ai-publish {{\n\
                     storage \"stores/app\"\n\
                     require-signature \"ed25519:{}\"\n\
                 }}\n\
             }}\n",
            kdl_escape_path(&cert),
            kdl_escape_path(&key),
            kdl_escape_path(&real_pub),
            kdl_escape_path(&pub_key),
        );
        let (st_code, st_out, _) = run_bin(
            &bin,
            &cwd_dir,
            &["check", "--fs", "--trusted-paths", "--format", "json", "-"],
            Some(stdin_kdl.as_bytes()),
        )?;
        assert_eq!(st_code, Some(1));
        let st_val: serde_json::Value = serde_json::from_slice(&st_out)?;
        assert!(
            w034s(&st_val).is_empty(),
            "stdin relative storage must not reach W034: {st_val}"
        );
        assert_eq!(
            st_val
                .pointer("/errors/0/code")
                .and_then(serde_json::Value::as_str),
            Some("E202")
        );
        assert_eq!(
            st_val
                .pointer("/errors/0/path")
                .and_then(serde_json::Value::as_str),
            Some("site[0].ai-publish.storage")
        );
        assert_eq!(
            notes_of(&st_val),
            vec![
                "trusted-paths: configuration could not be loaded or is invalid; no paths were verified"
            ]
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Oracle 2: Flag on — old-only and mixed-config exact byte parity against
    // checked-in bef6865 and v0.1.7 (9836e8a7) fixtures
    // -----------------------------------------------------------------------

    #[test]
    #[ignore = "requires an accepted local POSIX filesystem at / and /tmp (not overlayfs); run with --ignored in a tmpfs chroot or on a local-fs host"]
    #[allow(clippy::too_many_lines, clippy::similar_names)]
    fn linux_flag_on_old_only_and_mixed_config_exact_parity() -> TestResult {
        assert_local_root_fs()?;
        let profile = fixture_profile();
        let bin = miraserve_bin();
        let tmp = TempDir::new_fixed('p')?;
        let base = &tmp.path;
        let canon_base = fs::canonicalize(base)?;
        let raw_base_s = base.to_string_lossy().into_owned();
        let canon_base_s = canon_base.to_string_lossy().into_owned();
        let euid = rustix::process::geteuid().as_raw();

        let certs = base.join("certs");
        let trusted = base.join("trusted");
        let uncov_bad = base.join("uncov_bad");
        let docroot = uncov_bad.join("www");
        let read_tree = uncov_bad.join("rtree");
        let bad_tree = base.join("bad_tree");
        let bad_target = base.join("bad_target");
        let bad_store0 = base.join("bad_store0");
        let bad_store1 = base.join("bad_store1");
        let log_dir = base.join("bad_logs");
        let acme_bad = base.join("bad_acme");
        for d in [
            &certs,
            &trusted,
            &uncov_bad,
            &docroot,
            &read_tree,
            &bad_tree,
            &bad_target,
            &bad_store0,
            &bad_store1,
            &log_dir,
            &acme_bad,
        ] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o750)?;
        }
        // Intentionally bad, still-excluded read-tree & site.root ancestor!
        set_mode(&uncov_bad, 0o777)?;
        set_mode(&bad_tree, 0o775)?;
        set_mode(&bad_target, 0o777)?;
        set_mode(&bad_store0, 0o775)?;
        set_mode(&bad_store1, 0o777)?;
        set_mode(&log_dir, 0o775)?;
        set_mode(&acme_bad, 0o775)?;

        let link_to_bad = trusted.join("link_bad");
        symlink(&bad_target, &link_to_bad)?;
        let absent_sock = trusted.join("absent.sock");
        let miss_mid_sock = trusted.join("missing_mid/pool.sock");
        let keyd_bad_sock = bad_tree.join("keyd.sock");
        let log_f = log_dir.join("server.log");
        let acc_f = log_dir.join("access.log");

        let (cert, key) = gen_dev_cert(&bin, &certs, "s0.example,s1.example")?;
        let pub_key = write_pubkey(&certs)?;

        // Part A: Old-only config (no ai-publish.storage) covering all 5 existing classes +
        // excluded bad read-tree/site.root + absent socket prefix note + relative fastcgi-pass +
        // independent missing keyd.sock `--fs` error.
        let old_cfg = base.join("old_only.kdl");
        fs::write(
            &old_cfg,
            format!(
                "server {{\n\
                     listen \":443\"\n\
                     tls {{ key-isolation \"split-daemon\"; keyd-socket \"{}\"; cert \"{}\"; key \"{}\" }}\n\
                     sandbox {{ read-tree \"{}\"; socket-tree \"{}\" }}\n\
                 }}\n\
                 site \"s0.example\" {{\n\
                     root \"{}\"\n\
                     route \"/a/*\" {{ fastcgi-pass \"unix:{}/pool.sock\" }}\n\
                     route \"/ok/*\" {{ fastcgi-pass \"unix:{}\" }}\n\
                     route \"/mid/*\" {{ fastcgi-pass \"unix:{}\" }}\n\
                     route \"/rel/*\" {{ fastcgi-pass \"unix:rel/pool.sock\" }}\n\
                 }}\n\
                 site \"s1.example\" {{\n\
                     root \"{}\"\n\
                 }}\n",
                kdl_escape_path(&keyd_bad_sock),
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&read_tree),
                kdl_escape_path(&bad_tree),
                kdl_escape_path(&docroot),
                kdl_escape_path(&link_to_bad),
                kdl_escape_path(&absent_sock),
                kdl_escape_path(&miss_mid_sock),
                kdl_escape_path(&docroot),
            ),
        )?;

        // Part B: Mixed config — exact same 5 classes + keyd.sock error PLUS bad ai-publish.storage
        // on site[0] & site[1].
        let mixed_cfg = base.join("mixed.kdl");
        let s0_store_node = format!("storage \"{}\"", kdl_escape_path(&bad_store0));
        let s1_store_node = format!("storage \"{}\"", kdl_escape_path(&bad_store1));
        let mixed_kdl = format!(
            "server {{\n\
                 listen \":443\"\n\
                 tls {{ key-isolation \"split-daemon\"; keyd-socket \"{}\"; cert \"{}\"; key \"{}\" }}\n\
                 sandbox {{ read-tree \"{}\"; socket-tree \"{}\" }}\n\
             }}\n\
             site \"s0.example\" {{\n\
                 root \"{}\"\n\
                 route \"/a/*\" {{ fastcgi-pass \"unix:{}/pool.sock\" }}\n\
                 route \"/ok/*\" {{ fastcgi-pass \"unix:{}\" }}\n\
                 route \"/mid/*\" {{ fastcgi-pass \"unix:{}\" }}\n\
                 route \"/rel/*\" {{ fastcgi-pass \"unix:rel/pool.sock\" }}\n\
                 ai-publish {{\n\
                     {s0_store_node}\n\
                     require-signature \"ed25519:{}\"\n\
                 }}\n\
             }}\n\
             site \"s1.example\" {{\n\
                 root \"{}\"\n\
                 ai-publish {{\n\
                     {s1_store_node}\n\
                     require-signature \"ed25519:{}\"\n\
                 }}\n\
             }}\n",
            kdl_escape_path(&keyd_bad_sock),
            kdl_escape_path(&cert),
            kdl_escape_path(&key),
            kdl_escape_path(&read_tree),
            kdl_escape_path(&bad_tree),
            kdl_escape_path(&docroot),
            kdl_escape_path(&link_to_bad),
            kdl_escape_path(&absent_sock),
            kdl_escape_path(&miss_mid_sock),
            kdl_escape_path(&pub_key),
            kdl_escape_path(&docroot),
            kdl_escape_path(&pub_key),
        );
        fs::write(&mixed_cfg, &mixed_kdl)?;

        let acme_s = acme_bad.to_string_lossy().into_owned();
        let log_s = log_f.to_string_lossy().into_owned();
        let acc_s = acc_f.to_string_lossy().into_owned();
        let common_args = [
            "--fs",
            "--no-sandbox",
            "--trusted-paths",
            "--acme-dir",
            &acme_s,
            "--log-file",
            &log_s,
            "--access-log",
            &acc_s,
            "--log-max-bytes",
            "1024",
        ];

        let (old_code, old_val, old_stdout, old_stderr) =
            run_check_json(&bin, base, &common_args, &old_cfg)?;
        let old_cfg_s = old_cfg.to_str().ok_or("non-utf8 old_cfg")?;
        let mut text_args = vec!["check"];
        text_args.extend_from_slice(&common_args);
        text_args.push(old_cfg_s);
        let (old_txt_code, old_txt_out, old_txt_err) = run_bin(&bin, base, &text_args, None)?;
        let (m_code, m_val, m_stdout, m_stderr) =
            run_check_json(&bin, base, &common_args, &mixed_cfg)?;

        let norm = |raw: &[u8]| -> Result<String, Box<dyn std::error::Error>> {
            let text = String::from_utf8(raw.to_vec())?;
            Ok(normalize_euid(
                normalize_output(&text, &canon_base_s, &raw_base_s),
                euid,
            ))
        };

        let old_json_norm = norm(&old_stdout)?;
        let old_json_err_norm = norm(&old_stderr)?;
        let old_txt_out_norm = norm(&old_txt_out)?;
        let old_txt_err_norm = norm(&old_txt_err)?;
        let mixed_json_norm = norm(&m_stdout)?;
        let mixed_json_err_norm = norm(&m_stderr)?;

        let fdir = fixture_dir(profile);

        // Candidate semantic & position assertions:
        assert_eq!(old_code, Some(1), "missing keyd.sock must exit 1");
        assert_eq!(m_code, Some(1), "mixed missing keyd.sock must exit 1");
        assert_eq!(
            old_val
                .pointer("/errors/0/path")
                .and_then(serde_json::Value::as_str),
            Some("server.tls.keyd-socket")
        );
        assert_eq!(
            m_val.get("errors"),
            old_val.get("errors"),
            "mixed config errors must match old-only errors"
        );
        let old_w = w034s(&old_val);
        let old_paths: Vec<Option<&str>> = old_w.iter().map(|w| jstr(w, "path")).collect();
        assert_eq!(
            old_paths,
            vec![
                Some("server.sandbox.socket-tree"),
                Some("site[0].route[0].fastcgi-pass"),
                Some("site[0].route[2].fastcgi-pass"),
                Some("site[0].route[3].fastcgi-pass"),
                Some("server.tls.keyd-socket"),
                Some("server.tls.acme"),
                Some("server.log-file"),
                Some("server.access-log"),
            ],
            "old-only W034 paths: {old_w:#?}"
        );
        let old_notes = notes_of(&old_val);
        assert_eq!(
            old_notes,
            vec![
                expected_default_observer_note().as_str(),
                NEW_NARROWED,
                &format!(
                    "trusted-paths: site 's0.example' FastCGI Unix socket '{}': inspected existing \
                     prefix '{}' (stopped at 'absent.sock', not found by this lookup)",
                    absent_sock.display(),
                    trusted.display(),
                ),
            ]
        );
        let m_w = w034s(&m_val);
        assert_eq!(m_w.len(), old_w.len() + 2, "mixed W034 count: {m_w:#?}");
        for idx in 0..old_w.len() {
            assert_eq!(
                m_w.get(idx),
                old_w.get(idx),
                "existing W034[{idx}] changed when storage was added"
            );
        }
        assert_eq!(notes_of(&m_val), old_notes);

        let s0_loc_parts = loc_parts_of_occurrence(&mixed_kdl, &s0_store_node, 0)?;
        let s1_loc_parts = loc_parts_of_occurrence(&mixed_kdl, &s1_store_node, 0)?;
        assert_w034_full(
            m_w.get(8).copied().ok_or("missing storage W034[8]")?,
            "site[0].ai-publish.storage",
            &format!(
                "site 's0.example' ai-publish storage '{}': first untrusted component '{}' \
                 (uid {euid}, mode 0775): group or other writable",
                bad_store0.display(),
                bad_store0.display(),
            ),
            HELP_GEN,
            &loc_of_occurrence(&mixed_kdl, &s0_store_node, 0)?,
        );
        assert_w034_full(
            m_w.get(9).copied().ok_or("missing storage W034[9]")?,
            "site[1].ai-publish.storage",
            &format!(
                "site 's1.example' ai-publish storage '{}': first untrusted component '{}' \
                 (uid {euid}, mode 0777): group or other writable",
                bad_store1.display(),
                bad_store1.display(),
            ),
            HELP_GEN,
            &loc_of_occurrence(&mixed_kdl, &s1_store_node, 0)?,
        );

        // Byte-for-byte comparison against BOTH checked-in reference fixtures (`bef6865` & `v0.1.7`).
        let uid_label = if euid == 0 { "0" } else { "<EUID>" };
        let s0_entry = format_storage_w034_json_entry(
            "site[0].ai-publish.storage",
            &format!(
                "site 's0.example' ai-publish storage '<TMPDIR>/bad_store0': first untrusted \
                 component '<TMPDIR>/bad_store0' (uid {uid_label}, mode 0775): group or other writable"
            ),
            s0_loc_parts,
        )?;
        let s1_entry = format_storage_w034_json_entry(
            "site[1].ai-publish.storage",
            &format!(
                "site 's1.example' ai-publish storage '<TMPDIR>/bad_store1': first untrusted \
                 component '<TMPDIR>/bad_store1' (uid {uid_label}, mode 0777): group or other writable"
            ),
            s1_loc_parts,
        )?;

        for label in ["bef6865", "v017"] {
            let fixture_path = fdir.join(format!("flag_on_{label}.json"));
            let raw = fs::read_to_string(&fixture_path).map_err(|err| {
                format!(
                    "missing flag-on parity fixture '{}': {err}",
                    fixture_path.display()
                )
            })?;
            let expected: CaseFixture = serde_json::from_str(&raw)?;

            // 1. old_only_json: byte-identical modulo ONLY the narrowed-note literal.
            let exp_oj = expected
                .commands
                .get("old_only_json")
                .ok_or("missing old_only_json in fixture")?;
            assert_eq!(
                old_code, exp_oj.exit_code,
                "old_only_json exit mismatch vs {label}"
            );
            assert_eq!(
                exp_oj.stdout.matches(OLD_NARROWED).count(),
                1,
                "{label} old_only_json must contain OLD_NARROWED once"
            );
            let exp_oj_out = exp_oj.stdout.replacen(OLD_NARROWED, NEW_NARROWED, 1);
            assert_eq!(
                old_json_norm.as_bytes(),
                exp_oj_out.as_bytes(),
                "old_only_json stdout byte mismatch vs {label}\n--- EXPECTED ---\n{exp_oj_out}\n--- ACTUAL ---\n{old_json_norm}"
            );
            assert_eq!(
                old_json_err_norm.as_bytes(),
                exp_oj.stderr.as_bytes(),
                "old_only_json stderr byte mismatch vs {label}"
            );

            // 2. old_only_text: byte-identical modulo ONLY the narrowed-note literal.
            let exp_ot = expected
                .commands
                .get("old_only_text")
                .ok_or("missing old_only_text in fixture")?;
            assert_eq!(
                old_txt_code, exp_ot.exit_code,
                "old_only_text exit mismatch vs {label}"
            );
            let exp_ot_out = exp_ot.stdout.replacen(OLD_NARROWED, NEW_NARROWED, 1);
            let exp_ot_err = exp_ot.stderr.replacen(OLD_NARROWED, NEW_NARROWED, 1);
            assert_eq!(
                old_txt_out_norm.as_bytes(),
                exp_ot_out.as_bytes(),
                "old_only_text stdout byte mismatch vs {label}\n--- EXPECTED ---\n{exp_ot_out}\n--- ACTUAL ---\n{old_txt_out_norm}"
            );
            assert_eq!(
                old_txt_err_norm.as_bytes(),
                exp_ot_err.as_bytes(),
                "old_only_text stderr byte mismatch vs {label}\n--- EXPECTED ---\n{exp_ot_err}\n--- ACTUAL ---\n{old_txt_err_norm}"
            );

            // 3. mixed_json: exact byte-for-byte comparison pinning exit status, stderr,
            //    errors (including keyd.sock), summary counts, all 8 old W034 records,
            //    the exact 2 appended storage records, and all 3 notes!
            let exp_mj = expected
                .commands
                .get("mixed_json")
                .ok_or("missing mixed_json in fixture")?;
            assert_eq!(
                m_code, exp_mj.exit_code,
                "mixed_json exit mismatch vs {label}"
            );
            assert_eq!(
                mixed_json_err_norm.as_bytes(),
                exp_mj.stderr.as_bytes(),
                "mixed_json stderr byte mismatch vs {label}"
            );
            assert_eq!(
                exp_mj.stdout.matches(OLD_NARROWED).count(),
                1,
                "{label} mixed_json must contain OLD_NARROWED once"
            );
            let mut exp_mj_out = exp_mj.stdout.replacen(OLD_NARROWED, NEW_NARROWED, 1);
            assert_eq!(
                exp_mj_out.matches("    \"warnings\": 8,\n").count(),
                1,
                "{label} mixed_json must contain summary warnings=8 once"
            );
            exp_mj_out =
                exp_mj_out.replacen("    \"warnings\": 8,\n", "    \"warnings\": 10,\n", 1);
            let close_anchor = "\n  ],\n  \"notes\": [";
            assert_eq!(
                exp_mj_out.matches(close_anchor).count(),
                1,
                "{label} mixed_json must contain warnings closing anchor once"
            );
            exp_mj_out = exp_mj_out.replacen(
                close_anchor,
                &format!("{s0_entry}{s1_entry}{close_anchor}"),
                1,
            );
            assert_eq!(
                mixed_json_norm.as_bytes(),
                exp_mj_out.as_bytes(),
                "mixed_json stdout byte mismatch vs {label}\n--- EXPECTED ---\n{exp_mj_out}\n--- ACTUAL ---\n{mixed_json_norm}"
            );
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Oracle 3: Storage diagnostics full JSON matrix on real local Linux fs
    // -----------------------------------------------------------------------

    #[test]
    #[ignore = "requires an accepted local POSIX filesystem at / and /tmp (not overlayfs); run with --ignored in a tmpfs chroot or on a local-fs host"]
    #[allow(clippy::too_many_lines, clippy::similar_names)]
    fn linux_storage_diagnostics_full_json_matrix() -> TestResult {
        assert_local_root_fs()?;
        let bin = miraserve_bin();
        let tmp = TempDir::new_fixed('m')?;
        let base = &tmp.path;
        let euid = rustix::process::geteuid().as_raw();

        let certs = base.join("certs");
        let docroot = base.join("www");
        let trusted = base.join("trusted");
        let clean_store = trusted.join("clean_store");
        let desc_rel = clean_store.join("releases/v1");
        let wr_parent = base.join("wr_parent");
        let under_wr_parent = wr_parent.join("store");
        let wr_leaf = trusted.join("wr_leaf");
        let sticky_leaf = trusted.join("sticky_leaf");
        let sticky_anc = base.join("sticky_anc");
        let sticky_existing = sticky_anc.join("ok_store");
        let target_ok = base.join("target_ok");
        let target_bad = base.join("target_bad");
        let owner_dir = base.join("tenant_home");
        for d in [
            &certs,
            &docroot,
            &trusted,
            &clean_store,
            &desc_rel,
            &wr_parent,
            &under_wr_parent,
            &wr_leaf,
            &sticky_leaf,
            &sticky_anc,
            &sticky_existing,
            &target_ok,
            &target_bad,
            &owner_dir,
        ] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o750)?;
        }
        // Writable descendants inside clean_store: inspection MUST stop at clean_store!
        set_mode(&clean_store.join("releases"), 0o777)?;
        set_mode(&desc_rel, 0o777)?;
        fs::write(desc_rel.join("index.html"), b"ok")?;
        set_mode(&desc_rel.join("index.html"), 0o666)?;
        fs::write(clean_store.join("active.json"), b"{}")?;
        set_mode(&clean_store.join("active.json"), 0o666)?;

        set_mode(&wr_parent, 0o775)?;
        set_mode(&wr_leaf, 0o775)?;
        set_mode(&sticky_leaf, 0o1777)?;
        set_mode(&sticky_anc, 0o1777)?;
        set_mode(&target_bad, 0o777)?;

        let reg_file = trusted.join("not_a_dir");
        fs::write(&reg_file, b"regular")?;
        set_mode(&reg_file, 0o644)?;

        let sym_ok_abs = trusted.join("sym_ok_abs");
        symlink(&target_ok, &sym_ok_abs)?;
        let sym_ok_rel = trusted.join("sym_ok_rel");
        symlink("../target_ok", &sym_ok_rel)?;
        let sym_bad_tgt = trusted.join("sym_bad_tgt");
        symlink(&target_bad, &sym_bad_tgt)?;
        let sym_bad_parent = wr_parent.join("sym_to_ok");
        symlink(&target_ok, &sym_bad_parent)?;
        let loop_a = trusted.join("loop_a");
        let loop_b = trusted.join("loop_b");
        symlink(&loop_b, &loop_a)?;
        symlink(&loop_a, &loop_b)?;

        let (cert, key) = gen_dev_cert(&bin, &certs, "clean.example,a.example,b.example")?;
        let pub_key = write_pubkey(&certs)?;

        // (a)+(b)+(i)+(k): Clean 0750 store (with 0777/0666 descendants!), sticky existing trusted
        // child, absolute trusted symlink, and relative trusted symlink -> ALL exit 0 under --strict!
        // Pass `--no-sandbox` so an independent Landlock-refused host (`W035`) cannot disturb clean-store strict checks.
        for (tag, store_path) in [
            ("clean_with_bad_descendants", &clean_store),
            ("sticky_existing_child", &sticky_existing),
            ("trusted_abs_symlink", &sym_ok_abs),
            ("trusted_rel_symlink", &sym_ok_rel),
        ] {
            let cfg = base.join(format!("{tag}.kdl"));
            fs::write(
                &cfg,
                format!(
                    "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }} }}\n\
                     site \"clean.example\" {{\n\
                         root \"{}\"\n\
                         ai-publish {{\n\
                             storage \"{}\"\n\
                             require-signature \"ed25519:{}\"\n\
                         }}\n\
                     }}\n",
                    kdl_escape_path(&cert),
                    kdl_escape_path(&key),
                    kdl_escape_path(&docroot),
                    kdl_escape_path(store_path),
                    kdl_escape_path(&pub_key),
                ),
            )?;
            let (code, val, _, _) = run_check_json(
                &bin,
                base,
                &["--fs", "--no-sandbox", "--strict", "--trusted-paths"],
                &cfg,
            )?;
            assert_eq!(code, Some(0), "case {tag} must pass --strict: {val}");
            assert_eq!(val.get("valid"), Some(&serde_json::Value::Bool(true)));
            assert_eq!(
                val.get("errors")
                    .and_then(serde_json::Value::as_array)
                    .map(Vec::len),
                Some(0),
                "{tag} errors: {val}"
            );
            assert_eq!(
                val.get("warnings")
                    .and_then(serde_json::Value::as_array)
                    .map(Vec::len),
                Some(0),
                "{tag} warnings: {val}"
            );
            assert_eq!(
                notes_of(&val),
                vec![expected_default_observer_note().as_str(), NEW_NARROWED],
                "{tag} notes: {val}"
            );
        }

        // (c): Baseline-clean --strict and --allow-warning W034 on writable leaf (0 errors, 1 W034).
        let wr_leaf_node = format!("storage \"{}\"", kdl_escape_path(&wr_leaf));
        let wr_leaf_kdl = format!(
            "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }} }}\n\
             site \"clean.example\" {{\n\
                 root \"{}\"\n\
                 ai-publish {{\n\
                     {wr_leaf_node}\n\
                     require-signature \"ed25519:{}\"\n\
                 }}\n\
             }}\n",
            kdl_escape_path(&cert),
            kdl_escape_path(&key),
            kdl_escape_path(&docroot),
            kdl_escape_path(&pub_key),
        );
        let wr_leaf_cfg = base.join("wr_leaf.kdl");
        fs::write(&wr_leaf_cfg, &wr_leaf_kdl)?;
        let wr_leaf_loc = loc_of_occurrence(&wr_leaf_kdl, &wr_leaf_node, 0)?;
        let wr_leaf_msg = format!(
            "site 'clean.example' ai-publish storage '{}': first untrusted component '{}' \
             (uid {euid}, mode 0775): group or other writable",
            wr_leaf.display(),
            wr_leaf.display(),
        );

        let (s_code, s_val, _, _) = run_check_json(
            &bin,
            base,
            &["--fs", "--no-sandbox", "--strict", "--trusted-paths"],
            &wr_leaf_cfg,
        )?;
        assert_eq!(s_code, Some(1), "wr_leaf --strict must exit 1: {s_val}");
        assert_eq!(s_val.get("valid"), Some(&serde_json::Value::Bool(false)));
        assert_eq!(
            s_val
                .get("errors")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(0)
        );
        let sw = w034s(&s_val);
        assert_eq!(sw.len(), 1);
        assert_w034_full(
            sw.first().copied().ok_or("missing W034")?,
            "site[0].ai-publish.storage",
            &wr_leaf_msg,
            HELP_GEN,
            &wr_leaf_loc,
        );

        let (a_code, a_val, _, _) = run_check_json(
            &bin,
            base,
            &[
                "--fs",
                "--no-sandbox",
                "--strict",
                "--trusted-paths",
                "--allow-warning",
                "W034",
            ],
            &wr_leaf_cfg,
        )?;
        assert_eq!(a_code, Some(0), "allow-warning W034 must exit 0: {a_val}");
        assert_eq!(a_val.get("valid"), Some(&serde_json::Value::Bool(true)));
        assert_eq!(
            a_val
                .get("errors")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(0)
        );
        let aw = w034s(&a_val);
        assert_eq!(aw.len(), 1, "W034 must still be emitted when allowed");
        assert_w034_full(
            aw.first().copied().ok_or("missing allowed W034")?,
            "site[0].ai-publish.storage",
            &wr_leaf_msg,
            HELP_GEN,
            &wr_leaf_loc,
        );

        // (g): Missing leaf under existing 0750 parent -> 0 --fs errors, 1 W034, NO prefix note,
        // --strict exits 1 solely due to W034, --allow-warning W034 exits 0!
        let miss_leaf = trusted.join("absent_store");
        let miss_leaf_node = format!("storage \"{}\"", kdl_escape_path(&miss_leaf));
        let miss_leaf_kdl = format!(
            "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }} }}\n\
             site \"clean.example\" {{\n\
                 root \"{}\"\n\
                 ai-publish {{\n\
                     {miss_leaf_node}\n\
                     require-signature \"ed25519:{}\"\n\
                 }}\n\
             }}\n",
            kdl_escape_path(&cert),
            kdl_escape_path(&key),
            kdl_escape_path(&docroot),
            kdl_escape_path(&pub_key),
        );
        let miss_leaf_cfg = base.join("miss_leaf.kdl");
        fs::write(&miss_leaf_cfg, &miss_leaf_kdl)?;
        let (ml_code, ml_val, _, _) = run_check_json(
            &bin,
            base,
            &["--fs", "--no-sandbox", "--strict", "--trusted-paths"],
            &miss_leaf_cfg,
        )?;
        assert_eq!(
            ml_code,
            Some(1),
            "missing leaf --strict must fail: {ml_val}"
        );
        assert_eq!(
            ml_val
                .get("errors")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(0),
            "existing parent should have 0 --fs errors: {ml_val}"
        );
        assert_eq!(
            notes_of(&ml_val),
            vec![expected_default_observer_note().as_str(), NEW_NARROWED],
            "missing store must NOT emit a prefix note: {ml_val}"
        );
        let ml_w = w034s(&ml_val);
        assert_eq!(ml_w.len(), 1);
        assert_w034_full(
            ml_w.first().copied().ok_or("missing leaf W034")?,
            "site[0].ai-publish.storage",
            &format!(
                "site 'clean.example' ai-publish storage '{}': first untrusted component '{}' \
                 (uid unknown, mode unknown): {MISS_REASON}",
                miss_leaf.display(),
                miss_leaf.display(),
            ),
            HELP_GEN,
            &loc_of_occurrence(&miss_leaf_kdl, &miss_leaf_node, 0)?,
        );
        let (mla_code, mla_val, _, _) = run_check_json(
            &bin,
            base,
            &[
                "--fs",
                "--no-sandbox",
                "--strict",
                "--trusted-paths",
                "--allow-warning",
                "W034",
            ],
            &miss_leaf_cfg,
        )?;
        assert_eq!(
            mla_code,
            Some(0),
            "missing leaf allow-W034 exits 0: {mla_val}"
        );
        assert_eq!(w034s(&mla_val).len(), 1);

        // (h): Missing intermediate -> independent --fs error (parent missing) AND 1 W034 on
        // the FIRST missing intermediate component, NO prefix note, exit 1 even with allow-W034!
        let miss_mid = trusted.join("absent_mid/store");
        let miss_mid_node = format!("storage \"{}\"", kdl_escape_path(&miss_mid));
        let miss_mid_kdl = format!(
            "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }} }}\n\
             site \"clean.example\" {{\n\
                 root \"{}\"\n\
                 ai-publish {{\n\
                     {miss_mid_node}\n\
                     require-signature \"ed25519:{}\"\n\
                 }}\n\
             }}\n",
            kdl_escape_path(&cert),
            kdl_escape_path(&key),
            kdl_escape_path(&docroot),
            kdl_escape_path(&pub_key),
        );
        let miss_mid_cfg = base.join("miss_mid.kdl");
        fs::write(&miss_mid_cfg, &miss_mid_kdl)?;
        let (mm_code, mm_val, _, _) = run_check_json(
            &bin,
            base,
            &[
                "--fs",
                "--no-sandbox",
                "--strict",
                "--trusted-paths",
                "--allow-warning",
                "W034",
            ],
            &miss_mid_cfg,
        )?;
        assert_eq!(
            mm_code,
            Some(1),
            "missing parent --fs error keeps exit 1: {mm_val}"
        );
        assert_eq!(
            mm_val
                .get("errors")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(1),
            "expected 1 independent --fs error: {mm_val}"
        );
        assert_eq!(
            notes_of(&mm_val),
            vec![expected_default_observer_note().as_str(), NEW_NARROWED],
            "missing intermediate must NOT emit a prefix note"
        );
        let mm_w = w034s(&mm_val);
        assert_eq!(mm_w.len(), 1);
        assert_w034_full(
            mm_w.first().copied().ok_or("missing mid W034")?,
            "site[0].ai-publish.storage",
            &format!(
                "site 'clean.example' ai-publish storage '{}': first untrusted component '{}' \
                 (uid unknown, mode unknown): {MISS_REASON}",
                miss_mid.display(),
                trusted.join("absent_mid").display(),
            ),
            HELP_GEN,
            &loc_of_occurrence(&miss_mid_kdl, &miss_mid_node, 0)?,
        );

        // (d)+(e)+(f)+(j)+(l)+(o): Single-site failure cases asserted with exact full JSON objects!
        let sticky_miss_leaf = sticky_anc.join("absent_store");
        let sticky_miss_mid = sticky_anc.join("absent_mid/store");
        let failure_cases: Vec<(&str, String, String)> = vec![
            (
                "wr_parent",
                kdl_escape_path(&under_wr_parent),
                format!(
                    "site 'clean.example' ai-publish storage '{}': first untrusted component '{}' \
                     (uid {euid}, mode 0775): group or other writable",
                    under_wr_parent.display(),
                    wr_parent.display(),
                ),
            ),
            (
                "sticky_leaf",
                kdl_escape_path(&sticky_leaf),
                format!(
                    "site 'clean.example' ai-publish storage '{}': first untrusted component '{}' \
                     (uid {euid}, mode 1777): group or other writable",
                    sticky_leaf.display(),
                    sticky_leaf.display(),
                ),
            ),
            (
                "wrong_type_reg",
                kdl_escape_path(&reg_file),
                format!(
                    "site 'clean.example' ai-publish storage '{}': first untrusted component '{}' \
                     (uid {euid}, mode 0644): exists but is not a directory",
                    reg_file.display(),
                    reg_file.display(),
                ),
            ),
            (
                "sticky_miss_leaf",
                kdl_escape_path(&sticky_miss_leaf),
                format!(
                    "site 'clean.example' ai-publish storage '{}': first untrusted component '{}' \
                     (uid {euid}, mode 1777): missing component 'absent_store' under a parent where \
                     another account could create it, and if it is created later the permissions \
                     it would inherit are not verified",
                    sticky_miss_leaf.display(),
                    sticky_anc.display(),
                ),
            ),
            (
                "sticky_miss_mid",
                kdl_escape_path(&sticky_miss_mid),
                format!(
                    "site 'clean.example' ai-publish storage '{}': first untrusted component '{}' \
                     (uid {euid}, mode 1777): missing component 'absent_mid' under a parent where \
                     another account could create it, and if it is created later the permissions \
                     it would inherit are not verified",
                    sticky_miss_mid.display(),
                    sticky_anc.display(),
                ),
            ),
            (
                "bad_symlink_target",
                kdl_escape_path(&sym_bad_tgt),
                format!(
                    "site 'clean.example' ai-publish storage '{}': first untrusted component '{}' \
                     (uid {euid}, mode 0777): symbolic link whose own parent or target chain is \
                     untrusted (via '{}': group or other writable)",
                    sym_bad_tgt.display(),
                    target_bad.display(),
                    sym_bad_tgt.display(),
                ),
            ),
            (
                "bad_symlink_parent",
                kdl_escape_path(&sym_bad_parent),
                format!(
                    "site 'clean.example' ai-publish storage '{}': first untrusted component '{}' \
                     (uid {euid}, mode 0775): group or other writable",
                    sym_bad_parent.display(),
                    wr_parent.display(),
                ),
            ),
            (
                "symlink_loop",
                kdl_escape_path(&loop_a),
                format!(
                    "site 'clean.example' ai-publish storage '{}': first untrusted component '{}' \
                     (uid {euid}, mode 0777): could not be inspected \
                     (Too many levels of symbolic links (os error 40))",
                    loop_a.display(),
                    loop_a.display(),
                ),
            ),
            (
                "windows_drive_spelling",
                "C:/publish/store".to_owned(),
                "site 'clean.example' ai-publish storage 'C:/publish/store': first untrusted \
                 component 'C:/publish/store' (uid unknown, mode unknown): not verified: relative \
                 path depends on the working directory of the server"
                    .to_owned(),
            ),
        ];

        for (tag, storage_kdl_val, expected_msg) in &failure_cases {
            let node = format!("storage \"{storage_kdl_val}\"");
            let kdl = format!(
                "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }} }}\n\
                 site \"clean.example\" {{\n\
                     root \"{}\"\n\
                     ai-publish {{\n\
                         {node}\n\
                         require-signature \"ed25519:{}\"\n\
                     }}\n\
                 }}\n",
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&docroot),
                kdl_escape_path(&pub_key),
            );
            let cfg = base.join(format!("fail_{tag}.kdl"));
            fs::write(&cfg, &kdl)?;
            let (_c, val, _, _) = run_check_json(
                &bin,
                base,
                &["--fs", "--no-sandbox", "--trusted-paths"],
                &cfg,
            )?;
            let ws = w034s(&val);
            assert_eq!(ws.len(), 1, "case {tag} expected 1 W034: {val}");
            assert_w034_full(
                ws.first().copied().ok_or("missing W034")?,
                "site[0].ai-publish.storage",
                expected_msg,
                HELP_GEN,
                &loc_of_occurrence(&kdl, &node, 0)?,
            );
            assert_eq!(
                notes_of(&val),
                vec![expected_default_observer_note().as_str(), NEW_NARROWED],
                "case {tag} unexpected notes: {val}"
            );
        }

        // (m): Two sites sharing a store:
        //  - Identical literal storage paths are rejected at KDL load with `E401` (`R5-PUB-5`)
        //    before `--trusted-paths` runs.
        //  - Two symlinks aliasing the same absent store under `wr_parent` pass `R5-PUB-5` and
        //    each emit a per-site W034 in source index order (no deduplication).
        let dup_node = format!("storage \"{}\"", kdl_escape_path(&wr_leaf));
        let dup_kdl = format!(
            "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }} }}\n\
             site \"a.example\" {{\n\
                 root \"{}\"\n\
                 ai-publish {{\n\
                     {dup_node}\n\
                     require-signature \"ed25519:{}\"\n\
                 }}\n\
             }}\n\
             site \"b.example\" {{\n\
                 root \"{}\"\n\
                 ai-publish {{\n\
                     {dup_node}\n\
                     require-signature \"ed25519:{}\"\n\
                 }}\n\
             }}\n",
            kdl_escape_path(&cert),
            kdl_escape_path(&key),
            kdl_escape_path(&docroot),
            kdl_escape_path(&pub_key),
            kdl_escape_path(&docroot),
            kdl_escape_path(&pub_key),
        );
        let dup_cfg = base.join("dup.kdl");
        fs::write(&dup_cfg, &dup_kdl)?;
        let (dc, d_val, _, _) = run_check_json(
            &bin,
            base,
            &["--fs", "--no-sandbox", "--trusted-paths"],
            &dup_cfg,
        )?;
        assert_eq!(
            dc,
            Some(1),
            "R5-PUB-5 must reject literal duplicate storage: {d_val}"
        );
        assert_eq!(
            d_val
                .pointer("/errors/0/code")
                .and_then(serde_json::Value::as_str),
            Some("E401")
        );
        assert_eq!(
            d_val
                .pointer("/errors/0/path")
                .and_then(serde_json::Value::as_str),
            Some("site[1].ai-publish.storage")
        );
        assert!(
            w034s(&d_val).is_empty(),
            "E401 load error must not reach W034: {d_val}"
        );

        let shared_absent_target = wr_parent.join("shared_absent_store");
        let sym_shared_a = trusted.join("sym_shared_a");
        let sym_shared_b = trusted.join("sym_shared_b");
        symlink(&shared_absent_target, &sym_shared_a)?;
        symlink(&shared_absent_target, &sym_shared_b)?;
        let sa_node = format!("storage \"{}\"", kdl_escape_path(&sym_shared_a));
        let sb_node = format!("storage \"{}\"", kdl_escape_path(&sym_shared_b));
        let shared_kdl = format!(
            "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }} }}\n\
             site \"a.example\" {{\n\
                 root \"{}\"\n\
                 ai-publish {{\n\
                     {sa_node}\n\
                     require-signature \"ed25519:{}\"\n\
                 }}\n\
             }}\n\
             site \"b.example\" {{\n\
                 root \"{}\"\n\
                 ai-publish {{\n\
                     {sb_node}\n\
                     require-signature \"ed25519:{}\"\n\
                 }}\n\
             }}\n",
            kdl_escape_path(&cert),
            kdl_escape_path(&key),
            kdl_escape_path(&docroot),
            kdl_escape_path(&pub_key),
            kdl_escape_path(&docroot),
            kdl_escape_path(&pub_key),
        );
        let shared_cfg = base.join("shared_alias.kdl");
        fs::write(&shared_cfg, &shared_kdl)?;
        let (_sc, s_alias_val, _, _) = run_check_json(
            &bin,
            base,
            &["--fs", "--no-sandbox", "--trusted-paths"],
            &shared_cfg,
        )?;
        let saw = w034s(&s_alias_val);
        assert_eq!(
            saw.len(),
            2,
            "two sites aliasing the same store via symlinks must emit 2 W034s: {s_alias_val}"
        );
        assert_w034_full(
            saw.first().copied().ok_or("missing shared[0]")?,
            "site[0].ai-publish.storage",
            &format!(
                "site 'a.example' ai-publish storage '{}': first untrusted component '{}' \
                 (uid {euid}, mode 0775): symbolic link whose own parent or target chain is \
                 untrusted (via '{}': group or other writable)",
                sym_shared_a.display(),
                wr_parent.display(),
                sym_shared_a.display(),
            ),
            HELP_GEN,
            &loc_of_occurrence(&shared_kdl, &sa_node, 0)?,
        );
        assert_w034_full(
            saw.get(1).copied().ok_or("missing shared[1]")?,
            "site[1].ai-publish.storage",
            &format!(
                "site 'b.example' ai-publish storage '{}': first untrusted component '{}' \
                 (uid {euid}, mode 0775): symbolic link whose own parent or target chain is \
                 untrusted (via '{}': group or other writable)",
                sym_shared_b.display(),
                wr_parent.display(),
                sym_shared_b.display(),
            ),
            HELP_GEN,
            &loc_of_occurrence(&shared_kdl, &sb_node, 0)?,
        );

        // (n): Quarantined owner-dir site (missing docroot -> W026) STILL gets storage W034!
        let missing_tenant_root = owner_dir.join("absent_public_html");
        let q_node = format!("storage \"{}\"", kdl_escape_path(&wr_leaf));
        let q_kdl = format!(
            "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }} }}\n\
             site \"a.example\" {{\n\
                 owner-dir \"{}\"\n\
                 root \"{}\"\n\
                 ai-publish {{\n\
                     {q_node}\n\
                     require-signature \"ed25519:{}\"\n\
                 }}\n\
             }}\n",
            kdl_escape_path(&cert),
            kdl_escape_path(&key),
            kdl_escape_path(&owner_dir),
            kdl_escape_path(&missing_tenant_root),
            kdl_escape_path(&pub_key),
        );
        let q_cfg = base.join("quarantined.kdl");
        fs::write(&q_cfg, &q_kdl)?;
        let (qc, q_val, _, _) = run_check_json(
            &bin,
            base,
            &["--fs", "--no-sandbox", "--trusted-paths"],
            &q_cfg,
        )?;
        assert_eq!(
            qc,
            Some(0),
            "quarantined tenant site must not error: {q_val}"
        );
        assert_eq!(
            q_val
                .get("errors")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(0),
            "quarantined tenant site must have 0 errors: {q_val}"
        );
        let q_w026: Vec<&serde_json::Value> = q_val
            .get("warnings")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter(|w| jstr(w, "code") == Some("W026"))
            .collect();
        assert_eq!(
            q_w026.len(),
            1,
            "quarantined site must actually receive W026: {q_val}"
        );
        assert_eq!(
            q_w026.first().and_then(|w| jstr(w, "path")),
            Some("site[0].root"),
            "W026 must point at site[0].root: {q_val}"
        );
        assert!(
            q_w026
                .first()
                .and_then(|w| jstr(w, "message"))
                .is_some_and(
                    |m| m.contains("503 Service Unavailable") && m.contains("absent_public_html")
                ),
            "W026 message must describe missing tenant root quarantine: {q_val}"
        );
        let qw = w034s(&q_val);
        assert_eq!(
            qw.len(),
            1,
            "quarantined site must still get storage W034: {q_val}"
        );
        assert_w034_full(
            qw.first().copied().ok_or("missing quarantined W034")?,
            "site[0].ai-publish.storage",
            &format!(
                "site 'a.example' ai-publish storage '{}': first untrusted component '{}' \
                 (uid {euid}, mode 0775): group or other writable",
                wr_leaf.display(),
                wr_leaf.display(),
            ),
            HELP_GEN,
            &loc_of_occurrence(&q_kdl, &q_node, 0)?,
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Oracle 3 (continued): File-relative storage via symlinked config across
    // three distinguishable trees (local-fs walk)
    // -----------------------------------------------------------------------

    #[test]
    #[ignore = "requires an accepted local POSIX filesystem at / and /tmp (not overlayfs); run with --ignored in a tmpfs chroot or on a local-fs host"]
    #[allow(clippy::too_many_lines)]
    fn linux_storage_file_relative_symlinked_config_walk() -> TestResult {
        assert_local_root_fs()?;
        let bin = miraserve_bin();
        let tmp = TempDir::new_fixed('s')?;
        let base = &tmp.path;
        let euid = rustix::process::geteuid().as_raw();

        let certs = base.join("certs");
        let real_cfg_dir = base.join("real_cfg_tree");
        let link_cfg_dir = base.join("link_cfg_tree");
        let cwd_dir = base.join("cwd_tree");

        let real_store = real_cfg_dir.join("stores/app");
        let link_store = link_cfg_dir.join("stores/app");
        let cwd_store = cwd_dir.join("stores/app");
        let real_pub = real_cfg_dir.join("www");
        for d in [
            &certs,
            &real_cfg_dir,
            &link_cfg_dir,
            &cwd_dir,
            &real_store,
            &link_store,
            &cwd_store,
            &real_pub,
        ] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o750)?;
        }
        set_mode(&real_cfg_dir.join("stores"), 0o750)?;
        set_mode(&link_cfg_dir.join("stores"), 0o750)?;
        set_mode(&cwd_dir.join("stores"), 0o750)?;

        let (cert, key) = gen_dev_cert(&bin, &certs, "rel.example")?;
        let pub_key = write_pubkey(&certs)?;

        let storage_node = "storage \"stores/app\"";
        let rel_kdl = format!(
            "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }} }}\n\
             site \"rel.example\" {{\n\
                 root \"www\"\n\
                 ai-publish {{\n\
                     {storage_node}\n\
                     require-signature \"ed25519:{}\"\n\
                 }}\n\
             }}\n",
            kdl_escape_path(&cert),
            kdl_escape_path(&key),
            kdl_escape_path(&pub_key),
        );
        let real_cfg = real_cfg_dir.join("site.kdl");
        fs::write(&real_cfg, &rel_kdl)?;
        let sym_cfg = link_cfg_dir.join("site.kdl");
        symlink(&real_cfg, &sym_cfg)?;

        let canon_real_store = fs::canonicalize(&real_store)?;

        // Failure pair: ONLY `real_cfg_tree/stores/app` is 0775 while `link_cfg_tree` and `cwd_tree`
        // are clean 0750 -> MUST report W034 naming `<canon_real_cfg_tree>/stores/app`!
        set_mode(&real_store, 0o775)?;
        set_mode(&link_store, 0o750)?;
        set_mode(&cwd_store, 0o750)?;
        let (f_code, f_val, _, _) = run_check_json(
            &bin,
            &cwd_dir,
            &["--fs", "--no-sandbox", "--strict", "--trusted-paths"],
            &sym_cfg,
        )?;
        assert_eq!(
            f_code,
            Some(1),
            "bad real-cfg resolved store must fail --strict: {f_val}"
        );
        let fw = w034s(&f_val);
        assert_eq!(
            fw.len(),
            1,
            "expected 1 W034 at canonical real config dir: {f_val}"
        );
        assert_w034_full(
            fw.first().copied().ok_or("missing rel W034")?,
            "site[0].ai-publish.storage",
            &format!(
                "site 'rel.example' ai-publish storage '{}': first untrusted component '{}' \
                 (uid {euid}, mode 0775): group or other writable",
                canon_real_store.display(),
                canon_real_store.display(),
            ),
            HELP_GEN,
            &loc_of_occurrence(&rel_kdl, storage_node, 0)?,
        );

        // Pass pair: `real_cfg_tree/stores/app` is clean 0750 while BOTH `link_cfg_tree/stores/app`
        // AND `cwd_tree/stores/app` are 0777 -> MUST pass with exit 0 and 0 W034!
        set_mode(&real_store, 0o750)?;
        set_mode(&link_store, 0o777)?;
        set_mode(&cwd_store, 0o777)?;
        let (p_code, p_val, _, _) = run_check_json(
            &bin,
            &cwd_dir,
            &["--fs", "--no-sandbox", "--strict", "--trusted-paths"],
            &sym_cfg,
        )?;
        assert_eq!(
            p_code,
            Some(0),
            "clean real-cfg resolved store must pass even with 0777 link/cwd siblings: {p_val}"
        );
        assert_eq!(p_val.get("valid"), Some(&serde_json::Value::Bool(true)));
        assert!(w034s(&p_val).is_empty(), "expected 0 W034: {p_val}");

        Ok(())
    }

    // -----------------------------------------------------------------------
    // OverlayFS root rejection for ai-publish.storage (run in overlayfs container)
    // -----------------------------------------------------------------------

    #[test]
    #[ignore = "requires overlayfs (0x794c7630) at /; run with --ignored in an overlayfs container"]
    fn linux_storage_overlayfs_root_reported_not_verified() -> TestResult {
        let magic = fs_magic_of("/")?;
        assert_eq!(
            magic, 0x794C_7630,
            "precondition failed: / is 0x{magic:x}, requires overlayfs (0x794c7630)"
        );
        let bin = miraserve_bin();
        let tmp = TempDir::new_fixed('o')?;
        let base = &tmp.path;

        let certs = base.join("certs");
        let docroot = base.join("www");
        let store = base.join("store");
        for d in [&certs, &docroot, &store] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o750)?;
        }
        let (cert, key) = gen_dev_cert(&bin, &certs, "ovl.example")?;
        let pub_key = write_pubkey(&certs)?;
        let node = format!("storage \"{}\"", kdl_escape_path(&store));
        let kdl = format!(
            "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }} }}\n\
             site \"ovl.example\" {{\n\
                 root \"{}\"\n\
                 ai-publish {{\n\
                     {node}\n\
                     require-signature \"ed25519:{}\"\n\
                 }}\n\
             }}\n",
            kdl_escape_path(&cert),
            kdl_escape_path(&key),
            kdl_escape_path(&docroot),
            kdl_escape_path(&pub_key),
        );
        let cfg = base.join("ovl.kdl");
        fs::write(&cfg, &kdl)?;
        let (_code, val, _, _) = run_check_json(
            &bin,
            base,
            &["--fs", "--no-sandbox", "--trusted-paths"],
            &cfg,
        )?;
        let ws = w034s(&val);
        assert_eq!(
            ws.len(),
            1,
            "overlayfs root must report storage W034: {val}"
        );
        assert_w034_full(
            ws.first().copied().ok_or("missing overlay W034")?,
            "site[0].ai-publish.storage",
            &format!(
                "site 'ovl.example' ai-publish storage '{}': first untrusted component '/' \
                 (uid 0, mode 0755): could not be verified on this filesystem (filesystem 0x794c7630)",
                store.display(),
            ),
            HELP_GEN,
            &loc_of_occurrence(&kdl, &node, 0)?,
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Oracle 4: Non-root service UID mismatch on storage
    // -----------------------------------------------------------------------

    #[test]
    #[ignore = "requires non-root (euid != 0) and an accepted local POSIX filesystem at / and /tmp; run with --ignored as uid 1000 in a tmpfs chroot or on a local-fs host"]
    fn linux_storage_nonroot_observer_mismatch_adds_not_verified_w034() -> TestResult {
        let euid = rustix::process::geteuid().as_raw();
        assert_ne!(
            euid, 0,
            "precondition failed: requires non-root (euid != 0)"
        );
        assert_local_root_fs()?;
        let other_uid = if euid == 1000 { 1001 } else { 1000 };
        let bin = miraserve_bin();
        let tmp = TempDir::new_fixed('u')?;
        let base = &tmp.path;
        let certs = base.join("certs");
        let docroot = base.join("www");
        let store = base.join("store");
        for d in [&certs, &docroot, &store] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o750)?;
        }
        let (cert, key) = gen_dev_cert(&bin, &certs, "mis.example")?;
        let pub_key = write_pubkey(&certs)?;
        let node = format!("storage \"{}\"", kdl_escape_path(&store));
        let kdl = format!(
            "server {{\n\
                 listen \":443\"\n\
                 tls {{ cert \"{}\"; key \"{}\" }}\n\
                 sandbox {{ user \"{other_uid}\" }}\n\
             }}\n\
             site \"mis.example\" {{\n\
                 root \"{}\"\n\
                 ai-publish {{\n\
                     {node}\n\
                     require-signature \"ed25519:{}\"\n\
                 }}\n\
             }}\n",
            kdl_escape_path(&cert),
            kdl_escape_path(&key),
            kdl_escape_path(&docroot),
            kdl_escape_path(&pub_key),
        );
        let cfg = base.join("mis.kdl");
        fs::write(&cfg, &kdl)?;
        let loc = loc_of_occurrence(&kdl, &node, 0)?;

        let (code, val, _, _) = run_check_json(
            &bin,
            base,
            &["--fs", "--no-sandbox", "--strict", "--trusted-paths"],
            &cfg,
        )?;
        assert_eq!(code, Some(1), "observer mismatch must fail --strict: {val}");
        let ws = w034s(&val);
        assert_eq!(
            ws.len(),
            2,
            "expected walk owner-not-trusted + observer mismatch: {ws:#?}"
        );
        assert_w034_full(
            ws.first().copied().ok_or("missing walk W034")?,
            "site[0].ai-publish.storage",
            &format!(
                "site 'mis.example' ai-publish storage '{}': first untrusted component '{}' \
                 (uid {euid}, mode 0750): owner not trusted",
                store.display(),
                base.display(),
            ),
            HELP_GEN,
            &loc,
        );
        assert_w034_full(
            ws.get(1).copied().ok_or("missing mismatch W034")?,
            "site[0].ai-publish.storage",
            &format!(
                "site 'mis.example' ai-publish storage '{}': not verified: checked as uid {euid} \
                 but the configured service account is uid {other_uid}",
                store.display(),
            ),
            HELP_GEN,
            &loc,
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Oracle 4: Root multi-UID + actual service-UID run with supplementary
    // groups + hosting-panel layout with distinct PHP/tenant UIDs
    // -----------------------------------------------------------------------

    #[test]
    #[ignore = "requires root (euid == 0) and an accepted local POSIX filesystem at / and /tmp; run with --ignored as root in a tmpfs chroot or on a local-fs host"]
    #[allow(clippy::too_many_lines, clippy::similar_names)]
    fn linux_root_storage_multi_uid_service_uid_panel_and_supp_groups() -> TestResult {
        use rustix::fs::{Gid, Uid, chown};

        assert!(
            rustix::process::geteuid().is_root(),
            "precondition failed: requires root (euid == 0)"
        );
        assert_local_root_fs()?;

        let bin = miraserve_bin();
        let tmp = TempDir::new_fixed('k')?;
        let base = &tmp.path;
        // Let uid 1000 traverse `base` while keeping `base` root-owned 0755.
        set_mode(base, 0o755)?;

        let u0 = Some(Uid::from_raw(0));
        let g0 = Some(Gid::from_raw(0));
        let u1000 = Some(Uid::from_raw(1000));
        let g1000 = Some(Gid::from_raw(1000));
        let u2000 = Some(Uid::from_raw(2000));
        let g2000 = Some(Gid::from_raw(2000));
        let u3001 = Some(Uid::from_raw(3001));
        let g3001 = Some(Gid::from_raw(3001));

        let certs = base.join("certs");
        let php_dir = base.join("run_php");
        let home_dir = base.join("home");
        let tenant_a_home = home_dir.join("usr_a");
        let tenant_a_root = tenant_a_home.join("public_html");
        let tenant_b_home = home_dir.join("usr_b");
        let tenant_b_root = tenant_b_home.join("public_html");
        let acme_dir = base.join("acme");
        let log_dir = base.join("logs");
        let store_svc = base.join("store_svc");
        let store_root = base.join("store_root");
        let store_tenant = base.join("store_tenant");
        let sticky_dir = base.join("sticky");
        let store_sticky_tenant = sticky_dir.join("tenant_store");
        let supp_parent = base.join("supp_parent");
        let store_supp = supp_parent.join("store_supp");
        let store_gw_supp = supp_parent.join("store_gw_supp");

        for d in [
            &certs,
            &php_dir,
            &home_dir,
            &tenant_a_home,
            &tenant_a_root,
            &tenant_b_home,
            &tenant_b_root,
            &acme_dir,
            &log_dir,
            &store_svc,
            &store_root,
            &store_tenant,
            &sticky_dir,
            &store_sticky_tenant,
            &supp_parent,
            &store_supp,
            &store_gw_supp,
        ] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o755)?;
        }

        let (cert, key) = gen_dev_cert(&bin, &certs, "a.example,b.example,pub.example")?;
        let pub_key = write_pubkey(&certs)?;
        // Panel certs/keys & pubkey readable by group 1000 (`0640 root:1000` in `0750 root:1000`).
        set_mode(&certs, 0o750)?;
        chown(&certs, u0, g1000)?;
        set_mode(&cert, 0o640)?;
        chown(&cert, u0, g1000)?;
        set_mode(&key, 0o640)?;
        chown(&key, u0, g1000)?;
        set_mode(&pub_key, 0o640)?;
        chown(&pub_key, u0, g1000)?;

        // PHP-FPM socket directory owned by producer uid 2000 (0755) with 2 pools.
        let sock_a = php_dir.join("usr_a.sock");
        let sock_b = php_dir.join("usr_b.sock");
        let _la = UnixListener::bind(&sock_a)?;
        let _lb = UnixListener::bind(&sock_b)?;
        set_mode(&sock_a, 0o660)?;
        set_mode(&sock_b, 0o660)?;
        chown(&php_dir, u2000, g2000)?;
        chown(&sock_a, u2000, g1000)?;
        chown(&sock_b, u2000, g1000)?;

        // Tenant homes & roots owned by tenant uid 3001 (`0750 3001:1000`, `0755 3001:3001`).
        set_mode(&tenant_a_home, 0o750)?;
        chown(&tenant_a_home, u3001, g1000)?;
        chown(&tenant_a_root, u3001, g3001)?;
        set_mode(&tenant_b_home, 0o750)?;
        chown(&tenant_b_home, u3001, g1000)?;
        chown(&tenant_b_root, u3001, g3001)?;

        // Service-owned ACME (0700 1000:1000) & rotating logs (0750 1000:1000).
        set_mode(&acme_dir, 0o700)?;
        chown(&acme_dir, u1000, g1000)?;
        set_mode(&log_dir, 0o750)?;
        chown(&log_dir, u1000, g1000)?;

        // Publish stores with distinct owners & modes:
        set_mode(&store_svc, 0o750)?;
        chown(&store_svc, u1000, g1000)?;
        set_mode(&store_root, 0o750)?;
        chown(&store_root, u0, g1000)?;
        set_mode(&store_tenant, 0o755)?;
        chown(&store_tenant, u3001, g3001)?;
        set_mode(&sticky_dir, 0o1777)?;
        chown(&sticky_dir, u0, g0)?;
        set_mode(&store_sticky_tenant, 0o750)?;
        chown(&store_sticky_tenant, u3001, g3001)?;
        // Supplementary-group parent `0750 root:2000`: traversable by uid 1000 ONLY via supp group 2000!
        set_mode(&supp_parent, 0o750)?;
        chown(&supp_parent, u0, g2000)?;
        set_mode(&store_supp, 0o750)?;
        chown(&store_supp, u1000, g1000)?;
        set_mode(&store_gw_supp, 0o770)?;
        chown(&store_gw_supp, u1000, g2000)?;

        let run_as_service =
            |args: &[&str],
             cfg: &Path|
             -> Result<(Option<i32>, serde_json::Value), Box<dyn std::error::Error>> {
                let cfg_s = cfg.to_str().ok_or("non-utf8 cfg")?;
                let bin_s = bin.to_str().ok_or("non-utf8 bin")?;
                let mut full = vec![
                    "--reuid=1000",
                    "--regid=1000",
                    "--groups=1000,2000",
                    bin_s,
                    "check",
                ];
                full.extend_from_slice(args);
                full.push("--format");
                full.push("json");
                full.push(cfg_s);
                let (code, stdout, stderr) = run_bin(Path::new("setpriv"), base, &full, None)?;
                let val: serde_json::Value = serde_json::from_slice(&stdout).map_err(|e| {
                    format!(
                        "setpriv invalid json ({e}); stdout:\n{}\nstderr:\n{}",
                        String::from_utf8_lossy(&stdout),
                        String::from_utf8_lossy(&stderr),
                    )
                })?;
                Ok((code, val))
            };

        let acme_s = acme_dir.to_string_lossy().into_owned();
        let log_f = log_dir.join("server.log").to_string_lossy().into_owned();
        let panel_args = [
            "--fs",
            "--no-sandbox",
            "--trusted-paths",
            "--acme-dir",
            &acme_s,
            "--log-file",
            &log_f,
            "--log-max-bytes",
            "1024",
        ];

        // 1. Panel layout without publish, with clean service store, and with tenant store:
        //    tested BOTH as root (with sandbox.user "1000") AND as actual service uid 1000!
        let panel_base = format!(
            "server {{\n\
                 listen \":443\"\n\
                 tls {{ cert \"{}\"; key \"{}\" }}\n\
                 sandbox {{ user \"1000\"; read-tree \"{}\"; socket-tree \"{}\" }}\n\
             }}\n\
             site \"a.example\" {{\n\
                 owner-dir \"{}\"\n\
                 root \"{}\"\n\
                 route \"*.php\" {{ fastcgi-pass \"unix:{}\" }}\n\
             }}\n\
             site \"b.example\" {{\n\
                 owner-dir \"{}\"\n\
                 root \"{}\"\n\
                 route \"*.php\" {{ fastcgi-pass \"unix:{}\" }}\n\
             }}\n",
            kdl_escape_path(&cert),
            kdl_escape_path(&key),
            kdl_escape_path(&home_dir),
            kdl_escape_path(&php_dir),
            kdl_escape_path(&tenant_a_home),
            kdl_escape_path(&tenant_a_root),
            kdl_escape_path(&sock_a),
            kdl_escape_path(&tenant_b_home),
            kdl_escape_path(&tenant_b_root),
            kdl_escape_path(&sock_b),
        );

        let panel_no_pub = base.join("panel_no_pub.kdl");
        fs::write(&panel_no_pub, &panel_base)?;
        let panel_svc_store = base.join("panel_svc_store.kdl");
        fs::write(
            &panel_svc_store,
            format!(
                "{panel_base}\
                 site \"pub.example\" {{\n\
                     ai-publish {{\n\
                         storage \"{}\"\n\
                         require-signature \"ed25519:{}\"\n\
                     }}\n\
                 }}\n",
                kdl_escape_path(&store_svc),
                kdl_escape_path(&pub_key),
            ),
        )?;
        let bad_tenant_node = format!("storage \"{}\"", kdl_escape_path(&store_tenant));
        let panel_tenant_kdl = format!(
            "{panel_base}\
             site \"pub.example\" {{\n\
                 ai-publish {{\n\
                     {bad_tenant_node}\n\
                     require-signature \"ed25519:{}\"\n\
                 }}\n\
             }}\n",
            kdl_escape_path(&pub_key),
        );
        let panel_tenant_store = base.join("panel_tenant_store.kdl");
        fs::write(&panel_tenant_store, &panel_tenant_kdl)?;
        let bad_tenant_loc = loc_of_occurrence(&panel_tenant_kdl, &bad_tenant_node, 0)?;

        for cfg in [&panel_no_pub, &panel_svc_store, &panel_tenant_store] {
            set_mode(cfg, 0o640)?;
            chown(cfg, u0, g1000)?;
        }

        // Check as BOTH root (`sandbox.user "1000"`) and actual service uid 1000 (`groups=1000,2000`):
        for mode in ["root", "service_uid_1000"] {
            let val_none = if mode == "root" {
                run_check_json(&bin, base, &panel_args, &panel_no_pub)?.1
            } else {
                run_as_service(&panel_args, &panel_no_pub)?.1
            };
            let w_none = w034s(&val_none);
            assert_eq!(
                w_none.len(),
                3,
                "{mode} panel_no_pub must have 1+2 php W034s: {val_none}"
            );

            let val_svc = if mode == "root" {
                run_check_json(&bin, base, &panel_args, &panel_svc_store)?.1
            } else {
                run_as_service(&panel_args, &panel_svc_store)?.1
            };
            let w_svc = w034s(&val_svc);
            assert_eq!(
                w_svc, w_none,
                "{mode} panel with clean service store must add 0 W034"
            );

            let val_ten = if mode == "root" {
                run_check_json(&bin, base, &panel_args, &panel_tenant_store)?.1
            } else {
                run_as_service(&panel_args, &panel_tenant_store)?.1
            };
            let w_ten = w034s(&val_ten);
            assert_eq!(
                w_ten.len(),
                4,
                "{mode} panel with tenant store must have 3+1 W034s: {val_ten}"
            );
            assert_eq!(
                w_ten.get(..3),
                Some(w_none.as_slice()),
                "{mode} first 3 panel W034s must remain identical"
            );
            assert_w034_full(
                w_ten.get(3).copied().ok_or("missing 4th W034")?,
                "site[2].ai-publish.storage",
                &format!(
                    "site 'pub.example' ai-publish storage '{}': first untrusted component '{}' \
                     (uid 3001, mode 0755): owner not trusted",
                    store_tenant.display(),
                    store_tenant.display(),
                ),
                HELP_GEN,
                &bad_tenant_loc,
            );
        }

        // 2. Root with sandbox.user UNSET -> uid-1000 store emits W034 (`owner not trusted`)!
        let unset_node = format!("storage \"{}\"", kdl_escape_path(&store_svc));
        let unset_kdl = format!(
            "server {{ listen \":443\"; tls {{ cert \"{}\"; key \"{}\" }} }}\n\
             site \"pub.example\" {{\n\
                 ai-publish {{\n\
                     {unset_node}\n\
                     require-signature \"ed25519:{}\"\n\
                 }}\n\
             }}\n",
            kdl_escape_path(&cert),
            kdl_escape_path(&key),
            kdl_escape_path(&pub_key),
        );
        let unset_cfg = base.join("root_unset.kdl");
        fs::write(&unset_cfg, &unset_kdl)?;
        let (_uc, u_val, _, _) = run_check_json(
            &bin,
            base,
            &["--fs", "--no-sandbox", "--trusted-paths"],
            &unset_cfg,
        )?;
        let uw = w034s(&u_val);
        assert_eq!(
            uw.len(),
            1,
            "root with sandbox.user unset must reject uid-1000 store: {u_val}"
        );
        assert_w034_full(
            uw.first().copied().ok_or("missing unset W034")?,
            "site[0].ai-publish.storage",
            &format!(
                "site 'pub.example' ai-publish storage '{}': first untrusted component '{}' \
                 (uid 1000, mode 0750): owner not trusted",
                store_svc.display(),
                store_svc.display(),
            ),
            HELP_GEN,
            &loc_of_occurrence(&unset_kdl, &unset_node, 0)?,
        );

        // 3. Foreign-owned existing child in sticky dir (`1777 root:root` / `0750 3001:3001`) -> W034!
        let st_node = format!("storage \"{}\"", kdl_escape_path(&store_sticky_tenant));
        let st_kdl = format!(
            "server {{\n\
                 listen \":443\"\n\
                 tls {{ cert \"{}\"; key \"{}\" }}\n\
                 sandbox {{ user \"1000\" }}\n\
             }}\n\
             site \"pub.example\" {{\n\
                 ai-publish {{\n\
                     {st_node}\n\
                     require-signature \"ed25519:{}\"\n\
                 }}\n\
             }}\n",
            kdl_escape_path(&cert),
            kdl_escape_path(&key),
            kdl_escape_path(&pub_key),
        );
        let st_cfg = base.join("sticky_tenant.kdl");
        fs::write(&st_cfg, &st_kdl)?;
        let (_stc, st_val, _, _) = run_check_json(
            &bin,
            base,
            &["--fs", "--no-sandbox", "--trusted-paths"],
            &st_cfg,
        )?;
        let stw = w034s(&st_val);
        assert_eq!(
            stw.len(),
            1,
            "tenant child in sticky dir must emit W034: {st_val}"
        );
        assert_w034_full(
            stw.first().copied().ok_or("missing sticky tenant W034")?,
            "site[0].ai-publish.storage",
            &format!(
                "site 'pub.example' ai-publish storage '{}': first untrusted component '{}' \
                 (uid 3001, mode 0750): owner not trusted",
                store_sticky_tenant.display(),
                store_sticky_tenant.display(),
            ),
            HELP_GEN,
            &loc_of_occurrence(&st_kdl, &st_node, 0)?,
        );

        // 4. Actual service-UID (uid 1000, gid 1000, supplementary group 2000) deployment effects:
        //    (a) `supp_parent` (0750 root:2000) / `store_supp` (0750 1000:1000) -> exit 0, 0 W034!
        //    (b) `supp_parent` (0750 root:2000) / `store_gw_supp` (0770 1000:2000) -> exit 1, 1 W034!
        //    (c) `store_root` (0750 root:1000) -> 0 W034 (trusted owner/mode), while --fs writable
        //        probe fails with exit 1 (`errors.len() == 1`), proving W034 != service write access!
        let supp_ok_cfg = base.join("supp_ok.kdl");
        fs::write(
            &supp_ok_cfg,
            format!(
                "server {{\n\
                     listen \":443\"\n\
                     tls {{ cert \"{}\"; key \"{}\" }}\n\
                     sandbox {{ user \"1000\" }}\n\
                 }}\n\
                 site \"pub.example\" {{\n\
                     ai-publish {{\n\
                         storage \"{}\"\n\
                         require-signature \"ed25519:{}\"\n\
                     }}\n\
                 }}\n",
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&store_supp),
                kdl_escape_path(&pub_key),
            ),
        )?;
        set_mode(&supp_ok_cfg, 0o640)?;
        chown(&supp_ok_cfg, u0, g1000)?;
        let (sok_c, sok_v) = run_as_service(
            &["--fs", "--no-sandbox", "--strict", "--trusted-paths"],
            &supp_ok_cfg,
        )?;
        assert_eq!(
            sok_c,
            Some(0),
            "service uid with supp group 2000 must pass --strict: {sok_v}"
        );
        assert_eq!(
            sok_v
                .get("errors")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(0)
        );
        assert_eq!(
            sok_v
                .get("warnings")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(0)
        );

        let gw_node = format!("storage \"{}\"", kdl_escape_path(&store_gw_supp));
        let gw_kdl = format!(
            "server {{\n\
                 listen \":443\"\n\
                 tls {{ cert \"{}\"; key \"{}\" }}\n\
                 sandbox {{ user \"1000\" }}\n\
             }}\n\
             site \"pub.example\" {{\n\
                 ai-publish {{\n\
                     {gw_node}\n\
                     require-signature \"ed25519:{}\"\n\
                 }}\n\
             }}\n",
            kdl_escape_path(&cert),
            kdl_escape_path(&key),
            kdl_escape_path(&pub_key),
        );
        let supp_gw_cfg = base.join("supp_gw.kdl");
        fs::write(&supp_gw_cfg, &gw_kdl)?;
        set_mode(&supp_gw_cfg, 0o640)?;
        chown(&supp_gw_cfg, u0, g1000)?;
        let (sgw_c, sgw_v) = run_as_service(
            &["--fs", "--no-sandbox", "--strict", "--trusted-paths"],
            &supp_gw_cfg,
        )?;
        assert_eq!(
            sgw_c,
            Some(1),
            "0770 group-writable store must fail --strict: {sgw_v}"
        );
        let sgw_w = w034s(&sgw_v);
        assert_eq!(sgw_w.len(), 1);
        assert_w034_full(
            sgw_w.first().copied().ok_or("missing supp gw W034")?,
            "site[0].ai-publish.storage",
            &format!(
                "site 'pub.example' ai-publish storage '{}': first untrusted component '{}' \
                 (uid 1000, mode 0770): group or other writable",
                store_gw_supp.display(),
                store_gw_supp.display(),
            ),
            HELP_GEN,
            &loc_of_occurrence(&gw_kdl, &gw_node, 0)?,
        );

        let root_ro_cfg = base.join("root_ro.kdl");
        fs::write(
            &root_ro_cfg,
            format!(
                "server {{\n\
                     listen \":443\"\n\
                     tls {{ cert \"{}\"; key \"{}\" }}\n\
                     sandbox {{ user \"1000\" }}\n\
                 }}\n\
                 site \"pub.example\" {{\n\
                     ai-publish {{\n\
                         storage \"{}\"\n\
                         require-signature \"ed25519:{}\"\n\
                     }}\n\
                 }}\n",
                kdl_escape_path(&cert),
                kdl_escape_path(&key),
                kdl_escape_path(&store_root),
                kdl_escape_path(&pub_key),
            ),
        )?;
        set_mode(&root_ro_cfg, 0o640)?;
        chown(&root_ro_cfg, u0, g1000)?;
        let (rro_c, rro_v) =
            run_as_service(&["--fs", "--no-sandbox", "--trusted-paths"], &root_ro_cfg)?;
        assert_eq!(
            rro_c,
            Some(1),
            "root-owned 0750 store fails --fs writable probe as uid 1000: {rro_v}"
        );
        assert_eq!(
            rro_v
                .get("errors")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(1),
            "expected 1 --fs writable error: {rro_v}"
        );
        assert!(
            w034s(&rro_v).is_empty(),
            "root-owned 0750 store must emit 0 W034 (write access is outside W034): {rro_v}"
        );

        Ok(())
    }
}

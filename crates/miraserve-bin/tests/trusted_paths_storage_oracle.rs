//! Stage 3 (0.1.8) oracle tests for `site[N].ai-publish.storage` under
//! `miraserve check --fs --trusted-paths` (`W034`).
//!
//! Covers:
//! 1. Flag-off differential parity against `bef6865` (`MIRASERVE_BASELINE_BIN`) across text/JSON,
//!    plain/`--fs`, `--strict`, `--allow-warning`, `--quiet`, `--writable-set`, stdin, rejected
//!    padded storage, and `reload --dry-run`.
//! 2. Flag-on parity for the five existing classes on old-only configs (byte-identical modulo the
//!    exact narrowed-note literal) and on mixed configs (old W034 vector, order, observer note,
//!    and socket-prefix notes unchanged, with `site[N].ai-publish.storage` appended after the
//!    rotating-log pass in site source index order).
//! 3. Storage diagnostics on real accepted local Linux filesystems with exact literal assertions
//!    for every JSON field (`code`, `severity`, `path`, `message`, `help`, absence of `label`, and
//!    exact `location`), covering clean `0750`, foreign `0755`, writable parent/leaf/sticky leaf,
//!    wrong type, missing leaf/intermediate, sticky existing/missing child, trusted/bad/loop
//!    symlinks, two sites sharing a store, quarantined site, writable descendants under a clean
//!    store, Windows-drive spelling, file-relative storage via a symlinked config across three
//!    distinguishable trees, padded rejected input, and stdin relative storage.
//! 4. Deployment & multi-UID effects: actual service-UID execution (with effective supplementary
//!    groups), root with `sandbox.user` set and unset, distinct PHP/tenant UIDs, baseline-clean
//!    `--strict`/`--allow-warning W034`, and separation of `W034` counts from `--fs` write errors.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[path = "../../miraserve-config/tests/common/mod.rs"]
mod kdl_test_util;

use kdl_test_util::kdl_escape_path;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type RunOutput = (Option<i32>, Vec<u8>, Vec<u8>);

fn miraserve_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_miraserve"))
}

fn baseline_bin() -> Option<PathBuf> {
    std::env::var_os("MIRASERVE_BASELINE_BIN").map(PathBuf::from)
}

#[cfg(target_os = "linux")]
fn v017_bin() -> Option<PathBuf> {
    std::env::var_os("MIRASERVE_V017_BIN").map(PathBuf::from)
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Result<Self, std::io::Error> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = PathBuf::from(format!("/tmp/ms-tps-{tag}-{}-{nanos}", std::process::id()));
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

fn gen_dev_cert(dir: &Path, hosts: &str) -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error>> {
    let cert = dir.join("server.crt");
    let key = dir.join("server.key");
    let (code, _, stderr) = run_bin(
        &miraserve_bin(),
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

// ---------------------------------------------------------------------------
// 1. Flag-off differential parity against bef6865 (cross-platform)
// ---------------------------------------------------------------------------

#[test]
#[allow(clippy::too_many_lines)]
fn flag_off_bef6865_differential_parity() -> TestResult {
    let bin = miraserve_bin();
    let baseline = baseline_bin();
    let tmp = TempDir::new("flag-off")?;
    let base = &tmp.path;

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

    let (cert, key) = gen_dev_cert(&certs, "pub.example,miss.example")?;
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
    fs::write(
        &miss_cfg,
        format!(
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
        ),
    )?;

    // Rejected config (trailing space on ai-publish.storage -> E202).
    let padded_cfg = base.join("padded.kdl");
    fs::write(
        &padded_cfg,
        format!(
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
        ),
    )?;

    let cfg_s = cfg.to_str().ok_or("non-utf8 cfg")?;
    let miss_s = miss_cfg.to_str().ok_or("non-utf8 miss cfg")?;
    let padded_s = padded_cfg.to_str().ok_or("non-utf8 padded cfg")?;
    let acme_s = acme.to_str().ok_or("non-utf8 acme")?;

    let cases: [(&str, Vec<&str>, Option<&[u8]>); 13] = [
        ("check_text", vec!["check", cfg_s], None),
        ("check_json", vec!["check", "--format", "json", cfg_s], None),
        ("check_quiet", vec!["check", "--quiet", cfg_s], None),
        (
            "check_fs",
            vec!["check", "--fs", "--acme-dir", acme_s, cfg_s],
            None,
        ),
        (
            "check_fs_json",
            vec![
                "check",
                "--fs",
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
            vec!["check", "--fs", "--strict", "--acme-dir", acme_s, cfg_s],
            None,
        ),
        (
            "check_fs_strict_allow_w002",
            vec![
                "check",
                "--fs",
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
            vec!["check", "--fs", "--quiet", "--acme-dir", acme_s, cfg_s],
            None,
        ),
        (
            "check_fs_writable_set",
            vec![
                "check",
                "--fs",
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
            vec!["check", "--fs", "--format", "json", miss_s],
            None,
        ),
        (
            "check_fs_rejected_padded",
            vec!["check", "--fs", "--format", "json", padded_s],
            None,
        ),
        (
            "reload_dry_run_valid",
            vec!["reload", "--dry-run", "--format", "json", "--config", cfg_s],
            None,
        ),
    ];

    let mut extra_cases: Vec<(&str, Vec<&str>, Option<&[u8]>)> = cases.into_iter().collect();
    extra_cases.push((
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
    ));

    for (name, args, stdin_bytes) in &extra_cases {
        let (code, stdout, stderr) = run_bin(&bin, base, args, *stdin_bytes)?;
        match *name {
            "check_text" | "check_fs" => {
                assert_eq!(
                    code,
                    Some(0),
                    "{name} failed: {}",
                    String::from_utf8_lossy(&stderr)
                );
                assert!(
                    !String::from_utf8_lossy(&stderr).contains("W034"),
                    "{name} emitted W034"
                );
            }
            "check_quiet" | "check_fs_quiet" => {
                assert_eq!(code, Some(0), "{name} failed");
                assert_eq!(stdout, b"", "{name} stdout must be empty");
                assert!(!String::from_utf8_lossy(&stderr).contains("W034"));
            }
            "check_json" | "check_stdin_json" => {
                assert_eq!(code, Some(0), "{name} failed");
                let v: serde_json::Value = serde_json::from_slice(&stdout)?;
                assert_eq!(v.get("valid"), Some(&serde_json::Value::Bool(true)));
                assert_eq!(
                    v.pointer("/warnings/0/code")
                        .and_then(serde_json::Value::as_str),
                    Some("W002")
                );
            }
            "check_fs_json" => {
                assert_eq!(code, Some(0), "{name} failed");
                let v: serde_json::Value = serde_json::from_slice(&stdout)?;
                let warns = v
                    .get("warnings")
                    .and_then(serde_json::Value::as_array)
                    .ok_or("missing warnings")?;
                assert!(
                    warns
                        .iter()
                        .all(|w| w.get("code").and_then(serde_json::Value::as_str) != Some("W034")),
                    "flag off must never emit W034: {v}"
                );
            }
            "check_fs_strict" => {
                assert_eq!(code, Some(1), "W002 must fail --strict");
                assert!(!String::from_utf8_lossy(&stderr).contains("W034"));
            }
            "check_fs_strict_allow_w002" => {
                let v: serde_json::Value = serde_json::from_slice(&stdout)?;
                let has_w035 = v
                    .get("warnings")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|a| {
                        a.iter().any(|w| {
                            w.get("code").and_then(serde_json::Value::as_str) == Some("W035")
                        })
                    });
                assert_eq!(code, Some(i32::from(has_w035)), "{name}: {v}");
                assert!(
                    v.get("warnings")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|a| a.iter().all(|w| {
                            w.get("code").and_then(serde_json::Value::as_str) != Some("W034")
                        })),
                    "flag off must never emit W034: {v}"
                );
            }
            "check_fs_writable_set" => {
                assert_eq!(code, Some(0), "{name} failed");
                assert!(String::from_utf8_lossy(&stdout).starts_with("landlock "));
                assert!(!String::from_utf8_lossy(&stderr).contains("W034"));
            }
            "check_fs_missing_parent" => {
                assert_eq!(code, Some(1));
                let v: serde_json::Value = serde_json::from_slice(&stdout)?;
                assert_eq!(v.get("valid"), Some(&serde_json::Value::Bool(false)));
                assert_eq!(
                    v.get("errors")
                        .and_then(serde_json::Value::as_array)
                        .map(Vec::len),
                    Some(1)
                );
            }
            "check_fs_rejected_padded" => {
                assert_eq!(code, Some(1));
                let v: serde_json::Value = serde_json::from_slice(&stdout)?;
                assert_eq!(
                    v.pointer("/errors/0/code")
                        .and_then(serde_json::Value::as_str),
                    Some("E202")
                );
                assert_eq!(
                    v.pointer("/errors/0/path")
                        .and_then(serde_json::Value::as_str),
                    Some("site[0].ai-publish.storage")
                );
            }
            "reload_dry_run_valid" => {
                assert_eq!(code, Some(0));
                let v: serde_json::Value = serde_json::from_slice(&stdout)?;
                assert_eq!(
                    v.get("outcome").and_then(serde_json::Value::as_str),
                    Some("dry_run_passed")
                );
            }
            "reload_dry_run_rejected" => {
                assert_eq!(code, Some(1));
                let v: serde_json::Value = serde_json::from_slice(&stdout)?;
                assert_eq!(
                    v.get("outcome").and_then(serde_json::Value::as_str),
                    Some("dry_run_refused")
                );
            }
            other => return Err(format!("unhandled case {other}").into()),
        }

        if let Some(base_bin) = &baseline {
            let (b_code, b_stdout, b_stderr) = run_bin(base_bin, base, args, *stdin_bytes)?;
            assert_eq!(code, b_code, "exit code mismatch vs bef6865 on {name}");
            assert_eq!(
                stdout,
                b_stdout,
                "stdout mismatch vs bef6865 on {name}:\n--- bef6865 ---\n{}\n--- candidate ---\n{}",
                String::from_utf8_lossy(&b_stdout),
                String::from_utf8_lossy(&stdout),
            );
            assert_eq!(
                stderr,
                b_stderr,
                "stderr mismatch vs bef6865 on {name}:\n--- bef6865 ---\n{}\n--- candidate ---\n{}",
                String::from_utf8_lossy(&b_stderr),
                String::from_utf8_lossy(&stderr),
            );
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 2. Non-Linux flag-on with storage remains unchanged
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "linux"))]
#[test]
fn non_linux_trusted_paths_with_storage_unchanged() -> TestResult {
    let bin = miraserve_bin();
    let baseline = baseline_bin();
    let tmp = TempDir::new("nonlinux-store")?;
    let base = &tmp.path;

    let certs = base.join("certs");
    let docroot = base.join("www");
    let bad_store = base.join("store_bad");
    for d in [&certs, &docroot, &bad_store] {
        fs::create_dir_all(d)?;
        set_mode(d, 0o750)?;
    }
    set_mode(&bad_store, 0o777)?;
    let (cert, key) = gen_dev_cert(&certs, "pub.example")?;
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

    for args in [
        vec!["check", "--fs", "--strict", "--trusted-paths", cfg_s],
        vec![
            "check",
            "--fs",
            "--strict",
            "--trusted-paths",
            "--format",
            "json",
            cfg_s,
        ],
        vec!["check", "--fs", "--trusted-paths", "--writable-set", cfg_s],
        vec!["check", "--fs", "--trusted-paths", "--quiet", cfg_s],
    ] {
        let (code, stdout, stderr) = run_bin(&bin, base, &args, None)?;
        assert_eq!(code, Some(0), "non-linux args {args:?} failed");
        assert!(!String::from_utf8_lossy(&stderr).contains("W034"));
        if args.contains(&"json") {
            let v: serde_json::Value = serde_json::from_slice(&stdout)?;
            assert_eq!(
                v.get("notes"),
                Some(&serde_json::json!([
                    "--trusted-paths is Linux-only; no paths were verified"
                ]))
            );
            assert_eq!(
                v.get("warnings")
                    .and_then(serde_json::Value::as_array)
                    .map(Vec::len),
                Some(0)
            );
        }
        if let Some(base_bin) = &baseline {
            let (b_code, b_stdout, b_stderr) = run_bin(base_bin, base, &args, None)?;
            assert_eq!(code, b_code);
            assert_eq!(stdout, b_stdout);
            assert_eq!(stderr, b_stderr);
        }
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

    fn require_local_root_fs(test_name: &str) -> Result<bool, std::io::Error> {
        for p in ["/", "/tmp"] {
            let m = fs_magic_of(p)?;
            if !is_accepted_local_fs(m) {
                eprintln!(
                    "skipping {test_name}: {p} is on filesystem 0x{m:x} \
                     (not an accepted non-stacking local POSIX filesystem)"
                );
                return Ok(false);
            }
        }
        Ok(true)
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

    fn run_check_json(
        bin: &Path,
        cwd: &Path,
        args: &[&str],
        cfg: &Path,
    ) -> Result<(Option<i32>, serde_json::Value, Vec<u8>, Vec<u8>), Box<dyn std::error::Error>>
    {
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
        Ok(serde_json::json!({
            "line": line,
            "column": column,
            "offset": offset,
            "length": needle.len(),
        }))
    }

    fn assert_w034_full(
        issue: &serde_json::Value,
        expected_path: &str,
        expected_message: &str,
        expected_help: &str,
        expected_loc: &serde_json::Value,
    ) -> TestResult {
        assert_eq!(jstr(issue, "code"), Some("W034"), "issue: {issue}");
        assert_eq!(jstr(issue, "severity"), Some("warning"), "issue: {issue}");
        assert_eq!(jstr(issue, "path"), Some(expected_path), "issue: {issue}");
        assert_eq!(
            jstr(issue, "message"),
            Some(expected_message),
            "issue: {issue}"
        );
        assert_eq!(jstr(issue, "help"), Some(expected_help), "issue: {issue}");
        assert!(
            issue.get("label").is_none(),
            "label must be absent: {issue}"
        );
        let actual_loc = issue.get("location").ok_or("missing location")?;
        assert_eq!(
            actual_loc.get("line"),
            expected_loc.get("line"),
            "line mismatch: actual={actual_loc}, expected={expected_loc}, issue={issue}"
        );
        assert_eq!(
            actual_loc.get("column"),
            expected_loc.get("column"),
            "column mismatch: actual={actual_loc}, expected={expected_loc}, issue={issue}"
        );
        assert_eq!(
            actual_loc.get("offset"),
            expected_loc.get("offset"),
            "offset mismatch: actual={actual_loc}, expected={expected_loc}, issue={issue}"
        );
        // `kdl` node spans cover at least the node text (`storage "..."`).
        let act_len = actual_loc
            .get("length")
            .and_then(serde_json::Value::as_u64)
            .ok_or("missing length")?;
        let exp_len = expected_loc
            .get("length")
            .and_then(serde_json::Value::as_u64)
            .ok_or("missing expected length")?;
        assert!(
            act_len == exp_len || act_len == exp_len + 1,
            "length mismatch: actual={actual_loc}, expected={expected_loc}, issue={issue}"
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Oracle 2: Flag on — old-only and mixed-config exact parity
    // -----------------------------------------------------------------------

    #[test]
    #[allow(clippy::too_many_lines)]
    fn linux_flag_on_old_only_and_mixed_config_exact_parity() -> TestResult {
        if !require_local_root_fs("linux_flag_on_old_only_and_mixed_config_exact_parity")? {
            return Ok(());
        }
        let bin = miraserve_bin();
        let tmp = TempDir::new("parity-on")?;
        let base = &tmp.path;
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

        let (cert, key) = gen_dev_cert(&certs, "s0.example,s1.example")?;
        let pub_key = write_pubkey(&certs)?;

        // Part A: Old-only config (no ai-publish.storage) covering all 5 existing classes +
        // excluded bad read-tree/site.root + absent socket prefix note + relative fastcgi-pass.
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

        let acme_s = acme_bad.to_string_lossy().into_owned();
        let log_s = log_f.to_string_lossy().into_owned();
        let acc_s = acc_f.to_string_lossy().into_owned();
        let common_args = [
            "--fs",
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
            old_notes.first().copied(),
            Some(expected_default_observer_note().as_str())
        );
        assert_eq!(old_notes.get(1).copied(), Some(NEW_NARROWED));
        assert_eq!(
            old_notes.get(2).copied(),
            Some(
                format!(
                    "trusted-paths: site 's0.example' FastCGI Unix socket '{}': inspected existing \
                     prefix '{}' (stopped at 'absent.sock', not found by this lookup)",
                    absent_sock.display(),
                    trusted.display(),
                )
                .as_str()
            )
        );
        assert_eq!(old_notes.len(), 3, "unexpected notes: {old_notes:?}");

        // Differential comparison of old-only config against bef6865 (and v0.1.7 if provided):
        // whole JSON AND text output must be byte-identical modulo ONLY the narrowed-note literal!
        let old_cfg_s = old_cfg.to_str().ok_or("non-utf8 old_cfg")?;
        let mut text_args = vec!["check"];
        text_args.extend_from_slice(&common_args);
        text_args.push(old_cfg_s);
        let (old_txt_code, old_txt_out, old_txt_err) = run_bin(&bin, base, &text_args, None)?;

        for (label, maybe_ref_bin) in [("bef6865", baseline_bin()), ("v0.1.7", v017_bin())] {
            if let Some(ref_bin) = maybe_ref_bin {
                let (b_code, _b_val, b_stdout, b_stderr) =
                    run_check_json(&ref_bin, base, &common_args, &old_cfg)?;
                assert_eq!(old_code, b_code, "old-only JSON exit mismatch vs {label}");
                let b_stdout_s = String::from_utf8(b_stdout)?;
                assert!(
                    b_stdout_s.contains(OLD_NARROWED),
                    "{label} JSON stdout missing OLD_NARROWED"
                );
                assert_eq!(
                    String::from_utf8(old_stdout.clone())?,
                    b_stdout_s.replacen(OLD_NARROWED, NEW_NARROWED, 1),
                    "old-only JSON stdout mismatch vs {label} modulo narrowed note"
                );
                assert_eq!(
                    old_stderr, b_stderr,
                    "old-only JSON stderr mismatch vs {label}"
                );

                let (bt_code, bt_out, bt_err) = run_bin(&ref_bin, base, &text_args, None)?;
                assert_eq!(
                    old_txt_code, bt_code,
                    "old-only text exit mismatch vs {label}"
                );
                let bt_out_s = String::from_utf8(bt_out)?;
                let bt_err_s = String::from_utf8(bt_err)?;
                assert_eq!(
                    String::from_utf8(old_txt_out.clone())?,
                    bt_out_s.replacen(OLD_NARROWED, NEW_NARROWED, 1),
                    "old-only text stdout mismatch vs {label} modulo narrowed note"
                );
                assert_eq!(
                    String::from_utf8(old_txt_err.clone())?,
                    bt_err_s.replacen(OLD_NARROWED, NEW_NARROWED, 1),
                    "old-only text stderr mismatch vs {label} modulo narrowed note"
                );
            }
        }

        // Part B: Mixed config — exact same 5 classes PLUS bad ai-publish.storage on site[0] & site[1].
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

        let (_m_code, m_val, _, _) = run_check_json(&bin, base, &common_args, &mixed_cfg)?;
        let m_w = w034s(&m_val);
        assert_eq!(m_w.len(), old_w.len() + 2, "mixed W034 count: {m_w:#?}");

        // Position rule: the 8 existing diagnostics occupy [0..8] unchanged, and the 2 storage
        // diagnostics are appended at [8..10] in site source index order (0, 1)!
        let m_paths: Vec<Option<&str>> = m_w.iter().map(|w| jstr(w, "path")).collect();
        assert_eq!(
            m_paths,
            vec![
                Some("server.sandbox.socket-tree"),
                Some("site[0].route[0].fastcgi-pass"),
                Some("site[0].route[2].fastcgi-pass"),
                Some("site[0].route[3].fastcgi-pass"),
                Some("server.tls.keyd-socket"),
                Some("server.tls.acme"),
                Some("server.log-file"),
                Some("server.access-log"),
                Some("site[0].ai-publish.storage"),
                Some("site[1].ai-publish.storage"),
            ]
        );
        // Every existing diagnostic (index 0..8) has identical code/severity/path/message/help/location!
        for idx in 0..old_w.len() {
            assert_eq!(
                m_w.get(idx),
                old_w.get(idx),
                "existing W034[{idx}] changed when storage was added"
            );
        }
        // Notes are 100% identical to old-only!
        assert_eq!(notes_of(&m_val), old_notes);

        // Exact full JSON check of appended storage records [8] and [9]:
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
        )?;
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
        )?;

        // Differential check of the EXACT same mixed config against bef6865 (and v0.1.7):
        // removing ONLY the exact two storage records leaves the complete ordered old warnings
        // vector, observer note, and socket-prefix notes 100% identical!
        for (label, maybe_ref_bin) in [("bef6865", baseline_bin()), ("v0.1.7", v017_bin())] {
            if let Some(ref_bin) = maybe_ref_bin {
                let (_bc, b_val, _, _) = run_check_json(&ref_bin, base, &common_args, &mixed_cfg)?;
                let b_warns = b_val
                    .get("warnings")
                    .and_then(serde_json::Value::as_array)
                    .ok_or("missing baseline warnings")?;
                let mut m_warns_without_storage: Vec<serde_json::Value> = m_val
                    .get("warnings")
                    .and_then(serde_json::Value::as_array)
                    .ok_or("missing candidate warnings")?
                    .clone();
                let removed: Vec<serde_json::Value> = m_warns_without_storage
                    .iter()
                    .filter(|w| {
                        jstr(w, "code") == Some("W034")
                            && jstr(w, "path").is_some_and(|p| p.ends_with(".ai-publish.storage"))
                    })
                    .cloned()
                    .collect();
                assert_eq!(
                    removed.len(),
                    2,
                    "expected exactly 2 removed storage records"
                );
                m_warns_without_storage.retain(|w| {
                    !(jstr(w, "code") == Some("W034")
                        && jstr(w, "path").is_some_and(|p| p.ends_with(".ai-publish.storage")))
                });
                assert_eq!(
                    &m_warns_without_storage, b_warns,
                    "mixed config warnings (minus storage) diverged from {label}"
                );
                let b_notes = notes_of(&b_val);
                let m_notes = notes_of(&m_val);
                assert_eq!(b_notes.len(), m_notes.len());
                assert_eq!(m_notes.first(), b_notes.first());
                assert_eq!(b_notes.get(1), Some(&OLD_NARROWED));
                assert_eq!(m_notes.get(1), Some(&NEW_NARROWED));
                assert_eq!(m_notes.get(2..), b_notes.get(2..));
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Oracle 3: Storage diagnostics full JSON matrix on real local Linux fs
    // -----------------------------------------------------------------------

    #[test]
    #[allow(clippy::too_many_lines)]
    fn linux_storage_diagnostics_full_json_matrix() -> TestResult {
        if !require_local_root_fs("linux_storage_diagnostics_full_json_matrix")? {
            return Ok(());
        }
        let bin = miraserve_bin();
        let tmp = TempDir::new("matrix")?;
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

        let (cert, key) = gen_dev_cert(&certs, "clean.example,a.example,b.example")?;
        let pub_key = write_pubkey(&certs)?;

        // (a)+(b)+(i)+(k): Clean 0750 store (with 0777/0666 descendants!), sticky existing trusted
        // child, absolute trusted symlink, and relative trusted symlink -> ALL exit 0 under --strict!
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
            let (code, val, _, _) =
                run_check_json(&bin, base, &["--fs", "--strict", "--trusted-paths"], &cfg)?;
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
            &["--fs", "--strict", "--trusted-paths"],
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
        )?;

        let (a_code, a_val, _, _) = run_check_json(
            &bin,
            base,
            &[
                "--fs",
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
        )?;

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
            &["--fs", "--strict", "--trusted-paths"],
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
        )?;
        let (mla_code, mla_val, _, _) = run_check_json(
            &bin,
            base,
            &[
                "--fs",
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
        )?;

        // (d)+(e)+(f)+(j)+(l)+(o): Single-site failure cases asserted with exact full JSON fields!
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
            let (_c, val, _, _) = run_check_json(&bin, base, &["--fs", "--trusted-paths"], &cfg)?;
            let ws = w034s(&val);
            assert_eq!(ws.len(), 1, "case {tag} expected 1 W034: {val}");
            assert_w034_full(
                ws.first().copied().ok_or("missing W034")?,
                "site[0].ai-publish.storage",
                expected_msg,
                HELP_GEN,
                &loc_of_occurrence(&kdl, &node, 0)?,
            )?;
            assert_eq!(
                notes_of(&val),
                vec![expected_default_observer_note().as_str(), NEW_NARROWED],
                "case {tag} unexpected notes: {val}"
            );
        }

        // (m): Two sites sharing the exact same bad store -> 2 W034s in source order (no dedup!).
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
        let (_dc, d_val, _, _) =
            run_check_json(&bin, base, &["--fs", "--trusted-paths"], &dup_cfg)?;
        let dw = w034s(&d_val);
        assert_eq!(
            dw.len(),
            2,
            "two sites sharing store must emit 2 W034s: {d_val}"
        );
        assert_w034_full(
            dw.first().copied().ok_or("missing dup[0]")?,
            "site[0].ai-publish.storage",
            &format!(
                "site 'a.example' ai-publish storage '{}': first untrusted component '{}' \
                 (uid {euid}, mode 0775): group or other writable",
                wr_leaf.display(),
                wr_leaf.display(),
            ),
            HELP_GEN,
            &loc_of_occurrence(&dup_kdl, &dup_node, 0)?,
        )?;
        assert_w034_full(
            dw.get(1).copied().ok_or("missing dup[1]")?,
            "site[1].ai-publish.storage",
            &format!(
                "site 'b.example' ai-publish storage '{}': first untrusted component '{}' \
                 (uid {euid}, mode 0775): group or other writable",
                wr_leaf.display(),
                wr_leaf.display(),
            ),
            HELP_GEN,
            &loc_of_occurrence(&dup_kdl, &dup_node, 1)?,
        )?;

        // (n): Quarantined owner-dir site (missing/inaccessible docroot) STILL gets storage W034!
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
        let (_qc, q_val, _, _) = run_check_json(&bin, base, &["--fs", "--trusted-paths"], &q_cfg)?;
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
        )?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Oracle 3 (continued): File-relative storage via symlinked config across
    // three distinguishable trees + padded & stdin rejections
    // -----------------------------------------------------------------------

    #[test]
    #[allow(clippy::too_many_lines)]
    fn linux_storage_file_relative_symlinked_config_and_padded_rejection() -> TestResult {
        let bin = miraserve_bin();
        let tmp = TempDir::new("rel-sym")?;
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
        let bad_padded_dir = base.join("padded_target");
        for d in [
            &certs,
            &real_cfg_dir,
            &link_cfg_dir,
            &cwd_dir,
            &real_store,
            &link_store,
            &cwd_store,
            &real_pub,
            &bad_padded_dir,
        ] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o750)?;
        }
        set_mode(&real_cfg_dir.join("stores"), 0o750)?;
        set_mode(&link_cfg_dir.join("stores"), 0o750)?;
        set_mode(&cwd_dir.join("stores"), 0o750)?;
        set_mode(&bad_padded_dir, 0o777)?;

        let (cert, key) = gen_dev_cert(&certs, "rel.example")?;
        let pub_key = write_pubkey(&certs)?;

        // Part 1: Padded rejected storage & stdin relative storage NEVER reach W034 (runs on ALL fs!).
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

        // Stdin relative storage fails directory validation at load before W034.
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

        // Part 2: Symlinked config file resolving relative `storage "stores/app"` across three
        // distinguishable trees (`real_cfg_tree`, `link_cfg_tree`, `cwd_tree`).
        if !require_local_root_fs(
            "linux_storage_file_relative_symlinked_config_and_padded_rejection(walk)",
        )? {
            return Ok(());
        }

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
            &["--fs", "--strict", "--trusted-paths"],
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
        )?;

        // Pass pair: `real_cfg_tree/stores/app` is clean 0750 while BOTH `link_cfg_tree/stores/app`
        // AND `cwd_tree/stores/app` are 0777 -> MUST pass with exit 0 and 0 W034!
        set_mode(&real_store, 0o750)?;
        set_mode(&link_store, 0o777)?;
        set_mode(&cwd_store, 0o777)?;
        let (p_code, p_val, _, _) = run_check_json(
            &bin,
            &cwd_dir,
            &["--fs", "--strict", "--trusted-paths"],
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
    // OverlayFS root rejection for ai-publish.storage (runs on Docker overlayfs /)
    // -----------------------------------------------------------------------

    #[test]
    fn linux_storage_overlayfs_root_reported_not_verified() -> TestResult {
        let magic = fs_magic_of("/")?;
        if magic != 0x794C_7630 {
            eprintln!(
                "skipping linux_storage_overlayfs_root_reported_not_verified: / is 0x{magic:x}, not overlayfs"
            );
            return Ok(());
        }
        let bin = miraserve_bin();
        let tmp = TempDir::new("ovl-store")?;
        let base = &tmp.path;

        let certs = base.join("certs");
        let docroot = base.join("www");
        let store = base.join("store");
        for d in [&certs, &docroot, &store] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o750)?;
        }
        let (cert, key) = gen_dev_cert(&certs, "ovl.example")?;
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
        let (_code, val, _, _) = run_check_json(&bin, base, &["--fs", "--trusted-paths"], &cfg)?;
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
        )?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Oracle 4: Non-root service UID mismatch on storage
    // -----------------------------------------------------------------------

    #[test]
    fn linux_storage_nonroot_observer_mismatch_adds_not_verified_w034() -> TestResult {
        let euid = rustix::process::geteuid().as_raw();
        if euid == 0 {
            eprintln!(
                "skipping linux_storage_nonroot_observer_mismatch_adds_not_verified_w034: requires non-root"
            );
            return Ok(());
        }
        if !require_local_root_fs("linux_storage_nonroot_observer_mismatch_adds_not_verified_w034")?
        {
            return Ok(());
        }
        let other_uid = if euid == 1000 { 1001 } else { 1000 };
        let bin = miraserve_bin();
        let tmp = TempDir::new("nonroot-mis")?;
        let base = &tmp.path;
        let certs = base.join("certs");
        let docroot = base.join("www");
        let store = base.join("store");
        for d in [&certs, &docroot, &store] {
            fs::create_dir_all(d)?;
            set_mode(d, 0o750)?;
        }
        let (cert, key) = gen_dev_cert(&certs, "mis.example")?;
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

        let (code, val, _, _) =
            run_check_json(&bin, base, &["--fs", "--strict", "--trusted-paths"], &cfg)?;
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
        )?;
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
        )?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Oracle 4: Root multi-UID + actual service-UID run with supplementary
    // groups + hosting-panel layout with distinct PHP/tenant UIDs
    // -----------------------------------------------------------------------

    #[test]
    #[allow(clippy::too_many_lines)]
    fn linux_root_storage_multi_uid_service_uid_panel_and_supp_groups() -> TestResult {
        use rustix::fs::{Gid, Uid, chown};

        if !rustix::process::geteuid().is_root() {
            eprintln!(
                "skipping linux_root_storage_multi_uid_service_uid_panel_and_supp_groups: requires root"
            );
            return Ok(());
        }
        if !require_local_root_fs("linux_root_storage_multi_uid_service_uid_panel_and_supp_groups")?
        {
            return Ok(());
        }

        let bin = miraserve_bin();
        let tmp = TempDir::new("root-panel")?;
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

        let (cert, key) = gen_dev_cert(&certs, "a.example,b.example,pub.example")?;
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
            )?;
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
        let (_uc, u_val, _, _) =
            run_check_json(&bin, base, &["--fs", "--trusted-paths"], &unset_cfg)?;
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
        )?;

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
        let (_stc, st_val, _, _) =
            run_check_json(&bin, base, &["--fs", "--trusted-paths"], &st_cfg)?;
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
        )?;

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
        let (sok_c, sok_v) =
            run_as_service(&["--fs", "--strict", "--trusted-paths"], &supp_ok_cfg)?;
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
        let (sgw_c, sgw_v) =
            run_as_service(&["--fs", "--strict", "--trusted-paths"], &supp_gw_cfg)?;
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
        )?;

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
        let (rro_c, rro_v) = run_as_service(&["--fs", "--trusted-paths"], &root_ro_cfg)?;
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

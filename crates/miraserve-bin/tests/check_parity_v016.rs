//! Byte-for-byte parity oracle comparing configuration processing of `miraserve check` (without
//! `--trusted-paths`; `check --help` lists the new flag) against fixtures recorded from `v0.1.6`
//! (`a4c2ffc`).
//!
//! Run with `MIRASERVE_PARITY_BIN=/path/to/miraserve` to verify any binary (such as a `v0.1.6`
//! build) against the committed fixtures, or with `RECORD_V016_PARITY=1` and
//! `MIRASERVE_PARITY_BIN=/path/to/v0.1.6/miraserve` to record fixtures from `v0.1.6`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

#[path = "../../miraserve-config/tests/common/mod.rs"]
mod kdl_test_util;

use kdl_test_util::kdl_escape_path;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CommandSnapshot {
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CaseFixture {
    commands: BTreeMap<String, CommandSnapshot>,
}

struct CorpusCase {
    name: &'static str,
    config_path: PathBuf,
    cwd: PathBuf,
    extra_args: Vec<String>,
}

fn parity_bin() -> PathBuf {
    std::env::var_os("MIRASERVE_PARITY_BIN").map_or_else(
        || PathBuf::from(env!("CARGO_BIN_EXE_miraserve")),
        PathBuf::from,
    )
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[allow(clippy::unnecessary_wraps)]
fn fixture_profile() -> Option<&'static str> {
    #[cfg(target_os = "macos")]
    {
        Some("macos")
    }
    #[cfg(target_os = "linux")]
    {
        if rustix::process::geteuid().is_root() {
            Some("linux-root")
        } else {
            Some("linux-nonroot")
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

fn fixture_dir(profile: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("v016_parity")
        .join(profile)
}

fn normalize_output(
    raw: &[u8],
    canon_base: &str,
    raw_base: &str,
    repo: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut text = String::from_utf8(raw.to_vec())?;
    if !canon_base.is_empty() && canon_base != raw_base {
        text = text.replace(canon_base, "<TMPDIR>");
    }
    if !raw_base.is_empty() {
        text = text.replace(raw_base, "<TMPDIR>");
    }
    if !repo.is_empty() {
        text = text.replace(repo, "<REPO>");
    }
    Ok(text)
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

#[allow(clippy::too_many_lines)]
fn build_corpus(
    bin: &Path,
    base: &Path,
    repo: &Path,
) -> Result<Vec<CorpusCase>, Box<dyn std::error::Error>> {
    let certs_dir = base.join("certs");
    let static_root = base.join("static_root");
    let try_root = base.join("try_root");
    let php_root = base.join("php_root");
    let php_socks = base.join("php_socks");
    let homes = base.join("homes");
    let alice_home = homes.join("alice");
    let alice_root = alice_home.join("public_html");
    let acme_root = base.join("acme_root");
    let acme_state = base.join("acme_state");
    let releases_app = base.join("releases").join("app");
    let conf_dir = base.join("conf");
    let cwd_examples = base.join("cwd_examples");
    let cwd_nfpm = base.join("cwd_nfpm");

    for dir in [
        &certs_dir,
        &static_root,
        &try_root,
        &php_root,
        &php_socks,
        &homes,
        &alice_home,
        &alice_root,
        &acme_root,
        &acme_state,
        &releases_app,
        &conf_dir,
        &cwd_examples,
        &cwd_nfpm,
    ] {
        fs::create_dir_all(dir)?;
        set_mode(dir, 0o750)?;
    }
    set_mode(&acme_state, 0o700)?;

    fs::write(static_root.join("index.html"), b"<h1>static</h1>\n")?;
    fs::write(try_root.join("index.html"), b"<h1>spa</h1>\n")?;
    fs::write(php_root.join("index.php"), b"<?php echo 1;\n")?;
    fs::write(alice_root.join("index.html"), b"<h1>alice</h1>\n")?;
    fs::write(acme_root.join("index.html"), b"<h1>acme</h1>\n")?;

    let cert_path = certs_dir.join("server.crt");
    let key_path = certs_dir.join("server.key");
    let cert_out = Command::new(bin)
        .args([
            "cert",
            "generate-dev",
            "--hosts",
            "parity.example",
            "--cert",
        ])
        .arg(&cert_path)
        .arg("--key")
        .arg(&key_path)
        .output()?;
    if !cert_out.status.success() {
        return Err(format!(
            "cert generate-dev failed: {}",
            String::from_utf8_lossy(&cert_out.stderr)
        )
        .into());
    }
    set_mode(&cert_path, 0o640)?;
    set_mode(&key_path, 0o600)?;

    let pub_key_path = certs_dir.join("publish-jwt.pub");
    fs::write(&pub_key_path, b"0123456789abcdef0123456789abcdef\n")?;
    set_mode(&pub_key_path, 0o640)?;

    let cert_esc = kdl_escape_path(&cert_path);
    let key_esc = kdl_escape_path(&key_path);

    // Generated 1: static site
    let static_cfg = conf_dir.join("gen_static.kdl");
    fs::write(
        &static_cfg,
        format!(
            "server {{\n\
                 listen \":443\"\n\
                 tls {{ cert \"{cert_esc}\"; key \"{key_esc}\" }}\n\
             }}\n\
             site \"static.example\" {{\n\
                 security-headers \"strict\"\n\
                 precompressed \"br\" \"gz\"\n\
                 root \"{}\"\n\
             }}\n",
            kdl_escape_path(&static_root),
        ),
    )?;

    // Generated 2: try-files (including 0.1.6 fallback-unless-extension)
    let try_cfg = conf_dir.join("gen_try_files.kdl");
    fs::write(
        &try_cfg,
        format!(
            "server {{\n\
                 listen \":443\"\n\
                 tls {{ cert \"{cert_esc}\"; key \"{key_esc}\" }}\n\
             }}\n\
             site \"spa.example\" {{\n\
                 root \"{}\"\n\
                 route \"/*\" {{\n\
                     try-files \"{{path}}\" \"{{path}}/\" \"/index.html\" fallback-unless-extension=#true\n\
                 }}\n\
             }}\n",
            kdl_escape_path(&try_root),
        ),
    )?;

    // Generated 3: reverse-proxy with upstream-tls CA
    let proxy_cfg = conf_dir.join("gen_reverse_proxy.kdl");
    fs::write(
        &proxy_cfg,
        format!(
            "server {{\n\
                 listen \":443\"\n\
                 tls {{ cert \"{cert_esc}\"; key \"{key_esc}\" }}\n\
             }}\n\
             site \"api.example\" {{\n\
                 route \"/v1/*\" {{\n\
                     reverse-proxy {{\n\
                         upstream \"https://127.0.0.1:8443\"\n\
                         upstream-tls {{ ca-cert \"{cert_esc}\" }}\n\
                     }}\n\
                 }}\n\
             }}\n",
        ),
    )?;

    // Generated 4: FastCGI unix socket + socket-tree (existing listening socket + absent socket)
    let present_sock = php_socks.join("pool.sock");
    let absent_sock = php_socks.join("late.sock");
    let fastcgi_cfg = conf_dir.join("gen_fastcgi_socket_tree.kdl");
    fs::write(
        &fastcgi_cfg,
        format!(
            "server {{\n\
                 listen \":443\"\n\
                 tls {{ cert \"{cert_esc}\"; key \"{key_esc}\" }}\n\
                 sandbox {{ socket-tree \"{}\" }}\n\
             }}\n\
             site \"php.example\" {{\n\
                 root \"{}\"\n\
                 route \"*.php\" {{\n\
                     fastcgi-pass \"unix:{}\"\n\
                 }}\n\
                 route \"/late/*\" {{\n\
                     fastcgi-pass \"unix:{}\"\n\
                 }}\n\
             }}\n",
            kdl_escape_path(&php_socks),
            kdl_escape_path(&php_root),
            kdl_escape_path(&present_sock),
            kdl_escape_path(&absent_sock),
        ),
    )?;

    // Generated 5: owner-dir tenant site + read-tree
    let owner_cfg = conf_dir.join("gen_owner_dir.kdl");
    fs::write(
        &owner_cfg,
        format!(
            "server {{\n\
                 listen \":443\"\n\
                 tls {{ cert \"{cert_esc}\"; key \"{key_esc}\" }}\n\
                 sandbox {{ read-tree \"{}\" }}\n\
             }}\n\
             site \"alice.example\" {{\n\
                 owner-dir \"{}\"\n\
                 root \"{}\"\n\
             }}\n\
             site \"plain.example\" {{\n\
                 root \"{}\"\n\
             }}\n",
            kdl_escape_path(&homes),
            kdl_escape_path(&alice_home),
            kdl_escape_path(&alice_root),
            kdl_escape_path(&static_root),
        ),
    )?;

    // Generated 6: ACME site with explicit --acme-dir
    let acme_cfg = conf_dir.join("gen_acme.kdl");
    fs::write(
        &acme_cfg,
        format!(
            "server {{\n\
                 listen \":443\"\n\
                 tls {{\n\
                     acme {{\n\
                         email \"ops@example.com\"\n\
                         challenge \"tls-alpn-01\"\n\
                     }}\n\
                 }}\n\
             }}\n\
             site \"acme.example\" {{\n\
                 root \"{}\"\n\
             }}\n",
            kdl_escape_path(&acme_root),
        ),
    )?;

    // Generated 7: publish store (`ai-publish`)
    let publish_cfg = conf_dir.join("gen_publish.kdl");
    fs::write(
        &publish_cfg,
        format!(
            "server {{\n\
                 listen \":443\"\n\
                 tls {{ cert \"{cert_esc}\"; key \"{key_esc}\" }}\n\
             }}\n\
             site \"pub.example\" {{\n\
                 ai-publish {{\n\
                     storage \"{}\"\n\
                     site-id \"pub.example\"\n\
                     keep-versions 5\n\
                     require-signature \"ed25519:{}\"\n\
                     jwt-public-key \"ed25519:{}\"\n\
                     jwt-issuer \"https://auth.example\"\n\
                     mcp-endpoint \"/_miraserve/publish\" auth=\"oauth-jwt\"\n\
                 }}\n\
             }}\n",
            kdl_escape_path(&releases_app),
            kdl_escape_path(&pub_key_path),
            kdl_escape_path(&pub_key_path),
        ),
    )?;

    Ok(vec![
        CorpusCase {
            name: "examples_dev_local",
            config_path: PathBuf::from("dev-local.kdl"),
            cwd: repo.join("examples"),
            extra_args: Vec::new(),
        },
        CorpusCase {
            name: "examples_miraserve",
            config_path: repo.join("examples").join("miraserve.kdl"),
            cwd: cwd_examples,
            extra_args: Vec::new(),
        },
        CorpusCase {
            name: "packaging_nfpm",
            config_path: repo.join("packaging").join("nfpm").join("miraserve.kdl"),
            cwd: cwd_nfpm,
            extra_args: Vec::new(),
        },
        CorpusCase {
            name: "gen_static",
            config_path: static_cfg,
            cwd: base.to_path_buf(),
            extra_args: Vec::new(),
        },
        CorpusCase {
            name: "gen_try_files",
            config_path: try_cfg,
            cwd: base.to_path_buf(),
            extra_args: Vec::new(),
        },
        CorpusCase {
            name: "gen_reverse_proxy",
            config_path: proxy_cfg,
            cwd: base.to_path_buf(),
            extra_args: Vec::new(),
        },
        CorpusCase {
            name: "gen_fastcgi_socket_tree",
            config_path: fastcgi_cfg,
            cwd: base.to_path_buf(),
            extra_args: Vec::new(),
        },
        CorpusCase {
            name: "gen_owner_dir",
            config_path: owner_cfg,
            cwd: base.to_path_buf(),
            extra_args: Vec::new(),
        },
        CorpusCase {
            name: "gen_acme",
            config_path: acme_cfg,
            cwd: base.to_path_buf(),
            extra_args: vec![
                "--acme-dir".to_owned(),
                acme_state.to_string_lossy().into_owned(),
            ],
        },
        CorpusCase {
            name: "gen_publish",
            config_path: publish_cfg,
            cwd: base.to_path_buf(),
            extra_args: Vec::new(),
        },
    ])
}

#[test]
#[allow(clippy::too_many_lines)]
fn check_config_processing_without_trusted_paths_matches_v016_byte_for_byte() -> TestResult {
    let Some(profile) = fixture_profile() else {
        return Ok(());
    };
    let bin = parity_bin();
    let repo = fs::canonicalize(repo_root())?;
    let repo_raw = repo_root();

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    // Keep path short for macOS 104-byte sun_path limit and avoid leading '.' segments.
    let base = PathBuf::from(format!("/tmp/ms-p-{}-{nanos}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base)?;
    set_mode(&base, 0o750)?;
    let canon_base = fs::canonicalize(&base)?;

    let cases = build_corpus(&bin, &base, &repo)?;

    // Keep the Unix socket listener alive for the duration of the corpus run.
    #[cfg(unix)]
    let _sock_listener = {
        let sock_path = base.join("php_socks").join("pool.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock_path)?;
        set_mode(&sock_path, 0o660)?;
        listener
    };

    let raw_base_str = base.to_string_lossy().into_owned();
    let canon_base_str = canon_base.to_string_lossy().into_owned();
    let repo_str = repo.to_string_lossy().into_owned();
    let repo_raw_str = repo_raw.to_string_lossy().into_owned();

    let modes: &[(&str, &[&str])] = &[
        ("check", &["check"]),
        ("check_strict", &["check", "--strict"]),
        ("check_fs", &["check", "--fs"]),
        (
            "check_fs_strict_json",
            &["check", "--fs", "--strict", "--format", "json"],
        ),
        (
            "check_fs_writable_set",
            &["check", "--fs", "--writable-set"],
        ),
        ("check_dump_normalized", &["check", "--dump-normalized"]),
    ];

    let record_mode = std::env::var("RECORD_V016_PARITY").as_deref() == Ok("1");
    let fdir = fixture_dir(profile);
    if record_mode {
        fs::create_dir_all(&fdir)?;
    }

    for case in &cases {
        let mut actual_commands = BTreeMap::new();
        for &(mode_name, base_args) in modes {
            let mut cmd = Command::new(&bin);
            cmd.current_dir(&case.cwd).args(base_args);
            for extra in &case.extra_args {
                cmd.arg(extra);
            }
            cmd.arg(&case.config_path);
            let out = cmd.output()?;
            let mut stdout =
                normalize_output(&out.stdout, &canon_base_str, &raw_base_str, &repo_str)?;
            let mut stderr =
                normalize_output(&out.stderr, &canon_base_str, &raw_base_str, &repo_str)?;
            if repo_raw_str != repo_str {
                stdout = stdout.replace(&repo_raw_str, "<REPO>");
                stderr = stderr.replace(&repo_raw_str, "<REPO>");
            }
            actual_commands.insert(
                mode_name.to_owned(),
                CommandSnapshot {
                    exit_code: out.status.code(),
                    stdout,
                    stderr,
                },
            );
        }

        let actual = CaseFixture {
            commands: actual_commands,
        };
        let fixture_path = fdir.join(format!("{}.json", case.name));

        if record_mode {
            let json = serde_json::to_string_pretty(&actual)?;
            fs::write(&fixture_path, format!("{json}\n"))?;
            continue;
        }

        let expected_raw = fs::read_to_string(&fixture_path).map_err(|err| {
            format!(
                "missing v0.1.6 parity fixture '{}': {err}",
                fixture_path.display()
            )
        })?;
        let expected: CaseFixture = serde_json::from_str(&expected_raw)?;

        assert_eq!(
            actual.commands.keys().collect::<Vec<_>>(),
            expected.commands.keys().collect::<Vec<_>>(),
            "command set mismatch for case '{}'",
            case.name
        );

        for (mode_name, exp_snap) in &expected.commands {
            let act_snap = actual
                .commands
                .get(mode_name)
                .ok_or_else(|| format!("missing mode '{mode_name}' in actual output"))?;
            assert_eq!(
                act_snap.exit_code, exp_snap.exit_code,
                "exit status mismatch for case '{}' mode '{mode_name}' (profile={profile})",
                case.name
            );
            assert_eq!(
                act_snap.stdout.as_bytes(),
                exp_snap.stdout.as_bytes(),
                "stdout byte mismatch for case '{}' mode '{mode_name}' (profile={profile})\n--- EXPECTED ---\n{}\n--- ACTUAL ---\n{}",
                case.name,
                exp_snap.stdout,
                act_snap.stdout,
            );
            assert_eq!(
                act_snap.stderr.as_bytes(),
                exp_snap.stderr.as_bytes(),
                "stderr byte mismatch for case '{}' mode '{mode_name}' (profile={profile})\n--- EXPECTED ---\n{}\n--- ACTUAL ---\n{}",
                case.name,
                exp_snap.stderr,
                act_snap.stderr,
            );
        }
    }

    let _ = fs::remove_dir_all(&base);
    Ok(())
}

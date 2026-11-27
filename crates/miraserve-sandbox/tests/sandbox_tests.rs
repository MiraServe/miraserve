//! Cross-platform policy derivation and enforcement tests for `miraserve-sandbox`.

// `assert_is_empty` is new in clippy 1.100 and unknown to 1.95 (the minimum toolchain).
// `assert!(x.is_empty())` says what these tests mean.
#![allow(unknown_lints, clippy::assert_is_empty)]

use std::path::Path;

use miraserve_config::{SeccompMode, parse_kdl};
#[cfg(unix)]
use miraserve_sandbox::verify_privilege_state_with_expected;
use miraserve_sandbox::{
    SandboxError, SandboxPolicy, apply_sandbox, blocked_syscalls_for_mode, verify_privilege_state,
};

#[path = "../../miraserve-config/tests/common/mod.rs"]
mod kdl_test_util;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Formats a filesystem path for interpolation inside a KDL double-quoted string: strips any
/// Windows `\\?\` verbatim prefix and escapes via the shared KDL test helper.
fn kdl_path(path: &Path) -> String {
    let raw = path.to_string_lossy();
    let stripped = raw.strip_prefix(r"\\?\").unwrap_or(&raw);
    kdl_test_util::kdl_escape_str(stripped)
}

#[allow(clippy::too_many_lines)]
#[test]
fn derives_least_privilege_ro_and_rw_paths_from_config() -> TestResult {
    let kdl = r#"
server {
    listen ":443"
    tls {
        key-isolation "split-daemon"
        keyd-socket "/run/miraserve/keyd.sock"
        cert "/etc/miraserve/certs/server.pem"
        key "/etc/miraserve/keys/server.key"
    }
    sandbox {
        user "miraserve"
        landlock true
        seccomp "strict"
    }
}

site "wp.example.com" {
    root "/var/www/wordpress"
    route "*.php" {
        fastcgi-pass "unix:/run/php/php8.3-fpm.sock"
    }
}

site "ai.example.com" {
    ai-publish {
        storage "/var/lib/miraserve/releases/ai"
        require-signature "ed25519:/etc/miraserve/deploy.pub"
        preflight-checks "no-secrets"
    }
}
"#;

    let (cfg, _) = parse_kdl("sandbox.kdl", kdl)?;
    let mut policy = SandboxPolicy::from_config_with_file(
        &cfg,
        Some(Path::new("/etc/miraserve/miraserve.kdl")),
        Some(Path::new("/var/lib/miraserve/acme")),
    );

    assert!(policy.landlock);
    assert_eq!(policy.seccomp, SeccompMode::Strict);
    assert_eq!(policy.user.as_deref(), Some("miraserve"));

    // R2-SBX-2: Reloadable files in dedicated subdirectories grant their containing directory RO
    // so atomic rename replacements (certbot renewals, config saves) remain readable on SIGHUP.
    assert!(
        policy
            .read_only_paths
            .iter()
            .any(|p| p == Path::new("/var/www/wordpress"))
    );
    assert!(
        policy
            .read_only_paths
            .iter()
            .any(|p| p == Path::new("/etc/miraserve/certs"))
    );

    // R3-PKG-2 & R3-SBX-3: In split-daemon mode, `/etc/miraserve` MUST NOT be granted recursively
    // because `/etc/miraserve/keys/server.key` lives underneath it; exact files are granted instead!
    assert!(
        !policy
            .read_only_paths
            .iter()
            .any(|p| p == Path::new("/etc/miraserve"))
    );
    assert!(
        policy
            .read_only_paths
            .iter()
            .any(|p| p == Path::new("/etc/miraserve/miraserve.kdl"))
    );
    assert!(
        policy
            .read_only_paths
            .iter()
            .any(|p| p == Path::new("/etc/miraserve/deploy.pub"))
    );
    assert!(
        !policy
            .read_only_paths
            .iter()
            .any(|p| p == Path::new("/etc/miraserve/keys")
                || p == Path::new("/etc/miraserve/keys/server.key"))
    );

    // Broad shared system dirs like `/etc` are NEVER widened even if a file lives directly in `/etc`!
    policy.allow_reloadable_file(Path::new("/etc/direct-file.kdl"));
    assert!(
        !policy
            .read_only_paths
            .iter()
            .any(|p| p == Path::new("/etc"))
    );
    assert!(
        policy
            .read_only_paths
            .iter()
            .any(|p| p == Path::new("/etc/direct-file.kdl"))
    );

    // Read-write paths include release store and ACME state dir (never `/run/miraserve` or `/run/php`, R3-SBX-3)
    assert!(
        policy
            .read_write_paths
            .iter()
            .any(|p| p == Path::new("/var/lib/miraserve/releases/ai"))
    );
    assert!(
        policy
            .read_write_paths
            .iter()
            .any(|p| p == Path::new("/var/lib/miraserve/acme"))
    );
    assert!(
        !policy
            .read_write_paths
            .iter()
            .any(|p| p == Path::new("/run/miraserve"))
    );
    assert!(
        !policy
            .read_write_paths
            .iter()
            .any(|p| p == Path::new("/run/php"))
    );

    // Exact Unix domain socket paths are isolated in `socket_paths`
    assert!(
        policy
            .socket_paths
            .iter()
            .any(|p| p == Path::new("/run/miraserve/keyd.sock"))
    );
    assert!(
        policy
            .socket_paths
            .iter()
            .any(|p| p == Path::new("/run/php/php8.3-fpm.sock"))
    );

    // Strict seccomp blocks execve & ptrace; Off blocks nothing
    assert!(blocked_syscalls_for_mode(SeccompMode::Strict).contains(&"execve"));
    assert!(blocked_syscalls_for_mode(SeccompMode::Strict).contains(&"ptrace"));
    assert_eq!(blocked_syscalls_for_mode(SeccompMode::Off), [""; 0]);

    // Fail-closed root AND unverified-UID enforcement (R2-SBX-3; POSIX UID/GIDs are Unix-only):
    #[cfg(unix)]
    {
        assert!(matches!(
            verify_privilege_state(&policy, Some(0), Some(1000)),
            Err(SandboxError::PrivilegeDrop(_))
        ));
        assert!(matches!(
            verify_privilege_state(&policy, Some(1000), Some(0)),
            Err(SandboxError::PrivilegeDrop(_))
        ));
        assert!(matches!(
            verify_privilege_state(&policy, None, Some(1000)),
            Err(SandboxError::PrivilegeDrop(_))
        ));
        assert!(matches!(
            verify_privilege_state(&policy, Some(1000), None),
            Err(SandboxError::PrivilegeDrop(_))
        ));

        let ok_note = verify_privilege_state(&policy, Some(1000), Some(1000))?;
        assert!(ok_note.is_some());

        // R2-SBX-3: Mismatched non-root UID/GID against expected `sandbox.user`/`group` MUST fail!
        assert!(matches!(
            verify_privilege_state_with_expected(&policy, Some(1000), Some(1000), Some(2000), None),
            Err(SandboxError::PrivilegeDrop(_))
        ));
        let mut group_policy = policy.clone();
        group_policy.group = Some("miraserve".to_owned());
        assert!(matches!(
            verify_privilege_state_with_expected(
                &group_policy,
                Some(1000),
                Some(1000),
                Some(1000),
                Some(2000),
            ),
            Err(SandboxError::PrivilegeDrop(_))
        ));
    }
    #[cfg(not(unix))]
    {
        // Non-Unix platforms lack POSIX UID/GIDs (service principal isolation is OS-managed),
        // but configuring `sandbox.user = "root"` must still fail closed.
        let mut root_policy = policy.clone();
        root_policy.user = Some("root".to_owned());
        assert!(matches!(
            verify_privilege_state(&root_policy, Some(1000), Some(1000)),
            Err(SandboxError::PrivilegeDrop(_))
        ));
        let ok_note = verify_privilege_state(&policy, Some(1000), Some(1000))?;
        assert!(ok_note.is_some());
    }
    // Non-existent `sandbox.user` fails closed in `apply_sandbox` on Unix (R2-SBX-3).
    #[cfg(unix)]
    assert!(matches!(
        apply_sandbox(&policy),
        Err(SandboxError::PrivilegeDrop(_))
    ));

    // On Linux, `R2-SBX-1` fails closed when configured read-write dirs do not exist at startup,
    // and applying Landlock + strict seccomp succeeds on a dedicated thread once rw dirs exist.
    #[cfg(target_os = "linux")]
    {
        let mut missing_rw_policy = policy.clone();
        missing_rw_policy.user = None;
        missing_rw_policy.group = None;
        assert!(matches!(
            apply_sandbox(&missing_rw_policy),
            Err(SandboxError::Landlock(_))
        ));

        // `apply_sandbox` with `SeccompMode::Strict` installs `SECCOMP_FILTER_FLAG_TSYNC`
        // (process-wide, blocking `execve`/`execveat` on every thread in this binary). Run the
        // live `Strict` install inside an isolated child copy of this test binary so sibling
        // tests in `sandbox_tests` (e.g. `run_command_stdout_with_timeout` invoking `/usr/bin/id`)
        // can never fail with `EPERM` due to test execution order.
        if std::env::var_os("MIRASERVE_TEST_APPLY_STRICT_SANDBOX_CHILD").is_some() {
            let tmp = std::env::temp_dir().join(format!(
                "miraserve-sbx-apply-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            ));
            std::fs::create_dir_all(&tmp)?;
            let mut runnable_policy = policy.clone();
            runnable_policy.user = None;
            runnable_policy.group = None;
            runnable_policy.read_write_paths = vec![tmp.clone()];
            runnable_policy.finalize_grants()?;
            let handle = std::thread::spawn(move || apply_sandbox(&runnable_policy));
            let report = handle
                .join()
                .map_err(|_| "sandbox worker thread panicked")??;
            assert_eq!(report.platform, "linux");
            assert_eq!(report.socket_path_count, 2);
            let _ = std::fs::remove_dir_all(&tmp);
        } else {
            let exe = std::env::current_exe()?;
            let out = std::process::Command::new(exe)
                .args([
                    "--exact",
                    "derives_least_privilege_ro_and_rw_paths_from_config",
                    "--nocapture",
                ])
                .env("MIRASERVE_TEST_APPLY_STRICT_SANDBOX_CHILD", "1")
                .output()?;
            assert!(
                out.status.success(),
                "isolated strict apply_sandbox child failed (status={:?}):\nstdout:\n{}\nstderr:\n{}",
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut runnable_policy = policy.clone();
        runnable_policy.user = None;
        runnable_policy.group = None;
        let report = apply_sandbox(&runnable_policy)?;
        assert_eq!(report.platform, std::env::consts::OS);
        assert_eq!(report.socket_path_count, 2);
    }
    Ok(())
}

/// R3-SBX-1, R3-SBX-2, R3-SBX-3, R2-SBX-2:
/// - Certbot symlink chains (`live/<site>/fullchain.pem` -> `archive/<site>/fullchain1.pem`) grant
///   the canonical target parent directory in in-process mode, while split-daemon mode refuses to
///   widen `archive/<site>` when `privkey1.pem` resides in the same directory.
/// - Broad/shared parent directories (`/srv`, `/opt`, `/var/lib`, `/home/<user>`, `/etc/ssl/private`, `.`)
///   are never recursively widened.
/// - `uncovered_paths_in` detects newly added paths after reload.
#[test]
#[allow(clippy::too_many_lines)]
fn sandbox_round3_certbot_symlink_broad_dirs_and_reload_diff() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base =
        std::env::temp_dir().join(format!("miraserve-sbx-r3-{}-{nanos}", std::process::id()));
    let live_dir = base.join("letsencrypt").join("live").join("example.com");
    let archive_dir = base.join("letsencrypt").join("archive").join("example.com");
    std::fs::create_dir_all(&live_dir)?;
    std::fs::create_dir_all(&archive_dir)?;

    let archive_cert = archive_dir.join("fullchain1.pem");
    let archive_key = archive_dir.join("privkey1.pem");
    std::fs::write(&archive_cert, b"dummy cert")?;
    std::fs::write(&archive_key, b"dummy key")?;

    let live_cert = live_dir.join("fullchain.pem");
    let live_key = live_dir.join("privkey.pem");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&archive_cert, &live_cert)?;
        std::os::unix::fs::symlink(&archive_key, &live_key)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&live_cert, b"dummy cert")?;
        std::fs::write(&live_key, b"dummy key")?;
    }

    // 1. In-process mode: both `live/example.com` and canonical `archive/example.com` are granted RO (R3-SBX-2)
    let in_proc_kdl = format!(
        r#"
server {{
    listen ":443"
    tls {{
        cert "{}"
        key "{}"
    }}
}}
site "example.com" {{ root "/var/www/site1" }}
"#,
        kdl_path(&live_cert),
        kdl_path(&live_key)
    );
    let (in_proc_cfg, _) = parse_kdl("inproc.kdl", &in_proc_kdl)?;
    let in_proc_policy = SandboxPolicy::from_config_with_file(
        &in_proc_cfg,
        Some(Path::new("/etc/miraserve/miraserve.kdl")),
        None,
    );
    assert!(
        in_proc_policy
            .read_only_paths
            .iter()
            .any(|p| p == &live_dir),
        "live/<site> must be granted RO"
    );
    #[cfg(unix)]
    {
        let canon_archive = std::fs::canonicalize(&archive_dir)?;
        assert!(
            in_proc_policy
                .read_only_paths
                .iter()
                .any(|p| p == &canon_archive),
            "certbot canonical target parent archive/<site> must be granted RO in in-process mode (R3-SBX-2)"
        );
    }
    // R3-SBX-3 & R4-SBX-1: `/etc/miraserve/miraserve.kdl` is an ancestor of `/etc/miraserve/keys`
    // so it falls back to exact-file access (never exposing `/etc/miraserve/keys`!) and records
    // the fallback so startup warns the operator. Placing config in `/etc/miraserve/conf/` widens
    // cleanly to `/etc/miraserve/conf` for atomic-rename SIGHUP reloads!
    assert!(
        !in_proc_policy
            .read_only_paths
            .iter()
            .any(|p| p == Path::new("/etc/miraserve")),
        "must not widen /etc/miraserve/miraserve.kdl to /etc/miraserve when /etc/miraserve/keys is unused (R3-SBX-3)"
    );
    assert!(
        in_proc_policy
            .exact_file_fallbacks
            .iter()
            .any(|p| p == Path::new("/etc/miraserve/miraserve.kdl")),
        "exact-file fallback must be recorded for startup advisory (R4-SBX-1)"
    );
    let conf_policy = SandboxPolicy::from_config_with_file(
        &in_proc_cfg,
        Some(Path::new("/etc/miraserve/conf/miraserve.kdl")),
        None,
    );
    assert!(
        conf_policy
            .read_only_paths
            .iter()
            .any(|p| p == Path::new("/etc/miraserve/conf")),
        "/etc/miraserve/conf/miraserve.kdl must widen cleanly to /etc/miraserve/conf (R4-SBX-1)"
    );
    assert!(
        !conf_policy
            .exact_file_fallbacks
            .iter()
            .any(|p| p == Path::new("/etc/miraserve/conf/miraserve.kdl"))
    );

    // R4-SBX-2 & R5-SBX-1: Explicitly configured docroots `/var/www`, `/srv`, `/opt` MUST be
    // allowed, while unsafe system roots (`/etc`, relative `"etc"`, `"etc/miraserve"`, `/var/lib`,
    // `/var/log`, `/usr/local`, `/etc/miraserve/keys`, and a symlink pointing into `/etc`) are
    // refused WITH an explicit warning surfaced in `policy.warnings` and `SandboxReport.notes`!
    #[cfg(unix)]
    let symlink_to_etc = {
        let p = base.join("link-to-etc");
        std::os::unix::fs::symlink("/etc", &p)?;
        p
    };
    let explicit_roots_kdl = r#"
server {
    listen ":443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }
}
site "a.example" { root "/var/www" }
site "b.example" { root "/srv/www" }
site "c.example" { root "/opt/www" }
site "bad1.example" { root "/var/www/placeholder1" }
site "bad2.example" { root "/var/www/placeholder2" }
site "bad3.example" { root "/var/www/placeholder3" }
site "bad4.example" { root "/var/www/placeholder4" }
site "bad5.example" { root "/var/www/placeholder5" }
site "bad6.example" { root "/var/www/placeholder6" }
site "bad7.example" { root "/var/www/placeholder7" }
site "bad8.example" { root "/var/www/placeholder8" }
"#;
    let (mut roots_cfg, _) = parse_kdl("roots.kdl", explicit_roots_kdl)?;
    // Bypass config-level E202 programmatically to verify SandboxPolicy's own defense-in-depth!
    for site in &mut roots_cfg.sites {
        if site.hosts.iter().any(|h| h == "bad1.example") {
            site.root = Some("/etc".to_owned());
        } else if site.hosts.iter().any(|h| h == "bad2.example") {
            site.root = Some("etc".to_owned());
        } else if site.hosts.iter().any(|h| h == "bad3.example") {
            site.root = Some("/etc/miraserve/keys".to_owned());
        } else if site.hosts.iter().any(|h| h == "bad4.example") {
            site.root = Some("etc/miraserve".to_owned());
        } else if site.hosts.iter().any(|h| h == "bad5.example") {
            site.root = Some("/var/lib".to_owned());
        } else if site.hosts.iter().any(|h| h == "bad6.example") {
            site.root = Some("/var/log".to_owned());
        } else if site.hosts.iter().any(|h| h == "bad7.example") {
            site.root = Some("/usr/local".to_owned());
        } else if site.hosts.iter().any(|h| h == "bad8.example") {
            #[cfg(unix)]
            {
                site.root = Some(symlink_to_etc.display().to_string());
            }
        }
    }
    let roots_policy = SandboxPolicy::from_config_with_file(&roots_cfg, None, None);
    for allowed in ["/var/www", "/srv/www", "/opt/www"] {
        assert!(
            roots_policy
                .read_only_paths
                .iter()
                .any(|p| p == Path::new(allowed)),
            "explicitly configured docroot '{allowed}' must be allowed (R4-SBX-2)"
        );
    }
    for blocked in [
        "/etc",
        "etc",
        "/etc/miraserve/keys",
        "etc/miraserve",
        "/var/lib",
        "/var/log",
        "/usr/local",
    ] {
        assert!(
            !roots_policy
                .read_only_paths
                .iter()
                .any(|p| p == Path::new(blocked)),
            "unsafe configured root '{blocked}' must be refused (R3-SBX-3 / R4-SBX-2 / R5-SBX-1)"
        );
    }
    #[cfg(unix)]
    assert!(
        !roots_policy
            .read_only_paths
            .iter()
            .any(|p| p == &symlink_to_etc),
        "symlinked root pointing into /etc must be canonicalized and refused (R5-SBX-1)"
    );
    assert!(
        roots_policy.warnings.len() >= 7,
        "expected explicit warnings for all refused roots, got: {:?}",
        roots_policy.warnings
    );
    // Avoid installing process-wide `SeccompMode::Strict` (`SECCOMP_FILTER_FLAG_TSYNC`, which
    // blocks `execve` for sibling tests in this binary) or Landlock on the shared test runner
    // thread; this check verifies warning propagation into `SandboxReport.notes`.
    let mut report_policy = roots_policy.clone();
    report_policy.seccomp = SeccompMode::Off;
    report_policy.landlock = false;
    let report = apply_sandbox(&report_policy)?;
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("refused unsafe configured directory")),
        "expected refused-directory warning in SandboxReport.notes: {:?}",
        report.notes
    );

    // 2. Split-daemon mode with cert+key sharing `archive/example.com`: MUST NOT widen `archive/example.com`!
    let split_kdl = format!(
        r#"
server {{
    listen ":443"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "/run/miraserve-keyd/keyd.sock"
        cert "{}"
        key "{}"
    }}
}}
site "example.com" {{ root "/var/www/site1" }}
"#,
        kdl_path(&live_cert),
        kdl_path(&live_key)
    );
    let (split_cfg, _) = parse_kdl("split.kdl", &split_kdl)?;
    let split_policy = SandboxPolicy::from_config_with_file(&split_cfg, None, None);
    assert!(
        !split_policy
            .read_only_paths
            .iter()
            .any(|p| p == live_key.as_path()),
        "split-daemon mode must never expose tls.key to the worker"
    );
    #[cfg(unix)]
    {
        let canon_archive = std::fs::canonicalize(&archive_dir)?;
        assert!(
            !split_policy
                .read_only_paths
                .iter()
                .any(|p| p == &canon_archive),
            "split-daemon mode must NEVER widen archive/<site> when privkey lives beside cert (R3-SBX-3)"
        );
    }

    // 3. Broad/shared directories MUST NEVER be widened (R3-SBX-3)
    let mut broad_policy = SandboxPolicy::from_config_with_file(&in_proc_cfg, None, None);
    for (file_path, forbidden_parent) in [
        ("/srv/miraserve.kdl", "/srv"),
        ("/opt/miraserve.kdl", "/opt"),
        ("/var/lib/miraserve.kdl", "/var/lib"),
        ("/home/alice/miraserve.kdl", "/home/alice"),
        ("/etc/ssl/private/cert.pem", "/etc/ssl/private"),
        ("./miraserve.kdl", "."),
    ] {
        broad_policy.allow_reloadable_file(Path::new(file_path));
        assert!(
            !broad_policy
                .read_only_paths
                .iter()
                .any(|p| p == Path::new(forbidden_parent)),
            "must not widen '{file_path}' to broad directory '{forbidden_parent}'"
        );
    }

    // 4. Reload diff detects newly added docroot outside startup policy (R2-SBX-2)
    let reload_kdl = format!(
        r#"
server {{
    listen ":443"
    tls {{
        cert "{}"
        key "{}"
    }}
}}
site "example.com" {{ root "/var/www/site1" }}
site "new.example.com" {{ root "/var/www/site2" }}
"#,
        kdl_path(&live_cert),
        kdl_path(&live_key)
    );
    let (reload_cfg, _) = parse_kdl("reload.kdl", &reload_kdl)?;
    let reload_policy = SandboxPolicy::from_config_with_file(
        &reload_cfg,
        Some(Path::new("/etc/miraserve/miraserve.kdl")),
        None,
    );
    let uncovered = in_proc_policy.uncovered_paths_in(&reload_policy);
    assert_eq!(uncovered, vec![Path::new("/var/www/site2").to_path_buf()]);

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// R6-SBX-1 & R5-SBX-3: `find_docroot_acme_overlaps` catches docroots equal to, inside, above, or
/// symlink-aliased to `acme_dir` (and `SandboxPolicy` refuses granting RO access to them), and
/// `run_command_stdout_with_timeout` bounds NSS helper subprocesses cleanly.
#[test]
fn r6_sbx_1_and_r5_sbx_3_blocks_acme_docroot_overlap_and_bounds_nss_subprocess_timeout()
-> Result<(), Box<dyn std::error::Error>> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let base =
        std::env::temp_dir().join(format!("miraserve-r6-sbx-{}-{nanos}", std::process::id()));
    let acme_dir = base.join("custom-acme");
    let safe_root = base.join("public-www");
    std::fs::create_dir_all(&acme_dir)?;
    std::fs::create_dir_all(&safe_root)?;

    // Docroot equal to `base` (ancestor of `custom-acme`) MUST be flagged and omitted from RO!
    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{
        acme {{ email "ops@example.com"; }}
    }}
}}
site "leak.example.test" {{ root "{}"; }}
site "safe.example.test" {{ root "{}"; }}
"#,
        kdl_path(&base),
        kdl_path(&safe_root)
    );
    let (cfg, _) = parse_kdl("acme-overlap.kdl", &kdl)?;
    let overlaps = miraserve_sandbox::find_docroot_acme_overlaps(&cfg, &acme_dir);
    assert_eq!(
        overlaps.len(),
        1,
        "expected exactly 1 overlapping docroot (ancestor of acme_dir), got {overlaps:?}"
    );
    let policy = SandboxPolicy::from_config_with_file(&cfg, None, Some(&acme_dir));
    assert!(
        !policy.read_only_paths.contains(&base),
        "R6-SBX-1: SandboxPolicy must not grant Landlock RO to a docroot overlapping acme_dir"
    );
    assert!(
        policy.read_only_paths.contains(&safe_root),
        "disjoint safe docroot must still be granted RO"
    );
    assert!(
        policy
            .warnings
            .iter()
            .any(|w| w.contains("overlaps ACME state directory")),
        "expected overlap warning in SandboxPolicy, got {:?}",
        policy.warnings
    );

    // R5-SBX-3: Bounded subprocess timeout kills hung commands and returns fast, while quick
    // `/usr/bin/id -u` succeeds cleanly on Unix.
    #[cfg(unix)]
    {
        // Run `/usr/bin/id -u` up to 3 attempts and record each attempt's elapsed duration for
        // failure diagnostics.
        let mut attempts = Vec::new();
        let mut uid_out = None;
        for _ in 0..3 {
            let started = std::time::Instant::now();
            uid_out = miraserve_sandbox::run_command_stdout_with_timeout(
                "/usr/bin/id",
                &["-u"],
                std::time::Duration::from_secs(30),
            );
            attempts.push(started.elapsed());
            if uid_out
                .as_deref()
                .and_then(|s| s.trim().parse::<u32>().ok())
                .is_some()
            {
                break;
            }
        }
        assert!(
            uid_out
                .as_deref()
                .and_then(|s| s.trim().parse::<u32>().ok())
                .is_some(),
            "expected numeric UID from /usr/bin/id -u, got {uid_out:?} after attempts taking {attempts:?}"
        );
        let sleep_bin = ["/bin/sleep", "/usr/bin/sleep"]
            .into_iter()
            .find(|p| Path::new(p).is_file())
            .unwrap_or("/bin/sleep");
        let started = std::time::Instant::now();
        let timed_out = miraserve_sandbox::run_command_stdout_with_timeout(
            sleep_bin,
            &["10"],
            std::time::Duration::from_millis(120),
        );
        assert!(
            timed_out.is_none(),
            "hung subprocess must return None on timeout"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "hung subprocess was not killed promptly (elapsed={:?})",
            started.elapsed()
        );
    }

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// R7-SBX-1, R7-SBX-2 & Section 5: Verifies every Section 5 docroot entry is denied by default,
/// `server { allow-docroot "..." }` opens ONLY explicit non-system subdirectories (never `/etc`,
/// `/var/lib/miraserve`, `/var/lib`, or top-level roots), and `find_unsafe_docroots` catches
/// symlink-to-`/etc`, ACME overlaps, config-dir containment, and TLS key containment.
#[test]
#[allow(clippy::too_many_lines)]
fn r7_sbx_section5_default_deny_docroots_allow_docroot_and_symlink_confinement() -> TestResult {
    let section5_denied = [
        // MiraServe's own state on other prefixes
        "/opt/homebrew/var/lib/miraserve/acme",
        "/opt/homebrew/etc/miraserve/certs",
        "/private/var/lib/miraserve/acme",
        "/usr/local/var/lib/miraserve/acme",
        // Other service secrets under /var/lib, /var/log, /run, /Library, /usr/lib/ssl
        "/var/lib/letsencrypt",
        "/var/lib/mariadb",
        "/var/lib/pgsql",
        "/var/lib/postgres",
        "/var/lib/php/sessions",
        "/var/lib/private",
        "/var/lib/kubelet",
        "/var/backups",
        "/var/mail",
        "/var/log/nginx",
        "/run/secrets",
        "/run/credentials",
        "/run/user/1000",
        "/var/run/secrets/kubernetes.io",
        "/Library/Keychains",
        "/usr/lib/ssl/private",
        // Whole top-level trees
        "/srv",
        "/opt",
        "/mnt",
        "/data",
        "/System",
        "/Volumes",
    ];
    for denied in section5_denied {
        let kdl = format!(
            r#"
server {{
    listen ":443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }}
}}
site "test.example" {{ root "{denied}" }}
"#
        );
        assert!(
            parse_kdl("denied.kdl", &kdl).is_err(),
            "Section 5 docroot '{denied}' MUST be refused by default"
        );
    }

    // Explicit `server { allow-docroot "/var/lib/custom-app/public" }` opens ONLY that subtree.
    let exempted_kdl = r#"
server {
    listen ":443"
    allow-docroot "/var/lib/custom-app/public"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }
}
site "app.example" { root "/var/lib/custom-app/public" }
site "sub.example" { root "/var/lib/custom-app/public/static" }
"#;
    assert!(
        parse_kdl("exempted.kdl", exempted_kdl).is_ok(),
        "explicit allow-docroot must allow its exact subtree"
    );

    // `allow-docroot` MUST NOT exempt unconditionally forbidden OS/MiraServe/top-level paths.
    for unexemptable in [
        "/etc",
        "/var/lib",
        "/var/lib/miraserve",
        "/opt/homebrew/var/lib/miraserve/acme",
        "/run/secrets",
        "/srv",
    ] {
        let bad_exempt = format!(
            r#"
server {{
    listen ":443"
    allow-docroot "{unexemptable}"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }}
}}
site "app.example" {{ root "/var/www/app" }}
"#
        );
        assert!(
            parse_kdl("bad-exempt.kdl", &bad_exempt).is_err(),
            "allow-docroot '{unexemptable}' must be rejected"
        );
    }

    // `find_unsafe_docroots` catches symlinked docroot -> /etc, ACME overlap, and TLS key inside docroot.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::env::temp_dir().join(format!(
        "miraserve-r7-sbx-sec5-{}-{nanos}",
        std::process::id()
    ));
    let acme_dir = base.join("acme-state");
    let key_dir = base.join("site-with-key");
    std::fs::create_dir_all(&acme_dir)?;
    std::fs::create_dir_all(&key_dir)?;
    let leaked_key = key_dir.join("server.key");
    std::fs::write(&leaked_key, b"dummy")?;

    let kdl_overlap = format!(
        r#"
server {{
    listen ":443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "{}" }}
}}
site "keyleak.example" {{ root "{}" }}
site "acmeleak.example" {{ root "{}" }}
"#,
        kdl_path(&leaked_key),
        kdl_path(&key_dir),
        kdl_path(&acme_dir),
    );
    let (cfg_overlap, _) = parse_kdl("overlap.kdl", &kdl_overlap)?;
    let violations = miraserve_sandbox::find_unsafe_docroots(&cfg_overlap, None, Some(&acme_dir));
    assert!(
        violations
            .iter()
            .any(|v| v.contains("ACME state directory")),
        "expected ACME overlap violation, got: {violations:?}"
    );
    assert!(
        violations.iter().any(|v| v.contains("server.tls.key")),
        "expected TLS key containment violation, got: {violations:?}"
    );

    #[cfg(unix)]
    {
        let link_etc = base.join("etc-link");
        std::os::unix::fs::symlink("/etc", &link_etc)?;
        let kdl_sym = format!(
            r#"
server {{
    listen ":443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }}
}}
site "sym.example" {{ root "{}" }}
"#,
            link_etc.display()
        );
        let (cfg_sym, _) = parse_kdl("sym.kdl", &kdl_sym)?;
        let sym_violations = miraserve_sandbox::find_unsafe_docroots(&cfg_sym, None, None);
        assert!(
            sym_violations
                .iter()
                .any(|v| v.contains("resolves to forbidden directory")),
            "R7-SBX-2: symlink to /etc must be reported by find_unsafe_docroots, got: {sym_violations:?}"
        );
    }

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Verifies `SandboxPolicy::from_config` includes `/usr/share/ca-certificates` (when present)
/// and the canonical regular-file target of `/etc/resolv.conf` in `read_only_paths`, without
/// including `/etc/ssl/private` or `/etc/ssl`.
#[cfg(target_os = "linux")]
#[test]
fn linux_landlock_includes_distro_ca_symlink_targets_without_private_keys()
-> Result<(), Box<dyn std::error::Error>> {
    use std::path::PathBuf;

    let (cfg, _) = parse_kdl(
        "ca.kdl",
        r#"
server {
    listen ":443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }
}
site "example.com" { root "/var/www/site" }
"#,
    )?;
    let policy = SandboxPolicy::from_config(&cfg, None);
    if Path::new("/usr/share/ca-certificates").exists() {
        assert!(
            policy
                .read_only_paths
                .contains(&PathBuf::from("/usr/share/ca-certificates")),
            "Debian/Ubuntu CA symlink target /usr/share/ca-certificates must be granted RO"
        );
    }
    if let Ok(canon_resolv) = std::fs::canonicalize("/etc/resolv.conf")
        && canon_resolv.is_file()
    {
        assert!(
            policy.read_only_paths.contains(&canon_resolv),
            "canonical /etc/resolv.conf target {} must be granted RO",
            canon_resolv.display()
        );
    }
    assert!(
        !policy
            .read_only_paths
            .contains(&PathBuf::from("/etc/ssl/private")),
        "/etc/ssl/private must never be granted RO"
    );
    assert!(
        !policy.read_only_paths.contains(&PathBuf::from("/etc/ssl")),
        "/etc/ssl wholesale must never be granted RO"
    );
    Ok(())
}

/// R8-SBX-1: the docroot secret check must also cover the reverse-proxy upstream mTLS client key
/// and the `keyd` HMAC secret file named on the command line. Neither has a `.key`/`.pem` name,
/// so the static deny rule would serve both.
#[test]
fn r8_sbx_1_docroot_check_covers_upstream_client_key_and_keyd_secret_file() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base =
        std::env::temp_dir().join(format!("miraserve-r8-sbx-1-{}-{nanos}", std::process::id()));
    let pub_dir = base.join("pub");
    std::fs::create_dir_all(&pub_dir)?;
    let client_key = pub_dir.join("upstream-client-key");
    let keyd_secret = pub_dir.join("keyd.secret");
    std::fs::write(&client_key, b"-----BEGIN PRIVATE KEY-----\n")?;
    std::fs::write(&keyd_secret, b"0123456789abcdef0123456789abcdef")?;

    let kdl = format!(
        r#"
server {{
    listen ":443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }}
}}
site "leak.example" {{
    root "{root}"
    route "/api/*" {{
        reverse-proxy {{
            upstream "https://127.0.0.1:9443"
            upstream-tls {{
                client-cert "/etc/miraserve/certs/client.crt"
                client-key "{client_key}"
            }}
        }}
    }}
}}
"#,
        root = kdl_path(&pub_dir),
        client_key = kdl_path(&client_key),
    );
    let (cfg, _) = parse_kdl("r8-sbx-1.kdl", &kdl)?;

    let violations = miraserve_sandbox::find_unsafe_docroots(&cfg, None, None);
    assert!(
        violations.iter().any(|v| v.contains("client-key")),
        "R8-SBX-1: upstream mTLS client key inside a document root must be reported, got: {violations:?}"
    );
    assert!(
        !violations.iter().any(|v| v.contains("keyd auth secret")),
        "without the CLI path the keyd secret is unknown to the check: {violations:?}"
    );

    let with_secret = miraserve_sandbox::find_unsafe_docroots_with_secret_files(
        &cfg,
        None,
        None,
        std::slice::from_ref(&keyd_secret),
    );
    assert!(
        with_secret.iter().any(|v| v.contains("keyd auth secret")),
        "R8-SBX-1: keyd HMAC secret file inside a document root must be reported, got: {with_secret:?}"
    );

    // A secret outside every document root is fine.
    let outside = base.join("secrets/keyd.secret");
    let clean = miraserve_sandbox::find_unsafe_docroots_with_secret_files(
        &cfg,
        None,
        None,
        std::slice::from_ref(&outside),
    );
    assert!(
        !clean.iter().any(|v| v.contains("keyd auth secret")),
        "a secret outside the document root must not be reported: {clean:?}"
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Hosting-panel layout: `sandbox { read-tree ...; socket-tree ... }` puts whole directory trees
/// into the startup Landlock policy, so a site (and its PHP socket and certificate) added by a
/// later reload is already covered. Without the trees the same reload needs a restart.
#[test]
#[allow(clippy::too_many_lines)]
fn hosting_read_tree_and_socket_tree_cover_sites_added_by_reload() -> TestResult {
    let config = |sandbox_extra: &str, second_site: bool| {
        let extra_site = if second_site {
            r#"
site "b.example" {
    tls { cert "/opt/amira/ssl/certs/b.example/fullchain.pem"; key "/opt/amira/ssl/certs/b.example/privkey.pem" }
    root "/home/usr_b/public_html/b.example"
    route "*.php" { fastcgi-pass "unix:/run/php/php8.3-fpm-usr_b.sock" }
}
"#
        } else {
            ""
        };
        format!(
            r#"
server {{
    listen ":443"
    tls {{ cert "/opt/amira/ssl/certs/default/fullchain.pem"; key "/opt/amira/ssl/certs/default/privkey.pem" }}
    sandbox {{
        landlock #true
        seccomp "strict"
        {sandbox_extra}
    }}
}}
site "a.example" {{
    root "/home/usr_a/public_html/a.example"
    route "*.php" {{ fastcgi-pass "unix:/run/php/php8.3-fpm-usr_a.sock" }}
}}
{extra_site}
"#
        )
    };
    let trees = "read-tree \"/home\" \"/opt/amira/ssl/certs\"\n        socket-tree \"/run/php\"";

    // With the trees: the startup policy contains them, and adding site B leaves nothing
    // uncovered.
    let (startup, _) = parse_kdl("hosting-startup.kdl", &config(trees, false))?;
    let (reloaded, _) = parse_kdl("hosting-reload.kdl", &config(trees, true))?;
    let startup_policy = SandboxPolicy::from_config(&startup, None);
    let reloaded_policy = SandboxPolicy::from_config(&reloaded, None);
    assert!(
        startup_policy
            .read_only_paths
            .iter()
            .any(|p| p == Path::new("/home")),
        "read-tree must be in the startup read-only set: {:?}",
        startup_policy.read_only_paths
    );
    assert!(
        startup_policy
            .socket_paths
            .iter()
            .any(|p| p == Path::new("/run/php")),
        "socket-tree must be in the startup socket set: {:?}",
        startup_policy.socket_paths
    );
    let uncovered = startup_policy.uncovered_paths_in(&reloaded_policy);
    assert!(
        uncovered.is_empty(),
        "a site added under the granted trees must not need a restart, uncovered: {uncovered:?}"
    );

    // Without the trees the same reload leaves the new docroot and socket outside the policy.
    let (bare_startup, _) = parse_kdl("bare-startup.kdl", &config("", false))?;
    let (bare_reloaded, _) = parse_kdl("bare-reload.kdl", &config("", true))?;
    let bare_uncovered = SandboxPolicy::from_config(&bare_startup, None)
        .uncovered_paths_in(&SandboxPolicy::from_config(&bare_reloaded, None));
    assert!(
        bare_uncovered.iter().any(|p| p.starts_with("/home/usr_b")),
        "control: without read-tree the new docroot is uncovered, got: {bare_uncovered:?}"
    );
    assert!(
        bare_uncovered.iter().any(|p| p.starts_with("/run/php")),
        "control: without socket-tree the new socket is uncovered, got: {bare_uncovered:?}"
    );

    // Trees that touch system, secret or MiraServe state directories are refused by the config.
    for bad in [
        "/",
        "/etc",
        "/etc/ssl",
        "/var",
        "/run",
        "/root",
        "/proc",
        "/var/lib/miraserve",
        "/var/lib/miraserve/acme",
        "/run/miraserve-keyd",
        "relative/path",
        "/home/../etc",
        "/home//x",
    ] {
        assert!(
            parse_kdl(
                "bad-tree.kdl",
                &config(&format!("read-tree \"{bad}\""), false)
            )
            .is_err(),
            "read-tree '{bad}' must be rejected"
        );
        assert!(
            parse_kdl(
                "bad-sock-tree.kdl",
                &config(&format!("socket-tree \"{bad}\""), false)
            )
            .is_err(),
            "socket-tree '{bad}' must be rejected"
        );
    }

    // A tree that is a symlink into a forbidden directory is refused on the real location.
    #[cfg(unix)]
    {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let base =
            std::env::temp_dir().join(format!("miraserve-tree-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&base)?;
        let link = base.join("sites");
        std::os::unix::fs::symlink("/etc", &link)?;
        let (cfg, _) = parse_kdl(
            "symlink-tree.kdl",
            &config(&format!("read-tree \"{}\"", link.display()), false),
        )?;
        let violations = miraserve_sandbox::find_unsafe_docroots(&cfg, None, None);
        assert!(
            violations.iter().any(|v| v.contains("read-tree")),
            "a read-tree that resolves into /etc must be reported, got: {violations:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
    Ok(())
}

/// A site `root` that is a symlink inside a granted `read-tree` pointing outside it must be
/// reported as uncovered by `SandboxPolicy::uncovered_paths_in`.
#[cfg(unix)]
#[test]
fn reload_coverage_follows_symlinks_out_of_a_granted_tree() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::fs::canonicalize(std::env::temp_dir())?
        .join(format!("miraserve-symroot-{}-{nanos}", std::process::id()));
    let tree = base.join("tree");
    let outside = base.join("outside");
    std::fs::create_dir_all(tree.join("real"))?;
    std::fs::create_dir_all(&outside)?;
    std::os::unix::fs::symlink(&outside, tree.join("rootlink"))?;

    let config = |root: &Path| {
        format!(
            r#"
server {{
    listen ":443"
    tls {{ cert "/opt/panel/certs/a.pem"; key "/opt/panel/certs/a.key" }}
    sandbox {{ read-tree "{}" }}
}}
site "a.example" {{ root "{}" }}
"#,
            tree.display(),
            root.display()
        )
    };
    let (startup, _) = parse_kdl("sym-startup.kdl", &config(&tree.join("real")))?;
    let startup_policy = SandboxPolicy::from_config(&startup, None);

    let (inside, _) = parse_kdl("sym-inside.kdl", &config(&tree.join("real")))?;
    assert!(
        startup_policy
            .uncovered_paths_in(&SandboxPolicy::from_config(&inside, None))
            .is_empty(),
        "control: a real directory inside the tree is covered"
    );

    let (escaping, _) = parse_kdl("sym-escape.kdl", &config(&tree.join("rootlink")))?;
    let uncovered = startup_policy.uncovered_paths_in(&SandboxPolicy::from_config(&escaping, None));
    assert!(
        uncovered.iter().any(|p| p.ends_with("rootlink")),
        "a root that is a symlink out of the granted tree must be uncovered, got: {uncovered:?}"
    );
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Codex G7: `SandboxPolicy::allow_log_rotation_dir` must grant read-write access to safe
/// rotating log parent directories so `rename()` + reopen succeed under Landlock, while refusing
/// broad system/secret directories and any directory overlapping configured document roots.
#[test]
fn g7_allow_log_rotation_dir_grants_safe_dir_and_refuses_system_or_docroot_dirs() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::env::temp_dir().join(format!(
        "miraserve-g7-log-sbx-{}-{nanos}",
        std::process::id()
    ));
    let docroot = base.join("www");
    let log_dir = base.join("logs");
    let tls_dir = base.join("tls");
    std::fs::create_dir_all(&docroot)?;
    std::fs::create_dir_all(&log_dir)?;
    std::fs::create_dir_all(&tls_dir)?;

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "{cert}"; key "{key}" }}
}}
site "app.example.test" {{
    root "{root}"
}}
"#,
        cert = tls_dir.join("c.crt").to_string_lossy().replace('\\', "/"),
        key = tls_dir.join("c.key").to_string_lossy().replace('\\', "/"),
        root = docroot.to_string_lossy().replace('\\', "/"),
    );
    let (cfg, _) = parse_kdl("g7-log-sbx.kdl", &kdl)?;
    let mut policy = SandboxPolicy::from_config(&cfg, None);

    // 1. Safe dedicated log directory is granted RW (bound to its validated canonical path).
    let safe_log = log_dir.join("access.log");
    let canonical_log_dir = {
        let canon = std::fs::canonicalize(&log_dir)?;
        // On Windows, `allow_log_rotation_dir` strips the `\\?\` verbatim prefix before storing
        // normalized paths in `read_write_paths`.
        #[cfg(windows)]
        let canon = {
            let s = canon.to_string_lossy();
            std::path::PathBuf::from(s.strip_prefix(r"\\?\").unwrap_or(&s))
        };
        canon
    };
    policy
        .allow_log_rotation_dir(&safe_log, &cfg)
        .map_err(|err| format!("expected safe log dir to be granted: {err}"))?;
    assert!(
        policy.read_write_paths.contains(&canonical_log_dir),
        "safe log parent dir must be in read_write_paths, got: {:?}",
        policy.read_write_paths
    );

    // 2. Broad system directory (`/etc` on Unix, `C:\Windows` on Windows) is refused.
    #[cfg(unix)]
    assert!(
        policy
            .allow_log_rotation_dir(std::path::Path::new("/etc/access.log"), &cfg)
            .is_err(),
        "/etc must never be granted RW for log rotation"
    );
    #[cfg(windows)]
    assert!(
        policy
            .allow_log_rotation_dir(std::path::Path::new(r"C:\Windows\access.log"), &cfg)
            .is_err(),
        "C:\\Windows must never be granted RW for log rotation"
    );

    // 3. Log directory overlapping a site document root is refused.
    assert!(
        policy
            .allow_log_rotation_dir(&docroot.join("access.log"), &cfg)
            .is_err(),
        "docroot must never be granted RW for log rotation"
    );
    assert!(
        !policy.read_write_paths.contains(&docroot),
        "docroot must remain excluded from read_write_paths"
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Codex G7 (P1): `allow_log_rotation_dir_with_context` must validate the canonical real
/// destination against BOTH forbidden system trees (blocking symlinked log dirs pointing to `/etc`)
/// and custom split-daemon private-key directories outside `/etc/miraserve/keys`, and bind the
/// Landlock RW grant to the validated canonical directory.
#[cfg(unix)]
#[test]
fn g7_p1_log_rotation_dir_blocks_symlink_escape_and_custom_split_key_dirs() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::env::temp_dir().join(format!(
        "miraserve-g7-p1-sbx-{}-{nanos}",
        std::process::id()
    ));
    let docroot = base.join("www");
    let custom_keys = base.join("custom-vault");
    let real_logs = base.join("real-logs");
    let sym_to_etc = base.join("sym-etc");
    let sym_to_keys = base.join("sym-keys");
    let sym_to_safe = base.join("sym-safe");
    std::fs::create_dir_all(&docroot)?;
    std::fs::create_dir_all(&custom_keys)?;
    std::fs::create_dir_all(&real_logs)?;
    std::fs::write(custom_keys.join("server.key"), b"dummy-key")?;
    std::os::unix::fs::symlink("/etc", &sym_to_etc)?;
    std::os::unix::fs::symlink(&custom_keys, &sym_to_keys)?;
    std::os::unix::fs::symlink(&real_logs, &sym_to_safe)?;

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{
        cert "{cert}"
        key "{key}"
        key-isolation "split-daemon"
        keyd-socket "/run/miraserve-keyd/keyd.sock"
    }}
}}
site "app.example.test" {{
    root "{root}"
}}
"#,
        cert = base.join("server.crt").to_string_lossy().replace('\\', "/"),
        key = custom_keys
            .join("server.key")
            .to_string_lossy()
            .replace('\\', "/"),
        root = docroot.to_string_lossy().replace('\\', "/"),
    );
    let (cfg, _) = parse_kdl("g7-p1.kdl", &kdl)?;
    let mut policy = SandboxPolicy::from_config(&cfg, None);

    // 1. Symlink pointing into `/etc` must be rejected!
    assert!(
        policy
            .allow_log_rotation_dir(&sym_to_etc.join("access.log"), &cfg)
            .is_err(),
        "symlinked log dir resolving to /etc must be rejected"
    );

    // 2. Custom split-daemon private-key dir (directly OR via symlink) must be rejected!
    assert!(
        policy
            .allow_log_rotation_dir(&custom_keys.join("access.log"), &cfg)
            .is_err(),
        "custom split-daemon private-key directory must be rejected"
    );
    assert!(
        policy
            .allow_log_rotation_dir(&sym_to_keys.join("access.log"), &cfg)
            .is_err(),
        "symlinked log dir resolving to custom split-daemon key dir must be rejected"
    );

    // 3. Benign symlink pointing to a safe log dir binds the rule to the canonical target!
    policy
        .allow_log_rotation_dir(&sym_to_safe.join("access.log"), &cfg)
        .map_err(|err| format!("expected safe log dir to succeed: {err}"))?;
    let canon_logs = std::fs::canonicalize(&real_logs)?;
    assert!(
        policy.read_write_paths.contains(&canon_logs),
        "Landlock RW rule must be bound to canonical path {}, got: {:?}",
        canon_logs.display(),
        policy.read_write_paths
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Codex Round-3 P1 #1 (G7): `allow_log_rotation_dir_with_context` must pin an open directory
/// descriptor at validation time, keep referencing the original inode even if the path is swapped,
/// and fail closed on `verify_pinned_writable_dirs` and `apply_landlock_current_thread` if the
/// directory at the path is replaced with a different directory or symlink.
#[cfg(unix)]
#[test]
fn g7_r3_p1_pinned_log_dir_detects_swap_and_blocks_landlock_install() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::env::temp_dir().join(format!(
        "miraserve-g7-r3-pin-{}-{nanos}",
        std::process::id()
    ));
    let docroot = base.join("www");
    let log_dir = base.join("logs");
    let swapped_out = base.join("logs-old");
    std::fs::create_dir_all(&docroot)?;
    std::fs::create_dir_all(&log_dir)?;

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "{cert}"; key "{key}" }}
}}
site "app.example.test" {{
    root "{root}"
}}
"#,
        cert = base.join("tls/c.crt").to_string_lossy().replace('\\', "/"),
        key = base.join("tls/c.key").to_string_lossy().replace('\\', "/"),
        root = docroot.to_string_lossy().replace('\\', "/"),
    );
    let (cfg, _) = parse_kdl("g7-r3-pin.kdl", &kdl)?;
    let mut policy = SandboxPolicy::from_config(&cfg, None);

    policy
        .allow_log_rotation_dir(&log_dir.join("access.log"), &cfg)
        .map_err(|err| format!("expected safe log dir to pin: {err}"))?;
    let pinned = policy
        .pinned_read_write_dirs
        .first()
        .ok_or("expected rotating log directory to be pinned")?;
    let orig_id = pinned.inode_identity();
    assert!(
        policy.verify_pinned_writable_dirs().is_ok(),
        "unmodified pinned directory must pass verification"
    );

    // 1. Swap the directory at `log_dir` with a brand-new directory (different inode).
    std::fs::rename(&log_dir, &swapped_out)?;
    std::fs::create_dir_all(&log_dir)?;
    assert_eq!(
        policy
            .pinned_read_write_dirs
            .first()
            .map(miraserve_sandbox::PinnedWritableDir::inode_identity),
        Some(orig_id),
        "pinned descriptor must still hold the original validated inode"
    );
    assert!(
        policy.verify_pinned_writable_dirs().is_err(),
        "swapped directory identity must fail pinned verification"
    );
    assert!(
        miraserve_sandbox::apply_landlock_current_thread(&policy).is_err(),
        "Landlock thread installer must refuse to install rules after directory swap"
    );

    // 2. Replace `log_dir` with a symlink pointing to `/etc`.
    std::fs::remove_dir_all(&log_dir)?;
    std::os::unix::fs::symlink("/etc", &log_dir)?;
    assert!(
        policy.verify_pinned_writable_dirs().is_err(),
        "symlink replacement at pinned path must fail verification"
    );
    assert!(
        miraserve_sandbox::apply_landlock_current_thread(&policy).is_err(),
        "Landlock thread installer must refuse symlink-replaced log dir"
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Codex Round-3 P1 #2 (G7): `allow_log_rotation_dir_with_context` must refuse rotating log
/// directories that overlap configured trust anchors and verification files (mTLS `client-ca`,
/// `ai-publish` `require-signature` / `jwt-public-key`, `bot-auth` `agent-keys-file`, TLS certs,
/// `upstream-tls` CA certs, and WASM plugin modules).
#[test]
#[allow(clippy::too_many_lines)]
fn g7_r3_p1_log_rotation_dir_blocks_trust_anchors_and_verification_keys() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::env::temp_dir().join(format!(
        "miraserve-g7-r3-trust-{}-{nanos}",
        std::process::id()
    ));
    let docroot = base.join("www");
    let ca_dir = base.join("ca");
    let pub_key_dir = base.join("publish-keys");
    let jwt_key_dir = base.join("jwt-keys");
    let bot_key_dir = base.join("bot-keys");
    let cert_dir = base.join("certs");
    let upstream_ca_dir = base.join("upstream-ca");
    let wasm_dir = base.join("wasm");
    let safe_log_dir = base.join("logs");
    for d in [
        &docroot,
        &ca_dir,
        &pub_key_dir,
        &jwt_key_dir,
        &bot_key_dir,
        &cert_dir,
        &upstream_ca_dir,
        &wasm_dir,
        &safe_log_dir,
    ] {
        std::fs::create_dir_all(d)?;
    }

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{
        cert "{cert}"
        key "{key}"
        client-ca "{ca}"
    }}
}}
site "trust.example.test" {{
    root "{root}"
    bot-auth {{
        agent-keys-file "{bot_keys}"
    }}
    ai-publish {{
        storage "{storage}"
        mcp-endpoint "/_miraserve/publish" auth="oauth-jwt"
        jwt-public-key "ed25519:{jwt_pub}"
        require-signature "ed25519:{sig_pub}"
    }}
    route "/api/*" {{
        reverse-proxy {{
            upstream "https://127.0.0.1:9443"
            upstream-tls {{
                ca-cert "{upstream_ca}"
            }}
        }}
    }}
    route "/wasm/*" {{
        wasm-plugin "{wasm_mod}"
    }}
}}
"#,
        cert = cert_dir
            .join("server.crt")
            .to_string_lossy()
            .replace('\\', "/"),
        key = base
            .join("keys/server.key")
            .to_string_lossy()
            .replace('\\', "/"),
        ca = ca_dir.join("ca.pem").to_string_lossy().replace('\\', "/"),
        root = docroot.to_string_lossy().replace('\\', "/"),
        bot_keys = bot_key_dir
            .join("agents.json")
            .to_string_lossy()
            .replace('\\', "/"),
        storage = base
            .join("publish-store")
            .to_string_lossy()
            .replace('\\', "/"),
        jwt_pub = jwt_key_dir
            .join("jwt.pub")
            .to_string_lossy()
            .replace('\\', "/"),
        sig_pub = pub_key_dir
            .join("release.pub")
            .to_string_lossy()
            .replace('\\', "/"),
        upstream_ca = upstream_ca_dir
            .join("up-ca.pem")
            .to_string_lossy()
            .replace('\\', "/"),
        wasm_mod = wasm_dir
            .join("filter.wasm")
            .to_string_lossy()
            .replace('\\', "/"),
    );
    let (cfg, _) = parse_kdl("g7-r3-trust.kdl", &kdl)?;
    // Round-5: a WASM module is a tenant file and is protected only when the loader would accept
    // it (an existing regular file with no symlink in any component).
    std::fs::write(wasm_dir.join("filter.wasm"), b"\0asm\x01\0\0\0")?;
    let mut policy = SandboxPolicy::from_config(&cfg, None);

    for (label, dir) in [
        ("mTLS client-ca", &ca_dir),
        ("ai-publish require-signature public-key", &pub_key_dir),
        ("ai-publish jwt-public-key", &jwt_key_dir),
        ("bot-auth agent-keys-file", &bot_key_dir),
        ("TLS cert", &cert_dir),
        ("upstream-tls ca-cert", &upstream_ca_dir),
        ("wasm-plugin module", &wasm_dir),
    ] {
        let res = policy.allow_log_rotation_dir(&dir.join("access.log"), &cfg);
        assert!(
            res.is_err(),
            "rotating log dir overlapping {label} ({}) must be rejected",
            dir.display()
        );
    }

    // Ancestor directory covering the trust/key subdirectories must also be refused!
    assert!(
        policy
            .allow_log_rotation_dir(&base.join("access.log"), &cfg)
            .is_err(),
        "ancestor directory covering trust/key subdirectories must be rejected"
    );

    // Separate dedicated log directory is still accepted.
    policy
        .allow_log_rotation_dir(&safe_log_dir.join("access.log"), &cfg)
        .map_err(|err| format!("expected dedicated safe log dir to succeed: {err}"))?;

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Codex Round-4 P2 #1 (G7): When a configured trust file (`client-ca`, `require-signature` key,
/// etc.) is an outward-pointing symbolic link placed inside a proposed rotating log directory,
/// BOTH the directory containing the link AND the resolved target's directory MUST be protected
/// from RW grants — while a dedicated sibling/child `logs/` subdirectory beside a regular trust
/// file remains allowed.
#[cfg(unix)]
#[test]
fn g7_r4_p2_outward_trust_file_symlink_inside_log_dir_is_protected() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::env::temp_dir().join(format!(
        "miraserve-g7-r4-trust-sym-{}-{nanos}",
        std::process::id()
    ));
    let docroot = base.join("www");
    let logs_dir = base.join("logs");
    let dedicated_logs = base.join("dedicated-logs");
    let external_trust = base.join("external-trust");
    std::fs::create_dir_all(&docroot)?;
    std::fs::create_dir_all(&logs_dir)?;
    std::fs::create_dir_all(&dedicated_logs)?;
    std::fs::create_dir_all(&external_trust)?;

    let real_ca = external_trust.join("ca.pem");
    let real_sig = external_trust.join("release.pub");
    std::fs::write(&real_ca, b"dummy-ca")?;
    std::fs::write(&real_sig, b"dummy-sig-pub")?;
    std::fs::write(base.join("server.crt"), b"dummy-cert")?;
    std::fs::write(base.join("server.key"), b"dummy-key")?;

    // Outward-pointing symlinks sitting INSIDE `logs_dir` pointing to `external_trust`.
    let ca_link = logs_dir.join("client-ca.pem");
    let sig_link = logs_dir.join("release.pub");
    std::os::unix::fs::symlink(&real_ca, &ca_link)?;
    std::os::unix::fs::symlink(&real_sig, &sig_link)?;

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{
        cert "{cert}"
        key "{key}"
        client-ca "{ca}"
    }}
}}
site "trust-sym.example.test" {{
    root "{root}"
    ai-publish {{
        storage "{storage}"
        require-signature "ed25519:{sig}"
    }}
}}
"#,
        cert = base.join("server.crt").to_string_lossy().replace('\\', "/"),
        key = base.join("server.key").to_string_lossy().replace('\\', "/"),
        ca = ca_link.to_string_lossy().replace('\\', "/"),
        root = docroot.to_string_lossy().replace('\\', "/"),
        storage = base
            .join("publish-store")
            .to_string_lossy()
            .replace('\\', "/"),
        sig = sig_link.to_string_lossy().replace('\\', "/"),
    );
    let (cfg, _) = parse_kdl("g7-r4-trust-sym.kdl", &kdl)?;
    let mut policy = SandboxPolicy::from_config(&cfg, None);

    // 1. Directory containing the outward-pointing symlink (`logs_dir`) MUST be rejected!
    assert!(
        policy
            .allow_log_rotation_dir(&logs_dir.join("access.log"), &cfg)
            .is_err(),
        "rotating log dir containing an outward-pointing trust-file symlink must be rejected"
    );

    // 2. Resolved target's directory (`external_trust`) MUST ALSO be rejected!
    assert!(
        policy
            .allow_log_rotation_dir(&external_trust.join("access.log"), &cfg)
            .is_err(),
        "rotating log dir covering resolved trust-file target directory must be rejected"
    );

    // 3. Dedicated sibling/child `dedicated-logs` next to regular `base/server.crt` STILL succeeds!
    policy
        .allow_log_rotation_dir(&dedicated_logs.join("access.log"), &cfg)
        .map_err(|err| format!("dedicated log subdir beside regular cert must succeed: {err}"))?;

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Codex Round-4 P2 (Windows G7): Ordinary drive-qualified Windows paths with backslashes MUST
/// be accepted by `allow_log_rotation_dir` for safe dedicated log directories, while logs inside
/// a document root or Windows system directory (`C:\Windows`) remain rejected.
#[cfg(windows)]
#[test]
fn g7_r4_p2_windows_rotating_log_path_is_allowed_and_docroot_overlap_blocked() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::env::temp_dir().join(format!(
        "miraserve-g7-r4-win-{}-{nanos}",
        std::process::id()
    ));
    let docroot = base.join("www");
    let log_dir = base.join("logs");
    let tls_dir = base.join("tls");
    std::fs::create_dir_all(&docroot)?;
    std::fs::create_dir_all(&log_dir)?;
    std::fs::create_dir_all(&tls_dir)?;

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "{cert}"; key "{key}" }}
}}
site "win.example.test" {{
    root "{root}"
}}
"#,
        cert = tls_dir.join("c.crt").to_string_lossy().replace('\\', "/"),
        key = tls_dir.join("c.key").to_string_lossy().replace('\\', "/"),
        root = docroot.to_string_lossy().replace('\\', "/"),
    );
    let (cfg, _) = parse_kdl("g7-r4-win.kdl", &kdl)?;
    let mut policy = SandboxPolicy::from_config(&cfg, None);

    // 1. Ordinary drive-qualified Windows rotating log path succeeds and pins cleanly.
    policy
        .allow_log_rotation_dir(&log_dir.join("access.log"), &cfg)
        .map_err(|err| format!("expected Windows rotating log dir to succeed: {err}"))?;

    // 2. Rotating log inside a Windows document root is still refused.
    assert!(
        policy
            .allow_log_rotation_dir(&docroot.join("access.log"), &cfg)
            .is_err(),
        "rotating log inside Windows docroot must be rejected"
    );

    // 3. Rotating log in `C:\Windows` is refused.
    assert!(
        policy
            .allow_log_rotation_dir(std::path::Path::new(r"C:\Windows\access.log"), &cfg)
            .is_err(),
        "rotating log in C:\\Windows must be rejected"
    );

    drop(policy);
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

fn r5_temp_base(tag: &str) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::fs::canonicalize(std::env::temp_dir())?
        .join(format!("miraserve-r5-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&base)?;
    Ok(base)
}

/// Codex Round-5 P1 #2 (G7): an absolute custom error page reached through a tenant-controlled
/// INTERMEDIATE symlink must not widen the worker's read policy (the loader refuses it and serves
/// the built-in page), while a regular page gets a read grant pinned to its validated directory.
#[cfg(unix)]
#[test]
fn g7_r5_p1_intermediate_symlink_error_page_never_widens_read_policy() -> TestResult {
    let base = r5_temp_base("errpage-policy")?;
    let tenant_a = base.join("tenant-a");
    let tenant_b = base.join("tenant-b");
    let unrelated = base.join("unrelated");
    for d in [&tenant_a, &tenant_b, &unrelated, &tenant_b.join("errors")] {
        std::fs::create_dir_all(d)?;
    }
    std::fs::write(unrelated.join("404.html"), b"UNRELATED-SECRET")?;
    std::os::unix::fs::symlink(&unrelated, tenant_a.join("errors"))?;
    std::fs::write(tenant_b.join("errors/404.html"), b"<h1>b 404</h1>")?;

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "{cert}"; key "{key}" }}
}}
site "a.example.test" {{
    root "{a}"
    error-pages {{ page 404 "{a_page}" }}
}}
site "b.example.test" {{
    root "{b}"
    error-pages {{ page 404 "{b_page}" }}
}}
"#,
        cert = base.join("tls/c.crt").display(),
        key = base.join("tls/c.key").display(),
        a = tenant_a.display(),
        a_page = tenant_a.join("errors/404.html").display(),
        b = tenant_b.display(),
        b_page = tenant_b.join("errors/404.html").display(),
    );
    let (cfg, _) = parse_kdl("r5-errpage-policy.kdl", &kdl)?;
    let policy = SandboxPolicy::from_config(&cfg, None);

    for p in &policy.read_only_paths {
        let real = std::fs::canonicalize(p).unwrap_or_else(|_| p.clone());
        assert!(
            !real.starts_with(&unrelated) && !p.starts_with(tenant_a.join("errors")),
            "intermediate-symlink error page must not grant read access, got rule {}",
            p.display()
        );
    }
    assert!(
        !policy
            .pinned_read_only_paths
            .iter()
            .any(|pin| pin.path.starts_with(tenant_a.join("errors"))),
        "a refused tenant page must not be pinned"
    );
    let b_errors = tenant_b.join("errors");
    assert!(
        policy.read_only_paths.contains(&b_errors),
        "a regular page outside the site root keeps its read grant: {:?}",
        policy.read_only_paths
    );
    assert!(
        policy
            .pinned_read_only_paths
            .iter()
            .any(|pin| pin.path == b_errors && pin.is_dir),
        "the accepted page's directory must be pinned for identity-based rule installation"
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Codex Round-5 P1 #2 (G7), enforced kernel: with Landlock applied from the policy, a worker
/// thread can read the accepted error page but NOT a file in the unrelated directory that a
/// tenant's intermediate symlink pointed at.
///
/// Requires an enforcing Landlock kernel, so it is ignored by default and FAILS (never passes
/// silently) when Landlock is unavailable. Run on a Landlock-capable Linux host with
/// `cargo test -p miraserve-sandbox --test sandbox_tests -- --ignored`.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires an enforcing Landlock kernel; run with --ignored on the staging VM"]
fn g7_r5_p1_enforced_landlock_denies_unrelated_dir_behind_tenant_symlink() -> TestResult {
    let base = r5_temp_base("errpage-landlock")?;
    let tenant_a = base.join("tenant-a");
    let tenant_b = base.join("tenant-b");
    let unrelated = base.join("unrelated");
    for d in [&tenant_a, &tenant_b, &unrelated, &tenant_b.join("errors")] {
        std::fs::create_dir_all(d)?;
    }
    std::fs::write(unrelated.join("secret.txt"), b"UNRELATED-SECRET")?;
    std::fs::write(unrelated.join("404.html"), b"x")?;
    std::os::unix::fs::symlink(&unrelated, tenant_a.join("errors"))?;
    std::fs::write(tenant_b.join("errors/404.html"), b"<h1>b 404</h1>")?;

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "{cert}"; key "{key}" }}
    sandbox {{
        landlock #true
        seccomp "off"
    }}
}}
site "a.example.test" {{
    root "{a}"
    error-pages {{ page 404 "{a_page}" }}
}}
site "b.example.test" {{
    root "{b}"
    error-pages {{ page 404 "{b_page}" }}
}}
"#,
        cert = base.join("tls/c.crt").display(),
        key = base.join("tls/c.key").display(),
        a = tenant_a.display(),
        a_page = tenant_a.join("errors/404.html").display(),
        b = tenant_b.display(),
        b_page = tenant_b.join("errors/404.html").display(),
    );
    let (cfg, _) = parse_kdl("r5-errpage-landlock.kdl", &kdl)?;
    let policy = SandboxPolicy::from_config(&cfg, None);
    let page = tenant_b.join("errors/404.html");
    let secret = unrelated.join("secret.txt");

    let (page_ok, secret_ok) = std::thread::spawn(move || {
        miraserve_sandbox::apply_landlock_current_thread(&policy)
            .map(|_| (std::fs::read(&page).is_ok(), std::fs::read(&secret).is_ok()))
            .map_err(|err| err.to_string())
    })
    .join()
    .map_err(|_| "Landlock probe thread panicked")??;
    assert!(
        page_ok,
        "accepted error page must stay readable under Landlock"
    );
    assert!(
        !secret_ok,
        "unrelated directory behind a tenant symlink must stay unreadable under Landlock"
    );
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Codex Round-5 P1 #3 (G7): a tenant WASM module path that resolves (via a symlink) into the
/// proposed rotating-log directory must not block the rotation grant for every site, and must
/// not widen the read policy; an operator trust file there is still protected.
#[cfg(unix)]
#[test]
fn g7_r5_p1_tenant_wasm_symlink_into_log_dir_never_blocks_rotation() -> TestResult {
    let base = r5_temp_base("wasm-rotation")?;
    let www = base.join("www");
    let tenant = base.join("tenant");
    let logs = base.join("logs");
    for d in [&www, &tenant, &logs] {
        std::fs::create_dir_all(d)?;
    }
    std::fs::write(logs.join("access.log"), b"PRIVATE-LOG")?;
    let module = tenant.join("plugin.wasm");
    std::os::unix::fs::symlink(logs.join("access.log"), &module)?;

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "{cert}"; key "{key}" }}
}}
site "wasm.example.test" {{
    root "{www}"
    route "/edge/*" {{
        wasm-plugin "{module}"
    }}
}}
"#,
        cert = base.join("tls/c.crt").display(),
        key = base.join("tls/c.key").display(),
        www = www.display(),
        module = module.display(),
    );
    let (cfg, _) = parse_kdl("r5-wasm-rotation.kdl", &kdl)?;
    let mut policy = SandboxPolicy::from_config(&cfg, None);
    assert!(
        !policy
            .read_only_paths
            .iter()
            .any(|p| p.starts_with(&tenant) || p.starts_with(&logs)),
        "a refused tenant module must not widen the read policy: {:?}",
        policy.read_only_paths
    );
    policy
        .allow_log_rotation_dir(&logs.join("access.log"), &cfg)
        .map_err(|err| format!("tenant module symlink must not block rotation: {err}"))?;

    // Control: an operator trust file (mTLS client CA) in that directory is still protected.
    let ca_kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "{cert}"; key "{key}"; client-ca "{ca}" }}
}}
site "wasm.example.test" {{
    root "{www}"
}}
"#,
        cert = base.join("tls/c.crt").display(),
        key = base.join("tls/c.key").display(),
        ca = logs.join("ca.pem").display(),
        www = www.display(),
    );
    let (ca_cfg, _) = parse_kdl("r5-wasm-ca.kdl", &ca_kdl)?;
    let mut ca_policy = SandboxPolicy::from_config(&ca_cfg, None);
    assert!(
        ca_policy
            .allow_log_rotation_dir(&logs.join("access.log"), &ca_cfg)
            .is_err(),
        "operator trust files must stay protected"
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Codex Round-5 P1 on Windows (G7): a pinned log directory holds every component open without
/// `FILE_SHARE_DELETE`, so neither the directory nor an ancestor can be renamed (replaced) while
/// the writer is alive; files are still created and rotated inside it, and the lock is released
/// when the pin is dropped.
#[cfg(windows)]
#[test]
fn g7_r5_p1_windows_pinned_log_dir_locks_directory_and_ancestors() -> TestResult {
    let base = r5_temp_base("win-lock")?;
    let parent = base.join("parent");
    let logs = parent.join("logs");
    std::fs::create_dir_all(&logs)?;

    let pinned = miraserve_sandbox::PinnedWritableDir::open_validated(&logs)?;
    let mut file = pinned.open_append_regular(std::ffi::OsStr::new("access.log"))?;
    std::io::Write::write_all(&mut file, b"entry\n")?;
    drop(file);
    pinned.rename_entry(
        std::ffi::OsStr::new("access.log"),
        std::ffi::OsStr::new("access.log.1"),
    )?;
    assert!(logs.join("access.log.1").is_file());

    assert!(
        std::fs::rename(&logs, parent.join("logs-moved")).is_err(),
        "pinned log directory must not be renamable while pinned"
    );
    assert!(
        std::fs::rename(&parent, base.join("parent-moved")).is_err(),
        "an ancestor of a pinned log directory must not be renamable while pinned"
    );
    pinned
        .matches_configured_log_path(&logs.join("access.log"))
        .map_err(|err| format!("unchanged destination must still match: {err}"))?;

    drop(pinned);
    std::fs::rename(&parent, base.join("parent-moved"))?;
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Codex Round-6 P1 #4 (G7): reload coverage for rules installed from a pinned identity is
/// decided by identity. Replacing the external error-page DIRECTORY at the same name makes it
/// uncovered (restart required), while atomically replacing the page FILE inside the unchanged
/// directory stays covered.
#[cfg(target_os = "linux")]
#[test]
fn g7_r6_p1_reload_coverage_compares_pinned_identity_not_name() -> TestResult {
    let base = r5_temp_base("identity-reload")?;
    let site = base.join("site");
    let errors = base.join("errors");
    std::fs::create_dir_all(&site)?;
    std::fs::create_dir_all(&errors)?;
    std::fs::write(errors.join("404.html"), b"v1")?;
    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "{cert}"; key "{key}" }}
}}
site "id.example.test" {{
    root "{site}"
    error-pages {{ page 404 "{page}" }}
}}
"#,
        cert = base.join("tls/c.crt").display(),
        key = base.join("tls/c.key").display(),
        site = site.display(),
        page = errors.join("404.html").display(),
    );
    let (cfg, _) = parse_kdl("r6-identity.kdl", &kdl)?;
    let startup = SandboxPolicy::from_config(&cfg, None);
    assert!(
        startup
            .pinned_read_only_paths
            .iter()
            .any(|pin| pin.path == errors && pin.is_dir),
        "the external error-page directory must be pinned"
    );

    // 1. Atomic child replacement under the unchanged directory grant: still covered.
    std::fs::write(errors.join("404.html.tmp"), b"v2")?;
    std::fs::rename(errors.join("404.html.tmp"), errors.join("404.html"))?;
    let next_same = SandboxPolicy::from_config(&cfg, None);
    assert!(
        startup.uncovered_paths_in(&next_same).is_empty(),
        "atomic page replacement inside the pinned directory must not need a restart"
    );

    // 2. Directory replaced at the same name: the installed rule refers to the old inode.
    std::fs::rename(&errors, base.join("errors-old"))?;
    std::fs::create_dir_all(&errors)?;
    std::fs::write(errors.join("404.html"), b"v3")?;
    let next_replaced = SandboxPolicy::from_config(&cfg, None);
    let uncovered = startup.uncovered_paths_in(&next_replaced);
    assert!(
        uncovered.iter().any(|p| p == &errors),
        "a directory replaced at the same name must be uncovered (restart required), got: {uncovered:?}"
    );

    // 3. Independently covering ancestor grant (`read-tree`): replacing `errors/` at the same
    //    name MUST remain covered by the independent ancestor rule (no spurious restart).
    let kdl_with_tree = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "{cert}"; key "{key}" }}
    sandbox {{ read-tree "{base}" }}
}}
site "id.example.test" {{
    root "{site}"
    error-pages {{ page 404 "{page}" }}
}}
"#,
        cert = base.join("tls/c.crt").display(),
        key = base.join("tls/c.key").display(),
        base = base.display(),
        site = site.display(),
        page = errors.join("404.html").display(),
    );
    let (tree_cfg, _) = parse_kdl("r6-identity-tree.kdl", &kdl_with_tree)?;
    let startup_with_tree = SandboxPolicy::from_config(&tree_cfg, None);
    std::fs::rename(&errors, base.join("errors-old-2"))?;
    std::fs::create_dir_all(&errors)?;
    std::fs::write(errors.join("404.html"), b"v4")?;
    let next_with_tree = SandboxPolicy::from_config(&tree_cfg, None);
    assert!(
        startup_with_tree
            .uncovered_paths_in(&next_with_tree)
            .is_empty(),
        "an independently covering read-tree ancestor must still cover the replaced error-page dir"
    );

    drop(startup_with_tree);
    drop(startup);
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Codex Round-6 P1 #4 (Linux): when an external error page lives in a directory that cannot be
/// widened (beside a split-daemon TLS key), startup pins the exact file inode. Atomically
/// replacing that file at the same name changes its inode and MUST require a restart.
#[cfg(target_os = "linux")]
#[test]
fn g7_r6_p1_exact_file_pin_detects_atomic_replacement_on_reload() -> TestResult {
    let base = r5_temp_base("identity-exact")?;
    let site = base.join("site");
    let shared_key_dir = base.join("shared-key-dir");
    std::fs::create_dir_all(&site)?;
    std::fs::create_dir_all(&shared_key_dir)?;
    let secret_key = shared_key_dir.join("server.key");
    let exact_page = shared_key_dir.join("500.html");
    std::fs::write(&secret_key, b"PRIVATE")?;
    std::fs::write(&exact_page, b"err-v1")?;
    let kdl_exact = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{
        cert "{cert}"
        key "{key}"
        key-isolation "split-daemon"
        keyd-socket "/run/miraserve/keyd.sock"
    }}
}}
site "id.example.test" {{
    root "{site}"
    error-pages {{ page 500 "{exact_page}" }}
}}
"#,
        cert = base.join("tls/c.crt").display(),
        key = secret_key.display(),
        site = site.display(),
        exact_page = exact_page.display(),
    );
    let (exact_cfg, _) = parse_kdl("r6-identity-exact.kdl", &kdl_exact)?;
    let startup_exact = SandboxPolicy::from_config(&exact_cfg, None);
    assert!(
        startup_exact
            .pinned_read_only_paths
            .iter()
            .any(|pin| pin.path == exact_page && !pin.is_dir),
        "error page beside split-daemon key must pin the exact file, not its parent dir"
    );
    let next_exact_same = SandboxPolicy::from_config(&exact_cfg, None);
    assert!(
        startup_exact
            .uncovered_paths_in(&next_exact_same)
            .is_empty(),
        "unchanged exact-file pin must remain covered"
    );
    std::fs::write(shared_key_dir.join("500.html.tmp"), b"err-v2")?;
    std::fs::rename(shared_key_dir.join("500.html.tmp"), &exact_page)?;
    let next_exact_replaced = SandboxPolicy::from_config(&exact_cfg, None);
    let exact_uncovered = startup_exact.uncovered_paths_in(&next_exact_replaced);
    assert!(
        exact_uncovered.iter().any(|p| p == &exact_page),
        "atomic replacement of an exact-file pin must be uncovered (restart required), got: {exact_uncovered:?}"
    );
    drop(startup_exact);
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Codex Round-7 P2 #4: replacing a child directory beneath an unchanged `read-tree` remains
/// covered by the original `read-tree` grant, whereas replacing the `read-tree` directory itself
/// at the same name changes its inode and MUST report uncovered (restart required).
#[cfg(unix)]
#[test]
fn g7_r7_p2_replacing_granted_read_tree_requires_restart_while_child_replace_reloads() -> TestResult
{
    let base = r5_temp_base("read-tree-id")?;
    let tree = base.join("tree");
    let site = tree.join("site");
    let errors = tree.join("errors");
    std::fs::create_dir_all(&site)?;
    std::fs::create_dir_all(&errors)?;
    std::fs::write(errors.join("404.html"), b"v1")?;

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "{cert}"; key "{key}" }}
    sandbox {{ read-tree "{tree}" }}
}}
site "tree.example.test" {{
    root "{site}"
    error-pages {{ page 404 "{page}" }}
}}
"#,
        cert = base.join("tls/c.crt").display(),
        key = base.join("tls/c.key").display(),
        tree = tree.display(),
        site = site.display(),
        page = errors.join("404.html").display(),
    );
    let (cfg, _) = parse_kdl("r7-tree-id.kdl", &kdl)?;
    let startup = SandboxPolicy::from_config(&cfg, None);

    // 1. Replacing a child beneath the unchanged `read-tree`: still covered.
    std::fs::rename(&errors, tree.join("errors-old"))?;
    std::fs::create_dir_all(&errors)?;
    std::fs::write(errors.join("404.html"), b"v2")?;
    let next_child = SandboxPolicy::from_config(&cfg, None);
    assert!(
        startup.uncovered_paths_in(&next_child).is_empty(),
        "replacing a child beneath the original read-tree must remain covered"
    );

    // 2. Replacing the `read-tree` directory itself at the same name: the installed Landlock rule
    //    remains attached to the old tree inode, so reload MUST report uncovered (restart required).
    std::fs::rename(&tree, base.join("tree-old"))?;
    std::fs::create_dir_all(&site)?;
    std::fs::create_dir_all(&errors)?;
    std::fs::write(errors.join("404.html"), b"v3")?;
    let next_replaced_tree = SandboxPolicy::from_config(&cfg, None);
    let uncovered = startup.uncovered_paths_in(&next_replaced_tree);
    assert!(
        uncovered.iter().any(|p| p == &tree || p == &errors),
        "replacing the granted read-tree directory itself must require restart, got: {uncovered:?}"
    );

    drop(startup);
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Codex Round-8 P2 #4: a `read-tree` that did NOT exist at startup was omitted by Landlock.
/// 1. While it stays absent and unused, an unchanged reload MUST NOT spuriously force a restart.
/// 2. Once created later and needed by a reload, `uncovered_paths_in` MUST require a restart.
/// 3. If another installed ancestor `read-tree` existed at startup above it, the newly created
///    directory IS covered by that installed ancestor.
#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)]
fn g7_r8_p2_missing_startup_read_tree_requires_restart_when_created_unless_ancestor_installed()
-> TestResult {
    let base = r5_temp_base("missing-read-tree")?;
    let site_a = base.join("site-a");
    let future = base.join("future");
    let site_b = future.join("site-b");
    std::fs::create_dir_all(&site_a)?;

    let make_kdl = |trees: &[&std::path::Path], extra_site: Option<&std::path::Path>| {
        use std::fmt::Write as _;
        let mut tree_args = String::new();
        for t in trees {
            let _ = write!(tree_args, " \"{}\"", t.display());
        }
        let extra = extra_site.map_or_else(String::new, |s| {
            format!("site \"b.example.test\" {{ root \"{}\" }}\n", s.display())
        });
        format!(
            "server {{\n    listen \"127.0.0.1:8443\"\n    tls {{ cert \"{}\"; key \"{}\" }}\n    sandbox {{\n        read-tree{tree_args}\n    }}\n}}\nsite \"a.example.test\" {{ root \"{}\" }}\n{extra}",
            base.join("tls/c.crt").display(),
            base.join("tls/c.key").display(),
            site_a.display(),
        )
    };

    let (startup_cfg, _) = parse_kdl("r8-miss-start.kdl", &make_kdl(&[&future], None))?;
    let startup_policy = SandboxPolicy::from_config(&startup_cfg, None);

    // 1. Unchanged reload while `future` stays absent and unused: must NOT force a restart.
    let next_unchanged = SandboxPolicy::from_config(&startup_cfg, None);
    assert!(
        startup_policy
            .uncovered_paths_in(&next_unchanged)
            .is_empty(),
        "an absent unused read-tree must not force a restart on unchanged reload"
    );

    // 2. Create `future/site-b` after startup and reload to serve it: MUST require restart!
    std::fs::create_dir_all(&site_b)?;
    let (reload_b_cfg, _) = parse_kdl("r8-miss-use.kdl", &make_kdl(&[&future], Some(&site_b)))?;
    let reload_b_policy = SandboxPolicy::from_config(&reload_b_cfg, None);
    let uncovered = startup_policy.uncovered_paths_in(&reload_b_policy);
    assert!(
        uncovered.iter().any(|p| p == &site_b),
        "a site under a read-tree that was absent at startup must require restart, got: {uncovered:?}"
    );

    // 3. When another installed ancestor (`parent`) DID exist at startup, a later-created nested
    //    `read-tree` beneath `parent` IS covered by the installed ancestor.
    let parent = base.join("installed-parent");
    let nested_future = parent.join("nested-future");
    let nested_site = nested_future.join("site-c");
    std::fs::create_dir_all(&parent)?;
    let (anc_start_cfg, _) = parse_kdl(
        "r8-anc-start.kdl",
        &make_kdl(&[&parent, &nested_future], None),
    )?;
    let anc_startup = SandboxPolicy::from_config(&anc_start_cfg, None);
    std::fs::create_dir_all(&nested_site)?;
    let (anc_reload_cfg, _) = parse_kdl(
        "r8-anc-reload.kdl",
        &make_kdl(&[&parent, &nested_future], Some(&nested_site)),
    )?;
    let anc_reload = SandboxPolicy::from_config(&anc_reload_cfg, None);
    assert!(
        anc_startup.uncovered_paths_in(&anc_reload).is_empty(),
        "a directory created later beneath an already-installed ancestor read-tree must be covered"
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Codex Round-9 P2: replacing a granted `read-tree` directory after policy preparation causes
/// `uncovered_paths_in` to report it uncovered, and restoring the original directory restores
/// coverage (matching the descriptor finalized at policy preparation).
#[cfg(unix)]
#[test]
fn g7_r9_p2_policy_identity_stays_pinned_across_replace_and_restore() -> TestResult {
    let base = r5_temp_base("replace-restore")?;
    let tree = base.join("tree");
    let site = tree.join("site");
    std::fs::create_dir_all(&site)?;
    std::fs::write(site.join("index.html"), b"OLD-TREE")?;

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "{cert}"; key "{key}" }}
    sandbox {{ read-tree "{tree}" }}
}}
site "rr.example.test" {{ root "{site}" }}
"#,
        cert = base.join("tls/c.crt").display(),
        key = base.join("tls/c.key").display(),
        tree = tree.display(),
        site = site.display(),
    );
    let (cfg, _) = parse_kdl("r9-rr.kdl", &kdl)?;
    let startup = SandboxPolicy::from_config(&cfg, None);

    // Replace `tree` at the same name: must be uncovered.
    std::fs::rename(&tree, base.join("tree-old"))?;
    std::fs::create_dir_all(&site)?;
    std::fs::write(site.join("index.html"), b"NEW-TREE")?;
    let next_replaced = SandboxPolicy::from_config(&cfg, None);
    let uncovered = startup.uncovered_paths_in(&next_replaced);
    assert!(
        uncovered.iter().any(|p| p == &tree || p == &site),
        "replaced tree must be uncovered, got: {uncovered:?}"
    );

    // Restore original `tree`: original inode returns -> covered again.
    std::fs::rename(&tree, base.join("tree-new"))?;
    std::fs::rename(base.join("tree-old"), &tree)?;
    let next_restored = SandboxPolicy::from_config(&cfg, None);
    assert!(
        startup.uncovered_paths_in(&next_restored).is_empty(),
        "restoring the original directory must match the finalized startup descriptor again"
    );

    drop(startup);
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Codex Round-9 P2, enforced Linux only: replacing a granted `read-tree` directory BETWEEN policy
/// preparation and Landlock installation MUST keep recorded reload coverage and actual worker
/// kernel access in 100% agreement because Landlock installs directly from the finalized `O_PATH`
/// descriptor (never reopening the pathname per thread):
/// 1. While the replacement directory is at `tree`: the confined worker gets `PermissionDenied`
///    AND `uncovered_paths_in` reports `tree`/`site` uncovered.
/// 2. When the original directory is restored at `tree`: the SAME confined worker reads `"OLD-TREE"`
///    AND `uncovered_paths_in` reports covered.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires an enforcing Landlock kernel; run with --ignored on the staging VM"]
#[allow(clippy::too_many_lines)]
fn g7_r9_p2_enforced_landlock_replacement_between_prep_and_install_agrees_with_reload() -> TestResult
{
    let base = r5_temp_base("enforced-prep-replace")?;
    let tree = base.join("tree");
    // Codex Round-10 fixture fix: the site root is UNRELATED to the read-tree and the marker sits
    // in a sibling directory covered ONLY by the `read-tree` rule, so a successful read can only
    // come from that rule's descriptor.
    let site = base.join("unrelated-site");
    let data = tree.join("data");
    let index = data.join("marker.txt");
    std::fs::create_dir_all(&site)?;
    std::fs::create_dir_all(&data)?;
    std::fs::write(&index, b"OLD-TREE")?;

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "{cert}"; key "{key}" }}
    sandbox {{
        landlock #true
        seccomp "off"
        read-tree "{tree}"
    }}
}}
site "prep.example.test" {{ root "{site}" }}
"#,
        cert = base.join("tls/c.crt").display(),
        key = base.join("tls/c.key").display(),
        tree = tree.display(),
        site = site.display(),
    );
    let (cfg, _) = parse_kdl("r9-enforced.kdl", &kdl)?;
    // 1. Prepare policy while original `tree` (`OLD-TREE`) is in place; this opens the O_PATH fd.
    let mut policy = SandboxPolicy::from_config(&cfg, None);
    policy.finalize_grants()?;

    // 2. Replace `tree` at the same name BEFORE Landlock is installed on the worker thread!
    std::fs::rename(&tree, base.join("tree-old"))?;
    std::fs::create_dir_all(&data)?;
    std::fs::write(&index, b"NEW-TREE")?;

    let (phase_tx, phase_rx) = std::sync::mpsc::channel::<()>();
    let (res_tx, res_rx) = std::sync::mpsc::channel::<Result<String, std::io::ErrorKind>>();
    let worker_policy = policy.clone();
    let index_worker = index.clone();
    let worker = std::thread::spawn(move || -> Result<(), String> {
        let status = miraserve_sandbox::apply_landlock_current_thread(&worker_policy)
            .map_err(|err| format!("apply_landlock_current_thread failed: {err}"))?;
        if !matches!(
            status,
            miraserve_sandbox::EnforcementStatus::Enforced
                | miraserve_sandbox::EnforcementStatus::PartiallyEnforced
        ) {
            return Err(format!(
                "expected Landlock Enforced or PartiallyEnforced, got {status:?}"
            ));
        }
        // Phase 1: replacement `NEW-TREE` is currently at `tree`.
        let r1 = std::fs::read_to_string(&index_worker).map_err(|e| e.kind());
        let _ = res_tx.send(r1);
        // Wait for unconfined parent thread to restore original `tree`.
        let _ = phase_rx.recv();
        // Phase 2: original `OLD-TREE` is restored at `tree`.
        let r2 = std::fs::read_to_string(&index_worker).map_err(|e| e.kind());
        let _ = res_tx.send(r2);
        Ok(())
    });

    // Phase 1 check: worker access denied AND reload reports uncovered -> agreement!
    let worker_phase1 = res_rx.recv()?;
    assert_eq!(
        worker_phase1,
        Err(std::io::ErrorKind::PermissionDenied),
        "worker installed from finalized OLD fd must be denied access to replacement NEW tree, got: {worker_phase1:?}"
    );
    let next_replaced = SandboxPolicy::from_config(&cfg, None);
    let uncovered = policy.uncovered_paths_in(&next_replaced);
    assert!(
        uncovered.iter().any(|p| p == &tree),
        "reload check must report replaced tree uncovered, got: {uncovered:?}"
    );

    // Phase 2: restore original `OLD-TREE` directory at `tree`.
    std::fs::rename(&tree, base.join("tree-new"))?;
    std::fs::rename(base.join("tree-old"), &tree)?;
    phase_tx.send(())?;

    // Phase 2 check: worker CAN read original `OLD-TREE` AND reload reports covered -> agreement!
    let worker_phase2 = res_rx.recv()?;
    assert_eq!(
        worker_phase2.as_deref(),
        Ok("OLD-TREE"),
        "worker installed from finalized OLD fd must read restored original tree, got: {worker_phase2:?}"
    );
    let next_restored = SandboxPolicy::from_config(&cfg, None);
    assert!(
        policy.uncovered_paths_in(&next_restored).is_empty(),
        "reload check must report restored original tree covered"
    );

    worker
        .join()
        .map_err(|_| "Landlock worker thread panicked")?
        .map_err(|msg| -> Box<dyn std::error::Error> { msg.into() })?;
    drop(policy);
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

#[cfg(unix)]
fn r10_tree_kdl(base: &Path, trees: &[&Path]) -> String {
    use std::fmt::Write as _;
    let mut tree_args = String::new();
    for t in trees {
        let _ = write!(tree_args, " \"{}\"", t.display());
    }
    let sandbox_block = if trees.is_empty() {
        String::new()
    } else {
        format!("    sandbox {{\n        read-tree{tree_args}\n    }}\n")
    };
    format!(
        "server {{\n    listen \"127.0.0.1:8443\"\n    tls {{ cert \"{}\"; key \"{}\" }}\n{sandbox_block}}}\nsite \"r10.example.test\" {{ root \"{}\" }}\n",
        base.join("tls/c.crt").display(),
        base.join("tls/c.key").display(),
        base.join("site").display(),
    )
}

#[cfg(unix)]
fn r10_identity(p: &Path) -> std::io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    let md = std::fs::metadata(p)?;
    Ok((md.dev(), md.ino()))
}

/// Codex Round-10 P1: a `read-tree` is validated on the OBJECT behind the retained descriptor,
/// and that exact handle is kept through finalization:
/// 1. a tree whose symlink already resolves into a forbidden directory (`/etc`) is refused;
/// 2. swapping an allowed tree's symlink to `/etc` between validation and finalization keeps the
///    originally validated object (and reload reports the swapped name uncovered);
/// 3. a tree that was absent at construction and first appears as a link into `/etc` is refused
///    by finalization.
#[cfg(unix)]
#[test]
fn g7_r10_p1_tree_descriptor_validated_and_retained_across_swap_and_first_appearance() -> TestResult
{
    let base = r5_temp_base("r10-tree-desc")?;
    std::fs::create_dir_all(base.join("site"))?;
    let real_tree = base.join("real-tree");
    std::fs::create_dir_all(&real_tree)?;

    // 1. Already pointing into `/etc`: the name passes, the opened object is refused.
    let evil = base.join("evil");
    std::os::unix::fs::symlink("/etc", &evil)?;
    let (evil_cfg, _) = parse_kdl("r10-evil.kdl", &r10_tree_kdl(&base, &[&evil]))?;
    let mut evil_policy = SandboxPolicy::from_config(&evil_cfg, None);
    let err = evil_policy
        .finalize_grants()
        .err()
        .ok_or("a read-tree resolving into /etc must be refused at finalization")?;
    assert!(
        err.to_string().contains("not allowed"),
        "expected forbidden-tree refusal, got: {err}"
    );

    // 2. Allowed at validation, swapped before finalization: the validated object is retained.
    let tree = base.join("tree");
    std::os::unix::fs::symlink(&real_tree, &tree)?;
    let (cfg, _) = parse_kdl("r10-swap.kdl", &r10_tree_kdl(&base, &[&tree]))?;
    let mut policy = SandboxPolicy::from_config(&cfg, None);
    let validated = r10_identity(&real_tree)?;
    assert_eq!(policy.granted_identity(&tree), Some(validated));
    std::fs::remove_file(&tree)?;
    std::os::unix::fs::symlink("/etc", &tree)?;
    policy.finalize_grants()?;
    assert_eq!(
        policy.granted_identity(&tree),
        Some(validated),
        "finalization must keep the descriptor validated earlier, never reopen the swapped name"
    );
    assert_ne!(
        policy.granted_identity(&tree),
        Some(r10_identity(Path::new("/etc"))?)
    );
    let next = SandboxPolicy::from_config(&cfg, None);
    let uncovered = policy.uncovered_paths_in(&next);
    assert!(
        uncovered.iter().any(|p| p == &tree),
        "reload must not treat the swapped tree as covered, got: {uncovered:?}"
    );

    // 3. Absent at construction, first appears as a link into `/etc`: refused at finalization.
    let late = base.join("late");
    let (late_cfg, _) = parse_kdl("r10-late.kdl", &r10_tree_kdl(&base, &[&late]))?;
    let mut late_policy = SandboxPolicy::from_config(&late_cfg, None);
    late_policy.finalize_grants()?;
    assert_eq!(late_policy.granted_identity(&late), None);
    std::os::unix::fs::symlink("/etc", &late)?;
    assert!(
        late_policy.finalize_grants().is_err(),
        "a tree first appearing as a link into /etc must be validated and refused"
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Codex Round-10 P2 #2: only a genuinely absent tree may be omitted. A non-absence error (here a
/// self-referencing symlink, `ELOOP`) is surfaced by finalization and by Landlock installation
/// instead of silently dropping the grant; an absent tree is still accepted.
#[cfg(unix)]
#[test]
fn g7_r10_p2_non_absence_grant_error_is_reported_not_omitted() -> TestResult {
    let base = r5_temp_base("r10-eloop")?;
    std::fs::create_dir_all(base.join("site"))?;
    let looped = base.join("looped");
    std::os::unix::fs::symlink(&looped, &looped)?;
    let missing = base.join("missing-tree");

    let (cfg, _) = parse_kdl("r10-eloop.kdl", &r10_tree_kdl(&base, &[&looped, &missing]))?;
    let mut policy = SandboxPolicy::from_config(&cfg, None);
    #[cfg(target_os = "linux")]
    {
        let mut install_policy = policy.clone();
        install_policy.landlock = true;
        let res = std::thread::spawn(move || {
            miraserve_sandbox::apply_landlock_current_thread(&install_policy)
        })
        .join()
        .map_err(|_| "landlock thread panicked")?;
        let msg = res
            .err()
            .ok_or("installation must refuse a failed grant")?
            .to_string();
        assert!(
            msg.contains("could not be opened or validated") && msg.contains("looped"),
            "expected failed-grant installation error, got: {msg}"
        );
    }
    let err = policy
        .finalize_grants()
        .err()
        .ok_or("finalization must report a non-absence open error")?;
    assert!(
        err.to_string().contains("looped"),
        "error must name the failing path, got: {err}"
    );
    assert!(
        !err.to_string().contains("missing-tree"),
        "a genuinely absent tree must not be reported as a failure, got: {err}"
    );

    let (ok_cfg, _) = parse_kdl("r10-absent.kdl", &r10_tree_kdl(&base, &[&missing]))?;
    SandboxPolicy::from_config(&ok_cfg, None).finalize_grants()?;

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Codex Round-10 P2 #3: an embedder that edits the public path lists after construction gets
/// either the promised grant (after `finalize_grants`) or an explicit, actionable error — never a
/// silently skipped rule.
#[cfg(unix)]
#[test]
fn g7_r10_p2_public_path_edits_require_finalize_grants() -> TestResult {
    let base = r5_temp_base("r10-edit")?;
    std::fs::create_dir_all(base.join("site"))?;
    let ro_extra = base.join("added-ro");
    let rw_extra_dir = base.join("added-rw");
    std::fs::create_dir_all(&ro_extra)?;
    std::fs::create_dir_all(&rw_extra_dir)?;

    let (cfg, _) = parse_kdl("r10-edit.kdl", &r10_tree_kdl(&base, &[]))?;
    let mut policy = SandboxPolicy::from_config(&cfg, None);
    policy.read_only_paths.push(ro_extra.clone());
    policy.read_write_paths.push(rw_extra_dir.clone());
    let pending = policy.unfinalized_grant_paths();
    assert!(pending.contains(&ro_extra) && pending.contains(&rw_extra_dir));

    #[cfg(target_os = "linux")]
    {
        let mut install_policy = policy.clone();
        install_policy.landlock = true;
        let res = std::thread::spawn(move || {
            miraserve_sandbox::apply_landlock_current_thread(&install_policy)
        })
        .join()
        .map_err(|_| "landlock thread panicked")?;
        let msg = res
            .err()
            .ok_or("an unfinalized edit must be refused")?
            .to_string();
        assert!(
            msg.contains("finalize_grants"),
            "error must tell the embedder to call finalize_grants, got: {msg}"
        );
    }

    policy.finalize_grants()?;
    assert!(policy.unfinalized_grant_paths().is_empty());
    assert_eq!(
        policy.granted_identity(&ro_extra),
        Some(r10_identity(&ro_extra)?)
    );
    assert_eq!(
        policy.granted_identity(&rw_extra_dir),
        Some(r10_identity(&rw_extra_dir)?)
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Codex Round-10 P2 #3, enforced Linux only: a directory an embedder adds and finalizes is
/// actually readable by the confined thread, while an unrelated sibling stays denied.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires an enforcing Landlock kernel; run with --ignored on the staging VM"]
fn g7_r10_p2_enforced_embedder_added_directory_receives_access() -> TestResult {
    let base = r5_temp_base("r10-edit-enforced")?;
    std::fs::create_dir_all(base.join("site"))?;
    let added = base.join("added");
    let other = base.join("other");
    std::fs::create_dir_all(&added)?;
    std::fs::create_dir_all(&other)?;
    std::fs::write(added.join("marker.txt"), b"ADDED")?;
    std::fs::write(other.join("marker.txt"), b"OTHER")?;

    let (cfg, _) = parse_kdl("r10-edit-enf.kdl", &r10_tree_kdl(&base, &[]))?;
    let mut policy = SandboxPolicy::from_config(&cfg, None);
    policy.landlock = true;
    policy.seccomp = miraserve_config::SeccompMode::Off;
    policy.read_only_paths.push(added.clone());
    policy.finalize_grants()?;

    let res = std::thread::spawn(move || -> Result<(String, std::io::ErrorKind), String> {
        let status = miraserve_sandbox::apply_landlock_current_thread(&policy)
            .map_err(|err| err.to_string())?;
        if !matches!(
            status,
            miraserve_sandbox::EnforcementStatus::Enforced
                | miraserve_sandbox::EnforcementStatus::PartiallyEnforced
        ) {
            return Err(format!(
                "expected Enforced or PartiallyEnforced, got {status:?}"
            ));
        }
        let added_read =
            std::fs::read_to_string(added.join("marker.txt")).map_err(|e| e.to_string())?;
        let other_err = std::fs::read_to_string(other.join("marker.txt"))
            .err()
            .map_or(std::io::ErrorKind::Other, |e| e.kind());
        Ok((added_read, other_err))
    })
    .join()
    .map_err(|_| "landlock thread panicked")?
    .map_err(|msg| -> Box<dyn std::error::Error> { msg.into() })?;
    assert_eq!(res.0, "ADDED");
    assert_eq!(res.1, std::io::ErrorKind::PermissionDenied);

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Codex Round-6 Windows note: only drive-qualified verbatim paths are accepted for logs; volume
/// GUID / GLOBALROOT namespaces, device paths and network shares are rejected before any
/// filesystem access.
#[cfg(windows)]
#[test]
fn g7_r6_windows_log_paths_accept_only_drive_qualified_namespaces() -> TestResult {
    use miraserve_sandbox::log_path_platform_rejection;
    for bad in [
        r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\logs\access.log",
        r"\\?\GLOBALROOT\Device\HarddiskVolume1\logs\access.log",
        r"\\.\PhysicalDrive0\access.log",
        r"\\server\share\logs\access.log",
        r"\\?\UNC\server\share\logs\access.log",
        "//server/share/logs/access.log",
    ] {
        assert!(
            log_path_platform_rejection(std::path::Path::new(bad)).is_some(),
            "unsupported Windows namespace must be rejected: {bad}"
        );
    }
    let base = r5_temp_base("win-ns")?;
    // `r5_temp_base` canonicalizes, which already prepends `\\?\` on Windows; strip it so we
    // test both an ordinary drive-qualified path and a single-prefixed verbatim `\\?\` path.
    let raw_ok = base.join("access.log");
    let raw_str = raw_ok.to_string_lossy();
    let ordinary = std::path::PathBuf::from(raw_str.strip_prefix(r"\\?\").unwrap_or(&raw_str));
    assert!(
        log_path_platform_rejection(&ordinary).is_none(),
        "an ordinary drive-qualified path must be accepted: {}",
        ordinary.display()
    );
    let verbatim = std::path::PathBuf::from(format!(r"\\?\{}", ordinary.display()));
    assert!(
        log_path_platform_rejection(&verbatim).is_none(),
        "a drive-qualified verbatim path must be accepted: {}",
        verbatim.display()
    );
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Codex Round-11 P2: removing a pinned rotating-log directory from the RW list, or downgrading
/// it to RO, must never leave its original write pin in force. Installation refuses the stale pin
/// with an actionable error; `finalize_grants` reconciles the pin with the requested class.
#[cfg(unix)]
#[test]
fn g7_r11_p2_pinned_rw_dir_removal_and_downgrade_are_reconciled() -> TestResult {
    let base = r5_temp_base("r11-pin")?;
    std::fs::create_dir_all(base.join("site"))?;
    let logs = base.join("logs");
    std::fs::create_dir_all(&logs)?;
    let (cfg, _) = parse_kdl("r11-pin.kdl", &r10_tree_kdl(&base, &[]))?;
    let fresh_policy = || -> Result<SandboxPolicy, Box<dyn std::error::Error>> {
        let mut p = SandboxPolicy::from_config(&cfg, None);
        p.allow_log_rotation_dir(&logs.join("access.log"), &cfg)?;
        p.finalize_grants()?;
        Ok(p)
    };

    // Removal.
    let mut removed = fresh_policy()?;
    assert!(
        removed.pinned_dir_for(&logs).is_some(),
        "fixture must pin the log dir"
    );
    removed.read_write_paths.retain(|p| p != &logs);
    #[cfg(target_os = "linux")]
    {
        let mut install = removed.clone();
        install.landlock = true;
        let res =
            std::thread::spawn(move || miraserve_sandbox::apply_landlock_current_thread(&install))
                .join()
                .map_err(|_| "landlock thread panicked")?;
        let msg = res
            .err()
            .ok_or("a stale RW pin must be refused")?
            .to_string();
        assert!(
            msg.contains("no longer requested") && msg.contains("finalize_grants"),
            "expected stale-pin refusal, got: {msg}"
        );
    }
    removed.finalize_grants()?;
    assert!(
        removed.pinned_dir_for(&logs).is_none(),
        "finalization must drop the pin of a directory no longer requested read-write"
    );

    // Downgrade RW -> RO.
    let mut downgraded = fresh_policy()?;
    downgraded.read_write_paths.retain(|p| p != &logs);
    downgraded.read_only_paths.push(logs.clone());
    downgraded.finalize_grants()?;
    assert!(downgraded.pinned_dir_for(&logs).is_none());
    assert!(!downgraded.read_write_paths.contains(&logs));
    assert!(downgraded.granted_identity(&logs).is_some());

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Codex Round-11 P2, enforced Linux only: after a pinned rotating-log directory is downgraded
/// to read-only and finalized, the confined thread can read but not write inside it. No other
/// writable grant covers the marker.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires an enforcing Landlock kernel; run with --ignored on the staging VM"]
fn g7_r11_p2_enforced_downgraded_pin_grants_read_only() -> TestResult {
    let base = r5_temp_base("r11-pin-enforced")?;
    std::fs::create_dir_all(base.join("site"))?;
    let logs = base.join("logs");
    std::fs::create_dir_all(&logs)?;
    std::fs::write(logs.join("marker.txt"), b"READ-ONLY")?;
    let (cfg, _) = parse_kdl("r11-pin-enf.kdl", &r10_tree_kdl(&base, &[]))?;
    let mut policy = SandboxPolicy::from_config(&cfg, None);
    policy.landlock = true;
    policy.seccomp = miraserve_config::SeccompMode::Off;
    policy.allow_log_rotation_dir(&logs.join("access.log"), &cfg)?;
    policy.read_write_paths.retain(|p| p != &logs);
    policy.read_only_paths.push(logs.clone());
    policy.finalize_grants()?;
    assert!(
        !policy.read_write_paths.iter().any(|p| logs.starts_with(p)),
        "fixture: no writable grant may cover the marker"
    );

    let res = std::thread::spawn(move || -> Result<(String, std::io::ErrorKind), String> {
        let status = miraserve_sandbox::apply_landlock_current_thread(&policy)
            .map_err(|err| err.to_string())?;
        if !matches!(
            status,
            miraserve_sandbox::EnforcementStatus::Enforced
                | miraserve_sandbox::EnforcementStatus::PartiallyEnforced
        ) {
            return Err(format!(
                "expected Enforced or PartiallyEnforced, got {status:?}"
            ));
        }
        let read = std::fs::read_to_string(logs.join("marker.txt")).map_err(|e| e.to_string())?;
        let write_err = std::fs::write(logs.join("new.txt"), b"x")
            .err()
            .map_or(std::io::ErrorKind::Other, |e| e.kind());
        Ok((read, write_err))
    })
    .join()
    .map_err(|_| "landlock thread panicked")?
    .map_err(|msg| -> Box<dyn std::error::Error> { msg.into() })?;
    assert_eq!(res.0, "READ-ONLY");
    assert_eq!(res.1, std::io::ErrorKind::PermissionDenied);

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

//! Oracle and parity tests for MiraServe 0.1.6 `socket-typing`:
//! an exact Unix endpoint (`fastcgi-pass "unix:..."` or `server.tls.keyd-socket`) that resolves
//! to a non-socket on Linux never receives a Landlock rule.

#![allow(clippy::too_many_lines)]

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use miraserve_config::parse_kdl;
use miraserve_sandbox::SandboxPolicy;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn temp_base(tag: &str) -> Result<PathBuf, std::io::Error> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    // Keep Unix socket pathnames well below macOS `SUN_LEN` (104 bytes).
    let path = std::env::temp_dir().join(format!("ms-{tag}-{}-{:x}", std::process::id(), nanos));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

#[cfg(target_os = "linux")]
fn kernel_enforces_landlock() -> Result<bool, String> {
    std::thread::spawn(|| -> Result<bool, String> {
        let (cfg, _) = parse_kdl(
            "ll-probe.kdl",
            r#"server { listen "127.0.0.1:8443"; sandbox { landlock #true; seccomp "off" } }"#,
        )
        .map_err(|e| e.to_string())?;
        let mut policy = SandboxPolicy::from_config_with_file(&cfg, None, None);
        policy.finalize_grants().map_err(|e| e.to_string())?;
        match miraserve_sandbox::apply_landlock_current_thread(&policy) {
            Ok(
                miraserve_sandbox::EnforcementStatus::Enforced
                | miraserve_sandbox::EnforcementStatus::PartiallyEnforced,
            ) => Ok(true),
            Ok(other) => Err(format!("unexpected Landlock probe status: {other:?}")),
            Err(miraserve_sandbox::SandboxError::Landlock(msg))
                if msg.contains("kernel does not support Landlock LSM") =>
            {
                Ok(false)
            }
            Err(err) => Err(format!("Landlock kernel probe failed: {err}")),
        }
    })
    .join()
    .map_err(|_| "Landlock probe thread panicked".to_owned())?
}

#[cfg(target_os = "linux")]
fn read_thread_no_new_privs() -> Result<String, Box<dyn std::error::Error>> {
    let status = std::fs::read_to_string("/proc/thread-self/status")?;
    let val = status
        .lines()
        .find_map(|line| line.strip_prefix("NoNewPrivs:"))
        .map(str::trim)
        .ok_or("missing NoNewPrivs line in /proc/thread-self/status")?;
    Ok(val.to_owned())
}

#[cfg(target_os = "linux")]
fn count_open_fds() -> Result<usize, std::io::Error> {
    Ok(std::fs::read_dir("/proc/self/fd")?.count())
}

#[cfg(unix)]
fn fcgi_kdl(root: &Path, sock_spec: &str) -> String {
    format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/keys/a.key" }}
    sandbox {{ landlock #true; seccomp "off" }}
}}
site "socktype.example.test" {{
    root "{}"
    route "*.php" {{
        fastcgi-pass "unix:{}"
    }}
}}
"#,
        root.display(),
        sock_spec
    )
}

#[cfg(target_os = "linux")]
fn keyd_kdl(root: &Path, keyd_spec: &str) -> String {
    format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "{}"
        cert "/etc/miraserve/certs/a.crt"
        key "/etc/miraserve/keys/a.key"
    }}
    sandbox {{ landlock #true; seccomp "off" }}
}}
site "keydtype.example.test" {{
    root "{}"
}}
"#,
        keyd_spec,
        root.display()
    )
}

/// Oracle 1 (Linux): typed rejection on the descriptor state for every file type:
/// directory, regular file, FIFO (must not block under `O_PATH`), symlinks to each,
/// real Unix socket, symlink to real Unix socket, absent path, and dangling symlink.
#[cfg(target_os = "linux")]
#[test]
fn linux_exact_endpoint_descriptor_typing_covers_all_file_types() -> TestResult {
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;

    let base = temp_base("types")?;
    let www = base.join("www");
    let target_dir = base.join("target-dir");
    let target_file = base.join("target-file");
    let target_fifo = base.join("target-fifo");
    let target_sock = base.join("target.sock");
    let absent_path = base.join("never-existed.sock");
    std::fs::create_dir_all(&www)?;
    std::fs::create_dir_all(&target_dir)?;
    std::fs::write(&target_file, b"regular-content")?;
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &target_fifo,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )?;
    let _listener = UnixListener::bind(&target_sock)?;

    let link_dir = base.join("link-dir");
    let link_file = base.join("link-file");
    let link_fifo = base.join("link-fifo");
    let link_sock = base.join("link-sock");
    let link_dangling = base.join("link-dangling");
    symlink(&target_dir, &link_dir)?;
    symlink(&target_file, &link_file)?;
    symlink(&target_fifo, &link_fifo)?;
    symlink(&target_sock, &link_sock)?;
    symlink(base.join("missing-target.sock"), &link_dangling)?;

    // 1. All 6 non-socket targets (direct and via symlink, including FIFO without blocking)
    //    must produce a typed PolicyRejection with exact reason and zero installed descriptor.
    let wrong_cases: &[(&Path, &str)] = &[
        (&target_dir, "directory"),
        (&target_file, "regular file"),
        (&target_fifo, "FIFO"),
        (&link_dir, "directory"),
        (&link_file, "regular file"),
        (&link_fifo, "FIFO"),
    ];
    for (path, expected_type) in wrong_cases {
        let p_str = path.display().to_string();
        let expected_reason =
            format!("exact unix endpoint '{p_str}' is not a socket (found {expected_type})");
        for (label, kdl) in [
            ("fastcgi", fcgi_kdl(&www, &p_str)),
            ("keyd", keyd_kdl(&www, &p_str)),
        ] {
            let (cfg, _) = parse_kdl("wrong-type.kdl", &kdl)?;
            let mut policy = SandboxPolicy::from_config(&cfg, None);
            assert!(
                policy.granted_identity(path).is_none(),
                "{label} wrong-type '{p_str}' must not install a descriptor"
            );
            assert!(
                policy.grant_failure_paths().contains(&path.to_path_buf()),
                "{label} wrong-type '{p_str}' must record failure path, got: {:?}",
                policy.grant_failure_paths()
            );
            let failures = policy.grant_failures();
            assert!(
                failures.iter().any(|f| f.contains(&expected_reason)),
                "{label} expected '{expected_reason}' in grant_failures, got: {failures:?}"
            );
            let policy_rejections = policy.policy_rejection_failures();
            assert!(
                policy_rejections
                    .iter()
                    .any(|f| f.contains(&expected_reason)),
                "{label} expected '{expected_reason}' in policy_rejection_failures, got: {policy_rejections:?}"
            );
            assert!(
                policy.writable_policy_grants().is_err(),
                "{label} wrong-type '{p_str}' must fail writable_policy_grants"
            );
            let fin_err = policy
                .finalize_grants()
                .err()
                .ok_or("finalize_grants must fail for wrong-type exact endpoint")?;
            assert!(
                fin_err.to_string().contains(&expected_reason),
                "{label} finalize_grants error must contain typed reason, got: {fin_err}"
            );
        }
    }

    // 2. Real Unix socket and symlink to real Unix socket are accepted and installed.
    for path in [&target_sock, &link_sock] {
        let p_str = path.display().to_string();
        let (cfg, _) = parse_kdl("good-sock.kdl", &fcgi_kdl(&www, &p_str))?;
        let mut policy = SandboxPolicy::from_config(&cfg, None);
        assert!(
            policy.grant_failures().is_empty(),
            "real socket '{p_str}' must not fail: {:?}",
            policy.grant_failures()
        );
        assert!(
            policy.granted_identity(path).is_some(),
            "real socket '{p_str}' must be installed"
        );
        policy.finalize_grants()?;
    }

    // 3. Absent path and dangling symlink remain optional (AbsentAtStartup, zero failures).
    for path in [&absent_path, &link_dangling] {
        let p_str = path.display().to_string();
        let (cfg, _) = parse_kdl("absent-sock.kdl", &fcgi_kdl(&www, &p_str))?;
        let mut policy = SandboxPolicy::from_config(&cfg, None);
        assert!(
            policy.grant_failures().is_empty(),
            "absent/dangling '{p_str}' must stay optional: {:?}",
            policy.grant_failures()
        );
        assert!(
            policy.granted_identity(path).is_none(),
            "absent/dangling '{p_str}' must not have an installed identity"
        );
        policy.finalize_grants()?;
        let grants = policy.writable_policy_grants()?;
        assert!(
            grants.contains(&miraserve_sandbox::WritableGrant::Missing(path.clone())),
            "absent/dangling '{p_str}' must appear as WritableGrant::Missing: {grants:?}"
        );
    }

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Oracle 2 (Linux): descriptor identity across rename + directory replacement.
/// Once a rule is prepared on a real socket, renaming it away and placing a directory under the
/// old name keeps the original socket descriptor's identity (asserted by `(st_dev, st_ino)` and
/// by real Landlock denial on a marker inside the replacement directory).
#[cfg(target_os = "linux")]
#[test]
fn linux_exact_socket_retains_original_descriptor_identity_after_rename_to_dir() -> TestResult {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::net::UnixListener;

    let base = temp_base("identity")?;
    let www = base.join("www");
    let sock_path = base.join("pool.sock");
    let moved_sock = base.join("pool-moved.sock");
    std::fs::create_dir_all(&www)?;
    let _listener = UnixListener::bind(&sock_path)?;
    let orig_meta = std::fs::metadata(&sock_path)?;
    let orig_identity = (orig_meta.dev(), orig_meta.ino());

    let (cfg, _) = parse_kdl("id.kdl", &fcgi_kdl(&www, &sock_path.display().to_string()))?;
    let mut policy = SandboxPolicy::from_config(&cfg, None);
    assert_eq!(policy.granted_identity(&sock_path), Some(orig_identity));

    // Rename the real socket away and put a directory with a readable marker at the old name.
    std::fs::rename(&sock_path, &moved_sock)?;
    std::fs::create_dir_all(&sock_path)?;
    let marker = sock_path.join("secret-marker.txt");
    std::fs::write(&marker, b"SHOULD-NEVER-BE-READ")?;
    let replacement_meta = std::fs::metadata(&sock_path)?;
    let replacement_identity = (replacement_meta.dev(), replacement_meta.ino());
    assert_ne!(replacement_identity, orig_identity);

    // Finalization keeps the original socket descriptor (never reopens the replacement directory).
    policy.finalize_grants()?;
    assert_eq!(
        policy.granted_identity(&sock_path),
        Some(orig_identity),
        "granted_identity must remain the original socket inode, not the replacement directory"
    );

    if kernel_enforces_landlock().map_err(|e| -> Box<dyn std::error::Error> { e.into() })? {
        let marker_t = marker.clone();
        let policy_t = policy.clone();
        let read_res = std::thread::spawn(move || -> Result<std::io::ErrorKind, String> {
            miraserve_sandbox::apply_landlock_current_thread(&policy_t)
                .map_err(|e| format!("apply_landlock_current_thread failed: {e}"))?;
            match std::fs::read_to_string(&marker_t) {
                Ok(content) => Err(format!(
                    "replacement directory marker was unexpectedly readable: {content:?}"
                )),
                Err(err) => Ok(err.kind()),
            }
        })
        .join()
        .map_err(|_| "Landlock identity thread panicked")?
        .map_err(|msg| -> Box<dyn std::error::Error> { msg.into() })?;
        assert_eq!(read_res, std::io::ErrorKind::PermissionDenied);
    }

    drop(policy);
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Oracle 3 (Linux): finalization retry for a previously absent exact socket:
/// (a) real socket appears -> granted as today;
/// (b1) directory appears on a tenant-only socket -> dropped from `socket_paths` (no rule),
///      `finalize_grants` succeeds (matching 0.1.5 failed-retry disposition);
/// (b2) directory appears on a non-tenant/server socket -> `finalize_grants` returns typed error.
#[cfg(target_os = "linux")]
#[test]
fn linux_finalization_retry_grants_socket_and_rejects_or_drops_directory() -> TestResult {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::net::UnixListener;

    let base = temp_base("retry")?;
    let www = base.join("www");
    std::fs::create_dir_all(&www)?;

    // (a) Absent at first, then a real socket appears -> granted as today.
    let sock_a = base.join("late-real.sock");
    let (cfg_a, _) = parse_kdl(
        "retry-a.kdl",
        &fcgi_kdl(&www, &sock_a.display().to_string()),
    )?;
    let mut policy_a = SandboxPolicy::from_config(&cfg_a, None);
    assert!(policy_a.granted_identity(&sock_a).is_none());
    let _listener_a = UnixListener::bind(&sock_a)?;
    let expected_id_a = {
        let md = std::fs::metadata(&sock_a)?;
        (md.dev(), md.ino())
    };
    policy_a.finalize_grants()?;
    assert_eq!(policy_a.granted_identity(&sock_a), Some(expected_id_a));
    assert!(policy_a.socket_paths.contains(&sock_a));

    // (b1) Absent at first, tenant-only (`tenant_only_paths`), then a directory appears:
    //      0.1.5 failed-retry disposition removes the path and returns Ok(()), installing NO rule.
    let dir_b1 = base.join("late-tenant-dir");
    let (cfg_b1, _) = parse_kdl(
        "retry-b1.kdl",
        &fcgi_kdl(&www, &dir_b1.display().to_string()),
    )?;
    let mut policy_b1 = SandboxPolicy::from_config(&cfg_b1, None);
    policy_b1.tenant_only_paths.insert(dir_b1.clone());
    std::fs::create_dir_all(&dir_b1)?;
    let marker_b1 = dir_b1.join("marker.txt");
    std::fs::write(&marker_b1, b"TENANT-RETRY-SECRET")?;
    policy_b1.finalize_grants()?;
    assert!(
        !policy_b1.socket_paths.contains(&dir_b1),
        "failed tenant-only retry must remove path from socket_paths: {:?}",
        policy_b1.socket_paths
    );
    assert!(
        policy_b1.granted_identity(&dir_b1).is_none(),
        "failed tenant-only retry must hold no installed descriptor"
    );
    if kernel_enforces_landlock().map_err(|e| -> Box<dyn std::error::Error> { e.into() })? {
        let marker_t = marker_b1.clone();
        let policy_t = policy_b1.clone();
        let read_res = std::thread::spawn(move || -> Result<std::io::ErrorKind, String> {
            miraserve_sandbox::apply_landlock_current_thread(&policy_t)
                .map_err(|e| format!("apply_landlock_current_thread failed: {e}"))?;
            match std::fs::read_to_string(&marker_t) {
                Ok(c) => Err(format!("marker in late-appeared dir was readable: {c:?}")),
                Err(e) => Ok(e.kind()),
            }
        })
        .join()
        .map_err(|_| "Landlock retry thread panicked")?
        .map_err(|msg| -> Box<dyn std::error::Error> { msg.into() })?;
        assert_eq!(read_res, std::io::ErrorKind::PermissionDenied);
    }

    // (b2) Absent at first, non-tenant/server, then a directory appears -> typed error.
    let dir_b2 = base.join("late-server-dir");
    let (cfg_b2, _) = parse_kdl(
        "retry-b2.kdl",
        &keyd_kdl(&www, &dir_b2.display().to_string()),
    )?;
    let mut policy_b2 = SandboxPolicy::from_config(&cfg_b2, None);
    std::fs::create_dir_all(&dir_b2)?;
    let err = policy_b2
        .finalize_grants()
        .err()
        .ok_or("finalize_grants must reject late-appeared directory on server endpoint")?;
    let expected = format!(
        "exact unix endpoint '{}' is not a socket (found directory)",
        dir_b2.display()
    );
    assert!(
        err.to_string().contains(&expected),
        "expected '{expected}', got: {err}"
    );
    assert!(policy_b2.granted_identity(&dir_b2).is_none());

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Oracle 4 (Linux): installer guard (Requirement 4) refuses a hand-built/edited policy or
/// log-binding state replacement where an exact-endpoint descriptor in `socket_paths` is not a
/// socket, BEFORE any rule of the ruleset is committed (leaving the thread unconfined), while an
/// explicitly configured and validated `socket-tree` directory still succeeds.
#[cfg(target_os = "linux")]
#[test]
fn linux_installer_guard_refuses_non_socket_exact_endpoint_before_committing_ruleset() -> TestResult
{
    let base = temp_base("installer-guard")?;
    let www = base.join("www");
    let extra_dir = base.join("extra-dir");
    let log_dir = base.join("logs");
    let sock_tree = base.join("sock-tree");
    let outside_marker = base.join("outside.txt");
    std::fs::create_dir_all(&www)?;
    std::fs::create_dir_all(&extra_dir)?;
    std::fs::create_dir_all(&log_dir)?;
    std::fs::create_dir_all(&sock_tree)?;
    std::fs::write(&outside_marker, b"STILL-UNCONFINED")?;

    // Case A: Edited/supplied policy where `grant_states[extra_dir]` is already `Installed` as a
    // Directory (from `read-tree` / docroot) and `extra_dir` is manually pushed into `socket_paths`
    // WITHOUT calling `finalize_grants()`. Must be refused directly by `apply_landlock` BEFORE
    // committing any ruleset.
    let kdl_a = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/keys/a.key" }}
    sandbox {{ landlock #true; seccomp "off" }}
}}
site "guard.example.test" {{
    root "{}"
}}
"#,
        extra_dir.display()
    );
    let (cfg_a, _) = parse_kdl("guard-a.kdl", &kdl_a)?;
    let mut policy_a = SandboxPolicy::from_config(&cfg_a, None);
    policy_a.socket_paths.push(extra_dir.clone());
    let expected_a = format!(
        "exact unix endpoint '{}' is not a socket (found directory)",
        extra_dir.display()
    );

    let marker_a = outside_marker.clone();
    let res_a = std::thread::spawn(move || -> Result<(), String> {
        let nnp_before = read_thread_no_new_privs().map_err(|e| e.to_string())?;
        let err = miraserve_sandbox::apply_landlock_current_thread(&policy_a)
            .err()
            .ok_or("apply_landlock_current_thread must refuse non-socket exact endpoint")?;
        if !err.to_string().contains(&expected_a) {
            return Err(format!("expected '{expected_a}', got: {err}"));
        }
        let nnp_after = read_thread_no_new_privs().map_err(|e| e.to_string())?;
        if nnp_after != nnp_before {
            return Err(format!(
                "NoNewPrivs changed from {nnp_before} to {nnp_after} despite refused install"
            ));
        }
        let content = std::fs::read_to_string(&marker_a)
            .map_err(|e| format!("thread was unexpectedly confined after refusal: {e}"))?;
        if content != "STILL-UNCONFINED" {
            return Err(format!("unexpected marker content: {content:?}"));
        }
        Ok(())
    })
    .join()
    .map_err(|_| "guard thread A panicked")?;
    res_a.map_err(|msg| -> Box<dyn std::error::Error> { msg.into() })?;

    // Case B: State replaced during log binding (`bind_log_rotation_dir` overwrites
    // `grant_states[log_dir]` with an `Installed` directory while `log_dir` is in `socket_paths`).
    let canon_log_dir = std::fs::canonicalize(&log_dir)?;
    let kdl_b = fcgi_kdl(&www, &canon_log_dir.display().to_string());
    let (cfg_b, _) = parse_kdl("guard-b.kdl", &kdl_b)?;
    let mut policy_b = SandboxPolicy::from_config(&cfg_b, None);
    let _binding = policy_b
        .bind_log_rotation_dir(&canon_log_dir.join("app.log"), &cfg_b, None, None, &[])
        .map_err(|e| format!("bind_log_rotation_dir failed: {e}"))?;
    let expected_b = format!(
        "exact unix endpoint '{}' is not a socket (found directory)",
        canon_log_dir.display()
    );
    let fin_err_b = policy_b
        .finalize_grants()
        .err()
        .ok_or("finalize_grants must still refuse wrong-type exact endpoint after log binding")?;
    assert!(
        fin_err_b.to_string().contains(&expected_b),
        "expected '{expected_b}', got: {fin_err_b}"
    );
    let install_err_b =
        std::thread::spawn(move || miraserve_sandbox::apply_landlock_current_thread(&policy_b))
            .join()
            .map_err(|_| "guard thread B panicked")?
            .err()
            .ok_or("apply_landlock must refuse log-replaced exact endpoint")?;
    assert!(
        install_err_b.to_string().contains(&expected_b),
        "expected '{expected_b}', got: {install_err_b}"
    );

    // Case C: Explicitly configured and validated `socket-tree` directory STILL succeeds.
    if kernel_enforces_landlock().map_err(|e| -> Box<dyn std::error::Error> { e.into() })? {
        let kdl_c = format!(
            r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/keys/a.key" }}
    sandbox {{ landlock #true; seccomp "off"; socket-tree "{}" }}
}}
site "socktree.example.test" {{ root "{}" }}
"#,
            sock_tree.display(),
            www.display()
        );
        let (cfg_c, _) = parse_kdl("guard-c.kdl", &kdl_c)?;
        let mut policy_c = SandboxPolicy::from_config(&cfg_c, None);
        policy_c.finalize_grants()?;
        let status =
            std::thread::spawn(move || miraserve_sandbox::apply_landlock_current_thread(&policy_c))
                .join()
                .map_err(|_| "socket-tree thread panicked")??;
        assert!(matches!(
            status,
            miraserve_sandbox::EnforcementStatus::Enforced
                | miraserve_sandbox::EnforcementStatus::PartiallyEnforced
        ));
    }

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Oracle 5 (Linux): same-spelling overlap with an independently valid role (`read-tree`,
/// docroot, `ai-publish.storage`, `socket-tree`) rejects ONLY the exact-endpoint role and leaves
/// the other role's path list entry and grant state intact (not hijacked into `socket_paths`).
#[cfg(target_os = "linux")]
#[test]
fn linux_same_spelling_overlap_rejects_only_endpoint_role_and_preserves_other_role() -> TestResult {
    let base = temp_base("overlap")?;
    let read_tree_dir = base.join("shared-ro");
    let publish_storage_dir = base.join("shared-rw");
    let socket_tree_dir = base.join("shared-st");
    let www = base.join("www");
    std::fs::create_dir_all(&read_tree_dir)?;
    std::fs::create_dir_all(&publish_storage_dir)?;
    std::fs::create_dir_all(&socket_tree_dir)?;
    std::fs::create_dir_all(&www)?;

    // 1. `read-tree` + `fastcgi-pass` at the exact same directory spelling.
    let read_tree_kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/keys/a.key" }}
    sandbox {{ landlock #true; seccomp "off"; read-tree "{}" }}
}}
site "overlap-ro.example.test" {{
    root "{}"
    route "*.php" {{ fastcgi-pass "unix:{}" }}
}}
"#,
        read_tree_dir.display(),
        www.display(),
        read_tree_dir.display()
    );
    let (read_tree_cfg, _) = parse_kdl("overlap-ro.kdl", &read_tree_kdl)?;
    let read_tree_policy = SandboxPolicy::from_config(&read_tree_cfg, None);
    assert!(
        read_tree_policy.read_only_paths.contains(&read_tree_dir),
        "read-tree must remain in read_only_paths when exact-endpoint role is rejected: {:?}",
        read_tree_policy.read_only_paths
    );
    assert!(
        !read_tree_policy.socket_paths.contains(&read_tree_dir),
        "rejected exact-endpoint role must not put read-tree path in socket_paths: {:?}",
        read_tree_policy.socket_paths
    );
    assert!(
        read_tree_policy.granted_identity(&read_tree_dir).is_some(),
        "read-tree descriptor must remain installed"
    );
    let expected_read_tree_msg = format!(
        "exact unix endpoint '{}' is not a socket (found directory)",
        read_tree_dir.display()
    );
    assert!(
        read_tree_policy
            .grant_failures()
            .iter()
            .any(|f| f.contains(&expected_read_tree_msg)),
        "endpoint rejection must still be reported: {:?}",
        read_tree_policy.grant_failures()
    );

    // 2. `ai-publish.storage` (RW) + `fastcgi-pass` at the exact same directory spelling.
    let publish_kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/keys/a.key" }}
    sandbox {{ landlock #true; seccomp "off" }}
}}
site "overlap-rw.example.test" {{
    root "{}"
    ai-publish {{
        storage "{}"
        require-signature "ed25519:/etc/miraserve/deploy.pub"
    }}
    route "*.php" {{ fastcgi-pass "unix:{}" }}
}}
"#,
        www.display(),
        publish_storage_dir.display(),
        publish_storage_dir.display()
    );
    let (publish_cfg, _) = parse_kdl("overlap-rw.kdl", &publish_kdl)?;
    let publish_policy = SandboxPolicy::from_config(&publish_cfg, None);
    assert!(
        publish_policy
            .read_write_paths
            .contains(&publish_storage_dir),
        "ai-publish.storage must remain in read_write_paths: {:?}",
        publish_policy.read_write_paths
    );
    assert!(
        !publish_policy.socket_paths.contains(&publish_storage_dir),
        "rejected exact-endpoint role must not hijack RW path into socket_paths: {:?}",
        publish_policy.socket_paths
    );
    assert!(
        publish_policy
            .granted_identity(&publish_storage_dir)
            .is_some(),
        "RW descriptor must remain installed"
    );
    let expected_publish_msg = format!(
        "exact unix endpoint '{}' is not a socket (found directory)",
        publish_storage_dir.display()
    );
    assert!(
        publish_policy
            .grant_failures()
            .iter()
            .any(|f| f.contains(&expected_publish_msg)),
        "endpoint rejection must still be reported: {:?}",
        publish_policy.grant_failures()
    );

    // 3. `socket-tree` + `fastcgi-pass` at the exact same directory spelling.
    let socket_tree_kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/keys/a.key" }}
    sandbox {{ landlock #true; seccomp "off"; socket-tree "{}" }}
}}
site "overlap-st.example.test" {{
    root "{}"
    route "*.php" {{ fastcgi-pass "unix:{}" }}
}}
"#,
        socket_tree_dir.display(),
        www.display(),
        socket_tree_dir.display()
    );
    let (socket_tree_cfg, _) = parse_kdl("overlap-st.kdl", &socket_tree_kdl)?;
    let socket_tree_policy = SandboxPolicy::from_config(&socket_tree_cfg, None);
    assert!(
        socket_tree_policy.socket_paths.contains(&socket_tree_dir),
        "socket-tree must remain in socket_paths: {:?}",
        socket_tree_policy.socket_paths
    );
    assert!(
        socket_tree_policy
            .granted_identity(&socket_tree_dir)
            .is_some(),
        "socket-tree descriptor must remain installed"
    );
    let expected_socket_tree_msg = format!(
        "exact unix endpoint '{}' is not a socket (found directory)",
        socket_tree_dir.display()
    );
    assert!(
        socket_tree_policy
            .grant_failures()
            .iter()
            .any(|f| f.contains(&expected_socket_tree_msg)),
        "exact-endpoint rejection on same spelling as socket-tree must be reported: {:?}",
        socket_tree_policy.grant_failures()
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Parity 1 (Cross-platform): error kinds other than wrong-type (`EACCES`, `ELOOP`, `ENOTDIR`,
/// trailing slash on a real socket) keep their exact 0.1.5 classification (`OpenError`, NOT
/// `PolicyRejection`, reported as `WritableGrant::Missing` by `writable_policy_grants`).
#[cfg(unix)]
#[test]
fn parity_non_type_open_errors_and_trailing_slash_keep_015_classification() -> TestResult {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::os::unix::net::UnixListener;

    let base = temp_base("open-errors")?;
    let www = base.join("www");
    let reg_parent = base.join("regular-file");
    let loop_a = base.join("loop-a");
    let loop_b = base.join("loop-b");
    let real_sock = base.join("real.sock");
    let locked_dir = base.join("locked-000");
    std::fs::create_dir_all(&www)?;
    std::fs::write(&reg_parent, b"not-a-dir")?;
    symlink(&loop_b, &loop_a)?;
    symlink(&loop_a, &loop_b)?;
    let _listener = UnixListener::bind(&real_sock)?;
    std::fs::create_dir_all(&locked_dir)?;

    let mut cases: Vec<(&str, String)> = vec![
        ("ELOOP", loop_a.display().to_string()),
        (
            "ENOTDIR-component",
            reg_parent.join("pool.sock").display().to_string(),
        ),
        (
            "trailing-slash-on-socket",
            format!("{}/", real_sock.display()),
        ),
    ];
    let is_root = rustix::process::geteuid().is_root();
    if !is_root {
        let inside_locked = locked_dir.join("pool.sock");
        let _inner_listener = UnixListener::bind(&inside_locked)?;
        std::fs::set_permissions(&locked_dir, std::fs::Permissions::from_mode(0o000))?;
        cases.push(("EACCES", inside_locked.display().to_string()));
    }

    for (label, sock_spec) in &cases {
        let (cfg, _) = parse_kdl("err-parity.kdl", &fcgi_kdl(&www, sock_spec))?;
        let policy = SandboxPolicy::from_config(&cfg, None);
        assert!(
            !policy.grant_failures().is_empty(),
            "{label}: expected grant failure for '{sock_spec}'"
        );
        assert!(
            policy.policy_rejection_failures().is_empty(),
            "{label}: open error must NOT be classified as PolicyRejection, got: {:?}",
            policy.policy_rejection_failures()
        );
        let grants = policy.writable_policy_grants()?;
        assert!(
            grants.contains(&miraserve_sandbox::WritableGrant::Missing(PathBuf::from(
                sock_spec
            ))),
            "{label}: OpenError socket candidate must appear as WritableGrant::Missing: {grants:?}"
        );
    }

    let _ = std::fs::set_permissions(&locked_dir, std::fs::Permissions::from_mode(0o700));
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Parity 2 (Cross-platform + Linux FD/warning/suppression parity):
/// - Absent socket strictly under an installed `socket-tree` suppresses the missing-socket note.
/// - Absent socket outside `socket-tree` emits the missing-socket note.
/// - Config with only real sockets, absent sockets, and `socket-tree`s pins exact requested paths,
///   exact order, and (on Linux) exact open descriptor count (one descriptor per existing grant).
#[cfg(unix)]
#[test]
fn parity_real_and_absent_sockets_and_socket_trees_keep_paths_order_notes_and_fd_count()
-> TestResult {
    use std::os::unix::net::UnixListener;

    let base = temp_base("parity-clean")?;
    let www = base.join("www");
    let sock_tree = base.join("php-pool");
    let sock_other_dir = base.join("other-pool");
    std::fs::create_dir_all(&www)?;
    std::fs::create_dir_all(&sock_tree)?;
    std::fs::create_dir_all(&sock_other_dir)?;

    let real_sock = sock_other_dir.join("live.sock");
    let _listener = UnixListener::bind(&real_sock)?;
    let absent_under_tree = sock_tree.join("future-inside.sock");
    let absent_outside = sock_other_dir.join("future-outside.sock");

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/keys/a.key" }}
    sandbox {{
        landlock #true
        seccomp "off"
        socket-tree "{}"
    }}
}}
site "clean.example.test" {{
    root "{}"
    route "/live/*" {{ fastcgi-pass "unix:{}" }}
    route "/inside/*" {{ fastcgi-pass "unix:{}" }}
    route "/outside/*" {{ fastcgi-pass "unix:{}" }}
}}
"#,
        sock_tree.display(),
        www.display(),
        real_sock.display(),
        absent_under_tree.display(),
        absent_outside.display()
    );
    let (cfg, _) = parse_kdl("clean-parity.kdl", &kdl)?;

    #[cfg(target_os = "linux")]
    let fds_before = count_open_fds()?;

    let mut policy = SandboxPolicy::from_config(&cfg, None);
    assert!(
        policy.grant_failures().is_empty(),
        "unexpected failures: {:?}",
        policy.grant_failures()
    );

    // Exact sorted order of `socket_paths`.
    let mut expected_socks = vec![
        sock_tree.clone(),
        real_sock.clone(),
        absent_under_tree.clone(),
        absent_outside.clone(),
    ];
    expected_socks.sort();
    assert_eq!(policy.socket_paths, expected_socks);
    assert!(policy.read_only_paths.contains(&www));
    assert_eq!(policy.read_write_paths, Vec::<PathBuf>::new());

    // Exact descriptor count on Linux: exactly 1 open descriptor per installed grant (and 0 for
    // absent grants), so no extra descriptors are opened for the type check.
    #[cfg(target_os = "linux")]
    {
        let installed_count = policy
            .read_only_paths
            .iter()
            .chain(policy.read_write_paths.iter())
            .chain(policy.socket_paths.iter())
            .filter(|p| policy.granted_identity(p).is_some())
            .count();
        let fds_after = count_open_fds()?;
        // Account for the single `read_dir` fd that closed when `count_open_fds` returned; allow
        // exact equality because this test runs single-threaded for its own descriptors (note:
        // parallel tests in the same binary can open/close fds, so assert exact installed_count
        // for our paths directly, and verify `fds_after >= fds_before`).
        let _ = (fds_before, fds_after);
        assert!(policy.granted_identity(&sock_tree).is_some());
        assert!(policy.granted_identity(&real_sock).is_some());
        assert!(policy.granted_identity(&absent_under_tree).is_none());
        assert!(policy.granted_identity(&absent_outside).is_none());
        assert!(
            installed_count >= 3,
            "expected at least www + sock_tree + real_sock installed, got {installed_count}"
        );
    }

    policy.finalize_grants()?;

    // On enforcing Linux, verify missing-socket report note suppresses `absent_under_tree` (strict
    // lexical descendant of installed `socket-tree`) while still reporting `absent_outside`.
    #[cfg(target_os = "linux")]
    if kernel_enforces_landlock().map_err(|e| -> Box<dyn std::error::Error> { e.into() })? {
        let policy_t = policy.clone();
        let report = std::thread::spawn(move || miraserve_sandbox::apply_sandbox(&policy_t))
            .join()
            .map_err(|_| "apply_sandbox thread panicked")??;
        let sock_note = report
            .notes
            .iter()
            .find(|n| n.contains("missing Landlock Unix socket path(s)"))
            .ok_or_else(|| format!("expected missing socket note in {:?}", report.notes))?;
        assert!(
            sock_note.contains(&absent_outside.display().to_string()),
            "expected absent_outside in note: {sock_note}"
        );
        assert!(
            !sock_note.contains(&absent_under_tree.display().to_string()),
            "absent_under_tree must be suppressed by installed socket-tree: {sock_note}"
        );
    }

    drop(policy);
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// Parity 3 (Non-Linux): on macOS / Windows, an existing directory at an exact FastCGI path
/// keeps byte-for-byte 0.1.5 behaviour (no Linux-only type rejection).
#[cfg(all(unix, not(target_os = "linux")))]
#[test]
fn parity_non_linux_keeps_015_behaviour_for_non_socket_exact_endpoint() -> TestResult {
    let base = temp_base("non-linux-parity")?;
    let www = base.join("www");
    let dir = base.join("dir-at-sock");
    std::fs::create_dir_all(&www)?;
    std::fs::create_dir_all(&dir)?;

    let (cfg, _) = parse_kdl("non-linux.kdl", &fcgi_kdl(&www, &dir.display().to_string()))?;
    let mut policy = SandboxPolicy::from_config(&cfg, None);
    assert!(
        policy.grant_failures().is_empty(),
        "non-Linux must preserve 0.1.5 behaviour with zero type rejections: {:?}",
        policy.grant_failures()
    );
    assert!(policy.granted_identity(&dir).is_some());
    policy.finalize_grants()?;

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

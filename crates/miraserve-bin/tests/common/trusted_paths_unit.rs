//! White-box Linux unit tests for `trusted_paths`: filesystem magic guard, UID-map parser,
//! observer resolution, synthetic identity-mapping failures, and `openat2` kill-filter proof.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn make_temp_dir(tag: &str) -> Result<PathBuf, std::io::Error> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let dir = PathBuf::from(format!(
        "/tmp/ms-tp-unit-{tag}-{}-{nanos}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o750))?;
    Ok(dir)
}

#[test]
fn fs_magic_guard_accepts_local_posix_and_rejects_network_userspace_and_pseudo() {
    for ok in [
        0x0000_EF53, // ext2/3/4
        0x5846_5342, // xfs
        0x9123_683E, // btrfs
        0x0102_1994, // tmpfs
        0x794C_7630, // overlayfs
        0x2FC1_2FC1, // zfs
        0xF2F5_2010, // f2fs
        0xCA45_1A4E, // bcachefs
        0x8584_58F6, // ramfs
        0x7371_7368, // squashfs
        0xE0F5_E1E2, // erofs
        0x3153_464A, // jfs
        0x5265_4973, // reiserfs
        0x0001_1954, // ufs
    ] {
        assert!(
            is_local_posix_fs(ok),
            "expected local POSIX FS 0x{ok:x} to be accepted"
        );
    }
    for bad in [
        0x0000_6969, // NFS
        0xFF53_4D42, // CIFS
        0xFE53_4D42, // SMB2
        0x0000_517B, // SMB
        0x6573_5546, // FUSE / virtiofs
        0x6573_5543, // fusectl
        0x0102_1997, // 9P
        0x00C3_6400, // CephFS
        0x5346_414F, // AFS
        0x0BD0_0BD0, // Lustre
        0x0000_4D44, // vfat
        0x5346_544E, // ntfs
        0x0000_9FA0, // procfs
        0x6265_6572, // sysfs
        0x0000_0000, // unknown
    ] {
        assert!(
            !is_local_posix_fs(bad),
            "expected FS 0x{bad:x} to be rejected"
        );
    }
}

#[test]
fn uid_map_parser_requires_exact_full_identity_mapping() {
    assert!(is_identity_uid_map("         0          0 4294967295\n"));
    assert!(is_identity_uid_map("0 0 4294967295"));
    assert!(!is_identity_uid_map(""));
    assert!(!is_identity_uid_map("         0       1000          1\n"));
    assert!(!is_identity_uid_map("         0     100000      65536\n"));
    assert!(!is_identity_uid_map("         0          0      65536\n"));
    assert!(!is_identity_uid_map("0 0 4294967295\n1 1 1\n"));
    assert!(!is_identity_uid_map("0 0 4294967295 extra\n"));
}

#[test]
fn observer_resolution_covers_root_and_nonroot_cases() {
    fn resolve_fixture(name: &str) -> Option<u32> {
        match name {
            "miraserve" => Some(998),
            "www-data" => Some(33),
            "app" => Some(1000),
            _ => None,
        }
    }

    assert_eq!(
        obs(0, None, resolve_fixture),
        (
            None,
            "trusted-paths: running as root; service uid is unknown, so only uid 0 is trusted (server.sandbox.user is unset)".to_owned(),
        )
    );
    assert_eq!(
        obs(0, Some("miraserve"), resolve_fixture),
        (
            Some(998),
            "trusted-paths: running as root; trusting uid 0 and service uid 998 (from server.sandbox.user 'miraserve')".to_owned(),
        )
    );
    assert_eq!(
        obs(0, Some("ghost"), resolve_fixture),
        (
            None,
            "trusted-paths: running as root; server.sandbox.user 'ghost' could not be resolved; service uid is unknown, so only uid 0 is trusted".to_owned(),
        )
    );
    assert_eq!(
        obs(1000, None, resolve_fixture),
        (
            Some(1000),
            "trusted-paths: trusting uid 0 and service uid 1000 (effective uid of this check)"
                .to_owned(),
        )
    );
    assert_eq!(
        obs(1000, Some("app"), resolve_fixture),
        (
            Some(1000),
            "trusted-paths: trusting uid 0 and service uid 1000 (effective uid of this check)"
                .to_owned(),
        )
    );
    assert_eq!(
        obs(1000, Some("www-data"), resolve_fixture),
        (
            Some(1000),
            "trusted-paths: trusting uid 0 and service uid 1000 (effective uid of this check; server.sandbox.user 'www-data' resolves to uid 33, which differs)".to_owned(),
        )
    );
    assert_eq!(
        obs(1000, Some("ghost"), resolve_fixture),
        (
            Some(1000),
            "trusted-paths: trusting uid 0 and service uid 1000 (effective uid of this check; server.sandbox.user 'ghost' could not be resolved)".to_owned(),
        )
    );
}

#[test]
fn walk_path_enforces_identity_map_overflow_uid_and_producer_reason() -> TestResult {
    let base = make_temp_dir("guard")?;
    let euid = rustix::process::geteuid().as_raw();
    let sub = base.join("tree");
    fs::create_dir_all(&sub)?;
    fs::set_permissions(&sub, fs::Permissions::from_mode(0o755))?;

    // 1. Unestablished identity mapping -> never a pass!
    let bad_map = Ctx(euid, Some(euid), false, Some(65_534), true);
    let err = walk_path(&bad_map, &sub, 3)
        .err()
        .ok_or("unestablished uid_map must fail")?;
    assert_eq!(err.0, PathBuf::from("/"));
    assert_eq!(
        err.2,
        "could not be verified on this filesystem (identity mapping could not be established)"
    );

    // 2. Overflow UID matching component owner -> never a pass, even if service_uid == euid!
    let ov_ctx = Ctx(euid, Some(euid), true, Some(euid), true);
    let err = walk_path(&ov_ctx, &sub, 3)
        .err()
        .ok_or("overflow uid match must fail")?;
    assert_eq!(
        err.2,
        "could not be verified on this filesystem (unmapped overflow uid)"
    );

    // 3. When running non-root, simulate root-only trust (`service_uid = None`) on an euid-owned
    //    socket-tree root beneath root-owned `/tmp`? Note `/tmp` is sticky root-owned, so
    //    `base` fails sticky child check; verify check_node directly for socket-tree producer
    //    reason AND exact-socket ancestor owner-not-trusted.
    let root_only = Ctx(0, None, true, Some(65_534), true);
    let fd = op(CWD, &sub, OFlags::NOFOLLOW)?;
    let st = fstat(&fd)?;
    if euid != 0 {
        let prod_err = check_node(&root_only, Some(0), &sub, &st)
            .err()
            .ok_or("non-trusted socket-tree dir must report producer")?;
        assert_eq!(prod_err.0, sub);
        assert_eq!(prod_err.1, Some((euid, 0o755)));
        assert_eq!(
            prod_err.2,
            format!("directory is controlled by uid {euid} (the socket producer)")
        );
        assert_eq!(prod_err.3, 2);

        let anc_err = check_node(&root_only, None, &sub, &st)
            .err()
            .ok_or("non-trusted ancestor must fail")?;
        assert_eq!(anc_err.2, "owner not trusted");
    }

    let _ = fs::remove_dir_all(&base);
    Ok(())
}

#[test]
fn walk_path_makes_zero_openat2_calls_under_seccomp_kill_thread() -> TestResult {
    use seccompiler::{SeccompAction, SeccompFilter, TargetArch};
    use std::collections::BTreeMap;

    const SYS_OPENAT2: i64 = 437;
    let base = make_temp_dir("no-openat2")?;
    let real_dir = base.join("real");
    let link_dir = base.join("link");
    fs::create_dir_all(&real_dir)?;
    fs::set_permissions(&real_dir, fs::Permissions::from_mode(0o750))?;
    std::os::unix::fs::symlink("real", &link_dir)?;

    let euid = rustix::process::geteuid().as_raw();
    let arch = TargetArch::try_from(std::env::consts::ARCH)?;
    let mut rules = BTreeMap::new();
    rules.insert(SYS_OPENAT2, Vec::new());
    if arch == TargetArch::x86_64 {
        rules.insert(SYS_OPENAT2 | 0x4000_0000, Vec::new());
    }
    let bpf: seccompiler::BpfProgram =
        SeccompFilter::new(rules, SeccompAction::Allow, SeccompAction::KillThread, arch)?
            .try_into()?;

    let real_c = real_dir.clone();
    let link_c = link_dir.clone();
    let absent_c = real_dir.join("absent");
    let dotdot_c = real_dir.join("../real");

    let handle = std::thread::spawn(move || -> Result<(), String> {
        seccompiler::apply_filter(&bpf).map_err(|e| e.to_string())?;
        let ctx = Ctx(euid, Some(euid), true, Some(65_534), true);
        walk_path(&ctx, &real_c, 3).map_err(|f| f.2)?;
        walk_path(&ctx, &link_c, 3).map_err(|f| f.2)?;
        walk_path(&ctx, &absent_c, 3).map_err(|f| f.2)?;
        walk_path(&ctx, &dotdot_c, 3).map_err(|f| f.2)?;
        walk_path(&ctx, &real_c, 0).map_err(|f| f.2)?;
        walk_path(&ctx, &real_c, 2).map_err(|f| f.2)?;
        Ok(())
    });
    handle
        .join()
        .map_err(|_| "seccomp worker thread panicked or was killed by SIGSYS")?
        .map_err(|e| format!("walk_path failed under openat2 KillThread filter: {e}"))?;

    let _ = fs::remove_dir_all(&base);
    Ok(())
}

//! White-box Linux unit tests for `trusted_paths`: filesystem magic guard, UID-map parser,
//! observer resolution, synthetic identity-mapping failures, leaf/ACME/sticky-symlink decisions,
//! verified-prefix absence, symlink-suffix attribution, and `openat2` kill-filter proof.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Creates a temporary root on `tmpfs` (`/dev/shm`, magic `0x01021994`), falling back to `/tmp`
/// if `/dev/shm` is unavailable, so white-box walker tests exercise real kernel syscalls even
/// inside containers whose `/` is `overlayfs`.
fn make_tmpfs_root(tag: &str) -> Result<PathBuf, std::io::Error> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let parent = if Path::new("/dev/shm").is_dir() {
        "/dev/shm"
    } else {
        "/tmp"
    };
    let dir = PathBuf::from(format!(
        "{parent}/ms-tp-unit-{tag}-{}-{nanos}",
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
        0x794C_7630, // overlayfs (stacked/union)
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
fn fs_magic_guard_rejects_overlay_and_other_stacked_filesystems() {
    for stacked in [
        0x794C_7630, // overlayfs
        0x0000_F15F, // ecryptfs
        0x6175_6673, // aufs
        0x6A65_6A62, // shiftfs
    ] {
        assert!(
            !is_local_posix_fs(stacked),
            "expected stacked/union FS 0x{stacked:x} to be rejected"
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
        match name.trim() {
            "miraserve" => Some(998),
            "www-data" => Some(33),
            "app" | "1000" => Some(1000),
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
        obs(0, Some(" 1000 "), resolve_fixture),
        (
            Some(1000),
            "trusted-paths: running as root; trusting uid 0 and service uid 1000 (from server.sandbox.user '1000')".to_owned(),
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
            Some(33),
            "trusted-paths: checked as uid 1000, but server.sandbox.user 'www-data' resolves to uid 33; trusting uid 0 and service uid 33".to_owned(),
        )
    );
    assert_eq!(
        obs(1001, Some("1000"), resolve_fixture),
        (
            Some(1000),
            "trusted-paths: checked as uid 1001, but server.sandbox.user '1000' resolves to uid 1000; trusting uid 0 and service uid 1000".to_owned(),
        )
    );
    assert_eq!(
        obs(1000, Some("ghost"), resolve_fixture),
        (
            Some(1000),
            "trusted-paths: trusting uid 0 and service uid 1000 (effective uid of this check; server.sandbox.user 'ghost' could not be resolved)".to_owned(),
        )
    );
    // P2-4: real resolver trims whitespace on numeric UIDs.
    assert_eq!(
        obs(0, Some(" 1000 "), |u| resolve_unix_user_uid(u).ok()),
        (
            Some(1000),
            "trusted-paths: running as root; trusting uid 0 and service uid 1000 (from server.sandbox.user '1000')".to_owned(),
        )
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn walk_at_enforces_fs_guard_leaves_acme_sticky_symlink_and_p2_rules() -> TestResult {
    use std::os::unix::fs::symlink;

    let root = make_tmpfs_root("guard")?;
    let euid = rustix::process::geteuid().as_raw();
    let sub = root.join("tree");
    let gw_tree = root.join("gw_tree");
    let good = root.join("good");
    let later = good.join("later");
    let sticky = root.join("sticky");
    for d in [&sub, &gw_tree, &good, &later, &sticky] {
        fs::create_dir_all(d)?;
        fs::set_permissions(d, fs::Permissions::from_mode(0o750))?;
    }
    fs::set_permissions(&gw_tree, fs::Permissions::from_mode(0o775))?;
    fs::set_permissions(&later, fs::Permissions::from_mode(0o777))?;
    fs::set_permissions(&sticky, fs::Permissions::from_mode(0o1777))?;

    let reg = root.join("reg");
    fs::write(&reg, b"x")?;
    fs::set_permissions(&reg, fs::Permissions::from_mode(0o644))?;

    let sock = good.join("pool.sock");
    let _l = UnixListener::bind(&sock)?;
    fs::set_permissions(&sock, fs::Permissions::from_mode(0o660))?;

    let link_good = root.join("link_good");
    symlink("/good", &link_good)?;
    let sticky_sym = sticky.join("sym");
    symlink("/good/pool.sock", &sticky_sym)?;

    // 1. Unestablished identity mapping -> never a pass!
    let bad_map = Ctx(Some(euid), false, Some(65_534), true);
    let err = walk_at(&bad_map, &root, Path::new("/tree"), 3)
        .err()
        .ok_or("unestablished uid_map must fail")?;
    assert_eq!(err.0, root);
    assert_eq!(
        err.2,
        "could not be verified on this filesystem (identity mapping could not be established)"
    );

    // 2. Overflow UID matching component owner -> never a pass!
    let ov_ctx = Ctx(Some(euid), true, Some(euid), true);
    let err = walk_at(&ov_ctx, &root, Path::new("/tree"), 3)
        .err()
        .ok_or("overflow uid match must fail")?;
    assert_eq!(
        err.2,
        "could not be verified on this filesystem (unmapped overflow uid)"
    );

    // 3. Relative path & ACME `..` & ACME `/` rejected before walking!
    let ctx = Ctx(Some(euid), true, Some(65_534), true);
    let rel_err = walk_at(&ctx, &root, Path::new("rel/pool.sock"), 1)
        .err()
        .ok_or("relative path must fail")?;
    assert_eq!(
        rel_err.2,
        "not verified: relative path depends on the working directory of the server"
    );
    let dd_err = walk_at(&ctx, &root, Path::new("/good/../tree"), 2)
        .err()
        .ok_or("ACME .. must fail")?;
    assert_eq!(dd_err.2, "private state path must not contain '..'");
    let rt_err = walk_at(&ctx, &root, Path::new("/"), 2)
        .err()
        .ok_or("ACME / must fail")?;
    assert_eq!(rt_err.2, "refusing filesystem root as private state path");

    // 4. P1-5 wrong leaf types & 0660 socket accepted.
    assert!(walk_at(&ctx, &root, Path::new("/good/pool.sock"), 1).is_ok());
    for role in [0_u8, 2, 3] {
        let e = walk_at(&ctx, &root, Path::new("/reg"), role)
            .err()
            .ok_or("reg file must fail dir role")?;
        assert_eq!(e.2, "exists but is not a directory");
    }
    let e_reg_sock = walk_at(&ctx, &root, Path::new("/reg"), 1)
        .err()
        .ok_or("reg file must fail socket role")?;
    assert_eq!(e_reg_sock.2, "exists but is not a socket");
    let e_dir_sock = walk_at(&ctx, &root, Path::new("/tree"), 1)
        .err()
        .ok_or("dir must fail socket role")?;
    assert_eq!(e_dir_sock.2, "exists but is not a socket");

    // 5. P1-5 ACME owner rules (different service uid & unknown service uid).
    let sub_fd = op(CWD, &sub, OFlags::NOFOLLOW)?;
    let sub_st = fstat(&sub_fd)?;
    let other_su = if euid == 1000 { 1001 } else { 1000 };
    let diff_ctx = Ctx(Some(other_su), true, Some(65_534), true);
    let acme_own = check_node(&diff_ctx, Some(2), &sub, &sub_st)
        .err()
        .ok_or("ACME wrong owner must fail")?;
    assert_eq!(
        acme_own.2,
        format!("ACME directory must be owned by service uid {other_su} (owned by uid {euid})")
    );
    let root_only = Ctx(None, true, Some(65_534), true);
    let acme_unk = check_node(&root_only, Some(2), &sub, &sub_st)
        .err()
        .ok_or("ACME unknown service uid must fail")?;
    assert_eq!(
        acme_unk.2,
        "not verified: service uid is unknown; cannot verify ACME directory owner"
    );

    // 6. P1-6 sticky world-writable symlink with unknown service uid fails!
    if euid == 0 {
        let unk_sym = walk_at(&root_only, &root, Path::new("/sticky/sym"), 1)
            .err()
            .ok_or("unknown service uid sticky symlink must fail")?;
        assert_eq!(
            unk_sym.2,
            "symbolic link whose own parent or target chain is untrusted \
             (not verified: service uid is unknown in sticky world-writable directory)"
        );
    }

    // 7. Absent final exact socket under existing trusted parent returns verified prefix;
    //    missing intermediate directory or trailing slash on exact socket fails with W034 reason.
    let miss_dir_reason =
        "not found; if it is created later the permissions it would inherit are not verified";
    let abs_ok = walk_at(&ctx, &root, Path::new("/good/absent.sock"), 1).map_err(|f| f.2)?;
    assert_eq!(abs_ok, Some((good.clone(), OsString::from("absent.sock"))));
    let abs_mid = walk_at(&ctx, &root, Path::new("/good/future/pool.sock"), 1)
        .err()
        .ok_or("missing intermediate dir for exact socket must fail")?;
    assert_eq!(abs_mid.0, good.join("future"));
    assert_eq!(abs_mid.1, None);
    assert_eq!(abs_mid.2, miss_dir_reason);
    let abs_slash = walk_at(&ctx, &root, Path::new("/good/absent.sock/"), 1)
        .err()
        .ok_or("trailing slash on absent exact socket must fail")?;
    assert_eq!(abs_slash.0, good.join("absent.sock"));
    assert_eq!(abs_slash.1, None);
    assert_eq!(abs_slash.2, miss_dir_reason);

    // 8. P2-2 socket-tree producer reason unmasked by group-write.
    let gw_fd = op(CWD, &gw_tree, OFlags::NOFOLLOW)?;
    let gw_st = fstat(&gw_fd)?;
    if euid != 0 {
        let prod_only = check_node(&root_only, Some(0), &sub, &sub_st)
            .err()
            .ok_or("producer socket-tree must fail")?;
        assert_eq!(
            prod_only.2,
            format!("directory is controlled by uid {euid} (the socket producer)")
        );
        assert_eq!(prod_only.3, 2);

        let prod_gw = check_node(&root_only, Some(0), &gw_tree, &gw_st)
            .err()
            .ok_or("gw producer socket-tree must fail")?;
        assert_eq!(
            prod_gw.2,
            format!(
                "group or other writable (other accounts with search permission may be able to \
                 create or replace sockets); directory is controlled by uid {euid} (the socket \
                 producer)"
            )
        );
    }

    // 9. P2-5: ENOTDIR preserves known stat metadata; suffix after trusted symlink does not blame link;
    //    sticky missing intermediate names the missing component.
    let notdir = walk_at(&ctx, &root, Path::new("/reg/child.sock"), 1)
        .err()
        .ok_or("reg/child.sock must fail")?;
    assert_eq!(notdir.1, Some((euid, 0o644)));
    assert!(notdir.2.contains("Not a directory"), "got: {}", notdir.2);

    let suffix_err = walk_at(&ctx, &root, Path::new("/link_good/later/pool.sock"), 1)
        .err()
        .ok_or("writable suffix after trusted link must fail")?;
    assert_eq!(suffix_err.0, later);
    assert_eq!(suffix_err.2, "group or other writable");

    let stky_miss = walk_at(&ctx, &root, Path::new("/sticky/missing_mid/leaf"), 3)
        .err()
        .ok_or("missing under sticky must fail")?;
    assert_eq!(
        stky_miss.2,
        "missing component 'missing_mid' under a parent where another account could create it, \
         and if it is created later the permissions it would inherit are not verified"
    );

    // 10. Small pass 3: every missing directory component across all directory roles (0 socket-tree,
    //     2 ACME, 3 rotating log) fails with W034 reason; fmt_os is injective.
    for role in [0_u8, 2, 3] {
        let m_mid = walk_at(&ctx, &root, Path::new("/good/new/sub"), role)
            .err()
            .ok_or("missing intermediate dir must fail")?;
        assert_eq!(m_mid.0, good.join("new"));
        assert_eq!(m_mid.1, None);
        assert_eq!(m_mid.2, miss_dir_reason);
        let m_leaf = walk_at(&ctx, &root, Path::new("/good/absent_leaf"), role)
            .err()
            .ok_or("missing leaf dir must fail")?;
        assert_eq!(m_leaf.0, good.join("absent_leaf"));
        assert_eq!(m_leaf.1, None);
        assert_eq!(m_leaf.2, miss_dir_reason);
    }

    assert_eq!(
        fmt_os(OsStr::from_bytes(b"/tmp/bad_\xff")),
        "/tmp/bad_\\xff"
    );
    assert_eq!(
        fmt_os(OsStr::from_bytes(b"/tmp/bad_\xfe")),
        "/tmp/bad_\\xfe"
    );
    assert_eq!(fmt_os(OsStr::new("/tmp/bad_\u{FFFD}")), "/tmp/bad_\u{FFFD}");
    assert_eq!(fmt_os(OsStr::new("/tmp/bad_\\xff")), "/tmp/bad_\\\\xff");
    assert_eq!(fmt_os(OsStr::new("/tmp/nl\ndir")), "/tmp/nl\\ndir");
    assert_eq!(fmt_os(OsStr::new("/tmp/nl\\ndir")), "/tmp/nl\\\\ndir");

    let _ = fs::remove_dir_all(&root);
    Ok(())
}

#[test]
fn walk_at_makes_zero_openat2_calls_under_seccomp_kill_thread() -> TestResult {
    use seccompiler::{SeccompAction, SeccompFilter, TargetArch};
    use std::collections::BTreeMap;

    const SYS_OPENAT2: i64 = 437;
    let root = make_tmpfs_root("no-openat2")?;
    let real_dir = root.join("real");
    let link_dir = root.join("link");
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

    let root_c = root.clone();
    let handle = std::thread::spawn(move || -> Result<(), String> {
        seccompiler::apply_filter(&bpf).map_err(|e| e.to_string())?;
        let ctx = Ctx(Some(euid), true, Some(65_534), true);
        walk_at(&ctx, &root_c, Path::new("/real"), 3).map_err(|f| f.2)?;
        walk_at(&ctx, &root_c, Path::new("/link"), 3).map_err(|f| f.2)?;
        walk_at(&ctx, &root_c, Path::new("/real/absent.sock"), 1).map_err(|f| f.2)?;
        if walk_at(&ctx, &root_c, Path::new("/real/absent"), 3).is_ok() {
            return Err("expected missing created log dir to return Err".to_owned());
        }
        walk_at(&ctx, &root_c, Path::new("/real/../real"), 3).map_err(|f| f.2)?;
        walk_at(&ctx, &root_c, Path::new("/real"), 0).map_err(|f| f.2)?;
        walk_at(&ctx, &root_c, Path::new("/real"), 2).map_err(|f| f.2)?;
        Ok(())
    });
    handle
        .join()
        .map_err(|_| "seccomp worker thread panicked or was killed by SIGSYS")?
        .map_err(|e| format!("walk_at failed under openat2 KillThread filter: {e}"))?;

    let _ = fs::remove_dir_all(&root);
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn ai_publish_storage_check_is_metadata_only_and_makes_no_writes() -> TestResult {
    use seccompiler::{
        SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule, TargetArch,
    };
    use std::collections::BTreeMap;

    let tmpfs_root = make_tmpfs_root("storage-meta-tmpfs")?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let root = PathBuf::from(format!(
        "/tmp/ms-tp-unit-storage-meta-{}-{nanos}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o750))?;

    let tmp_ro = tmpfs_root.join("ro_store");
    let tmp_wr = tmpfs_root.join("wr_store");
    let tmp_ro_parent = tmpfs_root.join("ro_parent");
    for d in [&tmp_ro, &tmp_wr, &tmp_ro_parent] {
        fs::create_dir_all(d)?;
        fs::set_permissions(d, fs::Permissions::from_mode(0o750))?;
    }
    fs::set_permissions(&tmp_ro, fs::Permissions::from_mode(0o550))?;
    fs::set_permissions(&tmp_ro_parent, fs::Permissions::from_mode(0o550))?;
    fs::set_permissions(&tmp_wr, fs::Permissions::from_mode(0o775))?;

    let ro_store = root.join("ro_store");
    let wr_store = root.join("wr_store");
    let ro_parent = root.join("ro_parent");
    let pub_key = root.join("deploy.pub");
    for d in [&ro_store, &wr_store, &ro_parent] {
        fs::create_dir_all(d)?;
        fs::set_permissions(d, fs::Permissions::from_mode(0o750))?;
    }
    fs::write(&pub_key, b"0123456789abcdef0123456789abcdef\n")?;
    fs::set_permissions(&pub_key, fs::Permissions::from_mode(0o640))?;
    // Make `ro_store` and `ro_parent` read+search only (0550) and `wr_store` writable (0775).
    fs::set_permissions(&ro_store, fs::Permissions::from_mode(0o550))?;
    fs::set_permissions(&ro_parent, fs::Permissions::from_mode(0o550))?;
    fs::set_permissions(&wr_store, fs::Permissions::from_mode(0o775))?;

    let absent_leaf = ro_parent.join("absent_leaf");
    let absent_mid = ro_parent.join("absent_mid").join("store");
    let cfg_path = root.join("meta.kdl");
    fs::write(
        &cfg_path,
        format!(
            "server {{ listen \":443\" }}\n\
             site \"s0.example\" {{\n\
                 ai-publish {{ storage \"{}\"; require-signature \"ed25519:{}\" }}\n\
             }}\n\
             site \"s1.example\" {{\n\
                 ai-publish {{ storage \"{}\"; require-signature \"ed25519:{}\" }}\n\
             }}\n\
             site \"s2.example\" {{\n\
                 ai-publish {{ storage \"{}\"; require-signature \"ed25519:{}\" }}\n\
             }}\n\
             site \"s3.example\" {{\n\
                 ai-publish {{ storage \"{}\"; require-signature \"ed25519:{}\" }}\n\
             }}\n",
            ro_store.display(),
            pub_key.display(),
            wr_store.display(),
            pub_key.display(),
            absent_leaf.display(),
            pub_key.display(),
            absent_mid.display(),
            pub_key.display(),
        ),
    )?;
    let mut loaded = miraserve_config::load_file_detailed(&cfg_path)?;
    // Also append a synthetic 5th site duplicating site[1]'s exact `wr_store` path (bypassing
    // `R5-PUB-5` load-time overlap rejection) to prove `trusted_paths::check` emits per-field
    // without deduplicating repeated stores.
    if let Some(dup_site) = loaded.config.sites.get(1).cloned() {
        loaded.config.sites.push(dup_site);
    }

    let stat_snap = |p: &Path| -> Result<_, std::io::Error> {
        let fd = op(CWD, p, OFlags::DIRECTORY | OFlags::NOFOLLOW).map_err(std::io::Error::from)?;
        let st = fstat(&fd).map_err(std::io::Error::from)?;
        Ok((
            st.st_mtime,
            st.st_mtime_nsec,
            st.st_ctime,
            st.st_ctime_nsec,
            st.st_nlink,
        ))
    };
    let ro_store_before = stat_snap(&ro_store)?;
    let ro_parent_before = stat_snap(&ro_parent)?;

    let root_fd = op(CWD, "/", OFlags::DIRECTORY)?;
    let root_sf = fstatfs(&root_fd)?;
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let root_magic = root_sf.f_type as u32;

    let arch = TargetArch::try_from(std::env::consts::ARCH)?;
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    let (openat_nr, mutating_nrs): (i64, &[i64]) = match arch {
        TargetArch::aarch64 | TargetArch::riscv64 => (56, &[34, 35, 38, 45, 46, 52, 53, 276, 437]),
        TargetArch::x86_64 => (
            257,
            &[
                2, 76, 77, 82, 83, 85, 87, 90, 91, 258, 263, 264, 268, 316, 437,
            ],
        ),
    };
    for &nr in mutating_nrs {
        rules.insert(nr, Vec::new());
        if arch == TargetArch::x86_64 {
            rules.insert(nr | 0x4000_0000, Vec::new());
        }
    }
    // Also kill on `openat` with O_WRONLY (1), O_RDWR (2), O_CREAT (0o100), or O_TRUNC (0o1000).
    let openat_write_rules = vec![
        SeccompRule::new(vec![SeccompCondition::new(
            2,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(0o3),
            1,
        )?])?,
        SeccompRule::new(vec![SeccompCondition::new(
            2,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(0o3),
            2,
        )?])?,
        SeccompRule::new(vec![SeccompCondition::new(
            2,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(0o100),
            0o100,
        )?])?,
        SeccompRule::new(vec![SeccompCondition::new(
            2,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(0o1000),
            0o1000,
        )?])?,
    ];
    rules.insert(openat_nr, openat_write_rules.clone());
    if arch == TargetArch::x86_64 {
        rules.insert(openat_nr | 0x4000_0000, openat_write_rules);
    }
    let bpf: seccompiler::BpfProgram =
        SeccompFilter::new(rules, SeccompAction::Allow, SeccompAction::KillThread, arch)?
            .try_into()?;

    let euid = rustix::process::geteuid().as_raw();
    let tmpfs_c = tmpfs_root.clone();
    let cfg_c = cfg_path.clone();
    let handle = std::thread::spawn(move || -> Result<(Vec<ConfigIssue>, Vec<String>), String> {
        seccompiler::apply_filter(&bpf).map_err(|e| e.to_string())?;
        // 1. Direct `walk_at` on tmpfs root (works even when host `/` is overlayfs).
        let ctx = Ctx(Some(euid), true, Some(65_534), true);
        walk_at(&ctx, &tmpfs_c, Path::new("/ro_store"), 3).map_err(|f| f.2)?;
        if walk_at(&ctx, &tmpfs_c, Path::new("/wr_store"), 3)
            .err()
            .is_none_or(|f| f.2 != "group or other writable")
        {
            return Err("expected group or other writable on /wr_store".to_owned());
        }
        if walk_at(&ctx, &tmpfs_c, Path::new("/ro_parent/absent_leaf"), 3)
            .err()
            .is_none_or(|f| !f.2.starts_with("not found; "))
        {
            return Err("expected not found on /ro_parent/absent_leaf".to_owned());
        }
        // 2. Direct `trusted_paths::check` (bypassing `check_writable_dir` probe!).
        let args = CheckArgs {
            config: cfg_c,
            strict: false,
            allow_warning: Vec::new(),
            format: crate::check::OutputFormat::Text,
            dump_normalized: false,
            quiet: false,
            dev_tls: false,
            fs: true,
            trusted_paths: true,
            acme_dir: None,
            keyd_auth_secret_file: None,
            log_file: None,
            access_log: None,
            log_max_bytes: 0,
            no_sandbox: false,
            writable_set: false,
        };
        let mut issues = Vec::new();
        let notes = check(&mut issues, &loaded, &args);
        Ok((issues, notes))
    });
    let (issues, notes) = handle
        .join()
        .map_err(|_| "seccomp worker thread panicked or was killed by SIGSYS")?
        .map_err(|e| format!("metadata-only storage check failed under seccomp: {e}"))?;

    // Directory contents and timestamps/nlink must be completely untouched.
    assert_eq!(fs::read_dir(&ro_store)?.count(), 0);
    assert_eq!(fs::read_dir(&ro_parent)?.count(), 0);
    assert_eq!(stat_snap(&ro_store)?, ro_store_before);
    assert_eq!(stat_snap(&ro_parent)?, ro_parent_before);
    assert_eq!(
        notes.len(),
        2,
        "expected observer + narrowed notes only: {notes:?}"
    );

    // Assert the single exact deterministic result for the actual `/` filesystem.
    if is_local_posix_fs(root_magic) {
        let paths: Vec<Option<&str>> = issues.iter().map(|i| i.path.as_deref()).collect();
        assert_eq!(
            paths,
            vec![
                Some("site[1].ai-publish.storage"),
                Some("site[2].ai-publish.storage"),
                Some("site[3].ai-publish.storage"),
                Some("site[4].ai-publish.storage"),
            ],
            "expected W034 on wr_store + absent_leaf + absent_mid + dup wr_store (and 0 on 0550 ro_store): {issues:#?}"
        );
    } else {
        let paths: Vec<Option<&str>> = issues.iter().map(|i| i.path.as_deref()).collect();
        assert_eq!(
            paths,
            vec![
                Some("site[0].ai-publish.storage"),
                Some("site[1].ai-publish.storage"),
                Some("site[2].ai-publish.storage"),
                Some("site[3].ai-publish.storage"),
                Some("site[4].ai-publish.storage"),
            ],
            "expected W034 for all 5 sites on unsupported root fs 0x{root_magic:x}: {issues:#?}"
        );
        let expected_fs_frag = format!("(filesystem 0x{root_magic:x})");
        for issue in &issues {
            assert!(
                issue.message.contains(&expected_fs_frag),
                "expected {expected_fs_frag} in {}",
                issue.message
            );
        }
    }

    // Restore writable mode before cleanup.
    let _ = fs::set_permissions(&ro_store, fs::Permissions::from_mode(0o750));
    let _ = fs::set_permissions(&ro_parent, fs::Permissions::from_mode(0o750));
    let _ = fs::set_permissions(&tmp_ro, fs::Permissions::from_mode(0o750));
    let _ = fs::set_permissions(&tmp_ro_parent, fs::Permissions::from_mode(0o750));
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&tmpfs_root);
    Ok(())
}

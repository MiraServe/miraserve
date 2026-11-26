//! Live-kernel Linux integration tests for MiraServe's in-process set-ID seccomp-bpf policy
//! (scalar mode-bit rules, `O_PATH` exclusion, `io_uring` denial in both `Standard` and `Strict`,
//! `openat2` probe semantics, and `openat2` residual mode bits).
//!
//! Kept in its own integration-test binary (separate from `sandbox_tests.rs`, which calls
//! process-wide `apply_sandbox` with `SECCOMP_FILTER_FLAG_TSYNC` in `Strict` mode and would block
//! `execve` for sibling tests in the same process). Every test here installs seccomp only on a
//! dedicated OS thread or isolated child process.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use miraserve_config::{SeccompMode, parse_kdl};

#[path = "../../miraserve-config/tests/common/mod.rs"]
mod kdl_test_util;

use kdl_test_util::kdl_escape_path;
use miraserve_sandbox::{
    EnforcementStatus, SandboxError, SandboxPolicy, apply_landlock_current_thread,
    apply_seccomp_current_thread, compile_seccomp_bpf_bytes_for_host, probe_openat2_refused,
};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SYS_OPENAT2: i64 = 437;

fn temp_base(tag: &str) -> Result<PathBuf, std::io::Error> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let path = std::env::temp_dir().join(format!(
        "miraserve-seccomp-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn find_python3() -> Option<&'static str> {
    ["/usr/bin/python3", "/usr/local/bin/python3", "python3"]
        .into_iter()
        .find(|bin| {
            Command::new(bin)
                .arg("--version")
                .output()
                .is_ok_and(|o| o.status.success())
        })
}

fn proc_thread_seccomp_filters() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/thread-self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Seccomp_filters:") {
            return rest.trim().parse::<u32>().ok();
        }
    }
    None
}

fn bpf_to_bytes(bpf: &BpfProgram) -> Vec<u8> {
    let mut out = Vec::with_capacity(bpf.len() * 8);
    for insn in bpf {
        out.extend_from_slice(&insn.code.to_ne_bytes());
        out.push(insn.jt);
        out.push(insn.jf);
        out.extend_from_slice(&insn.k.to_ne_bytes());
    }
    out
}

fn compile_openat2_action_filter(action: SeccompAction) -> Result<BpfProgram, String> {
    let arch = TargetArch::try_from(std::env::consts::ARCH).map_err(|e| e.to_string())?;
    let mut rules = BTreeMap::new();
    rules.insert(SYS_OPENAT2, Vec::new());
    if arch == TargetArch::x86_64 {
        rules.insert(SYS_OPENAT2 | 0x4000_0000, Vec::new());
    }
    SeccompFilter::new(rules, SeccompAction::Allow, action, arch)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|e: seccompiler::BackendError| e.to_string())
}

/// Verifies that `SeccompMode::Off` installs no seccomp filter at all (neither the dangerous
/// syscall denylist nor the in-process set-ID policy) and does not add a seccomp filter layer.
#[test]
fn seccomp_mode_off_installs_no_setid_filter() -> TestResult {
    use rustix::fs::{CWD, Mode, OFlags, fchmod, fstat, openat};

    let base = temp_base("mode-off")?;
    let path = base.join("plain.txt");
    std::fs::write(&path, b"off")?;

    let path_for_thread = path.clone();
    let res = std::thread::spawn(move || -> Result<(), String> {
        let filters_before = proc_thread_seccomp_filters();
        let status = apply_seccomp_current_thread(SeccompMode::Off).map_err(|e| e.to_string())?;
        if status != EnforcementStatus::Disabled {
            return Err(format!("expected Disabled for Off, got {status:?}"));
        }
        let filters_after = proc_thread_seccomp_filters();
        if filters_before != filters_after {
            return Err(format!(
                "SeccompMode::Off unexpectedly changed Seccomp_filters on tested thread: {filters_before:?} -> {filters_after:?}"
            ));
        }
        let fd = openat(
            CWD,
            &path_for_thread,
            OFlags::RDWR | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| format!("open failed: {e}"))?;
        // Without a set-ID filter, fchmod with S_ISUID must succeed and set S_ISUID.
        fchmod(&fd, Mode::from_raw_mode(0o4644))
            .map_err(|e| format!("fchmod with S_ISUID failed under SeccompMode::Off: {e}"))?;
        let st = fstat(&fd).map_err(|e| format!("fstat failed: {e}"))?;
        if (st.st_mode & 0o4000) != 0o4000 {
            return Err(format!(
                "expected S_ISUID bit set under SeccompMode::Off, got mode {:o}",
                st.st_mode & 0o7777
            ));
        }
        let _ = fchmod(&fd, Mode::from_raw_mode(0o644));
        Ok(())
    })
    .join()
    .map_err(|_| "mode-off thread panicked")?;

    let _ = std::fs::remove_dir_all(&base);
    res.map_err(|msg| -> Box<dyn std::error::Error> { msg.into() })
}

fn verify_chmod_and_dir_rules(
    dir_fd: &rustix::fd::OwnedFd,
    ok_file: rustix::fs::Mode,
    ok_dir: rustix::fs::Mode,
    user_setid: rustix::fs::Mode,
    group_setid: rustix::fs::Mode,
    both_setid: rustix::fs::Mode,
) -> Result<(), String> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags, chmodat, fchmod, mkdirat, mknodat, openat};
    use rustix::io::Errno;

    let target_fd = openat(
        dir_fd,
        "existing.txt",
        OFlags::RDWR | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| format!("open existing.txt failed: {e}"))?;
    fchmod(&target_fd, ok_file).map_err(|e| format!("fchmod 0644 failed: {e}"))?;
    chmodat(dir_fd, "existing.txt", ok_file, AtFlags::empty())
        .map_err(|e| format!("fchmodat 0644 failed: {e}"))?;
    for bad in [user_setid, group_setid, both_setid] {
        if fchmod(&target_fd, bad) != Err(Errno::PERM) {
            return Err(format!("fchmod({bad:?}) did not return EPERM"));
        }
        if chmodat(dir_fd, "existing.txt", bad, AtFlags::empty()) != Err(Errno::PERM) {
            return Err(format!("fchmodat({bad:?}) did not return EPERM"));
        }
    }

    mkdirat(dir_fd, "dir_ok", ok_dir).map_err(|e| format!("mkdirat 0755 failed: {e}"))?;
    mknodat(dir_fd, "mknod_ok", FileType::RegularFile, ok_file, 0)
        .map_err(|e| format!("mknodat 0644 failed: {e}"))?;
    for (suffix, bad) in [("suid", user_setid), ("sgid", group_setid)] {
        if mkdirat(dir_fd, format!("dir_{suffix}"), bad) != Err(Errno::PERM) {
            return Err(format!("mkdirat({suffix}) did not return EPERM"));
        }
        if mknodat(
            dir_fd,
            format!("mknod_{suffix}"),
            FileType::RegularFile,
            bad,
            0,
        ) != Err(Errno::PERM)
        {
            return Err(format!("mknodat({suffix}) did not return EPERM"));
        }
    }
    Ok(())
}

fn verify_openat2_and_strict_exec_rules(
    mode: SeccompMode,
    dir_fd: &rustix::fd::OwnedFd,
    both_setid: rustix::fs::Mode,
) -> Result<(), String> {
    use rustix::fs::{Mode, OFlags, ResolveFlags, fstat, openat2};
    use rustix::io::Errno;

    let _ = openat2(
        dir_fd,
        "existing.txt",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|e| format!("openat2(O_RDONLY) failed: {e}"))?;

    let residual_fd = openat2(
        dir_fd,
        "openat2_residual_suid",
        OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC,
        both_setid,
        ResolveFlags::BENEATH,
    )
    .map_err(|e| format!("openat2(O_CREAT, S_ISUID|S_ISGID) residual open failed: {e}"))?;
    let residual_st =
        fstat(&residual_fd).map_err(|e| format!("fstat residual file failed: {e}"))?;
    if (residual_st.st_mode & 0o6000) != 0o6000 {
        return Err(format!(
            "openat2 residual file did not retain S_ISUID|S_ISGID bits: mode={:04o}",
            residual_st.st_mode & 0o7777
        ));
    }

    if mode == SeccompMode::Strict {
        let exec_err = Command::new("/bin/true")
            .status()
            .err()
            .ok_or_else(|| "execve must be denied in SeccompMode::Strict".to_owned())?;
        if exec_err.raw_os_error() != Some(Errno::PERM.raw_os_error()) {
            return Err(format!(
                "expected EPERM from execve in Strict mode, got: {exec_err}"
            ));
        }
    }
    Ok(())
}

fn verify_scalar_setid_rules_in_mode(
    mode: SeccompMode,
    work: &std::path::Path,
    existing: &std::path::Path,
) -> Result<(), String> {
    use rustix::fs::{CWD, Mode, OFlags, openat};
    use rustix::io::Errno;

    let status = apply_seccomp_current_thread(mode).map_err(|e| e.to_string())?;
    if status != EnforcementStatus::Enforced {
        return Err(format!("expected Enforced for {mode:?}, got {status:?}"));
    }
    if let Some(err) = probe_openat2_refused() {
        return Err(format!(
            "probe_openat2_refused unexpectedly reported: {err}"
        ));
    }

    let dir_fd = openat(
        CWD,
        work,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| format!("open work dir failed: {e}"))?;

    let ok_file = Mode::from_raw_mode(0o644);
    let ok_dir = Mode::from_raw_mode(0o755);
    let user_setid = Mode::from_raw_mode(0o4644);
    let group_setid = Mode::from_raw_mode(0o2644);
    let both_setid = Mode::from_raw_mode(0o6644);

    verify_chmod_and_dir_rules(
        &dir_fd,
        ok_file,
        ok_dir,
        user_setid,
        group_setid,
        both_setid,
    )?;

    let _ = openat(
        &dir_fd,
        "creat_ok",
        OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC,
        ok_file,
    )
    .map_err(|e| format!("openat(O_CREAT, 0644) failed: {e}"))?;
    match openat(
        &dir_fd,
        ".",
        OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
        ok_file,
    ) {
        Ok(_) | Err(Errno::OPNOTSUPP) => {}
        Err(e) => return Err(format!("openat(O_TMPFILE, 0644) unexpected error: {e}")),
    }
    for (suffix, bad) in [("suid", user_setid), ("sgid", group_setid)] {
        if openat(
            &dir_fd,
            format!("creat_{suffix}"),
            OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC,
            bad,
        )
        .err()
            != Some(Errno::PERM)
        {
            return Err(format!("openat(O_CREAT, {suffix}) did not return EPERM"));
        }
        if openat(
            &dir_fd,
            ".",
            OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
            bad,
        )
        .err()
            != Some(Errno::PERM)
        {
            return Err(format!("openat(O_TMPFILE, {suffix}) did not return EPERM"));
        }
    }
    let _ = openat(CWD, existing, OFlags::RDONLY | OFlags::CLOEXEC, both_setid)
        .map_err(|e| format!("openat(O_RDONLY, stale set-ID mode) failed: {e}"))?;
    let _ = openat(
        CWD,
        existing,
        OFlags::PATH | OFlags::CREATE | OFlags::CLOEXEC,
        both_setid,
    )
    .map_err(|e| format!("openat(O_PATH | O_CREAT, set-ID mode) failed: {e}"))?;

    verify_openat2_and_strict_exec_rules(mode, &dir_fd, both_setid)
}

/// Verifies MiraServe's in-process set-ID seccomp-bpf filter directly against the kernel in both
/// `SeccompMode::Standard` and `SeccompMode::Strict` on isolated threads (without `TSYNC`),
/// including `O_PATH` exclusion and checking the actual `S_ISUID | S_ISGID` mode bits on the
/// `openat2(O_CREAT)` residual file.
#[test]
fn setid_seccomp_filter_enforced_by_kernel_in_standard_and_strict_modes() -> TestResult {
    let base = temp_base("setid-seccomp")?;

    for mode in [SeccompMode::Standard, SeccompMode::Strict] {
        let work = base.join(format!("{mode:?}"));
        std::fs::create_dir_all(&work)?;
        let existing = work.join("existing.txt");
        std::fs::write(&existing, b"hello")?;

        let work_t = work.clone();
        let existing_t = existing.clone();
        let res = std::thread::spawn(move || {
            verify_scalar_setid_rules_in_mode(mode, &work_t, &existing_t)
        })
        .join()
        .map_err(|_| "seccomp test thread panicked")?;

        res.map_err(|msg| -> Box<dyn std::error::Error> { msg.into() })?;
    }

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

const RAW_SYSCALL_SCRIPT: &str = r#"
import ctypes, errno, os, platform, struct, sys

work = sys.argv[1].encode()
arch = platform.machine()
libc = ctypes.CDLL(None, use_errno=True)
syscall = libc.syscall
syscall.restype = ctypes.c_long

O_RDONLY = 0
O_RDWR = 2
O_CREAT = 0o100
O_PATH = 0o10000000
S_IFREG = 0o100000
IPC_PRIVATE = 0
IPC_CREAT = 0o1000
IPC_EXCL = 0o2000

if arch == "x86_64":
    O_TMPFILE = 0o20200000
    NR = dict(
        open=2, shmget=29, semget=64, msgget=68, mkdir=83, creat=85,
        chmod=90, fchmod=91, mknod=133, mq_open=240, mq_unlink=241,
        openat=257, mkdirat=258, mknodat=259, fchmodat=268,
        io_uring_setup=425, io_uring_enter=426, io_uring_register=427,
        openat2=437, fchmodat2=452,
        msgctl=71, semctl=66, shmctl=31,
    )
elif arch == "aarch64":
    O_TMPFILE = 0o20040000
    NR = dict(
        mknodat=33, mkdirat=34, fchmod=52, fchmodat=53, openat=56,
        mq_open=180, mq_unlink=181, msgget=186, msgctl=187,
        semget=190, semctl=191, shmget=194, shmctl=195,
        io_uring_setup=425, io_uring_enter=426, io_uring_register=427,
        openat2=437, fchmodat2=452,
    )
elif arch == "riscv64":
    print(f"SKIP:{arch}")
    sys.exit(0)
else:
    print(f"SKIP:{arch}")
    sys.exit(0)

def fail(msg):
    sys.stderr.write(msg + "\n")
    sys.exit(1)

def call(nr, *args):
    ctypes.set_errno(0)
    cargs = [ctypes.c_long(a) if isinstance(a, int) else a for a in args]
    ret = syscall(ctypes.c_long(nr), *cargs)
    return ret, ctypes.get_errno()

def expect_eperm(label, nr, *args):
    ret, err = call(nr, *args)
    if ret != -1 or err != errno.EPERM:
        fail(f"{label}: expected EPERM, got ret={ret} errno={err}")

def expect_ok(label, nr, *args, close_fd=False):
    ret, err = call(nr, *args)
    if ret < 0:
        fail(f"{label}: expected success, got ret={ret} errno={err}")
    if close_fd:
        os.close(ret)
    return ret

def expect_ok_or_errno(label, allowed_errnos, nr, *args, close_fd=False):
    ret, err = call(nr, *args)
    if ret < 0 and err not in allowed_errnos:
        fail(f"{label}: expected success or {allowed_errnos}, got ret={ret} errno={err}")
    if close_fd and ret >= 0:
        os.close(ret)
    return ret, err

def expect_errno(label, allowed_errnos, nr, *args):
    ret, err = call(nr, *args)
    if ret != -1 or err not in allowed_errnos:
        fail(f"{label}: expected errno in {allowed_errnos}, got ret={ret} errno={err}")

existing_p = ctypes.c_char_p(os.path.join(work, b"existing.txt"))
dir_fd = os.open(work, os.O_RDONLY | os.O_DIRECTORY)
f_fd = os.open(os.path.join(work, b"existing.txt"), os.O_RDWR)

# io_uring is denied in Standard mode as part of the set-ID policy.
expect_eperm("io_uring_setup", NR["io_uring_setup"], 0, 0)
expect_eperm("io_uring_enter", NR["io_uring_enter"], -1, 0, 0, 0, 0, 0)
expect_eperm("io_uring_register", NR["io_uring_register"], -1, 0, 0, 0)

# fchmod / fchmodat / fchmodat2
expect_ok("fchmod 0644", NR["fchmod"], f_fd, 0o644)
expect_eperm("fchmod S_ISUID", NR["fchmod"], f_fd, 0o4644)
expect_eperm("fchmod S_ISGID", NR["fchmod"], f_fd, 0o2644)

expect_ok("fchmodat 0644", NR["fchmodat"], dir_fd, ctypes.c_char_p(b"existing.txt"), 0o644)
expect_eperm("fchmodat S_ISUID", NR["fchmodat"], dir_fd, ctypes.c_char_p(b"existing.txt"), 0o4644)
expect_eperm("fchmodat S_ISGID", NR["fchmodat"], dir_fd, ctypes.c_char_p(b"existing.txt"), 0o2644)

expect_ok_or_errno("fchmodat2 0644", (errno.ENOSYS,), NR["fchmodat2"], dir_fd, ctypes.c_char_p(b"existing.txt"), 0o644, 0)
expect_eperm("fchmodat2 S_ISUID", NR["fchmodat2"], dir_fd, ctypes.c_char_p(b"existing.txt"), 0o4644, 0)
expect_eperm("fchmodat2 S_ISGID", NR["fchmodat2"], dir_fd, ctypes.c_char_p(b"existing.txt"), 0o2644, 0)

# mkdirat / mknodat
expect_ok("mkdirat 0755", NR["mkdirat"], dir_fd, ctypes.c_char_p(b"py_dir_ok"), 0o755)
expect_eperm("mkdirat S_ISUID", NR["mkdirat"], dir_fd, ctypes.c_char_p(b"py_dir_suid"), 0o4755)
expect_eperm("mkdirat S_ISGID", NR["mkdirat"], dir_fd, ctypes.c_char_p(b"py_dir_sgid"), 0o2755)

expect_ok("mknodat 0644", NR["mknodat"], dir_fd, ctypes.c_char_p(b"py_mknod_ok"), S_IFREG | 0o644, 0)
expect_eperm("mknodat S_ISUID", NR["mknodat"], dir_fd, ctypes.c_char_p(b"py_mknod_suid"), S_IFREG | 0o4644, 0)
expect_eperm("mknodat S_ISGID", NR["mknodat"], dir_fd, ctypes.c_char_p(b"py_mknod_sgid"), S_IFREG | 0o2644, 0)

# openat (O_CREAT, O_TMPFILE, O_RDONLY, O_PATH|O_CREAT)
expect_ok("openat O_CREAT 0644", NR["openat"], dir_fd, ctypes.c_char_p(b"py_openat_ok"), O_CREAT | O_RDWR, 0o644, close_fd=True)
expect_eperm("openat O_CREAT S_ISUID", NR["openat"], dir_fd, ctypes.c_char_p(b"py_openat_suid"), O_CREAT | O_RDWR, 0o4644)
expect_eperm("openat O_CREAT S_ISGID", NR["openat"], dir_fd, ctypes.c_char_p(b"py_openat_sgid"), O_CREAT | O_RDWR, 0o2644)
expect_ok_or_errno("openat O_TMPFILE 0644", (errno.EOPNOTSUPP,), NR["openat"], dir_fd, ctypes.c_char_p(b"."), O_TMPFILE | O_RDWR, 0o644, close_fd=True)
expect_eperm("openat O_TMPFILE S_ISUID", NR["openat"], dir_fd, ctypes.c_char_p(b"."), O_TMPFILE | O_RDWR, 0o4644)
expect_eperm("openat O_TMPFILE S_ISGID", NR["openat"], dir_fd, ctypes.c_char_p(b"."), O_TMPFILE | O_RDWR, 0o2644)
expect_ok("openat O_RDONLY stale setid", NR["openat"], dir_fd, ctypes.c_char_p(b"existing.txt"), O_RDONLY, 0o6755, close_fd=True)
expect_ok("openat O_PATH|O_CREAT setid", NR["openat"], dir_fd, ctypes.c_char_p(b"existing.txt"), O_PATH | O_CREAT, 0o6755, close_fd=True)

# mq_open (O_CREAT with/without set-ID; O_RDONLY on missing queue -> ENOENT or ENOSYS)
mq_name = ctypes.c_char_p(f"miraserve_seccomp_test_{os.getpid()}".encode())
expect_eperm("mq_open O_CREAT S_ISUID", NR["mq_open"], mq_name, O_CREAT | O_RDWR, 0o4600, 0)
expect_eperm("mq_open O_CREAT S_ISGID", NR["mq_open"], mq_name, O_CREAT | O_RDWR, 0o2600, 0)
expect_errno("mq_open O_RDONLY missing", (errno.ENOENT, errno.ENOSYS), NR["mq_open"], mq_name, O_RDONLY, 0o6600, 0)
ret, _ = expect_ok_or_errno("mq_open O_CREAT 0600", (errno.ENOSYS,), NR["mq_open"], mq_name, O_CREAT | O_RDWR, 0o600, 0, close_fd=True)
if ret >= 0:
    call(NR["mq_unlink"], mq_name)

# SysV IPC (msgget/semget/shmget): IPC_EXCL (0o2000) collides with S_ISGID and must succeed.
r_msg, _ = expect_ok_or_errno("msgget IPC_CREAT|IPC_EXCL", (errno.ENOSYS,), NR["msgget"], IPC_PRIVATE, IPC_CREAT | IPC_EXCL | 0o600)
if r_msg >= 0:
    call(NR["msgctl"], r_msg, 0, 0)
r_sem, _ = expect_ok_or_errno("semget IPC_CREAT|IPC_EXCL", (errno.ENOSYS,), NR["semget"], IPC_PRIVATE, 1, IPC_CREAT | IPC_EXCL | 0o600)
if r_sem >= 0:
    call(NR["semctl"], r_sem, 0, 0)
r_shm, _ = expect_ok_or_errno("shmget IPC_CREAT|IPC_EXCL", (errno.ENOSYS,), NR["shmget"], IPC_PRIVATE, 4096, IPC_CREAT | IPC_EXCL | 0o600)
if r_shm >= 0:
    call(NR["shmctl"], r_shm, 0, 0)

# openat2: read-only works; O_CREAT + set-ID succeeds AND retains S_ISUID|S_ISGID (documented residual).
how_ro = ctypes.create_string_buffer(struct.pack("<QQQ", O_RDONLY, 0, 0x08))
fd_ro = expect_ok("openat2 O_RDONLY", NR["openat2"], dir_fd, ctypes.c_char_p(b"existing.txt"), ctypes.byref(how_ro), 24)
os.close(fd_ro)
how_suid = ctypes.create_string_buffer(struct.pack("<QQQ", O_CREAT | O_RDWR, 0o6644, 0x08))
fd_suid = expect_ok("openat2 O_CREAT set-ID", NR["openat2"], dir_fd, ctypes.c_char_p(b"py_openat2_suid"), ctypes.byref(how_suid), 24)
st_suid = os.fstat(fd_suid)
os.close(fd_suid)
if (st_suid.st_mode & 0o6000) != 0o6000:
    fail(f"expected S_ISUID|S_ISGID on openat2 residual file, got {st_suid.st_mode:o}")

# x86_64 legacy non-*at syscalls
if arch == "x86_64":
    expect_ok("chmod 0644", NR["chmod"], existing_p, 0o644)
    expect_eperm("chmod S_ISUID", NR["chmod"], existing_p, 0o4644)
    expect_eperm("chmod S_ISGID", NR["chmod"], existing_p, 0o2644)

    expect_ok("mkdir 0755", NR["mkdir"], ctypes.c_char_p(os.path.join(work, b"py_leg_dir_ok")), 0o755)
    expect_eperm("mkdir S_ISUID", NR["mkdir"], ctypes.c_char_p(os.path.join(work, b"py_leg_dir_suid")), 0o4755)
    expect_eperm("mkdir S_ISGID", NR["mkdir"], ctypes.c_char_p(os.path.join(work, b"py_leg_dir_sgid")), 0o2755)

    expect_ok("mknod 0644", NR["mknod"], ctypes.c_char_p(os.path.join(work, b"py_leg_mknod_ok")), S_IFREG | 0o644, 0)
    expect_eperm("mknod S_ISUID", NR["mknod"], ctypes.c_char_p(os.path.join(work, b"py_leg_mknod_suid")), S_IFREG | 0o4644, 0)
    expect_eperm("mknod S_ISGID", NR["mknod"], ctypes.c_char_p(os.path.join(work, b"py_leg_mknod_sgid")), S_IFREG | 0o2644, 0)

    expect_ok("creat 0644", NR["creat"], ctypes.c_char_p(os.path.join(work, b"py_leg_creat_ok")), 0o644, close_fd=True)
    expect_eperm("creat S_ISUID", NR["creat"], ctypes.c_char_p(os.path.join(work, b"py_leg_creat_suid")), 0o4644)
    expect_eperm("creat S_ISGID", NR["creat"], ctypes.c_char_p(os.path.join(work, b"py_leg_creat_sgid")), 0o2644)

    expect_ok("open O_CREAT 0644", NR["open"], ctypes.c_char_p(os.path.join(work, b"py_leg_open_ok")), O_CREAT | O_RDWR, 0o644, close_fd=True)
    expect_eperm("open O_CREAT S_ISUID", NR["open"], ctypes.c_char_p(os.path.join(work, b"py_leg_open_suid")), O_CREAT | O_RDWR, 0o4644)
    expect_eperm("open O_CREAT S_ISGID", NR["open"], ctypes.c_char_p(os.path.join(work, b"py_leg_open_sgid")), O_CREAT | O_RDWR, 0o2644)
    expect_ok_or_errno("open O_TMPFILE 0644", (errno.EOPNOTSUPP,), NR["open"], ctypes.c_char_p(work), O_TMPFILE | O_RDWR, 0o644, close_fd=True)
    expect_eperm("open O_TMPFILE S_ISUID", NR["open"], ctypes.c_char_p(work), O_TMPFILE | O_RDWR, 0o4644)
    expect_eperm("open O_TMPFILE S_ISGID", NR["open"], ctypes.c_char_p(work), O_TMPFILE | O_RDWR, 0o2644)
    expect_ok("open O_RDONLY stale setid", NR["open"], existing_p, O_RDONLY, 0o6755, close_fd=True)
    expect_ok("open O_PATH|O_CREAT setid", NR["open"], existing_p, O_PATH | O_CREAT, 0o6755, close_fd=True)

os.close(f_fd)
os.close(dir_fd)
print(f"OK:{arch}")
"#;

/// Exercises EVERY raw syscall covered by (or explicitly excluded from) MiraServe's set-ID
/// seccomp-bpf policy on `x86_64` and `aarch64` (cleanly skipped on `riscv64`), asserting exact
/// expected outcomes, `O_PATH` exclusion, `io_uring` denial in `Standard`, and set-ID mode bits
/// on the `openat2` residual file.
#[test]
fn setid_seccomp_filter_enforced_for_all_arch_raw_syscalls() -> TestResult {
    if cfg!(target_arch = "riscv64") {
        return Ok(());
    }
    let Some(python_bin) = find_python3() else {
        if std::env::var_os("MIRASERVE_REQUIRE_RAW_SYSCALL_PROBE").is_some() {
            return Err(
                "python3 is required when MIRASERVE_REQUIRE_RAW_SYSCALL_PROBE is set".into(),
            );
        }
        return Ok(());
    };

    let base = temp_base("setid-raw-syscalls")?;
    std::fs::write(base.join("existing.txt"), b"raw")?;

    let base_t = base.clone();
    let py = python_bin.to_owned();
    let res = std::thread::spawn(move || -> Result<String, String> {
        let status =
            apply_seccomp_current_thread(SeccompMode::Standard).map_err(|e| e.to_string())?;
        if status != EnforcementStatus::Enforced {
            return Err(format!("expected Enforced, got {status:?}"));
        }
        let out = Command::new(&py)
            .args(["-c", RAW_SYSCALL_SCRIPT])
            .arg(&base_t)
            .output()
            .map_err(|e| format!("failed to run python3 raw syscall probe: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "raw syscall probe failed (status={}): stdout={} stderr={}",
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    })
    .join()
    .map_err(|_| "raw syscall seccomp thread panicked")?
    .map_err(|msg| -> Box<dyn std::error::Error> { msg.into() })?;

    assert!(
        res.contains("OK:") || res.contains("SKIP:"),
        "unexpected probe output: {res}"
    );
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

const STRICT_IO_URING_SCRIPT: &str = r#"
import ctypes, errno, platform, sys

def fail(msg):
    sys.stderr.write(msg + "\n")
    sys.exit(1)

bpf = sys.stdin.buffer.read()
if len(bpf) == 0 or len(bpf) % 8 != 0:
    fail(f"bad bpf len {len(bpf)}")
buf = ctypes.create_string_buffer(bpf, len(bpf))
class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]
fprog = SockFprog(len(bpf) // 8, ctypes.addressof(buf))

libc = ctypes.CDLL(None, use_errno=True)
ctypes.set_errno(0)
if libc.prctl(38, 1, 0, 0, 0) != 0:
    fail(f"PR_SET_NO_NEW_PRIVS failed: {ctypes.get_errno()}")
ctypes.set_errno(0)
if libc.prctl(22, 2, ctypes.byref(fprog), 0, 0) != 0:
    fail(f"PR_SET_SECCOMP failed: {ctypes.get_errno()}")

sc = libc.syscall
sc.restype = ctypes.c_long
def call(nr, *args):
    ctypes.set_errno(0)
    ret = sc(ctypes.c_long(nr), *[ctypes.c_long(a) if isinstance(a, int) else a for a in args])
    return ret, ctypes.get_errno()

for label, args in [
    ("io_uring_setup", (425, 0, 0)),
    ("io_uring_enter", (426, -1, 0, 0, 0, 0, 0)),
    ("io_uring_register", (427, -1, 0, 0, 0)),
]:
    ret, err = call(*args)
    if ret != -1 or err != errno.EPERM:
        fail(f"Strict {label}: expected EPERM, got ret={ret} errno={err}")

exec_nr = 59 if platform.machine() == "x86_64" else 221
ret, err = call(exec_nr, ctypes.c_char_p(b"/bin/true"), 0, 0)
if ret != -1 or err != errno.EPERM:
    fail(f"Strict execve: expected EPERM, got ret={ret} errno={err}")
print("STRICT_OK", flush=True)
"#;

const PROBE_IO_URING_SCRIPT: &str = r#"
import ctypes

libc = ctypes.CDLL(None, use_errno=True)
sc = libc.syscall
sc.restype = ctypes.c_long
def call(nr, *args):
    ctypes.set_errno(0)
    ret = sc(ctypes.c_long(nr), *[ctypes.c_long(a) for a in args])
    return ret, ctypes.get_errno()

r1, e1 = call(425, 0, 0)
r2, e2 = call(426, -1, 0, 0, 0, 0, 0)
r3, e3 = call(427, -1, 0, 0, 0)
print(f"RESULT:{r1},{e1},{r2},{e2},{r3},{e3}", flush=True)
print("PROBE_OK", flush=True)
"#;

const KILL_THREAD_OPENAT2_SCRIPT: &str = r#"
import ctypes, os, sys, threading, time

def fail(msg):
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()
    os._exit(1)

bpf = sys.stdin.buffer.read()
if len(bpf) == 0 or len(bpf) % 8 != 0:
    fail(f"bad bpf len {len(bpf)}")
buf = ctypes.create_string_buffer(bpf, len(bpf))
class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]
fprog = SockFprog(len(bpf) // 8, ctypes.addressof(buf))
libc = ctypes.CDLL(None, use_errno=True)

tid_box = []
setup_err = []
ready = threading.Event()

def victim():
    tid_box.append(threading.get_native_id())
    ctypes.set_errno(0)
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        setup_err.append(f"PR_SET_NO_NEW_PRIVS failed: {ctypes.get_errno()}")
        ready.set()
        return
    ctypes.set_errno(0)
    if libc.prctl(22, 2, ctypes.byref(fprog), 0, 0) != 0:
        setup_err.append(f"PR_SET_SECCOMP failed: {ctypes.get_errno()}")
        ready.set()
        return
    ready.set()
    how = ctypes.create_string_buffer(24)
    libc.syscall(
        ctypes.c_long(437),
        ctypes.c_long(-100),
        ctypes.c_char_p(b""),
        ctypes.byref(how),
        ctypes.c_long(24),
    )
    print("UNEXPECTED_RETURN", flush=True)

t = threading.Thread(target=victim, daemon=True)
t.start()
if not ready.wait(5.0):
    fail("victim thread did not finish setup")
if setup_err:
    fail(setup_err[0])
tid = tid_box[0]
task_dir = f"/proc/self/task/{tid}"
for _ in range(200):
    if not os.path.exists(task_dir):
        print(f"KILL_THREAD_MAIN_ALIVE:{tid}", flush=True)
        os._exit(0)
    time.sleep(0.01)
fail(f"victim thread {tid} still present at {task_dir}")
"#;

fn run_io_uring_probe(python_bin: &str) -> Result<String, String> {
    let out = Command::new(python_bin)
        .args(["-c", PROBE_IO_URING_SCRIPT])
        .output()
        .map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() || !stdout.lines().any(|l| l.trim() == "PROBE_OK") {
        return Err(format!(
            "io_uring probe failed (status={}): stdout={stdout} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr),
        ));
    }
    stdout
        .lines()
        .find(|l| l.starts_with("RESULT:"))
        .map(str::to_owned)
        .ok_or_else(|| format!("io_uring probe missing RESULT line: {stdout}"))
}

/// Live-kernel verification of `io_uring_setup` (425), `io_uring_enter` (426), and
/// `io_uring_register` (427) across `Strict` (exact compiled BPF installed with explicit checks
/// and required `STRICT_OK` completion marker so an unexpectedly successful `execve` fails) and
/// `Off` (compares against the same host's pre-install results — handling `kernel.io_uring_disabled`
/// cleanly — and reads `Seccomp_filters` on the tested thread via `/proc/thread-self/status`).
/// `Standard` is covered in `setid_seccomp_filter_enforced_for_all_arch_raw_syscalls`.
#[test]
fn io_uring_denied_in_standard_and_strict_and_unfiltered_in_off() -> TestResult {
    if cfg!(target_arch = "riscv64") {
        return Ok(());
    }
    let Some(python_bin) = find_python3() else {
        if std::env::var_os("MIRASERVE_REQUIRE_RAW_SYSCALL_PROBE").is_some() {
            return Err(
                "python3 is required when MIRASERVE_REQUIRE_RAW_SYSCALL_PROBE is set".into(),
            );
        }
        return Ok(());
    };

    let strict_bpf = compile_seccomp_bpf_bytes_for_host(SeccompMode::Strict)?;
    let mut strict_child = Command::new(python_bin)
        .args(["-c", STRICT_IO_URING_SCRIPT])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = strict_child.stdin.take() {
        stdin.write_all(&strict_bpf)?;
    }
    let strict_out = strict_child.wait_with_output()?;
    let strict_stdout = String::from_utf8_lossy(&strict_out.stdout);
    assert!(
        strict_out.status.success() && strict_stdout.lines().any(|l| l.trim() == "STRICT_OK"),
        "Strict io_uring probe failed or missed STRICT_OK marker (status={}):\nstdout={strict_stdout}\nstderr={}",
        strict_out.status,
        String::from_utf8_lossy(&strict_out.stderr),
    );

    let py = python_bin.to_owned();
    let off_res = std::thread::spawn(move || -> Result<(), String> {
        let before_filters = proc_thread_seccomp_filters();
        let before_probe = run_io_uring_probe(&py)?;
        let status = apply_seccomp_current_thread(SeccompMode::Off).map_err(|e| e.to_string())?;
        if status != EnforcementStatus::Disabled {
            return Err(format!("expected Disabled, got {status:?}"));
        }
        let after_filters = proc_thread_seccomp_filters();
        if after_filters != before_filters {
            return Err(format!(
                "SeccompMode::Off unexpectedly changed Seccomp_filters on tested thread: {before_filters:?} -> {after_filters:?}"
            ));
        }
        let after_probe = run_io_uring_probe(&py)?;
        if after_probe != before_probe {
            return Err(format!(
                "SeccompMode::Off altered host io_uring results: before={before_probe} after={after_probe}"
            ));
        }
        Ok(())
    })
    .join()
    .map_err(|_| "off io_uring thread panicked")?;
    off_res.map_err(|msg| -> Box<dyn std::error::Error> { msg.into() })
}

fn verify_kill_thread_openat2(python_bin: &str) -> Result<(), String> {
    let bpf = compile_openat2_action_filter(SeccompAction::KillThread)?;
    let bytes = bpf_to_bytes(&bpf);
    let mut child = Command::new(python_bin)
        .args(["-c", KILL_THREAD_OPENAT2_SCRIPT])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&bytes).map_err(|e| e.to_string())?;
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !out.status.success()
        || !stdout.contains("KILL_THREAD_MAIN_ALIVE:")
        || stdout.contains("UNEXPECTED_RETURN")
    {
        return Err(format!(
            "SECCOMP_RET_KILL_THREAD probe failed (status={}): stdout={stdout} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr),
        ));
    }
    Ok(())
}

/// Verifies P2-2 probe behavior directly against the kernel:
/// - `EACCES` and `EPERM` filters on `openat2` are reported as refusals by `probe_openat2_refused`.
/// - `EINVAL` is NOT reported as a refusal (silence means only "no recognised refusal"), and
///   calling `openat2` with an unsupported resolve bit returns `EINVAL` while
///   `probe_openat2_refused()` returns `None` (demonstrating the Linux 5.6–5.11 `RESOLVE_CACHED`
///   caveat).
/// - `SECCOMP_RET_KILL_PROCESS` terminates the entire child process with `SIGSYS`, whereas
///   `SECCOMP_RET_KILL_THREAD` terminates only the probing thread while leaving sibling threads
///   alive.
#[test]
fn openat2_probe_handles_eacces_eperm_einval_kill_and_resolve_caveat() -> TestResult {
    use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, openat2};
    use rustix::io::Errno;
    use std::os::unix::process::ExitStatusExt as _;

    // 1. Unfiltered probe succeeds (returns None), yet an unrecognized resolve flag returns EINVAL
    //    (matching Linux 5.6–5.11 when RESOLVE_CACHED is unsupported).
    assert_eq!(probe_openat2_refused(), None);
    let unsupported_resolve = openat2(
        CWD,
        "",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::from_bits_retain(1_u64 << 63),
    );
    assert_eq!(unsupported_resolve.err(), Some(Errno::INVAL));

    // 2. EACCES (13) and EPERM (1) -> refused; EINVAL (22) -> not reported as refused.
    for (errno_val, expect_refused) in [(13_u32, true), (1_u32, true), (22_u32, false)] {
        let res = std::thread::spawn(move || -> Result<(), String> {
            let bpf = compile_openat2_action_filter(SeccompAction::Errno(errno_val))?;
            seccompiler::apply_filter(&bpf).map_err(|e| e.to_string())?;
            let probed = probe_openat2_refused();
            if probed.is_some() != expect_refused {
                return Err(format!(
                    "errno={errno_val}: expected refused={expect_refused}, got {probed:?}"
                ));
            }
            Ok(())
        })
        .join()
        .map_err(|_| "openat2 probe thread panicked")?;
        res.map_err(|msg| -> Box<dyn std::error::Error> { msg.into() })?;
    }

    // 3. Kill-action filters on `openat2`:
    //    - `SECCOMP_RET_KILL_PROCESS` kills the whole child process with SIGSYS (31).
    //    - `SECCOMP_RET_KILL_THREAD` kills only the probing thread while the main thread stays alive.
    if let Some(python_bin) = find_python3() {
        let py = python_bin.to_owned();
        let kill_res = std::thread::spawn(move || -> Result<Option<i32>, String> {
            let bpf = compile_openat2_action_filter(SeccompAction::KillProcess)?;
            seccompiler::apply_filter(&bpf).map_err(|e| e.to_string())?;
            let out = Command::new(&py)
                .args([
                    "-c",
                    "import ctypes; libc=ctypes.CDLL(None); how=ctypes.create_string_buffer(24); libc.syscall(437, -100, b'', ctypes.byref(how), 24)",
                ])
                .output()
                .map_err(|e| e.to_string())?;
            Ok(out.status.signal())
        })
        .join()
        .map_err(|_| "kill-action probe thread panicked")?
        .map_err(|msg| -> Box<dyn std::error::Error> { msg.into() })?;
        assert_eq!(
            kill_res,
            Some(31), // SIGSYS on Linux
            "expected SIGSYS (31) under SECCOMP_RET_KILL_PROCESS on openat2, got {kill_res:?}"
        );

        verify_kill_thread_openat2(python_bin)
            .map_err(|msg| -> Box<dyn std::error::Error> { msg.into() })?;
    }

    Ok(())
}

fn kernel_enforces_landlock() -> Result<bool, String> {
    std::thread::spawn(|| -> Result<bool, String> {
        let (cfg, _) = parse_kdl(
            "ll-probe.kdl",
            r#"server { listen "127.0.0.1:8443"; sandbox { landlock #true; seccomp "off" } }"#,
        )
        .map_err(|e| e.to_string())?;
        let mut policy = SandboxPolicy::from_config_with_file(&cfg, None, None);
        policy.finalize_grants().map_err(|e| e.to_string())?;
        match apply_landlock_current_thread(&policy) {
            Ok(EnforcementStatus::Enforced | EnforcementStatus::PartiallyEnforced) => Ok(true),
            Ok(other) => Err(format!("unexpected Landlock probe status: {other:?}")),
            Err(SandboxError::Landlock(msg))
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

fn verify_o_tmpfile_under_landlock_socket_tree(
    policy: &SandboxPolicy,
    sock_tree: &std::path::Path,
    acme_dir: &std::path::Path,
) -> Result<(), String> {
    use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, fstat, openat, openat2};
    use rustix::io::Errno;

    let ll = apply_landlock_current_thread(policy).map_err(|e| e.to_string())?;
    if !matches!(
        ll,
        EnforcementStatus::Enforced | EnforcementStatus::PartiallyEnforced
    ) {
        return Err(format!("expected enforcing Landlock, got {ll:?}"));
    }
    let sc = apply_seccomp_current_thread(SeccompMode::Strict).map_err(|e| e.to_string())?;
    if sc != EnforcementStatus::Enforced {
        return Err(format!("expected Enforced seccomp, got {sc:?}"));
    }

    let sock_fd = openat(
        CWD,
        sock_tree,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| format!("open sock_tree dirfd failed: {e}"))?;
    let acme_fd = openat(
        CWD,
        acme_dir,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| format!("open acme_dir dirfd failed: {e}"))?;
    let both_setid = Mode::from_raw_mode(0o6644);

    // 1. Named regular-file creation (`O_CREAT`) in `socket-tree` is denied by Landlock (no MakeReg).
    let named_err = openat2(
        &sock_fd,
        "named_blocked",
        OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC,
        both_setid,
        ResolveFlags::BENEATH,
    )
    .err();
    if named_err != Some(Errno::ACCESS) {
        return Err(format!(
            "expected EACCES for named O_CREAT in socket-tree, got {named_err:?}"
        ));
    }

    // 2. Unnamed `O_TMPFILE` via `openat2` in `socket-tree` SUCCEEDS (Landlock checks hook_file_open
    //    WriteFile|ReadFile, NOT MakeReg) and retains S_ISUID|S_ISGID, while scalar `openat` returns EPERM.
    let scalar_err = openat(
        &sock_fd,
        ".",
        OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
        both_setid,
    )
    .err();
    if scalar_err != Some(Errno::PERM) {
        return Err(format!(
            "expected EPERM for scalar openat(O_TMPFILE, set-ID) in socket-tree, got {scalar_err:?}"
        ));
    }
    let tmp_fd = openat2(
        &sock_fd,
        ".",
        OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
        both_setid,
        ResolveFlags::BENEATH,
    )
    .map_err(|e| format!("openat2(O_TMPFILE, set-ID) in socket-tree unexpectedly failed: {e}"))?;
    let st = fstat(&tmp_fd).map_err(|e| format!("fstat socket-tree O_TMPFILE failed: {e}"))?;
    if (st.st_mode & 0o6000) != 0o6000 {
        return Err(format!(
            "socket-tree O_TMPFILE did not retain S_ISUID|S_ISGID: {:04o}",
            st.st_mode & 0o7777
        ));
    }

    verify_o_tmpfile_linkat_and_acme_control(&sock_fd, &acme_fd, &tmp_fd, both_setid)
}

fn verify_o_tmpfile_linkat_and_acme_control(
    sock_fd: &rustix::fd::OwnedFd,
    acme_fd: &rustix::fd::OwnedFd,
    tmp_fd: &rustix::fd::OwnedFd,
    both_setid: rustix::fs::Mode,
) -> Result<(), String> {
    use rustix::fs::{AtFlags, CWD, OFlags, ResolveFlags, fstat, linkat, openat2};
    use rustix::io::Errno;
    use std::os::fd::AsRawFd as _;

    // 3. Giving that unnamed socket-tree inode a directory entry (`linkat`) is blocked by Landlock:
    //    same-dir lacks MakeReg (EACCES); cross-dir into acme_dir lacks Refer on socket-tree (EACCES/EXDEV).
    let proc_fd_path = format!("/proc/self/fd/{}", tmp_fd.as_raw_fd());
    let link_same = linkat(
        CWD,
        &proc_fd_path,
        sock_fd,
        "linked_in_sock",
        AtFlags::SYMLINK_FOLLOW,
    );
    if link_same.err() != Some(Errno::ACCESS) {
        return Err(format!(
            "expected EACCES linking socket-tree O_TMPFILE into socket-tree, got {link_same:?}"
        ));
    }
    let link_cross = linkat(
        CWD,
        &proc_fd_path,
        acme_fd,
        "linked_in_acme",
        AtFlags::SYMLINK_FOLLOW,
    );
    if !matches!(link_cross.err(), Some(Errno::ACCESS | Errno::XDEV)) {
        return Err(format!(
            "expected EACCES or EXDEV linking socket-tree O_TMPFILE into acme_dir, got {link_cross:?}"
        ));
    }

    // 4. Positive control: `O_TMPFILE` + `linkat` inside `acme_dir` (which has MakeReg) succeeds.
    let acme_tmp = openat2(
        acme_fd,
        ".",
        OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
        both_setid,
        ResolveFlags::BENEATH,
    )
    .map_err(|e| format!("openat2(O_TMPFILE, set-ID) in acme_dir failed: {e}"))?;
    let acme_st = fstat(&acme_tmp).map_err(|e| format!("fstat acme_dir O_TMPFILE failed: {e}"))?;
    if (acme_st.st_mode & 0o6000) != 0o6000 {
        return Err(format!(
            "acme_dir O_TMPFILE did not retain S_ISUID|S_ISGID: {:04o}",
            acme_st.st_mode & 0o7777
        ));
    }
    let acme_proc_fd = format!("/proc/self/fd/{}", acme_tmp.as_raw_fd());
    linkat(
        CWD,
        &acme_proc_fd,
        acme_fd,
        "linked_in_acme_ok",
        AtFlags::SYMLINK_FOLLOW,
    )
    .map_err(|e| format!("control linkat of acme_dir O_TMPFILE into acme_dir failed: {e}"))?;
    Ok(())
}

/// Demonstrates P1-2's `O_TMPFILE` vs `MakeReg` distinction on a Landlock-enforcing Linux kernel:
/// beneath a configured `socket-tree` (`ReadFile | WriteFile`, no `MakeReg`/`Refer`), Landlock
/// denies named `openat2(O_CREAT)` with `EACCES`, allows unnamed `openat2(O_TMPFILE)` (which
/// checks `hook_file_open` write access and retains `S_ISUID|S_ISGID`), and denies `linkat` into
/// both the `socket-tree` (`EACCES`) and an RW `--acme-dir` (`EACCES`/`EXDEV`). Skips with a
/// printed reason when the running kernel lacks Landlock LSM or the temp filesystem lacks
/// `O_TMPFILE`.
#[test]
fn landlock_socket_tree_allows_openat2_o_tmpfile_setid_and_blocks_named_creation_and_linkat()
-> TestResult {
    use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, openat2};
    use rustix::io::Errno;

    if !kernel_enforces_landlock().map_err(|e| -> Box<dyn std::error::Error> { e.into() })? {
        eprintln!(
            "SKIP: host kernel does not enforce Landlock LSM; skipping O_TMPFILE under Landlock socket-tree test"
        );
        return Ok(());
    }

    let base = temp_base("landlock-otmpfile")?;
    let sock_tree = base.join("sock-tree");
    let acme_dir = base.join("acme");
    if let Some(reason) = miraserve_config::sandbox_tree_rejection(&sock_tree.to_string_lossy()) {
        eprintln!(
            "skipping landlock_o_tmpfile_check: temp path '{}' rejected by sandbox tree validator ({reason})",
            sock_tree.display()
        );
        let _ = std::fs::remove_dir_all(&base);
        return Ok(());
    }
    std::fs::create_dir_all(&sock_tree)?;
    std::fs::create_dir_all(&acme_dir)?;

    // Confirm the temp filesystem supports O_TMPFILE before confining.
    match openat2(
        CWD,
        &sock_tree,
        OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
        ResolveFlags::empty(),
    ) {
        Ok(_fd) => {}
        Err(err @ (Errno::OPNOTSUPP | Errno::ISDIR)) => {
            eprintln!("SKIP: temp filesystem does not support O_TMPFILE ({err})");
            let _ = std::fs::remove_dir_all(&base);
            return Ok(());
        }
        Err(err) => {
            let _ = std::fs::remove_dir_all(&base);
            return Err(format!("unexpected pre-sandbox O_TMPFILE probe error: {err}").into());
        }
    }

    let kdl = format!(
        "server {{\n    listen \"127.0.0.1:8443\"\n    sandbox {{ landlock #true; seccomp \"strict\"; socket-tree \"{}\" }}\n}}\n",
        kdl_escape_path(&sock_tree)
    );
    let (cfg, _) = parse_kdl("landlock-otmpfile.kdl", &kdl)?;
    let mut policy = SandboxPolicy::from_config_with_file(&cfg, None, Some(&acme_dir));
    policy.finalize_grants()?;

    let sock_t = sock_tree.clone();
    let acme_t = acme_dir.clone();
    let res = std::thread::spawn(move || {
        verify_o_tmpfile_under_landlock_socket_tree(&policy, &sock_t, &acme_t)
    })
    .join()
    .map_err(|_| "Landlock O_TMPFILE thread panicked")?;

    let _ = std::fs::remove_dir_all(&base);
    res.map_err(|msg| -> Box<dyn std::error::Error> { msg.into() })
}

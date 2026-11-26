//! Parity and identity tests for Linux Landlock Unix socket grants (0.1.6):
//! 4. PARITY (passes identically on 0.1.5 `074051e` AND on this branch, and actually detects
//!    changes to open sequence, tree descriptor lifetime, FD count, path/rule order & masks, and
//!    missing-socket notice text / once-per-process latch across two installations).
//! 5. IDENTITY: a real socket prepared, then replaced by a directory at the same name before
//!    installation: the installed rule stays on the original socket descriptor, the replacement
//!    directory receives no access, and no warning is emitted.

#![cfg(target_os = "linux")]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use miraserve_config::parse_kdl;
use miraserve_sandbox::{
    EnforcementStatus, SandboxError, SandboxPolicy, apply_landlock_current_thread, apply_sandbox,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const CHILD_ENV: &str = "MIRASERVE_SOCKET_TYPING_PARITY_CHILD";
const BASE_ENV: &str = "MIRASERVE_SOCKET_TYPING_PARITY_BASE";

fn kdl_escape_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Result<Self, std::io::Error> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let raw = std::env::temp_dir().join(format!(
            "miraserve-socktype-parity-{tag}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&raw)?;
        let path = fs::canonicalize(&raw)?;
        Ok(Self { path })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
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

#[derive(Default)]
struct EventVisitor {
    message: String,
    fields: BTreeMap<String, String>,
}

impl tracing::field::Visit for EventVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            value.clone_into(&mut self.message);
        } else {
            self.fields
                .insert(field.name().to_owned(), value.to_owned());
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let formatted = format!("{value:?}");
        if field.name() == "message" {
            self.message = formatted;
        } else {
            self.fields.insert(field.name().to_owned(), formatted);
        }
    }
}

#[derive(Debug, Clone)]
struct CapturedEvent {
    level: tracing::Level,
    message: String,
    fields: BTreeMap<String, String>,
}

struct EventCapture(Arc<Mutex<Vec<CapturedEvent>>>);

impl tracing::Subscriber for EventCapture {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);
        if let Ok(mut guard) = self.0.lock() {
            guard.push(CapturedEvent {
                level: *event.metadata().level(),
                message: visitor.message,
                fields: visitor.fields,
            });
        }
    }

    fn enter(&self, _span: &tracing::span::Id) {}
    fn exit(&self, _span: &tracing::span::Id) {}
}

fn snapshot_open_fds() -> Result<BTreeMap<i32, PathBuf>, std::io::Error> {
    let mut out = BTreeMap::new();
    for entry in fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        let name = entry.file_name();
        let Ok(fd) = name.to_string_lossy().parse::<i32>() else {
            continue;
        };
        if let Ok(target) = fs::read_link(entry.path()) {
            // Skip the directory descriptor opened by `read_dir("/proc/self/fd")` itself.
            if target == Path::new("/proc/self/fd")
                || target.to_string_lossy().ends_with("/fd") && target.starts_with("/proc/")
            {
                continue;
            }
            out.insert(fd, target);
        }
    }
    Ok(out)
}

fn lowest_free_fd(used: &BTreeSet<i32>) -> i32 {
    let mut fd = 0;
    while used.contains(&fd) {
        fd += 1;
    }
    fd
}

/// Independently computes the exact Linux system read-only paths that 0.1.5 adds on Linux (NOT
/// derived from `SandboxPolicy` internals).
fn expected_linux_system_ro_paths() -> BTreeSet<PathBuf> {
    let mut ro = BTreeSet::new();
    for sys_ro in [
        "/etc/ssl/certs",
        "/etc/ssl/openssl.cnf",
        "/etc/ssl/cert.pem",
        "/etc/ca-certificates",
        "/etc/ca-certificates.conf",
        "/usr/share/ca-certificates",
        "/usr/local/share/ca-certificates",
        "/etc/pki/tls/certs",
        "/etc/pki/tls/cert.pem",
        "/etc/pki/ca-trust",
        "/usr/share/pki/ca-trust-source",
        "/usr/share/pki/trust",
        "/var/lib/ca-certificates",
        "/etc/resolv.conf",
        "/etc/hosts",
    ] {
        let p = PathBuf::from(sys_ro);
        if p.exists() {
            if let Ok(canon) = fs::canonicalize(&p)
                && canon != p
                && canon.is_file()
            {
                ro.insert(canon);
            }
            ro.insert(p);
        }
    }
    let users_dir = Path::new("/etc/miraserve/auth");
    if users_dir.is_dir() {
        ro.insert(users_dir.to_path_buf());
    }
    ro
}

/// Independently predicts the exact `(fd_number -> canonical_path)` map Linux assigns when
/// opening grants in the 0.1.5 sequence (`RO` sorted -> `RW` sorted -> `Socket` sorted) with the
/// 0.1.5 tree validation descriptor lifetime (first `O_PATH` stays open throughout the no-follow
/// component walk and is closed only after the validated descriptor is returned).
///
/// Any change to open order (e.g. pre-opening sockets before RO), early close of the first tree
/// `O_PATH` descriptor, extra opens, or omitted opens changes either the FD numbers or count and
/// fails the assertion.
fn predict_015_open_fd_map(
    initial_open_fds: &BTreeSet<i32>,
    expected_read_only: &[PathBuf],
    expected_read_write: &[PathBuf],
    expected_socks: &[PathBuf],
    trees: &BTreeSet<PathBuf>,
) -> Result<BTreeMap<i32, PathBuf>, std::io::Error> {
    let mut used = initial_open_fds.clone();
    let mut predicted = BTreeMap::new();

    for p in expected_read_only
        .iter()
        .chain(expected_read_write.iter())
        .chain(expected_socks.iter())
    {
        if !p.exists() {
            // `openat` returns `ENOENT`; no descriptor retained.
            continue;
        }
        let canon = fs::canonicalize(p)?;
        if trees.contains(p) {
            // 0.1.5 `open_grant`:
            // 1. `openat(CWD, p, O_PATH | O_CLOEXEC)` -> `f0`, kept alive until return.
            let f0 = lowest_free_fd(&used);
            used.insert(f0);
            // 2. `pinned::open_dir_no_follow(&canon)` opens `/` (`f1`), then walks each normal
            //    component alternating between the next two lowest free slots (`f1` and `f2`),
            //    closing the previous component fd immediately after each step.
            let component_opens = canon.components().count(); // includes RootDir (`/`)
            let f1 = lowest_free_fd(&used);
            used.insert(f1);
            let final_fd = if component_opens <= 1 {
                f1
            } else {
                let f2 = lowest_free_fd(&used);
                used.remove(&f1);
                // After open #1 (`/` -> f1), open #2 takes f2 (drops f1), open #3 takes f1
                // (drops f2), ... so even total opens end on f2 and odd total opens end on f1.
                if component_opens.is_multiple_of(2) {
                    used.insert(f2);
                    f2
                } else {
                    used.insert(f1);
                    f1
                }
            };
            // 3. `open_grant` returns `GrantState::Installed { fd: final_fd }` and drops `f0`.
            used.remove(&f0);
            predicted.insert(final_fd, canon);
        } else {
            let f = lowest_free_fd(&used);
            used.insert(f);
            predicted.insert(f, canon);
        }
    }
    Ok(predicted)
}

fn run_child(test_name: &str, scenario: &str, base: &Path) -> TestResult {
    let exe = std::env::current_exe()?;
    let output = Command::new(exe)
        .args(["--exact", test_name, "--nocapture"])
        .env(CHILD_ENV, scenario)
        .env(BASE_ENV, base)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "child '{scenario}' failed (status={}):\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
        .into());
    }
    Ok(())
}

/// Test 4 (PARITY): passes identically on 0.1.5 (`074051e`) AND on this branch, and detects any
/// change to grant-open sequence, tree descriptor lifetime, descriptor count, installed rule order
/// and masks, and the missing-socket notice text / once-per-process latch across two installations.
#[test]
#[allow(clippy::too_many_lines)]
fn parity_open_sequence_fd_count_rules_masks_and_missing_socket_notice() -> TestResult {
    if let Ok(scenario) = std::env::var(CHILD_ENV) {
        assert_eq!(scenario, "parity");
        let base = PathBuf::from(std::env::var(BASE_ENV)?);
        let rt1 = base.join("a_rt1");
        let docroot = base.join("b_docroot");
        let rt2 = base.join("c_rt2");
        let absent_sock = base.join("d_absent.sock");
        let real_sock = base.join("e_real.sock");
        let sock_tree = base.join("f_stree");
        let inside_sock = sock_tree.join("inside.sock");
        let ungranted = base.join("z_ungranted");

        // Keep real sockets bound in this process (opened BEFORE the pre-FD snapshot so they are
        // part of `pre_fds`, not counted among policy grant FDs).
        let _real_listener = UnixListener::bind(&real_sock)?;
        let _inside_listener = UnixListener::bind(&inside_sock)?;

        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:8443"
    sandbox {{
        landlock #true
        seccomp "off"
        read-tree "{rt1}" "{rt2}"
        socket-tree "{sock_tree}"
    }}
}}
site "parity.example.test" {{
    root "{docroot}"
    route "/real.php" {{
        fastcgi-pass "unix:{real_sock}"
    }}
    route "/absent.php" {{
        fastcgi-pass "unix:{absent_sock}"
    }}
}}
"#,
            rt1 = kdl_escape_path(&rt1),
            rt2 = kdl_escape_path(&rt2),
            sock_tree = kdl_escape_path(&sock_tree),
            docroot = kdl_escape_path(&docroot),
            real_sock = kdl_escape_path(&real_sock),
            absent_sock = kdl_escape_path(&absent_sock),
        );
        let (cfg, _) = parse_kdl("parity.kdl", &kdl)?;

        // Build independent expected path lists (NOT derived from `SandboxPolicy`).
        let mut expected_ro_set = expected_linux_system_ro_paths();
        expected_ro_set.insert(rt1.clone());
        expected_ro_set.insert(docroot.clone());
        expected_ro_set.insert(rt2.clone());
        let expected_read_only: Vec<PathBuf> = expected_ro_set.into_iter().collect();
        let expected_read_write: Vec<PathBuf> = Vec::new();
        let expected_socks: Vec<PathBuf> =
            vec![absent_sock.clone(), real_sock.clone(), sock_tree.clone()];
        let trees: BTreeSet<PathBuf> = [rt1.clone(), rt2.clone(), sock_tree.clone()]
            .into_iter()
            .collect();

        // Snapshot FDs immediately before policy preparation (single-threaded child process).
        let pre_fd_map = snapshot_open_fds()?;
        let pre_fds: BTreeSet<i32> = pre_fd_map.keys().copied().collect();
        let expected_new_fds = predict_015_open_fd_map(
            &pre_fds,
            &expected_read_only,
            &expected_read_write,
            &expected_socks,
            &trees,
        )?;

        let mut policy = SandboxPolicy::from_config_with_file(&cfg, None, None);
        policy.finalize_grants()?;

        let post_fd_map = snapshot_open_fds()?;
        let actual_new_fds: BTreeMap<i32, PathBuf> = post_fd_map
            .into_iter()
            .filter(|(fd, _)| !pre_fds.contains(fd))
            .collect();

        // 1. Exact path-set order and spellings.
        assert_eq!(
            policy.read_only_paths, expected_read_only,
            "read_only_paths order/spelling mismatch"
        );
        assert_eq!(
            policy.read_write_paths, expected_read_write,
            "read_write_paths mismatch"
        );
        assert_eq!(
            policy.socket_paths, expected_socks,
            "socket_paths order/spelling mismatch"
        );

        // 2. Exact descriptor count AND exact FD-number-to-target-path assignment after preparation
        //    (detects reordered opens, early tree-FD close, leaked FDs, or omitted opens).
        assert_eq!(
            actual_new_fds.len(),
            expected_new_fds.len(),
            "descriptor count mismatch: actual={actual_new_fds:?} expected={expected_new_fds:?}"
        );
        assert_eq!(
            actual_new_fds, expected_new_fds,
            "grant open sequence / tree FD lifetime mismatch"
        );

        // 3. Install Landlock twice (on two separate threads) and verify:
        //    - missing-socket report note has exact 0.1.5 text on both installations
        //    - missing-socket WARN has exact 0.1.5 text and is emitted ONCE across two installs
        //    - kernel-enforced Landlock masks match exact 0.1.5 rights for every grant
        let events: Arc<Mutex<Vec<CapturedEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let _sub_guard = tracing::subscriber::set_default(EventCapture(Arc::clone(&events)));

        let expected_note = format!(
            "missing Landlock Unix socket path(s) omitted at startup (restart after creating): {}",
            absent_sock.display()
        );
        let expected_warn_msg = "configured Landlock Unix socket path(s) do not exist at startup and cannot be granted until restart";

        // Thread 1: install Landlock and exercise every rule mask directly against the kernel.
        let p1 = policy.clone();
        let rt1_c = rt1.clone();
        let rt2_c = rt2.clone();
        let docroot_c = docroot.clone();
        let real_sock_c = real_sock.clone();
        let sock_tree_c = sock_tree.clone();
        let inside_sock_c = inside_sock.clone();
        let ungranted_c = ungranted.clone();
        let expected_note_1 = expected_note.clone();
        let t1_events = Arc::clone(&events);
        std::thread::spawn(move || -> Result<(), String> {
            let _g = tracing::subscriber::set_default(EventCapture(t1_events));
            let report = apply_sandbox(&p1).map_err(|e| format!("apply_sandbox #1: {e}"))?;
            if !matches!(
                report.landlock,
                EnforcementStatus::Enforced | EnforcementStatus::PartiallyEnforced
            ) {
                return Err(format!(
                    "expected enforcing Landlock, got {:?}",
                    report.landlock
                ));
            }
            if !report.notes.contains(&expected_note_1) {
                return Err(format!(
                    "install #1 missing exact note `{expected_note_1}`; got {:?}",
                    report.notes
                ));
            }

            // RO trees & docroot: ReadFile + ReadDir allowed, WriteFile + MakeReg denied.
            for (label, dir, file) in [
                ("rt1", &rt1_c, "file.txt"),
                ("docroot", &docroot_c, "index.html"),
                ("rt2", &rt2_c, "file.txt"),
            ] {
                fs::read_to_string(dir.join(file))
                    .map_err(|e| format!("{label} ReadFile failed: {e}"))?;
                fs::read_dir(dir).map_err(|e| format!("{label} ReadDir failed: {e}"))?;
                let w = OpenOptions::new().write(true).open(dir.join(file));
                if w.err().map(|e| e.kind()) != Some(ErrorKind::PermissionDenied) {
                    return Err(format!("{label} must deny WriteFile under RO mask"));
                }
                let mk = fs::write(dir.join("new.txt"), b"x");
                if mk.err().map(|e| e.kind()) != Some(ErrorKind::PermissionDenied) {
                    return Err(format!("{label} must deny MakeReg under RO mask"));
                }
            }

            // Real exact socket: connect allowed.
            UnixStream::connect(&real_sock_c)
                .map_err(|e| format!("real exact socket connect failed: {e}"))?;

            // Socket-tree: ReadFile + WriteFile allowed (connect + existing file RW), ReadDir and
            // MakeReg denied.
            UnixStream::connect(&inside_sock_c)
                .map_err(|e| format!("socket-tree child connect failed: {e}"))?;
            fs::read_to_string(sock_tree_c.join("existing.txt"))
                .map_err(|e| format!("socket-tree ReadFile failed: {e}"))?;
            OpenOptions::new()
                .write(true)
                .open(sock_tree_c.join("existing.txt"))
                .map_err(|e| format!("socket-tree WriteFile failed: {e}"))?;
            if fs::read_dir(&sock_tree_c).err().map(|e| e.kind())
                != Some(ErrorKind::PermissionDenied)
            {
                return Err("socket-tree must deny ReadDir".to_owned());
            }
            if fs::write(sock_tree_c.join("created.txt"), b"x")
                .err()
                .map(|e| e.kind())
                != Some(ErrorKind::PermissionDenied)
            {
                return Err("socket-tree must deny MakeReg".to_owned());
            }

            // Ungranted sibling directory: ReadFile denied.
            if fs::read_to_string(ungranted_c.join("secret.txt"))
                .err()
                .map(|e| e.kind())
                != Some(ErrorKind::PermissionDenied)
            {
                return Err("ungranted directory must deny ReadFile".to_owned());
            }
            Ok(())
        })
        .join()
        .map_err(|_| "parity thread 1 panicked")??;

        // Materialize a DAC-readable file at the previously absent socket path now (unconfined
        // main thread) and confirm Thread 2 has NO Landlock rule for it, receives the exact same
        // note, and emits NO second WARN.
        fs::write(&absent_sock, b"LATE-ABSENT-MARKER")?;

        let p2 = policy.clone();
        let absent_sock_c = absent_sock.clone();
        let expected_note_2 = expected_note.clone();
        let t2_events = Arc::clone(&events);
        std::thread::spawn(move || -> Result<(), String> {
            let _g = tracing::subscriber::set_default(EventCapture(t2_events));
            let report = apply_sandbox(&p2).map_err(|e| format!("apply_sandbox #2: {e}"))?;
            if !report.notes.contains(&expected_note_2) {
                return Err(format!(
                    "install #2 missing exact note `{expected_note_2}`; got {:?}",
                    report.notes
                ));
            }
            if fs::read_to_string(&absent_sock_c)
                .err()
                .map(|e| e.kind())
                != Some(ErrorKind::PermissionDenied)
            {
                return Err("late-created absent socket path outside socket-tree must have no Landlock rule".to_owned());
            }
            Ok(())
        })
        .join()
        .map_err(|_| "parity thread 2 panicked")??;

        let captured = events
            .lock()
            .map_err(|_| "event capture lock poisoned")?
            .clone();
        let missing_warns: Vec<&CapturedEvent> = captured
            .iter()
            .filter(|e| e.level == tracing::Level::WARN && e.message == expected_warn_msg)
            .collect();
        assert_eq!(
            missing_warns.len(),
            1,
            "missing-socket WARN must be emitted ONCE across two installations, got {missing_warns:?} (all: {captured:?})"
        );
        let first_warn = missing_warns
            .first()
            .ok_or("expected one missing-socket warning")?;
        assert_eq!(
            first_warn.fields.get("missing_sockets").map(String::as_str),
            Some(absent_sock.to_string_lossy().as_ref()),
            "missing_sockets field mismatch: {first_warn:?}"
        );
        assert!(
            captured
                .iter()
                .all(|e| !e.message.contains("is not a socket")),
            "valid parity config must emit no non-socket warning: {captured:?}"
        );
        return Ok(());
    }

    if !kernel_enforces_landlock()? {
        eprintln!(
            "skipping parity_open_sequence_fd_count_rules_masks_and_missing_socket_notice: host kernel lacks Landlock LSM"
        );
        return Ok(());
    }

    let tmp = TempDir::new("parity")?;
    for (dir, file, body) in [
        ("a_rt1", "file.txt", "RT1"),
        ("b_docroot", "index.html", "DOCROOT"),
        ("c_rt2", "file.txt", "RT2"),
        ("f_stree", "existing.txt", "STREE"),
        ("z_ungranted", "secret.txt", "SECRET"),
    ] {
        let d = tmp.path.join(dir);
        fs::create_dir_all(&d)?;
        fs::write(d.join(file), body)?;
    }

    run_child(
        "parity_open_sequence_fd_count_rules_masks_and_missing_socket_notice",
        "parity",
        &tmp.path,
    )
}

/// Test 5 (IDENTITY): a real Unix socket is prepared into the policy, then the pathname is
/// replaced by a directory before Landlock installation. The installed rule remains bound to the
/// original socket descriptor's inode, the replacement directory receives no access, and no
/// warning is emitted.
#[test]
fn real_socket_replaced_by_directory_keeps_original_descriptor_and_no_warning() -> TestResult {
    if let Ok(scenario) = std::env::var(CHILD_ENV) {
        assert_eq!(scenario, "identity");
        let base = PathBuf::from(std::env::var(BASE_ENV)?);
        let docroot = base.join("www");
        let ep_sock = base.join("ep.sock");
        let moved_sock = base.join("ep-moved.sock");

        let _listener = UnixListener::bind(&ep_sock)?;
        let kdl = format!(
            r#"
server {{
    listen "127.0.0.1:8443"
    sandbox {{
        landlock #true
        seccomp "off"
    }}
}}
site "identity.example.test" {{
    root "{docroot}"
    route "/app.php" {{
        fastcgi-pass "unix:{ep_sock}"
    }}
}}
"#,
            docroot = kdl_escape_path(&docroot),
            ep_sock = kdl_escape_path(&ep_sock),
        );
        let (cfg, _) = parse_kdl("identity.kdl", &kdl)?;
        let mut policy = SandboxPolicy::from_config_with_file(&cfg, None, None);
        policy.finalize_grants()?;
        let original_id = policy
            .granted_identity(&ep_sock)
            .ok_or("expected installed identity for real socket")?;

        // Replace `ep.sock` on disk with a directory containing a DAC-readable marker BEFORE
        // installing Landlock. Keep the original socket inode alive at `ep-moved.sock`.
        fs::rename(&ep_sock, &moved_sock)?;
        fs::create_dir_all(&ep_sock)?;
        let dir_marker = ep_sock.join("marker.txt");
        fs::write(&dir_marker, "REPLACEMENT-DIR-MARKER")?;
        assert_eq!(fs::read_to_string(&dir_marker)?, "REPLACEMENT-DIR-MARKER");
        assert_eq!(
            policy.granted_identity(&ep_sock),
            Some(original_id),
            "prepared policy identity must stay pinned to original socket"
        );

        let events: Arc<Mutex<Vec<CapturedEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let t_events = Arc::clone(&events);
        std::thread::spawn(move || -> Result<(), String> {
            let _g = tracing::subscriber::set_default(EventCapture(t_events));
            let status = apply_landlock_current_thread(&policy)
                .map_err(|e| format!("apply_landlock_current_thread: {e}"))?;
            if !matches!(
                status,
                EnforcementStatus::Enforced | EnforcementStatus::PartiallyEnforced
            ) {
                return Err(format!("expected enforcing Landlock, got {status:?}"));
            }
            // Original socket descriptor's inode keeps its Landlock rule: connecting to the moved
            // socket inode succeeds.
            UnixStream::connect(&moved_sock)
                .map_err(|e| format!("connect to original socket inode failed: {e}"))?;
            // Replacement directory at the original name has NO Landlock rule.
            let dir_err = fs::read_to_string(&dir_marker).err().ok_or_else(|| {
                "replacement directory at socket name must not be readable under Landlock"
                    .to_owned()
            })?;
            if dir_err.kind() != ErrorKind::PermissionDenied {
                return Err(format!(
                    "expected PermissionDenied reading replacement dir marker, got {dir_err:?}"
                ));
            }
            Ok(())
        })
        .join()
        .map_err(|_| "identity thread panicked")??;

        let captured = events
            .lock()
            .map_err(|_| "event capture lock poisoned")?
            .clone();
        assert!(
            captured.iter().all(|e| e.level != tracing::Level::WARN),
            "replacing a prepared real socket with a directory must emit NO warning: {captured:?}"
        );
        return Ok(());
    }

    if !kernel_enforces_landlock()? {
        eprintln!(
            "skipping real_socket_replaced_by_directory_keeps_original_descriptor_and_no_warning: host kernel lacks Landlock LSM"
        );
        return Ok(());
    }

    let tmp = TempDir::new("identity")?;
    fs::create_dir_all(tmp.path.join("www"))?;
    run_child(
        "real_socket_replaced_by_directory_keeps_original_descriptor_and_no_warning",
        "identity",
        &tmp.path,
    )
}

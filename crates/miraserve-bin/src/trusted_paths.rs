//! Opt-in Linux trusted-path diagnostic (`--trusted-paths`, `W034`); roles: 0=tree, 1=sock, 2=acme, 3=dir.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};

use miraserve_config::{ConfigIssue, FastCgiTarget, LoadedConfig, RouteHandler, Severity};
use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{CWD, FileType, Mode, OFlags, Stat, fstat, fstatfs, openat, readlinkat};
use rustix::io::Errno;
use rustix::path::Arg;

use crate::check::CheckArgs;

const NARROWED: &str = "trusted-paths (narrowed): does not yet inspect config file, read-tree, \
    site/route roots, owner-dir, TLS certs/keys/CAs, keyd-auth-secret-file, acme-webroot, \
    basic-auth, bot-auth, ai-publish keys, error-pages, upstream-tls, mcp-gateway, wasm-plugin, \
    or non-rotating log paths";
const HELP_GEN: &str = "keep every ancestor (and exclusive state directory) owned by root or the \
    service account, not group/other-writable, on a local POSIX filesystem";
const HELP_PROD: &str = "set the socket-tree directory owner to root or the service account, or \
    pass --allow-warning W034 if you trust that socket producer";
const SYM_BAD: &str = "symbolic link whose own parent or target chain is untrusted";
const FS_BAD: &str = "could not be verified on this filesystem";

struct Ctx(u32, Option<u32>, bool, Option<u32>, bool);
struct Fail(PathBuf, Option<(u32, u32)>, String, u8);
struct Frame(OwnedFd, PathBuf, Stat, bool, bool);

fn fst(p: &Path, st: &Stat, r: impl Into<String>, fl: u8) -> Fail {
    let m = Some((st.st_uid, st.st_mode & 0o7777));
    Fail(p.into(), m, r.into(), fl)
}
fn fin(p: &Path, d: impl std::fmt::Display) -> Fail {
    Fail(p.into(), None, format!("could not be inspected ({d})"), 1)
}
fn op(d: impl AsFd, p: impl Arg, f: OFlags) -> Result<OwnedFd, Errno> {
    openat(d, p, OFlags::PATH | OFlags::CLOEXEC | f, Mode::empty())
}
pub(crate) fn is_local_posix_fs(m: u32) -> bool {
    const A: [u32; 4] = [0xEF53, 0x5846_5342, 0x9123_683E, 0x0102_1994];
    const B: [u32; 4] = [0x794C_7630, 0x2FC1_2FC1, 0xF2F5_2010, 0xCA45_1A4E];
    const C: [u32; 4] = [0x8584_58F6, 0x7371_7368, 0xE0F5_E1E2, 0x3153_464A];
    const D: [u32; 2] = [0x5265_4973, 0x0001_1954];
    A.contains(&m) || B.contains(&m) || C.contains(&m) || D.contains(&m)
}
pub(crate) fn is_identity_uid_map(s: &str) -> bool {
    let v: Vec<&str> = s.split_whitespace().collect();
    v.as_slice() == ["0", "0", "4294967295"]
}
fn lookup_uid(n: &str) -> Option<u32> {
    n.parse().ok().or_else(|| {
        let t = std::fs::read_to_string("/etc/passwd").ok()?;
        t.lines().find_map(|l| {
            let mut f = l.split(':');
            (f.next()? == n).then(|| f.nth(1)?.parse().ok())?
        })
    })
}
pub(crate) fn obs(eu: u32, u: Option<&str>, r: fn(&str) -> Option<u32>) -> (Option<u32>, String) {
    let (fk, df) = ("server.sandbox.user", "resolves to uid");
    let (res, tr) = (u.map(|nm| (nm, r(nm))), "trusting uid 0 and service uid");
    if eu == 0 {
        let u0 = "service uid is unknown, so only uid 0 is trusted";
        let msg = match res {
            Some((nm, Some(id))) => format!("{tr} {id} (from {fk} '{nm}')"),
            Some((nm, None)) => format!("{fk} '{nm}' could not be resolved; {u0}"),
            None => format!("{u0} ({fk} is unset)"),
        };
        let (id, out) = (
            res.and_then(|(_, id)| id),
            format!("trusted-paths: running as root; {msg}"),
        );
        return (id, out);
    }
    let ex = match res {
        Some((nm, Some(id))) if id != eu => format!("; {fk} '{nm}' {df} {id}, which differs"),
        Some((nm, None)) => format!("; {fk} '{nm}' could not be resolved"),
        _ => String::new(),
    };
    let out = format!("trusted-paths: {tr} {eu} (effective uid of this check{ex})");
    (Some(eu), out)
}
pub(crate) fn check(out: &mut Vec<ConfigIssue>, l: &LoadedConfig, a: &CheckArgs) -> Vec<String> {
    let cfg = &l.config;
    let euid = rustix::process::geteuid().as_raw();
    let (suid, onote) = obs(euid, cfg.server.sandbox.user.as_deref(), lookup_uid);
    let ru = |p| -> Option<u32> { std::fs::read_to_string(p).ok()?.trim().parse().ok() };
    let ov = ru("/proc/sys/kernel/overflowuid");
    let um = std::fs::read_to_string("/proc/self/uid_map");
    let id_ok = ov.is_some() && um.is_ok_and(|s| is_identity_uid_map(&s));
    let ps = ru("/proc/sys/fs/protected_symlinks").is_none_or(|v| v != 0);
    let ctx = Ctx(euid, suid, id_ok, ov, ps);
    let mut chk = |key: &str, lbl: &str, p: &Path, role: u8| {
        if let Err(Fail(comp, meta, reason, fl)) = walk_path(&ctx, p, role) {
            let uk = "uid unknown, mode unknown";
            let m = meta.map_or_else(|| uk.into(), |(u, d)| format!("uid {u}, mode {d:04o}"));
            let help = if fl & 2 != 0 { HELP_PROD } else { HELP_GEN };
            let (pd, cd) = (p.display(), comp.display());
            out.push(ConfigIssue {
                code: "W034".into(),
                severity: Severity::Warning,
                message: format!("{lbl} '{pd}': first untrusted component '{cd}' ({m}): {reason}"),
                path: Some(key.into()),
                help: Some(help.into()),
                label: None,
                location: l.location_for(key),
            });
        }
    };
    let tl = "server.sandbox socket-tree root";
    for t in &cfg.server.sandbox.socket_trees {
        chk("server.sandbox.socket-tree", tl, Path::new(t), 0);
    }
    for (i, s) in cfg.sites.iter().enumerate() {
        let h = s.hosts.first().map_or("<site>", String::as_str);
        for (j, r) in s.routes.iter().enumerate() {
            if let RouteHandler::FastCgi(f) = &r.handler
                && let FastCgiTarget::Unix { path } = &f.target
            {
                let k = format!("site[{i}].route[{j}].fastcgi-pass");
                let lb = format!("site '{h}' FastCGI Unix socket");
                chk(&k, &lb, Path::new(path), 1);
            }
        }
        if let Some(p) = &s.ai_publish {
            let k = format!("site[{i}].ai-publish.storage");
            let lb = format!("site '{h}' ai-publish storage");
            chk(&k, &lb, Path::new(&p.storage), 3);
        }
    }
    if let Some(s) = &cfg.server.tls.keyd_socket
        && !s.starts_with("tcp://")
    {
        let k = "server.tls.keyd-socket";
        chk(k, k, Path::new(s.strip_prefix("unix:").unwrap_or(s)), 1);
    }
    let def = Path::new(".miraserve-acme");
    let ac = a.acme_dir.as_deref().unwrap_or(def);
    if a.acme_dir.is_some() || cfg.server.tls.acme.is_some() {
        chk("server.tls.acme", "ACME directory", ac, 2);
    }
    for (o, k) in [(&a.log_file, "log-file"), (&a.access_log, "access-log")] {
        if let Some(p) = o.as_ref().filter(|_| a.log_max_bytes > 0) {
            let d = p.parent().filter(|x| !x.as_os_str().is_empty());
            let key = format!("server.{k}");
            let lb = format!("rotating --{k} parent directory");
            chk(&key, &lb, d.unwrap_or(Path::new(".")), 3);
        }
    }
    vec![onote, NARROWED.into()]
}
fn split_segs(raw: &OsStr) -> (bool, Vec<OsString>) {
    let b = raw.as_bytes();
    let mut out = Vec::new();
    for s in b.split(|&c| c == b'/').filter(|s| !s.is_empty()) {
        out.push(OsString::from_vec(s.to_vec()));
    }
    if b.ends_with(b"/") && b.iter().any(|&c| c != b'/') {
        out.push(OsString::from("."));
    }
    out.reverse();
    (b.starts_with(b"/"), out)
}
fn inspect_fd(c: &Ctx, fd: &OwnedFd, p: &Path) -> Result<(Stat, bool), Fail> {
    let st = fstat(fd).map_err(|e| fin(p, e))?;
    let fse = |d: &str| Err(fst(p, &st, format!("{FS_BAD} ({d})"), 1));
    match (c.2, c.3 == Some(st.st_uid)) {
        (false, _) => return fse("identity mapping could not be established"),
        (_, true) => return fse("unmapped overflow uid"),
        _ => {}
    }
    let sf = fstatfs(fd).map_err(|e| fin(p, e))?;
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let m = sf.f_type as u32;
    if !is_local_posix_fs(m) {
        return fse(&format!("filesystem 0x{m:x}"));
    }
    Ok((st, (sf.f_flags & 0x2000) != 0))
}
fn check_node(ctx: &Ctx, leaf: Option<u8>, path: &Path, st: &Stat) -> Result<bool, Fail> {
    if leaf == Some(1) {
        return Ok(false);
    }
    let (uid, wr, stky) = (st.st_uid, st.st_mode & 0o022 != 0, st.st_mode & 0o1000 != 0);
    let untrusted = uid != 0 && ctx.1 != Some(uid);
    if untrusted && (leaf.is_none() || !wr) {
        if leaf == Some(0) && FileType::from_raw_mode(st.st_mode) == FileType::Directory {
            let msg = format!("directory is controlled by uid {uid} (the socket producer)");
            return Err(fst(path, st, msg, 2));
        }
        return Err(fst(path, st, "owner not trusted", 0));
    }
    if wr && (leaf.is_some() || !stky) {
        return Err(fst(path, st, "group or other writable", 0));
    }
    Ok(wr && stky)
}
#[allow(clippy::too_many_lines)]
fn walk_path(c: &Ctx, raw: &Path, role: u8) -> Result<bool, Fail> {
    if raw.as_os_str().is_empty() {
        return Err(fin(raw, "empty path"));
    }
    let rp = PathBuf::from("/");
    let rfd = op(CWD, "/", OFlags::DIRECTORY).map_err(|e| fin(&rp, e))?;
    let (rst, rns) = inspect_fd(c, &rfd, &rp)?;
    let rsk = check_node(c, None, &rp, &rst)?;
    let mut stack = vec![Frame(rfd, rp, rst, rsk, rns)];
    let (is_abs, mut pending) = split_segs(raw.as_os_str());
    let (mut cwd_id, mut cwd_steps) = (None, 0_usize);
    if !is_abs {
        let dot = Path::new(".");
        let cst = fstat(op(CWD, ".", OFlags::DIRECTORY).map_err(|e| fin(dot, e))?)
            .map_err(|e| fin(dot, e))?;
        let cwd = std::env::current_dir().map_err(|e| fin(dot, e))?;
        let (_, cs) = split_segs(cwd.as_os_str());
        (cwd_id, cwd_steps) = (Some((cst.st_dev, cst.st_ino)), cs.len());
        if cwd_steps == 0 && (rst.st_dev, rst.st_ino) != (cst.st_dev, cst.st_ino) {
            return Err(fin(dot, "cwd identity mismatch"));
        }
        pending.extend(cs);
    }
    let (mut hops, mut via) = (0_usize, None::<PathBuf>);
    let wrap = |v: &Option<PathBuf>, mut f: Fail| {
        if let (Some(l), 0) = (v, f.3 & 1) {
            f.2 = format!("{SYM_BAD} (via '{}': {})", l.display(), f.2);
        }
        f
    };
    while let Some(seg) = pending.pop() {
        let Some(cur) = stack.last() else { break };
        if seg == "." {
            op(&cur.0, ".", OFlags::DIRECTORY).map_err(|e| fin(&cur.1, e))?;
            continue;
        }
        if seg == ".." {
            let dp = cur.1.join("..");
            let pfd = op(&cur.0, "..", OFlags::NOFOLLOW).map_err(|e| fin(&dp, e))?;
            let (pst, _) = inspect_fd(c, &pfd, &cur.1)?;
            let exp = stack.get(stack.len().saturating_sub(2)).or(stack.first());
            if !exp.is_some_and(|e| e.2.st_dev == pst.st_dev && e.2.st_ino == pst.st_ino) {
                return Err(fin(&dp, "parent changed during walk"));
            }
            if stack.len() > 1 {
                stack.pop();
            }
            continue;
        }
        let at_cwd_end = cwd_steps == 1;
        cwd_steps = cwd_steps.saturating_sub(1);
        let cp = cur.1.join(&seg);
        let fd = match op(&cur.0, &seg, OFlags::NOFOLLOW) {
            Ok(fd) => fd,
            Err(Errno::NOENT) if cur.3 => {
                let r = "missing component under a parent where another account could create it";
                return Err(wrap(&via, fst(&cur.1, &cur.2, r, 0)));
            }
            Err(Errno::NOENT) => return Ok(false),
            Err(e) => return Err(fin(&cp, e)),
        };
        let (st, nosym) = inspect_fd(c, &fd, &cp)?;
        if at_cwd_end && cwd_id.is_some_and(|id| (st.st_dev, st.st_ino) != id) {
            return Err(fin(&cp, "cwd identity mismatch"));
        }
        let is_sym = FileType::from_raw_mode(st.st_mode) == FileType::Symlink;
        if cur.3 && st.st_uid != 0 && c.1 != Some(st.st_uid) {
            let mut r = "owner not trusted".to_owned();
            if is_sym {
                r = format!("{SYM_BAD} (owner not trusted in sticky directory)");
            }
            return Err(wrap(&via, fst(&cp, &st, r, 0)));
        }
        if is_sym {
            let (pm, pu) = (cur.2.st_mode, cur.2.st_uid);
            let ps = c.4 && pm & 0o1002 == 0o1002 && st.st_uid != pu && st.st_uid != c.0;
            let why = match (role == 2, cur.4 || nosym, ps) {
                (true, _, _) => Some("symbolic links are not allowed for this role"),
                (_, true, _) => Some("mount has nosymfollow"),
                (_, _, true) => Some("blocked by fs.protected_symlinks"),
                _ => None,
            };
            if let Some(w) = why {
                return Err(fst(&cp, &st, format!("{SYM_BAD} ({w})"), 1));
            }
            hops += 1;
            if hops > 40 {
                return Err(fin(&cp, Errno::LOOP));
            }
            let tgt = readlinkat(&fd, "", Vec::new()).map_err(|e| fin(&cp, e))?;
            if tgt.as_bytes().is_empty() {
                return Err(fin(&cp, "empty symbolic link target"));
            }
            via.get_or_insert(cp);
            let (abs, tsegs) = split_segs(OsStr::from_bytes(tgt.as_bytes()));
            if abs {
                stack.truncate(1);
            }
            pending.extend(tsegs);
            continue;
        }
        if cwd_steps == 0 && pending.iter().all(|s| s == ".") {
            if !pending.is_empty() {
                op(&fd, ".", OFlags::DIRECTORY).map_err(|e| fin(&cp, e))?;
            }
            return check_node(c, Some(role), &cp, &st).map_err(|f| wrap(&via, f));
        }
        if FileType::from_raw_mode(st.st_mode) != FileType::Directory {
            return Err(fin(&cp, Errno::NOTDIR));
        }
        let sticky = check_node(c, None, &cp, &st).map_err(|f| wrap(&via, f))?;
        stack.push(Frame(fd, cp, st, sticky, nosym));
    }
    let cur = stack.last().ok_or_else(|| fin(raw, "empty walk stack"))?;
    check_node(c, Some(role), &cur.1, &cur.2).map_err(|f| wrap(&via, f))
}

#[cfg(test)]
#[path = "../tests/common/trusted_paths_unit.rs"]
mod unit_tests;

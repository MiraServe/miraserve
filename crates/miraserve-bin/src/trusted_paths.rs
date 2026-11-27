//! Opt-in Linux trusted-path diagnostic (`--trusted-paths`, `W034`); roles: 0=tree, 1=sock, 2=acme, 3=dir.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};

use miraserve_config::{ConfigIssue, FastCgiTarget, LoadedConfig, RouteHandler, Severity};
use miraserve_tls::{KeydEndpoint, resolve_unix_user_uid};
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
    service account, not group/other-writable, on an ordinary local POSIX filesystem; use absolute paths";
const HELP_PROD: &str = "set the socket-tree directory owner to root or the service account, or \
    pass --allow-warning W034 if you trust that socket producer (--allow-warning W034 applies to \
    all W034 warnings under --strict)";
const SYM_BAD: &str = "symbolic link whose own parent or target chain is untrusted";
const TREE_WR: &str =
    "group or other writable (other accounts can create or replace sockets in this tree)";
const STKY_OWN: &str = "owner not trusted in sticky directory";

type WalkRes = Result<Option<(PathBuf, OsString)>, Fail>;
struct Ctx(Option<u32>, bool, Option<u32>, bool);
struct Fail(PathBuf, Option<(u32, u32)>, String, u8);
struct Frame(OwnedFd, PathBuf, Stat, bool, bool);

fn fst(p: &Path, st: &Stat, r: impl Into<String>, fl: u8) -> Fail {
    let m = Some((st.st_uid, st.st_mode & 0o7777));
    Fail(p.into(), m, r.into(), fl)
}
fn fin(p: &Path, d: impl std::fmt::Display) -> Fail {
    Fail(p.into(), None, format!("could not be inspected ({d})"), 1)
}
fn fmeta(p: &Path, st: &Stat, d: impl std::fmt::Display) -> Fail {
    fst(p, st, format!("could not be inspected ({d})"), 1)
}
fn prod(u: u32) -> String {
    format!("directory is controlled by uid {u} (the socket producer)")
}
fn op(d: impl AsFd, p: impl Arg, f: OFlags) -> Result<OwnedFd, Errno> {
    openat(d, p, OFlags::PATH | OFlags::CLOEXEC | f, Mode::empty())
}
pub(crate) fn is_local_posix_fs(m: u32) -> bool {
    const A: [u32; 4] = [0xEF53, 0x5846_5342, 0x9123_683E, 0x0102_1994];
    const B: [u32; 4] = [0x2FC1_2FC1, 0xF2F5_2010, 0xCA45_1A4E, 0x8584_58F6];
    const C: [u32; 4] = [0x7371_7368, 0xE0F5_E1E2, 0x3153_464A, 0x5265_4973];
    A.contains(&m) || B.contains(&m) || C.contains(&m) || m == 0x0001_1954
}
pub(crate) fn is_identity_uid_map(s: &str) -> bool {
    let v: Vec<&str> = s.split_whitespace().collect();
    v.as_slice() == ["0", "0", "4294967295"]
}
pub(crate) fn obs(eu: u32, u: Option<&str>, r: fn(&str) -> Option<u32>) -> (Option<u32>, String) {
    let (fk, tr) = ("server.sandbox.user", "trusting uid 0 and service uid");
    let res = u.map(|nm| (nm.trim(), r(nm)));
    if eu == 0 {
        let u0 = "service uid is unknown, so only uid 0 is trusted";
        let m = match res {
            Some((nm, Some(id))) => format!("{tr} {id} (from {fk} '{nm}')"),
            Some((nm, None)) => format!("{fk} '{nm}' could not be resolved; {u0}"),
            None => format!("{u0} ({fk} is unset)"),
        };
        let out = format!("trusted-paths: running as root; {m}");
        return (res.and_then(|(_, id)| id), out);
    }
    if let Some((nm, Some(id))) = res
        && id != eu
    {
        let s = format!("checked as uid {eu}, but {fk} '{nm}' resolves to uid {id}; {tr} {id}");
        return (Some(id), format!("trusted-paths: {s}"));
    }
    let ex = match res {
        Some((nm, None)) => format!("; {fk} '{nm}' could not be resolved"),
        _ => String::new(),
    };
    let out = format!("trusted-paths: {tr} {eu} (effective uid of this check{ex})");
    (Some(eu), out)
}
pub(crate) fn check(out: &mut Vec<ConfigIssue>, l: &LoadedConfig, a: &CheckArgs) -> Vec<String> {
    let (cfg, euid) = (&l.config, rustix::process::geteuid().as_raw());
    let lu = |u: &str| resolve_unix_user_uid(u).ok();
    let (suid, onote) = obs(euid, cfg.server.sandbox.user.as_deref(), lu);
    let mis = suid.filter(|&id| euid != 0 && id != euid);
    let ru = |p| -> Option<u32> { std::fs::read_to_string(p).ok()?.trim().parse().ok() };
    let ov = ru("/proc/sys/kernel/overflowuid");
    let um = std::fs::read_to_string("/proc/self/uid_map");
    let id_ok = ov.is_some() && um.is_ok_and(|s| is_identity_uid_map(&s));
    let ps = ru("/proc/sys/fs/protected_symlinks").is_none_or(|v| v != 0);
    let (ctx, mut notes) = (Ctx(suid, id_ok, ov, ps), vec![onote, NARROWED.into()]);
    let mut chk = |k: &str, lb: &str, p: &Path, loc: bool, r: Result<u8, Fail>| {
        let mut fs = Vec::new();
        match r.and_then(|x| walk_at(&ctx, Path::new("/"), p, x)) {
            Ok(Some((pr, ms))) if mis.is_none() => {
                let (pd, rd, md) = (p.display(), pr.display(), ms.to_string_lossy());
                let pre = format!("trusted-paths: {lb} '{pd}': inspected existing prefix '{rd}'");
                let suf = format!("stopped at '{md}', not found by this lookup");
                notes.push(format!("{pre} ({suf})"));
            }
            Ok(_) => {}
            Err(f) => fs.push(f),
        }
        if let Some(su) = mis {
            let t = format!("but the configured service account is uid {su}");
            let m = format!("not verified: checked as uid {euid} {t}");
            fs.push(Fail(p.into(), None, m, 1));
        }
        for Fail(comp, meta, reason, fl) in fs {
            let (uk, pd, cd) = ("uid unknown, mode unknown", p.display(), comp.display());
            let m = meta.map_or_else(|| uk.into(), |(u, d)| format!("uid {u}, mode {d:04o}"));
            let help = if fl & 2 != 0 { HELP_PROD } else { HELP_GEN };
            out.push(ConfigIssue {
                code: "W034".into(),
                severity: Severity::Warning,
                message: format!("{lb} '{pd}': first untrusted component '{cd}' ({m}): {reason}"),
                path: Some(k.into()),
                help: Some(help.into()),
                label: None,
                location: if loc { l.location_for(k) } else { None },
            });
        }
    };
    let (tk, tl) = (
        "server.sandbox.socket-tree",
        "server.sandbox socket-tree root",
    );
    for t in &cfg.server.sandbox.socket_trees {
        let tp = t.trim_end_matches('/');
        let p = Path::new(if tp.is_empty() { t.as_str() } else { tp });
        chk(tk, tl, p, true, Ok(0));
    }
    for (i, s) in cfg.sites.iter().enumerate() {
        let h = s.hosts.first().map_or("<site>", String::as_str);
        for (j, r) in s.routes.iter().enumerate() {
            if let RouteHandler::FastCgi(f) = &r.handler
                && let FastCgiTarget::Unix { path } = &f.target
            {
                let k = format!("site[{i}].route[{j}].fastcgi-pass");
                let lb = format!("site '{h}' FastCGI Unix socket");
                chk(&k, &lb, Path::new(path), true, Ok(1));
            }
        }
        if let Some(st) = &s.ai_publish {
            let k = format!("site[{i}].ai-publish.storage");
            let lb = format!("site '{h}' ai-publish storage");
            chk(&k, &lb, Path::new(&st.storage), true, Ok(3));
        }
    }
    if let Some(s) = &cfg.server.tls.keyd_socket {
        let k = "server.tls.keyd-socket";
        match KeydEndpoint::parse(s) {
            Ok(KeydEndpoint::Unix(p)) => chk(k, k, &p, true, Ok(1)),
            Ok(KeydEndpoint::LoopbackTcp(_)) => {}
            Err(e) => chk(k, k, Path::new(s), true, Err(fin(Path::new(s), e))),
        }
    }
    let (ak, def) = ("server.tls.acme", Path::new(".miraserve-acme"));
    if a.acme_dir.is_some() || cfg.server.tls.acme.is_some() {
        let (ac, loc) = (a.acme_dir.as_deref().unwrap_or(def), a.acme_dir.is_none());
        chk(ak, "ACME directory", ac, loc, Ok(2));
    }
    for (o, k) in [(&a.log_file, "log-file"), (&a.access_log, "access-log")] {
        if let Some(p) = o.as_ref().filter(|_| a.log_max_bytes > 0) {
            let key = format!("server.{k}");
            let lb = format!("rotating --{k} parent directory");
            let (t, r) = if !p.as_os_str().as_bytes().starts_with(b"/") {
                (p.as_path(), Ok(3))
            } else if let Some(d) = p.parent().filter(|x| !x.as_os_str().is_empty()) {
                (d, Ok(3))
            } else {
                (p.as_path(), Err(fin(p, "log path has no parent directory")))
            };
            chk(&key, &lb, t, false, r);
        }
    }
    notes
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
    let fb = "could not be verified on this filesystem";
    let fse = |d: &str| Err(fst(p, &st, format!("{fb} ({d})"), 1));
    match (c.1, c.2 == Some(st.st_uid)) {
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
    let ft = FileType::from_raw_mode(st.st_mode);
    let fail = |r: String, fl| Err(fst(path, st, r, fl));
    match (leaf, ft) {
        (Some(1), FileType::Socket) => return Ok(false),
        (Some(1), _) => return fail("exists but is not a socket".into(), 0),
        (Some(_), FileType::Directory) | (None, _) => {}
        (Some(_), _) => return fail("exists but is not a directory".into(), 0),
    }
    let (uid, wr, stky) = (st.st_uid, st.st_mode & 0o022 != 0, st.st_mode & 0o1000 != 0);
    let unt = uid != 0 && ctx.0 != Some(uid);
    let unk = "not verified: service uid is unknown; cannot verify ACME directory owner";
    match (leaf, ctx.0, unt, wr) {
        (Some(2), None, _, _) => fail(unk.into(), 0),
        (Some(2), Some(s), _, _) if uid != s => {
            let m = format!("ACME directory must be owned by service uid {s} (owned by uid {uid})");
            fail(m, 0)
        }
        (Some(0), _, true, false) => fail(prod(uid), 2),
        (Some(0), _, true, true) => fail(format!("{TREE_WR}; {}", prod(uid)), 0),
        (Some(0), _, false, true) => fail(TREE_WR.into(), 0),
        (Some(0 | 2), _, _, false) => Ok(false),
        (_, _, true, _) => fail("owner not trusted".into(), 0),
        (_, _, _, true) if leaf.is_some() || !stky => fail("group or other writable".into(), 0),
        _ => Ok(wr && stky),
    }
}
#[allow(clippy::too_many_lines)]
fn walk_at(c: &Ctx, root: &Path, raw: &Path, role: u8) -> WalkRes {
    let (is_abs, mut pending) = split_segs(raw.as_os_str());
    let fnv = |r: &str| Err(Fail(raw.into(), None, r.into(), 1));
    let rel = "not verified: relative path depends on the working directory of the server";
    let dd = pending.iter().any(|s| s == "..");
    let rt = pending.iter().all(|s| s == ".");
    match (raw.as_os_str().is_empty(), is_abs, role == 2, dd, rt) {
        (true, _, _, _, _) => return Err(fin(raw, "empty path")),
        (_, false, _, _, _) => return fnv(rel),
        (_, _, true, true, _) => return fnv("private state path must not contain '..'"),
        (_, _, true, _, true) => return fnv("refusing filesystem root as private state path"),
        _ => {}
    }
    let rfd = op(CWD, root, OFlags::DIRECTORY).map_err(|e| fin(root, e))?;
    let (rst, rns) = inspect_fd(c, &rfd, root)?;
    let rsk = check_node(c, None, root, &rst)?;
    let mut stack = vec![Frame(rfd, root.into(), rst, rsk, rns)];
    let (mut hops, mut via, mut sym_rem) = (0_usize, None::<PathBuf>, 0_usize);
    let wrap = |v: &Option<PathBuf>, mut f: Fail| {
        if let (Some(l), 0) = (v, f.3 & 1) {
            f.2 = format!("{SYM_BAD} (via '{}': {})", l.display(), f.2);
        }
        f
    };
    let done = |p, st, v| {
        check_node(c, Some(role), p, st)
            .map(|_| None)
            .map_err(|f| wrap(v, f))
    };
    while let Some(seg) = pending.pop() {
        sym_rem = sym_rem.checked_sub(1).unwrap_or_else(|| {
            via = None;
            0
        });
        let Some(cur) = stack.last() else { break };
        if seg == "." {
            op(&cur.0, ".", OFlags::DIRECTORY).map_err(|e| fmeta(&cur.1, &cur.2, e))?;
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
        let cp = cur.1.join(&seg);
        let fd = match op(&cur.0, &seg, OFlags::NOFOLLOW) {
            Ok(fd) => fd,
            Err(Errno::NOENT) if cur.3 => {
                let m = "under a parent where another account could create it";
                let r = format!("missing component '{}' {m}", seg.to_string_lossy());
                return Err(wrap(&via, fst(&cur.1, &cur.2, r, 0)));
            }
            Err(Errno::NOENT) => return Ok(Some((cur.1.clone(), seg))),
            Err(e) => return Err(fin(&cp, e)),
        };
        let (st, nosym) = inspect_fd(c, &fd, &cp)?;
        let ft = FileType::from_raw_mode(st.st_mode);
        let is_sym = ft == FileType::Symlink;
        let is_leaf = !is_sym && pending.iter().all(|s| s == ".");
        if cur.3 && st.st_uid != 0 && c.0 != Some(st.st_uid) {
            let is_tr = is_leaf && role == 0 && ft == FileType::Directory;
            let (r, fl) = match (is_sym, is_tr, st.st_mode & 0o022 != 0) {
                (true, _, _) => (format!("{SYM_BAD} ({STKY_OWN})"), 0),
                (_, true, true) => (format!("{STKY_OWN}; {TREE_WR}; {}", prod(st.st_uid)), 0),
                (_, true, false) => (format!("{STKY_OWN}; {}", prod(st.st_uid)), 2),
                _ => ("owner not trusted".into(), 0),
            };
            return Err(wrap(&via, fst(&cp, &st, r, fl)));
        }
        if is_sym {
            let (sw, pu) = (cur.2.st_mode & 0o1002 == 0o1002, cur.2.st_uid);
            let unk = "not verified: service uid is unknown in sticky world-writable directory";
            let blk = "blocked by fs.protected_symlinks for service uid";
            if let Some(w) = match (role == 2, cur.4 || nosym, sw, c.0) {
                (true, _, _, _) => Some("symbolic links are not allowed for this role"),
                (_, true, _, _) => Some("mount has nosymfollow"),
                (_, _, true, None) => Some(unk),
                (_, _, true, Some(su)) if c.3 && st.st_uid != pu && st.st_uid != su => Some(blk),
                _ => None,
            } {
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
            sym_rem += tsegs.len();
            pending.extend(tsegs);
            continue;
        }
        if is_leaf {
            if !pending.is_empty() {
                op(&fd, ".", OFlags::DIRECTORY).map_err(|e| fmeta(&cp, &st, e))?;
            }
            return done(&cp, &st, &via);
        }
        if ft != FileType::Directory {
            return Err(fmeta(&cp, &st, Errno::NOTDIR));
        }
        let sticky = check_node(c, None, &cp, &st).map_err(|f| wrap(&via, f))?;
        stack.push(Frame(fd, cp, st, sticky, nosym));
    }
    let cur = stack.last().ok_or_else(|| fin(root, "empty walk stack"))?;
    done(&cur.1, &cur.2, &via)
}

#[cfg(test)]
#[path = "../tests/common/trusted_paths_unit.rs"]
mod unit_tests;

//! Strictly bounded local include resolver for Nginx and Apache file imports
//! (`R4-MIG-5`, `R5-MIG-5`, `R5-MIG-6`, `R5-MIG-7`).
//!
//! Only regular files confined within the imported config root directory are ever read;
//! parent traversal (`..`), escaping symlinks, non-regular files, cycles, excessive nesting
//! depth, excessive file counts, and excessive cumulative bytes are all rejected so callers
//! fail closed cleanly.

use std::collections::HashSet;
use std::fs;
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use crate::MAX_IMPORT_FILE_BYTES;

/// Maximum recursive include nesting depth.
pub(crate) const MAX_INCLUDE_DEPTH: usize = 8;

/// Maximum number of included files read across a single `miraserve import` invocation.
pub(crate) const MAX_INCLUDE_FILES: usize = 64;

/// Bounded state shared across recursive include expansion for one import.
#[derive(Debug)]
pub(crate) struct IncludeContext {
    /// Canonical root directory confining all readable includes (e.g. `/etc/nginx` or `/etc/httpd`).
    root_dir: PathBuf,
    /// Optional secondary search base (e.g. `/etc/httpd/conf` when `root_dir` is `/etc/httpd`).
    search_dir: PathBuf,
    /// Optional operator-supplied `--source-root` directory (`R7-MIG-13`) used to remap absolute
    /// include paths (such as `/etc/nginx/conf.d/*.conf`) inside a copied/uploaded config tree.
    source_root: Option<PathBuf>,
    depth: usize,
    files_read: usize,
    total_bytes: u64,
    active_stack: HashSet<PathBuf>,
}

/// Opens a canonicalized regular file without following any raced trailing symlink or blocking
/// on a raced FIFO/named pipe (`R7-MIG-15`).
pub(crate) fn open_regular_file_safe(canon_path: &Path) -> std::io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        #[cfg(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        ))]
        const FLAGS: i32 = 0x0004 | 0x0100; // O_NONBLOCK | O_NOFOLLOW
        #[cfg(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "arm")))]
        const FLAGS: i32 = 0x0800 | 0x8000; // O_NONBLOCK | O_NOFOLLOW
        #[cfg(all(
            target_os = "linux",
            not(any(target_arch = "aarch64", target_arch = "arm"))
        ))]
        const FLAGS: i32 = 0x0800 | 0x20000; // O_NONBLOCK | O_NOFOLLOW
        #[cfg(not(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly",
            target_os = "linux"
        )))]
        const FLAGS: i32 = 0;
        if FLAGS != 0 {
            opts.custom_flags(FLAGS);
        }
    }
    let file = opts.open(canon_path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "migration source path must be a regular file",
        ));
    }
    Ok(file)
}

/// Outcome of attempting to expand an `include` / `Include` / `IncludeOptional` directive on disk.
#[derive(Debug)]
pub(crate) enum BoundedIncludeResult {
    /// Target resolved safely inside the config root and all matching regular files were read.
    /// The vector may be empty when `optional == true` and the glob matched zero files in an
    /// existing directory under the config root.
    Expanded(Vec<(PathBuf, String)>),
    /// Target could not be resolved safely inside the config root, exceeded safety bounds,
    /// or caused an include cycle; caller must fall back to allow-list or fail closed.
    Unavailable,
}

impl IncludeContext {
    /// Creates a bounded include context anchored to the directory containing `source_path`.
    ///
    /// When `allow_parent_server_root` is `true` (Apache) and `source_path` resides inside a
    /// `conf/` subdirectory (such as RHEL `/etc/httpd/conf/httpd.conf`), the confining root is
    /// the parent directory (`/etc/httpd`) so `IncludeOptional conf.d/*.conf` resolves safely
    /// within the server root while still blocking all traversal outside it.
    pub(crate) fn from_source_path(
        source_path: &Path,
        allow_parent_server_root: bool,
        source_root: Option<&Path>,
    ) -> Option<Self> {
        let canon_file = fs::canonicalize(source_path).ok()?;
        let parent = canon_file.parent()?.to_path_buf();
        let canon_source_root = source_root.and_then(|sr| fs::canonicalize(sr).ok());
        let root_dir = if let Some(ref sr) = canon_source_root {
            sr.clone()
        } else if allow_parent_server_root
            && parent
                .file_name()
                .is_some_and(|n| n.eq_ignore_ascii_case("conf"))
            && let Some(grandparent) = parent.parent()
        {
            grandparent.to_path_buf()
        } else {
            parent.clone()
        };

        let mut active_stack = HashSet::new();
        active_stack.insert(canon_file);

        Some(Self {
            root_dir,
            search_dir: parent,
            source_root: canon_source_root,
            depth: 0,
            files_read: 0,
            total_bytes: 0,
            active_stack,
        })
    }

    /// Pushes `canon_path` onto the active include stack while expanding it.
    pub(crate) fn enter(&mut self, canon_path: PathBuf) -> bool {
        if self.depth >= MAX_INCLUDE_DEPTH || self.active_stack.contains(&canon_path) {
            return false;
        }
        self.depth = self.depth.saturating_add(1);
        self.active_stack.insert(canon_path);
        true
    }

    /// Pops `canon_path` from the active include stack once finished.
    pub(crate) fn leave(&mut self, canon_path: &Path) {
        self.active_stack.remove(canon_path);
        self.depth = self.depth.saturating_sub(1);
    }

    /// Attempts to expand `raw_target` (single file or single-directory `*` glob) strictly
    /// within `self.root_dir`.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn expand(&mut self, raw_target: &str, optional: bool) -> BoundedIncludeResult {
        if self.depth >= MAX_INCLUDE_DEPTH {
            return BoundedIncludeResult::Unavailable;
        }
        let clean = raw_target.trim().trim_matches('"').trim_matches('\'');
        if clean.is_empty() || clean.contains('\0') || clean.contains('\\') {
            return BoundedIncludeResult::Unavailable;
        }
        // Reject any `..` segment up front before touching the filesystem.
        for comp in Path::new(clean).components() {
            if matches!(comp, Component::ParentDir) {
                return BoundedIncludeResult::Unavailable;
            }
        }

        // Resolve candidate paths relative to search_dir / root_dir (or absolute inside root_dir,
        // remapping absolute server paths inside `--source-root` when provided, `R7-MIG-13`).
        // Recognize POSIX leading `/` as absolute on Windows too so `--source-root` remaps
        // Unix-style includes such as `/etc/nginx/conf.d/*.conf`.
        let candidate = if clean.starts_with('/') || Path::new(clean).is_absolute() {
            self.resolve_absolute_include_candidate(clean)
        } else {
            let in_search = join_relative_posix(&self.search_dir, clean);
            let in_root = join_relative_posix(&self.root_dir, clean);
            if candidate_parent_exists(&in_search) {
                in_search
            } else {
                in_root
            }
        };

        // Handle single-level wildcard glob in the filename segment (`dir/*.conf` or `dir/*`).
        // Check parent wildcards on the include target `clean` rather than `candidate`, because
        // Windows canonical verbatim paths (`\\?\C:\...`) always contain `?` in their prefix.
        let file_name = candidate.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let has_glob_in_name = file_name.contains('*') || file_name.contains('?');
        let parent_has_glob = Path::new(clean)
            .parent()
            .and_then(|p| p.to_str())
            .is_some_and(|s| s.contains('*') || s.contains('?'));
        if parent_has_glob {
            return BoundedIncludeResult::Unavailable;
        }

        if has_glob_in_name {
            let Some(dir) = candidate.parent() else {
                return BoundedIncludeResult::Unavailable;
            };
            let Ok(canon_dir) = fs::canonicalize(dir) else {
                return BoundedIncludeResult::Unavailable;
            };
            if !canon_dir.starts_with(&self.root_dir) || !canon_dir.is_dir() {
                return BoundedIncludeResult::Unavailable;
            }
            let Ok(entries) = fs::read_dir(&canon_dir) else {
                return BoundedIncludeResult::Unavailable;
            };
            let mut matched_paths: Vec<PathBuf> = Vec::new();
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name_str) = name.to_str() else {
                    continue;
                };
                if wildcard_match(file_name, name_str) {
                    matched_paths.push(entry.path());
                }
            }
            matched_paths.sort();

            let mut results = Vec::new();
            for path in matched_paths {
                let Some((canon, text)) = self.read_confined_file(&path) else {
                    return BoundedIncludeResult::Unavailable;
                };
                results.push((canon, text));
            }
            if results.is_empty() && !optional {
                return BoundedIncludeResult::Unavailable;
            }
            return BoundedIncludeResult::Expanded(results);
        }

        // Single file include (or directory include in Apache where a directory means all files inside).
        let Ok(canon) = fs::canonicalize(&candidate) else {
            return BoundedIncludeResult::Unavailable;
        };
        if !canon.starts_with(&self.root_dir) {
            return BoundedIncludeResult::Unavailable;
        }
        if canon.is_dir() {
            let Ok(entries) = fs::read_dir(&canon) else {
                return BoundedIncludeResult::Unavailable;
            };
            // R8-MIG-4: a directory-form `Include <dir>` makes the source server read the whole
            // tree: Apache descends into subdirectories and does not apply shell dotfile rules.
            // Reading only the top-level visible files would silently drop an ACL kept in
            // `conf.d/sub/acl.conf` or `conf.d/.acl.conf`. Rather than guess, a directory that
            // contains a subdirectory, a hidden entry or anything that is not a regular file is
            // reported as unavailable, which withholds the including scope.
            let mut files: Vec<PathBuf> = Vec::new();
            for entry in entries {
                let Ok(entry) = entry else {
                    return BoundedIncludeResult::Unavailable;
                };
                let hidden = entry
                    .file_name()
                    .to_str()
                    .is_none_or(|name| name.starts_with('.'));
                let path = entry.path();
                let is_plain_file = fs::symlink_metadata(&path).is_ok_and(|m| m.is_file());
                if hidden || !is_plain_file {
                    return BoundedIncludeResult::Unavailable;
                }
                files.push(path);
            }
            files.sort();
            let mut results = Vec::new();
            for path in files {
                let Some((c, text)) = self.read_confined_file(&path) else {
                    return BoundedIncludeResult::Unavailable;
                };
                results.push((c, text));
            }
            return BoundedIncludeResult::Expanded(results);
        }

        let Some((c, text)) = self.read_confined_file(&canon) else {
            return BoundedIncludeResult::Unavailable;
        };
        BoundedIncludeResult::Expanded(vec![(c, text)])
    }

    fn resolve_absolute_include_candidate(&self, clean: &str) -> PathBuf {
        const KNOWN_SERVER_PREFIXES: &[&str] = &[
            "/etc/nginx/",
            "/usr/local/etc/nginx/",
            "/etc/apache2/",
            "/private/etc/apache2/",
            "/etc/httpd/",
            "/usr/local/etc/httpd/",
            "/usr/local/lsws/conf/",
            "/usr/local/lsws/",
        ];
        if let Some(ref sr) = self.source_root {
            let rel_full = clean.trim_start_matches('/');
            let full_mapped = join_relative_posix(sr, rel_full);
            if candidate_parent_exists(&full_mapped) {
                return full_mapped;
            }
            for prefix in KNOWN_SERVER_PREFIXES {
                if let Some(rest) = clean.strip_prefix(prefix) {
                    let prefix_mapped = join_relative_posix(sr, rest);
                    if candidate_parent_exists(&prefix_mapped) {
                        return prefix_mapped;
                    }
                }
            }
            return full_mapped;
        }
        PathBuf::from(clean)
    }

    fn read_confined_file(&mut self, path: &Path) -> Option<(PathBuf, String)> {
        let canon = fs::canonicalize(path).ok()?;
        if !canon.starts_with(&self.root_dir) {
            return None;
        }
        if self.active_stack.contains(&canon) {
            return None;
        }
        if self.files_read >= MAX_INCLUDE_FILES {
            return None;
        }
        // R7-MIG-15: Open canonical target directly with `O_NOFOLLOW | O_NONBLOCK` and `fstat`
        // the resulting file descriptor so a raced FIFO or symlink swap can neither block nor escape!
        let file = open_regular_file_safe(&canon).ok()?;
        let meta = file.metadata().ok()?;
        let remaining = MAX_IMPORT_FILE_BYTES.saturating_sub(self.total_bytes);
        if meta.len() > remaining {
            return None;
        }
        let mut raw = Vec::new();
        file.take(remaining.saturating_add(1))
            .read_to_end(&mut raw)
            .ok()?;
        let len_u64 = raw.len() as u64;
        if len_u64 > remaining {
            return None;
        }
        let text = String::from_utf8(raw).ok()?;
        let stripped = text.strip_prefix('\u{FEFF}').unwrap_or(&text).to_owned();
        self.files_read = self.files_read.saturating_add(1);
        self.total_bytes = self.total_bytes.saturating_add(len_u64);
        Some((canon, stripped))
    }
}

/// Joins a POSIX-style relative include path (e.g. `conf.d/*.conf`) segment by segment onto
/// `base` so Windows verbatim paths (`\\?\C:\...`) receive native backslash separators rather
/// than forward slashes, which Win32 verbatim APIs do not normalize.
fn join_relative_posix(base: &Path, rel: &str) -> PathBuf {
    let mut out = base.to_path_buf();
    for seg in rel.split('/') {
        if !seg.is_empty() && seg != "." {
            out.push(seg);
        }
    }
    out
}

fn candidate_parent_exists(candidate: &Path) -> bool {
    if candidate.exists() {
        return true;
    }
    candidate.parent().is_some_and(Path::is_dir)
}

/// Simple `*` and `?` wildcard matcher on a single filename component (no regex dependency).
///
/// Follows POSIX `glob(3)` (`R7-MIG-6`): `*` and `?` NEVER match a leading `.` on hidden files
/// unless the pattern itself starts with `.`.
fn wildcard_match(pattern: &str, text: &str) -> bool {
    if text.starts_with('.') && !pattern.starts_with('.') {
        return false;
    }
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pat_idx, mut text_idx) = (0_usize, 0_usize);
    let mut star_pat: Option<usize> = None;
    let mut star_text: usize = 0;

    while let Some(&tc) = t.get(text_idx) {
        if p.get(pat_idx).is_some_and(|&pc| pc == '?' || pc == tc) {
            pat_idx = pat_idx.saturating_add(1);
            text_idx = text_idx.saturating_add(1);
        } else if p.get(pat_idx) == Some(&'*') {
            star_pat = Some(pat_idx);
            star_text = text_idx;
            pat_idx = pat_idx.saturating_add(1);
        } else if let Some(sp) = star_pat {
            pat_idx = sp.saturating_add(1);
            star_text = star_text.saturating_add(1);
            text_idx = star_text;
        } else {
            return false;
        }
    }
    while p.get(pat_idx) == Some(&'*') {
        pat_idx = pat_idx.saturating_add(1);
    }
    pat_idx == p.len()
}

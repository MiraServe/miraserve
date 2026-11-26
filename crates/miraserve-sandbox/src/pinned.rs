//! Pinned directory and file handles shared by Landlock rule installation, the CLI log writer,
//! and reload checks (Codex G7).
//!
//! - On Unix a [`PinnedWritableDir`] holds a no-follow directory descriptor (`O_PATH` on Linux, so
//!   reload identity checks and Landlock rules need no read right on the directory) plus its
//!   `(st_dev, st_ino)` identity. Log files are opened, inspected and renamed relative to it.
//! - On Windows it holds a handle to every path component below the drive root, each opened
//!   without `FILE_SHARE_DELETE` and validated as a non-reparse directory, so neither the directory
//!   nor any ancestor can be renamed, deleted or replaced while the handle is alive.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use miraserve_config::Config;

use crate::{
    SandboxError, find_docroot_log_overlaps, log_path_platform_rejection, make_abs_path,
    normalize_overlap_path, normalized_path_starts_with, normalized_paths_equal,
    normalized_paths_overlap,
};

/// Validated directory handle pinned during policy construction so Landlock rule installation,
/// log file opens and reload checks all bind to the exact same validated directory rather than
/// reopening it by pathname (Codex G7).
#[derive(Debug, Clone)]
pub struct PinnedWritableDir {
    /// Canonical path validated when this handle was acquired.
    pub path: PathBuf,
    #[cfg(unix)]
    pub(crate) file: Arc<std::fs::File>,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    /// Handles to every component below the root, opened with a share-check-participating
    /// access right (`FILE_LIST_DIRECTORY`) and without `FILE_SHARE_DELETE`.
    #[cfg(windows)]
    chain: Arc<Vec<std::fs::File>>,
    /// NTFS volume serial number of the pinned directory.
    #[cfg(windows)]
    volume: u64,
    /// NTFS file index (file ID) of the pinned directory.
    #[cfg(windows)]
    index: u64,
}

impl PartialEq for PinnedWritableDir {
    fn eq(&self, other: &Self) -> bool {
        #[cfg(unix)]
        {
            self.path == other.path && self.dev == other.dev && self.ino == other.ino
        }
        #[cfg(windows)]
        {
            normalized_paths_equal(&self.path, &other.path)
                && self.volume == other.volume
                && self.index == other.index
        }
        #[cfg(not(any(unix, windows)))]
        {
            normalized_paths_equal(&self.path, &other.path)
        }
    }
}

impl Eq for PinnedWritableDir {}

impl PinnedWritableDir {
    /// Opens `canonical_dir` component-by-component without following symlinks and records its
    /// device/inode identity.
    ///
    /// # Errors
    /// Returns [`SandboxError::Landlock`] if the directory cannot be opened without following
    /// symlinks or is not a directory.
    #[cfg(unix)]
    pub fn open_validated(canonical_dir: &Path) -> Result<Self, SandboxError> {
        let (file, dev, ino) = open_dir_no_follow(canonical_dir).map_err(|err| {
            SandboxError::Landlock(format!(
                "failed to pin validated writable directory '{}': {err}",
                canonical_dir.display()
            ))
        })?;
        Ok(Self {
            path: canonical_dir.to_path_buf(),
            file: Arc::new(file),
            dev,
            ino,
        })
    }

    /// Opens and locks every component of `canonical_dir` below the drive root and records the
    /// directory's NTFS file ID (Codex Round-6 P1).
    ///
    /// Each component is opened with `FILE_LIST_DIRECTORY` (a data-access right, so the open
    /// participates in NTFS share checks) and WITHOUT `FILE_SHARE_DELETE`: any later open that
    /// requests `DELETE` - needed to rename or delete the directory or an ancestor - fails with a
    /// sharing violation while the pin is alive. The service account needs list rights on every
    /// component. Identity checks compare the volume serial number and file ID.
    ///
    /// # Errors
    /// Returns [`SandboxError::Landlock`] if any component is a reparse point, is not a
    /// directory, is a network share or unsupported namespace, or cannot be opened and locked.
    #[cfg(windows)]
    pub fn open_validated(canonical_dir: &Path) -> Result<Self, SandboxError> {
        if let Some(reason) = log_path_platform_rejection(canonical_dir) {
            return Err(SandboxError::Landlock(reason));
        }
        let norm = normalize_overlap_path(canonical_dir);
        if let Some(reason) = log_path_platform_rejection(&norm) {
            return Err(SandboxError::Landlock(reason));
        }
        let chain = windows_lock_dir_chain(&norm)?;
        let leaf = chain.last().ok_or_else(|| {
            SandboxError::Landlock(format!(
                "refusing to pin filesystem root '{}'",
                norm.display()
            ))
        })?;
        let info = winapi_util::file::information(leaf).map_err(|err| {
            SandboxError::Landlock(format!(
                "failed to read file ID of pinned directory '{}': {err}",
                norm.display()
            ))
        })?;
        Ok(Self {
            path: norm,
            volume: info.volume_serial_number(),
            index: info.file_index(),
            chain: Arc::new(chain),
        })
    }

    /// Fallback for targets that are neither Unix nor Windows.
    ///
    /// # Errors
    /// Returns [`SandboxError::Landlock`] if `canonical_dir` is not an existing directory.
    #[cfg(not(any(unix, windows)))]
    pub fn open_validated(canonical_dir: &Path) -> Result<Self, SandboxError> {
        if !canonical_dir.is_dir() {
            return Err(SandboxError::Landlock(format!(
                "writable directory '{}' does not exist or is not a directory",
                canonical_dir.display()
            )));
        }
        Ok(Self {
            path: canonical_dir.to_path_buf(),
        })
    }

    /// Returns the pinned `(st_dev, st_ino)` directory identity on Unix.
    #[cfg(unix)]
    #[must_use]
    pub const fn inode_identity(&self) -> (u64, u64) {
        (self.dev, self.ino)
    }

    /// Opens or creates a regular file `file_name` directly inside this pinned directory in append
    /// mode WITHOUT following symlinks and validates the opened handle is a regular file.
    ///
    /// # Errors
    /// Returns an I/O error if `file_name` is invalid, is a symbolic link / reparse point / FIFO /
    /// directory, or cannot be opened.
    pub fn open_append_regular(&self, file_name: &OsStr) -> std::io::Result<std::fs::File> {
        validate_single_file_name(file_name)?;
        #[cfg(unix)]
        {
            use rustix::fs::{Mode, OFlags, openat};

            // Read access as well where the file allows it, so the caller can check how the
            // file ends through this very handle (a log left mid-line by a full disk). A
            // write-only file is still opened for appending.
            let flags = OFlags::APPEND
                | OFlags::CREATE
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | OFlags::NONBLOCK;
            let mode = Mode::from_raw_mode(0o640);
            let fd = openat(&*self.file, file_name, flags | OFlags::RDWR, mode)
                .or_else(|err| {
                    if err == rustix::io::Errno::ACCESS || err == rustix::io::Errno::PERM {
                        openat(&*self.file, file_name, flags | OFlags::WRONLY, mode)
                    } else {
                        Err(err)
                    }
                })
                .map_err(|err| {
                    std::io::Error::new(
                        std::io::Error::from(err).kind(),
                        format!(
                            "refusing to open log '{}' inside pinned directory '{}': {err}",
                            file_name.to_string_lossy(),
                            self.path.display()
                        ),
                    )
                })?;
            let file = std::fs::File::from(fd);
            let meta = file.metadata()?;
            if !meta.file_type().is_file() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "refusing to write logs to non-regular file '{}' inside '{}'",
                        file_name.to_string_lossy(),
                        self.path.display()
                    ),
                ));
            }
            Ok(file)
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};

            self.verify_identity().map_err(|err| {
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, err.to_string())
            })?;
            // Every component of `self.path` is held open without `FILE_SHARE_DELETE`, so this
            // pathname resolves through the locked, validated directory chain.
            let full = self.path.join(file_name);
            let open = |read: bool| {
                std::fs::OpenOptions::new()
                    .read(read)
                    .create(true)
                    .append(true)
                    .custom_flags(win::FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(&full)
            };
            // Read access as well where allowed, so how the file ends can be checked through
            // this handle.
            let file = open(true).or_else(|_| open(false))?;
            let meta = file.metadata()?;
            if (u64::from(meta.file_attributes()) & win::FILE_ATTRIBUTE_REPARSE_POINT) != 0
                || !meta.is_file()
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "refusing to write logs to reparse-point/non-regular path '{}'",
                        full.display()
                    ),
                ));
            }
            Ok(file)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let full = self.path.join(file_name);
            if let Ok(md) = std::fs::symlink_metadata(&full)
                && (md.file_type().is_symlink() || !md.file_type().is_file())
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "refusing to write logs to non-regular/symlink path '{}'",
                        full.display()
                    ),
                ));
            }
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&full)
        }
    }

    /// Returns `true` if `file_name` inside this pinned directory exists and is a symbolic link
    /// (or reparse point), without following it.
    ///
    /// # Errors
    /// Returns an I/O error if `file_name` is invalid or the lookup fails with an error other than
    /// "not found".
    pub fn is_symlink_entry(&self, file_name: &OsStr) -> std::io::Result<bool> {
        validate_single_file_name(file_name)?;
        #[cfg(unix)]
        {
            use rustix::fs::{AtFlags, FileType, statat};

            match statat(&*self.file, file_name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(st) => Ok(FileType::from_raw_mode(st.st_mode) == FileType::Symlink),
                Err(rustix::io::Errno::NOENT) => Ok(false),
                Err(err) => Err(std::io::Error::from(err)),
            }
        }
        #[cfg(not(unix))]
        {
            match std::fs::symlink_metadata(self.path.join(file_name)) {
                Ok(md) => Ok(md.file_type().is_symlink()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(err) => Err(err),
            }
        }
    }

    /// Returns `true` if `file_name` exists inside this pinned directory (without following
    /// symlinks).
    ///
    /// # Errors
    /// Returns an I/O error if `file_name` is invalid or the lookup fails with an error other than
    /// "not found".
    pub fn entry_exists(&self, file_name: &OsStr) -> std::io::Result<bool> {
        validate_single_file_name(file_name)?;
        #[cfg(unix)]
        {
            use rustix::fs::{AtFlags, statat};

            match statat(&*self.file, file_name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(_) => Ok(true),
                Err(rustix::io::Errno::NOENT) => Ok(false),
                Err(err) => Err(std::io::Error::from(err)),
            }
        }
        #[cfg(not(unix))]
        {
            match std::fs::symlink_metadata(self.path.join(file_name)) {
                Ok(_) => Ok(true),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(err) => Err(err),
            }
        }
    }

    /// Renames `old_name` to `new_name` inside this pinned directory (`renameat` on Unix; on
    /// Windows through the locked directory chain).
    ///
    /// # Errors
    /// Returns an I/O error if either filename is invalid or the rename fails.
    pub fn rename_entry(&self, old_name: &OsStr, new_name: &OsStr) -> std::io::Result<()> {
        validate_single_file_name(old_name)?;
        validate_single_file_name(new_name)?;
        #[cfg(unix)]
        {
            rustix::fs::renameat(&*self.file, old_name, &*self.file, new_name)
                .map_err(std::io::Error::from)
        }
        #[cfg(not(unix))]
        {
            #[cfg(windows)]
            self.verify_identity().map_err(|err| {
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, err.to_string())
            })?;
            std::fs::rename(self.path.join(old_name), self.path.join(new_name))
        }
    }

    /// Verifies that the pinned handle AND the directory currently at [`Self::path`] still have
    /// the validated identity (Unix `(st_dev, st_ino)`; Windows locked non-reparse chain).
    ///
    /// # Errors
    /// Returns [`SandboxError::Landlock`] if the handle or path changed identity or became a
    /// symlink / reparse point.
    pub fn verify_identity(&self) -> Result<(), SandboxError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;

            let fd_meta = self.file.metadata().map_err(|err| {
                SandboxError::Landlock(format!(
                    "failed to inspect pinned directory '{}': {err}",
                    self.path.display()
                ))
            })?;
            if !fd_meta.is_dir() || fd_meta.dev() != self.dev || fd_meta.ino() != self.ino {
                return Err(SandboxError::Landlock(format!(
                    "pinned directory handle '{}' changed identity",
                    self.path.display()
                )));
            }
            let (_, cur_dev, cur_ino) = open_dir_no_follow(&self.path).map_err(|err| {
                SandboxError::Landlock(format!(
                    "pinned directory '{}' is no longer reachable without following symlinks: {err}",
                    self.path.display()
                ))
            })?;
            if cur_dev != self.dev || cur_ino != self.ino {
                return Err(SandboxError::Landlock(format!(
                    "directory '{}' changed identity since it was validated (dev={}, ino={} -> dev={}, ino={})",
                    self.path.display(),
                    self.dev,
                    self.ino,
                    cur_dev,
                    cur_ino
                )));
            }
        }
        #[cfg(windows)]
        {
            for handle in self.chain.iter() {
                let info = winapi_util::file::information(handle).map_err(|err| {
                    SandboxError::Landlock(format!(
                        "failed to inspect pinned directory chain for '{}': {err}",
                        self.path.display()
                    ))
                })?;
                let attrs = info.file_attributes();
                if (attrs & win::FILE_ATTRIBUTE_REPARSE_POINT) != 0
                    || (attrs & win::FILE_ATTRIBUTE_DIRECTORY) == 0
                {
                    return Err(SandboxError::Landlock(format!(
                        "pinned directory chain for '{}' changed identity",
                        self.path.display()
                    )));
                }
            }
            let current = windows_probe_identity(&self.path, false).map_err(|err| {
                SandboxError::Landlock(format!(
                    "pinned directory '{}' is no longer reachable: {err}",
                    self.path.display()
                ))
            })?;
            if current.reparse
                || !current.dir
                || current.volume != self.volume
                || current.index != self.index
            {
                return Err(SandboxError::Landlock(format!(
                    "directory '{}' changed identity since it was validated (file ID {:x}:{:x} -> {:x}:{:x})",
                    self.path.display(),
                    self.volume,
                    self.index,
                    current.volume,
                    current.index
                )));
            }
        }
        Ok(())
    }

    /// Verifies that `configured_log_path` still resolves to this exact pinned directory
    /// (detecting a configured alias that moved after validation — Codex Round-4 P1 #3).
    ///
    /// # Errors
    /// Returns a descriptive error if the configured log path became a symlink, changed its
    /// canonical parent directory, or changed directory identity.
    pub fn matches_configured_log_path(&self, configured_log_path: &Path) -> Result<(), String> {
        self.verify_identity().map_err(|err| err.to_string())?;
        let abs_log = make_abs_path(configured_log_path);
        if std::fs::symlink_metadata(&abs_log).is_ok_and(|md| md.file_type().is_symlink()) {
            return Err(format!(
                "configured log path '{}' became a symbolic link after it was validated",
                configured_log_path.display()
            ));
        }
        let parent = abs_log
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| {
                format!(
                    "configured log path '{}' has no parent directory",
                    configured_log_path.display()
                )
            })?;
        let cur_real_parent = normalize_overlap_path(parent);
        if !normalized_paths_equal(&cur_real_parent, &self.path) {
            return Err(format!(
                "configured log path '{}' changed directory from validated '{}' to '{}'; restart MiraServe instead of reloading",
                configured_log_path.display(),
                self.path.display(),
                cur_real_parent.display()
            ));
        }
        #[cfg(unix)]
        {
            let (_, cur_dev, cur_ino) = open_dir_no_follow(&cur_real_parent).map_err(|err| {
                format!(
                    "configured log directory '{}' is no longer reachable without symlinks: {err}",
                    cur_real_parent.display()
                )
            })?;
            if cur_dev != self.dev || cur_ino != self.ino {
                return Err(format!(
                    "configured log path '{}' changed directory identity since it was validated; restart MiraServe instead of reloading",
                    configured_log_path.display()
                ));
            }
        }
        Ok(())
    }

    /// Returns `true` if `candidate` overlaps this pinned directory in either direction, by
    /// normalized path or (on Unix) by directory identity.
    #[must_use]
    pub fn overlaps_candidate_path(&self, candidate: &Path) -> bool {
        let norm_cand = normalize_overlap_path(candidate);
        normalized_paths_overlap(&norm_cand, &self.path) || self.has_same_identity(&norm_cand)
    }

    /// Returns `true` if this pinned directory is `candidate` or lies beneath it, i.e. a file in
    /// this directory would be served from a document root at `candidate`.
    #[must_use]
    pub fn is_within_candidate_path(&self, candidate: &Path) -> bool {
        let norm_cand = normalize_overlap_path(candidate);
        normalized_path_starts_with(&self.path, &norm_cand) || self.has_same_identity(&norm_cand)
    }

    #[cfg_attr(not(unix), allow(clippy::unused_self))]
    fn has_same_identity(&self, candidate: &Path) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;

            std::fs::metadata(candidate)
                .is_ok_and(|md| md.dev() == self.dev && md.ino() == self.ino)
        }
        #[cfg(not(unix))]
        {
            let _ = candidate;
            false
        }
    }
}

/// A configured CLI log path bound to the exact validated directory handle its writer uses, so
/// startup, the writer and every reload agree on one directory identity (Codex Round-5 P1 #1).
#[derive(Debug, Clone)]
pub struct PinnedLogDir {
    /// Log path exactly as configured on the command line.
    pub configured_path: PathBuf,
    /// Final path component opened relative to [`Self::dir`].
    pub file_name: OsString,
    /// Validated directory handle the log file lives in.
    pub dir: PinnedWritableDir,
    /// Whether size-based rotation (and therefore a directory-wide write grant) is enabled.
    pub rotating: bool,
}

impl PinnedLogDir {
    /// Associates `configured_path` with its validated directory handle.
    ///
    /// # Errors
    /// Returns an error if `configured_path` has no file name.
    pub fn new(
        configured_path: &Path,
        dir: PinnedWritableDir,
        rotating: bool,
    ) -> Result<Self, String> {
        let file_name = configured_path
            .file_name()
            .filter(|n| !n.is_empty())
            .ok_or_else(|| format!("log path '{}' has no file name", configured_path.display()))?
            .to_os_string();
        Ok(Self {
            configured_path: configured_path.to_path_buf(),
            file_name,
            dir,
            rotating,
        })
    }

    /// Verifies the configured path still resolves to the validated directory.
    ///
    /// # Errors
    /// Returns a descriptive error if the destination changed.
    pub fn verify_configured_destination(&self) -> Result<(), String> {
        self.dir.matches_configured_log_path(&self.configured_path)
    }

    /// Returns `true` if serving `docroot` would conflict with this log.
    ///
    /// A rotating log's directory carries a directory-wide write grant, so any overlap in either
    /// direction conflicts. A non-rotating log only conflicts when the file itself would be
    /// inside the served tree (Codex Round-5 P2).
    #[must_use]
    pub fn conflicts_with_docroot(&self, docroot: &Path) -> bool {
        if self.rotating {
            self.dir.overlaps_candidate_path(docroot)
        } else {
            self.dir.is_within_candidate_path(docroot)
        }
    }
}

/// Result of validating a configured log destination: the canonical directory that was
/// validated, plus its pinned handle when the directory already exists.
#[derive(Debug, Clone)]
pub struct LogDirBinding {
    /// Canonical parent directory the checks ran against.
    pub real_parent: PathBuf,
    /// Pinned handle for [`Self::real_parent`] (`None` while the directory does not exist yet).
    pub pinned: Option<PinnedWritableDir>,
}

/// Validates a NON-rotating log destination and pins its parent directory when it exists.
///
/// Rejects platform-unsupported destinations (network shares on Windows), a symlinked log file,
/// and a log FILE inside a served document root. A non-rotating log needs no directory-wide write
/// grant, so a private log beside (not inside) a site root is accepted.
///
/// # Errors
/// Returns a descriptive reason if the destination is unsafe or cannot be pinned.
pub fn bind_log_file_dir(log_path: &Path, config: &Config) -> Result<LogDirBinding, String> {
    if let Some(reason) = log_path_platform_rejection(log_path) {
        return Err(reason);
    }
    let abs = make_abs_path(log_path);
    let file_name = abs
        .file_name()
        .filter(|n| !n.is_empty())
        .ok_or_else(|| format!("log path '{}' has no file name", log_path.display()))?;
    let parent = abs
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| format!("log path '{}' has no parent directory", log_path.display()))?;
    let real_parent = normalize_overlap_path(parent);
    let overlaps = find_docroot_log_overlaps(config, &[real_parent.join(file_name)], &[]);
    if !overlaps.is_empty() {
        return Err(overlaps.join("; "));
    }
    if !real_parent.is_dir() {
        return Ok(LogDirBinding {
            real_parent,
            pinned: None,
        });
    }
    let dir = PinnedWritableDir::open_validated(&real_parent).map_err(|err| err.to_string())?;
    Ok(LogDirBinding {
        real_parent,
        pinned: Some(dir),
    })
}

/// A read-only path validated with the tenant-file no-follow rule and pinned so the Linux
/// Landlock rule is installed from the validated identity (Codex Round-5 P1 #2).
#[derive(Debug, Clone)]
pub struct PinnedReadOnlyPath {
    /// Path recorded in [`crate::SandboxPolicy::read_only_paths`] for this pin.
    pub path: PathBuf,
    /// Whether the pin is a directory (`true`) or an exact file (`false`).
    pub is_dir: bool,
    #[cfg(target_os = "linux")]
    pub(crate) file: Arc<std::fs::File>,
    /// `(st_dev, st_ino)` of the pinned object, compared on reload (Codex Round-6 P1 #4).
    #[cfg(target_os = "linux")]
    pub(crate) identity: (u64, u64),
}

impl PinnedReadOnlyPath {
    /// Returns `true` if the Landlock rule installed from this pin covers `candidate` as it
    /// exists NOW: the candidate (exact-file pin) or the candidate or one of its existing
    /// ancestors (directory pin) must still be the pinned object, compared by identity rather
    /// than by name. A directory or file replaced at the same name is therefore NOT covered.
    #[must_use]
    pub fn covers_by_identity(&self, candidate: &Path) -> bool {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt as _;

            let id_of = |p: &Path| std::fs::metadata(p).ok().map(|md| (md.dev(), md.ino()));
            if !self.is_dir {
                return id_of(candidate) == Some(self.identity);
            }
            let real = normalize_overlap_path(candidate);
            real.ancestors()
                .any(|anc| id_of(anc) == Some(self.identity))
        }
        #[cfg(not(target_os = "linux"))]
        {
            // No identity-installed rules exist off Linux; fall back to name coverage.
            let real = normalize_overlap_path(candidate);
            let pinned = normalize_overlap_path(&self.path);
            if self.is_dir {
                normalized_path_starts_with(&real, &pinned)
            } else {
                normalized_paths_equal(&real, &pinned)
            }
        }
    }
}

impl PartialEq for PinnedReadOnlyPath {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path && self.is_dir == other.is_dir
    }
}

impl Eq for PinnedReadOnlyPath {}

/// A tenant-controlled file (absolute custom error page or WASM module) that passed the exact
/// no-follow rule used by the error-page and WASM loaders: no symlink or reparse point in any
/// component and a regular-file leaf.
#[derive(Debug)]
pub(crate) struct ValidatedTenantFile {
    /// Canonical parent directory (used by the rotating-log protection check).
    pub(crate) canonical_parent: PathBuf,
    #[cfg(target_os = "linux")]
    parent_fd: std::fs::File,
    #[cfg(target_os = "linux")]
    parent_id: (u64, u64),
    #[cfg(target_os = "linux")]
    file_fd: std::fs::File,
    #[cfg(target_os = "linux")]
    file_id: (u64, u64),
}

impl ValidatedTenantFile {
    /// Converts into a directory pin recorded under `configured_parent`.
    #[cfg_attr(not(target_os = "linux"), allow(clippy::unused_self))]
    pub(crate) fn into_parent_pin(self, configured_parent: &Path) -> PinnedReadOnlyPath {
        PinnedReadOnlyPath {
            path: configured_parent.to_path_buf(),
            is_dir: true,
            #[cfg(target_os = "linux")]
            file: Arc::new(self.parent_fd),
            #[cfg(target_os = "linux")]
            identity: self.parent_id,
        }
    }

    /// Converts into an exact-file pin recorded under `configured_file`.
    #[cfg_attr(not(target_os = "linux"), allow(clippy::unused_self))]
    pub(crate) fn into_file_pin(self, configured_file: &Path) -> PinnedReadOnlyPath {
        PinnedReadOnlyPath {
            path: configured_file.to_path_buf(),
            is_dir: false,
            #[cfg(target_os = "linux")]
            file: Arc::new(self.file_fd),
            #[cfg(target_os = "linux")]
            identity: self.file_id,
        }
    }
}

/// Applies the tenant-file no-follow rule to the absolute path `path`, returning `None` when the
/// loaders would refuse it (symlink or reparse point in any component, missing, or non-regular).
pub(crate) fn validate_tenant_file(path: &Path) -> Option<ValidatedTenantFile> {
    if !path.is_absolute() {
        return None;
    }
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty())?;
    let leaf = path.file_name()?;
    #[cfg(unix)]
    {
        let (parent_fd, parent_dev, parent_ino) = open_dir_no_follow(parent).ok()?;
        #[cfg(target_os = "linux")]
        {
            use rustix::fs::{Mode, OFlags, openat};
            use std::os::unix::fs::MetadataExt as _;

            // `O_PATH | O_NOFOLLOW` opens a symlink leaf itself, which the regular-file check
            // below then rejects; a FIFO leaf is never opened for I/O.
            let fd = openat(
                &parent_fd,
                leaf,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .ok()?;
            let file_fd = std::fs::File::from(fd);
            let leaf_meta = file_fd.metadata().ok()?;
            if !leaf_meta.file_type().is_file() {
                return None;
            }
            Some(ValidatedTenantFile {
                canonical_parent: normalize_overlap_path(parent),
                parent_fd,
                parent_id: (parent_dev, parent_ino),
                file_fd,
                file_id: (leaf_meta.dev(), leaf_meta.ino()),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            use rustix::fs::{AtFlags, FileType, statat};

            let _ = (parent_dev, parent_ino);
            let st = statat(&parent_fd, leaf, AtFlags::SYMLINK_NOFOLLOW).ok()?;
            if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
                return None;
            }
            Some(ValidatedTenantFile {
                canonical_parent: normalize_overlap_path(parent),
            })
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};

        drop(windows_lock_dir_chain(parent).ok()?);
        let file = std::fs::OpenOptions::new()
            .access_mode(win::FILE_READ_ATTRIBUTES)
            .custom_flags(win::FILE_FLAG_OPEN_REPARSE_POINT)
            .open(parent.join(leaf))
            .ok()?;
        let md = file.metadata().ok()?;
        if (u64::from(md.file_attributes()) & win::FILE_ATTRIBUTE_REPARSE_POINT) != 0
            || !md.is_file()
        {
            return None;
        }
        Some(ValidatedTenantFile {
            canonical_parent: normalize_overlap_path(parent),
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = leaf;
        let md = std::fs::symlink_metadata(path).ok()?;
        if md.file_type().is_symlink() || !md.file_type().is_file() {
            return None;
        }
        Some(ValidatedTenantFile {
            canonical_parent: normalize_overlap_path(parent),
        })
    }
}

pub(crate) fn validate_single_file_name(file_name: &OsStr) -> std::io::Result<()> {
    let p = Path::new(file_name);
    let mut comps = p.components();
    match (comps.next(), comps.next()) {
        (Some(std::path::Component::Normal(_)), None) => Ok(()),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "log file name '{}' must be a single path component without separators",
                file_name.to_string_lossy()
            ),
        )),
    }
}

/// Opens the absolute directory `path` one component at a time without following symlinks
/// (except the macOS `/var` and `/tmp` OS root links) and returns it with its identity.
///
/// On Linux every component, including the leaf, is opened with `O_PATH`: the handle carries
/// identity only, so re-checking it on reload needs no Landlock read right on the directory, and
/// it remains valid as the `*at()` base and as a Landlock `PathBeneath` parent.
#[cfg(unix)]
pub(crate) fn open_dir_no_follow(path: &Path) -> Result<(std::fs::File, u64, u64), String> {
    use rustix::fs::{CWD, Mode, OFlags, openat};
    use std::os::unix::fs::MetadataExt as _;
    use std::path::Component;

    if !path.is_absolute() {
        return Err(format!("path '{}' must be absolute", path.display()));
    }
    let mut segments: Vec<&OsStr> = Vec::new();
    for comp in path.components() {
        match comp {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                return Err(format!(
                    "path '{}' contains disallowed traversal component",
                    path.display()
                ));
            }
            Component::Normal(seg) => segments.push(seg),
        }
    }

    #[cfg(target_os = "linux")]
    let step_base = OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let step_base = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;

    let mut dir_fd = openat(CWD, "/", step_base, Mode::empty())
        .map_err(|err| format!("failed to open '/': {err}"))?;

    for (idx, seg) in segments.iter().enumerate() {
        #[cfg(target_os = "macos")]
        let flags = if idx == 0 && (*seg == OsStr::new("var") || *seg == OsStr::new("tmp")) {
            step_base
        } else {
            step_base | OFlags::NOFOLLOW
        };
        #[cfg(not(target_os = "macos"))]
        let flags = {
            let _ = idx;
            step_base | OFlags::NOFOLLOW
        };
        dir_fd = openat(&dir_fd, *seg, flags, Mode::empty()).map_err(|err| {
            format!(
                "component '{}' is a symlink or inaccessible: {err}",
                seg.to_string_lossy()
            )
        })?;
    }

    let file = std::fs::File::from(dir_fd);
    let meta = file
        .metadata()
        .map_err(|err| format!("failed to fstat directory: {err}"))?;
    if !meta.is_dir() {
        return Err(format!("path '{}' is not a directory", path.display()));
    }
    Ok((file, meta.dev(), meta.ino()))
}

#[cfg(windows)]
pub(crate) mod win {
    pub(crate) const FILE_LIST_DIRECTORY: u32 = 0x0000_0001;
    pub(crate) const FILE_TRAVERSE: u32 = 0x0000_0020;
    pub(crate) const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
    pub(crate) const FILE_SHARE_READ: u32 = 0x0000_0001;
    pub(crate) const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    pub(crate) const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    pub(crate) const FILE_ATTRIBUTE_DIRECTORY: u64 = 0x0000_0010;
    pub(crate) const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    pub(crate) const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    pub(crate) const FILE_ATTRIBUTE_REPARSE_POINT: u64 = 0x0000_0400;
}

/// Identity of a path probed with an attributes-only open (never blocks or locks anything).
#[cfg(windows)]
struct WindowsIdentity {
    volume: u64,
    index: u64,
    reparse: bool,
    dir: bool,
}

#[cfg(windows)]
fn windows_probe_identity(path: &Path, follow: bool) -> std::io::Result<WindowsIdentity> {
    use std::os::windows::fs::OpenOptionsExt as _;

    let mut flags = win::FILE_FLAG_BACKUP_SEMANTICS;
    if !follow {
        flags |= win::FILE_FLAG_OPEN_REPARSE_POINT;
    }
    let probe = std::fs::OpenOptions::new()
        .access_mode(win::FILE_READ_ATTRIBUTES)
        .share_mode(win::FILE_SHARE_READ | win::FILE_SHARE_WRITE | win::FILE_SHARE_DELETE)
        .custom_flags(flags)
        .open(path)?;
    let info = winapi_util::file::information(&probe)?;
    let attrs = info.file_attributes();
    Ok(WindowsIdentity {
        volume: info.volume_serial_number(),
        index: info.file_index(),
        reparse: (attrs & win::FILE_ATTRIBUTE_REPARSE_POINT) != 0,
        dir: (attrs & win::FILE_ATTRIBUTE_DIRECTORY) != 0,
    })
}

/// Opens every component of the absolute directory `dir` below its root without following
/// reparse points and WITHOUT `FILE_SHARE_DELETE`, validating each is a non-reparse directory.
///
/// While the returned handles are alive no component can be renamed, deleted or replaced, so
/// pathname operations beneath `dir` resolve through the validated chain.
#[cfg(windows)]
pub(crate) fn windows_lock_dir_chain(dir: &Path) -> Result<Vec<std::fs::File>, SandboxError> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use std::path::Component;

    if !dir.is_absolute() {
        return Err(SandboxError::Landlock(format!(
            "directory '{}' must be absolute",
            dir.display()
        )));
    }
    let mut cur = PathBuf::new();
    let mut chain = Vec::new();
    for comp in dir.components() {
        match comp {
            Component::Prefix(_) | Component::RootDir => {
                cur.push(comp.as_os_str());
                continue;
            }
            Component::CurDir => continue,
            Component::ParentDir => {
                return Err(SandboxError::Landlock(format!(
                    "directory '{}' contains a parent traversal component",
                    dir.display()
                )));
            }
            Component::Normal(seg) => cur.push(seg),
        }
        // `FILE_LIST_DIRECTORY` is a data-access right, so this open takes part in NTFS share
        // checks: with `FILE_SHARE_DELETE` withheld, a later DELETE-access open (rename/delete of
        // this component) fails while the handle lives (Codex Round-6 P1).
        let handle = std::fs::OpenOptions::new()
            .access_mode(win::FILE_LIST_DIRECTORY | win::FILE_TRAVERSE | win::FILE_READ_ATTRIBUTES)
            .share_mode(win::FILE_SHARE_READ | win::FILE_SHARE_WRITE)
            .custom_flags(win::FILE_FLAG_OPEN_REPARSE_POINT | win::FILE_FLAG_BACKUP_SEMANTICS)
            .open(&cur)
            .map_err(|err| {
                SandboxError::Landlock(format!(
                    "failed to open and lock directory component '{}': {err}",
                    cur.display()
                ))
            })?;
        let meta = handle.metadata().map_err(|err| {
            SandboxError::Landlock(format!(
                "failed to inspect directory component '{}': {err}",
                cur.display()
            ))
        })?;
        if (u64::from(meta.file_attributes()) & win::FILE_ATTRIBUTE_REPARSE_POINT) != 0
            || !meta.is_dir()
        {
            return Err(SandboxError::Landlock(format!(
                "directory component '{}' is a reparse point or not a directory",
                cur.display()
            )));
        }
        chain.push(handle);
    }
    if chain.is_empty() {
        return Err(SandboxError::Landlock(format!(
            "refusing to pin filesystem root '{}'",
            dir.display()
        )));
    }
    Ok(chain)
}

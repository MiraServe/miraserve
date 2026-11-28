#![forbid(unsafe_code)]
//! MiraServe KDL configuration parser, strict security validator, and lock-free hot-reload store.
//!
//! # Security Invariants
//! - `#![forbid(unsafe_code)]` with zero `unwrap`/`expect`/`panic` on untrusted KDL inputs.
//! - Fail-closed schema parsing: unknown directives, unknown properties, and wrong types
//!   always produce typed [`ConfigError::Validation`] diagnostics with exact source spans.
//! - Enforces [`MAX_CONFIG_FILE_BYTES`] before loading files from disk to prevent OOM.
//! - Supports both KDL v2 (`#true`) and KDL v1 (`true`) syntax transparently.

pub mod error;
pub mod schema;
pub mod store;
pub mod units;

mod parser;
mod validate;

use std::collections::HashMap;
use std::fs;
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use miette::SourceSpan;

pub use error::{
    ConfigError, ConfigIssue, IssueDiagnostic, MAX_CONFIG_FILE_BYTES, Severity, SourceLocation,
    ValidationReport, compute_location,
};
pub use schema::*;
pub use store::ConfigStore;
pub use units::{BindAddr, ByteSize, IpCidr, Protocol, UnitParseError, parse_duration};
pub use validate::{
    DirPathVerdict, classify_dir_path, is_forbidden_dir_path, normalize_site_host,
    sandbox_tree_rejection, split_daemon_signing_keys,
};

/// Result of parsing and validating a configuration document, including the raw source text
/// so callers (such as `miraserve check`) can render source-annotated diagnostics for warnings
/// and attach exact source locations to `--fs` checks.
#[derive(Debug)]
pub struct LoadedConfig {
    /// Display name or file path of the configuration source.
    pub source_name: String,
    /// Raw KDL source text.
    pub source_text: String,
    /// Validated, normalized configuration model.
    pub config: Config,
    /// Non-fatal security warnings and advisories.
    pub report: ValidationReport,
    spans: HashMap<String, SourceSpan>,
    /// Byte offsets where each line starts, built on first use: one pass over the source for
    /// any number of location lookups.
    line_starts: std::sync::OnceLock<Vec<usize>>,
}

impl LoadedConfig {
    /// Converts all non-fatal security warnings into source-annotated `miette` diagnostics.
    #[must_use]
    pub fn warning_diagnostics(&self) -> Vec<IssueDiagnostic> {
        self.report
            .warnings
            .iter()
            .map(|w| w.to_diagnostic(&self.source_name, &self.source_text))
            .collect()
    }

    /// Resolves the 1-based line/column [`SourceLocation`] for a dotted configuration key path
    /// (e.g. `"server.tls.cert"`, `"site[0].root"`, `"site[0].error-pages.page.404"`), falling
    /// back to enclosing parent blocks when an exact leaf key has no recorded span.
    #[must_use]
    pub fn location_for(&self, key: &str) -> Option<SourceLocation> {
        if let Some(&span) = self.spans.get(key) {
            return Some(self.indexed_location(span));
        }
        let mut cur = key;
        while let Some((parent, _)) = cur.rsplit_once('.') {
            if let Some(&span) = self.spans.get(parent) {
                return Some(self.indexed_location(span));
            }
            cur = parent;
        }
        None
    }

    /// [`compute_location`] through the line index: a binary search for the line, then the
    /// characters of that line only.
    fn indexed_location(&self, span: SourceSpan) -> SourceLocation {
        let source = &self.source_text;
        let starts = self.line_starts.get_or_init(|| {
            std::iter::once(0)
                .chain(
                    source
                        .bytes()
                        .enumerate()
                        .filter(|&(_, b)| b == b'\n')
                        .map(|(i, _)| i + 1),
                )
                .collect()
        });
        let mut offset = span.offset().min(source.len());
        while offset > 0 && !source.is_char_boundary(offset) {
            offset = offset.saturating_sub(1);
        }
        let line_index = starts
            .partition_point(|&start| start <= offset)
            .saturating_sub(1);
        let line_start = starts.get(line_index).copied().unwrap_or(0);
        let column = source
            .get(line_start..offset)
            .map_or(0, |text| text.chars().count())
            + 1;
        SourceLocation {
            line: line_index + 1,
            column,
            offset,
            length: span.len().min(source.len().saturating_sub(offset)),
        }
    }
}

/// Parses and validates a MiraServe KDL configuration string.
///
/// # Errors
/// Returns [`ConfigError::Validation`] if syntax, schema, or security validation fails.
pub fn parse_kdl(
    source_name: impl Into<String>,
    kdl: &str,
) -> Result<(Config, ValidationReport), ConfigError> {
    let loaded = parse_kdl_detailed(source_name, kdl)?;
    Ok((loaded.config, loaded.report))
}

/// Parses and validates a MiraServe KDL string, retaining source metadata for diagnostic output.
///
/// Relative `root` and `ai-publish.storage` paths are rejected here because no configuration
/// file directory is known (`R5-SBX-1`). Use [`load_file_detailed`] or
/// [`parse_kdl_detailed_with_base_dir`] when loading from a file on disk (`R6-CFG-1`).
///
/// # Errors
/// Returns [`ConfigError::Validation`] if syntax, schema, or security validation fails.
pub fn parse_kdl_detailed(
    source_name: impl Into<String>,
    kdl: &str,
) -> Result<LoadedConfig, ConfigError> {
    parse_kdl_detailed_with_base_dir(source_name, kdl, None)
}

/// Parses and validates a MiraServe KDL string, optionally resolving relative `root` and
/// `ai-publish.storage` directory paths against `base_dir` (the absolute directory containing
/// the config file; if the config file is a symlink, `load_file_detailed` resolves against the
/// canonical target's parent directory, `R7-CFG-2`) before security validation (`R6-CFG-1`,
/// `R5-SBX-1`, `R7-CFG-1`).
///
/// Paths containing `..` or `\0` are never resolved and fail validation with `E202`. Every
/// resolved absolute path is still validated against sensitive system roots AND against
/// containing the configuration directory itself (`R7-CFG-1`, blocking `root "."` from serving
/// the `.kdl` config file).
///
/// # Errors
/// Returns [`ConfigError::Validation`] if syntax, schema, or security validation fails.
pub fn parse_kdl_detailed_with_base_dir(
    source_name: impl Into<String>,
    kdl: &str,
    base_dir: Option<&Path>,
) -> Result<LoadedConfig, ConfigError> {
    let source_name = source_name.into();
    let mut parsed = parser::parse_document(kdl);
    if let Some(dir) = base_dir {
        resolve_relative_dir_paths(&mut parsed, kdl, dir);
    }
    let outcome =
        validate::validate_config(&parsed.config, kdl, &parsed.spans, parsed.errors, base_dir);

    if !outcome.errors.is_empty() {
        return Err(ConfigError::Validation {
            source_name,
            source_text: kdl.to_owned(),
            errors: outcome.errors,
            warnings: outcome.warnings,
        });
    }

    Ok(LoadedConfig {
        source_name,
        source_text: kdl.to_owned(),
        config: parsed.config,
        report: ValidationReport {
            warnings: outcome.warnings,
        },
        spans: parsed.spans,
        line_starts: std::sync::OnceLock::new(),
    })
}

const RESOLVED_DIR_EDGE_WHITESPACE_HELP: &str = "verify which directory or file currently holds live data before editing the path; remove trailing whitespace from the final directory component before any trailing slash or '.'";

/// Resolves relative directory paths (`site.root`, `route.root`, `ai-publish.storage`) against
/// the config file's absolute parent directory while leaving traversal (`..`), empty, null-byte,
/// or already-absolute paths untouched so validator diagnostics stay exact (`R6-CFG-1`), and
/// rejects any relative value whose resolved directory name ends in Unicode whitespace.
fn resolve_relative_dir_paths(parsed: &mut parser::ParsedDocument, source: &str, base_dir: &Path) {
    let base_str = strip_windows_verbatim_prefix(base_dir);
    if !validate::is_absolute_config_path(&base_str) {
        return;
    }
    let clean_base = PathBuf::from(&base_str);
    let mut check_dir = |raw: &mut String, key: String, label: &str, scope: &str| {
        let had_source_ws = raw.as_str() != raw.trim();
        resolve_single_relative_dir(raw, &clean_base);
        if !had_source_ws && let Some(reason) = parser::edge_whitespace_reason(raw) {
            let msg = format!("{label} resolved directory name{scope} {reason}");
            let span = parsed.spans.get(&key).copied();
            parsed.errors.push(
                ConfigIssue::error("E202", msg, source, span)
                    .with_path(key)
                    .with_help(RESOLVED_DIR_EDGE_WHITESPACE_HELP),
            );
        }
    };

    for (site_idx, site) in parsed.config.sites.iter_mut().enumerate() {
        let primary_host = site.hosts.first().map_or("<unnamed>", String::as_str);
        let site_scope = format!(" on site '{primary_host}'");
        if let Some(root) = &mut site.root {
            check_dir(
                root,
                format!("site[{site_idx}].root"),
                "site 'root'",
                &site_scope,
            );
        }
        if let Some(publish) = &mut site.ai_publish {
            check_dir(
                &mut publish.storage,
                format!("site[{site_idx}].ai-publish.storage"),
                "ai-publish 'storage'",
                &site_scope,
            );
        }
        for (route_idx, route) in site.routes.iter_mut().enumerate() {
            if let Some(root) = &mut route.root {
                let route_scope = format!(" on route '{}' of site '{primary_host}'", route.pattern);
                check_dir(
                    root,
                    format!("site[{site_idx}].route[{route_idx}].root"),
                    "route 'root'",
                    &route_scope,
                );
            }
        }
    }
}

fn resolve_single_relative_dir(raw: &mut String, base_dir: &Path) {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.contains('\0')
        || validate::has_parent_traversal(trimmed)
        || validate::is_absolute_config_path(trimmed)
    {
        return;
    }

    let mut joined = base_dir.to_path_buf();
    for seg in trimmed.split(['/', '\\']) {
        if seg.is_empty() || seg == "." {
            continue;
        }
        joined.push(seg);
    }
    *raw = normalize_abs_path_string(&joined);
}

fn normalize_abs_path_string(path: &Path) -> String {
    let mut normalized = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            other => normalized.push(other.as_os_str()),
        }
    }
    strip_windows_verbatim_prefix(&normalized)
}

fn strip_windows_verbatim_prefix(path: &Path) -> String {
    let raw = path.to_string_lossy();
    if let Some(unc) = raw.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else if let Some(stripped) = raw.strip_prefix(r"\\?\") {
        stripped.to_owned()
    } else {
        raw.into_owned()
    }
}

fn config_file_base_dir(path: &Path) -> Option<PathBuf> {
    if let Ok(canon_file) = fs::canonicalize(path) {
        return canon_file.parent().map(Path::to_path_buf);
    }
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(path)
    };
    let parent = abs.parent()?;
    Some(fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf()))
}

/// Reads a KDL configuration file from disk (bounded by [`MAX_CONFIG_FILE_BYTES`]),
/// parses it, and validates all semantic and security invariants.
///
/// # Errors
/// Returns [`ConfigError::Io`], [`ConfigError::FileTooLarge`], or [`ConfigError::Validation`].
pub fn load_file(path: impl AsRef<Path>) -> Result<(Config, ValidationReport), ConfigError> {
    let loaded = load_file_detailed(path)?;
    Ok((loaded.config, loaded.report))
}

/// Reads, parses, and validates a KDL file from disk, retaining source text for rich diagnostics.
///
/// # Errors
/// Returns [`ConfigError::Io`], [`ConfigError::FileTooLarge`], or [`ConfigError::Validation`].
pub fn load_file_detailed(path: impl AsRef<Path>) -> Result<LoadedConfig, ConfigError> {
    let path_ref = path.as_ref();
    let file = fs::File::open(path_ref).map_err(|source| ConfigError::Io {
        path: path_ref.to_path_buf(),
        source,
    })?;

    let metadata = file.metadata().map_err(|source| ConfigError::Io {
        path: path_ref.to_path_buf(),
        source,
    })?;

    if metadata.len() > MAX_CONFIG_FILE_BYTES {
        return Err(ConfigError::FileTooLarge {
            path: path_ref.to_path_buf(),
            actual_bytes: metadata.len(),
            max_bytes: MAX_CONFIG_FILE_BYTES,
        });
    }

    // Also cap the streaming read itself in case the file grows concurrently (TOCTOU defense).
    let mut limited = file.take(MAX_CONFIG_FILE_BYTES.saturating_add(1));
    let mut raw = Vec::new();
    limited
        .read_to_end(&mut raw)
        .map_err(|source| ConfigError::Io {
            path: path_ref.to_path_buf(),
            source,
        })?;

    if (raw.len() as u64) > MAX_CONFIG_FILE_BYTES {
        return Err(ConfigError::FileTooLarge {
            path: path_ref.to_path_buf(),
            actual_bytes: raw.len() as u64,
            max_bytes: MAX_CONFIG_FILE_BYTES,
        });
    }

    let text = String::from_utf8(raw).map_err(|utf8_err| ConfigError::Io {
        path: path_ref.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, utf8_err),
    })?;

    let base_dir = config_file_base_dir(path_ref);
    parse_kdl_detailed_with_base_dir(path_ref.display().to_string(), &text, base_dir.as_deref())
}

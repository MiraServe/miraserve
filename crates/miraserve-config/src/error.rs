//! Typed configuration errors, security warnings, and `miette` diagnostics.

use std::fmt;
use std::path::PathBuf;

use miette::{Diagnostic, LabeledSpan, NamedSource, SourceSpan};
use serde::Serialize;
use thiserror::Error;

/// Maximum config file size allowed when reading from disk (10 MiB) to defend against
/// memory exhaustion (Threat Model T1).
pub const MAX_CONFIG_FILE_BYTES: u64 = 10 * 1024 * 1024;

/// Severity level of a configuration diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Hard validation or syntax error; configuration cannot be loaded.
    Error,
    /// Security advisory or non-fatal configuration warning; fails under `--strict`.
    Warning,
}

impl From<Severity> for miette::Severity {
    fn from(value: Severity) -> Self {
        match value {
            Severity::Error => Self::Error,
            Severity::Warning => Self::Warning,
        }
    }
}

/// Optional 1-based line and column location in a source file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SourceLocation {
    /// 1-based line number.
    pub line: usize,
    /// 1-based UTF-8 character column.
    pub column: usize,
    /// Byte offset from the start of the source text.
    pub offset: usize,
    /// Span length in bytes.
    pub length: usize,
}

/// Computes a safe, clamped [`SourceLocation`] from a byte span without risking panics.
#[must_use]
pub fn compute_location(source: &str, span: SourceSpan) -> SourceLocation {
    let raw_offset = span.offset().min(source.len());
    // Ensure offset falls on a valid UTF-8 char boundary by walking back if needed.
    let mut offset = raw_offset;
    while offset > 0 && !source.is_char_boundary(offset) {
        offset = offset.saturating_sub(1);
    }

    let max_len = source.len().saturating_sub(offset);
    let length = span.len().min(max_len);

    let prefix = source.get(..offset).unwrap_or("");
    let mut line = 1_usize;
    let mut column = 1_usize;
    for ch in prefix.chars() {
        if ch == '\n' {
            line = line.saturating_add(1);
            column = 1;
        } else {
            column = column.saturating_add(1);
        }
    }

    SourceLocation {
        line,
        column,
        offset,
        length,
    }
}

/// Clamps a [`SourceSpan`] to lie safely within `source_len`.
#[must_use]
pub fn clamp_span(span: SourceSpan, source_len: usize) -> SourceSpan {
    let start = span.offset().min(source_len);
    let len = span.len().min(source_len.saturating_sub(start));
    SourceSpan::new(start.into(), len)
}

/// A single structured configuration error or security warning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfigIssue {
    /// Stable diagnostic code (e.g. `"E104"`, `"W001"`).
    pub code: String,
    /// Severity level (`error` or `warning`).
    pub severity: Severity,
    /// Human-readable description of the issue.
    pub message: String,
    /// Optional dotted configuration key path (e.g. `"site[0].root"`, `"server.tls.cert"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Optional remediation advice.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
    /// Optional source span label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Optional location within the KDL source file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<SourceLocation>,
}

impl ConfigIssue {
    /// Creates a new hard error issue.
    #[must_use]
    pub fn error(
        code: impl Into<String>,
        message: impl Into<String>,
        source: &str,
        span: Option<SourceSpan>,
    ) -> Self {
        Self {
            code: code.into(),
            severity: Severity::Error,
            message: message.into(),
            path: None,
            help: None,
            label: None,
            location: span.map(|s| compute_location(source, s)),
        }
    }

    /// Creates a new security warning / advisory issue.
    #[must_use]
    pub fn warning(
        code: impl Into<String>,
        message: impl Into<String>,
        source: &str,
        span: Option<SourceSpan>,
    ) -> Self {
        Self {
            code: code.into(),
            severity: Severity::Warning,
            message: message.into(),
            path: None,
            help: None,
            label: None,
            location: span.map(|s| compute_location(source, s)),
        }
    }

    /// Attaches the dotted configuration key path (e.g. `"server.tls.cert"`, `"site[0].root"`).
    #[must_use]
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        let p = path.into();
        if !p.is_empty() {
            self.path = Some(p);
        }
        self
    }

    /// Attaches remediation help text.
    #[must_use]
    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    /// Attaches a short inline label for source-highlighted output.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Converts this issue into a renderable `miette` diagnostic attached to source text.
    #[must_use]
    pub fn to_diagnostic(&self, source_name: &str, source_text: &str) -> IssueDiagnostic {
        let span = self.location.map(|loc| {
            clamp_span(
                SourceSpan::new(loc.offset.into(), loc.length.max(1)),
                source_text.len(),
            )
        });
        IssueDiagnostic {
            code: self.code.clone(),
            severity: self.severity.into(),
            message: self.message.clone(),
            help: self.help.clone(),
            label: self.label.clone(),
            span,
            src: NamedSource::new(source_name, source_text.to_owned()),
        }
    }
}

impl fmt::Display for ConfigIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(loc) = self.location {
            write!(
                f,
                "[{}] {} (line {}, col {})",
                self.code, self.message, loc.line, loc.column
            )
        } else {
            write!(f, "[{}] {}", self.code, self.message)
        }
    }
}

/// Source-annotated `miette` diagnostic wrapper for a [`ConfigIssue`].
#[derive(Debug, Error)]
#[error("{message}")]
pub struct IssueDiagnostic {
    code: String,
    severity: miette::Severity,
    message: String,
    help: Option<String>,
    label: Option<String>,
    span: Option<SourceSpan>,
    src: NamedSource<String>,
}

impl Diagnostic for IssueDiagnostic {
    fn code<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        Some(Box::new(format!("miraserve::{}", self.code)))
    }

    fn severity(&self) -> Option<miette::Severity> {
        Some(self.severity)
    }

    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        self.help
            .as_ref()
            .map(|h| Box::new(h.as_str()) as Box<dyn fmt::Display + 'a>)
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        Some(&self.src)
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        let span = self.span?;
        let label = self.label.clone().or_else(|| Some("here".to_owned()));
        Some(Box::new(std::iter::once(LabeledSpan::new_with_span(
            label, span,
        ))))
    }
}

/// Non-fatal validation report returned alongside a valid parsed [`crate::Config`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ValidationReport {
    /// Security warnings and advisories produced during validation.
    pub warnings: Vec<ConfigIssue>,
}

impl ValidationReport {
    /// Returns `true` if there are no warnings.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.warnings.is_empty()
    }
}

/// Top-level error returned when loading, parsing, or validating MiraServe configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Failed to read the configuration file from disk.
    #[error("failed to read configuration file '{path}': {source}")]
    Io {
        /// Path that failed to read.
        path: PathBuf,
        /// Underlying OS I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Configuration file exceeded [`MAX_CONFIG_FILE_BYTES`].
    #[error(
        "configuration file '{path}' is {actual_bytes} bytes, exceeding safety limit of {max_bytes} bytes"
    )]
    FileTooLarge {
        /// Path to the oversized file.
        path: PathBuf,
        /// Actual byte size reported by the filesystem.
        actual_bytes: u64,
        /// Configured safety limit in bytes.
        max_bytes: u64,
    },
    /// One or more syntax, schema, or security validation errors occurred.
    #[error("configuration validation failed with {} error(s)", errors.len())]
    Validation {
        /// Name or path of the source document.
        source_name: String,
        /// Raw KDL source text for diagnostic rendering.
        source_text: String,
        /// Hard errors that prevented configuration loading.
        errors: Vec<ConfigIssue>,
        /// Security warnings collected alongside errors.
        warnings: Vec<ConfigIssue>,
    },
}

impl ConfigError {
    /// Returns the slice of structured validation errors, if this is a [`ConfigError::Validation`].
    #[must_use]
    pub fn validation_errors(&self) -> &[ConfigIssue] {
        match self {
            Self::Validation { errors, .. } => errors,
            Self::Io { .. } | Self::FileTooLarge { .. } => &[],
        }
    }

    /// Returns the slice of structured warnings collected alongside validation errors.
    #[must_use]
    pub fn validation_warnings(&self) -> &[ConfigIssue] {
        match self {
            Self::Validation { warnings, .. } => warnings,
            Self::Io { .. } | Self::FileTooLarge { .. } => &[],
        }
    }

    /// Renders all validation issues as source-annotated `miette` diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> Vec<IssueDiagnostic> {
        match self {
            Self::Validation {
                source_name,
                source_text,
                errors,
                warnings,
            } => errors
                .iter()
                .chain(warnings.iter())
                .map(|issue| issue.to_diagnostic(source_name, source_text))
                .collect(),
            Self::Io { .. } | Self::FileTooLarge { .. } => Vec::new(),
        }
    }
}

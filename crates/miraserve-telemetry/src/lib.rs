#![forbid(unsafe_code)]
//! Observability, Prometheus metrics, OTLP/HTTP JSON export, and secret-redacting
//! access/audit telemetry for MiraServe.

pub mod metrics;
pub mod otlp;
pub mod redact;

use thiserror::Error;

pub use metrics::{FileCacheOutcome, SecurityBlockReason, TelemetryRegistry};
pub use otlp::{MetricsServer, OtlpExporter, PROMETHEUS_CONTENT_TYPE, RunningMetricsServer};
pub use redact::{
    AccessLogRecord, redact_header_value, redact_request_target, redact_uri_query,
    sanitize_headers_for_log,
};

/// Errors produced by `miraserve-telemetry`.
#[derive(Debug, Error)]
pub enum TelemetryError {
    /// Network or socket binding I/O error.
    #[error("telemetry I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// TLS setup error for OTLP exporter.
    #[error("telemetry TLS error: {0}")]
    Tls(String),
    /// OTLP/HTTP collector export failure.
    #[error("OTLP export failed: {0}")]
    Export(String),
}

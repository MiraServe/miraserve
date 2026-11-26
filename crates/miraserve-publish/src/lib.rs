#![forbid(unsafe_code)]
//! Atomic self-updating AI website publisher (`miraserve-publish`) enforcing Threat Model T6:
//! - Ed25519 bundle signing and cryptographic verification (`aws-lc-rs`)
//! - Mandatory pre-flight checks (secret scanning, inline-script/XSS defense, CSP validation, quotas)
//! - Immutable versioned release storage with zero-downtime `ArcSwap` activation & instant rollback
//! - Built-in authenticated MCP JSON-RPC 2.0 publishing endpoint (`/_miraserve/publish`)

pub mod crypto;
pub mod mcp;
pub mod preflight;
pub mod store;

use std::path::PathBuf;

use thiserror::Error;

pub use crypto::{
    Ed25519SigningKey, Ed25519VerifyingKey, SignedBundle, SiteBundle,
    canonical_mcp_request_signing_input, sha256_hex,
};
pub use mcp::{McpPublishAuthContext, handle_mcp_publish_http, precheck_mcp_publish_auth};
pub use preflight::{PreflightViolation, run_preflight_checks};
pub use store::{
    DiskSyncGuard, ReleaseMetadata, ReleaseStore, ResignOptions, bundle_from_directory,
    is_canonical_release_id, try_claim_disk_sync,
};

/// Errors produced by `miraserve-publish`.
#[derive(Debug, Error)]
pub enum PublishError {
    /// Filesystem I/O error reading or writing release artifacts or keys.
    #[error("publish I/O error at '{path}': {source}")]
    Io {
        /// Path involved in the I/O operation.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },
    /// Invalid or malformed Ed25519 key material.
    #[error("invalid signing/verifying key: {0}")]
    InvalidKey(String),
    /// Cryptographic runtime error.
    #[error("cryptographic error: {0}")]
    Crypto(String),
    /// Bundle lacked a required Ed25519 signature.
    #[error("bundle is missing required Ed25519 signature")]
    MissingSignature,
    /// Ed25519 signature verification failed.
    #[error("bundle signature rejected: {0}")]
    InvalidSignature(String),
    /// One or more pre-flight security checks failed.
    #[error("pre-flight safety checks rejected bundle ({} violation(s))", .0.len())]
    PreflightFailed(Vec<PreflightViolation>),
    /// Requested release ID was not found for rollback.
    #[error("release not found: {0}")]
    ReleaseNotFound(String),
    /// Failed to open immutable release directory in `cap-std`.
    #[error("failed to open static release handle: {0}")]
    StaticOpen(String),
    /// JSON serialization/deserialization error.
    #[error("serialization error: {0}")]
    Serialization(String),
}

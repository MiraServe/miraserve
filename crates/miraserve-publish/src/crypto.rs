//! Ed25519 key generation, bijective length-prefixed SHA-256 bundle manifests,
//! `EdDSA` JWT helpers, and signature verification using `aws-lc-rs` (with `zeroize`
//! secret clearing on drop).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::File;
use std::io::Read as _;
use std::path::Path;

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64URL};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::PublishError;

const PUB_PREFIX: &str = "miraserve-ed25519-pub:";
const SEC_PREFIX: &str = "miraserve-ed25519-sec:";

/// Maximum key file size permitted when reading Ed25519 key files from disk (16 KiB).
const MAX_KEY_FILE_BYTES: u64 = 16 * 1024;

/// Ed25519 public verifying key (32 raw bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519VerifyingKey {
    bytes: [u8; 32],
}

impl Ed25519VerifyingKey {
    /// Parses a public key from `"miraserve-ed25519-pub:<base64>"` or raw base64 text.
    ///
    /// # Errors
    /// Returns [`PublishError::InvalidKey`] if decoding fails or key length is not 32 bytes.
    pub fn from_encoded(input: &str) -> Result<Self, PublishError> {
        let trimmed = input.trim();
        let b64 = trimmed.strip_prefix(PUB_PREFIX).unwrap_or(trimmed);
        let decoded = BASE64
            .decode(b64)
            .map_err(|err| PublishError::InvalidKey(format!("base64 decode failed: {err}")))?;
        let bytes: [u8; 32] = decoded.try_into().map_err(|_| {
            PublishError::InvalidKey("Ed25519 public key must be exactly 32 bytes".to_owned())
        })?;
        Ok(Self { bytes })
    }

    /// Loads an Ed25519 public key from a regular file on disk with a strict size cap.
    ///
    /// # Errors
    /// Returns [`PublishError`] on I/O, special-file, size-cap, or key parsing failure.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, PublishError> {
        let raw = read_bounded_regular_file(path.as_ref())?;
        Self::from_encoded(&raw)
    }

    /// Encodes the public key in MiraServe's text format (`miraserve-ed25519-pub:<base64>`).
    #[must_use]
    pub fn to_encoded(&self) -> String {
        format!("{PUB_PREFIX}{}", BASE64.encode(self.bytes))
    }

    /// Returns the raw 32-byte Ed25519 public key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Verifies an Ed25519 signature over `message`.
    ///
    /// # Errors
    /// Returns [`PublishError::InvalidSignature`] if verification fails.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), PublishError> {
        let pk = UnparsedPublicKey::new(&ED25519, self.bytes);
        pk.verify(message, signature).map_err(|_| {
            PublishError::InvalidSignature("Ed25519 signature verification failed".to_owned())
        })
    }
}

/// Ed25519 signing key pair with zeroized PKCS#8 secret material.
pub struct Ed25519SigningKey {
    pair: Ed25519KeyPair,
    pkcs8_bytes: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Ed25519SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519SigningKey")
            .field("public_key", &self.verifying_key().to_encoded())
            .finish_non_exhaustive()
    }
}

impl Ed25519SigningKey {
    /// Generates a fresh cryptographic Ed25519 key pair using `aws-lc-rs`.
    ///
    /// # Errors
    /// Returns [`PublishError::Crypto`] if OS entropy or key generation fails.
    pub fn generate() -> Result<Self, PublishError> {
        let pair = Ed25519KeyPair::generate()
            .map_err(|_| PublishError::Crypto("Ed25519 key generation failed".to_owned()))?;
        let doc = pair
            .to_pkcs8()
            .map_err(|_| PublishError::Crypto("Ed25519 PKCS#8 export failed".to_owned()))?;
        let pkcs8_bytes = Zeroizing::new(doc.as_ref().to_vec());
        Ok(Self { pair, pkcs8_bytes })
    }

    /// Parses a signing key from `"miraserve-ed25519-sec:<base64-pkcs8>"` text.
    ///
    /// # Errors
    /// Returns [`PublishError::InvalidKey`] if decoding or PKCS#8 parsing fails.
    pub fn from_encoded(input: &str) -> Result<Self, PublishError> {
        let trimmed = input.trim();
        let b64 = trimmed.strip_prefix(SEC_PREFIX).unwrap_or(trimmed);
        let decoded = Zeroizing::new(
            BASE64
                .decode(b64)
                .map_err(|err| PublishError::InvalidKey(format!("base64 decode failed: {err}")))?,
        );
        let pair = Ed25519KeyPair::from_pkcs8(&decoded).map_err(|err| {
            PublishError::InvalidKey(format!("invalid Ed25519 PKCS#8 key: {err}"))
        })?;
        Ok(Self {
            pair,
            pkcs8_bytes: decoded,
        })
    }

    /// Loads an Ed25519 signing key from a regular file on disk (zeroizing raw file contents).
    ///
    /// # Errors
    /// Returns [`PublishError`] on I/O, special-file, size-cap, or key parsing failure.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, PublishError> {
        let raw = Zeroizing::new(read_bounded_regular_file(path.as_ref())?);
        Self::from_encoded(&raw)
    }

    /// Exports the signing key in MiraServe's text format wrapped in [`Zeroizing`].
    #[must_use]
    pub fn to_encoded(&self) -> Zeroizing<String> {
        Zeroizing::new(format!("{SEC_PREFIX}{}", BASE64.encode(&*self.pkcs8_bytes)))
    }

    /// Returns the corresponding [`Ed25519VerifyingKey`].
    #[must_use]
    pub fn verifying_key(&self) -> Ed25519VerifyingKey {
        let mut bytes = [0_u8; 32];
        let raw = self.pair.public_key().as_ref();
        if let Some(slice) = raw.get(..32) {
            bytes.copy_from_slice(slice);
        }
        Ed25519VerifyingKey { bytes }
    }

    /// Signs `message` and returns the 64-byte Ed25519 signature.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.pair.sign(message).as_ref().to_vec()
    }

    /// Signs a compact `EdDSA` (`alg: "EdDSA"`) JWT suitable for `PublishAuthMode::OAuthJwt`
    /// or MCP Gateway OAuth testing (automatically includes `iat`).
    #[must_use]
    pub fn sign_oauth_jwt(&self, subject: &str, exp_unix: u64, scope: Option<&str>) -> String {
        self.sign_oauth_jwt_with_audience(subject, None, exp_unix, scope)
    }

    /// Signs a compact `EdDSA` (`alg: "EdDSA"`) JWT bound to an explicit `aud` (site host),
    /// `iat`, `exp`, and optional `scope` (`R2-PUB-3`).
    #[must_use]
    pub fn sign_oauth_jwt_with_audience(
        &self,
        subject: &str,
        audience: Option<&str>,
        exp_unix: u64,
        scope: Option<&str>,
    ) -> String {
        let header = BASE64URL.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let iat = now_unix.min(exp_unix);
        let mut obj = serde_json::Map::new();
        obj.insert(
            "sub".to_owned(),
            serde_json::Value::String(subject.to_owned()),
        );
        obj.insert("iat".to_owned(), serde_json::Value::from(iat));
        obj.insert("exp".to_owned(), serde_json::Value::from(exp_unix));
        if let Some(aud) = audience {
            obj.insert("aud".to_owned(), serde_json::Value::String(aud.to_owned()));
        }
        if let Some(sc) = scope {
            obj.insert("scope".to_owned(), serde_json::Value::String(sc.to_owned()));
        }
        let payload_bytes =
            serde_json::to_vec(&serde_json::Value::Object(obj)).unwrap_or_else(|_| b"{}".to_vec());
        let payload = BASE64URL.encode(payload_bytes);
        let signing_input = format!("{header}.{payload}");
        let sig = self.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", BASE64URL.encode(sig))
    }

    /// Signs an HTTP MCP publishing request for `PublishAuthMode::Ed25519`, bound to `site_host`,
    /// `endpoint_path`, `timestamp_unix`, optional `nonce`, and `body` (`R2-PUB-2`), returning the
    /// base64-encoded signature for the `X-MiraServe-Signature` header.
    #[must_use]
    pub fn sign_mcp_request(
        &self,
        site_host: &str,
        endpoint_path: &str,
        timestamp_unix: u64,
        nonce: Option<&str>,
        body: &[u8],
    ) -> String {
        let canonical = canonical_mcp_request_signing_input(
            site_host,
            endpoint_path,
            timestamp_unix,
            nonce,
            body,
        );
        BASE64.encode(self.sign(canonical.as_bytes()))
    }
}

/// Deterministic signing input for `PublishAuthMode::Ed25519` HTTP requests, bound to the target
/// site host, endpoint path, timestamp, optional nonce, and body SHA-256 (`R2-PUB-2`).
#[must_use]
pub fn canonical_mcp_request_signing_input(
    site_host: &str,
    endpoint_path: &str,
    timestamp_unix: u64,
    nonce: Option<&str>,
    body: &[u8],
) -> String {
    let host_norm = site_host.trim().to_ascii_lowercase();
    let nonce_str = nonce.unwrap_or("");
    format!(
        "POST\n{host_norm}\n{endpoint_path}\n{timestamp_unix}\n{nonce_str}\n{}",
        sha256_hex(body)
    )
}

fn read_bounded_regular_file(path: &Path) -> Result<String, PublishError> {
    let file = File::open(path).map_err(|source| PublishError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let meta = file.metadata().map_err(|source| PublishError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !meta.is_file() {
        return Err(PublishError::InvalidKey(format!(
            "key path '{}' is not a regular file",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    file.take(MAX_KEY_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| PublishError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if (bytes.len() as u64) > MAX_KEY_FILE_BYTES {
        return Err(PublishError::InvalidKey(format!(
            "key file '{}' exceeds maximum size of {MAX_KEY_FILE_BYTES} bytes",
            path.display()
        )));
    }
    String::from_utf8(bytes)
        .map_err(|err| PublishError::InvalidKey(format!("key file is not valid UTF-8: {err}")))
}

/// Immutable site file map ready for signing or deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteBundle {
    /// Relative POSIX path (e.g. `"index.html"`, `"assets/app.css"`) -> raw file bytes.
    pub files: BTreeMap<String, Vec<u8>>,
    /// Optional human/agent deployment note (e.g. `"Updated pricing table"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Unix epoch creation timestamp in seconds.
    pub created_at_unix: u64,
    /// Optional canonical target site identifier (e.g. `"blog.example.com"`, lowercased)
    /// cryptographically bound into `miraserve-bundle-v3` manifests so a bundle signed for one
    /// site cannot be replayed onto another site sharing the same key (`R3-PUB-5`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site_id: Option<String>,
}

impl SiteBundle {
    /// Produces the bijective, length-prefixed canonical byte representation signed by Ed25519:
    /// - `miraserve-bundle-v3` when `site_id` is set (cryptographically binding target site ID, `R3-PUB-5`)
    /// - `miraserve-bundle-v2` when `site_id` is `None` (backwards-compatible site-less manifests).
    #[must_use]
    pub fn canonical_manifest(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160 + self.files.len().saturating_mul(64));
        if let Some(site) = &self.site_id {
            let norm = site.trim().to_ascii_lowercase();
            out.extend_from_slice(b"miraserve-bundle-v3\0");
            out.extend_from_slice(&(norm.len() as u64).to_be_bytes());
            out.extend_from_slice(norm.as_bytes());
        } else {
            out.extend_from_slice(b"miraserve-bundle-v2\0");
        }
        out.extend_from_slice(&self.created_at_unix.to_be_bytes());
        match &self.note {
            Some(note) => {
                out.push(1);
                out.extend_from_slice(&(note.len() as u64).to_be_bytes());
                out.extend_from_slice(note.as_bytes());
            }
            None => {
                out.push(0);
            }
        }
        out.extend_from_slice(&(self.files.len() as u64).to_be_bytes());
        for (path, bytes) in &self.files {
            out.extend_from_slice(&(path.len() as u64).to_be_bytes());
            out.extend_from_slice(path.as_bytes());
            out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            let file_digest = digest(&SHA256, bytes);
            out.extend_from_slice(file_digest.as_ref());
        }
        out
    }

    /// Computes the deterministic SHA-256 hex digest of this bundle's canonical manifest.
    #[must_use]
    pub fn manifest_sha256_hex(&self) -> String {
        sha256_hex(&self.canonical_manifest())
    }
}

/// Site bundle paired with an optional Ed25519 signature (`base64`) over its canonical manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBundle {
    /// Bundle files and metadata.
    pub bundle: SiteBundle,
    /// Optional base64-encoded 64-byte Ed25519 signature over `bundle.canonical_manifest()`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_b64: Option<String>,
}

impl SignedBundle {
    /// Signs a [`SiteBundle`] with `key` and returns a [`SignedBundle`].
    #[must_use]
    pub fn sign(bundle: SiteBundle, key: &Ed25519SigningKey) -> Self {
        let manifest = bundle.canonical_manifest();
        let sig = key.sign(&manifest);
        Self {
            bundle,
            signature_b64: Some(BASE64.encode(sig)),
        }
    }

    /// Verifies the Ed25519 signature against `verifying_key` and returns the manifest SHA-256 hex.
    ///
    /// # Errors
    /// Returns [`PublishError::MissingSignature`] or [`PublishError::InvalidSignature`].
    pub fn verify(&self, verifying_key: &Ed25519VerifyingKey) -> Result<String, PublishError> {
        let Some(sig_b64) = &self.signature_b64 else {
            return Err(PublishError::MissingSignature);
        };
        let sig_bytes = BASE64.decode(sig_b64.trim()).map_err(|err| {
            PublishError::InvalidSignature(format!("invalid base64 signature: {err}"))
        })?;
        let manifest = self.bundle.canonical_manifest();
        verifying_key.verify(&manifest, &sig_bytes)?;
        Ok(sha256_hex(&manifest))
    }
}

/// Computes lowercase hex SHA-256 digest of `bytes` using `aws-lc-rs`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let d = digest(&SHA256, bytes);
    let mut hex = String::with_capacity(64);
    for b in d.as_ref() {
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

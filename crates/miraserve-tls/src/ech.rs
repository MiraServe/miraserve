//! Encrypted Client Hello (ECH / RFC 9849) HPKE key generation, lock-free rotation,
//! RFC 9180 HPKE seal/open helpers, and RFC 9460 DNS `HTTPS` record formatting
//! (Threat Model T3 — SNI metadata surveillance defense).

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use rustls::crypto::aws_lc_rs::hpke::DH_KEM_X25519_HKDF_SHA256_AES_128;
use rustls::crypto::hpke::{EncapsulatedSecret, Hpke as _, HpkePrivateKey, HpkePublicKey};
use rustls::pki_types::EchConfigListBytes;
use serde::Serialize;

use crate::TlsError;

/// RFC 9849 ECH configuration wire version (`0xfe0d`).
pub const ECH_CONFIG_VERSION: u16 = 0xfe0d;
/// RFC 9180 HPKE KEM ID for `DHKEM(X25519, HKDF-SHA256)`.
pub const HPKE_KEM_X25519_HKDF_SHA256: u16 = 0x0020;
/// RFC 9180 HPKE KDF ID for `HKDF-SHA256`.
pub const HPKE_KDF_HKDF_SHA256: u16 = 0x0001;
/// RFC 9180 HPKE AEAD ID for `AES-128-GCM`.
pub const HPKE_AEAD_AES_128_GCM: u16 = 0x0001;
/// RFC 9180 HPKE AEAD ID for `ChaCha20Poly1305`.
pub const HPKE_AEAD_CHACHA20_POLY1305: u16 = 0x0003;
/// Default RFC 9849 `maximum_name_length` padding boundary.
pub const DEFAULT_MAX_NAME_LENGTH: u8 = 64;

/// A single RFC 9849 ECH key pair and its wire-encoded `ECHConfig` bytes.
pub struct EchKeyEntry {
    /// 8-bit ECH configuration identifier (`0..=255`).
    pub config_id: u8,
    /// Public outer SNI DNS name advertised to clients (e.g. `"edge.example.com"`).
    pub public_name: String,
    /// Padding length (`maximum_name_length`) protecting inner SNI length.
    pub max_name_length: u8,
    /// Raw X25519 HPKE public key (`32` bytes).
    pub public_key: HpkePublicKey,
    /// Zeroized X25519 HPKE private key held strictly in memory.
    private_key: HpkePrivateKey,
    /// RFC 9849 wire encoding of this single `ECHConfig` (without outer `ECHConfigList` length).
    pub ech_config_bytes: Vec<u8>,
    /// Unix epoch creation timestamp in seconds.
    pub created_at_unix: u64,
}

impl std::fmt::Debug for EchKeyEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EchKeyEntry")
            .field("config_id", &self.config_id)
            .field("public_name", &self.public_name)
            .field("created_at_unix", &self.created_at_unix)
            .finish_non_exhaustive()
    }
}

impl EchKeyEntry {
    /// Generates a fresh RFC 9849 X25519 HPKE ECH configuration entry.
    ///
    /// # Errors
    /// Returns [`TlsError::CertGeneration`] if `public_name` is invalid or HPKE keygen fails.
    pub fn generate(
        config_id: u8,
        public_name: impl Into<String>,
        max_name_length: u8,
    ) -> Result<Self, TlsError> {
        let public_name = public_name.into();
        if !is_valid_ech_public_name(&public_name) {
            return Err(TlsError::CertGeneration(format!(
                "invalid RFC 9849 ECH public_name '{public_name}'"
            )));
        }

        let (public_key, private_key) = DH_KEM_X25519_HKDF_SHA256_AES_128
            .generate_key_pair()
            .map_err(|err| TlsError::CertGeneration(format!("HPKE X25519 keygen failed: {err}")))?;

        let ech_config_bytes = encode_ech_config(
            config_id,
            &public_key.0,
            &public_name,
            max_name_length.max(1),
        )?;

        let created_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        Ok(Self {
            config_id,
            public_name,
            max_name_length: max_name_length.max(1),
            public_key,
            private_key,
            ech_config_bytes,
            created_at_unix,
        })
    }

    /// Wraps this single `ECHConfig` into a wire-encoded RFC 9849 `ECHConfigList`.
    ///
    /// # Errors
    /// Returns [`TlsError::CertGeneration`] if length exceeds `u16::MAX`.
    pub fn to_ech_config_list(&self) -> Result<EchConfigListBytes<'static>, TlsError> {
        encode_ech_config_list(&[self.ech_config_bytes.as_slice()])
    }

    /// Decrypts (opens) an RFC 9180 HPKE ciphertext addressed to this ECH key entry.
    ///
    /// # Errors
    /// Returns [`TlsError::Rustls`] if HPKE decryption or authentication fails.
    pub fn hpke_open(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        DH_KEM_X25519_HKDF_SHA256_AES_128
            .open(enc, info, aad, ciphertext, &self.private_key)
            .map_err(|err| TlsError::Rustls(format!("ECH HPKE open failed: {err}")))
    }

    /// Encrypts (seals) a plaintext to this ECH key entry's public key using RFC 9180 HPKE.
    ///
    /// # Errors
    /// Returns [`TlsError::Rustls`] if HPKE encapsulation or sealing fails.
    pub fn hpke_seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(EncapsulatedSecret, Vec<u8>), TlsError> {
        DH_KEM_X25519_HKDF_SHA256_AES_128
            .seal(info, aad, plaintext, &self.public_key)
            .map_err(|err| TlsError::Rustls(format!("ECH HPKE seal failed: {err}")))
    }
}

/// Public, serializable snapshot of the active ECH configuration and RFC 9460 DNS `HTTPS` record.
#[derive(Debug, Clone, Serialize)]
pub struct EchPublicSnapshot {
    /// Active ECH configuration ID (`0..=255`).
    pub active_config_id: u8,
    /// Public outer SNI DNS name (`public_name`).
    pub public_name: String,
    /// Number of retained decryption keys (active + grace previous keys for DNS TTL overlap).
    pub retained_key_count: usize,
    /// Standard Base64 encoding of the active `ECHConfigList` (RFC 9460 `ech="..."` parameter).
    pub ech_config_list_b64: String,
    /// Ready-to-publish RFC 9460 DNS `HTTPS` zone file record line.
    pub dns_https_record: String,
    /// Configured automatic rotation interval in seconds.
    pub rotate_interval_secs: u64,
}

#[derive(Debug)]
struct EchKeyRing {
    /// Currently advertised key (published in DNS `HTTPS` record).
    active: Arc<EchKeyEntry>,
    /// Previous key kept during DNS TTL grace window so cached clients can still decrypt.
    previous: Option<Arc<EchKeyEntry>>,
}

/// Lock-free RFC 9849 ECH key-ring & rotation manager (`ArcSwap`) with graceful overlap.
#[derive(Debug)]
pub struct EchRotationManager {
    public_name: String,
    max_name_length: u8,
    rotate_interval: Duration,
    next_id: AtomicU8,
    ring: ArcSwap<EchKeyRing>,
}

impl EchRotationManager {
    /// Initializes a new [`EchRotationManager`] with a freshly generated active X25519 HPKE key.
    ///
    /// # Errors
    /// Returns [`TlsError::CertGeneration`] if `public_name` is invalid or HPKE keygen fails.
    pub fn new(
        public_name: impl Into<String>,
        rotate_interval: Duration,
    ) -> Result<Self, TlsError> {
        let public_name = public_name.into();
        let initial = Arc::new(EchKeyEntry::generate(
            1,
            public_name.clone(),
            DEFAULT_MAX_NAME_LENGTH,
        )?);
        Ok(Self {
            public_name,
            max_name_length: DEFAULT_MAX_NAME_LENGTH,
            rotate_interval,
            next_id: AtomicU8::new(2),
            ring: ArcSwap::from_pointee(EchKeyRing {
                active: initial,
                previous: None,
            }),
        })
    }

    /// Generates a new active ECH key with an incremented `config_id`, moving the prior active
    /// key into the grace slot so in-flight DNS-cached clients continue working seamlessly.
    ///
    /// # Errors
    /// Returns [`TlsError::CertGeneration`] if HPKE key generation fails.
    pub fn rotate(&self) -> Result<EchPublicSnapshot, TlsError> {
        let id = self.next_id.fetch_add(1, Ordering::AcqRel);
        let fresh = Arc::new(EchKeyEntry::generate(
            id,
            self.public_name.clone(),
            self.max_name_length,
        )?);
        self.ring.rcu(|current| EchKeyRing {
            active: Arc::clone(&fresh),
            previous: Some(Arc::clone(&current.active)),
        });
        self.public_snapshot()
    }

    /// Returns the currently active ECH key entry.
    #[must_use]
    pub fn active_entry(&self) -> Arc<EchKeyEntry> {
        Arc::clone(&self.ring.load().active)
    }

    /// Looks up a decryption key by `config_id` across both the active and grace-window slots.
    #[must_use]
    pub fn lookup_key(&self, config_id: u8) -> Option<Arc<EchKeyEntry>> {
        let guard = self.ring.load();
        if guard.active.config_id == config_id {
            return Some(Arc::clone(&guard.active));
        }
        if let Some(prev) = &guard.previous
            && prev.config_id == config_id
        {
            return Some(Arc::clone(prev));
        }
        None
    }

    /// Returns the wire-encoded RFC 9849 `ECHConfigList` for the active ECH configuration.
    ///
    /// # Errors
    /// Returns [`TlsError::CertGeneration`] if encoding fails.
    pub fn active_ech_config_list(&self) -> Result<EchConfigListBytes<'static>, TlsError> {
        self.ring.load().active.to_ech_config_list()
    }

    /// Returns a public snapshot including base64 `ECHConfigList` and an RFC 9460 DNS `HTTPS` RR.
    ///
    /// # Errors
    /// Returns [`TlsError::CertGeneration`] if wire encoding fails.
    pub fn public_snapshot(&self) -> Result<EchPublicSnapshot, TlsError> {
        let guard = self.ring.load();
        let list = guard.active.to_ech_config_list()?;
        let b64 = BASE64.encode(list.as_ref());
        let dns_record = format_dns_https_record(&self.public_name, &["h3", "h2"], &b64);
        let retained_key_count = 1 + usize::from(guard.previous.is_some());
        Ok(EchPublicSnapshot {
            active_config_id: guard.active.config_id,
            public_name: self.public_name.clone(),
            retained_key_count,
            ech_config_list_b64: b64,
            dns_https_record: dns_record,
            rotate_interval_secs: self.rotate_interval.as_secs(),
        })
    }
}

/// Formats an RFC 9460 DNS `HTTPS` resource record for publishing ECH + HTTP/3 ALPN.
#[must_use]
pub fn format_dns_https_record(owner_name: &str, alpns: &[&str], ech_list_b64: &str) -> String {
    let fqdn = if owner_name.ends_with('.') {
        owner_name.to_owned()
    } else {
        format!("{owner_name}.")
    };
    let alpn_csv = alpns.join(",");
    format!("{fqdn} 300 IN HTTPS 1 . alpn=\"{alpn_csv}\" ech=\"{ech_list_b64}\"")
}

/// Encodes a single RFC 9849 `ECHConfig` structure (`version = 0xfe0d`).
fn encode_ech_config(
    config_id: u8,
    public_key: &[u8],
    public_name: &str,
    max_name_length: u8,
) -> Result<Vec<u8>, TlsError> {
    let pk_len = u16::try_from(public_key.len())
        .map_err(|_| TlsError::CertGeneration("HPKE public key exceeds u16 length".to_owned()))?;
    let name_bytes = public_name.as_bytes();
    let name_len = u8::try_from(name_bytes.len())
        .map_err(|_| TlsError::CertGeneration("ECH public_name exceeds 255 bytes".to_owned()))?;

    // Advertise ONLY the HPKE suite backed by DH_KEM_X25519_HKDF_SHA256_AES_128.
    let suites: [(u16, u16); 1] = [(HPKE_KDF_HKDF_SHA256, HPKE_AEAD_AES_128_GCM)];
    let suites_byte_len = u16::try_from(suites.len() * 4)
        .map_err(|_| TlsError::CertGeneration("cipher suites list overflow".to_owned()))?;

    let mut contents = Vec::with_capacity(64 + name_bytes.len());
    // HpkeKeyConfig
    contents.push(config_id);
    contents.extend_from_slice(&HPKE_KEM_X25519_HKDF_SHA256.to_be_bytes());
    contents.extend_from_slice(&pk_len.to_be_bytes());
    contents.extend_from_slice(public_key);
    contents.extend_from_slice(&suites_byte_len.to_be_bytes());
    for (kdf, aead) in suites {
        contents.extend_from_slice(&kdf.to_be_bytes());
        contents.extend_from_slice(&aead.to_be_bytes());
    }
    // ECHConfigContents tail
    contents.push(max_name_length);
    contents.push(name_len);
    contents.extend_from_slice(name_bytes);
    // Extensions (empty, 2-byte zero length)
    contents.extend_from_slice(&0_u16.to_be_bytes());

    let contents_len = u16::try_from(contents.len())
        .map_err(|_| TlsError::CertGeneration("ECHConfigContents exceeds u16".to_owned()))?;

    let mut out = Vec::with_capacity(4 + contents.len());
    out.extend_from_slice(&ECH_CONFIG_VERSION.to_be_bytes());
    out.extend_from_slice(&contents_len.to_be_bytes());
    out.extend_from_slice(&contents);
    Ok(out)
}

/// Encodes one or more `ECHConfig` blobs into an RFC 9849 `ECHConfigList`.
fn encode_ech_config_list(configs: &[&[u8]]) -> Result<EchConfigListBytes<'static>, TlsError> {
    let total_len: usize = configs.iter().map(|c| c.len()).sum();
    let total_u16 = u16::try_from(total_len)
        .map_err(|_| TlsError::CertGeneration("ECHConfigList exceeds u16 length".to_owned()))?;
    let mut buf = Vec::with_capacity(2 + total_len);
    buf.extend_from_slice(&total_u16.to_be_bytes());
    for cfg in configs {
        buf.extend_from_slice(cfg);
    }
    Ok(EchConfigListBytes::from(buf))
}

fn is_valid_ech_public_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if trimmed.is_empty() {
        return false;
    }
    for label in trimmed.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return false;
        }
    }
    true
}

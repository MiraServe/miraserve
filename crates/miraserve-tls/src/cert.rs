//! PEM certificate/key loading (with secret zeroization), dev self-signed cert generation,
//! and X.509 certificate inspection.

use std::fs::File;
use std::io::Read as _;
use std::path::Path;
use std::sync::Arc;

use rcgen::{
    CertificateParams, CertifiedKey as RcgenCertifiedKey, KeyPair, PKCS_ECDSA_P256_SHA256,
};
use rustls::crypto::CryptoProvider;
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::Serialize;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer as _, X509Certificate};
use zeroize::Zeroizing;

use crate::TlsError;

/// Maximum PEM file size loaded from disk (2 MiB) to guard against OOM.
const MAX_PEM_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// PEM-encoded certificate chain and private key pair (zeroized on drop).
#[derive(Debug)]
pub struct GeneratedCertPem {
    /// PEM-encoded leaf certificate.
    pub cert_pem: String,
    /// PEM-encoded PKCS#8 private key (zeroized on drop).
    pub key_pem: Zeroizing<String>,
}

/// Human- and JSON-friendly summary of an X.509 leaf certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CertInfo {
    /// X.509 subject distinguished name.
    pub subject: String,
    /// X.509 issuer distinguished name.
    pub issuer: String,
    /// Hex-encoded serial number.
    pub serial_hex: String,
    /// Subject Alternative Names (DNS names and IP addresses).
    pub sans: Vec<String>,
    /// RFC 2822 / ISO-style validity start timestamp.
    pub not_before: String,
    /// RFC 2822 / ISO-style validity expiration timestamp.
    pub not_after: String,
    /// Validity span in days (truncated).
    pub validity_days: i64,
    /// Signature algorithm OID string.
    pub signature_algorithm: String,
    /// Number of certificates present in the PEM chain.
    pub chain_len: usize,
}

/// Loads a PEM certificate chain and private key from disk and compiles them into a
/// [`rustls::sign::CertifiedKey`] using the supplied [`CryptoProvider`].
///
/// Raw private key bytes read from disk are wrapped in [`Zeroizing`] and cleared on drop
/// (Threat Model T2).
///
/// # Errors
/// Returns [`TlsError`] if reading, PEM parsing, or signing key construction fails.
pub fn load_certified_key_from_files(
    cert_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
    provider: &CryptoProvider,
) -> Result<Arc<CertifiedKey>, TlsError> {
    let cert_bytes = read_bounded_file(cert_path.as_ref())?;
    let key_bytes = Zeroizing::new(read_bounded_file(key_path.as_ref())?);
    load_certified_key_from_pem(&cert_bytes, &key_bytes, provider)
}

/// Parses PEM-encoded certificate chain bytes and private key bytes into a [`CertifiedKey`].
///
/// # Errors
/// Returns [`TlsError`] if the PEM contains no certificates, no valid private key, or
/// if the key cannot be loaded into the crypto provider.
pub fn load_certified_key_from_pem(
    cert_pem: &[u8],
    key_pem: &[u8],
    provider: &CryptoProvider,
) -> Result<Arc<CertifiedKey>, TlsError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| TlsError::PemParse(format!("certificate PEM error: {err}")))?;

    if certs.is_empty() {
        return Err(TlsError::PemParse(
            "certificate PEM contains no certificates".to_owned(),
        ));
    }

    let key = PrivateKeyDer::from_pem_slice(key_pem)
        .map_err(|err| TlsError::PemParse(format!("private key PEM error: {err}")))?;

    let signing_key = provider
        .key_provider
        .load_private_key(key)
        .map_err(|err| TlsError::KeyLoad(err.to_string()))?;

    let certified = CertifiedKey::new(certs, signing_key);
    certified.keys_match().map_err(|err| {
        TlsError::KeyLoad(format!("certificate and private key do not match: {err}"))
    })?;

    Ok(Arc::new(certified))
}

/// Generates a self-signed ECDSA P-256 development TLS certificate covering the given
/// hostnames/IPs (automatically including `localhost`, `127.0.0.1`, and `::1`).
///
/// # Errors
/// Returns [`TlsError`] if certificate generation or key loading fails.
pub fn generate_dev_certificate(
    hosts: &[String],
    provider: &CryptoProvider,
) -> Result<(Arc<CertifiedKey>, GeneratedCertPem), TlsError> {
    let mut san_list: Vec<String> = Vec::with_capacity(hosts.len().saturating_add(3));
    for h in hosts {
        let trimmed = h.trim();
        if !trimmed.is_empty()
            && !san_list
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(trimmed))
        {
            san_list.push(trimmed.to_owned());
        }
    }
    for default_san in ["localhost", "127.0.0.1", "::1"] {
        if !san_list
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(default_san))
        {
            san_list.push(default_san.to_owned());
        }
    }

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|err| TlsError::CertGeneration(err.to_string()))?;
    let mut params = CertificateParams::new(san_list)
        .map_err(|err| TlsError::CertGeneration(err.to_string()))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "MiraServe Dev Certificate");
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "MiraServe Local Dev");

    let cert = params
        .self_signed(&key_pair)
        .map_err(|err| TlsError::CertGeneration(err.to_string()))?;

    let cert_pem = cert.pem();
    let key_pem = Zeroizing::new(key_pair.serialize_pem());
    let certified = load_certified_key_from_pem(cert_pem.as_bytes(), key_pem.as_bytes(), provider)?;

    Ok((certified, GeneratedCertPem { cert_pem, key_pem }))
}

/// Generates a short-lived self-signed dev certificate and returns raw PEM material
/// without compiling into a [`CertifiedKey`].
///
/// # Errors
/// Returns [`TlsError`] if certificate generation fails.
pub fn generate_dev_cert_pem(hosts: &[String]) -> Result<GeneratedCertPem, TlsError> {
    let provider = crate::build_crypto_provider(true);
    let (_key, pem) = generate_dev_certificate(hosts, &provider)?;
    Ok(pem)
}

/// Inspects the leaf certificate in a PEM file on disk.
///
/// # Errors
/// Returns [`TlsError`] if reading, PEM decoding, or X.509 DER parsing fails.
pub fn inspect_cert_file(path: impl AsRef<Path>) -> Result<CertInfo, TlsError> {
    let raw = read_bounded_file(path.as_ref())?;
    inspect_cert_pem(&raw)
}

/// Inspects the leaf certificate from PEM-encoded bytes.
///
/// # Errors
/// Returns [`TlsError`] if no certificate is found or X.509 DER parsing fails.
pub fn inspect_cert_pem(pem_bytes: &[u8]) -> Result<CertInfo, TlsError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem_bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| TlsError::PemParse(format!("certificate PEM error: {err}")))?;

    let leaf = certs
        .first()
        .ok_or_else(|| TlsError::PemParse("PEM contains no certificates".to_owned()))?;

    let (_, parsed) = X509Certificate::from_der(leaf.as_ref())
        .map_err(|err| TlsError::CertInspect(format!("X.509 DER parse failed: {err}")))?;

    let mut sans = Vec::new();
    if let Ok(Some(san_ext)) = parsed.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            match name {
                GeneralName::DNSName(dns) => sans.push((*dns).to_owned()),
                GeneralName::IPAddress(bytes) => {
                    if let Ok(arr) = <[u8; 4]>::try_from(*bytes) {
                        sans.push(std::net::Ipv4Addr::from(arr).to_string());
                    } else if let Ok(arr) = <[u8; 16]>::try_from(*bytes) {
                        sans.push(std::net::Ipv6Addr::from(arr).to_string());
                    }
                }
                _ => {}
            }
        }
    }

    let validity = parsed.validity();
    let span_secs = validity
        .not_after
        .timestamp()
        .saturating_sub(validity.not_before.timestamp());
    let validity_days = span_secs / 86_400;

    Ok(CertInfo {
        subject: parsed.subject().to_string(),
        issuer: parsed.issuer().to_string(),
        serial_hex: parsed.raw_serial_as_string(),
        sans,
        not_before: validity.not_before.to_string(),
        not_after: validity.not_after.to_string(),
        validity_days,
        signature_algorithm: parsed.signature_algorithm.algorithm.to_id_string(),
        chain_len: certs.len(),
    })
}

/// Converts a self-signed `rcgen` key pair bundle directly into a [`CertifiedKey`].
///
/// Does not invoke `CertifiedKey::keys_match()` (which parses via `webpki` and rejects
/// RFC 8737 critical `id-pe-acmeIdentifier` extensions); key/cert correspondence is
/// guaranteed by construction from the freshly generated `rcgen::CertifiedKey`.
pub(crate) fn certified_key_from_rcgen(
    rcgen_bundle: &RcgenCertifiedKey<KeyPair>,
    provider: &CryptoProvider,
) -> Result<Arc<CertifiedKey>, TlsError> {
    let cert_der = rcgen_bundle.cert.der().clone();
    let key_pem = Zeroizing::new(rcgen_bundle.signing_key.serialize_pem());
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|err| TlsError::PemParse(format!("private key PEM error: {err}")))?;
    let signing_key = provider
        .key_provider
        .load_private_key(key)
        .map_err(|err| TlsError::KeyLoad(err.to_string()))?;
    Ok(Arc::new(CertifiedKey::new(vec![cert_der], signing_key)))
}

pub(crate) fn read_bounded_file(path: &Path) -> Result<Vec<u8>, TlsError> {
    let file = File::open(path).map_err(|source| TlsError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    read_bounded_open_file(file, path)
}

/// Reads an already-opened regular file with the same size cap as [`read_bounded_file`]
/// (used by ACME to read cache entries through `O_NOFOLLOW` handles opened relative to verified
/// directories without changing manual-TLS pathname semantics; Codex Round-7 P2 #2).
pub(crate) fn read_bounded_open_file(file: File, path: &Path) -> Result<Vec<u8>, TlsError> {
    let meta = file.metadata().map_err(|source| TlsError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !meta.is_file() {
        return Err(TlsError::PemParse(format!(
            "PEM path '{}' is not a regular file",
            path.display()
        )));
    }
    let cap = usize::try_from(meta.len().min(MAX_PEM_FILE_BYTES)).unwrap_or(0);
    let mut buf = Vec::with_capacity(cap);
    file.take(MAX_PEM_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|source| TlsError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if (buf.len() as u64) > MAX_PEM_FILE_BYTES {
        return Err(TlsError::PemParse(format!(
            "PEM file '{}' exceeds maximum safety size of {MAX_PEM_FILE_BYTES} bytes",
            path.display()
        )));
    }
    Ok(buf)
}

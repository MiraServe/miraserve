//! Split-privilege TLS signing daemon (`miraserve-keyd`) and remote worker signer
//! enforcing Threat Model T2 (Heartbleed-class private key exfiltration defense).
//!
//! # Architecture & Hardening
//! - **Daemon (`KeydServer`):** Holds TLS private keys in a dedicated isolated process/store.
//!   Exposes ONLY public certificate metadata (`ListCerts`) and restricted signing (`Sign`)
//!   over a `0600` Unix domain socket (inside a `0700` directory, enforcing `peer_cred().uid()`)
//!   or an HMAC-SHA256 challenge-response authenticated loopback TCP socket.
//! - **Per-Key Anti-Oracle Guard:** Enforces RFC 8446 §4.4.3 TLS 1.3 `CertificateVerify`
//!   (rejecting `RSA_PKCS1_*` on TLS 1.3), and restricts TLS 1.2 signing exclusively to
//!   explicitly opted-in `allow_tls12` keys AND valid RFC 8422 ECDHE `ServerKeyExchange`
//!   payloads — blocking chosen-message signing abuse even if a worker is compromised.
//! - **Resource Bounds:** Connection cap (`Semaphore(128)`), per-IO timeouts (`5s`),
//!   accept-error backoff (`25ms`), and incremental bounded frame reads.

use std::collections::HashMap;
use std::io::Read as _;
use std::net::{SocketAddr, TcpStream as StdTcpStream};
use std::path::{Path, PathBuf};
use std::str::FromStr as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use rustls::crypto::tls13::OkmBlock;
use rustls::pki_types::CertificateDer;
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::cert::load_certified_key_from_files;
use crate::resolver::DynamicCertResolver;
use crate::{TlsError, build_crypto_provider};

/// Environment variable used by workers and `miraserve-keyd` to share a 32-byte base64
/// HMAC-SHA256 authentication secret when using `LoopbackTcp`.
pub const KEYD_AUTH_SECRET_ENV: &str = "MIRASERVE_KEYD_AUTH_SECRET";

/// Prepares the parent directory of a same-UID keyd Unix socket (Codex Round-5/6 P2).
///
/// A missing directory is created `0700` and an existing private directory is verified and
/// tightened to `0700` (see [`crate::acme::create_private_dir_all`]). A pre-existing sticky shared
/// directory such as `/tmp` (`1777`) is left untouched ONLY when it is owned by root or by this
/// process: the owner of a sticky directory can still replace any entry in it, so a sticky
/// directory owned by another account is refused. Clients additionally verify the connected
/// daemon's UID (see [`verify_keyd_server_uid`]), so a name claimed in a shared directory while
/// keyd is down is never trusted.
#[cfg(unix)]
fn ensure_keyd_socket_parent(parent: &Path) -> Result<(), TlsError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if let Ok(md) = std::fs::symlink_metadata(parent)
        && md.file_type().is_dir()
        && (md.permissions().mode() & 0o1000) != 0
    {
        let trusted_owner = md.uid() == 0 || md.uid() == process_effective_uid();
        if !trusted_owner {
            return Err(TlsError::KeyLoad(format!(
                "refusing keyd Unix socket in sticky directory '{}' owned by uid {}: its owner can replace the socket; use a private runtime directory",
                parent.display(),
                md.uid()
            )));
        }
        return Ok(());
    }
    crate::acme::create_private_dir_all(parent)
}

/// Evaluates whether a keyd socket parent chain establishes a trustworthy dedicated runtime
/// directory for `peer_uid` (Codex Round-7 P2 #3).
///
/// Every ancestor strictly above the socket's parent (e.g. `/` and `/run` for
/// `/run/miraserve-keyd/keyd.sock`) must be owned by root or `my_uid` and must NOT be group- or
/// world-writable at all (not even sticky, so another user cannot create a private directory
/// beneath `/tmp` and claim ownership of it). The socket's parent itself must not be
/// group/world-writable and must be owned by `peer_uid`.
#[cfg(unix)]
pub(crate) fn is_trusted_keyd_parent_chain(
    ancestors: &[(u32, u32)],
    parent: (u32, u32),
    my_uid: u32,
    peer_uid: u32,
) -> bool {
    if ancestors.is_empty() {
        return false;
    }
    let ancestors_trusted = ancestors
        .iter()
        .all(|&(uid, mode)| (uid == 0 || uid == my_uid) && (mode & 0o022) == 0);
    let (parent_uid, parent_mode) = parent;
    ancestors_trusted && (parent_mode & 0o022) == 0 && parent_uid == peer_uid
}

#[cfg(unix)]
type OwnerModeChain = (Vec<(u32, u32)>, (u32, u32));

/// Walks `socket_path.parent()` from `/` without following untrusted symlinks (using `O_PATH` on
/// Linux so Landlock never needs `READ_DIR` on `/` or `/run`) and returns `Some((ancestors, parent))`
/// metadata `(uid, mode)` pairs if every component is a real directory.
#[cfg(unix)]
fn inspect_keyd_socket_parent_chain(socket_path: &Path) -> Option<OwnerModeChain> {
    use rustix::fs::{CWD, FileType, Mode, OFlags, fstat, openat};
    use rustix::io::Errno;
    use std::path::Component;

    let parent = socket_path.parent().filter(|p| !p.as_os_str().is_empty())?;
    let abs = if parent.is_absolute() {
        parent.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(parent)
    };
    let mut parts: Vec<&std::ffi::OsStr> = Vec::new();
    for comp in abs.components() {
        match comp {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => parts.push(name),
            Component::ParentDir | Component::Prefix(_) => return None,
        }
    }
    if parts.is_empty() {
        return None;
    }

    #[cfg(target_os = "linux")]
    let root_flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let root_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
    let step_flags = root_flags | OFlags::NOFOLLOW;

    let mut cur_fd = openat(CWD, "/", root_flags, Mode::empty()).ok()?;
    let root_st = fstat(&cur_fd).ok()?;
    if FileType::from_raw_mode(root_st.st_mode) != FileType::Directory {
        return None;
    }
    let mut ancestors = Vec::with_capacity(parts.len());
    #[allow(clippy::useless_conversion)]
    let root_mode = u32::from(root_st.st_mode) & 0o7777;
    ancestors.push((root_st.st_uid, root_mode));

    let mut parent_meta: Option<(u32, u32)> = None;
    for (idx, comp) in parts.iter().enumerate() {
        let is_leaf = idx + 1 == parts.len();
        let next_fd = match openat(&cur_fd, *comp, step_flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::LOOP | Errno::NOTDIR) => {
                crate::acme::open_trusted_os_root_link(&cur_fd, comp, idx, is_leaf)
                    .ok()
                    .flatten()?
            }
            Err(_) => return None,
        };
        let st = fstat(&next_fd).ok()?;
        if FileType::from_raw_mode(st.st_mode) != FileType::Directory {
            return None;
        }
        #[allow(clippy::useless_conversion)]
        let step_mode = u32::from(st.st_mode) & 0o7777;
        let pair = (st.st_uid, step_mode);
        if is_leaf {
            parent_meta = Some(pair);
        } else {
            ancestors.push(pair);
        }
        cur_fd = next_fd;
    }
    Some((ancestors, parent_meta?))
}

/// Verifies the UID of the daemon at the other end of a keyd Unix socket (Codex Round-6/7 P2).
///
/// If `expected_server_uid` is explicitly pinned by the operator, only that exact UID is accepted.
/// Otherwise accepted daemon UIDs are: this process's own UID, root, or the owner of a dedicated
/// non-group/world-writable runtime directory whose entire ancestry is non-shared and root- or
/// self-owned (such as packaged `/run/miraserve-keyd` under root-owned `0755` `/run`).
///
/// # Errors
/// Returns [`TlsError::KeyLoad`] if the connected daemon's UID is not trusted.
#[cfg(unix)]
pub(crate) fn verify_keyd_server_uid(
    socket_path: &Path,
    peer_uid: u32,
    expected_server_uid: Option<u32>,
) -> Result<(), TlsError> {
    if let Some(expected) = expected_server_uid {
        if peer_uid == expected {
            return Ok(());
        }
        return Err(TlsError::KeyLoad(format!(
            "refusing keyd Unix socket '{}': connected daemon runs as uid {peer_uid}, expected configured uid {expected}",
            socket_path.display()
        )));
    }

    let my_uid = process_effective_uid();
    if peer_uid == 0 || peer_uid == my_uid {
        return Ok(());
    }
    if let Some((ancestors, parent)) = inspect_keyd_socket_parent_chain(socket_path)
        && is_trusted_keyd_parent_chain(&ancestors, parent, my_uid, peer_uid)
    {
        return Ok(());
    }
    Err(TlsError::KeyLoad(format!(
        "refusing keyd Unix socket '{}': connected daemon runs as uid {peer_uid}, which is neither this process, root, nor the owner of a dedicated runtime directory with non-shared root/self ancestry",
        socket_path.display()
    )))
}

/// Maximum IPC request frame size accepted by `miraserve-keyd` (256 KiB).
const MAX_KEYD_FRAME_BYTES: usize = 256 * 1024;
/// Maximum IPC response frame size accepted by worker clients (4 MiB, supporting large `ListCerts` vaults, `KEYD-3`).
const MAX_KEYD_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum payload length accepted by `Sign` (4 KiB; TLS 1.3 `CertificateVerify` is <= 162 bytes).
const MAX_SIGN_MESSAGE_BYTES: usize = 4096;
/// Maximum concurrent worker connections handled by `miraserve-keyd`.
const MAX_KEYD_CONNECTIONS: usize = 128;
/// Synchronous worker IPC socket read/write timeout.
const CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(5);
/// Per-operation server IPC timeout protecting daemon tasks against stalled frames.
const SERVER_IO_TIMEOUT: Duration = Duration::from_secs(5);
/// Idle keep-alive timeout between requests on an already-authenticated worker connection (`R3-KEYD-1`).
const SERVER_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum number of concurrent active TCP pre-auth HMAC handshakes (`R3-KEYD-1`).
const MAX_KEYD_PREAUTH_ACTIVE: usize = 64;
/// Maximum number of queued + active TCP pre-auth handshakes before dropping (`R3-KEYD-1`).
const MAX_KEYD_PREAUTH_QUEUED: usize = 128;
/// Short bounded queue wait for pre-auth / signing pool permits during legitimate bursts (`R3-KEYD-1`).
const KEYD_PERMIT_WAIT_TIMEOUT: Duration = Duration::from_millis(500);
/// Maximum idle authenticated IPC connections pooled per worker client (`R3-KEYD-1`).
const MAX_CLIENT_POOLED_CONNS: usize = 16;
/// Maximum idle age of a pooled client connection before discarding (half of `SERVER_IDLE_TIMEOUT`).
const CLIENT_POOL_MAX_IDLE: Duration = Duration::from_secs(15);
/// Backoff after transient listener accept errors.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(25);

/// RFC 8446 Section 4.4.3 TLS 1.3 server `CertificateVerify` context prefix (64 spaces + 34 bytes = 98 bytes).
const TLS13_SERVER_CERT_VERIFY_PREFIX: &[u8; 98] =
    b"                                                                TLS 1.3, server CertificateVerify\0";

/// Domain-separation prefix for `miraserve-keyd` HMAC-SHA256 challenge-response authentication.
const KEYD_AUTH_DOMAIN: &[u8] = b"miraserve-keyd-auth-v1:";

/// Candidate modern TLS signature schemes probed when registering a signing key in `keyd`.
const PROBE_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ED25519,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512,
];

/// Transport endpoint for IPC between MiraServe worker processes and `miraserve-keyd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeydEndpoint {
    /// Restricted local Unix domain socket (`0600` permissions in `0700` dir + `peer_cred` UID check).
    #[cfg(unix)]
    Unix(PathBuf),
    /// Strictly loopback TCP socket (`127.0.0.1:<port>` or `[::1]:<port>`) with mandatory HMAC-SHA256 auth.
    LoopbackTcp(SocketAddr),
}

impl KeydEndpoint {
    /// Parses a `keyd-socket` specification (`"/run/miraserve/keyd.sock"`, `"unix:/..."`,
    /// or loopback `"tcp://127.0.0.1:9444"`).
    ///
    /// # Errors
    /// Returns [`TlsError::KeyLoad`] if the endpoint is invalid, non-loopback TCP, or unsupported
    /// on the current platform.
    pub fn parse(spec: &str) -> Result<Self, TlsError> {
        let trimmed = spec.trim();
        if trimmed.is_empty() {
            return Err(TlsError::KeyLoad(
                "keyd endpoint cannot be empty".to_owned(),
            ));
        }
        if let Some(raw_tcp) = trimmed.strip_prefix("tcp://") {
            let addr = SocketAddr::from_str(raw_tcp).map_err(|err| {
                TlsError::KeyLoad(format!("invalid keyd TCP address '{trimmed}': {err}"))
            })?;
            if !addr.ip().is_loopback() {
                return Err(TlsError::KeyLoad(format!(
                    "keyd TCP endpoint '{trimmed}' MUST bind strictly to loopback (Threat Model T2)"
                )));
            }
            return Ok(Self::LoopbackTcp(addr));
        }

        let path_str = trimmed.strip_prefix("unix:").unwrap_or(trimmed);
        #[cfg(unix)]
        {
            Ok(Self::Unix(PathBuf::from(path_str)))
        }
        #[cfg(not(unix))]
        {
            let _ = path_str;
            Err(TlsError::KeyLoad(
                "Unix domain sockets are unavailable on this OS; use tcp://127.0.0.1:<port>"
                    .to_owned(),
            ))
        }
    }

    /// Formats the endpoint back into a canonical `keyd-socket` string.
    #[must_use]
    pub fn to_socket_string(&self) -> String {
        match self {
            #[cfg(unix)]
            Self::Unix(p) => p.display().to_string(),
            Self::LoopbackTcp(addr) => format!("tcp://{addr}"),
        }
    }
}

/// Generates a fresh 32-byte cryptographically random secret for `miraserve-keyd` IPC auth.
///
/// # Errors
/// Returns [`TlsError::KeyLoad`] if OS CSPRNG fails.
pub fn generate_keyd_auth_secret() -> Result<Zeroizing<[u8; 32]>, TlsError> {
    let mut secret = Zeroizing::new([0_u8; 32]);
    rustls::crypto::aws_lc_rs::default_provider()
        .secure_random
        .fill(secret.as_mut())
        .map_err(|_| TlsError::KeyLoad("CSPRNG failed generating keyd auth secret".to_owned()))?;
    Ok(secret)
}

/// Parses a 32-byte `miraserve-keyd` auth secret from standard Base64 or 64-char hex text.
///
/// # Errors
/// Returns [`TlsError::KeyLoad`] if decoding fails or decoded length is not 32 bytes.
pub fn parse_keyd_auth_secret(raw: &str) -> Result<Zeroizing<[u8; 32]>, TlsError> {
    let trimmed = raw.trim();
    if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut out = Zeroizing::new([0_u8; 32]);
        for i in 0..32 {
            let pair = trimmed.get(i * 2..i * 2 + 2).unwrap_or("00");
            let byte = u8::from_str_radix(pair, 16)
                .map_err(|_| TlsError::KeyLoad("invalid hex keyd auth secret".to_owned()))?;
            if let Some(slot) = out.get_mut(i) {
                *slot = byte;
            }
        }
        return Ok(out);
    }
    let decoded = Zeroizing::new(
        BASE64
            .decode(trimmed)
            .map_err(|err| TlsError::KeyLoad(format!("invalid base64 keyd auth secret: {err}")))?,
    );
    let arr: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| TlsError::KeyLoad("keyd auth secret must be exactly 32 bytes".to_owned()))?;
    Ok(Zeroizing::new(arr))
}

/// Loads an optional `miraserve-keyd` auth secret from a regular file on disk.
///
/// # Errors
/// Returns [`TlsError`] if reading or parsing fails.
pub fn load_keyd_auth_secret_file(path: &Path) -> Result<Zeroizing<[u8; 32]>, TlsError> {
    let bytes = Zeroizing::new(crate::cert::read_bounded_file(path)?);
    let text =
        Zeroizing::new(String::from_utf8(bytes.to_vec()).map_err(|_| {
            TlsError::KeyLoad("keyd auth secret file must be valid UTF-8".to_owned())
        })?);
    parse_keyd_auth_secret(&text)
}

/// Loads an optional `miraserve-keyd` auth secret from `MIRASERVE_KEYD_AUTH_SECRET`, returning
/// an explicit error if the environment variable is set to a malformed value (`R2-KEYD-3`).
///
/// # Errors
/// Returns [`TlsError::KeyLoad`] if `MIRASERVE_KEYD_AUTH_SECRET` is set but invalid.
pub fn load_keyd_auth_secret_from_env() -> Result<Option<Zeroizing<[u8; 32]>>, TlsError> {
    match std::env::var(KEYD_AUTH_SECRET_ENV) {
        Ok(raw) => parse_keyd_auth_secret(&raw).map(Some),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(TlsError::KeyLoad(format!(
            "{KEYD_AUTH_SECRET_ENV} is not valid UTF-8"
        ))),
    }
}

/// Public certificate metadata exported by `miraserve-keyd` to workers (contains NO private key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeydCertDescriptor {
    /// Unique identifier for this certificate/key slot.
    pub key_id: String,
    /// Hostnames served by this certificate (may include `*.domain`).
    pub hosts: Vec<String>,
    /// Whether this certificate is the default fallback certificate.
    pub is_default: bool,
    /// Base64-encoded X.509 DER certificate chain (leaf first).
    pub cert_chain_der_b64: Vec<String>,
    /// Wire ID of `rustls::SignatureAlgorithm`.
    pub algorithm_u8: u8,
    /// Wire IDs of supported `rustls::SignatureScheme`s.
    pub supported_schemes_u16: Vec<u16>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum KeydRequest {
    ListCerts,
    Sign {
        key_id: String,
        scheme_u16: u16,
        message_b64: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum KeydResponse {
    Certs { entries: Vec<KeydCertDescriptor> },
    Signature { signature_b64: String },
    Error { message: String },
}

#[derive(Debug)]
struct KeydEntry {
    descriptor: KeydCertDescriptor,
    certified_key: Arc<CertifiedKey>,
    allow_tls12: bool,
}

/// Isolated private-key vault held exclusively inside the `miraserve-keyd` daemon process.
#[derive(Debug, Default)]
pub struct KeydKeyStore {
    entries: HashMap<String, KeydEntry>,
    order: Vec<String>,
}

impl KeydKeyStore {
    /// Creates an empty key vault.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a TLS 1.3-strict [`CertifiedKey`] inside the daemon vault under `key_id`.
    ///
    /// # Errors
    /// Returns [`TlsError::KeyLoad`] if the key supports no modern TLS signature schemes.
    pub fn insert_certified_key(
        &mut self,
        key_id: impl Into<String>,
        hosts: Vec<String>,
        is_default: bool,
        certified_key: Arc<CertifiedKey>,
    ) -> Result<(), TlsError> {
        self.insert_certified_key_with_policy(key_id, hosts, is_default, certified_key, false)
    }

    /// Registers a [`CertifiedKey`] inside the daemon vault with an explicit per-key
    /// `allow_tls12` policy (`true` permits ONLY RFC 8422 ECDHE `ServerKeyExchange` signing
    /// in addition to TLS 1.3 `CertificateVerify`).
    ///
    /// # Errors
    /// Returns [`TlsError::KeyLoad`] if the key supports no modern TLS signature schemes.
    pub fn insert_certified_key_with_policy(
        &mut self,
        key_id: impl Into<String>,
        hosts: Vec<String>,
        is_default: bool,
        certified_key: Arc<CertifiedKey>,
        allow_tls12: bool,
    ) -> Result<(), TlsError> {
        let key_id = key_id.into();
        let supported_schemes: Vec<u16> = PROBE_SCHEMES
            .iter()
            .copied()
            .filter(|scheme| {
                // Never advertise legacy RSA_PKCS1_* on TLS 1.3-only keys.
                if !allow_tls12 && is_rsa_pkcs1_scheme(*scheme) {
                    return false;
                }
                certified_key.key.choose_scheme(&[*scheme]).is_some()
            })
            .map(u16::from)
            .collect();
        if supported_schemes.is_empty() {
            return Err(TlsError::KeyLoad(format!(
                "key '{key_id}' supports no recognized TLS signature schemes"
            )));
        }

        let cert_chain_der_b64 = certified_key
            .cert
            .iter()
            .map(|der| BASE64.encode(der.as_ref()))
            .collect();

        let descriptor = KeydCertDescriptor {
            key_id: key_id.clone(),
            hosts,
            is_default,
            cert_chain_der_b64,
            algorithm_u8: u8::from(certified_key.key.algorithm()),
            supported_schemes_u16: supported_schemes,
        };

        if !self.entries.contains_key(&key_id) {
            self.order.push(key_id.clone());
        }
        self.entries.insert(
            key_id,
            KeydEntry {
                descriptor,
                certified_key,
                allow_tls12,
            },
        );
        Ok(())
    }

    /// Loads a PEM certificate & private key pair from disk directly into the daemon vault
    /// (TLS 1.3-only anti-oracle policy by default).
    ///
    /// # Errors
    /// Returns [`TlsError`] if reading, parsing, or verifying the cert/key pair fails.
    pub fn load_pem_pair(
        &mut self,
        key_id: impl Into<String>,
        hosts: Vec<String>,
        is_default: bool,
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> Result<(), TlsError> {
        self.load_pem_pair_with_policy(key_id, hosts, is_default, cert_path, key_path, false)
    }

    /// Loads a PEM certificate & private key pair with an explicit per-key `allow_tls12` flag.
    ///
    /// # Errors
    /// Returns [`TlsError`] if reading, parsing, or verifying the cert/key pair fails.
    pub fn load_pem_pair_with_policy(
        &mut self,
        key_id: impl Into<String>,
        hosts: Vec<String>,
        is_default: bool,
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
        allow_tls12: bool,
    ) -> Result<(), TlsError> {
        let provider = build_crypto_provider(true);
        let ck = load_certified_key_from_files(cert_path, key_path, &provider)?;
        self.insert_certified_key_with_policy(key_id, hosts, is_default, ck, allow_tls12)
    }

    /// Returns the number of loaded signing keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when no signing keys are loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn list_descriptors(&self) -> Vec<KeydCertDescriptor> {
        self.order
            .iter()
            .filter_map(|id| self.entries.get(id).map(|e| e.descriptor.clone()))
            .collect()
    }

    fn sign(
        &self,
        key_id: &str,
        scheme: SignatureScheme,
        message: &[u8],
        global_allow_tls12: bool,
    ) -> Result<Vec<u8>, String> {
        if message.is_empty() || message.len() > MAX_SIGN_MESSAGE_BYTES {
            return Err(format!(
                "refusing to sign payload of {} bytes (must be 1..={MAX_SIGN_MESSAGE_BYTES})",
                message.len()
            ));
        }

        let entry = self
            .entries
            .get(key_id)
            .ok_or_else(|| format!("unknown key_id '{key_id}'"))?;

        if is_tls13_server_certificate_verify(message) {
            // RFC 8446 §4.4.3 forbids RSA PKCS#1 v1.5 in TLS 1.3 CertificateVerify.
            if is_rsa_pkcs1_scheme(scheme) {
                return Err(
                    "refused RSA PKCS#1 v1.5 scheme for TLS 1.3 CertificateVerify".to_owned(),
                );
            }
        } else if (entry.allow_tls12 || global_allow_tls12)
            && is_tls12_ecdhe_server_key_exchange(message)
        {
            // Permitted ONLY for explicitly opted-in TLS 1.2 keys AND valid RFC 8422 ECDHE params.
        } else {
            return Err(
                "refused non-TLS-1.3-CertificateVerify / non-TLS-1.2-ECDHE signing request (anti-oracle guard T2)"
                    .to_owned(),
            );
        }

        let signer = entry
            .certified_key
            .key
            .choose_scheme(&[scheme])
            .ok_or_else(|| format!("key '{key_id}' does not support scheme {scheme:?}"))?;
        signer
            .sign(message)
            .map_err(|err| format!("signing operation failed: {err}"))
    }
}

const fn is_rsa_pkcs1_scheme(scheme: SignatureScheme) -> bool {
    matches!(
        scheme,
        SignatureScheme::RSA_PKCS1_SHA256
            | SignatureScheme::RSA_PKCS1_SHA384
            | SignatureScheme::RSA_PKCS1_SHA512
    )
}

/// Checks whether `message` matches the RFC 8446 Section 4.4.3 TLS 1.3 server
/// `CertificateVerify` format (`64 * 0x20 || "TLS 1.3, server CertificateVerify\0" || hash`).
#[must_use]
pub fn is_tls13_server_certificate_verify(message: &[u8]) -> bool {
    let hash_len = message
        .len()
        .checked_sub(TLS13_SERVER_CERT_VERIFY_PREFIX.len());
    matches!(hash_len, Some(32 | 48 | 64)) && message.starts_with(TLS13_SERVER_CERT_VERIFY_PREFIX)
}

/// Checks whether `message` strictly matches an RFC 5246 §7.4.3 / RFC 8422 §5.4 TLS 1.2
/// ECDHE `ServerKeyExchange` signed payload:
/// `client_random(32) || server_random(32) || named_curve(0x03) || curve_id(2) || len(1) || pubkey`.
#[must_use]
pub fn is_tls12_ecdhe_server_key_exchange(message: &[u8]) -> bool {
    if message.len() < 69 {
        return false;
    }
    if message.get(64) != Some(&0x03) {
        return false;
    }
    let (Some(&c_hi), Some(&c_lo), Some(&pt_len)) =
        (message.get(65), message.get(66), message.get(67))
    else {
        return false;
    };
    let named_curve = u16::from_be_bytes([c_hi, c_lo]);
    let expected_len = match named_curve {
        0x0017 => 65_usize,  // secp256r1 uncompressed point
        0x0018 => 97_usize,  // secp384r1 uncompressed point
        0x0019 => 133_usize, // secp521r1 uncompressed point
        0x001d => 32_usize,  // x25519
        _ => return false,
    };
    if usize::from(pt_len) != expected_len || message.len() != 68 + expected_len {
        return false;
    }
    if named_curve != 0x001d && message.get(68) != Some(&0x04) {
        return false;
    }
    true
}

/// Handle to a running split-privilege `miraserve-keyd` signing daemon.
pub struct RunningKeyd {
    endpoint: KeydEndpoint,
    auth_secret: Option<Zeroizing<[u8; 32]>>,
    signatures_served: Arc<AtomicU64>,
    shutdown_tx: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for RunningKeyd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunningKeyd")
            .field("endpoint", &self.endpoint)
            .field("authenticated", &self.auth_secret.is_some())
            .field("signatures_served", &self.signatures_served())
            .finish_non_exhaustive()
    }
}

impl RunningKeyd {
    /// Returns the actual bound endpoint (resolving port `0` for loopback TCP tests).
    #[must_use]
    pub fn endpoint(&self) -> &KeydEndpoint {
        &self.endpoint
    }

    /// Returns the 32-byte HMAC-SHA256 authentication secret (always `Some` for `LoopbackTcp`).
    #[must_use]
    pub fn auth_secret(&self) -> Option<[u8; 32]> {
        self.auth_secret.as_deref().copied()
    }

    /// Returns total TLS handshake signatures successfully produced by this daemon.
    #[must_use]
    pub fn signatures_served(&self) -> u64 {
        self.signatures_served.load(Ordering::Acquire)
    }

    /// Shuts down the signing daemon gracefully and removes its Unix socket file ONLY if
    /// it is still a real Unix socket (never unlinking symlinks or regular files).
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.task.await;
        #[cfg(unix)]
        if let KeydEndpoint::Unix(path) = &self.endpoint {
            remove_existing_unix_socket(path);
        }
    }
}

/// Unix domain socket peer authorization policy for `miraserve-keyd` (`R3-PKG-2`, `R4-KEYD-1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeydUnixPeerPolicy {
    /// Strictest default: `0600` socket inside a `0700` directory; kernel `SO_PEERCRED`
    /// requires exact `cred.uid() == keyd_uid`.
    #[default]
    SameUidOnly,
    /// Separate-UID exact-peer authorization (`R4-KEYD-1`): `0660` socket inside a `0750`
    /// (setgid `2750 miraserve-keyd:miraserve` on systemd) directory; kernel `SO_PEERCRED`
    /// requires `cred.uid() == keyd_uid || cred.uid() == peer_uid` — NEVER authorizing the
    /// worker's entire group!
    SameUidOrPeerUid(u32),
    /// Strict single-peer UID authorization: `0660` socket inside a `0750` directory; kernel
    /// `SO_PEERCRED` requires `cred.uid() == peer_uid` (rejecting every other UID, including
    /// the keyd process's own UID when distinct).
    ExactPeerUid(u32),
    /// Legacy separate-UID group-isolated mode: `0660` socket inside a `0750` directory; kernel
    /// `SO_PEERCRED` requires `cred.uid() == keyd_uid || cred.gid() == keyd_gid`. Prefer
    /// [`Self::SameUidOrPeerUid`] (`--allow-peer-user`) to avoid authorizing unrelated group peers.
    SameUidOrGroup,
}

/// Resolves a Unix username or numeric UID string to a numeric `u32` UID without `unsafe` FFI
/// (parses numeric UIDs directly, scans `/etc/passwd`, and falls back to `/usr/bin/id -u` for
/// NSS/LDAP/SSSD accounts on Unix, `R4-KEYD-1` / `R5-SBX-3`).
///
/// # Errors
/// Returns [`TlsError::KeyLoad`] if `user` is empty, root (`0`), or cannot be resolved.
pub fn resolve_unix_user_uid(user: &str) -> Result<u32, TlsError> {
    let trimmed = user.trim();
    if trimmed.is_empty() {
        return Err(TlsError::KeyLoad(
            "peer user identifier must not be empty".to_owned(),
        ));
    }
    if let Ok(uid) = trimmed.parse::<u32>() {
        if uid == 0 {
            return Err(TlsError::KeyLoad(
                "refusing to authorize root (UID 0) as a keyd worker peer".to_owned(),
            ));
        }
        return Ok(uid);
    }
    if trimmed.eq_ignore_ascii_case("root") {
        return Err(TlsError::KeyLoad(
            "refusing to authorize 'root' as a keyd worker peer".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
            for line in content.lines() {
                let mut fields = line.split(':');
                if let (Some(name), Some(_pw), Some(uid_str)) =
                    (fields.next(), fields.next(), fields.next())
                    && name == trimmed
                    && let Ok(uid) = uid_str.parse::<u32>()
                {
                    if uid == 0 {
                        return Err(TlsError::KeyLoad(format!(
                            "user '{trimmed}' resolves to UID 0 (root); refused as keyd worker peer"
                        )));
                    }
                    return Ok(uid);
                }
            }
        }
        // Fallback to `/usr/bin/id -u` for NSS/LDAP/SSSD accounts (only safe identifier chars).
        if !trimmed.starts_with('-')
            && trimmed
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'$'))
            && let Ok(out) = std::process::Command::new("/usr/bin/id")
                .args(["-u", trimmed])
                .output()
            && out.status.success()
            && let Ok(uid) = String::from_utf8_lossy(&out.stdout).trim().parse::<u32>()
        {
            if uid == 0 {
                return Err(TlsError::KeyLoad(format!(
                    "user '{trimmed}' resolves to UID 0 (root); refused as keyd worker peer"
                )));
            }
            return Ok(uid);
        }
        Err(TlsError::KeyLoad(format!(
            "Unix user '{trimmed}' not found in /etc/passwd or NSS"
        )))
    }
    #[cfg(not(unix))]
    {
        Err(TlsError::KeyLoad(format!(
            "cannot resolve non-numeric Unix username '{trimmed}' on non-Unix host"
        )))
    }
}

/// Split-privilege TLS signing daemon (`miraserve-keyd`).
#[derive(Debug)]
pub struct KeydServer;

impl KeydServer {
    /// Starts a `miraserve-keyd` signing daemon listening on `endpoint`.
    ///
    /// For [`KeydEndpoint::LoopbackTcp`], automatically reads `MIRASERVE_KEYD_AUTH_SECRET`
    /// or generates a fresh CSPRNG 32-byte auth secret so TCP IPC is NEVER unauthenticated.
    ///
    /// # Errors
    /// Returns [`TlsError`] if binding the Unix socket or loopback TCP listener fails.
    pub async fn start(
        endpoint: KeydEndpoint,
        store: KeydKeyStore,
        allow_tls12_signing: bool,
    ) -> Result<RunningKeyd, TlsError> {
        let env_secret = load_keyd_auth_secret_from_env()?;
        let auth_secret = match &endpoint {
            KeydEndpoint::LoopbackTcp(_) => {
                if let Some(env_sec) = env_secret {
                    Some(env_sec)
                } else {
                    Some(generate_keyd_auth_secret()?)
                }
            }
            #[cfg(unix)]
            KeydEndpoint::Unix(_) => env_secret,
        };
        Self::start_with_auth(endpoint, store, allow_tls12_signing, auth_secret).await
    }

    /// Starts a `miraserve-keyd` signing daemon with an explicit optional 32-byte HMAC-SHA256
    /// authentication secret (REQUIRED for [`KeydEndpoint::LoopbackTcp`]).
    ///
    /// # Errors
    /// Returns [`TlsError`] if `LoopbackTcp` lacks an auth secret or socket binding fails.
    pub async fn start_with_auth(
        endpoint: KeydEndpoint,
        store: KeydKeyStore,
        allow_tls12_signing: bool,
        auth_secret: Option<Zeroizing<[u8; 32]>>,
    ) -> Result<RunningKeyd, TlsError> {
        Self::start_with_options(
            endpoint,
            store,
            allow_tls12_signing,
            auth_secret,
            KeydUnixPeerPolicy::SameUidOnly,
        )
        .await
    }

    /// Starts a `miraserve-keyd` signing daemon with explicit authentication secret and Unix
    /// peer authorization policy (`SameUidOnly` vs `SameUidOrGroup` for separate-UID systemd
    /// isolation, `R3-PKG-2`).
    ///
    /// # Errors
    /// Returns [`TlsError`] if `LoopbackTcp` lacks an auth secret or socket binding fails.
    #[allow(clippy::too_many_lines)]
    pub async fn start_with_options(
        endpoint: KeydEndpoint,
        store: KeydKeyStore,
        allow_tls12_signing: bool,
        auth_secret: Option<Zeroizing<[u8; 32]>>,
        unix_peer_policy: KeydUnixPeerPolicy,
    ) -> Result<RunningKeyd, TlsError> {
        let _ = unix_peer_policy;
        let store = Arc::new(store);
        let signatures_served = Arc::new(AtomicU64::new(0));
        let conn_sem = Arc::new(Semaphore::new(MAX_KEYD_CONNECTIONS));
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        match endpoint {
            KeydEndpoint::LoopbackTcp(addr) => {
                if !addr.ip().is_loopback() {
                    return Err(TlsError::KeyLoad(
                        "keyd TCP listener must bind strictly to loopback".to_owned(),
                    ));
                }
                let Some(secret) = auth_secret else {
                    return Err(TlsError::KeyLoad(
                        "keyd LoopbackTcp listener requires a 32-byte HMAC-SHA256 auth secret (Threat Model T2)"
                            .to_owned(),
                    ));
                };
                let listener = TcpListener::bind(addr)
                    .await
                    .map_err(|source| TlsError::Io {
                        path: PathBuf::from(addr.to_string()),
                        source,
                    })?;
                let local_addr = listener.local_addr().map_err(|source| TlsError::Io {
                    path: PathBuf::from(addr.to_string()),
                    source,
                })?;
                let resolved = KeydEndpoint::LoopbackTcp(local_addr);
                info!(
                    endpoint = %resolved.to_socket_string(),
                    keys = store.len(),
                    "miraserve-keyd listening (authenticated loopback TCP)"
                );

                let secret_arc = Arc::new(secret.clone());
                let counter = Arc::clone(&signatures_served);
                // R2-KEYD-1 & R3-KEYD-1: Separate pre-auth pool (64 active + 128 bounded queue,
                // 500ms wait) so legitimate >16 handshake bursts queue cleanly without blocking
                // `listener.accept()`, while silent unauthenticated peers still cannot starve
                // the main 128-slot authenticated signing pool!
                let preauth_sem = Arc::new(Semaphore::new(MAX_KEYD_PREAUTH_ACTIVE));
                let preauth_queue_sem = Arc::new(Semaphore::new(MAX_KEYD_PREAUTH_QUEUED));
                let task = tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            changed = shutdown_rx.changed() => {
                                if changed.is_err() || *shutdown_rx.borrow() {
                                    break;
                                }
                            }
                            accepted = listener.accept() => {
                                match accepted {
                                    Ok((mut stream, _peer)) => {
                                        let Ok(queue_permit) =
                                            Arc::clone(&preauth_queue_sem).try_acquire_owned()
                                        else {
                                            debug!("keyd TCP pre-auth queue saturated; dropping unauthenticated peer");
                                            drop(stream);
                                            continue;
                                        };
                                        let st = Arc::clone(&store);
                                        let ctr = Arc::clone(&counter);
                                        let sec = Arc::clone(&secret_arc);
                                        let pre_sem = Arc::clone(&preauth_sem);
                                        let main_sem = Arc::clone(&conn_sem);
                                        tokio::spawn(async move {
                                            let Ok(Ok(preauth_permit)) = tokio::time::timeout(
                                                KEYD_PERMIT_WAIT_TIMEOUT,
                                                pre_sem.acquire_owned(),
                                            )
                                            .await
                                            else {
                                                debug!("keyd TCP pre-auth wait timed out; dropping peer");
                                                return;
                                            };
                                            let authed = authenticate_keyd_peer(&mut stream, &sec).await;
                                            drop(preauth_permit);
                                            drop(queue_permit);
                                            if !authed {
                                                return;
                                            }
                                            let Ok(Ok(permit)) = tokio::time::timeout(
                                                KEYD_PERMIT_WAIT_TIMEOUT,
                                                main_sem.acquire_owned(),
                                            )
                                            .await
                                            else {
                                                debug!("keyd TCP signing connection cap reached; dropping peer");
                                                return;
                                            };
                                            let _permit = permit;
                                            handle_keyd_connection(
                                                stream,
                                                st,
                                                ctr,
                                                allow_tls12_signing,
                                                None,
                                            )
                                            .await;
                                        });
                                    }
                                    Err(err) => {
                                        warn!(error = %err, "keyd TCP accept error");
                                        tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                                    }
                                }
                            }
                        }
                    }
                });

                Ok(RunningKeyd {
                    endpoint: resolved,
                    auth_secret: Some(secret),
                    signatures_served,
                    shutdown_tx,
                    task,
                })
            }
            #[cfg(unix)]
            KeydEndpoint::Unix(path) => {
                use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

                if let Some(parent) = path.parent()
                    && !parent.as_os_str().is_empty()
                {
                    match unix_peer_policy {
                        KeydUnixPeerPolicy::SameUidOnly => ensure_keyd_socket_parent(parent)?,
                        KeydUnixPeerPolicy::SameUidOrPeerUid(_)
                        | KeydUnixPeerPolicy::ExactPeerUid(_)
                        | KeydUnixPeerPolicy::SameUidOrGroup => {
                            let mut builder = std::fs::DirBuilder::new();
                            builder.recursive(true).mode(0o750);
                            builder.create(parent).map_err(|source| TlsError::Io {
                                path: parent.to_path_buf(),
                                source,
                            })?;
                        }
                    }
                }

                // Refuse unlinking symlinks or non-socket files before bind (TOCTOU defense).
                if let Ok(md) = std::fs::symlink_metadata(&path) {
                    use std::os::unix::fs::FileTypeExt as _;
                    if !md.file_type().is_socket() {
                        return Err(TlsError::KeyLoad(format!(
                            "refusing to unlink non-socket path '{}' for keyd Unix socket",
                            path.display()
                        )));
                    }
                    std::fs::remove_file(&path).map_err(|source| TlsError::Io {
                        path: path.clone(),
                        source,
                    })?;
                }

                // R2-KEYD-3 & Codex Round-7 P2 #1: Derive expected effective UID/GID directly from
                // the OS kernel BEFORE binding (never trusting post-bind socket metadata or procfs).
                let (expected_user_id, expected_group_id) = current_unix_uid_gid();

                let listener =
                    tokio::net::UnixListener::bind(&path).map_err(|source| TlsError::Io {
                        path: path.clone(),
                        source,
                    })?;

                let socket_mode = match unix_peer_policy {
                    KeydUnixPeerPolicy::SameUidOnly => 0o600,
                    KeydUnixPeerPolicy::SameUidOrPeerUid(_)
                    | KeydUnixPeerPolicy::ExactPeerUid(_)
                    | KeydUnixPeerPolicy::SameUidOrGroup => 0o660,
                };

                // Fail closed if setting socket permissions fails.
                if let Err(source) =
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(socket_mode))
                {
                    drop(listener);
                    remove_existing_unix_socket(&path);
                    return Err(TlsError::Io { path, source });
                }

                info!(
                    socket = %path.display(),
                    uid = expected_user_id,
                    gid = expected_group_id,
                    policy = ?unix_peer_policy,
                    mode = format_args!("{socket_mode:04o}"),
                    keys = store.len(),
                    "miraserve-keyd listening (Unix socket + kernel peer_cred check)"
                );

                let secret_arc = auth_secret.as_ref().map(|s| Arc::new(s.clone()));
                let counter = Arc::clone(&signatures_served);
                let unix_queue_sem = Arc::new(Semaphore::new(MAX_KEYD_PREAUTH_QUEUED));
                let task = tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            changed = shutdown_rx.changed() => {
                                if changed.is_err() || *shutdown_rx.borrow() {
                                    break;
                                }
                            }
                            accepted = listener.accept() => {
                                match accepted {
                                    Ok((stream, _addr)) => {
                                        // Enforce kernel SO_PEERCRED / LOCAL_PEERCRED UID check
                                        // BEFORE consuming any queue or connection permit (`R4-KEYD-1`).
                                        let peer_ok = stream.peer_cred().is_ok_and(|cred| {
                                            match unix_peer_policy {
                                                KeydUnixPeerPolicy::SameUidOnly => {
                                                    cred.uid() == expected_user_id
                                                }
                                                KeydUnixPeerPolicy::SameUidOrPeerUid(allowed_uid) => {
                                                    cred.uid() == expected_user_id
                                                        || cred.uid() == allowed_uid
                                                }
                                                KeydUnixPeerPolicy::ExactPeerUid(allowed_uid) => {
                                                    cred.uid() == allowed_uid
                                                }
                                                KeydUnixPeerPolicy::SameUidOrGroup => {
                                                    cred.uid() == expected_user_id
                                                        || cred.gid() == expected_group_id
                                                }
                                            }
                                        });
                                        if !peer_ok {
                                            warn!("keyd rejected Unix peer with unauthorized UID/GID");
                                            drop(stream);
                                            continue;
                                        }
                                        // R3-KEYD-1: Bounded short wait on Unix signing pool permits
                                        // (matching TCP) so legitimate >128 bursts queue briefly
                                        // instead of instant drop!
                                        let Ok(queue_permit) =
                                            Arc::clone(&unix_queue_sem).try_acquire_owned()
                                        else {
                                            warn!("keyd Unix signing queue saturated; dropping peer");
                                            drop(stream);
                                            continue;
                                        };
                                        let main_sem = Arc::clone(&conn_sem);
                                        let st = Arc::clone(&store);
                                        let ctr = Arc::clone(&counter);
                                        let sec = secret_arc.clone();
                                        tokio::spawn(async move {
                                            let Ok(Ok(permit)) = tokio::time::timeout(
                                                KEYD_PERMIT_WAIT_TIMEOUT,
                                                main_sem.acquire_owned(),
                                            )
                                            .await
                                            else {
                                                warn!("keyd Unix signing connection wait timed out; dropping peer");
                                                return;
                                            };
                                            drop(queue_permit);
                                            let _permit = permit;
                                            handle_keyd_connection(
                                                stream,
                                                st,
                                                ctr,
                                                allow_tls12_signing,
                                                sec,
                                            )
                                            .await;
                                        });
                                    }
                                    Err(err) => {
                                        warn!(error = %err, "keyd Unix accept error");
                                        tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                                    }
                                }
                            }
                        }
                    }
                });

                Ok(RunningKeyd {
                    endpoint: KeydEndpoint::Unix(path),
                    auth_secret,
                    signatures_served,
                    shutdown_tx,
                    task,
                })
            }
        }
    }
}

/// Effective UID of this process directly from the OS kernel (`geteuid(2)` via `rustix`, zero
/// procfs or subprocess dependency; Codex Round-7 P2 #1).
#[cfg(unix)]
pub(crate) fn process_effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[cfg(unix)]
pub(crate) fn current_unix_uid_gid() -> (u32, u32) {
    (
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
    )
}

#[cfg(unix)]
fn remove_existing_unix_socket(path: &Path) {
    use std::os::unix::fs::FileTypeExt as _;
    if let Ok(md) = std::fs::symlink_metadata(path)
        && md.file_type().is_socket()
    {
        let _ = std::fs::remove_file(path);
    }
}

/// Strict pre-auth deadline for `miraserve-keyd` HMAC challenge-response (`R2-KEYD-1`).
const PREAUTH_IO_TIMEOUT: Duration = Duration::from_secs(1);

async fn authenticate_keyd_peer<S>(stream: &mut S, secret: &[u8; 32]) -> bool
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut nonce = [0_u8; 32];
    if rustls::crypto::aws_lc_rs::default_provider()
        .secure_random
        .fill(&mut nonce)
        .is_err()
    {
        return false;
    }
    if tokio::time::timeout(PREAUTH_IO_TIMEOUT, async {
        stream.write_all(&nonce).await?;
        stream.flush().await
    })
    .await
    .ok()
    .and_then(Result::ok)
    .is_none()
    {
        return false;
    }

    let mut client_tag = [0_u8; 32];
    if tokio::time::timeout(PREAUTH_IO_TIMEOUT, stream.read_exact(&mut client_tag))
        .await
        .ok()
        .and_then(Result::ok)
        .is_none()
    {
        return false;
    }

    let expected_tag = compute_keyd_auth_tag(secret, &nonce);
    if !ct_eq_32(&client_tag, &expected_tag) {
        warn!("keyd rejected unauthenticated IPC peer (HMAC challenge mismatch)");
        return false;
    }
    true
}

#[allow(clippy::too_many_lines)]
async fn handle_keyd_connection<S>(
    mut stream: S,
    store: Arc<KeydKeyStore>,
    signatures_served: Arc<AtomicU64>,
    global_allow_tls12: bool,
    auth_secret: Option<Arc<Zeroizing<[u8; 32]>>>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Perform mandatory HMAC-SHA256 challenge-response handshake when auth_secret is configured
    // (Unix sockets with optional secret; LoopbackTcp authenticates via `authenticate_keyd_peer`
    // under the pre-auth semaphore before acquiring a main signing slot).
    if let Some(secret) = &auth_secret
        && !authenticate_keyd_peer(&mut stream, secret).await
    {
        return;
    }

    loop {
        let mut len_buf = [0_u8; 4];
        match tokio::time::timeout(SERVER_IDLE_TIMEOUT, stream.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => return,
            Ok(Err(err)) => {
                debug!(error = %err, "keyd connection closed");
                return;
            }
            Err(_) => {
                debug!("keyd connection idle timeout waiting for next request");
                return;
            }
        }
        let frame_len = u32::from_be_bytes(len_buf) as usize;
        if frame_len == 0 || frame_len > MAX_KEYD_FRAME_BYTES {
            let _ = tokio::time::timeout(
                SERVER_IO_TIMEOUT,
                write_async_frame(
                    &mut stream,
                    &KeydResponse::Error {
                        message: "frame size out of bounds".to_owned(),
                    },
                ),
            )
            .await;
            return;
        }

        // Incremental bounded read avoids upfront 256 KiB allocation on truncated/malicious frames.
        let mut payload = Vec::with_capacity(frame_len.min(4096));
        let read_res = tokio::time::timeout(
            SERVER_IO_TIMEOUT,
            (&mut stream)
                .take(frame_len as u64)
                .read_to_end(&mut payload),
        )
        .await;
        if !matches!(read_res, Ok(Ok(n)) if n == frame_len) {
            return;
        }

        let response = match serde_json::from_slice::<KeydRequest>(&payload) {
            Ok(KeydRequest::ListCerts) => KeydResponse::Certs {
                entries: store.list_descriptors(),
            },
            Ok(KeydRequest::Sign {
                key_id,
                scheme_u16,
                message_b64,
            }) => match BASE64.decode(message_b64.as_bytes()) {
                Ok(msg) => {
                    let scheme = SignatureScheme::from(scheme_u16);
                    match store.sign(&key_id, scheme, &msg, global_allow_tls12) {
                        Ok(sig) => {
                            signatures_served.fetch_add(1, Ordering::AcqRel);
                            KeydResponse::Signature {
                                signature_b64: BASE64.encode(sig),
                            }
                        }
                        Err(message) => {
                            warn!(key_id = %key_id, reason = %message, "keyd rejected signing request");
                            KeydResponse::Error { message }
                        }
                    }
                }
                Err(err) => KeydResponse::Error {
                    message: format!("invalid base64 message: {err}"),
                },
            },
            Err(err) => KeydResponse::Error {
                message: format!("malformed keyd RPC request: {err}"),
            },
        };

        if tokio::time::timeout(SERVER_IO_TIMEOUT, write_async_frame(&mut stream, &response))
            .await
            .ok()
            .and_then(Result::ok)
            .is_none()
        {
            return;
        }
    }
}

fn compute_keyd_auth_tag(secret: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    let rustls::SupportedCipherSuite::Tls13(suite) =
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256
    else {
        return [0_u8; 32];
    };
    let mut msg = Vec::with_capacity(KEYD_AUTH_DOMAIN.len() + nonce.len());
    msg.extend_from_slice(KEYD_AUTH_DOMAIN);
    msg.extend_from_slice(nonce);
    let tag = suite.hkdf_provider.hmac_sign(&OkmBlock::new(secret), &msg);
    let mut out = [0_u8; 32];
    if let Some(slice) = tag.as_ref().get(..32) {
        out.copy_from_slice(slice);
    }
    out
}

fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0_u8;
    for i in 0..32 {
        if let (Some(&x), Some(&y)) = (a.get(i), b.get(i)) {
            diff |= x ^ y;
        }
    }
    diff == 0
}

async fn write_async_frame<S>(stream: &mut S, resp: &KeydResponse) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut json = serde_json::to_vec(resp).map_err(std::io::Error::other)?;
    if json.len() > MAX_KEYD_RESPONSE_BYTES {
        warn!(
            bytes = json.len(),
            limit = MAX_KEYD_RESPONSE_BYTES,
            "keyd response exceeded maximum IPC frame size"
        );
        json = serde_json::to_vec(&KeydResponse::Error {
            message: format!(
                "keyd response size {} exceeds {MAX_KEYD_RESPONSE_BYTES}-byte IPC frame limit",
                json.len()
            ),
        })
        .map_err(std::io::Error::other)?;
    }
    let len = u32::try_from(json.len()).map_err(std::io::Error::other)?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&json).await?;
    stream.flush().await
}

enum PooledKeydStream {
    Tcp(StdTcpStream),
    #[cfg(unix)]
    Unix {
        stream: std::os::unix::net::UnixStream,
        peer_uid: u32,
    },
}

impl PooledKeydStream {
    fn send_framed(&mut self, req_len: u32, req_bytes: &[u8]) -> Result<KeydResponse, TlsError> {
        match self {
            Self::Tcp(s) => sync_framed_exchange(s, req_len, req_bytes),
            #[cfg(unix)]
            Self::Unix { stream, .. } => sync_framed_exchange(stream, req_len, req_bytes),
        }
    }

    fn matches_expected_uid(&self, expected_server_uid: Option<u32>) -> bool {
        #[cfg(not(unix))]
        let _ = expected_server_uid;
        match self {
            Self::Tcp(_) => true,
            #[cfg(unix)]
            Self::Unix { peer_uid, .. } => expected_server_uid.is_none_or(|exp| *peer_uid == exp),
        }
    }
}

/// Bounded pool of already-authenticated persistent worker->keyd IPC connections (`R3-KEYD-1`).
///
/// Reusing authenticated sockets avoids a new TCP/Unix connect and HMAC pre-auth roundtrip on
/// every TLS handshake, so legitimate handshakes continue uninterrupted even during local
/// unauthenticated pre-auth floods.
#[derive(Default)]
struct KeydConnPool {
    idle: Mutex<Vec<(PooledKeydStream, Instant)>>,
}

impl KeydConnPool {
    fn take(&self, expected_server_uid: Option<u32>) -> Option<PooledKeydStream> {
        let now = Instant::now();
        let mut guard = match self.idle.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        while let Some((stream, last_used)) = guard.pop() {
            if now.saturating_duration_since(last_used) <= CLIENT_POOL_MAX_IDLE
                && stream.matches_expected_uid(expected_server_uid)
            {
                return Some(stream);
            }
        }
        None
    }

    fn put(&self, stream: PooledKeydStream) {
        let now = Instant::now();
        let mut guard = match self.idle.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.retain(|(_, ts)| now.saturating_duration_since(*ts) <= CLIENT_POOL_MAX_IDLE);
        if guard.len() < MAX_CLIENT_POOLED_CONNS {
            guard.push((stream, now));
        }
    }
}

/// Worker-side IPC client communicating with an isolated `miraserve-keyd` signing daemon.
#[derive(Clone)]
pub struct KeydClient {
    endpoint: KeydEndpoint,
    auth_secret: Option<Arc<Zeroizing<[u8; 32]>>>,
    pool: Arc<KeydConnPool>,
    io_timeout: Duration,
    expected_server_uid: Option<u32>,
}

impl std::fmt::Debug for KeydClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeydClient")
            .field("endpoint", &self.endpoint)
            .field("authenticated", &self.auth_secret.is_some())
            .field("io_timeout", &self.io_timeout)
            .field("expected_server_uid", &self.expected_server_uid)
            .finish_non_exhaustive()
    }
}

impl KeydClient {
    /// Creates a new [`KeydClient`] targeting `endpoint` (loading
    /// `MIRASERVE_KEYD_AUTH_SECRET` from the environment if valid; prefer
    /// [`Self::from_env`] when malformed env values must fail startup).
    #[must_use]
    pub fn new(endpoint: KeydEndpoint) -> Self {
        let auth_secret = match load_keyd_auth_secret_from_env() {
            Ok(secret) => secret.map(Arc::new),
            Err(err) => {
                warn!(error = %err, "ignoring malformed MIRASERVE_KEYD_AUTH_SECRET in KeydClient::new");
                None
            }
        };
        Self {
            endpoint,
            auth_secret,
            pool: Arc::new(KeydConnPool::default()),
            io_timeout: CLIENT_IO_TIMEOUT,
            expected_server_uid: None,
        }
    }

    /// Creates a new [`KeydClient`] targeting `endpoint`, failing fast if
    /// `MIRASERVE_KEYD_AUTH_SECRET` is set to a malformed value (`R2-KEYD-3`).
    ///
    /// # Errors
    /// Returns [`TlsError::KeyLoad`] when `MIRASERVE_KEYD_AUTH_SECRET` is present
    /// in the environment but is not a valid 32-byte Base64 or 64-hex secret.
    pub fn from_env(endpoint: KeydEndpoint) -> Result<Self, TlsError> {
        let auth_secret = load_keyd_auth_secret_from_env()?.map(Arc::new);
        Ok(Self {
            endpoint,
            auth_secret,
            pool: Arc::new(KeydConnPool::default()),
            io_timeout: CLIENT_IO_TIMEOUT,
            expected_server_uid: None,
        })
    }

    /// Creates a new [`KeydClient`] with an explicit 32-byte HMAC-SHA256 auth secret.
    #[must_use]
    pub fn with_auth_secret(endpoint: KeydEndpoint, secret: [u8; 32]) -> Self {
        Self {
            endpoint,
            auth_secret: Some(Arc::new(Zeroizing::new(secret))),
            pool: Arc::new(KeydConnPool::default()),
            io_timeout: CLIENT_IO_TIMEOUT,
            expected_server_uid: None,
        }
    }

    /// Pins the exact Unix UID expected from the connected `miraserve-keyd` daemon (Codex Round-7
    /// P2 #3, Round-8 P2 #2). Allocates an isolated connection pool whenever the expected UID
    /// changes so connections authenticated under an earlier policy or a differently pinned clone
    /// are never reused.
    #[must_use]
    pub fn with_expected_server_uid(mut self, uid: u32) -> Self {
        if self.expected_server_uid != Some(uid) {
            self.expected_server_uid = Some(uid);
            self.pool = Arc::new(KeydConnPool::default());
        }
        self
    }

    /// Overrides the connect/read/write I/O timeout for this client (used by `check --fs` probes
    /// and deterministic tests, `R6-CHK-1`, `R6-KEYD-1`).
    #[must_use]
    pub const fn with_io_timeout(mut self, timeout: Duration) -> Self {
        self.io_timeout = timeout;
        self
    }

    /// Performs a real timed `ListCerts` protocol probe against `keyd`, verifying socket
    /// connectivity, OS `SO_PEERCRED` UID authorization, and HMAC authentication (`R6-CHK-1`).
    ///
    /// # Errors
    /// Returns [`TlsError::KeyLoad`] if connect times out, peer UID/auth is rejected, or keyd
    /// returns an error.
    pub fn probe_access(&self) -> Result<usize, TlsError> {
        match self.roundtrip_sync(&KeydRequest::ListCerts)? {
            KeydResponse::Certs { entries } => Ok(entries.len()),
            KeydResponse::Error { message } => Err(TlsError::KeyLoad(message)),
            KeydResponse::Signature { .. } => Err(TlsError::KeyLoad(
                "unexpected keyd response to ListCerts probe".to_owned(),
            )),
        }
    }

    /// Fetches all public certificate chains from `keyd` and wraps each in a
    /// [`CertifiedKey`] backed by [`RemoteSigningKey`] (zero private key bytes in worker memory).
    ///
    /// # Errors
    /// Returns [`TlsError`] if IPC communication or DER decoding fails.
    pub fn load_remote_certified_keys(&self) -> Result<RemoteKeyBundle, TlsError> {
        let resp = self.roundtrip_sync(&KeydRequest::ListCerts)?;
        let entries = match resp {
            KeydResponse::Certs { entries } => entries,
            KeydResponse::Error { message } => return Err(TlsError::KeyLoad(message)),
            KeydResponse::Signature { .. } => {
                return Err(TlsError::KeyLoad(
                    "unexpected keyd response to ListCerts".to_owned(),
                ));
            }
        };

        let mut host_certs: Vec<(String, Arc<CertifiedKey>)> = Vec::new();
        let mut default_cert: Option<Arc<CertifiedKey>> = None;

        for desc in entries {
            let mut cert_chain = Vec::with_capacity(desc.cert_chain_der_b64.len());
            for b64 in &desc.cert_chain_der_b64 {
                let der = BASE64
                    .decode(b64.as_bytes())
                    .map_err(|err| TlsError::PemParse(format!("invalid cert DER base64: {err}")))?;
                cert_chain.push(CertificateDer::from(der));
            }
            if cert_chain.is_empty() {
                continue;
            }
            let supported_schemes: Vec<SignatureScheme> = desc
                .supported_schemes_u16
                .into_iter()
                .map(SignatureScheme::from)
                .collect();
            let remote_key = RemoteSigningKey {
                endpoint: self.endpoint.clone(),
                auth_secret: self.auth_secret.clone(),
                pool: Arc::clone(&self.pool),
                expected_server_uid: self.expected_server_uid,
                key_id: desc.key_id,
                algorithm: SignatureAlgorithm::from(desc.algorithm_u8),
                supported_schemes,
            };
            let ck = Arc::new(CertifiedKey::new(cert_chain, Arc::new(remote_key)));
            for host in desc.hosts {
                host_certs.push((host, Arc::clone(&ck)));
            }
            if desc.is_default || default_cert.is_none() {
                default_cert = Some(ck);
            }
        }

        if default_cert.is_none() && host_certs.is_empty() {
            return Err(TlsError::NoCertificates);
        }

        Ok(RemoteKeyBundle {
            host_certs,
            default_cert,
        })
    }

    /// Populates `resolver` exclusively with remote-signed certificates fetched from `keyd`.
    ///
    /// # Errors
    /// Returns [`TlsError`] if `keyd` cannot be contacted or serves no certificates.
    pub fn populate_resolver(&self, resolver: &DynamicCertResolver) -> Result<usize, TlsError> {
        let bundle = self.load_remote_certified_keys()?;
        let count = bundle.host_certs.len() + usize::from(bundle.default_cert.is_some());
        resolver.replace_all(bundle.host_certs, bundle.default_cert);
        Ok(count)
    }

    /// Sends a raw signing RPC request to `keyd` (used by [`RemoteSigningKey`] and anti-oracle tests).
    ///
    /// # Errors
    /// Returns [`TlsError::KeyLoad`] if `keyd` rejects the request or IPC fails.
    pub fn request_signature(
        &self,
        key_id: &str,
        scheme: SignatureScheme,
        message: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        let req = KeydRequest::Sign {
            key_id: key_id.to_owned(),
            scheme_u16: u16::from(scheme),
            message_b64: BASE64.encode(message),
        };
        match self.roundtrip_sync(&req)? {
            KeydResponse::Signature { signature_b64 } => {
                BASE64.decode(signature_b64.as_bytes()).map_err(|err| {
                    TlsError::KeyLoad(format!("invalid base64 signature from keyd: {err}"))
                })
            }
            KeydResponse::Error { message } => Err(TlsError::KeyLoad(message)),
            KeydResponse::Certs { .. } => Err(TlsError::KeyLoad(
                "unexpected keyd response to Sign".to_owned(),
            )),
        }
    }

    fn connect_and_authenticate(&self) -> Result<PooledKeydStream, TlsError> {
        let timeout = self.io_timeout;
        match &self.endpoint {
            KeydEndpoint::LoopbackTcp(addr) => {
                let Some(secret) = self.auth_secret.as_deref() else {
                    return Err(TlsError::KeyLoad(
                        "keyd LoopbackTcp client requires an auth secret (set MIRASERVE_KEYD_AUTH_SECRET or use KeydClient::with_auth_secret)"
                            .to_owned(),
                    ));
                };
                let mut stream = StdTcpStream::connect_timeout(addr, timeout).map_err(|err| {
                    TlsError::KeyLoad(format!("failed to connect to keyd at {addr}: {err}"))
                })?;
                let _ = stream.set_read_timeout(Some(timeout));
                let _ = stream.set_write_timeout(Some(timeout));
                sync_authenticate(&mut stream, secret)?;
                Ok(PooledKeydStream::Tcp(stream))
            }
            #[cfg(unix)]
            KeydEndpoint::Unix(path) => {
                // R2-KEYD-2, R5-KEYD-1 & R6-KEYD-1: Bound `UnixStream::connect` by `io_timeout`
                // without leaking detached threads, without panicking on current-thread Tokio
                // runtimes, and retrying `WouldBlock`/`EAGAIN` on saturated Unix listen backlogs!
                let (mut stream, peer_uid) =
                    connect_unix_with_timeout(path, timeout, self.expected_server_uid)?;
                let _ = stream.set_read_timeout(Some(timeout));
                let _ = stream.set_write_timeout(Some(timeout));
                if let Some(secret) = self.auth_secret.as_deref() {
                    sync_authenticate(&mut stream, secret)?;
                }
                Ok(PooledKeydStream::Unix { stream, peer_uid })
            }
        }
    }

    fn roundtrip_sync(&self, req: &KeydRequest) -> Result<KeydResponse, TlsError> {
        let req_bytes = serde_json::to_vec(req)
            .map_err(|err| TlsError::KeyLoad(format!("keyd RPC serialize error: {err}")))?;
        let req_len = u32::try_from(req_bytes.len())
            .map_err(|_| TlsError::KeyLoad("keyd RPC request too large".to_owned()))?;

        let do_io = || {
            // R3-KEYD-1 & Codex Round-8 P2 #2: Try reusing an already-authenticated pooled
            // connection only when its recorded peer UID matches the current policy.
            if let Some(mut pooled) = self.pool.take(self.expected_server_uid)
                && let Ok(resp) = pooled.send_framed(req_len, &req_bytes)
            {
                self.pool.put(pooled);
                return Ok(resp);
            }
            let mut fresh = self.connect_and_authenticate()?;
            let resp = fresh.send_framed(req_len, &req_bytes)?;
            self.pool.put(fresh);
            Ok(resp)
        };

        // Yield Tokio's multi-threaded worker slot & IO driver before blocking on keyd IPC.
        if let Ok(handle) = tokio::runtime::Handle::try_current()
            && handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
        {
            tokio::task::block_in_place(do_io)
        } else {
            do_io()
        }
    }
}

#[cfg(unix)]
async fn connect_unix_async(
    path: &Path,
    timeout: Duration,
    expected_server_uid: Option<u32>,
) -> Result<(std::os::unix::net::UnixStream, u32), TlsError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match tokio::time::timeout_at(deadline, tokio::net::UnixStream::connect(path)).await {
            Ok(Ok(stream)) => {
                // Codex Round-6/7 P2: authenticate the daemon's UID before trusting any response.
                let peer_uid = stream
                    .peer_cred()
                    .map_err(|err| {
                        TlsError::KeyLoad(format!(
                            "failed to read keyd daemon credentials on '{}': {err}",
                            path.display()
                        ))
                    })?
                    .uid();
                verify_keyd_server_uid(path, peer_uid, expected_server_uid)?;
                let std_stream = stream.into_std().map_err(|err| {
                    TlsError::KeyLoad(format!(
                        "failed converting keyd Unix stream '{}': {err}",
                        path.display()
                    ))
                })?;
                // `tokio::net::UnixStream::into_std` preserves `O_NONBLOCK`; restore blocking
                // mode so `set_read_timeout`/`set_write_timeout` and `read_exact` work reliably.
                std_stream.set_nonblocking(false).map_err(|err| {
                    TlsError::KeyLoad(format!(
                        "failed setting blocking mode on keyd Unix stream '{}': {err}",
                        path.display()
                    ))
                })?;
                return Ok((std_stream, peer_uid));
            }
            Ok(Err(err))
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    return Err(TlsError::KeyLoad(format!(
                        "timed out after {}ms connecting to keyd Unix socket '{}' (backlog busy: {err})",
                        timeout.as_millis(),
                        path.display()
                    )));
                }
                let pause = Duration::from_millis(5).min(deadline.saturating_duration_since(now));
                tokio::time::sleep(pause).await;
            }
            Ok(Err(err)) => {
                return Err(TlsError::KeyLoad(format!(
                    "failed to connect to keyd Unix socket '{}': {err}",
                    path.display()
                )));
            }
            Err(_) => {
                return Err(TlsError::KeyLoad(format!(
                    "timed out after {}ms connecting to keyd Unix socket '{}'",
                    timeout.as_millis(),
                    path.display()
                )));
            }
        }
    }
}

#[cfg(unix)]
fn connect_unix_with_timeout(
    path: &Path,
    timeout: Duration,
    expected_server_uid: Option<u32>,
) -> Result<(std::os::unix::net::UnixStream, u32), TlsError> {
    // R5-KEYD-1 & R6-KEYD-1:
    // 1. Use non-blocking Tokio `UnixStream::connect` bounded by `deadline`, retrying
    //    `WouldBlock`/`Interrupted` (e.g. Linux full Unix listen backlog `EAGAIN`) with short
    //    backoff until `deadline` instead of failing immediately.
    // 2. When invoked from a `CurrentThread` Tokio runtime, run the bounded temporary runtime on
    //    a scoped OS thread (`std::thread::scope`) so it NEVER panics with "Cannot start a runtime
    //    from within a runtime" and NEVER leaks detached threads!
    let run_on_fresh_rt = || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|err| TlsError::KeyLoad(format!("failed building connect runtime: {err}")))?;
        rt.block_on(connect_unix_async(path, timeout, expected_server_uid))
    };

    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
            return handle.block_on(connect_unix_async(path, timeout, expected_server_uid));
        }
        return std::thread::scope(|scope| {
            scope.spawn(run_on_fresh_rt).join().unwrap_or_else(|_| {
                Err(TlsError::KeyLoad(
                    "keyd Unix connect helper thread panicked".to_owned(),
                ))
            })
        });
    }

    run_on_fresh_rt()
}

fn sync_authenticate<S: std::io::Read + std::io::Write>(
    stream: &mut S,
    secret: &Zeroizing<[u8; 32]>,
) -> Result<(), TlsError> {
    let mut nonce = [0_u8; 32];
    stream
        .read_exact(&mut nonce)
        .map_err(|err| TlsError::KeyLoad(format!("keyd auth challenge read failed: {err}")))?;
    let tag = compute_keyd_auth_tag(secret, &nonce);
    stream
        .write_all(&tag)
        .and_then(|()| stream.flush())
        .map_err(|err| TlsError::KeyLoad(format!("keyd auth response write failed: {err}")))
}

fn sync_framed_exchange<S: std::io::Read + std::io::Write>(
    stream: &mut S,
    req_len: u32,
    req_bytes: &[u8],
) -> Result<KeydResponse, TlsError> {
    stream
        .write_all(&req_len.to_be_bytes())
        .and_then(|()| stream.write_all(req_bytes))
        .and_then(|()| stream.flush())
        .map_err(|err| TlsError::KeyLoad(format!("keyd IPC write failed: {err}")))?;

    let mut len_buf = [0_u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|err| TlsError::KeyLoad(format!("keyd IPC read length failed: {err}")))?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len == 0 || resp_len > MAX_KEYD_RESPONSE_BYTES {
        return Err(TlsError::KeyLoad(format!(
            "keyd returned invalid frame length {resp_len}"
        )));
    }
    let mut buf = Vec::with_capacity(resp_len.min(4096));
    let n = stream
        .take(resp_len as u64)
        .read_to_end(&mut buf)
        .map_err(|err| TlsError::KeyLoad(format!("keyd IPC read payload failed: {err}")))?;
    if n != resp_len {
        return Err(TlsError::KeyLoad(
            "keyd IPC response truncated before frame length".to_owned(),
        ));
    }
    serde_json::from_slice(&buf)
        .map_err(|err| TlsError::KeyLoad(format!("keyd returned malformed JSON: {err}")))
}

/// Public certificate set loaded from `miraserve-keyd` with remote signing handles.
#[derive(Debug)]
pub struct RemoteKeyBundle {
    /// Hostname -> remote-signed [`CertifiedKey`] mappings.
    pub host_certs: Vec<(String, Arc<CertifiedKey>)>,
    /// Default fallback remote-signed [`CertifiedKey`].
    pub default_cert: Option<Arc<CertifiedKey>>,
}

/// Worker-side [`rustls::sign::SigningKey`] delegating all private-key operations to `miraserve-keyd`.
pub struct RemoteSigningKey {
    endpoint: KeydEndpoint,
    auth_secret: Option<Arc<Zeroizing<[u8; 32]>>>,
    pool: Arc<KeydConnPool>,
    expected_server_uid: Option<u32>,
    key_id: String,
    algorithm: SignatureAlgorithm,
    supported_schemes: Vec<SignatureScheme>,
}

impl std::fmt::Debug for RemoteSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteSigningKey")
            .field("endpoint", &self.endpoint)
            .field("key_id", &self.key_id)
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

impl SigningKey for RemoteSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let chosen = offered
            .iter()
            .copied()
            .find(|s| self.supported_schemes.contains(s))?;
        let client = KeydClient {
            endpoint: self.endpoint.clone(),
            auth_secret: self.auth_secret.clone(),
            pool: Arc::clone(&self.pool),
            io_timeout: CLIENT_IO_TIMEOUT,
            expected_server_uid: self.expected_server_uid,
        };
        Some(Box::new(RemoteSigner {
            client,
            key_id: self.key_id.clone(),
            scheme: chosen,
        }))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

#[derive(Debug)]
struct RemoteSigner {
    client: KeydClient,
    key_id: String,
    scheme: SignatureScheme,
}

impl Signer for RemoteSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.client
            .request_signature(&self.key_id, self.scheme, message)
            .map_err(|err| rustls::Error::General(format!("miraserve-keyd signing error: {err}")))
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    /// Codex Round-6 P1 #3 & Round-7 P2 #3: `verify_keyd_server_uid` accepts self/root/pinned
    /// UIDs, trusts packaged split-UID ancestry (`/run/miraserve-keyd` under non-shared root
    /// `/run`), and rejects any private directory placed beneath a shared or sticky ancestor
    /// (such as `/tmp/attacker-dir`).
    #[test]
    fn r6_keyd_server_uid_and_parent_dir_checks() -> Result<(), Box<dyn std::error::Error>> {
        // Independent of the caller's umask (Ubuntu's default `0002` makes fixtures `0775`).
        let _ = rustix::process::umask(rustix::fs::Mode::from_bits_truncate(0o022));
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let base = std::env::temp_dir().join(format!(
            "miraserve-r6-keyd-uid-{}-{nanos}",
            std::process::id()
        ));
        let shared = base.join("shared");
        let private_under_shared = shared.join("attacker-private");
        let private = base.join("private");
        std::fs::create_dir_all(&private_under_shared)?;
        std::fs::create_dir_all(&private)?;
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o1777))?;
        std::fs::set_permissions(
            &private_under_shared,
            std::fs::Permissions::from_mode(0o700),
        )?;
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o755))?;

        let my_uid = process_effective_uid();
        let unexpected_uid = my_uid.wrapping_add(12_345).max(1);
        let shared_sock = shared.join("keyd.sock");
        let private_sock = private.join("keyd.sock");

        // Own UID and root are accepted; explicit expected_server_uid rejects mismatches.
        assert!(verify_keyd_server_uid(&shared_sock, my_uid, None).is_ok());
        assert!(verify_keyd_server_uid(&shared_sock, 0, None).is_ok());
        assert!(verify_keyd_server_uid(&shared_sock, unexpected_uid, Some(unexpected_uid)).is_ok());
        assert!(verify_keyd_server_uid(&shared_sock, my_uid, Some(unexpected_uid)).is_err());

        // Unexpected non-root/non-self peer UID MUST be rejected on shared and private dirs.
        assert!(verify_keyd_server_uid(&shared_sock, unexpected_uid, None).is_err());
        assert!(verify_keyd_server_uid(&private_sock, unexpected_uid, None).is_err());

        // Codex Round-7 P2 #3: even a private 0700 directory below a shared sticky parent (1777)
        // MUST fail the trusted-ancestry check!
        let under_shared_sock = private_under_shared.join("keyd.sock");
        let (ancestors, parent) = inspect_keyd_socket_parent_chain(&under_shared_sock)
            .ok_or("expected chain metadata")?;
        assert!(
            !is_trusted_keyd_parent_chain(&ancestors, parent, my_uid, my_uid),
            "private 0700 directory under a sticky 1777 shared ancestor must NOT be trusted"
        );

        // Packaged split-UID layout: `/` (0755 root) -> `/run` (0755 root) ->
        // `/run/miraserve-keyd` (2750 uid 999), worker uid 998:
        assert!(
            is_trusted_keyd_parent_chain(&[(0, 0o755), (0, 0o755)], (999, 0o2750), 998, 999),
            "packaged /run/miraserve-keyd split-UID layout must accept keyd uid 999"
        );
        assert!(
            !is_trusted_keyd_parent_chain(&[(0, 0o755), (0, 0o755)], (999, 0o2750), 998, 1001),
            "packaged /run/miraserve-keyd must reject unrelated peer uid 1001"
        );
        assert!(
            !is_trusted_keyd_parent_chain(&[(0, 0o755), (0, 0o1777)], (1001, 0o700), 998, 1001),
            "private 0700 directory owned by uid 1001 under /tmp (1777) must be rejected"
        );
        assert!(
            !is_trusted_keyd_parent_chain(&[(0, 0o755), (1001, 0o755)], (1001, 0o700), 998, 1001),
            "private 0700 directory under another user's ancestor must be rejected"
        );

        // Trusted private parent is tightened from 0755 to 0700; symlinked parent is refused.
        ensure_keyd_socket_parent(&private)?;
        let mode = std::fs::symlink_metadata(&private)?.permissions().mode() & 0o7777;
        assert_eq!(mode, 0o700, "private keyd parent must be tightened to 0700");

        let link = base.join("link-parent");
        std::os::unix::fs::symlink(&shared, &link)?;
        assert!(
            ensure_keyd_socket_parent(&link).is_err(),
            "symlinked keyd socket parent must be refused"
        );

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }
}

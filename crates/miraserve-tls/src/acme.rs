//! Automatic ACME v2 certificate issuance (`tls-alpn-01` & `http-01`), short-lived
//! certificate profiles, atomic `0600` secret persistence, RAII challenge cleanup, and
//! RFC 9773 ACME Renewal Information (ARI) scheduling.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, CertificateIdentifier, ChallengeType,
    Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus, RenewalInfo, RetryPolicy,
};
use miraserve_config::{AcmeChallenge, AcmeConfig};
use rcgen::{CertificateParams, CustomExtension, KeyPair, PKCS_ECDSA_P256_SHA256, SanType};
use rustls::crypto::CryptoProvider;
use rustls::sign::CertifiedKey;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::TlsError;
use crate::cert::{certified_key_from_rcgen, load_certified_key_from_pem, read_bounded_file};
use crate::resolver::{AcmeChallengeStore, DynamicCertResolver};

/// RFC 8737 `id-pe-acmeIdentifier` OID (`1.3.6.1.5.5.7.1.31`).
const ID_PE_ACME_IDENTIFIER_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 31];

/// Maximum duration permitted for a single ACME HTTP API request (`R2-ACME-2`).
const ACME_OP_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum duration permitted for a single RFC 9773 ARI query (`R5-ACME-5`).
pub const ARI_QUERY_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum number of concurrent RFC 9773 ARI queries executed per supervisor pass (`R5-ACME-5`).
pub const MAX_CONCURRENT_ARI_QUERIES: usize = 8;

/// Maximum duration permitted for ACME challenge/certificate polling (`R2-ACME-2`).
const ACME_POLL_TIMEOUT: Duration = Duration::from_secs(120);

/// Minimum interval enforced between consecutive ACME certificate orders for the same domain
/// so a broken ARI response, fast host clock, or failed disk persist can NEVER burn CA duplicate-
/// certificate rate limits in a tight loop (`R4-ACME-1`).
const MIN_DOMAIN_ORDER_INTERVAL: Duration = Duration::from_hours(1);

/// Minimum ARI cooldown applied after a successful issuance (`max(Retry-After, 3h)`, `R4-ACME-1`).
const POST_ISSUE_ARI_COOLDOWN: Duration = Duration::from_hours(3);

/// Initial backoff applied per domain after a failed or timed-out ARI query (`R4-ACME-1`, `R5-ACME-5`).
const ARI_QUERY_ERROR_BACKOFF_INITIAL: Duration = Duration::from_mins(15);

/// Maximum exponential backoff applied per domain after consecutive ARI failures (`R5-ACME-5`).
const ARI_QUERY_ERROR_BACKOFF_MAX: Duration = Duration::from_hours(4);

/// RAII cleanup guard ensuring every active HTTP-01 and TLS-ALPN-01 challenge is removed
/// from [`AcmeChallengeStore`] even on early error, timeout, or task cancellation.
struct ActiveChallengeGuard {
    store: Arc<AcmeChallengeStore>,
    alpn_domains: Vec<String>,
    http_tokens: Vec<(String, String)>,
}

impl ActiveChallengeGuard {
    fn new(store: Arc<AcmeChallengeStore>) -> Self {
        Self {
            store,
            alpn_domains: Vec::new(),
            http_tokens: Vec::new(),
        }
    }

    fn push_alpn(&mut self, domain: String, cert: Arc<CertifiedKey>) {
        self.store.set_alpn_cert(&domain, cert);
        self.alpn_domains.push(domain);
    }

    fn push_http01(&mut self, domain: String, token: String, key_auth: String) {
        self.store.set_http01_token(&domain, &token, key_auth);
        self.http_tokens.push((domain, token));
    }

    fn clear_now(&mut self) {
        for d in self.alpn_domains.drain(..) {
            self.store.clear_alpn_cert(&d);
        }
        for (d, tok) in self.http_tokens.drain(..) {
            self.store.clear_http01_token(&d, &tok);
        }
    }
}

impl Drop for ActiveChallengeGuard {
    fn drop(&mut self) {
        self.clear_now();
    }
}

/// Builds an RFC 8737 self-signed `TLS-ALPN-01` challenge certificate containing the
/// critical `id-pe-acmeIdentifier` extension with the SHA-256 digest of the key authorization.
///
/// # Errors
/// Returns [`TlsError`] if the digest is not 32 bytes or certificate generation fails.
pub fn build_tls_alpn_01_cert(
    domain: &str,
    key_auth_digest: &[u8],
    provider: &CryptoProvider,
) -> Result<Arc<CertifiedKey>, TlsError> {
    if key_auth_digest.len() != 32 {
        return Err(TlsError::Acme(format!(
            "invalid TLS-ALPN-01 digest length: expected 32 bytes, got {}",
            key_auth_digest.len()
        )));
    }

    // DER OCTET STRING: tag 0x04, length 0x20 (32), followed by 32 digest bytes.
    let mut der_value = Vec::with_capacity(34);
    der_value.push(0x04);
    der_value.push(0x20);
    der_value.extend_from_slice(key_auth_digest);

    let mut ext = CustomExtension::from_oid_content(ID_PE_ACME_IDENTIFIER_OID, der_value);
    ext.set_criticality(true);

    let mut params = CertificateParams::default();
    let dns_name = domain
        .to_owned()
        .try_into()
        .map_err(|err| TlsError::Acme(format!("invalid ACME DNS identifier '{domain}': {err}")))?;
    params.subject_alt_names = vec![SanType::DnsName(dns_name)];
    params.custom_extensions = vec![ext];

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|err| TlsError::CertGeneration(err.to_string()))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|err| TlsError::CertGeneration(err.to_string()))?;

    let bundle = rcgen::CertifiedKey {
        cert,
        signing_key: key_pair,
    };
    certified_key_from_rcgen(&bundle, provider)
}

/// Computes the recommended delay until the next certificate renewal attempt using
/// RFC 9773 ACME Renewal Information (`suggestedWindow`), picking the window midpoint
/// clamped to at least 60 seconds (or immediate if already past window end).
#[must_use]
pub fn compute_ari_renewal_delay(info: &RenewalInfo, now: SystemTime) -> Duration {
    compute_window_midpoint_delay(
        info.suggested_window.start.unix_timestamp(),
        info.suggested_window.end.unix_timestamp(),
        now,
    )
}

fn compute_window_midpoint_delay(start: i64, end: i64, now: SystemTime) -> Duration {
    let now_unix = now
        .duration_since(UNIX_EPOCH)
        .map_or(0_i64, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));

    let target = if end > start {
        start.saturating_add((end.saturating_sub(start)) / 2)
    } else {
        start
    };

    if target <= now_unix {
        Duration::ZERO
    } else {
        let diff = u64::try_from(target.saturating_sub(now_unix)).unwrap_or(60);
        Duration::from_secs(diff.max(60))
    }
}

/// Scheduling outcome computed from an RFC 9773 ARI response (`R3-ACME-1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AriScheduleDecision {
    /// `true` when the ARI suggested window is already open (`ari_delay == 0`) so the domain
    /// MUST be renewed immediately rather than sleeping.
    pub renew_now: bool,
    /// Earliest delay before the ACME supervisor may query `renewal_info` again for this domain
    /// (`Retry-After` strictly honored as a poll floor, minimum 60 seconds).
    pub next_ari_poll_after: Duration,
    /// Delay until the next wake-up (`Duration::ZERO` if `renew_now`; otherwise the earlier of
    /// `ari_delay` and `next_ari_poll_after`, while `next_ari_poll_after` prevents calling ARI
    /// before `Retry-After` elapses).
    pub wake_delay: Duration,
}

/// Computes the ARI renewal and poll schedule, treating a zero ARI delay as immediately due
/// and honoring `Retry-After` strictly as a poll floor (`R3-ACME-1`).
#[must_use]
pub fn plan_ari_schedule(ari_delay: Duration, retry_after: Duration) -> AriScheduleDecision {
    let next_ari_poll_after = retry_after.max(Duration::from_secs(60));
    if ari_delay.is_zero() {
        AriScheduleDecision {
            renew_now: true,
            next_ari_poll_after,
            wake_delay: Duration::ZERO,
        }
    } else {
        AriScheduleDecision {
            renew_now: false,
            next_ari_poll_after,
            wake_delay: ari_delay.min(next_ari_poll_after),
        }
    }
}

/// Live in-memory metadata for an ACME certificate installed in [`DynamicCertResolver`]
/// (`R2-ACME-1`, `R4-ACME-1`), preventing disk persistence failures from causing stale ARI queries
/// or tight re-order loops.
#[derive(Debug, Clone)]
struct InMemoryCertState {
    not_before: i64,
    not_after: i64,
    ari_id: Option<CertificateIdentifier<'static>>,
}

/// Coordinates ACME v2 account management, challenge fulfillment, and certificate issuance.
#[derive(Debug)]
pub struct AcmeManager {
    config: AcmeConfig,
    state_dir: PathBuf,
    challenge_store: Arc<AcmeChallengeStore>,
    resolver: Arc<DynamicCertResolver>,
    provider: Arc<CryptoProvider>,
    /// Tracks validity & RFC 9773 ARI ID of live in-memory ACME certificates installed in
    /// `resolver` (`R2-ACME-1`, `R4-ACME-1`).
    in_memory_certs: Mutex<HashMap<String, InMemoryCertState>>,
    /// Per-domain minimum cooldown between ACME certificate orders (`R4-ACME-1`).
    min_order_interval: Duration,
    /// Optional custom root CA certificate PEM for private/local ACME CAs (e.g. step-ca or
    /// local protocol-capable test CAs; Codex Round-8).
    ca_root_pem: Option<PathBuf>,
}

impl AcmeManager {
    /// Creates a new [`AcmeManager`] storing account credentials and issued certificates
    /// under `state_dir`.
    #[must_use]
    pub fn new(
        config: AcmeConfig,
        state_dir: impl Into<PathBuf>,
        challenge_store: Arc<AcmeChallengeStore>,
        resolver: Arc<DynamicCertResolver>,
        provider: Arc<CryptoProvider>,
    ) -> Self {
        Self {
            config,
            state_dir: state_dir.into(),
            challenge_store,
            resolver,
            provider,
            in_memory_certs: Mutex::new(HashMap::new()),
            min_order_interval: MIN_DOMAIN_ORDER_INTERVAL,
            ca_root_pem: None,
        }
    }

    /// Overrides the per-domain minimum order cooldown (primarily for deterministic testing).
    #[must_use]
    pub const fn with_min_order_interval(mut self, interval: Duration) -> Self {
        self.min_order_interval = interval;
        self
    }

    /// Configures a custom PEM root CA certificate for verifying HTTPS connections to a private
    /// or local test ACME CA (`instant_acme::Account::builder_with_root`).
    #[must_use]
    pub fn with_ca_root_pem(mut self, pem_path: impl Into<PathBuf>) -> Self {
        self.ca_root_pem = Some(pem_path.into());
        self
    }

    fn account_builder(&self) -> Result<instant_acme::AccountBuilder, TlsError> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        match &self.ca_root_pem {
            Some(root_pem) => {
                Account::builder_with_root(root_pem).map_err(|err| TlsError::Acme(err.to_string()))
            }
            None => Account::builder().map_err(|err| TlsError::Acme(err.to_string())),
        }
    }

    /// Returns the normalized ACME directory URL used for deterministic cache scoping.
    #[must_use]
    pub fn normalized_directory_url(&self) -> String {
        let raw = self
            .config
            .directory
            .as_deref()
            .unwrap_or_else(|| LetsEncrypt::Production.url());
        normalize_acme_directory_url(raw)
    }

    /// Returns the deterministic directory-scoped ACME state directory (`R6-ACME-1`, `R7-ACME-1`).
    ///
    /// Keying `certs/` by the SHA-256 digest of the normalized `directory_url` ONLY ensures:
    /// - switching between Let's Encrypt staging, production, or a custom ACME CA ALWAYS uses
    ///   isolated certificates and never serves staging certs under production;
    /// - changing only the contact email does NOT orphan or force re-issuance of valid cached
    ///   certificates (account credentials are scoped separately via [`Self::account_path`]).
    #[must_use]
    pub fn scoped_state_dir(&self) -> PathBuf {
        let dir_url = self.normalized_directory_url();
        let full_hash = sha256_hex(dir_url.as_bytes());
        let short_hash = full_hash.get(..16).unwrap_or(&full_hash);
        self.state_dir.join(format!("dir-{short_hash}"))
    }

    /// Returns the legacy `3b27f1d` intermediate directory keyed by `(directory_url, email)`.
    fn legacy_email_scoped_state_dir(&self) -> PathBuf {
        let dir_url = self.normalized_directory_url();
        let email = self.config.email.trim().to_ascii_lowercase();
        let mut scope_input = String::with_capacity(dir_url.len() + email.len() + 1);
        scope_input.push_str(&dir_url);
        scope_input.push('\0');
        scope_input.push_str(&email);
        let full_hash = sha256_hex(scope_input.as_bytes());
        let short_hash = full_hash.get(..16).unwrap_or(&full_hash);
        self.state_dir.join(format!("dir-{short_hash}"))
    }

    /// Leaf filename for this email's ACME account credentials inside [`Self::scoped_state_dir`].
    fn account_filename(&self) -> String {
        let email = self.config.email.trim().to_ascii_lowercase();
        let full_hash = sha256_hex(email.as_bytes());
        let short_hash = full_hash.get(..16).unwrap_or(&full_hash);
        format!("account-{short_hash}.json")
    }

    /// Returns the email-scoped ACME account credentials path inside [`Self::scoped_state_dir`]
    /// (`R6-ACME-1`, `R7-ACME-1`).
    #[must_use]
    pub fn account_path(&self) -> PathBuf {
        self.scoped_state_dir().join(self.account_filename())
    }

    /// Returns the scoped `certs/` directory for the configured ACME directory (`R6-ACME-1`,
    /// `R7-ACME-1`).
    #[must_use]
    pub fn certs_dir(&self) -> PathBuf {
        self.scoped_state_dir().join("certs")
    }

    /// Adopts pre-upgrade on-disk ACME state into [`Self::scoped_state_dir`] when it matches
    /// the configured ACME directory (`R7-ACME-1`). Returns `true` only if `&self.state_dir`
    /// passed private-directory verification.
    ///
    /// Supports migrating both:
    /// 1. The intermediate `3b27f1d` `(directory, email)` scoped directory; and
    /// 2. The legacy `4bd1f41` flat layout (`<state_dir>/account.json` + `<state_dir>/certs/`),
    ///    verifying `account.json`'s `"directory"` (or `"id"` origin) matches this manager's
    ///    directory URL so staging credentials/certs are never adopted into production.
    fn adopt_legacy_state_if_matching(&self) -> bool {
        // Codex Round-6/7 P2: verify the state root (no symlinked leaf, trusted ancestors, 0700)
        // before any legacy migration or credential/certificate read.
        if let Err(err) = create_private_dir_all(&self.state_dir) {
            warn!(error = %err, "ACME state directory failed private-directory verification; skipping legacy state adoption");
            return false;
        }
        let scoped_dir = self.scoped_state_dir();
        let account_dst = self.account_path();
        let certs_dst = self.certs_dir();

        // 1. Migrate intermediate 3b27f1d `(directory, email)`-scoped directory if present.
        let v1_dir = self.legacy_email_scoped_state_dir();
        if v1_dir != scoped_dir && is_real_dir(&v1_dir) {
            let v1_account = v1_dir.join("account.json");
            let v1_certs = v1_dir.join("certs");
            if (is_real_file(&v1_account) || is_real_dir(&v1_certs))
                && create_private_dir_all(&scoped_dir).is_ok()
            {
                if is_real_file(&v1_account)
                    && !account_dst.exists()
                    && move_secret_file(&v1_account, &account_dst)
                {
                    info!(
                        from = %v1_account.display(),
                        to = %account_dst.display(),
                        "migrated ACME account credentials into email-scoped path (R7-ACME-1)"
                    );
                }
                if is_real_dir(&v1_certs) && migrate_certs_dir(&v1_certs, &certs_dst) {
                    info!(
                        from = %v1_certs.display(),
                        to = %certs_dst.display(),
                        "migrated ACME certificates into directory-scoped cache (R7-ACME-1)"
                    );
                }
                let _ = fs::remove_dir(&v1_dir);
            }
        }

        // 2. Migrate legacy 4bd1f41 flat layout (`<state_dir>/account.json`, `<state_dir>/certs/`).
        let legacy_account = self.state_dir.join("account.json");
        let legacy_certs = self.state_dir.join("certs");
        let has_legacy_account = is_real_file(&legacy_account);
        let has_legacy_certs = is_real_dir(&legacy_certs);
        if !has_legacy_account && !has_legacy_certs {
            return true;
        }

        let target_dir_url = self.normalized_directory_url();
        let matches_directory = if has_legacy_account {
            legacy_account_matches_directory(&legacy_account, &target_dir_url)
        } else {
            // Without `account.json` to prove the CA directory, only adopt flat `certs/` for
            // the default Let's Encrypt Production directory (the 4bd1f41 default).
            self.config.directory.is_none()
        };
        if !matches_directory {
            return true;
        }

        if create_private_dir_all(&scoped_dir).is_err() {
            return false;
        }
        if has_legacy_account
            && !account_dst.exists()
            && move_secret_file(&legacy_account, &account_dst)
        {
            info!(
                directory = %target_dir_url,
                "migrated legacy ACME account.json into directory-scoped state (R7-ACME-1)"
            );
        }
        if has_legacy_certs && migrate_certs_dir(&legacy_certs, &certs_dst) {
            info!(
                directory = %target_dir_url,
                "migrated legacy ACME certs/ directory into directory-scoped cache (R7-ACME-1)"
            );
        }
        true
    }

    /// Loads or registers the ACME v2 account persisted in [`Self::account_path`].
    ///
    /// # Errors
    /// Returns [`TlsError`] if account creation, directory discovery, or disk I/O fails.
    pub async fn load_or_create_account(&self) -> Result<Account, TlsError> {
        create_private_dir_all(&self.state_dir)?;
        let _ = self.adopt_legacy_state_if_matching();
        let scoped_dir = self.scoped_state_dir();
        let verified_scoped = create_and_open_private_dir(&scoped_dir)?;

        let cred_filename = self.account_filename();
        let cred_path = self.account_path();
        if let Some(raw_bytes) = verified_scoped.read_private_file(&cred_filename)? {
            let raw_bytes = Zeroizing::new(raw_bytes);
            let raw = Zeroizing::new(String::from_utf8(raw_bytes.to_vec()).map_err(|err| {
                TlsError::Acme(format!("cached ACME credentials not UTF-8: {err}"))
            })?);
            let creds: AccountCredentials = serde_json::from_str(&raw)
                .map_err(|err| TlsError::Acme(format!("invalid cached ACME credentials: {err}")))?;
            let account = tokio::time::timeout(
                ACME_OP_TIMEOUT,
                self.account_builder()?.from_credentials(creds),
            )
            .await
            .map_err(|_| TlsError::Acme("timed out loading ACME account credentials".to_owned()))?
            .map_err(|err| TlsError::Acme(err.to_string()))?;
            return Ok(account);
        }

        let directory_url = self
            .config
            .directory
            .as_deref()
            .unwrap_or_else(|| LetsEncrypt::Production.url());
        let contact_uri = format!("mailto:{}", self.config.email);
        let contacts = [contact_uri.as_str()];

        let (account, credentials) = tokio::time::timeout(
            ACME_OP_TIMEOUT,
            self.account_builder()?.create(
                &NewAccount {
                    contact: &contacts,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                directory_url.to_owned(),
                None,
            ),
        )
        .await
        .map_err(|_| TlsError::Acme("timed out creating ACME v2 account".to_owned()))?
        .map_err(|err| TlsError::Acme(err.to_string()))?;

        let serialized =
            Zeroizing::new(serde_json::to_string_pretty(&credentials).map_err(|err| {
                TlsError::Acme(format!("failed to serialize ACME credentials: {err}"))
            })?);
        write_secret_file(&cred_path, serialized.as_bytes())?;
        info!(directory = directory_url, "created new ACME v2 account");
        Ok(account)
    }

    /// Requests and installs an ACME certificate for `domain` using the configured challenge.
    ///
    /// # Errors
    /// Returns [`TlsError`] if ACME authorization, finalization, or persistence fails.
    #[allow(clippy::too_many_lines)]
    pub async fn obtain_certificate(
        &self,
        account: &Account,
        domain: &str,
    ) -> Result<Arc<CertifiedKey>, TlsError> {
        let identifiers = [Identifier::Dns(domain.to_owned())];
        let mut new_order = NewOrder::new(&identifiers);

        if self.config.short_lived {
            if account.profiles().any(|p| p.name == "shortlived") {
                new_order = new_order.profile("shortlived");
            } else {
                warn!(
                    domain,
                    "ACME CA does not advertise a 'shortlived' profile; falling back to default certificate lifetime (R2-ACME-5)"
                );
            }
        }

        let mut order = tokio::time::timeout(ACME_OP_TIMEOUT, account.new_order(&new_order))
            .await
            .map_err(|_| TlsError::Acme(format!("ACME new_order timed out for '{domain}'")))?
            .map_err(|err| {
                TlsError::Acme(format!("ACME new_order failed for '{domain}': {err}"))
            })?;

        let desired_challenge = match self.config.challenge {
            AcmeChallenge::TlsAlpn01 => ChallengeType::TlsAlpn01,
            AcmeChallenge::Http01 => ChallengeType::Http01,
            AcmeChallenge::Dns01 => {
                return Err(TlsError::Acme(
                    "DNS-01 ACME provider hooks are not yet configured; use tls-alpn-01 or http-01"
                        .to_owned(),
                ));
            }
        };

        let mut challenge_guard = ActiveChallengeGuard::new(Arc::clone(&self.challenge_store));

        {
            let mut authorizations = order.authorizations();
            while let Some(authz_res) = tokio::time::timeout(ACME_OP_TIMEOUT, authorizations.next())
                .await
                .map_err(|_| {
                    TlsError::Acme(format!("ACME authorization fetch timed out for '{domain}'"))
                })?
            {
                let mut authz =
                    authz_res.map_err(|err| TlsError::Acme(format!("ACME authz error: {err}")))?;
                if matches!(authz.status, AuthorizationStatus::Valid) {
                    continue;
                }

                let mut challenge = authz.challenge(desired_challenge.clone()).ok_or_else(|| {
                    TlsError::Acme(format!(
                        "ACME server did not offer configured challenge {desired_challenge:?} for '{domain}'"
                    ))
                })?;

                match desired_challenge {
                    ChallengeType::TlsAlpn01 => {
                        let digest = challenge.key_authorization().digest();
                        let cert = build_tls_alpn_01_cert(domain, digest.as_ref(), &self.provider)?;
                        challenge_guard.push_alpn(domain.to_owned(), cert);
                    }
                    ChallengeType::Http01 => {
                        let token = challenge.token.clone();
                        let key_auth = challenge.key_authorization().as_str().to_owned();
                        challenge_guard.push_http01(domain.to_owned(), token, key_auth);
                    }
                    _ => {}
                }

                tokio::time::timeout(ACME_OP_TIMEOUT, challenge.set_ready())
                    .await
                    .map_err(|_| {
                        TlsError::Acme(format!("ACME challenge set_ready timed out for '{domain}'"))
                    })?
                    .map_err(|err| {
                        TlsError::Acme(format!("ACME challenge set_ready failed: {err}"))
                    })?;
            }
        }

        let status =
            tokio::time::timeout(ACME_POLL_TIMEOUT, order.poll_ready(&RetryPolicy::default()))
                .await
                .map_err(|_| {
                    TlsError::Acme(format!("ACME order poll_ready timed out for '{domain}'"))
                })
                .and_then(|res| {
                    res.map_err(|err| {
                        TlsError::Acme(format!("ACME order poll_ready failed: {err}"))
                    })
                });

        challenge_guard.clear_now();

        let status = status?;
        if status != OrderStatus::Ready {
            return Err(TlsError::Acme(format!(
                "ACME order for '{domain}' did not reach Ready state (got {status:?})"
            )));
        }

        let private_key_pem = Zeroizing::new(
            tokio::time::timeout(ACME_OP_TIMEOUT, order.finalize())
                .await
                .map_err(|_| TlsError::Acme(format!("ACME finalize timed out for '{domain}'")))?
                .map_err(|err| TlsError::Acme(format!("ACME finalize failed: {err}")))?,
        );
        let cert_chain_pem = tokio::time::timeout(
            ACME_POLL_TIMEOUT,
            order.poll_certificate(&RetryPolicy::default()),
        )
        .await
        .map_err(|_| TlsError::Acme(format!("ACME poll_certificate timed out for '{domain}'")))?
        .map_err(|err| TlsError::Acme(format!("ACME poll_certificate failed: {err}")))?;

        let certified = load_certified_key_from_pem(
            cert_chain_pem.as_bytes(),
            private_key_pem.as_bytes(),
            &self.provider,
        )?;

        // R2-ACME-1: Install the issued certificate live FIRST so a transient disk/sandbox
        // persistence failure never discards a valid certificate and burns CA rate limits!
        self.resolver
            .upsert_acme_host(domain, Arc::clone(&certified));
        self.record_in_memory_cert_pem(domain, cert_chain_pem.as_bytes());
        if let Err(err) = self.persist_certificate(domain, &cert_chain_pem, &private_key_pem) {
            warn!(
                domain,
                error = %err,
                "ACME certificate installed live in memory, but persisting to disk failed"
            );
        } else {
            info!(domain, "installed and persisted ACME certificate");
        }
        Ok(certified)
    }

    /// Installs a PEM-encoded certificate chain and private key into the live resolver, records
    /// its in-memory validity & ARI certificate ID (`R2-ACME-1`, `R4-ACME-1`), and atomically
    /// persists both files to disk (`R3-ACME-2`).
    ///
    /// # Errors
    /// Returns [`TlsError`] if the PEM pair is invalid or disk persistence fails (note: the
    /// certificate remains installed in memory even if disk persistence returns an error).
    pub fn install_and_persist_certificate_pem(
        &self,
        domain: &str,
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<Arc<CertifiedKey>, TlsError> {
        let certified =
            load_certified_key_from_pem(cert_pem.as_bytes(), key_pem.as_bytes(), &self.provider)?;
        self.resolver
            .upsert_acme_host(domain, Arc::clone(&certified));
        self.record_in_memory_cert_pem(domain, cert_pem.as_bytes());
        self.persist_certificate(domain, cert_pem, key_pem)?;
        Ok(certified)
    }

    fn record_in_memory_cert_pem(&self, domain: &str, pem_bytes: &[u8]) {
        if let Some((not_before, not_after)) = parse_cert_validity_unix(pem_bytes) {
            let ari_id = parse_cert_ari_id(pem_bytes);
            let mut map = match self.in_memory_certs.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            map.insert(
                domain.to_ascii_lowercase(),
                InMemoryCertState {
                    not_before,
                    not_after,
                    ari_id,
                },
            );
        }
    }

    fn in_memory_validity(&self, domain: &str) -> Option<(i64, i64)> {
        let map = match self.in_memory_certs.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        map.get(&domain.to_ascii_lowercase())
            .map(|s| (s.not_before, s.not_after))
    }

    fn in_memory_ari_id(&self, domain: &str) -> Option<CertificateIdentifier<'static>> {
        let map = match self.in_memory_certs.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        map.get(&domain.to_ascii_lowercase())
            .and_then(|s| s.ari_id.clone())
    }

    fn persist_certificate(
        &self,
        domain: &str,
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<(), TlsError> {
        let certs_dir = self.certs_dir();
        create_private_dir_all(&certs_dir)?;

        let safe_name = sanitize_domain_filename(domain);
        let bundle_path = certs_dir.join(format!("{safe_name}.bundle.pem"));

        // R5-ACME-3: Persist BOTH private key and certificate chain inside ONE `0600` combined
        // bundle via a single atomic temp+fsync+rename syscall so a crash at ANY instruction can
        // never leave a mismatched key/cert pair or orphaned backup!
        let mut combined =
            Zeroizing::new(String::with_capacity(key_pem.len() + cert_pem.len() + 2));
        combined.push_str(key_pem);
        if !combined.ends_with('\n') {
            combined.push('\n');
        }
        combined.push_str(cert_pem);
        let tmp_bundle = write_temp_file(&bundle_path, combined.as_bytes(), true)?;
        if let Err(source) = fs::rename(&tmp_bundle, &bundle_path) {
            let _ = fs::remove_file(&tmp_bundle);
            return Err(TlsError::Io {
                path: bundle_path,
                source,
            });
        }
        // Best-effort directory fsync so the atomic rename survives power loss.
        if let Ok(dir) = fs::File::open(&certs_dir) {
            let _ = dir.sync_all();
        }

        // R5-ACME-3 residual: Once the crash-atomic `.bundle.pem` succeeds, keep the legacy
        // `.key`/`.crt` operator inspection copies updated on a best-effort basis; a failure
        // there logs a warning instead of falsely failing persistence!
        if let Err(err) = persist_legacy_cert_pair(&certs_dir, &safe_name, cert_pem, key_pem) {
            warn!(
                domain,
                error = %err,
                "atomic ACME .bundle.pem saved, but updating legacy .crt/.key inspection copies failed"
            );
        }
        Ok(())
    }

    fn load_disk_cert_bundle_or_pair(&self, domain: &str) -> Option<(Arc<CertifiedKey>, Vec<u8>)> {
        // Codex Round-7 P2 #2: require successful state-directory verification before reading any
        // cached ACME bundle/cert/key, and read entries relative to the verified certs directory
        // without following symlinks (leaving manual-TLS pathname loading untouched).
        match open_existing_private_dir(&self.state_dir) {
            Ok(Some(_)) => {}
            Ok(None) => return None,
            Err(err) => {
                warn!(
                    domain,
                    error = %err,
                    "refusing to read ACME certificate cache from an unverified state directory"
                );
                return None;
            }
        }
        if !self.adopt_legacy_state_if_matching() {
            return None;
        }
        let certs_handle = match open_existing_private_dir(&self.certs_dir()) {
            Ok(Some(handle)) => handle,
            Ok(None) => return None,
            Err(err) => {
                warn!(
                    domain,
                    error = %err,
                    "refusing to read ACME certificate cache from an unverified certs directory"
                );
                return None;
            }
        };

        let safe = sanitize_domain_filename(domain);
        let bundle_name = format!("{safe}.bundle.pem");
        match certs_handle.read_private_file(&bundle_name) {
            Ok(Some(raw)) => {
                if let Ok(cert) = load_certified_key_from_pem(&raw, &raw, &self.provider) {
                    return Some((cert, raw));
                }
            }
            Ok(None) => {}
            Err(err) => {
                warn!(
                    domain,
                    file = %bundle_name,
                    error = %err,
                    "refusing unsafe cached ACME bundle entry"
                );
                return None;
            }
        }

        let cert_name = format!("{safe}.crt");
        let key_name = format!("{safe}.key");
        let cert_raw = match certs_handle.read_private_file(&cert_name) {
            Ok(Some(raw)) => raw,
            Ok(None) => return None,
            Err(err) => {
                warn!(
                    domain,
                    file = %cert_name,
                    error = %err,
                    "refusing unsafe cached ACME certificate entry"
                );
                return None;
            }
        };
        let key_raw = match certs_handle.read_private_file(&key_name) {
            Ok(Some(raw)) => Zeroizing::new(raw),
            Ok(None) => return None,
            Err(err) => {
                warn!(
                    domain,
                    file = %key_name,
                    error = %err,
                    "refusing unsafe cached ACME private key entry"
                );
                return None;
            }
        };
        if let Ok(cert) = load_certified_key_from_pem(&cert_raw, &key_raw, &self.provider) {
            return Some((cert, cert_raw));
        }
        None
    }

    fn disk_cert_validity(&self, domain: &str) -> Option<(i64, i64)> {
        let (_, raw) = self.load_disk_cert_bundle_or_pair(domain)?;
        parse_cert_validity_unix(&raw)
    }

    /// Single unified validity source for BOTH `needs_renewal` and `next_renewal_delay_for`
    /// (`R5-ACME-1`, `R5-ACME-2`): returns the fresher (`later not_after`) validity between the
    /// live in-memory certificate and the valid on-disk bundle/pair, so a disk persistence failure
    /// never triggers duplicate CA orders AND a fresher on-disk cert never causes a spin loop!
    fn effective_cert_validity(&self, domain: &str) -> Option<(i64, i64)> {
        let mem = self.in_memory_validity(domain);
        let disk = self.disk_cert_validity(domain);
        match (mem, disk) {
            (Some(m), Some(d)) => {
                if m.1 >= d.1 {
                    Some(m)
                } else {
                    Some(d)
                }
            }
            (Some(m), None) => Some(m),
            (None, Some(d)) => Some(d),
            (None, None) => None,
        }
    }

    /// Loads any previously persisted ACME certificates from `state_dir/certs` into the resolver,
    /// preferring the crash-atomic `.bundle.pem` (`R5-ACME-3`) and falling back to `.crt`/`.key`.
    pub fn load_cached_certificates(&self, domains: &[String]) {
        if let Err(err) = create_private_dir_all(&self.state_dir) {
            warn!(error = %err, "refusing to load cached ACME certificates from an unverified state directory");
            return;
        }
        if !self.adopt_legacy_state_if_matching() {
            return;
        }
        for domain in domains {
            if let Some((cert, raw)) = self.load_disk_cert_bundle_or_pair(domain) {
                self.record_in_memory_cert_pem(domain, &raw);
                self.resolver.upsert_acme_host(domain, cert);
                info!(domain, "loaded cached ACME certificate from disk");
            } else {
                let certs_dir = self.certs_dir();
                let safe = sanitize_domain_filename(domain);
                if fs::symlink_metadata(certs_dir.join(format!("{safe}.bundle.pem"))).is_ok()
                    || fs::symlink_metadata(certs_dir.join(format!("{safe}.crt"))).is_ok()
                {
                    warn!(domain, "ignoring invalid cached ACME certificate");
                }
            }
        }
    }

    fn validity_needs_renewal(&self, not_before: i64, not_after: i64) -> bool {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0_i64, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
        if not_after <= now_unix {
            return true;
        }
        let total_lifetime = not_after.saturating_sub(not_before).max(1);
        let remaining = not_after.saturating_sub(now_unix);
        let renew_threshold = (total_lifetime / 3).max(if self.config.short_lived {
            24 * 3600
        } else {
            72 * 3600
        });
        remaining <= renew_threshold
    }

    /// Returns `true` if `domain` has no valid certificate+key pair (neither in memory nor on
    /// disk) OR the fresher certificate's remaining lifetime is below 1/3 of validity
    /// (`R5-ACME-1`, `R5-ACME-2`).
    #[must_use]
    pub fn needs_renewal(&self, domain: &str) -> bool {
        if let Some((not_before, not_after)) = self.effective_cert_validity(domain) {
            return self.validity_needs_renewal(not_before, not_after);
        }
        true
    }

    /// Extracts the RFC 9773 `CertificateIdentifier` (`AKI.serial`) from whichever valid
    /// certificate (in-memory or on-disk bundle/pair) is fresher (`R4-ACME-1`, `R5-ACME-1`).
    #[must_use]
    pub fn cached_cert_ari_id(&self, domain: &str) -> Option<CertificateIdentifier<'static>> {
        let mem_val = self.in_memory_validity(domain);
        let disk_pair = self.load_disk_cert_bundle_or_pair(domain);
        let disk_val = disk_pair
            .as_ref()
            .and_then(|(_, raw)| parse_cert_validity_unix(raw));

        let prefer_mem = match (mem_val, disk_val) {
            (Some(m), Some(d)) => m.1 >= d.1,
            (Some(_), None) => true,
            (None, _) => false,
        };
        if prefer_mem && let Some(id) = self.in_memory_ari_id(domain) {
            return Some(id);
        }
        if let Some((_, raw)) = disk_pair
            && let Some(id) = parse_cert_ari_id(&raw)
        {
            return Some(id);
        }
        self.in_memory_ari_id(domain)
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_ari_queries_bounded(
        &self,
        acc: &Account,
        ari_targets: Vec<(String, String, CertificateIdentifier<'static>)>,
        ari_next_poll: &mut HashMap<String, Instant>,
        ari_error_streak: &mut HashMap<String, u32>,
        ari_renew_at: &mut HashMap<String, Instant>,
        ari_due: &mut HashSet<String>,
        last_retry_after: &mut HashMap<String, Duration>,
        last_order_at: &HashMap<String, Instant>,
        soonest: &mut Option<Duration>,
        newly_due_ready: &mut bool,
    ) -> HashSet<String> {
        let mut ari_handled: HashSet<String> = HashSet::new();
        let acc_ref = acc.clone();
        let results = run_bounded_ari_queries(
            ari_targets,
            MAX_CONCURRENT_ARI_QUERIES,
            ARI_QUERY_TIMEOUT,
            move |(_domain, _key, cert_id)| {
                let acc_c = acc_ref.clone();
                async move { acc_c.renewal_info(&cert_id).await }
            },
        )
        .await;

        for ((domain, key, _cid), outcome) in results {
            let poll_now = Instant::now();
            let order_cooldown_remaining = last_order_at
                .get(&key)
                .and_then(|&t| {
                    self.min_order_interval
                        .checked_sub(poll_now.saturating_duration_since(t))
                })
                .filter(|d| !d.is_zero());

            match outcome {
                Ok(Ok((ari_info, retry_after))) => {
                    ari_error_streak.remove(&key);
                    let ari_delay = compute_ari_renewal_delay(&ari_info, SystemTime::now());
                    let plan = plan_ari_schedule(ari_delay, retry_after);
                    last_retry_after.insert(key.clone(), plan.next_ari_poll_after);
                    ari_next_poll.insert(key.clone(), poll_now + plan.next_ari_poll_after);
                    ari_handled.insert(key.clone());
                    if plan.renew_now {
                        if let Some(rem) = order_cooldown_remaining {
                            *soonest = Some(soonest.map_or(rem, |p| p.min(rem)));
                        } else {
                            ari_due.insert(key);
                            *newly_due_ready = true;
                        }
                    } else {
                        ari_renew_at.insert(key, poll_now + ari_delay);
                        *soonest =
                            Some(soonest.map_or(plan.wake_delay, |p| p.min(plan.wake_delay)));
                    }
                }
                Ok(Err(err)) => {
                    let backoff = next_ari_error_backoff(ari_error_streak, &key);
                    warn!(domain = %domain, error = %err, backoff_secs = backoff.as_secs(), "ACME ARI query failed; backing off");
                    ari_next_poll.insert(key, poll_now + backoff);
                }
                Err(()) => {
                    let backoff = next_ari_error_backoff(ari_error_streak, &key);
                    warn!(domain = %domain, backoff_secs = backoff.as_secs(), "ACME ARI query timed out; backing off");
                    ari_next_poll.insert(key, poll_now + backoff);
                }
            }
        }
        ari_handled
    }

    /// Computes the next renewal wake-up schedule across all eligible domains, running live
    /// RFC 9773 ARI queries concurrently (capped at `MAX_CONCURRENT_ARI_QUERIES`, 10s timeout,
    /// exponential error backoff, `R5-ACME-5`) and using [`Self::effective_cert_validity`] so
    /// renewal checks and delay calculations never disagree (`R5-ACME-1`, `R5-ACME-2`).
    #[allow(clippy::too_many_arguments)]
    async fn schedule_next_delays(
        &self,
        eligible: &[String],
        account: Option<&Account>,
        ari_next_poll: &mut HashMap<String, Instant>,
        ari_error_streak: &mut HashMap<String, u32>,
        ari_renew_at: &mut HashMap<String, Instant>,
        ari_due: &mut HashSet<String>,
        last_retry_after: &mut HashMap<String, Duration>,
        last_order_at: &HashMap<String, Instant>,
    ) -> (Option<Duration>, bool) {
        let now_inst = Instant::now();
        let mut soonest: Option<Duration> = None;
        let mut newly_due_ready = false;

        // Collect domains that need a live ARI network query this pass.
        let mut ari_targets: Vec<(String, String, CertificateIdentifier<'static>)> = Vec::new();
        for domain in eligible {
            let key = domain.to_ascii_lowercase();
            let order_cooldown_remaining = last_order_at
                .get(&key)
                .and_then(|&t| {
                    self.min_order_interval
                        .checked_sub(now_inst.saturating_duration_since(t))
                })
                .filter(|d| !d.is_zero());

            if let Some(&target) = ari_renew_at.get(&key)
                && now_inst >= target
            {
                if let Some(rem) = order_cooldown_remaining {
                    soonest = Some(soonest.map_or(rem, |p| p.min(rem)));
                } else {
                    ari_due.insert(key);
                    newly_due_ready = true;
                }
                continue;
            }

            let can_poll_ari = ari_next_poll
                .get(&key)
                .is_none_or(|&earliest| now_inst >= earliest);
            if self.config.ari
                && can_poll_ari
                && account.is_some()
                && let Some(cert_id) = self.cached_cert_ari_id(domain)
            {
                ari_targets.push((domain.clone(), key, cert_id));
            }
        }

        // Execute live ARI queries concurrently with bounded parallelism & short timeout (R5-ACME-5).
        let ari_handled = if let Some(acc) = account
            && !ari_targets.is_empty()
        {
            self.run_ari_queries_bounded(
                acc,
                ari_targets,
                ari_next_poll,
                ari_error_streak,
                ari_renew_at,
                ari_due,
                last_retry_after,
                last_order_at,
                &mut soonest,
                &mut newly_due_ready,
            )
            .await
        } else {
            HashSet::new()
        };

        // Compute non-ARI / fallback certificate-validity wake-up delays for remaining domains.
        let end_now = Instant::now();
        for domain in eligible {
            let key = domain.to_ascii_lowercase();
            if ari_handled.contains(&key) {
                continue;
            }
            if let Some(&target) = ari_renew_at.get(&key) {
                let to_renew = target.saturating_duration_since(end_now);
                let to_poll = ari_next_poll
                    .get(&key)
                    .map_or(to_renew, |&p| p.saturating_duration_since(end_now));
                let wait = to_renew.min(to_poll);
                soonest = Some(soonest.map_or(wait, |p| p.min(wait)));
                continue;
            }

            let Some((not_before, not_after)) = self.effective_cert_validity(domain) else {
                continue;
            };
            let lifetime = not_after.saturating_sub(not_before);
            let win_start = not_before.saturating_add(lifetime.saturating_mul(2) / 3);
            let delay = compute_window_midpoint_delay(win_start, not_after, SystemTime::now());
            if delay.is_zero() {
                if let Some(rem) = last_order_at.get(&key).and_then(|&t| {
                    self.min_order_interval
                        .checked_sub(end_now.saturating_duration_since(t))
                }) && !rem.is_zero()
                {
                    soonest = Some(soonest.map_or(rem, |p| p.min(rem)));
                } else if self.needs_renewal(domain) {
                    // Only trigger immediate loop if `needs_renewal` ALSO agrees (R5-ACME-2)!
                    newly_due_ready = true;
                }
            } else {
                soonest = Some(soonest.map_or(delay, |p| p.min(delay)));
            }
        }

        (soonest, newly_due_ready)
    }

    /// Background ACME v2 issuance & RFC 9773 ARI renewal supervisor loop (`ACME-1`) for a
    /// static domain list (for dynamic hot-reload domain discovery, use
    /// [`Self::run_renewal_loop_with_domains_and_notify`]).
    pub async fn run_renewal_loop(
        self: Arc<Self>,
        domains: Vec<String>,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        self.run_renewal_loop_with_domains(move || domains.clone(), shutdown)
            .await;
    }

    /// Background ACME v2 issuance & renewal supervisor loop that re-reads eligible DNS domains
    /// from `domains_fn` on EVERY iteration so hot-reloaded sites automatically receive
    /// certificates and removed sites stop renewing (`R2-ACME-4`).
    pub async fn run_renewal_loop_with_domains<F>(
        self: Arc<Self>,
        domains_fn: F,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) where
        F: Fn() -> Vec<String> + Send + Sync + 'static,
    {
        self.run_renewal_loop_with_domains_and_notify(
            domains_fn,
            Arc::new(tokio::sync::Notify::new()),
            shutdown,
        )
        .await;
    }

    /// Background ACME v2 issuance & renewal supervisor loop with an explicit `reload_notify`
    /// signal woken immediately on hot reload (`R2-ACME-4`), full RFC 9773 ARI triggering
    /// (`R3-ACME-1`), per-domain order cooldown + post-issuance ARI cooldown (`R4-ACME-1`), and
    /// restart-resilient ARI account initialization.
    pub async fn run_renewal_loop_with_domains_and_notify<F>(
        self: Arc<Self>,
        domains_fn: F,
        reload_notify: Arc<tokio::sync::Notify>,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) where
        F: Fn() -> Vec<String> + Send + Sync + 'static,
    {
        self.run_renewal_loop_with_reload_check(domains_fn, || false, reload_notify, shutdown)
            .await;
    }

    /// Background ACME v2 issuance & renewal supervisor loop that ALSO exits cleanly whenever
    /// `config_changed_fn()` returns `true` so callers can rebuild [`AcmeManager`] immediately
    /// when `server.tls.acme` settings (directory, email, short-lived, ARI) change on reload
    /// (`R5-ACME-4`).
    #[allow(clippy::too_many_lines)]
    pub async fn run_renewal_loop_with_reload_check<F, C>(
        self: Arc<Self>,
        domains_fn: F,
        config_changed_fn: C,
        reload_notify: Arc<tokio::sync::Notify>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) where
        F: Fn() -> Vec<String> + Send + Sync + 'static,
        C: Fn() -> bool + Send + Sync + 'static,
    {
        let mut account: Option<Account> = None;
        let mut backoff_secs = 60_u64;
        let mut ari_due: HashSet<String> = HashSet::new();
        let mut ari_next_poll: HashMap<String, Instant> = HashMap::new();
        let mut ari_error_streak: HashMap<String, u32> = HashMap::new();
        let mut ari_renew_at: HashMap<String, Instant> = HashMap::new();
        let mut last_retry_after: HashMap<String, Duration> = HashMap::new();
        let mut last_order_at: HashMap<String, Instant> = HashMap::new();
        let mut consecutive_no_order_continues = 0_u32;
        let base_poll = if self.config.short_lived {
            Duration::from_hours(1)
        } else {
            Duration::from_hours(6)
        };

        loop {
            if *shutdown.borrow() || config_changed_fn() {
                break;
            }
            let raw_domains = domains_fn();
            let mut eligible = Vec::new();
            for d in raw_domains {
                if d.starts_with("*.") {
                    warn!(
                        domain = %d,
                        "skipping wildcard host in ACME supervisor (HTTP-01 / TLS-ALPN-01 cannot issue wildcards; R2-ACME-5)"
                    );
                    continue;
                }
                if d.eq_ignore_ascii_case("localhost") {
                    continue;
                }
                if !eligible
                    .iter()
                    .any(|existing: &String| existing.eq_ignore_ascii_case(&d))
                {
                    eligible.push(d);
                }
            }

            let now_inst = Instant::now();
            let due: Vec<&String> = eligible
                .iter()
                .filter(|d| {
                    let key = d.to_ascii_lowercase();
                    // R4-ACME-1: Never re-order the same domain within `min_order_interval`.
                    if last_order_at.get(&key).is_some_and(|&t| {
                        now_inst.saturating_duration_since(t) < self.min_order_interval
                    }) {
                        return false;
                    }
                    self.needs_renewal(d)
                        || ari_due.contains(&key)
                        || ari_renew_at.get(&key).is_some_and(|&t| now_inst >= t)
                })
                .collect();

            let mut any_error = false;
            let mut ordered_any = false;
            let need_account = !due.is_empty() || (self.config.ari && !eligible.is_empty());
            if need_account && account.is_none() {
                let init_res = tokio::select! {
                    biased;
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                        continue;
                    }
                    res = self.load_or_create_account() => res,
                };
                match init_res {
                    Ok(acc) => account = Some(acc),
                    Err(err) => {
                        warn!(error = %err, "ACME account initialization failed; will retry");
                        if !due.is_empty() {
                            any_error = true;
                        }
                    }
                }
            }

            if !due.is_empty()
                && let Some(acc) = &account
            {
                let mut shutting_down = false;
                for domain in due {
                    let obtain_res = tokio::select! {
                        biased;
                        changed = shutdown.changed() => {
                            if changed.is_err() || *shutdown.borrow() {
                                shutting_down = true;
                                break;
                            }
                            continue;
                        }
                        res = self.obtain_certificate(acc, domain) => res,
                    };
                    match obtain_res {
                        Ok(_) => {
                            ordered_any = true;
                            let key = domain.to_ascii_lowercase();
                            let issued_now = Instant::now();
                            // R4-ACME-1: Record order timestamp and enforce a post-issuance ARI
                            // cooldown of `max(Retry-After, 3h)` instead of clearing `ari_next_poll`
                            // so a failed disk persist or sticky ARI window can NEVER spin orders!
                            last_order_at.insert(key.clone(), issued_now);
                            let cooldown = last_retry_after
                                .get(&key)
                                .copied()
                                .unwrap_or(Duration::ZERO)
                                .max(POST_ISSUE_ARI_COOLDOWN);
                            ari_next_poll.insert(key.clone(), issued_now + cooldown);
                            ari_due.remove(&key);
                            ari_renew_at.remove(&key);
                            info!(
                                domain = %domain,
                                ari = self.config.ari,
                                short_lived = self.config.short_lived,
                                "ACME certificate issued/renewed and installed live"
                            );
                        }
                        Err(err) => {
                            warn!(
                                domain = %domain,
                                error = %err,
                                "ACME certificate issuance failed; will retry with backoff"
                            );
                            any_error = true;
                        }
                    }
                }
                if shutting_down {
                    break;
                }
            }

            if ordered_any {
                consecutive_no_order_continues = 0;
            }

            let sleep_dur = if any_error {
                let d = Duration::from_secs(backoff_secs);
                backoff_secs = backoff_secs.saturating_mul(2).min(3_600);
                consecutive_no_order_continues = 0;
                d
            } else {
                backoff_secs = 60;
                let (soonest, newly_due_ready) = self
                    .schedule_next_delays(
                        &eligible,
                        account.as_ref(),
                        &mut ari_next_poll,
                        &mut ari_error_streak,
                        &mut ari_renew_at,
                        &mut ari_due,
                        &mut last_retry_after,
                        &last_order_at,
                    )
                    .await;
                // R5-ACME-2: Never busy-loop if no domain was ordered on the previous
                // immediate pass; enforce a hard ceiling of 1 immediate re-entry before sleeping.
                if newly_due_ready && consecutive_no_order_continues == 0 {
                    consecutive_no_order_continues += 1;
                    continue;
                }
                consecutive_no_order_continues = 0;
                match soonest {
                    Some(d) => d.clamp(Duration::from_secs(60), base_poll),
                    None => base_poll,
                }
            };

            tokio::select! {
                () = tokio::time::sleep(sleep_dur) => {}
                () = reload_notify.notified() => {
                    info!("ACME supervisor woken by configuration reload");
                    if config_changed_fn() {
                        break;
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    }
}

fn normalize_acme_directory_url(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    if let Some((scheme, rest)) = trimmed.split_once("://") {
        let (authority, path) = match rest.find('/') {
            Some(idx) => rest.split_at(idx),
            None => (rest, ""),
        };
        format!(
            "{}://{}{path}",
            scheme.to_ascii_lowercase(),
            authority.to_ascii_lowercase()
        )
    } else {
        trimmed.to_owned()
    }
}

fn extract_url_origin(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let (scheme, rest) = trimmed.split_once("://")?;
    let authority = rest.split('/').next()?;
    if scheme.is_empty() || authority.is_empty() {
        return None;
    }
    Some(format!(
        "{}://{}",
        scheme.to_ascii_lowercase(),
        authority.to_ascii_lowercase()
    ))
}

fn legacy_account_matches_directory(account_path: &Path, expected_dir_url: &str) -> bool {
    let Ok(raw) = read_bounded_file(account_path) else {
        return false;
    };
    let Ok(val) = serde_json::from_slice::<serde_json::Value>(&raw) else {
        return false;
    };
    if let Some(dir) = val.get("directory").and_then(serde_json::Value::as_str) {
        return normalize_acme_directory_url(dir) == expected_dir_url;
    }
    if let Some(id) = val.get("id").and_then(serde_json::Value::as_str)
        && let (Some(id_origin), Some(expected_origin)) =
            (extract_url_origin(id), extract_url_origin(expected_dir_url))
    {
        return id_origin == expected_origin;
    }
    false
}

fn is_real_dir(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|md| md.file_type().is_dir())
}

fn is_real_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|md| md.file_type().is_file())
}

fn move_secret_file(src: &Path, dst: &Path) -> bool {
    if fs::rename(src, dst).is_err() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = fs::set_permissions(dst, fs::Permissions::from_mode(0o600));
    }
    true
}

fn migrate_certs_dir(src: &Path, dst: &Path) -> bool {
    if !dst.exists() {
        if fs::rename(src, dst).is_ok() {
            let _ = create_private_dir_all(dst);
            return true;
        }
        return false;
    }
    if !is_real_dir(dst) {
        return false;
    }
    let Ok(entries) = fs::read_dir(src) else {
        return false;
    };
    let mut moved_any = false;
    for entry in entries.flatten() {
        let entry_path = entry.path();
        if !is_real_file(&entry_path) {
            continue;
        }
        let target = dst.join(entry.file_name());
        if !target.exists() && fs::rename(&entry_path, &target).is_ok() {
            moved_any = true;
        }
    }
    let _ = fs::remove_dir(src);
    moved_any
}

fn persist_legacy_cert_pair(
    certs_dir: &Path,
    safe_name: &str,
    cert_pem: &str,
    key_pem: &str,
) -> Result<(), TlsError> {
    let cert_path = certs_dir.join(format!("{safe_name}.crt"));
    let key_path = certs_dir.join(format!("{safe_name}.key"));
    let tmp_key_path = write_temp_file(&key_path, key_pem.as_bytes(), true)?;
    let tmp_cert_path = match write_temp_file(&cert_path, cert_pem.as_bytes(), false) {
        Ok(p) => p,
        Err(err) => {
            let _ = fs::remove_file(&tmp_key_path);
            return Err(err);
        }
    };
    let key_backup_path = certs_dir.join(format!("{safe_name}.key.bak"));
    let had_prev_key = if key_path.is_file() {
        fs::copy(&key_path, &key_backup_path).is_ok()
    } else {
        false
    };
    if let Err(source) = fs::rename(&tmp_key_path, &key_path) {
        let _ = fs::remove_file(&tmp_key_path);
        let _ = fs::remove_file(&tmp_cert_path);
        if had_prev_key {
            let _ = fs::remove_file(&key_backup_path);
        }
        return Err(TlsError::Io {
            path: key_path,
            source,
        });
    }
    if let Err(source) = fs::rename(&tmp_cert_path, &cert_path) {
        let _ = fs::remove_file(&tmp_cert_path);
        if had_prev_key {
            let _ = fs::rename(&key_backup_path, &key_path);
        }
        return Err(TlsError::Io {
            path: cert_path,
            source,
        });
    }
    if had_prev_key {
        let _ = fs::remove_file(&key_backup_path);
    }
    Ok(())
}

/// Executes a batch of asynchronous ARI queries with bounded concurrency (`max_concurrency`) and a
/// per-query timeout (`R5-ACME-5`). Returns `Err(())` for queries that exceed `per_query_timeout`.
pub async fn run_bounded_ari_queries<T, R, F, Fut>(
    targets: Vec<T>,
    max_concurrency: usize,
    per_query_timeout: Duration,
    mut query_fn: F,
) -> Vec<(T, Result<R, ()>)>
where
    T: Clone + Send + 'static,
    R: Send + 'static,
    F: FnMut(T) -> Fut,
    Fut: std::future::Future<Output = R> + Send + 'static,
{
    let limit = max_concurrency.max(1);
    let mut join_set = tokio::task::JoinSet::new();
    let mut iter = targets.into_iter();
    let mut out = Vec::new();

    for _ in 0..limit {
        if let Some(target) = iter.next() {
            let fut = query_fn(target.clone());
            join_set.spawn(async move {
                let res = tokio::time::timeout(per_query_timeout, fut)
                    .await
                    .map_err(|_| ());
                (target, res)
            });
        }
    }
    while let Some(joined) = join_set.join_next().await {
        if let Some(target) = iter.next() {
            let fut = query_fn(target.clone());
            join_set.spawn(async move {
                let res = tokio::time::timeout(per_query_timeout, fut)
                    .await
                    .map_err(|_| ());
                (target, res)
            });
        }
        if let Ok(item) = joined {
            out.push(item);
        }
    }
    out
}

/// Records an ARI query failure/timeout for `key` and returns the exponential backoff duration
/// (`15 min -> 30 min -> 1 h -> 2 h -> 4 h` cap, `R5-ACME-5`).
pub fn next_ari_error_backoff<S: std::hash::BuildHasher>(
    ari_error_streak: &mut HashMap<String, u32, S>,
    key: &str,
) -> Duration {
    let streak = ari_error_streak
        .entry(key.to_owned())
        .and_modify(|s| *s = s.saturating_add(1))
        .or_insert(0);
    let mult = 1_u32.checked_shl((*streak).min(4)).unwrap_or(16);
    ARI_QUERY_ERROR_BACKOFF_INITIAL
        .saturating_mul(mult)
        .min(ARI_QUERY_ERROR_BACKOFF_MAX)
}

fn find_leaf_certificate_pem(pem_bytes: &[u8]) -> Option<x509_parser::pem::Pem> {
    x509_parser::pem::Pem::iter_from_buffer(pem_bytes)
        .filter_map(Result::ok)
        .find(|p| p.label.eq_ignore_ascii_case("CERTIFICATE"))
}

fn parse_cert_validity_unix(pem_bytes: &[u8]) -> Option<(i64, i64)> {
    let pem = find_leaf_certificate_pem(pem_bytes)?;
    let cert = pem.parse_x509().ok()?;
    let validity = cert.validity();
    Some((
        validity.not_before.timestamp(),
        validity.not_after.timestamp(),
    ))
}

fn parse_cert_ari_id(pem_bytes: &[u8]) -> Option<CertificateIdentifier<'static>> {
    let pem = find_leaf_certificate_pem(pem_bytes)?;
    let cert = pem.parse_x509().ok()?;
    let aki_bytes = cert.extensions().iter().find_map(|ext| {
        if let x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(aki) =
            ext.parsed_extension()
        {
            aki.key_identifier.as_ref().map(|k| k.0)
        } else {
            None
        }
    })?;
    let serial_bytes = cert.raw_serial();
    let id = CertificateIdentifier::new(
        rustls::pki_types::Der::from_slice(aki_bytes),
        rustls::pki_types::Der::from_slice(serial_bytes),
    );
    Some(id.into_owned())
}

/// Creates a collision-free filesystem stem by appending a truncated SHA-256 digest of the
/// lowercased domain name (preventing `*.example.com` vs `_example.com` collisions).
fn sanitize_domain_filename(domain: &str) -> String {
    let lower = domain.to_ascii_lowercase();
    let safe_prefix: String = lower
        .chars()
        .take(48)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let hash_hex = sha256_short_hex(lower.as_bytes());
    format!("{safe_prefix}_{hash_hex}")
}

/// Computes a lowercase hex SHA-256 digest using `aws-lc-rs` (via `rustls`).
#[must_use]
pub fn sha256_hex(input: &[u8]) -> String {
    let rustls::SupportedCipherSuite::Tls13(suite) =
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256
    else {
        return String::new();
    };
    let digest = suite.common.hash_provider.hash(input);
    let mut out = String::with_capacity(64);
    for &b in digest.as_ref() {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn sha256_short_hex(input: &[u8]) -> String {
    let full = sha256_hex(input);
    full.get(..16).unwrap_or("0000000000000000").to_owned()
}

/// Creates (or verifies) the PRIVATE state directory `dir` (`R3-PKG-4`, Codex Round-6/7).
///
/// On Unix, walks `dir` component by component from `/` with `O_NOFOLLOW | O_DIRECTORY`:
/// - on Linux, `/` and all intermediate ancestors are opened with `O_PATH` (traversal-only,
///   requiring zero `LANDLOCK_ACCESS_FS_READ_DIR` on `/` or ungranted ancestors; Codex Round-7 P1);
/// - every existing ancestor must be a real directory (not an untrusted symlink), owned by root or
///   this process, and not group/world-writable unless sticky (e.g. `/tmp`);
/// - missing components are created `0700` via `mkdirat` on the already-verified parent descriptor
///   and reopened with `O_NOFOLLOW | O_DIRECTORY`;
/// - the leaf is opened with `O_RDONLY | O_DIRECTORY | O_NOFOLLOW` (within the worker's Landlock
///   RW grant), must be owned by this process's kernel euid, and its mode is checked/tightened to
///   `0700` through the opened handle (`fchmod`).
///
/// Any metadata, open, ownership, or symlink error is returned rather than treated as success.
///
/// # Errors
/// Returns [`TlsError::Io`] if creation, validation or permission tightening fails.
pub fn create_private_dir_all(dir: &Path) -> Result<(), TlsError> {
    create_and_open_private_dir(dir).map(|_| ())
}

/// Validates a private state directory (such as `--acme-dir`) using the exact same no-follow,
/// ancestor-safety, and ownership rules as [`create_private_dir_all`], **without** creating
/// missing components or modifying permissions (`fchmod`).
///
/// Returns `Ok(true)` if the directory exists and passes every check, `Ok(false)` if a component
/// does not exist yet (after every existing ancestor passed), or `Err(TlsError::Io)` with the same
/// diagnostic startup produces on a symlinked leaf/ancestor, `..`, `/`, unsafe ancestor, wrong
/// leaf owner, or non-directory component.
///
/// # Errors
/// Returns [`TlsError::Io`] if any existing component fails validation or cannot be inspected.
pub fn validate_private_dir_read_only(dir: &Path) -> Result<bool, TlsError> {
    #[cfg(unix)]
    {
        open_verified_private_dir_unix(dir, false, false)
            .map(|opt| opt.is_some())
            .map_err(|source| TlsError::Io {
                path: dir.to_path_buf(),
                source,
            })
    }
    #[cfg(not(unix))]
    {
        open_existing_private_dir(dir).map(|opt| opt.is_some())
    }
}

struct VerifiedPrivateDir {
    #[cfg(unix)]
    fd: rustix::fd::OwnedFd,
    path: PathBuf,
}

impl VerifiedPrivateDir {
    /// Reads a regular, process-owned file directly inside this verified private directory
    /// without following symlinks (`openat(..., O_NOFOLLOW)` on Unix; Codex Round-7 P2 #2).
    fn read_private_file(&self, file_name: &str) -> Result<Option<Vec<u8>>, TlsError> {
        if file_name.is_empty()
            || file_name.contains('/')
            || file_name.contains('\\')
            || file_name == "."
            || file_name == ".."
        {
            return Err(TlsError::Io {
                path: self.path.join(file_name),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid ACME state filename",
                ),
            });
        }
        let full_path = self.path.join(file_name);
        #[cfg(unix)]
        {
            use rustix::fs::{FileType, Mode, OFlags, fstat, openat};
            use rustix::io::Errno;

            // Codex Round-8 P2 #3: include `O_NONBLOCK` so a stale FIFO with no writer returns
            // immediately and is rejected by the `fstat` regular-file check instead of blocking
            // startup or reload.
            let file_fd = match openat(
                &self.fd,
                file_name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(fd) => fd,
                Err(Errno::NOENT) => return Ok(None),
                Err(Errno::LOOP) => {
                    return Err(TlsError::Io {
                        path: full_path,
                        source: std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            "refusing symbolic link inside ACME private state directory",
                        ),
                    });
                }
                Err(err) => {
                    return Err(TlsError::Io {
                        path: full_path,
                        source: err.into(),
                    });
                }
            };
            let st = fstat(&file_fd).map_err(|err| TlsError::Io {
                path: full_path.clone(),
                source: err.into(),
            })?;
            if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
                return Err(TlsError::Io {
                    path: full_path,
                    source: std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "ACME state entry is not a regular file",
                    ),
                });
            }
            let euid = crate::keyd::process_effective_uid();
            if st.st_uid != euid {
                return Err(TlsError::Io {
                    path: full_path,
                    source: std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!(
                            "ACME state file is owned by uid {}, not this process (uid {euid})",
                            st.st_uid
                        ),
                    ),
                });
            }
            let file = fs::File::from(file_fd);
            crate::cert::read_bounded_open_file(file, &full_path).map(Some)
        }
        #[cfg(not(unix))]
        {
            match fs::symlink_metadata(&full_path) {
                Ok(md) if md.file_type().is_file() => read_bounded_file(&full_path).map(Some),
                Ok(_) => Err(TlsError::Io {
                    path: full_path,
                    source: std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "refusing symbolic link or non-regular file inside ACME state directory",
                    ),
                }),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(source) => Err(TlsError::Io {
                    path: full_path,
                    source,
                }),
            }
        }
    }
}

fn create_and_open_private_dir(dir: &Path) -> Result<VerifiedPrivateDir, TlsError> {
    #[cfg(unix)]
    {
        let fd = open_verified_private_dir_unix(dir, true, true)
            .map_err(|source| TlsError::Io {
                path: dir.to_path_buf(),
                source,
            })?
            .ok_or_else(|| TlsError::Io {
                path: dir.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "private state directory vanished during creation",
                ),
            })?;
        Ok(VerifiedPrivateDir {
            fd,
            path: dir.to_path_buf(),
        })
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir).map_err(|source| TlsError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        Ok(VerifiedPrivateDir {
            path: dir.to_path_buf(),
        })
    }
}

fn open_existing_private_dir(dir: &Path) -> Result<Option<VerifiedPrivateDir>, TlsError> {
    #[cfg(unix)]
    {
        let opt =
            open_verified_private_dir_unix(dir, false, true).map_err(|source| TlsError::Io {
                path: dir.to_path_buf(),
                source,
            })?;
        Ok(opt.map(|fd| VerifiedPrivateDir {
            fd,
            path: dir.to_path_buf(),
        }))
    }
    #[cfg(not(unix))]
    {
        match fs::symlink_metadata(dir) {
            Ok(md) if md.file_type().is_dir() => Ok(Some(VerifiedPrivateDir {
                path: dir.to_path_buf(),
            })),
            Ok(_) => Err(TlsError::Io {
                path: dir.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "ACME state path is not a real directory",
                ),
            }),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(TlsError::Io {
                path: dir.to_path_buf(),
                source,
            }),
        }
    }
}

#[cfg(unix)]
fn open_verified_private_dir_unix(
    dir: &Path,
    create_missing: bool,
    tighten_mode: bool,
) -> std::io::Result<Option<rustix::fd::OwnedFd>> {
    use rustix::fs::{CWD, Mode, OFlags, fstat, mkdirat, openat};
    use rustix::io::Errno;
    use std::path::Component;

    let abs = if dir.is_absolute() {
        dir.to_path_buf()
    } else {
        std::env::current_dir()?.join(dir)
    };
    let mut parts: Vec<&std::ffi::OsStr> = Vec::new();
    for comp in abs.components() {
        match comp {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => parts.push(name),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "private state path '{}' must not contain '..' or unsupported prefix",
                        dir.display()
                    ),
                ));
            }
        }
    }
    if parts.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "refusing filesystem root '{}' as private state path",
                dir.display()
            ),
        ));
    }

    let euid = Some(crate::keyd::process_effective_uid());
    // Codex Round-7 P1: on Linux, open `/` and every non-leaf ancestor with `O_PATH` so Landlock
    // never needs `READ_DIR` on `/` or ungranted ancestors; open the verified leaf with `O_RDONLY`
    // (inside the worker's Landlock RW grant) so `fchmod` and `openat` cache reads succeed.
    #[cfg(target_os = "linux")]
    let (root_flags, ancestor_flags) = (
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
    );
    #[cfg(not(target_os = "linux"))]
    let (root_flags, ancestor_flags) = (
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
    );
    let leaf_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;

    let mut cur_fd = openat(CWD, "/", root_flags, Mode::empty())?;

    for (idx, comp) in parts.iter().enumerate() {
        let is_leaf = idx + 1 == parts.len();
        let step_flags = if is_leaf { leaf_flags } else { ancestor_flags };
        let next_fd = match openat(&cur_fd, *comp, step_flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => {
                if !create_missing {
                    return Ok(None);
                }
                match mkdirat(&cur_fd, *comp, Mode::from_raw_mode(0o700)) {
                    Ok(()) | Err(Errno::EXIST) => {}
                    Err(err) => return Err(err.into()),
                }
                openat(&cur_fd, *comp, step_flags, Mode::empty()).map_err(|err| {
                    if matches!(err, Errno::LOOP | Errno::NOTDIR) {
                        std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            format!(
                                "private state path '{}' contains a symbolic link or non-directory component",
                                dir.display()
                            ),
                        )
                    } else {
                        err.into()
                    }
                })?
            }
            Err(Errno::LOOP | Errno::NOTDIR) => {
                if let Some(fd) = open_trusted_os_root_link(&cur_fd, comp, idx, is_leaf)? {
                    fd
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!(
                            "private state path '{}' contains a symbolic link or non-directory component",
                            dir.display()
                        ),
                    ));
                }
            }
            Err(err) => return Err(err.into()),
        };

        let st = fstat(&next_fd)?;
        check_or_tighten_private_dir_fd(&next_fd, &st, dir, euid, is_leaf, tighten_mode)?;
        cur_fd = next_fd;
    }
    Ok(Some(cur_fd))
}

/// Pure ownership & permission verifier for private state directories (Codex Round-7 P2 #1).
///
/// Fails closed if `euid` is `None` (never skips ownership checks when the effective UID is
/// unknown).
#[cfg(unix)]
fn check_private_dir_ownership_and_mode(
    st_uid: u32,
    st_mode: u32,
    euid: Option<u32>,
    is_leaf: bool,
    dir: &Path,
) -> std::io::Result<()> {
    let Some(uid) = euid else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "cannot verify ownership of private state path '{}': effective UID is unknown",
                dir.display()
            ),
        ));
    };
    if is_leaf {
        if st_uid != uid {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "private state directory '{}' is owned by uid {st_uid}, not this process (uid {uid})",
                    dir.display(),
                ),
            ));
        }
    } else {
        let owner_ok = st_uid == 0 || st_uid == uid;
        let shared_writable = (st_mode & 0o022) != 0 && (st_mode & 0o1000) == 0;
        if !owner_ok || shared_writable {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "private state path '{}' has unsafe ancestor component (uid {st_uid}, mode {:04o})",
                    dir.display(),
                    st_mode & 0o7777
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn check_or_tighten_private_dir_fd(
    fd: &rustix::fd::OwnedFd,
    st: &rustix::fs::Stat,
    dir: &Path,
    euid: Option<u32>,
    is_leaf: bool,
    tighten_mode: bool,
) -> std::io::Result<()> {
    use rustix::fs::{FileType, Mode, fchmod};

    if FileType::from_raw_mode(st.st_mode) != FileType::Directory {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("private state path '{}' is not a directory", dir.display()),
        ));
    }
    #[allow(clippy::useless_conversion)]
    let raw_mode = u32::from(st.st_mode);
    check_private_dir_ownership_and_mode(st.st_uid, raw_mode, euid, is_leaf, dir)?;
    if tighten_mode && is_leaf && (st.st_mode & 0o7777) != 0o700 {
        fchmod(fd, Mode::from_raw_mode(0o700))?;
    }
    Ok(())
}

/// Allows macOS's root-owned top-level OS links (`/var -> private/var`, `/tmp -> private/tmp`,
/// `/etc -> private/etc`) as non-leaf ancestors while rejecting every other symlink.
// Only the macOS body can fail; the signature is shared with the other Unix targets.
#[cfg(unix)]
#[cfg_attr(not(target_os = "macos"), allow(clippy::unnecessary_wraps))]
pub(crate) fn open_trusted_os_root_link(
    parent_fd: &rustix::fd::OwnedFd,
    comp: &std::ffi::OsStr,
    depth: usize,
    is_leaf: bool,
) -> std::io::Result<Option<rustix::fd::OwnedFd>> {
    #[cfg(target_os = "macos")]
    {
        use rustix::fs::{AtFlags, FileType, Mode, OFlags, openat, statat};
        if !is_leaf
            && depth == 0
            && (comp == std::ffi::OsStr::new("var")
                || comp == std::ffi::OsStr::new("tmp")
                || comp == std::ffi::OsStr::new("etc"))
            && let Ok(link_st) = statat(parent_fd, comp, AtFlags::SYMLINK_NOFOLLOW)
            && FileType::from_raw_mode(link_st.st_mode) == FileType::Symlink
            && link_st.st_uid == 0
        {
            let fd = openat(
                parent_fd,
                comp,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            return Ok(Some(fd));
        }
        Ok(None)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (parent_fd, comp, depth, is_leaf);
        Ok(None)
    }
}

/// Creates missing parent directories with `0o700` on Unix WITHOUT altering permissions of any
/// pre-existing directory (`R5-PKG-2`), so writing a secret file into a shared directory such as
/// `/etc/miraserve/certs` (`0750 root:miraserve`) never locks the `miraserve` worker out.
fn ensure_parent_dir_exists(dir: &Path) -> Result<(), TlsError> {
    if dir.exists() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(dir).map_err(|source| TlsError::Io {
            path: dir.to_path_buf(),
            source,
        })
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir).map_err(|source| TlsError::Io {
            path: dir.to_path_buf(),
            source,
        })
    }
}

/// Creates a uniquely-named temporary sibling file beside `path`, writes all `bytes`, and calls
/// `sync_all()` without replacing `path` yet (used for paired atomic persistence in `R3-ACME-2`).
fn write_temp_file(path: &Path, bytes: &[u8], secret: bool) -> Result<PathBuf, TlsError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        ensure_parent_dir_exists(parent)?;
    }

    let mut rand_bytes = [0_u8; 8];
    let _ = rustls::crypto::aws_lc_rs::default_provider()
        .secure_random
        .fill(&mut rand_bytes);
    let suffix = u64::from_be_bytes(rand_bytes);
    let file_name = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("secret");
    let tmp_path = path.with_file_name(format!(
        ".{file_name}.tmp-{}-{suffix:016x}",
        std::process::id()
    ));

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(if secret { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = secret;

    let mut file = opts.open(&tmp_path).map_err(|source| TlsError::Io {
        path: tmp_path.clone(),
        source,
    })?;

    if let Err(source) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&tmp_path);
        return Err(TlsError::Io {
            path: tmp_path,
            source,
        });
    }
    drop(file);
    Ok(tmp_path)
}

/// Atomically writes secret key material to `path` with `0o600` permissions set at file
/// creation time (eliminating any pre-`chmod` world-readable TOCTOU window!).
///
/// # Errors
/// Returns [`TlsError::Io`] if temp creation, write, sync, or atomic rename fails.
pub fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<(), TlsError> {
    let tmp_path = write_temp_file(path, bytes, true)?;
    if let Err(source) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(TlsError::Io {
            path: path.to_path_buf(),
            source,
        });
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// Codex Round-7 P2 #1: ownership verification must fail closed when the effective UID is
    /// unknown (`None`) and enforce strict leaf/ancestor rules independently of procfs.
    #[test]
    fn r7_acme_ownership_check_fails_closed_on_unknown_uid() {
        let p = Path::new("/var/lib/miraserve/acme");
        assert!(check_private_dir_ownership_and_mode(0, 0o755, None, false, p).is_err());
        assert!(check_private_dir_ownership_and_mode(1000, 0o700, None, true, p).is_err());

        assert!(check_private_dir_ownership_and_mode(1000, 0o700, Some(1000), true, p).is_ok());
        assert!(check_private_dir_ownership_and_mode(1000, 0o755, Some(1000), true, p).is_ok());
        assert!(check_private_dir_ownership_and_mode(0, 0o700, Some(1000), true, p).is_err());
        assert!(check_private_dir_ownership_and_mode(1001, 0o700, Some(1000), true, p).is_err());

        assert!(check_private_dir_ownership_and_mode(0, 0o755, Some(1000), false, p).is_ok());
        assert!(check_private_dir_ownership_and_mode(0, 0o1777, Some(1000), false, p).is_ok());
        assert!(check_private_dir_ownership_and_mode(1000, 0o755, Some(1000), false, p).is_ok());
        assert!(check_private_dir_ownership_and_mode(1001, 0o700, Some(1000), false, p).is_err());
        assert!(check_private_dir_ownership_and_mode(0, 0o775, Some(1000), false, p).is_err());
        assert!(check_private_dir_ownership_and_mode(1000, 0o777, Some(1000), false, p).is_err());
    }
}

//! Lock-free SNI certificate resolver (`ArcSwap::rcu`) supporting exact host matches,
//! wildcard certificates, default fallback, atomic hot reload, domain-scoped HTTP-01
//! challenges, and strictly isolated RFC 8737 ACME `tls-alpn-01` resolution.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use arc_swap::ArcSwap;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

/// ALPN protocol identifier for RFC 8737 ACME TLS-ALPN-01 validation.
pub const ACME_TLS_ALPN_PROTOCOL: &[u8] = b"acme-tls/1";

/// Lock-free store for active ACME challenge material shared between the TLS layer
/// (`tls-alpn-01`) and the HTTP layer (`http-01`), updated atomically via `ArcSwap::rcu`.
#[derive(Debug, Default)]
pub struct AcmeChallengeStore {
    alpn_certs: ArcSwap<HashMap<String, Arc<CertifiedKey>>>,
    /// Domain-scoped HTTP-01 challenges keyed by `lowercased_domain -> (token -> key_auth)`.
    /// Nested maps allow borrowed `(&str, &str)` lookups without allocating a composite key.
    http01_tokens: ArcSwap<HashMap<String, HashMap<String, String>>>,
}

impl AcmeChallengeStore {
    /// Creates an empty challenge store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an active RFC 8737 TLS-ALPN-01 certificate for `domain`.
    #[allow(clippy::needless_pass_by_value)]
    pub fn set_alpn_cert(&self, domain: &str, cert: Arc<CertifiedKey>) {
        let key = domain.to_ascii_lowercase();
        self.alpn_certs.rcu(|current| {
            let mut next = (**current).clone();
            next.insert(key.clone(), Arc::clone(&cert));
            next
        });
    }

    /// Removes a completed TLS-ALPN-01 challenge certificate for `domain`.
    pub fn clear_alpn_cert(&self, domain: &str) {
        let key = domain.to_ascii_lowercase();
        self.alpn_certs.rcu(|current| {
            let mut next = (**current).clone();
            next.remove(&key);
            next
        });
    }

    /// Looks up an active TLS-ALPN-01 challenge certificate for `domain`.
    #[must_use]
    pub fn get_alpn_cert(&self, domain: &str) -> Option<Arc<CertifiedKey>> {
        let key = domain.to_ascii_lowercase();
        self.alpn_certs.load().get(&key).cloned()
    }

    /// Returns `true` if an active TLS-ALPN-01 challenge exists for `domain`.
    #[must_use]
    pub fn has_alpn_challenge(&self, domain: &str) -> bool {
        let key = domain.to_ascii_lowercase();
        self.alpn_certs.load().contains_key(&key)
    }

    /// Registers an active domain-scoped HTTP-01 challenge token and its key authorization.
    #[allow(clippy::needless_pass_by_value)]
    pub fn set_http01_token(&self, domain: &str, token: &str, key_auth: String) {
        let domain_key = domain.to_ascii_lowercase();
        self.http01_tokens.rcu(|current| {
            let mut next = (**current).clone();
            next.entry(domain_key.clone())
                .or_default()
                .insert(token.to_owned(), key_auth.clone());
            next
        });
    }

    /// Removes a completed domain-scoped HTTP-01 challenge token.
    pub fn clear_http01_token(&self, domain: &str, token: &str) {
        let domain_key = domain.to_ascii_lowercase();
        self.http01_tokens.rcu(|current| {
            let mut next = (**current).clone();
            if let Some(tokens) = next.get_mut(&domain_key) {
                tokens.remove(token);
                if tokens.is_empty() {
                    next.remove(&domain_key);
                }
            }
            next
        });
    }

    /// Returns `true` if an active HTTP-01 challenge token exists strictly for `(domain, token)`
    /// (RFC 8555 §8.3), without cloning the key authorization or allocating when the store is
    /// empty or `domain` is already lowercase.
    #[must_use]
    pub fn has_http01_token(&self, domain: &str, token: &str) -> bool {
        let snap = self.http01_tokens.load();
        if snap.is_empty() {
            return false;
        }
        if domain.bytes().all(|b| !b.is_ascii_uppercase()) {
            snap.get(domain)
                .is_some_and(|tokens| tokens.contains_key(token))
        } else {
            let lower = domain.to_ascii_lowercase();
            snap.get(&lower)
                .is_some_and(|tokens| tokens.contains_key(token))
        }
    }

    /// Looks up the HTTP-01 key authorization strictly for `(domain, token)` (RFC 8555 §8.3),
    /// avoiding heap allocation on empty stores and on misses for already-lowercase `domain`.
    #[must_use]
    pub fn get_http01_token(&self, domain: &str, token: &str) -> Option<String> {
        let snap = self.http01_tokens.load();
        if snap.is_empty() {
            return None;
        }
        let tokens = if domain.bytes().all(|b| !b.is_ascii_uppercase()) {
            snap.get(domain)?
        } else {
            let lower = domain.to_ascii_lowercase();
            snap.get(&lower)?
        };
        tokens.get(token).cloned()
    }
}

/// Dedicated RFC 8737 ACME `tls-alpn-01` certificate resolver attached EXCLUSIVELY to
/// [`crate::TlsConfigSet::acme_alpn`].
///
/// Enforces RFC 8737 §3 isolation: returns an ACME challenge certificate ONLY when the
/// client's ALPN extension offers `acme-tls/1` as its sole protocol, guaranteeing that
/// QUIC/HTTP/3 (`h3`) or application TCP (`h2`/`http/1.1`) sessions can never negotiate
/// over an ephemeral challenge certificate.
#[derive(Debug)]
pub struct AcmeAlpnCertResolver {
    acme: Arc<AcmeChallengeStore>,
}

impl AcmeAlpnCertResolver {
    /// Creates a new isolated ACME TLS-ALPN-01 resolver backed by `acme`.
    #[must_use]
    pub const fn new(acme: Arc<AcmeChallengeStore>) -> Self {
        Self { acme }
    }
}

impl ResolvesServerCert for AcmeAlpnCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let mut alpns = client_hello.alpn()?;
        let first = alpns.next()?;
        // RFC 8737 §3: `acme-tls/1` MUST be the sole ALPN protocol offered.
        if first != ACME_TLS_ALPN_PROTOCOL || alpns.next().is_some() {
            return None;
        }
        let domain = client_hello.server_name()?;
        self.acme.get_alpn_cert(domain)
    }
}

#[derive(Debug, Default, Clone)]
struct CertTable {
    exact: HashMap<String, Arc<CertifiedKey>>,
    wildcard: HashMap<String, Arc<CertifiedKey>>,
    default: Option<Arc<CertifiedKey>>,
    /// Host keys installed dynamically by ACME (as opposed to static manual config certs),
    /// enabling reloads to drop removed manual certs immediately while preserving active ACME
    /// certs without racing the ACME supervisor (`R2-ACME-6`).
    acme_exact: HashSet<String>,
    acme_wildcard: HashSet<String>,
    /// Wildcard suffixes installed from a tenant site's own pair, with that site's index: such a
    /// wildcard serves only names no other site owns (HTTP would route those elsewhere, and the
    /// tenant's quarantine must not take their certificate away).
    tenant_wildcard_site: HashMap<String, usize>,
    /// Exact host name -> index of the site that owns it.
    host_site: HashMap<String, usize>,
}

/// Lock-free dynamic SNI certificate resolver implementing [`ResolvesServerCert`] for
/// production application traffic (NEVER serves ACME challenge certificates).
#[derive(Debug)]
pub struct DynamicCertResolver {
    table: ArcSwap<CertTable>,
    acme: Arc<AcmeChallengeStore>,
}

impl DynamicCertResolver {
    /// Creates an empty resolver attached to the supplied [`AcmeChallengeStore`].
    #[must_use]
    pub fn new(acme: Arc<AcmeChallengeStore>) -> Self {
        Self {
            table: ArcSwap::from_pointee(CertTable::default()),
            acme,
        }
    }

    /// Returns a handle to the shared [`AcmeChallengeStore`].
    #[must_use]
    pub fn acme_store(&self) -> Arc<AcmeChallengeStore> {
        Arc::clone(&self.acme)
    }

    /// Returns `true` if at least one host, wildcard, or default certificate is loaded.
    #[must_use]
    pub fn has_certificates(&self) -> bool {
        let snap = self.table.load();
        snap.default.is_some() || !snap.exact.is_empty() || !snap.wildcard.is_empty()
    }

    /// Sets the default fallback certificate used when no exact/wildcard SNI match exists.
    #[allow(clippy::needless_pass_by_value)]
    pub fn set_default(&self, cert: Arc<CertifiedKey>) {
        self.table.rcu(|current| {
            let mut next = (**current).clone();
            next.default = Some(Arc::clone(&cert));
            next
        });
    }

    /// Inserts or replaces the certificate for a single hostname (supports `"*.example.com"`).
    #[allow(clippy::needless_pass_by_value)]
    pub fn upsert_host(&self, host: &str, cert: Arc<CertifiedKey>) {
        let host = host.to_owned();
        self.table.rcu(|current| {
            let mut next = (**current).clone();
            insert_entry(&mut next, &host, Arc::clone(&cert), false);
            next
        });
    }

    /// Inserts or replaces an ACME-issued certificate for a single hostname, marking it as
    /// ACME-managed so hot reloads preserve it while dropping removed manual certs (`R2-ACME-6`).
    #[allow(clippy::needless_pass_by_value)]
    pub fn upsert_acme_host(&self, host: &str, cert: Arc<CertifiedKey>) {
        let host = host.to_owned();
        self.table.rcu(|current| {
            let mut next = (**current).clone();
            insert_entry(&mut next, &host, Arc::clone(&cert), true);
            next
        });
    }

    /// Atomically replaces the entire certificate table.
    pub fn replace_all(
        &self,
        hosts: impl IntoIterator<Item = (String, Arc<CertifiedKey>)>,
        default: Option<Arc<CertifiedKey>>,
    ) {
        self.replace_all_with_owners(hosts, default, HashMap::new(), HashMap::new());
    }

    /// [`Self::replace_all`] that also records site ownership: `tenant_wildcard_site` maps a
    /// tenant site's wildcard suffix (`example.com` for `*.example.com`) to that site's index,
    /// and `host_site` maps every exact host name to the index of the site that owns it. A
    /// tenant wildcard is then never used for a name another site owns.
    pub fn replace_all_with_owners(
        &self,
        hosts: impl IntoIterator<Item = (String, Arc<CertifiedKey>)>,
        default: Option<Arc<CertifiedKey>>,
        tenant_wildcard_site: HashMap<String, usize>,
        host_site: HashMap<String, usize>,
    ) {
        let mut next = CertTable {
            exact: HashMap::new(),
            wildcard: HashMap::new(),
            default,
            acme_exact: HashSet::new(),
            acme_wildcard: HashSet::new(),
            tenant_wildcard_site,
            host_site,
        };
        for (host, cert) in hosts {
            insert_entry(&mut next, &host, cert, false);
        }
        self.table.store(Arc::new(next));
    }

    /// Preserves any existing exact/wildcard/default certificates from `previous` that are
    /// not explicitly overridden in `self` (legacy helper; prefer [`Self::commit_reload_preserving_acme`]).
    pub fn preserve_missing_from(&self, previous: &Self) {
        let prev = previous.table.load();
        self.table.rcu(|current| {
            let mut next = (**current).clone();
            for (k, v) in &prev.exact {
                next.exact.entry(k.clone()).or_insert_with(|| Arc::clone(v));
                if prev.acme_exact.contains(k) {
                    next.acme_exact.insert(k.clone());
                }
            }
            for (k, v) in &prev.wildcard {
                next.wildcard
                    .entry(k.clone())
                    .or_insert_with(|| Arc::clone(v));
                if prev.acme_wildcard.contains(k) {
                    next.acme_wildcard.insert(k.clone());
                }
            }
            if next.default.is_none() {
                next.default.clone_from(&prev.default);
            }
            next
        });
    }

    /// Atomically commits a staged reload table into `self` via `ArcSwap::rcu` (`R2-ACME-6`):
    /// - Takes all fresh manual/keyd/cached certs from `staged` (so removed or revoked manual
    ///   certs are dropped immediately on reload).
    /// - Preserves ONLY currently live **ACME-managed** certs for hosts still listed in
    ///   `keep_acme_hosts` (never racing a concurrent ACME `upsert_acme_host`!).
    /// - Preserves the existing default fallback cert only when `keep_default_fallback` is true
    ///   and `staged` has no default cert of its own.
    pub fn commit_reload_preserving_acme(
        &self,
        staged: &Self,
        keep_acme_hosts: &HashSet<String>,
        keep_default_fallback: bool,
    ) {
        let staged_snap = staged.table.load_full();
        self.table.rcu(|current| {
            let mut next = (*staged_snap).clone();
            for host in &current.acme_exact {
                if keep_acme_hosts.contains(host)
                    && !next.exact.contains_key(host)
                    && let Some(cert) = current.exact.get(host)
                {
                    next.exact.insert(host.clone(), Arc::clone(cert));
                    next.acme_exact.insert(host.clone());
                }
            }
            for suffix in &current.acme_wildcard {
                let wild_key = format!("*.{suffix}");
                if keep_acme_hosts.contains(&wild_key)
                    && !next.wildcard.contains_key(suffix)
                    && let Some(cert) = current.wildcard.get(suffix)
                {
                    next.wildcard.insert(suffix.clone(), Arc::clone(cert));
                    next.acme_wildcard.insert(suffix.clone());
                }
            }
            if keep_default_fallback && next.default.is_none() {
                next.default.clone_from(&current.default);
            }
            next
        });
    }

    /// Atomically commits a fully prepared staged resolver's certificate table into `self`.
    pub fn swap_table_from(&self, staged: &Self) {
        let snap = staged.table.load_full();
        self.table.store(snap);
    }

    /// Resolves a certificate for an explicit hostname (primarily for inspection and testing).
    #[must_use]
    pub fn lookup_host(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        let snapshot = self.table.load();
        let lower = host.to_ascii_lowercase();
        if let Some(cert) = snapshot.exact.get(&lower) {
            return Some(Arc::clone(cert));
        }
        if let Some((_, suffix)) = lower.split_once('.')
            && let Some(cert) = snapshot.wildcard.get(suffix)
        {
            // A tenant's wildcard does not cover a name another site owns.
            let foreign = snapshot
                .tenant_wildcard_site
                .get(suffix)
                .zip(snapshot.host_site.get(&lower))
                .is_some_and(|(tenant, owner)| tenant != owner);
            if !foreign {
                return Some(Arc::clone(cert));
            }
        }
        snapshot.default.clone()
    }
}

fn insert_entry(table: &mut CertTable, host: &str, cert: Arc<CertifiedKey>, is_acme: bool) {
    let lower = host.to_ascii_lowercase();
    if let Some(suffix) = lower.strip_prefix("*.") {
        table.wildcard.insert(suffix.to_owned(), cert);
        if is_acme {
            table.acme_wildcard.insert(suffix.to_owned());
        } else {
            table.acme_wildcard.remove(suffix);
        }
    } else {
        table.exact.insert(lower.clone(), cert);
        if is_acme {
            table.acme_exact.insert(lower);
        } else {
            table.acme_exact.remove(&lower);
        }
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // Application certificate resolver NEVER returns ACME TLS-ALPN-01 challenge certs!
        if let Some(host) = client_hello.server_name() {
            return self.lookup_host(host);
        }
        self.table.load().default.clone()
    }
}

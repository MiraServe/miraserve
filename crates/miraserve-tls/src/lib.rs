#![forbid(unsafe_code)]
//! Post-quantum TLS 1.3 (`X25519MLKEM768`), dynamic SNI certificate management,
//! dev TLS generation, and ACME v2 / RFC 9773 ARI support for MiraServe.

pub mod acme;
pub mod cert;
pub mod ech;
pub mod keyd;
pub mod resolver;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use miraserve_config::{Config, KeyIsolation, Protocol, TlsVersion, UpstreamTlsConfig};
pub use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use thiserror::Error;
use zeroize::Zeroizing;

pub use acme::{
    ARI_QUERY_TIMEOUT, AcmeManager, AriScheduleDecision, MAX_CONCURRENT_ARI_QUERIES,
    build_tls_alpn_01_cert, compute_ari_renewal_delay, create_private_dir_all,
    next_ari_error_backoff, plan_ari_schedule, run_bounded_ari_queries, sha256_hex,
    validate_private_dir_read_only, write_secret_file,
};
pub use cert::{
    CertInfo, GeneratedCertPem, generate_dev_cert_pem, generate_dev_certificate, inspect_cert_file,
    inspect_cert_pem, load_certified_key_from_files, load_certified_key_from_pem,
};
pub use ech::{EchKeyEntry, EchPublicSnapshot, EchRotationManager, format_dns_https_record};
pub use keyd::{
    KEYD_AUTH_SECRET_ENV, KeydCertDescriptor, KeydClient, KeydEndpoint, KeydKeyStore, KeydServer,
    KeydUnixPeerPolicy, RemoteKeyBundle, RemoteSigningKey, RunningKeyd, generate_keyd_auth_secret,
    is_tls12_ecdhe_server_key_exchange, is_tls13_server_certificate_verify,
    load_keyd_auth_secret_file, load_keyd_auth_secret_from_env, parse_keyd_auth_secret,
    resolve_unix_user_uid,
};
pub use resolver::{
    ACME_TLS_ALPN_PROTOCOL, AcmeAlpnCertResolver, AcmeChallengeStore, DynamicCertResolver,
};

/// Errors produced by MiraServe's TLS, certificate, and ACME subsystems.
#[derive(Debug, Error)]
pub enum TlsError {
    /// Filesystem I/O error reading or writing certificates/keys/ACME state.
    #[error("TLS I/O error at '{path}': {source}")]
    Io {
        /// Path involved in the I/O operation.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },
    /// Invalid PEM encoding or empty certificate chain.
    #[error("PEM parsing error: {0}")]
    PemParse(String),
    /// Signing key could not be loaded or did not match leaf certificate.
    #[error("private key error: {0}")]
    KeyLoad(String),
    /// Self-signed or challenge certificate generation failure.
    #[error("certificate generation failed: {0}")]
    CertGeneration(String),
    /// X.509 DER inspection error.
    #[error("certificate inspection failed: {0}")]
    CertInspect(String),
    /// `rustls` configuration builder error.
    #[error("TLS configuration error: {0}")]
    Rustls(String),
    /// ACME v2 client or challenge error.
    #[error("ACME error: {0}")]
    Acme(String),
    /// Server configured for HTTPS with no certificates and `--dev-tls` disabled.
    #[error("no TLS certificates available: configure cert/key, enable ACME, or pass --dev-tls")]
    NoCertificates,
}

/// Builds the `aws-lc-rs` [`CryptoProvider`] with optional Post-Quantum Hybrid key exchange.
///
/// When `pqc_hybrid` is `true` (default), **`X25519MLKEM768` (RFC 10024)** is prioritized
/// first ahead of classical `X25519`, `SECP256R1`, and `SECP384R1`.
#[must_use]
pub fn build_crypto_provider(pqc_hybrid: bool) -> Arc<CryptoProvider> {
    let mut provider = aws_lc_rs::default_provider();
    if pqc_hybrid {
        provider.kx_groups = vec![
            kx_group::X25519MLKEM768,
            kx_group::X25519,
            kx_group::SECP256R1,
            kx_group::SECP384R1,
        ];
    } else {
        provider.kx_groups = vec![kx_group::X25519, kx_group::SECP256R1, kx_group::SECP384R1];
    }
    Arc::new(provider)
}

/// Per-site strict mTLS client-certificate trust verifier built from ONE site's effective
/// `client-ca` PEM bundle (prevents cross-site CA confusion across TCP, QUIC/HTTP/3, and
/// HTTP/2 coalesced connections).
#[derive(Debug, Clone)]
pub struct ClientCertTrust {
    verifier: Arc<dyn ClientCertVerifier>,
}

impl ClientCertTrust {
    /// Loads a single `client-ca` PEM file into a strict `WebPKI` [`ClientCertTrust`] verifier.
    ///
    /// # Errors
    /// Returns [`TlsError`] if the PEM file cannot be read, contains no valid certificates,
    /// or `rustls` fails to construct the `WebPKI` verifier.
    pub fn from_pem_file(path: &str, pqc_hybrid: bool) -> Result<Self, TlsError> {
        let roots = load_single_client_ca_roots(path)?;
        let provider = build_crypto_provider(pqc_hybrid);
        let verifier = WebPkiClientVerifier::builder_with_provider(roots, provider)
            .build()
            .map_err(|err| {
                TlsError::Rustls(format!("failed to build site mTLS verifier: {err}"))
            })?;
        Ok(Self { verifier })
    }

    /// Cryptographically verifies a TLS-authenticated peer DER certificate chain (`[leaf, ...]`)
    /// specifically against THIS site's trusted `client-ca` roots, returning the verified leaf
    /// X.509 Subject DN on success or `None` if the chain is untrusted, expired, or empty.
    #[must_use]
    pub fn verify_peer_chain(&self, chain_der: &[Vec<u8>]) -> Option<String> {
        let leaf_bytes = chain_der.first()?;
        let leaf = CertificateDer::from(leaf_bytes.as_slice());
        let intermediates: Vec<CertificateDer<'_>> = chain_der
            .get(1..)
            .unwrap_or(&[])
            .iter()
            .map(|b| CertificateDer::from(b.as_slice()))
            .collect();
        self.verifier
            .verify_client_cert(&leaf, &intermediates, UnixTime::now())
            .ok()?;
        extract_verified_client_cert_dn(Some(&[leaf]))
    }
}

#[derive(Debug, Clone)]
struct SiteTlsVariants {
    tls13_pqc: Arc<ServerConfig>,
    tls13_classical: Arc<ServerConfig>,
    tls12_pqc: Arc<ServerConfig>,
    tls12_classical: Arc<ServerConfig>,
}

/// Collection of pre-built [`ServerConfig`] variants sharing one lock-free [`DynamicCertResolver`].
///
/// Enables true per-SNI TLS 1.3 vs legacy TLS 1.2 (`compat-tls-1-2`), PQC, and **per-site
/// `client-ca` mTLS** isolation on the same TCP listener via `tokio_rustls::LazyConfigAcceptor`,
/// plus dedicated configs for RFC 8737 `acme-tls/1` and HTTP/3 (`h3`).
#[derive(Debug, Clone)]
pub struct TlsConfigSet {
    /// Strict TLS 1.3 + `X25519MLKEM768` PQC hybrid (default, trusting only global `server.tls.client_ca`).
    pub tls13_pqc: Arc<ServerConfig>,
    /// Strict TLS 1.3 with classical key exchange only.
    pub tls13_classical: Arc<ServerConfig>,
    /// TLS 1.3 + TLS 1.2 + `X25519MLKEM768` PQC hybrid (for `compat-tls-1-2` sites).
    pub tls12_pqc: Arc<ServerConfig>,
    /// TLS 1.3 + TLS 1.2 with classical key exchange only.
    pub tls12_classical: Arc<ServerConfig>,
    /// Dedicated TLS 1.3 config advertising ALPN `acme-tls/1`.
    pub acme_alpn: Arc<ServerConfig>,
    /// Dedicated TLS 1.3 + `X25519MLKEM768` config for QUIC / HTTP/3 (`alpn = ["h3"]`).
    pub quic_h3: Arc<ServerConfig>,
    /// Shared dynamic SNI certificate resolver.
    pub resolver: Arc<DynamicCertResolver>,
    /// Isolated per-site TCP [`ServerConfig`] sets for sites declaring their own `site.tls.client-ca`.
    site_mtls_overrides: HashMap<String, SiteTlsVariants>,
}

impl TlsConfigSet {
    /// Constructs all TLS server config variants for a listener's enabled TCP protocols.
    ///
    /// # Errors
    /// Returns [`TlsError::Rustls`] if `rustls` rejects the protocol/provider combination.
    pub fn build(
        resolver: Arc<DynamicCertResolver>,
        tcp_protocols: &[Protocol],
    ) -> Result<Self, TlsError> {
        Self::build_with_config(resolver, tcp_protocols, None)
    }

    /// Constructs all TLS server config variants honoring optional `client-ca` mTLS roots
    /// (`PUB-2`) and `pqc-hybrid` preference for HTTP/3 QUIC (`TLS-1`).
    ///
    /// # Errors
    /// Returns [`TlsError`] if any `client-ca` PEM fails to load or `rustls` rejects configuration.
    #[allow(clippy::too_many_lines)]
    pub fn build_with_config(
        resolver: Arc<DynamicCertResolver>,
        tcp_protocols: &[Protocol],
        config: Option<&Config>,
    ) -> Result<Self, TlsError> {
        let mut tcp_alpn: Vec<Vec<u8>> = Vec::new();
        if tcp_protocols.contains(&Protocol::H2) {
            tcp_alpn.push(b"h2".to_vec());
        }
        if tcp_protocols.contains(&Protocol::H1) || tcp_alpn.is_empty() {
            tcp_alpn.push(b"http/1.1".to_vec());
        }

        let pqc_provider = build_crypto_provider(true);
        let classical_provider = build_crypto_provider(false);
        // Default TCP configs trust ONLY the global `server.tls.client-ca` (never pooling
        // site-specific CAs into other sites!). Sites with their own `site.tls.client-ca`
        // receive isolated per-site TCP ServerConfigs selected by SNI in `select_for_handshake`.
        let global_client_roots = config
            .and_then(|c| c.server.tls.client_ca.as_deref())
            .map(load_single_client_ca_roots)
            .transpose()?;

        let tls13_pqc = build_single_server_config(
            Arc::clone(&pqc_provider),
            &[&rustls::version::TLS13],
            Arc::clone(&resolver),
            tcp_alpn.clone(),
            global_client_roots.as_ref(),
        )?;
        let tls13_classical = build_single_server_config(
            Arc::clone(&classical_provider),
            &[&rustls::version::TLS13],
            Arc::clone(&resolver),
            tcp_alpn.clone(),
            global_client_roots.as_ref(),
        )?;
        let tls12_pqc = build_single_server_config(
            Arc::clone(&pqc_provider),
            &[&rustls::version::TLS13, &rustls::version::TLS12],
            Arc::clone(&resolver),
            tcp_alpn.clone(),
            global_client_roots.as_ref(),
        )?;
        let tls12_classical = build_single_server_config(
            Arc::clone(&classical_provider),
            &[&rustls::version::TLS13, &rustls::version::TLS12],
            Arc::clone(&resolver),
            tcp_alpn.clone(),
            global_client_roots.as_ref(),
        )?;

        let mut site_mtls_overrides = HashMap::new();
        if let Some(cfg) = config {
            for site in &cfg.sites {
                if site.quarantine.is_some() {
                    continue;
                }
                if let Some(site_ca) = site.tls.as_ref().and_then(|t| t.client_ca.as_deref()) {
                    // A tenant site's client CA that cannot be loaded is skipped here; the router
                    // cannot load it either and answers 503 for that site, so no request reaches
                    // its content without the client-certificate check.
                    let site_roots = match load_single_client_ca_roots(site_ca) {
                        Ok(roots) => roots,
                        Err(err) if site.owner_dir.is_some() => {
                            tracing::warn!(
                                site = %site.hosts.first().map_or("<site>", String::as_str),
                                error = %err,
                                "tenant site client CA cannot be loaded; skipped"
                            );
                            continue;
                        }
                        Err(err) => return Err(err),
                    };
                    let variants = SiteTlsVariants {
                        tls13_pqc: Arc::new(build_single_server_config(
                            Arc::clone(&pqc_provider),
                            &[&rustls::version::TLS13],
                            Arc::clone(&resolver),
                            tcp_alpn.clone(),
                            Some(&site_roots),
                        )?),
                        tls13_classical: Arc::new(build_single_server_config(
                            Arc::clone(&classical_provider),
                            &[&rustls::version::TLS13],
                            Arc::clone(&resolver),
                            tcp_alpn.clone(),
                            Some(&site_roots),
                        )?),
                        tls12_pqc: Arc::new(build_single_server_config(
                            Arc::clone(&pqc_provider),
                            &[&rustls::version::TLS13, &rustls::version::TLS12],
                            Arc::clone(&resolver),
                            tcp_alpn.clone(),
                            Some(&site_roots),
                        )?),
                        tls12_classical: Arc::new(build_single_server_config(
                            Arc::clone(&classical_provider),
                            &[&rustls::version::TLS13, &rustls::version::TLS12],
                            Arc::clone(&resolver),
                            tcp_alpn.clone(),
                            Some(&site_roots),
                        )?),
                    };
                    for host in &site.hosts {
                        site_mtls_overrides.insert(host.to_ascii_lowercase(), variants.clone());
                    }
                }
            }
        }

        // Dedicated RFC 8737 ACME TLS-ALPN-01 config using isolated AcmeAlpnCertResolver
        // so QUIC/H3 and application TCP sessions NEVER serve ephemeral challenge certs.
        let acme_resolver: Arc<dyn rustls::server::ResolvesServerCert> =
            Arc::new(AcmeAlpnCertResolver::new(resolver.acme_store()));
        let acme_alpn = build_single_server_config_with_resolver(
            Arc::clone(&pqc_provider),
            &[&rustls::version::TLS13],
            acme_resolver,
            vec![ACME_TLS_ALPN_PROTOCOL.to_vec()],
            None,
        )?;
        // QUIC/H3 configures a single `ServerConfig` per UDP socket before SNI inspection;
        // accept union CAs for handshake transport ONLY, while `CompiledSite::verify_mtls_peer`
        // cryptographically verifies the presented peer chain strictly against the routed site's
        // own `ClientCertTrust` on every request!
        let quic_client_roots = config
            .map(load_union_client_ca_roots)
            .transpose()?
            .flatten();
        // TLS-1: Respect global `pqc-hybrid` configuration for QUIC / HTTP/3 as well.
        let quic_pqc = config.is_none_or(|c| c.server.tls.pqc_hybrid);
        let quic_provider = if quic_pqc {
            pqc_provider
        } else {
            classical_provider
        };
        let mut quic_h3_cfg = build_single_server_config(
            quic_provider,
            &[&rustls::version::TLS13],
            Arc::clone(&resolver),
            vec![b"h3".to_vec()],
            quic_client_roots.as_ref(),
        )?;
        // QUIC requires early-data disabled by default unless explicitly opted in.
        quic_h3_cfg.max_early_data_size = 0;

        Ok(Self {
            tls13_pqc: Arc::new(tls13_pqc),
            tls13_classical: Arc::new(tls13_classical),
            tls12_pqc: Arc::new(tls12_pqc),
            tls12_classical: Arc::new(tls12_classical),
            acme_alpn: Arc::new(acme_alpn),
            quic_h3: Arc::new(quic_h3_cfg),
            resolver,
            site_mtls_overrides,
        })
    }

    /// Selects the exact [`ServerConfig`] for a `ClientHello`'s SNI and ALPN list using
    /// the current active MiraServe [`Config`], preserving per-site `client-ca` isolation.
    #[must_use]
    pub fn select_for_handshake(
        &self,
        config: &Config,
        sni: Option<&str>,
        client_alpns: &[&[u8]],
    ) -> Arc<ServerConfig> {
        // RFC 8737 §3: ACME TLS-ALPN-01 applies ONLY when `acme-tls/1` is the SOLE ALPN offered.
        if client_alpns.len() == 1
            && client_alpns.first() == Some(&ACME_TLS_ALPN_PROTOCOL)
            && let Some(domain) = sni
            && self.resolver.acme_store().has_alpn_challenge(domain)
        {
            return Arc::clone(&self.acme_alpn);
        }

        let mut allow_tls12 = config.server.tls.min_version == TlsVersion::V1_2;
        let mut pqc = config.server.tls.pqc_hybrid;

        if let Some(host) = sni
            && let Some(site) = find_site_for_host(config, host)
            && let Some(site_tls) = &site.tls
        {
            if site_tls.compat_tls_1_2 {
                allow_tls12 = true;
            }
            if let Some(override_pqc) = site_tls.pqc_hybrid {
                pqc = override_pqc;
            }
        }

        // If this SNI site declares its own `site.tls.client-ca`, select its isolated ServerConfig!
        if let Some(host) = sni {
            let lower = host.to_ascii_lowercase();
            let site_variants = self.site_mtls_overrides.get(&lower).or_else(|| {
                lower
                    .split_once('.')
                    .and_then(|(_, suffix)| self.site_mtls_overrides.get(&format!("*.{suffix}")))
            });
            if let Some(v) = site_variants {
                return match (allow_tls12, pqc) {
                    (false, true) => Arc::clone(&v.tls13_pqc),
                    (false, false) => Arc::clone(&v.tls13_classical),
                    (true, true) => Arc::clone(&v.tls12_pqc),
                    (true, false) => Arc::clone(&v.tls12_classical),
                };
            }
        }

        match (allow_tls12, pqc) {
            (false, true) => Arc::clone(&self.tls13_pqc),
            (false, false) => Arc::clone(&self.tls13_classical),
            (true, true) => Arc::clone(&self.tls12_pqc),
            (true, false) => Arc::clone(&self.tls12_classical),
        }
    }
}

/// Populates a [`DynamicCertResolver`] from configured PEM cert/key files and/or
/// generates a self-signed development certificate when `dev_tls` is enabled.
///
/// Returns the generated dev certificate PEM when `dev_tls` generated a fallback cert
/// (useful for tests and local tooling).
///
/// # Errors
/// Returns [`TlsError`] if any configured PEM file fails to load or if no certificates
/// are available (and ACME is not configured).
pub fn populate_resolver_from_config(
    resolver: &DynamicCertResolver,
    config: &Config,
    dev_tls: bool,
) -> Result<Option<GeneratedCertPem>, TlsError> {
    populate_resolver_from_config_with_keyd_secret(resolver, config, dev_tls, None)
}

/// Populates a [`DynamicCertResolver`] from configured PEM cert/key files, an isolated
/// `miraserve-keyd` daemon (with optional explicit 32-byte HMAC-SHA256 IPC auth secret),
/// or a self-signed development certificate when `dev_tls` is enabled.
///
/// # Errors
/// Returns [`TlsError`] if any configured PEM file or `keyd` IPC load fails, or if no
/// certificates are available (and ACME is not configured).
pub fn populate_resolver_from_config_with_keyd_secret(
    resolver: &DynamicCertResolver,
    config: &Config,
    dev_tls: bool,
    keyd_auth_secret: Option<[u8; 32]>,
) -> Result<Option<GeneratedCertPem>, TlsError> {
    // Split-privilege mode (Threat Model T2): worker never reads private keys from disk;
    // all signing is delegated to the isolated `miraserve-keyd` daemon over IPC.
    if config.server.tls.key_isolation == KeyIsolation::SplitDaemon {
        let socket_spec = config.server.tls.keyd_socket.as_deref().ok_or_else(|| {
            TlsError::KeyLoad(
                "key-isolation \"split-daemon\" requires 'keyd-socket' to be configured".to_owned(),
            )
        })?;
        let endpoint = KeydEndpoint::parse(socket_spec)?;
        let client = match keyd_auth_secret {
            Some(secret) => KeydClient::with_auth_secret(endpoint, secret),
            None => KeydClient::from_env(endpoint)?,
        };
        let _loaded = client.populate_resolver(resolver)?;
        return Ok(None);
    }

    let provider = build_crypto_provider(config.server.tls.pqc_hybrid);
    let mut host_certs = Vec::new();
    let mut default_cert = None;
    let mut generated_dev = None;

    if let (Some(cert_path), Some(key_path)) = (&config.server.tls.cert, &config.server.tls.key) {
        let loaded = load_certified_key_from_files(cert_path, key_path, &provider)?;
        default_cert = Some(loaded);
    }

    let mut tenant_wildcard_site: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for (site_index, site) in config.sites.iter().enumerate() {
        let tenant = site.owner_dir.is_some();
        // A tenant site's certificate serves that site's own hosts only, never as the shared
        // fallback for other hosts, so neither its quarantine nor its failure can take another
        // site's certificate away. A quarantined tenant site's pair is not loaded at all.
        if tenant && site.quarantine.is_some() {
            continue;
        }
        if let Some(site_tls) = &site.tls
            && let (Some(cert_path), Some(key_path)) = (&site_tls.cert, &site_tls.key)
        {
            let site_label = site.hosts.first().map_or("<site>", String::as_str);
            let loaded = match load_certified_key_from_files(cert_path, key_path, &provider) {
                Ok(loaded) => loaded,
                // A tenant site's certificate that cannot be loaded affects that site only
                // (its hosts get the default certificate; the router answers 503 for a site it
                // cannot load). Other sites' certificates keep failing the configuration.
                Err(err) if site.owner_dir.is_some() => {
                    tracing::warn!(
                        site = %site_label,
                        error = %err,
                        "tenant site certificate cannot be loaded; skipped"
                    );
                    continue;
                }
                Err(err) => {
                    return Err(TlsError::KeyLoad(format!(
                        "site '{site_label}' tls ('{cert_path}', '{key_path}'): {err}"
                    )));
                }
            };
            for host in &site.hosts {
                host_certs.push((host.clone(), Arc::clone(&loaded)));
                if tenant && let Some(suffix) = host.to_ascii_lowercase().strip_prefix("*.") {
                    tenant_wildcard_site.insert(suffix.to_owned(), site_index);
                }
            }
            if default_cert.is_none() && !tenant {
                default_cert = Some(loaded);
            }
        }
    }

    if default_cert.is_none() && dev_tls {
        let all_hosts: Vec<String> = config
            .sites
            .iter()
            .flat_map(|s| s.hosts.iter().cloned())
            .collect();
        let (cert, pem) = generate_dev_certificate(&all_hosts, &provider)?;
        default_cert = Some(cert);
        generated_dev = Some(pem);
    }

    // Decided from the configuration, not from which tenant pairs loaded: when tenant sites
    // declare certificates, an unusable or quarantined tenant pair takes only that site's hosts
    // offline (no other host ever used it), and the rest of the configuration still activates.
    let tenant_pair_declared = config.sites.iter().any(|site| {
        site.owner_dir.is_some()
            && site
                .tls
                .as_ref()
                .is_some_and(|tls| tls.cert.is_some() && tls.key.is_some())
    });
    if default_cert.is_none()
        && host_certs.is_empty()
        && config.server.tls.acme.is_none()
        && !tenant_pair_declared
    {
        return Err(TlsError::NoCertificates);
    }

    // Which site owns each exact name (the site HTTP routes it to: the first one listing it).
    let mut host_site: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (index, site) in config.sites.iter().enumerate() {
        for host in site.hosts.iter().filter(|h| !h.starts_with("*.")) {
            host_site.entry(host.to_ascii_lowercase()).or_insert(index);
        }
    }
    resolver.replace_all_with_owners(host_certs, default_cert, tenant_wildcard_site, host_site);
    Ok(generated_dev)
}

/// Builds a `rustls` [`ClientConfig`] for upstream HTTPS reverse-proxy, MCP gateway, and OTLP
/// connections enforcing TLS 1.3 + `X25519MLKEM768` PQC by default (Threat Model T3), with
/// bounded PEM reads for custom CA bundles and upstream mutual TLS (mTLS).
///
/// # Errors
/// Returns [`TlsError`] if custom CA/client PEM files fail to parse or load.
pub fn build_upstream_client_config(
    upstream_tls: Option<&UpstreamTlsConfig>,
) -> Result<ClientConfig, TlsError> {
    let provider = build_crypto_provider(true);
    let mut roots = RootCertStore::empty();

    if let Some(ca_path) = upstream_tls.and_then(|u| u.ca_cert.as_deref()) {
        let raw = cert::read_bounded_file(std::path::Path::new(ca_path))?;
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&raw)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| TlsError::PemParse(format!("upstream CA PEM error: {err}")))?;
        let (added, _ignored) = roots.add_parsable_certificates(certs);
        if added == 0 {
            return Err(TlsError::PemParse(format!(
                "upstream CA bundle '{ca_path}' contained no valid certificates"
            )));
        }
    } else {
        let native = rustls_native_certs::load_native_certs();
        let (_added, _ignored) = roots.add_parsable_certificates(native.certs);
    }

    // Threat Model T3: Enforce TLS 1.3 + X25519MLKEM768 PQC on outbound connections.
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| TlsError::Rustls(err.to_string()))?
        .with_root_certificates(roots);

    let client_cfg = match upstream_tls
        .and_then(|u| u.client_cert.as_deref().zip(u.client_key.as_deref()))
    {
        Some((cert_path, key_path)) => {
            let cert_raw = cert::read_bounded_file(std::path::Path::new(cert_path))?;
            let key_raw = Zeroizing::new(cert::read_bounded_file(std::path::Path::new(key_path))?);
            let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_raw)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|err| TlsError::PemParse(format!("client cert PEM error: {err}")))?;
            let key = PrivateKeyDer::from_pem_slice(&key_raw)
                .map_err(|err| TlsError::PemParse(format!("client key PEM error: {err}")))?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|err| TlsError::Rustls(err.to_string()))?
        }
        None => builder.with_no_client_auth(),
    };

    Ok(client_cfg)
}

/// Maps standard X.509 subject attribute OIDs to their RFC 4514 canonical short names.
fn x509_oid_short_name(oid: &x509_parser::oid_registry::Oid<'_>) -> String {
    match oid.to_id_string().as_str() {
        "2.5.4.3" => "CN".to_owned(),
        "2.5.4.6" => "C".to_owned(),
        "2.5.4.7" => "L".to_owned(),
        "2.5.4.8" => "ST".to_owned(),
        "2.5.4.9" => "STREET".to_owned(),
        "2.5.4.10" => "O".to_owned(),
        "2.5.4.11" => "OU".to_owned(),
        "0.9.2342.19200300.100.1.1" => "UID".to_owned(),
        "0.9.2342.19200300.100.1.25" => "DC".to_owned(),
        "1.2.840.113549.1.9.1" => "emailAddress".to_owned(),
        other => other.to_owned(),
    }
}

/// Escapes an X.509 RDN attribute value strictly per RFC 4514 §2.4 so embedded commas, equals
/// signs, plus signs, backslashes, or control bytes can NEVER spoof additional RDNs (`R5-PUB-2`).
fn escape_rfc4514_value(val: &str) -> String {
    let mut out = String::with_capacity(val.len());
    let chars: Vec<char> = val.chars().collect();
    for (idx, &ch) in chars.iter().enumerate() {
        let is_first = idx == 0;
        let is_last = idx + 1 == chars.len();
        if ch.is_control() {
            for b in ch.to_string().as_bytes() {
                use std::fmt::Write as _;
                let _ = write!(out, "\\{b:02X}");
            }
        } else if matches!(ch, ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=')
            || (is_first && matches!(ch, ' ' | '#'))
            || (is_last && ch == ' ')
        {
            out.push('\\');
            out.push(ch);
        } else {
            out.push(ch);
        }
    }
    out
}

/// Serializes an X.509 Distinguished Name with strict RFC 4514 escaping (`R5-PUB-2`).
fn format_x509_name_rfc4514(name: &x509_parser::x509::X509Name<'_>) -> String {
    let mut rdns = Vec::new();
    for rdn in name.iter_rdn() {
        let mut avas = Vec::new();
        for ava in rdn.iter() {
            let key = x509_oid_short_name(ava.attr_type());
            let val = if let Ok(s) = ava.as_str() {
                escape_rfc4514_value(s)
            } else {
                // Non-string ASN.1 value: RFC 4514 §2.4 hex encoding `#<hex-DER>`
                let mut hex = String::from("#");
                for b in ava.attr_value().data {
                    use std::fmt::Write as _;
                    let _ = write!(hex, "{b:02X}");
                }
                hex
            };
            avas.push(format!("{key}={val}"));
        }
        if !avas.is_empty() {
            rdns.push(avas.join("+"));
        }
    }
    rdns.join(", ")
}

/// Extracts the verified X.509 Subject DN (RFC 4514 escaped, `R5-PUB-2`) from a TLS-authenticated
/// peer leaf certificate (never trusting HTTP headers; returns `None` when no client certificate
/// was verified, `PUB-2`).
#[must_use]
pub fn extract_verified_client_cert_dn(
    peer_certs: Option<&[CertificateDer<'_>]>,
) -> Option<String> {
    let leaf = peer_certs?.first()?;
    let (_, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref()).ok()?;
    let subject = format_x509_name_rfc4514(parsed.subject());
    if subject.trim().is_empty() {
        None
    } else {
        Some(subject)
    }
}

/// Extracts the raw DER peer certificate chain from a TLS connection (`[leaf, intermediates...]`)
/// so the HTTP router can cryptographically verify the peer against the routed site's own `client-ca`.
#[must_use]
pub fn extract_peer_cert_chain_der(
    peer_certs: Option<&[CertificateDer<'_>]>,
) -> Option<Arc<[Vec<u8>]>> {
    let certs = peer_certs?;
    if certs.is_empty() {
        return None;
    }
    let vec: Vec<Vec<u8>> = certs.iter().map(|c| c.as_ref().to_vec()).collect();
    Some(Arc::from(vec))
}

/// Extracts the raw DER peer certificate chain from a type-erased QUIC `quinn::Connection::peer_identity()`.
#[must_use]
pub fn extract_peer_cert_chain_der_any(
    peer_identity: Option<Box<dyn std::any::Any>>,
) -> Option<Arc<[Vec<u8>]>> {
    let certs = peer_identity?
        .downcast::<Vec<CertificateDer<'static>>>()
        .ok()?;
    extract_peer_cert_chain_der(Some(certs.as_slice()))
}

/// Extracts the verified X.509 Subject DN from a DER certificate chain's leaf certificate.
#[must_use]
pub fn extract_verified_client_cert_dn_from_der(chain: &[Vec<u8>]) -> Option<String> {
    let leaf = chain.first()?;
    extract_verified_client_cert_dn(Some(&[CertificateDer::from(leaf.as_slice())]))
}

/// Extracts the verified X.509 Subject DN from a type-erased QUIC `quinn::Connection::peer_identity()`
/// (`Box<dyn Any>` holding `Vec<CertificateDer<'static>>`, `PUB-2`).
#[must_use]
pub fn extract_verified_client_cert_dn_any(
    peer_identity: Option<Box<dyn std::any::Any>>,
) -> Option<String> {
    let certs = peer_identity?
        .downcast::<Vec<CertificateDer<'static>>>()
        .ok()?;
    extract_verified_client_cert_dn(Some(certs.as_slice()))
}

fn load_single_client_ca_roots(path: &str) -> Result<Arc<RootCertStore>, TlsError> {
    let raw = cert::read_bounded_file(std::path::Path::new(path))?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&raw)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| TlsError::PemParse(format!("client CA PEM '{path}' error: {err}")))?;
    let mut roots = RootCertStore::empty();
    let (added, _ignored) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(TlsError::PemParse(format!(
            "client CA bundle '{path}' contained no valid X.509 certificates"
        )));
    }
    Ok(Arc::new(roots))
}

fn load_union_client_ca_roots(config: &Config) -> Result<Option<Arc<RootCertStore>>, TlsError> {
    let mut ca_paths: Vec<&str> = Vec::new();
    if let Some(ca) = config.server.tls.client_ca.as_deref() {
        ca_paths.push(ca);
    }
    for site in &config.sites {
        // Quarantined sites and tenant sites contribute no roots to the shared union: a tenant
        // CA must not widen (or, when unreadable, break) trust for other sites; tenant sites
        // use their own per-site override.
        if site.quarantine.is_some() || site.owner_dir.is_some() {
            continue;
        }
        if let Some(ca) = site.tls.as_ref().and_then(|t| t.client_ca.as_deref())
            && !ca_paths.contains(&ca)
        {
            ca_paths.push(ca);
        }
    }
    if ca_paths.is_empty() {
        return Ok(None);
    }

    let mut roots = RootCertStore::empty();
    let mut total_added = 0_usize;
    for path in ca_paths {
        let raw = cert::read_bounded_file(std::path::Path::new(path))?;
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&raw)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| TlsError::PemParse(format!("client CA PEM '{path}' error: {err}")))?;
        let (added, _ignored) = roots.add_parsable_certificates(certs);
        if added == 0 {
            return Err(TlsError::PemParse(format!(
                "client CA bundle '{path}' contained no valid X.509 certificates"
            )));
        }
        total_added = total_added.saturating_add(added);
    }
    if total_added == 0 {
        return Ok(None);
    }
    Ok(Some(Arc::new(roots)))
}

fn build_single_server_config(
    provider: Arc<CryptoProvider>,
    versions: &[&'static rustls::SupportedProtocolVersion],
    resolver: Arc<DynamicCertResolver>,
    alpn_protocols: Vec<Vec<u8>>,
    client_roots: Option<&Arc<RootCertStore>>,
) -> Result<ServerConfig, TlsError> {
    build_single_server_config_with_resolver(
        provider,
        versions,
        resolver,
        alpn_protocols,
        client_roots,
    )
}

fn build_single_server_config_with_resolver(
    provider: Arc<CryptoProvider>,
    versions: &[&'static rustls::SupportedProtocolVersion],
    resolver: Arc<dyn rustls::server::ResolvesServerCert>,
    alpn_protocols: Vec<Vec<u8>>,
    client_roots: Option<&Arc<RootCertStore>>,
) -> Result<ServerConfig, TlsError> {
    let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(versions)
        .map_err(|err| TlsError::Rustls(err.to_string()))?;

    let mut cfg = if let Some(roots) = client_roots {
        // Optional client authentication with strict WebPKI CA verification:
        // public routes work without client certs while mTLS routes verify TLS peer identity!
        let verifier = WebPkiClientVerifier::builder_with_provider(Arc::clone(roots), provider)
            .allow_unauthenticated()
            .build()
            .map_err(|err| TlsError::Rustls(format!("failed to build mTLS verifier: {err}")))?;
        builder
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(resolver)
    } else {
        builder.with_no_client_auth().with_cert_resolver(resolver)
    };
    cfg.alpn_protocols = alpn_protocols;
    Ok(cfg)
}

fn find_site_for_host<'a>(
    config: &'a Config,
    host: &str,
) -> Option<&'a miraserve_config::SiteConfig> {
    let lower = host.to_ascii_lowercase();
    if let Some(exact) = config
        .sites
        .iter()
        .find(|s| s.hosts.iter().any(|h| h.eq_ignore_ascii_case(&lower)))
    {
        return Some(exact);
    }
    if let Some((_, suffix)) = lower.split_once('.') {
        let wildcard = format!("*.{suffix}");
        return config
            .sites
            .iter()
            .find(|s| s.hosts.iter().any(|h| h.eq_ignore_ascii_case(&wildcard)));
    }
    None
}

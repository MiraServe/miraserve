#![forbid(unsafe_code)]
//! Automated configuration importers converting **Nginx**, **Caddy**, **Apache**, and
//! **OpenLiteSpeed** configurations into validated MiraServe KDL v2.

mod apache;
mod caddy;
mod includes;
mod ir;
mod nginx;
mod openlitespeed;

use std::fs;
use std::path::{Path, PathBuf};

use thiserror::Error;

pub use ir::{MigrationNote, MigrationReport, SourceFormat};

/// Maximum legacy config file size accepted by `miraserve import` (10 MiB).
pub const MAX_IMPORT_FILE_BYTES: u64 = 10 * 1024 * 1024;

/// Errors produced during legacy configuration import.
#[derive(Debug, Error)]
pub enum MigrateError {
    /// Failed to read the legacy config file from disk.
    #[error("failed to read '{path}': {source}")]
    Io {
        /// File path that failed to read.
        path: PathBuf,
        /// Underlying OS I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Input file exceeded [`MAX_IMPORT_FILE_BYTES`].
    #[error("input file '{path}' exceeds safety size limit of {MAX_IMPORT_FILE_BYTES} bytes")]
    FileTooLarge {
        /// Oversized input path.
        path: PathBuf,
    },
    /// All candidate routes/sites were withheld because untranslatable security directives
    /// (authentication, ACLs, rate limits, mTLS) were present (`MIG-2`, `MIG-3`).
    #[error(
        "refused to emit open routes: all sites/routes in {format} config had untranslatable security controls ({} issue(s))",
        downgrades.len()
    )]
    AllRoutesBlockedBySecurity {
        /// Format used for parsing.
        format: SourceFormat,
        /// Exact security directives that caused routes to be withheld.
        downgrades: Vec<MigrationNote>,
    },
    /// No sites or routes could be recognized from the input.
    #[error("no migratable sites or routes found in {format} input")]
    EmptyMigration {
        /// Format used for parsing.
        format: SourceFormat,
    },
    /// Internal safety check: generated KDL failed `miraserve-config` validation.
    #[error("generated KDL failed validation: {0}")]
    ValidationFailed(String),
}

/// Heuristically detects the legacy server configuration format from its contents (`MIG-7`).
#[must_use]
pub fn detect_format(input: &str) -> SourceFormat {
    let input = input.strip_prefix('\u{FEFF}').unwrap_or(input);
    let lower = input.to_ascii_lowercase();
    if lower.contains("<virtualhost")
        || lower.contains("documentroot")
        || lower.contains("proxypass ")
    {
        return SourceFormat::Apache;
    }
    if lower.contains("vhdomain")
        || lower.contains("extprocessor")
        || lower.contains("docroot")
        || lower.contains("vhssl")
        || lower.contains("vhroot")
        || lower.contains("virtualhost ")
    {
        return SourceFormat::OpenLiteSpeed;
    }
    // Check Nginx-exclusive directives first (`;`-terminated statements).
    if lower.contains("server_name")
        || lower.contains("proxy_pass")
        || lower.contains("fastcgi_pass")
    {
        return SourceFormat::Nginx;
    }
    // Check Caddy-distinctive directives BEFORE generic `try_files` (Caddyfiles also use `try_files`!).
    if lower.contains("reverse_proxy")
        || lower.contains("php_fastcgi")
        || lower.contains("file_server")
        || lower.contains("handle_path")
        || lower.contains("basicauth")
        || lower.contains("basic_auth")
    {
        return SourceFormat::Caddy;
    }
    if lower.contains("try_files") {
        if input.contains(';') {
            return SourceFormat::Nginx;
        }
        return SourceFormat::Caddy;
    }
    SourceFormat::Nginx
}

/// Options controlling [`migrate_str_with_options`] and [`migrate_file_with_options`] (`R3-MIG-3`,
/// `R7-MIG-13`).
#[derive(Debug, Clone, Default)]
pub struct MigrateOptions {
    /// When `true`, globally security-blocked sites are still rendered into `report.kdl`
    /// (with `report.security_downgrades` populated) rather than returning
    /// [`MigrateError::AllRoutesBlockedBySecurity`]. Default is `false` (fail-closed).
    pub allow_insecure: bool,
    /// Optional local directory root containing a copied/uploaded server config tree (`R7-MIG-13`),
    /// used to remap absolute `include` paths (such as `/etc/nginx/conf.d/*.conf`) strictly inside
    /// the confined root.
    pub source_root: Option<PathBuf>,
}

/// Imports a legacy configuration string into validated MiraServe KDL v2 (fail-closed default).
///
/// Security-sensitive routes protected by untranslatable authentication, ACL, or rate-limit
/// directives are omitted from `report.kdl` and recorded in `report.security_downgrades`
/// so migrated configs never silently widen access (`MIG-2`, `MIG-3`).
///
/// # Errors
/// Returns [`MigrateError`] if no safe sites remain or generated KDL fails validation.
pub fn migrate_str(input: &str, format: SourceFormat) -> Result<MigrationReport, MigrateError> {
    migrate_str_with_options(input, format, MigrateOptions::default())
}

/// Imports a legacy configuration string with explicit [`MigrateOptions`] (`R3-MIG-3`).
///
/// # Errors
/// Returns [`MigrateError`] if no sites remain or generated KDL fails validation.
#[allow(clippy::needless_pass_by_value)]
pub fn migrate_str_with_options(
    input: &str,
    format: SourceFormat,
    options: MigrateOptions,
) -> Result<MigrationReport, MigrateError> {
    migrate_str_internal(input, format, &options, None)
}

#[allow(clippy::too_many_lines)]
fn migrate_str_internal(
    input: &str,
    format: SourceFormat,
    options: &MigrateOptions,
    source_path: Option<&Path>,
) -> Result<MigrationReport, MigrateError> {
    // R5-MIG-8: Strip UTF-8 BOM if present so BOM-prefixed Nginx/Apache/Caddy/OLS files parse cleanly.
    let input = input.strip_prefix('\u{FEFF}').unwrap_or(input);
    let resolved_format = match format {
        SourceFormat::Auto => detect_format(input),
        explicit => explicit,
    };

    let source_root = options.source_root.as_deref();
    let mut doc = match resolved_format {
        SourceFormat::Nginx | SourceFormat::Auto => {
            nginx::parse_nginx_raw_with_path(input, source_path, source_root)
        }
        SourceFormat::Caddy => caddy::parse_caddy_raw(input),
        SourceFormat::Apache => apache::parse_apache_raw_with_path(input, source_path, source_root),
        SourceFormat::OpenLiteSpeed => {
            openlitespeed::parse_openlitespeed_raw_with_path(input, source_path, source_root)
        }
    };
    if let Some(fatal) = doc.fatal_error.take() {
        return Err(MigrateError::ValidationFailed(fatal));
    }
    ir::finalize_doc_with_options(&mut doc, options.allow_insecure);

    if doc.sites.is_empty() {
        if !doc.security_downgrades.is_empty() {
            return Err(MigrateError::AllRoutesBlockedBySecurity {
                format: resolved_format,
                downgrades: doc.security_downgrades,
            });
        }
        return Err(MigrateError::EmptyMigration {
            format: resolved_format,
        });
    }

    let migrated_sites = doc.sites.len();
    let migrated_routes: usize = doc.sites.iter().map(|s| s.routes.len()).sum();
    let insecure_sites_emitted: Vec<String> = doc
        .sites
        .iter()
        .filter(|s| s.emitted_insecure)
        .map(|s| s.hosts.join(", "))
        .collect();
    let kdl = ir::render_kdl(&doc, resolved_format, options.allow_insecure);

    // Self-verify every generated KDL output against miraserve-config and verify rendered site /
    // route structure matches `MigratedDoc` 1-to-1 so KDL injection is impossible (`R5-MIG-7`, `R6-MIG-1`).
    let (cfg, validation_report) =
        miraserve_config::parse_kdl("migrated.kdl", &kdl).map_err(|err| {
            let details: Vec<String> = err
                .validation_errors()
                .iter()
                .map(|issue| {
                    if let Some(help) = &issue.help {
                        format!("[{}] {} (help: {})", issue.code, issue.message, help)
                    } else {
                        format!("[{}] {}", issue.code, issue.message)
                    }
                })
                .collect();
            if details.is_empty() {
                MigrateError::ValidationFailed(err.to_string())
            } else {
                MigrateError::ValidationFailed(format!("{err}: {}", details.join("; ")))
            }
        })?;

    let parsed_routes: usize = cfg.sites.iter().map(|s| s.routes.len()).sum();
    if cfg.sites.len() != migrated_sites || parsed_routes != migrated_routes {
        return Err(MigrateError::ValidationFailed(format!(
            "generated KDL structure mismatch (expected {migrated_sites} site(s) and {migrated_routes} route(s), parsed {} site(s) and {parsed_routes} route(s))",
            cfg.sites.len()
        )));
    }
    for (expected_site, parsed_site) in doc.sites.iter().zip(cfg.sites.iter()) {
        if expected_site.hosts != parsed_site.hosts {
            return Err(MigrateError::ValidationFailed(format!(
                "generated KDL site host mismatch (expected {:?}, parsed {:?})",
                expected_site.hosts, parsed_site.hosts
            )));
        }
        if expected_site.root != parsed_site.root {
            return Err(MigrateError::ValidationFailed(format!(
                "generated KDL site root mismatch (expected {:?}, parsed {:?})",
                expected_site.root, parsed_site.root
            )));
        }
        if expected_site.routes.len() != parsed_site.routes.len() {
            return Err(MigrateError::ValidationFailed(format!(
                "generated KDL route count mismatch for site {:?} (expected {}, parsed {})",
                expected_site.hosts,
                expected_site.routes.len(),
                parsed_site.routes.len()
            )));
        }
        for (exp_route, got_route) in expected_site.routes.iter().zip(parsed_site.routes.iter()) {
            if exp_route.pattern != got_route.pattern {
                return Err(MigrateError::ValidationFailed(format!(
                    "generated KDL route pattern mismatch (expected '{}', parsed '{}')",
                    exp_route.pattern, got_route.pattern
                )));
            }
            let handler_matches = match (&exp_route.handler, &got_route.handler) {
                (
                    ir::MigratedHandler::ReverseProxy {
                        upstreams,
                        preserve_host,
                        allow_upgrades,
                    },
                    miraserve_config::RouteHandler::ReverseProxy(rp),
                ) => {
                    let got_ups: Vec<&str> = rp.upstreams.iter().map(|u| u.url.as_str()).collect();
                    let exp_ups: Vec<&str> = upstreams.iter().map(String::as_str).collect();
                    got_ups == exp_ups
                        && rp.preserve_host == *preserve_host
                        && rp.allow_upgrades == *allow_upgrades
                }
                (
                    ir::MigratedHandler::FastCgi { target },
                    miraserve_config::RouteHandler::FastCgi(fcgi),
                ) => match &fcgi.target {
                    miraserve_config::FastCgiTarget::Unix { path } => {
                        target.strip_prefix("unix:") == Some(path.as_str())
                    }
                    miraserve_config::FastCgiTarget::Tcp { host, port } => {
                        let expected_addr = if host.contains(':') {
                            format!("[{host}]:{port}")
                        } else {
                            format!("{host}:{port}")
                        };
                        target.strip_prefix("tcp://") == Some(expected_addr.as_str())
                    }
                },
                (
                    ir::MigratedHandler::TryFiles { candidates },
                    miraserve_config::RouteHandler::TryFiles(got_tf),
                ) => candidates == &got_tf.candidates && !got_tf.fallback_unless_extension,
                (ir::MigratedHandler::Static, miraserve_config::RouteHandler::Static(_)) => true,
                _ => false,
            };
            if !handler_matches {
                return Err(MigrateError::ValidationFailed(format!(
                    "generated KDL route handler mismatch for pattern '{}'",
                    exp_route.pattern
                )));
            }
        }
    }

    let validation_warnings = validation_report
        .warnings
        .into_iter()
        .map(|w| w.to_string())
        .collect();

    Ok(MigrationReport {
        source_format: resolved_format,
        kdl,
        migrated_sites,
        migrated_routes,
        security_upgrades: doc.security_upgrades,
        security_downgrades: doc.security_downgrades,
        insecure_sites_emitted,
        notes: doc.notes,
        validation_warnings,
    })
}

/// Reads a legacy configuration file from disk and converts it into validated MiraServe KDL v2.
///
/// Rejects non-regular files (such as FIFOs/sockets/devices) and enforces [`MAX_IMPORT_FILE_BYTES`].
///
/// # Errors
/// Returns [`MigrateError`] on I/O failure, size cap violation, or parse/validation failure.
pub fn migrate_file(
    path: impl AsRef<Path>,
    format: SourceFormat,
) -> Result<MigrationReport, MigrateError> {
    migrate_file_with_options(path, format, MigrateOptions::default())
}

/// Reads a legacy configuration file from disk and converts it with explicit [`MigrateOptions`].
///
/// # Errors
/// Returns [`MigrateError`] on I/O failure, size cap violation, or parse/validation failure.
#[allow(clippy::needless_pass_by_value)]
pub fn migrate_file_with_options(
    path: impl AsRef<Path>,
    format: SourceFormat,
    options: MigrateOptions,
) -> Result<MigrationReport, MigrateError> {
    use std::io::Read as _;

    let path_ref = path.as_ref();
    // R7-MIG-15: Canonicalize first (allowing legitimate Debian `sites-enabled/*` symlinks),
    // then open the canonical target with `O_NOFOLLOW | O_NONBLOCK` + `fstat` so a raced FIFO
    // or symlink swap can neither block nor bypass regular-file enforcement!
    let canon_path = fs::canonicalize(path_ref).map_err(|source| MigrateError::Io {
        path: path_ref.to_path_buf(),
        source,
    })?;
    let file =
        includes::open_regular_file_safe(&canon_path).map_err(|source| MigrateError::Io {
            path: path_ref.to_path_buf(),
            source,
        })?;
    let meta = file.metadata().map_err(|source| MigrateError::Io {
        path: path_ref.to_path_buf(),
        source,
    })?;
    if meta.len() > MAX_IMPORT_FILE_BYTES {
        return Err(MigrateError::FileTooLarge {
            path: path_ref.to_path_buf(),
        });
    }
    let mut raw = Vec::new();
    file.take(MAX_IMPORT_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut raw)
        .map_err(|source| MigrateError::Io {
            path: path_ref.to_path_buf(),
            source,
        })?;
    if (raw.len() as u64) > MAX_IMPORT_FILE_BYTES {
        return Err(MigrateError::FileTooLarge {
            path: path_ref.to_path_buf(),
        });
    }
    let content = String::from_utf8(raw).map_err(|err| MigrateError::Io {
        path: path_ref.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, err),
    })?;
    migrate_str_internal(&content, format, &options, Some(path_ref))
}

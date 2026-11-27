//! Comprehensive schema, security-invariant, and hot-reload tests for `miraserve-config`.

// `assert_is_empty` is new in clippy 1.100 and unknown to 1.95 (the minimum toolchain).
// `assert!(x.is_empty())` says what these tests mean.
#![allow(unknown_lints, clippy::assert_is_empty)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use miraserve_config::{
    AcmeChallenge, AuditLogMode, BindAddr, ByteSize, ConfigError, ConfigStore, HeaderStatusMatcher,
    KeyIsolation, LoadBalancePolicy, PrecompressedPolicy, PreflightCheck, Protocol,
    PublishAuthMode, RateLimitKey, RouteHandler, SeccompMode, SecurityHeadersPolicy,
    SignatureAlgorithm, SiteHttpMode, SitePreset, StreamingFlushMode, TlsVersion,
    UnverifiedBotAction, load_file, parse_duration, parse_kdl, parse_kdl_detailed_with_base_dir,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn example_config_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("examples")
        .join("miraserve.kdl")
}

fn error_codes(err: &ConfigError) -> Vec<String> {
    err.validation_errors()
        .iter()
        .map(|issue| issue.code.clone())
        .collect()
}

/// Formats a filesystem path for interpolation inside a KDL double-quoted string: strips any
/// Windows `\\?\` verbatim prefix and escapes backslashes so Windows paths parse as KDL strings.
fn kdl_path(path: &Path) -> String {
    let raw = path.to_string_lossy();
    let stripped = raw.strip_prefix(r"\\?\").unwrap_or(&raw);
    stripped.replace('\\', "\\\\")
}

#[test]
fn parses_reference_example_miraserve_kdl() -> TestResult {
    let (cfg, report) = load_file(example_config_path())?;

    // Server listeners
    assert_eq!(cfg.server.listeners.len(), 2);
    let https = cfg.server.listeners.first().ok_or("missing listener 0")?;
    assert_eq!(https.addr, BindAddr::parse(":443")?);
    assert_eq!(
        https.protocols,
        vec![Protocol::H3, Protocol::H2, Protocol::H1]
    );
    assert!(!https.redirect_https);

    let http = cfg.server.listeners.get(1).ok_or("missing listener 1")?;
    assert_eq!(http.addr, BindAddr::parse(":80")?);
    assert!(http.redirect_https);
    assert_eq!(http.protocols, vec![Protocol::H1]);

    // Global TLS + ACME
    assert_eq!(cfg.server.tls.min_version, TlsVersion::V1_3);
    assert!(cfg.server.tls.pqc_hybrid);
    assert_eq!(cfg.server.tls.key_isolation, KeyIsolation::InProcess);
    let acme = cfg.server.tls.acme.as_ref().ok_or("missing acme block")?;
    assert_eq!(acme.email, "ops@example.com");
    assert_eq!(acme.challenge, AcmeChallenge::TlsAlpn01);
    assert!(acme.short_lived);
    assert!(acme.ari);

    // Sandbox
    assert_eq!(cfg.server.sandbox.user.as_deref(), Some("miraserve"));
    assert!(cfg.server.sandbox.landlock);
    assert_eq!(cfg.server.sandbox.seccomp, SeccompMode::Strict);

    // Sites
    assert_eq!(cfg.sites.len(), 3);

    // Site 0: future.example.com
    let future = cfg.sites.first().ok_or("missing site 0")?;
    assert_eq!(future.hosts, vec!["future.example.com"]);
    assert_eq!(future.security_headers, SecurityHeadersPolicy::Strict);
    let rl = future.rate_limit.as_ref().ok_or("missing rate_limit")?;
    assert_eq!(rl.requests, 600);
    assert_eq!(rl.per, Duration::from_secs(60));
    assert_eq!(rl.burst, 150);
    assert_eq!(rl.key, RateLimitKey::ClientIp);

    let bot = future.bot_auth.as_ref().ok_or("missing bot_auth")?;
    assert!(bot.verify_rfc9421);
    assert_eq!(bot.on_unverified_ai_ua, UnverifiedBotAction::Throttle);
    let agent = bot.allow_agents.first().ok_or("missing allow_agent")?;
    assert_eq!(agent.name, "verified-ai-agents");
    assert!(agent.serve_markdown);

    let publish = future.ai_publish.as_ref().ok_or("missing ai_publish")?;
    assert_eq!(publish.storage, "/var/lib/miraserve/releases/future");
    assert_eq!(publish.keep_versions, 20);
    let sig = publish
        .require_signature
        .as_ref()
        .ok_or("missing signature")?;
    assert_eq!(sig.algorithm, SignatureAlgorithm::Ed25519);
    assert_eq!(sig.public_key_path, "/etc/miraserve/deploy-agent.pub");
    assert_eq!(
        publish.preflight_checks,
        vec![
            PreflightCheck::NoSecrets,
            PreflightCheck::CspValid,
            PreflightCheck::MaxSize(ByteSize::from_bytes(50 * ByteSize::MB)),
        ]
    );
    let ep = publish
        .mcp_endpoint
        .as_ref()
        .ok_or("missing mcp_endpoint")?;
    assert_eq!(ep.path, "/_miraserve/publish");
    assert_eq!(ep.auth, PublishAuthMode::OAuthJwt);

    // Site 1: legacy-blog.example.com
    let legacy = cfg.sites.get(1).ok_or("missing site 1")?;
    assert_eq!(legacy.hosts, vec!["legacy-blog.example.com"]);
    assert_eq!(legacy.preset, Some(SitePreset::WordpressHardened));
    assert_eq!(legacy.root.as_deref(), Some("/var/www/wordpress"));
    assert_eq!(legacy.routes.len(), 2);

    // Site 2: ai.example.com
    let ai = cfg.sites.get(2).ok_or("missing site 2")?;
    assert_eq!(ai.hosts, vec!["ai.example.com"]);
    let mcp_route = ai.routes.first().ok_or("missing mcp route")?;
    assert_eq!(mcp_route.pattern, "/mcp/*");
    match &mcp_route.handler {
        RouteHandler::McpGateway(mcp) => {
            assert_eq!(mcp.upstream, "https://10.0.1.20:8443");
            assert!(mcp.oauth_resource_metadata);
            assert_eq!(mcp.allow_tools, vec!["docs_search", "catalog_read"]);
            assert_eq!(mcp.deny_tools, vec!["*_delete", "*_exec"]);
            assert_eq!(mcp.audit_log, AuditLogMode::StructuredJson);
        }
        other => return Err(format!("expected McpGateway, got {other:?}").into()),
    }

    let proxy_route = ai.routes.get(1).ok_or("missing proxy route")?;
    assert_eq!(proxy_route.pattern, "/v1/*");
    match &proxy_route.handler {
        RouteHandler::ReverseProxy(rp) => {
            assert_eq!(rp.upstreams.len(), 2);
            assert_eq!(rp.streaming_flush, StreamingFlushMode::Immediate);
            assert_eq!(rp.lb_policy, LoadBalancePolicy::RoundRobin);
            let hc = rp.health_check.as_ref().ok_or("missing health_check")?;
            assert_eq!(hc.path, "/health");
            assert_eq!(hc.interval, Duration::from_secs(5));
        }
        other => return Err(format!("expected ReverseProxy, got {other:?}").into()),
    }

    // Reference example ships strict-clean with zero warnings (`R7-RL-2` + strict example).
    assert!(
        report.warnings.is_empty(),
        "examples/miraserve.kdl should pass --strict with zero warnings, got: {:?}",
        report.warnings
    );

    Ok(())
}

#[test]
fn parses_kdl_v2_hardened_config_with_zero_warnings() -> TestResult {
    let kdl_v2 = r#"
server {
    listen "[::]:443" protocols="h3,h2,h1"
    listen "0.0.0.0:80" redirect-https=#true

    tls {
        min-version "1.3"
        pqc-hybrid #true
        key-isolation "split-daemon"
        keyd-socket "/run/miraserve/keyd.sock"
        cert "/etc/miraserve/certs/server.pem"
        key "/etc/miraserve/keys/server.key"
        client-ca "/etc/miraserve/client-ca.pem"
        ech #false
    }

    sandbox {
        user "miraserve"
        group "miraserve"
        landlock #true
        seccomp "strict"
    }

    timeouts {
        tls-handshake "5s"
        header-read "8s"
        idle-keepalive "45s"
        graceful-drain "20s"
        min-body-rate-bps 2048
    }

    limits {
        max-header-bytes "16KiB"
        max-body-bytes "5MiB"
        max-concurrent-streams 64
        max-h2-rst-stream-per-sec 25
    }
}

site "hardened.example.org" "www.hardened.example.org" {
    preset "static-strict"
    security-headers "strict"
    rate-limit requests=120 per="1m" burst=20 key="header:x-client-token"

    ai-publish {
        storage "/var/lib/miraserve/releases/hardened"
        site-id "hardened-prod"
        keep-versions 15
        require-signature "ed25519:/etc/miraserve/deploy.pub"
        allowed-subjects "CN=deploy-bot"
        preflight-checks "no-secrets" "csp-valid" "no-inline-scripts" "max-size=25MiB" "max-files=2000"
        mcp-endpoint "/_miraserve/publish" auth="mtls"
    }

    route "/local-api/*" {
        reverse-proxy {
            upstream "http://127.0.0.1:8080" weight=2
            streaming-flush "immediate"
            lb-policy "least-conn"
            health-check path="/ready" interval="5s" timeout="2s" unhealthy-threshold=2
        }
    }
}
"#;

    let (cfg, report) = parse_kdl("hardened-v2.kdl", kdl_v2)?;
    assert!(
        report.is_clean(),
        "expected zero warnings, got {:?}",
        report.warnings
    );
    assert_eq!(cfg.server.tls.key_isolation, KeyIsolation::SplitDaemon);
    assert!(!cfg.server.tls.ech);
    assert_eq!(
        cfg.sites
            .first()
            .and_then(|s| s.ai_publish.as_ref())
            .and_then(|p| p.site_id.as_deref()),
        Some("hardened-prod")
    );
    assert_eq!(
        cfg.sites
            .first()
            .and_then(|s| s.ai_publish.as_ref())
            .map(|p| p.allowed_subjects.as_slice()),
        Some(["CN=deploy-bot".to_owned()].as_slice())
    );
    assert_eq!(
        cfg.server.tls.client_ca.as_deref(),
        Some("/etc/miraserve/client-ca.pem")
    );
    assert_eq!(cfg.server.timeouts.tls_handshake, Duration::from_secs(5));
    assert_eq!(
        cfg.server.limits.max_body_bytes,
        ByteSize::from_bytes(5 * ByteSize::MIB)
    );
    let site = cfg.sites.first().ok_or("missing site")?;
    assert_eq!(site.hosts.len(), 2);
    Ok(())
}

#[test]
fn parses_units_durations_and_bind_addrs() -> TestResult {
    // ByteSize
    assert_eq!(ByteSize::parse("512B")?.as_bytes(), 512);
    assert_eq!(ByteSize::parse("50MB")?.as_bytes(), 50_000_000);
    assert_eq!(ByteSize::parse("16KiB")?.as_bytes(), 16_384);
    assert_eq!(ByteSize::parse("2gib")?.as_bytes(), 2 * ByteSize::GIB);
    assert!(ByteSize::parse("").is_err());
    assert!(ByteSize::parse("50XB").is_err());
    assert!(ByteSize::parse("99999999999999999999TB").is_err());

    // Duration
    assert_eq!(parse_duration("500ms")?, Duration::from_millis(500));
    assert_eq!(parse_duration("5s")?, Duration::from_secs(5));
    assert_eq!(parse_duration("1m30s")?, Duration::from_secs(90));
    assert_eq!(parse_duration("2h")?, Duration::from_secs(7_200));
    assert_eq!(parse_duration("1d")?, Duration::from_hours(24));
    assert!(parse_duration("").is_err());
    assert!(parse_duration("10").is_err());
    assert!(parse_duration("5w").is_err());
    assert!(parse_duration("99999999999999999999d").is_err());

    // BindAddr: bare `:443` is dual-stack (conflicts with both IPv4 and IPv6 on 443),
    // while explicit `0.0.0.0:443` and `[::]:443` occupy disjoint address families.
    let wildcard = BindAddr::parse(":443")?;
    let v4_any = BindAddr::parse("0.0.0.0:443")?;
    let v6_any = BindAddr::parse("[::]:443")?;
    let v4_lo = BindAddr::parse("127.0.0.1:443")?;
    let v6_lo = BindAddr::parse("[::1]:443")?;
    assert!(wildcard.conflicts_with(&v4_any));
    assert!(wildcard.conflicts_with(&v6_any));
    assert!(wildcard.conflicts_with(&v4_lo));
    assert!(wildcard.conflicts_with(&v6_lo));
    assert!(!v4_any.conflicts_with(&v6_any));
    assert!(!v4_lo.conflicts_with(&v6_lo));
    assert!(v4_any.conflicts_with(&v4_lo));
    assert!(v6_any.conflicts_with(&v6_lo));
    assert!(BindAddr::parse(":0").is_err());
    assert!(BindAddr::parse("::1:443").is_err());
    assert!(BindAddr::parse("not-an-ip:443").is_err());

    // Protocols
    assert_eq!(
        Protocol::parse_list("h3, h2, h1")?,
        vec![Protocol::H3, Protocol::H2, Protocol::H1]
    );
    assert!(Protocol::parse_list("h3,h3").is_err());
    assert!(Protocol::parse_list("h4").is_err());
    assert!(Protocol::parse_list("").is_err());

    Ok(())
}

#[test]
fn rejects_fail_closed_unknown_directives_and_properties() {
    let bad = r#"
server {
    listen ":443" bogus-prop=true
    mystery-block {
        foo "bar"
    }
}
unknown-root "x"
"#;

    let Err(err) = parse_kdl("bad.kdl", bad) else {
        unreachable!("expected parse_kdl to fail");
    };
    let codes = error_codes(&err);
    assert!(codes.contains(&"E003".to_owned()), "codes: {codes:?}");
    assert!(codes.contains(&"E002".to_owned()), "codes: {codes:?}");
}

#[test]
fn enforces_tls_listener_and_acme_security_rules() {
    let bad = r#"
server {
    listen ":443" protocols="h3,h2"
    listen "0.0.0.0:443" protocols="h2,h1"
    listen ":80" protocols="h3,h1" redirect-https=true

    tls {
        min-version "1.1"
        cert "/etc/miraserve/cert.pem"
        keyd-socket "/run/miraserve/keyd.sock"
        acme {
            email "not-an-email"
            directory "http://insecure-acme.example.com/dir"
        }
    }
}
"#;

    let Err(err) = parse_kdl("bad-tls.kdl", bad) else {
        unreachable!("expected validation error");
    };
    let codes = error_codes(&err);
    assert!(codes.contains(&"E102".to_owned()), "codes: {codes:?}");
    assert!(codes.contains(&"E103".to_owned()), "codes: {codes:?}");
    assert!(codes.contains(&"E104".to_owned()), "codes: {codes:?}");
    assert!(codes.contains(&"E105".to_owned()), "codes: {codes:?}");
    assert!(codes.contains(&"E106".to_owned()), "codes: {codes:?}");
}

#[test]
fn enforces_sandbox_and_cross_platform_path_confinement() {
    let bad = r#"
server {
    listen ":443"
    sandbox {
        user "root"
        group "0"
    }
}

site "posix-escape.example.com" {
    root "/var/www/site/../../etc"
}

site "win-escape.example.com" {
    root "C:\\srv\\..\\Windows"
}

site "etc-root.example.com" {
    root "/etc/nginx"
}

site "drive-root.example.com" {
    root "C:\\"
}
"#;

    let Err(err) = parse_kdl("bad-paths.kdl", bad) else {
        unreachable!("expected validation error");
    };
    let codes = error_codes(&err);
    let e201_count = codes.iter().filter(|c| c.as_str() == "E201").count();
    let e202_count = codes.iter().filter(|c| c.as_str() == "E202").count();
    assert_eq!(e201_count, 2, "expected 2 E201 errors, got {codes:?}");
    assert_eq!(e202_count, 4, "expected 4 E202 errors, got {codes:?}");
}

#[test]
fn enforces_ai_publish_and_mcp_gateway_security_policies() -> TestResult {
    // Hard errors: unauthenticated ai-publish & invalid mcp-endpoint auth
    let bad = r#"
server {
    listen ":443"
}

site "unauth-ai.example.com" {
    ai-publish {
        storage "/var/lib/miraserve/releases/unauth"
        keep-versions 0
        mcp-endpoint "/_publish" auth="none"
    }
}

site "bad-mcp.example.com" {
    route "/mcp/*" {
        mcp-gateway upstream="ftp://10.0.0.1:21" {
            max-json-depth 0
            max-request-bytes "0B"
        }
    }
}
"#;
    let Err(err) = parse_kdl("bad-ai.kdl", bad) else {
        return Err("expected validation failure".into());
    };
    let codes = error_codes(&err);
    assert!(codes.contains(&"E401".to_owned()), "codes: {codes:?}");
    assert!(codes.contains(&"E403".to_owned()), "codes: {codes:?}");

    // Security warnings on weakened AI/MCP/proxy/TLS posture
    let weakened = r#"
server {
    listen ":443"
    tls {
        min-version "1.2"
        pqc-hybrid false
    }
    sandbox {
        landlock false
        seccomp "off"
    }
}

site "warn.example.com" {
    security-headers "off"
    root "/var/www/warn"
    bot-auth {
        verify-rfc9421 false
    }
    ai-publish {
        storage "/var/lib/miraserve/releases/warn"
        require-signature "ed25519:/etc/miraserve/key.pub"
        preflight-checks "csp-valid"
    }
    route "/mcp/*" {
        mcp-gateway upstream="http://10.0.1.20:8080" {
            oauth-resource-metadata false
            allow-tools "*"
            audit-log "off"
        }
    }
    route "/static/*" {
        static {
            dotfiles "allow"
        }
    }
}
"#;
    let (_cfg, report) = parse_kdl("weakened.kdl", weakened)?;
    let warn_codes: Vec<&str> = report.warnings.iter().map(|w| w.code.as_str()).collect();
    for expected in [
        "W001", "W002", "W003", "W004", "W005", "W006", "W008", "W009", "W010",
    ] {
        assert!(
            warn_codes.contains(&expected),
            "expected warning {expected}, got {warn_codes:?}"
        );
    }
    assert!(
        report.warnings.iter().any(|w| {
            w.code == "W003"
                && w.path.as_deref() == Some("server.sandbox.seccomp")
                && w.message.contains("set-ID")
        }),
        "W003 for seccomp off must name the lost in-process set-ID protection: {:?}",
        report.warnings
    );

    Ok(())
}

#[test]
fn enforces_routing_proxy_and_duplicate_host_invariants() {
    let bad = r#"
server {
    listen ":443"
}

site "dup.example.com" {
    route "/*" {
        try-files "{path}"
    }
}

site "DUP.EXAMPLE.COM" {
    route "/mix/*" {
        fastcgi-pass "unix:/run/php.sock"
        reverse-proxy {
            upstream "https://10.0.0.1:8000"
        }
    }
    route "/bad-hc/*" {
        reverse-proxy {
            health-check path="no-slash" interval="5s" timeout="10s"
        }
    }
}
"#;
    let Err(err) = parse_kdl("bad-routes.kdl", bad) else {
        unreachable!("expected validation error");
    };
    let codes = error_codes(&err);
    assert!(codes.contains(&"E107".to_owned()), "codes: {codes:?}");
    assert!(codes.contains(&"E302".to_owned()), "codes: {codes:?}");
    assert!(codes.contains(&"E303".to_owned()), "codes: {codes:?}");
    assert!(codes.contains(&"E305".to_owned()), "codes: {codes:?}");
}

#[test]
fn never_panics_on_hostile_or_malformed_kdl_inputs() {
    let deeply_nested_blocks = format!("{}{}", "a { ".repeat(128), "}".repeat(128));
    let deeply_nested_comments = format!("{}{}", "/* ".repeat(128), "*/ ".repeat(128));
    let corpus = [
        "",
        "   \n\t\r\n  ",
        "{{{{{",
        "server { listen \"unterminated",
        "server { listen 99999999999999999999999999999999999999999999 }",
        "site \"a.example.com\" { root \"/var/www\0evil\" }",
        "/* unterminated comment",
        "\u{feff}server { listen \":443\" }\n\0\0",
        deeply_nested_blocks.as_str(),
        deeply_nested_comments.as_str(),
    ];

    for (idx, sample) in corpus.iter().enumerate() {
        let res = parse_kdl(format!("fuzz-{idx}.kdl"), sample);
        assert!(res.is_err(), "sample {idx} unexpectedly succeeded");
    }
}

#[test]
fn config_store_performs_lock_free_atomic_reload_and_preserves_state_on_error() -> TestResult {
    let v1 = r#"
server {
    listen ":443"
}
site "v1.example.com" {
    root "/var/www/v1"
}
"#;
    let v2 = r#"
server {
    listen ":443"
}
site "v2.example.com" {
    root "/var/www/v2"
}
"#;
    let broken = r#"
server {
    listen ":443"
    tls { min-version "1.0" }
}
"#;

    let (initial, _) = parse_kdl("v1.kdl", v1)?;
    let store = Arc::new(ConfigStore::new(initial));
    assert_eq!(store.generation(), 1);
    assert_eq!(
        store
            .current()
            .sites
            .first()
            .and_then(|s| s.hosts.first())
            .map(String::as_str),
        Some("v1.example.com")
    );

    // Failed reload must not mutate active config or generation.
    assert!(store.reload_from_str("broken.kdl", broken).is_err());
    assert_eq!(store.generation(), 1);
    assert_eq!(
        store
            .snapshot()
            .sites
            .first()
            .and_then(|s| s.hosts.first())
            .map(String::as_str),
        Some("v1.example.com")
    );

    // Concurrent lock-free readers + atomic writer reload test.
    thread::scope(|scope| {
        for _ in 0..4 {
            let reader = Arc::clone(&store);
            scope.spawn(move || {
                for _ in 0..500 {
                    let snap = reader.current();
                    let host = snap
                        .sites
                        .first()
                        .and_then(|s| s.hosts.first())
                        .map(String::as_str);
                    assert!(matches!(host, Some("v1.example.com" | "v2.example.com")));
                }
            });
        }

        let writer = Arc::clone(&store);
        scope.spawn(move || {
            for i in 0..20 {
                let src = if i % 2 == 0 { v2 } else { v1 };
                let _ = writer.reload_from_str("swap.kdl", src);
            }
        });
    });

    let (final_gen, _) = store.reload_from_str("v2.kdl", v2)?;
    assert_eq!(final_gen, store.generation());
    assert!(final_gen >= 2);
    assert_eq!(
        store
            .snapshot()
            .sites
            .first()
            .and_then(|s| s.hosts.first())
            .map(String::as_str),
        Some("v2.example.com")
    );

    Ok(())
}

#[test]
fn parses_and_validates_wasm_telemetry_ech_and_keyd_config() -> TestResult {
    let valid_kdl = r#"
server {
    listen ":443" protocols="h3,h2,h1"
    tls {
        min-version "1.3"
        pqc-hybrid #true
        key-isolation "split-daemon"
        keyd-socket "tcp://127.0.0.1:9444"
        ech #false
    }
    telemetry {
        metrics-listen "127.0.0.1:9090"
        metrics-path "/metrics"
        otlp-endpoint "https://otel.internal:4318"
        service-name "miraserve-edge"
        redact-logs #true
    }
}

site "wasm.example.com" {
    route "/edge/*" {
        wasm-plugin "/var/lib/miraserve/plugins/auth.wasm" max-memory="8MB" max-fuel=2000000 timeout="50ms"
    }
}
"#;

    let (cfg, report) = parse_kdl("m4.kdl", valid_kdl)?;
    assert!(
        report.is_clean(),
        "unexpected warnings: {:?}",
        report.warnings
    );
    assert_eq!(cfg.server.tls.key_isolation, KeyIsolation::SplitDaemon);
    assert!(!cfg.server.tls.ech);
    assert!(cfg.server.tls.ech_public_name.is_none());
    assert_eq!(cfg.server.telemetry.service_name, "miraserve-edge");
    assert_eq!(cfg.server.telemetry.metrics_path, "/metrics");

    // R2-ACME-5: Dead `ech-public-name` and explicit `ech-rotate` are rejected fail-closed with E107.
    let dead_ech_kdl = r#"
server {
    listen ":443"
    tls {
        key-isolation "split-daemon"
        keyd-socket "tcp://127.0.0.1:9444"
        ech #false
        ech-public-name "edge.example.com"
        ech-rotate "30m"
    }
}
site "ech.example.com" { root "/var/www" }
"#;
    let ech_err = parse_kdl("dead-ech.kdl", dead_ech_kdl)
        .err()
        .ok_or("expected E107 rejection for dead ECH directives")?;
    let ConfigError::Validation { errors, .. } = ech_err else {
        return Err(format!("expected Validation error, got {ech_err:?}").into());
    };
    assert!(
        errors
            .iter()
            .any(|e| e.code == "E107" && e.message.contains("ech-public-name")),
        "expected E107 for ech-public-name: {errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|e| e.code == "E107" && e.message.contains("ech-rotate")),
        "expected E107 for ech-rotate: {errors:?}"
    );

    // R3-HTTP-1: Configurable `body-idle-timeout` and explicit `min-body-rate-bps 0` opt-out (W016).
    let timeouts_kdl = r#"
server {
    listen ":443"
    tls {
        key-isolation "split-daemon"
        keyd-socket "tcp://127.0.0.1:9444"
    }
    timeouts {
        body-idle-timeout "45s"
        min-body-rate-bps 0
    }
}
site "upload.example.com" { root "/var/www" }
"#;
    let (t_cfg, t_report) = parse_kdl("timeouts.kdl", timeouts_kdl)?;
    assert_eq!(
        t_cfg.server.timeouts.body_idle_timeout,
        Duration::from_secs(45)
    );
    assert_eq!(t_cfg.server.timeouts.min_body_rate_bps, 0);
    assert!(
        t_report.warnings.iter().any(|w| w.code == "W016"),
        "expected W016 warning for min-body-rate-bps 0: {:?}",
        t_report.warnings
    );

    let bad_kdl = r#"
server {
    listen ":443"
    tls {
        key-isolation "split-daemon"
        keyd-socket "tcp://0.0.0.0:9444"
    }
}
site "bad-wasm.example.com" {
    route "/fn/*" {
        wasm-plugin "/opt/bad.wasm" max-memory="512MB" max-fuel=0 timeout="60s"
    }
}
"#;
    let err = parse_kdl("bad_m4.kdl", bad_kdl);
    assert!(err.is_err());
    if let Err(ConfigError::Validation { errors, .. }) = err {
        let codes: Vec<&str> = errors.iter().map(|e| e.code.as_str()).collect();
        assert!(codes.contains(&"E105"), "codes: {codes:?}");
        assert!(codes.contains(&"E501"), "codes: {codes:?}");
    } else {
        return Err("expected Validation error".into());
    }
    Ok(())
}

#[test]
fn security_audit_preflight_lexer_desync_and_validator_hardening() -> TestResult {
    // 1. KDL v2 raw string with escaped-quote trap (`#"\"#`) must not desync brace counting
    let raw_string_trap = format!("a #\"\\\"# {}", "{".repeat(200));
    assert!(parse_kdl("raw-trap.kdl", &raw_string_trap).is_err());

    // 2. Non-LF KDL line terminators (CR / U+2028) terminate `//` line comments
    let cr_comment_trap = format!("// comment\r{}", "{".repeat(200));
    assert!(parse_kdl("cr-trap.kdl", &cr_comment_trap).is_err());
    let ls_comment_trap = format!("// comment\u{2028}{}", "{".repeat(200));
    assert!(parse_kdl("ls-trap.kdl", &ls_comment_trap).is_err());

    // 3. Long `*` run inside block comment rejected before parser recursion
    let star_bomb = format!("/*{}*/", "*".repeat(1000));
    assert!(parse_kdl("star-bomb.kdl", &star_bomb).is_err());

    // 4. Validator hardening: numeric zero alias user/group ("00"), `//etc`, `ed25519` without
    // require-signature, excessive wasm max-fuel, and excessive mcp max-json-depth.
    let bad = r#"
server {
    listen ":443"
    sandbox {
        user "00"
        group "000"
    }
}

site "hardened.example.com" {
    root "//etc/./passwd"
    ai-publish {
        storage "/var/lib/miraserve/releases/h"
        mcp-endpoint "/_miraserve/publish" auth="ed25519"
    }
    route "/mcp/*" {
        mcp-gateway upstream="http://127.0.0.1:8080" {
            max-json-depth 500
        }
    }
    route "/fn/*" {
        wasm-plugin "/opt/fn.wasm" max-fuel=999999999
    }
}
"#;
    let Err(err) = parse_kdl("hardened-bad.kdl", bad) else {
        return Err("expected validation failure".into());
    };
    let codes = error_codes(&err);
    assert!(codes.contains(&"E201".to_owned()), "codes: {codes:?}");
    assert!(codes.contains(&"E202".to_owned()), "codes: {codes:?}");
    assert!(codes.contains(&"E401".to_owned()), "codes: {codes:?}");
    assert!(codes.contains(&"E403".to_owned()), "codes: {codes:?}");
    assert!(codes.contains(&"E501".to_owned()), "codes: {codes:?}");
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn claude_audit_fail_closed_validation_and_new_schema_directives() -> TestResult {
    // 1. Fail-closed rejections: tls.ech true (ECH-1), acme dns-01 (ACME-1), split-daemon without
    //    keyd-socket (KEYD-4), mtls without client-ca (PUB-2), oauth-jwt without require-signature (PUB-1),
    //    empty allow-tools (MCP-3), oauth-resource-metadata without jwt verifier (MCP-2),
    //    wasm allow-hosts (WASM-6), static route with only ai-publish (CFG-1), mid-path wildcard (CFG-2),
    //    and metrics-listen port collision (CFG-6).
    let bad = r#"
server {
    listen ":443"
    tls {
        key-isolation "split-daemon"
        ech #true
        acme {
            email "ops@example.com"
            challenge "dns-01"
        }
    }
    telemetry {
        metrics-listen "127.0.0.1:443"
    }
}

site "bad1.example.com" {
    ai-publish {
        storage "/var/lib/miraserve/releases/b1"
        mcp-endpoint "/_miraserve/publish" auth="mtls"
    }
    route "/static/*" {
        static {}
    }
    route "/api/*/v1" {
        reverse-proxy {
            upstream "https://10.0.0.1:8443"
        }
    }
}

site "bad2.example.com" {
    ai-publish {
        storage "/var/lib/miraserve/releases/b2"
        mcp-endpoint "/_miraserve/publish" auth="oauth-jwt"
    }
    route "/mcp/*" {
        mcp-gateway upstream="https://10.0.0.2:8443" {
            oauth-resource-metadata #true
        }
    }
    route "/fn/*" {
        wasm-plugin "/opt/fn.wasm" {
            allow-hosts "api.example.com"
        }
    }
}
"#;
    let Err(err) = parse_kdl("claude-bad.kdl", bad) else {
        return Err("expected validation failure for unimplemented/insecure features".into());
    };
    let codes = error_codes(&err);
    for expected in [
        "E102", "E105", "E106", "E107", "E301", "E303", "E401", "E403", "E501",
    ] {
        assert!(
            codes.contains(&expected.to_owned()),
            "missing expected error code {expected} in {codes:?}"
        );
    }

    // 2. Explicit dual-stack 0.0.0.0:443 + [::]:443 (CFG-4), bot-auth inline agent-key (BOT-1),
    //    default preflight-checks (PUB-13), shadowed route warning (CFG-2), and MCP jwt-public-key (MCP-2).
    let good_with_shadow = r#"
server {
    listen "0.0.0.0:443" protocols="h3,h2,h1"
    listen "[::]:443" protocols="h3,h2,h1"
    tls {
        client-ca "/etc/miraserve/client-ca.pem"
    }
}

site "edge.example.com" {
    root "/var/www/edge"
    bot-auth {
        verify-rfc9421 #true
        allow-agent "verified-ai-agents" serve-markdown=#true
        agent-key "bot-2026" group="verified-ai-agents" ed25519="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    }
    ai-publish {
        storage "/var/lib/miraserve/releases/edge"
        require-signature "ed25519:/etc/miraserve/deploy.pub"
        mcp-endpoint "/_miraserve/publish" auth="mtls"
    }
    route "/mcp/*" {
        mcp-gateway upstream="https://10.0.0.5:8443" {
            oauth-resource-metadata #true
            jwt-public-key "ed25519:/etc/miraserve/mcp.pub"
            jwt-issuer "https://auth.example.com"
            jwt-audience "https://edge.example.com"
            required-scope "mcp:invoke"
            allow-tools "docs_search"
        }
    }
    route "/*" {
        static {}
    }
    route "/admin/*" {
        static {}
    }
}
"#;
    let (cfg, report) = parse_kdl("claude-good.kdl", good_with_shadow)?;
    let site = cfg.sites.first().ok_or("missing site")?;
    // PUB-13: omitted preflight-checks defaults to NoSecrets + MaxSize(50MiB)
    let pub_cfg = site.ai_publish.as_ref().ok_or("missing ai_publish")?;
    assert!(
        pub_cfg
            .preflight_checks
            .contains(&PreflightCheck::NoSecrets)
    );
    // BOT-1: inline agent-key parsed
    let bot = site.bot_auth.as_ref().ok_or("missing bot_auth")?;
    assert_eq!(bot.agent_keys.len(), 1);
    // CFG-2: shadowed route warning W014 emitted
    assert!(
        report.warnings.iter().any(|w| w.code == "W014"),
        "expected W014 shadowed route warning, got {:?}",
        report.warnings
    );

    // 3. Codex Finding 3: MCP claim policies (`required-scope`, `jwt-issuer`, `jwt-audience`)
    //    with `oauth-resource-metadata #false` and NO verifier MUST fail closed with E403!
    for claim_line in [
        r#"required-scope "mcp:admin""#,
        r#"jwt-issuer "https://auth.example.com""#,
        r#"jwt-audience "https://api.example.com""#,
    ] {
        let claim_without_verifier = format!(
            r#"
server {{
    listen ":443"
}}
site "mcp.example.com" {{
    route "/mcp/*" {{
        mcp-gateway upstream="http://127.0.0.1:9001" {{
            oauth-resource-metadata #false
            {claim_line}
            allow-tools "docs_search"
        }}
    }}
}}
"#
        );
        let err = parse_kdl("claim-no-verifier.kdl", &claim_without_verifier)
            .err()
            .ok_or("expected E403 when claim policy is set without JWT verifier")?;
        assert!(
            err.validation_errors().iter().any(|e| e.code == "E403"),
            "expected E403 for {claim_line}, got: {:?}",
            err.validation_errors()
        );
    }

    // 4. R2-PUB-4: `auth="mtls"` MUST require `require-signature` so a broad CA cannot push unsigned bundles.
    let mtls_unsigned = r#"
server {
    listen ":443"
}
site "mtls-unsigned.example.com" {
    tls {
        client-ca "/etc/miraserve/ca.pem"
    }
    ai-publish {
        storage "/var/lib/miraserve/releases"
        mcp-endpoint "/_miraserve/publish" auth="mtls"
    }
}
"#;
    let mtls_err = parse_kdl("mtls-unsigned.kdl", mtls_unsigned)
        .err()
        .ok_or("expected E403 when auth=mtls lacks require-signature")?;
    assert!(
        mtls_err
            .validation_errors()
            .iter()
            .any(|e| e.code == "E401"),
        "expected E401 for unsigned mTLS publish, got: {:?}",
        mtls_err.validation_errors()
    );

    // 5. R2-MCP-2: Plain `http://` non-loopback `jwks-url` is rejected with E403,
    //    and `jwks-url` without `jwt-audience` emits warning W006.
    let http_jwks = r#"
server {
    listen ":443"
}
site "mcp-http-jwks.example.com" {
    route "/mcp/*" {
        mcp-gateway upstream="http://127.0.0.1:9001" {
            jwks-url "http://idp.example.com/.well-known/jwks.json"
            jwt-audience "https://mcp-http-jwks.example.com"
            allow-tools "docs_search"
        }
    }
}
"#;
    let jwks_err = parse_kdl("http-jwks.kdl", http_jwks)
        .err()
        .ok_or("expected E403 for non-loopback http:// jwks-url")?;
    assert!(
        jwks_err
            .validation_errors()
            .iter()
            .any(|e| e.code == "E403"),
        "expected E403 for http:// jwks-url, got: {:?}",
        jwks_err.validation_errors()
    );

    // R5-MCP-7: `oauth-resource-metadata #true` (default) without `jwt-audience` -> E403!
    let https_jwks_no_aud_oauth = r#"
server {
    listen ":443"
}
site "mcp-no-aud.example.com" {
    route "/mcp/*" {
        mcp-gateway upstream="http://127.0.0.1:9001" {
            jwks-url "https://idp.example.com/.well-known/jwks.json"
            jwt-issuer "https://idp.example.com"
            allow-tools "docs_search"
        }
    }
}
"#;
    let no_aud_err = parse_kdl("no-aud-oauth.kdl", https_jwks_no_aud_oauth)
        .err()
        .ok_or("expected E403 when oauth-resource-metadata omits jwt-audience (R5-MCP-7)")?;
    assert!(
        no_aud_err
            .validation_errors()
            .iter()
            .any(|e| e.code == "E403" && e.message.contains("jwt-audience")),
        "expected E403 for missing jwt-audience with oauth-resource-metadata, got: {:?}",
        no_aud_err.validation_errors()
    );

    // With oauth-resource-metadata #false, jwks-url without jwt-audience emits warning W006.
    let https_jwks_no_aud = r#"
server {
    listen ":443"
}
site "mcp-no-aud.example.com" {
    route "/mcp/*" {
        mcp-gateway upstream="http://127.0.0.1:9001" {
            oauth-resource-metadata #false
            jwks-url "https://idp.example.com/.well-known/jwks.json"
            jwt-issuer "https://idp.example.com"
            allow-tools "docs_search"
        }
    }
}
"#;
    let (_, report_no_aud) = parse_kdl("no-aud-jwks.kdl", https_jwks_no_aud)?;
    assert!(
        report_no_aud.warnings.iter().any(|w| w.code == "W006"),
        "expected W006 when jwks-url lacks jwt-audience, got: {:?}",
        report_no_aud.warnings
    );

    // 6. R2-ACME-3: `acme` with `key-isolation "split-daemon"` and no manual certs -> E106!
    let split_acme = r#"
server {
    listen ":443"
    tls {
        key-isolation "split-daemon"
        keyd-socket "/run/miraserve/keyd.sock"
        acme {
            email "ops@example.com"
            challenge "tls-alpn-01"
        }
    }
}
site "split-acme.example.com" {
    root "/var/www/site"
}
"#;
    let split_acme_err = parse_kdl("split-acme.kdl", split_acme)
        .err()
        .ok_or("expected E106 for acme + split-daemon without manual certs")?;
    assert!(
        split_acme_err
            .validation_errors()
            .iter()
            .any(|e| e.code == "E106"),
        "expected E106, got {:?}",
        split_acme_err.validation_errors()
    );

    // 7. CFG-6: FastCGI route without a site or route `root` -> E303!
    let fcgi_no_root = r#"
server {
    listen ":443"
}
site "no-root-php.example.com" {
    route "*.php" {
        fastcgi-pass "unix:/run/php/php-fpm.sock"
    }
}
"#;
    let fcgi_err = parse_kdl("fcgi-no-root.kdl", fcgi_no_root)
        .err()
        .ok_or("expected E303 when FastCGI route has no root")?;
    assert!(
        fcgi_err
            .validation_errors()
            .iter()
            .any(|e| e.code == "E303"),
        "expected E303, got {:?}",
        fcgi_err.validation_errors()
    );

    // 8. R2-CFG-1: Legitimate long block comment with >1000 `*` and `/` parses cleanly!
    let long_comment_kdl = format!(
        "/*\n{}\n*/\nserver {{\n    listen \":443\"\n    tls {{\n        cert \"/etc/miraserve/certs/starter.crt\"\n        key \"/etc/miraserve/certs/starter.key\"\n    }}\n}}\nsite \"comment.example.test\" {{\n    root \"/var/www/html\"\n}}\n",
        " * https://example.com/a/b/c/d/e/f/g/h\n".repeat(200)
    );
    let (comment_cfg, comment_rep) = parse_kdl("long-comment.kdl", &long_comment_kdl)?;
    assert!(
        comment_rep.is_clean(),
        "unexpected warnings: {:?}",
        comment_rep.warnings
    );
    assert_eq!(comment_cfg.sites.len(), 1);

    // 9. R3-PKG-1: HTTPS listener with no cert/key, no ACME, and no split-daemon keyd emits W015.
    let no_cert_kdl = r#"
server {
    listen ":443"
}
site "nocert.example.test" {
    root "/var/www/html"
}
"#;
    let (_nc_cfg, nc_rep) = parse_kdl("no-cert.kdl", no_cert_kdl)?;
    assert!(
        nc_rep.warnings.iter().any(|w| w.code == "W015"),
        "expected W015 when no cert/ACME/split-daemon is configured, got {:?}",
        nc_rep.warnings
    );

    // 10. R4-PUB-3 & §4 Q4: `ai-publish` validates `site-id`, `jwt-public-key`, `jwt-issuer`,
    //     `allowed-subjects`, and warns W018 (missing site-id on multi-host/wildcard) + W019
    //     (missing allowed-subjects on mTLS).
    let warn_pub_kdl = r#"
server {
    listen ":443"
    tls {
        cert "/etc/miraserve/certs/a.crt"
        key "/etc/miraserve/certs/a.key"
        client-ca "/etc/miraserve/ca.pem"
    }
}
site "*.example.test" "alt.example.test" {
    ai-publish {
        storage "/var/lib/miraserve/releases/w"
        require-signature "ed25519:/etc/miraserve/deploy.pub"
        mcp-endpoint "/_miraserve/publish" auth="mtls"
    }
}
"#;
    let (_wp_cfg, wp_rep) = parse_kdl("warn-pub.kdl", warn_pub_kdl)?;
    assert!(
        wp_rep.warnings.iter().any(|w| w.code == "W018"),
        "expected W018 for wildcard/multi-host ai-publish without site-id, got {:?}",
        wp_rep.warnings
    );
    assert!(
        wp_rep.warnings.iter().any(|w| w.code == "W019"),
        "expected W019 for mTLS ai-publish without allowed-subjects, got {:?}",
        wp_rep.warnings
    );

    // Mismatched `jwt-public-key` on auth="mtls" or `allowed-subjects` on auth="oauth-jwt" -> E401!
    let mismatch_pub_kdl = r#"
server {
    listen ":443"
    tls {
        cert "/etc/miraserve/certs/a.crt"
        key "/etc/miraserve/certs/a.key"
        client-ca "/etc/miraserve/ca.pem"
    }
}
site "mismatch.example.test" {
    ai-publish {
        storage "/var/lib/miraserve/releases/m"
        site-id "mismatch-site"
        require-signature "ed25519:/etc/miraserve/deploy.pub"
        jwt-public-key "ed25519:/etc/miraserve/jwt.pub"
        mcp-endpoint "/_miraserve/publish" auth="mtls"
    }
}
"#;
    let mismatch_err = parse_kdl("mismatch-pub.kdl", mismatch_pub_kdl)
        .err()
        .ok_or("expected E401 when jwt-public-key is paired with auth=\"mtls\"")?;
    assert!(
        mismatch_err
            .validation_errors()
            .iter()
            .any(|e| e.code == "E401"),
        "expected E401, got {:?}",
        mismatch_err.validation_errors()
    );

    Ok(())
}

/// R4-MCP-2 (`oauth-resource-metadata true` requires explicit `jwt-issuer`),
/// R2-PRX-2 / DOS-7 (dedicated upstream connect/response/body-idle timeouts),
/// and DOS-1 (`limits.max-connections-per-ip`).
#[test]
fn round4_mcp_issuer_and_upstream_timeouts_and_conn_cap_config() -> TestResult {
    // 1. R4-MCP-2: OAuth resource metadata without explicit `jwt-issuer` -> E403.
    let missing_iss = r#"
server {
    listen ":443"
}
site "mcp-no-iss.example.test" {
    route "/mcp/*" {
        mcp-gateway upstream="http://127.0.0.1:9001" {
            oauth-resource-metadata #true
            jwks-url "https://idp.example.com/.well-known/jwks.json"
            allow-tools "docs_search"
        }
    }
}
"#;
    let err = parse_kdl("mcp-no-iss.kdl", missing_iss)
        .err()
        .ok_or("expected E403 when oauth-resource-metadata lacks jwt-issuer")?;
    assert!(
        err.validation_errors().iter().any(|e| e.code == "E403"),
        "expected E403, got {:?}",
        err.validation_errors()
    );

    // 2. Dedicated upstream timeouts & `max-connections-per-ip` parse & validate cleanly.
    let valid_kdl = r#"
server {
    listen ":443"
    tls {
        cert "/etc/miraserve/certs/starter.crt"
        key "/etc/miraserve/certs/starter.key"
    }
    timeouts {
        upstream-connect-timeout "5s"
        upstream-response-timeout "45s"
        upstream-body-idle-timeout "20s"
    }
    limits {
        max-connections-per-ip 128
        max-streamed-answers-per-ip 32
        max-streamed-answers-per-backend 12
    }
}
site "tuned.example.test" {
    root "/var/www/html"
}
"#;
    let (cfg, rep) = parse_kdl("tuned.kdl", valid_kdl)?;
    assert!(rep.is_clean(), "unexpected warnings: {:?}", rep.warnings);
    assert_eq!(cfg.server.limits.max_streamed_answers_per_ip, 32);
    assert_eq!(cfg.server.limits.max_streamed_answers_per_backend, 12);

    // One backend can have its own number; out of range is refused.
    let with_route = |property: &str| {
        format!(
            r#"
server {{
    listen ":443"
    tls {{ cert "/etc/miraserve/certs/starter.crt"; key "/etc/miraserve/certs/starter.key" }}
}}
site "pool.example.test" {{
    root "/var/www/html"
    route "*.php" {{
        fastcgi-pass "unix:/run/php/pool.sock" {property}
    }}
}}
"#
        )
    };
    let (pool_cfg, _) = parse_kdl("pool.kdl", &with_route("max-streamed-answers=2"))?;
    let own = pool_cfg
        .sites
        .iter()
        .flat_map(|site| &site.routes)
        .find_map(|route| match &route.handler {
            miraserve_config::RouteHandler::FastCgi(fcgi) => Some(fcgi.max_streamed_answers),
            _ => None,
        });
    assert_eq!(own, Some(Some(2)));
    assert!(parse_kdl("pool-zero.kdl", &with_route("max-streamed-answers=0")).is_err());
    assert_eq!(
        miraserve_config::LimitsConfig::default().max_streamed_answers_per_backend,
        4
    );
    assert_eq!(
        miraserve_config::LimitsConfig::default().max_streamed_answers_per_ip,
        8
    );
    assert_eq!(cfg.server.timeouts.upstream_connect, Duration::from_secs(5));
    assert_eq!(
        cfg.server.timeouts.upstream_response,
        Duration::from_secs(45)
    );
    assert_eq!(
        cfg.server.timeouts.upstream_body_idle,
        Duration::from_secs(20)
    );
    assert_eq!(cfg.server.limits.max_connections_per_ip, 128);

    // 3. Zero/out-of-bounds upstream timeouts & `max-connections-per-ip 0` -> E007.
    let invalid_bounds = r#"
server {
    listen ":443"
    timeouts {
        upstream-connect-timeout "500s"
        upstream-response-timeout "0s"
        upstream-body-idle-timeout "5000s"
    }
    limits {
        max-connections-per-ip 0
    }
}
site "bad-bounds.example.test" {
    root "/var/www/html"
}
"#;
    let bounds_err = parse_kdl("bad-bounds.kdl", invalid_bounds)
        .err()
        .ok_or("expected E007 for out-of-range timeouts / max-connections-per-ip")?;
    assert!(
        bounds_err
            .validation_errors()
            .iter()
            .filter(|e| e.code == "E007")
            .count()
            >= 4,
        "expected >= 4 E007 errors, got {:?}",
        bounds_err.validation_errors()
    );

    Ok(())
}

#[test]
fn parses_and_validates_site_error_pages_and_login_url() -> TestResult {
    // 1. Valid site `error-pages` block with safe login-url and relative/absolute overrides
    let ok_kdl = r#"
server {
    listen ":443"
    tls {
        cert "/etc/miraserve/certs/app.crt"
        key "/etc/miraserve/certs/app.key"
    }
}
site "pages.example.test" {
    root "/var/www/pages"
    error-pages {
        login-url "/login"
        page 404 "errors/404.html"
        page 500 "/etc/miraserve/errors/500.html"
    }
}
"#;
    let (cfg, rep) = parse_kdl("error-pages-ok.kdl", ok_kdl)?;
    assert!(rep.is_clean(), "unexpected warnings: {:?}", rep.warnings);
    let ep = cfg
        .sites
        .first()
        .and_then(|s| s.error_pages.as_ref())
        .ok_or("expected parsed error_pages")?;
    assert_eq!(ep.login_url.as_deref(), Some("/login"));
    assert_eq!(
        ep.pages.get(&404).map(String::as_str),
        Some("errors/404.html")
    );
    assert_eq!(
        ep.pages.get(&500).map(String::as_str),
        Some("/etc/miraserve/errors/500.html")
    );

    // 2. Rejects unsafe login-url schemes (`javascript:`, `//evil`), non-error status, traversal,
    //    and relative path without site root.
    let bad_kdl = r#"
server {
    listen ":443"
    tls {
        cert "/etc/miraserve/certs/app.crt"
        key "/etc/miraserve/certs/app.key"
    }
}
site "bad-pages.example.test" {
    error-pages {
        login-url "javascript:alert(1)"
        page 200 "errors/200.html"
        page 404 "../secret.html"
    }
}
"#;
    let err = parse_kdl("error-pages-bad.kdl", bad_kdl)
        .err()
        .ok_or("expected validation errors for unsafe error-pages")?;
    assert!(err.validation_errors().iter().any(|e| e.code == "E203"));
    assert!(err.validation_errors().iter().any(|e| e.code == "E202"));

    let open_redir_login = r#"
server {
    listen ":443"
    tls {
        cert "/etc/miraserve/certs/app.crt"
        key "/etc/miraserve/certs/app.key"
    }
}
site "open-redir.example.test" {
    root "/var/www/pages"
    error-pages {
        login-url "//evil.example/phish"
    }
}
"#;
    assert!(parse_kdl("open-redir-login.kdl", open_redir_login).is_err());
    Ok(())
}

/// Round 5 Wave 2 config validation regressions:
/// - `R5-PUB-3`: `auth="oauth-jwt"` without `require-signature` fails closed (`E401`) even if
///   `jwt-public-key` is set; omitting `jwt-public-key` emits explicit warning `W020`.
/// - `R5-PUB-5`: Duplicate `site-id` or duplicate `storage` across two sites fails (`E401`).
/// - `R5-PUB-2`: Malformed `allowed-subjects` entry without `ATTR=VAL` fails (`E401`).
/// - `R5-MCP-7`: `oauth-resource-metadata #true` without `jwt-audience` fails (`E403`).
#[test]
#[allow(clippy::too_many_lines)]
fn round5_wave2_publish_oauth_require_sig_w020_uniqueness_and_mcp_audience() -> TestResult {
    // 1. R5-PUB-3: oauth-jwt with ONLY jwt-public-key (no require-signature) -> E401!
    let jwt_no_sig = r#"
server {
    listen ":443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }
}
site "pub1.example.com" {
    ai-publish {
        storage "/var/lib/miraserve/releases/pub1"
        jwt-public-key "ed25519:/etc/miraserve/jwt.pub"
        mcp-endpoint "/_miraserve/publish" auth="oauth-jwt"
    }
}
"#;
    let err = parse_kdl("jwt-no-sig.kdl", jwt_no_sig)
        .err()
        .ok_or("expected E401 when oauth-jwt omits require-signature (R5-PUB-3)")?;
    assert!(
        err.validation_errors()
            .iter()
            .any(|e| e.code == "E401" && e.message.contains("require-signature")),
        "expected E401 mentioning require-signature, got: {:?}",
        err.validation_errors()
    );

    // 2. R5-PUB-3 (W020): oauth-jwt with require-signature but NO jwt-public-key -> real W020!
    let jwt_fallback = r#"
server {
    listen ":443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }
}
site "pub2.example.com" {
    ai-publish {
        storage "/var/lib/miraserve/releases/pub2"
        require-signature "ed25519:/etc/miraserve/deploy.pub"
        mcp-endpoint "/_miraserve/publish" auth="oauth-jwt"
    }
}
"#;
    let (_, report) = parse_kdl("jwt-fallback.kdl", jwt_fallback)?;
    assert!(
        report.warnings.iter().any(|w| w.code == "W020"),
        "expected W020 warning when oauth-jwt falls back to require-signature key, got: {:?}",
        report.warnings
    );

    // 3. R5-PUB-5: Duplicate site-id AND duplicate storage across sites -> E401!
    let dup_pub = r#"
server {
    listen ":443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }
}
site "a.example.com" {
    ai-publish {
        storage "/var/lib/miraserve/releases/shared"
        site-id "same-site"
        require-signature "ed25519:/etc/miraserve/deploy.pub"
    }
}
site "b.example.com" {
    ai-publish {
        storage "/var/lib/miraserve/releases/./shared/"
        site-id "same-site"
        require-signature "ed25519:/etc/miraserve/deploy.pub"
    }
}
"#;
    let dup_err = parse_kdl("dup-pub.kdl", dup_pub)
        .err()
        .ok_or("expected E401 for duplicate site-id and storage (R5-PUB-5)")?;
    assert!(
        dup_err
            .validation_errors()
            .iter()
            .any(|e| e.code == "E401" && e.message.contains("duplicate ai-publish site-id")),
        "expected duplicate site-id E401, got: {:?}",
        dup_err.validation_errors()
    );
    assert!(
        dup_err
            .validation_errors()
            .iter()
            .any(|e| e.code == "E401" && e.message.contains("duplicate ai-publish storage")),
        "expected duplicate storage E401, got: {:?}",
        dup_err.validation_errors()
    );

    // 4. R5-PUB-2: Malformed allowed-subjects (not ATTR=VAL) -> E401!
    let bad_subj = r#"
server {
    listen ":443"
    tls {
        cert "/etc/miraserve/certs/a.crt"
        key "/etc/miraserve/certs/a.key"
        client-ca "/etc/miraserve/certs/ca.pem"
    }
}
site "mtls.example.com" {
    ai-publish {
        storage "/var/lib/miraserve/releases/mtls"
        require-signature "ed25519:/etc/miraserve/deploy.pub"
        allowed-subjects "not-a-valid-dn"
        mcp-endpoint "/_miraserve/publish" auth="mtls"
    }
}
"#;
    let subj_err = parse_kdl("bad-subj.kdl", bad_subj)
        .err()
        .ok_or("expected E401 for malformed allowed-subjects (R5-PUB-2)")?;
    assert!(
        subj_err
            .validation_errors()
            .iter()
            .any(|e| e.code == "E401" && e.message.contains("allowed-subjects")),
        "expected allowed-subjects E401, got: {:?}",
        subj_err.validation_errors()
    );

    Ok(())
}

/// Round 5 Wave 4 config validation (`R5-DOS-1`, `R5-RL-1`, `R5-HTTP-2`, `R5-PRX-3`):
/// - `server.limits`: configurable `max-connections`, lowered default `max-connections-per-ip` (128),
///   `trusted-proxies` CIDR list (rejecting `/0` catch-alls).
/// - `server.timeouts.max-body-duration` validated (`> 0`, `<= 86400s`), `W016` mentions it.
/// - `rate-limit`: optional `ip-ceiling-multiplier` and `max-keys-per-ip`.
/// - `reverse-proxy`: optional per-route `upstream-connect-timeout`, `upstream-response-timeout`,
///   and `upstream-body-idle-timeout` overrides (up to 24h for SSE).
#[test]
fn round5_wave4_limits_trusted_proxies_rate_limit_caps_and_per_route_proxy_timeouts() -> TestResult
{
    // 1. Default `max-connections-per-ip` is lowered to 128 and `max-connections` defaults to 16384.
    let defaults_kdl = r#"
server {
    listen ":443"
    tls {
        cert "/etc/miraserve/certs/starter.crt"
        key "/etc/miraserve/certs/starter.key"
    }
}
site "defaults.example.test" {
    root "/var/www/html"
}
"#;
    let (def_cfg, def_rep) = parse_kdl("defaults.kdl", defaults_kdl)?;
    assert!(
        def_rep.is_clean(),
        "unexpected warnings: {:?}",
        def_rep.warnings
    );
    assert_eq!(def_cfg.server.limits.max_connections, 16_384);
    assert_eq!(def_cfg.server.limits.max_connections_per_ip, 128);
    assert!(def_cfg.server.limits.trusted_proxies.is_empty());
    assert_eq!(
        def_cfg.server.timeouts.max_body_duration,
        Duration::from_hours(1)
    );

    // 2. Valid Wave 4 knobs parse and validate cleanly.
    let tuned_kdl = r#"
server {
    listen ":443"
    tls {
        cert "/etc/miraserve/certs/starter.crt"
        key "/etc/miraserve/certs/starter.key"
    }
    timeouts {
        max-body-duration "30m"
    }
    limits {
        max-connections 8192
        max-connections-per-ip 64
        trusted-proxies "10.0.0.0/8" "192.168.1.10" "2001:db8::/32"
    }
}
site "api.example.test" {
    rate-limit requests=100 per="1m" burst=10 key="header:x-api-key" ip-ceiling-multiplier=25 max-keys-per-ip=128
    route "/events/*" {
        reverse-proxy {
            upstream "http://127.0.0.1:9000"
            streaming-flush "immediate"
            upstream-connect-timeout "3s"
            upstream-response-timeout "15s"
            upstream-body-idle-timeout "2h"
        }
    }
}
"#;
    let (cfg, rep) = parse_kdl("tuned-w4.kdl", tuned_kdl)?;
    // R7-XFF-2: `10.0.0.0/8` and `2001:db8::/32` are accepted with W022 broad-CIDR advisories.
    assert!(
        rep.warnings.iter().all(|w| w.code == "W022"),
        "unexpected non-W022 warnings: {:?}",
        rep.warnings
    );
    assert_eq!(rep.warnings.len(), 2);
    assert_eq!(cfg.server.limits.max_connections, 8_192);
    assert_eq!(cfg.server.limits.max_connections_per_ip, 64);
    assert_eq!(cfg.server.limits.trusted_proxies.len(), 3);
    let first_cidr = cfg
        .server
        .limits
        .trusted_proxies
        .first()
        .ok_or("missing first trusted proxy CIDR")?;
    assert!(
        first_cidr.contains("10.42.0.5".parse()?),
        "10.0.0.0/8 must match 10.42.0.5"
    );
    assert!(
        !first_cidr.contains("11.0.0.1".parse()?),
        "10.0.0.0/8 must NOT match 11.0.0.1"
    );
    assert_eq!(
        cfg.server.timeouts.max_body_duration,
        Duration::from_mins(30)
    );
    let site0 = cfg.sites.first().ok_or("missing site0")?;
    let rl = site0.rate_limit.as_ref().ok_or("missing rate_limit")?;
    assert_eq!(rl.ip_ceiling_multiplier, Some(25));
    assert_eq!(rl.max_keys_per_ip, Some(128));
    let route0 = site0.routes.first().ok_or("missing route0")?;
    match &route0.handler {
        RouteHandler::ReverseProxy(rp) => {
            assert_eq!(rp.upstream_connect_timeout, Some(Duration::from_secs(3)));
            assert_eq!(rp.upstream_response_timeout, Some(Duration::from_secs(15)));
            assert_eq!(rp.upstream_body_idle_timeout, Some(Duration::from_hours(2)));
        }
        other => return Err(format!("expected ReverseProxy, got {other:?}").into()),
    }

    // 3. Invalid `/0` trusted-proxy CIDR, zero `max-connections`, zero `ip-ceiling-multiplier`,
    //    and out-of-range per-route timeout are rejected with validation errors.
    let bad_kdl = r#"
server {
    listen ":443"
    timeouts {
        max-body-duration "0s"
    }
    limits {
        max-connections 0
        trusted-proxies "0.0.0.0/0"
    }
}
site "bad.example.test" {
    rate-limit requests=10 per="1m" burst=5 key="header:x-k" ip-ceiling-multiplier=0 max-keys-per-ip=0
    route "/sse/*" {
        reverse-proxy {
            upstream "http://127.0.0.1:9000"
            upstream-body-idle-timeout "100000s"
        }
    }
}
"#;
    let err = parse_kdl("bad-w4.kdl", bad_kdl)
        .err()
        .ok_or("expected validation errors for invalid Wave 4 limits/timeouts")?;
    assert!(
        err.validation_errors().iter().any(|e| e.code == "E007"),
        "expected E007 errors, got {:?}",
        err.validation_errors()
    );
    assert!(
        err.validation_errors().iter().any(|e| e.code == "E204"),
        "expected E204 errors for 0 multiplier/cap, got {:?}",
        err.validation_errors()
    );

    Ok(())
}

/// R6-CFG-1: Relative `root` resolves against the config file's directory on disk (fixing
/// `examples/dev-local.kdl`), while still refusing relative paths without a file base dir,
/// refusing `..` traversal, and rejecting any relative root that resolves into sensitive system
/// directories such as `/etc/miraserve` (`R5-SBX-1`).
#[test]
fn r6_cfg_1_relative_root_resolves_against_config_dir_and_blocks_sensitive_targets() -> TestResult {
    let dev_local = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("examples")
        .join("dev-local.kdl");
    let (cfg, _report) = load_file(&dev_local)?;
    let site = cfg.sites.first().ok_or("dev-local.kdl missing site")?;
    let resolved_root = site.root.as_deref().ok_or("dev-local.kdl missing root")?;
    assert!(
        Path::new(resolved_root).is_absolute(),
        "loaded relative root must normalize to an absolute path, got '{resolved_root}'"
    );
    assert!(
        resolved_root.ends_with("www"),
        "expected resolved root ending in 'www', got '{resolved_root}'"
    );

    let rel_kdl = r#"
server {
    listen "127.0.0.1:8443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }
}
site "localhost" {
    root "certs"
}
"#;
    // Relative root inside `/etc/miraserve` resolves to `/etc/miraserve/certs` -> E202!
    let etc_err = parse_kdl_detailed_with_base_dir(
        "/etc/miraserve/miraserve.kdl",
        rel_kdl,
        Some(Path::new("/etc/miraserve")),
    )
    .err()
    .ok_or("expected E202 for relative root under /etc/miraserve")?;
    assert!(error_codes(&etc_err).contains(&"E202".to_owned()));

    // Relative root `etc/miraserve` under `/` resolves to `/etc/miraserve` -> E202!
    let root_etc_kdl = rel_kdl.replace(r#"root "certs""#, r#"root "etc/miraserve""#);
    let root_err =
        parse_kdl_detailed_with_base_dir("/miraserve.kdl", &root_etc_kdl, Some(Path::new("/")))
            .err()
            .ok_or("expected E202 for relative 'etc/miraserve' under /")?;
    assert!(error_codes(&root_err).contains(&"E202".to_owned()));

    // Relative root with `..` traversal under a safe project dir STILL fails E202!
    let trav_kdl = rel_kdl.replace(r#"root "certs""#, r#"root "../etc""#);
    let trav_err = parse_kdl_detailed_with_base_dir(
        "/opt/app/miraserve.kdl",
        &trav_kdl,
        Some(Path::new("/opt/app")),
    )
    .err()
    .ok_or("expected E202 for '../etc' traversal")?;
    assert!(error_codes(&trav_err).contains(&"E202".to_owned()));

    // In-memory / stdin parse with NO base dir STILL rejects relative roots with E202!
    let stdin_err = parse_kdl("<stdin>", rel_kdl)
        .err()
        .ok_or("expected E202 for relative root without base_dir")?;
    assert!(error_codes(&stdin_err).contains(&"E202".to_owned()));

    Ok(())
}

/// R5-PUB-5: Cross-site `ai-publish.storage` uniqueness catches symlink aliases, case aliases,
/// and nested paths (`a` vs `a/releases`).
#[test]
fn r5_pub_5_ai_publish_storage_blocks_symlink_case_alias_and_nested_paths() -> TestResult {
    let base =
        std::env::temp_dir().join(format!("miraserve-r5-pub-5-storage-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let real_a = base.join("SiteA");
    std::fs::create_dir_all(&real_a)?;

    // 1. Nested paths (`a` vs `a/releases`) -> E401!
    let nested_releases = real_a.join("releases");
    let nested_kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key"; }}
}}
site "a.example.test" {{
    ai-publish {{ storage "{}"; site-id "site-a"; }}
}}
site "b.example.test" {{
    ai-publish {{ storage "{}"; site-id "site-b"; }}
}}
"#,
        kdl_path(&real_a),
        kdl_path(&nested_releases)
    );
    let nested_err = parse_kdl("nested-storage.kdl", &nested_kdl)
        .err()
        .ok_or("expected E401 for nested storage")?;
    assert!(error_codes(&nested_err).contains(&"E401".to_owned()));

    // 2. Case alias (`SiteA` vs `sitea`) -> E401!
    let lower_a = base.join("sitea");
    let case_kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key"; }}
}}
site "a.example.test" {{
    ai-publish {{ storage "{}"; site-id "site-a"; }}
}}
site "b.example.test" {{
    ai-publish {{ storage "{}"; site-id "site-b"; }}
}}
"#,
        kdl_path(&real_a),
        kdl_path(&lower_a)
    );
    let case_err = parse_kdl("case-storage.kdl", &case_kdl)
        .err()
        .ok_or("expected E401 for case-alias storage")?;
    assert!(error_codes(&case_err).contains(&"E401".to_owned()));

    // 3. Symlink alias (`link-a` -> `SiteA`) -> E401!
    #[cfg(unix)]
    {
        let link_a = base.join("link-a");
        std::os::unix::fs::symlink(&real_a, &link_a)?;
        let sym_kdl = format!(
            r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key"; }}
}}
site "a.example.test" {{
    ai-publish {{ storage "{}"; site-id "site-a"; }}
}}
site "b.example.test" {{
    ai-publish {{ storage "{}"; site-id "site-b"; }}
}}
"#,
            real_a.display(),
            link_a.display()
        );
        let sym_err = parse_kdl("symlink-storage.kdl", &sym_kdl)
            .err()
            .ok_or("expected E401 for symlink-alias storage")?;
        assert!(error_codes(&sym_err).contains(&"E401".to_owned()));
    }

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// R5-PRX-3 residual: `mcp-gateway` routes support per-route `upstream-connect-timeout`,
/// `upstream-response-timeout`, and `upstream-body-idle-timeout` (up to 24h for long-lived SSE).
#[test]
fn r5_prx_3_mcp_gateway_accepts_and_validates_per_route_upstream_timeouts() -> TestResult {
    let ok_kdl = r#"
server {
    listen "127.0.0.1:8443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key"; }
}
site "mcp.example.test" {
    route "/mcp/*" {
        mcp-gateway upstream="http://127.0.0.1:9001" {
            oauth-resource-metadata #false
            allow-tools "docs_search"
            upstream-connect-timeout "5s"
            upstream-response-timeout "30s"
            upstream-body-idle-timeout "30m"
        }
    }
}
"#;
    let (cfg, _) = parse_kdl("mcp-timeouts.kdl", ok_kdl)?;
    let site = cfg.sites.first().ok_or("missing site")?;
    let route = site.routes.first().ok_or("missing route")?;
    match &route.handler {
        miraserve_config::RouteHandler::McpGateway(mcp) => {
            assert_eq!(mcp.upstream_connect_timeout, Some(Duration::from_secs(5)));
            assert_eq!(mcp.upstream_response_timeout, Some(Duration::from_secs(30)));
            assert_eq!(
                mcp.upstream_body_idle_timeout,
                Some(Duration::from_mins(30))
            );
        }
        other => return Err(format!("expected McpGateway, got {other:?}").into()),
    }

    let bad_kdl = ok_kdl.replace(
        r#"upstream-body-idle-timeout "30m""#,
        r#"upstream-body-idle-timeout "48h""#,
    );
    let err = parse_kdl("mcp-timeouts-bad.kdl", &bad_kdl)
        .err()
        .ok_or("expected E007 for >24h mcp upstream-body-idle-timeout")?;
    assert!(error_codes(&err).contains(&"E007".to_owned()));
    Ok(())
}

/// R6-DOS-1: Binding a private/internal IP or loopback with a production hostname without
/// `trusted-proxies` and at low `max-connections-per-ip` emits warning `W021`, which clears when
/// `trusted-proxies` is configured, `max-connections-per-ip` is raised, or the site is local dev.
#[test]
fn r6_dos_1_warns_w021_on_private_or_production_loopback_listener_without_trusted_proxies()
-> TestResult {
    let private_kdl = r#"
server {
    listen "10.0.0.5:8443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key"; }
}
site "app.example.com" {
    root "/var/www/app"
}
"#;
    let (_, report) = parse_kdl("private.kdl", private_kdl)?;
    assert!(
        report.warnings.iter().any(|w| w.code == "W021"),
        "expected W021 on private listener without trusted-proxies, got {:?}",
        report.warnings
    );

    let loopback_prod_kdl = r#"
server {
    listen "127.0.0.1:8443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key"; }
}
site "prod.example.com" {
    root "/var/www/prod"
}
"#;
    let (_, prod_report) = parse_kdl("loopback-prod.kdl", loopback_prod_kdl)?;
    assert!(
        prod_report.warnings.iter().any(|w| w.code == "W021"),
        "expected W021 on loopback listener with production site host, got {:?}",
        prod_report.warnings
    );

    // Configuring `trusted-proxies` clears W021.
    let with_proxy_kdl = r#"
server {
    listen "10.0.0.5:8443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key"; }
    limits {
        trusted-proxies "10.0.0.0/8"
    }
}
site "app.example.com" {
    root "/var/www/app"
}
"#;
    let (_, fixed_report) = parse_kdl("with-proxy.kdl", with_proxy_kdl)?;
    assert!(
        !fixed_report.warnings.iter().any(|w| w.code == "W021"),
        "W021 must clear once trusted-proxies is set, got {:?}",
        fixed_report.warnings
    );

    // Local dev loopback (`localhost` / `*.test`) stays clean.
    let dev_kdl = r#"
server {
    listen "127.0.0.1:8443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key"; }
}
site "localhost" {
    root "/var/www/dev"
}
"#;
    let (_, dev_report) = parse_kdl("dev-loopback.kdl", dev_kdl)?;
    assert!(
        !dev_report.warnings.iter().any(|w| w.code == "W021"),
        "local dev loopback must not trigger W021, got {:?}",
        dev_report.warnings
    );
    Ok(())
}

/// R6-DOS-2: `rate-limit.max-keys-per-ip` is capped at 1024 to bound memory, and
/// `server.limits.ipv6-prefix-conn-multiplier` is configurable in `1..=1000`.
#[test]
fn r6_dos_2_enforces_max_keys_per_ip_1024_bound_and_ipv6_prefix_conn_multiplier() -> TestResult {
    let ok_kdl = r#"
server {
    listen ":443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key"; }
    limits {
        ipv6-prefix-conn-multiplier 8
    }
}
site "campus.example.test" {
    root "/var/www/campus"
    rate-limit requests=100 per="1m" burst=10 key="header:x-api-key" max-keys-per-ip=1024
}
"#;
    let (cfg, _) = parse_kdl("r6-dos-2-ok.kdl", ok_kdl)?;
    assert_eq!(cfg.server.limits.ipv6_prefix_conn_multiplier, 8);

    let too_many_keys = ok_kdl.replace("max-keys-per-ip=1024", "max-keys-per-ip=1025");
    let err_keys = parse_kdl("r6-dos-2-keys.kdl", &too_many_keys)
        .err()
        .ok_or("expected E204 for max-keys-per-ip=1025")?;
    assert!(error_codes(&err_keys).contains(&"E204".to_owned()));

    for bad_mult in [0_u32, 1001] {
        let bad_kdl = ok_kdl.replace(
            "ipv6-prefix-conn-multiplier 8",
            &format!("ipv6-prefix-conn-multiplier {bad_mult}"),
        );
        let err_mult = parse_kdl("r6-dos-2-mult.kdl", &bad_kdl)
            .err()
            .ok_or("expected E007 for out-of-range ipv6-prefix-conn-multiplier")?;
        assert!(error_codes(&err_mult).contains(&"E007".to_owned()));
    }
    Ok(())
}

/// R6-XFF-4: `trusted-proxies` rejects ultra-broad IPv4 (`< /8`, e.g. `0.0.0.0/1` + `128.0.0.0/1`)
/// and IPv6 (`< /16`, e.g. `::/1`) CIDRs while accepting `/8`+ IPv4 and `/16`+ IPv6 ranges.
#[test]
fn r6_xff_4_rejects_overly_broad_trusted_proxies_cidrs() -> TestResult {
    for broad in [
        r#""0.0.0.0/1" "128.0.0.0/1""#,
        r#""10.0.0.0/7""#,
        r#""::/1""#,
        r#""2000::/15""#,
    ] {
        let bad_kdl = format!(
            r#"
server {{
    listen ":443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key"; }}
    limits {{
        trusted-proxies {broad}
    }}
}}
site "edge.example.test" {{ root "/var/www/edge"; }}
"#
        );
        let err = parse_kdl("broad-proxy.kdl", &bad_kdl)
            .err()
            .ok_or_else(|| format!("expected E007 for overly broad trusted-proxies {broad}"))?;
        assert!(
            error_codes(&err).contains(&"E007".to_owned()),
            "expected E007 for {broad}, got {:?}",
            err.validation_errors()
        );
    }

    let ok_kdl = r#"
server {
    listen ":443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key"; }
    limits {
        trusted-proxies "10.0.0.0/8" "127.0.0.1/32" "2001:db8::/32" "fc00::/16"
    }
}
site "edge.example.test" { root "/var/www/edge"; }
"#;
    let (cfg, _) = parse_kdl("narrow-proxy.kdl", ok_kdl)?;
    assert_eq!(cfg.server.limits.trusted_proxies.len(), 4);
    Ok(())
}

/// R6-SBX-1: Refuse document roots pointing to MiraServe internal state (`/var/lib/miraserve`,
/// `/var/lib/miraserve/acme`, `/run/miraserve-keyd`), system/DB trees (`/var/lib/mysql`,
/// `/var/lib/postgresql`, `/usr/local/etc`, `/var/spool/cron`), hidden dot-directories
/// (`/home/bob/.ssh`), or overlapping any configured `ai-publish.storage` directory.
#[test]
fn r6_sbx_1_refuses_acme_miraserve_state_db_dotdirs_and_publish_storage_docroots() -> TestResult {
    for forbidden in [
        "/var/lib/miraserve",
        "/var/lib/miraserve/acme",
        "/var/lib/miraserve/releases/app",
        "/var/lib/mysql",
        "/var/lib/postgresql",
        "/home/bob/.ssh",
        "/usr/local/etc",
        "/var/spool/cron",
        "/run/miraserve-keyd",
    ] {
        let kdl = format!(
            r#"
server {{
    listen ":443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key"; }}
}}
site "leak.example.test" {{ root "{forbidden}"; }}
"#
        );
        let err = parse_kdl("r6-sbx-1.kdl", &kdl)
            .err()
            .ok_or_else(|| format!("R6-SBX-1: docroot '{forbidden}' MUST be rejected"))?;
        assert!(
            error_codes(&err).contains(&"E202".to_owned()),
            "expected E202 for docroot '{forbidden}', got {:?}",
            err.validation_errors()
        );
    }

    // Docroot overlapping a site's `ai-publish.storage` (equal, child, or ancestor) MUST fail E202.
    for overlapping_root in [
        "/srv/app-data/releases",
        "/srv/app-data/releases/live",
        "/srv/app-data",
    ] {
        let overlap_kdl = format!(
            r#"
server {{
    listen ":443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key"; }}
}}
site "pub.example.test" {{
    ai-publish {{ storage "/srv/app-data/releases"; site-id "pub"; }}
}}
site "static.example.test" {{
    root "{overlapping_root}"
}}
"#
        );
        let err = parse_kdl("r6-sbx-1-overlap.kdl", &overlap_kdl)
            .err()
            .ok_or_else(|| {
                format!("R6-SBX-1: docroot '{overlapping_root}' overlapping ai-publish.storage MUST fail")
            })?;
        assert!(error_codes(&err).contains(&"E202".to_owned()));
    }

    // Dedicated `/var/lib/miraserve/releases/app` remains valid specifically for `ai-publish.storage`,
    // while `/var/lib/miraserve/acme` and `/var/lib/miraserve` itself are refused even for storage.
    let valid_pub = r#"
server {
    listen ":443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key"; }
}
site "pub.example.test" {
    ai-publish {
        storage "/var/lib/miraserve/releases/app"
        site-id "pub"
        require-signature "ed25519:/etc/miraserve/deploy.pub"
    }
}
"#;
    let _ = parse_kdl("valid-pub.kdl", valid_pub)?;

    let bad_pub = valid_pub.replace("/var/lib/miraserve/releases/app", "/var/lib/miraserve/acme");
    let bad_err = parse_kdl("bad-pub.kdl", &bad_pub)
        .err()
        .ok_or("expected E202 for ai-publish.storage pointing at /var/lib/miraserve/acme")?;
    assert!(error_codes(&bad_err).contains(&"E202".to_owned()));
    Ok(())
}

/// R7-CFG-1: Loading a config file from disk refuses `root "."` (or any site/route root equal to
/// or an ancestor of the config file's directory) with `E202`, while permitting a dedicated
/// subdirectory like `root "www"`.
#[test]
fn r7_cfg_1_rejects_docroot_containing_config_file() -> TestResult {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base =
        std::env::temp_dir().join(format!("miraserve-r7-cfg-1-{}-{nanos}", std::process::id()));
    let conf_dir = base.join("conf");
    let www_dir = base.join("www");
    std::fs::create_dir_all(&conf_dir)?;
    std::fs::create_dir_all(&www_dir)?;
    // Roots are compared as written; write the temp directory in its resolved form (macOS
    // reaches it through the /var -> /private/var link).
    let base = std::fs::canonicalize(&base)?;
    let conf_dir = base.join("conf");

    // 1. `root "."` resolves to the config file's own directory -> E202!
    let dot_cfg = base.join("site.kdl");
    std::fs::write(
        &dot_cfg,
        r#"
server {
    listen "127.0.0.1:8443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key"; }
}
site "localhost" {
    root "."
}
"#,
    )?;
    let dot_err = miraserve_config::load_file(&dot_cfg)
        .err()
        .ok_or("R7-CFG-1: `root \".\"` must be rejected with E202")?;
    assert!(
        error_codes(&dot_err).contains(&"E202".to_owned()),
        "expected E202, got: {:?}",
        dot_err.validation_errors()
    );

    // 2. Ancestor docroot containing `conf/site.kdl` -> E202!
    let nested_cfg = conf_dir.join("site.kdl");
    std::fs::write(
        &nested_cfg,
        format!(
            r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key"; }}
}}
site "localhost" {{
    root "{}"
}}
"#,
            kdl_path(&base)
        ),
    )?;
    let anc_err = miraserve_config::load_file(&nested_cfg)
        .err()
        .ok_or("R7-CFG-1: docroot that is an ancestor of config dir must be rejected with E202")?;
    assert!(error_codes(&anc_err).contains(&"E202".to_owned()));

    // 3. Dedicated subdirectory `root "www"` (not containing config dir) -> passes!
    let ok_cfg = base.join("ok.kdl");
    std::fs::write(
        &ok_cfg,
        r#"
server {
    listen "127.0.0.1:8443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key"; }
}
site "localhost" {
    root "www"
}
"#,
    )?;
    let (cfg, _) = miraserve_config::load_file(&ok_cfg)?;
    assert_eq!(cfg.sites.len(), 1);

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

/// R6-XFF-4, R7-XFF-2 & R6-DOS-1:
/// - Rejects `0.0.0.0/8`, `::/16`, CIDRs with host bits set (`10.0.0.1/8`, `2001:db8::1/32`),
///   and cumulative `trusted-proxies` covering >= 50% of IPv4 space (128+ `/8`s).
/// - Emits `W022` on IPv4 broader than `/24` or IPv6 broader than `/64`, clean on `/32` & `/128`.
/// - Emits `W021` on wildcard non-443 backend ports (`:8443`) serving production hostnames.
#[test]
fn r7_xff_2_r6_xff_4_trusted_proxies_host_bits_unspecified_aggregate_and_w022() -> TestResult {
    use std::fmt::Write as _;

    for bad_cidr in [
        "0.0.0.0/8",
        "::/16",
        "10.0.0.1/8",
        "192.168.1.5/24",
        "2001:db8::1/32",
    ] {
        let kdl = format!(
            r#"
server {{
    listen ":443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key"; }}
    limits {{ trusted-proxies "{bad_cidr}"; }}
}}
site "app.example.com" {{ root "/var/www/app"; }}
"#
        );
        let err = parse_kdl("bad-cidr.kdl", &kdl)
            .err()
            .ok_or_else(|| format!("R6-XFF-4: expected rejection for '{bad_cidr}'"))?;
        assert!(
            error_codes(&err).contains(&"E007".to_owned()),
            "expected E007 for '{bad_cidr}', got {err:?}"
        );
    }

    // Cumulative >= 50% IPv4 coverage via 130 distinct /8 entries MUST be rejected with E007!
    let mut many_cidrs = String::new();
    for octet in 1..=130_u8 {
        let _ = write!(many_cidrs, "\"{octet}.0.0.0/8\" ");
    }
    let union_kdl = format!(
        r#"
server {{
    listen ":443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key"; }}
    limits {{ trusted-proxies {many_cidrs}; }}
}}
site "app.example.com" {{ root "/var/www/app"; }}
"#
    );
    let union_err = parse_kdl("union.kdl", &union_kdl)
        .err()
        .ok_or("R6-XFF-4: 130 /8s covering >= 50% of IPv4 space must be rejected")?;
    assert!(error_codes(&union_err).contains(&"E007".to_owned()));

    // Exact /32 and /128 proxy IPs pass with ZERO warnings!
    let exact_kdl = r#"
server {
    listen ":8443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key"; }
    limits { trusted-proxies "10.0.1.10/32" "2001:db8:1::1/128"; }
}
site "app.example.com" { root "/var/www/app"; }
"#;
    let (_, exact_rep) = parse_kdl("exact.kdl", exact_kdl)?;
    assert!(
        exact_rep.is_clean(),
        "exact /32 & /128 trusted-proxies should emit zero warnings, got {:?}",
        exact_rep.warnings
    );

    // Wildcard non-443 backend port (`:8443`) with production hostname without trusted-proxies -> W021!
    let wildcard_backend = r#"
server {
    listen ":8443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key"; }
}
site "app.example.com" { root "/var/www/app"; }
"#;
    let (_, wb_rep) = parse_kdl("wb.kdl", wildcard_backend)?;
    assert!(
        wb_rep.warnings.iter().any(|w| w.code == "W021"),
        "R6-DOS-1: wildcard :8443 backend listener with production host should emit W021, got {:?}",
        wb_rep.warnings
    );

    Ok(())
}

/// Review 2: `reverse-proxy { preserve-host #true }` parses, defaults to off, and rejects a
/// non-boolean value.
#[test]
fn review2_reverse_proxy_preserve_host_parses_and_defaults_off() -> TestResult {
    let kdl = |extra: &str| {
        format!(
            r#"
server {{
    listen ":443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }}
}}
site "app.example" {{
    route "/*" {{
        reverse-proxy {{
            upstream "http://127.0.0.1:3000"
            {extra}
        }}
    }}
}}
"#
        )
    };
    let preserve_of = |text: &str| -> Result<bool, Box<dyn std::error::Error>> {
        let (cfg, _) = parse_kdl("preserve-host.kdl", text)?;
        let route = cfg
            .sites
            .first()
            .and_then(|s| s.routes.first())
            .ok_or("missing route")?;
        match &route.handler {
            RouteHandler::ReverseProxy(rp) => Ok(rp.preserve_host),
            other => Err(format!("unexpected handler: {other:?}").into()),
        }
    };
    assert!(!preserve_of(&kdl(""))?, "preserve-host must default to off");
    assert!(preserve_of(&kdl("preserve-host #true"))?);
    assert!(!preserve_of(&kdl("preserve-host #false"))?);
    assert!(
        parse_kdl("preserve-host-bad.kdl", &kdl("preserve-host \"yes\"")).is_err(),
        "a non-boolean preserve-host value must be rejected"
    );

    // `allow-upgrades` defaults to on (the behaviour before the option existed).
    let upgrades_of = |text: &str| -> Result<bool, Box<dyn std::error::Error>> {
        let (cfg, _) = parse_kdl("allow-upgrades.kdl", text)?;
        let route = cfg
            .sites
            .first()
            .and_then(|s| s.routes.first())
            .ok_or("missing route")?;
        match &route.handler {
            RouteHandler::ReverseProxy(rp) => Ok(rp.allow_upgrades),
            other => Err(format!("unexpected handler: {other:?}").into()),
        }
    };
    assert!(upgrades_of(&kdl(""))?, "allow-upgrades must default to on");
    assert!(!upgrades_of(&kdl("allow-upgrades #false"))?);
    assert!(upgrades_of(&kdl("allow-upgrades #true"))?);
    assert!(
        parse_kdl("allow-upgrades-bad.kdl", &kdl("allow-upgrades 1")).is_err(),
        "a non-boolean allow-upgrades value must be rejected"
    );

    // Review 4: a health probe must reach the same virtual host as real requests.
    let hc = "health-check path=\"/health\" interval=\"5s\"";
    assert!(
        parse_kdl("hc-plain.kdl", &kdl(hc)).is_ok(),
        "a health check without preserve-host needs no host"
    );
    assert!(
        parse_kdl(
            "hc-preserve-no-host.kdl",
            &kdl(&format!("preserve-host #true\n            {hc}"))
        )
        .is_err(),
        "preserve-host with a health check must require a probe host"
    );
    assert!(
        parse_kdl(
            "hc-preserve-host.kdl",
            &kdl(&format!(
                "preserve-host #true\n            {hc} host=\"app.example\""
            ))
        )
        .is_ok()
    );
    assert!(
        parse_kdl(
            "hc-host-no-preserve.kdl",
            &kdl(&format!("{hc} host=\"app.example\""))
        )
        .is_err(),
        "a probe host without preserve-host would test a different virtual host"
    );
    assert!(
        parse_kdl(
            "hc-bad-host.kdl",
            &kdl(&format!(
                "preserve-host #true\n            {hc} host=\"a b\\r\\nX: y\""
            ))
        )
        .is_err(),
        "a probe host must be a plain hostname"
    );
    Ok(())
}

#[test]
fn site_index_order_parses_and_rejects_invalid_entries() -> Result<(), Box<dyn std::error::Error>> {
    let ok_kdl = r#"
server {
    listen ":443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }
}
site "php.example.com" {
    root "/var/www/php"
    index "index.php" "index.html"
    route "*.php" { fastcgi-pass "unix:/run/php/php-fpm.sock" }
}
"#;
    let (cfg, _) = parse_kdl("site-index.kdl", ok_kdl)?;
    let site = cfg.sites.first().ok_or("missing site")?;
    assert_eq!(
        site.index.as_deref(),
        Some(&["index.php".to_owned(), "index.html".to_owned()][..])
    );
    // FastCGI `*.php` matches PATH_INFO paths like `/script.php/extra` consistently in `match_route`.
    assert!(site.match_route("/script.php/extra").is_some());
    assert!(site.match_route("/script.php").is_some());

    for bad in ["\"../evil.php\"", "\".env\"", "\"sub/index.php\"", "\"\""] {
        let bad_kdl = format!(
            r#"
server {{
    listen ":443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }}
}}
site "php.example.com" {{
    root "/var/www/php"
    index {bad}
}}
"#
        );
        assert!(
            parse_kdl("bad-index.kdl", &bad_kdl).is_err(),
            "invalid index entry {bad} must be rejected"
        );
    }
    Ok(())
}

#[test]
fn wave6_ipv6_site_names_and_config_issue_key_paths() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Bare and bracketed IPv6 literals are valid site names (HANDOVER §5 #11).
    let ok_v6 = r#"
server {
    listen "[::]:443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }
}
site "[2001:db8::1]" {
    root "/var/www/v6-a"
}
site "::1" {
    root "/var/www/v6-b"
}
"#;
    let (cfg, _) = parse_kdl("ipv6-ok.kdl", ok_v6)?;
    assert_eq!(cfg.sites.len(), 2);

    // 2. Canonical duplicates (`[2001:db8:0::1]` vs `2001:db8::1`) are rejected with E107 + path!
    let dup_v6 = r#"
server {
    listen "[::]:443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }
}
site "[2001:db8:0:0::1]" {
    root "/var/www/v6-a"
}
site "2001:db8::1" {
    root "/var/www/v6-b"
}
"#;
    let dup_err = parse_kdl("ipv6-dup.kdl", dup_v6)
        .err()
        .ok_or("expected duplicate canonical IPv6 site to fail with E107")?;
    let e107 = dup_err
        .validation_errors()
        .iter()
        .find(|i| i.code == "E107")
        .ok_or("expected E107 issue")?;
    assert_eq!(
        e107.path.as_deref(),
        Some("site[1].host[0]"),
        "validation error must include dotted config key path"
    );

    // 3. IPv6 with port `[::1]:443` and wildcard `*.::1` are still rejected with E107.
    for bad in ["[::1]:443", "*.::1", "example.com:8080"] {
        let bad_kdl = format!(
            r#"
server {{
    listen ":443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }}
}}
site "{bad}" {{
    root "/var/www/bad"
}}
"#
        );
        let err = parse_kdl("ipv6-bad.kdl", &bad_kdl)
            .err()
            .ok_or_else(|| format!("expected '{bad}' to be rejected with E107"))?;
        assert!(error_codes(&err).contains(&"E107".to_owned()));
    }
    Ok(())
}

/// Verifies that W021 does not fire for an extra listener port beside `:443` or for a bracketed
/// IPv6 literal (`site "[::1]"`), while still warning for a non-standard port with a hostname.
#[test]
fn w021_ignores_an_extra_port_beside_443_and_bracketed_ipv6_site_names() {
    let has_w021 = |kdl: &str| match parse_kdl("w021.kdl", kdl) {
        Ok((_, report)) => report.warnings.iter().any(|w| w.code == "W021"),
        Err(err) => err.validation_warnings().iter().any(|w| w.code == "W021"),
    };
    let tls = r#"tls { cert "/c.pem"; key "/k.pem" }"#;

    assert!(
        !has_w021(&format!(
            "server {{ listen \":443\"; listen \":3080\"; {tls} }}\nsite \"shop.example.com\" {{ root \"/var/www/shop\" }}\n"
        )),
        "an extra port beside :443 is not a load-balancer backend"
    );
    assert!(
        has_w021(&format!(
            "server {{ listen \":8443\"; {tls} }}\nsite \"shop.example.com\" {{ root \"/var/www/shop\" }}\n"
        )),
        "control: only a non-standard port with a real hostname still warns"
    );
    assert!(
        !has_w021(&format!(
            "server {{ listen \":8443\"; {tls} }}\nsite \"[::1]\" {{ root \"/var/www/shop\" }}\n"
        )),
        "a bracketed IPv6 literal is an address, like 127.0.0.1"
    );
}

/// `min-response-rate-bytes-per-sec` is the clear name of `min-response-rate-bps`; both work,
/// and setting both is refused.
#[test]
fn min_response_rate_has_a_clear_name_and_the_old_one_still_works() -> TestResult {
    let config = |timeouts: &str| {
        format!(
            r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
    timeouts {{ {timeouts} }}
}}
site "rate.example.test" {{ root "/srv/www" }}
"#
        )
    };
    let (new_name, _) = parse_kdl("a.kdl", &config("min-response-rate-bytes-per-sec 2048"))?;
    assert_eq!(new_name.server.timeouts.min_response_rate_bps, 2048);
    let (old_name, _) = parse_kdl("b.kdl", &config("min-response-rate-bps 4096"))?;
    assert_eq!(old_name.server.timeouts.min_response_rate_bps, 4096);
    let both = parse_kdl(
        "c.kdl",
        &config("min-response-rate-bps 1; min-response-rate-bytes-per-sec 2"),
    );
    assert!(
        both.as_ref()
            .err()
            .is_some_and(|err| error_codes(err).contains(&"E003".to_owned())),
        "setting both names must be refused"
    );
    Ok(())
}

#[test]
fn site_http_directive_parses_valid_modes_and_rejects_invalid_ones() -> TestResult {
    let base_tls = r#"tls { cert "/c.pem"; key "/k.pem" }"#;

    // Default is Redirect; explicit "redirect" and "serve" parse cleanly with a redirect-https listener.
    let valid_kdl = format!(
        r#"
server {{
    listen ":443"
    listen ":80" redirect-https=#true
    {base_tls}
}}
site "default.example.test" {{
    root "/var/www/default"
}}
site "redir.example.test" {{
    http "redirect"
    root "/var/www/redir"
}}
site "plain.example.test" {{
    http "serve"
    root "/var/www/plain"
}}
"#
    );
    let (cfg, report) = parse_kdl("http-valid.kdl", &valid_kdl)?;
    assert_eq!(cfg.sites.len(), 3);
    assert_eq!(
        cfg.sites.first().map(|s| s.http),
        Some(SiteHttpMode::Redirect)
    );
    assert_eq!(
        cfg.sites.get(1).map(|s| s.http),
        Some(SiteHttpMode::Redirect)
    );
    assert_eq!(cfg.sites.get(2).map(|s| s.http), Some(SiteHttpMode::Serve));
    assert!(
        !report.warnings.iter().any(|w| w.code == "W031"),
        "expected no W031 when a redirect-https listener exists, got: {:?}",
        report.warnings
    );

    // Unknown value -> E203 with helpful hint mentioning supported values.
    let unknown_kdl = format!(
        r#"
server {{
    listen ":443"
    listen ":80" redirect-https=#true
    {base_tls}
}}
site "bad.example.test" {{
    http "allow"
    root "/var/www/bad"
}}
"#
    );
    let err = parse_kdl("http-unknown.kdl", &unknown_kdl)
        .err()
        .ok_or("expected unknown site http mode to fail")?;
    let e203 = err
        .validation_errors()
        .iter()
        .find(|issue| issue.code == "E203")
        .ok_or_else(|| format!("expected E203, got {:?}", err.validation_errors()))?;
    assert!(
        e203.help
            .as_deref()
            .is_some_and(|h| h.contains("redirect") && h.contains("serve")),
        "expected hint to name supported modes, got: {:?}",
        e203.help
    );

    // Duplicate `http` -> E005.
    let dup_kdl = format!(
        r#"
server {{
    listen ":443"
    listen ":80" redirect-https=#true
    {base_tls}
}}
site "dup.example.test" {{
    http "redirect"
    http "serve"
    root "/var/www/dup"
}}
"#
    );
    let dup_err = parse_kdl("http-dup.kdl", &dup_kdl)
        .err()
        .ok_or("expected duplicate http directive to fail")?;
    assert!(
        error_codes(&dup_err).contains(&"E005".to_owned()),
        "expected E005, got {:?}",
        dup_err.validation_errors()
    );
    Ok(())
}

#[test]
fn site_http_serve_warns_w031_when_no_redirect_https_listener() -> TestResult {
    let no_http_listener_kdl = r#"
server {
    listen ":443"
    tls { cert "/c.pem"; key "/k.pem" }
}
site "orphan.example.test" {
    http "serve"
    root "/var/www/orphan"
}
"#;
    let (_, warn_report) = parse_kdl("http-no-listener.kdl", no_http_listener_kdl)?;
    let w031 = warn_report
        .warnings
        .iter()
        .find(|w| w.code == "W031")
        .ok_or_else(|| format!("expected W031 warning, got: {:?}", warn_report.warnings))?;
    assert_eq!(w031.path.as_deref(), Some("site[0].http"));
    assert_eq!(w031.location.as_ref().map(|loc| loc.line), Some(7));
    Ok(())
}

#[allow(clippy::too_many_lines)]
#[test]
fn site_http_credentials_property_parses_warns_and_rejects_invalid_uses() -> TestResult {
    let base_server = r#"
server {
    listen ":443"
    listen ":80" redirect-https=#true
    tls { cert "/c.pem"; key "/k.pem" }
}
"#;

    // `credentials=#true` on `http "serve"` -> parses true + emits W032 naming the site.
    // `credentials=#false` on `http "serve"` -> parses false + no W032.
    let valid_kdl = format!(
        r#"{base_server}
site "cleartext.example.test" {{
    http "serve" credentials=#true
    root "/var/www/cleartext"
}}
site "explicit-false.example.test" {{
    http "serve" credentials=#false
    root "/var/www/false"
}}
site "default-serve.example.test" {{
    http "serve"
    root "/var/www/default"
}}
"#
    );
    let (cfg, report) = parse_kdl("http-creds-valid.kdl", &valid_kdl)?;
    assert_eq!(cfg.sites.len(), 3);
    assert_eq!(cfg.sites.first().map(|s| s.http), Some(SiteHttpMode::Serve));
    assert_eq!(
        cfg.sites.first().map(|s| s.http_credentials),
        Some(true),
        "expected http_credentials=true on site[0]"
    );
    assert_eq!(cfg.sites.get(1).map(|s| s.http), Some(SiteHttpMode::Serve));
    assert_eq!(
        cfg.sites.get(1).map(|s| s.http_credentials),
        Some(false),
        "expected http_credentials=false on site[1]"
    );
    assert_eq!(
        cfg.sites.get(2).map(|s| s.http_credentials),
        Some(false),
        "expected default http_credentials=false on site[2]"
    );
    let w032s: Vec<_> = report
        .warnings
        .iter()
        .filter(|w| w.code == "W032")
        .collect();
    assert_eq!(
        w032s.len(),
        1,
        "expected exactly one W032 warning, got: {w032s:?}"
    );
    let w032 = w032s.first().ok_or("missing W032")?;
    assert_eq!(
        w032.message,
        "passwords for cleartext.example.test travel unencrypted over plain HTTP (http \"serve\" credentials=#true)"
    );
    assert_eq!(w032.path.as_deref(), Some("site[0].http"));

    // `credentials` on `http "redirect"` is ALWAYS a config error (both #true and #false).
    for prop in ["credentials=#true", "credentials=#false"] {
        let kdl = format!(
            r#"{base_server}
site "redir.example.test" {{
    http "redirect" {prop}
    root "/var/www/redir"
}}
"#
        );
        let err = parse_kdl("http-creds-redirect.kdl", &kdl)
            .err()
            .ok_or_else(|| format!("expected `http \"redirect\" {prop}` to fail"))?;
        assert!(
            error_codes(&err).contains(&"E003".to_owned()),
            "expected E003 for `http \"redirect\" {prop}`, got {:?}",
            err.validation_errors()
        );
    }

    // Wrong type for `credentials` -> E004.
    for bad_val in [r#"credentials="true""#, "credentials=1"] {
        let kdl = format!(
            r#"{base_server}
site "badtype.example.test" {{
    http "serve" {bad_val}
    root "/var/www/badtype"
}}
"#
        );
        let err = parse_kdl("http-creds-badtype.kdl", &kdl)
            .err()
            .ok_or_else(|| format!("expected `{bad_val}` to fail"))?;
        assert!(
            error_codes(&err).contains(&"E004".to_owned()),
            "expected E004 for `{bad_val}`, got {:?}",
            err.validation_errors()
        );
    }

    // Unknown property on `http` -> E003.
    for mode in ["serve", "redirect"] {
        let kdl = format!(
            r#"{base_server}
site "unknown-prop.example.test" {{
    http "{mode}" extra=#true
    root "/var/www/unknown"
}}
"#
        );
        let err = parse_kdl("http-unknown-prop.kdl", &kdl)
            .err()
            .ok_or_else(|| format!("expected unknown property on `http \"{mode}\"` to fail"))?;
        assert!(
            error_codes(&err).contains(&"E003".to_owned()),
            "expected E003 for unknown property on `http \"{mode}\"`, got {:?}",
            err.validation_errors()
        );
    }
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn precompressed_policy_parses_valid_forms_and_rejects_invalid_inputs() -> TestResult {
    let base_server = r#"
server {
    listen ":443"
    tls { cert "/etc/miraserve/c.pem"; key "/etc/miraserve/k.pem" }
    sandbox { user "miraserve"; landlock #true; seccomp "strict" }
}
"#;
    let valid_kdl = format!(
        r#"{base_server}
site "default-off.example.test" {{
    root "/var/www/default-off"
}}
site "explicit-off.example.test" {{
    precompressed "off"
    root "/var/www/explicit-off"
}}
site "subset.example.test" {{
    precompressed "gz" "br"
    root "/var/www/subset"
    route "/all/*" {{
        static {{
            precompressed "all"
        }}
    }}
    route "/none/*" {{
        static {{
            precompressed "off"
        }}
    }}
    route "/inherit/*" {{
        static
    }}
}}
site "all.example.test" {{
    precompressed "all"
    root "/var/www/all"
}}
"#
    );
    let (cfg, _) = parse_kdl("precompressed-valid.kdl", &valid_kdl)?;
    assert_eq!(cfg.sites.len(), 4);
    assert_eq!(
        cfg.sites.first().map(|s| s.precompressed),
        Some(PrecompressedPolicy::OFF)
    );
    assert_eq!(
        cfg.sites.get(1).map(|s| s.precompressed),
        Some(PrecompressedPolicy::OFF)
    );
    let subset_expected = PrecompressedPolicy {
        zst: false,
        br: true,
        gz: true,
    };
    assert_eq!(
        cfg.sites.get(2).map(|s| s.precompressed),
        Some(subset_expected)
    );
    assert_eq!(subset_expected.enabled_names(), vec!["br", "gz"]);
    assert_eq!(
        cfg.sites.get(3).map(|s| s.precompressed),
        Some(PrecompressedPolicy::ALL)
    );
    assert_eq!(
        PrecompressedPolicy::ALL.enabled_names(),
        vec!["zst", "br", "gz"]
    );

    let subset_routes = &cfg.sites.get(2).ok_or("missing site[2]")?.routes;
    match subset_routes.first().map(|r| &r.handler) {
        Some(RouteHandler::Static(st)) => {
            assert_eq!(st.precompressed, PrecompressedPolicy::ALL);
            assert!(st.precompressed_explicit);
        }
        other => return Err(format!("expected Static route[0], got {other:?}").into()),
    }
    match subset_routes.get(1).map(|r| &r.handler) {
        Some(RouteHandler::Static(st)) => {
            assert_eq!(st.precompressed, PrecompressedPolicy::OFF);
            assert!(st.precompressed_explicit);
        }
        other => return Err(format!("expected Static route[1], got {other:?}").into()),
    }
    match subset_routes.get(2).map(|r| &r.handler) {
        Some(RouteHandler::Static(st)) => {
            assert_eq!(st.precompressed, PrecompressedPolicy::OFF);
            assert!(!st.precompressed_explicit);
        }
        other => return Err(format!("expected Static route[2], got {other:?}").into()),
    }

    for (label, directive, expected_code) in [
        ("empty", "precompressed", "E004"),
        ("unknown gzip", r#"precompressed "gzip""#, "E203"),
        ("unknown brotli", r#"precompressed "brotli""#, "E203"),
        ("unknown zstd", r#"precompressed "zstd""#, "E203"),
        ("unknown uppercase", r#"precompressed "BR""#, "E203"),
        ("unknown deflate", r#"precompressed "deflate""#, "E203"),
        ("duplicate br", r#"precompressed "br" "br""#, "E005"),
        ("duplicate gz", r#"precompressed "gz" "br" "gz""#, "E005"),
        ("duplicate off", r#"precompressed "off" "off""#, "E005"),
        ("duplicate all", r#"precompressed "all" "all""#, "E005"),
        ("off mixed with br", r#"precompressed "off" "br""#, "E203"),
        ("gz mixed with off", r#"precompressed "gz" "off""#, "E203"),
        ("off mixed with all", r#"precompressed "off" "all""#, "E203"),
        ("all mixed with br", r#"precompressed "all" "br""#, "E203"),
        ("zst mixed with all", r#"precompressed "zst" "all""#, "E203"),
        ("non-string bool", "precompressed #true", "E004"),
        (
            "unknown property",
            r#"precompressed "br" extra=#true"#,
            "E003",
        ),
        ("child block", r#"precompressed "br" { x 1 }"#, "E004"),
        (
            "duplicate directive",
            "precompressed \"br\"\n    precompressed \"gz\"",
            "E005",
        ),
    ] {
        let kdl = format!(
            r#"{base_server}
site "bad.example.test" {{
    {directive}
    root "/var/www/bad"
}}
"#
        );
        let err = parse_kdl("precompressed-bad.kdl", &kdl)
            .err()
            .ok_or_else(|| format!("expected `{label}` ({directive}) to fail"))?;
        assert!(
            error_codes(&err).contains(&expected_code.to_owned()),
            "expected {expected_code} for `{label}` ({directive}), got {:?}",
            err.validation_errors()
        );
    }

    // Route-level `static { precompressed ... }` enforces the exact same validation rules.
    let bad_route_kdl = format!(
        r#"{base_server}
site "bad-route.example.test" {{
    root "/var/www/bad"
    route "/assets/*" {{
        static {{
            precompressed "off" "br"
        }}
    }}
}}
"#
    );
    let err = parse_kdl("precompressed-bad-route.kdl", &bad_route_kdl)
        .err()
        .ok_or("expected route-level `precompressed \"off\" \"br\"` to fail")?;
    assert!(error_codes(&err).contains(&"E203".to_owned()));
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn header_rule_status_condition_parses_and_rejects_invalid_lists() -> TestResult {
    let base_server = r#"
server {
    listen ":443"
    tls { cert "/etc/miraserve/c.pem"; key "/etc/miraserve/k.pem" }
    sandbox { user "miraserve"; landlock #true; seccomp "strict" }
}
"#;
    let valid_kdl = format!(
        r#"{base_server}
site "hdr.example.test" {{
    root "/var/www/hdr"
    headers {{
        set "Cache-Control" "no-cache"
        add "X-Error" "yes" status="4xx 5xx"
        remove "X-Debug" status="200 206 304"
    }}
    route "/assets/*" {{
        static
        headers {{
            set "cache-control" "public, max-age=31536000, immutable" status="  200   206 304 "
            add "X-Class" "ok" status="2xx 3xx"
        }}
    }}
}}
"#
    );
    let (cfg, _) = parse_kdl("header-status-valid.kdl", &valid_kdl)?;
    let site = cfg.sites.first().ok_or("missing site[0]")?;
    assert_eq!(site.headers.len(), 3);
    assert!(site.headers.first().is_some_and(|r| r.status.is_empty()));
    assert_eq!(
        site.headers.get(1).map(|r| r.status.as_slice()),
        Some([HeaderStatusMatcher::Class(4), HeaderStatusMatcher::Class(5),].as_slice())
    );
    assert_eq!(
        site.headers.get(2).map(|r| r.status.as_slice()),
        Some(
            [
                HeaderStatusMatcher::Code(200),
                HeaderStatusMatcher::Code(206),
                HeaderStatusMatcher::Code(304),
            ]
            .as_slice()
        )
    );
    let route = site.routes.first().ok_or("missing route[0]")?;
    assert_eq!(
        route.headers.first().map(|r| r.status.as_slice()),
        Some(
            [
                HeaderStatusMatcher::Code(200),
                HeaderStatusMatcher::Code(206),
                HeaderStatusMatcher::Code(304),
            ]
            .as_slice()
        )
    );
    assert_eq!(
        route.headers.get(1).map(|r| r.status.as_slice()),
        Some([HeaderStatusMatcher::Class(2), HeaderStatusMatcher::Class(3),].as_slice())
    );

    for (label, rule) in [
        ("empty status", r#"set "X-A" "1" status="""#),
        ("whitespace only", r#"set "X-A" "1" status="   ""#),
        ("comma separated", r#"set "X-A" "1" status="200,304""#),
        ("tab separated", r#"set "X-A" "1" status="200\t304""#),
        ("newline separated", r#"set "X-A" "1" status="200\n304""#),
        ("non-string int", r#"set "X-A" "1" status=200"#),
        ("non-string bool", r#"set "X-A" "1" status=#true"#),
        ("1xx unsupported", r#"set "X-A" "1" status="1xx""#),
        ("6xx unsupported", r#"set "X-A" "1" status="6xx""#),
        ("0xx unsupported", r#"set "X-A" "1" status="0xx""#),
        ("uppercase 2XX", r#"set "X-A" "1" status="2XX""#),
        ("short class 2x", r#"set "X-A" "1" status="2x""#),
        ("below 200 (100)", r#"set "X-A" "1" status="100""#),
        ("below 200 (199)", r#"set "X-A" "1" status="199""#),
        ("above 599 (600)", r#"set "X-A" "1" status="600""#),
        ("two digits", r#"set "X-A" "1" status="20""#),
        ("four digits", r#"set "X-A" "1" status="0200""#),
        ("signed", r#"set "X-A" "1" status="+200""#),
        ("non-numeric", r#"set "X-A" "1" status="ok""#),
        ("duplicate code", r#"set "X-A" "1" status="200 200""#),
        ("duplicate class", r#"set "X-A" "1" status="2xx 2xx""#),
        (
            "unknown property",
            r#"set "X-A" "1" status="200" foo="bar""#,
        ),
        ("remove invalid status", r#"remove "X-A" status="999""#),
        ("add invalid status", r#"add "X-A" "1" status="1xx""#),
    ] {
        let kdl = format!(
            r#"{base_server}
site "bad-hdr.example.test" {{
    root "/var/www/bad"
    headers {{
        {rule}
    }}
}}
"#
        );
        let err = parse_kdl("header-status-bad.kdl", &kdl)
            .err()
            .ok_or_else(|| format!("expected `{label}` ({rule}) to fail"))?;
        assert!(
            error_codes(&err).contains(&"E309".to_owned()),
            "expected E309 for `{label}` ({rule}), got {:?}",
            err.validation_errors()
        );
    }

    // Over 64 status entries is rejected.
    let too_many: String = (200_u16..265)
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let over_kdl = format!(
        r#"{base_server}
site "many-hdr.example.test" {{
    root "/var/www/many"
    headers {{
        set "X-Many" "1" status="{too_many}"
    }}
}}
"#
    );
    let err = parse_kdl("header-status-many.kdl", &over_kdl)
        .err()
        .ok_or("expected > 64 status entries to fail")?;
    assert!(error_codes(&err).contains(&"E309".to_owned()));
    Ok(())
}

#[test]
fn file_cache_config_parsing_defaults_and_bounds() -> TestResult {
    let make = |limits_extra: &str, site_extra: &str| {
        format!(
            r#"
server {{
    listen ":443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
    limits {{ {limits_extra} }}
}}
site "cache.example.test" {{
    root "/var/www/cache"
    {site_extra}
}}
"#
        )
    };

    // Default: off on site, 64MiB process-wide budget, zero warnings.
    let (cfg, report) = parse_kdl("default.kdl", &make("", ""))?;
    assert!(
        report.warnings.is_empty(),
        "warnings: {:?}",
        report.warnings
    );
    assert_eq!(
        cfg.server.limits.file_cache_bytes,
        ByteSize::from_bytes(64 * ByteSize::MIB)
    );
    assert_eq!(cfg.sites.first().and_then(|s| s.file_cache), None);

    // Explicit "off" on site and "0" / integer 0 on limits.file-cache-bytes.
    let (cfg_off, report_off) = parse_kdl(
        "off.kdl",
        &make("file-cache-bytes \"0\"", "file-cache \"off\""),
    )?;
    assert!(report_off.warnings.is_empty());
    assert_eq!(cfg_off.server.limits.file_cache_bytes.as_bytes(), 0);
    assert_eq!(cfg_off.sites.first().and_then(|s| s.file_cache), None);

    let (cfg_zero_int, _) = parse_kdl("zero-int.kdl", &make("file-cache-bytes 0", ""))?;
    assert_eq!(cfg_zero_int.server.limits.file_cache_bytes.as_bytes(), 0);

    // Valid window boundaries: 100ms, 1s, 60s; valid budgets: 1KiB, 1GiB.
    for (raw_win, expected) in [
        ("100ms", Duration::from_millis(100)),
        ("1s", Duration::from_secs(1)),
        ("60s", Duration::from_secs(60)),
        ("1m", Duration::from_secs(60)),
    ] {
        let (cfg_ok, rep) = parse_kdl(
            "valid.kdl",
            &make(
                "file-cache-bytes \"1GiB\"",
                &format!("file-cache \"{raw_win}\""),
            ),
        )?;
        assert!(
            rep.warnings.is_empty(),
            "file-cache {raw_win} must not emit warnings: {:?}",
            rep.warnings
        );
        assert_eq!(
            cfg_ok.sites.first().and_then(|s| s.file_cache),
            Some(expected)
        );
        assert_eq!(
            cfg_ok.server.limits.file_cache_bytes.as_bytes(),
            ByteSize::GIB
        );
    }

    // Invalid site file-cache windows: below 100ms, above 60s, malformed.
    for bad_win in ["0ms", "99ms", "61s", "2m", "not-a-duration", ""] {
        let err = parse_kdl(
            "bad-win.kdl",
            &make("", &format!("file-cache \"{bad_win}\"")),
        )
        .err()
        .ok_or_else(|| format!("expected file-cache '{bad_win}' to fail"))?;
        assert!(
            error_codes(&err).contains(&"E007".to_owned()),
            "file-cache '{bad_win}' errors: {:?}",
            error_codes(&err)
        );
    }

    // Duplicate file-cache rejected with E005.
    let dup_err = parse_kdl("dup.kdl", &make("", "file-cache \"1s\"\nfile-cache \"2s\""))
        .err()
        .ok_or("expected duplicate file-cache to fail")?;
    assert!(error_codes(&dup_err).contains(&"E005".to_owned()));

    // Invalid limits.file-cache-bytes: > 1GiB, non-zero bare integer, malformed string.
    for bad_budget in [
        "file-cache-bytes \"2GiB\"",
        "file-cache-bytes 1024",
        "file-cache-bytes \"nope\"",
    ] {
        let err = parse_kdl("bad-budget.kdl", &make(bad_budget, ""))
            .err()
            .ok_or_else(|| format!("expected '{bad_budget}' to fail"))?;
        assert!(
            error_codes(&err).contains(&"E007".to_owned()),
            "'{bad_budget}' errors: {:?}",
            error_codes(&err)
        );
    }
    Ok(())
}

/// `workers` in `server`: "shared" (the default), "auto" or a number from 1 to 256; anything
/// else is refused.
#[test]
fn server_workers_setting_parses_and_validates() -> Result<(), Box<dyn std::error::Error>> {
    use miraserve_config::Workers;
    let with = |line: &str| {
        format!(
            r#"
server {{
    listen ":443"
    tls {{ cert "/etc/miraserve/certs/starter.crt"; key "/etc/miraserve/certs/starter.key" }}
    {line}
}}
site "workers.example.test" {{
    root "/var/www/html"
}}
"#
        )
    };
    let (plain, _) = parse_kdl("workers-none.kdl", &with(""))?;
    assert_eq!(plain.server.workers, Workers::Shared);
    assert!(plain.server.workers.is_shared());
    for (line, expected) in [
        (r#"workers "shared""#, Workers::Shared),
        (r#"workers "auto""#, Workers::Auto),
        ("workers 1", Workers::Count(1)),
        ("workers 256", Workers::Count(256)),
    ] {
        let (cfg, _) = parse_kdl("workers.kdl", &with(line))?;
        assert_eq!(cfg.server.workers, expected, "{line}");
    }
    for line in [
        "workers 0",
        "workers 257",
        r#"workers "many""#,
        "workers 2 3",
        "workers 2 fast=#true",
    ] {
        assert!(parse_kdl("workers-bad.kdl", &with(line)).is_err(), "{line}");
    }
    Ok(())
}

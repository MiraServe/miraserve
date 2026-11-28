//! Stage 2 (0.1.8) oracle tests for KDL host-filesystem path edge-whitespace rejection.
//!
//! Structured as two strict sets:
//! - Parity cases (`parity_*`): MUST pass on both `441a58d` (0.1.7 baseline) and the 0.1.8 branch.
//! - Rejection cases (`reject_*`): MUST fail on `441a58d` and pass on the 0.1.8 branch.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use common::kdl_escape_path;
use miraserve_config::{
    ConfigError, ConfigIssue, load_file_detailed, parse_kdl_detailed,
    parse_kdl_detailed_with_base_dir,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const EXPECTED_HELP: &str = "verify which directory or file currently holds live data before editing the path; remove leading or trailing whitespace from the configured path";

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Result<Self, std::io::Error> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = PathBuf::from(format!(
            "/tmp/ms-pws-cfg-{tag}-{}-{nanos}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn expect_validation_errors(
    res: Result<miraserve_config::LoadedConfig, ConfigError>,
) -> Result<Vec<ConfigIssue>, Box<dyn std::error::Error>> {
    match res {
        Ok(loaded) => Err(format!(
            "expected ConfigError::Validation, but config loaded cleanly (sites={})",
            loaded.config.sites.len()
        )
        .into()),
        Err(ConfigError::Validation { errors, .. }) => Ok(errors),
        Err(other) => Err(format!("expected ConfigError::Validation, got: {other}").into()),
    }
}

fn find_single_e202<'a>(
    errors: &'a [ConfigIssue],
    expected_path: &str,
    expected_message: &str,
) -> Result<&'a ConfigIssue, Box<dyn std::error::Error>> {
    let matching: Vec<&ConfigIssue> = errors
        .iter()
        .filter(|e| e.code == "E202" && e.path.as_deref() == Some(expected_path))
        .collect();
    let [issue] = matching.as_slice() else {
        return Err(format!(
            "expected exactly 1 E202 at '{expected_path}', got errors: {errors:#?}"
        )
        .into());
    };
    assert_eq!(
        issue.message, expected_message,
        "unexpected message for '{expected_path}': {issue:#?}"
    );
    assert_eq!(
        issue.help.as_deref(),
        Some(EXPECTED_HELP),
        "unexpected help for '{expected_path}': {issue:#?}"
    );
    assert!(
        issue.location.is_some(),
        "expected a real source location for '{expected_path}': {issue:#?}"
    );
    Ok(issue)
}

// ============================================================================
// PARITY ORACLE CASES — must pass on BOTH 441a58d AND the 0.1.8 branch
// ============================================================================

#[test]
fn parity_clean_paths_with_internal_spaces_and_windows_drive_paths() -> TestResult {
    let kdl = r#"
server {
    listen ":443"
    acme-webroot "/srv/acme webroot/dir"
    allow-docroot "/var/lib/my app/public" "/var/lib/other app/site"
    tls {
        key-isolation "split-daemon"
        keyd-socket "/run/miraserve keyd/keyd socket.sock"
        cert "/etc/my certs/server cert.pem"
        key "/etc/my keys/server key.pem"
        client-ca "/etc/my certs/client ca.pem"
    }
    sandbox {
        read-tree "/srv/web roots" "/home/panel sites"
        socket-tree "/run/php pools"
    }
}
site "spaces.example" {
    owner-dir "/srv/tenants/alice home"
    basic-auth "/etc/my auth/alice users.htpasswd" realm="Members"
    root "/srv/tenants/alice home/public html"
    tls {
        cert "/etc/my certs/alice cert.pem"
        key "/etc/my keys/alice key.pem"
        client-ca "/etc/my certs/alice ca.pem"
    }
    bot-auth {
        agent-keys-file "/etc/my bots/agent keys.json"
    }
    error-pages {
        page 404 "custom errors/not found.html"
        page 503 "/srv/tenants/alice home/custom errors/503 page.html"
    }
    route "/static/*" {
        root "/srv/tenants/alice home/static files"
        static {
            index "index.html"
        }
    }
    route "*.php" {
        fastcgi-pass "unix:/run/php pools/alice pool.sock"
    }
    route "/plugin/*" {
        wasm-plugin "/opt/my plugins/hello world.wasm"
    }
    route "/mcp/*" {
        mcp-gateway upstream="https://127.0.0.1:9001" {
            jwt-public-key "ed25519:/etc/my keys/mcp jwt.pub"
            jwt-issuer "https://auth.example"
            jwt-audience "https://spaces.example/mcp"
            allow-tools "docs_read"
        }
    }
    route "/api/*" {
        reverse-proxy {
            upstream "https://127.0.0.1:8443"
            upstream-tls {
                ca-cert "/etc/my certs/upstream ca.pem"
                client-cert "/etc/my certs/upstream client.pem"
                client-key "/etc/my keys/upstream client.key"
            }
        }
    }
}
site "publish.example" {
    ai-publish {
        storage "/srv/publish stores/my site"
        require-signature "ed25519:/etc/my keys/deploy pub.pub"
        jwt-public-key "ed25519:/etc/my keys/publish jwt.pub"
        jwt-issuer "https://auth.example"
        mcp-endpoint "/_miraserve/publish" auth="oauth-jwt"
    }
}
"#;
    let loaded = parse_kdl_detailed("internal-spaces.kdl", kdl)?;
    assert_eq!(
        loaded.config.server.acme_webroot.as_deref(),
        Some("/srv/acme webroot/dir")
    );
    let [site0, site1] = loaded.config.sites.as_slice() else {
        return Err("expected 2 sites".into());
    };
    assert_eq!(
        site0.root.as_deref(),
        Some("/srv/tenants/alice home/public html")
    );
    assert_eq!(
        site1.ai_publish.as_ref().map(|p| p.storage.as_str()),
        Some("/srv/publish stores/my site")
    );

    // Windows drive paths with internal spaces (both forward and backslash separators).
    let win_kdl = r#"
server {
    listen ":443"
    tls {
        cert "C:/Program Files/MiraServe/server.crt"
        key "C:\\Program Files\\MiraServe\\server.key"
    }
}
site "win.example" {
    root "C:/Program Files/My Site/www"
}
site "win-pub.example" {
    ai-publish {
        storage "D:\\Web Data\\My Releases\\app"
        require-signature "ed25519:C:/Program Files/MiraServe/deploy.pub"
    }
}
"#;
    let win_loaded = parse_kdl_detailed("windows-paths.kdl", win_kdl)?;
    let [win0, win1] = win_loaded.config.sites.as_slice() else {
        return Err("expected 2 windows sites".into());
    };
    assert_eq!(win0.root.as_deref(), Some("C:/Program Files/My Site/www"));
    assert_eq!(
        win1.ai_publish.as_ref().map(|p| p.storage.as_str()),
        Some(r"D:\Web Data\My Releases\app")
    );

    // Explicit Windows base dir with clean relative paths.
    let win_rel_kdl = r#"
server {
    listen ":443"
    tls { cert "C:/Certs/a.crt"; key "C:/Certs/a.key" }
}
site "win-rel.example" {
    root "public html"
}
"#;
    let win_rel = parse_kdl_detailed_with_base_dir(
        "win-rel.kdl",
        win_rel_kdl,
        Some(Path::new(r"C:\Program Files\My App")),
    )?;
    let resolved_root = win_rel
        .config
        .sites
        .first()
        .and_then(|s| s.root.as_deref())
        .ok_or("expected resolved root")?;
    assert!(
        resolved_root.ends_with("public html"),
        "expected resolved Windows relative root, got: {resolved_root}"
    );
    Ok(())
}

#[test]
fn parity_file_stdin_explicit_base_and_symlinked_config_relative_resolution() -> TestResult {
    let tmp = TempDir::new("rel-symlink")?;
    let real_dir = tmp.path.join("real conf");
    let link_dir = tmp.path.join("link conf");
    fs::create_dir_all(real_dir.join("public"))?;
    fs::create_dir_all(real_dir.join("releases"))?;
    fs::create_dir_all(&link_dir)?;

    let kdl = r#"
server {
    listen ":443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }
}
site "rel.example" {
    root "public"
    route "/sub/*" {
        root "sub dir/assets"
        static {}
    }
}
site "pub.example" {
    ai-publish {
        storage "releases"
        require-signature "ed25519:/etc/miraserve/deploy.pub"
    }
}
"#;
    let real_cfg = real_dir.join("miraserve.kdl");
    fs::write(&real_cfg, kdl)?;

    // 1. Direct file load resolves against canonical config parent.
    let canon_real_dir = fs::canonicalize(&real_dir)?;
    let file_loaded = load_file_detailed(&real_cfg)?;
    let [fs0, fs1] = file_loaded.config.sites.as_slice() else {
        return Err("expected 2 sites".into());
    };
    assert_eq!(
        fs0.root.as_deref(),
        Some(canon_real_dir.join("public").to_string_lossy().as_ref())
    );
    assert_eq!(
        fs0.routes.first().and_then(|r| r.root.as_deref()),
        Some(
            canon_real_dir
                .join("sub dir")
                .join("assets")
                .to_string_lossy()
                .as_ref()
        )
    );
    assert_eq!(
        fs1.ai_publish.as_ref().map(|p| p.storage.as_str()),
        Some(canon_real_dir.join("releases").to_string_lossy().as_ref())
    );

    // 2. Symlinked config resolves against canonical target's parent (not link_dir).
    #[cfg(unix)]
    {
        let link_cfg = link_dir.join("miraserve.kdl");
        std::os::unix::fs::symlink(&real_cfg, &link_cfg)?;
        let link_loaded = load_file_detailed(&link_cfg)?;
        let [ls0, ls1] = link_loaded.config.sites.as_slice() else {
            return Err("expected 2 symlink sites".into());
        };
        assert_eq!(ls0.root, fs0.root);
        assert_eq!(
            ls1.ai_publish.as_ref().map(|p| &p.storage),
            fs1.ai_publish.as_ref().map(|p| &p.storage)
        );
    }

    // 3. Explicit base matches file load.
    let explicit = parse_kdl_detailed_with_base_dir("explicit.kdl", kdl, Some(&canon_real_dir))?;
    assert_eq!(explicit.config, file_loaded.config);

    // 4. Stdin / string parse (no base dir) rejects relative dirs with E202.
    let stdin_errs = expect_validation_errors(parse_kdl_detailed("<stdin>", kdl))?;
    let [se0, se1, se2] = stdin_errs.as_slice() else {
        return Err(format!("expected 3 relative-dir E202s: {stdin_errs:#?}").into());
    };
    assert_eq!(se0.code, "E202");
    assert_eq!(se0.path.as_deref(), Some("site[0].root"));
    assert_eq!(
        se0.message,
        "site root path 'public' must be an absolute path"
    );
    assert_eq!(se1.code, "E202");
    assert_eq!(se1.path.as_deref(), Some("site[0].route[0].root"));
    assert_eq!(
        se1.message,
        "route root path 'sub dir/assets' must be an absolute path"
    );
    assert_eq!(se2.code, "E202");
    assert_eq!(se2.path.as_deref(), Some("site[1].ai-publish.storage"));
    assert_eq!(
        se2.message,
        "ai-publish storage path 'releases' must be an absolute path"
    );
    Ok(())
}

#[test]
fn parity_excluded_grammars_index_try_files_and_inline_keys_unchanged() -> TestResult {
    let kdl = r#"
server {
    listen ":443"
    tls { cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key" }
}
site "excluded.example" {
    root "/srv/www/excluded"
    index " index.html" "home.html "
    route "/spa/*" {
        try-files " {path}" "/index.html "
    }
    route "/st/*" {
        static {
            index " landing.html "
        }
    }
    route "/mcp/*" {
        mcp-gateway upstream="https://127.0.0.1:9001" {
            jwt-public-key "miraserve-ed25519-pub:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            jwt-issuer "https://auth.example"
            jwt-audience "https://excluded.example/mcp"
            allow-tools "docs_read"
        }
    }
}
site "pub-inline.example" {
    ai-publish {
        storage "/srv/publish/inline"
        require-signature "ed25519:/etc/miraserve/deploy.pub"
        jwt-public-key "miraserve-ed25519-pub:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        jwt-issuer "https://auth.example"
        mcp-endpoint "/_miraserve/publish" auth="oauth-jwt"
    }
}
"#;
    let loaded = parse_kdl_detailed("excluded.kdl", kdl)?;
    let site0 = loaded.config.sites.first().ok_or("expected site[0]")?;
    assert_eq!(
        site0.index,
        Some(vec![" index.html".to_owned(), "home.html ".to_owned()])
    );
    let [r0, r1, _] = site0.routes.as_slice() else {
        return Err("expected 3 routes".into());
    };
    match &r0.handler {
        miraserve_config::RouteHandler::TryFiles(tf) => {
            assert_eq!(
                tf.candidates,
                vec![" {path}".to_owned(), "/index.html ".to_owned()]
            );
        }
        other => return Err(format!("expected TryFiles, got {other:?}").into()),
    }
    match &r1.handler {
        miraserve_config::RouteHandler::Static(st) => {
            assert_eq!(st.index, vec![" landing.html ".to_owned()]);
        }
        other => return Err(format!("expected Static, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn parity_already_invalid_route_scheme_empty_pair_and_tcp_cases_no_churn() -> TestResult {
    // 1. Prohibited route basic-auth (both clean and trailing space stay E311 route prohibition).
    for users_file in ["/etc/miraserve/htpasswd", "/etc/miraserve/htpasswd "] {
        let kdl = format!(
            r#"
server {{
    listen ":443"
    tls {{ cert "/etc/miraserve/a.crt"; key "/etc/miraserve/a.key" }}
}}
site "rba.example" {{
    root "/srv/www/rba"
    route "/admin/*" {{
        basic-auth "{users_file}"
        static {{}}
    }}
}}
"#
        );
        let errs = expect_validation_errors(parse_kdl_detailed("rba.kdl", &kdl))?;
        let [err] = errs.as_slice() else {
            return Err(format!("unexpected errors for '{users_file}': {errs:#?}").into());
        };
        assert_eq!(err.code, "E311");
        assert_eq!(err.path.as_deref(), Some("site[0].route[0]"));
        assert!(
            err.message
                .contains("`access` and `basic-auth` are available for a whole site only"),
            "unexpected message: {}",
            err.message
        );
    }

    // 2. Empty values keep their exact existing errors.
    let empty_kdl = r#"
server {
    listen ":443"
    acme-webroot ""
    allow-docroot ""
    tls {
        cert ""
        key ""
        client-ca ""
    }
    sandbox {
        read-tree ""
        socket-tree ""
    }
}
site "empty.example" {
    owner-dir ""
    basic-auth ""
    root ""
    bot-auth { agent-keys-file "" }
    error-pages { page 404 "" }
    route "*.php" {
        fastcgi-pass "unix:"
    }
    route "/w/*" {
        wasm-plugin ""
    }
    route "/m/*" {
        mcp-gateway upstream="https://127.0.0.1:9001" {
            jwt-public-key "ed25519:"
            jwt-issuer "https://auth.example"
            jwt-audience "https://empty.example/mcp"
            allow-tools "docs_read"
        }
    }
}
site "empty-pub.example" {
    ai-publish {
        storage ""
        require-signature "ed25519:"
        jwt-public-key "ed25519:"
        jwt-issuer "https://auth.example"
        mcp-endpoint "/_miraserve/publish" auth="oauth-jwt"
    }
}
"#;
    let errs = expect_validation_errors(parse_kdl_detailed("empty.kdl", empty_kdl))?;
    assert!(
        errs.iter()
            .any(|e| e.code == "E301" && e.message == "owner-dir '' must be an absolute path"),
        "missing owner-dir empty E301: {errs:#?}"
    );
    assert!(
        errs.iter().any(|e| e.code == "E311"
            && e.message == "basic-auth users file '' must be an absolute path"),
        "missing basic-auth empty E311: {errs:#?}"
    );
    assert!(
        errs.iter()
            .any(|e| e.code == "E304" && e.message == "FastCGI Unix socket path must not be empty"),
        "missing fastcgi-pass unix: empty E304: {errs:#?}"
    );
    assert!(
        errs.iter().any(|e| e.code == "E401"
            && e.message == "require-signature public key path must not be empty"),
        "missing require-signature empty E401: {errs:#?}"
    );
    assert!(
        errs.iter().any(|e| e.code == "E202"
            && e.path.as_deref() == Some("site[1].ai-publish.storage")
            && e.message == "ai-publish storage path must not be empty"),
        "missing storage empty E202: {errs:#?}"
    );
    assert!(
        errs.iter().any(|e| e.code == "E202"
            && e.path.as_deref() == Some("server.sandbox.read-tree")
            && e.message
                == "sandbox 'read-tree' path '' is not allowed: it must be an absolute path"),
        "missing read-tree empty E202: {errs:#?}"
    );

    // 3. Invalid schemes keep E401 / E403 unchanged.
    let bad_scheme_kdl = r#"
server {
    listen ":443"
    tls { cert "/etc/miraserve/a.crt"; key "/etc/miraserve/a.key" }
}
site "scheme.example" {
    ai-publish {
        storage "/srv/publish/scheme"
        require-signature "rsa:/etc/miraserve/deploy.pub "
        jwt-public-key "rsa:/etc/miraserve/jwt.pub "
        jwt-issuer "https://auth.example"
        mcp-endpoint "/_miraserve/publish" auth="oauth-jwt"
    }
    route "/mcp/*" {
        mcp-gateway upstream="https://127.0.0.1:9001" {
            jwt-public-key "rsa:/etc/miraserve/mcp.pub "
            jwt-issuer "https://auth.example"
            jwt-audience "https://scheme.example/mcp"
            allow-tools "docs_read"
        }
    }
}
"#;
    let scheme_errs = expect_validation_errors(parse_kdl_detailed("scheme.kdl", bad_scheme_kdl))?;
    assert!(
        scheme_errs
            .iter()
            .any(|e| e.code == "E401" && e.message == "unsupported signature algorithm 'rsa'"),
        "expected E401 unsupported signature algorithm: {scheme_errs:#?}"
    );
    assert!(
        scheme_errs.iter().any(|e| e.code == "E401"
            && e.path.as_deref() == Some("site[0].ai-publish.jwt-public-key")
            && e.message
                == "invalid ai-publish 'jwt-public-key' format 'rsa:/etc/miraserve/jwt.pub '"),
        "expected E401 invalid ai-publish jwt-public-key: {scheme_errs:#?}"
    );
    assert!(
        scheme_errs.iter().any(|e| e.code == "E403"
            && e.path.as_deref() == Some("site[0].route[0].mcp-gateway.jwt-public-key")
            && e.message
                == "invalid mcp-gateway 'jwt-public-key' format 'rsa:/etc/miraserve/mcp.pub '"),
        "expected E403 invalid mcp-gateway jwt-public-key: {scheme_errs:#?}"
    );

    // 4. Keyd TCP grammar/loopback/nonzero-port and FastCGI TCP remain exact E105 / E304.
    let keyd_tcp_space = r#"
server {
    listen ":443"
    tls {
        key-isolation "split-daemon"
        keyd-socket "tcp:// 127.0.0.1:9444"
        cert "/etc/miraserve/a.crt"
        key "/etc/miraserve/a.key"
    }
}
site "tcp.example" {
    root "/srv/www/tcp"
    route "*.php" {
        fastcgi-pass "tcp://127.0.0.1:9000 "
    }
}
"#;
    let tcp_errs = expect_validation_errors(parse_kdl_detailed("tcp.kdl", keyd_tcp_space))?;
    assert!(
        tcp_errs.iter().any(|e| e.code == "E105"
            && e.path.as_deref() == Some("server.tls.keyd-socket")
            && e.message == "invalid 'keyd-socket' TCP address 'tcp:// 127.0.0.1:9444'"),
        "expected E105 for tcp:// 127.0.0.1:9444: {tcp_errs:#?}"
    );
    assert!(
        tcp_errs
            .iter()
            .any(|e| e.code == "E304"
                && e.message == "invalid FastCGI port in 'tcp://127.0.0.1:9000 '"),
        "expected E304 for FastCGI TCP trailing space: {tcp_errs:#?}"
    );
    assert!(
        !tcp_errs.iter().any(|e| e.code == "E202"),
        "expected zero E202 errors on TCP grammar failures: {tcp_errs:#?}"
    );

    // 5. Keyd non-loopback and zero-port TCP checks unchanged.
    for bad_tcp in ["tcp://0.0.0.0:9444", "tcp://127.0.0.1:0"] {
        let kdl = format!(
            r#"
server {{
    listen ":443"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "{bad_tcp}"
        cert "/etc/miraserve/a.crt"
        key "/etc/miraserve/a.key"
    }}
}}
site "loopback.example" {{ root "/srv/www/lb" }}
"#
        );
        let errs = expect_validation_errors(parse_kdl_detailed("lb.kdl", &kdl))?;
        let [err] = errs.as_slice() else {
            return Err(format!("expected 1 E105 for {bad_tcp}: {errs:#?}").into());
        };
        assert_eq!(err.code, "E105");
        assert_eq!(err.path.as_deref(), Some("server.tls.keyd-socket"));
    }

    // 6. Missing cert/key pairs keep E105 unchanged.
    let pair_kdl = r#"
server {
    listen ":443"
    tls { cert "/etc/miraserve/a.crt" }
}
site "pair.example" {
    root "/srv/www/pair"
    tls { key "/etc/miraserve/s.key" }
    route "/api/*" {
        reverse-proxy {
            upstream "https://127.0.0.1:8443"
            upstream-tls { client-cert "/etc/miraserve/c.crt" }
        }
    }
}
"#;
    let pair_errs = expect_validation_errors(parse_kdl_detailed("pair.kdl", pair_kdl))?;
    assert_eq!(
        pair_errs.len(),
        3,
        "expected 3 E105 pair errors: {pair_errs:#?}"
    );
    assert!(pair_errs.iter().all(|e| e.code == "E105"));
    Ok(())
}

// ============================================================================
// REJECTION ORACLE CASES — MUST FAIL on 441a58d and PASS on the 0.1.8 branch
// ============================================================================

#[test]
#[allow(clippy::too_many_lines)]
fn reject_every_host_path_directive_leading_trailing_escaped_and_unicode_whitespace() -> TestResult
{
    // 1. Complete single-config matrix exercising EVERY changed directive with distinct
    //    whitespace kinds (ASCII space, tab, LF, CR, NBSP U+00A0, ideographic space U+3000)
    //    and verifying exact semantic JSON paths, messages, help, and argument source columns.
    let kdl = "server {\n\
    listen \":443\"\n\
    acme-webroot \"/srv/acme \"\n\
    allow-docroot \"/var/lib/ok\" \" /var/lib/bad\"\n\
    tls {\n\
        key-isolation \"split-daemon\"\n\
        keyd-socket \"/run/miraserve-keyd/keyd.sock\\t\"\n\
        cert \"\\u{00A0}/etc/miraserve/server.crt\"\n\
        key \"/etc/miraserve/server.key\\u{3000}\"\n\
        client-ca \" /etc/miraserve/ca.pem \"\n\
    }\n\
    sandbox {\n\
        read-tree \"/home\" \"/var/www \"\n\
        socket-tree \"/run/php\" \"\\t/run/php-bad\"\n\
    }\n\
}\n\
site \"full.example\" {\n\
    owner-dir \"/srv/tenants/alice \"\n\
    basic-auth \" /etc/miraserve/htpasswd\"\n\
    root \"/srv/www/site\\n\"\n\
    tls {\n\
        cert \"/etc/miraserve/site.crt \"\n\
        key \" /etc/miraserve/site.key\"\n\
        client-ca \"/etc/miraserve/site-ca.pem\\r\"\n\
    }\n\
    bot-auth {\n\
        agent-keys-file \" /etc/miraserve/agents.json\"\n\
    }\n\
    error-pages {\n\
        page 404 \"errors/404.html \"\n\
    }\n\
    route \"/ok/*\" {\n\
        static {}\n\
    }\n\
    route \"/bad/*\" {\n\
        root \"/srv/www/route \"\n\
        fastcgi-pass \"unix:/run/php/fpm.sock \"\n\
    }\n\
    route \"/wasm/*\" {\n\
        wasm-plugin \" /opt/plugins/app.wasm\"\n\
    }\n\
    route \"/mcp/*\" {\n\
        mcp-gateway upstream=\"https://127.0.0.1:9001\" {\n\
            jwt-public-key \"ed25519:/etc/miraserve/mcp.pub \"\n\
            jwt-issuer \"https://auth.example\"\n\
            jwt-audience \"https://full.example/mcp\"\n\
            allow-tools \"docs_read\"\n\
        }\n\
    }\n\
    route \"/proxy/*\" {\n\
        reverse-proxy {\n\
            upstream \"https://127.0.0.1:8443\"\n\
            upstream-tls {\n\
                ca-cert \" /etc/miraserve/up-ca.pem\"\n\
                client-cert \"/etc/miraserve/up-cert.pem \"\n\
                client-key \"/etc/miraserve/up-key.pem\\u{00A0}\"\n\
            }\n\
        }\n\
    }\n\
}\n\
site \"pub.example\" {\n\
    ai-publish {\n\
        storage #\"/srv/publish/app \"#\n\
        require-signature \"ed25519: /etc/miraserve/deploy.pub\"\n\
        jwt-public-key \" ed25519:/etc/miraserve/jwt.pub\"\n\
        jwt-issuer \"https://auth.example\"\n\
        mcp-endpoint \"/_miraserve/publish\" auth=\"oauth-jwt\"\n\
    }\n\
}\n";

    let errs = expect_validation_errors(parse_kdl_detailed("matrix.kdl", kdl))?;

    let expected: &[(&str, &str)] = &[
        (
            "server.acme-webroot",
            "server.acme-webroot path ends with whitespace (U+0020)",
        ),
        (
            "server.allow-docroot[1]",
            "server.allow-docroot path starts with whitespace (U+0020)",
        ),
        (
            "server.tls.keyd-socket",
            "keyd-socket path ends with whitespace (U+0009)",
        ),
        (
            "server.tls.cert",
            "TLS certificate path starts with whitespace (U+00A0)",
        ),
        (
            "server.tls.key",
            "TLS private key path ends with whitespace (U+3000)",
        ),
        (
            "server.tls.client-ca",
            "mTLS client CA bundle path starts and ends with whitespace (U+0020)",
        ),
        (
            "server.sandbox.read-tree",
            "sandbox 'read-tree' path ends with whitespace (U+0020)",
        ),
        (
            "server.sandbox.socket-tree",
            "sandbox 'socket-tree' path starts with whitespace (U+0009)",
        ),
        (
            "site[0].owner-dir",
            "owner-dir path ends with whitespace (U+0020)",
        ),
        (
            "site[0].basic-auth",
            "basic-auth users file path starts with whitespace (U+0020)",
        ),
        (
            "site[0].root",
            "site root path ends with whitespace (U+000A)",
        ),
        (
            "site[0].tls.cert",
            "TLS certificate path ends with whitespace (U+0020)",
        ),
        (
            "site[0].tls.key",
            "TLS private key path starts with whitespace (U+0020)",
        ),
        (
            "site[0].tls.client-ca",
            "site mTLS client CA bundle path ends with whitespace (U+000D)",
        ),
        (
            "site[0].bot-auth.agent-keys-file",
            "bot-auth agent-keys-file path starts with whitespace (U+0020)",
        ),
        (
            "site[0].error-pages.page.404",
            "error page path ends with whitespace (U+0020)",
        ),
        (
            "site[0].route[1].root",
            "route root path ends with whitespace (U+0020)",
        ),
        (
            "site[0].route[1].fastcgi-pass",
            "FastCGI Unix socket path ends with whitespace (U+0020)",
        ),
        (
            "site[0].route[2].wasm-plugin",
            "wasm-plugin module path starts with whitespace (U+0020)",
        ),
        (
            "site[0].route[3].mcp-gateway.jwt-public-key",
            "mcp-gateway JWT public key path ends with whitespace (U+0020)",
        ),
        (
            "site[0].route[4].reverse-proxy.upstream-tls.ca-cert",
            "upstream-tls ca-cert path starts with whitespace (U+0020)",
        ),
        (
            "site[0].route[4].reverse-proxy.upstream-tls.client-cert",
            "upstream-tls client-cert path ends with whitespace (U+0020)",
        ),
        (
            "site[0].route[4].reverse-proxy.upstream-tls.client-key",
            "upstream-tls client-key path ends with whitespace (U+00A0)",
        ),
        (
            "site[1].ai-publish.storage",
            "ai-publish storage path ends with whitespace (U+0020)",
        ),
        (
            "site[1].ai-publish.require-signature",
            "require-signature public key path starts with whitespace (U+0020)",
        ),
        (
            "site[1].ai-publish.jwt-public-key",
            "ai-publish JWT public key path starts with whitespace (U+0020)",
        ),
    ];

    assert_eq!(
        errs.len(),
        expected.len(),
        "expected ONLY the {} E202 errors with zero secondary/spurious errors, got {} errors:\n{errs:#?}",
        expected.len(),
        errs.len()
    );

    for &(path, msg) in expected {
        let issue = find_single_e202(&errs, path, msg)?;
        // Specifically assert that list-valued directives locate the 2nd (offending) argument,
        // not column 5/9 of the directive name.
        if path == "server.allow-docroot[1]" {
            let loc = issue.location.ok_or("missing location")?;
            assert_eq!(loc.line, 4);
            assert_eq!(
                loc.column, 29,
                "allow-docroot[1] must point to 2nd arg: {loc:?}"
            );
            assert_eq!(
                kdl.get(loc.offset..loc.offset + loc.length),
                Some("\" /var/lib/bad\"")
            );
        } else if path == "server.sandbox.read-tree" {
            let loc = issue.location.ok_or("missing location")?;
            assert_eq!(loc.line, 13);
            assert_eq!(loc.column, 19, "read-tree must point to 2nd arg: {loc:?}");
            assert_eq!(
                kdl.get(loc.offset..loc.offset + loc.length),
                Some("\"/var/www \"")
            );
        } else if path == "server.sandbox.socket-tree" {
            let loc = issue.location.ok_or("missing location")?;
            assert_eq!(loc.line, 14);
            assert_eq!(loc.column, 24, "socket-tree must point to 2nd arg: {loc:?}");
            assert_eq!(
                kdl.get(loc.offset..loc.offset + loc.length),
                Some("\"\\t/run/php-bad\"")
            );
        }
    }

    // 2. Additional prefixed-form variants:
    //    - keyd-socket: outer leading space on TCP (must NOT fall into file branch!),
    //      outer trailing space on TCP, outer leading space on unix:, inner space after unix:.
    for (val, expected_msg) in [
        (
            " tcp://127.0.0.1:9444",
            "keyd-socket path starts with whitespace (U+0020)",
        ),
        (
            "tcp://127.0.0.1:9444 ",
            "keyd-socket path ends with whitespace (U+0020)",
        ),
        (
            " unix:/run/miraserve-keyd/keyd.sock",
            "keyd-socket path starts with whitespace (U+0020)",
        ),
        (
            "unix: /run/miraserve-keyd/keyd.sock",
            "keyd-socket path starts with whitespace (U+0020)",
        ),
    ] {
        let k = format!(
            "server {{\n\
                 listen \":443\"\n\
                 tls {{\n\
                     key-isolation \"split-daemon\"\n\
                     keyd-socket \"{val}\"\n\
                     cert \"/etc/miraserve/a.crt\"\n\
                     key \"/etc/miraserve/a.key\"\n\
                 }}\n\
             }}\n\
             site \"k.example\" {{ root \"/srv/www/k\" }}\n"
        );
        let e = expect_validation_errors(parse_kdl_detailed("keyd.kdl", &k))?;
        assert_eq!(
            e.len(),
            1,
            "expected single E202 for keyd-socket '{val}', got: {e:#?}"
        );
        find_single_e202(&e, "server.tls.keyd-socket", expected_msg)?;
    }

    //    - fastcgi-pass unix: outer leading space & inner leading space after unix:.
    for (val, expected_msg) in [
        (
            " unix:/run/php/fpm.sock",
            "FastCGI Unix socket path starts with whitespace (U+0020)",
        ),
        (
            "unix: /run/php/fpm.sock",
            "FastCGI Unix socket path starts with whitespace (U+0020)",
        ),
    ] {
        let k = format!(
            "server {{\n\
                 listen \":443\"\n\
                 tls {{ cert \"/etc/miraserve/a.crt\"; key \"/etc/miraserve/a.key\" }}\n\
             }}\n\
             site \"f.example\" {{\n\
                 root \"/srv/www/f\"\n\
                 route \"*.php\" {{ fastcgi-pass \"{val}\" }}\n\
             }}\n"
        );
        let e = expect_validation_errors(parse_kdl_detailed("fcgi.kdl", &k))?;
        assert_eq!(
            e.len(),
            1,
            "expected single E202 for fastcgi-pass '{val}', got: {e:#?}"
        );
        find_single_e202(&e, "site[0].route[0].fastcgi-pass", expected_msg)?;
    }

    //    - require-signature & jwt-public-key outer leading/trailing & inner space after ed25519:.
    for (sig, jwt, sig_msg, jwt_msg) in [
        (
            " ed25519:/etc/miraserve/d.pub",
            "ed25519: /etc/miraserve/j.pub",
            "require-signature public key path starts with whitespace (U+0020)",
            "ai-publish JWT public key path starts with whitespace (U+0020)",
        ),
        (
            "ed25519:/etc/miraserve/d.pub ",
            "ed25519:/etc/miraserve/j.pub ",
            "require-signature public key path ends with whitespace (U+0020)",
            "ai-publish JWT public key path ends with whitespace (U+0020)",
        ),
    ] {
        let k = format!(
            "server {{\n\
                 listen \":443\"\n\
                 tls {{ cert \"/etc/miraserve/a.crt\"; key \"/etc/miraserve/a.key\" }}\n\
             }}\n\
             site \"p.example\" {{\n\
                 ai-publish {{\n\
                     storage \"/srv/publish/p\"\n\
                     require-signature \"{sig}\"\n\
                     jwt-public-key \"{jwt}\"\n\
                     jwt-issuer \"https://auth.example\"\n\
                     mcp-endpoint \"/_miraserve/publish\" auth=\"oauth-jwt\"\n\
                 }}\n\
             }}\n"
        );
        let e = expect_validation_errors(parse_kdl_detailed("pub-tags.kdl", &k))?;
        assert_eq!(
            e.len(),
            2,
            "expected 2 E202s (no secondary E401), got: {e:#?}"
        );
        find_single_e202(&e, "site[0].ai-publish.require-signature", sig_msg)?;
        find_single_e202(&e, "site[0].ai-publish.jwt-public-key", jwt_msg)?;
    }

    //    - mcp-gateway jwt-public-key outer leading & inner space after ed25519:.
    for val in [
        " ed25519:/etc/miraserve/m.pub",
        "ed25519: /etc/miraserve/m.pub",
    ] {
        let k = format!(
            "server {{\n\
                 listen \":443\"\n\
                 tls {{ cert \"/etc/miraserve/a.crt\"; key \"/etc/miraserve/a.key\" }}\n\
             }}\n\
             site \"m.example\" {{\n\
                 route \"/mcp/*\" {{\n\
                     mcp-gateway upstream=\"https://127.0.0.1:9001\" {{\n\
                         jwt-public-key \"{val}\"\n\
                         jwt-issuer \"https://auth.example\"\n\
                         jwt-audience \"https://m.example/mcp\"\n\
                         allow-tools \"docs_read\"\n\
                     }}\n\
                 }}\n\
             }}\n"
        );
        let e = expect_validation_errors(parse_kdl_detailed("mcp-tag.kdl", &k))?;
        assert_eq!(
            e.len(),
            1,
            "expected 1 E202 for mcp jwt '{val}', got: {e:#?}"
        );
        find_single_e202(
            &e,
            "site[0].route[0].mcp-gateway.jwt-public-key",
            "mcp-gateway JWT public key path starts with whitespace (U+0020)",
        )?;
    }

    //    - KDL v2 multiline string with trailing whitespace on path value.
    let multiline_kdl = "server {\n\
    listen \":443\"\n\
    tls { cert \"/etc/miraserve/a.crt\"; key \"/etc/miraserve/a.key\" }\n\
}\n\
site \"ml.example\" {\n\
    root \"\"\"\n\
        /srv/www/ml \n\
        \"\"\"\n\
}\n";
    let ml_errs = expect_validation_errors(parse_kdl_detailed("ml.kdl", multiline_kdl))?;
    assert_eq!(
        ml_errs.len(),
        1,
        "expected 1 E202 for multiline root: {ml_errs:#?}"
    );
    find_single_e202(
        &ml_errs,
        "site[0].root",
        "site root path ends with whitespace (U+0020)",
    )?;

    Ok(())
}

#[test]
fn reject_file_backed_padded_relative_and_resolved_dir_exception() -> TestResult {
    let tmp = TempDir::new("rel-reject")?;
    let base_dir = tmp.path.join("conf");
    fs::create_dir_all(&base_dir)?;

    // 1. File-backed padded relative `storage " releases "` and `root " public "` MUST NOT be
    //    silently trimmed and joined; they must fail with E202 at their KDL locations.
    let padded_rel_kdl = r#"
server {
    listen ":443"
    tls { cert "/etc/miraserve/a.crt"; key "/etc/miraserve/a.key" }
}
site "padded-rel.example" {
    root " public "
    route "/sub/*" {
        root " sub"
        static {}
    }
}
site "padded-pub.example" {
    ai-publish {
        storage " releases "
        require-signature "ed25519:/etc/miraserve/deploy.pub"
    }
}
"#;
    let padded_cfg = base_dir.join("padded-rel.kdl");
    fs::write(&padded_cfg, padded_rel_kdl)?;
    let padded_errs = expect_validation_errors(load_file_detailed(&padded_cfg))?;
    assert_eq!(padded_errs.len(), 3, "expected 3 E202s: {padded_errs:#?}");
    find_single_e202(
        &padded_errs,
        "site[0].root",
        "site root path starts and ends with whitespace (U+0020)",
    )?;
    find_single_e202(
        &padded_errs,
        "site[0].route[0].root",
        "route root path starts with whitespace (U+0020)",
    )?;
    find_single_e202(
        &padded_errs,
        "site[1].ai-publish.storage",
        "ai-publish storage path starts and ends with whitespace (U+0020)",
    )?;

    // 2. Narrow resolved-directory exception (MUST 3): source strings have NO edge whitespace,
    //    but dropping trailing `.` / `/` / `\` exposes terminal whitespace in the resolved path.
    let resolved_ws_kdl = "server {\n\
    listen \":443\"\n\
    tls { cert \"/etc/miraserve/a.crt\"; key \"/etc/miraserve/a.key\" }\n\
}\n\
site \"res-root.example\" {\n\
    root \"pub /.\"\n\
    route \"/sub/*\" {\n\
        root \"sub /\"\n\
        static {}\n\
    }\n\
}\n\
site \"res-pub.example\" {\n\
    ai-publish {\n\
        storage \"app /.\"\n\
        require-signature \"ed25519:/etc/miraserve/deploy.pub\"\n\
    }\n\
}\n\
site \"res-nbsp.example\" {\n\
    ai-publish {\n\
        storage \"app\\u{00A0}/.\"\n\
        require-signature \"ed25519:/etc/miraserve/deploy.pub\"\n\
    }\n\
}\n";
    let res_cfg = base_dir.join("resolved-ws.kdl");
    fs::write(&res_cfg, resolved_ws_kdl)?;
    let res_errs = expect_validation_errors(load_file_detailed(&res_cfg))?;
    assert_eq!(
        res_errs.len(),
        4,
        "expected 4 resolved-dir E202s with zero secondary errors: {res_errs:#?}"
    );
    find_single_e202(
        &res_errs,
        "site[0].root",
        "site root resolved directory name ends with whitespace (U+0020)",
    )?;
    find_single_e202(
        &res_errs,
        "site[0].route[0].root",
        "route root resolved directory name ends with whitespace (U+0020)",
    )?;
    find_single_e202(
        &res_errs,
        "site[1].ai-publish.storage",
        "ai-publish storage resolved directory name ends with whitespace (U+0020)",
    )?;
    find_single_e202(
        &res_errs,
        "site[2].ai-publish.storage",
        "ai-publish storage resolved directory name ends with whitespace (U+00A0)",
    )?;

    // 3. Windows backslash separator exposing terminal whitespace against explicit Windows base.
    let win_res_kdl = r#"
server {
    listen ":443"
    tls { cert "C:/Certs/a.crt"; key "C:/Certs/a.key" }
}
site "win-res.example" {
    root "pub \\"
}
"#;
    let win_res_errs = expect_validation_errors(parse_kdl_detailed_with_base_dir(
        "win-res.kdl",
        win_res_kdl,
        Some(Path::new(r"C:\srv\app")),
    ))?;
    assert_eq!(win_res_errs.len(), 1, "expected 1 E202: {win_res_errs:#?}");
    find_single_e202(
        &win_res_errs,
        "site[0].root",
        "site root resolved directory name ends with whitespace (U+0020)",
    )?;

    // 4. Clean absolute path `storage "<dir>/app /."` has NO source padding and is NOT rewritten;
    //    verify leading-space file-backed `storage " /srv/publish/app"` is rejected with E202.
    let lead_abs_kdl = format!(
        "server {{\n\
             listen \":443\"\n\
             tls {{ cert \"/etc/miraserve/a.crt\"; key \"/etc/miraserve/a.key\" }}\n\
         }}\n\
         site \"lead.example\" {{\n\
             ai-publish {{\n\
                 storage \" {}/releases/app\"\n\
                 require-signature \"ed25519:/etc/miraserve/deploy.pub\"\n\
             }}\n\
         }}\n",
        kdl_escape_path(&tmp.path)
    );
    let lead_cfg = base_dir.join("lead-abs.kdl");
    fs::write(&lead_cfg, lead_abs_kdl)?;
    let lead_errs = expect_validation_errors(load_file_detailed(&lead_cfg))?;
    assert_eq!(lead_errs.len(), 1, "expected 1 E202: {lead_errs:#?}");
    find_single_e202(
        &lead_errs,
        "site[0].ai-publish.storage",
        "ai-publish storage path starts with whitespace (U+0020)",
    )?;

    Ok(())
}

#[test]
fn reject_padded_missing_pair_preserves_missing_pair_error() -> TestResult {
    let kdl = r#"
server {
    listen ":443"
    tls { cert "/etc/miraserve/a.crt " }
}
site "pair-ws.example" {
    root "/srv/www/pair"
}
"#;
    let errs = expect_validation_errors(parse_kdl_detailed("pair-ws.kdl", kdl))?;
    assert_eq!(errs.len(), 2, "expected E202 + E105, got: {errs:#?}");
    find_single_e202(
        &errs,
        "server.tls.cert",
        "TLS certificate path ends with whitespace (U+0020)",
    )?;
    assert!(
        errs.iter()
            .any(|e| e.code == "E105" && e.path.as_deref() == Some("server.tls")),
        "expected missing-pair E105 to be preserved: {errs:#?}"
    );
    Ok(())
}

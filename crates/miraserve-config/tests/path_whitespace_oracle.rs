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
const EXPECTED_RESOLVED_HELP: &str = "verify which directory or file currently holds live data before editing the path; remove trailing whitespace from the final directory component before any trailing slash or '.'";

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Result<Self, std::io::Error> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path =
            std::env::temp_dir().join(format!("ms-pws-cfg-{tag}-{}-{nanos}", std::process::id()));
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

fn native_abs(posix: &str) -> String {
    if cfg!(windows) {
        format!("C:{posix}")
    } else {
        posix.to_owned()
    }
}

fn strip_windows_verbatim_prefix(path: &Path) -> String {
    let raw = path.to_string_lossy();
    if let Some(unc) = raw.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else if let Some(stripped) = raw.strip_prefix(r"\\?\") {
        stripped.to_owned()
    } else {
        raw.into_owned()
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

fn assert_exact_issues(errors: &[ConfigIssue], expected: &[(&str, Option<&str>, &str)]) {
    let actual: Vec<(&str, Option<&str>, &str)> = errors
        .iter()
        .map(|e| (e.code.as_str(), e.path.as_deref(), e.message.as_str()))
        .collect();
    assert_eq!(
        actual, expected,
        "diagnostic list mismatch\nactual={errors:#?}"
    );
    for issue in errors {
        let expects_location = issue
            .path
            .as_deref()
            .is_none_or(|p| !p.starts_with("sites."));
        if expects_location {
            assert!(
                issue.location.is_some(),
                "expected real source location on issue: {issue:#?}"
            );
        }
    }
}

fn find_single_e202<'a>(
    errors: &'a [ConfigIssue],
    expected_path: &str,
    expected_message: &str,
    expected_help: &str,
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
        Some(expected_help),
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
    let owner_dir = native_abs("/srv/tenants/alice home");
    let users_file = native_abs("/etc/my auth/alice users.htpasswd");
    let kdl = format!(
        r#"
server {{
    listen ":443"
    acme-webroot "/srv/acme webroot/dir"
    allow-docroot "/var/lib/my app/public" "/var/lib/other app/site"
    tls {{
        key-isolation "split-daemon"
        keyd-socket "/run/miraserve keyd/keyd socket.sock"
        cert "/etc/my certs/server cert.pem"
        key "/etc/my keys/server key.pem"
        client-ca "/etc/my certs/client ca.pem"
    }}
    sandbox {{
        read-tree "/srv/web roots" "/home/panel sites"
        socket-tree "/run/php pools"
    }}
}}
site "spaces.example" {{
    owner-dir "{owner_dir}"
    basic-auth "{users_file}" realm="Members"
    root "/srv/tenants/alice home/public html"
    tls {{
        cert "/etc/my certs/alice cert.pem"
        key "/etc/my keys/alice key.pem"
        client-ca "/etc/my certs/alice ca.pem"
    }}
    bot-auth {{
        agent-keys-file "/etc/my bots/agent keys.json"
    }}
    error-pages {{
        page 404 "custom errors/not found.html"
        page 503 "/srv/tenants/alice home/custom errors/503 page.html"
    }}
    route "/static/*" {{
        root "/srv/tenants/alice home/static files"
        static {{
            index "index.html"
        }}
    }}
    route "*.php" {{
        fastcgi-pass "unix:/run/php pools/alice pool.sock"
    }}
    route "/plugin/*" {{
        wasm-plugin "/opt/my plugins/hello world.wasm"
    }}
    route "/mcp/*" {{
        mcp-gateway upstream="https://127.0.0.1:9001" {{
            jwt-public-key "ed25519:/etc/my keys/mcp jwt.pub"
            jwt-issuer "https://auth.example"
            jwt-audience "https://spaces.example/mcp"
            allow-tools "docs_read"
        }}
    }}
    route "/api/*" {{
        reverse-proxy {{
            upstream "https://127.0.0.1:8443"
            upstream-tls {{
                ca-cert "/etc/my certs/upstream ca.pem"
                client-cert "/etc/my certs/upstream client.pem"
                client-key "/etc/my keys/upstream client.key"
            }}
        }}
    }}
}}
site "publish.example" {{
    ai-publish {{
        storage "/srv/publish stores/my site"
        require-signature "ed25519:/etc/my keys/deploy pub.pub"
        jwt-public-key "ed25519:/etc/my keys/publish jwt.pub"
        jwt-issuer "https://auth.example"
        mcp-endpoint "/_miraserve/publish" auth="oauth-jwt"
    }}
}}
"#
    );
    let loaded = parse_kdl_detailed("internal-spaces.kdl", &kdl)?;
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

    // Clean absolute path `storage "<dir>/app /."` has no edge whitespace and is NOT rewritten.
    let tmp = TempDir::new("abs-dot")?;
    let abs_dot_storage = format!("{}/app /.", kdl_escape_path(&tmp.path));
    let abs_dot_cfg = tmp.path.join("abs-dot.kdl");
    fs::write(
        &abs_dot_cfg,
        format!(
            "server {{\n\
                 listen \":443\"\n\
                 tls {{ cert \"/etc/miraserve/a.crt\"; key \"/etc/miraserve/a.key\" }}\n\
             }}\n\
             site \"abs-dot.example\" {{\n\
                 ai-publish {{\n\
                     storage \"{abs_dot_storage}\"\n\
                     require-signature \"ed25519:/etc/miraserve/deploy.pub\"\n\
                 }}\n\
             }}\n"
        ),
    )?;
    let abs_dot_loaded = load_file_detailed(&abs_dot_cfg)?;
    assert_eq!(
        abs_dot_loaded
            .config
            .sites
            .first()
            .and_then(|s| s.ai_publish.as_ref())
            .map(|p| p.storage.as_str()),
        Some(abs_dot_storage.as_str())
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

    // 1. Direct file load resolves against canonical config parent (verbatim prefix stripped).
    let canon_real_dir = fs::canonicalize(&real_dir)?;
    let expected_base = PathBuf::from(strip_windows_verbatim_prefix(&canon_real_dir));
    let file_loaded = load_file_detailed(&real_cfg)?;
    let [fs0, fs1] = file_loaded.config.sites.as_slice() else {
        return Err("expected 2 sites".into());
    };
    assert_eq!(
        fs0.root.as_deref(),
        Some(expected_base.join("public").to_string_lossy().as_ref())
    );
    assert_eq!(
        fs0.routes.first().and_then(|r| r.root.as_deref()),
        Some(
            expected_base
                .join("sub dir")
                .join("assets")
                .to_string_lossy()
                .as_ref()
        )
    );
    assert_eq!(
        fs1.ai_publish.as_ref().map(|p| p.storage.as_str()),
        Some(expected_base.join("releases").to_string_lossy().as_ref())
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
    assert_exact_issues(
        &stdin_errs,
        &[
            (
                "E202",
                Some("site[0].root"),
                "site root path 'public' must be an absolute path",
            ),
            (
                "E202",
                Some("site[0].route[0].root"),
                "route root path 'sub dir/assets' must be an absolute path",
            ),
            (
                "E202",
                Some("site[1].ai-publish.storage"),
                "ai-publish storage path 'releases' must be an absolute path",
            ),
        ],
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
#[allow(clippy::too_many_lines)]
fn parity_already_invalid_route_scheme_empty_pair_and_tcp_cases_no_churn() -> TestResult {
    // 1a. Prohibited route basic-auth (both clean and trailing space stay exact E311 prohibition).
    let rba_clean = native_abs("/etc/miraserve/htpasswd");
    let rba_padded = format!("{rba_clean} ");
    for users_file in [&rba_clean, &rba_padded] {
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
        assert_exact_issues(
            &errs,
            &[(
                "E311",
                Some("site[0].route[0]"),
                "route '/admin/*' on site 'rba.example': `access` and `basic-auth` are available for a whole site only; move them to the site block",
            )],
        );
    }

    // 1b. Exempt route basic-auth overlapping `acme-webroot` keeps EXACTLY the 441a58d overlap
    //     E202 followed by the route-prohibition E311 (no diagnostic lost or reordered).
    #[cfg(unix)]
    {
        let overlap_kdl = r#"
server {
    listen ":443"
    acme-webroot "/srv/acme"
    tls { cert "/etc/miraserve/a.crt"; key "/etc/miraserve/a.key" }
}
site "rba-overlap.example" {
    root "/srv/www/rba"
    route "/admin/*" {
        basic-auth "/srv/acme/.well-known/acme-challenge/token "
        static {}
    }
}
"#;
        let overlap_errs =
            expect_validation_errors(parse_kdl_detailed("rba-overlap.kdl", overlap_kdl))?;
        assert_exact_issues(
            &overlap_errs,
            &[
                (
                    "E202",
                    Some("site[0].route[0].basic-auth"),
                    "credential file '/srv/acme/.well-known/acme-challenge/token ' is inside the challenge directory of server.acme-webroot '/srv/acme', whose files are served before any site check; keep credentials elsewhere",
                ),
                (
                    "E311",
                    Some("site[0].route[0]"),
                    "route '/admin/*' on site 'rba-overlap.example': `access` and `basic-auth` are available for a whole site only; move them to the site block",
                ),
            ],
        );
    }

    // 2. Empty values keep their exact full ordered error list (every code, path, message, location).
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
    assert_exact_issues(
        &errs,
        &[
            ("E301", None, "owner-dir '' must be an absolute path"),
            (
                "E311",
                None,
                "basic-auth users file '' must be an absolute path",
            ),
            ("E304", None, "FastCGI Unix socket path must not be empty"),
            ("E302", None, "route '*.php' does not configure a handler"),
            (
                "E401",
                None,
                "require-signature public key path must not be empty",
            ),
            (
                "E202",
                Some("server.tls.cert"),
                "TLS certificate path must not be empty",
            ),
            (
                "E202",
                Some("server.tls.key"),
                "TLS private key path must not be empty",
            ),
            (
                "E202",
                Some("server.tls.client-ca"),
                "mTLS client CA bundle path must not be empty",
            ),
            (
                "E202",
                Some("server.sandbox.read-tree"),
                "sandbox 'read-tree' path '' is not allowed: it must be an absolute path",
            ),
            (
                "E202",
                Some("server.sandbox.socket-tree"),
                "sandbox 'socket-tree' path '' is not allowed: it must be an absolute path",
            ),
            (
                "E202",
                Some("server.allow-docroot[0]"),
                "server.allow-docroot path must not be empty",
            ),
            (
                "E202",
                Some("server.acme-webroot"),
                "server.acme-webroot path must not be empty",
            ),
            (
                "E202",
                Some("site[0].root"),
                "site root path must not be empty",
            ),
            (
                "E202",
                Some("site[0].bot-auth.agent-keys-file"),
                "bot-auth agent-keys-file path must not be empty",
            ),
            (
                "E202",
                Some("site[0].error-pages.page.404"),
                "error page path must not be empty",
            ),
            (
                "E202",
                Some("site[0].route[0].wasm-plugin"),
                "wasm-plugin module path must not be empty",
            ),
            (
                "E202",
                Some("site[0].route[1].mcp-gateway.jwt-public-key"),
                "mcp-gateway JWT public key path must not be empty",
            ),
            (
                "E202",
                Some("site[1].ai-publish.storage"),
                "ai-publish storage path must not be empty",
            ),
            (
                "E202",
                Some("site[1].ai-publish.jwt-public-key"),
                "ai-publish JWT public key path must not be empty",
            ),
            (
                "E401",
                Some("site[1].ai-publish.mcp-endpoint"),
                "ai-publish mcp-endpoint with auth=\"oauth-jwt\" on site 'empty-pub.example' requires 'require-signature' to prevent unsigned bundle deploys",
            ),
            (
                "E202",
                Some("sites.0.root"),
                "site root '' overlaps ai-publish.storage '' and would expose publish metadata/releases",
            ),
        ],
    );

    // 3. Invalid schemes keep their exact full ordered E401 / E403 error list.
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
    assert_exact_issues(
        &scheme_errs,
        &[
            ("E401", None, "unsupported signature algorithm 'rsa'"),
            (
                "E401",
                Some("site[0].ai-publish.jwt-public-key"),
                "invalid ai-publish 'jwt-public-key' format 'rsa:/etc/miraserve/jwt.pub '",
            ),
            (
                "E401",
                Some("site[0].ai-publish.mcp-endpoint"),
                "ai-publish mcp-endpoint with auth=\"oauth-jwt\" on site 'scheme.example' requires 'require-signature' to prevent unsigned bundle deploys",
            ),
            (
                "E403",
                Some("site[0].route[0].mcp-gateway.jwt-public-key"),
                "invalid mcp-gateway 'jwt-public-key' format 'rsa:/etc/miraserve/mcp.pub '",
            ),
        ],
    );

    // 4. Keyd TCP grammar and FastCGI TCP keep their exact full ordered error list.
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
    assert_exact_issues(
        &tcp_errs,
        &[
            (
                "E304",
                None,
                "invalid FastCGI port in 'tcp://127.0.0.1:9000 '",
            ),
            ("E302", None, "route '*.php' does not configure a handler"),
            (
                "E105",
                Some("server.tls.keyd-socket"),
                "invalid 'keyd-socket' TCP address 'tcp:// 127.0.0.1:9444'",
            ),
        ],
    );

    // 5. Keyd non-loopback and zero-port TCP checks unchanged.
    for (bad_tcp, expected_msg) in [
        (
            "tcp://0.0.0.0:9444",
            "'keyd-socket' TCP endpoint 'tcp://0.0.0.0:9444' must bind strictly to loopback (127.0.0.1 or [::1])",
        ),
        (
            "tcp://127.0.0.1:0",
            "'keyd-socket' TCP endpoint 'tcp://127.0.0.1:0' must bind strictly to loopback (127.0.0.1 or [::1])",
        ),
    ] {
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
        assert_exact_issues(
            &errs,
            &[("E105", Some("server.tls.keyd-socket"), expected_msg)],
        );
    }

    // 6. Missing cert/key pairs keep exact ordered E105 codes, paths, messages, and locations.
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
    assert_exact_issues(
        &pair_errs,
        &[
            (
                "E105",
                Some("server.tls"),
                "TLS certificate configured without a matching private key",
            ),
            (
                "E105",
                Some("site[0].tls"),
                "TLS private key configured without a matching certificate",
            ),
            (
                "E105",
                Some("site[0].route[0].reverse-proxy.upstream-tls"),
                "TLS certificate configured without a matching private key",
            ),
        ],
    );
    Ok(())
}

// ============================================================================
// REJECTION ORACLE CASES — MUST FAIL on 441a58d and PASS on the 0.1.8 branch
// ============================================================================

#[test]
#[allow(clippy::too_many_lines)]
fn reject_every_host_path_directive_leading_trailing_escaped_and_unicode_whitespace() -> TestResult
{
    let owner_dir = format!("{} ", native_abs("/srv/tenants/alice"));
    let basic_auth = format!("{} ", native_abs("/etc/miraserve/htpasswd"));
    // 1. Complete single-config matrix exercising EVERY changed directive with distinct
    //    whitespace kinds (ASCII space, tab, LF, CR, NBSP U+00A0, ideographic space U+3000)
    //    on spellings that were clean on 441a58d, verifying exact directive + site/route messages,
    //    exact semantic JSON paths, help, and argument source columns.
    let kdl = format!(
        "server {{\n\
    listen \":443\"\n\
    acme-webroot \"/srv/acme \"\n\
    allow-docroot \"/var/lib/ok\" \" /var/lib/bad\"\n\
    tls {{\n\
        key-isolation \"split-daemon\"\n\
        keyd-socket \"/run/miraserve-keyd/keyd.sock\\t\"\n\
        cert \"\\u{{00A0}}/etc/miraserve/server.crt\"\n\
        key \"/etc/miraserve/server.key\\u{{3000}}\"\n\
        client-ca \" /etc/miraserve/ca.pem \"\n\
    }}\n\
    sandbox {{\n\
        read-tree \"/home\" \"/var/www \"\n\
        socket-tree \"/run/php\" \"/run/php-bad\\u{{00A0}}\"\n\
    }}\n\
}}\n\
site \"full.example\" {{\n\
    owner-dir \"{owner_dir}\"\n\
    basic-auth \"{basic_auth}\"\n\
    root \"/srv/www/site\\n\"\n\
    tls {{\n\
        cert \"/etc/miraserve/site.crt \"\n\
        key \" /etc/miraserve/site.key\"\n\
        client-ca \"/etc/miraserve/site-ca.pem\\r\"\n\
    }}\n\
    bot-auth {{\n\
        agent-keys-file \" /etc/miraserve/agents.json\"\n\
    }}\n\
    error-pages {{\n\
        page 404 \"errors/404.html \"\n\
    }}\n\
    route \"/ok/*\" {{\n\
        static {{}}\n\
    }}\n\
    route \"/bad/*\" {{\n\
        root \"/srv/www/route \"\n\
        fastcgi-pass \"unix:/run/php/fpm.sock \"\n\
    }}\n\
    route \"/wasm/*\" {{\n\
        wasm-plugin \" /opt/plugins/app.wasm\"\n\
    }}\n\
    route \"/mcp/*\" {{\n\
        mcp-gateway upstream=\"https://127.0.0.1:9001\" {{\n\
            jwt-public-key \"ed25519:/etc/miraserve/mcp.pub \"\n\
            jwt-issuer \"https://auth.example\"\n\
            jwt-audience \"https://full.example/mcp\"\n\
            allow-tools \"docs_read\"\n\
        }}\n\
    }}\n\
    route \"/proxy/*\" {{\n\
        reverse-proxy {{\n\
            upstream \"https://127.0.0.1:8443\"\n\
            upstream-tls {{\n\
                ca-cert \" /etc/miraserve/up-ca.pem\"\n\
                client-cert \"/etc/miraserve/up-cert.pem \"\n\
                client-key \"/etc/miraserve/up-key.pem\\u{{00A0}}\"\n\
            }}\n\
        }}\n\
    }}\n\
}}\n\
site \"pub.example\" {{\n\
    ai-publish {{\n\
        storage #\"/srv/publish/app \"#\n\
        require-signature \"ed25519: /etc/miraserve/deploy.pub\"\n\
        jwt-public-key \"ed25519: /etc/miraserve/jwt.pub\"\n\
        jwt-issuer \"https://auth.example\"\n\
        mcp-endpoint \"/_miraserve/publish\" auth=\"oauth-jwt\"\n\
    }}\n\
}}\n"
    );

    let errs = expect_validation_errors(parse_kdl_detailed("matrix.kdl", &kdl))?;

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
            "server.tls 'keyd-socket' path ends with whitespace (U+0009)",
        ),
        (
            "server.tls.cert",
            "server.tls 'cert' path starts with whitespace (U+00A0)",
        ),
        (
            "server.tls.key",
            "server.tls 'key' path ends with whitespace (U+3000)",
        ),
        (
            "server.tls.client-ca",
            "server.tls 'client-ca' path starts and ends with whitespace (U+0020)",
        ),
        (
            "server.sandbox.read-tree",
            "sandbox 'read-tree' path ends with whitespace (U+0020)",
        ),
        (
            "server.sandbox.socket-tree",
            "sandbox 'socket-tree' path ends with whitespace (U+00A0)",
        ),
        (
            "site[0].owner-dir",
            "'owner-dir' path on site 'full.example' ends with whitespace (U+0020)",
        ),
        (
            "site[0].basic-auth",
            "'basic-auth' path on site 'full.example' ends with whitespace (U+0020)",
        ),
        (
            "site[0].root",
            "site 'root' path on site 'full.example' ends with whitespace (U+000A)",
        ),
        (
            "site[0].tls.cert",
            "site.tls 'cert' path on site 'full.example' ends with whitespace (U+0020)",
        ),
        (
            "site[0].tls.key",
            "site.tls 'key' path on site 'full.example' starts with whitespace (U+0020)",
        ),
        (
            "site[0].tls.client-ca",
            "site.tls 'client-ca' path on site 'full.example' ends with whitespace (U+000D)",
        ),
        (
            "site[0].bot-auth.agent-keys-file",
            "bot-auth 'agent-keys-file' path on site 'full.example' starts with whitespace (U+0020)",
        ),
        (
            "site[0].error-pages.page.404",
            "error-pages 'page' 404 path on site 'full.example' ends with whitespace (U+0020)",
        ),
        (
            "site[0].route[1].root",
            "route 'root' path on route '/bad/*' of site 'full.example' ends with whitespace (U+0020)",
        ),
        (
            "site[0].route[1].fastcgi-pass",
            "'fastcgi-pass' path on route '/bad/*' of site 'full.example' ends with whitespace (U+0020)",
        ),
        (
            "site[0].route[2].wasm-plugin",
            "'wasm-plugin' path on route '/wasm/*' of site 'full.example' starts with whitespace (U+0020)",
        ),
        (
            "site[0].route[3].mcp-gateway.jwt-public-key",
            "mcp-gateway 'jwt-public-key' path on route '/mcp/*' of site 'full.example' ends with whitespace (U+0020)",
        ),
        (
            "site[0].route[4].reverse-proxy.upstream-tls.ca-cert",
            "upstream-tls 'ca-cert' path on route '/proxy/*' of site 'full.example' starts with whitespace (U+0020)",
        ),
        (
            "site[0].route[4].reverse-proxy.upstream-tls.client-cert",
            "upstream-tls 'client-cert' path on route '/proxy/*' of site 'full.example' ends with whitespace (U+0020)",
        ),
        (
            "site[0].route[4].reverse-proxy.upstream-tls.client-key",
            "upstream-tls 'client-key' path on route '/proxy/*' of site 'full.example' ends with whitespace (U+00A0)",
        ),
        (
            "site[1].ai-publish.storage",
            "ai-publish 'storage' path on site 'pub.example' ends with whitespace (U+0020)",
        ),
        (
            "site[1].ai-publish.require-signature",
            "ai-publish 'require-signature' path on site 'pub.example' starts with whitespace (U+0020)",
        ),
        (
            "site[1].ai-publish.jwt-public-key",
            "ai-publish 'jwt-public-key' path on site 'pub.example' starts with whitespace (U+0020)",
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
        let issue = find_single_e202(&errs, path, msg, EXPECTED_HELP)?;
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
                Some("\"/run/php-bad\\u{00A0}\"")
            );
        }
    }

    // 2. Additional prefixed-form variants:
    //    - keyd-socket spellings that were accepted on 441a58d emit a single E202.
    for (val, expected_msg) in [
        (
            " tcp://127.0.0.1:9444",
            "server.tls 'keyd-socket' path starts with whitespace (U+0020)",
        ),
        (
            " unix:/run/miraserve-keyd/keyd.sock",
            "server.tls 'keyd-socket' path starts with whitespace (U+0020)",
        ),
        (
            "unix: /run/miraserve-keyd/keyd.sock",
            "server.tls 'keyd-socket' path starts with whitespace (U+0020)",
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
        assert_exact_issues(
            &e,
            &[("E202", Some("server.tls.keyd-socket"), expected_msg)],
        );
    }

    //    - fastcgi-pass unix: inner leading space after unix: emits a single E202.
    {
        let k = "server {\n\
                 listen \":443\"\n\
                 tls { cert \"/etc/miraserve/a.crt\"; key \"/etc/miraserve/a.key\" }\n\
             }\n\
             site \"f.example\" {\n\
                 root \"/srv/www/f\"\n\
                 route \"*.php\" { fastcgi-pass \"unix: /run/php/fpm.sock\" }\n\
             }\n";
        let e = expect_validation_errors(parse_kdl_detailed("fcgi.kdl", k))?;
        assert_exact_issues(
            &e,
            &[(
                "E202",
                Some("site[0].route[0].fastcgi-pass"),
                "'fastcgi-pass' path on route '*.php' of site 'f.example' starts with whitespace (U+0020)",
            )],
        );
    }

    //    - require-signature & jwt-public-key trailing / inner space after ed25519:.
    {
        let k = "server {\n\
                 listen \":443\"\n\
                 tls { cert \"/etc/miraserve/a.crt\"; key \"/etc/miraserve/a.key\" }\n\
             }\n\
             site \"p.example\" {\n\
                 ai-publish {\n\
                     storage \"/srv/publish/p\"\n\
                     require-signature \"ed25519:/etc/miraserve/d.pub \"\n\
                     jwt-public-key \"ed25519:/etc/miraserve/j.pub \"\n\
                     jwt-issuer \"https://auth.example\"\n\
                     mcp-endpoint \"/_miraserve/publish\" auth=\"oauth-jwt\"\n\
                 }\n\
             }\n";
        let e = expect_validation_errors(parse_kdl_detailed("pub-tags.kdl", k))?;
        assert_exact_issues(
            &e,
            &[
                (
                    "E202",
                    Some("site[0].ai-publish.require-signature"),
                    "ai-publish 'require-signature' path on site 'p.example' ends with whitespace (U+0020)",
                ),
                (
                    "E202",
                    Some("site[0].ai-publish.jwt-public-key"),
                    "ai-publish 'jwt-public-key' path on site 'p.example' ends with whitespace (U+0020)",
                ),
            ],
        );
    }

    //    - mcp-gateway jwt-public-key inner space after ed25519:.
    {
        let k = "server {\n\
                 listen \":443\"\n\
                 tls { cert \"/etc/miraserve/a.crt\"; key \"/etc/miraserve/a.key\" }\n\
             }\n\
             site \"m.example\" {\n\
                 route \"/mcp/*\" {\n\
                     mcp-gateway upstream=\"https://127.0.0.1:9001\" {\n\
                         jwt-public-key \"ed25519: /etc/miraserve/m.pub\"\n\
                         jwt-issuer \"https://auth.example\"\n\
                         jwt-audience \"https://m.example/mcp\"\n\
                         allow-tools \"docs_read\"\n\
                     }\n\
                 }\n\
             }\n";
        let e = expect_validation_errors(parse_kdl_detailed("mcp-tag.kdl", k))?;
        assert_exact_issues(
            &e,
            &[(
                "E202",
                Some("site[0].route[0].mcp-gateway.jwt-public-key"),
                "mcp-gateway 'jwt-public-key' path on route '/mcp/*' of site 'm.example' starts with whitespace (U+0020)",
            )],
        );
    }

    // 3. All 6 representative Unicode whitespace classes at leading, trailing, and both edges.
    for (kdl_ws, codepoint) in [
        (" ", "U+0020"),
        ("\\t", "U+0009"),
        ("\\n", "U+000A"),
        ("\\r", "U+000D"),
        ("\\u{00A0}", "U+00A0"),
        ("\\u{3000}", "U+3000"),
    ] {
        for (val, expected_reason) in [
            (
                format!("{kdl_ws}/srv/www/ws"),
                format!("starts with whitespace ({codepoint})"),
            ),
            (
                format!("/srv/www/ws{kdl_ws}"),
                format!("ends with whitespace ({codepoint})"),
            ),
            (
                format!("{kdl_ws}/srv/www/ws{kdl_ws}"),
                format!("starts and ends with whitespace ({codepoint})"),
            ),
        ] {
            let k = format!(
                "server {{\n\
                     listen \":443\"\n\
                     tls {{ cert \"/etc/miraserve/a.crt\"; key \"/etc/miraserve/a.key\" }}\n\
                 }}\n\
                 site \"ws.example\" {{ root \"{val}\" }}\n"
            );
            let e = expect_validation_errors(parse_kdl_detailed("ws.kdl", &k))?;
            let expected_msg = format!("site 'root' path on site 'ws.example' {expected_reason}");
            assert_exact_issues(&e, &[("E202", Some("site[0].root"), &expected_msg)]);
        }
    }
    // Distinct leading and trailing whitespace code points.
    {
        let k = "server {\n\
                 listen \":443\"\n\
                 tls { cert \"/etc/miraserve/a.crt\"; key \"/etc/miraserve/a.key\" }\n\
             }\n\
             site \"ws.example\" { root \"\\t/srv/www/ws\\u{00A0}\" }\n";
        let e = expect_validation_errors(parse_kdl_detailed("ws-both.kdl", k))?;
        assert_exact_issues(
            &e,
            &[(
                "E202",
                Some("site[0].root"),
                "site 'root' path on site 'ws.example' starts with whitespace (U+0009) and ends with whitespace (U+00A0)",
            )],
        );
    }

    // 4. KDL v2 multiline string with trailing whitespace on path value.
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
    assert_exact_issues(
        &ml_errs,
        &[(
            "E202",
            Some("site[0].root"),
            "site 'root' path on site 'ml.example' ends with whitespace (U+0020)",
        )],
    );

    Ok(())
}

#[test]
fn reject_file_backed_padded_relative_and_resolved_dir_exception() -> TestResult {
    let tmp = TempDir::new("rel-reject")?;
    let base_dir = tmp.path.join("conf");
    fs::create_dir_all(&base_dir)?;

    // 1. File-backed padded relative `storage " releases "` and `root " public "` are rejected
    //    with E202 at their KDL locations and emit no spurious "must be an absolute path" error.
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
    assert_exact_issues(
        &padded_errs,
        &[
            (
                "E202",
                Some("site[0].root"),
                "site 'root' path on site 'padded-rel.example' starts and ends with whitespace (U+0020)",
            ),
            (
                "E202",
                Some("site[0].route[0].root"),
                "route 'root' path on route '/sub/*' of site 'padded-rel.example' starts with whitespace (U+0020)",
            ),
            (
                "E202",
                Some("site[1].ai-publish.storage"),
                "ai-publish 'storage' path on site 'padded-pub.example' starts and ends with whitespace (U+0020)",
            ),
        ],
    );

    // 2. Resolved-directory check: source strings have NO edge whitespace, but dropping trailing
    //    `.` / `/` / `\` exposes terminal whitespace in the resolved directory name, with
    //    component-specific remediation help.
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
        storage \"app2\\u{00A0}/.\"\n\
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
        "site 'root' resolved directory name on site 'res-root.example' ends with whitespace (U+0020)",
        EXPECTED_RESOLVED_HELP,
    )?;
    find_single_e202(
        &res_errs,
        "site[0].route[0].root",
        "route 'root' resolved directory name on route '/sub/*' of site 'res-root.example' ends with whitespace (U+0020)",
        EXPECTED_RESOLVED_HELP,
    )?;
    find_single_e202(
        &res_errs,
        "site[1].ai-publish.storage",
        "ai-publish 'storage' resolved directory name on site 'res-pub.example' ends with whitespace (U+0020)",
        EXPECTED_RESOLVED_HELP,
    )?;
    find_single_e202(
        &res_errs,
        "site[2].ai-publish.storage",
        "ai-publish 'storage' resolved directory name on site 'res-nbsp.example' ends with whitespace (U+00A0)",
        EXPECTED_RESOLVED_HELP,
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
        "site 'root' resolved directory name on site 'win-res.example' ends with whitespace (U+0020)",
        EXPECTED_RESOLVED_HELP,
    )?;

    // 4. File-backed absolute path with leading whitespace is rejected with E202.
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
        "ai-publish 'storage' path on site 'lead.example' starts with whitespace (U+0020)",
        EXPECTED_HELP,
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
    assert_exact_issues(
        &errs,
        &[
            (
                "E202",
                Some("server.tls.cert"),
                "server.tls 'cert' path ends with whitespace (U+0020)",
            ),
            (
                "E105",
                Some("server.tls"),
                "TLS certificate configured without a matching private key",
            ),
        ],
    );
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn reject_no_early_return_preserves_all_existing_diagnostics_across_all_families() -> TestResult {
    // 1. Audit P1 #2 literal example 1: padded site `basic-auth` with empty `realm=""` must emit
    //    the new E202 AND preserve the existing E311 for the empty realm.
    let users_padded = format!("{} ", native_abs("/srv/auth/users"));
    {
        let kdl = format!(
            r#"
server {{
    listen ":443"
    tls {{ cert "/etc/miraserve/a.crt"; key "/etc/miraserve/a.key" }}
}}
site "auth-realm.example" {{
    root "/srv/www/auth"
    basic-auth "{users_padded}" realm=""
}}
"#
        );
        let errs = expect_validation_errors(parse_kdl_detailed("auth-realm.kdl", &kdl))?;
        assert_exact_issues(
            &errs,
            &[
                (
                    "E202",
                    Some("site[0].basic-auth"),
                    "'basic-auth' path on site 'auth-realm.example' ends with whitespace (U+0020)",
                ),
                (
                    "E311",
                    None,
                    "basic-auth realm must be 1-128 characters without quotes, backslashes or control characters",
                ),
            ],
        );
    }

    // 2. Audit P1 #2 literal example 2: padded site `basic-auth` with unknown property `typo="x"`
    //    must emit the new E202 AND preserve the existing E003.
    {
        let kdl = format!(
            r#"
server {{
    listen ":443"
    tls {{ cert "/etc/miraserve/a.crt"; key "/etc/miraserve/a.key" }}
}}
site "auth-prop.example" {{
    root "/srv/www/auth"
    basic-auth "{users_padded}" typo="x"
}}
"#
        );
        let errs = expect_validation_errors(parse_kdl_detailed("auth-prop.kdl", &kdl))?;
        assert_exact_issues(
            &errs,
            &[
                (
                    "E202",
                    Some("site[0].basic-auth"),
                    "'basic-auth' path on site 'auth-prop.example' ends with whitespace (U+0020)",
                ),
                ("E003", None, "unknown property 'typo' on 'basic-auth'"),
            ],
        );
    }

    // 3. Multi-error test per server directive family:
    //    - server.acme-webroot (unknown prop + padded + forbidden dir)
    //    - server.allow-docroot (unknown prop + padded + forbidden dir)
    //    - server.tls.{cert,key,client-ca} (unknown prop + padded + missing pair)
    //    - server.tls.keyd-socket (padded trailing-space TCP + invalid TCP E105)
    //    - server.sandbox.{read-tree,socket-tree} (unknown prop + padded + sandbox_tree_rejection)
    {
        let kdl = r#"
server {
    listen ":443"
    acme-webroot "/etc " extra="x"
    allow-docroot "/etc " extra="y"
    tls {
        key-isolation "split-daemon"
        keyd-socket "tcp://127.0.0.1:9444 "
        cert "/etc/miraserve/a.crt " extra="z"
    }
    sandbox {
        read-tree " /var/www" extra="r"
        socket-tree "/etc/foo "
    }
}
site "srv-multi.example" {
    root "/srv/www/srv-multi"
}
"#;
        let errs = expect_validation_errors(parse_kdl_detailed("srv-multi.kdl", kdl))?;
        assert_exact_issues(
            &errs,
            &[
                (
                    "E003",
                    None,
                    "unexpected property 'extra' on 'acme-webroot'",
                ),
                (
                    "E202",
                    Some("server.acme-webroot"),
                    "server.acme-webroot path ends with whitespace (U+0020)",
                ),
                (
                    "E003",
                    None,
                    "unexpected property 'extra' on 'allow-docroot'",
                ),
                (
                    "E202",
                    Some("server.allow-docroot[0]"),
                    "server.allow-docroot path ends with whitespace (U+0020)",
                ),
                (
                    "E202",
                    Some("server.tls.keyd-socket"),
                    "server.tls 'keyd-socket' path ends with whitespace (U+0020)",
                ),
                ("E003", None, "unexpected property 'extra' on 'cert'"),
                (
                    "E202",
                    Some("server.tls.cert"),
                    "server.tls 'cert' path ends with whitespace (U+0020)",
                ),
                ("E003", None, "unexpected property 'extra' on 'read-tree'"),
                (
                    "E202",
                    Some("server.sandbox.read-tree"),
                    "sandbox 'read-tree' path starts with whitespace (U+0020)",
                ),
                (
                    "E202",
                    Some("server.sandbox.socket-tree"),
                    "sandbox 'socket-tree' path ends with whitespace (U+0020)",
                ),
                (
                    "E105",
                    Some("server.tls"),
                    "TLS certificate configured without a matching private key",
                ),
                (
                    "E105",
                    Some("server.tls.keyd-socket"),
                    "invalid 'keyd-socket' TCP address 'tcp://127.0.0.1:9444 '",
                ),
                (
                    "E202",
                    Some("server.sandbox.read-tree"),
                    "sandbox 'read-tree' path ' /var/www' is not allowed: it must be an absolute path",
                ),
                (
                    "E202",
                    Some("server.sandbox.socket-tree"),
                    "sandbox 'socket-tree' path '/etc/foo ' is not allowed: it is inside a system, secret or MiraServe state directory",
                ),
                (
                    "E202",
                    Some("server.allow-docroot[0]"),
                    "server.allow-docroot '/etc ' points to an unconditionally forbidden OS or MiraServe directory and cannot be exempted",
                ),
                (
                    "E202",
                    Some("server.acme-webroot"),
                    "server.acme-webroot '/etc ' points to a forbidden OS or MiraServe directory",
                ),
            ],
        );
    }

    // 4. Multi-error test per site directive family:
    //    - site.owner-dir (leading space -> E202 + E301 non-absolute)
    //    - site.basic-auth (leading space -> E202 + E311 non-absolute)
    //    - site.root (unknown prop + padded + forbidden dir)
    //    - site.tls (unknown prop + padded key + missing cert E105)
    //    - site.bot-auth.agent-keys-file (unknown prop + padded + '..' traversal)
    //    - site.error-pages.page (padded + invalid status 200 E203)
    {
        let kdl = r#"
server {
    listen ":443"
    tls { cert "/etc/miraserve/a.crt"; key "/etc/miraserve/a.key" }
}
site "site-multi.example" {
    owner-dir " /srv/tenants/alice"
    basic-auth " /srv/auth/users"
    root "/etc " extra="r"
    tls { key "/etc/miraserve/s.key " extra="k" }
    bot-auth { agent-keys-file "/etc/../agents.json " extra="b" }
    error-pages { page 200 "errors/200.html " }
}
"#;
        let errs = expect_validation_errors(parse_kdl_detailed("site-multi.kdl", kdl))?;
        assert_exact_issues(
            &errs,
            &[
                (
                    "E202",
                    Some("site[0].owner-dir"),
                    "'owner-dir' path on site 'site-multi.example' starts with whitespace (U+0020)",
                ),
                (
                    "E301",
                    None,
                    "owner-dir ' /srv/tenants/alice' must be an absolute path",
                ),
                (
                    "E202",
                    Some("site[0].basic-auth"),
                    "'basic-auth' path on site 'site-multi.example' starts with whitespace (U+0020)",
                ),
                (
                    "E311",
                    None,
                    "basic-auth users file ' /srv/auth/users' must be an absolute path",
                ),
                ("E003", None, "unexpected property 'extra' on 'root'"),
                (
                    "E202",
                    Some("site[0].root"),
                    "site 'root' path on site 'site-multi.example' ends with whitespace (U+0020)",
                ),
                ("E003", None, "unexpected property 'extra' on 'key'"),
                (
                    "E202",
                    Some("site[0].tls.key"),
                    "site.tls 'key' path on site 'site-multi.example' ends with whitespace (U+0020)",
                ),
                (
                    "E003",
                    None,
                    "unexpected property 'extra' on 'agent-keys-file'",
                ),
                (
                    "E202",
                    Some("site[0].bot-auth.agent-keys-file"),
                    "bot-auth 'agent-keys-file' path on site 'site-multi.example' ends with whitespace (U+0020)",
                ),
                (
                    "E202",
                    Some("site[0].error-pages.page.200"),
                    "error-pages 'page' 200 path on site 'site-multi.example' ends with whitespace (U+0020)",
                ),
                (
                    "E105",
                    Some("site[0].tls"),
                    "TLS private key configured without a matching certificate",
                ),
                (
                    "E202",
                    Some("site[0].root"),
                    "site root path '/etc ' points to a sensitive or overly broad system directory",
                ),
                (
                    "E202",
                    Some("site[0].bot-auth.agent-keys-file"),
                    "bot-auth agent-keys-file path '/etc/../agents.json ' contains forbidden '..' parent traversal segment",
                ),
                (
                    "E203",
                    Some("site[0].error-pages.page.200"),
                    "error page status '200' must be between 400 and 599",
                ),
            ],
        );
    }

    // 5. Multi-error test for site `ai-publish` family (`storage`, `require-signature`,
    //    `jwt-public-key`) preserving unsupported algorithm, invalid JWT format, and forbidden dir.
    {
        let kdl = r#"
server {
    listen ":443"
    tls { cert "/etc/miraserve/a.crt"; key "/etc/miraserve/a.key" }
}
site "pub-multi.example" {
    ai-publish {
        storage "/etc "
        require-signature " ed25519:/etc/miraserve/d.pub"
        jwt-public-key " ed25519:/etc/miraserve/j.pub"
        jwt-issuer "https://auth.example"
        mcp-endpoint "/_miraserve/publish" auth="oauth-jwt"
    }
}
"#;
        let errs = expect_validation_errors(parse_kdl_detailed("pub-multi.kdl", kdl))?;
        assert_exact_issues(
            &errs,
            &[
                (
                    "E202",
                    Some("site[0].ai-publish.storage"),
                    "ai-publish 'storage' path on site 'pub-multi.example' ends with whitespace (U+0020)",
                ),
                (
                    "E202",
                    Some("site[0].ai-publish.require-signature"),
                    "ai-publish 'require-signature' path on site 'pub-multi.example' starts with whitespace (U+0020)",
                ),
                ("E401", None, "unsupported signature algorithm ' ed25519'"),
                (
                    "E202",
                    Some("site[0].ai-publish.jwt-public-key"),
                    "ai-publish 'jwt-public-key' path on site 'pub-multi.example' starts with whitespace (U+0020)",
                ),
                (
                    "E202",
                    Some("site[0].ai-publish.storage"),
                    "ai-publish storage path '/etc ' points to a sensitive or overly broad system directory",
                ),
                (
                    "E401",
                    Some("site[0].ai-publish.jwt-public-key"),
                    "invalid ai-publish 'jwt-public-key' format ' ed25519:/etc/miraserve/j.pub'",
                ),
                (
                    "E401",
                    Some("site[0].ai-publish.mcp-endpoint"),
                    "ai-publish mcp-endpoint with auth=\"oauth-jwt\" on site 'pub-multi.example' requires 'require-signature' to prevent unsigned bundle deploys",
                ),
            ],
        );
    }

    // 6. Multi-error test per route directive family:
    //    - route.root (unknown prop + padded + forbidden dir)
    //    - route.fastcgi-pass (padded unix: + bad timeout + unknown prop; and outer space before unix:)
    //    - route.wasm-plugin (padded + unknown prop + invalid max-fuel)
    //    - route.mcp-gateway.jwt-public-key (unknown prop + leading space before ed25519: -> E403)
    //    - route.reverse-proxy.upstream-tls (unknown prop + padded client-cert + missing client-key)
    {
        let kdl = r#"
server {
    listen ":443"
    tls { cert "/etc/miraserve/a.crt"; key "/etc/miraserve/a.key" }
}
site "route-multi.example" {
    root "/srv/www/route-multi"
    route "/r/*" {
        root "/etc " extra="r"
        static {}
    }
    route "/f1/*" {
        fastcgi-pass "unix:/run/php/fpm.sock " timeout="bad" typo="x"
    }
    route "/f2/*" {
        fastcgi-pass " unix:/run/php/fpm.sock"
    }
    route "/w/*" {
        wasm-plugin " /opt/plugins/app.wasm" typo="w" max-fuel=0
    }
    route "/m/*" {
        mcp-gateway upstream="https://127.0.0.1:9001" {
            jwt-public-key " ed25519:/etc/miraserve/mcp.pub" extra="m"
            jwt-issuer "https://auth.example"
            jwt-audience "https://route-multi.example/m"
            allow-tools "docs_read"
        }
    }
    route "/p/*" {
        reverse-proxy {
            upstream "https://127.0.0.1:8443"
            upstream-tls {
                client-cert "/etc/miraserve/c.crt " extra="u"
            }
        }
    }
}
"#;
        let errs = expect_validation_errors(parse_kdl_detailed("route-multi.kdl", kdl))?;
        assert_exact_issues(
            &errs,
            &[
                ("E003", None, "unexpected property 'extra' on 'root'"),
                (
                    "E202",
                    Some("site[0].route[0].root"),
                    "route 'root' path on route '/r/*' of site 'route-multi.example' ends with whitespace (U+0020)",
                ),
                (
                    "E202",
                    Some("site[0].route[1].fastcgi-pass"),
                    "'fastcgi-pass' path on route '/f1/*' of site 'route-multi.example' ends with whitespace (U+0020)",
                ),
                (
                    "E304",
                    None,
                    "invalid fastcgi-pass timeout 'bad': invalid numeric value in 'bad'",
                ),
                ("E003", None, "unknown property 'typo' on 'fastcgi-pass'"),
                (
                    "E202",
                    Some("site[0].route[2].fastcgi-pass"),
                    "'fastcgi-pass' path on route '/f2/*' of site 'route-multi.example' starts with whitespace (U+0020)",
                ),
                (
                    "E304",
                    None,
                    "invalid FastCGI port in ' unix:/run/php/fpm.sock'",
                ),
                ("E302", None, "route '/f2/*' does not configure a handler"),
                (
                    "E202",
                    Some("site[0].route[2].wasm-plugin"),
                    "'wasm-plugin' path on route '/w/*' of site 'route-multi.example' starts with whitespace (U+0020)",
                ),
                ("E003", None, "unknown property 'typo' on 'wasm-plugin'"),
                (
                    "E003",
                    None,
                    "unexpected property 'extra' on 'jwt-public-key'",
                ),
                (
                    "E202",
                    Some("site[0].route[3].mcp-gateway.jwt-public-key"),
                    "mcp-gateway 'jwt-public-key' path on route '/m/*' of site 'route-multi.example' starts with whitespace (U+0020)",
                ),
                ("E003", None, "unexpected property 'extra' on 'client-cert'"),
                (
                    "E202",
                    Some("site[0].route[4].reverse-proxy.upstream-tls.client-cert"),
                    "upstream-tls 'client-cert' path on route '/p/*' of site 'route-multi.example' ends with whitespace (U+0020)",
                ),
                (
                    "E202",
                    Some("site[0].route[0].root"),
                    "route root path '/etc ' points to a sensitive or overly broad system directory",
                ),
                (
                    "E501",
                    Some("site[0].route[2].wasm-plugin.max-fuel"),
                    "wasm-plugin 'max-fuel' must be between 1 and 50000000",
                ),
                (
                    "E403",
                    Some("site[0].route[3].mcp-gateway.jwt-public-key"),
                    "invalid mcp-gateway 'jwt-public-key' format ' ed25519:/etc/miraserve/mcp.pub'",
                ),
                (
                    "E105",
                    Some("site[0].route[4].reverse-proxy.upstream-tls"),
                    "TLS certificate configured without a matching private key",
                ),
            ],
        );
    }

    // 7. Resolved-directory multi-error: `storage "app /."` plus `keep-versions 0`.
    {
        let tmp = TempDir::new("res-multi")?;
        let cfg = tmp.path.join("res-multi.kdl");
        fs::write(
            &cfg,
            "server {\n\
                 listen \":443\"\n\
                 tls { cert \"/etc/miraserve/a.crt\"; key \"/etc/miraserve/a.key\" }\n\
             }\n\
             site \"res-multi.example\" {\n\
                 ai-publish {\n\
                     storage \"app /.\"\n\
                     keep-versions 0\n\
                     require-signature \"ed25519:/etc/miraserve/deploy.pub\"\n\
                 }\n\
             }\n",
        )?;
        let errs = expect_validation_errors(load_file_detailed(&cfg))?;
        assert_exact_issues(
            &errs,
            &[
                (
                    "E202",
                    Some("site[0].ai-publish.storage"),
                    "ai-publish 'storage' resolved directory name on site 'res-multi.example' ends with whitespace (U+0020)",
                ),
                (
                    "E401",
                    Some("site[0].ai-publish.keep-versions"),
                    "ai-publish 'keep-versions' must be between 1 and 1000, found 0",
                ),
            ],
        );
    }

    // 8. Collector preservation for padded in-scope values:
    //    - `validate_acme_webroot_credentials` (site basic-auth inside acme-webroot)
    //    - `publish_stores` overlap (root vs padded storage)
    //    - `seen_publish_storages` duplicate (clean storage vs padded storage)
    //    - `docroot_contains_config_dir` (file-backed padded `root " . "`)
    #[cfg(unix)]
    {
        let tmp = TempDir::new("collectors")?;
        let cfg = tmp.path.join("collectors.kdl");
        fs::write(
            &cfg,
            "server {\n\
                 listen \":443\"\n\
                 acme-webroot \"/srv/acme\"\n\
                 tls { cert \"/etc/miraserve/a.crt\"; key \"/etc/miraserve/a.key\" }\n\
             }\n\
             site \"c1.example\" {\n\
                 basic-auth \"/srv/acme/.well-known/acme-challenge/token \"\n\
                 root \" . \"\n\
                 ai-publish {\n\
                     storage \"/srv/publish/shared\"\n\
                     require-signature \"ed25519:/etc/miraserve/deploy.pub\"\n\
                 }\n\
             }\n\
             site \"c2.example\" {\n\
                 root \"/srv/publish/shared\"\n\
                 ai-publish {\n\
                     storage \"/srv/publish/shared \"\n\
                     require-signature \"ed25519:/etc/miraserve/deploy.pub\"\n\
                 }\n\
             }\n",
        )?;
        let errs = expect_validation_errors(load_file_detailed(&cfg))?;
        let canon_cfg_dir = fs::canonicalize(&tmp.path)?;
        let expected_cfg_msg = format!(
            "site.root '{}' contains the configuration directory '{}' and would expose the config file over HTTP (R7-CFG-1)",
            canon_cfg_dir.display(),
            canon_cfg_dir.display()
        );
        assert_exact_issues(
            &errs,
            &[
                (
                    "E202",
                    Some("site[0].basic-auth"),
                    "'basic-auth' path on site 'c1.example' ends with whitespace (U+0020)",
                ),
                (
                    "E202",
                    Some("site[0].root"),
                    "site 'root' path on site 'c1.example' starts and ends with whitespace (U+0020)",
                ),
                (
                    "E202",
                    Some("site[1].ai-publish.storage"),
                    "ai-publish 'storage' path on site 'c2.example' ends with whitespace (U+0020)",
                ),
                (
                    "E202",
                    Some("site[0].basic-auth"),
                    "credential file '/srv/acme/.well-known/acme-challenge/token ' is inside the challenge directory of server.acme-webroot '/srv/acme', whose files are served before any site check; keep credentials elsewhere",
                ),
                (
                    "E401",
                    Some("site[1].ai-publish.storage"),
                    "duplicate ai-publish storage directory '/srv/publish/shared ' overlaps site 'c1.example' storage '/srv/publish/shared'",
                ),
                ("E202", Some("site[0].root"), &expected_cfg_msg),
                (
                    "E202",
                    Some("sites.1.root"),
                    "site root '/srv/publish/shared' overlaps ai-publish.storage '/srv/publish/shared' and would expose publish metadata/releases",
                ),
            ],
        );
    }

    Ok(())
}

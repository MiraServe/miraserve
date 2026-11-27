//! Round-trip migration tests for Nginx, Caddy, Apache, and OpenLiteSpeed importers.

// `assert_is_empty` is new in clippy 1.100 and unknown to 1.95 (the minimum toolchain).
// `assert!(x.is_empty())` says what these tests mean.
#![allow(unknown_lints, clippy::assert_is_empty)]

use std::fmt::Write as _;
use std::fs;

use miraserve_config::{FastCgiTarget, RouteHandler, SitePreset, parse_kdl};
use miraserve_migrate::{SourceFormat, migrate_str};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn migrates_nginx_wordpress_and_proxy_to_valid_kdl() -> TestResult {
    let nginx = r"
server {
    listen 80;
    server_name blog.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name blog.example.com www.blog.example.com;
    root /var/www/wordpress;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_certificate /etc/ssl/blog.crt;
    ssl_certificate_key /etc/ssl/blog.key;

    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    }

    location /api/ {
        proxy_pass https://10.0.1.50:8443;
    }

    location / {
        try_files $uri $uri/ /index.php?$args;
    }
}
";

    let report = migrate_str(nginx, SourceFormat::Auto)?;
    assert_eq!(report.source_format, SourceFormat::Nginx);
    assert_eq!(report.migrated_sites, 1);
    assert_eq!(report.migrated_routes, 3);

    let (cfg, _) = parse_kdl("migrated-nginx.kdl", &report.kdl)?;
    let site = cfg.sites.first().ok_or("missing site")?;
    assert_eq!(site.hosts, vec!["blog.example.com", "www.blog.example.com"]);
    assert_eq!(site.preset, Some(SitePreset::WordpressHardened));
    assert_eq!(site.root.as_deref(), Some("/var/www/wordpress"));
    assert!(site.routes.iter().any(|r| matches!(
        &r.handler,
        RouteHandler::FastCgi(fcgi) if matches!(&fcgi.target, FastCgiTarget::Unix { path } if path == "/run/php/php8.3-fpm.sock")
    )));
    assert!(
        site.routes
            .iter()
            .any(|r| matches!(&r.handler, RouteHandler::ReverseProxy(_)))
    );
    assert!(
        site.routes
            .iter()
            .any(|r| matches!(&r.handler, RouteHandler::TryFiles(_)))
    );
    Ok(())
}

#[test]
fn migrates_caddyfile_to_valid_kdl() -> TestResult {
    let caddy = r"
{
    email ops@caddy-site.example
}

app.caddy-site.example {
    root * /var/www/app
    handle /v1/* {
        reverse_proxy https://10.0.2.10:8000 https://10.0.2.11:8000 {
            header_up Host {upstream_hostport}
        }
    }
    handle /* {
        file_server
    }
}
";

    let report = migrate_str(caddy, SourceFormat::Auto)?;
    assert_eq!(report.source_format, SourceFormat::Caddy);
    let (cfg, _) = parse_kdl("migrated-caddy.kdl", &report.kdl)?;
    assert_eq!(
        cfg.server.tls.acme.as_ref().map(|a| a.email.as_str()),
        Some("ops@caddy-site.example")
    );
    let site = cfg.sites.first().ok_or("missing site")?;
    assert_eq!(site.hosts, vec!["app.caddy-site.example"]);
    assert_eq!(site.routes.len(), 2);
    Ok(())
}

#[test]
fn migrates_apache_virtualhost_wordpress_to_valid_kdl() -> TestResult {
    let apache = r#"
<VirtualHost *:443>
    ServerName shop.example.org
    ServerAlias www.shop.example.org
    ServerAdmin admin@shop.example.org
    DocumentRoot "/var/www/wordpress"
    SSLCertificateFile /etc/ssl/shop.crt
    SSLCertificateKeyFile /etc/ssl/shop.key

    ProxyPass /api https://10.0.3.20:8443
    <FilesMatch "\.php$">
        SetHandler "proxy:unix:/run/php/php8.3-fpm.sock|fcgi://localhost"
    </FilesMatch>
    RewriteRule . /index.php [L]
</VirtualHost>
"#;

    let report = migrate_str(apache, SourceFormat::Auto)?;
    assert_eq!(report.source_format, SourceFormat::Apache);
    let (cfg, _) = parse_kdl("migrated-apache.kdl", &report.kdl)?;
    let site = cfg.sites.first().ok_or("missing site")?;
    assert_eq!(site.hosts, vec!["shop.example.org", "www.shop.example.org"]);
    assert_eq!(site.preset, Some(SitePreset::WordpressHardened));
    assert!(site.routes.iter().any(|r| r.pattern == "*.php"));
    assert!(site.routes.iter().any(|r| r.pattern == "/api/*"));
    assert!(site.routes.iter().any(|r| r.pattern == "/*"));
    Ok(())
}

#[test]
fn migrates_openlitespeed_vhconf_to_valid_kdl() -> TestResult {
    let ols = r"
vhDomain                  ols.example.net, www.ols.example.net
docRoot                   /var/www/wordpress
adminEmails               ops@ols.example.net

extprocessor phpfpm83 {
  type                    fcgi
  address                 uds://tmp/lshttpd/phpfpm.sock
}

extprocessor api_backend {
  type                    proxy
  address                 https://10.0.4.10:8080
}

context /api/ {
  type                    proxy
  handler                 api_backend
}

vhssl  {
  keyFile                 /etc/ssl/ols.key
  certFile                /etc/ssl/ols.crt
}

rewrite  {
  rules                   RewriteRule . /index.php [L]
}
";

    let report = migrate_str(ols, SourceFormat::Auto)?;
    assert_eq!(report.source_format, SourceFormat::OpenLiteSpeed);
    assert!(report.security_downgrades.is_empty());
    let (cfg, _) = parse_kdl("migrated-ols.kdl", &report.kdl)?;
    let site = cfg.sites.first().ok_or("missing site")?;
    assert_eq!(site.hosts, vec!["ols.example.net", "www.ols.example.net"]);
    assert_eq!(site.preset, Some(SitePreset::WordpressHardened));
    assert!(site.routes.iter().any(|r| r.pattern == "*.php"));
    assert!(site.routes.iter().any(|r| r.pattern == "/api/*"));
    // MIG-7: `uds://tmp/lshttpd/phpfpm.sock` must preserve leading `/` -> `unix:/tmp/lshttpd/phpfpm.sock`.
    assert!(site.routes.iter().any(|r| matches!(
        &r.handler,
        RouteHandler::FastCgi(fcgi) if matches!(&fcgi.target, FastCgiTarget::Unix { path } if path == "/tmp/lshttpd/phpfpm.sock")
    )));
    Ok(())
}

#[test]
fn nginx_one_line_locations_nested_blocks_upstreams_exact_and_security_omission() -> TestResult {
    let nginx = r#"
upstream app_pool {
    server 10.0.5.10:8080;
    server 10.0.5.11:8080;
}

server {
    listen 127.0.0.1:8443 ssl;
    server_name *.internal.example;

    location = /health {
        proxy_set_header Host $host;
        proxy_pass http://app_pool;
    }

    location /admin/ {
        auth_basic "Restricted";
        auth_basic_user_file /etc/nginx/.htpasswd;
        proxy_pass http://127.0.0.1:9000;
    }

    location /public/ {
        if ($request_method = OPTIONS) {
            return 204;
        }
        proxy_pass http://10.0.5.20:8080/v1/;
    }
}
"#;

    let report = migrate_str(nginx, SourceFormat::Auto)?;
    assert_eq!(report.source_format, SourceFormat::Nginx);
    // MIG-3: `/admin/` auth_basic must produce a security downgrade AND omit `/admin/` route!
    assert!(
        !report.security_downgrades.is_empty(),
        "expected security_downgrades for auth_basic"
    );

    let (cfg, _) = parse_kdl("migrated-nginx-sec.kdl", &report.kdl)?;
    // MIG-4: loopback bind `127.0.0.1:8443` preserved and NO public `:80` emitted!
    assert_eq!(cfg.server.listeners.len(), 1);
    assert_eq!(
        cfg.server
            .listeners
            .first()
            .map(|l| l.addr.to_string())
            .as_deref(),
        Some("127.0.0.1:8443")
    );

    let site = cfg.sites.first().ok_or("missing site")?;
    // MIG-6: wildcard host `*.internal.example` preserved!
    assert_eq!(site.hosts, vec!["*.internal.example"]);
    // MIG-3: `/admin/` route MUST NOT be emitted open!
    assert!(
        !site.routes.iter().any(|r| r.pattern.contains("admin")),
        "protected /admin/ route must be omitted, got routes: {:?}",
        site.routes
    );
    // MIG-7: exact `location = /health` NOT widened to `/health/*`!
    let health = site
        .routes
        .iter()
        .find(|r| r.pattern == "/health")
        .ok_or("missing exact /health route")?;
    // MIG-6: `upstream app_pool` resolved to both pool members!
    assert!(matches!(
        &health.handler,
        RouteHandler::ReverseProxy(rp) if rp.upstreams.len() == 2
    ));
    // MIG-6: the nested `if` inside `/public/` did NOT prematurely close the location (the
    // `/health` route after it parsed), and the location is withheld: `if (...) { return 204; }`
    // answers matching requests itself in the source, so dropping it would turn them into real
    // upstream calls.
    assert!(
        !site.routes.iter().any(|r| r.pattern == "/public/*"),
        "a location with an untranslated `if` must be withheld, got routes: {:?}",
        site.routes
    );
    assert!(
        report
            .security_downgrades
            .iter()
            .any(|d| d.directive.contains("if")),
        "expected a downgrade naming the untranslated `if`: {:?}",
        report.security_downgrades
    );
    Ok(())
}

#[test]
fn apache_access_control_and_loopback_bind_preserved() -> TestResult {
    // Pure reverse-proxy vhost (no DocumentRoot static fallback): `/admin` is genuinely omitted
    // while non-overlapping `/public/*` remains safe and loopback bind `127.0.0.1:8443` is preserved.
    let apache = r"
<VirtualHost 127.0.0.1:8443>
    ServerName internal.corp.test
    <Location /public>
        ProxyPass http://127.0.0.1:3000
    </Location>
    <Location /admin>
        Require valid-user
        AuthType Basic
        ProxyPass http://127.0.0.1:9000
    </Location>
</VirtualHost>
";
    let report = migrate_str(apache, SourceFormat::Auto)?;
    assert_eq!(report.source_format, SourceFormat::Apache);
    assert!(
        !report.security_downgrades.is_empty(),
        "Require valid-user / AuthType must emit security_downgrades"
    );
    let (cfg, _) = parse_kdl("apache-sec.kdl", &report.kdl)?;
    assert_eq!(cfg.server.listeners.len(), 1);
    assert_eq!(
        cfg.server
            .listeners
            .first()
            .map(|l| l.addr.to_string())
            .as_deref(),
        Some("127.0.0.1:8443")
    );
    let site = cfg.sites.first().ok_or("missing site")?;
    assert!(site.routes.iter().any(|r| r.pattern == "/public/*"));
    assert!(
        !site.routes.iter().any(|r| r.pattern.contains("admin")),
        "/admin protected by Require valid-user must be omitted"
    );

    // R5-MIG-4: When `DocumentRoot` IS set alongside `<Location /admin> Require valid-user`,
    // static root fallback would serve `/admin`, so default fail-closed withholds the site and
    // `--allow-insecure` tags it `// INSECURE:`!
    let apache_with_root = r#"
<VirtualHost 127.0.0.1:8443>
    ServerName internal.corp.test
    DocumentRoot "/var/www/app"
    <Location /public>
        ProxyPass http://127.0.0.1:3000
    </Location>
    <Location /admin>
        Require valid-user
        AuthType Basic
        ProxyPass http://127.0.0.1:9000
    </Location>
</VirtualHost>
"#;
    assert!(matches!(
        migrate_str(apache_with_root, SourceFormat::Apache),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));
    let insecure_rep = miraserve_migrate::migrate_str_with_options(
        apache_with_root,
        SourceFormat::Apache,
        miraserve_migrate::MigrateOptions {
            allow_insecure: true,
            ..miraserve_migrate::MigrateOptions::default()
        },
    )?;
    assert_eq!(
        insecure_rep.insecure_sites_emitted,
        vec!["internal.corp.test".to_owned()]
    );
    assert!(insecure_rep.kdl.contains("// INSECURE:"));
    Ok(())
}

#[test]
fn caddy_named_matcher_try_files_detection_and_basicauth() -> TestResult {
    // MIG-7: Caddyfile containing `try_files` MUST be detected as Caddy, not Nginx!
    // MIG-5 & R5-MIG-4: site-level `reverse_proxy @internal 127.0.0.1:9000` fails closed under
    // default mode (never becoming catch-all or `http://@internal`), and under `--allow-insecure`
    // still omits `127.0.0.1:9000`, preserves `bind 127.0.0.1`, and tags the site `// INSECURE:`!
    let caddy = r"
app.example.test {
    bind 127.0.0.1
    root * /var/www/app
    @internal remote_ip 10.0.0.0/8
    reverse_proxy @internal 127.0.0.1:9000
    handle /public/* {
        try_files {path} {path}/ /index.html
    }
}
";
    assert!(matches!(
        migrate_str(caddy, SourceFormat::Auto),
        Err(
            miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity {
                format: SourceFormat::Caddy,
                ..
            }
        )
    ));
    let report = miraserve_migrate::migrate_str_with_options(
        caddy,
        SourceFormat::Auto,
        miraserve_migrate::MigrateOptions {
            allow_insecure: true,
            ..miraserve_migrate::MigrateOptions::default()
        },
    )?;
    assert_eq!(report.source_format, SourceFormat::Caddy);
    assert!(
        !report.security_downgrades.is_empty(),
        "named matcher @internal route must record a security downgrade"
    );
    assert_eq!(
        report.insecure_sites_emitted,
        vec!["app.example.test".to_owned()]
    );
    let (cfg, _) = parse_kdl("caddy-matcher.kdl", &report.kdl)?;
    // MIG-4: `bind 127.0.0.1` preserved!
    assert_eq!(
        cfg.server
            .listeners
            .first()
            .map(|l| l.addr.to_string())
            .as_deref(),
        Some("127.0.0.1:443")
    );
    let site = cfg.sites.first().ok_or("missing site")?;
    assert!(
        !site
            .routes
            .iter()
            .any(|r| matches!(&r.handler, RouteHandler::ReverseProxy(_))),
        "@internal reverse_proxy must be omitted, never turned into catch-all or http://@internal"
    );
    assert!(site.routes.iter().any(|r| r.pattern == "/public/*"));
    Ok(())
}

/// R2-MIG-1, R2-MIG-2, R2-MIG-3, R2-MIG-4 regression tests covering Nginx, Apache, Caddy, and OLS.
#[test]
#[allow(clippy::too_many_lines)]
fn importers_wave2_security_downgrades_and_bind_address_preservation() -> TestResult {
    // 1. Nginx: http-level allow/deny, unexpanded `include`, `location ~ /\.git { deny all; }` on
    //    catch-all proxy, `internal`/`auth_jwt`/`access_by_lua`, bare IP `listen 127.0.0.1;`,
    //    `listen unix:...`, and catch-all `return 444`.
    let nginx_http_acl = r"
http {
    allow 10.0.0.0/8;
    deny all;
    server {
        listen 127.0.0.1;
        server_name internal.example.test;
        location / {
            proxy_pass http://127.0.0.1:8080;
        }
    }
}
";
    let res_http = migrate_str(nginx_http_acl, SourceFormat::Nginx);
    assert!(
        matches!(
            res_http,
            Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
        ),
        "http-level allow/deny must fail closed and withhold inherited server routes, got: {res_http:?}"
    );

    let nginx_bare_ip = r"
server {
    listen 127.0.0.1;
    server_name loopback.example.test;
    location / {
        proxy_pass http://127.0.0.1:8080;
    }
}
";
    let rep_bare = migrate_str(nginx_bare_ip, SourceFormat::Nginx)?;
    let (cfg_bare, _) = parse_kdl("nginx-bare.kdl", &rep_bare.kdl)?;
    assert_eq!(
        cfg_bare
            .server
            .listeners
            .first()
            .map(|l| l.addr.to_string())
            .as_deref(),
        Some("127.0.0.1:443"),
        "bare IP `listen 127.0.0.1;` must preserve loopback scope and terminate TLS on :443 (not port 80, R3-MIG-8)"
    );
    assert!(
        cfg_bare
            .server
            .listeners
            .iter()
            .any(|l| l.addr.to_string() == "127.0.0.1:80" && l.redirect_https),
        "bare IP `listen 127.0.0.1;` should keep 127.0.0.1:80 as HTTP->HTTPS redirect"
    );

    let nginx_inc_and_git = r"
server {
    listen 443 ssl;
    server_name app.example.test;
    location /secret {
        include snippets/basic-auth.conf;
        proxy_pass http://127.0.0.1:9000;
    }
    location /internal-cb {
        internal;
        proxy_pass http://127.0.0.1:9001;
    }
    location /api {
        auth_jwt on;
        proxy_pass http://127.0.0.1:9002;
    }
    location ~ /\.git {
        deny all;
    }
    location / {
        proxy_pass http://127.0.0.1:3000;
    }
}
";
    let rep_inc = migrate_str(nginx_inc_and_git, SourceFormat::Nginx);
    match rep_inc {
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { downgrades, .. }) => {
            assert!(
                downgrades.len() >= 4,
                "expected downgrades for include, internal, auth_jwt, and /.git deny on proxy; got {downgrades:?}"
            );
        }
        other => {
            return Err(format!(
                "expected AllRoutesBlockedBySecurity when /.git deny blocks catch-all proxy, got {other:?}"
            )
            .into());
        }
    }

    // Nginx `listen unix:` downgrade + catch-all `return 444` fails closed without emitting open routes
    let nginx_unix_444 = r"
server {
    listen unix:/run/nginx.sock;
    listen 80 default_server;
    return 444;
}
";
    match migrate_str(nginx_unix_444, SourceFormat::Nginx) {
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { downgrades, .. }) => {
            assert!(
                downgrades
                    .iter()
                    .any(|d| d.directive == "listen" || d.directive == "return"),
                "expected downgrade for unix listen / return 444, got {downgrades:?}"
            );
        }
        Ok(rep) => {
            assert!(
                rep.security_downgrades
                    .iter()
                    .any(|d| d.directive == "listen" || d.directive == "return"),
                "expected downgrade for unix listen / return 444, got {:?}",
                rep.security_downgrades
            );
        }
        Err(other) => return Err(format!("unexpected migrate error: {other:?}").into()),
    }

    // 2. Apache: global `<Directory>` + `Require` + global `Listen 127.0.0.1:8080` + `Include`
    let apache_global = r#"
Listen 127.0.0.1:8080
Include conf-enabled/auth.conf
<Directory /var/www/app>
    Require ip 10.0.0.0/8
</Directory>
<VirtualHost *:8080>
    ServerName corp.example.test
    DocumentRoot "/var/www/app"
    <Location /open>
        ProxyPass http://127.0.0.1:4000
    </Location>
</VirtualHost>
"#;
    match migrate_str(apache_global, SourceFormat::Apache) {
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { downgrades, .. }) => {
            assert!(
                downgrades.len() >= 2,
                "expected Apache global Include + Require downgrades, got {downgrades:?}"
            );
        }
        Ok(rep_ap) => {
            assert!(
                rep_ap.security_downgrades.len() >= 2,
                "expected Apache global Include + Require downgrades, got {:?}",
                rep_ap.security_downgrades
            );
        }
        Err(other) => return Err(format!("unexpected apache error: {other:?}").into()),
    }

    // Verify global Apache `Listen 127.0.0.1:8080` preserves loopback without widening to `:443`
    let apache_loopback = r"
Listen 127.0.0.1:8080
<VirtualHost *:8080>
    ServerName local.example.test
    <Location /health>
        ProxyPass http://127.0.0.1:4000
    </Location>
</VirtualHost>
";
    let rep_ap_lo = migrate_str(apache_loopback, SourceFormat::Apache)?;
    let (cfg_ap, _) = parse_kdl("apache-loopback.kdl", &rep_ap_lo.kdl)?;
    assert_eq!(
        cfg_ap
            .server
            .listeners
            .iter()
            .map(|l| l.addr.to_string())
            .collect::<Vec<_>>(),
        vec!["127.0.0.1:8080".to_owned()],
        "global Apache Listen 127.0.0.1:8080 must stay loopback-only"
    );

    // 3. Caddy: `import` and blocking `error @denied 403` emit security downgrades (failing closed)
    let caddy_imp = r"
secure.example.test {
    import common_auth
    error @denied 403
    reverse_proxy /api/* 127.0.0.1:8000
}
";
    let caddy_downgrades = match migrate_str(caddy_imp, SourceFormat::Caddy) {
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { downgrades, .. }) => {
            downgrades
        }
        Ok(rep) => rep.security_downgrades,
        Err(other) => return Err(format!("unexpected caddy error: {other:?}").into()),
    };
    assert!(
        caddy_downgrades.iter().any(|d| d.directive == "import"),
        "Caddy import must emit security downgrade: {caddy_downgrades:?}"
    );
    assert!(
        caddy_downgrades.iter().any(|d| d.directive == "error"),
        "Caddy blocking error must emit security downgrade: {caddy_downgrades:?}"
    );

    // 4. OpenLiteSpeed: `listener { address 127.0.0.1:8088 }`, `context { allowBrowse 0 }`, and
    //    `lsapi` MUST fail closed by default (`R2-MIG-4`, `R5-MIG-1`, `R5-MIG-4`), and under
    //    `--allow-insecure` tag the site `// INSECURE:` while still omitting `fastcgi-pass` and
    //    preserving `127.0.0.1:8088`!
    let ols = r"
listener local {
    address 127.0.0.1:8088
}
virtualHost app.example.test {
    docRoot /var/www/ols
    context /private {
        allowBrowse 0
    }
    extprocessor lsphp83 {
        type lsapi
        address uds://tmp/lshttpd/lsphp.sock
    }
}
";
    assert!(matches!(
        migrate_str(ols, SourceFormat::OpenLiteSpeed),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));
    let rep_ols = miraserve_migrate::migrate_str_with_options(
        ols,
        SourceFormat::OpenLiteSpeed,
        miraserve_migrate::MigrateOptions {
            allow_insecure: true,
            ..miraserve_migrate::MigrateOptions::default()
        },
    )?;
    assert!(
        rep_ols
            .security_downgrades
            .iter()
            .any(|d| d.directive == "allowBrowse"),
        "OLS allowBrowse 0 must emit security downgrade"
    );
    assert!(
        rep_ols
            .security_downgrades
            .iter()
            .any(|d| d.directive == "extprocessor.lsapi"),
        "OLS lsapi must emit security downgrade (and omit fastcgi-pass), got {:?}",
        rep_ols.security_downgrades
    );
    assert!(
        !rep_ols.kdl.contains("fastcgi-pass"),
        "OLS lsapi must NOT be emitted as fastcgi-pass"
    );
    assert_eq!(
        rep_ols.insecure_sites_emitted,
        vec!["app.example.test".to_owned()]
    );
    assert!(rep_ols.kdl.contains("// INSECURE:"));
    let (cfg_ols, _) = parse_kdl("ols-wave2.kdl", &rep_ols.kdl)?;
    assert_eq!(
        cfg_ols
            .server
            .listeners
            .iter()
            .map(|l| l.addr.to_string())
            .collect::<Vec<_>>(),
        vec!["127.0.0.1:8088".to_owned()],
        "OLS listener address must be preserved without widening to :443"
    );
    Ok(())
}

/// Round-3 Importer regressions (`R3-MIG-1` through `R3-MIG-8`):
/// - `R3-MIG-1`: Nginx `access_by_lua_block { ... }` withholds the route with a security downgrade
/// - `R3-MIG-2`: Caddy `route @internal { reverse_proxy ... }`, `redir @m`, `rewrite @m`, and
///   unknown blocks are withheld instead of leaking inner directives as open routes
/// - `R3-MIG-3`: Certbot Nginx/Apache & stock distro configs (`options-ssl-nginx.conf`, Certbot
///   port-80 redirect server, `snippets/fastcgi-php.conf`, `modules-enabled/*.conf`, stock Apache
///   `<Directory /> Require all denied`, `options-ssl-apache.conf`) import cleanly, AND
///   `MigrateOptions { allow_insecure: true }` emits globally-blocked sites with warnings
/// - `R3-MIG-4`: Mixed loopback + public sites withhold the loopback site instead of exposing it
/// - `R3-MIG-5`: Apache global `AllowOverride`/`AuthGroupFile`/blocking `RewriteRule` (`[f]`/`[r=403]`)
///   and `Redirect 403` / `RedirectMatch 404` emit security downgrades
/// - `R3-MIG-6`: Nginx `location ~ /\. { deny all; }` on prefix-proxy `/api/` emits a downgrade
/// - `R3-MIG-7`: Caddy `{ default_bind 127.0.0.1 }` binds `127.0.0.1:443` instead of `:443`
/// - `R3-MIG-8`: OLS `[ANY]:443` normalizes to `:443`, OLS listener `clientVerify` downgrades,
///   Caddy `localhost` + public site isolates `localhost` and keeps `:443`, Nginx `@fallback`
///   is skipped, and Nginx `if (...) { return 400; }` downgrades.
#[test]
#[allow(clippy::too_many_lines)]
fn importers_round3_security_stock_configs_and_scope_isolation() -> TestResult {
    // 1. R3-MIG-1: Nginx `access_by_lua_block { ... }` MUST NOT be emitted as an open route!
    let nginx_lua = r#"
server {
    listen 443 ssl;
    server_name lua.example.test;
    location /secret {
        access_by_lua_block {
            ngx.exit(ngx.HTTP_FORBIDDEN)
        }
        proxy_pass http://127.0.0.1:9000;
    }
    location /health {
        proxy_pass http://127.0.0.1:8080;
    }
    location @fallback {
        proxy_pass http://127.0.0.1:8081;
    }
    location /guarded {
        if ($http_x_token = "") {
            return 400;
        }
        proxy_pass http://127.0.0.1:8082;
    }
}
"#;
    let rep_lua = migrate_str(nginx_lua, SourceFormat::Nginx)?;
    assert!(
        rep_lua
            .security_downgrades
            .iter()
            .any(|d| d.directive == "access_by_lua_block"),
        "access_by_lua_block must emit a security downgrade: {:?}",
        rep_lua.security_downgrades
    );
    assert!(
        !rep_lua.kdl.contains("/secret"),
        "route guarded by access_by_lua_block must be withheld"
    );
    assert!(
        !rep_lua.kdl.contains("@fallback"),
        "R3-MIG-8: named @fallback location must not become /@fallback/*"
    );
    assert!(
        !rep_lua.kdl.contains("/guarded"),
        "R3-MIG-8: location with `if (...) return 400` must be withheld"
    );
    assert!(rep_lua.kdl.contains("/health"));

    // 2. R3-MIG-2 & R5-MIG-4: Caddy `route @internal { reverse_proxy admin:9000 }` & unknown
    //    blocks fail closed at site level (and under `--allow-insecure` still omit `admin:9000`
    //    and `secret:9999` while tagging the site `// INSECURE:`)!
    let caddy_route_matcher = r"
app.example.test {
    @internal remote_ip 10.0.0.0/8
    route @internal {
        reverse_proxy admin:9000
    }
    redir @internal /ok
    rewrite @internal /internal
    custom_auth_block {
        reverse_proxy secret:9999
    }
    reverse_proxy /public/* web:8080
}
";
    assert!(matches!(
        migrate_str(caddy_route_matcher, SourceFormat::Caddy),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));
    let rep_caddy = miraserve_migrate::migrate_str_with_options(
        caddy_route_matcher,
        SourceFormat::Caddy,
        miraserve_migrate::MigrateOptions {
            allow_insecure: true,
            ..miraserve_migrate::MigrateOptions::default()
        },
    )?;
    assert!(
        rep_caddy
            .security_downgrades
            .iter()
            .any(|d| d.directive == "route")
    );
    assert!(
        rep_caddy
            .security_downgrades
            .iter()
            .any(|d| d.directive == "redir")
    );
    assert!(
        rep_caddy
            .security_downgrades
            .iter()
            .any(|d| d.directive == "rewrite")
    );
    assert!(
        rep_caddy
            .security_downgrades
            .iter()
            .any(|d| d.directive == "custom_auth_block")
    );
    assert!(!rep_caddy.kdl.contains("admin:9000"));
    assert!(!rep_caddy.kdl.contains("secret:9999"));
    assert!(rep_caddy.kdl.contains("web:8080"));
    assert_eq!(
        rep_caddy.insecure_sites_emitted,
        vec!["app.example.test".to_owned()]
    );

    // 3. R3-MIG-3: Stock Certbot Nginx & stock Apache configs import cleanly with ZERO security downgrades!
    let certbot_nginx = r"
include /etc/nginx/modules-enabled/*.conf;
http {
    include /etc/nginx/mime.types;
    server {
        listen 443 ssl;
        server_name blog.example.com;
        root /var/www/wordpress;
        include /etc/letsencrypt/options-ssl-nginx.conf;
        ssl_certificate /etc/letsencrypt/live/blog.example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/blog.example.com/privkey.pem;
        location ~ \.php$ {
            include snippets/fastcgi-php.conf;
            fastcgi_pass unix:/run/php/php8.3-fpm.sock;
        }
        location ~ /\.ht {
            deny all;
        }
        location / {
            try_files $uri $uri/ /index.php?$args;
        }
    }
    server {
        if ($host = blog.example.com) {
            return 301 https://$host$request_uri;
        }
        listen 80;
        server_name blog.example.com;
        return 404;
    }
}
";
    let rep_certbot = migrate_str(certbot_nginx, SourceFormat::Nginx)?;
    assert!(
        rep_certbot.security_downgrades.is_empty(),
        "stock Certbot Nginx WordPress config must import cleanly, got downgrades: {:?}",
        rep_certbot.security_downgrades
    );
    assert_eq!(rep_certbot.migrated_sites, 1);

    let stock_apache = r"
IncludeOptional mods-enabled/*.load
IncludeOptional mods-enabled/*.conf
<Directory />
    AllowOverride none
    Require all denied
</Directory>
<VirtualHost *:443>
    ServerName shop.example.com
    DocumentRoot /var/www/html
    Include /etc/letsencrypt/options-ssl-apache.conf
    SSLCertificateFile /etc/letsencrypt/live/shop.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/shop.example.com/privkey.pem
</VirtualHost>
";
    let rep_ap = migrate_str(stock_apache, SourceFormat::Apache)?;
    assert!(
        rep_ap.security_downgrades.is_empty(),
        "stock Apache + Certbot config must import cleanly, got downgrades: {:?}",
        rep_ap.security_downgrades
    );
    assert_eq!(rep_ap.migrated_sites, 1);

    // R3-MIG-3: `--allow-insecure` (`MigrateOptions { allow_insecure: true }`) emits globally blocked sites!
    let global_blocked = r"
http {
    allow 10.0.0.0/8;
    deny all;
    server {
        listen 443 ssl;
        server_name locked.example.test;
        root /var/www/locked;
    }
}
";
    assert!(migrate_str(global_blocked, SourceFormat::Nginx).is_err());
    let forced = miraserve_migrate::migrate_str_with_options(
        global_blocked,
        SourceFormat::Nginx,
        miraserve_migrate::MigrateOptions {
            allow_insecure: true,
            ..miraserve_migrate::MigrateOptions::default()
        },
    )?;
    assert_eq!(forced.migrated_sites, 1);
    assert!(!forced.security_downgrades.is_empty());

    // 4. R3-MIG-4: Mixed loopback-only admin site + public site MUST withhold admin site!
    let mixed_nginx = r"
server {
    listen 127.0.0.1:8080;
    server_name admin.internal;
    location / {
        proxy_pass http://127.0.0.1:9000;
    }
}
server {
    listen 443 ssl;
    server_name public.example.com;
    root /var/www/public;
}
";
    let rep_mixed = migrate_str(mixed_nginx, SourceFormat::Nginx)?;
    assert!(
        !rep_mixed.kdl.contains("admin.internal"),
        "loopback-only site must be withheld when mixed with public site (R3-MIG-4)"
    );
    assert!(rep_mixed.kdl.contains("public.example.com"));
    assert!(
        rep_mixed
            .security_downgrades
            .iter()
            .any(|d| d.directive == "listen")
    );

    // 5. R3-MIG-5: Apache global AllowOverride/AuthGroupFile, case-insensitive `[f]`/`[r=403]`, RedirectMatch 403
    let apache_gaps = r"
<Directory /var/www/app>
    AllowOverride All
    AuthGroupFile /etc/apache2/groups
</Directory>
<VirtualHost *:443>
    ServerName app.example.com
    DocumentRoot /var/www/app
    RewriteRule ^/secret - [r=403,nc,l]
    RedirectMatch 404 ^/\.git
</VirtualHost>
";
    let err_ap = migrate_str(apache_gaps, SourceFormat::Apache)
        .err()
        .ok_or("expected AllRoutesBlockedBySecurity for apache_gaps")?;
    let miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { downgrades, .. } = err_ap
    else {
        return Err(format!("unexpected error variant: {err_ap:?}").into());
    };
    assert!(
        downgrades
            .iter()
            .any(|d| d.directive.eq_ignore_ascii_case("allowoverride"))
    );
    assert!(
        downgrades
            .iter()
            .any(|d| d.directive.eq_ignore_ascii_case("authgroupfile"))
    );
    assert!(downgrades.iter().any(|d| d.directive == "RewriteRule"));
    assert!(
        downgrades
            .iter()
            .any(|d| d.directive.eq_ignore_ascii_case("redirectmatch"))
    );

    // 6. R3-MIG-6: Nginx `location ~ /\. { deny all; }` on prefix-proxy site MUST downgrade!
    let nginx_prefix_dot = r"
server {
    listen 443 ssl;
    server_name api.example.com;
    root /var/www/static;
    location ~ /\. {
        deny all;
    }
    location /api/ {
        proxy_pass http://127.0.0.1:3000;
    }
}
";
    assert!(
        matches!(
            migrate_str(nginx_prefix_dot, SourceFormat::Nginx),
            Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
        ),
        "dotfile deny on prefix-proxy site must fail closed (R3-MIG-6)"
    );

    // 7. R3-MIG-7: Caddy `{ default_bind 127.0.0.1 }` binds loopback `127.0.0.1:443`!
    let caddy_default_bind = r"
{
    default_bind 127.0.0.1
}
internal.example.test {
    reverse_proxy 127.0.0.1:8080
}
";
    let rep_default_bind = migrate_str(caddy_default_bind, SourceFormat::Caddy)?;
    let (cfg_db, _) = parse_kdl("caddy-db.kdl", &rep_default_bind.kdl)?;
    assert_eq!(
        cfg_db
            .server
            .listeners
            .iter()
            .map(|l| l.addr.to_string())
            .collect::<Vec<_>>(),
        vec!["127.0.0.1:443".to_owned()]
    );

    // 8. R3-MIG-8: Caddy `localhost` alongside public site keeps `:443` and withholds `localhost`;
    //    OLS `[ANY]:443` normalizes to `:443`; OLS listener `clientVerify` downgrades.
    let caddy_mixed = r"
localhost {
    reverse_proxy 127.0.0.1:9000
}
public.example.com {
    root * /var/www/public
    file_server
}
";
    let rep_caddy_mixed = migrate_str(caddy_mixed, SourceFormat::Caddy)?;
    assert!(!rep_caddy_mixed.kdl.contains("9000"));
    assert!(rep_caddy_mixed.kdl.contains("public.example.com"));
    let (cfg_cm, _) = parse_kdl("caddy-mixed.kdl", &rep_caddy_mixed.kdl)?;
    assert!(
        cfg_cm
            .server
            .listeners
            .iter()
            .any(|l| l.addr.to_string() == ":443")
    );

    let ols_any = r"
listener Default {
    address [ANY]:443
}
virtualHost ols.example.com {
    docRoot /var/www/ols
}
";
    let rep_ols_any = migrate_str(ols_any, SourceFormat::OpenLiteSpeed)?;
    let (cfg_ols_any, _) = parse_kdl("ols-any.kdl", &rep_ols_any.kdl)?;
    assert!(
        cfg_ols_any
            .server
            .listeners
            .iter()
            .any(|l| l.addr.to_string() == ":443")
    );

    let ols_mtls = r"
listener Secure {
    address [ANY]:443
    clientVerify 1
}
virtualHost mtls.example.com {
    docRoot /var/www/mtls
}
";
    assert!(matches!(
        migrate_str(ols_mtls, SourceFormat::OpenLiteSpeed),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    Ok(())
}

/// R4-MIG-3 & R5-MIG-7: Tests against **byte-for-byte unmodified** upstream distribution and
/// project configuration files in `tests/fixtures/` (see `tests/fixtures/SOURCES.md` for URLs,
/// versions, and SHA-256 hashes — zero fixture edits!).
#[test]
#[allow(clippy::too_many_lines)]
fn importers_round5_upstream_byte_for_byte_fixtures() -> TestResult {
    let tmp_base = std::env::temp_dir().join(format!(
        "miraserve-r5-fixtures-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&tmp_base)?;

    // 1. WordPress.org Developer Handbook single-site Nginx recipe (byte-for-byte):
    //    https://developer.wordpress.org/advanced-administration/server/web-server/nginx/
    //    Contains `upstream php { server unix:/tmp/php-cgi.socket; server 127.0.0.1:9000; }` + `fastcgi_pass php;`.
    let wp_org_raw = include_str!("fixtures/wordpress_org_nginx_single_site.conf");
    let rep_wp = migrate_str(wp_org_raw, SourceFormat::Nginx)?;
    assert!(
        rep_wp.security_downgrades.is_empty(),
        "byte-for-byte wordpress.org Nginx recipe must import cleanly: {:?}",
        rep_wp.security_downgrades
    );
    let (cfg_wp, _) = parse_kdl("wordpress-org.kdl", &rep_wp.kdl)?;
    let wp_site = cfg_wp.sites.first().ok_or("missing wordpress site")?;
    assert_eq!(wp_site.hosts, vec!["domain.tld"]);
    assert_eq!(wp_site.preset, Some(SitePreset::WordpressHardened));
    assert!(wp_site.routes.iter().any(|r| matches!(
        &r.handler,
        RouteHandler::FastCgi(fcgi) if matches!(&fcgi.target, FastCgiTarget::Unix { path } if path == "/tmp/php-cgi.socket")
    )));

    // 2. Caddy v2.11.9 stock Caddyfile (byte-for-byte):
    //    https://raw.githubusercontent.com/caddyserver/dist/v2.11.9/config/Caddyfile
    //    `:80 { root * /usr/share/caddy; file_server }` must NOT put TLS `h3,h2,h1` on `:80`!
    let caddy_stock = include_str!("fixtures/caddy_stock_Caddyfile");
    let rep_caddy = migrate_str(caddy_stock, SourceFormat::Caddy)?;
    assert!(
        rep_caddy.security_downgrades.is_empty(),
        "byte-for-byte Caddy v2.11.9 Caddyfile must import cleanly: {:?}",
        rep_caddy.security_downgrades
    );
    let (cfg_caddy, _) = parse_kdl("caddy-stock.kdl", &rep_caddy.kdl)?;
    assert!(
        cfg_caddy
            .server
            .listeners
            .iter()
            .any(|l| l.addr.to_string() == ":443" && !l.redirect_https),
        "stock Caddyfile `:80` must terminate TLS on :443: {:?}",
        cfg_caddy.server.listeners
    );
    assert!(
        cfg_caddy
            .server
            .listeners
            .iter()
            .any(|l| l.addr.to_string() == ":80" && l.redirect_https),
        "stock Caddyfile `:80` must bind :80 as HTTP->HTTPS redirect (never TLS on :80): {:?}",
        cfg_caddy.server.listeners
    );
    assert_eq!(
        cfg_caddy.sites.first().and_then(|s| s.root.as_deref()),
        Some("/usr/share/caddy")
    );

    // 3. Debian 12 `nginx-common 1.22.1-9+deb12u10` `/etc/nginx/sites-available/default` (byte-for-byte)
    let deb_nginx_default = include_str!("fixtures/debian12_nginx_default.conf");
    let rep_deb_def = migrate_str(deb_nginx_default, SourceFormat::Nginx)?;
    assert!(
        rep_deb_def.security_downgrades.is_empty(),
        "byte-for-byte Debian 12 nginx default site must import cleanly: {:?}",
        rep_deb_def.security_downgrades
    );
    let (cfg_deb_def, _) = parse_kdl("debian12-nginx-default.kdl", &rep_deb_def.kdl)?;
    assert_eq!(
        cfg_deb_def.sites.first().and_then(|s| s.root.as_deref()),
        Some("/var/www/html")
    );

    // 4. Debian 12 `nginx-common 1.22.1-9+deb12u10` `/etc/nginx/nginx.conf` (byte-for-byte):
    //    Unexpanded `include /etc/nginx/conf.d/*.conf;` and `sites-enabled/*` MUST fail closed (`R5-MIG-6`).
    let deb_nginx_main = include_str!("fixtures/debian12_nginx.conf");
    assert!(
        matches!(
            migrate_str(deb_nginx_main, SourceFormat::Nginx),
            Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
        ),
        "unexpanded Debian 12 nginx.conf with unread conf.d/*.conf / sites-enabled/* must fail closed"
    );

    // 4b. Bounded local Nginx include expansion via `migrate_file`: expanding `conf.d/*.conf` and
    //     `sites-enabled/*` imports cleanly when `conf.d/` has no ACLs, AND fails closed if
    //     `conf.d/acl.conf` injects an http-level `allow`/`deny`!
    let nginx_tree = tmp_base.join("nginx-tree");
    std::fs::create_dir_all(nginx_tree.join("conf.d"))?;
    std::fs::create_dir_all(nginx_tree.join("sites-enabled"))?;
    std::fs::write(nginx_tree.join("sites-enabled/default"), deb_nginx_default)?;
    std::fs::write(
        nginx_tree.join("nginx.conf"),
        "http {\n    include conf.d/*.conf;\n    include sites-enabled/*;\n}\n",
    )?;
    let rep_ngx_tree =
        miraserve_migrate::migrate_file(nginx_tree.join("nginx.conf"), SourceFormat::Nginx)?;
    assert!(
        rep_ngx_tree.security_downgrades.is_empty(),
        "clean local nginx tree with empty conf.d/ + default site must import cleanly: {:?}",
        rep_ngx_tree.security_downgrades
    );
    std::fs::write(
        nginx_tree.join("conf.d/acl.conf"),
        "allow 10.0.0.0/8;\ndeny all;\n",
    )?;
    assert!(
        matches!(
            miraserve_migrate::migrate_file(nginx_tree.join("nginx.conf"), SourceFormat::Nginx),
            Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
        ),
        "R5-MIG-6: http-level allow/deny inside conf.d/acl.conf MUST fail closed when expanded"
    );

    // 5. Debian 12 `apache2 2.4.71-1~deb12u1` `/etc/apache2/sites-available/000-default.conf` (byte-for-byte)
    let deb_000 = include_str!("fixtures/debian12_apache_000-default.conf");
    let rep_000 = migrate_str(deb_000, SourceFormat::Apache)?;
    assert!(
        rep_000.security_downgrades.is_empty(),
        "byte-for-byte Debian 12 000-default.conf must import cleanly: {:?}",
        rep_000.security_downgrades
    );
    let (cfg_000, _) = parse_kdl("debian12-000-default.kdl", &rep_000.kdl)?;
    assert!(cfg_000.server.tls.acme.is_none());
    assert_eq!(
        cfg_000.sites.first().and_then(|s| s.root.as_deref()),
        Some("/var/www/html")
    );

    // 6. Full Debian 12 `/etc/apache2/` tree (`apache2.conf` + `ports.conf` + `sites-enabled/000-default.conf`,
    //    all byte-for-byte unmodified!) imported via `migrate_file`: bounded local include expansion
    //    reads `ports.conf`, `conf-enabled/`, and `sites-enabled/000-default.conf` cleanly!
    let deb_ap_dir = tmp_base.join("debian-apache2");
    std::fs::create_dir_all(deb_ap_dir.join("conf-enabled"))?;
    std::fs::create_dir_all(deb_ap_dir.join("sites-enabled"))?;
    std::fs::write(
        deb_ap_dir.join("apache2.conf"),
        include_str!("fixtures/debian12_apache2.conf"),
    )?;
    std::fs::write(
        deb_ap_dir.join("ports.conf"),
        include_str!("fixtures/debian12_apache_ports.conf"),
    )?;
    std::fs::write(deb_ap_dir.join("sites-enabled/000-default.conf"), deb_000)?;
    let rep_deb_ap =
        miraserve_migrate::migrate_file(deb_ap_dir.join("apache2.conf"), SourceFormat::Apache)?;
    assert!(
        rep_deb_ap.security_downgrades.is_empty(),
        "full byte-for-byte Debian 12 apache2 tree must import cleanly via migrate_file: {:?}",
        rep_deb_ap.security_downgrades
    );
    assert_eq!(rep_deb_ap.migrated_sites, 1);
    let (cfg_deb_ap, _) = parse_kdl("debian12-apache2.kdl", &rep_deb_ap.kdl)?;
    assert_eq!(
        cfg_deb_ap.sites.first().and_then(|s| s.root.as_deref()),
        Some("/var/www/html")
    );

    // 7. Full Rocky Linux 9 / RHEL 9 `/etc/httpd/` tree (`conf/httpd.conf` + `conf.d/ssl.conf`,
    //    both byte-for-byte unmodified!) imported via `migrate_file`:
    //    `IncludeOptional conf.d/*.conf` expands `ssl.conf`, `<VirtualHost _default_:443>` inherits
    //    global `DocumentRoot "/var/www/html"`, and preserves `localhost.crt`/`localhost.key` (`R5-MIG-7`)!
    let rhel_dir = tmp_base.join("rhel9-httpd");
    std::fs::create_dir_all(rhel_dir.join("conf"))?;
    std::fs::create_dir_all(rhel_dir.join("conf.d"))?;
    std::fs::write(
        rhel_dir.join("conf/httpd.conf"),
        include_str!("fixtures/rhel9_httpd.conf"),
    )?;
    std::fs::write(
        rhel_dir.join("conf.d/ssl.conf"),
        include_str!("fixtures/rhel9_ssl.conf"),
    )?;
    let rep_rhel =
        miraserve_migrate::migrate_file(rhel_dir.join("conf/httpd.conf"), SourceFormat::Apache)?;
    assert!(
        rep_rhel.security_downgrades.is_empty(),
        "full byte-for-byte RHEL 9 httpd.conf + conf.d/ssl.conf must import cleanly: {:?}",
        rep_rhel.security_downgrades
    );
    let (cfg_rhel, _) = parse_kdl("rhel9-httpd-ssl.kdl", &rep_rhel.kdl)?;
    assert_eq!(cfg_rhel.sites.len(), 1);
    let rhel_site = cfg_rhel.sites.first().ok_or("missing RHEL site")?;
    assert_eq!(rhel_site.root.as_deref(), Some("/var/www/html"));
    assert_eq!(
        rhel_site.tls.as_ref().and_then(|t| t.cert.as_deref()),
        Some("/etc/pki/tls/certs/localhost.crt")
    );
    assert_eq!(
        rhel_site.tls.as_ref().and_then(|t| t.key.as_deref()),
        Some("/etc/pki/tls/private/localhost.key")
    );

    // 8. Certbot v2.11.0 `default-ssl.conf` (byte-for-byte): `_default_:443` + `BrowserMatch \`
    //    continuation + stock `<FilesMatch "\.(cgi|shtml|phtml|php)$"> SSLOptions +StdEnvVars`
    //    imports cleanly with ZERO downgrades!
    let cb_ssl = include_str!("fixtures/certbot_apache_default-ssl.conf");
    let rep_cb_ssl = migrate_str(cb_ssl, SourceFormat::Apache)?;
    assert!(
        rep_cb_ssl.security_downgrades.is_empty(),
        "byte-for-byte Certbot v2.11.0 default-ssl.conf must import cleanly: {:?}",
        rep_cb_ssl.security_downgrades
    );
    let (cfg_cb_ssl, _) = parse_kdl("certbot-default-ssl.kdl", &rep_cb_ssl.kdl)?;
    assert_eq!(
        cfg_cb_ssl.sites.first().and_then(|s| s.root.as_deref()),
        Some("/var/www/html")
    );

    // 9. Certbot v2.11.0 `certbot.conf` (byte-for-byte): has Apache 2.2 open `Order allow,deny` +
    //    `allow from all` on `/var/www/` & `/usr/lib/cgi-bin` (NOT flagged!) AND genuine loopback
    //    ACL `Deny from all; Allow from 127.0.0.0/...` on `/usr/share/doc/` (flagged!).
    let cb_ap = include_str!("fixtures/certbot_apache_certbot.conf");
    let rep_cb_ap = migrate_str(cb_ap, SourceFormat::Apache)?;
    assert!(
        rep_cb_ap
            .security_downgrades
            .iter()
            .any(|d| d.message.contains("/usr/share/doc")),
        "Certbot certbot.conf must catch genuine Deny/Allow ACL on /usr/share/doc: {:?}",
        rep_cb_ap.security_downgrades
    );
    assert!(
        !rep_cb_ap
            .security_downgrades
            .iter()
            .any(|d| d.message.contains("/var/www")),
        "Apache 2.2 `Order allow,deny` + `allow from all` on /var/www/ must NOT be flagged: {:?}",
        rep_cb_ap.security_downgrades
    );

    // 10. Certbot v2.11.0 `both.com` & `sslon.com` (byte-for-byte): parser handles duplicate
    //     hosts and legacy `ssl on;` cleanly (no validation abort).
    let cb_both = include_str!("fixtures/certbot_nginx_both.com.conf");
    assert!(matches!(
        migrate_str(cb_both, SourceFormat::Nginx),
        Err(miraserve_migrate::MigrateError::EmptyMigration { .. })
    ));
    let cb_sslon = include_str!("fixtures/certbot_nginx_sslon.com.conf");
    assert!(matches!(
        migrate_str(cb_sslon, SourceFormat::Nginx),
        Err(miraserve_migrate::MigrateError::EmptyMigration { .. })
    ));

    // 11. OpenLiteSpeed v1.9.4 `Example/vhconf.conf` (byte-for-byte unmodified!):
    //     Upstream genuinely ships `RewriteFile .htaccess`, `context /protected/{ required user test;
    //     realm SampleProtectedArea }`, and `context /blocked/{ allowBrowse 0 }` — fail-closed
    //     import MUST catch ALL THREE and refuse to emit the site open!
    let ols_example = include_str!("fixtures/ols_Example_vhconf.conf");
    let Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity {
        downgrades: ols_ex_dg,
        ..
    }) = migrate_str(ols_example, SourceFormat::OpenLiteSpeed)
    else {
        return Err(
            "byte-for-byte OLS v1.9.4 Example/vhconf.conf has .htaccess + /protected/ + /blocked/ and MUST fail closed"
                .into(),
        );
    };
    assert!(ols_ex_dg.iter().any(|d| d.directive == "RewriteFile"));
    assert!(
        ols_ex_dg
            .iter()
            .any(|d| d.directive == "realm" || d.directive == "required")
    );
    assert!(ols_ex_dg.iter().any(|d| d.directive == "allowBrowse"));

    // 12. OpenLiteSpeed v1.9.4 `httpd_config.conf.in` (byte-for-byte unmodified!):
    //     MUST NOT fail on `module cache`, zero `perClientConnLimit`, or stock `accessDenyDir`,
    //     and MUST detect `extprocessor.lsapi` (`lsphp`) as a security downgrade!
    let ols_httpd = include_str!("fixtures/ols_httpd_config.conf.in");
    let Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity {
        downgrades: ols_hd_dg,
        ..
    }) = migrate_str(ols_httpd, SourceFormat::OpenLiteSpeed)
    else {
        return Err(
            "byte-for-byte OLS v1.9.4 httpd_config.conf.in has lsphp LSAPI and must report extprocessor.lsapi"
                .into(),
        );
    };
    assert!(
        ols_hd_dg
            .iter()
            .any(|d| d.directive == "extprocessor.lsapi"),
        "expected extprocessor.lsapi downgrade: {ols_hd_dg:?}"
    );
    assert!(
        !ols_hd_dg.iter().any(|d| d.directive == "module"
            || d.directive == "perClientConnLimit"
            || d.directive == "accessDenyDir"),
        "stock OLS module cache / zero perClientConnLimit / stock accessDenyDir must NOT downgrade: {ols_hd_dg:?}"
    );

    // 13. Caddyfile with `php_fastcgi unix//run/php/php8.3-fpm.sock`
    let caddy_php_full = r"
{
    email ops@caddy-php.example.com
}

blog.caddy-php.example.com {
    root * /var/www/wordpress
    encode zstd gzip
    php_fastcgi unix//run/php/php8.3-fpm.sock
    file_server
}
";
    let rep_caddy_php = migrate_str(caddy_php_full, SourceFormat::Caddy)?;
    assert!(
        rep_caddy_php.security_downgrades.is_empty(),
        "Caddyfile with php_fastcgi unix// must import cleanly: {:?}",
        rep_caddy_php.security_downgrades
    );
    let (cfg_cphp, _) = parse_kdl("caddy-php.kdl", &rep_caddy_php.kdl)?;
    let cphp_site = cfg_cphp.sites.first().ok_or("missing caddy site")?;
    assert!(cphp_site.routes.iter().any(|r| matches!(
        &r.handler,
        RouteHandler::FastCgi(fcgi) if matches!(&fcgi.target, FastCgiTarget::Unix { path } if path == "/run/php/php8.3-fpm.sock")
    )));

    let _ = std::fs::remove_dir_all(&tmp_base);
    Ok(())
}

/// Round-4 Importer security regressions (`R4-MIG-1`, `R4-MIG-2`, `R4-MIG-4`, `R4-MIG-5`,
/// `R4-MIG-6`, `MIG-6`, `R2-MIG-4`).
#[test]
#[allow(clippy::too_many_lines)]
fn importers_round4_security_regressions() -> TestResult {
    // 1. R4-MIG-1: Apache global `<Directory /var/www/site/admin>` (subdirectory of DocumentRoot),
    //    `<DirectoryMatch>`, regex `<Directory ~ ...>`, wildcard `*`, and unmatched `<Directory>`
    //    MUST ALL fail closed!
    let apache_subdir = r"
<Directory /var/www/site/admin>
    AuthType Basic
    Require valid-user
</Directory>
<VirtualHost *:443>
    ServerName site.example.com
    DocumentRoot /var/www/site
</VirtualHost>
";
    assert!(
        matches!(
            migrate_str(apache_subdir, SourceFormat::Apache),
            Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
        ),
        "R4-MIG-1: global <Directory /var/www/site/admin> MUST block vhost DocumentRoot /var/www/site"
    );

    for (label, bad_dir) in [
        (
            "DirectoryMatch",
            r#"<DirectoryMatch "^/var/www/site/admin">"#,
        ),
        (
            "Directory regex ~",
            r#"<Directory ~ "^/var/www/site/admin">"#,
        ),
        ("Directory wildcard *", r"<Directory /var/www/*/admin>"),
        ("Unmatched Directory", r"<Directory /opt/other/secret>"),
    ] {
        let close_tag = if label == "DirectoryMatch" {
            "</DirectoryMatch>"
        } else {
            "</Directory>"
        };
        let cfg_text = format!(
            "{bad_dir}\n    Require valid-user\n{close_tag}\n<VirtualHost *:443>\n    ServerName s.example.com\n    DocumentRoot /var/www/site\n</VirtualHost>\n"
        );
        assert!(
            matches!(
                migrate_str(&cfg_text, SourceFormat::Apache),
                Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
            ),
            "R4-MIG-1 ({label}) must fail closed"
        );
    }

    // R4-MIG-6: Multiple sites under ONE global `<Directory /var/www>` restriction emit ONE
    // downgrade (not quadratic per-site clones!).
    let apache_multi_site = r"
<Directory /var/www>
    Require valid-user
</Directory>
<VirtualHost *:443>
    ServerName a.example.com
    DocumentRoot /var/www/a
</VirtualHost>
<VirtualHost *:443>
    ServerName b.example.com
    DocumentRoot /var/www/b
</VirtualHost>
<VirtualHost *:443>
    ServerName c.example.com
    DocumentRoot /var/www/c
</VirtualHost>
";
    let Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { downgrades, .. }) =
        migrate_str(apache_multi_site, SourceFormat::Apache)
    else {
        return Err(
            "expected AllRoutesBlockedBySecurity for 3 sites under blocked /var/www".into(),
        );
    };
    assert_eq!(
        downgrades.len(),
        1,
        "global <Directory> restriction must emit 1 downgrade, not 3 clones: {downgrades:?}"
    );

    // 2. R4-MIG-2: `--allow-insecure` emits `// INSECURE: emitted despite ...` per blocked site,
    //    updates KDL header (never claiming omitted!), sets `insecure_sites_emitted`, and does
    //    not claim blocked sites were withheld!
    let insecure_rep = miraserve_migrate::migrate_str_with_options(
        apache_subdir,
        SourceFormat::Apache,
        miraserve_migrate::MigrateOptions {
            allow_insecure: true,
            ..miraserve_migrate::MigrateOptions::default()
        },
    )?;
    assert_eq!(
        insecure_rep.insecure_sites_emitted,
        vec!["site.example.com".to_owned()]
    );
    assert!(
        insecure_rep
            .kdl
            .contains("INSECURE OUTPUT (--allow-insecure)"),
        "KDL header must declare insecure output: {}",
        insecure_rep.kdl
    );
    assert!(
        !insecure_rep.kdl.contains("affected routes were omitted!"),
        "KDL header must NOT claim routes were omitted when blocked site was emitted"
    );
    assert!(
        insecure_rep.kdl.contains("// INSECURE: emitted despite "),
        "blocked site must carry per-site // INSECURE marker: {}",
        insecure_rep.kdl
    );
    assert!(
        insecure_rep
            .security_downgrades
            .iter()
            .all(|d| !d.message.contains("sites withheld")),
        "downgrade messages must not claim sites were withheld when emitted"
    );

    // 3. R4-MIG-4: Apache `Listen 127.0.0.1:8080` + `Listen 443` + `<VirtualHost *:8080>`
    //    resolves `*:8080` strictly to `127.0.0.1:8080` (withheld from public mixed config!).
    let apache_r4_mig4 = r"
Listen 127.0.0.1:8080
Listen 443
<VirtualHost *:8080>
    ServerName internal.local
    DocumentRoot /var/www/internal
</VirtualHost>
<VirtualHost *:443>
    ServerName public.example.com
    DocumentRoot /var/www/public
</VirtualHost>
";
    let rep_mig4 = migrate_str(apache_r4_mig4, SourceFormat::Apache)?;
    assert!(
        !rep_mig4.kdl.contains("internal.local"),
        "R4-MIG-4: *:8080 bound to Listen 127.0.0.1:8080 MUST be withheld from mixed public config: {}",
        rep_mig4.kdl
    );
    assert!(rep_mig4.kdl.contains("public.example.com"));
    assert!(
        rep_mig4
            .security_downgrades
            .iter()
            .any(|d| d.directive == "listen")
    );

    // 4. R4-MIG-5: Basename-only include bypass (`/srv/acl/proxy_params` & `/srv/acl/ports.conf`)
    //    MUST fail closed!
    let nginx_evil_inc = r"
server {
    listen 443 ssl;
    server_name inc.example.com;
    location /admin {
        include /srv/acl/proxy_params;
        proxy_pass http://127.0.0.1:9000;
    }
    location /public {
        include /etc/nginx/proxy_params;
        proxy_pass http://127.0.0.1:8080;
    }
}
";
    let rep_inc = migrate_str(nginx_evil_inc, SourceFormat::Nginx)?;
    assert!(
        !rep_inc.kdl.contains("/admin"),
        "R4-MIG-5: /srv/acl/proxy_params must NOT be trusted by basename"
    );
    assert!(rep_inc.kdl.contains("/public"));
    assert!(
        rep_inc
            .security_downgrades
            .iter()
            .any(|d| d.directive == "include" && d.message.contains("/admin"))
    );
    assert!(
        rep_inc
            .notes
            .iter()
            .any(|n| n.directive == "include" && n.message.contains("/etc/nginx/proxy_params")),
        "canonical /etc/nginx/proxy_params must emit an informational note"
    );

    let apache_evil_inc = r"
Include /srv/acl/ports.conf
<VirtualHost *:443>
    ServerName ap-inc.example.com
    DocumentRoot /var/www/html
</VirtualHost>
";
    assert!(matches!(
        migrate_str(apache_evil_inc, SourceFormat::Apache),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    // 5. R4-MIG-6: WAF/ModSecurity/SSLRequire/CrowdSec/Coraza/OLS module/lsrecaptcha, non-Certbot
    //    `if ($remote_addr != ...)`, `listen hostname:port`, and alternation dotfile regex!
    let nginx_modsec = r"
server {
    listen 443 ssl;
    server_name waf.example.com;
    modsecurity on;
    root /var/www/app;
}
";
    assert!(matches!(
        migrate_str(nginx_modsec, SourceFormat::Nginx),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    let nginx_bad_if = r"
server {
    listen 443 ssl;
    server_name if.example.com;
    if ($remote_addr != 10.0.0.1) {
        return 301 https://blocked.example.com/;
    }
    root /var/www/app;
}
";
    assert!(matches!(
        migrate_str(nginx_bad_if, SourceFormat::Nginx),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    let nginx_hostname_listen = r"
server {
    listen internal.corp:443 ssl;
    server_name corp.example.com;
    root /var/www/corp;
}
";
    assert!(matches!(
        migrate_str(nginx_hostname_listen, SourceFormat::Nginx),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    let nginx_alt_dotfile = r"
server {
    listen 443 ssl;
    server_name alt.example.com;
    root /var/www/app;
    location ~ /\.|/(vendor|storage)/ {
        deny all;
    }
}
";
    assert!(
        matches!(
            migrate_str(nginx_alt_dotfile, SourceFormat::Nginx),
            Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
        ),
        "R4-MIG-6 & R5-MIG-4: `location ~ /\\.|/(vendor|storage)/` must NOT be classified as dotfile-only and must fail closed when `root` would serve /vendor/ or /storage/"
    );

    let apache_waf = r"
<VirtualHost *:443>
    ServerName waf.example.com
    DocumentRoot /var/www/app
    SecRuleEngine On
    SSLRequire %{SSL_CLIENT_S_DN_CN} eq 'admin'
    RewriteRule ^/maint - [R=503,L]
</VirtualHost>
";
    let Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity {
        downgrades: ap_waf_dg,
        ..
    }) = migrate_str(apache_waf, SourceFormat::Apache)
    else {
        return Err("expected Apache SecRuleEngine/SSLRequire/[R=503] to fail closed".into());
    };
    assert!(
        ap_waf_dg
            .iter()
            .any(|d| d.directive.eq_ignore_ascii_case("SecRuleEngine"))
    );
    assert!(
        ap_waf_dg
            .iter()
            .any(|d| d.directive.eq_ignore_ascii_case("SSLRequire"))
    );
    assert!(ap_waf_dg.iter().any(|d| d.directive == "RewriteRule"));

    let caddy_bare_waf = r"
waf.example.com {
    crowdsec
    coraza_waf
    root * /var/www/app
    file_server
}
";
    assert!(matches!(
        migrate_str(caddy_bare_waf, SourceFormat::Caddy),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    let ols_waf = r"
vhDomain ols-waf.example.com
docRoot /var/www/app
module mod_security {
    modsecurity on
}
lsrecaptcha {
    enabled 1
}
";
    assert!(matches!(
        migrate_str(ols_waf, SourceFormat::OpenLiteSpeed),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    // 6. MIG-6: Prefix-stripping `proxy_pass http://backend/;` and Caddy `handle_path` emit security downgrades!
    let nginx_strip = r"
server {
    listen 443 ssl;
    server_name strip.example.com;
    location /api/ {
        proxy_pass http://127.0.0.1:8080/;
    }
}
";
    let rep_strip = migrate_str(nginx_strip, SourceFormat::Nginx)?;
    assert!(
        rep_strip
            .security_downgrades
            .iter()
            .any(|d| d.directive == "proxy_pass"),
        "MIG-6: prefix-stripping proxy_pass must emit a security downgrade"
    );

    let caddy_strip = r"
strip.example.com {
    handle_path /api/* {
        reverse_proxy 127.0.0.1:8080
    }
}
";
    let rep_caddy_prefix = migrate_str(caddy_strip, SourceFormat::Caddy)?;
    assert!(
        rep_caddy_prefix
            .security_downgrades
            .iter()
            .any(|d| d.directive == "handle_path"),
        "MIG-6: Caddy handle_path prefix stripping must emit a security downgrade"
    );

    // 7. R2-MIG-4 & R5-MIG-1: OpenLiteSpeed `type lsapi` MUST fail closed by default, MUST NOT be
    //    emitted as `fastcgi-pass`, and under `--allow-insecure` MUST tag the site `// INSECURE:`!
    let ols_lsapi = r"
vhDomain lsapi.example.com
docRoot /var/www/app
extprocessor lsphp83 {
    type lsapi
    address uds://tmp/lshttpd/lsphp.sock
}
";
    assert!(matches!(
        migrate_str(ols_lsapi, SourceFormat::OpenLiteSpeed),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));
    let rep_lsapi = miraserve_migrate::migrate_str_with_options(
        ols_lsapi,
        SourceFormat::OpenLiteSpeed,
        miraserve_migrate::MigrateOptions {
            allow_insecure: true,
            ..miraserve_migrate::MigrateOptions::default()
        },
    )?;
    assert!(
        !rep_lsapi.kdl.contains("fastcgi-pass"),
        "R2-MIG-4: LSAPI processor must NEVER be emitted as fastcgi-pass: {}",
        rep_lsapi.kdl
    );
    assert!(
        rep_lsapi
            .security_downgrades
            .iter()
            .any(|d| d.directive == "extprocessor.lsapi"),
        "R2-MIG-4: LSAPI processor must emit extprocessor.lsapi security downgrade"
    );
    assert_eq!(
        rep_lsapi.insecure_sites_emitted,
        vec!["lsapi.example.com".to_owned()]
    );
    assert!(
        rep_lsapi
            .kdl
            .contains("// INSECURE: emitted despite extprocessor.lsapi")
    );

    Ok(())
}

/// Round-5 Importer comprehensive regression suite covering `R5-MIG-1` through `R5-MIG-8`,
/// `R4-MIG-5`, `MIG-6`, and `R2-MIG-4`.
#[test]
#[allow(clippy::too_many_lines)]
fn importers_round5_all_findings_regressions() -> TestResult {
    // --- R5-MIG-1: PHP sites without a *.php FastCGI route MUST fail closed ---
    let apache_mod_php = r"
<VirtualHost *:80>
    ServerName shop.example.com
    DocumentRoot /var/www/shop
    DirectoryIndex index.php
</VirtualHost>
";
    assert!(matches!(
        migrate_str(apache_mod_php, SourceFormat::Apache),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    let apache_proxy_pass_match = r"
<VirtualHost *:443>
    ServerName fpm.example.com
    DocumentRoot /var/www/fpm
    ProxyPassMatch ^/(.*\.php(/.*)?)$ fcgi://127.0.0.1:9000/var/www/fpm/$1
</VirtualHost>
";
    assert!(matches!(
        migrate_str(apache_proxy_pass_match, SourceFormat::Apache),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    // Nginx `location ~ \.(php|phtml)$ { fastcgi_pass ...; }` now translates `*.php` + note!
    let nginx_php_phtml = r"
server {
    listen 443 ssl;
    server_name php.example.com;
    root /var/www/php;
    location ~ \.(php|phtml)$ {
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    }
}
";
    let rep_phtml = migrate_str(nginx_php_phtml, SourceFormat::Nginx)?;
    assert!(rep_phtml.security_downgrades.is_empty());
    let (cfg_phtml, _) = parse_kdl("php-phtml.kdl", &rep_phtml.kdl)?;
    assert!(
        cfg_phtml
            .sites
            .first()
            .is_some_and(|s| s.routes.iter().any(|r| r.pattern == "*.php"))
    );

    // OLS server-level `scriptHandler` mapping php without any fcgi processor fails closed!
    let ols_scripthandler = r"
scriptHandler {
    add lsapi:lsphp php
}
virtualHost app.example.com {
    docRoot /var/www/app
}
";
    assert!(matches!(
        migrate_str(ols_scripthandler, SourceFormat::OpenLiteSpeed),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    // --- R5-MIG-2: Laravel `try_files ... /index.php` + `^/uploads/.*\.php$` MUST NOT map to wordpress-hardened ---
    let nginx_laravel_uploads = r"
server {
    listen 443 ssl;
    server_name laravel.example.com;
    root /var/www/laravel/public;
    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }
    location ~* ^/uploads/.*\.php$ {
        deny all;
    }
    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    }
}
";
    assert!(
        matches!(
            migrate_str(nginx_laravel_uploads, SourceFormat::Nginx),
            Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
        ),
        "R5-MIG-2: Laravel /uploads/.*.php deny must NOT be replaced by wordpress-hardened"
    );
    let laravel_insecure = miraserve_migrate::migrate_str_with_options(
        nginx_laravel_uploads,
        SourceFormat::Nginx,
        miraserve_migrate::MigrateOptions {
            allow_insecure: true,
            ..miraserve_migrate::MigrateOptions::default()
        },
    )?;
    assert!(
        !laravel_insecure.kdl.contains("wordpress-hardened"),
        "Laravel try_files must NOT turn on wordpress-hardened: {}",
        laravel_insecure.kdl
    );

    // --- R5-MIG-3: Untranslated security headers (CSP) MUST fail closed across Nginx, Caddy, Apache ---
    let nginx_csp = r#"
server {
    listen 443 ssl;
    server_name csp.example.com;
    root /var/www/app;
    add_header Content-Security-Policy "default-src 'self'" always;
}
"#;
    assert!(matches!(
        migrate_str(nginx_csp, SourceFormat::Nginx),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    let caddy_csp_inline = r#"
csp.example.com {
    root * /var/www/app
    header Content-Security-Policy "default-src 'self'"
    file_server
}
"#;
    assert!(matches!(
        migrate_str(caddy_csp_inline, SourceFormat::Caddy),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    let caddy_csp_block = r#"
csp.example.com {
    root * /var/www/app
    header {
        Content-Security-Policy "default-src 'self'"
    }
    file_server
}
"#;
    assert!(matches!(
        migrate_str(caddy_csp_block, SourceFormat::Caddy),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    let apache_csp = r#"
<VirtualHost *:443>
    ServerName csp.example.com
    DocumentRoot /var/www/app
    Header always set Content-Security-Policy "default-src 'self'"
</VirtualHost>
"#;
    assert!(matches!(
        migrate_str(apache_csp, SourceFormat::Apache),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    // --- R5-MIG-4: Location-scoped blockers overlapping catch-all routes / static root / separate ProxyPass ---
    let nginx_admin_overlap = r"
server {
    listen 443 ssl;
    server_name overlap.example.com;
    root /var/www/site;
    location /admin/ {
        allow 10.0.0.0/8;
        deny all;
    }
    location / {
        try_files $uri $uri/ /index.html;
    }
}
";
    assert!(matches!(
        migrate_str(nginx_admin_overlap, SourceFormat::Nginx),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));
    let nginx_admin_ins = miraserve_migrate::migrate_str_with_options(
        nginx_admin_overlap,
        SourceFormat::Nginx,
        miraserve_migrate::MigrateOptions {
            allow_insecure: true,
            ..miraserve_migrate::MigrateOptions::default()
        },
    )?;
    assert_eq!(
        nginx_admin_ins.insecure_sites_emitted,
        vec!["overlap.example.com".to_owned()]
    );
    assert!(
        nginx_admin_ins
            .kdl
            .contains("INSECURE OUTPUT (--allow-insecure)")
    );
    assert!(
        nginx_admin_ins
            .kdl
            .contains("// INSECURE: emitted despite ")
    );

    let apache_separate_loc = r"
<VirtualHost *:443>
    ServerName split.example.com
    ProxyPass /admin http://127.0.0.1:9000/admin
    <Location /admin>
        Require valid-user
    </Location>
</VirtualHost>
";
    assert!(
        matches!(
            migrate_str(apache_separate_loc, SourceFormat::Apache),
            Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
        ),
        "R5-MIG-4: Apache separate <Location /admin> must block ProxyPass /admin"
    );

    let caddy_route_notlocal = r"
admin.example.com {
    route /admin/* {
        @notlocal not remote_ip 127.0.0.1
        respond @notlocal 403
        reverse_proxy 127.0.0.1:9000
    }
}
";
    assert!(
        matches!(
            migrate_str(caddy_route_notlocal, SourceFormat::Caddy),
            Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
        ),
        "R5-MIG-4: Caddy respond @notlocal 403 inside route /admin/* must withhold reverse_proxy"
    );

    // --- R5-MIG-5: Apache `Include ports.conf` unread vs read from disk, and `<VirtualHost internal.corp:80>` ---
    let apache_unread_ports = r"
Include ports.conf
<VirtualHost *:8080>
    ServerName local.example.com
    DocumentRoot /var/www/local
</VirtualHost>
";
    assert!(
        matches!(
            migrate_str(apache_unread_ports, SourceFormat::Apache),
            Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
        ),
        "R5-MIG-5: unread `Include ports.conf` with wildcard `<VirtualHost *:8080>` must fail closed"
    );

    let tmp_ports = std::env::temp_dir().join(format!(
        "miraserve-r5-ports-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&tmp_ports)?;
    std::fs::write(tmp_ports.join("ports.conf"), "Listen 127.0.0.1:8080\n")?;
    std::fs::write(tmp_ports.join("apache2.conf"), apache_unread_ports)?;
    let rep_ports =
        miraserve_migrate::migrate_file(tmp_ports.join("apache2.conf"), SourceFormat::Apache)?;
    assert!(rep_ports.security_downgrades.is_empty());
    let (cfg_ports, _) = parse_kdl("ports-read.kdl", &rep_ports.kdl)?;
    assert_eq!(
        cfg_ports
            .server
            .listeners
            .iter()
            .map(|l| l.addr.to_string())
            .collect::<Vec<_>>(),
        vec!["127.0.0.1:8080".to_owned()],
        "R5-MIG-5: reading sibling ports.conf must keep 127.0.0.1:8080 loopback-only"
    );
    let _ = std::fs::remove_dir_all(&tmp_ports);

    let apache_host_bind = r"
<VirtualHost internal.corp:80>
    ServerName corp.example.com
    DocumentRoot /var/www/corp
</VirtualHost>
";
    assert!(
        matches!(
            migrate_str(apache_host_bind, SourceFormat::Apache),
            Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
        ),
        "R5-MIG-5: `<VirtualHost internal.corp:80>` must fail closed instead of dropping bind"
    );

    // --- R5-MIG-6 & R4-MIG-5: Parsing gaps & case-sensitive include allow-list ---
    let nginx_hash_in_url = r"
server {
    listen 443 ssl;
    server_name hash.example.com;
    root /var/www/site;
    location /admin/ {
        error_page 403 https://a.example.com/#denied; deny all;
    }
}
";
    assert!(
        matches!(
            migrate_str(nginx_hash_in_url, SourceFormat::Nginx),
            Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
        ),
        "R5-MIG-6: `#` inside unquoted URL must NOT swallow `deny all;`"
    );

    let apache_continuation_and_cond = r"
<VirtualHost *:443>
    ServerName rw.example.com
    DocumentRoot /var/www/rw
    RewriteRule ^/admin - \
        [F]
</VirtualHost>
";
    assert!(matches!(
        migrate_str(apache_continuation_and_cond, SourceFormat::Apache),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    let apache_remote_addr_redirect = r"
<VirtualHost *:443>
    ServerName acl.example.com
    DocumentRoot /var/www/acl
    RewriteCond %{REMOTE_ADDR} !^10\.0\.0\.1$
    RewriteRule ^ https://denied.example.com/ [R=302,L]
</VirtualHost>
";
    assert!(matches!(
        migrate_str(apache_remote_addr_redirect, SourceFormat::Apache),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    let apache_r405 = r"
<VirtualHost *:443>
    ServerName m405.example.com
    DocumentRoot /var/www/app
    RewriteRule ^/old - [L,R=405]
</VirtualHost>
";
    assert!(matches!(
        migrate_str(apache_r405, SourceFormat::Apache),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    for flag in ["[L,R=403]", "[R=404,L]", "[nc,f]"] {
        let ols_rw = format!(
            "vhDomain rw.example.com\ndocRoot /var/www/app\nrewrite {{\n  rules RewriteRule ^/secret - {flag}\n}}\n"
        );
        assert!(
            matches!(
                migrate_str(&ols_rw, SourceFormat::OpenLiteSpeed),
                Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
            ),
            "R5-MIG-6: OLS rewrite flag {flag} must fail closed"
        );
    }

    let nginx_php_admin = r#"
server {
    listen 443 ssl;
    server_name ini.example.com;
    root /var/www/app;
    location ~ \.php$ {
        fastcgi_param PHP_ADMIN_VALUE "open_basedir=/var/www/app";
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    }
}
"#;
    assert!(matches!(
        migrate_str(nginx_php_admin, SourceFormat::Nginx),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    let ols_php_ini = r"
vhDomain ini.example.com
docRoot /var/www/app
phpIniOverride {
    php_admin_value open_basedir /var/www/app
}
";
    assert!(matches!(
        migrate_str(ols_php_ini, SourceFormat::OpenLiteSpeed),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    // R4-MIG-5: Case-sensitive include allow-list rejects `/etc/nginx/Proxy_Params`!
    let nginx_case_inc = r"
server {
    listen 443 ssl;
    server_name case.example.com;
    location /admin {
        include /etc/nginx/Proxy_Params;
        proxy_pass http://127.0.0.1:9000;
    }
}
";
    assert!(matches!(
        migrate_str(nginx_case_inc, SourceFormat::Nginx),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    // --- R5-MIG-7 & MIG-6: Stock/common configs & path-rewriting ---
    // 1. Certbot Nginx Node proxy (`location / { proxy_pass http://127.0.0.1:3000/; }`) -> 0 downgrades!
    let nginx_node = r"
server {
    listen 443 ssl;
    server_name node.example.com;
    location / {
        proxy_pass http://127.0.0.1:3000/;
    }
}
";
    let rep_node = migrate_str(nginx_node, SourceFormat::Nginx)?;
    assert!(
        rep_node.security_downgrades.is_empty(),
        "R5-MIG-7: `location / {{ proxy_pass http://127.0.0.1:3000/; }}` must NOT falsely downgrade: {:?}",
        rep_node.security_downgrades
    );

    // 2. Debian Nginx default with PHP + `/\.ht` uncommented -> 0 downgrades!
    let nginx_deb_php_ht = r"
server {
    listen 80 default_server;
    root /var/www/html;
    index index.php index.html;
    server_name _;
    location / {
        try_files $uri $uri/ =404;
    }
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
    }
    location ~ /\.ht {
        deny all;
    }
}
";
    let rep_deb_php_ht = migrate_str(nginx_deb_php_ht, SourceFormat::Nginx)?;
    assert!(
        rep_deb_php_ht.security_downgrades.is_empty(),
        "R5-MIG-7: Debian nginx default with PHP + /.ht must import cleanly: {:?}",
        rep_deb_php_ht.security_downgrades
    );

    // 3. Certbot Apache `000-default` + `-le-ssl` merges into ONE site with cert/key (NO site-2.local!)
    let apache_certbot_pair = r"
<VirtualHost *:80>
    ServerName blog.example.com
    DocumentRoot /var/www/blog
</VirtualHost>
<VirtualHost *:443>
    ServerName blog.example.com
    DocumentRoot /var/www/blog
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/blog.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/blog.example.com/privkey.pem
</VirtualHost>
";
    let rep_pair = migrate_str(apache_certbot_pair, SourceFormat::Apache)?;
    assert!(rep_pair.security_downgrades.is_empty());
    assert_eq!(rep_pair.migrated_sites, 1);
    assert!(!rep_pair.kdl.contains("site-2.local"));
    let (cfg_pair, _) = parse_kdl("certbot-pair.kdl", &rep_pair.kdl)?;
    assert_eq!(
        cfg_pair
            .sites
            .first()
            .and_then(|s| s.tls.as_ref())
            .and_then(|t| t.cert.as_deref()),
        Some("/etc/letsencrypt/live/blog.example.com/fullchain.pem")
    );

    // 4. Plain-HTTP Nginx `listen 8080;` (no `ssl`) -> redirect-https on `:8080`, TLS on `:443`!
    let nginx_plain_8080 = r"
server {
    listen 8080;
    server_name plain.example.com;
    root /var/www/plain;
}
";
    let rep_8080 = migrate_str(nginx_plain_8080, SourceFormat::Nginx)?;
    let (cfg_8080, _) = parse_kdl("plain-8080.kdl", &rep_8080.kdl)?;
    assert!(
        cfg_8080
            .server
            .listeners
            .iter()
            .any(|l| l.addr.to_string() == ":8080" && l.redirect_https),
        "R5-MIG-7: plain-HTTP `listen 8080;` must NOT terminate TLS on :8080: {:?}",
        cfg_8080.server.listeners
    );
    assert!(
        cfg_8080
            .server
            .listeners
            .iter()
            .any(|l| l.addr.to_string() == ":443" && !l.redirect_https)
    );

    // 5. Caddy `reverse_proxy { transport http { ... } }` -> 0 downgrades!
    let caddy_transport = r"
app.example.com {
    reverse_proxy 127.0.0.1:3000 {
        transport http {
            versions 1.1
        }
    }
}
";
    let rep_ct = migrate_str(caddy_transport, SourceFormat::Caddy)?;
    assert!(
        rep_ct.security_downgrades.is_empty(),
        "R5-MIG-7: Caddy reverse_proxy transport http block must import cleanly: {:?}",
        rep_ct.security_downgrades
    );

    // 6. MIG-6: Apache `ProxyPass /api/ http://b:8080/api/v1/public/` & Caddy `uri strip_prefix` downgrade!
    let apache_pp_rewrite = r"
<VirtualHost *:443>
    ServerName api.example.com
    ProxyPass /api/ http://127.0.0.1:8080/api/v1/public/
</VirtualHost>
";
    let rep_pp = migrate_str(apache_pp_rewrite, SourceFormat::Apache)?;
    assert!(
        rep_pp
            .security_downgrades
            .iter()
            .any(|d| d.directive == "ProxyPass"),
        "MIG-6: Apache ProxyPass path rewrite must emit security downgrade"
    );
    assert!(
        !rep_pp.kdl.contains("/api/v1/public"),
        "upstream URL must have path suffix stripped: {}",
        rep_pp.kdl
    );

    let caddy_uri_strip = r"
api.example.com {
    handle /api/* {
        uri strip_prefix /api
        reverse_proxy 127.0.0.1:8080
    }
}
";
    let rep_uri = migrate_str(caddy_uri_strip, SourceFormat::Caddy)?;
    assert!(
        rep_uri
            .security_downgrades
            .iter()
            .any(|d| d.directive == "uri"),
        "MIG-6: Caddy `uri strip_prefix` must emit security downgrade"
    );

    // 7. Special hosts (`.example.com`, regex, IDN, Caddy `{$DOMAIN}`, Caddy snippets) -> valid KDL!
    let nginx_special_hosts = r"
server {
    listen 443 ssl;
    server_name .example.com ~^www\.(.+)$ münchen.de;
    root /var/www/site;
}
";
    let rep_hosts = migrate_str(nginx_special_hosts, SourceFormat::Nginx)?;
    let (cfg_hosts, _) = parse_kdl("special-hosts.kdl", &rep_hosts.kdl)?;
    let hosts = &cfg_hosts.sites.first().ok_or("missing site")?.hosts;
    assert!(hosts.contains(&"example.com".to_owned()));
    assert!(hosts.contains(&"*.example.com".to_owned()));

    let caddy_snippet_env = r"
(logging) {
    log {
        output file /var/log/caddy.log
    }
}
{$DOMAIN} {
    root * /var/www/site
    file_server
}
";
    let rep_snippet = migrate_str(caddy_snippet_env, SourceFormat::Caddy)?;
    assert!(rep_snippet.security_downgrades.is_empty());
    let _ = parse_kdl("caddy-snippet.kdl", &rep_snippet.kdl)?;

    // --- R5-MIG-8: return 423, OLS statusCode 403, depth > 32, quoted DocumentRoot, ${VAR}, BOM, 20k binds ---
    let nginx_423 = r"
server {
    listen 443 ssl;
    server_name lock.example.com;
    root /var/www/lock;
    return 423;
}
";
    assert!(matches!(
        migrate_str(nginx_423, SourceFormat::Nginx),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    let ols_status_403 = r"
vhDomain block.example.com
docRoot /var/www/site
context /secret {
    type redirect
    statusCode 403
}
";
    assert!(matches!(
        migrate_str(ols_status_403, SourceFormat::OpenLiteSpeed),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    // Nginx nesting > MAX_BLOCK_DEPTH (32) fails closed instead of silently dropping inner blocks!
    let mut deep_nginx = String::from(
        "server {\n  listen 443 ssl;\n  server_name d.example.com;\n  root /var/www/d;\n",
    );
    for _ in 0..36 {
        deep_nginx.push_str("  if ($x) {\n");
    }
    deep_nginx.push_str("    deny all;\n");
    for _ in 0..36 {
        deep_nginx.push_str("  }\n");
    }
    deep_nginx.push_str("}\n");
    assert!(
        matches!(
            migrate_str(&deep_nginx, SourceFormat::Nginx),
            Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
        ),
        "R5-MIG-8: Nginx nesting deeper than 32 must fail closed"
    );

    // Apache quoted DocumentRoot with spaces preserved!
    let apache_spaces = r#"
<VirtualHost *:443>
    ServerName spaces.example.com
    DocumentRoot "/var/www/my site"
</VirtualHost>
"#;
    let rep_spaces = migrate_str(apache_spaces, SourceFormat::Apache)?;
    let (cfg_spaces, _) = parse_kdl("apache-spaces.kdl", &rep_spaces.kdl)?;
    assert_eq!(
        cfg_spaces.sites.first().and_then(|s| s.root.as_deref()),
        Some("/var/www/my site")
    );

    // Apache unexpanded `${VAR}` in DocumentRoot fails closed (never emitted literally)!
    let apache_env_root = r#"
<VirtualHost *:443>
    ServerName env.example.com
    DocumentRoot "/var/www/${SITE_NAME}"
</VirtualHost>
"#;
    assert!(matches!(
        migrate_str(apache_env_root, SourceFormat::Apache),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    // UTF-8 BOM prefix on Nginx config parses cleanly!
    let bom_nginx = "\u{FEFF}server {\n    listen 443 ssl;\n    server_name bom.example.com;\n    root /var/www/bom;\n}\n";
    let rep_bom = migrate_str(bom_nginx, SourceFormat::Auto)?;
    assert_eq!(rep_bom.source_format, SourceFormat::Nginx);
    assert_eq!(rep_bom.migrated_sites, 1);

    // O(1) bind dedup: 20,000 duplicate `listen` directives must complete well under 2 seconds!
    let mut big_nginx =
        String::from("server {\n  server_name perf.example.com;\n  root /var/www/perf;\n");
    for i in 0..20_000_u32 {
        let port = 10_000 + (i % 500);
        let _ = writeln!(big_nginx, "  listen 127.0.0.1:{port} ssl;");
    }
    big_nginx.push_str("}\n");
    let t0 = std::time::Instant::now();
    let rep_perf = migrate_str(&big_nginx, SourceFormat::Nginx)?;
    let elapsed = t0.elapsed();
    assert_eq!(rep_perf.migrated_sites, 1);
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "R5-MIG-8: 20k binds must complete in O(N) (<2s), took {elapsed:?}"
    );

    Ok(())
}

/// Helper verifying Round-6 Process Request invariant on every emitted `MigrationReport`:
/// re-parses `report.kdl` via `miraserve_config::parse_kdl` and confirms site count and total
/// route count match the report summary 1-to-1.
fn verify_parsed_report(
    name: &str,
    report: &miraserve_migrate::MigrationReport,
) -> Result<miraserve_config::Config, Box<dyn std::error::Error>> {
    let (cfg, _) = parse_kdl(name, &report.kdl)?;
    assert_eq!(
        cfg.sites.len(),
        report.migrated_sites,
        "{name}: parsed site count must match report.migrated_sites"
    );
    let total_routes: usize = cfg.sites.iter().map(|s| s.routes.len()).sum();
    assert_eq!(
        total_routes, report.migrated_routes,
        "{name}: parsed route count must match report.migrated_routes"
    );
    Ok(cfg)
}

/// R6-MIG-1: `--allow-insecure` must never allow quoted newlines or Unicode U+2028 line
/// separators in an untrusted source config to break out of a `// INSECURE:` comment and inject
/// new KDL nodes (e.g. a rogue `site "evil.example.com"` proxying to `169.254.169.254`).
#[test]
fn r6_mig_1_allow_insecure_blocks_kdl_comment_injection_and_u2028() -> TestResult {
    let inj_newline = r#"
server {
    listen 80; server_name victim.example.com; root /var/www/victim;
    include "/opt/x.conf
site \"evil.example.com\" {
    route \"/*\" { reverse-proxy { upstream \"http://169.254.169.254\"; }; }
}
//";
}
"#;
    let inj_u2028 = "server {\n    listen 80; server_name victim2.example.com; root /var/www/victim2;\n    include \"/opt/x.conf\u{2028}site \\\"evil.example.com\\\" { route \\\"/*\\\" { reverse-proxy { upstream \\\"http://169.254.169.254\\\"; }; } }\";\n}\n";

    for (label, raw, expected_host) in [
        ("newline", inj_newline, "victim.example.com"),
        ("u2028", inj_u2028, "victim2.example.com"),
    ] {
        let rep = miraserve_migrate::migrate_str_with_options(
            raw,
            SourceFormat::Nginx,
            miraserve_migrate::MigrateOptions {
                allow_insecure: true,
                ..miraserve_migrate::MigrateOptions::default()
            },
        )?;
        let cfg = verify_parsed_report(label, &rep)?;
        assert_eq!(cfg.sites.len(), 1, "{label}: injected site must not exist");
        let site = cfg.sites.first().ok_or("missing site")?;
        assert_eq!(site.hosts, vec![expected_host]);
        assert!(
            !rep.kdl.contains("evil.example.com") && !rep.kdl.contains("169.254.169.254"),
            "{label}: injected payload must never appear in KDL output:\n{}",
            rep.kdl
        );
    }
    Ok(())
}

/// R6-MIG-2: A PHP allow-list regex (`location ~ ^/(index|wp-login|wp-cron)\.php$`) must emit
/// exact-path routes rather than widening to `*.php`, and Apache `SetHandler proxy:fcgi` must
/// respect its enclosing `<FilesMatch>`/`<Location>` and fail closed on untranslatable or bare
/// scopes.
#[test]
fn r6_mig_2_php_allowlist_not_widened_to_all_php_nginx_and_apache() -> TestResult {
    let nginx_allowlist = r"
server {
    listen 443 ssl;
    server_name wp.example.com;
    root /var/www/site;
    location ~ ^/(index|wp-login|wp-cron)\.php$ {
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    }
    location / {
        try_files $uri $uri/ =404;
    }
}
";
    let rep = migrate_str(nginx_allowlist, SourceFormat::Nginx)?;
    assert!(
        rep.security_downgrades.is_empty(),
        "exact allow-list regex should translate cleanly: {:?}",
        rep.security_downgrades
    );
    let cfg = verify_parsed_report("r6-mig-2-nginx.kdl", &rep)?;
    let site = cfg.sites.first().ok_or("missing site")?;
    assert!(
        !site.routes.iter().any(|r| r.pattern == "*.php"),
        "allow-list must NEVER be widened to `*.php`: {:?}",
        site.routes
    );
    for allowed in ["/index.php", "/wp-login.php", "/wp-cron.php"] {
        let matched = site.match_route(allowed).ok_or("missing route")?;
        assert!(
            matches!(matched.handler, RouteHandler::FastCgi(_)),
            "{allowed} must reach FastCGI, got {matched:?}"
        );
    }
    let blocked_upload = site
        .match_route("/wp-content/uploads/shell.php")
        .ok_or("missing fallback route")?;
    assert!(
        !matches!(blocked_upload.handler, RouteHandler::FastCgi(_)),
        "/wp-content/uploads/shell.php must NOT reach FastCGI, got {blocked_upload:?}"
    );

    // Complex untranslatable Nginx PHP regex fails closed.
    let nginx_complex = r"
server {
    listen 443 ssl;
    server_name complex.example.com;
    root /var/www/site;
    location ~ ^/app/.*\.php$ {
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    }
}
";
    assert!(matches!(
        migrate_str(nginx_complex, SourceFormat::Nginx),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    // Apache bare `SetHandler proxy:fcgi` outside `<FilesMatch>`/`<Location>` fails closed.
    let apache_bare = r#"
<VirtualHost *:443>
    ServerName bare.example.com
    DocumentRoot /var/www/site
    SetHandler "proxy:unix:/run/php/php8.3-fpm.sock|fcgi://localhost"
</VirtualHost>
"#;
    assert!(matches!(
        migrate_str(apache_bare, SourceFormat::Apache),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    // Apache `<Location /admin.php>` emits exact `/admin.php`, never `*.php`.
    let apache_exact_loc = r#"
<VirtualHost *:443>
    ServerName exact.example.com
    DocumentRoot /var/www/site
    <Location /admin.php>
        SetHandler "proxy:unix:/run/php/php8.3-fpm.sock|fcgi://localhost"
    </Location>
</VirtualHost>
"#;
    let rep_ap = migrate_str(apache_exact_loc, SourceFormat::Apache)?;
    let cfg_ap = verify_parsed_report("r6-mig-2-apache.kdl", &rep_ap)?;
    let ap_site = cfg_ap.sites.first().ok_or("missing apache site")?;
    assert!(matches!(
        ap_site.match_route("/admin.php").map(|r| &r.handler),
        Some(RouteHandler::FastCgi(_))
    ));
    assert!(
        ap_site.match_route("/other.php").is_none(),
        "/other.php must not be matched by exact /admin.php FastCGI route"
    );
    Ok(())
}

/// R6-MIG-3: Multi-extension PHP execution rules across Nginx, Apache, and Caddy `split` must
/// emit one FastCGI route per executed extension rather than silently dropping secondary
/// extensions such as `.php5`, `.php7`, `.phtml`, or `.inc`.
#[test]
fn r6_mig_3_multi_extension_php_emits_all_extensions_nginx_apache_caddy() -> TestResult {
    let nginx_multi = r"
server {
    listen 443 ssl;
    server_name multi-nginx.example.com;
    root /var/www/site;
    location ~ \.(php|phtml|php5)$ {
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    }
}
";
    let rep_n = migrate_str(nginx_multi, SourceFormat::Nginx)?;
    let cfg_n = verify_parsed_report("r6-mig-3-nginx.kdl", &rep_n)?;
    let site_n = cfg_n.sites.first().ok_or("missing nginx site")?;
    for path in ["/a.php", "/a.phtml", "/a.php5"] {
        assert!(
            matches!(
                site_n.match_route(path).map(|r| &r.handler),
                Some(RouteHandler::FastCgi(_))
            ),
            "Nginx multi-ext: {path} must reach FastCGI"
        );
    }

    let apache_multi = r#"
<VirtualHost *:443>
    ServerName multi-apache.example.com
    DocumentRoot /var/www/site
    <FilesMatch "\.(php|php5|php7|inc)$">
        SetHandler "proxy:unix:/run/php/php8.3-fpm.sock|fcgi://localhost"
    </FilesMatch>
</VirtualHost>
"#;
    let rep_a = migrate_str(apache_multi, SourceFormat::Apache)?;
    let cfg_a = verify_parsed_report("r6-mig-3-apache.kdl", &rep_a)?;
    let site_a = cfg_a.sites.first().ok_or("missing apache site")?;
    for path in ["/a.php", "/a.php5", "/a.php7", "/a.inc"] {
        assert!(
            matches!(
                site_a.match_route(path).map(|r| &r.handler),
                Some(RouteHandler::FastCgi(_))
            ),
            "Apache multi-ext: {path} must reach FastCGI"
        );
    }

    let caddy_split = r"
multi-caddy.example.com {
    root * /var/www/site
    php_fastcgi unix//run/php/php8.3-fpm.sock {
        split .php .php5
    }
    file_server
}
";
    let rep_c = migrate_str(caddy_split, SourceFormat::Caddy)?;
    let cfg_c = verify_parsed_report("r6-mig-3-caddy.kdl", &rep_c)?;
    let site_c = cfg_c.sites.first().ok_or("missing caddy site")?;
    for path in ["/a.php", "/a.php5"] {
        assert!(
            matches!(
                site_c.match_route(path).map(|r| &r.handler),
                Some(RouteHandler::FastCgi(_))
            ),
            "Caddy split: {path} must reach FastCGI"
        );
    }
    Ok(())
}

/// R6-MIG-4: Nested Nginx `location` blocks (such as `location /app/ { location ~ \.php$ { fastcgi_pass ...; } }`)
/// must fail closed rather than collapsing the inner `fastcgi_pass` onto the outer `/app/*` prefix.
#[test]
fn r6_mig_4_nested_nginx_php_location_never_turns_prefix_into_fastcgi() -> TestResult {
    let nested = r"
server {
    listen 443 ssl;
    server_name nested.example.com;
    root /var/www/site;
    location /app/ {
        location ~ \.php$ {
            fastcgi_pass unix:/run/php/php8.3-fpm.sock;
        }
    }
}
";
    let Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { downgrades, .. }) =
        migrate_str(nested, SourceFormat::Nginx)
    else {
        return Err("nested Nginx PHP location must fail closed".into());
    };
    assert!(
        downgrades
            .iter()
            .any(|d| d.directive == "nested location" && d.message.contains("/app/")),
        "expected nested location downgrade, got: {downgrades:?}"
    );
    Ok(())
}

/// R6-MIG-5: Untranslated response headers must be refused by default across OpenLiteSpeed
/// (`extraHeaders` heredoc & single-line), Nginx (`add_header` & `proxy_cookie_flags`), Apache
/// (`Header edit Set-Cookie`, `Header set Referrer-Policy`), and Caddy (`header`).
#[test]
fn r6_mig_5_untranslated_response_headers_default_refused_across_all_importers() -> TestResult {
    let ols_csp = r"
vhDomain ols-hdr.example.com
docRoot /var/www/ols
context / {
  extraHeaders <<<END_extraHeaders
  Content-Security-Policy: default-src 'self'
  END_extraHeaders
}
";
    assert!(matches!(
        migrate_str(ols_csp, SourceFormat::OpenLiteSpeed),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    for (label, nginx_snippet) in [
        (
            "Referrer-Policy no-referrer",
            r#"add_header Referrer-Policy "no-referrer" always;"#,
        ),
        ("X-Robots-Tag", r#"add_header X-Robots-Tag "noindex";"#),
        (
            "Cache-Control no-store",
            r#"add_header Cache-Control "no-store"; "#,
        ),
        (
            "proxy_cookie_flags",
            r"proxy_cookie_flags ~ secure httponly samesite=strict;",
        ),
    ] {
        let cfg_txt = format!(
            "server {{\n listen 443 ssl;\n server_name h.example.com;\n location / {{\n  {nginx_snippet}\n  proxy_pass http://127.0.0.1:8080;\n }}\n}}\n"
        );
        assert!(
            matches!(
                migrate_str(&cfg_txt, SourceFormat::Nginx),
                Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
            ),
            "Nginx {label} must fail closed"
        );
    }

    let apache_cookie_edit = r"
<VirtualHost *:443>
    ServerName cookie.example.com
    DocumentRoot /var/www/site
    Header always edit Set-Cookie ^(.*)$ $1;HttpOnly;Secure
</VirtualHost>
";
    assert!(matches!(
        migrate_str(apache_cookie_edit, SourceFormat::Apache),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    let caddy_referrer = r#"
hdr.example.com {
    root * /var/www/site
    header Referrer-Policy "no-referrer"
    file_server
}
"#;
    assert!(matches!(
        migrate_str(caddy_referrer, SourceFormat::Caddy),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    // Safe headers covered at equal-or-stronger strength by `security-headers "strict"` pass cleanly.
    let safe_nginx = r#"
server {
    listen 443 ssl;
    server_name safe-hdr.example.com;
    root /var/www/site;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
}
"#;
    let rep_safe = migrate_str(safe_nginx, SourceFormat::Nginx)?;
    assert!(rep_safe.security_downgrades.is_empty());
    verify_parsed_report("r6-mig-5-safe.kdl", &rep_safe)?;
    Ok(())
}

/// R6-MIG-6: Importing a Unix FIFO directly or via `include conf.d/*.conf;` must fail immediately
/// instead of blocking forever in `File::open`.
#[cfg(unix)]
#[test]
fn r6_mig_6_fifo_rejected_without_hanging_on_direct_import_and_include() -> TestResult {
    let dir = std::env::temp_dir().join(format!("miraserve-r6-mig-6-fifo-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let conf_d = dir.join("conf.d");
    fs::create_dir_all(&conf_d)?;

    let direct_fifo = dir.join("direct.conf");
    let inc_fifo = conf_d.join("00-trap.conf");
    for fifo in [&direct_fifo, &inc_fifo] {
        let status = std::process::Command::new("mkfifo").arg(fifo).status()?;
        assert!(status.success(), "mkfifo failed for {}", fifo.display());
    }

    let t0 = std::time::Instant::now();
    let direct_res = miraserve_migrate::migrate_file(&direct_fifo, SourceFormat::Nginx);
    assert!(
        t0.elapsed() < std::time::Duration::from_secs(2),
        "direct FIFO import must not hang"
    );
    assert!(
        matches!(direct_res, Err(miraserve_migrate::MigrateError::Io { .. })),
        "direct FIFO import must fail with Io error, got {direct_res:?}"
    );

    let main_conf = dir.join("nginx.conf");
    fs::write(
        &main_conf,
        "http {\n    include conf.d/*.conf;\n    server {\n        listen 443 ssl;\n        server_name ok.example.com;\n        root /var/www/ok;\n    }\n}\n",
    )?;
    let t1 = std::time::Instant::now();
    let inc_res = miraserve_migrate::migrate_file(&main_conf, SourceFormat::Nginx);
    assert!(
        t1.elapsed() < std::time::Duration::from_secs(2),
        "included FIFO must not hang"
    );
    assert!(
        matches!(
            inc_res,
            Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
        ),
        "unexpandable FIFO include must fail closed, got {inc_res:?}"
    );

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// R6-MIG-7: Emitted routes must be ordered from most specific to least specific so `*.php`
/// precedes `/*` on the unmodified WordPress.org recipe and `/wp-login.php` + `/wp-admin/index.php`
/// actually dispatch to FastCGI.
#[test]
fn r6_mig_7_route_ordering_keeps_wordpress_php_reachable_before_catchall() -> TestResult {
    let wp_org_raw = include_str!("fixtures/wordpress_org_nginx_single_site.conf");
    let rep = migrate_str(wp_org_raw, SourceFormat::Nginx)?;
    assert!(rep.security_downgrades.is_empty());
    let cfg = verify_parsed_report("r6-mig-7-wp.kdl", &rep)?;
    let site = cfg.sites.first().ok_or("missing wp site")?;

    let php_idx = site
        .routes
        .iter()
        .position(|r| r.pattern == "*.php")
        .ok_or("missing *.php route")?;
    let catchall_idx = site
        .routes
        .iter()
        .position(|r| r.pattern == "/*")
        .ok_or("missing /* route")?;
    assert!(
        php_idx < catchall_idx,
        "*.php (idx {php_idx}) MUST precede /* (idx {catchall_idx}): {:?}",
        site.routes
    );

    for php_url in ["/wp-login.php", "/wp-admin/index.php", "/index.php"] {
        let matched = site.match_route(php_url).ok_or("no matching route")?;
        assert!(
            matches!(matched.handler, RouteHandler::FastCgi(_)),
            "{php_url} MUST dispatch to FastCGI, got {matched:?}"
        );
    }
    let static_match = site.match_route("/about/").ok_or("missing fallback")?;
    assert!(matches!(
        static_match.handler,
        RouteHandler::TryFiles { .. }
    ));
    Ok(())
}

/// R6-MIG-8: Plain-HTTP listeners across Caddy (`:8080`, `http://127.0.0.1:8081`), Nginx
/// (`10.0.0.5:8080`, `[::1]:8080`), and OpenLiteSpeed (`httpd_config.conf` + `vhconf.conf` with
/// `127.0.0.1:8088`, `secure 0`) must preserve scoping, never invent public `:80`/`:443` when
/// inappropriate, and emit explicit notes when plain HTTP becomes TLS.
#[test]
#[allow(clippy::too_many_lines)]
fn r6_mig_8_listeners_preserve_plain_http_scoping_and_emit_notes() -> TestResult {
    // 1. Caddy bare `:8080 {` -> NOT TLS on 8080 and NO invented `:80`!
    let caddy_8080 = ":8080 {\n    root * /var/www/html\n    file_server\n}\n";
    let rep_c8080 = migrate_str(caddy_8080, SourceFormat::Caddy)?;
    let cfg_c8080 = verify_parsed_report("r6-mig-8-caddy8080.kdl", &rep_c8080)?;
    assert!(
        cfg_c8080
            .server
            .listeners
            .iter()
            .any(|l| l.addr.to_string() == ":8080" && l.redirect_https),
        "Caddy :8080 must be redirect-https, not TLS on 8080: {:?}",
        cfg_c8080.server.listeners
    );
    assert!(
        !cfg_c8080
            .server
            .listeners
            .iter()
            .any(|l| l.addr.to_string() == ":80"),
        "Caddy :8080 must NOT invent a public :80 listener: {:?}",
        cfg_c8080.server.listeners
    );
    assert!(
        rep_c8080.notes.iter().any(|n| n.directive == "listen"),
        "Caddy :8080 must emit an explicit listener migration note"
    );

    // 2. Caddy `http://127.0.0.1:8081` -> scoped on 127.0.0.1:8081 (no public :443/:80) + note!
    let caddy_local = "http://127.0.0.1:8081 {\n    root * /var/www/local\n    file_server\n}\n";
    let rep_clocal = migrate_str(caddy_local, SourceFormat::Caddy)?;
    let cfg_clocal = verify_parsed_report("r6-mig-8-caddylocal.kdl", &rep_clocal)?;
    assert_eq!(cfg_clocal.server.listeners.len(), 1);
    assert_eq!(
        cfg_clocal
            .server
            .listeners
            .first()
            .ok_or("missing caddy local listener")?
            .addr
            .to_string(),
        "127.0.0.1:8081"
    );
    assert!(
        rep_clocal
            .notes
            .iter()
            .any(|n| n.message.contains("upgraded to HTTPS")),
        "Caddy http://127.0.0.1:8081 must note plain-HTTP-to-TLS upgrade: {:?}",
        rep_clocal.notes
    );

    // 3. Nginx `listen 10.0.0.5:8080;` & `[::1]:8080;` -> scoped + explicit note!
    let nginx_scoped = "server {\n    listen 10.0.0.5:8080;\n    listen [::1]:8080;\n    server_name int.example.com;\n    root /var/www/int;\n}\n";
    let rep_ns = migrate_str(nginx_scoped, SourceFormat::Nginx)?;
    let cfg_ns = verify_parsed_report("r6-mig-8-nginxscoped.kdl", &rep_ns)?;
    let addrs: Vec<String> = cfg_ns
        .server
        .listeners
        .iter()
        .map(|l| l.addr.to_string())
        .collect();
    assert_eq!(addrs, vec!["10.0.0.5:8080", "[::1]:8080"]);
    assert!(
        rep_ns
            .notes
            .iter()
            .any(|n| n.message.contains("upgraded to HTTPS")),
        "Nginx scoped plain-HTTP listeners must note TLS upgrade: {:?}",
        rep_ns.notes
    );

    // 4. OpenLiteSpeed `httpd_config.conf` + `vhconf.conf` with `127.0.0.1:8088; secure 0`
    //    must stay strictly scoped on `127.0.0.1:8088` (NO public :443 or :80) + emit note!
    let dir = std::env::temp_dir().join(format!("miraserve-r6-mig-8-ols-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("conf/vhosts/InternalApp"))?;
    fs::write(
        dir.join("conf/vhosts/InternalApp/vhconf.conf"),
        "docRoot $VH_ROOT/html/\n",
    )?;
    let ols_httpd = dir.join("conf/httpd_config.conf");
    fs::write(
        &ols_httpd,
        r"
virtualHost InternalApp {
    vhRoot /var/www/internal
    configFile conf/vhosts/InternalApp/vhconf.conf
}
listener LocalOnly {
    address 127.0.0.1:8088
    secure 0
    map InternalApp internal.example.com
}
",
    )?;
    let rep_ols = miraserve_migrate::migrate_file(&ols_httpd, SourceFormat::Auto)?;
    assert_eq!(rep_ols.source_format, SourceFormat::OpenLiteSpeed);
    let cfg_ols = verify_parsed_report("r6-mig-8-ols.kdl", &rep_ols)?;
    assert_eq!(cfg_ols.server.listeners.len(), 1);
    assert_eq!(
        cfg_ols
            .server
            .listeners
            .first()
            .ok_or("missing ols listener")?
            .addr
            .to_string(),
        "127.0.0.1:8088"
    );
    let ols_site = cfg_ols.sites.first().ok_or("missing ols site")?;
    assert_eq!(ols_site.hosts, vec!["internal.example.com"]);
    assert_eq!(ols_site.root.as_deref(), Some("/var/www/internal/html/"));
    assert!(
        rep_ols
            .notes
            .iter()
            .any(|n| n.message.contains("upgraded to HTTPS")),
        "OLS scoped plain-HTTP listener must note TLS upgrade: {:?}",
        rep_ols.notes
    );
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// R6-MIG-9: Realistic stock server trees — Debian Apache with `mods-enabled/status.conf`,
/// `mods-enabled/dir.conf`, and `conf-enabled/php8.2-fpm.conf` (`.phps` + `^\.ph...` denies);
/// RHEL Apache with stock `conf.d/userdir.conf` + `conf.d/welcome.conf`; and Caddy with
/// same-file `import <snippet>` — must import cleanly, while a Caddy snippet containing
/// `basic_auth` must still fail closed.
#[test]
fn r6_mig_9_realistic_stock_trees_status_userdir_debian_php_and_caddy_snippets() -> TestResult {
    let base =
        std::env::temp_dir().join(format!("miraserve-r6-mig-9-trees-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);

    // 1. Realistic Debian 12 Apache tree with `mods-enabled/status.conf`, `mods-enabled/dir.conf`,
    //    and `conf-enabled/php8.2-fpm.conf` (stock `.phps` & dotfile PHP denies).
    let deb = base.join("debian-apache2");
    fs::create_dir_all(deb.join("mods-enabled"))?;
    fs::create_dir_all(deb.join("conf-enabled"))?;
    fs::create_dir_all(deb.join("sites-enabled"))?;
    fs::write(
        deb.join("ports.conf"),
        include_str!("fixtures/debian12_apache_ports.conf"),
    )?;
    fs::write(
        deb.join("mods-enabled/status.conf"),
        "<IfModule mod_status.c>\n    <Location /server-status>\n        SetHandler server-status\n        Require local\n    </Location>\n</IfModule>\n",
    )?;
    fs::write(
        deb.join("mods-enabled/dir.conf"),
        "<IfModule mod_dir.c>\n    DirectoryIndex index.html index.cgi index.pl index.php index.xhtml index.htm\n</IfModule>\n",
    )?;
    fs::write(
        deb.join("conf-enabled/php8.2-fpm.conf"),
        r#"
<IfModule proxy_fcgi_module>
    <FilesMatch ".+\.ph(ar|p|tml)$">
        SetHandler "proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost"
    </FilesMatch>
    <FilesMatch ".+\.phps$">
        Require all denied
    </FilesMatch>
    <FilesMatch "^\.ph(ar|p|ps|tml)$">
        Require all denied
    </FilesMatch>
</IfModule>
"#,
    )?;
    fs::write(
        deb.join("sites-enabled/000-default.conf"),
        include_str!("fixtures/debian12_apache_000-default.conf"),
    )?;
    let deb_main = deb.join("apache2.conf");
    fs::write(&deb_main, include_str!("fixtures/debian12_apache2.conf"))?;
    let rep_deb = miraserve_migrate::migrate_file(&deb_main, SourceFormat::Apache)?;
    assert!(
        rep_deb.security_downgrades.is_empty(),
        "realistic Debian Apache tree with status.conf + dir.conf + php8.2-fpm.conf must import cleanly: {:?}",
        rep_deb.security_downgrades
    );
    let cfg_deb = verify_parsed_report("r6-mig-9-debian.kdl", &rep_deb)?;
    let deb_site = cfg_deb.sites.first().ok_or("missing debian site")?;
    for php_url in ["/index.php", "/app.phtml", "/pkg.phar"] {
        assert!(
            matches!(
                deb_site.match_route(php_url).map(|r| &r.handler),
                Some(RouteHandler::FastCgi(_))
            ),
            "Debian PHP-FPM site: {php_url} must reach FastCGI"
        );
    }

    // 2. Realistic RHEL 9 Apache tree with stock `conf.d/userdir.conf` and `conf.d/welcome.conf`.
    let rhel = base.join("rhel-httpd");
    fs::create_dir_all(rhel.join("conf"))?;
    fs::create_dir_all(rhel.join("conf.d"))?;
    fs::write(
        rhel.join("conf.d/userdir.conf"),
        r#"
<IfModule mod_userdir.c>
    UserDir disabled
</IfModule>
<Directory "/home/*/public_html">
    AllowOverride FileInfo AuthConfig Limit Indexes
    Options MultiViews Indexes SymLinksIfOwnerMatch IncludesNoExec
    Require method GET POST OPTIONS
</Directory>
"#,
    )?;
    fs::write(
        rhel.join("conf.d/welcome.conf"),
        "<LocationMatch \"^/+$\">\n    Options -Indexes\n    ErrorDocument 403 /.noindex.html\n</LocationMatch>\n<Directory /usr/share/httpd/noindex>\n    AllowOverride None\n    Require all granted\n</Directory>\n",
    )?;
    fs::write(
        rhel.join("conf.d/ssl.conf"),
        include_str!("fixtures/rhel9_ssl.conf"),
    )?;
    let rhel_main = rhel.join("conf/httpd.conf");
    fs::write(&rhel_main, include_str!("fixtures/rhel9_httpd.conf"))?;
    let rep_rhel = miraserve_migrate::migrate_file(&rhel_main, SourceFormat::Apache)?;
    assert!(
        rep_rhel.security_downgrades.is_empty(),
        "realistic RHEL tree with userdir.conf + welcome.conf + ssl.conf must import cleanly: {:?}",
        rep_rhel.security_downgrades
    );
    verify_parsed_report("r6-mig-9-rhel.kdl", &rep_rhel)?;

    // 3. Caddyfile with same-file `(snippet)` + `import snippet` (with args), plus security
    //    check proving a snippet containing `basic_auth` STILL fails closed!
    let caddy_clean = r"
(php_backend) {
    encode zstd gzip
    php_fastcgi {args[0]}
    file_server
}

blog.example.com {
    root * /var/www/blog
    import php_backend unix//run/php/php8.3-fpm.sock
}
";
    let rep_c = migrate_str(caddy_clean, SourceFormat::Caddy)?;
    assert!(
        rep_c.security_downgrades.is_empty(),
        "Caddy same-file snippet import must succeed: {:?}",
        rep_c.security_downgrades
    );
    let cfg_c = verify_parsed_report("r6-mig-9-caddy.kdl", &rep_c)?;
    let c_site = cfg_c.sites.first().ok_or("missing caddy site")?;
    assert!(matches!(
        c_site.match_route("/index.php").map(|r| &r.handler),
        Some(RouteHandler::FastCgi(_))
    ));

    let caddy_auth_snippet = r"
(admin_auth) {
    basic_auth {
        admin $2a$14$hash
    }
}

admin.example.com {
    root * /var/www/admin
    import admin_auth
    file_server
}
";
    assert!(
        matches!(
            migrate_str(caddy_auth_snippet, SourceFormat::Caddy),
            Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
        ),
        "Caddy snippet containing basic_auth MUST still fail closed after expansion"
    );

    let _ = fs::remove_dir_all(&base);
    Ok(())
}

/// R6-MIG-10: Notes and downgrades must redact non-directive lines (e.g. `/etc/shadow` password
/// hashes in an included file) and strip all ANSI terminal escape sequences and control chars.
#[test]
fn r6_mig_10_notes_redact_non_directive_secrets_and_strip_ansi_escapes() -> TestResult {
    let dir = std::env::temp_dir().join(format!(
        "miraserve-r6-mig-10-sanitize-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("conf.d"))?;
    fs::write(
        dir.join("conf.d/shadow.conf"),
        "root:$6$saltsalt$SuperSecretShadowHash123:19000:0:99999:7:::\n\x1b[31mFAKE_ALERT\x1b[0m;\n",
    )?;
    let main_conf = dir.join("nginx.conf");
    fs::write(
        &main_conf,
        "http {\n    server {\n        listen 443 ssl;\n        server_name san.example.com;\n        root /var/www/san;\n        include conf.d/shadow.conf;\n    }\n}\n",
    )?;

    // R8-MIG-1: text the importer cannot recognise is a blocker, not a note, so the site is
    // withheld. The diagnostics it carries must still never echo the unrecognised content.
    let downgrades = match miraserve_migrate::migrate_file(&main_conf, SourceFormat::Nginx) {
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { downgrades, .. }) => {
            downgrades
        }
        other => {
            return Err(format!(
                "R8-MIG-1: unrecognised included text must withhold the site, got: {other:?}"
            )
            .into());
        }
    };
    assert!(!downgrades.is_empty());
    for note in &downgrades {
        assert!(
            !note.directive.contains("SuperSecretShadowHash123")
                && !note.message.contains("SuperSecretShadowHash123")
                && !note.directive.contains("$6$saltsalt")
                && !note.message.contains("$6$saltsalt"),
            "shadow hash must NEVER be echoed into diagnostics: {note:?}"
        );
        assert!(
            !note.directive.contains('\x1b') && !note.message.contains('\x1b'),
            "ANSI escape byte must NEVER appear in diagnostics: {note:?}"
        );
    }

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// R6-MIG-11: Smaller importer defects — `$is_args$args` translation, differing HTTP/HTTPS
/// `DocumentRoot` values failing closed, undefined OLS `$VH_ROOT` failing closed, `client_max_body_size`
/// note, `server_name _; return 444` security downgrade, OLS vhost name not emitted as hostname,
/// and included file names recorded on `MigrationNote.file`.
#[test]
#[allow(clippy::too_many_lines)]
fn r6_mig_11_smaller_importer_fixes_is_args_roots_vhroot_body_size_444_ols_name_file_lines()
-> TestResult {
    // 1. `$is_args$args` -> `{query}` (never leaving literal `$is_args`), plus `client_max_body_size` note.
    let nginx_args = r"
server {
    listen 443 ssl;
    server_name app.example.com;
    root /var/www/app;
    client_max_body_size 50m;
    location / {
        try_files $uri $uri/ /index.php$is_args$args;
    }
    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    }
}
";
    let rep_args = migrate_str(nginx_args, SourceFormat::Nginx)?;
    let cfg_args = verify_parsed_report("r6-mig-11-args.kdl", &rep_args)?;
    assert!(
        !rep_args.kdl.contains("$is_args"),
        "literal `$is_args` must not remain in try-files KDL:\n{}",
        rep_args.kdl
    );
    assert!(
        rep_args.kdl.contains("/index.php?{query}"),
        "expected `/index.php?{{query}}` in KDL:\n{}",
        rep_args.kdl
    );
    assert!(
        rep_args
            .notes
            .iter()
            .any(|n| n.directive == "client_max_body_size"),
        "client_max_body_size must emit a manual-review note: {:?}",
        rep_args.notes
    );
    let site_args = cfg_args.sites.first().ok_or("missing site")?;
    assert!(matches!(
        site_args.match_route("/index.php").map(|r| &r.handler),
        Some(RouteHandler::FastCgi(_))
    ));

    // 2. Differing HTTP & HTTPS DocumentRoots for the same host fail closed instead of silently picking one.
    let diff_roots = r"
server {
    listen 80;
    server_name dual.example.com;
    root /var/www/public-http;
}
server {
    listen 443 ssl;
    server_name dual.example.com;
    root /var/www/private-https;
}
";
    assert!(matches!(
        migrate_str(diff_roots, SourceFormat::Nginx),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    // 3. `server_name _; return 444;` emits a security downgrade rather than silently dropping.
    let nginx_444 = r"
server {
    listen 443 ssl default_server;
    server_name _;
    return 444;
}
server {
    listen 443 ssl;
    server_name real.example.com;
    root /var/www/real;
}
";
    let rep_444 = migrate_str(nginx_444, SourceFormat::Nginx)?;
    verify_parsed_report("r6-mig-11-444.kdl", &rep_444)?;
    assert!(
        rep_444
            .security_downgrades
            .iter()
            .any(|d| d.directive == "return" && d.message.contains("444")),
        "server_name _ return 444 must emit a security downgrade, not silent drop: {:?}",
        rep_444.security_downgrades
    );

    // 4. Undefined OLS `$VH_ROOT` fails closed instead of guessing `/var/www`.
    let ols_undef_root = "vhDomain app.example.com\ndocRoot $VH_ROOT/html/\n";
    assert!(matches!(
        migrate_str(ols_undef_root, SourceFormat::OpenLiteSpeed),
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
    ));

    // 5. OLS `virtualHost Example` does NOT emit internal name `"Example"` as a hostname.
    let ols_vhname = r"
virtualHost Example {
    vhRoot /var/www/ex
    vhDomain real-ols.example.com
    docRoot $VH_ROOT/html
}
";
    let rep_vh = migrate_str(ols_vhname, SourceFormat::OpenLiteSpeed)?;
    let cfg_vh = verify_parsed_report("r6-mig-11-ols-vh.kdl", &rep_vh)?;
    let vh_site = cfg_vh.sites.first().ok_or("missing ols site")?;
    assert_eq!(vh_site.hosts, vec!["real-ols.example.com"]);

    // 6. Included-file diagnostics record `note.file == Some("included.conf")`.
    let dir = std::env::temp_dir().join(format!("miraserve-r6-mig-11-file-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("conf.d"))?;
    fs::write(
        dir.join("conf.d/included.conf"),
        "server {\n    listen 443 ssl;\n    server_name incfile.example.com;\n    root /var/www/inc;\n    client_max_body_size 16m;\n}\n",
    )?;
    let main_conf = dir.join("nginx.conf");
    fs::write(&main_conf, "http {\n    include conf.d/included.conf;\n}\n")?;
    let rep_inc = miraserve_migrate::migrate_file(&main_conf, SourceFormat::Nginx)?;
    verify_parsed_report("r6-mig-11-inc.kdl", &rep_inc)?;
    assert!(
        rep_inc.notes.iter().any(|n| {
            n.directive == "client_max_body_size" && n.file.as_deref() == Some("included.conf")
        }),
        "included file notes must carry source file name: {:?}",
        rep_inc.notes
    );

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// R7-MIG-1, R7-MIG-2 & R7-MIG-3:
/// - Literal non-regex Nginx `location /status.php` never widens to site-wide `*.php`.
/// - Attached Nginx modifiers without whitespace (`~^/...`, `~*...`, `=/health`, `^~/files/`)
///   parse identically to spaced modifiers (allow-lists never widen to `*.php`).
/// - Preferential prefix `location ^~ /files/` sorts BEFORE `*.php` so `/files/x.php` never executes.
#[test]
#[allow(clippy::too_many_lines)]
fn r7_mig_1_2_3_nginx_literal_php_attached_modifiers_and_preferential_prefix_order() -> TestResult {
    // 1. R7-MIG-1: Literal prefix `location /status.php` stays scoped to `/status.php/*`, NEVER `*.php`.
    let lit_php = r"
server {
    listen 443 ssl;
    server_name status.example.com;
    root /var/www/status;
    location /status.php {
        fastcgi_pass 127.0.0.1:9000;
    }
    location / {
        try_files $uri $uri/ =404;
    }
}
";
    let rep_lit = migrate_str(lit_php, SourceFormat::Nginx)?;
    let cfg_lit = verify_parsed_report("r7-mig-1-lit.kdl", &rep_lit)?;
    let site_lit = cfg_lit.sites.first().ok_or("missing site")?;
    assert!(
        !site_lit.routes.iter().any(|r| r.pattern == "*.php"),
        "R7-MIG-1: literal `location /status.php` MUST NOT widen to `*.php`: {:?}",
        site_lit.routes
    );
    assert!(
        site_lit.routes.iter().any(|r| r.pattern == "/status.php/*"),
        "R7-MIG-1: expected `/status.php/*` route, got: {:?}",
        site_lit.routes
    );

    // 2. R7-MIG-2: Attached modifiers without space (`~^/`, `~*`, `=`, `^~`).
    let attached = r"
server {
    listen 443 ssl;
    server_name attached.example.com;
    root /var/www/app;
    location =/health {
        proxy_pass http://127.0.0.1:9001;
    }
    location ^~/files/ {
        try_files $uri =404;
    }
    location ~^/(index|wp-cron)\.php$ {
        fastcgi_pass 127.0.0.1:9000;
    }
}
";
    let rep_att = migrate_str(attached, SourceFormat::Nginx)?;
    let cfg_att = verify_parsed_report("r7-mig-2-attached.kdl", &rep_att)?;
    let site_att = cfg_att.sites.first().ok_or("missing site")?;
    assert!(
        !site_att.routes.iter().any(|r| r.pattern == "*.php"),
        "R7-MIG-2: attached `location ~^/(index|wp-cron)\\.php$` MUST NOT widen to `*.php`: {:?}",
        site_att.routes
    );
    assert!(site_att.routes.iter().any(|r| r.pattern == "/health"));
    assert!(site_att.routes.iter().any(|r| r.pattern == "/index.php"));
    assert!(site_att.routes.iter().any(|r| r.pattern == "/wp-cron.php"));
    assert!(site_att.routes.iter().any(|r| r.pattern == "/files/*"));

    // 3. R7-MIG-3: `location ^~ /files/` sorts BEFORE `*.php`!
    let pref = r"
server {
    listen 443 ssl;
    server_name files.example.com;
    root /var/www/files;
    location ^~ /files/ {
        try_files $uri =404;
    }
    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    }
    location / {
        try_files $uri $uri/ /index.php?$args;
    }
}
";
    let rep_pref = migrate_str(pref, SourceFormat::Nginx)?;
    let cfg_pref = verify_parsed_report("r7-mig-3-pref.kdl", &rep_pref)?;
    let site_pref = cfg_pref.sites.first().ok_or("missing site")?;
    let files_pos = site_pref
        .routes
        .iter()
        .position(|r| r.pattern == "/files/*")
        .ok_or("missing /files/* route")?;
    let php_pos = site_pref
        .routes
        .iter()
        .position(|r| r.pattern == "*.php")
        .ok_or("missing *.php route")?;
    let catchall_pos = site_pref
        .routes
        .iter()
        .position(|r| r.pattern == "/*")
        .ok_or("missing /* route")?;
    assert!(
        files_pos < php_pos && php_pos < catchall_pos,
        "R7-MIG-3: ^~ `/files/*` ({files_pos}) MUST precede `*.php` ({php_pos}), which MUST precede `/*` ({catchall_pos})"
    );
    Ok(())
}

/// R7-MIG-4, R7-MIG-5, R7-MIG-10 & R7-MIG-11:
/// - Apache `<Directory>` narrower than `DocumentRoot` (whether before or after `DocumentRoot`)
///   or `<Location>` enclosing `<FilesMatch>`/`SetHandler` refuses instead of widening to `*.php`.
/// - Caddy `php_fastcgi` inside a non-root `handle` OR with a path matcher (`php_fastcgi /blog/*`)
///   refuses with a security downgrade (never widening to `*.php` or emitting `tcp:///blog/*`).
/// - OpenLiteSpeed respects `scriptHandler` suffixes (Python `py` -> `*.py`, never `*.php`) and
///   refuses scoped `fcgi` contexts and unmapped non-PHP `extprocessor` blocks.
#[test]
#[allow(clippy::too_many_lines)]
fn r7_mig_4_5_10_11_scoped_php_handlers_refused_across_apache_caddy_and_ols() -> TestResult {
    // 1. R7-MIG-4: Apache `<Directory /var/www/d/app><FilesMatch "\.php$">SetHandler ...` -> refused!
    for apache_scoped in [
        r#"
<VirtualHost *:443>
    ServerName narrow-dir.example.com
    DocumentRoot /var/www/d
    <Directory /var/www/d/app>
        <FilesMatch "\.php$">
            SetHandler "proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost"
        </FilesMatch>
    </Directory>
</VirtualHost>
"#,
        r#"
<VirtualHost *:443>
    ServerName dir-before-docroot.example.com
    <Directory /var/www/d/app>
        <FilesMatch "\.php$">
            SetHandler "proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost"
        </FilesMatch>
    </Directory>
    DocumentRoot /var/www/d
</VirtualHost>
"#,
        r#"
<VirtualHost *:443>
    ServerName narrow-loc.example.com
    DocumentRoot /var/www/d
    <Location /app/>
        <FilesMatch "\.php$">
            SetHandler "proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost"
        </FilesMatch>
    </Location>
</VirtualHost>
"#,
    ] {
        let res = migrate_str(apache_scoped, SourceFormat::Apache);
        assert!(
            matches!(
                res,
                Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
            ),
            "R7-MIG-4: narrowed Apache SetHandler scope MUST be refused, got: {res:?}"
        );
    }

    // Apache `<Directory /var/www/d>` EQUAL to `DocumentRoot /var/www/d` STILL succeeds cleanly!
    let apache_full_dir = r#"
<VirtualHost *:443>
    ServerName full-dir.example.com
    DocumentRoot /var/www/d
    <Directory /var/www/d>
        <FilesMatch "\.php$">
            SetHandler "proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost"
        </FilesMatch>
    </Directory>
</VirtualHost>
"#;
    let rep_full = migrate_str(apache_full_dir, SourceFormat::Apache)?;
    let cfg_full = verify_parsed_report("r7-mig-4-full.kdl", &rep_full)?;
    let site_full = cfg_full.sites.first().ok_or("missing apache full site")?;
    assert!(site_full.routes.iter().any(|r| r.pattern == "*.php"));

    // 2. R7-MIG-5: Caddy `handle /blog/* { php_fastcgi ... }` refused (never site-wide `*.php`)!
    let caddy_handle_php = r"
blog.example.com {
    root * /var/www/site
    handle /blog/* {
        php_fastcgi unix//run/php/php-fpm.sock
    }
    handle {
        file_server
    }
}
";
    let res_ch = migrate_str(caddy_handle_php, SourceFormat::Caddy);
    assert!(
        matches!(
            res_ch,
            Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
        ),
        "R7-MIG-5: Caddy php_fastcgi inside non-root handle MUST fail closed, got: {res_ch:?}"
    );

    // 3. R7-MIG-11: Caddy `php_fastcgi /blog/* unix//run/php/php-fpm.sock` refuses as scoped
    //    `php_fastcgi` (NOT `E304 invalid FastCGI endpoint 'tcp:///blog/*'`).
    let caddy_matcher_php = r"
blog.example.com {
    root * /var/www/site
    php_fastcgi /blog/* unix//run/php/php-fpm.sock
}
";
    match migrate_str(caddy_matcher_php, SourceFormat::Caddy) {
        Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { downgrades, .. }) => {
            assert!(
                downgrades.iter().any(|d| d.directive == "php_fastcgi"),
                "expected php_fastcgi downgrade, got: {downgrades:?}"
            );
        }
        other => {
            return Err(
                format!("R7-MIG-11: expected AllRoutesBlockedBySecurity, got: {other:?}").into(),
            );
        }
    }

    // 4. R7-MIG-10: OpenLiteSpeed Python `fcgi` + `scriptHandler` emits `*.py` (NEVER `*.php`),
    //    and scoped `context /app/ { type fcgi; handler py_app; }` refuses cleanly!
    let ols_py_script = r"
vhDomain pyapp.example.com
docRoot /var/www/pyapp
extprocessor py_app {
    type fcgi
    address uds://run/pyapp.sock
}
scriptHandler {
    add fcgi:py_app py
}
";
    let rep_ols_py = migrate_str(ols_py_script, SourceFormat::OpenLiteSpeed)?;
    let cfg_ols_py = verify_parsed_report("r7-mig-10-py.kdl", &rep_ols_py)?;
    let site_ols_py = cfg_ols_py.sites.first().ok_or("missing ols py site")?;
    assert!(
        site_ols_py.routes.iter().any(|r| r.pattern == "*.py"),
        "R7-MIG-10: expected *.py route for OLS scriptHandler py, got: {:?}",
        site_ols_py.routes
    );
    assert!(
        !site_ols_py.routes.iter().any(|r| r.pattern == "*.php"),
        "R7-MIG-10: OLS Python fcgi MUST NOT emit *.php"
    );

    let ols_py_ctx = r"
vhDomain pyctx.example.com
docRoot /var/www/pyctx
extprocessor py_app {
    type fcgi
    address uds://run/pyapp.sock
}
context /app/ {
    type fcgi
    handler py_app
}
";
    assert!(
        matches!(
            migrate_str(ols_py_ctx, SourceFormat::OpenLiteSpeed),
            Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
        ),
        "R7-MIG-10: scoped OLS fcgi context MUST be refused"
    );

    Ok(())
}

/// R7-MIG-6, R7-MIG-7, R7-MIG-9 & R7-MIG-12:
/// - Include globs (`*.conf`) follow POSIX `glob(3)` and NEVER import dotfiles like `.disabled-admin.conf`.
/// - Caddy `reverse_proxy { header_down ...; transport http { tls_trusted_ca_certs ... } }` and
///   Nginx `proxy_hide_header` / `more_set_headers` fail closed on security headers.
/// - Nginx redirect-only locations (`location /backup/ { return 302 /; }`) fail closed instead of
///   exposing `/backup/*` through `/*`.
/// - Benign caching headers (`Cache-Control: public, no-transform`, `Expires`, `Vary`) emit an
///   informational note with 0 downgrades while `Cache-Control: private, no-store` still fails closed.
#[test]
#[allow(clippy::too_many_lines)]
fn r7_mig_6_7_9_12_hidden_globs_headers_redirects_and_benign_cache_allowlist() -> TestResult {
    // 1. R7-MIG-6: Hidden `.disabled-admin.conf` is NOT imported by `include conf.d/*.conf;`.
    let dir = std::env::temp_dir().join(format!("miraserve-r7-mig-6-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("conf.d"))?;
    fs::write(
        dir.join("conf.d/site.conf"),
        "server {\n    listen 443 ssl;\n    server_name public.example.com;\n    root /var/www/pub;\n}\n",
    )?;
    fs::write(
        dir.join("conf.d/.disabled-admin.conf"),
        "server {\n    listen 443 ssl;\n    server_name admin.example.com;\n    location / { proxy_pass http://10.0.0.9:9000; }\n}\n",
    )?;
    let main_conf = dir.join("nginx.conf");
    fs::write(&main_conf, "http {\n    include conf.d/*.conf;\n}\n")?;
    let rep_glob = miraserve_migrate::migrate_file(&main_conf, SourceFormat::Nginx)?;
    let cfg_glob = verify_parsed_report("r7-mig-6-glob.kdl", &rep_glob)?;
    assert_eq!(cfg_glob.sites.len(), 1);
    let glob_site = cfg_glob.sites.first().ok_or("missing site")?;
    assert_eq!(glob_site.hosts, vec!["public.example.com"]);
    assert!(!rep_glob.kdl.contains("admin.example.com"));
    let _ = fs::remove_dir_all(&dir);

    // 2. R7-MIG-7: Caddy `reverse_proxy` sub-directives (`header_down`, `transport http { tls_trusted_ca_certs }`)
    //    and Nginx `proxy_hide_header` / `more_set_headers` fail closed!
    for caddy_bad in [
        "app.example.com {\n    reverse_proxy 127.0.0.1:8080 {\n        header_down -X-Internal-Token\n    }\n}\n",
        "app.example.com {\n    reverse_proxy 127.0.0.1:8080 {\n        header_down Content-Security-Policy \"default-src 'self'\"\n    }\n}\n",
        "app.example.com {\n    reverse_proxy https://10.0.0.5:8443 {\n        transport http {\n            tls_trusted_ca_certs /etc/ssl/internal-ca.pem\n        }\n    }\n}\n",
    ] {
        assert!(
            matches!(
                migrate_str(caddy_bad, SourceFormat::Caddy),
                Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
            ),
            "R7-MIG-7: Caddy reverse_proxy security sub-directive MUST fail closed:\n{caddy_bad}"
        );
    }
    for nginx_bad in [
        "server {\n    listen 443 ssl;\n    server_name a.example.com;\n    location / {\n        proxy_pass http://127.0.0.1:8080;\n        proxy_hide_header X-Internal-Token;\n    }\n}\n",
        "server {\n    listen 443 ssl;\n    server_name a.example.com;\n    root /var/www/a;\n    more_set_headers \"Content-Security-Policy: default-src 'self'\";\n}\n",
    ] {
        assert!(
            matches!(
                migrate_str(nginx_bad, SourceFormat::Nginx),
                Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
            ),
            "R7-MIG-7: Nginx proxy_hide_header/more_set_headers MUST fail closed:\n{nginx_bad}"
        );
    }

    // 3. R7-MIG-9: Redirect-only location `location /backup/ { return 302 /; }` fails closed!
    let nginx_redir_loc = r"
server {
    listen 443 ssl;
    server_name backup.example.com;
    root /var/www/site;
    location /backup/ {
        return 302 /;
    }
    location / {
        try_files $uri $uri/ =404;
    }
}
";
    assert!(
        matches!(
            migrate_str(nginx_redir_loc, SourceFormat::Nginx),
            Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
        ),
        "R7-MIG-9: redirect-only location `/backup/` MUST fail closed instead of falling through to `/*`"
    );

    // 4. R7-MIG-12: Benign public caching headers pass cleanly with notes; `private, no-store` still fails closed!
    let nginx_cache_ok = r#"
server {
    listen 443 ssl;
    server_name static.example.com;
    root /var/www/static;
    location /assets/ {
        add_header Cache-Control "public, no-transform";
        expires 30d;
        try_files $uri =404;
    }
    location / {
        try_files $uri $uri/ =404;
    }
}
"#;
    let rep_cache_ok = migrate_str(nginx_cache_ok, SourceFormat::Nginx)?;
    assert!(
        rep_cache_ok.security_downgrades.is_empty(),
        "R7-MIG-12: benign Cache-Control public must not downgrade: {:?}",
        rep_cache_ok.security_downgrades
    );
    assert!(
        rep_cache_ok
            .notes
            .iter()
            .any(|n| n.directive == "add_header")
    );

    let caddy_cache_ok = r#"
static.example.com {
    root * /var/www/static
    encode gzip zstd
    header /assets/* Cache-Control "public, max-age=31536000, immutable"
    file_server
}
"#;
    let rep_caddy_ok = migrate_str(caddy_cache_ok, SourceFormat::Caddy)?;
    assert!(
        rep_caddy_ok.security_downgrades.is_empty(),
        "R7-MIG-12: benign Caddy Cache-Control + encode must not downgrade: {:?}",
        rep_caddy_ok.security_downgrades
    );

    let nginx_nostore = r#"
server {
    listen 443 ssl;
    server_name auth.example.com;
    root /var/www/auth;
    add_header Cache-Control "private, no-store";
}
"#;
    assert!(
        matches!(
            migrate_str(nginx_nostore, SourceFormat::Nginx),
            Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
        ),
        "R7-MIG-12: Cache-Control `private, no-store` MUST still fail closed"
    );

    Ok(())
}

/// R7-MIG-8, R7-MIG-13, R7-MIG-14, R7-MIG-16, R7-MIG-17 & R7-CFG-2:
/// - Caddy snippet expansion bomb fails cleanly at the expansion limit (never OOMs or silently truncates).
/// - `MigrateOptions { source_root }` remaps `/etc/nginx/conf.d/*.conf` inside a copied tree.
/// - Attacker-controlled text actually reaches the `// INSECURE:` comment sanitizer (`R7-MIG-14`,
///   revert-checkable!).
/// - `kdl_quote` escapes `U+202E` and `U+FEFF` so generated KDL passes strict KDL v2 validation.
/// - Nginx `root .;` fails closed instead of guessing `/usr/share/nginx/html`.
#[test]
#[allow(clippy::too_many_lines)]
fn r7_mig_8_13_14_16_17_snippet_bomb_source_root_sanitizer_bidi_and_nginx_dot_root() -> TestResult {
    // 1. R7-MIG-8 & R7-MIG-17: Exponential Caddy snippet bomb fails at the expansion cap within the test bound.
    let mut bomb = String::from("(s0) {\n}\n");
    for n in 1..=7 {
        use std::fmt::Write as _;
        let _ = writeln!(bomb, "(s{n}) {{");
        for _ in 0..30 {
            let _ = writeln!(bomb, "    import s{}", n - 1);
        }
        bomb.push_str("}\n");
    }
    bomb.push_str("bomb.example.com {\n    import s7\n    file_server\n}\n");
    let t0 = std::time::Instant::now();
    let bomb_res = migrate_str(&bomb, SourceFormat::Caddy);
    assert!(
        matches!(bomb_res, Err(miraserve_migrate::MigrateError::ValidationFailed(ref m)) if m.contains("expansion")),
        "R7-MIG-8: Caddy snippet bomb must fail with expansion limit error, got: {bomb_res:?}"
    );
    assert!(
        t0.elapsed() < std::time::Duration::from_millis(250),
        "R7-MIG-8: Caddy snippet bomb took {:?} (expected < 250ms)",
        t0.elapsed()
    );

    // 2. R7-MIG-13: Copied Debian nginx.conf tree with absolute `/etc/nginx/conf.d/*.conf` works
    //    when `source_root` is provided!
    let tree = std::env::temp_dir().join(format!("miraserve-r7-mig-13-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tree);
    fs::create_dir_all(tree.join("conf.d"))?;
    fs::write(
        tree.join("conf.d/app.conf"),
        "server {\n    listen 443 ssl;\n    server_name relocated.example.com;\n    root /var/www/relocated;\n}\n",
    )?;
    let main_ngx = tree.join("nginx.conf");
    fs::write(
        &main_ngx,
        "http {\n    include /etc/nginx/conf.d/*.conf;\n}\n",
    )?;
    let rep_sr = miraserve_migrate::migrate_file_with_options(
        &main_ngx,
        SourceFormat::Nginx,
        miraserve_migrate::MigrateOptions {
            allow_insecure: false,
            source_root: Some(tree.clone()),
        },
    )?;
    let cfg_sr = verify_parsed_report("r7-mig-13-sr.kdl", &rep_sr)?;
    assert_eq!(cfg_sr.sites.len(), 1);
    let sr_site = cfg_sr.sites.first().ok_or("missing relocated site")?;
    assert_eq!(sr_site.hosts, vec!["relocated.example.com"]);
    let _ = fs::remove_dir_all(&tree);

    // 3. R7-MIG-14: Attacker-controlled text actually reaches `site.block_site` -> `// INSECURE:`
    //    comment AND `MigrationNote::message` — verifying `sanitize_diagnostic_text` blocks KDL
    //    comment breakout (`\n` AND `\u{2028}`)!
    let kdl_inject_hdr = concat!(
        "server {\n",
        "    listen 443 ssl;\n",
        "    server_name victim.example.com;\n",
        "    root /var/www/victim;\n",
        "    add_header \"X-Custom\nsite \\\"evil-nl.example\\\" { root \\\"/var/www/evil\\\" }\u{2028}site \\\"evil-ls.example\\\" { root \\\"/var/www/evil\\\" }\" \"1\";\n",
        "}\n"
    );
    let rep_inj = miraserve_migrate::migrate_str_with_options(
        kdl_inject_hdr,
        SourceFormat::Nginx,
        miraserve_migrate::MigrateOptions {
            allow_insecure: true,
            ..miraserve_migrate::MigrateOptions::default()
        },
    )?;
    let cfg_inj = verify_parsed_report("r7-mig-14-inj.kdl", &rep_inj)?;
    assert_eq!(
        cfg_inj.sites.len(),
        1,
        "R7-MIG-14: comment breakout must never inject a second site; KDL:\n{}",
        rep_inj.kdl
    );
    let inj_site = cfg_inj.sites.first().ok_or("missing victim site")?;
    assert_eq!(inj_site.hosts, vec!["victim.example.com"]);
    for line in rep_inj.kdl.lines() {
        assert!(
            !line.contains('\u{2028}') && !line.contains('\u{2029}'),
            "R7-MIG-14: raw Unicode line separator leaked into KDL"
        );
    }

    // 4. R7-MIG-16: `kdl_quote` safely escapes U+202E and U+FEFF so generated KDL validates cleanly!
    let bidi_nginx = "server {\n    listen 443 ssl;\n    server_name bidi.example.com;\n    root /var/www/bidi;\n    location / {\n        try_files $uri \"/safe\u{202E}name\u{FEFF}.html\" =404;\n    }\n}\n";
    let rep_bidi = migrate_str(bidi_nginx, SourceFormat::Nginx)?;
    let _ = verify_parsed_report("r7-mig-16-bidi.kdl", &rep_bidi)?;
    assert!(!rep_bidi.kdl.contains('\u{202E}'));
    assert!(!rep_bidi.kdl.contains('\u{FEFF}'));
    assert!(rep_bidi.kdl.contains("\\u{202e}"));
    assert!(rep_bidi.kdl.contains("\\u{feff}"));

    // 5. R7-CFG-2: Nginx `root .;` fails closed instead of silently mapping to `/usr/share/nginx/html`.
    let nginx_dot_root =
        "server {\n    listen 443 ssl;\n    server_name dot.example.com;\n    root .;\n}\n";
    assert!(
        matches!(
            migrate_str(nginx_dot_root, SourceFormat::Nginx),
            Err(miraserve_migrate::MigrateError::AllRoutesBlockedBySecurity { .. })
        ),
        "R7-CFG-2: Nginx `root .;` MUST fail closed"
    );

    Ok(())
}

//! Round-8 importer regression tests (`R8-MIG-1` .. `R8-MIG-9`).
//!
//! The rule under test is one sentence: an importer may leave a directive untranslated only
//! when it KNOWS the directive is inert; anything else it does not translate must make the
//! import fail (a security downgrade, which the CLI turns into a non-zero exit) instead of
//! becoming a "manual review" note on a config that is less safe than the source.

use std::fs;

use miraserve_migrate::{MigrateError, SourceFormat, migrate_file, migrate_str};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// `true` when the import is refused: either nothing could be emitted, or the report carries
/// security downgrades (the CLI exits non-zero on those unless `--allow-insecure` is passed).
fn is_refused(source: &str, format: SourceFormat) -> bool {
    match migrate_str(source, format) {
        Ok(report) => !report.security_downgrades.is_empty(),
        // Any error is a non-zero exit with nothing written, which is a refusal.
        Err(_) => true,
    }
}

fn assert_refused(label: &str, source: &str, format: SourceFormat) {
    assert!(
        is_refused(source, format),
        "{label}: import MUST be refused (fail closed), but it succeeded with no downgrade:\n{source}"
    );
}

/// Imports cleanly (no downgrade) and returns the generated KDL.
fn assert_clean(label: &str, source: &str, format: SourceFormat) -> Result<String, String> {
    match migrate_str(source, format) {
        Ok(report) if report.security_downgrades.is_empty() => Ok(report.kdl),
        Ok(report) => Err(format!(
            "{label}: a legitimate config must import cleanly, got downgrades: {:?}",
            report.security_downgrades
        )),
        Err(err) => Err(format!(
            "{label}: a legitimate config must import cleanly, got error: {err:?}"
        )),
    }
}

fn nginx_server(body: &str) -> String {
    format!("server {{\n listen 80;\n server_name a.test;\n root /var/www/a;\n{body}\n}}\n")
}

fn apache_vhost(body: &str) -> String {
    format!(
        "<VirtualHost *:80>\nServerName a.test\nDocumentRoot /var/www/a\n{body}\n</VirtualHost>\n"
    )
}

#[test]
#[allow(clippy::too_many_lines)]
fn r8_mig_nginx_untranslated_directives_fail_closed() {
    let cases: &[(&str, &str)] = &[
        (
            "R8-MIG-1 uwsgi_pass",
            "location /static/ { try_files $uri =404; }\n location / { include uwsgi_params; uwsgi_pass unix:/run/uwsgi/app.sock; }",
        ),
        (
            "R8-MIG-1 scgi_pass",
            "location / { scgi_pass 127.0.0.1:4000; }",
        ),
        (
            "R8-MIG-1 grpc_pass",
            "location /api/ { grpc_pass grpc://127.0.0.1:9000; }",
        ),
        (
            "R8-MIG-1 content_by_lua_block",
            "location /app/ { content_by_lua_block { ngx.say(1) } }",
        ),
        (
            "R8-MIG-1 js_content",
            "location /app/ { js_content main.handler; }",
        ),
        (
            "R8-MIG-1 unknown location directive",
            "location /x/ { frobnicate on; }",
        ),
        ("R8-MIG-1 unknown server directive", "frobnicate on;"),
        (
            "R8-MIG-1 unknown server block",
            "frobnicate_block { thing on; }",
        ),
        (
            "R8-MIG-1 if with rewrite",
            "location / { if (!-e $request_filename) { rewrite ^(.+)$ /index.php?q=$1 last; } }",
        ),
        ("R8-MIG-1 internal", "location /protected/ { internal; }"),
        (
            "R8-MIG-6 fastcgi_hide_header",
            "location /api/ { fastcgi_hide_header X-Internal-Token; fastcgi_pass 127.0.0.1:9000; }",
        ),
        (
            "R8-MIG-6 uwsgi_hide_header (server)",
            "uwsgi_hide_header X-Internal-Token;\n location / { try_files $uri =404; }",
        ),
        (
            "R8-MIG-7 location rewrite redirect",
            "location /admin/ { rewrite ^ /login.html redirect; }",
        ),
        (
            "R8-MIG-7 server rewrite",
            "rewrite ^/backup/.*$ /index.html last;",
        ),
        (
            "R8-MIG-8 alias",
            "location /private/ { alias /var/www/a/public-only/; }",
        ),
        (
            "review: conditional empty 2xx hides a method the source refused to forward",
            "location /api/ { if ($request_method = DELETE) { return 204; } proxy_pass http://127.0.0.1:9000; }",
        ),
        (
            "review: CORS preflight idiom is still a conditional response",
            "location /public/ { if ($request_method = OPTIONS) { return 204; } proxy_pass http://127.0.0.1:9000; }",
        ),
        (
            "review: proxy_set_header blanks an identity header the upstream trusts",
            "location / { proxy_set_header X-Remote-User \"\"; proxy_pass http://127.0.0.1:9000; }",
        ),
        (
            "review: proxy_set_header sets a role header",
            "location / { proxy_set_header X-Auth-Role $role; proxy_pass http://127.0.0.1:9000; }",
        ),
        (
            "review: proxy_set_header strips Authorization",
            "location / { proxy_set_header Authorization \"\"; proxy_pass http://127.0.0.1:9000; }",
        ),
        (
            "review: proxy_set_header pins Host to an internal name",
            "location / { proxy_set_header Host backend.internal; proxy_pass http://127.0.0.1:9000; }",
        ),
        (
            "review: fastcgi_param blanks an identity header for the application",
            "location ~ \\.php$ { fastcgi_param HTTP_X_REMOTE_USER \"\"; fastcgi_pass 127.0.0.1:9000; }",
        ),
        (
            "review: server-level proxy_set_header for an identity header",
            "proxy_set_header X-Remote-User \"\";\n location / { proxy_pass http://127.0.0.1:9000; }",
        ),
        (
            "review 2: SCRIPT_FILENAME pinned to one front controller",
            "location ~ \\.php$ { fastcgi_param SCRIPT_FILENAME /var/www/a/index.php; fastcgi_pass 127.0.0.1:9000; }",
        ),
        (
            "review 2: SCRIPT_FILENAME built from another root",
            "location ~ \\.php$ { fastcgi_param SCRIPT_FILENAME /srv/other$fastcgi_script_name; fastcgi_pass 127.0.0.1:9000; }",
        ),
        (
            "review 2: standard FastCGI name with a non-standard value",
            "location ~ \\.php$ { fastcgi_param REMOTE_ADDR $http_x_real_ip; fastcgi_pass 127.0.0.1:9000; }",
        ),
        (
            "review 2: Host pinned to a variable the proxy does not reproduce",
            "location / { proxy_set_header Host $server_name; proxy_pass http://127.0.0.1:9000; }",
        ),
        (
            "review 2: forwarding header with a client-controlled value",
            "location / { proxy_set_header X-Forwarded-For $http_x_forwarded_for; proxy_pass http://127.0.0.1:9000; }",
        ),
        (
            "review 2: X-Forwarded-Proto passed through from the client",
            "location / { proxy_set_header X-Forwarded-Proto $http_x_forwarded_proto; proxy_pass http://127.0.0.1:9000; }",
        ),
        (
            "review 2: X-Forwarded-Port is never sent by the proxy",
            "location / { proxy_set_header X-Forwarded-Port $server_port; proxy_pass http://127.0.0.1:9000; }",
        ),
        (
            "review 2: identity header inherited from server level",
            "proxy_set_header X-Remote-User \"\";\n location / { proxy_pass http://127.0.0.1:9000; }",
        ),
        (
            "R8-MIG-8 location root differs",
            "location /private/ { root /srv/other; }",
        ),
    ];
    for (label, body) in cases {
        assert_refused(label, &nginx_server(body), SourceFormat::Nginx);
    }
}

#[test]
fn r8_mig_nginx_legitimate_configs_still_import() -> TestResult {
    let wordpress = r"
server {
    listen 443 ssl http2;
    server_name blog.example.com;
    root /var/www/blog;
    index index.php index.html;
    ssl_certificate /etc/ssl/blog.crt;
    ssl_certificate_key /etc/ssl/blog.key;
    client_max_body_size 64m;
    gzip on; gzip_types text/css application/javascript;
    error_page 404 /404.html;
    location / { try_files $uri $uri/ /index.php?$args; }
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param HTTPS on;
        fastcgi_read_timeout 60s;
        fastcgi_buffers 16 16k;
    }
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ { expires max; log_not_found off; access_log off; }
    location ~ /\.ht { deny all; }
    location = /favicon.ico { log_not_found off; access_log off; }
}
";
    let kdl = assert_clean("wordpress", wordpress, SourceFormat::Nginx)?;
    assert!(kdl.contains("route \"*.php\""), "{kdl}");
    assert!(kdl.contains("route \"/*\""), "{kdl}");

    // The stock nginx.org default server keeps its root in `location /`.
    let stock = r"
server {
    listen       80;
    server_name  localhost;
    location / {
        root   /usr/share/nginx/html;
        index  index.html index.htm;
    }
    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   /usr/share/nginx/html;
    }
}
";
    let kdl = assert_clean("stock default", stock, SourceFormat::Nginx)?;
    assert!(kdl.contains("root \"/usr/share/nginx/html\""), "{kdl}");

    // Forwarding headers MiraServe's proxy manages itself, the client's own Host, and the
    // WebSocket upgrade pair are reproduced, so these rules need no translation.
    let proxy = nginx_server(
        "location /app/ { proxy_set_header Host $host; proxy_set_header X-Real-IP $remote_addr; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; proxy_set_header X-Forwarded-Proto $scheme; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection \"upgrade\"; proxy_http_version 1.1; proxy_pass http://10.0.5.20:8080; proxy_send_timeout 30s; }",
    );
    let kdl = assert_clean("standard proxy headers", &proxy, SourceFormat::Nginx)?;
    assert!(kdl.contains("route \"/app/*\""), "{kdl}");
    Ok(())
}

/// Review 2: `proxy_set_header` and request-handling directives written at `http` level are
/// inherited by every location below that defines none of its own.
#[test]
fn review2_nginx_http_level_rules_are_inherited_and_checked() -> TestResult {
    let http = |http_rules: &str, location: &str| {
        format!(
            "http {{\n {http_rules}\n server {{ listen 80; server_name a.test;\n  location / {{ {location} }}\n }}\n}}\n"
        )
    };
    assert_refused(
        "identity header blanked at http level",
        &http(
            "proxy_set_header X-Remote-User \"\";",
            "proxy_pass http://127.0.0.1:9000;",
        ),
        SourceFormat::Nginx,
    );
    assert_refused(
        "custom fastcgi_param at http level",
        &http(
            "fastcgi_param HTTP_X_REMOTE_USER \"\";",
            "proxy_pass http://127.0.0.1:9000;",
        ),
        SourceFormat::Nginx,
    );
    assert_refused(
        "proxy_pass_header at http level",
        &http(
            "proxy_pass_header X-Accel-Redirect;",
            "proxy_pass http://127.0.0.1:9000;",
        ),
        SourceFormat::Nginx,
    );
    // A location that defines its own rules does not inherit the http-level ones (Nginx
    // semantics), so the http-level identity rule does not apply there.
    let overridden = http(
        "proxy_set_header X-Remote-User \"\";",
        "proxy_set_header Host $host; proxy_pass http://127.0.0.1:9000;",
    );
    let kdl = assert_clean(
        "location overrides inherited rules",
        &overridden,
        SourceFormat::Nginx,
    )?;
    assert!(kdl.contains("preserve-host #true"), "{kdl}");

    // `Host $host` inherited from http level reaches the location and is translated.
    let inherited_host = http(
        "proxy_set_header Host $host;\n proxy_set_header X-Real-IP $remote_addr;",
        "proxy_pass http://127.0.0.1:9000;",
    );
    let kdl = assert_clean("inherited Host $host", &inherited_host, SourceFormat::Nginx)?;
    assert!(kdl.contains("preserve-host #true"), "{kdl}");

    // No Host rule at all is Nginx's default (`$proxy_host`), which is MiraServe's default too.
    let default_host = http("", "proxy_pass http://127.0.0.1:9000;");
    let kdl = assert_clean("default Host", &default_host, SourceFormat::Nginx)?;
    assert!(!kdl.contains("preserve-host"), "{kdl}");
    Ok(())
}

/// Review 2 regression guard for over-refusal: a Debian/Ubuntu tree read from disk, where the
/// stock `snippets/fastcgi-php.conf`, `fastcgi.conf` and `proxy_params` are expanded inline.
#[test]
fn review2_stock_debian_nginx_tree_from_disk_imports_cleanly() -> TestResult {
    let dir = std::env::temp_dir().join(format!(
        "miraserve-review2-nginx-tree-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("snippets"))?;
    fs::create_dir_all(dir.join("sites-enabled"))?;
    fs::write(
        dir.join("snippets/fastcgi-php.conf"),
        "fastcgi_split_path_info ^(.+?\\.php)(/.*)$;\ntry_files $fastcgi_script_name =404;\nset $path_info $fastcgi_path_info;\nfastcgi_param PATH_INFO $path_info;\nfastcgi_index index.php;\ninclude fastcgi.conf;\n",
    )?;
    fs::write(
        dir.join("fastcgi.conf"),
        "fastcgi_param  SCRIPT_FILENAME    $document_root$fastcgi_script_name;\nfastcgi_param  QUERY_STRING       $query_string;\nfastcgi_param  REQUEST_METHOD     $request_method;\nfastcgi_param  CONTENT_TYPE       $content_type;\nfastcgi_param  CONTENT_LENGTH     $content_length;\nfastcgi_param  SCRIPT_NAME        $fastcgi_script_name;\nfastcgi_param  REQUEST_URI        $request_uri;\nfastcgi_param  DOCUMENT_URI       $document_uri;\nfastcgi_param  DOCUMENT_ROOT      $document_root;\nfastcgi_param  SERVER_PROTOCOL    $server_protocol;\nfastcgi_param  REQUEST_SCHEME     $scheme;\nfastcgi_param  HTTPS              $https if_not_empty;\nfastcgi_param  GATEWAY_INTERFACE  CGI/1.1;\nfastcgi_param  SERVER_SOFTWARE    nginx/$nginx_version;\nfastcgi_param  REMOTE_ADDR        $remote_addr;\nfastcgi_param  REMOTE_PORT        $remote_port;\nfastcgi_param  REMOTE_USER        $remote_user;\nfastcgi_param  SERVER_ADDR        $server_addr;\nfastcgi_param  SERVER_PORT        $server_port;\nfastcgi_param  SERVER_NAME        $server_name;\nfastcgi_param  REDIRECT_STATUS    200;\n",
    )?;
    fs::write(
        dir.join("proxy_params"),
        "proxy_set_header Host $http_host;\nproxy_set_header X-Real-IP $remote_addr;\nproxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\nproxy_set_header X-Forwarded-Proto $scheme;\n",
    )?;
    fs::write(
        dir.join("sites-enabled/wp"),
        "server {\n listen 80;\n server_name blog.example.com;\n root /var/www/blog;\n index index.php;\n location / { try_files $uri $uri/ /index.php?$args; }\n location ~ \\.php$ {\n  include snippets/fastcgi-php.conf;\n  fastcgi_pass unix:/run/php/php8.2-fpm.sock;\n }\n location /api/ {\n  include proxy_params;\n  proxy_pass http://127.0.0.1:3000;\n }\n}\n",
    )?;
    let main = dir.join("nginx.conf");
    fs::write(&main, "events {}\nhttp {\n include sites-enabled/*;\n}\n")?;

    let report = migrate_file(&main, SourceFormat::Nginx)?;
    assert!(
        report.security_downgrades.is_empty(),
        "the stock Debian PHP and proxy snippets must import cleanly: {:?}",
        report.security_downgrades
    );
    assert!(report.kdl.contains("route \"*.php\""), "{}", report.kdl);
    assert!(report.kdl.contains("route \"/api/*\""), "{}", report.kdl);
    assert!(
        report.kdl.contains("preserve-host #true"),
        "`proxy_params` sets `Host $http_host`, which must become preserve-host:\n{}",
        report.kdl
    );

    // The same tree with the front controller pinned must be refused.
    fs::write(
        dir.join("fastcgi.conf"),
        "fastcgi_param  SCRIPT_FILENAME    /var/www/blog/index.php;\n",
    )?;
    let pinned = match migrate_file(&main, SourceFormat::Nginx) {
        Ok(r) => !r.security_downgrades.is_empty(),
        Err(_) => true,
    };
    assert!(
        pinned,
        "a pinned SCRIPT_FILENAME read from an included file must be refused"
    );
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn r8_mig_apache_conditionals_handlers_and_unknown_directives_fail_closed() {
    let php = "<FilesMatch \\.php$>\nSetHandler \"proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost\"\n</FilesMatch>\n";
    let cases: Vec<(&str, String)> = vec![
        (
            "R8-MIG-2 <If> around ProxyPass",
            "<Location /admin/>\n<If \"-R '10.0.0.0/8'\">\nProxyPass \"http://127.0.0.1:9000/admin/\"\n</If>\n</Location>".to_owned(),
        ),
        (
            "R8-MIG-2 <If> around PHP handler",
            "<If \"-R '10.0.0.0/8'\">\n<FilesMatch \\.php$>\nSetHandler \"proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost\"\n</FilesMatch>\n</If>".to_owned(),
        ),
        (
            "R8-MIG-2 <IfDefine>",
            "<IfDefine ENABLE_ADMIN_PROXY>\nProxyPass /admin/ http://127.0.0.1:9000/admin/\n</IfDefine>".to_owned(),
        ),
        (
            "R8-MIG-2 negated <IfModule>",
            "<IfModule !mod_proxy_fcgi.c>\nProxyPass /x/ http://127.0.0.1:9001/\n</IfModule>".to_owned(),
        ),
        (
            "R8-MIG-2 <Else>",
            "<If \"%{HTTP_HOST} == 'a.test'\">\nHeader set X-A 1\n</If>\n<Else>\nProxyPass /e/ http://127.0.0.1:9002/\n</Else>".to_owned(),
        ),
        (
            "R8-MIG-3 SetHandler none in <Directory>",
            format!("{php}<Directory /var/www/a/uploads>\n<FilesMatch \\.php$>\nSetHandler none\n</FilesMatch>\n</Directory>"),
        ),
        (
            "R8-MIG-3 SetHandler none in <Location>",
            format!("{php}<Location /uploads>\nSetHandler none\n</Location>"),
        ),
        (
            "R8-MIG-3 SetHandler default-handler",
            format!("{php}<DirectoryMatch \"^/var/www/a/(uploads|cache)\">\nSetHandler default-handler\n</DirectoryMatch>"),
        ),
        (
            "R8-MIG-3 RemoveHandler",
            format!("{php}<Location /uploads>\nRemoveHandler .php\n</Location>"),
        ),
        (
            "R8-MIG-1 WSGIScriptAlias /",
            "WSGIScriptAlias / /var/www/a/app/wsgi.py".to_owned(),
        ),
        (
            "R8-MIG-1 SetHandler cgi-script",
            "<Directory /var/www/a/scripts>\nSetHandler cgi-script\n</Directory>".to_owned(),
        ),
        ("R8-MIG-1 unknown directive", "Frobnicate On".to_owned()),
        (
            "review: RequestHeader removes an identity header the upstream trusts",
            "RequestHeader unset X-Remote-User\nProxyPass / http://127.0.0.1:3000/".to_owned(),
        ),
        (
            "review: RequestHeader sets an X-Forwarded-* name MiraServe does not manage",
            "RequestHeader set X-Forwarded-User \"%{REMOTE_USER}s\"\nProxyPass / http://127.0.0.1:3000/".to_owned(),
        ),
        (
            "review: ProxyPass inside a positive <IfModule> may be dormant in the source",
            "<IfModule mod_proxy.c>\nProxyPass /admin/ http://127.0.0.1:9000/admin/\n</IfModule>".to_owned(),
        ),
        (
            "review 2: ServerAlias inside a positive <IfModule> may be dormant",
            "<IfModule mod_alias.c>\nServerAlias other.test\n</IfModule>".to_owned(),
        ),
        (
            "review 2: RequestHeader unset X-Forwarded-Host while the proxy adds it back",
            "RequestHeader unset X-Forwarded-Host\nProxyPass / http://127.0.0.1:3000/".to_owned(),
        ),
        (
            "review 2: RequestHeader set X-Forwarded-Port is never sent by the proxy",
            "RequestHeader set X-Forwarded-Port \"443\"\nProxyPass / http://127.0.0.1:3000/".to_owned(),
        ),
        (
            "review 2: RequestHeader set X-Forwarded-Proto from a client header",
            "RequestHeader set X-Forwarded-Proto \"%{X-Client-Proto}i\"\nProxyPass / http://127.0.0.1:3000/".to_owned(),
        ),
        (
            "review 2: ProxyPreserveHost scoped to a section",
            "<Location /app/>\nProxyPreserveHost On\nProxyPass http://127.0.0.1:3000/app/\n</Location>".to_owned(),
        ),
        (
            "review: PHP handler inside a positive <IfModule>",
            "<IfModule proxy_fcgi_module>\n<FilesMatch \\.php$>\nSetHandler \"proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost\"\n</FilesMatch>\n</IfModule>".to_owned(),
        ),
        (
            "R8-MIG-1 unknown container",
            "<Frobnicate x>\nProxyPass /f/ http://127.0.0.1:9003/\n</Frobnicate>".to_owned(),
        ),
        (
            "R8-MIG-8 AliasMatch",
            "AliasMatch ^/private/(.*)$ /srv/other/$1".to_owned(),
        ),
    ];
    for (label, body) in &cases {
        assert_refused(label, &apache_vhost(body), SourceFormat::Apache);
    }

    // The same classes outside any <VirtualHost>.
    let global_cases: &[(&str, &str)] = &[
        (
            "R8-MIG-1 global WSGIScriptAlias",
            "ServerName g.test\nDocumentRoot /srv/django\nWSGIScriptAlias / /srv/django/app/wsgi.py\n",
        ),
        (
            "R8-MIG-2 global <If>",
            "ServerName g.test\nDocumentRoot /var/www/g\n<If \"-R '10.0.0.0/8'\">\nProxyPass /admin/ http://127.0.0.1:9000/admin/\n</If>\n",
        ),
        (
            "R8-MIG-3 global SetHandler none",
            "ServerName g.test\nDocumentRoot /var/www/g\n<Directory /var/www/g/uploads>\nSetHandler none\n</Directory>\n",
        ),
    ];
    for (label, source) in global_cases {
        assert_refused(label, source, SourceFormat::Apache);
    }
}

#[test]
fn r8_mig_apache_legitimate_configs_still_import_and_alias_prefixes_are_closed() -> TestResult {
    let debian_default = "<VirtualHost *:80>\n\tServerAdmin webmaster@localhost\n\tDocumentRoot /var/www/html\n\tErrorLog ${APACHE_LOG_DIR}/error.log\n\tCustomLog ${APACHE_LOG_DIR}/access.log combined\n</VirtualHost>\n";
    let kdl = assert_clean("debian 000-default", debian_default, SourceFormat::Apache)?;
    assert!(kdl.contains("root \"/var/www/html\""), "{kdl}");

    let proxy = "<VirtualHost *:443>\nServerName app.example.com\nSSLEngine on\nSSLCertificateFile /etc/ssl/app.crt\nSSLCertificateKeyFile /etc/ssl/app.key\nProxyPreserveHost On\nProxyRequests Off\nRequestHeader set X-Forwarded-Proto \"https\"\nProxyPass / http://127.0.0.1:3000/\nProxyPassReverse / http://127.0.0.1:3000/\nErrorDocument 503 /maintenance.html\n<IfModule mod_headers.c>\nProxyTimeout 60\n</IfModule>\n</VirtualHost>\n";
    let kdl = assert_clean("reverse proxy vhost", proxy, SourceFormat::Apache)?;
    assert!(kdl.contains("http://127.0.0.1:3000"), "{kdl}");
    assert!(
        kdl.contains("preserve-host #true"),
        "`ProxyPreserveHost On` must become preserve-host:\n{kdl}"
    );
    let no_preserve = "<VirtualHost *:443>\nServerName app.example.com\nSSLEngine on\nSSLCertificateFile /etc/ssl/app.crt\nSSLCertificateKeyFile /etc/ssl/app.key\nProxyPass / http://127.0.0.1:3000/\n</VirtualHost>\n";
    let kdl = assert_clean(
        "proxy without ProxyPreserveHost",
        no_preserve,
        SourceFormat::Apache,
    )?;
    assert!(!kdl.contains("preserve-host"), "{kdl}");
    let global_preserve = format!("ProxyPreserveHost On\n{no_preserve}");
    let kdl = assert_clean(
        "server-wide ProxyPreserveHost",
        &global_preserve,
        SourceFormat::Apache,
    )?;
    assert!(
        kdl.contains("preserve-host #true"),
        "a server-wide `ProxyPreserveHost On` is inherited by the virtual host:\n{kdl}"
    );

    // A literal alias prefix is not migrated, and it must not fall through to the document root
    // or to `*.php`: it gets an explicit 404 route.
    let aliases = apache_vhost(
        "ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/\nAlias /doc/ \"/usr/share/doc/\"\n<FilesMatch \\.php$>\nSetHandler \"proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost\"\n</FilesMatch>",
    );
    let report = migrate_str(&aliases, SourceFormat::Apache)?;
    assert!(
        report.security_downgrades.is_empty(),
        "{:?}",
        report.security_downgrades
    );
    let cgi = report
        .kdl
        .find("route \"/cgi-bin/*\"")
        .ok_or("missing closed /cgi-bin/* route")?;
    let php = report
        .kdl
        .find("route \"*.php\"")
        .ok_or("missing *.php route")?;
    assert!(
        cgi < php,
        "the closed alias prefix must be matched before `*.php`:\n{}",
        report.kdl
    );
    let after_cgi = report.kdl.get(cgi..).unwrap_or("");
    assert!(
        after_cgi
            .lines()
            .nth(1)
            .is_some_and(|l| l.contains("try-files \"=404\"")),
        "closed prefix must answer 404:\n{}",
        report.kdl
    );
    assert!(
        report.kdl.contains("route \"/doc/*\""),
        "missing closed /doc/* route:\n{}",
        report.kdl
    );
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.message.contains("answers 404")),
        "the operator must be told the prefix is closed: {:?}",
        report.notes
    );
    Ok(())
}

#[test]
fn r8_mig_4_apache_directory_include_with_subdir_or_dotfile_fails_closed() -> TestResult {
    let acl = "<Location /admin/>\nRequire ip 10.0.0.0/8\n</Location>\n";
    let vhost = "<VirtualHost *:80>\nServerName i.test\nProxyPass /admin/ http://127.0.0.1:9000/admin/\nInclude conf.d\n</VirtualHost>\n";
    for (label, rel) in [
        ("subdirectory", "conf.d/sub/acl.conf"),
        ("dotfile", "conf.d/.acl.conf"),
        ("plain file", "conf.d/acl.conf"),
    ] {
        let dir = std::env::temp_dir().join(format!(
            "miraserve-r8-mig-4-{}-{}",
            label.replace(' ', "-"),
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let acl_path = dir.join(rel);
        fs::create_dir_all(acl_path.parent().ok_or("no parent")?)?;
        fs::write(&acl_path, acl)?;
        let main = dir.join("site.conf");
        fs::write(&main, vhost)?;

        let refused = match migrate_file(&main, SourceFormat::Apache) {
            Ok(report) => {
                assert!(
                    report.security_downgrades.is_empty()
                        || !report.kdl.contains("route \"/admin/*\""),
                    "R8-MIG-4 ({label}): /admin/ must never be emitted without its ACL:\n{}",
                    report.kdl
                );
                !report.security_downgrades.is_empty()
            }
            Err(MigrateError::AllRoutesBlockedBySecurity { .. }) => true,
            Err(other) => return Err(format!("unexpected error: {other:?}").into()),
        };
        assert!(
            refused,
            "R8-MIG-4 ({label}): an ACL kept in an included directory must withhold /admin/"
        );
        let _ = fs::remove_dir_all(&dir);
    }
    Ok(())
}

#[test]
fn r8_mig_caddy_hide_redirects_and_unknown_directives_fail_closed() -> TestResult {
    let refused: &[(&str, &str)] = &[
        (
            "R8-MIG-5 file_server hide",
            "a.test {\n  root * /srv/a\n  file_server {\n    hide secret.txt /root/private\n  }\n}\n",
        ),
        (
            "R8-MIG-5 file_server unknown option",
            "a.test {\n  root * /srv/a\n  file_server {\n    frobnicate on\n  }\n}\n",
        ),
        (
            "review: file_server limited to one subtree must not become site-wide",
            "a.test {\n  root * /srv/a\n  file_server /public/*\n}\n",
        ),
        (
            "review: file_server with a named matcher",
            "a.test {\n  root * /srv/a\n  @assets path /assets/*\n  file_server @assets\n}\n",
        ),
        (
            "review: hide .well-known is not covered by the dotfile default",
            "a.test {\n  root * /srv/a\n  file_server {\n    hide .well-known\n  }\n}\n",
        ),
        (
            "review: hide a file under .well-known",
            "a.test {\n  root * /srv/a\n  file_server {\n    hide /srv/a/.well-known/.secret\n  }\n}\n",
        ),
        (
            "review 2: file_server with its own matcher inside a handle",
            "a.test {\n  root * /srv/a\n  handle /a/* {\n    file_server /a/public/*\n  }\n}\n",
        ),
        (
            "review 2: hide pattern with ? can cover .well-known",
            "a.test {\n  root * /srv/a\n  file_server {\n    hide .well-know?\n  }\n}\n",
        ),
        (
            "review 2: hide pattern with a bracket class",
            "a.test {\n  root * /srv/a\n  file_server {\n    hide .[w]ell-known\n  }\n}\n",
        ),
        (
            "review 2: two document roots in one site",
            "a.test {\n  handle /a/* {\n    root * /srv/a\n    file_server\n  }\n  handle /b/* {\n    root * /srv/b\n    file_server\n  }\n}\n",
        ),
        (
            "R8-MIG-1 respond",
            "a.test {\n  root * /srv/a\n  respond /health 200\n  file_server\n}\n",
        ),
        (
            "R8-MIG-1 templates",
            "a.test {\n  root * /srv/a\n  templates\n  file_server\n}\n",
        ),
        (
            "R8-MIG-1 unknown directive",
            "a.test {\n  root * /srv/a\n  frobnicate on\n  file_server\n}\n",
        ),
        (
            "R8-MIG-7 rewrite everything",
            "a.test {\n  root * /srv/a\n  rewrite * /index.html\n  file_server\n}\n",
        ),
        (
            "R8-MIG-7 redirect everything on a site with content",
            "a.test {\n  root * /srv/a\n  redir https://b.test{uri}\n  file_server\n}\n",
        ),
        (
            "R8-MIG-7 redirect in front of a proxy with no document root",
            "a.test {\n  redir /backup/* /\n  reverse_proxy localhost:3000\n}\n",
        ),
    ];
    for (label, source) in refused {
        assert_refused(label, source, SourceFormat::Caddy);
    }

    // Hiding only dotfiles is what MiraServe does by default; path-scoped redirects on a site
    // with a document root are closed with 404 routes.
    let closed = "b.test {\n  root * /srv/b\n  redir /backup/* /\n  rewrite /private/* /index.html\n  redir /old /new\n  file_server {\n    hide .git .env\n    precompressed br gzip\n  }\n}\n";
    let kdl = assert_clean("closed redirects", closed, SourceFormat::Caddy)?;
    for pattern in ["/backup/*", "/private/*", "/old"] {
        let at = kdl
            .find(&format!("route \"{pattern}\""))
            .ok_or_else(|| format!("missing closed route {pattern}:\n{kdl}"))?;
        assert!(
            kdl.get(at..)
                .unwrap_or("")
                .lines()
                .nth(1)
                .is_some_and(|l| l.contains("try-files \"=404\"")),
            "{pattern} must answer 404:\n{kdl}"
        );
    }

    // Review 2: a file server scoped by `handle` must not leave the rest of the document root
    // reachable. The scoped route is kept and every other path is closed.
    let scoped = "s.test {\n  root * /srv/s\n  handle /public/* {\n    file_server\n  }\n}\n";
    let kdl = assert_clean("scoped file server", scoped, SourceFormat::Caddy)?;
    assert!(kdl.contains("route \"/public/*\""), "{kdl}");
    let catch_all = kdl.find("route \"/*\"").ok_or_else(|| {
        format!("the document-root fallback must be closed with a catch-all route:\n{kdl}")
    })?;
    assert!(
        kdl.get(catch_all..)
            .unwrap_or("")
            .lines()
            .nth(1)
            .is_some_and(|l| l.contains("try-files \"=404\"")),
        "the catch-all must answer 404:\n{kdl}"
    );
    assert!(
        kdl.find("route \"/public/*\"") < Some(catch_all),
        "the scoped route must be matched before the catch-all:\n{kdl}"
    );
    // A site-wide file server keeps the ordinary document-root behaviour: no catch-all 404.
    let site_wide = "w.test {\n  root * /srv/w\n  file_server\n}\n";
    let kdl = assert_clean("site-wide file server", site_wide, SourceFormat::Caddy)?;
    assert!(!kdl.contains("=404"), "{kdl}");

    // The everyday Caddyfile: tuning, covered headers, a proxy, and a redirect-only www block.
    let typical = "example.com {\n  encode gzip zstd\n  log\n  header Strict-Transport-Security \"max-age=31536000\"\n  header X-Content-Type-Options nosniff\n  reverse_proxy localhost:3000\n}\nwww.example.com {\n  redir https://example.com{uri}\n}\n";
    let kdl = assert_clean("typical Caddyfile", typical, SourceFormat::Caddy)?;
    assert!(kdl.contains("http://localhost:3000"), "{kdl}");
    assert!(
        kdl.contains("preserve-host #true"),
        "Caddy forwards the client's Host by default, which must become preserve-host:\n{kdl}"
    );
    Ok(())
}

#[test]
fn r8_mig_openlitespeed_contexts_and_htaccess_fail_closed() -> TestResult {
    assert_refused(
        "R8-MIG-9 autoLoadHtaccess",
        "docRoot                   /var/www/o\nrewrite  {\n  enable                  1\n  autoLoadHtaccess        1\n}\n",
        SourceFormat::OpenLiteSpeed,
    );
    assert_refused(
        "R8-MIG-1 unknown context option",
        "docRoot                   /var/www/o\ncontext /x/ {\n  frobnicate              1\n}\n",
        SourceFormat::OpenLiteSpeed,
    );
    assert_refused(
        "R8-MIG-7 unknown context type",
        "docRoot                   /var/www/o\ncontext /x/ {\n  type                    frobnicate\n}\n",
        SourceFormat::OpenLiteSpeed,
    );

    let closed = "docRoot                   /var/www/o\ncontext /backup/ {\n  type                    redirect\n  statusCode              302\n  location                /\n}\ncontext /private/ {\n  location                /var/www/o/public-only/\n  allowBrowse             1\n}\n";
    let kdl = assert_clean("closed contexts", closed, SourceFormat::OpenLiteSpeed)?;
    for pattern in ["/backup/*", "/private/*"] {
        let at = kdl
            .find(&format!("route \"{pattern}\""))
            .ok_or_else(|| format!("missing closed route {pattern}:\n{kdl}"))?;
        assert!(
            kdl.get(at..)
                .unwrap_or("")
                .lines()
                .nth(1)
                .is_some_and(|l| l.contains("try-files \"=404\"")),
            "{pattern} must answer 404:\n{kdl}"
        );
    }
    Ok(())
}

/// Review 3: an `https://` pool must stay HTTPS, a pool with Nginx's default `Host` (the pool
/// name) cannot be reproduced, and WebSocket tunnelling is on only where the source enabled it.
#[test]
fn review3_nginx_pool_scheme_pool_host_and_websocket_policy() -> TestResult {
    let with_pool = |location: &str| {
        format!(
            "upstream tls_pool {{ server 10.0.0.5:8443; server 10.0.0.6:8443; }}\nserver {{ listen 80; server_name a.test;\n location / {{ {location} }}\n}}\n"
        )
    };

    let https_pool = with_pool("proxy_set_header Host $host; proxy_pass https://tls_pool;");
    let kdl = assert_clean("https pool", &https_pool, SourceFormat::Nginx)?;
    assert!(
        kdl.contains("upstream \"https://10.0.0.5:8443\"")
            && kdl.contains("upstream \"https://10.0.0.6:8443\""),
        "an `https://` pool must be emitted as HTTPS members:\n{kdl}"
    );
    assert!(
        !kdl.contains("http://10.0.0."),
        "a TLS pool must never be downgraded to plaintext:\n{kdl}"
    );

    let plain_pool = with_pool("proxy_set_header Host $host; proxy_pass http://tls_pool;");
    let kdl = assert_clean("http pool", &plain_pool, SourceFormat::Nginx)?;
    assert!(kdl.contains("upstream \"http://10.0.0.5:8443\""), "{kdl}");

    assert_refused(
        "pool with the default Host (the pool name)",
        &with_pool("proxy_pass https://tls_pool;"),
        SourceFormat::Nginx,
    );
    assert_refused(
        "pool with an explicit $proxy_host",
        &with_pool("proxy_set_header Host $proxy_host; proxy_pass https://tls_pool;"),
        SourceFormat::Nginx,
    );

    // WebSocket policy. Nginx forwards an upgrade only when BOTH headers are set explicitly.
    let no_rules = nginx_server("location /api/ { proxy_pass http://127.0.0.1:9000; }");
    let kdl = assert_clean("no upgrade rules", &no_rules, SourceFormat::Nginx)?;
    assert!(
        kdl.contains("allow-upgrades #false"),
        "without the Upgrade/Connection pair the source never tunnels WebSockets:\n{kdl}"
    );
    let suppressed = nginx_server(
        "location /api/ { proxy_http_version 1.1; proxy_set_header Connection \"\"; proxy_pass http://127.0.0.1:9000; }",
    );
    let kdl = assert_clean("Connection cleared", &suppressed, SourceFormat::Nginx)?;
    assert!(kdl.contains("allow-upgrades #false"), "{kdl}");
    let upgrade_only = nginx_server(
        "location /api/ { proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection \"\"; proxy_pass http://127.0.0.1:9000; }",
    );
    let kdl = assert_clean(
        "Upgrade without Connection",
        &upgrade_only,
        SourceFormat::Nginx,
    )?;
    assert!(kdl.contains("allow-upgrades #false"), "{kdl}");
    let enabled = nginx_server(
        "location /ws/ { proxy_http_version 1.1; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection \"upgrade\"; proxy_pass http://127.0.0.1:9000; }",
    );
    let kdl = assert_clean("WebSocket enabled", &enabled, SourceFormat::Nginx)?;
    assert!(
        !kdl.contains("allow-upgrades"),
        "a location that sets the Upgrade/Connection pair keeps WebSocket tunnelling:\n{kdl}"
    );

    // Apache `ProxyPass http://` does not tunnel WebSockets either.
    let apache = apache_vhost("ProxyPass /api/ http://127.0.0.1:3000/api/");
    let kdl = assert_clean("apache proxy", &apache, SourceFormat::Apache)?;
    assert!(kdl.contains("allow-upgrades #false"), "{kdl}");
    Ok(())
}

/// Review 3: Caddy serves file contents only through `file_server`, matches a path without `*`
/// exactly, and picks the transport and default `Host` from the upstream address.
#[test]
#[allow(clippy::too_many_lines)]
fn review3_caddy_file_server_exact_matchers_and_https_upstreams() -> TestResult {
    let refused: &[(&str, &str)] = &[
        (
            "php_fastcgi without file_server would start serving static files",
            "a.test {\n  root * /srv/a\n  php_fastcgi unix//run/php/php-fpm.sock\n}\n",
        ),
        (
            "site-wide try_files without file_server",
            "a.test {\n  root * /srv/a\n  try_files {path} /index.html\n}\n",
        ),
        (
            "try_files in a handle without file_server",
            "a.test {\n  root * /srv/a\n  handle /app/* {\n    try_files {path} /app/index.html\n  }\n}\n",
        ),
        (
            "glob matcher that is neither exact nor a /prefix/* pattern",
            "a.test {\n  root * /srv/a\n  handle /foo* {\n    file_server\n  }\n}\n",
        ),
        (
            "HTTPS upstream with the version-dependent default Host",
            "a.test {\n  reverse_proxy https://backend.internal:8443\n}\n",
        ),
        (
            "HTTPS upstream in a block without header_up Host",
            "a.test {\n  reverse_proxy https://backend.internal:8443 {\n    lb_policy round_robin\n  }\n}\n",
        ),
        (
            "scheme-less upstream on port 443 is ambiguous",
            "a.test {\n  reverse_proxy backend.internal:443\n}\n",
        ),
        (
            "h2c upstream cannot be reproduced",
            "a.test {\n  reverse_proxy h2c://127.0.0.1:9000\n}\n",
        ),
        (
            "header_up Host with an arbitrary value",
            "a.test {\n  reverse_proxy https://backend.internal:8443 {\n    header_up Host other.internal\n  }\n}\n",
        ),
    ];
    for (label, source) in refused {
        assert_refused(label, source, SourceFormat::Caddy);
    }

    // The standard PHP site pairs `php_fastcgi` with `file_server`.
    let php =
        "p.test {\n  root * /srv/p\n  php_fastcgi unix//run/php/php-fpm.sock\n  file_server\n}\n";
    let kdl = assert_clean("php_fastcgi with file_server", php, SourceFormat::Caddy)?;
    assert!(kdl.contains("route \"*.php\""), "{kdl}");

    // `handle /` is the homepage only. It must not become `/*`, and the rest of the document
    // root must stay unreachable.
    let homepage = "h.test {\n  root * /srv/h\n  handle / {\n    file_server\n  }\n}\n";
    let kdl = assert_clean("exact homepage handle", homepage, SourceFormat::Caddy)?;
    assert!(
        kdl.contains("route \"/\" {"),
        "`handle /` must stay an exact route:\n{kdl}"
    );
    let catch_all = kdl
        .find("route \"/*\"")
        .ok_or_else(|| format!("the rest of the root must be closed:\n{kdl}"))?;
    assert!(
        kdl.get(catch_all..)
            .unwrap_or("")
            .lines()
            .nth(1)
            .is_some_and(|l| l.contains("try-files \"=404\"")),
        "the catch-all must answer 404, not serve files:\n{kdl}"
    );

    // An exact proxy matcher stays exact.
    let exact_proxy = "e.test {\n  handle /admin {\n    reverse_proxy 127.0.0.1:9000\n  }\n  reverse_proxy /api 127.0.0.1:9001\n  reverse_proxy /v1/* 127.0.0.1:9002\n}\n";
    let kdl = assert_clean("exact proxy matchers", exact_proxy, SourceFormat::Caddy)?;
    assert!(kdl.contains("route \"/admin\" {"), "{kdl}");
    assert!(kdl.contains("route \"/api\" {"), "{kdl}");
    assert!(kdl.contains("route \"/v1/*\" {"), "{kdl}");
    assert!(
        !kdl.contains("route \"/admin/*\"") && !kdl.contains("route \"/api/*\""),
        "exact matchers must not be widened to prefixes:\n{kdl}"
    );

    // HTTPS upstreams with an explicit Host.
    let upstream_host = "u.test {\n  reverse_proxy https://backend.internal:8443 {\n    header_up Host {upstream_hostport}\n  }\n}\n";
    let kdl = assert_clean(
        "https upstream, upstream host",
        upstream_host,
        SourceFormat::Caddy,
    )?;
    assert!(
        kdl.contains("upstream \"https://backend.internal:8443\""),
        "{kdl}"
    );
    assert!(
        !kdl.contains("preserve-host"),
        "`header_up Host {{upstream_hostport}}` is MiraServe's default Host:\n{kdl}"
    );
    let client_host = "c.test {\n  reverse_proxy https://backend.internal:443 {\n    header_up Host {host}\n  }\n}\n";
    let kdl = assert_clean(
        "https upstream, client host",
        client_host,
        SourceFormat::Caddy,
    )?;
    assert!(
        kdl.contains("upstream \"https://backend.internal:443\""),
        "an explicit https:// upstream must stay HTTPS:\n{kdl}"
    );
    assert!(kdl.contains("preserve-host #true"), "{kdl}");
    Ok(())
}

/// Review 4: Caddy matchers nest, a scoped `root` is not the site root, a scheme-less upstream on
/// port 443 has no knowable transport, and `$connection_upgrade` is only what its `map` says.
#[test]
#[allow(clippy::too_many_lines)]
fn review4_caddy_nested_matchers_scoped_root_port_443_and_nginx_upgrade_map() -> TestResult {
    // An inner matcher broader than its `handle` must not widen the route.
    let broader = "a.test {\n  handle /api/* {\n    reverse_proxy /* 127.0.0.1:9000\n  }\n}\n";
    let kdl = assert_clean(
        "inner matcher broader than handle",
        broader,
        SourceFormat::Caddy,
    )?;
    assert!(kdl.contains("route \"/api/*\" {"), "{kdl}");
    assert!(
        !kdl.contains("route \"/*\""),
        "the backend must stay confined to the handle's path:\n{kdl}"
    );
    // A narrower inner matcher narrows it.
    let narrower =
        "a.test {\n  handle /api/* {\n    reverse_proxy /api/v1/* 127.0.0.1:9000\n  }\n}\n";
    let kdl = assert_clean(
        "inner matcher narrower than handle",
        narrower,
        SourceFormat::Caddy,
    )?;
    assert!(kdl.contains("route \"/api/v1/*\" {"), "{kdl}");
    assert!(!kdl.contains("route \"/api/*\""), "{kdl}");
    // Disjoint matchers never match: no route for that backend.
    let disjoint = "a.test {\n  handle /api/* {\n    reverse_proxy /admin/* 127.0.0.1:9000\n  }\n  reverse_proxy /ok/* 127.0.0.1:9001\n}\n";
    let kdl = assert_clean("disjoint matchers", disjoint, SourceFormat::Caddy)?;
    assert!(
        !kdl.contains("127.0.0.1:9000"),
        "a backend that Caddy never reaches must not get a route:\n{kdl}"
    );
    assert!(kdl.contains("route \"/ok/*\" {"), "{kdl}");

    let refused: &[(&str, &str)] = &[
        (
            "root inside a path-scoped handle with a fallback file_server",
            "a.test {\n  handle /app/* {\n    root * /srv/app\n    file_server\n  }\n  file_server\n}\n",
        ),
        (
            "root with a path matcher",
            "a.test {\n  root /blog/* /srv/blog\n  file_server\n}\n",
        ),
        (
            "scheme-less upstream on port 443",
            "a.test {\n  reverse_proxy backend.internal:443 {\n    header_up Host {upstream_hostport}\n  }\n}\n",
        ),
    ];
    for (label, source) in refused {
        assert_refused(label, source, SourceFormat::Caddy);
    }
    // With the scheme written out, port 443 over plain HTTP is taken at its word.
    let plain_443 = "a.test {\n  reverse_proxy http://backend.internal:443\n}\n";
    let kdl = assert_clean("explicit http on 443", plain_443, SourceFormat::Caddy)?;
    assert!(
        kdl.contains("upstream \"http://backend.internal:443\""),
        "{kdl}"
    );

    // Nginx `$connection_upgrade` is defined by a `map`. Only the stock map means "upgrade when
    // the client asks".
    let ws = |map: &str| {
        format!(
            "{map}\nserver {{ listen 80; server_name a.test;\n location /ws/ {{ proxy_http_version 1.1; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection $connection_upgrade; proxy_pass http://127.0.0.1:9000; }}\n}}\n"
        )
    };
    let stock = ws("map $http_upgrade $connection_upgrade {\n default upgrade;\n '' close;\n}");
    let kdl = assert_clean("stock upgrade map", &stock, SourceFormat::Nginx)?;
    assert!(
        !kdl.contains("allow-upgrades"),
        "the stock map keeps WebSocket tunnelling on:\n{kdl}"
    );
    assert_refused(
        "upgrade map keyed on the host",
        &ws("map $host $connection_upgrade {\n default close;\n ws.a.test upgrade;\n}"),
        SourceFormat::Nginx,
    );
    assert_refused(
        "upgrade map with an extra conditional entry",
        &ws(
            "map $http_upgrade $connection_upgrade {\n default upgrade;\n '' close;\n websocket-admin close;\n}",
        ),
        SourceFormat::Nginx,
    );
    assert_refused(
        "$connection_upgrade with no map the importer can read",
        &ws(""),
        SourceFormat::Nginx,
    );
    assert_refused(
        "two maps defining $connection_upgrade",
        &ws(
            "map $http_upgrade $connection_upgrade {\n default upgrade;\n '' close;\n}\nmap $host $connection_upgrade {\n default upgrade;\n}",
        ),
        SourceFormat::Nginx,
    );
    Ok(())
}

//! Full-stack Milestone 2 end-to-end test:
//! Live HTTPS WordPress site (`preset "wordpress-hardened"` + `try-files` + pure-Rust FastCGI),
//! verifying permalink rewrite -> PHP-FPM execution, upload webshell & xmlrpc.php blocking
//! before PHP-FPM, dotfile denial, and `wp-login.php` GCRA rate limiting.

use std::collections::HashMap;
use std::fs;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::header::{HOST, RETRY_AFTER};
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper_util::rt::TokioIo;
use miraserve_config::{ConfigStore, parse_kdl};
use miraserve_core::{ListenerKind, MiraServeServer, ServerOptions};
use miraserve_fastcgi::protocol::{
    EndRequestBody, RecordType, decode_params, read_record, write_record, write_stream_records,
};
use miraserve_tls::build_crypto_provider;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::AsyncWriteExt as _;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Result<Self, std::io::Error> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "miraserve-wp-e2e-{tag}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn reserve_free_port() -> Result<u16, std::io::Error> {
    let sock = StdTcpListener::bind("127.0.0.1:0")?;
    Ok(sock.local_addr()?.port())
}

async fn spawn_mock_wordpress_fpm(
    hits: Arc<AtomicUsize>,
) -> Result<(SocketAddr, tokio::task::AbortHandle), std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let hits_c = Arc::clone(&hits);
            tokio::spawn(async move {
                let mut raw_params = Vec::new();
                let req_id;
                loop {
                    let Ok(rec) = read_record(&mut stream).await else {
                        return;
                    };
                    match rec.record_type {
                        RecordType::Params if !rec.content.is_empty() => {
                            raw_params.extend_from_slice(&rec.content);
                        }
                        RecordType::Stdin if rec.content.is_empty() => {
                            req_id = rec.request_id;
                            break;
                        }
                        _ => {}
                    }
                }
                hits_c.fetch_add(1, Ordering::AcqRel);
                let params: HashMap<String, String> = decode_params(&raw_params)
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                let script = params.get("SCRIPT_NAME").map_or("", String::as_str);
                let uri = params.get("REQUEST_URI").map_or("", String::as_str);
                let port = params.get("SERVER_PORT").map_or("", String::as_str);
                let method = params.get("REQUEST_METHOD").map_or("", String::as_str);
                let payload = format!(
                    "Content-Type: text/html\r\n\r\nwordpress-fpm|script={script}|uri={uri}|port={port}|method={method}"
                );
                let _ = write_stream_records(
                    &mut stream,
                    RecordType::Stdout,
                    req_id,
                    payload.as_bytes(),
                    true,
                )
                .await;
                let end = EndRequestBody {
                    app_status: 0,
                    protocol_status: 0,
                }
                .encode();
                let _ = write_record(&mut stream, RecordType::EndRequest, req_id, &end).await;
                let _ = stream.flush().await;
            });
        }
    });

    Ok((addr, task.abort_handle()))
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn live_wordpress_hardened_fastcgi_and_rate_limiting() -> TestResult {
    let docroot = TempDir::new("docroot")?;
    fs::write(docroot.path.join("style.css"), b"body { color: #111; }")?;
    fs::write(
        docroot.path.join("index.php"),
        b"<?php // TOP_SECRET_PHP_SOURCE router",
    )?;
    fs::create_dir_all(docroot.path.join("sub"))?;
    fs::write(
        docroot.path.join("sub/index.php"),
        b"<?php // TOP_SECRET_PHP_SOURCE sub",
    )?;
    fs::write(docroot.path.join("wp-login.php"), b"<?php // login")?;
    fs::write(
        docroot.path.join("secret-app.php"),
        b"<?php $db = 'TOP_SECRET_PHP_SOURCE';",
    )?;
    fs::create_dir_all(docroot.path.join("uploads"))?;
    fs::write(docroot.path.join("uploads/photo.jpg"), b"JPEGDATA")?;
    // R2-FCGI-1: Real WordPress `/wp-admin/index.php` AND attacker-uploaded `/wp-content/uploads/index.php`
    fs::create_dir_all(docroot.path.join("wp-admin"))?;
    fs::write(
        docroot.path.join("wp-admin/index.php"),
        b"<?php /* TOP_SECRET_PHP_SOURCE */ echo 'wp-admin';",
    )?;
    fs::create_dir_all(docroot.path.join("wp-content/uploads"))?;
    fs::write(
        docroot.path.join("wp-content/uploads/index.php"),
        b"<?php /* TOP_SECRET_PHP_SOURCE */ system($_GET['c']);",
    )?;
    fs::write(docroot.path.join(".env"), b"WP_SECRET=nope")?;
    fs::write(
        docroot.path.join("wp-config.php"),
        b"<?php define('DB_PASSWORD', 'secret');",
    )?;

    let fpm_hits = Arc::new(AtomicUsize::new(0));
    let (fpm_addr, fpm_abort) = spawn_mock_wordpress_fpm(Arc::clone(&fpm_hits)).await?;
    let tls_port = reserve_free_port()?;
    let root_str = docroot.path.to_string_lossy().replace('\\', "/");

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:{tls_port}" protocols="h2,h1"
    tls {{
        min-version "1.3"
        pqc-hybrid #true
    }}
}}

site "wp.example.test" {{
    preset "wordpress-hardened"
    security-headers "strict"
    root "{root_str}"

    route "*.php" {{
        fastcgi-pass "tcp://127.0.0.1:{fpm_port}"
    }}

    route "/*" {{
        try-files "{{path}}" "{{path}}/" "/index.php?{{query}}"
    }}
}}

site "index-php.example.test" {{
    security-headers "strict"
    root "{root_str}"

    route "*.php" {{
        fastcgi-pass "tcp://127.0.0.1:{fpm_port}"
    }}

    route "/*" {{
        static {{
            index "index.php"
        }}
    }}
}}

site "static-only-index-php.example.test" {{
    security-headers "strict"
    root "{root_str}"

    route "/*" {{
        static {{
            index "index.php"
        }}
    }}
}}
"#,
        fpm_port = fpm_addr.port()
    );

    let (cfg, report) = parse_kdl("wp.kdl", &kdl)?;
    assert!(
        report.warnings.iter().all(|w| w.code == "W015"),
        "unexpected warnings: {:?}",
        report.warnings
    );

    let server = MiraServeServer::start(
        Arc::new(ConfigStore::new(cfg)),
        ServerOptions {
            dev_tls: true,
            ..ServerOptions::default()
        },
    )
    .await?;

    let https_addr = server
        .bound_listeners()
        .iter()
        .find(|b| b.kind == ListenerKind::HttpsTcp)
        .ok_or("missing HTTPS listener")?
        .local_addr;
    let dev_pem = server.dev_cert_pem().ok_or("missing dev cert PEM")?;

    let mut roots = RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(dev_pem.as_bytes()).collect::<Result<_, _>>()?;
    let (added, _) = roots.add_parsable_certificates(certs);
    assert_eq!(added, 1);

    let mut cli_tls = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cli_tls.alpn_protocols = vec![b"http/1.1".to_vec()];

    let cli_tls = Arc::new(cli_tls);
    let tcp = TcpStream::connect(https_addr).await?;
    let tls_stream = TlsConnector::from(Arc::clone(&cli_tls))
        .connect(ServerName::try_from("wp.example.test")?, tcp)
        .await?;
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_stream)).await?;
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    // 1. Static asset hits cap-std directly (PHP-FPM untouched)
    let css_resp = sender
        .send_request(
            Request::builder()
                .uri("/style.css")
                .header(HOST, "wp.example.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(css_resp.status(), StatusCode::OK);
    assert_eq!(
        css_resp.into_body().collect().await?.to_bytes().as_ref(),
        b"body { color: #111; }"
    );
    assert_eq!(fpm_hits.load(Ordering::Acquire), 0);

    // 2. Attack paths MUST be blocked by wordpress-hardened / PATH-6 BEFORE PHP-FPM!
    for (evil_path, expected_status) in [
        ("/xmlrpc.php", StatusCode::FORBIDDEN),
        (
            "/wp-content/uploads/2026/webshell.php",
            StatusCode::FORBIDDEN,
        ),
        (
            "//wp-content/uploads/2026/webshell.php",
            StatusCode::FORBIDDEN,
        ),
        (
            "/wp-content//uploads/2026/webshell.php",
            StatusCode::FORBIDDEN,
        ),
        ("/blog/wp-content/uploads/shell.php", StatusCode::FORBIDDEN),
        ("/wp-includes/evil.php", StatusCode::FORBIDDEN),
        ("/uploads/photo.jpg/evil.php", StatusCode::NOT_FOUND),
        ("/.env", StatusCode::NOT_FOUND),
        ("/wp-config.php", StatusCode::NOT_FOUND),
        ("/wp-config.php/", StatusCode::NOT_FOUND),
        ("/secret-app.php%3Ffoo=1", StatusCode::NOT_FOUND),
        ("/.well-known/../wp-config.php", StatusCode::BAD_REQUEST),
    ] {
        let resp = sender
            .send_request(
                Request::builder()
                    .uri(evil_path)
                    .header(HOST, "wp.example.test")
                    .body(Empty::<Bytes>::new())?,
            )
            .await?;
        let status = resp.status();
        let body = resp.into_body().collect().await?.to_bytes();
        assert_eq!(status, expected_status, "unexpected status for {evil_path}");
        assert!(
            !body.windows(21).any(|w| w == b"TOP_SECRET_PHP_SOURCE"),
            "PHP source leaked on {evil_path}!"
        );
    }
    assert_eq!(
        fpm_hits.load(Ordering::Acquire),
        0,
        "blocked WordPress exploits must NEVER invoke PHP-FPM"
    );

    // 3. WordPress pretty permalink (GET and POST REST API `FCGI-1`) hits try-files -> *.php FastCGI
    //    with accurate listener `SERVER_PORT` (`FCGI-5`)!
    let expected_port = https_addr.port();
    let post_resp = sender
        .send_request(
            Request::builder()
                .uri("/2026/my-article?preview=true")
                .header(HOST, "wp.example.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(post_resp.status(), StatusCode::OK);
    let post_body = post_resp.into_body().collect().await?.to_bytes();
    assert_eq!(
        String::from_utf8_lossy(&post_body),
        format!(
            "wordpress-fpm|script=/index.php|uri=/2026/my-article?preview=true|port={expected_port}|method=GET"
        )
    );
    assert_eq!(fpm_hits.load(Ordering::Acquire), 1);

    let rest_post = sender
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("/wp-json/wp/v2/posts")
                .header(HOST, "wp.example.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(rest_post.status(), StatusCode::OK);
    let rest_body = rest_post.into_body().collect().await?.to_bytes();
    assert_eq!(
        String::from_utf8_lossy(&rest_body),
        format!(
            "wordpress-fpm|script=/index.php|uri=/wp-json/wp/v2/posts|port={expected_port}|method=POST"
        )
    );
    assert_eq!(fpm_hits.load(Ordering::Acquire), 2);

    // 3b. R2-FCGI-1: `GET /wp-admin/` MUST execute `/wp-admin/index.php` via FastCGI (NOT root
    //     `/index.php` and NEVER static PHP source!), while `GET /wp-content/uploads/` with an
    //     uploaded `index.php` MUST STILL be blocked 403 by `wordpress-hardened` preset!
    let wp_admin_resp = sender
        .send_request(
            Request::builder()
                .uri("/wp-admin/?page=dashboard")
                .header(HOST, "wp.example.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(wp_admin_resp.status(), StatusCode::OK);
    let wp_admin_body = wp_admin_resp.into_body().collect().await?.to_bytes();
    assert_eq!(
        String::from_utf8_lossy(&wp_admin_body),
        format!(
            "wordpress-fpm|script=/wp-admin/index.php|uri=/wp-admin/?page=dashboard|port={expected_port}|method=GET"
        )
    );
    assert_eq!(fpm_hits.load(Ordering::Acquire), 3);

    let uploads_dir_resp = sender
        .send_request(
            Request::builder()
                .uri("/wp-content/uploads/")
                .header(HOST, "wp.example.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(
        uploads_dir_resp.status(),
        StatusCode::FORBIDDEN,
        "uploaded /wp-content/uploads/index.php must STILL be blocked 403 by wordpress-hardened"
    );
    assert_eq!(
        fpm_hits.load(Ordering::Acquire),
        3,
        "blocked uploads/index.php must never invoke PHP-FPM"
    );

    // 3c. R3-HTTP-3: `GET /wp-admin` without trailing slash returns 301 -> `/wp-admin/`!
    let wp_admin_noslash = sender
        .send_request(
            Request::builder()
                .uri("/wp-admin?page=settings")
                .header(HOST, "wp.example.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(wp_admin_noslash.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(
        wp_admin_noslash
            .headers()
            .get(http::header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/wp-admin/?page=settings")
    );

    // 3d. R2-FCGI-1: `POST /wp-admin/` executes `/wp-admin/index.php` via PHP-FPM, while
    //     `POST /wp-content/uploads/` is STILL blocked 403 by `wordpress-hardened`!
    let wp_admin_post = sender
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("/wp-admin/?action=save")
                .header(HOST, "wp.example.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(wp_admin_post.status(), StatusCode::OK);
    let wp_admin_post_body = wp_admin_post.into_body().collect().await?.to_bytes();
    assert_eq!(
        String::from_utf8_lossy(&wp_admin_post_body),
        format!(
            "wordpress-fpm|script=/wp-admin/index.php|uri=/wp-admin/?action=save|port={expected_port}|method=POST"
        )
    );
    assert_eq!(fpm_hits.load(Ordering::Acquire), 4);

    let uploads_post_resp = sender
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("/wp-content/uploads/")
                .header(HOST, "wp.example.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(uploads_post_resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(fpm_hits.load(Ordering::Acquire), 4);

    // 3e. R2-HTTP-3: Encoded `%2F` on filesystem/FastCGI/try-files route is STILL rejected 400!
    let encoded_slash_wp = sender
        .send_request(
            Request::builder()
                .uri("/wp-admin%2Findex.php")
                .header(HOST, "wp.example.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(encoded_slash_wp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(fpm_hits.load(Ordering::Acquire), 4);

    // 4. Rapid wp-login.php brute-force triggers GCRA 429 Too Many Requests with Retry-After!
    for _ in 0..5 {
        let ok_login = sender
            .send_request(
                Request::builder()
                    .method(Method::POST)
                    .uri("/wp-login.php")
                    .header(HOST, "wp.example.test")
                    .body(Empty::<Bytes>::new())?,
            )
            .await?;
        assert_eq!(ok_login.status(), StatusCode::OK);
    }
    let throttled = sender
        .send_request(
            Request::builder()
                .method(Method::POST)
                .uri("/wp-login.php")
                .header(HOST, "wp.example.test")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(throttled.headers().contains_key(RETRY_AFTER));

    // 5. Codex Recheck Finding 1 & Codex G9 (Live HTTPS):
    //    - On a site WITH a `*.php` FastCGI route, `static { index "index.php" }` uses the
    //      unified directory-index resolver to execute `index.php` via PHP-FPM on `/` and `/sub/`
    //      (and 301 redirects `/sub` -> `/sub/`), NEVER leaking `TOP_SECRET_PHP_SOURCE`.
    //    - On a static-only site WITHOUT a `*.php` FastCGI route, `static { index "index.php" }`
    //      rejects `/`, `/sub`, and `/sub/` with 404 Not Found, NEVER leaking PHP source.
    let tcp_idx = TcpStream::connect(https_addr).await?;
    let tls_idx = TlsConnector::from(Arc::clone(&cli_tls))
        .connect(ServerName::try_from("index-php.example.test")?, tcp_idx)
        .await?;
    let (mut idx_sender, idx_conn) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_idx)).await?;
    let idx_conn_task = tokio::spawn(async move {
        let _ = idx_conn.await;
    });
    for (dir_path, expected_status) in [
        ("/", StatusCode::OK),
        ("/sub", StatusCode::MOVED_PERMANENTLY),
        ("/sub/", StatusCode::OK),
    ] {
        let resp = idx_sender
            .send_request(
                Request::builder()
                    .uri(dir_path)
                    .header(HOST, "index-php.example.test")
                    .body(Empty::<Bytes>::new())?,
            )
            .await?;
        let status = resp.status();
        let body = resp.into_body().collect().await?.to_bytes();
        assert_eq!(
            status, expected_status,
            "index-php.example.test unexpected status for {dir_path}"
        );
        assert!(
            !body.windows(21).any(|w| w == b"TOP_SECRET_PHP_SOURCE"),
            "PHP source leaked via directory index on {dir_path}!"
        );
    }
    idx_conn_task.abort();

    let tcp_static_only = TcpStream::connect(https_addr).await?;
    let tls_static_only = TlsConnector::from(Arc::clone(&cli_tls))
        .connect(
            ServerName::try_from("static-only-index-php.example.test")?,
            tcp_static_only,
        )
        .await?;
    let (mut so_sender, so_conn) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_static_only)).await?;
    let so_conn_task = tokio::spawn(async move {
        let _ = so_conn.await;
    });
    for dir_path in ["/", "/sub", "/sub/"] {
        let resp = so_sender
            .send_request(
                Request::builder()
                    .uri(dir_path)
                    .header(HOST, "static-only-index-php.example.test")
                    .body(Empty::<Bytes>::new())?,
            )
            .await?;
        let status = resp.status();
        let body = resp.into_body().collect().await?.to_bytes();
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "static-only index.php route must reject {dir_path} instead of leaking PHP source"
        );
        assert!(
            !body.windows(21).any(|w| w == b"TOP_SECRET_PHP_SOURCE"),
            "PHP source leaked via static-only directory index on {dir_path}!"
        );
    }
    so_conn_task.abort();

    conn_task.abort();
    server.shutdown().await;
    fpm_abort.abort();
    Ok(())
}

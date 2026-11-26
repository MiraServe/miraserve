//! Byte-for-byte parity ORACLE test for the opt-in static file cache (`file-cache "<window>"`)
//! against all post-review changes (0.1.5):
//! - Per-request HTTP/2 execution (`Spawned` and `InTaskExec` via `test-h2-hooks`, `RootReadPolicy`)
//! - Per-worker `SO_REUSEPORT` loops (`workers 2` on Linux)
//! - Single-shot `HeaderMap` sizing and Markdown budget
//! - Borrowed canonical paths and inline access-log strings
//! - Precompressed siblings (`.zst`, `.br`, `.gz`) and on-the-fly compression
//! - Status-conditioned site and route `headers` rules (including `try-files` fallback route ownership)
//! - Conditional `304`, `Range`/`If-Range` `206`/`416`, `HEAD` (including `HEAD`+`Range`)
//! - Large-file bound (`> 256 KiB` never cached, including large base with small precompressed sibling)
//! - Credential-file protection (dotfiles and published `basic-auth` users file never cached)
//! - Documented window visibility after on-disk mutation (Linux stores via `openat2`; macOS stores nothing)

use std::fs;
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::header::{
    ACCEPT, ACCEPT_ENCODING, CONTENT_ENCODING, DATE, ETAG, HOST, IF_MODIFIED_SINCE, IF_NONE_MATCH,
    IF_RANGE, LAST_MODIFIED, RANGE,
};
use http::{HeaderValue, Method, Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper::client::conn::{http1 as h1_client, http2 as h2_client};
use hyper_util::rt::{TokioExecutor, TokioIo};
use miraserve_config::{ConfigStore, parse_kdl};
use miraserve_core::{CoreError, ListenerKind, MiraServeServer, RunningServer, ServerOptions};
use miraserve_tls::build_crypto_provider;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Maximum file size eligible for in-memory serving and `FileCache` admission (`256 KiB`).
const FILE_CACHE_SIZE_BOUND_BYTES: usize = 256 * 1024;

/// Serializes tests in this binary because `test_h2_exec_override_guard` and published credential
/// files are process-wide.
fn oracle_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Result<Self, std::io::Error> {
        static SEQ: AtomicUsize = AtomicUsize::new(1);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "miraserve-fcache-oracle-{tag}-{}-{}-{nanos}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn kdl_str(&self) -> String {
        self.path.to_string_lossy().replace('\\', "/")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn reserve_free_port() -> Result<u16, std::io::Error> {
    for _ in 0..64 {
        let tcp = StdTcpListener::bind("127.0.0.1:0")?;
        let port = tcp.local_addr()?.port();
        if StdUdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return Ok(port);
        }
    }
    Err(std::io::Error::new(
        ErrorKind::AddrInUse,
        "failed to reserve a free 127.0.0.1 TCP+UDP port",
    ))
}

async fn start_server_retrying<F>(
    mut make_kdl: F,
) -> Result<(RunningServer, SocketAddr), Box<dyn std::error::Error>>
where
    F: FnMut(u16) -> String,
{
    let mut last_err: Option<CoreError> = None;
    for _ in 0..16 {
        let port = reserve_free_port()?;
        let kdl = make_kdl(port);
        let (cfg, _) = parse_kdl("file-cache-oracle.kdl", &kdl)?;
        match MiraServeServer::start(
            Arc::new(ConfigStore::new(cfg)),
            ServerOptions {
                dev_tls: true,
                ..ServerOptions::default()
            },
        )
        .await
        {
            Ok(server) => {
                let https_addr = server
                    .bound_listeners()
                    .iter()
                    .find(|b| b.kind == ListenerKind::HttpsTcp)
                    .ok_or("missing HttpsTcp listener")?
                    .local_addr;
                return Ok((server, https_addr));
            }
            Err(CoreError::Bind { source, addr }) if source.kind() == ErrorKind::AddrInUse => {
                last_err = Some(CoreError::Bind { addr, source });
            }
            Err(err) => return Err(err.into()),
        }
    }
    Err(last_err.map_or_else(|| "exhausted bind retries".into(), Into::into))
}

fn build_roots(cert_pem: &str) -> Result<RootCertStore, Box<dyn std::error::Error>> {
    let mut roots = RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert_pem.as_bytes()).collect::<Result<_, _>>()?;
    let (added, _) = roots.add_parsable_certificates(certs);
    assert_eq!(added, 1);
    Ok(roots)
}

/// Equal-length hostnames (20 bytes each) so even generated error pages that interpolate the
/// requested hostname have identical `Content-Length` across cached and uncached sites.
const CACHED_HOST: &str = "cached01.oracle.test";
const SHORT_WIN_HOST: &str = "shortwin.oracle.test";
const UNCACHED_HOST: &str = "nocache1.oracle.test";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CacheExpectation {
    /// On platforms where `FileCache` admits entries (`openat2` available), the second request
    /// to the cached site must record a cache hit (`hits_after == hits_before + 1`).
    HitOnSecond,
    /// Must never hit or fill `FileCache` (e.g. `Range`, `POST`, `404`, `301`, Markdown, `> 256 KiB`,
    /// credential files).
    Bypass,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CapturedResponse {
    status: StatusCode,
    /// Ordered headers excluding `Date` and `X-Request-Id` (and with the random 22-char CSP nonce
    /// normalized on generated `4xx`/`5xx` error responses only).
    headers: Vec<(String, Vec<u8>)>,
    has_request_id: bool,
    body: Vec<u8>,
}

impl CapturedResponse {
    fn header_str(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .and_then(|(_, v)| std::str::from_utf8(v).ok())
    }
}

/// Normalizes ONLY the per-request random CSP nonce on generated `4xx`/`5xx` error responses while
/// asserting it is a canonical 128-bit `URL_SAFE_NO_PAD` Base64 encoding (22 base64url chars with
/// the 4 trailing pad bits zeroed, i.e. last char in `A|Q|g|w`).
fn normalize_error_csp(raw: &[u8]) -> Result<Vec<u8>, String> {
    let s = std::str::from_utf8(raw).map_err(|e| format!("non-utf8 error CSP: {e}"))?;
    let Some((prefix, rest)) = s.split_once("'nonce-") else {
        return Err(format!("missing CSP nonce in error CSP header: {s:?}"));
    };
    let Some((nonce, suffix)) = rest.split_once('\'') else {
        return Err(format!("unterminated CSP nonce in {s:?}"));
    };
    let bytes = nonce.as_bytes();
    if bytes.len() != 22 {
        return Err(format!(
            "unexpected CSP nonce length {}: {nonce:?}",
            bytes.len()
        ));
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
    {
        return Err(format!("non-base64url character in CSP nonce: {nonce:?}"));
    }
    if !matches!(bytes.last().copied(), Some(b'A' | b'Q' | b'g' | b'w')) {
        return Err(format!(
            "non-zero trailing base64url pad bits in 128-bit CSP nonce: {nonce:?}"
        ));
    }
    Ok(format!("{prefix}'nonce-<NONCE>'{suffix}").into_bytes())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Proto {
    H1,
    H2,
}

async fn send_request(
    addr: SocketAddr,
    roots: &RootCertStore,
    proto: Proto,
    host: &str,
    method: Method,
    uri: &str,
    extra_headers: &[(http::HeaderName, HeaderValue)],
) -> Result<CapturedResponse, Box<dyn std::error::Error>> {
    let mut tls_cfg = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    tls_cfg.alpn_protocols = match proto {
        Proto::H1 => vec![b"http/1.1".to_vec()],
        Proto::H2 => vec![b"h2".to_vec()],
    };

    let tcp = TcpStream::connect(addr).await?;
    let tls = TlsConnector::from(Arc::new(tls_cfg))
        .connect(ServerName::try_from(host.to_owned())?, tcp)
        .await?;

    let mut builder = Request::builder().method(method);
    if proto == Proto::H2 {
        builder = builder.uri(format!("https://{host}{uri}"));
    } else {
        builder = builder.uri(uri).header(HOST, host);
    }
    for (k, v) in extra_headers {
        builder = builder.header(k.clone(), v.clone());
    }
    let req = builder.body(Empty::<Bytes>::new())?;

    let resp = match proto {
        Proto::H1 => {
            let (mut sender, conn) = h1_client::handshake(TokioIo::new(tls)).await?;
            let conn_task = tokio::spawn(async move {
                let _ = conn.await;
            });
            let r = sender.send_request(req).await?;
            let status = r.status();
            let raw_headers = r.headers().clone();
            let body = r.into_body().collect().await?.to_bytes().to_vec();
            conn_task.abort();
            (status, raw_headers, body)
        }
        Proto::H2 => {
            let (mut sender, conn) =
                h2_client::handshake(TokioExecutor::new(), TokioIo::new(tls)).await?;
            let conn_task = tokio::spawn(async move {
                let _ = conn.await;
            });
            let r = sender.send_request(req).await?;
            let status = r.status();
            let raw_headers = r.headers().clone();
            let body = r.into_body().collect().await?.to_bytes().to_vec();
            conn_task.abort();
            (status, raw_headers, body)
        }
    };

    let (status, raw_headers, mut body) = resp;
    let is_error = status.is_client_error() || status.is_server_error();
    let mut headers = Vec::with_capacity(raw_headers.len());
    let mut request_id: Option<String> = None;
    let mut saw_error_csp = false;
    for (name, value) in &raw_headers {
        let lower = name.as_str().to_ascii_lowercase();
        if lower == DATE.as_str() {
            continue;
        }
        if lower == "x-request-id" {
            request_id = Some(value.to_str()?.to_owned());
            continue;
        }
        let val_bytes = if is_error && lower == "content-security-policy" {
            saw_error_csp = true;
            normalize_error_csp(value.as_bytes())?
        } else {
            value.as_bytes().to_vec()
        };
        headers.push((lower, val_bytes));
    }
    if is_error && !saw_error_csp {
        return Err(format!(
            "missing Content-Security-Policy header on generated {status} error response for {uri}"
        )
        .into());
    }
    // For `2xx`/`3xx` responses, `body` stays 100% raw untouched bytes. Only for generated
    // `4xx`/`5xx` error pages normalize the per-request random `X-Request-Id` and the queried
    // equal-length hostname so the rest of the error page (and `Content-Length`) compare exact.
    if is_error && let Ok(mut text) = String::from_utf8(body.clone()) {
        if let Some(ref rid) = request_id {
            text = text.replace(rid, "<REQUEST_ID>");
        }
        text = text.replace(host, "<ORACLE_HOST>");
        body = text.into_bytes();
    }
    Ok(CapturedResponse {
        status,
        headers,
        has_request_id: request_id.is_some(),
        body,
    })
}

/// Populates the shared fixture directory used by both `cached.oracle.test` and `uncached.oracle.test`.
fn populate_oracle_tree(root: &std::path::Path) -> Result<(), std::io::Error> {
    fs::write(root.join("hello.txt"), b"hello file-cache oracle payload\n")?;
    fs::write(root.join("empty.txt"), b"")?;
    fs::write(root.join(".env"), b"SECRET=never-serve\n")?;

    // > 1024 B compressible payload (no precompressed siblings -> exercises on-the-fly compression).
    let compressible = "miraserve-file-cache-compressible-line-0123456789\n".repeat(90);
    fs::write(root.join("compressible.txt"), compressible.as_bytes())?;

    // Precompressed sibling fixture with distinct payload lengths per encoding.
    let precomp_base = "console.log('precompressed-oracle-fixture');\n".repeat(80);
    fs::write(root.join("precomp.js"), precomp_base.as_bytes())?;
    fs::write(
        root.join("precomp.js.zst"),
        b"FAKEZST-PRECOMP-PAYLOAD-11111",
    )?;
    fs::write(
        root.join("precomp.js.br"),
        b"FAKEBR-PRECOMP-PAYLOAD-222222222",
    )?;
    fs::write(
        root.join("precomp.js.gz"),
        b"FAKEGZ-PRECOMP-PAYLOAD-333333333333",
    )?;

    // Directory index and trailing-slash redirect fixture.
    fs::create_dir_all(root.join("sub"))?;
    fs::write(root.join("sub").join("index.html"), b"<h1>Sub Index</h1>\n")?;

    // Markdown negotiation fixture (HTML + authored .md sibling).
    fs::write(root.join("page.html"), b"<h1>Oracle Page</h1>\n")?;
    fs::write(root.join("page.md"), b"# Oracle Page\n")?;

    // Large file (256 KiB + 1 byte): must NEVER be admitted to FileCache.
    let large_payload = vec![b'L'; FILE_CACHE_SIZE_BOUND_BYTES + 1];
    fs::write(root.join("large.bin"), &large_payload)?;

    // Large base file (> 256 KiB) with a tiny precompressed sibling: must NEVER be admitted.
    fs::write(root.join("large-precomp.js"), &large_payload)?;
    fs::write(root.join("large-precomp.js.gz"), b"TINY-GZ-OF-LARGE-BASE")?;

    // Tagged static route fixture.
    fs::create_dir_all(root.join("tagged"))?;
    fs::write(
        root.join("tagged").join("item.txt"),
        b"tagged static item\n",
    )?;
    fs::write(
        root.join("tagged").join("comp.txt"),
        compressible.as_bytes(),
    )?;

    // `try-files` fixture (direct match + fallback to a dedicated fallback-owned route).
    fs::create_dir_all(root.join("app"))?;
    fs::write(root.join("app").join("direct.txt"), b"app direct match\n")?;
    fs::write(
        root.join("app").join("fallback.html"),
        b"<html><body>SPA fallback</body></html>\n",
    )?;

    // Mutation-window visibility target.
    fs::write(root.join("mutated.txt"), b"version-one-payload\n")?;

    // Pre-1970 mtime fixture (verifies fresh + cached omit Last-Modified and never panic).
    let pre_epoch_path = root.join("pre-epoch.txt");
    fs::write(&pre_epoch_path, b"before-unix-epoch-1969\n")?;
    #[cfg(unix)]
    {
        let pre_epoch_time = UNIX_EPOCH
            .checked_sub(Duration::from_secs(86_400))
            .ok_or_else(|| std::io::Error::other("pre-epoch SystemTime underflow"))?;
        fs::OpenOptions::new()
            .write(true)
            .open(&pre_epoch_path)?
            .set_modified(pre_epoch_time)?;
    }
    Ok(())
}

fn build_dual_site_kdl(port: u16, root_str: &str, workers_line: &str, window: &str) -> String {
    let site_body = |host: &str, cache_line: &str| {
        format!(
            r#"
site "{host}" {{
    root "{root_str}"
    {cache_line}
    security-headers "strict"
    precompressed "all"
    headers {{
        set "x-site-all" "yes"
        set "x-site-200" "ok200" status="200"
        set "x-site-304" "notmod304" status="304"
        set "x-site-206" "part206" status="206"
        add "x-multi" "first"
        add "x-multi" "second"
        remove "x-absent"
    }}
    route "/tagged/*" {{
        static {{
            precompressed "all"
        }}
        headers {{
            set "x-route-tag" "tagged-static"
            set "x-route-200" "r200" status="200"
            set "x-route-304" "r304" status="304"
        }}
    }}
    route "/app/fallback.html" {{
        static {{}}
        headers {{
            set "x-fallback-owner" "fallback-route"
        }}
    }}
    route "/app/*" {{
        try-files "{{path}}" "/app/fallback.html"
        headers {{
            set "x-try-route" "try-owner"
        }}
    }}
}}
"#
        )
    };
    let cached = site_body(CACHED_HOST, "file-cache \"30s\"");
    let short_win = site_body(SHORT_WIN_HOST, &format!("file-cache \"{window}\""));
    let uncached = site_body(UNCACHED_HOST, "");
    format!(
        r#"
server {{
    listen "127.0.0.1:{port}" protocols="h2,h1"
    {workers_line}
    tls {{
        min-version "1.3"
        pqc-hybrid #true
    }}
}}
{cached}
{short_win}
{uncached}
"#
    )
}

/// Asserts exact response parity (status, ordered headers except `Date` and `X-Request-Id`,
/// request-id presence, and raw body bytes) between `uncached.oracle.test` and BOTH a first
/// (fill/miss) and second (warm hit) request to `cached_host`, AND asserts exact `FileCache`
/// hit/fill telemetry counter deltas for every eligible and bypass case.
#[allow(clippy::too_many_arguments)]
async fn assert_parity(
    server: &RunningServer,
    openat2_available: bool,
    cached_host: &str,
    addr: SocketAddr,
    roots: &RootCertStore,
    proto: Proto,
    label: &str,
    method: Method,
    uri: &str,
    extra_headers: &[(http::HeaderName, HeaderValue)],
    expected_status: StatusCode,
    cache_expect: CacheExpectation,
) -> Result<CapturedResponse, Box<dyn std::error::Error>> {
    let uncached = send_request(
        addr,
        roots,
        proto,
        UNCACHED_HOST,
        method.clone(),
        uri,
        extra_headers,
    )
    .await?;
    assert_eq!(
        uncached.status, expected_status,
        "{proto:?} {label}: uncached status mismatch"
    );

    let (hits_before_first, _, fills_before_first, _) = server.telemetry().file_cache_counts();
    let cached_first = send_request(
        addr,
        roots,
        proto,
        cached_host,
        method.clone(),
        uri,
        extra_headers,
    )
    .await?;
    assert_eq!(
        cached_first, uncached,
        "{proto:?} {label}: cached (1st / fill) diverged from uncached"
    );

    let (hits_before_second, _, fills_before_second, _) = server.telemetry().file_cache_counts();
    let cached_second =
        send_request(addr, roots, proto, cached_host, method, uri, extra_headers).await?;
    let (hits_after_second, _, fills_after_second, _) = server.telemetry().file_cache_counts();
    assert_eq!(
        cached_second, uncached,
        "{proto:?} {label}: cached (2nd / hit) diverged from uncached"
    );

    if openat2_available {
        match cache_expect {
            CacheExpectation::HitOnSecond => {
                assert_eq!(
                    (hits_after_second, fills_after_second),
                    (hits_before_second + 1, fills_before_second),
                    "{proto:?} {label}: expected 2nd cached request to record a FileCache hit without refilling \
                     (before=({hits_before_second},{fills_before_second}), after=({hits_after_second},{fills_after_second}), fills_before_first={fills_before_first})"
                );
            }
            CacheExpectation::Bypass => {
                assert_eq!(
                    (hits_after_second, fills_after_second),
                    (hits_before_first, fills_before_first),
                    "{proto:?} {label}: bypass case must neither hit nor fill FileCache \
                     (before=({hits_before_first},{fills_before_first}), after=({hits_after_second},{fills_after_second}))"
                );
            }
        }
    } else {
        assert_eq!(
            (hits_after_second, fills_after_second),
            (hits_before_first, fills_before_first),
            "{proto:?} {label}: without openat2, FileCache must record zero hits and zero fills"
        );
    }

    Ok(uncached)
}

#[allow(clippy::too_many_lines)]
async fn run_full_matrix(
    server: &RunningServer,
    openat2_available: bool,
    addr: SocketAddr,
    roots: &RootCertStore,
    proto: Proto,
) -> TestResult {
    // 1. Plain GET, HEAD, empty file, directory index, directory redirect.
    let hello = assert_parity(
        server,
        openat2_available,
        CACHED_HOST,
        addr,
        roots,
        proto,
        "GET /hello.txt",
        Method::GET,
        "/hello.txt",
        &[],
        StatusCode::OK,
        CacheExpectation::HitOnSecond,
    )
    .await?;
    assert_eq!(hello.body, b"hello file-cache oracle payload\n");
    assert_eq!(hello.header_str("x-site-all"), Some("yes"));
    assert_eq!(hello.header_str("x-site-200"), Some("ok200"));
    assert_eq!(hello.header_str("x-site-304"), None);
    assert_eq!(hello.header_str("x-site-206"), None);

    let head_hello = assert_parity(
        server,
        openat2_available,
        CACHED_HOST,
        addr,
        roots,
        proto,
        "HEAD /hello.txt",
        Method::HEAD,
        "/hello.txt",
        &[],
        StatusCode::OK,
        CacheExpectation::HitOnSecond,
    )
    .await?;
    assert_eq!(head_hello.body, [] as [u8; 0]);

    let empty = assert_parity(
        server,
        openat2_available,
        CACHED_HOST,
        addr,
        roots,
        proto,
        "GET /empty.txt",
        Method::GET,
        "/empty.txt",
        &[],
        StatusCode::OK,
        CacheExpectation::HitOnSecond,
    )
    .await?;
    assert_eq!(empty.body, [] as [u8; 0]);

    let _ = assert_parity(
        server,
        openat2_available,
        CACHED_HOST,
        addr,
        roots,
        proto,
        "GET /sub/",
        Method::GET,
        "/sub/",
        &[],
        StatusCode::OK,
        CacheExpectation::HitOnSecond,
    )
    .await?;

    let _ = assert_parity(
        server,
        openat2_available,
        CACHED_HOST,
        addr,
        roots,
        proto,
        "GET /sub redirect",
        Method::GET,
        "/sub",
        &[],
        StatusCode::MOVED_PERMANENTLY,
        CacheExpectation::Bypass,
    )
    .await?;

    // 1b. Pre-1970 mtime file: exact fresh vs cached parity, omits Last-Modified, never panics,
    //     and ignores If-Modified-Since (returns 200, not 304).
    let pre_epoch = assert_parity(
        server,
        openat2_available,
        CACHED_HOST,
        addr,
        roots,
        proto,
        "GET /pre-epoch.txt",
        Method::GET,
        "/pre-epoch.txt",
        &[],
        StatusCode::OK,
        CacheExpectation::HitOnSecond,
    )
    .await?;
    assert_eq!(pre_epoch.body, b"before-unix-epoch-1969\n");
    #[cfg(unix)]
    {
        assert_eq!(
            pre_epoch.header_str(LAST_MODIFIED.as_str()),
            None,
            "{proto:?}: pre-epoch file must omit Last-Modified"
        );
        let _ = assert_parity(
            server,
            openat2_available,
            CACHED_HOST,
            addr,
            roots,
            proto,
            "GET /pre-epoch.txt IMS stays 200",
            Method::GET,
            "/pre-epoch.txt",
            &[(
                IF_MODIFIED_SINCE,
                HeaderValue::from_static("Thu, 01 Jan 1970 00:00:00 GMT"),
            )],
            StatusCode::OK,
            CacheExpectation::HitOnSecond,
        )
        .await?;
    }

    // 2. Non-GET/HEAD method, missing file, dotfile protection, borrowed/normalized query paths.
    let _ = assert_parity(
        server,
        openat2_available,
        CACHED_HOST,
        addr,
        roots,
        proto,
        "POST /hello.txt",
        Method::POST,
        "/hello.txt",
        &[],
        StatusCode::METHOD_NOT_ALLOWED,
        CacheExpectation::Bypass,
    )
    .await?;
    let _ = assert_parity(
        server,
        openat2_available,
        CACHED_HOST,
        addr,
        roots,
        proto,
        "GET /missing.txt",
        Method::GET,
        "/missing.txt",
        &[],
        StatusCode::NOT_FOUND,
        CacheExpectation::Bypass,
    )
    .await?;
    let _ = assert_parity(
        server,
        openat2_available,
        CACHED_HOST,
        addr,
        roots,
        proto,
        "GET /.env dotfile",
        Method::GET,
        "/.env",
        &[],
        StatusCode::NOT_FOUND,
        CacheExpectation::Bypass,
    )
    .await?;
    let _ = assert_parity(
        server,
        openat2_available,
        CACHED_HOST,
        addr,
        roots,
        proto,
        "GET /hello.txt?q=1",
        Method::GET,
        "/hello.txt?q=1",
        &[],
        StatusCode::OK,
        CacheExpectation::HitOnSecond,
    )
    .await?;
    let _ = assert_parity(
        server,
        openat2_available,
        CACHED_HOST,
        addr,
        roots,
        proto,
        "GET /tagged//item.txt normalized",
        Method::GET,
        "/tagged//item.txt",
        &[],
        StatusCode::OK,
        CacheExpectation::HitOnSecond,
    )
    .await?;

    // 3. Conditional 304 / 200 (If-None-Match & If-Modified-Since, GET & HEAD).
    let lm = HeaderValue::from_str(
        hello
            .header_str(LAST_MODIFIED.as_str())
            .ok_or("missing Last-Modified")?,
    )?;
    #[cfg(unix)]
    {
        let etag = HeaderValue::from_str(hello.header_str(ETAG.as_str()).ok_or("missing ETag")?)?;
        let r304 = assert_parity(
            server,
            openat2_available,
            CACHED_HOST,
            addr,
            roots,
            proto,
            "GET /hello.txt 304 INM",
            Method::GET,
            "/hello.txt",
            &[(IF_NONE_MATCH, etag.clone())],
            StatusCode::NOT_MODIFIED,
            CacheExpectation::HitOnSecond,
        )
        .await?;
        assert_eq!(r304.header_str("x-site-304"), Some("notmod304"));
        assert_eq!(r304.header_str("x-site-200"), None);
        assert_eq!(r304.body, [] as [u8; 0]);

        let _ = assert_parity(
            server,
            openat2_available,
            CACHED_HOST,
            addr,
            roots,
            proto,
            "HEAD /hello.txt 304 INM",
            Method::HEAD,
            "/hello.txt",
            &[(IF_NONE_MATCH, etag.clone())],
            StatusCode::NOT_MODIFIED,
            CacheExpectation::HitOnSecond,
        )
        .await?;

        let _ = assert_parity(
            server,
            openat2_available,
            CACHED_HOST,
            addr,
            roots,
            proto,
            "GET /hello.txt 200 mismatched INM",
            Method::GET,
            "/hello.txt",
            &[(IF_NONE_MATCH, HeaderValue::from_static("\"no-match\""))],
            StatusCode::OK,
            CacheExpectation::HitOnSecond,
        )
        .await?;

        // Range + matching If-Range -> 206; Range + mismatched If-Range -> 200.
        let r206_ir = assert_parity(
            server,
            openat2_available,
            CACHED_HOST,
            addr,
            roots,
            proto,
            "GET /hello.txt 206 If-Range match",
            Method::GET,
            "/hello.txt",
            &[
                (RANGE, HeaderValue::from_static("bytes=0-4")),
                (IF_RANGE, etag),
            ],
            StatusCode::PARTIAL_CONTENT,
            CacheExpectation::Bypass,
        )
        .await?;
        assert_eq!(r206_ir.body, b"hello");
        assert_eq!(r206_ir.header_str("x-site-206"), Some("part206"));
    }

    let _ = assert_parity(
        server,
        openat2_available,
        CACHED_HOST,
        addr,
        roots,
        proto,
        "GET /hello.txt 304 IMS",
        Method::GET,
        "/hello.txt",
        &[(IF_MODIFIED_SINCE, lm)],
        StatusCode::NOT_MODIFIED,
        CacheExpectation::HitOnSecond,
    )
    .await?;

    // 4. Range (206, 416), mismatched If-Range (200), and HEAD+Range (200 whole-file).
    let r206 = assert_parity(
        server,
        openat2_available,
        CACHED_HOST,
        addr,
        roots,
        proto,
        "GET /hello.txt 206 Range",
        Method::GET,
        "/hello.txt",
        &[(RANGE, HeaderValue::from_static("bytes=6-15"))],
        StatusCode::PARTIAL_CONTENT,
        CacheExpectation::Bypass,
    )
    .await?;
    assert_eq!(r206.body, b"file-cache");
    assert_eq!(r206.header_str("x-site-206"), Some("part206"));

    let _ = assert_parity(
        server,
        openat2_available,
        CACHED_HOST,
        addr,
        roots,
        proto,
        "GET /hello.txt 416 Range",
        Method::GET,
        "/hello.txt",
        &[(RANGE, HeaderValue::from_static("bytes=99999-"))],
        StatusCode::RANGE_NOT_SATISFIABLE,
        CacheExpectation::Bypass,
    )
    .await?;

    let _ = assert_parity(
        server,
        openat2_available,
        CACHED_HOST,
        addr,
        roots,
        proto,
        "GET /hello.txt 200 If-Range mismatch",
        Method::GET,
        "/hello.txt",
        &[
            (RANGE, HeaderValue::from_static("bytes=0-4")),
            (IF_RANGE, HeaderValue::from_static("\"stale-etag\"")),
        ],
        StatusCode::OK,
        CacheExpectation::Bypass,
    )
    .await?;

    let head_range = assert_parity(
        server,
        openat2_available,
        CACHED_HOST,
        addr,
        roots,
        proto,
        "HEAD /hello.txt + Range",
        Method::HEAD,
        "/hello.txt",
        &[(RANGE, HeaderValue::from_static("bytes=0-4"))],
        StatusCode::OK,
        CacheExpectation::Bypass,
    )
    .await?;
    assert_eq!(head_range.body, [] as [u8; 0]);

    // 5. On-the-fly compression (`Accept-Encoding` matrix + HEAD compressed).
    for (enc_label, ae, expected_ce) in [
        ("otf gzip", "gzip", Some("gzip")),
        ("otf br", "br", Some("br")),
        ("otf zstd", "zstd", Some("zstd")),
        ("otf br, gzip", "br, gzip", Some("br")),
        ("otf gzip;q=0", "gzip;q=0", None),
        ("otf identity", "identity", None),
    ] {
        let resp = assert_parity(
            server,
            openat2_available,
            CACHED_HOST,
            addr,
            roots,
            proto,
            enc_label,
            Method::GET,
            "/compressible.txt",
            &[(ACCEPT_ENCODING, HeaderValue::from_static(ae))],
            StatusCode::OK,
            CacheExpectation::HitOnSecond,
        )
        .await?;
        assert_eq!(
            resp.header_str(CONTENT_ENCODING.as_str()),
            expected_ce,
            "{proto:?} {enc_label}: unexpected Content-Encoding"
        );
    }
    let head_gz = assert_parity(
        server,
        openat2_available,
        CACHED_HOST,
        addr,
        roots,
        proto,
        "HEAD /compressible.txt gzip",
        Method::HEAD,
        "/compressible.txt",
        &[(ACCEPT_ENCODING, HeaderValue::from_static("gzip"))],
        StatusCode::OK,
        CacheExpectation::HitOnSecond,
    )
    .await?;
    assert_eq!(head_gz.header_str(CONTENT_ENCODING.as_str()), Some("gzip"));
    assert_eq!(head_gz.body, [] as [u8; 0]);

    // 6. Precompressed siblings (`.zst`, `.br`, `.gz`, identity, q=0 exclusion, 304 on sibling).
    for (label, ae, expected_ce, expected_body) in [
        (
            "precomp zstd",
            "zstd",
            Some("zstd"),
            &b"FAKEZST-PRECOMP-PAYLOAD-11111"[..],
        ),
        (
            "precomp br",
            "br",
            Some("br"),
            &b"FAKEBR-PRECOMP-PAYLOAD-222222222"[..],
        ),
        (
            "precomp gzip",
            "gzip",
            Some("gzip"),
            &b"FAKEGZ-PRECOMP-PAYLOAD-333333333333"[..],
        ),
        (
            "precomp zstd;q=0, br, gzip",
            "zstd;q=0, br, gzip",
            Some("br"),
            &b"FAKEBR-PRECOMP-PAYLOAD-222222222"[..],
        ),
        ("precomp all q=0", "zstd;q=0, br;q=0, gzip;q=0", None, &[]),
    ] {
        let resp = assert_parity(
            server,
            openat2_available,
            CACHED_HOST,
            addr,
            roots,
            proto,
            label,
            Method::GET,
            "/precomp.js",
            &[(ACCEPT_ENCODING, HeaderValue::from_static(ae))],
            StatusCode::OK,
            CacheExpectation::HitOnSecond,
        )
        .await?;
        assert_eq!(resp.header_str(CONTENT_ENCODING.as_str()), expected_ce);
        if !expected_body.is_empty() {
            assert_eq!(resp.body.as_slice(), expected_body);
        }
    }
    #[cfg(unix)]
    {
        let gz_probe = send_request(
            addr,
            roots,
            proto,
            UNCACHED_HOST,
            Method::GET,
            "/precomp.js",
            &[(ACCEPT_ENCODING, HeaderValue::from_static("gzip"))],
        )
        .await?;
        let gz_etag = HeaderValue::from_str(
            gz_probe
                .header_str(ETAG.as_str())
                .ok_or("missing gz etag")?,
        )?;
        let _ = assert_parity(
            server,
            openat2_available,
            CACHED_HOST,
            addr,
            roots,
            proto,
            "GET /precomp.js gzip 304",
            Method::GET,
            "/precomp.js",
            &[
                (ACCEPT_ENCODING, HeaderValue::from_static("gzip")),
                (IF_NONE_MATCH, gz_etag),
            ],
            StatusCode::NOT_MODIFIED,
            CacheExpectation::HitOnSecond,
        )
        .await?;
    }

    // 7. Route-level static & status-conditioned header rules + `try-files` direct & fallback ownership.
    let tagged = assert_parity(
        server,
        openat2_available,
        CACHED_HOST,
        addr,
        roots,
        proto,
        "GET /tagged/item.txt",
        Method::GET,
        "/tagged/item.txt",
        &[],
        StatusCode::OK,
        CacheExpectation::HitOnSecond,
    )
    .await?;
    assert_eq!(tagged.header_str("x-route-tag"), Some("tagged-static"));
    assert_eq!(tagged.header_str("x-route-200"), Some("r200"));
    assert_eq!(tagged.header_str("x-route-304"), None);
    #[cfg(unix)]
    {
        let tag_etag = HeaderValue::from_str(
            tagged
                .header_str(ETAG.as_str())
                .ok_or("missing tagged etag")?,
        )?;
        let tagged_304 = assert_parity(
            server,
            openat2_available,
            CACHED_HOST,
            addr,
            roots,
            proto,
            "GET /tagged/item.txt 304",
            Method::GET,
            "/tagged/item.txt",
            &[(IF_NONE_MATCH, tag_etag)],
            StatusCode::NOT_MODIFIED,
            CacheExpectation::HitOnSecond,
        )
        .await?;
        assert_eq!(tagged_304.header_str("x-route-tag"), Some("tagged-static"));
        assert_eq!(tagged_304.header_str("x-route-304"), Some("r304"));
        assert_eq!(tagged_304.header_str("x-route-200"), None);
    }

    let _ = assert_parity(
        server,
        openat2_available,
        CACHED_HOST,
        addr,
        roots,
        proto,
        "GET /tagged/comp.txt gzip",
        Method::GET,
        "/tagged/comp.txt",
        &[(ACCEPT_ENCODING, HeaderValue::from_static("gzip"))],
        StatusCode::OK,
        CacheExpectation::HitOnSecond,
    )
    .await?;

    let tf_direct = assert_parity(
        server,
        openat2_available,
        CACHED_HOST,
        addr,
        roots,
        proto,
        "GET /app/direct.txt try-files direct",
        Method::GET,
        "/app/direct.txt",
        &[],
        StatusCode::OK,
        CacheExpectation::HitOnSecond,
    )
    .await?;
    assert_eq!(tf_direct.header_str("x-try-route"), Some("try-owner"));
    assert_eq!(tf_direct.header_str("x-fallback-owner"), None);

    let tf_fb = assert_parity(
        server,
        openat2_available,
        CACHED_HOST,
        addr,
        roots,
        proto,
        "GET /app/missing-spa try-files fallback",
        Method::GET,
        "/app/missing-spa",
        &[],
        StatusCode::OK,
        CacheExpectation::HitOnSecond,
    )
    .await?;
    assert_eq!(tf_fb.body, b"<html><body>SPA fallback</body></html>\n");
    assert_eq!(
        tf_fb.header_str("x-fallback-owner"),
        Some("fallback-route"),
        "cached try-files fallback hit must preserve fallback route header ownership"
    );
    assert_eq!(tf_fb.header_str("x-try-route"), None);

    // 8. Markdown negotiation (authored sibling bypasses cache; HTML request hits cache & keeps Vary: Accept).
    let md = assert_parity(
        server,
        openat2_available,
        CACHED_HOST,
        addr,
        roots,
        proto,
        "GET /page.html Accept: text/markdown",
        Method::GET,
        "/page.html",
        &[(ACCEPT, HeaderValue::from_static("text/markdown"))],
        StatusCode::OK,
        CacheExpectation::Bypass,
    )
    .await?;
    assert_eq!(md.body, b"# Oracle Page\n");

    let html = assert_parity(
        server,
        openat2_available,
        CACHED_HOST,
        addr,
        roots,
        proto,
        "GET /page.html Accept: text/html",
        Method::GET,
        "/page.html",
        &[(ACCEPT, HeaderValue::from_static("text/html"))],
        StatusCode::OK,
        CacheExpectation::HitOnSecond,
    )
    .await?;
    assert_eq!(html.body, b"<h1>Oracle Page</h1>\n");

    // 9. Large-file bound (> 256 KiB): byte-identical and MUST NEVER admit to FileCache!
    let large = assert_parity(
        server,
        openat2_available,
        CACHED_HOST,
        addr,
        roots,
        proto,
        "GET /large.bin (> 256 KiB)",
        Method::GET,
        "/large.bin",
        &[],
        StatusCode::OK,
        CacheExpectation::Bypass,
    )
    .await?;
    assert_eq!(large.body.len(), FILE_CACHE_SIZE_BOUND_BYTES + 1);

    let large_pre = assert_parity(
        server,
        openat2_available,
        CACHED_HOST,
        addr,
        roots,
        proto,
        "GET /large-precomp.js gzip (base > 256 KiB)",
        Method::GET,
        "/large-precomp.js",
        &[(ACCEPT_ENCODING, HeaderValue::from_static("gzip"))],
        StatusCode::OK,
        CacheExpectation::Bypass,
    )
    .await?;
    assert_eq!(large_pre.body, b"TINY-GZ-OF-LARGE-BASE");

    Ok(())
}

/// Checks documented window visibility when `/mutated.txt` changes on disk:
/// - Uncached site sees the new content immediately.
/// - On Linux with `openat2` available, cached site serves OLD bytes within the window and NEW
///   bytes once the window expires.
/// - On non-Linux (macOS/Windows) or when `openat2` is refused, the cache stores nothing and
///   immediately serves NEW bytes.
async fn verify_window_visibility(
    root: &std::path::Path,
    server: &RunningServer,
    addr: SocketAddr,
    roots: &RootCertStore,
    proto: Proto,
    window: Duration,
    openat2_available: bool,
) -> TestResult {
    let old_bytes = b"version-one-payload\n";
    let new_bytes = b"version-two-longer-payload-after-window\n";
    fs::write(root.join("mutated.txt"), old_bytes)?;

    // Prime cache on shortwin.oracle.test and verify parity with uncached.oracle.test.
    let primed = assert_parity(
        server,
        openat2_available,
        SHORT_WIN_HOST,
        addr,
        roots,
        proto,
        "GET /mutated.txt (initial)",
        Method::GET,
        "/mutated.txt",
        &[],
        StatusCode::OK,
        CacheExpectation::HitOnSecond,
    )
    .await?;
    assert_eq!(primed.body.as_slice(), old_bytes);

    // Mutate file on disk.
    fs::write(root.join("mutated.txt"), new_bytes)?;

    // Immediately verify uncached sees NEW bytes.
    let uncached_now = send_request(
        addr,
        roots,
        proto,
        UNCACHED_HOST,
        Method::GET,
        "/mutated.txt",
        &[],
    )
    .await?;
    assert_eq!(uncached_now.body.as_slice(), new_bytes);

    // Immediately verify cached behavior within window.
    let cached_within = send_request(
        addr,
        roots,
        proto,
        SHORT_WIN_HOST,
        Method::GET,
        "/mutated.txt",
        &[],
    )
    .await?;
    if openat2_available {
        assert_eq!(
            cached_within.body.as_slice(),
            old_bytes,
            "{proto:?}: Linux cached site with openat2 should still serve cached bytes within window"
        );
    } else {
        assert_eq!(
            cached_within.body.as_slice(),
            new_bytes,
            "{proto:?}: without openat2 (e.g. macOS) file-cache stores nothing and sees new bytes immediately"
        );
    }

    // Wait past the window and verify exact parity on the new content.
    tokio::time::sleep(window + Duration::from_millis(150)).await;
    let after = assert_parity(
        server,
        openat2_available,
        SHORT_WIN_HOST,
        addr,
        roots,
        proto,
        "GET /mutated.txt (after window)",
        Method::GET,
        "/mutated.txt",
        &[],
        StatusCode::OK,
        CacheExpectation::HitOnSecond,
    )
    .await?;
    assert_eq!(after.body.as_slice(), new_bytes);

    let (hits, _misses, fills, _budget) = server.telemetry().file_cache_counts();
    if openat2_available {
        assert!(
            fills > 0 && hits > 0,
            "{proto:?}: expected Linux file-cache to record fills ({fills}) and hits ({hits})"
        );
    } else {
        assert_eq!(
            (fills, hits),
            (0, 0),
            "{proto:?}: expected non-openat2 platform to store nothing (fills={fills}, hits={hits})"
        );
    }
    Ok(())
}

fn host_allows_file_cache_admission() -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        miraserve_core::probe_openat2_refused().is_none()
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        false
    }
}

#[test]
fn file_cache_oracle_h1_and_h2_spawned_and_intask_parity_and_window() -> TestResult {
    let _serial = oracle_test_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let dir = TempDir::new("h1-h2")?;
        populate_oracle_tree(&dir.path)?;
        let root_str = dir.kdl_str();
        let openat2_ok = host_allows_file_cache_admission();

        // 1. Shared runtime: HTTP/1.1 + HTTP/2 (Spawned executor)
        {
            let _exec_guard = miraserve_http::test_h2_exec_override_guard(Some(false));
            let (server, addr) =
                start_server_retrying(|port| build_dual_site_kdl(port, &root_str, "", "400ms"))
                    .await?;
            let roots = build_roots(server.dev_cert_pem().ok_or("missing dev cert")?)?;

            run_full_matrix(&server, openat2_ok, addr, &roots, Proto::H1).await?;

            let (in_before, sp_before) = miraserve_http::test_h2_exec_stream_counts();
            let mm_before = miraserve_http::test_h2_handoff_mismatch_count();
            run_full_matrix(&server, openat2_ok, addr, &roots, Proto::H2).await?;
            let (in_after, sp_after) = miraserve_http::test_h2_exec_stream_counts();
            let mm_after = miraserve_http::test_h2_handoff_mismatch_count();
            assert_eq!(
                in_after, in_before,
                "Spawned override must execute zero in-task H2 streams"
            );
            assert!(
                sp_after > sp_before,
                "Spawned override must execute spawned H2 streams (before={sp_before}, after={sp_after})"
            );
            assert_eq!(
                mm_after, mm_before,
                "expected zero HTTP/2 handoff mismatches under Spawned executor"
            );

            verify_window_visibility(
                &dir.path,
                &server,
                addr,
                &roots,
                Proto::H1,
                Duration::from_millis(400),
                openat2_ok,
            )
            .await?;
            server.shutdown().await;
        }

        // 2. Shared runtime: HTTP/2 with forced `InTaskExec` (tests cached response inside the
        //    connection task, route classification, and RootReadPolicy interaction).
        {
            let _exec_guard = miraserve_http::test_h2_exec_override_guard(Some(true));
            let (server, addr) =
                start_server_retrying(|port| build_dual_site_kdl(port, &root_str, "", "400ms"))
                    .await?;
            let roots = build_roots(server.dev_cert_pem().ok_or("missing dev cert")?)?;

            let (in_before, sp_before) = miraserve_http::test_h2_exec_stream_counts();
            let mm_before = miraserve_http::test_h2_handoff_mismatch_count();
            run_full_matrix(&server, openat2_ok, addr, &roots, Proto::H2).await?;
            verify_window_visibility(
                &dir.path,
                &server,
                addr,
                &roots,
                Proto::H2,
                Duration::from_millis(400),
                openat2_ok,
            )
            .await?;
            let (in_after, sp_after) = miraserve_http::test_h2_exec_stream_counts();
            let mm_after = miraserve_http::test_h2_handoff_mismatch_count();
            assert!(
                in_after > in_before,
                "InTaskExec override must execute in-task H2 streams (before={in_before}, after={in_after})"
            );
            assert_eq!(
                sp_after, sp_before,
                "InTaskExec override must execute zero spawned H2 streams"
            );
            assert_eq!(
                mm_after, mm_before,
                "expected zero HTTP/2 handoff mismatches under InTaskExec"
            );
            server.shutdown().await;
        }

        Ok(())
    })
}

#[test]
fn file_cache_oracle_workers2_h1_and_h2_parity_and_window() -> TestResult {
    let _serial = oracle_test_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    rt.block_on(async {
        let dir = TempDir::new("workers2")?;
        populate_oracle_tree(&dir.path)?;
        let root_str = dir.kdl_str();
        let openat2_ok = host_allows_file_cache_admission();

        let (server, addr) = start_server_retrying(|port| {
            build_dual_site_kdl(port, &root_str, "workers 2", "400ms")
        })
        .await?;
        let roots = build_roots(server.dev_cert_pem().ok_or("missing dev cert")?)?;

        run_full_matrix(&server, openat2_ok, addr, &roots, Proto::H1).await?;
        run_full_matrix(&server, openat2_ok, addr, &roots, Proto::H2).await?;
        verify_window_visibility(
            &dir.path,
            &server,
            addr,
            &roots,
            Proto::H2,
            Duration::from_millis(400),
            openat2_ok,
        )
        .await?;

        server.shutdown().await;
        Ok(())
    })
}

#[test]
fn file_cache_oracle_credential_file_is_never_served_from_cache() -> TestResult {
    let _serial = oracle_test_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let dir = TempDir::new("cred")?;
        let www = dir.path.join("www");
        let auth = dir.path.join("auth");
        fs::create_dir_all(&www)?;
        fs::create_dir_all(&auth)?;

        let users_file = auth.join("users.htpasswd");
        fs::write(
            &users_file,
            "ann:$2y$04$euq2l0Zl/ScQTk3CQ399bOWoEjKfBFWbHiK4fmzlEbAioTmwnGI4q\n",
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&auth, fs::Permissions::from_mode(0o700))?;
            fs::set_permissions(&users_file, fs::Permissions::from_mode(0o600))?;
        }
        // Hard-link the credential file into the docroot to verify credential protection beats
        // FileCache on both initial lookup and warm cache checks.
        let alias = www.join("leaked-users.txt");
        fs::hard_link(&users_file, &alias)?;
        fs::write(www.join("public.txt"), b"public ok\n")?;

        let www_str = www.to_string_lossy().replace('\\', "/");
        let users_str = users_file.to_string_lossy().replace('\\', "/");
        let openat2_ok = host_allows_file_cache_admission();

        let (server, addr) = start_server_retrying(|port| {
            format!(
                r#"
server {{
    listen "127.0.0.1:{port}" protocols="h2,h1"
    tls {{ min-version "1.3"; pqc-hybrid #true }}
}}
site "{CACHED_HOST}" {{
    root "{www_str}"
    file-cache "10s"
    security-headers "strict"
}}
site "{UNCACHED_HOST}" {{
    root "{www_str}"
    security-headers "strict"
}}
site "auth.oracle.test" {{
    root "{www_str}"
    basic-auth "{users_str}" realm="Restricted"
}}
"#
            )
        })
        .await?;
        let roots = build_roots(server.dev_cert_pem().ok_or("missing dev cert")?)?;

        for proto in [Proto::H1, Proto::H2] {
            let pub_resp = assert_parity(
                &server,
                openat2_ok,
                CACHED_HOST,
                addr,
                &roots,
                proto,
                "GET /public.txt with cred active",
                Method::GET,
                "/public.txt",
                &[],
                StatusCode::OK,
                CacheExpectation::HitOnSecond,
            )
            .await?;
            assert_eq!(pub_resp.body, b"public ok\n");

            // Hard-linked credential file MUST return identical 404 on both uncached and cached
            // sites, NEVER hit or fill FileCache, and NEVER leak its contents.
            let cred_resp = assert_parity(
                &server,
                openat2_ok,
                CACHED_HOST,
                addr,
                &roots,
                proto,
                "GET /leaked-users.txt credential denial",
                Method::GET,
                "/leaked-users.txt",
                &[],
                StatusCode::NOT_FOUND,
                CacheExpectation::Bypass,
            )
            .await?;
            assert!(
                !String::from_utf8_lossy(&cred_resp.body).contains("$2y$04$"),
                "credential hash must never appear in response body"
            );
        }

        server.shutdown().await;
        Ok(())
    })
}

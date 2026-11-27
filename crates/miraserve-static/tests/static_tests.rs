//! Integration tests for `miraserve-static`: `cap-std` symlink confinement, dotfile denial,
//! ETag / 304, HTTP Range, precompressed + on-the-fly Brotli/Gzip, streaming large files,
//! and `try-files`.

use std::fs;
use std::io::Read as _;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::read::GzDecoder;
use http::header::{
    ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG,
    IF_NONE_MATCH, RANGE, VARY,
};
#[cfg(not(unix))]
use http::header::{IF_MODIFIED_SINCE, LAST_MODIFIED};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use http_body_util::BodyExt as _;
use miraserve_config::{DotfilesPolicy, PrecompressedPolicy, StaticConfig};
use miraserve_static::{StaticServer, TryFilesOutcome};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Result<Self, std::io::Error> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!(
            "miraserve-static-{tag}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir)?;
        Ok(Self { path: dir })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[tokio::test]
async fn serves_index_etag_304_head_and_range_requests() -> TestResult {
    let tmp = TempDir::new("basic")?;
    fs::write(tmp.path.join("index.html"), b"<html>Hello MiraServe</html>")?;
    fs::write(tmp.path.join("alphabet.txt"), b"0123456789abcdef")?;

    let server = StaticServer::open(&tmp.path, StaticConfig::default())?;

    // Directory index
    let resp = server.serve(&Method::GET, "/", &HeaderMap::new()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/html; charset=utf-8")
    );
    #[cfg(unix)]
    let etag = resp
        .headers()
        .get(ETAG)
        .and_then(|v| v.to_str().ok())
        .ok_or("missing ETag")?
        .to_owned();
    #[cfg(not(unix))]
    let last_modified = {
        // On non-Unix platforms (Windows), mira-static intentionally omits ETag because there is
        // no immutable inode ctime; revalidate via Last-Modified / If-Modified-Since instead.
        assert!(resp.headers().get(ETAG).is_none());
        resp.headers()
            .get(LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .ok_or("missing Last-Modified")?
            .to_owned()
    };
    let body = resp.into_body().collect().await?.to_bytes();
    assert_eq!(body.as_ref(), b"<html>Hello MiraServe</html>");

    // Conditional 304 via If-None-Match (Unix) or If-Modified-Since (Windows)
    let mut cond_headers = HeaderMap::new();
    #[cfg(unix)]
    cond_headers.insert(IF_NONE_MATCH, HeaderValue::from_str(&etag)?);
    #[cfg(not(unix))]
    cond_headers.insert(IF_MODIFIED_SINCE, HeaderValue::from_str(&last_modified)?);
    let resp_304 = server.serve(&Method::GET, "/", &cond_headers).await;
    assert_eq!(resp_304.status(), StatusCode::NOT_MODIFIED);
    assert!(resp_304.into_body().collect().await?.to_bytes().is_empty());

    // HEAD returns headers without body
    let resp_head = server
        .serve(&Method::HEAD, "/alphabet.txt", &HeaderMap::new())
        .await;
    assert_eq!(resp_head.status(), StatusCode::OK);
    assert_eq!(
        resp_head
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()),
        Some("16")
    );
    assert!(resp_head.into_body().collect().await?.to_bytes().is_empty());

    // Range: bytes=2-5 -> "2345"
    let mut range_headers = HeaderMap::new();
    range_headers.insert(RANGE, HeaderValue::from_static("bytes=2-5"));
    let resp_206 = server
        .serve(&Method::GET, "/alphabet.txt", &range_headers)
        .await;
    assert_eq!(resp_206.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        resp_206
            .headers()
            .get(CONTENT_RANGE)
            .and_then(|v| v.to_str().ok()),
        Some("bytes 2-5/16")
    );
    assert_eq!(
        resp_206.into_body().collect().await?.to_bytes().as_ref(),
        b"2345"
    );

    // Suffix range: bytes=-4 -> "cdef"
    let mut suffix_headers = HeaderMap::new();
    suffix_headers.insert(RANGE, HeaderValue::from_static("bytes=-4"));
    let resp_suffix = server
        .serve(&Method::GET, "/alphabet.txt", &suffix_headers)
        .await;
    assert_eq!(resp_suffix.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        resp_suffix.into_body().collect().await?.to_bytes().as_ref(),
        b"cdef"
    );

    // Unsatisfiable range -> 416
    let mut bad_range = HeaderMap::new();
    bad_range.insert(RANGE, HeaderValue::from_static("bytes=999-1000"));
    let resp_416 = server
        .serve(&Method::GET, "/alphabet.txt", &bad_range)
        .await;
    assert_eq!(resp_416.status(), StatusCode::RANGE_NOT_SATISFIABLE);

    // Non-GET/HEAD -> 405
    let resp_405 = server
        .serve(&Method::POST, "/alphabet.txt", &HeaderMap::new())
        .await;
    assert_eq!(resp_405.status(), StatusCode::METHOD_NOT_ALLOWED);

    Ok(())
}

#[tokio::test]
async fn enforces_cap_std_symlink_confinement_traversal_and_dotfile_denial() -> TestResult {
    let parent = TempDir::new("security")?;
    let docroot = parent.path.join("public");
    fs::create_dir_all(docroot.join(".git"))?;
    fs::write(docroot.join("ok.txt"), b"public")?;
    fs::write(docroot.join(".env"), b"SECRET=12345")?;
    fs::write(docroot.join(".git").join("config"), b"[core]")?;

    let outside_secret = parent.path.join("outside-secret.txt");
    fs::write(&outside_secret, b"TOP_SECRET_HOST_FILE")?;

    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside_secret, docroot.join("escape.txt"))?;

    let server = StaticServer::open(
        &docroot,
        StaticConfig {
            dotfiles: DotfilesPolicy::Deny,
            ..StaticConfig::default()
        },
    )?;

    // Legitimate file works
    let ok = server
        .serve(&Method::GET, "/ok.txt", &HeaderMap::new())
        .await;
    assert_eq!(ok.status(), StatusCode::OK);

    // Path traversal blocked
    for evil in [
        "/../outside-secret.txt",
        "/%2e%2e/outside-secret.txt",
        "/sub/../../outside-secret.txt",
        "/foo\\bar",
        "/ok.txt%00.jpg",
    ] {
        let resp = server.serve(&Method::GET, evil, &HeaderMap::new()).await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "expected 400 for traversal path '{evil}', got {}",
            resp.status()
        );
    }

    // Dotfiles denied
    for dot in ["/.env", "/.git/config"] {
        let resp = server.serve(&Method::GET, dot, &HeaderMap::new()).await;
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "dotfile '{dot}' leaked"
        );
    }

    // Symlink pointing outside docroot MUST be blocked by cap-std!
    #[cfg(unix)]
    {
        let escape = server
            .serve(&Method::GET, "/escape.txt", &HeaderMap::new())
            .await;
        assert_eq!(
            escape.status(),
            StatusCode::NOT_FOUND,
            "cap-std MUST block symlink escape outside docroot"
        );
    }

    Ok(())
}

#[tokio::test]
async fn negotiates_precompressed_and_onthefly_compression_and_streams_large_files() -> TestResult {
    let tmp = TempDir::new("compress")?;
    let large_json = format!("{{\"items\":[{}]}}", "\"miraserve\",".repeat(500));
    fs::write(tmp.path.join("data.json"), large_json.as_bytes())?;

    // Pre-compressed .zst sibling
    fs::write(tmp.path.join("bundle.js"), b"console.log('raw');")?;
    fs::write(tmp.path.join("bundle.js.zst"), b"FAKE_ZSTD_BYTES")?;

    // Large binary file > 256 KiB to exercise chunked streaming path
    let big_bin = vec![0x5A_u8; 320 * 1024];
    fs::write(tmp.path.join("big.bin"), &big_bin)?;

    let server = StaticServer::open(
        &tmp.path,
        StaticConfig {
            precompressed: PrecompressedPolicy::ALL,
            ..StaticConfig::default()
        },
    )?;
    let mut zst_hdrs = HeaderMap::new();
    zst_hdrs.insert(ACCEPT_ENCODING, HeaderValue::from_static("zstd, br, gzip"));
    let resp_zst = server.serve(&Method::GET, "/bundle.js", &zst_hdrs).await;
    assert_eq!(resp_zst.status(), StatusCode::OK);
    assert_eq!(
        resp_zst
            .headers()
            .get(CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        Some("zstd")
    );
    assert_eq!(
        resp_zst.into_body().collect().await?.to_bytes().as_ref(),
        b"FAKE_ZSTD_BYTES"
    );

    // On-the-fly pure-Rust gzip
    let mut gz_hdrs = HeaderMap::new();
    gz_hdrs.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
    let resp_gz = server.serve(&Method::GET, "/data.json", &gz_hdrs).await;
    assert_eq!(resp_gz.status(), StatusCode::OK);
    assert_eq!(
        resp_gz
            .headers()
            .get(CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        Some("gzip")
    );
    assert_eq!(
        resp_gz.headers().get(VARY).and_then(|v| v.to_str().ok()),
        Some("Accept-Encoding")
    );
    let gz_bytes = resp_gz.into_body().collect().await?.to_bytes();
    let mut decoder = GzDecoder::new(gz_bytes.as_ref());
    let mut plain_text = String::new();
    decoder.read_to_string(&mut plain_text)?;
    assert_eq!(plain_text, large_json);

    // On-the-fly pure-Rust Zstandard (`zstd` > `br` > `gzip`)
    let resp_zst_otf = server.serve(&Method::GET, "/data.json", &zst_hdrs).await;
    assert_eq!(resp_zst_otf.status(), StatusCode::OK);
    assert_eq!(
        resp_zst_otf
            .headers()
            .get(CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        Some("zstd")
    );
    let zst_bytes = resp_zst_otf.into_body().collect().await?.to_bytes();
    assert!(
        zst_bytes.len() < large_json.len(),
        "on-the-fly zstd should shrink compressible JSON"
    );
    let zst_decoded = miraserve_static::compress::decompress_zstd(&zst_bytes)?;
    assert_eq!(zst_decoded.as_slice(), large_json.as_bytes());

    // On-the-fly pure-Rust Brotli
    let mut br_hdrs = HeaderMap::new();
    br_hdrs.insert(ACCEPT_ENCODING, HeaderValue::from_static("br, gzip"));
    let resp_br = server.serve(&Method::GET, "/data.json", &br_hdrs).await;
    assert_eq!(
        resp_br
            .headers()
            .get(CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        Some("br")
    );
    let br_bytes = resp_br.into_body().collect().await?.to_bytes();
    assert!(br_bytes.len() < large_json.len());

    // Large streaming file (> 256 KiB)
    let resp_big = server
        .serve(&Method::GET, "/big.bin", &HeaderMap::new())
        .await;
    assert_eq!(resp_big.status(), StatusCode::OK);
    let streamed = resp_big.into_body().collect().await?.to_bytes();
    assert_eq!(streamed.len(), big_bin.len());
    assert_eq!(streamed.as_ref(), big_bin.as_slice());

    Ok(())
}

#[tokio::test]
async fn try_files_serves_existing_or_returns_internal_rewrite() -> TestResult {
    let tmp = TempDir::new("tryfiles")?;
    fs::write(tmp.path.join("about.html"), b"about page")?;
    let server = StaticServer::open(&tmp.path, StaticConfig::default())?;

    let candidates = vec![
        "{path}".to_owned(),
        "{path}/".to_owned(),
        "/index.php?{query}".to_owned(),
    ];

    match server
        .serve_try_files(
            &Method::GET,
            "/about.html",
            None,
            &HeaderMap::new(),
            &candidates,
        )
        .await
    {
        TryFilesOutcome::Response(resp)
        | TryFilesOutcome::FallbackResponse { response: resp, .. } => {
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(
                (*resp).into_body().collect().await?.to_bytes().as_ref(),
                b"about page"
            );
        }
        TryFilesOutcome::InternalRewrite(target) => {
            return Err(format!("expected static hit, got rewrite {target}").into());
        }
    }

    match server
        .serve_try_files(
            &Method::GET,
            "/blog/post-1",
            Some("page=2"),
            &HeaderMap::new(),
            &candidates,
        )
        .await
    {
        TryFilesOutcome::InternalRewrite(target) => {
            assert_eq!(target, "/index.php?page=2");
        }
        TryFilesOutcome::Response(resp)
        | TryFilesOutcome::FallbackResponse { response: resp, .. } => {
            return Err(format!("expected rewrite, got status {}", resp.status()).into());
        }
    }

    Ok(())
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn blocks_trailing_slash_on_regular_file_double_decode_and_dotfile_symlink() -> TestResult {
    let tmp = TempDir::new("canon")?;
    fs::write(tmp.path.join("wp-config.php"), b"<?php $DB_PASS='secret';")?;
    fs::write(tmp.path.join(".env"), b"SECRET=999")?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(tmp.path.join(".env"), tmp.path.join("innocent.txt"))?;

    let server = StaticServer::open(
        &tmp.path,
        StaticConfig {
            dotfiles: DotfilesPolicy::Deny,
            ..StaticConfig::default()
        },
    )?;

    // Trailing slash on regular file MUST return 404 (not leak wp-config.php source!)
    let resp = server
        .serve_canonical(&Method::GET, "/wp-config.php/", &HeaderMap::new())
        .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // serve_canonical must NOT perform a second percent-decode on `%70`
    let resp_double = server
        .serve_canonical(&Method::GET, "/wp-config.%70hp", &HeaderMap::new())
        .await;
    assert_eq!(resp_double.status(), StatusCode::NOT_FOUND);

    // In-tree symlink targeting `.env` MUST be denied under DotfilesPolicy::Deny
    #[cfg(unix)]
    {
        let resp_sym = server
            .serve_canonical(&Method::GET, "/innocent.txt", &HeaderMap::new())
            .await;
        assert_eq!(resp_sym.status(), StatusCode::NOT_FOUND);
    }

    // PATH-5: RFC 8615 `/.well-known/security.txt` is served while `/.well-known/.env` stays denied
    fs::create_dir_all(tmp.path.join(".well-known"))?;
    fs::write(
        tmp.path.join(".well-known").join("security.txt"),
        b"Contact: mailto:sec@example.com\n",
    )?;
    fs::write(tmp.path.join(".well-known").join(".env"), b"LEAK=1")?;
    let wk_ok = server
        .serve_canonical(&Method::GET, "/.well-known/security.txt", &HeaderMap::new())
        .await;
    assert_eq!(wk_ok.status(), StatusCode::OK);
    let wk_env = server
        .serve_canonical(&Method::GET, "/.well-known/.env", &HeaderMap::new())
        .await;
    assert_eq!(wk_env.status(), StatusCode::NOT_FOUND);

    // FCGI-1: POST to try-files falls through to internal rewrite instead of returning 405!
    let candidates = vec![
        "{path}".to_owned(),
        "{path}/".to_owned(),
        "/index.php?{query}".to_owned(),
    ];
    match server
        .serve_try_files_canonical(
            &Method::POST,
            "/wp-json/wp/v2/posts",
            Some("draft=1"),
            &HeaderMap::new(),
            &candidates,
        )
        .await
    {
        TryFilesOutcome::InternalRewrite(target) => {
            assert_eq!(target, "/index.php?draft=1");
        }
        TryFilesOutcome::Response(resp)
        | TryFilesOutcome::FallbackResponse { response: resp, .. } => {
            return Err(format!(
                "POST try-files must rewrite to fallback, got {}",
                resp.status()
            )
            .into());
        }
    }

    // STAT-1: If-Range mismatch MUST return full 200 OK instead of 206 Partial Content
    fs::write(tmp.path.join("asset.bin"), b"0123456789abcdef")?;
    let mut range_hdrs = HeaderMap::new();
    range_hdrs.insert(http::header::RANGE, "bytes=0-3".parse()?);
    range_hdrs.insert(http::header::IF_RANGE, "\"stale-etag\"".parse()?);
    let full_resp = server
        .serve_canonical(&Method::GET, "/asset.bin", &range_hdrs)
        .await;
    assert_eq!(full_resp.status(), StatusCode::OK);
    assert_eq!(
        full_resp.into_body().collect().await?.to_bytes().as_ref(),
        b"0123456789abcdef"
    );

    // PATH-6 helper: exists_regular_file returns true only for real non-dotfile regular files
    assert!(server.exists_regular_file("/asset.bin"));
    assert!(!server.exists_regular_file("/asset.bin/"));
    assert!(!server.exists_regular_file("/.env"));
    assert!(!server.exists_regular_file("/missing.php"));

    // Codex Finding 1: try-files MUST keep path and query separated before substitution AND
    // enforce forbidden script extensions on final file candidates (never leaking PHP source!).
    fs::write(tmp.path.join("secret.php"), b"<?php echo 'SECRET_SRC';")?;
    let forbidden = vec![".php".to_owned()];
    let candidates_with_ext = vec![
        "{path}".to_owned(),
        "{path}.php".to_owned(),
        "/index.php?{query}".to_owned(),
    ];
    for attack in ["/secret.php?foo=1", "/secret.php", "/secret"] {
        match server
            .serve_try_files_canonical_filtered(
                &Method::GET,
                attack,
                Some("k=v"),
                &HeaderMap::new(),
                &candidates_with_ext,
                &forbidden,
            )
            .await
        {
            TryFilesOutcome::InternalRewrite(target) => {
                assert_eq!(target, "/index.php?k=v");
            }
            TryFilesOutcome::Response(resp)
            | TryFilesOutcome::FallbackResponse { response: resp, .. } => {
                let status = resp.status();
                let body = (*resp).into_body().collect().await?.to_bytes();
                assert!(
                    !body.windows(10).any(|w| w == b"SECRET_SRC"),
                    "try-files leaked PHP source for {attack} (status {status})"
                );
            }
        }
    }

    // Codex Recheck Finding 1: static route configured with `index "index.php"` MUST NOT
    // leak PHP source code when `forbidden_extensions` includes `.php` (both root and subdir,
    // plus fallback to `index.html` and symlink-to-`.php` protection).
    fs::write(tmp.path.join("index.php"), b"<?php echo 'ROOT_INDEX_PHP';")?;
    fs::create_dir_all(tmp.path.join("sub"))?;
    fs::write(
        tmp.path.join("sub").join("index.php"),
        b"<?php echo 'SUB_INDEX_PHP';",
    )?;

    let php_index_only = StaticServer::open(
        &tmp.path,
        StaticConfig {
            index: vec!["index.php".to_owned()],
            ..StaticConfig::default()
        },
    )?
    .with_forbidden_extensions([".php".to_owned()]);

    for dir_uri in ["/", "/sub", "/sub/"] {
        let resp = php_index_only
            .serve_canonical(&Method::GET, dir_uri, &HeaderMap::new())
            .await;
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "directory index {dir_uri} must NOT serve forbidden index.php"
        );
        let body = resp.into_body().collect().await?.to_bytes();
        assert!(!body.windows(5).any(|w| w == b"<?php"));
    }

    // When both `index.php` and `index.html` are configured, skip forbidden `index.php`
    // and safely serve `index.html`!
    fs::write(tmp.path.join("index.html"), b"<h1>Safe HTML Index</h1>")?;
    let php_then_html = StaticServer::open(
        &tmp.path,
        StaticConfig {
            index: vec!["index.php".to_owned(), "index.html".to_owned()],
            ..StaticConfig::default()
        },
    )?
    .with_forbidden_extensions([".php".to_owned()]);
    let idx_resp = php_then_html
        .serve_canonical(&Method::GET, "/", &HeaderMap::new())
        .await;
    assert_eq!(idx_resp.status(), StatusCode::OK);
    assert_eq!(
        idx_resp.into_body().collect().await?.to_bytes().as_ref(),
        b"<h1>Safe HTML Index</h1>"
    );

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("secret.php", tmp.path.join("alias.txt"))?;
        let sym_resp = php_index_only
            .serve_canonical(&Method::GET, "/alias.txt", &HeaderMap::new())
            .await;
        assert_eq!(
            sym_resp.status(),
            StatusCode::NOT_FOUND,
            "symlink targeting forbidden .php file must NOT be served statically"
        );
    }

    Ok(())
}

/// R2-FCGI-1 (POST directory script index) & R3-HTTP-3 (301 redirect for `/wp-admin` without slash).
#[tokio::test]
async fn round3_try_files_post_directory_script_index_and_301_slash_redirect() -> TestResult {
    let tmp = TempDir::new("wp-dir-idx")?;
    fs::create_dir_all(tmp.path.join("wp-admin"))?;
    fs::write(
        tmp.path.join("wp-admin").join("index.php"),
        b"<?php echo 'admin';",
    )?;
    fs::write(tmp.path.join("index.php"), b"<?php echo 'root';")?;

    let server = StaticServer::open(
        &tmp.path,
        StaticConfig {
            index: vec!["index.php".to_owned(), "index.html".to_owned()],
            ..StaticConfig::default()
        },
    )?
    .with_forbidden_extensions([".php".to_owned()]);

    let candidates = vec![
        "{path}".to_owned(),
        "{path}/".to_owned(),
        "/index.php?{query}".to_owned(),
    ];
    let forbidden = vec![".php".to_owned()];

    // 1. R2-FCGI-1: `POST /wp-admin/` MUST rewrite to `/wp-admin/index.php` (NOT root `/index.php`)!
    match server
        .serve_try_files_canonical_filtered(
            &Method::POST,
            "/wp-admin/",
            Some("action=save"),
            &HeaderMap::new(),
            &candidates,
            &forbidden,
        )
        .await
    {
        TryFilesOutcome::InternalRewrite(target) => {
            assert_eq!(target, "/wp-admin/index.php?action=save");
        }
        TryFilesOutcome::Response(resp)
        | TryFilesOutcome::FallbackResponse { response: resp, .. } => {
            return Err(format!(
                "expected POST /wp-admin/ InternalRewrite, got status {}",
                resp.status()
            )
            .into());
        }
    }

    // 2. R3-HTTP-3: `GET /wp-admin?tab=general` (no trailing slash) MUST return 301 -> `/wp-admin/?tab=general`!
    match server
        .serve_try_files_canonical_filtered(
            &Method::GET,
            "/wp-admin",
            Some("tab=general"),
            &HeaderMap::new(),
            &candidates,
            &forbidden,
        )
        .await
    {
        TryFilesOutcome::Response(resp)
        | TryFilesOutcome::FallbackResponse { response: resp, .. } => {
            assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
            assert_eq!(
                resp.headers()
                    .get(http::header::LOCATION)
                    .and_then(|v| v.to_str().ok()),
                Some("/wp-admin/?tab=general")
            );
        }
        TryFilesOutcome::InternalRewrite(target) => {
            return Err(format!(
                "expected 301 redirect for GET /wp-admin without slash, got rewrite {target}"
            )
            .into());
        }
    }

    // 3. `GET /wp-admin/?tab=general` (with trailing slash) still rewrites to `/wp-admin/index.php?tab=general`.
    match server
        .serve_try_files_canonical_filtered(
            &Method::GET,
            "/wp-admin/",
            Some("tab=general"),
            &HeaderMap::new(),
            &candidates,
            &forbidden,
        )
        .await
    {
        TryFilesOutcome::InternalRewrite(target) => {
            assert_eq!(target, "/wp-admin/index.php?tab=general");
        }
        TryFilesOutcome::Response(resp)
        | TryFilesOutcome::FallbackResponse { response: resp, .. } => {
            return Err(format!(
                "expected GET /wp-admin/ InternalRewrite, got status {}",
                resp.status()
            )
            .into());
        }
    }

    Ok(())
}

/// R4-HTTP-4:
/// - Fallback try-files candidate `"/app/"` MUST NOT emit a 301 redirect built from an attacker's
///   missing request path (such as `/%09/evil.example` -> open redirect `/\t/evil.example/`).
/// - Non-ASCII and special-character (`%`, `?`, `#`) directory names emit valid RFC 3986
///   percent-encoded `Location` headers on trailing-slash 301 redirects.
#[tokio::test]
async fn round4_try_files_redirect_fallback_open_redirect_and_non_ascii_percent_encoding()
-> TestResult {
    let tmp = TempDir::new("r4-http4-redirect")?;
    fs::create_dir_all(tmp.path.join("app"))?;
    fs::write(tmp.path.join("app").join("index.php"), b"<?php echo 'app';")?;
    fs::create_dir_all(tmp.path.join("caf\u{00e9}"))?;
    fs::write(
        tmp.path.join("caf\u{00e9}").join("index.php"),
        b"<?php echo 'cafe';",
    )?;
    fs::create_dir_all(tmp.path.join("dir%25name"))?;
    fs::write(
        tmp.path.join("dir%25name").join("index.php"),
        b"<?php echo 'pct';",
    )?;

    let server = StaticServer::open(
        &tmp.path,
        StaticConfig {
            index: vec!["index.php".to_owned()],
            ..StaticConfig::default()
        },
    )?
    .with_forbidden_extensions([".php".to_owned()]);
    let forbidden = vec![".php".to_owned()];

    // 1. Fallback template `"/app/"` on missing path `/\t/evil.example` (decoded `/%09/evil.example`)
    //    MUST NOT emit a 301 redirect to `/\t/evil.example/` — it rewrites to `/app/index.php`!
    let fallback_candidates = vec!["{path}".to_owned(), "/app/".to_owned()];
    match server
        .serve_try_files_canonical_filtered(
            &Method::GET,
            "/\t/evil.example",
            None,
            &HeaderMap::new(),
            &fallback_candidates,
            &forbidden,
        )
        .await
    {
        TryFilesOutcome::InternalRewrite(target) => {
            assert_eq!(target, "/app/index.php");
        }
        TryFilesOutcome::Response(resp)
        | TryFilesOutcome::FallbackResponse { response: resp, .. } => {
            return Err(format!(
                "fallback /app/ must NOT redirect missing path (got status {}, loc {:?})",
                resp.status(),
                resp.headers().get(http::header::LOCATION)
            )
            .into());
        }
    }

    // 2. Non-ASCII directory `/café` emits 301 with valid ASCII percent-encoded `Location: /caf%C3%A9/`.
    let std_candidates = vec!["{path}".to_owned(), "{path}/".to_owned(), "=404".to_owned()];
    match server
        .serve_try_files_canonical_filtered(
            &Method::GET,
            "/caf\u{00e9}",
            Some("a=1"),
            &HeaderMap::new(),
            &std_candidates,
            &forbidden,
        )
        .await
    {
        TryFilesOutcome::Response(resp)
        | TryFilesOutcome::FallbackResponse { response: resp, .. } => {
            assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
            assert_eq!(
                resp.headers()
                    .get(http::header::LOCATION)
                    .and_then(|v| v.to_str().ok()),
                Some("/caf%C3%A9/?a=1")
            );
        }
        TryFilesOutcome::InternalRewrite(target) => {
            return Err(format!("expected 301 for /café, got rewrite {target}").into());
        }
    }

    // 3. Literal `%` in directory name (`dir%25name`) is percent-encoded so browsers round-trip cleanly.
    match server
        .serve_try_files_canonical_filtered(
            &Method::GET,
            "/dir%25name",
            None,
            &HeaderMap::new(),
            &std_candidates,
            &forbidden,
        )
        .await
    {
        TryFilesOutcome::Response(resp)
        | TryFilesOutcome::FallbackResponse { response: resp, .. } => {
            assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
            assert_eq!(
                resp.headers()
                    .get(http::header::LOCATION)
                    .and_then(|v| v.to_str().ok()),
                Some("/dir%2525name/")
            );
        }
        TryFilesOutcome::InternalRewrite(target) => {
            return Err(format!("expected 301 for /dir%25name, got rewrite {target}").into());
        }
    }

    Ok(())
}

/// R5-MIG-1 server-side default defense-in-depth: a bare `StaticServer::open()` with NO
/// `with_forbidden_extensions()` call MUST still refuse `.php`, `.phtml`, `.phar`, and `.phps`
/// (direct files, directory index `index.php`, and symlinks), while `exists_regular_file` still
/// returns `true` for FastCGI `PATH-6` verification.
#[tokio::test]
async fn round5_default_refuses_php_phtml_phar_phps_without_fastcgi_route() -> TestResult {
    let dir = TempDir::new("r5-default-php")?;
    let root = &dir.path;
    fs::write(root.join("index.html"), b"<h1>Safe HTML</h1>")?;
    fs::write(root.join("index.php"), b"<?php echo 'SECRET_INDEX'; ?>")?;
    fs::write(root.join("config.php"), b"<?php $pw = 'SECRET_CFG'; ?>")?;
    fs::write(root.join("shell.phtml"), b"<?php system($_GET['c']); ?>")?;
    fs::write(root.join("pkg.phar"), b"<?php __HALT_COMPILER(); ?>")?;
    fs::write(root.join("view.phps"), b"<?php echo 'SECRET_PHPS'; ?>")?;

    let server = StaticServer::open(
        root,
        StaticConfig {
            index: vec!["index.php".to_owned(), "index.html".to_owned()],
            ..StaticConfig::default()
        },
    )?;

    for path in [
        "/config.php",
        "/index.php",
        "/shell.phtml",
        "/pkg.phar",
        "/view.phps",
    ] {
        let resp = server.serve(&Method::GET, path, &HeaderMap::new()).await;
        assert_ne!(
            resp.status(),
            StatusCode::OK,
            "default StaticServer must NEVER serve {path} as static text (R5-MIG-1)"
        );
        let body = resp.into_body().collect().await?.to_bytes();
        assert!(
            !body.windows(5).any(|w| w == b"<?php"),
            "PHP source leaked on {path}!"
        );
    }

    let idx_resp = server.serve(&Method::GET, "/", &HeaderMap::new()).await;
    assert_eq!(idx_resp.status(), StatusCode::OK);
    let idx_body = idx_resp.into_body().collect().await?.to_bytes();
    assert_eq!(idx_body.as_ref(), b"<h1>Safe HTML</h1>");

    assert!(server.exists_regular_file("/index.php"));
    Ok(())
}

/// R6-STA-1 & R5-MIG-1 (server-side): Verifies default static refusal covers extended PHP
/// extensions (`.php5`, `.php7`, `.php8`, `.pht`, `.phpt`, `.inc`), direct requests for
/// precompressed script copies (`x.php.gz`, `x.php.br`, `x.php.zst`, `x.php5.gz`), multi-hop
/// symlink chains (`a.txt -> b.txt -> secret.php`), symlink loops, and multi-hop dotfile
/// symlinks (`d1.txt -> d2.txt -> .env`), while continuing to serve benign compressed files
/// (`app.js.gz`) and multi-hop symlinks to regular static content.
#[tokio::test]
async fn r6_sta_1_blocks_extended_php_extensions_compressed_copies_and_multihop_symlinks()
-> TestResult {
    let dir = TempDir::new("r6-sta-1")?;
    let root = &dir.path;
    fs::write(root.join("public.txt"), b"hello-static")?;
    fs::write(root.join("app.js.gz"), b"fake-gzip-js")?;
    fs::write(root.join(".env"), b"DB_PASS=secret")?;
    fs::write(root.join("secret.php"), b"<?php echo 'SECRET'; ?>")?;
    for ext in ["php5", "php7", "php8", "pht", "phpt", "inc"] {
        fs::write(root.join(format!("x.{ext}")), b"<?php echo 'LEAK'; ?>")?;
    }
    for compressed in ["x.php.gz", "x.php.br", "x.php.zst", "x.php5.gz"] {
        fs::write(root.join(compressed), b"<?php echo 'COMPRESSED_LEAK'; ?>")?;
    }

    #[cfg(unix)]
    {
        // Two-hop symlink to `.php`
        std::os::unix::fs::symlink("secret.php", root.join("hop1.txt"))?;
        std::os::unix::fs::symlink("hop1.txt", root.join("hop2.txt"))?;
        // Two-hop symlink to `.env`
        std::os::unix::fs::symlink(".env", root.join("dot1.txt"))?;
        std::os::unix::fs::symlink("dot1.txt", root.join("dot2.txt"))?;
        // Symlink loop
        std::os::unix::fs::symlink("loop2.txt", root.join("loop1.txt"))?;
        std::os::unix::fs::symlink("loop1.txt", root.join("loop2.txt"))?;
        // Benign two-hop symlink to regular static file
        std::os::unix::fs::symlink("public.txt", root.join("ok1.txt"))?;
        std::os::unix::fs::symlink("ok1.txt", root.join("ok2.txt"))?;
    }

    let server = StaticServer::open(root, StaticConfig::default())?;

    for blocked in [
        "/x.php5",
        "/x.php7",
        "/x.php8",
        "/x.pht",
        "/x.phpt",
        "/x.inc",
        "/x.php.gz",
        "/x.php.br",
        "/x.php.zst",
        "/x.php5.gz",
    ] {
        let resp = server.serve(&Method::GET, blocked, &HeaderMap::new()).await;
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "default static server must refuse {blocked} with 404 (R6-STA-1)"
        );
    }

    // Benign `.js.gz` requested directly still works!
    let js_gz = server
        .serve(&Method::GET, "/app.js.gz", &HeaderMap::new())
        .await;
    assert_eq!(js_gz.status(), StatusCode::OK);

    #[cfg(unix)]
    {
        for blocked_link in ["/hop2.txt", "/dot2.txt", "/loop1.txt"] {
            let resp = server
                .serve(&Method::GET, blocked_link, &HeaderMap::new())
                .await;
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "multi-hop symlink {blocked_link} must be refused (R6-STA-1)"
            );
        }

        let ok_link = server
            .serve(&Method::GET, "/ok2.txt", &HeaderMap::new())
            .await;
        assert_eq!(ok_link.status(), StatusCode::OK);
        assert_eq!(
            ok_link.into_body().collect().await?.to_bytes().as_ref(),
            b"hello-static"
        );
    }

    Ok(())
}

/// R7-STA-1 & R7-STA-2: Refuses backup/editor/archive copies of PHP and `.inc` files in ANY
/// non-final dot position, trailing `~`/`_`, Windows trailing-space (`x.php%20`) and NTFS ADS
/// (`x.php::$DATA`) spellings, symlinks targeting them, and default-denied private keys, backups,
/// and `composer.json`/`composer.lock` while preserving normal static files.
#[tokio::test]
async fn r7_sta_1_blocks_script_backups_secrets_and_windows_ads_trailing_space() -> TestResult {
    let dir = TempDir::new("r7-sta-1")?;
    let root = &dir.path;
    fs::write(root.join("php-guide.html"), b"<h1>PHP Guide</h1>")?;
    fs::write(root.join("app.min.js"), b"console.log(1);")?;

    let blocked_files = [
        "wp-config.php.bak",
        "x.php~",
        "x.php.orig",
        "x.php.swp",
        "x.php.swo",
        "x.php.save",
        "x.php.old",
        "x.php.1",
        "x.php.bz2",
        "x.php.xz",
        "x.php.zip",
        "x.php.tar",
        "x.php_",
        "x.php.dist",
        "x.php.sample",
        "x.php.tmp",
        "x.php.txt",
        "x.php.gz.bak",
        "x.php.bak.gz",
        "x.inc.bak",
        "server.key",
        "x.bundle.pem",
        "cert.pem.gz",
        "index.html~",
        "notes.bak",
        "composer.json",
        "composer.lock",
    ];
    for name in blocked_files {
        fs::write(root.join(name), b"SECRET <?php echo 1; ?>")?;
    }

    #[cfg(unix)]
    {
        fs::write(root.join("x.php "), b"SECRET SPACE")?;
        fs::write(root.join("x.php::$DATA"), b"SECRET ADS")?;
        std::os::unix::fs::symlink("wp-config.php.bak", root.join("link-php-bak.txt"))?;
        std::os::unix::fs::symlink("server.key", root.join("link-key.txt"))?;
    }

    let server = StaticServer::open(root, StaticConfig::default())?;
    for name in blocked_files {
        let req_path = format!("/{name}");
        let resp = server
            .serve(&Method::GET, &req_path, &HeaderMap::new())
            .await;
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "R7-STA-1: static server must refuse {req_path} with 404"
        );
    }

    #[cfg(unix)]
    {
        for special in [
            "/x.php%20",
            "/x.php::$DATA",
            "/link-php-bak.txt",
            "/link-key.txt",
        ] {
            let resp = server.serve(&Method::GET, special, &HeaderMap::new()).await;
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "R7-STA-1/R7-STA-2: static server must refuse {special} with 404"
            );
        }
    }

    // Benign static assets whose base name merely contains `php` remain servable.
    for ok_path in ["/php-guide.html", "/app.min.js"] {
        let resp = server.serve(&Method::GET, ok_path, &HeaderMap::new()).await;
        assert_eq!(resp.status(), StatusCode::OK, "{ok_path} should stay 200");
    }
    Ok(())
}

/// R8-STA-1/2/3/4: the deny rule is one token rule, not a list of spellings. A script or secret
/// extension followed by ANY non-alphanumeric byte (or the end of the name) is refused; a name
/// that is a rendered asset (`index.php.html`, `header.inc.html`, `report.php.pdf`) is served;
/// a `:` in a Unix filename does not hide the rest of the name from the rules.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn r8_sta_1_script_extension_token_rule_blocks_every_separator_and_keeps_rendered_assets()
-> TestResult {
    let dir = TempDir::new("r8-sta-1")?;
    let root = &dir.path;

    let blocked_files = [
        // R8-STA-1: non-dot separators after the script extension.
        "wp-config.php-old",
        "wp-config.php_bak",
        "wp-config.php-2024",
        "x.php-bak",
        "x.php,v",
        "#x.php#",
        "x.php#bak",
        "x.php copy",
        "x.php(1)",
        "x.php;.jpg",
        "x.php@2x",
        "x.php+old",
        "x.php=",
        "x.phtml-old",
        "x.inc-old",
        // A rendered-asset extension only exempts the name when it is the whole remainder.
        "x.php.bak.html",
        "x.php-old.html",
        "x.php.html.bak",
        // R8-STA-4: secrets as a token, dumps and key stores.
        "server.key.1",
        "server.key.txt",
        "server.key-old",
        "cert.pem.bak",
        "id_rsa",
        "id_ed25519",
        "dump.sql",
        "dump.sql.gz",
        "db.sqlite",
        "store.p12",
        "store.pfx",
        "store.jks",
        "vault.kdbx",
        "web.config",
        // Editor autosave and lock files.
        "#index.html#",
        ".#index.html",
    ];
    for name in blocked_files {
        fs::write(root.join(name), b"SECRET <?php echo 1; ?>")?;
    }
    #[cfg(unix)]
    {
        // R8-STA-2: a colon must not truncate the name before the rules run.
        fs::write(root.join("a:x.php.bak"), b"SECRET COLON")?;
        fs::write(root.join("a:server.key"), b"SECRET COLON KEY")?;
        fs::write(root.join("x.php::$DATA"), b"SECRET ADS")?;
    }

    let allowed_files = [
        // R8-STA-3: rendered assets and ordinary names stay servable.
        "index.php.html",
        "header.inc.html",
        "file.inc.js",
        "report.php.pdf",
        "cheatsheet.php.png",
        "php-guide.html",
        "my.python.notes.txt",
        "x.phpx",
        "app.old.css",
        "jquery.min.js",
        "a.b.c.png",
        "keynote-slides.html",
        "robots.txt",
    ];
    for name in allowed_files {
        fs::write(root.join(name), b"ok")?;
    }

    let server = StaticServer::open(root, StaticConfig::default())?;
    for name in blocked_files {
        let req_path = format!(
            "/{}",
            name.replace('#', "%23")
                .replace(' ', "%20")
                .replace(';', "%3B")
        );
        let resp = server
            .serve(&Method::GET, &req_path, &HeaderMap::new())
            .await;
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "R8-STA-1/4: static server must refuse {name:?} ({req_path}) with 404"
        );
    }
    #[cfg(unix)]
    {
        // A literal `?` in a file or directory name is part of the name. The deny rules must
        // see the real leaf, not the name cut at the `?`.
        fs::write(root.join("notes?.sql"), b"SECRET QMARK")?;
        fs::write(root.join("x?.php.bak"), b"SECRET QMARK PHP")?;
        fs::create_dir_all(root.join("d?x"))?;
        fs::write(root.join("d?x/dump.sql"), b"SECRET QMARK DIR")?;
        fs::write(root.join("d?x/ok.txt"), b"ok")?;
        let server = StaticServer::open(root, StaticConfig::default())?;
        for special in ["/notes%3F.sql", "/x%3F.php.bak", "/d%3Fx/dump.sql"] {
            let resp = server.serve(&Method::GET, special, &HeaderMap::new()).await;
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "static server must refuse {special} (literal `?` in the path) with 404"
            );
        }
        let resp = server
            .serve(&Method::GET, "/d%3Fx/ok.txt", &HeaderMap::new())
            .await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "an ordinary file in a directory whose name contains `?` stays servable"
        );
    }
    #[cfg(unix)]
    for special in ["/a:x.php.bak", "/a:server.key", "/x.php::$DATA"] {
        let resp = server.serve(&Method::GET, special, &HeaderMap::new()).await;
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "R8-STA-2: static server must refuse {special} with 404"
        );
    }
    for name in allowed_files {
        let req_path = format!("/{name}");
        let resp = server
            .serve(&Method::GET, &req_path, &HeaderMap::new())
            .await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "R8-STA-3: {req_path} is a legitimate static file and must stay 200"
        );
    }
    Ok(())
}

/// With `try-files "{path}" "{path}/" "=404"` and a document root holding `index.php`, `/` must
/// resolve to `/index.php` just as `/sub/` resolves to `/sub/index.php`.
#[tokio::test]
async fn try_files_resolves_script_index_for_the_site_root_like_a_subdirectory() -> TestResult {
    let tmp = TempDir::new("root-idx")?;
    fs::create_dir_all(tmp.path.join("sub"))?;
    fs::write(tmp.path.join("index.php"), b"<?php echo 'root';")?;
    fs::write(tmp.path.join("sub").join("index.php"), b"<?php echo 'sub';")?;
    let server = StaticServer::open(&tmp.path, StaticConfig::default())?
        .with_forbidden_extensions([".php".to_owned()]);
    let candidates = vec!["{path}".to_owned(), "{path}/".to_owned(), "=404".to_owned()];
    let forbidden = vec![".php".to_owned()];

    for (request, expected) in [("/", "/index.php"), ("/sub/", "/sub/index.php")] {
        match server
            .serve_try_files_canonical_filtered(
                &Method::GET,
                request,
                None,
                &HeaderMap::new(),
                &candidates,
                &forbidden,
            )
            .await
        {
            TryFilesOutcome::InternalRewrite(target) => assert_eq!(
                target, expected,
                "GET {request} must be handed to its directory's index script"
            ),
            TryFilesOutcome::Response(resp)
            | TryFilesOutcome::FallbackResponse { response: resp, .. } => {
                return Err(format!(
                    "GET {request} must rewrite to {expected}, got status {}",
                    resp.status()
                )
                .into());
            }
        }
    }
    Ok(())
}

/// Codex G2: `read_no_symlink_file` must resolve component-by-component from the root directory
/// descriptor with `O_DIRECTORY | O_NOFOLLOW` so neither static symlinked ancestors nor concurrent
/// ancestor directory renames/symlink swaps can ever read another tenant's file.
#[cfg(unix)]
#[test]
fn g2_read_no_symlink_file_resists_ancestor_symlink_and_concurrent_swap() -> TestResult {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let tmp = TempDir::new("g2-ancestor-race")?;
    let tenant_a_real = tmp.path.join("tenant-a-real");
    let tenant_b = tmp.path.join("tenant-b");
    fs::create_dir_all(tenant_a_real.join("errors"))?;
    fs::create_dir_all(tenant_b.join("errors"))?;
    fs::write(tenant_a_real.join("errors/404.html"), b"TENANT-A-404")?;
    fs::write(tenant_b.join("errors/404.html"), b"TENANT-B-SECRET")?;

    // 1. Static symlinked ancestor is rejected.
    let link_ancestor = tmp.path.join("link-ancestor");
    std::os::unix::fs::symlink(&tenant_b, &link_ancestor)?;
    let static_err =
        miraserve_static::read_no_symlink_file(&link_ancestor.join("errors/404.html"), 64 * 1024);
    assert!(
        static_err.is_err(),
        "symlinked ancestor directory must be refused"
    );

    // 2. Concurrent ancestor swap race: rapidly swap `active` between a real directory containing
    //    TENANT-A-404 and a symlink pointing to `tenant-b` (TENANT-B-SECRET) while calling
    //    `read_no_symlink_file` in a tight loop. Not a single read may ever return TENANT-B-SECRET!
    let active = tmp.path.join("active");
    let parked_real = tmp.path.join("parked-real");
    let symlink_staging = tmp.path.join("symlink-staging");
    fs::rename(&tenant_a_real, &active)?;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_swapper = Arc::clone(&stop);
    let active_s = active.clone();
    let parked_s = parked_real.clone();
    let sym_s = symlink_staging.clone();
    let target_b = tenant_b.clone();

    let swapper = std::thread::spawn(move || {
        while !stop_swapper.load(Ordering::Acquire) {
            let _ = fs::remove_file(&sym_s);
            let _ = std::os::unix::fs::symlink(&target_b, &sym_s);
            if fs::rename(&active_s, &parked_s).is_ok() {
                let _ = fs::rename(&sym_s, &active_s);
                std::thread::yield_now();
                let _ = fs::remove_file(&active_s);
                let _ = fs::rename(&parked_s, &active_s);
            }
            std::thread::yield_now();
        }
    });

    let target_file = active.join("errors/404.html");
    let mut ok_reads = 0_usize;
    let mut rejected_reads = 0_usize;
    for _ in 0..400 {
        match miraserve_static::read_no_symlink_file(&target_file, 64 * 1024) {
            Ok(bytes) => {
                assert_eq!(
                    bytes.as_slice(),
                    b"TENANT-A-404",
                    "ancestor swap race MUST NEVER leak another tenant's file"
                );
                ok_reads = ok_reads.saturating_add(1);
            }
            Err(_) => {
                rejected_reads = rejected_reads.saturating_add(1);
            }
        }
    }
    stop.store(true, Ordering::Release);
    let _ = swapper.join();
    assert!(
        ok_reads > 0 || rejected_reads > 0,
        "expected loop iterations to execute"
    );
    Ok(())
}

/// Codex G2 (Windows P1): On native Windows, `read_no_symlink_file` opens every ancestor
/// directory and leaf file with `FILE_FLAG_OPEN_REPARSE_POINT` and validates the opened handle's
/// `FILE_ATTRIBUTE_REPARSE_POINT` attribute directly, loading regular pages while rejecting
/// symlinked ancestors and leaf symlinks.
#[cfg(windows)]
#[test]
fn g2_windows_read_no_symlink_file_loads_regular_and_rejects_ancestor_or_leaf_symlinks()
-> TestResult {
    let tmp = TempDir::new("g2-win-reparse")?;
    let tenant_a = tmp.path.join("tenant-a");
    let tenant_b = tmp.path.join("tenant-b");
    fs::create_dir_all(tenant_a.join("errors"))?;
    fs::create_dir_all(tenant_b.join("errors"))?;
    let regular_page = tenant_a.join("errors").join("404.html");
    let secret_page = tenant_b.join("errors").join("404.html");
    fs::write(&regular_page, b"TENANT-A-404")?;
    fs::write(&secret_page, b"TENANT-B-SECRET")?;

    // 1. Regular absolute file loads cleanly.
    let ok = miraserve_static::read_no_symlink_file(&regular_page, 64 * 1024)?;
    assert_eq!(ok.as_slice(), b"TENANT-A-404");

    // 2. Ancestor directory symlink is rejected (when privilege/Developer Mode allows creation).
    let ancestor_link = tmp.path.join("ancestor-link");
    if std::os::windows::fs::symlink_dir(&tenant_b, &ancestor_link).is_ok() {
        let err = miraserve_static::read_no_symlink_file(
            &ancestor_link.join("errors").join("404.html"),
            64 * 1024,
        );
        assert!(
            err.is_err(),
            "Windows symlinked ancestor directory must be refused"
        );
    }

    // 3. Leaf file symlink is rejected.
    let leaf_link = tenant_a.join("errors").join("leaf-link.html");
    if std::os::windows::fs::symlink_file(&secret_page, &leaf_link).is_ok() {
        let err = miraserve_static::read_no_symlink_file(&leaf_link, 64 * 1024);
        assert!(err.is_err(), "Windows leaf file symlink must be refused");
    }

    Ok(())
}

/// Compressed bodies are cached per file state. A repeated request gets the same body, and an
/// edited file (new length or modification time) is compressed afresh, never served from the
/// copy made for the old content.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn compressed_response_cache_follows_file_changes() -> TestResult {
    async fn gzip_get(
        server: &StaticServer,
    ) -> Result<(String, String), Box<dyn std::error::Error>> {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
        let resp = server.serve(&Method::GET, "/page.css", &headers).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok()),
            Some("gzip")
        );
        let etag = resp
            .headers()
            .get(ETAG)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let body = resp.into_body().collect().await?.to_bytes();
        let mut text = String::new();
        GzDecoder::new(&body[..]).read_to_string(&mut text)?;
        Ok((text, etag))
    }

    let tmp = TempDir::new("compress-cache")?;
    let file = tmp.path.join("page.css");
    let first = "body { color: red }\n".repeat(200);
    fs::write(&file, &first)?;
    let server = StaticServer::open(&tmp.path, StaticConfig::default())?;

    let (text_a, etag_a) = gzip_get(&server).await?;
    assert_eq!(text_a, first);
    let (text_b, etag_b) = gzip_get(&server).await?;
    assert_eq!(
        (text_b.as_str(), etag_b.as_str()),
        (first.as_str(), etag_a.as_str())
    );

    // Same length, different content, later modification time.
    let second = first.replace("red", "tan");
    assert_eq!(second.len(), first.len());
    fs::write(&file, &second)?;
    let later = SystemTime::now() + std::time::Duration::from_secs(5);
    fs::File::options()
        .write(true)
        .open(&file)?
        .set_modified(later)?;
    let (text_c, etag_c) = gzip_get(&server).await?;
    assert_eq!(
        text_c, second,
        "an edited file must not be served from the cache"
    );
    // No tag at all where the platform has no inode change time (Windows); a new one elsewhere.
    assert!(etag_c.is_empty() || etag_c != etag_a);

    // Same length, different content, and the OLD modification time put back (what `rsync -t`,
    // `tar` or `touch -d` produce). The inode change time still differs, so this is new content.
    let original_mtime = fs::metadata(&file)?.modified()?;
    let restored = second.replace("tan", "sky");
    assert_eq!(restored.len(), second.len());
    fs::write(&file, &restored)?;
    fs::File::options()
        .write(true)
        .open(&file)?
        .set_modified(original_mtime)?;
    let (text_r, etag_r) = gzip_get(&server).await?;
    assert_eq!(
        text_r, restored,
        "same size and a restored modification time must not hit the old cache entry"
    );
    // Where the platform gives no inode change time no tag is sent at all (both are empty);
    // everywhere else the tag must change.
    assert!(
        etag_r.is_empty() || etag_r != etag_c,
        "the validator must change too, or a client revalidating with the old one gets 304"
    );

    // Review after 17ec17b: a client revalidating with the previous validator gets the new
    // content, not 304, and a resumed download with it gets the whole new file, not a range of
    // it spliced onto the old one.
    let mut revalidate = HeaderMap::new();
    revalidate.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
    revalidate.insert(IF_NONE_MATCH, HeaderValue::from_str(&etag_c)?);
    let resp = server.serve(&Method::GET, "/page.css", &revalidate).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let identity_old = server
        .serve(&Method::GET, "/page.css", &HeaderMap::new())
        .await;
    let identity_tag = identity_old
        .headers()
        .get(ETAG)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let mut resume = HeaderMap::new();
    resume.insert(RANGE, HeaderValue::from_static("bytes=10-19"));
    resume.insert(
        http::header::IF_RANGE,
        HeaderValue::from_str(&identity_tag)?,
    );
    // With a current tag a resume is a range; without any tag there is nothing to resume with.
    let expected_resume = if identity_tag.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::PARTIAL_CONTENT
    };
    assert_eq!(
        server
            .serve(&Method::GET, "/page.css", &resume)
            .await
            .status(),
        expected_resume,
        "the current tag still allows resuming"
    );
    let content = format!("{restored}/* edit */");
    let same_size = content
        .get(..restored.len())
        .unwrap_or("")
        .replace("sky", "sea");
    fs::write(&file, &same_size)?;
    fs::File::options()
        .write(true)
        .open(&file)?
        .set_modified(original_mtime)?;
    assert_eq!(
        server
            .serve(&Method::GET, "/page.css", &resume)
            .await
            .status(),
        StatusCode::OK,
        "an old tag after a same-size, same-mtime edit must give the whole new file"
    );
    let mut by_date = HeaderMap::new();
    by_date.insert(RANGE, HeaderValue::from_static("bytes=10-19"));
    by_date.insert(
        http::header::IF_RANGE,
        HeaderValue::from_str(&httpdate::fmt_http_date(original_mtime))?,
    );
    assert_eq!(
        server
            .serve(&Method::GET, "/page.css", &by_date)
            .await
            .status(),
        StatusCode::OK,
        "a date in If-Range proves nothing once mtimes can be restored"
    );

    // A longer file.
    let third = format!("{same_size}/* more */\n");
    fs::write(&file, &third)?;
    let (text_d, _) = gzip_get(&server).await?;
    assert_eq!(text_d, third);
    Ok(())
}

/// Review of section 4d: conditional headers that are present but not plain text (an opaque
/// entity tag issued by another server) are conditions that fail, not absent ones: no range is
/// served on them and the date is not consulted instead.
#[tokio::test]
async fn opaque_conditional_headers_never_grant_a_range_or_a_304() -> TestResult {
    let tmp = TempDir::new("opaque-tags")?;
    fs::write(tmp.path.join("file.bin"), vec![7_u8; 4096])?;
    let server = StaticServer::open(&tmp.path, StaticConfig::default())?;

    let mut range = HeaderMap::new();
    range.insert(RANGE, HeaderValue::from_static("bytes=0-9"));
    range.insert(
        http::header::IF_RANGE,
        HeaderValue::from_bytes(b"\"old-origin-\xe9t\xe9\"")?,
    );
    let resp = server.serve(&Method::GET, "/file.bin", &range).await;
    assert_eq!(resp.status(), StatusCode::OK, "full file, not a range");

    let mut revalidate = HeaderMap::new();
    revalidate.insert(IF_NONE_MATCH, HeaderValue::from_bytes(b"\"\xe9\"")?);
    revalidate.insert(
        http::header::IF_MODIFIED_SINCE,
        HeaderValue::from_static("Fri, 01 Jan 2100 00:00:00 GMT"),
    );
    let resp = server.serve(&Method::GET, "/file.bin", &revalidate).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "If-None-Match decides alone; a non-matching opaque tag is not a 304"
    );
    Ok(())
}

/// Review of section 4e: `If-None-Match` is a list of quoted tags; commas and `*` inside a tag
/// belong to it, and one unreadable member does not hide a matching one.
#[tokio::test]
async fn if_none_match_list_is_parsed_by_quoted_members() -> TestResult {
    let tmp = TempDir::new("inm-list")?;
    fs::write(tmp.path.join("a.txt"), b"current")?;
    let server = StaticServer::open(&tmp.path, StaticConfig::default())?;
    let current = server
        .serve(&Method::GET, "/a.txt", &HeaderMap::new())
        .await;
    let tag = current
        .headers()
        .get(ETAG)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    if tag.is_empty() {
        // No entity tag on this platform: nothing to match.
        return Ok(());
    }
    let status = |value: &[u8]| -> Result<HeaderMap, Box<dyn std::error::Error>> {
        let mut headers = HeaderMap::new();
        headers.insert(IF_NONE_MATCH, HeaderValue::from_bytes(value)?);
        Ok(headers)
    };

    let stale = status(b"\"old,*,tag\"")?;
    assert_eq!(
        server.serve(&Method::GET, "/a.txt", &stale).await.status(),
        StatusCode::OK,
        "a stale tag containing a comma and an asterisk is not a wildcard"
    );
    let mut mixed = b"\"\xe9t\xe9\", ".to_vec();
    mixed.extend_from_slice(tag.as_bytes());
    assert_eq!(
        server
            .serve(&Method::GET, "/a.txt", &status(&mixed)?)
            .await
            .status(),
        StatusCode::NOT_MODIFIED,
        "the current tag matches although an earlier member is not text"
    );
    let weak = format!("W/{tag}");
    assert_eq!(
        server
            .serve(&Method::GET, "/a.txt", &status(weak.as_bytes())?)
            .await
            .status(),
        StatusCode::NOT_MODIFIED
    );
    assert_eq!(
        server
            .serve(&Method::GET, "/a.txt", &status(b" * ")?)
            .await
            .status(),
        StatusCode::NOT_MODIFIED
    );
    Ok(())
}

/// Review 29: a decoded `?` (from `%3F`) in a rewrite destination stays part of the path; the
/// first `?` of the target is always the query separator.
#[test]
fn rewrite_target_keeps_decoded_question_marks_in_the_path() {
    let target = miraserve_static::rewrite_target("/a?b#c%d", Some("x=1"));
    assert_eq!(target, "/a%3Fb%23c%25d?x=1");
    let (path, query) = target.split_once('?').unwrap_or((target.as_str(), ""));
    assert_eq!(miraserve_static::decode_rewrite_path(path), "/a?b#c%d");
    assert_eq!(query, "x=1");
    assert_eq!(miraserve_static::rewrite_target("/plain", None), "/plain");
    assert_eq!(miraserve_static::decode_rewrite_path("/100%"), "/100%");
}

/// Review 30: an explicitly empty fallback query (`/index.php?`) stays empty instead of letting
/// the incoming query through; no query stays no query.
#[test]
fn rewrite_target_keeps_an_explicitly_empty_query() {
    assert_eq!(
        miraserve_static::rewrite_target("/index.php", Some("")),
        "/index.php?"
    );
    assert_eq!(
        miraserve_static::rewrite_target("/index.php", None),
        "/index.php"
    );
}

/// Review 30: a credential named directly in the ACME challenge directory reserves its name even
/// while the file is missing (restoring it later never makes it answerable); one in a
/// subdirectory or elsewhere reserves nothing.
#[test]
fn reserved_acme_tokens_cover_missing_credentials() -> Result<(), Box<dyn std::error::Error>> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let challenges = std::env::temp_dir()
        .join(format!("miraserve-reserved-{}-{nanos}", std::process::id()))
        .join(".well-known")
        .join("acme-challenge");
    std::fs::create_dir_all(challenges.join("certs"))?;
    // A key configured through a link elsewhere whose (missing) target is in the directory.
    let elsewhere = challenges
        .parent()
        .and_then(std::path::Path::parent)
        .map(|base| base.join("keys"))
        .ok_or("base")?;
    std::fs::create_dir_all(&elsewhere)?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(challenges.join("linked_key"), elsewhere.join("site.pem"))?;
    let reserved = miraserve_static::reserved_acme_tokens(
        &challenges,
        &[
            challenges.join("site_key"),
            challenges.join("site.key"),
            challenges.join("certs").join("other_key"),
            elsewhere.join("site.pem"),
            std::path::PathBuf::from("/etc/miraserve/auth/site.htpasswd"),
        ],
    );
    assert!(reserved.contains("site_key"));
    // `site.key` can never be a token, so it reserves nothing.
    assert!(!reserved.contains("site.key"));
    #[cfg(unix)]
    assert!(
        reserved.contains("linked_key"),
        "link target reserved: {reserved:?}"
    );
    if let Some(base) = challenges.parent().and_then(std::path::Path::parent) {
        let _ = std::fs::remove_dir_all(base);
    }
    Ok(())
}

/// A request still running with an older configuration does not serve a hard link of a
/// credential a newer configuration uses (Codex 66 and 67 P1 1), and only while one uses it;
/// other files with several names are served.
#[tokio::test]
async fn published_credentials_count_for_other_configurations() -> TestResult {
    let tmp = TempDir::new("published")?;
    let root = tmp.path.join("root");
    fs::create_dir_all(&root)?;
    let users = tmp.path.join("users");
    fs::write(&users, "ann:hash")?;
    fs::hard_link(&users, root.join("users.txt"))?;
    fs::write(root.join("page.txt"), "page")?;
    fs::hard_link(root.join("page.txt"), root.join("other.txt"))?;
    let old = StaticServer::open(&root, StaticConfig::default())?;
    let status = |path: &'static str| {
        let old = &old;
        async move {
            old.serve(&Method::GET, path, &HeaderMap::new())
                .await
                .status()
        }
    };
    assert_eq!(status("/users.txt").await, StatusCode::OK);
    let handles = [fs::File::open(&users)?];
    let newer = miraserve_static::handle_identities(&handles);
    miraserve_static::publish_secret_files(&newer);
    assert_eq!(status("/users.txt").await, StatusCode::NOT_FOUND);
    assert_eq!(status("/other.txt").await, StatusCode::OK);
    drop(newer);
    assert_eq!(status("/users.txt").await, StatusCode::OK);
    Ok(())
}

/// `try-files` on a site whose PHP no route runs: a leftover `index.php` is not served and does
/// not hide `index.html` either; with a PHP route it is the directory's index as before. The
/// path in a query template is data and cannot add parameters (Cloudflare-skills audit of
/// v0.1.0, claim 21).
#[tokio::test]
async fn try_files_chooses_a_script_index_only_when_scripts_are_routed() -> TestResult {
    let tmp = TempDir::new("routed-idx")?;
    fs::write(tmp.path.join("index.php"), b"<?php echo 'left over';")?;
    fs::write(tmp.path.join("index.html"), b"HTML INDEX")?;
    let config = StaticConfig {
        index: vec!["index.php".to_owned(), "index.html".to_owned()],
        ..StaticConfig::default()
    };
    let server =
        StaticServer::open(&tmp.path, config)?.with_forbidden_extensions([".php".to_owned()]);
    let candidates = vec!["{path}".to_owned(), "{path}/".to_owned(), "=404".to_owned()];
    let forbidden = vec![".php".to_owned()];
    let run = |routed: bool| {
        let (server, candidates, forbidden) = (&server, &candidates, &forbidden);
        async move {
            let runs_script: miraserve_static::ScriptOwner = std::sync::Arc::new(move |_| routed);
            server
                .serve_try_files_canonical_routed(
                    &Method::GET,
                    "/",
                    None,
                    &HeaderMap::new(),
                    candidates,
                    forbidden,
                    &runs_script,
                )
                .await
        }
    };
    match run(false).await {
        TryFilesOutcome::Response(resp)
        | TryFilesOutcome::FallbackResponse { response: resp, .. } => {
            assert_eq!(resp.status(), StatusCode::OK);
            let body = resp.into_body().collect().await?.to_bytes();
            assert_eq!(&body[..], b"HTML INDEX");
        }
        TryFilesOutcome::InternalRewrite(target) => {
            return Err(format!("no route runs PHP, yet rewritten to {target}").into());
        }
    }
    assert!(matches!(
        run(true).await,
        TryFilesOutcome::InternalRewrite(target) if target == "/index.php"
    ));

    let front = vec![
        "{path}".to_owned(),
        "/index.php?p={path}&{query}".to_owned(),
    ];
    let outcome = server
        .serve_try_files_canonical_routed(
            &Method::GET,
            "/a&admin=1 x",
            Some("q=1"),
            &HeaderMap::new(),
            &front,
            &forbidden,
            &(std::sync::Arc::new(|_: &str| true) as miraserve_static::ScriptOwner),
        )
        .await;
    assert!(
        matches!(&outcome, TryFilesOutcome::InternalRewrite(target)
            if target == "/index.php?p=/a%26admin%3D1%20x&q=1"),
        "{}",
        match &outcome {
            TryFilesOutcome::InternalRewrite(target) => target.clone(),
            TryFilesOutcome::Response(resp)
            | TryFilesOutcome::FallbackResponse { response: resp, .. } => resp.status().to_string(),
        }
    );
    Ok(())
}

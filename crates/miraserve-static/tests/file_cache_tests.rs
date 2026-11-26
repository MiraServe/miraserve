//! Comprehensive tests for the opt-in, time-bounded static file cache in `miraserve-static`.
//!
//! The tests of fills and hits are compiled for Linux and Android only: the cache admits a
//! response only when its file was opened by one whole-path kernel lookup, which exists on
//! those platforms alone; elsewhere nothing is ever stored (pinned by
//! `file_cache_without_link_free_lookup_tests` in `miraserve-static`). The other tests run everywhere.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[cfg_attr(
    not(any(target_os = "linux", target_os = "android")),
    allow(dead_code, unused_imports)
)]
use http::header::{
    ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG,
    IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, RANGE,
};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use http_body_util::BodyExt as _;
use miraserve_config::StaticConfig;
#[cfg_attr(
    not(any(target_os = "linux", target_os = "android")),
    allow(dead_code, unused_imports)
)]
use miraserve_static::{
    Conversion, FileCache, FileCacheBudget, FileCacheCounters, MAX_CACHE_KEY_BYTES, ManualClock,
    StaticBody, StaticServer, TryFilesOutcome, UNIDENTIFIED_CREDENTIAL, handle_identities,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

static TEST_SEQ: AtomicU64 = AtomicU64::new(1);

fn temp_root(label: &str) -> Result<PathBuf, std::io::Error> {
    let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let dir = std::env::temp_dir().join(format!(
        "miraserve-fc-{label}-{}-{seq}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

async fn read_body(
    resp: http::Response<StaticBody>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(resp.into_body().collect().await?.to_bytes().to_vec())
}

#[tokio::test]
async fn off_by_default_sees_every_change_on_very_next_request() -> TestResult {
    let root = temp_root("off-default")?;
    let path = root.join("live.txt");
    fs::write(&path, b"version-1")?;

    let server = StaticServer::open(&root, StaticConfig::default())?;
    let r1 = server
        .serve_canonical(&Method::GET, "/live.txt", &HeaderMap::new())
        .await;
    assert_eq!(r1.status(), StatusCode::OK);
    assert_eq!(read_body(r1).await?, b"version-1");

    // Replace content -> visible immediately on the very next request.
    fs::write(&path, b"version-2")?;
    let r2 = server
        .serve_canonical(&Method::GET, "/live.txt", &HeaderMap::new())
        .await;
    assert_eq!(r2.status(), StatusCode::OK);
    assert_eq!(read_body(r2).await?, b"version-2");

    // Delete -> 404 immediately on the very next request.
    fs::remove_file(&path)?;
    let r3 = server
        .serve_canonical(&Method::GET, "/live.txt", &HeaderMap::new())
        .await;
    assert_eq!(r3.status(), StatusCode::NOT_FOUND);

    let _ = fs::remove_dir_all(&root);
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn cached_file_touches_no_disk_inside_window_and_fixed_deadline_does_not_extend() -> TestResult
{
    let root = temp_root("fixed-deadline")?;
    let file = root.join("hello.txt");
    fs::write(&file, b"hello cached world")?;

    let clock = ManualClock::new();
    let budget = Arc::new(FileCacheBudget::new(1024 * 1024));
    let counters = FileCacheCounters::new();
    let cache = FileCache::with_clock(Arc::clone(&budget), counters.clone(), clock.cache_clock());
    let server = StaticServer::open(&root, StaticConfig::default())?
        .with_file_cache(Arc::clone(&cache), Duration::from_secs(1));

    // t = 0ms: miss + fill (deadline fixed at t = 1000ms).
    let r1 = server
        .serve_canonical(&Method::GET, "/hello.txt", &HeaderMap::new())
        .await;
    assert_eq!(r1.status(), StatusCode::OK);
    assert_eq!(read_body(r1).await?, b"hello cached world");
    assert_eq!(counters.snapshot(), (0, 1, 1, 0));

    // Delete the file from disk immediately after fill.
    fs::remove_file(&file)?;

    // t = 500ms: cache hit serves the same bytes without touching disk.
    clock.advance(Duration::from_millis(500));
    let r2 = server
        .serve_canonical(&Method::GET, "/hello.txt", &HeaderMap::new())
        .await;
    assert_eq!(r2.status(), StatusCode::OK);
    assert_eq!(read_body(r2).await?, b"hello cached world");
    assert_eq!(counters.snapshot(), (1, 1, 1, 0));

    // t = 999ms: still inside the original 1000ms window.
    clock.advance(Duration::from_millis(499));
    let r3 = server
        .serve_canonical(&Method::GET, "/hello.txt", &HeaderMap::new())
        .await;
    assert_eq!(r3.status(), StatusCode::OK);
    assert_eq!(read_body(r3).await?, b"hello cached world");
    assert_eq!(counters.snapshot(), (2, 1, 1, 0));

    // t = 1000ms: exact fixed deadline reached (hits at 500ms and 999ms did NOT extend it).
    clock.advance(Duration::from_millis(1));
    let r4 = server
        .serve_canonical(&Method::GET, "/hello.txt", &HeaderMap::new())
        .await;
    assert_eq!(r4.status(), StatusCode::NOT_FOUND);
    assert_eq!(counters.snapshot(), (2, 2, 1, 0));
    assert_eq!(cache.entry_count(), 0);
    assert_eq!(budget.used_bytes(), 0);

    let _ = fs::remove_dir_all(&root);
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn mutations_replace_chmod_parent_rename_and_symlink_retarget() -> TestResult {
    let root = temp_root("mutations")?;
    let dir = root.join("sub");
    fs::create_dir_all(&dir)?;
    let replace_path = root.join("replace.txt");
    let chmod_path = root.join("perm.txt");
    let nested_path = dir.join("nested.txt");
    let target_a = root.join("a.txt");
    let target_b = root.join("b.txt");
    let link_path = root.join("link.txt");

    fs::write(&replace_path, b"old-body")?;
    fs::write(&chmod_path, b"readable-body")?;
    fs::write(&nested_path, b"nested-body")?;
    fs::write(&target_a, b"target-A")?;
    fs::write(&target_b, b"target-B")?;
    #[cfg(unix)]
    std::os::unix::fs::symlink("a.txt", &link_path)?;

    let clock = ManualClock::new();
    let budget = Arc::new(FileCacheBudget::new(1024 * 1024));
    let counters = FileCacheCounters::new();
    let cache = FileCache::with_clock(budget, counters.clone(), clock.cache_clock());
    let server = StaticServer::open(&root, StaticConfig::default())?
        .with_file_cache(Arc::clone(&cache), Duration::from_secs(1));

    // Prime all entries at t = 0.
    assert_eq!(
        read_body(
            server
                .serve_canonical(&Method::GET, "/replace.txt", &HeaderMap::new())
                .await
        )
        .await?,
        b"old-body"
    );
    assert_eq!(
        read_body(
            server
                .serve_canonical(&Method::GET, "/perm.txt", &HeaderMap::new())
                .await
        )
        .await?,
        b"readable-body"
    );
    assert_eq!(
        read_body(
            server
                .serve_canonical(&Method::GET, "/sub/nested.txt", &HeaderMap::new())
                .await
        )
        .await?,
        b"nested-body"
    );
    #[cfg(unix)]
    assert_eq!(
        read_body(
            server
                .serve_canonical(&Method::GET, "/link.txt", &HeaderMap::new())
                .await
        )
        .await?,
        b"target-A"
    );

    // Mutate everything on disk while inside the 1s window.
    fs::write(&replace_path, b"new-body-after-window")?;
    fs::rename(&dir, root.join("sub-renamed"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&chmod_path, fs::Permissions::from_mode(0o000))?;
        fs::remove_file(&link_path)?;
        std::os::unix::fs::symlink("b.txt", &link_path)?;
    }

    // t = 500ms (inside window): old answers remain served from memory.
    clock.advance(Duration::from_millis(500));
    assert_eq!(
        read_body(
            server
                .serve_canonical(&Method::GET, "/replace.txt", &HeaderMap::new())
                .await
        )
        .await?,
        b"old-body"
    );
    assert_eq!(
        read_body(
            server
                .serve_canonical(&Method::GET, "/perm.txt", &HeaderMap::new())
                .await
        )
        .await?,
        b"readable-body"
    );
    assert_eq!(
        read_body(
            server
                .serve_canonical(&Method::GET, "/sub/nested.txt", &HeaderMap::new())
                .await
        )
        .await?,
        b"nested-body"
    );
    // A path through a symbolic link is selected by the full resolver and is never stored, so
    // the retargeted link is seen at once, inside the window.
    #[cfg(unix)]
    assert_eq!(
        read_body(
            server
                .serve_canonical(&Method::GET, "/link.txt", &HeaderMap::new())
                .await
        )
        .await?,
        b"target-B"
    );

    // t = 1000ms (past deadline): every change is visible immediately.
    clock.advance(Duration::from_millis(500));
    let replaced_resp = server
        .serve_canonical(&Method::GET, "/replace.txt", &HeaderMap::new())
        .await;
    assert_eq!(replaced_resp.status(), StatusCode::OK);
    assert_eq!(read_body(replaced_resp).await?, b"new-body-after-window");

    let renamed_resp = server
        .serve_canonical(&Method::GET, "/sub/nested.txt", &HeaderMap::new())
        .await;
    assert_eq!(renamed_resp.status(), StatusCode::NOT_FOUND);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        // When running as root (e.g. inside a Docker container), root ignores mode 000 on files,
        // so only assert 404 for chmod 000 when running unprivileged.
        let is_root = rustix::process::geteuid().is_root();
        let r_perm = server
            .serve_canonical(&Method::GET, "/perm.txt", &HeaderMap::new())
            .await;
        if !is_root {
            assert_eq!(r_perm.status(), StatusCode::NOT_FOUND);
        }
        let _ = fs::set_permissions(&chmod_path, fs::Permissions::from_mode(0o644));

        let r_link = server
            .serve_canonical(&Method::GET, "/link.txt", &HeaderMap::new())
            .await;
        assert_eq!(r_link.status(), StatusCode::OK);
        assert_eq!(read_body(r_link).await?, b"target-B");
    }

    let _ = fs::remove_dir_all(&root);
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn representations_head_304_range_threshold_and_non_cacheable() -> TestResult {
    let root = temp_root("representations")?;
    let sub = root.join("dir");
    fs::create_dir_all(&sub)?;
    fs::write(sub.join("index.html"), b"<h1>hi</h1>")?;

    // 1. Precompressed siblings (.br and .gz) + identity.
    let asset = root.join("app.js");
    let asset_br = root.join("app.js.br");
    let asset_gz = root.join("app.js.gz");
    fs::write(&asset, b"console.log('identity');")?;
    fs::write(&asset_br, b"BROTLI-BYTES")?;
    fs::write(&asset_gz, b"GZIP-BYTES")?;

    // 2. Compressible text file >= 1024 bytes without precompressed siblings (on-the-fly).
    let text_body = "MiraServe static file cache on-the-fly compression test line.\n".repeat(40);
    let text_path = root.join("article.txt");
    fs::write(&text_path, text_body.as_bytes())?;

    // 3. Empty (0-byte) file and oversized (> 256 KiB) file.
    fs::write(root.join("empty.txt"), b"")?;
    let big_path = root.join("big.bin");
    fs::write(&big_path, vec![b'X'; 256 * 1024 + 1])?;

    let clock = ManualClock::new();
    let budget = Arc::new(FileCacheBudget::new(4 * 1024 * 1024));
    let counters = FileCacheCounters::new();
    let cache = FileCache::with_clock(budget, counters.clone(), clock.cache_clock());
    let server = StaticServer::open(
        &root,
        StaticConfig {
            precompressed: miraserve_config::PrecompressedPolicy::ALL,
            ..StaticConfig::default()
        },
    )?
    .with_file_cache(Arc::clone(&cache), Duration::from_secs(5));

    // Prime identity, br, and gzip representations of /app.js.
    let mut h_br = HeaderMap::new();
    h_br.insert(ACCEPT_ENCODING, HeaderValue::from_static("br, gzip"));
    let mut h_gz = HeaderMap::new();
    h_gz.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
    let mut h_gz_no_br = HeaderMap::new();
    h_gz_no_br.insert(ACCEPT_ENCODING, HeaderValue::from_static("br;q=0, gzip"));

    let r_id = server
        .serve_canonical(&Method::GET, "/app.js", &HeaderMap::new())
        .await;
    let r_br = server.serve_canonical(&Method::GET, "/app.js", &h_br).await;
    let r_gz = server.serve_canonical(&Method::GET, "/app.js", &h_gz).await;
    assert_eq!(r_id.headers().get(CONTENT_ENCODING), None);
    assert_eq!(
        r_br.headers()
            .get(CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        Some("br")
    );
    assert_eq!(
        r_gz.headers()
            .get(CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        Some("gzip")
    );
    let id_etag = r_id.headers().get(ETAG).cloned();
    let id_lm = r_id.headers().get(LAST_MODIFIED).cloned();
    let br_etag = r_br.headers().get(ETAG).cloned();
    assert_eq!(read_body(r_id).await?, b"console.log('identity');");
    assert_eq!(read_body(r_br).await?, b"BROTLI-BYTES");
    assert_eq!(read_body(r_gz).await?, b"GZIP-BYTES");

    // Prime on-the-fly gzip and br for /article.txt, plus empty.txt.
    let otf_gz = server
        .serve_canonical(&Method::GET, "/article.txt", &h_gz)
        .await;
    assert_eq!(
        otf_gz
            .headers()
            .get(CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        Some("gzip")
    );
    let otf_gz_bytes = read_body(otf_gz).await?;
    assert_eq!(
        miraserve_static::compress::decompress_gzip(&otf_gz_bytes)?,
        text_body.as_bytes()
    );

    let otf_br = server
        .serve_canonical(&Method::GET, "/article.txt", &h_br)
        .await;
    assert_eq!(
        otf_br
            .headers()
            .get(CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        Some("br")
    );
    let otf_br_bytes = read_body(otf_br).await?;
    assert_eq!(
        miraserve_static::compress::decompress_brotli(&otf_br_bytes)?,
        text_body.as_bytes()
    );

    let r_empty = server
        .serve_canonical(&Method::GET, "/empty.txt", &HeaderMap::new())
        .await;
    assert_eq!(r_empty.status(), StatusCode::OK);
    assert_eq!(read_body(r_empty).await?, b"");

    // Delete the source files so every hit below MUST come from cache!
    fs::remove_file(&asset)?;
    fs::remove_file(&asset_br)?;
    fs::remove_file(&asset_gz)?;
    fs::remove_file(&text_path)?;
    fs::remove_file(root.join("empty.txt"))?;

    // Verify hits keep representations strictly separated and share masks (`br;q=0, gzip` == `gzip`).
    let hit_id = server
        .serve_canonical(&Method::GET, "/app.js", &HeaderMap::new())
        .await;
    assert_eq!(hit_id.headers().get(CONTENT_ENCODING), None);
    assert_eq!(read_body(hit_id).await?, b"console.log('identity');");

    let hit_br = server.serve_canonical(&Method::GET, "/app.js", &h_br).await;
    assert_eq!(
        hit_br
            .headers()
            .get(CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        Some("br")
    );
    assert_eq!(hit_br.headers().get(ETAG), br_etag.as_ref());
    assert_eq!(read_body(hit_br).await?, b"BROTLI-BYTES");

    let hit_gz = server
        .serve_canonical(&Method::GET, "/app.js", &h_gz_no_br)
        .await;
    assert_eq!(
        hit_gz
            .headers()
            .get(CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        Some("gzip")
    );
    assert_eq!(read_body(hit_gz).await?, b"GZIP-BYTES");

    let hit_otf_gz = server
        .serve_canonical(&Method::GET, "/article.txt", &h_gz)
        .await;
    assert_eq!(read_body(hit_otf_gz).await?, otf_gz_bytes);

    let hit_otf_br = server
        .serve_canonical(&Method::GET, "/article.txt", &h_br)
        .await;
    assert_eq!(read_body(hit_otf_br).await?, otf_br_bytes);

    let hit_empty = server
        .serve_canonical(&Method::GET, "/empty.txt", &HeaderMap::new())
        .await;
    assert_eq!(hit_empty.status(), StatusCode::OK);
    assert_eq!(
        hit_empty
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()),
        Some("0")
    );
    assert_eq!(read_body(hit_empty).await?, b"");

    // HEAD after GET shares the entry (exact headers, empty body, zero disk access).
    let head_br = server
        .serve_canonical(&Method::HEAD, "/app.js", &h_br)
        .await;
    assert_eq!(head_br.status(), StatusCode::OK);
    assert_eq!(
        head_br
            .headers()
            .get(CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        Some("br")
    );
    assert_eq!(
        head_br
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()),
        Some("12")
    );
    assert_eq!(head_br.headers().get(ETAG), br_etag.as_ref());
    assert_eq!(read_body(head_br).await?, b"");

    // 304 from cached validators (If-None-Match & If-Modified-Since) with file deleted on disk.
    if let Some(etag) = id_etag {
        let mut cond = HeaderMap::new();
        cond.insert(IF_NONE_MATCH, etag);
        let r_304 = server.serve_canonical(&Method::GET, "/app.js", &cond).await;
        assert_eq!(r_304.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(read_body(r_304).await?, b"");

        let mut mismatch = HeaderMap::new();
        mismatch.insert(IF_NONE_MATCH, HeaderValue::from_static("\"different\""));
        let r_200 = server
            .serve_canonical(&Method::GET, "/app.js", &mismatch)
            .await;
        assert_eq!(r_200.status(), StatusCode::OK);
        assert_eq!(read_body(r_200).await?, b"console.log('identity');");
    }
    if let Some(lm) = id_lm {
        let mut cond = HeaderMap::new();
        cond.insert(IF_MODIFIED_SINCE, lm);
        let r_304 = server.serve_canonical(&Method::GET, "/app.js", &cond).await;
        assert_eq!(r_304.status(), StatusCode::NOT_MODIFIED);
    }

    // Range bypasses cache completely (hits disk directly).
    fs::write(&asset, b"0123456789")?;
    let mut range_hdrs = HeaderMap::new();
    range_hdrs.insert(RANGE, HeaderValue::from_static("bytes=2-5"));
    let fills_before_range = counters.fills();
    let hits_before_range = counters.hits();
    let r_range = server
        .serve_canonical(&Method::GET, "/app.js", &range_hdrs)
        .await;
    assert_eq!(r_range.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        r_range
            .headers()
            .get(CONTENT_RANGE)
            .and_then(|v| v.to_str().ok()),
        Some("bytes 2-5/10")
    );
    assert_eq!(read_body(r_range).await?, b"2345");
    assert_eq!(counters.hits(), hits_before_range);
    assert_eq!(counters.fills(), fills_before_range);

    // File over 256 KiB threshold is NOT cached.
    let fills_before_big = counters.fills();
    let r_big = server
        .serve_canonical(&Method::GET, "/big.bin", &HeaderMap::new())
        .await;
    assert_eq!(r_big.status(), StatusCode::OK);
    assert_eq!(read_body(r_big).await?.len(), 256 * 1024 + 1);
    assert_eq!(counters.fills(), fills_before_big);

    // File growing over threshold after expiry is NOT cached on refill.
    let grow_path = root.join("grow.bin");
    fs::write(&grow_path, b"small")?;
    assert_eq!(
        read_body(
            server
                .serve_canonical(&Method::GET, "/grow.bin", &HeaderMap::new())
                .await
        )
        .await?,
        b"small"
    );
    let fills_after_small = counters.fills();
    fs::write(&grow_path, vec![b'G'; 256 * 1024 + 10])?;
    clock.advance(Duration::from_secs(5));
    let r_grown = server
        .serve_canonical(&Method::GET, "/grow.bin", &HeaderMap::new())
        .await;
    assert_eq!(read_body(r_grown).await?.len(), 256 * 1024 + 10);
    assert_eq!(counters.fills(), fills_after_small);
    // Delete the grown file -> next request sees 404 immediately (was not cached).
    fs::remove_file(&grow_path)?;
    assert_eq!(
        server
            .serve_canonical(&Method::GET, "/grow.bin", &HeaderMap::new())
            .await
            .status(),
        StatusCode::NOT_FOUND
    );

    // Non-cacheable responses: directory redirect (301), 404, Markdown conversion.
    let fills_before_non = counters.fills();
    let r_redir = server
        .serve_canonical(&Method::GET, "/dir", &HeaderMap::new())
        .await;
    assert_eq!(r_redir.status(), StatusCode::MOVED_PERMANENTLY);
    let r_404 = server
        .serve_canonical(&Method::GET, "/nope.txt", &HeaderMap::new())
        .await;
    assert_eq!(r_404.status(), StatusCode::NOT_FOUND);
    let conv = Conversion {
        bare: HeaderMap::new(),
        max_len: 1024 * 1024,
        take: Arc::new(|| true),
    };
    let r_conv = server
        .serve_canonical_choosing(&Method::GET, "/dir/", None, &HeaderMap::new(), &conv)
        .await;
    assert_eq!(r_conv.status(), StatusCode::OK);
    assert_eq!(counters.fills(), fills_before_non);

    let _ = fs::remove_dir_all(&root);
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn try_files_hit_skips_earlier_candidates_and_index_probes() -> TestResult {
    let root = temp_root("try-files")?;
    let override_dir = root.join("override");
    let sub_dir = root.join("sub");
    fs::create_dir_all(&override_dir)?;
    fs::create_dir_all(&sub_dir)?;
    fs::write(root.join("app.txt"), b"fallback-app")?;
    fs::write(sub_dir.join("index.html"), b"sub-index")?;

    let candidates = vec![
        "/override{path}".to_owned(),
        "{path}".to_owned(),
        "{path}/".to_owned(),
        "=404".to_owned(),
    ];

    let clock = ManualClock::new();
    let budget = Arc::new(FileCacheBudget::new(1024 * 1024));
    let counters = FileCacheCounters::new();
    let cache = FileCache::with_clock(budget, counters.clone(), clock.cache_clock());
    let server = StaticServer::open(&root, StaticConfig::default())?
        .with_file_cache(Arc::clone(&cache), Duration::from_secs(1))
        .with_try_files_candidates(candidates.clone());

    // Prime /app.txt (candidate 0 misses, candidate 1 succeeds) and /sub/ (index.html).
    let out1 = server
        .serve_try_files_canonical(
            &Method::GET,
            "/app.txt",
            None,
            &HeaderMap::new(),
            &candidates,
        )
        .await;
    let TryFilesOutcome::Response(r1) = out1 else {
        return Err("expected static response for /app.txt".into());
    };
    assert_eq!(read_body(*r1).await?, b"fallback-app");

    let out_idx = server
        .serve_try_files_canonical(&Method::GET, "/sub/", None, &HeaderMap::new(), &candidates)
        .await;
    let TryFilesOutcome::Response(r_idx) = out_idx else {
        return Err("expected static response for /sub/".into());
    };
    assert_eq!(read_body(*r_idx).await?, b"sub-index");

    // Now create a higher-priority override AND delete the original files!
    fs::write(override_dir.join("app.txt"), b"override-wins")?;
    fs::remove_file(root.join("app.txt"))?;
    fs::remove_file(sub_dir.join("index.html"))?;

    // Inside window: hits skip probing /override/app.txt and /sub/index.html.
    clock.advance(Duration::from_millis(400));
    let out2 = server
        .serve_try_files_canonical(
            &Method::GET,
            "/app.txt",
            None,
            &HeaderMap::new(),
            &candidates,
        )
        .await;
    let TryFilesOutcome::Response(r2) = out2 else {
        return Err("expected cached response for /app.txt".into());
    };
    assert_eq!(read_body(*r2).await?, b"fallback-app");

    let out_idx2 = server
        .serve_try_files_canonical(&Method::GET, "/sub/", None, &HeaderMap::new(), &candidates)
        .await;
    let TryFilesOutcome::Response(r_idx2) = out_idx2 else {
        return Err("expected cached response for /sub/".into());
    };
    assert_eq!(read_body(*r_idx2).await?, b"sub-index");

    // Past deadline: normal try-files loop runs in full; /override/app.txt wins and /sub/ is 404.
    clock.advance(Duration::from_millis(600));
    let out3 = server
        .serve_try_files_canonical(
            &Method::GET,
            "/app.txt",
            None,
            &HeaderMap::new(),
            &candidates,
        )
        .await;
    let TryFilesOutcome::FallbackResponse { response: r3, .. } = out3 else {
        return Err("expected override response".into());
    };
    assert_eq!(read_body(*r3).await?, b"override-wins");

    let out_idx3 = server
        .serve_try_files_canonical(&Method::GET, "/sub/", None, &HeaderMap::new(), &candidates)
        .await;
    let TryFilesOutcome::Response(r_idx3) = out_idx3 else {
        return Err("expected 404 for /sub/".into());
    };
    assert_eq!(r_idx3.status(), StatusCode::NOT_FOUND);

    // try-files with `{query}` in the template path safely bypasses cache.
    fs::write(root.join("q-a.txt"), b"query-a")?;
    fs::write(root.join("q-b.txt"), b"query-b")?;
    let query_candidates = vec!["/q-{query}.txt".to_owned(), "=404".to_owned()];
    let q_srv = StaticServer::open(&root, StaticConfig::default())?
        .with_file_cache(Arc::clone(&cache), Duration::from_secs(10))
        .with_try_files_candidates(query_candidates.clone());
    let qa = q_srv
        .serve_try_files_canonical(
            &Method::GET,
            "/item",
            Some("a"),
            &HeaderMap::new(),
            &query_candidates,
        )
        .await;
    let qb = q_srv
        .serve_try_files_canonical(
            &Method::GET,
            "/item",
            Some("b"),
            &HeaderMap::new(),
            &query_candidates,
        )
        .await;
    let (
        TryFilesOutcome::FallbackResponse { response: ra, .. },
        TryFilesOutcome::FallbackResponse { response: rb, .. },
    ) = (qa, qb)
    else {
        return Err("expected responses for query-dependent try-files".into());
    };
    assert_eq!(read_body(*ra).await?, b"query-a");
    assert_eq!(read_body(*rb).await?, b"query-b");

    let _ = fs::remove_dir_all(&root);
    Ok(())
}

#[tokio::test]
async fn credential_file_and_hard_link_are_never_cached_or_served() -> TestResult {
    let root = temp_root("credential")?;
    let cred_dir = temp_root("credential-secret")?;
    let secret_path = cred_dir.join("users.htpasswd");
    fs::write(&secret_path, b"admin:$2y$10$secret")?;
    let secret_handle = fs::File::open(&secret_path)?;
    let secret_ids = handle_identities(std::slice::from_ref(&secret_handle));

    // Place a hard link to the credential file inside the docroot (plus a .gz sibling link).
    let link_in_root = root.join("public.txt");
    let link_gz = root.join("normal.txt.gz");
    fs::write(root.join("normal.txt"), b"ordinary content")?;
    fs::hard_link(&secret_path, &link_in_root)?;
    fs::hard_link(&secret_path, &link_gz)?;

    let clock = ManualClock::new();
    let budget = Arc::new(FileCacheBudget::new(1024 * 1024));
    let counters = FileCacheCounters::new();
    let cache = FileCache::with_clock(budget, counters.clone(), clock.cache_clock());
    let mut server = StaticServer::open(
        &root,
        StaticConfig {
            precompressed: miraserve_config::PrecompressedPolicy::ALL,
            ..StaticConfig::default()
        },
    )?
    .with_file_cache(Arc::clone(&cache), Duration::from_secs(10));
    server.set_secret_files(secret_ids);

    // Direct hard link to credential -> 404 and never cached.
    let r1 = server
        .serve_canonical(&Method::GET, "/public.txt", &HeaderMap::new())
        .await;
    assert_eq!(r1.status(), StatusCode::NOT_FOUND);
    assert_eq!(counters.fills(), 0);
    assert_eq!(cache.entry_count(), 0);

    // Precompressed sibling hard-linked to credential -> 404 and never cached.
    let mut gz_hdrs = HeaderMap::new();
    gz_hdrs.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
    let r2 = server
        .serve_canonical(&Method::GET, "/normal.txt", &gz_hdrs)
        .await;
    assert_eq!(r2.status(), StatusCode::NOT_FOUND);
    assert_eq!(counters.fills(), 0);
    assert_eq!(cache.entry_count(), 0);

    // With UNIDENTIFIED_CREDENTIAL, any multi-linked file is refused and never cached.
    let shared_a = root.join("multi_a.txt");
    let shared_b = root.join("multi_b.txt");
    fs::write(&shared_a, b"shared-inode")?;
    fs::hard_link(&shared_a, &shared_b)?;
    let mut unid_server = StaticServer::open(&root, StaticConfig::default())?
        .with_file_cache(Arc::clone(&cache), Duration::from_secs(10));
    unid_server.set_secret_files(Arc::from([UNIDENTIFIED_CREDENTIAL]));
    let r3 = unid_server
        .serve_canonical(&Method::GET, "/multi_a.txt", &HeaderMap::new())
        .await;
    assert_eq!(r3.status(), StatusCode::NOT_FOUND);
    assert_eq!(counters.fills(), 0);

    drop(secret_handle);
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&cred_dir);
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn budget_exhaustion_slow_reader_retention_sweep_and_reload() -> TestResult {
    let root = temp_root("budget")?;
    let body_a = vec![b'A'; 4_096];
    let body_b = vec![b'B'; 4_096];
    fs::write(root.join("a.bin"), &body_a)?;
    fs::write(root.join("b.bin"), &body_b)?;

    let clock = ManualClock::new();
    // Enough for ONE 4 KiB entry + its metadata (~4.5 KiB), NOT two (~9 KiB).
    let budget = Arc::new(FileCacheBudget::new(6_000));
    let counters = FileCacheCounters::new();
    let cache_gen1 =
        FileCache::with_clock(Arc::clone(&budget), counters.clone(), clock.cache_clock());
    let server_gen1 = StaticServer::open(&root, StaticConfig::default())?
        .with_file_cache(Arc::clone(&cache_gen1), Duration::from_secs(1));

    // Fill /a.bin -> succeeds and charges budget.
    let first_a = server_gen1
        .serve_canonical(&Method::GET, "/a.bin", &HeaderMap::new())
        .await;
    assert_eq!(first_a.status(), StatusCode::OK);
    assert_eq!(read_body(first_a).await?, body_a);
    assert_eq!(counters.fills(), 1);
    assert_eq!(counters.not_cached_budget(), 0);
    let used_with_a = budget.used_bytes();
    assert!(
        used_with_a > 4_096 && used_with_a <= 6_000,
        "used={used_with_a}"
    );

    // Request /b.bin while /a.bin holds the budget -> served 200 OK, NOT cached, budget counter +1.
    let first_b = server_gen1
        .serve_canonical(&Method::GET, "/b.bin", &HeaderMap::new())
        .await;
    assert_eq!(first_b.status(), StatusCode::OK);
    assert_eq!(read_body(first_b).await?, body_b);
    assert_eq!(counters.fills(), 1);
    assert_eq!(counters.not_cached_budget(), 1);
    assert_eq!(budget.used_bytes(), used_with_a);

    // Slow reader gets a hit on /a.bin and holds the Response without draining the body.
    let slow_reader_resp = server_gen1
        .serve_canonical(&Method::GET, "/a.bin", &HeaderMap::new())
        .await;
    assert_eq!(slow_reader_resp.status(), StatusCode::OK);
    assert_eq!(counters.hits(), 1);

    // Advance past /a.bin's deadline and sweep expired entries.
    clock.advance(Duration::from_secs(1));
    assert_eq!(cache_gen1.sweep_expired(), 1);
    assert_eq!(cache_gen1.entry_count(), 0);
    // Entry metadata and empty shard map were released, while the slow reader STILL keeps the
    // 4096-byte exact buffer + owner box charged!
    assert_eq!(
        budget.used_bytes(),
        miraserve_static::charged_body_bytes(4_096)
    );

    // Simulate reload: drop generation 1 completely and create an empty generation 2 on the same
    // shared budget.
    drop(server_gen1);
    drop(cache_gen1);
    let cache_gen2 =
        FileCache::with_clock(Arc::clone(&budget), counters.clone(), clock.cache_clock());
    let server_gen2 = StaticServer::open(&root, StaticConfig::default())?
        .with_file_cache(Arc::clone(&cache_gen2), Duration::from_secs(1));

    // Even after reload dropped generation 1, the slow reader still pins the body + owner bytes,
    // so /b.bin (4096 + meta > 6000 - pinned) still cannot exceed the budget!
    assert_eq!(
        budget.used_bytes(),
        miraserve_static::charged_body_bytes(4_096)
    );
    let second_b = server_gen2
        .serve_canonical(&Method::GET, "/b.bin", &HeaderMap::new())
        .await;
    assert_eq!(second_b.status(), StatusCode::OK);
    assert_eq!(read_body(second_b).await?, body_b);
    assert_eq!(counters.not_cached_budget(), 2);

    // Slow reader finally finishes and drops the body -> budget returns to 0!
    assert_eq!(read_body(slow_reader_resp).await?, body_a);
    assert_eq!(budget.used_bytes(), 0);

    // Now /b.bin fits and is cached in generation 2!
    let third_b = server_gen2
        .serve_canonical(&Method::GET, "/b.bin", &HeaderMap::new())
        .await;
    assert_eq!(third_b.status(), StatusCode::OK);
    assert_eq!(read_body(third_b).await?, body_b);
    assert_eq!(counters.fills(), 2);
    assert!(budget.used_bytes() > 4_096);

    // Opportunistic sweep on budget pressure reclaims expired /b.bin so /a.bin can enter.
    clock.advance(Duration::from_secs(1));
    let second_a = server_gen2
        .serve_canonical(&Method::GET, "/a.bin", &HeaderMap::new())
        .await;
    assert_eq!(second_a.status(), StatusCode::OK);
    assert_eq!(read_body(second_a).await?, body_a);
    assert_eq!(counters.fills(), 3);
    assert_eq!(cache_gen2.entry_count(), 1);

    let _ = fs::remove_dir_all(&root);
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn concurrent_fills_one_wins_none_blocks_and_long_keys_bypass() -> TestResult {
    let root = temp_root("concurrent")?;
    let payload = b"concurrent-static-file-body".repeat(16);
    fs::write(root.join("hot.txt"), &payload)?;

    let clock = ManualClock::new();
    let budget = Arc::new(FileCacheBudget::new(1024 * 1024));
    let counters = FileCacheCounters::new();
    let cache = FileCache::with_clock(Arc::clone(&budget), counters.clone(), clock.cache_clock());
    let server = Arc::new(
        StaticServer::open(&root, StaticConfig::default())?
            .with_file_cache(Arc::clone(&cache), Duration::from_secs(5)),
    );

    let mut handles = Vec::with_capacity(16);
    for _ in 0..16 {
        let srv = Arc::clone(&server);
        handles.push(tokio::spawn(async move {
            let resp = srv
                .serve_canonical(&Method::GET, "/hot.txt", &HeaderMap::new())
                .await;
            let status = resp.status();
            let body = resp
                .into_body()
                .collect()
                .await
                .map(|c| c.to_bytes().to_vec())
                .unwrap_or_default();
            (status, body)
        }));
    }
    for h in handles {
        let (status, body) = h.await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, payload);
    }
    assert_eq!(counters.fills(), 1, "exactly one concurrent fill wins");
    assert_eq!(cache.entry_count(), 1);
    assert_eq!(
        counters.hits() + counters.misses(),
        16,
        "every request counted once"
    );

    // Overlong key (> MAX_CACHE_KEY_BYTES) bypasses cache cleanly without panic.
    let overlong = format!("/{}", "a".repeat(MAX_CACHE_KEY_BYTES + 32));
    let r_long = server
        .serve_canonical(&Method::GET, &overlong, &HeaderMap::new())
        .await;
    assert_eq!(r_long.status(), StatusCode::NOT_FOUND);
    assert_eq!(cache.entry_count(), 1);

    // Zero budget disables hits and fills cleanly.
    budget.set_limit(0);
    fs::write(root.join("hot.txt"), b"fresh-after-disable")?;
    let r_disabled = server
        .serve_canonical(&Method::GET, "/hot.txt", &HeaderMap::new())
        .await;
    assert_eq!(r_disabled.status(), StatusCode::OK);
    assert_eq!(
        r_disabled
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/plain; charset=utf-8")
    );
    assert_eq!(read_body(r_disabled).await?, b"fresh-after-disable");

    let _ = fs::remove_dir_all(&root);
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn p1_3_b_unidentified_credential_disables_hits_and_admissions() -> TestResult {
    let root = temp_root("unidentified-cred")?;
    let single = root.join("single.txt");
    fs::write(&single, b"single-link-v1")?;

    let clock = ManualClock::new();
    let budget = Arc::new(FileCacheBudget::new(1024 * 1024));
    let counters = FileCacheCounters::new();
    let cache = FileCache::with_clock(Arc::clone(&budget), counters.clone(), clock.cache_clock());

    let mut server = StaticServer::open(&root, StaticConfig::default())?
        .with_file_cache(Arc::clone(&cache), Duration::from_secs(60));
    server.set_secret_files(Arc::from([UNIDENTIFIED_CREDENTIAL]));

    // Single-link file is served 200 OK, but MUST NOT be admitted while UNIDENTIFIED_CREDENTIAL
    // is present in secret_files.
    let r1 = server
        .serve_canonical(&Method::GET, "/single.txt", &HeaderMap::new())
        .await;
    assert_eq!(r1.status(), StatusCode::OK);
    assert_eq!(read_body(r1).await?, b"single-link-v1");
    assert_eq!(counters.fills(), 0);
    assert_eq!(counters.hits(), 0);
    assert_eq!(cache.entry_count(), 0);
    assert_eq!(budget.used_bytes(), 0);

    // If that file later acquires a second hard link inside the window, the next GET immediately
    // sees nlink > 1 on disk and returns 404 (never a stale cached 200).
    fs::hard_link(&single, root.join("alias.txt"))?;
    let r2 = server
        .serve_canonical(&Method::GET, "/single.txt", &HeaderMap::new())
        .await;
    assert_eq!(
        r2.status(),
        StatusCode::NOT_FOUND,
        "P1-3(b): single-link file that gains a link under UNIDENTIFIED_CREDENTIAL must be refused"
    );

    // Also verify a previously cached entry cannot be hit once UNIDENTIFIED_CREDENTIAL is set.
    let other = root.join("other.txt");
    fs::write(&other, b"before-marker")?;
    let mut srv_warm = StaticServer::open(&root, StaticConfig::default())?
        .with_file_cache(Arc::clone(&cache), Duration::from_secs(60));
    let rw1 = srv_warm
        .serve_canonical(&Method::GET, "/other.txt", &HeaderMap::new())
        .await;
    assert_eq!(read_body(rw1).await?, b"before-marker");
    assert_eq!(counters.fills(), 1);
    srv_warm.set_secret_files(Arc::from([UNIDENTIFIED_CREDENTIAL]));
    fs::write(&other, b"after-marker")?;
    let hits_before = counters.hits();
    let rw2 = srv_warm
        .serve_canonical(&Method::GET, "/other.txt", &HeaderMap::new())
        .await;
    assert_eq!(read_body(rw2).await?, b"after-marker");
    assert_eq!(counters.hits(), hits_before);
    assert_eq!(counters.fills(), 1);

    let _ = fs::remove_dir_all(&root);
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn p1_4_range_and_if_range_bypass_direct_and_try_files() -> TestResult {
    let root = temp_root("range-if-range")?;
    fs::write(root.join("a.txt"), b"0123456789")?;
    let candidates = vec!["{path}".to_owned(), "=404".to_owned()];

    let clock = ManualClock::new();
    let budget = Arc::new(FileCacheBudget::new(1024 * 1024));
    let counters = FileCacheCounters::new();
    let cache = FileCache::with_clock(budget, counters.clone(), clock.cache_clock());
    let server = StaticServer::open(&root, StaticConfig::default())?
        .with_file_cache(Arc::clone(&cache), Duration::from_secs(60))
        .with_try_files_candidates(candidates.clone());

    // 1. GET with If-Range (no Range) must NOT admit on direct or try-files.
    let mut if_range_hdrs = HeaderMap::new();
    if_range_hdrs.insert(
        http::header::IF_RANGE,
        HeaderValue::from_static("\"stale\""),
    );
    let r_direct = server
        .serve_canonical(&Method::GET, "/a.txt", &if_range_hdrs)
        .await;
    assert_eq!(r_direct.status(), StatusCode::OK);
    assert_eq!(read_body(r_direct).await?, b"0123456789");
    let tf_out = server
        .serve_try_files_canonical(&Method::GET, "/a.txt", None, &if_range_hdrs, &candidates)
        .await;
    let TryFilesOutcome::Response(r_tf) = tf_out else {
        return Err("expected response".into());
    };
    assert_eq!(r_tf.status(), StatusCode::OK);
    assert_eq!(counters.fills(), 0);
    assert_eq!(cache.entry_count(), 0);

    // 2. Warm direct + try-files entries, then delete file on disk.
    let _ = server
        .serve_canonical(&Method::GET, "/a.txt", &HeaderMap::new())
        .await;
    let _ = server
        .serve_try_files_canonical(&Method::GET, "/a.txt", None, &HeaderMap::new(), &candidates)
        .await;
    assert_eq!(counters.fills(), 2);
    fs::remove_file(root.join("a.txt"))?;

    // Plain GET hits both, while Range or If-Range (GET or HEAD) bypass and see 404.
    let mut range_hdrs = HeaderMap::new();
    range_hdrs.insert(RANGE, HeaderValue::from_static("bytes=0-3"));
    for (method, hdrs) in [
        (&Method::GET, &if_range_hdrs),
        (&Method::HEAD, &if_range_hdrs),
        (&Method::GET, &range_hdrs),
        (&Method::HEAD, &range_hdrs),
    ] {
        assert!(
            server.try_serve_cached(method, "/a.txt", hdrs).is_none(),
            "try_serve_cached must decline {method} with range/if-range"
        );
        let r = server.serve_canonical(method, "/a.txt", hdrs).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        let tf = server
            .serve_try_files_canonical(method, "/a.txt", None, hdrs, &candidates)
            .await;
        let TryFilesOutcome::Response(bypassed_tf) = tf else {
            return Err("expected response".into());
        };
        assert_eq!(bypassed_tf.status(), StatusCode::NOT_FOUND);
    }

    let _ = fs::remove_dir_all(&root);
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn p2_c_setters_on_cloned_server_allocate_fresh_namespace() -> TestResult {
    let root = temp_root("p2c-namespace")?;
    fs::write(root.join("a.html"), b"fallback-A")?;
    fs::write(root.join("b.html"), b"fallback-B")?;
    fs::write(root.join("note.txt"), b"note-content")?;
    let sub = root.join("dir");
    fs::create_dir_all(&sub)?;
    fs::write(sub.join("index.php"), b"<?php ?>")?;
    fs::write(sub.join("index.html"), b"dir-static-html")?;

    let clock = ManualClock::new();
    let budget = Arc::new(FileCacheBudget::new(1024 * 1024));
    let counters = FileCacheCounters::new();
    let cache = FileCache::with_clock(budget, counters.clone(), clock.cache_clock());
    let base = StaticServer::open(&root, StaticConfig::default())?
        .with_file_cache(Arc::clone(&cache), Duration::from_secs(60));

    // 1. Rebinding try-files candidates on a clone gets a fresh namespace id.
    let cand_a = vec!["{path}".to_owned(), "/a.html".to_owned()];
    let cand_b = vec!["{path}".to_owned(), "/b.html".to_owned()];
    let srv_a = base.clone().with_try_files_candidates(cand_a.clone());
    let out_a = srv_a
        .serve_try_files_canonical(&Method::GET, "/missing", None, &HeaderMap::new(), &cand_a)
        .await;
    let TryFilesOutcome::FallbackResponse { response: ra, .. } = out_a else {
        return Err("expected fallback-A".into());
    };
    assert_eq!(read_body(*ra).await?, b"fallback-A");

    let srv_b = srv_a.clone().with_try_files_candidates(cand_b.clone());
    let out_b = srv_b
        .serve_try_files_canonical(&Method::GET, "/missing", None, &HeaderMap::new(), &cand_b)
        .await;
    let TryFilesOutcome::FallbackResponse { response: rb, .. } = out_b else {
        return Err("expected fallback-B".into());
    };
    assert_eq!(
        read_body(*rb).await?,
        b"fallback-B",
        "P2-c: rebinding try-files on clone must NOT hit old fallback-A entry"
    );

    // 2. Rebinding try-files script predicate gets a fresh namespace id.
    let cfg_idx = StaticConfig {
        index: vec!["index.php".to_owned(), "index.html".to_owned()],
        ..StaticConfig::default()
    };
    let dir_cands = vec!["{path}".to_owned(), "=404".to_owned()];
    let pred_no_php: miraserve_static::ScriptOwner = Arc::new(|_| false);
    let pred_yes_php: miraserve_static::ScriptOwner = Arc::new(|p| {
        std::path::Path::new(p)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("php"))
    });
    let srv_p1 = StaticServer::open(&root, cfg_idx)?
        .with_forbidden_extensions([".php".to_owned()])
        .with_file_cache(Arc::clone(&cache), Duration::from_secs(60))
        .with_try_files_candidates(dir_cands.clone())
        .with_try_files_script_extensions(vec![".php".to_owned()])
        .with_try_files_script_owner(Arc::clone(&pred_no_php));
    let out_p1 = srv_p1
        .serve_try_files_canonical_routed(
            &Method::GET,
            "/dir/",
            None,
            &HeaderMap::new(),
            &dir_cands,
            &[".php".to_owned()],
            &pred_no_php,
        )
        .await;
    let TryFilesOutcome::Response(rp1) = out_p1 else {
        return Err("expected dir-static-html when no route runs php".into());
    };
    assert_eq!(read_body(*rp1).await?, b"dir-static-html");
    assert_eq!(
        counters.fills(),
        3,
        "srv_p1 with bound script extensions must populate cache before rebinding"
    );

    let srv_p2 = srv_p1
        .clone()
        .with_try_files_script_owner(Arc::clone(&pred_yes_php));
    let out_p2 = srv_p2
        .serve_try_files_canonical_routed(
            &Method::GET,
            "/dir/",
            None,
            &HeaderMap::new(),
            &dir_cands,
            &[".php".to_owned()],
            &pred_yes_php,
        )
        .await;
    assert!(
        matches!(out_p2, TryFilesOutcome::InternalRewrite(ref p) if p == "/dir/index.php"),
        "P2-c: rebinding script predicate on clone must NOT hit old static index entry: {out_p2:?}"
    );

    // 3. Changing forbidden_extensions on a clone gets a fresh namespace id.
    let rn1 = base
        .serve_canonical(&Method::GET, "/note.txt", &HeaderMap::new())
        .await;
    assert_eq!(rn1.status(), StatusCode::OK);
    let srv_forbid = base.clone().with_forbidden_extensions([".txt".to_owned()]);
    let rn2 = srv_forbid
        .serve_canonical(&Method::GET, "/note.txt", &HeaderMap::new())
        .await;
    assert_eq!(
        rn2.status(),
        StatusCode::NOT_FOUND,
        "P2-c: forbidding .txt on clone must NOT hit cached /note.txt"
    );

    // 4. Changing secret_files on a clone gets a fresh namespace id.
    let note_handle = fs::File::open(root.join("note.txt"))?;
    let note_ids = handle_identities(std::slice::from_ref(&note_handle));
    let mut srv_secret = base.clone();
    srv_secret.set_secret_files(note_ids);
    let rn3 = srv_secret
        .serve_canonical(&Method::GET, "/note.txt", &HeaderMap::new())
        .await;
    assert_eq!(
        rn3.status(),
        StatusCode::NOT_FOUND,
        "P2-c: setting secret_files on clone must NOT hit cached /note.txt"
    );

    drop(note_handle);
    let _ = fs::remove_dir_all(&root);
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn p2_d_precompressed_sibling_requires_base_file_within_threshold() -> TestResult {
    let root = temp_root("p2d-base-threshold")?;
    // Base file > 256 KiB (300 KiB), tiny precompressed .br sibling (1 KiB).
    fs::write(root.join("big.js"), vec![b'x'; 300 * 1024])?;
    fs::write(root.join("big.js.br"), b"BR-BIG-V1")?;
    // Base file <= 256 KiB (200 KiB), tiny precompressed .br sibling.
    fs::write(root.join("small.js"), vec![b'y'; 200 * 1024])?;
    fs::write(root.join("small.js.br"), b"BR-SMALL-V1")?;

    let clock = ManualClock::new();
    let budget = Arc::new(FileCacheBudget::new(2 * 1024 * 1024));
    let counters = FileCacheCounters::new();
    let cache = FileCache::with_clock(budget, counters.clone(), clock.cache_clock());
    let server = StaticServer::open(
        &root,
        StaticConfig {
            precompressed: miraserve_config::PrecompressedPolicy::ALL,
            ..StaticConfig::default()
        },
    )?
    .with_file_cache(Arc::clone(&cache), Duration::from_secs(60));

    let mut br_hdrs = HeaderMap::new();
    br_hdrs.insert(ACCEPT_ENCODING, HeaderValue::from_static("br"));

    // Over-threshold base + tiny .br sibling: served 200 OK, NEVER cached.
    let r_big1 = server
        .serve_canonical(&Method::GET, "/big.js", &br_hdrs)
        .await;
    assert_eq!(r_big1.status(), StatusCode::OK);
    assert_eq!(read_body(r_big1).await?, b"BR-BIG-V1");
    assert_eq!(
        counters.fills(),
        0,
        "P2-d: precompressed sibling of >256 KiB base file must NOT be cached"
    );
    assert_eq!(cache.entry_count(), 0);

    // Editing .br sibling is visible immediately on next request.
    fs::write(root.join("big.js.br"), b"BR-BIG-V2")?;
    let r_big2 = server
        .serve_canonical(&Method::GET, "/big.js", &br_hdrs)
        .await;
    assert_eq!(read_body(r_big2).await?, b"BR-BIG-V2");

    // Within-threshold base + tiny .br sibling DOES cache.
    let r_small1 = server
        .serve_canonical(&Method::GET, "/small.js", &br_hdrs)
        .await;
    assert_eq!(read_body(r_small1).await?, b"BR-SMALL-V1");
    assert_eq!(counters.fills(), 1);
    fs::remove_file(root.join("small.js.br"))?;
    let r_small2 = server
        .serve_canonical(&Method::GET, "/small.js", &br_hdrs)
        .await;
    assert_eq!(read_body(r_small2).await?, b"BR-SMALL-V1");
    assert_eq!(counters.hits(), 1);

    let _ = fs::remove_dir_all(&root);
    Ok(())
}

/// P2-c: The script-extension list actually used is part of the `try-files` namespace:
/// warming `/dir/` through unfiltered `serve_try_files_canonical` (`&[]`) must NEVER be hit by
/// `serve_try_files_canonical_filtered` with `[".php"]`, and rebinding
/// `with_try_files_script_extensions` on a clone allocates a fresh namespace ID.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn p2_c_try_files_filtered_and_unfiltered_never_share_key() -> TestResult {
    let root = temp_root("p2c-script-ext-ns")?;
    let dir = root.join("dir");
    fs::create_dir_all(&dir)?;
    fs::write(dir.join("index.php"), b"<?php echo 1; ?>")?;
    fs::write(dir.join("index.html"), b"static-html-index")?;

    let cfg = StaticConfig {
        index: vec!["index.php".to_owned(), "index.html".to_owned()],
        ..StaticConfig::default()
    };
    let candidates = vec!["{path}".to_owned(), "=404".to_owned()];

    let clock = ManualClock::new();
    let budget = Arc::new(FileCacheBudget::new(1024 * 1024));
    let counters = FileCacheCounters::new();
    let cache = FileCache::with_clock(budget, counters.clone(), clock.cache_clock());
    let server = StaticServer::open(&root, cfg)?
        .with_file_cache(Arc::clone(&cache), Duration::from_secs(60))
        .with_try_files_candidates(candidates.clone());

    // 1. Warm `/dir/` via unfiltered `serve_try_files_canonical` (empty script-extension list):
    //    HTML wins and is cached under the `&[]` namespace.
    let out1 = server
        .serve_try_files_canonical(&Method::GET, "/dir/", None, &HeaderMap::new(), &candidates)
        .await;
    let TryFilesOutcome::Response(r1) = out1 else {
        return Err("expected HTML response from unfiltered try-files".into());
    };
    assert_eq!(read_body(*r1).await?, b"static-html-index");
    assert_eq!(counters.fills(), 1);

    // 2. Call `serve_try_files_canonical_filtered` with `[".php"]` on the SAME `StaticServer`:
    //    MUST NOT hit the `&[]` cached HTML entry — MUST return InternalRewrite("/dir/index.php")!
    let out2 = server
        .serve_try_files_canonical_filtered(
            &Method::GET,
            "/dir/",
            None,
            &HeaderMap::new(),
            &candidates,
            &[".php".to_owned()],
        )
        .await;
    assert!(
        matches!(out2, TryFilesOutcome::InternalRewrite(ref target) if target == "/dir/index.php"),
        "P2-c: filtered try-files must NOT hit unfiltered cached HTML entry: {out2:?}"
    );
    assert_eq!(counters.hits(), 0);

    // 3. Rebinding `with_try_files_script_extensions` on a clone allocates a fresh namespace ID
    //    even without changing `forbidden_extensions` (`.phtml` and `.php` are both in the
    //    default forbidden list) and isolates `[".phtml"]` from `[".php"]` and `&[]`.
    let srv_phtml = server
        .clone()
        .with_try_files_script_extensions(vec![".phtml".to_owned()]);
    let out3 = srv_phtml
        .serve_try_files_canonical_filtered(
            &Method::GET,
            "/dir/",
            None,
            &HeaderMap::new(),
            &candidates,
            &[".phtml".to_owned()],
        )
        .await;
    let TryFilesOutcome::Response(r3) = out3 else {
        return Err("expected HTML when only .phtml is a script extension".into());
    };
    assert_eq!(read_body(*r3).await?, b"static-html-index");
    assert_eq!(counters.fills(), 2);

    // Unfiltered call (`&[]`) on `srv_phtml` (which bound `[".phtml"]`) must NOT hit `[".phtml"]`.
    let hits_before_unfiltered = counters.hits();
    let _ = srv_phtml
        .serve_try_files_canonical(&Method::GET, "/dir/", None, &HeaderMap::new(), &candidates)
        .await;
    assert_eq!(
        counters.hits(),
        hits_before_unfiltered,
        "P2-c: unfiltered call must NOT hit a server bound to [.phtml]"
    );

    let srv_php = srv_phtml
        .clone()
        .with_try_files_script_extensions(vec![".php".to_owned()]);
    let out4 = srv_php
        .serve_try_files_canonical_filtered(
            &Method::GET,
            "/dir/",
            None,
            &HeaderMap::new(),
            &candidates,
            &[".php".to_owned()],
        )
        .await;
    assert!(
        matches!(out4, TryFilesOutcome::InternalRewrite(ref target) if target == "/dir/index.php"),
        "P2-c: rebinding script extensions to [.php] must NOT hit [.phtml] cache entry: {out4:?}"
    );

    let _ = fs::remove_dir_all(&root);
    Ok(())
}

/// P2-d: `FillStart` carries the owning cache's identity; passing a `FillStart` sampled from
/// cache A (with a 10s-ahead manual clock) into server B (clock at 0s, 100ms window) must be
/// refused and admit nothing on direct, looked-up, and `try-files` entry points.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn p2_d_foreign_fill_start_across_caches_is_refused() -> TestResult {
    let root = temp_root("p2d-foreign-fill-start")?;
    fs::write(root.join("doc.txt"), b"v1-body")?;

    let clock_a = ManualClock::new();
    clock_a.advance(Duration::from_secs(10));
    let cache_a = FileCache::with_clock(
        Arc::new(FileCacheBudget::new(1024 * 1024)),
        FileCacheCounters::new(),
        clock_a.cache_clock(),
    );
    let foreign_start = cache_a.sample_fill_start();

    let clock_b = ManualClock::new();
    let counters_b = FileCacheCounters::new();
    let cache_b = FileCache::with_clock(
        Arc::new(FileCacheBudget::new(1024 * 1024)),
        counters_b.clone(),
        clock_b.cache_clock(),
    );
    let candidates = vec!["{path}".to_owned(), "=404".to_owned()];
    let server_b = StaticServer::open(&root, StaticConfig::default())?
        .with_file_cache(Arc::clone(&cache_b), Duration::from_millis(100))
        .with_try_files_candidates(candidates.clone());

    // 1. Direct with_start
    let r1 = server_b
        .serve_canonical_with_query_with_start(
            &Method::GET,
            "/doc.txt",
            None,
            &HeaderMap::new(),
            foreign_start,
        )
        .await;
    assert_eq!(r1.status(), StatusCode::OK);
    assert_eq!(read_body(r1).await?, b"v1-body");
    assert_eq!(
        counters_b.fills(),
        0,
        "P2-d: foreign FillStart must NOT admit via serve_canonical_with_query_with_start"
    );
    assert_eq!(cache_b.entry_count(), 0);

    // 2. Looked-up with_start
    let r2 = server_b
        .serve_canonical_looked_up_with_start(
            &Method::GET,
            "/doc.txt",
            None,
            &HeaderMap::new(),
            None,
            foreign_start,
        )
        .await;
    assert_eq!(r2.status(), StatusCode::OK);
    assert_eq!(read_body(r2).await?, b"v1-body");
    assert_eq!(
        counters_b.fills(),
        0,
        "P2-d: foreign FillStart must NOT admit via serve_canonical_looked_up_with_start"
    );
    assert_eq!(cache_b.entry_count(), 0);

    // 3. Try-files with_start
    let no_scripts: miraserve_static::ScriptOwner = Arc::new(|_| false);
    let server_b_tf = server_b
        .clone()
        .with_try_files_script_owner(Arc::clone(&no_scripts));
    let mut sampled = None;
    let out3 = server_b_tf
        .serve_try_files_canonical_routed_with_start(
            &Method::GET,
            "/doc.txt",
            None,
            &HeaderMap::new(),
            &candidates,
            &[],
            &no_scripts,
            Some(foreign_start),
            &mut sampled,
        )
        .await;
    let TryFilesOutcome::Response(r3) = out3 else {
        return Err("expected response from try-files".into());
    };
    assert_eq!(r3.status(), StatusCode::OK);
    assert_eq!(read_body(*r3).await?, b"v1-body");
    assert_eq!(
        counters_b.fills(),
        0,
        "P2-d: foreign FillStart must NOT admit via serve_try_files_canonical_routed_with_start"
    );
    assert!(
        sampled.is_none(),
        "P2-d: foreign FillStart must NOT propagate through sampled_out"
    );
    assert_eq!(cache_b.entry_count(), 0);

    // Confirm a native FillStart from cache_b DOES admit cleanly.
    let native_start = cache_b.sample_fill_start();
    let r4 = server_b
        .serve_canonical_with_query_with_start(
            &Method::GET,
            "/doc.txt",
            None,
            &HeaderMap::new(),
            native_start,
        )
        .await;
    assert_eq!(r4.status(), StatusCode::OK);
    assert_eq!(counters_b.fills(), 1);

    let _ = fs::remove_dir_all(&root);
    Ok(())
}

/// 0.1.6 Item 3: enabling `fallback-unless-extension` allocates a fresh file-cache namespace,
/// never serves an extension-like path from an earlier cached fallback entry, and never creates
/// a cached entry when fallback is refused.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn try_files_fallback_unless_extension_isolates_and_never_caches_refused_fallback()
-> TestResult {
    let root = temp_root("tf-ext-cache")?;
    fs::write(root.join("index.html"), b"SPA_SHELL")?;
    fs::write(root.join("real.js"), b"REAL_JS")?;

    let clock = ManualClock::new();
    let counters = FileCacheCounters::new();
    let cache = FileCache::with_clock(
        Arc::new(FileCacheBudget::new(1024 * 1024)),
        counters.clone(),
        clock.cache_clock(),
    );
    let candidates = vec![
        "{path}".to_owned(),
        "{path}/".to_owned(),
        "/index.html".to_owned(),
    ];
    let no_scripts: miraserve_static::ScriptOwner = Arc::new(|_| false);

    // 1. Default server (`fallback_unless_extension = false`) caches `/assets/nope.js` -> `/index.html`.
    let default_srv = StaticServer::open(&root, StaticConfig::default())?
        .with_file_cache(Arc::clone(&cache), Duration::from_secs(60))
        .with_try_files_candidates(candidates.clone())
        .with_try_files_script_owner(Arc::clone(&no_scripts));
    let out_warm = default_srv
        .serve_try_files_canonical_routed(
            &Method::GET,
            "/assets/nope.js",
            None,
            &HeaderMap::new(),
            &candidates,
            &[],
            &no_scripts,
        )
        .await;
    let TryFilesOutcome::FallbackResponse { response, .. } = out_warm else {
        return Err("expected default server to serve fallback for /assets/nope.js".into());
    };
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(read_body(*response).await?, b"SPA_SHELL");
    assert_eq!(counters.fills(), 1);
    assert_eq!(cache.entry_count(), 1);

    // 2. Cloning with `with_try_files_fallback_unless_extension(true)` allocates a fresh namespace:
    //    `/assets/nope.js` MUST NOT hit the cached fallback entry and MUST NOT create one.
    let ext_srv = default_srv.with_try_files_fallback_unless_extension(true);
    let hits_before = counters.hits();
    let fills_before = counters.fills();
    let entries_before = cache.entry_count();
    for _ in 0..2 {
        let out_refused = ext_srv
            .serve_try_files_canonical_routed(
                &Method::GET,
                "/assets/nope.js",
                None,
                &HeaderMap::new(),
                &candidates,
                &[],
                &no_scripts,
            )
            .await;
        let TryFilesOutcome::Response(resp) = out_refused else {
            return Err("expected 404 Response for refused extension fallback".into());
        };
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
    assert_eq!(counters.hits(), hits_before);
    assert_eq!(counters.fills(), fills_before);
    assert_eq!(cache.entry_count(), entries_before);

    // 3. Extensionless `/about` DOES fall back and cache; `/assets/nope.js` still misses & 404s.
    let out_about = ext_srv
        .serve_try_files_canonical_routed(
            &Method::GET,
            "/about",
            None,
            &HeaderMap::new(),
            &candidates,
            &[],
            &no_scripts,
        )
        .await;
    let TryFilesOutcome::FallbackResponse { response, .. } = out_about else {
        return Err("expected fallback for /about".into());
    };
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(read_body(*response).await?, b"SPA_SHELL");
    assert_eq!(counters.fills(), fills_before + 1);

    let out_still_404 = ext_srv
        .serve_try_files_canonical_routed(
            &Method::GET,
            "/assets/nope.js",
            None,
            &HeaderMap::new(),
            &candidates,
            &[],
            &no_scripts,
        )
        .await;
    let TryFilesOutcome::Response(resp) = out_still_404 else {
        return Err("expected 404 for /assets/nope.js after /about cached".into());
    };
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // 4. Existing file `/real.js` is served and cached directly.
    let out_real = ext_srv
        .serve_try_files_canonical_routed(
            &Method::GET,
            "/real.js",
            None,
            &HeaderMap::new(),
            &candidates,
            &[],
            &no_scripts,
        )
        .await;
    let TryFilesOutcome::Response(resp) = out_real else {
        return Err("expected direct Response for existing /real.js".into());
    };
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(read_body(*resp).await?, b"REAL_JS");
    assert_eq!(counters.fills(), fills_before + 2);

    let _ = fs::remove_dir_all(&root);
    Ok(())
}

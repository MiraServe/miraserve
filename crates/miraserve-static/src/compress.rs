//! Content-Encoding negotiation (`zstd`, `br`, `gzip`) and pure-Rust on-the-fly compression.

use std::io::Write as _;

use flate2::Compression;
use flate2::write::GzEncoder;

/// Minimum payload size in bytes before applying on-the-fly compression.
pub const MIN_COMPRESS_BYTES: u64 = 1_024;

/// Maximum payload size in bytes eligible for in-memory on-the-fly compression (4 MiB).
/// Larger payloads use pre-compressed `.zst`/`.br`/`.gz` siblings or stream uncompressed.
pub const MAX_ONTHEFLY_COMPRESS_BYTES: u64 = 4 * 1024 * 1024;

/// Supported HTTP content encodings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentEncoding {
    /// Zstandard (`zstd`), served from pre-compressed `.zst` siblings or compressed on the fly.
    Zstd,
    /// Brotli (`br`), served from `.br` siblings or compressed on the fly.
    Brotli,
    /// Gzip (`gzip`), served from `.gz` siblings or compressed on the fly.
    Gzip,
}

impl ContentEncoding {
    /// HTTP `Content-Encoding` header token.
    #[must_use]
    pub const fn header_value(self) -> &'static str {
        match self {
            Self::Zstd => "zstd",
            Self::Brotli => "br",
            Self::Gzip => "gzip",
        }
    }

    /// Pre-compressed sibling file extension suffix.
    #[must_use]
    pub const fn file_extension(self) -> &'static str {
        match self {
            Self::Zstd => ".zst",
            Self::Brotli => ".br",
            Self::Gzip => ".gz",
        }
    }
}

/// Parses an HTTP `Accept-Encoding` header and returns accepted encodings in server
/// preference order (`zstd` > `br` > `gzip`), respecting `q=0` exclusions.
#[must_use]
pub fn accepted_encodings(header_val: &str) -> Vec<ContentEncoding> {
    let mut zstd_ok = false;
    let mut br_ok = false;
    let mut gzip_ok = false;

    for raw_part in header_val.split(',') {
        let mut segments = raw_part.trim().split(';');
        let Some(token_raw) = segments.next() else {
            continue;
        };
        let token = token_raw.trim().to_ascii_lowercase();

        let mut q_nonzero = true;
        for param in segments {
            let p = param.trim();
            if let Some(q_str) = p.strip_prefix("q=").or_else(|| p.strip_prefix("Q="))
                && let Ok(q) = q_str.trim().parse::<f32>()
                && q <= 0.0
            {
                q_nonzero = false;
            }
        }
        if !q_nonzero {
            continue;
        }

        match token.as_str() {
            "zstd" => zstd_ok = true,
            "br" => br_ok = true,
            "gzip" => gzip_ok = true,
            _ => {}
        }
    }

    let mut ordered = Vec::with_capacity(3);
    if zstd_ok {
        ordered.push(ContentEncoding::Zstd);
    }
    if br_ok {
        ordered.push(ContentEncoding::Brotli);
    }
    if gzip_ok {
        ordered.push(ContentEncoding::Gzip);
    }
    ordered
}

/// Returns `true` when `Accept-Encoding` explicitly excludes `identity` (`identity;q=0`, or
/// `*;q=0` without an explicit `identity` entry of `q > 0`), per RFC 9110 §12.5.3.
#[must_use]
pub fn identity_excluded(header_val: &str) -> bool {
    let mut explicit_identity: Option<bool> = None;
    let mut wildcard_excluded = false;
    let mut wildcard_allowed = false;

    for raw_part in header_val.split(',') {
        let mut segments = raw_part.trim().split(';');
        let Some(token_raw) = segments.next() else {
            continue;
        };
        let token = token_raw.trim();
        let is_identity = token.eq_ignore_ascii_case("identity");
        let is_wildcard = token == "*";
        if !is_identity && !is_wildcard {
            continue;
        }

        let mut q_nonzero = true;
        for param in segments {
            let p = param.trim();
            if let Some(q_str) = p.strip_prefix("q=").or_else(|| p.strip_prefix("Q="))
                && let Ok(q) = q_str.trim().parse::<f32>()
                && q <= 0.0
            {
                q_nonzero = false;
            }
        }

        if is_identity {
            if q_nonzero {
                explicit_identity = Some(true);
            } else if explicit_identity.is_none() {
                explicit_identity = Some(false);
            }
        } else if is_wildcard {
            if q_nonzero {
                wildcard_allowed = true;
            } else {
                wildcard_excluded = true;
            }
        }
    }

    match explicit_identity {
        Some(allowed) => !allowed,
        None => wildcard_excluded && !wildcard_allowed,
    }
}

/// Bitmask flags for accepted HTTP content encodings (`zstd`, `br`, `gzip`), used only when a
/// site opts into the static file cache.
pub(crate) const ENC_MASK_ZSTD: u8 = 1 << 0;
pub(crate) const ENC_MASK_BR: u8 = 1 << 1;
pub(crate) const ENC_MASK_GZIP: u8 = 1 << 2;

/// Parses an HTTP `Accept-Encoding` header into a compact 3-bit mask of accepted encodings
/// (`zstd`, `br`, `gzip`), matching [`accepted_encodings`] without heap allocation.
/// Called only on cache-enabled sites.
#[must_use]
pub(crate) fn accepted_encoding_mask(header_val: &str) -> u8 {
    let mut mask = 0_u8;

    for raw_part in header_val.split(',') {
        let mut segments = raw_part.trim().split(';');
        let Some(token_raw) = segments.next() else {
            continue;
        };
        let token = token_raw.trim();
        let bit = if token.eq_ignore_ascii_case("zstd") {
            ENC_MASK_ZSTD
        } else if token.eq_ignore_ascii_case("br") {
            ENC_MASK_BR
        } else if token.eq_ignore_ascii_case("gzip") {
            ENC_MASK_GZIP
        } else {
            continue;
        };

        let mut q_nonzero = true;
        for param in segments {
            let p = param.trim();
            if let Some(q_str) = p.strip_prefix("q=").or_else(|| p.strip_prefix("Q="))
                && let Ok(q) = q_str.trim().parse::<f32>()
                && q <= 0.0
            {
                q_nonzero = false;
            }
        }
        if q_nonzero {
            mask |= bit;
        }
    }

    mask
}

/// Returns `true` if a MIME content-type benefits from HTTP compression (explicitly excluding
/// Server-Sent Events `text/event-stream`, which must stream immediately without buffering).
#[must_use]
pub fn is_compressible_mime(mime: &str) -> bool {
    if mime == "text/event-stream" {
        return false;
    }
    mime.starts_with("text/")
        || matches!(
            mime,
            "application/javascript"
                | "application/json"
                | "application/problem+json"
                | "application/xml"
                | "application/xhtml+xml"
                | "application/rss+xml"
                | "application/atom+xml"
                | "application/wasm"
                | "image/svg+xml"
        )
}

/// Compresses `input` in memory using pure-Rust Zstandard (RFC 8878 fast level).
///
/// # Errors
/// Currently infallible in memory, returning `io::Result` for parity with other encoders.
pub fn compress_zstd(input: &[u8]) -> std::io::Result<Vec<u8>> {
    Ok(ruzstd::encoding::compress_to_vec(
        input,
        ruzstd::encoding::CompressionLevel::Fastest,
    ))
}

/// Compresses `input` in memory using pure-Rust Brotli (quality 4 — fast edge latency).
///
/// # Errors
/// Returns an [`std::io::Error`] if the encoder fails to flush.
pub fn compress_brotli(input: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() / 2);
    let mut writer = brotli::CompressorWriter::new(&mut out, 4_096, 4, 22);
    writer.write_all(input)?;
    writer.flush()?;
    drop(writer);
    Ok(out)
}

/// Compresses `input` in memory using pure-Rust gzip (`flate2` / `miniz_oxide`).
///
/// # Errors
/// Returns an [`std::io::Error`] if the encoder fails to finalize.
pub fn compress_gzip(input: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::with_capacity(input.len() / 2), Compression::fast());
    encoder.write_all(input)?;
    encoder.finish()
}

/// Compresses `input` using the selected [`ContentEncoding`].
///
/// # Errors
/// Returns an [`std::io::Error`] if compression fails.
pub fn compress_bytes(enc: ContentEncoding, input: &[u8]) -> std::io::Result<Vec<u8>> {
    match enc {
        ContentEncoding::Zstd => compress_zstd(input),
        ContentEncoding::Brotli => compress_brotli(input),
        ContentEncoding::Gzip => compress_gzip(input),
    }
}

/// Decompresses a Zstandard (RFC 8878) payload using pure-Rust `ruzstd`.
///
/// # Errors
/// Returns an [`std::io::Error`] if `input` is not a valid Zstandard frame.
pub fn decompress_zstd(input: &[u8]) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;

    let mut decoder = ruzstd::decoding::StreamingDecoder::new(input)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))?;
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

enum StreamCompressorInner {
    Gzip(flate2::write::GzEncoder<Vec<u8>>),
    Brotli(Box<brotli::CompressorWriter<Vec<u8>>>),
}

/// Incremental chunk-by-chunk compressor for unknown-length HTTP response streams (`gzip` / `br`).
///
/// Flushes every input chunk immediately so live plain-text logs and NDJSON streams deliver
/// response headers and early chunks while the upstream remains open (Codex G6).
pub struct StreamCompressor {
    inner: std::sync::Mutex<Option<StreamCompressorInner>>,
}

impl StreamCompressor {
    /// Creates a streaming compressor for `enc`, returning `None` for encodings that do not
    /// support arbitrary tiny-chunk flushing (e.g. pure-Rust `zstd` block framing).
    #[must_use]
    pub fn new(enc: ContentEncoding) -> Option<Self> {
        let inner = match enc {
            ContentEncoding::Gzip => StreamCompressorInner::Gzip(flate2::write::GzEncoder::new(
                Vec::new(),
                flate2::Compression::fast(),
            )),
            ContentEncoding::Brotli => StreamCompressorInner::Brotli(Box::new(
                brotli::CompressorWriter::new(Vec::new(), 4096, 4, 22),
            )),
            ContentEncoding::Zstd => return None,
        };
        Some(Self {
            inner: std::sync::Mutex::new(Some(inner)),
        })
    }

    /// Compresses `data` and immediately flushes a decodable compressed block.
    ///
    /// # Errors
    /// Returns an [`std::io::Error`] if the compressor lock is poisoned or writing fails.
    pub fn push_chunk(&self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        self.push_piece(data, true)
    }

    /// Compresses a slice of an input chunk, flushing a decodable compressed block only when
    /// `flush` is `true`. Feeding a chunk in pieces with `flush = false` for every piece except
    /// the last produces the exact same compressed output bytes as one [`Self::push_chunk`] call
    /// on the full chunk while bounding CPU work per poll on a worker event loop.
    ///
    /// # Errors
    /// Returns an [`std::io::Error`] if the compressor lock is poisoned or writing fails.
    pub fn push_piece(&self, data: &[u8], flush: bool) -> std::io::Result<Vec<u8>> {
        use std::io::Write as _;

        let mut guard = self
            .inner
            .lock()
            .map_err(|_| std::io::Error::other("stream compressor lock poisoned"))?;
        let Some(encoder) = guard.as_mut() else {
            return Ok(Vec::new());
        };
        match encoder {
            StreamCompressorInner::Gzip(enc) => {
                enc.write_all(data)?;
                if flush {
                    enc.flush()?;
                }
                Ok(std::mem::take(enc.get_mut()))
            }
            StreamCompressorInner::Brotli(enc) => {
                enc.write_all(data)?;
                if flush {
                    enc.flush()?;
                }
                Ok(std::mem::take(enc.get_mut()))
            }
        }
    }

    /// Finalizes the stream and returns any trailing footer/metablock bytes.
    ///
    /// # Errors
    /// Returns an [`std::io::Error`] if the compressor lock is poisoned or finalization fails.
    pub fn finish(&self) -> std::io::Result<Vec<u8>> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| std::io::Error::other("stream compressor lock poisoned"))?;
        let Some(encoder) = guard.take() else {
            return Ok(Vec::new());
        };
        match encoder {
            StreamCompressorInner::Gzip(enc) => enc.finish(),
            StreamCompressorInner::Brotli(enc) => Ok(enc.into_inner()),
        }
    }
}

/// Decompresses a complete or sync-flushed partial gzip stream chunk-by-chunk.
///
/// # Errors
/// Returns an [`std::io::Error`] if `input` is not valid gzip data.
pub fn decompress_gzip(input: &[u8]) -> std::io::Result<Vec<u8>> {
    use std::io::Write as _;

    let mut dec = flate2::write::GzDecoder::new(Vec::new());
    dec.write_all(input)?;
    dec.flush()?;
    Ok(dec.get_ref().clone())
}

/// Decompresses a complete or flushed partial brotli stream.
///
/// # Errors
/// Returns an [`std::io::Error`] if `input` is not valid brotli data.
pub fn decompress_brotli(input: &[u8]) -> std::io::Result<Vec<u8>> {
    use std::io::Write as _;

    let mut dec = brotli::DecompressorWriter::new(Vec::new(), 4096);
    dec.write_all(input)?;
    dec.flush()?;
    Ok(dec.get_ref().clone())
}

/// Identifies one compressed representation of one file state: the file's device and inode,
/// its length, modification time and inode change time (as read from the open file), and the
/// encoding. Any write to the file gives a different key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CompressedKey {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) len: u64,
    pub(crate) modified: std::time::SystemTime,
    /// Inode change time (seconds, nanoseconds). Unlike the modification time it cannot be set
    /// back, so a file rewritten in place with the same size and a restored modification time
    /// (`rsync -t`, `tar`, `touch -d`) is still a different entry.
    pub(crate) changed: (i64, i64),
    pub(crate) encoding: ContentEncoding,
}

/// Memory the compressed-response cache may hold, for the whole process.
const COMPRESSED_CACHE_BUDGET_BYTES: usize = 64 * 1024 * 1024;

/// Largest single compressed body kept (an eighth of the budget).
const COMPRESSED_CACHE_MAX_ENTRY_BYTES: usize = COMPRESSED_CACHE_BUDGET_BYTES / 8;

#[derive(Default)]
struct CompressedCache {
    entries: std::collections::HashMap<CompressedKey, (bytes::Bytes, u64)>,
    total_bytes: usize,
    clock: u64,
}

fn compressed_cache() -> &'static std::sync::Mutex<CompressedCache> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<CompressedCache>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(CompressedCache::default()))
}

#[cfg(all(test, target_os = "linux"))]
fn compressed_cache_reads_by_file()
-> &'static std::sync::Mutex<std::collections::HashMap<(u64, u64), usize>> {
    static MAP: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<(u64, u64), usize>>,
    > = std::sync::OnceLock::new();
    MAP.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn reset_compressed_cache_reads_for(device: u64, inode: u64) {
    compressed_cache_reads_by_file()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert((device, inode), 0);
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn compressed_cache_reads_for(device: u64, inode: u64) -> usize {
    compressed_cache_reads_by_file()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&(device, inode))
        .copied()
        .unwrap_or(0)
}

/// Returns the cached compressed body for `key`, if any.
///
/// Compressing a file is the most expensive thing the static server does, and without a cache
/// it was done again for every request of every text file that has no precompressed sibling.
/// The cache holds bodies only; whether a request may see the file at all is decided by the
/// lookup that runs before this on every request.
pub(crate) fn cached_compressed(key: &CompressedKey) -> Option<bytes::Bytes> {
    #[cfg(all(test, target_os = "linux"))]
    {
        let mut counts = compressed_cache_reads_by_file()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *counts.entry((key.device, key.inode)).or_insert(0) += 1;
    }
    let mut cache = compressed_cache()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    cache.clock = cache.clock.saturating_add(1);
    let now = cache.clock;
    let (body, used) = cache.entries.get_mut(key)?;
    *used = now;
    Some(body.clone())
}

/// Stores a compressed body, evicting the least recently used entries when the budget is full.
pub(crate) fn store_compressed(key: CompressedKey, body: &bytes::Bytes) {
    if body.len() > COMPRESSED_CACHE_MAX_ENTRY_BYTES {
        return;
    }
    let mut cache = compressed_cache()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    cache.clock = cache.clock.saturating_add(1);
    let now = cache.clock;
    if let Some((old, _)) = cache.entries.insert(key, (body.clone(), now)) {
        cache.total_bytes = cache.total_bytes.saturating_sub(old.len());
    }
    cache.total_bytes = cache.total_bytes.saturating_add(body.len());
    if cache.total_bytes <= COMPRESSED_CACHE_BUDGET_BYTES {
        return;
    }
    // Over budget: drop the oldest entries until an eighth of the budget is free again, so
    // this scan does not run on every insert.
    let target = COMPRESSED_CACHE_BUDGET_BYTES.saturating_sub(COMPRESSED_CACHE_MAX_ENTRY_BYTES);
    let mut by_age: Vec<(u64, CompressedKey)> = cache
        .entries
        .iter()
        .map(|(key, (_, used))| (*used, key.clone()))
        .collect();
    by_age.sort_unstable_by_key(|(used, _)| *used);
    for (_, key) in by_age {
        if cache.total_bytes <= target {
            break;
        }
        if let Some((old, _)) = cache.entries.remove(&key) {
            cache.total_bytes = cache.total_bytes.saturating_sub(old.len());
        }
    }
}

#[cfg(test)]
mod cache_tests {
    use super::{
        COMPRESSED_CACHE_BUDGET_BYTES, COMPRESSED_CACHE_MAX_ENTRY_BYTES, CompressedKey,
        ContentEncoding, cached_compressed, store_compressed,
    };
    use std::time::{Duration, SystemTime};

    fn key(inode: u64, len: u64, mtime_secs: u64, encoding: ContentEncoding) -> CompressedKey {
        CompressedKey {
            // A device number no real file system uses, so parallel tests do not collide.
            device: u64::MAX - 7,
            inode,
            len,
            modified: SystemTime::UNIX_EPOCH + Duration::from_secs(mtime_secs),
            changed: (0, 0),
            encoding,
        }
    }

    fn a_changed_file_or_another_encoding_is_a_different_entry() {
        let body = bytes::Bytes::from_static(b"compressed");
        let stored = key(1, 100, 1_000, ContentEncoding::Gzip);
        store_compressed(stored.clone(), &body);
        assert_eq!(cached_compressed(&stored), Some(body));
        for other in [
            key(2, 100, 1_000, ContentEncoding::Gzip),
            key(1, 101, 1_000, ContentEncoding::Gzip),
            key(1, 100, 1_001, ContentEncoding::Gzip),
            key(1, 100, 1_000, ContentEncoding::Brotli),
            CompressedKey {
                changed: (0, 1),
                ..key(1, 100, 1_000, ContentEncoding::Gzip)
            },
        ] {
            assert_eq!(cached_compressed(&other), None, "{other:?}");
        }
    }

    /// One test for both parts: the eviction part fills the process-wide cache, which would
    /// evict the first part's entry if the two ran in parallel. Holds the crate-wide exclusive
    /// test lock so parallel tests with seeded compression-cache entries stay deterministic.
    #[test]
    fn entries_are_exact_and_the_cache_is_bounded() {
        let _lock = crate::CRED_EPOCH_TEST_LOCK.blocking_write();
        a_changed_file_or_another_encoding_is_a_different_entry();
        oversized_bodies_are_not_kept_and_old_entries_are_evicted();
    }

    fn oversized_bodies_are_not_kept_and_old_entries_are_evicted() {
        let huge = bytes::Bytes::from(vec![0_u8; COMPRESSED_CACHE_MAX_ENTRY_BYTES + 1]);
        let huge_key = key(10, 1, 1, ContentEncoding::Zstd);
        store_compressed(huge_key.clone(), &huge);
        assert_eq!(cached_compressed(&huge_key), None);

        // Fill past the budget with entries of the largest allowed size.
        let chunk = bytes::Bytes::from(vec![0_u8; COMPRESSED_CACHE_MAX_ENTRY_BYTES]);
        let count = COMPRESSED_CACHE_BUDGET_BYTES / COMPRESSED_CACHE_MAX_ENTRY_BYTES + 3;
        for i in 0..count {
            store_compressed(key(100 + i as u64, 1, 1, ContentEncoding::Zstd), &chunk);
        }
        assert_eq!(
            cached_compressed(&key(100, 1, 1, ContentEncoding::Zstd)),
            None,
            "the oldest entry is evicted once the budget is exceeded"
        );
        assert!(
            cached_compressed(&key(100 + count as u64 - 1, 1, 1, ContentEncoding::Zstd)).is_some(),
            "the newest entry stays"
        );
    }

    #[test]
    fn push_piece_matches_push_chunk_byte_for_byte_for_gzip_and_brotli()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut payload = Vec::with_capacity(512 * 1024);
        for i in 0_u32..16_384 {
            use std::io::Write as _;
            let _ = writeln!(
                payload,
                "{{\"idx\":{i},\"text\":\"streaming piece parity\"}}"
            );
        }
        let chunk_sizes = [1_024_usize, 65_536, 65_537, 200_000, 512 * 1024];

        for enc in [ContentEncoding::Gzip, ContentEncoding::Brotli] {
            for size in chunk_sizes {
                let slice = payload.get(..size.min(payload.len())).unwrap_or(&payload);

                let whole =
                    super::StreamCompressor::new(enc).ok_or("expected stream compressor")?;
                let mut whole_out = whole.push_chunk(slice)?;
                whole_out.extend_from_slice(&whole.finish()?);

                let chunked =
                    super::StreamCompressor::new(enc).ok_or("expected stream compressor")?;
                let mut chunked_out = Vec::new();
                let slices: Vec<&[u8]> = slice.chunks(64 * 1024).collect();
                for (idx, part) in slices.iter().enumerate() {
                    let is_last = idx + 1 == slices.len();
                    chunked_out.extend_from_slice(&chunked.push_piece(part, is_last)?);
                }
                chunked_out.extend_from_slice(&chunked.finish()?);

                assert_eq!(
                    chunked_out, whole_out,
                    "chunked push_piece output must match push_chunk byte for byte ({enc:?}, len={size})"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn identity_excluded_honors_rfc_9110_q0_and_wildcard_rules() {
        use super::identity_excluded;

        assert!(!identity_excluded(""));
        assert!(!identity_excluded("gzip"));
        assert!(!identity_excluded("gzip, br"));
        assert!(!identity_excluded("gzip, identity"));
        assert!(!identity_excluded("gzip, identity;q=0.5"));
        assert!(!identity_excluded("gzip, *;q=0.5"));
        assert!(!identity_excluded("gzip, identity;q=0.5, *;q=0"));
        assert!(!identity_excluded("gzip, identity, *;q=0"));

        assert!(identity_excluded("gzip, identity;q=0"));
        assert!(identity_excluded("gzip, IDENTITY; Q=0.000"));
        assert!(identity_excluded("gzip, *;q=0"));
        assert!(identity_excluded("br, *;q=0.0"));
        assert!(identity_excluded("identity;q=0"));
        assert!(identity_excluded("*;q=0"));
    }
}

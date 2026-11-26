//! RFC 9110 single-range `Range: bytes=...` parser for static file serving.

/// Inclusive byte range `[start, end]` within a known total file length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ByteRange {
    /// First byte offset (inclusive).
    pub(crate) start: u64,
    /// Last byte offset (inclusive).
    pub(crate) end: u64,
}

impl ByteRange {
    /// Number of bytes covered by this inclusive range.
    #[must_use]
    pub(crate) fn len(self) -> u64 {
        self.end.saturating_sub(self.start).saturating_add(1)
    }
}

/// Outcome of parsing an HTTP `Range` header against a file of `total_len` bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RangeParseResult {
    /// No usable single-byte range requested (serve full representation).
    Ignore,
    /// Valid satisfiable byte range (`206 Partial Content`).
    Satisfiable(ByteRange),
    /// Syntactically valid `bytes=` range that cannot be satisfied (`416 Range Not Satisfiable`).
    Unsatisfiable,
}

/// Parses a single `Range: bytes=...` header value against `total_len`.
///
/// Multi-range requests (containing `,`) fall back to serving the full representation,
/// which is RFC 9110 §14.2 compliant and avoids multipart range amplification DoS.
#[must_use]
pub(crate) fn parse_single_byte_range(header_val: &str, total_len: u64) -> RangeParseResult {
    let trimmed = header_val.trim();
    let Some(spec) = trimmed.strip_prefix("bytes=") else {
        return RangeParseResult::Ignore;
    };
    if spec.contains(',') {
        return RangeParseResult::Ignore;
    }
    let Some((start_str, end_str)) = spec.trim().split_once('-') else {
        return RangeParseResult::Ignore;
    };

    if total_len == 0 {
        return RangeParseResult::Unsatisfiable;
    }

    let last_byte = total_len.saturating_sub(1);

    if start_str.is_empty() {
        // Suffix range: bytes=-N (last N bytes)
        let Ok(suffix) = end_str.trim().parse::<u64>() else {
            return RangeParseResult::Ignore;
        };
        if suffix == 0 {
            return RangeParseResult::Unsatisfiable;
        }
        let start = total_len.saturating_sub(suffix);
        return RangeParseResult::Satisfiable(ByteRange {
            start,
            end: last_byte,
        });
    }

    let Ok(start) = start_str.trim().parse::<u64>() else {
        return RangeParseResult::Ignore;
    };
    if start >= total_len {
        return RangeParseResult::Unsatisfiable;
    }

    if end_str.trim().is_empty() {
        // Open-ended range: bytes=start-
        return RangeParseResult::Satisfiable(ByteRange {
            start,
            end: last_byte,
        });
    }

    let Ok(raw_end) = end_str.trim().parse::<u64>() else {
        return RangeParseResult::Ignore;
    };
    if raw_end < start {
        return RangeParseResult::Ignore;
    }

    RangeParseResult::Satisfiable(ByteRange {
        start,
        end: raw_end.min(last_byte),
    })
}

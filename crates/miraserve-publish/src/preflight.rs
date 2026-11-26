//! Pre-flight safety checks executed before atomic site bundle activation (Threat Model T6).
//!
//! Guards self-updating AI websites against secret leaks (including non-UTF-8 and UTF-16
//! obfuscation), inline XSS injection across HTML/SVG/XHTML/XML, weakened CSP meta tags,
//! pre-compressed sibling bypasses, unsafe cross-platform paths, and storage quota abuse.

use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

use html5ever::interface::tree_builder::{
    ElemName, ElementFlags, NodeOrText, QuirksMode, TreeSink,
};
use html5ever::tendril::StrTendril;
use html5ever::tokenizer::{
    BufferQueue, Token, TokenSink, TokenSinkResult, Tokenizer, TokenizerOpts,
};
use html5ever::tree_builder::{TreeBuilder, TreeBuilderOpts};
use html5ever::{Attribute, LocalName, Namespace, ParseOpts, QualName, TokenizerResult};
use miraserve_config::PreflightCheck;
use serde::Serialize;

use crate::crypto::SiteBundle;

/// Maximum DOM nodes accepted in a single HTML or XML document (anti-DoS bound, `R4-PUB-6`).
const MAX_DOM_NODES: usize = 200_000;
/// Maximum DOM tree nesting depth accepted in a single HTML or XML document (`R5-PUB-8`, `R6-PUB-6`).
const MAX_DOM_DEPTH: u16 = 512;
/// Maximum attributes accepted on a single HTML or XML element (`R6-PUB-6`).
const MAX_ATTRS_PER_ELEMENT: usize = 1_024;
/// Maximum total attribute bytes stored across an entire parsed DOM arena (`R6-PUB-6`),
/// preventing HTML5 adoption-agency formatting-element cloning from amplifying memory.
const MAX_TOTAL_ATTR_BYTES: usize = 4 * 1024 * 1024;
/// Per-file active markup size cap (2 MiB) to bound parser memory/CPU (`R5-PUB-8`).
const MAX_MARKUP_FILE_BYTES: usize = 2 * 1024 * 1024;
/// Chunk size fed to `html5ever` per step so limit/fatal aborts trigger immediately (`R5-PUB-8`).
const HTML_FEED_CHUNK_BYTES: usize = 4_096;
/// Hard per-file CPU budget for HTML/XML preflight scanning (`R7-SCAN-3`), measured with
/// [`scan_clock_now`].
const MAX_FILE_MARKUP_SCAN_DURATION: Duration = Duration::from_secs(1);
/// Base whole-bundle CPU budget across all active markup files (`R7-SCAN-3`).
const MAX_BUNDLE_MARKUP_SCAN_DURATION: Duration = Duration::from_secs(5);
/// Extra whole-bundle budget per MiB of active markup (`R8-SCAN-1`). A fixed 5 s budget rejected
/// large legitimate sites; the per-file budget above still bounds any single hostile file.
const BUNDLE_MARKUP_SCAN_DURATION_PER_MIB: Duration = Duration::from_secs(1);

/// Whole-bundle scan budget for `markup_bytes` of active markup (`R8-SCAN-1`).
fn bundle_markup_scan_budget(markup_bytes: u64) -> Duration {
    let markup_mib = u32::try_from(markup_bytes / (1024 * 1024)).unwrap_or(u32::MAX);
    MAX_BUNDLE_MARKUP_SCAN_DURATION
        .saturating_add(BUNDLE_MARKUP_SCAN_DURATION_PER_MIB.saturating_mul(markup_mib))
}

/// Clock for the scan budgets (`R8-SCAN-1`).
///
/// On Unix this is the CPU time consumed by the scanning thread, so the budget measures the
/// scanner's own work. A wall clock made the verdict depend on what else the machine was doing:
/// the same valid bundle passed on an idle host and was rejected under load, and the same check
/// at startup could drop a site to an older release. Elsewhere it falls back to elapsed wall time.
#[cfg(unix)]
fn scan_clock_now() -> Duration {
    let ts = rustix::time::clock_gettime(rustix::time::ClockId::ThreadCPUTime);
    Duration::new(
        u64::try_from(ts.tv_sec).unwrap_or(0),
        u32::try_from(ts.tv_nsec).unwrap_or(0),
    )
}

#[cfg(not(unix))]
fn scan_clock_now() -> Duration {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START.get_or_init(std::time::Instant::now).elapsed()
}

/// HTML/XHTML XML namespace URI.
const HTML_NS: &str = "http://www.w3.org/1999/xhtml";
/// SVG XML namespace URI.
const SVG_NS: &str = "http://www.w3.org/2000/svg";
/// `XLink` XML namespace URI.
const XLINK_NS: &str = "http://www.w3.org/1999/xlink";
/// Standard XML namespace URI (`xml:base`, `xml:lang`, etc.).
const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

/// A single pre-flight safety check violation preventing publication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreflightViolation {
    /// Stable pre-flight rule identifier (e.g. `"NO_SECRETS"`, `"NO_INLINE_SCRIPTS"`).
    pub rule: &'static str,
    /// Offending bundle file path (or `"<bundle>"` for whole-bundle limits).
    pub path: String,
    /// Human-readable violation explanation.
    pub detail: String,
}

/// Runs mandatory path safety validation plus every configured [`PreflightCheck`] on `bundle`.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn run_preflight_checks(
    bundle: &SiteBundle,
    checks: &[PreflightCheck],
) -> Vec<PreflightViolation> {
    let mut violations = Vec::new();

    if bundle.files.is_empty() {
        violations.push(PreflightViolation {
            rule: "NON_EMPTY_BUNDLE",
            path: "<bundle>".to_owned(),
            detail: "bundle must contain at least one file".to_owned(),
        });
        return violations;
    }

    // 1. Always enforce path confinement, disallow pre-compressed siblings, reject Unicode
    //    case-colliding paths (`A.html` vs `a.html`, `É.html` vs `é.html`, `R2-PUB-8`), and
    //    reject file/directory prefix collisions (`PUB-9`).
    let mut normalized_paths = std::collections::HashSet::with_capacity(bundle.files.len());
    for path in bundle.files.keys() {
        if let Some(reason) = check_bundle_path_safety(path) {
            violations.push(PreflightViolation {
                rule: "SAFE_PATH",
                path: path.clone(),
                detail: reason.to_owned(),
            });
        } else {
            let norm = path.trim_start_matches('/').to_lowercase();
            if !normalized_paths.insert(norm) {
                violations.push(PreflightViolation {
                    rule: "SAFE_PATH",
                    path: path.clone(),
                    detail: format!(
                        "bundle path '{path}' collides case-insensitively with another file in the same bundle"
                    ),
                });
            }
        }
    }
    for path in bundle.files.keys() {
        let trimmed = path.trim_start_matches('/').to_lowercase();
        let mut cursor = trimmed.as_str();
        while let Some((parent, _)) = cursor.rsplit_once('/') {
            if normalized_paths.contains(parent) {
                violations.push(PreflightViolation {
                    rule: "SAFE_PATH",
                    path: path.clone(),
                    detail: format!(
                        "bundle path '{path}' conflicts with regular file '{parent}' in the same bundle"
                    ),
                });
                break;
            }
            cursor = parent;
        }
    }

    // 2. Run configured non-markup checks first, and record whether active-markup checks apply.
    let mut check_no_inline = false;
    let mut check_csp_valid = false;
    let mut size_or_file_limit_failed = false;
    for check in checks {
        match check {
            PreflightCheck::MaxSize(limit) => {
                let total: u64 = bundle
                    .files
                    .values()
                    .fold(0_u64, |acc, b| acc.saturating_add(b.len() as u64));
                if total > limit.as_bytes() {
                    size_or_file_limit_failed = true;
                    violations.push(PreflightViolation {
                        rule: "MAX_SIZE",
                        path: "<bundle>".to_owned(),
                        detail: format!(
                            "total bundle size {total} bytes exceeds max-size limit of {} bytes",
                            limit.as_bytes()
                        ),
                    });
                }
            }
            PreflightCheck::MaxFiles(limit) => {
                if bundle.files.len() > usize::try_from(*limit).unwrap_or(usize::MAX) {
                    size_or_file_limit_failed = true;
                    violations.push(PreflightViolation {
                        rule: "MAX_FILES",
                        path: "<bundle>".to_owned(),
                        detail: format!(
                            "bundle contains {} files, exceeding max-files limit of {limit}",
                            bundle.files.len()
                        ),
                    });
                }
            }
            PreflightCheck::NoSecrets => {
                for (path, bytes) in &bundle.files {
                    if let Some(kind) = detect_leaked_secret_bytes(bytes) {
                        violations.push(PreflightViolation {
                            rule: "NO_SECRETS",
                            path: path.clone(),
                            detail: format!("potential leaked credential detected ({kind})"),
                        });
                    }
                }
            }
            PreflightCheck::NoInlineScripts => check_no_inline = true,
            PreflightCheck::CspValid => check_csp_valid = true,
        }
    }

    // 3. Real HTML5 (`html5ever`) + strict XML (`roxmltree`, DTD subset disabled) tree inspection
    //    driven by exact served MIME type (`R4-PUB-1`, `R4-PUB-4`, `R4-PUB-6`, `R5-PUB-8..14`).
    //    R5-PUB-8: Skip expensive markup parsing when bundle `max-size` / `max-files` already failed.
    //    R7-SCAN-3 & R8-SCAN-1: Enforce a whole-bundle CPU-time budget across all markup files.
    if (check_no_inline || check_csp_valid) && !size_or_file_limit_failed {
        let markup_bytes: u64 = bundle
            .files
            .iter()
            .filter(|(path, _)| classify_markup_kind(path).is_some())
            .map(|(_, bytes)| bytes.len() as u64)
            .sum();
        let bundle_deadline =
            scan_clock_now().saturating_add(bundle_markup_scan_budget(markup_bytes));
        for (path, bytes) in &bundle.files {
            let Some(kind) = classify_markup_kind(path) else {
                continue;
            };
            if scan_clock_now() > bundle_deadline {
                push_markup_parse_error(
                    &mut violations,
                    path,
                    "bundle markup scan exceeded total CPU time budget",
                    check_no_inline,
                    check_csp_valid,
                );
                break;
            }
            inspect_active_markup(
                path,
                bytes,
                kind,
                check_no_inline,
                check_csp_valid,
                bundle_deadline,
                &mut violations,
            );
        }
    }

    violations
}

fn check_bundle_path_safety(path: &str) -> Option<&'static str> {
    if path.is_empty() {
        return Some("file path must not be empty");
    }
    if path.starts_with('/')
        || path.contains('\\')
        || path.contains('\0')
        || path.chars().any(char::is_control)
    {
        return Some(
            "file path must be a relative POSIX path without leading '/', '\\', or control characters",
        );
    }
    // Block Windows drive prefixes (e.g. `C:foo`, `C:/foo`) and ADS streams (`file:stream`).
    if path.contains(':') {
        return Some("file path must not contain ':' (Windows drive or stream prefix)");
    }
    // Block pre-compressed static siblings (`.gz`, `.br`, `.zst`) that MiraServe StaticServer
    // would serve directly over uncompressed counterparts, bypassing HTML/secret preflight.
    if is_precompressed_artifact_path(path) {
        return Some(
            "pre-compressed static siblings (.gz, .br, .zst) are forbidden in AI publish bundles",
        );
    }

    for seg in path.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return Some("file path contains forbidden '.', '..', or empty segment");
        }
        if seg.starts_with('.') && seg != ".well-known" {
            return Some("dotfiles are forbidden in published site bundles");
        }
        if seg.ends_with('.') || seg.ends_with(' ') {
            return Some("file path segment must not end with '.' or trailing space");
        }
        if is_windows_reserved_name(seg) {
            return Some("file path contains reserved OS device name");
        }
    }
    None
}

fn is_precompressed_artifact_path(path: &str) -> bool {
    std::path::Path::new(path)
        .extension()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|ext| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "gz" | "gzip" | "br" | "brotli" | "zst" | "zstd" | "svgz"
            )
        })
}

fn is_windows_reserved_name(seg: &str) -> bool {
    let trimmed = seg.trim_end_matches(['.', ' ']);
    let stem = trimmed
        .split('.')
        .next()
        .unwrap_or(trimmed)
        .trim_end_matches(' ');
    let upper = stem.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM0"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT0"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

/// Document grammar classification derived from the exact MIME type served by `miraserve-static`
/// (`R3-PUB-1`, `R3-PUB-2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MarkupKind {
    /// HTML (`text/html`, including `.html`, `.htm`, `.hxt`, `.shtml`). Supports HTML5 raw-text
    /// elements ONLY outside `<svg>`/`<math>` foreign content.
    Html,
    /// XML/XHTML/SVG/MathML/XSLT/RSS/Atom (`image/svg+xml`, `application/xhtml+xml`, `text/xml`,
    /// `application/xml`, `*+xml`, `text/xsl`, etc.). Raw-text skipping is NEVER allowed in XML.
    Xml,
}

fn classify_markup_kind(path: &str) -> Option<MarkupKind> {
    let essence = miraserve_static::mime_essence_for_path(std::path::Path::new(path));
    if essence == "text/html" {
        return Some(MarkupKind::Html);
    }
    if matches!(
        essence.as_str(),
        "image/svg+xml"
            | "application/xhtml+xml"
            | "application/xml"
            | "text/xml"
            | "text/xsl"
            | "application/xslt+xml"
            | "application/mathml+xml"
            | "application/rss+xml"
            | "application/atom+xml"
    ) || essence.ends_with("+xml")
    {
        return Some(MarkupKind::Xml);
    }
    // Belt-and-suspenders extension fallback for active markup extensions.
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(std::ffi::OsStr::to_str)
        .map(str::to_ascii_lowercase);
    match ext.as_deref() {
        Some("html" | "htm" | "shtml" | "hxt") => Some(MarkupKind::Html),
        Some(
            "xhtml" | "xht" | "svg" | "xml" | "xsl" | "xslt" | "mathml" | "mml" | "rss" | "atom"
            | "rdf" | "xul",
        ) => Some(MarkupKind::Xml),
        _ => None,
    }
}

fn inspect_active_markup(
    path: &str,
    bytes: &[u8],
    kind: MarkupKind,
    check_no_inline: bool,
    check_csp_valid: bool,
    bundle_deadline: Duration,
    violations: &mut Vec<PreflightViolation>,
) {
    // R5-PUB-8: Per-file active markup size cap prevents unbounded parser CPU/RAM on huge single files.
    if bytes.len() > MAX_MARKUP_FILE_BYTES {
        push_markup_parse_error(
            violations,
            path,
            &format!(
                "active HTML/SVG/XML file size ({} bytes) exceeds the 2 MiB ({MAX_MARKUP_FILE_BYTES} bytes) preflight markup scan cap; split large HTML pages or optimize/externalize large SVG assets",
                bytes.len()
            ),
            check_no_inline,
            check_csp_valid,
        );
        return;
    }
    // R3-PUB-2: Reject UTF-16/UTF-32 BOMs and ANY NUL byte (defeating BOM-less UTF-16 smuggling).
    if bytes.starts_with(&[0xFE, 0xFF])
        || bytes.starts_with(&[0xFF, 0xFE])
        || bytes.starts_with(&[0x00, 0x00, 0xFE, 0xFF])
        || bytes.contains(&0)
    {
        push_markup_parse_error(
            violations,
            path,
            "active HTML/SVG/XML document contains forbidden NUL bytes or non-UTF-8 BOM",
            check_no_inline,
            check_csp_valid,
        );
        return;
    }
    let Ok(markup) = std::str::from_utf8(bytes) else {
        push_markup_parse_error(
            violations,
            path,
            "active HTML/SVG/XML document must be valid UTF-8",
            check_no_inline,
            check_csp_valid,
        );
        return;
    };

    let file_deadline = scan_clock_now()
        .saturating_add(MAX_FILE_MARKUP_SCAN_DURATION)
        .min(bundle_deadline);
    match kind {
        MarkupKind::Html => {
            inspect_html_document(
                path,
                markup,
                check_no_inline,
                check_csp_valid,
                file_deadline,
                violations,
            );
        }
        MarkupKind::Xml => {
            inspect_xml_document(
                path,
                markup,
                check_no_inline,
                check_csp_valid,
                file_deadline,
                violations,
            );
        }
    }
}

fn push_markup_parse_error(
    violations: &mut Vec<PreflightViolation>,
    path: &str,
    detail: &str,
    check_no_inline: bool,
    check_csp_valid: bool,
) {
    if check_no_inline {
        violations.push(PreflightViolation {
            rule: "NO_INLINE_SCRIPTS",
            path: path.to_owned(),
            detail: detail.to_owned(),
        });
    }
    if check_csp_valid {
        violations.push(PreflightViolation {
            rule: "CSP_VALID",
            path: path.to_owned(),
            detail: detail.to_owned(),
        });
    }
}

/// Scans raw bytes for leaked credentials across UTF-8, lossy UTF-8 (defeating invalid-byte
/// prefix bypasses), and UTF-16LE/BE encodings.
fn detect_leaked_secret_bytes(bytes: &[u8]) -> Option<&'static str> {
    let lossy = String::from_utf8_lossy(bytes);
    if let Some(kind) = detect_leaked_secret(&lossy) {
        return Some(kind);
    }

    // Check UTF-16LE / UTF-16BE encodings (explicit BOM or high NUL-byte cadence).
    if let Some(decoded_utf16) = try_decode_utf16_ascii(bytes)
        && let Some(kind) = detect_leaked_secret(&decoded_utf16)
    {
        return Some(kind);
    }

    None
}

fn try_decode_utf16_ascii(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 8 {
        return None;
    }
    let (is_be, slice) = if bytes.starts_with(&[0xFE, 0xFF]) {
        (true, bytes.get(2..)?)
    } else if bytes.starts_with(&[0xFF, 0xFE]) {
        (false, bytes.get(2..)?)
    } else {
        // Heuristic: check if at least 25% of bytes are NUL (typical UTF-16 ASCII text).
        let mut even_nuls = 0_usize;
        let mut odd_nuls = 0_usize;
        for (idx, &b) in bytes.iter().enumerate() {
            if b == 0 {
                if idx % 2 == 0 {
                    even_nuls = even_nuls.saturating_add(1);
                } else {
                    odd_nuls = odd_nuls.saturating_add(1);
                }
            }
        }
        let nul_count = even_nuls.saturating_add(odd_nuls);
        if nul_count * 4 < bytes.len() {
            return None;
        }
        (even_nuls > odd_nuls, bytes)
    };

    let (pairs, _) = slice.as_chunks::<2>();
    let mut units = Vec::with_capacity(pairs.len());
    for &[b0, b1] in pairs {
        let unit = if is_be {
            u16::from_be_bytes([b0, b1])
        } else {
            u16::from_le_bytes([b0, b1])
        };
        units.push(unit);
    }
    Some(String::from_utf16_lossy(&units))
}

/// Deterministic high-precision secret scanner (zero regex DoS risk).
fn detect_leaked_secret(text: &str) -> Option<&'static str> {
    // 1. Private keys
    if text.contains("-----BEGIN ") && text.contains(" PRIVATE KEY-----") {
        return Some("PEM private key block");
    }
    if text.contains("miraserve-ed25519-sec:") {
        return Some("MiraServe Ed25519 signing secret");
    }

    // 2. High-confidence provider key prefixes
    let prefixes: &[(&str, usize, &str)] = &[
        ("sk-ant-", 20, "Anthropic API key"),
        ("sk-proj-", 20, "OpenAI project API key"),
        ("sk_live_", 16, "Stripe live secret key"),
        ("ghp_", 24, "GitHub personal access token"),
        ("github_pat_", 24, "GitHub fine-grained PAT"),
        ("xoxb-", 20, "Slack bot token"),
        ("xoxp-", 20, "Slack user token"),
        ("AIzaSy", 30, "Google API key"),
    ];

    for &(prefix, min_len, label) in prefixes {
        if has_token_with_prefix(text, prefix, min_len) {
            return Some(label);
        }
    }

    // 3. AWS Access Key ID: `AKIA` followed by 16 uppercase alphanumeric chars
    if has_aws_access_key(text) {
        return Some("AWS access key ID");
    }

    // 4. Generic OpenAI legacy `sk-` followed by >= 32 alphanumeric chars
    if has_token_with_prefix(text, "sk-", 35) {
        return Some("OpenAI / bearer secret key");
    }

    None
}

fn has_token_with_prefix(text: &str, prefix: &str, min_total_len: usize) -> bool {
    let mut search = text;
    while let Some(pos) = search.find(prefix) {
        let candidate = search.get(pos..).unwrap_or("");
        let tok_len = candidate
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
            .count();
        if tok_len >= min_total_len {
            return true;
        }
        search = candidate.get(prefix.len()..).unwrap_or("");
    }
    false
}

fn has_aws_access_key(text: &str) -> bool {
    let mut search = text;
    while let Some(pos) = search.find("AKIA") {
        let candidate = search.get(pos..).unwrap_or("");
        let ok = candidate.get(4..20).is_some_and(|rest| {
            rest.bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        });
        if ok {
            return true;
        }
        search = candidate.get(4..).unwrap_or("");
    }
    false
}

/// Owned element name returned by [`HtmlDomSink::elem_name`] (O(1) interned `QualName` clone;
/// avoids holding any `RefCell` borrow across `html5ever` callbacks).
#[derive(Debug)]
struct OwnedElemName(QualName);

impl ElemName for OwnedElemName {
    fn ns(&self) -> &Namespace {
        &self.0.ns
    }

    fn local_name(&self) -> &LocalName {
        &self.0.local
    }
}

type NodeId = usize;

/// Namespace-aware DOM attribute preserving XML/HTML attribute namespaces (`R5-PUB-14`).
#[derive(Debug, Clone)]
struct ParsedAttr {
    ns: Option<String>,
    local: String,
    value: String,
}

impl ParsedAttr {
    fn is_unqualified(&self, expected_local: &str) -> bool {
        self.ns.is_none() && self.local == expected_local
    }

    fn is_href(&self) -> bool {
        self.local == "href" && (self.ns.is_none() || self.ns.as_deref() == Some(XLINK_NS))
    }
}

/// Arena node with O(1) intrusive doubly-linked sibling pointers (`R5-PUB-8`: eliminates ALL
/// quadratic `Vec::position()` / `Vec::remove()` / `Vec::insert()` foster-parenting scans!).
struct DomNode {
    parent: Option<NodeId>,
    first_child: Option<NodeId>,
    last_child: Option<NodeId>,
    prev_sibling: Option<NodeId>,
    next_sibling: Option<NodeId>,
    depth: u16,
    line: u64,
    data: NodeData,
}

enum NodeData {
    Document,
    DocumentFragment,
    Doctype,
    Element {
        name: QualName,
        attrs: Vec<ParsedAttr>,
        mathml_integration_point: bool,
        template_contents: Option<NodeId>,
        had_duplicate_attributes: bool,
    },
    Text(String),
    Comment,
    ProcessingInstruction {
        target: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArenaLimitExceeded {
    Depth,
    Nodes,
    AttrCount,
    AttrBytes,
    ScanTimeout,
}

struct ArenaState {
    nodes: Vec<DomNode>,
    current_line: u64,
    fatal_parse_error: Option<(u64, String)>,
    limit_exceeded: Option<ArenaLimitExceeded>,
    total_attr_bytes: usize,
    abort_flag: Rc<Cell<bool>>,
}

impl ArenaState {
    fn new(abort_flag: Rc<Cell<bool>>) -> Self {
        Self {
            nodes: vec![DomNode {
                parent: None,
                first_child: None,
                last_child: None,
                prev_sibling: None,
                next_sibling: None,
                depth: 0,
                line: 1,
                data: NodeData::Document,
            }],
            current_line: 1,
            fatal_parse_error: None,
            limit_exceeded: None,
            total_attr_bytes: 0,
            abort_flag,
        }
    }

    fn record_limit(&mut self, kind: ArenaLimitExceeded) {
        if self.limit_exceeded.is_none() {
            self.limit_exceeded = Some(kind);
        }
        self.abort_flag.set(true);
    }

    fn account_attr_bytes(&mut self, bytes: usize) -> bool {
        self.total_attr_bytes = self.total_attr_bytes.saturating_add(bytes);
        if self.total_attr_bytes > MAX_TOTAL_ATTR_BYTES {
            self.record_limit(ArenaLimitExceeded::AttrBytes);
            return false;
        }
        true
    }

    fn push_node(&mut self, data: NodeData) -> NodeId {
        if self.nodes.len() >= MAX_DOM_NODES {
            self.record_limit(ArenaLimitExceeded::Nodes);
        }
        // Always return a distinct valid handle during the remainder of the current 4 KiB chunk
        // so `html5ever`'s internal `open_elems` stack never sees document handle `0` and panics;
        // `parse_html_dom` drops the parser immediately after the chunk finishes (`R5-PUB-8`).
        let id = self.nodes.len();
        self.nodes.push(DomNode {
            parent: None,
            first_child: None,
            last_child: None,
            prev_sibling: None,
            next_sibling: None,
            depth: 0,
            line: self.current_line,
            data,
        });
        id
    }

    /// O(1) unlink from parent's doubly-linked child list (`R5-PUB-8`).
    fn detach(&mut self, target: NodeId) {
        let Some((old_parent, prev, next)) = self.nodes.get_mut(target).and_then(|n| {
            let p = n.parent.take()?;
            let prev = n.prev_sibling.take();
            let next = n.next_sibling.take();
            Some((p, prev, next))
        }) else {
            return;
        };
        if let Some(prev_id) = prev {
            if let Some(prev_node) = self.nodes.get_mut(prev_id) {
                prev_node.next_sibling = next;
            }
        } else if let Some(parent_node) = self.nodes.get_mut(old_parent) {
            parent_node.first_child = next;
        }
        if let Some(next_id) = next {
            if let Some(next_node) = self.nodes.get_mut(next_id) {
                next_node.prev_sibling = prev;
            }
        } else if let Some(parent_node) = self.nodes.get_mut(old_parent) {
            parent_node.last_child = prev;
        }
    }

    fn check_child_depth(&mut self, parent: NodeId) -> Option<u16> {
        let parent_depth = self.nodes.get(parent).map_or(0, |n| n.depth);
        let child_depth = parent_depth.saturating_add(1);
        if child_depth > MAX_DOM_DEPTH {
            self.record_limit(ArenaLimitExceeded::Depth);
            return None;
        }
        Some(child_depth)
    }

    /// O(1) append to parent's doubly-linked child list with strict nesting depth cap (`R5-PUB-8`).
    fn append_child(&mut self, parent: NodeId, child: NodeOrText<NodeId>) {
        if self.abort_flag.get() {
            return;
        }
        let Some(child_depth) = self.check_child_depth(parent) else {
            return;
        };
        match child {
            NodeOrText::AppendText(text) => {
                if let Some(last_id) = self.nodes.get(parent).and_then(|n| n.last_child)
                    && let Some(NodeData::Text(existing)) =
                        self.nodes.get_mut(last_id).map(|n| &mut n.data)
                {
                    existing.push_str(&text);
                    return;
                }
                let text_id = self.push_node(NodeData::Text(text.to_string()));
                if text_id == 0 {
                    return;
                }
                self.link_as_last_child(parent, text_id, child_depth);
            }
            NodeOrText::AppendNode(child_id) => {
                if child_id == 0 || child_id == parent {
                    return;
                }
                self.detach(child_id);
                self.link_as_last_child(parent, child_id, child_depth);
            }
        }
    }

    fn link_as_last_child(&mut self, parent: NodeId, child_id: NodeId, child_depth: u16) {
        let old_last = self.nodes.get(parent).and_then(|p| p.last_child);
        if let Some(cn) = self.nodes.get_mut(child_id) {
            cn.parent = Some(parent);
            cn.prev_sibling = old_last;
            cn.next_sibling = None;
            cn.depth = child_depth;
        }
        if let Some(last_id) = old_last {
            if let Some(ln) = self.nodes.get_mut(last_id) {
                ln.next_sibling = Some(child_id);
            }
        } else if let Some(pn) = self.nodes.get_mut(parent) {
            pn.first_child = Some(child_id);
        }
        if let Some(pn) = self.nodes.get_mut(parent) {
            pn.last_child = Some(child_id);
        }
    }

    /// O(1) insert immediately before `sibling` using intrusive sibling pointers (`R5-PUB-8`).
    fn insert_before_sibling(&mut self, sibling: NodeId, new_node: NodeOrText<NodeId>) {
        if self.abort_flag.get() {
            return;
        }
        let Some((parent, prev_of_sibling)) = self
            .nodes
            .get(sibling)
            .and_then(|n| Some((n.parent?, n.prev_sibling)))
        else {
            return;
        };
        let Some(child_depth) = self.check_child_depth(parent) else {
            return;
        };
        match new_node {
            NodeOrText::AppendText(text) => {
                if let Some(prev_id) = prev_of_sibling
                    && let Some(NodeData::Text(existing)) =
                        self.nodes.get_mut(prev_id).map(|n| &mut n.data)
                {
                    existing.push_str(&text);
                    return;
                }
                let text_id = self.push_node(NodeData::Text(text.to_string()));
                if text_id == 0 {
                    return;
                }
                self.link_before(parent, sibling, prev_of_sibling, text_id, child_depth);
            }
            NodeOrText::AppendNode(child_id) => {
                if child_id == 0 || child_id == parent || child_id == sibling {
                    return;
                }
                self.detach(child_id);
                // Re-read sibling's current `prev_sibling` after `detach(child_id)` in case
                // `child_id` was itself `prev_of_sibling`!
                let cur_prev = self.nodes.get(sibling).and_then(|n| n.prev_sibling);
                self.link_before(parent, sibling, cur_prev, child_id, child_depth);
            }
        }
    }

    fn link_before(
        &mut self,
        parent: NodeId,
        sibling: NodeId,
        prev: Option<NodeId>,
        child_id: NodeId,
        child_depth: u16,
    ) {
        if let Some(cn) = self.nodes.get_mut(child_id) {
            cn.parent = Some(parent);
            cn.prev_sibling = prev;
            cn.next_sibling = Some(sibling);
            cn.depth = child_depth;
        }
        if let Some(prev_id) = prev {
            if let Some(pn) = self.nodes.get_mut(prev_id) {
                pn.next_sibling = Some(child_id);
            }
        } else if let Some(parent_node) = self.nodes.get_mut(parent) {
            parent_node.first_child = Some(child_id);
        }
        if let Some(sn) = self.nodes.get_mut(sibling) {
            sn.prev_sibling = Some(child_id);
        }
    }
}

/// Zero-`unsafe` O(1) arena-backed `html5ever` `TreeSink` implementing full WHATWG HTML5 parsing
/// including SVG/MathML namespaces, HTML integration points, `<template>` fragments, script
/// double-escaped states, bounded DOM node counts, and bounded tree depth (`R4-PUB-1`, `R5-PUB-8`).
struct HtmlDomSink {
    state: Rc<RefCell<ArenaState>>,
    fallback_name: QualName,
}

impl HtmlDomSink {
    fn new(state: Rc<RefCell<ArenaState>>) -> Self {
        Self {
            state,
            fallback_name: QualName::new(None, Namespace::from(""), LocalName::from("")),
        }
    }
}

/// Allow-list of benign WHATWG HTML5 parse errors encountered on ordinary valid pages (`R5-PUB-9`),
/// while keeping EVERY security-critical tokenizer/foreign-content error fatal (`R4-PUB-1`):
/// - Empty `.html` / snippet HTML without `<!DOCTYPE html>`
/// - Standard legacy HTML/XHTML DOCTYPEs (`Bad DOCTYPE: Doctype { name: Some(Tendril("html"))`)
/// - Unescaped `<` in prose such as `a < b` (EXCEPT `<?` bogus PIs!)
/// - Missing semicolon on named character references (`&nbsp`, `AT&T`)
/// - Self-closing syntax on non-void HTML elements (`<div/>`, `<i class="fa"/>`)
/// - Duplicate safe attributes on non-security elements (handled per-element in DOM inspection)
/// - Ordinary HTML tree recovery (stray `</p>`, nested `<a>`, unclosed HTML body tags at EOF)
///
/// Security-critical errors that remain STRICTLY FATAL:
/// - Bogus PIs (`Saw ? in state TagOpen`), attributes on end tags, self-closing end tags
/// - Unexpected EOF inside comments/scripts/rawtext/tags (`Saw EOF in state ...`)
/// - Bogus DOCTYPE syntax (`Saw ... in state Doctype*`), foreign-content mismatches
#[allow(clippy::too_many_lines)]
fn is_benign_html5_parse_error(msg: &str) -> bool {
    // 1. Empty `.html` or snippet HTML omitting `<!DOCTYPE html>`
    if msg.ends_with("in insertion mode Initial")
        && (msg.starts_with("Unexpected token Tag(Tag { kind: StartTag")
            || msg.starts_with("Unexpected token Tag { kind: StartTag")
            || msg.starts_with("Unexpected token CharacterTokens(")
            || msg.starts_with("Unexpected token Eof"))
    {
        return true;
    }

    // 2. Legacy valid HTML/XHTML DOCTYPEs (e.g. XHTML 1.0 Transitional, HTML 4.01, `<!DOCTYPE html5>`)
    if msg.starts_with("Bad DOCTYPE: Doctype { name: Some(")
        && (msg.contains("\"html\"")
            || msg.contains("\"HTML\"")
            || msg.contains("\"html5\"")
            || msg.contains("\"HTML5\""))
    {
        return true;
    }

    // 3. `a < b` or `x < 5` in prose (NEVER allow `<?` bogus PI or `\0`!)
    if let Some(rest) = msg.strip_prefix("Saw ")
        && rest.ends_with(" in state TagOpen")
        && !rest.starts_with('?')
        && !rest.starts_with('!')
        && !rest.starts_with('/')
        && !rest.starts_with('\0')
    {
        return true;
    }

    // 3b. R6-PUB-7: Benign sloppy HTML5 tokenizer syntax that browsers and `html5ever` parse identically:
    //     - Missing space between attributes (`<a href="/x"class="y">`)
    //     - Abrupt `--!>` HTML5 comment closer (`<!-- a --!>`)
    //     - Space after `</` in stray end tag (`</ p>`)
    if let Some(rest) = msg.strip_prefix("Saw ") {
        if rest.ends_with(" in state AfterAttributeValueQuoted") && !rest.starts_with('\0') {
            return true;
        }
        if msg == "Saw > in state CommentEndBang" {
            return true;
        }
        if rest.ends_with(" in state EndTagOpen")
            && (rest.starts_with(' ') || rest.starts_with('\t') || rest.starts_with('\n'))
        {
            return true;
        }
        // R7-SCAN-6: Whitespace after `/` in a self-closing start tag (`<img src=a.png / >`)
        // transitions to `BeforeAttributeName`; any trailing `onerror=...` is still tokenized as
        // a real attribute and caught by `check_element_security`.
        if rest.ends_with(" in state SelfClosingStartTag")
            && (rest.starts_with(' ')
                || rest.starts_with('\t')
                || rest.starts_with('\n')
                || rest.starts_with('\r'))
        {
            return true;
        }
    }

    // 4. Missing semicolon on named or numeric character references (`&nbsp`, `a&b`, `&#169 2025`)
    if msg == "Character reference does not end with semicolon"
        || msg == "Semicolon missing after numeric character reference"
        || msg.starts_with("Invalid character reference &")
    {
        return true;
    }

    // 5. `<div/>` / `<i class="fa"/>` (self-closing solidus on non-void HTML element)
    if msg == "Unacknowledged self-closing tag" {
        return true;
    }

    // 6. Duplicate attributes: enforced strictly per-element on security-sensitive tags in DOM walk,
    //    permitting benign `<div class="a" class="b">` while failing closed on `<script>`/`<meta>`/etc.
    if msg == "Duplicate attribute" {
        return true;
    }

    // 7. Standard HTML5 body/table/head tree-builder recovery (stray `</p>`, `<head><noscript><img>`,
    //    duplicate `<body>`, `<head>` in body, `<td>` in body, `<table><form>`, `<table><input>`).
    //    All resulting elements and merged attributes are still inspected by `check_element_security`.
    //    Foreign-content (`InForeignContent`) errors remain STRICTLY FATAL!
    if matches!(
        msg,
        "No <p> tag to close"
            | "No matching tag to close"
            | "Closing wrong heading tag"
            | "No heading tag to close"
            | "nested heading tags"
            | "nested buttons"
            | "nested forms"
            | "Nested <nobr>"
            | "nested options"
            | "hr in option"
            | "Formatting element not open"
            | "Formatting element not in scope"
            | "Formatting element not current node"
            | "Found special tag while closing generic tag"
            | "expected to close <td> or <th> with cell"
            | "</body> with no <body> in scope"
            | "</html> with no <body> in scope"
            | "Non-space table text"
            | "Null form element pointer on </form>"
            | "Form element not in scope on </form>"
            | "Bad open element on </form>"
    ) {
        return true;
    }

    if msg.starts_with("Unexpected open element while closing ")
        || (msg.starts_with("Unexpected open tag {http://www.w3.org/1999/xhtml}:")
            && msg.ends_with(" at end of body"))
    {
        return true;
    }

    if (msg.starts_with("Unexpected token Tag(Tag { kind: EndTag")
        || msg.starts_with("Unexpected token Tag { kind: EndTag"))
        && !msg.contains("InForeignContent")
    {
        return true;
    }

    if (msg.starts_with("Unexpected token Tag(Tag { kind: StartTag")
        || msg.starts_with("Unexpected token Tag { kind: StartTag"))
        && !msg.contains("InForeignContent")
        && (msg.ends_with(" in insertion mode InHeadNoscript")
            || msg.ends_with(" in insertion mode InBody")
            || msg.ends_with(" in insertion mode InTable")
            || msg.ends_with(" in insertion mode InTableBody")
            || msg.ends_with(" in insertion mode InRow")
            || msg.ends_with(" in insertion mode InCell")
            || msg.ends_with(" in insertion mode InCaption")
            || msg.ends_with(" in insertion mode InSelect")
            || msg.ends_with(" in insertion mode InSelectInTable")
            || msg.ends_with(" in insertion mode AfterBody")
            || msg.ends_with(" in insertion mode AfterAfterBody")
            || msg.ends_with(" in insertion mode InHead")
            || msg.ends_with(" in insertion mode AfterHead"))
    {
        return true;
    }

    if msg.starts_with("Unexpected token Eof in insertion mode InBody")
        || msg.starts_with("Unexpected token Eof in insertion mode AfterBody")
        || msg.starts_with("Unexpected token Eof in insertion mode InHead")
        || msg.starts_with("Unexpected token Eof in insertion mode InTable")
    {
        return true;
    }

    false
}

impl TreeSink for HtmlDomSink {
    type Handle = NodeId;
    type Output = Rc<RefCell<ArenaState>>;
    type ElemName<'a> = OwnedElemName;

    fn finish(self) -> Self::Output {
        self.state
    }

    fn set_current_line(&self, line_number: u64) {
        self.state.borrow_mut().current_line = line_number;
    }

    fn parse_error(&self, msg: Cow<'static, str>) {
        if is_benign_html5_parse_error(&msg) {
            return;
        }
        let mut st = self.state.borrow_mut();
        if st.fatal_parse_error.is_none() {
            let line = st.current_line;
            st.fatal_parse_error = Some((line, msg.into_owned()));
            st.abort_flag.set(true);
        }
    }

    fn get_document(&self) -> Self::Handle {
        0
    }

    fn elem_name<'a>(&'a self, target: &'a Self::Handle) -> Self::ElemName<'a> {
        let st = self.state.borrow();
        let name = st
            .nodes
            .get(*target)
            .and_then(|node| match &node.data {
                NodeData::Element { name, .. } => Some(name.clone()),
                _ => None,
            })
            .unwrap_or_else(|| self.fallback_name.clone());
        OwnedElemName(name)
    }

    fn create_element(
        &self,
        name: QualName,
        attrs: Vec<Attribute>,
        flags: ElementFlags,
    ) -> Self::Handle {
        let mut st = self.state.borrow_mut();
        let aborted = st.abort_flag.get();
        let template_contents = if flags.template {
            Some(st.push_node(NodeData::DocumentFragment))
        } else {
            None
        };
        let converted_attrs = if aborted {
            Vec::new()
        } else if attrs.len() > MAX_ATTRS_PER_ELEMENT {
            st.record_limit(ArenaLimitExceeded::AttrCount);
            Vec::new()
        } else {
            let mut out = Vec::with_capacity(attrs.len());
            for a in attrs {
                let ns_str: &str = &a.name.ns;
                let ns = if ns_str.is_empty() {
                    None
                } else {
                    Some(ns_str.to_owned())
                };
                let local = a.name.local.to_ascii_lowercase().to_string();
                let value = a.value.to_string();
                let entry_bytes = ns
                    .as_ref()
                    .map_or(0, String::len)
                    .saturating_add(local.len())
                    .saturating_add(value.len());
                if !st.account_attr_bytes(entry_bytes) {
                    out.clear();
                    break;
                }
                out.push(ParsedAttr { ns, local, value });
            }
            out
        };
        st.push_node(NodeData::Element {
            name,
            attrs: converted_attrs,
            mathml_integration_point: flags.mathml_annotation_xml_integration_point,
            template_contents,
            had_duplicate_attributes: flags.had_duplicate_attributes,
        })
    }

    fn create_comment(&self, _text: StrTendril) -> Self::Handle {
        self.state.borrow_mut().push_node(NodeData::Comment)
    }

    fn create_pi(&self, target: StrTendril, _data: StrTendril) -> Self::Handle {
        self.state
            .borrow_mut()
            .push_node(NodeData::ProcessingInstruction {
                target: target.to_string(),
            })
    }

    fn append(&self, parent: &Self::Handle, child: NodeOrText<Self::Handle>) {
        self.state.borrow_mut().append_child(*parent, child);
    }

    fn append_based_on_parent_node(
        &self,
        element: &Self::Handle,
        prev_element: &Self::Handle,
        child: NodeOrText<Self::Handle>,
    ) {
        let has_parent = self
            .state
            .borrow()
            .nodes
            .get(*element)
            .is_some_and(|n| n.parent.is_some());
        if has_parent {
            self.append_before_sibling(element, child);
        } else {
            self.append(prev_element, child);
        }
    }

    fn append_doctype_to_document(
        &self,
        _name: StrTendril,
        _public_id: StrTendril,
        _system_id: StrTendril,
    ) {
        let mut st = self.state.borrow_mut();
        let id = st.push_node(NodeData::Doctype);
        st.append_child(0, NodeOrText::AppendNode(id));
    }

    fn get_template_contents(&self, target: &Self::Handle) -> Self::Handle {
        let st = self.state.borrow();
        st.nodes
            .get(*target)
            .and_then(|node| match &node.data {
                NodeData::Element {
                    template_contents, ..
                } => *template_contents,
                _ => None,
            })
            .unwrap_or(0)
    }

    fn same_node(&self, x: &Self::Handle, y: &Self::Handle) -> bool {
        x == y
    }

    fn set_quirks_mode(&self, _mode: QuirksMode) {}

    fn append_before_sibling(&self, sibling: &Self::Handle, new_node: NodeOrText<Self::Handle>) {
        self.state
            .borrow_mut()
            .insert_before_sibling(*sibling, new_node);
    }

    fn add_attrs_if_missing(&self, target: &Self::Handle, attrs: Vec<Attribute>) {
        let mut st = self.state.borrow_mut();
        if st.abort_flag.get() {
            return;
        }
        let mut added_bytes = 0_usize;
        let mut count_exceeded = false;
        let mut bytes_exceeded = false;
        let current_total = st.total_attr_bytes;
        if let Some(NodeData::Element {
            attrs: existing, ..
        }) = st.nodes.get_mut(*target).map(|n| &mut n.data)
        {
            for attr in attrs {
                let ns_str: &str = &attr.name.ns;
                let ns_opt = if ns_str.is_empty() {
                    None
                } else {
                    Some(ns_str.to_owned())
                };
                let local = attr.name.local.to_ascii_lowercase().to_string();
                if !existing.iter().any(|a| a.ns == ns_opt && a.local == local) {
                    if existing.len() >= MAX_ATTRS_PER_ELEMENT {
                        count_exceeded = true;
                        break;
                    }
                    let value = attr.value.to_string();
                    let entry_bytes = ns_opt
                        .as_ref()
                        .map_or(0, String::len)
                        .saturating_add(local.len())
                        .saturating_add(value.len());
                    added_bytes = added_bytes.saturating_add(entry_bytes);
                    if current_total.saturating_add(added_bytes) > MAX_TOTAL_ATTR_BYTES {
                        bytes_exceeded = true;
                        break;
                    }
                    existing.push(ParsedAttr {
                        ns: ns_opt,
                        local,
                        value,
                    });
                }
            }
        }
        st.total_attr_bytes = st.total_attr_bytes.saturating_add(added_bytes);
        if count_exceeded {
            st.record_limit(ArenaLimitExceeded::AttrCount);
        }
        if bytes_exceeded {
            st.record_limit(ArenaLimitExceeded::AttrBytes);
        }
    }

    fn remove_from_parent(&self, target: &Self::Handle) {
        self.state.borrow_mut().detach(*target);
    }

    fn reparent_children(&self, node: &Self::Handle, new_parent: &Self::Handle) {
        if node == new_parent {
            return;
        }
        let mut st = self.state.borrow_mut();
        if st.abort_flag.get() {
            return;
        }
        let Some(child_depth) = st.check_child_depth(*new_parent) else {
            return;
        };
        let mut cur = st.nodes.get_mut(*node).and_then(|n| {
            n.last_child = None;
            n.first_child.take()
        });
        while let Some(child_id) = cur {
            let next = st.nodes.get_mut(child_id).and_then(|c| {
                c.prev_sibling = None;
                c.next_sibling.take()
            });
            st.link_as_last_child(*new_parent, child_id, child_depth);
            cur = next;
        }
    }

    fn is_mathml_annotation_xml_integration_point(&self, handle: &Self::Handle) -> bool {
        let st = self.state.borrow();
        st.nodes.get(*handle).is_some_and(|node| match &node.data {
            NodeData::Element {
                mathml_integration_point,
                ..
            } => *mathml_integration_point,
            _ => false,
        })
    }
}

/// `TokenSink` wrapper enforcing per-tag attribute count and wall-clock CPU budget directly on
/// `html5ever`'s token stream (`R7-SCAN-3`) before tokens ever reach `TreeBuilder`.
struct BoundedTokenSink {
    inner: TreeBuilder<NodeId, HtmlDomSink>,
    state: Rc<RefCell<ArenaState>>,
    deadline: Duration,
}

impl TokenSink for BoundedTokenSink {
    type Handle = NodeId;

    fn process_token(&self, token: Token, line_number: u64) -> TokenSinkResult<Self::Handle> {
        {
            let mut st = self.state.borrow_mut();
            if st.abort_flag.get() {
                return TokenSinkResult::Continue;
            }
            if scan_clock_now() > self.deadline {
                st.current_line = line_number;
                st.record_limit(ArenaLimitExceeded::ScanTimeout);
                return TokenSinkResult::Continue;
            }
            if let Token::TagToken(ref tag) = token
                && tag.attrs.len() > MAX_ATTRS_PER_ELEMENT
            {
                st.current_line = line_number;
                st.record_limit(ArenaLimitExceeded::AttrCount);
                return TokenSinkResult::Continue;
            }
        }
        self.inner.process_token(token, line_number)
    }

    fn end(&self) {
        if !self.state.borrow().abort_flag.get() {
            self.inner.end();
        }
    }

    fn adjusted_current_node_present_but_not_in_html_namespace(&self) -> bool {
        self.inner
            .adjusted_current_node_present_but_not_in_html_namespace()
    }
}

/// Parses HTML5 in bounded 4 KiB chunks (`R5-PUB-8`, `R7-SCAN-3`) and aborts immediately on the
/// first fatal parse error, DOM depth/node/attribute cap, or wall-clock CPU deadline so adversarial
/// inputs terminate in milliseconds instead of quadratic minutes.
fn parse_html_dom(markup: &str, scripting_enabled: bool, deadline: Duration) -> ArenaState {
    let abort_flag = Rc::new(Cell::new(false));
    let shared_state = Rc::new(RefCell::new(ArenaState::new(Rc::clone(&abort_flag))));
    let opts = ParseOpts {
        tokenizer: TokenizerOpts {
            // `exact_errors: false` in `html5ever`'s tokenizer emits detailed
            // `"Saw <ch> in state <State>"` / `"Saw EOF in state <State>"` diagnostics AND
            // enables the fast `pop_except_from` scanning path (`R5-PUB-8`, `R5-PUB-9`).
            exact_errors: false,
            ..TokenizerOpts::default()
        },
        tree_builder: TreeBuilderOpts {
            exact_errors: true,
            scripting_enabled,
            ..TreeBuilderOpts::default()
        },
    };
    let tb = TreeBuilder::new(
        HtmlDomSink::new(Rc::clone(&shared_state)),
        opts.tree_builder,
    );
    let bounded_sink = BoundedTokenSink {
        inner: tb,
        state: Rc::clone(&shared_state),
        deadline,
    };
    let tokenizer = Tokenizer::new(bounded_sink, opts.tokenizer);
    let input_buffer = BufferQueue::default();
    let mut rest = markup;
    while !rest.is_empty() {
        if scan_clock_now() > deadline {
            shared_state
                .borrow_mut()
                .record_limit(ArenaLimitExceeded::ScanTimeout);
        }
        if abort_flag.get() {
            drop(tokenizer);
            let fallback_flag = Rc::new(Cell::new(true));
            return std::mem::replace(
                &mut *shared_state.borrow_mut(),
                ArenaState::new(fallback_flag),
            );
        }
        let mut split_at = rest.len().min(HTML_FEED_CHUNK_BYTES);
        while split_at < rest.len() && !rest.is_char_boundary(split_at) {
            split_at += 1;
        }
        let (chunk, tail) = rest.split_at(split_at);
        input_buffer.push_back(StrTendril::from(chunk));
        loop {
            let res = tokenizer.feed(&input_buffer);
            if scan_clock_now() > deadline {
                shared_state
                    .borrow_mut()
                    .record_limit(ArenaLimitExceeded::ScanTimeout);
            }
            if abort_flag.get() || matches!(res, TokenizerResult::Done) {
                break;
            }
        }
        if abort_flag.get() {
            // Drop tokenizer directly without flushing EOF so aborted deeply-nested or timed-out
            // parses return instantaneously with zero `html5ever` unwind cost!
            drop(tokenizer);
            let fallback_flag = Rc::new(Cell::new(true));
            return std::mem::replace(
                &mut *shared_state.borrow_mut(),
                ArenaState::new(fallback_flag),
            );
        }
        rest = tail;
    }
    tokenizer.end();
    let finished = tokenizer.sink.inner.sink.finish();
    let fallback_flag = Rc::new(Cell::new(false));
    std::mem::replace(&mut *finished.borrow_mut(), ArenaState::new(fallback_flag))
}

/// Returns `true` when `tag_name` switches the HTML5 tokenizer into RCDATA or RAWTEXT mode
/// (outside `<svg>`/`<math>` foreign content) where `<!--` does NOT start an HTML comment
/// (`R7-SCAN-3`).
fn is_html_rawtext_or_rcdata_tag(tag_name: &str) -> bool {
    tag_name.eq_ignore_ascii_case("script")
        || tag_name.eq_ignore_ascii_case("style")
        || tag_name.eq_ignore_ascii_case("title")
        || tag_name.eq_ignore_ascii_case("textarea")
        || tag_name.eq_ignore_ascii_case("xmp")
        || tag_name.eq_ignore_ascii_case("iframe")
        || tag_name.eq_ignore_ascii_case("noembed")
        || tag_name.eq_ignore_ascii_case("noframes")
}

/// Zero-allocation O(N) pre-scanner run BEFORE `html5ever`/`roxmltree` (`R6-PUB-6`, `R7-SCAN-3`)
/// to reject:
/// - Any single start tag carrying more than [`MAX_ATTRS_PER_ELEMENT`] attributes (defeating
///   quadratic duplicate-attribute checks in `html5ever::tokenizer` / `roxmltree`), while tracking
///   HTML5 RCDATA/RAWTEXT elements and `<svg>`/`<math>` foreign-content depth so `<title><!--`,
///   `<textarea><!--`, and `<svg><script><g ...>` cannot desynchronize the prescanner.
/// - XML/SVG element nesting deeper than [`MAX_DOM_DEPTH`] (before `roxmltree` parses).
#[allow(clippy::too_many_lines)]
fn prescan_markup_tag_bounds(markup: &str, is_xml: bool) -> Result<(), (usize, &'static str)> {
    let bytes = markup.as_bytes();
    let len = bytes.len();
    let mut i = 0_usize;
    let mut line = 1_usize;
    let mut xml_depth = 0_u16;
    let mut foreign_depth = 0_u16;

    while i < len {
        let b = bytes.get(i).copied().unwrap_or(0);
        if b == b'\n' {
            line += 1;
            i += 1;
            continue;
        }
        if b != b'<' {
            i += 1;
            continue;
        }

        let rest = markup.get(i..).unwrap_or("");
        // Comments `<!-- ... -->` (or `--!>` in HTML)
        if rest.starts_with("<!--") {
            i += 4;
            while i < len {
                if bytes.get(i) == Some(&b'\n') {
                    line += 1;
                }
                let tail = markup.get(i..).unwrap_or("");
                if tail.starts_with("-->") {
                    i += 3;
                    break;
                }
                if !is_xml && tail.starts_with("--!>") {
                    i += 4;
                    break;
                }
                i += 1;
            }
            continue;
        }
        // XML CDATA `<![CDATA[ ... ]]>`
        if rest.starts_with("<![CDATA[") {
            i += 9;
            while i < len {
                if bytes.get(i) == Some(&b'\n') {
                    line += 1;
                }
                if markup.get(i..).is_some_and(|t| t.starts_with("]]>")) {
                    i += 3;
                    break;
                }
                i += 1;
            }
            continue;
        }
        // Processing instructions `<? ... ?>`
        if rest.starts_with("<?") {
            i += 2;
            while i < len {
                if bytes.get(i) == Some(&b'\n') {
                    line += 1;
                }
                if markup.get(i..).is_some_and(|t| t.starts_with("?>")) {
                    i += 2;
                    break;
                }
                i += 1;
            }
            continue;
        }
        // Declarations `<!DOCTYPE ...>` etc.
        if rest.starts_with("<!") {
            i += 2;
            let mut quote: Option<u8> = None;
            while i < len {
                let c = bytes.get(i).copied().unwrap_or(0);
                if c == b'\n' {
                    line += 1;
                }
                i += 1;
                if let Some(q) = quote {
                    if c == q {
                        quote = None;
                    }
                } else if c == b'"' || c == b'\'' {
                    quote = Some(c);
                } else if c == b'>' {
                    break;
                }
            }
            continue;
        }
        // End tag `</...>`
        if bytes.get(i + 1) == Some(&b'/') {
            if is_xml {
                xml_depth = xml_depth.saturating_sub(1);
            }
            i += 2;
            let end_name_start = i;
            while let Some(&c) = bytes.get(i) {
                if c.is_ascii_whitespace() || c == b'/' || c == b'>' {
                    break;
                }
                i += 1;
            }
            let end_name = markup.get(end_name_start..i).unwrap_or("");
            if !is_xml
                && (end_name.eq_ignore_ascii_case("svg") || end_name.eq_ignore_ascii_case("math"))
            {
                foreign_depth = foreign_depth.saturating_sub(1);
            }
            while i < len {
                let c = bytes.get(i).copied().unwrap_or(0);
                if c == b'\n' {
                    line += 1;
                }
                i += 1;
                if c == b'>' {
                    break;
                }
            }
            continue;
        }
        // Start tag `<name ...>` (ignore prose like `a < b` where next byte isn't ASCII letter)
        if !bytes.get(i + 1).is_some_and(u8::is_ascii_alphabetic) {
            i += 1;
            continue;
        }
        let tag_line = line;
        i += 1;
        let name_start = i;
        while let Some(&c) = bytes.get(i) {
            if c.is_ascii_whitespace() || c == b'/' || c == b'>' {
                break;
            }
            i += 1;
        }
        let tag_name = markup.get(name_start..i).unwrap_or("");

        let mut attr_count = 0_usize;
        let mut expect_new_attr = false;
        let mut quote: Option<u8> = None;
        let mut last_non_ws = b' ';
        while i < len {
            let c = bytes.get(i).copied().unwrap_or(0);
            if c == b'\n' {
                line += 1;
            }
            i += 1;
            if let Some(q) = quote {
                if c == q {
                    quote = None;
                    expect_new_attr = true;
                    last_non_ws = c;
                }
                continue;
            }
            match c {
                b'>' => break,
                b'"' | b'\'' => {
                    quote = Some(c);
                    expect_new_attr = false;
                    last_non_ws = c;
                }
                b' ' | b'\t' | b'\r' | b'\n' | 0x0C => {
                    expect_new_attr = true;
                }
                b'/' => {
                    last_non_ws = b'/';
                    expect_new_attr = false;
                }
                b'=' => {
                    expect_new_attr = false;
                    last_non_ws = b'=';
                }
                _ => {
                    if expect_new_attr {
                        attr_count += 1;
                        if attr_count > MAX_ATTRS_PER_ELEMENT {
                            return Err((
                                tag_line,
                                "markup element exceeds maximum attribute count of 1024 per tag",
                            ));
                        }
                    }
                    expect_new_attr = false;
                    last_non_ws = c;
                }
            }
        }

        if is_xml && last_non_ws != b'/' {
            xml_depth = xml_depth.saturating_add(1);
            if xml_depth > MAX_DOM_DEPTH {
                return Err((
                    tag_line,
                    "XML/SVG document exceeds maximum element nesting depth of 512",
                ));
            }
        }

        if !is_xml {
            if last_non_ws != b'/'
                && (tag_name.eq_ignore_ascii_case("svg") || tag_name.eq_ignore_ascii_case("math"))
            {
                foreign_depth = foreign_depth.saturating_add(1);
                continue;
            }
            // Only enter HTML5 RCDATA/RAWTEXT/PLAINTEXT modes outside `<svg>`/`<math>` foreign
            // content (`R7-SCAN-3`)! Inside `<svg>`, `<script>` is a normal foreign element and
            // its children MUST be scanned. Inside HTML `<title>`/`<textarea>`/`<style>`/etc.,
            // `<!--` is literal text, NOT a comment, so scanning directly to `</tag_name` prevents
            // `<title><!--</title><g a0 ...>-->` from desynchronizing prescan!
            if foreign_depth == 0 {
                if tag_name.eq_ignore_ascii_case("plaintext") {
                    break;
                }
                if is_html_rawtext_or_rcdata_tag(tag_name) {
                    let closer = format!("</{}", tag_name.to_ascii_lowercase());
                    let closer_len = closer.len();
                    while i < len {
                        if bytes.get(i) == Some(&b'\n') {
                            line += 1;
                        }
                        if bytes.get(i) == Some(&b'<')
                            && markup
                                .get(i..i + closer_len)
                                .is_some_and(|s| s.eq_ignore_ascii_case(&closer))
                            && bytes.get(i + closer_len).is_some_and(|&after| {
                                after == b'>' || after == b'/' || after.is_ascii_whitespace()
                            })
                        {
                            break;
                        }
                        i += 1;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Computes 1-based `(line, col)` lazily ONLY when an XML violation is emitted (`R6-PUB-6`),
/// replacing the per-node `roxmltree::Document::text_pos_at` O(N^2) rescan.
fn line_col_at(text: &str, byte_offset: usize) -> (usize, usize) {
    let clamped = byte_offset.min(text.len());
    let prefix = text.get(..clamped).unwrap_or("");
    let mut row = 1_usize;
    let mut last_nl = 0_usize;
    for (idx, b) in prefix.bytes().enumerate() {
        if b == b'\n' {
            row += 1;
            last_nl = idx + 1;
        }
    }
    let col = prefix.get(last_nl..).map_or(1, |s| s.chars().count() + 1);
    (row, col)
}

fn inspect_html_document(
    path: &str,
    markup: &str,
    check_no_inline: bool,
    check_csp_valid: bool,
    deadline: Duration,
    violations: &mut Vec<PreflightViolation>,
) {
    if let Err((line, reason)) = prescan_markup_tag_bounds(markup, false) {
        push_markup_parse_error(
            violations,
            path,
            &format!("line {line}: {reason}"),
            check_no_inline,
            check_csp_valid,
        );
        return;
    }

    let dom_scripted = parse_html_dom(markup, true, deadline);
    let (mut no_inline_err, mut csp_err, saw_noscript) =
        inspect_html_arena(&dom_scripted, check_no_inline, check_csp_valid);

    // Also parse `<noscript>` contents with `scripting_enabled: false` so JS-disabled browsers
    // cannot render/execute hidden elements inside `<noscript>`.
    if saw_noscript && (no_inline_err.is_none() || csp_err.is_none()) {
        let dom_noscript = parse_html_dom(markup, false, deadline);
        let (ns_inline, ns_csp, _) = inspect_html_arena(
            &dom_noscript,
            check_no_inline && no_inline_err.is_none(),
            check_csp_valid && csp_err.is_none(),
        );
        if no_inline_err.is_none() {
            no_inline_err = ns_inline;
        }
        if csp_err.is_none() {
            csp_err = ns_csp;
        }
    }

    if let Some(detail) = no_inline_err {
        violations.push(PreflightViolation {
            rule: "NO_INLINE_SCRIPTS",
            path: path.to_owned(),
            detail,
        });
    }
    if let Some(detail) = csp_err {
        violations.push(PreflightViolation {
            rule: "CSP_VALID",
            path: path.to_owned(),
            detail,
        });
    }
}

fn is_security_sensitive_element(local: &str) -> bool {
    matches!(
        local,
        "script"
            | "meta"
            | "link"
            | "iframe"
            | "object"
            | "embed"
            | "frame"
            | "frameset"
            | "base"
            | "use"
            | "animate"
            | "set"
            | "animatemotion"
            | "animatetransform"
            | "animatecolor"
            | "handler"
            | "listener"
    )
}

#[allow(clippy::too_many_lines)]
fn inspect_html_arena(
    arena: &ArenaState,
    check_no_inline: bool,
    check_csp_valid: bool,
) -> (Option<String>, Option<String>, bool) {
    if let Some(limit) = arena.limit_exceeded {
        let msg = match limit {
            ArenaLimitExceeded::Depth => format!(
                "HTML document exceeds maximum DOM nesting depth of {MAX_DOM_DEPTH} (line {})",
                arena.current_line
            ),
            ArenaLimitExceeded::Nodes => format!(
                "HTML document exceeds maximum DOM node limit of {MAX_DOM_NODES} (line {})",
                arena.current_line
            ),
            ArenaLimitExceeded::AttrCount => format!(
                "HTML element exceeds maximum attribute count of {MAX_ATTRS_PER_ELEMENT} (line {})",
                arena.current_line
            ),
            ArenaLimitExceeded::AttrBytes => format!(
                "HTML document exceeds maximum expanded attribute memory budget of {MAX_TOTAL_ATTR_BYTES} bytes (line {})",
                arena.current_line
            ),
            ArenaLimitExceeded::ScanTimeout => format!(
                "HTML document scan exceeded CPU time budget (line {})",
                arena.current_line
            ),
        };
        return (
            check_no_inline.then(|| msg.clone()),
            check_csp_valid.then_some(msg),
            false,
        );
    }

    let mut no_inline_err: Option<String> = None;
    let mut csp_err: Option<String> = None;
    let mut saw_noscript = false;
    let mut sensitive_dup_attr_line: Option<u64> = None;

    for node in &arena.nodes {
        match &node.data {
            NodeData::ProcessingInstruction { target }
                if check_no_inline
                    && no_inline_err.is_none()
                    && target.eq_ignore_ascii_case("xml-stylesheet") =>
            {
                no_inline_err = Some(format!(
                    "line {}: markup contains forbidden xml-stylesheet processing instruction",
                    node.line
                ));
            }
            NodeData::Element {
                name,
                attrs,
                had_duplicate_attributes,
                ..
            } => {
                let ns_str: &str = &name.ns;
                let is_html_ns = ns_str == HTML_NS;
                let is_svg_ns = ns_str == SVG_NS;
                let local_str: &str = &name.local;
                let local = local_str.to_ascii_lowercase();
                if is_html_ns && local == "noscript" {
                    saw_noscript = true;
                }
                if *had_duplicate_attributes
                    && is_security_sensitive_element(&local)
                    && sensitive_dup_attr_line.is_none()
                {
                    sensitive_dup_attr_line = Some(node.line);
                }

                if check_no_inline && no_inline_err.is_none() {
                    let (script_text, has_non_text_children) = if local == "script" {
                        collect_html_children_text(&arena.nodes, node.first_child)
                    } else {
                        (String::new(), false)
                    };
                    if let Some(reason) = check_element_security(
                        is_html_ns,
                        is_svg_ns,
                        &local,
                        attrs,
                        &script_text,
                        has_non_text_children,
                    ) {
                        no_inline_err = Some(format!("line {}: {reason}", node.line));
                    }
                }

                if check_csp_valid
                    && csp_err.is_none()
                    && is_html_ns
                    && local == "meta"
                    && let Some(reason) = check_csp_meta_attrs(attrs)
                {
                    csp_err = Some(format!("line {}: {reason}", node.line));
                }
            }
            _ => {}
        }
    }

    // Fail closed on any non-benign HTML5 tokenizer/tree parse error or duplicate attribute on a
    // security-sensitive element, reporting exact line number (`R4-PUB-1`, `R5-PUB-9`).
    let structural_err = arena
        .fatal_parse_error
        .as_ref()
        .map(|(line, e)| {
            format!("line {line}: malformed HTML5 markup rejected by strict parser ({e})")
        })
        .or_else(|| {
            sensitive_dup_attr_line.map(|line| {
                format!(
                    "line {line}: security-sensitive HTML5 element contains duplicate attributes"
                )
            })
        });
    if let Some(err_msg) = structural_err {
        if check_no_inline && no_inline_err.is_none() {
            no_inline_err = Some(err_msg.clone());
        }
        if check_csp_valid && csp_err.is_none() {
            csp_err = Some(err_msg);
        }
    }

    (no_inline_err, csp_err, saw_noscript)
}

fn collect_html_children_text(nodes: &[DomNode], first_child: Option<NodeId>) -> (String, bool) {
    let mut text = String::new();
    let mut has_non_text = false;
    let mut cur = first_child;
    while let Some(cid) = cur {
        let Some(node) = nodes.get(cid) else {
            break;
        };
        match &node.data {
            NodeData::Text(t) => text.push_str(t),
            _ => has_non_text = true,
        }
        cur = node.next_sibling;
    }
    (text, has_non_text)
}

/// Validates and strips a plain external-only XML/SVG DOCTYPE declaration (`<!DOCTYPE name
/// [PUBLIC "..." "..." | SYSTEM "..."]>`) that contains ZERO `[...]` internal DTD subset
/// (`R5-PUB-9`), while returning a clear actionable error for any DOCTYPE carrying an internal
/// `[...]` subset or `<!ENTITY` declaration (`R4-PUB-1`).
#[allow(clippy::too_many_lines)]
fn strip_safe_subsetless_xml_doctype(markup: &str) -> Result<Cow<'_, str>, String> {
    let bytes = markup.as_bytes();
    let mut i = 0_usize;
    // Skip optional UTF-8 BOM
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        i = 3;
    }
    // Walk XML prolog (whitespace, `<?...?>` XML decl/PIs, `<!--...-->` comments) until either
    // `<!DOCTYPE` or the root element `<...`.
    loop {
        while matches!(bytes.get(i), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            i += 1;
        }
        let rest = markup.get(i..).unwrap_or("");
        if rest.starts_with("<?") {
            let Some(end_rel) = rest.find("?>") else {
                return Ok(Cow::Borrowed(markup));
            };
            i += end_rel + 2;
        } else if rest.starts_with("<!--") {
            let Some(end_rel) = rest.find("-->") else {
                return Ok(Cow::Borrowed(markup));
            };
            i += end_rel + 3;
        } else if rest.starts_with("<!DOCTYPE")
            && rest
                .as_bytes()
                .get(9)
                .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        {
            let doctype_start = i;
            let mut p = i + 9;
            // 1. Whitespace + DOCTYPE root name
            while matches!(bytes.get(p), Some(b' ' | b'\t' | b'\r' | b'\n')) {
                p += 1;
            }
            let name_start = p;
            while let Some(&b) = bytes.get(p) {
                if b.is_ascii_alphanumeric() || matches!(b, b':' | b'_' | b'-' | b'.') {
                    p += 1;
                } else {
                    break;
                }
            }
            if p == name_start {
                return Err(
                    "XML/SVG DOCTYPE has invalid root name; remove the <!DOCTYPE ...> declaration or use a plain PUBLIC/SYSTEM DOCTYPE without an internal '[...]' subset".to_owned(),
                );
            }
            // Helper to parse a single quoted string literal (`"..."` or `'...'`).
            let skip_ws = |idx: &mut usize| {
                while matches!(bytes.get(*idx), Some(b' ' | b'\t' | b'\r' | b'\n')) {
                    *idx += 1;
                }
            };
            let parse_quoted = |idx: &mut usize| -> bool {
                let Some(&q) = bytes.get(*idx) else {
                    return false;
                };
                if q != b'"' && q != b'\'' {
                    return false;
                }
                *idx += 1;
                while let Some(&b) = bytes.get(*idx) {
                    *idx += 1;
                    if b == q {
                        return true;
                    }
                }
                false
            };

            skip_ws(&mut p);
            let after_name = markup.get(p..).unwrap_or("");
            if after_name.starts_with("PUBLIC")
                && after_name
                    .as_bytes()
                    .get(6)
                    .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
            {
                p += 6;
                skip_ws(&mut p);
                if !parse_quoted(&mut p) {
                    return Err(
                        "XML/SVG DOCTYPE PUBLIC identifier is malformed; remove any internal '[...]' DTD subset or remove the <!DOCTYPE ...> header".to_owned(),
                    );
                }
                skip_ws(&mut p);
                if !parse_quoted(&mut p) {
                    return Err(
                        "XML/SVG DOCTYPE SYSTEM literal after PUBLIC is malformed; remove any internal '[...]' DTD subset or remove the <!DOCTYPE ...> header".to_owned(),
                    );
                }
                skip_ws(&mut p);
            } else if after_name.starts_with("SYSTEM")
                && after_name
                    .as_bytes()
                    .get(6)
                    .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
            {
                p += 6;
                skip_ws(&mut p);
                if !parse_quoted(&mut p) {
                    return Err(
                        "XML/SVG DOCTYPE SYSTEM literal is malformed; remove any internal '[...]' DTD subset or remove the <!DOCTYPE ...> header".to_owned(),
                    );
                }
                skip_ws(&mut p);
            }

            // ONLY accept immediate `>` closing the DOCTYPE (rejects `[` internal subset & trailing junk!)
            if bytes.get(p) != Some(&b'>') {
                return Err(
                    "XML/SVG DOCTYPE contains a forbidden internal DTD subset '[...]' or extra tokens; remove the '[...]' subset (and any <!ENTITY> declarations) from <!DOCTYPE ...>".to_owned(),
                );
            }
            let doctype_end = p + 1;
            // Replace the verified subset-less DOCTYPE with equal newlines so roxmltree line
            // numbers remain 100% accurate!
            let mut stripped = String::with_capacity(markup.len());
            stripped.push_str(markup.get(..doctype_start).unwrap_or(""));
            let newlines = markup
                .get(doctype_start..doctype_end)
                .unwrap_or("")
                .bytes()
                .filter(|&b| b == b'\n')
                .count();
            for _ in 0..newlines {
                stripped.push('\n');
            }
            stripped.push_str(markup.get(doctype_end..).unwrap_or(""));
            return Ok(Cow::Owned(stripped));
        } else {
            return Ok(Cow::Borrowed(markup));
        }
    }
}

#[allow(clippy::too_many_lines)]
fn inspect_xml_document(
    path: &str,
    markup: &str,
    check_no_inline: bool,
    check_csp_valid: bool,
    deadline: Duration,
    violations: &mut Vec<PreflightViolation>,
) {
    // R5-PUB-9 & R4-PUB-1: Accept plain external-only DOCTYPE headers (e.g. W3C/Illustrator SVG
    // `<!DOCTYPE svg PUBLIC ...>`) with NO `[...]` internal subset by stripping them strictly
    // before passing to `roxmltree` with `allow_dtd: false`, while rejecting any `[...]` subset
    // or ENTITY declaration with an actionable error message!
    let sanitized_xml = match strip_safe_subsetless_xml_doctype(markup) {
        Ok(s) => s,
        Err(msg) => {
            push_markup_parse_error(violations, path, &msg, check_no_inline, check_csp_valid);
            return;
        }
    };

    // R6-PUB-6: Bounded O(N) pre-scan rejects >1024 attrs/tag and >512 nesting depth BEFORE
    // `roxmltree` parses!
    if let Err((line, reason)) = prescan_markup_tag_bounds(&sanitized_xml, true) {
        push_markup_parse_error(
            violations,
            path,
            &format!("line {line}: {reason}"),
            check_no_inline,
            check_csp_valid,
        );
        return;
    }

    let opts = roxmltree::ParsingOptions {
        allow_dtd: false,
        nodes_limit: u32::try_from(MAX_DOM_NODES).unwrap_or(200_000),
        ..roxmltree::ParsingOptions::default()
    };
    let doc = match roxmltree::Document::parse_with_options(&sanitized_xml, opts) {
        Ok(doc) => doc,
        Err(err) => {
            push_markup_parse_error(
                violations,
                path,
                &format!(
                    "malformed or DTD-bearing XML/SVG document rejected ({err}); ensure well-formed XML without internal '[...]' DTD subsets"
                ),
                check_no_inline,
                check_csp_valid,
            );
            return;
        }
    };

    let mut no_inline_err: Option<String> = None;
    let mut csp_err: Option<String> = None;

    // R6-PUB-6: Explicit iterative stack walk enforcing MAX_DOM_DEPTH + lazy line/col computation
    // ONLY on error (eliminating `roxmltree::Document::text_pos_at`'s O(N^2) per-node rescan!).
    let mut stack: Vec<(roxmltree::Node<'_, '_>, u16)> = vec![(doc.root(), 0)];
    let mut attrs_buf: Vec<ParsedAttr> = Vec::new();
    let mut visited_nodes = 0_usize;
    while let Some((node, depth)) = stack.pop() {
        visited_nodes += 1;
        if visited_nodes.is_multiple_of(512) && scan_clock_now() > deadline {
            push_markup_parse_error(
                violations,
                path,
                "XML/SVG document scan exceeded CPU time budget",
                check_no_inline,
                check_csp_valid,
            );
            return;
        }
        if depth > MAX_DOM_DEPTH {
            let (row, col) = line_col_at(&sanitized_xml, node.range().start);
            push_markup_parse_error(
                violations,
                path,
                &format!(
                    "line {row} col {col}: XML/SVG document exceeds maximum element nesting depth of {MAX_DOM_DEPTH}"
                ),
                check_no_inline,
                check_csp_valid,
            );
            return;
        }

        // Push children in reverse order so document order is preserved during traversal.
        let child_depth = if node.is_element() {
            depth.saturating_add(1)
        } else {
            depth
        };
        let children_start = stack.len();
        for child in node.children() {
            if child.is_element() || child.is_pi() {
                stack.push((child, child_depth));
            }
        }
        if let Some(slice) = stack.get_mut(children_start..) {
            slice.reverse();
        }

        if node.is_pi() {
            if let Some(pi) = node.pi()
                && pi.target.eq_ignore_ascii_case("xml-stylesheet")
                && check_no_inline
                && no_inline_err.is_none()
            {
                let (row, col) = line_col_at(&sanitized_xml, node.range().start);
                no_inline_err = Some(format!(
                    "line {row} col {col}: markup contains forbidden xml-stylesheet processing instruction"
                ));
            }
            continue;
        }
        if !node.is_element() {
            continue;
        }

        if node.attributes().len() > MAX_ATTRS_PER_ELEMENT {
            let (row, col) = line_col_at(&sanitized_xml, node.range().start);
            push_markup_parse_error(
                violations,
                path,
                &format!(
                    "line {row} col {col}: XML/SVG element exceeds maximum attribute count of {MAX_ATTRS_PER_ELEMENT}"
                ),
                check_no_inline,
                check_csp_valid,
            );
            return;
        }

        let is_html_ns = node.tag_name().namespace() == Some(HTML_NS);
        let is_svg_ns = node.tag_name().namespace() == Some(SVG_NS);
        let local = node.tag_name().name().to_ascii_lowercase();
        // R5-PUB-14: Preserve exact XML attribute namespaces so namespaced `x:type` is NOT
        // mistaken for un-namespaced XHTML `<script type="...">`!
        attrs_buf.clear();
        for a in node.attributes() {
            attrs_buf.push(ParsedAttr {
                ns: a.namespace().map(str::to_owned),
                local: a.name().to_ascii_lowercase(),
                value: a.value().to_owned(),
            });
        }

        if check_no_inline && no_inline_err.is_none() {
            let (script_text, has_non_text_children) = if local == "script" {
                collect_xml_children_text(node)
            } else {
                (String::new(), false)
            };
            if let Some(reason) = check_element_security(
                is_html_ns,
                is_svg_ns,
                &local,
                &attrs_buf,
                &script_text,
                has_non_text_children,
            ) {
                let (row, col) = line_col_at(&sanitized_xml, node.range().start);
                no_inline_err = Some(format!("line {row} col {col}: {reason}"));
            }
        }

        if check_csp_valid
            && csp_err.is_none()
            && local == "meta"
            && let Some(reason) = check_csp_meta_attrs(&attrs_buf)
        {
            let (row, col) = line_col_at(&sanitized_xml, node.range().start);
            csp_err = Some(format!("line {row} col {col}: {reason}"));
        }

        if (!check_no_inline || no_inline_err.is_some()) && (!check_csp_valid || csp_err.is_some())
        {
            break;
        }
    }

    if let Some(reason) = no_inline_err {
        violations.push(PreflightViolation {
            rule: "NO_INLINE_SCRIPTS",
            path: path.to_owned(),
            detail: reason,
        });
    }
    if let Some(reason) = csp_err {
        violations.push(PreflightViolation {
            rule: "CSP_VALID",
            path: path.to_owned(),
            detail: reason,
        });
    }
}

fn collect_xml_children_text(node: roxmltree::Node<'_, '_>) -> (String, bool) {
    let mut text = String::new();
    let mut has_non_text = false;
    for child in node.children() {
        if child.is_text() {
            if let Some(t) = child.text() {
                text.push_str(t);
            }
        } else {
            has_non_text = true;
        }
    }
    (text, has_non_text)
}

/// Normalizes a decoded attribute value into an ASCII-lowercase, whitespace/control-stripped
/// string for URL scheme checking (entities are already decoded by `html5ever`/`roxmltree`).
fn normalize_url_value(decoded: &str) -> String {
    decoded
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && !c.is_control())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn is_forbidden_active_uri_scheme(norm: &str) -> bool {
    norm.starts_with("javascript:")
        || norm.starts_with("vbscript:")
        || norm.starts_with("data:text/html")
        || norm.starts_with("data:text/javascript")
        || norm.starts_with("data:application/javascript")
        || norm.starts_with("data:text/ecmascript")
        || norm.starts_with("data:application/ecmascript")
        || norm.starts_with("data:application/xhtml+xml")
        || norm.starts_with("data:text/xml")
        || norm.starts_with("data:application/xml")
}

/// Returns `true` when `s` starts with an RFC 3986 / WHATWG URL scheme (`^[A-Za-z][A-Za-z0-9+.-]*:`).
///
/// Rejecting scheme-prefixed strings unconditionally closes the WHATWG same-scheme-vs-cross-scheme
/// divergence (`R7-SCAN-1`): `https:evil.example/x.js` is parsed as relative on an `https://` page
/// but as cross-origin `https://evil.example/x.js` on an `http://` page (and vice versa for `http:`).
fn has_url_scheme_prefix(s: &str) -> bool {
    let mut bytes = s.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() {
        return false;
    }
    for b in bytes {
        if b == b':' {
            return true;
        }
        if !(b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.')) {
            return false;
        }
    }
    false
}

/// Returns `true` ONLY when `raw` has NO URL scheme prefix AND resolves strictly to the SAME
/// origin against BOTH `https://` and `http://` probe bases across two distinct RFC 2606
/// `.invalid` hosts under the WHATWG URL Standard (`url::Url::join`), defeating `https:host/x.js`,
/// `https:/host/x.js`, `\/host/x.js`, `/\host`, `\\host`, `//host`, tab/CR/LF obfuscation, and
/// scheme overrides (`R5-PUB-10`, `R6-PUB-1`, `R7-SCAN-1`).
fn is_same_origin_relative_url(raw: &str) -> bool {
    // WHATWG URL §4.3: trim leading/trailing ASCII C0 controls and space, then strip all ASCII
    // tab (0x09), LF (0x0A), and CR (0x0D) characters anywhere in the string.
    let trimmed = raw.trim_matches(|c: char| c <= '\u{0020}');
    let cleaned: String = trimmed
        .chars()
        .filter(|&c| !matches!(c, '\t' | '\n' | '\r'))
        .collect();
    if cleaned.is_empty() || has_url_scheme_prefix(&cleaned) {
        return false;
    }

    for (base_str, expected_scheme, expected_host) in [
        (
            "https://origin-a.miraserve.invalid/dir/page.html",
            "https",
            "origin-a.miraserve.invalid",
        ),
        (
            "https://origin-b.miraserve.invalid/dir/page.html",
            "https",
            "origin-b.miraserve.invalid",
        ),
        (
            "http://origin-a.miraserve.invalid/dir/page.html",
            "http",
            "origin-a.miraserve.invalid",
        ),
        (
            "http://origin-b.miraserve.invalid/dir/page.html",
            "http",
            "origin-b.miraserve.invalid",
        ),
    ] {
        let Ok(base) = url::Url::parse(base_str) else {
            return false;
        };
        let Ok(resolved) = base.join(&cleaned) else {
            return false;
        };
        if resolved.scheme() != expected_scheme
            || resolved.host_str() != Some(expected_host)
            || resolved.port().is_some()
            || !resolved.username().is_empty()
            || resolved.password().is_some()
        {
            return false;
        }
    }
    true
}

/// Implements WHATWG HTML §8.1.6.5 "parse a URL-like import specifier" (`R7-SCAN-2`):
/// browsers parse any importmap target that does NOT literally start with `"/"`, `"./"`, or
/// `"../"` as an absolute URL with NO base URL (so `"https:evil.example/m.js"` loads cross-origin
/// even on an HTTPS page!).
///
/// Only literal relative URL-like specifiers starting with `"/"` (excluding `"//"` and `"/\\"`),
/// `"./"`, or `"../"` that ALSO pass [`is_same_origin_relative_url`] are accepted.
fn is_same_origin_importmap_specifier(raw: &str) -> bool {
    let starts_url_like_relative = raw.starts_with("./")
        || raw.starts_with("../")
        || (raw.starts_with('/') && !raw.starts_with("//") && !raw.starts_with("/\\"));
    if !starts_url_like_relative {
        return false;
    }
    is_same_origin_relative_url(raw)
}

/// Parses an HTML `srcset` attribute into individual candidate URLs (`R5-PUB-9`), properly
/// preserving commas inside `data:image/svg+xml;base64,...` / `data:image/svg+xml,...` URIs.
fn parse_srcset_urls(srcset: &str) -> Vec<&str> {
    let mut urls = Vec::new();
    let bytes = srcset.as_bytes();
    let mut i = 0_usize;
    while i < bytes.len() {
        // Skip leading whitespace and stray commas
        while matches!(bytes.get(i), Some(b' ' | b'\t' | b'\r' | b'\n' | b',')) {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let url_start = i;
        let starts_data = srcset.get(i..).is_some_and(|s| {
            s.len() >= 5 && s.get(..5).is_some_and(|p| p.eq_ignore_ascii_case("data:"))
        });
        if starts_data {
            // In a data: URI, the comma separates media-type from payload; URL ends at ASCII whitespace.
            while let Some(&b) = bytes.get(i) {
                if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
                    break;
                }
                i += 1;
            }
        } else {
            // Standard URL ends at ASCII whitespace or comma.
            while let Some(&b) = bytes.get(i) {
                if matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b',') {
                    break;
                }
                i += 1;
            }
        }
        if let Some(u) = srcset.get(url_start..i) {
            let trimmed = u.trim_end_matches(',');
            if !trimmed.is_empty() {
                urls.push(trimmed);
            }
        }
        // Skip optional descriptor (`1x`, `200w`, etc.) up to the next `,`
        while let Some(&b) = bytes.get(i) {
            i += 1;
            if b == b',' {
                break;
            }
        }
    }
    urls
}

/// Returns `true` when a `<link>` element's un-namespaced `rel` attribute exclusively declares
/// passive icon relations so `data:image/svg+xml` favicons are permitted (`R4-PUB-4`).
fn is_icon_only_link_rel(attrs: &[ParsedAttr]) -> bool {
    let mut saw_icon = false;
    for a in attrs {
        if a.is_unqualified("rel") {
            for token in a.value.split_ascii_whitespace() {
                let lower = token.to_ascii_lowercase();
                if matches!(
                    lower.as_str(),
                    "icon" | "shortcut" | "apple-touch-icon" | "mask-icon"
                ) {
                    saw_icon = true;
                } else {
                    return false;
                }
            }
        }
    }
    saw_icon
}

fn attr_local_name(name: &str) -> &str {
    name.rsplit_once(':').map_or(name, |(_, local)| local)
}

/// Implements WHATWG HTML §4.2.5.3 shared declarative refresh steps (`R5-PUB-13`), handling
/// `0; url = javascript:alert(1)`, `0; javascript:alert(1)` (no `url=`), and comma delimiters.
fn extract_meta_refresh_url(content: &str) -> Option<&str> {
    let bytes = content.as_bytes();
    let mut i = 0_usize;
    let skip_ws = |idx: &mut usize| {
        while matches!(bytes.get(*idx), Some(b' ' | b'\t' | b'\r' | b'\n' | 0x0C)) {
            *idx += 1;
        }
    };

    skip_ws(&mut i);
    // Skip leading numeric delay (digits and optional `.digits`)
    let time_start = i;
    while matches!(bytes.get(i), Some(b'0'..=b'9')) {
        i += 1;
    }
    if i == time_start && bytes.get(i) != Some(&b'.') {
        return None;
    }
    while matches!(bytes.get(i), Some(b'0'..=b'9' | b'.')) {
        i += 1;
    }
    // Advance past any remaining non-delimiter chars on the time component up to `;`, `,`, or ws
    while let Some(&b) = bytes.get(i) {
        if matches!(b, b';' | b',' | b' ' | b'\t' | b'\r' | b'\n' | 0x0C) {
            break;
        }
        i += 1;
    }
    skip_ws(&mut i);
    if matches!(bytes.get(i), Some(b';' | b',')) {
        i += 1;
    }
    skip_ws(&mut i);
    if i >= bytes.len() {
        return None;
    }

    // Optional `url` + optional whitespace + `=`
    let saved = i;
    if content
        .get(i..i + 3)
        .is_some_and(|s| s.eq_ignore_ascii_case("url"))
    {
        let mut probe = i + 3;
        skip_ws(&mut probe);
        if bytes.get(probe) == Some(&b'=') {
            probe += 1;
            skip_ws(&mut probe);
            i = probe;
        } else {
            i = saved;
        }
    }

    if i >= bytes.len() {
        return None;
    }
    // Optional enclosing single or double quote
    let quote = match bytes.get(i).copied() {
        Some(q @ (b'\'' | b'"')) => {
            i += 1;
            Some(q)
        }
        _ => None,
    };
    let url_start = i;
    if let Some(q) = quote {
        while let Some(&b) = bytes.get(i) {
            if b == q {
                break;
            }
            i += 1;
        }
        content.get(url_start..i)
    } else {
        content.get(url_start..).map(str::trim)
    }
}

/// Recursively verifies that a parsed JSON value (`importmap` / `speculationrules`) contains no
/// executable URL schemes (`javascript:`, `vbscript:`, `data:`) in any string field (`R4-PUB-4`).
fn json_contains_executable_uri(val: &serde_json::Value) -> bool {
    match val {
        serde_json::Value::String(s) => {
            let norm = normalize_url_value(s);
            norm.starts_with("javascript:")
                || norm.starts_with("vbscript:")
                || norm.starts_with("data:")
        }
        serde_json::Value::Array(arr) => arr.iter().any(json_contains_executable_uri),
        serde_json::Value::Object(map) => map.values().any(json_contains_executable_uri),
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            false
        }
    }
}

/// Validates `<script type="importmap">` JSON so every mapped specifier target in `"imports"`
/// and `"scopes"` satisfies WHATWG "parse a URL-like import specifier" (`R6-PUB-3`, `R7-SCAN-2`)
/// and every URL key in `"scopes"` / `"integrity"` resolves strictly to the same origin.
fn validate_importmap_json(val: &serde_json::Value) -> Option<&'static str> {
    let Some(root) = val.as_object() else {
        return Some("<script type=\"importmap\"> body must be a JSON object");
    };
    if json_contains_executable_uri(val) {
        return Some("<script type=\"importmap\"> contains forbidden executable URI scheme");
    }
    if let Some(imports) = root.get("imports") {
        let Some(map) = imports.as_object() else {
            return Some("<script type=\"importmap\"> \"imports\" field must be a JSON object");
        };
        for target in map.values() {
            let Some(url_str) = target.as_str() else {
                return Some(
                    "<script type=\"importmap\"> \"imports\" targets must be same-origin URL strings",
                );
            };
            if !is_same_origin_importmap_specifier(url_str) {
                return Some(
                    "<script type=\"importmap\"> \"imports\" target must be a same-origin URL-like relative specifier starting with '/', './', or '../' (cross-origin and bare module targets are forbidden)",
                );
            }
        }
    }
    if let Some(scopes) = root.get("scopes") {
        let Some(scopes_map) = scopes.as_object() else {
            return Some("<script type=\"importmap\"> \"scopes\" field must be a JSON object");
        };
        for (scope_prefix, inner) in scopes_map {
            if !is_same_origin_relative_url(scope_prefix) {
                return Some(
                    "<script type=\"importmap\"> \"scopes\" prefix must be a same-origin relative URL",
                );
            }
            let Some(inner_map) = inner.as_object() else {
                return Some("<script type=\"importmap\"> scope entry must be a JSON object");
            };
            for target in inner_map.values() {
                let Some(url_str) = target.as_str() else {
                    return Some(
                        "<script type=\"importmap\"> scope target must be a same-origin URL string",
                    );
                };
                if !is_same_origin_importmap_specifier(url_str) {
                    return Some(
                        "<script type=\"importmap\"> scope target must be a same-origin URL-like relative specifier starting with '/', './', or '../' (cross-origin and bare module targets are forbidden)",
                    );
                }
            }
        }
    }
    if let Some(integrity) = root.get("integrity") {
        let Some(int_map) = integrity.as_object() else {
            return Some("<script type=\"importmap\"> \"integrity\" field must be a JSON object");
        };
        for url_key in int_map.keys() {
            if !is_same_origin_relative_url(url_key) {
                return Some(
                    "<script type=\"importmap\"> \"integrity\" URL key must be a same-origin relative URL",
                );
            }
        }
    }
    None
}

/// Validates `<script type="speculationrules">` JSON against executable schemes and cross-origin
/// `"urls"` targets (`R6-PUB-3`).
fn validate_speculationrules_json(val: &serde_json::Value) -> Option<&'static str> {
    let Some(root) = val.as_object() else {
        return Some("<script type=\"speculationrules\"> body must be a JSON object");
    };
    if json_contains_executable_uri(val) {
        return Some("<script type=\"speculationrules\"> contains forbidden executable URI scheme");
    }
    for section in ["prerender", "prefetch"] {
        if let Some(rules) = root.get(section)
            && let Some(arr) = rules.as_array()
        {
            for rule in arr {
                if let Some(urls) = rule.get("urls").and_then(serde_json::Value::as_array) {
                    for entry in urls {
                        if let Some(u) = entry.as_str()
                            && !is_same_origin_relative_url(u)
                        {
                            return Some(
                                "<script type=\"speculationrules\"> \"urls\" entries must be same-origin relative URLs",
                            );
                        }
                    }
                }
            }
        }
    }
    None
}

#[allow(clippy::too_many_lines)]
fn check_element_security(
    is_html_ns: bool,
    is_svg_ns: bool,
    local_name: &str,
    attrs: &[ParsedAttr],
    script_text: &str,
    has_non_text_children: bool,
) -> Option<&'static str> {
    // 1. Block SVG Tiny / XML Events scripting elements outright.
    if matches!(local_name, "handler" | "listener") {
        return Some("markup contains forbidden scripting element (<handler>/<listener>)");
    }

    let is_script = local_name == "script";
    let is_active_embed = is_script
        || matches!(
            local_name,
            "iframe" | "object" | "embed" | "frame" | "frameset" | "use" | "base"
        );
    let is_smil_anim = matches!(
        local_name,
        "animate" | "set" | "animatemotion" | "animatetransform" | "animatecolor"
    );

    // 1b. R5-PUB-10 & R6-PUB-1: Restrict `<base href=...>` to relative same-origin paths so a
    //     prompt-injected `<base href="https://evil.example/">` or `<base href="\/evil/">` can
    //     NEVER hijack relative `<script src="app.js">`!
    if local_name == "base" {
        for a in attrs {
            if (a.is_unqualified("href") || a.is_href()) && !is_same_origin_relative_url(&a.value) {
                return Some(
                    "<base href> must be a relative same-origin path (cross-origin <base> is forbidden)",
                );
            }
        }
    }

    // 2. Inspect every attribute on the parsed DOM element.
    for attr in attrs {
        let attr_local = attr_local_name(&attr.local);
        let attr_val = attr.value.as_str();

        // 2.0. Reject cross-origin `xml:base` on any element (honored by Firefox/Safari in SVG/XML).
        if ((attr.ns.as_deref() == Some(XML_NS) && attr.local == "base")
            || attr.local == "xml:base")
            && !is_same_origin_relative_url(attr_val)
        {
            return Some(
                "xml:base attribute must be a relative same-origin path (cross-origin xml:base is forbidden)",
            );
        }

        // 2a. Reject ALL `on*` inline event handlers (onfocus, onerror, onload, onanimationstart, etc.).
        if attr_local.starts_with("on") && attr_local.len() >= 3 {
            return Some("markup contains forbidden inline event handler attribute (on*)");
        }
        // 2b. Reject `<iframe srcdoc=...>` inline HTML execution.
        if attr_local == "srcdoc" {
            return Some("markup contains forbidden srcdoc attribute");
        }

        // 2c. SMIL animation vectors (`R4-PUB-1`): check `attributeName` and every `;`-delimited
        //     segment of `values`, `from`, `to`, `by`!
        if is_smil_anim {
            if attr_local == "attributename" {
                let target = normalize_url_value(attr_val);
                let target_local = attr_local_name(&target);
                if target_local.starts_with("on")
                    || matches!(
                        target_local,
                        "href" | "src" | "srcdoc" | "action" | "formaction" | "data"
                    )
                {
                    return Some("SMIL animation targets forbidden executable/URL attribute");
                }
            }
            if matches!(attr_local, "values" | "from" | "to" | "by") {
                for segment in attr_val.split(';') {
                    let seg_norm = normalize_url_value(segment);
                    if seg_norm.starts_with("javascript:")
                        || seg_norm.starts_with("vbscript:")
                        || seg_norm.starts_with("data:")
                    {
                        return Some(
                            "SMIL animation attribute contains forbidden executable URI scheme",
                        );
                    }
                }
            }
        }

        // 2d. Handle `srcset` multi-candidate URLs cleanly (`R5-PUB-9`).
        if attr_local == "srcset" {
            let passive_srcset = is_html_ns && matches!(local_name, "img" | "source");
            for url in parse_srcset_urls(attr_val) {
                let url_norm = normalize_url_value(url);
                if is_forbidden_active_uri_scheme(&url_norm) {
                    return Some("srcset attribute contains forbidden executable URI scheme");
                }
                if url_norm.starts_with("data:image/svg+xml") && !passive_srcset {
                    return Some(
                        "data:image/svg+xml in srcset is only permitted on HTML <img> and <source>",
                    );
                }
            }
            continue;
        }

        // 2e. Executable URI schemes & `data:` policy (`R4-PUB-4`, `R5-PUB-9`, `R6-PUB-7`): allow
        //     passive `data:image/svg+xml` on HTML `<img src>`, `<video poster>`,
        //     `<link rel="icon" href>`, and SVG `<image href>` / `<feImage href>`.
        let norm = normalize_url_value(attr_val);
        if is_active_embed
            && matches!(
                attr_local,
                "src" | "href" | "data" | "codebase" | "archive" | "poster"
            )
            && norm.starts_with("data:")
        {
            return Some("markup active element contains forbidden data: URI source");
        }
        if is_forbidden_active_uri_scheme(&norm) {
            return Some("markup attribute contains forbidden executable URI scheme");
        }
        if norm.starts_with("data:image/svg+xml") {
            let allowed_passive_svg_data = (is_html_ns
                && ((local_name == "img" && attr.is_unqualified("src"))
                    || (local_name == "video" && attr.is_unqualified("poster"))
                    || (local_name == "link"
                        && attr.is_unqualified("href")
                        && is_icon_only_link_rel(attrs))))
                || (is_svg_ns && matches!(local_name, "image" | "feimage") && attr.is_href());
            if !allowed_passive_svg_data {
                return Some(
                    "data:image/svg+xml URI is only permitted on passive image contexts (<img src/srcset>, <source srcset>, <video poster>, <link rel=\"icon\">, SVG <image>/<feImage>)",
                );
            }
        }
    }

    // 3. Block `<meta http-equiv="refresh" content="...">` using full WHATWG §4.2.5.3 parsing (`R5-PUB-13`).
    if local_name == "meta" {
        let is_refresh = attrs.iter().any(|a| {
            a.is_unqualified("http-equiv") && a.value.trim().eq_ignore_ascii_case("refresh")
        });
        if is_refresh {
            for a in attrs {
                if a.is_unqualified("content")
                    && let Some(raw_url) = extract_meta_refresh_url(&a.value)
                {
                    let url_norm = normalize_url_value(raw_url);
                    if url_norm.starts_with("javascript:")
                        || url_norm.starts_with("vbscript:")
                        || url_norm.starts_with("data:")
                        || url_norm.starts_with("blob:")
                    {
                        return Some("meta refresh contains forbidden executable URI scheme");
                    }
                }
            }
        }
    }

    // 4. Strictly validate every `<script>` element (both HTML and SVG/XML namespaces).
    if is_script {
        // R6-PUB-2: Inspect EVERY `src`, `href`, and `xlink:href` attribute on `<script>` (not
        // just the first!) so `<svg><script xlink:href="ok.js" href="https://evil.example/x.js">`
        // and `<svg><script src="ok.js" href="https://evil.example/x.js">` are always caught!
        let mut saw_html_src = false;
        let mut saw_svg_href = false;
        for a in attrs {
            let is_src = a.is_unqualified("src");
            let is_href = a.is_href();
            if !is_src && !is_href {
                continue;
            }
            if a.value.trim_matches(|c: char| c <= '\u{0020}').is_empty() {
                continue;
            }
            if !is_same_origin_relative_url(&a.value) {
                return if is_html_ns {
                    Some(
                        "external <script> URL attribute must be a scheme-less same-origin relative path (cross-origin scripts are forbidden)",
                    )
                } else {
                    Some(
                        "non-HTML <script> external URL must be a scheme-less same-origin relative path (cross-origin scripts are forbidden)",
                    )
                };
            }
            if is_src {
                saw_html_src = true;
            }
            if is_href {
                saw_svg_href = true;
            }
        }

        // R5-PUB-14: Require un-namespaced `type` attribute so XHTML `<script x:type="application/json">`
        // cannot masquerade as an inert data block!
        let type_val = attrs
            .iter()
            .find(|a| a.is_unqualified("type"))
            .map(|a| a.value.trim().to_ascii_lowercase());

        // Non-HTML `<script>` (e.g. SVG `<script>`) is ONLY permitted as an empty same-origin
        // external script reference (`href` or `xlink:href`, since browsers ignore `src` on SVG
        // scripts) — never inline content, cross-origin URLs, or child elements (`R4-PUB-1`,
        // `R5-PUB-10`, `R6-PUB-2`).
        if !is_html_ns {
            if !saw_svg_href {
                return Some(
                    "non-HTML <script> element must reference a same-origin external script via href/xlink:href and contain no inline content",
                );
            }
            if has_non_text_children || !script_text.trim().is_empty() {
                return Some("non-HTML <script> element must not contain inline content");
            }
            return None;
        }

        if saw_html_src {
            if has_non_text_children || !script_text.trim().is_empty() {
                return Some(
                    "external <script src=...> element must not also contain inline content",
                );
            }
            return None;
        }

        // Inline HTML `<script>` is ONLY permitted for validated JSON data blocks, same-origin
        // `importmap`, safe `speculationrules` (`R4-PUB-4`, `R6-PUB-3`), and inert
        // `text/template` / `text/x-template` blocks (`R5-PUB-9`, `R6-PUB-7`), with zero non-text
        // children!
        if has_non_text_children {
            return Some("inline <script> element contains forbidden child nodes or comments");
        }
        // R6-PUB-7: Strip optional MIME parameters (e.g. `; charset=utf-8` or `; x`) ONLY for
        // MIME-typed inert data blocks; `importmap` and `speculationrules` are exact keywords.
        match type_val.as_deref() {
            Some("importmap") => {
                let Ok(parsed) = serde_json::from_str::<serde_json::Value>(script_text) else {
                    return Some("<script type=\"importmap\"> body must be valid JSON");
                };
                if let Some(reason) = validate_importmap_json(&parsed) {
                    return Some(reason);
                }
            }
            Some("speculationrules") => {
                let Ok(parsed) = serde_json::from_str::<serde_json::Value>(script_text) else {
                    return Some("<script type=\"speculationrules\"> body must be valid JSON");
                };
                if let Some(reason) = validate_speculationrules_json(&parsed) {
                    return Some(reason);
                }
            }
            Some(raw_type) => {
                let essence = raw_type.split(';').next().unwrap_or(raw_type).trim();
                match essence {
                    "application/json" | "application/ld+json" => {
                        if serde_json::from_str::<serde_json::Value>(script_text).is_err() {
                            return Some(
                                "<script type=\"application/json\"> body must be valid JSON",
                            );
                        }
                    }
                    "text/template" | "text/x-template" => {}
                    _ => {
                        return Some(
                            "markup contains inline <script> block (same-origin external scripts with src= only)",
                        );
                    }
                }
            }
            None => {
                return Some(
                    "markup contains inline <script> block (same-origin external scripts with src= only)",
                );
            }
        }
    }

    None
}

/// Returns `true` if `low` (lowercased CSP source token) dangerously widens an active
/// script/object/frame/base directive (`R5-PUB-9`, `R6-PUB-9`, `R7-SCAN-5`), catching
/// `'unsafe-inline'`, `'unsafe-eval'`, `'unsafe-hashes'`, `*`, wildcard hosts/ports (`https://*`,
/// `http://*:80`, `*.com`, `*.example`, `https://*.com`, `https://*.example.com`, `*:*`), and
/// broad scheme sources (`http:`, `https:`, `ws:`, `wss:`, `ftp:`, `data:`, `blob:`).
fn is_unsafe_active_csp_source(low: &str) -> bool {
    if matches!(
        low,
        "'unsafe-inline'"
            | "'unsafe-eval'"
            | "'unsafe-hashes'"
            | "*"
            | "http:"
            | "https:"
            | "ws:"
            | "wss:"
            | "ftp:"
            | "filesystem:"
            | "data:"
            | "blob:"
    ) || low.starts_with("data:")
        || low.starts_with("blob:")
    {
        return true;
    }
    if low.starts_with('\'') {
        return false;
    }
    let after_scheme = low
        .split_once("://")
        .map_or_else(|| low.strip_prefix("//").unwrap_or(low), |(_, rest)| rest);
    let host_and_port = after_scheme.split('/').next().unwrap_or(after_scheme);
    host_and_port.contains('*')
}

/// Per-directive CSP meta-tag validator (`R5-PUB-9`, `R6-PUB-9`):
/// - Permits safe passive directives like `img-src 'self' data:` and `style-src 'self' 'unsafe-inline'`.
/// - Strictly rejects `'unsafe-inline'`, `'unsafe-eval'`, `'unsafe-hashes'`, `data:`, `blob:`,
///   wildcard `*` / `https://*` / `http://*`, and broad scheme sources on active directives!
/// - Rejects `javascript:` and `vbscript:` in EVERY directive.
fn check_csp_meta_attrs(attrs: &[ParsedAttr]) -> Option<&'static str> {
    let is_csp_meta = attrs.iter().any(|a| {
        a.is_unqualified("http-equiv")
            && matches!(
                a.value.trim().to_ascii_lowercase().as_str(),
                "content-security-policy" | "content-security-policy-report-only"
            )
    });
    if !is_csp_meta {
        return None;
    }
    for a in attrs {
        if !a.is_unqualified("content") {
            continue;
        }
        for raw_directive in a.value.split(';') {
            let mut tokens = raw_directive.split_ascii_whitespace();
            let Some(raw_name) = tokens.next() else {
                continue;
            };
            let dir_name = raw_name.to_ascii_lowercase();
            let is_active_directive = matches!(
                dir_name.as_str(),
                "default-src"
                    | "script-src"
                    | "script-src-elem"
                    | "script-src-attr"
                    | "object-src"
                    | "worker-src"
                    | "frame-src"
                    | "child-src"
                    | "base-uri"
            );
            for tok in tokens {
                let low = tok.to_ascii_lowercase();
                if low.starts_with("javascript:") || low.starts_with("vbscript:") {
                    return Some("CSP meta tag contains forbidden javascript:/vbscript: source");
                }
                if is_active_directive && is_unsafe_active_csp_source(&low) {
                    return Some(
                        "CSP meta tag weakens an active script/object/frame/base directive with unsafe source ('unsafe-inline', 'unsafe-eval', 'unsafe-hashes', '*', 'https://*', 'http:', 'https:', 'data:', or 'blob:')",
                    );
                }
            }
        }
    }
    None
}

#[cfg(all(test, unix))]
mod scan_clock_tests {
    use super::*;

    /// R8-SCAN-1: the scan budget must measure the scanner's own CPU work. Time spent waiting
    /// (descheduled on a busy host, here: asleep) must not count, or a loaded machine rejects
    /// bundles that an idle one accepts.
    #[test]
    fn r8_scan_1_scan_clock_counts_cpu_time_not_waiting_time() {
        let before_sleep = scan_clock_now();
        std::thread::sleep(Duration::from_millis(400));
        let slept = scan_clock_now().saturating_sub(before_sleep);
        assert!(
            slept < Duration::from_millis(100),
            "R8-SCAN-1: 400 ms of waiting advanced the scan clock by {slept:?}; it must track CPU time"
        );

        // Real work does advance it.
        let before_work = scan_clock_now();
        let mut acc = 0_u64;
        let mut spins = 0_u64;
        while scan_clock_now().saturating_sub(before_work) < Duration::from_millis(50) {
            acc = acc
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(spins);
            spins = spins.saturating_add(1);
            assert!(
                spins < 5_000_000_000,
                "scan clock never advanced under CPU work"
            );
        }
        std::hint::black_box(acc);
    }

    /// R8-SCAN-1: the whole-bundle budget grows with the amount of markup, so a large site of
    /// ordinary pages is not rejected by a fixed 5 s budget.
    #[test]
    fn r8_scan_1_bundle_budget_scales_with_markup_size() {
        // Exercises the production function, so restoring a fixed budget fails here.
        const MIB: u64 = 1024 * 1024;
        assert_eq!(
            bundle_markup_scan_budget(0),
            MAX_BUNDLE_MARKUP_SCAN_DURATION
        );
        assert_eq!(
            bundle_markup_scan_budget(MIB - 1),
            MAX_BUNDLE_MARKUP_SCAN_DURATION
        );
        assert!(bundle_markup_scan_budget(144 * MIB) >= Duration::from_secs(40));
        assert!(bundle_markup_scan_budget(144 * MIB) > bundle_markup_scan_budget(10 * MIB));
        assert!(bundle_markup_scan_budget(u64::MAX) >= bundle_markup_scan_budget(144 * MIB));
    }
}
